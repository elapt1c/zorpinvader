//! The client loop: join a controller, claim a block, scan it, report it.
//!
//! A client is a complete scanner minus the choice of targets. It never picks
//! what to scan and never decides when the scan is over: the controller sends a
//! block, the ports, the rate share and the pipeline settings, and the client
//! reports progress and results until the controller says it is done.
//!
//! Transport is `curl`, which the fetcher already depends on at runtime. That
//! buys `https://` with the system CA store for free — including controllers
//! published through `cloudflared` — with no TLS stack in this binary.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::engine::ScanEngine;
use crate::main_mod::conf::Zorp;

use super::protocol::*;
use super::scheduler::JobSpec;
use super::set4::format_ip;

/// Minimum spacing between progress reports, so a fast block does not spam the
/// controller.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(2);

/// How long to wait when the controller has work but none free.
const WAIT_INTERVAL: Duration = Duration::from_secs(2);

/// Retries for a single HTTP call before the caller deals with the failure.
const HTTP_ATTEMPTS: usize = 3;

/// Run a client until the controller reports the scan complete or the user
/// interrupts it.
pub fn run(zorp: Arc<Zorp>) -> i32 {
    let base = zorp.client_url.trim_end_matches('/').to_string();
    let token = zorp.token.clone().unwrap_or_default();
    if token.is_empty() {
        eprintln!("ERROR: --client requires --token <token> (the controller prints it on start)");
        return 1;
    }

    let name = zorp
        .client_name
        .clone()
        .unwrap_or_else(|| hostname().unwrap_or_else(|| "client".to_string()));

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        let _ = ctrlc::set_handler(move || {
            eprintln!("\n[client] shutting down");
            stop.store(true, Ordering::SeqCst);
        });
    }

    // Join first: the controller owns the pipeline settings, so the engine is
    // built with them rather than with whatever the client's flags said.
    let join = match join(&base, &token, &name, zorp.max_rate, &stop) {
        Some(j) => j,
        None => return 1,
    };
    eprintln!(
        "[client] joined {} as {} ({} blocks of {} addresses, {}s lease)",
        join.server_version, join.client_id, join.blocks_total, join.block_size, join.lease_s
    );

    let engine = match ScanEngine::new(&zorp, join.tpc, join.include_safe) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("ERROR: {}", e);
            return 1;
        }
    };
    eprintln!(
        "[client] adapter {} source {} ports {}",
        engine.adapter_name(),
        format_ip(engine.source_ip()),
        join.ports
    );

    let mut spool = Spool::new(&name);
    spool.flush(&base, &token);

    let mut blocks_done = 0u64;
    let mut exit_code = 0;

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        // Anything spooled while the controller was unreachable gets another try
        // before asking for more work.
        spool.flush(&base, &token);

        let claim = match post_retry(
            &format!("{}{}", base, PATH_CLAIM),
            &token,
            &ClaimRequest {
                client_id: join.client_id.clone(),
                pps_cap: zorp.max_rate,
            },
            &stop,
        ) {
            Some((200, body)) => match serde_json::from_str::<ClaimResponse>(&body) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[client] bad claim response: {}", e);
                    std::thread::sleep(WAIT_INTERVAL);
                    continue;
                }
            },
            Some((code, body)) => {
                eprintln!("[client] claim rejected ({}): {}", code, body);
                if code == 401 {
                    exit_code = 1;
                    break;
                }
                std::thread::sleep(WAIT_INTERVAL);
                continue;
            }
            None => {
                // Controller unreachable; keep spooled results and retry.
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        if claim.done {
            eprintln!("[client] controller reports the scan complete");
            break;
        }

        let job = match claim.job {
            Some(j) => j,
            None => {
                // Everything is leased to other clients right now.
                std::thread::sleep(WAIT_INTERVAL);
                continue;
            }
        };

        let spec = JobSpec {
            job_id: job.job_id,
            begin: job.begin,
            end: job.end,
            cidr: job.cidr.clone(),
            ports: job.ports.clone(),
            rate: effective_rate(claim.rate, zorp.max_rate),
            resume_pos: job.resume_pos,
            lease_s: job.lease_s,
            include_safe: job.include_safe,
            tpc: job.tpc,
        };

        eprintln!(
            "[client] block {} {} resume {} rate {}{}",
            job.job_id,
            job.cidr,
            job.resume_pos,
            if spec.rate > 0.0 {
                format!("{:.0} pps", spec.rate)
            } else {
                "uncapped".to_string()
            },
            if job.resume_pos > 0 {
                " (resuming leased block)"
            } else {
                ""
            }
        );

        let cancel = Arc::new(AtomicBool::new(false));
        let mut last_progress = Instant::now();

        let outcome = engine.scan_block(&spec, &cancel, &mut |progress| {
            if stop.load(Ordering::SeqCst) {
                return false;
            }

            if last_progress.elapsed() >= PROGRESS_INTERVAL {
                last_progress = Instant::now();
                match post_json(
                    &format!("{}{}", base, PATH_PROGRESS),
                    &token,
                    &ProgressRequest {
                        client_id: join.client_id.clone(),
                        job_id: spec.job_id,
                        pos: progress.pos,
                        syns: progress.syns,
                        synacks: progress.synacks,
                    },
                ) {
                    Ok((200, body)) => {
                        if let Ok(reply) = serde_json::from_str::<ProgressResponse>(&body) {
                            if reply.cancel {
                                eprintln!("\n[client] controller reassigned block {}", spec.job_id);
                                cancel.store(true, Ordering::SeqCst);
                                return false;
                            }
                        }
                    }
                    Ok((code, body)) => {
                        eprintln!("\n[client] progress rejected ({}): {}", code, body);
                        cancel.store(true, Ordering::SeqCst);
                        return false;
                    }
                    Err(_) => {
                        // Transient: the lease is long, keep scanning.
                    }
                }
            }

            // Nothing to show once the block is exhausted; the summary line
            // follows and the grace period would otherwise repaint 100%.
            if progress.pos >= progress.total {
                return true;
            }
            let pct = if progress.total > 0 {
                progress.pos as f64 * 100.0 / progress.total as f64
            } else {
                0.0
            };
            let pps = if progress.elapsed_s > 0.0 {
                progress.syns as f64 / progress.elapsed_s
            } else {
                0.0
            };
            eprint!(
                "\r\x1b[K[{}] block {} {:>6.2}% | {:>6.1}k pps | hits {:<5} | syns {}",
                join.client_id,
                spec.job_id,
                pct,
                pps / 1000.0,
                progress.hits,
                progress.syns
            );
            let _ = std::io::stderr().flush();
            true
        });

        let outcome = match outcome {
            Ok(o) => o,
            Err(e) => {
                eprintln!("\n[client] block {} failed: {}", spec.job_id, e);
                let _ = post_json(
                    &format!("{}{}", base, PATH_RELEASE),
                    &token,
                    &ReleaseRequest {
                        client_id: join.client_id.clone(),
                        job_id: spec.job_id,
                        pos: 0,
                        reason: e,
                    },
                );
                std::thread::sleep(WAIT_INTERVAL);
                continue;
            }
        };

        eprintln!(
            "\n[client] block {} {} pos {}/{} syns {} synacks {} hits {} keys {}",
            spec.job_id,
            spec.cidr,
            outcome.pos,
            outcome.total,
            outcome.syns,
            outcome.synacks,
            outcome.hits.len(),
            outcome.keys.len()
        );

        // Results first: coverage can be retried, a key cannot be re-found for
        // free.
        let results = ResultsRequest {
            client_id: join.client_id.clone(),
            job_id: spec.job_id,
            hits: outcome
                .hits
                .iter()
                .map(|(ip, port)| HitRecord {
                    ip: format_ip(*ip),
                    port: *port,
                })
                .collect(),
            keys: outcome.keys.clone(),
            syns: outcome.syns,
            synacks: outcome.synacks,
        };
        if !results.hits.is_empty() || !results.keys.is_empty() {
            if !post_results(&base, &token, &results) {
                spool.append(&results);
                eprintln!("[client] results spooled locally, will retry");
            }
        }

        if outcome.completed {
            match post_retry(
                &format!("{}{}", base, PATH_COMPLETE),
                &token,
                &CompleteRequest {
                    client_id: join.client_id.clone(),
                    job_id: spec.job_id,
                    pos: outcome.pos,
                    syns: outcome.syns,
                    synacks: outcome.synacks,
                },
                &stop,
            ) {
                Some((200, _)) => blocks_done += 1,
                Some((code, body)) => eprintln!("[client] complete rejected ({}): {}", code, body),
                None => {
                    // The lease will expire and the block will be re-leased;
                    // nothing is lost, only re-scanned.
                    eprintln!("[client] could not report completion of block {}", spec.job_id);
                }
            }
        } else {
            let _ = post_json(
                &format!("{}{}", base, PATH_RELEASE),
                &token,
                &ReleaseRequest {
                    client_id: join.client_id.clone(),
                    job_id: spec.job_id,
                    pos: outcome.pos,
                    reason: if stop.load(Ordering::SeqCst) {
                        "client shutting down".to_string()
                    } else {
                        "interrupted".to_string()
                    },
                },
            );
        }

        if stop.load(Ordering::SeqCst) {
            break;
        }
    }

    spool.flush(&base, &token);
    eprintln!("[client] {} blocks completed", blocks_done);
    engine.shutdown();
    exit_code
}

fn effective_rate(controller_rate: f64, client_cap: f64) -> f64 {
    match (controller_rate > 0.0, client_cap > 0.0) {
        (true, true) => controller_rate.min(client_cap),
        (true, false) => controller_rate,
        (false, true) => client_cap,
        (false, false) => 0.0,
    }
}

fn join(
    base: &str,
    token: &str,
    name: &str,
    pps_cap: f64,
    stop: &Arc<AtomicBool>,
) -> Option<JoinResponse> {
    let request = JoinRequest {
        api_version: API_VERSION,
        name: name.to_string(),
        pps_cap,
    };
    loop {
        if stop.load(Ordering::SeqCst) {
            return None;
        }
        match post_retry(&format!("{}{}", base, PATH_JOIN), token, &request, stop) {
            Some((200, body)) => match serde_json::from_str::<JoinResponse>(&body) {
                Ok(j) => return Some(j),
                Err(e) => eprintln!("[client] bad join response: {}", e),
            },
            Some((code, body)) => {
                eprintln!("[client] join rejected ({}): {}", code, body);
                if code == 401 || code == 400 {
                    // Wrong token or version: retrying will not help.
                    return None;
                }
            }
            None => eprintln!("[client] controller unreachable at {}", base),
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

fn post_results(base: &str, token: &str, results: &ResultsRequest) -> bool {
    match post_json(&format!("{}{}", base, PATH_RESULTS), token, results) {
        Ok((200, _)) => true,
        Ok((code, body)) => {
            eprintln!("[client] results rejected ({}): {}", code, body);
            code < 500
        }
        Err(e) => {
            eprintln!("[client] results delivery failed: {}", e);
            false
        }
    }
}

/// POST JSON with up to [`HTTP_ATTEMPTS`] tries. Returns `None` when the
/// controller could not be reached at all.
fn post_retry<T: serde::Serialize>(
    url: &str,
    token: &str,
    body: &T,
    stop: &Arc<AtomicBool>,
) -> Option<(u16, String)> {
    for attempt in 0..HTTP_ATTEMPTS {
        if stop.load(Ordering::SeqCst) {
            return None;
        }
        match post_json(url, token, body) {
            Ok(reply) => return Some(reply),
            Err(e) => {
                if attempt + 1 == HTTP_ATTEMPTS {
                    eprintln!("[client] {}: {}", url, e);
                    return None;
                }
                std::thread::sleep(Duration::from_millis(500 * (1 << attempt)));
            }
        }
    }
    None
}

fn post_json<T: serde::Serialize>(
    url: &str,
    token: &str,
    body: &T,
) -> Result<(u16, String), String> {
    let payload = serde_json::to_string(body).map_err(|e| e.to_string())?;
    let auth = format!("Authorization: Bearer {}", token);

    let mut child = Command::new("curl")
        .args([
            "-sS",
            "--connect-timeout",
            "10",
            "--max-time",
            "60",
            "-X",
            "POST",
            "-H",
            "Expect:",
            "-H",
            "Content-Type: application/json",
            "-H",
            &auth,
            "--data-binary",
            "@-",
            "-w",
            "\n%{http_code}",
            url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run curl: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(payload.as_bytes())
            .map_err(|e| format!("curl stdin: {}", e))?;
    }

    let output = child.wait_with_output().map_err(|e| format!("curl: {}", e))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    let text = String::from_utf8_lossy(&output.stdout).to_string();
    let (body, code) = text
        .rsplit_once('\n')
        .ok_or_else(|| "malformed curl output".to_string())?;
    let code: u16 = code
        .trim()
        .parse()
        .map_err(|_| format!("malformed HTTP status: {}", code))?;
    Ok((code, body.to_string()))
}

/// Local queue for results the controller could not accept yet.
struct Spool {
    path: PathBuf,
}

impl Spool {
    fn new(client_name: &str) -> Self {
        let safe: String = client_name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        Spool {
            path: PathBuf::from(format!("zorp-spool-{}.jsonl", safe)),
        }
    }

    fn append(&mut self, results: &ResultsRequest) {
        let line = match serde_json::to_string(results) {
            Ok(l) => l,
            Err(_) => return,
        };
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(file, "{}", line);
        }
    }

    /// Try to deliver everything spooled so far, then remove the file.
    fn flush(&mut self, base: &str, token: &str) {
        let body = match std::fs::read_to_string(&self.path) {
            Ok(b) => b,
            Err(_) => return,
        };

        let mut undelivered = Vec::new();
        for line in body.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<ResultsRequest>(line) {
                Ok(results) => {
                    if !post_results(base, token, &results) {
                        undelivered.push(line.to_string());
                    }
                }
                Err(_) => {} // corrupt line: drop it rather than loop forever
            }
        }

        if undelivered.is_empty() {
            let _ = std::fs::remove_file(&self.path);
        } else {
            let _ = std::fs::write(&self.path, undelivered.join("\n") + "\n");
            eprintln!("[client] {} spooled result batch(es) still pending", undelivered.len());
        }
    }
}

fn hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    let name = String::from_utf8_lossy(&buf[..end]).to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_is_the_tighter_of_controller_share_and_local_cap() {
        assert_eq!(effective_rate(5000.0, 0.0), 5000.0);
        assert_eq!(effective_rate(0.0, 2000.0), 2000.0);
        assert_eq!(effective_rate(5000.0, 2000.0), 2000.0);
        assert_eq!(effective_rate(0.0, 0.0), 0.0);
    }
}
