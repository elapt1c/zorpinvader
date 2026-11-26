//! The client loop: join a controller, claim a block, scan it, report it.
//!
//! A client is a complete scanner minus the choice of targets. It never picks
//! what to scan and never decides when the scan is over: the controller sends a
//! block, the ports, the rate share and the pipeline settings, and the client
//! reports telemetry and results until the controller says it is done.
//!
//! Transport is `curl`, which the fetcher already depends on at runtime. That
//! buys `https://` with the system CA store for free, and — with
//! `--socks5-hostname` — `.onion` targets through tor, without this binary
//! containing a TLS stack or a Tor implementation.

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
use super::tor::{self, TorConfig, TorMode};

/// Telemetry cadence on the wire. The controller's dashboard is only as live as
/// this; 5s is the balance between a responsive view and noise on the socket.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(5);

/// How long to wait when the controller has work but none free.
const WAIT_INTERVAL: Duration = Duration::from_secs(2);

/// Retries for a single HTTP call before the caller deals with the failure.
const HTTP_ATTEMPTS: usize = 3;

/// Run a client until the controller reports the scan complete or the user
/// interrupts it.
pub fn run(zorp: Arc<Zorp>) -> i32 {
    let (base, is_onion) = normalize_url(&zorp.client_url);
    // No token is the normal case: the controller is open and the address is
    // the way in. --token is only for controllers that ask for one.
    let token = zorp.token.clone().filter(|t| !t.trim().is_empty());

    // `.onion` implies tor; anything else only goes through tor when asked.
    let mut tor_handle = if is_onion || zorp.tor {
        let cfg = TorConfig {
            mode: TorMode::Required,
            binary: zorp.tor_binary.clone(),
            socks: zorp.tor_socks.clone(),
            data_dir: zorp
                .tor_dir
                .clone()
                .unwrap_or_else(TorConfig::default_data_dir),
            timeout: Duration::from_secs(zorp.tor_timeout),
            auto_install: zorp.auto_install,
        };
        match tor::start_client(&cfg) {
            Ok(handle) => {
                eprintln!(
                    "[client] tor ready ({}){}",
                    handle.socks.as_deref().unwrap_or("?"),
                    if handle.managed {
                        ", private instance"
                    } else {
                        ", reusing existing tor"
                    }
                );
                Some(handle)
            }
            Err(e) => {
                eprintln!("ERROR: {}", e);
                return 1;
            }
        }
    } else {
        None
    };

    let transport = Transport {
        base,
        token,
        socks: tor_handle.as_ref().and_then(|t| t.socks.clone()),
    };

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
    let join = match join(&transport, &name, zorp.max_rate, &stop) {
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
    spool.flush(&transport);

    let mut blocks_done = 0u64;
    let mut exit_code = 0;

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        // Anything spooled while the controller was unreachable gets another try
        // before asking for more work.
        spool.flush(&transport);

        let claim = match transport.post_retry(
            PATH_CLAIM,
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
                    eprintln!("[client] this controller requires a token: pass --token <token>");
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
        // Keys confirmed during this block, drained as the verifier writes them
        // so the controller's key log is live rather than end-of-block.
        let mut block_keys: Vec<KeyRecord> = Vec::new();
        let mut rate_sample = (Instant::now(), 0u64);
        let mut smooth_pps = 0.0f64;

        let outcome = engine.scan_block(&spec, &cancel, &mut |progress| {
            if stop.load(Ordering::SeqCst) {
                return false;
            }

            // Instantaneous rate, smoothed: block averages decay over the run
            // and would make the dashboard lie late in a block.
            let now = Instant::now();
            let dt = now.duration_since(rate_sample.0).as_secs_f64();
            if dt >= 0.3 {
                let instant = progress.syns.saturating_sub(rate_sample.1) as f64 / dt;
                smooth_pps = if smooth_pps > 0.0 {
                    smooth_pps * 0.6 + instant * 0.4
                } else {
                    instant
                };
                rate_sample = (now, progress.syns);
            }

            // Telemetry every 5s: enough for a live dashboard without turning
            // the control channel into a packet stream of its own.
            if last_progress.elapsed() >= PROGRESS_INTERVAL {
                last_progress = Instant::now();
                block_keys.extend(engine.drain_keys());
                let pps = smooth_pps;
                match transport.post(
                    PATH_PROGRESS,
                    &ProgressRequest {
                        client_id: join.client_id.clone(),
                        job_id: spec.job_id,
                        pos: progress.pos,
                        syns: progress.syns,
                        synacks: progress.synacks,
                        total: progress.total,
                        hits: progress.hits,
                        keys: block_keys.len() as u64,
                        rate: pps,
                        block: spec.cidr.clone(),
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
            let pps = smooth_pps;
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
                let _ = transport.post(
                    PATH_RELEASE,
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

        // Keys drained during telemetry plus whatever landed at block end.
        let mut all_keys = block_keys;
        all_keys.extend(outcome.keys.iter().cloned());

        eprintln!(
            "\n[client] block {} {} pos {}/{} syns {} synacks {} hits {} keys {}",
            spec.job_id,
            spec.cidr,
            outcome.pos,
            outcome.total,
            outcome.syns,
            outcome.synacks,
            outcome.hits.len(),
            all_keys.len()
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
            keys: all_keys,
            syns: outcome.syns,
            synacks: outcome.synacks,
        };
        if !results.hits.is_empty() || !results.keys.is_empty() {
            if !post_results(&transport, &results) {
                spool.append(&results);
                eprintln!("[client] results spooled locally, will retry");
            }
        }

        if outcome.completed {
            match transport.post_retry(
                PATH_COMPLETE,
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
            let _ = transport.post(
                PATH_RELEASE,
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

    spool.flush(&transport);
    eprintln!("[client] {} blocks completed", blocks_done);
    if let Some(handle) = tor_handle.as_mut() {
        handle.stop();
    }
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

/// Accept `host`, `host:port`, `http://host`, `https://host`, and `.onion`
/// addresses for any of them. Returns the base URL and whether tor is needed.
pub fn normalize_url(raw: &str) -> (String, bool) {
    let raw = raw.trim();
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{}", raw)
    };
    let base = with_scheme.trim_end_matches('/').to_string();

    let needs_tor = {
        let host_part = base
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(base.as_str());
        let host = host_part.split('/').next().unwrap_or(host_part);
        // A trailing `:port` must not hide the `.onion` suffix.
        let host = match host.rsplit_once(':') {
            Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
            _ => host,
        };
        tor::is_onion_address(host)
    };

    (base, needs_tor)
}

fn join(
    transport: &Transport,
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
        match transport.post_retry(PATH_JOIN, &request, stop) {
            Some((200, body)) => match serde_json::from_str::<JoinResponse>(&body) {
                Ok(j) => return Some(j),
                Err(e) => eprintln!("[client] bad join response: {}", e),
            },
            Some((code, body)) => {
                eprintln!("[client] join rejected ({}): {}", code, body);
                if code == 401 {
                    eprintln!("[client] this controller requires a token: pass --token <token>");
                    return None;
                }
                if code == 400 {
                    // Version mismatch or malformed request: retrying will not help.
                    return None;
                }
            }
            None => eprintln!("[client] controller unreachable at {}", transport.base),
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

fn post_results(transport: &Transport, results: &ResultsRequest) -> bool {
    match transport.post(PATH_RESULTS, results) {
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

/// Where the client sends requests and how it reaches the controller.
#[derive(Clone)]
struct Transport {
    base: String,
    /// `None` for an open controller.
    token: Option<String>,
    /// SOCKS5 proxy for `.onion` targets.
    socks: Option<String>,
}

impl Transport {
    fn post_retry<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
        stop: &Arc<AtomicBool>,
    ) -> Option<(u16, String)> {
        for attempt in 0..HTTP_ATTEMPTS {
            if stop.load(Ordering::SeqCst) {
                return None;
            }
            match self.post(path, body) {
                Ok(reply) => return Some(reply),
                Err(e) => {
                    if attempt + 1 == HTTP_ATTEMPTS {
                        eprintln!("[client] {}{}: {}", self.base, path, e);
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(500 * (1 << attempt)));
                }
            }
        }
        None
    }

    fn post<T: serde::Serialize>(&self, path: &str, body: &T) -> Result<(u16, String), String> {
        let payload = serde_json::to_string(body).map_err(|e| e.to_string())?;
        let url = format!("{}{}", self.base, path);

        let mut args: Vec<String> = vec![
            "-sS".into(),
            "--connect-timeout".into(),
            "20".into(),
            "--max-time".into(),
            "90".into(),
            "-X".into(),
            "POST".into(),
            "-H".into(),
            "Expect:".into(),
            "-H".into(),
            "Content-Type: application/json".into(),
            "--data-binary".into(),
            "@-".into(),
            "-w".into(),
            "\n%{http_code}".into(),
        ];
        if let Some(token) = &self.token {
            args.push("-H".into());
            args.push(format!("Authorization: Bearer {}", token));
        }
        if let Some(socks) = &self.socks {
            // `-hostname` makes the proxy resolve the name: an onion address is
            // never looked up locally, and no DNS leak can happen.
            args.push("--socks5-hostname".into());
            args.push(socks.clone());
        }
        args.push(url);

        let mut child = Command::new("curl")
            .args(&args)
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
    fn flush(&mut self, transport: &Transport) {
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
                    if !post_results(transport, &results) {
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
            eprintln!(
                "[client] {} spooled result batch(es) still pending",
                undelivered.len()
            );
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

    #[test]
    fn urls_are_normalised_and_onion_detected() {
        let onion = format!("{}.onion", "a".repeat(56));
        assert_eq!(normalize_url(&onion), (format!("http://{}", onion), true));
        assert_eq!(
            normalize_url(&format!("https://{}/", onion)),
            (format!("https://{}", onion), true)
        );
        assert_eq!(
            normalize_url(&format!("{}.onion:8080", "b".repeat(56))),
            (format!("http://{}.onion:8080", "b".repeat(56)), true)
        );
        assert_eq!(
            normalize_url("https://zi.elaptic.dev/"),
            ("https://zi.elaptic.dev".to_string(), false)
        );
        assert_eq!(
            normalize_url("ctrl.internal:8000"),
            ("http://ctrl.internal:8000".to_string(), false)
        );
        // A hostname that merely contains "onion" is not an onion address.
        assert_eq!(
            normalize_url("onion.example.com"),
            ("http://onion.example.com".to_string(), false)
        );
    }
}
