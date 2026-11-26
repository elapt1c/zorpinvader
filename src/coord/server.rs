//! The controller: HTTP handlers around a [`Scheduler`].
//!
//! The controller never transmits. It plans the scan, hands out blocks, records
//! coverage, and writes the authoritative copy of the results. That split is why
//! a controller can run on a tiny VM (or a laptop behind a tunnel) while the
//! clients are the machines with the network path and the packet budget.

use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::main_mod::conf::{self, Zorp};

use super::http::{self, Request};
use super::plan::Plan;
use super::protocol::*;
use super::scheduler::{Claim, Options, Scheduler};
use super::set4;

/// Concurrent connection cap. Clients are few and their requests are short.
const MAX_CONNECTIONS: usize = 64;

/// How often the controller prints a status line and reaps expired leases.
const TICK: Duration = Duration::from_secs(2);

/// How often scheduler state is flushed to disk.
const SAVE_INTERVAL: Duration = Duration::from_secs(10);

type Handler = fn(&Request, &AppState) -> (u16, String);

struct AppState {
    sched: Mutex<Scheduler>,
    token: String,
    version: String,
    started: Instant,
    live_connections: AtomicUsize,
}

/// Run the controller until interrupted.
pub fn run(zorp: Arc<Zorp>) -> i32 {
    let targets = match super::targets::build(&zorp) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ERROR: {}", e);
            return 1;
        }
    };
    let ports = super::targets::ports(&zorp);
    let seed = if zorp.seed != 0 {
        zorp.seed
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    };

    let mut plan = Plan::new(&ports, targets, zorp.job_size, seed);
    plan.restrict_shard(zorp.shard.one, zorp.shard.of);
    let token = match &zorp.token {
        Some(t) if !t.trim().is_empty() => t.clone(),
        _ => http::random_token(),
    };
    let opts = Options {
        state_path: zorp.state_file.clone(),
        results_dir: zorp.results_dir.clone(),
        lease_s: zorp.lease_s,
        include_safe: zorp.include_safe,
        tpc: zorp.tpc,
        target_rate: zorp.max_rate,
        resume: zorp.auto_resume,
        reset: zorp.reset_state,
    };

    let scheduler = match Scheduler::load_or_create(plan.clone(), opts) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ERROR: {}", e);
            return 1;
        }
    };

    let bind_addr = format!("{}:{}", zorp.server_bind, zorp.server_port);
    let listener = match TcpListener::bind(&bind_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ERROR: cannot bind {}: {}", bind_addr, e);
            return 1;
        }
    };
    if let Err(e) = listener.set_nonblocking(true) {
        eprintln!("ERROR: cannot configure listener: {}", e);
        return 1;
    }

    let app = Arc::new(AppState {
        sched: Mutex::new(scheduler),
        token: token.clone(),
        version: conf::VERSION.to_string(),
        started: Instant::now(),
        live_connections: AtomicUsize::new(0),
    });

    print_banner(&plan, &bind_addr, &token, zorp.lease_s);

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        let _ = ctrlc::set_handler(move || {
            eprintln!("\n[ctrl] shutting down, saving state...");
            stop.store(true, Ordering::SeqCst);
        });
    }

    let mut last_tick = Instant::now();
    let mut last_save = Instant::now();
    let mut last_status = Instant::now();

    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                if app.live_connections.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                    let mut stream = stream;
                    http::respond_json(
                        &mut stream,
                        503,
                        &serde_json::to_string(&ErrorResponse::new("too many connections"))
                            .unwrap_or_default(),
                    );
                    continue;
                }
                let app = app.clone();
                app.live_connections.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(move || {
                    serve_connection(stream, app.clone());
                    app.live_connections.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("[ctrl] accept error: {}", e);
                std::thread::sleep(Duration::from_millis(250));
            }
        }

        if last_tick.elapsed() >= TICK {
            last_tick = Instant::now();
            app.sched.lock().reap();
        }

        let status_interval = if stderr_is_tty() {
            TICK
        } else {
            Duration::from_secs(15)
        };
        if last_status.elapsed() >= status_interval {
            last_status = Instant::now();
            print_status(&mut *app.sched.lock());
        }

        if last_save.elapsed() >= SAVE_INTERVAL {
            last_save = Instant::now();
            let mut sched = app.sched.lock();
            if sched.is_dirty() {
                if let Err(e) = sched.save() {
                    eprintln!("\n[state] save failed: {}", e);
                }
            }
        }
    }

    {
        let mut sched = app.sched.lock();
        match sched.save() {
            Ok(()) => eprintln!("\n[state] saved to {}", zorp.state_file.display()),
            Err(e) => eprintln!("\n[state] save failed: {}", e),
        }
        print_final(&sched);
    }
    0
}

fn print_banner(plan: &Plan, bind_addr: &str, token: &str, lease_s: u64) {
    eprintln!("ZorpInvader controller {} — {}", conf::VERSION, bind_addr);
    eprintln!("  ports          {}", plan.ports);
    eprintln!(
        "  targets        {} address(es) in {} CIDR(s)",
        plan.total_addresses(),
        plan.targets.to_cidrs().len()
    );
    eprintln!(
        "  blocks         {} of {} addresses",
        plan.blocks_len(),
        plan.chunk
    );
    eprintln!("  lease          {}s", lease_s);
    eprintln!("  auth token     {}", token);
    eprintln!("  endpoints      {}", PATH_CLAIM);
    eprintln!("                 {}  (human-readable status)", PATH_STATUS);
    eprintln!("  clients:");
    eprintln!(
        "    zorpinvader --client http://<this-host>/ --token {}",
        token
    );
    eprintln!("  Behind TLS, use the public URL instead of http://.");
    eprintln!();
}

fn stderr_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDERR_FILENO) == 1 }
}

fn print_status(sched: &mut Scheduler) {
    let status = sched.status();
    let eta = format_eta(status.eta_s);
    let clients = status
        .clients
        .iter()
        .filter(|c| c.idle_s < 90)
        .count() as u64;
    let line = format!(
        "[ctrl] {:>6}/{:<6} blocks {:>6.2}% | {:>5} clients {:>8.1}k pps | hits {:<6} keys {:<4} | eta {}",
        status.blocks_done,
        status.blocks_total,
        status.percent,
        clients,
        status.rate_pps / 1000.0,
        status.hits,
        status.keys,
        eta
    );
    use std::io::Write;
    // A live status line needs a terminal; when stderr is a log file, emit plain
    // lines occasionally instead of a river of carriage returns.
    if stderr_is_tty() {
        eprint!("\r\x1b[K{}", line);
    } else {
        eprintln!("{}", line);
    }
    let _ = std::io::stderr().flush();
}

fn print_final(sched: &Scheduler) {
    let coverage = sched.coverage();
    eprintln!(
        "\n[ctrl] {} of {} addresses covered ({:.2}%), {} blocks done, {} partial, {} in flight",
        coverage.addresses_done,
        coverage.addresses_total,
        coverage.percent,
        coverage.blocks_done,
        coverage.blocks_partial,
        coverage.blocks_inflight
    );
}

fn format_eta(seconds: u64) -> String {
    if seconds == 0 {
        return "--".to_string();
    }
    let h = seconds / 3600;
    let m = (seconds % 3600) / 60;
    let s = seconds % 60;
    if h > 0 {
        format!("{}h{:02}m", h, m)
    } else if m > 0 {
        format!("{}m{:02}s", m, s)
    } else {
        format!("{}s", s)
    }
}

fn serve_connection(mut stream: std::net::TcpStream, app: Arc<AppState>) {
    let request = match http::read_request(&mut stream) {
        Ok(r) => r,
        Err(e) => {
            http::respond_json(
                &mut stream,
                400,
                &serde_json::to_string(&ErrorResponse::new(e)).unwrap_or_default(),
            );
            return;
        }
    };

    let (status, body) = route(&request, &app);
    http::respond_json(&mut stream, status, &body);
}

fn route(request: &Request, app: &AppState) -> (u16, String) {
    // Unauthenticated: health and the banner. Everything else needs the token.
    if request.path == PATH_HEALTH {
        return (200, "ok".to_string());
    }
    if request.path == "/" && request.method == "GET" {
        return (200, banner_text(app));
    }

    match request.bearer() {
        Some(token) if http::token_matches(&app.token, token) => {}
        Some(_) => return (401, error_json("invalid token")),
        None => return (401, error_json("missing bearer token")),
    }

    for (method, path, handler) in ROUTES {
        if request.method == *method && request.path == *path {
            return handler(request, app);
        }
    }

    if ROUTES.iter().any(|(_, path, _)| request.path == *path) {
        return (405, error_json("method not allowed"));
    }
    (404, error_json("unknown endpoint"))
}

static ROUTES: &[(&str, &str, Handler)] = &[
    ("POST", PATH_JOIN, handle_join),
    ("POST", PATH_CLAIM, handle_claim),
    ("POST", PATH_PROGRESS, handle_progress),
    ("POST", PATH_RESULTS, handle_results),
    ("POST", PATH_COMPLETE, handle_complete),
    ("POST", PATH_RELEASE, handle_release),
    ("GET", PATH_STATUS, handle_status),
    ("GET", PATH_COVERAGE, handle_coverage),
];

fn banner_text(app: &AppState) -> String {
    let status = app.sched.lock().status();
    format!(
        "ZorpInvader controller {}\nuptime {}s\nblocks {}/{}\ncoverage {:.2}%\n",
        app.version,
        app.started.elapsed().as_secs(),
        status.blocks_done,
        status.blocks_total,
        status.percent
    )
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn handle_join(request: &Request, app: &AppState) -> (u16, String) {
    let body: JoinRequest = match request.json() {
        Ok(b) => b,
        Err(e) => return (400, error_json(&e)),
    };
    if body.api_version != 0 && body.api_version != API_VERSION {
        return (
            400,
            error_json(&format!(
                "api version mismatch: client {}, controller {}",
                body.api_version, API_VERSION
            )),
        );
    }

    let name = if body.name.trim().is_empty() {
        "unnamed".to_string()
    } else {
        body.name.trim().to_string()
    };
    let client_id = format!("{}-{:06x}", slug(&name), short_random());

    let mut sched = app.sched.lock();
    sched.register_client(&client_id, &name);
    let response = JoinResponse {
        api_version: API_VERSION,
        client_id,
        server_version: conf::VERSION.to_string(),
        ports: sched.plan.ports.clone(),
        block_size: sched.plan.chunk,
        blocks_total: sched.plan.blocks_len() as u64,
        lease_s: sched.lease_s(),
        include_safe: sched.include_safe(),
        tpc: sched.tpc(),
    };
    (200, json(&response))
}

fn handle_claim(request: &Request, app: &AppState) -> (u16, String) {
    let body: ClaimRequest = match request.json() {
        Ok(b) => b,
        Err(e) => return (400, error_json(&e)),
    };

    let mut sched = app.sched.lock();
    match sched.claim(&body.client_id) {
        Claim::Job(job) => {
            let spec = JobWire {
                job_id: job.job_id,
                begin: job.begin,
                end: job.end,
                cidr: job.cidr.clone(),
                ports: job.ports.clone(),
                rate: job.rate,
                resume_pos: job.resume_pos,
                lease_s: job.lease_s,
                include_safe: job.include_safe,
                tpc: job.tpc,
            };
            let response = ClaimResponse {
                job: Some(spec),
                rate: job.rate,
                done: false,
                blocks_remaining: sched.blocks_remaining(),
            };
            (200, json(&response))
        }
        Claim::Waiting => {
            let rate = sched.current_rate();
            let response = ClaimResponse {
                job: None,
                rate,
                done: false,
                blocks_remaining: sched.blocks_remaining(),
            };
            (200, json(&response))
        }
        Claim::Done => {
            let response = ClaimResponse {
                job: None,
                rate: 0.0,
                done: true,
                blocks_remaining: 0,
            };
            (200, json(&response))
        }
    }
}

fn handle_progress(request: &Request, app: &AppState) -> (u16, String) {
    let body: ProgressRequest = match request.json() {
        Ok(b) => b,
        Err(e) => return (400, error_json(&e)),
    };
    let mut sched = app.sched.lock();
    let (rate, cancel) = sched.progress(
        &body.client_id,
        body.job_id,
        body.pos,
        body.syns,
        body.synacks,
    );
    (
        200,
        json(&ProgressResponse { rate, cancel }),
    )
}

fn handle_results(request: &Request, app: &AppState) -> (u16, String) {
    let body: ResultsRequest = match request.json() {
        Ok(b) => b,
        Err(e) => return (400, error_json(&e)),
    };

    let mut hits = Vec::with_capacity(body.hits.len());
    for hit in &body.hits {
        if let (Some(ip), true) = (set4::parse_ipv4(&hit.ip), hit.port > 0) {
            hits.push((ip, hit.port));
        }
    }

    let mut sched = app.sched.lock();
    let (accepted_hits, accepted_keys, duplicate_hits, duplicate_keys) =
        sched.submit_results(
            &body.client_id,
            body.job_id,
            &hits,
            &body.keys,
            body.syns,
            body.synacks,
        );
    (
        200,
        json(&ResultsResponse {
            accepted_hits,
            accepted_keys,
            duplicate_hits,
            duplicate_keys,
        }),
    )
}

fn handle_complete(request: &Request, app: &AppState) -> (u16, String) {
    let body: CompleteRequest = match request.json() {
        Ok(b) => b,
        Err(e) => return (400, error_json(&e)),
    };
    let mut sched = app.sched.lock();
    match sched.complete(&body.client_id, body.job_id, body.pos, body.syns, body.synacks) {
        Ok(duplicate) => (
            200,
            json(&CompleteResponse {
                ok: true,
                duplicate,
                blocks_remaining: sched.blocks_remaining(),
            }),
        ),
        Err(e) => (400, error_json(&e)),
    }
}

fn handle_release(request: &Request, app: &AppState) -> (u16, String) {
    let body: ReleaseRequest = match request.json() {
        Ok(b) => b,
        Err(e) => return (400, error_json(&e)),
    };
    let mut sched = app.sched.lock();
    sched.release(&body.client_id, body.job_id, body.pos);
    if !body.reason.is_empty() {
        eprintln!("\n[ctrl] {} released block {}: {}", body.client_id, body.job_id, body.reason);
    }
    (200, json(&serde_json::json!({ "ok": true })))
}

fn handle_status(_request: &Request, app: &AppState) -> (u16, String) {
    let status = app.sched.lock().status();
    (200, json(&status))
}

fn handle_coverage(_request: &Request, app: &AppState) -> (u16, String) {
    let coverage = app.sched.lock().coverage();
    (200, json(&coverage))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|e| error_json(&e.to_string()))
}

fn error_json(message: &str) -> String {
    serde_json::to_string(&ErrorResponse::new(message))
        .unwrap_or_else(|_| "{\"error\":\"internal\"}".to_string())
}

fn slug(name: &str) -> String {
    let mut out: String = name
        .chars()
        .take(24)
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect();
    if out.is_empty() {
        out.push_str("client");
    }
    out
}

fn short_random() -> u32 {
    use rand::Rng;
    rand::thread_rng().gen::<u32>()
}
