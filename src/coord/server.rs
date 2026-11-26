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

use super::dashboard::{self, Dashboard};
use super::http::{self, Request};
use super::plan::Plan;
use super::protocol::*;
use super::scheduler::{Claim, ConnectionInfo, Options, Scheduler};
use super::set4;
use super::tor::{self, TorConfig, TorMode};

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

    let mut scheduler = match Scheduler::load_or_create(plan.clone(), opts) {
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

    // Publish over tor when asked. The onion address is part of the progress
    // file, so a worker can be started from that file alone.
    let tor_cfg = TorConfig {
        mode: if zorp.tor { TorMode::Required } else { TorMode::Off },
        binary: zorp.tor_binary.clone(),
        socks: None,
        data_dir: zorp.tor_dir.clone().unwrap_or_else(|| {
            let parent = zorp
                .state_file
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            parent.join("tor")
        }),
        timeout: Duration::from_secs(zorp.tor_timeout),
    };
    let mut tor_handle = if zorp.tor {
        match tor::start_server(zorp.server_port, &tor_cfg) {
            Ok(handle) => Some(handle),
            Err(e) => {
                eprintln!("ERROR: {}", e);
                return 1;
            }
        }
    } else {
        None
    };

    let listen = format!("{}:{}", zorp.server_bind, zorp.server_port);
    let onion = tor_handle.as_ref().and_then(|t| t.onion.clone());
    let url = match &onion {
        Some(onion) => format!("http://{}", onion),
        None => format!("http://{}:{}", display_host(&zorp.server_bind), zorp.server_port),
    };
    let connection = ConnectionInfo {
        listen: listen.clone(),
        onion: onion.clone(),
        url: url.clone(),
        token: token.clone(),
        // A bare onion address is what a human copies; the scheme is optional.
        connect: match &onion {
            Some(onion) => format!("zorpinvader --client {} --token {}", onion, token),
            None => format!("zorpinvader --client {} --token {}", url, token),
        },
    };
    scheduler.set_connection(connection.clone());
    if let Err(e) = scheduler.save() {
        eprintln!("[state] save failed: {}", e);
    }

    let app = Arc::new(AppState {
        sched: Mutex::new(scheduler),
        token: token.clone(),
        version: conf::VERSION.to_string(),
        started: Instant::now(),
        live_connections: AtomicUsize::new(0),
    });

    print_banner(&plan, &bind_addr, &token, zorp.lease_s, &connection, &zorp.state_file);

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
    let mut dashboard = Dashboard::new();
    let interactive = dashboard::stderr_is_tty();
    let status_interval = if interactive {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(15)
    };

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

        if last_status.elapsed() >= status_interval {
            last_status = Instant::now();
            // Take a snapshot under the lock, then draw outside it.
            let (status, keys) = {
                let mut sched = app.sched.lock();
                (sched.status(), sched.key_events().clone())
            };
            if interactive {
                dashboard.render(&status, Some(&connection), &keys);
            } else {
                dashboard.render_plain(&status, Some(&connection));
            }
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
    // Stop the tor we started; a supervised instance must not outlive us.
    if let Some(handle) = tor_handle.as_mut() {
        handle.stop();
    }
    0
}

/// A bind address of `0.0.0.0` is not something a client can dial, so advertise
/// the machine's primary IPv4 instead. A UDP `connect` only consults the routing
/// table; it sends no packets.
fn display_host(bind: &str) -> String {
    match bind {
        "0.0.0.0" | "::" | "" => primary_ipv4().unwrap_or_else(|| "127.0.0.1".to_string()),
        other => other.to_string(),
    }
}

fn primary_ipv4() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:53").ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => {
            Some(ip.to_string())
        }
        _ => None,
    }
}

fn print_banner(
    plan: &Plan,
    bind_addr: &str,
    token: &str,
    lease_s: u64,
    connection: &ConnectionInfo,
    state_path: &std::path::Path,
) {
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
    match &connection.onion {
        Some(onion) => eprintln!("  onion          {}", onion),
        None => eprintln!("  onion          (not published; pass --tor)"),
    }
    eprintln!("  progress file  {}", state_path.display());
    eprintln!("  endpoints      {}", PATH_CLAIM);
    eprintln!("                 {}  (human-readable status)", PATH_STATUS);
    eprintln!("  connect a worker:");
    eprintln!("    {}", connection.connect);
    eprintln!("  Progress, token and onion address are in the progress file:");
    eprintln!("    cat {}", state_path.display());
    eprintln!();
}

fn print_final(sched: &Scheduler) {
    let coverage = sched.coverage();
    match sched.connection() {
        Some(conn) => eprintln!("[ctrl] worker command: {}", conn.connect),
        None => {}
    }
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
        body.total,
        body.hits,
        body.keys,
        body.rate,
        &body.block,
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
