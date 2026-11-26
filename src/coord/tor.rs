//! Tor transport: an onion service for the controller, SOCKS5 for clients.
//!
//! # Why a supervised `tor` process and not a Tor library
//!
//! Speaking the Tor protocol in-process is not something this binary should
//! attempt: the onion-service half (descriptor publication, introduction points,
//! rendezvous) is the part every "just use a library" plan underestimates. Arti,
//! the Rust implementation, still marks onion-service *hosting* experimental and
//! ships it behind `__is_experimental` APIs, and the C tor is the only
//! implementation with a track record of publishing hidden services.
//!
//! So this module supervises a real `tor` binary instead:
//!
//! * it never downloads anything — a missing binary is a clear, actionable error;
//! * every instance gets its own `DataDirectory`, SOCKS port and hidden-service
//!   keys, so it cannot collide with a tor the user already runs;
//! * a pidfile lets a later run reap a tor that outlived a crash;
//! * an already-running SOCKS proxy (9050/9150) is detected and reused, verified
//!   with a real SOCKS5 handshake instead of assuming the port is tor.
//!
//! Both roles bootstrap the same way: wait for `Bootstrapped 100%` in the log,
//! then hand back either the `.onion` address (controller) or the SOCKS address
//! (client).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Ports where a user-managed tor usually listens.
pub const COMMON_SOCKS_PORTS: [u16; 2] = [9050, 9150];

/// Virtual port the onion service answers on, so the address is just `x.onion`.
const ONION_VPORT: &str = "80";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TorMode {
    /// Off unless `--tor` was asked for.
    #[default]
    Off,
    /// Use tor when it makes sense (`.onion` target on a client, `--tor` on a
    /// controller) and fall back to plain TCP only for non-onion targets.
    Auto,
    /// Fail when tor is unavailable instead of falling back.
    Required,
}

#[derive(Clone, Debug)]
pub struct TorConfig {
    pub mode: TorMode,
    /// Explicit tor binary; otherwise `$PATH` and the usual sbin locations.
    pub binary: Option<PathBuf>,
    /// Existing SOCKS endpoint (`host:port`) to use instead of starting tor.
    pub socks: Option<String>,
    /// Where this instance keeps its DataDirectory, log, pidfile and HS keys.
    pub data_dir: PathBuf,
    pub timeout: Duration,
}

impl TorConfig {
    pub fn new(data_dir: PathBuf) -> Self {
        TorConfig {
            mode: TorMode::Off,
            binary: None,
            socks: None,
            data_dir,
            timeout: Duration::from_secs(180),
        }
    }
}

/// What a started tor gives us.
pub struct TorHandle {
    /// `.onion` address (controller role).
    pub onion: Option<String>,
    /// `host:port` of a SOCKS5 proxy usable for `.onion` connections.
    pub socks: Option<String>,
    /// True when this process owns the tor instance and must stop it.
    pub managed: bool,
    child: Option<ManagedTor>,
}

impl TorHandle {
    pub fn stop(&mut self) {
        if let Some(child) = self.child.take() {
            child.stop();
        }
    }

    /// Endpoint to print in the banner and write to the progress file.
    pub fn describe(&self) -> String {
        match (&self.onion, &self.socks) {
            (Some(onion), Some(socks)) => format!("{} (socks {})", onion, socks),
            (Some(onion), None) => onion.clone(),
            (None, Some(socks)) => format!("socks {}", socks),
            (None, None) => "tor (not started)".to_string(),
        }
    }
}

impl Drop for TorHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

struct ManagedTor {
    child: Child,
    pidfile: PathBuf,
    logfile: PathBuf,
}

impl ManagedTor {
    fn stop(mut self) {
        // SIGTERM so tor can tear down its circuits and release the HS ports.
        unsafe {
            libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                _ if Instant::now() >= deadline => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
                _ => std::thread::sleep(Duration::from_millis(100)),
            }
        }
        let _ = std::fs::remove_file(&self.pidfile);
    }
}

/// Start tor and publish the controller on an onion service.
pub fn start_server(listen_port: u16, cfg: &TorConfig) -> Result<TorHandle, String> {
    let binary = find_tor_binary(cfg)?;
    std::fs::create_dir_all(&cfg.data_dir).map_err(|e| format!("{}: {}", cfg.data_dir.display(), e))?;
    let data_dir = canonical(&cfg.data_dir);
    reap_stale_tor(&data_dir);

    let hs_dir = data_dir.join("hidden_service");
    let logfile = data_dir.join("tor.log");
    let _ = std::fs::remove_file(&logfile);
    if let Some(parent) = hs_dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    // tor wants to create the HS dir itself, but its parent must exist.
    set_private_dir(&data_dir);

    let mut cmd = Command::new(&binary);
    cmd.arg("--SocksPort")
        .arg("0")
        .arg("--DataDirectory")
        .arg(&data_dir)
        .arg("--Log")
        .arg(format!("notice file {}", logfile.display()))
        .arg("--HiddenServiceDir")
        .arg(&hs_dir)
        .arg("--HiddenServicePort")
        .arg(format!("{} 127.0.0.1:{}", ONION_VPORT, listen_port))
        .arg("--ClientOnly")
        .arg("1")
        .arg("--AvoidDiskWrites")
        .arg("1")
        .arg("--CookieAuthentication")
        .arg("0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let child = spawn(cmd, &binary)?;
    let pidfile = write_pidfile(&data_dir, child.id())?;
    let managed = ManagedTor {
        child,
        pidfile,
        logfile: logfile.clone(),
    };

    eprintln!("[tor] publishing hidden service on 127.0.0.1:{}", listen_port);
    wait_for_bootstrap(&managed, cfg.timeout)?;

    let hostname_path = hs_dir.join("hostname");
    let onion = wait_for_hostname(&hostname_path, cfg.timeout)?;
    eprintln!("[tor] onion service ready: {}", onion);

    Ok(TorHandle {
        onion: Some(onion),
        socks: None,
        managed: true,
        child: Some(managed),
    })
}

/// Start (or reuse) tor so `.onion` URLs can be reached from this client.
pub fn start_client(cfg: &TorConfig) -> Result<TorHandle, String> {
    // An endpoint the user pointed at wins, as long as it actually speaks SOCKS5.
    if let Some(socks) = &cfg.socks {
        if probe_socks(socks) {
            return Ok(TorHandle {
                onion: None,
                socks: Some(socks.clone()),
                managed: false,
                child: None,
            });
        }
        return Err(format!(
            "--tor-socks {} does not answer a SOCKS5 handshake",
            socks
        ));
    }

    // Reuse a tor the user already runs rather than starting a second one.
    for port in COMMON_SOCKS_PORTS {
        let addr = format!("127.0.0.1:{}", port);
        if probe_socks(&addr) {
            log::info!("[tor] reusing SOCKS proxy at {}", addr);
            return Ok(TorHandle {
                onion: None,
                socks: Some(addr),
                managed: false,
                child: None,
            });
        }
    }

    let binary = find_tor_binary(cfg)?;
    std::fs::create_dir_all(&cfg.data_dir).map_err(|e| format!("{}: {}", cfg.data_dir.display(), e))?;
    let data_dir = canonical(&cfg.data_dir);
    reap_stale_tor(&data_dir);
    set_private_dir(&data_dir);

    let logfile = data_dir.join("tor.log");
    let _ = std::fs::remove_file(&logfile);
    let socks_port = free_port()?;

    let mut cmd = Command::new(&binary);
    cmd.arg("--SocksPort")
        .arg(format!("127.0.0.1:{}", socks_port))
        .arg("--DataDirectory")
        .arg(&data_dir)
        .arg("--Log")
        .arg(format!("notice file {}", logfile.display()))
        .arg("--ClientOnly")
        .arg("1")
        .arg("--AvoidDiskWrites")
        .arg("1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let child = spawn(cmd, &binary)?;
    let pidfile = write_pidfile(&data_dir, child.id())?;
    let managed = ManagedTor {
        child,
        pidfile,
        logfile: logfile.clone(),
    };

    eprintln!(
        "[tor] starting {} (socks 127.0.0.1:{}, data {})",
        binary.display(),
        socks_port,
        data_dir.display()
    );
    wait_for_bootstrap(&managed, cfg.timeout)?;

    Ok(TorHandle {
        onion: None,
        socks: Some(format!("127.0.0.1:{}", socks_port)),
        managed: true,
        child: Some(managed),
    })
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn spawn(mut cmd: Command, binary: &Path) -> Result<Child, String> {
    cmd.spawn()
        .map_err(|e| format!("cannot start {}: {}", binary.display(), e))
}

fn find_tor_binary(cfg: &TorConfig) -> Result<PathBuf, String> {
    if let Some(binary) = &cfg.binary {
        if binary.is_file() {
            return Ok(binary.clone());
        }
        return Err(format!("--tor-binary {} does not exist", binary.display()));
    }

    for candidate in ["/usr/bin/tor", "/usr/sbin/tor", "/usr/local/bin/tor", "/opt/homebrew/bin/tor"] {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Ok(path);
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let path = PathBuf::from(dir).join("tor");
            if path.is_file() {
                return Ok(path);
            }
        }
    }

    Err("tor is not installed. ZorpInvader supervises a real tor rather than \
         reimplementing the Tor protocol; install it and retry:\n  \
         Debian/Ubuntu: sudo apt install tor\n  \
         Fedora:        sudo dnf install tor\n  \
         macOS:         brew install tor\n\
         Or point at an existing instance with --tor-socks 127.0.0.1:9050."
        .to_string())
}

fn canonical(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn set_private_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

fn write_pidfile(data_dir: &Path, pid: u32) -> Result<PathBuf, String> {
    let pidfile = data_dir.join("zorpinvader-tor.pid");
    std::fs::write(&pidfile, format!("{}", pid))
        .map_err(|e| format!("{}: {}", pidfile.display(), e))?;
    Ok(pidfile)
}

/// Reap a tor left behind by a crashed run that used the same data directory.
fn reap_stale_tor(data_dir: &Path) {
    let pidfile = data_dir.join("zorpinvader-tor.pid");
    let pid: i32 = match std::fs::read_to_string(&pidfile)
        .ok()
        .and_then(|s| s.trim().parse().ok())
    {
        Some(pid) => pid,
        None => {
            let _ = std::fs::remove_file(&pidfile);
            return;
        }
    };
    if pid <= 1 {
        let _ = std::fs::remove_file(&pidfile);
        return;
    }

    // Only kill it if it is really *our* tor: same data directory on its
    // command line. Never signal an unrelated pid.
    let cmdline = std::fs::read(format!("/proc/{}/cmdline", pid)).unwrap_or_default();
    let needle = data_dir.as_os_str().to_string_lossy().to_string();
    let looks_like_ours = cmdline
        .split(|b| *b == 0)
        .any(|arg| String::from_utf8_lossy(arg).contains(&needle))
        && String::from_utf8_lossy(&cmdline).contains("tor");

    if looks_like_ours {
        eprintln!("[tor] reaping stale tor (pid {})", pid);
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
        for _ in 0..50 {
            if !Path::new(&format!("/proc/{}", pid)).exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if Path::new(&format!("/proc/{}", pid)).exists() {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
        }
    }
    let _ = std::fs::remove_file(&pidfile);
}

/// Wait until tor reports a complete bootstrap, surfacing progress on stderr.
fn wait_for_bootstrap(managed: &ManagedTor, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    let mut last_pct = 0u64;

    while started.elapsed() < timeout {
        if let Ok(text) = std::fs::read_to_string(&managed.logfile) {
            if text.contains("Bootstrapped 100%") {
                if is_tty() {
                    eprint!("\r\x1b[K");
                }
                return Ok(());
            }
            if let Some(pct) = last_bootstrap_percent(&text) {
                if pct != last_pct {
                    last_pct = pct;
                    if is_tty() {
                        eprint!("\r\x1b[K[tor] bootstrapped {}%", pct);
                    } else if pct % 25 == 0 {
                        eprintln!("[tor] bootstrapped {}%", pct);
                    }
                }
            }
            for marker in ["Problem bootstrapping", "Fatal", "Could not bind"] {
                if let Some(line) = text.lines().find(|l| l.contains(marker)) {
                    return Err(format!("tor failed: {}", line.trim()));
                }
            }
        }

        if !process_alive(managed.child.id()) {
            return Err(format!(
                "tor exited during bootstrap; see {}",
                managed.logfile.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    Err(format!(
        "tor did not bootstrap within {}s; see {}",
        timeout.as_secs(),
        managed.logfile.display()
    ))
}

fn process_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

fn last_bootstrap_percent(log: &str) -> Option<u64> {
    let mut last = None;
    for line in log.lines() {
        if let Some(idx) = line.find("Bootstrapped ") {
            let rest = &line[idx + "Bootstrapped ".len()..];
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(pct) = digits.parse() {
                last = Some(pct);
            }
        }
    }
    last
}

fn wait_for_hostname(path: &Path, timeout: Duration) -> Result<String, String> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if let Ok(text) = std::fs::read_to_string(path) {
            let onion = text.trim().to_string();
            if is_onion_address(&onion) {
                return Ok(onion);
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(format!(
        "tor did not publish a hostname at {} within {}s",
        path.display(),
        timeout.as_secs()
    ))
}

pub fn is_onion_address(address: &str) -> bool {
    let host = address.trim().trim_end_matches('.');
    match host.strip_suffix(".onion") {
        Some(base) => {
            (base.len() == 56 || base.len() == 16)
                && base.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        }
        None => false,
    }
}

/// A real SOCKS5 greeting, so we never mistake an open port for a usable proxy.
pub fn probe_socks(addr: &str) -> bool {
    let socket = match addr.parse() {
        Ok(socket) => socket,
        Err(_) => match addr.rsplit_once(':') {
            Some((host, port)) => match port.parse::<u16>() {
                Ok(port) => match format!("{}:{}", host, port).parse() {
                    Ok(socket) => socket,
                    Err(_) => return false,
                },
                Err(_) => return false,
            },
            None => return false,
        },
    };

    let mut stream = match TcpStream::connect_timeout(&socket, Duration::from_secs(3)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    // Greeting: version 5, one method, no auth.
    if stream.write_all(&[0x05, 0x01, 0x00]).is_err() {
        return false;
    }
    let mut reply = [0u8; 2];
    if stream.read_exact(&mut reply).is_err() {
        return false;
    }
    reply == [0x05, 0x00]
}

fn free_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    drop(listener);
    Ok(port)
}

fn is_tty() -> bool {
    unsafe { libc::isatty(libc::STDERR_FILENO) == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn recognises_onion_addresses() {
        let v3 = format!("{}.onion", "a".repeat(56));
        assert!(is_onion_address(&v3));
        assert!(is_onion_address(&format!("{}\n", v3)));
        assert!(is_onion_address(&format!("{}.onion.", "b".repeat(56))));
        assert!(is_onion_address("expyuzz4wqqyqhjn.onion")); // v2-shaped, 16 chars
        assert!(!is_onion_address("example.com"));
        assert!(!is_onion_address(&format!("{}.onion", "A".repeat(56))));
        assert!(!is_onion_address(&format!("{}.onion", "a".repeat(55))));
    }

    #[test]
    fn parses_bootstrap_progress() {
        let log = "\
Nov 26 00:39:11.000 [notice] Bootstrapped 10% (conn_done): Connected to a relay
Nov 26 00:39:12.000 [notice] Bootstrapped 75% (enough_dirinfo): Loaded enough directory info
";
        assert_eq!(last_bootstrap_percent(log), Some(75));
        assert!(log.contains("Bootstrapped 10%"));
        assert!(!log.contains("Bootstrapped 100%"));
    }

    #[test]
    fn socks5_probe_rejects_non_socks_and_accepts_socks() {
        // A listener that answers the greeting correctly.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 3];
            stream.read_exact(&mut buf).unwrap();
            assert_eq!(buf, [0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).unwrap();
        });
        assert!(probe_socks(&addr));
        handle.join().unwrap();

        // A listener that closes immediately is not a SOCKS proxy.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let _ = listener.accept();
        });
        assert!(!probe_socks(&addr));

        // Nothing listening at all.
        assert!(!probe_socks("127.0.0.1:1"));
        assert!(!probe_socks("not-an-address"));
    }

    #[test]
    fn free_port_returns_a_bindable_port() {
        let port = free_port().unwrap();
        assert!(port > 0);
        let _ = TcpListener::bind(("127.0.0.1", port)).expect("port should be free");
    }

    #[test]
    fn missing_binary_is_an_actionable_error() {
        let cfg = TorConfig {
            binary: Some(PathBuf::from("/nonexistent/tor")),
            ..TorConfig::new(std::env::temp_dir().join("zorp-tor-test"))
        };
        let err = find_tor_binary(&cfg).unwrap_err();
        assert!(err.contains("does not exist"), "got: {}", err);
    }
}
