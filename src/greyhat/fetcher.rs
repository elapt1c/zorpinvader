//! HTTP fetcher: receives (ip, port) targets, fetches pages, extracts
//! `<script>` tags, fetches referenced JavaScript, and feeds everything
//! through the [`GreyhatScanner`].

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crossbeam_queue::ArrayQueue;
use parking_lot::Condvar;

use crate::massip::addr::IpAddress;

use super::greyhat::GreyhatScanner;
use super::verifier::Verifier;

// ---------------------------------------------------------------------------
// CDN detection
// ---------------------------------------------------------------------------

/// Well-known CDN hostnames whose scripts are unlikely to contain
/// site-specific API keys and are therefore skipped.
const CDN_HOSTS: &[&str] = &[
    "cloudflare.com",
    "googleapis.com",
    "googletagmanager.com",
    "google-analytics.com",
    "jsdelivr.net",
    "unpkg.com",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "ajax.googleapis.com",
    "code.jquery.com",
    "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com",
    "bootcdn.net",
    "cdn.bootcss.com",
    "polyfill.io",
    "facebook.net",
    "connect.facebook.net",
    "twimg.com",
    "platform.twitter.com",
    "assets.adobedtm.com",
    "hotjar.com",
    "static.hotjar.com",
];

fn is_cdn_url(url: &str) -> bool {
    CDN_HOSTS.iter().any(|host| url.contains(host))
}

// ---------------------------------------------------------------------------
// Fetcher stats
// ---------------------------------------------------------------------------

/// Atomic counters for fetcher activity.
pub struct FetcherStats {
    pub pages_fetched: AtomicU64,
    pub scripts_fetched: AtomicU64,
    pub gzip_bodies: AtomicU64,
    pub html_bodies: AtomicU64,
    pub script_tags_found: AtomicU64,
    pub script_cdn_skipped: AtomicU64,
    pub script_dns_failed: AtomicU64,
    pub script_fetched_ok: AtomicU64,
}

impl Default for FetcherStats {
    fn default() -> Self {
        Self::new()
    }
}

impl FetcherStats {
    pub fn new() -> Self {
        Self {
            pages_fetched: AtomicU64::new(0),
            scripts_fetched: AtomicU64::new(0),
            gzip_bodies: AtomicU64::new(0),
            html_bodies: AtomicU64::new(0),
            script_tags_found: AtomicU64::new(0),
            script_cdn_skipped: AtomicU64::new(0),
            script_dns_failed: AtomicU64::new(0),
            script_fetched_ok: AtomicU64::new(0),
        }
    }

    pub fn pages(&self) -> u64 { self.pages_fetched.load(Ordering::Relaxed) }
    pub fn scripts(&self) -> u64 { self.scripts_fetched.load(Ordering::Relaxed) }
    pub fn gzip(&self) -> u64 { self.gzip_bodies.load(Ordering::Relaxed) }
    pub fn html_bodies(&self) -> u64 { self.html_bodies.load(Ordering::Relaxed) }
    pub fn script_tags(&self) -> u64 { self.script_tags_found.load(Ordering::Relaxed) }
    pub fn script_cdn(&self) -> u64 { self.script_cdn_skipped.load(Ordering::Relaxed) }
    pub fn script_dns_fail(&self) -> u64 { self.script_dns_failed.load(Ordering::Relaxed) }
    pub fn script_ok(&self) -> u64 { self.script_fetched_ok.load(Ordering::Relaxed) }
}

// ---------------------------------------------------------------------------
// Job queue
// ---------------------------------------------------------------------------

/// A pending HTTP fetch job.
#[derive(Debug, Clone)]
struct FetchJob {
    ip: String,
    port: u16,
}

/// Bounded queue for fetch jobs; drops the oldest job when full.
const QUEUE_SIZE: usize = 8192;

// ---------------------------------------------------------------------------
// Fetcher
// ---------------------------------------------------------------------------

/// Multi-threaded HTTP fetcher that:
/// 1. Fetches the root page of `http://<ip>:<port>/`
/// 2. Scans the HTML body for API keys
/// 3. Extracts `<script src="…">` tags
/// 4. Fetches non-CDN JavaScript files and scans them too
pub struct Fetcher {
    queue: Arc<ArrayQueue<FetchJob>>,
    stats: Arc<FetcherStats>,
    scanner: Arc<GreyhatScanner>,
    verifier: Arc<Verifier>,
    num_threads: usize,
    running: Arc<(parking_lot::Mutex<bool>, Condvar)>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Fetcher {
    /// Create and start the fetcher with `threads_per_core` workers per CPU
    /// core (capped at 32 total threads).
    pub fn new(scanner: Arc<GreyhatScanner>, verifier: Arc<Verifier>, threads_per_core: Option<usize>) -> Self {
        let nc = num_cpus().max(1);
        let tpc = threads_per_core.unwrap_or(16);
        let num_threads = (nc * tpc).min(32);

        let queue = Arc::new(ArrayQueue::<FetchJob>::new(QUEUE_SIZE));
        let stats = Arc::new(FetcherStats::new());
        let running_flag = Arc::new((parking_lot::Mutex::new(true), Condvar::new()));

        let mut threads = Vec::with_capacity(num_threads);
        for _ in 0..num_threads {
            let q = Arc::clone(&queue);
            let s = Arc::clone(&stats);
            let sc = Arc::clone(&scanner);
            let v = Arc::clone(&verifier);
            let rf = Arc::clone(&running_flag);
            threads.push(std::thread::spawn(move || {
                worker_loop(q, s, sc, v, rf);
            }));
        }

        log::info!("[fetcher] {} workers on {} cores", num_threads, nc);

        Self {
            queue,
            stats,
            scanner,
            verifier,
            num_threads,
            running: running_flag,
            threads,
        }
    }

    /// Borrow the fetcher statistics.
    pub fn stats(&self) -> &FetcherStats {
        &self.stats
    }

    /// Submit an (ip, port) target for HTTP fetching.
    pub fn submit(&self, ip: &str, port: u16) {
        let job = FetchJob {
            ip: ip.to_string(),
            port,
        };
        // Best-effort push; if the queue is full, pop the oldest then retry.
        if self.queue.push(job.clone()).is_err() {
            let _ = self.queue.pop(); // drop oldest
            let _ = self.queue.push(job);
        }

        // Wake a worker
        let (lock, cvar) = &*self.running;
        let _guard = lock.lock();
        cvar.notify_one();
    }

    /// Shut down all worker threads and wait for them to finish.
    pub fn shutdown(mut self) {
        {
            let (lock, cvar) = &*self.running;
            let mut flag = lock.lock();
            *flag = false;
            cvar.notify_all();
        }
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }

    /// Current queue depth.
    pub fn queue_depth(&self) -> usize {
        self.queue.len()
    }
}

// ---------------------------------------------------------------------------
// Worker loop
// ---------------------------------------------------------------------------

fn worker_loop(
    queue: Arc<ArrayQueue<FetchJob>>,
    stats: Arc<FetcherStats>,
    scanner: Arc<GreyhatScanner>,
    verifier: Arc<Verifier>,
    running: Arc<(parking_lot::Mutex<bool>, Condvar)>,
) {
    loop {
        // Try to pop a job; if queue empty, wait or exit.
        let job = loop {
            if let Some(j) = queue.pop() {
                break j;
            }
            let (lock, cvar) = &*running;
            let guard = lock.lock();
            if !*guard {
                return;
            }
            // Wait briefly, then retry
            let _ = cvar.wait_for(&mut { guard }, Duration::from_millis(100));
        };

        let url = format!("http://{}:{}/", job.ip, job.port);
        if let Some(body) = http_get(&url) {
            process_html(&job.ip, job.port, &body, &stats, &scanner, &verifier);
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/// Fetch a URL via `curl` subprocess, returning the body bytes.
fn http_get(url: &str) -> Option<Vec<u8>> {
    let output = Command::new("/usr/bin/curl")
        .args([
            "-s", "-L",
            "-m", "4",
            "--connect-timeout", "2",
            "-A", "ZorpInvader/1.0",
            url,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if output.stdout.is_empty() {
        return None;
    }
    Some(output.stdout)
}

// ---------------------------------------------------------------------------
// HTML processing
// ---------------------------------------------------------------------------

/// Process an HTML response body: scan it for API keys, then extract and
/// fetch referenced `<script src="…">` files and scan those too.
fn process_html(
    ip: &str,
    port: u16,
    html: &[u8],
    stats: &FetcherStats,
    scanner: &GreyhatScanner,
    verifier: &Verifier,
) {
    if html.len() < 16 {
        return;
    }

    // Detect gzip-compressed responses (magic bytes 0x1f 0x8b)
    if html.len() > 2 && html[0] == 0x1f && html[1] == 0x8b {
        stats.gzip_bodies.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // Reject binary content: null bytes in the first 4 KB
    if html[..html.len().min(4096)].contains(&0) {
        return;
    }

    stats.pages_fetched.fetch_add(1, Ordering::Relaxed);
    scanner.stats().total_sites_checked.fetch_add(1, Ordering::Relaxed);
    scanner.stats().total_html_sites.fetch_add(1, Ordering::Relaxed);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    scanner.stats().last_html_time.store(now, Ordering::Relaxed);

    // Check for HTML markers
    let lower = ascii_lowercase(html);
    if lower.contains("<script")
        || lower.contains("<html")
        || lower.contains("<body")
        || lower.contains("<head")
    {
        stats.html_bodies.fetch_add(1, Ordering::Relaxed);
    }

    // Parse the IP into an IpAddress for the scanner
    let ip_addr = parse_ipv4(ip);

    // Scan the full HTML body for inline keys
    scanner.scan(ip_addr, html, verifier);

    // Extract <script src="…"> tags (up to 10 per page)
    let mut pos = 0usize;
    let mut script_count = 0u32;

    while script_count < 10 {
        // Find next "<script" (case-insensitive)
        let tag_start = match find_ci(html, pos, b"<script") {
            Some(p) => p,
            None => break,
        };

        stats.script_tags_found.fetch_add(1, Ordering::Relaxed);
        pos = tag_start + 7; // skip past "<script"

        // Find closing '>'
        let tag_end = match html[pos..].iter().position(|&b| b == b'>') {
            Some(off) => pos + off,
            None => break,
        };

        let tag_slice = &html[pos..tag_end];

        // Look for src= within this tag
        if let Some(src_rel) = find_ci(tag_slice, 0, b"src") {
            let mut i = src_rel + 3;
            // skip whitespace
            while i < tag_slice.len() && (tag_slice[i] == b' ' || tag_slice[i] == b'\t') {
                i += 1;
            }
            if i < tag_slice.len() && tag_slice[i] == b'=' {
                i += 1;
            }
            while i < tag_slice.len() && (tag_slice[i] == b' ' || tag_slice[i] == b'\t') {
                i += 1;
            }
            if i < tag_slice.len() && (tag_slice[i] == b'"' || tag_slice[i] == b'\'') {
                let quote = tag_slice[i];
                i += 1;
                if let Some(end_q) = tag_slice[i..].iter().position(|&b| b == quote) {
                    let src_bytes = &tag_slice[i..i + end_q];
                    if let Ok(src) = std::str::from_utf8(src_bytes) {
                        let url = resolve_url(ip, port, src);
                        if is_cdn_url(&url) {
                            stats.script_cdn_skipped.fetch_add(1, Ordering::Relaxed);
                        } else if let Some(js_body) = http_get(&url) {
                            stats.scripts_fetched.fetch_add(1, Ordering::Relaxed);
                            stats.script_fetched_ok.fetch_add(1, Ordering::Relaxed);
                            scanner.scan(
                                ip_addr,
                                &js_body,
                                verifier,
                            );
                        } else {
                            stats.script_dns_failed.fetch_add(1, Ordering::Relaxed);
                        }
                        script_count += 1;
                    }
                }
            }
        }

        pos = tag_end + 1;
    }
}

// ---------------------------------------------------------------------------
// URL resolution
// ---------------------------------------------------------------------------

/// Resolve a script `src` attribute to an absolute URL.
fn resolve_url(ip: &str, port: u16, src: &str) -> String {
    if src.starts_with('/') {
        format!("http://{}:{}{}", ip, port, src)
    } else if src.contains("://") {
        src.to_string()
    } else {
        format!("http://{}:{}/{}", ip, port, src)
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Case-insensitive byte-sequence search within `haystack` starting at `offset`.
fn find_ci(haystack: &[u8], offset: usize, needle: &[u8]) -> Option<usize> {
    let nlen = needle.len();
    if haystack.len() < offset + nlen {
        return None;
    }
    for i in offset..=(haystack.len() - nlen) {
        let mut matched = true;
        for j in 0..nlen {
            if haystack[i + j].to_ascii_lowercase() != needle[j].to_ascii_lowercase() {
                matched = false;
                break;
            }
        }
        if matched {
            return Some(i);
        }
    }
    None
}

/// Lowercase ASCII bytes into a String (lossy).
fn ascii_lowercase(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii() {
                (b as char).to_ascii_lowercase()
            } else {
                '?'
            }
        })
        .collect()
}

/// Parse a dotted-quad IPv4 string into an [`IpAddress`].
fn parse_ipv4(ip: &str) -> IpAddress {
    let parts: Vec<u32> = ip
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    if parts.len() == 4 {
        let v4 = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
        IpAddress::V4(v4)
    } else {
        IpAddress::V4(0)
    }
}

/// Return the number of available CPU cores.
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_url_absolute() {
        assert_eq!(
            resolve_url("1.2.3.4", 80, "/js/app.js"),
            "http://1.2.3.4:80/js/app.js"
        );
    }

    #[test]
    fn test_resolve_url_full() {
        assert_eq!(
            resolve_url("1.2.3.4", 80, "https://cdn.example.com/x.js"),
            "https://cdn.example.com/x.js"
        );
    }

    #[test]
    fn test_resolve_url_relative() {
        assert_eq!(
            resolve_url("1.2.3.4", 8080, "app.js"),
            "http://1.2.3.4:8080/app.js"
        );
    }

    #[test]
    fn test_is_cdn_url() {
        assert!(is_cdn_url("https://cdnjs.cloudflare.com/ajax/libs/foo.js"));
        assert!(is_cdn_url("//cdn.jsdelivr.net/npm/bar"));
        assert!(!is_cdn_url("http://1.2.3.4/js/app.js"));
    }

    #[test]
    fn test_parse_ipv4() {
        if let IpAddress::V4(v) = parse_ipv4("192.168.1.1") {
            assert_eq!(v, (192 << 24) | (168 << 16) | (1 << 8) | 1);
        } else {
            panic!("expected V4");
        }
    }

    #[test]
    fn test_find_ci() {
        let data = b"Hello <SCRIPT src=\"x.js\"> world";
        assert_eq!(find_ci(data, 0, b"<script"), Some(6));
        assert_eq!(find_ci(data, 0, b"SRC"), Some(14));
    }
}
