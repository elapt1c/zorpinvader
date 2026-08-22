//! Status reporting and rate calculation for scan progress.
//!
//! This module tracks scan progress and displays real-time statistics
//! including packet rate, completion percentage, estimated time remaining,
//! key scan log, fetcher activity, and verifier results.

use std::io::Write;
use std::sync::atomic::Ordering;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::greyhat::fetcher::Fetcher;
use crate::greyhat::greyhat::GreyhatScanner;
use crate::greyhat::verifier::Verifier;
use crate::pixie::timer::gettime;
use super::globals;

/// Status tracking structure for scan progress reporting.
///
/// Maintains rolling averages of packet rates and tracks
/// overall scan completion metrics.
#[derive(Debug)]
pub struct Status {
    /// Last measurement point
    pub last: LastStatus,

    /// Timer counter
    pub timer: u64,

    /// Character count for output formatting
    pub char_count: u8,

    /// Rolling rate history (8 samples)
    pub last_rates: [f64; 8],

    /// Index into last_rates array
    pub last_count: usize,

    /// Whether the scan runs infinitely
    pub is_infinite: bool,

    /// Total TCBs (TCP control blocks) created
    pub total_tcbs: u64,

    /// Total SYN-ACK responses received
    pub total_synacks: u64,

    /// Total SYN packets sent
    pub total_syns: u64,
}

/// Snapshot of the last measurement point for rate calculations.
#[derive(Debug, Clone, Copy)]
pub struct LastStatus {
    /// High-resolution timestamp (microseconds)
    pub clock: f64,

    /// Wall-clock time (seconds since epoch)
    pub time: u64,

    /// Packet count at last measurement
    pub count: u64,
}

impl Default for Status {
    fn default() -> Self {
        Self::new()
    }
}

impl Status {
    /// Create a new Status structure with default values.
    pub fn new() -> Self {
        Status {
            last: LastStatus {
                clock: 0.0,
                time: 0,
                count: 0,
            },
            timer: 1,
            char_count: 0,
            last_rates: [0.0; 8],
            last_count: 0,
            is_infinite: false,
            total_tcbs: 0,
            total_synacks: 0,
            total_syns: 0,
        }
    }

    /// Initialize the status tracker for a new scan.
    ///
    /// Clears the terminal screen and records the starting time.
    pub fn start(&mut self) {
        self.last.clock = gettime() as f64;
        self.last.time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last.count = 0;
        self.timer = 1;
        self.last_rates = [0.0; 8];
        self.last_count = 0;

        // Clear screen
        eprint!("\x1b[2J");
    }

    /// Print current scan status with rate, progress, key scan log,
    /// fetcher activity, and verifier results.
    ///
    /// # Arguments
    ///
    /// * `count` - Current packet count
    /// * `max_count` - Total packets to send
    /// * `pps` - Current packets per second
    /// * `total_tcbs` - Total TCP connections
    /// * `total_synacks` - Total SYN-ACK responses
    /// * `total_syns` - Total SYN packets sent
    /// * `exiting` - Whether we're in shutdown mode
    /// * `json_status` - Whether to output JSON format
    /// * `scanner` - Greyhat scanner for key/site stats
    /// * `fetcher` - HTTP fetcher for page/script stats
    /// * `verifier` - API key verifier for validation stats
    pub fn print(
        &mut self,
        count: u64,
        max_count: u64,
        pps: f64,
        total_tcbs: u64,
        total_synacks: u64,
        total_syns: u64,
        exiting: u64,
        json_status: bool,
        scanner: &GreyhatScanner,
        fetcher: &Fetcher,
        verifier: &Verifier,
    ) {
        let _ = (total_tcbs, total_syns, exiting);

        globals::update_global_now();

        let now = gettime() as f64;
        let elapsed_time = (now - self.last.clock) / 1_000_000.0;

        if elapsed_time <= 0.0 {
            return;
        }

        let rate = count.saturating_sub(self.last.count) as f64 / elapsed_time;
        self.last_rates[self.last_count & 0x7] = rate;
        self.last_count += 1;

        let avg_rate: f64 = self.last_rates.iter().sum::<f64>() / 8.0;
        let kpps = pps / 1000.0;
        let percent_done = if max_count > 0 {
            (count as f64 * 100.0) / max_count as f64
        } else {
            0.0
        };
        let time_remaining = if avg_rate > 0.0 {
            (1.0 - percent_done / 100.0) * (max_count as f64 / avg_rate)
        } else {
            0.0
        };
        let hours = (time_remaining / 3600.0) as u32;
        let minutes = ((time_remaining / 60.0) as u32) % 60;
        let seconds = (time_remaining as u32) % 60;

        // Gather real stats from pipeline components
        let stats = scanner.stats();
        let valid = verifier.stats().valid.load(Ordering::Relaxed);
        let invalid = verifier.stats().invalid.load(Ordering::Relaxed);
        let pending = verifier.stats().pending.load(Ordering::Relaxed);
        let keys_found = stats.total_keys_found.load(Ordering::Relaxed);
        let html_sites = stats.total_html_sites.load(Ordering::Relaxed);
        let f_stats = fetcher.stats();

        if json_status {
            eprintln!(
                r#"{{"status":"{}","rate_kpps":{:.2},"progress_pct":{:.2},"eta":"{:02}:{:02}:{:02}","found":{},"keys_valid":{},"keys_detected":{},"html_sites":{},"fetcher_pages":{},"fetcher_scripts":{},"fetcher_queue":{}}}"#,
                if globals::is_tx_done() { "Waiting" } else { "Scanning" },
                kpps,
                percent_done,
                hours, minutes, seconds,
                total_synacks,
                valid, keys_found, html_sites,
                f_stats.pages(), f_stats.scripts(),
                fetcher.queue_depth()
            );
        } else {
            let status_str = if globals::is_tx_done() { "Waiting" } else { "Scanning" };
            let sep = "\u{2500}".repeat(78);

            // Row 1: Header bar with key counts
            eprint!("\x1b[1;1H\x1b[2K\x1b[44;37m ZorpInvader \u{2502} Status: {} \u{2502} Keys: {}/{}/{} \x1b[0m\n",
                status_str, valid, keys_found, html_sites);

            // Row 2: Rate, position/total, ETA, found ports
            let rate_str = if pps <= 0.0 {
                format!("{:6.2} kpps", kpps)
            } else if pps >= 1_000_000.0 {
                format!("{:.2} Mpps", pps / 1_000_000.0)
            } else {
                format!("{:.2} kpps", kpps)
            };
            eprint!("\x1b[2;1H\x1b[2K \x1b[32mRate:\x1b[0m {} \u{2502} \x1b[36mProgress:\x1b[0m {}/{} ({:.1}%) \u{2502} \x1b[33mETA:\x1b[0m {:02}:{:02}:{:02} \u{2502} \x1b[31mFound:\x1b[0m {}\n",
                rate_str, count, max_count, percent_done, hours, minutes, seconds, total_synacks);

            // Row 3: Separator
            eprint!("\x1b[3;1H\x1b[2K\x1b[37m{}\x1b[0m\n", sep);

            // Row 4: KEY SCAN LOG header
            eprint!("\x1b[4;1H\x1b[2K\x1b[35m[  KEY SCAN LOG  ]\x1b[0m\n");

            // Rows 5-14: Last 10 key scan log entries (most recent at bottom)
            let (entries, ptr) = verifier.key_log().snapshot();
            let num_entries = entries.iter().filter(|e| !e.is_empty()).count();
            let show_count = num_entries.min(10);
            let start_pos = if num_entries > 10 { num_entries - 10 } else { 0 };

            for i in 0..10 {
                let row = 5 + i;
                if i < show_count {
                    let entry_idx = (start_pos + i) % entries.len();
                    let entry = &entries[entry_idx];
                    let color = if entry.contains("[CONFIRMED]") {
                        "\x1b[32m"
                    } else if entry.contains("[REJECTED]") {
                        "\x1b[31m"
                    } else if entry.contains("[EXHAUSTED]") {
                        "\x1b[36m"
                    } else if entry.contains("[DETECTED]") {
                        "\x1b[33m"
                    } else {
                        "\x1b[37m"
                    };
                    eprint!("\x1b[{};1H\x1b[2K{}{}\x1b[0m\n", row, color, entry);
                } else {
                    eprint!("\x1b[{};1H\x1b[2K\n", row);
                }
            }

            // Row 15: Separator
            eprint!("\x1b[15;1H\x1b[2K\x1b[37m{}\x1b[0m\n", sep);

            // Row 16: Fetcher stats
            eprint!("\x1b[16;1H\x1b[2K\x1b[36mFetcher:\x1b[0m pages={} scripts={} \u{2502} \x1b[35mgzip={} html={} <script>={}\x1b[0m \u{2502} \x1b[33mqueue={}\x1b[0m\n",
                f_stats.pages(), f_stats.scripts(),
                f_stats.gzip(), f_stats.html_bodies(), f_stats.script_tags(),
                fetcher.queue_depth());

            // Row 17: Verifier stats
            eprint!("\x1b[17;1H\x1b[2K\x1b[37mValid: {} \u{2502} Invalid: {} \u{2502} Pending: {}\x1b[0m\n",
                valid, invalid, pending);

            let _ = std::io::stderr().flush();
        }

        // Write raw status to file for external watchdog
        if let Ok(mut f) = std::fs::File::create("/tmp/zorp_status") {
            let _ = writeln!(f, "ETA: {:02}:{:02}:{:02} Found: {}", hours, minutes, seconds, total_synacks);
        }

        self.last.clock = now;
        self.last.count = count;
    }

    /// Finalize status reporting when scan completes.
    pub fn finish(&mut self) {
        eprintln!("\nScan Complete.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_new() {
        let status = Status::new();
        assert_eq!(status.timer, 1);
        assert_eq!(status.last.count, 0);
        assert_eq!(status.last_rates, [0.0; 8]);
    }

    #[test]
    fn test_status_start() {
        let mut status = Status::new();
        status.start();
        assert!(status.last.clock > 0.0);
    }
}
