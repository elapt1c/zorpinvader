//! The controller's live view: every node, plus the same scrolling key log the
//! standalone scan shows.
//!
//! The standalone TUI is built for one scanner. A controller has N of them, so
//! the layout is a table sorted by throughput: one row per node with its block,
//! progress bar, rate, hits and keys. The key log below it is the shared influx —
//! a confirmed key from any node appears there with the node that found it.
//!
//! Everything is drawn with absolute cursor positions onto stderr, so a redraw
//! never scrolls the terminal. When stderr is not a terminal (systemd, a log
//! file, a pipe) the same information is emitted as plain periodic lines.

use std::collections::VecDeque;
use std::io::Write;

use super::protocol::StatusResponse;
use super::scheduler::{ConnectionInfo, KeyEvent};

/// Key-log rows on screen.
const KEY_ROWS: usize = 6;
/// Used when the terminal size cannot be queried.
const FALLBACK_WIDTH: usize = 110;
const FALLBACK_HEIGHT: usize = 40;

pub struct Dashboard {
    width: usize,
    height: usize,
    last_rows: usize,
}

impl Default for Dashboard {
    fn default() -> Self {
        Self::new()
    }
}

impl Dashboard {
    pub fn new() -> Self {
        let (width, height) = term_size();
        Dashboard {
            width,
            height,
            last_rows: 0,
        }
    }

    /// Redraw the whole view. Cheap enough to call once per second.
    pub fn render(
        &mut self,
        status: &StatusResponse,
        connection: Option<&ConnectionInfo>,
        key_log: &VecDeque<KeyEvent>,
    ) {
        let (width, height) = term_size();
        self.width = width;
        self.height = height;

        let sep = "─".repeat(width.saturating_sub(1));
        let mut row = 1usize;
        let mut out = String::with_capacity(4096);

        // Row 1: title bar
        let uptime = format_duration(status.elapsed_s);
        let endpoint = connection
            .and_then(|c| c.onion.clone())
            .or_else(|| connection.map(|c| c.url.clone()).filter(|u| !u.is_empty()))
            .unwrap_or_else(|| status_endpoint(status));
        push_row(
            &mut out,
            row,
            &format!(
                "\x1b[44;97m ZorpInvader controller \u{2502} {} \u{2502} {} \u{2502} \x1b[0m",
                endpoint, uptime
            ),
        );
        row += 1;

        // Row 2: coverage and throughput
        push_row(
            &mut out,
            row,
            &format!(
                " \x1b[36mCoverage:\x1b[0m {:>6.2}%  \x1b[36mBlocks:\x1b[0m {}/{}  \
                 \x1b[36mAddresses:\x1b[0m {}/{}  \x1b[32mRate:\x1b[0m {}  \x1b[33mETA:\x1b[0m {}",
                status.percent,
                status.blocks_done,
                status.blocks_total,
                human(status.addresses_done),
                human(status.addresses_total),
                rate(status.rate_pps),
                format_duration(status.eta_s),
            ),
        );
        row += 1;

        // Row 3: totals
        push_row(
            &mut out,
            row,
            &format!(
                " \x1b[35mClients:\x1b[0m {}  \x1b[35mInflight:\x1b[0m {}  \
                 \x1b[35mPartial:\x1b[0m {}  \x1b[31mHits:\x1b[0m {}  \
                 \x1b[32mKeys:\x1b[0m {}",
                status.clients.len(),
                status.blocks_inflight,
                status.blocks_partial,
                status.hits,
                status.keys
            ),
        );
        row += 1;

        // Separator + node table header
        push_row(&mut out, row, &format!("\x1b[90m{}\x1b[0m", sep));
        row += 1;

        push_row(
            &mut out,
            row,
            &format!(
                "\x1b[1;37m {:16} {:22} {:6} {:12} {:>8} {:>6} {:>5} {:>4}\x1b[0m",
                "NODE", "BLOCK", "PROG", "BAR", "PPS", "HITS", "KEYS", "IDLE"
            ),
        );
        row += 1;

        // Nodes: reserve the footer space (key log + the join panel).
        let footer_rows = 2 + KEY_ROWS + 3;
        let node_slots = height.saturating_sub(row + footer_rows - 1).max(1);
        let mut nodes: Vec<&super::protocol::ClientSnapshot> = status.clients.iter().collect();
        nodes.sort_by(|a, b| {
            b.pps
                .partial_cmp(&a.pps)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.name.cmp(&b.name))
        });

        if nodes.is_empty() {
            push_row(
                &mut out,
                row,
                " \x1b[33mno clients connected — waiting for workers\x1b[0m",
            );
            row += 1;
        } else {
            let shown = nodes.len().min(node_slots);
            for client in nodes.iter().take(shown) {
                let pct = if client.total > 0 {
                    client.pos as f64 * 100.0 / client.total as f64
                } else {
                    0.0
                };
                let state_color = if client.idle_s > 30 {
                    "\x1b[90m"
                } else {
                    "\x1b[0m"
                };
                let line = format!(
                    " {}{:16}\x1b[0m {:22} {:>5.1}% {:12} {:>8} {:>6} {:>5} {:>3}s",
                    state_color,
                    clip(&client.name, 16),
                    clip(&client.block, 22),
                    pct,
                    bar(pct, 10),
                    rate(client.pps),
                    client.hits,
                    client.keys,
                    client.idle_s
                );
                push_row(&mut out, row, &truncate(&line, width));
                row += 1;
            }
            if nodes.len() > shown {
                push_row(
                    &mut out,
                    row,
                    &format!(" \x1b[90m… {} more node(s)\x1b[0m", nodes.len() - shown),
                );
                row += 1;
            }
        }

        // Separator + key log
        push_row(&mut out, row, &format!("\x1b[90m{}\x1b[0m", sep));
        row += 1;
        push_row(&mut out, row, "\x1b[35m[  KEY LOG  ]\x1b[0m");
        row += 1;

        let recent: Vec<&KeyEvent> = key_log.iter().rev().take(KEY_ROWS).collect();
        for i in 0..KEY_ROWS {
            // Newest at the bottom, like the standalone log.
            let entry = recent.get(KEY_ROWS - 1 - i);
            let line = match entry {
                Some(event) => format!(
                    " \x1b[32m{}\x1b[0m  {:<34} {:<12} {:<16} {}",
                    event.at,
                    mask_key(&event.key),
                    clip(&event.provider, 12),
                    clip(&event.client, 16),
                    event.ip
                ),
                None => String::new(),
            };
            push_row(&mut out, row, &truncate(&line, width));
            row += 1;
        }

        // Footer: the join panel. Like a room code, it stays on screen for the
        // whole run so it can be read off and pasted at any moment.
        push_row(&mut out, row, &format!("\x1b[90m{}\x1b[0m", sep));
        row += 1;
        let (headline, command) = join_panel(connection);
        push_row(&mut out, row, &truncate(&headline, width));
        row += 1;
        push_row(&mut out, row, &truncate(&command, width));

        // Clear anything left from a taller previous frame.
        out.push_str(&format!("\x1b[{};1H\x1b[J", row + 1));
        eprint!("{}", out);
        let _ = std::io::stderr().flush();
        self.last_rows = row + 1;
    }

    /// Non-interactive equivalent: one block of plain lines.
    pub fn render_plain(&self, status: &StatusResponse, connection: Option<&ConnectionInfo>) {
        let endpoint = connection
            .and_then(|c| c.onion.clone())
            .or_else(|| connection.map(|c| c.url.clone()).filter(|u| !u.is_empty()))
            .unwrap_or_else(|| status_endpoint(status));
        if let Some(conn) = connection {
            if !conn.connect.is_empty() {
                println!("[join] {}", conn.connect);
            }
        }
        println!(
            "[ctrl] {} | {:.2}% {}/{} blocks | {} addrs | {} | {} clients | hits {} | keys {} | eta {}",
            endpoint,
            status.percent,
            status.blocks_done,
            status.blocks_total,
            human(status.addresses_done),
            rate(status.rate_pps),
            status.clients.len(),
            status.hits,
            status.keys,
            format_duration(status.eta_s)
        );
        for client in &status.clients {
            let pct = if client.total > 0 {
                client.pos as f64 * 100.0 / client.total as f64
            } else {
                0.0
            };
            println!(
                "[node] {:<20} {:<22} {:>5.1}% {:>8} hits {:<5} keys {:<4} idle {}s",
                clip(&client.name, 20),
                clip(&client.block, 22),
                pct,
                rate(client.pps),
                client.hits,
                client.keys,
                client.idle_s
            );
        }
        let _ = std::io::stdout().flush();
    }
}

pub fn stderr_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDERR_FILENO) == 1 }
}

fn push_row(out: &mut String, row: usize, text: &str) {
    out.push_str(&format!("\x1b[{};1H\x1b[2K{}", row, text));
}

fn term_size() -> (usize, usize) {
    #[repr(C)]
    struct Winsize {
        ws_row: u16,
        ws_col: u16,
        ws_xpixel: u16,
        ws_ypixel: u16,
    }
    let mut ws = Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let rc = unsafe {
        libc::ioctl(
            libc::STDERR_FILENO,
            libc::TIOCGWINSZ,
            &mut ws as *mut Winsize,
        )
    };
    if rc == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
        (ws.ws_col as usize, ws.ws_row as usize)
    } else {
        (FALLBACK_WIDTH, FALLBACK_HEIGHT)
    }
}

/// The two lines of the join panel: the address to read off, and the command to
/// paste. Falls back to the listen address when no onion is published.
fn join_panel(connection: Option<&ConnectionInfo>) -> (String, String) {
    let conn = match connection {
        Some(conn) => conn,
        None => {
            return (
                " \x1b[1;97mJOIN\x1b[0m  \x1b[90mno connection information\x1b[0m".to_string(),
                String::new(),
            )
        }
    };

    let address = match &conn.onion {
        Some(onion) => onion.clone(),
        None => conn.url.clone(),
    };

    let headline = format!(
        " \x1b[1;97mJOIN\x1b[0m  \x1b[1;36m{}\x1b[0m \x1b[90m│\x1b[0m \x1b[33mtoken {}\x1b[0m",
        address, conn.token
    );
    let command = if conn.connect.is_empty() {
        String::new()
    } else {
        format!(
            " \x1b[90mcopy:\x1b[0m \x1b[32m{}\x1b[0m",
            conn.connect
        )
    };
    (headline, command)
}

fn status_endpoint(status: &StatusResponse) -> String {
    if status.targets.is_empty() {
        "controller".to_string()
    } else {
        format!("{} target CIDR(s)", status.targets.len())
    }
}

fn bar(pct: f64, width: usize) -> String {
    let filled = ((pct / 100.0) * width as f64).round().clamp(0.0, width as f64) as usize;
    let mut out = String::with_capacity(width * 3);
    out.push('[');
    for i in 0..width {
        out.push(if i < filled { '█' } else { '·' });
    }
    out.push(']');
    out
}

fn rate(pps: f64) -> String {
    if pps >= 1_000_000.0 {
        format!("{:.2}M/s", pps / 1_000_000.0)
    } else if pps >= 1_000.0 {
        format!("{:.1}k/s", pps / 1_000.0)
    } else {
        format!("{:.0}/s", pps)
    }
}

fn human(n: u64) -> String {
    match n {
        0..=9_999 => n.to_string(),
        10_000..=999_999 => format!("{:.1}k", n as f64 / 1_000.0),
        1_000_000..=999_999_999 => format!("{:.1}M", n as f64 / 1_000_000.0),
        _ => format!("{:.2}G", n as f64 / 1_000_000_000.0),
    }
}

fn format_duration(seconds: u64) -> String {
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

/// Keys are long and unbroken; show enough to identify one without spilling the
/// whole secret into a terminal someone may be screen-sharing.
fn mask_key(key: &str) -> String {
    if key.len() <= 16 {
        return key.to_string();
    }
    let head: String = key.chars().take(12).collect();
    let tail: String = key
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{}\u{2026}{}", head, tail)
}

fn clip(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let mut out: String = text.chars().take(width.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

/// Truncate an already-styled line, ignoring ANSI escapes for the length count.
fn truncate(line: &str, width: usize) -> String {
    let mut visible = 0usize;
    let mut in_escape = false;
    let mut out = String::with_capacity(line.len());
    for ch in line.chars() {
        if in_escape {
            if ch == 'm' {
                in_escape = false;
            }
            out.push(ch);
            continue;
        }
        if ch == '\x1b' {
            in_escape = true;
            out.push(ch);
            continue;
        }
        if visible >= width.saturating_sub(1) {
            break;
        }
        visible += 1;
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bars_scale_with_percentage() {
        assert_eq!(bar(0.0, 4), "[····]");
        assert_eq!(bar(100.0, 4), "[████]");
        assert_eq!(bar(50.0, 4), "[██··]");
        assert_eq!(bar(150.0, 4), "[████]");
    }

    #[test]
    fn rates_and_counts_are_human_readable() {
        assert_eq!(rate(900.0), "900/s");
        assert_eq!(rate(61_200.0), "61.2k/s");
        assert_eq!(rate(2_500_000.0), "2.50M/s");
        assert_eq!(human(512), "512");
        assert_eq!(human(12_400), "12.4k");
        assert_eq!(human(3_200_000), "3.2M");
    }

    #[test]
    fn keys_are_masked_in_the_middle() {
        let key = "EXAMPLEKEY_abcdefghijklmnopqrstuvwxyz012345";
        let masked = mask_key(key);
        assert_eq!(masked, "EXAMPLEKEY_a\u{2026}2345");
        assert!(!masked.contains("abcdefghij"));
        // Short keys are left alone rather than mangled.
        assert_eq!(mask_key("short"), "short");
    }

    #[test]
    fn truncation_ignores_ansi_escapes() {
        let line = "\x1b[32mabcdefghij\x1b[0m";
        let cut = truncate(line, 5);
        assert_eq!(cut, "\x1b[32mabcd");
    }

    #[test]
    fn join_panel_shows_address_token_and_command() {
        let onion = format!("{}.onion", "c".repeat(56));
        let conn = ConnectionInfo {
            listen: "0.0.0.0:8000".into(),
            onion: Some(onion.clone()),
            url: format!("http://{}", onion),
            token: "tok123".into(),
            connect: format!("zorpinvader --client {} --token tok123", onion),
        };
        let (headline, command) = join_panel(Some(&conn));
        assert!(headline.contains(&onion), "headline: {}", headline);
        assert!(headline.contains("token tok123"));
        assert!(command.contains(&format!("--client {}", onion)));
        // The escaped line must still fit a standard 110-column terminal.
        assert!(truncate(&headline, 110).contains("tok123"));

        // Without an onion the listen URL is the join address.
        let plain = ConnectionInfo {
            onion: None,
            ..conn
        };
        let (headline, _) = join_panel(Some(&plain));
        assert!(headline.contains("http://"));
        assert!(headline.contains("token tok123"));

        let (empty, _) = join_panel(None);
        assert!(empty.contains("no connection information"));
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(format_duration(0), "--");
        assert_eq!(format_duration(42), "42s");
        assert_eq!(format_duration(125), "2m05s");
        assert_eq!(format_duration(3 * 3600 + 12 * 60), "3h12m");
    }
}
