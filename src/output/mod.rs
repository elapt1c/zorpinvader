//! Output management and dispatch.
//!
//! This module provides the [`OutputFormat`] trait that all output plugins implement,
//! and the [`OutputManager`] that dispatches status/banner events to the configured
//! format (JSON, XML, text, binary, etc.).
//!
//! Ported from C `output.h` / `output.c`.

pub mod record;
pub mod tcp_services;

pub mod json;
pub mod ndjson;
pub mod xml;
pub mod text;
pub mod grepable;
pub mod binary;
pub mod null;
pub mod redis;
pub mod unicornscan;
pub mod certs;
pub mod hostonly;

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::massip::addr::IpAddress;

// ---------------------------------------------------------------------------
// PortStatus / ApplicationProtocol enums
//
// These belong in dedicated modules (e.g. `proto::status`, `proto::app`) but
// are defined here until those modules are ported.
// ---------------------------------------------------------------------------

/// Whether a probed port is open, closed, or responding to ARP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PortStatus {
    Unknown = 0,
    Open = 1,
    Closed = 2,
    Arp = 3,
}

impl PortStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            PortStatus::Open => "open",
            PortStatus::Closed => "closed",
            PortStatus::Arp => "up",
            PortStatus::Unknown => "unknown",
        }
    }
}

impl fmt::Display for PortStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Application-layer protocol identified from banner data.
///
/// Discriminant values **must** be preserved — they are embedded in binary
/// output files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ApplicationProtocol {
    None = 0,
    Heur = 1,
    Ssh1 = 2,
    Ssh2 = 3,
    Http = 4,
    Ftp = 5,
    DnsVersionBind = 6,
    Snmp = 7,
    Nbtstat = 8,
    Ssl3 = 9,
    Smb = 10,
    Smtp = 11,
    Pop3 = 12,
    Imap4 = 13,
    UdpZeroAccess = 14,
    X509Cert = 15,
    X509CaCert = 16,
    HtmlTitle = 17,
    HtmlFull = 18,
    Ntp = 19,
    Vuln = 20,
    Heartbleed = 21,
    Ticketbleed = 22,
    VncOld = 23,
    Safe = 24,
    Memcached = 25,
    Scripting = 26,
    Versioning = 27,
    Coap = 28,
    Telnet = 29,
    Rdp = 30,
    HttpServer = 31,
    Minecraft = 32,
    VncRfb = 33,
    VncInfo = 34,
    Isakmp = 35,
    Error = 36,
}

impl ApplicationProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            ApplicationProtocol::None => "unknown",
            ApplicationProtocol::Heur => "heur",
            ApplicationProtocol::Ssh1 => "ssh1",
            ApplicationProtocol::Ssh2 => "ssh2",
            ApplicationProtocol::Http => "http",
            ApplicationProtocol::Ftp => "ftp",
            ApplicationProtocol::DnsVersionBind => "dns-versionbind",
            ApplicationProtocol::Snmp => "snmp",
            ApplicationProtocol::Nbtstat => "nbtstat",
            ApplicationProtocol::Ssl3 => "ssl",
            ApplicationProtocol::Smb => "smb",
            ApplicationProtocol::Smtp => "smtp",
            ApplicationProtocol::Pop3 => "pop3",
            ApplicationProtocol::Imap4 => "imap4",
            ApplicationProtocol::UdpZeroAccess => "udp-zeroaccess",
            ApplicationProtocol::X509Cert => "X509-cert",
            ApplicationProtocol::X509CaCert => "X509-CA-cert",
            ApplicationProtocol::HtmlTitle => "html-title",
            ApplicationProtocol::HtmlFull => "html",
            ApplicationProtocol::Ntp => "ntp",
            ApplicationProtocol::Vuln => "vuln",
            ApplicationProtocol::Heartbleed => "heartbleed",
            ApplicationProtocol::Ticketbleed => "ticketbleed",
            ApplicationProtocol::VncOld => "vnc-old",
            ApplicationProtocol::Safe => "safe",
            ApplicationProtocol::Memcached => "memcached",
            ApplicationProtocol::Scripting => "scripting",
            ApplicationProtocol::Versioning => "versioning",
            ApplicationProtocol::Coap => "coap",
            ApplicationProtocol::Telnet => "telnet",
            ApplicationProtocol::Rdp => "rdp",
            ApplicationProtocol::HttpServer => "http-server",
            ApplicationProtocol::Minecraft => "minecraft",
            ApplicationProtocol::VncRfb => "vnc-rfb",
            ApplicationProtocol::VncInfo => "vnc-info",
            ApplicationProtocol::Isakmp => "isakmp",
            ApplicationProtocol::Error => "error",
        }
    }
}

impl fmt::Display for ApplicationProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Output format selector
// ---------------------------------------------------------------------------

/// Which output format to use. Mirrors the C `Output_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormatType {
    None,
    List,        // text
    Unicornscan,
    Xml,
    Json,
    NdJson,
    Certs,
    Binary,
    Grepable,
    Redis,
    Hostonly,
    Interactive,
}

// ---------------------------------------------------------------------------
// The OutputFormat trait
// ---------------------------------------------------------------------------

/// Trait implemented by every output plugin (JSON, XML, text, …).
///
/// This is the Rust equivalent of the C `struct OutputType` function-pointer
/// table.
pub trait OutputFormat: Send {
    /// File extension associated with this format (e.g. `"json"`, `"xml"`).
    fn file_extension(&self) -> &str;

    /// Called once before the first record is written.
    /// Write file headers here.
    fn open(&mut self, writer: &mut dyn Write, ctx: &OutputContext) -> io::Result<()>;

    /// Called once after the last record. Write trailers here.
    fn close(&mut self, writer: &mut dyn Write, ctx: &OutputContext) -> io::Result<()>;

    /// Report a port status event (open / closed / arp).
    fn report_status(
        &mut self,
        writer: &mut dyn Write,
        ctx: &OutputContext,
        event: &StatusEvent,
    ) -> io::Result<()>;

    /// Report a banner (application-layer data captured from a port).
    fn report_banner(
        &mut self,
        writer: &mut dyn Write,
        ctx: &OutputContext,
        event: &BannerEvent,
    ) -> io::Result<()>;
}

// ---------------------------------------------------------------------------
// Event types passed to OutputFormat methods
// ---------------------------------------------------------------------------

/// A port-status event (open, closed, arp).
#[derive(Debug, Clone)]
pub struct StatusEvent {
    pub timestamp: u64,
    pub ip: IpAddress,
    pub ip_proto: u32,
    pub port: u32,
    pub status: PortStatus,
    pub reason: u32,
    pub ttl: u32,
    pub mac: Option<[u8; 6]>,
}

/// A banner event (application-layer data from a port).
#[derive(Debug, Clone)]
pub struct BannerEvent {
    pub timestamp: u64,
    pub ip: IpAddress,
    pub ip_proto: u32,
    pub port: u32,
    pub proto: ApplicationProtocol,
    pub ttl: u32,
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Context passed to every OutputFormat call (read-only stats/config)
// ---------------------------------------------------------------------------

/// Read-only context available to every output plugin during formatting.
pub struct OutputContext {
    /// Timestamp (epoch seconds) when the scan started.
    pub when_scan_started: u64,
    /// Whether to use GMT instead of local time.
    pub is_gmt: bool,
    /// Running counts of events, used by some formats (XML stats).
    pub counts: OutputCounts,
    /// XML stylesheet path, if any.
    pub xml_stylesheet: Option<String>,
}

/// Running counters of observed events.
#[derive(Debug, Clone, Default)]
pub struct OutputCounts {
    pub tcp_open: u64,
    pub tcp_closed: u64,
    pub tcp_banner: u64,
    pub udp_open: u64,
    pub udp_closed: u64,
    pub sctp_open: u64,
    pub sctp_closed: u64,
    pub icmp_echo: u64,
    pub icmp_timestamp: u64,
    pub arp_open: u64,
    pub oproto_open: u64,
    pub oproto_closed: u64,
}

// ---------------------------------------------------------------------------
// Rotation configuration
// ---------------------------------------------------------------------------

/// Configuration for output file rotation.
#[derive(Debug, Clone)]
pub struct RotateConfig {
    /// Rotate every N seconds. 0 = no time-based rotation.
    pub period: u64,
    /// Offset added to the rotation boundary.
    pub offset: u64,
    /// Rotate when file exceeds this many bytes. 0 = no size-based rotation.
    pub filesize: u64,
    /// Directory to move rotated files into.
    pub directory: Option<PathBuf>,
}

impl Default for RotateConfig {
    fn default() -> Self {
        Self {
            period: 0,
            offset: 0,
            filesize: 0,
            directory: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Redis configuration
// ---------------------------------------------------------------------------

/// Configuration for the Redis output target.
#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub ip: IpAddress,
    pub port: u32,
    pub password: Option<String>,
}

// ---------------------------------------------------------------------------
// OutputManager
// ---------------------------------------------------------------------------

/// Central output manager. Creates the appropriate [`OutputFormat`] plugin,
/// opens files, handles rotation, and dispatches events.
///
/// One `OutputManager` is created per receive thread.
pub struct OutputManager {
    /// The active output plugin.
    format: Box<dyn OutputFormat>,

    /// Which format type was selected.
    format_type: OutputFormatType,

    /// Output file path (None for stdout or null output).
    filename: Option<PathBuf>,

    /// Buffered writer for the output file (or stdout).
    writer: Option<BufWriter<Box<dyn Write>>>,

    /// Whether the file header has been written yet.
    is_virgin_file: bool,

    /// Whether the first JSON record has been seen (for comma handling).
    pub is_first_record_seen: bool,

    /// Timestamp when the scan started.
    when_scan_started: u64,

    /// Rotation state.
    rotate: RotateState,

    /// Display/format flags.
    pub is_banner: bool,
    pub is_banner_rawudp: bool,
    pub is_output_flush: bool,
    pub is_gmt: bool,
    pub is_interactive: bool,
    pub is_show_open: bool,
    pub is_show_closed: bool,
    pub is_show_host: bool,
    pub is_append: bool,

    /// Running event counters.
    pub counts: OutputCounts,

    /// XML stylesheet path.
    xml_stylesheet: Option<String>,

    /// Redis configuration (only used by the Redis output).
    pub redis: Option<RedisConfig>,
}

/// Internal rotation bookkeeping.
struct RotateState {
    config: RotateConfig,
    next_rotate_time: u64,
    last_rotate_time: u64,
    bytes_written: u64,
    file_count: u32,
}

// ---------------------------------------------------------------------------
// Free-standing helper functions (ported from output.c)
// ---------------------------------------------------------------------------

/// Map IP protocol number to a human-readable name.
pub fn name_from_ip_proto(ip_proto: u32) -> &'static str {
    match ip_proto {
        0 => "arp",
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        132 => "sctp",
        _ => "err",
    }
}

/// Map IP version number to a string.
pub fn name_from_ip_version(version: u8) -> &'static str {
    match version {
        4 => "ipv4",
        6 => "ipv6",
        _ => "err",
    }
}

/// Build an nmap-style "reason" string from TCP flag bits.
pub fn reason_string(flags: u32) -> String {
    let mut parts = Vec::new();
    if flags & 0x01 != 0 { parts.push("fin"); }
    if flags & 0x02 != 0 { parts.push("syn"); }
    if flags & 0x04 != 0 { parts.push("rst"); }
    if flags & 0x08 != 0 { parts.push("psh"); }
    if flags & 0x10 != 0 { parts.push("ack"); }
    if flags & 0x20 != 0 { parts.push("urg"); }
    if flags & 0x40 != 0 { parts.push("ece"); }
    if flags & 0x80 != 0 { parts.push("cwr"); }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join("-")
    }
}

/// Escape non-printable and unsafe characters from banner data.
///
/// Printable ASCII is kept as-is (except `<`, `>`, `&`, `\`, `"`, `'` which
/// are hex-escaped). Everything else becomes `\xNN`.
pub fn normalize_string(px: &[u8]) -> String {
    let mut out = String::with_capacity(px.len());
    for &c in px {
        if c.is_ascii_graphic()
            && c != b'<'
            && c != b'>'
            && c != b'&'
            && c != b'\\'
            && c != b'"'
            && c != b'\''
        {
            out.push(c as char);
        } else if c == b' ' {
            out.push(' ');
        } else {
            out.push_str(&format!("\\x{:02x}", c));
        }
    }
    out
}

/// Like [`normalize_string`], but escapes non-printables as `\u00NN` for
/// JSON-safety.
pub fn normalize_json_string(px: &[u8]) -> String {
    let mut out = String::with_capacity(px.len());
    for &c in px {
        if c.is_ascii_graphic()
            && c != b'<'
            && c != b'>'
            && c != b'&'
            && c != b'\\'
            && c != b'"'
            && c != b'\''
        {
            out.push(c as char);
        } else if c == b' ' {
            out.push(' ');
        } else {
            out.push_str(&format!("\\u00{:02x}", c));
        }
    }
    out
}

/// Return the IP version (4 or 6) of an [`IpAddress`].
pub fn ip_version(ip: &IpAddress) -> u8 {
    match ip {
        IpAddress::V4(_) => 4,
        IpAddress::V6(_) => 6,
    }
}

// ---------------------------------------------------------------------------
// OutputManager implementation
// ---------------------------------------------------------------------------

impl OutputManager {
    /// Create a new `OutputManager` with the given format type and output path.
    ///
    /// If `filename` is `Some`, the file is opened immediately so that errors
    /// are caught early rather than mid-scan.
    pub fn new(
        format_type: OutputFormatType,
        filename: Option<PathBuf>,
        rotate_config: RotateConfig,
        is_append: bool,
    ) -> io::Result<Self> {
        let format: Box<dyn OutputFormat> = match format_type {
            OutputFormatType::List => Box::new(text::TextOutput::new()),
            OutputFormatType::Unicornscan => Box::new(unicornscan::UnicornscanOutput::new()),
            OutputFormatType::Xml => Box::new(xml::XmlOutput::new()),
            OutputFormatType::Json => Box::new(json::JsonOutput::new()),
            OutputFormatType::NdJson => Box::new(ndjson::NdJsonOutput::new()),
            OutputFormatType::Certs => Box::new(certs::CertsOutput::new()),
            OutputFormatType::Binary => Box::new(binary::BinaryOutput::new()),
            OutputFormatType::Grepable => Box::new(grepable::GrepableOutput::new()),
            OutputFormatType::Redis => Box::new(redis::RedisOutput::new()),
            OutputFormatType::Hostonly => Box::new(hostonly::HostonlyOutput::new()),
            OutputFormatType::None | OutputFormatType::Interactive => {
                Box::new(null::NullOutput::new())
            }
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let writer = if let Some(ref path) = filename {
            if format_type == OutputFormatType::None {
                None
            } else if path.to_str() == Some("-") {
                Some(BufWriter::new(Box::new(io::stdout()) as Box<dyn Write>))
            } else {
                let file = if is_append {
                    OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)?
                } else {
                    File::create(path)?
                };
                Some(BufWriter::new(Box::new(file) as Box<dyn Write>))
            }
        } else {
            None
        };

        // Compute the first rotation time.
        let next_rotate_time = if rotate_config.period == 0 {
            u64::MAX
        } else {
            Self::next_rotate_time(now, rotate_config.period, rotate_config.offset)
        };

        Ok(Self {
            format,
            format_type,
            filename,
            writer,
            is_virgin_file: true,
            is_first_record_seen: false,
            when_scan_started: now,
            rotate: RotateState {
                config: rotate_config,
                next_rotate_time,
                last_rotate_time: now,
                bytes_written: 0,
                file_count: 0,
            },
            is_banner: false,
            is_banner_rawudp: false,
            is_output_flush: false,
            is_gmt: false,
            is_interactive: false,
            is_show_open: true,
            is_show_closed: true,
            is_show_host: true,
            is_append,
            counts: OutputCounts::default(),
            xml_stylesheet: None,
            redis: None,
        })
    }

    /// Build an [`OutputContext`] snapshot from the current manager state.
    fn make_context(&self) -> OutputContext {
        OutputContext {
            when_scan_started: self.when_scan_started,
            is_gmt: self.is_gmt,
            counts: self.counts.clone(),
            xml_stylesheet: self.xml_stylesheet.clone(),
        }
    }

    /// Report a port status event.
    pub fn report_status(&mut self, event: StatusEvent) {
        // Update counters.
        match event.status {
            PortStatus::Open => match event.ip_proto {
                1 => self.counts.icmp_echo += 1,
                6 => self.counts.tcp_open += 1,
                17 => self.counts.udp_open += 1,
                132 => self.counts.sctp_open += 1,
                _ => self.counts.oproto_open += 1,
            },
            PortStatus::Closed => match event.ip_proto {
                6 => self.counts.tcp_closed += 1,
                17 => self.counts.udp_closed += 1,
                132 => self.counts.sctp_closed += 1,
                _ => self.counts.oproto_closed += 1,
            },
            PortStatus::Arp => {
                self.counts.arp_open += 1;
            }
            _ => {}
        }

        // Filter by show-open / show-closed preferences.
        if !self.is_show_closed && event.status == PortStatus::Closed {
            return;
        }
        if !self.is_show_open && event.status == PortStatus::Open {
            return;
        }

        // Check rotation (before borrowing writer).
        let now = Self::now_epoch();
        if self.should_rotate(now) {
            if let Err(e) = self.do_rotate(false) {
                log::error!("rotation failed: {}", e);
            }
        }

        // Prepare context before borrowing writer.
        let ctx = self.make_context();
        let is_virgin = self.is_virgin_file;
        let is_flush = self.is_output_flush;

        let writer = match self.writer.as_mut() {
            Some(w) => w,
            None => return,
        };

        // Write file header on first record.
        if is_virgin {
            if let Err(e) = self.format.open(writer, &ctx) {
                log::error!("output open failed: {}", e);
                return;
            }
            self.is_virgin_file = false;
        }

        if let Err(e) = self.format.report_status(writer, &ctx, &event) {
            log::error!("report_status failed: {}", e);
        }

        if is_flush {
            let _ = writer.flush();
        }
    }

    /// Report a banner event.
    pub fn report_banner(&mut self, event: BannerEvent) {
        if !self.is_banner {
            return;
        }

        // Interactive mode: also print to stdout.
        if self.is_interactive || self.format_type == OutputFormatType::Interactive {
            let ip_str = event.ip.to_string();
            let banner = normalize_string(&event.data);
            println!(
                "Banner on port {}/{}/{}: [{}] {}",
                event.port,
                name_from_ip_proto(event.ip_proto),
                ip_str,
                event.proto.as_str(),
                banner,
            );
        }

        // Check rotation (before borrowing writer).
        let now = Self::now_epoch();
        if self.should_rotate(now) {
            if let Err(e) = self.do_rotate(false) {
                log::error!("rotation failed: {}", e);
            }
        }

        // Prepare context before borrowing writer.
        let ctx = self.make_context();
        let is_virgin = self.is_virgin_file;
        let is_flush = self.is_output_flush;

        let writer = match self.writer.as_mut() {
            Some(w) => w,
            None => return,
        };

        if is_virgin {
            if let Err(e) = self.format.open(writer, &ctx) {
                log::error!("output open failed: {}", e);
                return;
            }
            self.is_virgin_file = false;
        }

        if let Err(e) = self.format.report_banner(writer, &ctx, &event) {
            log::error!("report_banner failed: {}", e);
        }

        if is_flush {
            let _ = writer.flush();
        }
    }

    /// Flush and close the output, writing any trailers.
    pub fn finish(&mut self) {
        // If rotating, do a final rotate.
        if self.rotate.config.period > 0 || self.rotate.config.filesize > 0 {
            log::info!("doing final rotate");
            let _ = self.do_rotate(true);
            return;
        }

        let is_virgin = self.is_virgin_file;
        let ctx = self.make_context();
        if let Some(writer) = self.writer.as_mut() {
            if !is_virgin {
                let _ = self.format.close(writer, &ctx);
            }
            let _ = writer.flush();
        }
    }

    // -- rotation helpers ---------------------------------------------------

    fn now_epoch() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn should_rotate(&self, now: u64) -> bool {
        if self.is_virgin_file {
            return false;
        }
        if now >= self.rotate.next_rotate_time {
            return true;
        }
        if self.rotate.config.filesize > 0
            && self.rotate.bytes_written >= self.rotate.config.filesize
        {
            return true;
        }
        false
    }

    fn next_rotate_time(last: u64, period: u64, offset: u64) -> u64 {
        if period == 0 {
            return u64::MAX;
        }
        last - (last % period) + period + offset
    }

    /// Rotate the current output file: close, rename, and reopen.
    ///
    /// If `is_closing` is true (program shutting down), the file is not
    /// reopened.
    fn do_rotate(&mut self, is_closing: bool) -> io::Result<()> {
        let dir = match &self.rotate.config.directory {
            Some(d) => d.clone(),
            None => return Ok(()),
        };
        let filename = match &self.filename {
            Some(f) => f.clone(),
            None => return Ok(()),
        };

        // Flush and write trailers on the current file.
        let is_virgin = self.is_virgin_file;
        let ctx = self.make_context();
        if let Some(writer) = self.writer.as_mut() {
            if !is_virgin {
                let _ = self.format.close(writer, &ctx);
            }
            let _ = writer.flush();
        }

        // Build the rotated filename.
        let stem = filename
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("output");

        let rotated_name = if self.rotate.config.filesize > 0 {
            // Size-based rotation: sequential index.
            let ext = filename
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            if ext.is_empty() {
                format!("{}/{}-{:05}", dir.display(), stem, self.rotate.file_count)
            } else {
                let base = filename
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(stem);
                format!(
                    "{}/{}-{:05}.{}",
                    dir.display(),
                    base,
                    self.rotate.file_count,
                    ext
                )
            }
        } else {
            // Time-based rotation.
            let chrono_now = chrono::Utc::now();
            let time_str = if self.is_gmt {
                format!(
                    "{:02}{:02}{:02}-{:02}{:02}{:02}",
                    chrono_now.format("%y"),
                    chrono_now.format("%m"),
                    chrono_now.format("%d"),
                    chrono_now.format("%H"),
                    chrono_now.format("%M"),
                    chrono_now.format("%S"),
                )
            } else {
                let local = chrono_now.with_timezone(&chrono::Local);
                format!(
                    "{:02}{:02}{:02}-{:02}{:02}{:02}",
                    local.format("%y"),
                    local.format("%m"),
                    local.format("%d"),
                    local.format("%H"),
                    local.format("%M"),
                    local.format("%S"),
                )
            };
            format!(
                "{}/{}-{}",
                dir.display(),
                time_str,
                stem,
            )
        };

        self.rotate.file_count += 1;

        // Rename the current file.
        if let Err(e) = fs::rename(&filename, &rotated_name) {
            log::error!("rename({:?}, {:?}) failed: {}", filename, rotated_name, e);
        } else {
            log::info!("rotated: {}", rotated_name);
        }

        // Reset counters.
        self.counts = OutputCounts::default();
        self.rotate.bytes_written = 0;

        if is_closing {
            self.writer = None;
            return Ok(());
        }

        // Reopen.
        let file = File::create(&filename)?;
        self.writer = Some(BufWriter::new(Box::new(file) as Box<dyn Write>));
        self.is_virgin_file = true;
        self.rotate.last_rotate_time = Self::now_epoch();

        if self.rotate.config.period > 0 {
            self.rotate.next_rotate_time = Self::next_rotate_time(
                Self::now_epoch(),
                self.rotate.config.period,
                self.rotate.config.offset,
            );
        }

        Ok(())
    }
}

impl Drop for OutputManager {
    fn drop(&mut self) {
        self.finish();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_from_ip_proto() {
        assert_eq!(name_from_ip_proto(6), "tcp");
        assert_eq!(name_from_ip_proto(17), "udp");
        assert_eq!(name_from_ip_proto(0), "arp");
        assert_eq!(name_from_ip_proto(1), "icmp");
        assert_eq!(name_from_ip_proto(132), "sctp");
        assert_eq!(name_from_ip_proto(99), "err");
    }

    #[test]
    fn test_name_from_ip_version() {
        assert_eq!(name_from_ip_version(4), "ipv4");
        assert_eq!(name_from_ip_version(6), "ipv6");
        assert_eq!(name_from_ip_version(9), "err");
    }

    #[test]
    fn test_reason_string() {
        assert_eq!(reason_string(0x02 | 0x10), "syn-ack");
        assert_eq!(reason_string(0), "none");
        assert_eq!(reason_string(0x01), "fin");
        assert_eq!(reason_string(0xFF), "fin-syn-rst-psh-ack-urg-ece-cwr");
    }

    #[test]
    fn test_normalize_string() {
        assert_eq!(normalize_string(b"hello"), "hello");
        assert_eq!(normalize_string(b"he\x00llo"), "he\\x00llo");
        assert_eq!(normalize_string(b"a<b"), "a\\x3cb");
    }

    #[test]
    fn test_normalize_json_string() {
        assert_eq!(normalize_json_string(b"hello"), "hello");
        assert_eq!(normalize_json_string(b"he\x00llo"), "he\\u0000llo");
    }

    #[test]
    fn test_port_status_display() {
        assert_eq!(PortStatus::Open.as_str(), "open");
        assert_eq!(PortStatus::Closed.as_str(), "closed");
        assert_eq!(PortStatus::Arp.as_str(), "up");
    }

    #[test]
    fn test_application_protocol_display() {
        assert_eq!(ApplicationProtocol::Http.as_str(), "http");
        assert_eq!(ApplicationProtocol::Ssh2.as_str(), "ssh2");
        assert_eq!(ApplicationProtocol::None.as_str(), "unknown");
    }

    #[test]
    fn test_indexed_filename_logic() {
        // Port of the C selftest for indexed_filename.
        // This tests the concept; the actual function is in the C codebase.
        // In Rust we use PathBuf manipulation instead.
        let base = "foo.bar";
        let index = 1;
        let ext_pos = base.rfind('.').unwrap_or(base.len());
        let result = format!("{}.{:02}{}", &base[..ext_pos], index, &base[ext_pos..]);
        assert_eq!(result, "foo.01.bar");
    }
}
