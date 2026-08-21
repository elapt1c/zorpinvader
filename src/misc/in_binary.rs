//! Binary scan file reader.
//!
//! Reads the output of previous scans that were saved in the binary
//! format (produced by `out-binary.c`, using the `-oB` parameter or
//! `--output-format binary`). This allows the user to re-output in
//! another format like JSON or XML while preserving original timestamps.
//!
//! **Ported from C `in-binary.c`.**

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use crate::massip::addr::{IpAddress, Ipv6Address};
use crate::massip::massip::MassIP;
use crate::massip::rangesv4::RangeList;
use crate::output::{
    ApplicationProtocol, OutputManager, PortStatus, StatusEvent, BannerEvent,
};

use super::in_filter::readscan_filter_pass;

/// Maximum buffer size for a single record (1 MiB).
const BUF_MAX: usize = 1024 * 1024;

/// Magic header for the binary scan file format.
const FILE_MAGIC: &[u8] = b"zorp/1.1";

/// Record type codes embedded in the binary file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum RecordType {
    StatusOpen = 1,
    StatusClosed = 2,
    Banner3 = 3,
    Banner4Old = 4,
    Banner4 = 5,
    Status2Open = 6,
    Status2Closed = 7,
    Banner9 = 9,
    Status6Open = 10,
    Status6Closed = 11,
    Banner6 = 13,
    FileHeader = b'm',
}

impl RecordType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(RecordType::StatusOpen),
            2 => Some(RecordType::StatusClosed),
            3 => Some(RecordType::Banner3),
            4 => Some(RecordType::Banner4Old),
            5 => Some(RecordType::Banner4),
            6 => Some(RecordType::Status2Open),
            7 => Some(RecordType::Status2Closed),
            9 => Some(RecordType::Banner9),
            10 => Some(RecordType::Status6Open),
            11 => Some(RecordType::Status6Closed),
            13 => Some(RecordType::Banner6),
            b'm' => Some(RecordType::FileHeader),
            _ => None,
        }
    }
}

/// A parsed record from the binary scan file.
#[derive(Debug, Clone)]
struct ScanRecord {
    timestamp: u32,
    ip: IpAddress,
    ip_proto: u8,
    port: u16,
    reason: u8,
    ttl: u8,
    mac: [u8; 6],
    app_proto: u16,
}

impl Default for ScanRecord {
    fn default() -> Self {
        ScanRecord {
            timestamp: 0,
            ip: IpAddress::V4(0),
            ip_proto: 0,
            port: 0,
            reason: 0,
            ttl: 0,
            mac: [0; 6],
            app_proto: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Byte-level readers matching the C code's _get_byte / _get_short etc.
// ---------------------------------------------------------------------------

/// Cursor for reading big-endian fields from a record buffer.
struct RecordCursor<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> RecordCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        RecordCursor { buf, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.offset)
    }

    fn get_byte(&mut self) -> u8 {
        if self.offset < self.buf.len() {
            let b = self.buf[self.offset];
            self.offset += 1;
            b
        } else {
            self.offset += 1;
            0xFF
        }
    }

    fn get_u32(&mut self) -> u32 {
        let o = self.offset;
        self.offset += 4;
        if o + 4 <= self.buf.len() {
            (self.buf[o] as u32) << 24
                | (self.buf[o + 1] as u32) << 16
                | (self.buf[o + 2] as u32) << 8
                | (self.buf[o + 3] as u32)
        } else {
            0xFFFFFFFF
        }
    }

    fn get_u16(&mut self) -> u16 {
        let o = self.offset;
        self.offset += 2;
        if o + 2 <= self.buf.len() {
            (self.buf[o] as u16) << 8 | (self.buf[o + 1] as u16)
        } else {
            0xFFFF
        }
    }

    fn get_u64(&mut self) -> u64 {
        let o = self.offset;
        self.offset += 8;
        if o + 8 <= self.buf.len() {
            (self.buf[o] as u64) << 56
                | (self.buf[o + 1] as u64) << 48
                | (self.buf[o + 2] as u64) << 40
                | (self.buf[o + 3] as u64) << 32
                | (self.buf[o + 4] as u64) << 24
                | (self.buf[o + 5] as u64) << 16
                | (self.buf[o + 6] as u64) << 8
                | (self.buf[o + 7] as u64)
        } else {
            0xFFFFFFFFFFFFFFFF
        }
    }
}

// ---------------------------------------------------------------------------
// Record parsers
// ---------------------------------------------------------------------------

/// Parse a type-1/2 status record (original format, 12 bytes minimum).
fn parse_status(
    out: &mut OutputManager,
    status: PortStatus,
    buf: &[u8],
    when_scan_started: &mut u64,
) {
    if buf.len() < 12 {
        return;
    }

    let timestamp = (buf[0] as u32) << 24
        | (buf[1] as u32) << 16
        | (buf[2] as u32) << 8
        | (buf[3] as u32);
    let ip_v4 = (buf[4] as u32) << 24
        | (buf[5] as u32) << 16
        | (buf[6] as u32) << 8
        | (buf[7] as u32);
    let port = (buf[8] as u16) << 8 | (buf[9] as u16);
    let reason = buf[10];
    let ttl = buf[11];

    let mac = if ip_v4 == 0 && buf.len() >= 18 {
        let mut m = [0u8; 6];
        m.copy_from_slice(&buf[12..18]);
        Some(m)
    } else {
        None
    };

    if *when_scan_started == 0 {
        *when_scan_started = timestamp as u64;
    }

    let ip_proto = match port {
        53 | 123 | 137 | 161 => 17,
        36422 | 36412 | 2905 => 132,
        _ => 6,
    };

    out.report_status(StatusEvent {
        timestamp: timestamp as u64,
        ip: IpAddress::V4(ip_v4),
        ip_proto,
        port: port as u32,
        status,
        reason: reason as u32,
        ttl: ttl as u32,
        mac,
    });
}

/// Parse a type-6/7 status2 record (13 bytes minimum, with explicit ip_proto).
fn parse_status2(
    out: &mut OutputManager,
    status: PortStatus,
    buf: &[u8],
    when_scan_started: &mut u64,
    filter: Option<&MassIP>,
) {
    if buf.len() < 13 {
        return;
    }

    let timestamp = (buf[0] as u32) << 24
        | (buf[1] as u32) << 16
        | (buf[2] as u32) << 8
        | (buf[3] as u32);
    let ip_v4 = (buf[4] as u32) << 24
        | (buf[5] as u32) << 16
        | (buf[6] as u32) << 8
        | (buf[7] as u32);
    let ip_proto = buf[8];
    let port = (buf[9] as u16) << 8 | (buf[10] as u16);
    let reason = buf[11];
    let ttl = buf[12];

    let mac = if ip_v4 == 0 && buf.len() >= 19 {
        let mut m = [0u8; 6];
        m.copy_from_slice(&buf[13..19]);
        Some(m)
    } else {
        None
    };

    if *when_scan_started == 0 {
        *when_scan_started = timestamp as u64;
    }

    let ip = IpAddress::V4(ip_v4);

    // Apply filter
    if let Some(f) = filter {
        if f.count_ipv4s > 0 && !f.has_ip(ip) {
            return;
        }
        if f.count_ports > 0 && !f.has_port(port as u32) {
            return;
        }
    }

    out.report_status(StatusEvent {
        timestamp: timestamp as u64,
        ip,
        ip_proto: ip_proto as u32,
        port: port as u32,
        status,
        reason: reason as u32,
        ttl: ttl as u32,
        mac,
    });
}

/// Parse a type-10/11 IPv6 status record.
fn parse_status6(
    out: &mut OutputManager,
    status: PortStatus,
    buf: &[u8],
    when_scan_started: &mut u64,
    filter: Option<&MassIP>,
) {
    let mut cur = RecordCursor::new(buf);

    let timestamp = cur.get_u32();
    let ip_proto = cur.get_byte();
    let port = cur.get_u16();
    let reason = cur.get_byte();
    let ttl = cur.get_byte();
    let version = cur.get_byte();
    if version != 6 {
        log::error!("[-] corrupt record: expected IPv6, got version {}", version);
        return;
    }
    let hi = cur.get_u64();
    let lo = cur.get_u64();

    if *when_scan_started == 0 {
        *when_scan_started = timestamp as u64;
    }

    let ip = IpAddress::V6(Ipv6Address::new(hi, lo));

    if let Some(f) = filter {
        if f.count_ipv4s > 0 && !f.has_ip(ip) {
            return;
        }
        if f.count_ports > 0 && !f.has_port(port as u32) {
            return;
        }
    }

    out.report_status(StatusEvent {
        timestamp: timestamp as u64,
        ip,
        ip_proto: ip_proto as u32,
        port: port as u32,
        status,
        reason: reason as u32,
        ttl: ttl as u32,
        mac: None,
    });
}

/// Parse a type-3 banner record (old format, 12 bytes header).
fn parse_banner3(out: &mut OutputManager, buf: &[u8], when_scan_started: &mut u64) {
    if buf.len() < 12 {
        return;
    }

    let timestamp = (buf[0] as u32) << 24
        | (buf[1] as u32) << 16
        | (buf[2] as u32) << 8
        | (buf[3] as u32);
    let ip_v4 = (buf[4] as u32) << 24
        | (buf[5] as u32) << 16
        | (buf[6] as u32) << 8
        | (buf[7] as u32);
    let port = (buf[8] as u16) << 8 | (buf[9] as u16);
    let app_proto = (buf[10] as u16) << 8 | (buf[11] as u16);

    if *when_scan_started == 0 {
        *when_scan_started = timestamp as u64;
    }

    let banner_data = if buf.len() > 12 { &buf[12..] } else { &[] };

    out.report_banner(BannerEvent {
        timestamp: timestamp as u64,
        ip: IpAddress::V4(ip_v4),
        ip_proto: 6, // always TCP in old format
        port: port as u32,
        proto: app_proto_to_enum(app_proto as u32),
        ttl: 0,
        data: banner_data.to_vec(),
    });
}

/// Parse a type-4/5 banner record (13 bytes header).
fn parse_banner4(out: &mut OutputManager, buf: &[u8], when_scan_started: &mut u64) {
    if buf.len() < 13 {
        return;
    }

    let timestamp = (buf[0] as u32) << 24
        | (buf[1] as u32) << 16
        | (buf[2] as u32) << 8
        | (buf[3] as u32);
    let ip_v4 = (buf[4] as u32) << 24
        | (buf[5] as u32) << 16
        | (buf[6] as u32) << 8
        | (buf[7] as u32);
    let ip_proto = buf[8];
    let port = (buf[9] as u16) << 8 | (buf[10] as u16);
    let app_proto = (buf[11] as u16) << 8 | (buf[12] as u16);

    if *when_scan_started == 0 {
        *when_scan_started = timestamp as u64;
    }

    let banner_data = if buf.len() > 13 { &buf[13..] } else { &[] };

    out.report_banner(BannerEvent {
        timestamp: timestamp as u64,
        ip: IpAddress::V4(ip_v4),
        ip_proto: ip_proto as u32,
        port: port as u32,
        proto: app_proto_to_enum(app_proto as u32),
        ttl: 0,
        data: banner_data.to_vec(),
    });
}

/// Parse a type-9 banner record (14 bytes header, with TTL).
fn parse_banner9(
    out: &mut OutputManager,
    buf: &[u8],
    when_scan_started: &mut u64,
    filter: Option<&MassIP>,
    btypes: Option<&RangeList>,
) {
    if buf.len() < 14 {
        return;
    }

    let timestamp = (buf[0] as u32) << 24
        | (buf[1] as u32) << 16
        | (buf[2] as u32) << 8
        | (buf[3] as u32);
    let ip_v4 = (buf[4] as u32) << 24
        | (buf[5] as u32) << 16
        | (buf[6] as u32) << 8
        | (buf[7] as u32);
    let ip_proto = buf[8];
    let port = (buf[9] as u16) << 8 | (buf[10] as u16);
    let app_proto = (buf[11] as u16) << 8 | (buf[12] as u16);
    let ttl = buf[13];

    if *when_scan_started == 0 {
        *when_scan_started = timestamp as u64;
    }

    let ip = IpAddress::V4(ip_v4);

    if !readscan_filter_pass(ip, port as u32, app_proto as u32, filter, btypes) {
        return;
    }

    let data = if buf.len() > 14 { &buf[14..] } else { &[] };

    out.report_banner(BannerEvent {
        timestamp: timestamp as u64,
        ip,
        ip_proto: ip_proto as u32,
        port: port as u32,
        proto: app_proto_to_enum(app_proto as u32),
        ttl: ttl as u32,
        data: data.to_vec(),
    });
}

/// Parse a type-13 IPv6 banner record.
fn parse_banner6(
    out: &mut OutputManager,
    buf: &[u8],
    when_scan_started: &mut u64,
    filter: Option<&MassIP>,
    btypes: Option<&RangeList>,
) {
    let mut cur = RecordCursor::new(buf);

    let timestamp = cur.get_u32();
    let ip_proto = cur.get_byte();
    let port = cur.get_u16();
    let app_proto = cur.get_u16();
    let ttl = cur.get_byte();
    let version = cur.get_byte();
    if version != 6 {
        log::error!("[-] corrupt record: expected IPv6 banner, got version {}", version);
        return;
    }
    let hi = cur.get_u64();
    let lo = cur.get_u64();

    if *when_scan_started == 0 {
        *when_scan_started = timestamp as u64;
    }

    let ip = IpAddress::V6(Ipv6Address::new(hi, lo));

    if !readscan_filter_pass(ip, port as u32, app_proto as u32, filter, btypes) {
        return;
    }

    let offset = cur.offset;
    let data = if offset < buf.len() {
        &buf[offset..]
    } else {
        &[]
    };

    out.report_banner(BannerEvent {
        timestamp: timestamp as u64,
        ip,
        ip_proto: ip_proto as u32,
        port: port as u32,
        proto: app_proto_to_enum(app_proto as u32),
        ttl: ttl as u32,
        data: data.to_vec(),
    });
}

// ---------------------------------------------------------------------------
// Variable-length integer readers (for record type and length fields)
// ---------------------------------------------------------------------------

/// Read a variable-length encoded unsigned integer from the file.
/// Each byte uses 7 bits for data and the high bit as a continuation flag.
fn read_varint(reader: &mut impl Read) -> io::Result<Option<u64>> {
    let mut byte = [0u8; 1];
    if reader.read_exact(&mut byte).is_err() {
        return Ok(None); // EOF
    }
    let mut value = (byte[0] & 0x7F) as u64;
    while byte[0] & 0x80 != 0 {
        if reader.read_exact(&mut byte).is_err() {
            return Ok(None);
        }
        value = (value << 7) | (byte[0] & 0x7F) as u64;
    }
    Ok(Some(value))
}

// ---------------------------------------------------------------------------
// Main file parser
// ---------------------------------------------------------------------------

/// Parse a single binary scan file and feed records into the output manager.
///
/// Returns the total number of records processed.
fn binaryfile_parse(
    out: &mut OutputManager,
    filename: &Path,
    filter: Option<&MassIP>,
    btypes: Option<&RangeList>,
) -> u64 {
    let file = match File::open(filename) {
        Ok(f) => f,
        Err(e) => {
            log::error!("[-] FAIL: --readscan {}: {}", filename.display(), e);
            return 0;
        }
    };
    let mut reader = BufReader::new(file);

    log::info!("[+] --readscan {}", filename.display());

    let mut buf = vec![0u8; BUF_MAX];
    let mut when_scan_started: u64 = 0;
    let mut total_records: u64 = 0;

    // First record is a pseudo-record (header).
    // The C code reads 'a'+2 = 99 bytes for the header.
    let header_size = b'a' as usize + 2; // 99
    match reader.read_exact(&mut buf[..header_size]) {
        Ok(()) => {}
        Err(_) => {
            log::error!("[-] {}: file too short for header", filename.display());
            return 0;
        }
    }

    // Validate magic
    if &buf[..FILE_MAGIC.len()] != FILE_MAGIC {
        log::error!(
            "[-] {}: unknown file format (expected \"zorp/1.1\")",
            filename.display()
        );
        return 0;
    }

    // Look for start time in header
    if buf[11] == b'.' {
        // Try to parse version and timestamp from the header
        if let Ok(header_str) = std::str::from_utf8(&buf[12..header_size]) {
            let version_part = header_str.split_whitespace().next().unwrap_or("");
            if let Ok(version) = version_part.parse::<u32>() {
                if version >= 2 {
                    // Find the 's:' timestamp marker
                    if let Some(pos) = header_str.find("s:") {
                        let ts_str = &header_str[pos + 2..];
                        if let Ok(ts) = ts_str.trim().parse::<u64>() {
                            when_scan_started = ts;
                        }
                    }
                }
            }
        }
    }

    // Read all subsequent records
    loop {
        // Read record type (variable-length encoded)
        let record_type = match read_varint(&mut reader) {
            Ok(Some(v)) => v,
            Ok(None) => break, // EOF
            Err(_) => break,
        };

        // Read record length (variable-length encoded)
        let length = match read_varint(&mut reader) {
            Ok(Some(v)) => v as usize,
            Ok(None) => break,
            Err(_) => break,
        };

        if length > BUF_MAX {
            log::error!("[-] file corrupt: record length {} exceeds max", length);
            break;
        }

        // Read record body
        match reader.read_exact(&mut buf[..length]) {
            Ok(()) => {}
            Err(_) => break,
        }

        let record_buf = &buf[..length];

        // Dispatch based on record type
        let rt = RecordType::from_u8(record_type as u8);
        match rt {
            Some(RecordType::StatusOpen) => {
                if btypes.map_or(true, |bt| bt.count() == 0) {
                    parse_status(out, PortStatus::Open, record_buf, &mut when_scan_started);
                }
            }
            Some(RecordType::StatusClosed) => {
                if btypes.map_or(true, |bt| bt.count() == 0) {
                    parse_status(out, PortStatus::Closed, record_buf, &mut when_scan_started);
                }
            }
            Some(RecordType::Banner3) => {
                parse_banner3(out, record_buf, &mut when_scan_started);
            }
            Some(RecordType::Banner4Old) => {
                // Read one more byte (the C code does this)
                let mut extra = [0u8; 1];
                if reader.read_exact(&mut extra).is_ok() {
                    // Append the extra byte to buffer
                    let new_len = length + 1;
                    if new_len <= BUF_MAX {
                        buf[length] = extra[0];
                        parse_banner4(out, &buf[..new_len], &mut when_scan_started);
                    }
                }
            }
            Some(RecordType::Banner4) => {
                parse_banner4(out, record_buf, &mut when_scan_started);
            }
            Some(RecordType::Status2Open) => {
                if btypes.map_or(true, |bt| bt.count() == 0) {
                    parse_status2(out, PortStatus::Open, record_buf, &mut when_scan_started, filter);
                }
            }
            Some(RecordType::Status2Closed) => {
                if btypes.map_or(true, |bt| bt.count() == 0) {
                    parse_status2(out, PortStatus::Closed, record_buf, &mut when_scan_started, filter);
                }
            }
            Some(RecordType::Banner9) => {
                parse_banner9(out, record_buf, &mut when_scan_started, filter, btypes);
            }
            Some(RecordType::Status6Open) => {
                if btypes.map_or(true, |bt| bt.count() == 0) {
                    parse_status6(out, PortStatus::Open, record_buf, &mut when_scan_started, filter);
                }
            }
            Some(RecordType::Status6Closed) => {
                if btypes.map_or(true, |bt| bt.count() == 0) {
                    parse_status6(out, PortStatus::Closed, record_buf, &mut when_scan_started, filter);
                }
            }
            Some(RecordType::Banner6) => {
                parse_banner6(out, record_buf, &mut when_scan_started, filter, btypes);
            }
            Some(RecordType::FileHeader) => {
                // Ignore file header records
            }
            None => {
                log::error!("[-] file corrupt: unknown type {}", record_type);
                break;
            }
        }

        total_records += 1;
        if total_records & 0xFFFF == 0 {
            log::info!("[+] {}: {:8} records\r", filename.display(), total_records);
        }
    }

    total_records
}

/// Read binary scan files and output the results.
///
/// This is the main entry point for `--readscan` mode. It reads one or
/// more binary scan files and feeds the records through the output
/// manager, preserving original timestamps.
///
/// * `out` — the output manager to write results to.
/// * `files` — list of binary scan file paths.
/// * `filter` — optional IP/port filter from command-line targets.
/// * `btypes` — optional banner-type filter.
pub fn readscan_binary_scanfile(
    out: &mut OutputManager,
    files: &[&Path],
    filter: Option<&MassIP>,
    btypes: Option<&RangeList>,
) {
    for file in files {
        binaryfile_parse(out, file, filter, btypes);
    }
}

// ---------------------------------------------------------------------------
// ApplicationProtocol conversion helper
// ---------------------------------------------------------------------------

/// Convert a numeric application protocol code to the enum.
fn app_proto_to_enum(code: u32) -> ApplicationProtocol {
    match code {
        0 => ApplicationProtocol::None,
        1 => ApplicationProtocol::Heur,
        2 => ApplicationProtocol::Ssh1,
        3 => ApplicationProtocol::Ssh2,
        4 => ApplicationProtocol::Http,
        5 => ApplicationProtocol::Ftp,
        6 => ApplicationProtocol::DnsVersionBind,
        7 => ApplicationProtocol::Snmp,
        8 => ApplicationProtocol::Nbtstat,
        9 => ApplicationProtocol::Ssl3,
        10 => ApplicationProtocol::Smb,
        11 => ApplicationProtocol::Smtp,
        12 => ApplicationProtocol::Pop3,
        13 => ApplicationProtocol::Imap4,
        14 => ApplicationProtocol::UdpZeroAccess,
        15 => ApplicationProtocol::X509Cert,
        16 => ApplicationProtocol::X509CaCert,
        17 => ApplicationProtocol::HtmlTitle,
        18 => ApplicationProtocol::HtmlFull,
        19 => ApplicationProtocol::Ntp,
        20 => ApplicationProtocol::Vuln,
        21 => ApplicationProtocol::Heartbleed,
        22 => ApplicationProtocol::Ticketbleed,
        23 => ApplicationProtocol::VncOld,
        24 => ApplicationProtocol::Safe,
        25 => ApplicationProtocol::Memcached,
        26 => ApplicationProtocol::Scripting,
        27 => ApplicationProtocol::Versioning,
        28 => ApplicationProtocol::Coap,
        29 => ApplicationProtocol::Telnet,
        30 => ApplicationProtocol::Rdp,
        31 => ApplicationProtocol::HttpServer,
        32 => ApplicationProtocol::Minecraft,
        33 => ApplicationProtocol::VncRfb,
        34 => ApplicationProtocol::VncInfo,
        35 => ApplicationProtocol::Isakmp,
        36 => ApplicationProtocol::Error,
        _ => ApplicationProtocol::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_type_roundtrip() {
        assert_eq!(RecordType::from_u8(1), Some(RecordType::StatusOpen));
        assert_eq!(RecordType::from_u8(6), Some(RecordType::Status2Open));
        assert_eq!(RecordType::from_u8(10), Some(RecordType::Status6Open));
        assert_eq!(RecordType::from_u8(13), Some(RecordType::Banner6));
        assert_eq!(RecordType::from_u8(b'm'), Some(RecordType::FileHeader));
        assert_eq!(RecordType::from_u8(99), None);
    }

    #[test]
    fn varint_single_byte() {
        let data: &[u8] = &[42];
        let mut cursor = data;
        let result = read_varint(&mut cursor).unwrap();
        assert_eq!(result, Some(42));
    }

    #[test]
    fn varint_two_bytes() {
        // 0x80 | 0x01 = continuation + value bits
        // Second byte: 0x01
        // Value = (0 << 7) | 1 = 1 — actually (0x00 << 7) | 0x01 = 1
        // Let's encode 128: first byte = 0x81 (continue, data=1), second = 0x00
        // Value = (1 << 7) | 0 = 128
        let data: &[u8] = &[0x81, 0x00];
        let mut cursor = data;
        let result = read_varint(&mut cursor).unwrap();
        assert_eq!(result, Some(128));
    }

    #[test]
    fn record_cursor_reads() {
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x0A, // u32 = 10
            0xFF,                   // byte = 255
            0x00, 0x50,             // u16 = 80
        ];
        let mut cur = RecordCursor::new(buf);
        assert_eq!(cur.get_u32(), 10);
        assert_eq!(cur.get_byte(), 255);
        assert_eq!(cur.get_u16(), 80);
        assert_eq!(cur.remaining(), 0);
    }

    #[test]
    fn app_proto_roundtrip() {
        assert_eq!(app_proto_to_enum(0), ApplicationProtocol::None);
        assert_eq!(app_proto_to_enum(9), ApplicationProtocol::Ssl3);
        assert_eq!(app_proto_to_enum(20), ApplicationProtocol::Vuln);
        assert_eq!(app_proto_to_enum(999), ApplicationProtocol::None);
    }
}
