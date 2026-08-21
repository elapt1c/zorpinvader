//! Parser for the `nmap-service-probes` file.
//!
//! This file describes how to probe network services and identify them
//! by matching their responses against known patterns. The format is
//! documented in the nmap project:
//!
//! ```text
//! Exclude <port specification>
//! Probe <protocol> <probename> <probestring>
//! match <service> <pattern> [<versioninfo>]
//! softmatch <service> <pattern>
//! ports <portlist>
//! sslports <portlist>
//! totalwaitms <milliseconds>
//! tcpwrappedms <milliseconds>
//! rarity <value between 1 and 9>
//! fallback <Comma separated list of probes>
//! ```
//!
//! **Ported from C `read-service-probes.c`.**

use std::fmt;
use std::fs;
use std::io::{self, Write as IoWrite};
use std::path::Path;

use crate::massip::port::{TEMPL_TCP, TEMPL_UDP, TEMPL_SCTP};
use crate::massip::rangesv4::{RangeList, rangelist_parse_ports};

// ---------------------------------------------------------------------------
// Enum types
// ---------------------------------------------------------------------------

/// Record types found in the service-probes file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvcPRecordType {
    Unknown,
    Exclude,
    Probe,
    Match,
    Softmatch,
    Ports,
    Sslports,
    Totalwaitms,
    Tcpwrappedms,
    Rarity,
    Fallback,
}

/// Version info field types in match directives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvcVInfoType {
    Unknown,
    ProductName,
    Version,
    Info,
    Hostname,
    OperatingSystem,
    DeviceType,
    CpeName,
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Version info entry attached to a match directive.
#[derive(Debug, Clone)]
pub struct ServiceVersionInfo {
    pub info_type: SvcVInfoType,
    pub value: String,
    pub is_a: bool,
}

/// Fallback probe reference.
#[derive(Debug, Clone)]
pub struct ServiceProbeFallback {
    pub name: String,
}

/// A single match (or softmatch) directive.
#[derive(Debug, Clone)]
pub struct ServiceProbeMatch {
    pub service: String,
    pub regex: String,
    pub regex_length: usize,
    pub versioninfo: Vec<ServiceVersionInfo>,
    pub is_case_insensitive: bool,
    pub is_include_newlines: bool,
    pub is_softmatch: bool,
}

/// A single probe definition with its associated directives.
#[derive(Debug, Clone)]
pub struct NmapServiceProbe {
    pub name: String,
    pub hellostring: Vec<u8>,
    pub protocol: u32,
    pub totalwaitms: u32,
    pub tcpwrappedms: u32,
    pub rarity: u32,
    pub ports: RangeList,
    pub sslports: RangeList,
    pub matches: Vec<ServiceProbeMatch>,
    pub fallback: Vec<ServiceProbeFallback>,
}

/// The complete list of service probes parsed from a file.
#[derive(Debug)]
pub struct NmapServiceProbeList {
    pub list: Vec<NmapServiceProbe>,
    pub exclude: RangeList,
}

// ---------------------------------------------------------------------------
// Parsing context (internal)
// ---------------------------------------------------------------------------

struct ParseContext {
    filename: String,
    line_number: u32,
}

impl ParseContext {
    fn new(filename: &str) -> Self {
        ParseContext {
            filename: filename.to_string(),
            line_number: 0,
        }
    }

    fn warn(&self, col: usize, msg: &str) {
        eprintln!("{}:{}:{}: {}", self.filename, self.line_number, col, msg);
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn is_hexchar(c: u8) -> bool {
    matches!(c, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')
}

fn hexval(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0xFF,
    }
}

// ---------------------------------------------------------------------------
// Type parsing
// ---------------------------------------------------------------------------

/// Parse the record type keyword from the beginning of a line.
/// Returns the type and the byte offset after the keyword + trailing whitespace.
fn parse_type(line: &[u8], offset: &mut usize) -> SvcPRecordType {
    let line_length = line.len();
    let start = *offset;

    // Find end of keyword
    while *offset < line_length && !line[*offset].is_ascii_whitespace() {
        *offset += 1;
    }
    let name = &line[start..*offset];

    // Skip trailing whitespace
    while *offset < line_length && line[*offset].is_ascii_whitespace() {
        *offset += 1;
    }

    match name {
        b"exclude" | b"Exclude" => SvcPRecordType::Exclude,
        b"probe" | b"Probe" => SvcPRecordType::Probe,
        b"match" | b"Match" => SvcPRecordType::Match,
        b"softmatch" | b"Softmatch" => SvcPRecordType::Softmatch,
        b"ports" | b"Ports" => SvcPRecordType::Ports,
        b"sslports" | b"Sslports" => SvcPRecordType::Sslports,
        b"totalwaitms" | b"Totalwaitms" => SvcPRecordType::Totalwaitms,
        b"tcpwrappedms" | b"Tcpwrappedms" => SvcPRecordType::Tcpwrappedms,
        b"rarity" | b"Rarity" => SvcPRecordType::Rarity,
        b"fallback" | b"Fallback" => SvcPRecordType::Fallback,
        _ => SvcPRecordType::Unknown,
    }
}

// ---------------------------------------------------------------------------
// Port parsing
// ---------------------------------------------------------------------------

fn parse_ports(ctx: &ParseContext, line: &str, offset: usize) -> RangeList {
    let mut ranges = RangeList::new();
    let mut is_error = false;
    rangelist_parse_ports(&mut ranges, &line[offset..], Some(&mut is_error), 0);
    if is_error {
        ctx.warn(offset, "bad port spec");
        ranges.remove_all();
    }
    ranges
}

// ---------------------------------------------------------------------------
// Number parsing
// ---------------------------------------------------------------------------

fn parse_number(ctx: &ParseContext, line: &[u8], mut offset: usize) -> u32 {
    let line_length = line.len();
    let mut number = 0u32;

    while offset < line_length && line[offset].is_ascii_digit() {
        number = number * 10 + (line[offset] - b'0') as u32;
        offset += 1;
    }
    while offset < line_length && line[offset].is_ascii_whitespace() {
        offset += 1;
    }

    if offset != line_length {
        ctx.warn(offset, "unexpected character after number");
    }

    number
}

// ---------------------------------------------------------------------------
// Name parsing
// ---------------------------------------------------------------------------

fn parse_name(line: &[u8], offset: &mut usize) -> Option<String> {
    let line_length = line.len();
    let name_start = *offset;

    // Grab non-whitespace characters
    while *offset < line_length && !line[*offset].is_ascii_whitespace() {
        *offset += 1;
    }
    let name_length = *offset - name_start;
    if name_length == 0 {
        return None;
    }

    // Skip trailing whitespace
    while *offset < line_length && line[*offset].is_ascii_whitespace() {
        *offset += 1;
    }

    Some(
        String::from_utf8_lossy(&line[name_start..name_start + name_length]).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// Fallback parsing
// ---------------------------------------------------------------------------

fn parse_fallback(
    ctx: &ParseContext,
    line: &[u8],
    mut offset: usize,
) -> Vec<ServiceProbeFallback> {
    let line_length = line.len();
    let mut result = Vec::new();

    while offset < line_length {
        let name_start = offset;

        // Grab characters until comma or whitespace
        while offset < line_length
            && !line[offset].is_ascii_whitespace()
            && line[offset] != b','
        {
            offset += 1;
        }
        let name_length = offset - name_start;

        // Skip commas and whitespace
        while offset < line_length
            && (line[offset].is_ascii_whitespace() || line[offset] == b',')
        {
            offset += 1;
        }

        if name_length == 0 {
            ctx.warn(name_start, "fallback name too short");
            break;
        }

        let name =
            String::from_utf8_lossy(&line[name_start..name_start + name_length]).into_owned();
        result.push(ServiceProbeFallback { name });
    }

    result
}

// ---------------------------------------------------------------------------
// Probe parsing
// ---------------------------------------------------------------------------

fn parse_probe(
    ctx: &ParseContext,
    line: &[u8],
    mut offset: usize,
    list: &mut NmapServiceProbeList,
) {
    let line_length = line.len();

    // Create a new blank probe
    let mut probe = NmapServiceProbe {
        name: String::new(),
        hellostring: Vec::new(),
        protocol: 0,
        totalwaitms: 0,
        tcpwrappedms: 0,
        rarity: 0,
        ports: RangeList::new(),
        sslports: RangeList::new(),
        matches: Vec::new(),
        fallback: Vec::new(),
    };

    // <protocol>
    if line_length - offset <= 3 {
        ctx.warn(offset, "probe line too short");
        return;
    }
    if &line[offset..offset + 3] == b"TCP" {
        probe.protocol = 6;
    } else if &line[offset..offset + 3] == b"UDP" {
        probe.protocol = 17;
    } else {
        ctx.warn(offset, "unknown protocol");
        return;
    }
    offset += 3;
    if offset < line_length && !line[offset].is_ascii_whitespace() {
        ctx.warn(offset, "unexpected character after protocol");
        return;
    }
    while offset < line_length && line[offset].is_ascii_whitespace() {
        offset += 1;
    }

    // <probename>
    match parse_name(line, &mut offset) {
        Some(name) => probe.name = name,
        None => {
            ctx.warn(offset, "probename parse error");
            return;
        }
    }

    // <probestring> — must start with 'q', then a delimiter char
    if line_length - offset <= 2 {
        ctx.warn(offset, "probe string too short");
        return;
    }
    if line[offset] != b'q' {
        ctx.warn(offset, &format!("expected 'q', found '{}'", line[offset] as char));
        return;
    }
    offset += 1;

    let delimiter = line[offset];
    offset += 1;

    let mut hello = Vec::with_capacity(line_length - offset);

    while offset < line_length && line[offset] != delimiter {
        if line[offset] != b'\\' {
            hello.push(line[offset]);
            offset += 1;
            continue;
        }

        // Skip the backslash
        offset += 1;
        if offset >= line_length || line[offset] == delimiter {
            ctx.warn(offset, "premature end of escape sequence");
            return;
        }

        match line[offset] {
            b'\\' => {
                hello.push(b'\\');
                offset += 1;
            }
            b'0' => {
                hello.push(0);
                offset += 1;
            }
            b'a' => {
                hello.push(b'\x07');
                offset += 1;
            }
            b'b' => {
                hello.push(b'\x08');
                offset += 1;
            }
            b'f' => {
                hello.push(b'\x0C');
                offset += 1;
            }
            b'n' => {
                hello.push(b'\n');
                offset += 1;
            }
            b'r' => {
                hello.push(b'\r');
                offset += 1;
            }
            b't' => {
                hello.push(b'\t');
                offset += 1;
            }
            b'v' => {
                hello.push(b'\x0B');
                offset += 1;
            }
            b'x' => {
                offset += 1;
                if offset + 2 > line_length
                    || line[offset] == delimiter
                    || (offset + 1 < line_length && line[offset + 1] == delimiter)
                {
                    ctx.warn(offset, "hex escape too short");
                    return;
                }
                if !is_hexchar(line[offset]) || !is_hexchar(line[offset + 1]) {
                    ctx.warn(offset, "invalid hex in escape");
                    return;
                }
                let val = (hexval(line[offset]) << 4) | hexval(line[offset + 1]);
                hello.push(val);
                offset += 2;
            }
            other => {
                ctx.warn(
                    offset,
                    &format!("unexpected escape character '{}'", other as char),
                );
                return;
            }
        }
    }

    if offset >= line_length || line[offset] != delimiter {
        ctx.warn(offset, &format!("missing end delimiter '{}'", delimiter as char));
        return;
    }

    probe.hellostring = hello;
    list.list.push(probe);
}

// ---------------------------------------------------------------------------
// Match parsing
// ---------------------------------------------------------------------------

fn parse_match(
    ctx: &ParseContext,
    line: &[u8],
    mut offset: usize,
    is_softmatch: bool,
) -> Option<ServiceProbeMatch> {
    let line_length = line.len();

    // <servicename>
    let service = match parse_name(line, &mut offset) {
        Some(s) => s,
        None => {
            ctx.warn(offset, "servicename is empty");
            return None;
        }
    };

    // <pattern> — must start with 'm', then delimiter
    if line_length - offset <= 2 {
        ctx.warn(offset, "match pattern too short");
        return None;
    }
    if line[offset] != b'm' {
        ctx.warn(offset, &format!("expected 'm', found '{}'", line[offset] as char));
        return None;
    }
    offset += 1;

    let delimiter = line[offset];
    offset += 1;

    // Find end of regex
    let regex_start = offset;
    while offset < line_length && line[offset] != delimiter {
        offset += 1;
    }
    if offset >= line_length || line[offset] != delimiter {
        ctx.warn(
            offset,
            &format!("missing ending delimiter '{}'", delimiter as char),
        );
        return None;
    }
    let regex = String::from_utf8_lossy(&line[regex_start..offset]).into_owned();
    let regex_length = regex.len();
    offset += 1; // skip end delimiter

    // Parse regex options
    let mut is_case_insensitive = false;
    let mut is_include_newlines = false;

    while offset < line_length && !line[offset].is_ascii_whitespace() {
        match line[offset] {
            b'i' => is_case_insensitive = true,
            b's' => is_include_newlines = true,
            other => {
                ctx.warn(
                    offset,
                    &format!("unknown regex option '{}'", other as char),
                );
                return None;
            }
        }
        offset += 1;
    }
    while offset < line_length && line[offset].is_ascii_whitespace() {
        offset += 1;
    }

    // <versioninfo> — optional fields
    let mut versioninfo = Vec::new();

    while offset < line_length {
        if offset + 2 >= line_length {
            ctx.warn(offset, "unexpected character at end of versioninfo");
            return None;
        }

        // Parse identifier
        let id = line[offset];
        offset += 1;
        if id == b'c' {
            if offset + 3 > line_length || &line[offset..offset + 3] != b"pe:" {
                ctx.warn(offset, "expected 'cpe:'");
                return None;
            }
            offset += 3;
        }

        let info_type = match id {
            b'p' => SvcVInfoType::ProductName,
            b'v' => SvcVInfoType::Version,
            b'i' => SvcVInfoType::Info,
            b'h' => SvcVInfoType::Hostname,
            b'o' => SvcVInfoType::OperatingSystem,
            b'd' => SvcVInfoType::DeviceType,
            b'c' => SvcVInfoType::CpeName,
            _ => {
                ctx.warn(offset, &format!("unknown versioninfo id '{}'", id as char));
                return None;
            }
        };

        // Parse delimiter + value
        if offset + 2 >= line_length {
            ctx.warn(offset, "versioninfo value too short");
            return None;
        }
        let vi_delimiter = line[offset];
        offset += 1;

        let value_start = offset;
        while offset < line_length && line[offset] != vi_delimiter {
            offset += 1;
        }
        if offset >= line_length || line[offset] != vi_delimiter {
            ctx.warn(
                offset,
                &format!("missing ending delimiter '{}'", vi_delimiter as char),
            );
            return None;
        }
        let value = String::from_utf8_lossy(&line[value_start..offset]).into_owned();
        offset += 1; // skip end delimiter

        // Check for trailing 'a' flag (cpe)
        let mut is_a = false;
        if id == b'c' && offset < line_length && line[offset] == b'a' {
            is_a = true;
            offset += 1;
        }

        // Skip whitespace
        while offset < line_length && line[offset].is_ascii_whitespace() {
            offset += 1;
        }

        versioninfo.push(ServiceVersionInfo {
            info_type,
            value,
            is_a,
        });
    }

    Some(ServiceProbeMatch {
        service,
        regex,
        regex_length,
        versioninfo,
        is_case_insensitive,
        is_include_newlines,
        is_softmatch,
    })
}

// ---------------------------------------------------------------------------
// Line-level parsing
// ---------------------------------------------------------------------------

fn parse_line(list: &mut NmapServiceProbeList, ctx: &mut ParseContext, line: &str) {
    let line_bytes = line.as_bytes();
    let mut line_length = line_bytes.len();
    let mut offset = 0usize;

    // Trim trailing whitespace / newline
    while line_length > 0 && line_bytes[line_length - 1].is_ascii_whitespace() {
        line_length -= 1;
    }

    // Skip leading whitespace
    while offset < line_length && line_bytes[offset].is_ascii_whitespace() {
        offset += 1;
    }

    // Ignore empty lines
    if offset >= line_length {
        return;
    }

    // Ignore comment lines (lines starting with punctuation, typically '#')
    if line_bytes[offset].is_ascii_punctuation() && line_bytes[offset] == b'#' {
        return;
    }
    // The C code checks ispunct() which includes more than just '#'
    if line_bytes[offset].is_ascii_punctuation() {
        return;
    }

    // Parse the type keyword
    let record_type = parse_type(line_bytes, &mut offset);

    match record_type {
        SvcPRecordType::Unknown => {
            ctx.warn(offset, &format!("unknown type: '{}'", String::from_utf8_lossy(&line_bytes[..offset])));
            return;
        }
        SvcPRecordType::Exclude => {
            if !list.list.is_empty() {
                ctx.warn(offset, "'Exclude' directive only valid before any 'Probe'");
                return;
            }
            let ranges = parse_ports(ctx, line, offset);
            if ranges.count() == 0 {
                ctx.warn(offset, "'Exclude' bad format");
            } else {
                list.exclude.merge(&ranges);
            }
            return;
        }
        SvcPRecordType::Probe => {
            parse_probe(ctx, &line_bytes[..line_length], offset, list);
            return;
        }
        _ => {}
    }

    // Remaining directives operate on the current probe
    if list.list.is_empty() {
        ctx.warn(offset, "directive only valid after a 'Probe'");
        return;
    }

    let probe_idx = list.list.len() - 1;

    match record_type {
        SvcPRecordType::Ports => {
            let ranges = parse_ports(ctx, line, offset);
            if ranges.count() == 0 {
                ctx.warn(offset, "bad ports format");
            } else {
                list.list[probe_idx].ports.merge(&ranges);
            }
        }
        SvcPRecordType::Sslports => {
            let ranges = parse_ports(ctx, line, offset);
            if ranges.count() == 0 {
                ctx.warn(offset, "bad sslports format");
            } else {
                list.list[probe_idx].sslports.merge(&ranges);
            }
        }
        SvcPRecordType::Match | SvcPRecordType::Softmatch => {
            let is_soft = record_type == SvcPRecordType::Softmatch;
            if let Some(m) = parse_match(ctx, &line_bytes[..line_length], offset, is_soft) {
                list.list[probe_idx].matches.push(m);
            }
        }
        SvcPRecordType::Totalwaitms => {
            list.list[probe_idx].totalwaitms =
                parse_number(ctx, &line_bytes[..line_length], offset);
        }
        SvcPRecordType::Tcpwrappedms => {
            list.list[probe_idx].tcpwrappedms =
                parse_number(ctx, &line_bytes[..line_length], offset);
        }
        SvcPRecordType::Rarity => {
            list.list[probe_idx].rarity =
                parse_number(ctx, &line_bytes[..line_length], offset);
        }
        SvcPRecordType::Fallback => {
            let fb = parse_fallback(ctx, &line_bytes[..line_length], offset);
            list.list[probe_idx].fallback.extend(fb);
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

impl NmapServiceProbeList {
    /// Create a new, empty probe list.
    pub fn new() -> Self {
        NmapServiceProbeList {
            list: Vec::new(),
            exclude: RangeList::new(),
        }
    }

    /// Read and parse an `nmap-service-probes` file from disk.
    pub fn read_file(filename: &Path) -> io::Result<Self> {
        let contents = fs::read_to_string(filename)?;
        let mut list = Self::new();
        let mut ctx = ParseContext::new(
            filename.to_str().unwrap_or("<unknown>"),
        );

        for line in contents.lines() {
            ctx.line_number += 1;
            parse_line(&mut list, &mut ctx, line);
        }

        Ok(list)
    }

    /// Parse service probes from a string (for testing).
    pub fn from_str(contents: &str, name: &str) -> Self {
        let mut list = Self::new();
        let mut ctx = ParseContext::new(name);

        for line in contents.lines() {
            ctx.line_number += 1;
            parse_line(&mut list, &mut ctx, line);
        }

        list
    }

    /// Print the parsed probes to a writer (for debugging/testing).
    pub fn print_to<W: IoWrite>(&self, out: &mut W) {
        print_ports(&self.exclude, out, "Exclude", None);

        for probe in &self.list {
            let proto_str = if probe.protocol == 6 { "TCP" } else { "UDP" };
            let _ = write!(out, "Probe {} {} q", proto_str, probe.name);
            print_hello(out, &probe.hellostring, b'|');
            let _ = writeln!(out);

            if probe.rarity > 0 {
                let _ = writeln!(out, "rarity {}", probe.rarity);
            }
            if probe.totalwaitms > 0 {
                let _ = writeln!(out, "totalwaitms {}", probe.totalwaitms);
            }
            if probe.tcpwrappedms > 0 {
                let _ = writeln!(out, "tcpwrappedms {}", probe.tcpwrappedms);
            }

            let default_proto = if probe.protocol == 6 {
                Some(TEMPL_TCP)
            } else {
                Some(TEMPL_UDP)
            };
            print_ports(&probe.ports, out, "ports", default_proto);
            print_ports(&probe.sslports, out, "sslports", default_proto);

            for m in &probe.matches {
                let _ = write!(out, "match {} m", m.service);
                print_dstring(out, m.regex.as_bytes(), b'/');
                if m.is_case_insensitive {
                    let _ = write!(out, "i");
                }
                if m.is_include_newlines {
                    let _ = write!(out, "s");
                }
                let _ = write!(out, " ");

                for vi in &m.versioninfo {
                    let tag = match vi.info_type {
                        SvcVInfoType::Unknown => "u",
                        SvcVInfoType::ProductName => "p",
                        SvcVInfoType::Version => "v",
                        SvcVInfoType::Info => "i",
                        SvcVInfoType::Hostname => "h",
                        SvcVInfoType::OperatingSystem => "o",
                        SvcVInfoType::DeviceType => "e",
                        SvcVInfoType::CpeName => "cpe:",
                    };
                    let _ = write!(out, "{}", tag);
                    print_dstring(out, vi.value.as_bytes(), b'/');
                    if vi.is_a {
                        let _ = write!(out, "a");
                    }
                    let _ = write!(out, " ");
                }
                let _ = writeln!(out);
            }
        }
    }

    /// Self-test: parse a small set of known-good lines and verify no panics.
    pub fn selftest() -> bool {
        let lines = "\
Exclude 53,T:9100,U:30000-40000
Probe UDP DNSStatusRequest q|\\0\\0\\x10\\0\\0\\0\\0\\0\\0\\0\\0\\0|
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
ports 80
sslports 443
Probe TCP NULL q||
ports 21,43,110,113,199,505,540,1248,5432,30444
match ftp m/^220.*Welcome to .*Pure-?FTPd (\\d\\S+\\s*)/ p/Pure-FTPd/ v/$1/ cpe:/a:pureftpd:pure-ftpd:$1/
match ssh m/^SSH-([\\d.]+)-OpenSSH[_-]([\\w.]+)\\r?\\n/i p/OpenSSH/ v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/
match mysql m|^\\x10\\0\\0\\x01\\xff\\x13\\x04Bad handshake$| p/MySQL/ cpe:/a:mysql:mysql/
match chargen m|@ABCDEFGHIJKLMNOPQRSTUVWXYZ|
match uucp m|^login: login: login: $| p/NetBSD uucpd/ o/NetBSD/ cpe:/o:netbsd:netbsd/a
match printer m|^([\\w-_.]+): lpd: Illegal service request\\n$| p/lpd/ h/$1/
match afs m|^[\\d\\D]{28}\\s*(OpenAFS)([\\d\\.]{3}[^\\s\\0]*)\\0| p/$1/ v/$2/
";

        let list = NmapServiceProbeList::from_str(lines, "<selftest>");

        // Basic structural checks
        if list.list.len() != 3 {
            eprintln!(
                "[-] service probes selftest: expected 3 probes, got {}",
                list.list.len()
            );
            return false;
        }

        // First probe: UDP DNSStatusRequest
        let p0 = &list.list[0];
        if p0.name != "DNSStatusRequest" || p0.protocol != 17 {
            eprintln!("[-] service probes selftest: probe 0 mismatch");
            return false;
        }

        // Second probe: TCP GetRequest, ports 80, sslports 443
        let p1 = &list.list[1];
        if p1.name != "GetRequest" || p1.protocol != 6 {
            eprintln!("[-] service probes selftest: probe 1 mismatch");
            return false;
        }
        if p1.ports.count() == 0 {
            eprintln!("[-] service probes selftest: probe 1 has no ports");
            return false;
        }
        if p1.sslports.count() == 0 {
            eprintln!("[-] service probes selftest: probe 1 has no sslports");
            return false;
        }

        // Third probe: TCP NULL, with many matches
        let p2 = &list.list[2];
        if p2.name != "NULL" || p2.protocol != 6 {
            eprintln!("[-] service probes selftest: probe 2 mismatch");
            return false;
        }
        if p2.matches.len() != 7 {
            eprintln!(
                "[-] service probes selftest: expected 7 matches, got {}",
                p2.matches.len()
            );
            return false;
        }

        // Check a specific match: ssh should be case-insensitive
        let ssh_match = &p2.matches[1];
        if ssh_match.service != "ssh" || !ssh_match.is_case_insensitive {
            eprintln!("[-] service probes selftest: ssh match mismatch");
            return false;
        }
        if ssh_match.versioninfo.len() != 3 {
            eprintln!(
                "[-] service probes selftest: ssh match expected 3 versioninfo, got {}",
                ssh_match.versioninfo.len()
            );
            return false;
        }

        true
    }
}

impl Default for NmapServiceProbeList {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Print helpers
// ---------------------------------------------------------------------------

fn contains_char(data: &[u8], c: u8) -> bool {
    data.iter().any(|&b| b == c)
}

/// Print a delimited string, choosing an alternative delimiter if the
/// preferred one appears in the string.
fn print_dstring<W: IoWrite>(out: &mut W, data: &[u8], preferred_delimiter: u8) {
    let delimiters = b"|/\"'#*+-!@$%^&()_=";
    let mut delimiter = preferred_delimiter;

    if contains_char(data, delimiter) {
        for &d in delimiters {
            if !contains_char(data, d) {
                delimiter = d;
                break;
            }
        }
    }

    let _ = out.write_all(&[delimiter]);
    let _ = out.write_all(data);
    let _ = out.write_all(&[delimiter]);
}

/// Print a hello/probe string with escape sequences.
fn print_hello<W: IoWrite>(out: &mut W, data: &[u8], preferred_delimiter: u8) {
    let delimiters = b"|/\"'#*+-!@$%^&()_=";
    let mut delimiter = preferred_delimiter;

    if contains_char(data, delimiter) {
        for &d in delimiters {
            if !contains_char(data, d) {
                delimiter = d;
                break;
            }
        }
    }

    let _ = out.write_all(&[delimiter]);
    for &c in data {
        match c {
            b'\\' => { let _ = out.write_all(b"\\\\"); }
            0     => { let _ = out.write_all(b"\\0"); }
            0x07  => { let _ = out.write_all(b"\\a"); }
            0x08  => { let _ = out.write_all(b"\\b"); }
            0x0C  => { let _ = out.write_all(b"\\f"); }
            b'\n' => { let _ = out.write_all(b"\\n"); }
            b'\r' => { let _ = out.write_all(b"\\r"); }
            b'\t' => { let _ = out.write_all(b"\\t"); }
            0x0B  => { let _ = out.write_all(b"\\v"); }
            c if c.is_ascii_graphic() || c == b' ' => {
                let _ = out.write_all(&[c]);
            }
            _ => {
                let _ = write!(out, "\\x{:02x}", c);
            }
        }
    }
    let _ = out.write_all(&[delimiter]);
}

/// Print port ranges. This is a simplified version that handles TCP/UDP/SCTP.
fn print_ports<W: IoWrite>(
    ranges: &RangeList,
    out: &mut W,
    prefix: &str,
    default_proto: Option<u32>,
) {
    if ranges.count() == 0 {
        return;
    }

    let _ = write!(out, "{} ", prefix);

    let mut current_proto = default_proto;

    for (i, range) in ranges.list.iter().enumerate() {
        let begin = range.begin;
        let end = range.end;

        // Determine protocol
        let proto = if begin < TEMPL_UDP {
            TEMPL_TCP
        } else if begin < TEMPL_SCTP {
            TEMPL_UDP
        } else {
            TEMPL_SCTP
        };

        // Adjust port numbers
        let port_begin = begin - proto;
        let port_end = end - proto;

        if i > 0 {
            let _ = write!(out, ",");
        }

        if current_proto != Some(proto) {
            current_proto = Some(proto);
            match proto {
                TEMPL_TCP => { let _ = write!(out, "T:"); }
                TEMPL_UDP => { let _ = write!(out, "U:"); }
                TEMPL_SCTP => { let _ = write!(out, "S:"); }
                _ => {}
            }
        }

        let _ = write!(out, "{}", port_begin);
        if port_end > port_begin {
            let _ = write!(out, "-{}", port_end);
        }
    }
    let _ = writeln!(out);
}

// ---------------------------------------------------------------------------
// Display implementations
// ---------------------------------------------------------------------------

impl fmt::Display for NmapServiceProbeList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = Vec::new();
        self.print_to(&mut buf);
        let s = String::from_utf8_lossy(&buf);
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selftest_passes() {
        assert!(NmapServiceProbeList::selftest());
    }

    #[test]
    fn parse_empty_string() {
        let list = NmapServiceProbeList::from_str("", "<empty>");
        assert!(list.list.is_empty());
    }

    #[test]
    fn parse_comments_ignored() {
        let list = NmapServiceProbeList::from_str("# this is a comment\n", "<comment>");
        assert!(list.list.is_empty());
    }

    #[test]
    fn parse_single_probe() {
        let input = "Probe TCP TestProbe q|hello\\n|\nports 80,443\n";
        let list = NmapServiceProbeList::from_str(input, "<single>");
        assert_eq!(list.list.len(), 1);
        let probe = &list.list[0];
        assert_eq!(probe.name, "TestProbe");
        assert_eq!(probe.protocol, 6);
        assert_eq!(probe.hellostring, b"hello\n");
    }

    #[test]
    fn parse_null_probe() {
        let input = "Probe TCP NULL q||\n";
        let list = NmapServiceProbeList::from_str(input, "<null>");
        assert_eq!(list.list.len(), 1);
        assert!(list.list[0].hellostring.is_empty());
    }

    #[test]
    fn parse_hex_escapes() {
        let input = "Probe UDP Test q|\\x00\\x01\\xff|\n";
        let list = NmapServiceProbeList::from_str(input, "<hex>");
        assert_eq!(list.list[0].hellostring, vec![0x00, 0x01, 0xFF]);
    }

    #[test]
    fn parse_match_with_versioninfo() {
        let input = "\
Probe TCP Test q||
match ssh m/^SSH-([\\d.]+)/i p/OpenSSH/ v/$1/
";
        let list = NmapServiceProbeList::from_str(input, "<match>");
        assert_eq!(list.list[0].matches.len(), 1);
        let m = &list.list[0].matches[0];
        assert_eq!(m.service, "ssh");
        assert!(m.is_case_insensitive);
        assert_eq!(m.versioninfo.len(), 2);
        assert_eq!(m.versioninfo[0].info_type, SvcVInfoType::ProductName);
        assert_eq!(m.versioninfo[0].value, "OpenSSH");
        assert_eq!(m.versioninfo[1].info_type, SvcVInfoType::Version);
        assert_eq!(m.versioninfo[1].value, "$1");
    }

    #[test]
    fn parse_exclude() {
        let input = "Exclude 53,T:9100\nProbe TCP X q||\n";
        let list = NmapServiceProbeList::from_str(input, "<exclude>");
        assert!(list.exclude.count() > 0);
    }

    #[test]
    fn parse_rarity() {
        let input = "Probe TCP Test q||\nrarity 6\n";
        let list = NmapServiceProbeList::from_str(input, "<rarity>");
        assert_eq!(list.list[0].rarity, 6);
    }

    #[test]
    fn parse_fallback() {
        let input = "Probe TCP Test q||\nfallback GetRequest,GenericLines\n";
        let list = NmapServiceProbeList::from_str(input, "<fallback>");
        assert_eq!(list.list[0].fallback.len(), 2);
        assert_eq!(list.list[0].fallback[0].name, "GetRequest");
        assert_eq!(list.list[0].fallback[1].name, "GenericLines");
    }

    #[test]
    fn print_roundtrip() {
        let input = "\
Probe TCP TestProbe q|GET / HTTP/1.0\\r\\n\\r\\n|
ports 80
sslports 443
rarity 3
match http m|^HTTP/| p/some-server/
";
        let list = NmapServiceProbeList::from_str(input, "<roundtrip>");
        let mut output = Vec::new();
        list.print_to(&mut output);
        let printed = String::from_utf8(output).unwrap();
        // Verify key elements are present
        assert!(printed.contains("Probe TCP TestProbe"));
        assert!(printed.contains("ports"));
        assert!(printed.contains("sslports"));
        assert!(printed.contains("rarity 3"));
        assert!(printed.contains("match http"));
    }
}
