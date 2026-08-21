//! Parser for the nmap-payloads file format.
//!
//! The nmap-payloads file defines UDP probe payloads for various services.
//! Each entry specifies a set of ports, a C-style string payload, and
//! optionally a source port.
//!
//! Format:
//! ```text
//! udp <ports>
//! "<payload>"
//! source <port>
//! ```

use std::io::BufRead;

/// Check if a character is an octal digit (0-7).
fn is_octal_digit(c: u8) -> bool {
    (b'0'..=b'7').contains(&c)
}

/// Convert a hex character to its numeric value.
fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// Check if a character is a hex digit.
fn is_hex_digit(c: u8) -> bool {
    matches!(c, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')
}

/// Append a single byte to the buffer if there's room.
fn append_byte(buf: &mut Vec<u8>, max: usize, c: u8) {
    if buf.len() < max {
        buf.push(c);
    }
}

/// Parse a C-style string literal from the input, handling escape sequences.
///
/// Supports:
/// - `\\n`, `\\r`, `\\t`, `\\a`, `\\b`, `\\f`, `\\v` - standard escapes
/// - `\\xHH` - hex escapes (1-2 digits)
/// - `\\OOO` - octal escapes (1-3 digits)
/// - `\\\\` - literal backslash
///
/// Returns the remaining unparsed portion of the input after the closing quote.
pub fn parse_c_string<'a>(buf: &mut Vec<u8>, max: usize, line: &'a [u8]) -> &'a [u8] {
    if line.is_empty() || line[0] != b'"' {
        return line;
    }

    let mut offset = 1;

    while offset < line.len() && line[offset] != b'"' {
        if line[offset] == b'\\' {
            offset += 1;
            if offset >= line.len() {
                break;
            }
            match line[offset] {
                b'0'..=b'9' => {
                    // Octal escape: up to 3 digits
                    let mut val: u8 = 0;
                    if offset < line.len() && is_octal_digit(line[offset]) {
                        val = val.wrapping_mul(8).wrapping_add(hex_val(line[offset]));
                        offset += 1;
                    }
                    if offset < line.len() && is_octal_digit(line[offset]) {
                        val = val.wrapping_mul(8).wrapping_add(hex_val(line[offset]));
                        offset += 1;
                    }
                    if offset < line.len() && is_octal_digit(line[offset]) {
                        val = val.wrapping_mul(8).wrapping_add(hex_val(line[offset]));
                        offset += 1;
                    }
                    append_byte(buf, max, val);
                    continue;
                }
                b'x' => {
                    // Hex escape: up to 2 digits
                    offset += 1;
                    let mut val: u8 = 0;
                    if offset < line.len() && is_hex_digit(line[offset]) {
                        val = val.wrapping_mul(16).wrapping_add(hex_val(line[offset]));
                        offset += 1;
                    }
                    if offset < line.len() && is_hex_digit(line[offset]) {
                        val = val.wrapping_mul(16).wrapping_add(hex_val(line[offset]));
                        offset += 1;
                    }
                    append_byte(buf, max, val);
                    continue;
                }
                b'a' => {
                    append_byte(buf, max, b'\x07');
                }
                b'b' => {
                    append_byte(buf, max, b'\x08');
                }
                b'f' => {
                    append_byte(buf, max, b'\x0C');
                }
                b'n' => {
                    append_byte(buf, max, b'\n');
                }
                b'r' => {
                    append_byte(buf, max, b'\r');
                }
                b't' => {
                    append_byte(buf, max, b'\t');
                }
                b'v' => {
                    append_byte(buf, max, b'\x0B');
                }
                _ => {
                    // Default: literal character (including backslash)
                    append_byte(buf, max, line[offset]);
                }
            }
        } else {
            append_byte(buf, max, line[offset]);
        }
        offset += 1;
    }

    // Skip closing quote
    if offset < line.len() && line[offset] == b'"' {
        offset += 1;
    }

    &line[offset..]
}

/// Trim leading and trailing whitespace from a byte slice.
fn trim(line: &[u8]) -> &[u8] {
    let start = line.iter().position(|&b| !b.is_ascii_whitespace()).unwrap_or(line.len());
    let end = line.iter().rposition(|&b| !b.is_ascii_whitespace()).map_or(0, |p| p + 1);
    if start >= end {
        &[]
    } else {
        &line[start..end]
    }
}

/// Check if a line is a comment (starts with #, /, or ;).
fn is_comment(line: &[u8]) -> bool {
    !line.is_empty() && matches!(line[0], b'#' | b'/' | b';')
}

/// Parse a comma-separated list of port numbers and ranges.
///
/// Examples: "53", "53,161", "100-200", "53,161,162,500-520"
fn parse_port_list(line: &[u8]) -> Vec<u16> {
    let mut ports = Vec::new();
    let s = String::from_utf8_lossy(line);

    for part in s.split(',') {
        let part = part.trim();
        if let Some(dash_pos) = part.find('-') {
            let start_str = &part[..dash_pos];
            let end_str = &part[dash_pos + 1..];
            if let (Ok(start), Ok(end)) = (start_str.parse::<u16>(), end_str.parse::<u16>()) {
                for p in start..=end {
                    ports.push(p);
                }
            }
        } else if let Ok(port) = part.parse::<u16>() {
            ports.push(port);
        }
    }

    ports
}

/// A parsed nmap-payloads entry.
#[derive(Debug, Clone)]
pub struct NmapPayload {
    /// Destination ports this payload applies to.
    pub ports: Vec<u16>,
    /// The raw payload bytes.
    pub data: Vec<u8>,
    /// Optional source port (0x10000 = unspecified).
    pub source_port: u32,
}

/// Read and parse an nmap-payloads formatted file.
///
/// The format consists of records like:
/// ```text
/// udp 53
/// "payload bytes here"
/// source 12345
///
/// udp 161,162
/// "more payload"
/// ```
///
/// Returns a vector of parsed payload entries.
pub fn read_nmap_payloads<R: BufRead>(
    reader: &mut R,
    filename: &str,
) -> Vec<NmapPayload> {
    let mut results = Vec::new();
    let mut line_buf = String::new();
    let mut line_number: u32 = 0;

    // Helper: read next non-empty, non-comment line
    let mut get_next_line = |reader: &mut R,
                             line_buf: &mut String,
                             line_number: &mut u32|
     -> Option<String> {
        loop {
            line_buf.clear();
            match reader.read_line(line_buf) {
                Ok(0) => return None,
                Ok(_) => {
                    *line_number += 1;
                    let trimmed = trim(line_buf.as_bytes()).to_vec();
                    if trimmed.is_empty() || is_comment(&trimmed) {
                        continue;
                    }
                    return Some(String::from_utf8_lossy(&trimmed).into_owned());
                }
                Err(_) => return None,
            }
        }
    };

    // We keep a "lookahead" line for multi-line records
    let mut pending_line: Option<String> = None;

    loop {
        // Get the "udp <ports>" line
        let line = if let Some(l) = pending_line.take() {
            l
        } else {
            match get_next_line(reader, &mut line_buf, &mut line_number) {
                Some(l) => l,
                None => break,
            }
        };

        // Expect "udp" prefix
        if !line.starts_with("udp") {
            log::warn!(
                "{}:{}: syntax error, expected \"udp\"",
                filename,
                line_number
            );
            continue;
        }

        // Parse port list after "udp"
        let rest = line[3..].trim();
        let ports = parse_port_list(rest.as_bytes());
        if ports.is_empty() {
            log::warn!(
                "{}:{}: no valid ports found",
                filename,
                line_number
            );
            continue;
        }

        // Read C-string payload lines
        let mut payload = Vec::new();
        let mut source_port: u32 = 0x10000; // default: unspecified

        loop {
            let next = match get_next_line(reader, &mut line_buf, &mut line_number) {
                Some(l) => l,
                None => break,
            };

            if next.starts_with('"') {
                // Parse C-string payload
                let bytes = next.as_bytes();
                parse_c_string(&mut payload, 1500, bytes);
            } else if next.starts_with("source") {
                // Parse source port
                let src_rest = next[6..].trim();
                if let Ok(p) = src_rest.parse::<u32>() {
                    source_port = p;
                } else {
                    log::warn!(
                        "{}:{}: expected source port number",
                        filename,
                        line_number
                    );
                }
                break;
            } else {
                // This is the start of the next record
                pending_line = Some(next);
                break;
            }
        }

        if !payload.is_empty() && !ports.is_empty() {
            results.push(NmapPayload {
                ports,
                data: payload,
                source_port,
            });
        }
    }

    results
}

/// Self-test for the C-string parser.
pub fn selftest() -> bool {
    let input = b"\"\\t\\n\\r\\x1f\\123\"";
    let mut buf = Vec::new();
    parse_c_string(&mut buf, 1024, input);

    let expected = b"\t\n\r\x1f\x53";
    if buf != expected {
        log::error!(
            "nmap_payloads selftest failed: got {:?}, expected {:?}",
            buf,
            expected
        );
        return false;
    }

    // Test hex escape
    let input2 = b"\"\\x41\\x42\"";
    let mut buf2 = Vec::new();
    parse_c_string(&mut buf2, 1024, input2);
    assert_eq!(buf2, b"AB");

    // Test octal escape
    let input3 = b"\"\\101\"";
    let mut buf3 = Vec::new();
    parse_c_string(&mut buf3, 1024, input3);
    assert_eq!(buf3, b"A"); // \101 = 65 = 'A'

    // Test backslash escape
    let input4 = b"\"a\\\\b\"";
    let mut buf4 = Vec::new();
    parse_c_string(&mut buf4, 1024, input4);
    assert_eq!(buf4, b"a\\b");

    // Test empty string
    let input5 = b"\"\"";
    let mut buf5 = Vec::new();
    parse_c_string(&mut buf5, 1024, input5);
    assert!(buf5.is_empty());

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_c_string_basic() {
        assert!(selftest());
    }

    #[test]
    fn test_parse_c_string_hex() {
        let mut buf = Vec::new();
        parse_c_string(&mut buf, 1024, b"\"\\x00\\xff\"");
        assert_eq!(buf, vec![0x00, 0xFF]);
    }

    #[test]
    fn test_parse_c_string_mixed() {
        let mut buf = Vec::new();
        parse_c_string(&mut buf, 1024, b"\"hello\\nworld\"");
        assert_eq!(buf, b"hello\nworld");
    }

    #[test]
    fn test_parse_port_list_single() {
        let ports = parse_port_list(b"53");
        assert_eq!(ports, vec![53]);
    }

    #[test]
    fn test_parse_port_list_multiple() {
        let ports = parse_port_list(b"53,161,162");
        assert_eq!(ports, vec![53, 161, 162]);
    }

    #[test]
    fn test_parse_port_list_range() {
        let ports = parse_port_list(b"100-103");
        assert_eq!(ports, vec![100, 101, 102, 103]);
    }

    #[test]
    fn test_read_nmap_payloads() {
        let input = b"# comment\nudp 53\n\"\\x50\\xb6\\x01\\x20\"\nsource 1234\n\nudp 161,162\n\"snmp test\"\n";
        let mut cursor = std::io::Cursor::new(input.as_ref());
        let results = read_nmap_payloads(&mut cursor, "test");

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].ports, vec![53]);
        assert_eq!(results[0].data, vec![0x50, 0xB6, 0x01, 0x20]);
        assert_eq!(results[0].source_port, 1234);
        assert_eq!(results[1].ports, vec![161, 162]);
        assert_eq!(results[1].data, b"snmp test");
    }
}
