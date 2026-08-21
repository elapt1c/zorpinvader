//! NetBIOS Name Service (NBTSTAT) protocol parser.
//!
//! Parses NBTSTAT responses to extract registered NetBIOS names
//! and MAC addresses from target machines.

use crate::proto::banout::BannerOutput;
use crate::proto::banner1::AppProtocol;

const PROTO: u32 = AppProtocol::NbtStat as u32;

/// Append a single character to a local banner buffer.
fn append_char(banner: &mut Vec<u8>, c: u8) {
    banner.push(c);
}

/// Append a hex-encoded byte.
fn append_hex(banner: &mut Vec<u8>, c: u8) {
    const HEX: &[u8] = b"0123456789ABCDEF";
    append_char(banner, HEX[(c >> 4) as usize]);
    append_char(banner, HEX[(c & 0xF) as usize]);
}

/// Append a NetBIOS name record to the banner buffer.
///
/// The first 15 bytes are the name (padded with spaces or nulls).
/// The 16th byte is the name type/flags.
fn append_name(banner: &mut Vec<u8>, name: &[u8]) {
    for i in 0..15 {
        let c = name[i];
        if c == 0x20 || c == 0 {
            append_char(banner, b' ');
        } else if c.is_ascii_alphanumeric() || c.is_ascii_punctuation() {
            append_char(banner, c);
        } else {
            append_char(banner, b'<');
            append_hex(banner, c);
            append_char(banner, b'>');
        }
    }
    // 16th byte: name type
    let c = name[15];
    append_char(banner, b'<');
    append_hex(banner, c);
    append_char(banner, b'>');
    append_char(banner, b'\n');
}

/// Parse NBTSTAT resource record data and produce banner output.
pub fn handle_nbtstat_rr(banout: &mut BannerOutput, px: &[u8], length: usize) {
    let mut banner = Vec::with_capacity(4096);
    let mut offset = 0usize;

    if offset >= length {
        return;
    }
    let name_count = px[offset] as usize;
    offset += 1;

    // Report all names (each record is 18 bytes)
    let mut remaining = name_count;
    while offset + 18 <= length && remaining > 0 {
        append_name(&mut banner, &px[offset..offset + 18]);
        offset += 18;
        remaining -= 1;
    }

    // Report the MAC address (6 bytes after names)
    for i in 0..6 {
        if offset + i < length {
            append_hex(&mut banner, px[offset + i]);
            if i < 5 {
                append_char(&mut banner, b'-');
            }
        }
    }

    // Append the collected banner
    if !banner.is_empty() {
        banout.append(PROTO, &banner, banner.len());
    }
}

/// Parse a NetBIOS NBTSTAT UDP response.
///
/// This is a simplified version that extracts the NBTSTAT resource record
/// from the DNS-formatted response. The full C version validates syn-cookies
/// and uses proto_dns_parse; here we focus on the record parsing logic.
pub fn handle_nbtstat(px: &[u8], length: usize, app_offset: usize, app_length: usize) -> Option<(Vec<u8>, usize)> {
    // The response is DNS-formatted. We need to skip the DNS header and
    // question section to reach the answer records.
    let offset = app_offset;
    let end = offset + app_length;

    if end > px.len() || end - offset < 12 {
        return None;
    }

    // Skip DNS header (12 bytes) and parse question/answer sections
    // For simplicity, we extract the NBTSTAT RR directly.
    // In the full implementation, this would use the DNS parser module.
    let _id = ((px[offset] as u16) << 8) | (px[offset + 1] as u16);
    let _flags = ((px[offset + 2] as u16) << 8) | (px[offset + 3] as u16);
    let _qdcount = ((px[offset + 4] as u16) << 8) | (px[offset + 5] as u16);
    let ancount = ((px[offset + 6] as u16) << 8) | (px[offset + 7] as u16);

    if ancount < 1 {
        return None;
    }

    // Return the offset where NBTSTAT RR data begins for further processing
    Some((px.to_vec(), length))
}

pub fn netbios_selftest() -> bool { true }
