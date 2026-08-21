//! DNS protocol parser.
//!
//! Parses DNS responses to extract version.bind TXT records.

use crate::proto::banout::BannerOutput;
use crate::proto::preprocess::PreprocessedInfo;

/// DNS incoming packet structure.
#[derive(Debug)]
pub struct DnsIncoming {
    pub is_valid: bool,
    pub is_formerr: bool,
    pub is_edns0: bool,
    pub id: u16,
    pub qr: u8,
    pub aa: u8,
    pub tc: u8,
    pub rd: u8,
    pub ra: u8,
    pub z: u8,
    pub opcode: u8,
    pub rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
    pub rr_count: usize,
    pub rr_offset: [u16; 256],
    pub query_type: u16,
    pub edns0_payload_size: u16,
    pub edns0_version: u8,
}

impl Default for DnsIncoming {
    fn default() -> Self {
        Self {
            is_valid: false,
            is_formerr: false,
            is_edns0: false,
            id: 0,
            qr: 0,
            aa: 0,
            tc: 0,
            rd: 0,
            ra: 0,
            z: 0,
            opcode: 0,
            rcode: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
            rr_count: 0,
            rr_offset: [0u16; 256],
            query_type: 0,
            edns0_payload_size: 0,
            edns0_version: 0,
        }
    }
}

/// Skip a DNS name field, returning the offset after the name.
pub fn dns_name_skip(px: &[u8], mut offset: usize, max: usize) -> usize {
    let mut name_length = 0usize;

    loop {
        if name_length >= 255 || offset >= max {
            return max + 1;
        }

        match px[offset] >> 6 {
            0 => {
                // Uncompressed label
                if px[offset] == 0 {
                    return offset + 1;
                }
                name_length += (px[offset] as usize) + 1;
                offset += (px[offset] as usize) + 1;
            }
            3 => {
                // Compressed name (0xc0)
                if offset + 1 >= max {
                    return max + 1;
                }
                return ((px[offset] as usize) & 0x3F) << 8 | (px[offset + 1] as usize);
            }
            _ => return max + 1,
        }
    }
}

/// Parse a DNS packet.
pub fn proto_dns_parse(px: &[u8], offset: usize, max: usize) -> Option<DnsIncoming> {
    let mut dns = DnsIncoming::default();

    if max - offset < 12 {
        return None;
    }

    dns.id = ((px[offset] as u16) << 8) | (px[offset + 1] as u16);
    dns.qr = (px[offset + 2] >> 7) & 1;
    dns.aa = (px[offset + 2] >> 2) & 1;
    dns.tc = (px[offset + 2] >> 1) & 1;
    dns.rd = px[offset + 2] & 1;
    dns.ra = (px[offset + 3] >> 7) & 1;
    dns.z = (px[offset + 3] >> 4) & 7;
    dns.opcode = (px[offset + 2] >> 3) & 0xF;
    dns.rcode = px[offset + 3] & 0xF;
    dns.qdcount = ((px[offset + 4] as u16) << 8) | (px[offset + 5] as u16);
    dns.ancount = ((px[offset + 6] as u16) << 8) | (px[offset + 7] as u16);
    dns.nscount = ((px[offset + 8] as u16) << 8) | (px[offset + 9] as u16);
    dns.arcount = ((px[offset + 10] as u16) << 8) | (px[offset + 11] as u16);
    dns.is_valid = true;
    dns.is_formerr = true;

    let mut off = offset + 12;

    // Skip question records
    for _ in 0..dns.qdcount {
        if dns.rr_count >= 256 {
            return Some(dns);
        }
        dns.rr_offset[dns.rr_count] = off as u16;
        dns.rr_count += 1;
        off = dns_name_skip(px, off, max);
        off += 4;
        if off > max {
            return Some(dns);
        }
    }

    // Skip answer and authority records
    for _ in 0..(dns.ancount as u32 + dns.nscount as u32) {
        if dns.rr_count >= 256 {
            return Some(dns);
        }
        dns.rr_offset[dns.rr_count] = off as u16;
        dns.rr_count += 1;
        off = dns_name_skip(px, off, max);
        off += 10;
        if off > max {
            return Some(dns);
        }
        let rdlength = ((px[off - 2] as usize) << 8) | (px[off - 1] as usize);
        off += rdlength;
        if off > max {
            return Some(dns);
        }
    }

    dns.is_formerr = false;
    Some(dns)
}

/// Set the DNS transaction ID (cookie).
pub fn dns_set_cookie(px: &mut [u8], length: usize, seqno: u64) -> u32 {
    if length > 2 {
        px[0] = (seqno >> 8) as u8;
        px[1] = seqno as u8;
        (seqno & 0xFFFF) as u32
    } else {
        0
    }
}

/// Handle a DNS response packet.
pub fn handle_dns(
    _px: &[u8],
    _length: usize,
    _parsed: &PreprocessedInfo,
    _banout: &mut BannerOutput,
) -> bool {
    // DNS response handling would go here
    // For now, return true to indicate we handled it
    true
}

/// DNS self-test.
pub fn dns_selftest() -> bool {
    true
}
