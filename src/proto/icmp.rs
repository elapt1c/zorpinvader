//! ICMP packet handler.
use crate::proto::preprocess::PreprocessedInfo;

/// Parse port unreachable ICMP data to extract embedded IP/port info.
pub fn parse_port_unreachable(px: &[u8], length: usize) -> Option<(u32, u32, u16, u16, u32)> {
    if length < 24 {
        return None;
    }
    let ip_me = (px[12] as u32) << 24 | (px[13] as u32) << 16 | (px[14] as u32) << 8 | px[15] as u32;
    let ip_them = (px[16] as u32) << 24 | (px[17] as u32) << 16 | (px[18] as u32) << 8 | px[19] as u32;
    let ip_proto = px[9] as u32;

    let ihl = ((px[0] & 0xF) as usize) * 4;
    let remaining = length.checked_sub(ihl)?;
    if remaining < 4 {
        return None;
    }
    let inner = &px[ihl..];
    let port_me = ((inner[0] as u16) << 8) | inner[1] as u16;
    let port_them = ((inner[2] as u16) << 8) | inner[3] as u16;

    Some((ip_me, ip_them, port_me, port_them, ip_proto))
}

/// Handle ICMP packets (echo replies, destination unreachable).
pub fn handle_icmp(_parsed: &PreprocessedInfo, _px: &[u8], _length: usize) {
    // ICMP handling: echo replies, dest unreachable, etc.
}

pub fn icmp_selftest() -> bool {
    // Test parse_port_unreachable
    let short_blob: &[u8] = &[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x01,
    ];
    assert!(parse_port_unreachable(short_blob, short_blob.len()).is_none());
    true
}
