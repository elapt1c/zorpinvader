//! Packet preprocessing module.
//!
//! Parses raw network frames (Ethernet, IP, TCP, UDP, etc.) to extract
//! addresses, ports, and protocol information. This is the minimal
//! parsing necessary to find address/port information.
//!
//! Faithfully reproduces the C `preprocess_frame` function, including
//! all byte offsets and state machine transitions.

use crate::massip::addr::{IpAddress, Ipv6Address};

/// What protocol was found during preprocessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FoundType {
    Nothing = 0,
    Ethernet,
    Ipv4,
    Ipv6,
    Icmp,
    Tcp,
    Udp,
    Sctp,
    Dns,
    Ipv6Hop,
    Ieee8021Q,
    Mpls,
    WifiData,
    Wifi,
    Radiotap,
    Prism,
    Llc,
    Arp,
    Sll,       // Linux SLL
    Oproto,    // some other IP protocol
    Igmp,
    NdpV6,
}

/// Parsed information from a raw network frame.
///
/// Contains pointers (as offsets) into the original packet for MAC addresses,
/// IP addresses, ports, and application-layer data.
#[derive(Debug, Clone)]
pub struct PreprocessedInfo {
    /// Offset of source MAC address in packet (6 bytes)
    pub mac_src_offset: usize,
    /// Offset of destination MAC address in packet (6 bytes)
    pub mac_dst_offset: usize,
    /// Offset of BSS MAC address in packet (WiFi, 6 bytes)
    pub mac_bss_offset: usize,

    /// Offset of IP header in packet (14 for normal Ethernet)
    pub ip_offset: u32,
    /// IP version: 4 or 6
    pub ip_version: u32,
    /// IP protocol number: 6 for TCP, 17 for UDP, etc.
    pub ip_protocol: u32,
    /// Total length of the IP payload
    pub ip_length: u32,
    /// IP TTL value
    pub ip_ttl: u32,

    /// Source IP address
    pub src_ip: IpAddress,
    /// Destination IP address
    pub dst_ip: IpAddress,

    /// Offset of transport header (34 for normal Ethernet)
    pub transport_offset: u32,
    /// Length of transport payload
    pub transport_length: u32,

    /// Source port (for TCP/UDP) or opcode (for ARP)
    pub port_src: u32,
    /// Destination port
    pub port_dst: u32,

    /// Offset of application-layer data (start of TCP payload)
    pub app_offset: u32,
    /// Length of application-layer data
    pub app_length: u32,

    /// What was found during parsing
    pub found: FoundType,
    /// Offset where the found item starts
    pub found_offset: u32,

    /// Opcode field (ICMPv6 type, ARP opcode, etc.)
    pub opcode: u32,
    /// Source MAC address bytes (extracted from frame)
    pub mac_src: [u8; 6],
}

impl Default for PreprocessedInfo {
    fn default() -> Self {
        Self {
            mac_src_offset: 0,
            mac_dst_offset: 0,
            mac_bss_offset: 0,
            ip_offset: 0,
            ip_version: 0,
            ip_protocol: 0,
            ip_length: 0,
            ip_ttl: 0,
            src_ip: IpAddress::V4(0),
            dst_ip: IpAddress::V4(0),
            transport_offset: 0,
            transport_length: 0,
            port_src: 0,
            port_dst: 0,
            app_offset: 0,
            app_length: 0,
            found: FoundType::Nothing,
            found_offset: 0,
            opcode: 0,
            mac_src: [0u8; 6],
        }
    }
}

/// Read a 16-bit big-endian value from a byte slice.
#[inline]
fn ex16be(px: &[u8], offset: usize) -> u16 {
    ((px[offset] as u16) << 8) | (px[offset + 1] as u16)
}

/// Read a 16-bit little-endian value from a byte slice.
#[inline]
fn ex16le(px: &[u8], offset: usize) -> u16 {
    (px[offset] as u16) | ((px[offset + 1] as u16) << 8)
}

/// Read a 24-bit big-endian value from a byte slice.
#[inline]
fn ex24be(px: &[u8], offset: usize) -> u32 {
    ((px[offset] as u32) << 16)
        | ((px[offset + 1] as u32) << 8)
        | (px[offset + 2] as u32)
}

/// Read a 32-bit big-endian value from a byte slice.
#[inline]
fn ex32be(px: &[u8], offset: usize) -> u32 {
    ((px[offset] as u32) << 24)
        | ((px[offset + 1] as u32) << 16)
        | ((px[offset + 2] as u32) << 8)
        | (px[offset + 3] as u32)
}

/// Read a 32-bit little-endian value from a byte slice.
#[inline]
fn ex32le(px: &[u8], offset: usize) -> u32 {
    (px[offset] as u32)
        | ((px[offset + 1] as u32) << 8)
        | ((px[offset + 2] as u32) << 16)
        | ((px[offset + 3] as u32) << 24)
}

/// Parse a raw network frame and extract protocol information.
///
/// # Arguments
/// * `px` - Raw packet bytes
/// * `length` - Length of the packet
/// * `link_type` - Link type (1 = Ethernet, 113 = Linux SLL, etc.)
///
/// # Returns
/// `Some(PreprocessedInfo)` if useful protocol data was found, `None` otherwise.
pub fn preprocess_frame(
    px: &[u8],
    length: u32,
    link_type: u32,
) -> Option<PreprocessedInfo> {
    let mut info = PreprocessedInfo::default();
    let mut length = length as usize;
    let mut offset: usize = 0;
    let mut ethertype: u16 = 0;

    info.transport_offset = 0;
    info.found = FoundType::Nothing;
    info.found_offset = 0;

    // If not standard Ethernet, go to link-type parsing
    if link_type != 1 {
        return parse_linktype(px, length, link_type, &mut info);
    }

    // Parse Ethernet header
    if !verify_remaining(px, length, offset, 14, FoundType::Ethernet, &mut info) {
        return None;
    }

    info.mac_dst_offset = offset;
    info.mac_src_offset = offset + 6;
    ethertype = ex16be(px, offset + 12);
    offset += 14;

    if ethertype < 2000 {
        return parse_llc(px, length, offset, ethertype, &mut info);
    }
    if ethertype != 0x0800 {
        return parse_ethertype(px, length, offset, ethertype, &mut info);
    }

    parse_ipv4(px, length, offset, &mut info)
}

/// Check that at least `n` bytes remain in the packet.
fn verify_remaining(
    _px: &[u8],
    length: usize,
    offset: usize,
    n: usize,
    found: FoundType,
    info: &mut PreprocessedInfo,
) -> bool {
    if offset + n > length {
        return false;
    }
    info.found_offset = offset as u32;
    info.found = found;
    true
}

/// Parse IPv4 header.
fn parse_ipv4(
    px: &[u8],
    mut length: usize,
    offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    let mut offset = offset;
    info.ip_offset = offset as u32;

    if !verify_remaining(px, length, offset, 20, FoundType::Ipv4, info) {
        return None;
    }

    // Check version
    if (px[offset] >> 4) != 4 {
        return None;
    }

    // Check header length
    let header_length = ((px[offset] & 0x0F) as usize) * 4;
    if !verify_remaining(px, length, offset, header_length, FoundType::Ipv4, info) {
        return None;
    }

    // Check for fragmentation
    let flags = px[offset + 6] & 0xE0;
    let fragment_offset = ((ex16be(px, offset + 6) as u32) & 0x3FFF) << 3;
    if fragment_offset != 0 || (flags & 0x20) != 0 {
        return None; // fragmented
    }

    // Check total length
    let total_length = ex16be(px, offset + 2) as usize;
    if !verify_remaining(px, length, offset, total_length, FoundType::Ipv4, info) {
        return None;
    }
    if total_length < header_length {
        return None;
    }
    length = offset + total_length;

    // Save IP info
    info.ip_version = ((px[offset] >> 4) & 0xF) as u32;
    info.src_ip = IpAddress::V4(
        (px[offset + 12] as u32) << 24
            | (px[offset + 13] as u32) << 16
            | (px[offset + 14] as u32) << 8
            | (px[offset + 15] as u32),
    );
    info.dst_ip = IpAddress::V4(
        (px[offset + 16] as u32) << 24
            | (px[offset + 17] as u32) << 16
            | (px[offset + 18] as u32) << 8
            | (px[offset + 19] as u32),
    );

    info.ip_ttl = px[offset + 8] as u32;
    info.ip_protocol = px[offset + 9] as u32;
    info.ip_length = total_length as u32;

    if info.ip_version != 4 {
        return None;
    }

    offset += header_length;
    info.transport_offset = offset as u32;
    info.transport_length = (length - offset) as u32;

    match info.ip_protocol {
        1 => parse_icmp(px, length, offset, info),
        2 => parse_igmp(px, length, offset, info),
        6 => parse_tcp(px, length, offset, info),
        17 => parse_udp(px, length, offset, info),
        132 => parse_sctp(px, length, offset, info),
        _ => {
            verify_remaining(px, length, offset, 0, FoundType::Oproto, info);
            None
        }
    }
}

/// Parse TCP header.
fn parse_tcp(
    px: &[u8],
    length: usize,
    offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    if !verify_remaining(px, length, offset, 20, FoundType::Tcp, info) {
        return None;
    }

    let tcp_length = (px[offset + 12] >> 2) as usize;
    if !verify_remaining(px, length, offset, tcp_length, FoundType::Tcp, info) {
        return None;
    }

    info.port_src = ex16be(px, offset) as u32;
    info.port_dst = ex16be(px, offset + 2) as u32;
    info.app_offset = (offset + tcp_length) as u32;
    info.app_length = (length - (offset + tcp_length)) as u32;

    Some(info.clone())
}

/// Parse UDP header.
fn parse_udp(
    px: &[u8],
    length: usize,
    offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    if !verify_remaining(px, length, offset, 8, FoundType::Udp, info) {
        return None;
    }

    info.port_src = ex16be(px, offset) as u32;
    info.port_dst = ex16be(px, offset + 2) as u32;
    let new_offset = offset + 8;
    info.app_offset = new_offset as u32;
    info.app_length = (length - new_offset) as u32;

    if info.port_dst == 53 || info.port_src == 53 {
        return parse_dns(px, length, new_offset, info);
    }

    Some(info.clone())
}

/// Parse ICMP header.
fn parse_icmp(
    px: &[u8],
    length: usize,
    offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    if !verify_remaining(px, length, offset, 4, FoundType::Icmp, info) {
        return None;
    }
    info.port_src = px[offset] as u32;
    info.port_dst = px[offset + 1] as u32;
    Some(info.clone())
}

/// Parse IGMP header.
fn parse_igmp(
    px: &[u8],
    length: usize,
    offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    if !verify_remaining(px, length, offset, 4, FoundType::Igmp, info) {
        return None;
    }
    info.port_src = 0;
    info.port_dst = px[offset] as u32;
    Some(info.clone())
}

/// Parse SCTP header.
fn parse_sctp(
    px: &[u8],
    length: usize,
    offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    if !verify_remaining(px, length, offset, 12, FoundType::Sctp, info) {
        return None;
    }
    info.port_src = ex16be(px, offset) as u32;
    info.port_dst = ex16be(px, offset + 2) as u32;
    info.app_offset = (offset + 12) as u32;
    info.app_length = (length - (offset + 12)) as u32;
    Some(info.clone())
}

/// Parse DNS header (minimal validation).
fn parse_dns(
    px: &[u8],
    length: usize,
    offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    if !verify_remaining(px, length, offset, 8, FoundType::Dns, info) {
        return None;
    }
    Some(info.clone())
}

/// Parse IPv6 header.
fn parse_ipv6(
    px: &[u8],
    mut length: usize,
    offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    let mut offset = offset;
    info.ip_offset = offset as u32;

    if !verify_remaining(px, length, offset, 40, FoundType::Ipv6, info) {
        return None;
    }

    // Check version
    if (px[offset] >> 4) != 6 {
        return None;
    }

    // Payload length
    let payload_length = ex16be(px, offset + 4) as usize;
    if !verify_remaining(px, length, offset, 40 + payload_length, FoundType::Ipv6, info) {
        return None;
    }
    if length > offset + 40 + payload_length {
        length = offset + 40 + payload_length;
    }

    // Save IP info
    info.ip_version = ((px[offset] >> 4) & 0xF) as u32;
    info.ip_protocol = px[offset + 6] as u32;

    // Source IPv6
    let src_hi = (px[offset + 8] as u64) << 56
        | (px[offset + 9] as u64) << 48
        | (px[offset + 10] as u64) << 40
        | (px[offset + 11] as u64) << 32
        | (px[offset + 12] as u64) << 24
        | (px[offset + 13] as u64) << 16
        | (px[offset + 14] as u64) << 8
        | (px[offset + 15] as u64);
    let src_lo = (px[offset + 16] as u64) << 56
        | (px[offset + 17] as u64) << 48
        | (px[offset + 18] as u64) << 40
        | (px[offset + 19] as u64) << 32
        | (px[offset + 20] as u64) << 24
        | (px[offset + 21] as u64) << 16
        | (px[offset + 22] as u64) << 8
        | (px[offset + 23] as u64);
    info.src_ip = IpAddress::V6(Ipv6Address { hi: src_hi, lo: src_lo });

    // Destination IPv6
    let dst_hi = (px[offset + 24] as u64) << 56
        | (px[offset + 25] as u64) << 48
        | (px[offset + 26] as u64) << 40
        | (px[offset + 27] as u64) << 32
        | (px[offset + 28] as u64) << 24
        | (px[offset + 29] as u64) << 16
        | (px[offset + 30] as u64) << 8
        | (px[offset + 31] as u64);
    let dst_lo = (px[offset + 32] as u64) << 56
        | (px[offset + 33] as u64) << 48
        | (px[offset + 34] as u64) << 40
        | (px[offset + 35] as u64) << 32
        | (px[offset + 36] as u64) << 24
        | (px[offset + 37] as u64) << 16
        | (px[offset + 38] as u64) << 8
        | (px[offset + 39] as u64);
    info.dst_ip = IpAddress::V6(Ipv6Address { hi: dst_hi, lo: dst_lo });

    offset += 40;
    info.transport_offset = offset as u32;
    info.transport_length = (length - offset) as u32;

    parse_ipv6_next(px, length, offset, info)
}

/// Parse IPv6 next-header field.
fn parse_ipv6_next(
    px: &[u8],
    length: usize,
    offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    match info.ip_protocol {
        0 => parse_ipv6_hop_by_hop(px, length, offset, info),
        6 => parse_tcp(px, length, offset, info),
        17 => parse_udp(px, length, offset, info),
        58 => parse_icmpv6(px, length, offset, info),
        132 => parse_sctp(px, length, offset, info),
        0x2C => None, // IPv6 fragment
        _ => None,
    }
}

/// Parse IPv6 hop-by-hop options header.
fn parse_ipv6_hop_by_hop(
    px: &[u8],
    length: usize,
    offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    if !verify_remaining(px, length, offset, 8, FoundType::Ipv6Hop, info) {
        return None;
    }
    info.ip_protocol = px[offset] as u32;
    let len = (px[offset + 1] as usize) + 8;
    if !verify_remaining(px, length, offset, len, FoundType::Ipv6Hop, info) {
        return None;
    }
    let new_offset = offset + len;
    info.transport_offset = new_offset as u32;
    info.transport_length = (length - new_offset) as u32;
    parse_ipv6_next(px, length, new_offset, info)
}

/// Parse ICMPv6 header.
fn parse_icmpv6(
    px: &[u8],
    length: usize,
    offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    if !verify_remaining(px, length, offset, 4, FoundType::Icmp, info) {
        return None;
    }

    let icmp_type = px[offset] as u32;
    let icmp_code = px[offset + 1] as u32;

    info.port_src = icmp_type;
    info.port_dst = icmp_code;

    if (133..=136).contains(&icmp_type) {
        info.found = FoundType::NdpV6;
    }

    Some(info.clone())
}

/// Parse ethertype dispatch.
fn parse_ethertype(
    px: &[u8],
    length: usize,
    offset: usize,
    ethertype: u16,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    match ethertype {
        0x0800 => parse_ipv4(px, length, offset, info),
        0x0806 => parse_arp(px, length, offset, info),
        0x86DD => parse_ipv6(px, length, offset, info),
        0x8100 => parse_vlan8021q(px, length, offset, info),
        0x8847 => parse_vlan_mpls(px, length, offset, info),
        _ => None,
    }
}

/// Parse 802.1Q VLAN tag.
fn parse_vlan8021q(
    px: &[u8],
    length: usize,
    offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    if !verify_remaining(px, length, offset, 4, FoundType::Ieee8021Q, info) {
        return None;
    }
    let ethertype = ex16be(px, offset + 2);
    let new_offset = offset + 4;
    parse_ethertype(px, length, new_offset, ethertype, info)
}

/// Parse MPLS VLAN tags (may have multiple layers).
fn parse_vlan_mpls(
    px: &[u8],
    length: usize,
    mut offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    // Skip multiple MPLS labels
    while offset + 4 < length && (px[offset + 2] & 1) == 0 {
        offset += 4;
    }

    if !verify_remaining(px, length, offset, 4, FoundType::Mpls, info) {
        return None;
    }
    offset += 4;

    if (px[offset - 4 + 2] & 1) != 0 {
        parse_ipv4(px, length, offset, info)
    } else {
        None
    }
}

/// Parse LLC (Logical Link Control) header.
fn parse_llc(
    px: &[u8],
    length: usize,
    mut offset: usize,
    _ethertype: u16,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    if !verify_remaining(px, length, offset, 3, FoundType::Llc, info) {
        return None;
    }

    let val = ex24be(px, offset);
    match val {
        0x0000AA => {
            offset += 2;
            if !verify_remaining(px, length, offset, 3, FoundType::Llc, info) {
                return None;
            }
            // Fall through to aaaa03 check
        }
        0xAAAA03 => {}
        _ => return None,
    }

    offset += 3;

    if !verify_remaining(px, length, offset, 5, FoundType::Llc, info) {
        return None;
    }

    let oui = ex24be(px, offset);
    let ethertype = ex16be(px, offset + 3);
    offset += 5;

    match oui {
        0x000000 => parse_ethertype(px, length, offset, ethertype, info),
        _ => None,
    }
}

/// Parse ARP packet.
fn parse_arp(
    px: &[u8],
    length: usize,
    offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    let mut offset = offset;
    info.ip_version = 256;
    info.ip_offset = offset as u32;

    if !verify_remaining(px, length, offset, 8, FoundType::Arp, info) {
        return None;
    }

    let hardware_length = px[offset + 4] as usize;
    let protocol_length = px[offset + 5] as usize;
    let opcode = ((px[offset + 6] as u32) << 8) | (px[offset + 7] as u32);
    info.port_src = opcode; // opcode stored in port_src for ARP
    info.ip_protocol = opcode;
    offset += 8;

    let total = 2 * hardware_length + 2 * protocol_length;
    if !verify_remaining(px, length, offset, total, FoundType::Arp, info) {
        return None;
    }

    info.src_ip = IpAddress::V4(
        (px[offset + hardware_length] as u32) << 24
            | (px[offset + hardware_length + 1] as u32) << 16
            | (px[offset + hardware_length + 2] as u32) << 8
            | (px[offset + hardware_length + 3] as u32),
    );
    info.dst_ip = IpAddress::V4(
        (px[offset + 2 * hardware_length + protocol_length] as u32) << 24
            | (px[offset + 2 * hardware_length + protocol_length + 1] as u32) << 16
            | (px[offset + 2 * hardware_length + protocol_length + 2] as u32) << 8
            | (px[offset + 2 * hardware_length + protocol_length + 3] as u32),
    );

    info.found_offset = info.ip_offset;
    Some(info.clone())
}

/// Parse link type dispatch.
fn parse_linktype(
    px: &[u8],
    length: usize,
    link_type: u32,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    match link_type {
        0 => {
            // NULL/Loopback
            if length < 4 {
                return None;
            }
            let offset = 4usize;
            match ex32be(px, 0) {
                0x02000000 | 0x00000002 => parse_ipv4(px, length, offset, info),
                0x18000000 | 0x00000018
                | 0x1C000000 | 0x0000001C
                | 0x1E000000 | 0x0000001E => parse_ipv6(px, length, offset, info),
                _ => None,
            }
        }
        1 => {
            // Standard Ethernet - handled by caller before this function
            // But we handle it here for completeness
            if !verify_remaining(px, length, 0, 14, FoundType::Ethernet, info) {
                return None;
            }
            let ethertype = ex16be(px, 12);
            info.mac_dst_offset = 0;
            info.mac_src_offset = 6;
            if ethertype < 2000 {
                return parse_llc(px, length, 14, ethertype, info);
            }
            parse_ethertype(px, length, 14, ethertype, info)
        }
        12 => {
            // Raw IP
            if length < 1 {
                return None;
            }
            match px[0] >> 4 {
                4 => parse_ipv4(px, length, 0, info),
                6 => parse_ipv6(px, length, 0, info),
                _ => None,
            }
        }
        0x69 => parse_wifi(px, length, 0, info),
        113 => parse_linux_sll(px, length, 0, info),
        119 => parse_prism_header(px, length, 0, info),
        127 => parse_radiotap_header(px, length, 0, info),
        _ => None,
    }
}

/// Parse Linux SLL (cooked capture) header.
fn parse_linux_sll(
    px: &[u8],
    length: usize,
    offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    if !verify_remaining(px, length, offset, 16, FoundType::Sll, info) {
        return None;
    }

    let ethertype = ex16be(px, offset + 14);
    let new_offset = offset + 16;

    parse_ethertype(px, length, new_offset, ethertype, info)
}

/// Parse WiFi frame.
fn parse_wifi(
    px: &[u8],
    length: usize,
    offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    if !verify_remaining(px, length, offset, 2, FoundType::Wifi, info) {
        return None;
    }

    match px[offset] {
        0x08 | 0x88 => {
            if px[1] & 0x40 != 0 {
                return None;
            }
            parse_wifi_data(px, length, offset, info)
        }
        _ => None,
    }
}

/// Parse WiFi data frame.
fn parse_wifi_data(
    px: &[u8],
    length: usize,
    offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    if !verify_remaining(px, length, offset, 24, FoundType::WifiData, info) {
        return None;
    }

    let flag = px[offset];

    match px[offset + 1] & 0x03 {
        0 | 2 => {
            info.mac_dst_offset = offset + 4;
            info.mac_bss_offset = offset + 10;
            info.mac_src_offset = offset + 16;
        }
        1 => {
            info.mac_bss_offset = offset + 4;
            info.mac_src_offset = offset + 10;
            info.mac_dst_offset = offset + 16;
        }
        3 => {
            info.mac_bss_offset = 0; // zero MAC placeholder
            info.mac_dst_offset = offset + 16;
            info.mac_src_offset = offset + 24;
            // Extra offset for 4-address frames
        }
        _ => return None,
    }

    if (px[offset + 1] & 0x04) != 0 || (px[offset + 22] & 0xF) != 0 {
        return None;
    }

    let mut new_offset = offset + 24;
    if flag == 0x88 {
        new_offset += 2;
    }

    parse_llc(px, length, new_offset, 0, info)
}

/// Parse Radiotap header (WiFi capture header).
fn parse_radiotap_header(
    px: &[u8],
    mut length: usize,
    offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    let mut offset = offset;
    if !verify_remaining(px, length, offset, 8, FoundType::Radiotap, info) {
        return None;
    }
    if px[offset] != 0 {
        return None;
    }

    let header_length = ex16le(px, offset + 2) as usize;
    let features = ex32le(px, offset + 4);

    if !verify_remaining(px, length, offset, header_length, FoundType::Radiotap, info) {
        return None;
    }

    // If FCS is present at the end of the packet, remove it
    if features & 0x4000 != 0 {
        if offset + header_length >= 4 && length >= 4 {
            let fcs_header = ex32le(px, offset + header_length - 4);
            let fcs_frame = ex32le(px, length - 4);
            if fcs_header == fcs_frame {
                length -= 4;
            }
        }
        if !verify_remaining(px, length, offset, header_length, FoundType::Radiotap, info) {
            return None;
        }
    }

    offset += header_length;
    parse_wifi(px, length, offset, info)
}

/// Parse Prism header.
fn parse_prism_header(
    px: &[u8],
    length: usize,
    offset: usize,
    info: &mut PreprocessedInfo,
) -> Option<PreprocessedInfo> {
    if !verify_remaining(px, length, offset, 8, FoundType::Prism, info) {
        return None;
    }

    if ex32le(px, offset) != 0x00000044 {
        return None;
    }

    let header_length = ex32le(px, offset + 4) as usize;
    if header_length > 0xFFFFF {
        return None;
    }

    if !verify_remaining(px, length, offset, header_length, FoundType::Prism, info) {
        return None;
    }

    let new_offset = offset + header_length;
    parse_wifi(px, length, new_offset, info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_ethernet_ipv4_tcp() {
        // Construct a minimal Ethernet + IPv4 + TCP packet
        let mut pkt = vec![0u8; 54]; // 14 (eth) + 20 (ipv4) + 20 (tcp)

        // Ethernet header
        pkt[12] = 0x08; pkt[13] = 0x00; // IPv4 ethertype

        // IPv4 header
        pkt[14] = 0x45; // version 4, IHL 5 (20 bytes)
        pkt[16] = 0x00; pkt[17] = 0x28; // total length = 40
        pkt[23] = 0x06; // protocol = TCP

        // Source IP: 10.0.0.1
        pkt[26] = 10; pkt[27] = 0; pkt[28] = 0; pkt[29] = 1;
        // Dest IP: 10.0.0.2
        pkt[30] = 10; pkt[31] = 0; pkt[32] = 0; pkt[33] = 2;

        // TCP header
        pkt[34] = 0x00; pkt[35] = 80; // src port = 80
        pkt[36] = 0x1F; pkt[37] = 0x90; // dst port = 8080
        pkt[46] = 0x50; // data offset = 5 (20 bytes)

        let result = preprocess_frame(&pkt, pkt.len() as u32, 1);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.port_src, 80);
        assert_eq!(info.port_dst, 8080);
        assert_eq!(info.ip_protocol, 6);
    }

    #[test]
    fn test_too_short() {
        let pkt = vec![0u8; 5]; // too short for anything
        let result = preprocess_frame(&pkt, pkt.len() as u32, 1);
        assert!(result.is_none());
    }
}
