//! Packet template construction and target-setting.
//!
//! Pre-built packet templates for each protocol (TCP, UDP, SCTP, ICMP, ARP).
//! The transmit thread uses these templates to quickly build packets by
//! patching in destination IP addresses, port numbers, and sequence numbers
//! rather than constructing packets from scratch for every probe.
//!
//! Each template is stored as both an IPv4 and IPv6 variant. The IPv6 variant
//! is automatically derived from the IPv4 template during initialization.

use crate::massip::addr::{Ipv4Address, Ipv6Address, MacAddress};
use super::opts::TemplateOptions;
use super::payloads::PayloadsUdp;
use super::tcp_hdr;

// -----------------------------------------------------------------------
// Protocol identifiers
// -----------------------------------------------------------------------

/// Protocol type for a packet template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateProtocol {
    Tcp,
    Udp,
    Sctp,
    IcmpPing,
    IcmpTimestamp,
    Arp,
    Oproto,
    VulnCheck,
}

impl TemplateProtocol {
    /// Convert to array index.
    pub fn index(self) -> usize {
        match self {
            TemplateProtocol::Tcp => 0,
            TemplateProtocol::Udp => 1,
            TemplateProtocol::Sctp => 2,
            TemplateProtocol::IcmpPing => 3,
            TemplateProtocol::IcmpTimestamp => 4,
            TemplateProtocol::Arp => 5,
            TemplateProtocol::Oproto => 6,
            TemplateProtocol::VulnCheck => 7,
        }
    }
}

/// Number of protocol slots in a template set.
const PROTO_COUNT: usize = 8;

// -----------------------------------------------------------------------
// Data-link type constants (matching pcap)
// -----------------------------------------------------------------------

const DLT_NULL: u32 = 0;
const DLT_ETHERNET: u32 = 1;
const DLT_RAW: u32 = 12;

// -----------------------------------------------------------------------
// Default packet templates
// -----------------------------------------------------------------------

/// Default TCP SYN template (Ethernet + IPv4 + TCP with MSS option).
static DEFAULT_TCP_TEMPLATE: &[u8] = b"\
\x00\x01\x02\x03\x04\x05\
\x06\x07\x08\x09\x0a\x0b\
\x08\x00\
\x45\x00\
\x00\x2c\
\x00\x00\
\x00\x00\
\xff\x06\
\xff\xff\
\x00\x00\x00\x00\
\x00\x00\x00\x00\
\x00\x00\
\x00\x00\
\x00\x00\x00\x00\
\x00\x00\x00\x00\
\x60\
\x02\
\x04\x01\
\xff\xff\
\x00\x00\
\x02\x04\x05\xb4";

/// Default UDP template (Ethernet + IPv4 + UDP).
static DEFAULT_UDP_TEMPLATE: &[u8] = b"\
\x00\x01\x02\x03\x04\x05\
\x06\x07\x08\x09\x0a\x0b\
\x08\x00\
\x45\x00\
\x00\x1c\
\x00\x00\
\x00\x00\
\xff\x11\
\xff\xff\
\x00\x00\x00\x00\
\x00\x00\x00\x00\
\xfe\xdc\
\x00\x00\
\x00\x08\
\x00\x00";

/// Default SCTP INIT template (Ethernet + IPv4 + SCTP).
static DEFAULT_SCTP_TEMPLATE: &[u8] = b"\
\x00\x01\x02\x03\x04\x05\
\x06\x07\x08\x09\x0a\x0b\
\x08\x00\
\x45\x00\
\x00\x34\
\x00\x00\
\x00\x00\
\xff\x84\
\x00\x00\
\x00\x00\x00\x00\
\x00\x00\x00\x00\
\x00\x00\
\x00\x00\
\x00\x00\x00\x00\
\x58\xe4\x5d\x36\
\x01\x00\
\x00\x14\
\x9e\x8d\x52\x25\
\x00\x00\x80\x00\
\x00\x0a\
\x08\x00\
\x46\x1a\xdf\x3d";

/// Default ICMP echo request (ping) template.
static DEFAULT_ICMP_PING_TEMPLATE: &[u8] = b"\
\x00\x01\x02\x03\x04\x05\
\x06\x07\x08\x09\x0a\x0b\
\x08\x00\
\x45\x00\
\x00\x4c\
\x00\x00\
\x00\x00\
\xff\x01\
\xff\xff\
\x00\x00\x00\x00\
\x00\x00\x00\x00\
\x08\x00\
\x00\x00\
\x00\x00\x00\x00\
\x08\x09\x0a\x0b\
\x0c\x0d\x0e\x0f\
\x10\x11\x12\x13\
\x14\x15\x16\x17\
\x18\x19\x1a\x1b\
\x1c\x1d\x1e\x1f\
\x20\x21\x22\x23\
\x24\x25\x26\x27\
\x28\x29\x2a\x2b\
\x2c\x2d\x2e\x2f\
\x30\x31\x32\x33\
\x34\x35\x36\x37";

/// Default ICMP timestamp request template.
static DEFAULT_ICMP_TIMESTAMP_TEMPLATE: &[u8] = b"\
\x00\x01\x02\x03\x04\x05\
\x06\x07\x08\x09\x0a\x0b\
\x08\x00\
\x45\x00\
\x00\x28\
\x00\x00\
\x00\x00\
\xff\x01\
\xff\xff\
\x00\x00\x00\x00\
\x00\x00\x00\x00\
\x0d\x00\
\x00\x00\
\x00\x00\
\x00\x00\
\x00\x00\x00\x00\
\x00\x00\x00\x00\
\x00\x00\x00\x00";

/// Default ARP request template.
static DEFAULT_ARP_TEMPLATE: &[u8] = b"\
\xff\xff\xff\xff\xff\xff\
\x00\x00\x00\x00\x00\x00\
\x08\x06\
\x00\x01\
\x08\x00\
\x06\x04\
\x00\x01\
\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00";

// -----------------------------------------------------------------------
// Checksum helpers
// -----------------------------------------------------------------------

/// Compute the IP header checksum (partial, without final complement).
///
/// `offset` is the start of the IP header in the packet buffer.
/// `max_offset` limits the range to check.
fn ip_header_checksum(buf: &[u8], offset: usize, max_offset: usize) -> u32 {
    let header_length = ((buf[offset] & 0x0F) as usize) * 4;
    let end = std::cmp::min(max_offset, offset + header_length);

    let mut xsum: u32 = 0;
    let mut i = offset;
    while i + 1 < end {
        xsum += ((buf[i] as u32) << 8) | (buf[i + 1] as u32);
        i += 2;
    }

    // Fold carries
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);

    xsum
}

/// Compute TCP pseudo-header + data checksum (partial, without complement).
fn tcp_checksum_ipv4(buf: &[u8], offset_ip: usize, offset_tcp: usize, tcp_length: usize) -> u64 {
    let mut xsum: u64 = 6; // protocol number
    xsum += tcp_length as u64;

    // Source IP
    xsum += ((buf[offset_ip + 12] as u64) << 8) | buf[offset_ip + 13] as u64;
    xsum += ((buf[offset_ip + 14] as u64) << 8) | buf[offset_ip + 15] as u64;

    // Destination IP
    xsum += ((buf[offset_ip + 16] as u64) << 8) | buf[offset_ip + 17] as u64;
    xsum += ((buf[offset_ip + 18] as u64) << 8) | buf[offset_ip + 19] as u64;

    // TCP data
    let mut i = 0;
    while i + 1 < tcp_length {
        xsum += ((buf[offset_tcp + i] as u64) << 8) | buf[offset_tcp + i + 1] as u64;
        i += 2;
    }

    // Handle odd byte
    if tcp_length & 1 != 0 {
        xsum += (buf[offset_tcp + tcp_length - 1] as u64) << 8;
    }

    // Fold carries
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);

    xsum
}

/// Compute UDP pseudo-header + data checksum (partial, without complement).
fn udp_checksum_ipv4(buf: &[u8], offset_ip: usize, offset_udp: usize, udp_length: usize) -> u64 {
    let mut xsum: u64 = 17; // UDP protocol number
    xsum += udp_length as u64;

    // Source IP
    xsum += ((buf[offset_ip + 12] as u64) << 8) | buf[offset_ip + 13] as u64;
    xsum += ((buf[offset_ip + 14] as u64) << 8) | buf[offset_ip + 15] as u64;

    // Destination IP
    xsum += ((buf[offset_ip + 16] as u64) << 8) | buf[offset_ip + 17] as u64;
    xsum += ((buf[offset_ip + 18] as u64) << 8) | buf[offset_ip + 19] as u64;

    // UDP data
    let mut i = 0;
    while i + 1 < udp_length {
        xsum += ((buf[offset_udp + i] as u64) << 8) | buf[offset_udp + i + 1] as u64;
        i += 2;
    }

    if udp_length & 1 != 0 {
        xsum += (buf[offset_udp + udp_length - 1] as u64) << 8;
    }

    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);

    xsum
}

/// Compute a public UDP checksum (used externally for template fixup).
pub fn udp_checksum2(buf: &[u8], offset_ip: usize, offset_udp: usize, udp_length: usize) -> u32 {
    udp_checksum_ipv4(buf, offset_ip, offset_udp, udp_length) as u32
}

/// Compute ICMP checksum (no pseudo-header).
fn icmp_checksum(buf: &[u8], offset_icmp: usize, icmp_length: usize) -> u64 {
    let mut xsum: u64 = 0;
    let mut i = 0;

    while i + 1 < icmp_length {
        xsum += ((buf[offset_icmp + i] as u64) << 8) | buf[offset_icmp + i + 1] as u64;
        i += 2;
    }

    if icmp_length & 1 != 0 {
        xsum += (buf[offset_icmp + icmp_length - 1] as u64) << 8;
    }

    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);

    xsum
}

/// Compute IPv6 pseudo-header checksum for TCP/UDP.
///
/// `src` and `dst` are the 16-byte IPv6 addresses.
/// `next_header` is the protocol number (6 for TCP, 17 for UDP).
fn checksum_ipv6(
    src: &[u8],
    dst: &[u8],
    next_header: u32,
    payload_length: usize,
    payload: &[u8],
) -> u64 {
    let mut xsum: u64 = 0;

    // Source address (16 bytes)
    for i in (0..16).step_by(2) {
        xsum += ((src[i] as u64) << 8) | src[i + 1] as u64;
    }

    // Destination address (16 bytes)
    for i in (0..16).step_by(2) {
        xsum += ((dst[i] as u64) << 8) | dst[i + 1] as u64;
    }

    // Upper-layer packet length (32-bit)
    xsum += payload_length as u64;

    // Next header (32-bit, zero-padded)
    xsum += next_header as u64;

    // Payload data
    let mut i = 0;
    while i + 1 < payload_length {
        xsum += ((payload[i] as u64) << 8) | payload[i + 1] as u64;
        i += 2;
    }
    if payload_length & 1 != 0 {
        xsum += (payload[payload_length - 1] as u64) << 8;
    }

    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);

    xsum
}

/// Compute a simple CRC32c-style checksum for SCTP.
///
/// TODO: Replace with a proper CRC32c implementation from a proto module.
/// This is a simplified placeholder.
fn sctp_checksum(buf: &[u8], length: usize) -> u32 {
    // CRC32c lookup table (first 16 entries for a minimal implementation)
    // A full implementation requires the complete 256-entry table.
    let mut crc: u32 = 0xFFFF_FFFF;
    for i in 0..length {
        crc ^= buf[i] as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F6_3B78;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

// -----------------------------------------------------------------------
// Packet header parsing (minimal, for template initialization)
// -----------------------------------------------------------------------

/// Result of minimal packet parsing.
struct ParsedPacket {
    ip_offset: usize,
    ip_version: u8,
    ip_protocol: u8,
    ip_length: usize,
    transport_offset: usize,
    app_offset: usize,
    found: ParsedType,
}

#[derive(Debug, PartialEq)]
enum ParsedType {
    Nothing,
    Tcp,
    Udp,
    Icmp,
    Sctp,
    Arp,
}

/// Parse an Ethernet-framed packet to find header offsets.
///
/// This is a minimal parser sufficient for template initialization.
/// It handles Ethernet + IPv4/IPv6 + TCP/UDP/ICMP/SCTP and ARP.
fn parse_packet(buf: &[u8], data_link: u32) -> Option<ParsedPacket> {
    match data_link {
        DLT_ETHERNET => parse_ethernet(buf),
        DLT_RAW => parse_raw_ip(buf, 0),
        DLT_NULL => {
            // Null data link: 4-byte header with address family
            if buf.len() < 4 {
                return None;
            }
            parse_raw_ip(buf, 4)
        }
        _ => {
            log::error!("unsupported data link type: {}", data_link);
            None
        }
    }
}

fn parse_ethernet(buf: &[u8]) -> Option<ParsedPacket> {
    if buf.len() < 14 {
        return None;
    }

    let mut offset = 14;
    let mut ethertype = ((buf[12] as u16) << 8) | buf[13] as u16;

    // Handle 802.1Q VLAN tag
    if ethertype == 0x8100 {
        if buf.len() < 18 {
            return None;
        }
        ethertype = ((buf[16] as u16) << 8) | buf[17] as u16;
        offset = 18;
    }

    match ethertype {
        0x0800 => parse_ipv4(buf, offset),
        0x86DD => parse_ipv6(buf, offset),
        0x0806 => {
            // ARP
            Some(ParsedPacket {
                ip_offset: offset,
                ip_version: 0,
                ip_protocol: 0,
                ip_length: 28, // ARP is 28 bytes
                transport_offset: offset,
                app_offset: offset + 28,
                found: ParsedType::Arp,
            })
        }
        _ => None,
    }
}

fn parse_raw_ip(buf: &[u8], offset: usize) -> Option<ParsedPacket> {
    if offset >= buf.len() {
        return None;
    }
    let version = (buf[offset] >> 4) & 0x0F;
    match version {
        4 => parse_ipv4(buf, offset),
        6 => parse_ipv6(buf, offset),
        _ => None,
    }
}

fn parse_ipv4(buf: &[u8], offset: usize) -> Option<ParsedPacket> {
    if buf.len() < offset + 20 {
        return None;
    }

    let ip_hdr_len = ((buf[offset] & 0x0F) as usize) * 4;
    let total_length = ((buf[offset + 2] as usize) << 8) | buf[offset + 3] as usize;
    let protocol = buf[offset + 9];
    let transport_offset = offset + ip_hdr_len;

    let (found, app_offset) = match protocol {
        6 => {
            // TCP
            if buf.len() < transport_offset + 20 {
                return None;
            }
            let tcp_hdr_len = ((buf[transport_offset + 12] >> 4) as usize) * 4;
            (ParsedType::Tcp, transport_offset + tcp_hdr_len)
        }
        17 => {
            // UDP
            if buf.len() < transport_offset + 8 {
                return None;
            }
            (ParsedType::Udp, transport_offset + 8)
        }
        1 => {
            // ICMP
            (ParsedType::Icmp, offset + total_length)
        }
        132 => {
            // SCTP
            if buf.len() < transport_offset + 12 {
                return None;
            }
            (ParsedType::Sctp, transport_offset + 12)
        }
        _ => {
            (ParsedType::Nothing, offset + total_length)
        }
    };

    Some(ParsedPacket {
        ip_offset: offset,
        ip_version: 4,
        ip_protocol: protocol,
        ip_length: total_length,
        transport_offset,
        app_offset,
        found,
    })
}

fn parse_ipv6(buf: &[u8], offset: usize) -> Option<ParsedPacket> {
    if buf.len() < offset + 40 {
        return None;
    }

    let payload_length = ((buf[offset + 4] as usize) << 8) | buf[offset + 5] as usize;
    let next_header = buf[offset + 6];
    let transport_offset = offset + 40;

    let (found, app_offset) = match next_header {
        6 => {
            // TCP
            if buf.len() < transport_offset + 20 {
                return None;
            }
            let tcp_hdr_len = ((buf[transport_offset + 12] >> 4) as usize) * 4;
            (ParsedType::Tcp, transport_offset + tcp_hdr_len)
        }
        17 => {
            // UDP
            if buf.len() < transport_offset + 8 {
                return None;
            }
            (ParsedType::Udp, transport_offset + 8)
        }
        58 => {
            // ICMPv6
            (ParsedType::Icmp, offset + 40 + payload_length)
        }
        132 => {
            // SCTP
            (ParsedType::Sctp, transport_offset + 12)
        }
        _ => {
            (ParsedType::Nothing, offset + 40 + payload_length)
        }
    };

    Some(ParsedPacket {
        ip_offset: offset,
        ip_version: 6,
        ip_protocol: next_header,
        ip_length: 40 + payload_length,
        transport_offset,
        app_offset,
        found,
    })
}

// -----------------------------------------------------------------------
// Template structures
// -----------------------------------------------------------------------

/// One half (IPv4 or IPv6) of a packet template.
#[derive(Clone)]
pub struct TemplateHalf {
    /// Total packet length.
    pub length: usize,
    /// Offset to the IP header.
    pub offset_ip: usize,
    /// Offset to the transport (TCP/UDP/ICMP) header.
    pub offset_tcp: usize,
    /// Offset to the application payload.
    pub offset_app: usize,
    /// The raw packet bytes.
    pub packet: Vec<u8>,
    /// Pre-computed partial IP header checksum.
    pub checksum_ip: u32,
    /// Pre-computed partial transport-layer checksum.
    pub checksum_tcp: u32,
    /// IP identification field template.
    pub ip_id: u32,
}

impl Default for TemplateHalf {
    fn default() -> Self {
        Self {
            length: 0,
            offset_ip: 0,
            offset_tcp: 0,
            offset_app: 0,
            packet: Vec::new(),
            checksum_ip: 0,
            checksum_tcp: 0,
            ip_id: 0,
        }
    }
}

/// A complete packet template with both IPv4 and IPv6 variants.
#[derive(Clone)]
pub struct TemplatePacket {
    pub ipv4: TemplateHalf,
    pub ipv6: TemplateHalf,
    pub proto: TemplateProtocol,
    /// Pointer index to the UDP payloads database (used for UDP templates).
    /// The actual `PayloadsUdp` is stored in the `TemplateSet`.
    pub payloads_index: Option<PayloadsIndex>,
}

/// Which payloads database to use for this template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadsIndex {
    Udp,
    Oproto,
}

impl Default for TemplatePacket {
    fn default() -> Self {
        Self {
            ipv4: TemplateHalf::default(),
            ipv6: TemplateHalf::default(),
            proto: TemplateProtocol::Tcp,
            payloads_index: None,
        }
    }
}

/// A complete set of packet templates, one for each protocol.
pub struct TemplateSet {
    pub templates: Vec<TemplatePacket>,
    pub entropy: u64,
    pub udp_payloads: Option<PayloadsUdp>,
    pub oproto_payloads: Option<PayloadsUdp>,
}

impl TemplateSet {
    /// Create an empty template set.
    pub fn new() -> Self {
        Self {
            templates: Vec::with_capacity(PROTO_COUNT),
            entropy: 0,
            udp_payloads: None,
            oproto_payloads: None,
        }
    }
}

impl Default for TemplateSet {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------
// Template initialization
// -----------------------------------------------------------------------

/// Initialize a single template from raw packet bytes.
fn template_init(
    source_mac: MacAddress,
    router_mac_ipv4: MacAddress,
    router_mac_ipv6: MacAddress,
    packet_bytes: &[u8],
    data_link: u32,
) -> TemplatePacket {
    let mut tmpl = TemplatePacket::default();

    // Copy the template bytes
    tmpl.ipv4.packet = packet_bytes.to_vec();
    tmpl.ipv4.length = packet_bytes.len();

    // Parse the template to find header offsets
    let parsed = match parse_packet(&tmpl.ipv4.packet, data_link) {
        Some(p) => p,
        None => {
            log::error!("bad packet template: could not parse");
            return tmpl;
        }
    };

    tmpl.ipv4.offset_ip = parsed.ip_offset;
    tmpl.ipv4.offset_tcp = parsed.transport_offset;
    tmpl.ipv4.offset_app = parsed.app_offset;

    // Truncate to actual packet length
    if parsed.found == ParsedType::Arp {
        tmpl.ipv4.length = parsed.ip_offset + 28;
    } else {
        tmpl.ipv4.length = parsed.ip_offset + parsed.ip_length;
    }

    // Trim buffer to actual length
    tmpl.ipv4.packet.truncate(tmpl.ipv4.length);

    let px = &mut tmpl.ipv4.packet;

    // Overwrite MAC addresses
    if data_link == DLT_ETHERNET {
        px[0..6].copy_from_slice(&router_mac_ipv4.addr);
        px[6..12].copy_from_slice(&source_mac.addr);
    }

    // Zero out source/dest IP addresses in template
    if parsed.found == ParsedType::Arp {
        // Set sender MAC in ARP
        if parsed.ip_offset + 14 <= px.len() {
            px[parsed.ip_offset..parsed.ip_offset + 6].copy_from_slice(&source_mac.addr);
        }
        tmpl.proto = TemplateProtocol::Arp;

        // Build IPv6 template (minimal for ARP)
        tmpl.ipv6 = tmpl.ipv4.clone();
        return tmpl;
    }

    // Zero IP addresses for checksum pre-computation
    if parsed.ip_version == 4 && parsed.ip_offset + 20 <= px.len() {
        // Zero IP ID, checksum, and addresses
        px[parsed.ip_offset + 4] = 0;
        px[parsed.ip_offset + 5] = 0;
        px[parsed.ip_offset + 10] = 0;
        px[parsed.ip_offset + 11] = 0;
        for i in 12..20 {
            px[parsed.ip_offset + i] = 0;
        }
    }

    // Compute partial IP checksum
    tmpl.ipv4.checksum_ip =
        ip_header_checksum(&tmpl.ipv4.packet, tmpl.ipv4.offset_ip, tmpl.ipv4.length) as u32;

    // Compute partial transport-layer checksum and set protocol
    match parsed.ip_protocol {
        1 => {
            // ICMP
            tmpl.ipv4.offset_app = tmpl.ipv4.length;
            tmpl.ipv4.checksum_tcp = icmp_checksum(
                &tmpl.ipv4.packet,
                tmpl.ipv4.offset_tcp,
                tmpl.ipv4.length - tmpl.ipv4.offset_tcp,
            ) as u32;
            tmpl.proto = if tmpl.ipv4.packet.get(tmpl.ipv4.offset_tcp) == Some(&8) {
                TemplateProtocol::IcmpPing
            } else {
                TemplateProtocol::IcmpTimestamp
            };
        }
        6 => {
            // TCP: zero ports, seqno, checksum
            let t = tmpl.ipv4.offset_tcp;
            if t + 20 <= tmpl.ipv4.packet.len() {
                for i in 0..8 {
                    tmpl.ipv4.packet[t + i] = 0;
                }
                tmpl.ipv4.packet[t + 16] = 0;
                tmpl.ipv4.packet[t + 17] = 0;
            }
            tmpl.ipv4.checksum_tcp = tcp_checksum_ipv4(
                &tmpl.ipv4.packet,
                tmpl.ipv4.offset_ip,
                tmpl.ipv4.offset_tcp,
                tmpl.ipv4.offset_app - tmpl.ipv4.offset_tcp,
            ) as u32;
            tmpl.proto = TemplateProtocol::Tcp;
        }
        17 => {
            // UDP: zero checksum
            let t = tmpl.ipv4.offset_tcp;
            if t + 8 <= tmpl.ipv4.packet.len() {
                tmpl.ipv4.packet[t + 6] = 0;
                tmpl.ipv4.packet[t + 7] = 0;
            }
            tmpl.ipv4.checksum_tcp = udp_checksum_ipv4(
                &tmpl.ipv4.packet,
                tmpl.ipv4.offset_ip,
                tmpl.ipv4.offset_tcp,
                tmpl.ipv4.length - tmpl.ipv4.offset_tcp,
            ) as u32;
            tmpl.proto = TemplateProtocol::Udp;
        }
        132 => {
            // SCTP
            tmpl.ipv4.checksum_tcp = sctp_checksum(
                &tmpl.ipv4.packet[tmpl.ipv4.offset_tcp..],
                tmpl.ipv4.length - tmpl.ipv4.offset_tcp,
            );
            tmpl.proto = TemplateProtocol::Sctp;
        }
        _ => {}
    }

    // Handle data-link adjustments for raw IP
    if data_link == DLT_NULL {
        let shift = tmpl.ipv4.offset_ip - 4;
        let len = tmpl.ipv4.length;
        tmpl.ipv4.packet.copy_within(tmpl.ipv4.offset_ip..len, 4);
        tmpl.ipv4.length -= shift;
        tmpl.ipv4.offset_tcp -= shift;
        tmpl.ipv4.offset_app -= shift;
        tmpl.ipv4.offset_ip = 4;
        // Write AF_INET = 2
        tmpl.ipv4.packet[0..4].copy_from_slice(&2u32.to_ne_bytes());
    } else if data_link == DLT_RAW {
        let shift = tmpl.ipv4.offset_ip;
        if shift > 0 {
            let len = tmpl.ipv4.length;
            tmpl.ipv4.packet.copy_within(shift..len, 0);
            tmpl.ipv4.length -= shift;
            tmpl.ipv4.offset_tcp -= shift;
            tmpl.ipv4.offset_app -= shift;
            tmpl.ipv4.offset_ip = 0;
        }
    }

    // Build IPv6 template from IPv4 template
    template_init_ipv6(&mut tmpl, router_mac_ipv6, data_link);

    tmpl
}

/// Create an IPv6 packet template from an IPv4 template.
///
/// Replaces the IPv4 header with an IPv6 header, keeping the
/// transport-layer and above unchanged.
fn template_init_ipv6(tmpl: &mut TemplatePacket, router_mac_ipv6: MacAddress, data_link: u32) {
    let ipv4 = &tmpl.ipv4;
    let payload_length = ipv4.length - ipv4.offset_tcp;
    let offset_ip = ipv4.offset_ip;
    let offset_tcp = ipv4.offset_tcp;
    let parsed_protocol = ipv4.packet.get(offset_ip + 9).copied().unwrap_or(0);

    // Create buffer with room for IPv6 header (40 bytes) instead of IPv4 header
    let offset_tcp6 = offset_ip + 40;
    let mut buf = vec![0u8; offset_tcp6 + payload_length];

    // Copy everything before IP header (Ethernet, etc.)
    buf[..offset_ip].copy_from_slice(&ipv4.packet[..offset_ip]);

    // Copy transport payload to new position
    if offset_tcp < ipv4.packet.len() {
        let copy_len = std::cmp::min(payload_length, buf.len() - offset_tcp6);
        buf[offset_tcp6..offset_tcp6 + copy_len]
            .copy_from_slice(&ipv4.packet[offset_tcp..offset_tcp + copy_len]);
    }

    // Fill IPv6 header
    buf[offset_ip] = 0x60; // version = 6
    buf[offset_ip + 4] = (payload_length >> 8) as u8;
    buf[offset_ip + 5] = (payload_length & 0xFF) as u8;

    // Next header: map ICMP (1) to ICMPv6 (58)
    let next_header = if parsed_protocol == 1 { 58 } else { parsed_protocol };
    buf[offset_ip + 6] = next_header;
    buf[offset_ip + 7] = 0xFF; // hop limit = 255

    // Fix ICMP type for IPv6 (ping: 8 -> 128)
    if parsed_protocol == 1 && offset_tcp6 < buf.len() {
        if buf[offset_tcp6] == 8 {
            buf[offset_tcp6] = 128; // echo request -> ICMPv6 echo request
        }
    }

    // Update Ethernet header for IPv6
    match data_link {
        DLT_ETHERNET => {
            buf[0..6].copy_from_slice(&router_mac_ipv6.addr);
            buf[12] = 0x86;
            buf[13] = 0xDD;
        }
        DLT_NULL => {
            // AF_INET6 = 10 (Linux) or 24 (macOS) -- use 10
            buf[0..4].copy_from_slice(&10u32.to_ne_bytes());
        }
        _ => {}
    }

    // Parse the new IPv6 packet to get offsets
    let total_length = offset_ip + 40 + payload_length;

    tmpl.ipv6 = TemplateHalf {
        length: total_length,
        offset_ip: offset_ip,
        offset_tcp: offset_tcp6,
        offset_app: offset_tcp6 + (tmpl.ipv4.offset_app - tmpl.ipv4.offset_tcp),
        packet: buf,
        checksum_ip: 0, // IPv6 has no header checksum
        checksum_tcp: 0, // Computed at send time
        ip_id: 0,
    };
}

/// Initialize the complete template set with all protocol templates.
///
/// This creates packet templates for TCP, UDP, SCTP, ICMP ping,
/// ICMP timestamp, ARP, and optionally Oproto and VulnCheck.
pub fn template_packet_init(
    source_mac: MacAddress,
    router_mac_ipv4: MacAddress,
    router_mac_ipv6: MacAddress,
    udp_payloads: Option<PayloadsUdp>,
    oproto_payloads: Option<PayloadsUdp>,
    data_link: u32,
    entropy: u64,
    templ_opts: &TemplateOptions,
) -> TemplateSet {
    let mut set = TemplateSet {
        templates: Vec::with_capacity(PROTO_COUNT),
        entropy,
        udp_payloads,
        oproto_payloads,
    };

    // SCTP
    {
        let tmpl = template_init(
            source_mac,
            router_mac_ipv4,
            router_mac_ipv6,
            DEFAULT_SCTP_TEMPLATE,
            data_link,
        );
        set.templates.push(tmpl);
    }

    // TCP (apply options first)
    {
        let mut tcp_buf = DEFAULT_TCP_TEMPLATE.to_vec();
        tcp_hdr::templ_tcp_apply_options(&mut tcp_buf, templ_opts);
        let tmpl = template_init(
            source_mac,
            router_mac_ipv4,
            router_mac_ipv6,
            &tcp_buf,
            data_link,
        );
        set.templates.push(tmpl);
    }

    // UDP
    {
        let mut tmpl = template_init(
            source_mac,
            router_mac_ipv4,
            router_mac_ipv6,
            DEFAULT_UDP_TEMPLATE,
            data_link,
        );
        tmpl.payloads_index = Some(PayloadsIndex::Udp);
        set.templates.push(tmpl);
    }

    // Oproto (reuse UDP template structure)
    {
        let mut tmpl = template_init(
            source_mac,
            router_mac_ipv4,
            router_mac_ipv6,
            DEFAULT_UDP_TEMPLATE,
            data_link,
        );
        tmpl.payloads_index = Some(PayloadsIndex::Oproto);
        tmpl.proto = TemplateProtocol::Oproto;
        set.templates.push(tmpl);
    }

    // ICMP ping
    {
        let tmpl = template_init(
            source_mac,
            router_mac_ipv4,
            router_mac_ipv6,
            DEFAULT_ICMP_PING_TEMPLATE,
            data_link,
        );
        set.templates.push(tmpl);
    }

    // ICMP timestamp
    {
        let tmpl = template_init(
            source_mac,
            router_mac_ipv4,
            router_mac_ipv6,
            DEFAULT_ICMP_TIMESTAMP_TEMPLATE,
            data_link,
        );
        set.templates.push(tmpl);
    }

    // ARP
    {
        let tmpl = template_init(
            source_mac,
            router_mac_ipv4,
            router_mac_ipv6,
            DEFAULT_ARP_TEMPLATE,
            data_link,
        );
        set.templates.push(tmpl);
    }

    set
}

// -----------------------------------------------------------------------
// Target setting
// -----------------------------------------------------------------------

/// Determine which template to use based on the port number range.
///
/// Port ranges encode the protocol:
/// - `[0..65535]` = TCP
/// - `[65536..131071]` = UDP
/// - `[131072..196607]` = SCTP
/// - `[196608]` = ICMP echo
/// - `[196609]` = ICMP timestamp
/// - `[196610]` = ARP
fn select_template(set: &TemplateSet, port_them: u32) -> Option<usize> {
    use crate::massip::port::{TEMPL_TCP, TEMPL_UDP, TEMPL_SCTP, TEMPL_ICMP_ECHO, TEMPL_ICMP_TIMESTAMP, TEMPL_ARP};

    for (i, tmpl) in set.templates.iter().enumerate() {
        match tmpl.proto {
            TemplateProtocol::Tcp if port_them < TEMPL_TCP + 65536 => return Some(i),
            TemplateProtocol::Udp if (TEMPL_UDP..TEMPL_UDP + 65536).contains(&port_them) => return Some(i),
            TemplateProtocol::Sctp if (TEMPL_SCTP..TEMPL_SCTP + 65536).contains(&port_them) => return Some(i),
            TemplateProtocol::IcmpPing if port_them == TEMPL_ICMP_ECHO => return Some(i),
            TemplateProtocol::IcmpTimestamp if port_them == TEMPL_ICMP_TIMESTAMP => return Some(i),
            TemplateProtocol::Arp if port_them == TEMPL_ARP => return Some(i),
            _ => continue,
        }
    }
    None
}

/// Set the target address and port in a packet template for IPv4.
///
/// Takes a template set and produces a complete packet in `px` targeted
/// at the given destination. The packet is ready to transmit after this
/// call returns.
///
/// Returns the number of bytes written to `px`, or 0 on error.
pub fn template_set_target_ipv4(
    set: &TemplateSet,
    ip_them: Ipv4Address,
    port_them: u32,
    ip_me: Ipv4Address,
    port_me: u16,
    seqno: u32,
    px: &mut [u8],
) -> usize {
    let tmpl_idx = match select_template(set, port_them) {
        Some(i) => i,
        None => return 0,
    };

    let tmpl = &set.templates[tmpl_idx];
    let port_them = port_them & 0xFFFF;

    // ARP special case
    if tmpl.proto == TemplateProtocol::Arp {
        let copy_len = std::cmp::min(px.len(), tmpl.ipv4.length);
        px[..copy_len].copy_from_slice(&tmpl.ipv4.packet[..copy_len]);
        let off = tmpl.ipv4.offset_ip;
        if off + 28 <= copy_len {
            // Sender IP (offset 14 within ARP)
            px[off + 14] = (ip_me >> 24) as u8;
            px[off + 15] = (ip_me >> 16) as u8;
            px[off + 16] = (ip_me >> 8) as u8;
            px[off + 17] = (ip_me >> 0) as u8;
            // Target IP (offset 24 within ARP)
            px[off + 24] = (ip_them >> 24) as u8;
            px[off + 25] = (ip_them >> 16) as u8;
            px[off + 26] = (ip_them >> 8) as u8;
            px[off + 27] = (ip_them >> 0) as u8;
        }
        return copy_len;
    }

    // Copy template to output buffer
    let copy_len = std::cmp::min(px.len(), tmpl.ipv4.length);
    px[..copy_len].copy_from_slice(&tmpl.ipv4.packet[..copy_len]);

    let offset_ip = tmpl.ipv4.offset_ip;
    let offset_tcp = tmpl.ipv4.offset_tcp;
    let ip_id = ip_them ^ (port_them & 0xFFFF) ^ seqno;

    // Fill IP header fields
    let total_length = tmpl.ipv4.length - tmpl.ipv4.offset_ip;
    px[offset_ip + 2] = (total_length >> 8) as u8;
    px[offset_ip + 3] = (total_length & 0xFF) as u8;
    px[offset_ip + 4] = (ip_id >> 8) as u8;
    px[offset_ip + 5] = (ip_id & 0xFF) as u8;

    // Source IP
    px[offset_ip + 12] = (ip_me >> 24) as u8;
    px[offset_ip + 13] = (ip_me >> 16) as u8;
    px[offset_ip + 14] = (ip_me >> 8) as u8;
    px[offset_ip + 15] = (ip_me >> 0) as u8;

    // Destination IP
    px[offset_ip + 16] = (ip_them >> 24) as u8;
    px[offset_ip + 17] = (ip_them >> 16) as u8;
    px[offset_ip + 18] = (ip_them >> 8) as u8;
    px[offset_ip + 19] = (ip_them >> 0) as u8;

    // IP checksum
    px[offset_ip + 10] = 0;
    px[offset_ip + 11] = 0;
    let xsum_ip = !ip_header_checksum(px, offset_ip, tmpl.ipv4.length) as u16;
    px[offset_ip + 10] = (xsum_ip >> 8) as u8;
    px[offset_ip + 11] = (xsum_ip & 0xFF) as u8;

    // Transport-layer checksum and fields
    match tmpl.proto {
        TemplateProtocol::Tcp => {
            px[offset_tcp + 0] = (port_me >> 8) as u8;
            px[offset_tcp + 1] = (port_me & 0xFF) as u8;
            px[offset_tcp + 2] = (port_them >> 8) as u8;
            px[offset_tcp + 3] = (port_them & 0xFF) as u8;
            px[offset_tcp + 4] = (seqno >> 24) as u8;
            px[offset_tcp + 5] = (seqno >> 16) as u8;
            px[offset_tcp + 6] = (seqno >> 8) as u8;
            px[offset_tcp + 7] = (seqno >> 0) as u8;

            let mut xsum: u64 = tmpl.ipv4.checksum_tcp as u64
                + ip_me as u64
                + ip_them as u64
                + port_me as u64
                + port_them as u64
                + seqno as u64;
            xsum = (xsum >> 16) + (xsum & 0xFFFF);
            xsum = (xsum >> 16) + (xsum & 0xFFFF);
            xsum = (xsum >> 16) + (xsum & 0xFFFF);
            xsum = !xsum;

            px[offset_tcp + 16] = (xsum >> 8) as u8;
            px[offset_tcp + 17] = (xsum & 0xFF) as u8;
        }
        TemplateProtocol::Udp => {
            px[offset_tcp + 0] = (port_me >> 8) as u8;
            px[offset_tcp + 1] = (port_me & 0xFF) as u8;
            px[offset_tcp + 2] = (port_them >> 8) as u8;
            px[offset_tcp + 3] = (port_them & 0xFF) as u8;

            let udp_len = tmpl.ipv4.length - tmpl.ipv4.offset_app + 8;
            px[offset_tcp + 4] = (udp_len >> 8) as u8;
            px[offset_tcp + 5] = (udp_len & 0xFF) as u8;

            px[offset_tcp + 6] = 0;
            px[offset_tcp + 7] = 0;

            let xsum = udp_checksum_ipv4(px, offset_ip, offset_tcp, tmpl.ipv4.length - offset_tcp);
            let xsum = !xsum;
            px[offset_tcp + 6] = (xsum >> 8) as u8;
            px[offset_tcp + 7] = (xsum & 0xFF) as u8;
        }
        TemplateProtocol::Sctp => {
            px[offset_tcp + 0] = (port_me >> 8) as u8;
            px[offset_tcp + 1] = (port_me & 0xFF) as u8;
            px[offset_tcp + 2] = (port_them >> 8) as u8;
            px[offset_tcp + 3] = (port_them & 0xFF) as u8;

            px[offset_tcp + 16] = (seqno >> 24) as u8;
            px[offset_tcp + 17] = (seqno >> 16) as u8;
            px[offset_tcp + 18] = (seqno >> 8) as u8;
            px[offset_tcp + 19] = (seqno >> 0) as u8;

            let xsum = sctp_checksum(&px[offset_tcp..], tmpl.ipv4.length - offset_tcp);
            px[offset_tcp + 8] = (xsum >> 24) as u8;
            px[offset_tcp + 9] = (xsum >> 16) as u8;
            px[offset_tcp + 10] = (xsum >> 8) as u8;
            px[offset_tcp + 11] = (xsum & 0xFF) as u8;
        }
        TemplateProtocol::IcmpPing | TemplateProtocol::IcmpTimestamp => {
            // For ICMP, seqno is derived from a SYN-cookie-like hash.
            // TODO: integrate with syn_cookie module.
            // For now, use a simple hash of the addresses.
            let icmp_seqno = seqno;
            px[offset_tcp + 4] = (icmp_seqno >> 24) as u8;
            px[offset_tcp + 5] = (icmp_seqno >> 16) as u8;
            px[offset_tcp + 6] = (icmp_seqno >> 8) as u8;
            px[offset_tcp + 7] = (icmp_seqno >> 0) as u8;

            let mut xsum: u64 = tmpl.ipv4.checksum_tcp as u64 + icmp_seqno as u64;
            xsum = (xsum >> 16) + (xsum & 0xFFFF);
            xsum = (xsum >> 16) + (xsum & 0xFFFF);
            xsum = (xsum >> 16) + (xsum & 0xFFFF);
            xsum = !xsum;

            px[offset_tcp + 2] = (xsum >> 8) as u8;
            px[offset_tcp + 3] = (xsum & 0xFF) as u8;
        }
        TemplateProtocol::Arp | TemplateProtocol::Oproto | TemplateProtocol::VulnCheck => {}
    }

    copy_len
}

/// Set the target address and port in a packet template for IPv6.
///
/// Returns the number of bytes written to `px`, or 0 on error.
pub fn template_set_target_ipv6(
    set: &TemplateSet,
    ip_them: Ipv6Address,
    port_them: u32,
    ip_me: Ipv6Address,
    port_me: u16,
    seqno: u32,
    px: &mut [u8],
) -> usize {
    let tmpl_idx = match select_template(set, port_them) {
        Some(i) => i,
        None => return 0,
    };

    let tmpl = &set.templates[tmpl_idx];
    let port_them = port_them & 0xFFFF;

    // Copy template
    let copy_len = std::cmp::min(px.len(), tmpl.ipv6.length);
    px[..copy_len].copy_from_slice(&tmpl.ipv6.packet[..copy_len]);

    let offset_ip = tmpl.ipv6.offset_ip;
    let offset_tcp = tmpl.ipv6.offset_tcp;
    let offset_app = tmpl.ipv6.offset_app;

    // Set payload length in IPv6 header
    let payload_len = copy_len - offset_ip - 40;
    px[offset_ip + 4] = (payload_len >> 8) as u8;
    px[offset_ip + 5] = (payload_len & 0xFF) as u8;

    // Source IPv6 address (16 bytes at offset_ip+8)
    let src_bytes = ip_me.to_bytes();
    px[offset_ip + 8..offset_ip + 24].copy_from_slice(&src_bytes);

    // Destination IPv6 address (16 bytes at offset_ip+24)
    let dst_bytes = ip_them.to_bytes();
    px[offset_ip + 24..offset_ip + 40].copy_from_slice(&dst_bytes);

    // Transport-layer fields
    match tmpl.proto {
        TemplateProtocol::Tcp => {
            px[offset_tcp + 0] = (port_me >> 8) as u8;
            px[offset_tcp + 1] = (port_me & 0xFF) as u8;
            px[offset_tcp + 2] = (port_them >> 8) as u8;
            px[offset_tcp + 3] = (port_them & 0xFF) as u8;
            px[offset_tcp + 4] = (seqno >> 24) as u8;
            px[offset_tcp + 5] = (seqno >> 16) as u8;
            px[offset_tcp + 6] = (seqno >> 8) as u8;
            px[offset_tcp + 7] = (seqno >> 0) as u8;

            px[offset_tcp + 16] = 0;
            px[offset_tcp + 17] = 0;

            let tcp_len = copy_len - offset_tcp;
            let xsum = checksum_ipv6(
                &px[offset_ip + 8..offset_ip + 24],
                &px[offset_ip + 24..offset_ip + 40],
                6,
                tcp_len,
                &px[offset_tcp..offset_tcp + tcp_len],
            );
            let xsum = !xsum;

            px[offset_tcp + 16] = (xsum >> 8) as u8;
            px[offset_tcp + 17] = (xsum & 0xFF) as u8;
        }
        TemplateProtocol::Udp => {
            px[offset_tcp + 0] = (port_me >> 8) as u8;
            px[offset_tcp + 1] = (port_me & 0xFF) as u8;
            px[offset_tcp + 2] = (port_them >> 8) as u8;
            px[offset_tcp + 3] = (port_them & 0xFF) as u8;

            let udp_len = copy_len - offset_tcp;
            px[offset_tcp + 4] = (udp_len >> 8) as u8;
            px[offset_tcp + 5] = (udp_len & 0xFF) as u8;
            px[offset_tcp + 6] = 0;
            px[offset_tcp + 7] = 0;

            let xsum = checksum_ipv6(
                &px[offset_ip + 8..offset_ip + 24],
                &px[offset_ip + 24..offset_ip + 40],
                17,
                udp_len,
                &px[offset_tcp..offset_tcp + udp_len],
            );
            let xsum = !xsum;

            px[offset_tcp + 6] = (xsum >> 8) as u8;
            px[offset_tcp + 7] = (xsum & 0xFF) as u8;
        }
        TemplateProtocol::Sctp => {
            px[offset_tcp + 0] = (port_me >> 8) as u8;
            px[offset_tcp + 1] = (port_me & 0xFF) as u8;
            px[offset_tcp + 2] = (port_them >> 8) as u8;
            px[offset_tcp + 3] = (port_them & 0xFF) as u8;

            px[offset_tcp + 16] = (seqno >> 24) as u8;
            px[offset_tcp + 17] = (seqno >> 16) as u8;
            px[offset_tcp + 18] = (seqno >> 8) as u8;
            px[offset_tcp + 19] = (seqno >> 0) as u8;

            let xsum = sctp_checksum(&px[offset_tcp..copy_len], copy_len - offset_tcp);
            px[offset_tcp + 8] = (xsum >> 24) as u8;
            px[offset_tcp + 9] = (xsum >> 16) as u8;
            px[offset_tcp + 10] = (xsum >> 8) as u8;
            px[offset_tcp + 11] = (xsum & 0xFF) as u8;
        }
        TemplateProtocol::IcmpPing | TemplateProtocol::IcmpTimestamp => {
            px[offset_tcp + 4] = (seqno >> 24) as u8;
            px[offset_tcp + 5] = (seqno >> 16) as u8;
            px[offset_tcp + 6] = (seqno >> 8) as u8;
            px[offset_tcp + 7] = (seqno >> 0) as u8;

            let icmp_len = copy_len - offset_tcp;
            let xsum = checksum_ipv6(
                &px[offset_ip + 8..offset_ip + 24],
                &px[offset_ip + 24..offset_ip + 40],
                58, // ICMPv6
                icmp_len,
                &px[offset_tcp..offset_tcp + icmp_len],
            );
            let xsum = !xsum;

            px[offset_tcp + 2] = (xsum >> 8) as u8;
            px[offset_tcp + 3] = (xsum & 0xFF) as u8;
        }
        _ => {}
    }

    copy_len
}

// -----------------------------------------------------------------------
// TCP response packet creation (for banner grabbing)
// -----------------------------------------------------------------------

/// Create a TCP packet containing a payload, based on the original SYN template.
///
/// Used for banner grabbing: after receiving a SYN-ACK, we send back
/// an ACK with an optional payload.
pub fn tcp_create_packet(
    tmpl: &TemplatePacket,
    ip_them: crate::massip::addr::IpAddress,
    port_them: u16,
    ip_me: crate::massip::addr::IpAddress,
    port_me: u16,
    seqno: u32,
    ackno: u32,
    flags: u8,
    payload: &[u8],
    px: &mut [u8],
) -> usize {
    match (ip_them, ip_me) {
        (crate::massip::addr::IpAddress::V4(them4), crate::massip::addr::IpAddress::V4(me4)) => {
            tcp_create_packet_ipv4(tmpl, them4, port_them, me4, port_me, seqno, ackno, flags, payload, px)
        }
        (crate::massip::addr::IpAddress::V6(them6), crate::massip::addr::IpAddress::V6(me6)) => {
            tcp_create_packet_ipv6(tmpl, them6, port_them, me6, port_me, seqno, ackno, flags, payload, px)
        }
        _ => 0, // mixed v4/v6 not supported
    }
}

fn tcp_create_packet_ipv4(
    tmpl: &TemplatePacket,
    ip_them: Ipv4Address,
    port_them: u16,
    ip_me: Ipv4Address,
    port_me: u16,
    seqno: u32,
    ackno: u32,
    flags: u8,
    payload: &[u8],
    px: &mut [u8],
) -> usize {
    let offset_ip = tmpl.ipv4.offset_ip;
    let offset_tcp = tmpl.ipv4.offset_tcp;
    let offset_payload = offset_tcp + ((tmpl.ipv4.packet[offset_tcp + 12] >> 4) as usize) * 4;
    let new_length = offset_payload + payload.len();
    let ip_len = (offset_payload - offset_ip) + payload.len();
    let ip_id = ip_them ^ (port_them as u32) ^ seqno;

    if new_length > px.len() {
        log::error!("tcp_create_packet: payload too large");
        return 0;
    }

    // Copy template up to end, then payload
    let copy_len = std::cmp::min(px.len(), tmpl.ipv4.length);
    px[..copy_len].copy_from_slice(&tmpl.ipv4.packet[..copy_len]);
    if offset_payload + payload.len() <= px.len() {
        px[offset_payload..offset_payload + payload.len()].copy_from_slice(payload);
    }

    // IP header fields
    px[offset_ip + 2] = (ip_len >> 8) as u8;
    px[offset_ip + 3] = (ip_len & 0xFF) as u8;
    px[offset_ip + 4] = (ip_id >> 8) as u8;
    px[offset_ip + 5] = (ip_id & 0xFF) as u8;

    px[offset_ip + 12] = (ip_me >> 24) as u8;
    px[offset_ip + 13] = (ip_me >> 16) as u8;
    px[offset_ip + 14] = (ip_me >> 8) as u8;
    px[offset_ip + 15] = (ip_me >> 0) as u8;

    px[offset_ip + 16] = (ip_them >> 24) as u8;
    px[offset_ip + 17] = (ip_them >> 16) as u8;
    px[offset_ip + 18] = (ip_them >> 8) as u8;
    px[offset_ip + 19] = (ip_them >> 0) as u8;

    // IP checksum
    let old_len = ((tmpl.ipv4.packet[offset_ip + 2] as u32) << 8)
        | tmpl.ipv4.packet[offset_ip + 3] as u32;

    let mut xsum: u64 = tmpl.ipv4.checksum_ip as u64
        + (ip_id & 0xFFFF) as u64
        + ip_me as u64
        + ip_them as u64
        + (ip_len as u64).wrapping_sub(old_len as u64);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = !xsum;

    px[offset_ip + 10] = (xsum >> 8) as u8;
    px[offset_ip + 11] = (xsum & 0xFF) as u8;

    // TCP fields
    px[offset_tcp + 0] = (port_me >> 8) as u8;
    px[offset_tcp + 1] = (port_me & 0xFF) as u8;
    px[offset_tcp + 2] = (port_them >> 8) as u8;
    px[offset_tcp + 3] = (port_them & 0xFF) as u8;
    px[offset_tcp + 4] = (seqno >> 24) as u8;
    px[offset_tcp + 5] = (seqno >> 16) as u8;
    px[offset_tcp + 6] = (seqno >> 8) as u8;
    px[offset_tcp + 7] = (seqno >> 0) as u8;

    px[offset_tcp + 8] = (ackno >> 24) as u8;
    px[offset_tcp + 9] = (ackno >> 16) as u8;
    px[offset_tcp + 10] = (ackno >> 8) as u8;
    px[offset_tcp + 11] = (ackno >> 0) as u8;

    px[offset_tcp + 13] = flags;
    px[offset_tcp + 14] = (1200u16 >> 8) as u8; // window = 1200
    px[offset_tcp + 15] = (1200u16 & 0xFF) as u8;
    px[offset_tcp + 16] = 0;
    px[offset_tcp + 17] = 0;

    // TCP checksum
    let tcp_len = new_length - offset_tcp;
    let xsum = tcp_checksum_ipv4(px, offset_ip, offset_tcp, tcp_len);
    let xsum = !xsum;

    px[offset_tcp + 16] = (xsum >> 8) as u8;
    px[offset_tcp + 17] = (xsum & 0xFF) as u8;

    // Pad to minimum 60 bytes
    if new_length < 60 {
        for i in new_length..60 {
            if i < px.len() {
                px[i] = 0;
            }
        }
        return 60;
    }

    new_length
}

fn tcp_create_packet_ipv6(
    tmpl: &TemplatePacket,
    ip_them: Ipv6Address,
    port_them: u16,
    ip_me: Ipv6Address,
    port_me: u16,
    seqno: u32,
    ackno: u32,
    flags: u8,
    payload: &[u8],
    px: &mut [u8],
) -> usize {
    let offset_ip = tmpl.ipv6.offset_ip;
    let offset_tcp = tmpl.ipv6.offset_tcp;
    let offset_app = tmpl.ipv6.offset_app;

    if offset_app + payload.len() > px.len() {
        log::error!("tcp_create_packet_ipv6: payload too large");
        return 0;
    }

    // Copy template up to app payload
    let copy_len = std::cmp::min(px.len(), offset_app);
    px[..copy_len].copy_from_slice(&tmpl.ipv6.packet[..copy_len]);
    px[offset_app..offset_app + payload.len()].copy_from_slice(payload);

    // IPv6 payload length
    let total = offset_app + payload.len();
    let payload_len = total - offset_ip - 40;
    px[offset_ip + 4] = (payload_len >> 8) as u8;
    px[offset_ip + 5] = (payload_len & 0xFF) as u8;

    // Source IPv6
    let src = ip_me.to_bytes();
    px[offset_ip + 8..offset_ip + 24].copy_from_slice(&src);

    // Destination IPv6
    let dst = ip_them.to_bytes();
    px[offset_ip + 24..offset_ip + 40].copy_from_slice(&dst);

    // TCP fields
    px[offset_tcp + 0] = (port_me >> 8) as u8;
    px[offset_tcp + 1] = (port_me & 0xFF) as u8;
    px[offset_tcp + 2] = (port_them >> 8) as u8;
    px[offset_tcp + 3] = (port_them & 0xFF) as u8;
    px[offset_tcp + 4] = (seqno >> 24) as u8;
    px[offset_tcp + 5] = (seqno >> 16) as u8;
    px[offset_tcp + 6] = (seqno >> 8) as u8;
    px[offset_tcp + 7] = (seqno >> 0) as u8;

    px[offset_tcp + 8] = (ackno >> 24) as u8;
    px[offset_tcp + 9] = (ackno >> 16) as u8;
    px[offset_tcp + 10] = (ackno >> 8) as u8;
    px[offset_tcp + 11] = (ackno >> 0) as u8;

    px[offset_tcp + 13] = flags;
    px[offset_tcp + 14] = (1200u16 >> 8) as u8;
    px[offset_tcp + 15] = (1200u16 & 0xFF) as u8;
    px[offset_tcp + 16] = 0;
    px[offset_tcp + 17] = 0;

    // TCP checksum
    let tcp_len = total - offset_tcp;
    let xsum = checksum_ipv6(
        &px[offset_ip + 8..offset_ip + 24],
        &px[offset_ip + 24..offset_ip + 40],
        6,
        tcp_len,
        &px[offset_tcp..offset_tcp + tcp_len],
    );
    let xsum = !xsum;

    px[offset_tcp + 16] = (xsum >> 8) as u8;
    px[offset_tcp + 17] = (xsum & 0xFF) as u8;

    total
}

// -----------------------------------------------------------------------
// Utility functions
// -----------------------------------------------------------------------

/// Set the TCP window field in an existing packet.
///
/// Used to cause the recipient to fragment data on the response,
/// evading IDS that triggers on outgoing packets.
pub fn tcp_set_window(px: &mut [u8], window: u16) {
    // Find TCP header (assume Ethernet framing)
    let parsed = match parse_packet(px, DLT_ETHERNET) {
        Some(p) if p.found == ParsedType::Tcp => p,
        _ => return,
    };

    let offset = parsed.transport_offset;
    if offset + 20 > px.len() {
        return;
    }

    // Set window field
    px[offset + 14] = (window >> 8) as u8;
    px[offset + 15] = (window & 0xFF) as u8;

    // Zero checksum for recalculation
    px[offset + 16] = 0;
    px[offset + 17] = 0;

    // Recalculate TCP checksum
    let tcp_length = parsed.app_offset - offset + (px.len() - parsed.app_offset);
    let xsum = tcp_checksum_ipv4(px, parsed.ip_offset, offset, tcp_length);
    let xsum = !xsum;

    px[offset + 16] = (xsum >> 8) as u8;
    px[offset + 17] = (xsum & 0xFF) as u8;
}

/// Overwrite the TTL field in all templates.
pub fn template_set_ttl(set: &mut TemplateSet, ttl: u8) {
    for tmpl in &mut set.templates {
        let offset = tmpl.ipv4.offset_ip;
        if offset + 9 < tmpl.ipv4.packet.len() {
            tmpl.ipv4.packet[offset + 8] = ttl;
        }
        tmpl.ipv4.checksum_ip =
            ip_header_checksum(&tmpl.ipv4.packet, tmpl.ipv4.offset_ip, tmpl.ipv4.length) as u32;
    }
}

/// Insert a VLAN tag into all templates.
pub fn template_set_vlan(set: &mut TemplateSet, vlan: u16) {
    for tmpl in &mut set.templates {
        if tmpl.ipv4.length < 14 {
            continue;
        }

        let old = tmpl.ipv4.packet.clone();
        let mut new_pkt = vec![0u8; tmpl.ipv4.length + 4];

        // Copy first 12 bytes (MAC addresses)
        new_pkt[..12].copy_from_slice(&old[..12]);

        // Insert VLAN tag
        new_pkt[12] = 0x81;
        new_pkt[13] = 0x00;
        new_pkt[14] = (vlan >> 8) as u8;
        new_pkt[15] = (vlan & 0xFF) as u8;

        // Copy rest of packet
        new_pkt[16..].copy_from_slice(&old[12..tmpl.ipv4.length]);

        tmpl.ipv4.packet = new_pkt;
        tmpl.ipv4.length += 4;
        tmpl.ipv4.offset_ip += 4;
        tmpl.ipv4.offset_tcp += 4;
        tmpl.ipv4.offset_app += 4;
    }
}

/// Deep-copy a template set.
pub fn template_copy(set: &TemplateSet) -> TemplateSet {
    TemplateSet {
        templates: set.templates.clone(),
        entropy: set.entropy,
        udp_payloads: None, // PayloadsUdp is not Clone by design
        oproto_payloads: None,
    }
}

// -----------------------------------------------------------------------
// Self-test
// -----------------------------------------------------------------------

/// Run the self-test for the template module.
pub fn selftest() -> bool {
    use super::opts::TemplateOptions;

    let opts = TemplateOptions::default();
    let source_mac = MacAddress { addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55] };
    let router_mac = MacAddress { addr: [0x66, 0x55, 0x44, 0x33, 0x22, 0x11] };

    let set = template_packet_init(
        source_mac,
        router_mac,
        router_mac,
        None,
        None,
        DLT_ETHERNET,
        0,
        &opts,
    );

    let mut failures = 0;

    // Verify templates were created
    for tmpl in &set.templates {
        if tmpl.ipv4.packet.is_empty() {
            failures += 1;
        }
        if tmpl.ipv6.packet.is_empty() && tmpl.proto != TemplateProtocol::Arp {
            failures += 1;
        }
    }

    // Verify protocol assignments
    let has_tcp = set.templates.iter().any(|t| t.proto == TemplateProtocol::Tcp);
    let has_udp = set.templates.iter().any(|t| t.proto == TemplateProtocol::Udp);
    let has_icmp = set.templates.iter().any(|t| t.proto == TemplateProtocol::IcmpPing);

    if !has_tcp || !has_udp || !has_icmp {
        failures += 1;
    }

    // Test target setting for TCP
    let mut px = vec![0u8; 2048];
    let len = template_set_target_ipv4(
        &set,
        0x0A000001, // 10.0.0.1
        crate::massip::port::TEMPL_TCP + 80,
        0xC0A80001, // 192.168.0.1
        12345,
        0x12345678,
        &mut px,
    );

    if len == 0 {
        failures += 1;
    } else {
        // Verify Ethernet addresses
        if px[0..6] != router_mac.addr {
            failures += 1;
        }
        if px[6..12] != source_mac.addr {
            failures += 1;
        }
    }

    if failures > 0 {
        log::error!("template selftest: {} failures", failures);
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::templ::opts::TemplateOptions;

    #[test]
    fn test_selftest() {
        assert!(selftest(), "Template selftest failed");
    }

    #[test]
    fn test_ip_checksum() {
        // Minimal IPv4 header with zero checksum field
        let mut hdr = [
            0x45, 0x00, 0x00, 0x3c, // ver/ihl, tos, total len
            0x1c, 0x46, 0x40, 0x00, // id, flags/frag
            0x40, 0x06, 0x00, 0x00, // ttl, proto=TCP, checksum=0
            0xac, 0x10, 0x0a, 0x63, // src ip
            0xac, 0x10, 0x0c, 0x33, // dst ip
        ];

        let xsum = ip_header_checksum(&hdr, 0, 20);
        let xsum = !xsum as u16;
        hdr[10] = (xsum >> 8) as u8;
        hdr[11] = (xsum & 0xFF) as u8;

        // Verify: recomputing should give zero
        let verify = ip_header_checksum(&hdr, 0, 20);
        assert_eq!((!verify as u16), 0);
    }

    #[test]
    fn test_parse_ethernet_ipv4_tcp() {
        let tmpl = DEFAULT_TCP_TEMPLATE;
        let parsed = parse_packet(tmpl, DLT_ETHERNET).expect("should parse");
        assert_eq!(parsed.ip_version, 4);
        assert_eq!(parsed.ip_protocol, 6); // TCP
        assert_eq!(parsed.ip_offset, 14);
        assert_eq!(parsed.transport_offset, 34); // 14 + 20
        assert_eq!(parsed.found, ParsedType::Tcp);
    }

    #[test]
    fn test_parse_ethernet_arp() {
        let tmpl = DEFAULT_ARP_TEMPLATE;
        let parsed = parse_packet(tmpl, DLT_ETHERNET).expect("should parse");
        assert_eq!(parsed.found, ParsedType::Arp);
    }

    #[test]
    fn test_template_init_tcp() {
        let opts = TemplateOptions::default();
        let src = MacAddress { addr: [0; 6] };
        let rtr = MacAddress { addr: [0xFF; 6] };

        let set = template_packet_init(src, rtr, rtr, None, None, DLT_ETHERNET, 0, &opts);

        let tcp_tmpl = set.templates.iter().find(|t| t.proto == TemplateProtocol::Tcp);
        assert!(tcp_tmpl.is_some());

        let tcp = tcp_tmpl.unwrap();
        assert!(!tcp.ipv4.packet.is_empty());
        assert!(!tcp.ipv6.packet.is_empty());
        assert_eq!(tcp.ipv4.offset_ip, 14);
        assert_eq!(tcp.ipv4.offset_tcp, 34);
    }

    #[test]
    fn test_template_set_target_ipv4_tcp() {
        let opts = TemplateOptions::default();
        let src = MacAddress { addr: [0xAA; 6] };
        let rtr = MacAddress { addr: [0xBB; 6] };

        let set = template_packet_init(src, rtr, rtr, None, None, DLT_ETHERNET, 0, &opts);

        let mut px = vec![0u8; 2048];
        let len = template_set_target_ipv4(
            &set,
            0x01020304,
            crate::massip::port::TEMPL_TCP + 80,
            0x0A0B0C0D,
            54321,
            0xDEADBEEF,
            &mut px,
        );

        assert!(len > 0);
        // Check destination IP was set correctly
        assert_eq!(px[30], 0x01); // offset_ip(14) + 16
        assert_eq!(px[31], 0x02);
        assert_eq!(px[32], 0x03);
        assert_eq!(px[33], 0x04);
    }
}
