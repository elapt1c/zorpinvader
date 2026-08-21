//! Packet trace logging for debugging (--packet-trace option).
//!
//! This module provides human-readable packet logging similar to tcpdump,
//! showing direction (sent/received), protocol, addresses, and flags.

use std::io::Write;

use crate::pixie::timer::gettime;
use crate::massip::addr::{IpAddress, Ipv6Address, ipv4address_fmt, ipv6address_fmt};

/// Protocol types found in packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoundProto {
    None,
    Arp,
    Tcp,
    Udp,
    Icmp,
    Dns,
    Ipv6,
}

/// Parsed information about a network packet.
#[derive(Debug, Clone)]
pub struct PacketInfo {
    /// Source IP address
    pub src_ip: IpAddress,

    /// Destination IP address
    pub dst_ip: IpAddress,

    /// Source port
    pub port_src: u16,

    /// Destination port
    pub port_dst: u16,

    /// Protocol type
    pub proto: FoundProto,

    /// Offset to payload data
    pub payload_offset: usize,

    /// Length of application payload
    pub payload_length: usize,

    /// TCP flags (for TCP packets)
    pub tcp_flags: u8,

    /// ARP type (for ARP packets)
    pub arp_type: u16,
}

impl Default for PacketInfo {
    fn default() -> Self {
        Self {
            src_ip: IpAddress::V4(0),
            dst_ip: IpAddress::V4(0),
            port_src: 0,
            port_dst: 0,
            proto: FoundProto::None,
            payload_offset: 0,
            payload_length: 0,
            tcp_flags: 0,
            arp_type: 0,
        }
    }
}

/// Write a packet trace line to the given output.
///
/// # Arguments
///
/// * `out` - Output stream to write to
/// * `pt_start` - Start time for relative timestamps (seconds)
/// * `px` - Raw packet bytes
/// * `length` - Length of packet data
/// * `is_sent` - True if this is an outgoing packet
/// * `info` - Pre-parsed packet information
pub fn packet_trace<W: Write>(
    out: &mut W,
    pt_start: f64,
    _px: &[u8],
    _length: usize,
    is_sent: bool,
    info: &PacketInfo,
) {
    let timestamp = gettime() as f64 / 1_000_000.0;
    let direction = if is_sent { "SENT" } else { "RCVD" };

    let from = format_address(info.src_ip, info.port_src);
    let to = format_address(info.dst_ip, info.port_dst);

    match info.proto {
        FoundProto::Arp => {
            let type_str = match info.arp_type {
                1 => "request",
                2 => "response",
                _ => "unknown",
            };
            let _ = writeln!(
                out,
                "{} ({:5.4}) ARP  {:21} > {:21} {}",
                direction,
                timestamp - pt_start,
                from,
                to,
                type_str
            );
        }

        FoundProto::Udp | FoundProto::Dns => {
            let _ = writeln!(
                out,
                "{} ({:5.4}) UDP  {:21} > {:21}",
                direction,
                timestamp - pt_start,
                from,
                to
            );
        }

        FoundProto::Icmp => {
            let _ = writeln!(
                out,
                "{} ({:5.4}) ICMP {:21} > {:21}",
                direction,
                timestamp - pt_start,
                from,
                to
            );
        }

        FoundProto::Tcp => {
            let flags_str = format_tcp_flags(info.tcp_flags);
            if info.payload_length > 0 {
                let _ = writeln!(
                    out,
                    "{} ({:5.4}) TCP  {:21} > {:21} {} {}-bytes",
                    direction,
                    timestamp - pt_start,
                    from,
                    to,
                    flags_str,
                    info.payload_length
                );
            } else {
                let _ = writeln!(
                    out,
                    "{} ({:5.4}) TCP  {:21} > {:21} {}",
                    direction,
                    timestamp - pt_start,
                    from,
                    to,
                    flags_str
                );
            }
        }

        FoundProto::Ipv6 => {
            // IPv6 encapsulation - could be expanded
        }

        FoundProto::None => {
            let _ = writeln!(
                out,
                "{} ({:5.4}) UNK  {:21} > {:21}",
                direction,
                timestamp - pt_start,
                from,
                to
            );
        }
    }
}

/// Format an IP address with port for display.
fn format_address(ip: IpAddress, port: u16) -> String {
    match ip {
        IpAddress::V4(v4) => format!("[{}]:{}", ipv4address_fmt(v4), port),
        IpAddress::V6(v6) => format!("[{}]:{}", ipv6address_fmt(v6), port),
    }
}

/// Convert TCP flags byte to human-readable string.
fn format_tcp_flags(flags: u8) -> String {
    // Check for common flag combinations first
    match flags {
        0x00 => return "NULL".to_string(),
        0x01 => return "FIN".to_string(),
        0x02 => return "SYN".to_string(),
        0x04 => return "RST".to_string(),
        0x08 => return "PSH".to_string(),
        0x10 => return "ACK".to_string(),
        0x11 => return "FIN-ACK".to_string(),
        0x12 => return "SYN-ACK".to_string(),
        0x14 => return "RST-ACK".to_string(),
        0x15 => return "RST-FIN-ACK".to_string(),
        0x18 => return "ACK-PSH".to_string(),
        0x19 => return "FIN-ACK-PSH".to_string(),
        _ => {}
    }

    // Build string from individual flags
    let mut result = String::new();
    if flags & 0x01 != 0 {
        result.push_str("FIN");
    }
    if flags & 0x02 != 0 {
        result.push_str("SYN");
    }
    if flags & 0x04 != 0 {
        result.push_str("RST");
    }
    if flags & 0x08 != 0 {
        result.push_str("PSH");
    }
    if flags & 0x10 != 0 {
        result.push_str("ACK");
    }
    if flags & 0x20 != 0 {
        result.push_str("URG");
    }
    if flags & 0x40 != 0 {
        result.push_str("ECE");
    }
    if flags & 0x80 != 0 {
        result.push_str("CWR");
    }

    if result.is_empty() {
        "NONE".to_string()
    } else {
        result
    }
}

/// Simple packet preprocessor to extract basic packet info.
///
/// This is a simplified version that handles common cases.
/// For full parsing, see the proto module.
pub fn preprocess_packet(px: &[u8], length: usize) -> Option<PacketInfo> {
    if length < 14 {
        return None;
    }

    // Ethernet header
    let ethertype = ((px[12] as u16) << 8) | (px[13] as u16);

    let mut info = PacketInfo::default();
    info.payload_offset = 14;

    match ethertype {
        0x0806 => {
            // ARP
            if length < 14 + 28 {
                return None;
            }
            info.proto = FoundProto::Arp;
            info.arp_type = ((px[20] as u16) << 8) | (px[21] as u16);
            // Extract sender/target IPs (simplified)
            let sender_ip = ((px[28] as u32) << 24)
                | ((px[29] as u32) << 16)
                | ((px[30] as u32) << 8)
                | (px[31] as u32);
            let target_ip = ((px[38] as u32) << 24)
                | ((px[39] as u32) << 16)
                | ((px[40] as u32) << 8)
                | (px[41] as u32);
            info.src_ip = IpAddress::V4(sender_ip);
            info.dst_ip = IpAddress::V4(target_ip);
        }

        0x0800 => {
            // IPv4
            if length < 14 + 20 {
                return None;
            }
            let ihl = ((px[14] & 0x0F) as usize) * 4;
            let protocol = px[23];

            let src_ip = ((px[26] as u32) << 24)
                | ((px[27] as u32) << 16)
                | ((px[28] as u32) << 8)
                | (px[29] as u32);
            let dst_ip = ((px[30] as u32) << 24)
                | ((px[31] as u32) << 16)
                | ((px[32] as u32) << 8)
                | (px[33] as u32);

            info.src_ip = IpAddress::V4(src_ip);
            info.dst_ip = IpAddress::V4(dst_ip);

            let transport_offset = 14 + ihl;

            match protocol {
                6 => {
                    // TCP
                    if length < transport_offset + 20 {
                        return None;
                    }
                    info.proto = FoundProto::Tcp;
                    info.port_src = ((px[transport_offset] as u16) << 8)
                        | (px[transport_offset + 1] as u16);
                    info.port_dst = ((px[transport_offset + 2] as u16) << 8)
                        | (px[transport_offset + 3] as u16);
                    let data_offset = ((px[transport_offset + 12] >> 4) as usize) * 4;
                    info.tcp_flags = px[transport_offset + 13];
                    info.payload_offset = transport_offset + data_offset;
                    if length > info.payload_offset {
                        info.payload_length = length - info.payload_offset;
                    }
                }

                17 => {
                    // UDP
                    if length < transport_offset + 8 {
                        return None;
                    }
                    info.proto = FoundProto::Udp;
                    info.port_src = ((px[transport_offset] as u16) << 8)
                        | (px[transport_offset + 1] as u16);
                    info.port_dst = ((px[transport_offset + 2] as u16) << 8)
                        | (px[transport_offset + 3] as u16);
                    info.payload_offset = transport_offset + 8;
                    if length > info.payload_offset {
                        info.payload_length = length - info.payload_offset;
                    }
                }

                1 => {
                    // ICMP
                    info.proto = FoundProto::Icmp;
                    info.payload_offset = transport_offset;
                }

                _ => {}
            }
        }

        0x86DD => {
            // IPv6
            if length < 14 + 40 {
                return None;
            }
            info.proto = FoundProto::Ipv6;
            // Simplified - would need full IPv6 parsing
        }

        _ => {}
    }

    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_tcp_flags() {
        assert_eq!(format_tcp_flags(0x02), "SYN");
        assert_eq!(format_tcp_flags(0x12), "SYN-ACK");
        assert_eq!(format_tcp_flags(0x10), "ACK");
        assert_eq!(format_tcp_flags(0x01), "FIN");
    }

    #[test]
    fn test_format_address() {
        let addr = format_address(IpAddress::V4(0x0A000001), 80);
        assert_eq!(addr, "[10.0.0.1]:80");
    }
}
