//! IPv6 Neighbor Discovery Protocol (NDP) handling.
//!
//! This module serves two purposes:
//!
//! 1. **Synchronous router resolution** at startup: send a Router
//!    Solicitation and parse the Router Advertisement to discover the
//!    router's MAC address.
//! 2. **Asynchronous Neighbor Advertisement replies** during scanning:
//!    respond to Neighbor Solicitation requests so the router can
//!    deliver response packets to us.
//!
//! Converted from `c-src/stack-ndpv6.h` and `c-src/stack-ndpv6.c`.

use crate::massip::addr::{Ipv6Address, MacAddress, IpAddress};
use crate::rawsock::adapter::Adapter;
use crate::proto::preprocess::PreprocessedInfo;
use super::ifmod;
use super::queue::Stack;

// ---------------------------------------------------------------------------
// Helper: safe buffer append functions (mirror the C _append* helpers)
// ---------------------------------------------------------------------------

fn append_byte(buf: &mut [u8], offset: &mut usize, val: u8) {
    if *offset < buf.len() {
        buf[*offset] = val;
        *offset += 1;
    }
}

fn append_bytes(buf: &mut [u8], offset: &mut usize, data: &[u8]) {
    let end = *offset + data.len();
    if end <= buf.len() {
        buf[*offset..end].copy_from_slice(data);
        *offset = end;
    } else {
        *offset = buf.len();
    }
}

fn append_short(buf: &mut [u8], offset: &mut usize, val: u16) {
    append_byte(buf, offset, (val >> 8) as u8);
    append_byte(buf, offset, (val & 0xFF) as u8);
}

fn read_byte(buf: &[u8], offset: &mut usize) -> Option<u8> {
    if *offset < buf.len() {
        let val = buf[*offset];
        *offset += 1;
        Some(val)
    } else {
        None
    }
}

fn read_short(buf: &[u8], offset: &mut usize) -> Option<u16> {
    let hi = read_byte(buf, offset)? as u16;
    let lo = read_byte(buf, offset)? as u16;
    Some((hi << 8) | lo)
}

fn read_u32(buf: &[u8], offset: &mut usize) -> Option<u32> {
    let b0 = read_byte(buf, offset)? as u32;
    let b1 = read_byte(buf, offset)? as u32;
    let b2 = read_byte(buf, offset)? as u32;
    let b3 = read_byte(buf, offset)? as u32;
    Some((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
}

fn read_ipv6(buf: &[u8], offset: &mut usize) -> Option<Ipv6Address> {
    if *offset + 16 > buf.len() {
        *offset = buf.len();
        return None;
    }
    let addr = Ipv6Address::from_bytes(&buf[*offset..*offset + 16]);
    *offset += 16;
    Some(addr)
}

// ---------------------------------------------------------------------------
// Checksum (stub - delegates to proto::checksum when available)
// ---------------------------------------------------------------------------

/// Compute ICMPv6 checksum.
///
/// Uses the standard IPv6 pseudo-header checksum algorithm. This is a
/// placeholder that will be replaced when `proto::checksum` is fully
/// implemented.
fn checksum_ipv6(
    src_ip: &[u8],
    dst_ip: &[u8],
    next_header: u8,
    payload_len: usize,
    payload: &[u8],
) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: source IPv6 address.
    for chunk in src_ip.chunks(2) {
        if chunk.len() == 2 {
            sum += ((chunk[0] as u32) << 8) | (chunk[1] as u32);
        }
    }

    // Pseudo-header: destination IPv6 address.
    for chunk in dst_ip.chunks(2) {
        if chunk.len() == 2 {
            sum += ((chunk[0] as u32) << 8) | (chunk[1] as u32);
        }
    }

    // Pseudo-header: upper-layer packet length.
    sum += payload_len as u32;

    // Pseudo-header: next header.
    sum += next_header as u32;

    // ICMPv6 payload.
    let payload_slice = &payload[..payload_len.min(payload.len())];
    for chunk in payload_slice.chunks(2) {
        if chunk.len() == 2 {
            sum += ((chunk[0] as u32) << 8) | (chunk[1] as u32);
        } else {
            sum += (chunk[0] as u32) << 8;
        }
    }

    // Fold carries.
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Handle an incoming IPv6 Neighbor Solicitation request.
///
/// When we have transmitted packets with a spoofed source IPv6 address,
/// the router will send us a Neighbor Solicitation to verify our MAC.
/// We must reply with a Neighbor Advertisement containing our MAC.
pub fn incoming_request(
    stack: &Stack,
    parsed: &PreprocessedInfo,
    px: &[u8],
    length: usize,
) -> Result<(), &'static str> {
    // Verify it's a Neighbor Solicitation (ICMPv6 type 135).
    if parsed.opcode != 135 {
        return Err("not a Neighbor Solicitation");
    }

    let offset_ip = parsed.ip_offset as usize;
    let offset_ip_src = offset_ip + 8;
    let offset_ip_dst = offset_ip + 24;
    let offset_icmpv6 = parsed.transport_offset as usize;

    // Need at least 24 bytes of ICMPv6 payload.
    if length < offset_icmpv6 + 24 {
        return Err("packet too short");
    }

    // Extract the target IPv6 address from the solicitation.
    let target_ip_bytes = &px[offset_icmpv6 + 8..offset_icmpv6 + 24];
    let target_ip = Ipv6Address::from_bytes(target_ip_bytes);

    // Verify this is one of our addresses.
    if !stack.src.is_my_ip(IpAddress::V6(target_ip)) {
        return Err("not our address");
    }

    log::info!(
        "[+] received NDP request for {}",
        target_ip
    );

    // Get a packet buffer.
    let mut response = stack.get_packet_buffer().ok_or("no packet buffer")?;
    let max = response.px.len();

    // Start by copying the incoming packet as a template.
    let copy_len = length.min(max);
    response.px[..copy_len].copy_from_slice(&px[..copy_len]);

    let buf = &mut response.px;
    let mut offset: usize = offset_icmpv6;

    // Swap destination/source MACs.
    buf[0..6].copy_from_slice(&px[6..12]);
    buf[6..12].copy_from_slice(&stack.source_mac.addr);

    // Swap source/destination IPv6 addresses.
    buf[offset_ip_src..offset_ip_src + 16]
        .copy_from_slice(&px[offset_ip_dst..offset_ip_dst + 16]);
    buf[offset_ip_dst..offset_ip_dst + 16]
        .copy_from_slice(&px[offset_ip_src..offset_ip_src + 16]);

    // Format Neighbor Advertisement.
    append_byte(buf, &mut offset, 136); // type = Neighbor Advertisement
    append_byte(buf, &mut offset, 0);   // code
    append_byte(buf, &mut offset, 0);   // checksum hi (filled later)
    append_byte(buf, &mut offset, 0);   // checksum lo (filled later)
    append_byte(buf, &mut offset, 0x60); // flags: Solicited + Override
    append_byte(buf, &mut offset, 0);
    append_byte(buf, &mut offset, 0);
    append_byte(buf, &mut offset, 0);
    append_bytes(buf, &mut offset, target_ip_bytes); // target address
    append_byte(buf, &mut offset, 2);   // option: target link-layer address
    append_byte(buf, &mut offset, 1);   // length = 8 bytes (1 unit)
    append_bytes(buf, &mut offset, &stack.source_mac.addr);

    // Compute and fill in the ICMPv6 checksum.
    let xsum = checksum_ipv6(
        &buf[offset_ip_src..offset_ip_src + 16],
        &buf[offset_ip_dst..offset_ip_dst + 16],
        58, // ICMPv6
        offset - offset_icmpv6,
        &buf[offset_icmpv6..],
    );
    buf[offset_icmpv6 + 2] = (xsum >> 8) as u8;
    buf[offset_icmpv6 + 3] = (xsum & 0xFF) as u8;

    response.length = offset;
    stack.transmit_packet_buffer(response);
    Ok(())
}

/// Extract router information from a Router Advertisement.
///
/// Parses the RA to find the router's MAC address and verify the
/// advertised prefix matches our source IPv6 address.
fn extract_router_advertisement(
    buf: &[u8],
    length: usize,
    parsed: &PreprocessedInfo,
    my_ipv6: Ipv6Address,
) -> Option<(Ipv6Address, MacAddress)> {
    if parsed.ip_version != 6 || parsed.ip_protocol != 58 {
        return None;
    }

    let mut offset = parsed.transport_offset as usize;
    let router_ip = parsed.src_ip;

    // type = Router Advertisement (134)
    if read_byte(buf, &mut offset)? != 134 {
        return None;
    }
    // code = 0
    if read_byte(buf, &mut offset)? != 0 {
        return None;
    }
    // checksum
    read_short(buf, &mut offset)?;
    // hop limit
    read_byte(buf, &mut offset)?;
    // flags
    read_byte(buf, &mut offset)?;
    // router lifetime
    read_short(buf, &mut offset)?;
    // reachable time
    read_u32(buf, &mut offset)?;
    // retrans timer
    read_u32(buf, &mut offset)?;

    let mut router_mac = MacAddress::default();
    let mut is_mac_explicit = false;
    let mut is_same_prefix = true;

    // Parse options.
    while offset + 8 <= length {
        let opt_type = buf[offset];
        let opt_len = (buf[offset + 1] as usize) * 8;
        if opt_len == 0 || offset + opt_len > length {
            break;
        }

        let mut off2 = offset + 2;
        let opt_end = offset + opt_len;

        match opt_type {
            3 => {
                // Prefix Information option.
                let prefix_len = read_byte(buf, &mut off2).unwrap_or(0) as u32;
                read_byte(buf, &mut off2); // flags
                read_u32(buf, &mut off2); // valid lifetime
                read_u32(buf, &mut off2); // preferred lifetime
                read_u32(buf, &mut off2); // reserved
                if let Some(prefix) = read_ipv6(buf, &mut off2) {
                    log::info!("[+] IPv6.prefix = {}/{}", prefix, prefix_len);
                    if !my_ipv6.is_equal_prefixed(prefix, prefix_len) {
                        log::warn!(
                            "[-] WARNING: our source-ip is {}, but router prefix announces {}/{}",
                            my_ipv6, prefix, prefix_len
                        );
                        is_same_prefix = false;
                    }
                }
            }
            25 => {
                // Recursive DNS Server option.
                read_short(buf, &mut off2); // reserved
                read_u32(buf, &mut off2);   // lifetime
                while off2 + 16 <= opt_end {
                    if let Some(resolver) = read_ipv6(buf, &mut off2) {
                        log::info!("[+] IPv6.DNS = {}", resolver);
                    }
                }
            }
            1 => {
                // Source Link-Layer Address option.
                if opt_len == 8 {
                    router_mac = MacAddress::new(
                        buf[offset + 2..offset + 8].try_into().unwrap(),
                    );
                    is_mac_explicit = true;
                }
            }
            _ => {}
        }

        offset += opt_len;
    }

    if !is_mac_explicit {
        // Fall back to the Ethernet source MAC from the packet.
        router_mac = MacAddress::new(parsed.mac_src);
    }

    if !is_same_prefix {
        return None;
    }

    let router_ipv6 = match router_ip {
        IpAddress::V6(v6) => v6,
        _ => return None,
    };

    Some((router_ipv6, router_mac))
}

/// Resolve the local router's MAC address via IPv6 Router Solicitation.
///
/// Sends a Router Solicitation and waits for a Router Advertisement
/// response. This is synchronous and used at startup only.
///
/// Returns the router's MAC address on success.
pub fn resolve(
    adapter: &Adapter,
    my_ipv6: Ipv6Address,
    my_mac: MacAddress,
) -> Result<MacAddress, &'static str> {
    // VPN/tunnel links don't use NDP.
    if ifmod::is_vpn_link(adapter) {
        return Ok(MacAddress::new([0, 0, 0, 0, 0, 2]));
    }

    let mut buf = [0u8; 128];
    let max = buf.len();
    let mut offset: usize = 0;

    // Ethernet header: all-routers multicast MAC.
    append_bytes(&mut buf, &mut offset, &[0x33, 0x33, 0x00, 0x00, 0x00, 0x02]);
    append_bytes(&mut buf, &mut offset, &my_mac.addr);

    if adapter.is_vlan {
        append_short(&mut buf, &mut offset, 0x8100);
        append_short(&mut buf, &mut offset, adapter.vlan_id as u16);
    }
    append_short(&mut buf, &mut offset, 0x86DD); // EtherType = IPv6

    // IPv6 header.
    let offset_ip = offset;
    append_byte(&mut buf, &mut offset, 0x60); // version = 6
    append_byte(&mut buf, &mut offset, 0);
    append_short(&mut buf, &mut offset, 0); // payload length (filled later)
    append_byte(&mut buf, &mut offset, 58); // next header = ICMPv6
    append_byte(&mut buf, &mut offset, 255); // hop limit

    // Source IPv6: link-local derived from MAC (EUI-64).
    let offset_ip_src = offset;
    append_short(&mut buf, &mut offset, 0xFE80);
    append_short(&mut buf, &mut offset, 0);
    append_short(&mut buf, &mut offset, 0);
    append_short(&mut buf, &mut offset, 0);
    append_bytes(&mut buf, &mut offset, &my_mac.addr[..3]);
    buf[offset - 3] |= 0x02; // flip universal/local bit
    append_short(&mut buf, &mut offset, 0xFFFE);
    append_bytes(&mut buf, &mut offset, &my_mac.addr[3..6]);

    // Destination IPv6: all-routers link-local (ff02::2).
    let offset_ip_dst = offset;
    append_short(&mut buf, &mut offset, 0xFF02);
    for _ in 0..6 {
        append_short(&mut buf, &mut offset, 0);
    }
    append_short(&mut buf, &mut offset, 2);

    // ICMPv6 Router Solicitation.
    let offset_icmpv6 = offset;
    append_byte(&mut buf, &mut offset, 133); // type = Router Solicitation
    append_byte(&mut buf, &mut offset, 0);   // code
    append_short(&mut buf, &mut offset, 0);   // checksum (filled later)
    append_short(&mut buf, &mut offset, 0);   // reserved
    append_short(&mut buf, &mut offset, 0);   // reserved
    append_byte(&mut buf, &mut offset, 1);    // option = source link-layer addr
    append_byte(&mut buf, &mut offset, 1);    // length = 1 unit (8 bytes)
    append_bytes(&mut buf, &mut offset, &my_mac.addr);

    // Fill in IPv6 payload length.
    let payload_len = offset - offset_icmpv6;
    buf[offset_ip + 4] = (payload_len >> 8) as u8;
    buf[offset_ip + 5] = (payload_len & 0xFF) as u8;

    // Compute ICMPv6 checksum.
    let xsum = checksum_ipv6(
        &buf[offset_ip_src..offset_ip_src + 16],
        &buf[offset_ip_dst..offset_ip_dst + 16],
        58,
        payload_len,
        &buf[offset_icmpv6..],
    );
    buf[offset_icmpv6 + 2] = (xsum >> 8) as u8;
    buf[offset_icmpv6 + 3] = (xsum & 0xFF) as u8;

    // Send the solicitation.
    adapter.send_packet(&buf[..offset]).map_err(|_| "send failed")?;

    // Also send a shorter version without the source link-layer option
    // (some routers prefer this).
    let short_offset = offset - 8;
    let short_payload_len = short_offset - offset_icmpv6;
    buf[offset_ip + 4] = (short_payload_len >> 8) as u8;
    buf[offset_ip + 5] = (short_payload_len & 0xFF) as u8;
    let xsum2 = checksum_ipv6(
        &buf[offset_ip_src..offset_ip_src + 16],
        &buf[offset_ip_dst..offset_ip_dst + 16],
        58,
        short_payload_len,
        &buf[offset_icmpv6..],
    );
    buf[offset_icmpv6 + 2] = (xsum2 >> 8) as u8;
    buf[offset_icmpv6 + 3] = (xsum2 & 0xFF) as u8;
    adapter.send_packet(&buf[..short_offset]).ok();

    // Wait for a Router Advertisement response.
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(10);
    let mut recv_buf = [0u8; 2048];
    let mut attempts: u32 = 0;

    loop {
        if start.elapsed() >= timeout || attempts > 10 {
            return Err("NDP resolution timed out");
        }

        // Retransmit once per second.
        if start.elapsed().as_secs() > attempts as u64 {
            attempts += 1;
            adapter.send_packet(&buf[..short_offset]).ok();
        }

        let recv_result = match adapter.recv_packet(&mut recv_buf) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let pkt_len = recv_result.data.len();
        let pkt = recv_result.data;

        // Basic validation: must be an IPv6 packet with ICMPv6.
        if pkt_len < 54 {
            continue;
        }
        // Check EtherType for IPv6 (0x86DD).
        let ether_offset = if adapter.is_vlan { 16 } else { 12 };
        if pkt_len < ether_offset + 2 {
            continue;
        }
        if pkt[ether_offset] != 0x86 || pkt[ether_offset + 1] != 0xDD {
            continue;
        }

        let ip_offset = ether_offset + 2;
        if pkt_len < ip_offset + 40 {
            continue;
        }

        // Check for Router Advertisement (type 134).
        let icmp_offset = ip_offset + 40;
        if pkt_len < icmp_offset + 1 {
            continue;
        }
        if pkt[icmp_offset] != 134 {
            continue;
        }

        // Build a minimal PreprocessedInfo for extraction.
        let parsed = PreprocessedInfo {
            ip_version: 6,
            ip_protocol: 58,
            ip_offset: ip_offset as u32,
            transport_offset: icmp_offset as u32,
            src_ip: IpAddress::V6(
                Ipv6Address::from_bytes(&pkt[ip_offset + 8..ip_offset + 24]),
            ),
            mac_src: pkt[6..12].try_into().unwrap(),
            opcode: 134,
            ..Default::default()
        };

        if let Some((_router_ip, router_mac)) =
            extract_router_advertisement(pkt, pkt_len, &parsed, my_ipv6)
        {
            log::info!("[+] NDP: router MAC = {}", router_mac);
            return Ok(router_mac);
        }
    }
}
