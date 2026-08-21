//! ARP (Address Resolution Protocol) handling for IPv4.
//!
//! This module serves two purposes:
//!
//! 1. **Synchronous resolution** at startup: send an ARP request and wait
//!    for the response to discover the local router's MAC address.
//! 2. **Asynchronous replies** during scanning: respond to ARP requests
//!    from the router so it can route response packets back to us.
//!
//! Converted from `c-src/stack-arpv4.h` and `c-src/stack-arpv4.c`.

use crate::massip::addr::{Ipv4Address, MacAddress};
use crate::rawsock::adapter::Adapter;
use super::ifmod;
use super::queue::{Stack, PacketBuffer};

/// Parsed fields from an incoming ARP packet.
#[derive(Debug, Default)]
struct ArpIncomingRequest {
    is_valid: bool,
    opcode: u16,
    hardware_type: u16,
    protocol_type: u16,
    hardware_length: u8,
    protocol_length: u8,
    ip_src: Ipv4Address,
    ip_dst: Ipv4Address,
    mac_src_offset: usize,
    mac_dst_offset: usize,
}

/// Parse an ARP packet starting at `offset` within `px`.
///
/// Only validates that the packet has the expected structure (Ethernet
/// hardware, IPv4 protocol). Returns `None` if the packet is malformed
/// or unsupported.
fn parse_arp_request(px: &[u8], offset: usize) -> Option<ArpIncomingRequest> {
    let max = px.len();

    // Need at least 8 bytes for the ARP header.
    if offset + 8 > max {
        return None;
    }

    let hardware_type = ((px[offset] as u16) << 8) | (px[offset + 1] as u16);
    let protocol_type = ((px[offset + 2] as u16) << 8) | (px[offset + 3] as u16);
    let hardware_length = px[offset + 4];
    let protocol_length = px[offset + 5];
    let opcode = ((px[offset + 6] as u16) << 8) | (px[offset + 7] as u16);

    // We only support Ethernet (1) or IEEE 802 (6) hardware with IPv4.
    if protocol_length != 4 || hardware_length != 6 {
        return None;
    }
    if protocol_type != 0x0800 {
        return None;
    }
    if hardware_type != 1 && hardware_type != 6 {
        return None;
    }

    let addr_start = offset + 8;
    let needed = 2 * (hardware_length as usize) + 2 * (protocol_length as usize);
    if addr_start + needed > max {
        return None;
    }

    let mac_src_offset = addr_start;
    let ip_src_offset = mac_src_offset + hardware_length as usize;
    let ip_src = ((px[ip_src_offset] as u32) << 24)
        | ((px[ip_src_offset + 1] as u32) << 16)
        | ((px[ip_src_offset + 2] as u32) << 8)
        | (px[ip_src_offset + 3] as u32);

    let mac_dst_offset = ip_src_offset + protocol_length as usize;
    let ip_dst_offset = mac_dst_offset + hardware_length as usize;
    let ip_dst = ((px[ip_dst_offset] as u32) << 24)
        | ((px[ip_dst_offset + 1] as u32) << 16)
        | ((px[ip_dst_offset + 2] as u32) << 8)
        | (px[ip_dst_offset + 3] as u32);

    Some(ArpIncomingRequest {
        is_valid: true,
        opcode,
        hardware_type,
        protocol_type,
        hardware_length,
        protocol_length,
        ip_src,
        ip_dst,
        mac_src_offset,
        mac_dst_offset,
    })
}

/// Resolve an IPv4 address to a MAC address by sending ARP requests.
///
/// This is a **synchronous** operation used at startup to discover the
/// router's MAC address. It sends an ARP request, waits up to ~10 seconds
/// for a reply, and retransmits once per second.
///
/// Returns the resolved MAC address on success, or an error if the
/// resolution timed out.
pub fn resolve(
    adapter: &Adapter,
    my_ipv4: Ipv4Address,
    my_mac: MacAddress,
    your_ipv4: Ipv4Address,
) -> Result<MacAddress, &'static str> {
    // VPN/tunnel links don't use ARP; use a fake MAC.
    if ifmod::is_vpn_link(adapter) {
        return Ok(MacAddress::new([0, 0, 0, 0, 0, 2]));
    }

    // Build the ARP request packet.
    let mut arp_packet = [0u8; 64];

    // Ethernet header: broadcast destination.
    arp_packet[0..6].copy_from_slice(&[0xFF; 6]);
    arp_packet[6..12].copy_from_slice(&my_mac.addr);
    arp_packet[12..14].copy_from_slice(&[0x08, 0x06]); // EtherType = ARP

    let arp_start: usize = if adapter.is_vlan {
        // Insert VLAN tag.
        arp_packet[12] = 0x81;
        arp_packet[13] = 0x00;
        arp_packet[14] = (adapter.vlan_id >> 8) as u8;
        arp_packet[15] = (adapter.vlan_id & 0xFF) as u8;
        // Move EtherType after VLAN tag.
        arp_packet[16] = 0x08;
        arp_packet[17] = 0x06;
        18
    } else {
        14
    };

    // ARP header.
    arp_packet[arp_start..arp_start + 8].copy_from_slice(&[
        0x00, 0x01, // hardware = Ethernet
        0x08, 0x00, // protocol = IPv4
        0x06, 0x04, // MAC len = 6, IP len = 4
        0x00, 0x01, // opcode = request
    ]);

    // Sender hardware address (our MAC).
    arp_packet[arp_start + 8..arp_start + 14].copy_from_slice(&my_mac.addr);
    // Sender protocol address (our IP).
    arp_packet[arp_start + 14] = (my_ipv4 >> 24) as u8;
    arp_packet[arp_start + 15] = (my_ipv4 >> 16) as u8;
    arp_packet[arp_start + 16] = (my_ipv4 >> 8) as u8;
    arp_packet[arp_start + 17] = (my_ipv4) as u8;

    // Target hardware address (unknown = zeros).
    arp_packet[arp_start + 18..arp_start + 24].copy_from_slice(&[0u8; 6]);
    // Target protocol address.
    arp_packet[arp_start + 24] = (your_ipv4 >> 24) as u8;
    arp_packet[arp_start + 25] = (your_ipv4 >> 16) as u8;
    arp_packet[arp_start + 26] = (your_ipv4 >> 8) as u8;
    arp_packet[arp_start + 27] = (your_ipv4) as u8;

    let send_len = if adapter.is_vlan { 64 } else { 60 };
    let send_buf = &arp_packet[..send_len];

    // Send the initial request.
    adapter.send_packet(send_buf).map_err(|_| "send failed")?;

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(10);
    let mut recv_buf = [0u8; 2048];
    let mut attempts: u32 = 0;
    let mut notice_given = false;

    loop {
        if start.elapsed() >= timeout {
            return Err("ARP resolution timed out");
        }

        // Retransmit once per second, up to 10 attempts.
        if start.elapsed().as_secs() > attempts as u64 {
            attempts += 1;
            if attempts > 10 {
                return Err("ARP resolution timed out");
            }
            adapter.send_packet(send_buf).ok();

            if !notice_given && attempts > 1 {
                log::info!(
                    "[+] resolving router {}.{}.{}.{} with ARP (may take some time)...",
                    (your_ipv4 >> 24) & 0xFF,
                    (your_ipv4 >> 16) & 0xFF,
                    (your_ipv4 >> 8) & 0xFF,
                    your_ipv4 & 0xFF,
                );
                notice_given = true;
            }
        }

        // Try to receive a packet.
        let recv_result = match adapter.recv_packet(&mut recv_buf) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let length = recv_result.data.len();
        let px = recv_result.data;

        // Check for ARP reply opcode at the expected offset.
        let arp_offset = if adapter.is_vlan { 18 } else { 14 };
        if length < arp_offset + 28 {
            continue;
        }

        // Verify EtherType is ARP.
        let ether_offset = if adapter.is_vlan { 16 } else { 12 };
        if px[ether_offset] != 0x08 || px[ether_offset + 1] != 0x06 {
            continue;
        }

        let response = match parse_arp_request(px, arp_offset) {
            Some(r) => r,
            None => continue,
        };

        // Must be a reply (opcode 2).
        if response.opcode != 2 {
            continue;
        }

        // Must be addressed to us.
        if response.ip_dst != my_ipv4 {
            continue;
        }
        if px[response.mac_dst_offset..response.mac_dst_offset + 6] != my_mac.addr {
            continue;
        }

        // Must be from the target.
        if response.ip_src != your_ipv4 {
            continue;
        }

        // Success!
        let mut result_mac = [0u8; 6];
        result_mac.copy_from_slice(&px[response.mac_src_offset..response.mac_src_offset + 6]);

        log::info!(
            "[+] ARP: {}.{}.{}.{} == {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            (your_ipv4 >> 24) & 0xFF,
            (your_ipv4 >> 16) & 0xFF,
            (your_ipv4 >> 8) & 0xFF,
            your_ipv4 & 0xFF,
            result_mac[0], result_mac[1], result_mac[2],
            result_mac[3], result_mac[4], result_mac[5],
        );

        return Ok(MacAddress::new(result_mac));
    }
}

/// Handle an incoming ARP request and send a reply.
///
/// Called from the receive thread when an ARP request is detected that
/// targets one of our IP addresses. Formats an ARP reply and queues it
/// for transmission.
///
/// Returns `Ok(())` on success, or an error if the request was invalid
/// or no packet buffer was available.
pub fn incoming_request(
    stack: &Stack,
    my_ip: Ipv4Address,
    my_mac: MacAddress,
    px: &[u8],
    length: usize,
) -> Result<(), &'static str> {
    // Parse the incoming ARP request (Ethernet header is 14 bytes).
    let request = parse_arp_request(px, 14).ok_or("invalid ARP packet")?;

    // Must be a request (opcode 1).
    if request.opcode != 1 {
        return Err("not an ARP request");
    }

    // Must be asking for our IP.
    if request.ip_dst != my_ip {
        return Err("not addressed to us");
    }

    // Get a free packet buffer.
    let mut response = stack.get_packet_buffer().ok_or("no packet buffer")?;

    // ARP reply is 42 bytes, but Ethernet minimum is 60 bytes.
    response.length = 60;
    response.px[..60].fill(0);

    // Ethernet header: reply to the requester.
    response.px[0..6].copy_from_slice(&px[request.mac_src_offset..request.mac_src_offset + 6]);
    response.px[6..12].copy_from_slice(&my_mac.addr);
    response.px[12..14].copy_from_slice(&[0x08, 0x06]); // EtherType = ARP

    // ARP header.
    response.px[14..22].copy_from_slice(&[
        0x00, 0x01, // hardware = Ethernet
        0x08, 0x00, // protocol = IPv4
        0x06, 0x04, // MAC len = 6, IP len = 4
        0x00, 0x02, // opcode = reply
    ]);

    // Sender = us.
    response.px[22..28].copy_from_slice(&my_mac.addr);
    response.px[28] = (my_ip >> 24) as u8;
    response.px[29] = (my_ip >> 16) as u8;
    response.px[30] = (my_ip >> 8) as u8;
    response.px[31] = (my_ip) as u8;

    // Target = the requester.
    response.px[32..38].copy_from_slice(&px[request.mac_src_offset..request.mac_src_offset + 6]);
    response.px[38] = (request.ip_src >> 24) as u8;
    response.px[39] = (request.ip_src >> 16) as u8;
    response.px[40] = (request.ip_src >> 8) as u8;
    response.px[41] = (request.ip_src) as u8;

    // Queue for transmission.
    stack.transmit_packet_buffer(response);
    Ok(())
}
