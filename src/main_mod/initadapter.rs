//! Adapter initialization: discover source MAC, router MAC, and source IP.
//!
//! This module implements the equivalent of the C `zorp_initialize_adapter()`
//! function. It opens a network adapter, discovers the source MAC and IP
//! addresses (auto-detecting them if not manually configured), and resolves
//! the router MAC addresses via ARP (IPv4) and NDP (IPv6).

use std::net::{Ipv4Addr, Ipv6Addr};

use log::{debug, error, info, warn};

use crate::massip::addr::{
    Ipv4Address, Ipv6Address, MacAddress as MassipMac,
};
use crate::massip::massip::MassIP;
use crate::rawsock::adapter::{Adapter, AdapterConfig, LinkType};
use crate::rawsock::getif::get_default_interface;
use crate::rawsock::getip::{get_adapter_ip, get_adapter_ipv6};
use crate::rawsock::getmac::get_adapter_mac;
use crate::rawsock::getroute::get_default_gateway;
use crate::rawsock::MacAddress as RawsockMac;
use crate::stack::{arpv4, ndpv6};

use super::conf::{NicConfig, Zorp};

/// Convert a rawsock MacAddress to a massip MacAddress.
fn mac_to_massip(mac: &RawsockMac) -> MassipMac {
    MassipMac { addr: mac.addr }
}

/// Convert a massip MacAddress to a rawsock MacAddress.
fn mac_to_rawsock(mac: &MassipMac) -> RawsockMac {
    RawsockMac::new(mac.addr)
}

/// Convert a std Ipv4Addr to an Ipv4Address (u32).
fn ipv4addr_to_u32(ip: Ipv4Addr) -> Ipv4Address {
    u32::from(ip)
}

/// Convert an Ipv4Address (u32) to a std Ipv4Addr.
fn u32_to_ipv4addr(ip: Ipv4Address) -> Ipv4Addr {
    Ipv4Addr::from(ip)
}

/// Convert a std Ipv6Addr to an Ipv6Address.
fn ipv6addr_to_massip(ip: Ipv6Addr) -> Ipv6Address {
    let octets = ip.octets();
    let hi = u64::from_be_bytes([
        octets[0], octets[1], octets[2], octets[3],
        octets[4], octets[5], octets[6], octets[7],
    ]);
    let lo = u64::from_be_bytes([
        octets[8], octets[9], octets[10], octets[11],
        octets[12], octets[13], octets[14], octets[15],
    ]);
    Ipv6Address::new(hi, lo)
}

/// Format an Ipv4Address (u32) as a dotted-quad string.
fn fmt_ipv4(ip: Ipv4Address) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF,
    )
}

/// Format a MAC address as a colon-separated hex string.
fn fmt_mac(mac: &MassipMac) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac.addr[0], mac.addr[1], mac.addr[2],
        mac.addr[3], mac.addr[4], mac.addr[5],
    )
}

/// Result of adapter initialization.
pub struct AdapterInitResult {
    /// The opened and configured adapter.
    pub adapter: Adapter,
    /// Discovered source MAC address.
    pub source_mac: MassipMac,
    /// Resolved router MAC address for IPv4.
    pub router_mac_ipv4: MassipMac,
    /// Resolved router MAC address for IPv6.
    pub router_mac_ipv6: MassipMac,
}

/// Initialize a network adapter for the given NIC index.
///
/// This performs the following steps:
/// 1. Determine which interface to use (auto-detect if not specified).
/// 2. Open the adapter with the configured options.
/// 3. Discover or use the configured source MAC address.
/// 4. Discover or use the configured source IPv4 address, and resolve
///    the router MAC via ARP if needed.
/// 5. Discover or use the configured source IPv6 address, and resolve
///    the router MAC via NDP if needed.
///
/// Returns `Ok(AdapterInitResult)` on success, or `Err` with a descriptive
/// message on failure.
pub fn initialize_adapter(
    zorp: &Zorp,
    nic: &mut NicConfig,
    _index: usize,
    targets: &MassIP,
) -> Result<AdapterInitResult, String> {
    // ---------------------------------------------------------------
    // 1. Determine the interface name
    // ---------------------------------------------------------------
    let ifname = if !nic.ifname.is_empty() {
        nic.ifname.clone()
    } else {
        match get_default_interface() {
            Ok(Some(name)) => name,
            Ok(None) | Err(_) => {
                return Err(
                    "could not determine default interface\n\
                     [hint] try \"--interface ethX\""
                        .to_string(),
                );
            }
        }
    };
    info!("interface = {}", ifname);

    // ---------------------------------------------------------------
    // 2. Open the adapter
    // ---------------------------------------------------------------
    let adapter_config = AdapterConfig {
        name: ifname.clone(),
        is_packet_trace: zorp.nmap_packet_trace,
        is_offline: zorp.is_offline,
        is_vlan: nic.is_vlan,
        vlan_id: nic.vlan_id,
    };

    let adapter = Adapter::open(&adapter_config).map_err(|e| {
        format!("if:{}:init: failed: {}", ifname, e)
    })?;

    nic.link_type = adapter.link_type.to_raw();
    info!("interface-type = {}", nic.link_type);

    // ---------------------------------------------------------------
    // 3. Discover MAC address
    // ---------------------------------------------------------------
    let mut source_mac = nic.source_mac;

    let needs_mac = !matches!(
        adapter.link_type,
        LinkType::RawIp
    );

    if !needs_mac {
        info!("source-mac = none");
    } else {
        if source_mac.is_zero() && !nic.my_mac_count {
            // Auto-detect MAC from the OS
            match get_adapter_mac(&ifname) {
                Ok(mac) => {
                    source_mac = mac_to_massip(&mac);
                }
                Err(e) => {
                    warn!("could not detect MAC address for {}: {}", ifname, e);
                }
            }
        }

        if source_mac.is_zero() {
            return Err(format!(
                "failed to detect MAC address of interface \"{}\"\n\
                 [hint] try \"--source-mac 00-11-22-33-44-55\"",
                ifname
            ));
        }

        info!("source-mac = {}", fmt_mac(&source_mac));
    }

    // ---------------------------------------------------------------
    // 4. IPv4 address and router MAC
    // ---------------------------------------------------------------
    let mut router_mac_ipv4 = nic.router_mac_ipv4;
    let mut is_usable_ipv4 = !targets.has_ipv4_targets();

    if targets.has_ipv4_targets() {
        let mut adapter_ip = nic.src_ipv4_first;

        if adapter_ip == 0 {
            // Auto-detect IPv4 from the OS
            match get_adapter_ip(&ifname) {
                Ok(Some(ip)) => {
                    adapter_ip = ipv4addr_to_u32(ip);
                    nic.src_ipv4_first = adapter_ip;
                    nic.src_ipv4_last = adapter_ip;
                    nic.src_ipv4_range = 1;
                }
                Ok(None) => {}
                Err(e) => {
                    warn!("could not detect IP for {}: {}", ifname, e);
                }
            }
        }

        if adapter_ip == 0 {
            error!("failed to detect IP of interface \"{}\"", ifname);
            error!("  [hint] did you spell the name correctly?");
            error!(
                "  [hint] if it has no IP address, manually set with \
                 \"--source-ip 198.51.100.17\""
            );
            if targets.has_ipv4_targets() {
                return Err(format!(
                    "failed to detect IP of interface \"{}\"",
                    ifname
                ));
            }
        }

        if adapter_ip != 0 {
            info!("source-ip = {}", fmt_ipv4(adapter_ip));
            is_usable_ipv4 = true;
        }

        // -----------------------------------------------------------
        // Router MAC for IPv4
        // -----------------------------------------------------------
        if zorp.is_offline {
            // Offline benchmarking: use a fake router MAC
            router_mac_ipv4 = MassipMac {
                addr: [0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            };
        } else if matches!(adapter.link_type, LinkType::RawIp) {
            info!("router-mac-ipv4 = implicit");
        } else if router_mac_ipv4.is_zero() && adapter_ip != 0 {
            // Try to discover the default gateway and ARP for its MAC
            let router_ipv4 = if nic.router_ip != 0 {
                Some(nic.router_ip)
            } else {
                match get_default_gateway(Some(&ifname)) {
                    Ok(Some(gw)) => Some(ipv4addr_to_u32(gw)),
                    Ok(None) => None,
                    Err(e) => {
                        warn!("could not detect default gateway: {}", e);
                        None
                    }
                }
            };

            if let Some(router_ip) = router_ipv4 {
                info!("router-ip = {}", fmt_ipv4(router_ip));
                debug!("if({}): arp: resolving router MAC", ifname);

                match arpv4::resolve(&adapter, adapter_ip, source_mac, router_ip) {
                    Ok(mac) => {
                        router_mac_ipv4 = mac;
                    }
                    Err(e) => {
                        warn!("ARP resolve failed: {}", e);
                    }
                }
            }

            info!("router-mac-ipv4 = {}", fmt_mac(&router_mac_ipv4));

            if router_mac_ipv4.is_zero() {
                return Err(format!(
                    "ARP timed-out resolving MAC address for router \"{}\"\n\
                     [hint] try \"--router-ip 192.0.2.1\" to specify different router\n\
                     [hint] try \"--router-mac 66-55-44-33-22-11\" to bypass ARP\n\
                     [hint] try \"--interface eth0\" to change interface",
                    ifname
                ));
            }
        }
    }

    // ---------------------------------------------------------------
    // 5. IPv6 address and router MAC
    // ---------------------------------------------------------------
    let mut router_mac_ipv6 = nic.router_mac_ipv6;
    let mut is_usable_ipv6 = !targets.has_ipv6_targets();

    if targets.has_ipv6_targets() {
        let mut adapter_ipv6 = nic.src_ipv6_first;

        if adapter_ipv6.is_zero() {
            // Auto-detect IPv6 from the OS
            match get_adapter_ipv6(&ifname) {
                Ok(Some(ip)) => {
                    adapter_ipv6 = ipv6addr_to_massip(ip);
                    nic.src_ipv6_first = adapter_ipv6;
                    nic.src_ipv6_last = adapter_ipv6;
                    nic.src_ipv6_range = 1;
                }
                Ok(None) => {}
                Err(e) => {
                    warn!("could not detect IPv6 for {}: {}", ifname, e);
                }
            }
        }

        if adapter_ipv6.is_zero() {
            return Err(format!(
                "failed to detect IPv6 address of interface \"{}\"\n\
                 [hint] did you spell the name correctly?\n\
                 [hint] if it has no IP address, manually set with \
                 \"--source-ip 2001:3b8::1234\"",
                ifname
            ));
        }

        info!("source-ip = [{}]", crate::massip::addr::ipv6address_fmt(adapter_ipv6));
        is_usable_ipv6 = true;

        // -----------------------------------------------------------
        // Router MAC for IPv6
        // -----------------------------------------------------------
        if zorp.is_offline {
            router_mac_ipv6 = MassipMac {
                addr: [0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            };
        }

        if router_mac_ipv6.is_zero() {
            debug!("if({}): ndp: resolving router MAC", ifname);
            match ndpv6::resolve(&adapter, adapter_ipv6, source_mac) {
                Ok(mac) => {
                    router_mac_ipv6 = mac;
                }
                Err(e) => {
                    warn!("NDP resolve failed: {}", e);
                }
            }
        }

        info!("router-mac-ipv6 = {}", fmt_mac(&router_mac_ipv6));

        if router_mac_ipv6.is_zero() {
            return Err(format!(
                "NDP timed-out resolving MAC address for router \"{}\"\n\
                 [hint] try \"--router-mac-ipv6 66-55-44-33-22-11\" to bypass NDP\n\
                 [hint] try \"--interface eth0\" to change interface",
                ifname
            ));
        }
    }

    // ---------------------------------------------------------------
    // Mark the NIC as usable if both address families are usable
    // ---------------------------------------------------------------
    nic.is_usable = is_usable_ipv4 && is_usable_ipv6;

    // Store discovered MAC addresses back into the NIC config
    nic.source_mac = source_mac;
    nic.router_mac_ipv4 = router_mac_ipv4;
    nic.router_mac_ipv6 = router_mac_ipv6;

    debug!("if({}): initialization done", ifname);

    Ok(AdapterInitResult {
        adapter,
        source_mac,
        router_mac_ipv4,
        router_mac_ipv6,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_roundtrip() {
        let ip: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let as_u32 = ipv4addr_to_u32(ip);
        assert_eq!(as_u32, 0xC000_0201);
        let back = u32_to_ipv4addr(as_u32);
        assert_eq!(back, ip);
    }

    #[test]
    fn test_ipv6_to_massip() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let massip = ipv6addr_to_massip(ip);
        assert_eq!(massip.hi, 0x2001_0db8_0000_0000);
        assert_eq!(massip.lo, 1);
    }

    #[test]
    fn test_mac_conversion() {
        let rawsock_mac = RawsockMac::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let massip_mac = mac_to_massip(&rawsock_mac);
        assert_eq!(massip_mac.addr, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let back = mac_to_rawsock(&massip_mac);
        assert_eq!(back.addr, rawsock_mac.addr);
    }

    #[test]
    fn test_fmt_mac() {
        let mac = MassipMac {
            addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        };
        assert_eq!(fmt_mac(&mac), "00:11:22:33:44:55");
    }

    #[test]
    fn test_fmt_ipv4() {
        assert_eq!(fmt_ipv4(0xC000_0201), "192.0.2.1");
    }
}
