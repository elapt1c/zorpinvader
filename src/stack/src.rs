//! Source IP/port tracking for spoofed scanning.
//!
//! When performing Internet-scale scans, we spoof source IP addresses and
//! port numbers from a configured range. This module tracks those ranges
//! and provides functions to check whether a given IP/port belongs to us.
//!
//! Converted from `c-src/stack-src.h` and `c-src/stack-src.c`.

use crate::massip::addr::{IpAddress, Ipv4Address, Ipv6Address};

/// Source IP addresses and port ranges used for spoofed scanning.
///
/// All outgoing probes use IP addresses and ports drawn from these ranges.
/// When responses come back, we verify they match these ranges to confirm
/// they belong to our scan.
#[derive(Debug, Clone)]
pub struct StackSrc {
    /// IPv4 source address range.
    pub ipv4: AddressRange<Ipv4Address>,

    /// Source port range (applies to both IPv4 and IPv6).
    pub port: AddressRange<u16>,

    /// IPv6 source address range.
    pub ipv6: Ipv6Range,
}

/// A simple first..=last range with a precomputed count.
#[derive(Debug, Clone)]
pub struct AddressRange<T> {
    pub first: T,
    pub last: T,
    pub range: u32,
}

/// IPv6 address range (hi/lo pairs).
#[derive(Debug, Clone)]
pub struct Ipv6Range {
    pub first: Ipv6Address,
    pub last: Ipv6Address,
    pub range: u32,
}

impl StackSrc {
    /// Create a new `StackSrc` with the given IPv4 and port ranges.
    pub fn new(
        ipv4_first: Ipv4Address,
        ipv4_last: Ipv4Address,
        port_first: u16,
        port_last: u16,
    ) -> Self {
        Self {
            ipv4: AddressRange {
                first: ipv4_first,
                last: ipv4_last,
                range: ipv4_last.wrapping_sub(ipv4_first).wrapping_add(1),
            },
            port: AddressRange {
                first: port_first,
                last: port_last,
                range: (port_last as u32) - (port_first as u32) + 1,
            },
            ipv6: Ipv6Range {
                first: Ipv6Address::default(),
                last: Ipv6Address::default(),
                range: 0,
            },
        }
    }

    /// Set the IPv6 source address range.
    pub fn set_ipv6_range(&mut self, first: Ipv6Address, last: Ipv6Address) {
        // Approximate range as the difference in the low 32 bits + 1.
        // For large ranges, callers should set `range` explicitly.
        let range = if last.lo >= first.lo {
            (last.lo - first.lo + 1) as u32
        } else {
            1
        };
        self.ipv6 = Ipv6Range { first, last, range };
    }

    /// Check whether a given IP address AND port belong to our scan source.
    pub fn is_myself(&self, ip: IpAddress, port: u16) -> bool {
        self.is_my_ip(ip) && self.is_my_port(port)
    }

    /// Check whether a given IP address is in our source range.
    pub fn is_my_ip(&self, ip: IpAddress) -> bool {
        match ip {
            IpAddress::V4(v4) => self.ipv4.first <= v4 && v4 <= self.ipv4.last,
            IpAddress::V6(v6) => self.ipv6.first.is_equal(v6),
        }
    }

    /// Check whether a given port is in our source port range.
    pub fn is_my_port(&self, port: u16) -> bool {
        self.port.first <= port && port <= self.port.last
    }

    /// Advance to the next source port (and possibly IP) for reconnection.
    ///
    /// When wrapping past the last port, also advances the IP address.
    /// Returns `(new_ip, new_port)`.
    pub fn next_ip_port(&self, ip: IpAddress, port: u16) -> (IpAddress, u16) {
        let mut new_port = port.wrapping_sub(self.port.first).wrapping_add(1);
        new_port = new_port.wrapping_add(self.port.first);

        if new_port >= self.port.last {
            new_port = self.port.first;

            // Ports wrapped, so advance the IP address too.
            match ip {
                IpAddress::V4(v4) => {
                    let mut new_ip = v4.wrapping_sub(self.ipv4.first).wrapping_add(1);
                    new_ip = new_ip.wrapping_add(self.ipv4.first);
                    if new_ip >= self.ipv4.last {
                        new_ip = self.ipv4.first;
                    }
                    (IpAddress::V4(new_ip), new_port)
                }
                IpAddress::V6(v6) => {
                    let diff = v6.subtract(self.ipv6.first);
                    let diff = diff.add_u64(1);
                    let mut new_ip = self.ipv6.first.add(diff);
                    if self.ipv6.last.is_less_than(new_ip) {
                        new_ip = self.ipv6.first;
                    }
                    (IpAddress::V6(new_ip), new_port)
                }
            }
        } else {
            (ip, new_port)
        }
    }
}
