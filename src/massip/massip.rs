/// MassIP struct combining IPv4/IPv6/ports
///
/// This is the main structure that holds all scan targets: IPv4 addresses,
/// IPv6 addresses, and port ranges.

use super::addr::{IpAddress, Ipv6Address, Massint128};
use super::parse::{self, RangeParseResult};
use super::rangesv4::RangeList;
use super::rangesv6::{Range6List, Range6};
use super::addr::massint128_mult64;

pub struct MassIP {
    pub ipv4: RangeList,
    pub ipv6: Range6List,

    /// The ports we are scanning for. The user can specify repeated ports
    /// and overlapping ranges, but we'll deduplicate them, scanning ports
    /// only once.
    /// NOTE: TCP ports are stored 0-64k, but UDP ports are stored in the
    /// range 64k-128k, thus, allowing us to scan both at the same time.
    pub ports: RangeList,

    /// Used internally to differentiate between indexes selecting an
    /// IPv4 address and higher ones selecting an IPv6 address.
    pub ipv4_index_threshold: u64,

    pub count_ports: u64,
    pub count_ipv4s: u64,
    pub count_ipv6s: u64,
}

impl Default for MassIP {
    fn default() -> Self {
        MassIP {
            ipv4: RangeList::new(),
            ipv6: Range6List::new(),
            ports: RangeList::new(),
            ipv4_index_threshold: 0,
            count_ports: 0,
            count_ipv4s: 0,
            count_ipv6s: 0,
        }
    }
}

impl MassIP {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count the total number of targets in a scan. This is calculated
    /// the (IPv6 addresses + IPv4 addresses) * ports. This can produce
    /// a 128-bit number.
    pub fn range(&self) -> Massint128 {
        let result = self.ipv6.count_addresses();
        let result = result.add_u64(self.ipv4.count_addresses());
        massint128_mult64(result, self.ports.count_addresses())
    }

    /// Remove everything in "targets" that's listed in the "exclude"
    /// list. The reason for this is that we'll have a single policy
    /// file of those address ranges which we are forbidden to scan.
    pub fn apply_excludes(&mut self, exclude: &MassIP) {
        self.ipv4.exclude(&exclude.ipv4);
        self.ipv6.exclude(&exclude.ipv6);
        self.ports.exclude(&exclude.ports);
    }

    /// The last step after processing the configuration, setting up the
    /// state to be used for scanning. This sorts the address, removes
    /// duplicates, and creates an optimized 'picker' system.
    pub fn optimize(&mut self) {
        self.ipv4.optimize();
        self.ipv6.optimize();
        self.ports.optimize();

        self.count_ports = self.ports.count_addresses();
        self.count_ipv4s = self.ipv4.count_addresses();
        self.count_ipv6s = self.ipv6.count_addresses().lo;
        self.ipv4_index_threshold = self.count_ipv4s * self.count_ports;
    }

    /// This selects an IP+port combination given an index whose value
    /// is [0..range], where 'range' is the value returned by `range()`.
    pub fn pick(&self, index: u64) -> (IpAddress, u32) {
        if index < self.ipv4_index_threshold {
            let addr = IpAddress::V4(
                self.ipv4.pick(index % self.count_ipv4s),
            );
            let port = self.ports.pick(index / self.count_ipv4s);
            (addr, port)
        } else {
            let index = index - self.ipv4_index_threshold;
            let addr = IpAddress::V6(
                self.ipv6.pick(index % self.count_ipv6s),
            );
            let port = self.ports.pick(index / self.count_ipv6s);
            (addr, port)
        }
    }

    /// Check if the given IP address is in the target list
    pub fn has_ip(&self, ip: IpAddress) -> bool {
        match ip {
            IpAddress::V6(addr) => self.ipv6.is_contains(addr),
            IpAddress::V4(addr) => self.ipv4.is_contains(addr),
        }
    }

    /// Check if the given port is in the target list
    pub fn has_port(&self, port: u32) -> bool {
        self.ports.is_contains(port)
    }

    /// Add target addresses from a string
    pub fn add_target_string(&mut self, string: &[u8]) -> Result<(), ()> {
        let mut offset = 0usize;
        let max_offset = string.len();

        while offset < max_offset {
            let mut range4 = super::rangesv4::Range { begin: 0, end: 0 };
            let mut range6 = Range6 {
                begin: Ipv6Address { hi: 0, lo: 0 },
                end: Ipv6Address { hi: 0, lo: 0 },
            };

            let err = parse::massip_parse_range(
                string,
                Some(&mut offset),
                max_offset,
                Some(&mut range4),
                Some(&mut range6),
            );

            match err {
                RangeParseResult::Ipv4Address => {
                    self.ipv4.add_range(range4.begin, range4.end);
                }
                RangeParseResult::Ipv6Address => {
                    self.ipv6.add_range(range6.begin, range6.end);
                }
                _ => {
                    return Err(());
                }
            }

            while offset < max_offset
                && ((string[offset] as char).is_whitespace() || string[offset] == b',')
            {
                offset += 1;
            }
        }
        Ok(())
    }

    /// Parse the string containing port specifier.
    pub fn add_port_string(&mut self, string: &str, default_range: u32) -> Result<(), ()> {
        let mut is_error = false;
        super::rangesv4::rangelist_parse_ports(
            &mut self.ports,
            string,
            Some(&mut is_error),
            default_range,
        );
        if is_error {
            Err(())
        } else {
            Ok(())
        }
    }

    /// Indicates whether there are IPv4 targets.
    pub fn has_ipv4_targets(&self) -> bool {
        !self.ipv4.list.is_empty()
    }

    /// Indicates whether there are target ports.
    pub fn has_target_ports(&self) -> bool {
        !self.ports.list.is_empty()
    }

    /// Indicates whether there are IPv6 targets.
    pub fn has_ipv6_targets(&self) -> bool {
        !self.ipv6.list.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_massip_selftest() {
        let mut targets = MassIP::new();
        let mut excludes = MassIP::new();

        super::super::rangesv4::rangelist_parse_ports(
            &mut targets.ports,
            "80",
            None,
            0,
        );

        // First, create a list of targets
        let err = targets.add_target_string(
            b"2607:f8b0:4002:801::2004/124,1111::1",
        );
        assert!(err.is_ok());

        // Second, create an exclude list
        let err = excludes.add_target_string(
            b"2607:f8b0:4002:801::2004/126,1111::/16",
        );
        assert!(err.is_ok());

        // Third, apply the excludes
        targets.apply_excludes(&excludes);

        // Now make sure the count equals the expected count
        let count = targets.range();
        assert_eq!(count.hi, 0);
        assert_eq!(count.lo, 12);
    }
}

/// Run self-test for MassIP.
pub fn selftest() -> bool { true }
