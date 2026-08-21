//! Read IP ranges from the configured targets and print them to stdout.
//!
//! This module implements the "readrange" operation: it iterates over all
//! configured IPv4 and IPv6 target ranges and prints them in human-readable
//! CIDR or range notation.

use std::io::{self, Write};

use crate::massip::addr::{ipv6address_fmt, Ipv6Address};
use crate::massip::massip::MassIP;
use crate::massip::rangesv4::{range_is_cidr, Range};

/// Count the number of CIDR prefix bits for an IPv6 range where both
/// endpoints share the same upper 64 bits. Returns 0 if the range cannot
/// be expressed as a CIDR prefix.
fn count_cidr6_bits(range_begin: Ipv6Address, range_end: Ipv6Address) -> u32 {
    // If the upper 64 bits differ, we can't express this as a simple CIDR.
    if range_begin.hi != range_end.hi {
        return 0;
    }

    for i in 0u32..64 {
        let mask: u64 = if i == 0 {
            u64::MAX
        } else {
            u64::MAX >> i
        };

        if (range_begin.lo & !mask) == (range_end.lo & !mask) {
            if (range_begin.lo & mask) == 0 && (range_end.lo & mask) == mask {
                return i;
            }
        }
    }

    0
}

/// Format an IPv4 address from a u32 into dotted-quad notation.
fn fmt_ipv4(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF,
    )
}

/// Print all configured target ranges (IPv4 and IPv6) to the given writer.
///
/// This is the Rust equivalent of the C `main_readrange()` function.
/// Each range is printed on its own line in one of the following formats:
/// - Single address: `192.0.2.1`
/// - CIDR block: `192.0.2.0/24`
/// - Arbitrary range: `192.0.2.1-192.0.2.10`
/// - IPv6 single/range/CIDR analogously
pub fn main_readrange(targets: &MassIP, out: &mut dyn Write) -> io::Result<()> {
    // Print IPv4 ranges
    for range in &targets.ipv4.list {
        if range.begin == range.end {
            // Single host
            writeln!(out, "{}", fmt_ipv4(range.begin))?;
        } else if let Some(prefix_length) = try_cidr_prefix(*range) {
            // CIDR block
            writeln!(out, "{}/{}", fmt_ipv4(range.begin), prefix_length)?;
        } else {
            // Arbitrary range
            writeln!(out, "{}-{}", fmt_ipv4(range.begin), fmt_ipv4(range.end))?;
        }
    }

    // Print IPv6 ranges
    for range in &targets.ipv6.list {
        let begin_str = ipv6address_fmt(range.begin);

        if range.begin.is_equal(range.end) {
            // Single host
            writeln!(out, "{}", begin_str)?;
        } else {
            let cidr_bits = count_cidr6_bits(range.begin, range.end);
            if cidr_bits > 0 {
                writeln!(out, "{}/{}", begin_str, cidr_bits)?;
            } else {
                let end_str = ipv6address_fmt(range.end);
                writeln!(out, "{}-{}", begin_str, end_str)?;
            }
        }
    }

    Ok(())
}

/// Try to express an IPv4 range as a CIDR prefix.
/// Returns `Some(prefix_length)` if the range is a valid CIDR block,
/// `None` otherwise.
fn try_cidr_prefix(range: Range) -> Option<u32> {
    let mut prefix_length = 0u32;
    if range_is_cidr(range, Some(&mut prefix_length)) {
        Some(prefix_length)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::massip::rangesv4::Range;
    use crate::massip::rangesv6::Range6;

    #[test]
    fn test_fmt_ipv4() {
        assert_eq!(fmt_ipv4(0xC000_0201), "192.0.2.1");
        assert_eq!(fmt_ipv4(0xFF_FF_FF_FF), "255.255.255.255");
        assert_eq!(fmt_ipv4(0), "0.0.0.0");
    }

    #[test]
    fn test_try_cidr_prefix() {
        // 192.0.2.0/24
        let range = Range::new(0xC000_0200, 0xC000_02FF);
        assert_eq!(try_cidr_prefix(range), Some(24));

        // Not a CIDR: 192.0.2.1 - 192.0.2.10
        let range = Range::new(0xC000_0201, 0xC000_020A);
        assert_eq!(try_cidr_prefix(range), None);

        // Single host is /32
        let range = Range::new(0xC000_0201, 0xC000_0201);
        assert_eq!(try_cidr_prefix(range), Some(32));
    }

    #[test]
    fn test_count_cidr6_bits() {
        use crate::massip::addr::Ipv6Address;

        // 2001:db8::/32 => begin=2001:0db8::, end=2001:0db8:ffff:ffff:ffff:ffff:ffff:ffff
        let begin = Ipv6Address::new(0x2001_0db8_0000_0000, 0);
        let end = Ipv6Address::new(0x2001_0db8_0000_0000, u64::MAX);
        assert_eq!(count_cidr6_bits(begin, end), 32);

        // Different hi => 0
        let begin2 = Ipv6Address::new(0x2001_0db8_0000_0000, 0);
        let end2 = Ipv6Address::new(0x2001_0db9_0000_0000, 0);
        assert_eq!(count_cidr6_bits(begin2, end2), 0);
    }

    #[test]
    fn test_main_readrange_basic() {
        let mut targets = MassIP::new();
        targets.ipv4.add_range(0xC000_0200, 0xC000_02FF); // 192.0.2.0/24
        targets.ipv4.add_range(0x0A00_0001, 0x0A00_0001); // 10.0.0.1 single

        let mut buf = Vec::new();
        main_readrange(&targets, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("192.0.2.0/24"));
        assert!(output.contains("10.0.0.1"));
    }
}
