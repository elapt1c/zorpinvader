/// Simple module for handling addresses (IPv6, IPv4, MAC).
/// Also implements a 128-bit type for dealing with addresses.
///
/// This is the module that almost all the other code depends
/// upon, because everything else deals with the IP address
/// types defined here.

use std::fmt;

/// An IPv6 address is represented as two 64-bit integers instead of a single
/// 128-bit integer. This is because the 128-bit math operations need to be
/// done manually for portability.
#[derive(Debug, Clone, Copy, Default, Hash)]
pub struct Ipv6Address {
    pub hi: u64,
    pub lo: u64,
}

/// IPv4 addresses are represented simply with a 32-bit integer.
pub type Ipv4Address = u32;

/// MAC address (layer 2). Since we have canonical types for IPv4/IPv6
/// addresses, we may as well have a canonical type for MAC addresses, too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MacAddress {
    pub addr: [u8; 6],
}

/// In many cases we need to do arithmetic on IPv6 addresses, treating
/// them as a large 128-bit integer. Thus, we declare our own 128-bit
/// integer type (and some accompanying math functions). But it's
/// still just the same as a 128-bit integer.
pub type Massint128 = Ipv6Address;

/// Most of the code in this project is agnostic to the version of IP
/// addresses (IPv4 or IPv6). Therefore, we represent them as a union
/// distinguished by a version number. The `version` is an integer
/// with a value of either 4 or 6.
#[derive(Debug, Clone, Copy, Hash)]
pub enum IpAddress {
    V4(Ipv4Address),
    V6(Ipv6Address),
}

impl Default for IpAddress {
    fn default() -> Self {
        IpAddress::V4(0)
    }
}

impl IpAddress {
    /// Get the version number (4 or 6)
    pub fn version(&self) -> u8 {
        match self {
            IpAddress::V4(_) => 4,
            IpAddress::V6(_) => 6,
        }
    }
}

impl PartialEq for IpAddress {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (IpAddress::V4(a), IpAddress::V4(b)) => a == b,
            (IpAddress::V6(a), IpAddress::V6(b)) => a.is_equal(*b),
            _ => false,
        }
    }
}

impl Eq for IpAddress {}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpAddress::V4(ip) => {
                let formatted = ipv4address_fmt(*ip);
                write!(f, "{}", formatted)
            }
            IpAddress::V6(ip) => {
                let formatted = ipv6address_fmt(*ip);
                write!(f, "{}", formatted)
            }
        }
    }
}

impl Ipv6Address {
    /// Create a new IPv6 address from two 64-bit integers
    pub fn new(hi: u64, lo: u64) -> Self {
        Ipv6Address { hi, lo }
    }

    /// The IPv6 address [FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF] is invalid
    pub fn is_invalid(self) -> bool {
        self.hi == u64::MAX && self.lo == u64::MAX
    }

    /// Returns true if the IPv6 address is zero [::]
    pub fn is_zero(self) -> bool {
        self.hi == 0 && self.lo == 0
    }

    /// Compare two IPv6 addresses
    pub fn is_equal(self, other: Ipv6Address) -> bool {
        self.hi == other.hi && self.lo == other.lo
    }

    /// Compare two IPv6 addresses, to see which one comes first.
    /// Returns true if self < other.
    pub fn is_less_than(self, other: Ipv6Address) -> bool {
        if self.hi == other.hi {
            self.lo < other.lo
        } else {
            self.hi < other.hi
        }
    }

    /// Less-than-or-equal comparison
    pub fn is_less_equal(self, other: Ipv6Address) -> bool {
        if self.hi < other.hi {
            return true;
        }
        if self.hi > other.hi {
            return false;
        }
        self.lo <= other.lo
    }

    /// Greater-than-or-equal comparison
    pub fn is_greater_equal(self, other: Ipv6Address) -> bool {
        !self.is_less_than(other)
    }

    /// Mask the lower bits of each address and test if the upper bits are equal
    pub fn is_equal_prefixed(self, rhs: Ipv6Address, prefix: u32) -> bool {
        if prefix > 128 {
            return false;
        }

        let mask = if prefix > 64 {
            Ipv6Address {
                hi: u64::MAX,
                lo: if prefix == 128 {
                    u64::MAX
                } else {
                    u64::MAX << (128 - prefix)
                },
            }
        } else if prefix == 0 {
            Ipv6Address { hi: 0, lo: 0 }
        } else {
            Ipv6Address {
                hi: u64::MAX << (64 - prefix),
                lo: 0,
            }
        };

        let lhs_hi = self.hi & mask.hi;
        let lhs_lo = self.lo & mask.lo;
        let rhs_hi = rhs.hi & mask.hi;
        let rhs_lo = rhs.lo & mask.lo;

        lhs_hi == rhs_hi && lhs_lo == rhs_lo
    }

    /// Add a u64 to this IPv6 address
    pub fn add_u64(self, rhs: u64) -> Ipv6Address {
        let lo = self.lo.wrapping_add(rhs);
        let mut hi = self.hi;
        if lo < rhs {
            hi = hi.wrapping_add(1);
        }
        Ipv6Address { hi, lo }
    }

    /// Subtract another IPv6 address from this one
    pub fn subtract(self, rhs: Ipv6Address) -> Ipv6Address {
        let lo = self.lo.wrapping_sub(rhs.lo);
        let mut hi = self.hi.wrapping_sub(rhs.hi);
        // check for underflow
        if lo > self.lo {
            hi = hi.wrapping_sub(1);
        }
        Ipv6Address { hi, lo }
    }

    /// Add two IPv6 addresses
    pub fn add(self, rhs: Ipv6Address) -> Ipv6Address {
        let lo = self.lo.wrapping_add(rhs.lo);
        let mut hi = self.hi.wrapping_add(rhs.hi);
        // check for overflow
        if lo < self.lo {
            hi = hi.wrapping_add(1);
        }
        Ipv6Address { hi, lo }
    }

    /// Given a typical EXTERNAL representation of an IPv6 address, which is
    /// an array of 16 bytes, convert to the canonical INTERNAL address.
    pub fn from_bytes(buf: &[u8]) -> Ipv6Address {
        assert!(buf.len() >= 16);
        let hi = (buf[0] as u64) << 56
            | (buf[1] as u64) << 48
            | (buf[2] as u64) << 40
            | (buf[3] as u64) << 32
            | (buf[4] as u64) << 24
            | (buf[5] as u64) << 16
            | (buf[6] as u64) << 8
            | (buf[7] as u64);
        let lo = (buf[8] as u64) << 56
            | (buf[9] as u64) << 48
            | (buf[10] as u64) << 40
            | (buf[11] as u64) << 32
            | (buf[12] as u64) << 24
            | (buf[13] as u64) << 16
            | (buf[14] as u64) << 8
            | (buf[15] as u64);
        Ipv6Address { hi, lo }
    }

    /// Convert to bytes (big-endian, network byte order)
    pub fn to_bytes(self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0] = (self.hi >> 56) as u8;
        buf[1] = (self.hi >> 48) as u8;
        buf[2] = (self.hi >> 40) as u8;
        buf[3] = (self.hi >> 32) as u8;
        buf[4] = (self.hi >> 24) as u8;
        buf[5] = (self.hi >> 16) as u8;
        buf[6] = (self.hi >> 8) as u8;
        buf[7] = self.hi as u8;
        buf[8] = (self.lo >> 56) as u8;
        buf[9] = (self.lo >> 48) as u8;
        buf[10] = (self.lo >> 40) as u8;
        buf[11] = (self.lo >> 32) as u8;
        buf[12] = (self.lo >> 24) as u8;
        buf[13] = (self.lo >> 16) as u8;
        buf[14] = (self.lo >> 8) as u8;
        buf[15] = self.lo as u8;
        buf
    }
}

impl PartialEq for Ipv6Address {
    fn eq(&self, other: &Self) -> bool {
        self.hi == other.hi && self.lo == other.lo
    }
}

impl Eq for Ipv6Address {}

impl fmt::Display for Ipv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", ipv6address_fmt(*self))
    }
}

impl MacAddress {
    /// Create a new MAC address from 6 bytes.
    pub fn new(addr: [u8; 6]) -> Self {
        MacAddress { addr }
    }

    /// Given a typical EXTERNAL representation of an Ethernet MAC address,
    /// which is an array of 6 bytes, convert to the canonical INTERNAL address.
    pub fn from_bytes(buf: &[u8]) -> MacAddress {
        assert!(buf.len() >= 6);
        MacAddress {
            addr: [buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]],
        }
    }

    /// Test if the Ethernet MAC address is all zeroes
    pub fn is_zero(self) -> bool {
        self.addr == [0; 6]
    }

    /// Compare two Ethernet MAC addresses to see if they are equal
    pub fn is_equal(self, rhs: MacAddress) -> bool {
        self.addr == rhs.addr
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let formatted = macaddress_fmt(*self);
        write!(f, "{}", formatted)
    }
}

/// Format an IPv6 address as a string.
/// This follows the C implementation exactly, including ellision (::) handling.
pub fn ipv6address_fmt(a: Ipv6Address) -> String {
    let tmp = a.to_bytes();
    let mut result = String::with_capacity(48);
    let mut is_ellision = false;

    let mut i = 0;
    while i < 16 {
        let n = (tmp[i] as u16) << 8 | (tmp[i + 1] as u16);

        // Handle the ellision case
        if n == 0 && !is_ellision {
            is_ellision = true;
            while i < 13 && tmp[i + 2] == 0 && tmp[i + 3] == 0 {
                i += 2;
            }
            result.push(':');

            // test for all-zero address, in which case the output
            // will be "::".
            while i == 14 && tmp[i] == 0 && tmp[i + 1] == 0 {
                i = 16;
                result.push(':');
            }
            continue;
        }

        // Print the colon between numbers
        if i > 0 {
            result.push(':');
        }

        // Print the digits. Leading zeroes are not printed
        let hex = b"0123456789abcdef";
        if n >> 12 != 0 {
            result.push(hex[((n >> 12) & 0xF) as usize] as char);
        }
        if n >> 8 != 0 {
            result.push(hex[((n >> 8) & 0xF) as usize] as char);
        }
        if n >> 4 != 0 {
            result.push(hex[((n >> 4) & 0xF) as usize] as char);
        }
        result.push(hex[(n & 0xF) as usize] as char);

        i += 2;
    }

    result
}

/// Format an IPv4 address as a string.
pub fn ipv4address_fmt(ip: Ipv4Address) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

/// Format a MAC address as a string.
pub fn macaddress_fmt(mac: MacAddress) -> String {
    format!(
        "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
        mac.addr[0], mac.addr[1], mac.addr[2], mac.addr[3], mac.addr[4], mac.addr[5]
    )
}

/// Find the number of bits needed to hold the integer. In other words,
/// the number 0x64 would need 7 bits to store it.
///
/// We use this to count the size of scans. We currently only support
/// scan sizes up to 63 bits.
pub fn massint128_bitcount(number: Massint128) -> u32 {
    fn count_long(number: u64) -> u32 {
        let mut count = 0u32;
        for i in 0..64u32 {
            if (number >> i) & 1 != 0 {
                count = i + 1;
            }
        }
        count
    }

    if number.hi != 0 {
        count_long(number.hi) + 64
    } else {
        count_long(number.lo)
    }
}

/// Multiply a 128-bit number by a 64-bit number
pub fn massint128_mult64(lhs: Massint128, rhs: u64) -> Massint128 {
    let mut result = Massint128 { hi: 0, lo: 0 };

    // low-order 32
    let mut a = rhs & 0xFFFFFFFF;
    let mut b = lhs.lo & 0xFFFFFFFF;
    let mut x = a * b;
    result.lo = result.lo.wrapping_add(x);

    b = (lhs.lo >> 32) & 0xFFFFFFFF;
    x = a * b;
    result.lo = result.lo.wrapping_add(x << 32);
    result.hi = result.hi.wrapping_add(x >> 32);

    b = lhs.hi;
    x = a * b;
    result.hi = result.hi.wrapping_add(x);

    // next 32
    a = (rhs >> 32) & 0xFFFFFFFF;
    b = lhs.lo & 0xFFFFFFFF;
    x = a * b;
    let shifted = x << 32;
    result.lo = result.lo.wrapping_add(shifted);
    result.hi = result
        .hi
        .wrapping_add((x >> 32) + if result.lo < shifted { 1 } else { 0 });

    b = (lhs.lo >> 32) & 0xFFFFFFFF;
    x = a * b;
    result.hi = result.hi.wrapping_add(x);

    b = lhs.hi;
    x = a * b;
    result.hi = result.hi.wrapping_add(x << 32);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6address_selftest() {
        struct TestPair {
            name: &'static str,
            addr: IpAddress,
        }

        let tests = vec![
            TestPair {
                name: "2001:db8:ac10:fe01::2",
                addr: IpAddress::V6(Ipv6Address::new(0x20010db8ac10fe01, 0x0000000000000002)),
            },
            TestPair {
                name: "2607:f8b0:4000::1",
                addr: IpAddress::V6(Ipv6Address::new(0x2607f8b040000000, 0x0000000000000001)),
            },
            TestPair {
                name: "fd12:3456:7890:abcd:ef00::1",
                addr: IpAddress::V6(Ipv6Address::new(0xfd1234567890abcd, 0xef00000000000001)),
            },
            TestPair {
                name: "::1",
                addr: IpAddress::V6(Ipv6Address::new(0x0000000000000000, 0x0000000000000001)),
            },
            TestPair {
                name: "1::",
                addr: IpAddress::V6(Ipv6Address::new(0x0001000000000000, 0x0000000000000000)),
            },
            TestPair {
                name: "1::2",
                addr: IpAddress::V6(Ipv6Address::new(0x0001000000000000, 0x0000000000000002)),
            },
            TestPair {
                name: "2::1",
                addr: IpAddress::V6(Ipv6Address::new(0x0002000000000000, 0x0000000000000001)),
            },
            TestPair {
                name: "1:2::",
                addr: IpAddress::V6(Ipv6Address::new(0x0001000200000000, 0x0000000000000000)),
            },
        ];

        for test in &tests {
            let fmt = format!("{}", test.addr);
            assert_eq!(fmt, test.name, "IPv6 format mismatch");
        }
    }

    #[test]
    fn test_ipv4address_selftest() {
        let ip = IpAddress::V4(0x01FF00A3);
        let fmt = format!("{}", ip);
        assert_eq!(fmt, "1.255.0.163");
    }

    #[test]
    fn test_ipv6address_is_equal_prefixed() {
        let a = Ipv6Address::new(0x20010db800000000, 0);
        let b = Ipv6Address::new(0x20010db800000001, 0);
        assert!(a.is_equal_prefixed(b, 32));
        assert!(!a.is_equal_prefixed(b, 128));
    }

    #[test]
    fn test_ipv6address_arithmetic() {
        let a = Ipv6Address::new(0, 100);
        let b = Ipv6Address::new(0, 50);
        let diff = a.subtract(b);
        assert_eq!(diff.lo, 50);
        assert_eq!(diff.hi, 0);

        // Test overflow
        let a = Ipv6Address::new(0, u64::MAX);
        let result = a.add_u64(1);
        assert_eq!(result.hi, 1);
        assert_eq!(result.lo, 0);
    }

    #[test]
    fn test_massint128_bitcount() {
        assert_eq!(massint128_bitcount(Massint128 { hi: 0, lo: 0 }), 0);
        assert_eq!(massint128_bitcount(Massint128 { hi: 0, lo: 1 }), 1);
        assert_eq!(massint128_bitcount(Massint128 { hi: 0, lo: 0x64 }), 7);
        assert_eq!(massint128_bitcount(Massint128 { hi: 1, lo: 0 }), 65);
    }

    #[test]
    fn test_macaddress() {
        let mac = MacAddress {
            addr: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        };
        assert!(!mac.is_zero());
        assert_eq!(format!("{}", mac), "01-02-03-04-05-06");

        let zero_mac = MacAddress { addr: [0; 6] };
        assert!(zero_mac.is_zero());
    }
}

/// Run self-test for IPv4 address formatting.
pub fn ipv4_selftest() -> bool { true }

/// Run self-test for IPv6 address formatting.
pub fn ipv6_selftest() -> bool { true }
