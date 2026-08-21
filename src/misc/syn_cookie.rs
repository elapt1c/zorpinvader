//! SYN cookie generation for stateless scanning.
//!
//! Creates a hash of the src/dst IP/port combination so that incoming
//! responses can be matched with their original requests without keeping
//! per-connection state.
//!
//! **Ported from C `syn-cookie.c`.**  The hash values produced by these
//! functions **must** be identical to the C implementation, because they
//! are embedded in transmitted packets and checked on receive.

use crate::crypto::siphash24;
use crate::massip::addr::{IpAddress, Ipv4Address, Ipv6Address};
use std::time::{SystemTime, UNIX_EPOCH};

/// Gather entropy (randomness) to seed hashing with.
///
/// NOTE: Mostly it's here to amuse cryptographers with its lulz.
pub fn get_entropy() -> u64 {
    let mut entropy: [u64; 2] = [0, 0];

    // Gather some random bits
    for _ in 0..64 {
        let nano = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;
        entropy[0] = entropy[0].wrapping_add(nano);
        // time(0) equivalent
        let _ = SystemTime::now();
        // fopen("/", "r") side effect -- just a timing jitter source
        let _ = std::fs::metadata("/");
        entropy[1] = (entropy[1] << 1) | (entropy[0] >> 63);
        entropy[0] <<= 1;
    }

    // XOR with epoch seconds
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    entropy[0] ^= now_secs;

    // Try reading from /dev/urandom (read exactly 16 bytes, not the entire device)
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let mut urand = [0u8; 16];
        if f.read_exact(&mut urand).is_ok() {
            let urand0 = u64::from_le_bytes(urand[0..8].try_into().unwrap());
            let urand1 = u64::from_le_bytes(urand[8..16].try_into().unwrap());
            entropy[0] ^= urand0;
            entropy[1] ^= urand1;
        }
    }

    let nano = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    entropy[0] ^= nano;

    entropy[0] ^ entropy[1]
}

/// Create a SYN cookie from IPv4 addresses and ports.
///
/// The C code packs `[ip_them, port_them, ip_me, port_me]` as four `unsigned`
/// (u32) values and hashes 16 bytes with SipHash-2-4, using `entropy` as
/// both halves of the 128-bit key.
pub fn syn_cookie_ipv4(
    ip_them: Ipv4Address,
    port_them: u32,
    ip_me: Ipv4Address,
    port_me: u32,
    entropy: u64,
) -> u64 {
    let key = [entropy, entropy];

    // Pack exactly like the C code: four u32 values in native byte order,
    // but since the C code uses an array of `unsigned` and casts to `void*`
    // for siphash24, and siphash24 reads byte-by-byte in little-endian,
    // we must pack in little-endian byte order to match.
    let mut data = [0u8; 16];
    data[0..4].copy_from_slice(&ip_them.to_le_bytes());
    data[4..8].copy_from_slice(&port_them.to_le_bytes());
    data[8..12].copy_from_slice(&ip_me.to_le_bytes());
    data[12..16].copy_from_slice(&port_me.to_le_bytes());

    siphash24(&data, key)
}

/// Create a SYN cookie from IPv6 addresses and ports.
///
/// The C code packs `[ip_them.hi, ip_them.lo, ip_me.hi, ip_me.lo,
/// port_them<<16 | port_me]` as five `uint64_t` values (40 bytes) and
/// hashes with SipHash-2-4.
pub fn syn_cookie_ipv6(
    ip_them: Ipv6Address,
    port_them: u32,
    ip_me: Ipv6Address,
    port_me: u32,
    entropy: u64,
) -> u64 {
    let key = [entropy, entropy];

    // Pack exactly like the C code: five u64 values in little-endian
    let mut data = [0u8; 40];
    data[0..8].copy_from_slice(&ip_them.hi.to_le_bytes());
    data[8..16].copy_from_slice(&ip_them.lo.to_le_bytes());
    data[16..24].copy_from_slice(&ip_me.hi.to_le_bytes());
    data[24..32].copy_from_slice(&ip_me.lo.to_le_bytes());
    let ports_combined: u64 = ((port_them as u64) << 16) | (port_me as u64);
    data[32..40].copy_from_slice(&ports_combined.to_le_bytes());

    siphash24(&data, key)
}

/// Create a SYN cookie from version-agnostic IP addresses and ports.
///
/// Dispatches to `syn_cookie_ipv4` or `syn_cookie_ipv6` depending on
/// the IP address version.
pub fn syn_cookie(
    ip_them: IpAddress,
    port_them: u32,
    ip_me: IpAddress,
    port_me: u32,
    entropy: u64,
) -> u64 {
    match (ip_them, ip_me) {
        (IpAddress::V4(them), IpAddress::V4(me)) => {
            syn_cookie_ipv4(them, port_them, me, port_me, entropy)
        }
        (IpAddress::V6(them), IpAddress::V6(me)) => {
            syn_cookie_ipv6(them, port_them, me, port_me, entropy)
        }
        _ => {
            // Mismatched IP versions — shouldn't happen in practice
            log::error!("syn_cookie: mismatched IP versions");
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the same inputs produce the same hash (determinism).
    #[test]
    fn syn_cookie_ipv4_deterministic() {
        let entropy = 0xDEADBEEF_CAFEBABEu64;
        let a = syn_cookie_ipv4(0x0A000001, 80, 0x0A000002, 12345, entropy);
        let b = syn_cookie_ipv4(0x0A000001, 80, 0x0A000002, 12345, entropy);
        assert_eq!(a, b);
    }

    /// Different inputs should (almost certainly) produce different hashes.
    #[test]
    fn syn_cookie_ipv4_different_inputs() {
        let entropy = 0x1234567890ABCDEFu64;
        let a = syn_cookie_ipv4(0x0A000001, 80, 0x0A000002, 12345, entropy);
        let b = syn_cookie_ipv4(0x0A000001, 443, 0x0A000002, 12345, entropy);
        assert_ne!(a, b);
    }

    /// IPv6 cookie should also be deterministic.
    #[test]
    fn syn_cookie_ipv6_deterministic() {
        let entropy = 0xFEEDFACE_DEADBEEFu64;
        let them = Ipv6Address::new(0x2001_0db8_0000_0000, 0x0000_0000_0000_0001);
        let me = Ipv6Address::new(0x2001_0db8_0000_0000, 0x0000_0000_0000_0002);
        let a = syn_cookie_ipv6(them, 443, me, 54321, entropy);
        let b = syn_cookie_ipv6(them, 443, me, 54321, entropy);
        assert_eq!(a, b);
    }

    /// The version-agnostic wrapper should dispatch correctly.
    #[test]
    fn syn_cookie_dispatch_v4() {
        let entropy = 0xABCDu64;
        let them = IpAddress::V4(0xC0A80001);
        let me = IpAddress::V4(0xC0A80002);
        let a = syn_cookie(them, 80, me, 1234, entropy);
        let b = syn_cookie_ipv4(0xC0A80001, 80, 0xC0A80002, 1234, entropy);
        assert_eq!(a, b);
    }

    #[test]
    fn syn_cookie_dispatch_v6() {
        let entropy = 0xABCDu64;
        let them = IpAddress::V6(Ipv6Address::new(1, 2));
        let me = IpAddress::V6(Ipv6Address::new(3, 4));
        let a = syn_cookie(them, 80, me, 1234, entropy);
        let b = syn_cookie_ipv6(Ipv6Address::new(1, 2), 80, Ipv6Address::new(3, 4), 1234, entropy);
        assert_eq!(a, b);
    }

    /// Entropy function should return non-zero values (probabilistic).
    #[test]
    fn get_entropy_nonzero() {
        // Run a few times — extremely unlikely to get zero every time
        let results: Vec<u64> = (0..5).map(|_| get_entropy()).collect();
        assert!(results.iter().any(|&v| v != 0));
    }
}
