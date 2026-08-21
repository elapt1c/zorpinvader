//! RST filter — suppress duplicate RST transmissions.
//!
//! In theory, we should transmit a RST packet every time we receive an
//! invalid TCP packet. In practice, this can lead to endless transmits
//! when the other side continues to transmit bad packets (accidentally
//! or as an intentional attack on the scanner).
//!
//! The design is a simple non-deterministic algorithm: hash the IP/port
//! combo, update a counter at that bucket, and stop transmitting resets
//! once the limit is reached. A random bucket is also slowly emptied on
//! each call, so an occasional RST still gets through.
//!
//! **Ported from C `misc-rstfilter.c`.**

use crate::crypto::siphash24;
use crate::massip::addr::IpAddress;

/// Filter that rate-limits outgoing RST packets per source/dest pair.
///
/// Each IP/port combination is hashed into a bucket. The bucket uses a
/// nibble (4-bit) counter — when it reaches 15 the packet is filtered.
/// A random bucket is decremented on each call so the filter slowly
/// drains.
pub struct ResetFilter {
    /// Random seed chosen at startup so adversaries can't predict buckets.
    seed: u64,
    /// Number of buckets (always a power of two).
    bucket_count: usize,
    /// Mask for fast modulo: `bucket_count - 1`.
    bucket_mask: usize,
    /// Monotonic counter mixed into the random-drain hash.
    counter: u32,
    /// Packed nibble counters — `bucket_count / 2` bytes, each holding two
    /// 4-bit counters (low and high nibble).
    buckets: Vec<u8>,
}

/// Round up to the nearest power of two. Returns 1 for input 0.
fn next_pow2(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    if n & (n - 1) == 0 {
        return n;
    }
    let mut bit_count = 0usize;
    let mut v = n;
    while v != 0 {
        v >>= 1;
        bit_count += 1;
    }
    1usize << bit_count
}

impl ResetFilter {
    /// Create a new RST filter.
    ///
    /// * `seed` — random seed (e.g. from [`get_entropy`]) so that
    ///   adversaries can't predict bucket placement.
    /// * `bucket_count` — desired number of buckets; will be rounded up
    ///   to the nearest power of two. 16384 is a reasonable default.
    pub fn new(seed: u64, bucket_count: usize) -> Self {
        let count = next_pow2(bucket_count);
        ResetFilter {
            seed,
            bucket_count: count,
            bucket_mask: count - 1,
            counter: 0,
            // Each byte holds two nibble-counters, so we need count/2 bytes.
            buckets: vec![0u8; count / 2],
        }
    }

    /// Test whether the given RST packet should be **filtered** (suppressed).
    ///
    /// Returns `true` if the packet should be dropped (filtered out),
    /// `false` if it should be transmitted.
    ///
    /// As a side-effect, a random bucket is decremented (slow drain).
    pub fn is_filter(
        &mut self,
        src_ip: IpAddress,
        src_port: u32,
        dst_ip: IpAddress,
        dst_port: u32,
    ) -> bool {
        // Build the input data (5 × u64 in little-endian)
        let mut input = [0u64; 5];
        match (src_ip, dst_ip) {
            (IpAddress::V4(src), IpAddress::V4(dst)) => {
                input[0] = src as u64;
                input[1] = src_port as u64;
                input[2] = dst as u64;
                input[3] = dst_port as u64;
            }
            (IpAddress::V6(src), IpAddress::V6(dst)) => {
                input[0] = src.hi;
                input[1] = src.lo;
                input[2] = dst.hi;
                input[3] = dst.lo;
                input[4] = ((src_port as u64) << 16) | (dst_port as u64);
            }
            _ => {
                // Mixed IP versions — shouldn't happen
                return false;
            }
        }

        let key = [self.seed, self.seed];

        // Hash the input and select a bucket
        let hash = siphash24(&input_to_bytes(&input), key);
        let index = (hash as usize) & self.bucket_mask;

        // Read/update the nibble counter at this bucket
        let mut result = false;
        let byte_idx = index / 2;
        if index & 1 != 0 {
            // Odd index → low nibble
            if (*&self.buckets[byte_idx] & 0x0F) == 0x0F {
                result = true; // filter out
            } else {
                self.buckets[byte_idx] = self.buckets[byte_idx].wrapping_add(0x01);
            }
        } else {
            // Even index → high nibble
            if (self.buckets[byte_idx] & 0xF0) == 0xF0 {
                result = true; // filter out
            } else {
                self.buckets[byte_idx] = self.buckets[byte_idx].wrapping_add(0x10);
            }
        }

        // Empty a random bucket (slow drain)
        let counter = self.counter;
        self.counter = self.counter.wrapping_add(1);
        let drain_input: [u64; 2] = [hash as u64, counter as u64];
        let drain_hash = siphash24(&u64_pair_to_bytes(&drain_input), key);
        let drain_index = (drain_hash as usize) & self.bucket_mask;
        let drain_byte = drain_index / 2;
        if drain_index & 1 != 0 {
            if self.buckets[drain_byte] & 0x0F != 0 {
                self.buckets[drain_byte] = self.buckets[drain_byte].wrapping_sub(0x01);
            }
        } else {
            if self.buckets[drain_byte] & 0xF0 != 0 {
                self.buckets[drain_byte] = self.buckets[drain_byte].wrapping_sub(0x10);
            }
        }

        result
    }

    /// Self-test: verify that the first 15 packets pass, then most are filtered.
    ///
    /// Returns `true` on success.
    pub fn selftest() -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let src = IpAddress::V4(1);
        let dst = IpAddress::V4(3);

        let mut rf = ResetFilter::new(seed, 64);

        // Verify the first 15 packets pass the filter
        for _ in 0..15 {
            if rf.is_filter(src, 2, dst, 4) {
                eprintln!("[-] rstfilter failed: early packet filtered");
                return false;
            }
        }

        // Run 1000 more times and count filtered vs passed
        let mut count_filtered = 0u32;
        let mut count_passed = 0u32;
        for _ in 0..1000 {
            if rf.is_filter(src, 2, dst, 4) {
                count_filtered += 1;
            } else {
                count_passed += 1;
            }
        }

        // SOME must have passed, due to us emptying random buckets
        if count_passed == 0 {
            eprintln!("[-] rstfilter failed: no packets passed");
            return false;
        }

        // However, the vast majority should be filtered
        if count_passed > count_filtered / 10 {
            eprintln!(
                "[-] rstfilter failed: too many passed ({}) vs filtered ({})",
                count_passed, count_filtered
            );
            return false;
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Helpers to pack u64 arrays into byte slices for siphash24
// ---------------------------------------------------------------------------

/// Pack five u64 values into 40 bytes (little-endian), matching the C code's
/// `uint64_t data[5]` passed to `siphash24`.
fn input_to_bytes(input: &[u64; 5]) -> Vec<u8> {
    let mut bytes = vec![0u8; 40];
    for (i, &val) in input.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
    }
    bytes
}

/// Pack two u64 values into 16 bytes (little-endian).
fn u64_pair_to_bytes(input: &[u64; 2]) -> Vec<u8> {
    let mut bytes = vec![0u8; 16];
    bytes[0..8].copy_from_slice(&input[0].to_le_bytes());
    bytes[8..16].copy_from_slice(&input[1].to_le_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_pow2_values() {
        assert_eq!(next_pow2(0), 1);
        assert_eq!(next_pow2(1), 1);
        assert_eq!(next_pow2(2), 2);
        assert_eq!(next_pow2(3), 4);
        assert_eq!(next_pow2(4), 4);
        assert_eq!(next_pow2(5), 8);
        assert_eq!(next_pow2(100), 128);
        assert_eq!(next_pow2(1024), 1024);
        assert_eq!(next_pow2(16384), 16384);
    }

    #[test]
    fn selftest_passes() {
        assert!(ResetFilter::selftest());
    }

    #[test]
    fn first_packets_pass() {
        let mut rf = ResetFilter::new(42, 128);
        let src = IpAddress::V4(10);
        let dst = IpAddress::V4(20);
        for _ in 0..14 {
            assert!(!rf.is_filter(src, 1234, dst, 80));
        }
    }
}
