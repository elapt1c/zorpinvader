//! Duplicate response detection using hash-based deduplication.
//!
//! Since ZorpInvader is a stateless scanner, it may receive multiple responses
//! for the same probe (e.g., retransmissions or duplicate network paths).
//! This module maintains a fixed-size hash table to filter out duplicates
//! without requiring unbounded memory.
//!
//! The algorithm uses a bucket-based approach where each hash bucket holds
//! 4 entries. New entries are prepended, pushing older entries out (aging).
//! Frequently-seen entries migrate to the front of their bucket.

use crate::massip::addr::{IpAddress, Ipv4Address, Ipv6Address};

/// Number of hash buckets (must be power of 2).
const DEDUP_ENTRIES: usize = 65536;

/// Entries per bucket for aging/collision handling.
const BUCKET_SIZE: usize = 4;

/// FNV-1a hash seed value.
const FNV1A_SEED: u32 = 0x811C_9DC5;

/// FNV-1a prime multiplier.
const FNV1A_PRIME: u32 = 0x0100_0193;

/// Hash table for duplicate detection.
///
/// Contains separate arrays for IPv4 and IPv6 entries since they
/// have different address sizes and hash functions.
pub struct DedupTable {
    /// IPv4 dedup entries (heap-allocated to avoid stack overflow)
    entries: Vec<[DedupEntryV4; BUCKET_SIZE]>,

    /// IPv6 dedup entries (heap-allocated to avoid stack overflow)
    entries6: Vec<[DedupEntryV6; BUCKET_SIZE]>,
}

/// A single dedup entry for IPv4 connections.
#[derive(Clone, Copy, Default)]
struct DedupEntryV4 {
    ip_them: u32,
    port_them: u16,
    ip_me: u32,
    port_me: u16,
}

/// A single dedup entry for IPv6 connections.
#[derive(Clone, Copy, Default)]
struct DedupEntryV6 {
    ip_them: Ipv6Address,
    ip_me: Ipv6Address,
    port_them: u16,
    port_me: u16,
}

impl Default for DedupTable {
    fn default() -> Self {
        Self::new()
    }
}

impl DedupTable {
    /// Create a new deduplication table.
    ///
    /// Allocates and zero-initializes the hash table on the heap
    /// (using Vec to avoid stack overflow from large Box::new).
    pub fn new() -> Self {
        DedupTable {
            entries: vec![[DedupEntryV4::default(); BUCKET_SIZE]; DEDUP_ENTRIES],
            entries6: vec![[DedupEntryV6::default(); BUCKET_SIZE]; DEDUP_ENTRIES],
        }
    }

    /// Check if a response is a duplicate.
    ///
    /// Returns `true` if this exact combination of (ip_them, port_them, ip_me, port_me)
    /// has been seen recently. If not a duplicate, the entry is added to the table.
    ///
    /// # Arguments
    ///
    /// * `ip_them` - Remote IP address
    /// * `port_them` - Remote port
    /// * `ip_me` - Local IP address
    /// * `port_me` - Local port
    pub fn is_duplicate(
        &mut self,
        ip_them: IpAddress,
        port_them: u32,
        ip_me: IpAddress,
        port_me: u32,
    ) -> bool {
        match (ip_them, ip_me) {
            (IpAddress::V4(them), IpAddress::V4(me)) => {
                self.is_duplicate_v4(them, port_them, me, port_me)
            }
            (IpAddress::V6(them), IpAddress::V6(me)) => {
                self.is_duplicate_v6(them, port_them, me, port_me)
            }
            _ => false, // Mixed address families shouldn't happen
        }
    }

    /// Check for duplicate IPv4 response.
    fn is_duplicate_v4(
        &mut self,
        ip_them: Ipv4Address,
        port_them: u32,
        ip_me: Ipv4Address,
        port_me: u32,
    ) -> bool {
        // Hash the socket tuple
        let hash = (ip_them.wrapping_add(port_them))
            ^ ((ip_me).wrapping_add(ip_them >> 16))
            ^ (ip_them >> 24)
            ^ port_me;
        let idx = (hash as usize) & (DEDUP_ENTRIES - 1);

        let bucket = &mut self.entries[idx];

        // Search for existing entry
        for i in 0..BUCKET_SIZE {
            if bucket[i].ip_them == ip_them
                && bucket[i].port_them == port_them as u16
                && bucket[i].ip_me == ip_me
                && bucket[i].port_me == port_me as u16
            {
                // Found it - move to front for better cache behavior
                if i > 0 {
                    bucket.swap(0, i);
                }
                return true;
            }
        }

        // Not found - add to front, pushing others back
        for j in (1..BUCKET_SIZE).rev() {
            bucket[j] = bucket[j - 1];
        }

        bucket[0] = DedupEntryV4 {
            ip_them,
            port_them: port_them as u16,
            ip_me,
            port_me: port_me as u16,
        };

        false
    }

    /// Check for duplicate IPv6 response.
    fn is_duplicate_v6(
        &mut self,
        ip_them: Ipv6Address,
        port_them: u32,
        ip_me: Ipv6Address,
        port_me: u32,
    ) -> bool {
        // Hash using FNV-1a
        let hash = self.hash_ipv6(ip_them, port_them, ip_me, port_me);
        let idx = (hash as usize) & (DEDUP_ENTRIES - 1);

        let bucket = &mut self.entries6[idx];

        // Search for existing entry
        for i in 0..BUCKET_SIZE {
            if bucket[i].ip_them.is_equal(ip_them)
                && bucket[i].port_them == port_them as u16
                && bucket[i].ip_me.is_equal(ip_me)
                && bucket[i].port_me == port_me as u16
            {
                // Found it - move to front
                if i > 0 {
                    bucket.swap(0, i);
                }
                return true;
            }
        }

        // Not found - add to front
        for j in (1..BUCKET_SIZE).rev() {
            bucket[j] = bucket[j - 1];
        }

        bucket[0] = DedupEntryV6 {
            ip_them,
            port_them: port_them as u16,
            ip_me,
            port_me: port_me as u16,
        };

        false
    }

    /// Hash an IPv6 socket tuple using FNV-1a.
    fn hash_ipv6(
        &self,
        ip_them: Ipv6Address,
        port_them: u32,
        ip_me: Ipv6Address,
        port_me: u32,
    ) -> u32 {
        let mut hash = FNV1A_SEED;

        hash = fnv1a_u64(ip_them.hi, hash);
        hash = fnv1a_u64(ip_them.lo, hash);
        hash = fnv1a_u16(port_them as u16, hash);
        hash = fnv1a_u64(ip_me.hi, hash);
        hash = fnv1a_u64(ip_me.lo, hash);
        hash = fnv1a_u16(port_me as u16, hash);

        hash
    }

    /// Run self-test to verify dedup functionality.
    ///
    /// Returns `true` if all tests pass.
    pub fn selftest() -> bool {
        let mut table = DedupTable::new();

        // Test 1: First check should not be a duplicate
        let ip_me = IpAddress::V4(0x12345678);
        let ip_them = IpAddress::V4(0x0abcdef0);
        let port_me = 0x1234;
        let port_them = 0xfedc;

        if table.is_duplicate(ip_them, port_them, ip_me, port_me) {
            eprintln!("dedup selftest: first check should not be duplicate");
            return false;
        }

        // Test 2: Second check should be a duplicate
        if !table.is_duplicate(ip_them, port_them, ip_me, port_me) {
            eprintln!("dedup selftest: second check should be duplicate");
            return false;
        }

        // Test 3: IPv6 dedup
        let ip_me6 = IpAddress::V6(Ipv6Address::new(0x12345678, 0x12345678));
        let ip_them6 = IpAddress::V6(Ipv6Address::new(0x0abcdef0, 0x0abcdef0));

        if table.is_duplicate(ip_them6, port_them, ip_me6, port_me) {
            eprintln!("dedup selftest: IPv6 first check should not be duplicate");
            return false;
        }

        if !table.is_duplicate(ip_them6, port_them, ip_me6, port_me) {
            eprintln!("dedup selftest: IPv6 second check should be duplicate");
            return false;
        }

        // Test 4: Statistical test with many random entries
        let mut seed: u32 = 0;
        let mut found_matches = 0;

        for _ in 0..100_000 {
            let ip_me = IpAddress::V4(lcg_rand(&mut seed) & 0xFF800000);
            let ip_them = IpAddress::V4(lcg_rand(&mut seed) & 0x1FF);
            let port_me = (lcg_rand(&mut seed) & 0xFF80) as u32;
            let port_them = (lcg_rand(&mut seed) & 0x1FF) as u32;

            if table.is_duplicate(ip_them, port_them, ip_me, port_me) {
                found_matches += 1;
            }
        }

        // Expect around 30 matches (statistically)
        if found_matches == 0 || found_matches > 200 {
            eprintln!(
                "dedup selftest: expected ~30 matches, got {}",
                found_matches
            );
            return false;
        }

        true
    }
}

/// FNV-1a hash helper for a single byte.
#[inline]
fn fnv1a_byte(c: u8, hash: u32) -> u32 {
    (c as u32 ^ hash).wrapping_mul(FNV1A_PRIME)
}

/// FNV-1a hash helper for a u16.
#[inline]
fn fnv1a_u16(data: u16, hash: u32) -> u32 {
    let mut h = fnv1a_byte((data & 0xFF) as u8, hash);
    h = fnv1a_byte(((data >> 8) & 0xFF) as u8, h);
    h
}

/// FNV-1a hash helper for a u64.
#[inline]
fn fnv1a_u64(data: u64, hash: u32) -> u32 {
    let mut h = hash;
    for i in 0..8 {
        h = fnv1a_byte(((data >> (i * 8)) & 0xFF) as u8, h);
    }
    h
}

/// Simple deterministic PRNG for testing (matches C implementation).
fn lcg_rand(seed: &mut u32) -> u32 {
    const A: u32 = 214013;
    const C: u32 = 2531011;
    *seed = seed.wrapping_mul(A).wrapping_add(C);
    (*seed >> 16) & 0x7FFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedup_selftest() {
        assert!(DedupTable::selftest());
    }

    #[test]
    fn test_dedup_basic() {
        let mut table = DedupTable::new();

        let ip1 = IpAddress::V4(0x0A000001);
        let ip2 = IpAddress::V4(0x0A000002);

        // Different tuples should not be duplicates
        assert!(!table.is_duplicate(ip1, 80, ip2, 12345));
        assert!(!table.is_duplicate(ip2, 80, ip1, 12345));

        // Same tuple as first call → IS a duplicate
        assert!(table.is_duplicate(ip1, 80, ip2, 12345));

        // Completely new tuple should not be duplicate
        let ip3 = IpAddress::V4(0xC0A80001);
        assert!(!table.is_duplicate(ip3, 443, ip1, 54321));
        assert!(table.is_duplicate(ip3, 443, ip1, 54321));
    }

    #[test]
    fn test_fnv1a() {
        // Test that FNV-1a produces expected values
        let hash = fnv1a_byte(b'a', FNV1A_SEED);
        assert_ne!(hash, FNV1A_SEED);
    }
}
