//! IPv4 address-set algebra.
//!
//! A scan's coverage is a *set of addresses*, not a position in a queue, so
//! resuming needs exact set arithmetic: union, difference and intersection over
//! `u32` address space. The set is stored as sorted, disjoint, non-adjacent
//! inclusive intervals. That representation is exact, and its size is bounded by
//! the number of *discontinuities* in the covered space rather than the number of
//! addresses — scanning 1000 consecutive /24s costs one interval, not 256k
//! entries.
//!
//! Serialisation is a minimal CIDR decomposition of each interval. Note that the
//! decomposition is per-interval: `1.2.3.0/24` plus `1.2.4.0/24` merges into the
//! single interval `1.2.3.0-1.2.4.255`, but that interval is *not* a CIDR (a /23
//! would have to start on an even /23 boundary), so it decomposes back into the
//! same two CIDRs. Adjacent runs that *are* CIDR-aligned (`1.2.2.0/24` +
//! `1.2.3.0/24` → `1.2.2.0/23`) do collapse.

use serde::{Deserialize, Serialize};

/// A closed interval of IPv4 addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interval {
    pub begin: u32,
    pub end: u32,
}

impl Interval {
    pub fn new(begin: u32, end: u32) -> Self {
        Interval { begin, end }
    }

    /// Number of addresses in the interval.
    pub fn len(&self) -> u64 {
        self.end as u64 - self.begin as u64 + 1
    }

}

/// A set of IPv4 addresses held as sorted, disjoint, non-adjacent intervals.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RangeSet4 {
    ranges: Vec<Interval>,
}

impl RangeSet4 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_intervals<I: IntoIterator<Item = (u32, u32)>>(items: I) -> Self {
        let mut set = Self::new();
        for (begin, end) in items {
            set.add(begin, end);
        }
        set
    }

    /// Parse a list of CIDR strings (`1.2.3.0/24`, `1.2.3.4`).
    pub fn from_cidrs<S: AsRef<str>>(items: &[S]) -> Result<Self, String> {
        let mut set = Self::new();
        for item in items {
            set.add_cidr(item.as_ref())?;
        }
        Ok(set)
    }

    /// Insert an interval, merging with any overlapping or adjacent interval.
    pub fn add(&mut self, begin: u32, end: u32) {
        if begin > end {
            return;
        }

        // First interval that could touch [begin, end]: its end+1 >= begin.
        let mut first = 0usize;
        while first < self.ranges.len() {
            if self.ranges[first].end as u64 + 1 < begin as u64 {
                first += 1;
            } else {
                break;
            }
        }

        let mut merged = Interval::new(begin, end);
        let mut last = first;
        while last < self.ranges.len() && self.ranges[last].begin as u64 <= merged.end as u64 + 1 {
            merged.begin = merged.begin.min(self.ranges[last].begin);
            merged.end = merged.end.max(self.ranges[last].end);
            last += 1;
        }

        self.ranges.splice(first..last, [merged]);
    }

    /// Insert a CIDR or bare address.
    pub fn add_cidr(&mut self, spec: &str) -> Result<(), String> {
        let (begin, end) = parse_cidr(spec)?;
        self.add(begin, end);
        Ok(())
    }

    pub fn contains(&self, addr: u32) -> bool {
        self.ranges
            .binary_search_by(|r| {
                if addr < r.begin {
                    std::cmp::Ordering::Greater
                } else if addr > r.end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Total number of addresses in the set.
    pub fn count(&self) -> u64 {
        self.ranges.iter().map(|r| r.len()).sum()
    }

    pub fn intervals(&self) -> &[Interval] {
        &self.ranges
    }

    pub fn first(&self) -> Option<Interval> {
        self.ranges.first().copied()
    }

    pub fn clear(&mut self) {
        self.ranges.clear();
    }

    pub fn union_with(&mut self, other: &RangeSet4) {
        for r in &other.ranges {
            self.add(r.begin, r.end);
        }
    }

    pub fn union(&self, other: &RangeSet4) -> RangeSet4 {
        let mut out = self.clone();
        out.union_with(other);
        out
    }

    /// Remove every address present in `other`.
    pub fn subtract(&mut self, other: &RangeSet4) {
        if other.ranges.is_empty() || self.ranges.is_empty() {
            return;
        }

        let mut out: Vec<Interval> = Vec::with_capacity(self.ranges.len());
        for r in &self.ranges {
            let mut cur_begin = r.begin as u64;
            let cur_end = r.end as u64;

            for o in &other.ranges {
                let ob = o.begin as u64;
                let oe = o.end as u64;
                if oe < cur_begin || ob > cur_end {
                    continue;
                }
                if ob > cur_begin {
                    out.push(Interval::new(cur_begin as u32, (ob - 1) as u32));
                }
                if oe == u64::from(u32::MAX) {
                    cur_begin = cur_end + 1;
                } else {
                    cur_begin = (oe + 1).max(cur_begin);
                }
                if cur_begin > cur_end {
                    break;
                }
            }

            if cur_begin <= cur_end {
                out.push(Interval::new(cur_begin as u32, cur_end as u32));
            }
        }

        self.ranges = out;
    }

    /// Addresses present in both sets.
    pub fn intersect(&self, other: &RangeSet4) -> RangeSet4 {
        let mut out = RangeSet4::new();
        let mut i = 0usize;
        let mut j = 0usize;
        while i < self.ranges.len() && j < other.ranges.len() {
            let a = self.ranges[i];
            let b = other.ranges[j];
            let begin = a.begin.max(b.begin);
            let end = a.end.min(b.end);
            if begin <= end {
                out.add(begin, end);
            }
            if a.end < b.end {
                i += 1;
            } else {
                j += 1;
            }
        }
        out
    }

    /// Serialise as a minimal CIDR decomposition (one string per CIDR).
    pub fn to_cidrs(&self) -> Vec<String> {
        let mut out = Vec::new();
        for r in &self.ranges {
            for (begin, prefix) in range_to_cidrs(r.begin, r.end) {
                out.push(format_cidr(begin, prefix));
            }
        }
        out
    }

    /// Carve the set into aligned blocks of at most `chunk` addresses.
    ///
    /// Every block starts and ends on an aligned boundary for the largest power
    /// of two that divides its size, so each block is exactly one CIDR. This is
    /// what makes job allocation and coverage bookkeeping cheap: a block is
    /// either fully covered or not.
    pub fn blocks(&self, chunk: u64, next_id: &mut u64) -> Vec<Interval> {
        let chunk = chunk.max(1).min(1u64 << 32);
        let mut out = Vec::new();

        for r in &self.ranges {
            let mut cursor = r.begin as u64;
            let end = r.end as u64;
            while cursor <= end {
                // Largest aligned power of two starting at `cursor`...
                let mut size = if cursor == 0 {
                    1u64 << 32
                } else {
                    // u64 view keeps the 0-address case out of the shift below.
                    (cursor & cursor.wrapping_neg()) as u64
                };
                size = size.min(chunk);
                // ...trimmed until it fits inside the remaining interval.
                while size > 1 && cursor + size - 1 > end {
                    size >>= 1;
                }

                let begin = cursor as u32;
                let block_end = (cursor + size - 1) as u32;
                out.push(Interval::new(begin, block_end));
                *next_id += 1;
                cursor += size;
            }
        }

        out
    }
}

/// Parse `a.b.c.d` or `a.b.c.d/n` into an inclusive interval.
pub fn parse_cidr(spec: &str) -> Result<(u32, u32), String> {
    let spec = spec.trim();
    let (addr_part, prefix_part) = match spec.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (spec, None),
    };

    let addr = parse_ipv4(addr_part).ok_or_else(|| format!("invalid IPv4 address: {}", spec))?;
    let prefix: u32 = match prefix_part {
        Some(p) => p
            .parse()
            .map_err(|_| format!("invalid prefix length: {}", spec))?,
        None => 32,
    };
    if prefix > 32 {
        return Err(format!("prefix length out of range: {}", spec));
    }

    let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let begin = addr & mask;
    let end = begin | !mask;
    Ok((begin, end))
}

/// Parse a dotted-quad address.
pub fn parse_ipv4(s: &str) -> Option<u32> {
    let mut parts = s.split('.');
    let mut addr: u32 = 0;
    for _ in 0..4 {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let octet: u32 = part.parse().ok()?;
        if octet > 255 {
            return None;
        }
        addr = (addr << 8) | octet;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(addr)
}

/// Format an address as dotted quad.
pub fn format_ip(addr: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (addr >> 24) & 0xFF,
        (addr >> 16) & 0xFF,
        (addr >> 8) & 0xFF,
        addr & 0xFF
    )
}

/// Format `begin`/`prefix` as a CIDR string.
pub fn format_cidr(begin: u32, prefix: u8) -> String {
    format!("{}/{}", format_ip(begin), prefix)
}

/// Decompose an inclusive interval into the fewest CIDRs that cover it exactly.
pub fn range_to_cidrs(begin: u32, end: u32) -> Vec<(u32, u8)> {
    let mut out = Vec::new();
    if begin > end {
        return out;
    }
    let mut cursor = begin as u64;
    let end = end as u64;

    while cursor <= end {
        // Alignment limit: the largest power of two that starts a block here.
        let align = if cursor == 0 {
            1u64 << 32
        } else {
            cursor & cursor.wrapping_neg()
        };
        // Size limit: must not run past the end of the interval.
        let remaining = end - cursor + 1;
        let mut size = align.min(1u64 << 32);
        while size > remaining {
            size >>= 1;
        }
        let prefix = 32 - size.trailing_zeros() as u8;
        out.push((cursor as u32, prefix));
        cursor += size;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_cidrs() {
        assert_eq!(parse_cidr("10.0.0.0/8").unwrap(), (0x0A000000, 0x0AFFFFFF));
        assert_eq!(parse_cidr("1.2.3.4").unwrap(), (0x01020304, 0x01020304));
        assert_eq!(parse_cidr("0.0.0.0/0").unwrap(), (0, u32::MAX));
        assert!(parse_cidr("1.2.3.4/33").is_err());
        assert!(parse_cidr("1.2.3").is_err());
        assert!(parse_cidr("256.1.1.1").is_err());
    }

    #[test]
    fn adjacent_aligned_halves_collapse_to_one_cidr() {
        let mut set = RangeSet4::new();
        set.add_cidr("1.2.2.0/24").unwrap();
        set.add_cidr("1.2.3.0/24").unwrap();
        assert_eq!(set.intervals().len(), 1);
        assert_eq!(set.to_cidrs(), vec!["1.2.2.0/23".to_string()]);
        assert_eq!(set.count(), 512);
    }

    #[test]
    fn adjacent_unaligned_halves_merge_but_stay_two_cidrs() {
        // The user-visible case: /24s at 1.2.3.0 and 1.2.4.0 are contiguous, so
        // they merge into one interval, but no single CIDR covers exactly them.
        let mut set = RangeSet4::new();
        set.add_cidr("1.2.3.0/24").unwrap();
        set.add_cidr("1.2.4.0/24").unwrap();
        assert_eq!(set.intervals().len(), 1);
        assert_eq!(set.count(), 512);
        assert_eq!(
            set.to_cidrs(),
            vec!["1.2.3.0/24".to_string(), "1.2.4.0/24".to_string()]
        );
        assert!(set.contains(0x010203FF));
        assert!(set.contains(0x01020400));
        assert!(!set.contains(0x01020500));
    }

    #[test]
    fn all_space_round_trips_through_cidrs() {
        let mut set = RangeSet4::new();
        set.add_cidr("0.0.0.0/0").unwrap();
        assert_eq!(set.count(), 1u64 << 32);
        assert_eq!(set.to_cidrs(), vec!["0.0.0.0/0".to_string()]);
    }

    #[test]
    fn subtract_carves_holes() {
        let mut set = RangeSet4::new();
        set.add_cidr("0.0.0.0/0").unwrap();
        let mut excl = RangeSet4::new();
        excl.add_cidr("10.0.0.0/8").unwrap();
        excl.add_cidr("192.168.0.0/16").unwrap();
        set.subtract(&excl);

        assert_eq!(set.count(), (1u64 << 32) - (1 << 24) - (1 << 16));
        assert!(!set.contains(0x0A000001));
        assert!(!set.contains(0xC0A80001));
        assert!(set.contains(0x0B000001));
        assert!(set.contains(0xC0A90001));
        // Re-adding the excluded space must restore the whole /0 as one interval.
        let mut back = set.clone();
        back.union_with(&excl);
        assert_eq!(back.intervals().len(), 1);
        assert_eq!(back.count(), 1u64 << 32);
    }

    #[test]
    fn subtract_when_exclude_covers_the_end() {
        let mut set = RangeSet4::new();
        set.add(0x01020300, 0x010203FF);
        let mut excl = RangeSet4::new();
        excl.add(0x01020380, u32::MAX);
        set.subtract(&excl);
        assert_eq!(set.intervals(), &[Interval::new(0x01020300, 0x0102037F)]);

        let mut set = RangeSet4::new();
        set.add(0x01020300, 0x010203FF);
        let mut excl = RangeSet4::new();
        excl.add(0, 0x010202FF);
        set.subtract(&excl);
        assert_eq!(set.intervals(), &[Interval::new(0x01020300, 0x010203FF)]);
    }

    #[test]
    fn intersect_is_exact() {
        let mut a = RangeSet4::new();
        a.add_cidr("10.0.0.0/8").unwrap();
        let mut b = RangeSet4::new();
        b.add_cidr("10.128.0.0/9").unwrap();
        b.add_cidr("11.0.0.0/8").unwrap();
        let c = a.intersect(&b);
        assert_eq!(c.to_cidrs(), vec!["10.128.0.0/9".to_string()]);
    }

    #[test]
    fn blocks_are_cidr_aligned_and_cover_everything() {
        let mut set = RangeSet4::new();
        set.add_cidr("1.2.3.0/24").unwrap();
        let mut id = 0u64;
        let blocks = set.blocks(64, &mut id);
        assert_eq!(blocks.len(), 4);
        assert_eq!(id, 4);
        assert_eq!(blocks[0], Interval::new(0x01020300, 0x0102033F));
        assert_eq!(blocks[3], Interval::new(0x010203C0, 0x010203FF));

        let mut set = RangeSet4::new();
        set.add_cidr("0.0.0.0/0").unwrap();
        let mut id = 0u64;
        let blocks = set.blocks(1 << 20, &mut id);
        assert_eq!(blocks.len(), 4096);
        assert_eq!(blocks[0], Interval::new(0, (1 << 20) - 1));
        assert_eq!(blocks[4095].end, u32::MAX);
        // Every block is exactly one CIDR.
        for b in &blocks {
            assert_eq!(range_to_cidrs(b.begin, b.end).len(), 1);
        }
    }

    #[test]
    fn blocks_handle_unaligned_leftovers() {
        let mut set = RangeSet4::new();
        set.add(0x01020305, 0x0102037F);
        let mut id = 0u64;
        let blocks = set.blocks(64, &mut id);
        // 5..=127 carves as 5..=5, 6..=7, 8..=15, 16..=31, 32..=63, 64..=127.
        assert_eq!(blocks.len(), 6);
        assert_eq!(
            blocks.iter().map(|b| b.len()).sum::<u64>(),
            0x0102037Fu64 - 0x01020305 + 1
        );
    }
}
