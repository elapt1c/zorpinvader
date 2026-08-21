/// List of IPv6 ranges.
/// Same as the rangesv4 module, but for IPv6 instead of IPv4.

use super::addr::{Ipv6Address, Massint128};

/// A range of IPv6 ranges.
/// Inclusive, so [begin..=end] includes both begin and end.
#[derive(Debug, Clone, Copy)]
pub struct Range6 {
    pub begin: Ipv6Address,
    pub end: Ipv6Address,
}

impl Range6 {
    pub fn new(begin: Ipv6Address, end: Ipv6Address) -> Self {
        Range6 { begin, end }
    }

    /// Tests if the range is bad/invalid (end < begin).
    pub fn is_bad(&self) -> bool {
        self.end.is_less_than(self.begin)
    }
}

/// An array of ranges in sorted order
#[derive(Debug, Clone)]
pub struct Range6List {
    pub list: Vec<Range6>,
    pub picker: Vec<u64>,
    pub is_sorted: bool,
}

impl Default for Range6List {
    fn default() -> Self {
        Range6List {
            list: Vec::new(),
            picker: Vec::new(),
            is_sorted: false,
        }
    }
}

impl Range6List {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of ranges in the list
    pub fn count(&self) -> usize {
        self.list.len()
    }

    /// Returns 'true' if the indicated IPv6 address is in one of the target ranges.
    pub fn is_contains(&self, ip: Ipv6Address) -> bool {
        for range in &self.list {
            if range.begin.is_less_equal(ip) && ip.is_less_equal(range.end) {
                return true;
            }
        }
        false
    }

    /// Adds the given range to the targets list. The given range can be a duplicate
    /// or overlap with an existing range, which will get combined with existing ranges.
    pub fn add_range(&mut self, begin: Ipv6Address, end: Ipv6Address) {
        let range = Range6 { begin, end };

        // If empty list, then add this one
        if self.list.is_empty() {
            self.list.push(range);
            self.is_sorted = true;
            return;
        }

        // If new range overlaps the last range in the list, then combine it
        let last_idx = self.list.len() - 1;
        if range6_is_overlap(self.list[last_idx], range) {
            range6_combine(&mut self.list[last_idx], range);
            self.is_sorted = false;
            return;
        }

        // append to the end of our list
        self.list.push(range);
        self.is_sorted = false;
    }

    /// Removes the given range from the target list.
    pub fn remove_range(&mut self, begin: Ipv6Address, end: Ipv6Address) {
        let x = Range6 { begin, end };
        let mut i = 0;

        while i < self.list.len() {
            if !range6_is_overlap(self.list[i], x) {
                i += 1;
                continue;
            }

            // If the removal-range wholly covers the range, delete it completely
            if begin.is_less_equal(self.list[i].begin) && self.list[i].end.is_less_equal(end) {
                self.list.remove(i);
                continue;
            }

            // If the removal-range bisects the target-range, truncate the lower end
            // and add a new high-end
            if self.list[i].begin.is_less_equal(begin) && end.is_less_equal(self.list[i].end) {
                let newrange = Range6 {
                    begin: plus_one(end),
                    end: self.list[i].end,
                };
                self.list[i].end = minus_one(begin);
                self.add_range(newrange.begin, newrange.end);
                continue;
            }

            // If overlap on the lower side
            if self.list[i].begin.is_less_equal(end) && end.is_less_equal(self.list[i].end) {
                self.list[i].begin = plus_one(end);
            }

            // If overlap on the upper side
            if self.list[i].begin.is_less_equal(begin) && begin.is_less_equal(self.list[i].end) {
                self.list[i].end = minus_one(begin);
            }

            i += 1;
        }
    }

    /// Same as remove_range(), except the input is a range structure instead of start/stop numbers.
    pub fn remove_range2(&mut self, range: Range6) {
        self.remove_range(range.begin, range.end);
    }

    /// Remove all the ranges in the range list.
    pub fn remove_all(&mut self) {
        self.list.clear();
        self.picker.clear();
        self.is_sorted = false;
    }

    /// Merge two range lists
    pub fn merge(&mut self, other: &Range6List) {
        for range in &other.list {
            self.add_range(range.begin, range.end);
        }
    }

    /// Counts the total number of IPv6 addresses in the target list.
    pub fn count_addresses(&self) -> Massint128 {
        let mut result = Ipv6Address { hi: 0, lo: 0 };

        for range in &self.list {
            let x = range.end.subtract(range.begin);
            if x.hi == u64::MAX && x.lo == u64::MAX {
                return x; // overflow
            }
            let x = x.add_u64(1);
            result = result.add(x);
        }

        result
    }

    /// Given an index in a continuous range of [0...count], pick a corresponding
    /// IPv6 address from a list of non-continuous ranges.
    pub fn pick(&self, index: u64) -> Ipv6Address {
        let maxmax = self.list.len();
        let mut min = 0usize;
        let mut max = self.list.len();

        if self.picker.is_empty() {
            panic!("ipv6 picker is null");
        }

        let mid;
        loop {
            let m = min + (max - min) / 2;
            if index < self.picker[m] {
                max = m;
                continue;
            }
            if index >= self.picker[m] {
                if m + 1 == maxmax {
                    mid = m;
                    break;
                } else if index < self.picker[m + 1] {
                    mid = m;
                    break;
                } else {
                    min = m + 1;
                }
            }
        }

        self.list[mid].begin.add_u64(index - self.picker[mid])
    }

    /// Sorts the list of targets.
    pub fn sort(&mut self) {
        // Empty lists are sorted
        if self.list.is_empty() {
            self.is_sorted = true;
            return;
        }

        if self.is_sorted {
            return;
        }

        // First, sort the list
        self.list.sort_by(|a, b| {
            if a.begin.is_equal(b.begin) {
                std::cmp::Ordering::Equal
            } else if a.begin.is_less_than(b.begin) {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });

        // Second, combine all overlapping ranges
        let original_count = self.list.len();
        let mut newlist = Range6List::new();
        for range in &self.list {
            newlist.add_range(range.begin, range.end);
        }

        log::trace!(
            "range6:sort: combined from {} elements to {} elements",
            original_count,
            newlist.list.len()
        );

        self.list = newlist.list;
        self.is_sorted = true;
    }

    /// Optimizes the target list for faster binary-search picking.
    pub fn optimize(&mut self) {
        if self.list.is_empty() {
            return;
        }

        if !self.is_sorted {
            self.sort();
        }

        self.picker.clear();
        self.picker.reserve(self.list.len());

        let mut total = Ipv6Address { hi: 0, lo: 0 };
        for range in &self.list {
            self.picker.push(total.lo);
            let x = range.end.subtract(range.begin).add_u64(1);
            total = total.add(x);
        }
    }

    /// Apply the exclude ranges, removing everything from "targets" that's also in "excludes".
    /// Returns the total number of IP addresses removed.
    pub fn exclude(&mut self, excludes: &Range6List) -> Ipv6Address {
        let mut count = Ipv6Address { hi: 0, lo: 0 };

        for range in &excludes.list {
            let x = range.end.subtract(range.begin).add_u64(1);
            count = count.add(x);
            self.remove_range(range.begin, range.end);
        }

        count
    }
}

/// Test if two IPv6 ranges overlap.
fn range6_is_overlap(lhs: Range6, rhs: Range6) -> bool {
    let ffff = Ipv6Address {
        hi: u64::MAX,
        lo: u64::MAX,
    };

    if lhs.begin.is_less_than(rhs.begin) {
        if lhs.end.is_equal(ffff) || plus_one(lhs.end).is_greater_equal(rhs.begin) {
            return true;
        }
    }
    if lhs.begin.is_greater_equal(rhs.begin) {
        if lhs.end.is_less_equal(rhs.end) {
            return true;
        }
    }

    if rhs.begin.is_less_than(lhs.begin) {
        if rhs.end.is_equal(ffff) || plus_one(rhs.end).is_greater_equal(lhs.begin) {
            return true;
        }
    }
    if rhs.begin.is_greater_equal(lhs.begin) {
        if rhs.end.is_less_equal(lhs.end) {
            return true;
        }
    }

    false
}

/// Combine two ranges, such as when they overlap.
fn range6_combine(lhs: &mut Range6, rhs: Range6) {
    if rhs.begin.is_less_equal(lhs.begin) {
        lhs.begin = rhs.begin;
    }
    if lhs.end.is_less_equal(rhs.end) {
        lhs.end = rhs.end;
    }
}

/// Subtract 1 from an IPv6 address
fn minus_one(ip: Ipv6Address) -> Ipv6Address {
    if ip.lo == 0 {
        Ipv6Address {
            hi: ip.hi - 1,
            lo: u64::MAX,
        }
    } else {
        Ipv6Address {
            hi: ip.hi,
            lo: ip.lo - 1,
        }
    }
}

/// Add 1 to an IPv6 address
fn plus_one(ip: Ipv6Address) -> Ipv6Address {
    if ip.lo == u64::MAX {
        Ipv6Address {
            hi: ip.hi + 1,
            lo: 0,
        }
    } else {
        Ipv6Address {
            hi: ip.hi,
            lo: ip.lo + 1,
        }
    }
}

/// Deterministic random number generator for repeatable tests.
fn r_rand(seed: &mut u32) -> u32 {
    let a: u32 = 214013;
    let c: u32 = 2531011;
    *seed = seed.wrapping_mul(a).wrapping_add(c);
    (*seed >> 16) & 0x7fff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regress_pick2() {
        let mut seed: u32 = 0;

        // Test add/subtract identity
        for _i in 0..65536u32 {
            let a = Ipv6Address {
                hi: r_rand(&mut seed) as u64,
                lo: (r_rand(&mut seed) as u64) << 49,
            };
            let b = Ipv6Address {
                hi: r_rand(&mut seed) as u64,
                lo: 0x8765432100000000u64,
            };

            let c = a.add(b);
            let d = c.subtract(b);

            assert!(a.is_equal(d), "add/subtract identity failed");
        }

        // Run 100 randomized regression tests
        for i in 3..100u32 {
            seed = i;

            let mut targets = Range6List::new();
            let mut begin = Ipv6Address { hi: 0, lo: 0 };

            // fill the target list with random ranges
            let num_targets = (r_rand(&mut seed) % 5 + 1) as usize;
            for _j in 0..num_targets {
                begin.lo += (r_rand(&mut seed) % 10) as u64;
                let end = Ipv6Address {
                    hi: begin.hi,
                    lo: begin.lo + (r_rand(&mut seed) % 10) as u64,
                };
                targets.add_range(begin, end);
            }

            // Optimize for faster 'picking' addresses from an index
            targets.optimize();

            // Duplicate the targetlist using the picker
            let mut duplicate = Range6List::new();
            let range_count = targets.count_addresses();
            assert_eq!(range_count.hi, 0, "range too big");
            let range = range_count.lo;

            for j in 0..range {
                let addr = targets.pick(j);
                duplicate.add_range(addr, addr);
            }

            // at this point, the two range lists should be identical
            assert_eq!(targets.list.len(), duplicate.list.len(), "count mismatch at iteration {}", i);
            for k in 0..targets.list.len() {
                assert!(
                    targets.list[k].begin.is_equal(duplicate.list[k].begin),
                    "begin mismatch at {}",
                    k
                );
                assert!(
                    targets.list[k].end.is_equal(duplicate.list[k].end),
                    "end mismatch at {}",
                    k
                );
            }
        }
    }

    #[test]
    fn test_ranges6_selftest() {
        use super::super::parse::{massip_parse_range, RangeParseResult};

        let mut r = Range6 {
            begin: Ipv6Address { hi: 0, lo: 0 },
            end: Ipv6Address { hi: 0, lo: 0 },
        };
        let result = massip_parse_range(
            b"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            None,
            0,
            None,
            Some(&mut r),
        );
        assert!(matches!(result, RangeParseResult::Ipv6Address));
        assert_eq!(r.begin.hi, 0x20010db885a30000u64);
        assert_eq!(r.begin.lo, 0x00008a2e03707334u64);
    }
}
