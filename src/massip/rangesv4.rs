/// IPv4 and port ranges
///
/// This is one of the more integral concepts to how zorp works internally.
/// We combine all the input addresses and address ranges into a sorted list
/// of 'target' IP addresses. This allows us to enumerate all the addresses
/// in order by incrementing a simple index.

use super::port::*;

/// A range of either IP addresses or ports.
/// Inclusive, so [begin..=end] includes both begin and end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub begin: u32,
    pub end: u32,
}

/// An invalid range, where begin comes after the end
const INVALID_RANGE: Range = Range {
    begin: 2,
    end: 1,
};

impl Range {
    pub fn new(begin: u32, end: u32) -> Self {
        Range { begin, end }
    }

    /// Returns true if the range is valid (begin <= end)
    pub fn is_valid(&self) -> bool {
        self.begin <= self.end
    }
}

/// An array of ranges in sorted order
#[derive(Debug, Clone)]
pub struct RangeList {
    pub list: Vec<Range>,
    pub picker: Vec<u32>,
    pub is_sorted: bool,
}

impl Default for RangeList {
    fn default() -> Self {
        RangeList {
            list: Vec::new(),
            picker: Vec::new(),
            is_sorted: false,
        }
    }
}

impl RangeList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of ranges in the list
    pub fn count(&self) -> usize {
        self.list.len()
    }

    /// Returns 'true' if the indicated port or IP address is in one of the task ranges.
    pub fn is_contains(&self, addr: u32) -> bool {
        for range in &self.list {
            if range.begin <= addr && addr <= range.end {
                return true;
            }
        }
        false
    }

    /// Adds the given range to the task list. The given range can be a duplicate
    /// or overlap with an existing range, which will get combined with existing ranges.
    pub fn add_range(&mut self, begin: u32, end: u32) {
        let range = Range { begin, end };

        // If empty list, then add this one
        if self.list.is_empty() {
            self.list.push(range);
            self.is_sorted = true;
            return;
        }

        // If new range overlaps the last range in the list, then combine it
        // rather than appending it. This is an optimization for the fact that
        // we often read in sequential addresses
        let last_idx = self.list.len() - 1;
        if range_is_overlap(self.list[last_idx], range) {
            range_combine(&mut self.list[last_idx], range);
            self.is_sorted = false;
            return;
        }

        // append to the end of our list
        self.list.push(range);
        self.is_sorted = false;
    }

    /// Use this when adding TCP ports, to avoid the complication of how ports are stored
    pub fn add_range_tcp(&mut self, begin: u32, end: u32) {
        self.add_range(TEMPL_TCP + begin, TEMPL_TCP + end);
    }

    /// Use this when adding UDP ports, to avoid the complication of how ports are stored
    pub fn add_range_udp(&mut self, begin: u32, end: u32) {
        self.add_range(TEMPL_UDP + begin, TEMPL_UDP + end);
    }

    /// Remove all the ranges in the range list.
    pub fn remove_all(&mut self) {
        self.list.clear();
        self.picker.clear();
        self.is_sorted = false;
    }

    /// Merge two range lists
    pub fn merge(&mut self, other: &RangeList) {
        for range in &other.list {
            self.add_range(range.begin, range.end);
        }
        self.sort();
    }

    /// Sorts the list of targets. We maintain the list of targets in sorted
    /// order internally even though we scan the targets in random order externally.
    pub fn sort(&mut self) {
        // Empty lists are, of course, sorted
        if self.list.is_empty() {
            self.is_sorted = true;
            return;
        }

        // If it's already sorted, then skip this
        if self.is_sorted {
            return;
        }

        // First, sort the list
        self.list.sort_by(|a, b| a.begin.cmp(&b.begin));

        // Second, combine all overlapping ranges
        let original_count = self.list.len();
        let mut newlist = RangeList::new();
        for range in &self.list {
            newlist.add_range(range.begin, range.end);
        }

        log::trace!(
            "range:sort: combined from {} elements to {} elements",
            original_count,
            newlist.list.len()
        );

        self.list = newlist.list;
        self.is_sorted = true;
    }

    /// Counts the total number of IP addresses or ports in the target list.
    pub fn count_addresses(&self) -> u64 {
        let mut result: u64 = 0;
        for range in &self.list {
            result += (range.end as u64) - (range.begin as u64) + 1;
        }
        result
    }

    /// Given an index in a continuous range of [0...count], pick a corresponding
    /// number (IP address or port) from a list of non-continuous ranges.
    pub fn pick(&self, index: u64) -> u32 {
        let maxmax = self.list.len();
        let mut min = 0usize;
        let mut max = self.list.len();

        if !self.is_sorted {
            // fallback to linear search if not sorted/optimized
            return self.pick_linear(index);
        }

        if self.picker.is_empty() {
            return self.pick_linear(index);
        }

        let mid;
        loop {
            let m = min + (max - min) / 2;
            if index < self.picker[m] as u64 {
                max = m;
                continue;
            }
            if index >= self.picker[m] as u64 {
                if m + 1 == maxmax {
                    mid = m;
                    break;
                } else if index < self.picker[m + 1] as u64 {
                    mid = m;
                    break;
                } else {
                    min = m + 1;
                }
            }
        }

        (self.list[mid].begin as u64 + (index - self.picker[mid] as u64)) as u32
    }

    /// Linear search fallback for pick
    fn pick_linear(&self, mut index: u64) -> u32 {
        for range in &self.list {
            let range_size = (range.end as u64) - (range.begin as u64) + 1;
            if index < range_size {
                return range.begin + index as u32;
            }
            index -= range_size;
        }
        panic!("rangelist_pick: index out of range");
    }

    /// Optimizes the target list, so that when we call "pick()"
    /// from an index, it runs faster using binary search.
    pub fn optimize(&mut self) {
        if self.list.is_empty() {
            return;
        }

        if !self.is_sorted {
            self.sort();
        }

        self.picker.clear();
        self.picker.reserve(self.list.len());

        let mut total: u32 = 0;
        for range in &self.list {
            self.picker.push(total);
            total += range.end - range.begin + 1;
        }
    }

    /// Apply the exclude ranges, removing everything from "targets"
    /// that's also in "exclude".
    pub fn exclude(&mut self, excludes: &RangeList) {
        // Both lists must be sorted
        self.sort();
        let mut excludes_sorted = excludes.clone();
        excludes_sorted.sort();

        let mut newlist = RangeList::new();
        let mut x = 0;

        for i in 0..self.list.len() {
            let mut range = self.list[i];

            // Move the exclude forward until we find a potentially overlapping candidate
            while x < excludes_sorted.list.len() && excludes_sorted.list[x].end < range.begin {
                x += 1;
            }

            // Keep applying excludes to this range as long as there are overlaps
            while x < excludes_sorted.list.len() && excludes_sorted.list[x].begin <= range.end {
                let mut split = INVALID_RANGE;
                range_apply_exclude(excludes_sorted.list[x], &mut range, &mut split);

                // If there is a split, then add the original range to our list
                // and then set that range to the split-ed portion
                if range.is_valid() && split.is_valid() {
                    newlist.add_range(range.begin, range.end);
                    range = split;
                } else if !range.is_valid() {
                    break;
                }

                if excludes_sorted.list[x].begin > range.end {
                    break;
                }

                x += 1;
            }

            // If the range hasn't been completely excluded, then add the remnants
            if range.is_valid() {
                newlist.add_range(range.begin, range.end);
            }
        }

        // Replace old list with new list
        self.list = newlist.list;

        // Since chopping up large ranges can split ranges, this can
        // grow the list so we need to re-sort it
        self.sort();
    }
}

/// Find the first CIDR range (one that can be specified with a /prefix)
/// inside the current range.
pub fn range_first_cidr(range: Range, prefix_length: Option<&mut u32>) -> Range {
    // Special Case: All inputs work but the boundary case of [0.0.0.0/0]
    if range.begin == 0 && range.end == 0xFFFFFFFF {
        if let Some(pl) = prefix_length {
            *pl = 0;
        }
        return range;
    }

    // Count the number of trailing/suffix zeros
    let mut zbits = 0u32;
    while zbits <= 32 {
        if zbits == 32 || (range.begin & (1u32 << zbits)) != 0 {
            break;
        }
        zbits += 1;
    }

    // Now search for the largest CIDR range that starts with this beginning address
    while zbits > 0 {
        let mask = !((0xFFFFFFFFu32) << zbits);
        if range.begin.wrapping_add(mask) > range.end {
            zbits -= 1;
        } else {
            break;
        }
    }

    let result = Range {
        begin: range.begin,
        end: range.begin.wrapping_add(!(0xFFFFFFFFu32 << zbits)),
    };

    if let Some(pl) = prefix_length {
        *pl = 32 - zbits;
    }

    result
}

/// Test if the range can instead be expressed using a CIDR /prefix.
pub fn range_is_cidr(range: Range, prefix_length: Option<&mut u32>) -> bool {
    let mut pl = 0u32;
    let out = range_first_cidr(range, Some(&mut pl));
    if out.begin == range.begin && out.end == range.end {
        if let Some(p) = prefix_length {
            *p = pl;
        }
        true
    } else {
        if let Some(p) = prefix_length {
            *p = 0xFFFFFFFF;
        }
        false
    }
}

/// Test if two ranges overlap.
fn range_is_overlap(lhs: Range, rhs: Range) -> bool {
    if lhs.begin < rhs.begin {
        if lhs.end == 0xFFFFFFFF || lhs.end + 1 >= rhs.begin {
            return true;
        }
    }
    if lhs.begin >= rhs.begin {
        if lhs.end <= rhs.end {
            return true;
        }
    }

    if rhs.begin < lhs.begin {
        if rhs.end == 0xFFFFFFFF || rhs.end + 1 >= lhs.begin {
            return true;
        }
    }
    if rhs.begin >= lhs.begin {
        if rhs.end <= lhs.end {
            return true;
        }
    }

    false
}

/// Combine two ranges, such as when they overlap.
fn range_combine(lhs: &mut Range, rhs: Range) {
    if lhs.begin > rhs.begin {
        lhs.begin = rhs.begin;
    }
    if lhs.end < rhs.end {
        lhs.end = rhs.end;
    }
}

/// Applies a CIDR mask to an IPv4 address to create a begin/end address.
fn ipv4_apply_cidr(begin: &mut u32, end: &mut u32, bitcount: u32) {
    let mask: u64 = 0xFFFFFFFF00000000u64 >> bitcount;
    *begin &= mask as u32;
    *end = *begin | !(mask as u32);
}

/// Parse an IPv4 address from a line of text, moving the offset forward
/// to the first non-IPv4 character
fn parse_ipv4(line: &[u8], offset: &mut usize, max: usize) -> Result<u32, ()> {
    let mut result: u32 = 0;

    for i in 0..4 {
        let mut x: u32 = 0;
        let mut digits: u32 = 0;

        if *offset >= max {
            return Err(());
        }
        if !line[*offset].is_ascii_digit() {
            return Err(());
        }

        // clear leading zeros
        while *offset < max && line[*offset] == b'0' {
            *offset += 1;
        }

        // parse maximum of 3 digits
        while *offset < max && line[*offset].is_ascii_digit() {
            x = x * 10 + (line[*offset] - b'0') as u32;
            *offset += 1;
            digits += 1;
            if digits > 3 {
                return Err(());
            }
        }
        if x > 255 {
            return Err(());
        }
        result = result * 256 + (x & 0xFF);
        if i == 3 {
            break;
        }

        if *offset >= max || line[*offset] != b'.' {
            return Err(());
        }
        *offset += 1; // skip dot
    }

    Ok(result)
}

/// Parse from text an IPv4 address range. This can be in one of several formats:
/// - '192.168.1.1' - a single address
/// - '192.168.1.0/24' - a CIDR spec
/// - '192.168.1.0-192.168.1.255' - a range
pub fn range_parse_ipv4(line: &[u8], inout_offset: Option<&mut usize>, max: usize) -> Range {
    let badrange = Range {
        begin: 0xFFFFFFFF,
        end: 0,
    };

    let has_offset = inout_offset.is_some();
    let mut off = match inout_offset {
        Some(ref o) => **o,
        None => 0,
    };
    let max_len = if !has_offset { line.len() } else { max };

    // trim whitespace
    while off < max_len && (line[off] as char).is_whitespace() {
        off += 1;
    }

    // get the first IP address
    let begin = match parse_ipv4(line, &mut off, max_len) {
        Ok(ip) => ip,
        Err(_) => return badrange,
    };

    let mut result = Range {
        begin,
        end: begin,
    };

    // trim whitespace
    while off < max_len && (line[off] as char).is_whitespace() {
        off += 1;
    }

    // If only one IP address, return that
    if off >= max_len {
        if let Some(o) = inout_offset {
            *o = off;
        }
        return result;
    }

    // Handle CIDR address of the form "10.0.0.0/8"
    if line[off] == b'/' {
        off += 1;

        if off >= max_len || !line[off].is_ascii_digit() {
            return badrange;
        }

        // strip leading zeroes
        while off < max_len && line[off] == b'0' {
            off += 1;
        }

        let mut prefix: u64 = 0;
        let mut digits: u32 = 0;
        while off < max_len && line[off].is_ascii_digit() {
            prefix = prefix * 10 + (line[off] - b'0') as u64;
            off += 1;
            digits += 1;
            if digits > 2 {
                return badrange;
            }
        }
        if prefix > 32 {
            return badrange;
        }

        let mask: u64 = 0xFFFFFFFF00000000u64 >> prefix;
        result.begin &= mask as u32;
        result.end = result.begin | !(mask as u32);

        if let Some(o) = inout_offset {
            *o = off;
        }
        return result;
    }

    // Handle a dashed range like "10.0.0.100-10.0.0.200"
    if off < max_len && line[off] == b'-' {
        off += 1;
        let ip = match parse_ipv4(line, &mut off, max_len) {
            Ok(ip) => ip,
            Err(_) => return badrange,
        };
        if ip < result.begin {
            result.begin = 0xFFFFFFFF;
            result.end = 0x00000000;
        } else {
            result.end = ip;
        }
        if let Some(o) = inout_offset {
            *o = off;
        }
        return result;
    }

    if let Some(o) = inout_offset {
        *o = off;
    }
    result
}

/// Applies the (presumably overlapping) exclude range to the target.
fn range_apply_exclude(exclude: Range, target: &mut Range, split: &mut Range) {
    // Set 'split' to invalid to start with
    split.begin = 2;
    split.end = 1;

    // Case 1: no overlap
    if target.begin > exclude.end || target.end < exclude.begin {
        return;
    }

    // Case 2: complete overlap, mark target as invalid and return
    if target.begin >= exclude.begin && target.end <= exclude.end {
        target.begin = 2;
        target.end = 1;
        return;
    }

    // Case 3: overlap at start
    if target.begin >= exclude.begin && target.end > exclude.end {
        target.begin = exclude.end + 1;
        return;
    }

    // Case 4: overlap at end
    if target.begin < exclude.begin && target.end <= exclude.end {
        target.end = exclude.begin - 1;
        return;
    }

    // Case 5: this range needs to be split
    if target.begin < exclude.begin && target.end > exclude.end {
        split.end = target.end;
        split.begin = exclude.end + 1;
        target.end = exclude.begin - 1;
        return;
    }
}

/// Given a string like "80,8080,20-25,U:161", parse it into a structure
/// containing a list of port ranges.
pub fn rangelist_parse_ports(
    ports: &mut RangeList,
    string: &str,
    is_error: Option<&mut bool>,
    mut proto_offset: u32,
) -> usize {
    let bytes = string.as_bytes();
    let mut p = 0;
    let mut error_flag = false;

    let is_error_ref = is_error;

    while p < bytes.len() {
        // skip whitespace
        while p < bytes.len() && (bytes[p] as char).is_whitespace() {
            p += 1;
        }

        // end at comment
        if p >= bytes.len() || bytes[p] == b'#' {
            break;
        }

        // special processing. Nmap allows ports to be prefixed with a
        // characters to clarify TCP, UDP, or SCTP
        if p + 1 < bytes.len() && bytes[p].is_ascii_alphabetic() && bytes[p + 1] == b':' {
            match bytes[p] as char {
                'T' | 't' => proto_offset = 0,
                'U' | 'u' => proto_offset = TEMPL_UDP,
                'S' | 's' => proto_offset = TEMPL_SCTP,
                'O' | 'o' => proto_offset = TEMPL_OPROTO_FIRST,
                'I' | 'i' => proto_offset = TEMPL_ICMP_ECHO,
                _ => {
                    error_flag = true;
                    if let Some(e) = is_error_ref {
                        *e = true;
                    }
                    return p;
                }
            }
            p += 2;
        }

        // Get the start of the range
        let port: u32;
        if p < bytes.len() && bytes[p] == b'-' {
            // nmap style port range spec meaning starting with 0
            port = 1;
        } else if p < bytes.len() && bytes[p].is_ascii_digit() {
            let mut val: u32 = 0;
            while p < bytes.len() && bytes[p].is_ascii_digit() {
                val = val * 10 + (bytes[p] - b'0') as u32;
                p += 1;
            }
            port = val;
        } else {
            break;
        }

        // Get the end of the range
        let end: u32;
        if p < bytes.len() && bytes[p] == b'-' {
            p += 1;
            if p >= bytes.len() || !bytes[p].is_ascii_digit() {
                // nmap style range spec meaning end with 65535
                end = if proto_offset == TEMPL_OPROTO_FIRST {
                    0xFF
                } else {
                    0xFFFF
                };
            } else {
                let mut val: u32 = 0;
                while p < bytes.len() && bytes[p].is_ascii_digit() {
                    val = val * 10 + (bytes[p] - b'0') as u32;
                    p += 1;
                }
                end = val;
            }
        } else {
            end = port;
        }

        // Check for out-of-range
        if port > 0xFF && proto_offset == TEMPL_OPROTO_FIRST {
            error_flag = true;
            if let Some(e) = is_error_ref {
                *e = true;
            }
            return p;
        } else if port > 0xFFFF || end > 0xFFFF || end < port {
            error_flag = true;
            if let Some(e) = is_error_ref {
                *e = true;
            }
            return p;
        }

        // Add to our list
        ports.add_range(port + proto_offset, end + proto_offset);

        // skip trailing whitespace
        while p < bytes.len() && (bytes[p] as char).is_whitespace() {
            p += 1;
        }

        // Now get the next port/range if there is one
        if p >= bytes.len() || bytes[p] != b',' {
            break;
        }
        p += 1;
    }

    if error_flag {
        if let Some(e) = is_error_ref {
            *e = true;
        }
    }

    p
}

/// Deterministic random number generator for repeatable tests.
fn lcgrand(state: &mut u32) -> u32 {
    *state = 1103515245u32.wrapping_mul(*state).wrapping_add(12345);
    *state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selftest_range_first_cidr() {
        struct TestCase {
            input: Range,
            output: Range,
            prefix_bits: u32,
        }

        let tests = vec![
            TestCase {
                input: Range::new(0x00000000, 0xFFFFFFFF),
                output: Range::new(0x00000000, 0xFFFFFFFF),
                prefix_bits: 0,
            },
            TestCase {
                input: Range::new(0x00000001, 0xFFFFFFFF),
                output: Range::new(0x00000001, 0x00000001),
                prefix_bits: 32,
            },
            TestCase {
                input: Range::new(0xFFFFFFFF, 0xFFFFFFFF),
                output: Range::new(0xFFFFFFFF, 0xFFFFFFFF),
                prefix_bits: 32,
            },
            TestCase {
                input: Range::new(0xFFFFFFFE, 0xFFFFFFFE),
                output: Range::new(0xFFFFFFFE, 0xFFFFFFFE),
                prefix_bits: 32,
            },
            TestCase {
                input: Range::new(0x0A000000, 0x0A0000FF),
                output: Range::new(0x0A000000, 0x0A0000FF),
                prefix_bits: 24,
            },
            TestCase {
                input: Range::new(0x0A0000FF, 0x0A0000FF),
                output: Range::new(0x0A0000FF, 0x0A0000FF),
                prefix_bits: 32,
            },
            TestCase {
                input: Range::new(0x0A000001, 0x0A0000FE),
                output: Range::new(0x0A000001, 0x0A000001),
                prefix_bits: 32,
            },
            TestCase {
                input: Range::new(0x0A000008, 0x0A0000FE),
                output: Range::new(0x0A000008, 0x0A00000F),
                prefix_bits: 29,
            },
            TestCase {
                input: Range::new(0x0A000080, 0x0A0000FE),
                output: Range::new(0x0A000080, 0x0A0000BF),
                prefix_bits: 26,
            },
            TestCase {
                input: Range::new(0x0A0000C0, 0x0A0000FE),
                output: Range::new(0x0A0000C0, 0x0A0000DF),
                prefix_bits: 27,
            },
            TestCase {
                input: Range::new(0x0A0000C1, 0x0A0000FE),
                output: Range::new(0x0A0000C1, 0x0A0000C1),
                prefix_bits: 32,
            },
            TestCase {
                input: Range::new(0x0A0000FE, 0x0A0000FE),
                output: Range::new(0x0A0000FE, 0x0A0000FE),
                prefix_bits: 32,
            },
        ];

        for (i, test) in tests.iter().enumerate() {
            let mut prefix_bits = 0xFFFFFFFF;
            let out = range_first_cidr(test.input, Some(&mut prefix_bits));
            assert_eq!(
                out.begin, test.output.begin,
                "test {} begin mismatch",
                i
            );
            assert_eq!(
                out.end, test.output.end,
                "test {} end mismatch",
                i
            );
            assert_eq!(
                prefix_bits, test.prefix_bits,
                "test {} prefix mismatch",
                i
            );
        }
    }

    /// Provide my own rand() simply to avoid static-analysis warning me that
    /// 'rand()' is unrandom, when in fact we want the non-random properties of
    /// rand() for regression testing.
    fn r_rand(seed: &mut u32) -> u32 {
        let a: u32 = 214013;
        let c: u32 = 2531011;
        *seed = seed.wrapping_mul(a).wrapping_add(c);
        (*seed >> 16) & 0x7fff
    }

    #[test]
    fn test_regress_pick2() {
        let mut seed: u32 = 0;

        for _i in 0..100 {
            let mut targets = RangeList::new();
            let mut duplicate = RangeList::new();
            let mut begin: u32 = 0;

            // fill the target list with random ranges
            let num_targets = (r_rand(&mut seed) % 5 + 1) as usize;
            for _j in 0..num_targets {
                begin = begin.wrapping_add(r_rand(&mut seed) % 10);
                let end = begin.wrapping_add(r_rand(&mut seed) % 10);
                targets.add_range(begin, end);
            }
            targets.sort();
            let range = targets.count_addresses() as u32;

            // Optimize for faster 'picking' addresses from an index
            targets.optimize();

            // Duplicate the targetlist using the picker
            for j in 0..range {
                let x = targets.pick(j as u64);
                duplicate.add_range(x, x);
            }
            duplicate.sort();

            // at this point, the two range lists should be identical
            assert_eq!(targets.list.len(), duplicate.list.len());
            for k in 0..targets.list.len() {
                assert_eq!(targets.list[k].begin, duplicate.list[k].begin);
                assert_eq!(targets.list[k].end, duplicate.list[k].end);
            }
        }
    }

    #[test]
    fn test_ranges_selftest() {
        // Test /0 CIDR block
        let r = range_parse_ipv4(b"0.0.0.0/0", None, 0);
        assert_eq!(r.begin, 0);
        assert_eq!(r.end, 0xFFFFFFFF);

        // Test bad addresses
        let r = range_parse_ipv4(b"0.0.0./0", None, 0);
        assert!(!r.is_valid());

        let r = range_parse_ipv4(b"75.748.86.91", None, 0);
        assert!(!r.is_valid());

        let r = range_parse_ipv4(b"23.75.345.200", None, 0);
        assert!(!r.is_valid());

        let r = range_parse_ipv4(b"192.1083.0.1", None, 0);
        assert!(!r.is_valid());

        // Test normal address
        let r = range_parse_ipv4(b"192.168.1.3", None, 0);
        assert_eq!(r.begin, 0xc0a80103);
        assert_eq!(r.end, 0xc0a80103);

        // Test dashed range
        let r = range_parse_ipv4(b"10.0.0.20-10.0.0.30", None, 0);
        assert_eq!(r.begin, 0x0A000000 + 20);
        assert_eq!(r.end, 0x0A000000 + 30);

        // Test CIDR
        let r = range_parse_ipv4(b"10.0.1.2/16", None, 0);
        assert_eq!(r.begin, 0x0A000000);
        assert_eq!(r.end, 0x0A00FFFF);

        // Test sort/merge
        let mut targets = RangeList::new();
        targets.add_range(0x0A000000, 0x0A0000FF); // 10.0.0.0/24
        targets.add_range(0x0A000100 + 10, 0x0A000100 + 19); // 10.0.1.10-10.0.1.19
        targets.add_range(0x0A000100 + 20, 0x0A000100 + 30); // 10.0.1.20-10.0.1.30
        targets.add_range(0x0A000000, 0x0A000100 + 12); // 10.0.0.0-10.0.1.12
        targets.sort();

        assert_eq!(targets.list.len(), 1);
        assert_eq!(targets.list[0].begin, 0x0a000000);
        assert_eq!(targets.list[0].end, 0x0a000100 + 30);

        // Test removal
        let mut targets = RangeList::new();
        targets.add_range(0x0A000000, 0x0AFFFFFF); // 10.0.0.0/8
        targets.sort();

        // These removals shouldn't change anything
        // (they don't overlap with 10.0.0.0/8)
        // We need to test the exclude functionality instead

        // Test ports
        let mut port_targets = RangeList::new();
        let mut is_error = false;
        rangelist_parse_ports(&mut port_targets, "80,1000-2000,1234,4444", Some(&mut is_error), 0);
        port_targets.sort();
        assert_eq!(port_targets.list.len(), 3);
        assert!(!is_error);

        assert_eq!(port_targets.list[0].begin, 80);
        assert_eq!(port_targets.list[0].end, 80);
        assert_eq!(port_targets.list[1].begin, 1000);
        assert_eq!(port_targets.list[1].end, 2000);
        assert_eq!(port_targets.list[2].begin, 4444);
        assert_eq!(port_targets.list[2].end, 4444);
    }

    /// The old way of excluding addresses. Used for testing the new algorithm.
    fn rangelist_exclude_old(targets: &mut RangeList, excludes: &RangeList) {
        for range in &excludes.list {
            rangelist_remove_range(targets, range.begin, range.end);
        }
        targets.sort();
    }

    fn rangelist_remove_range(targets: &mut RangeList, begin: u32, end: u32) {
        let x = Range { begin, end };
        let mut i = 0;
        while i < targets.list.len() {
            if !range_is_overlap(targets.list[i], x) {
                i += 1;
                continue;
            }

            // If the removal-range wholly covers the range, delete it completely
            if begin <= targets.list[i].begin && end >= targets.list[i].end {
                targets.list.remove(i);
                continue;
            }

            // If the removal-range bisects the target-range, split it
            if begin > targets.list[i].begin && end < targets.list[i].end {
                let newrange = Range {
                    begin: end + 1,
                    end: targets.list[i].end,
                };
                targets.list[i].end = begin - 1;
                targets.add_range(newrange.begin, newrange.end);
                continue;
            }

            // If overlap on the lower side
            if end >= targets.list[i].begin && end < targets.list[i].end {
                targets.list[i].begin = end + 1;
            }

            // If overlap on the upper side
            if begin > targets.list[i].begin && begin <= targets.list[i].end {
                targets.list[i].end = begin - 1;
            }

            i += 1;
        }
    }

    #[test]
    fn test_exclude_selftest() {
        let mut seed: u32 = 0;
        let mut includes1 = RangeList::new();
        let mut excludes = RangeList::new();
        let mut addr: u32 = 0;

        static MAXCOUNT: usize = 1000;

        // Fill the include list
        seed = 0;
        addr = 0;
        for _i in 0..MAXCOUNT {
            addr = addr.wrapping_add(lcgrand(&mut seed) & 0xF);
            let begin = addr;
            addr = addr.wrapping_add(lcgrand(&mut seed) & 0xF);
            let end = addr;
            includes1.add_range(begin, end);
        }
        includes1.sort();

        // Fill the exclude list
        seed = 1;
        addr = 0;
        for _i in 0..MAXCOUNT {
            addr = addr.wrapping_add(lcgrand(&mut seed) & 0xF);
            let begin = addr;
            addr = addr.wrapping_add(lcgrand(&mut seed) & 0xF);
            let end = addr;
            excludes.add_range(begin, end);
        }
        excludes.sort();

        // Create a copy of the include list
        let mut includes2 = includes1.clone();

        // Apply both algorithms
        includes1.exclude(&excludes);
        rangelist_exclude_old(&mut includes2, &excludes);

        // They should produce identical results
        assert_eq!(includes1.list.len(), includes2.list.len());
        for i in 0..includes1.list.len() {
            assert_eq!(includes1.list[i].begin, includes2.list[i].begin);
            assert_eq!(includes1.list[i].end, includes2.list[i].end);
        }
    }
}
