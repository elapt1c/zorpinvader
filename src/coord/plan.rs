//! Scan plan: turn a target set into CIDR-aligned job blocks, plus a
//! deterministic block ordering that spreads early work across the address
//! space instead of walking it front to back.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use super::set4::{format_cidr, Interval, RangeSet4};

/// Default number of addresses per job block.
pub const DEFAULT_JOB_SIZE: u64 = 1024;

/// Upper bound on the number of blocks a plan may contain. The state file and
/// the scheduling bookkeeping are linear in this, so it is kept small enough to
/// stay a few hundred kilobytes at most.
pub const MAX_BLOCKS: u64 = 65536;

/// A single schedulable unit of work: an aligned address range. Every block is
/// exactly one CIDR, so "block covered" is unambiguous in the state file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Block {
    pub id: u64,
    pub begin: u32,
    pub end: u32,
}

impl Block {
    pub fn len(&self) -> u64 {
        self.end as u64 - self.begin as u64 + 1
    }

    pub fn cidr(&self) -> String {
        match super::set4::range_to_cidrs(self.begin, self.end).first() {
            Some((begin, prefix)) => format_cidr(*begin, *prefix),
            None => String::new(),
        }
    }

    pub fn interval(&self) -> Interval {
        Interval::new(self.begin, self.end)
    }
}

/// The immutable half of a scan: what to hit, in what order.
#[derive(Clone, Debug)]
pub struct Plan {
    pub ports: String,
    pub targets: RangeSet4,
    pub chunk: u64,
    pub seed: u64,
    pub blocks: Vec<Block>,
    pub order: Vec<u64>,
    pub fingerprint: u64,
}

impl Plan {
    /// Build a plan. `chunk` of 0 selects an automatic block size that keeps the
    /// block count under [`MAX_BLOCKS`] while staying at least
    /// [`DEFAULT_JOB_SIZE`] addresses (so small scans still get useful jobs).
    pub fn new(ports: &str, targets: RangeSet4, chunk: u64, seed: u64) -> Self {
        let ports = canonical_ports(ports);
        let fingerprint = fingerprint(&ports, &targets);
        let total = targets.count();
        let chunk = resolve_chunk(chunk, total);

        let mut next_id = 0u64;
        let intervals = targets.blocks(chunk, &mut next_id);
        let blocks: Vec<Block> = intervals
            .iter()
            .enumerate()
            .map(|(id, i)| Block {
                id: id as u64,
                begin: i.begin,
                end: i.end,
            })
            .collect();

        let order = shuffle_order(blocks.len(), seed);

        Plan {
            ports,
            targets,
            chunk,
            seed,
            blocks,
            order,
            fingerprint,
        }
    }

    /// Keep only the blocks belonging to static shard `one` of `of`.
    ///
    /// Static sharding predates the controller and still works: each shard keeps
    /// every `of`-th block, so several machines with the same plan and different
    /// `--shard` values cover the target set without overlap. Block ids are
    /// renumbered so a shard's state file is self-contained.
    pub fn restrict_shard(&mut self, one: u32, of: u32) {
        if of <= 1 || one == 0 {
            return;
        }
        let stride = of as usize;
        let offset = (one - 1) as usize;
        let kept: Vec<Block> = self
            .blocks
            .iter()
            .enumerate()
            .filter(|(index, _)| index % stride == offset)
            .map(|(_, block)| *block)
            .collect();
        self.blocks = kept
            .into_iter()
            .enumerate()
            .map(|(id, block)| Block {
                id: id as u64,
                begin: block.begin,
                end: block.end,
            })
            .collect();
        self.order = shuffle_order(self.blocks.len(), self.seed);
    }

    pub fn block(&self, id: u64) -> Option<Block> {
        self.blocks.get(id as usize).copied()
    }

    pub fn total_addresses(&self) -> u64 {
        self.targets.count()
    }

    pub fn blocks_len(&self) -> usize {
        self.blocks.len()
    }

    /// Number of ports in the plan (ranges like `1-100` count as 100).
    pub fn ports_count(&self) -> u64 {
        self.ports
            .split(',')
            .map(|token| {
                let token = token.trim();
                if token.is_empty() {
                    return 0;
                }
                match token.split_once('-') {
                    Some((a, b)) => match (a.parse::<u64>(), b.parse::<u64>()) {
                        (Ok(a), Ok(b)) if b >= a => b - a + 1,
                        _ => 0,
                    },
                    None => 1,
                }
            })
            .sum()
    }
}

/// Normalise a port specification for plan comparison and display. The wire
/// form is always the canonical comma list, so `80, 443` and `443,80` are the
/// same plan.
pub fn canonical_ports(ports: &str) -> String {
    let mut ports: Vec<u32> = ports
        .split(',')
        .filter_map(|p| p.trim().parse::<u32>().ok())
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Identity of a scan plan: the ports and the exact target set. Any change here
/// means an old state file cannot be resumed.
pub fn fingerprint(ports: &str, targets: &RangeSet4) -> u64 {
    let mut hasher = DefaultHasher::new();
    ports.hash(&mut hasher);
    for interval in targets.intervals() {
        interval.begin.hash(&mut hasher);
        interval.end.hash(&mut hasher);
    }
    hasher.finish()
}

pub fn fingerprint_hex(value: u64) -> String {
    format!("{:016x}", value)
}

/// Pick a power-of-two block size for `total` addresses.
pub fn resolve_chunk(requested: u64, total: u64) -> u64 {
    if requested > 0 {
        // Round up to a power of two so blocks stay CIDR-aligned.
        let mut chunk = 1u64;
        while chunk < requested && chunk < (1u64 << 32) {
            chunk <<= 1;
        }
        return chunk.min(1u64 << 32);
    }

    let mut chunk = DEFAULT_JOB_SIZE;
    if total > chunk.saturating_mul(MAX_BLOCKS) {
        while chunk < (1u64 << 32) && chunk.saturating_mul(MAX_BLOCKS) < total {
            chunk <<= 1;
        }
    }
    chunk
}

/// Deterministic shuffle of block ids, so a partial scan covers the whole
/// address space rather than its beginning. The seed is stored in the state
/// file, which keeps a resumed scan on the same order.
pub fn shuffle_order(n: usize, seed: u64) -> Vec<u64> {
    let mut ids: Vec<u64> = (0..n as u64).collect();
    let mut rng = SplitMix64::new(seed ^ 0x5DEE_CE66_D1A4_9B3B);
    for i in (1..n).rev() {
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        ids.swap(i, j);
    }
    ids
}

/// Tiny deterministic RNG; avoids pulling in `rand` just to shuffle block ids.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_of(cidrs: &[&str]) -> RangeSet4 {
        RangeSet4::from_cidrs(cidrs).unwrap()
    }

    #[test]
    fn plan_blocks_cover_targets_exactly() {
        let targets = set_of(&["10.0.0.0/20", "11.0.0.0/24"]);
        let plan = Plan::new("80,443", targets.clone(), 256, 7);
        assert_eq!(plan.blocks_len(), 16 + 1);
        let covered = RangeSet4::from_intervals(
            plan.blocks.iter().map(|b| (b.begin, b.end)),
        );
        assert_eq!(covered, targets);
    }

    #[test]
    fn blocks_carry_their_cidr() {
        let plan = Plan::new("80", set_of(&["1.2.3.0/24"]), 64, 1);
        let names: Vec<String> = plan.blocks.iter().map(|b| b.cidr()).collect();
        assert_eq!(
            names,
            vec!["1.2.3.0/26", "1.2.3.64/26", "1.2.3.128/26", "1.2.3.192/26"]
        );
    }

    #[test]
    fn auto_chunk_keeps_block_count_bounded() {
        let all = set_of(&["0.0.0.0/0"]);
        let plan = Plan::new("80,443,8080,8443,8000,3000,5000,8888", all, 0, 1);
        assert!(plan.blocks_len() as u64 <= MAX_BLOCKS);
        assert!(plan.chunk >= DEFAULT_JOB_SIZE);
        assert_eq!(plan.total_addresses(), 1u64 << 32);

        // Small scans keep the default job size.
        let small = Plan::new("80", set_of(&["10.0.0.0/24"]), 0, 1);
        assert_eq!(small.chunk, DEFAULT_JOB_SIZE);
        assert_eq!(small.blocks_len(), 1);
    }

    #[test]
    fn order_is_a_deterministic_permutation() {
        let a = shuffle_order(1000, 42);
        let b = shuffle_order(1000, 42);
        let c = shuffle_order(1000, 43);
        assert_eq!(a, b);
        assert_ne!(a, c);
        let mut sorted = a.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..1000u64).collect::<Vec<_>>());
        // A shuffled order should not start at 0 for this seed set.
        assert_ne!(a[0], 0);
    }

    #[test]
    fn fingerprint_tracks_ports_and_targets() {
        let one = set_of(&["10.0.0.0/8"]);
        let two = set_of(&["10.0.0.0/8", "11.0.0.0/8"]);
        assert_eq!(fingerprint("80", &one), fingerprint("80", &one));
        assert_ne!(fingerprint("80", &one), fingerprint("443", &one));
        assert_ne!(fingerprint("80", &one), fingerprint("80", &two));
    }

    #[test]
    fn shards_partition_the_target_set_without_overlap() {
        let targets = set_of(&["10.0.0.0/20"]);
        let mut shards = Vec::new();
        for one in 1..=4u32 {
            let mut plan = Plan::new("80", targets.clone(), 256, 7);
            plan.restrict_shard(one, 4);
            shards.push(plan);
        }
        assert!(shards.iter().all(|p| p.blocks_len() == 4));
        let mut covered = RangeSet4::new();
        let mut total = 0u64;
        for plan in &shards {
            for block in &plan.blocks {
                assert!(!covered.contains(block.begin), "shards overlap");
                covered.add(block.begin, block.end);
                total += block.len();
            }
        }
        assert_eq!(total, targets.count());
        assert_eq!(covered, targets);
    }

    #[test]
    fn canonical_ports_sorts_and_dedups() {
        assert_eq!(canonical_ports("443, 80,80 ,8080"), "80,443,8080");
    }
}
