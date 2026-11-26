//! Per-block results collected while a block is being scanned.

use parking_lot::Mutex;

/// Bounded set of open ports found in the current block.
///
/// A block is at most `block_size * ports` probes, so the capacity is exact and
/// the vector cannot grow past what the block can physically produce.
pub struct HitLog {
    hits: Mutex<Vec<(u32, u16)>>,
    capacity: Mutex<u64>,
}

impl Default for HitLog {
    fn default() -> Self {
        Self::new()
    }
}

impl HitLog {
    pub fn new() -> Self {
        HitLog {
            hits: Mutex::new(Vec::new()),
            capacity: Mutex::new(u64::MAX),
        }
    }

    /// Start a block: clear previous hits and cap the log at `capacity`.
    pub fn reset(&self, capacity: u64) {
        self.hits.lock().clear();
        *self.capacity.lock() = capacity;
    }

    pub fn push(&self, ip: u32, port: u16) {
        let mut hits = self.hits.lock();
        let capacity = *self.capacity.lock();
        if (hits.len() as u64) < capacity {
            hits.push((ip, port));
        }
    }

    pub fn len(&self) -> usize {
        self.hits.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Take everything collected since the last reset.
    pub fn take(&self) -> Vec<(u32, u16)> {
        std::mem::take(&mut *self.hits.lock())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_capacity_and_clears_on_reset() {
        let log = HitLog::new();
        log.reset(2);
        log.push(1, 80);
        log.push(2, 80);
        log.push(3, 80);
        assert_eq!(log.len(), 2);
        assert_eq!(log.take(), vec![(1, 80), (2, 80)]);
        log.reset(10);
        assert!(log.is_empty());
    }
}
