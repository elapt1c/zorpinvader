//! Extended ring buffer — a simple fixed-size SPSC ring for `u64` elements.
//!
//! This is a minimal lock-free ring used in the original C code for
//! inter-thread element passing. The ring has a fixed size of 16 slots
//! and stores `u64` values. A zero value indicates an empty slot.

use std::sync::atomic::{AtomicU64, Ordering};

/// Fixed ring size (must be a power of 2).
const XRING_SIZE: usize = 16;

/// Result codes for add/remove operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XRingResult {
    Success,
    Failure,
}

/// A fixed-size single-producer single-consumer ring of `u64` values.
///
/// Uses atomic operations for thread safety. A value of `0` means
/// the slot is empty (so `0` cannot be stored as a valid element).
pub struct XRing {
    head: AtomicU64,
    tail: AtomicU64,
    ring: Vec<AtomicU64>,
}

impl XRing {
    /// Create a new empty XRing.
    pub fn new() -> Self {
        let ring = (0..XRING_SIZE)
            .map(|_| AtomicU64::new(0))
            .collect();
        XRing {
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
            ring,
        }
    }

    /// Try to add a value to the ring.
    ///
    /// Returns `XRingResult::Failure` if the ring is full or `value` is 0.
    pub fn add(&self, value: u64) -> XRingResult {
        if value == 0 {
            return XRingResult::Failure;
        }

        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);

        if head >= tail + XRING_SIZE as u64 {
            return XRingResult::Failure;
        }

        let idx = (head & (XRING_SIZE as u64 - 1)) as usize;
        let current = self.ring[idx].load(Ordering::Acquire);

        if current != 0 {
            return XRingResult::Failure;
        }

        self.ring[idx].store(value, Ordering::Release);
        self.head.store(head + 1, Ordering::Release);
        XRingResult::Success
    }

    /// Try to remove a value from the ring.
    ///
    /// Returns 0 if the ring is empty or the slot is unexpectedly zero.
    pub fn remove(&self) -> u64 {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);

        if tail >= head {
            return 0;
        }

        let idx = (tail & (XRING_SIZE as u64 - 1)) as usize;
        let num = self.ring[idx].load(Ordering::Acquire);

        if num != 0 {
            self.ring[idx].store(0, Ordering::Release);
            self.tail.store(tail + 1, Ordering::Release);
            num
        } else {
            0
        }
    }

    /// Returns `true` if the ring appears empty.
    pub fn is_empty(&self) -> bool {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        tail >= head
    }
}

impl Default for XRing {
    fn default() -> Self {
        Self::new()
    }
}

/// Run the built-in self-test.
///
/// Spawns a producer thread that inserts values 1..=1000, and a consumer
/// thread that removes and sums them. The expected sum is 500500.
/// Runs 1000 iterations to stress-test the ring.
///
/// Returns 0 on success, 1 on failure.
pub fn xring_selftest() -> i32 {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, AtomicBool};
    use std::thread;

    struct TestState {
        xring: Arc<XRing>,
        producer_started: AtomicU32,
        producer_done: AtomicU32,
        consumer_done: AtomicBool,
        total_count: AtomicU64,
        not_active: AtomicBool,
    }

    for _iteration in 0..1000 {
        let state = Arc::new(TestState {
            xring: Arc::new(XRing::new()),
            producer_started: AtomicU32::new(0),
            producer_done: AtomicU32::new(0),
            consumer_done: AtomicBool::new(false),
            total_count: AtomicU64::new(0),
            not_active: AtomicBool::new(false),
        });

        // Producer thread
        let prod_state = Arc::clone(&state);
        let producer = thread::spawn(move || {
            prod_state
                .producer_started
                .fetch_add(1, Ordering::SeqCst);
            for i in (1..=1000u64).rev() {
                while prod_state.xring.add(i) == XRingResult::Failure {
                    std::hint::spin_loop();
                }
            }
            prod_state.producer_done.fetch_add(1, Ordering::SeqCst);
        });

        // Wait for producer to start
        while state.producer_started.load(Ordering::SeqCst) < 1 {
            std::hint::spin_loop();
        }

        // Consumer thread
        let cons_state = Arc::clone(&state);
        let consumer = thread::spawn(move || {
            while !cons_state.not_active.load(Ordering::Acquire) {
                let e = cons_state.xring.remove();
                if e != 0 {
                    cons_state.total_count.fetch_add(e, Ordering::Relaxed);
                }
            }
            // Drain remaining
            loop {
                let e = cons_state.xring.remove();
                if e == 0 {
                    break;
                }
                cons_state.total_count.fetch_add(e, Ordering::Relaxed);
            }
            cons_state.consumer_done.store(true, Ordering::Release);
        });

        // Wait for producer
        producer.join().unwrap();

        // Tell consumer to stop
        state.not_active.store(true, Ordering::Release);

        // Wait for consumer
        consumer.join().unwrap();

        let result = state.total_count.load(Ordering::Relaxed);
        if result != 500500 {
            eprintln!("xring: selftest failed with {}", result);
            return 1;
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_add_remove() {
        let ring = XRing::new();
        assert!(ring.is_empty());

        assert_eq!(ring.add(42), XRingResult::Success);
        assert!(!ring.is_empty());

        assert_eq!(ring.remove(), 42);
        assert!(ring.is_empty());
    }

    #[test]
    fn test_zero_rejected() {
        let ring = XRing::new();
        assert_eq!(ring.add(0), XRingResult::Failure);
    }

    #[test]
    fn test_fill_and_drain() {
        let ring = XRing::new();

        // Fill the ring (XRING_SIZE - 1 usable slots for head/tail semantics)
        let mut count = 0;
        for i in 1..=(XRING_SIZE as u64) {
            if ring.add(i) == XRingResult::Success {
                count += 1;
            }
        }
        assert!(count > 0);

        // Drain all
        let mut sum = 0u64;
        loop {
            let v = ring.remove();
            if v == 0 {
                break;
            }
            sum += v;
        }
        // Sum of 1..=count
        assert_eq!(sum, count * (count + 1) / 2);
    }

    #[test]
    fn test_selftest() {
        assert_eq!(xring_selftest(), 0);
    }
}
