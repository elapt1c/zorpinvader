//! Lock-free ring buffer derived from Intel DPDK / FreeBSD bufring.
//!
//! A fixed-size FIFO queue implemented as a table of pointers. Head and tail
//! pointers are modified atomically, allowing concurrent access. Supports:
//! - FIFO (First In First Out)
//! - Fixed maximum size (must be power of 2)
//! - Lockless implementation
//! - Multi- or single-consumer dequeue
//! - Multi- or single-producer enqueue
//! - Bulk and burst operations

use std::cell::UnsafeCell;
use std::fmt;
use std::sync::atomic::{AtomicU32, Ordering, fence};

/// Flag: default enqueue is single-producer.
pub const RING_F_SP_ENQ: u32 = 0x0001;
/// Flag: default dequeue is single-consumer.
pub const RING_F_SC_DEQ: u32 = 0x0002;
/// Quota exceeded for burst ops.
pub const RTE_RING_QUOT_EXCEED: i32 = 1 << 31;
/// Ring size mask.
pub const RTE_RING_SZ_MASK: u32 = 0x0FFFFFFF;

/// Error: not enough room in ring.
const ENOBUFS: i32 = 119;
/// Error: quota exceeded.
const EDQUOT: i32 = 122;
/// Error: not enough entries.
const ENOENT: i32 = 2;
/// Error: invalid argument.
const EINVAL: i32 = 22;

/// Queue behavior for bulk/burst operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueBehavior {
    /// Enqueue/dequeue a fixed number of items.
    Fixed,
    /// Enqueue/dequeue as many items as possible.
    Variable,
}

/// Ring creation flags.
#[derive(Debug, Clone, Copy)]
pub struct RingFlags {
    bits: u32,
}

impl RingFlags {
    pub const NONE: Self = Self { bits: 0 };
    pub const SP_ENQ: Self = Self { bits: RING_F_SP_ENQ };
    pub const SC_DEQ: Self = Self { bits: RING_F_SC_DEQ };

    pub const fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }

    pub const fn bits(self) -> u32 {
        self.bits
    }

    pub const fn union(self, other: Self) -> Self {
        Self { bits: self.bits | other.bits }
    }
}

/// Producer status within the ring.
#[repr(C)]
struct ProdHead {
    watermark: u32,
    sp_enqueue: u32,
    size: u32,
    mask: u32,
    head: AtomicU32,
    tail: AtomicU32,
}

/// Consumer status within the ring.
#[repr(C)]
struct ConsHead {
    sc_dequeue: u32,
    size: u32,
    mask: u32,
    head: AtomicU32,
    tail: AtomicU32,
}

/// A lock-free ring buffer (DPDK-style).
///
/// The ring stores raw pointer-sized values. The producer and consumer each
/// have head and tail indices that are modified atomically.
pub struct RteRing {
    flags: i32,
    prod: ProdHead,
    cons: ConsHead,
    ring: UnsafeCell<Vec<*mut ()>>,
}

// SAFETY: The ring uses atomic operations for concurrent access.
unsafe impl Send for RteRing {}
unsafe impl Sync for RteRing {}

impl RteRing {
    /// Create a new ring buffer.
    ///
    /// `count` must be a power of 2 and not exceed `RTE_RING_SZ_MASK`.
    /// The usable ring size is `count - 1`.
    pub fn new(count: u32, flags: RingFlags) -> Option<Self> {
        if count == 0 || !count.is_power_of_two() || count > RTE_RING_SZ_MASK {
            return None;
        }

        let ring = vec![std::ptr::null_mut(); count as usize];

        Some(RteRing {
            flags: flags.bits() as i32,
            prod: ProdHead {
                watermark: count,
                sp_enqueue: if flags.contains(RingFlags::SP_ENQ) { 1 } else { 0 },
                size: count,
                mask: count - 1,
                head: AtomicU32::new(0),
                tail: AtomicU32::new(0),
            },
            cons: ConsHead {
                sc_dequeue: if flags.contains(RingFlags::SC_DEQ) { 1 } else { 0 },
                size: count,
                mask: count - 1,
                head: AtomicU32::new(0),
                tail: AtomicU32::new(0),
            },
            ring: UnsafeCell::new(ring),
        })
    }

    /// Change the high water mark. If `count` is 0, watermarking is disabled.
    pub fn set_water_mark(&mut self, count: u32) -> Result<(), i32> {
        if count >= self.prod.size {
            return Err(EINVAL);
        }
        let wm = if count == 0 { self.prod.size } else { count };
        self.prod.watermark = wm;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal enqueue implementations
    // -----------------------------------------------------------------------

    /// Multi-producer enqueue (CAS-based).
    fn mp_do_enqueue(
        &self,
        obj_table: &[*const ()],
        n: u32,
        behavior: QueueBehavior,
    ) -> i32 {
        let mut n = n;
        let max = n;
        let mask = self.prod.mask;

        let mut prod_head;
        let mut prod_next;
        let mut free_entries;

        // Move prod.head atomically
        loop {
            // Reset n to the initial burst count
            n = max;

            prod_head = self.prod.head.load(Ordering::Acquire);
            let cons_tail = self.cons.tail.load(Ordering::Acquire);
            free_entries = mask.wrapping_add(cons_tail).wrapping_sub(prod_head);

            // Check that we have enough room
            if n > free_entries {
                if behavior == QueueBehavior::Fixed {
                    return -ENOBUFS;
                } else {
                    if free_entries == 0 {
                        return 0;
                    }
                    n = free_entries;
                }
            }

            prod_next = prod_head.wrapping_add(n);
            match self.prod.head.compare_exchange_weak(
                prod_head,
                prod_next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }

        // Write entries in ring
        unsafe {
            let ring = &mut *self.ring.get();
            for i in 0..n as usize {
                ring[(prod_head.wrapping_add(i as u32) & mask) as usize] =
                    obj_table[i] as *mut ();
            }
        }
        fence(Ordering::Release);

        // Check watermark
        let ret = if (mask + 1).wrapping_sub(free_entries).wrapping_add(n) > self.prod.watermark {
            match behavior {
                QueueBehavior::Fixed => -EDQUOT,
                QueueBehavior::Variable => (n as i32) | RTE_RING_QUOT_EXCEED,
            }
        } else {
            match behavior {
                QueueBehavior::Fixed => 0,
                QueueBehavior::Variable => n as i32,
            }
        };

        // Wait for preceding enqueues to complete
        while self.prod.tail.load(Ordering::Acquire) != prod_head {
            std::hint::spin_loop();
        }

        self.prod.tail.store(prod_next, Ordering::Release);
        ret
    }

    /// Single-producer enqueue.
    fn sp_do_enqueue(
        &self,
        obj_table: &[*const ()],
        mut n: u32,
        behavior: QueueBehavior,
    ) -> i32 {
        let mask = self.prod.mask;

        let prod_head = self.prod.head.load(Ordering::Acquire);
        let cons_tail = self.cons.tail.load(Ordering::Acquire);
        let free_entries = mask.wrapping_add(cons_tail).wrapping_sub(prod_head);

        // Check that we have enough room
        if n > free_entries {
            if behavior == QueueBehavior::Fixed {
                return -ENOBUFS;
            } else {
                if free_entries == 0 {
                    return 0;
                }
                n = free_entries;
            }
        }

        let prod_next = prod_head.wrapping_add(n);
        self.prod.head.store(prod_next, Ordering::Release);

        // Write entries in ring
        unsafe {
            let ring = &mut *self.ring.get();
            for i in 0..n as usize {
                ring[(prod_head.wrapping_add(i as u32) & mask) as usize] =
                    obj_table[i] as *mut ();
            }
        }
        fence(Ordering::Release);

        // Check watermark
        let ret = if (mask + 1).wrapping_sub(free_entries).wrapping_add(n) > self.prod.watermark {
            match behavior {
                QueueBehavior::Fixed => -EDQUOT,
                QueueBehavior::Variable => (n as i32) | RTE_RING_QUOT_EXCEED,
            }
        } else {
            match behavior {
                QueueBehavior::Fixed => 0,
                QueueBehavior::Variable => n as i32,
            }
        };

        self.prod.tail.store(prod_next, Ordering::Release);
        ret
    }

    /// Multi-consumer dequeue (CAS-based).
    fn mc_do_dequeue(
        &self,
        obj_table: &mut [*mut ()],
        n: u32,
        behavior: QueueBehavior,
    ) -> i32 {
        let mut n = n;
        let max = n;
        let mask = self.prod.mask;

        let mut cons_head;
        let mut cons_next;

        // Move cons.head atomically
        loop {
            n = max;

            cons_head = self.cons.head.load(Ordering::Acquire);
            let prod_tail = self.prod.tail.load(Ordering::Acquire);
            let entries = prod_tail.wrapping_sub(cons_head);

            if n > entries {
                if behavior == QueueBehavior::Fixed {
                    return -ENOENT;
                } else {
                    if entries == 0 {
                        return 0;
                    }
                    n = entries;
                }
            }

            cons_next = cons_head.wrapping_add(n);
            match self.cons.head.compare_exchange_weak(
                cons_head,
                cons_next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }

        // Copy from ring
        fence(Ordering::Acquire);
        unsafe {
            let ring = &*self.ring.get();
            for i in 0..n as usize {
                obj_table[i] = ring[(cons_head.wrapping_add(i as u32) & mask) as usize];
            }
        }

        // Wait for preceding dequeues to complete
        while self.cons.tail.load(Ordering::Acquire) != cons_head {
            std::hint::spin_loop();
        }

        self.cons.tail.store(cons_next, Ordering::Release);

        match behavior {
            QueueBehavior::Fixed => 0,
            QueueBehavior::Variable => n as i32,
        }
    }

    /// Single-consumer dequeue.
    fn sc_do_dequeue(
        &self,
        obj_table: &mut [*mut ()],
        mut n: u32,
        behavior: QueueBehavior,
    ) -> i32 {
        let mask = self.prod.mask;

        let cons_head = self.cons.head.load(Ordering::Acquire);
        let prod_tail = self.prod.tail.load(Ordering::Acquire);
        let entries = prod_tail.wrapping_sub(cons_head);

        if n > entries {
            if behavior == QueueBehavior::Fixed {
                return -ENOENT;
            } else {
                if entries == 0 {
                    return 0;
                }
                n = entries;
            }
        }

        let cons_next = cons_head.wrapping_add(n);
        self.cons.head.store(cons_next, Ordering::Release);

        // Copy from ring
        fence(Ordering::Acquire);
        unsafe {
            let ring = &*self.ring.get();
            for i in 0..n as usize {
                obj_table[i] = ring[(cons_head.wrapping_add(i as u32) & mask) as usize];
            }
        }

        self.cons.tail.store(cons_next, Ordering::Release);

        match behavior {
            QueueBehavior::Fixed => 0,
            QueueBehavior::Variable => n as i32,
        }
    }

    // -----------------------------------------------------------------------
    // Bulk enqueue
    // -----------------------------------------------------------------------

    /// Enqueue several objects (multi-producer safe).
    pub fn mp_enqueue_bulk(&self, obj_table: &[*const ()]) -> i32 {
        self.mp_do_enqueue(obj_table, obj_table.len() as u32, QueueBehavior::Fixed)
    }

    /// Enqueue several objects (single-producer).
    pub fn sp_enqueue_bulk(&self, obj_table: &[*const ()]) -> i32 {
        self.sp_do_enqueue(obj_table, obj_table.len() as u32, QueueBehavior::Fixed)
    }

    /// Enqueue several objects (auto-selects SP or MP based on flags).
    pub fn enqueue_bulk(&self, obj_table: &[*const ()]) -> i32 {
        if self.prod.sp_enqueue != 0 {
            self.sp_enqueue_bulk(obj_table)
        } else {
            self.mp_enqueue_bulk(obj_table)
        }
    }

    // -----------------------------------------------------------------------
    // Single enqueue
    // -----------------------------------------------------------------------

    /// Enqueue one object (multi-producer safe).
    pub fn mp_enqueue(&self, obj: *const ()) -> i32 {
        self.mp_enqueue_bulk(std::slice::from_ref(&obj))
    }

    /// Enqueue one object (single-producer).
    pub fn sp_enqueue(&self, obj: *const ()) -> i32 {
        self.sp_enqueue_bulk(std::slice::from_ref(&obj))
    }

    /// Enqueue one object (auto-selects SP or MP based on flags).
    pub fn enqueue(&self, obj: *const ()) -> i32 {
        if self.prod.sp_enqueue != 0 {
            self.sp_enqueue(obj)
        } else {
            self.mp_enqueue(obj)
        }
    }

    // -----------------------------------------------------------------------
    // Bulk dequeue
    // -----------------------------------------------------------------------

    /// Dequeue several objects (multi-consumer safe).
    pub fn mc_dequeue_bulk(&self, obj_table: &mut [*mut ()]) -> i32 {
        self.mc_do_dequeue(obj_table, obj_table.len() as u32, QueueBehavior::Fixed)
    }

    /// Dequeue several objects (single-consumer).
    pub fn sc_dequeue_bulk(&self, obj_table: &mut [*mut ()]) -> i32 {
        self.sc_do_dequeue(obj_table, obj_table.len() as u32, QueueBehavior::Fixed)
    }

    /// Dequeue several objects (auto-selects SC or MC based on flags).
    pub fn dequeue_bulk(&self, obj_table: &mut [*mut ()]) -> i32 {
        if self.cons.sc_dequeue != 0 {
            self.sc_dequeue_bulk(obj_table)
        } else {
            self.mc_dequeue_bulk(obj_table)
        }
    }

    // -----------------------------------------------------------------------
    // Single dequeue
    // -----------------------------------------------------------------------

    /// Dequeue one object (multi-consumer safe).
    pub fn mc_dequeue(&self) -> Option<*mut ()> {
        let mut obj: *mut () = std::ptr::null_mut();
        let ret = self.mc_dequeue_bulk(std::slice::from_mut(&mut obj));
        if ret == 0 { Some(obj) } else { None }
    }

    /// Dequeue one object (single-consumer).
    pub fn sc_dequeue(&self) -> Option<*mut ()> {
        let mut obj: *mut () = std::ptr::null_mut();
        let ret = self.sc_dequeue_bulk(std::slice::from_mut(&mut obj));
        if ret == 0 { Some(obj) } else { None }
    }

    /// Dequeue one object (auto-selects SC or MC based on flags).
    pub fn dequeue(&self) -> Option<*mut ()> {
        if self.cons.sc_dequeue != 0 {
            self.sc_dequeue()
        } else {
            self.mc_dequeue()
        }
    }

    // -----------------------------------------------------------------------
    // Burst enqueue
    // -----------------------------------------------------------------------

    /// Enqueue burst (multi-producer safe). Returns number enqueued.
    pub fn mp_enqueue_burst(&self, obj_table: &[*const ()]) -> i32 {
        self.mp_do_enqueue(obj_table, obj_table.len() as u32, QueueBehavior::Variable)
    }

    /// Enqueue burst (single-producer). Returns number enqueued.
    pub fn sp_enqueue_burst(&self, obj_table: &[*const ()]) -> i32 {
        self.sp_do_enqueue(obj_table, obj_table.len() as u32, QueueBehavior::Variable)
    }

    /// Enqueue burst (auto-selects SP or MP). Returns number enqueued.
    pub fn enqueue_burst(&self, obj_table: &[*const ()]) -> i32 {
        if self.prod.sp_enqueue != 0 {
            self.sp_enqueue_burst(obj_table)
        } else {
            self.mp_enqueue_burst(obj_table)
        }
    }

    // -----------------------------------------------------------------------
    // Burst dequeue
    // -----------------------------------------------------------------------

    /// Dequeue burst (multi-consumer safe). Returns number dequeued.
    pub fn mc_dequeue_burst(&self, obj_table: &mut [*mut ()]) -> i32 {
        self.mc_do_dequeue(obj_table, obj_table.len() as u32, QueueBehavior::Variable)
    }

    /// Dequeue burst (single-consumer). Returns number dequeued.
    pub fn sc_dequeue_burst(&self, obj_table: &mut [*mut ()]) -> i32 {
        self.sc_do_dequeue(obj_table, obj_table.len() as u32, QueueBehavior::Variable)
    }

    /// Dequeue burst (auto-selects SC or MC). Returns number dequeued.
    pub fn dequeue_burst(&self, obj_table: &mut [*mut ()]) -> i32 {
        if self.cons.sc_dequeue != 0 {
            self.sc_dequeue_burst(obj_table)
        } else {
            self.mc_dequeue_burst(obj_table)
        }
    }

    // -----------------------------------------------------------------------
    // Status queries
    // -----------------------------------------------------------------------

    /// Test if the ring is full.
    pub fn is_full(&self) -> bool {
        let prod_tail = self.prod.tail.load(Ordering::Acquire);
        let cons_tail = self.cons.tail.load(Ordering::Acquire);
        (cons_tail.wrapping_sub(prod_tail).wrapping_sub(1) & self.prod.mask) == 0
    }

    /// Test if the ring is empty.
    pub fn is_empty(&self) -> bool {
        let prod_tail = self.prod.tail.load(Ordering::Acquire);
        let cons_tail = self.cons.tail.load(Ordering::Acquire);
        cons_tail == prod_tail
    }

    /// Return the number of entries in the ring.
    pub fn count(&self) -> u32 {
        let prod_tail = self.prod.tail.load(Ordering::Acquire);
        let cons_tail = self.cons.tail.load(Ordering::Acquire);
        prod_tail.wrapping_sub(cons_tail) & self.prod.mask
    }

    /// Return the number of free entries in the ring.
    pub fn free_count(&self) -> u32 {
        let prod_tail = self.prod.tail.load(Ordering::Acquire);
        let cons_tail = self.cons.tail.load(Ordering::Acquire);
        cons_tail.wrapping_sub(prod_tail).wrapping_sub(1) & self.prod.mask
    }

    /// Return the ring size.
    pub fn size(&self) -> u32 {
        self.prod.size
    }

    /// Return the flags.
    pub fn flags(&self) -> i32 {
        self.flags
    }

    /// Dump ring status to a string.
    pub fn dump(&self) -> String {
        let prod_head = self.prod.head.load(Ordering::Acquire);
        let prod_tail = self.prod.tail.load(Ordering::Acquire);
        let cons_head = self.cons.head.load(Ordering::Acquire);
        let cons_tail = self.cons.tail.load(Ordering::Acquire);
        format!(
            "  flags={:x}\n  size={}\n  ct={}\n  ch={}\n  pt={}\n  ph={}\n  used={}\n  avail={}\n  watermark={}",
            self.flags,
            self.prod.size,
            cons_tail,
            cons_head,
            prod_tail,
            prod_head,
            self.count(),
            self.free_count(),
            if self.prod.watermark == self.prod.size { 0 } else { self.prod.watermark },
        )
    }
}

impl fmt::Debug for RteRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RteRing")
            .field("flags", &self.flags)
            .field("size", &self.prod.size)
            .field("count", &self.count())
            .field("free", &self.free_count())
            .finish()
    }
}

/// Run the self-test from the original C code.
/// Returns 0 on success, 1 on failure.
pub fn rte_ring_selftest() -> i32 {
    use std::sync::Arc;
    use std::thread;
    use std::sync::atomic::{AtomicU32, AtomicBool};

    struct TestState {
        ring: Arc<RteRing>,
        producer_started: AtomicU32,
        producer_done: AtomicU32,
        consumer_done: AtomicBool,
        total_count: std::sync::atomic::AtomicU64,
        not_active: AtomicBool,
    }

    for _iteration in 0..100 {
        let state = Arc::new(TestState {
            ring: Arc::new(
                RteRing::new(16, RingFlags::SP_ENQ.union(RingFlags::SC_DEQ)).unwrap(),
            ),
            producer_started: AtomicU32::new(0),
            producer_done: AtomicU32::new(0),
            consumer_done: AtomicBool::new(false),
            total_count: std::sync::atomic::AtomicU64::new(0),
            not_active: AtomicBool::new(false),
        });

        // Producer thread
        let prod_state = Arc::clone(&state);
        let producer = thread::spawn(move || {
            prod_state
                .producer_started
                .fetch_add(1, Ordering::SeqCst);
            for i in (1..=1000u64).rev() {
                let ptr = i as usize as *const ();
                loop {
                    if prod_state.ring.sp_enqueue(ptr) == 0 {
                        break;
                    }
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
                if let Some(ptr) = cons_state.ring.sc_dequeue() {
                    let val = ptr as u64;
                    cons_state.total_count.fetch_add(val, Ordering::Relaxed);
                }
            }
            // Drain remaining
            while !cons_state.ring.is_empty() {
                if let Some(ptr) = cons_state.ring.sc_dequeue() {
                    let val = ptr as u64;
                    cons_state.total_count.fetch_add(val, Ordering::Relaxed);
                }
            }
            cons_state.consumer_done.store(true, Ordering::Release);
        });

        // Wait for producer to finish
        producer.join().unwrap();

        // Tell consumer to stop
        state.not_active.store(true, Ordering::Release);

        // Wait for consumer to finish
        consumer.join().unwrap();

        let result = state.total_count.load(Ordering::Relaxed);
        // Sum of 1..=1000 = 500500
        if result != 500500 {
            eprintln!("rte_ring: selftest failed with {}", result);
            return 1;
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_basic() {
        let ring = RteRing::new(16, RingFlags::SP_ENQ.union(RingFlags::SC_DEQ)).unwrap();
        assert!(ring.is_empty());
        assert!(!ring.is_full());
        assert_eq!(ring.size(), 16);
    }

    #[test]
    fn test_create_invalid_size() {
        assert!(RteRing::new(0, RingFlags::NONE).is_none());
        assert!(RteRing::new(3, RingFlags::NONE).is_none()); // not power of 2
        assert!(RteRing::new(15, RingFlags::NONE).is_none());
    }

    #[test]
    fn test_sp_enqueue_sc_dequeue() {
        let ring = RteRing::new(16, RingFlags::SP_ENQ.union(RingFlags::SC_DEQ)).unwrap();

        // Enqueue a few items
        for i in 1..=5u64 {
            let ret = ring.sp_enqueue(i as usize as *const ());
            assert_eq!(ret, 0);
        }

        assert_eq!(ring.count(), 5);

        // Dequeue them
        for i in 1..=5u64 {
            let ptr = ring.sc_dequeue().unwrap();
            assert_eq!(ptr as u64, i);
        }

        assert!(ring.is_empty());
    }

    #[test]
    fn test_watermark() {
        let mut ring = RteRing::new(16, RingFlags::SP_ENQ.union(RingFlags::SC_DEQ)).unwrap();
        assert!(ring.set_water_mark(8).is_ok());
        assert!(ring.set_water_mark(16).is_err()); // >= size
    }

    #[test]
    fn test_selftest() {
        assert_eq!(rte_ring_selftest(), 0);
    }
}

/// Module-level selftest wrapper.
pub fn selftest() -> bool { rte_ring_selftest() == 0 }
