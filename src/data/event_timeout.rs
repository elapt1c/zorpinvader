//! Timeout-based event handling for connection management.
//!
//! This implements a circular ring of timeout entries. An index moves around
//! the ring; at each slot is a linked-list of entries at that time index.
//! Because the ring wraps, entries from the far future may coexist at the
//! same slot, so timestamps are double-checked during removal.
//!
//! Each `TimeoutEntry` lives inside another data structure (e.g. a TCB).
//! The `offset` field stores the byte offset of the entry within that
//! containing structure, so we can recover a pointer to the container.

use std::ptr;

/// Ticks per second (1/16384 of a second granularity).
pub const TICKS_PER_SECOND: u64 = 16384;

/// Convert seconds to ticks.
pub const fn TICKS_FROM_SECS(secs: u64) -> u64 {
    secs * 16384
}

/// Convert microseconds to ticks.
pub const fn TICKS_FROM_USECS(usecs: u64) -> u64 {
    usecs / 16384
}

/// Convert seconds + microseconds to ticks.
pub const fn TICKS_FROM_TV(secs: u64, usecs: u64) -> u64 {
    TICKS_FROM_SECS(secs) + TICKS_FROM_USECS(usecs)
}

/// Number of slots in the timeout ring (must be a power of 2).
const RING_SIZE: usize = 1024 * 1024;

/// A timeout entry that lives inside another data structure.
///
/// This is a doubly-linked list node. When linked, `prev` points to the
/// pointer that points to this entry (either a slot head or the `next`
/// field of the preceding entry). When unlinked, both pointers are null.
pub struct TimeoutEntry {
    /// Timestamp in ticks (1/16384 s). Zero when unlinked.
    pub timestamp: u64,
    /// Next entry in the linked list (null if tail).
    next: *mut TimeoutEntry,
    /// Pointer to the pointer that points to us (null if unlinked).
    prev: *mut *mut TimeoutEntry,
    /// Byte offset of this entry within the containing structure.
    offset: usize,
}

impl TimeoutEntry {
    /// Create a new unlinked timeout entry.
    pub fn new() -> Self {
        TimeoutEntry {
            timestamp: 0,
            next: ptr::null_mut(),
            prev: ptr::null_mut(),
            offset: 0,
        }
    }

    /// Initialize (or re-initialize) an entry as unlinked.
    pub fn init(&mut self) {
        self.next = ptr::null_mut();
        self.prev = ptr::null_mut();
    }

    /// Returns `true` if this entry is not currently linked into a ring.
    pub fn is_unlinked(&self) -> bool {
        self.prev.is_null() || self.next.is_null()
    }

    /// Unlink this entry from its current ring slot.
    ///
    /// # Safety
    /// The entry must either be fully unlinked or correctly linked
    /// into a valid timeout ring.
    pub unsafe fn unlink(&mut self) {
        if self.prev.is_null() && self.next.is_null() {
            return;
        }
        // Patch the previous pointer to skip us
        if !self.prev.is_null() {
            *self.prev = self.next;
        }
        // Patch the next entry's prev to skip us
        if !self.next.is_null() {
            (*self.next).prev = self.prev;
        }
        self.next = ptr::null_mut();
        self.prev = ptr::null_mut();
        self.timestamp = 0;
    }
}

impl Default for TimeoutEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// The timeout subsystem — a circular ring of linked-list slots.
pub struct Timeouts {
    /// Monotonically increasing index (mod mask).
    current_index: u64,
    /// Number of outstanding (linked) timeout entries.
    outstanding_count: u64,
    /// Bitmask for wrapping (RING_SIZE - 1).
    mask: usize,
    /// The ring of slot heads.
    slots: Vec<*mut TimeoutEntry>,
}

// SAFETY: Timeouts is designed for single-threaded use from the packet
// processing thread. The raw pointers point to entries owned elsewhere.
unsafe impl Send for Timeouts {}

impl Timeouts {
    /// Create a new timeout subsystem.
    ///
    /// `timestamp_now` is the current time in ticks
    /// (e.g. `time(0) * TICKS_PER_SECOND`).
    pub fn new(timestamp_now: u64) -> Self {
        Timeouts {
            current_index: timestamp_now,
            outstanding_count: 0,
            mask: RING_SIZE - 1,
            slots: vec![ptr::null_mut(); RING_SIZE],
        }
    }

    /// Insert a timeout entry into the ring.
    ///
    /// `entry` — the timeout entry (lives inside the containing structure).
    /// `offset` — byte offset of `entry` within the containing structure
    ///            (used to recover the container pointer on removal).
    /// `timestamp_expires` — when the timeout fires, in ticks.
    ///
    /// # Safety
    /// `entry` must be a valid, properly aligned pointer that will remain
    /// valid for the lifetime of the timeout.
    pub unsafe fn add(
        &mut self,
        entry: *mut TimeoutEntry,
        offset: usize,
        timestamp_expires: u64,
    ) {
        let e = &mut *entry;

        // Unlink from old position if already linked
        if e.timestamp != 0 {
            self.outstanding_count -= 1;
        }
        e.unlink();

        // Initialize the new entry
        e.timestamp = timestamp_expires;
        e.offset = offset;

        // Link into the appropriate slot
        let index = (timestamp_expires & self.mask as u64) as usize;
        e.next = self.slots[index];
        self.slots[index] = entry;
        e.prev = &mut self.slots[index] as *mut *mut TimeoutEntry;
        if !e.next.is_null() {
            (*e.next).prev = &mut e.next as *mut *mut TimeoutEntry;
        }

        self.outstanding_count += 1;
    }

    /// Remove the next expired entry (older than `timestamp_now`).
    ///
    /// Call repeatedly until it returns `None` to drain all expired entries.
    ///
    /// Returns a pointer to the **containing structure** (not the entry
    /// itself), computed by subtracting `entry.offset` from the entry pointer.
    pub fn remove(&mut self, timestamp_now: u64) -> Option<*mut u8> {
        // Walk forward through the ring until we find something expired
        while self.current_index <= timestamp_now {
            let slot = (self.current_index & self.mask as u64) as usize;
            let mut entry = self.slots[slot];

            // Walk the linked list at this slot
            while !entry.is_null() {
                let e = unsafe { &*entry };
                if e.timestamp <= timestamp_now {
                    break;
                }
                entry = e.next;
            }

            if !entry.is_null() {
                // Found an expired entry
                let e = unsafe { &mut *entry };
                let offset = e.offset;
                unsafe { e.unlink(); }
                self.outstanding_count -= 1;

                // Return pointer to the containing structure
                let container = unsafe {
                    (entry as *mut u8).sub(offset)
                };
                return Some(container);
            }

            // Nothing at this slot, advance
            self.current_index += 1;
        }

        None
    }

    /// Return the number of outstanding timeout entries.
    pub fn outstanding_count(&self) -> u64 {
        self.outstanding_count
    }

    /// Return the current index position.
    pub fn current_index(&self) -> u64 {
        self.current_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticks_conversion() {
        assert_eq!(TICKS_FROM_SECS(1), 16384);
        assert_eq!(TICKS_FROM_SECS(10), 163840);
        assert_eq!(TICKS_FROM_USECS(16384), 1);
        assert_eq!(TICKS_FROM_TV(1, 16384), 16385);
    }

    #[test]
    fn test_entry_init_and_unlink() {
        let mut entry = TimeoutEntry::new();
        assert!(entry.is_unlinked());
        assert_eq!(entry.timestamp, 0);

        entry.init();
        assert!(entry.is_unlinked());
    }

    #[test]
    fn test_timeouts_create() {
        let t = Timeouts::new(1000);
        assert_eq!(t.current_index(), 1000);
        assert_eq!(t.outstanding_count(), 0);
    }

    #[test]
    fn test_timeouts_add_and_remove() {
        let mut timeouts = Timeouts::new(0);

        // We need a container struct to hold the entry
        #[repr(C)]
        struct MyConnection {
            data: u32,
            entry: TimeoutEntry,
        }

        let mut conn = Box::new(MyConnection {
            data: 42,
            entry: TimeoutEntry::new(),
        });

        let entry_offset = memoffset_of_entry();
        let entry_ptr = &mut conn.entry as *mut TimeoutEntry;

        // Add timeout that expires at tick 100
        unsafe {
            timeouts.add(entry_ptr, entry_offset, 100);
        }
        assert_eq!(timeouts.outstanding_count(), 1);

        // Remove at tick 200 (should find the expired entry)
        let result = timeouts.remove(200);
        assert!(result.is_some(), "should find expired entry");
        assert_eq!(timeouts.outstanding_count(), 0);

        // Verify we got back a pointer to our container
        let container_ptr = result.unwrap() as *mut MyConnection;
        unsafe {
            assert_eq!((*container_ptr).data, 42);
        }

        fn memoffset_of_entry() -> usize {
            // Use a null pointer trick to get the offset
            let base = 0usize;
            let fake = base as *const MyConnection;
            let field = unsafe { &(*fake).entry as *const TimeoutEntry as usize };
            field - base
        }
    }

    #[test]
    fn test_timeouts_remove_not_expired() {
        let mut timeouts = Timeouts::new(0);

        #[repr(C)]
        struct MyConn {
            _data: u32,
            entry: TimeoutEntry,
        }

        let mut conn = Box::new(MyConn {
            _data: 0,
            entry: TimeoutEntry::new(),
        });

        let entry_ptr = &mut conn.entry as *mut TimeoutEntry;
        let offset = {
            let base = 0usize as *const MyConn;
            unsafe { &(*base).entry as *const TimeoutEntry as usize }
        };

        // Add timeout at tick 1000
        unsafe {
            timeouts.add(entry_ptr, offset, 1000);
        }

        // Try to remove at tick 500 — should NOT find it
        let result = timeouts.remove(500);
        assert!(result.is_none(), "should not find non-expired entry");
        assert_eq!(timeouts.outstanding_count(), 1);
    }
}
