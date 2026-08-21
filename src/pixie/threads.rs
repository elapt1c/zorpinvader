//! Thread management, CPU affinity, priority, and atomic operations.
//!
//! Mirrors the C `pixie-threads` module. Rust's `std::thread` and
//! `std::sync::atomic` handle most of the heavy lifting; platform-specific
//! bits (affinity, scheduling priority) go through `nix` / `libc`.

use std::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};

use log::warn;

// ---------------------------------------------------------------------------
// CPU topology
// ---------------------------------------------------------------------------

/// Returns the number of CPUs available in the system, including virtual
/// CPUs (hyper-threads).  On a single-processor system the result is `1`.
pub fn cpu_get_count() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

// ---------------------------------------------------------------------------
// Thread lifecycle
// ---------------------------------------------------------------------------

/// Spawn a new thread that executes the closure `f`.
///
/// Returns a [`JoinHandle`] that can later be passed to [`thread_join`].
/// The `flags` parameter from the C API is unnecessary — Rust closures
/// capture their environment directly.
pub fn begin_thread<F>(f: F) -> JoinHandle<()>
where
    F: FnOnce() + Send + 'static,
{
    thread::spawn(f)
}

/// Block until the thread represented by `handle` finishes.
///
/// If the thread panicked, the panic payload is logged and the function
/// returns normally (mirroring the C semantics where `pthread_join` always
/// succeeds).
pub fn thread_join(handle: JoinHandle<()>) {
    if let Err(payload) = handle.join() {
        if let Some(msg) = payload.downcast_ref::<&str>() {
            warn!("thread_join: thread panicked: {}", msg);
        } else if let Some(msg) = payload.downcast_ref::<String>() {
            warn!("thread_join: thread panicked: {}", msg);
        } else {
            warn!("thread_join: thread panicked with non-string payload");
        }
    }
}

// ---------------------------------------------------------------------------
// CPU affinity & priority  (Linux-specific; no-ops elsewhere)
// ---------------------------------------------------------------------------

/// Pin the current thread to the given CPU (0-indexed).
///
/// On Linux this calls `sched_setaffinity`.  On other platforms the call is
/// a no-op that logs a warning.
pub fn cpu_set_affinity(processor: u32) {
    #[cfg(target_os = "linux")]
    {
        use nix::sched::{sched_setaffinity, CpuSet};
        use nix::unistd::Pid;

        let mut cpuset = CpuSet::new();
        if cpuset.set(processor as usize).is_err() {
            warn!(
                "cpu_set_affinity: processor {} out of range",
                processor
            );
            return;
        }

        // Pid 0 = calling thread.
        if let Err(e) = sched_setaffinity(Pid::from_raw(0), &cpuset) {
            warn!("cpu_set_affinity: sched_setaffinity failed: {}", e);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = processor;
        warn!("cpu_set_affinity: not implemented on this platform");
    }
}

/// Raise the scheduling priority of the current thread to the maximum
/// allowed by its current policy.
///
/// This is a best-effort call — if the OS denies the request (e.g. the
/// process is not running as root) a warning is logged and execution
/// continues.
pub fn cpu_raise_priority() {
    #[cfg(target_os = "linux")]
    unsafe {
        let thread = libc::pthread_self();
        let mut policy: libc::c_int = 0;
        let mut param = std::mem::zeroed::<libc::sched_param>();

        let ret = libc::pthread_getschedparam(thread, &mut policy, &mut param);
        if ret != 0 {
            warn!("cpu_raise_priority: pthread_getschedparam failed: {}", ret);
            return;
        }

        let max_prio = libc::sched_get_priority_max(policy);
        if max_prio == -1 {
            warn!("cpu_raise_priority: sched_get_priority_max failed");
            return;
        }

        let ret = libc::pthread_setschedprio(thread, max_prio);
        if ret != 0 {
            warn!(
                "cpu_raise_priority: pthread_setschedprio failed: {}",
                ret
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        warn!("cpu_raise_priority: not implemented on this platform");
    }
}

// ---------------------------------------------------------------------------
// Atomic operations
// ---------------------------------------------------------------------------

/// Atomically subtract `rhs` from `*lhs`, returning the **previous** value.
pub fn locked_subtract_u32(lhs: &AtomicU32, rhs: u32) -> u32 {
    lhs.fetch_sub(rhs, Ordering::SeqCst)
}

/// Atomically add `src` to `*dst`, returning the **new** (post-addition) value.
///
/// This mirrors `__sync_add_and_fetch` / `_InterlockedExchangeAdd`-and-fetch
/// semantics from the C code.
pub fn locked_add_u32(dst: &AtomicU32, src: u32) -> u32 {
    dst.fetch_add(src, Ordering::SeqCst).wrapping_add(src)
}

/// Atomic compare-and-swap on a 32-bit value.
///
/// If `*dst == expected`, store `src` into `*dst` and return `true`.
/// Otherwise leave `*dst` unchanged and return `false`.
pub fn locked_cas32(dst: &AtomicU32, src: u32, expected: u32) -> bool {
    dst.compare_exchange(expected, src, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

/// Atomic compare-and-swap on a 64-bit value.
///
/// If `*dst == expected`, store `src` into `*dst` and return `true`.
/// Otherwise leave `*dst` unchanged and return `false`.
pub fn locked_cas64(dst: &AtomicU64, src: u64, expected: u64) -> bool {
    dst.compare_exchange(expected, src, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

// ---------------------------------------------------------------------------
// Memory fences & CPU hints
// ---------------------------------------------------------------------------

/// Write (release) memory barrier — ensures all prior stores are visible
/// before any subsequent stores.
#[inline]
pub fn fence_release() {
    fence(Ordering::Release);
}

/// Read (acquire) memory barrier — ensures all subsequent loads see the
/// effects of prior stores that were paired with a release fence.
#[inline]
pub fn fence_acquire() {
    fence(Ordering::Acquire);
}

/// Hint to the processor that we are in a spin-wait loop.
///
/// On x86 this emits a `PAUSE` instruction; on other architectures it may
/// be a no-op or yield hint.
#[inline]
pub fn cpu_pause() {
    std::hint::spin_loop();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::sync::Arc;

    #[test]
    fn cpu_count_at_least_one() {
        assert!(cpu_get_count() >= 1);
    }

    #[test]
    fn begin_and_join_thread() {
        let flag = Arc::new(AtomicU32::new(0));
        let flag_clone = Arc::clone(&flag);
        let handle = begin_thread(move || {
            locked_add_u32(&flag_clone, 42);
        });
        thread_join(handle);
        assert_eq!(flag.load(Ordering::SeqCst), 42);
    }

    #[test]
    fn locked_add_returns_new_value() {
        let val = AtomicU32::new(10);
        let result = locked_add_u32(&val, 5);
        assert_eq!(result, 15);
        assert_eq!(val.load(Ordering::SeqCst), 15);
    }

    #[test]
    fn locked_subtract_returns_old_value() {
        let val = AtomicU32::new(10);
        let result = locked_subtract_u32(&val, 3);
        assert_eq!(result, 10);
        assert_eq!(val.load(Ordering::SeqCst), 7);
    }

    #[test]
    fn cas32_success_and_failure() {
        let val = AtomicU32::new(42);
        assert!(locked_cas32(&val, 99, 42));
        assert_eq!(val.load(Ordering::SeqCst), 99);
        assert!(!locked_cas32(&val, 100, 42)); // 42 != 99
        assert_eq!(val.load(Ordering::SeqCst), 99);
    }

    #[test]
    fn cas64_success_and_failure() {
        let val = AtomicU64::new(1_000_000);
        assert!(locked_cas64(&val, 2_000_000, 1_000_000));
        assert_eq!(val.load(Ordering::SeqCst), 2_000_000);
        assert!(!locked_cas64(&val, 3_000_000, 1_000_000));
        assert_eq!(val.load(Ordering::SeqCst), 2_000_000);
    }
}
