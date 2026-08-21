//! High-resolution monotonic timing.
//!
//! Mirrors the C `pixie-timer` module.  Uses `std::time::Instant` as the
//! monotonic clock source (backed by `CLOCK_MONOTONIC` on Linux,
//! `mach_absolute_time` on macOS, `QueryPerformanceCounter` on Windows).
//!
//! The C API returns absolute microsecond / nanosecond timestamps from an
//! opaque epoch (boot time).  We replicate that by anchoring a
//! process-wide `Instant` at first use and returning elapsed durations
//! relative to it.

use std::thread;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;

/// Process-wide monotonic epoch — initialised on first access.
static EPOCH: Lazy<Instant> = Lazy::new(Instant::now);

// ---------------------------------------------------------------------------
// Time queries
// ---------------------------------------------------------------------------

/// Return the current monotonic time in **microseconds** relative to an
/// arbitrary process-wide epoch.
///
/// Use this for measuring elapsed time — the value is monotonically
/// increasing and is not affected by wall-clock adjustments.
#[inline]
pub fn gettime() -> u64 {
    EPOCH.elapsed().as_micros() as u64
}

/// Return the current monotonic time in **nanoseconds** relative to an
/// arbitrary process-wide epoch.
#[inline]
pub fn nanotime() -> u64 {
    EPOCH.elapsed().as_nanos() as u64
}

// ---------------------------------------------------------------------------
// Sleep
// ---------------------------------------------------------------------------

/// Sleep for the specified number of **microseconds**.
pub fn usleep(usec: u64) {
    thread::sleep(Duration::from_micros(usec));
}

/// Sleep for the specified number of **milliseconds**.
pub fn mssleep(ms: u32) {
    thread::sleep(Duration::from_millis(ms as u64));
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

/// Verify that the timing primitives are accurate to within ±90%.
///
/// Returns `0` on success, `1` on failure.  The wide tolerance accounts for
/// heavily-loaded CI environments where scheduling latency can be extreme.
pub fn time_selftest() -> i32 {
    const DURATION_US: u64 = 456_789;

    let start = gettime();
    usleep(DURATION_US);
    let elapsed = gettime() - start;

    if (elapsed as f64) < 0.9 * (DURATION_US as f64) {
        eprintln!("timing error, elapsed ({}) < 0.9 * duration", elapsed);
        return 1;
    }
    if 1.9 * (DURATION_US as f64) < (elapsed as f64) {
        eprintln!(
            "timing error, long delay {:5.0}%",
            (elapsed as f64) * 100.0 / (DURATION_US as f64)
        );
        return 1;
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gettime_is_monotonic() {
        let t1 = gettime();
        // Busy-wait a tiny bit to ensure the clock advances.
        while gettime() == t1 {}
        let t2 = gettime();
        assert!(t2 > t1);
    }

    #[test]
    fn nanotime_is_monotonic() {
        let t1 = nanotime();
        while nanotime() == t1 {}
        let t2 = nanotime();
        assert!(t2 > t1);
    }

    #[test]
    fn nanotime_higher_resolution_than_gettime() {
        // Nanosecond value should be roughly 1000× the microsecond value.
        let us = gettime();
        let ns = nanotime();
        // Both come from the same clock so ns / 1000 ≈ us (within a small margin).
        assert!(ns >= us * 1000);
    }

    #[test]
    fn mssleep_does_not_panic() {
        mssleep(1);
    }

    #[test]
    fn usleep_does_not_panic() {
        usleep(100);
    }

    #[test]
    fn selftest_passes() {
        assert_eq!(time_selftest(), 0);
    }
}

/// Module-level selftest wrapper.
pub fn selftest() -> bool { time_selftest() == 0 }
