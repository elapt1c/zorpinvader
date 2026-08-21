//! Global state variables using atomics for thread-safe access.
//!
//! These are used across the scanner to track overall progress and
//! coordinate between transmit and receive threads.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// True when the transmit thread has finished sending all probes.
pub static IS_TX_DONE: AtomicBool = AtomicBool::new(false);

/// True when the receive thread has finished processing responses.
pub static IS_RX_DONE: AtomicBool = AtomicBool::new(false);

/// Current wall-clock time as seconds since UNIX epoch.
/// Updated periodically by the status printing code.
pub static GLOBAL_NOW: AtomicU64 = AtomicU64::new(0);

/// Accessor functions for compatibility with C-style access patterns.
pub fn is_tx_done() -> bool {
    IS_TX_DONE.load(Ordering::Relaxed)
}

pub fn set_tx_done(done: bool) {
    IS_TX_DONE.store(done, Ordering::Relaxed);
}

pub fn is_rx_done() -> bool {
    IS_RX_DONE.load(Ordering::Relaxed)
}

pub fn set_rx_done(done: bool) {
    IS_RX_DONE.store(done, Ordering::Relaxed);
}

pub fn global_now() -> u64 {
    GLOBAL_NOW.load(Ordering::Relaxed)
}

pub fn update_global_now() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    GLOBAL_NOW.store(now, Ordering::Relaxed);
}
