//! The scan unit: one adapter plus the fetch/verify pipeline, scan one block at a time.
//!
//! * [`scan_unit`] — [`ScanEngine`], the thing that actually emits packets.
//! * [`hits`] — bounded per-block collection of open ports.
//! * [`keys`] — tails `found_keys.csv` so confirmed keys can be reported.

pub mod hits;
pub mod keys;
pub mod scan_unit;

pub use hits::HitLog;
pub use keys::KeyTail;
pub use scan_unit::{BlockOutcome, BlockProgress, ScanEngine};
