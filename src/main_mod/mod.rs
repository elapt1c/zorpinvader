//! Main module group for ZorpInvader.
//!
//! This module contains the core configuration, status reporting, rate limiting,
//! duplicate detection, packet tracing, and other main-level functionality.

pub mod conf;
pub mod status;
pub mod throttle;
pub mod dedup;
pub mod ptrace;
pub mod globals;
pub mod readrange;
pub mod initadapter;
pub mod listscan;

pub use conf::{Zorp, Operation, OutputFormat};
pub use status::Status;
pub use throttle::Throttler;
pub use dedup::DedupTable;
pub use globals::{is_tx_done, is_rx_done, global_now};
