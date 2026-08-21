//! Utility modules for network operations, logging, and safe operations.

pub mod logger;
pub mod checksum;
pub mod safefunc;
pub mod errormsg;
pub mod extract;
pub mod malloc;

// Re-export commonly used functions and types (not macros - those are auto-exported at crate root)
pub use logger::{set_log_level, get_log_level, add_log_level};
pub use checksum::{checksum_ipv4, checksum_ipv6};
pub use extract::{ExtractBuffer, Endian};
pub use errormsg::{errmsg_init, errmsg_clear};
