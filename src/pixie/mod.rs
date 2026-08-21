//! Platform abstraction layer — portable wrappers for OS-specific APIs.
//!
//! This module mirrors the C `pixie-*` portability layer, providing
//! cross-platform access to threads, timers, file I/O, crash backtraces,
//! and socket type aliases.

pub mod threads;
pub mod timer;
pub mod file;
pub mod backtrace;
pub mod sockets;

pub use threads::{
    cpu_get_count, begin_thread, thread_join,
    cpu_set_affinity, cpu_raise_priority,
    locked_subtract_u32, locked_add_u32, locked_cas32, locked_cas64,
    fence_release, fence_acquire, cpu_pause,
};

pub use timer::{gettime, nanotime, usleep, mssleep, time_selftest};

pub use file::fopen_shareable;

pub use backtrace::{backtrace_init, backtrace_finish};

pub use sockets::{Socket, INVALID_SOCKET};
