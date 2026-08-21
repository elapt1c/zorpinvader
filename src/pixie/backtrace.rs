//! Crash backtrace printing.
//!
//! Mirrors the C `pixie-backtrace` module.  The C version installs a
//! `SIGSEGV` handler that walks the stack with `backtrace_symbols` and
//! optionally resolves addresses via `addr2line`.
//!
//! In Rust, the idiomatic equivalent is a custom **panic hook** that prints
//! a `std::backtrace::Backtrace`.  This covers all panic-induced crashes;
//! true segmentation faults (which bypass the panic mechanism) would require
//! an external crate such as `signal-hook` — but those are exceedingly rare
//! in safe Rust code.

use std::backtrace::Backtrace;
use std::panic;
use std::sync::Mutex;

use once_cell::sync::Lazy;

/// Stores the resolved executable path for diagnostic output.
static PROGRAM_PATH: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));

/// Initialise crash-backtrace handling.
///
/// `program_path` should be `argv[0]` or an equivalent identifier for the
/// running executable.  On Linux we attempt to resolve the real path via
/// `/proc/self/exe`; on failure the supplied string is used as-is.
///
/// A custom panic hook is installed that prints:
///   * a header directing users to the project's issue tracker
///   * the panic message and source location
///   * a full stack backtrace
pub fn backtrace_init(program_path: &str) {
    // Resolve the real executable path when possible.
    {
        let mut path = PROGRAM_PATH.lock().unwrap();
        *path = std::fs::read_link("/proc/self/exe")
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| program_path.to_string());
    }

    panic::set_hook(Box::new(|info| {
        eprintln!("======================================================================");
        eprintln!(" Panic: please post this backtrace to:");
        eprintln!(" https://github.com/elapt1c/zorpinvader/issues");
        eprintln!("======================================================================");

        // Panic message.
        if let Some(msg) = info.payload().downcast_ref::<&str>() {
            eprintln!("message: {}", msg);
        } else if let Some(msg) = info.payload().downcast_ref::<String>() {
            eprintln!("message: {}", msg);
        }

        // Source location.
        if let Some(loc) = info.location() {
            eprintln!("at {}:{}:{}", loc.file(), loc.line(), loc.column());
        }

        // Full backtrace.
        eprintln!("\nBacktrace:\n{}", Backtrace::force_capture());
    }));
}

/// Clean up backtrace resources.
///
/// The C implementation is a no-op on most platforms; the Rust version is
/// likewise a no-op because the panic hook lives for the process lifetime.
pub fn backtrace_finish() {
    // Intentionally empty — nothing to tear down.
}

/// Retrieve the resolved program path stored during [`backtrace_init`].
///
/// This is a convenience accessor for other modules that may want to
/// display the executable name in diagnostics.
pub fn program_path() -> String {
    PROGRAM_PATH
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_and_query_path() {
        backtrace_init("test_program");
        let path = program_path();
        // On Linux, /proc/self/exe should resolve; otherwise we fall back.
        assert!(!path.is_empty());
    }

    #[test]
    fn finish_does_not_panic() {
        backtrace_finish();
    }
}
