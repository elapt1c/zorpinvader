//! Logging utilities with adjustable verbosity levels.
//!
//! Provides logging functions that output to stderr based on verbosity level.
//! Higher verbosity levels produce more detailed output.

use std::io::Write;
use std::net::IpAddr;
use std::sync::atomic::{AtomicI32, Ordering};

/// Global debug level - controls verbosity of log output
static GLOBAL_DEBUG_LEVEL: AtomicI32 = AtomicI32::new(0);

/// Set the global log level
pub fn set_log_level(level: i32) {
    GLOBAL_DEBUG_LEVEL.store(level, Ordering::SeqCst);
}

/// Get the current global log level
pub fn get_log_level() -> i32 {
    GLOBAL_DEBUG_LEVEL.load(Ordering::SeqCst)
}

/// Add to the global log level
pub fn add_log_level(delta: i32) {
    GLOBAL_DEBUG_LEVEL.fetch_add(delta, Ordering::SeqCst);
}

/// Log a message if the current debug level is >= the specified level.
///
/// # Arguments
/// * `level` - The verbosity level required to show this message
/// * `args` - Format arguments
///
/// # Example
/// ```
/// use zi::util::logger::log;
/// log(1, "Processing packet {}", packet_id);
/// ```
#[macro_export]
macro_rules! log {
    ($level:expr, $($arg:tt)*) => {
        $crate::util::logger::log_impl($level, format_args!($($arg)*))
    };
}

/// Internal implementation for logging
pub fn log_impl(level: i32, args: std::fmt::Arguments) {
    if level <= get_log_level() {
        let stderr = std::io::stderr();
        let mut handle = stderr.lock();
        let _ = writeln!(handle, "{}", args);
    }
}

/// Log a message with IP address and port information.
///
/// # Arguments
/// * `level` - The verbosity level required to show this message
/// * `ip` - The IP address to include in the log
/// * `port` - The port number to include in the log
/// * `args` - Format arguments
#[macro_export]
macro_rules! log_ip {
    ($level:expr, $ip:expr, $port:expr, $($arg:tt)*) => {
        $crate::util::logger::log_ip_impl($level, $ip, $port, format_args!($($arg)*))
    };
}

/// Internal implementation for IP logging
pub fn log_ip_impl(level: i32, ip: IpAddr, port: u16, args: std::fmt::Arguments) {
    if level <= get_log_level() {
        let stderr = std::io::stderr();
        let mut handle = stderr.lock();
        let _ = write!(handle, "{}:{}: ", ip, port);
        let _ = writeln!(handle, "{}", args);
    }
}

/// Log a network message with local port and remote IP.
///
/// # Arguments
/// * `port_me` - The local port number
/// * `ip_them` - The remote IP address
/// * `args` - Format arguments
#[macro_export]
macro_rules! log_net {
    ($port_me:expr, $ip_them:expr, $($arg:tt)*) => {
        $crate::util::logger::log_net_impl($port_me, $ip_them, format_args!($($arg)*))
    };
}

/// Internal implementation for network logging
pub fn log_net_impl(port_me: u16, ip_them: IpAddr, args: std::fmt::Arguments) {
    let stderr = std::io::stderr();
    let mut handle = stderr.lock();
    let _ = write!(handle, "{}:{}: ", port_me, ip_them);
    let _ = writeln!(handle, "{}", args);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_operations() {
        set_log_level(0);
        assert_eq!(get_log_level(), 0);

        add_log_level(2);
        assert_eq!(get_log_level(), 2);

        set_log_level(5);
        assert_eq!(get_log_level(), 5);
    }
}
