//! Error message handling with deduplication.
//!
//! Provides error reporting functions that print each unique error message
//! only once, using a hash table to track seen messages.

use std::collections::HashSet;
use std::io::Write;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};

/// Global entropy value for hash randomization
static ENTROPY: OnceLock<u64> = OnceLock::new();

/// Global table of seen error messages
static SEEN_MESSAGES: OnceLock<Mutex<HashSet<u64>>> = OnceLock::new();

/// Initialize the error message system with entropy for hash randomization.
///
/// # Arguments
/// * `entropy` - Random value used for hash seeding
pub fn errmsg_init(entropy: u64) {
    let _ = ENTROPY.set(entropy);
    let _ = SEEN_MESSAGES.set(Mutex::new(HashSet::new()));
}

/// Get the entropy value, defaulting to 0 if not initialized
fn get_entropy() -> u64 {
    ENTROPY.get().copied().unwrap_or(0)
}

/// Get or initialize the seen messages set
fn get_seen_messages() -> &'static Mutex<HashSet<u64>> {
    SEEN_MESSAGES.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Hash a string using a simple hash function with entropy.
///
/// This is a simplified version - in production, use a proper hash like siphash.
fn hash_string(s: &str, entropy: u64) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    entropy.hash(&mut hasher);
    hasher.finish()
}

/// Check if a message has been seen before and mark it as seen.
///
/// Returns true if this is the first time seeing this message.
fn check_and_mark_seen(msg: &str) -> bool {
    let entropy = get_entropy();
    let hash = hash_string(msg, entropy);

    let mut seen = get_seen_messages().lock().unwrap();
    seen.insert(hash)
}

/// Print an error message only once.
///
/// Subsequent calls with the same message will be silently ignored.
///
/// # Arguments
/// * `args` - Format arguments
///
/// # Example
/// ```
/// use zi::util::errormsg::errmsg;
/// errmsg!("Connection failed: {}", error);
/// ```
#[macro_export]
macro_rules! errmsg {
    ($($arg:tt)*) => {
        $crate::util::errormsg::errmsg_impl(format_args!($($arg)*))
    };
}

/// Internal implementation for error messages
pub fn errmsg_impl(args: std::fmt::Arguments) {
    let msg = format!("{}", args);

    // Only print if we haven't seen this message before
    if check_and_mark_seen(&msg) {
        let stderr = std::io::stderr();
        let mut handle = stderr.lock();
        let _ = write!(handle, "[-] ERR: ");
        let _ = writeln!(handle, "{}", msg);
    }
}

/// Print an error message with IP and port, only once.
///
/// Subsequent calls with the same message will be silently ignored.
///
/// # Arguments
/// * `ip` - The IP address to include in the error
/// * `port` - The port number to include in the error
/// * `args` - Format arguments
///
/// # Example
/// ```
/// use zi::util::errormsg::errmsg_ip;
/// errmsg_ip!(addr, port, "Connection refused");
/// ```
#[macro_export]
macro_rules! errmsg_ip {
    ($ip:expr, $port:expr, $($arg:tt)*) => {
        $crate::util::errormsg::errmsg_ip_impl($ip, $port, format_args!($($arg)*))
    };
}

/// Internal implementation for IP error messages
pub fn errmsg_ip_impl(ip: IpAddr, port: u16, args: std::fmt::Arguments) {
    let msg = format!("{}:{}: {}", ip, port, args);

    // Only print if we haven't seen this message before
    if check_and_mark_seen(&msg) {
        let stderr = std::io::stderr();
        let mut handle = stderr.lock();
        let _ = write!(handle, "[-] {}", msg);
        let _ = writeln!(handle);
    }
}

/// Clear all seen error messages, allowing them to be printed again.
///
/// Useful for testing or resetting error state.
pub fn errmsg_clear() {
    if let Some(seen) = SEEN_MESSAGES.get() {
        let mut messages = seen.lock().unwrap();
        messages.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_errmsg_deduplication() {
        errmsg_init(12345);

        // First call should return true (new message)
        assert!(check_and_mark_seen("test error 1"));

        // Second call with same message should return false (already seen)
        assert!(!check_and_mark_seen("test error 1"));

        // Different message should return true
        assert!(check_and_mark_seen("test error 2"));
    }

    #[test]
    fn test_errmsg_clear() {
        errmsg_init(12345);

        assert!(check_and_mark_seen("test clear"));
        assert!(!check_and_mark_seen("test clear"));

        errmsg_clear();

        // After clearing, should be able to see it again
        assert!(check_and_mark_seen("test clear"));
    }

    #[test]
    fn test_hash_string() {
        let hash1 = hash_string("test", 123);
        let hash2 = hash_string("test", 123);
        let hash3 = hash_string("test", 456);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
}
