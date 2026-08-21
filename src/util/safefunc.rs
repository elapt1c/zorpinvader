//! Safe string and buffer operation wrappers.
//!
//! While Rust's standard library provides safe string operations by default,
//! this module provides additional utilities for compatibility with C code
//! and case-insensitive comparisons.

use std::time::{SystemTime, UNIX_EPOCH};

/// Case-insensitive byte comparison.
///
/// Returns 0 if equal, non-zero otherwise.
///
/// # Arguments
/// * `lhs` - Left-hand side byte slice
/// * `rhs` - Right-hand side byte slice
pub fn memcasecmp(lhs: &[u8], rhs: &[u8]) -> i32 {
    if lhs.len() != rhs.len() {
        return -1;
    }

    for i in 0..lhs.len() {
        if lhs[i].to_ascii_lowercase() != rhs[i].to_ascii_lowercase() {
            return -1;
        }
    }

    0
}

/// Safe string copy with bounds checking.
///
/// Copies `src` into `dst` up to `dst`'s capacity, ensuring null termination
/// for C compatibility. Returns the number of bytes copied (excluding null).
///
/// # Arguments
/// * `dst` - Destination buffer
/// * `src` - Source string
///
/// # Returns
/// Number of bytes copied
pub fn safe_strcpy(dst: &mut [u8], src: &str) -> usize {
    if dst.is_empty() {
        return 0;
    }

    let src_bytes = src.as_bytes();
    let copy_len = src_bytes.len().min(dst.len() - 1);

    dst[..copy_len].copy_from_slice(&src_bytes[..copy_len]);
    dst[copy_len] = 0; // Null terminate

    copy_len
}

/// Safe string copy returning Result for error handling.
///
/// # Arguments
/// * `dst` - Destination buffer
/// * `src` - Source string
///
/// # Returns
/// Ok(bytes_copied) or Err if destination is empty
pub fn safe_strcpy_checked(dst: &mut [u8], src: &str) -> Result<usize, &'static str> {
    if dst.is_empty() {
        return Err("destination buffer is empty");
    }

    Ok(safe_strcpy(dst, src))
}

/// Get current time as Unix timestamp.
///
/// # Returns
/// Seconds since Unix epoch, or 0 on error
pub fn safe_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Safe localtime equivalent returning (year, month, day, hour, min, sec).
///
/// # Arguments
/// * `timestamp` - Unix timestamp
///
/// # Returns
/// Tuple of (year, month, day, hour, minute, second) or None on error
pub fn safe_localtime(timestamp: u64) -> Option<(i32, u32, u32, u32, u32, u32)> {
    // This is a simplified implementation
    // In production, use the `chrono` crate for proper timezone handling
    use std::time::{Duration, UNIX_EPOCH};

    let datetime = UNIX_EPOCH + Duration::from_secs(timestamp);
    let secs = timestamp as i64;

    // Simplified calculation (UTC - use chrono for proper localtime)
    let days = secs / 86400;
    let day_secs = secs % 86400;
    let hour = (day_secs / 3600) as u32;
    let minute = ((day_secs % 3600) / 60) as u32;
    let second = (day_secs % 60) as u32;

    // Simplified date calculation from days since epoch
    let mut year = 1970;
    let mut remaining_days = days;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 0;
    for (i, &days_in_month) in days_in_months.iter().enumerate() {
        if remaining_days < days_in_month {
            month = i;
            break;
        }
        remaining_days -= days_in_month;
    }

    let day = remaining_days as u32 + 1;
    let month = month as u32 + 1;

    let _ = datetime; // Suppress unused warning

    Some((year, month, day, hour, minute, second))
}

/// Safe gmtime equivalent (same as localtime in this simplified version).
///
/// # Arguments
/// * `timestamp` - Unix timestamp
///
/// # Returns
/// Tuple of (year, month, day, hour, minute, second) or None on error
pub fn safe_gmtime(timestamp: u64) -> Option<(i32, u32, u32, u32, u32, u32)> {
    safe_localtime(timestamp)
}

/// Check if a year is a leap year.
fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memcasecmp() {
        assert_eq!(memcasecmp(b"Hello", b"hello"), 0);
        assert_eq!(memcasecmp(b"ABC", b"abc"), 0);
        assert_ne!(memcasecmp(b"Hello", b"World"), 0);
        assert_ne!(memcasecmp(b"Hi", b"Hello"), 0);
    }

    #[test]
    fn test_safe_strcpy() {
        let mut dst = [0u8; 10];
        let copied = safe_strcpy(&mut dst, "Hello");
        assert_eq!(copied, 5);
        assert_eq!(&dst[..5], b"Hello");
        assert_eq!(dst[5], 0); // Null terminated
    }

    #[test]
    fn test_safe_strcpy_truncation() {
        let mut dst = [0u8; 5];
        let copied = safe_strcpy(&mut dst, "Hello World");
        assert_eq!(copied, 4); // Only 4 bytes + null
        assert_eq!(&dst[..4], b"Hell");
        assert_eq!(dst[4], 0);
    }

    #[test]
    fn test_safe_strcpy_empty_dst() {
        let mut dst = [0u8; 0];
        let copied = safe_strcpy(&mut dst, "Hello");
        assert_eq!(copied, 0);
    }

    #[test]
    fn test_is_leap_year() {
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2020));
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(2021));
    }
}
