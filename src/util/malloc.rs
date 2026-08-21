//! Safe memory allocation helpers.
//!
//! While Rust's standard library already handles out-of-memory conditions
//! by panicking, this module provides explicit allocation functions that
//! match the C API and provide additional overflow checking.

use std::alloc::{alloc, alloc_zeroed, realloc, Layout};

/// Maximum size for a single dimension to prevent overflow
const MAX_NUM: usize = 1 << (std::mem::size_of::<usize>() * 4);

/// Check for multiplication overflow in allocation size.
///
/// # Arguments
/// * `count` - Number of elements
/// * `size` - Size of each element
///
/// # Returns
/// Ok(total_size) if no overflow, Err if overflow detected
fn check_overflow(count: usize, size: usize) -> Result<usize, &'static str> {
    if count >= MAX_NUM || size >= MAX_NUM {
        if size != 0 && count >= usize::MAX / size {
            return Err("allocation size overflow");
        }
    }
    Ok(count * size)
}

/// Allocate memory with panic on failure.
///
/// # Arguments
/// * `size` - Number of bytes to allocate
///
/// # Returns
/// A pointer to the allocated memory
///
/// # Panics
/// Panics if allocation fails or size is zero
pub fn safe_malloc(size: usize) -> *mut u8 {
    let size = if size == 0 { 1 } else { size };

    let layout = Layout::from_size_align(size, 1).expect("invalid layout");

    // SAFETY: layout is valid and non-zero
    let ptr = unsafe { alloc(layout) };

    if ptr.is_null() {
        eprintln!("[-] out of memory, aborting");
        std::process::abort();
    }

    ptr
}

/// Allocate zeroed memory with panic on failure.
///
/// # Arguments
/// * `count` - Number of elements
/// * `size` - Size of each element
///
/// # Returns
/// A pointer to the allocated zeroed memory
///
/// # Panics
/// Panics if allocation fails or size overflows
pub fn safe_calloc(count: usize, size: usize) -> *mut u8 {
    let total_size = check_overflow(count, size).unwrap_or_else(|_| {
        eprintln!("[-] alloc too large, aborting");
        std::process::abort();
    });

    if total_size == 0 {
        return std::ptr::null_mut();
    }

    let layout = Layout::from_size_align(total_size, 1).expect("invalid layout");

    // SAFETY: layout is valid and non-zero
    let ptr = unsafe { alloc_zeroed(layout) };

    if ptr.is_null() {
        eprintln!("[-] out of memory, aborting");
        std::process::abort();
    }

    ptr
}

/// Reallocate memory with panic on failure.
///
/// # Arguments
/// * `ptr` - Pointer to existing allocation (or null for new allocation)
/// * `old_size` - Size of the existing allocation
/// * `new_size` - New size to allocate
///
/// # Returns
/// A pointer to the reallocated memory
///
/// # Panics
/// Panics if reallocation fails
pub fn safe_realloc(ptr: *mut u8, old_size: usize, new_size: usize) -> *mut u8 {
    let new_size = if new_size == 0 { 1 } else { new_size };
    let old_size = if old_size == 0 { 1 } else { old_size };

    let layout = Layout::from_size_align(old_size, 1).expect("invalid layout");

    // SAFETY: ptr and layout are valid
    let new_ptr = unsafe { realloc(ptr, layout, new_size) };

    if new_ptr.is_null() {
        eprintln!("[-] out of memory, aborting");
        std::process::abort();
    }

    new_ptr
}

/// Reallocate array memory with overflow checking and panic on failure.
///
/// # Arguments
/// * `ptr` - Pointer to existing allocation (or null for new allocation)
/// * `old_size` - Size of the existing allocation
/// * `count` - New number of elements
/// * `size` - Size of each element
///
/// # Returns
/// A pointer to the reallocated memory
///
/// # Panics
/// Panics if size overflows or reallocation fails
pub fn safe_reallocarray(
    ptr: *mut u8,
    old_size: usize,
    count: usize,
    size: usize,
) -> *mut u8 {
    let new_size = check_overflow(count, size).unwrap_or_else(|_| {
        eprintln!("[-] alloc too large, aborting");
        std::process::abort();
    });

    if new_size == 0 {
        return std::ptr::null_mut();
    }

    safe_realloc(ptr, old_size, new_size)
}

/// Duplicate a string with panic on failure.
///
/// # Arguments
/// * `s` - String to duplicate
///
/// # Returns
/// A new String with the same contents
///
/// # Note
/// In Rust, this is equivalent to `s.to_string()`, but provided for
/// API compatibility with the C code.
pub fn safe_strdup(s: &str) -> String {
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_overflow() {
        assert!(check_overflow(10, 10).is_ok());
        assert_eq!(check_overflow(10, 10).unwrap(), 100);

        // Test overflow detection
        let result = check_overflow(usize::MAX, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_safe_malloc() {
        let ptr = safe_malloc(100);
        assert!(!ptr.is_null());

        // Clean up
        unsafe {
            std::alloc::dealloc(ptr, Layout::from_size_align(100, 1).unwrap());
        }
    }

    #[test]
    fn test_safe_calloc() {
        let ptr = safe_calloc(10, 10);
        assert!(!ptr.is_null());

        // Verify zeroed
        for i in 0..100 {
            assert_eq!(unsafe { *ptr.add(i) }, 0);
        }

        // Clean up
        unsafe {
            std::alloc::dealloc(ptr, Layout::from_size_align(100, 1).unwrap());
        }
    }

    #[test]
    fn test_safe_realloc() {
        let ptr = safe_malloc(50);
        assert!(!ptr.is_null());

        let new_ptr = safe_realloc(ptr, 50, 100);
        assert!(!new_ptr.is_null());

        // Clean up
        unsafe {
            std::alloc::dealloc(new_ptr, Layout::from_size_align(100, 1).unwrap());
        }
    }

    #[test]
    fn test_safe_strdup() {
        let original = "Hello, World!";
        let duplicate = safe_strdup(original);
        assert_eq!(duplicate, original);
    }

    #[test]
    fn test_zero_size_allocation() {
        let ptr = safe_malloc(0);
        assert!(!ptr.is_null());

        // Clean up
        unsafe {
            std::alloc::dealloc(ptr, Layout::from_size_align(1, 1).unwrap());
        }
    }
}
