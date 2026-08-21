//! Portable file operations.
//!
//! Mirrors the C `pixie-file` module.  The primary purpose of the C code is
//! to open files in a "shareable" way on Windows (where `fopen` locks the
//! file).  On Unix this is straightforward; the Rust implementation uses
//! `std::fs::OpenOptions` on all platforms.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Open a file for writing in a shareable manner.
///
/// * If `is_append` is `true`, the file is opened in append mode (writes go
///   to the end; the file is created if it does not exist).
/// * If `is_append` is `false`, the file is truncated or created.
///
/// On Windows the underlying C code uses `CreateFileA` with
/// `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE` so that the file
/// can be renamed or read while open.  Rust's `std::fs::OpenOptions` already
/// opens files with generous sharing on Windows, so no special handling is
/// needed.
///
/// # Errors
///
/// Returns an [`io::Error`] if the file cannot be opened or created.
pub fn fopen_shareable(filename: &str, is_append: bool) -> Result<File, io::Error> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .append(is_append)
        .truncate(!is_append)
        .open(Path::new(filename))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn open_write_truncate() {
        let dir = std::env::temp_dir().join("pixie_file_test_write");
        let path = dir.to_string_lossy().to_string();

        // First write
        {
            let mut f = fopen_shareable(&path, false).expect("open for write");
            write!(f, "hello").unwrap();
        }

        // Second write should truncate
        {
            let mut f = fopen_shareable(&path, false).expect("open for write (truncate)");
            write!(f, "x").unwrap();
        }

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "x");

        std::fs::remove_file(&dir).ok();
    }

    #[test]
    fn open_append() {
        let dir = std::env::temp_dir().join("pixie_file_test_append");
        let path = dir.to_string_lossy().to_string();

        // Initial write
        {
            let mut f = fopen_shareable(&path, false).expect("open for write");
            write!(f, "hello").unwrap();
        }

        // Append
        {
            let mut f = fopen_shareable(&path, true).expect("open for append");
            write!(f, " world").unwrap();
        }

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "hello world");

        std::fs::remove_file(&dir).ok();
    }
}
