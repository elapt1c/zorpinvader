//! Socket type definitions.
//!
//! Mirrors the C `pixie-sockets` header, which provides a platform-
//! independent `SOCKET` typedef.  In Rust, most socket work goes through
//! `std::net`, but raw file descriptors / handles are still needed when
//! interfacing with low-level APIs (e.g. raw sockets, `select`).

/// Platform-native raw socket type.
///
/// * **Unix** — `i32` (file descriptor), matching `typedef int SOCKET` in C.
/// * **Windows** — `usize` (`SOCKET` / `RawSocket`), matching `WinSock2.h`.
#[cfg(unix)]
pub type Socket = std::os::unix::io::RawFd;

#[cfg(windows)]
pub type Socket = std::os::windows::io::RawSocket;

/// Sentinel value representing an invalid / uninitialised socket.
///
/// * **Unix** — `-1`
/// * **Windows** — `!0` (`INVALID_SOCKET` from `WinSock2.h`)
#[cfg(unix)]
pub const INVALID_SOCKET: Socket = -1;

#[cfg(windows)]
pub const INVALID_SOCKET: Socket = !0;

/// Check whether a raw socket value is valid.
#[inline]
pub fn is_valid_socket(sock: Socket) -> bool {
    sock != INVALID_SOCKET
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_socket_is_not_valid() {
        assert!(!is_valid_socket(INVALID_SOCKET));
    }

    #[test]
    fn zero_is_valid_socket() {
        // fd 0 (stdin) is technically a valid fd value.
        assert!(is_valid_socket(0));
    }

    #[test]
    fn positive_fd_is_valid() {
        assert!(is_valid_socket(3));
    }
}
