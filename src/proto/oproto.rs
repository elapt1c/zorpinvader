//! Other IP protocol handler.
//!
//! Handles IP protocols that are not TCP, UDP, ICMP, or SCTP.
//! Used for scanning things like GRE tunnels.
//!
//! Currently a stub that does nothing, matching the C implementation.

use crate::proto::preprocess::PreprocessedInfo;

/// Handle a response for an "other" IP protocol.
///
/// This is intentionally a no-op stub, matching the C source.
/// The C code does nothing with the packet data.
pub fn handle_oproto(
    _px: &[u8],
    _length: usize,
    _parsed: &PreprocessedInfo,
    _entropy: u64,
) {
    // No-op: the C implementation ignores all parameters
}

pub fn oproto_selftest() -> bool { true }
