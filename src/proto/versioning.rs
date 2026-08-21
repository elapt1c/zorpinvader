//! Service versioning protocol parser.
//!
//! A stub parser registered for service versioning.
//! The C implementation is largely a placeholder with no real parsing logic.

use crate::proto::banout::BannerOutput;
use crate::proto::banner1::{Banner1, StreamState};

/// Parse versioning data (stub - no-op).
///
/// The C implementation does nothing with the input data.
pub fn versioning_tcp_parse(
    _banner1: &Banner1,
    pstate: &mut StreamState,
    _px: &[u8],
    _length: usize,
    _banout: &mut BannerOutput,
) {
    // No-op: the C implementation ignores all parameters
    // and just saves the (unchanged) state back
    let _state = pstate.state;
}

pub fn versioning_init(_banner1: &mut Banner1) {}
pub fn versioning_selftest() -> bool { true }
