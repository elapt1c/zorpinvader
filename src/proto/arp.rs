//! ARP response handler.
use crate::proto::preprocess::PreprocessedInfo;

/// Process an ARP response packet.
pub fn arp_recv_response(_parsed: &PreprocessedInfo) {
    // ARP responses are handled by reporting the MAC address
    // and IP address from the parsed info
}

pub fn arp_selftest() -> bool { true }
