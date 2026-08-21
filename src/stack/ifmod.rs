//! Network interface helpers.
//!
//! Provides a thin wrapper around the adapter to query the datalink (link
//! layer) type, which determines how we handle ARP/NDP resolution.
//!
//! Converted from `c-src/stack-if.c`.
//!
//! Named `ifmod` to avoid collision with the Rust `if` keyword.

use crate::rawsock::adapter::{Adapter, LinkType};

/// Return the datalink type of the given adapter.
///
/// Returns `1` for Ethernet. If the adapter uses a raw-socket ring
/// (DPDK-style), we always report Ethernet. Otherwise we return the
/// adapter's native link type.
pub fn datalink(adapter: &Adapter) -> u32 {
    // In the C code, if adapter->ring is non-NULL, the link type is
    // always 1 (Ethernet). We model this by checking if the adapter
    // has an active socket (our equivalent of the raw ring).
    if adapter.socket().is_some() {
        1 // Ethernet
    } else {
        adapter.link_type.to_raw()
    }
}

/// Check whether the adapter uses a VPN/tunnel link (datalink type 12).
///
/// When using a VPN, ARP/NDP resolution is meaningless and we must use
/// a fake router MAC address.
pub fn is_vpn_link(adapter: &Adapter) -> bool {
    adapter.link_type.to_raw() == 12
}

/// Check whether the adapter is Ethernet.
pub fn is_ethernet(adapter: &Adapter) -> bool {
    adapter.link_type == LinkType::Ethernet
}
