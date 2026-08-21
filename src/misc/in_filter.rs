//! Filtering for binary scan file records.
//!
//! When reading back binary scan results (`--readscan`), the user may
//! want to filter records by IP address, port number, or banner type.
//! This module provides that filtering logic.
//!
//! **Ported from C `in-filter.c`.**

use crate::massip::addr::IpAddress;
use crate::massip::massip::MassIP;
use crate::massip::rangesv4::RangeList;

/// Decide whether a record passes the readscan filter.
///
/// Returns `true` if the record should be kept, `false` if it should be
/// dropped.
///
/// * `filter` — optional IP/port filter (from command-line targets).
///   If `None` or empty, all IPs/ports pass.
/// * `btypes` — optional banner-type filter. If `None` or empty,
///   all banner types pass.
pub fn readscan_filter_pass(
    ip: IpAddress,
    port: u32,
    banner_type: u32,
    filter: Option<&MassIP>,
    btypes: Option<&RangeList>,
) -> bool {
    if let Some(f) = filter {
        if f.count_ipv4s > 0 && !f.has_ip(ip) {
            return false;
        }
        if f.count_ports > 0 && !f.has_port(port) {
            return false;
        }
    }
    if let Some(bt) = btypes {
        if bt.count() > 0 && !bt.is_contains(banner_type) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_filter_passes_everything() {
        assert!(readscan_filter_pass(
            IpAddress::V4(0x0A000001),
            80,
            4,
            None,
            None,
        ));
    }
}
