/// MassIP module - handles IP addresses, ports, and range management.
///
/// This module is the Rust conversion of the C massip module group,
/// providing types and functions for managing IPv4/IPv6 addresses,
/// port ranges, and scan target lists.

pub mod addr;
pub mod port;
pub mod rangesv4;
pub mod rangesv6;
pub mod massip;
pub mod parse;

// Re-export commonly used types
pub use addr::{Ipv4Address, Ipv6Address, IpAddress, MacAddress, Massint128};
pub use port::*;
pub use rangesv4::{Range, RangeList};
pub use rangesv6::{Range6, Range6List};
pub use massip::MassIP;
pub use parse::{RangeParseResult, massip_parse_range, massip_parse_file, massip_parse_ipv4, massip_parse_ipv6};
