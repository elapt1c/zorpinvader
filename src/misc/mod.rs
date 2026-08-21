//! Miscellaneous utility modules.
//!
//! This group collects several independent subsystems that don't fit
//! neatly into the other top-level modules:
//!
//! - [`syn_cookie`] — SYN cookie generation for stateless scanning
//! - [`rstfilter`] — RST filter to suppress duplicate RST transmissions
//! - [`in_binary`] — Binary scan file reader (`--readscan`)
//! - [`in_filter`] — Filtering for binary scan results
//! - [`in_report`] — Reporting/annotation from binary scan files
//! - [`read_service_probes`] — Nmap `nmap-service-probes` file parser

pub mod syn_cookie;
pub mod rstfilter;
pub mod in_binary;
pub mod in_filter;
pub mod in_report;
pub mod read_service_probes;

// Re-export commonly used items
pub use syn_cookie::{syn_cookie, syn_cookie_ipv4, syn_cookie_ipv6, get_entropy};
pub use rstfilter::ResetFilter;
pub use in_binary::readscan_binary_scanfile;
pub use in_filter::readscan_filter_pass;
pub use in_report::CnDatabase;
pub use read_service_probes::{
    NmapServiceProbeList, NmapServiceProbe, ServiceProbeMatch,
    ServiceVersionInfo, ServiceProbeFallback,
    SvcPRecordType, SvcVInfoType,
};
