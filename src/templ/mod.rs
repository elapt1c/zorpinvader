//! Packet template module.
//!
//! Pre-built packet templates for each protocol (TCP, UDP, SCTP, ICMP, ARP).
//! The transmit thread uses these templates to quickly build packets by
//! patching in IP/port values rather than constructing packets from scratch.

pub mod opts;
pub mod nmap_payloads;
pub mod payloads;
pub mod tcp_hdr;
pub mod pkt;

pub use opts::{AddRemove, TemplateOptions};
pub use payloads::PayloadsUdp;
pub use pkt::{TemplateProtocol, TemplatePacket, TemplateSet};
