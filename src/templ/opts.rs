//! Template options configuration.
//!
//! Controls how packet template fields are modified based on
//! command-line configuration. Each field can be left at its
//! default value, explicitly added, or removed.

use crate::massip::addr::{IpAddress, MacAddress};

/// Whether to leave a field at default, add/set it, or remove it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddRemove {
    /// Leave the field at its default template value.
    Default,
    /// Add or set the field to a specific value.
    Add,
    /// Remove the field from the template.
    Remove,
}

impl std::default::Default for AddRemove {
    fn default() -> Self {
        AddRemove::Default
    }
}

/// TCP-specific template options.
#[derive(Debug, Clone)]
pub struct TcpOptions {
    pub is_badsum: AddRemove,
    pub is_tsecho: AddRemove,
    pub is_tsreply: AddRemove,
    pub is_flags: AddRemove,
    pub is_ackno: AddRemove,
    pub is_seqno: AddRemove,
    pub is_win: AddRemove,
    pub is_mss: AddRemove,
    pub is_sackok: AddRemove,
    pub is_wscale: AddRemove,
    pub flags: u32,
    pub ackno: u32,
    pub seqno: u32,
    pub win: u32,
    pub mss: u32,
    pub sackok: u32,
    pub wscale: u32,
    pub tsecho: u32,
    pub tsreply: u32,
}

impl Default for TcpOptions {
    fn default() -> Self {
        Self {
            is_badsum: AddRemove::Default,
            is_tsecho: AddRemove::Default,
            is_tsreply: AddRemove::Default,
            is_flags: AddRemove::Default,
            is_ackno: AddRemove::Default,
            is_seqno: AddRemove::Default,
            is_win: AddRemove::Default,
            is_mss: AddRemove::Default,
            is_sackok: AddRemove::Default,
            is_wscale: AddRemove::Default,
            flags: 0,
            ackno: 0,
            seqno: 0,
            win: 0,
            mss: 0,
            sackok: 0,
            wscale: 0,
            tsecho: 0,
            tsreply: 0,
        }
    }
}

/// UDP-specific template options.
#[derive(Debug, Clone, Default)]
pub struct UdpOptions {
    pub is_badsum: AddRemove,
}

/// ARP-specific template options.
#[derive(Debug, Clone)]
pub struct ArpOptions {
    pub is_sender_mac: AddRemove,
    pub is_sender_ip: AddRemove,
    pub is_target_mac: AddRemove,
    pub is_target_ip: AddRemove,
    pub sender_mac: MacAddress,
    pub sender_ip: IpAddress,
    pub target_mac: MacAddress,
    pub target_ip: IpAddress,
}

impl Default for ArpOptions {
    fn default() -> Self {
        Self {
            is_sender_mac: AddRemove::Default,
            is_sender_ip: AddRemove::Default,
            is_target_mac: AddRemove::Default,
            is_target_ip: AddRemove::Default,
            sender_mac: MacAddress::default(),
            sender_ip: IpAddress::V4(0),
            target_mac: MacAddress::default(),
            target_ip: IpAddress::V4(0),
        }
    }
}

/// IPv4-specific template options.
#[derive(Debug, Clone, Default)]
pub struct Ipv4Options {
    pub is_badsum: AddRemove,
    pub is_tos: AddRemove,
    pub is_ipid: AddRemove,
    pub is_df: AddRemove,
    pub is_mf: AddRemove,
    pub is_ttl: AddRemove,
    pub tos: u32,
    pub ipid: u32,
    pub ttl: u32,
}

/// Complete set of template options controlling packet construction.
///
/// These options are applied during template initialization to
/// customize packet fields such as TCP options (MSS, SACK, window
/// scale, timestamps), TTL, TOS, and more.
#[derive(Debug, Clone, Default)]
pub struct TemplateOptions {
    pub tcp: TcpOptions,
    pub udp: UdpOptions,
    pub arp: ArpOptions,
    pub ipv4: Ipv4Options,
}
