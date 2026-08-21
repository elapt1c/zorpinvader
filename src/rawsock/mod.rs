//! Raw sockets module — platform-independent API for raw Ethernet frame I/O,
//! adapter discovery, pcap file reading/writing, and network interface queries.
//!
//! On Linux this uses AF_PACKET raw sockets and netlink for interface discovery.

pub mod adapter;
pub mod getif;
pub mod getip;
pub mod getmac;
pub mod getroute;
pub mod pcapfile;
pub mod rawsock;

pub use adapter::{Adapter, AdapterConfig, LinkType};
pub use pcapfile::PcapFile;
pub use rawsock::RawSocket;

use std::net::{Ipv4Addr, Ipv6Addr};

/// A 6-byte MAC (hardware) address.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress {
    pub addr: [u8; 6],
}

impl MacAddress {
    pub const ZERO: Self = Self { addr: [0; 6] };

    pub fn new(bytes: [u8; 6]) -> Self {
        Self { addr: bytes }
    }

    pub fn from_slice(s: &[u8]) -> Option<Self> {
        if s.len() >= 6 {
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&s[..6]);
            Some(Self { addr })
        } else {
            None
        }
    }

    pub fn is_zero(&self) -> bool {
        self.addr == [0; 6]
    }

    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.addr
    }
}

impl std::fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.addr[0],
            self.addr[1],
            self.addr[2],
            self.addr[3],
            self.addr[4],
            self.addr[5]
        )
    }
}

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// Unified IP address type (v4 or v6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpAddress {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl From<Ipv4Addr> for IpAddress {
    fn from(a: Ipv4Addr) -> Self {
        Self::V4(a)
    }
}

impl From<Ipv6Addr> for IpAddress {
    fn from(a: Ipv6Addr) -> Self {
        Self::V6(a)
    }
}
