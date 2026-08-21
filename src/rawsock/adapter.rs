//! Network adapter abstraction wrapping a raw socket (or pcap handle) with
//! associated metadata: interface name, MAC, IP, link type, VLAN tagging.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use super::MacAddress;
use super::rawsock::RawSocket;

/// Link-layer type reported by the adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum LinkType {
    /// Ethernet (IEEE 802.3)
    Ethernet = 1,
    /// Raw IP — no datalink header
    RawIp = 101,
    /// IEEE 802.11 WiFi
    Wifi = 105,
    /// Linux cooked capture (e.g. "any" pseudo-interface)
    LinuxSll = 113,
}

impl LinkType {
    pub fn from_raw(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Ethernet),
            101 => Some(Self::RawIp),
            105 => Some(Self::Wifi),
            113 => Some(Self::LinuxSll),
            _ => None,
        }
    }

    pub fn to_raw(self) -> u32 {
        self as u32
    }
}

/// Configuration used when opening an adapter.
#[derive(Clone, Debug)]
pub struct AdapterConfig {
    /// Interface name (e.g. "eth0").
    pub name: String,
    /// Whether to enable packet-trace logging.
    pub is_packet_trace: bool,
    /// Whether the caller is running in offline/benchmark mode (no real socket).
    pub is_offline: bool,
    /// Whether the interface is VLAN-tagged.
    pub is_vlan: bool,
    /// VLAN tag ID (when `is_vlan` is true).
    pub vlan_id: u32,
}

impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            is_packet_trace: false,
            is_offline: false,
            is_vlan: false,
            vlan_id: 0,
        }
    }
}

/// A fully-instantiated network adapter.
pub struct Adapter {
    /// Interface name.
    pub name: String,
    /// Hardware MAC address of this interface.
    pub mac: MacAddress,
    /// IPv4 address assigned to this interface (if any).
    pub ip: Option<Ipv4Addr>,
    /// IPv6 address assigned to this interface (if any).
    pub ipv6: Option<Ipv6Addr>,
    /// Link-layer type (Ethernet, raw IP, etc.).
    pub link_type: LinkType,
    /// Whether VLAN tagging is active.
    pub is_vlan: bool,
    /// VLAN ID (only meaningful when `is_vlan` is true).
    pub vlan_id: u32,
    /// Whether --packet-trace is enabled.
    pub is_packet_trace: bool,
    /// Wall-clock instant used as the packet-trace time origin.
    pub pt_start: Instant,
    /// The underlying raw socket (None when running offline).
    socket: Option<RawSocket>,
}

impl Adapter {
    /// Create an adapter handle for the given configuration.
    ///
    /// If `config.is_offline` is true no socket is actually opened; the
    /// returned adapter can be used for benchmarking the packet-building
    /// pipeline without touching the network.
    pub fn open(config: &AdapterConfig) -> std::io::Result<Self> {
        let socket = if config.is_offline {
            None
        } else {
            Some(RawSocket::open(&config.name)?)
        };

        Ok(Self {
            name: config.name.clone(),
            mac: MacAddress::ZERO,
            ip: None,
            ipv6: None,
            link_type: LinkType::Ethernet,
            is_vlan: config.is_vlan,
            vlan_id: config.vlan_id,
            is_packet_trace: config.is_packet_trace,
            pt_start: Instant::now(),
            socket,
        })
    }

    /// Populate MAC / IP / IPv6 fields by querying the OS.
    pub fn discover_addresses(&mut self) -> std::io::Result<()> {
        if let Ok(mac) = super::getmac::get_adapter_mac(&self.name) {
            self.mac = mac;
        }
        if let Ok(Some(ip)) = super::getip::get_adapter_ip(&self.name) {
            self.ip = Some(ip);
        }
        if let Ok(Some(ipv6)) = super::getip::get_adapter_ipv6(&self.name) {
            self.ipv6 = Some(ipv6);
        }
        Ok(())
    }

    /// Return a reference to the underlying raw socket, if any.
    pub fn socket(&self) -> Option<&RawSocket> {
        self.socket.as_ref()
    }

    /// Return a mutable reference to the underlying raw socket, if any.
    pub fn socket_mut(&mut self) -> Option<&mut RawSocket> {
        self.socket.as_mut()
    }

    /// Send a raw Ethernet frame.
    pub fn send_packet(&self, packet: &[u8]) -> std::io::Result<()> {
        if let Some(ref sock) = self.socket {
            sock.send(packet)
        } else {
            // Offline mode: silently drop.
            Ok(())
        }
    }

    /// Receive a single raw Ethernet frame.
    ///
    /// Returns `(length, secs_since_epoch, usecs, packet_bytes)`.
    pub fn recv_packet<'a>(&self, buf: &'a mut [u8]) -> std::io::Result<RecvPacket<'a>> {
        match self.socket {
            Some(ref sock) => sock.recv(buf),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "adapter is offline",
            )),
        }
    }
}

/// Result of a successful receive.
pub struct RecvPacket<'a> {
    /// Captured packet bytes (slice into the caller-provided buffer).
    pub data: &'a [u8],
    /// Timestamp seconds since epoch.
    pub secs: u32,
    /// Timestamp microseconds within the second.
    pub usecs: u32,
}
