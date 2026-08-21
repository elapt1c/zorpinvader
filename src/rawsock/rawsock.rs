//! Linux raw-socket implementation using AF_PACKET.
//!
//! Provides send/receive of raw Ethernet frames, bypassing libpcap for
//! maximum performance.

use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::{SystemTime, UNIX_EPOCH};

use super::adapter::RecvPacket;

/// A raw AF_PACKET socket bound to a named interface.
pub struct RawSocket {
    fd: RawFd,
    ifindex: i32,
    /// Cached interface name for diagnostics.
    ifname: String,
}

// AF_PACKET constants (from linux/if_packet.h / linux/if_ether.h).
const AF_PACKET: i32 = 17;
const SOCK_RAW: i32 = 3;
const ETH_P_ALL: u16 = 0x0003;
const PACKET_ADD_MEMBERSHIP: i32 = 1;
const PACKET_MR_PROMISC: u16 = 1;
const SO_ATTACH_FILTER: i32 = 26;
const PACKET_TX_RING: i32 = 13;

/// `sockaddr_ll` — Linux link-layer socket address.
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

/// `packet_mreq` for entering promiscuous mode.
#[repr(C)]
struct PacketMreq {
    mr_ifindex: i32,
    mr_type: u16,
    mr_alen: u16,
    mr_address: [u8; 8],
}

impl RawSocket {
    /// Open an AF_PACKET raw socket bound to the named interface (e.g. "eth0").
    pub fn open(ifname: &str) -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                AF_PACKET,
                SOCK_RAW,
                (ETH_P_ALL as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Resolve interface index.
        let ifindex = if_nametoindex(ifname)?;

        // Bind to the interface.
        let addr = SockaddrLl {
            sll_family: AF_PACKET as u16,
            sll_protocol: (ETH_P_ALL as u16).to_be(),
            sll_ifindex: ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const SockaddrLl as *const libc::sockaddr,
                mem::size_of::<SockaddrLl>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            fd,
            ifindex,
            ifname: ifname.to_owned(),
        })
    }

    /// Enable promiscuous mode on the interface.
    pub fn set_promiscuous(&self) -> io::Result<()> {
        let mreq = PacketMreq {
            mr_ifindex: self.ifindex,
            mr_type: PACKET_MR_PROMISC,
            mr_alen: 0,
            mr_address: [0; 8],
        };
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                PACKET_ADD_MEMBERSHIP,
                &mreq as *const PacketMreq as *const libc::c_void,
                mem::size_of::<PacketMreq>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Set the receive buffer size.
    pub fn set_recv_buffer_size(&self, size: usize) -> io::Result<()> {
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size as *const usize as *const libc::c_void,
                mem::size_of::<usize>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Send a raw Ethernet frame.
    pub fn send(&self, packet: &[u8]) -> io::Result<()> {
        let addr = SockaddrLl {
            sll_family: AF_PACKET as u16,
            sll_protocol: (ETH_P_ALL as u16).to_be(),
            sll_ifindex: self.ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: [0; 8],
        };

        // Extract destination MAC from the first 6 bytes of the frame.
        if packet.len() >= 6 {
            let mut a = addr;
            a.sll_addr[..6].copy_from_slice(&packet[..6]);
            let ret = unsafe {
                libc::sendto(
                    self.fd,
                    packet.as_ptr() as *const libc::c_void,
                    packet.len(),
                    0,
                    &a as *const SockaddrLl as *const libc::sockaddr,
                    mem::size_of::<SockaddrLl>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet too short (need at least Ethernet header)",
            ));
        }
        Ok(())
    }

    /// Receive a single raw Ethernet frame into `buf`.
    ///
    /// Returns the captured data slice, plus a timestamp.
    pub fn recv<'a>(&self, buf: &'a mut [u8]) -> io::Result<RecvPacket<'a>> {
        let mut msg_name: SockaddrLl = unsafe { mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = &mut msg_name as *mut SockaddrLl as *mut libc::c_void;
        msg.msg_namelen = mem::size_of::<SockaddrLl>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;

        let n = unsafe { libc::recvmsg(self.fd, &mut msg, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let len = n as usize;

        // Get a timestamp from CLOCK_REALTIME.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs() as u32;
        let usecs = now.subsec_micros();

        Ok(RecvPacket {
            data: &buf[..len],
            secs,
            usecs,
        })
    }

    /// Return the interface index this socket is bound to.
    pub fn ifindex(&self) -> i32 {
        self.ifindex
    }

    /// Return the interface name.
    pub fn ifname(&self) -> &str {
        &self.ifname
    }

    /// Return the raw file descriptor.
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Resolve an interface name to its kernel index (like C's `if_nametoindex`).
fn if_nametoindex(name: &str) -> io::Result<i32> {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    let bytes = name.as_bytes();
    if bytes.len() >= libc::IF_NAMESIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    buf[..bytes.len()].copy_from_slice(bytes);

    let idx = unsafe { libc::if_nametoindex(buf.as_ptr() as *const libc::c_char) };
    if idx == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(idx as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_ll_size() {
        // sockaddr_ll is 20 bytes on Linux.
        assert_eq!(mem::size_of::<SockaddrLl>(), 20);
    }
}

/// List all available network adapters.
pub fn list_adapters() {
    println!("list_adapters not yet implemented");
}
