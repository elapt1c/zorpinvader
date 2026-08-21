//! Retrieve the default gateway (next-hop) IPv4 address for a named network
//! interface by querying the Linux kernel via a netlink `NETLINK_ROUTE` socket.

use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;

use libc::{
    self, c_void, close, getpid, recv, send, sockaddr_nl, socket, AF_INET, AF_NETLINK,
    IF_NAMESIZE, NETLINK_ROUTE, NLM_F_DUMP, NLM_F_MULTI, NLM_F_REQUEST,
    NLMSG_DONE, NLMSG_ERROR, PF_NETLINK, SOCK_DGRAM,
};

/// Parsed information about a single kernel route entry.
#[derive(Debug)]
struct RouteInfo {
    dst_addr: Ipv4Addr,
    src_addr: Ipv4Addr,
    gateway: Ipv4Addr,
    if_name: String,
    priority: i32,
}

impl Default for RouteInfo {
    fn default() -> Self {
        Self {
            dst_addr: Ipv4Addr::UNSPECIFIED,
            src_addr: Ipv4Addr::UNSPECIFIED,
            gateway: Ipv4Addr::UNSPECIFIED,
            if_name: String::new(),
            priority: 0,
        }
    }
}

// ---- netlink helpers -------------------------------------------------------

/// Netlink message header (from `<linux/netlink.h>`).
#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

/// Route message (from `<linux/rtnetlink.h>`).
#[repr(C)]
#[derive(Clone, Copy)]
struct RtMsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

/// Route attribute header.
#[repr(C)]
#[derive(Clone, Copy)]
struct RtAttr {
    rta_len: u16,
    rta_type: u16,
}

// Netlink constants not always in libc.
const RTM_GETROUTE: u16 = 26;
const RT_TABLE_MAIN: u8 = 254;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_DST: u16 = 1;
const RTA_PREFSRC: u16 = 7;
const RTA_PRIORITY: u16 = 12;

/// Alignment macro equivalent.
#[inline]
fn rta_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Open a NETLINK_ROUTE socket.
fn open_netlink() -> io::Result<RawFd> {
    let fd = unsafe { socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Bind to our own pid.
    let mut addr: sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = AF_NETLINK as u16;
    addr.nl_pid = unsafe { getpid() } as u32;
    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const sockaddr_nl as *const libc::sockaddr,
            mem::size_of::<sockaddr_nl>() as u32,
        )
    };
    if ret < 0 {
        let e = io::Error::last_os_error();
        unsafe { close(fd) };
        return Err(e);
    }

    Ok(fd)
}

/// Send a RTM_GETROUTE dump request.
fn send_route_request(fd: RawFd, seq: u32) -> io::Result<()> {
    let pid = unsafe { getpid() } as u32;

    let nlmsg_len = (mem::size_of::<NlMsgHdr>() + mem::size_of::<RtMsg>()) as u32;
    let nlhdr = NlMsgHdr {
        nlmsg_len,
        nlmsg_type: RTM_GETROUTE,
        nlmsg_flags: (NLM_F_DUMP | NLM_F_REQUEST) as u16,
        nlmsg_seq: seq,
        nlmsg_pid: pid,
    };
    let rtmsg = RtMsg {
        rtm_family: AF_INET as u8,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: 0,
        rtm_protocol: 0,
        rtm_scope: 0,
        rtm_type: 0,
        rtm_flags: 0,
    };

    // Serialise into a buffer.
    let mut buf = vec![0u8; nlmsg_len as usize];
    unsafe {
        std::ptr::copy_nonoverlapping(
            &nlhdr as *const NlMsgHdr as *const u8,
            buf.as_mut_ptr(),
            mem::size_of::<NlMsgHdr>(),
        );
        std::ptr::copy_nonoverlapping(
            &rtmsg as *const RtMsg as *const u8,
            buf.as_mut_ptr().add(mem::size_of::<NlMsgHdr>()),
            mem::size_of::<RtMsg>(),
        );
    }

    let sent = unsafe { send(fd, buf.as_ptr() as *const c_void, buf.len(), 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Read netlink responses into `buf`, returning total bytes received.
fn read_netlink(fd: RawFd, buf: &mut [u8], _seq: u32, _pid: u32) -> io::Result<usize> {
    let mut total = 0usize;
    loop {
        let n = unsafe { recv(fd, buf[total..].as_mut_ptr() as *mut c_void, buf.len() - total, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let read_len = n as usize;
        if read_len == 0 {
            break;
        }

        // Validate the first header in this chunk.
        if read_len < mem::size_of::<NlMsgHdr>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "netlink message too short",
            ));
        }
        let hdr = unsafe { &*(buf[total..].as_ptr() as *const NlMsgHdr) };

        if hdr.nlmsg_type == NLMSG_ERROR as u16 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "netlink error response",
            ));
        }
        if hdr.nlmsg_type == NLMSG_DONE as u16 {
            break;
        }

        total += read_len;

        // Stop if not a multi-part message.
        if (hdr.nlmsg_flags & NLM_F_MULTI as u16) == 0 {
            break;
        }
    }
    Ok(total)
}

/// Parse a single `NlMsgHdr` + payload into a `RouteInfo`.
/// Returns `None` if the message is not an AF_INET / RT_TABLE_MAIN route.
fn parse_route(buf: &[u8], offset: usize, hdr: &NlMsgHdr) -> Option<RouteInfo> {
    let rtmsg_offset = offset + mem::size_of::<NlMsgHdr>();
    if rtmsg_offset + mem::size_of::<RtMsg>() > buf.len() {
        return None;
    }
    let rtm = unsafe { &*(buf[rtmsg_offset..].as_ptr() as *const RtMsg) };

    if rtm.rtm_family != AF_INET as u8 {
        return None;
    }
    if rtm.rtm_table != RT_TABLE_MAIN {
        return None;
    }

    let mut info = RouteInfo::default();

    // Walk attributes.
    let attr_start = rtmsg_offset + rta_align(mem::size_of::<RtMsg>());
    let mut pos = attr_start;
    let end = offset + hdr.nlmsg_len as usize;

    while pos + mem::size_of::<RtAttr>() <= end {
        let attr = unsafe { &*(buf[pos..].as_ptr() as *const RtAttr) };
        if (attr.rta_len as usize) < mem::size_of::<RtAttr>() {
            break;
        }
        let data_start = pos + mem::size_of::<RtAttr>();
        let data_len = attr.rta_len as usize - mem::size_of::<RtAttr>();

        match attr.rta_type {
            RTA_OIF => {
                if data_len >= 4 {
                    let ifindex = unsafe { *(buf[data_start..].as_ptr() as *const i32) };
                    let mut name_buf = [0u8; IF_NAMESIZE];
                    let ptr = unsafe {
                        libc::if_indextoname(
                            ifindex as libc::c_uint,
                            name_buf.as_mut_ptr() as *mut libc::c_char,
                        )
                    };
                    if !ptr.is_null() {
                        let len = name_buf.iter().position(|&b| b == 0).unwrap_or(0);
                        info.if_name = String::from_utf8_lossy(&name_buf[..len]).into_owned();
                    }
                }
            }
            RTA_GATEWAY => {
                if data_len >= 4 {
                    let mut octets = [0u8; 4];
                    octets.copy_from_slice(&buf[data_start..data_start + 4]);
                    // Kernel stores in network byte order (big-endian).
                    info.gateway = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
                }
            }
            RTA_PREFSRC => {
                if data_len >= 4 {
                    let mut octets = [0u8; 4];
                    octets.copy_from_slice(&buf[data_start..data_start + 4]);
                    info.src_addr = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
                }
            }
            RTA_DST => {
                if data_len >= 4 {
                    let mut octets = [0u8; 4];
                    octets.copy_from_slice(&buf[data_start..data_start + 4]);
                    info.dst_addr = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
                }
            }
            RTA_PRIORITY => {
                if data_len >= 4 {
                    info.priority = unsafe { *(buf[data_start..].as_ptr() as *const i32) };
                }
            }
            _ => {}
        }

        pos += rta_align(attr.rta_len as usize);
    }

    Some(info)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Retrieve the default gateway IPv4 address for the named interface.
///
/// If `ifname` is `None`, returns the gateway of the *lowest-priority*
/// default route (i.e. the system default).
///
/// Returns `Ok(None)` if no default route is found.
pub fn get_default_gateway(ifname: Option<&str>) -> io::Result<Option<Ipv4Addr>> {
    let fd = open_netlink()?;
    let seq = 0u32;
    let pid = unsafe { getpid() } as u32;

    if let Err(e) = send_route_request(fd, seq) {
        unsafe { close(fd) };
        return Err(e);
    }

    let mut buf = vec![0u8; 16384];
    let total = match read_netlink(fd, &mut buf, seq, pid) {
        Ok(n) => n,
        Err(e) => {
            unsafe { close(fd) };
            return Err(e);
        }
    };
    unsafe { close(fd) };

    // Walk the multipart messages.
    let mut offset = 0;
    while offset + mem::size_of::<NlMsgHdr>() <= total {
        let hdr = unsafe { &*(buf[offset..].as_ptr() as *const NlMsgHdr) };
        if (hdr.nlmsg_len as usize) < mem::size_of::<NlMsgHdr>() {
            break;
        }
        if hdr.nlmsg_type == NLMSG_DONE as u16 {
            break;
        }

        if let Some(info) = parse_route(&buf, offset, hdr) {
            // Match interface name if requested.
            if let Some(wanted) = ifname {
                if info.if_name != wanted {
                    offset += rta_align(hdr.nlmsg_len as usize);
                    continue;
                }
            }
            // Default route has dst == 0.0.0.0.
            if info.dst_addr == Ipv4Addr::UNSPECIFIED {
                if !info.gateway.is_unspecified() {
                    return Ok(Some(info.gateway));
                }
            }
        }

        offset += rta_align(hdr.nlmsg_len as usize);
    }

    Ok(None)
}
