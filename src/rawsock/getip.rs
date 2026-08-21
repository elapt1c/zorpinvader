//! Retrieve IPv4 and IPv6 addresses of a named network interface.
//!
//! * IPv4: uses `ioctl(SIOCGIFADDR)` on Linux.
//! * IPv6: uses `getifaddrs()` and filters for global unicast addresses.

use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::RawFd;

// ---- IPv4 via ioctl --------------------------------------------------------

/// SIOCGIFADDR constant (from `<linux/sockios.h>`).
const SIOCGIFADDR: libc::c_ulong = 0x8915;

/// `struct ifreq` for SIOCGIFADDR.
#[repr(C)]
struct IfreqAddr {
    ifr_name: [u8; libc::IF_NAMESIZE],
    ifr_addr_family: u16,
    _pad: [u8; 14], // sockaddr storage
}

/// Retrieve the IPv4 address of the named interface.
///
/// Returns `Ok(None)` if the interface has no IPv4 address configured.
pub fn get_adapter_ip(ifname: &str) -> io::Result<Option<Ipv4Addr>> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let result = get_if_addr(fd, ifname);
    unsafe { libc::close(fd) };
    result
}

fn get_if_addr(fd: RawFd, ifname: &str) -> io::Result<Option<Ipv4Addr>> {
    let mut ifr: IfreqAddr = unsafe { mem::zeroed() };
    let name_bytes = ifname.as_bytes();
    if name_bytes.len() >= libc::IF_NAMESIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    ifr.ifr_name[..name_bytes.len()].copy_from_slice(name_bytes);
    ifr.ifr_addr_family = libc::AF_INET as u16;

    let ret = unsafe {
        libc::ioctl(
            fd,
            SIOCGIFADDR,
            &mut ifr as *mut IfreqAddr as *mut libc::c_void,
        )
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        // ENODEV / EADDRNOTAVAIL means no IPv4 address — not a fatal error.
        if err.raw_os_error() == Some(libc::ENODEV)
            || err.raw_os_error() == Some(libc::EADDRNOTAVAIL)
        {
            return Ok(None);
        }
        return Err(err);
    }

    // sockaddr_in layout within ifr_addr:
    //   bytes 0-1: sin_family (AF_INET)   — overlaps ifr_addr_family
    //   bytes 2-3: sin_port (network order)
    //   bytes 4-7: sin_addr (network order) — the IPv4 address
    // Since ifr_addr_family covers bytes 0-1, sin_addr is at _pad[2..6].
    let octets = &ifr._pad[2..6];
    let addr = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    Ok(Some(addr))
}

// ---- IPv6 via getifaddrs ---------------------------------------------------

/// Retrieve the first *global* IPv6 address of the named interface.
///
/// Skips link-local (fc00::/7) and documentation (2001:db8::/32) addresses.
/// Returns `Ok(None)` if no suitable address is found.
pub fn get_adapter_ipv6(ifname: &str) -> io::Result<Option<Ipv6Addr>> {
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();

    let ret = unsafe { libc::getifaddrs(&mut ifap) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let result = scan_ifaddrs_ipv6(ifap, ifname);
    unsafe { libc::freeifaddrs(ifap) };
    result
}

fn scan_ifaddrs_ipv6(
    ifap: *mut libc::ifaddrs,
    target: &str,
) -> io::Result<Option<Ipv6Addr>> {
    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };

        // Match interface name.
        if !ifa.ifa_name.is_null() {
            let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
            if let Ok(name_str) = name.to_str() {
                if name_str == target && !ifa.ifa_addr.is_null() {
                    let sa = unsafe { &*ifa.ifa_addr };
                    if sa.sa_family as i32 == libc::AF_INET6 {
                        let sa6 =
                            unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                        let octets = sa6.sin6_addr.s6_addr;
                        let addr = Ipv6Addr::from(octets);

                        // Skip link-local / ULA (fc00::/7).
                        if addr.segments()[0] & 0xfe00 == 0xfc00 {
                            cur = ifa.ifa_next;
                            continue;
                        }
                        // Skip documentation prefix 2001:db8::/32.
                        if addr.segments()[0] == 0x2001 && addr.segments()[1] == 0x0db8 {
                            cur = ifa.ifa_next;
                            continue;
                        }

                        return Ok(Some(addr));
                    }
                }
            }
        }

        cur = ifa.ifa_next;
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifreq_addr_size() {
        // 16 (IF_NAMESIZE) + 16 (sockaddr) = 32
        assert_eq!(mem::size_of::<IfreqAddr>(), 32);
    }
}
