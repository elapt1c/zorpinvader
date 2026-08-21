//! Retrieve the hardware MAC address of a named network interface.
//!
//! On Linux this uses `ioctl(SIOCGIFHWADDR)`.

use std::io;
use std::mem;
use std::os::unix::io::RawFd;

use super::MacAddress;

/// Retrieve the MAC (hardware) address of the named interface (e.g. "eth0").
///
/// Returns `Ok(MacAddress)` on success, or an I/O error if the interface
/// cannot be found or the ioctl fails.
pub fn get_adapter_mac(ifname: &str) -> io::Result<MacAddress> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let result = get_hw_addr(fd, ifname);
    unsafe { libc::close(fd) };
    result
}

/// Perform the `SIOCGIFHWADDR` ioctl.
fn get_hw_addr(fd: RawFd, ifname: &str) -> io::Result<MacAddress> {
    // Build ifreq struct.
    let mut ifr: IfreqHw = unsafe { mem::zeroed() };

    let name_bytes = ifname.as_bytes();
    if name_bytes.len() >= libc::IF_NAMESIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    ifr.ifr_name[..name_bytes.len()].copy_from_slice(name_bytes);
    ifr.ifr_name[name_bytes.len()] = 0; // NUL-terminate

    // SIOCGIFHWADDR = 0x8927
    let ret = unsafe {
        libc::ioctl(
            fd,
            SIOCGIFHWADDR,
            &mut ifr as *mut IfreqHw as *mut libc::c_void,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let family = ifr.ifr_hwaddr.sa_family;
    log::debug!("if:{}: hardware family=0x{:04x}", ifname, family);

    let mut mac_bytes = [0u8; 6];
    for (dst, src) in mac_bytes.iter_mut().zip(ifr.ifr_hwaddr.sa_data[..6].iter()) {
        *dst = *src as u8;
    }

    // Kludge: for VPN tunnels with raw IP there isn't a hardware address,
    // so return a fake one instead.
    if mac_bytes == [0; 6] && family == 0xfffe {
        log::info!("{}: creating fake MAC address", ifname);
        mac_bytes[5] = 1;
    }

    Ok(MacAddress::new(mac_bytes))
}

/// SIOCGIFHWADDR constant (from `<linux/sockios.h>`).
const SIOCGIFHWADDR: libc::c_ulong = 0x8927;

/// `struct ifreq` layout sufficient for SIOCGIFHWADDR.
///
/// The `ifr_hwaddr` field is a `sockaddr` whose `sa_data` holds the 6-byte
/// hardware address on Linux.
#[repr(C)]
struct IfreqHw {
    ifr_name: [u8; libc::IF_NAMESIZE],
    ifr_hwaddr: Sockaddr,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Sockaddr {
    sa_family: u16,
    sa_data: [i8; 14],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifreq_size() {
        // ifreq should be IF_NAMESIZE + sizeof(sockaddr) = 16 + 16 = 32
        assert_eq!(mem::size_of::<IfreqHw>(), libc::IF_NAMESIZE + 16);
    }
}
