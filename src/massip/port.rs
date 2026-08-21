/// Ports are 16-bit numbers ([0..65535]), but different
/// transports (TCP, UDP, SCTP) are distinct port ranges. Thus, we
/// instead of three 64k ranges we could instead treat this internally
/// as a 192k port range. We can expand this range to include other
/// things we scan for, such as ICMP pings or ARP requests.

pub const TEMPL_TCP: u32 = 0;
pub const TEMPL_TCP_LAST: u32 = 65535;
pub const TEMPL_UDP: u32 = 65536;
pub const TEMPL_UDP_LAST: u32 = 65536 + 65535;
pub const TEMPL_SCTP: u32 = 65536 * 2;
pub const TEMPL_SCTP_LAST: u32 = 65536 * 2 + 65535;
pub const TEMPL_ICMP_ECHO: u32 = 65536 * 3;
pub const TEMPL_ICMP_TIMESTAMP: u32 = 65536 * 3 + 1;
pub const TEMPL_ARP: u32 = 65536 * 3 + 2;
pub const TEMPL_OPROTO_FIRST: u32 = 65536 * 3 + 256;
pub const TEMPL_OPROTO_LAST: u32 = 65536 * 3 + 256 + 255;
pub const TEMPL_VULNCHECK: u32 = 65536 * 4;
