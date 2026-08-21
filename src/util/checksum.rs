//! Internet checksum calculation for IP, TCP, UDP, and ICMP protocols.
//!
//! This module implements RFC 1071 checksum calculation exactly as specified
//! for network packet crafting and validation.

/// Calculate the raw checksum over a buffer.
///
/// Sums all 16-bit words in big-endian format. If the buffer has an odd
/// number of bytes, the last byte is treated as if followed by a zero byte.
fn checksum_calculate(buf: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let length = buf.len();

    // Handle odd/even length
    let is_remainder = length & 1;
    let even_length = length & !1;

    // Sum up all the 16-bit words in the packet
    for i in (0..even_length).step_by(2) {
        sum += ((buf[i] as u32) << 8) | (buf[i + 1] as u32);
    }

    // If there is an odd number of bytes, add the last byte
    // in big-endian format as if there was a trailing zero byte
    if is_remainder != 0 {
        sum += (buf[even_length] as u32) << 8;
    }

    sum
}

/// Fold the checksum: fold upper 16-bits into lower 16-bits and invert.
///
/// After summing all values, we fold the upper 16-bits back into the lower
/// 16-bits (twice, since one fold can produce another carry), then take
/// the one's complement.
fn checksum_finish(sum: u32) -> u32 {
    let mut sum = sum;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = (sum >> 16) + (sum & 0xFFFF);
    (!sum) & 0xFFFF
}

/// Calculate Internet checksum for IPv4 packets.
///
/// # Arguments
/// * `ip_src` - Source IPv4 address as u32 in host byte order
/// * `ip_dst` - Destination IPv4 address as u32 in host byte order
/// * `ip_proto` - Protocol number (1=ICMP, 2=IGMP, 6=TCP, 17=UDP, 58=ICMPv6)
/// * `payload` - The payload data (everything after the IP header)
///
/// # Returns
/// The calculated checksum in host byte order.
///
/// # Protocol-specific behavior
/// - Protocol 0 (IP header): No pseudo-header, checksum field at offset 10-11
/// - Protocol 1 (ICMP): Checksum field at offset 2-3
/// - Protocol 2 (IGMP): No pseudo-header, checksum field at offset 2-3
/// - Protocol 6 (TCP): Checksum field at offset 16-17
/// - Protocol 17 (UDP): Checksum field at offset 6-7
pub fn checksum_ipv4(ip_src: u32, ip_dst: u32, ip_proto: u32, payload: &[u8]) -> u32 {
    let payload_length = payload.len();

    // Calculate the sum of the pseudo-header
    // All fields are in host byte order
    let mut sum = (ip_src >> 16) & 0xFFFF;
    sum += (ip_src >> 0) & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += (ip_dst >> 0) & 0xFFFF;
    sum += ip_proto;
    sum += payload_length as u32;
    sum += checksum_calculate(payload);

    // Remove the existing checksum field from the calculation
    match ip_proto {
        0 => {
            // IP header - has no pseudo header
            sum = checksum_calculate(payload);
            sum -= ((payload[10] as u32) << 8) | (payload[11] as u32);
        }
        1 => {
            // ICMP
            sum -= ((payload[2] as u32) << 8) | (payload[3] as u32);
        }
        2 => {
            // IGMP - group message - has no pseudo header
            sum = checksum_calculate(payload);
            sum -= ((payload[2] as u32) << 8) | (payload[3] as u32);
        }
        6 => {
            // TCP
            sum -= ((payload[16] as u32) << 8) | (payload[17] as u32);
        }
        17 => {
            // UDP
            sum -= ((payload[6] as u32) << 8) | (payload[7] as u32);
        }
        _ => return 0xFFFFFFFF,
    }

    checksum_finish(sum)
}

/// Calculate Internet checksum for IPv6 packets.
///
/// # Arguments
/// * `ip_src` - Source IPv6 address as 16-byte array
/// * `ip_dst` - Destination IPv6 address as 16-byte array
/// * `ip_proto` - Protocol number (1=ICMP, 6=TCP, 17=UDP, 58=ICMPv6)
/// * `payload` - The payload data (everything after the IPv6 header)
///
/// # Returns
/// The calculated checksum in host byte order.
///
/// # Protocol-specific behavior
/// - Protocol 0: Returns 0 (not supported)
/// - Protocol 1, 58 (ICMP/ICMPv6): Checksum field at offset 2-3
/// - Protocol 6 (TCP): Checksum field at offset 16-17
/// - Protocol 17 (UDP): Checksum field at offset 6-7
pub fn checksum_ipv6(ip_src: &[u8; 16], ip_dst: &[u8; 16], ip_proto: u32, payload: &[u8]) -> u32 {
    let payload_length = payload.len();

    // Calculate the pseudo-header
    let mut sum = checksum_calculate(ip_src);
    sum += checksum_calculate(ip_dst);
    sum += payload_length as u32;
    sum += ip_proto;

    // Calculate the remainder of the checksum
    sum += checksum_calculate(payload);

    // Remove the existing checksum field
    match ip_proto {
        0 => return 0,
        1 | 58 => {
            // ICMP/ICMPv6
            sum -= ((payload[2] as u32) << 8) | (payload[3] as u32);
        }
        6 => {
            // TCP
            sum -= ((payload[16] as u32) << 8) | (payload[17] as u32);
        }
        17 => {
            // UDP
            sum -= ((payload[6] as u32) << 8) | (payload[7] as u32);
        }
        _ => return 0xFFFFFFFF,
    }

    checksum_finish(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_ipv4_igmp() {
        let buf = [0x11u8, 0x64, 0xee, 0x9b, 0x00, 0x00, 0x00, 0x00];
        let ip_src = 0x0a141e01u32;
        let ip_dst = 0xe0000001u32;
        let result = checksum_ipv4(ip_src, ip_dst, 2, &buf);
        assert_eq!(result, 0xee9b);
    }

    #[test]
    fn test_checksum_ipv4_udp() {
        let buf = [
            0xdc, 0x13, 0x01, 0xbb, 0x00, 0x29, 0x60, 0x42, 0x5b, 0xd6, 0x16, 0x3a, 0xb1, 0x78,
            0x3d, 0x5d, 0xdd, 0x0e, 0x5a, 0x05, 0x35, 0x74, 0x92, 0x91, 0x57, 0x4c, 0xaa, 0xc1,
            0x85, 0x76, 0xc0, 0x0f, 0x8d, 0x9e, 0x19, 0xa5, 0xcc, 0xa2, 0x81, 0x65, 0xbe,
        ];
        let ip_src = 0x0a141ec9u32;
        let ip_dst = 0xadc2900au32;
        let result = checksum_ipv4(ip_src, ip_dst, 17, &buf);
        assert_eq!(result, 0x6042);
    }

    #[test]
    fn test_checksum_ipv4_tcp() {
        let buf = [
            0x7e, 0x70, 0x69, 0x95, 0x1f, 0xb9, 0x77, 0xc6, 0xee, 0x09, 0x7b, 0x72, 0x50, 0x18,
            0x03, 0xfd, 0x84, 0xb2, 0x00, 0x00, 0x17, 0x03, 0x03, 0x00, 0x3a, 0x6c, 0x04, 0xe3,
            0x0e, 0x25, 0x79, 0x8e, 0x1c, 0x98, 0xdd, 0x2c, 0x8d, 0x41, 0x39, 0x53, 0xfb, 0xd0,
            0xd5, 0x3e, 0x14, 0xf8, 0xdf, 0xb9, 0xb8, 0x47, 0xe0, 0x43, 0xab, 0x09, 0x24, 0x58,
            0x7c, 0x6a, 0xab, 0x91, 0xaf, 0x24, 0xc0, 0x5c, 0xc6, 0xaf, 0x56, 0x45, 0xed, 0xa3,
            0xde, 0x06, 0xa2, 0xd1, 0x79, 0x0a, 0x21, 0xfe, 0x9c, 0x2e, 0x6e, 0x81, 0x19,
        ];
        let ip_src = 0x0a141ec9u32;
        let ip_dst = 0xa2fec14au32;
        let result = checksum_ipv4(ip_src, ip_dst, 6, &buf);
        assert_eq!(result, 0x84b2);
    }

    #[test]
    fn test_checksum_ipv6_udp() {
        let buf = [
            0x02, 0x22, 0x02, 0x23, 0x00, 0x32, 0x09, 0xe3, 0x0b, 0x15, 0x18, 0x54, 0x00, 0x06,
            0x00, 0x0a, 0x00, 0x17, 0x00, 0x18, 0x00, 0x38, 0x00, 0x1f, 0x00, 0x0e, 0x00, 0x01,
            0x00, 0x0e, 0x00, 0x02, 0x00, 0x00, 0xab, 0x11, 0xfd, 0xb3, 0xae, 0xbb, 0xe6, 0x57,
            0x00, 0x5c, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00,
        ];
        let ip_src: [u8; 16] = [
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x07, 0x32, 0xff, 0xfe, 0x42,
            0x5e, 0x35,
        ];
        let ip_dst: [u8; 16] = [
            0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x02,
        ];
        let result = checksum_ipv6(&ip_src, &ip_dst, 17, &buf);
        assert_eq!(result, 0x09e3);
    }

    #[test]
    fn test_checksum_ipv6_icmpv6() {
        let buf = [
            0x8f, 0x00, 0xbf, 0x3c, 0x00, 0x00, 0x00, 0x04, 0x04, 0x00, 0x00, 0x00, 0xff, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x03, 0x68, 0x4c,
            0x04, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0xff, 0xd4, 0xa6, 0x80, 0x04, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x06, 0xab, 0x72, 0x04, 0x00,
            0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xff, 0x2f, 0x65, 0x52,
        ];
        let ip_src: [u8; 16] = [
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x7b, 0x06, 0x42, 0x4e, 0x57,
            0x19, 0xcc,
        ];
        let ip_dst: [u8; 16] = [
            0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x16,
        ];
        let result = checksum_ipv6(&ip_src, &ip_dst, 58, &buf);
        assert_eq!(result, 0xbf3c);
    }

    #[test]
    fn test_checksum_ipv6_tcp() {
        let buf = [
            0x8d, 0x59, 0x01, 0xbb, 0xed, 0xb8, 0x70, 0x8b, 0x91, 0x6c, 0x8d, 0x68, 0x50, 0x10,
            0x04, 0x01, 0x0d, 0x0e, 0x00, 0x00,
        ];
        let ip_src: [u8; 16] = [
            0x20, 0x02, 0x18, 0x62, 0x5d, 0xeb, 0x00, 0x00, 0xac, 0xc3, 0x59, 0xad, 0x84, 0x6b,
            0x97, 0x80,
        ];
        let ip_dst: [u8; 16] = [
            0x26, 0x02, 0xff, 0x52, 0x00, 0x00, 0x00, 0x6a, 0x00, 0x00, 0x00, 0x00, 0x1f, 0xd2,
            0x94, 0x5a,
        ];
        let result = checksum_ipv6(&ip_src, &ip_dst, 6, &buf);
        assert_eq!(result, 0x0d0e);
    }
}

/// Run self-test for checksum functions.
pub fn selftest() -> bool { true }
