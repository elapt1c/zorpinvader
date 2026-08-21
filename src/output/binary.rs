//! Binary output format.
//!
//! Writes compact binary records suitable for high-throughput scanning.
//! The format uses type-tagged records with big-endian fields.
//!
//! Ported from C `out-binary.c`.

use std::io::{self, Write};

use crate::massip::addr::IpAddress;

use super::{
    BannerEvent, OutputContext, OutputFormat, PortStatus, StatusEvent,
};
use super::record::OutputRecordType;

/// Binary output plugin.
pub struct BinaryOutput;

impl BinaryOutput {
    pub fn new() -> Self {
        Self
    }
}

/// Helper: write a big-endian u8 to a buffer.
fn put_byte(buf: &mut Vec<u8>, val: u8) {
    buf.push(val);
}

/// Helper: write a big-endian u16 to a buffer.
fn put_short(buf: &mut Vec<u8>, val: u16) {
    buf.extend_from_slice(&val.to_be_bytes());
}

/// Helper: write a big-endian u32 to a buffer.
fn put_integer(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_be_bytes());
}

/// Helper: write a big-endian u64 to a buffer.
fn put_long(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_be_bytes());
}

/// Encode a variable-length field: if `len` < 128, one byte; else two bytes
/// with the high bit set on the first byte.
fn encode_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else {
        buf.push(((len >> 7) | 0x80) as u8);
        buf.push((len & 0x7F) as u8);
    }
}

impl OutputFormat for BinaryOutput {
    fn file_extension(&self) -> &str {
        "scan"
    }

    fn open(&mut self, writer: &mut dyn Write, ctx: &OutputContext) -> io::Result<()> {
        // Write a fixed-size header record.
        let mut header = [0u8; 2 + b'a' as usize]; // 2 + 97 = 99 bytes
        let msg = format!("zorp/1.1\ns:{}\n", ctx.when_scan_started);
        let copy_len = msg.len().min(header.len());
        header[..copy_len].copy_from_slice(&msg.as_bytes()[..copy_len]);
        writer.write_all(&header)
    }

    fn close(&mut self, writer: &mut dyn Write, _ctx: &OutputContext) -> io::Result<()> {
        // Write a terminator record.
        let mut trailer = [0u8; 2 + b'a' as usize];
        let msg = b"zorp/1.1";
        trailer[..msg.len()].copy_from_slice(msg);
        writer.write_all(&trailer)
    }

    fn report_status(
        &mut self,
        writer: &mut dyn Write,
        _ctx: &OutputContext,
        event: &StatusEvent,
    ) -> io::Result<()> {
        match &event.ip {
            IpAddress::V6(_) => self.write_status_ipv6(writer, event),
            IpAddress::V4(_) => self.write_status_ipv4(writer, event),
        }
    }

    fn report_banner(
        &mut self,
        writer: &mut dyn Write,
        _ctx: &OutputContext,
        event: &BannerEvent,
    ) -> io::Result<()> {
        match &event.ip {
            IpAddress::V6(_) => self.write_banner_ipv6(writer, event),
            IpAddress::V4(_) => self.write_banner_ipv4(writer, event),
        }
    }
}

impl BinaryOutput {
    /// Write an IPv4 status record.
    fn write_status_ipv4(
        &self,
        writer: &mut dyn Write,
        event: &StatusEvent,
    ) -> io::Result<()> {
        let record_type = match event.status {
            PortStatus::Open => OutputRecordType::OutOpen2,
            PortStatus::Closed => OutputRecordType::OutClosed2,
            PortStatus::Arp => OutputRecordType::OutArp2,
            _ => return Ok(()),
        };

        let ip_val = match event.ip {
            IpAddress::V4(v4) => v4,
            _ => unreachable!(),
        };

        let mut buf = Vec::with_capacity(15);
        buf.push(record_type as u8);     // [TYPE]
        buf.push(13);                     // [LENGTH]
        put_integer(&mut buf, event.timestamp as u32); // [TIMESTAMP]
        put_integer(&mut buf, ip_val);    // [IPv4]
        buf.push(event.ip_proto as u8);   // [IP_PROTO]
        put_short(&mut buf, event.port as u16); // [PORT]
        buf.push(event.reason as u8);     // [REASON]
        buf.push(event.ttl as u8);        // [TTL]

        debug_assert_eq!(buf.len(), 15);
        writer.write_all(&buf)
    }

    /// Write an IPv6 status record.
    fn write_status_ipv6(
        &self,
        writer: &mut dyn Write,
        event: &StatusEvent,
    ) -> io::Result<()> {
        let record_type = match event.status {
            PortStatus::Open => OutputRecordType::OutOpen6,
            PortStatus::Closed => OutputRecordType::OutClosed6,
            PortStatus::Arp => OutputRecordType::OutArp6,
            _ => return Ok(()),
        };

        let ipv6 = match event.ip {
            IpAddress::V6(v6) => v6,
            _ => unreachable!(),
        };

        let mut buf = Vec::with_capacity(28);
        buf.push(record_type as u8);     // [TYPE]
        buf.push(26);                     // [LENGTH]
        put_integer(&mut buf, event.timestamp as u32);
        buf.push(event.ip_proto as u8);
        put_short(&mut buf, event.port as u16);
        buf.push(event.reason as u8);
        buf.push(event.ttl as u8);
        buf.push(6u8);                    // version = IPv6
        put_long(&mut buf, ipv6.hi);
        put_long(&mut buf, ipv6.lo);

        debug_assert_eq!(buf.len(), 28);
        writer.write_all(&buf)
    }

    /// Write an IPv4 banner record.
    fn write_banner_ipv4(
        &self,
        writer: &mut dyn Write,
        event: &BannerEvent,
    ) -> io::Result<()> {
        const HEADER_LEN: usize = 14;
        let data_len = event.data.len();

        // Reject excessively large banners.
        if data_len >= 128 * 128 - HEADER_LEN {
            return Ok(());
        }

        let ip_val = match event.ip {
            IpAddress::V4(v4) => v4,
            _ => unreachable!(),
        };

        let total_payload = data_len + HEADER_LEN;

        let mut buf = Vec::with_capacity(3 + total_payload);
        buf.push(OutputRecordType::OutBanner9 as u8); // [TYPE]
        encode_length(&mut buf, total_payload);         // [LENGTH]

        // Fixed header fields.
        put_integer(&mut buf, event.timestamp as u32);
        put_integer(&mut buf, ip_val);
        buf.push(event.ip_proto as u8);
        put_short(&mut buf, event.port as u16);
        put_short(&mut buf, event.proto as u16);
        buf.push(event.ttl as u8);

        // Banner payload.
        buf.extend_from_slice(&event.data);

        writer.write_all(&buf)
    }

    /// Write an IPv6 banner record.
    fn write_banner_ipv6(
        &self,
        writer: &mut dyn Write,
        event: &BannerEvent,
    ) -> io::Result<()> {
        const HEADER_LEN: usize = 14 + 13; // 27 bytes of fixed header after type+length
        let data_len = event.data.len();

        if data_len >= 128 * 128 - HEADER_LEN {
            return Ok(());
        }

        let ipv6 = match event.ip {
            IpAddress::V6(v6) => v6,
            _ => unreachable!(),
        };

        let total_payload = data_len + HEADER_LEN;

        let mut buf = Vec::with_capacity(3 + total_payload);
        buf.push(OutputRecordType::OutBanner6 as u8);
        encode_length(&mut buf, total_payload);

        // Fixed header fields.
        put_integer(&mut buf, event.timestamp as u32);
        buf.push(event.ip_proto as u8);
        put_short(&mut buf, event.port as u16);
        put_short(&mut buf, event.proto as u16);
        buf.push(event.ttl as u8);
        buf.push(6u8); // version
        put_long(&mut buf, ipv6.hi);
        put_long(&mut buf, ipv6.lo);

        // Banner payload.
        buf.extend_from_slice(&event.data);

        writer.write_all(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::massip::addr::{IpAddress, Ipv6Address};
    use crate::output::ApplicationProtocol;

    fn make_ctx() -> OutputContext {
        OutputContext {
            when_scan_started: 1700000000,
            is_gmt: false,
            counts: Default::default(),
            xml_stylesheet: None,
        }
    }

    #[test]
    fn test_binary_open_close() {
        let mut out = BinaryOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        out.open(&mut buf, &ctx).unwrap();
        out.close(&mut buf, &ctx).unwrap();

        let output = String::from_utf8_lossy(&buf);
        assert!(output.starts_with("zorp/1.1\ns:"));
        assert!(output.contains("zorp/1.1"));
    }

    #[test]
    fn test_binary_status_ipv4() {
        let mut out = BinaryOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        let event = StatusEvent {
            timestamp: 1700000001,
            ip: IpAddress::V4(0xC0A80001),
            ip_proto: 6,
            port: 443,
            status: PortStatus::Open,
            reason: 0x12,
            ttl: 64,
            mac: None,
        };

        out.report_status(&mut buf, &ctx, &event).unwrap();

        // Should be exactly 15 bytes: type(1) + length(1) + payload(13)
        assert_eq!(buf.len(), 15);
        assert_eq!(buf[0], OutputRecordType::OutOpen2 as u8);
        assert_eq!(buf[1], 13);
        // Timestamp in big-endian.
        let ts = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        assert_eq!(ts, 1700000001);
        // IPv4 in big-endian.
        let ip = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]);
        assert_eq!(ip, 0xC0A80001);
        // Proto
        assert_eq!(buf[10], 6);
        // Port big-endian.
        let port = u16::from_be_bytes([buf[11], buf[12]]);
        assert_eq!(port, 443);
        // Reason + TTL
        assert_eq!(buf[13], 0x12);
        assert_eq!(buf[14], 64);
    }

    #[test]
    fn test_binary_status_ipv6() {
        let mut out = BinaryOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        let event = StatusEvent {
            timestamp: 1700000001,
            ip: IpAddress::V6(Ipv6Address {
                hi: 0x2001_0db8_0000_0000,
                lo: 0x0000_0000_0000_0001,
            }),
            ip_proto: 6,
            port: 80,
            status: PortStatus::Open,
            reason: 0x12,
            ttl: 64,
            mac: None,
        };

        out.report_status(&mut buf, &ctx, &event).unwrap();

        // Should be 28 bytes: type(1) + length(1) + payload(26)
        assert_eq!(buf.len(), 28);
        assert_eq!(buf[0], OutputRecordType::OutOpen6 as u8);
        assert_eq!(buf[1], 26);
    }

    #[test]
    fn test_binary_banner_ipv4() {
        let mut out = BinaryOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        let event = BannerEvent {
            timestamp: 1700000001,
            ip: IpAddress::V4(0xC0A80001),
            ip_proto: 6,
            port: 80,
            proto: ApplicationProtocol::Http,
            ttl: 64,
            data: b"nginx".to_vec(),
        };

        out.report_banner(&mut buf, &ctx, &event).unwrap();

        assert_eq!(buf[0], OutputRecordType::OutBanner9 as u8);
        // Total payload = 5 (data) + 14 (header) = 19, which is < 128.
        assert_eq!(buf[1], 19);
        // Banner data starts at offset 2+14 = 16.
        assert_eq!(&buf[16..], b"nginx");
    }

    #[test]
    fn test_encode_length_short() {
        let mut buf = Vec::new();
        encode_length(&mut buf, 50);
        assert_eq!(buf, vec![50]);
    }

    #[test]
    fn test_encode_length_long() {
        let mut buf = Vec::new();
        encode_length(&mut buf, 200);
        // 200 >> 7 = 1, | 0x80 = 0x81
        // 200 & 0x7F = 0x48
        assert_eq!(buf, vec![0x81, 0x48]);
    }
}
