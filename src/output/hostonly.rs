//! Host-only output format.
//!
//! Prints only the IP address of responding hosts — one address per line,
//! no port numbers, no protocol details. Useful for building host lists.
//!
//! Ported from C `out-hostonly.c`.

use std::io::{self, Write};

use super::{BannerEvent, OutputContext, OutputFormat, StatusEvent};

/// Host-only output plugin.
pub struct HostonlyOutput;

impl HostonlyOutput {
    pub fn new() -> Self {
        Self
    }
}

impl OutputFormat for HostonlyOutput {
    fn file_extension(&self) -> &str {
        "hostonly"
    }

    fn open(&mut self, _writer: &mut dyn Write, _ctx: &OutputContext) -> io::Result<()> {
        Ok(())
    }

    fn close(&mut self, _writer: &mut dyn Write, _ctx: &OutputContext) -> io::Result<()> {
        Ok(())
    }

    fn report_status(
        &mut self,
        writer: &mut dyn Write,
        _ctx: &OutputContext,
        event: &StatusEvent,
    ) -> io::Result<()> {
        writeln!(writer, "{}", event.ip)
    }

    fn report_banner(
        &mut self,
        writer: &mut dyn Write,
        _ctx: &OutputContext,
        event: &BannerEvent,
    ) -> io::Result<()> {
        writeln!(writer, "{}", event.ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::massip::addr::{IpAddress, Ipv6Address};
    use crate::output::{PortStatus, ApplicationProtocol};

    fn make_ctx() -> OutputContext {
        OutputContext {
            when_scan_started: 1700000000,
            is_gmt: false,
            counts: Default::default(),
            xml_stylesheet: None,
        }
    }

    #[test]
    fn test_hostonly_status() {
        let mut out = HostonlyOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        let event = StatusEvent {
            timestamp: 1700000001,
            ip: IpAddress::V4(0xC0A80001),
            ip_proto: 6,
            port: 80,
            status: PortStatus::Open,
            reason: 0,
            ttl: 64,
            mac: None,
        };

        out.report_status(&mut buf, &ctx, &event).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output.trim(), "192.168.0.1");
    }

    #[test]
    fn test_hostonly_banner() {
        let mut out = HostonlyOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        let event = BannerEvent {
            timestamp: 1700000001,
            ip: IpAddress::V4(0x0A000001),
            ip_proto: 6,
            port: 443,
            proto: ApplicationProtocol::Ssl3,
            ttl: 64,
            data: b"cert data".to_vec(),
        };

        out.report_banner(&mut buf, &ctx, &event).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output.trim(), "10.0.0.1");
    }

    #[test]
    fn test_hostonly_ipv6() {
        let mut out = HostonlyOutput::new();
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
            reason: 0,
            ttl: 64,
            mac: None,
        };

        out.report_status(&mut buf, &ctx, &event).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("2001:db8::1"));
    }

    #[test]
    fn test_hostonly_no_headers() {
        let mut out = HostonlyOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        out.open(&mut buf, &ctx).unwrap();
        out.close(&mut buf, &ctx).unwrap();

        assert!(buf.is_empty());
    }
}
