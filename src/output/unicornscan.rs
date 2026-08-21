//! Unicornscan-compatible output format.
//!
//! Produces output compatible with the `unicornscan` tool's format.
//! TCP results use unicornscan's native layout; other protocols fall
//! back to a grepable-style format.
//!
//! Ported from C `out-unicornscan.c`.

use std::io::{self, Write};

use super::{
    name_from_ip_proto,
    BannerEvent, OutputContext, OutputFormat, StatusEvent,
};
use super::tcp_services;

/// Unicornscan output plugin.
pub struct UnicornscanOutput;

impl UnicornscanOutput {
    pub fn new() -> Self {
        Self
    }
}

impl OutputFormat for UnicornscanOutput {
    fn file_extension(&self) -> &str {
        "uni"
    }

    fn open(&mut self, writer: &mut dyn Write, _ctx: &OutputContext) -> io::Result<()> {
        writeln!(writer, "#zorp")
    }

    fn close(&mut self, writer: &mut dyn Write, _ctx: &OutputContext) -> io::Result<()> {
        writeln!(writer, "# end")
    }

    fn report_status(
        &mut self,
        writer: &mut dyn Write,
        _ctx: &OutputContext,
        event: &StatusEvent,
    ) -> io::Result<()> {
        let ip_str = event.ip.to_string();

        if event.ip_proto == 6 {
            // TCP: unicornscan native format.
            let service = tcp_services::tcp_service_name(event.port);
            writeln!(
                writer,
                "TCP {}\t{:>16}[{:>5}]\t\tfrom {}  ttl {}",
                event.status.as_str(),
                service,
                event.port,
                ip_str,
                event.ttl,
            )
        } else {
            // Non-TCP: fall back to grepable-like format.
            write!(writer, "Host: {} ()", ip_str)?;
            writeln!(
                writer,
                "\tPorts: {}/{}/{}/{}/{}/{}/{}",
                event.port,
                event.status.as_str(),
                name_from_ip_proto(event.ip_proto),
                "", // owner
                "", // service
                "", // SunRPC info
                "", // Version info
            )
        }
    }

    fn report_banner(
        &mut self,
        _writer: &mut dyn Write,
        _ctx: &OutputContext,
        _event: &BannerEvent,
    ) -> io::Result<()> {
        // Unicornscan is SYN-only — no banner output.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::massip::addr::IpAddress;
    use crate::output::PortStatus;

    fn make_ctx() -> OutputContext {
        OutputContext {
            when_scan_started: 1700000000,
            is_gmt: false,
            counts: Default::default(),
            xml_stylesheet: None,
        }
    }

    #[test]
    fn test_unicornscan_tcp() {
        let mut out = UnicornscanOutput::new();
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
        assert!(output.contains("TCP open"));
        assert!(output.contains("192.168.0.1"));
        assert!(output.contains("ttl 64"));
    }

    #[test]
    fn test_unicornscan_udp_fallback() {
        let mut out = UnicornscanOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        let event = StatusEvent {
            timestamp: 1700000001,
            ip: IpAddress::V4(0xC0A80001),
            ip_proto: 17,
            port: 53,
            status: PortStatus::Open,
            reason: 0,
            ttl: 64,
            mac: None,
        };

        out.report_status(&mut buf, &ctx, &event).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Host: 192.168.0.1 ()"));
        assert!(output.contains("Ports: 53/open/udp/"));
    }

    #[test]
    fn test_unicornscan_banner_is_noop() {
        let mut out = UnicornscanOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        let event = BannerEvent {
            timestamp: 1700000001,
            ip: IpAddress::V4(0xC0A80001),
            ip_proto: 6,
            port: 80,
            proto: crate::output::ApplicationProtocol::Http,
            ttl: 64,
            data: b"test".to_vec(),
        };

        out.report_banner(&mut buf, &ctx, &event).unwrap();
        assert!(buf.is_empty());
    }
}
