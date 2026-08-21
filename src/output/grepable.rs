//! Grepable output format (nmap-compatible `-oG`).
//!
//! Produces tab-delimited output that is easy to parse with `grep`, `awk`,
//! and similar tools.
//!
//! Ported from C `out-grepable.c`.

use std::io::{self, Write};

use chrono::{DateTime, Utc};

use super::{
    name_from_ip_proto, normalize_string,
    BannerEvent, OutputContext, OutputFormat, StatusEvent,
};
use super::tcp_services;

/// Grepable output plugin.
pub struct GrepableOutput;

impl GrepableOutput {
    pub fn new() -> Self {
        Self
    }
}

impl OutputFormat for GrepableOutput {
    fn file_extension(&self) -> &str {
        "grepable"
    }

    fn open(&mut self, writer: &mut dyn Write, ctx: &OutputContext) -> io::Result<()> {
        let started = ctx.when_scan_started as i64;
        let dt = DateTime::<Utc>::from_timestamp(started, 0)
            .unwrap_or_default();
        let timestamp = dt.format("%c").to_string();

        writeln!(writer, "# Zorp 1.0 scan initiated {}", timestamp)
    }

    fn close(&mut self, writer: &mut dyn Write, _ctx: &OutputContext) -> io::Result<()> {
        let now = Utc::now();
        let timestamp = now.format("%c").to_string();
        writeln!(writer, "# Zorp done at {}", timestamp)
    }

    fn report_status(
        &mut self,
        writer: &mut dyn Write,
        _ctx: &OutputContext,
        event: &StatusEvent,
    ) -> io::Result<()> {
        let ip_str = event.ip.to_string();
        let service = match event.ip_proto {
            6 => tcp_services::tcp_service_name(event.port),
            17 => tcp_services::udp_service_name(event.port),
            _ => tcp_services::oproto_service_name(event.ip_proto),
        };

        write!(writer, "Timestamp: {}", event.timestamp)?;
        write!(writer, "\tHost: {} ()", ip_str)?;
        writeln!(
            writer,
            "\tPorts: {}/{}/{}/{}/{}/{}/{}",
            event.port,
            event.status.as_str(),
            name_from_ip_proto(event.ip_proto),
            "",       // owner
            service,   // service
            "",       // SunRPC info
            "",       // Version info
        )
    }

    fn report_banner(
        &mut self,
        writer: &mut dyn Write,
        _ctx: &OutputContext,
        event: &BannerEvent,
    ) -> io::Result<()> {
        let ip_str = event.ip.to_string();
        let banner = normalize_string(&event.data);

        write!(writer, "Host: {} ()", ip_str)?;
        write!(writer, "\tPort: {}", event.port)?;
        write!(writer, "\tService: {}", event.proto.as_str())?;
        writeln!(writer, "\tBanner: {}", banner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::massip::addr::IpAddress;
    use crate::output::{PortStatus, ApplicationProtocol};

    fn make_ctx() -> OutputContext {
        OutputContext {
            when_scan_started: 1700000000,
            is_gmt: true,
            counts: Default::default(),
            xml_stylesheet: None,
        }
    }

    #[test]
    fn test_grepable_status() {
        let mut out = GrepableOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        let event = StatusEvent {
            timestamp: 1700000001,
            ip: IpAddress::V4(0xC0A80001),
            ip_proto: 6,
            port: 22,
            status: PortStatus::Open,
            reason: 0,
            ttl: 64,
            mac: None,
        };

        out.report_status(&mut buf, &ctx, &event).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Timestamp: 1700000001"));
        assert!(output.contains("Host: 192.168.0.1 ()"));
        assert!(output.contains("Ports: 22/open/tcp/"));
    }

    #[test]
    fn test_grepable_banner() {
        let mut out = GrepableOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        let event = BannerEvent {
            timestamp: 1700000001,
            ip: IpAddress::V4(0xC0A80001),
            ip_proto: 6,
            port: 80,
            proto: ApplicationProtocol::Http,
            ttl: 64,
            data: b"nginx/1.19".to_vec(),
        };

        out.report_banner(&mut buf, &ctx, &event).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Host: 192.168.0.1 ()"));
        assert!(output.contains("Service: http"));
        assert!(output.contains("Banner: nginx/1.19"));
    }
}
