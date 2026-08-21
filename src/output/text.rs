//! Plain-text / interactive output format.
//!
//! Produces a simple, human-readable text stream suitable for terminal
//! display or piping to other tools.
//!
//! Ported from C `out-text.c`.

use std::io::{self, Write};

use super::{
    name_from_ip_proto, normalize_string,
    BannerEvent, OutputContext, OutputFormat, StatusEvent,
};

/// Text output plugin.
pub struct TextOutput;

impl TextOutput {
    pub fn new() -> Self {
        Self
    }
}

impl OutputFormat for TextOutput {
    fn file_extension(&self) -> &str {
        "txt"
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
        writeln!(
            writer,
            "{} {} {} {} {}",
            event.status.as_str(),
            name_from_ip_proto(event.ip_proto),
            event.port,
            ip_str,
            event.timestamp,
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
        writeln!(
            writer,
            "banner {} {} {} {} {} {}",
            name_from_ip_proto(event.ip_proto),
            event.port,
            ip_str,
            event.timestamp,
            event.proto.as_str(),
            banner,
        )
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
            is_gmt: false,
            counts: Default::default(),
            xml_stylesheet: None,
        }
    }

    #[test]
    fn test_text_open_close() {
        let mut out = TextOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        out.open(&mut buf, &ctx).unwrap();
        out.close(&mut buf, &ctx).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output, "#zorp\n# end\n");
    }

    #[test]
    fn test_text_status() {
        let mut out = TextOutput::new();
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
        assert_eq!(output.trim(), "open tcp 80 192.168.0.1 1700000001");
    }

    #[test]
    fn test_text_banner() {
        let mut out = TextOutput::new();
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

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("banner tcp 80 192.168.0.1 1700000001 http nginx"));
    }
}
