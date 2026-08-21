//! JSON output format.
//!
//! Writes scan results as a JSON array of objects. Each record is a JSON
//! object with `ip`, `timestamp`, and `ports` fields.
//!
//! Ported from C `out-json.c`.

use std::io::{self, Write};

use crate::massip::addr::IpAddress;

use super::{
    ApplicationProtocol, BannerEvent, OutputContext, OutputFormat, StatusEvent,
    name_from_ip_proto, normalize_json_string, reason_string,
};

/// JSON output plugin.
pub struct JsonOutput {
    /// Whether the first record has been written (controls comma insertion).
    first_record_seen: bool,
}

impl JsonOutput {
    pub fn new() -> Self {
        Self {
            first_record_seen: false,
        }
    }
}

impl OutputFormat for JsonOutput {
    fn file_extension(&self) -> &str {
        "json"
    }

    fn open(&mut self, writer: &mut dyn Write, _ctx: &OutputContext) -> io::Result<()> {
        writeln!(writer, "[")
    }

    fn close(&mut self, writer: &mut dyn Write, _ctx: &OutputContext) -> io::Result<()> {
        writeln!(writer, "]")
    }

    fn report_status(
        &mut self,
        writer: &mut dyn Write,
        _ctx: &OutputContext,
        event: &StatusEvent,
    ) -> io::Result<()> {
        // Handle comma separator: prepend comma for all records except the first.
        if self.first_record_seen {
            write!(writer, ",\n")?;
        } else {
            self.first_record_seen = true;
        }

        let ip_str = event.ip.to_string();
        let reason = reason_string(event.reason);

        write!(
            writer,
            "{{ \"ip\": \"{}\", \"timestamp\": \"{}\", \"ports\": [ {{\"port\": {}, \
             \"proto\": \"{}\", \"status\": \"{}\", \"reason\": \"{}\", \"ttl\": {}}} ] }}",
            ip_str,
            event.timestamp,
            event.port,
            name_from_ip_proto(event.ip_proto),
            event.status.as_str(),
            reason,
            event.ttl,
        )
    }

    fn report_banner(
        &mut self,
        writer: &mut dyn Write,
        _ctx: &OutputContext,
        event: &BannerEvent,
    ) -> io::Result<()> {
        if self.first_record_seen {
            write!(writer, ",\n")?;
        } else {
            self.first_record_seen = true;
        }

        let ip_str = event.ip.to_string();
        let banner = normalize_json_string(&event.data);

        write!(
            writer,
            "{{ \"ip\": \"{}\", \"timestamp\": \"{}\", \"ports\": [ {{\"port\": {}, \
             \"proto\": \"{}\", \"service\": {{\"name\": \"{}\", \"banner\": \"{}\"}} }} ] }}",
            ip_str,
            event.timestamp,
            event.port,
            name_from_ip_proto(event.ip_proto),
            event.proto.as_str(),
            banner,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::massip::addr::Ipv6Address;

    fn make_ctx() -> OutputContext {
        OutputContext {
            when_scan_started: 1700000000,
            is_gmt: false,
            counts: Default::default(),
            xml_stylesheet: None,
        }
    }

    #[test]
    fn test_json_status_output() {
        let mut out = JsonOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        // Open bracket.
        out.open(&mut buf, &ctx).unwrap();

        let event = StatusEvent {
            timestamp: 1700000001,
            ip: IpAddress::V4(0xC0A80001), // 192.168.0.1
            ip_proto: 6,
            port: 443,
            status: super::super::PortStatus::Open,
            reason: 0x12, // syn-ack
            ttl: 64,
            mac: None,
        };

        out.report_status(&mut buf, &ctx, &event).unwrap();

        // Second record should have comma.
        out.report_status(&mut buf, &ctx, &event).unwrap();

        out.close(&mut buf, &ctx).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("[\n"));
        assert!(output.ends_with("]\n"));
        assert!(output.contains("\"ip\": \"192.168.0.1\""));
        assert!(output.contains("\"port\": 443"));
        assert!(output.contains("\"status\": \"open\""));
        assert!(output.contains("\"reason\": \"syn-ack\""));
        // Verify comma between records.
        assert!(output.contains("},\n{ "));
    }

    #[test]
    fn test_json_banner_output() {
        let mut out = JsonOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        out.open(&mut buf, &ctx).unwrap();

        let event = BannerEvent {
            timestamp: 1700000001,
            ip: IpAddress::V4(0x0A000001), // 10.0.0.1
            ip_proto: 6,
            port: 80,
            proto: ApplicationProtocol::Http,
            ttl: 64,
            data: b"Apache/2.4".to_vec(),
        };

        out.report_banner(&mut buf, &ctx, &event).unwrap();
        out.close(&mut buf, &ctx).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("\"name\": \"http\""));
        assert!(output.contains("\"banner\": \"Apache/2.4\""));
    }
}
