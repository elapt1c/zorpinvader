//! NDJSON (Newline-Delimited JSON) output format.
//!
//! Each line is a self-contained JSON object. No array wrapper, no trailing
//! commas — ideal for streaming parsers and `jq` pipelines.
//!
//! Ported from C `out-ndjson.c`.

use std::io::{self, Write};

use super::{
    ApplicationProtocol, BannerEvent, OutputContext, OutputFormat, StatusEvent,
    name_from_ip_proto, normalize_json_string, reason_string,
};

/// NDJSON output plugin.
pub struct NdJsonOutput;

impl NdJsonOutput {
    pub fn new() -> Self {
        Self
    }
}

impl OutputFormat for NdJsonOutput {
    fn file_extension(&self) -> &str {
        "ndjson"
    }

    fn open(&mut self, _writer: &mut dyn Write, _ctx: &OutputContext) -> io::Result<()> {
        // No header needed for NDJSON.
        Ok(())
    }

    fn close(&mut self, _writer: &mut dyn Write, _ctx: &OutputContext) -> io::Result<()> {
        // No trailer needed for NDJSON.
        Ok(())
    }

    fn report_status(
        &mut self,
        writer: &mut dyn Write,
        _ctx: &OutputContext,
        event: &StatusEvent,
    ) -> io::Result<()> {
        let ip_str = event.ip.to_string();
        let reason = reason_string(event.reason);

        writeln!(
            writer,
            "{{\"ip\":\"{}\",\"timestamp\":\"{}\",\"port\":{},\"proto\":\"{}\",\
             \"rec_type\":\"status\",\"data\":{{\"status\":\"{}\",\"reason\":\"{}\",\"ttl\":{}}}}}",
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
        let ip_str = event.ip.to_string();
        let banner = normalize_json_string(&event.data);

        writeln!(
            writer,
            "{{\"ip\":\"{}\",\"timestamp\":\"{}\",\"port\":{},\"proto\":\"{}\",\
             \"rec_type\":\"banner\",\"data\":{{\"service_name\":\"{}\",\"banner\":\"{}\"}}}}",
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
    use crate::massip::addr::IpAddress;

    fn make_ctx() -> OutputContext {
        OutputContext {
            when_scan_started: 1700000000,
            is_gmt: false,
            counts: Default::default(),
            xml_stylesheet: None,
        }
    }

    #[test]
    fn test_ndjson_status() {
        let mut out = NdJsonOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        let event = StatusEvent {
            timestamp: 1700000001,
            ip: IpAddress::V4(0xC0A80001),
            ip_proto: 6,
            port: 22,
            status: super::super::PortStatus::Open,
            reason: 0x12,
            ttl: 64,
            mac: None,
        };

        out.report_status(&mut buf, &ctx, &event).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.ends_with('\n'));
        assert!(output.contains("\"rec_type\":\"status\""));
        assert!(output.contains("\"ip\":\"192.168.0.1\""));
        assert!(output.contains("\"status\":\"open\""));
        // Each line is valid JSON on its own — no commas, no brackets.
        assert!(!output.contains('['));
        assert!(!output.contains(']'));
    }

    #[test]
    fn test_ndjson_banner() {
        let mut out = NdJsonOutput::new();
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
        assert!(output.contains("\"rec_type\":\"banner\""));
        assert!(output.contains("\"service_name\":\"http\""));
        assert!(output.contains("\"banner\":\"nginx/1.19\""));
    }

    #[test]
    fn test_ndjson_no_header_or_trailer() {
        let mut out = NdJsonOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        out.open(&mut buf, &ctx).unwrap();
        out.close(&mut buf, &ctx).unwrap();

        assert!(buf.is_empty());
    }
}
