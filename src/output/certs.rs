//! Certificate output format.
//!
//! Extracts X.509 certificates from banner data and writes them in PEM
//! format. Port status events are ignored since certificates only appear
//! in banner data.
//!
//! Ported from C `out-certs.c`.

use std::io::{self, Write};

use super::{BannerEvent, OutputContext, OutputFormat, StatusEvent};

/// Certificate output plugin.
pub struct CertsOutput;

impl CertsOutput {
    pub fn new() -> Self {
        Self
    }
}

/// Line width for PEM-encoded certificate output.
const PEM_LINE_WIDTH: usize = 72;

impl OutputFormat for CertsOutput {
    fn file_extension(&self) -> &str {
        "cert"
    }

    fn open(&mut self, _writer: &mut dyn Write, _ctx: &OutputContext) -> io::Result<()> {
        // No header needed.
        Ok(())
    }

    fn close(&mut self, writer: &mut dyn Write, _ctx: &OutputContext) -> io::Result<()> {
        writeln!(writer, "{{finished: 1}}")
    }

    fn report_status(
        &mut self,
        _writer: &mut dyn Write,
        _ctx: &OutputContext,
        _event: &StatusEvent,
    ) -> io::Result<()> {
        // Certificates only come with banner data — no port status to report.
        Ok(())
    }

    fn report_banner(
        &mut self,
        writer: &mut dyn Write,
        _ctx: &OutputContext,
        event: &BannerEvent,
    ) -> io::Result<()> {
        let data = &event.data;

        // Strip the "cert:" prefix if present.
        let cert_data = if data.len() > 5 && &data[..5] == b"cert:" {
            &data[5..]
        } else {
            data.as_slice()
        };

        writeln!(writer, "-----BEGIN CERTIFICATE-----")?;

        // Write base64-like data in 72-character lines.
        // The C code assumes the data is already base64-encoded at this point.
        for chunk in cert_data.chunks(PEM_LINE_WIDTH) {
            writer.write_all(chunk)?;
            writeln!(writer)?;
        }

        writeln!(writer, "-----END CERTIFICATE-----")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::massip::addr::IpAddress;
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
    fn test_certs_status_is_noop() {
        let mut out = CertsOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        let event = StatusEvent {
            timestamp: 1700000001,
            ip: IpAddress::V4(0xC0A80001),
            ip_proto: 6,
            port: 443,
            status: crate::output::PortStatus::Open,
            reason: 0,
            ttl: 64,
            mac: None,
        };

        out.report_status(&mut buf, &ctx, &event).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn test_certs_banner_with_prefix() {
        let mut out = CertsOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        // Simulate banner data with "cert:" prefix followed by base64 content.
        let mut data = b"cert:".to_vec();
        data.extend_from_slice(b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA");

        let event = BannerEvent {
            timestamp: 1700000001,
            ip: IpAddress::V4(0xC0A80001),
            ip_proto: 6,
            port: 443,
            proto: ApplicationProtocol::X509Cert,
            ttl: 64,
            data,
        };

        out.report_banner(&mut buf, &ctx, &event).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("-----BEGIN CERTIFICATE-----"));
        assert!(output.contains("-----END CERTIFICATE-----"));
        assert!(output.contains("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"));
        // Should NOT contain the "cert:" prefix.
        assert!(!output.contains("cert:"));
    }

    #[test]
    fn test_certs_banner_without_prefix() {
        let mut out = CertsOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        let event = BannerEvent {
            timestamp: 1700000001,
            ip: IpAddress::V4(0xC0A80001),
            ip_proto: 6,
            port: 443,
            proto: ApplicationProtocol::X509Cert,
            ttl: 64,
            data: b"MIIBIjANBg".to_vec(),
        };

        out.report_banner(&mut buf, &ctx, &event).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("-----BEGIN CERTIFICATE-----"));
        assert!(output.contains("MIIBIjANBg"));
    }

    #[test]
    fn test_certs_close() {
        let mut out = CertsOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        out.close(&mut buf, &ctx).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output.trim(), "{finished: 1}");
    }
}
