//! Null output format (`/dev/null`).
//!
//! Discards all output. Useful when the user only wants interactive console
//! output or when output is being handled elsewhere (e.g., fetcher).
//!
//! Ported from C `out-null.c`.

use std::io::{self, Write};

use super::{BannerEvent, OutputContext, OutputFormat, StatusEvent};

/// Null output plugin — discards everything.
pub struct NullOutput;

impl NullOutput {
    pub fn new() -> Self {
        Self
    }
}

impl OutputFormat for NullOutput {
    fn file_extension(&self) -> &str {
        "null"
    }

    fn open(&mut self, _writer: &mut dyn Write, _ctx: &OutputContext) -> io::Result<()> {
        Ok(())
    }

    fn close(&mut self, _writer: &mut dyn Write, _ctx: &OutputContext) -> io::Result<()> {
        Ok(())
    }

    fn report_status(
        &mut self,
        _writer: &mut dyn Write,
        _ctx: &OutputContext,
        _event: &StatusEvent,
    ) -> io::Result<()> {
        Ok(())
    }

    fn report_banner(
        &mut self,
        _writer: &mut dyn Write,
        _ctx: &OutputContext,
        _event: &BannerEvent,
    ) -> io::Result<()> {
        Ok(())
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
    fn test_null_produces_no_output() {
        let mut out = NullOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        out.open(&mut buf, &ctx).unwrap();

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

        let banner = BannerEvent {
            timestamp: 1700000001,
            ip: IpAddress::V4(0xC0A80001),
            ip_proto: 6,
            port: 80,
            proto: ApplicationProtocol::Http,
            ttl: 64,
            data: b"test".to_vec(),
        };
        out.report_banner(&mut buf, &ctx, &banner).unwrap();

        out.close(&mut buf, &ctx).unwrap();

        assert!(buf.is_empty(), "null output should produce zero bytes");
    }
}
