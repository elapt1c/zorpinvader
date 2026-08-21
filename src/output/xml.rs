//! XML output format (nmap-compatible).
//!
//! Produces an XML document with `<nmaprun>` as the root element, compatible
//! with tools that parse nmap XML output.
//!
//! Ported from C `out-xml.c`.

use std::io::{self, Write};

use chrono::{DateTime, Local, Utc};

use super::{
    name_from_ip_proto, name_from_ip_version, normalize_string, reason_string,
    BannerEvent, OutputContext, OutputFormat, StatusEvent,
};

/// XML output plugin.
pub struct XmlOutput;

impl XmlOutput {
    pub fn new() -> Self {
        Self
    }
}

impl OutputFormat for XmlOutput {
    fn file_extension(&self) -> &str {
        "xml"
    }

    fn open(&mut self, writer: &mut dyn Write, ctx: &OutputContext) -> io::Result<()> {
        write!(writer, "<?xml version=\"1.0\"?>\r\n")?;
        write!(writer, "<!-- zorp v1.0 scan -->\r\n")?;

        if let Some(ref stylesheet) = ctx.xml_stylesheet {
            if !stylesheet.is_empty() {
                write!(
                    writer,
                    "<?xml-stylesheet href=\"{}\" type=\"text/xsl\"?>\r\n",
                    stylesheet
                )?;
            }
        }

        let now = chrono::Utc::now().timestamp() as u64;
        write!(
            writer,
            "<nmaprun scanner=\"{}\" start=\"{}\" version=\"{}\" xmloutputversion=\"{}\">\r\n",
            "zorp", now, "1.0-BETA", "1.03",
        )?;
        write!(
            writer,
            "<scaninfo type=\"{}\" protocol=\"{}\" />\r\n",
            "syn", "tcp",
        )
    }

    fn close(&mut self, writer: &mut dyn Write, ctx: &OutputContext) -> io::Result<()> {
        let now = Utc::now();
        let time_str = if ctx.is_gmt {
            now.format("%Y-%m-%d %H:%M:%S").to_string()
        } else {
            let local: DateTime<Local> = now.with_timezone(&Local);
            local.format("%Y-%m-%d %H:%M:%S").to_string()
        };

        let now_epoch = now.timestamp() as u64;
        let elapsed = now_epoch.saturating_sub(ctx.when_scan_started);

        write!(
            writer,
            "<runstats>\r\n\
             <finished time=\"{}\" timestr=\"{}\" elapsed=\"{}\" />\r\n\
             <hosts up=\"{}\" down=\"{}\" total=\"{}\" />\r\n\
             </runstats>\r\n\
             </nmaprun>\r\n",
            now_epoch,
            time_str,
            elapsed,
            ctx.counts.tcp_open,
            ctx.counts.tcp_closed,
            ctx.counts.tcp_open + ctx.counts.tcp_closed,
        )
    }

    fn report_status(
        &mut self,
        writer: &mut dyn Write,
        _ctx: &OutputContext,
        event: &StatusEvent,
    ) -> io::Result<()> {
        let ip_str = event.ip.to_string();
        let version = super::ip_version(&event.ip);
        let reason = reason_string(event.reason);

        write!(
            writer,
            "<host endtime=\"{}\">",
            event.timestamp,
        )?;
        write!(
            writer,
            "<address addr=\"{}\" addrtype=\"{}\"/>",
            ip_str,
            name_from_ip_version(version),
        )?;
        write!(writer, "<ports>")?;
        write!(
            writer,
            "<port protocol=\"{}\" portid=\"{}\">",
            name_from_ip_proto(event.ip_proto),
            event.port,
        )?;
        write!(
            writer,
            "<state state=\"{}\" reason=\"{}\" reason_ttl=\"{}\"/>",
            event.status.as_str(),
            reason,
            event.ttl,
        )?;
        write!(writer, "</port>")?;
        write!(writer, "</ports>")?;
        write!(writer, "</host>\r\n")
    }

    fn report_banner(
        &mut self,
        writer: &mut dyn Write,
        _ctx: &OutputContext,
        event: &BannerEvent,
    ) -> io::Result<()> {
        let ip_str = event.ip.to_string();
        let version = super::ip_version(&event.ip);
        let banner = normalize_string(&event.data);

        let reason = match event.proto {
            super::ApplicationProtocol::Ssh1
            | super::ApplicationProtocol::Ssh2
            | super::ApplicationProtocol::Http
            | super::ApplicationProtocol::Ftp
            | super::ApplicationProtocol::Smtp
            | super::ApplicationProtocol::Pop3
            | super::ApplicationProtocol::Imap4 => "syn-ack",
            _ => "response",
        };

        write!(
            writer,
            "<host endtime=\"{}\">",
            event.timestamp,
        )?;
        write!(
            writer,
            "<address addr=\"{}\" addrtype=\"{}\"/>",
            ip_str,
            name_from_ip_version(version),
        )?;
        write!(writer, "<ports>")?;
        write!(
            writer,
            "<port protocol=\"{}\" portid=\"{}\">",
            name_from_ip_proto(event.ip_proto),
            event.port,
        )?;
        write!(
            writer,
            "<state state=\"open\" reason=\"{}\" reason_ttl=\"{}\" />",
            reason, event.ttl,
        )?;
        write!(
            writer,
            "<service name=\"{}\" banner=\"{}\"></service>",
            event.proto.as_str(),
            banner,
        )?;
        write!(writer, "</port>")?;
        write!(writer, "</ports>")?;
        write!(writer, "</host>\r\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::massip::addr::{IpAddress, Ipv6Address};
    use crate::output::{OutputCounts, PortStatus, ApplicationProtocol};

    fn make_ctx() -> OutputContext {
        OutputContext {
            when_scan_started: 1700000000,
            is_gmt: true,
            counts: OutputCounts {
                tcp_open: 10,
                tcp_closed: 5,
                ..Default::default()
            },
            xml_stylesheet: None,
        }
    }

    #[test]
    fn test_xml_open() {
        let mut out = XmlOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        out.open(&mut buf, &ctx).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("<?xml version=\"1.0\"?>"));
        assert!(output.contains("<nmaprun scanner=\"zorp\""));
        assert!(output.contains("version=\"1.0-BETA\""));
        assert!(output.contains("<scaninfo type=\"syn\" protocol=\"tcp\" />"));
    }

    #[test]
    fn test_xml_open_with_stylesheet() {
        let mut out = XmlOutput::new();
        let mut ctx = make_ctx();
        ctx.xml_stylesheet = Some("http://example.com/style.xsl".to_string());
        let mut buf = Vec::new();

        out.open(&mut buf, &ctx).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("xml-stylesheet href=\"http://example.com/style.xsl\""));
    }

    #[test]
    fn test_xml_close_stats() {
        let mut out = XmlOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        out.close(&mut buf, &ctx).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("<hosts up=\"10\" down=\"5\" total=\"15\" />"));
        assert!(output.contains("</nmaprun>"));
    }

    #[test]
    fn test_xml_status() {
        let mut out = XmlOutput::new();
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

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("addr=\"192.168.0.1\""));
        assert!(output.contains("addrtype=\"ipv4\""));
        assert!(output.contains("portid=\"443\""));
        assert!(output.contains("state=\"open\""));
        assert!(output.contains("reason=\"syn-ack\""));
    }

    #[test]
    fn test_xml_banner() {
        let mut out = XmlOutput::new();
        let ctx = make_ctx();
        let mut buf = Vec::new();

        let event = BannerEvent {
            timestamp: 1700000001,
            ip: IpAddress::V4(0x0A000001),
            ip_proto: 6,
            port: 80,
            proto: ApplicationProtocol::Http,
            ttl: 64,
            data: b"Apache/2.4".to_vec(),
        };

        out.report_banner(&mut buf, &ctx, &event).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("state=\"open\""));
        assert!(output.contains("name=\"http\""));
        assert!(output.contains("banner=\"Apache/2.4\""));
    }
}
