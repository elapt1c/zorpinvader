//! CoAP (Constrained Application Protocol) parser.
//!
//! Parses CoAP responses from IoT devices. Implements the equivalent of
//! `GET /.well-known/core` response parsing.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |Ver| T |  TKL  |      Code     |          Message ID           |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |   Token (if any, TKL bytes) ...
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |   Options (if any) ...
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |1 1 1 1 1 1 1 1|    Payload (if any) ...
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::proto::banout::BannerOutput;
use crate::proto::banner1::AppProtocol;

/// A parsed CoAP link.
#[derive(Clone, Copy)]
struct CoapLink {
    link_offset: usize,
    link_length: usize,
    #[allow(dead_code)]
    parms_offset: usize,
    #[allow(dead_code)]
    parms_length: usize,
}

/// Return a human-readable CoAP response code string.
fn response_code(code: u32) -> &'static str {
    let c = |x: u32, y: u32| (x << 5) | y;
    match code {
        x if x == c(2, 0) => "Okay",
        x if x == c(2, 1) => "Created",
        x if x == c(2, 2) => "Deleted",
        x if x == c(2, 3) => "Valid",
        x if x == c(2, 4) => "Changed",
        x if x == c(2, 5) => "Content",
        x if x == c(4, 0) => "Bad Request",
        x if x == c(4, 1) => "Unauthorized",
        x if x == c(4, 2) => "Bad Option",
        x if x == c(4, 3) => "Forbidden",
        x if x == c(4, 4) => "Not Found",
        x if x == c(4, 5) => "Method Not Allowed",
        x if x == c(4, 6) => "Not Acceptable",
        x if x == c(4, 12) => "Precondition Failed",
        x if x == c(4, 13) => "Request Too Large",
        x if x == c(4, 15) => "Unsupported Content-Format",
        x if x == c(5, 0) => "Internal Server Error",
        x if x == c(5, 1) => "Not Implemented",
        x if x == c(5, 2) => "Bad Gateway",
        x if x == c(5, 3) => "Service Unavailable",
        x if x == c(5, 4) => "Gateway Timeout",
        x if x == c(5, 5) => "Proxying Not Supported",
        _ => match code >> 5 {
            2 => "Okay",
            4 => "Error",
            _ => "PARSE_ERR",
        },
    }
}

/// Check if a byte is an RFC 5987 attr-char.
fn is_attr_char(c: u8) -> bool {
    matches!(c,
        b'!' | b'#' | b'$' | b'&' | b'+' | b'-' | b'.' |
        b'^' | b'_' | b'`' | b'|' | b'~'
    ) || c.is_ascii_alphanumeric()
}

/// Parse CoAP link-format payload into a list of links.
fn parse_links(px: &[u8], offset: usize, length: usize) -> Vec<CoapLink> {
    #[derive(Clone, Copy, PartialEq)]
    enum LinkState {
        LinkBegin,
        LinkValue,
        LinkEnd,
        ParmBegin,
        ParmNameBegin,
        ParmValueBegin,
        ParmQuoted,
        ParmQuotedEscape,
        ParmName,
        ParmValue,
        Invalid,
    }

    let mut links = Vec::new();
    let mut state = LinkState::LinkBegin;
    let mut current = CoapLink {
        link_offset: offset,
        link_length: 0,
        parms_offset: offset,
        parms_length: 0,
    };

    let mut off = offset;
    while off < length {
        let c = px[off];
        match state {
            LinkState::Invalid => break,
            LinkState::LinkBegin => {
                if c.is_ascii_whitespace() {
                    off += 1;
                    continue;
                }
                if c != b'<' {
                    state = LinkState::Invalid;
                    break;
                }
                current = CoapLink {
                    link_offset: off + 1,
                    link_length: 0,
                    parms_offset: off + 1,
                    parms_length: 0,
                };
                state = LinkState::LinkValue;
            }
            LinkState::LinkValue => {
                if c == b'>' {
                    state = LinkState::LinkEnd;
                } else {
                    current.link_length += 1;
                }
            }
            LinkState::LinkEnd => {
                current.parms_offset = off + 1;
                current.parms_length = 0;
                if c.is_ascii_whitespace() {
                    off += 1;
                    continue;
                } else if c == b',' {
                    links.push(current);
                    state = LinkState::LinkBegin;
                } else if c == b';' {
                    state = LinkState::ParmNameBegin;
                } else {
                    state = LinkState::Invalid;
                }
            }
            LinkState::ParmBegin => {
                if c.is_ascii_whitespace() {
                    off += 1;
                    continue;
                } else if c == b',' {
                    current.parms_length = off - current.parms_offset;
                    links.push(current);
                    state = LinkState::LinkBegin;
                } else if c == b';' {
                    state = LinkState::ParmNameBegin;
                } else {
                    state = LinkState::Invalid;
                }
            }
            LinkState::ParmNameBegin => {
                if c.is_ascii_whitespace() {
                    off += 1;
                    continue;
                }
                if !is_attr_char(c) {
                    state = LinkState::Invalid;
                } else {
                    state = LinkState::ParmName;
                }
            }
            LinkState::ParmName => {
                if c.is_ascii_whitespace() {
                    off += 1;
                    continue;
                } else if c == b'=' {
                    state = LinkState::ParmValueBegin;
                } else if !is_attr_char(c) {
                    state = LinkState::Invalid;
                }
            }
            LinkState::ParmValueBegin => {
                if c.is_ascii_whitespace() {
                    off += 1;
                    continue;
                } else if c == b'"' {
                    state = LinkState::ParmQuoted;
                } else if c == b';' {
                    state = LinkState::ParmNameBegin;
                } else if c == b',' {
                    current.parms_length = off - current.parms_offset;
                    links.push(current);
                    state = LinkState::LinkBegin;
                } else {
                    state = LinkState::ParmValue;
                }
            }
            LinkState::ParmValue => {
                if c.is_ascii_whitespace() {
                    off += 1;
                    continue;
                } else if c == b';' {
                    state = LinkState::ParmNameBegin;
                } else if c == b',' {
                    current.parms_length = off - current.parms_offset;
                    links.push(current);
                    state = LinkState::LinkBegin;
                }
            }
            LinkState::ParmQuoted => {
                if c == b'\\' {
                    state = LinkState::ParmQuotedEscape;
                } else if c == b'"' {
                    state = LinkState::ParmValue;
                }
            }
            LinkState::ParmQuotedEscape => {
                state = LinkState::ParmQuoted;
            }
        }
        off += 1;
    }

    // Push last link if in a valid end state
    if state == LinkState::LinkEnd || state == LinkState::ParmBegin
        || state == LinkState::ParmName || state == LinkState::ParmValue
        || state == LinkState::ParmNameBegin || state == LinkState::ParmValueBegin
    {
        current.parms_length = off - current.parms_offset;
        links.push(current);
    }

    links
}

/// Parse a CoAP packet and produce banner output.
///
/// Returns `true` if the packet is a valid CoAP response.
pub fn coap_parse(px: &[u8], length: usize, banout: &mut BannerOutput) -> (bool, u32) {
    let proto = AppProtocol::Coap as u32;

    // Minimum packet size
    if length < 4 || px.len() < length {
        return (false, 0);
    }

    let version = (px[0] >> 6) & 3;
    let pkt_type = (px[0] >> 4) & 3;
    let token_length = (px[0] & 0x0F) as usize;
    let code = px[1] as u32;
    let request_id = ((px[2] as u32) << 8) | (px[3] as u32);

    // Only version 1 supported
    if version != 1 {
        return (false, 0);
    }

    // Only ACK type (2) supported
    if pkt_type != 2 {
        return (false, 0);
    }

    // Token length sanity check
    if token_length > 8 || 4 + token_length > length {
        return (false, 0);
    }

    // Parse token
    let mut token: u64 = 0;
    for i in 0..token_length {
        token = (token << 8) | (px[4 + i] as u64);
    }

    // Response code
    {
        let s = format!("rsp={}.{}({})", code >> 5, code & 0x1F, response_code(code));
        banout.append_str(proto, &s);
    }

    // Token
    if token != 0 {
        let s = format!(" token=0x{:x}", token);
        banout.append_str(proto, &s);
    }

    // Parse options
    let mut offset = 4 + token_length;
    let mut optnum: u32 = 0;
    let mut content_format: u32 = 0;

    while offset < length {
        let opt = px[offset] as u32;
        offset += 1;
        if opt == 0xFF {
            break;
        }
        let mut optlen = (opt & 0x0F) as usize;
        let mut delta = (opt >> 4) & 0x0F;

        // Decode delta
        match delta {
            0..=12 => optnum += delta,
            13 => {
                if offset >= length {
                    banout.append_str(proto, " PARSE_ERR");
                    optnum = 0xFFFF_FFFF;
                } else {
                    delta = (px[offset] as u32) + 13;
                    offset += 1;
                    optnum += delta;
                }
            }
            14 => {
                if offset + 1 >= length {
                    banout.append_str(proto, " PARSE_ERR");
                    optnum = 0xFFFF_FFFF;
                } else {
                    delta = ((px[offset] as u32) << 8) | (px[offset + 1] as u32);
                    delta += 269;
                    offset += 2;
                    optnum += delta;
                }
            }
            15 => {
                if optlen != 15 {
                    banout.append_str(proto, " PARSE_ERR");
                }
                optnum = 0xFFFF_FFFF;
            }
            _ => {}
        }

        // Decode optlen
        match optlen {
            0..=12 => {}
            13 => {
                if offset >= length {
                    banout.append_str(proto, " PARSE_ERR");
                    optnum = 0xFFFF_FFFF;
                } else {
                    optlen = (px[offset] as usize) + 13;
                    offset += 1;
                }
            }
            14 => {
                if offset + 1 >= length {
                    banout.append_str(proto, " PARSE_ERR");
                    optnum = 0xFFFF_FFFF;
                } else {
                    optlen = (((px[offset] as usize) << 8) | (px[offset + 1] as usize)) + 269;
                    offset += 2;
                }
            }
            _ => {}
        }

        if offset + optlen > length {
            banout.append_str(proto, " PARSE_ERR");
            optnum = 0xFFFF_FFFF;
        }

        // Process option contents
        match optnum {
            0xFFFF_FFFF => {}
            1 => banout.append_str(proto, " /If-Match/"),
            3 => banout.append_str(proto, " /Uri-Host/"),
            4 => banout.append_str(proto, " /Etag"),
            5 => banout.append_str(proto, " /If-None-Match/"),
            7 => banout.append_str(proto, " /Uri-Port/"),
            8 => banout.append_str(proto, " /Location-Path/"),
            11 => banout.append_str(proto, " /Uri-Path/"),
            12 => {
                banout.append_str(proto, " /Content-Format/");
                content_format = 0;
                for j in 0..optlen {
                    content_format = (content_format << 8) | (px[offset + j] as u32);
                }
            }
            14 => banout.append_str(proto, " /Max-Age/"),
            15 => banout.append_str(proto, " /Uri-Query/"),
            17 => banout.append_str(proto, " /Accept/"),
            20 => banout.append_str(proto, " /Location-Query/"),
            35 => banout.append_str(proto, " /Proxy-Uri/"),
            39 => banout.append_str(proto, " /Proxy-Scheme/"),
            60 => banout.append_str(proto, " /Size1/"),
            _ => banout.append_str(proto, " /(Unknown)/"),
        }

        if optnum == 0xFFFF_FFFF {
            break;
        }

        offset += optlen;
    }

    // Content format
    match content_format {
        0 => banout.append_str(proto, " text-plain"),
        40 => {
            banout.append_str(proto, " application/link-format");
            let links = parse_links(px, offset, length);
            for link in &links {
                banout.append_char(proto, b' ');
                banout.append(proto, &px[link.link_offset..], link.link_length);
            }
        }
        41 => banout.append_str(proto, " application/xml"),
        42 => banout.append_str(proto, " application/octet-stream"),
        47 => banout.append_str(proto, " application/exi"),
        50 => banout.append_str(proto, " application/json"),
        _ => banout.append_str(proto, " (unknown-content-type)"),
    }

    (true, request_id)
}

/// Set the CoAP message ID cookie in an outgoing packet.
pub fn coap_udp_set_cookie(px: &mut [u8], length: usize, seqno: u64) -> u32 {
    if length < 4 {
        return 0;
    }
    px[2] = (seqno >> 8) as u8;
    px[3] = (seqno & 0xFF) as u8;
    0
}

/// Helper for selftest: check if a named link exists in the parsed list.
fn test_is_link(name: &str, input: &[u8], links: &[CoapLink]) -> bool {
    let name_bytes = name.as_bytes();
    for link in links {
        if link.link_length != name_bytes.len() {
            continue;
        }
        if link.link_offset + link.link_length <= input.len()
            && &input[link.link_offset..link.link_offset + link.link_length] == name_bytes
        {
            return true;
        }
    }
    false
}

/// Self-test for the CoAP parser.
pub fn proto_coap_selftest() -> bool {
    // Test quoted link parsing
    {
        let input = b"</sensors/temp>;if=\"se\\\"\\;\\,\\<\\>\\\\nsor\",</success>";
        let links = parse_links(input, 0, input.len());
        if !test_is_link("/success", input, &links) {
            return false;
        }
    }

    // Test a simple link
    {
        let input = b"</sensors/temp>;if=\"sensor\"";
        let links = parse_links(input, 0, input.len());
        if !test_is_link("/sensors/temp", input, &links) {
            return false;
        }
    }

    // Test a complex dump
    {
        let input = b"</sensors/temp>;if=\"sensor\",\
</sensors/light>;if=\"sensor\",\
</sensors>;ct=40,\
</sensors/temp>;rt=\"temperature-c\";if=\"sensor\",\
</sensors/light>;rt=\"light-lux\";if=\"sensor\",\
</sensors/light>;rt=\"light-lux\";if=\"sensor\",\
</sensors/light>;rt=\"light-lux core.sen-light\";if=\"sensor\",\
</sensors>;ct=40;title=\"Sensor Index\",\
</sensors/temp>;rt=\"temperature-c\";if=\"sensor\",\
</sensors/light>;rt=\"light-lux\";if=\"sensor\",\
<http://www.example.com/sensors/t123>;anchor=\"/sensors/temp\";rel=\"describedby\",\
</t>;anchor=\"/sensors/temp\";rel=\"alternate\",\
</firmware/v2.1>;rt=\"firmware\";sz=262144";
        let links = parse_links(input, 0, input.len());
        if !test_is_link("/firmware/v2.1", input, &links) {
            return false;
        }
    }

    // Test a full packet
    {
        let input: &[u8] = b"\x60\x45\x01\xce\xc1\x28\xff\x3c\x2f\x72\x65\x67\x69\x73\x74\x65\
\x72\x3e\x2c\x3c\x2f\x6e\x64\x6d\x2f\x64\x69\x73\x3e\x2c\x3c\x2f\
\x6e\x64\x6d\x2f\x63\x69\x3e\x2c\x3c\x2f\x6d\x69\x72\x72\x6f\x72\
\x3e\x2c\x3c\x2f\x75\x68\x70\x3e\x2c\x3c\x2f\x6e\x64\x6d\x2f\x6c\
\x6f\x67\x6f\x75\x74\x3e\x2c\x3c\x2f\x6e\x64\x6d\x2f\x6c\x6f\x67\
\x69\x6e\x3e\x2c\x3c\x2f\x69\x6e\x66\x6f\x3e";

        let mut banout = BannerOutput::new();
        let (is_valid, request_id) = coap_parse(input, input.len(), &mut banout);
        if !is_valid {
            return false;
        }
        if request_id != 462 {
            return false;
        }
    }

    true
}
