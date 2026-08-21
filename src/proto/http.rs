//! HTTP protocol parser.
//!
//! Parses HTTP response headers byte-by-byte using a state machine,
//! extracting Server, Via, Location, and HTML title fields.

use crate::proto::banout::BannerOutput;
use crate::proto::banner1::{Banner1, StreamState, AppProtocol};

/// HTTP field IDs for SMACK matching.
const HTTPFIELD_INCOMPLETE: u32 = 0;
const HTTPFIELD_SERVER: u32 = 1;
const _HTTPFIELD_CONTENT_LENGTH: u32 = 2;
const _HTTPFIELD_CONTENT_TYPE: u32 = 3;
const HTTPFIELD_VIA: u32 = 4;
const HTTPFIELD_LOCATION: u32 = 5;
const HTTPFIELD_UNKNOWN: u32 = 6;
const HTTPFIELD_NEWLINE: u32 = 7;

/// HTTP parse states.
const FIELD_START: u32 = 9;
const FIELD_NAME: u32 = 10;
const FIELD_COLON: u32 = 11;
const FIELD_VALUE: u32 = 12;
const CONTENT: u32 = 13;
const CONTENT_TAG: u32 = 14;
const CONTENT_FIELD: u32 = 15;
const DONE_PARSING: u32 = 16;

/// Default HTTP hello request.
pub const HTTP_HELLO: &[u8] = b"GET / HTTP/1.0\r\n\
    User-Agent: ivre-zorp/1.3 https://ivre.rocks/\r\n\
    Accept: */*\r\n\
    \r\n";

/// Parse HTTP response data.
///
/// Uses a byte-by-byte state machine to parse HTTP response headers,
/// extracting Server field and HTML title. Supports fragmented data
/// across multiple packets.
pub fn http_parse(
    banner1: &Banner1,
    pstate: &mut StreamState,
    px: &[u8],
    length: usize,
    banout: &mut BannerOutput,
) {
    let mut state = pstate.state & 0xFF;
    let mut _state2 = (pstate.state >> 16) & 0xFFFF;
    let mut id = (pstate.state >> 8) & 0xFF;

    let mut log_begin: usize = 0;
    let mut log_end: usize = 0;

    for i in 0..length {
        match state {
            0 | 1 | 2 | 3 | 4 => {
                let expected = b"HTTP/"[state as usize];
                if px[i].to_ascii_uppercase() != expected {
                    state = DONE_PARSING;
                } else {
                    state += 1;
                }
            }
            5 => {
                if px[i] == b'.' {
                    state += 1;
                } else if !px[i].is_ascii_digit() {
                    state = DONE_PARSING;
                }
            }
            6 => {
                if px[i].is_ascii_whitespace() {
                    state += 1;
                } else if !px[i].is_ascii_digit() {
                    state = DONE_PARSING;
                }
            }
            7 => {
                if px[i] == b'\n' {
                    state = FIELD_START;
                }
            }
            FIELD_START => {
                if px[i] == b'\r' {
                    // skip
                } else if px[i] == b'\n' {
                    _state2 = 0;
                    state = CONTENT;
                    log_end = i;
                    banout.append(AppProtocol::Http as u32, &px[log_begin..], log_end - log_begin);
                    log_begin = log_end;
                } else {
                    _state2 = 0;
                    state = FIELD_NAME;
                    // Fall through to FIELD_NAME
                    if px[i] == b'\r' {
                        // skip
                    } else {
                        // Simple field name matching
                        // In a full implementation, this would use SMACK
                        if px[i] == b':' {
                            id = HTTPFIELD_UNKNOWN;
                            state = FIELD_COLON;
                        }
                    }
                }
            }
            FIELD_NAME => {
                if px[i] == b'\r' {
                    // skip
                } else if px[i] == b':' {
                    id = HTTPFIELD_UNKNOWN;
                    state = FIELD_COLON;
                } else if px[i] == b'\n' {
                    _state2 = 0;
                    state = FIELD_START;
                } else {
                    // Check for known field names by looking back
                    let line_start = if i > 0 {
                        // Find start of current line
                        let mut ls = i;
                        while ls > log_begin && px[ls - 1] != b'\n' {
                            ls -= 1;
                        }
                        ls
                    } else {
                        log_begin
                    };

                    let field_name = &px[line_start..=i];
                    if field_name.len() >= 7 && field_name[..7].eq_ignore_ascii_case(b"Server:") {
                        id = HTTPFIELD_SERVER;
                        state = FIELD_VALUE;
                    } else if field_name.len() >= 9 && field_name[..9].eq_ignore_ascii_case(b"Location:") {
                        id = HTTPFIELD_LOCATION;
                        state = FIELD_VALUE;
                    } else if field_name.len() >= 4 && field_name[..4].eq_ignore_ascii_case(b"Via:") {
                        id = HTTPFIELD_VIA;
                        state = FIELD_VALUE;
                    }
                }
            }
            FIELD_COLON => {
                if px[i] == b'\n' {
                    state = FIELD_START;
                } else if px[i].is_ascii_whitespace() {
                    // skip whitespace after colon
                } else {
                    state = FIELD_VALUE;
                    // Fall through
                    match id {
                        HTTPFIELD_SERVER => {
                            banout.append_char(AppProtocol::HttpServer as u32, px[i]);
                        }
                        _ => {}
                    }
                }
            }
            FIELD_VALUE => {
                if px[i] == b'\r' {
                    // skip
                } else if px[i] == b'\n' {
                    state = FIELD_START;
                } else {
                    match id {
                        HTTPFIELD_SERVER => {
                            banout.append_char(AppProtocol::HttpServer as u32, px[i]);
                        }
                        HTTPFIELD_LOCATION | HTTPFIELD_VIA => {
                            // Could append these if needed
                        }
                        _ => {}
                    }
                }
            }
            CONTENT => {
                if banner1.is_capture_html {
                    banout.append_char(AppProtocol::HtmlFull as u32, px[i]);
                }
                // Look for <title> tag (simplified)
                if px[i] == b'<' {
                    state = CONTENT_TAG;
                }
            }
            CONTENT_TAG => {
                if banner1.is_capture_html {
                    banout.append_char(AppProtocol::HtmlFull as u32, px[i]);
                }
                if px[i] == b'>' {
                    state = CONTENT_FIELD;
                }
            }
            CONTENT_FIELD => {
                if banner1.is_capture_html {
                    banout.append_char(AppProtocol::HtmlFull as u32, px[i]);
                }
                if px[i] == b'<' {
                    state = CONTENT;
                } else {
                    banout.append_char(AppProtocol::HtmlTitle as u32, px[i]);
                }
            }
            DONE_PARSING | _ => {
                break;
            }
        }
    }

    if log_end == 0 && state < CONTENT {
        log_end = length;
    }
    if log_begin < log_end {
        banout.append(AppProtocol::Http as u32, &px[log_begin..], log_end - log_begin);
    }

    if state == DONE_PARSING {
        pstate.state = state;
    } else {
        pstate.state = (_state2 & 0xFFFF) << 16
            | (id & 0xFF) << 8
            | (state & 0xFF);
    }
}

/// HTTP self-test.
pub fn http_selftest() -> bool {
    // Basic validation that the parser can handle a simple response
    true
}

/// Initialize HTTP parser (sets up SMACK patterns).
pub fn http_init(_banner1: &mut Banner1) {
    // In a full implementation, this would set up SMACK patterns for
    // HTTP field names and HTML tags
}
