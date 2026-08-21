//! FTP protocol parser.
//!
//! Parses FTP server responses and handles AUTH TLS upgrade.

use crate::proto::banout::BannerOutput;
use crate::proto::banner1::{Banner1, StreamState, AppProtocol, ProtocolSubState};

/// Parse FTP data using a state machine.
///
/// States 0-5: Parse initial banner (220 response).
/// States 100-105: Parse AUTH TLS response.
pub fn ftp_parse(
    _banner1: &Banner1,
    pstate: &mut StreamState,
    px: &[u8],
    length: usize,
    banout: &mut BannerOutput,
) {
    let mut state = pstate.state;
    let (mut code, mut is_last) = if let ProtocolSubState::Ftp(ref ftp) = pstate.sub {
        (ftp.code, ftp.is_last)
    } else {
        (0u32, false)
    };

    for i in 0..length {
        match state {
            0 | 100 => {
                code = 0;
                state += 1;
                // Fall through
                if !px[i].is_ascii_digit() {
                    state = 0xFFFF_FFFF;
                } else {
                    code = code * 10 + (px[i] - b'0') as u32;
                    state += 1;
                    banout.append_char(AppProtocol::Ftp as u32, px[i]);
                }
            }
            1 | 2 | 3 | 101 | 102 | 103 => {
                if !px[i].is_ascii_digit() {
                    state = 0xFFFF_FFFF;
                } else {
                    code = code * 10 + (px[i] - b'0') as u32;
                    state += 1;
                    banout.append_char(AppProtocol::Ftp as u32, px[i]);
                }
            }
            4 | 104 => {
                if px[i] == b' ' {
                    is_last = true;
                    state += 1;
                    banout.append_char(AppProtocol::Ftp as u32, px[i]);
                } else if px[i] == b'-' {
                    is_last = false;
                    state += 1;
                    banout.append_char(AppProtocol::Ftp as u32, px[i]);
                } else {
                    state = 0xFFFF_FFFF;
                }
            }
            5 => {
                if px[i] == b'\r' {
                    continue;
                } else if px[i] == b'\n' {
                    if is_last {
                        // Would send AUTH TLS
                        state = 100;
                        banout.append_char(AppProtocol::Ftp as u32, px[i]);
                    } else {
                        banout.append_char(AppProtocol::Ftp as u32, px[i]);
                        state = 0;
                    }
                } else if px[i] == 0 || !px[i].is_ascii_graphic() {
                    state = 0xFFFF_FFFF;
                } else {
                    banout.append_char(AppProtocol::Ftp as u32, px[i]);
                }
            }
            105 => {
                if px[i] == b'\r' {
                    continue;
                } else if px[i] == b'\n' {
                    if code == 234 {
                        // Switch to SSL
                        let port = pstate.port;
                        *pstate = StreamState::default();
                        pstate.app_proto = AppProtocol::Ssl3 as u16;
                        pstate.is_sent_sslhello = true;
                        pstate.port = port;
                        state = 0;
                        // Would send SSL hello here
                    } else {
                        state = 0xFFFF_FFFF;
                    }
                } else if px[i] == 0 || !px[i].is_ascii_graphic() {
                    state = 0xFFFF_FFFF;
                } else {
                    banout.append_char(AppProtocol::Ftp as u32, px[i]);
                }
            }
            _ => break,
        }
    }

    pstate.state = state;
    if let ProtocolSubState::Ftp(ref mut ftp) = pstate.sub {
        ftp.code = code;
        ftp.is_last = is_last;
    }
}

pub fn ftp_init(_banner1: &mut Banner1) {}
pub fn ftp_selftest() -> bool { true }
