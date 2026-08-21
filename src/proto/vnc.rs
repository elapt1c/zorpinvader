//! VNC (RFB) protocol parser.
//!
//! Parses the Remote Framebuffer Protocol handshake, extracting
//! version info, security types, and server initialization data.

use crate::proto::banout::BannerOutput;
use crate::proto::banner1::{Banner1, StreamState, AppProtocol};

/// Append a human-readable security type name.
fn vnc_append_sectype(banout: &mut BannerOutput, sectype: u32) {
    match sectype {
        0 => banout.append_str(AppProtocol::VncInfo as u32, "  invalid"),
        1 => banout.append_str(AppProtocol::VncInfo as u32, "  none"),
        2 => banout.append_str(AppProtocol::VncInfo as u32, "  VNC-chap"),
        5 => banout.append_str(AppProtocol::VncInfo as u32, "  RA2"),
        6 => banout.append_str(AppProtocol::VncInfo as u32, "  RA2ne"),
        7 => banout.append_str(AppProtocol::VncInfo as u32, "  SSPI"),
        8 => banout.append_str(AppProtocol::VncInfo as u32, "  SSPIne"),
        16 => banout.append_str(AppProtocol::VncInfo as u32, "  Tight"),
        17 => banout.append_str(AppProtocol::VncInfo as u32, "  Ultra"),
        18 => banout.append_str(AppProtocol::VncInfo as u32, "  TLS"),
        19 => banout.append_str(AppProtocol::VncInfo as u32, "  VeNCrypt"),
        20 => banout.append_str(AppProtocol::VncInfo as u32, "  GTK-VNC-SASL"),
        21 => banout.append_str(AppProtocol::VncInfo as u32, "  MD5"),
        22 => banout.append_str(AppProtocol::VncInfo as u32, "  Colin-Dean-xvp"),
        30 => banout.append_str(AppProtocol::VncInfo as u32, "  Apple30"),
        35 => banout.append_str(AppProtocol::VncInfo as u32, "  Apple35"),
        _ => {
            let s = format!("  {}", sectype);
            banout.append_str(AppProtocol::VncInfo as u32, &s);
        }
    }
}

// State constants
const RFB3_3_SECURITYTYPES: u32 = 50;
const RFB_SECURITYERROR: u32 = 60;
const RFB3_7_SECURITYTYPES: u32 = 100;
const RFB_SERVERINIT: u32 = 200;
const RFB_SECURITYRESULT: u32 = 300;
const RFB_DONE: u32 = 0x7FFF_FFFF;

/// Parse VNC/RFB protocol data using a state machine.
pub fn vnc_parse(
    _banner1: &Banner1,
    pstate: &mut StreamState,
    px: &[u8],
    length: usize,
    banout: &mut BannerOutput,
) {
    let mut state = pstate.state;
    let (mut sectype, version, mut len, mut width, mut height) =
        if let crate::proto::banner1::ProtocolSubState::Vnc(ref vnc) = pstate.sub {
            (vnc.sectype, vnc.version, vnc.len, vnc.width, vnc.height)
        } else {
            (0u32, 0u8, 0u8, 0u16, 0u16)
        };

    for i in 0..length {
        match state {
            // States 0..10: Read "RFB xxx.yyy\n" version string
            0..=10 => {
                banout.append_char(AppProtocol::VncRfb as u32, px[i]);
                if state == 10 && px[i] != b'\n' {
                    state = 0xFFFF_FFFF;
                } else if state == 10 {
                    // Version line complete. Determine version.
                    // In the C code, pstate->sub.vnc.version is set externally
                    // by pattern matching. We use the stored version.
                    let v = (version % 10) as usize;
                    // Would send response based on version here (tcpapi_send).
                    if v < 7 {
                        state = RFB3_3_SECURITYTYPES;
                    } else {
                        state = RFB3_7_SECURITYTYPES;
                    }
                } else {
                    state += 1;
                }
            }

            // Read 4-byte big-endian security type / error code
            RFB3_3_SECURITYTYPES | RFB_SECURITYERROR | RFB_SECURITYRESULT | 220 => {
                sectype = px[i] as u32;
                state += 1;
            }
            51 | 52 | 61 | 62 | 301 | 302 | 221 | 222 => {
                sectype = (sectype << 8) | (px[i] as u32);
                state += 1;
            }

            // RFB 3.3 security type complete
            53 => {
                sectype = (sectype << 8) | (px[i] as u32);
                banout.append_str(AppProtocol::VncInfo as u32, "Security types:\n");
                vnc_append_sectype(banout, sectype);
                if sectype == 0 {
                    state = RFB_SECURITYERROR;
                } else if sectype == 1 {
                    // None auth - send ClientInit
                    state = RFB_SERVERINIT;
                } else {
                    state = RFB_DONE;
                }
            }

            // Security result complete
            303 => {
                sectype = (sectype << 8) | (px[i] as u32);
                if sectype == 0 {
                    state = RFB_SERVERINIT;
                } else {
                    state = RFB_SECURITYERROR;
                }
            }

            // Security error message length countdown
            63 => {
                sectype = (sectype << 8) | px[i] as u32;
                banout.append_str(AppProtocol::VncInfo as u32, "ERROR: ");
                state += 1;
            }
            64 => {
                if sectype == 0 {
                    state = RFB_DONE;
                } else {
                    sectype -= 1;
                    banout.append_char(AppProtocol::VncInfo as u32, px[i]);
                }
            }

            // RFB 3.7+ security types list
            100 => {
                len = px[i];
                if len == 0 {
                    state = RFB_SECURITYERROR;
                } else {
                    state += 1;
                    banout.append_str(AppProtocol::VncInfo as u32, "Security types:\n");
                }
            }
            101 => {
                if len != 0 {
                    len -= 1;
                    vnc_append_sectype(banout, px[i] as u32);
                }
                if len == 0 {
                    banout.append_char(AppProtocol::VncInfo as u32, b'\n');
                    if (version % 10) < 7 {
                        state = RFB_SERVERINIT;
                    } else if (version % 10) == 7 {
                        state = RFB_SERVERINIT;
                    } else {
                        state = RFB_SECURITYRESULT;
                    }
                } else {
                    banout.append_char(AppProtocol::VncInfo as u32, b'\n');
                }
            }

            // ServerInit: width (2 bytes big-endian)
            200 => {
                width = px[i] as u16;
                state += 1;
            }
            201 => {
                width = (width << 8) | (px[i] as u16);
                let s = format!(" width={}", width);
                banout.append_str(AppProtocol::VncRfb as u32, &s);
                state += 1;
            }

            // ServerInit: height (2 bytes big-endian)
            202 => {
                height = px[i] as u16;
                state += 1;
            }
            203 => {
                height = (height << 8) | (px[i] as u16);
                let s = format!(" height={}", height);
                banout.append_str(AppProtocol::VncRfb as u32, &s);
                state += 1;
            }

            // Skip pixel format (16 bytes: states 204..219)
            204..=219 => {
                state += 1;
            }

            // Name length (4 bytes big-endian) at states 220..223
            223 => {
                sectype = (sectype << 8) | (px[i] as u32);
                state += 1;
                if sectype != 0 {
                    banout.append_str(AppProtocol::VncInfo as u32, "Name: ");
                } else {
                    state = RFB_DONE;
                }
            }

            // Name contents
            224 => {
                sectype -= 1;
                banout.append_char(AppProtocol::VncInfo as u32, px[i]);
                if sectype == 0 {
                    banout.append_char(AppProtocol::VncInfo as u32, b'\n');
                    state = RFB_DONE;
                }
            }

            RFB_DONE | _ => break,
        }
    }

    pstate.state = state;
    if let crate::proto::banner1::ProtocolSubState::Vnc(ref mut vnc) = pstate.sub {
        vnc.sectype = sectype;
        vnc.version = version;
        vnc.len = len;
        vnc.width = width;
        vnc.height = height;
    }
}

pub fn vnc_init(_banner1: &mut Banner1) {}
pub fn vnc_selftest() -> bool { true }
