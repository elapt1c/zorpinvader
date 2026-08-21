//! Telnet protocol parser.
//!
//! Parses Telnet option negotiation (IAC sequences) and extracts
//! banner text from telnet server responses. Builds a negotiation
//! reply for WILL/WONT/DO/DONT options.

use crate::proto::banout::BannerOutput;
use crate::proto::banner1::{Banner1, StreamState, AppProtocol};

const PROTO: u32 = AppProtocol::Telnet as u32;

// Telnet negotiation flags
const FLAG_WILL: u8 = 1;
const FLAG_WONT: u8 = 2;
const FLAG_DO: u8 = 4;
const FLAG_DONT: u8 = 8;

// Telnet state machine states
const TELNET_DATA: u32 = 0;
const TELNET_IAC: u32 = 1;
const TELNET_DO: u32 = 2;
const TELNET_DONT: u32 = 3;
const TELNET_WILL: u32 = 4;
const TELNET_WONT: u32 = 5;
const TELNET_SB: u32 = 6;
const TELNET_SB_DATA: u32 = 7;
const TELNET_INVALID: u32 = 8;

/// Parse Telnet data using a state machine.
///
/// Processes IAC (Interpret As Command) sequences for option negotiation.
/// All bytes are appended to the banner output; IAC sequences are parsed
/// to build a WILL/WONT/DO/DONT reply.
///
/// Returns the negotiation reply bytes that should be sent back.
pub fn telnet_parse(
    _banner1: &Banner1,
    pstate: &mut StreamState,
    px: &[u8],
    length: usize,
    banout: &mut BannerOutput,
) -> Vec<u8> {
    let mut state = pstate.state;
    let mut nego = [0u8; 256];

    for offset in 0..length {
        let c = px[offset];
        banout.append_char(PROTO, c);

        match state {
            TELNET_DATA => {
                if c == 0xFF {
                    state = TELNET_IAC;
                }
            }
            TELNET_IAC => {
                match c {
                    240 | 241 | 242 | 243 | 244 | 245 | 246 | 247 | 248 | 249 => {
                        // SE, NOP, Data Mark, BRK, IP, AO, AYT, EC, EL, GA
                        state = TELNET_DATA;
                    }
                    250 => state = TELNET_SB,    // SB - subnegotiation
                    251 => state = TELNET_WILL,  // WILL
                    252 => state = TELNET_WONT,  // WONT
                    253 => state = TELNET_DO,    // DO
                    254 => state = TELNET_DONT,  // DONT
                    _ => state = TELNET_INVALID,
                }
            }
            TELNET_SB_DATA => {
                if c == 0xFF {
                    state = TELNET_IAC;
                }
            }
            TELNET_SB => {
                state = TELNET_SB_DATA;
            }
            TELNET_DO => {
                nego[c as usize] |= FLAG_WONT;
                state = TELNET_DATA;
            }
            TELNET_DONT => {
                nego[c as usize] |= FLAG_WONT;
                state = TELNET_DATA;
            }
            TELNET_WILL => {
                nego[c as usize] |= FLAG_DONT;
                state = TELNET_DATA;
            }
            TELNET_WONT => {
                nego[c as usize] |= FLAG_DONT;
                state = TELNET_DATA;
            }
            _ => break,
        }
    }

    // Build reply
    let mut reply = Vec::new();
    for i in 0..256u16 {
        if nego[i as usize] & FLAG_WILL != 0 {
            reply.push(0xFF); // IAC
            reply.push(0xFB); // WILL
            reply.push(i as u8);
        }
        if nego[i as usize] & FLAG_WONT != 0 {
            reply.push(0xFF); // IAC
            reply.push(0xFC); // WONT
            reply.push(i as u8);
        }
        if nego[i as usize] & FLAG_DO != 0 {
            reply.push(0xFF); // IAC
            reply.push(0xFD); // DO
            reply.push(i as u8);
        }
        if nego[i as usize] & FLAG_DONT != 0 {
            reply.push(0xFF); // IAC
            reply.push(0xFE); // DONT
            reply.push(i as u8);
        }
    }

    pstate.state = state;
    reply
}

/// Self-test helper: parse input and check if output contains expected string.
fn telnet_selftest_item(input: &[u8], output: &str) -> bool {
    let banner1 = Banner1::default();
    let mut pstate = StreamState::default();
    let mut banout = BannerOutput::new();

    let _ = telnet_parse(&banner1, &mut pstate, input, input.len(), &mut banout);

    banout.is_contains(PROTO, output)
}

/// Self-test for the Telnet parser.
pub fn telnet_selftest() -> bool {
    let tests: &[(&[u8], &str)] = &[
        (b"\xff\xfd\x1flogin:", "login:"),
        (b"\xff\xfd\x27\xff\xfd\x18 ", " "),
        (
            b"\xff\xfb\x25\xff\xfd\x03\xff\xfb\x18\xff\xfb\x1f\xff\xfb\x20\xff\
\xfb\x21\xff\xfb\x22\xff\xfb\x27\xff\xfd\x05\
\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f\
\xff\xfa\x18\x01\xff\xf0\
\x0d\x0a\x55\x73\x65\x72\x20\x41\x63\x63\x65\x73\x73\x20\x56\x65\
\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x0d\x0a\x0d\x0a",
            "User Access",
        ),
        (
            b"\xff\xfd\x01\xff\xfd\x1f\xff\xfd\x21\xff\xfb\x01\xff\xfb\x03\x46\
\x36\x37\x30\x0d\x0a\x0d\x4c\x6f\x67\x69\x6e\x3a\x20",
            "F670\r\n\rLogin:",
        ),
    ];

    for (input, expected) in tests {
        if !telnet_selftest_item(input, expected) {
            return false;
        }
    }
    true
}

pub fn telnet_init(_banner1: &mut Banner1) {}
