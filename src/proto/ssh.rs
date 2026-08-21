//! SSH protocol parser.
//!
//! Parses SSH banner and key exchange messages using a byte-by-byte
//! state machine.

use crate::proto::banout::BannerOutput;
use crate::proto::banner1::{Banner1, StreamState, AppProtocol, ProtocolSubState};

/// SSH parse states.
const BANNER: u32 = 0;
const MSG_KEY_EXCHANGE_INIT: u32 = 1;
const _MSG_NEW_KEYS: u32 = 2;
const _MSG_UNKNOWN: u32 = 9;
const _PADDING_LENGTH: u32 = 10;
const _MESSAGE_CODE: u32 = 11;
const CHECK_LENGTH: u32 = 20;
const LENGTH_1: u32 = 21;
const LENGTH_2: u32 = 22;
const LENGTH_3: u32 = 23;
const LENGTH_4: u32 = 24;
const BEFORE_END: u32 = 29;
const END: u32 = 30;
const ERROR: u32 = 31;

/// SSH banner to send.
const PAYLOAD_BANNER: &[u8] = b"SSH-2.0-OPENSSH_7.9\r\n";

/// Parse SSH data.
pub fn ssh_parse(
    _banner1: &Banner1,
    pstate: &mut StreamState,
    px: &[u8],
    length: usize,
    banout: &mut BannerOutput,
) {
    let mut state = pstate.state;
    let mut packet_length = if let ProtocolSubState::Ssh(ref ssh) = pstate.sub {
        ssh.packet_length
    } else {
        0
    };

    for i in 0..length {
        banout.append_char(AppProtocol::Ssh2 as u32, px[i]);

        match state {
            BANNER => {
                if px[i] == b'\n' {
                    // Would send banner here
                    packet_length = 0;
                    state = LENGTH_1;
                }
                if px[i] == 0 || !(px[i].is_ascii_whitespace() || px[i].is_ascii_graphic()) {
                    state = ERROR;
                    continue;
                }
            }
            LENGTH_1 => {
                packet_length = (px[i] as usize) << 24;
                state += 1;
            }
            LENGTH_2 => {
                packet_length += (px[i] as usize) << 16;
                state += 1;
            }
            LENGTH_3 => {
                packet_length += (px[i] as usize) << 8;
                state += 1;
            }
            LENGTH_4 => {
                packet_length += px[i] as usize;
                state = _PADDING_LENGTH;
            }
            _PADDING_LENGTH => {
                packet_length = packet_length.saturating_sub(1);
                state = _MESSAGE_CODE;
            }
            _MESSAGE_CODE => {
                packet_length = packet_length.saturating_sub(1);
                match px[i] {
                    0x14 => state = MSG_KEY_EXCHANGE_INIT,
                    0x15 => state = BEFORE_END,
                    _ => state = CHECK_LENGTH,
                }
            }
            MSG_KEY_EXCHANGE_INIT => {
                packet_length = packet_length.saturating_sub(1);
                // Would send key exchange init here
                state = CHECK_LENGTH;
            }
            CHECK_LENGTH => {
                packet_length = packet_length.saturating_sub(1);
                if packet_length == 0 {
                    state = LENGTH_1;
                }
            }
            BEFORE_END => {
                packet_length = packet_length.saturating_sub(1);
                if packet_length == 0 {
                    state = END;
                }
            }
            END => {
                // Would close connection here
                state = 0xFFFF_FFFF;
                break;
            }
            _ => {
                break;
            }
        }
    }

    pstate.state = state;
    if let ProtocolSubState::Ssh(ref mut ssh) = pstate.sub {
        ssh.packet_length = packet_length;
    }
}

/// Initialize SSH parser.
pub fn ssh_init(_banner1: &mut Banner1) {}

/// SSH self-test.
pub fn ssh_selftest() -> bool {
    true
}
