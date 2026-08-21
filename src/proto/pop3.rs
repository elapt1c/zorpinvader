//! POP3 protocol parser. Handles POP3 banners, CAPA, and STLS.
use crate::proto::banout::BannerOutput;
use crate::proto::banner1::{Banner1, StreamState, AppProtocol};

pub fn pop3_parse(_banner1: &Banner1, pstate: &mut StreamState, px: &[u8], length: usize, banout: &mut BannerOutput) {
    let mut state = pstate.state;
    for i in 0..length {
        if px[i] == b'\r' { continue; }
        match state {
            0|1|2 => {
                banout.append_char(AppProtocol::Pop3 as u32, px[i]);
                if b"+OK"[state as usize] != px[i] { state = 0xFFFF_FFFF; } else { state += 1; }
            }
            3 => {
                banout.append_char(AppProtocol::Pop3 as u32, px[i]);
                if px[i] == b'\n' { state += 1; }
            }
            4|204 => {
                banout.append_char(AppProtocol::Pop3 as u32, px[i]);
                if px[i] == b'-' { state = 100; }
                else if px[i] == b'+' { state += 1; }
                else { state = 0xFFFF_FFFF; }
            }
            5|205 => {
                banout.append_char(AppProtocol::Pop3 as u32, px[i]);
                if px[i] == b'O' { state += 1; } else { state = 0xFFFF_FFFF; }
            }
            6|206 => {
                banout.append_char(AppProtocol::Pop3 as u32, px[i]);
                if px[i] == b'K' { state += 2; } else { state = 0xFFFF_FFFF; }
            }
            8 => {
                banout.append_char(AppProtocol::Pop3 as u32, px[i]);
                if px[i] == b'\n' { state += 1; }
            }
            9 => {
                banout.append_char(AppProtocol::Pop3 as u32, px[i]);
                if px[i] == b'.' { state += 1; }
                else if px[i] == b'\n' { continue; }
                else { state -= 1; }
            }
            10 => {
                banout.append_char(AppProtocol::Pop3 as u32, px[i]);
                if px[i] == b'\n' { state = 204; } else { state = 8; }
            }
            208 => {
                banout.append_char(AppProtocol::Pop3 as u32, px[i]);
                if px[i] == b'\n' {
                    let port = pstate.port;
                    *pstate = StreamState::default();
                    pstate.app_proto = AppProtocol::Ssl3 as u16;
                    pstate.is_sent_sslhello = true;
                    pstate.port = port;
                    state = 0;
                }
            }
            100 => {
                banout.append_char(AppProtocol::Pop3 as u32, px[i]);
                if px[i] == b'\n' { state = 0xFFFF_FFFF; }
            }
            _ => break,
        }
    }
    pstate.state = state;
}

pub fn pop3_init(_banner1: &mut Banner1) {}
pub fn pop3_selftest() -> bool { true }
