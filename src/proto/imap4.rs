//! IMAP4 protocol parser. Handles IMAP4 banners, CAPABILITY, and STARTTLS.
use crate::proto::banout::BannerOutput;
use crate::proto::banner1::{Banner1, StreamState, AppProtocol};

pub fn imap4_parse(_banner1: &Banner1, pstate: &mut StreamState, px: &[u8], length: usize, banout: &mut BannerOutput) {
    let mut state = pstate.state;
    for i in 0..length {
        if px[i] == b'\r' { continue; }
        match state {
            0 => { banout.append_char(AppProtocol::Imap4 as u32, px[i]); if px[i] == b'*' { state += 1; } else { state = 0xFFFF_FFFF; } }
            1 => { if px[i] == b' ' { banout.append_char(AppProtocol::Imap4 as u32, px[i]); } else { state = 0xFFFF_FFFF; } }
            2 => { banout.append_char(AppProtocol::Imap4 as u32, px[i]); if px[i] == b'O' { state += 1; } else { state = 0xFFFF_FFFF; } }
            3 => { banout.append_char(AppProtocol::Imap4 as u32, px[i]); if px[i] == b'K' { state += 1; } else { state = 0xFFFF_FFFF; } }
            4 => {
                if px[i] == b' ' { banout.append_char(AppProtocol::Imap4 as u32, px[i]); state += 1; }
                else if px[i] != b'\n' { banout.append_char(AppProtocol::Imap4 as u32, px[i]); }
                else { state += 1; /* fall through */ }
            }
            5 => {
                banout.append_char(AppProtocol::Imap4 as u32, px[i]);
                if px[i] == b'\n' { state = 100; }
            }
            100|300 => {
                banout.append_char(AppProtocol::Imap4 as u32, px[i]);
                if px[i] == b'*' { state += 100; }
                else if px[i] == b'a' { state += 1; }
                else { state = 0xFFFF_FFFF; }
            }
            101|301 => { banout.append_char(AppProtocol::Imap4 as u32, px[i]); if px[i] == b'0' { state += 1; } else { state = 0xFFFF_FFFF; } }
            102|302 => { banout.append_char(AppProtocol::Imap4 as u32, px[i]); if px[i] == b'0' { state += 1; } else { state = 0xFFFF_FFFF; } }
            103 => { banout.append_char(AppProtocol::Imap4 as u32, px[i]); if px[i] == b'1' { state += 1; } else { state = 0xFFFF_FFFF; } }
            303 => { banout.append_char(AppProtocol::Imap4 as u32, px[i]); if px[i] == b'2' { state += 1; } else { state = 0xFFFF_FFFF; } }
            104|304 => { banout.append_char(AppProtocol::Imap4 as u32, px[i]); if px[i] == b' ' { state += 1; } else { state = 0xFFFF_FFFF; } }
            105 => { banout.append_char(AppProtocol::Imap4 as u32, px[i]); if px[i] == b'\n' { state = 300; } }
            200|400 => { banout.append_char(AppProtocol::Imap4 as u32, px[i]); if px[i] == b'\n' { state -= 100; } }
            305 => {
                if px[i] == b'\n' {
                    let port = pstate.port;
                    *pstate = StreamState::default();
                    pstate.app_proto = AppProtocol::Ssl3 as u16;
                    pstate.is_sent_sslhello = true;
                    pstate.port = port;
                    state = 0;
                }
            }
            _ => break,
        }
    }
    pstate.state = state;
}

pub fn imap4_init(_banner1: &mut Banner1) {}
pub fn imap4_selftest() -> bool { true }
