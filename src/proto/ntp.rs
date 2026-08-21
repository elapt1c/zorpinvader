//! NTP protocol handler.
use crate::proto::banout::BannerOutput;
use crate::proto::preprocess::PreprocessedInfo;
use crate::proto::banner1::AppProtocol;

/// Set NTP cookie (NTP doesn't use cookies).
pub fn ntp_set_cookie(_px: &mut [u8], _length: usize, _seqno: u64) -> u32 { 0 }

/// Handle NTP response.
pub fn ntp_handle_response(px: &[u8], _length: usize, parsed: &PreprocessedInfo, banout: &mut BannerOutput) -> bool {
    let offset = parsed.app_offset as usize;
    let app_length = parsed.app_length as usize;
    if app_length < 4 || offset + app_length > px.len() { return false; }

    let version = (px[offset] >> 3) & 7;
    if version != 2 { return false; }

    let mode = px[offset] & 7;
    match mode {
        6 => {} // control
        7 => {
            // Private mode
            let implementation = px[offset + 2];
            match implementation {
                0 => banout.append_str(AppProtocol::Ntp as u32, "UNIV"),
                2 => banout.append_str(AppProtocol::Ntp as u32, "XNTPD-OLD"),
                3 => banout.append_str(AppProtocol::Ntp as u32, "XNTPD"),
                _ => {}
            }
        }
        _ => {}
    }
    true
}

pub fn ntp_selftest() -> bool { true }
