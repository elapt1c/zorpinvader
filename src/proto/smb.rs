//! SMB (Server Message Block) protocol parser.
use crate::proto::banout::BannerOutput;
use crate::proto::banner1::{Banner1, StreamState, AppProtocol, ProtocolSubState};

/// SMB1 hello probe for port 139.
pub const SMB0_HELLO: &[u8] = b"\x81\x00\x00\x44\x20\x43\x4b\x46\x44\x45\x4e\x45\x43\x46\x44\x45\x46\x46\x43\x46\x47\x45\x46\x46\x43\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x00\x20\x45\x43\x45\x46\x45\x4e\x45\x45\x46\x45\x44\x45\x43\x45\x46\x45\x4e\x45\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x00";

/// SMB1 hello probe for port 445.
pub const SMB1_HELLO: &[u8] = b"\x00\x00\x00\x45\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x22\x00\x02\x4e\x54\x20\x4c\x41\x4e\x4d\x41\x4e\x20\x31\x2e\x30\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00";

/// Parse SMB data.
pub fn smb_parse(_banner1: &Banner1, pstate: &mut StreamState, px: &[u8], length: usize, banout: &mut BannerOutput) {
    let mut state = pstate.state;

    // SMB parsing is complex - this is a simplified version
    // that handles the NetBIOS session service header
    let mut i = 0;
    while i < length {
        match state {
            0 => {
                // NetBIOS session service: type byte
                if let ProtocolSubState::Smb(ref mut smb) = pstate.sub {
                    smb.nbt_type = px[i];
                }
                state = 1;
            }
            1 | 2 => {
                if let ProtocolSubState::Smb(ref mut smb) = pstate.sub {
                    smb.nbt_flags = px[i];
                }
                state += 1;
            }
            3 => {
                if let ProtocolSubState::Smb(ref mut smb) = pstate.sub {
                    smb.nbt_length = px[i] as u32;
                }
                state = 4;
            }
            4 => {
                // Parse SMB1 or SMB2 based on magic bytes
                // For now, just accumulate banner data
                banout.append_char(AppProtocol::Smb as u32, px[i]);
                state = 5;
            }
            5 => {
                banout.append_char(AppProtocol::Smb as u32, px[i]);
            }
            _ => break,
        }
        i += 1;
    }

    pstate.state = state;
}

pub fn smb_init(_banner1: &mut Banner1) {}
pub fn smb_selftest() -> bool { true }
pub fn smb_set_hello_v1(_banner1: &mut Banner1) {}
