//! Minecraft protocol parser.
//!
//! Parses the Minecraft server list ping response (JSON), stripping
//! embedded base64-encoded PNG favicon data to reduce banner size.

use crate::proto::banout::BannerOutput;
use crate::proto::banner1::{Banner1, StreamState, AppProtocol, ProtocolSubState};

const PROTO: u32 = AppProtocol::Mc as u32;

/// Build a Minecraft handshake packet for the given port and IP.
fn hand_shake(port: u16, ip: &[u8]) -> Vec<u8> {
    let ip_len = ip.len();
    let tlen = 10 + ip_len;
    let mut ret = vec![0u8; tlen];
    ret[0] = (7 + ip_len) as u8;
    // ret[1] = 0 (already zeroed)
    ret[2] = 0xf7;
    ret[3] = 5;
    ret[4] = ip_len as u8;
    ret[5..5 + ip_len].copy_from_slice(ip);
    ret[tlen - 5] = (port >> 8) as u8;
    ret[tlen - 4] = (port & 0xFF) as u8;
    ret[tlen - 3] = 1;
    ret[tlen - 2] = 1;
    ret[tlen - 1] = 0;
    ret
}

/// Search for a byte subsequence in a buffer (like memmem).
fn mem_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Parse Minecraft server response data.
///
/// Tracks bracket depth to detect JSON completion. Strips base64-encoded
/// PNG favicon data (`data:image/png;base64...`) from the response to
/// keep banners small.
pub fn mc_parse(
    _banner1: &Banner1,
    pstate: &mut StreamState,
    px: &[u8],
    length: usize,
    banout: &mut BannerOutput,
) {
    let (mut ban_mem, mut total_len, mut img_start, mut img_end, mut brackcount) =
        if let ProtocolSubState::Mc(ref mc) = pstate.sub {
            (mc.ban_mem.clone(), mc.total_len, mc.img_start, mc.img_end, mc.bracket_count)
        } else {
            (Vec::new(), 0usize, 0usize, 0usize, 0i32)
        };

    // Count brackets to detect JSON completion
    for i in 0..length {
        if px[i] == b'{' {
            brackcount += 1;
        }
        if px[i] == b'}' {
            brackcount -= 1;
        }
    }

    if (img_start != 0 && img_end != 0) || brackcount <= 0 {
        // Already stripped image data, or JSON complete - output directly
        banout.append(PROTO, px, length);
    } else {
        // Accumulate data
        ban_mem.extend_from_slice(&px[..length]);
        total_len += length;

        if img_start == 0 {
            // Search for start of favicon data
            let needle = b"data:image/png;base64";
            if let Some(pos) = mem_find(&ban_mem, needle) {
                img_start = pos;
            }
        } else {
            // We found the start, now look for the closing quote
            if let Some(pos) = ban_mem[img_start..total_len].iter().position(|&b| b == b'"') {
                img_end = img_start + pos;
                // Copy data after the base64 block over the image data
                let after_len = total_len - img_end;
                ban_mem.copy_within(img_end..total_len, img_start);
                total_len = img_start + after_len;
                ban_mem.truncate(total_len);

                // Output the cleaned banner
                banout.append(PROTO, &ban_mem, total_len);

                // Reset - no longer tracking image
                img_start = 0;
                img_end = 0;
            }
        }
    }

    // Save state back
    if let ProtocolSubState::Mc(ref mut mc) = pstate.sub {
        mc.ban_mem = ban_mem;
        mc.total_len = total_len;
        mc.img_start = img_start;
        mc.img_end = img_end;
        mc.bracket_count = brackcount;
    }
}

pub fn mc_init(_banner1: &mut Banner1) {
    // Pre-build handshake packet; in the C code this is stored globally.
    // The Rust architecture handles this differently via ProtocolParserStream.hello
    let _ = hand_shake(25565, b"localhost");
}

pub fn mc_selftest() -> bool { true }
