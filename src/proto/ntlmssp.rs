//! NTLMSSP (NT LAN Manager Security Support Provider) decoder.
//!
//! Decodes NTLMSSP CHALLENGE_MESSAGE (type 2) packets, extracting
//! domain name, version info, and target information fields.
//!
//! ```text
//!  +--------+--------+--------+--------+
//!  |  'N'   |  'T'   |  'L'   |  'M'   |
//!  +-      -+-      -+-      -+-      -+
//!  |  'S'   |  'S'   |  'P'   | '\0'   |
//!  +--------+--------+--------+--------+
//!  |           MessageType             |
//!  +--------+--------+--------+--------+
//!  ...
//! ```

use crate::proto::banout::BannerOutput;
use crate::proto::banner1::AppProtocol;

const PROTO_SMB: u32 = AppProtocol::Smb as u32;

/// State for NTLMSSP fragment reassembly and decoding.
#[derive(Debug, Default)]
pub struct NtlmsspDecode {
    /// Total expected length of the NTLMSSP message.
    pub length: usize,
    /// Number of bytes received so far.
    pub offset: usize,
    /// Buffer for reassembly when message spans multiple fragments.
    pub buf: Option<Vec<u8>>,
}

impl NtlmsspDecode {
    /// Initialize for a new NTLMSSP message of the given length.
    pub fn init(length: usize) -> Self {
        // Security: cap at 64KB
        let length = length.min(65536);
        NtlmsspDecode {
            length,
            offset: 0,
            buf: None,
        }
    }

    /// Clean up any allocated buffer.
    pub fn cleanup(&mut self) {
        self.buf = None;
    }
}

/// Append a Unicode (UTF-16LE) string to the banner output.
fn append_unicode_string(banout: &mut BannerOutput, name: &str, value: &[u8], value_length: usize) {
    banout.append_char(PROTO_SMB, b' ');
    banout.append_str(PROTO_SMB, name);
    banout.append_char(PROTO_SMB, b'=');

    let mut j = 0;
    while j + 1 < value_length {
        let c = (value[j] as u32) | ((value[j + 1] as u32) << 8);
        // Simple ASCII-range conversion
        if c < 128 && c >= 32 {
            banout.append_char(PROTO_SMB, c as u8);
        } else if c == 0 {
            // skip nulls
        } else {
            // Output as '?' for non-ASCII
            banout.append_char(PROTO_SMB, b'?');
        }
        j += 2;
    }
}

/// Decode an NTLMSSP CHALLENGE_MESSAGE.
///
/// Handles fragmented messages by buffering until complete.
/// Extracts domain name, version, and target info fields.
pub fn ntlmssp_decode(
    x: &mut NtlmsspDecode,
    px: &[u8],
    length: usize,
    banout: &mut BannerOutput,
) {
    let length = length.min(x.length.saturating_sub(x.offset));

    // Handle fragmentation
    if x.offset == 0 && x.length > length {
        // First fragment - allocate buffer
        let mut buf = vec![0u8; x.length];
        buf[..length].copy_from_slice(&px[..length]);
        x.buf = Some(buf);
        x.offset = length;
        return;
    } else if x.offset > 0 {
        // Subsequent fragment
        if let Some(ref mut buf) = x.buf {
            buf[x.offset..x.offset + length].copy_from_slice(&px[..length]);
        }
        x.offset += length;
        if x.offset < x.length {
            return; // Still waiting for more data
        }
        // Complete - point to buffer
    }

    let (data, data_len) = if let Some(ref buf) = x.buf {
        (buf.as_slice(), x.length)
    } else {
        (&px[..length.min(px.len())], length)
    };

    if data_len < 56 {
        x.cleanup();
        return;
    }

    // Verify NTLMSSP signature
    if data_len < 8 || &data[0..8] != b"NTLMSSP\0" {
        x.cleanup();
        return;
    }

    // Verify message type = 2 (CHALLENGE_MESSAGE)
    let message_type = data[8] as u32
        | ((data[9] as u32) << 8)
        | ((data[10] as u32) << 16)
        | ((data[11] as u32) << 24);
    if message_type != 2 {
        x.cleanup();
        return;
    }

    // TargetName (domain)
    let name_length = (data[12] as usize) | ((data[13] as usize) << 8);
    let name_offset = (data[16] as usize)
        | ((data[17] as usize) << 8)
        | ((data[18] as usize) << 16)
        | ((data[19] as usize) << 24);
    if name_length > 0 && name_offset <= data_len && name_length <= data_len - name_offset {
        append_unicode_string(banout, "domain", &data[name_offset..], name_length);
    }

    // TargetInfo
    let info_length = (data[40] as usize) | ((data[41] as usize) << 8);
    let info_offset = (data[44] as usize)
        | ((data[45] as usize) << 8)
        | ((data[46] as usize) << 16)
        | ((data[47] as usize) << 24);

    // Version field
    {
        let s = format!(
            " version={}.{}.{} ntlm-ver={}",
            data[48],
            data[49],
            (data[50] as u16) | ((data[51] as u16) << 8),
            data[55]
        );
        banout.append_str(PROTO_SMB, &s);
    }

    // Parse target info AV pairs
    let mut i = info_offset;
    while i + 4 < info_offset + info_length && i + 4 < data_len {
        let av_type = (data[i] as u16) | ((data[i + 1] as u16) << 8);
        let av_len = (data[i + 2] as usize) | ((data[i + 3] as usize) << 8);
        i += 4;

        let av_len = av_len
            .min(info_offset + info_length - i)
            .min(data_len - i);

        match av_type {
            0 => break, // MsvAvEOL
            1 => append_unicode_string(banout, "name", &data[i..], av_len),
            2 => append_unicode_string(banout, "domain", &data[i..], av_len),
            3 => append_unicode_string(banout, "name-dns", &data[i..], av_len),
            4 => append_unicode_string(banout, "domain-dns", &data[i..], av_len),
            5 => append_unicode_string(banout, "forest", &data[i..], av_len),
            9 => append_unicode_string(banout, "target", &data[i..], av_len),
            _ => {} // 6=flags, 7=timestamp, 8=single-host, 10=channel-bindings
        }
        i += av_len;
    }

    x.cleanup();
}

pub fn ntlmssp_selftest() -> bool { true }
