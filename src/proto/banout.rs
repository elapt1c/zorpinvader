//! Banner Output module.
//!
//! Tracks "banners" from a connection. These are often simple strings
//! (like the FTP hello string), binary protocol data, or bulk data
//! such as BASE64-encoded X.509 certificates from SSL.
//!
//! One connection can produce multiple banners for different protocols
//! (e.g., SSL protocol info and an X.509 certificate).

/// Default inline buffer size for banner data.
const DEFAULT_BANNER_SIZE: usize = 200;

/// Sentinel value for auto-detecting string length via nul terminator.
pub const AUTO_LEN: usize = usize::MAX;

/// Base64 encoding state for streaming base64 output.
#[derive(Debug, Default, Clone)]
pub struct BannerBase64 {
    state: u8, // 0..2
    temp: u32,
}

impl BannerBase64 {
    pub fn new() -> Self {
        Self { state: 0, temp: 0 }
    }
}

/// A single banner entry in the linked list of banners.
/// Each entry tracks banner data for a specific protocol.
#[derive(Debug, Clone)]
struct BannerEntry {
    protocol: u32,
    banner: Vec<u8>,
}

/// Accumulates banner data from protocol parsers.
///
/// The first protocol's data is stored inline; additional protocols
/// cause new entries to be allocated. This mirrors the C linked-list
/// design but uses `Vec` for storage.
#[derive(Debug, Clone)]
pub struct BannerOutput {
    entries: Vec<BannerEntry>,
}

impl Default for BannerOutput {
    fn default() -> Self {
        Self::new()
    }
}

impl BannerOutput {
    /// Create a new, empty banner output.
    pub fn new() -> Self {
        BannerOutput {
            entries: Vec::new(),
        }
    }

    /// Release all banner data and reset to initial state.
    pub fn release(&mut self) {
        self.entries.clear();
    }

    /// Find the entry for the given protocol.
    /// Protocol matching uses only the lower 16 bits (matching C behavior for `banout_string`).
    fn find_entry(&self, proto: u32) -> Option<&BannerEntry> {
        self.entries.iter().find(|e| e.protocol == proto)
    }

    /// Find a mutable entry for the given protocol.
    fn find_entry_mut(&mut self, proto: u32) -> Option<&mut BannerEntry> {
        self.entries.iter_mut().find(|e| e.protocol == proto)
    }

    /// Find or create an entry for the given protocol.
    fn find_or_create_entry(&mut self, proto: u32) -> &mut BannerEntry {
        let pos = self.entries.iter().position(|e| e.protocol == proto);
        match pos {
            Some(idx) => &mut self.entries[idx],
            None => {
                self.entries.push(BannerEntry {
                    protocol: proto,
                    banner: Vec::with_capacity(DEFAULT_BANNER_SIZE),
                });
                self.entries.last_mut().unwrap()
            }
        }
    }

    /// Append raw bytes to the banner for the given protocol.
    ///
    /// If `length` is `AUTO_LEN`, the length is determined by treating `px`
    /// as a C string (up to the first nul byte).
    pub fn append(&mut self, proto: u32, px: &[u8], length: usize) {
        let data = if length == AUTO_LEN {
            // Find nul terminator or use entire slice
            let end = px.iter().position(|&b| b == 0).unwrap_or(px.len());
            &px[..end]
        } else {
            &px[..length.min(px.len())]
        };

        let entry = self.find_or_create_entry(proto);
        entry.banner.extend_from_slice(data);
    }

    /// Append a single character to the banner.
    pub fn append_char(&mut self, proto: u32, c: u8) {
        let entry = self.find_or_create_entry(proto);
        entry.banner.push(c);
    }

    /// Append a formatted string to the banner.
    pub fn append_str(&mut self, proto: u32, s: &str) {
        let entry = self.find_or_create_entry(proto);
        entry.banner.extend_from_slice(s.as_bytes());
    }

    /// Append a newline if the banner for this protocol already has content.
    pub fn newline(&mut self, proto: u32) {
        let has_content = self.find_entry(proto).map_or(false, |e| !e.banner.is_empty());
        if has_content {
            self.append_char(proto, b'\n');
        }
    }

    /// End the banner for the current protocol by setting the high bit.
    /// This signals that the banner is complete (used for SSL certificates).
    pub fn end(&mut self, proto: u32) {
        if let Some(entry) = self.find_entry_mut(proto) {
            if !entry.banner.is_empty() {
                entry.protocol |= 0x8000_0000;
            }
        }
    }

    /// Append a hex integer with the specified number of digits.
    /// If digits is 0, the minimum number of digits needed is used.
    pub fn append_hexint(&mut self, proto: u32, number: u64, mut digits: i32) {
        if digits == 0 {
            digits = 16;
            while digits > 0 {
                if (number >> ((digits - 1) * 4)) & 0xF != 0 {
                    break;
                }
                digits -= 1;
            }
        }

        while digits > 0 {
            let nibble = ((number >> ((digits - 1) * 4)) & 0xF) as usize;
            let c = b"0123456789abcdef"[nibble];
            self.append_char(proto, c);
            digits -= 1;
        }
    }

    /// Append a Unicode codepoint, encoding as UTF-8.
    pub fn append_unicode(&mut self, proto: u32, c: u32) {
        if c > 0xFFFF {
            self.append_char(proto, (0xF0 | ((c >> 18) & 0x03)) as u8);
            self.append_char(proto, (0x80 | ((c >> 12) & 0x3F)) as u8);
            self.append_char(proto, (0x80 | ((c >> 6) & 0x3F)) as u8);
            self.append_char(proto, (0x80 | (c & 0x3F)) as u8);
        } else if c > 0x7FF {
            self.append_char(proto, (0xE0 | ((c >> 12) & 0x0F)) as u8);
            self.append_char(proto, (0x80 | ((c >> 6) & 0x3F)) as u8);
            self.append_char(proto, (0x80 | (c & 0x3F)) as u8);
        } else if c > 0x7F {
            self.append_char(proto, (0xC0 | ((c >> 6) & 0x1F)) as u8);
            self.append_char(proto, (0x80 | (c & 0x3F)) as u8);
        } else {
            self.append_char(proto, c as u8);
        }
    }

    /// Get the banner string for a given protocol.
    /// Protocol matching uses lower 16 bits.
    pub fn string(&self, proto: u32) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|e| (e.protocol & 0xFFFF) == proto)
            .map(|e| e.banner.as_slice())
    }

    /// Get the length of the banner for a given protocol (exact match).
    pub fn string_length(&self, proto: u32) -> usize {
        self.find_entry(proto)
            .map_or(0, |e| e.banner.len())
    }

    /// Compare the banner string for a protocol to a fixed string.
    pub fn is_equal(&self, proto: u32, s: &str) -> bool {
        match self.string(proto) {
            None => s.is_empty(),
            Some(banner) => banner == s.as_bytes(),
        }
    }

    /// Check if the banner for a protocol contains the given string.
    pub fn is_contains(&self, proto: u32, s: &str) -> bool {
        match self.string(proto) {
            None => s.is_empty(),
            Some(banner) => {
                let needle = s.as_bytes();
                if needle.len() > banner.len() {
                    return false;
                }
                banner
                    .windows(needle.len())
                    .any(|window| window == needle)
            }
        }
    }

    /// Initialize base64 encoding state.
    pub fn init_base64(base64: &mut BannerBase64) {
        base64.state = 0;
        base64.temp = 0;
    }

    const B64_CHARS: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Append data as base64-encoded text to the banner.
    /// Must call `init_base64` before the first fragment and
    /// `finalize_base64` after the last fragment.
    pub fn append_base64(
        &mut self,
        proto: u32,
        px: &[u8],
        base64: &mut BannerBase64,
    ) {
        let mut x = base64.temp;
        let mut state = base64.state;

        for &byte in px {
            match state {
                0 => {
                    x = (byte as u32) << 16;
                    state = 1;
                }
                1 => {
                    x |= (byte as u32) << 8;
                    state = 2;
                }
                2 => {
                    x |= byte as u32;
                    state = 0;
                    self.append_char(proto, Self::B64_CHARS[((x >> 18) & 0x3F) as usize]);
                    self.append_char(proto, Self::B64_CHARS[((x >> 12) & 0x3F) as usize]);
                    self.append_char(proto, Self::B64_CHARS[((x >> 6) & 0x3F) as usize]);
                    self.append_char(proto, Self::B64_CHARS[(x & 0x3F) as usize]);
                }
                _ => unreachable!(),
            }
        }

        base64.temp = x;
        base64.state = state;
    }

    /// Finalize base64 encoding, appending padding characters as needed.
    pub fn finalize_base64(
        &mut self,
        proto: u32,
        base64: &BannerBase64,
    ) {
        let x = base64.temp;
        match base64.state {
            0 => {}
            1 => {
                self.append_char(proto, Self::B64_CHARS[((x >> 18) & 0x3F) as usize]);
                self.append_char(proto, Self::B64_CHARS[((x >> 12) & 0x3F) as usize]);
                self.append_char(proto, b'=');
                self.append_char(proto, b'=');
            }
            2 => {
                self.append_char(proto, Self::B64_CHARS[((x >> 18) & 0x3F) as usize]);
                self.append_char(proto, Self::B64_CHARS[((x >> 12) & 0x3F) as usize]);
                self.append_char(proto, Self::B64_CHARS[((x >> 6) & 0x3F) as usize]);
                self.append_char(proto, b'=');
            }
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_append() {
        let mut banout = BannerOutput::new();

        for _ in 0..10 {
            banout.append(1, b"xxxx", 4);
            banout.append(2, b"yyyyy", 5);
        }

        assert_eq!(banout.string_length(1), 40);
        assert_eq!(banout.string_length(2), 50);
    }

    #[test]
    fn test_base64_encoding() {
        let mut banout = BannerOutput::new();

        // 1 byte
        let mut base64 = BannerBase64::new();
        banout.append_base64(1, b"x", &mut base64);
        banout.finalize_base64(1, &base64);
        assert!(banout.is_equal(1, "eA=="));

        // 2 bytes
        let mut base64 = BannerBase64::new();
        banout.append_base64(2, b"bc", &mut base64);
        banout.finalize_base64(2, &base64);
        assert!(banout.is_equal(2, "YmM="));

        // 3 bytes
        let mut base64 = BannerBase64::new();
        banout.append_base64(3, b"mno", &mut base64);
        banout.finalize_base64(3, &base64);
        assert!(banout.is_equal(3, "bW5v"));

        // 4 bytes
        let mut base64 = BannerBase64::new();
        banout.append_base64(4, b"stuv", &mut base64);
        banout.finalize_base64(4, &base64);
        assert!(banout.is_equal(4, "c3R1dg=="));

        // 5 bytes
        let mut base64 = BannerBase64::new();
        banout.append_base64(5, b"fghij", &mut base64);
        banout.finalize_base64(5, &base64);
        assert!(banout.is_equal(5, "ZmdoaWo="));
    }

    #[test]
    fn test_release() {
        let mut banout = BannerOutput::new();
        banout.append(1, b"test", 4);
        assert_eq!(banout.string_length(1), 4);
        banout.release();
        assert_eq!(banout.string_length(1), 0);
    }

    #[test]
    fn test_is_contains() {
        let mut banout = BannerOutput::new();
        banout.append(1, b"hello world", 11);
        assert!(banout.is_contains(1, "world"));
        assert!(!banout.is_contains(1, "xyz"));
    }

    #[test]
    fn test_append_unicode() {
        let mut banout = BannerOutput::new();
        // ASCII
        banout.append_unicode(1, b'A' as u32);
        assert!(banout.is_equal(1, "A"));
    }
}
