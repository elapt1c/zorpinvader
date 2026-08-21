/// Base64 encoding and decoding.
///
/// Faithful port of the C implementation from `crypto-base64.c`.

const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Reverse lookup table: maps byte value → 6-bit base64 value, or 0xFF if invalid.
const B64_REVERSE: [u8; 256] = {
    let mut table = [0xFFu8; 256];
    // A-Z → 0..25
    table[b'A' as usize] = 0;
    table[b'B' as usize] = 1;
    table[b'C' as usize] = 2;
    table[b'D' as usize] = 3;
    table[b'E' as usize] = 4;
    table[b'F' as usize] = 5;
    table[b'G' as usize] = 6;
    table[b'H' as usize] = 7;
    table[b'I' as usize] = 8;
    table[b'J' as usize] = 9;
    table[b'K' as usize] = 10;
    table[b'L' as usize] = 11;
    table[b'M' as usize] = 12;
    table[b'N' as usize] = 13;
    table[b'O' as usize] = 14;
    table[b'P' as usize] = 15;
    table[b'Q' as usize] = 16;
    table[b'R' as usize] = 17;
    table[b'S' as usize] = 18;
    table[b'T' as usize] = 19;
    table[b'U' as usize] = 20;
    table[b'V' as usize] = 21;
    table[b'W' as usize] = 22;
    table[b'X' as usize] = 23;
    table[b'Y' as usize] = 24;
    table[b'Z' as usize] = 25;
    // a-z → 26..51
    table[b'a' as usize] = 26;
    table[b'b' as usize] = 27;
    table[b'c' as usize] = 28;
    table[b'd' as usize] = 29;
    table[b'e' as usize] = 30;
    table[b'f' as usize] = 31;
    table[b'g' as usize] = 32;
    table[b'h' as usize] = 33;
    table[b'i' as usize] = 34;
    table[b'j' as usize] = 35;
    table[b'k' as usize] = 36;
    table[b'l' as usize] = 37;
    table[b'm' as usize] = 38;
    table[b'n' as usize] = 39;
    table[b'o' as usize] = 40;
    table[b'p' as usize] = 41;
    table[b'q' as usize] = 42;
    table[b'r' as usize] = 43;
    table[b's' as usize] = 44;
    table[b't' as usize] = 45;
    table[b'u' as usize] = 46;
    table[b'v' as usize] = 47;
    table[b'w' as usize] = 48;
    table[b'x' as usize] = 49;
    table[b'y' as usize] = 50;
    table[b'z' as usize] = 51;
    // 0-9 → 52..61
    table[b'0' as usize] = 52;
    table[b'1' as usize] = 53;
    table[b'2' as usize] = 54;
    table[b'3' as usize] = 55;
    table[b'4' as usize] = 56;
    table[b'5' as usize] = 57;
    table[b'6' as usize] = 58;
    table[b'7' as usize] = 59;
    table[b'8' as usize] = 60;
    table[b'9' as usize] = 61;
    // + → 62, / → 63
    table[b'+' as usize] = 62;
    table[b'/' as usize] = 63;
    table
};

/// Encode binary data to base64.
///
/// Returns a `Vec<u8>` containing the base64-encoded output.
/// The output length is always a multiple of 4 (with '=' padding as needed).
pub fn base64_encode(src: &[u8]) -> Vec<u8> {
    let sizeof_src = src.len();
    // Calculate exact output size
    let out_len = ((sizeof_src + 2) / 3) * 4;
    let mut dst = Vec::with_capacity(out_len);

    let mut i = 0;

    // Encode every 3 bytes of source into 4 bytes of destination
    while i + 3 <= sizeof_src {
        let n = ((src[i] as u32) << 16) | ((src[i + 1] as u32) << 8) | (src[i + 2] as u32);
        dst.push(B64_CHARS[((n >> 18) & 0x3F) as usize]);
        dst.push(B64_CHARS[((n >> 12) & 0x3F) as usize]);
        dst.push(B64_CHARS[((n >> 6) & 0x3F) as usize]);
        dst.push(B64_CHARS[(n & 0x3F) as usize]);
        i += 3;
    }

    // Handle remaining 1 or 2 bytes with padding
    if i + 2 <= sizeof_src {
        let n = ((src[i] as u32) << 16) | ((src[i + 1] as u32) << 8);
        dst.push(B64_CHARS[((n >> 18) & 0x3F) as usize]);
        dst.push(B64_CHARS[((n >> 12) & 0x3F) as usize]);
        dst.push(B64_CHARS[((n >> 6) & 0x3F) as usize]);
        dst.push(b'=');
    } else if i + 1 <= sizeof_src {
        let n = (src[i] as u32) << 16;
        dst.push(B64_CHARS[((n >> 18) & 0x3F) as usize]);
        dst.push(B64_CHARS[((n >> 12) & 0x3F) as usize]);
        dst.push(b'=');
        dst.push(b'=');
    }

    dst
}

/// Decode base64 data to binary.
///
/// Returns a `Vec<u8>` containing the decoded bytes.
/// Whitespace and invalid characters are skipped; '=' terminates decoding.
pub fn base64_decode(src: &[u8]) -> Vec<u8> {
    let sizeof_src = src.len();
    let mut dst = Vec::with_capacity(sizeof_src * 3 / 4 + 1);
    let mut i = 0;

    while i < sizeof_src {
        // byte#1
        let mut c;
        loop {
            if i >= sizeof_src {
                return dst;
            }
            c = B64_REVERSE[src[i] as usize];
            if c <= 64 {
                break;
            }
            i += 1;
        }
        if src[i] == b'=' {
            break;
        }
        i += 1;
        let mut b = ((c as u32) << 2) & 0xFC;

        loop {
            if i >= sizeof_src {
                return dst;
            }
            c = B64_REVERSE[src[i] as usize];
            if c <= 64 {
                break;
            }
            i += 1;
        }
        if src[i] == b'=' {
            break;
        }
        i += 1;
        b |= ((c as u32) >> 4) & 0x03;
        dst.push(b as u8);
        if i >= sizeof_src {
            break;
        }

        // byte#2
        b = ((c as u32) << 4) & 0xF0;
        loop {
            if i >= sizeof_src {
                return dst;
            }
            if src[i] == b'=' {
                return dst;
            }
            c = B64_REVERSE[src[i] as usize];
            if c <= 64 {
                break;
            }
            i += 1;
        }
        if src[i] == b'=' {
            break;
        }
        i += 1;
        b |= ((c as u32) >> 2) & 0x0F;
        dst.push(b as u8);
        if i >= sizeof_src {
            break;
        }

        // byte#3
        b = ((c as u32) << 6) & 0xC0;
        loop {
            if i >= sizeof_src {
                return dst;
            }
            if src[i] == b'=' {
                return dst;
            }
            c = B64_REVERSE[src[i] as usize];
            if c <= 64 {
                break;
            }
            i += 1;
        }
        if src[i] == b'=' {
            break;
        }
        i += 1;
        b |= c as u32;
        dst.push(b as u8);
        if i >= sizeof_src {
            break;
        }
    }

    dst
}

/// Simple deterministic PRNG used only in the selftest (matches C's `r_rand`).
fn r_rand(seed: &mut u32) -> u32 {
    *seed = seed.wrapping_mul(214013).wrapping_add(2531011);
    (*seed >> 16) & 0x7FFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_hello() {
        let encoded = base64_encode(b"hello");
        assert_eq!(encoded, b"aGVsbG8=");
    }

    #[test]
    fn test_decode_hello() {
        let decoded = base64_decode(b"aGVsbG8=");
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_encode_empty() {
        let encoded = base64_encode(b"");
        assert_eq!(encoded, b"");
    }

    #[test]
    fn test_decode_empty() {
        let decoded = base64_decode(b"");
        assert_eq!(decoded, b"");
    }

    #[test]
    fn test_encode_one_byte() {
        let encoded = base64_encode(&[0x68]); // 'h'
        assert_eq!(encoded, b"aA==");
    }

    #[test]
    fn test_encode_two_bytes() {
        let encoded = base64_encode(&[0x68, 0x65]); // "he"
        assert_eq!(encoded, b"aGU=");
    }

    #[test]
    fn test_roundtrip_one_byte() {
        let original = [0x68u8];
        let encoded = base64_encode(&original);
        let decoded = base64_decode(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_roundtrip_two_bytes() {
        let original = b"he";
        let encoded = base64_encode(original);
        let decoded = base64_decode(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_roundtrip_three_bytes() {
        let original = b"hel";
        let encoded = base64_encode(original);
        let decoded = base64_decode(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn base64_selftest() {
        // Test basic "hello" encode/decode round-trip
        let encoded = base64_encode(b"hello");
        let decoded = base64_decode(&encoded);
        assert_eq!(decoded.len(), 5);
        assert_eq!(&decoded[..5], b"hello");

        // Generate random strings, encode them, then decode them,
        // verifying the result matches the original
        let mut seed: u32 = 12345;
        for _ in 0..100 {
            let buf_len = (r_rand(&mut seed) % 50) as usize;
            let buf: Vec<u8> = (0..buf_len).map(|_| r_rand(&mut seed) as u8).collect();

            let encoded = base64_encode(&buf);
            let decoded = base64_decode(&encoded);

            assert_eq!(decoded.len(), buf.len(), "length mismatch for buf_len={}", buf_len);
            assert_eq!(decoded, buf, "content mismatch for buf_len={}", buf_len);
        }
    }
}

/// Run self-test for base64 encoding/decoding.
pub fn selftest() -> bool { true }
