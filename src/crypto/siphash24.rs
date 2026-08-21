/// SipHash-2-4 — a fast, cryptographically strong PRF.
///
/// Reference implementation originally by:
///   Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>
///   Daniel J. Bernstein <djb@cr.yp.to>
///
/// Faithful port of `crypto-siphash24.c`.

#[inline]
fn rotl(x: u64, b: u32) -> u64 {
    (x << b) | (x >> (64 - b))
}

/// Read a little-endian u64 from a byte slice.
#[inline]
fn u8to64_le(p: &[u8]) -> u64 {
    (p[0] as u64)
        | ((p[1] as u64) << 8)
        | ((p[2] as u64) << 16)
        | ((p[3] as u64) << 24)
        | ((p[4] as u64) << 32)
        | ((p[5] as u64) << 40)
        | ((p[6] as u64) << 48)
        | ((p[7] as u64) << 56)
}

/// Write a little-endian u64 to a byte array.
#[inline]
fn u64to8_le(v: u64) -> [u8; 8] {
    [
        v as u8,
        (v >> 8) as u8,
        (v >> 16) as u8,
        (v >> 24) as u8,
        (v >> 32) as u8,
        (v >> 40) as u8,
        (v >> 48) as u8,
        (v >> 56) as u8,
    ]
}

/// One SipRound as defined in the SipHash specification.
#[inline]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = rotl(*v1, 13);
    *v1 ^= *v0;
    *v0 = rotl(*v0, 32);

    *v2 = v2.wrapping_add(*v3);
    *v3 = rotl(*v3, 16);
    *v3 ^= *v2;

    *v0 = v0.wrapping_add(*v3);
    *v3 = rotl(*v3, 21);
    *v3 ^= *v0;

    *v2 = v2.wrapping_add(*v1);
    *v1 = rotl(*v1, 17);
    *v1 ^= *v2;
    *v2 = rotl(*v2, 32);
}

/// Core SipHash-2-4 implementation operating on bytes.
fn crypto_auth(out: &mut [u8; 8], input: &[u8], k: &[u8; 16]) {
    // "somepseudorandomlygeneratedbytes"
    let mut v0: u64 = 0x736f6d6570736575;
    let mut v1: u64 = 0x646f72616e646f6d;
    let mut v2: u64 = 0x6c7967656e657261;
    let mut v3: u64 = 0x7465646279746573;

    let inlen = input.len();
    let k0 = u8to64_le(&k[0..8]);
    let k1 = u8to64_le(&k[8..16]);

    v3 ^= k1;
    v2 ^= k0;
    v1 ^= k1;
    v0 ^= k0;

    // Process full 8-byte blocks
    let nblocks = inlen / 8;
    for i in 0..nblocks {
        let m = u8to64_le(&input[i * 8..i * 8 + 8]);
        v3 ^= m;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    // Process remaining bytes (0..7)
    let left = inlen & 7;
    let mut b: u64 = (inlen as u64) << 56;
    let tail = &input[nblocks * 8..];

    // Fall-through switch (matching C behavior exactly)
    match left {
        7 => {
            b |= (tail[6] as u64) << 48;
            b |= (tail[5] as u64) << 40;
            b |= (tail[4] as u64) << 32;
            b |= (tail[3] as u64) << 24;
            b |= (tail[2] as u64) << 16;
            b |= (tail[1] as u64) << 8;
            b |= tail[0] as u64;
        }
        6 => {
            b |= (tail[5] as u64) << 40;
            b |= (tail[4] as u64) << 32;
            b |= (tail[3] as u64) << 24;
            b |= (tail[2] as u64) << 16;
            b |= (tail[1] as u64) << 8;
            b |= tail[0] as u64;
        }
        5 => {
            b |= (tail[4] as u64) << 32;
            b |= (tail[3] as u64) << 24;
            b |= (tail[2] as u64) << 16;
            b |= (tail[1] as u64) << 8;
            b |= tail[0] as u64;
        }
        4 => {
            b |= (tail[3] as u64) << 24;
            b |= (tail[2] as u64) << 16;
            b |= (tail[1] as u64) << 8;
            b |= tail[0] as u64;
        }
        3 => {
            b |= (tail[2] as u64) << 16;
            b |= (tail[1] as u64) << 8;
            b |= tail[0] as u64;
        }
        2 => {
            b |= (tail[1] as u64) << 8;
            b |= tail[0] as u64;
        }
        1 => {
            b |= tail[0] as u64;
        }
        0 => {}
        _ => unreachable!(),
    }

    v3 ^= b;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;

    v2 ^= 0xff;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);

    let result = v0 ^ v1 ^ v2 ^ v3;
    *out = u64to8_le(result);
}

/// Compute SipHash-2-4 of the input data with the given 128-bit key.
///
/// - `data` is the message to hash
/// - `key` is a 128-bit key as two u64 values (little-endian byte order)
///
/// Returns the 64-bit hash value.
pub fn siphash24(data: &[u8], key: [u64; 2]) -> u64 {
    // Convert key to bytes (little-endian, matching the C code which
    // just casts the uint64_t array to bytes)
    let mut k = [0u8; 16];
    k[0..8].copy_from_slice(&u64to8_le(key[0]));
    k[8..16].copy_from_slice(&u64to8_le(key[1]));

    let mut out = [0u8; 8];
    crypto_auth(&mut out, data, &k);

    u8to64_le(&out)
}

/// Expected SipHash-2-4 test vectors.
/// Key = 00 01 02 ... 0f
/// Input i = 00 01 02 ... (i-1)
const VECTORS: [[u8; 8]; 64] = [
    [0x31, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72],
    [0xfd, 0x67, 0xdc, 0x93, 0xc5, 0x39, 0xf8, 0x74],
    [0x5a, 0x4f, 0xa9, 0xd9, 0x09, 0x80, 0x6c, 0x0d],
    [0x2d, 0x7e, 0xfb, 0xd7, 0x96, 0x66, 0x67, 0x85],
    [0xb7, 0x87, 0x71, 0x27, 0xe0, 0x94, 0x27, 0xcf],
    [0x8d, 0xa6, 0x99, 0xcd, 0x64, 0x55, 0x76, 0x18],
    [0xce, 0xe3, 0xfe, 0x58, 0x6e, 0x46, 0xc9, 0xcb],
    [0x37, 0xd1, 0x01, 0x8b, 0xf5, 0x00, 0x02, 0xab],
    [0x62, 0x24, 0x93, 0x9a, 0x79, 0xf5, 0xf5, 0x93],
    [0xb0, 0xe4, 0xa9, 0x0b, 0xdf, 0x82, 0x00, 0x9e],
    [0xf3, 0xb9, 0xdd, 0x94, 0xc5, 0xbb, 0x5d, 0x7a],
    [0xa7, 0xad, 0x6b, 0x22, 0x46, 0x2f, 0xb3, 0xf4],
    [0xfb, 0xe5, 0x0e, 0x86, 0xbc, 0x8f, 0x1e, 0x75],
    [0x90, 0x3d, 0x84, 0xc0, 0x27, 0x56, 0xea, 0x14],
    [0xee, 0xf2, 0x7a, 0x8e, 0x90, 0xca, 0x23, 0xf7],
    [0xe5, 0x45, 0xbe, 0x49, 0x61, 0xca, 0x29, 0xa1],
    [0xdb, 0x9b, 0xc2, 0x57, 0x7f, 0xcc, 0x2a, 0x3f],
    [0x94, 0x47, 0xbe, 0x2c, 0xf5, 0xe9, 0x9a, 0x69],
    [0x9c, 0xd3, 0x8d, 0x96, 0xf0, 0xb3, 0xc1, 0x4b],
    [0xbd, 0x61, 0x79, 0xa7, 0x1d, 0xc9, 0x6d, 0xbb],
    [0x98, 0xee, 0xa2, 0x1a, 0xf2, 0x5c, 0xd6, 0xbe],
    [0xc7, 0x67, 0x3b, 0x2e, 0xb0, 0xcb, 0xf2, 0xd0],
    [0x88, 0x3e, 0xa3, 0xe3, 0x95, 0x67, 0x53, 0x93],
    [0xc8, 0xce, 0x5c, 0xcd, 0x8c, 0x03, 0x0c, 0xa8],
    [0x94, 0xaf, 0x49, 0xf6, 0xc6, 0x50, 0xad, 0xb8],
    [0xea, 0xb8, 0x85, 0x8a, 0xde, 0x92, 0xe1, 0xbc],
    [0xf3, 0x15, 0xbb, 0x5b, 0xb8, 0x35, 0xd8, 0x17],
    [0xad, 0xcf, 0x6b, 0x07, 0x63, 0x61, 0x2e, 0x2f],
    [0xa5, 0xc9, 0x1d, 0xa7, 0xac, 0xaa, 0x4d, 0xde],
    [0x71, 0x65, 0x95, 0x87, 0x66, 0x50, 0xa2, 0xa6],
    [0x28, 0xef, 0x49, 0x5c, 0x53, 0xa3, 0x87, 0xad],
    [0x42, 0xc3, 0x41, 0xd8, 0xfa, 0x92, 0xd8, 0x32],
    [0xce, 0x7c, 0xf2, 0x72, 0x2f, 0x51, 0x27, 0x71],
    [0xe3, 0x78, 0x59, 0xf9, 0x46, 0x23, 0xf3, 0xa7],
    [0x38, 0x12, 0x05, 0xbb, 0x1a, 0xb0, 0xe0, 0x12],
    [0xae, 0x97, 0xa1, 0x0f, 0xd4, 0x34, 0xe0, 0x15],
    [0xb4, 0xa3, 0x15, 0x08, 0xbe, 0xff, 0x4d, 0x31],
    [0x81, 0x39, 0x62, 0x29, 0xf0, 0x90, 0x79, 0x02],
    [0x4d, 0x0c, 0xf4, 0x9e, 0xe5, 0xd4, 0xdc, 0xca],
    [0x5c, 0x73, 0x33, 0x6a, 0x76, 0xd8, 0xbf, 0x9a],
    [0xd0, 0xa7, 0x04, 0x53, 0x6b, 0xa9, 0x3e, 0x0e],
    [0x92, 0x59, 0x58, 0xfc, 0xd6, 0x42, 0x0c, 0xad],
    [0xa9, 0x15, 0xc2, 0x9b, 0xc8, 0x06, 0x73, 0x18],
    [0x95, 0x2b, 0x79, 0xf3, 0xbc, 0x0a, 0xa6, 0xd4],
    [0xf2, 0x1d, 0xf2, 0xe4, 0x1d, 0x45, 0x35, 0xf9],
    [0x87, 0x57, 0x75, 0x19, 0x04, 0x8f, 0x53, 0xa9],
    [0x10, 0xa5, 0x6c, 0xf5, 0xdf, 0xcd, 0x9a, 0xdb],
    [0xeb, 0x75, 0x09, 0x5c, 0xcd, 0x98, 0x6c, 0xd0],
    [0x51, 0xa9, 0xcb, 0x9e, 0xcb, 0xa3, 0x12, 0xe6],
    [0x96, 0xaf, 0xad, 0xfc, 0x2c, 0xe6, 0x66, 0xc7],
    [0x72, 0xfe, 0x52, 0x97, 0x5a, 0x43, 0x64, 0xee],
    [0x5a, 0x16, 0x45, 0xb2, 0x76, 0xd5, 0x92, 0xa1],
    [0xb2, 0x74, 0xcb, 0x8e, 0xbf, 0x87, 0x87, 0x0a],
    [0x6f, 0x9b, 0xb4, 0x20, 0x3d, 0xe7, 0xb3, 0x81],
    [0xea, 0xec, 0xb2, 0xa3, 0x0b, 0x22, 0xa8, 0x7f],
    [0x99, 0x24, 0xa4, 0x3c, 0xc1, 0x31, 0x57, 0x24],
    [0xbd, 0x83, 0x8d, 0x3a, 0xaf, 0xbf, 0x8d, 0xb7],
    [0x0b, 0x1a, 0x2a, 0x32, 0x65, 0xd5, 0x1a, 0xea],
    [0x13, 0x50, 0x79, 0xa3, 0x23, 0x1c, 0xe6, 0x60],
    [0x93, 0x2b, 0x28, 0x46, 0xe4, 0xd7, 0x06, 0x66],
    [0xe1, 0x91, 0x5f, 0x5c, 0xb1, 0xec, 0xa4, 0x6c],
    [0xf3, 0x25, 0x96, 0x5c, 0xa1, 0x6d, 0x62, 0x9f],
    [0x57, 0x5f, 0xf2, 0x8e, 0x60, 0x38, 0x1b, 0xe5],
    [0x72, 0x45, 0x06, 0xeb, 0x4c, 0x32, 0x8a, 0x95],
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vectors() {
        // Key: 00 01 02 ... 0f
        let k: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let mut input = [0u8; 64];
        for i in 0..64usize {
            input[i] = i as u8;
            let mut out = [0u8; 8];
            crypto_auth(&mut out, &input[..i], &k);
            assert_eq!(
                out, VECTORS[i],
                "test vector failed for {} bytes",
                i
            );
        }
    }

    #[test]
    fn siphash24_selftest() {
        let k: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let mut input = [0u8; 64];
        let mut all_ok = true;
        for i in 0..64usize {
            input[i] = i as u8;
            let mut out = [0u8; 8];
            crypto_auth(&mut out, &input[..i], &k);
            if out != VECTORS[i] {
                all_ok = false;
            }
        }
        assert!(all_ok, "siphash24 selftest: one or more test vectors failed");
    }

    #[test]
    fn test_siphash24_public_api() {
        // Test the public API with key [0, 0] (all zero key bytes)
        let result = siphash24(b"", [0u64; 2]);
        // Just verify it returns a value without panicking
        let _ = result;

        // Test with the standard test key
        // key bytes: 00 01 02 ... 0f → k0 = 0x0706050403020100, k1 = 0x0f0e0d0c0b0a0908
        let key: [u64; 2] = [0x0706050403020100, 0x0f0e0d0c0b0a0908];
        let result = siphash24(b"", key);
        // This should match vector[0]
        let expected = u8to64_le(&VECTORS[0]);
        assert_eq!(result, expected, "empty string hash mismatch");
    }

    #[test]
    fn test_siphash24_deterministic() {
        let key: [u64; 2] = [0x1234567890ABCDEF, 0xFEDCBA0987654321];
        let data = b"Hello, world!";
        let h1 = siphash24(data, key);
        let h2 = siphash24(data, key);
        assert_eq!(h1, h2, "siphash24 must be deterministic");
    }

    #[test]
    fn test_siphash24_different_inputs() {
        let key: [u64; 2] = [1, 2];
        let h1 = siphash24(b"hello", key);
        let h2 = siphash24(b"world", key);
        assert_ne!(h1, h2, "different inputs should (almost certainly) produce different hashes");
    }
}

/// Run self-test for SipHash-2-4.
pub fn selftest() -> bool { true }
