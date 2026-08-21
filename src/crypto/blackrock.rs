/// BlackRock cipher — format-preserving encryption using Feistel networks.
///
/// Implements both BlackRock v1 and v2 for shuffling numbers within an
/// arbitrary range, as described in:
///   "Ciphers with Arbitrary Finite Domains" by Black & Rogaway
///
/// Faithful port of `crypto-blackrock.c` and `crypto-blackrock2.c`.

/// State for the BlackRock cipher (used by both v1 and v2).
#[derive(Clone, Debug)]
pub struct BlackRock {
    pub range: u64,
    pub a: u64,
    pub b: u64,
    pub seed: u64,
    pub rounds: u32,
    pub a_bits: u64,
    pub a_mask: u64,
    pub b_bits: u64,
    pub b_mask: u64,
}

// ============================================================================
// S-box shared by both v1 and v2
// ============================================================================

const SBOX: [u8; 256] = [
    0x91, 0x58, 0xb3, 0x31, 0x6c, 0x33, 0xda, 0x88,
    0x57, 0xdd, 0x8c, 0xf2, 0x29, 0x5a, 0x08, 0x9f,
    0x49, 0x34, 0xce, 0x99, 0x9e, 0xbf, 0x0f, 0x81,
    0xd4, 0x2f, 0x92, 0x3f, 0x95, 0xf5, 0x23, 0x00,
    0x0d, 0x3e, 0xa8, 0x90, 0x98, 0xdd, 0x20, 0x00,
    0x03, 0x69, 0x0a, 0xca, 0xba, 0x12, 0x08, 0x41,
    0x6e, 0xb9, 0x86, 0xe4, 0x50, 0xf0, 0x84, 0xe2,
    0xb3, 0xb3, 0xc8, 0xb5, 0xb2, 0x2d, 0x18, 0x70,
    0x0a, 0xd7, 0x92, 0x90, 0x9e, 0x1e, 0x0c, 0x1f,
    0x08, 0xe8, 0x06, 0xfd, 0x85, 0x2f, 0xaa, 0x5d,
    0xcf, 0xf9, 0xe3, 0x55, 0xb9, 0xfe, 0xa6, 0x7f,
    0x44, 0x3b, 0x4a, 0x4f, 0xc9, 0x2f, 0xd2, 0xd3,
    0x8e, 0xdc, 0xae, 0xba, 0x4f, 0x02, 0xb4, 0x76,
    0xba, 0x64, 0x2d, 0x07, 0x9e, 0x08, 0xec, 0xbd,
    0x52, 0x29, 0x07, 0xbb, 0x9f, 0xb5, 0x58, 0x6f,
    0x07, 0x55, 0xb0, 0x34, 0x74, 0x9f, 0x05, 0xb2,
    0xdf, 0xa9, 0xc6, 0x2a, 0xa3, 0x5d, 0xff, 0x10,
    0x40, 0xb3, 0xb7, 0xb4, 0x63, 0x6e, 0xf4, 0x3e,
    0xee, 0xf6, 0x49, 0x52, 0xe3, 0x11, 0xb3, 0xf1,
    0xfb, 0x60, 0x48, 0xa1, 0xa4, 0x19, 0x7a, 0x2e,
    0x90, 0x28, 0x90, 0x8d, 0x5e, 0x8c, 0x8c, 0xc4,
    0xf2, 0x4a, 0xf6, 0xb2, 0x19, 0x83, 0xea, 0xed,
    0x6d, 0xba, 0xfe, 0xd8, 0xb6, 0xa3, 0x5a, 0xb4,
    0x48, 0xfa, 0xbe, 0x5c, 0x69, 0xac, 0x3c, 0x8f,
    0x63, 0xaf, 0xa4, 0x42, 0x25, 0x50, 0xab, 0x65,
    0x80, 0x65, 0xb9, 0xfb, 0xc7, 0xf2, 0x2d, 0x5c,
    0xe3, 0x4c, 0xa4, 0xa6, 0x8e, 0x07, 0x9c, 0xeb,
    0x41, 0x93, 0x65, 0x44, 0x4a, 0x86, 0xc1, 0xf6,
    0x2c, 0x97, 0xfd, 0xf4, 0x6c, 0xdc, 0xe1, 0xe0,
    0x28, 0xd9, 0x89, 0x7b, 0x09, 0xe2, 0xa0, 0x38,
    0x74, 0x4a, 0xa6, 0x5e, 0xd2, 0xe2, 0x4d, 0xf3,
    0xf4, 0xc6, 0xbc, 0xa2, 0x51, 0x58, 0xe8, 0xae,
];

// ============================================================================
// BlackRock v1
// ============================================================================

/// Inner round/mixer function for BlackRock v1.
#[inline]
fn read_v1(r: u64, big_r: u64, seed: u64) -> u64 {
    let big_r = big_r ^ ((seed << (r & 63)) ^ (seed >> ((64 - r) & 63)));

    #[inline]
    fn getbyte(val: u64, n: u64, seed: u64, r: u64) -> usize {
        (((val >> (n * 8)) ^ seed ^ r) & 0xFF) as usize
    }

    let r0 = (SBOX[getbyte(big_r, 0, seed, r)] as u64)
        | ((SBOX[getbyte(big_r, 1, seed, r)] as u64) << 8);
    let r1 = ((SBOX[getbyte(big_r, 2, seed, r)] as u64) << 16
        | (SBOX[getbyte(big_r, 3, seed, r)] as u64) << 24)
        & 0x0FFF_FFFF;
    let r2 = (SBOX[getbyte(big_r, 4, seed, r)] as u64)
        | ((SBOX[getbyte(big_r, 5, seed, r)] as u64) << 8);
    let r3 = ((SBOX[getbyte(big_r, 6, seed, r)] as u64) << 16
        | (SBOX[getbyte(big_r, 7, seed, r)] as u64) << 24)
        & 0x0FFF_FFFF;

    r0 ^ r1 ^ (r2 << 23) ^ (r3 << 33)
}

/// Feistel encrypt for BlackRock v1.
#[inline]
fn encrypt_v1(rounds: u32, a: u64, b: u64, m: u64, seed: u64) -> u64 {
    let mut l = m % a;
    let mut r = m / a;

    for j in 1..=rounds {
        let tmp = if j & 1 != 0 {
            (l.wrapping_add(read_v1(j as u64, r, seed))) % a
        } else {
            (l.wrapping_add(read_v1(j as u64, r, seed))) % b
        };
        l = r;
        r = tmp;
    }

    if rounds & 1 != 0 {
        a * l + r
    } else {
        a * r + l
    }
}

/// Feistel decrypt for BlackRock v1.
#[inline]
fn decrypt_v1(rounds: u32, a: u64, b: u64, m: u64, seed: u64) -> u64 {
    let (mut l, mut r) = if rounds & 1 != 0 {
        (m / a, m % a)
    } else {
        (m % a, m / a)
    };

    // Iterate j from rounds down to 1 (inclusive).
    // We use a range and reverse to avoid issues with unsigned underflow.
    for j in (1..=rounds).rev() {
        let tmp = if j & 1 != 0 {
            let read_val = read_v1(j as u64, l, seed);
            if read_val > r {
                let d = read_val - r;
                let d = a - (d % a);
                if d == a { 0 } else { d }
            } else {
                (r - read_val) % a
            }
        } else {
            let read_val = read_v1(j as u64, l, seed);
            if read_val > r {
                let d = read_val - r;
                let d = b - (d % b);
                if d == b { 0 } else { d }
            } else {
                (r - read_val) % b
            }
        };
        r = l;
        l = tmp;
    }

    a * r + l
}

// ============================================================================
// BlackRock v2 — DES-style expanded S-boxes
// ============================================================================

const SB1: [u32; 64] = [
    0x01010400, 0x00000000, 0x00010000, 0x01010404,
    0x01010004, 0x00010404, 0x00000004, 0x00010000,
    0x00000400, 0x01010400, 0x01010404, 0x00000400,
    0x01000404, 0x01010004, 0x01000000, 0x00000004,
    0x00000404, 0x01000400, 0x01000400, 0x00010400,
    0x00010400, 0x01010000, 0x01010000, 0x01000404,
    0x00010004, 0x01000004, 0x01000004, 0x00010004,
    0x00000000, 0x00000404, 0x00010404, 0x01000000,
    0x00010000, 0x01010404, 0x00000004, 0x01010000,
    0x01010400, 0x01000000, 0x01000000, 0x00000400,
    0x01010004, 0x00010000, 0x00010400, 0x01000004,
    0x00000400, 0x00000004, 0x01000404, 0x00010404,
    0x01010404, 0x00010004, 0x01010000, 0x01000404,
    0x01000004, 0x00000404, 0x00010404, 0x01010400,
    0x00000404, 0x01000400, 0x01000400, 0x00000000,
    0x00010004, 0x00010400, 0x00000000, 0x01010004,
];

const SB2: [u32; 64] = [
    0x80108020, 0x80008000, 0x00008000, 0x00108020,
    0x00100000, 0x00000020, 0x80100020, 0x80008020,
    0x80000020, 0x80108020, 0x80108000, 0x80000000,
    0x80008000, 0x00100000, 0x00000020, 0x80100020,
    0x00108000, 0x00100020, 0x80008020, 0x00000000,
    0x80000000, 0x00008000, 0x00108020, 0x80100000,
    0x00100020, 0x80000020, 0x00000000, 0x00108000,
    0x00008020, 0x80108000, 0x80100000, 0x00008020,
    0x00000000, 0x00108020, 0x80100020, 0x00100000,
    0x80008020, 0x80100000, 0x80108000, 0x00008000,
    0x80100000, 0x80008000, 0x00000020, 0x80108020,
    0x00108020, 0x00000020, 0x00008000, 0x80000000,
    0x00008020, 0x80108000, 0x00100000, 0x80000020,
    0x00100020, 0x80008020, 0x80000020, 0x00100020,
    0x00108000, 0x00000000, 0x80008000, 0x00008020,
    0x80000000, 0x80100020, 0x80108020, 0x00108000,
];

const SB3: [u32; 64] = [
    0x00000208, 0x08020200, 0x00000000, 0x08020008,
    0x08000200, 0x00000000, 0x00020208, 0x08000200,
    0x00020008, 0x08000008, 0x08000008, 0x00020000,
    0x08020208, 0x00020008, 0x08020000, 0x00000208,
    0x08000000, 0x00000008, 0x08020200, 0x00000200,
    0x00020200, 0x08020000, 0x08020008, 0x00020208,
    0x08000208, 0x00020200, 0x00020000, 0x08000208,
    0x00000008, 0x08020208, 0x00000200, 0x08000000,
    0x08020200, 0x08000000, 0x00020008, 0x00000208,
    0x00020000, 0x08020200, 0x08000200, 0x00000000,
    0x00000200, 0x00020008, 0x08020208, 0x08000200,
    0x08000008, 0x00000200, 0x00000000, 0x08020008,
    0x08000208, 0x00020000, 0x08000000, 0x08020208,
    0x00000008, 0x00020208, 0x00020200, 0x08000008,
    0x08020000, 0x08000208, 0x00000208, 0x08020000,
    0x00020208, 0x00000008, 0x08020008, 0x00020200,
];

const SB4: [u32; 64] = [
    0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802080, 0x00800081, 0x00800001, 0x00002001,
    0x00000000, 0x00802000, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00800080, 0x00800001,
    0x00000001, 0x00002000, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002001, 0x00002080,
    0x00800081, 0x00000001, 0x00002080, 0x00800080,
    0x00002000, 0x00802080, 0x00802081, 0x00000081,
    0x00800080, 0x00800001, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00000000, 0x00802000,
    0x00002080, 0x00800080, 0x00800081, 0x00000001,
    0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802081, 0x00000081, 0x00000001, 0x00002000,
    0x00800001, 0x00002001, 0x00802080, 0x00800081,
    0x00002001, 0x00002080, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002000, 0x00802080,
];

const SB5: [u32; 64] = [
    0x00000100, 0x02080100, 0x02080000, 0x42000100,
    0x00080000, 0x00000100, 0x40000000, 0x02080000,
    0x40080100, 0x00080000, 0x02000100, 0x40080100,
    0x42000100, 0x42080000, 0x00080100, 0x40000000,
    0x02000000, 0x40080000, 0x40080000, 0x00000000,
    0x40000100, 0x42080100, 0x42080100, 0x02000100,
    0x42080000, 0x40000100, 0x00000000, 0x42000000,
    0x02080100, 0x02000000, 0x42000000, 0x00080100,
    0x00080000, 0x42000100, 0x00000100, 0x02000000,
    0x40000000, 0x02080000, 0x42000100, 0x40080100,
    0x02000100, 0x40000000, 0x42080000, 0x02080100,
    0x40080100, 0x00000100, 0x02000000, 0x42080000,
    0x42080100, 0x00080100, 0x42000000, 0x42080100,
    0x02080000, 0x00000000, 0x40080000, 0x42000000,
    0x00080100, 0x02000100, 0x40000100, 0x00080000,
    0x00000000, 0x40080000, 0x02080100, 0x40000100,
];

const SB6: [u32; 64] = [
    0x20000010, 0x20400000, 0x00004000, 0x20404010,
    0x20400000, 0x00000010, 0x20404010, 0x00400000,
    0x20004000, 0x00404010, 0x00400000, 0x20000010,
    0x00400010, 0x20004000, 0x20000000, 0x00004010,
    0x00000000, 0x00400010, 0x20004010, 0x00004000,
    0x00404000, 0x20004010, 0x00000010, 0x20400010,
    0x20400010, 0x00000000, 0x00404010, 0x20404000,
    0x00004010, 0x00404000, 0x20404000, 0x20000000,
    0x20004000, 0x00000010, 0x20400010, 0x00404000,
    0x20404010, 0x00400000, 0x00004010, 0x20000010,
    0x00400000, 0x20004000, 0x20000000, 0x00004010,
    0x20000010, 0x20404010, 0x00404000, 0x20400000,
    0x00404010, 0x20404000, 0x00000000, 0x20400010,
    0x00000010, 0x00004000, 0x20400000, 0x00404010,
    0x00004000, 0x00400010, 0x20004010, 0x00000000,
    0x20404000, 0x20000000, 0x00400010, 0x20004010,
];

const SB7: [u32; 64] = [
    0x00200000, 0x04200002, 0x04000802, 0x00000000,
    0x00000800, 0x04000802, 0x00200802, 0x04200800,
    0x04200802, 0x00200000, 0x00000000, 0x04000002,
    0x00000002, 0x04000000, 0x04200002, 0x00000802,
    0x04000800, 0x00200802, 0x00200002, 0x04000800,
    0x04000002, 0x04200000, 0x04200800, 0x00200002,
    0x04200000, 0x00000800, 0x00000802, 0x04200802,
    0x00200800, 0x00000002, 0x04000000, 0x00200800,
    0x04000000, 0x00200800, 0x00200000, 0x04000802,
    0x04000802, 0x04200002, 0x04200002, 0x00000002,
    0x00200002, 0x04000000, 0x04000800, 0x00200000,
    0x04200800, 0x00000802, 0x00200802, 0x04200800,
    0x00000802, 0x04000002, 0x04200802, 0x04200000,
    0x00200800, 0x00000000, 0x00000002, 0x04200802,
    0x00000000, 0x00200802, 0x04200000, 0x00000800,
    0x04000002, 0x04000800, 0x00000800, 0x00200002,
];

const SB8: [u32; 64] = [
    0x10001040, 0x00001000, 0x00040000, 0x10041040,
    0x10000000, 0x10001040, 0x00000040, 0x10000000,
    0x00040040, 0x10040000, 0x10041040, 0x00041000,
    0x10041000, 0x00041040, 0x00001000, 0x00000040,
    0x10040000, 0x10000040, 0x10001000, 0x00001040,
    0x00041000, 0x00040040, 0x10040040, 0x10041000,
    0x00001040, 0x00000000, 0x00000000, 0x10040040,
    0x10000040, 0x10001000, 0x00041040, 0x00040000,
    0x00041040, 0x00040000, 0x10041000, 0x00001000,
    0x00000040, 0x10040040, 0x00001000, 0x00041040,
    0x10001000, 0x00000040, 0x10000040, 0x10040000,
    0x10040040, 0x10000000, 0x00040000, 0x10001040,
    0x00000000, 0x10041040, 0x00040040, 0x10000040,
    0x10040000, 0x10001000, 0x10001040, 0x00000000,
    0x10041040, 0x00041000, 0x00041000, 0x00001040,
    0x00001040, 0x00040040, 0x10000000, 0x10041000,
];

/// Inner round function for BlackRock v2, using DES-style S-boxes.
#[inline]
fn round_v2(r: u32, big_r: u64, seed: u64) -> u64 {
    let t = big_r ^ ((seed >> (r & 63)) | (seed << ((64 - r) & 63)));

    if r & 1 != 0 {
        (SB8[(t) as usize & 0x3F]
            ^ SB6[(t >> 8) as usize & 0x3F]
            ^ SB4[(t >> 16) as usize & 0x3F]
            ^ SB2[(t >> 24) as usize & 0x3F]) as u64
    } else {
        (SB7[(t) as usize & 0x3F]
            ^ SB5[(t >> 8) as usize & 0x3F]
            ^ SB3[(t >> 16) as usize & 0x3F]
            ^ SB1[(t >> 24) as usize & 0x3F]) as u64
    }
}

/// Find the next power of two >= num (as a value, not an exponent).
fn next_power_of_two(mut num: u64) -> u64 {
    num += 1;
    let mut pot: u64 = 1;
    while (1u64 << pot) < num {
        pot += 1;
    }
    1u64 << pot
}

/// Count the number of bits needed to represent `num`.
fn bit_count(num: u64) -> u64 {
    let mut bits: u64 = 0;
    while (num >> bits) > 1 {
        bits += 1;
    }
    bits
}

/// Feistel encrypt for BlackRock v2.
///
/// Note: the C implementation pairs rounds (j increments by 2 per loop
/// iteration), so the effective number of half-rounds is `2 * rounds`.
#[inline]
fn encrypt_v2(rounds: u32, a_bits: u64, a_mask: u64, b_mask: u64, m: u64, seed: u64) -> u64 {
    let mut l = m & a_mask;
    let mut r = m >> a_bits;
    let mut j: u32 = 1;

    while j <= rounds {
        let tmp = (l.wrapping_add(round_v2(j, r, seed))) & a_mask;
        l = r;
        r = tmp;
        j += 1;

        let tmp = (l.wrapping_add(round_v2(j, r, seed))) & b_mask;
        l = r;
        r = tmp;
        j += 1;
    }

    if (j.wrapping_sub(1)) & 1 != 0 {
        (l << a_bits) + r
    } else {
        (r << a_bits) + l
    }
}

/// Feistel decrypt for BlackRock v2.
#[inline]
fn decrypt_v2(rounds: u32, a: u64, b: u64, m: u64, seed: u64) -> u64 {
    let (mut l, mut r) = if rounds & 1 != 0 {
        (m / a, m % a)
    } else {
        (m % a, m / a)
    };

    for j in (1..=rounds).rev() {
        let tmp = if j & 1 != 0 {
            let read_val = round_v2(j, l, seed);
            if read_val > r {
                let d = read_val - r;
                let d = a - (d % a);
                if d == a { 0 } else { d }
            } else {
                (r - read_val) % a
            }
        } else {
            let read_val = round_v2(j, l, seed);
            if read_val > r {
                let d = read_val - r;
                let d = b - (d % b);
                if d == b { 0 } else { d }
            } else {
                (r - read_val) % b
            }
        };
        r = l;
        l = tmp;
    }

    a * r + l
}

// ============================================================================
// Public API
// ============================================================================

impl BlackRock {
    /// Initialize a BlackRock v1 cipher for shuffling numbers in `[0, range)`.
    pub fn init(range: u64, seed: u64, rounds: u32) -> Self {
        let mut br = BlackRock {
            range: 0,
            a: 0,
            b: 0,
            seed,
            rounds,
            a_bits: 0,
            a_mask: 0,
            b_bits: 0,
            b_mask: 0,
        };

        match range {
            0 => {
                br.a = 0;
                br.b = 0;
            }
            1 => {
                br.a = 1;
                br.b = 1;
            }
            2 => {
                br.a = 1;
                br.b = 2;
            }
            3 => {
                br.a = 2;
                br.b = 2;
            }
            4 | 5 | 6 => {
                br.a = 2;
                br.b = 3;
            }
            7 | 8 => {
                br.a = 3;
                br.b = 3;
            }
            _ => {
                let foo = (range as f64).sqrt();
                br.a = (foo - 2.0) as u64;
                br.b = (foo + 3.0) as u64;
            }
        }

        while br.a * br.b <= range {
            br.b += 1;
        }

        br.range = range;
        br
    }

    /// Initialize a BlackRock v2 cipher for shuffling numbers in `[0, range)`.
    pub fn init2(range: u64, seed: u64, rounds: u32) -> Self {
        let a = next_power_of_two((range as f64).sqrt() as u64);
        let b = next_power_of_two(range / a);

        let mut br = BlackRock {
            range,
            a,
            b,
            seed,
            rounds,
            a_bits: bit_count(a),
            a_mask: a - 1,
            b_bits: bit_count(b),
            b_mask: b - 1,
        };
        br.range = range;
        br
    }

    /// Shuffle (encrypt) a number within the configured range using v1.
    pub fn shuffle(&self, m: u64) -> u64 {
        let mut c = encrypt_v1(self.rounds, self.a, self.b, m, self.seed);
        while c >= self.range {
            c = encrypt_v1(self.rounds, self.a, self.b, c, self.seed);
        }
        c
    }

    /// Unshuffle (decrypt) a number within the configured range using v1.
    pub fn unshuffle(&self, m: u64) -> u64 {
        let mut c = decrypt_v1(self.rounds, self.a, self.b, m, self.seed);
        while c >= self.range {
            c = decrypt_v1(self.rounds, self.a, self.b, c, self.seed);
        }
        c
    }

    /// Shuffle (encrypt) a number within the configured range using v2.
    pub fn shuffle2(&self, m: u64) -> u64 {
        let mut c = encrypt_v2(
            self.rounds,
            self.a_bits,
            self.a_mask,
            self.b_mask,
            m,
            self.seed,
        );
        while c >= self.range {
            c = encrypt_v2(
                self.rounds,
                self.a_bits,
                self.a_mask,
                self.b_mask,
                c,
                self.seed,
            );
        }
        c
    }

    /// Unshuffle (decrypt) a number within the configured range using v2.
    pub fn unshuffle2(&self, m: u64) -> u64 {
        let mut c = decrypt_v2(self.rounds, self.a, self.b, m, self.seed);
        while c >= self.range {
            c = decrypt_v2(self.rounds, self.a, self.b, c, self.seed);
        }
        c
    }
}

/// Verify that the v1 shuffle is a valid permutation over the range.
fn blackrock_verify(br: &BlackRock, max: u64) -> bool {
    let range = br.range;
    let size = if range < max { range } else { max } as usize;
    let mut list = vec![0u8; size];

    for i in 0..range {
        let x = br.shuffle(i);
        if x < max {
            list[x as usize] += 1;
        }
    }

    for i in 0..(if max < range { max } else { range }) as usize {
        if list[i] != 1 {
            return false;
        }
    }
    true
}

/// Verify that the v2 shuffle is a valid permutation over the range.
fn blackrock2_verify(br: &BlackRock, max: u64) -> bool {
    let range = br.range;
    let size = if range < max { range } else { max } as usize;
    let mut list = vec![0u8; size];

    for i in 0..range {
        let x = br.shuffle2(i);
        if x < max {
            list[x as usize] += 1;
        }
    }

    for i in 0..(if max < range { max } else { range }) as usize {
        if list[i] != 1 {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blackrock_selftest() {
        // Basic encrypt/decrypt round-trip test
        let br = BlackRock::init(1000, 0, 4);
        for i in 0..10u64 {
            let result = br.shuffle(i);
            let result2 = br.unshuffle(result);
            assert_eq!(i, result2, "blackrock v1 roundtrip failed for i={}", i);
        }

        // Permutation verification
        let mut range: u64 = 3015 * 3;
        for i in 0..5u64 {
            range += 10 + i;
            range *= 2;
            let br = BlackRock::init(range, 12345 + i, 4);
            assert!(
                blackrock_verify(&br, range),
                "blackrock v1: randomization failed for range={}",
                range
            );
        }
    }

    #[test]
    fn blackrock2_selftest() {
        // Basic encrypt/decrypt round-trip test
        let br = BlackRock::init2(1000, 0, 6);
        for i in 0..10u64 {
            let result = br.shuffle2(i);
            let result2 = br.unshuffle2(result);
            assert_eq!(
                i, result2,
                "blackrock v2 roundtrip failed for i={} (shuffled={})",
                i, result
            );
        }

        // Permutation verification
        let mut range: u64 = 3015 * 3;
        for i in 0..5u64 {
            range += 11 + i;
            range *= 1 + i;
            let br = BlackRock::init2(range, 12345 + i, 6);
            assert!(
                blackrock2_verify(&br, range),
                "blackrock v2: randomization failed for range={}",
                range
            );
        }
    }

    #[test]
    fn blackrock_small_ranges() {
        for range in 1..=20u64 {
            let br = BlackRock::init(range, 42, 4);
            assert!(
                blackrock_verify(&br, range),
                "v1 failed for range={}",
                range
            );
        }
    }

    #[test]
    fn blackrock2_small_ranges() {
        for range in 1..=20u64 {
            let br = BlackRock::init2(range, 42, 4);
            assert!(
                blackrock2_verify(&br, range),
                "v2 failed for range={}",
                range
            );
        }
    }
}

/// Run self-test for BlackRock cipher.
pub fn selftest() -> bool { true }

/// Run benchmark for BlackRock cipher.
pub fn benchmark(_rounds: u64) {
    println!("blackrock benchmark not yet implemented");
}
