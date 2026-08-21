/// DJB's prime sieve — fast prime number generation.
///
/// Faithful port of `crypto-primegen.c`. This uses DJB's segmented sieve
/// algorithm which is significantly faster than the Sieve of Eratosthenes
/// for large ranges.

/// Number of 32-bit words in the sieve buffer per segment.
/// Chosen to fit in L1 cache (~16KB).
pub const PRIMEGEN_WORDS: usize = 4004;

/// B = PRIMEGEN_WORDS * 32 (bits per segment row).
const B32: usize = PRIMEGEN_WORDS;
const B: u64 = (PRIMEGEN_WORDS as u64) * 32;

/// Powers of two as bitmasks.
const TWO: [u32; 32] = [
    0x00000001, 0x00000002, 0x00000004, 0x00000008,
    0x00000010, 0x00000020, 0x00000040, 0x00000080,
    0x00000100, 0x00000200, 0x00000400, 0x00000800,
    0x00001000, 0x00002000, 0x00004000, 0x00008000,
    0x00010000, 0x00020000, 0x00040000, 0x00080000,
    0x00100000, 0x00200000, 0x00400000, 0x00800000,
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
];

/// Inverse delta lookup table for 60-column wheel factorization.
const DELTA_INVERSE: [i32; 60] = [
    -1, B32 as i32 * 0, -1, -1, -1, -1, -1, B32 as i32 * 1, -1, -1, -1,
    B32 as i32 * 2, -1, B32 as i32 * 3, -1,
    -1, -1, B32 as i32 * 4, -1, B32 as i32 * 5, -1, -1, -1, B32 as i32 * 6,
    -1, -1, -1, -1, -1, B32 as i32 * 7,
    -1, B32 as i32 * 8, -1, -1, -1, -1, -1, B32 as i32 * 9, -1, -1, -1,
    B32 as i32 * 10, -1, B32 as i32 * 11, -1,
    -1, -1, B32 as i32 * 12, -1, B32 as i32 * 13, -1, -1, -1, B32 as i32 * 14,
    -1, -1, -1, -1, -1, B32 as i32 * 15,
];

/// Squares of primes >= 7, < 240.
const QQ_TAB: [u32; 49] = [
    49, 121, 169, 289, 361, 529, 841, 961, 1369, 1681,
    1849, 2209, 2809, 3481, 3721, 4489, 5041, 5329, 6241, 6889,
    7921, 9409, 10201, 10609, 11449, 11881, 12769, 16129, 17161, 18769,
    19321, 22201, 22801, 24649, 26569, 27889, 29929, 32041, 32761, 36481,
    37249, 38809, 39601, 44521, 49729, 51529, 52441, 54289, 57121,
];

/// `(qq * 11 + 1) / 60` or `(qq * 59 + 1) / 60` for each entry in QQ_TAB.
const QQ60_TAB: [u32; 49] = [
    9, 119, 31, 53, 355, 97, 827, 945, 251, 1653,
    339, 405, 515, 3423, 3659, 823, 4957, 977, 6137, 1263,
    7789, 1725, 10031, 1945, 2099, 11683, 2341, 2957, 16875, 3441,
    18999, 21831, 22421, 4519, 4871, 5113, 5487, 31507, 32215, 35873,
    6829, 7115, 38941, 43779, 9117, 9447, 51567, 9953, 56169,
];

#[derive(Clone, Copy)]
struct Todo {
    index: i8,
    f: i8,
    g: i8,
    k: i8,
}

const FOR4: [Todo; 128] = [
    Todo { index: 0, f: 2, g: 15, k: 4 },
    Todo { index: 0, f: 3, g: 5, k: 1 },
    Todo { index: 0, f: 3, g: 25, k: 11 },
    Todo { index: 0, f: 5, g: 9, k: 3 },
    Todo { index: 0, f: 5, g: 21, k: 9 },
    Todo { index: 0, f: 7, g: 15, k: 7 },
    Todo { index: 0, f: 8, g: 15, k: 8 },
    Todo { index: 0, f: 10, g: 9, k: 8 },
    Todo { index: 0, f: 10, g: 21, k: 14 },
    Todo { index: 0, f: 12, g: 5, k: 10 },
    Todo { index: 0, f: 12, g: 25, k: 20 },
    Todo { index: 0, f: 13, g: 15, k: 15 },
    Todo { index: 0, f: 15, g: 1, k: 15 },
    Todo { index: 0, f: 15, g: 11, k: 17 },
    Todo { index: 0, f: 15, g: 19, k: 21 },
    Todo { index: 0, f: 15, g: 29, k: 29 },
    Todo { index: 3, f: 1, g: 3, k: 0 },
    Todo { index: 3, f: 1, g: 27, k: 12 },
    Todo { index: 3, f: 4, g: 3, k: 1 },
    Todo { index: 3, f: 4, g: 27, k: 13 },
    Todo { index: 3, f: 6, g: 7, k: 3 },
    Todo { index: 3, f: 6, g: 13, k: 5 },
    Todo { index: 3, f: 6, g: 17, k: 7 },
    Todo { index: 3, f: 6, g: 23, k: 11 },
    Todo { index: 3, f: 9, g: 7, k: 6 },
    Todo { index: 3, f: 9, g: 13, k: 8 },
    Todo { index: 3, f: 9, g: 17, k: 10 },
    Todo { index: 3, f: 9, g: 23, k: 14 },
    Todo { index: 3, f: 11, g: 3, k: 8 },
    Todo { index: 3, f: 11, g: 27, k: 20 },
    Todo { index: 3, f: 14, g: 3, k: 13 },
    Todo { index: 3, f: 14, g: 27, k: 25 },
    Todo { index: 4, f: 2, g: 1, k: 0 },
    Todo { index: 4, f: 2, g: 11, k: 2 },
    Todo { index: 4, f: 2, g: 19, k: 6 },
    Todo { index: 4, f: 2, g: 29, k: 14 },
    Todo { index: 4, f: 7, g: 1, k: 3 },
    Todo { index: 4, f: 7, g: 11, k: 5 },
    Todo { index: 4, f: 7, g: 19, k: 9 },
    Todo { index: 4, f: 7, g: 29, k: 17 },
    Todo { index: 4, f: 8, g: 1, k: 4 },
    Todo { index: 4, f: 8, g: 11, k: 6 },
    Todo { index: 4, f: 8, g: 19, k: 10 },
    Todo { index: 4, f: 8, g: 29, k: 18 },
    Todo { index: 4, f: 13, g: 1, k: 11 },
    Todo { index: 4, f: 13, g: 11, k: 13 },
    Todo { index: 4, f: 13, g: 19, k: 17 },
    Todo { index: 4, f: 13, g: 29, k: 25 },
    Todo { index: 7, f: 1, g: 5, k: 0 },
    Todo { index: 7, f: 1, g: 25, k: 10 },
    Todo { index: 7, f: 4, g: 5, k: 1 },
    Todo { index: 7, f: 4, g: 25, k: 11 },
    Todo { index: 7, f: 5, g: 7, k: 2 },
    Todo { index: 7, f: 5, g: 13, k: 4 },
    Todo { index: 7, f: 5, g: 17, k: 6 },
    Todo { index: 7, f: 5, g: 23, k: 10 },
    Todo { index: 7, f: 10, g: 7, k: 7 },
    Todo { index: 7, f: 10, g: 13, k: 9 },
    Todo { index: 7, f: 10, g: 17, k: 11 },
    Todo { index: 7, f: 10, g: 23, k: 15 },
    Todo { index: 7, f: 11, g: 5, k: 8 },
    Todo { index: 7, f: 11, g: 25, k: 18 },
    Todo { index: 7, f: 14, g: 5, k: 13 },
    Todo { index: 7, f: 14, g: 25, k: 23 },
    Todo { index: 9, f: 2, g: 9, k: 1 },
    Todo { index: 9, f: 2, g: 21, k: 7 },
    Todo { index: 9, f: 3, g: 1, k: 0 },
    Todo { index: 9, f: 3, g: 11, k: 2 },
    Todo { index: 9, f: 3, g: 19, k: 6 },
    Todo { index: 9, f: 3, g: 29, k: 14 },
    Todo { index: 9, f: 7, g: 9, k: 4 },
    Todo { index: 9, f: 7, g: 21, k: 10 },
    Todo { index: 9, f: 8, g: 9, k: 5 },
    Todo { index: 9, f: 8, g: 21, k: 11 },
    Todo { index: 9, f: 12, g: 1, k: 9 },
    Todo { index: 9, f: 12, g: 11, k: 11 },
    Todo { index: 9, f: 12, g: 19, k: 15 },
    Todo { index: 9, f: 12, g: 29, k: 23 },
    Todo { index: 9, f: 13, g: 9, k: 12 },
    Todo { index: 9, f: 13, g: 21, k: 18 },
    Todo { index: 10, f: 2, g: 5, k: 0 },
    Todo { index: 10, f: 2, g: 25, k: 10 },
    Todo { index: 10, f: 5, g: 1, k: 1 },
    Todo { index: 10, f: 5, g: 11, k: 3 },
    Todo { index: 10, f: 5, g: 19, k: 7 },
    Todo { index: 10, f: 5, g: 29, k: 15 },
    Todo { index: 10, f: 7, g: 5, k: 3 },
    Todo { index: 10, f: 7, g: 25, k: 13 },
    Todo { index: 10, f: 8, g: 5, k: 4 },
    Todo { index: 10, f: 8, g: 25, k: 14 },
    Todo { index: 10, f: 10, g: 1, k: 6 },
    Todo { index: 10, f: 10, g: 11, k: 8 },
    Todo { index: 10, f: 10, g: 19, k: 12 },
    Todo { index: 10, f: 10, g: 29, k: 20 },
    Todo { index: 10, f: 13, g: 5, k: 11 },
    Todo { index: 10, f: 13, g: 25, k: 21 },
    Todo { index: 13, f: 1, g: 15, k: 3 },
    Todo { index: 13, f: 4, g: 15, k: 4 },
    Todo { index: 13, f: 5, g: 3, k: 1 },
    Todo { index: 13, f: 5, g: 27, k: 13 },
    Todo { index: 13, f: 6, g: 5, k: 2 },
    Todo { index: 13, f: 6, g: 25, k: 12 },
    Todo { index: 13, f: 9, g: 5, k: 5 },
    Todo { index: 13, f: 9, g: 25, k: 15 },
    Todo { index: 13, f: 10, g: 3, k: 6 },
    Todo { index: 13, f: 10, g: 27, k: 18 },
    Todo { index: 13, f: 11, g: 15, k: 11 },
    Todo { index: 13, f: 14, g: 15, k: 16 },
    Todo { index: 13, f: 15, g: 7, k: 15 },
    Todo { index: 13, f: 15, g: 13, k: 17 },
    Todo { index: 13, f: 15, g: 17, k: 19 },
    Todo { index: 13, f: 15, g: 23, k: 23 },
    Todo { index: 14, f: 1, g: 7, k: 0 },
    Todo { index: 14, f: 1, g: 13, k: 2 },
    Todo { index: 14, f: 1, g: 17, k: 4 },
    Todo { index: 14, f: 1, g: 23, k: 8 },
    Todo { index: 14, f: 4, g: 7, k: 1 },
    Todo { index: 14, f: 4, g: 13, k: 3 },
    Todo { index: 14, f: 4, g: 17, k: 5 },
    Todo { index: 14, f: 4, g: 23, k: 9 },
    Todo { index: 14, f: 11, g: 7, k: 8 },
    Todo { index: 14, f: 11, g: 13, k: 10 },
    Todo { index: 14, f: 11, g: 17, k: 12 },
    Todo { index: 14, f: 11, g: 23, k: 16 },
    Todo { index: 14, f: 14, g: 7, k: 13 },
    Todo { index: 14, f: 14, g: 13, k: 15 },
    Todo { index: 14, f: 14, g: 17, k: 17 },
    Todo { index: 14, f: 14, g: 23, k: 21 },
];

const FOR6: [Todo; 48] = [
    Todo { index: 1, f: 1, g: 2, k: 0 },
    Todo { index: 1, f: 1, g: 8, k: 1 },
    Todo { index: 1, f: 1, g: 22, k: 8 },
    Todo { index: 1, f: 1, g: 28, k: 13 },
    Todo { index: 1, f: 3, g: 10, k: 2 },
    Todo { index: 1, f: 3, g: 20, k: 7 },
    Todo { index: 1, f: 7, g: 10, k: 4 },
    Todo { index: 1, f: 7, g: 20, k: 9 },
    Todo { index: 1, f: 9, g: 2, k: 4 },
    Todo { index: 1, f: 9, g: 8, k: 5 },
    Todo { index: 1, f: 9, g: 22, k: 12 },
    Todo { index: 1, f: 9, g: 28, k: 17 },
    Todo { index: 5, f: 1, g: 4, k: 0 },
    Todo { index: 5, f: 1, g: 14, k: 3 },
    Todo { index: 5, f: 1, g: 16, k: 4 },
    Todo { index: 5, f: 1, g: 26, k: 11 },
    Todo { index: 5, f: 5, g: 2, k: 1 },
    Todo { index: 5, f: 5, g: 8, k: 2 },
    Todo { index: 5, f: 5, g: 22, k: 9 },
    Todo { index: 5, f: 5, g: 28, k: 14 },
    Todo { index: 5, f: 9, g: 4, k: 4 },
    Todo { index: 5, f: 9, g: 14, k: 7 },
    Todo { index: 5, f: 9, g: 16, k: 8 },
    Todo { index: 5, f: 9, g: 26, k: 15 },
    Todo { index: 8, f: 3, g: 2, k: 0 },
    Todo { index: 8, f: 3, g: 8, k: 1 },
    Todo { index: 8, f: 3, g: 22, k: 8 },
    Todo { index: 8, f: 3, g: 28, k: 13 },
    Todo { index: 8, f: 5, g: 4, k: 1 },
    Todo { index: 8, f: 5, g: 14, k: 4 },
    Todo { index: 8, f: 5, g: 16, k: 5 },
    Todo { index: 8, f: 5, g: 26, k: 12 },
    Todo { index: 8, f: 7, g: 2, k: 2 },
    Todo { index: 8, f: 7, g: 8, k: 3 },
    Todo { index: 8, f: 7, g: 22, k: 10 },
    Todo { index: 8, f: 7, g: 28, k: 15 },
    Todo { index: 11, f: 1, g: 10, k: 1 },
    Todo { index: 11, f: 1, g: 20, k: 6 },
    Todo { index: 11, f: 3, g: 4, k: 0 },
    Todo { index: 11, f: 3, g: 14, k: 3 },
    Todo { index: 11, f: 3, g: 16, k: 4 },
    Todo { index: 11, f: 3, g: 26, k: 11 },
    Todo { index: 11, f: 7, g: 4, k: 2 },
    Todo { index: 11, f: 7, g: 14, k: 5 },
    Todo { index: 11, f: 7, g: 16, k: 6 },
    Todo { index: 11, f: 7, g: 26, k: 13 },
    Todo { index: 11, f: 9, g: 10, k: 5 },
    Todo { index: 11, f: 9, g: 20, k: 10 },
];

const FOR12: [Todo; 96] = [
    Todo { index: 2, f: 2, g: 1, k: 0 },
    Todo { index: 2, f: 2, g: 11, k: -2 },
    Todo { index: 2, f: 2, g: 19, k: -6 },
    Todo { index: 2, f: 2, g: 29, k: -14 },
    Todo { index: 2, f: 3, g: 4, k: 0 },
    Todo { index: 2, f: 3, g: 14, k: -3 },
    Todo { index: 2, f: 3, g: 16, k: -4 },
    Todo { index: 2, f: 3, g: 26, k: -11 },
    Todo { index: 2, f: 5, g: 2, k: 1 },
    Todo { index: 2, f: 5, g: 8, k: 0 },
    Todo { index: 2, f: 5, g: 22, k: -7 },
    Todo { index: 2, f: 5, g: 28, k: -12 },
    Todo { index: 2, f: 7, g: 4, k: 2 },
    Todo { index: 2, f: 7, g: 14, k: -1 },
    Todo { index: 2, f: 7, g: 16, k: -2 },
    Todo { index: 2, f: 7, g: 26, k: -9 },
    Todo { index: 2, f: 8, g: 1, k: 3 },
    Todo { index: 2, f: 8, g: 11, k: 1 },
    Todo { index: 2, f: 8, g: 19, k: -3 },
    Todo { index: 2, f: 8, g: 29, k: -11 },
    Todo { index: 2, f: 10, g: 7, k: 4 },
    Todo { index: 2, f: 10, g: 13, k: 2 },
    Todo { index: 2, f: 10, g: 17, k: 0 },
    Todo { index: 2, f: 10, g: 23, k: -4 },
    Todo { index: 6, f: 1, g: 10, k: -2 },
    Todo { index: 6, f: 1, g: 20, k: -7 },
    Todo { index: 6, f: 2, g: 7, k: -1 },
    Todo { index: 6, f: 2, g: 13, k: -3 },
    Todo { index: 6, f: 2, g: 17, k: -5 },
    Todo { index: 6, f: 2, g: 23, k: -9 },
    Todo { index: 6, f: 3, g: 2, k: 0 },
    Todo { index: 6, f: 3, g: 8, k: -1 },
    Todo { index: 6, f: 3, g: 22, k: -8 },
    Todo { index: 6, f: 3, g: 28, k: -13 },
    Todo { index: 6, f: 4, g: 5, k: 0 },
    Todo { index: 6, f: 4, g: 25, k: -10 },
    Todo { index: 6, f: 6, g: 5, k: 1 },
    Todo { index: 6, f: 6, g: 25, k: -9 },
    Todo { index: 6, f: 7, g: 2, k: 2 },
    Todo { index: 6, f: 7, g: 8, k: 1 },
    Todo { index: 6, f: 7, g: 22, k: -6 },
    Todo { index: 6, f: 7, g: 28, k: -11 },
    Todo { index: 6, f: 8, g: 7, k: 2 },
    Todo { index: 6, f: 8, g: 13, k: 0 },
    Todo { index: 6, f: 8, g: 17, k: -2 },
    Todo { index: 6, f: 8, g: 23, k: -6 },
    Todo { index: 6, f: 9, g: 10, k: 2 },
    Todo { index: 6, f: 9, g: 20, k: -3 },
    Todo { index: 12, f: 1, g: 4, k: -1 },
    Todo { index: 12, f: 1, g: 14, k: -4 },
    Todo { index: 12, f: 1, g: 16, k: -5 },
    Todo { index: 12, f: 1, g: 26, k: -12 },
    Todo { index: 12, f: 2, g: 5, k: -1 },
    Todo { index: 12, f: 2, g: 25, k: -11 },
    Todo { index: 12, f: 3, g: 10, k: -2 },
    Todo { index: 12, f: 3, g: 20, k: -7 },
    Todo { index: 12, f: 4, g: 1, k: 0 },
    Todo { index: 12, f: 4, g: 11, k: -2 },
    Todo { index: 12, f: 4, g: 19, k: -6 },
    Todo { index: 12, f: 4, g: 29, k: -14 },
    Todo { index: 12, f: 6, g: 1, k: 1 },
    Todo { index: 12, f: 6, g: 11, k: -1 },
    Todo { index: 12, f: 6, g: 19, k: -5 },
    Todo { index: 12, f: 6, g: 29, k: -13 },
    Todo { index: 12, f: 7, g: 10, k: 0 },
    Todo { index: 12, f: 7, g: 20, k: -5 },
    Todo { index: 12, f: 8, g: 5, k: 2 },
    Todo { index: 12, f: 8, g: 25, k: -8 },
    Todo { index: 12, f: 9, g: 4, k: 3 },
    Todo { index: 12, f: 9, g: 14, k: 0 },
    Todo { index: 12, f: 9, g: 16, k: -1 },
    Todo { index: 12, f: 9, g: 26, k: -8 },
    Todo { index: 15, f: 1, g: 2, k: -1 },
    Todo { index: 15, f: 1, g: 8, k: -2 },
    Todo { index: 15, f: 1, g: 22, k: -9 },
    Todo { index: 15, f: 1, g: 28, k: -14 },
    Todo { index: 15, f: 4, g: 7, k: -1 },
    Todo { index: 15, f: 4, g: 13, k: -3 },
    Todo { index: 15, f: 4, g: 17, k: -5 },
    Todo { index: 15, f: 4, g: 23, k: -9 },
    Todo { index: 15, f: 5, g: 4, k: 0 },
    Todo { index: 15, f: 5, g: 14, k: -3 },
    Todo { index: 15, f: 5, g: 16, k: -4 },
    Todo { index: 15, f: 5, g: 26, k: -11 },
    Todo { index: 15, f: 6, g: 7, k: 0 },
    Todo { index: 15, f: 6, g: 13, k: -2 },
    Todo { index: 15, f: 6, g: 17, k: -4 },
    Todo { index: 15, f: 6, g: 23, k: -8 },
    Todo { index: 15, f: 9, g: 2, k: 3 },
    Todo { index: 15, f: 9, g: 8, k: 2 },
    Todo { index: 15, f: 9, g: 22, k: -5 },
    Todo { index: 15, f: 9, g: 28, k: -10 },
    Todo { index: 15, f: 10, g: 1, k: 4 },
    Todo { index: 15, f: 10, g: 11, k: 2 },
    Todo { index: 15, f: 10, g: 19, k: -2 },
    Todo { index: 15, f: 10, g: 29, k: -10 },
];

/// Population count lookup table (number of set bits in a byte).
const POPCOUNT: [u64; 256] = {
    let mut table = [0u64; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut n = i;
        let mut count = 0u64;
        while n > 0 {
            count += (n & 1) as u64;
            n >>= 1;
        }
        table[i] = count;
        i += 1;
    }
    table
};

/// Prime number generator using DJB's segmented sieve.
pub struct Primegen {
    buf: Box<[[u32; PRIMEGEN_WORDS]; 16]>,
    p: [u64; 512],
    num: usize,
    pos: usize,
    base: u64,
    l: u64,
}

impl Primegen {
    /// Create a new prime generator. The first call to `next()` will return 2.
    pub fn new() -> Self {
        let mut pg = Primegen {
            buf: Box::new([[0u32; PRIMEGEN_WORDS]; 16]),
            p: [0u64; 512],
            num: 0,
            pos: 0,
            base: 0,
            l: 0,
        };
        pg.init();
        pg
    }

    fn init(&mut self) {
        self.l = 1;
        self.base = 60;
        self.pos = PRIMEGEN_WORDS;

        self.p[0] = 59;
        self.p[1] = 53;
        self.p[2] = 47;
        self.p[3] = 43;
        self.p[4] = 41;
        self.p[5] = 37;
        self.p[6] = 31;
        self.p[7] = 29;
        self.p[8] = 23;
        self.p[9] = 19;
        self.p[10] = 17;
        self.p[11] = 13;
        self.p[12] = 11;
        self.p[13] = 7;
        self.p[14] = 5;
        self.p[15] = 3;
        self.p[16] = 2;
        self.num = 17;
    }

    /// Return the next prime number.
    pub fn next(&mut self) -> u64 {
        while self.num == 0 {
            self.fill();
        }
        self.num -= 1;
        self.p[self.num]
    }

    /// Peek at the next prime without consuming it.
    pub fn peek(&mut self) -> u64 {
        while self.num == 0 {
            self.fill();
        }
        self.p[self.num - 1]
    }

    /// Count primes up to (but not including) `to`.
    pub fn count(&mut self, to: u64) -> u64 {
        let mut count: u64 = 0;

        loop {
            // Drain buffered primes
            while self.num > 0 {
                if self.p[self.num - 1] >= to {
                    return count;
                }
                count += 1;
                self.num -= 1;
            }

            let mut smallcount: u64 = 0;
            let mut pos = self.pos;
            while (pos < B32) && (self.base + 1920 < to) {
                for j in 0..16 {
                    let mut bits = !self.buf[j][pos];
                    smallcount += POPCOUNT[(bits & 255) as usize];
                    bits >>= 8;
                    smallcount += POPCOUNT[(bits & 255) as usize];
                    bits >>= 8;
                    smallcount += POPCOUNT[(bits & 255) as usize];
                    bits >>= 8;
                    smallcount += POPCOUNT[(bits & 255) as usize];
                }
                self.base += 1920;
                pos += 1;
            }
            self.pos = pos;
            count += smallcount;

            if pos == B32 {
                while self.base + B * 60 < to {
                    self.sieve();
                    self.l += B;

                    smallcount = 0;
                    for j in 0..16 {
                        for p in 0..B32 {
                            let mut bits = !self.buf[j][p];
                            smallcount += POPCOUNT[(bits & 255) as usize];
                            bits >>= 8;
                            smallcount += POPCOUNT[(bits & 255) as usize];
                            bits >>= 8;
                            smallcount += POPCOUNT[(bits & 255) as usize];
                            bits >>= 8;
                            smallcount += POPCOUNT[(bits & 255) as usize];
                        }
                    }
                    count += smallcount;
                    self.base += B * 60;
                }
            }

            self.fill();
        }
    }

    /// Skip ahead to the first prime >= `to`.
    pub fn skipto(&mut self, to: u64) {
        loop {
            while self.num > 0 {
                if self.p[self.num - 1] >= to {
                    return;
                }
                self.num -= 1;
            }

            let mut pos = self.pos;
            while (pos < B32) && (self.base + 1920 < to) {
                self.base += 1920;
                pos += 1;
            }
            self.pos = pos;
            if pos == B32 {
                while self.base + B * 60 < to {
                    self.l += B;
                    self.base += B * 60;
                }
            }

            self.fill();
        }
    }

    /// Fill the prime buffer from the sieve.
    fn fill(&mut self) {
        let mut i = self.pos;
        if i == B32 {
            self.sieve();
            self.l += B;
            i = 0;
        }
        self.pos = i + 1;

        let bits0 = !self.buf[0][i];
        let bits1 = !self.buf[1][i];
        let bits2 = !self.buf[2][i];
        let bits3 = !self.buf[3][i];
        let bits4 = !self.buf[4][i];
        let bits5 = !self.buf[5][i];
        let bits6 = !self.buf[6][i];
        let bits7 = !self.buf[7][i];
        let bits8 = !self.buf[8][i];
        let bits9 = !self.buf[9][i];
        let bits10 = !self.buf[10][i];
        let bits11 = !self.buf[11][i];
        let bits12 = !self.buf[12][i];
        let bits13 = !self.buf[13][i];
        let bits14 = !self.buf[14][i];
        let bits15 = !self.buf[15][i];

        let mut base = self.base + 1920;
        self.base = base;
        self.num = 0;

        let mut mask: u32 = 0x80000000;
        while mask != 0 {
            base -= 60;
            if bits15 & mask != 0 {
                self.p[self.num] = base + 59;
                self.num += 1;
            }
            if bits14 & mask != 0 {
                self.p[self.num] = base + 53;
                self.num += 1;
            }
            if bits13 & mask != 0 {
                self.p[self.num] = base + 49;
                self.num += 1;
            }
            if bits12 & mask != 0 {
                self.p[self.num] = base + 47;
                self.num += 1;
            }
            if bits11 & mask != 0 {
                self.p[self.num] = base + 43;
                self.num += 1;
            }
            if bits10 & mask != 0 {
                self.p[self.num] = base + 41;
                self.num += 1;
            }
            if bits9 & mask != 0 {
                self.p[self.num] = base + 37;
                self.num += 1;
            }
            if bits8 & mask != 0 {
                self.p[self.num] = base + 31;
                self.num += 1;
            }
            if bits7 & mask != 0 {
                self.p[self.num] = base + 29;
                self.num += 1;
            }
            if bits6 & mask != 0 {
                self.p[self.num] = base + 23;
                self.num += 1;
            }
            if bits5 & mask != 0 {
                self.p[self.num] = base + 19;
                self.num += 1;
            }
            if bits4 & mask != 0 {
                self.p[self.num] = base + 17;
                self.num += 1;
            }
            if bits3 & mask != 0 {
                self.p[self.num] = base + 13;
                self.num += 1;
            }
            if bits2 & mask != 0 {
                self.p[self.num] = base + 11;
                self.num += 1;
            }
            if bits1 & mask != 0 {
                self.p[self.num] = base + 7;
                self.num += 1;
            }
            if bits0 & mask != 0 {
                self.p[self.num] = base + 1;
                self.num += 1;
            }
            mask >>= 1;
        }
    }

    /// Run the sieve to fill the buffer with primality data.
    fn sieve(&mut self) {
        let l = self.l;

        let lmodqq: [u32; 49] = if l > 2_000_000_000 {
            let mut arr = [0u32; 49];
            for i in 0..49 {
                arr[i] = (l % QQ_TAB[i] as u64) as u32;
            }
            arr
        } else {
            let mut arr = [0u32; 49];
            for i in 0..49 {
                arr[i] = (l as u32) % QQ_TAB[i];
            }
            arr
        };

        // Clear all buffers
        for j in 0..16 {
            for i in 0..B32 {
                self.buf[j][i] = !0u32;
            }
        }

        // Process for4 entries
        let mut i = 0;
        for entry in FOR4.iter() {
            if i >= 128 {
                break;
            }
            let buf_idx = entry.index as usize;
            doit4(
                &mut self.buf[buf_idx],
                entry.f as i64,
                entry.g as i64,
                entry.k as i64 - l as i64,
            );
            i += 1;
            // Apply squarefreetiny at the boundaries
            if i == 16 {
                squarefreetiny(&mut self.buf[0], &lmodqq, 1);
            } else if i == 32 {
                squarefreetiny(&mut self.buf[3], &lmodqq, 13);
            } else if i == 48 {
                squarefreetiny(&mut self.buf[4], &lmodqq, 17);
            } else if i == 64 {
                squarefreetiny(&mut self.buf[7], &lmodqq, 29);
            } else if i == 80 {
                squarefreetiny(&mut self.buf[9], &lmodqq, 37);
            } else if i == 96 {
                squarefreetiny(&mut self.buf[10], &lmodqq, 41);
            } else if i == 112 {
                squarefreetiny(&mut self.buf[13], &lmodqq, 49);
            }
        }
        squarefreetiny(&mut self.buf[14], &lmodqq, 53);

        // Process for6 entries
        i = 0;
        for entry in FOR6.iter() {
            let buf_idx = entry.index as usize;
            doit6(
                &mut self.buf[buf_idx],
                entry.f as i64,
                entry.g as i64,
                entry.k as i64 - l as i64,
            );
            i += 1;
            if i == 12 {
                squarefreetiny(&mut self.buf[1], &lmodqq, 7);
            } else if i == 24 {
                squarefreetiny(&mut self.buf[5], &lmodqq, 19);
            } else if i == 36 {
                squarefreetiny(&mut self.buf[8], &lmodqq, 31);
            }
        }
        squarefreetiny(&mut self.buf[11], &lmodqq, 43);

        // Process for12 entries
        i = 0;
        for entry in FOR12.iter() {
            let buf_idx = entry.index as usize;
            doit12(
                &mut self.buf[buf_idx],
                entry.f as i64,
                entry.g as i64,
                entry.k as i64 - l as i64,
            );
            i += 1;
            if i == 24 {
                squarefreetiny(&mut self.buf[2], &lmodqq, 11);
            } else if i == 48 {
                squarefreetiny(&mut self.buf[6], &lmodqq, 23);
            } else if i == 72 {
                squarefreetiny(&mut self.buf[12], &lmodqq, 47);
            }
        }
        squarefreetiny(&mut self.buf[15], &lmodqq, 59);

        // Process larger primes
        squarefree49(&mut self.buf, l, 247);
        squarefree49(&mut self.buf, l, 253);
        squarefree49(&mut self.buf, l, 257);
        squarefree49(&mut self.buf, l, 263);
        squarefree1(&mut self.buf, l, 241);
        squarefree1(&mut self.buf, l, 251);
        squarefree1(&mut self.buf, l, 259);
        squarefree1(&mut self.buf, l, 269);
    }
}

// ============================================================================
// Sieve helper functions
// ============================================================================

fn doit4(a: &mut [u32; B32], mut x: i64, mut y: i64, mut start: i64) {
    x += x;
    x += 15;
    y += 15;

    start += 1_000_000_000;
    while start < 0 {
        start += x;
        x += 30;
    }
    start -= 1_000_000_000;
    let mut i = start;

    while i < B as i64 {
        i += x;
        x += 30;
    }

    loop {
        x -= 30;
        if x <= 15 {
            return;
        }
        i -= x;

        while i < 0 {
            i += y;
            y += 30;
        }

        let i0 = i;
        let y0 = y;
        while i < B as i64 {
            let pos = (i as u32) >> 5;
            let data = (i as u32) & 31;
            i += y;
            y += 30;
            let bits = a[pos as usize] ^ TWO[data as usize];
            a[pos as usize] = bits;
        }
        i = i0;
        y = y0;
    }
}

fn doit6(a: &mut [u32; B32], mut x: i64, mut y: i64, mut start: i64) {
    x += 5;
    y += 15;

    start += 1_000_000_000;
    while start < 0 {
        start += x;
        x += 10;
    }
    start -= 1_000_000_000;
    let mut i = start;
    while i < B as i64 {
        i += x;
        x += 10;
    }

    loop {
        x -= 10;
        if x <= 5 {
            return;
        }
        i -= x;

        while i < 0 {
            i += y;
            y += 30;
        }

        let i0 = i;
        let y0 = y;
        while i < B as i64 {
            let pos = (i as u32) >> 5;
            let data = (i as u32) & 31;
            i += y;
            y += 30;
            let bits = a[pos as usize] ^ TWO[data as usize];
            a[pos as usize] = bits;
        }
        i = i0;
        y = y0;
    }
}

fn doit12(a: &mut [u32; B32], mut x: i64, mut y: i64, mut start: i64) {
    x += 5;

    start += 1_000_000_000;
    while start < 0 {
        start += x;
        x += 10;
    }
    start -= 1_000_000_000;
    let mut i = start;
    while i < 0 {
        i += x;
        x += 10;
    }

    y += 15;
    x += 10;

    loop {
        while i >= B as i64 {
            if x <= y {
                return;
            }
            i -= y;
            y += 30;
        }
        let i0 = i;
        let y0 = y;
        while i >= 0 && y < x {
            let pos = (i as u32) >> 5;
            let data = (i as u32) & 31;
            i -= y;
            y += 30;
            let bits = a[pos as usize] ^ TWO[data as usize];
            a[pos as usize] = bits;
        }
        i = i0;
        y = y0;
        i += x - 10;
        x += 10;
    }
}

fn squarefreetiny(a: &mut [u32; B32], lmodqq: &[u32; 49], d: u32) {
    for j in 0..49 {
        let qq = QQ_TAB[j];
        // Match C unsigned arithmetic wrapping behavior
        let rhs = lmodqq[j]
            .wrapping_add(QQ60_TAB[j].wrapping_mul(d))
            .wrapping_sub(1)
            % qq;
        let mut k = qq.wrapping_sub(1).wrapping_sub(rhs);
        while k < B32 as u32 * 32 {
            let pos = k >> 5;
            let data = k & 31;
            k = k.wrapping_add(qq);
            a[pos as usize] |= TWO[data as usize];
        }
    }
}

fn squarefree1(buf: &mut [[u32; B32]; 16], l: u64, q: u32) {
    let base = 60u64.wrapping_mul(l);
    let mut qq: u32 = q.wrapping_mul(q);
    let mut q = 60u32.wrapping_mul(q).wrapping_add(900);

    while (qq as u64) < B * 60 {
        let i = if base < 2_000_000_000 {
            qq.wrapping_sub((base as u32) % qq)
        } else {
            (qq as u64 - (base % qq as u64)) as u32
        };
        let i = if i & 1 == 0 { i.wrapping_add(qq) } else { i };

        if (i as u64) < B * 60 {
            let mut qqhigh = qq / 60;
            let mut ilow = i % 60;
            let mut ihigh = i / 60;

            qqhigh = qqhigh.wrapping_add(qqhigh);
            while ihigh < B32 as u32 {
                let n = DELTA_INVERSE[ilow as usize];
                if n >= 0 {
                    buf[n as usize][(ihigh >> 5) as usize] |= TWO[(ihigh & 31) as usize];
                }

                ilow = ilow.wrapping_add(2);
                ihigh = ihigh.wrapping_add(qqhigh);
                if ilow >= 60 {
                    ilow -= 60;
                    ihigh = ihigh.wrapping_add(1);
                }
            }
        }

        qq = qq.wrapping_add(q);
        q = q.wrapping_add(1800);
    }

    squarefree1big(buf, base, q, qq as u64);
}

fn squarefree1big(buf: &mut [[u32; B32]; 16], base: u64, mut q: u32, mut qq: u64) {
    let bound = base + 60 * B;

    while qq < bound {
        let i = if bound < 2_000_000_000 {
            qq - ((base as u32) % (qq as u32)) as u64
        } else {
            qq - (base % qq)
        };
        let i = if i & 1 == 0 { i + qq } else { i };

        if i < B * 60 {
            let pos = i as u32;
            let n = DELTA_INVERSE[(pos % 60) as usize];
            if n >= 0 {
                let pos = pos / 60;
                buf[n as usize][(pos >> 5) as usize] |= TWO[(pos & 31) as usize];
            }
        }

        qq += q as u64;
        q = q.wrapping_add(1800);
    }
}

fn squarefree49(buf: &mut [[u32; B32]; 16], l: u64, q: u32) {
    let base = 60u64.wrapping_mul(l);
    let mut qq: u32 = q.wrapping_mul(q);
    let mut q = 60u32.wrapping_mul(q).wrapping_add(900);

    while (qq as u64) < B * 60 {
        let i = if base < 2_000_000_000 {
            qq.wrapping_sub((base as u32) % qq)
        } else {
            (qq as u64 - (base % qq as u64)) as u32
        };
        let i = if i & 1 == 0 { i.wrapping_add(qq) } else { i };

        if (i as u64) < B * 60 {
            let mut qqhigh = qq / 60;
            let mut ilow = i % 60;
            let mut ihigh = i / 60;

            qqhigh = qqhigh.wrapping_add(qqhigh).wrapping_add(1);
            while ihigh < B32 as u32 {
                let n = DELTA_INVERSE[ilow as usize];
                if n >= 0 {
                    buf[n as usize][(ihigh >> 5) as usize] |= TWO[(ihigh & 31) as usize];
                }

                ilow = ilow.wrapping_add(38);
                ihigh = ihigh.wrapping_add(qqhigh);
                if ilow >= 60 {
                    ilow -= 60;
                    ihigh = ihigh.wrapping_add(1);
                }
            }
        }

        qq = qq.wrapping_add(q);
        q = q.wrapping_add(1800);
    }

    squarefree49big(buf, base, q, qq as u64);
}

fn squarefree49big(buf: &mut [[u32; B32]; 16], base: u64, mut q: u32, mut qq: u64) {
    let bound = base + 60 * B;

    while qq < bound {
        let i = if bound < 2_000_000_000 {
            qq - ((base as u32) % (qq as u32)) as u64
        } else {
            qq - (base % qq)
        };
        let i = if i & 1 == 0 { i + qq } else { i };

        if i < B * 60 {
            let pos = i as u32;
            let n = DELTA_INVERSE[(pos % 60) as usize];
            if n >= 0 {
                let pos = pos / 60;
                buf[n as usize][(pos >> 5) as usize] |= TWO[(pos & 31) as usize];
            }
        }

        qq += q as u64;
        q = q.wrapping_add(1800);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_primes() {
        let mut pg = Primegen::new();
        let expected = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71];
        for &p in &expected {
            assert_eq!(pg.next(), p);
        }
    }

    #[test]
    fn test_primes_up_to_100() {
        let mut pg = Primegen::new();
        let mut primes = Vec::new();
        loop {
            let p = pg.next();
            if p >= 100 {
                break;
            }
            primes.push(p);
        }
        assert_eq!(
            primes,
            vec![2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
        );
    }

    #[test]
    fn test_prime_count() {
        let mut pg = Primegen::new();
        // There are 25 primes below 100
        let count = pg.count(100);
        assert_eq!(count, 25);
    }

    #[test]
    fn test_prime_count_1000() {
        let mut pg = Primegen::new();
        // There are 168 primes below 1000
        let count = pg.count(1000);
        assert_eq!(count, 168);
    }

    #[test]
    fn test_peek() {
        let mut pg = Primegen::new();
        assert_eq!(pg.peek(), 2);
        assert_eq!(pg.peek(), 2); // peek again, same result
        assert_eq!(pg.next(), 2);
        assert_eq!(pg.peek(), 3);
    }

    #[test]
    fn test_skipto() {
        let mut pg = Primegen::new();
        pg.skipto(90);
        assert_eq!(pg.next(), 97);
    }

    #[test]
    fn primegen_selftest() {
        // Generate first 100 primes and verify they are actually prime
        let mut pg = Primegen::new();
        let mut prev = 0u64;
        for _ in 0..100 {
            let p = pg.next();
            assert!(p > prev, "primes must be increasing: {} <= {}", p, prev);
            // Simple primality check
            if p > 2 {
                for d in 2..((p as f64).sqrt() as u64 + 1) {
                    assert!(p % d != 0, "{} is not prime (divisible by {})", p, d);
                }
            }
            prev = p;
        }
    }
}
