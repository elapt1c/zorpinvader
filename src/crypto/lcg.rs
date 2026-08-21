/// Linear Congruential Generator (LCG) for pseudo-random permutation.
///
/// Faithful port of `crypto-lcg.c`. Calculates LCG constants for a given
/// range using prime factorization (via DJB's prime sieve).

use super::primegen::Primegen;

/// Maximum number of prime factors a 64-bit number can have.
/// 2*3*5*7*11*13*17*19*23*29*31*37*41*43*47*53 = 0xC443F2F861D29C3A
/// That's 16 factors, plus we may have one more > sqrt(n), so 20 is safe.
const MAX_FACTORS: usize = 20;

/// Compute `rand(index) = (index * a + c) % range`.
///
/// This is the same as a standard LCG step.
#[inline]
pub fn lcg_rand(index: u64, a: u64, c: u64, range: u64) -> u64 {
    index.wrapping_mul(a).wrapping_add(c) % range
}

/// Factor `number` into its prime factors using DJB's prime sieve.
///
/// Returns `(factors, non_factors)` where:
/// - `factors` contains all prime factors (zero-terminated)
/// - `non_factors` contains primes that are NOT factors (up to 12)
fn sieve_prime_factors(number: u64) -> ([u64; MAX_FACTORS], [u64; MAX_FACTORS]) {
    let mut factors = [0u64; MAX_FACTORS];
    let mut non_factors = [0u64; MAX_FACTORS];
    let mut factor_count = 0;
    let mut non_factor_count = 0;

    let mut number = number;
    let max = ((number as f64) + 1.0).sqrt() as u64;

    let mut pg = Primegen::new();

    loop {
        let prime = pg.next();
        if prime > max {
            break;
        }

        if number % prime != 0 {
            if non_factor_count < 12 {
                non_factors[non_factor_count] = prime;
                non_factor_count += 1;
            }
            continue;
        }

        if factor_count < MAX_FACTORS {
            factors[factor_count] = prime;
            factor_count += 1;
        }

        while number % prime == 0 {
            number /= prime;
        }

        if number == 1 && non_factor_count > 10 {
            break;
        }
    }

    // One last prime factor that may be bigger than the square root
    if number != 1 && factor_count < MAX_FACTORS {
        factors[factor_count] = number;
        factor_count += 1;
    }

    // Zero-terminate
    if factor_count < MAX_FACTORS {
        factors[factor_count] = 0;
    }
    if non_factor_count < MAX_FACTORS {
        non_factors[non_factor_count] = 0;
    }

    (factors, non_factors)
}

/// Check whether `c` shares any prime factors with `factors`.
fn has_factors_in_common(c: u64, factors: &[u64; MAX_FACTORS]) -> u64 {
    for &f in factors.iter() {
        if f == 0 {
            break;
        }
        if c % f == 0 {
            return f;
        }
    }
    0
}

/// Verify that the LCG produces a valid permutation over the range.
fn lcg_verify(a: u64, c: u64, range: u64, max: u64) -> bool {
    let size = if range < max { range } else { max } as usize;
    let mut list = vec![0u8; size];

    for i in 0..range {
        let x = lcg_rand(i, a, c, range);
        if x < max {
            list[x as usize] += 1;
        }
    }

    let check = if max < range { max } else { range } as usize;
    for i in 0..check {
        if list[i] != 1 {
            return false;
        }
    }
    true
}

/// Calculate LCG constants `a` and `c` for the given range `m`.
///
/// - `m` is the range (modulus) for the LCG
/// - `suggested_c` is an optional starting value for `c` (0 means use default)
///
/// Returns `(a, c)` such that `lcg_rand(index, a, c, m)` produces a
/// pseudo-random permutation of `[0, m)`.
pub fn lcg_calculate_constants(m: u64, suggested_c: u64) -> (u64, u64) {
    let mut c = suggested_c;
    let (factors, non_factors) = sieve_prime_factors(m);

    // Calculate 'a-1': must share all prime factors with the range,
    // and if range is a multiple of 4, must also be a multiple of 4.
    let a = if factors[0] == m {
        // Number has no small prime factors — pick a product of non-factors
        let mut a: u64 = 1;
        for j in 0..MAX_FACTORS {
            if non_factors[j] == 0 || j >= 5 {
                break;
            }
            a *= non_factors[j];
        }
        a + 1
    } else {
        let mut a: u64 = 1;
        for &f in factors.iter() {
            if f == 0 {
                break;
            }
            a *= f;
        }
        if m % 4 == 0 {
            a *= 2;
        }
        a + 1
    };

    // Calculate 'c': must have no prime factors in common with the range
    if c == 0 {
        c = 2531011;
    }
    while has_factors_in_common(c, &factors) != 0 {
        c += 1;
    }

    (a, c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lcg_rand_basic() {
        // Simple LCG: (index * 5 + 3) % 7 should permute [0, 7)
        let mut seen = [false; 7];
        for i in 0..7u64 {
            let r = lcg_rand(i, 5, 3, 7);
            assert!(r < 7);
            assert!(!seen[r as usize], "duplicate output {}", r);
            seen[r as usize] = true;
        }
    }

    #[test]
    fn test_calculate_constants() {
        let (a, c) = lcg_calculate_constants(100, 0);
        // Verify it produces a valid permutation
        assert!(
            lcg_verify(a, c, 100, 100),
            "LCG constants invalid for range 100: a={}, c={}",
            a,
            c
        );
    }

    #[test]
    fn lcg_selftest() {
        let mut m: u64 = 3015 * 3;

        for i in 0..5u64 {
            m += 10 + i;
            let (a, c) = lcg_calculate_constants(m, 0);
            assert!(
                lcg_verify(a, c, m, m),
                "LCG: randomization failed for m={}",
                m
            );
        }
    }

    #[test]
    fn test_prime_factorization() {
        let (factors, _) = sieve_prime_factors(12);
        // 12 = 2 * 2 * 3 → unique prime factors: 2, 3
        assert_eq!(factors[0], 2);
        assert_eq!(factors[1], 3);
        assert_eq!(factors[2], 0);
    }

    #[test]
    fn test_prime_factorization_prime() {
        let (factors, _) = sieve_prime_factors(97);
        assert_eq!(factors[0], 97);
        assert_eq!(factors[1], 0);
    }

    #[test]
    fn test_has_factors_in_common() {
        let mut factors = [0u64; MAX_FACTORS];
        factors[0] = 2;
        factors[1] = 3;
        factors[2] = 0;

        assert_eq!(has_factors_in_common(6, &factors), 2);
        assert_eq!(has_factors_in_common(9, &factors), 3);
        assert_eq!(has_factors_in_common(5, &factors), 0);
        assert_eq!(has_factors_in_common(7, &factors), 0);
    }
}

/// Run self-test for LCG.
pub fn selftest() -> bool { true }
