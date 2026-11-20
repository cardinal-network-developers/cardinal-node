//! Shamir secret sharing of a 32-byte secret over GF(2^8), with the
//! reduction polynomial x^8 + x^4 + x^3 + x + 1, as in SLIP-0039
//! (`identity.md#data-recovery`). Each byte of the secret is the constant
//! term of its own random polynomial of degree threshold − 1; share `i`
//! holds the 32 values at x = i.

use zeroize::Zeroizing;

use crate::random::fill_random;

/// One share: its x coordinate (from 1) and the 32 values there.
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    /// The x coordinate, from 1.
    pub x: u8,
    /// The value of each byte's polynomial at `x`.
    pub y: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Share({}, ..)", self.x)
    }
}

fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

fn inv(a: u8) -> u8 {
    // a^254 = a^-1 in GF(2^8)
    let mut r = 1u8;
    let mut base = a;
    let mut e = 254u32;
    while e > 0 {
        if e & 1 != 0 {
            r = mul(r, base);
        }
        base = mul(base, base);
        e >>= 1;
    }
    r
}

/// Splits `secret` into `n` shares, any `threshold` of which rebuild it.
/// `threshold` must be at least 1 and at most `n`, and `n` at most 255.
pub fn split(secret: &[u8; 32], threshold: usize, n: usize) -> Option<Vec<Share>> {
    if threshold == 0 || threshold > n || n > 255 {
        return None;
    }
    // coefficients[k][j]: the coefficient of x^k for byte j
    let mut coefficients: Vec<Zeroizing<[u8; 32]>> = Vec::with_capacity(threshold);
    coefficients.push(Zeroizing::new(*secret));
    for _ in 1..threshold {
        let mut c = Zeroizing::new([0u8; 32]);
        fill_random(&mut c[..]);
        coefficients.push(c);
    }
    let mut out = Vec::with_capacity(n);
    for i in 1..=n {
        let x = i as u8;
        let mut y = Zeroizing::new([0u8; 32]);
        for j in 0..32 {
            // Horner, from the highest coefficient down
            let mut acc = 0u8;
            for c in coefficients.iter().rev() {
                acc = mul(acc, x) ^ c[j];
            }
            y[j] = acc;
        }
        out.push(Share { x, y });
    }
    Some(out)
}

/// Rebuilds the secret from shares with distinct, non-zero x, by Lagrange
/// interpolation at zero. Given fewer than the threshold, the result is
/// some other value: the caller checks it against what it should open.
pub fn combine(shares: &[Share]) -> Option<Zeroizing<[u8; 32]>> {
    if shares.is_empty() {
        return None;
    }
    for (i, a) in shares.iter().enumerate() {
        if a.x == 0 || shares[..i].iter().any(|b| b.x == a.x) {
            return None;
        }
    }
    let mut out = Zeroizing::new([0u8; 32]);
    for (i, si) in shares.iter().enumerate() {
        // basis polynomial at zero: prod over j != i of x_j / (x_j - x_i)
        let mut basis = 1u8;
        for (j, sj) in shares.iter().enumerate() {
            if i != j {
                basis = mul(basis, mul(sj.x, inv(sj.x ^ si.x)));
            }
        }
        for b in 0..32 {
            out[b] ^= mul(si.y[b], basis);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_inverse() {
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1, "{a}");
        }
        // the AES field: 0x53 * 0xca = 1
        assert_eq!(mul(0x53, 0xca), 1);
    }

    #[test]
    fn any_threshold_of_shares_rebuilds_the_secret() {
        let secret = [0x5a; 32];
        let shares = split(&secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);
        for a in 0..5 {
            for b in a + 1..5 {
                for c in b + 1..5 {
                    let got = combine(&[shares[a].clone(), shares[b].clone(), shares[c].clone()])
                        .unwrap();
                    assert_eq!(*got, secret);
                }
            }
        }
        // two are not enough
        let two = combine(&shares[..2]).unwrap();
        assert_ne!(*two, secret);
        // all five rebuild it too
        assert_eq!(*combine(&shares).unwrap(), secret);
    }

    #[test]
    fn a_threshold_of_one_gives_the_secret_to_everyone() {
        let secret = [7; 32];
        for s in split(&secret, 1, 3).unwrap() {
            assert_eq!(*s.y, secret);
        }
    }

    #[test]
    fn bad_parameters_and_shares_are_refused() {
        assert!(split(&[0; 32], 0, 3).is_none());
        assert!(split(&[0; 32], 4, 3).is_none());
        assert!(split(&[0; 32], 2, 256).is_none());
        let s = split(&[1; 32], 2, 3).unwrap();
        assert!(combine(&[]).is_none());
        assert!(combine(&[s[0].clone(), s[0].clone()]).is_none());
    }
}
