//! Range fingerprints (`sync.md#fingerprints`).

use cardinal_encoding::write_varint;

use crate::Id;

/// A 16-byte range fingerprint.
pub type Fingerprint = [u8; 16];

/// A sum of ids read as 256-bit little-endian integers, modulo 2^256.
///
/// Sums form a group, so the sum of a range is a difference of prefix
/// sums.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Sum(pub [u64; 4]);

impl Sum {
    /// Zero.
    pub const ZERO: Sum = Sum([0; 4]);

    /// The id as a 256-bit little-endian integer.
    #[inline]
    pub fn of(id: &Id) -> Sum {
        let mut l = [0u64; 4];
        for (i, limb) in l.iter_mut().enumerate() {
            *limb = u64::from_le_bytes(id[8 * i..8 * i + 8].try_into().unwrap());
        }
        Sum(l)
    }

    /// `self + other` modulo 2^256.
    #[inline]
    pub fn plus(self, other: Sum) -> Sum {
        let mut out = [0u64; 4];
        let mut carry = false;
        for (i, o) in out.iter_mut().enumerate() {
            let (s1, c1) = self.0[i].overflowing_add(other.0[i]);
            let (s2, c2) = s1.overflowing_add(carry as u64);
            *o = s2;
            carry = c1 | c2;
        }
        Sum(out)
    }

    /// Adds one id.
    #[inline]
    pub fn add_id(self, id: &Id) -> Sum {
        self.plus(Sum::of(id))
    }

    /// `self - other` modulo 2^256.
    #[inline]
    pub fn minus(self, other: Sum) -> Sum {
        let mut out = [0u64; 4];
        let mut borrow = false;
        for (i, o) in out.iter_mut().enumerate() {
            let (s1, b1) = self.0[i].overflowing_sub(other.0[i]);
            let (s2, b2) = s1.overflowing_sub(borrow as u64);
            *o = s2;
            borrow = b1 | b2;
        }
        Sum(out)
    }

    /// The 32-byte little-endian form.
    pub fn to_bytes(self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, l) in self.0.iter().enumerate() {
            b[8 * i..8 * i + 8].copy_from_slice(&l.to_le_bytes());
        }
        b
    }
}

/// `first16(BLAKE3(sum || varint(count)))`.
pub fn fingerprint(sum: Sum, count: u64) -> Fingerprint {
    let mut input = Vec::with_capacity(42);
    input.extend_from_slice(&sum.to_bytes());
    write_varint(count, &mut input);
    let h = blake3::hash(&input);
    h.as_bytes()[..16].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic() {
        let max = Sum([u64::MAX; 4]);
        let one = Sum([1, 0, 0, 0]);
        assert_eq!(max.plus(one), Sum::ZERO);
        assert_eq!(Sum::ZERO.minus(one), max);
        let a = Sum::of(&[0xab; 32]);
        let b = Sum::of(&[0x17; 32]);
        assert_eq!(a.plus(b).minus(b), a);
        assert_eq!(Sum::of(&a.to_bytes()), a);
    }

    #[test]
    fn empty_fingerprint() {
        let mut input = vec![0u8; 32];
        input.push(0);
        assert_eq!(
            fingerprint(Sum::ZERO, 0)[..],
            blake3::hash(&input).as_bytes()[..16]
        );
    }
}
