//! Unsigned LEB128 varints, minimal and at most 9 bytes (`encoding.md#varint`).

use crate::DecodeError;

/// The largest value a varint can carry: `2^63 - 1`.
pub const VARINT_MAX: u64 = (1 << 63) - 1;

/// The maximum length of a varint in bytes.
pub const VARINT_MAX_LEN: usize = 9;

/// Appends the varint encoding of `value` to `out`.
///
/// # Panics
///
/// Panics if `value > VARINT_MAX`. Every caller in this crate stays within
/// range by construction.
pub fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    assert!(value <= VARINT_MAX, "varint value {value} exceeds 2^63 - 1");
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Returns the varint encoding of `value` as a new vector.
///
/// This is the `varint(i)` used in several derivations of the specification.
///
/// # Panics
///
/// Panics if `value > VARINT_MAX`.
pub fn varint(value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(varint_len(value));
    write_varint(value, &mut out);
    out
}

/// The number of bytes the varint encoding of `value` occupies.
pub fn varint_len(value: u64) -> usize {
    let bits = 64 - (value | 1).leading_zeros() as usize;
    bits.div_ceil(7)
}

/// Reads a varint from the start of `input`, returning the value and the
/// number of bytes consumed. `offset` is only used for error reporting.
///
/// Rejects non-minimal encodings and encodings longer than 9 bytes.
pub fn read_varint(input: &[u8], offset: usize) -> Result<(u64, usize), DecodeError> {
    let mut value: u64 = 0;
    for i in 0..VARINT_MAX_LEN {
        let Some(&byte) = input.get(i) else {
            return Err(DecodeError::UnexpectedEnd { offset: offset + i });
        };
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            if byte == 0 && i > 0 {
                return Err(DecodeError::NonMinimalVarint { offset });
            }
            return Ok((value, i + 1));
        }
    }
    Err(DecodeError::VarintTooLong { offset })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_encodings() {
        assert_eq!(varint(0), [0x00]);
        assert_eq!(varint(1), [0x01]);
        assert_eq!(varint(127), [0x7f]);
        assert_eq!(varint(128), [0x80, 0x01]);
        assert_eq!(varint(300), [0xac, 0x02]);
        assert_eq!(
            varint(VARINT_MAX),
            [0xff; 8].iter().copied().chain([0x7f]).collect::<Vec<_>>()
        );
    }

    #[test]
    fn lengths() {
        for (v, n) in [
            (0, 1),
            (127, 1),
            (128, 2),
            (16383, 2),
            (16384, 3),
            (VARINT_MAX, 9),
        ] {
            assert_eq!(varint_len(v), n, "{v}");
            assert_eq!(varint(v).len(), n, "{v}");
        }
    }

    #[test]
    fn rejects_non_minimal() {
        assert_eq!(
            read_varint(&[0x80, 0x00], 0),
            Err(DecodeError::NonMinimalVarint { offset: 0 })
        );
        assert_eq!(
            read_varint(&[0x81, 0x80, 0x00], 0),
            Err(DecodeError::NonMinimalVarint { offset: 0 })
        );
        assert_eq!(read_varint(&[0x00], 0), Ok((0, 1)));
    }

    #[test]
    fn rejects_ten_bytes() {
        let mut bytes = [0xffu8; 10];
        bytes[9] = 0x01;
        assert_eq!(
            read_varint(&bytes, 0),
            Err(DecodeError::VarintTooLong { offset: 0 })
        );
        // 9 bytes all with continuation bits is also too long.
        assert_eq!(
            read_varint(&[0xff; 9], 0),
            Err(DecodeError::VarintTooLong { offset: 0 })
        );
    }

    #[test]
    fn rejects_truncated() {
        assert_eq!(
            read_varint(&[0x80], 3),
            Err(DecodeError::UnexpectedEnd { offset: 4 })
        );
        assert_eq!(
            read_varint(&[], 0),
            Err(DecodeError::UnexpectedEnd { offset: 0 })
        );
    }

    #[test]
    #[should_panic]
    fn write_out_of_range_panics() {
        write_varint(1 << 63, &mut Vec::new());
    }
}
