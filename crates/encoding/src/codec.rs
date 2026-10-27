//! The encoder and the strict decoder.

use crate::value::{Int, Record, Value};
use crate::varint::{read_varint, varint_len, write_varint};
use crate::DecodeError;

/// The maximum nesting depth of lists and records (`encoding.md#limits`).
///
/// A scalar has depth 0; a list or record has depth one more than its
/// deepest item. A top-level list of lists of integers has depth 2.
pub const MAX_DEPTH: usize = 32;

const T_UINT: u64 = 0;
const T_NEG: u64 = 1;
const T_BYTES: u64 = 2;
const T_TEXT: u64 = 3;
const T_LIST: u64 = 4;
const T_RECORD: u64 = 5;

fn write_header(t: u64, n: u64, out: &mut Vec<u8>) {
    // n < 2^60 for every representable value, so the header fits a varint.
    write_varint((n << 3) | t, out);
}

fn header_len(n: u64) -> usize {
    varint_len(n << 3)
}

impl Value {
    /// Appends the canonical encoding of this value to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Value::Int(i) => {
                let v = i.get();
                if v >= 0 {
                    write_header(T_UINT, v as u64, out);
                } else {
                    write_header(T_NEG, (-1 - v) as u64, out);
                }
            }
            Value::Bytes(b) => {
                write_header(T_BYTES, b.len() as u64, out);
                out.extend_from_slice(b);
            }
            Value::Text(t) => {
                write_header(T_TEXT, t.len() as u64, out);
                out.extend_from_slice(t.as_bytes());
            }
            Value::List(items) => {
                write_header(T_LIST, items.len() as u64, out);
                for item in items {
                    item.encode_into(out);
                }
            }
            Value::Record(r) => r.encode_into(out),
        }
    }

    /// The canonical encoding of this value.
    ///
    /// Values nested deeper than [`MAX_DEPTH`] encode, but no decoder will
    /// accept them; producers must keep within the limit.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut out);
        out
    }

    /// The length of the canonical encoding, without producing it.
    pub fn encoded_len(&self) -> usize {
        match self {
            Value::Int(i) => {
                let v = i.get();
                header_len(if v >= 0 { v as u64 } else { (-1 - v) as u64 })
            }
            Value::Bytes(b) => header_len(b.len() as u64) + b.len(),
            Value::Text(t) => header_len(t.len() as u64) + t.len(),
            Value::List(items) => {
                header_len(items.len() as u64) + items.iter().map(Value::encoded_len).sum::<usize>()
            }
            Value::Record(r) => r.encoded_len(),
        }
    }
}

impl Record {
    /// Appends the canonical encoding of this record to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        write_header(T_RECORD, self.len() as u64, out);
        for (k, v) in self {
            write_varint(*k, out);
            v.encode_into(out);
        }
    }

    /// The canonical encoding of this record.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut out);
        out
    }

    /// The length of the canonical encoding.
    pub fn encoded_len(&self) -> usize {
        header_len(self.len() as u64)
            + self
                .iter()
                .map(|(k, v)| varint_len(*k) + v.encoded_len())
                .sum::<usize>()
    }

    /// Decodes exactly one record from `input`, rejecting anything else
    /// (including trailing bytes).
    pub fn decode(input: &[u8]) -> Result<Record, DecodeError> {
        match decode(input)? {
            Value::Record(r) => Ok(r),
            other => Err(DecodeError::NotARecord {
                found: other.type_name(),
            }),
        }
    }
}

/// Decodes exactly one value from `input`. Trailing bytes are an error.
pub fn decode(input: &[u8]) -> Result<Value, DecodeError> {
    let (value, used) = decode_prefix(input)?;
    if used != input.len() {
        return Err(DecodeError::TrailingBytes { offset: used });
    }
    Ok(value)
}

/// Decodes one value from the start of `input`, returning it and the number
/// of bytes it occupied. For contexts that carry several values in a row.
pub fn decode_prefix(input: &[u8]) -> Result<(Value, usize), DecodeError> {
    let mut d = Decoder { input, pos: 0 };
    let v = d.value(0)?;
    Ok((v, d.pos))
}

/// Checks that `input` is exactly one canonical value, without building it.
pub fn validate(input: &[u8]) -> Result<(), DecodeError> {
    decode(input).map(|_| ())
}

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl Decoder<'_> {
    fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    fn varint(&mut self) -> Result<u64, DecodeError> {
        let (v, n) = read_varint(&self.input[self.pos..], self.pos)?;
        self.pos += n;
        Ok(v)
    }

    fn take(&mut self, n: u64, at: usize) -> Result<&[u8], DecodeError> {
        if n > self.remaining() as u64 {
            return Err(DecodeError::LengthExceedsInput { offset: at });
        }
        let start = self.pos;
        self.pos += n as usize;
        Ok(&self.input[start..self.pos])
    }

    /// Each item takes at least one byte, so a count larger than the
    /// remaining input is malformed. Checking this first bounds allocation.
    fn check_count(&self, n: u64, at: usize) -> Result<usize, DecodeError> {
        if n > self.remaining() as u64 {
            return Err(DecodeError::LengthExceedsInput { offset: at });
        }
        Ok(n as usize)
    }

    fn value(&mut self, depth: usize) -> Result<Value, DecodeError> {
        let at = self.pos;
        let h = self.varint()?;
        let t = h & 7;
        let n = h >> 3;
        match t {
            T_UINT => Ok(Value::Int(
                Int::from_u64(n).expect("n < 2^60 by varint bound"),
            )),
            T_NEG => Ok(Value::Int(
                Int::new(-1 - n as i64).expect("n < 2^60 by varint bound"),
            )),
            T_BYTES => Ok(Value::Bytes(self.take(n, at)?.to_vec())),
            T_TEXT => {
                let bytes = self.take(n, at)?;
                let s = std::str::from_utf8(bytes)
                    .map_err(|_| DecodeError::InvalidUtf8 { offset: at })?;
                Ok(Value::Text(s.to_owned()))
            }
            T_LIST => {
                if depth >= MAX_DEPTH {
                    return Err(DecodeError::TooDeep { offset: at });
                }
                let count = self.check_count(n, at)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::List(items))
            }
            T_RECORD => {
                if depth >= MAX_DEPTH {
                    return Err(DecodeError::TooDeep { offset: at });
                }
                let count = self.check_count(n, at)?;
                let mut record = Record::new();
                let mut last: Option<u64> = None;
                for _ in 0..count {
                    let key_at = self.pos;
                    let key = self.varint()?;
                    if let Some(prev) = last {
                        if key == prev {
                            return Err(DecodeError::DuplicateKey {
                                offset: key_at,
                                key,
                            });
                        }
                        if key < prev {
                            return Err(DecodeError::UnsortedKeys {
                                offset: key_at,
                                key,
                            });
                        }
                    }
                    last = Some(key);
                    let v = self.value(depth + 1)?;
                    record.insert(key, v);
                }
                Ok(Value::Record(record))
            }
            _ => Err(DecodeError::ReservedType {
                offset: at,
                t: t as u8,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }

    #[test]
    fn spec_example() {
        let r = Record::new()
            .with(0, 6u32)
            .with(1, vec![0x0a, 0x0b])
            .with(3, "Ana");
        let bytes = r.encode();
        assert_eq!(bytes, hex("1d 00 30 01 12 0a 0b 03 1b 41 6e 61"));
        assert_eq!(Record::decode(&bytes).unwrap(), r);
        assert_eq!(r.to_string(), r#"{0: 6, 1: h'0a0b', 3: "Ana"}"#);
    }

    #[test]
    fn integers() {
        for (v, h) in [
            (0i64, "00"),
            (1, "08"),
            (15, "78"),
            (16, "8001"),
            (-1, "01"),
            (-2, "09"),
            (-16, "79"),
            (-17, "8101"),
            ((1 << 60) - 1, "f8ffffffffffffff7f"),
            (-(1 << 60), "f9ffffffffffffff7f"),
        ] {
            let val = Value::from(v);
            assert_eq!(hex::encode(val.encode()), h, "{v}");
            assert_eq!(decode(&hex(h)).unwrap(), val);
            assert_eq!(val.encoded_len(), h.len() / 2);
        }
    }

    #[test]
    fn rejects() {
        use DecodeError::*;
        let cases: &[(&str, DecodeError)] = &[
            ("", UnexpectedEnd { offset: 0 }),
            ("06", ReservedType { offset: 0, t: 6 }),
            ("07", ReservedType { offset: 0, t: 7 }),
            ("8000", NonMinimalVarint { offset: 0 }),
            ("0000", TrailingBytes { offset: 1 }),
            ("12 0a", LengthExceedsInput { offset: 0 }),
            ("0b ff", InvalidUtf8 { offset: 0 }),
            ("15 01 00 00 00", UnsortedKeys { offset: 3, key: 0 }),
            ("15 01 00 01 00", DuplicateKey { offset: 3, key: 1 }),
            ("14 00", LengthExceedsInput { offset: 0 }),
            ("0d 00", UnexpectedEnd { offset: 2 }),
        ];
        for (h, err) in cases {
            assert_eq!(decode(&hex(h)), Err(err.clone()), "{h}");
        }
        // Record key encoded non-minimally.
        assert_eq!(
            decode(&hex("0d 80 00 00")),
            Err(NonMinimalVarint { offset: 1 })
        );
        // Nested reserved type.
        assert_eq!(decode(&hex("0c 06")), Err(ReservedType { offset: 1, t: 6 }));
    }

    #[test]
    fn depth_limit() {
        let mut v = Value::from(0u32);
        for _ in 0..MAX_DEPTH {
            v = Value::List(vec![v]);
        }
        assert_eq!(v.depth(), MAX_DEPTH);
        assert_eq!(decode(&v.encode()).unwrap(), v);
        let too_deep = Value::List(vec![v]);
        assert!(matches!(
            decode(&too_deep.encode()),
            Err(DecodeError::TooDeep { .. })
        ));

        let mut r = Value::from(0u32);
        for _ in 0..=MAX_DEPTH {
            r = Value::Record(Record::new().with(1, r));
        }
        assert!(matches!(
            decode(&r.encode()),
            Err(DecodeError::TooDeep { .. })
        ));
    }

    #[test]
    fn huge_count_does_not_allocate() {
        // A list claiming 2^59 items in a 9-byte header.
        let mut bytes = Vec::new();
        write_varint(((1u64 << 59) << 3) | 4, &mut bytes);
        assert!(matches!(
            decode(&bytes),
            Err(DecodeError::LengthExceedsInput { .. })
        ));
    }

    #[test]
    fn unknown_fields_round_trip() {
        let original = Record::new()
            .with(0, 4u32)
            .with(1, "known")
            .with(77, Record::new().with(5, vec![Value::from(1u32)]))
            .with(1_000_000, vec![1u8, 2, 3]);
        let bytes = original.encode();
        let decoded = Record::decode(&bytes).unwrap();
        assert_eq!(decoded.text(1).unwrap(), "known");
        assert_eq!(decoded.encode(), bytes);
        let unknown: Vec<u64> = decoded.unknown_fields(&[0, 1]).map(|(k, _)| k).collect();
        assert_eq!(unknown, [77, 1_000_000]);
    }

    #[test]
    fn prefix_decoding() {
        let mut bytes = Value::from("a").encode();
        bytes.extend(Value::from(7u32).encode());
        let (v, n) = decode_prefix(&bytes).unwrap();
        assert_eq!(v, Value::from("a"));
        let (w, m) = decode_prefix(&bytes[n..]).unwrap();
        assert_eq!(w, Value::from(7u32));
        assert_eq!(n + m, bytes.len());
    }
}
