//! The encoder and the strict decoder.

use crate::value::{Int, Record, Value};
use crate::varint::{read_varint, varint_len, write_varint};
use crate::DecodeError;

/// The maximum nesting depth of lists and records (`encoding.md#limits`).
///
/// A scalar has depth 0; a list or record has depth one more than its
/// deepest item. A top-level list of lists of integers has depth 2.
pub const MAX_DEPTH: usize = 32;

/// The most items a list reserves room for before reading them.
const PREALLOCATED: usize = 256;

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
    let mut d = Decoder {
        c: Cursor::new(input),
    };
    let v = d.value(0)?;
    Ok((v, d.c.pos))
}

/// Checks that `input` is exactly one canonical value, without building it.
pub fn validate(input: &[u8]) -> Result<(), DecodeError> {
    let mut c = Cursor::new(input);
    c.skip(0)?;
    c.end()
}

/// Checks that `input` is exactly one canonical record, without building
/// it: what [`Record::decode`] refuses, refused with the same error.
pub fn check_record(input: &[u8]) -> Result<(), DecodeError> {
    let mut c = Cursor::new(input);
    let first = c.head()?;
    c.pos = first.at;
    c.skip(0)?;
    c.end()?;
    if first.major != Major::Record {
        return Err(DecodeError::NotARecord {
            found: first.major.name(),
        });
    }
    Ok(())
}

/// A value's major type (`encoding.md#values`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Major {
    Uint,
    Neg,
    Bytes,
    Text,
    List,
    Record,
}

impl Major {
    /// The name [`Value::type_name`] gives a value of this type.
    pub fn name(self) -> &'static str {
        match self {
            Major::Uint => "uint",
            Major::Neg => "neg",
            Major::Bytes => "bytes",
            Major::Text => "text",
            Major::List => "list",
            Major::Record => "record",
        }
    }
}

/// A value's header, as read: where it starts, its type, and its number
/// (an integer's value, or a length, or a count).
#[derive(Clone, Copy, Debug)]
pub struct Head {
    pub at: usize,
    pub major: Major,
    pub n: u64,
}

/// Reads a message straight from its bytes, one value at a time, for a
/// reader that makes its own values rather than a tree (the local
/// interface's typed records). Every check the decoder makes is made here,
/// and the decoder makes them here too, so the two refuse the same bytes
/// with the same errors: each value's header a minimal varint of a type
/// not reserved, lengths and counts within the input, text UTF-8, nesting
/// no deeper than [`MAX_DEPTH`], a record's keys ascending and not
/// repeated, and nothing after the value ([`Cursor::end`]).
pub struct Cursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// At the start of `input`.
    #[inline]
    pub fn new(input: &'a [u8]) -> Self {
        Cursor { input, pos: 0 }
    }

    /// Where it is in the input.
    #[inline]
    pub fn pos(&self) -> usize {
        self.pos
    }

    #[inline]
    fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    #[inline]
    fn varint(&mut self) -> Result<u64, DecodeError> {
        let (v, n) = read_varint(&self.input[self.pos..], self.pos)?;
        self.pos += n;
        Ok(v)
    }

    /// The next value's header.
    #[inline]
    pub fn head(&mut self) -> Result<Head, DecodeError> {
        let at = self.pos;
        let h = self.varint()?;
        let n = h >> 3;
        let major = match h & 7 {
            T_UINT => Major::Uint,
            T_NEG => Major::Neg,
            T_BYTES => Major::Bytes,
            T_TEXT => Major::Text,
            T_LIST => Major::List,
            T_RECORD => Major::Record,
            t => {
                return Err(DecodeError::ReservedType {
                    offset: at,
                    t: t as u8,
                })
            }
        };
        Ok(Head { at, major, n })
    }

    /// The bytes of a value of bytes or text whose header is `h`, which
    /// the input must hold.
    #[inline]
    pub fn bytes(&mut self, h: &Head) -> Result<&'a [u8], DecodeError> {
        if h.n > self.remaining() as u64 {
            return Err(DecodeError::LengthExceedsInput { offset: h.at });
        }
        let start = self.pos;
        self.pos += h.n as usize;
        Ok(&self.input[start..self.pos])
    }

    /// The text of a value of text whose header is `h`: in the input, and
    /// UTF-8.
    #[inline]
    pub fn text(&mut self, h: &Head) -> Result<&'a str, DecodeError> {
        let bytes = self.bytes(h)?;
        std::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8 { offset: h.at })
    }

    /// How many items a list, or fields a record, whose header is `h`
    /// holds, at nesting `depth` (0 for the message itself): within
    /// [`MAX_DEPTH`], and no more than the bytes left, since each takes one
    /// at least, so that a count is refused before anything is reserved for
    /// it (`encoding.md#limits`).
    #[inline]
    pub fn count(&self, h: &Head, depth: usize) -> Result<usize, DecodeError> {
        if depth >= MAX_DEPTH {
            return Err(DecodeError::TooDeep { offset: h.at });
        }
        if h.n > self.remaining() as u64 {
            return Err(DecodeError::LengthExceedsInput { offset: h.at });
        }
        Ok(h.n as usize)
    }

    /// A record's next key, after `last`, the key before it: ascending,
    /// and not repeated.
    #[inline]
    pub fn key(&mut self, last: Option<u64>) -> Result<u64, DecodeError> {
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
        Ok(key)
    }

    /// Passes over the next value, at nesting `depth`, checked as the
    /// decoder checks it.
    pub fn skip(&mut self, depth: usize) -> Result<(), DecodeError> {
        let h = self.head()?;
        self.skip_after(&h, depth)
    }

    /// Passes over the rest of the value whose header `h` was just read.
    pub fn skip_after(&mut self, h: &Head, depth: usize) -> Result<(), DecodeError> {
        match h.major {
            Major::Uint | Major::Neg => Ok(()),
            Major::Bytes => self.bytes(h).map(drop),
            Major::Text => self.text(h).map(drop),
            Major::List => {
                for _ in 0..self.count(h, depth)? {
                    self.skip(depth + 1)?;
                }
                Ok(())
            }
            Major::Record => {
                let mut last = None;
                for _ in 0..self.count(h, depth)? {
                    last = Some(self.key(last)?);
                    self.skip(depth + 1)?;
                }
                Ok(())
            }
        }
    }

    /// Nothing is left after the value read: trailing bytes are an error.
    #[inline]
    pub fn end(&self) -> Result<(), DecodeError> {
        if self.pos != self.input.len() {
            return Err(DecodeError::TrailingBytes { offset: self.pos });
        }
        Ok(())
    }
}

struct Decoder<'a> {
    c: Cursor<'a>,
}

impl Decoder<'_> {
    fn value(&mut self, depth: usize) -> Result<Value, DecodeError> {
        let h = self.c.head()?;
        match h.major {
            Major::Uint => Ok(Value::Int(
                Int::from_u64(h.n).expect("n < 2^60 by varint bound"),
            )),
            Major::Neg => Ok(Value::Int(
                Int::new(-1 - h.n as i64).expect("n < 2^60 by varint bound"),
            )),
            Major::Bytes => Ok(Value::Bytes(self.c.bytes(&h)?.to_vec())),
            Major::Text => Ok(Value::Text(self.c.text(&h)?.to_owned())),
            Major::List => {
                let count = self.c.count(&h, depth)?;
                // A count within the input can still be many times the
                // memory of the bytes it claims, nested 32 deep, so the
                // list grows with what is actually read.
                let mut items = Vec::with_capacity(count.min(PREALLOCATED));
                for _ in 0..count {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::List(items))
            }
            Major::Record => {
                let count = self.c.count(&h, depth)?;
                let mut record = Record::new();
                let mut last: Option<u64> = None;
                for _ in 0..count {
                    let key = self.c.key(last)?;
                    last = Some(key);
                    let v = self.value(depth + 1)?;
                    record.insert(key, v);
                }
                Ok(Value::Record(record))
            }
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
            ("15 00", LengthExceedsInput { offset: 0 }),
            ("1b 41", LengthExceedsInput { offset: 0 }),
            ("0c 12 00", LengthExceedsInput { offset: 1 }),
            ("0d 00", UnexpectedEnd { offset: 2 }),
        ];
        for (h, err) in cases {
            assert_eq!(decode(&hex(h)), Err(err.clone()), "{h}");
            assert_eq!(validate(&hex(h)), Err(err.clone()), "{h}");
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
        let too_deep = Value::List(vec![v.clone()]);
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
        // checked without building, the same
        assert_eq!(
            validate(&too_deep.encode()),
            decode(&too_deep.encode()).map(drop)
        );
        assert_eq!(
            check_record(&r.encode()),
            Record::decode(&r.encode()).map(drop)
        );
        assert_eq!(validate(&v.encode()), Ok(()));
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
