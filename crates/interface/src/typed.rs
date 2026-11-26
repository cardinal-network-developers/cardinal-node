//! Typed requests, replies and records of the local interface: each a Rust
//! value whose fields the compiler knows, written straight to the base
//! encoding and read straight from it, with no tree of names between.
//!
//! A record is declared once, with [`typed!`](crate::typed) in
//! [`table`](super::table): the declaration gives the struct, its table
//! row (the numbers, names and types `apps.md` lists, which the comparison
//! with the specification reads), and its encoding. Nothing else says
//! what a typed record holds, so the two cannot drift.
//!
//! What a field's Rust type is on the wire:
//!
//! | Rust | table | sent |
//! |---|---|---|
//! | `String`, `Cow<'static, str>` | text | always |
//! | `bool` | bool | always, 0 or 1 |
//! | `i64` | int | always |
//! | [`Kind`] | kind | a number, or the bytes that name it |
//! | [`Scalar`] | int or text | as the record says |
//! | `u64` | uint | always (one at 2^60 or more is this build's mistake) |
//! | `[u8; N]` | bytes | always; read back only at exactly N bytes |
//! | `Bytes` (`bytes::Bytes`, re-exported) | bytes | always, of any length |
//! | [`Reference`] | ref | text, or an id's bytes |
//! | `Vec<T>` | a list of T | always, empty or not |
//! | a typed record | its record | always |
//! | `Option<T>` | as T | only when it is `Some` |
//! | `Box<T>` | as T | as T: for a record that holds itself |
//! | `n gone name: T` | a number no longer used, once T | never; passed over when read |
//!
//! A field that is not an `Option` is one this service always sends; read
//! back, its absence is an error, as is a value of the wrong type. Fields a
//! later version may add are passed over, as before.
//!
//! A message is read straight from its bytes ([`Wire::read`], a record's
//! [`Fields::read_fields`]), field after field, with no tree between: each
//! field's value is made once, from the bytes, and nothing else is. The
//! checks are the decoder's own ([`Cursor`], which the decoder also reads
//! with) and the tree's, in the same order, so that a message is refused
//! exactly when, and in exactly the words with which, decoding it into the
//! encoding's tree and taking the fields from that refuses it: a message
//! that is not one canonical record is refused for that before any field
//! is (where a field is found wrong first, the rest is checked before it
//! is said); then the first field wrong, in the order of their numbers.
//! The way through the tree ([`Wire::take`], [`Fields::take_fields`],
//! [`read_reply_tree`]) is kept, as what the direct reading is held to.

use std::borrow::Cow;
use std::fmt;

use cardinal_encoding::varint::varint_len;
use cardinal_encoding::{check_record, write_varint, Cursor, DecodeError, Head, Major};
use cardinal_encoding::{Record, Value};

use crate::table::{Field, Request, Ty};
use crate::{page_room, status, Page, Refused, MAX_MESSAGE, WHY};

// The base encoding's major types (`encoding.md`).
const T_UINT: u64 = 0;
const T_NEG: u64 = 1;
const T_BYTES: u64 = 2;
const T_TEXT: u64 = 3;
const T_LIST: u64 = 4;
const T_RECORD: u64 = 5;

/// The largest integer the base encoding holds, plus one.
const LIMIT: u64 = 1 << 60;

/// The most items a list read is given room for before they are read, as
/// the decoder does (`cardinal_encoding`'s codec).
const MOST_RESERVED: usize = 256;

#[inline]
pub(crate) fn header(t: u64, n: u64, out: &mut Vec<u8>) {
    varint((n << 3) | t, out);
}

/// A varint, as `write_varint` writes it: the one byte of most inline,
/// the others out of line.
#[inline]
fn varint(v: u64, out: &mut Vec<u8>) {
    if v < 0x80 {
        out.push(v as u8);
    } else {
        long_varint(v, out);
    }
}

#[inline(never)]
fn long_varint(v: u64, out: &mut Vec<u8>) {
    write_varint(v, out);
}

#[inline]
pub(crate) fn header_len(n: u64) -> usize {
    varint_len(n << 3)
}

/// The start of a record of `n` fields.
#[inline]
pub fn record_header(n: u64, out: &mut Vec<u8>) {
    header(T_RECORD, n, out);
}

/// A field's number, before its value.
#[inline]
pub fn key(n: u64, out: &mut Vec<u8>) {
    varint(n, out);
}

/// The length of a field's number.
#[inline]
pub fn key_len(n: u64) -> usize {
    varint_len(n)
}

/// A field's name as the tables give it: its Rust name, without `r#`.
pub const fn field_name(s: &'static str) -> &'static str {
    let b = s.as_bytes();
    if b.len() > 2 && b[0] == b'r' && b[1] == b'#' {
        let (_, rest) = b.split_at(2);
        match std::str::from_utf8(rest) {
            Ok(r) => r,
            Err(_) => panic!("a field's name is text"),
        }
    } else {
        s
    }
}

/// The numbers of a paged reply's list, `more` and `next`, by their names;
/// the build fails without one of them.
pub const fn paged_numbers(fields: &[Field], list: &str) -> [u64; 3] {
    [
        number(fields, list),
        number(fields, "more"),
        number(fields, "next"),
    ]
}

/// The number of the field called `name`; the build fails without one.
pub const fn number(fields: &[Field], name: &str) -> u64 {
    let mut i = 0;
    while i < fields.len() {
        let (a, b) = (fields[i].name.as_bytes(), name.as_bytes());
        if a.len() == b.len() {
            let mut j = 0;
            while j < a.len() && a[j] == b[j] {
                j += 1;
            }
            if j == a.len() {
                return fields[i].n;
            }
        }
        i += 1;
    }
    panic!("a paged reply has its list, `more` and `next`")
}

/// Whether two names are the same, at compile time.
const fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() && a[i] == b[i] {
        i += 1;
    }
    i == a.len()
}

/// Fails the build unless `given` names exactly the fields a record always
/// has, `required`, in the order of their numbers: what
/// [`new!`](crate::new) checks.
pub const fn named(required: &[&'static str], given: &[&'static str]) {
    let mut i = 0;
    while i < required.len() && i < given.len() {
        if !same(field_name(given[i]), required[i]) {
            panic!(
                "new!: give the fields the record always has by their names, each once, in \
                 the order of their numbers (as its declaration lists them)"
            );
        }
        i += 1;
    }
    if given.len() < required.len() {
        panic!("new!: a field the record always has is not given");
    }
    if given.len() > required.len() {
        panic!(
            "new!: a field given is not one the record always has: set it after, \
             as `Name {{ field, ..new!(Name {{ .. }}) }}`"
        );
    }
}

/// Fails the build unless the fields are numbered in order, each once: the
/// order the encoding writes them in.
pub const fn ascending(fields: &[Field]) {
    let mut i = 1;
    while i < fields.len() {
        assert!(
            fields[i - 1].n < fields[i].n,
            "a typed record's fields are declared in the order of their numbers"
        );
        i += 1;
    }
}

/// Where in a message a value is, for an error to say: `files.files[3].name`.
/// Built only along the way down, and written out only on an error.
#[derive(Clone, Copy)]
pub enum At<'a> {
    Top(&'a str),
    Field(&'a At<'a>, &'static str),
    Item(&'a At<'a>, usize),
}

impl fmt::Display for At<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            At::Top(s) => write!(f, "{s}"),
            At::Field(p, name) => write!(f, "{p}.{name}"),
            At::Item(p, i) => write!(f, "{p}[{i}]"),
        }
    }
}

/// A value that has a place in the local interface's records.
pub trait Wire: Sized {
    /// Its type in the tables.
    const TY: Ty;
    /// The type of a list of them in the tables.
    const LIST: Ty = Ty::List(&Self::TY);
    /// Whether it is an `Option`, which only a record's field may be.
    const OPTIONAL: bool = false;
    /// Whether it is sent: an `Option` that is `None` is not.
    #[inline]
    fn sent(&self) -> bool {
        true
    }
    /// Whether the encoding can hold it: an integer it cannot is this
    /// build's mistake, said as the tables by name said it.
    #[inline]
    fn check(&self, _: &At) -> Result<(), String> {
        Ok(())
    }
    /// Appends its encoding.
    fn encode_into(&self, out: &mut Vec<u8>);
    /// The length of its encoding.
    fn encoded_len(&self) -> usize;
    /// The length of its encoding, and whether the encoding can hold it
    /// ([`Wire::check`] passes): both in one pass. A type that overrides
    /// it answers as its `check` would.
    #[inline]
    fn measured(&self) -> (usize, bool) {
        (self.encoded_len(), self.check(&At::Top("")).is_ok())
    }
    /// Reads it from what came, taking what it holds.
    fn take(v: Value, at: &At) -> Result<Self, String>;
    /// Reads it straight from the bytes, as the value at nesting `depth`
    /// (the message itself is 0): what [`Wire::take`] makes of the same
    /// value, or the same refusal ([`Bad`]).
    fn read(c: &mut Cursor<'_>, depth: usize, at: &At) -> Result<Self, Bad>;
    /// What it is when its field did not come.
    fn absent(at: &At) -> Result<Self, String> {
        Err(format!("{at} is missing"))
    }
    /// Of text, where the tests run: itself, if it is not one of `known`,
    /// the values its row names (none, of another type).
    #[cfg(debug_assertions)]
    fn unknown(&self, _known: &[&str]) -> Option<String> {
        None
    }
}

/// Text that is not one of `known`.
#[cfg(debug_assertions)]
fn unknown_text(t: &str, known: &[&str]) -> Option<String> {
    (!known.contains(&t)).then(|| t.to_owned())
}

fn wrong(at: &At, what: &str) -> String {
    format!("{at} should be {what}")
}

/// [`wrong`], as a refusal of the direct reading: said once.
#[cold]
#[inline(never)]
fn bad(at: &At, what: &str) -> Bad {
    Bad::Field(wrong(at, what))
}

/// An unsigned integer whose header is `h`, as [`u64::take`] reads one.
#[inline]
fn uint_of(h: &Head, at: &At) -> Result<u64, Bad> {
    match h.major {
        Major::Uint => Ok(h.n),
        _ => Err(bad(at, "an unsigned integer")),
    }
}

/// An integer whose header is `h`, as [`i64::take`] reads one.
#[inline]
fn int_of(h: &Head, at: &At) -> Result<i64, Bad> {
    match h.major {
        // below 2^60 either way, as the decoder's headers are
        Major::Uint => Ok(h.n as i64),
        Major::Neg => Ok(-1 - h.n as i64),
        _ => Err(bad(at, "an integer")),
    }
}

/// Why a message could not be read straight from its bytes: what the way
/// through the tree refuses it with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bad {
    /// It is not one canonical record: the decoder's error, which the
    /// tree's decoding refuses it with first.
    Form(DecodeError),
    /// A field is not what its row says, or one always sent is missing:
    /// in the words the tree's reading says it in.
    Field(String),
}

impl From<DecodeError> for Bad {
    #[inline]
    fn from(e: DecodeError) -> Bad {
        Bad::Form(e)
    }
}

impl fmt::Display for Bad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bad::Form(e) => write!(f, "not one record: {e}"),
            Bad::Field(why) => f.write_str(why),
        }
    }
}

/// A record being read straight from the bytes, field after field in the
/// order of their numbers, as its declaration lists them
/// ([`Fields::read_fields`]): the keys that come before a field asked for
/// (one this build does not know, or a number no longer used) are passed
/// over, checked as the decoder checks them.
pub struct Walk<'c, 'a> {
    c: &'c mut Cursor<'a>,
    /// The record's own nesting; its fields are one deeper.
    depth: usize,
    /// Fields not yet come to.
    left: usize,
    /// The key read last, whose value comes next, if any is left.
    next: Option<u64>,
}

impl<'c, 'a> Walk<'c, 'a> {
    /// A record whose header `h` was just read, at nesting `depth`.
    #[inline(never)]
    pub fn start(c: &'c mut Cursor<'a>, h: &Head, depth: usize) -> Result<Self, Bad> {
        let left = c.count(h, depth)?;
        let mut w = Walk {
            c,
            depth,
            left,
            next: None,
        };
        w.key()?;
        Ok(w)
    }

    /// Reads the next field's key, if one is left.
    #[inline]
    fn key(&mut self) -> Result<(), DecodeError> {
        let last = self.next;
        self.next = match self.left {
            0 => None,
            _ => {
                self.left -= 1;
                Some(self.c.key(last)?)
            }
        };
        Ok(())
    }

    /// Passes over the fields numbered below `n`: whether the next is
    /// numbered `n`, its value then the next thing read.
    #[inline(never)]
    pub fn to(&mut self, n: u64) -> Result<bool, Bad> {
        while let Some(k) = self.next {
            if k >= n {
                return Ok(k == n);
            }
            self.c.skip(self.depth + 1)?;
            self.key()?;
        }
        Ok(false)
    }

    /// The value of field `n`, which [`Walk::to`] came to, read by `read`.
    #[inline]
    fn value<T>(
        &mut self,
        read: impl FnOnce(&mut Cursor<'a>, usize) -> Result<T, Bad>,
    ) -> Result<T, Bad> {
        let v = read(self.c, self.depth + 1)?;
        self.key()?;
        Ok(v)
    }

    /// Passes over the fields left, to the end of the record.
    #[inline(never)]
    pub fn finish(mut self) -> Result<(), Bad> {
        self.to(u64::MAX).map(drop)
    }
}

/// Reads field `row` of the record `w` is in, straight from the bytes, as
/// [`take_field`] reads it from the tree: once per field type.
#[inline(never)]
pub fn read_field<T: Wire>(w: &mut Walk, row: &'static Field, at: &At) -> Result<T, Bad> {
    let at = At::Field(at, row.name);
    if w.to(row.n)? {
        w.value(|c, depth| T::read(c, depth, &at))
    } else {
        T::absent(&at).map_err(Bad::Field)
    }
}

/// A typed record held in another, read straight from the bytes.
#[inline]
pub fn record_read<R: Fields>(c: &mut Cursor<'_>, depth: usize, at: &At) -> Result<R, Bad> {
    let h = c.head()?;
    let mut w = record_walk(c, &h, depth, at)?;
    let r = R::read_fields(&mut w, at)?;
    w.finish()?;
    Ok(r)
}

/// The walk of a record whose header `h` was just read, or why it is no
/// record: written once.
#[inline(never)]
fn record_walk<'c, 'a>(
    c: &'c mut Cursor<'a>,
    h: &Head,
    depth: usize,
    at: &At,
) -> Result<Walk<'c, 'a>, Bad> {
    if h.major != Major::Record {
        return Err(Bad::Field(format!("{at} should be a record")));
    }
    Walk::start(c, h, depth)
}

/// Reads a whole message straight from its bytes: `body` reads its
/// fields, on the walk through its record; then the rest is passed over,
/// and nothing may follow. Its refusal is the tree's: where a field is
/// found wrong, the whole message is checked first, and if it is not one
/// canonical record that is said instead, as decoding it whole first says
/// it.
#[inline]
pub fn read_message<T>(
    msg: &[u8],
    body: impl FnOnce(&mut Walk) -> Result<T, Bad>,
) -> Result<T, Bad> {
    let mut c = Cursor::new(msg);
    let got = match opened(&mut c, msg) {
        Ok(mut w) => match body(&mut w) {
            Ok(v) => closed(w).map(|()| v),
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    };
    got.map_err(|e| settled(msg, e))
}

/// The walk through a message's record, or why it is none.
#[inline(never)]
fn opened<'c, 'a>(c: &'c mut Cursor<'a>, msg: &[u8]) -> Result<Walk<'c, 'a>, Bad> {
    let h = c.head()?;
    if h.major != Major::Record {
        // the tree's decoding says first what else is wrong with it
        return Err(Bad::Form(check_record(msg).err().unwrap_or(
            DecodeError::NotARecord {
                found: h.major.name(),
            },
        )));
    }
    Walk::start(c, &h, 0)
}

/// The rest of a message's record passed over, and nothing after it.
#[inline(never)]
fn closed(mut w: Walk) -> Result<(), Bad> {
    w.to(u64::MAX)?;
    w.c.end()?;
    Ok(())
}

/// A refusal, as the tree's: a field found wrong is said only if the
/// whole message is one canonical record.
#[cold]
#[inline(never)]
fn settled(msg: &[u8], e: Bad) -> Bad {
    match e {
        Bad::Field(why) => match check_record(msg) {
            Err(form) => Bad::Form(form),
            Ok(()) => Bad::Field(why),
        },
        form => form,
    }
}

impl Wire for String {
    const TY: Ty = Ty::Text;
    #[cfg(debug_assertions)]
    fn unknown(&self, known: &[&str]) -> Option<String> {
        unknown_text(self, known)
    }
    #[inline]
    fn encode_into(&self, out: &mut Vec<u8>) {
        header(T_TEXT, self.len() as u64, out);
        out.extend_from_slice(self.as_bytes());
    }
    #[inline]
    fn encoded_len(&self) -> usize {
        header_len(self.len() as u64) + self.len()
    }
    fn take(v: Value, at: &At) -> Result<Self, String> {
        match v {
            Value::Text(t) => Ok(t),
            _ => Err(wrong(at, "text")),
        }
    }
    #[inline]
    fn read(c: &mut Cursor<'_>, _: usize, at: &At) -> Result<Self, Bad> {
        let h = c.head()?;
        match h.major {
            Major::Text => Ok(c.text(&h)?.to_owned()),
            _ => Err(bad(at, "text")),
        }
    }
}

impl Wire for Cow<'static, str> {
    const TY: Ty = Ty::Text;
    #[cfg(debug_assertions)]
    fn unknown(&self, known: &[&str]) -> Option<String> {
        unknown_text(self, known)
    }
    #[inline]
    fn encode_into(&self, out: &mut Vec<u8>) {
        header(T_TEXT, self.len() as u64, out);
        out.extend_from_slice(self.as_bytes());
    }
    #[inline]
    fn encoded_len(&self) -> usize {
        header_len(self.len() as u64) + self.len()
    }
    fn take(v: Value, at: &At) -> Result<Self, String> {
        String::take(v, at).map(Cow::Owned)
    }
    #[inline]
    fn read(c: &mut Cursor<'_>, depth: usize, at: &At) -> Result<Self, Bad> {
        String::read(c, depth, at).map(Cow::Owned)
    }
}

impl Wire for bool {
    const TY: Ty = Ty::Bool;
    #[inline]
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(if *self { 1 << 3 } else { 0 });
    }
    #[inline]
    fn encoded_len(&self) -> usize {
        1
    }
    fn take(v: Value, at: &At) -> Result<Self, String> {
        v.as_bool().ok_or_else(|| wrong(at, "0 or 1"))
    }
    #[inline]
    fn read(c: &mut Cursor<'_>, _: usize, at: &At) -> Result<Self, Bad> {
        match c.head()? {
            Head {
                major: Major::Uint,
                n: n @ (0 | 1),
                ..
            } => Ok(n == 1),
            _ => Err(bad(at, "0 or 1")),
        }
    }
}

impl Wire for u64 {
    const TY: Ty = Ty::Uint;
    fn check(&self, at: &At) -> Result<(), String> {
        if *self < LIMIT {
            Ok(())
        } else {
            Err(format!("{at} should be below 2^60, not {self}"))
        }
    }
    /// Only one [`Wire::check`] passed is written: the reply's own fields
    /// are checked before, and the others are no reply's.
    #[inline]
    fn encode_into(&self, out: &mut Vec<u8>) {
        header(T_UINT, (*self).min(LIMIT - 1), out);
    }
    #[inline]
    fn encoded_len(&self) -> usize {
        header_len(*self)
    }
    #[inline]
    fn measured(&self) -> (usize, bool) {
        (header_len(*self), *self < LIMIT)
    }
    fn take(v: Value, at: &At) -> Result<Self, String> {
        v.as_uint().ok_or_else(|| wrong(at, "an unsigned integer"))
    }
    #[inline]
    fn read(c: &mut Cursor<'_>, _: usize, at: &At) -> Result<Self, Bad> {
        let h = c.head()?;
        uint_of(&h, at)
    }
}

impl<const N: usize> Wire for [u8; N] {
    const TY: Ty = Ty::BytesOf(N);
    #[inline]
    fn encode_into(&self, out: &mut Vec<u8>) {
        header(T_BYTES, N as u64, out);
        out.extend_from_slice(self);
    }
    #[inline]
    fn encoded_len(&self) -> usize {
        header_len(N as u64) + N
    }
    fn take(v: Value, at: &At) -> Result<Self, String> {
        match v {
            Value::Bytes(b) => b.try_into().map_err(|_| wrong(at, &format!("{N} bytes"))),
            _ => Err(wrong(at, "bytes")),
        }
    }
    #[inline]
    fn read(c: &mut Cursor<'_>, _: usize, at: &At) -> Result<Self, Bad> {
        let h = c.head()?;
        match h.major {
            Major::Bytes => c
                .bytes(&h)?
                .try_into()
                .map_err(|_| Bad::Field(wrong(at, &format!("{N} bytes")))),
            _ => Err(bad(at, "bytes")),
        }
    }
}

impl Wire for bytes::Bytes {
    const TY: Ty = Ty::Bytes;
    #[inline]
    fn encode_into(&self, out: &mut Vec<u8>) {
        header(T_BYTES, self.len() as u64, out);
        out.extend_from_slice(self);
    }
    #[inline]
    fn encoded_len(&self) -> usize {
        header_len(self.len() as u64) + self.len()
    }
    fn take(v: Value, at: &At) -> Result<Self, String> {
        match v {
            Value::Bytes(b) => Ok(b.into()),
            _ => Err(wrong(at, "bytes")),
        }
    }
    #[inline]
    fn read(c: &mut Cursor<'_>, _: usize, at: &At) -> Result<Self, Bad> {
        let h = c.head()?;
        match h.major {
            Major::Bytes => Ok(bytes::Bytes::copy_from_slice(c.bytes(&h)?)),
            _ => Err(bad(at, "bytes")),
        }
    }
}

impl Wire for i64 {
    const TY: Ty = Ty::Int;
    fn check(&self, at: &At) -> Result<(), String> {
        if (-(LIMIT as i64)..LIMIT as i64).contains(self) {
            Ok(())
        } else {
            Err(format!("{at} should be within 2^60, not {self}"))
        }
    }
    #[inline]
    fn encode_into(&self, out: &mut Vec<u8>) {
        let v = (*self).clamp(-(LIMIT as i64), LIMIT as i64 - 1);
        if v >= 0 {
            header(T_UINT, v as u64, out);
        } else {
            header(T_NEG, (-1 - v) as u64, out);
        }
    }
    #[inline]
    fn encoded_len(&self) -> usize {
        let v = (*self).clamp(-(LIMIT as i64), LIMIT as i64 - 1);
        header_len(if v >= 0 { v as u64 } else { (-1 - v) as u64 })
    }
    #[inline]
    fn measured(&self) -> (usize, bool) {
        (
            self.encoded_len(),
            (-(LIMIT as i64)..LIMIT as i64).contains(self),
        )
    }
    fn take(v: Value, at: &At) -> Result<Self, String> {
        v.as_int().ok_or_else(|| wrong(at, "an integer"))
    }
    #[inline]
    fn read(c: &mut Cursor<'_>, _: usize, at: &At) -> Result<Self, Bad> {
        let h = c.head()?;
        int_of(&h, at)
    }
}

/// A kind or a profile (`encoding.md#kinds`): a small number, or the bytes
/// that name it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Number(u64),
    Named(bytes::Bytes),
}

impl Wire for Kind {
    const TY: Ty = Ty::Kind;
    fn check(&self, at: &At) -> Result<(), String> {
        match self {
            Kind::Number(n) => n.check(at),
            Kind::Named(_) => Ok(()),
        }
    }
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Kind::Number(n) => n.encode_into(out),
            Kind::Named(b) => b.encode_into(out),
        }
    }
    fn encoded_len(&self) -> usize {
        match self {
            Kind::Number(n) => n.encoded_len(),
            Kind::Named(b) => b.encoded_len(),
        }
    }
    fn measured(&self) -> (usize, bool) {
        match self {
            Kind::Number(n) => n.measured(),
            Kind::Named(b) => b.measured(),
        }
    }
    fn take(v: Value, at: &At) -> Result<Self, String> {
        match v {
            Value::Bytes(b) => Ok(Kind::Named(b.into())),
            v => u64::take(v, at).map(Kind::Number),
        }
    }
    fn read(c: &mut Cursor<'_>, _: usize, at: &At) -> Result<Self, Bad> {
        let h = c.head()?;
        match h.major {
            Major::Bytes => Ok(Kind::Named(bytes::Bytes::copy_from_slice(c.bytes(&h)?))),
            _ => uint_of(&h, at).map(Kind::Number),
        }
    }
}

/// An integer or text, as the record it is in says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scalar {
    Int(i64),
    Text(String),
}

impl Wire for Scalar {
    const TY: Ty = Ty::Scalar;
    fn check(&self, at: &At) -> Result<(), String> {
        match self {
            Scalar::Int(n) => n.check(at),
            Scalar::Text(_) => Ok(()),
        }
    }
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Scalar::Int(n) => n.encode_into(out),
            Scalar::Text(t) => t.encode_into(out),
        }
    }
    fn encoded_len(&self) -> usize {
        match self {
            Scalar::Int(n) => n.encoded_len(),
            Scalar::Text(t) => t.encoded_len(),
        }
    }
    fn measured(&self) -> (usize, bool) {
        match self {
            Scalar::Int(n) => n.measured(),
            Scalar::Text(t) => t.measured(),
        }
    }
    fn take(v: Value, at: &At) -> Result<Self, String> {
        match v {
            Value::Text(t) => Ok(Scalar::Text(t)),
            v => i64::take(v, at).map(Scalar::Int),
        }
    }
    fn read(c: &mut Cursor<'_>, _: usize, at: &At) -> Result<Self, Bad> {
        let h = c.head()?;
        match h.major {
            Major::Text => Ok(Scalar::Text(c.text(&h)?.to_owned())),
            _ => int_of(&h, at).map(Scalar::Int),
        }
    }
}

impl<T: Wire> Wire for Option<T> {
    const TY: Ty = {
        assert!(!T::OPTIONAL, "an Option holds no Option");
        T::TY
    };
    const OPTIONAL: bool = true;
    #[inline]
    fn sent(&self) -> bool {
        self.as_ref().is_some_and(Wire::sent)
    }
    #[cfg(debug_assertions)]
    fn unknown(&self, known: &[&str]) -> Option<String> {
        self.as_ref().and_then(|v| v.unknown(known))
    }
    fn check(&self, at: &At) -> Result<(), String> {
        self.as_ref().map_or(Ok(()), |v| v.check(at))
    }
    #[inline]
    fn encode_into(&self, out: &mut Vec<u8>) {
        if let Some(v) = self {
            v.encode_into(out);
        }
    }
    #[inline]
    fn encoded_len(&self) -> usize {
        self.as_ref().map_or(0, Wire::encoded_len)
    }
    #[inline]
    fn measured(&self) -> (usize, bool) {
        self.as_ref().map_or((0, true), Wire::measured)
    }
    fn take(v: Value, at: &At) -> Result<Self, String> {
        T::take(v, at).map(Some)
    }
    #[inline]
    fn read(c: &mut Cursor<'_>, depth: usize, at: &At) -> Result<Self, Bad> {
        T::read(c, depth, at).map(Some)
    }
    fn absent(_: &At) -> Result<Self, String> {
        Ok(None)
    }
}

impl<T: Wire> Wire for Vec<T> {
    const TY: Ty = {
        assert!(
            !T::OPTIONAL,
            "a list's items are never optional: Option is only a record's field"
        );
        T::LIST
    };
    fn check(&self, at: &At) -> Result<(), String> {
        for (i, x) in self.iter().enumerate() {
            x.check(&At::Item(at, i))?;
        }
        Ok(())
    }
    fn encode_into(&self, out: &mut Vec<u8>) {
        header(T_LIST, self.len() as u64, out);
        for x in self {
            x.encode_into(out);
        }
    }
    fn encoded_len(&self) -> usize {
        header_len(self.len() as u64) + self.iter().map(Wire::encoded_len).sum::<usize>()
    }
    fn measured(&self) -> (usize, bool) {
        let (mut len, mut ok) = (header_len(self.len() as u64), true);
        for x in self {
            let (l, o) = x.measured();
            len += l;
            ok &= o;
        }
        (len, ok)
    }
    fn take(v: Value, at: &At) -> Result<Self, String> {
        let Value::List(items) = v else {
            return Err(wrong(at, "a list"));
        };
        // no more room first than the decoder itself keeps for a list
        let mut out = Vec::with_capacity(items.len().min(MOST_RESERVED));
        for (i, x) in items.into_iter().enumerate() {
            out.push(T::take(x, &At::Item(at, i))?);
        }
        Ok(out)
    }
    fn read(c: &mut Cursor<'_>, depth: usize, at: &At) -> Result<Self, Bad> {
        let h = c.head()?;
        if h.major != Major::List {
            return Err(bad(at, "a list"));
        }
        let count = c.count(&h, depth)?;
        // no more room first than the decoder itself keeps for a list
        let mut out = Vec::with_capacity(count.min(MOST_RESERVED));
        for i in 0..count {
            out.push(T::read(c, depth + 1, &At::Item(at, i))?);
        }
        Ok(out)
    }
}

/// A value held on the heap, as a record that holds itself holds itself:
/// on the wire it is the value. Its row is named in the declaration
/// (`n field: Option<Box<T>> as {ROW}`), since a row that holds itself
/// cannot be had from the type.
impl<T: Wire> Wire for Box<T> {
    const TY: Ty = T::TY;
    const LIST: Ty = T::LIST;
    fn sent(&self) -> bool {
        (**self).sent()
    }
    fn check(&self, at: &At) -> Result<(), String> {
        (**self).check(at)
    }
    fn encode_into(&self, out: &mut Vec<u8>) {
        (**self).encode_into(out)
    }
    fn encoded_len(&self) -> usize {
        (**self).encoded_len()
    }
    fn measured(&self) -> (usize, bool) {
        (**self).measured()
    }
    fn take(v: Value, at: &At) -> Result<Self, String> {
        T::take(v, at).map(Box::new)
    }
    fn read(c: &mut Cursor<'_>, depth: usize, at: &At) -> Result<Self, Bad> {
        T::read(c, depth, at).map(Box::new)
    }
}

/// A `ref` (`apps.md`, Types): what a person typed, or the bytes of an id,
/// which only that id answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reference {
    Typed(String),
    Id(Vec<u8>),
}

impl Reference {
    /// The view of it that the lookups take.
    pub fn as_ref(&self) -> crate::Ref<'_> {
        match self {
            Reference::Typed(t) => crate::Ref::Typed(t),
            Reference::Id(b) => crate::Ref::Id(crate::IdGiven::Bytes(b)),
        }
    }
}

impl Reference {
    /// The ref as the handlers not yet given [`crate::Ref`] hold it: text
    /// as it was typed, an id given as bytes as [`crate::EXACT`] then its
    /// hex. Only for those handlers, whose words (an error naming the ref
    /// as it came) are kept as they were.
    pub fn held(&self) -> Cow<'_, str> {
        match self {
            Reference::Typed(t) => Cow::Borrowed(t),
            Reference::Id(b) => Cow::Owned(format!("{}{}", crate::EXACT, crate::hex(b))),
        }
    }
}

impl Wire for Reference {
    const TY: Ty = Ty::Ref;
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Reference::Typed(t) => t.encode_into(out),
            Reference::Id(b) => {
                header(T_BYTES, b.len() as u64, out);
                out.extend_from_slice(b);
            }
        }
    }
    fn encoded_len(&self) -> usize {
        match self {
            Reference::Typed(t) => t.encoded_len(),
            Reference::Id(b) => header_len(b.len() as u64) + b.len(),
        }
    }
    fn take(v: Value, at: &At) -> Result<Self, String> {
        match v {
            Value::Bytes(b) => Ok(Reference::Id(b)),
            Value::Text(t) if t.starts_with(crate::EXACT) => {
                Err(format!("{at} is text that begins with NUL"))
            }
            Value::Text(t) => Ok(Reference::Typed(t)),
            _ => Err(wrong(at, "text or bytes")),
        }
    }
    fn read(c: &mut Cursor<'_>, _: usize, at: &At) -> Result<Self, Bad> {
        let h = c.head()?;
        match h.major {
            Major::Bytes => Ok(Reference::Id(c.bytes(&h)?.to_vec())),
            Major::Text => {
                let t = c.text(&h)?;
                if t.starts_with(crate::EXACT) {
                    return Err(Bad::Field(format!("{at} is text that begins with NUL")));
                }
                Ok(Reference::Typed(t.to_owned()))
            }
            _ => Err(bad(at, "text or bytes")),
        }
    }
}

/// The fields of a typed record, as [`typed!`](crate::typed) writes them:
/// the list of its fields, which the shared code below walks to measure,
/// check and write them ([`Body`]), and reading them back.
///
/// A record's own code is only that list ([`Fields::each`]) and its
/// reading ([`Fields::take_fields`]), each a call per field; what is done
/// with a field is written once per field type, in the visitors here,
/// rather than once per record, which is what keeps the binaries small.
pub trait Fields: Sized {
    /// Every field, numbered, as the tables give them.
    const FIELDS: &'static [Field];
    /// Shows `v` each field this build has, in the order of their
    /// numbers, with its row.
    fn each<V: Visit>(&self, v: &mut V);
    /// The names of the fields it always has, in the order of their
    /// numbers: what [`new!`](crate::new) is given, by name.
    const REQUIRED: &'static [&'static str];
    /// Reads its fields from `r`, taking what they hold; keys this build
    /// does not know are passed over.
    fn take_fields(r: Record, at: &At) -> Result<Self, String>;
    /// Reads its fields straight from the bytes, on the walk through its
    /// record: what [`Fields::take_fields`] makes of the same record, or
    /// the same refusal.
    fn read_fields(w: &mut Walk, at: &At) -> Result<Self, Bad>;
}

/// What is done with each field of a record ([`Fields::each`]), given its
/// row and its value.
pub trait Visit {
    fn field<T: Wire>(&mut self, row: &'static Field, v: &T);
}

/// Counts the fields sent and adds up their encoded lengths, each with
/// its number.
struct Measure<'a> {
    skip: &'a [u64],
    n: u64,
    len: usize,
    /// Whether the encoding can hold every field measured.
    ok: bool,
}

/// Whether `n` is one of the fields left out: rarely any are.
#[inline]
fn skipped(skip: &[u64], n: u64) -> bool {
    !skip.is_empty() && listed(skip, n)
}

#[inline(never)]
fn listed(skip: &[u64], n: u64) -> bool {
    skip.contains(&n)
}

impl Visit for Measure<'_> {
    #[inline(never)]
    fn field<T: Wire>(&mut self, row: &'static Field, v: &T) {
        if v.sent() && !skipped(self.skip, row.n) {
            let (len, ok) = v.measured();
            self.n += 1;
            self.len += key_len(row.n) + len;
            self.ok &= ok;
            // where the tests run, text of a closed set that holds none of
            // its values is said, as this build's mistake; it is sent as it
            // is, as a release build sends it
            #[cfg(debug_assertions)]
            if let Some(t) = v.unknown(row.known).filter(|_| !row.known.is_empty()) {
                mistake(format_args!(
                    "{} is {t:?}, which is none of the values its row names",
                    row.name
                ));
            }
        }
    }
}

/// Writes the fields sent, each after its number, and counts them.
struct Encode<'a> {
    skip: &'a [u64],
    out: &'a mut Vec<u8>,
    n: u64,
}

impl Visit for Encode<'_> {
    #[inline(never)]
    fn field<T: Wire>(&mut self, row: &'static Field, v: &T) {
        if v.sent() && !skipped(self.skip, row.n) {
            key(row.n, self.out);
            v.encode_into(self.out);
            self.n += 1;
        }
    }
}

/// Finds the fields the encoding cannot hold.
struct Invalid<'a> {
    at: &'a At<'a>,
    out: Vec<(u64, &'static str, String)>,
}

impl Visit for Invalid<'_> {
    #[inline(never)]
    fn field<T: Wire>(&mut self, row: &'static Field, v: &T) {
        if v.sent() {
            let at = At::Field(self.at, row.name);
            if let Err(e) = v.check(&at) {
                self.out.push((row.n, row.name, e));
            }
        }
    }
}

/// A record's fields seen without its type: what the shared code that
/// writes a message takes, so that it is written once.
pub trait Body {
    /// How many of its fields are sent, leaving out those numbered in
    /// `skip`; their length, each with its number; and whether the
    /// encoding can hold them all (whether [`Body::invalid`] finds none).
    fn measure(&self, skip: &[u64]) -> (u64, usize, bool);
    /// Writes the encodings of its fields, in order, each after its
    /// number, leaving out those numbered in `skip`: how many.
    fn write(&self, skip: &[u64], out: &mut Vec<u8>) -> u64;
    /// Its fields that the encoding cannot hold, each with why, in the
    /// order of their names: none, unless this build has made a mistake.
    fn invalid(&self, at: &At) -> Vec<(u64, &'static str, String)>;
}

impl<R: Fields> Body for R {
    fn measure(&self, skip: &[u64]) -> (u64, usize, bool) {
        let mut v = Measure {
            skip,
            n: 0,
            len: 0,
            ok: true,
        };
        self.each(&mut v);
        (v.n, v.len, v.ok)
    }
    fn write(&self, skip: &[u64], out: &mut Vec<u8>) -> u64 {
        let mut v = Encode { skip, out, n: 0 };
        self.each(&mut v);
        v.n
    }
    fn invalid(&self, at: &At) -> Vec<(u64, &'static str, String)> {
        let mut v = Invalid {
            at,
            out: Vec::new(),
        };
        self.each(&mut v);
        by_name(v.out)
    }
}

/// Its length as a record of its own, leaving out the fields numbered in
/// `skip`.
pub fn record_len_except(r: &dyn Body, skip: &[u64]) -> usize {
    let (n, len, _) = r.measure(skip);
    header_len(n) + len
}

/// In the order of their names, as the tables by name met them.
/// Stable, and by hand: there are at most a few, and a sort of the
/// standard library's is some 15 KB of code.
fn by_name(mut v: Vec<(u64, &'static str, String)>) -> Vec<(u64, &'static str, String)> {
    for i in 1..v.len() {
        let mut j = i;
        while j > 0 && v[j - 1].1 > v[j].1 {
            v.swap(j - 1, j);
            j -= 1;
        }
    }
    v
}

/// Reads field `row` of a record, taking what it holds: for each
/// record's [`Fields::take_fields`], once per field type.
#[inline(never)]
pub fn take_field<T: Wire>(r: &mut Record, row: &'static Field, at: &At) -> Result<T, String> {
    let at = At::Field(at, row.name);
    match r.remove(row.n) {
        Some(v) => T::take(v, &at),
        None => T::absent(&at),
    }
}

/// The place of the field numbered `n` in `fields`; the build fails
/// without one.
pub const fn index(fields: &[Field], n: u64) -> usize {
    let mut i = 0;
    while i < fields.len() {
        if fields[i].n == n {
            return i;
        }
        i += 1;
    }
    panic!("a typed record's field has its row")
}

/// A typed record held in another (`typed!` with a row): its encoding
/// as a value. The header, which says how many fields follow, is written
/// once they are: one byte is kept for it, as many as a record of fewer
/// than 16 fields needs.
pub fn record_into(r: &dyn Body, out: &mut Vec<u8>) {
    let at = out.len();
    out.push(0);
    let n = r.write(&[], out);
    header_at(at, n, out);
}

/// Writes at `at`, where one byte was kept for it, the header of a record
/// of `n` fields.
fn header_at(at: usize, n: u64, out: &mut Vec<u8>) {
    let h = (n << 3) | T_RECORD;
    if h < 0x80 {
        out[at] = h as u8;
        return;
    }
    // a varint, as `write_varint` writes it, without a vector for it
    let (mut b, mut len, mut v) = ([0u8; 10], 0, h);
    loop {
        b[len] = (v & 0x7f) as u8;
        v >>= 7;
        len += 1;
        if v == 0 {
            break;
        }
        b[len - 1] |= 0x80;
    }
    out.splice(at..at + 1, b[..len].iter().copied());
}

/// The length of a typed record held in another.
pub fn record_len(r: &dyn Body) -> usize {
    let (n, len, _) = r.measure(&[]);
    header_len(n) + len
}

/// The length of a typed record held in another, and whether the
/// encoding can hold it.
pub fn record_measured(r: &dyn Body) -> (usize, bool) {
    let (n, len, ok) = r.measure(&[]);
    (header_len(n) + len, ok)
}

/// Whether a record held in another can be encoded: its first field
/// that cannot, with why.
pub fn record_check(r: &dyn Body, at: &At) -> Result<(), String> {
    match r.invalid(at).into_iter().next() {
        Some((_, _, e)) => Err(e),
        None => Ok(()),
    }
}

/// A record held in another, read back.
pub fn record_take<R: Fields>(v: Value, at: &At) -> Result<R, String> {
    match v {
        Value::Record(r) => R::take_fields(r, at),
        _ => Err(format!("{at} should be a record")),
    }
}

/// A typed request: its arguments are `Self`, and it answers `Reply`.
/// `asks!` (in [`table`](crate::table)) writes it, with how the reply pages, from the
/// declaration; nothing about a request is written twice.
pub trait Ask: Fields + Clone + Send + Sync + 'static {
    /// Its row in [`REQUESTS`](crate::REQUESTS).
    const REQUEST: &'static Request;
    type Reply: Fields + Send;
    /// Whether the connection carries a stream after it, answered by the
    /// connection itself (`watch`, `call-media`).
    const STREAM: bool = false;
    /// Whether answering it changes nothing (`reads`), unless one of
    /// `UNLESS` is given (`reads unless a or b`): as it is declared.
    const READS: bool = false;
    const UNLESS: &'static [&'static str] = &[];
    /// The lists of its reply that come in pages, in turn, each with the
    /// field of its records that names one too large for a message: none
    /// for a reply that comes whole.
    const LISTS: &'static [(&'static str, Option<&'static str>)] = &[];
    /// What its handler answers: the reply, or (of a reply the handler
    /// cuts to the page itself, `precut`) the reply with where its page
    /// begins and how many there are in all, [`Precut`].
    type Answered: Send;

    /// Whether answering it changes nothing, so that it may be answered
    /// twice: where the tests run, by name beside typed, and compared.
    fn reads(&self) -> bool {
        false
    }

    /// The reply as a message: the page asked for, of a paged request.
    fn reply_bytes(&self, reply: Self::Answered) -> Vec<u8>;

    /// Whether it asks for one page itself (a client's).
    fn one_page(&self) -> bool {
        true
    }
    /// The request for the page after `had`, the pages so far, if there
    /// is more.
    fn next_page(&self, _had: &Self::Reply) -> Option<Self> {
        None
    }
    /// Adds `page`'s items to `all`'s, with its `more` and `next`: whether
    /// it had any.
    fn join(_all: &mut Self::Reply, _page: Self::Reply) -> bool {
        false
    }
    /// Every page joined: no `more` or `next` left.
    fn whole(_all: &mut Self::Reply) {}
    /// The same arguments asked past an item too large for a message on
    /// its own, which error 4, `failed`, names (`apps.md`, Pages): with
    /// `after` one more than its place, or `before` its id. None for a
    /// request that does not page, for another error, or for one that names
    /// no item, or one before where this page began.
    fn past(&self, _failed: &Failed) -> Option<Self> {
        None
    }

    /// It as a message, numbered; or why the encoding cannot hold it, as
    /// the tables by name said.
    fn encode(&self) -> Result<Vec<u8>, Unencodable> {
        request_message(Self::REQUEST, self)
    }

    /// Its arguments from a request off the wire, already read as one
    /// record whose key 0 is this request's number: the way through the
    /// tree, which [`Ask::read_request`] is held to.
    fn from_request(r: Record) -> Result<Self, Refused> {
        Self::take_fields(r, &At::Top(Self::REQUEST.name)).map_err(Refused::malformed)
    }

    /// Its arguments from a request's message, whose key 0 is this
    /// request's number ([`crate::request_of`]), read straight from its
    /// bytes: what [`crate::decode_record`] and [`Ask::from_request`] make
    /// of it, or their refusal, in their words.
    fn read_request(msg: &[u8]) -> Result<Self, Refused> {
        read_message(msg, |w| Self::read_fields(w, &At::Top(Self::REQUEST.name))).map_err(malformed)
    }
}

/// A request that could not be read, as error 2.
#[cold]
#[inline(never)]
fn malformed(b: Bad) -> Refused {
    Refused::malformed(b.to_string())
}

/// A message of a stream, typed: an event of `watch` or a frame of
/// `call-media` (`apps.md`, The local interface), whose key 0 says which.
pub trait Streamed: Fields {
    /// Its row in [`EVENTS`](crate::EVENTS) or [`FRAMES`](crate::FRAMES).
    const KIND: &'static Request;

    /// It as a message.
    /// A field the encoding cannot hold is this build's mistake: it is
    /// left out, and said.
    fn message(&self) -> Vec<u8> {
        stream_message(Self::KIND, self)
    }
}

/// A request as a message, numbered; or why the encoding cannot hold it,
/// as the tables by name said.
fn request_message(spec: &Request, args: &dyn Body) -> Result<Vec<u8>, Unencodable> {
    let (n, len, ok) = args.measure(&[]);
    if !ok {
        if let Some((_, _, e)) = args.invalid(&At::Top(spec.name)).first() {
            return Err(Unencodable(e.clone()));
        }
    }
    let mut out = Vec::with_capacity(16 + len);
    header(T_RECORD, 1 + n, &mut out);
    write_varint(0, &mut out);
    spec.n.encode_into(&mut out);
    args.write(&[], &mut out);
    Ok(out)
}

/// A message of a stream: [`Streamed::message`].
fn stream_message(kind: &Request, m: &dyn Body) -> Vec<u8> {
    let (mut n, mut len, ok) = m.measure(&[]);
    let mut skip = Vec::new();
    if !ok {
        let invalid = m.invalid(&At::Top(kind.name));
        skip = invalid.iter().map(|(n, _, _)| *n).collect();
        if let Some((_, _, e)) = invalid.first() {
            mistake(format_args!("{e}; left out"));
        }
        (n, len, _) = m.measure(&skip);
    }
    let mut out = Vec::with_capacity(4 + len);
    header(T_RECORD, 1 + n, &mut out);
    write_varint(0, &mut out);
    kind.n.encode_into(&mut out);
    m.write(&skip, &mut out);
    out
}

/// A reply that says it was done, with `reply`'s fields: as a message. A
/// field the encoding cannot hold is this build's mistake, met as the
/// tables by name met it: where the tests run (a debug build) the request
/// fails, `internal: ...`; elsewhere that field is left out; either way the
/// service says so in its log.
pub fn reply_message<R: Fields>(name: &str, reply: &R) -> Vec<u8> {
    reply_body(name, reply)
}

/// [`reply_message`], written once.
fn reply_body(name: &str, reply: &dyn Body) -> Vec<u8> {
    let (mut n, mut len, ok) = reply.measure(&[]);
    let mut skip = Vec::new();
    if !ok {
        let invalid = reply.invalid(&At::Top(name));
        skip = invalid.iter().map(|(n, _, _)| *n).collect();
        if let Some((_, _, e)) = invalid.first() {
            mistake(format_args!("reply to {name}: {e}"));
            if cfg!(debug_assertions) {
                return crate::error_reply(status::FAILED, &format!("internal: {e}"));
            }
        }
        (n, len, _) = reply.measure(&skip);
    }
    let mut out = Vec::with_capacity(4 + len);
    header(T_RECORD, 1 + n, &mut out);
    write_varint(0, &mut out);
    status::OK.encode_into(&mut out);
    reply.write(&skip, &mut out);
    out
}

/// This build's mistake, a value the encoding cannot hold, said in the
/// log of a program that has one (the `tracing` feature, which the service
/// turns on); a message is written without it either way.
#[inline(never)]
fn mistake(_what: fmt::Arguments) {
    #[cfg(feature = "tracing")]
    tracing::error!("{_what}");
}

/// A request a client could not send: a value of its arguments the
/// encoding cannot hold, said as the tables by name said it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unencodable(pub String);

impl fmt::Display for Unencodable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unencodable {}

/// Where a request paged by position goes on past the item error 4,
/// `failed`, names: one more than its place, where that place is in the
/// page asked for, from `after`.
pub fn past_after(failed: &Failed, after: Option<u64>) -> Option<u64> {
    if failed.status != status::TOO_LARGE {
        return None;
    }
    let at = failed.at.filter(|at| *at >= after.unwrap_or(0))?;
    at.checked_add(1)
}

/// Where a request paged back from the newest goes on past the item error
/// 4, `failed`, names: before its id, where that is not where the page
/// asked for began.
pub fn past_before(failed: &Failed, before: &Option<Reference>) -> Option<Reference> {
    if failed.status != status::TOO_LARGE {
        return None;
    }
    let id = failed.id.as_ref()?;
    match before {
        Some(Reference::Id(b)) if b == id => None,
        _ => Some(Reference::Id(id.clone())),
    }
}

/// What a stream's message's key 0 must be.
const KIND: &str = "key 0 of a stream's message says what it is";

/// The number in a stream's message's key 0, which says what it is: read
/// straight from the bytes.
#[inline(never)]
pub fn kind_of(w: &mut Walk) -> Result<u64, Bad> {
    if !w.to(0)? {
        return Err(Bad::Field(KIND.into()));
    }
    w.value(|c, _| match c.head()? {
        Head {
            major: Major::Uint,
            n,
            ..
        } => Ok(n),
        _ => Err(Bad::Field(KIND.into())),
    })
}

/// A stream's message decoded into the encoding's tree, and its key 0:
/// the way through the tree, which [`kind_of`] is held to.
pub fn stream_record(msg: &[u8]) -> Result<(u64, Record), Unreadable> {
    let r = Record::decode(msg).map_err(|e| Unreadable(format!("not one record: {e}")))?;
    let n = r
        .get(0)
        .and_then(Value::as_uint)
        .ok_or_else(|| Unreadable(KIND.into()))?;
    Ok((n, r))
}

/// A reply that did not do what was asked, as a client reads it: exactly
/// what the reply said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failed {
    pub status: u64,
    /// Key 1, as it came: empty where the service said nothing more. A
    /// client shows it as [`Failed`]'s `Display` does, or words an empty
    /// one its own way.
    pub why: String,
    /// Of error 4 to a paged request: which item was too large.
    pub at: Option<u64>,
    pub id: Option<Vec<u8>>,
}

impl Failed {
    /// Why, for a person: key 1, or, where it is empty, the status's name
    /// (`failed` for a status this build has no name for).
    pub fn words(&self) -> &str {
        match self.why.as_str() {
            "" => status::name(self.status).unwrap_or("failed"),
            why => why,
        }
    }
}

/// [`Failed::words`].
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.words())
    }
}

impl std::error::Error for Failed {}

/// A reply that could not be read: not one record, or not what the
/// request answers (a field it always has missing, or of another type).
/// The service answered; a client says so, and not that none is running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable(pub String);

impl fmt::Display for Unreadable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "could not read the service's reply: {}", self.0)
    }
}

impl std::error::Error for Unreadable {}

impl From<Bad> for Unreadable {
    #[cold]
    fn from(b: Bad) -> Unreadable {
        Unreadable(b.to_string())
    }
}

/// Key 1 of an error's reply, why (`apps.md`, Replies): text, always.
pub static WHY_ROW: Field = Field {
    n: WHY,
    name: "why",
    ty: Ty::Text,
    #[cfg(test)]
    optional: false,
    #[cfg(any(test, debug_assertions))]
    known: &[],
};

/// Where in an error's reply a field is, for what an unreadable one says.
const IN_AN_ERROR: At<'static> = At::Top("error");

/// What a reply's key 0 must be.
const STATUS: &str = "a reply's key 0 is its status";

/// A reply off the wire, read straight from its bytes: what it says, or
/// how it failed. An error is [`Unreadable`], in the words the way
/// through the tree ([`read_reply_tree`]) says it in.
pub fn read_reply<A: Ask>(msg: &[u8]) -> Result<Result<A::Reply, Failed>, Unreadable> {
    read_message(msg, |w| match status_of(w)? {
        status::OK => A::Reply::read_fields(w, &At::Top(A::REQUEST.name)).map(Ok),
        st => refusal(w, st).map(Err),
    })
    .map_err(Unreadable::from)
}

/// A reply's status, key 0, read straight from the bytes.
#[inline(never)]
fn status_of(w: &mut Walk) -> Result<u64, Bad> {
    if !w.to(0)? {
        return Err(Bad::Field(STATUS.into()));
    }
    w.value(|c, _| match c.head()? {
        Head {
            major: Major::Uint,
            n,
            ..
        } => Ok(n),
        _ => Err(Bad::Field(STATUS.into())),
    })
}

/// An error's reply after its status, read straight from the bytes: why,
/// and what more it says ([`ErrorMore`](crate::table::ErrorMore)).
#[cold]
#[inline(never)]
fn refusal(w: &mut Walk, status: u64) -> Result<Failed, Bad> {
    let why = read_field::<String>(w, &WHY_ROW, &IN_AN_ERROR)?;
    let more = crate::table::ErrorMore::read_fields(w, &IN_AN_ERROR)?;
    Ok(failed(status, why, more))
}

fn failed(status: u64, why: String, more: crate::table::ErrorMore) -> Failed {
    Failed {
        status,
        why,
        at: more.at,
        id: more.id.map(|b| b.to_vec()),
    }
}

/// A reply off the wire, read the way through the encoding's tree: the
/// message decoded whole into its `Record`, then each field taken from it.
/// What [`read_reply`] is held to, in the tests; nothing else needs it.
pub fn read_reply_tree<A: Ask>(msg: &[u8]) -> Result<Result<A::Reply, Failed>, Unreadable> {
    match reply_record(msg)? {
        Ok(r) => A::Reply::take_fields(r, &At::Top(A::REQUEST.name))
            .map(Ok)
            .map_err(Unreadable),
        Err(failed) => Ok(Err(failed)),
    }
}

/// A reply off the wire, decoded into the encoding's tree and read as far
/// as its status: the record of what it says, without why, or how it
/// failed. An error is [`Unreadable`].
pub fn reply_record(msg: &[u8]) -> Result<Result<Record, Failed>, Unreadable> {
    let unreadable = Unreadable;
    let mut r = Record::decode(msg).map_err(|e| unreadable(format!("not one record: {e}")))?;
    let st = r
        .remove(0)
        .and_then(|v| v.as_uint())
        .ok_or_else(|| unreadable(STATUS.into()))?;
    if st != status::OK {
        let why = take_field::<String>(&mut r, &WHY_ROW, &IN_AN_ERROR).map_err(Unreadable)?;
        let more = crate::table::ErrorMore::take_fields(r, &IN_AN_ERROR).map_err(Unreadable)?;
        return Ok(Err(failed(st, why, more)));
    }
    r.remove(WHY);
    Ok(Ok(r))
}

/// A reply that did not do what was asked: its status, why, and what more
/// an error says ([`ErrorMore`](crate::table::ErrorMore)), as a message.
pub fn error_message(status: u64, why: &str, more: &crate::table::ErrorMore) -> Vec<u8> {
    let (n, len, _) = Body::measure(more, &[]);
    let mut out = Vec::with_capacity(8 + why.len() + len);
    header(T_RECORD, 2 + n, &mut out);
    write_varint(0, &mut out);
    status.encode_into(&mut out);
    write_varint(WHY, &mut out);
    header(T_TEXT, why.len() as u64, &mut out);
    out.extend_from_slice(why.as_bytes());
    Body::write(more, &[], &mut out);
    out
}

/// An error that says which item of a paged answer was too large for a
/// message on its own (`apps.md`, Errors).
pub fn too_large_message(why: &str, at: u64, id: Option<&[u8]>) -> Vec<u8> {
    let more = crate::table::ErrorMore {
        at: Some(at),
        id: id.map(bytes::Bytes::copy_from_slice),
    };
    error_message(status::TOO_LARGE, why, &more)
}

/// A paged answer cut to its page, or the item that cannot be given.
pub struct Cut {
    /// Whether there is more after (or, back from the newest, before) it.
    pub more: bool,
    /// The cursor of the next page: `after` counts as a number, `before`
    /// as the id of the oldest item had.
    pub next: Option<u64>,
}

/// An answer too large to give, as a message.
pub struct Unpaged(pub Vec<u8>);

/// What a page may hold beside a reply's other fields: as the old pager
/// counted, so the pages are the same.
fn room(spec: &Request, base: usize) -> usize {
    MAX_MESSAGE.saturating_sub(base + page_room(spec))
}

/// Error 4 for item `at` of `list`, `n` bytes, too large for a message
/// beside the rest of the answer, by its place and its `id` where its
/// records have one.
pub fn too_large(spec: &Request, list: &str, at: usize, n: usize, id: Option<&[u8]>) -> Unpaged {
    let why = format!(
        "item {at} of {list} is {n} bytes, more than a message may hold beside the rest of the \
         answer to {}",
        spec.name
    );
    Unpaged(too_large_message(&why, at as u64, id))
}

/// Cuts `items`, the one list of a reply paged by position, to the page
/// asked for (`apps.md`, Pages): from `after` on, at most `limit` items,
/// and as many as fit in a message beside the reply's other fields, whose
/// length is `base`. An item too large for a message alone is error 4,
/// which says which, by its place and its `id` where it has one.
pub fn page_after<T: Wire>(
    spec: &Request,
    list: &str,
    items: &mut Vec<T>,
    base: usize,
    after: Option<u64>,
    limit: Option<u64>,
    id: impl Fn(&T) -> Option<&[u8]>,
) -> Result<Cut, Unpaged> {
    debug_assert_eq!(spec.page, Page::After);
    let start = after.unwrap_or(0) as usize;
    let all = items.len();
    let taken = cut_forward(
        spec,
        list,
        (start, all, start),
        base,
        limit,
        &|i| items[i].encoded_len(),
        &|i| id(&items[i]),
    )?;
    items.drain(..start.min(all));
    items.truncate(taken);
    let at = start + taken;
    let more = at < all;
    Ok(Cut {
        more,
        next: more.then_some(at as u64),
    })
}

/// A reply its handler cut itself: the items from `from` on, rendered for
/// the page asked for and no further, of `total` in all. The page is then
/// cut to what fits, as the old pager cut a reply that said `_page_from`
/// and `_page_total`.
pub struct Precut<R> {
    pub reply: R,
    pub from: u64,
    pub total: u64,
}

/// Cuts `items`, the one list of a reply the handler cut itself, from its
/// item `from` of `total`, to the page asked for: as [`page_after`], and
/// with the arithmetic the old pager had for it (`api::page`, with
/// `_page_from` and `_page_total`).
#[allow(clippy::too_many_arguments)]
pub fn page_precut<T: Wire>(
    spec: &Request,
    list: &str,
    items: &mut Vec<T>,
    base: usize,
    after: Option<u64>,
    limit: Option<u64>,
    from: u64,
    total: u64,
    id: impl Fn(&T) -> Option<&[u8]>,
) -> Result<Cut, Unpaged> {
    debug_assert_eq!(spec.page, Page::After);
    let from = from as usize;
    let start = (after.unwrap_or(0) as usize).max(from);
    let len = items.len();
    let all = (total as usize).max(from + len);
    let skip = start - from;
    let taken = cut_forward(
        spec,
        list,
        (skip, len, start),
        base,
        limit,
        &|i| items[i].encoded_len(),
        &|i| id(&items[i]),
    )?;
    items.drain(..skip.min(len));
    items.truncate(taken);
    let at = start + taken;
    let more = at < all;
    Ok(Cut {
        more,
        next: more.then_some(at as u64),
    })
}

/// Cuts `items`, the one list of a reply paged back from the newest, to
/// the page asked for: the newest of them, at most `limit`, and as many as
/// fit; oldest first. `next` is then the place of the oldest given, which
/// the caller turns into its id.
pub fn page_before<T: Wire>(
    spec: &Request,
    list: &str,
    items: &mut Vec<T>,
    base: usize,
    limit: Option<u64>,
    id: impl Fn(&T) -> Option<&[u8]>,
) -> Result<bool, Unpaged> {
    debug_assert!(matches!(spec.page, Page::Before { .. }));
    let taken = cut_back(
        spec,
        list,
        items.len(),
        base,
        limit,
        &|i| items[i].encoded_len(),
        &|i| id(&items[i]),
    )?;
    let left = items.len() - taken;
    items.drain(..left);
    Ok(left > 0)
}

/// How many of the items `first` up to `len` (by their place in the list)
/// fit in a page, at most `limit`, beside the reply's other fields, whose
/// length is `base`; or error 4 for the first, at `place` in the answer,
/// if it does not fit alone. Written once for every list.
fn cut_forward<'a>(
    spec: &Request,
    list: &str,
    (first, len, place): (usize, usize, usize),
    base: usize,
    limit: Option<u64>,
    len_of: &dyn Fn(usize) -> usize,
    id_of: &dyn Fn(usize) -> Option<&'a [u8]>,
) -> Result<usize, Unpaged> {
    let limit = limit.filter(|n| *n > 0).map_or(usize::MAX, |n| n as usize);
    let room = room(spec, base);
    let (mut used, mut taken) = (0usize, 0usize);
    for i in first..len {
        if taken >= limit {
            break;
        }
        let n = len_of(i);
        if used + n > room {
            if taken == 0 {
                return Err(too_large(spec, list, place, n, id_of(i)));
            }
            break;
        }
        used += n;
        taken += 1;
    }
    Ok(taken)
}

/// How many of the `len` items, newest (last) first, fit in a page, as
/// [`cut_forward`]; error 4 names the newest.
fn cut_back<'a>(
    spec: &Request,
    list: &str,
    len: usize,
    base: usize,
    limit: Option<u64>,
    len_of: &dyn Fn(usize) -> usize,
    id_of: &dyn Fn(usize) -> Option<&'a [u8]>,
) -> Result<usize, Unpaged> {
    let limit = limit.filter(|n| *n > 0).map_or(usize::MAX, |n| n as usize);
    let room = room(spec, base);
    let (mut used, mut taken) = (0usize, 0usize);
    for i in (0..len).rev() {
        if taken >= limit {
            break;
        }
        let n = len_of(i);
        if used + n > room {
            if taken == 0 {
                return Err(too_large(spec, list, len - 1, n, id_of(i)));
            }
            break;
        }
        used += n;
        taken += 1;
    }
    Ok(taken)
}

/// A list of a reply paged by position through several lists in turn: a
/// list always sent, or one sent only when it is `Some`.
pub trait PagedList {
    /// What it lists.
    type Item;
    /// How many it holds.
    fn count(&self) -> usize;
    /// Its item `i`.
    fn item(&self, i: usize) -> Option<&Self::Item>;
    /// Each item's encoded length, in order, after those of the lists
    /// before, each with its list's name.
    fn lens(&self, name: &'static str, out: &mut Vec<(&'static str, usize)>);
    /// Keeps of it what falls in the page: the items `start` to `start +
    /// taken` of all the lists together, where this one's begin at `at`,
    /// which is moved past it.
    fn keep(&mut self, at: &mut usize, start: usize, taken: usize);
    /// Adds a page's items after its own; whether there were any.
    fn extend_with(&mut self, page: Self) -> bool;
}

impl<T: Wire> PagedList for Vec<T> {
    type Item = T;
    fn count(&self) -> usize {
        self.len()
    }
    fn item(&self, i: usize) -> Option<&T> {
        self.get(i)
    }
    fn lens(&self, name: &'static str, out: &mut Vec<(&'static str, usize)>) {
        out.extend(self.iter().map(|x| (name, x.encoded_len())));
    }
    fn keep(&mut self, at: &mut usize, start: usize, taken: usize) {
        let (from, len) = (*at, self.len());
        *at += len;
        let lo = start.clamp(from, from + len) - from;
        let hi = (start + taken).clamp(from, from + len) - from;
        self.truncate(hi);
        self.drain(..lo);
    }
    fn extend_with(&mut self, page: Self) -> bool {
        let grew = !page.is_empty();
        self.extend(page);
        grew
    }
}

impl<T: Wire> PagedList for Option<Vec<T>> {
    type Item = T;
    fn count(&self) -> usize {
        self.as_ref().map_or(0, Vec::len)
    }
    fn item(&self, i: usize) -> Option<&T> {
        self.as_ref().and_then(|v| v.get(i))
    }
    fn lens(&self, name: &'static str, out: &mut Vec<(&'static str, usize)>) {
        if let Some(v) = self {
            v.lens(name, out);
        }
    }
    fn keep(&mut self, at: &mut usize, start: usize, taken: usize) {
        if let Some(v) = self {
            v.keep(at, start, taken);
        }
    }
    fn extend_with(&mut self, page: Self) -> bool {
        match (self.as_mut(), page) {
            (_, None) => false,
            (Some(v), Some(p)) => v.extend_with(p),
            (None, Some(p)) => {
                let grew = !p.is_empty();
                *self = Some(p);
                grew
            }
        }
    }
}

/// Cuts a reply paged by position through several lists in turn, as the
/// old pager did (`api::page`): `items` are every item's list and length,
/// the lists one after another in the order of their numbers; from
/// `after` on, at most `limit` of them, and as many as fit beside the
/// reply's other fields, whose length is `base`. The page is the items
/// from the first returned, as many as the second; an item too large for
/// a message alone is [`TooLarge`], to be said as error 4, by its place
/// and its id where its list's records have one.
pub fn cut_after(
    spec: &Request,
    items: &[(&'static str, usize)],
    base: usize,
    after: Option<u64>,
    limit: Option<u64>,
) -> Result<(usize, usize, Cut), TooLarge> {
    debug_assert_eq!(spec.page, Page::After);
    let limit = limit.filter(|n| *n > 0).map_or(usize::MAX, |n| n as usize);
    let start = after.unwrap_or(0) as usize;
    let all = items.len();
    let room = room(spec, base);
    let (mut used, mut taken) = (0usize, 0usize);
    for &(list, n) in items.iter().skip(start) {
        if taken >= limit {
            break;
        }
        if used + n > room {
            if taken == 0 {
                return Err(TooLarge { list, at: start, n });
            }
            break;
        }
        used += n;
        taken += 1;
    }
    let at = start + taken;
    let more = at < all;
    Ok((
        start,
        taken,
        Cut {
            more,
            next: more.then_some(at as u64),
        },
    ))
}

/// An item of a reply paged through several lists in turn too large for a
/// message beside the rest of the answer: its list, its place among all
/// the lists' items, and its length.
pub struct TooLarge {
    pub list: &'static str,
    pub at: usize,
    pub n: usize,
}
