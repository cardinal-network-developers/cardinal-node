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
//! | `bytes::Bytes` | bytes | always, of any length; taken without a copy |
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

use std::borrow::Cow;
use std::fmt;

use cardinal_encoding::varint::varint_len;
use cardinal_encoding::{write_varint, Record, Value};

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
    /// What it is when its field did not come.
    fn absent(at: &At) -> Result<Self, String> {
        Err(format!("{at} is missing"))
    }
}

fn wrong(at: &At, what: &str) -> String {
    format!("{at} should be {what}")
}

impl Wire for String {
    const TY: Ty = Ty::Text;
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
}

impl Wire for Cow<'static, str> {
    const TY: Ty = Ty::Text;
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
    /// Reads its fields from `r`, taking what they hold; keys this build
    /// does not know are passed over.
    fn take_fields(r: Record, at: &At) -> Result<Self, String>;
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

    /// It as a message, numbered; or why the encoding cannot hold it, as
    /// the tables by name said.
    fn encode(&self) -> Result<Vec<u8>, Unencodable> {
        request_message(Self::REQUEST, self)
    }

    /// Its arguments from a request off the wire, already read as one
    /// record whose key 0 is this request's number.
    fn from_request(r: Record) -> Result<Self, Refused> {
        Self::take_fields(r, &At::Top(Self::REQUEST.name)).map_err(Refused::malformed)
    }
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

/// A reply that did not do what was asked, as a client reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failed {
    pub status: u64,
    pub why: String,
    /// Of error 4 to a paged request: which item was too large.
    pub at: Option<u64>,
    pub id: Option<Vec<u8>>,
}

impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.why)
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

/// A reply off the wire: what it says, or how it failed. An error is
/// [`Unreadable`].
pub fn read_reply<A: Ask>(msg: &[u8]) -> Result<Result<A::Reply, Failed>, Unreadable> {
    match reply_record(msg)? {
        Ok(r) => A::Reply::take_fields(r, &At::Top(A::REQUEST.name))
            .map(Ok)
            .map_err(Unreadable),
        Err(failed) => Ok(Err(failed)),
    }
}

/// A reply off the wire, read as far as its status: the record of what
/// it says, without why, or how it failed. An error is [`Unreadable`].
pub fn reply_record(msg: &[u8]) -> Result<Result<Record, Failed>, Unreadable> {
    let unreadable = Unreadable;
    let mut r = Record::decode(msg).map_err(|e| unreadable(format!("not one record: {e}")))?;
    let st = r
        .remove(0)
        .and_then(|v| v.as_uint())
        .ok_or_else(|| unreadable("a reply's key 0 is its status".into()))?;
    if st != status::OK {
        let why = match r.remove(WHY) {
            Some(Value::Text(t)) if !t.is_empty() => t,
            _ => status::name(st).unwrap_or("failed").to_owned(),
        };
        let at = r.get(2).and_then(Value::as_uint);
        let id = match r.remove(3) {
            Some(Value::Bytes(b)) => Some(b),
            _ => None,
        };
        return Ok(Err(Failed {
            status: st,
            why,
            at,
            id,
        }));
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
