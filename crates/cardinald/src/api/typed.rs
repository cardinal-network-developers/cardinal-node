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
//! | `u64` | uint | always (one at 2^60 or more is this build's mistake) |
//! | `[u8; N]` | bytes | always; read back only at exactly N bytes |
//! | `bytes::Bytes` | bytes | always, of any length; taken without a copy |
//! | [`Reference`] | ref | text, or an id's bytes |
//! | `Vec<T>` | a list of T | always, empty or not |
//! | a typed record | its record | always |
//! | `Option<T>` | as T | only when it is `Some` |
//! | [`Gone<T>`] | a number no longer used, once T | never; passed over when read |
//!
//! A field that is not an `Option` is one this service always sends; read
//! back, its absence is an error, as is a value of the wrong type. Fields a
//! later version may add are passed over, as before.

use std::borrow::Cow;
use std::fmt;

use cardinal_encoding::varint::varint_len;
use cardinal_encoding::{write_varint, Record, Value};

use super::table::{Field, Request, Ty};
use super::{page_room, status, Page, Refused, WHY};
use crate::transport::MAX_MESSAGE;

// The base encoding's major types (`encoding.md`).
const T_UINT: u64 = 0;
const T_BYTES: u64 = 2;
const T_TEXT: u64 = 3;
const T_LIST: u64 = 4;
const T_RECORD: u64 = 5;

/// The largest integer the base encoding holds, plus one.
const LIMIT: u64 = 1 << 60;

#[inline]
pub(crate) fn header(t: u64, n: u64, out: &mut Vec<u8>) {
    write_varint((n << 3) | t, out);
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
    write_varint(n, out);
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
    /// Whether it is sent: an `Option` that is `None` is not.
    #[inline]
    fn sent(&self) -> bool {
        true
    }
    /// Appends its encoding.
    fn encode_into(&self, out: &mut Vec<u8>);
    /// The length of its encoding.
    fn encoded_len(&self) -> usize;
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
    /// One the encoding cannot hold is this build's mistake: it is left
    /// out, and said, as the service did with a field without a number.
    fn sent(&self) -> bool {
        if *self < LIMIT {
            return true;
        }
        tracing::error!("{self} is too large for the local interface; left out");
        debug_assert!(false, "{self} is too large for the local interface");
        false
    }
    #[inline]
    fn encode_into(&self, out: &mut Vec<u8>) {
        header(T_UINT, *self, out);
    }
    #[inline]
    fn encoded_len(&self) -> usize {
        header_len(*self)
    }
    fn take(v: Value, at: &At) -> Result<Self, String> {
        v.as_uint().ok_or_else(|| wrong(at, "an unsigned integer"))
    }
}

impl<const N: usize> Wire for [u8; N] {
    const TY: Ty = Ty::Bytes;
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

/// A field whose number is no longer used (`Ty::Gone`): it keeps its row
/// in the tables, with the type it had, and is never sent; what comes
/// under it is passed over, as fields a later version adds are.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gone<T>(std::marker::PhantomData<T>);

impl<T: Wire> Wire for Gone<T> {
    const TY: Ty = Ty::Gone(&T::TY);
    #[inline]
    fn sent(&self) -> bool {
        false
    }
    #[inline]
    fn encode_into(&self, _: &mut Vec<u8>) {}
    #[inline]
    fn encoded_len(&self) -> usize {
        0
    }
    fn take(_: Value, _: &At) -> Result<Self, String> {
        Ok(Gone(std::marker::PhantomData))
    }
    fn absent(_: &At) -> Result<Self, String> {
        Ok(Gone(std::marker::PhantomData))
    }
}

impl<T: Wire> Wire for Option<T> {
    const TY: Ty = T::TY;
    const LIST: Ty = T::LIST;
    #[inline]
    fn sent(&self) -> bool {
        self.as_ref().is_some_and(Wire::sent)
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
    fn take(v: Value, at: &At) -> Result<Self, String> {
        T::take(v, at).map(Some)
    }
    fn absent(_: &At) -> Result<Self, String> {
        Ok(None)
    }
}

impl<T: Wire> Wire for Vec<T> {
    const TY: Ty = T::LIST;
    fn encode_into(&self, out: &mut Vec<u8>) {
        header(T_LIST, self.len() as u64, out);
        for x in self {
            x.encode_into(out);
        }
    }
    fn encoded_len(&self) -> usize {
        header_len(self.len() as u64) + self.iter().map(Wire::encoded_len).sum::<usize>()
    }
    fn take(v: Value, at: &At) -> Result<Self, String> {
        let Value::List(items) = v else {
            return Err(wrong(at, "a list"));
        };
        let mut out = Vec::with_capacity(items.len());
        for (i, x) in items.into_iter().enumerate() {
            out.push(T::take(x, &At::Item(at, i))?);
        }
        Ok(out)
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
    pub fn as_ref(&self) -> super::Ref<'_> {
        match self {
            Reference::Typed(t) => super::Ref::Typed(t),
            Reference::Id(b) => super::Ref::Id(super::IdGiven::Bytes(b)),
        }
    }
}

impl Reference {
    /// The ref as the handlers not yet given [`super::Ref`] hold it: text
    /// as it was typed, an id given as bytes as [`super::EXACT`] then its
    /// hex. Only for those handlers, whose words (an error naming the ref
    /// as it came) are kept as they were.
    pub fn held(&self) -> Cow<'_, str> {
        match self {
            Reference::Typed(t) => Cow::Borrowed(t),
            Reference::Id(b) => Cow::Owned(format!("{}{}", super::EXACT, hex::encode(b))),
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
            Value::Text(t) if t.starts_with(super::EXACT) => {
                Err(format!("{at} is text that begins with NUL"))
            }
            Value::Text(t) => Ok(Reference::Typed(t)),
            _ => Err(wrong(at, "text or bytes")),
        }
    }
}

/// The fields of a typed record, as [`typed!`](crate::typed) writes them:
/// how many are sent, their encoding, and reading them back.
pub trait Fields: Sized {
    /// Every field, numbered, as the tables give them.
    const FIELDS: &'static [Field];
    /// How many of its fields are sent, leaving out those numbered in `skip`.
    fn present_except(&self, skip: &[u64]) -> u64;
    /// The encodings of its fields, in order, each after its number.
    fn encode_fields(&self, out: &mut Vec<u8>);
    /// Their length, leaving out those numbered in `skip`.
    fn fields_len_except(&self, skip: &[u64]) -> usize;
    /// Reads its fields from `r`, from key `first` up, taking what they
    /// hold; keys this build does not know are passed over.
    fn take_fields(r: Record, at: &At) -> Result<Self, String>;

    /// Its length as a record of its own, leaving out the fields numbered
    /// in `skip`.
    fn record_len_except(&self, skip: &[u64]) -> usize {
        header_len(self.present_except(skip)) + self.fields_len_except(skip)
    }
}

/// A typed request: its arguments are `Self`, and it answers `Reply`.
pub trait Ask: Fields {
    /// Its row in [`REQUESTS`](super::REQUESTS).
    const REQUEST: &'static Request;
    type Reply: Fields;

    /// It as a message, numbered.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.fields_len_except(&[]));
        header(T_RECORD, 1 + self.present_except(&[]), &mut out);
        write_varint(0, &mut out);
        Self::REQUEST.n.encode_into(&mut out);
        self.encode_fields(&mut out);
        out
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
    /// Its row in [`EVENTS`](super::EVENTS) or [`FRAMES`](super::FRAMES).
    const KIND: &'static Request;

    /// It as a message.
    fn message(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.fields_len_except(&[]));
        header(T_RECORD, 1 + self.present_except(&[]), &mut out);
        write_varint(0, &mut out);
        Self::KIND.n.encode_into(&mut out);
        self.encode_fields(&mut out);
        out
    }
}

/// A reply that says it was done, with `reply`'s fields: as a message.
pub fn reply_message<R: Fields>(reply: &R) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + reply.fields_len_except(&[]));
    header(T_RECORD, 1 + reply.present_except(&[]), &mut out);
    write_varint(0, &mut out);
    status::OK.encode_into(&mut out);
    reply.encode_fields(&mut out);
    out
}

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

/// A reply off the wire: what it says, or how it failed.
pub fn read_reply<A: Ask>(msg: &[u8]) -> anyhow::Result<Result<A::Reply, Failed>> {
    let mut r = Record::decode(msg)?;
    let st = r
        .remove(0)
        .and_then(|v| v.as_uint())
        .ok_or_else(|| anyhow::anyhow!("a reply's key 0 is its status"))?;
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
    let reply = A::Reply::take_fields(r, &At::Top(A::REQUEST.name)).map_err(anyhow::Error::msg)?;
    Ok(Ok(reply))
}

/// A reply that did not do what was asked: its status, why, and what more
/// an error says ([`ErrorMore`](super::table::ErrorMore)), as a message.
pub fn error_message(status: u64, why: &str, more: &super::table::ErrorMore) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + why.len() + more.fields_len_except(&[]));
    header(T_RECORD, 2 + more.present_except(&[]), &mut out);
    write_varint(0, &mut out);
    status.encode_into(&mut out);
    write_varint(WHY, &mut out);
    header(T_TEXT, why.len() as u64, &mut out);
    out.extend_from_slice(why.as_bytes());
    more.encode_fields(&mut out);
    out
}

/// An error that says which item of a paged answer was too large for a
/// message on its own (`apps.md`, Errors).
pub fn too_large_message(why: &str, at: u64, id: Option<&[u8]>) -> Vec<u8> {
    let more = super::table::ErrorMore {
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

fn too_large(spec: &Request, list: &str, at: usize, n: usize, id: Option<&[u8]>) -> Unpaged {
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
    let limit = limit.filter(|n| *n > 0).map_or(usize::MAX, |n| n as usize);
    let start = after.unwrap_or(0) as usize;
    let all = items.len();
    let room = room(spec, base);
    let (mut used, mut taken) = (0usize, 0usize);
    for x in items.iter().skip(start) {
        if taken >= limit {
            break;
        }
        let n = x.encoded_len();
        if used + n > room {
            if taken == 0 {
                return Err(too_large(spec, list, start, n, id(x)));
            }
            break;
        }
        used += n;
        taken += 1;
    }
    items.drain(..start.min(all));
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
    let limit = limit.filter(|n| *n > 0).map_or(usize::MAX, |n| n as usize);
    let room = room(spec, base);
    let (mut used, mut taken) = (0usize, 0usize);
    for x in items.iter().rev() {
        if taken >= limit {
            break;
        }
        let n = x.encoded_len();
        if used + n > room {
            if taken == 0 {
                return Err(too_large(spec, list, items.len() - 1, n, id(x)));
            }
            break;
        }
        used += n;
        taken += 1;
    }
    let left = items.len() - taken;
    items.drain(..left);
    Ok(left > 0)
}
