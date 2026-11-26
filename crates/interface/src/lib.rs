//! The local interface of a Cardinal node (`apps.md#the-local-interface`),
//! as typed records: every request, its arguments and its reply, every
//! record a reply holds, the events of `watch` and the frames of
//! `call-media`, declared once, with their encoding both ways in the base
//! encoding and their rows in the tables. The service (`cardinald`), its
//! command line and any Rust client share them; nothing here answers a
//! request or opens a socket.
//!
//! - [`table`]: the declarations. `typed!` declares a record (the struct,
//!   its row, its encoding), `asks!` a request (its row, how its reply
//!   pages), `streams!` an event or a frame, `program!` what the service's
//!   program says; [`each_request!`] lists every request once, from which
//!   [`REQUESTS`] is made, and the service its answering.
//! - [`typed`]: the [`Wire`](typed::Wire) trait and the field types,
//!   writing and reading messages, and paging, both its sides.
//! - [`client`]: what a client needs to ask a request and read its reply
//!   typed, page after page, over a transport it supplies.
//! - Here: the numbers every message shares (status, why), `ref`s, the
//!   lookups in the tables, and the text rendering by the tables' names.
//!
//! The same declarations are exported for clients in other languages as
//! one file, `interface.bin` (the base encoding) with its text rendering
//! beside it, `interface.txt`, which a test keeps up to date
//! (`export.rs` says what they hold).
//!
//! A client asks with the arguments' own type and reads the reply's:
//!
//! ```
//! use cardinal_interface::client::{ask, Transport};
//! use cardinal_interface::{typed::Failed, FilesArgs};
//!
//! /// Carries a request's message to the service and back; here, a
//! /// service that has no files at all.
//! struct Empty;
//!
//! impl Transport for Empty {
//!     type Error = Box<dyn std::error::Error>;
//!     fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, Self::Error> {
//!         let (_, record) = cardinal_interface::decode_record(request).map_err(|r| r.why)?;
//!         let args = <FilesArgs as cardinal_interface::typed::Ask>::from_request(record)
//!             .map_err(|r| r.why)?;
//!         let mine = cardinal_interface::Place::new("mine".into());
//!         let reply = cardinal_interface::FilesReply::new(Vec::new(), String::new(), mine, false);
//!         Ok(cardinal_interface::typed::Ask::reply_bytes(&args, reply))
//!     }
//! }
//!
//! let files: Result<_, Failed> = ask(&mut Empty, &FilesArgs::new()).unwrap();
//! assert!(files.unwrap().files.is_empty());
//! ```

pub mod client;
pub mod table;
pub mod typed;

#[cfg(test)]
mod export;
#[cfg(test)]
mod tests;

use cardinal_encoding::{Record, Value};

// The typed records, requests and replies, and the tables' rows.
pub use table::*;

/// What the macros name, from wherever they are used.
#[doc(hidden)]
pub mod __private {
    pub use cardinal_encoding::{Record, Value};
}

/// The version of this interface. A client compares it with `hello`'s.
/// 2: the base encoding, with numbered fields, in place of lines of JSON.
pub const VERSION: u64 = 3;

/// The most a message may be, either way (`apps.md`, The local interface).
pub const MAX_MESSAGE: usize = 256 * 1024;

/// A reply's key 0, and the numbers of the errors (`apps.md`, Errors).
pub mod status {
    /// The request was done.
    pub const OK: u64 = 0;
    /// The service could not do it; the reply says why.
    pub const FAILED: u64 = 1;
    /// Not one canonical record, larger than a message may be, or a field
    /// of the wrong type.
    pub const MALFORMED: u64 = 2;
    /// A request number this service does not know.
    pub const UNKNOWN: u64 = 3;
    /// The answer would be larger than a message may be.
    pub const TOO_LARGE: u64 = 4;
    /// The request needs the person's 24 words, in its `words`.
    pub const NEEDS_WORDS: u64 = 5;
    /// A recovery invitation that a guardian accepts needs `for`.
    pub const NEEDS_FOR: u64 = 6;

    /// The name a tool shows for a status.
    pub fn name(n: u64) -> Option<&'static str> {
        Some(match n {
            OK => "ok",
            FAILED => "failed",
            MALFORMED => "malformed",
            UNKNOWN => "unknown request",
            TOO_LARGE => "too large",
            NEEDS_WORDS => "needs words",
            NEEDS_FOR => "needs for",
            _ => return None,
        })
    }
}

/// What key 0 of a `call-media` frame says it is: the frames' rows, typed
/// in [`table`].
pub mod frame {
    use super::table;

    /// Audio of the call, in the codec its client chose.
    pub const AUDIO: u64 = table::FRAME_AUDIO.n;
    /// A frame of another format the call took, named in key 2.
    pub const OTHER: u64 = table::FRAME_OTHER.n;
    /// The shape of a window's viewport, width and height in keys 1 and 2
    /// (`basics/video.md`): from the window, its own; from the service, a
    /// receiver's, with key 3 in a group.
    pub const VIEWPORT: u64 = table::FRAME_VIEWPORT.n;
    /// From the window, in a group: the level, key 1, it asks of the sender
    /// in key 3 (`basics/video.md#groups`).
    pub const LEVEL: u64 = table::FRAME_LEVEL.n;
    /// To the window, in a group: whether small (key 1) and large (key 2)
    /// pictures of its own are asked for.
    pub const ASKED: u64 = table::FRAME_ASKED.n;
    /// A key picture of the size in key 4: from the window, asked of the
    /// sender in key 3; to it, asked of its own.
    pub const KEY: u64 = table::FRAME_KEY.n;
    /// From the window: whether this person's camera is on, key 1
    /// (`basics/video.md#cameras`).
    pub const CAMERA: u64 = table::FRAME_CAMERA.n;
}

/// A reply's key 1 in an error: why, in words.
pub const WHY: u64 = 1;

/// A failure to turn a message into a request: the status to answer with,
/// and why.
#[derive(Debug)]
pub struct Refused {
    pub status: u64,
    pub why: String,
}

impl Refused {
    /// A request that is not what its row says: error 2.
    pub fn malformed(why: impl Into<String>) -> Refused {
        Refused {
            status: status::MALFORMED,
            why: why.into(),
        }
    }
}

/// How the service holds a `ref` that came as bytes: this mark, then the
/// bytes in hex. A `ref` sent as text never begins with it (one that does
/// is malformed), so an id given as bytes is never taken for a name or for
/// the start of an id (`apps.md`, Types): [`reference`] tells the two
/// apart, and a handler that reads it as text finds nothing by it.
pub const EXACT: char = '\u{0}';

/// A `ref` argument, as a handler takes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ref<'a> {
    /// Text, as a person types it: a name, or the start of an id in hex,
    /// read by whatever rules the request has for it.
    Typed(&'a str),
    /// The bytes of an id: that id and nothing else.
    Id(IdGiven<'a>),
}

/// The bytes of an id given as a `ref`: as they came, on the typed way, or
/// held as hex, on the way by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdGiven<'a> {
    Bytes(&'a [u8]),
    Hex(&'a str),
}

impl IdGiven<'_> {
    /// The id in hex, as an error shows it.
    pub fn hex(&self) -> std::borrow::Cow<'_, str> {
        match self {
            IdGiven::Bytes(b) => hex(b).into(),
            IdGiven::Hex(h) => (*h).into(),
        }
    }

    /// Its bytes, where they are bytes of hex.
    pub fn bytes(&self) -> Option<std::borrow::Cow<'_, [u8]>> {
        match self {
            IdGiven::Bytes(b) => Some((*b).into()),
            IdGiven::Hex(h) => unhex(h).map(Into::into),
        }
    }
}

/// A `ref` argument as the service holds it on the way by name, told apart.
pub fn reference(s: &str) -> Ref<'_> {
    match s.strip_prefix(EXACT) {
        Some(h) => Ref::Id(IdGiven::Hex(h)),
        None => Ref::Typed(s),
    }
}

/// The hex of a `ref` that only an id answers, given as bytes or typed in
/// hex: for a handler that reads it as an id whole.
pub fn id_hex(s: &str) -> &str {
    s.strip_prefix(EXACT).unwrap_or(s)
}

/// A `ref` as an error shows it: an id given as bytes in hex, text as it
/// was typed.
pub fn shown(s: &str) -> &str {
    id_hex(s)
}

impl Ref<'_> {
    /// Whether this is `id` given as bytes: the id whole, or its first
    /// eight bytes, as the service gives the ids of people and devices
    /// (`identity`, `key`, `id`). Text is never an id here.
    pub fn is_id(&self, id: &[u8]) -> bool {
        match self {
            Ref::Typed(_) => false,
            Ref::Id(IdGiven::Bytes(b)) => {
                *b == id || (b.len() == 8 && id.len() > 8 && id.starts_with(b))
            }
            Ref::Id(IdGiven::Hex(h)) => {
                let full = hex(id);
                *h == full || (h.len() == 16 && id.len() > 8 && full.starts_with(h))
            }
        }
    }
}

/// A `ref` as an error shows it: an id given as bytes in hex, text as it
/// was typed.
impl std::fmt::Display for Ref<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ref::Typed(t) => f.write_str(t),
            Ref::Id(id) => f.write_str(&id.hex()),
        }
    }
}

/// The first eight bytes of an id, as the service gives the ids of people
/// and devices.
pub fn short_id(id: &[u8; 32]) -> [u8; 8] {
    let mut out = [0; 8];
    out.copy_from_slice(&id[..8]);
    out
}

/// Bytes in lower-case hex, as an error or a tool shows them.
pub fn hex(b: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(DIGITS[(x >> 4) as usize] as char);
        s.push(DIGITS[(x & 15) as usize] as char);
    }
    s
}

/// The bytes of hex, of either case; `None` for anything else.
pub fn unhex(h: &str) -> Option<Vec<u8>> {
    fn digit(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let h = h.as_bytes();
    if h.len() % 2 != 0 {
        return None;
    }
    h.chunks(2)
        .map(|p| Some((digit(p[0])? << 4) | digit(p[1])?))
        .collect()
}

/// The request with this name, if it is answered.
pub fn by_name(name: &str) -> Option<&'static Request> {
    REQUESTS.iter().find(|r| r.name == name && !r.gone)
}

/// What the service's program says when asked `option` (`--store`,
/// `--clear`), as its table gives it.
pub fn program(option: &str) -> Option<&'static Request> {
    PROGRAM.iter().find(|r| r.name == option)
}

/// The request with this number, answered or not: a tool that shows
/// traffic names one no longer answered too.
pub fn by_number(n: u64) -> Option<&'static Request> {
    REQUESTS.iter().find(|r| r.n == n)
}

/// The field numbered `n` of `fields`.
pub fn field_by_number(fields: &[Field], n: u64) -> Option<&Field> {
    fields.iter().find(|f| f.n == n)
}

/// A request off the wire as one record, and the row of the request its
/// key 0 names: one this service answers.
pub fn decode_record(msg: &[u8]) -> Result<(&'static Request, Record), Refused> {
    let r = Record::decode(msg).map_err(|e| Refused::malformed(format!("not one record: {e}")))?;
    let n = r
        .get(0)
        .and_then(Value::as_uint)
        .ok_or_else(|| Refused::malformed("key 0 should be the request's number"))?;
    let spec = by_number(n).ok_or_else(|| Refused {
        status: status::UNKNOWN,
        why: format!("this service has no request {n}"),
    })?;
    if spec.gone {
        return Err(Refused {
            status: status::UNKNOWN,
            why: format!("this service no longer answers request {n}, {}", spec.name),
        });
    }
    Ok((spec, r))
}

/// Room kept in a message beside a page's items: the status, `more`,
/// `next`, and each list's key and length.
#[doc(hidden)]
pub const PAGE_ROOM: usize = 64;
#[doc(hidden)]
pub const LIST_ROOM: usize = 12;

/// The room a page of `spec` keeps beside its items: [`PAGE_ROOM`], and
/// [`LIST_ROOM`] for each list paged.
#[doc(hidden)]
pub fn page_room(spec: &Request) -> usize {
    let lists = match spec.page {
        Page::Before { list } => spec.reply.iter().filter(|f| f.name == list).count(),
        _ => spec
            .reply
            .iter()
            .filter(|f| matches!(f.ty, Ty::List(_) | Ty::Recs(_)))
            .count(),
    };
    PAGE_ROOM + LIST_ROOM * lists
}

/// An error reply.
pub fn error_reply(status: u64, why: &str) -> Vec<u8> {
    Record::new().with(0, status).with(WHY, why).encode()
}

/// A `watch` event: something changed, and this is the count of changes.
pub fn event_message(seq: u64) -> Vec<u8> {
    typed::Streamed::message(&Changed { seq })
}

/// The display form of a message, in the text rendering with the tables'
/// names (`encoding.md#text-rendering`): for a tool that shows traffic.
/// `fields` are the message's own, and `zero` names what key 0 holds.
pub fn render(msg: &[u8], zero: Zero, fields: &[Field], first: u64) -> String {
    let r = match Record::decode(msg) {
        Ok(r) => r,
        Err(e) => return format!("(not one record: {e}) h'{}'", hex(msg)),
    };
    let mut parts = Vec::new();
    for (k, v) in r.iter() {
        let shown = if *k == 0 {
            let n = v.as_uint();
            let named = n.and_then(|n| match zero {
                Zero::Request => by_number(n).map(|r| r.name),
                Zero::Status => status::name(n),
                Zero::Stream(t) => t.iter().find(|e| e.n == n).map(|e| e.name),
            });
            let label = match zero {
                Zero::Request => "request",
                Zero::Status => "status",
                Zero::Stream(_) => "is",
            };
            match named {
                Some(name) => format!("{label}: {name}"),
                None => format!("{label}: {v}"),
            }
        } else if *k < first {
            match (zero, *k) {
                (Zero::Status, WHY) => format!("why: {}", short(v)),
                _ => format!("{k}: {}", short(v)),
            }
        } else {
            match field_by_number(fields, *k) {
                Some(f) => format!("{}: {}", f.name, render_value(&f.ty, v)),
                None => format!("{k}: {}", short(v)),
            }
        };
        parts.push(shown);
    }
    format!("{{{}}}", parts.join(", "))
}

/// What key 0 of a message holds, for [`render`].
#[derive(Clone, Copy)]
pub enum Zero {
    Request,
    Status,
    Stream(&'static [Request]),
}

/// A request as a tool shows it.
pub fn render_request(msg: &[u8]) -> String {
    let fields = Record::decode(msg)
        .ok()
        .and_then(|r| r.get(0).and_then(Value::as_uint))
        .and_then(by_number)
        .map_or(&[][..], |r| r.args);
    render(msg, Zero::Request, fields, 1)
}

/// A reply to `spec` as a tool shows it: an error's with the fields an
/// error has.
pub fn render_reply(spec: &Request, msg: &[u8]) -> String {
    let failed = Record::decode(msg)
        .ok()
        .and_then(|r| r.get(0).and_then(Value::as_uint))
        .is_some_and(|st| st != status::OK);
    let fields = if failed { ERROR_FIELDS } else { spec.reply };
    render(msg, Zero::Status, fields, 2)
}

/// A message of a stream (`watch`'s events, `call-media`'s frames) as a
/// tool shows it.
pub fn render_stream(table: &'static [Request], msg: &[u8]) -> String {
    let fields = Record::decode(msg)
        .ok()
        .and_then(|r| r.get(0).and_then(Value::as_uint))
        .and_then(|n| table.iter().find(|e| e.n == n))
        .map_or(&[][..], |e| e.args);
    render(msg, Zero::Stream(table), fields, 1)
}

/// Bytes longer than this are shown by their length and first bytes.
const SHOWN_BYTES: usize = 32;

fn short(v: &Value) -> String {
    match v {
        Value::Bytes(b) if b.len() > SHOWN_BYTES => {
            format!("h'{}…' ({} bytes)", hex(&b[..SHOWN_BYTES / 2]), b.len())
        }
        Value::List(items) => {
            let shown: Vec<String> = items.iter().map(short).collect();
            format!("[{}]", shown.join(", "))
        }
        Value::Record(r) => {
            let shown: Vec<String> = r
                .iter()
                .map(|(k, x)| format!("{k}: {}", short(x)))
                .collect();
            format!("{{{}}}", shown.join(", "))
        }
        v => v.to_string(),
    }
}

fn render_value(ty: &Ty, v: &Value) -> String {
    match (ty, v) {
        (Ty::List(item), Value::List(items)) => {
            let shown: Vec<String> = items.iter().map(|x| render_value(item, x)).collect();
            format!("[{}]", shown.join(", "))
        }
        (Ty::Rec(r), Value::Record(rec)) => {
            let shown: Vec<String> = rec
                .iter()
                .map(|(k, x)| match field_by_number(r.fields, *k) {
                    Some(f) => format!("{}: {}", f.name, render_value(&f.ty, x)),
                    None => format!("{k}: {}", short(x)),
                })
                .collect();
            format!("{{{}}}", shown.join(", "))
        }
        (Ty::Recs(r), Value::List(items)) => {
            let shown: Vec<String> = items.iter().map(|x| render_value(&Ty::Rec(r), x)).collect();
            format!("[{}]", shown.join(", "))
        }
        _ => short(v),
    }
}
