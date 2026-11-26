//! The local interface's messages (`apps.md#the-local-interface`): each one
//! record in the base encoding, with numbered fields.
//!
//! Two ways lead from a handler to the wire, while the one replaces the
//! other (`DEVIATIONS.md`, Typed records):
//!
//! - **Typed** ([`typed`]): a request's arguments, its reply and each record
//!   in it are Rust values, declared once in [`table`] with `typed!`, which
//!   gives both the struct and its table row; `asks!` declares the request
//!   (how it is answered and paged), `streams!` a frame or an event,
//!   `program!` what the service's program says. Ids, keys and hashes are
//!   bytes; a value goes to the wire and back with no tree of names and no
//!   hex. The connection answers a typed request from its row
//!   ([`Request::answer`]).
//! - **By name** (the rest, for now): the handler builds a JSON tree with
//!   field names, and this module turns it into a record at the edge by the
//!   tables in [`table`], hex becoming bytes. Main's handlers of the typed
//!   requests are kept by name too, in test and debug builds, to compare
//!   with. It goes once every request is typed.
//!
//! The command line and the tests speak the same tables, through
//! [`encode_request`] and [`decode_reply`] by name, or the typed values'
//! own encodings.

pub mod table;
pub mod typed;

#[cfg(unix)]
pub mod blocking;

use cardinal_encoding::{Record, Value};
use serde_json::{json, Map, Value as Json};

// The typed records, requests and replies, and the tables' rows.
pub use table::*;

use crate::transport::MAX_MESSAGE;

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
    pub(crate) fn malformed(why: impl Into<String>) -> Refused {
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
            IdGiven::Bytes(b) => hex::encode(b).into(),
            IdGiven::Hex(h) => (*h).into(),
        }
    }

    /// Its bytes, where they are bytes of hex.
    pub fn bytes(&self) -> Option<std::borrow::Cow<'_, [u8]>> {
        match self {
            IdGiven::Bytes(b) => Some((*b).into()),
            IdGiven::Hex(h) => hex::decode(h).ok().map(Into::into),
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
                let full = hex::encode(id);
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

/// The field in use called `name`: one no longer used may have had the
/// name before it.
fn field_by_name<'a>(fields: &'a [Field], name: &str) -> Option<&'a Field> {
    fields
        .iter()
        .find(|f| f.name == name && !matches!(f.ty, Ty::Gone(_)))
}

fn field_by_number(fields: &[Field], n: u64) -> Option<&Field> {
    fields.iter().find(|f| f.n == n)
}

/// Turns a value the service holds by name into its wire form.
fn to_wire(ty: &Ty, v: &Json, at: &str) -> Result<Value, String> {
    let wrong = |what: &str| format!("{at} should be {what}, not {v}");
    Ok(match ty {
        Ty::Text => Value::from(v.as_str().ok_or_else(|| wrong("text"))?),
        Ty::Bytes => {
            let s = v.as_str().ok_or_else(|| wrong("hex"))?;
            Value::from(hex::decode(s).map_err(|_| wrong("hex"))?)
        }
        Ty::Uint => {
            let n = v.as_u64().ok_or_else(|| wrong("an unsigned integer"))?;
            Value::from(cardinal_encoding::Int::from_u64(n).ok_or_else(|| wrong("below 2^60"))?)
        }
        Ty::Int => {
            let n = v.as_i64().ok_or_else(|| wrong("an integer"))?;
            Value::from(cardinal_encoding::Int::new(n).ok_or_else(|| wrong("within 2^60"))?)
        }
        Ty::Bool => Value::from(v.as_bool().ok_or_else(|| wrong("true or false"))?),
        Ty::Ref => {
            let s = v.as_str().ok_or_else(|| wrong("text"))?;
            match s.strip_prefix(EXACT) {
                None => Value::from(s),
                Some(h) => Value::from(hex::decode(h).map_err(|_| wrong("hex"))?),
            }
        }
        Ty::Kind => match v {
            Json::Number(_) => to_wire(&Ty::Uint, v, at)?,
            _ => to_wire(&Ty::Bytes, v, at)?,
        },
        Ty::Scalar => match v {
            Json::Number(_) => to_wire(&Ty::Int, v, at)?,
            _ => to_wire(&Ty::Text, v, at)?,
        },
        Ty::List(item) => {
            let items = v.as_array().ok_or_else(|| wrong("a list"))?;
            let mut out = Vec::with_capacity(items.len());
            for (i, x) in items.iter().enumerate() {
                out.push(to_wire(item, x, &format!("{at}[{i}]"))?);
            }
            Value::List(out)
        }
        Ty::Rec(r) => {
            let o = v.as_object().ok_or_else(|| wrong("a record"))?;
            Value::Record(record_to_wire(r.fields, o, at)?)
        }
        Ty::Recs(r) => {
            let items = v.as_array().ok_or_else(|| wrong("a list"))?;
            let mut out = Vec::with_capacity(items.len());
            for (i, x) in items.iter().enumerate() {
                let at = format!("{at}[{i}]");
                let o = x
                    .as_object()
                    .ok_or_else(|| format!("{at} should be a record"))?;
                out.push(Value::Record(record_to_wire(r.fields, o, &at)?));
            }
            Value::List(out)
        }
        Ty::Gone(_) => return Err(format!("{at} is no longer used")),
    })
}

fn record_to_wire(fields: &[Field], o: &Map<String, Json>, at: &str) -> Result<Record, String> {
    let mut r = Record::new();
    for (k, v) in o {
        if v.is_null() {
            continue;
        }
        let Some(f) = field_by_name(fields, k) else {
            return Err(format!("{at}.{k} has no number"));
        };
        r.insert(f.n, to_wire(&f.ty, v, &format!("{at}.{k}"))?);
    }
    Ok(r)
}

/// Turns a value off the wire into the form the service holds by name.
fn from_wire(ty: &Ty, v: &Value, at: &str) -> Result<Json, String> {
    let wrong = |what: &str| format!("{at} should be {what}");
    Ok(match ty {
        Ty::Text => json!(v.as_text().ok_or_else(|| wrong("text"))?),
        Ty::Bytes => json!(hex::encode(v.as_bytes().ok_or_else(|| wrong("bytes"))?)),
        Ty::Uint => json!(v.as_uint().ok_or_else(|| wrong("an unsigned integer"))?),
        Ty::Int => json!(v.as_int().ok_or_else(|| wrong("an integer"))?),
        Ty::Bool => json!(v.as_bool().ok_or_else(|| wrong("0 or 1"))?),
        Ty::Ref => match v {
            Value::Bytes(b) => json!(format!("{EXACT}{}", hex::encode(b))),
            _ => {
                let t = v.as_text().ok_or_else(|| wrong("text or bytes"))?;
                if t.starts_with(EXACT) {
                    return Err(format!("{at} is text that begins with NUL"));
                }
                json!(t)
            }
        },
        Ty::Kind => match v {
            Value::Bytes(b) => json!(hex::encode(b)),
            _ => from_wire(&Ty::Uint, v, at)?,
        },
        Ty::Scalar => match v {
            Value::Text(t) => json!(t),
            _ => from_wire(&Ty::Int, v, at)?,
        },
        Ty::List(item) => {
            let items = v.as_list().ok_or_else(|| wrong("a list"))?;
            let mut out = Vec::with_capacity(items.len());
            for (i, x) in items.iter().enumerate() {
                out.push(from_wire(item, x, &format!("{at}[{i}]"))?);
            }
            Json::Array(out)
        }
        Ty::Rec(r) => {
            let rec = v.as_record().ok_or_else(|| wrong("a record"))?;
            Json::Object(record_from_wire(r.fields, rec, at, 0)?)
        }
        Ty::Recs(r) => {
            let items = v.as_list().ok_or_else(|| wrong("a list"))?;
            let mut out = Vec::with_capacity(items.len());
            for (i, x) in items.iter().enumerate() {
                let at = format!("{at}[{i}]");
                let rec = x
                    .as_record()
                    .ok_or_else(|| format!("{at} should be a record"))?;
                out.push(Json::Object(record_from_wire(r.fields, rec, &at, 0)?));
            }
            Json::Array(out)
        }
        Ty::Gone(_) => Json::Null,
    })
}

/// The fields of `rec` that `fields` names, from key `first` up; others,
/// which a later version may have added, are left out, and so are those no
/// longer used.
fn record_from_wire(
    fields: &[Field],
    rec: &Record,
    at: &str,
    first: u64,
) -> Result<Map<String, Json>, String> {
    let mut o = Map::new();
    for (k, v) in rec.iter() {
        if *k < first {
            continue;
        }
        if let Some(f) = field_by_number(fields, *k).filter(|f| !matches!(f.ty, Ty::Gone(_))) {
            o.insert(
                f.name.to_owned(),
                from_wire(&f.ty, v, &format!("{at}.{}", f.name))?,
            );
        }
    }
    Ok(o)
}

/// A request as a message: `req` names it in `cmd`, and its arguments by
/// name.
pub fn encode_request(req: &Json) -> anyhow::Result<(&'static Request, Vec<u8>)> {
    let o = req
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("a request is a record"))?;
    let name = o.get("cmd").and_then(Json::as_str).unwrap_or("");
    let spec = by_name(name).ok_or_else(|| anyhow::anyhow!("there is no request {name:?}"))?;
    let mut args = o.clone();
    args.remove("cmd");
    let mut r = record_to_wire(spec.args, &args, name).map_err(anyhow::Error::msg)?;
    r.insert(0, spec.n);
    Ok((spec, r.encode()))
}

/// A request off the wire, as the handlers take it: `cmd` and the
/// arguments by name.
pub fn decode_request(msg: &[u8]) -> Result<(&'static Request, Json), Refused> {
    let (spec, r) = decode_record(msg)?;
    Ok((spec, by_name_from(spec, &r)?))
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

/// A request's arguments by name, as the handlers not yet typed take them,
/// with `cmd`.
pub fn by_name_from(spec: &'static Request, r: &Record) -> Result<Json, Refused> {
    let mut o = record_from_wire(spec.args, r, spec.name, 1).map_err(Refused::malformed)?;
    o.insert("cmd".into(), json!(spec.name));
    Ok(Json::Object(o))
}

/// What a handler may add to a paged reply when it gave only some of its
/// lists' items, for [`page`]: the position of the first it gave (of an
/// `after` page), and how many there are in all; or (of a `before` page)
/// how many older than those it gave there are. Never sent.
pub const PAGE_FROM: &str = "_page_from";
pub const PAGE_TOTAL: &str = "_page_total";
pub const PAGE_OLDER: &str = "_page_older";

/// Room kept in a message beside a page's items: the status, `more`,
/// `next`, and each list's key and length.
const PAGE_ROOM: usize = 64;
const LIST_ROOM: usize = 12;

/// The room a page of `spec` keeps beside its items: [`PAGE_ROOM`], and
/// [`LIST_ROOM`] for each list paged.
pub(crate) fn page_room(spec: &Request) -> usize {
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

/// A paged answer that could not be given: the status, why, and what
/// says which item.
pub type Unpaged = (u64, String, ErrorMore);

/// Cuts a paged reply (`apps.md`, Pages) to the page the request asks
/// for: at most `limit` items, and as many as fit in a message with the
/// reply's other fields, from the cursor on; with `more` and, when there
/// is more, `next`. Lists not paged are left whole. An item too large for
/// a message alone is an error, `TOO_LARGE`, that says which item, by its
/// place and its id: nothing is cut silently, and a client can ask for
/// what comes after it.
pub fn page(spec: &Request, req: &Json, mut reply: Json) -> Result<Json, Unpaged> {
    let Some(o) = reply.as_object_mut() else {
        return Ok(reply);
    };
    let num = |o: &mut Map<String, Json>, k: &str| o.remove(k).and_then(|v| v.as_u64());
    let from = num(o, PAGE_FROM).unwrap_or(0) as usize;
    let total = num(o, PAGE_TOTAL).map(|t| t as usize);
    let older = num(o, PAGE_OLDER).unwrap_or(0) as usize;
    if spec.page == Page::Whole {
        return Ok(reply);
    }
    let limit = req
        .get("limit")
        .and_then(Json::as_u64)
        .filter(|n| *n > 0)
        .map_or(usize::MAX, |n| n as usize);
    let lists: Vec<&Field> = match spec.page {
        Page::Before { list } => spec.reply.iter().filter(|f| f.name == list).collect(),
        _ => spec
            .reply
            .iter()
            .filter(|f| matches!(f.ty, Ty::List(_) | Ty::Recs(_)))
            .collect(),
    };
    let mut lists: Vec<&Field> = lists;
    lists.sort_by_key(|f| f.n);
    // every item, by its list, in order
    let mut items: Vec<(usize, Json)> = Vec::new();
    let mut present = vec![false; lists.len()];
    for (li, f) in lists.iter().enumerate() {
        if let Some(v) = o.remove(f.name) {
            if let Json::Array(a) = v {
                present[li] = true;
                items.extend(a.into_iter().map(|x| (li, x)));
            } else if !v.is_null() {
                o.insert(f.name.to_owned(), v);
            }
        }
    }
    let base = record_to_wire(spec.reply, o, spec.name)
        .map(|r| r.encoded_len())
        .unwrap_or(0);
    let room = MAX_MESSAGE.saturating_sub(base + PAGE_ROOM + LIST_ROOM * lists.len());
    let size = |li: usize, x: &Json| -> usize {
        let ty = match &lists[li].ty {
            Ty::List(t) => *t,
            Ty::Recs(r) => {
                return x
                    .as_object()
                    .and_then(|o| record_to_wire(r.fields, o, lists[li].name).ok())
                    .map_or(0, |r| r.encoded_len())
            }
            _ => return 0,
        };
        to_wire(ty, x, lists[li].name).map_or(0, |v| v.encoded_len())
    };
    let too_large = |li: usize, at: usize, n: usize, x: &Json| {
        // its id, where its records have one
        let id = match &lists[li].ty {
            Ty::Recs(r)
                if field_by_name(r.fields, "id").is_some_and(|f| matches!(f.ty, Ty::Bytes)) =>
            {
                x.get("id").and_then(Json::as_str)
            }
            _ => None,
        };
        // An id not in hex was left out with `at`, as the tables did.
        let more = match id.map(hex::decode) {
            Some(Err(_)) => {
                tracing::error!("an error's fields: {}.id is not hex", lists[li].name);
                ErrorMore::new()
            }
            id => ErrorMore {
                at: Some(at as u64),
                id: id.and_then(Result::ok).map(Into::into),
            },
        };
        (
            status::TOO_LARGE,
            format!(
                "item {at} of {} is {n} bytes, more than a message may hold beside the rest \
                 of the answer to {}",
                lists[li].name, spec.name
            ),
            more,
        )
    };
    let mut used = 0usize;
    let mut taken: Vec<(usize, Json)> = Vec::new();
    let (more, next) = match spec.page {
        Page::Whole => unreachable!("answered whole above"),
        Page::After => {
            let after = req.get("after").and_then(Json::as_u64).unwrap_or(0) as usize;
            let start = after.max(from);
            let all = total.unwrap_or(from + items.len()).max(from + items.len());
            let mut at = start;
            for (li, x) in items.into_iter().skip(start - from) {
                if taken.len() >= limit {
                    break;
                }
                let n = size(li, &x);
                if used + n > room {
                    if taken.is_empty() {
                        return Err(too_large(li, at, n, &x));
                    }
                    break;
                }
                used += n;
                taken.push((li, x));
                at += 1;
            }
            let more = at < all;
            (more, more.then(|| json!(at)))
        }
        Page::Before { .. } => {
            let mut left = items.len();
            while let Some((li, x)) = items.pop() {
                if taken.len() >= limit {
                    items.push((li, x));
                    break;
                }
                let n = size(li, &x);
                if used + n > room {
                    if taken.is_empty() {
                        return Err(too_large(li, older + left - 1, n, &x));
                    }
                    items.push((li, x));
                    break;
                }
                used += n;
                taken.push((li, x));
                left -= 1;
            }
            taken.reverse();
            let more = left > 0 || older > 0;
            let next = taken.first().and_then(|(_, x)| x.get("id")).cloned();
            (more, if more { next } else { None })
        }
    };
    for (li, f) in lists.iter().enumerate() {
        if present[li] {
            o.insert(f.name.to_owned(), json!([]));
        }
    }
    for (li, x) in taken {
        if let Some(Json::Array(a)) = o.get_mut(lists[li].name) {
            a.push(x);
        }
    }
    o.insert("more".into(), json!(more));
    if let Some(next) = next {
        o.insert("next".into(), next);
    }
    Ok(reply)
}

/// A reply as a message. `Err` is a status other than OK and why.
pub fn encode_reply(spec: &Request, reply: Result<&Json, (u64, &str)>) -> Vec<u8> {
    match reply {
        Ok(v) => {
            let empty = Map::new();
            let o = v.as_object().unwrap_or(&empty);
            match record_to_wire(spec.reply, o, spec.name) {
                Ok(mut r) => {
                    r.insert(0, status::OK);
                    r.encode()
                }
                Err(e) => {
                    tracing::error!("reply to {}: {e}", spec.name);
                    if cfg!(debug_assertions) {
                        // A field without a number is this build's mistake:
                        // where the tests run, it fails the request.
                        return error_reply(status::FAILED, &format!("internal: {e}"));
                    }
                    let mut kept = o.clone();
                    kept.retain(|k, x| {
                        field_by_name(spec.reply, k).is_some_and(|f| to_wire(&f.ty, x, k).is_ok())
                    });
                    let mut r = record_to_wire(spec.reply, &kept, spec.name).unwrap_or_default();
                    r.insert(0, status::OK);
                    r.encode()
                }
            }
        }
        Err((status, why)) => error_reply(status, why),
    }
}

/// An error reply.
pub fn error_reply(status: u64, why: &str) -> Vec<u8> {
    Record::new().with(0, status).with(WHY, why).encode()
}

/// An error reply that says more than why, typed.
pub fn error_reply_with(status: u64, why: &str, more: &ErrorMore) -> Vec<u8> {
    typed::error_message(status, why, more)
}

/// [`error_reply_with`] as it was by name, taking the fields of
/// [`ERROR_FIELDS`] as a tree: kept only to show the typed one sends the
/// same bytes.
#[cfg(test)]
pub(crate) fn error_reply_with_by_name(status: u64, why: &str, more: &Json) -> Vec<u8> {
    let empty = Map::new();
    let o = more.as_object().unwrap_or(&empty);
    let mut r = record_to_wire(ERROR_FIELDS, o, "error").unwrap_or_else(|e| {
        tracing::error!("an error's fields: {e}");
        Record::new()
    });
    r.insert(0, status);
    r.insert(WHY, why);
    r.encode()
}

/// A reply off the wire, in the form the command line has always read:
/// `ok`, and on an error `error` with why and `needs_words` or
/// `needs_for`; then the reply's fields by name.
pub fn decode_reply(spec: &Request, msg: &[u8]) -> anyhow::Result<Json> {
    let r = Record::decode(msg)?;
    let st = r
        .get(0)
        .and_then(Value::as_uint)
        .ok_or_else(|| anyhow::anyhow!("a reply's key 0 is its status"))?;
    if st != status::OK {
        let why = r.get(WHY).and_then(Value::as_text).unwrap_or("");
        let why = if why.is_empty() {
            status::name(st).unwrap_or("failed").to_owned()
        } else {
            why.to_owned()
        };
        let mut out = record_from_wire(ERROR_FIELDS, &r, "error", 2).unwrap_or_default();
        for (k, v) in [
            ("ok", json!(false)),
            ("error", json!(why)),
            ("status", json!(st)),
            ("needs_words", json!(st == status::NEEDS_WORDS)),
            ("needs_for", json!(st == status::NEEDS_FOR)),
        ] {
            out.insert(k.into(), v);
        }
        return Ok(Json::Object(out));
    }
    let mut o = record_from_wire(spec.reply, &r, spec.name, 2).map_err(anyhow::Error::msg)?;
    o.insert("ok".into(), json!(true));
    Ok(Json::Object(o))
}

/// A stream's message (an event of `watch`, a frame of `call-media`) as a
/// record: `kind` names it in the table, and its fields by name.
pub fn encode_stream(table: &[Request], kind: &str, fields: &Json) -> anyhow::Result<Vec<u8>> {
    let spec = table
        .iter()
        .find(|e| e.name == kind)
        .ok_or_else(|| anyhow::anyhow!("no {kind} in this stream"))?;
    let empty = Map::new();
    let o = fields.as_object().unwrap_or(&empty);
    let mut r = record_to_wire(spec.args, o, kind).map_err(anyhow::Error::msg)?;
    r.insert(0, spec.n);
    Ok(r.encode())
}

/// A stream's message off the wire: its kind's name, and its fields by
/// name. `None` for a kind this build does not know.
pub fn decode_stream(
    table: &'static [Request],
    msg: &[u8],
) -> anyhow::Result<Option<(&'static str, Json)>> {
    let r = Record::decode(msg)?;
    let n = r
        .get(0)
        .and_then(Value::as_uint)
        .ok_or_else(|| anyhow::anyhow!("key 0 is what the message is"))?;
    let Some(spec) = table.iter().find(|e| e.n == n) else {
        return Ok(None);
    };
    let o = record_from_wire(spec.args, &r, spec.name, 1).map_err(anyhow::Error::msg)?;
    Ok(Some((spec.name, Json::Object(o))))
}

/// A `watch` event: something changed, and this is the count of changes.
pub fn event_message(seq: u64) -> Vec<u8> {
    typed::Streamed::message(&Changed { seq })
}

/// A `watch` event off the wire: `{"event": "changed", "seq": n}`, or
/// `None` for an event this build does not know.
pub fn decode_event(msg: &[u8]) -> anyhow::Result<Option<Json>> {
    Ok(decode_stream(EVENTS, msg)?.map(|(kind, mut fields)| {
        fields["event"] = json!(kind);
        fields
    }))
}

/// A `call-media` frame as a message: `{"audio": hex}` and in a group
/// `from`, `{"frame": hex, "format": hex}` and in a group `size`,
/// `{"width": n, "height": n}`, `{"level": n, "from": hex}`, `{"small": b,
/// "large": b}`, `{"from": hex, "size": n}` for a key picture, or
/// `{"camera": b}`.
pub fn frame_message(frame: &Json) -> anyhow::Result<Vec<u8>> {
    let kind = if frame.get("frame").is_some() {
        "frame"
    } else if frame.get("width").is_some() {
        "viewport"
    } else if frame.get("level").is_some() {
        "level"
    } else if frame.get("small").is_some() {
        "asked"
    } else if frame.get("size").is_some() {
        "key"
    } else if frame.get("camera").is_some() {
        "camera"
    } else {
        "audio"
    };
    encode_stream(FRAMES, kind, frame)
}

/// A `call-media` frame off the wire, named as [`frame_message`] takes it;
/// `None` for one this build does not know.
pub fn decode_frame(msg: &[u8]) -> anyhow::Result<Option<Json>> {
    Ok(decode_stream(FRAMES, msg)?.map(|(_, fields)| fields))
}

/// The display form of a message, in the text rendering with the tables'
/// names (`encoding.md#text-rendering`): for a tool that shows traffic.
/// `fields` are the message's own, and `zero` names what key 0 holds.
pub fn render(msg: &[u8], zero: Zero, fields: &[Field], first: u64) -> String {
    let r = match Record::decode(msg) {
        Ok(r) => r,
        Err(e) => return format!("(not one record: {e}) h'{}'", hex::encode(msg)),
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
            format!(
                "h'{}…' ({} bytes)",
                hex::encode(&b[..SHOWN_BYTES / 2]),
                b.len()
            )
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

#[cfg(test)]
mod tests;

#[cfg(test)]
mod same_bytes;
