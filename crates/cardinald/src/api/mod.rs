//! The local interface's messages (`apps.md#the-local-interface`): each one
//! record in the base encoding, with numbered fields.
//!
//! Inside the service a request and its reply are JSON trees with field
//! names, as the handlers have always built them; the tables in [`table`]
//! give every request, argument and reply field its number and type, and
//! this module turns one form into the other at the edge. A value the
//! service keeps as hex (a key, an id, a hash) is bytes on the wire.
//!
//! The command line and the tests speak the same tables, through
//! [`encode_request`] and [`decode_reply`].

pub mod table;

#[cfg(unix)]
pub mod blocking;

use cardinal_encoding::{Record, Value};
use serde_json::{json, Map, Value as Json};

pub use table::{Field, Rec, Request, Ty, EVENTS, FRAMES, REQUESTS};

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

/// What key 0 of a `call-media` frame says it is.
pub mod frame {
    /// Audio of the call, in the codec its client chose.
    pub const AUDIO: u64 = 1;
    /// A frame of another format the call took, named in key 2.
    pub const OTHER: u64 = 2;
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
    fn malformed(why: impl Into<String>) -> Refused {
        Refused {
            status: status::MALFORMED,
            why: why.into(),
        }
    }
}

/// The request with this name, if it is answered.
pub fn by_name(name: &str) -> Option<&'static Request> {
    REQUESTS.iter().find(|r| r.name == name && !r.gone)
}

/// The request with this number, answered or not: a tool that shows
/// traffic names one no longer answered too.
pub fn by_number(n: u64) -> Option<&'static Request> {
    REQUESTS.iter().find(|r| r.n == n)
}

fn field_by_name<'a>(fields: &'a [Field], name: &str) -> Option<&'a Field> {
    fields.iter().find(|f| f.name == name)
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
        Ty::Ref => Value::from(v.as_str().ok_or_else(|| wrong("text"))?),
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
            Value::Bytes(b) => json!(hex::encode(b)),
            _ => json!(v.as_text().ok_or_else(|| wrong("text or bytes"))?),
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
    let mut o = record_from_wire(spec.args, &r, spec.name, 1).map_err(Refused::malformed)?;
    o.insert("cmd".into(), json!(spec.name));
    Ok((spec, Json::Object(o)))
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
        return Ok(json!({
            "ok": false,
            "error": why,
            "status": st,
            "needs_words": st == status::NEEDS_WORDS,
            "needs_for": st == status::NEEDS_FOR,
        }));
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
    encode_stream(EVENTS, "changed", &json!({"seq": seq})).expect("the table has it")
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
/// `from`, or `{"frame": hex, "format": hex}`.
pub fn frame_message(frame: &Json) -> anyhow::Result<Vec<u8>> {
    let kind = if frame.get("frame").is_some() {
        "frame"
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

/// A reply to `spec` as a tool shows it.
pub fn render_reply(spec: &Request, msg: &[u8]) -> String {
    render(msg, Zero::Status, spec.reply, 2)
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
