//! The way by name (`DEVIATIONS.md`, Typed records): a request and its
//! reply as JSON trees by the tables' field names, hex for bytes, turned
//! into records and back by the same tables. The service answered with it
//! before its requests were typed; it is kept, in test and debug builds
//! and with the `by-name` feature, for main's handlers kept to compare
//! with (`control::by_name`), for the tests, which ask by name, and for
//! the benchmark. A release build has none of it.

use cardinal_encoding::{Record, Value};
use serde_json::{json, Map, Value as Json};

use super::*;
use crate::transport::MAX_MESSAGE;

/// The field in use called `name`: one no longer used may have had the
/// name before it.
fn field_by_name<'a>(fields: &'a [Field], name: &str) -> Option<&'a Field> {
    fields
        .iter()
        .find(|f| f.name == name && !matches!(f.ty, Ty::Gone(_)))
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
