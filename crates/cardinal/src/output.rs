//! The command line's JSON output (`cardinal status --json`, `cardinal
//! speedtest --json`, `cardinal contact-status NAME --json`): a format for
//! parsers, kept as it always was. A typed reply is written as the tree the
//! reply by name was: each field by its name in the tables, keys sorted,
//! bytes as lower-case hex, an id given as bytes in a `ref` as NUL then its
//! hex, `ok: true` added, and, of a reply joined from pages, no `more` or
//! `next`. JSON is only this output; nothing here talks to the service.

use cardinal_encoding::{Record, Value};
use cardinal_interface::{self as api, typed::Ask, Field, Ty};
use serde_json::{json, Map, Value as Json};

/// The reply to `args`, as JSON.
pub fn reply_json<A: Ask>(args: &A, reply: &A::Reply) -> anyhow::Result<Json> {
    let spec = A::REQUEST;
    let msg = api::typed::reply_message(spec.name, reply);
    let r = Record::decode(&msg)?;
    let mut o = record(spec.reply, &r, spec.name, 2).map_err(anyhow::Error::msg)?;
    o.insert("ok".into(), json!(true));
    // every page joined: what said there was more is gone
    if spec.page != api::Page::Whole && !args.one_page() {
        o.remove("more");
        o.remove("next");
    }
    Ok(Json::Object(o))
}

/// The fields of `rec` that `fields` names, from key `first` up; those no
/// longer used are left out.
fn record(
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
        let Some(f) = fields
            .iter()
            .find(|f| f.n == *k)
            .filter(|f| !matches!(f.ty, Ty::Gone(_)))
        else {
            continue;
        };
        o.insert(
            f.name.to_owned(),
            value(&f.ty, v, &format!("{at}.{}", f.name))?,
        );
    }
    Ok(o)
}

/// One value, as JSON.
fn value(ty: &Ty, v: &Value, at: &str) -> Result<Json, String> {
    let wrong = |what: &str| format!("{at} should be {what}");
    Ok(match ty {
        Ty::Text => json!(v.as_text().ok_or_else(|| wrong("text"))?),
        Ty::Bytes | Ty::BytesOf(_) => {
            json!(hex::encode(v.as_bytes().ok_or_else(|| wrong("bytes"))?))
        }
        Ty::Uint => json!(v.as_uint().ok_or_else(|| wrong("an unsigned integer"))?),
        Ty::Int => json!(v.as_int().ok_or_else(|| wrong("an integer"))?),
        Ty::Bool => json!(v.as_bool().ok_or_else(|| wrong("0 or 1"))?),
        Ty::Ref => match v {
            Value::Bytes(b) => json!(format!("{}{}", api::EXACT, hex::encode(b))),
            _ => {
                let t = v.as_text().ok_or_else(|| wrong("text or bytes"))?;
                if t.starts_with(api::EXACT) {
                    return Err(format!("{at} is text that begins with NUL"));
                }
                json!(t)
            }
        },
        Ty::Kind => match v {
            Value::Bytes(b) => json!(hex::encode(b)),
            _ => value(&Ty::Uint, v, at)?,
        },
        Ty::Scalar => match v {
            Value::Text(t) => json!(t),
            _ => value(&Ty::Int, v, at)?,
        },
        Ty::List(item) => {
            let items = v.as_list().ok_or_else(|| wrong("a list"))?;
            let mut out = Vec::with_capacity(items.len());
            for (i, x) in items.iter().enumerate() {
                out.push(value(item, x, &format!("{at}[{i}]"))?);
            }
            Json::Array(out)
        }
        Ty::Rec(r) => {
            let rec = v.as_record().ok_or_else(|| wrong("a record"))?;
            Json::Object(record(r.fields, rec, at, 0)?)
        }
        Ty::Recs(r) => {
            let items = v.as_list().ok_or_else(|| wrong("a list"))?;
            let mut out = Vec::with_capacity(items.len());
            for (i, x) in items.iter().enumerate() {
                let at = format!("{at}[{i}]");
                let rec = x
                    .as_record()
                    .ok_or_else(|| format!("{at} should be a record"))?;
                out.push(Json::Object(record(r.fields, rec, &at, 0)?));
            }
            Json::Array(out)
        }
        Ty::Gone(_) => Json::Null,
    })
}
