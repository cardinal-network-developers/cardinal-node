//! Inspection: a read-only look at everything this device holds, for
//! whoever designs the data structures: the identity log, every space as a
//! host stores it (sealed entries, epochs, wraps, sizes) and as a member
//! reads it (entries, ops, the state tree), the account space included.
//!
//! That is exactly what `apps.md#what-the-application-sees` says an
//! application never sees, so it is behind a grant the person makes on this
//! device: off until they turn it on (`cardinal inspect on`), for a time they
//! choose, and only for whoever holds the token that turning it on printed.
//! The grant lives in this service's memory alone: it is never written down,
//! a restart ends it, and `cardinal inspect off` ends it at once. Nothing
//! here writes anything, and no private key leaves the service: an epoch
//! key, a blob key, a secret node's value or an invitation's secret is shown
//! as what it is and how long, never as its bytes.
//!
//! On a desktop without a sandbox this guards against accident, not against
//! a program running as the person, which can read the disk anyway
//! (`apps.md#the-limit`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use cardinal_blob::{BlobRef, ObjectStore};
use cardinal_encoding::{Record, Value};
use cardinal_identity::IdentityLog;
use cardinal_space::state::FieldValue;
use cardinal_space::{
    account, reach_node_id, EpochKey, NodeId, NodeKind, Profile, SealedEntry, Space, SpaceEntry,
    SpaceId, SpaceOpBody, ROOT,
};
use serde_json::{json, Value as Json};

use crate::core::{Core, Holder};
use crate::daemon::Daemon;

/// How long a grant lasts when the person names no time.
pub const DEFAULT_MINUTES: u64 = 60;
/// The longest a grant may last: a day.
pub const MAX_MINUTES: u64 = 24 * 60;

/// How many bytes of a value are shown unless more are asked for.
const DEFAULT_LIMIT: usize = 48;
/// The most bytes of one value given in one reply: more than a sealed
/// entry may hold (256 KiB), so any value can be seen whole.
const MAX_LIMIT: usize = 300_000;
/// How many items of a list are shown unless more are asked for.
const DEFAULT_ITEMS: usize = 24;
/// How many entries or nodes one reply lists at most.
const MAX_PAGE: usize = 5_000;
/// How deep a value is rendered before it is cut.
const MAX_DEPTH: usize = 32;

struct Grant {
    token: [u8; 32],
    until: Instant,
    until_ms: u64,
}

/// The person's grant to inspect this device, if they made one.
#[derive(Default)]
pub struct Inspection {
    grant: Mutex<Option<Grant>>,
}

impl Inspection {
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Grant>> {
        self.grant.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Turns inspection on for `minutes`, with a new token: any token given
    /// before stops working. Returns the token, in hex, and until when.
    pub fn grant(&self, minutes: u64) -> anyhow::Result<(String, u64)> {
        if minutes == 0 || minutes > MAX_MINUTES {
            anyhow::bail!("a grant lasts from 1 to {MAX_MINUTES} minutes");
        }
        let token: [u8; 32] = cardinal_crypto::random_bytes();
        let span = Duration::from_secs(minutes * 60);
        let until_ms = crate::core::now_ms() + span.as_millis() as u64;
        *self.lock() = Some(Grant {
            token,
            until: Instant::now() + span,
            until_ms,
        });
        tracing::info!("inspection turned on for {minutes} minutes");
        Ok((hex::encode(token), until_ms))
    }

    /// Turns inspection off. Returns whether it was on.
    pub fn revoke(&self) -> bool {
        let was = self.lock().take().is_some_and(|g| g.until > Instant::now());
        tracing::info!("inspection turned off");
        was
    }

    /// Whether inspection is on, and until when: for `status`, so that a
    /// window can say so.
    pub fn status(&self) -> Json {
        match &*self.lock() {
            Some(g) if g.until > Instant::now() => json!({"on": true, "until": g.until_ms}),
            _ => json!({"on": false}),
        }
    }

    /// Fails unless inspection is on and `token` is its token.
    pub fn check(&self, token: Option<&str>) -> anyhow::Result<()> {
        let off = || {
            anyhow::anyhow!(
                "inspection is off on this device: its person turns it on with \
                 `cardinal inspect on`, which gives the token"
            )
        };
        let mut g = self.lock();
        let Some(grant) = g.as_ref() else {
            return Err(off());
        };
        if grant.until <= Instant::now() {
            *g = None;
            return Err(off());
        }
        let given = token.and_then(|t| hex::decode(t).ok()).unwrap_or_default();
        if !cardinal_crypto::ct_eq(&given, &grant.token) {
            anyhow::bail!("that is not the token inspection was turned on with");
        }
        Ok(())
    }
}

/// How much of each value to show.
#[derive(Clone, Copy)]
struct Opts {
    limit: usize,
    items: usize,
}

impl Opts {
    fn of(req: &Json) -> Opts {
        let n = |name: &str, default: usize| {
            req.get(name)
                .and_then(Json::as_u64)
                .map_or(default, |v| (v as usize).min(MAX_LIMIT))
        };
        Opts {
            limit: n("limit", DEFAULT_LIMIT),
            items: n("items", DEFAULT_ITEMS),
        }
    }
}

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

fn kind_json(k: &NodeKind) -> Json {
    match k {
        NodeKind::Uint(n) => json!(n),
        NodeKind::Named(h) => json!(hex::encode(h)),
    }
}

fn profile_json(p: Profile) -> Json {
    match p {
        Profile::Core(n) => json!(n),
        Profile::Named(h) => json!(hex::encode(h)),
    }
}

/// A key or secret, shown as what it is and how long, never as its bytes.
fn secret(what: &str, len: usize) -> Json {
    json!({"t": "secret", "what": what, "len": len})
}

/// A record `{1: epoch id, 2: key}` whose key is that epoch's: as `rotate`
/// and `start` carry old epochs' keys.
fn is_epoch_key_pair(r: &Record) -> bool {
    let (Some(id), Some(key)) = (
        r.get(1).and_then(Value::as_bytes),
        r.get(2).and_then(Value::as_bytes),
    ) else {
        return false;
    };
    let Ok(key) = <[u8; 32]>::try_from(key) else {
        return false;
    };
    id.len() == 16 && EpochKey::from_bytes(key).id()[..] == id[..]
}

/// What a record holds that must not leave the service, by field key.
fn secret_field(r: &Record, key: u64) -> Option<&'static str> {
    if key == 2 && BlobRef::from_record(r).is_ok() {
        return Some("blob key");
    }
    if key == 2 && is_epoch_key_pair(r) {
        return Some("epoch key");
    }
    let is_invitation = r.get(0).and_then(Value::as_uint) == Some(6)
        && r.get(1)
            .and_then(Value::as_bytes)
            .is_some_and(|b| b.len() == 32);
    if key == 4 && is_invitation {
        return Some("invitation secret");
    }
    None
}

/// Whether a record holds a key or a secret anywhere within it, bytes that
/// encode records included.
fn holds_secret(r: &Record) -> bool {
    fn value(v: &Value, depth: usize) -> bool {
        if depth > MAX_DEPTH {
            return true;
        }
        match v {
            Value::Record(r) => record(r, depth),
            Value::List(l) => l.iter().any(|x| value(x, depth + 1)),
            Value::Bytes(b) if b.len() > 32 => {
                Record::decode(b).is_ok_and(|r| record(&r, depth + 1))
            }
            _ => false,
        }
    }
    fn record(r: &Record, depth: usize) -> bool {
        r.iter()
            .any(|(k, v)| secret_field(r, *k).is_some() || value(v, depth + 1))
    }
    record(r, 0)
}

/// What shape a record has that the explorer can name.
fn shape(r: &Record, store: Option<&dyn ObjectStore>) -> Option<Json> {
    if let Ok(b) = BlobRef::from_record(r) {
        let here = store.map(|s| s.has(&b.id).unwrap_or(false));
        return Some(
            json!({"is": "blob reference", "id": h(&b.id), "size": b.size,
            "levels": b.levels, "here": here}),
        );
    }
    if is_epoch_key_pair(r) {
        return Some(json!({"is": "epoch key"}));
    }
    None
}

struct Render<'a> {
    o: Opts,
    store: Option<&'a dyn ObjectStore>,
}

impl Render<'_> {
    fn value(&self, v: &Value, depth: usize) -> Json {
        let len = v.encoded_len();
        if depth > MAX_DEPTH {
            return json!({"t": "deep", "len": len});
        }
        match v {
            Value::Int(_) => json!({"t": "int", "v": v.as_int(), "len": len}),
            Value::Bytes(b) => {
                // Bytes that are themselves an encoded record, such as a
                // signed object or a grant, are read too; and if that
                // record holds a key, its bytes are not shown.
                let inner = (b.len() > 32).then(|| Record::decode(b).ok()).flatten();
                let withheld = inner.as_ref().is_some_and(holds_secret);
                let shown = if withheld {
                    &b[..0]
                } else {
                    &b[..b.len().min(self.o.limit)]
                };
                let mut out = json!({"t": "bytes", "n": b.len(), "len": len, "hex": h(shown),
                    "cut": b.len() > shown.len()});
                if withheld {
                    out["withheld"] = json!("these bytes encode a key");
                    out["cut"] = json!(false);
                }
                if let Some(r) = inner {
                    out["inner"] = self.record(&r, depth + 1);
                }
                out
            }
            Value::Text(t) => {
                let mut end = t.len().min(self.o.limit.max(80));
                while !t.is_char_boundary(end) {
                    end -= 1;
                }
                json!({"t": "text", "n": t.len(), "len": len, "v": &t[..end], "cut": end < t.len()})
            }
            Value::List(items) => {
                let shown: Vec<Json> = items
                    .iter()
                    .take(self.o.items)
                    .map(|x| self.value(x, depth + 1))
                    .collect();
                json!({"t": "list", "n": items.len(), "len": len, "items": shown,
                    "cut": items.len() > self.o.items})
            }
            Value::Record(r) => self.record(r, depth),
        }
    }

    fn record(&self, r: &Record, depth: usize) -> Json {
        let fields: Vec<Json> = r
            .iter()
            .map(|(k, v)| {
                let v = match secret_field(r, *k) {
                    Some(what) => secret(what, v.as_bytes().map_or(0, <[u8]>::len)),
                    None => self.value(v, depth + 1),
                };
                json!({"k": k, "v": v})
            })
            .collect();
        let mut out =
            json!({"t": "record", "n": r.len(), "len": r.encoded_len(), "fields": fields});
        if let Some(s) = shape(r, self.store) {
            out["shape"] = s;
        }
        out
    }
}

/// Replaces field `key` of a rendered record with a secret.
fn hide_field(rendered: &mut Json, key: u64, what: &str) {
    if let Some(fields) = rendered.get_mut("fields").and_then(Json::as_array_mut) {
        for f in fields {
            if f["k"] == json!(key) {
                let n = f["v"]["n"].as_u64().unwrap_or(0) as usize;
                f["v"] = secret(what, n);
            }
        }
    }
}

/// Follows `path` into a value: record keys, list places, and `"inner"` for
/// the record bytes encode.
fn at(v: &Value, path: &[Json]) -> anyhow::Result<Value> {
    let mut cur = v.clone();
    for step in path {
        cur = match (&cur, step) {
            (Value::Record(r), Json::Number(n)) => {
                let k = n.as_u64().unwrap_or(u64::MAX);
                if secret_field(r, k).is_some() {
                    anyhow::bail!("that is a key, and keys are not shown");
                }
                r.get(k).cloned()
            }
            (Value::List(l), Json::Number(n)) => {
                n.as_u64().and_then(|i| l.get(i as usize).cloned())
            }
            (Value::Bytes(b), Json::String(s)) if s == "inner" => {
                Record::decode(b).ok().map(Value::Record)
            }
            _ => None,
        }
        .ok_or_else(|| anyhow::anyhow!("nothing is at that path"))?;
    }
    Ok(cur)
}

/// The secret nodes of the account space: kind 5, whose field 2 is a secret
/// (`profiles.md#account`).
fn secret_nodes(sp: &Space) -> HashSet<NodeId> {
    if sp.profile() != Profile::ACCOUNT {
        return HashSet::new();
    }
    let secret = NodeKind::Uint(account::SECRET);
    sp.state()
        .nodes()
        .filter(|n| n.kind == secret)
        .map(|n| n.id)
        .collect()
}

/// An op, rendered, with what is secret in it hidden.
fn render_op(
    r: &Render,
    sp: &Space,
    secrets: &HashSet<NodeId>,
    op: &cardinal_space::SpaceOp,
) -> Json {
    let mut out = r.record(op.record(), 0);
    match op.body() {
        SpaceOpBody::Create { kind, .. }
            if sp.profile() == Profile::ACCOUNT && *kind == NodeKind::Uint(account::SECRET) =>
        {
            if let Some(f) = out.get_mut("fields").and_then(Json::as_array_mut) {
                for f in f.iter_mut().filter(|f| f["k"] == json!(4)) {
                    hide_field(&mut f["v"], 2, "secret");
                }
            }
        }
        SpaceOpBody::Set { node, key: 2, .. } if secrets.contains(node) => {
            hide_field(&mut out, 3, "secret");
        }
        _ => {}
    }
    out
}

/// Where, in an entry's record, its ops hold a secret node's value: field 2
/// of the fields a `create` of a secret gives, and the value of a `set` of
/// field 2 of one.
fn secret_positions(sp: &Space, e: &SpaceEntry) -> Vec<Vec<Json>> {
    if sp.profile() != Profile::ACCOUNT {
        return Vec::new();
    }
    let secrets = secret_nodes(sp);
    let mut out = Vec::new();
    for (i, op) in e.ops().iter().enumerate() {
        match op.body() {
            SpaceOpBody::Create { kind, .. } if *kind == NodeKind::Uint(account::SECRET) => {
                out.push(vec![json!(5), json!(i), json!(4), json!(2)]);
            }
            SpaceOpBody::Set { node, key: 2, .. } if secrets.contains(node) => {
                out.push(vec![json!(5), json!(i), json!(3)]);
            }
            _ => {}
        }
    }
    out
}

/// What an op is about, for counting bytes: the kind of the node it makes
/// or names, `"reach"` for a reach node, or nothing for a control op.
fn op_kind(sp: &Space, e: &SpaceEntry, i: usize) -> Option<Json> {
    let op = &e.ops()[i];
    let node = match op.body() {
        SpaceOpBody::Create { kind, .. } => return Some(kind_json(kind)),
        SpaceOpBody::Set { node, .. }
        | SpaceOpBody::Move { node, .. }
        | SpaceOpBody::Delete { node, .. }
        | SpaceOpBody::Restore { node } => *node,
        _ => return None,
    };
    if node == reach_node_id(&e.author()) {
        return Some(json!("reach"));
    }
    sp.state().node(&node).map(|n| kind_json(&n.kind))
}

/// Where an entry's bytes go, from its sealed form in.
fn weigh(sealed_bytes: &[u8], sp: Option<&Space>, e: Option<&SpaceEntry>) -> Json {
    let sealed_len = sealed_bytes.len();
    let rec = Record::decode(sealed_bytes).ok();
    let field_len = |k| {
        rec.as_ref()
            .and_then(|r| r.get(k))
            .map_or(0, Value::encoded_len)
    };
    let wraps = field_len(4);
    let cipher = rec
        .as_ref()
        .and_then(|r| r.get(3))
        .and_then(Value::as_bytes)
        .map_or(0, <[u8]>::len);
    let mut out = json!({
        "sealed": sealed_len,
        "wraps": wraps,
        "ciphertext": cipher,
        // the sealed record's own fields and framing: epoch, nonce, open key
        "header": sealed_len.saturating_sub(cipher + wraps),
        "aead": if cipher >= 16 { 16 } else { 0 },
    });
    let (Some(sp), Some(e)) = (sp, e) else {
        return out;
    };
    let signed = e.signed().encode().len();
    let body = e.signed().body().len();
    let mut ops = Vec::new();
    let mut ops_len = 0;
    for (i, op) in e.ops().iter().enumerate() {
        let n = op.record().encoded_len();
        ops_len += n;
        let number = op.record().get(0).map(|v| match v.as_uint() {
            Some(n) => json!(n),
            None => json!(v.as_bytes().map(h)),
        });
        ops.push(json!([number, op_kind(sp, e, i), n]));
    }
    out["signature"] = json!(signed.saturating_sub(body));
    out["fields"] = json!(body.saturating_sub(ops_len));
    out["ops"] = json!(ops);
    out
}

/// What this person calls a space, where anything says.
fn label_of(core: &Core, id: &SpaceId, sp: Option<&Space>) -> Option<String> {
    let acc = core.account().and_then(|h| h.space.as_ref());
    if core.account_id() == Some(*id) {
        return Some("account".into());
    }
    if let Some(acc) = acc {
        let st = acc.state();
        if let Some(c) = account::contacts(st).into_iter().find(|c| c.space == *id) {
            return Some(c.petname);
        }
        if let Some(s) = account::spaces(st).into_iter().find(|s| s.space == *id) {
            if !s.name.is_empty() {
                return Some(s.name);
            }
        }
    }
    let sp = sp?;
    if core.files_id() == Some(*id) {
        return Some("files".into());
    }
    // a group's name is its conversation's title
    let conv = sp
        .state()
        .children(&ROOT)
        .into_iter()
        .find(|n| n.kind == NodeKind::Uint(1));
    conv.and_then(|n| n.field(1))
        .and_then(Value::as_text)
        .map(str::to_owned)
}

fn sealed_total(hd: &Holder) -> (usize, usize) {
    let mut n = 0;
    let mut bytes = 0;
    for sid in hd.set.iter() {
        n += 1;
        bytes += hd.get(sid).map_or(0, |b| b.len());
    }
    (n, bytes)
}

fn space_brief(core: &Core, hd: &Holder) -> Json {
    let (n, bytes) = sealed_total(hd);
    let sp = hd.space.as_ref();
    let me = core.me();
    json!({
        "id": h(&hd.id),
        "label": label_of(core, &hd.id, sp),
        "profile": sp.map(|s| profile_json(s.profile())),
        "opened": sp.is_some(),
        "sealed": n,
        "bytes": bytes,
        "pending": hd.pending().len(),
        "entries": sp.map(|s| s.dag().len()),
        "valid": sp.map(|s| s.validity().valid.len()),
        "members": sp.map(|s| s.members().len()),
        "my_role": sp.and_then(|s| me.and_then(|m| s.role_of(&m))),
        "nodes": sp.map(|s| s.state().len()),
        "epochs": sp.map(|s| s.keyring().len()),
        "account": core.account_id() == Some(hd.id),
        "files": core.files_id() == Some(hd.id),
        "successor": sp.and_then(Space::successor).map(|s| h(&s)),
    })
}

fn log_bytes(log: &IdentityLog) -> usize {
    log.entries().map(|e| e.encode().len()).sum()
}

fn overview(d: &Daemon) -> Json {
    let core = d.core();
    let device = core.keys.device.key();
    let names: HashMap<[u8; 32], String> = core
        .account()
        .and_then(|h| h.space.as_ref())
        .map(|sp| {
            account::devices(sp.state())
                .into_iter()
                .map(|r| (r.key, r.name))
                .collect()
        })
        .unwrap_or_default();
    let contacts: HashMap<[u8; 32], String> = core
        .account()
        .and_then(|h| h.space.as_ref())
        .map(|sp| {
            let cs = account::contacts(sp.state()).into_iter();
            cs.map(|c| (c.identity, c.petname)).collect()
        })
        .unwrap_or_default();
    let identity = core.identity.as_ref().map(|i| {
        let st = i.state();
        let keys: Vec<Json> = st
            .roots
            .values()
            .chain(st.keys.values())
            .map(|k| {
                json!({
                    "key": h(&k.key),
                    "power": format!("{:?}", k.power).to_lowercase(),
                    "link_key": k.link_key.as_ref().map(|l| json!({"x25519": h(l.x25519()),
                        "len": l.to_record().encoded_len()})),
                    "recovery_key": k.recovery_key.as_ref().map(|l| l.to_record().encoded_len()),
                    "added_in": h(&k.added_in),
                    "name": names.get(&k.key),
                    "this_device": k.key == device,
                })
            })
            .collect();
        json!({
            "id": h(&i.id()),
            "entries": i.log.len(),
            "bytes": log_bytes(&i.log),
            "heads": i.log.heads().iter().map(|x| h(x)).collect::<Vec<_>>(),
            "frozen": st.frozen,
            "contested": st.contested,
            "keys": keys,
            "removed": st.removed().map(|k| h(k)).collect::<Vec<_>>(),
            "encryption_key": st.encryption_key.as_ref().map(|k| json!({
                "entry": h(&k.entry),
                "x25519": h(k.public.x25519()),
                "len": k.public.to_record().encoded_len(),
            })),
            // how many identity encryption keys this device can open, not
            // the keys
            "encryption_keys_held": i.enc.len(),
            "recovery_policies": st.current_policies.len(),
        })
    });
    let others: Vec<Json> = core
        .others
        .iter()
        .map(|(id, o)| {
            json!({
                "id": h(id),
                "name": contacts.get(id),
                "entries": o.log.len(),
                "bytes": log_bytes(&o.log),
            })
        })
        .collect();
    let spaces: Vec<Json> = core
        .spaces
        .values()
        .map(|hd| space_brief(&core, hd))
        .collect();
    let usage = d.store.usage();
    json!({
        "device": {"key": h(&device), "name": names.get(&device),
            "link_x25519": h(core.keys.link.public_key().x25519())},
        "identity": identity,
        "others": others,
        "spaces": spaces,
        "store": {"objects": usage.objects, "bytes": usage.bytes},
        "version": env!("CARGO_PKG_VERSION"),
    })
}

fn hex32(req: &Json, name: &str) -> anyhow::Result<[u8; 32]> {
    let s = req
        .get(name)
        .and_then(Json::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing argument {name}"))?;
    hex::decode(s)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("{name} is 32 bytes of hex"))
}

fn hex16(req: &Json, name: &str) -> anyhow::Result<[u8; 16]> {
    let s = req
        .get(name)
        .and_then(Json::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing argument {name}"))?;
    hex::decode(s)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("{name} is 16 bytes of hex"))
}

/// A record without one of its fields.
fn without(r: &Record, key: u64) -> Record {
    let mut r = r.clone();
    r.remove(key);
    r
}

fn path_of(req: &Json) -> Option<&[Json]> {
    req.get("path").and_then(Json::as_array).map(Vec::as_slice)
}

/// An identity log: this device's own, or another held here.
fn identity(d: &Daemon, req: &Json) -> anyhow::Result<Json> {
    let core = d.core();
    let own = core.identity.as_ref().map(|i| &i.log);
    let log = match req.get("who").and_then(Json::as_str) {
        None => own.ok_or_else(|| anyhow::anyhow!("this device has no identity yet"))?,
        Some(_) => {
            let who = hex32(req, "who")?;
            match own.filter(|l| l.id() == who) {
                Some(l) => l,
                None => {
                    let o = core.others.get(&who);
                    &o.ok_or_else(|| anyhow::anyhow!("no log of that identity is held here"))?
                        .log
                }
            }
        }
    };
    let o = Opts::of(req);
    let r = Render { o, store: None };
    if let Some(e) = req.get("entry").and_then(Json::as_str) {
        let id: [u8; 32] = hex::decode(e)
            .ok()
            .and_then(|b| b.try_into().ok())
            .unwrap_or_default();
        let entry = log
            .get(&id)
            .ok_or_else(|| anyhow::anyhow!("no such entry in that log"))?;
        let v = Value::Record(entry.signed().to_record());
        let v = at(&v, path_of(req).unwrap_or(&[]))?;
        return Ok(json!({"value": r.value(&v, 0)}));
    }
    let st = log.state();
    let order = log.dag().log_order();
    let entries: Vec<Json> = order
        .iter()
        .filter_map(|id| log.get(id))
        .map(|e| {
            let ops: Vec<Json> = e
                .ops()
                .iter()
                .map(|op| json!({"bytes": op.record().encoded_len(), "op": r.record(op.record(), 0)}))
                .collect();
            json!({
                "id": h(&e.id()),
                "parents": e.parents().iter().map(|p| h(p)).collect::<Vec<_>>(),
                "signer": h(&e.signer()),
                "signer_power": st.power(&e.signer()).map(|p| format!("{p:?}").to_lowercase()),
                "valid": st.is_valid(&e.id()),
                "in_effect": st.in_effect.contains(&e.id()),
                "bytes": e.encode().len(),
                "body": e.signed().body().len(),
                "signatures": e.signed().signatures().len(),
                "ops": ops,
                "header": r.record(&without(e.record(), 3), 0),
            })
        })
        .collect();
    let attached: Vec<Json> = log
        .attached()
        .map(|a| json!({"id": h(&a.id()), "entries": a.len(), "bytes": log_bytes(a)}))
        .collect();
    Ok(json!({
        "id": h(&log.id()),
        "entries": entries,
        "attached": attached,
        "stalled": st.stalled.iter().map(|x| h(x)).collect::<Vec<_>>(),
    }))
}

fn holder<'a>(core: &'a Core, req: &Json) -> anyhow::Result<&'a Holder> {
    let id = hex32(req, "space")?;
    core.spaces
        .get(&id)
        .ok_or_else(|| anyhow::anyhow!("no such space is held here"))
}

/// One space: what it is, who is in it, its epochs, and how its state is
/// made up.
fn space(d: &Daemon, req: &Json) -> anyhow::Result<Json> {
    let core = d.core();
    let hd = holder(&core, req)?;
    let mut out = space_brief(&core, hd);
    let Some(sp) = hd.space.as_ref() else {
        return Ok(out);
    };
    let contacts: HashMap<[u8; 32], String> = core
        .account()
        .and_then(|h| h.space.as_ref())
        .map(|a| {
            account::contacts(a.state())
                .into_iter()
                .map(|c| (c.identity, c.petname))
                .collect()
        })
        .unwrap_or_default();
    let me = core.me();
    let st = sp.state();
    let members: Vec<Json> = sp
        .members()
        .iter()
        .map(|m| {
            json!({
                "identity": h(&m.identity),
                "role": m.role,
                "left": sp.has_left(&m.identity),
                "added_by": sp.added_by(&m.identity).map(|x| h(&x)),
                "name": if Some(m.identity) == me { Some("me".to_string()) }
                        else { contacts.get(&m.identity).cloned() },
                "log_held": Some(m.identity) == me || core.others.contains_key(&m.identity),
                "reach_node": h(&reach_node_id(&m.identity)),
            })
        })
        .collect();

    // Epochs: which entries started each, how many entries each holds,
    // and whether this device holds its key.
    let mut epochs: BTreeMap<[u8; 16], Json> = BTreeMap::new();
    for id in sp.dag().log_order() {
        let Some(e) = sp.entry(id) else { continue };
        let ep = epochs.entry(e.epoch()).or_insert_with(|| {
            json!({"id": h(&e.epoch()), "entries": 0, "started_by": null,
                "held": sp.keyring().get(&e.epoch()).is_some()})
        });
        ep["entries"] = json!(ep["entries"].as_u64().unwrap_or(0) + 1);
        if e.starts_epoch() && ep["started_by"].is_null() {
            ep["started_by"] = json!({"entry": h(id), "author": h(&e.author()), "time": e.time()});
        }
    }
    for s in hd.pending() {
        let ep = epochs.entry(s.epoch()).or_insert_with(
            || json!({"id": h(&s.epoch()), "entries": 0, "started_by": null, "held": false}),
        );
        ep["pending"] = json!(ep["pending"].as_u64().unwrap_or(0) + 1);
    }

    // The state, by kind: how many nodes, how many deleted, their bytes.
    let mut kinds: BTreeMap<String, (Json, usize, usize, usize, usize)> = BTreeMap::new();
    for n in st.nodes() {
        let bytes = node_bytes(n);
        let k = kinds
            .entry(format!("{:?}", n.kind))
            .or_insert((kind_json(&n.kind), 0, 0, 0, 0));
        k.1 += 1;
        k.2 += n.deleted as usize;
        k.3 += bytes;
        k.4 += n.fields.values().filter(|v| v.len() > 1).count();
    }
    let kinds: Vec<Json> = kinds
        .into_values()
        .map(|(kind, n, del, bytes, conflicts)| {
            json!({"kind": kind, "nodes": n, "deleted": del, "bytes": bytes, "conflicts": conflicts})
        })
        .collect();

    // Special nodes: the root, and the reach nodes that hold anything.
    let identities: HashMap<NodeId, [u8; 32]> = sp
        .dag()
        .iter()
        .map(|(_, e)| e.author())
        .chain(sp.members().iter().map(|m| m.identity))
        .map(|i| (reach_node_id(&i), i))
        .collect();
    let o = Opts::of(req);
    let r = Render {
        o,
        store: Some(&*d.store),
    };
    let reach: Vec<Json> = st
        .reach_nodes()
        .map(|(id, fields)| {
            json!({
                "id": h(id),
                "identity": identities.get(id).map(|i| h(i)),
                "fields": fields_json(&r, fields, &HashSet::new()),
                "bytes": fields.values().flatten().map(value_bytes).sum::<usize>(),
            })
        })
        .collect();
    let root_children = st.children(&ROOT).len();
    let genesis = sp.entry(&sp.id());
    let policy = sp.policy();
    out["policy"] = json!({"history_shared": policy.history_shared, "public": sp.is_public(),
        "rotate_after": policy.rotate_after});
    out["owner"] = json!(sp.owner().map(|o| h(&o)));
    out["creator"] = json!(h(&sp.creator()));
    out["created"] = json!(genesis.and_then(SpaceEntry::time));
    out["members"] = json!(members);
    out["epochs"] = json!(epochs.into_values().collect::<Vec<_>>());
    out["current_epoch"] = json!(sp.current_epoch().map(|e| h(&e)));
    out["heads"] = json!(sp.heads().iter().map(|x| h(x)).collect::<Vec<_>>());
    out["kinds"] = json!(kinds);
    out["root"] = json!({"id": h(&ROOT), "children": root_children});
    out["reach"] = json!(reach);
    out["rejected"] = json!(st.rejected().count());
    out["unwitnessed"] = json!(sp.validity().unwitnessed.len());
    out["conflicts"] = json!(st.conflicts().len());
    out["stats"] = json!({"appended": sp.stats().appended, "recomputed": sp.stats().recomputed});
    Ok(out)
}

fn value_bytes(v: &FieldValue) -> usize {
    v.value.as_ref().map_or(0, Value::encoded_len)
}

fn node_bytes(n: &cardinal_space::Node) -> usize {
    n.name.len() + n.fields.values().flatten().map(value_bytes).sum::<usize>()
}

fn fields_json(r: &Render, fields: &BTreeMap<u64, Vec<FieldValue>>, hidden: &HashSet<u64>) -> Json {
    let out: Vec<Json> = fields
        .iter()
        .map(|(k, values)| {
            let vs: Vec<Json> = values
                .iter()
                .map(|fv| {
                    let v = match &fv.value {
                        None => json!({"t": "cleared"}),
                        Some(v) if hidden.contains(k) => secret("secret", v.encoded_len()),
                        Some(v) => r.value(v, 0),
                    };
                    json!({"entry": h(&fv.entry), "op": fv.op, "v": v})
                })
                .collect();
            json!({"k": k, "values": vs, "conflict": values.len() > 1})
        })
        .collect();
    json!(out)
}

/// The entries of a space, one page of them, as a host holds them
/// (`view: "sealed"`) or as a member reads them (`view: "opened"`, the
/// default).
fn entries(d: &Daemon, req: &Json) -> anyhow::Result<Json> {
    let core = d.core();
    let hd = holder(&core, req)?;
    let offset = req.get("offset").and_then(Json::as_u64).unwrap_or(0) as usize;
    let count = req
        .get("count")
        .and_then(Json::as_u64)
        .map_or(500, |c| (c as usize).min(MAX_PAGE));
    let sp = hd.space.as_ref();
    let mut opened: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
    if let Some(sp) = sp {
        for (eid, s) in sp.sealed_entries() {
            opened.insert(s.sealed_id(), *eid);
        }
    }
    if req.get("view").and_then(Json::as_str) == Some("sealed") {
        let mut ids: Vec<&[u8; 32]> = hd.set.iter().collect();
        ids.sort();
        let total = ids.len();
        let list: Vec<Json> = ids
            .into_iter()
            .skip(offset)
            .take(count)
            .map(|sid| {
                let bytes = hd.get(sid).unwrap_or_default();
                let s = SealedEntry::decode(&bytes).ok();
                let entry = opened.get(sid);
                let e = entry.and_then(|id| sp.and_then(|sp| sp.entry(id)));
                json!({
                    "sealed_id": h(sid),
                    "bytes": bytes.len(),
                    "epoch": s.as_ref().map(|s| h(&s.epoch())),
                    "wraps": s.as_ref().and_then(|s| s.wraps()).map(|w| w.len()),
                    "open_key": s.as_ref().is_some_and(|s| s.open_key().is_some()),
                    "entry": entry.map(|x| h(x)),
                    "position": entry.and_then(|x| sp.and_then(|sp| sp.dag().position(x))),
                    "weigh": weigh(&bytes, sp, e),
                })
            })
            .collect();
        return Ok(json!({"total": total, "offset": offset, "entries": list}));
    }
    let Some(sp) = sp else {
        anyhow::bail!("this space cannot be opened here: only its sealed entries can be seen");
    };
    let sealed_of: HashMap<[u8; 32], [u8; 32]> = opened.iter().map(|(s, e)| (*e, *s)).collect();
    let order = sp.dag().log_order();
    let st = sp.state();
    let v = sp.validity();
    let list: Vec<Json> = order
        .iter()
        .enumerate()
        .skip(offset)
        .take(count)
        .filter_map(|(pos, id)| {
            let e = sp.entry(id)?;
            let sid = sealed_of.get(id);
            let bytes = sid.and_then(|s| hd.get(s)).unwrap_or_default();
            Some(json!({
                "entry": h(id),
                "position": pos,
                "sealed_id": sid.map(|s| h(s)),
                "author": h(&e.author()),
                "signer": h(&e.signer()),
                "time": e.time(),
                "epoch": h(&e.epoch()),
                "parents": e.parents().iter().map(|p| h(p)).collect::<Vec<_>>(),
                "starts_epoch": e.starts_epoch(),
                "valid": v.is_valid(id),
                "author_ok": v.author_ok.contains(id),
                "unwitnessed": v.unwitnessed.contains(id),
                "accepted": st.is_accepted(id),
                "genesis": e.is_genesis(),
                "weigh": weigh(&bytes, Some(sp), Some(e)),
            }))
        })
        .collect();
    Ok(
        json!({"total": order.len(), "offset": offset, "entries": list,
        "pending": hd.pending().len()}),
    )
}

/// One entry whole: its sealed form, its signed object and its ops, or the
/// value at `path` within one of them (`root`: `sealed`, `signed` or
/// `entry`).
fn entry(d: &Daemon, req: &Json) -> anyhow::Result<Json> {
    let core = d.core();
    let hd = holder(&core, req)?;
    let o = Opts::of(req);
    let r = Render {
        o,
        store: Some(&*d.store),
    };
    let sp = hd.space.as_ref();
    // by entry id, or by sealed id for one this device cannot open
    let (eid, sid) = if req.get("sealed_id").is_some() {
        let sid = hex32(req, "sealed_id")?;
        let eid = sp.and_then(|sp| {
            sp.sealed_entries()
                .find(|(_, s)| s.sealed_id() == sid)
                .map(|(e, _)| *e)
        });
        (eid, Some(sid))
    } else {
        let eid = hex32(req, "entry")?;
        let sid = sp
            .and_then(|sp| sp.sealed(&eid))
            .map(SealedEntry::sealed_id);
        (Some(eid), sid)
    };
    let bytes = sid.and_then(|s| hd.get(&s));
    let sealed_value = bytes.as_ref().and_then(|b| Record::decode(b).ok());
    let e = eid.and_then(|id| sp.and_then(|sp| sp.entry(&id)));
    if let Some(path) = path_of(req) {
        let (root, rest) = path
            .split_first()
            .ok_or_else(|| anyhow::anyhow!("empty path"))?;
        let base = match root.as_str() {
            Some("sealed") => sealed_value.map(Value::Record),
            Some("signed") => e.map(|e| Value::Record(e.signed().to_record())),
            Some("entry") => e.map(|e| Value::Record(e.record().clone())),
            _ => None,
        }
        .ok_or_else(|| anyhow::anyhow!("nothing is at that path"))?;
        if root.as_str() == Some("sealed") && rest.first() == Some(&json!(5)) {
            anyhow::bail!("that is a key, and keys are not shown");
        }
        // A secret node's value is a secret only by where it is, so no path
        // may lead to it or to anything that holds it.
        if let (Some(e), Some(sp)) = (e, sp) {
            let hidden = secret_positions(sp, e);
            let under = |p: &[Json]| {
                hidden.iter().any(|h| {
                    let n = p.len().min(h.len());
                    p[..n] == h[..n]
                })
            };
            let refused = match root.as_str() {
                Some("entry") => under(rest),
                Some("signed") => !hidden.is_empty() && (rest.is_empty() || rest[0] == json!(1)),
                _ => false,
            };
            if refused {
                anyhow::bail!("that holds a secret, and secrets are not shown");
            }
        }
        let v = at(&base, rest)?;
        let mut out = r.value(&v, 0);
        if root.as_str() == Some("sealed") && rest.is_empty() {
            hide_field(&mut out, 5, "epoch key in the clear (public space)");
        }
        return Ok(json!({"value": out}));
    }
    let mut sealed_json = sealed_value.as_ref().map(|s| r.record(s, 0));
    if let Some(s) = sealed_json.as_mut() {
        hide_field(s, 5, "epoch key in the clear (public space)");
    }
    let mut out = json!({
        "entry": eid.map(|x| h(&x)),
        "sealed_id": sid.map(|x| h(&x)),
        "sealed": sealed_json,
        "weigh": bytes.as_ref().map(|b| weigh(b, sp, e)),
    });
    if let (Some(e), Some(sp)) = (e, sp) {
        let secrets = secret_nodes(sp);
        let ops: Vec<Json> = e
            .ops()
            .iter()
            .enumerate()
            .map(|(i, op)| {
                let made = matches!(op.body(), SpaceOpBody::Create { .. })
                    .then(|| h(&cardinal_space::entry::derived_id(&e.id(), i)));
                json!({
                    "index": i,
                    "bytes": op.record().encoded_len(),
                    "kind": op_kind(sp, e, i),
                    "creates": made,
                    "op": render_op(&r, sp, &secrets, op),
                })
            })
            .collect();
        let head = without(e.record(), 5);
        let sigs: Vec<Json> = e
            .signed()
            .signatures()
            .iter()
            .map(|s| json!({"key": h(&s.key), "signature": 64}))
            .collect();
        let v = sp.validity();
        out["header"] = r.record(&head, 0);
        out["ops"] = json!(ops);
        out["signatures"] = json!(sigs);
        out["valid"] = json!(v.is_valid(&e.id()));
        out["accepted"] = json!(sp.state().is_accepted(&e.id()));
        out["position"] = json!(sp.dag().position(&e.id()));
        out["children"] = json!(sp
            .dag()
            .children(&e.id())
            .iter()
            .map(|c| h(c))
            .collect::<Vec<_>>());
    }
    Ok(out)
}

fn node_brief(n: &cardinal_space::Node, sp: &Space) -> Json {
    json!({
        "id": h(&n.id),
        "kind": kind_json(&n.kind),
        "parent": h(&n.parent),
        "name": n.name,
        "deleted": n.deleted,
        "delete_conflict": n.delete_conflict,
        "creator": h(&n.creator),
        "created": n.created,
        "created_in": h(&n.created_in),
        "position": sp.dag().position(&n.created_in),
        "bytes": node_bytes(n),
        "fields": n.fields.iter().map(|(k, v)| json!([k, v.iter().map(value_bytes).sum::<usize>(), v.len()])).collect::<Vec<_>>(),
        "children": sp.state().children(&n.id).len(),
    })
}

/// The nodes of a space, those of one `kind` or under one `parent`.
fn nodes(d: &Daemon, req: &Json) -> anyhow::Result<Json> {
    let core = d.core();
    let hd = holder(&core, req)?;
    let sp = hd
        .space
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("this space cannot be opened here"))?;
    let st = sp.state();
    let kind = req.get("kind");
    let parent = match req.get("parent") {
        Some(_) => Some(hex16(req, "parent")?),
        None => None,
    };
    let offset = req.get("offset").and_then(Json::as_u64).unwrap_or(0) as usize;
    let count = req
        .get("count")
        .and_then(Json::as_u64)
        .map_or(500, |c| (c as usize).min(MAX_PAGE));
    let mut list: Vec<&cardinal_space::Node> = st
        .nodes()
        .filter(|n| kind.is_none_or(|k| kind_json(&n.kind) == *k))
        .filter(|n| parent.is_none_or(|p| n.parent == p))
        .collect();
    list.sort_by_key(|n| (sp.dag().position(&n.created_in), n.id));
    let total = list.len();
    let out: Vec<Json> = list
        .into_iter()
        .skip(offset)
        .take(count)
        .map(|n| node_brief(n, sp))
        .collect();
    Ok(json!({"total": total, "offset": offset, "nodes": out}))
}

/// One node whole: its fields and every value, and the ops in the history
/// that made or named it. `path` (field key, value place, then into the
/// value) gives one value at a time.
fn node(d: &Daemon, req: &Json) -> anyhow::Result<Json> {
    let core = d.core();
    let hd = holder(&core, req)?;
    let sp = hd
        .space
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("this space cannot be opened here"))?;
    let st = sp.state();
    let id = hex16(req, "node")?;
    let o = Opts::of(req);
    let r = Render {
        o,
        store: Some(&*d.store),
    };
    let secrets = secret_nodes(sp);
    let hidden: HashSet<u64> = if secrets.contains(&id) {
        [2].into()
    } else {
        HashSet::new()
    };
    let reach = st.reach_nodes().find(|(n, _)| **n == id).map(|(_, f)| f);
    let fields = match (st.node(&id), reach) {
        (Some(n), _) => &n.fields,
        (None, Some(f)) => f,
        (None, None) if id == ROOT => &BTreeMap::new(),
        _ => anyhow::bail!("no such node in that space"),
    };
    if let Some(path) = path_of(req) {
        let key = path
            .first()
            .and_then(Json::as_u64)
            .ok_or_else(|| anyhow::anyhow!("bad path"))?;
        if hidden.contains(&key) {
            anyhow::bail!("that is a secret, and secrets are not shown");
        }
        let i = path.get(1).and_then(Json::as_u64).unwrap_or(0) as usize;
        let v = fields
            .get(&key)
            .and_then(|vs| vs.get(i))
            .and_then(|fv| fv.value.as_ref())
            .ok_or_else(|| anyhow::anyhow!("nothing is at that path"))?;
        let v = at(v, path.get(2..).unwrap_or(&[]))?;
        return Ok(json!({"value": r.value(&v, 0)}));
    }
    let mut out = match st.node(&id) {
        Some(n) => node_brief(n, sp),
        None => json!({"id": h(&id), "special": if id == ROOT { "root" } else { "reach" }}),
    };
    out["values"] = fields_json(&r, fields, &hidden);
    if id == ROOT {
        out["children"] = json!(st.children(&ROOT).len());
    }
    // its history: every op that made or named it, in log order
    let mut history = Vec::new();
    for eid in sp.dag().log_order() {
        let Some(e) = sp.entry(eid) else { continue };
        for (i, op) in e.ops().iter().enumerate() {
            let made = matches!(op.body(), SpaceOpBody::Create { .. })
                && cardinal_space::entry::derived_id(eid, i) == id;
            let named = cardinal_space::state::named_nodes(op.body()).contains(&id);
            if made || (named && id != ROOT) {
                history.push(json!({
                    "entry": h(eid),
                    "index": i,
                    "op": op.record().get(0).and_then(Value::as_uint),
                    "author": h(&e.author()),
                    "time": e.time(),
                    "bytes": op.record().encoded_len(),
                    "valid": sp.validity().is_valid(eid),
                    "accepted": st.is_accepted(eid),
                }));
            }
        }
    }
    out["history"] = json!(history);
    Ok(out)
}

/// Answers an inspection request. The caller has checked the grant.
pub fn handle(d: &Daemon, req: &Json) -> anyhow::Result<Json> {
    let what = req.get("what").and_then(Json::as_str).unwrap_or("overview");
    tracing::debug!("inspected: {what}");
    match what {
        "overview" => Ok(overview(d)),
        "identity" => identity(d, req),
        "space" => space(d, req),
        "entries" => entries(d, req),
        "entry" => entry(d, req),
        "nodes" => nodes(d, req),
        "node" => node(d, req),
        other => anyhow::bail!("there is nothing to inspect called {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grant_needs_its_token_and_ends() {
        let i = Inspection::default();
        assert!(i.check(None).is_err(), "off until turned on");
        let (token, _) = i.grant(5).unwrap();
        assert!(i.check(Some(&token)).is_ok());
        assert!(i.check(None).is_err());
        assert!(i.check(Some(&"00".repeat(32))).is_err());
        let (again, _) = i.grant(5).unwrap();
        assert!(
            i.check(Some(&token)).is_err(),
            "a new grant ends the old token"
        );
        assert!(i.check(Some(&again)).is_ok());
        assert_eq!(i.status()["on"], true);
        assert!(i.revoke());
        assert!(i.check(Some(&again)).is_err());
        assert_eq!(i.status()["on"], false);
        assert!(i.grant(0).is_err());
        assert!(i.grant(MAX_MINUTES + 1).is_err());
    }

    #[test]
    fn an_expired_grant_is_off() {
        let i = Inspection::default();
        let (token, _) = i.grant(1).unwrap();
        i.lock().as_mut().unwrap().until = Instant::now() - Duration::from_secs(1);
        assert!(i.check(Some(&token)).is_err());
        assert_eq!(i.status()["on"], false);
    }

    fn rendered_text(j: &Json) -> String {
        j.to_string()
    }

    #[test]
    fn keys_are_never_rendered() {
        let r = Render {
            o: Opts {
                limit: MAX_LIMIT,
                items: 1000,
            },
            store: None,
        };
        // an epoch key, as `rotate` carries it
        let k = EpochKey::generate();
        let pair = Record::new()
            .with(1, k.id().to_vec())
            .with(2, k.bytes().to_vec());
        let out = rendered_text(&r.record(&pair, 0));
        assert!(!out.contains(&hex::encode(k.bytes())), "{out}");
        assert!(out.contains("epoch key"));
        // a blob reference's key
        let key = [7u8; 32];
        let blob = Record::new()
            .with(1, vec![1u8; 32])
            .with(2, key.to_vec())
            .with(3, 10u32)
            .with(4, 0u32);
        let out = rendered_text(&r.value(&Value::List(vec![Value::Record(blob.clone())]), 0));
        assert!(!out.contains(&hex::encode(key)), "{out}");
        assert!(out.contains("blob reference"));
        // an invitation's secret, even inside bytes that encode it
        let secret_bytes = [9u8; 16];
        let inv = Record::new()
            .with(0, 6u32)
            .with(1, vec![2u8; 32])
            .with(4, secret_bytes.to_vec());
        let out = rendered_text(&r.value(&Value::Bytes(inv.encode()), 0));
        assert!(!out.contains(&hex::encode(secret_bytes)), "{out}");
        // and none of them by path either
        assert!(at(&Value::Record(pair), &[json!(2)]).is_err());
        assert!(at(&Value::Record(blob), &[json!(2)]).is_err());
        assert!(at(&Value::Bytes(inv.encode()), &[json!("inner"), json!(4)]).is_err());
    }

    #[test]
    fn values_are_cut_and_say_how_long_they_are() {
        let r = Render {
            o: Opts { limit: 4, items: 2 },
            store: None,
        };
        let v = Value::Bytes(vec![0xab; 100]);
        let out = r.value(&v, 0);
        assert_eq!(out["n"], 100);
        assert_eq!(out["hex"], "abababab");
        assert_eq!(out["cut"], true);
        assert_eq!(out["len"], v.encoded_len());
        let l = Value::List(vec![
            Value::from(1u32),
            Value::from(2u32),
            Value::from(3u32),
        ]);
        let out = r.value(&l, 0);
        assert_eq!(out["n"], 3);
        assert_eq!(out["items"].as_array().unwrap().len(), 2);
        assert_eq!(out["cut"], true);
        let t = Value::Text("é".repeat(100));
        let out = r.value(&t, 0);
        assert_eq!(out["cut"], true);
        assert!(out["v"].as_str().unwrap().len() <= 80);
    }
}
