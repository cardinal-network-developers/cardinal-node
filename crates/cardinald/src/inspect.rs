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
//! key, a blob key, a secret node's value, a reach node's presence secret
//! or an invitation's secret is shown
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

use crate::api::typed::{Kind, Reference, Scalar};
use crate::api::{
    AttachedLog, EncryptionKey, EpochShown, IdentityEntry, InspectDevice, InspectEntry,
    InspectEpoch, InspectIdentity, InspectKey, InspectOp, InspectSpace, InspectValue, KindCount,
    LinkKey, NodeBrief, NodeField, NodeHistory, NodeValue, OtherLog, PolicyShown, ReachNode,
    RootShown, Shape, SignatureShown, SpaceMember, StartedBy, StatsShown, StoreShown, ValueField,
    WeighedOp, Weight,
};

use crate::core::{Core, Holder};
use crate::daemon::Daemon;

#[cfg(any(test, debug_assertions, feature = "by-name"))]
pub(crate) mod by_name;

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
/// How many entries or nodes are rendered for one page at most: fewer
/// than that fit in a message (`api::page` cuts the page to what fits).
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
    /// before stops working. Returns the token, and until when.
    pub fn grant(&self, minutes: u64) -> anyhow::Result<([u8; 32], u64)> {
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
        Ok((token, until_ms))
    }

    /// Fails unless inspection is on and `token` is its token: given as
    /// bytes, or typed in hex.
    pub fn check(&self, token: Option<&Reference>) -> anyhow::Result<()> {
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
        let given = match token {
            Some(Reference::Typed(t)) => hex::decode(t).unwrap_or_default(),
            Some(Reference::Id(b)) => b.clone(),
            None => Vec::new(),
        };
        if !cardinal_crypto::ct_eq(&given, &grant.token) {
            anyhow::bail!("that is not the token inspection was turned on with");
        }
        Ok(())
    }

    /// Turns inspection off. Returns whether it was on.
    pub fn revoke(&self) -> bool {
        let was = self.lock().take().is_some_and(|g| g.until > Instant::now());
        tracing::info!("inspection turned off");
        was
    }

    /// Whether inspection is on, and until when: for `status`, so that a
    /// window can say so.
    pub fn shown(&self) -> crate::api::Inspection {
        match &*self.lock() {
            Some(g) if g.until > Instant::now() => crate::api::Inspection {
                on: true,
                until: Some(g.until_ms),
            },
            _ => crate::api::Inspection {
                on: false,
                until: None,
            },
        }
    }
}

/// How much of each value to show.
#[derive(Clone, Copy)]
struct Opts {
    limit: usize,
    items: usize,
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

/// The nodes whose field 2 is a secret: in the account space the secret
/// nodes, kind 5 (`profiles.md#account`); and in any space every reach
/// node, whose field 2 is a presence secret (`profiles.md#reach`, D74).
fn secret_nodes(sp: &Space) -> HashSet<NodeId> {
    let st = sp.state();
    let mut out: HashSet<NodeId> = st.reach_nodes().map(|(n, _)| *n).collect();
    out.extend(sp.members().iter().map(|m| reach_node_id(&m.identity)));
    if sp.profile() == Profile::ACCOUNT {
        let secret = NodeKind::Uint(account::SECRET);
        out.extend(st.nodes().filter(|n| n.kind == secret).map(|n| n.id));
    }
    out
}

/// What this person calls a space, where anything says.
pub(crate) fn label_of(core: &Core, id: &SpaceId, sp: Option<&Space>) -> Option<String> {
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

pub(crate) fn sealed_total(hd: &Holder) -> (usize, usize) {
    let mut n = 0;
    let mut bytes = 0;
    for sid in hd.set.iter() {
        n += 1;
        bytes += hd.get(sid).map_or(0, |b| b.len());
    }
    (n, bytes)
}

fn log_bytes(log: &IdentityLog) -> usize {
    log.entries().map(|e| e.encode().len()).sum()
}

/// A record without one of its fields.
fn without(r: &Record, key: u64) -> Record {
    let mut r = r.clone();
    r.remove(key);
    r
}

fn value_bytes(v: &FieldValue) -> usize {
    v.value.as_ref().map_or(0, Value::encoded_len)
}

fn node_bytes(n: &cardinal_space::Node) -> usize {
    n.name.len() + n.fields.values().flatten().map(value_bytes).sum::<usize>()
}

impl Opts {
    /// How much of each value a request asks to be shown.
    fn given(value_bytes: Option<u64>, items: Option<u64>) -> Opts {
        let n = |v: Option<u64>, default: usize| v.map_or(default, |v| (v as usize).min(MAX_LIMIT));
        Opts {
            limit: n(value_bytes, DEFAULT_LIMIT),
            items: n(items, DEFAULT_ITEMS),
        }
    }
}

/// Where a page of entries or nodes starts, and how many are rendered for
/// it (`apps.md`, Pages).
fn page_of(after: Option<u64>, limit: Option<u64>) -> (usize, usize) {
    let after = after.unwrap_or(0) as usize;
    let limit = limit.filter(|n| *n > 0);
    (
        after,
        limit.map_or(MAX_PAGE, |c| (c as usize).min(MAX_PAGE)),
    )
}

fn kind_of(k: &NodeKind) -> Kind {
    match k {
        NodeKind::Uint(n) => Kind::Number(*n),
        NodeKind::Named(h) => Kind::Named(bytes::Bytes::copy_from_slice(h)),
    }
}

fn profile_of(p: Profile) -> Kind {
    match p {
        Profile::Core(n) => Kind::Number(n),
        Profile::Named(h) => Kind::Named(bytes::Bytes::copy_from_slice(&h)),
    }
}

/// A value rendered as only what it is: `t` alone.
fn only(t: &'static str) -> InspectValue {
    InspectValue::new(t.into())
}

/// A key or secret, shown as what it is and how long, never as its bytes.
fn secret(what: &str, len: usize) -> InspectValue {
    let mut v = only("secret");
    v.what = Some(what.to_owned());
    v.len = Some(len as u64);
    v
}

/// What shape a record has that the explorer can name.
fn shape(r: &Record, store: Option<&dyn ObjectStore>) -> Option<Shape> {
    if let Ok(b) = BlobRef::from_record(r) {
        let here = store.map(|s| s.has(&b.id).unwrap_or(false));
        let mut out = Shape::new("blob reference".into());
        out.id = Some(b.id);
        out.size = Some(b.size);
        out.levels = Some(b.levels);
        out.here = here;
        return Some(out);
    }
    if is_epoch_key_pair(r) {
        return Some(Shape::new("epoch key".into()));
    }
    None
}

struct Render<'a> {
    o: Opts,
    store: Option<&'a dyn ObjectStore>,
}

impl Render<'_> {
    fn value(&self, v: &Value, depth: usize) -> InspectValue {
        let len = v.encoded_len() as u64;
        if depth > MAX_DEPTH {
            let mut out = only("deep");
            out.len = Some(len);
            return out;
        }
        match v {
            Value::Int(_) => {
                let mut out = only("int");
                out.v = v.as_int().map(Scalar::Int);
                out.len = Some(len);
                out
            }
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
                let mut out = only("bytes");
                out.n = Some(b.len() as u64);
                out.len = Some(len);
                out.data = Some(bytes::Bytes::copy_from_slice(shown));
                out.cut = Some(b.len() > shown.len());
                if withheld {
                    out.withheld = Some("these bytes encode a key".into());
                    out.cut = Some(false);
                }
                if let Some(r) = inner {
                    out.inner = Some(Box::new(self.record(&r, depth + 1)));
                }
                out
            }
            Value::Text(t) => {
                let mut end = t.len().min(self.o.limit.max(80));
                while !t.is_char_boundary(end) {
                    end -= 1;
                }
                let mut out = only("text");
                out.n = Some(t.len() as u64);
                out.len = Some(len);
                out.v = Some(Scalar::Text(t[..end].to_owned()));
                out.cut = Some(end < t.len());
                out
            }
            Value::List(items) => {
                let shown: Vec<InspectValue> = items
                    .iter()
                    .take(self.o.items)
                    .map(|x| self.value(x, depth + 1))
                    .collect();
                let mut out = only("list");
                out.n = Some(items.len() as u64);
                out.len = Some(len);
                out.items = Some(shown);
                out.cut = Some(items.len() > self.o.items);
                out
            }
            Value::Record(r) => self.record(r, depth),
        }
    }

    fn record(&self, r: &Record, depth: usize) -> InspectValue {
        let fields: Vec<ValueField> = r
            .iter()
            .map(|(k, v)| {
                let v = match secret_field(r, *k) {
                    Some(what) => secret(what, v.as_bytes().map_or(0, <[u8]>::len)),
                    None => self.value(v, depth + 1),
                };
                ValueField { k: *k, v }
            })
            .collect();
        let mut out = only("record");
        out.n = Some(r.len() as u64);
        out.len = Some(r.encoded_len() as u64);
        out.fields = Some(fields);
        out.shape = shape(r, self.store);
        out
    }
}

/// Replaces field `key` of a rendered record with a secret.
fn hide_field(rendered: &mut InspectValue, key: u64, what: &str) {
    if let Some(fields) = rendered.fields.as_mut() {
        for f in fields {
            if f.k == key {
                let n = f.v.n.unwrap_or(0) as usize;
                f.v = secret(what, n);
            }
        }
    }
}

/// A step of a path into a value as a key or a place: a number of the
/// base encoding, as the way by name read it (a negative one is none).
fn step_number(s: &Scalar) -> Option<u64> {
    match s {
        Scalar::Int(n) => u64::try_from(*n).ok(),
        Scalar::Text(_) => None,
    }
}

/// Follows `path` into a value: record keys, list places, and `"inner"` for
/// the record bytes encode.
fn at(v: &Value, path: &[Scalar]) -> anyhow::Result<Value> {
    let mut cur = v.clone();
    for step in path {
        cur = match (&cur, step) {
            (Value::Record(r), Scalar::Int(_)) => {
                let k = step_number(step).unwrap_or(u64::MAX);
                if secret_field(r, k).is_some() {
                    anyhow::bail!("that is a key, and keys are not shown");
                }
                r.get(k).cloned()
            }
            (Value::List(l), Scalar::Int(_)) => {
                step_number(step).and_then(|i| l.get(i as usize).cloned())
            }
            (Value::Bytes(b), Scalar::Text(s)) if s == "inner" => {
                Record::decode(b).ok().map(Value::Record)
            }
            _ => None,
        }
        .ok_or_else(|| anyhow::anyhow!("nothing is at that path"))?;
    }
    Ok(cur)
}

/// An op, rendered, with what is secret in it hidden.
fn render_op(
    r: &Render,
    sp: &Space,
    secrets: &HashSet<NodeId>,
    op: &cardinal_space::SpaceOp,
) -> InspectValue {
    let mut out = r.record(op.record(), 0);
    match op.body() {
        SpaceOpBody::Create { kind, .. }
            if sp.profile() == Profile::ACCOUNT && *kind == NodeKind::Uint(account::SECRET) =>
        {
            if let Some(f) = out.fields.as_mut() {
                for f in f.iter_mut().filter(|f| f.k == 4) {
                    hide_field(&mut f.v, 2, "secret");
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
fn secret_positions(sp: &Space, e: &SpaceEntry) -> Vec<Vec<Scalar>> {
    let account = sp.profile() == Profile::ACCOUNT;
    let mut secrets = secret_nodes(sp);
    secrets.insert(reach_node_id(&e.author()));
    let mut out = Vec::new();
    let n = |x: usize| Scalar::Int(x as i64);
    for (i, op) in e.ops().iter().enumerate() {
        match op.body() {
            SpaceOpBody::Create { kind, .. }
                if account && *kind == NodeKind::Uint(account::SECRET) =>
            {
                out.push(vec![n(5), n(i), n(4), n(2)]);
            }
            SpaceOpBody::Set { node, key: 2, .. } if secrets.contains(node) => {
                out.push(vec![n(5), n(i), n(3)]);
            }
            _ => {}
        }
    }
    out
}

/// What an op is about, for counting bytes: the kind of the node it makes
/// or names, or its author's reach node; nothing for a control op.
enum About {
    Kind(Kind),
    Reach,
}

/// What an op is about: the kind of the node it makes or names, its
/// author's reach node, or nothing for a control op.
fn op_kind(sp: &Space, e: &SpaceEntry, i: usize) -> Option<About> {
    let op = &e.ops()[i];
    let node = match op.body() {
        SpaceOpBody::Create { kind, .. } => return Some(About::Kind(kind_of(kind))),
        SpaceOpBody::Set { node, .. }
        | SpaceOpBody::Move { node, .. }
        | SpaceOpBody::Delete { node, .. }
        | SpaceOpBody::Restore { node } => *node,
        _ => return None,
    };
    if node == reach_node_id(&e.author()) {
        return Some(About::Reach);
    }
    sp.state()
        .node(&node)
        .map(|n| About::Kind(kind_of(&n.kind)))
}

/// [`op_kind`] as an op's fields say it: `kind`, or `reach`.
fn op_about(sp: &Space, e: &SpaceEntry, i: usize) -> (Option<Kind>, Option<bool>) {
    match op_kind(sp, e, i) {
        Some(About::Reach) => (None, Some(true)),
        Some(About::Kind(k)) => (Some(k), None),
        None => (None, None),
    }
}

/// Where an entry's bytes go, from its sealed form in.
fn weigh(sealed_bytes: &[u8], sp: Option<&Space>, e: Option<&SpaceEntry>) -> Weight {
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
    let mut out = Weight::new(
        if cipher >= 16 { 16 } else { 0 },
        cipher as u64,
        // the sealed record's own fields and framing: epoch, nonce, open key
        sealed_len.saturating_sub(cipher + wraps) as u64,
        sealed_len as u64,
        wraps as u64,
    );
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
        let number = op.record().get(0).and_then(|v| match v.as_uint() {
            Some(n) => Some(Kind::Number(n)),
            None => v
                .as_bytes()
                .map(|b| Kind::Named(bytes::Bytes::copy_from_slice(b))),
        });
        let (kind, reach) = op_about(sp, e, i);
        let mut weighed = WeighedOp::new(n as u64);
        weighed.kind = kind;
        weighed.reach = reach;
        weighed.op = number;
        ops.push(weighed);
    }
    out.signature = Some(signed.saturating_sub(body) as u64);
    out.fields = Some(body.saturating_sub(ops_len) as u64);
    out.ops = Some(ops);
    out
}

fn space_brief(core: &Core, hd: &Holder) -> InspectSpace {
    let (n, bytes) = sealed_total(hd);
    let sp = hd.space.as_ref();
    let me = core.me();
    let mut out = InspectSpace::new(
        core.account_id() == Some(hd.id),
        bytes as u64,
        core.files_id() == Some(hd.id),
        hd.id,
        sp.is_some(),
        hd.pending().len() as u64,
        n as u64,
    );
    out.label = label_of(core, &hd.id, sp);
    out.profile = sp.map(|s| profile_of(s.profile()));
    out.entries = sp.map(|s| s.dag().len() as u64);
    out.valid = sp.map(|s| s.validity().valid.len() as u64);
    out.members = sp.map(|s| s.members().len() as u64);
    out.my_role = sp.and_then(|s| me.and_then(|m| s.role_of(&m)));
    out.nodes = sp.map(|s| s.state().len() as u64);
    out.epochs = sp.map(|s| s.keyring().len() as u64);
    out.successor = sp.and_then(Space::successor);
    out
}

/// `inspect`: the overview.
fn overview(d: &Daemon) -> crate::api::InspectReply {
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
        let keys: Vec<InspectKey> = st
            .roots
            .values()
            .chain(st.keys.values())
            .map(|k| InspectKey {
                added_in: k.added_in,
                key: k.key,
                link_key: k.link_key.as_ref().map(|l| LinkKey {
                    len: l.to_record().encoded_len() as u64,
                    x25519: *l.x25519(),
                }),
                name: names.get(&k.key).cloned(),
                power: format!("{:?}", k.power).to_lowercase(),
                recovery_key: k
                    .recovery_key
                    .as_ref()
                    .map(|l| l.to_record().encoded_len() as u64),
                this_device: k.key == device,
            })
            .collect();
        InspectIdentity {
            bytes: log_bytes(&i.log) as u64,
            contested: st.contested,
            encryption_key: st.encryption_key.as_ref().map(|k| EncryptionKey {
                entry: k.entry,
                len: k.public.to_record().encoded_len() as u64,
                x25519: *k.public.x25519(),
            }),
            // how many identity encryption keys this device can open, not
            // the keys
            encryption_keys_held: i.enc.len() as u64,
            entries: i.log.len() as u64,
            frozen: st.frozen,
            heads: i.log.heads(),
            id: i.id(),
            keys,
            recovery_policies: st.current_policies.len() as u64,
            removed: st.removed().copied().collect(),
        }
    });
    let others: Vec<OtherLog> = core
        .others
        .iter()
        .map(|(id, o)| OtherLog {
            bytes: log_bytes(&o.log) as u64,
            entries: o.log.len() as u64,
            id: *id,
            name: contacts.get(id).cloned(),
        })
        .collect();
    let spaces: Vec<InspectSpace> = core
        .spaces
        .values()
        .map(|hd| space_brief(&core, hd))
        .collect();
    let usage = d.store.usage();
    let mut reply = crate::api::InspectReply::new(
        InspectDevice {
            key: device,
            link_x25519: *core.keys.link.public_key().x25519(),
            name: names.get(&device).cloned(),
        },
        others,
        spaces,
        StoreShown {
            bytes: usage.bytes,
            objects: usage.objects,
        },
        env!("CARGO_PKG_VERSION").into(),
        false,
    );
    reply.identity = identity;
    reply
}

/// An id of `N` bytes a request gives: as bytes, or typed in hex.
fn id_of<const N: usize>(r: Option<&Reference>, name: &str) -> anyhow::Result<[u8; N]> {
    let r = r.ok_or_else(|| anyhow::anyhow!("missing argument {name}"))?;
    let b = match r {
        Reference::Typed(t) => hex::decode(t).ok(),
        Reference::Id(b) => Some(b.clone()),
    };
    b.and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("{name} is {N} bytes of hex"))
}

/// `inspect-identity`: an identity log, this device's own or another held
/// here.
fn identity(
    d: &Daemon,
    a: &crate::api::InspectIdentityArgs,
) -> anyhow::Result<crate::api::InspectIdentityReply> {
    let core = d.core();
    let own = core.identity.as_ref().map(|i| &i.log);
    let log = match a.who.as_ref() {
        None => own.ok_or_else(|| anyhow::anyhow!("this device has no identity yet"))?,
        Some(_) => {
            let who: [u8; 32] = id_of(a.who.as_ref(), "who")?;
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
    let o = Opts::given(a.value_bytes, a.items);
    let r = Render { o, store: None };
    let mut reply = crate::api::InspectIdentityReply::new(false);
    if let Some(e) = a.entry.as_ref() {
        let id: [u8; 32] = match e {
            Reference::Typed(t) => hex::decode(t).ok(),
            Reference::Id(b) => Some(b.clone()),
        }
        .and_then(|b| b.try_into().ok())
        .unwrap_or_default();
        let entry = log
            .get(&id)
            .ok_or_else(|| anyhow::anyhow!("no such entry in that log"))?;
        let v = Value::Record(entry.signed().to_record());
        let v = at(&v, a.path.as_deref().unwrap_or(&[]))?;
        reply.value = Some(r.value(&v, 0));
        return Ok(reply);
    }
    let st = log.state();
    let order = log.dag().log_order();
    let entries: Vec<IdentityEntry> = order
        .iter()
        .filter_map(|id| log.get(id))
        .map(|e| {
            let ops: Vec<InspectOp> = e
                .ops()
                .iter()
                .map(|op| {
                    InspectOp::new(op.record().encoded_len() as u64, r.record(op.record(), 0))
                })
                .collect();
            IdentityEntry {
                body: e.signed().body().len() as u64,
                bytes: e.encode().len() as u64,
                header: r.record(&without(e.record(), 3), 0),
                id: e.id(),
                in_effect: st.in_effect.contains(&e.id()),
                ops,
                parents: e.parents().to_vec(),
                signatures: e.signed().signatures().len() as u64,
                signer: e.signer(),
                signer_power: st
                    .power(&e.signer())
                    .map(|p| format!("{p:?}").to_lowercase()),
                valid: st.is_valid(&e.id()),
            }
        })
        .collect();
    let attached: Vec<AttachedLog> = log
        .attached()
        .map(|a| AttachedLog {
            bytes: log_bytes(a) as u64,
            entries: a.len() as u64,
            id: a.id(),
        })
        .collect();
    reply.id = Some(log.id());
    reply.entries = Some(entries);
    reply.attached = Some(attached);
    reply.stalled = Some(st.stalled.clone());
    Ok(reply)
}

fn holder<'a>(core: &'a Core, space: Option<&Reference>) -> anyhow::Result<&'a Holder> {
    let id: [u8; 32] = id_of(space, "space")?;
    core.spaces
        .get(&id)
        .ok_or_else(|| anyhow::anyhow!("no such space is held here"))
}

/// `inspect-space`: one space, what it is, who is in it, its epochs, and
/// how its state is made up.
fn space(
    d: &Daemon,
    a: &crate::api::InspectSpaceArgs,
) -> anyhow::Result<crate::api::InspectSpaceReply> {
    let core = d.core();
    let hd = holder(&core, a.space.as_ref())?;
    let brief = space_brief(&core, hd);
    let mut out = crate::api::InspectSpaceReply::new(
        brief.account,
        brief.bytes,
        brief.files,
        brief.id,
        brief.opened,
        brief.pending,
        brief.sealed,
        false,
    );
    out.entries = brief.entries;
    out.label = brief.label;
    out.my_role = brief.my_role;
    out.nodes = brief.nodes;
    out.profile = brief.profile;
    out.successor = brief.successor;
    out.valid = brief.valid;
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
    let members: Vec<SpaceMember> = sp
        .members()
        .iter()
        .map(|m| SpaceMember {
            added_by: sp.added_by(&m.identity),
            identity: m.identity,
            left: sp.has_left(&m.identity),
            log_held: Some(m.identity) == me || core.others.contains_key(&m.identity),
            name: if Some(m.identity) == me {
                Some("me".to_string())
            } else {
                contacts.get(&m.identity).cloned()
            },
            reach_node: reach_node_id(&m.identity),
            role: m.role,
        })
        .collect();

    // Epochs: which entries started each, how many entries each holds,
    // and whether this device holds its key.
    let mut epochs: BTreeMap<[u8; 16], EpochShown> = BTreeMap::new();
    for id in sp.dag().log_order() {
        let Some(e) = sp.entry(id) else { continue };
        let ep = epochs.entry(e.epoch()).or_insert_with(|| EpochShown {
            epoch: InspectEpoch::new(0, sp.keyring().get(&e.epoch()).is_some(), e.epoch()),
            pending: None,
        });
        ep.epoch.entries += 1;
        if e.starts_epoch() && ep.epoch.started_by.is_none() {
            ep.epoch.started_by = Some(StartedBy {
                author: e.author(),
                entry: *id,
                time: e.time(),
            });
        }
    }
    for s in hd.pending() {
        let ep = epochs.entry(s.epoch()).or_insert_with(|| EpochShown {
            epoch: InspectEpoch::new(0, false, s.epoch()),
            pending: None,
        });
        ep.pending = Some(ep.pending.unwrap_or(0) + 1);
    }

    // The state, by kind: how many nodes, how many deleted, their bytes.
    let mut kinds: BTreeMap<String, (Kind, usize, usize, usize, usize)> = BTreeMap::new();
    for n in st.nodes() {
        let bytes = node_bytes(n);
        let k = kinds
            .entry(format!("{:?}", n.kind))
            .or_insert((kind_of(&n.kind), 0, 0, 0, 0));
        k.1 += 1;
        k.2 += n.deleted as usize;
        k.3 += bytes;
        k.4 += n.fields.values().filter(|v| v.len() > 1).count();
    }
    let kinds: Vec<KindCount> = kinds
        .into_values()
        .map(|(kind, n, del, bytes, conflicts)| KindCount {
            bytes: bytes as u64,
            conflicts: conflicts as u64,
            deleted: del as u64,
            kind,
            nodes: n as u64,
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
    let o = Opts::given(a.value_bytes, a.items);
    let r = Render {
        o,
        store: Some(&*d.store),
    };
    let reach: Vec<ReachNode> = st
        .reach_nodes()
        .map(|(id, fields)| ReachNode {
            bytes: fields.values().flatten().map(value_bytes).sum::<usize>() as u64,
            fields: fields_shown(&r, fields, &HashSet::new()),
            id: *id,
            identity: identities.get(id).copied(),
        })
        .collect();
    let root_children = st.children(&ROOT).len();
    let genesis = sp.entry(&sp.id());
    let policy = sp.policy();
    out.policy = Some(PolicyShown {
        history_shared: policy.history_shared,
        public: sp.is_public(),
        rotate_after: policy.rotate_after,
    });
    out.owner = sp.owner();
    out.creator = Some(sp.creator());
    out.created = genesis.and_then(SpaceEntry::time);
    out.members = Some(members);
    out.epochs = Some(epochs.into_values().collect());
    out.current_epoch = sp.current_epoch();
    out.heads = Some(sp.heads());
    out.kinds = Some(kinds);
    out.root = Some(RootShown {
        children: root_children as u64,
        id: ROOT,
    });
    out.reach = Some(reach);
    out.rejected = Some(st.rejected().count() as u64);
    out.unwitnessed = Some(sp.validity().unwitnessed.len() as u64);
    out.conflicts = Some(st.conflicts().len() as u64);
    out.stats = Some(StatsShown {
        appended: sp.stats().appended,
        recomputed: sp.stats().recomputed,
    });
    Ok(out)
}

fn fields_shown(
    r: &Render,
    fields: &BTreeMap<u64, Vec<FieldValue>>,
    hidden: &HashSet<u64>,
) -> Vec<NodeField> {
    fields
        .iter()
        .map(|(k, values)| {
            let vs: Vec<NodeValue> = values
                .iter()
                .map(|fv| {
                    let v = match &fv.value {
                        None => only("cleared"),
                        Some(v) if hidden.contains(k) => {
                            secret("secret", v.as_bytes().map_or(v.encoded_len(), <[u8]>::len))
                        }
                        Some(v) => r.value(v, 0),
                    };
                    NodeValue {
                        entry: fv.entry,
                        op: fv.op as u64,
                        v,
                    }
                })
                .collect();
            NodeField {
                conflict: values.len() > 1,
                k: *k,
                values: vs,
            }
        })
        .collect()
}

/// `inspect-entries`: the entries of a space, one page of them, as a host
/// holds them (`view: "sealed"`) or as a member reads them (`view:
/// "opened"`, the default).
fn entries(
    d: &Daemon,
    a: &crate::api::InspectEntriesArgs,
) -> anyhow::Result<crate::api::typed::Precut<crate::api::InspectEntriesReply>> {
    let core = d.core();
    let hd = holder(&core, a.space.as_ref())?;
    let (offset, count) = page_of(a.after, a.limit);
    let sp = hd.space.as_ref();
    let mut opened: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
    if let Some(sp) = sp {
        for (eid, s) in sp.sealed_entries() {
            opened.insert(s.sealed_id(), *eid);
        }
    }
    let precut = |reply, total: usize| crate::api::typed::Precut {
        reply,
        from: offset as u64,
        total: total as u64,
    };
    if a.view.as_deref() == Some("sealed") {
        let mut ids: Vec<&[u8; 32]> = hd.set.iter().collect();
        ids.sort();
        let total = ids.len();
        let list: Vec<InspectEntry> = ids
            .into_iter()
            .skip(offset)
            .take(count)
            .map(|sid| {
                let bytes = hd.get(sid).unwrap_or_default();
                let s = SealedEntry::decode(&bytes).ok();
                let entry = opened.get(sid);
                let e = entry.and_then(|id| sp.and_then(|sp| sp.entry(id)));
                let mut out = InspectEntry::new(weigh(&bytes, sp, e));
                out.sealed_id = Some(*sid);
                out.bytes = Some(bytes.len() as u64);
                out.epoch = s.as_ref().map(|s| s.epoch());
                out.wraps = s.as_ref().and_then(|s| s.wraps()).map(|w| w.len() as u64);
                out.open_key = Some(s.as_ref().is_some_and(|s| s.open_key().is_some()));
                out.entry = entry.copied();
                out.position = entry
                    .and_then(|x| sp.and_then(|sp| sp.dag().position(x)))
                    .map(|p| p as u64);
                out
            })
            .collect();
        return Ok(precut(
            crate::api::InspectEntriesReply::new(list, total as u64, false),
            total,
        ));
    }
    let Some(sp) = sp else {
        anyhow::bail!("this space cannot be opened here: only its sealed entries can be seen");
    };
    let sealed_of: HashMap<[u8; 32], [u8; 32]> = opened.iter().map(|(s, e)| (*e, *s)).collect();
    let order = sp.dag().log_order();
    let st = sp.state();
    let v = sp.validity();
    let list: Vec<InspectEntry> = order
        .iter()
        .enumerate()
        .skip(offset)
        .take(count)
        .filter_map(|(pos, id)| {
            let e = sp.entry(id)?;
            let sid = sealed_of.get(id);
            let bytes = sid.and_then(|s| hd.get(s)).unwrap_or_default();
            let mut out = InspectEntry::new(weigh(&bytes, Some(sp), Some(e)));
            out.entry = Some(*id);
            out.position = Some(pos as u64);
            out.sealed_id = sid.copied();
            out.author = Some(e.author());
            out.signer = Some(e.signer());
            out.time = e.time();
            out.epoch = Some(e.epoch());
            out.parents = Some(e.parents().to_vec());
            out.starts_epoch = Some(e.starts_epoch());
            out.valid = Some(v.is_valid(id));
            out.author_ok = Some(v.author_ok.contains(id));
            out.unwitnessed = Some(v.unwitnessed.contains(id));
            out.accepted = Some(st.is_accepted(id));
            out.genesis = Some(e.is_genesis());
            Some(out)
        })
        .collect();
    let mut reply = crate::api::InspectEntriesReply::new(list, order.len() as u64, false);
    reply.pending = Some(hd.pending().len() as u64);
    Ok(precut(reply, order.len()))
}

/// The root of a path into an entry: `sealed`, `signed` or `entry`.
fn root_is(s: &Scalar, name: &str) -> bool {
    matches!(s, Scalar::Text(t) if t == name)
}

/// `inspect-entry`: one entry whole, its sealed form, its signed object
/// and its ops, or the value at `path` within one of them (`root`:
/// `sealed`, `signed` or `entry`).
fn entry(
    d: &Daemon,
    a: &crate::api::InspectEntryArgs,
) -> anyhow::Result<crate::api::InspectEntryReply> {
    let core = d.core();
    let hd = holder(&core, a.space.as_ref())?;
    let o = Opts::given(a.value_bytes, a.items);
    let r = Render {
        o,
        store: Some(&*d.store),
    };
    let sp = hd.space.as_ref();
    // by entry id, or by sealed id for one this device cannot open
    let (eid, sid) = if a.sealed_id.is_some() {
        let sid: [u8; 32] = id_of(a.sealed_id.as_ref(), "sealed_id")?;
        let eid = sp.and_then(|sp| {
            sp.sealed_entries()
                .find(|(_, s)| s.sealed_id() == sid)
                .map(|(e, _)| *e)
        });
        (eid, Some(sid))
    } else {
        let eid: [u8; 32] = id_of(a.entry.as_ref(), "entry")?;
        let sid = sp
            .and_then(|sp| sp.sealed(&eid))
            .map(SealedEntry::sealed_id);
        (Some(eid), sid)
    };
    let bytes = sid.and_then(|s| hd.get(&s));
    let sealed_value = bytes.as_ref().and_then(|b| Record::decode(b).ok());
    let e = eid.and_then(|id| sp.and_then(|sp| sp.entry(&id)));
    let mut out = crate::api::InspectEntryReply::new(false);
    if let Some(path) = a.path.as_deref() {
        let (root, rest) = path
            .split_first()
            .ok_or_else(|| anyhow::anyhow!("empty path"))?;
        let base = if root_is(root, "sealed") {
            sealed_value.map(Value::Record)
        } else if root_is(root, "signed") {
            e.map(|e| Value::Record(e.signed().to_record()))
        } else if root_is(root, "entry") {
            e.map(|e| Value::Record(e.record().clone()))
        } else {
            None
        }
        .ok_or_else(|| anyhow::anyhow!("nothing is at that path"))?;
        if root_is(root, "sealed") && rest.first() == Some(&Scalar::Int(5)) {
            anyhow::bail!("that is a key, and keys are not shown");
        }
        // A secret node's value is a secret only by where it is, so no path
        // may lead to it or to anything that holds it.
        if let (Some(e), Some(sp)) = (e, sp) {
            let hidden = secret_positions(sp, e);
            let under = |p: &[Scalar]| {
                hidden.iter().any(|h| {
                    let n = p.len().min(h.len());
                    p[..n] == h[..n]
                })
            };
            let refused = if root_is(root, "entry") {
                under(rest)
            } else if root_is(root, "signed") {
                !hidden.is_empty() && (rest.is_empty() || rest[0] == Scalar::Int(1))
            } else {
                false
            };
            if refused {
                anyhow::bail!("that holds a secret, and secrets are not shown");
            }
        }
        let v = at(&base, rest)?;
        let mut value = r.value(&v, 0);
        if root_is(root, "sealed") && rest.is_empty() {
            hide_field(&mut value, 5, "epoch key in the clear (public space)");
        }
        out.value = Some(value);
        return Ok(out);
    }
    let mut sealed_shown = sealed_value.as_ref().map(|s| r.record(s, 0));
    if let Some(s) = sealed_shown.as_mut() {
        hide_field(s, 5, "epoch key in the clear (public space)");
    }
    out.entry = eid;
    out.sealed_id = sid;
    out.sealed = sealed_shown;
    out.weigh = bytes.as_ref().map(|b| weigh(b, sp, e));
    if let (Some(e), Some(sp)) = (e, sp) {
        let secrets = secret_nodes(sp);
        let ops: Vec<InspectOp> = e
            .ops()
            .iter()
            .enumerate()
            .map(|(i, op)| {
                let made = matches!(op.body(), SpaceOpBody::Create { .. })
                    .then(|| cardinal_space::entry::derived_id(&e.id(), i));
                let (kind, reach) = op_about(sp, e, i);
                let mut out = InspectOp::new(
                    op.record().encoded_len() as u64,
                    render_op(&r, sp, &secrets, op),
                );
                out.kind = kind;
                out.reach = reach;
                out.index = Some(i as u64);
                out.creates = made;
                out
            })
            .collect();
        let head = without(e.record(), 5);
        let sigs: Vec<SignatureShown> = e
            .signed()
            .signatures()
            .iter()
            .map(|s| SignatureShown {
                key: s.key,
                signature: bytes::Bytes::copy_from_slice(&s.signature),
            })
            .collect();
        let v = sp.validity();
        out.header = Some(r.record(&head, 0));
        out.ops = Some(ops);
        out.signatures = Some(sigs);
        out.valid = Some(v.is_valid(&e.id()));
        out.accepted = Some(sp.state().is_accepted(&e.id()));
        out.position = sp.dag().position(&e.id()).map(|p| p as u64);
        out.children = Some(sp.dag().children(&e.id()).to_vec());
    }
    Ok(out)
}

fn node_brief(n: &cardinal_space::Node, sp: &Space) -> NodeBrief {
    NodeBrief {
        bytes: node_bytes(n) as u64,
        children: sp.state().children(&n.id).len() as u64,
        created: n.created,
        created_in: n.created_in,
        creator: n.creator,
        delete_conflict: n.delete_conflict,
        deleted: n.deleted,
        fields: n
            .fields
            .iter()
            .map(|(k, v)| {
                vec![
                    *k,
                    v.iter().map(value_bytes).sum::<usize>() as u64,
                    v.len() as u64,
                ]
            })
            .collect(),
        id: n.id,
        kind: kind_of(&n.kind),
        name: n.name.clone(),
        parent: n.parent,
        position: sp.dag().position(&n.created_in).map(|p| p as u64),
    }
}

/// `inspect-nodes`: the nodes of a space, those of one `kind` or under one
/// `parent`.
fn nodes(
    d: &Daemon,
    a: &crate::api::InspectNodesArgs,
) -> anyhow::Result<crate::api::typed::Precut<crate::api::InspectNodesReply>> {
    let core = d.core();
    let hd = holder(&core, a.space.as_ref())?;
    let sp = hd
        .space
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("this space cannot be opened here"))?;
    let st = sp.state();
    let kind = a.kind.as_ref();
    let parent: Option<[u8; 16]> = match a.parent.as_ref() {
        Some(_) => Some(id_of(a.parent.as_ref(), "parent")?),
        None => None,
    };
    let (offset, count) = page_of(a.after, a.limit);
    let mut list: Vec<&cardinal_space::Node> = st
        .nodes()
        .filter(|n| kind.is_none_or(|k| kind_of(&n.kind) == *k))
        .filter(|n| parent.is_none_or(|p| n.parent == p))
        .collect();
    list.sort_by_key(|n| (sp.dag().position(&n.created_in), n.id));
    let total = list.len();
    let out: Vec<NodeBrief> = list
        .into_iter()
        .skip(offset)
        .take(count)
        .map(|n| node_brief(n, sp))
        .collect();
    Ok(crate::api::typed::Precut {
        reply: crate::api::InspectNodesReply::new(out, total as u64, false),
        from: offset as u64,
        total: total as u64,
    })
}

/// `inspect-node`: one node whole, its fields and every value, and the ops
/// in the history that made or named it. `path` (field key, value place,
/// then into the value) gives one value at a time.
fn node(
    d: &Daemon,
    a: &crate::api::InspectNodeArgs,
) -> anyhow::Result<crate::api::InspectNodeReply> {
    let core = d.core();
    let hd = holder(&core, a.space.as_ref())?;
    let sp = hd
        .space
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("this space cannot be opened here"))?;
    let st = sp.state();
    let id: [u8; 16] = id_of(a.node.as_ref(), "node")?;
    let o = Opts::given(a.value_bytes, a.items);
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
    let mut out = crate::api::InspectNodeReply::new(false);
    if let Some(path) = a.path.as_deref() {
        let key = path
            .first()
            .and_then(step_number)
            .ok_or_else(|| anyhow::anyhow!("bad path"))?;
        if hidden.contains(&key) {
            anyhow::bail!("that is a secret, and secrets are not shown");
        }
        let i = path.get(1).and_then(step_number).unwrap_or(0) as usize;
        let v = fields
            .get(&key)
            .and_then(|vs| vs.get(i))
            .and_then(|fv| fv.value.as_ref())
            .ok_or_else(|| anyhow::anyhow!("nothing is at that path"))?;
        let v = at(v, path.get(2..).unwrap_or(&[]))?;
        out.value = Some(r.value(&v, 0));
        return Ok(out);
    }
    match st.node(&id) {
        Some(n) => {
            let b = node_brief(n, sp);
            out.bytes = Some(b.bytes);
            out.children = Some(b.children);
            out.created = b.created;
            out.created_in = Some(b.created_in);
            out.creator = Some(b.creator);
            out.delete_conflict = Some(b.delete_conflict);
            out.deleted = Some(b.deleted);
            out.fields = Some(b.fields);
            out.id = Some(b.id);
            out.kind = Some(b.kind);
            out.name = Some(b.name);
            out.parent = Some(b.parent);
            out.position = b.position;
        }
        None => {
            out.id = Some(id);
            out.special = Some(if id == ROOT { "root" } else { "reach" }.into());
        }
    }
    out.values = Some(fields_shown(&r, fields, &hidden));
    if id == ROOT {
        out.children = Some(st.children(&ROOT).len() as u64);
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
                history.push(NodeHistory {
                    accepted: st.is_accepted(eid),
                    author: e.author(),
                    bytes: op.record().encoded_len() as u64,
                    entry: *eid,
                    index: i as u64,
                    op: op.record().get(0).and_then(Value::as_uint),
                    time: e.time(),
                    valid: sp.validity().is_valid(eid),
                });
            }
        }
    }
    out.history = Some(history);
    Ok(out)
}

/// The typed inspection requests' answers (`control::typed`): the grant
/// checked first, then the view.
pub mod answers {
    use super::*;
    use crate::api::*;

    /// `inspect`.
    pub fn overview(d: &Daemon, a: &InspectArgs) -> anyhow::Result<InspectReply> {
        d.inspection.check(a.token.as_ref())?;
        tracing::debug!("inspected: overview");
        Ok(super::overview(d))
    }

    /// `inspect-identity`.
    pub fn identity(d: &Daemon, a: &InspectIdentityArgs) -> anyhow::Result<InspectIdentityReply> {
        d.inspection.check(a.token.as_ref())?;
        tracing::debug!("inspected: identity");
        super::identity(d, a)
    }

    /// `inspect-space`.
    pub fn space(d: &Daemon, a: &InspectSpaceArgs) -> anyhow::Result<InspectSpaceReply> {
        d.inspection.check(a.token.as_ref())?;
        tracing::debug!("inspected: space");
        super::space(d, a)
    }

    /// `inspect-entries`.
    pub fn entries(
        d: &Daemon,
        a: &InspectEntriesArgs,
    ) -> anyhow::Result<typed::Precut<InspectEntriesReply>> {
        d.inspection.check(a.token.as_ref())?;
        tracing::debug!("inspected: entries");
        super::entries(d, a)
    }

    /// `inspect-entry`.
    pub fn entry(d: &Daemon, a: &InspectEntryArgs) -> anyhow::Result<InspectEntryReply> {
        d.inspection.check(a.token.as_ref())?;
        tracing::debug!("inspected: entry");
        super::entry(d, a)
    }

    /// `inspect-nodes`.
    pub fn nodes(
        d: &Daemon,
        a: &InspectNodesArgs,
    ) -> anyhow::Result<typed::Precut<InspectNodesReply>> {
        d.inspection.check(a.token.as_ref())?;
        tracing::debug!("inspected: nodes");
        super::nodes(d, a)
    }

    /// `inspect-node`.
    pub fn node(d: &Daemon, a: &InspectNodeArgs) -> anyhow::Result<InspectNodeReply> {
        d.inspection.check(a.token.as_ref())?;
        tracing::debug!("inspected: node");
        super::node(d, a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grant_needs_its_token_and_ends() {
        let i = Inspection::default();
        let typed = |t: &[u8]| Reference::Typed(hex::encode(t));
        assert!(i.check(None).is_err(), "off until turned on");
        let (token, _) = i.grant(5).unwrap();
        assert!(i.check(Some(&Reference::Id(token.to_vec()))).is_ok());
        assert!(i.check(Some(&typed(&token))).is_ok());
        assert!(i
            .check(Some(&Reference::Typed(hex::encode(token).to_uppercase())))
            .is_ok());
        assert!(i.check(None).is_err());
        assert!(i.check(Some(&typed(&[0; 32]))).is_err());
        let (again, _) = i.grant(5).unwrap();
        assert!(
            i.check(Some(&typed(&token))).is_err(),
            "a new grant ends the old token"
        );
        assert!(i.check(Some(&typed(&again))).is_ok());
        assert!(i.shown().on);
        assert!(i.revoke());
        assert!(i.check(Some(&typed(&again))).is_err());
        assert!(!i.shown().on);
        assert!(i.grant(0).is_err());
        assert!(i.grant(MAX_MINUTES + 1).is_err());
    }

    #[test]
    fn keys_are_never_rendered() {
        use crate::api::typed::Wire;
        let r = Render {
            o: Opts {
                limit: MAX_LIMIT,
                items: 1000,
            },
            store: None,
        };
        let shown = |v: &InspectValue| {
            let mut out = Vec::new();
            v.encode_into(&mut out);
            out
        };
        let holds = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
        // an epoch key, as `rotate` carries it
        let k = EpochKey::generate();
        let pair = Record::new()
            .with(1, k.id().to_vec())
            .with(2, k.bytes().to_vec());
        let out = r.record(&pair, 0);
        assert!(!holds(&shown(&out), k.bytes()));
        assert_eq!(out.shape.as_ref().unwrap().is, "epoch key");
        // a blob reference's key
        let key = [7u8; 32];
        let blob = Record::new()
            .with(1, vec![1u8; 32])
            .with(2, key.to_vec())
            .with(3, 10u32)
            .with(4, 0u32);
        let out = r.value(&Value::List(vec![Value::Record(blob.clone())]), 0);
        assert!(!holds(&shown(&out), &key));
        // an invitation's secret, even inside bytes that encode it
        let secret_bytes = [9u8; 16];
        let inv = Record::new()
            .with(0, 6u32)
            .with(1, vec![2u8; 32])
            .with(4, secret_bytes.to_vec());
        let out = r.value(&Value::Bytes(inv.encode()), 0);
        assert!(!holds(&shown(&out), &secret_bytes));
        // and none of them by path either
        let int = |n: i64| Scalar::Int(n);
        assert!(at(&Value::Record(pair), &[int(2)]).is_err());
        assert!(at(&Value::Record(blob), &[int(2)]).is_err());
        assert!(at(
            &Value::Bytes(inv.encode()),
            &[Scalar::Text("inner".into()), int(4)]
        )
        .is_err());
    }
}
