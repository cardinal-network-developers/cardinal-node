//! The application interface (`apps.md#the-application-interface`): a
//! second endpoint beside the person's own, for any program. A program
//! gives the application documents it implements, and sees and changes
//! only the spaces of the families the person approved it for, through
//! handles, with what it writes checked against its documents
//! (`profiles.md#applications-normative`) before this device signs it.
//!
//! Approvals are nodes of the account (kind 18), so every device of the
//! person lists them. The person is asked through their window: here a
//! question the person's interface lists (`app-questions`) and answers
//! (`app-answer`), as `cardinal approve` does.
//!
//! On a plain Linux desktop a program is named by the executable its
//! connection's peer runs. Every program there runs as the person and can
//! read this service's files, so an approval records what the person
//! chose, and protects nothing.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use cardinal_encoding::{Record, Value};
use cardinal_identity::EntryId;
use cardinal_link::Priority;
use cardinal_space::application::{self, Document, Family, Type};
use cardinal_space::entry::derived_id;
use cardinal_space::{
    account, NodeId, NodeKind, Profile, Space, SpaceId, SpaceOp, SpaceOpBody, ROOT,
};
use serde_json::{json, Value as Json};
use tokio::sync::oneshot;

use crate::core::{now_ms, Core};
use crate::daemon::Daemon;
use crate::transport::{Listener, Reader, Received, Writer, MAX_MESSAGE};

/// The version of this interface: 1, a draft until it is published.
pub const API: u64 = 1;
/// The account's approval kind (`profiles.md#account`).
pub const APPROVAL: u64 = 18;
/// The most a page holds of what a reply lists, so that it fits a message.
const PAGE_BYTES: usize = 200 * 1024;

/// The requests, by number (`apps.md`, Numbers).
mod req {
    pub const HELLO: u64 = 1;
    pub const WATCH: u64 = 2;
    pub const APPROVE: u64 = 3;
    pub const NEW_SPACE: u64 = 4;
    pub const SPACES: u64 = 5;
    pub const MEMBERS: u64 = 6;
    pub const NODES: u64 = 7;
    pub const WRITE: u64 = 8;
    pub const FILE_PUT: u64 = 9;
    pub const FILE_GET: u64 = 10;
    pub const SHARE: u64 = 11;
}

/// The errors, by number.
mod err {
    pub const FAILED: u64 = 1;
    pub const MALFORMED: u64 = 2;
    pub const UNKNOWN: u64 = 3;
    pub const TOO_LARGE: u64 = 4;
    pub const NOT_APPROVED: u64 = 5;
    pub const REFUSED: u64 = 6;
}

/// A request not done: the error's number, why, and for a refused write
/// the op's place.
struct No {
    code: u64,
    why: String,
    at: Option<usize>,
}

fn no(code: u64, why: impl Into<String>) -> No {
    No {
        code,
        why: why.into(),
        at: None,
    }
}

fn failed(e: impl std::fmt::Display) -> No {
    no(err::FAILED, format!("{e:#}"))
}

impl From<anyhow::Error> for No {
    fn from(e: anyhow::Error) -> No {
        failed(e)
    }
}

type Answer = Result<Record, No>;

/// What the person is asked.
#[derive(Clone, Debug)]
pub enum Asks {
    /// May the program see, or see and change, every space of a family.
    Family { root: [u8; 32], change: bool },
    /// May it start a space, and change the family's spaces.
    NewSpace { root: [u8; 32], name: String },
    /// Whom to share a space with, and as what.
    Share { space: SpaceId, role: u64 },
}

/// The person's answer.
#[derive(Debug, Default)]
pub struct Said {
    pub yes: bool,
    pub people: Vec<String>,
    pub role: Option<u64>,
}

/// A question waiting for the person.
pub struct Question {
    pub id: u64,
    pub program: String,
    pub named: String,
    pub asks: Asks,
    pub what: String,
    answer: Option<oneshot::Sender<Said>>,
}

/// What the service keeps for the application interface, in memory.
pub struct Apps {
    /// The sequence numbers given since this service started are above
    /// this; one below it is answered whole.
    base: u64,
    questions: Mutex<(u64, Vec<Question>)>,
    seqs: Mutex<HashMap<SpaceId, Tracker>>,
    /// The files put by programs, by handle, until they are written.
    files: Mutex<HashMap<[u8; 16], (SpaceId, Record)>>,
}

impl Default for Apps {
    fn default() -> Apps {
        Apps {
            base: now_ms().saturating_mul(1000),
            questions: Mutex::new((1, Vec::new())),
            seqs: Mutex::new(HashMap::new()),
            files: Mutex::new(HashMap::new()),
        }
    }
}

/// The order in which this device took a space's entries, since it
/// started: what a sequence number counts.
#[derive(Default)]
struct Tracker {
    seen: HashMap<EntryId, u64>,
    next: u64,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Apps {
    /// The space's sequence number now, taking note of what is new.
    fn seq(&self, sp: &Space) -> u64 {
        let mut all = lock(&self.seqs);
        let t = all.entry(sp.id()).or_default();
        // what was there when this service first looked counts as 0
        let first = t.seen.is_empty();
        for e in sp.state().applied() {
            if !t.seen.contains_key(e) {
                let n = if first { 0 } else { t.next + 1 };
                t.next = n;
                t.seen.insert(*e, n);
            }
        }
        self.base + t.next
    }

    /// The entries taken after `since`, or `None` when it is no number
    /// given since this service started: then everything.
    fn since(&self, sp: &Space, since: u64) -> Option<Vec<EntryId>> {
        let now = self.seq(sp);
        if since < self.base || since > now {
            return None;
        }
        let all = lock(&self.seqs);
        let t = all.get(&sp.id())?;
        let after = since - self.base;
        Some(
            t.seen
                .iter()
                .filter(|(_, n)| **n > after)
                .map(|(e, _)| *e)
                .collect(),
        )
    }

    /// Asks the person, and waits for the answer.
    async fn ask(&self, d: &Daemon, program: &str, named: &str, asks: Asks, what: String) -> Said {
        let (tx, rx) = oneshot::channel();
        {
            let mut q = lock(&self.questions);
            let id = q.0;
            q.0 += 1;
            q.1.retain(|q| q.answer.as_ref().is_some_and(|a| !a.is_closed()));
            q.1.push(Question {
                id,
                program: program.to_owned(),
                named: named.to_owned(),
                asks,
                what,
                answer: Some(tx),
            });
        }
        d.bump();
        let said = rx.await.unwrap_or_default();
        d.bump();
        said
    }
}

// ---- Approvals in the account ----

/// An approval node of the account.
#[derive(Clone, Debug)]
pub struct Approval {
    pub node: NodeId,
    pub device: [u8; 32],
    pub program: String,
    pub named: String,
    pub family: [u8; 32],
    pub change: bool,
    pub revoked: bool,
}

/// Every approval the account holds.
pub fn approvals(core: &Core) -> Vec<Approval> {
    let Some(acc) = core.account().and_then(|a| a.space.as_ref()) else {
        return Vec::new();
    };
    let st = acc.state();
    let last = |n: &cardinal_space::Node, k| n.values(k).iter().rev().find_map(|v| v.value.clone());
    st.children(&ROOT)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(APPROVAL) && !n.deleted)
        .filter_map(|n| {
            let b32 =
                |v: Option<Value>| v.and_then(|v| v.as_bytes().and_then(|b| b.try_into().ok()));
            let text = |k| last(n, k).and_then(|v| v.as_text().map(str::to_owned));
            let flag = |k| last(n, k).and_then(|v| v.as_bool()).unwrap_or(false);
            Some(Approval {
                node: n.id,
                device: b32(last(n, 1))?,
                program: text(2)?,
                named: text(3).unwrap_or_default(),
                family: b32(last(n, 4))?,
                change: flag(5),
                revoked: n
                    .values(6)
                    .iter()
                    .any(|v| v.value.as_ref().and_then(Value::as_bool) == Some(true)),
            })
        })
        .collect()
}

/// The families a program is approved for on this device, and whether it
/// may change each.
fn approved(d: &Daemon, program: &str) -> HashMap<[u8; 32], bool> {
    let me = d.keys.key();
    let mut out: HashMap<[u8; 32], bool> = HashMap::new();
    for a in approvals(&d.core()) {
        if a.device == me && a.program == program && !a.revoked {
            *out.entry(a.family).or_default() |= a.change;
        }
    }
    out
}

fn record_approval(
    d: &Arc<Daemon>,
    program: &str,
    named: &str,
    root: [u8; 32],
    change: bool,
) -> anyhow::Result<()> {
    let account = d
        .core()
        .account_id()
        .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
    let fields = Record::new()
        .with(1, d.keys.key())
        .with(2, program)
        .with(3, named)
        .with(4, root)
        .with(5, change);
    let op = SpaceOp::create(NodeKind::Uint(APPROVAL), ROOT, "approval", fields);
    d.write_and_push(&account, vec![op])?;
    Ok(())
}

// ---- Handles ----

fn handle_key(d: &Daemon) -> [u8; 32] {
    blake3::derive_key("cardinal application handles 1", &d.keys.signing.seed()[..])
}

/// A handle: opaque, and different for each program on this device.
fn handle(d: &Daemon, program: &str, what: &[u8], id: &[u8]) -> [u8; 16] {
    let mut h = blake3::Hasher::new_keyed(&handle_key(d));
    h.update(&(program.len() as u64).to_le_bytes());
    h.update(program.as_bytes());
    h.update(&(what.len() as u64).to_le_bytes());
    h.update(what);
    h.update(id);
    h.finalize().as_bytes()[..16].try_into().expect("16")
}

fn space_handle(d: &Daemon, program: &str, space: &SpaceId) -> [u8; 16] {
    handle(d, program, b"space", space)
}

fn member_handle(d: &Daemon, program: &str, space: &SpaceId, who: &[u8; 32]) -> [u8; 16] {
    let mut what = b"member".to_vec();
    what.extend_from_slice(space);
    handle(d, program, &what, who)
}

fn file_handle(d: &Daemon, program: &str, space: &SpaceId, blob: &Record) -> [u8; 16] {
    let mut what = b"file".to_vec();
    what.extend_from_slice(space);
    handle(d, program, &what, &blob.encode())
}

// ---- A connection ----

struct Conn {
    program: String,
    named: String,
    family: Option<Family>,
}

impl Conn {
    fn family(&self) -> Result<&Family, No> {
        self.family
            .as_ref()
            .ok_or_else(|| no(err::NOT_APPROVED, "say hello first, with your documents"))
    }
}

/// How the platform names the program at the other end of a connection.
fn program_of(pid: Option<u32>) -> String {
    let exe = pid.and_then(|p| std::fs::read_link(format!("/proc/{p}/exe")).ok());
    match exe {
        Some(p) => {
            let p = p.to_string_lossy();
            p.strip_suffix(" (deleted)").unwrap_or(&p).to_owned()
        }
        None => "unknown".to_owned(),
    }
}

/// Starts serving the application interface.
#[cfg(unix)]
pub fn serve(d: Arc<Daemon>) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let path = d.paths.app_socket();
    let mut listener =
        Listener::bind(&path).map_err(|e| anyhow::anyhow!("{e:#} for {}", path.display()))?;
    Ok(tokio::spawn(async move {
        loop {
            let Ok((r, w, pid)) = listener.accept_peer().await else {
                continue;
            };
            let conn = Conn {
                program: program_of(pid),
                named: String::new(),
                family: None,
            };
            tokio::spawn(connection(d.clone(), conn, r, w));
        }
    }))
}

fn reply(r: Answer) -> Vec<u8> {
    let rec = match r {
        Ok(rec) => rec.with(0, 0u64),
        Err(n) => Record::new()
            .with(0, n.code)
            .with(1, n.why.as_str())
            .with_opt(2, n.at.map(|a| a as u64)),
    };
    let bytes = rec.encode();
    if bytes.len() > MAX_MESSAGE {
        return Record::new()
            .with(0, err::TOO_LARGE)
            .with(1, "the answer would be larger than a message: ask for less")
            .encode();
    }
    bytes
}

async fn connection(d: Arc<Daemon>, mut conn: Conn, mut r: Reader, mut w: Writer) {
    while let Ok(Some(got)) = r.recv().await {
        let msg = match got {
            Received::Message(m) => m,
            Received::TooLarge => {
                let why = format!("a message is at most {MAX_MESSAGE} bytes");
                if w.send(&reply(Err(no(err::MALFORMED, why)))).await.is_err() {
                    return;
                }
                continue;
            }
        };
        let Ok(rec) = Record::decode(&msg) else {
            if w.send(&reply(Err(no(err::MALFORMED, "not one canonical record"))))
                .await
                .is_err()
            {
                return;
            }
            continue;
        };
        let number = rec.get(0).and_then(Value::as_uint);
        if number == Some(req::WATCH) {
            if conn.family.is_none() {
                let _ = w
                    .send(&reply(Err(no(err::NOT_APPROVED, "say hello first"))))
                    .await;
                continue;
            }
            if w.send(&reply(Ok(Record::new()))).await.is_ok() {
                watch(&d, &conn, r, w).await;
            }
            return;
        }
        let answer = match number {
            Some(req::HELLO) => hello(&d, &mut conn, &rec),
            Some(n) => request(&d, &conn, n, &rec).await,
            None => Err(no(err::MALFORMED, "a request's key 0 is its number")),
        };
        if w.send(&reply(answer)).await.is_err() {
            return;
        }
    }
}

async fn request(d: &Arc<Daemon>, conn: &Conn, n: u64, rec: &Record) -> Answer {
    match n {
        req::APPROVE => approve(d, conn, rec).await,
        req::NEW_SPACE => new_space(d, conn, rec).await,
        req::SPACES => spaces(d, conn, rec),
        req::MEMBERS => members(d, conn, rec),
        req::NODES => nodes(d, conn, rec),
        req::WRITE => write(d, conn, rec),
        req::FILE_PUT => file_put(d, conn, rec).await,
        req::FILE_GET => file_get(d, conn, rec).await,
        req::SHARE => share(d, conn, rec).await,
        _ => Err(no(err::UNKNOWN, format!("there is no request {n}"))),
    }
}

// ---- Arguments ----

fn bytes_arg<const N: usize>(rec: &Record, k: u64, what: &str) -> Result<[u8; N], No> {
    rec.get(k)
        .and_then(Value::as_bytes)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| no(err::MALFORMED, format!("{what} is {N} bytes")))
}

fn text_arg<'a>(rec: &'a Record, k: u64, what: &str) -> Result<&'a str, No> {
    rec.get(k)
        .and_then(Value::as_text)
        .ok_or_else(|| no(err::MALFORMED, format!("{what} is text")))
}

fn uint_opt(rec: &Record, k: u64) -> Result<Option<u64>, No> {
    match rec.get(k) {
        None => Ok(None),
        Some(v) => v
            .as_uint()
            .map(Some)
            .ok_or_else(|| no(err::MALFORMED, format!("field {k} is an unsigned integer"))),
    }
}

/// A page of `items`, each already encoded as a value: those from `after`,
/// as many as `limit` says or as fit. Answers them, `more` and `next`.
fn page(
    items: Vec<Value>,
    rec: &Record,
    after_key: u64,
    limit_key: u64,
) -> Result<(Vec<Value>, bool, u64), No> {
    let after = uint_opt(rec, after_key)?.unwrap_or(0) as usize;
    let limit = uint_opt(rec, limit_key)?
        .filter(|l| *l > 0)
        .map(|l| l as usize);
    let mut out = Vec::new();
    let mut size = 0;
    let mut at = after;
    for v in items.into_iter().skip(after) {
        let n = v.encoded_len();
        if limit.is_some_and(|l| out.len() >= l) || (!out.is_empty() && size + n > PAGE_BYTES) {
            return Ok((out, true, at as u64));
        }
        if n > PAGE_BYTES {
            return Err(no(
                err::TOO_LARGE,
                format!("item {at} is too large for a message on its own"),
            ));
        }
        size += n;
        out.push(v);
        at += 1;
    }
    Ok((out, false, at as u64))
}

// ---- What a program may see ----

/// The spaces a program may see, with the family each is of, and whether
/// it may change it.
fn visible(d: &Daemon, program: &str) -> Vec<(SpaceId, [u8; 32], bool)> {
    let ok = approved(d, program);
    if ok.is_empty() {
        return Vec::new();
    }
    let core = d.core();
    let Some(me) = core.me() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, h) in &core.spaces {
        let Some(sp) = h.space.as_ref() else { continue };
        let Profile::Named(root) = sp.profile() else {
            continue;
        };
        let Some(change) = ok.get(&root) else {
            continue;
        };
        if !core.is_joined(id) || core.is_superseded(id) || sp.has_left(&me) {
            continue;
        }
        let role = sp.role_of(&me).unwrap_or(0);
        out.push((*id, root, *change && role >= cardinal_space::group::WRITER));
    }
    out
}

/// The space a handle names, if the program may see it.
fn space_of(
    d: &Daemon,
    conn: &Conn,
    rec: &Record,
    k: u64,
) -> Result<(SpaceId, [u8; 32], bool), No> {
    let h: [u8; 16] = bytes_arg(rec, k, "a space")?;
    visible(d, &conn.program)
        .into_iter()
        .find(|(id, _, _)| space_handle(d, &conn.program, id) == h)
        .ok_or_else(|| {
            no(
                err::NOT_APPROVED,
                "no space this program may see has that handle",
            )
        })
}

fn hello(d: &Arc<Daemon>, conn: &mut Conn, rec: &Record) -> Answer {
    let named = rec
        .get(1)
        .and_then(Value::as_text)
        .unwrap_or("")
        .trim()
        .to_owned();
    let docs = match rec.get(2) {
        None => Vec::new(),
        Some(v) => v
            .as_list()
            .ok_or_else(|| no(err::MALFORMED, "documents are a list of bytes"))?
            .iter()
            .map(|b| {
                let b = b
                    .as_bytes()
                    .ok_or_else(|| no(err::MALFORMED, "a document is bytes"))?;
                Document::parse(b).map_err(|e| no(err::FAILED, e))
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    let names: Vec<Value> = docs.iter().map(|d| Value::from(d.name)).collect();
    let family = Family::new(docs).map_err(|e| no(err::FAILED, e))?;
    conn.named = if named.is_empty() {
        "A program".into()
    } else {
        named
    };
    conn.family = Some(family);
    let ok = approved(d, &conn.program);
    let approved: Vec<Value> = ok
        .iter()
        .map(|(f, c)| Value::Record(Record::new().with(1, *f).with_opt(2, c.then_some(true))))
        .collect();
    Ok(Record::new()
        .with(2, API)
        .with(3, env!("CARGO_PKG_VERSION"))
        .with(4, Value::List(names))
        .with(5, conn.program.as_str())
        .with(7, Value::List(approved)))
}

/// The title of an application the program gave, or of one a space holds.
fn title(conn: &Conn, root: &[u8; 32]) -> String {
    conn.family
        .as_ref()
        .and_then(|f| f.document(root))
        .map(|d| d.title.clone())
        .unwrap_or_else(|| "an application".into())
}

const UNISOLATED: &str = "Any program on this computer could read all of your Cardinal data.";

fn root_given(conn: &Conn, rec: &Record, k: u64) -> Result<[u8; 32], No> {
    let root: [u8; 32] = bytes_arg(rec, k, "an application")?;
    let f = conn.family()?;
    match f.document(&root) {
        Some(d) if d.parent.is_none() && d.translates.is_none() => Ok(root),
        Some(_) => Err(no(err::FAILED, "that is not the root of its family")),
        None => Err(no(err::FAILED, "that application was not given in hello")),
    }
}

async fn approve(d: &Arc<Daemon>, conn: &Conn, rec: &Record) -> Answer {
    let root = root_given(conn, rec, 1)?;
    let change = rec.get(2).and_then(Value::as_bool).unwrap_or(false);
    let had = approved(d, &conn.program).get(&root).copied();
    let done = |change: bool| {
        Record::new().with(
            2,
            Record::new()
                .with(1, root)
                .with_opt(2, change.then_some(true)),
        )
    };
    if had.is_some_and(|c| c || !change) {
        return Ok(done(had.unwrap_or(false)));
    }
    let t = title(conn, &root);
    let what = match change {
        true => format!("{} may see and change every {t} you have, and those shared with you later. {UNISOLATED}", conn.named),
        false => format!("{} may see every {t} you have, and those shared with you later. {UNISOLATED}", conn.named),
    };
    let said = d
        .apps
        .ask(
            d,
            &conn.program,
            &conn.named,
            Asks::Family { root, change },
            what,
        )
        .await;
    if !said.yes {
        return Ok(Record::new());
    }
    record_approval(d, &conn.program, &conn.named, root, change)?;
    Ok(done(change))
}

async fn new_space(d: &Arc<Daemon>, conn: &Conn, rec: &Record) -> Answer {
    let root = root_given(conn, rec, 1)?;
    let name = text_arg(rec, 2, "a name")?.trim().to_owned();
    if name.is_empty() || name.contains('\n') {
        return Err(no(err::FAILED, "a space's name is one line, not empty"));
    }
    let may = approved(d, &conn.program).get(&root).copied() == Some(true);
    if !may {
        let t = title(conn, &root);
        let what = format!(
            "{} wants to start a {t}: {name}. It will be able to see and change every {t} you have, and those shared with you later. {UNISOLATED}",
            conn.named
        );
        let asks = Asks::NewSpace {
            root,
            name: name.clone(),
        };
        if !d
            .apps
            .ask(d, &conn.program, &conn.named, asks, what)
            .await
            .yes
        {
            return Err(no(err::NOT_APPROVED, "the person said no"));
        }
        record_approval(d, &conn.program, &conn.named, root, true)?;
    }
    let doc = conn.family()?.document(&root).expect("given").clone();
    let genesis = vec![SpaceOp::from_record(application::document_node(&doc))];
    let id = d.core().create_app_space(root, genesis)?;
    let account = d
        .core()
        .account_id()
        .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
    d.write_and_push(&account, vec![account::create_space(&id, &name)])?;
    d.bump();
    Ok(Record::new().with(2, space_handle(d, &conn.program, &id)))
}

/// The person's name for a space: the account's.
fn local_name(core: &Core, id: &SpaceId) -> String {
    let Some(acc) = core.account().and_then(|a| a.space.as_ref()) else {
        return String::new();
    };
    account::spaces(acc.state())
        .into_iter()
        .filter(|s| s.space == *id && !s.declined)
        .map(|s| s.name)
        .find(|n| !n.is_empty())
        .unwrap_or_default()
}

fn spaces(d: &Arc<Daemon>, conn: &Conn, rec: &Record) -> Answer {
    conn.family()?;
    let all = visible(d, &conn.program);
    let items: Vec<Value> = {
        let core = d.core();
        all.iter()
            .map(|(id, root, change)| {
                let sp = core.spaces.get(id).and_then(|h| h.space.as_ref());
                let owner = sp.and_then(|sp| {
                    sp.members()
                        .iter()
                        .find(|m| m.role == cardinal_space::group::OWNER)
                        .map(|m| m.identity)
                });
                Value::Record(
                    Record::new()
                        .with(1, space_handle(d, &conn.program, id))
                        .with(2, local_name(&core, id))
                        .with(3, *root)
                        .with_opt(4, owner.map(|o| member_handle(d, &conn.program, id, &o)))
                        .with_opt(5, change.then_some(true)),
                )
            })
            .collect()
    };
    let (items, more, next) = page(items, rec, 1, 2)?;
    Ok(Record::new()
        .with(2, Value::List(items))
        .with_opt(3, more.then_some(true))
        .with_opt(4, more.then_some(next)))
}

fn role_name(role: u64) -> &'static str {
    match role {
        cardinal_space::group::OWNER => "owner",
        cardinal_space::group::ADMIN => "admin",
        cardinal_space::group::WRITER => "writer",
        _ => "reader",
    }
}

/// The members of a space, as the program is given them.
fn member_list(d: &Daemon, program: &str, id: &SpaceId) -> Vec<Value> {
    let me_name = crate::names::my_name(d);
    let core = d.core();
    let me = core.me();
    let contacts = core.contacts();
    let Some(sp) = core.spaces.get(id).and_then(|h| h.space.as_ref()) else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for m in sp.members() {
        if !seen.insert(m.identity) {
            continue;
        }
        let you = Some(m.identity) == me;
        let name = if you {
            me_name.clone()
        } else {
            contacts
                .iter()
                .find(|c| c.identity == m.identity)
                .map(|c| match c.petname.is_empty() {
                    false => c.petname.clone(),
                    true => c.suggested.clone().unwrap_or_default(),
                })
                .unwrap_or_default()
        };
        let role = sp.role_of(&m.identity).unwrap_or(m.role);
        out.push(Value::Record(
            Record::new()
                .with(1, member_handle(d, program, id, &m.identity))
                .with(2, name)
                .with(3, role_name(role))
                .with_opt(4, you.then_some(true))
                .with_opt(5, sp.has_left(&m.identity).then_some(true)),
        ));
    }
    out
}

fn members(d: &Arc<Daemon>, conn: &Conn, rec: &Record) -> Answer {
    let (id, _, _) = space_of(d, conn, rec, 1)?;
    let items = member_list(d, &conn.program, &id);
    let (items, more, next) = page(items, rec, 2, 3)?;
    Ok(Record::new()
        .with(2, Value::List(items))
        .with_opt(3, more.then_some(true))
        .with_opt(4, more.then_some(next)))
}

/// The nodes the entries named or made, with what is beneath those they
/// deleted or restored.
fn touched(sp: &Space, entries: &[EntryId]) -> HashSet<NodeId> {
    let st = sp.state();
    let mut out = HashSet::new();
    let mut below = Vec::new();
    for e in entries {
        let Some(entry) = sp.entry(e) else { continue };
        for (i, op) in entry.ops().iter().enumerate() {
            match op.body() {
                SpaceOpBody::Create { .. } => {
                    out.insert(derived_id(e, i));
                }
                SpaceOpBody::Set { node, .. } | SpaceOpBody::Move { node, .. } => {
                    out.insert(*node);
                }
                SpaceOpBody::Delete { node, .. } | SpaceOpBody::Restore { node } => {
                    out.insert(*node);
                    below.push(*node);
                }
                _ => {}
            }
        }
    }
    while let Some(n) = below.pop() {
        for c in st.children(&n) {
            if out.insert(c.id) {
                below.push(c.id);
            }
        }
    }
    out
}

/// A value of the space as the program is given it: members and files as
/// handles.
fn outward(
    d: &Daemon,
    program: &str,
    space: &SpaceId,
    ty: Option<(Type, bool)>,
    v: &Value,
) -> Value {
    let one = |t: Type, v: &Value| -> Value {
        match t {
            Type::Member => match v.as_bytes().and_then(|b| <[u8; 32]>::try_from(b).ok()) {
                Some(who) => Value::from(member_handle(d, program, space, &who)),
                None => v.clone(),
            },
            Type::File => match v.as_record() {
                Some(r) => {
                    let h = file_handle(d, program, space, r);
                    lock(&d.apps.files).insert(h, (*space, r.clone()));
                    Value::from(h)
                }
                None => v.clone(),
            },
            _ => v.clone(),
        }
    };
    match ty {
        Some((t @ (Type::Member | Type::File), false)) => one(t, v),
        Some((t @ (Type::Member | Type::File), true)) => match v.as_list() {
            Some(items) => Value::List(items.iter().map(|x| one(t, x)).collect()),
            None => v.clone(),
        },
        _ => v.clone(),
    }
}

fn nodes(d: &Arc<Daemon>, conn: &Conn, rec: &Record) -> Answer {
    let (id, _, _) = space_of(d, conn, rec, 1)?;
    let family = conn.family()?;
    let parent: Option<NodeId> = match rec.get(2) {
        None => None,
        Some(_) => Some(bytes_arg(rec, 2, "a parent")?),
    };
    let kind = match rec.get(3) {
        None => None,
        Some(v) => Some(match (v.as_uint(), v.as_bytes()) {
            (Some(n), _) => NodeKind::Uint(n),
            (_, Some(b)) => NodeKind::Named(
                b.try_into()
                    .map_err(|_| no(err::MALFORMED, "a kind is a number or 32 bytes"))?,
            ),
            _ => return Err(no(err::MALFORMED, "a kind is a number or 32 bytes")),
        }),
    };
    let since = uint_opt(rec, 4)?;
    let program = &conn.program;
    let (items, seq) = {
        let core = d.core();
        let sp = core
            .spaces
            .get(&id)
            .and_then(|h| h.space.as_ref())
            .ok_or_else(|| no(err::FAILED, "that space is not open here"))?;
        let seq = d.apps.seq(sp);
        let changed = since
            .and_then(|s| d.apps.since(sp, s))
            .map(|e| touched(sp, &e));
        let st = sp.state();
        let mut all: Vec<&cardinal_space::Node> = st
            .nodes()
            .filter(|n| n.kind != NodeKind::Uint(application::DOCUMENT_NODE))
            .filter(|n| parent.is_none_or(|p| n.parent == p))
            .filter(|n| kind.is_none_or(|k| n.kind == k))
            .filter(|n| match &changed {
                Some(c) => c.contains(&n.id),
                None => st.is_visible(&n.id),
            })
            .collect();
        all.sort_by_key(|n| (n.created, n.id));
        let items: Vec<Value> = all
            .into_iter()
            .map(|n| {
                let def = family.known(&n.kind).map(|k| k.def.clone());
                let mut fields = Vec::new();
                for (key, values) in &n.fields {
                    if *key == application::AUTHOR_OWNED {
                        continue;
                    }
                    let ty = def
                        .as_ref()
                        .and_then(|k| k.field(*key))
                        .map(|f| (f.ty, f.list));
                    let set: Vec<_> = values
                        .iter()
                        .filter_map(|v| v.value.as_ref().map(|x| (v.entry, x)))
                        .collect();
                    let f = match set.as_slice() {
                        [] => continue,
                        [(_, v)] => Record::new()
                            .with(1, *key)
                            .with(2, outward(d, program, &id, ty, v)),
                        many => {
                            let versions = many.iter().map(|(e, v)| {
                                let by = sp
                                    .entry(e)
                                    .map(|e| member_handle(d, program, &id, &e.author()));
                                Value::Record(
                                    Record::new()
                                        .with(1, outward(d, program, &id, ty, v))
                                        .with_opt(2, by),
                                )
                            });
                            Record::new()
                                .with(1, *key)
                                .with(3, Value::List(versions.collect()))
                        }
                    };
                    fields.push(Value::Record(f));
                }
                let deleted = !st.is_visible(&n.id);
                Value::Record(
                    Record::new()
                        .with(1, n.id)
                        .with(2, n.kind.to_value())
                        .with(3, n.parent)
                        .with(4, n.name.as_str())
                        .with(5, Value::List(fields))
                        .with_opt(6, family.fits(st, n).then_some(true))
                        .with_opt(7, deleted.then_some(true))
                        .with(8, member_handle(d, program, &id, &n.creator))
                        .with_opt(9, n.created),
                )
            })
            .collect();
        (items, seq)
    };
    let (items, more, next) = page(items, rec, 5, 6)?;
    Ok(Record::new()
        .with(2, Value::List(items))
        .with(3, seq)
        .with_opt(4, more.then_some(true))
        .with_opt(5, more.then_some(next)))
}

/// A value the program wrote, as the space holds it: handles of members
/// and files turned back into what they name.
fn inward(
    d: &Daemon,
    program: &str,
    space: &SpaceId,
    sp: &Space,
    ty: Option<(Type, bool)>,
    v: &Value,
) -> Result<Value, String> {
    let one = |t: Type, v: &Value| -> Result<Value, String> {
        let h: Option<[u8; 16]> = v.as_bytes().and_then(|b| b.try_into().ok());
        match t {
            Type::Member => {
                let h = h.ok_or("a member is given by its handle")?;
                sp.members()
                    .iter()
                    .find(|m| member_handle(d, program, space, &m.identity) == h)
                    .map(|m| Value::from(m.identity))
                    .ok_or_else(|| "no member of the space has that handle".into())
            }
            Type::File => {
                let h = h.ok_or("a file is given by its handle")?;
                let files = lock(&d.apps.files);
                match files.get(&h) {
                    Some((s, r)) if s == space => Ok(Value::Record(r.clone())),
                    _ => Err("no file of the space has that handle".into()),
                }
            }
            _ => Ok(v.clone()),
        }
    };
    match ty {
        Some((t @ (Type::Member | Type::File), false)) => one(t, v),
        Some((t @ (Type::Member | Type::File), true)) => match v.as_list() {
            Some(items) => Ok(Value::List(
                items.iter().map(|x| one(t, x)).collect::<Result<_, _>>()?,
            )),
            None => Ok(v.clone()),
        },
        _ => Ok(v.clone()),
    }
}

fn write(d: &Arc<Daemon>, conn: &Conn, rec: &Record) -> Answer {
    let (id, root, change) = space_of(d, conn, rec, 1)?;
    if !change {
        return Err(no(
            err::NOT_APPROVED,
            "this program may not change that space",
        ));
    }
    let family = conn.family()?.only(&[root]);
    let ops: Vec<Record> = rec
        .get(2)
        .and_then(Value::as_list)
        .ok_or_else(|| no(err::MALFORMED, "ops are a list of records"))?
        .iter()
        .map(|v| {
            v.as_record()
                .cloned()
                .ok_or_else(|| no(err::MALFORMED, "an op is a record"))
        })
        .collect::<Result<_, _>>()?;
    if ops.is_empty() {
        return Err(no(err::FAILED, "a write has one op at least"));
    }
    let program = &conn.program;
    let refused = |at: usize, why: String| No {
        code: err::REFUSED,
        why,
        at: Some(at),
    };
    let written = {
        let mut core = d.core();
        let me = core
            .me()
            .ok_or_else(|| no(err::FAILED, "this device has no identity yet"))?;
        let checked = {
            let sp = core
                .spaces
                .get(&id)
                .and_then(|h| h.space.as_ref())
                .ok_or_else(|| no(err::FAILED, "that space is not open here"))?;
            // members and files back from their handles
            let mut inside = Vec::new();
            for (at, op) in ops.iter().enumerate() {
                let mut op = op.clone();
                match op.get(0).and_then(Value::as_uint) {
                    Some(32) => {
                        let kind = op.get(1).and_then(|v| match (v.as_uint(), v.as_bytes()) {
                            (Some(n), _) => Some(NodeKind::Uint(n)),
                            (_, Some(b)) => b.try_into().ok().map(NodeKind::Named),
                            _ => None,
                        });
                        let def = kind.and_then(|k| family.known(&k)).map(|k| k.def.clone());
                        if let (Some(def), Some(fields)) =
                            (def, op.get(4).and_then(Value::as_record).cloned())
                        {
                            let mut out = Record::new();
                            for (k, v) in fields.iter() {
                                let ty = def.field(*k).map(|f| (f.ty, f.list));
                                out.insert(
                                    *k,
                                    inward(d, program, &id, sp, ty, v)
                                        .map_err(|e| refused(at, e))?,
                                );
                            }
                            op.insert(4, out);
                        }
                    }
                    Some(33) => {
                        let node: Option<NodeId> = op
                            .get(1)
                            .and_then(Value::as_bytes)
                            .and_then(|b| b.try_into().ok());
                        let n = node.and_then(|n| sp.state().node(&n));
                        let def = n.and_then(|n| family.known(&n.kind)).map(|k| k.def.clone());
                        let key = op.get(2).and_then(Value::as_uint);
                        if let (Some(def), Some(key), Some(v)) = (def, key, op.get(3).cloned()) {
                            let ty = def.field(key).map(|f| (f.ty, f.list));
                            op.insert(
                                3,
                                inward(d, program, &id, sp, ty, &v).map_err(|e| refused(at, e))?,
                            );
                        }
                    }
                    _ => {}
                }
                inside.push(op);
            }
            let checked = application::check(&family, sp.state(), &me, &inside)
                .map_err(|r| refused(r.at, r.why))?;
            let mut all = checked.clone();
            for doc in application::documents_wanted(&family, sp.state(), &checked) {
                all.push(application::document_node(&doc));
            }
            all
        };
        let ops: Vec<SpaceOp> = checked.into_iter().map(SpaceOp::from_record).collect();
        core.write_entry(&id, ops)?
    };
    let (entry, bytes) = written;
    d.push(&id, vec![bytes]);
    d.bump();
    let made: Vec<Value> = ops
        .iter()
        .enumerate()
        .filter(|(_, op)| op.get(0).and_then(Value::as_uint) == Some(32))
        .map(|(i, _)| Value::from(derived_id(&entry, i)))
        .collect();
    Ok(Record::new().with(2, Value::List(made)).with(3, "waiting"))
}

/// The key content is stored under in a space now.
fn secret(d: &Daemon, space: &SpaceId) -> anyhow::Result<cardinal_blob::ConvergenceSecret> {
    let core = d.core();
    let sp = core.spaces.get(space).and_then(|h| h.space.as_ref());
    let sp = sp.ok_or_else(|| anyhow::anyhow!("that space is not open here"))?;
    let key = sp.current_epoch().and_then(|e| sp.keyring().get(&e));
    let key = key.ok_or_else(|| anyhow::anyhow!("that space has no key yet"))?;
    Ok(cardinal_blob::ConvergenceSecret::from_epoch_key(
        key.bytes(),
    ))
}

async fn file_put(d: &Arc<Daemon>, conn: &Conn, rec: &Record) -> Answer {
    let (id, _, change) = space_of(d, conn, rec, 1)?;
    if !change {
        return Err(no(
            err::NOT_APPROVED,
            "this program may not change that space",
        ));
    }
    let from = std::path::PathBuf::from(text_arg(rec, 2, "from")?);
    let secret = secret(d, &id)?;
    let dd = d.clone();
    let blob = tokio::task::spawn_blocking(move || -> anyhow::Result<cardinal_blob::BlobRef> {
        let mut f = std::fs::File::open(&from)
            .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", from.display()))?;
        anyhow::ensure!(f.metadata()?.is_file(), "{} is not a file", from.display());
        let mut w = cardinal_blob::BlobWriter::new(&secret, &*dd.store);
        std::io::copy(&mut f, &mut w)?;
        Ok(w.finish()?.0)
    })
    .await
    .map_err(failed)??;
    let r = blob.to_record();
    let h = file_handle(d, &conn.program, &id, &r);
    lock(&d.apps.files).insert(h, (id, r));
    Ok(Record::new().with(2, h).with(3, blob.size))
}

async fn file_get(d: &Arc<Daemon>, conn: &Conn, rec: &Record) -> Answer {
    let (id, _, _) = space_of(d, conn, rec, 1)?;
    let h: [u8; 16] = bytes_arg(rec, 2, "a file")?;
    let to = std::path::PathBuf::from(text_arg(rec, 3, "to")?);
    let blob = {
        let files = lock(&d.apps.files);
        match files.get(&h) {
            Some((s, r)) if *s == id => r.clone(),
            _ => {
                return Err(no(
                    err::FAILED,
                    "no file of that space has that handle: list its nodes first",
                ))
            }
        }
    };
    let blob = cardinal_blob::BlobRef::from_record(&blob)
        .map_err(|_| no(err::FAILED, "that file cannot be read"))?;
    let members: Vec<[u8; 32]> = {
        let core = d.core();
        let sp = core.spaces.get(&id).and_then(|h| h.space.as_ref());
        sp.map(|sp| sp.present()).unwrap_or_default()
    };
    let in_touch = d.people_in_touch();
    let from: Vec<[u8; 32]> = members
        .into_iter()
        .filter(|w| in_touch.contains(w))
        .collect();
    let mut last = anyhow::anyhow!("nobody who has it is in touch right now");
    for who in from.into_iter().map(Some).chain([None]) {
        let (dd, written) = (d.clone(), to.clone());
        let got = tokio::task::spawn_blocking(move || -> anyhow::Result<u64> {
            let fetch = match who {
                Some(w) => crate::fetch::Fetcher::from_contact(&dd, Priority::Interactive, w),
                None => crate::fetch::Fetcher::new(&dd, Priority::Interactive),
            };
            let mut reader = cardinal_blob::BlobReader::new(&*dd.store, &fetch, blob);
            crate::contacts::write_new(&written, |out| crate::contacts::write_out(&mut reader, out))
        })
        .await
        .map_err(failed)?;
        match got {
            Ok(size) => return Ok(Record::new().with(2, size)),
            Err(e) => last = e,
        }
    }
    Err(failed(last))
}

async fn share(d: &Arc<Daemon>, conn: &Conn, rec: &Record) -> Answer {
    let (id, root, _) = space_of(d, conn, rec, 1)?;
    let (shared, role) = conn
        .family()?
        .document(&root)
        .and_then(|doc| doc.sharing)
        .unwrap_or((false, 0));
    if !shared {
        return Err(no(
            err::FAILED,
            "a space of this application has no members but its owner",
        ));
    }
    {
        let core = d.core();
        let me = core
            .me()
            .ok_or_else(|| no(err::FAILED, "this device has no identity yet"))?;
        let sp = core.spaces.get(&id).and_then(|h| h.space.as_ref());
        let mine = sp.and_then(|sp| sp.role_of(&me)).unwrap_or(0);
        if mine < cardinal_space::group::ADMIN {
            return Err(no(err::FAILED, "only its owner or an admin shares a space"));
        }
    }
    let name = local_name(&d.core(), &id);
    let what = format!(
        "{} wants to share {name}. Choose whom to share it with: they can {} unless you say otherwise.",
        conn.named,
        if role >= 1 { "see and change it" } else { "see it" }
    );
    let said = d
        .apps
        .ask(
            d,
            &conn.program,
            &conn.named,
            Asks::Share { space: id, role },
            what,
        )
        .await;
    if said.yes && !said.people.is_empty() {
        let role = said.role.unwrap_or(role);
        let theirs: Vec<_> = said
            .people
            .iter()
            .map(|p| crate::contacts::listed(d, p))
            .collect::<anyhow::Result<_>>()?;
        let ids: Vec<[u8; 32]> = theirs.iter().map(|c| c.identity).collect();
        let bytes = d.core().add_to_space(&id, &ids, role)?;
        d.push(&id, vec![bytes]);
        for c in &theirs {
            let op = cardinal_space::group::create_offer_of(&id, &name, Profile::Named(root));
            d.write_and_push(&c.space, vec![op])?;
        }
        d.bump();
    }
    Ok(Record::new().with(2, Value::List(member_list(d, &conn.program, &id))))
}

/// Tells the program whenever a space it may see changed, with the
/// space's sequence number, each one at the start.
async fn watch(d: &Arc<Daemon>, conn: &Conn, mut r: Reader, mut w: Writer) {
    let mut changed = d.changed.subscribe();
    let mut stopping = d.stopping.subscribe();
    let mut told: HashMap<SpaceId, u64> = HashMap::new();
    loop {
        changed.borrow_and_update();
        let now: Vec<(SpaceId, u64)> = {
            let visible = visible(d, &conn.program);
            let core = d.core();
            visible
                .iter()
                .filter_map(|(id, _, _)| {
                    let sp = core.spaces.get(id)?.space.as_ref()?;
                    Some((*id, d.apps.seq(sp)))
                })
                .collect()
        };
        for (id, seq) in now {
            if told.get(&id) == Some(&seq) {
                continue;
            }
            let ev = Record::new()
                .with(0, 1u64)
                .with(1, space_handle(d, &conn.program, &id))
                .with(2, seq);
            if w.send(&ev.encode()).await.is_err() {
                return;
            }
            told.insert(id, seq);
        }
        tokio::select! {
            c = changed.changed() => if c.is_err() { return },
            _ = stopping.changed() => return,
            m = r.recv() => match m {
                Ok(Some(_)) => {}
                _ => return,
            },
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

// ---- The person's side (`apps.md`, numbers 220 to 229) ----

fn asks_name(a: &Asks) -> &'static str {
    match a {
        Asks::Family { .. } => "family",
        Asks::NewSpace { .. } => "new-space",
        Asks::Share { .. } => "share",
    }
}

/// `app-questions`: what programs ask the person, waiting.
pub fn questions(d: &Daemon) -> Json {
    let mut q = lock(&d.apps.questions);
    q.1.retain(|q| q.answer.as_ref().is_some_and(|a| !a.is_closed()));
    let all: Vec<Json> =
        q.1.iter()
            .map(|q| {
                let role = match q.asks {
                    Asks::Share { role, .. } => Some(role_name(role)),
                    _ => None,
                };
                json!({"id": q.id, "program": q.program, "name": q.named, "what": q.what,
                   "asks": asks_name(&q.asks), "role": role})
            })
            .collect();
    json!({"questions": all})
}

/// `app-answer`: the person's answer to a question.
pub fn answer(d: &Daemon, req: &Json) -> anyhow::Result<Json> {
    let id = req["id"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("missing argument id"))?;
    let yes = req["yes"].as_bool() == Some(true);
    let people: Vec<String> = req["people"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| p.as_str().map(|s| crate::api::id_hex(s).to_owned()))
        .collect();
    let role = match req["role"].as_str() {
        None | Some("") => None,
        Some("reader") => Some(cardinal_space::group::READER),
        Some("writer") => Some(cardinal_space::group::WRITER),
        Some(r) => anyhow::bail!("a role is reader or writer, not {r}"),
    };
    let tx = {
        let mut q = lock(&d.apps.questions);
        let at = q.1.iter().position(|q| q.id == id);
        let at = at.ok_or_else(|| anyhow::anyhow!("no question {id} is waiting"))?;
        let q = q.1.remove(at);
        if let Asks::Share { .. } = q.asks {
            anyhow::ensure!(!yes || !people.is_empty(), "say whom to share it with");
        }
        q.answer
    };
    if let Some(tx) = tx {
        let _ = tx.send(Said { yes, people, role });
    }
    d.bump();
    Ok(json!({}))
}

/// The title of a family's root, from a space of it that holds its
/// document node.
fn family_title(core: &Core, root: &[u8; 32]) -> Option<(String, String)> {
    core.spaces.values().find_map(|h| {
        let sp = h.space.as_ref()?;
        if sp.profile() != Profile::Named(*root) {
            return None;
        }
        application::documents_in(sp.state())
            .into_iter()
            .find(|d| d.name == *root)
            .map(|d| (d.title, d.sentence))
    })
}

/// `approvals`: every approval of the person's, on every device.
pub fn list_approvals(d: &Daemon) -> Json {
    let core = d.core();
    let acc = core.account().and_then(|a| a.space.as_ref());
    let me = d.keys.key();
    let all: Vec<Json> = approvals(&core)
        .into_iter()
        .map(|a| {
            let device = acc.and_then(|s| account::device_name(s.state(), &a.device));
            let covers = family_title(&core, &a.family).map(|t| t.0).unwrap_or_else(|| hex::encode(&a.family[..8]));
            json!({"id": hex::encode(a.node), "device": device, "program": a.program, "name": a.named,
                   "covers": covers, "family": hex::encode(a.family), "change": a.change,
                   "revoked": a.revoked, "this_device": a.device == me})
        })
        .collect();
    json!({"approvals": all})
}

/// `approval-revoke`: sets an approval's field 6.
pub fn revoke(d: &Arc<Daemon>, id: &str) -> anyhow::Result<Json> {
    let id = crate::api::id_hex(id).to_ascii_lowercase();
    let (account, node) = {
        let core = d.core();
        let found: Vec<NodeId> = approvals(&core)
            .into_iter()
            .map(|a| a.node)
            .filter(|n| !id.is_empty() && hex::encode(n).starts_with(&id))
            .collect();
        let node = match found[..] {
            [one] => one,
            [] => anyhow::bail!("there is no approval {id}"),
            _ => anyhow::bail!("more than one approval starts with {id}"),
        };
        let account = core
            .account_id()
            .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
        (account, node)
    };
    d.write_and_push(&account, vec![account::set_field(node, 6, true)])?;
    Ok(json!({}))
}

/// A space offered: its id, the name it was offered by, who offered it,
/// and its application's title and sentence where the space says them.
type Offered = (SpaceId, String, String, Option<(String, String)>);

/// The spaces of applications offered to this person and not yet taken:
/// (space, name, from, the application's title and sentence).
fn offers(core: &Core) -> Vec<Offered> {
    let declined = core.declined();
    let mut out: Vec<Offered> = Vec::new();
    for c in core.contacts().into_iter().filter(|c| !c.refused) {
        for o in core.offers_from(&c.identity) {
            let Some(sp) = core.spaces.get(&o.space).and_then(|h| h.space.as_ref()) else {
                continue;
            };
            let Profile::Named(root) = sp.profile() else {
                continue;
            };
            if core.is_joined(&o.space)
                || declined.contains(&o.space)
                || out.iter().any(|x| x.0 == o.space)
            {
                continue;
            }
            let doc = application::documents_in(sp.state())
                .into_iter()
                .find(|d| d.name == root)
                .map(|d| (d.title, d.sentence));
            let from = if c.petname.is_empty() {
                c.suggested.clone().unwrap_or_default()
            } else {
                c.petname.clone()
            };
            out.push((o.space, o.name, from, doc));
        }
    }
    out
}

/// `app-offers`: spaces of applications offered to this person.
pub fn list_offers(d: &Daemon) -> Json {
    let all: Vec<Json> = offers(&d.core())
        .into_iter()
        .map(|(id, name, from, doc)| {
            let (app, sentence) = doc.unzip();
            json!({"space": hex::encode(id), "name": name, "from": from,
                   "application": app, "sentence": sentence})
        })
        .collect();
    json!({"offers": all})
}

/// `app-join`: the person takes a space offered them; it is kept in the
/// account, as a group joined with nothing to say there is (D75).
pub fn join(d: &Arc<Daemon>, space: &str) -> anyhow::Result<Json> {
    let s = crate::api::id_hex(space).to_ascii_lowercase();
    let (id, name, account) = {
        let core = d.core();
        let all = offers(&core);
        let found: Vec<_> = all
            .into_iter()
            .filter(|o| (!s.is_empty() && hex::encode(o.0).starts_with(&s)) || o.1 == space)
            .collect();
        let (id, name) = match &found[..] {
            [one] => (one.0, one.1.clone()),
            [] => anyhow::bail!("nothing offered to you is {space}"),
            _ => anyhow::bail!("more than one offer is {space}: give its id"),
        };
        let account = core
            .account_id()
            .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
        (id, name, account)
    };
    d.write_and_push(&account, vec![account::create_space(&id, &name)])?;
    d.bump();
    Ok(json!({"space": hex::encode(id), "name": name}))
}
