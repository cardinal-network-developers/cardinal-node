//! Delivery tokens and the mailbox (`hosts.md#mailbox`).
//!
//! A host holds small sealed envelopes until its owner's devices collect them.
//! A token is the only thing that lets anyone but the owner leave one, and
//! each has a limit: a mailbox that is full refuses, and never absorbs. The
//! host reads nothing here. It learns how many envelopes arrive under each
//! token, and when.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cardinal_crypto::aead::{xchacha20poly1305_decrypt, xchacha20poly1305_encrypt_random};
use cardinal_crypto::{derive, random_bytes, Purpose};
use cardinal_encoding::{Record, Value};
use cardinal_identity::{EntryId, KeyId};
use cardinal_link::{Admission, CarrierKind, Role, SecretEntry, Service, Session, Stream, Target};
use cardinal_space::relationship::{self, Reach};
use cardinal_space::{EpochId, SpaceId};
use cardinal_sync::Message;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::daemon::{Daemon, PeerKind};
use crate::net::{self, from_value, to_value, Access};
use crate::paths::write_private;
use crate::rendezvous::call;

/// A delivery token.
pub type Token = [u8; 16];

/// The longest envelope, encoded.
pub const MAX_ENVELOPE: usize = 1024;
/// Envelopes in one reply to `fetch`.
const FETCH_PAGE: usize = 64;
/// The longest message here: a page of envelopes.
const MAX_MESSAGE: usize = 128 * 1024;
/// Quota class 0, the only one: envelopes waiting under one token.
const OUTSTANDING: usize = 256;
/// Quota class 0: deposits a day under one token.
const PER_DAY: u32 = 1024;
/// How long an envelope waits for its owner, in seconds.
const RETENTION: u64 = 30 * 24 * 60 * 60;
const DAY: u64 = 24 * 60 * 60;
/// How often to look for something to deliver or collect, if nothing says so
/// sooner.
const LOOK_EVERY: Duration = Duration::from_secs(30);
/// The least time between looks.
const LOOK_GAP: Duration = Duration::from_millis(500);
/// How often a person with no host looks at their contacts' hosts: nobody
/// can tell them when there is something to fetch.
const PULL_EVERY: Duration = Duration::from_secs(5 * 60);
/// An envelope (`hosts.md#envelopes`).
const ENVELOPE: u64 = 11;
/// An envelope payload.
const PAYLOAD: u64 = 7;

const OP_ERROR: u64 = 0;
pub(crate) const OP_DEPOSIT: u64 = 1;
pub(crate) const OP_FETCH: u64 = 2;
pub(crate) const OP_ACK: u64 = 3;
pub(crate) const OP_REGISTER: u64 = 4;
pub(crate) const OP_REVOKE: u64 = 5;
const OP_USAGE: u64 = 6;
const NOT_PERMITTED: u64 = 1;
const FULL: u64 = 2;
const UNKNOWN: u64 = 3;
const MALFORMED: u64 = 4;

/// An envelope a host holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Held {
    /// Its place among everything this host has held for its owner.
    pub sequence: u64,
    /// The token it came under.
    pub token: Token,
    /// When it arrived, in seconds.
    at: u64,
    /// The envelope.
    pub envelope: Vec<u8>,
}

/// Why a deposit was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The token is not active here.
    NotPermitted,
    /// The token has reached its limit.
    Full,
    /// That is not an envelope.
    Malformed,
}

/// How far an owner device has got.
#[derive(Clone, Copy, Default, Serialize, Deserialize)]
struct Fetcher {
    /// When it last fetched, in seconds.
    at: u64,
    /// The last sequence it acknowledged.
    acked: u64,
}

/// What is kept besides the envelopes.
#[derive(Default, Serialize, Deserialize)]
struct Saved {
    /// Active tokens.
    active: BTreeSet<String>,
    /// Revoked tokens, which can never be active again.
    revoked: BTreeSet<String>,
    /// The last sequence given out.
    last: u64,
    /// The day `deposits` counts.
    day: u64,
    /// Deposits that day, by token.
    deposits: BTreeMap<String, u32>,
    /// Owner devices that have fetched.
    fetchers: BTreeMap<String, Fetcher>,
}

/// Tokens and envelopes on disk. Each envelope is a file of its own, because
/// they come and go one at a time.
pub struct Store {
    dir: PathBuf,
    saved: Saved,
    held: BTreeMap<u64, Held>,
}

impl Store {
    /// Opens what is in `dir`.
    pub fn load(dir: PathBuf) -> Store {
        let saved = std::fs::read(dir.join("state.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let mut held = BTreeMap::new();
        for file in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let sequence = file.file_name().to_str().and_then(|n| n.parse().ok());
            let bytes = std::fs::read(file.path()).ok();
            if let (Some(sequence), Some(bytes)) = (sequence, bytes) {
                if let Some(h) = Held::read(sequence, &bytes) {
                    held.insert(sequence, h);
                }
            }
        }
        Store { dir, saved, held }
    }

    fn save(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let bytes = serde_json::to_vec(&self.saved).unwrap_or_default();
        write_private(&self.dir.join("state.json"), &bytes, 0o600)
    }

    /// Makes a token active, unless it was revoked, which is final. Returns
    /// whether it is newly active.
    pub fn register(&mut self, token: &Token) -> bool {
        let t = hex::encode(token);
        if self.saved.revoked.contains(&t) || !self.saved.active.insert(t) {
            return false;
        }
        let _ = self.save();
        true
    }

    /// Revokes a token for good. What was left under it stays until
    /// collected.
    pub fn revoke(&mut self, token: &Token) {
        let t = hex::encode(token);
        self.saved.active.remove(&t);
        self.saved.revoked.insert(t);
        let _ = self.save();
    }

    /// Active tokens.
    pub fn active(&self) -> Vec<Token> {
        let decode = |t: &String| hex::decode(t).ok()?.try_into().ok();
        self.saved.active.iter().filter_map(decode).collect()
    }

    /// Whether a token is active.
    pub fn is_active(&self, token: &Token) -> bool {
        self.saved.active.contains(&hex::encode(token))
    }

    fn waiting_under(&self, token: &Token) -> usize {
        self.held.values().filter(|h| h.token == *token).count()
    }

    /// Leaves an envelope, and gives its sequence.
    pub fn deposit(&mut self, token: &Token, envelope: &[u8], now: u64) -> Result<u64, Refused> {
        if envelope.is_empty() || envelope.len() > MAX_ENVELOPE {
            return Err(Refused::Malformed);
        }
        if !self.is_active(token) {
            return Err(Refused::NotPermitted);
        }
        self.sweep(now);
        if now / DAY != self.saved.day {
            self.saved.day = now / DAY;
            self.saved.deposits.clear();
        }
        let t = hex::encode(token);
        let today = self.saved.deposits.get(&t).copied().unwrap_or(0);
        if today >= PER_DAY || self.waiting_under(token) >= OUTSTANDING {
            return Err(Refused::Full);
        }
        let held = Held {
            sequence: self.saved.last + 1,
            token: *token,
            at: now,
            envelope: envelope.to_vec(),
        };
        // Nothing is promised until it is on disk.
        let kept = std::fs::create_dir_all(&self.dir).and_then(|()| {
            write_private(
                &self.dir.join(held.sequence.to_string()),
                &held.bytes(),
                0o600,
            )
        });
        kept.map_err(|_| Refused::Full)?;
        self.saved.last = held.sequence;
        self.saved.deposits.insert(t, today + 1);
        self.held.insert(held.sequence, held);
        let _ = self.save();
        Ok(self.saved.last)
    }

    /// Envelopes after `after`, a page of them, and whether there are more.
    pub fn fetch(&mut self, device: &KeyId, after: u64, now: u64) -> (Vec<Held>, bool) {
        let fetcher = self.saved.fetchers.entry(hex::encode(device)).or_default();
        fetcher.at = now;
        let _ = self.save();
        let mut next = self.held.range(after + 1..).map(|(_, h)| h.clone());
        let page: Vec<Held> = next.by_ref().take(FETCH_PAGE).collect();
        (page, next.next().is_some())
    }

    /// A device has everything up to `sequence`.
    pub fn ack(&mut self, device: &KeyId, sequence: u64, now: u64) {
        let fetcher = self.saved.fetchers.entry(hex::encode(device)).or_default();
        fetcher.at = now;
        fetcher.acked = fetcher.acked.max(sequence.min(self.saved.last));
        self.sweep(now);
        let _ = self.save();
    }

    /// Envelopes and bytes waiting, and deposits today, by token.
    fn usage(&self) -> Vec<(Token, usize, u32)> {
        self.active()
            .into_iter()
            .map(|t| {
                let today = self.saved.deposits.get(&hex::encode(t));
                (t, self.waiting_under(&t), today.copied().unwrap_or(0))
            })
            .collect()
    }

    /// Lets go of what every recent device has collected, and of what has
    /// waited too long. A device gone longer than that holds nothing up.
    fn sweep(&mut self, now: u64) {
        let recent = |at: u64| now.saturating_sub(at) < RETENTION;
        self.saved.fetchers.retain(|_, f| recent(f.at));
        let collected = self.saved.fetchers.values().map(|f| f.acked).min();
        let gone: Vec<u64> = self
            .held
            .values()
            .filter(|h| !recent(h.at) || collected.is_some_and(|c| h.sequence <= c))
            .map(|h| h.sequence)
            .collect();
        for sequence in gone {
            self.held.remove(&sequence);
            let _ = std::fs::remove_file(self.dir.join(sequence.to_string()));
        }
    }
}

impl Held {
    fn bytes(&self) -> Vec<u8> {
        let mut b = self.token.to_vec();
        b.extend_from_slice(&self.at.to_le_bytes());
        b.extend_from_slice(&self.envelope);
        b
    }

    fn read(sequence: u64, b: &[u8]) -> Option<Held> {
        let (token, rest) = b.split_first_chunk::<16>()?;
        let (at, envelope) = rest.split_first_chunk::<8>()?;
        Some(Held {
            sequence,
            token: *token,
            at: u64::from_le_bytes(*at),
            envelope: envelope.to_vec(),
        })
    }
}

/// A device's mailbox, if it is a host, and who holds a token here.
pub struct Mailbox {
    store: Mutex<Store>,
    /// Tokens, by the id of their secret at the endpoint.
    secrets: Mutex<HashMap<u64, Token>>,
    /// Which of this device's entries each member has been sent, by space
    /// and member, so that nothing is lost to being offline or restarting.
    sent: Mutex<BTreeMap<String, BTreeSet<String>>>,
    sent_path: PathBuf,
}

fn sent_key(space: &SpaceId, member: &[u8; 32]) -> String {
    format!("{}:{}", hex::encode(space), hex::encode(member))
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn now() -> u64 {
    let since = SystemTime::now().duration_since(UNIX_EPOCH);
    since.map_or(0, |t| t.as_secs())
}

impl Mailbox {
    /// Opens the mailbox in `dir`.
    pub fn load(dir: PathBuf) -> Mailbox {
        let sent_path = dir.join("sent.json");
        let sent = std::fs::read(&sent_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Mailbox {
            store: Mutex::new(Store::load(dir)),
            secrets: Mutex::new(HashMap::new()),
            sent: Mutex::new(sent),
            sent_path,
        }
    }

    /// Notes that a member has these entries of a space.
    fn mark_sent(&self, space: &SpaceId, member: &[u8; 32], ids: &[EntryId]) {
        let mut sent = lock(&self.sent);
        let got = sent.entry(sent_key(space, member)).or_default();
        let before = got.len();
        got.extend(ids.iter().map(hex::encode));
        if got.len() != before {
            let bytes = serde_json::to_vec(&*sent).unwrap_or_default();
            let saved = self.sent_path.parent().map(std::fs::create_dir_all);
            if !matches!(saved, Some(Ok(())))
                || write_private(&self.sent_path, &bytes, 0o600).is_err()
            {
                tracing::warn!("cannot save what was delivered");
            }
        }
    }

    /// Those of `ids` a member has not been sent.
    fn unsent(
        &self,
        space: &SpaceId,
        member: &[u8; 32],
        ids: Vec<(EntryId, Vec<u8>)>,
    ) -> Vec<(EntryId, Vec<u8>)> {
        let sent = lock(&self.sent);
        let got = sent.get(&sent_key(space, member));
        ids.into_iter()
            .filter(|(id, _)| !got.is_some_and(|g| g.contains(&hex::encode(id))))
            .collect()
    }

    /// The token a session was opened with, if it was.
    pub fn token_of(&self, s: &Session) -> Option<Token> {
        match s.admission() {
            Admission::Secret { id, .. } if s.role() == Role::Responder => {
                lock(&self.secrets).get(&id).copied()
            }
            _ => None,
        }
    }
}

/// Lets a token's holder open a session with this host (`link.md#handshake`).
fn admit(d: &Daemon, token: &Token) {
    let mut entry = SecretEntry::new(&derive(Purpose::Token, token)[..]);
    entry.uses = None;
    let id = d.endpoint.add_secret(entry);
    lock(&d.mailbox.secrets).insert(id, *token);
}

/// Stops admitting a token.
fn dismiss(d: &Daemon, token: &Token) {
    let mut secrets = lock(&d.mailbox.secrets);
    let ids: Vec<u64> = secrets
        .iter()
        .filter(|(_, t)| *t == token)
        .map(|(id, _)| *id)
        .collect();
    for id in ids {
        secrets.remove(&id);
        d.endpoint.remove_secret(id);
    }
}

/// Admits the holders of every token, on a device that is a host.
pub fn open(d: &Daemon) {
    let active = lock(&d.mailbox.store).active();
    for token in &active {
        admit(d, token);
    }
}

/// Stops admitting anyone, on a device that no longer is a host.
pub fn close(d: &Daemon) {
    let active = lock(&d.mailbox.store).active();
    for token in &active {
        dismiss(d, token);
    }
}

/// Makes a token active here.
pub fn register(d: &Daemon, token: &Token) {
    if lock(&d.mailbox.store).register(token) {
        admit(d, token);
    }
}

/// Revokes a token here.
pub fn revoke(d: &Daemon, token: &Token) {
    lock(&d.mailbox.store).revoke(token);
    dismiss(d, token);
}

fn error(code: u64) -> Record {
    Record::new().with(0, OP_ERROR).with(1, code)
}

fn read_token(v: Option<&Value>) -> Option<Token> {
    v?.as_bytes()?.try_into().ok()
}

/// Serves the `mailbox` service. Leaving an envelope takes a token, and all
/// else takes being the owner.
pub async fn serve(d: &Arc<Daemon>, s: &Session, mut st: Stream) -> anyhow::Result<()> {
    let Some(v) = st.recv_message_max(MAX_MESSAGE).await? else {
        return Ok(());
    };
    let Some(r) = v.as_record() else {
        return Ok(());
    };
    let reply = answer(d, s, r);
    st.send_message(&Value::Record(reply)).await?;
    st.shutdown().await?;
    Ok(())
}

fn answer(d: &Daemon, s: &Session, r: &Record) -> Record {
    if !d.config().host {
        return error(NOT_PERMITTED);
    }
    let op = r.get(0).and_then(Value::as_uint);
    if op == Some(OP_DEPOSIT) {
        return deposit(d, r);
    }
    let PeerKind::Own(device) = d.classify(s) else {
        return error(NOT_PERMITTED);
    };
    match op {
        Some(OP_FETCH) => {
            let after = r.get(1).and_then(Value::as_uint).unwrap_or(0);
            let (page, more) = lock(&d.mailbox.store).fetch(&device, after, now());
            let list = page.iter().map(|h| {
                let held = Record::new().with(1, h.sequence).with(2, h.token);
                Value::Record(held.with(3, h.envelope.clone()))
            });
            Record::new()
                .with(0, OP_FETCH)
                .with(1, Value::list(list))
                .with(2, more)
        }
        Some(OP_ACK) => {
            let Some(sequence) = r.get(1).and_then(Value::as_uint) else {
                return error(MALFORMED);
            };
            lock(&d.mailbox.store).ack(&device, sequence, now());
            Record::new().with(0, OP_ACK)
        }
        Some(OP_REGISTER) => {
            let Ok(list) = r.record_list(1) else {
                return error(MALFORMED);
            };
            for token in list.iter().filter_map(|t| read_token(t.get(1))) {
                register(d, &token);
            }
            Record::new().with(0, OP_REGISTER)
        }
        Some(OP_REVOKE) => {
            let Ok(list) = r.list(1) else {
                return error(MALFORMED);
            };
            for token in list.iter().filter_map(|t| read_token(Some(t))) {
                revoke(d, &token);
            }
            Record::new().with(0, OP_REVOKE)
        }
        Some(OP_USAGE) => {
            let usage = lock(&d.mailbox.store).usage();
            let list = usage.iter().map(|(token, held, today)| {
                let line = Record::new().with(1, *token).with(2, *held);
                Value::Record(line.with(3, u64::from(*today)))
            });
            Record::new().with(0, OP_USAGE).with(1, Value::list(list))
        }
        _ => error(UNKNOWN),
    }
}

fn deposit(d: &Daemon, r: &Record) -> Record {
    let token = read_token(r.get(1));
    let envelope = r.get(2).and_then(Value::as_bytes);
    let (Some(token), Some(envelope)) = (token, envelope) else {
        return error(MALFORMED);
    };
    let left = lock(&d.mailbox.store).deposit(&token, envelope, now());
    match left {
        Ok(_) => {
            d.bump();
            Record::new().with(0, OP_DEPOSIT)
        }
        Err(Refused::NotPermitted) => error(NOT_PERMITTED),
        Err(Refused::Full) => error(FULL),
        Err(Refused::Malformed) => error(MALFORMED),
    }
}

/// Seals one entry of a space, or a heads message, into an envelope.
fn seal(epoch: &EpochId, key: &[u8; 32], notice: impl Into<Value>) -> Vec<u8> {
    let payload = Record::new().with(0, PAYLOAD).with(1, notice).encode();
    let (nonce, ciphertext) = xchacha20poly1305_encrypt_random(key, &[], &payload);
    Record::new()
        .with(0, ENVELOPE)
        .with(1, *epoch)
        .with(2, nonce)
        .with(3, ciphertext)
        .encode()
}

/// Which epoch an envelope is sealed under.
fn epoch_of(envelope: &[u8]) -> Option<EpochId> {
    let r = Record::decode(envelope).ok()?;
    r.get(1)?.as_bytes()?.try_into().ok()
}

/// What an envelope holds.
#[derive(Debug, PartialEq, Eq)]
enum Notice {
    /// An entry of the space.
    Entry(Vec<u8>),
    /// A heads message: what is new, to fetch from a host.
    Heads(Vec<[u8; 32]>),
}

/// Opens an envelope.
fn open_envelope(envelope: &[u8], key: &[u8; 32]) -> Option<Notice> {
    let r = Record::decode(envelope).ok()?;
    if r.get(0)?.as_uint()? != ENVELOPE {
        return None;
    }
    let nonce: [u8; 24] = r.get(2)?.as_bytes()?.try_into().ok()?;
    let plain = xchacha20poly1305_decrypt(key, &nonce, &[], r.get(3)?.as_bytes()?).ok()?;
    let payload = Record::decode(&plain).ok()?;
    if payload.get(0)?.as_uint()? != PAYLOAD {
        return None;
    }
    let notice = payload.get(1)?;
    if let Some(entry) = notice.as_bytes() {
        return Some(Notice::Entry(entry.to_vec()));
    }
    match from_value(notice.clone()).ok()? {
        Message::Heads { ids, .. } => Some(Notice::Heads(ids)),
        _ => None,
    }
}

/// Gets a token from each of this person's hosts it can reach.
async fn reach_here(d: &Arc<Daemon>) -> Vec<Reach> {
    let me = d.keys.key();
    let hosts = d.core().mailboxes();
    let mut reach = Vec::new();
    for (grant, device) in hosts {
        let token: Token = random_bytes();
        if device == me {
            register(d, &token);
        } else {
            let host = *grant.link_key.x25519();
            let at_host = |s: &Session| s.peer_static() == host;
            let Some(s) = d.own_sessions().into_iter().find(at_host) else {
                continue;
            };
            let one = Value::Record(Record::new().with(1, token).with(2, 0u64));
            let ask = Record::new()
                .with(0, OP_REGISTER)
                .with(1, Value::list([one]));
            if let Err(e) = call(&s, Service::MAILBOX, ask).await {
                tracing::debug!("registering a token: {e:#}");
                continue;
            }
        }
        reach.push(Reach {
            endpoints: grant.endpoints,
            host: *grant.link_key.x25519(),
            token,
        });
    }
    reach
}

/// Writes where this person can be reached about a space, if they have a
/// host and have not said yet.
pub async fn write_reach(d: &Arc<Daemon>, space: &SpaceId) -> anyhow::Result<()> {
    let me = d.core().identity.as_ref().map(|i| i.id());
    let Some(me) = me else {
        return Ok(());
    };
    if d.core().reach_of(space, &me).is_some() {
        return Ok(());
    }
    let reach = reach_here(d).await;
    if !reach.is_empty() {
        d.write_and_push(space, vec![relationship::create_reach(&me, &reach)])?;
    }
    Ok(())
}

/// Ends what this person's tokens in a space allow, for someone refused.
pub async fn withdraw_reach(d: &Arc<Daemon>, space: &SpaceId) -> anyhow::Result<()> {
    let me = d.core().identity.as_ref().map(|i| i.id());
    let found = me.and_then(|me| d.core().reach_of(space, &me));
    let Some((_, reach)) = found else {
        return Ok(());
    };
    for r in &reach {
        if r.host == *d.keys.link.public_key().x25519() {
            revoke(d, &r.token);
            continue;
        }
        let at_host = |s: &Session| s.peer_static() == r.host;
        if let Some(s) = d.own_sessions().into_iter().find(at_host) {
            let ask = Record::new()
                .with(0, OP_REVOKE)
                .with(1, Value::list([Value::from(r.token)]));
            call(&s, Service::MAILBOX, ask).await?;
        }
    }
    Ok(())
}

/// Gives a space fresh tokens, in place of any revoked.
pub async fn renew_reach(d: &Arc<Daemon>, space: &SpaceId) -> anyhow::Result<()> {
    let me = d.core().identity.as_ref().map(|i| i.id());
    let found = me.and_then(|me| d.core().reach_of(space, &me));
    let Some((node, _)) = found else {
        return write_reach(d, space).await;
    };
    let reach = reach_here(d).await;
    d.write_and_push(space, vec![relationship::set_reach(node, &reach)])?;
    Ok(())
}

/// Two people have just reconciled a space: what this device wrote in it so
/// far needs no delivering.
pub fn met(d: &Daemon, space: &SpaceId, member: &[u8; 32]) {
    let ids: Vec<EntryId> = d
        .core()
        .entries_by(space, &d.keys.key())
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    d.mailbox.mark_sent(space, member, &ids);
}

/// Opens a session with a host of someone else's, with their token. It says
/// nothing of who is asking, and is good for one space.
async fn at_host(d: &Daemon, r: &Reach, addr: SocketAddr) -> Option<Session> {
    let secret = derive(Purpose::Token, &r.token);
    let target = |c: CarrierKind| Target::invitation(addr, c, r.host, &secret[..]).anonymous();
    d.dial(target).await.ok()
}

/// Fetches a space from a member's host.
async fn pull(d: &Arc<Daemon>, space: &SpaceId, reach: &[Reach]) -> bool {
    for r in reach {
        for addr in r.endpoints.iter().filter_map(|e| e.socket_addr()) {
            let Some(s) = at_host(d, r, addr).await else {
                continue;
            };
            let done = net::reconcile(d, &s, *space).await;
            s.close("fetched");
            match done {
                Ok(()) => return true,
                Err(e) => tracing::debug!("fetching from a host: {e:#}"),
            }
        }
    }
    false
}

/// Fetches a space from the hosts of the members with no session here.
async fn pull_from_members(d: &Arc<Daemon>, space: &SpaceId, members: &[[u8; 32]]) {
    let in_touch = d.people_in_touch();
    for member in members.iter().filter(|m| !in_touch.contains(*m)) {
        let found = d.core().reach_of(space, member);
        if let Some((_, reach)) = found {
            pull(d, space, &reach).await;
        }
    }
}

/// Looks for anything new, for a person whom nobody can tell.
async fn pull_all(d: &Arc<Daemon>) {
    if !d.core().mailboxes().is_empty() {
        return;
    }
    let shared = d.core().shared_spaces();
    for (space, members) in shared {
        pull_from_members(d, &space, &members).await;
    }
}

/// Takes `envelopes` to the first host in `reach` that will have them, and
/// says which were left.
async fn leave(d: &Arc<Daemon>, reach: &[Reach], envelopes: &[(EntryId, Vec<u8>)]) -> Vec<EntryId> {
    for r in reach {
        for addr in r.endpoints.iter().filter_map(|e| e.socket_addr()) {
            let Some(s) = at_host(d, r, addr).await else {
                continue;
            };
            let mut left = Vec::new();
            for (id, envelope) in envelopes {
                let ask = Record::new()
                    .with(0, OP_DEPOSIT)
                    .with(1, r.token)
                    .with(2, envelope.clone());
                match call(&s, Service::MAILBOX, ask).await {
                    Ok(reply) if reply.get(0).and_then(Value::as_uint) == Some(OP_DEPOSIT) => {
                        left.push(*id);
                    }
                    other => {
                        tracing::debug!("a host took no envelope: {other:?}");
                        break;
                    }
                }
            }
            s.close("delivered");
            if !left.is_empty() {
                return left;
            }
        }
    }
    Vec::new()
}

/// Delivers what this device wrote to each member it has no session with.
async fn deliver(d: &Arc<Daemon>) {
    let shared = d.core().shared_spaces();
    if shared.is_empty() {
        return;
    }
    let me = d.keys.key();
    let connected = d.connected_people();
    let in_touch = d.people_in_touch();
    for (space, members) in shared {
        if let Err(e) = write_reach(d, &space).await {
            tracing::debug!("writing where to reach this person: {e:#}");
        }
        for member in members {
            let mine = d.core().entries_by(&space, &me);
            if connected.contains(&member) {
                let ids: Vec<EntryId> = mine.iter().map(|(id, _)| *id).collect();
                d.mailbox.mark_sent(&space, &member, &ids);
                continue;
            }
            if in_touch.contains(&member) {
                continue;
            }
            let unsent = d.mailbox.unsent(&space, &member, mine);
            if unsent.is_empty() {
                continue;
            }
            let found = d.core().reach_of(&space, &member);
            let Some((_, reach)) = found else {
                continue;
            };
            let Some((epoch, key)) = d.core().envelope_key(&space) else {
                continue;
            };
            let (fits, long): (Vec<_>, Vec<_>) = unsent
                .iter()
                .map(|(id, entry)| (*id, seal(&epoch, &key, &entry[..])))
                .partition(|(_, envelope)| envelope.len() <= MAX_ENVELOPE);
            let left = leave(d, &reach, &fits).await;
            d.mailbox.mark_sent(&space, &member, &left);
            // Too long to carry, so say that it is there, if this person has
            // a host to fetch it from.
            let hosted = d.core().identity.as_ref().map(|i| i.id());
            let hosted = hosted.is_some_and(|me| d.core().reach_of(&space, &me).is_some());
            if long.is_empty() || !hosted {
                continue;
            }
            let ids: Vec<EntryId> = long.iter().map(|(id, _)| *id).collect();
            let heads = Message::Heads {
                label: space,
                ids: ids.clone(),
            };
            let notice = (ids[0], seal(&epoch, &key, to_value(&heads)));
            if !leave(d, &reach, &[notice]).await.is_empty() {
                d.mailbox.mark_sent(&space, &member, &ids);
            }
        }
    }
}

/// Collects this host's own mailbox. The host is one of the owner's devices,
/// and everything it takes in reaches the others by the usual sync, so they
/// need not poll it.
async fn collect(d: &Arc<Daemon>) {
    if !d.config().host {
        return;
    }
    let me = d.keys.key();
    let mut after = 0;
    loop {
        let (page, more) = lock(&d.mailbox.store).fetch(&me, after, now());
        let Some(last) = page.last().map(|h| h.sequence) else {
            return;
        };
        for held in &page {
            take_in(d, held).await;
        }
        lock(&d.mailbox.store).ack(&me, last, now());
        after = last;
        if !more {
            return;
        }
    }
}

/// Opens an envelope and takes in what it holds. One that cannot be opened is
/// dropped: its sender gets nothing from holding the queue up.
async fn take_in(d: &Arc<Daemon>, held: &Held) {
    let opened = (|| {
        let core = d.core();
        let space = core.space_of_token(&held.token)?;
        let key = core.envelope_key_of(&space, &epoch_of(&held.envelope)?)?;
        Some((space, open_envelope(&held.envelope, &key)?))
    })();
    let Some((space, notice)) = opened else {
        tracing::debug!("dropping envelope {}: it does not open", held.sequence);
        return;
    };
    let entry = match notice {
        Notice::Entry(entry) => entry,
        Notice::Heads(ids) => {
            let missing = ids.iter().any(|id| !d.core().has(&space, id));
            let shared = d.core().shared_spaces();
            let members = shared.into_iter().find(|(id, _)| *id == space);
            if let (true, Some((_, members))) = (missing, members) {
                pull_from_members(d, &space, &members).await;
            }
            return;
        }
    };
    let d2 = d.clone();
    let taken = tokio::task::spawn_blocking(move || d2.ingest(space, vec![entry], Access::Full));
    match taken.await {
        Ok(Ok(outcome)) => {
            let me = *d.keys.link.public_key().x25519();
            d.pass_on(space, outcome.complete, outcome.objects, me);
        }
        Ok(Err(e)) => tracing::debug!("envelope {}: {e:#}", held.sequence),
        Err(e) => tracing::debug!("envelope {}: {e}", held.sequence),
    }
}

fn pull_every() -> Duration {
    std::env::var("CARDINAL_TEST_PULL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map_or(PULL_EVERY, Duration::from_secs)
}

/// Keeps delivering and collecting, whenever there may be something to do.
pub fn start(d: Arc<Daemon>) {
    tokio::spawn(async move {
        let mut changed = d.changed.subscribe();
        let mut every = tokio::time::interval(LOOK_EVERY.min(pull_every()));
        let mut pulled: Option<Instant> = None;
        loop {
            tokio::select! {
                _ = every.tick() => {}
                _ = changed.changed() => {}
            }
            deliver(&d).await;
            collect(&d).await;
            if pulled.is_none_or(|t| t.elapsed() >= pull_every()) {
                pulled = Some(Instant::now());
                pull_all(&d).await;
            }
            tokio::time::sleep(LOOK_GAP).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use cardinal_space::grant::Endpoint;

    const T: Token = [1; 16];
    const OTHER: Token = [2; 16];
    const PHONE: KeyId = [3; 32];
    const LAPTOP: KeyId = [4; 32];

    #[test]
    fn a_heads_message_fits_in_an_envelope_and_comes_out_whole() {
        let ids = vec![[1; 32], [2; 32]];
        let heads = Message::Heads {
            label: [3; 32],
            ids: ids.clone(),
        };
        let envelope = seal(&[7; 16], &[8; 32], to_value(&heads));
        assert!(envelope.len() <= MAX_ENVELOPE);
        assert_eq!(open_envelope(&envelope, &[8; 32]), Some(Notice::Heads(ids)));
    }

    #[test]
    fn a_reach_node_fits_in_an_envelope() {
        let reach = Reach {
            endpoints: vec![Endpoint::parse("203.0.113.9:7171").unwrap(); 2],
            host: [1; 32],
            token: [2; 16],
        };
        let op = relationship::create_reach(&[3; 32], &[reach.clone(), reach]);
        let body = op.record().encode();
        assert!(body.len() < MAX_ENVELOPE / 2, "{} bytes", body.len());
    }

    #[test]
    fn an_envelope_opens_only_with_its_key() {
        let (epoch, key) = ([7; 16], [8; 32]);
        let envelope = seal(&epoch, &key, &b"an entry"[..]);
        assert_eq!(epoch_of(&envelope), Some(epoch));
        let opened = open_envelope(&envelope, &key).unwrap();
        assert_eq!(opened, Notice::Entry(b"an entry".to_vec()));
        assert_eq!(open_envelope(&envelope, &[9; 32]), None);
        assert_eq!(open_envelope(b"not an envelope", &key), None);
    }

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::load(dir.path().join("mailbox"));
        s.register(&T);
        (dir, s)
    }

    #[test]
    fn a_deposit_needs_an_active_token() {
        let (_dir, mut s) = store();
        assert_eq!(s.deposit(&OTHER, b"x", 1), Err(Refused::NotPermitted));
        assert_eq!(s.deposit(&T, b"x", 1), Ok(1));
        assert_eq!(s.deposit(&T, b"y", 1), Ok(2));
    }

    #[test]
    fn a_revoked_token_never_comes_back() {
        let (_dir, mut s) = store();
        s.revoke(&T);
        assert!(!s.register(&T), "stale views cannot undo a revocation");
        assert_eq!(s.deposit(&T, b"x", 1), Err(Refused::NotPermitted));
    }

    #[test]
    fn an_envelope_has_a_size() {
        let (_dir, mut s) = store();
        assert_eq!(s.deposit(&T, b"", 1), Err(Refused::Malformed));
        let long = vec![0; MAX_ENVELOPE + 1];
        assert_eq!(s.deposit(&T, &long, 1), Err(Refused::Malformed));
        assert!(s.deposit(&T, &long[1..], 1).is_ok());
    }

    #[test]
    fn a_full_mailbox_refuses_one_token_and_not_the_next() {
        let (_dir, mut s) = store();
        s.register(&OTHER);
        for _ in 0..OUTSTANDING {
            s.deposit(&T, b"x", 1).unwrap();
        }
        assert_eq!(s.deposit(&T, b"x", 1), Err(Refused::Full));
        assert!(s.deposit(&OTHER, b"x", 1).is_ok());
    }

    #[test]
    fn a_day_has_a_limit_even_if_everything_is_collected() {
        let (_dir, mut s) = store();
        s.fetch(&PHONE, 0, 1);
        for _ in 0..PER_DAY {
            let sequence = s.deposit(&T, b"x", 1).unwrap();
            s.ack(&PHONE, sequence, 1);
        }
        assert_eq!(s.deposit(&T, b"x", 1), Err(Refused::Full));
        assert!(s.deposit(&T, b"x", 1 + DAY).is_ok());
    }

    #[test]
    fn it_all_survives_a_restart() {
        let (dir, mut s) = store();
        s.deposit(&T, b"kept", 1).unwrap();
        let mut again = Store::load(dir.path().join("mailbox"));
        assert!(again.is_active(&T));
        let (page, _) = again.fetch(&PHONE, 0, 2);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].envelope, b"kept");
        assert_eq!(page[0].token, T);
        assert_eq!(again.deposit(&T, b"next", 2), Ok(2));
    }

    #[test]
    fn sequences_never_repeat_after_everything_is_collected() {
        let (dir, mut s) = store();
        s.fetch(&PHONE, 0, 1);
        let sequence = s.deposit(&T, b"x", 1).unwrap();
        s.ack(&PHONE, sequence, 1);
        assert!(s.held.is_empty());
        let mut again = Store::load(dir.path().join("mailbox"));
        assert_eq!(again.deposit(&T, b"y", 2), Ok(2));
    }

    #[test]
    fn an_envelope_waits_for_every_recent_device() {
        let (_dir, mut s) = store();
        s.fetch(&PHONE, 0, 1);
        s.fetch(&LAPTOP, 0, 1);
        let sequence = s.deposit(&T, b"x", 1).unwrap();
        s.ack(&PHONE, sequence, 2);
        assert_eq!(s.fetch(&LAPTOP, 0, 3).0.len(), 1);
        s.ack(&LAPTOP, sequence, 4);
        assert!(s.fetch(&PHONE, 0, 5).0.is_empty());
    }

    #[test]
    fn a_device_long_gone_holds_nothing_up() {
        let (_dir, mut s) = store();
        s.fetch(&LAPTOP, 0, 1);
        let later = 1 + RETENTION;
        s.fetch(&PHONE, 0, later);
        let sequence = s.deposit(&T, b"x", later).unwrap();
        s.ack(&PHONE, sequence, later);
        assert!(s.held.is_empty());
    }

    #[test]
    fn an_envelope_nobody_collects_goes_in_the_end() {
        let (_dir, mut s) = store();
        s.deposit(&T, b"old", 1).unwrap();
        s.deposit(&T, b"new", 1 + RETENTION).unwrap();
        let (page, _) = s.fetch(&PHONE, 0, 1 + RETENTION);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].envelope, b"new");
    }

    #[test]
    fn a_device_cannot_acknowledge_what_has_not_arrived() {
        let (_dir, mut s) = store();
        s.fetch(&PHONE, 0, 1);
        s.ack(&PHONE, 1000, 1);
        s.deposit(&T, b"x", 1).unwrap();
        assert_eq!(s.fetch(&PHONE, 0, 2).0.len(), 1);
    }

    #[test]
    fn a_page_says_when_there_is_more() {
        let (_dir, mut s) = store();
        for _ in 0..FETCH_PAGE + 1 {
            s.deposit(&T, b"x", 1).unwrap();
        }
        let (page, more) = s.fetch(&PHONE, 0, 2);
        assert_eq!(page.len(), FETCH_PAGE);
        assert!(more);
        let last = page.last().unwrap().sequence;
        let (rest, more) = s.fetch(&PHONE, last, 2);
        assert_eq!(rest.len(), 1);
        assert!(!more);
    }
}
