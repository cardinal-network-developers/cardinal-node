//! Delivery tokens and the mailbox (`hosts.md#mailbox`).
//!
//! A host holds small sealed envelopes until its owner's devices collect them.
//! A token is the only thing that lets anyone but the owner leave one, and
//! each has a limit: a mailbox that is full refuses, and never absorbs. The
//! host reads nothing here. It learns how many envelopes arrive under each
//! token, and when.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cardinal_crypto::aead::{xchacha20poly1305_decrypt, xchacha20poly1305_encrypt_random};
use cardinal_crypto::{derive, random_bytes, Purpose};
use cardinal_encoding::{Record, Value};
use cardinal_identity::{EntryId, KeyId};
use cardinal_link::{Admission, CarrierKind, Role, SecretEntry, Service, Session, Stream, Target};
use cardinal_space::grant::Endpoint;
use cardinal_space::relationship::{self, Reach};
use cardinal_space::{EpochId, SpaceId};
use cardinal_sync::{identity_log_label, Message};
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
/// How long one exchange with a host may take.
const AT_HOST_WITHIN: Duration = Duration::from_secs(30);
/// Least time between fetches of a space for what an envelope needs.
const PULL_GAP: Duration = Duration::from_secs(60);
/// How many hosts of a reach node to try, and addresses of each: a contact
/// wrote it.
const MAX_REACH: usize = 4;
/// Envelopes left with a host at a time.
const LEAVE_AT_ONCE: usize = 32;
/// Ids in a `heads` message, which must fit an envelope.
const MAX_HEADS: usize = 16;
/// Sessions at a time with one token. A holder can make keys without limit.
pub const TOKEN_SESSIONS: usize = 4;
/// Streams at a time on a session opened with a token.
pub const TOKEN_STREAMS: usize = 8;
/// The longest sync message on a session opened with a token.
pub const TOKEN_MESSAGE: usize = 256 * 1024;
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

    /// Lets go of one envelope, on the host that took it in. One that cannot
    /// be opened yet must not hold up those behind it, so this is not `ack`.
    pub fn taken(&mut self, sequence: u64) {
        self.held.remove(&sequence);
        let _ = std::fs::remove_file(self.dir.join(sequence.to_string()));
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
    /// Hosts of others in use. The link keeps one session between two
    /// devices, so a second would end the first.
    going: Mutex<HashSet<[u8; 32]>>,
    /// When each space was last fetched for an envelope's sake.
    pulled: Mutex<HashMap<SpaceId, Instant>>,
    /// Held while this device writes where to reach its person.
    reaching: tokio::sync::Mutex<()>,
    /// The spaces where what this device set about on its own failed, as
    /// for a log that cannot be written, and when it tries again.
    put_off: Mutex<HashMap<SpaceId, PutOff>>,
    /// Tests: run once a token is registered and before the list is
    /// written, where an entry may arrive.
    #[cfg(test)]
    before_write: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

/// An attempt put off, and for how long the next one will be.
struct PutOff {
    until: Instant,
    wait: Duration,
}

/// How long a write of the list that failed waits before it is tried
/// again, at first and at most: each failure doubles it.
const PUT_OFF: (Duration, Duration) = (Duration::from_secs(60), Duration::from_secs(3600));

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
            going: Mutex::new(HashSet::new()),
            pulled: Mutex::new(HashMap::new()),
            reaching: tokio::sync::Mutex::new(()),
            put_off: Mutex::new(HashMap::new()),
            #[cfg(test)]
            before_write: Mutex::new(None),
        }
    }

    /// Notes that a member has these entries of a space.
    pub(crate) fn mark_sent(&self, space: &SpaceId, member: &[u8; 32], ids: &[EntryId]) {
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

    /// Those of `ids` a member has not been sent, by id.
    pub(crate) fn not_sent(
        &self,
        space: &SpaceId,
        member: &[u8; 32],
        ids: Vec<EntryId>,
    ) -> HashSet<EntryId> {
        let sent = lock(&self.sent);
        let got = sent.get(&sent_key(space, member));
        let was_sent = |id: &EntryId| got.is_some_and(|g| g.contains(&hex::encode(id)));
        ids.into_iter().filter(|id| !was_sent(id)).collect()
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

    /// Whether a token is active here.
    pub fn is_active(&self, token: &Token) -> bool {
        lock(&self.store).is_active(token)
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

/// Stops admitting a token, and ends what it opened.
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
    drop(secrets);
    d.end_token_sessions(token);
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

/// Which of this person's hosts a list is to gain.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Add {
    /// Every host of theirs it does not name: their act, or their joining.
    Every,
    /// This device alone, if it is one: what a device does on its own.
    Own,
}

/// Hosts to name, and which of their tokens were registered for it.
#[derive(Default)]
struct Given {
    /// Each host, with a token for the space.
    reach: Vec<Reach>,
    /// Those whose token was made and registered now: what is taken back
    /// if the list is not written after all.
    new: Vec<Reach>,
}

/// This person's hosts that `named` does not name, each with a token for
/// `space` registered at it, in the order the account gives them. A host
/// that cannot be reached from here now gives no token, and is left out.
/// This device, as a host, gives a token it gave for the space before if
/// one is still active, and a new one only if none is: every token given
/// serves until revoked, so a second would only be one more to keep.
async fn reach_here(d: &Arc<Daemon>, space: &SpaceId, named: &[Reach], add: Add) -> Given {
    let me = d.keys.key();
    let hosts = d.core().mailboxes();
    let mut given = Given::default();
    for (grant, device) in hosts {
        let host = *grant.link_key.x25519();
        if named.iter().any(|r| r.host == host) || (add == Add::Own && device != me) {
            continue;
        }
        let (token, new) = if device == me {
            own_token(d, space)
        } else {
            let token: Token = random_bytes();
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
            (token, true)
        };
        let reach = Reach {
            endpoints: grant.endpoints,
            host,
            token,
        };
        if new {
            given.new.push(reach.clone());
        }
        given.reach.push(reach);
    }
    #[cfg(test)]
    if let Some(arrives) = lock(&d.mailbox.before_write).take() {
        arrives();
    }
    given
}

/// A token of this host's for a space: one it gave there before that is
/// still active, or a new one, registered. Says whether it is new.
fn own_token(d: &Daemon, space: &SpaceId) -> (Token, bool) {
    let here = *d.keys.link.public_key().x25519();
    let given = d.core().tokens_given(space, &here);
    let store = lock(&d.mailbox.store);
    let active = given.into_iter().find(|t| store.is_active(t));
    drop(store);
    match active {
        Some(token) => (token, false),
        None => {
            let token: Token = random_bytes();
            register(d, &token);
            (token, true)
        }
    }
}

/// Takes back tokens registered for a list that was then not written
/// (R1, R5): each is revoked at its host, here or over the session it was
/// registered on. A host that cannot be reached now keeps a token nothing
/// names; nothing was told of it, so nobody holds it.
async fn take_back(d: &Arc<Daemon>, new: &[Reach]) {
    let here = *d.keys.link.public_key().x25519();
    for r in new {
        if r.host == here {
            revoke(d, &r.token);
            continue;
        }
        let at_host = |s: &Session| s.peer_static() == r.host;
        let Some(s) = d.own_sessions().into_iter().find(at_host) else {
            continue;
        };
        let ask = Record::new()
            .with(0, OP_REVOKE)
            .with(1, Value::list([Value::from(r.token)]));
        if let Err(e) = call(&s, Service::MAILBOX, ask).await {
            tracing::debug!("taking back a token: {e:#}");
        }
    }
}

/// What a write of the list that software makes on its own was decided
/// on: looked at again, under the core's lock, at the moment of writing.
/// While a token was being registered an entry may have arrived, and one
/// that set the list, an empty list above all, is later than the
/// decision (R1): a no must not be written over.
struct Decided {
    telling: crate::core::Telling,
    set_by: Vec<String>,
}

impl Decided {
    fn now(core: &crate::core::Core, space: &SpaceId) -> Decided {
        Decided {
            telling: core.telling(space),
            set_by: core.list_set_by(space),
        }
    }

    fn still(&self, core: &crate::core::Core, space: &SpaceId) -> bool {
        core.list_set_by(space) == self.set_by && core.telling(space) == self.telling
    }
}

/// Sets the list as software decided on its own, if nothing that the
/// decision rests on has changed since; and takes back the tokens
/// registered for it if it has, or if the write fails. A write that fails
/// is put off, longer each time, and not tried at every look (R5). Says
/// whether the list was written.
async fn set_as_decided(
    d: &Arc<Daemon>,
    space: &SpaceId,
    decided: &Decided,
    reach: &[Reach],
    new: &[Reach],
) -> anyhow::Result<bool> {
    let me = me(d)?;
    let set = relationship::set_reach(&me, reach);
    let written = d.write_and_push_if(space, vec![set], |core| decided.still(core, space));
    match written {
        Ok(Some(_)) => {
            lock(&d.mailbox.put_off).remove(space);
            Ok(true)
        }
        Ok(None) => {
            tracing::debug!("the list was set meanwhile: it is looked at again");
            take_back(d, new).await;
            Ok(false)
        }
        Err(e) => {
            take_back(d, new).await;
            put_off(d, space);
            Err(e)
        }
    }
}

/// Notes that what software set about on its own in a space failed.
fn put_off(d: &Daemon, space: &SpaceId) {
    let mut all = lock(&d.mailbox.put_off);
    let wait = match all.get(space) {
        Some(was) => (was.wait * 2).min(PUT_OFF.1),
        None => PUT_OFF.0,
    };
    let until = Instant::now() + wait;
    all.insert(*space, PutOff { until, wait });
}

/// Whether an attempt in a space is put off for now.
fn is_put_off(d: &Daemon, space: &SpaceId) -> bool {
    let all = lock(&d.mailbox.put_off);
    all.get(space).is_some_and(|p| Instant::now() < p.until)
}

fn me(d: &Daemon) -> anyhow::Result<[u8; 32]> {
    let me = d.core().identity.as_ref().map(|i| i.id());
    me.ok_or_else(|| anyhow::anyhow!("this device has no identity"))
}

/// Sets this person's reach node in a space now: to their hosts, each with
/// a fresh token for this space, or to an empty list if they have none or
/// `share` is false (`contact.md#accepting`, step 5; `profiles.md#group`).
/// This is how a relationship or a group is accepted. Naming a host is the
/// person's act, or their joining among contacts: the caller knows which
/// ([`write_reach`] has what software does on its own). Says whether the
/// list names a host afterwards.
pub async fn say_reach(d: &Arc<Daemon>, space: &SpaceId, share: bool) -> anyhow::Result<bool> {
    let _one = d.mailbox.reaching.lock().await;
    say_reach_locked(d, space, share).await
}

async fn say_reach_locked(d: &Arc<Daemon>, space: &SpaceId, share: bool) -> anyhow::Result<bool> {
    let me = me(d)?;
    let given = if share {
        reach_here(d, space, &[], Add::Every).await
    } else {
        Given::default()
    };
    let reach = given.reach;
    let set = relationship::set_reach(&me, &reach);
    if let Err(e) = d.write_and_push(space, vec![set]) {
        take_back(d, &given.new).await;
        return Err(e);
    }
    if reach.is_empty() {
        // what the node named before is in use no longer
        revoke_left(d, space);
    }
    Ok(!reach.is_empty())
}

/// What became of the person's saying that a space's members may have
/// where their hosts are.
pub enum Shared {
    /// The list names their hosts.
    Named,
    /// They have no host: there is nothing to share, and nothing was
    /// written or kept for later.
    NoHost,
    /// They have one, and it cannot be reached from this device now to
    /// give out a token: their yes is kept on this device, and finished
    /// when the host can be reached ([`write_reach`]).
    Waiting,
}

/// The person says, on this device, that a space's members may have where
/// their hosts are (`group-reach`). What the list names already stays, in
/// its order, and each host of theirs it does not name is added after,
/// with a fresh token. A list that needs no change is not written again:
/// a yes was to the space, whoever has been added to it since.
///
/// With no host there is nothing to share and nothing is written: an
/// answer is not kept for a host they may take up later. With a host that
/// cannot be reached now, to register a token, the yes is kept on this
/// device and finished later, unless the list is set meanwhile
/// (`hosts.md#telling-others-where-to-reach-you`).
pub async fn share_reach(d: &Arc<Daemon>, space: &SpaceId) -> anyhow::Result<Shared> {
    let _one = d.mailbox.reaching.lock().await;
    let me = me(d)?;
    let t = d.core().telling(space);
    if !t.hosted && !t.shared {
        return Ok(Shared::NoHost);
    }
    let mut reach = d.core().reach_of(space, &me);
    let given = reach_here(d, space, &reach, Add::Every).await;
    let more = given.reach;
    if reach.is_empty() && more.is_empty() {
        if !t.set {
            // their first entry there: the yes is kept against it
            d.write_and_push(space, vec![relationship::set_reach(&me, &[])])?;
        }
        d.core().keep_yes(space);
        return Ok(Shared::Waiting);
    }
    // where it held two lists, the person's yes makes them one
    if !more.is_empty() || t.two {
        reach.extend(more);
        let set = relationship::set_reach(&me, &reach);
        if let Err(e) = d.write_and_push(space, vec![set]) {
            take_back(d, &given.new).await;
            return Err(e);
        }
    }
    Ok(Shared::Named)
}

/// What software does to this person's reach node in a space on its own,
/// its own entry aside (`hosts.md#telling-others-where-to-reach-you`,
/// [`Telling`](crate::core::Telling)). It never names a host where the
/// list is set and names none, among contacts either: an empty list may be
/// the person's no, written on another of their devices, and nothing else
/// records it. It never takes out a host, and never writes only to make
/// two lists one (D70).
///
/// - Where they have left and it names a host, it is emptied.
/// - Among contacts, a list never set is set, to the person's hosts,
///   which is how whoever made a space joins it; and in a relationship a
///   device that has become a host adds itself, after those the list
///   names.
/// - A yes the person gave on this device while no host could be reached
///   is finished: the hosts are named once a token is registered. Only
///   this device does that, and not once the list has been set since.
///
/// A token that has gone, an address that changed and taking itself out
/// are the host's own ([`keep_own_entry`]). In any other case only the
/// person's act sets the list (`group-join`, `group-reach`).
pub async fn write_reach(d: &Arc<Daemon>, space: &SpaceId) -> anyhow::Result<()> {
    // One at a time: two that both found none would each register a token and
    // write, and leave a token that leads nowhere.
    let _one = d.mailbox.reaching.lock().await;
    if is_put_off(d, space) {
        return Ok(());
    }
    let (decided, named) = {
        let core = d.core();
        let Some(me) = core.me() else {
            return Ok(());
        };
        (Decided::now(&core, space), core.reach_of(space, &me))
    };
    let t = &decided.telling;
    if t.empties_unasked() {
        // The person left, and another of their devices had not heard.
        let emptied = say_reach_locked(d, space, false).await;
        if emptied.is_err() {
            put_off(d, space);
        }
        return emptied.map(|_| ());
    }
    if t.waiting {
        if !t.hosted {
            // the host they meant serves them no longer
            d.core().drop_yes(space);
            return Ok(());
        }
        let given = reach_here(d, space, &[], Add::Every).await;
        if !given.reach.is_empty() {
            // setting the list is what ends the wait; a list set while
            // the token was registered ended it already
            set_as_decided(d, space, &decided, &given.reach, &given.new).await?;
        }
        return Ok(());
    }
    if !t.sets_unasked() {
        return Ok(());
    }
    // The others as they read, each host once, unchanged. A list never
    // set is the person's joining, and names every host of theirs; to one
    // that is set a device adds only itself.
    let add = if t.set { Add::Own } else { Add::Every };
    let given = reach_here(d, space, &named, add).await;
    let more = given.reach;
    // A host that cannot be reached now gives no token. The empty list
    // that leaves is said once, and not again each time this looks.
    if !t.worth_saying(more.len()) {
        return Ok(());
    }
    // Whoever made a space joins it here, among contacts: with a host out
    // of reach, that yes is kept like any other.
    let wait = !t.set && !t.relationship && t.hosted && more.is_empty();
    let mut reach = named;
    reach.extend(more);
    let written = set_as_decided(d, space, &decided, &reach, &given.new).await?;
    if wait && written {
        d.core().keep_yes(space);
    }
    Ok(())
}

/// Ends every token this device ever gave out as a host in a space where
/// its person's reach node now names nobody: they have left the space
/// (`spaces.md#members-and-roles`), or emptied the node, as when they say
/// no (`hosts.md#delivery-tokens`). The host does this itself, when it
/// writes the entry or when the entry reaches it from another of the
/// person's devices. A token revoked never comes back: sharing again, or
/// joining again, sets the reach node again with new ones.
///
/// The node that would say which tokens were given is the one that was
/// just emptied, and a token serves whether the list names it or not
/// (`profiles.md#reach`), so they are read from every value the person
/// ever wrote to it. That is looked for only where the node has been set
/// and names no host, on a device with a token active.
///
/// It does not ask whether this device is a host now: a no given while
/// hosting was off holds when it is on again.
pub fn revoke_left(d: &Daemon, space: &SpaceId) {
    let here = *d.keys.link.public_key().x25519();
    // taken before the core is: never one lock inside the other
    let active: HashSet<Token> = lock(&d.mailbox.store).active().into_iter().collect();
    if active.is_empty() {
        return;
    }
    let given: Vec<Token> = {
        let core = d.core();
        let Some(me) = core.me() else { return };
        let Some(sp) = core.spaces.get(space).and_then(|h| h.space.as_ref()) else {
            return;
        };
        let names_none = relationship::reach_is_set(sp.state(), &me)
            && relationship::reach_of(sp, &me).is_empty();
        if !sp.has_left(&me) && !names_none {
            return;
        }
        core.tokens_given(space, &here)
    };
    for token in given.iter().filter(|t| active.contains(*t)) {
        revoke(d, token);
    }
}

/// Ends every token this device ever gave out as a host in the
/// relationship with anyone refused, named in the list there now or not
/// (R3: a token two lists once held, of which the one result kept the
/// other, let a refused contact in). The host does this itself, from what
/// reaches it in the account space, so that a refusal made on a device
/// that cannot reach it still holds.
pub fn revoke_refused(d: &Daemon) {
    let here = *d.keys.link.public_key().x25519();
    let active: HashSet<Token> = lock(&d.mailbox.store).active().into_iter().collect();
    if active.is_empty() {
        return;
    }
    let given: Vec<Token> = {
        let core = d.core();
        let contacts = core.contacts();
        let refused = contacts.iter().filter(|c| c.refused);
        refused
            .flat_map(|c| core.tokens_given(&c.space, &here))
            .collect()
    };
    for token in given.iter().filter(|t| active.contains(*t)) {
        revoke(d, token);
    }
}

/// Keeps this device's own entry in its person's reach nodes, wherever one
/// names it, and no other (D70,
/// `hosts.md#telling-others-where-to-reach-you`). A host gives its entry a
/// token where the one there has gone, for anyone not refused now (a
/// revoked token never comes back), and the addresses its grant gives now:
/// a contact away from home tries only the addresses a reach node names.
/// A device that is a host no longer takes itself out. Each host stays
/// where it is in the list, whose order is its person's, and another
/// host's entry is written as it was read. A reach node that names no host
/// is left as it is: that was its person's answer.
pub fn keep_own_entry(d: &Arc<Daemon>) {
    let host = d.config().host;
    let here = *d.keys.link.public_key().x25519();
    let Some(me) = d.core().identity.as_ref().map(|i| i.id()) else {
        return;
    };
    let named = d.core().spaces_naming_here();
    if named.is_empty() {
        return;
    }
    let endpoints = crate::host::own_grant(d).map(|g| g.endpoints);
    // Someone refused is given nothing new: their space is not shared.
    let shared: HashSet<SpaceId> = {
        let shared = d.core().shared_spaces().into_iter();
        shared.map(|(space, _)| space).collect()
    };
    for space in named {
        if host && !shared.contains(&space) {
            continue;
        }
        if is_put_off(d, &space) {
            continue;
        }
        // taken before the core is: never one lock inside the other
        let active: HashSet<Token> = lock(&d.mailbox.store).active().into_iter().collect();
        let mut new = Vec::new();
        let (due, decided) = {
            let core = d.core();
            let given = core.tokens_given(&space, &here);
            // One it gave here before and still honours, before a new
            // one: it never holds two where one serves.
            let fresh = || {
                let again = given.iter().find(|t| active.contains(*t));
                again.copied().unwrap_or_else(|| {
                    let t: Token = random_bytes();
                    new.push(t);
                    t
                })
            };
            let active = |t: &Token| active.contains(t);
            let due = core.own_entry_due(&space, host, endpoints.as_deref(), active, fresh);
            (due, Decided::now(&core, &space))
        };
        let Some(reach) = due else {
            continue;
        };
        for token in &new {
            register(d, token);
        }
        #[cfg(test)]
        if let Some(arrives) = lock(&d.mailbox.before_write).take() {
            arrives();
        }
        // A no that arrived since, and ended the token this renews, is
        // not written over (R1); a token made for a write that is not
        // made is ended (R5).
        let set = relationship::set_reach(&me, &reach);
        let written = d.write_and_push_if(&space, vec![set], |core| decided.still(core, &space));
        if !matches!(written, Ok(Some(_))) {
            for token in &new {
                revoke(d, token);
            }
        }
        match written {
            Ok(Some(_)) => {
                lock(&d.mailbox.put_off).remove(&space);
                if reach.is_empty() {
                    revoke_left(d, &space);
                }
            }
            Ok(None) => {}
            Err(e) => {
                put_off(d, &space);
                tracing::debug!("keeping this device's entry among its person's hosts: {e:#}");
            }
        }
    }
}

/// Brings this host's part of a reach node up to date: a fresh token for one
/// that has gone, and the addresses it is reached at now. Says whether
/// anything changed.
pub(crate) fn kept_current(
    reach: &mut [Reach],
    here: &[u8; 32],
    endpoints: Option<&[Endpoint]>,
    active: impl Fn(&Token) -> bool,
    mut fresh: impl FnMut() -> Token,
) -> bool {
    let mut changed = false;
    for r in reach.iter_mut().filter(|r| r.host == *here) {
        if !active(&r.token) {
            r.token = fresh();
            changed = true;
        }
        if let Some(now) = endpoints.filter(|e| !e.is_empty() && *e != r.endpoints.as_slice()) {
            r.endpoints = now.to_vec();
            changed = true;
        }
    }
    changed
}

/// What this device has written in a set, if it is a space.
pub fn written_here(d: &Daemon, space: &SpaceId) -> Vec<EntryId> {
    let mine = d.core().entries_by(space, &d.keys.key());
    mine.into_iter().map(|(id, _)| id).collect()
}

/// Two people have just reconciled a space: what this device wrote in it so
/// far needs no delivering.
pub fn met(d: &Daemon, space: &SpaceId, member: &[u8; 32]) {
    d.mailbox.mark_sent(space, member, &written_here(d, space));
}

/// A host in use, until this goes.
pub(crate) struct Going<'a> {
    going: &'a Mutex<HashSet<[u8; 32]>>,
    host: [u8; 32],
}

impl Drop for Going<'_> {
    fn drop(&mut self) {
        lock(self.going).remove(&self.host);
    }
}

pub(crate) fn going_to(d: &Daemon, host: [u8; 32]) -> Option<Going<'_>> {
    claim(&d.mailbox.going, host)
}

fn claim(going: &Mutex<HashSet<[u8; 32]>>, host: [u8; 32]) -> Option<Going<'_>> {
    // Lazily: a guard made and dropped here would take the lock held here.
    lock(going).insert(host).then(|| Going { going, host })
}

/// Where to try the hosts in `reach`.
pub(crate) fn addresses(reach: &[Reach]) -> Vec<(&Reach, SocketAddr)> {
    let hosts = reach.iter().take(MAX_REACH);
    hosts
        .flat_map(|r| {
            let endpoints = r.endpoints.iter().take(MAX_REACH);
            endpoints
                .filter_map(|e| e.socket_addr())
                .map(move |a| (r, a))
        })
        .collect()
}

/// Opens a session with a host of someone else's, with their token. It says
/// nothing of who is asking, and is good for one space. A contact wrote where
/// this goes, so it must not be this device, or one it has a session with,
/// which this would end.
async fn at_host(d: &Daemon, r: &Reach, addr: SocketAddr) -> Option<Session> {
    let here = *d.keys.link.public_key().x25519();
    if r.host == here || d.session_kind(&r.host).is_some() || d.rendezvous.holds(&r.host) {
        return None;
    }
    let secret = derive(Purpose::Token, &r.token);
    let target = |c: CarrierKind| Target::invitation(addr, c, r.host, &secret[..]).anonymous();
    d.dial(target).await.ok()
}

/// Fetches a space from a member's host, with the member's log, which what
/// they write there is judged by. A session with a token is the only way this
/// person hears of their devices.
async fn pull(d: &Arc<Daemon>, space: &SpaceId, member: &[u8; 32], reach: &[Reach]) -> bool {
    for (r, addr) in addresses(reach) {
        let Some(_going) = going_to(d, r.host) else {
            continue;
        };
        let Some(s) = at_host(d, r, addr).await else {
            continue;
        };
        let fetching = async {
            let log = identity_log_label(member);
            net::reconcile_as(d, &s, log, Access::Other(*member)).await?;
            net::reconcile_as(d, &s, *space, Access::Full).await
        };
        let done = tokio::time::timeout(AT_HOST_WITHIN, fetching).await;
        s.close("fetched");
        match done {
            Ok(Ok(())) => return true,
            Ok(Err(e)) => tracing::debug!("fetching from a host: {e:#}"),
            Err(_) => tracing::debug!("fetching from a host: it took too long"),
        }
    }
    false
}

/// Fetches a space from the hosts of the members with no session here.
async fn pull_from_members(d: &Arc<Daemon>, space: &SpaceId, members: &[[u8; 32]]) -> bool {
    let in_touch = d.people_in_touch();
    let mut fetched = false;
    for member in members.iter().filter(|m| !in_touch.contains(*m)) {
        let reach = d.core().reach_of(space, member);
        if !reach.is_empty() {
            fetched |= pull(d, space, member, &reach).await;
        }
    }
    fetched
}

/// Fetches a space for what an envelope needs, not too often: what asks for
/// this may be a contact's doing.
async fn pull_for(d: &Arc<Daemon>, space: &SpaceId) -> bool {
    {
        let mut pulled = lock(&d.mailbox.pulled);
        if pulled.get(space).is_some_and(|t| t.elapsed() < PULL_GAP) {
            return false;
        }
        pulled.insert(*space, Instant::now());
    }
    let shared = d.core().shared_spaces();
    let members = shared.into_iter().find(|(id, _)| id == space);
    let fetched = match members {
        Some((_, members)) => pull_from_members(d, space, &members).await,
        None => false,
    };
    if !fetched {
        lock(&d.mailbox.pulled).remove(space);
    }
    fetched
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
    for (r, addr) in addresses(reach) {
        let Some(_going) = going_to(d, r.host) else {
            continue;
        };
        let Some(s) = at_host(d, r, addr).await else {
            continue;
        };
        let mut left = Vec::new();
        let leaving = async {
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
        };
        let _ = tokio::time::timeout(AT_HOST_WITHIN, leaving).await;
        s.close("delivered");
        if !left.is_empty() {
            return left;
        }
    }
    Vec::new()
}

/// Delivers what this device wrote in a space to a member it has no session
/// with. A member counts as having something only once a deposit or a
/// reconcile says so: a session that merely looks open may be gone.
async fn deliver_to(d: &Arc<Daemon>, space: &SpaceId, member: &[u8; 32]) {
    let mine = d.core().entries_by(space, &d.keys.key());
    let unsent = d.mailbox.unsent(space, member, mine);
    if unsent.is_empty() || d.people_in_touch().contains(member) {
        return;
    }
    let reach = d.core().reach_of(space, member);
    if reach.is_empty() {
        // Nowhere to leave it: they are looked for instead, through this
        // person's devices that may be in touch with them (`sync.md#neighbours`).
        d.rendezvous.use_contact(member);
        return;
    }
    let Some((epoch, key)) = d.core().envelope_key(space) else {
        return;
    };
    let (fits, long): (Vec<_>, Vec<_>) = unsent
        .iter()
        .map(|(id, entry)| (*id, seal(&epoch, &key, &entry[..])))
        .partition(|(_, envelope)| envelope.len() <= MAX_ENVELOPE);
    let some = &fits[..fits.len().min(LEAVE_AT_ONCE)];
    let left = leave(d, &reach, some).await;
    d.mailbox.mark_sent(space, member, &left);
    // Too long to carry, so say that it is there, if this person has a host
    // to fetch it from.
    let me = d.core().identity.as_ref().map(|i| i.id());
    let hosted = me.is_some_and(|me| !d.core().reach_of(space, &me).is_empty());
    if long.is_empty() || !hosted {
        return;
    }
    let mut ids = d.core().heads(space);
    ids.truncate(MAX_HEADS);
    let heads = Message::Heads { label: *space, ids };
    let notice = (long[0].0, seal(&epoch, &key, to_value(&heads)));
    if !leave(d, &reach, &[notice]).await.is_empty() {
        let long: Vec<EntryId> = long.iter().map(|(id, _)| *id).collect();
        d.mailbox.mark_sent(space, member, &long);
    }
}

/// Delivers what this device wrote to each member it has no session with.
async fn deliver(d: &Arc<Daemon>) {
    keep_own_entry(d);
    let shared = d.core().shared_spaces();
    for (space, members) in shared {
        // Before anything else, since it holds for a space this person
        // has left as well: there it empties a reach node that names
        // their hosts again, and writes nothing else. Where they were
        // only offered the space it writes nothing at all.
        if let Err(e) = write_reach(d, &space).await {
            tracing::debug!("writing where to reach this person: {e:#}");
        }
        // Nothing of this person's goes in a group they have not joined.
        if crate::groups::not_joined(d, &space) {
            continue;
        }
        for member in members {
            deliver_to(d, &space, &member).await;
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
            if take_in(d, held).await == Taken::Done {
                lock(&d.mailbox.store).taken(held.sequence);
            }
        }
        after = last;
        if !more {
            return;
        }
    }
}

/// What became of an envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Taken {
    /// It is finished with.
    Done,
    /// Something it needs has not arrived. It waits, until retention ends.
    NotYet,
}

/// Opens an envelope and takes in what it holds. One that can never open is
/// dropped: its sender gets nothing from it.
async fn take_in(d: &Arc<Daemon>, held: &Held) -> Taken {
    let Some(epoch) = epoch_of(&held.envelope) else {
        return Taken::Done;
    };
    let found = {
        let core = d.core();
        let space = core.space_of_token(&held.token);
        space.map(|space| (space, core.envelope_key_of(&space, &epoch)))
    };
    // The space itself may be on its way here from another of the owner's
    // devices.
    let Some((space, key)) = found else {
        return Taken::NotYet;
    };
    // The key may be in an entry too long for an envelope.
    let Some(key) = key else {
        pull_for(d, &space).await;
        return Taken::NotYet;
    };
    let Some(notice) = open_envelope(&held.envelope, &key) else {
        tracing::debug!("dropping envelope {}: it does not open", held.sequence);
        return Taken::Done;
    };
    match notice {
        Notice::Heads(ids) => {
            let lacks = |d: &Daemon| ids.iter().any(|id| !d.core().has(&space, id));
            if lacks(d) {
                pull_for(d, &space).await;
            }
            if lacks(d) {
                Taken::NotYet
            } else {
                Taken::Done
            }
        }
        Notice::Entry(entry) => {
            let d2 = d.clone();
            let sealed = entry.clone();
            let ingest = move || d2.ingest(space, vec![sealed], Access::Full);
            match tokio::task::spawn_blocking(ingest).await {
                Ok(Ok(outcome)) => {
                    let me = *d.keys.link.public_key().x25519();
                    let lacks_parents = outcome.missing_parents;
                    d.pass_on(space, outcome.complete, outcome.objects, me);
                    if lacks_parents {
                        pull_for(d, &space).await;
                    }
                    // It may be from a device this person has not heard of.
                    if !d.core().entry_counts(&space, &entry) {
                        pull_for(d, &space).await;
                        return Taken::NotYet;
                    }
                    Taken::Done
                }
                Ok(Err(e)) => {
                    tracing::debug!("envelope {}: {e:#}", held.sequence);
                    Taken::NotYet
                }
                Err(e) => {
                    tracing::debug!("envelope {}: {e}", held.sequence);
                    Taken::NotYet
                }
            }
        }
    }
}

fn pull_every() -> Duration {
    std::env::var("CARDINAL_TEST_PULL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map_or(PULL_EVERY, Duration::from_secs)
}

/// Keeps delivering and collecting, whenever there may be something to do.
/// The two go separately: what comes in must not wait on a host of someone
/// else's that does not answer.
pub fn start(d: Arc<Daemon>) {
    let collecting = d.clone();
    tokio::spawn(async move {
        let mut changed = collecting.changed.subscribe();
        let mut every = tokio::time::interval(LOOK_EVERY);
        loop {
            tokio::select! {
                _ = every.tick() => {}
                _ = changed.changed() => {}
            }
            collect(&collecting).await;
            tokio::time::sleep(LOOK_GAP).await;
        }
    });
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

    /// A second claim on a host in use once hung the thread that made it.
    #[test]
    fn a_host_in_use_is_refused_and_freed() {
        let going = Arc::new(Mutex::new(HashSet::new()));
        let g = going.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let first = claim(&g, [1; 32]);
            let second = claim(&g, [1; 32]);
            let other = claim(&g, [2; 32]);
            let refused = first.is_some() && second.is_none() && other.is_some();
            drop(first);
            let _ = tx.send(refused && claim(&g, [1; 32]).is_some());
        });
        let ok = rx.recv_timeout(Duration::from_secs(5));
        assert_eq!(ok, Ok(true), "a second claim hangs or is let through");
    }
    use cardinal_crypto::aead::xchacha20poly1305_encrypt;
    use cardinal_space::grant::Endpoint;
    use cardinal_space::EpochKey;

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
        let op = relationship::set_reach(&[3; 32], &[reach.clone(), reach]);
        let body = op.record().encode();
        assert!(body.len() < MAX_ENVELOPE / 2, "{} bytes", body.len());
    }

    #[test]
    fn a_reach_node_follows_where_its_host_is_now() {
        let home = Endpoint::parse("172.20.1.20:7171").unwrap();
        let public = Endpoint::parse("203.0.113.9:7171").unwrap();
        let theirs = Reach {
            endpoints: vec![home.clone()],
            host: [9; 32],
            token: OTHER,
        };
        let mut reach = vec![
            Reach {
                endpoints: vec![home.clone()],
                host: [1; 32],
                token: T,
            },
            theirs.clone(),
        ];
        let now = [home.clone(), public.clone()];
        let never = || -> Token { panic!("an active token is kept") };
        // Here now at home and on the internet: the node says so.
        assert!(kept_current(
            &mut reach,
            &[1; 32],
            Some(&now),
            |_| true,
            never
        ));
        assert_eq!(reach[0].endpoints, now);
        assert_eq!(reach[0].token, T);
        assert_eq!(reach[1], theirs, "another host's part is its own");
        // Already current: nothing to write.
        assert!(!kept_current(
            &mut reach,
            &[1; 32],
            Some(&now),
            |_| true,
            never
        ));
        // A token gone is renewed, where it is.
        assert!(kept_current(
            &mut reach,
            &[1; 32],
            Some(&now),
            |_| false,
            || [5; 16]
        ));
        assert_eq!(reach[0].token, [5; 16]);
        assert_eq!(reach[0].endpoints, now);
    }

    /// D68 (`profiles.md#reach`). The order of the list is its person's.
    /// A host that brings its own part up to date stays where it is, and
    /// what stands before and after it is written as it was read, an
    /// endpoint this version cannot use included.
    #[test]
    fn a_reach_node_kept_current_keeps_its_order() {
        use cardinal_encoding::Record;
        let radio = Record::new()
            .with(1, [0x52u8; 8])
            .with(2, "by its document");
        let other = |n: u8| Reach {
            endpoints: vec![Endpoint::from_record(&radio)],
            host: [n; 32],
            token: [n; 16],
        };
        let old = Endpoint::parse("172.20.1.20:7171").unwrap();
        let now = [Endpoint::parse("203.0.113.9:7171").unwrap()];
        let here = Reach {
            endpoints: vec![old],
            host: [1; 32],
            token: T,
        };
        let mut reach = vec![other(7), here, other(8)];
        assert!(kept_current(
            &mut reach,
            &[1; 32],
            Some(&now),
            |_| false,
            || [5; 16]
        ));
        let hosts: Vec<u8> = reach.iter().map(|r| r.host[0]).collect();
        assert_eq!(hosts, [7, 1, 8]);
        assert_eq!(
            (reach[1].token, &reach[1].endpoints[..]),
            ([5; 16], &now[..])
        );
        assert_eq!((&reach[0], &reach[2]), (&other(7), &other(8)));
        assert_eq!(reach[0].endpoints[0].to_record(), radio);
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

    /// `vectors/mailbox.json`: built by hand from `hosts.md` rather than by
    /// `seal`, then opened by the code a device runs. Rewrite it after an
    /// intentional change with `CARDINAL_WRITE_VECTORS=1`.
    #[test]
    fn mailbox_vectors() {
        let epoch_key = EpochKey::from_bytes([0x41; 32]);
        let (epoch, key) = (epoch_key.id(), epoch_key.mailbox_key());
        let nonce = [0x42; 24];
        let envelope = |notice: Value| {
            let payload = Record::new().with(0, 7u64).with(1, notice).encode();
            let ciphertext = xchacha20poly1305_encrypt(&key, &nonce, &[], &payload);
            let sealed = Record::new()
                .with(0, 11u64)
                .with(1, epoch)
                .with(2, nonce)
                .with(3, ciphertext)
                .encode();
            (payload, sealed)
        };

        let (entry_payload, entry_sealed) = envelope(Value::from(&b"a sealed entry"[..]));
        let opened = open_envelope(&entry_sealed, &key);
        assert_eq!(opened, Some(Notice::Entry(b"a sealed entry".to_vec())));
        assert_eq!(epoch_of(&entry_sealed), Some(epoch));

        let ids = vec![[0x43; 32], [0x44; 32]];
        let heads = Message::Heads {
            label: [0x45; 32],
            ids: ids.clone(),
        };
        let (heads_payload, heads_sealed) = envelope(to_value(&heads));
        assert_eq!(open_envelope(&heads_sealed, &key), Some(Notice::Heads(ids)));

        let token = [0x46; 16];
        let reach = Reach {
            endpoints: vec![Endpoint::parse("203.0.113.9:7171").unwrap()],
            host: [0x47; 32],
            token,
        };
        let op = relationship::set_reach(&[0x48; 32], &[reach]);

        let vectors = serde_json::json!({
            "description": "Mailbox (hosts.md#envelopes, profiles.md#reach). \
                Envelopes use XChaCha20-Poly1305 with empty associated data. \
                Inputs are fixed bytes, not secrets.",
            "epoch_key": hex::encode(epoch_key.bytes()),
            "epoch_id": hex::encode(epoch),
            "mailbox_key": hex::encode(&key[..]),
            "nonce": hex::encode(nonce),
            "entry_envelope": {
                "payload": hex::encode(entry_payload),
                "envelope": hex::encode(entry_sealed),
            },
            "heads_envelope": {
                "payload": hex::encode(heads_payload),
                "envelope": hex::encode(heads_sealed),
            },
            "token_session": {
                "token": hex::encode(token),
                "secret": hex::encode(&derive(Purpose::Token, &token)[..]),
            },
            "reach_node": hex::encode(cardinal_space::reach_node_id(&[0x48; 32])),
            "reach_node_set": hex::encode(op.record().encode()),
        });
        let text = serde_json::to_string_pretty(&vectors).unwrap() + "\n";
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/mailbox.json");
        if std::env::var_os("CARDINAL_WRITE_VECTORS").is_some() {
            std::fs::write(&path, text).unwrap();
            return;
        }
        let existing = std::fs::read_to_string(&path).unwrap();
        assert!(existing == text, "{} is out of date", path.display());
    }

    /// A service in this process, on a directory of its own, with nothing
    /// running in it but what a test calls: one device of a person who has
    /// one contact, Bo, and the relationship with him.
    struct Home {
        d: Arc<Daemon>,
        rel: SpaceId,
        me: [u8; 32],
        here: [u8; 32],
        bo: crate::core::Core,
        _dirs: [tempfile::TempDir; 2],
    }

    impl Home {
        async fn new() -> Home {
            use cardinal_space::account::{self, Regard};
            let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
            let (paths, config) = crate::testing::set_up(dirs[0].path());
            let d = Daemon::start(paths, config).await.unwrap();
            let (paths, _) = crate::testing::set_up(dirs[1].path());
            let keys = crate::keys::Keys::load_or_create(&paths.device_key()).unwrap();
            let mut bo = crate::core::Core::load(&paths, Arc::new(keys)).unwrap();
            let me = d.core().me().unwrap();
            let them = bo.me().unwrap();
            let log = |c: &crate::core::Core| c.identity.as_ref().unwrap().all_entries();
            let (mine, theirs) = (log(&d.core()), log(&bo));
            d.core().ingest_other(them, &theirs).unwrap();
            bo.ingest_other(me, &mine).unwrap();
            let (rel, genesis) = d.core().create_relationship(&them).unwrap();
            bo.accept_relationship(&genesis, &me).unwrap();
            let account = d.core().account_id().unwrap();
            let contact = account::create_contact(&them, "Bo", &rel, Regard::default());
            d.write_and_push(&account, vec![contact]).unwrap();
            let here = *d.keys.link.public_key().x25519();
            Home {
                d,
                rel,
                me,
                here,
                bo,
                _dirs: dirs,
            }
        }

        fn hosts(&self) {
            crate::host::enable(&self.d, &["203.0.113.5:7171".to_owned()]).unwrap();
        }

        fn active(&self) -> Vec<Token> {
            let mut all = lock(&self.d.mailbox.store).active();
            all.sort();
            all
        }

        /// The entries of a space nothing here comes after.
        fn heads(&self, space: &SpaceId) -> Vec<EntryId> {
            let core = self.d.core();
            core.spaces[space].space.as_ref().unwrap().heads()
        }

        fn named(&self, space: &SpaceId) -> Vec<Reach> {
            self.d.core().reach_of(space, &self.me)
        }

        /// A list set by another of the person's devices at the same
        /// moment as the one that is there, which names this host with a
        /// token that device registered here.
        fn set_beside(&self, space: &SpaceId) -> Token {
            let token: Token = random_bytes();
            register(&self.d, &token);
            let mut list = self.named(space);
            list[0].token = token;
            let last = self.heads(space);
            let set = relationship::set_reach(&self.me, &list);
            let mut core = self.d.core();
            core.write_entry_concurrent(space, &last, vec![set])
                .unwrap();
            token
        }

        /// The host writes its own entry again, as for an address that
        /// changed: then there is one list, with the token it reads.
        fn writes_again(&self, space: &SpaceId) -> Token {
            let list = self.named(space);
            let set = relationship::set_reach(&self.me, &list);
            self.d.write_and_push(space, vec![set]).unwrap();
            list[0].token
        }

        fn refuses_bo(&self) {
            use cardinal_space::account;
            let account = self.d.core().account_id().unwrap();
            let node = self.d.core().contacts()[0].node;
            let refuse = account::set_field(node, account::REFUSED, true);
            self.d.write_and_push(&account, vec![refuse]).unwrap();
            self.d.peers_changed();
        }
    }

    /// D70. On a host, a relationship names it unasked; with two lists
    /// set at once, both tokens are active and nothing is written for
    /// that, look after look.
    #[tokio::test(flavor = "multi_thread")]
    async fn two_lists_are_left_as_two_and_both_tokens_serve() {
        let h = Home::new().await;
        h.hosts();
        write_reach(&h.d, &h.rel).await.unwrap();
        let first = h.named(&h.rel);
        assert_eq!(first.len(), 1);
        assert_eq!((first[0].host, h.active()), (h.here, vec![first[0].token]));
        let second = h.set_beside(&h.rel);
        let held = h.heads(&h.rel);
        assert_eq!(held.len(), 2);
        for _ in 0..3 {
            keep_own_entry(&h.d);
            write_reach(&h.d, &h.rel).await.unwrap();
        }
        assert_eq!(h.heads(&h.rel), held, "something was written");
        assert_eq!(h.named(&h.rel).len(), 1, "one host, named in both");
        let mut both = vec![first[0].token, second];
        both.sort();
        assert_eq!(h.active(), both);
        for token in both {
            assert_eq!(h.d.core().space_of_token(&token), Some(h.rel));
        }
    }

    /// R3. Refusing a contact ends every token they were given, and not
    /// only the one the list names now: a token that two lists once held
    /// and the list names no longer still opened a session with the host.
    /// The same for a no, which empties the list.
    #[tokio::test(flavor = "multi_thread")]
    async fn refusing_ends_every_token_given_for_the_space() {
        let h = Home::new().await;
        h.hosts();
        write_reach(&h.d, &h.rel).await.unwrap();
        h.set_beside(&h.rel);
        h.writes_again(&h.rel);
        assert_eq!(h.active().len(), 2, "a token goes when it is unnamed");
        h.refuses_bo();
        assert_eq!(h.active(), Vec::<Token>::new());
        // and nothing gives him a new one
        keep_own_entry(&h.d);
        write_reach(&h.d, &h.rel).await.unwrap();
        assert_eq!(h.active(), Vec::<Token>::new());

        // A no ends them all too.
        let h = Home::new().await;
        h.hosts();
        write_reach(&h.d, &h.rel).await.unwrap();
        h.set_beside(&h.rel);
        h.writes_again(&h.rel);
        say_reach(&h.d, &h.rel, false).await.unwrap();
        assert_eq!(h.active(), Vec::<Token>::new());
    }

    /// R4. What is left under a token the list names no longer is opened
    /// like anything else: the token is active, so the host took the
    /// envelope and its sender counts it delivered.
    #[tokio::test(flavor = "multi_thread")]
    async fn what_is_left_under_a_token_no_longer_named_is_opened() {
        let mut h = Home::new().await;
        h.hosts();
        write_reach(&h.d, &h.rel).await.unwrap();
        let other = h.set_beside(&h.rel);
        let named = h.writes_again(&h.rel);
        let old = if named == other {
            let all = h.active();
            *all.iter().find(|t| **t != named).unwrap()
        } else {
            other
        };
        // Bo read the list while it held both, and leaves a message under
        // the one that is named no longer.
        let conversation = {
            let core = h.d.core();
            let sp = core.spaces[&h.rel].space.as_ref().unwrap();
            relationship::conversation(sp).unwrap()
        };
        let said = relationship::create_message(conversation, "are you there?");
        let (_, entry) = h.bo.write_entry(&h.rel, vec![said]).unwrap();
        let (epoch, key) = h.bo.envelope_key(&h.rel).unwrap();
        let envelope = seal(&epoch, &key, &entry[..]);
        let left = lock(&h.d.mailbox.store).deposit(&old, &envelope, now());
        assert!(left.is_ok(), "the host does not take it");
        collect(&h.d).await;
        let texts = || -> Vec<String> {
            let core = h.d.core();
            let sp = core.spaces[&h.rel].space.as_ref().unwrap();
            let all = relationship::messages(sp);
            all.into_iter().map(|m| m.text).collect()
        };
        assert_eq!(texts(), ["are you there?"]);
        let device = h.d.keys.key();
        let (waiting, _) = lock(&h.d.mailbox.store).fetch(&device, 0, now());
        assert!(waiting.is_empty(), "it is still held");
    }

    /// D70. `host --off` on the host itself takes it out of the lists
    /// that name it: nobody else may. Turned on again, it adds itself in a
    /// relationship.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_host_turned_off_takes_itself_out() {
        let h = Home::new().await;
        h.hosts();
        write_reach(&h.d, &h.rel).await.unwrap();
        assert_eq!(h.named(&h.rel).len(), 1);
        crate::host::disable(&h.d).unwrap();
        assert!(h.named(&h.rel).is_empty(), "it is still listed");
        assert!(h.d.core().reach_is_set(&h.rel, &h.me));
        // nothing puts it back while it is off
        keep_own_entry(&h.d);
        write_reach(&h.d, &h.rel).await.unwrap();
        assert!(h.named(&h.rel).is_empty());
        h.hosts();
        write_reach(&h.d, &h.rel).await.unwrap();
        let named = h.named(&h.rel);
        assert_eq!(named.len(), 1);
        assert_eq!(h.active(), vec![named[0].token]);
    }

    impl Home {
        /// A group this person made with Bo in it, who is their contact:
        /// they are in it, and their list there was never set.
        fn group(&self) -> SpaceId {
            let them = self.bo.me().unwrap();
            let shown = [(them, "Bo".to_owned())];
            let mut core = self.d.core();
            core.create_group("Choir", "Ana", &shown).unwrap()
        }

        /// While this device next registers a token, an entry arrives
        /// from another of its person's devices that sets the list of a
        /// space empty: their no.
        fn a_no_arrives_meanwhile(&self, space: SpaceId) {
            let (d, me) = (self.d.clone(), self.me);
            let arrives = move || {
                let no = relationship::set_reach(&me, &[]);
                d.core().write(&space, vec![no]).unwrap();
                revoke_left(&d, &space);
            };
            *lock(&self.d.mailbox.before_write) = Some(Box::new(arrives));
        }

        fn revoked(&self) -> usize {
            lock(&self.d.mailbox.store).saved.revoked.len()
        }
    }

    /// R1. A yes kept for a host out of reach is finished once a token is
    /// registered. A no that arrives while it is being registered is later
    /// than the yes: the list stays empty, and the token is ended.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_no_that_arrives_while_a_kept_yes_is_finished_stands() {
        let h = Home::new().await;
        h.hosts();
        let g = h.group();
        // the yes, kept against an empty list
        say_reach(&h.d, &g, false).await.unwrap();
        h.d.core().keep_yes(&g);
        assert!(h.d.core().telling(&g).waiting);
        h.a_no_arrives_meanwhile(g);
        write_reach(&h.d, &g).await.unwrap();
        assert!(h.named(&g).is_empty(), "the no was written over");
        assert_eq!(h.active(), Vec::<Token>::new(), "its token is left");
        assert!(!h.d.core().telling(&g).waiting);
        // and it stays so
        write_reach(&h.d, &g).await.unwrap();
        assert!(h.named(&g).is_empty());

        // With nothing arriving, the yes is finished.
        let h = Home::new().await;
        h.hosts();
        let g = h.group();
        say_reach(&h.d, &g, false).await.unwrap();
        h.d.core().keep_yes(&g);
        write_reach(&h.d, &g).await.unwrap();
        assert_eq!(h.named(&g).len(), 1);
        assert!(!h.d.core().telling(&g).waiting);
    }

    /// R1, the host's side. Its token in a list has gone, and it sets
    /// about giving the entry another. A no arrives first: nothing is
    /// written on top of it, and no token is left.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_no_that_arrives_while_a_host_renews_its_token_stands() {
        let h = Home::new().await;
        h.hosts();
        let g = h.group();
        write_reach(&h.d, &g).await.unwrap();
        let named = h.named(&g);
        assert_eq!(named.len(), 1);
        revoke(&h.d, &named[0].token);
        h.a_no_arrives_meanwhile(g);
        keep_own_entry(&h.d);
        assert!(h.named(&g).is_empty(), "the no was written over");
        assert_eq!(h.active(), Vec::<Token>::new(), "its token is left");
        keep_own_entry(&h.d);
        write_reach(&h.d, &g).await.unwrap();
        assert!(h.named(&g).is_empty());

        // With nothing arriving, the entry gets a new token.
        let h = Home::new().await;
        h.hosts();
        let g = h.group();
        write_reach(&h.d, &g).await.unwrap();
        let was = h.named(&g)[0].token;
        revoke(&h.d, &was);
        keep_own_entry(&h.d);
        let now = h.named(&g)[0].token;
        assert!(now != was && h.active() == vec![now]);
    }

    /// R5. A token is registered before the write that would name it. A
    /// write that fails, as on a full disk, ends the token again, and the
    /// attempt is put off: it is not made at every look, each with a new
    /// token.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_token_registered_for_a_write_that_fails_is_ended() {
        let h = Home::new().await;
        h.hosts();
        for _ in 0..5 {
            h.d.core().break_log_for_test(&h.rel);
            assert!(h.named(&h.rel).is_empty());
            let _ = write_reach(&h.d, &h.rel).await;
        }
        assert_eq!(h.active(), Vec::<Token>::new(), "tokens nothing names");
        assert_eq!(h.revoked(), 1, "it was tried at every look");
        // Once the wait is over it is tried again: the log is still as
        // the test left it, and then it is not.
        lock(&h.d.mailbox.put_off).clear();
        assert!(write_reach(&h.d, &h.rel).await.is_err());
        assert_eq!((h.active().len(), h.revoked()), (0, 2));
        lock(&h.d.mailbox.put_off).clear();
        write_reach(&h.d, &h.rel).await.unwrap();
        assert_eq!(h.named(&h.rel).len(), 1);
        assert_eq!(h.active().len(), 1);

        // The same for the host's own entry.
        let named = h.named(&h.rel);
        revoke(&h.d, &named[0].token);
        let revoked = h.revoked();
        for _ in 0..5 {
            h.d.core().break_log_for_test(&h.rel);
            keep_own_entry(&h.d);
        }
        assert_eq!(h.active(), Vec::<Token>::new(), "tokens nothing names");
        assert_eq!(h.revoked(), revoked + 1, "it was tried at every look");
    }
}
