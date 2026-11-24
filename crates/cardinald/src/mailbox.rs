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
use cardinal_space::account;
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
/// Where envelopes wait until collected, as for a contact this device
/// hosts: how long an owner device may go without fetching and still hold
/// envelopes up.
const FETCHER_GONE: u64 = 30 * 24 * 60 * 60;
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
pub(crate) const OP_USAGE: u64 = 6;
/// Sent by a contact's device that hosts this person, to their devices
/// present there: an envelope waits (D87). No reply.
pub(crate) const OP_WAITING: u64 = 7;
pub(crate) const NOT_PERMITTED: u64 = 1;
const FULL: u64 = 2;
pub(crate) const UNKNOWN: u64 = 3;
pub(crate) const MALFORMED: u64 = 4;

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
    /// How long an envelope waits for its owner, in seconds: `None` until
    /// collected, as for a contact this device hosts (D87).
    retention: Option<u64>,
    /// How long an owner device may go without fetching and still hold
    /// envelopes up, in seconds.
    fetchers_within: u64,
    /// Whether the quota counts all tokens together, as for a contact this
    /// device hosts, rather than each token alone.
    whole: bool,
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
        Store {
            dir,
            saved,
            held,
            retention: Some(RETENTION),
            fetchers_within: RETENTION,
            whole: false,
        }
    }

    /// The same, as for a contact this device hosts (D87): each envelope
    /// waits until it is collected, by the owner devices that fetched
    /// within the last 30 days, and the quota counts all their tokens
    /// together.
    pub(crate) fn until_collected(mut self) -> Store {
        self.retention = None;
        self.fetchers_within = FETCHER_GONE;
        self.whole = true;
        self
    }

    /// Forgets the owner devices not among `devices`, as those taken out
    /// of the owner's log: they hold nothing up any longer.
    pub(crate) fn keep_fetchers(&mut self, devices: &HashSet<KeyId>, now: u64) {
        let before = self.saved.fetchers.len();
        let keep: HashSet<String> = devices.iter().map(hex::encode).collect();
        self.saved.fetchers.retain(|k, _| keep.contains(k));
        if self.saved.fetchers.len() != before {
            self.sweep(now);
            let _ = self.save();
        }
    }

    /// Envelopes waiting, under any token.
    pub(crate) fn waiting(&self) -> usize {
        self.held.len()
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
        let limits = (Some(OUTSTANDING as u64), Some(u64::from(PER_DAY)));
        self.deposit_within(token, envelope, now, limits)
    }

    /// [`deposit`](Self::deposit), within a quota class's limits: envelopes
    /// waiting and deposits a day, `None` no limit; under one token, or
    /// under all of them together for a contact this device hosts.
    pub(crate) fn deposit_within(
        &mut self,
        token: &Token,
        envelope: &[u8],
        now: u64,
        (outstanding, per_day): (Option<u64>, Option<u64>),
    ) -> Result<u64, Refused> {
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
        let (counted, waiting) = if self.whole {
            let all: u32 = self.saved.deposits.values().sum();
            (all, self.held.len())
        } else {
            (today, self.waiting_under(token))
        };
        let over = |n: u64, limit: Option<u64>| limit.is_some_and(|l| n >= l);
        if over(u64::from(counted), per_day) || over(waiting as u64, outstanding) {
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
    pub(crate) fn usage(&self) -> Vec<(Token, usize, u32)> {
        self.active()
            .into_iter()
            .map(|t| {
                let today = self.saved.deposits.get(&hex::encode(t));
                (t, self.waiting_under(&t), today.copied().unwrap_or(0))
            })
            .collect()
    }

    /// Lets go of what every recent device has collected, and of what has
    /// waited too long. A device that has not fetched for a while holds
    /// nothing up.
    fn sweep(&mut self, now: u64) {
        let recent = |at: u64| self.retention.is_none_or(|r| now.saturating_sub(at) < r);
        let within = self.fetchers_within;
        self.saved
            .fetchers
            .retain(|_, f| now.saturating_sub(f.at) < within);
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
    pub(crate) reaching: tokio::sync::Mutex<()>,
    /// The contacts this device hosts, and its hosts that are contacts'
    /// (D87).
    pub(crate) hosted: crate::hosting::Hosted,
    /// The spaces where what this device set about on its own failed, as
    /// for a log that cannot be written, and when it tries again.
    put_off: Mutex<HashMap<SpaceId, PutOff>>,
    /// The spaces where this device set about writing the person's no and
    /// has not yet written the empty list (D75): finished at the next look,
    /// after a failed write or a crash. Kept in `pending-no.json`.
    pending_no: Mutex<BTreeSet<SpaceId>>,
    pending_no_path: PathBuf,
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
        let pending_no_path = dir.join("pending-no.json");
        let pending_no: BTreeSet<SpaceId> = std::fs::read(&pending_no_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<String>>(&b).ok())
            .unwrap_or_default()
            .iter()
            .filter_map(|h| hex::decode(h).ok()?.try_into().ok())
            .collect();
        let sent = std::fs::read(&sent_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Mailbox {
            store: Mutex::new(Store::load(dir.clone())),
            secrets: Mutex::new(HashMap::new()),
            sent: Mutex::new(sent),
            sent_path,
            going: Mutex::new(HashSet::new()),
            pulled: Mutex::new(HashMap::new()),
            reaching: tokio::sync::Mutex::new(()),
            hosted: crate::hosting::Hosted::load(dir.join("hosted")),
            put_off: Mutex::new(HashMap::new()),
            pending_no: Mutex::new(pending_no),
            pending_no_path,
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

    /// Tests: whether the holders of a token are let in.
    #[cfg(test)]
    pub(crate) fn admits(&self, token: &Token) -> bool {
        lock(&self.secrets).values().any(|t| t == token)
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
pub(crate) fn admit(d: &Daemon, token: &Token) {
    let mut entry = SecretEntry::new(&derive(Purpose::Token, token)[..]);
    entry.uses = None;
    let id = d.endpoint.add_secret(entry);
    lock(&d.mailbox.secrets).insert(id, *token);
}

/// Stops admitting a token, and ends what it opened.
pub(crate) fn dismiss(d: &Daemon, token: &Token) {
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

pub(crate) fn error(code: u64) -> Record {
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
    // A contact's device that hosts this person says an envelope waits.
    if r.get(0).and_then(Value::as_uint) == Some(OP_WAITING) {
        if let PeerKind::Contact(who, _) = d.classify(s) {
            crate::hosting::told_waiting(d, &who, &s.peer_static());
        }
        return Ok(());
    }
    let reply = answer(d, s, r);
    st.send_message(&Value::Record(reply)).await?;
    st.shutdown().await?;
    Ok(())
}

fn answer(d: &Daemon, s: &Session, r: &Record) -> Record {
    if !crate::outside::serving(d) {
        return error(NOT_PERMITTED);
    }
    let op = r.get(0).and_then(Value::as_uint);
    if op == Some(OP_DEPOSIT) {
        return deposit(d, r);
    }
    let device = match d.classify(s) {
        PeerKind::Own(device) => device,
        // a device of a contact this one hosts, for their own mailbox
        PeerKind::Contact(who, device) => {
            return crate::hosting::answer_owner(d, &who, &device, r)
                .unwrap_or(error(NOT_PERMITTED))
        }
        _ => return error(NOT_PERMITTED),
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
    let own = lock(&d.mailbox.store).is_active(&token);
    let left = match own {
        true => lock(&d.mailbox.store).deposit(&token, envelope, now()),
        // a token of a contact this device hosts, or none
        false => crate::hosting::deposit(d, &token, envelope, now()),
    };
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
///
/// What software does `unasked` names a device that named itself as a
/// host (D72) only where every other member is a trusted contact: its
/// address is a home address, and only they get a session with it.
async fn reach_here(
    d: &Arc<Daemon>,
    space: &SpaceId,
    named: &[Reach],
    add: Add,
    unasked: bool,
) -> Given {
    let me = d.keys.key();
    let hosts = d.core().mailboxes();
    let trusted = !unasked || d.core().among_trusted(space);
    // What the person said no to is not named unasked (D75).
    let no = match unasked {
        true => d.core().hosts_no(space),
        false => Default::default(),
    };
    let mut given = Given::default();
    if no.no_hosts {
        return given;
    }
    for (grant, device) in hosts {
        let host = *grant.link_key.x25519();
        if named.iter().any(|r| r.host == host) || (add == Add::Own && device != me) {
            continue;
        }
        if no.not_this(&host) {
            continue;
        }
        if crate::outside::is_self_named(&grant) && !trusted {
            continue;
        }
        let (token, new) = if device == me {
            own_token(d, space)
        } else {
            let token: Token = random_bytes();
            let Some(s) = d.session(&host) else {
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
            extra: Default::default(),
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
pub(crate) struct Decided {
    telling: crate::core::Telling,
    set_by: Vec<String>,
}

impl Decided {
    pub(crate) fn now(core: &crate::core::Core, space: &SpaceId) -> Decided {
        Decided {
            telling: core.telling(space),
            set_by: core.list_set_by(space),
        }
    }

    pub(crate) fn still(&self, core: &crate::core::Core, space: &SpaceId) -> bool {
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
pub(crate) fn put_off(d: &Daemon, space: &SpaceId) {
    let mut all = lock(&d.mailbox.put_off);
    let wait = match all.get(space) {
        Some(was) => (was.wait * 2).min(PUT_OFF.1),
        None => PUT_OFF.0,
    };
    let until = Instant::now() + wait;
    all.insert(*space, PutOff { until, wait });
}

/// Whether an attempt in a space is put off for now.
pub(crate) fn is_put_off(d: &Daemon, space: &SpaceId) -> bool {
    let all = lock(&d.mailbox.put_off);
    all.get(space).is_some_and(|p| Instant::now() < p.until)
}

fn me(d: &Daemon) -> anyhow::Result<[u8; 32]> {
    let me = d.core().identity.as_ref().map(|i| i.id());
    me.ok_or_else(|| anyhow::anyhow!("this device has no identity"))
}

/// The person's answer, on this device, to whether a space's members have
/// where their hosts are (`contact.md#accepting`, step 5;
/// `profiles.md#group`; D75). With `share` false it is their no: the
/// account records "no hosts here" for the space, so that no device of
/// theirs names a host there, and the list is set empty, even where it is
/// empty already. With `share` true it is their yes: the record is taken
/// out, and the list names every host of theirs that can be named now,
/// each with a token for this space; with none, nothing is written in the
/// space, and the list stays as it was, unset too. Says whether the list
/// names a host afterwards.
pub async fn say_reach(d: &Arc<Daemon>, space: &SpaceId, share: bool) -> anyhow::Result<bool> {
    let _one = d.mailbox.reaching.lock().await;
    if !share {
        say_no_locked(d, space).await?;
        return Ok(false);
    }
    let hosts = all_hosts(d);
    let chain = d.core().chain(space);
    record(d, |st| account::yes_ops(st, &chain, &hosts))?;
    pending_no(d, space, false);
    say_reach_locked(d, space, share).await
}

/// The person's no (D75): noted on this device first, then recorded in
/// the account, then the empty list written with, beside it, the account
/// entry it rests on (`relationship::set_rests_on`), so that a host of
/// theirs that has the list before the record waits for the record; and
/// the note taken out. A note left by a write that failed or a crash is
/// finished at the next look ([`write_reach`]).
async fn say_no_locked(d: &Arc<Daemon>, space: &SpaceId) -> anyhow::Result<()> {
    pending_no(d, space, true);
    let name = local_name(d, space);
    let ids = record(d, |st| account::say_no_ops(st, space, &name))?;
    let me = me(d)?;
    let mut ops = vec![relationship::set_reach(&me, &[])];
    ops.extend(ids.last().map(|a| relationship::set_rests_on(&me, a)));
    d.write_and_push(space, ops)?;
    revoke_left(d, space);
    pending_no(d, space, false);
    Ok(())
}

/// Notes, or takes out the note, that this device is writing a no in
/// `space`.
fn pending_no(d: &Daemon, space: &SpaceId, pending: bool) {
    let mut all = lock(&d.mailbox.pending_no);
    let changed = match pending {
        true => all.insert(*space),
        false => all.remove(space),
    };
    if changed {
        let list: Vec<String> = all.iter().map(hex::encode).collect();
        let bytes = serde_json::to_vec(&list).unwrap_or_default();
        if let Err(e) = write_private(&d.mailbox.pending_no_path, &bytes, 0o600) {
            tracing::warn!("cannot keep a no to finish later: {e}");
        }
    }
}

/// Whether every account entry the person's lists in `space` rest on is
/// held here (`relationship::rests_on`): until then a no the list was
/// written for may not have arrived, and no host names itself there.
pub(crate) fn record_here(core: &crate::core::Core, space: &SpaceId) -> bool {
    let (Some(me), Some(sp)) = (
        core.me(),
        core.spaces.get(space).and_then(|h| h.space.as_ref()),
    ) else {
        return false;
    };
    let wanted = relationship::rests_on(sp.state(), &me);
    if wanted.is_empty() {
        return true;
    }
    let Some(acc) = core.account().and_then(|a| a.space.as_ref()) else {
        return false;
    };
    wanted.iter().all(|e| acc.entry(e).is_some())
}

async fn say_reach_locked(d: &Arc<Daemon>, space: &SpaceId, share: bool) -> anyhow::Result<bool> {
    let me = me(d)?;
    let given = if share {
        reach_here(d, space, &[], Add::Every, false).await
    } else {
        Given::default()
    };
    let reach = given.reach;
    if share && reach.is_empty() {
        // a device writes the list when it has something to say (D75)
        return Ok(false);
    }
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

/// Every host of this person's, by static key.
fn all_hosts(d: &Daemon) -> Vec<[u8; 32]> {
    let hosts = d.core().mailboxes();
    hosts.iter().map(|(g, _)| *g.link_key.x25519()).collect()
}

/// What the account space node for a space is called, if one is made for
/// a no: the group's name, or the contact's petname.
fn local_name(d: &Daemon, space: &SpaceId) -> String {
    let core = d.core();
    if let Some(c) = core.contacts().into_iter().find(|c| c.space == *space) {
        return c.petname;
    }
    let sp = core.spaces.get(space).and_then(|h| h.space.as_ref());
    sp.map(cardinal_space::group::name).unwrap_or_default()
}

/// Writes in the account what `ops` makes of its state, if anything:
/// the person's record of a no (D75). `ops` runs under the core's lock.
fn record(
    d: &Arc<Daemon>,
    ops: impl FnOnce(&cardinal_space::State) -> Vec<cardinal_space::SpaceOp>,
) -> anyhow::Result<Vec<EntryId>> {
    let (account, ops) = {
        let core = d.core();
        let acc = core
            .account()
            .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
        let st = acc
            .space
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("the account space is not open yet"))?
            .state();
        (acc.id, ops(st))
    };
    if ops.is_empty() {
        return Ok(Vec::new());
    }
    d.write_and_push(&account, ops)
}

/// One of this person's hosts, by its device's name or the start of its
/// key in hex: its static key.
pub fn host_by_name(d: &Daemon, name: &str) -> anyhow::Result<[u8; 32]> {
    let hosts = d.core().mailboxes();
    let want = name.trim().to_lowercase();
    let found = hosts.iter().find(|(_, device)| {
        d.device_name(device).to_lowercase() == want
            || (want.len() >= 4 && hex::encode(device).starts_with(&want))
    });
    match found {
        Some((g, _)) => Ok(*g.link_key.x25519()),
        None => anyhow::bail!("{name} is not a host of yours"),
    }
}

/// The person takes one host out of a space's list by hand (D75): the
/// account records "not this host here" for it, so that it does not name
/// itself there again, and the list is written without it, the others as
/// they read. Says whether the list named it.
pub async fn take_out_host(
    d: &Arc<Daemon>,
    space: &SpaceId,
    host: &[u8; 32],
) -> anyhow::Result<bool> {
    let _one = d.mailbox.reaching.lock().await;
    let name = local_name(d, space);
    let chain = d.core().chain(space);
    let mut ids = record(d, |st| account::not_this_host_ops(st, &chain, &name, host))?;
    if ids.is_empty() {
        // recorded before: the list rests on the entry that recorded it
        let core = d.core();
        let no = core.hosts_no(space);
        let acc = core.account().and_then(|a| a.space.as_ref());
        let made = no
            .not_these
            .iter()
            .filter(|(_, h)| h == host)
            .find_map(|(n, _)| acc.and_then(|a| a.state().node(n)).map(|n| n.created_in));
        ids.extend(made);
    }
    let me = me(d)?;
    let mut reach = d.core().reach_of(space, &me);
    let before = reach.len();
    reach.retain(|r| r.host != *host);
    if reach.len() == before {
        return Ok(false);
    }
    let mut ops = vec![relationship::set_reach(&me, &reach)];
    ops.extend(ids.last().map(|a| relationship::set_rests_on(&me, a)));
    d.write_and_push(space, ops)?;
    if reach.is_empty() {
        revoke_left(d, space);
    }
    Ok(true)
}

/// Two people have just met: the relationship names this person's hosts
/// that can be named now. With none (no host, or none reachable from here
/// to register a token), nothing is written: the list stays unset, and is
/// set to the person's hosts once one can be named ([`write_reach`]). An
/// empty list would be their no, which nothing fills in
/// (`hosts.md#telling-others-where-to-reach-you`).
pub async fn on_meeting(d: &Arc<Daemon>, space: &SpaceId) -> anyhow::Result<()> {
    let _one = d.mailbox.reaching.lock().await;
    let me = me(d)?;
    let given = reach_here(d, space, &[], Add::Every, true).await;
    if given.reach.is_empty() {
        return Ok(());
    }
    let set = relationship::set_reach(&me, &given.reach);
    if let Err(e) = d.write_and_push(space, vec![set]) {
        take_back(d, &given.new).await;
        return Err(e);
    }
    Ok(())
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
    // A yes by hand clears the record of a no (D75).
    let hosts = all_hosts(d);
    let chain = d.core().chain(space);
    record(d, |st| account::yes_ops(st, &chain, &hosts))?;
    let mut reach = d.core().reach_of(space, &me);
    let given = reach_here(d, space, &reach, Add::Every, false).await;
    let more = given.reach;
    if reach.is_empty() && more.is_empty() {
        // kept against the list as it is, unset too: a device writes the
        // list when it has something to say
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
/// [`Telling`](crate::core::Telling), D75). It never names a host where
/// the person's account says "no hosts here", nor one it says "not this
/// host here" for. It never takes out a host, and never writes only to
/// make two lists one (D70).
///
/// - Where they have left and it names a host, it is emptied.
/// - Among contacts, a list never set is set, to the person's hosts,
///   which is how whoever made a space joins it; with none to name it
///   stays unset. To a list that is set, empty or not, a host adds
///   itself, after those it names: a host names itself wherever the
///   person has not said no.
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
    if lock(&d.mailbox.pending_no).contains(space) {
        // a no this device began and did not finish
        let finished = say_no_locked(d, space).await;
        if finished.is_err() {
            put_off(d, space);
        }
        return finished;
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
        let given = reach_here(d, space, &[], Add::Every, true).await;
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
    // A host names itself to a list that is set only once the account
    // holds whatever no that list rests on (D75): the two spaces may
    // arrive in either order.
    if t.set && !record_here(&d.core(), space) {
        return Ok(());
    }
    // The others as they read, each host once, unchanged. A list never
    // set is the person's joining, and names every host of theirs; to one
    // that is set a device adds only itself.
    let add = if t.set { Add::Own } else { Add::Every };
    let given = reach_here(d, space, &named, add, true).await;
    let more = given.reach;
    // A host that cannot be reached now gives no token, and with nothing
    // to add nothing is written: an empty list written for want of a host
    // would look like a no. Whoever made a space and has a host out of
    // reach is named once it can be, at a later look.
    if !t.worth_saying(more.len()) {
        return Ok(());
    }
    let mut reach = named;
    reach.extend(more);
    set_as_decided(d, space, &decided, &reach, &given.new).await?;
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
/// Takes a device the person removed out of every list that names it
/// (`hosts.md`: an entry stays "until that device, or the person, takes it
/// out"). A lost host never takes itself out, and while it is named,
/// contacts go on leaving messages with whoever holds it. Each list is
/// written as it reads, without that entry, if nothing it rests on has
/// changed since. One left empty is no no (D75): the account records
/// none, and another host of the person's may name itself there.
pub fn take_out_removed(d: &Arc<Daemon>, gone: &[u8; 32]) {
    let Some(me) = d.core().identity.as_ref().map(|i| i.id()) else {
        return;
    };
    let named: Vec<SpaceId> = {
        let core = d.core();
        let names = |id: &&SpaceId| core.reach_of(id, &me).iter().any(|r| r.host == *gone);
        core.spaces.keys().filter(names).copied().collect()
    };
    for space in named {
        let (reach, decided) = {
            let core = d.core();
            let mut reach = core.reach_of(&space, &me);
            reach.retain(|r| r.host != *gone);
            (reach, Decided::now(&core, &space))
        };
        let set = relationship::set_reach(&me, &reach);
        let written = d.write_and_push_if(&space, vec![set], |core| decided.still(core, &space));
        if !matches!(written, Ok(Some(_))) {
            tracing::warn!(
                "{} still names a removed device",
                crate::core::short(&space)
            );
        }
    }
}

pub fn keep_own_entry(d: &Arc<Daemon>) {
    let host = crate::outside::serving(d);
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
        // one made for an entry that is taken out instead is not given
        new.retain(|t| reach.iter().any(|r| r.token == *t));
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
    // The newest of what fits goes inside envelopes, a short burst as one
    // envelope each, so that it reaches them even if this device is gone
    // by the time they look. Anything else is told of by one heads
    // message, to fetch from whoever has it: this person's host, or
    // another member's (`hosts.md#mailbox`), or from this device when the
    // two next meet.
    let sealed: Vec<_> = unsent
        .iter()
        .map(|(id, entry)| (*id, seal(&epoch, &key, &entry[..])))
        .collect();
    let (carry, told) = to_carry(sealed);
    let left = leave(d, &reach, &carry).await;
    d.mailbox.mark_sent(space, member, &left);
    if told.is_empty() {
        return;
    }
    let mut ids = d.core().heads(space);
    ids.truncate(MAX_HEADS);
    let heads = Message::Heads { label: *space, ids };
    let notice = (told[0], seal(&epoch, &key, to_value(&heads)));
    if !leave(d, &reach, &[notice]).await.is_empty() {
        d.mailbox.mark_sent(space, member, &told);
    }
}

/// Of entries sealed into envelopes, in log order: those to carry inside
/// envelopes, the newest that fit, at most [`LEAVE_AT_ONCE`], still in log
/// order; and those a heads message tells of instead, the ones too long
/// for an envelope and anything older that fits but is not carried.
fn to_carry(sealed: Vec<(EntryId, Vec<u8>)>) -> (Vec<(EntryId, Vec<u8>)>, Vec<EntryId>) {
    let (mut carry, mut told): (Vec<_>, Vec<_>) = sealed
        .into_iter()
        .partition(|(_, envelope)| envelope.len() <= MAX_ENVELOPE);
    let older = carry.len().saturating_sub(LEAVE_AT_ONCE);
    told.extend(carry.drain(..older));
    (carry, told.into_iter().map(|(id, _)| id).collect())
}

/// Delivers what this device wrote to each member it has no session with.
async fn deliver(d: &Arc<Daemon>) {
    keep_own_entry(d);
    crate::presence::keep(d);
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
    if !crate::outside::serving(d) {
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

/// Collects this person's mailbox at a contact's device that hosts them
/// (D87), over the session `s` with it: each envelope is taken in as one
/// at a host of their own, and the host is told how far everything is
/// taken. One that cannot be taken in yet holds back the acknowledgment of
/// those after it, which are fetched again and taken in again, at no harm.
/// Gives how many were taken in, and whether any is held back so.
pub(crate) async fn collect_at(d: &Arc<Daemon>, s: &Session) -> anyhow::Result<(usize, bool)> {
    let mut after = 0;
    let mut acked = None;
    let mut blocked = false;
    let mut taken = 0;
    loop {
        let asked = after;
        let ask = Record::new().with(0, OP_FETCH).with(1, after);
        let reply = call(s, Service::MAILBOX, ask).await?;
        anyhow::ensure!(
            reply.get(0).and_then(Value::as_uint) == Some(OP_FETCH),
            "the host did not let this device fetch"
        );
        let list = reply.record_list(1).unwrap_or_default();
        for r in &list {
            let sequence = r.get(1).and_then(Value::as_uint);
            let token = read_token(r.get(2));
            let envelope = r.get(3).and_then(Value::as_bytes);
            let (Some(sequence), Some(token), Some(envelope)) = (sequence, token, envelope) else {
                continue;
            };
            let held = Held {
                sequence,
                token,
                at: now(),
                envelope: envelope.to_vec(),
            };
            after = after.max(sequence);
            match take_in(d, &held).await {
                Taken::Done if !blocked => {
                    acked = Some(sequence);
                    taken += 1;
                }
                Taken::Done => taken += 1,
                Taken::NotYet => blocked = true,
            }
        }
        let more = reply.get(2).and_then(Value::as_bool) == Some(true);
        // A host that says there is more and gives nothing past what it
        // gave is not asked again.
        if list.is_empty() || !more || after <= asked {
            break;
        }
    }
    if let Some(sequence) = acked {
        call(
            s,
            Service::MAILBOX,
            Record::new().with(0, OP_ACK).with(1, sequence),
        )
        .await?;
    }
    Ok((taken, blocked))
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
    let found = d.core().envelope_space(&held.token, &epoch);
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
    crate::hosting::start(d.clone());
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

    /// The newest that fit are carried, in log order; what is too long, and
    /// anything older past what one look leaves, is told of by a notice.
    #[test]
    fn the_newest_that_fit_are_carried_and_the_rest_told_of() {
        let entry = |n: u8, len: usize| ([n; 32], vec![0; len]);
        let (carry, told) = to_carry(vec![entry(1, 100), entry(2, 2000), entry(3, 200)]);
        let ids: Vec<EntryId> = carry.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![[1; 32], [3; 32]]);
        assert_eq!(told, vec![[2; 32]]);

        let burst: Vec<_> = (0..LEAVE_AT_ONCE as u8 + 3).map(|n| entry(n, 50)).collect();
        let (carry, told) = to_carry(burst);
        assert_eq!(carry.len(), LEAVE_AT_ONCE);
        assert_eq!(carry[0].0, [3; 32]);
        assert_eq!(carry.last().unwrap().0, [LEAVE_AT_ONCE as u8 + 2; 32]);
        assert_eq!(told, vec![[0; 32], [1; 32], [2; 32]]);
    }

    #[test]
    fn a_reach_node_fits_in_an_envelope() {
        let reach = Reach {
            endpoints: vec![Endpoint::parse("203.0.113.9:7171").unwrap(); 2],
            host: [1; 32],
            token: [2; 16],
            extra: Default::default(),
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
            extra: Default::default(),
        };
        let mut reach = vec![
            Reach {
                endpoints: vec![home.clone()],
                host: [1; 32],
                token: T,
                extra: Default::default(),
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
            extra: Default::default(),
        };
        let old = Endpoint::parse("172.20.1.20:7171").unwrap();
        let now = [Endpoint::parse("203.0.113.9:7171").unwrap()];
        let here = Reach {
            endpoints: vec![old],
            host: [1; 32],
            token: T,
            extra: Default::default(),
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

    fn hosted_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::load(dir.path().join("hosted")).until_collected();
        s.register(&T);
        (dir, s)
    }

    /// Review H2. For a contact this device hosts, an envelope waits until
    /// collected, but not for a device that stopped fetching: after 30
    /// days without a fetch it holds nothing up.
    #[test]
    fn a_hosted_device_that_stops_fetching_holds_nothing_up() {
        let (_dir, mut s) = hosted_store();
        s.fetch(&LAPTOP, 0, 1);
        s.fetch(&PHONE, 0, 1);
        let first = s.deposit(&T, b"x", 1).unwrap();
        s.ack(&PHONE, first, 2);
        assert_eq!(s.waiting(), 1, "the laptop has not collected it");
        // still waiting for anyone after the retention of an own host
        let later = 1 + RETENTION + DAY;
        assert_eq!(s.fetch(&PHONE, 0, later - FETCHER_GONE + 10).0.len(), 1);
        let next = s.deposit(&T, b"y", later).unwrap();
        s.ack(&PHONE, next, later);
        assert_eq!(s.waiting(), 0, "the laptop, silent 30 days, held it up");
    }

    /// Review H2. A device taken out of the owner's log holds nothing up.
    #[test]
    fn a_device_out_of_the_log_holds_nothing_up() {
        let (_dir, mut s) = hosted_store();
        s.fetch(&LAPTOP, 0, 1);
        s.fetch(&PHONE, 0, 1);
        let sequence = s.deposit(&T, b"x", 1).unwrap();
        s.ack(&PHONE, sequence, 2);
        assert_eq!(s.waiting(), 1);
        s.keep_fetchers(&HashSet::from([PHONE]), 3);
        assert_eq!(s.waiting(), 0);
    }

    /// Review M6. For a contact this device hosts, the quota counts all
    /// their tokens together: more tokens are not more room.
    #[test]
    fn a_hosted_quota_counts_every_token_together() {
        let (_dir, mut s) = hosted_store();
        s.register(&OTHER);
        let limits = (Some(2), Some(3));
        assert!(s.deposit_within(&T, b"x", 1, limits).is_ok());
        assert!(s.deposit_within(&OTHER, b"x", 1, limits).is_ok());
        assert_eq!(
            s.deposit_within(&OTHER, b"x", 1, limits),
            Err(Refused::Full)
        );
        assert_eq!(s.deposit_within(&T, b"x", 1, limits), Err(Refused::Full));
        // collected, there is room again within the day's count
        s.fetch(&PHONE, 0, 1);
        s.ack(&PHONE, 2, 1);
        assert!(s.deposit_within(&T, b"x", 1, limits).is_ok());
        s.ack(&PHONE, 3, 1);
        assert_eq!(
            s.deposit_within(&OTHER, b"x", 1, limits),
            Err(Refused::Full)
        );
        assert!(s.deposit_within(&OTHER, b"x", 1 + DAY, limits).is_ok());
        // an own host's store counts each token alone
        let (_d2, mut own) = store();
        own.register(&OTHER);
        assert!(own.deposit_within(&T, b"x", 1, (Some(1), None)).is_ok());
        assert!(own.deposit_within(&OTHER, b"x", 1, (Some(1), None)).is_ok());
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
            extra: Default::default(),
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
        // CARDINAL_VECTORS names the folder where a test runs away from
        // the source (on another system).
        let path = std::env::var_os("CARDINAL_VECTORS")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
            })
            .join("mailbox.json");
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

        /// The router gives this device `at` outside, and it names itself
        /// there (D72), as the port mapping loop has it do.
        fn router_gives(&self, at: &str) {
            let m = crate::portmap::Mapping {
                protocol: crate::portmap::Protocol::Pcp,
                external: at.parse().unwrap(),
                internal_port: 7171,
                lifetime: 7200,
            };
            lock(&self.d.portmap).mapping = Some((m, Instant::now()));
            // held long enough, and a day after the last new one
            {
                let mut o = lock(&self.d.outside);
                o.seen = Some((at.parse().unwrap(), 0));
                o.last_new = 0;
            }
            crate::outside::tick(&self.d);
        }

        fn trusts_bo(&self, trusted: bool) {
            use cardinal_space::account;
            let account = self.d.core().account_id().unwrap();
            let node = self.d.core().contacts()[0].node;
            let set = account::set_field(node, account::TRUSTED, trusted);
            self.d.write_and_push(&account, vec![set]).unwrap();
        }

        fn entries(&self, space: &SpaceId) -> usize {
            self.d.core().entries_by(space, &self.d.keys.key()).len()
        }

        fn endpoints(&self, space: &SpaceId) -> Vec<String> {
            let named = self.named(space);
            let here = named.iter().find(|r| r.host == self.here);
            here.map(|r| r.endpoints.iter().map(|e| e.to_string()).collect())
                .unwrap_or_default()
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

    /// D72. A device the router gives an address outside names itself in
    /// a relationship with a trusted contact, and not with one who is
    /// not; with no host to name, the list stays unset, not empty.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_device_that_can_be_reached_names_itself_only_among_the_trusted() {
        let h = Home::new().await;
        h.trusts_bo(false);
        // no host at all: an empty list would be a no
        write_reach(&h.d, &h.rel).await.unwrap();
        assert!(
            !h.d.core().reach_is_set(&h.rel, &h.me),
            "an empty list was written"
        );
        // a LAN address is never named
        h.router_gives("192.168.1.5:7171");
        assert!(crate::outside::named(&h.d).is_empty());
        h.router_gives("203.0.113.5:60001");
        assert!(crate::outside::serving(&h.d));
        let grant = crate::host::own_grant(&h.d).unwrap();
        assert!(crate::outside::is_self_named(&grant), "it offers storage");
        on_meeting(&h.d, &h.rel).await.unwrap();
        write_reach(&h.d, &h.rel).await.unwrap();
        assert!(
            h.named(&h.rel).is_empty(),
            "named for a contact not trusted"
        );
        assert!(!h.d.core().reach_is_set(&h.rel, &h.me));
        h.trusts_bo(true);
        write_reach(&h.d, &h.rel).await.unwrap();
        assert_eq!(h.endpoints(&h.rel), ["203.0.113.5:60001"]);
        // It is not on the recovery sheet: no restore comes from it.
        assert_eq!(
            crate::host::sheet(&h.d).unwrap()["hosts"],
            serde_json::json!([])
        );
    }

    /// D72. Where the list is empty, it was the person's no: a device that
    /// named itself does not add itself there, in a relationship either.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_device_that_named_itself_leaves_an_empty_list_alone() {
        let h = Home::new().await;
        say_reach(&h.d, &h.rel, false).await.unwrap();
        h.router_gives("203.0.113.5:60001");
        write_reach(&h.d, &h.rel).await.unwrap();
        assert!(h.named(&h.rel).is_empty(), "it filled in a no");
        keep_own_entry(&h.d);
        assert!(h.named(&h.rel).is_empty());
        // the person's yes names it
        assert!(matches!(
            share_reach(&h.d, &h.rel).await.unwrap(),
            Shared::Named
        ));
        assert_eq!(h.endpoints(&h.rel), ["203.0.113.5:60001"]);

        // In a group of trusted contacts it joins a list that names a host,
        // and not one that names none.
        let h = Home::new().await;
        let g = h.group();
        say_reach(&h.d, &g, false).await.unwrap();
        h.router_gives("203.0.113.5:60001");
        write_reach(&h.d, &g).await.unwrap();
        assert!(h.named(&g).is_empty(), "it filled in a no");
        let g2 = h.group();
        write_reach(&h.d, &g2).await.unwrap();
        assert_eq!(h.endpoints(&g2), ["203.0.113.5:60001"], "joining names it");
        // and not where someone is not trusted
        let h = Home::new().await;
        h.trusts_bo(false);
        h.router_gives("203.0.113.5:60001");
        let g = h.group();
        write_reach(&h.d, &g).await.unwrap();
        assert!(h.named(&g).is_empty(), "named among the untrusted");
    }

    /// D72. Where a member stops being trusted, a device that named
    /// itself gives no new address there: it takes itself out instead.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_device_that_named_itself_leaves_a_space_no_longer_trusted() {
        let h = Home::new().await;
        h.router_gives("203.0.113.5:60001");
        write_reach(&h.d, &h.rel).await.unwrap();
        assert_eq!(h.endpoints(&h.rel), ["203.0.113.5:60001"]);
        h.trusts_bo(false);
        // nothing new: the entry stays, the person's agreement stands
        keep_own_entry(&h.d);
        assert_eq!(h.endpoints(&h.rel), ["203.0.113.5:60001"]);
        h.router_gives("198.51.100.7:7171");
        assert!(
            h.named(&h.rel).is_empty(),
            "a new address went to the untrusted"
        );
        assert!(h.active().is_empty(), "a token is left");
    }

    /// D72. A new address is written where the device is named, newest
    /// first and three at most; a renewal, or an address that comes back,
    /// writes nothing; turned off, it takes itself out.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_device_that_named_itself_writes_only_for_a_new_address() {
        let h = Home::new().await;
        h.router_gives("203.0.113.5:60001");
        write_reach(&h.d, &h.rel).await.unwrap();
        assert_eq!(h.endpoints(&h.rel), ["203.0.113.5:60001"]);
        let account = h.d.core().account_id().unwrap();
        let (rel, acc) = (h.entries(&h.rel), h.entries(&account));
        h.router_gives("203.0.113.5:60001");
        write_reach(&h.d, &h.rel).await.unwrap();
        keep_own_entry(&h.d);
        assert_eq!(h.entries(&h.rel), rel, "a renewal was written");
        assert_eq!(h.entries(&account), acc);
        for at in ["198.51.100.7:7171", "192.0.2.9:4000", "203.0.113.77:1"] {
            h.router_gives(at);
        }
        assert_eq!(
            h.endpoints(&h.rel),
            ["203.0.113.77:1", "192.0.2.9:4000", "198.51.100.7:7171"]
        );
        let rel = h.entries(&h.rel);
        h.router_gives("198.51.100.7:7171");
        assert_eq!(h.entries(&h.rel), rel, "written to reorder");
        // turned off: out of the list, and no host
        h.d.config().port_mapping = false;
        crate::outside::tick(&h.d);
        assert!(h.named(&h.rel).is_empty());
        assert!(!crate::outside::serving(&h.d));
        assert!(crate::host::own_grant(&h.d).is_none());
        assert!(h.active().is_empty(), "its token is left");
    }

    /// Meeting someone with no host to name leaves the list unset, not
    /// empty: an empty list is a no, which nothing fills in. Found on the
    /// home network, 2026-11-19: a relationship made while no host could be
    /// named never named the host the person had.
    #[tokio::test(flavor = "multi_thread")]
    async fn meeting_with_no_host_to_name_leaves_the_list_for_later() {
        let h = Home::new().await;
        on_meeting(&h.d, &h.rel).await.unwrap();
        assert!(
            !h.d.core().reach_is_set(&h.rel, &h.me),
            "an empty list was written"
        );
        // Nor by the delivery pass after, with still nothing to name.
        write_reach(&h.d, &h.rel).await.unwrap();
        assert!(
            !h.d.core().reach_is_set(&h.rel, &h.me),
            "a pass wrote an empty list"
        );
        h.hosts();
        write_reach(&h.d, &h.rel).await.unwrap();
        let named = h.named(&h.rel);
        assert_eq!(named.len(), 1, "the host is named once there is one");
        assert_eq!(named[0].host, h.here);

        // In a relationship, a host adds itself even to a list emptied
        // before; and the person's yes names every host of theirs.
        let h2 = Home::new().await;
        say_reach(&h2.d, &h2.rel, true).await.unwrap();
        h2.hosts();
        write_reach(&h2.d, &h2.rel).await.unwrap();
        assert_eq!(h2.named(&h2.rel).len(), 1, "the host adds itself");
        say_reach(&h2.d, &h2.rel, false).await.unwrap();
        assert!(h2.named(&h2.rel).is_empty());
        assert!(matches!(
            share_reach(&h2.d, &h2.rel).await.unwrap(),
            Shared::Named
        ));
        assert_eq!(h2.named(&h2.rel).len(), 1, "a yes names it");

        // With a host already, meeting names it at once.
        let h = Home::new().await;
        h.hosts();
        on_meeting(&h.d, &h.rel).await.unwrap();
        assert_eq!(h.named(&h.rel).len(), 1);
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
                // as a no is said (D75): the record, then the list
                let account = d.core().account_id().unwrap();
                let record = {
                    let core = d.core();
                    let st = core.account().unwrap().space.as_ref().unwrap().state();
                    account::say_no_ops(st, &space, "a space")
                };
                d.core().write(&account, record).unwrap();
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
        let empty = relationship::set_reach(&h.me, &[]);
        h.d.write_and_push(&g, vec![empty]).unwrap();
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
        let empty = relationship::set_reach(&h.me, &[]);
        h.d.write_and_push(&g, vec![empty]).unwrap();
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

    /// The presence secret this person gives Bo, as his device reads it.
    fn given(h: &Home) -> Vec<[u8; 32]> {
        let core = h.d.core();
        let sp = core.spaces[&h.rel].space.as_ref().unwrap();
        relationship::presence_of(sp.state(), &h.me)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_trusted_contact_is_given_the_presence_secret_and_one_trusted_no_longer_is_not() {
        let h = Home::new().await;
        assert!(crate::presence::current(&h.d.core()).is_none());
        crate::presence::keep(&h.d);
        let first = crate::presence::current(&h.d.core()).expect("made for Bo");
        assert_eq!(given(&h), [first]);
        assert_eq!(crate::presence::advertised(&h.d.core()), Some(first));
        // Nothing more to do.
        let n = h.entries(&h.rel);
        crate::presence::keep(&h.d);
        assert_eq!(h.entries(&h.rel), n);
        // Trusted no longer: a new secret, which he is not given; and with
        // nobody trusted, nothing is advertised.
        h.trusts_bo(false);
        crate::presence::keep(&h.d);
        let second = crate::presence::current(&h.d.core()).unwrap();
        assert_ne!(second, first);
        assert_eq!(crate::presence::secrets(&h.d.core()).len(), 1);
        assert!(given(&h).is_empty(), "the one he had is not taken back");
        assert_eq!(crate::presence::advertised(&h.d.core()), None);
        // The old one he has is not in use: no new one at every look.
        crate::presence::keep(&h.d);
        assert_eq!(crate::presence::current(&h.d.core()), Some(second));
        // Trusted again, he is given the one in use.
        h.trusts_bo(true);
        crate::presence::keep(&h.d);
        assert_eq!(given(&h), [second]);
        assert_eq!(crate::presence::current(&h.d.core()), Some(second));
        // Of two made at once, the one with the lowest node id is used,
        // and given where the other was.
        let account = h.d.core().account_id().unwrap();
        let op = crate::core::create_secret(crate::presence::PURPOSE, &[9; 32]);
        h.d.write_and_push(&account, vec![op]).unwrap();
        let all = crate::presence::secrets(&h.d.core());
        assert_eq!(all.len(), 2);
        let lowest = all.iter().min().unwrap().1;
        crate::presence::keep(&h.d);
        assert_eq!(crate::presence::current(&h.d.core()), Some(lowest));
        assert_eq!(given(&h), [lowest]);
    }

    /// Review L3. Someone given the secret in a relationship that can no
    /// longer be written in (left, here) and then trusted no longer: the
    /// secret they hold is renewed all the same.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_secret_given_where_nothing_more_is_written_is_still_renewed() {
        let h = Home::new().await;
        crate::presence::keep(&h.d);
        let first = crate::presence::current(&h.d.core()).unwrap();
        h.d.write_and_push(&h.rel, vec![cardinal_space::SpaceOp::leave()])
            .unwrap();
        h.trusts_bo(false);
        crate::presence::keep(&h.d);
        assert_ne!(crate::presence::current(&h.d.core()), Some(first));
        assert_eq!(given(&h), [first], "nothing is written where they left");
    }

    /// Review L4. Two contact nodes for one person, made at once on two
    /// devices, one of them no longer trusting him: he is not trusted, and
    /// is not given the secret.
    #[tokio::test(flavor = "multi_thread")]
    async fn two_nodes_for_one_contact_are_one_contact() {
        use cardinal_space::account::{self, Regard};
        let h = Home::new().await;
        crate::presence::keep(&h.d);
        let first = crate::presence::current(&h.d.core()).unwrap();
        assert_eq!(given(&h), [first]);
        let account = h.d.core().account_id().unwrap();
        let them = h.bo.me().unwrap();
        let hosts_only = Regard {
            trusted: false,
            introductions: true,
        };
        let twin = account::create_contact(&them, "Bo", &h.rel, hosts_only);
        h.d.write_and_push(&account, vec![twin]).unwrap();
        assert_eq!(h.d.core().contacts().len(), 2);
        crate::presence::keep(&h.d);
        assert_ne!(crate::presence::current(&h.d.core()), Some(first));
        assert!(given(&h).is_empty());
        assert!(crate::presence::of_contacts(&h.d.core()).is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_presence_secret_leaves_the_list_of_hosts_as_it_is() {
        let h = Home::new().await;
        assert!(!h.d.core().reach_is_set(&h.rel, &h.me));
        crate::presence::keep(&h.d);
        assert_eq!(given(&h).len(), 1);
        assert!(
            !h.d.core().reach_is_set(&h.rel, &h.me),
            "field 2 is not field 1"
        );
    }

    #[test]
    fn a_host_entry_keeps_fields_this_version_does_not_know() {
        let mut extra = Record::new();
        extra.insert(9, "from later");
        let reach = Reach {
            endpoints: vec![Endpoint::parse("203.0.113.9:7171").unwrap()],
            host: [4; 32],
            token: [5; 16],
            extra,
        };
        let op = relationship::set_reach(&[6; 32], std::slice::from_ref(&reach));
        let list = op.record().get(3).unwrap().as_list().unwrap();
        let entry = list[0].as_record().unwrap();
        assert_eq!(entry.get(9).and_then(Value::as_text), Some("from later"));
        assert_eq!(entry.get(2).and_then(Value::as_bytes), Some(&[4u8; 32][..]));
    }

    impl Home {
        fn record(&self, space: &SpaceId) -> account::HostsNo {
            self.d.core().hosts_no(space)
        }
    }

    /// D75. A no is recorded in the account, and an explicit host does not
    /// name itself over it, at any look; a yes by hand takes it out.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_no_stands_against_an_explicit_host() {
        let h = Home::new().await;
        h.hosts();
        say_reach(&h.d, &h.rel, false).await.unwrap();
        assert!(h.record(&h.rel).no_hosts, "the no is not recorded");
        assert!(h.d.core().reach_is_set(&h.rel, &h.me));
        for _ in 0..2 {
            write_reach(&h.d, &h.rel).await.unwrap();
            keep_own_entry(&h.d);
            assert!(h.named(&h.rel).is_empty(), "a host named itself over a no");
        }
        assert!(matches!(
            share_reach(&h.d, &h.rel).await.unwrap(),
            Shared::Named
        ));
        assert_eq!(h.named(&h.rel).len(), 1);
        assert!(!h.record(&h.rel).no_hosts, "a yes leaves the no");
    }

    /// D75. A list emptied with no no recorded, as by the bug of
    /// 2026-11-19, is not a no: a host fills it in itself.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_emptied_list_with_no_record_is_filled_by_a_host() {
        let h = Home::new().await;
        h.hosts();
        let empty = relationship::set_reach(&h.me, &[]);
        h.d.write_and_push(&h.rel, vec![empty]).unwrap();
        assert!(h.d.core().reach_is_set(&h.rel, &h.me));
        assert!(!h.record(&h.rel).no_hosts);
        write_reach(&h.d, &h.rel).await.unwrap();
        let named = h.named(&h.rel);
        assert_eq!(named.len(), 1, "the host did not name itself");
        assert_eq!(named[0].host, h.here);
        // In a group too, where the person made it among contacts.
        let g = h.group();
        let empty = relationship::set_reach(&h.me, &[]);
        h.d.write_and_push(&g, vec![empty]).unwrap();
        write_reach(&h.d, &g).await.unwrap();
        assert_eq!(h.named(&g).len(), 1);
    }

    /// D75. A host taken out by hand stays out: the account says "not
    /// this host here" for it, until the person says yes.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_host_taken_out_by_hand_stays_out() {
        let h = Home::new().await;
        h.hosts();
        write_reach(&h.d, &h.rel).await.unwrap();
        assert_eq!(h.named(&h.rel).len(), 1);
        let here = h.here;
        assert!(take_out_host(&h.d, &h.rel, &here).await.unwrap());
        assert!(h.record(&h.rel).not_this(&here));
        assert!(!h.record(&h.rel).no_hosts, "not a no to every host");
        for _ in 0..2 {
            write_reach(&h.d, &h.rel).await.unwrap();
            keep_own_entry(&h.d);
            assert!(h.named(&h.rel).is_empty(), "it named itself again");
        }
        // Taken out again, nothing more is recorded.
        let account = h.d.core().account_id().unwrap();
        let n = h.entries(&account);
        assert!(!take_out_host(&h.d, &h.rel, &here).await.unwrap());
        assert_eq!(h.entries(&account), n);
        assert!(matches!(
            share_reach(&h.d, &h.rel).await.unwrap(),
            Shared::Named
        ));
        assert_eq!(h.named(&h.rel).len(), 1);
        assert!(!h.record(&h.rel).not_this(&here), "a yes leaves it out");
        // A device not a host of theirs cannot be taken out by name.
        assert!(host_by_name(&h.d, "nobody").is_err());
    }

    /// D75. Whoever made a group, with no host to name, leaves the list
    /// unset, not empty; a host they take up later names itself there.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_group_with_no_host_to_name_is_left_unset() {
        let h = Home::new().await;
        let g = h.group();
        write_reach(&h.d, &g).await.unwrap();
        assert!(
            !h.d.core().reach_is_set(&g, &h.me),
            "an empty list was written"
        );
        // A yes by hand with no host to reach writes no empty list either.
        say_reach(&h.d, &g, true).await.unwrap();
        assert!(!h.d.core().reach_is_set(&g, &h.me));
        h.hosts();
        write_reach(&h.d, &g).await.unwrap();
        assert_eq!(h.named(&g).len(), 1);
    }

    /// D81. The field is the spec's `no record`, whose key differs from
    /// the `no-record` this implementation wrote before (an extension's key
    /// is the first 7 bytes of its name): a list emptied by an older
    /// device, resting on a record under the old name, still waits for it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_no_record_under_the_old_name_is_still_read() {
        assert_ne!(
            relationship::no_record_key(),
            relationship::old_no_record_key()
        );
        assert_eq!(
            relationship::no_record_key().to_be_bytes()[1..],
            *b"no reco"
        );
        let h = Home::new().await;
        h.hosts();
        let elsewhere = [9u8; 32];
        let v = Value::Record(Record::new().with(1, elsewhere));
        let old = cardinal_space::SpaceOp::set(
            cardinal_space::reach_node_id(&h.me),
            relationship::old_no_record_key(),
            Some(v),
        );
        let ops = vec![relationship::set_reach(&h.me, &[]), old];
        h.d.write_and_push(&h.rel, ops).unwrap();
        {
            let core = h.d.core();
            let sp = core.spaces[&h.rel].space.as_ref().unwrap();
            assert_eq!(relationship::rests_on(sp.state(), &h.me), vec![elsewhere]);
        }
        for _ in 0..2 {
            write_reach(&h.d, &h.rel).await.unwrap();
            assert!(h.named(&h.rel).is_empty(), "filled in before the record");
        }
        // What this device writes is under the spec's name.
        say_reach(&h.d, &h.rel, false).await.unwrap();
        let core = h.d.core();
        let sp = core.spaces[&h.rel].space.as_ref().unwrap();
        assert!(!sp
            .state()
            .reach_values(&h.me, relationship::no_record_key())
            .is_empty());
    }

    /// D75, review H1. Another of the person's devices says no: its empty
    /// list reaches this host before the account entry that records the
    /// no (as through a contact, while the host and the phone are not
    /// connected). The list says what it rests on, and the host waits for
    /// that entry, however long; with it here and no no in it, it names
    /// itself.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_no_whose_record_is_still_on_its_way_is_not_filled_in() {
        let h = Home::new().await;
        h.hosts();
        let elsewhere = [9u8; 32];
        let ops = vec![
            relationship::set_reach(&h.me, &[]),
            relationship::set_rests_on(&h.me, &elsewhere),
        ];
        h.d.write_and_push(&h.rel, ops).unwrap();
        for _ in 0..3 {
            write_reach(&h.d, &h.rel).await.unwrap();
            assert!(h.named(&h.rel).is_empty(), "filled in before the record");
        }
        // The entry it rests on is here, and records no no: then the list
        // was emptied by mistake, and fills itself again.
        let account = h.d.core().account_id().unwrap();
        let node = h.d.core().contacts()[0].node;
        let here =
            h.d.write_and_push(
                &account,
                vec![account::set_field(node, account::CATEGORY, "Family")],
            )
            .unwrap();
        let ops = vec![relationship::set_rests_on(&h.me, &here[0])];
        h.d.write_and_push(&h.rel, ops).unwrap();
        write_reach(&h.d, &h.rel).await.unwrap();
        assert_eq!(h.named(&h.rel).len(), 1);
        // A no said here rests on its own record, which is here at once.
        say_reach(&h.d, &h.rel, false).await.unwrap();
        let core = h.d.core();
        let sp = core.spaces[&h.rel].space.as_ref().unwrap();
        let on = relationship::rests_on(sp.state(), &h.me);
        assert_eq!(on.len(), 1);
        assert!(core
            .account()
            .unwrap()
            .space
            .as_ref()
            .unwrap()
            .entry(&on[0])
            .is_some());
    }

    /// D75, review L5. A no this device began and could not finish (the
    /// list was not written) is finished at the next look.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_no_left_unfinished_is_finished_at_the_next_look() {
        let h = Home::new().await;
        h.hosts();
        write_reach(&h.d, &h.rel).await.unwrap();
        assert_eq!(h.named(&h.rel).len(), 1);
        pending_no(&h.d, &h.rel, true);
        write_reach(&h.d, &h.rel).await.unwrap();
        assert!(h.named(&h.rel).is_empty(), "the no was not finished");
        assert!(h.record(&h.rel).no_hosts);
        assert!(lock(&h.d.mailbox.pending_no).is_empty());
        // and the note survives a restart: it is kept beside the mailbox
        pending_no(&h.d, &h.rel, true);
        let saved = std::fs::read(&h.d.mailbox.pending_no_path).unwrap();
        assert!(String::from_utf8_lossy(&saved).contains(&hex::encode(h.rel)));
        pending_no(&h.d, &h.rel, false);
    }

    /// Review M1. A contact's tag replayed at many addresses costs a few
    /// tries a minute and no more: the looks through hosts are left free,
    /// and their trail is not overwritten.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_replayed_tag_costs_a_few_tries_and_no_look() {
        let h = Home::new().await;
        let bo = h.bo.me().unwrap();
        for port in 1..=6u16 {
            let at: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            crate::rendezvous::found_nearby(&h.d, bo, at).await;
        }
        let trail = h.d.rendezvous.trail(&bo);
        assert_eq!(trail.nearby.len(), 3, "{:?}", trail.nearby);
        assert!(trail.look.is_empty(), "a look was overwritten");
        assert_eq!(trail.looks, 0);
        assert!(!h.d.rendezvous.looked(&bo).1, "the look slot was taken");
    }
}
