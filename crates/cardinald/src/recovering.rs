//! A new device recovering an identity through its guardians
//! (`identity.md#how-guardians-act`, `hosts.md#restore`, D77), for a person
//! who lost every admin device and the recovery words. No sheet is needed.
//!
//! 1. `cardinal recover start [CODE] [--key KEY]`: the device makes new
//!    words, and so a new root and recovery key, and a recovery helper
//!    (`helper.rs`). With CODE, a guardian's recovery invitation, the
//!    helper meets that guardian in a relationship of its own; the person
//!    brings each guardian's the same way. `cardinal recover invite`
//!    makes one for a guardian to take up instead, where the two are
//!    together. Through each relationship the guardian's device proposes
//!    parents, the policy and the person's hosts, and carries the person's
//!    log. On the first proposal this device signs the `recover`, naming
//!    its own link key to receive shares, keeping those of the proposed
//!    hosts the person's log names as their devices (and the host whose
//!    sheet key the person gave, if any), and removing every other key.
//!    It then carries the same `recover` to every guardian, and each
//!    guardian's acts to the others, for as long as the recovery is under
//!    way.
//! 2. The person reads the fingerprint to each guardian, who endorse, wait,
//!    and confirm (`guardians.rs`).
//! 3. `cardinal recover finish`: once the recovery is in effect, through a
//!    kept host as a restore from the words does (`prove` with the new
//!    root), or, with no host, from the log the guardians carried: this
//!    device adds itself with the root, rebuilds the guardian key from the
//!    shares sealed to it and opens the encryption key, and sets a fresh
//!    one. It shows the new words. The helper is dropped.
//!
//! What it holds meanwhile, the new words above all, is kept in
//! `recovering.json`, readable by this user only, until it is done.
//! Afterwards `recovered.json` keeps the hosts the recovery kept and when
//! each was last heard from, so that one lost with everything else is
//! seen and removed first.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cardinal_crypto::{HybridPublicKey, RecoveryPhrase};
use cardinal_identity::guardians::fingerprint;
use cardinal_identity::{EntryBuilder, EntryId, IdentityEntry, IdentityLog, IdentityOp, KeyId};
use cardinal_space::account::{self, Regard};
use cardinal_space::relationship::{self, Proposal, ProposedHost};
use cardinal_space::SpaceId;
use cardinal_sync::identity_log_label;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};

use crate::core::now_ms;
use crate::daemon::{Daemon, PairState};
use crate::helper::Helper;
use crate::net::{self, Access};

/// A recovery under way on this device.
#[derive(Serialize, Deserialize)]
struct Under {
    /// The new recovery words.
    words: String,
    /// The identity recovered (hex), once a guardian's invitation or the
    /// person named it.
    identity: Option<String>,
    /// The signed `recover` (hex), once there is one.
    entry: Option<String>,
    /// The X25519 key of the host on the person's sheet (hex), if they
    /// gave it.
    #[serde(default)]
    sheet_host: Option<String>,
    /// The hosts the `recover` keeps.
    #[serde(default)]
    kept: Vec<Kept>,
}

/// A host a recovery kept.
#[derive(Clone, Serialize, Deserialize)]
struct Kept {
    /// Its device key (hex).
    key: String,
    /// Its X25519 static key (hex).
    host: String,
    /// Where it was said to listen.
    addrs: Vec<String>,
    /// When it was last heard from, by this device, after the recovery.
    #[serde(default)]
    heard_ms: Option<u64>,
}

impl Kept {
    fn key(&self) -> Option<KeyId> {
        hex::decode(&self.key).ok()?.try_into().ok()
    }
    fn host(&self) -> Option<[u8; 32]> {
        hex::decode(&self.host).ok()?.try_into().ok()
    }
}

/// After a recovery: the hosts it kept.
#[derive(Default, Serialize, Deserialize)]
struct Recovered {
    kept: Vec<Kept>,
}

fn load(d: &Daemon) -> Option<Under> {
    let b = std::fs::read(d.paths.recovering()).ok()?;
    serde_json::from_slice(&b).ok()
}

fn save(d: &Daemon, u: &Under) -> anyhow::Result<()> {
    crate::paths::write_private(&d.paths.recovering(), &serde_json::to_vec(u)?, 0o600)?;
    Ok(())
}

fn load_recovered(d: &Daemon) -> Option<Recovered> {
    let b = std::fs::read(d.paths.recovered()).ok()?;
    serde_json::from_slice(&b).ok()
}

fn save_recovered(d: &Daemon, r: &Recovered) {
    let bytes = serde_json::to_vec(r).unwrap_or_default();
    if let Err(e) = crate::paths::write_private(&d.paths.recovered(), &bytes, 0o600) {
        tracing::warn!("cannot keep the hosts the recovery kept: {e}");
    }
}

fn phrase_of(u: &Under) -> anyhow::Result<RecoveryPhrase> {
    RecoveryPhrase::parse(&u.words).map_err(|e| anyhow::anyhow!("the recovery under way: {e}"))
}

fn identity_of(u: &Under) -> Option<EntryId> {
    hex::decode(u.identity.as_ref()?).ok()?.try_into().ok()
}

fn entry_of(u: &Under) -> Option<IdentityEntry> {
    IdentityEntry::decode(&hex::decode(u.entry.as_ref()?).ok()?).ok()
}

fn the_fingerprint(d: &Daemon, phrase: &RecoveryPhrase) -> String {
    fingerprint(
        &phrase.root_signing_key().public_key(),
        Some(d.keys.link.public_key()),
    )
}

fn not_set_up(d: &Daemon) -> anyhow::Result<()> {
    anyhow::ensure!(
        d.core().identity.is_none(),
        "this device already belongs to someone. Nothing was changed."
    );
    Ok(())
}

// ---- The helper, and what it carries --------------------------------------

/// One recovery helper starts at a time.
static STARTING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The helper, started if it is not running, and carrying from then on.
async fn helper(d: &Arc<Daemon>) -> anyhow::Result<Arc<Helper>> {
    let _one = STARTING.lock().await;
    if let Some(h) = d.helper.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        return Ok(h);
    }
    let h = crate::helper::start(d).await?;
    let (d2, h2) = (d.clone(), h.clone());
    tokio::spawn(async move { carrying(d2, h2).await });
    Ok(h)
}

/// Goes on with a recovery under way, after a restart.
pub fn resume(d: &Arc<Daemon>) {
    if load(d).is_none() || d.core().identity.is_some() {
        return;
    }
    let d = d.clone();
    tokio::spawn(async move {
        if let Err(e) = helper(&d).await {
            tracing::warn!("cannot go on with the recovery under way: {e:#}");
        }
    });
}

/// Carries, every second, for as long as `h` is this device's helper.
async fn carrying(d: Arc<Daemon>, h: Arc<Helper>) {
    loop {
        let still = d
            .helper
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|x| Arc::ptr_eq(x, &h));
        if !still || load(&d).is_none() {
            return;
        }
        if let Err(e) = carry_round(&d, &h).await {
            tracing::debug!("carrying the recovery: {e:#}");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// The helper's recovery relationships for `who`: each guardian it met,
/// and the space.
fn relationships(h: &Daemon, who: &EntryId) -> Vec<([u8; 32], SpaceId)> {
    h.core()
        .contacts()
        .into_iter()
        .filter(|c| c.recovery_of == Some(*who))
        .map(|c| (c.identity, c.space))
        .collect()
}

/// What the guardians wrote for a recovery of `who`, in all the helper's
/// relationships: the identity entries they carried, and their proposals.
fn gathered(h: &Daemon, who: &EntryId) -> (Vec<Vec<u8>>, Vec<Proposal>) {
    let rels = relationships(h, who);
    let core = h.core();
    let mut entries = Vec::new();
    let mut proposals = Vec::new();
    for (guardian, space) in rels {
        let Some(sp) = core.spaces.get(&space).and_then(|h| h.space.as_ref()) else {
            continue;
        };
        entries.extend(
            relationship::carried(sp)
                .into_iter()
                .filter(|c| c.author == guardian && c.identity == *who)
                .map(|c| c.entry),
        );
        proposals.extend(
            relationship::proposals(sp)
                .into_iter()
                .filter(|p| p.author == guardian && p.identity == *who),
        );
    }
    (entries, proposals)
}

/// The person's log as the guardians carried it, with their own logs
/// under its label, and `recover` if given.
fn working_log(entries: &[Vec<u8>], who: &EntryId, recover: Option<&[u8]>) -> Option<IdentityLog> {
    let decoded: Vec<IdentityEntry> = entries
        .iter()
        .map(Vec::as_slice)
        .chain(recover)
        .filter_map(|b| IdentityEntry::decode(b).ok())
        .collect();
    let genesis = decoded.iter().find(|e| e.is_genesis() && e.id() == *who)?;
    let mut log = IdentityLog::from_genesis(genesis.clone()).ok()?;
    // in any order: each is put in once its parents are
    for e in &decoded {
        if e.id() != *who {
            let _ = log.insert_any(e.clone());
        }
    }
    Some(log)
}

/// The hosts a `recover` keeps, of those a guardian proposed: each the
/// person's log names as one of their device keys, with the static key
/// the guardian gave for it. A host the log does not name is not kept, so
/// that a guardian cannot bring in a device of their own. The host whose
/// sheet key the person typed, if the log names it, is kept beside them.
pub(crate) fn keep_from(
    log: &IdentityLog,
    proposed: &[ProposedHost],
    sheet: Option<[u8; 32]>,
) -> Vec<(KeyId, [u8; 32], Vec<SocketAddr>)> {
    let st = log.state();
    let link = |k: &KeyId| {
        st.keys
            .get(k)
            .and_then(|k| k.link_key.as_ref())
            .map(|l| *l.x25519())
    };
    let mut out: Vec<(KeyId, [u8; 32], Vec<SocketAddr>)> = Vec::new();
    for p in proposed {
        if link(&p.key) == Some(p.host) && !out.iter().any(|(k, ..)| *k == p.key) {
            let addrs = p.endpoints.iter().filter_map(|e| e.socket_addr()).collect();
            out.push((p.key, p.host, addrs));
        }
    }
    if let Some(sheet) = sheet {
        let named = st.keys.values().find(|k| link(&k.key) == Some(sheet));
        if let Some(k) = named.filter(|k| !out.iter().any(|(x, ..)| *x == k.key)) {
            out.push((k.key, sheet, Vec::new()));
        }
    }
    out
}

/// Signs the `recover`, on the first proposal (keeping the hosts of every
/// proposal there is by then), and carries it and every guardian's acts to
/// every guardian.
async fn carry_round(d: &Arc<Daemon>, h: &Arc<Helper>) -> anyhow::Result<()> {
    let Some(mut u) = load(d) else {
        return Ok(());
    };
    let Some(who) = identity_of(&u) else {
        return Ok(());
    };
    let (entries, proposals) = gathered(&h.d, &who);
    if u.entry.is_none() {
        let first = proposals.first();
        let log = first.and_then(|_| working_log(&entries, &who, None));
        if let (Some(p), Some(log)) = (first, log) {
            let sheet = u
                .sheet_host
                .as_ref()
                .and_then(|s| hex::decode(s).ok())
                .and_then(|b| b.try_into().ok());
            // the hosts every guardian heard from so far proposed, under
            // the same policy
            let hosts: Vec<ProposedHost> = proposals
                .iter()
                .filter(|q| q.policy == p.policy)
                .flat_map(|q| q.hosts.iter().cloned())
                .collect();
            let kept = keep_from(&log, &hosts, sheet);
            let keep: Vec<KeyId> = kept.iter().map(|(k, ..)| *k).collect();
            let phrase = phrase_of(&u)?;
            let root = phrase.root_signing_key();
            let e = recover_entry(
                &who,
                &p.parents,
                &root,
                &keep,
                d.keys.link.public_key(),
                p.policy,
                phrase.recovery_key_pair().public_key(),
            )?;
            u.entry = Some(hex::encode(e.encode()));
            u.kept = kept
                .into_iter()
                .map(|(k, host, addrs)| Kept {
                    key: hex::encode(k),
                    host: hex::encode(host),
                    addrs: addrs.iter().map(SocketAddr::to_string).collect(),
                    heard_ms: None,
                })
                .collect();
            save(d, &u)?;
            tracing::info!(
                "recovery asked for, keeping {} of the {} hosts proposed; fingerprint {}",
                u.kept.len(),
                hosts.len(),
                the_fingerprint(d, &phrase)
            );
        }
    }
    // What goes to every guardian: the `recover`, and each guardian's acts
    // with their pasts. The person's own log each guardian has.
    let mut out: Vec<Vec<u8>> = entry_of(&u).map(|e| e.encode()).into_iter().collect();
    out.extend(
        entries
            .into_iter()
            .filter(|b| IdentityEntry::decode(b).is_ok_and(|e| e.identity() != who)),
    );
    if out.is_empty() {
        return Ok(());
    }
    let out = Arc::new(out);
    for (_, space) in relationships(&h.d, &who) {
        let out = out.clone();
        h.on(move |hd| async move { crate::guardians::carry(&hd, &space, &who, &out) })
            .await?;
    }
    Ok(())
}

fn recover_entry(
    identity: &EntryId,
    parents: &[EntryId],
    root: &cardinal_crypto::SigningKey,
    keep: &[KeyId],
    link: &HybridPublicKey,
    policy: EntryId,
    recovery_key: &HybridPublicKey,
) -> anyhow::Result<IdentityEntry> {
    Ok(EntryBuilder::new(*identity, parents)
        .op(IdentityOp::recover(
            root.public_key(),
            keep,
            link,
            policy,
            recovery_key,
        ))
        .sign(root)?)
}

// ---- The person ----------------------------------------------------------

/// How a recovery under way stands, by what the guardians carried.
struct Standing {
    guardians: usize,
    proposed: usize,
    endorsed: usize,
    confirmed: usize,
    threshold: u64,
    in_effect: bool,
}

fn standing(h: Option<&Arc<Helper>>, u: &Under) -> Option<(Standing, Option<IdentityLog>)> {
    let h = h?;
    let who = identity_of(u)?;
    let (entries, proposals) = gathered(&h.d, &who);
    let mine = entry_of(u);
    let log = working_log(&entries, &who, mine.as_ref().map(|e| e.encode()).as_deref());
    let mut s = Standing {
        guardians: relationships(&h.d, &who).len(),
        proposed: proposals.len(),
        endorsed: 0,
        confirmed: 0,
        threshold: 0,
        in_effect: false,
    };
    if let (Some(log), Some(e)) = (log.as_ref(), mine.as_ref()) {
        if let Some(r) = log.recovery(&e.id()) {
            if let Some(p) = log.policy(&r.policy) {
                s.endorsed = log.endorsed_by(&r.entry, &p, &[]).len();
                s.confirmed = log.confirmed_by(&r.entry, &p, &[]).len();
                s.threshold = p.threshold;
            }
            s.in_effect = log.state().in_effect.contains(&r.entry);
        }
    }
    Some((s, log))
}

fn kept_json(d: &Daemon, kept: &[Kept]) -> Vec<Json> {
    let names = d.core().device_names();
    kept.iter()
        .map(|k| {
            let key = k.key();
            json!({
                "key": k.key.get(..16).unwrap_or(&k.key),
                "name": key.and_then(|key| names.get(&key).cloned()),
                "online": k.host().is_some_and(|h| d.is_online(&h)),
                "heard_ms": k.heard_ms,
            })
        })
        .collect()
}

/// `cardinal recover`: what is under way on this device, or what the last
/// recovery kept.
pub fn status(d: &Daemon) -> anyhow::Result<Json> {
    let Some(u) = load(d) else {
        let kept = load_recovered(d).map(|r| r.kept).unwrap_or_default();
        return Ok(json!({"under_way": false, "kept": kept_json(d, &kept), "now_ms": now_ms()}));
    };
    let phrase = phrase_of(&u)?;
    let h = d.helper.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let s = standing(h.as_ref(), &u).map(|(s, _)| s);
    Ok(json!({
        "under_way": true,
        "identity": u.identity,
        "fingerprint": the_fingerprint(d, &phrase),
        "helper": h.is_some(),
        "guardians": s.as_ref().map_or(0, |s| s.guardians),
        "proposed": s.as_ref().map_or(0, |s| s.proposed),
        "asked": u.entry.is_some(),
        "endorsed": s.as_ref().map_or(0, |s| s.endorsed),
        "confirmed": s.as_ref().map_or(0, |s| s.confirmed),
        "threshold": s.as_ref().map_or(0, |s| s.threshold),
        "in_effect": s.as_ref().is_some_and(|s| s.in_effect),
        "kept": kept_json(d, &u.kept),
        "now_ms": now_ms(),
    }))
}

/// `cardinal recover start [CODE] [--key KEY] [--identity ID]`: starts a
/// recovery if none is under way, and with CODE, a guardian's recovery
/// invitation, meets that guardian through the helper. `key` is the sheet
/// key of a host to keep; `identity`, whom to recover, where no code says.
pub async fn start(
    d: &Arc<Daemon>,
    code: Option<&str>,
    key: Option<&str>,
    identity: Option<&str>,
) -> anyhow::Result<Json> {
    not_set_up(d)?;
    let invitation = match code {
        Some(c) => {
            let inv = cardinal_contact::Invitation::from_text(c.trim())
                .map_err(|_| anyhow::anyhow!("that is not an invitation"))?;
            anyhow::ensure!(
                inv.recovery_of.is_some(),
                "that is not a recovery invitation. Ask a guardian for one: `cardinal guarding \
                 invite NAME` on their device."
            );
            Some(inv)
        }
        None => None,
    };
    let named = match identity {
        Some(i) => Some(
            hex::decode(i.trim())
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(|| anyhow::anyhow!("{i} is not an identity id (64 hex digits)"))?,
        ),
        None => None,
    };
    let sheet = match key {
        Some(k) => Some(crate::host::read_sheet_key(k).ok_or_else(|| {
            anyhow::anyhow!("that key does not check out; a character was probably mistyped")
        })?),
        None => None,
    };
    let mut u = load(d).unwrap_or_else(|| Under {
        words: RecoveryPhrase::generate().to_words().to_string(),
        identity: None,
        entry: None,
        sheet_host: None,
        kept: Vec::new(),
    });
    let who = invitation.as_ref().and_then(|i| i.recovery_of).or(named);
    if let Some(who) = who {
        if let Some(was) = identity_of(&u) {
            anyhow::ensure!(
                was == who,
                "this device is recovering someone else; that is for another person"
            );
        }
        if let (Some(i), Some(n)) = (invitation.as_ref().and_then(|i| i.recovery_of), named) {
            anyhow::ensure!(i == n, "that invitation is for someone else");
        }
        u.identity = Some(hex::encode(who));
    }
    if let Some(sheet) = sheet {
        let was = u.sheet_host.replace(hex::encode(sheet));
        anyhow::ensure!(
            u.entry.is_none() || was == u.sheet_host,
            "the recovery was asked for already, without that host; to keep it, start over \
             (`cardinal recover cancel`, then tell your guardians not to confirm the old one)"
        );
    }
    save(d, &u)?;
    let h = helper(d).await?;
    if let Some(inv) = invitation {
        let code = inv.to_text();
        let met = account::Met {
            how: account::MET_THEIR_INVITATION,
            ..Default::default()
        };
        h.on(move |hd| async move {
            crate::contacts::accept(&hd, &code, None, Regard::default(), met).await
        })
        .await
        .map_err(|e| anyhow::anyhow!("could not reach that guardian: {e:#}"))?;
    }
    let phrase = phrase_of(&u)?;
    Ok(json!({
        "fingerprint": the_fingerprint(d, &phrase),
        "identity": u.identity,
    }))
}

/// `cardinal recover invite [--address ADDR]`: an invitation for a
/// guardian to take up on their device, where the two are together. It
/// names whom this device recovers, so only a guardian of theirs answers
/// it.
pub async fn invite(d: &Arc<Daemon>, at: Option<&str>) -> anyhow::Result<Json> {
    not_set_up(d)?;
    let u = load(d).ok_or_else(|| {
        anyhow::anyhow!("no recovery is under way here; start one with `cardinal recover start`")
    })?;
    let who = identity_of(&u).ok_or_else(|| {
        anyhow::anyhow!(
            "this device does not know whom it recovers yet: use a guardian's invitation \
             first, or give the identity (`cardinal recover start --identity ID`)"
        )
    })?;
    let h = helper(d).await?;
    let at = at.map(str::to_owned);
    let code = h
        .on(move |hd| async move {
            crate::contacts::invite_recovery(&hd, at.as_deref(), who).map(|i| i.to_text())
        })
        .await?;
    let phrase = phrase_of(&u)?;
    Ok(json!({"code": code, "fingerprint": the_fingerprint(d, &phrase)}))
}

/// `cardinal recover cancel`: gives up the recovery under way on this
/// device: the words, the `recover`, and the helper with everything it
/// had go. The person tells each guardian not to confirm it.
pub async fn cancel(d: &Arc<Daemon>) -> anyhow::Result<Json> {
    let u = load(d);
    let fp = u
        .as_ref()
        .and_then(|u| phrase_of(u).ok())
        .map(|p| the_fingerprint(d, &p));
    crate::helper::stop(d, true).await?;
    let _ = std::fs::remove_file(d.paths.recovering());
    Ok(json!({"fingerprint": fp}))
}

/// `cardinal recover finish [--host ADDR --key KEY] [--without-hosts]`:
/// becomes the person's device once the recovery is in effect: through a
/// host the recovery kept, or the one given, as a restore from the words
/// does; or, with no host kept or `without_hosts`, from the log the
/// guardians carried, with new account and files spaces.
pub async fn finish(
    d: &Arc<Daemon>,
    at: Option<&str>,
    key: Option<&str>,
    without_hosts: bool,
) -> anyhow::Result<Json> {
    not_set_up(d)?;
    let u = load(d).ok_or_else(|| {
        anyhow::anyhow!("no recovery is under way here; start one with a guardian's invitation")
    })?;
    phrase_of(&u)?;
    let identity =
        identity_of(&u).ok_or_else(|| anyhow::anyhow!("no guardian has been reached yet"))?;
    anyhow::ensure!(
        u.entry.is_some(),
        "no guardian has proposed your recovery yet; wait for one, or bring another's \
         invitation"
    );
    let mut kept = u.kept.clone();
    let through: Option<String> = match (at, key) {
        (Some(at), Some(key)) => {
            let (s, addr, host, host_key) = crate::host::open_restore(d, at, key).await?;
            through_host(d, s, addr, host, host_key, at, identity, &u.words).await?;
            heard_now(&mut kept, &host);
            Some(at.to_owned())
        }
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!("give the host's address and key together, as on your sheet")
        }
        (None, None) => {
            let h = d.helper.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let Some((s, log)) = standing(h.as_ref(), &u) else {
                anyhow::bail!("the recovery helper is not running; try again in a moment");
            };
            if !s.in_effect {
                anyhow::bail!(
                    "your guardians have not all confirmed yet: {} of {} endorsed, {} \
                     confirmed, of {} needed. Try again later.",
                    s.endorsed,
                    s.guardians.max(s.threshold as usize),
                    s.confirmed,
                    s.threshold
                );
            }
            let log = log.expect("in effect");
            if !kept.is_empty() && !without_hosts {
                let mut failed = Vec::new();
                let mut done = None;
                'hosts: for k in &kept {
                    let Some(host) = k.host() else { continue };
                    for a in k.addrs.iter().filter_map(|a| a.parse::<SocketAddr>().ok()) {
                        match crate::host::open_restore_at(d, a, host).await {
                            Ok((s, host_key)) => {
                                let at = a.to_string();
                                match through_host(d, s, a, host, host_key, &at, identity, &u.words)
                                    .await
                                {
                                    Ok(()) => {
                                        done = Some((at, host));
                                        break 'hosts;
                                    }
                                    Err(e) => failed.push(format!("{a}: {e:#}")),
                                }
                            }
                            Err(e) => failed.push(format!("{e:#}")),
                        }
                    }
                }
                let Some((at, host)) = done else {
                    anyhow::bail!(
                        "none of the hosts your recovery kept could be reached ({}). Try again \
                         once one is on; if they were lost too, finish without them: `cardinal \
                         recover finish --without-hosts`.",
                        if failed.is_empty() {
                            "they gave no address".to_owned()
                        } else {
                            failed.join("; ")
                        }
                    );
                };
                heard_now(&mut kept, &host);
                Some(at)
            } else {
                from_guardians(d, log, &u.words).await?;
                None
            }
        }
    };
    // The guardians see each other's confirmations before the helper goes.
    last_carry(d).await;
    crate::helper::stop(d, true).await?;
    let _ = std::fs::remove_file(d.paths.recovering());
    save_recovered(d, &Recovered { kept: kept.clone() });
    Ok(json!({
        "at": through,
        "words": u.words,
        "kept": kept_json(d, &kept),
        "now_ms": now_ms(),
    }))
}

/// Carries what is left to carry, and syncs each relationship with the
/// guardian's devices in touch, ten seconds at most each, so that every
/// guardian sees the recovery in effect.
async fn last_carry(d: &Arc<Daemon>) {
    let h = d.helper.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let (Some(h), Some(who)) = (h, load(d).as_ref().and_then(identity_of)) else {
        return;
    };
    if let Err(e) = carry_round(d, &h).await {
        tracing::debug!("carrying the recovery: {e:#}");
    }
    let _ = h
        .on(move |hd| async move {
            for (guardian, space) in relationships(&hd, &who) {
                for s in hd.sessions_of(&guardian) {
                    let r = tokio::time::timeout(
                        Duration::from_secs(10),
                        net::reconcile(&hd, &s, space),
                    )
                    .await;
                    if !matches!(r, Ok(Ok(()))) {
                        tracing::debug!("a guardian's device did not sync the recovery");
                    }
                }
            }
            Ok(())
        })
        .await;
}

fn heard_now(kept: &mut [Kept], host: &[u8; 32]) {
    let host = hex::encode(host);
    for k in kept.iter_mut().filter(|k| k.host == host) {
        k.heard_ms = Some(now_ms());
    }
}

/// Becomes the person's device through a host, once the recovery is in
/// effect there: proves the new root to it, takes the log, and adds this
/// device with the root (`hosts.md#restore`).
#[allow(clippy::too_many_arguments)]
async fn through_host(
    d: &Arc<Daemon>,
    s: cardinal_link::Session,
    addr: SocketAddr,
    host: [u8; 32],
    host_key: [u8; 32],
    at: &str,
    identity: EntryId,
    words: &str,
) -> anyhow::Result<()> {
    let root = RecoveryPhrase::parse(words)?.root_signing_key();
    let proven = crate::host::send_proof(&s, &root).await?;
    if proven != Some(identity) {
        s.close("not yet");
        anyhow::bail!(
            "that host does not know this device as yours yet: your guardians have not all \
             confirmed the recovery, or their confirmations have not reached it. Try again \
             later."
        );
    }
    *d.pairing.lock().unwrap_or_else(|e| e.into_inner()) = PairState::Joining {
        identity,
        admin_static: host,
        admin_name: at.to_owned(),
        admin_key: host_key,
        admin_addr: Some(addr),
    };
    d.on_session(s.clone());
    let label = identity_log_label(&identity);
    net::reconcile(d, &s, label).await?;
    let log = d
        .core()
        .joining_log(&identity)
        .ok_or_else(|| anyhow::anyhow!("that device did not send the identity log"))?;
    let keys = d.keys.clone();
    let entries =
        tokio::task::spawn_blocking(move || crate::core::recovered_entries(log, &keys, &root))
            .await??;
    for (entry, id) in &entries {
        net::deliver(&s, label, entry.clone(), *id).await?;
    }
    d.ingest(
        label,
        entries.into_iter().map(|(e, _)| e).collect(),
        Access::Join(identity),
    )?;
    Ok(())
}

/// Becomes the person's device from the log the guardians carried, with
/// no host: adds this device with the root, sets a fresh encryption key,
/// and makes new account and files spaces, since nothing is left of the
/// old ones that this device can reach.
async fn from_guardians(d: &Arc<Daemon>, log: IdentityLog, words: &str) -> anyhow::Result<()> {
    let keys = d.keys.clone();
    let root = RecoveryPhrase::parse(words)?.root_signing_key();
    let mut all = crate::core::log_bytes(&log);
    let entries =
        tokio::task::spawn_blocking(move || crate::core::recovered_entries(log, &keys, &root))
            .await??;
    all.extend(entries.into_iter().map(|(e, _)| e));
    let config = crate::config::Config::load(&d.paths.config())?;
    let person = crate::config::default_person();
    let paths = d.paths.clone();
    tokio::task::spawn_blocking(move || {
        crate::setup::install_entries(&paths, &all, &config, &person)
    })
    .await??;
    crate::control::reload(d)?;
    d.identity_changed();
    Ok(())
}

/// A session with one of this person's devices opened: if it is a host a
/// recovery kept, it was heard from now.
pub fn heard(d: &Daemon, key: &KeyId) {
    if !d.paths.recovered().exists() {
        return;
    }
    let Some(mut r) = load_recovered(d) else {
        return;
    };
    let key = hex::encode(key);
    let mut changed = false;
    for k in r.kept.iter_mut().filter(|k| k.key == key) {
        k.heard_ms = Some(now_ms());
        changed = true;
    }
    if changed {
        save_recovered(d, &r);
    }
}

/// `cardinal keep-work DEVICE [--up-to all|TIME]`: what a removed device
/// of this person's wrote that nothing witnessed, with when it says it
/// wrote each; with `up_to`, keeps it up to that point (milliseconds since
/// the epoch, or "all"), as after a recovery that kept none of the old
/// keys. Only what the person recognizes should be kept: a thief's writes
/// with a stolen device are among them (`spaces.md#authors`).
pub fn keep_work(d: &Arc<Daemon>, name: &str, up_to: Option<&str>) -> anyhow::Result<Json> {
    let w = name.trim().to_lowercase();
    let keys: Vec<KeyId> = d
        .core()
        .device_names()
        .into_iter()
        .filter(|(k, v)| v.to_lowercase() == w || (!w.is_empty() && hex::encode(k).starts_with(&w)))
        .map(|(k, _)| k)
        .collect();
    let key = match keys.as_slice() {
        [] => anyhow::bail!("no device was called {name:?}"),
        [k] => *k,
        _ => anyhow::bail!("more than one device was called {name:?}; give the start of its key"),
    };
    let work = d.core().unwitnessed_work(&key)?;
    let listed: Vec<Json> = work
        .iter()
        .map(|(s, x, t)| {
            json!({"space": hex::encode(&s[..8]), "entry": hex::encode(&x[..8]), "time_ms": t})
        })
        .collect();
    let Some(up_to) = up_to else {
        return Ok(json!({"kept": 0, "set_aside": listed}));
    };
    let up_to = match up_to.trim() {
        "all" => None,
        t => Some(t.parse::<u64>().map_err(|_| {
            anyhow::anyhow!("give the point as \"all\" or as a time in milliseconds, as listed")
        })?),
    };
    let (written, kept) = d.core().keep_work(&key, up_to)?;
    for (space, bytes) in written {
        d.push(&space, vec![bytes]);
    }
    d.bump();
    Ok(json!({"kept": kept, "set_aside": listed}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cardinal_crypto::HybridKeyPair;
    use cardinal_identity::{Created, DeviceKeys, Power};

    /// A guardian proposes the person's host, and a device of their own
    /// beside it: only the host the person's log names is kept, and the
    /// sheet's host beside it.
    #[test]
    fn a_host_the_log_does_not_name_is_not_kept() {
        let first = DeviceKeys::generate();
        let Created {
            mut log, phrase, ..
        } = IdentityLog::create_with(
            RecoveryPhrase::from_entropy(&[3; 32]),
            &first,
            HybridKeyPair::generate(),
        )
        .unwrap();
        let root = phrase.root_signing_key();
        let enc = log.open_with_phrase(&phrase).unwrap();
        let add = |log: &mut IdentityLog| {
            let k = DeviceKeys::generate();
            let req = k.request(&log.id(), Power::Device);
            log.add_key(&root, &req, Some(&enc)).unwrap();
            k
        };
        let nuc = add(&mut log);
        let other = add(&mut log);
        let theirs = DeviceKeys::generate();
        let at = cardinal_space::grant::Endpoint::parse("192.0.2.7:7171").unwrap();
        let host = |k: &DeviceKeys| ProposedHost {
            key: k.signing.public_key(),
            host: *k.link.public_key().x25519(),
            endpoints: vec![at.clone()],
        };
        let mut lying = host(&nuc);
        lying.host = *theirs.link.public_key().x25519();
        let proposed = [host(&nuc), host(&theirs), lying];
        let kept = keep_from(&log, &proposed, None);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].0, nuc.signing.public_key());
        assert_eq!(kept[0].2, vec!["192.0.2.7:7171".parse().unwrap()]);
        // the sheet's host, by its static key
        let kept = keep_from(&log, &proposed, Some(*other.link.public_key().x25519()));
        assert_eq!(kept.len(), 2);
        // a sheet key the log does not name adds nothing
        let kept = keep_from(&log, &proposed, Some(*theirs.link.public_key().x25519()));
        assert_eq!(kept.len(), 1);
    }
}
