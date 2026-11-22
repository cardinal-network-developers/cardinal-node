//! A new device recovering an identity through its guardians
//! (`identity.md#how-guardians-act`, `hosts.md#restore`, D77), for a person
//! who lost every admin device and the recovery words. No sheet is needed.
//!
//! 1. `cardinal recover start [CODE]`: the device makes new words, and so a
//!    new root and recovery key, and a recovery helper (`helper.rs`). With
//!    CODE, a guardian's recovery invitation, the helper meets that
//!    guardian in a relationship of its own; the person brings each
//!    guardian's the same way. `cardinal recover invite` makes one for a
//!    guardian to take up instead, where the two are together. Through each
//!    relationship the guardian's device proposes parents and the policy,
//!    and carries the person's log. On the first proposal whose parents the
//!    carried log holds, this device signs the `recover`, naming its own
//!    link key to receive shares and keeping **no** old key: every device
//!    and host of the person's is removed (Daniel, 2026-11-20). It then
//!    carries the same `recover` to every guardian, and each guardian's
//!    acts to the others, for as long as the recovery is under way.
//! 2. The person reads the fingerprint to each guardian, who endorse, wait,
//!    and confirm (`guardians.rs`).
//! 3. `cardinal recover finish`: once the recovery is in effect, from the
//!    log the guardians carried, this device adds itself with the root,
//!    rebuilds the guardian key from the shares sealed to it and opens the
//!    encryption key, sets a fresh one, and makes new account and files
//!    spaces. It shows the new words, and the devices the person had, to
//!    pair again. The helper is dropped.
//!
//! What it holds meanwhile, the new words above all, is kept in
//! `recovering.json`, readable by this user only, until it is done.
//! Afterwards `recovered.json` keeps the devices to pair again.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use cardinal_crypto::{HybridPublicKey, RecoveryPhrase};
use cardinal_identity::guardians::fingerprint;
use cardinal_identity::{EntryBuilder, EntryId, IdentityEntry, IdentityLog, IdentityOp, KeyId};
use cardinal_space::account::{self, Regard};
use cardinal_space::relationship::{self, Proposal};
use cardinal_space::SpaceId;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};

use crate::daemon::Daemon;
use crate::helper::Helper;
use crate::net;

/// Field 9 of an invitation a new device makes before it knows whom it
/// recovers: the guardian who takes it up names the person, from their own
/// contacts (DEVIATIONS.md).
pub const ANYONE: [u8; 32] = [0; 32];

/// Whether a helper's contact is a recovery relationship for `who`: made
/// for them, or for whomever the guardian named.
fn for_recovery(c: &account::ContactRecord, who: &EntryId) -> bool {
    c.recovery_of == Some(*who) || c.recovery_of == Some(ANYONE)
}

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
    /// The device and admin keys the person had as of the `recover`'s
    /// parents (hex), all of which it removes: the devices to pair again.
    #[serde(default)]
    forgotten: Vec<String>,
    /// `cardinal recover finish` began making this device the person's:
    /// once it is, the words are shown once more and this goes.
    #[serde(default)]
    finishing: bool,
}

/// After a recovery: the devices to pair again.
#[derive(Default, Serialize, Deserialize)]
struct Recovered {
    pair_again: Vec<String>,
    /// The device and admin keys the recovery removed (hex): what they
    /// wrote is looked at as each space arrives, after the finish too.
    #[serde(default)]
    forgotten: Vec<String>,
    /// When the person said they lost them, by those devices' clocks.
    #[serde(default)]
    lost_at: Option<u64>,
    /// When the recovery finished, by this device's clock (ms): a lost
    /// device's work is kept as it arrives for [`AFTER_FINISH`] from then.
    /// None in a file from before.
    #[serde(default)]
    finished_ms: Option<u64>,
}

/// How long after a recovery finished what a lost device wrote is kept as
/// each space arrives. After that, only the person's own `keep-work` keeps
/// more.
pub const AFTER_FINISH: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);

impl Recovered {
    fn fresh(&self) -> bool {
        self.finished_ms.is_some_and(|f| {
            crate::core::now_ms() < f.saturating_add(AFTER_FINISH.as_millis() as u64)
        })
    }
}

/// Whether this device was made the person's by a recovery that removed
/// their other devices.
pub fn was_recovered(d: &Daemon) -> bool {
    load_recovered(d).is_some_and(|r| !r.forgotten.is_empty())
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
        tracing::warn!("cannot keep the devices to pair again: {e}");
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
        d.core().identity.is_none() || load(d).is_none(),
        "this device was recovered: look at the recovery to see your new recovery words"
    );
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
    // a helper whose recovery ended, but whose directory could not go
    crate::helper::remove_left(d);
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
            // tried again next time, changed or not
            h.seen.store(u64::MAX, std::sync::atomic::Ordering::SeqCst);
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
        .filter(|c| for_recovery(c, who))
        .map(|c| (c.identity, c.space))
        .collect()
}

/// What the guardians wrote for a recovery of `who`, in all the helper's
/// relationships: the identity entries they carried, and their proposals,
/// in the order the helper met them.
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

/// The log as of `parents`: its genesis and their causal past.
fn log_at(log: &IdentityLog, parents: &[EntryId]) -> Option<IdentityLog> {
    let genesis = log.get(&log.id())?.clone();
    let mut past = log.dag().ancestors_of(parents);
    past.extend(parents.iter().copied());
    let mut at = IdentityLog::from_genesis(genesis).ok()?;
    for e in log.entries() {
        if e.id() != log.id() && past.contains(&e.id()) {
            let _ = at.insert(e.clone());
        }
    }
    Some(at)
}

/// Whether a proposal can be signed as it is, on the log the guardians
/// carried: it acts under the policy in effect now, and its parents are
/// all held, valid (or decisions in effect), and descend from that policy.
fn usable(log: &IdentityLog, p: &Proposal) -> bool {
    let st = log.state();
    let current = log.current_policy().map(|c| c.entry);
    let held = |x: &EntryId| {
        log.get(x).is_some() && (*x == log.id() || st.valid.contains(x) || st.in_effect.contains(x))
    };
    !p.parents.is_empty()
        && current == Some(p.policy)
        && p.parents.iter().all(held)
        && p.parents
            .iter()
            .any(|x| *x == p.policy || log.dag().is_ancestor(&p.policy, x))
}

/// The proposal to sign, and the device and admin keys the person had as of
/// its parents, which the `recover` removes: the first usable one, in the
/// order the helper met the guardians. One not usable yet (its parents
/// still arriving) or ever (another policy) is passed over.
fn choose<'a>(log: &IdentityLog, proposals: &'a [Proposal]) -> Option<(&'a Proposal, Vec<KeyId>)> {
    let p = proposals.iter().find(|p| usable(log, p))?;
    let at = log_at(log, &p.parents)?;
    let had = at.state().keys.keys().copied().collect();
    Some((p, had))
}

/// Signs the `recover`, on the first proposal that can be signed, and
/// carries it and every guardian's acts on the person's log to every
/// guardian.
async fn carry_round(d: &Arc<Daemon>, h: &Arc<Helper>) -> anyhow::Result<()> {
    let Some(mut u) = load(d) else {
        return Ok(());
    };
    // Whom it recovers, if this device does not know yet: as the first
    // guardian to propose, through an invitation for whomever they named,
    // says.
    if identity_of(&u).is_none() {
        let named = {
            let hc = h.d.core();
            hc.contacts()
                .into_iter()
                .filter(|c| c.recovery_of == Some(ANYONE))
                .find_map(|c| {
                    let sp = hc.spaces.get(&c.space)?.space.as_ref()?;
                    relationship::proposals(sp)
                        .into_iter()
                        .find(|p| p.author == c.identity)
                        .map(|p| p.identity)
                })
        };
        if let Some(who) = named {
            u.identity = Some(hex::encode(who));
            save(d, &u)?;
            tracing::info!(
                "the guardian said whom this recovers: {}",
                crate::core::short(&who)
            );
        }
    }
    let Some(who) = identity_of(&u) else {
        return Ok(());
    };
    // Nothing changed at the helper since the last round: nothing to do.
    let seq = *h.d.changed.borrow();
    if u.entry.is_some() && h.seen.swap(seq, std::sync::atomic::Ordering::SeqCst) == seq {
        return Ok(());
    }
    let (entries, proposals) = gathered(&h.d, &who);
    if u.entry.is_none() {
        let log = working_log(&entries, &who, None);
        if let Some((p, had)) = log.as_ref().and_then(|l| choose(l, &proposals)) {
            let phrase = phrase_of(&u)?;
            let root = phrase.root_signing_key();
            let e = recover_entry(
                &who,
                &p.parents,
                &root,
                &[],
                d.keys.link.public_key(),
                p.policy,
                phrase.recovery_key_pair().public_key(),
            )?;
            u.entry = Some(hex::encode(e.encode()));
            u.forgotten = had.iter().map(hex::encode).collect();
            save(d, &u)?;
            tracing::info!(
                "recovery asked for, removing all {} of the person's devices; fingerprint {}",
                had.len(),
                the_fingerprint(d, &phrase)
            );
        }
    }
    // What goes to every guardian: the `recover`, and what the log keeps
    // of anyone else's: the causal pasts of acts on the person's log.
    let Some(mine) = entry_of(&u) else {
        return Ok(());
    };
    let mine = mine.encode();
    let mut out: Vec<Vec<u8>> = vec![mine.clone()];
    if let Some(log) = working_log(&entries, &who, Some(&mine)) {
        for a in log.attached() {
            out.extend(a.entries().map(IdentityEntry::encode));
        }
    }
    let out: Vec<(EntryId, Vec<u8>)> = out
        .into_iter()
        .filter_map(|b| Some((IdentityEntry::decode(&b).ok()?.id(), b)))
        .collect();
    for (guardian, space) in relationships(&h.d, &who) {
        // what was carried there already, by this run
        let new: Vec<(EntryId, Vec<u8>)> = {
            let known = h.carried.lock().unwrap_or_else(|e| e.into_inner());
            let there = known.get(&space);
            out.iter()
                .filter(|(id, _)| !there.is_some_and(|t| t.contains(id)))
                .cloned()
                .collect()
        };
        if new.is_empty() {
            continue;
        }
        let bytes: Vec<Vec<u8>> = new.iter().map(|(_, b)| b.clone()).collect();
        let n = h
            .on(move |hd| async move {
                let n = crate::guardians::carry(&hd, &space, &who, &bytes)?;
                // and to the guardian now, over any session there is
                let hd2 = hd.clone();
                tokio::spawn(async move { sync_with(&hd2, &guardian, &space).await });
                Ok(n)
            })
            .await?;
        tracing::debug!(
            "carried {n} of {} entries to a guardian, in {}",
            new.len(),
            crate::core::short(&space)
        );
        h.carried
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(space)
            .or_default()
            .extend(new.into_iter().map(|(id, _)| id));
    }
    Ok(())
}

pub(crate) fn recover_entry(
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

/// The devices to pair again, by the name the account gives each, if it
/// remembers one.
fn pair_again_json(d: &Daemon, keys: &[String]) -> Vec<Json> {
    let names = d.core().device_names();
    keys.iter()
        .map(|k| {
            let key: Option<KeyId> = hex::decode(k).ok().and_then(|b| b.try_into().ok());
            json!({
                "key": k.get(..16).unwrap_or(k),
                "name": key.and_then(|key| names.get(&key).cloned()),
            })
        })
        .collect()
}

/// `cardinal recover`: what is under way on this device, or the devices
/// the last recovery left to pair again.
pub fn status(d: &Arc<Daemon>) -> anyhow::Result<Json> {
    let Some(u) = load(d) else {
        let r = load_recovered(d).unwrap_or_default();
        return Ok(json!({
            "under_way": false,
            "pair_again": pair_again_json(d, &r.pair_again),
            // as the spaces arrive, after the finish
            "lost_devices": lost_json(d),
            "lost_at": r.lost_at,
        }));
    };
    // `finish` made this device the person's but did not get to the end, as
    // when the service stopped: the words are shown this once, and what was
    // kept for the recovery goes.
    if d.core().identity.is_some() {
        // what the guardians gave back is taken up first: the helper's store
        // goes only after
        // the words are shown whatever happens here
        if let Err(e) = complete_install(d, &u) {
            tracing::warn!("taking up what the guardians gave back: {e:#}");
        }
        let _ = std::fs::remove_file(d.paths.recovering());
        let d2 = d.clone();
        tokio::spawn(async move {
            let _ = crate::helper::stop(&d2).await;
            crate::helper::remove_left(&d2);
        });
        return Ok(json!({
            "under_way": false,
            "finished": true,
            "words": u.words,
            "pair_again": pair_again_json(d, &u.forgotten),
        }));
    }
    let phrase = phrase_of(&u)?;
    let h = d.helper.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let s = standing(h.as_ref(), &u).map(|(s, _)| s);
    let held = match (h.as_ref(), identity_of(&u)) {
        (Some(h), Some(who)) => usize::from(account_back(&h.d.core(), &who)),
        _ => 0,
    };
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
        "held": held,
        // the devices the recovery removes: before finishing, by key alone
        "lost_devices": u
            .forgotten
            .iter()
            .map(|k| json!({"key": k.get(..16).unwrap_or(k), "name": null}))
            .collect::<Vec<_>>(),
    }))
}

/// `cardinal recover start [CODE] [--identity ID]`: starts a recovery if
/// none is under way, and with CODE, a guardian's recovery invitation,
/// meets that guardian through the helper. `identity` is whom to recover,
/// where no code says.
pub async fn start(
    d: &Arc<Daemon>,
    code: Option<&str>,
    identity: Option<&str>,
) -> anyhow::Result<Json> {
    not_set_up(d)?;
    let invitation = match code {
        Some(c) => {
            let inv = cardinal_contact::Invitation::from_text(c.trim())
                .map_err(|_| anyhow::anyhow!("that is not an invitation"))?;
            anyhow::ensure!(
                inv.recovery_of.is_some(),
                "that is not a recovery invitation. Ask a guardian for one: their device \
                 makes it."
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
    let mut u = load(d).unwrap_or_else(|| Under {
        words: RecoveryPhrase::generate().to_words().to_string(),
        identity: None,
        entry: None,
        forgotten: Vec::new(),
        finishing: false,
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
    save(d, &u)?;
    let h = helper(d).await?;
    if let Some(inv) = invitation {
        let code = inv.to_text();
        let met = account::Met {
            how: account::MET_THEIR_INVITATION,
            ..Default::default()
        };
        h.on(move |hd| async move {
            crate::contacts::accept(&hd, &code, None, Regard::default(), met, true).await
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
    let u =
        load(d).ok_or_else(|| anyhow::anyhow!("no recovery is under way here: start one first"))?;
    // With no identity known yet, the invitation is for whomever the
    // guardian who takes it up says (DEVIATIONS.md).
    let who = identity_of(&u).unwrap_or(ANYONE);
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
    crate::helper::stop(d).await?;
    let _ = std::fs::remove_file(d.paths.recovering());
    crate::helper::remove_left(d);
    Ok(json!({"fingerprint": fp}))
}

/// `cardinal recover finish`: becomes the person's device once the
/// recovery is in effect, from the log the guardians carried, with new
/// account and files spaces. The recovery kept none of the old devices:
/// they are listed, to pair again.
pub async fn finish(
    d: &Arc<Daemon>,
    without_account: bool,
    lost_at: Option<u64>,
) -> anyhow::Result<Json> {
    not_set_up(d)?;
    let mut u = load(d).ok_or_else(|| {
        anyhow::anyhow!("no recovery is under way here; start one with a guardian's invitation")
    })?;
    phrase_of(&u)?;
    anyhow::ensure!(
        identity_of(&u).is_some(),
        "no guardian has been reached yet"
    );
    anyhow::ensure!(
        u.entry.is_some(),
        "no guardian has proposed your recovery yet; wait for one, or bring another's \
         invitation"
    );
    let h = d.helper.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let Some((s, log)) = standing(h.as_ref(), &u) else {
        anyhow::bail!("the recovery helper is not running; try again in a moment");
    };
    if !s.in_effect {
        anyhow::bail!(
            "your guardians have not all confirmed yet: {} endorsed, {} confirmed, of {} \
             needed. Try again later.",
            s.endorsed,
            s.confirmed,
            s.threshold
        );
    }
    let log = log.expect("in effect");
    let given = copies(
        h.as_ref().expect("running"),
        &identity_of(&u).expect("checked"),
    );
    tracing::info!(
        "the guardians gave back {} sets, {} entries",
        given.len(),
        given.iter().map(|(_, e)| e.len()).sum::<usize>()
    );
    // Without the account the person starts with an empty one, for good:
    // only on their word.
    let back = account_back(
        &h.as_ref().expect("running").d.core(),
        &identity_of(&u).expect("checked"),
    );
    anyhow::ensure!(
        without_account || back,
        "your guardians have not given back your account yet: it comes once one of them and \
         this device are in touch. Try again in a moment. If none of them holds it, you can \
         go on without it, and start with an empty account."
    );
    // From here this device may become the person's at any moment: if it
    // stops before the end, `cardinal recover` shows the words.
    u.finishing = true;
    save(d, &u)?;
    save_recovered(
        d,
        &Recovered {
            pair_again: u.forgotten.clone(),
            forgotten: u.forgotten.clone(),
            lost_at,
            finished_ms: Some(crate::core::now_ms()),
        },
    );
    // the link keys the removed devices had, by their keys
    let log_links: Vec<(KeyId, [u8; 32])> = log
        .entries()
        .flat_map(|e| e.ops().to_vec())
        .filter_map(|o| match o.body() {
            cardinal_identity::OpBody::AddKey {
                key,
                link_key: Some(l),
                ..
            } => Some((*key, *l.x25519())),
            _ => None,
        })
        .collect();
    let logs = guardians_logs(
        h.as_ref().expect("running"),
        &identity_of(&u).expect("checked"),
    );
    let back = from_guardians(d, log, &u.words, given, logs).await?;
    // What the account remembers, if it came back; else the keys removed.
    let pair_again = match back {
        true => remembered(d),
        false => u.forgotten.clone(),
    };
    save_recovered(
        d,
        &Recovered {
            pair_again: pair_again.clone(),
            forgotten: u.forgotten.clone(),
            lost_at,
            finished_ms: Some(crate::core::now_ms()),
        },
    );
    // The removed devices' hosts leave the lists that name them, and the
    // secrets they held are made anew (`hosts.md#local-discovery`).
    after_removal(d, &forgotten_links(&log_links, &u.forgotten));
    // What the removed devices wrote is set aside, as after any recovery
    // that kept none of them: kept up to when they were lost, if the
    // person says, as each space arrives ([`tend_recovered`]).
    tend_recovered(d);
    let set_aside = lost_json(d);
    // The guardians see each other's confirmations before the helper goes.
    last_carry(d).await;
    crate::helper::stop(d).await?;
    let _ = std::fs::remove_file(d.paths.recovering());
    crate::helper::remove_left(d);
    Ok(json!({
        "words": u.words,
        "account": back,
        "pair_again": pair_again_json(d, &pair_again),
        "lost_devices": set_aside,
    }))
}

/// After a `finish` cut short once the device became the person's: takes
/// up what the guardians gave back, from the helper's store, as `finish`
/// would have, before the helper goes. Each step is idempotent.
fn complete_install(d: &Arc<Daemon>, u: &Under) -> anyhow::Result<()> {
    let Some(who) = identity_of(u) else {
        return Ok(());
    };
    let running = d.helper.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let given = match running {
        Some(h) => copies(&h, &who),
        None => {
            let hp = crate::helper::paths(&d.paths);
            if !crate::core::has_identity(&hp) {
                return Ok(());
            }
            let keys = Arc::new(crate::keys::Keys::load_or_create(&hp.device_key())?);
            let mut hc = crate::core::Core::load(&hp, keys)?;
            hc.takes_recovery_copies = true;
            copies_in(&hc, &who)
        }
    };
    let labels: Vec<[u8; 32]> = given.iter().map(|(l, _)| *l).collect();
    {
        let mut core = d.core();
        for (label, sealed) in &given {
            if let Err(e) = core.ingest_space(*label, sealed) {
                tracing::warn!("a set a guardian gave back: {e:#}");
            }
        }
        core.keep_given_back(&labels)?;
        if core.account_id().is_none() {
            let config = crate::config::Config::load(&d.paths.config())?;
            let keys = d.keys.clone();
            crate::setup::create_spaces(
                &mut core,
                &keys,
                &config,
                &crate::config::default_person(),
            )?;
        }
    }
    d.identity_changed();
    d.housekeeping();
    Ok(())
}

/// Whether an entry is not a `recover` (which the new root signs too).
fn recovery_entry_not(e: &IdentityEntry) -> bool {
    !e.ops()
        .iter()
        .any(|o| matches!(o.body(), cardinal_identity::OpBody::Recover { .. }))
}

/// Syncs a recovery relationship with the guardian's devices in touch, ten
/// seconds at most each.
async fn sync_with(hd: &Arc<Daemon>, guardian: &[u8; 32], space: &SpaceId) {
    for s in hd.sessions_of(guardian) {
        let r = tokio::time::timeout(Duration::from_secs(10), net::reconcile(hd, &s, *space)).await;
        if !matches!(r, Ok(Ok(()))) {
            tracing::debug!("a guardian's device did not sync the recovery");
        }
    }
}

/// The link keys of the removed devices `forgotten` (hex), from what
/// the log said of them.
fn forgotten_links(links: &[(KeyId, [u8; 32])], forgotten: &[String]) -> Vec<[u8; 32]> {
    links
        .iter()
        .filter(|(k, _)| forgotten.contains(&hex::encode(k)))
        .map(|(_, l)| *l)
        .collect()
}

/// After a recovery removed every old device: each that was a host leaves
/// the reach lists that name it, with its tokens, as when the person
/// removes one; and the discovery and presence secrets, which those
/// devices held, are made anew, the presence secret given again to each
/// trusted contact, and the advertisements follow (`hosts.md#local-discovery`).
fn after_removal(d: &Arc<Daemon>, links: &[[u8; 32]]) {
    for l in links {
        crate::mailbox::take_out_removed(d, l);
    }
    let ops: Vec<cardinal_space::SpaceOp> = {
        let core = d.core();
        let Some(acc) = core.account().and_then(|a| a.space.as_ref()) else {
            return;
        };
        acc.state()
            .children(&cardinal_space::ROOT)
            .into_iter()
            .filter(|n| {
                n.kind == cardinal_space::entry::NodeKind::Uint(account::SECRET) && !n.deleted
            })
            .filter(|n| {
                let p = n.field(1).and_then(|v| v.as_text());
                p == Some(crate::core::DISCOVERY_PURPOSE) || p == Some(crate::presence::PURPOSE)
            })
            .map(|n| cardinal_space::SpaceOp::delete(n.id))
            .collect()
    };
    let Some(acc) = d.core().account_id() else {
        return;
    };
    let mut ops = ops;
    let fresh: [u8; 32] = cardinal_crypto::random_bytes();
    ops.push(crate::core::create_secret(
        crate::core::DISCOVERY_PURPOSE,
        &fresh,
    ));
    if let Err(e) = d.write_and_push(&acc, ops) {
        tracing::warn!("cannot renew the discovery secrets after the recovery: {e:#}");
        return;
    }
    // a new presence secret, given where it is due
    crate::presence::keep(d);
    tracing::info!("new discovery and presence secrets, after the recovery");
}

/// What the recovery's removed devices wrote, as spaces arrive after the
/// finish: kept up to when the person said they were lost, but for their
/// successions, which no keep lists and which so fall: the old space stands
/// again, and whoever followed returns to it
/// (`spaces.md#a-succession-by-a-device-that-is-later-removed`).
pub fn tend_recovered(d: &Arc<Daemon>) {
    let Some(r) = load_recovered(d) else {
        return;
    };
    // kept as spaces arrive only for a while after the finish: then by the
    // person's own `keep-work` (a thief sets the clock those entries give)
    let Some(up_to) = r.lost_at.filter(|_| r.fresh()) else {
        return;
    };
    if r.forgotten.is_empty() || d.core().identity.is_none() {
        return;
    }
    for k in r
        .forgotten
        .iter()
        .filter_map(|k| hex::decode(k).ok()?.try_into().ok())
    {
        let k: KeyId = k;
        // the core is let go before what was written is pushed
        let kept = d.core().keep_work(&k, Some(up_to));
        match kept {
            Ok((written, _)) => {
                for (space, bytes) in written {
                    d.push(&space, vec![bytes]);
                }
            }
            Err(e) => tracing::debug!("keeping what a lost device wrote: {e:#}"),
        }
    }
}

/// `recover-lost-at` (`lost_at`): when the person lost the devices the
/// recovery removed, said after the finish: what they wrote up to then is
/// kept, as each space arrives.
pub fn set_lost_at(d: &Arc<Daemon>, lost_at: Option<u64>) -> anyhow::Result<Json> {
    let mut r = load_recovered(d).ok_or_else(|| anyhow::anyhow!("no recovery took place here"))?;
    r.lost_at = lost_at;
    save_recovered(d, &r);
    tend_recovered(d);
    Ok(json!({"lost_devices": lost_json(d)}))
}

/// The devices the recovery removed, with how much of what each wrote is
/// set aside in the spaces held now.
fn lost_json(d: &Daemon) -> Vec<Json> {
    let Some(r) = load_recovered(d) else {
        return Vec::new();
    };
    r.forgotten
        .iter()
        .filter_map(|k| hex::decode(k).ok()?.try_into().ok())
        .map(|k: KeyId| {
            let left = d.core().unwitnessed_work(&k).map(|w| w.len()).unwrap_or(0);
            json!({
                "key": hex::encode(&k[..8]),
                "name": d.core().device_names().get(&k).cloned(),
                "set_aside": left,
            })
        })
        .collect()
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
    // What the new root wrote, taking the identity up: the guardians know
    // this device by it, and that their personas' purpose is over.
    let root = load(d).as_ref().and_then(entry_of).map(|e| e.signer());
    let mine: Vec<Vec<u8>> = {
        let core = d.core();
        core.identity
            .as_ref()
            .map(|i| {
                i.log
                    .entries()
                    .filter(|e| Some(e.signer()) == root && recovery_entry_not(e))
                    .map(IdentityEntry::encode)
                    .collect()
            })
            .unwrap_or_default()
    };
    let _ = h
        .on(move |hd| async move {
            for (guardian, space) in relationships(&hd, &who) {
                if let Err(e) = crate::guardians::carry(&hd, &space, &who, &mine) {
                    tracing::debug!("carrying the new device's entries: {e:#}");
                }
                sync_with(&hd, &guardian, &space).await;
            }
            Ok(())
        })
        .await;
}

/// The sets the guardians' personas gave the helper to hold (D80): the
/// sealed account and each one's relationship space with the person, by
/// label, with every sealed entry of each.
fn copies(h: &Helper, who: &EntryId) -> Vec<([u8; 32], Vec<Vec<u8>>)> {
    copies_in(&h.d.core(), who)
}

/// The sets the guardians' personas name as the account: the one a new
/// device must have back.
fn account_labels(core: &crate::core::Core, who: &EntryId) -> Vec<[u8; 32]> {
    core.contacts()
        .into_iter()
        .filter(|c| for_recovery(c, who))
        .filter_map(|c| {
            let sp = core.spaces.get(&c.space)?.space.as_ref()?;
            relationship::held_account(sp, &c.identity)
        })
        .collect()
}

/// Whether the account is among what the guardians gave back.
fn account_back(core: &crate::core::Core, who: &EntryId) -> bool {
    account_labels(core, who)
        .iter()
        .any(|l| core.set(l).iter().next().is_some())
}

/// The guardians' own logs, which each guardian's persona carried under
/// the guardian's own id: the person's contacts, whose devices the new
/// device knows by them.
fn guardians_logs(h: &Helper, who: &EntryId) -> Vec<([u8; 32], Vec<Vec<u8>>)> {
    let core = h.d.core();
    let mut by: BTreeMap<[u8; 32], Vec<Vec<u8>>> = BTreeMap::new();
    for c in core.contacts().into_iter().filter(|c| for_recovery(c, who)) {
        let Some(sp) = core.spaces.get(&c.space).and_then(|x| x.space.as_ref()) else {
            continue;
        };
        // one log a persona: its guardian's own
        let mut theirs: Option<[u8; 32]> = None;
        for x in relationship::carried(sp) {
            if x.author == c.identity && x.identity != *who {
                if theirs.is_some_and(|t| t != x.identity) {
                    continue;
                }
                theirs = Some(x.identity);
                by.entry(x.identity).or_default().push(x.entry);
            }
        }
    }
    by.into_iter().collect()
}

/// [`copies`], from a helper's core, running or not.
fn copies_in(core: &crate::core::Core, who: &EntryId) -> Vec<([u8; 32], Vec<Vec<u8>>)> {
    let rels: Vec<([u8; 32], SpaceId)> = core
        .contacts()
        .into_iter()
        .filter(|c| for_recovery(c, who))
        .map(|c| (c.identity, c.space))
        .collect();
    let mut labels: Vec<[u8; 32]> = Vec::new();
    for (persona, _) in rels {
        for l in core.held_taken(&persona) {
            if !labels.contains(&l) {
                labels.push(l);
            }
        }
    }
    labels
        .into_iter()
        .map(|l| {
            let ids: Vec<[u8; 32]> = core.set(&l).iter().copied().collect();
            let all = ids.iter().filter_map(|id| core.get(&l, id)).collect();
            (l, all)
        })
        .collect()
}

/// Becomes the person's device from what the guardians carried: adds this
/// device with the root, sets a fresh encryption key, and takes up the
/// account and the guardians' relationships they held, sealed, opened now
/// with the encryption key the guardian key opened (D80). With no account
/// among them, new account and files spaces are made. Returns whether the
/// account came back.
async fn from_guardians(
    d: &Arc<Daemon>,
    log: IdentityLog,
    words: &str,
    copies: Vec<([u8; 32], Vec<Vec<u8>>)>,
    logs: Vec<([u8; 32], Vec<Vec<u8>>)>,
) -> anyhow::Result<bool> {
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
    let back = tokio::task::spawn_blocking(move || {
        crate::setup::install_recovered(&paths, &all, &copies, &logs, &config, &person)
    })
    .await??;
    crate::control::reload(d)?;
    d.identity_changed();
    // this device in the account, and its placement, as for any device
    d.housekeeping();
    Ok(back)
}

/// The devices the account remembers, but this one: the person's other
/// devices and hosts, which the recovery removed, to pair again.
fn remembered(d: &Daemon) -> Vec<String> {
    let core = d.core();
    let me = d.keys.key();
    let Some(acc) = core.account().and_then(|a| a.space.as_ref()) else {
        return Vec::new();
    };
    account::devices(acc.state())
        .into_iter()
        .filter(|x| x.key != me)
        .map(|x| hex::encode(x.key))
        .collect()
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

    #[test]
    fn after_the_window_nothing_more_is_kept() {
        let now = crate::core::now_ms();
        let at = |f: Option<u64>| Recovered {
            finished_ms: f,
            ..Recovered::default()
        };
        assert!(at(Some(now)).fresh());
        let past = AFTER_FINISH.as_millis() as u64 + 1000;
        assert!(!at(Some(now - past)).fresh());
        // a file from before the window was kept keeps nothing
        assert!(!at(None).fresh());
    }

    /// A person with a host, another device, and an admin.
    fn person() -> (IdentityLog, Vec<KeyId>) {
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
        let mut keys = vec![first.key()];
        for power in [Power::Device, Power::Device, Power::Admin] {
            let k = DeviceKeys::generate();
            let req = k.request(&log.id(), power);
            log.add_key(&root, &req, Some(&enc)).unwrap();
            keys.push(k.key());
        }
        (log, keys)
    }

    fn proposal(log: &IdentityLog, author: u8) -> Proposal {
        Proposal {
            node: [0; 16],
            author: [author; 32],
            identity: log.id(),
            parents: log.recovery_parents(),
            policy: log.current_policy().unwrap().entry,
        }
    }

    /// The proposal arrives before the log it names: nothing is signed
    /// until its parents are all here, and then every device the person
    /// had by then is listed, to be removed and paired again. A proposal
    /// under another policy is passed over for the next.
    #[test]
    fn a_recover_waits_for_the_log_its_proposal_names() {
        let (log, keys) = person();
        let all: Vec<Vec<u8>> = log.entries().map(IdentityEntry::encode).collect();
        let good = proposal(&log, 1);
        let mut bad = proposal(&log, 2);
        bad.policy = [9; 32];
        let proposals = vec![bad, good];
        let early = working_log(&all[..1], &log.id(), None).unwrap();
        assert!(choose(&early, &proposals).is_none());
        let half = working_log(&all[..2], &log.id(), None).unwrap();
        assert!(choose(&half, &proposals).is_none());
        let mut shuffled = all.clone();
        shuffled.reverse();
        let whole = working_log(&shuffled, &log.id(), None).unwrap();
        let (chosen, mut had) = choose(&whole, &proposals).unwrap();
        assert_eq!(chosen.author, [1; 32]);
        had.sort();
        let mut keys = keys;
        keys.sort();
        assert_eq!(had, keys);
    }

    /// `finish` made the device the person's and stopped before the end:
    /// `cardinal recover` shows the words once, and then nothing is under
    /// way.
    #[tokio::test]
    async fn words_left_by_a_finish_cut_short_are_shown_once() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, config) = crate::testing::set_up(dir.path());
        let d = Daemon::start(paths, config).await.unwrap();
        let words = RecoveryPhrase::generate().to_words().to_string();
        let u = Under {
            words: words.clone(),
            identity: d.core().me().map(hex::encode),
            entry: None,
            forgotten: vec![hex::encode([5u8; 32])],
            finishing: true,
        };
        save(&d, &u).unwrap();
        std::fs::create_dir_all(d.paths.recovery_helper()).unwrap();
        let v = status(&d).unwrap();
        assert_eq!(v["finished"], true);
        assert_eq!(v["words"].as_str(), Some(words.as_str()));
        assert_eq!(v["pair_again"].as_array().map(Vec::len), Some(1));
        let v = status(&d).unwrap();
        assert!(v["words"].is_null(), "{v}");
        assert_eq!(v["under_way"], false);
        assert!(!d.paths.recovering().exists());
        for _ in 0..50 {
            if !d.paths.recovery_helper().exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(!d.paths.recovery_helper().exists());
        // and nothing more is started on top of it
        let e = start(&d, None, None).await.unwrap_err();
        assert!(e.to_string().contains("already belongs"), "{e}");
    }
}
