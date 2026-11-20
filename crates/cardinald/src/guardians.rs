//! Guardians (`identity.md#guardians`): recovery through people you trust.
//!
//! **The person.** `cardinal guardians set NAME... --threshold N` names
//! guardians from trusted contacts: a `set_recovery` with a hidden
//! commitment and a sealed record for each, and a guardian key whose shares
//! the records carry. The first guardians, under a policy naming none, are
//! named by its controller, the root, so the recovery words are asked for.
//! The account space marks who they are (contact field 5); the log does
//! not. A fresh encryption key follows, wrapped to the guardian key too.
//!
//! **A guardian.** Every guardian holds the person's log, as a contact, and
//! finds its own record by opening the sealed ones: that is how it is
//! told. `cardinal guarding` lists whom this person guards and any
//! recovery wanted. A guardian gives the person's new device a code
//! (`cardinal guarding code NAME`), over which that device signs a
//! `recover` the guardian's device proposes and appends; then each
//! guardian, after checking the fingerprint with the person, endorses,
//! waits the delay from when it saw a threshold endorse, and confirms with
//! its share sealed to the new device. Endorsements and confirmations are
//! entries in the guardian's own log, delivered with that log to the
//! person's devices and hosts under the person's label
//! (`identity.md#distribution`).
//!
//! The new device's side is `recovering.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cardinal_crypto::HybridKeyPair;
use cardinal_encoding::{Record, Value};
use cardinal_identity::guardians::{same_fingerprint, Policy, Recovery, DEFAULT_DELAY};
use cardinal_identity::{EntryId, IdentityEntry, IdentityLog, IdentityOp, OpBody, Power};
use cardinal_link::{Service, Session, Stream};
use cardinal_space::account;
use cardinal_sync::identity_log_label;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use tokio::io::AsyncWriteExt;

use crate::core::{now_ms, short};
use crate::daemon::{lock, Daemon, PeerKind};
use crate::net;

/// The link service a new device and a guardian's device speak over a
/// help code's session. The spec leaves how they meet to software
/// (DEVIATIONS.md).
pub const SERVICE_NAME: &str = "cardinal-node recovery help 1";

/// The link service.
pub fn service() -> Service {
    Service::App(*blake3::hash(SERVICE_NAME.as_bytes()).as_bytes())
}

/// Messages of the help service: the new device asks, the guardian's
/// device proposes, the new device sends the signed `recover`, the
/// guardian's device says it took it.
pub(crate) const ASK: u64 = 1;
pub(crate) const PROPOSAL: u64 = 2;
pub(crate) const RECOVER: u64 = 3;
pub(crate) const TAKEN: u64 = 4;
pub(crate) const REFUSED: u64 = 0;

/// The prefix of a help code.
pub const HELP_PREFIX: &str = "cardinal-help:";

/// How long a help code is good for.
pub const HELP_FOR: Duration = Duration::from_secs(24 * 60 * 60);

/// What this device has seen as a guardian, kept across restarts: when
/// it first saw a threshold of guardians endorse each recovery, which is
/// when its wait starts (`identity.md#how-guardians-act`, step 3).
#[derive(Default, Serialize, Deserialize)]
struct Seen {
    /// Decision (hex) to milliseconds since the epoch.
    threshold: BTreeMap<String, u64>,
}

fn load_seen(d: &Daemon) -> Seen {
    std::fs::read(d.paths.guarding())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_seen(d: &Daemon, seen: &Seen) {
    let bytes = serde_json::to_vec_pretty(seen).unwrap_or_default();
    if let Err(e) = crate::paths::write_private(&d.paths.guarding(), &bytes, 0o600) {
        tracing::warn!("cannot keep what this device saw as a guardian: {e}");
    }
}

fn delay_text(secs: u64) -> String {
    let (n, unit) = match secs {
        s if s % 86_400 == 0 && s > 0 => (s / 86_400, "day"),
        s if s % 3600 == 0 && s > 0 => (s / 3600, "hour"),
        s if s % 60 == 0 && s > 0 => (s / 60, "minute"),
        s => (s, "second"),
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

fn my_id(d: &Daemon) -> anyhow::Result<EntryId> {
    d.core()
        .identity
        .as_ref()
        .map(|i| i.id())
        .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone"))
}

// ---- The person ----------------------------------------------------------

/// `cardinal guardians`: who guards this person, as their own devices know
/// it from the account space, and the policy as everyone sees it.
pub fn show(d: &Daemon) -> anyhow::Result<Json> {
    let core = d.core();
    let ident = core
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone"))?;
    let policy = ident.log.current_policy();
    let mut names: Vec<String> = core
        .contacts()
        .into_iter()
        .filter(|c| c.guardian)
        .map(|c| c.petname)
        .collect();
    names.sort_by_key(|n| n.to_lowercase());
    let st = ident.state();
    let others: Vec<&IdentityLog> = core.others.values().map(|o| &o.log).collect();
    let recoveries: Vec<Json> = ident
        .log
        .recoveries()
        .into_iter()
        .filter_map(|r| {
            let p = ident.log.policy(&r.policy)?;
            Some(json!({
                "fingerprint": r.fingerprint(),
                "endorsed": ident.log.endorsed_by(&r.entry, &p, &others).len(),
                "confirmed": ident.log.confirmed_by(&r.entry, &p, &others).len(),
                "in_effect": st.in_effect.contains(&r.entry),
                "objected": objected(&ident.log, &r.entry),
                "id": hex::encode(r.entry),
            }))
        })
        .collect();
    Ok(json!({
        "guardians": policy.as_ref().map_or(0, |p| p.commitments.len()),
        "threshold": policy.as_ref().map_or(0, |p| p.threshold),
        "delay": policy.as_ref().map_or(0, |p| p.delay),
        "delay_text": delay_text(policy.as_ref().map_or(0, |p| p.delay)),
        "data": policy.as_ref().is_some_and(|p| p.guardian_key.is_some()),
        "names": names,
        "recoveries": recoveries,
        "frozen": st.frozen,
    }))
}

/// `cardinal guardians set NAME... --threshold N [--delay SECONDS]`.
pub fn set(
    d: &Arc<Daemon>,
    who: &[String],
    threshold: Option<u64>,
    delay: Option<u64>,
    words: Option<&str>,
) -> anyhow::Result<Json> {
    anyhow::ensure!(!who.is_empty(), "name at least one guardian");
    let mut chosen = Vec::new();
    for w in who {
        let c = crate::contacts::find(d, w)?;
        anyhow::ensure!(
            c.connects(),
            "{} is not someone you trust; a guardian must be (`cardinal contacts {} trust`)",
            c.petname,
            c.petname
        );
        anyhow::ensure!(
            !chosen
                .iter()
                .any(|x: &account::ContactRecord| x.identity == c.identity),
            "{} is named twice",
            c.petname
        );
        chosen.push(c);
    }
    let n = chosen.len() as u64;
    let threshold = threshold.unwrap_or(n / 2 + 1);
    anyhow::ensure!(
        threshold * 2 > n && threshold <= n,
        "with {n} guardians the threshold is between {} and {n}: more than half of them",
        n / 2 + 1
    );
    let delay = delay.unwrap_or(DEFAULT_DELAY);
    let (unguarded, named) = {
        let core = d.core();
        let ident = core
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone"))?;
        let policy = ident
            .log
            .current_policy()
            .ok_or_else(|| anyhow::anyhow!("your identity has no recovery policy in effect"))?;
        let mut named = Vec::new();
        for c in &chosen {
            let key = core.encryption_key_of(&c.identity).map_err(|_| {
                anyhow::anyhow!(
                    "{}'s identity log is not here yet; try again once you have been in touch",
                    c.petname
                )
            })?;
            named.push((c.identity, key));
        }
        (!policy.guarded(), named)
    };
    anyhow::ensure!(
        unguarded,
        "you have guardians already. Changing them needs your guardians to confirm the \
         change, which this version cannot ask of them yet."
    );
    // The first guardians are named by the policy's controller, the root.
    let root = crate::recovery::signer(
        d,
        words,
        |_| false,
        || "your first guardians are named with your recovery words".to_owned(),
    )?
    .expect("asked for the words");
    let entries = {
        let mut core = d.core();
        let ident = core.identity.as_mut().expect("identity");
        let current = ident
            .enc
            .first()
            .map(|k| HybridKeyPair::from_secret_bytes(&k.secret_bytes()));
        let e1 = ident
            .log
            .set_guardians(&root, &named, threshold, delay, true, current.as_ref())
            .map_err(|e| anyhow::anyhow!("cannot name these guardians: {e}"))?;
        ident.record_own(&e1)?;
        // After a change of guardians, a fresh encryption key, wrapped to
        // the new guardian key (`identity.md#the-identity-encryption-key`).
        let mine = ident.state().power(&d.keys.key());
        let signer = if mine >= Some(Power::Admin) {
            &d.keys.device.signing
        } else {
            &root
        };
        let fresh = HybridKeyPair::generate();
        let e2 = ident
            .log
            .set_encryption_key(signer, &fresh, current.as_ref())?;
        ident.record_own(&e2)?;
        vec![e1.encode(), e2.encode()]
    };
    d.identity_changed();
    d.push_identity(entries);
    mark_guardians(d, &chosen)?;
    Ok(json!({
        "names": chosen.iter().map(|c| c.petname.clone()).collect::<Vec<_>>(),
        "threshold": threshold,
        "delay": delay,
        "delay_text": delay_text(delay),
    }))
}

/// Marks the guardians in the account space, and nobody else.
fn mark_guardians(d: &Arc<Daemon>, chosen: &[account::ContactRecord]) -> anyhow::Result<()> {
    let Some(acc) = d.core().account_id() else {
        return Ok(());
    };
    let ops: Vec<_> = d
        .core()
        .contacts()
        .into_iter()
        .filter_map(|c| {
            let now = chosen.iter().any(|x| x.identity == c.identity);
            (now != c.guardian).then(|| account::set_field(c.node, account::GUARDIAN, now))
        })
        .collect();
    if !ops.is_empty() {
        d.write_and_push(&acc, ops)?;
    }
    Ok(())
}

/// `cardinal guardians object`: a device the person holds disagrees with a
/// recovery under way. It cancels nothing; it doubles the guardians' wait.
pub fn object(d: &Arc<Daemon>, which: Option<&str>) -> anyhow::Result<Json> {
    let entry = {
        let mut core = d.core();
        let ident = core
            .identity
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone"))?;
        let st = ident.state();
        anyhow::ensure!(
            st.power(&d.keys.key()) >= Some(Power::Admin),
            "only an admin device may object"
        );
        let pending: Vec<Recovery> = ident
            .log
            .recoveries()
            .into_iter()
            .filter(|r| !st.in_effect.contains(&r.entry))
            .filter(|r| which.is_none_or(|w| same_fingerprint(w, &r.fingerprint())))
            .collect();
        let r = match pending.as_slice() {
            [] => anyhow::bail!("no recovery is under way"),
            [r] => r.clone(),
            _ => anyhow::bail!("more than one recovery is under way; give its fingerprint"),
        };
        let e = ident
            .log
            .append(&d.keys.device.signing, vec![IdentityOp::object(r.entry)])?;
        ident.record_own(&e)?;
        e.encode()
    };
    d.identity_changed();
    d.push_identity(vec![entry]);
    Ok(json!({}))
}

fn objected(log: &IdentityLog, decision: &EntryId) -> bool {
    let st = log.state();
    log.entries().any(|e| {
        st.is_valid(&e.id())
            && e.ops()
                .iter()
                .any(|o| matches!(o.body(), OpBody::Object { decision: x } if x == decision))
    })
}

// ---- A guardian ----------------------------------------------------------

/// Someone this person guards, as this device sees it.
pub(crate) struct Guarded {
    pub identity: EntryId,
    pub name: String,
    pub policy: Policy,
    pub position: u64,
    pub salt: [u8; 32],
    pub share: Option<cardinal_crypto::shamir::Share>,
}

/// Whom this person guards: every contact whose current policy holds a
/// record sealed to this identity that opens its commitment.
pub(crate) fn guarded(d: &Daemon) -> Vec<Guarded> {
    let core = d.core();
    let Some(ident) = core.identity.as_ref() else {
        return Vec::new();
    };
    let me = ident.id();
    let keys: Vec<HybridKeyPair> = ident
        .enc
        .iter()
        .map(|k| HybridKeyPair::from_secret_bytes(&k.secret_bytes()))
        .collect();
    let mut out = Vec::new();
    for c in core.contacts() {
        let Some(other) = core.others.get(&c.identity) else {
            continue;
        };
        let mut policies: Vec<Policy> = other.log.current_policy().into_iter().collect();
        // and the policy any recovery acts under, which a later change
        // may have replaced
        for r in other.log.recoveries() {
            if !policies.iter().any(|p| p.entry == r.policy) {
                policies.extend(other.log.policy(&r.policy));
            }
        }
        for policy in policies {
            if let Some(rec) = other.log.guardian_record(&policy, &me, &keys) {
                out.push(Guarded {
                    identity: c.identity,
                    name: c.petname.clone(),
                    policy,
                    position: rec.position,
                    salt: rec.salt,
                    share: rec.share,
                });
            }
        }
    }
    out
}

/// A recovery of someone this person guards, as this device sees it.
struct Wanted {
    recovery: Recovery,
    endorsed: BTreeSet<EntryId>,
    confirmed: BTreeSet<EntryId>,
    in_effect: bool,
    objected: bool,
}

fn wanted(d: &Daemon, g: &Guarded) -> Vec<Wanted> {
    let core = d.core();
    let Some(other) = core.others.get(&g.identity) else {
        return Vec::new();
    };
    let mine: Vec<&IdentityLog> = core.identity.as_ref().map(|i| &i.log).into_iter().collect();
    let st = other.log.state();
    other
        .log
        .recoveries()
        .into_iter()
        .filter(|r| r.policy == g.policy.entry)
        .map(|r| Wanted {
            endorsed: other.log.endorsed_by(&r.entry, &g.policy, &mine),
            confirmed: other.log.confirmed_by(&r.entry, &g.policy, &mine),
            in_effect: st.in_effect.contains(&r.entry),
            objected: objected(&other.log, &r.entry),
            recovery: r,
        })
        .collect()
}

/// Notes when a threshold of guardians was first seen to endorse each
/// recovery of someone this person guards. Called whenever a log changes.
pub fn observe(d: &Daemon) {
    // one at a time: what is seen is read, added to, and written back
    static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    let mut seen = load_seen(d);
    let mut changed = false;
    for g in guarded(d) {
        for w in wanted(d, &g) {
            let key = hex::encode(w.recovery.entry);
            if w.endorsed.len() as u64 >= g.policy.threshold && !seen.threshold.contains_key(&key) {
                tracing::info!(
                    "a recovery of {} is pending: {} of {} guardians endorsed it",
                    g.name,
                    w.endorsed.len(),
                    g.policy.commitments.len()
                );
                seen.threshold.insert(key, now_ms());
                changed = true;
            }
        }
    }
    if changed {
        save_seen(d, &seen);
    }
}

/// When this guardian may confirm: the delay after it saw the threshold,
/// twice the delay after an objection (`identity.md#how-guardians-act`).
fn confirm_from(seen: &Seen, g: &Guarded, w: &Wanted) -> Option<u64> {
    let since = seen.threshold.get(&hex::encode(w.recovery.entry))?;
    let wait = g
        .policy
        .delay
        .saturating_mul(if w.objected { 2 } else { 1 });
    Some(since.saturating_add(wait.saturating_mul(1000)))
}

/// `cardinal guarding`: whom this person guards, and recoveries wanted.
pub fn list(d: &Daemon) -> Json {
    observe(d);
    let seen = load_seen(d);
    let me = d.core().identity.as_ref().map(|i| i.id());
    let people: Vec<Json> = guarded(d)
        .iter()
        .map(|g| {
            let recoveries: Vec<Json> = wanted(d, g)
                .iter()
                .map(|w| {
                    let mine = |s: &BTreeSet<EntryId>| me.is_some_and(|m| s.contains(&m));
                    json!({
                        "fingerprint": w.recovery.fingerprint(),
                        "endorsed": w.endorsed.len(),
                        "confirmed": w.confirmed.len(),
                        "endorsed_by_me": mine(&w.endorsed),
                        "confirmed_by_me": mine(&w.confirmed),
                        "pending": w.endorsed.len() as u64 >= g.policy.threshold,
                        "confirm_from_ms": confirm_from(&seen, g, w),
                        "objected": w.objected,
                        "in_effect": w.in_effect,
                    })
                })
                .collect();
            json!({
                "name": g.name,
                "id": hex::encode(&g.identity[..8]),
                "guardians": g.policy.commitments.len(),
                "threshold": g.policy.threshold,
                "delay": g.policy.delay,
                "delay_text": delay_text(g.policy.delay),
                "recoveries": recoveries,
            })
        })
        .collect();
    json!({"guarding": people, "now_ms": now_ms()})
}

fn find_guarded(d: &Daemon, who: &str) -> anyhow::Result<Guarded> {
    let c = crate::contacts::find(d, who)?;
    let mut all = guarded(d);
    let at = all
        .iter()
        .rposition(|g| g.identity == c.identity)
        .ok_or_else(|| anyhow::anyhow!("you do not guard {}", c.petname))?;
    Ok(all.swap_remove(at))
}

/// The one recovery of `g` the person means, by the fingerprint they read.
fn find_wanted(d: &Daemon, g: &Guarded, fingerprint: &str) -> anyhow::Result<Wanted> {
    let mut all = wanted(d, g);
    anyhow::ensure!(!all.is_empty(), "nobody has asked to recover {}", g.name);
    let shown: Vec<String> = all.iter().map(|w| w.recovery.fingerprint()).collect();
    let at = pick_fingerprint(&shown, fingerprint, &g.name)?;
    Ok(all.swap_remove(at))
}

/// Which of the recoveries `shown` the person read out: exactly one must
/// match. Two that match are refused, since the fingerprint cannot tell
/// them apart: someone may have made one to look like the other.
fn pick_fingerprint(shown: &[String], typed: &str, name: &str) -> anyhow::Result<usize> {
    let matching: Vec<usize> = (0..shown.len())
        .filter(|i| same_fingerprint(typed, &shown[*i]))
        .collect();
    match matching.as_slice() {
        [i] => Ok(*i),
        [] => anyhow::bail!(
            "that is not the fingerprint of a recovery of {name}: check it with them again. \
             Someone else may be trying to take their identity."
        ),
        _ => anyhow::bail!(
            "more than one recovery of {name} has that fingerprint, so it cannot tell them \
             apart: someone else may be trying to take their identity. Do not endorse or \
             confirm either until you know which is theirs."
        ),
    }
}

/// `cardinal guarding endorse NAME FINGERPRINT`: after checking with the
/// person by whatever means they trust, says a recovery is wanted.
pub async fn endorse(d: &Arc<Daemon>, who: &str, fingerprint: &str) -> anyhow::Result<Json> {
    let g = find_guarded(d, who)?;
    let w = find_wanted(d, &g, fingerprint)?;
    if !d
        .core()
        .identity
        .as_ref()
        .is_some_and(|i| w.endorsed.contains(&i.id()))
    {
        act(
            d,
            &g,
            IdentityOp::endorse(w.recovery.entry, g.position, g.salt),
        )
        .await?;
    }
    observe(d);
    Ok(list(d))
}

/// `cardinal guarding confirm NAME FINGERPRINT`: after the wait, and after
/// checking the fingerprint again with the person, confirms the recovery,
/// with this guardian's share sealed to the new device.
pub async fn confirm(d: &Arc<Daemon>, who: &str, fingerprint: &str) -> anyhow::Result<Json> {
    let g = find_guarded(d, who)?;
    // Own devices first, so this person's phone and laptop do not confirm
    // opposite decisions unawares.
    sync_own_log(d).await;
    observe(d);
    let w = find_wanted(d, &g, fingerprint)?;
    let me = my_id(d)?;
    if w.confirmed.contains(&me) {
        return Ok(list(d));
    }
    anyhow::ensure!(
        w.endorsed.len() as u64 >= g.policy.threshold,
        "{} of {} guardians have endorsed this recovery; it waits for {}",
        w.endorsed.len(),
        g.policy.commitments.len(),
        g.policy.threshold
    );
    let from = confirm_from(&load_seen(d), &g, &w).unwrap_or(u64::MAX);
    let now = now_ms();
    anyhow::ensure!(
        now >= from,
        "the wait is not over: you can confirm in {}{}",
        delay_text((from - now).div_ceil(1000)),
        if w.objected {
            " (twice the delay: one of their devices objected)"
        } else {
            ""
        }
    );
    check_chain(d, &g, &w.recovery)?;
    let share = g
        .share
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("this policy gave you no share"))?;
    let sealed = {
        let core = d.core();
        let other = core.others.get(&g.identity).expect("guarded");
        other.log.seal_share(&w.recovery, share)?
    };
    act(
        d,
        &g,
        IdentityOp::confirm(w.recovery.entry, g.position, g.salt, Some(&sealed)),
    )
    .await?;
    Ok(list(d))
}

/// The chain rule (`identity.md#guardian-decisions`): every decision under
/// the policy this guardian confirmed before is in the new one's past.
fn check_chain(d: &Daemon, g: &Guarded, recovery: &Recovery) -> anyhow::Result<()> {
    let core = d.core();
    let ident = core.identity.as_ref().expect("identity");
    let other = core.others.get(&g.identity).expect("guarded");
    chain_allows(&ident.log, &other.log, &g.salt, recovery, &g.name)
}

/// The chain rule, on this guardian's own log `mine` and the guarded log
/// `theirs`. A confirmation is under this policy if it carries this
/// guardian's salt for it, which is never used for another; one whose
/// decision is not held here is refused too, since it cannot be shown to
/// be in the new decision's past.
fn chain_allows(
    mine: &IdentityLog,
    theirs: &IdentityLog,
    salt: &[u8; 32],
    recovery: &Recovery,
    name: &str,
) -> anyhow::Result<()> {
    for e in mine.entries() {
        for op in e.ops() {
            let OpBody::Confirm {
                decision, salt: s, ..
            } = op.body()
            else {
                continue;
            };
            if s != salt || *decision == recovery.entry {
                continue;
            }
            anyhow::ensure!(
                theirs.get(decision).is_some(),
                "you confirmed a decision about {name} that this device does not hold; wait \
                 until it has their whole log"
            );
            anyhow::ensure!(
                theirs.dag().is_ancestor(decision, &recovery.entry),
                "you confirmed another decision about {name} that this recovery does not know \
                 of; confirming both would freeze their identity"
            );
        }
    }
    Ok(())
}

/// Reconciles this person's own log with their devices in touch.
async fn sync_own_log(d: &Arc<Daemon>) {
    let Some(label) = d.core().identity_label() else {
        return;
    };
    for s in d.own_sessions() {
        let r = tokio::time::timeout(Duration::from_secs(10), net::reconcile(d, &s, label)).await;
        if !matches!(r, Ok(Ok(()))) {
            tracing::debug!(
                "syncing the log with {} before confirming",
                short(&s.peer_static())
            );
        }
    }
}

/// Writes `op` in this guardian's own log, and delivers that log up to it
/// to the guarded person's devices and hosts, under the person's label.
async fn act(d: &Arc<Daemon>, g: &Guarded, op: IdentityOp) -> anyhow::Result<()> {
    let (entry, log) = {
        let mut core = d.core();
        let ident = core
            .identity
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone"))?;
        let e = ident.log.append(&d.keys.device.signing, vec![op])?;
        ident.record_own(&e)?;
        let past = ident.log.dag().ancestors(&e.id());
        let log: Vec<Vec<u8>> = ident
            .log
            .entries()
            .filter(|x| past.contains(&x.id()) || x.id() == e.id())
            .map(IdentityEntry::encode)
            .collect();
        (e, log)
    };
    d.identity_changed();
    d.push_identity(vec![entry.encode()]);
    // Held here under their label too, so that whoever syncs it with this
    // device gets it.
    d.core().ingest_other(g.identity, &log)?;
    deliver(d, &g.identity, log).await;
    observe(d);
    Ok(())
}

/// Sends a guardian's log, or a `recover`, under `guarded`'s label to that
/// person's devices in touch and this person's own.
pub(crate) async fn deliver(d: &Arc<Daemon>, guarded: &EntryId, objects: Vec<Vec<u8>>) {
    let label = identity_log_label(guarded);
    let sessions: Vec<Session> = d
        .sessions_of(guarded)
        .into_iter()
        .chain(d.own_sessions())
        .collect();
    for s in sessions {
        let sent = tokio::time::timeout(
            Duration::from_secs(10),
            net::send_objects(&s, label, objects.clone()),
        )
        .await;
        if !matches!(sent, Ok(Ok(()))) {
            tracing::debug!("delivering to {}", short(&s.peer_static()));
        }
    }
}

// ---- Help codes ----------------------------------------------------------

/// A help code: where this guardian's device is, and a secret that opens a
/// session with it for one recovery of one person.
pub struct HelpCode {
    /// Whom it helps recover.
    pub identity: EntryId,
    /// This device's X25519 static key.
    pub static_key: [u8; 32],
    /// The secret.
    pub secret: [u8; 16],
    /// Addresses to try.
    pub addrs: Vec<SocketAddr>,
}

impl HelpCode {
    /// The text form.
    pub fn to_text(&self) -> String {
        let r = Record::new()
            .with(1, self.identity)
            .with(2, self.static_key)
            .with(3, self.secret)
            .with(
                4,
                Value::list(self.addrs.iter().map(|a| Value::from(a.to_string()))),
            );
        format!(
            "{HELP_PREFIX}{}",
            cardinal_contact::invitation::base32_encode(&r.encode())
        )
    }

    /// Reads one, however it was pasted.
    pub fn from_text(s: &str) -> Option<HelpCode> {
        let body: String = s
            .trim()
            .strip_prefix(HELP_PREFIX)?
            .split_whitespace()
            .collect();
        let bytes = cardinal_contact::invitation::base32_decode(&body)?;
        let r = Record::decode(&bytes).ok()?;
        Some(HelpCode {
            identity: r.bytes_n(1).ok()?,
            static_key: r.bytes_n(2).ok()?,
            secret: r.bytes_n(3).ok()?,
            addrs: r
                .list(4)
                .ok()?
                .iter()
                .filter_map(|v| v.as_text()?.parse().ok())
                .collect(),
        })
    }
}

/// `cardinal guarding code NAME`: a code for NAME's new device, which it
/// uses to reach this device and ask it to propose their recovery.
pub fn help(d: &Arc<Daemon>, who: &str, at: &[String]) -> anyhow::Result<Json> {
    let g = find_guarded(d, who)?;
    let secret: [u8; 16] = cardinal_crypto::random_bytes();
    let mut entry = cardinal_link::SecretEntry::new(&secret);
    entry.uses = None;
    let id = d.endpoint.add_secret(entry);
    lock(&d.helping).insert(id, g.identity);
    let d2 = d.clone();
    d.rt.spawn(async move {
        tokio::time::sleep(HELP_FOR).await;
        d2.endpoint.remove_secret(id);
        lock(&d2.helping).remove(&id);
    });
    let mut addrs: Vec<SocketAddr> = Vec::new();
    for a in at {
        addrs.push(a.parse().map_err(|_| {
            anyhow::anyhow!("{a} is not an address; it looks like 192.168.1.20:7171")
        })?);
    }
    if addrs.is_empty() {
        let port = d.endpoint.tcp_addr().map_or(0, |a| a.port());
        addrs.extend(
            crate::daemon::local_ips()
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port)),
        );
        addrs.push(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    let code = HelpCode {
        identity: g.identity,
        static_key: *d.keys.link.public_key().x25519(),
        secret,
        addrs,
    };
    Ok(json!({"code": code.to_text(), "name": g.name}))
}

/// Who a help code's session is for, if it was opened with one.
pub fn helping(d: &Daemon, s: &Session) -> Option<EntryId> {
    match s.admission() {
        cardinal_link::Admission::Secret { id, .. } => lock(&d.helping).get(&id).copied(),
        _ => None,
    }
}

fn refused(why: &str) -> Value {
    Value::Record(Record::new().with(0, REFUSED).with(1, why))
}

/// Serves the help service on a help code's session: proposes a recovery,
/// and takes the `recover` the new device signed.
pub async fn serve(d: &Arc<Daemon>, s: &Session, mut st: Stream) -> anyhow::Result<()> {
    let PeerKind::Helped(identity) = d.classify(s) else {
        st.reset(0);
        return Ok(());
    };
    while let Some(v) = st.recv_message_max(64 * 1024).await? {
        let r = v
            .as_record()
            .ok_or_else(|| anyhow::anyhow!("not a record"))?;
        let reply = match r.get(0).and_then(Value::as_uint) {
            Some(ASK) => proposal(d, &identity).unwrap_or_else(|e| refused(&e.to_string())),
            Some(RECOVER) => {
                let bytes = r.bytes(1).unwrap_or_default().to_vec();
                match take_recover(d, &identity, &bytes).await {
                    Ok(()) => Value::Record(Record::new().with(0, TAKEN)),
                    Err(e) => refused(&e.to_string()),
                }
            }
            _ => break,
        };
        st.send_message(&reply).await?;
    }
    let _ = st.shutdown().await;
    Ok(())
}

/// What the new device needs to sign a `recover`: the parents, the policy,
/// and the person's keys in effect, of which it may keep some.
fn proposal(d: &Daemon, identity: &EntryId) -> anyhow::Result<Value> {
    let g = guarded(d)
        .into_iter()
        .find(|g| g.identity == *identity)
        .ok_or_else(|| anyhow::anyhow!("this device no longer guards them"))?;
    let core = d.core();
    let other = core.others.get(identity).expect("guarded");
    let current = other.log.current_policy();
    anyhow::ensure!(
        current.as_ref().map(|p| p.entry) == Some(g.policy.entry),
        "their guardians have changed"
    );
    let st = other.log.state();
    let keys = st.keys.values().map(|k| {
        Value::Record(
            Record::new()
                .with(1, k.key)
                .with_opt(2, k.link_key.as_ref().map(|l| *l.x25519()))
                .with(3, k.power.value()),
        )
    });
    Ok(Value::Record(
        Record::new()
            .with(0, PROPOSAL)
            .with(1, *identity)
            .with(
                2,
                Value::list(other.log.recovery_parents().into_iter().map(Value::from)),
            )
            .with(3, g.policy.entry)
            .with(4, Value::list(keys)),
    ))
}

/// Takes a `recover` of `identity` from its new device: appends it to the
/// log here and passes it on to the person's devices and hosts.
async fn take_recover(d: &Arc<Daemon>, identity: &EntryId, bytes: &[u8]) -> anyhow::Result<()> {
    let e = IdentityEntry::decode(bytes)?;
    anyhow::ensure!(e.identity() == *identity, "that is someone else's");
    let [op] = e.ops() else {
        anyhow::bail!("a recover is alone in its entry");
    };
    let OpBody::Recover { root, policy, .. } = op.body() else {
        anyhow::bail!("that is not a recover");
    };
    anyhow::ensure!(e.signer() == *root, "a recover is signed by its new root");
    {
        let g = guarded(d)
            .into_iter()
            .find(|g| g.identity == *identity)
            .ok_or_else(|| anyhow::anyhow!("this device no longer guards them"))?;
        anyhow::ensure!(
            *policy == g.policy.entry,
            "that recovery acts under another policy"
        );
    }
    d.core().ingest_other(*identity, &[bytes.to_vec()])?;
    tracing::info!(
        "a recovery of {} was asked for; fingerprint {}",
        short(identity),
        cardinal_identity::guardians::fingerprint(
            root,
            match op.body() {
                OpBody::Recover { link_key, .. } => link_key.as_ref(),
                _ => None,
            }
        )
    );
    deliver(d, identity, vec![bytes.to_vec()]).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cardinal_crypto::RecoveryPhrase;
    use cardinal_identity::{Created, DeviceKeys};

    #[test]
    fn a_fingerprint_two_recoveries_share_is_refused() {
        let shown = vec!["ABCDE-FGHJK".to_owned(), "ZZZZZ-00000".to_owned()];
        assert_eq!(pick_fingerprint(&shown, "abcde fghjk", "Ana").unwrap(), 0);
        assert!(pick_fingerprint(&shown, "QQQQQ-QQQQQ", "Ana").is_err());
        let twice = vec!["ABCDE-FGHJK".to_owned(), "ABCDE-FGHJK".to_owned()];
        let e = pick_fingerprint(&twice, "ABCDE-FGHJK", "Ana").unwrap_err();
        assert!(e.to_string().contains("more than one"), "{e}");
    }

    fn log(n: u8) -> (IdentityLog, DeviceKeys) {
        let d = DeviceKeys::generate();
        let Created { log, .. } = IdentityLog::create_with(
            RecoveryPhrase::from_entropy(&[n; 32]),
            &d,
            HybridKeyPair::generate(),
        )
        .unwrap();
        (log, d)
    }

    #[test]
    fn a_confirmation_of_a_decision_not_held_stops_the_chain() {
        let (theirs, _) = log(1);
        let (mut mine, me) = log(2);
        let salt = [7; 32];
        let recovery = Recovery {
            entry: [1; 32],
            root: [2; 32],
            keep: Vec::new(),
            link_key: None,
            policy: theirs.id(),
        };
        // nothing confirmed yet
        assert!(chain_allows(&mine, &theirs, &salt, &recovery, "Ana").is_ok());
        // a confirmation under another salt is another policy's
        mine.append(
            &me.signing,
            vec![IdentityOp::confirm([9; 32], 1, [8; 32], None)],
        )
        .unwrap();
        assert!(chain_allows(&mine, &theirs, &salt, &recovery, "Ana").is_ok());
        // one under this policy, of a decision this device does not hold
        mine.append(
            &me.signing,
            vec![IdentityOp::confirm([9; 32], 1, salt, None)],
        )
        .unwrap();
        let e = chain_allows(&mine, &theirs, &salt, &recovery, "Ana").unwrap_err();
        assert!(e.to_string().contains("does not hold"), "{e}");
    }
}
