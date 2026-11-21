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
//! told. `cardinal guarding` lists whom this person guards and the one
//! recovery of each it shows at a time. The person's new device makes a
//! recovery helper, an identity of its own (`helper.rs`), and meets each
//! guardian through an ordinary invitation naming, in field 9, whom it
//! recovers (`contact.md#invitations`): usually one the guardian makes
//! (`cardinal guarding invite NAME`), or one the new device makes, which
//! only a guardian's person can answer. That gives a relationship of its
//! own with each guardian, shown as "recovery for" the person and never as a
//! contact. Through it the guardian's device proposes the `recover`
//! (parents, policy, and the hosts the person's reach node names in the
//! guardian's relationship with them, each a device key of the person's
//! log) and carries the person's log; the helper carries back the signed
//! `recover` and the other guardians' acts, so that guardians who are
//! strangers see each other's endorsements without learning who the
//! others are. Each guardian, after checking the five-word fingerprint
//! with the person and being warned in plain words, endorses, waits the
//! delay from when it saw a threshold endorse, and confirms with its share
//! sealed to the new device. Endorsements and confirmations are entries in
//! the guardian's own log, delivered with that log to the person's devices
//! and hosts under the person's label (`identity.md#distribution`), and
//! carried to every helper of the recovery.
//!
//! The new device's side is `recovering.rs`.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use std::time::Duration;

use cardinal_crypto::HybridKeyPair;
use cardinal_identity::guardians::{same_fingerprint, Policy, Recovery, DEFAULT_DELAY};
use cardinal_identity::{EntryId, IdentityEntry, IdentityLog, IdentityOp, OpBody, Power};
use cardinal_link::Session;
use cardinal_space::account;
use cardinal_space::relationship::{self, ProposedHost};
use cardinal_space::{SpaceId, SpaceOp};
use cardinal_sync::identity_log_label;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};

use crate::core::{now_ms, short};
use crate::daemon::Daemon;
use crate::net;

/// What software tells a guardian, in plain words, before they endorse
/// and again before they confirm (`identity.md#how-guardians-act`, step 2).
pub fn caution(name: &str) -> String {
    format!(
        "Before you go on: this gives whoever holds that new device {name}'s whole identity. \
         It is safest done in person. Over the phone or a video call, go ahead only when you \
         are sure of the voice and the face, and after asking something only {name} would \
         know. Someone hurrying you is a reason to wait."
    )
}

/// What a second recovery of someone shows, while another is under way.
fn second_warning(name: &str, waiting: usize) -> String {
    format!(
        "{} recovery of {name} arrived while this one is under way. Someone else may be \
         trying to take their identity. Ask {name}, in person if you can, which is theirs; \
         only this one is shown until you tell this device never to confirm it \
         (`cardinal guarding never`).",
        if waiting == 1 {
            "Another"
        } else {
            "More than one other"
        }
    )
}

/// The account setting by which a guardian says never to confirm a
/// recovery, on every device of theirs: this, then the decision's id in
/// hex (`profiles.md#account`, kind 6).
pub const NEVER_SETTING: &str = "guardians: never confirm ";

/// What this device has seen as a guardian, kept across restarts: when
/// it first saw a threshold of guardians endorse each recovery, which is
/// when its wait starts (`identity.md#how-guardians-act`, step 3), and
/// when it first saw each recovery, which is the order they are shown in.
#[derive(Default, Serialize, Deserialize)]
struct Seen {
    /// Decision (hex) to milliseconds since the epoch.
    threshold: BTreeMap<String, u64>,
    /// Decision (hex) to milliseconds since the epoch.
    #[serde(default)]
    first: BTreeMap<String, u64>,
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
        if c.recovery_of.is_some() {
            continue;
        }
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

/// Whether this person guards `who`.
pub(crate) fn guards(d: &Daemon, who: &EntryId) -> bool {
    guarded(d).iter().any(|g| g.identity == *who)
}

/// A recovery invitation naming `who` is answered here only if this person
/// guards them. Anyone else's device tells its person so, and sends
/// nothing back: guardians and others look alike from outside
/// (`identity.md#how-guardians-act`).
pub(crate) fn may_answer(d: &Daemon, who: &EntryId) -> anyhow::Result<()> {
    anyhow::ensure!(
        guards(d, who),
        "that is an invitation to help someone recover their identity, and you are not one \
         of their guardians (or this device does not know you are yet). Nothing was sent \
         back. If someone asked you to use it, they may be trying to find out who guards \
         that person."
    );
    Ok(())
}

/// What a recovery's relationship is called on a guardian's devices: never
/// the helper's own name, nor a contact's.
pub(crate) fn helper_petname(d: &Daemon, who: &EntryId) -> String {
    let core = d.core();
    let name = core
        .contacts()
        .into_iter()
        .find(|c| c.identity == *who && c.recovery_of.is_none())
        .map_or_else(|| account::short_key(who), |c| c.petname);
    format!("recovery for {name}")
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

/// The recoveries this person said never to confirm, on any of their
/// devices.
fn nevers(d: &Daemon) -> HashSet<EntryId> {
    let core = d.core();
    let Some(acc) = core.account().and_then(|a| a.space.as_ref()) else {
        return HashSet::new();
    };
    account::settings(acc.state())
        .into_iter()
        .filter(|(_, v)| v.as_bool() == Some(true))
        .filter_map(|(name, _)| {
            let hex = name.strip_prefix(NEVER_SETTING)?;
            hex::decode(hex).ok()?.try_into().ok()
        })
        .collect()
}

/// The recoveries of `g`, as a guardian is shown them: the one shown, the
/// others under way that wait behind it, and those said never to. One
/// recovery of a person is shown at a time: one in effect, else the first
/// this device saw of those not said never to
/// (`identity.md#how-guardians-act`).
struct Shown {
    shown: Option<Wanted>,
    waiting: Vec<Wanted>,
    never: Vec<Wanted>,
}

fn shown(d: &Daemon, seen: &Seen, g: &Guarded) -> Shown {
    let never = nevers(d);
    let mut all = wanted(d, g);
    let first = |w: &Wanted| {
        seen.first
            .get(&hex::encode(w.recovery.entry))
            .copied()
            .unwrap_or(u64::MAX)
    };
    all.sort_by_key(|w| (!w.in_effect, first(w), w.recovery.entry));
    let (never, mut rest): (Vec<Wanted>, Vec<Wanted>) = all
        .into_iter()
        .partition(|w| never.contains(&w.recovery.entry) && !w.in_effect);
    let shown = (!rest.is_empty()).then(|| rest.remove(0));
    // once one is in effect, the others can no longer be
    if shown.as_ref().is_some_and(|w| w.in_effect) {
        rest.clear();
    }
    Shown {
        shown,
        waiting: rest,
        never,
    }
}

/// Notes when each recovery of someone this person guards was first seen,
/// and when a threshold of guardians was first seen to endorse it. Called
/// whenever a log changes.
pub fn observe(d: &Daemon) {
    // one at a time: what is seen is read, added to, and written back
    static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    let mut seen = load_seen(d);
    let mut changed = false;
    for g in guarded(d) {
        let all = wanted(d, &g);
        let under_way = |seen: &Seen| {
            all.iter()
                .filter(|w| !w.in_effect && seen.first.contains_key(&hex::encode(w.recovery.entry)))
                .count()
        };
        for w in &all {
            let key = hex::encode(w.recovery.entry);
            if !seen.first.contains_key(&key) {
                if under_way(&seen) > 0 && !w.in_effect {
                    tracing::warn!(
                        "a second recovery of {} arrived (fingerprint {}) while one is under way",
                        g.name,
                        w.recovery.fingerprint()
                    );
                }
                seen.first.insert(key.clone(), now_ms());
                changed = true;
            }
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
        d.bump();
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

/// The recovery relationships for `who`: contacts that are a recovery
/// helper of theirs, in this person's account.
fn helpers_of(d: &Daemon, who: &EntryId) -> Vec<account::ContactRecord> {
    let core = d.core();
    let mut v: Vec<_> = core
        .contacts()
        .into_iter()
        .filter(|c| c.recovery_of == Some(*who) && !c.refused)
        .collect();
    v.sort_by_key(|c| c.space);
    v
}

/// `cardinal guarding`: whom this person guards, and the recovery of each
/// shown, with any others that wait behind it.
pub fn list(d: &Daemon) -> Json {
    observe(d);
    let seen = load_seen(d);
    let me = d.core().identity.as_ref().map(|i| i.id());
    let people: Vec<Json> = guarded(d)
        .iter()
        .map(|g| {
            let s = shown(d, &seen, g);
            let mine = |set: &BTreeSet<EntryId>| me.is_some_and(|m| set.contains(&m));
            let recoveries: Vec<Json> = s
                .shown
                .iter()
                .map(|w| {
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
                        "caution": (!w.in_effect).then(|| caution(&g.name)),
                    })
                })
                .collect();
            let never: Vec<String> = s.never.iter().map(|w| w.recovery.fingerprint()).collect();
            json!({
                "name": g.name,
                "id": hex::encode(g.identity),
                "guardians": g.policy.commitments.len(),
                "threshold": g.policy.threshold,
                "delay": g.policy.delay,
                "delay_text": delay_text(g.policy.delay),
                "recoveries": recoveries,
                "waiting": s.waiting.len(),
                "warning": (!s.waiting.is_empty()).then(|| second_warning(&g.name, s.waiting.len())),
                "never": never,
                "helpers": helpers_of(d, &g.identity).len(),
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

/// The recovery of `g` the person means, by the fingerprint they read: the
/// one shown. One that waits behind it, or one said never to, is refused,
/// with why.
fn find_wanted(d: &Daemon, g: &Guarded, fingerprint: &str) -> anyhow::Result<Wanted> {
    let s = shown(d, &load_seen(d), g);
    anyhow::ensure!(
        s.shown.is_some() || !s.never.is_empty(),
        "nobody has asked to recover {}",
        g.name
    );
    let matches = |ws: &[Wanted]| {
        ws.iter()
            .any(|w| same_fingerprint(fingerprint, &w.recovery.fingerprint()))
    };
    anyhow::ensure!(
        !matches(&s.never),
        "you told this device never to confirm that recovery of {}",
        g.name
    );
    anyhow::ensure!(
        !matches(&s.waiting),
        "that is another recovery of {name}, which waits while one is under way. If the one \
         under way is not theirs, tell this device never to confirm it (`cardinal guarding \
         never {name} FINGERPRINT`).",
        name = g.name
    );
    let mut shown: Vec<Wanted> = s.shown.into_iter().collect();
    let fps: Vec<String> = shown.iter().map(|w| w.recovery.fingerprint()).collect();
    let at = pick_fingerprint(&fps, fingerprint, &g.name)?;
    Ok(shown.swap_remove(at))
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
    // opposite decisions unawares, nor one said never to on the other.
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

/// `cardinal guarding never NAME FINGERPRINT`: the person asked that a
/// recovery be started over (their new device was lost before it took
/// effect), so this guardian never endorses or confirms the old one, on
/// any of their devices (`identity.md#how-guardians-act`).
pub fn never(d: &Arc<Daemon>, who: &str, fingerprint: &str) -> anyhow::Result<Json> {
    let g = find_guarded(d, who)?;
    let all = wanted(d, &g);
    let fps: Vec<String> = all.iter().map(|w| w.recovery.fingerprint()).collect();
    let w = &all[pick_fingerprint(&fps, fingerprint, &g.name)?];
    anyhow::ensure!(
        !w.in_effect,
        "that recovery of {} is in effect already; nothing undoes it",
        g.name
    );
    if !nevers(d).contains(&w.recovery.entry) {
        let acc = d
            .core()
            .account_id()
            .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
        let name = format!("{NEVER_SETTING}{}", hex::encode(w.recovery.entry));
        d.write_and_push(&acc, vec![account::create_setting(&name, true)])?;
    }
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

/// Reconciles this person's own log, and their account, with their devices
/// in touch.
async fn sync_own_log(d: &Arc<Daemon>) {
    let labels: Vec<[u8; 32]> = {
        let core = d.core();
        core.identity_label()
            .into_iter()
            .chain(core.account_id())
            .collect()
    };
    for s in d.own_sessions() {
        for label in &labels {
            let r =
                tokio::time::timeout(Duration::from_secs(10), net::reconcile(d, &s, *label)).await;
            if !matches!(r, Ok(Ok(()))) {
                tracing::debug!("syncing with {} before confirming", short(&s.peer_static()));
            }
        }
    }
}

/// Writes `op` in this guardian's own log, and delivers that log up to it
/// to the guarded person's devices and hosts, under the person's label,
/// and to every recovery helper of theirs.
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
    for c in helpers_of(d, &g.identity) {
        if let Err(e) = carry(d, &c.space, &g.identity, &log) {
            tracing::debug!("carrying to a recovery helper: {e:#}");
        }
    }
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

// ---- Recovery relationships ---------------------------------------------

/// The most an entry written to carry identity entries holds, so that a
/// contact's device takes it whole (`mailbox::TOKEN_MESSAGE`).
const CARRY_BATCH: usize = 32 * 1024;

/// Writes in a relationship space, as `carried` nodes, each of `entries`
/// that is not there yet, whoever carried it. `recovered` is whom the
/// recovery is of.
pub(crate) fn carry(
    d: &Arc<Daemon>,
    space: &SpaceId,
    recovered: &EntryId,
    entries: &[Vec<u8>],
) -> anyhow::Result<usize> {
    let ops: Vec<SpaceOp> = {
        let core = d.core();
        let Some(sp) = core.spaces.get(space).and_then(|h| h.space.as_ref()) else {
            return Ok(0);
        };
        let mut there: HashSet<EntryId> = relationship::carried(sp)
            .iter()
            .filter_map(|c| IdentityEntry::decode(&c.entry).ok())
            .map(|e| e.id())
            .collect();
        entries
            .iter()
            .filter_map(|b| {
                let id = IdentityEntry::decode(b).ok()?.id();
                there
                    .insert(id)
                    .then(|| relationship::create_carried(recovered, b))
            })
            .collect()
    };
    let n = ops.len();
    let mut batch = Vec::new();
    let mut size = 0;
    for op in ops {
        let len = op.record().encode().len();
        if !batch.is_empty() && size + len > CARRY_BATCH {
            d.write_and_push(space, std::mem::take(&mut batch))?;
            size = 0;
        }
        size += len;
        batch.push(op);
    }
    if !batch.is_empty() {
        d.write_and_push(space, batch)?;
    }
    Ok(n)
}

/// `cardinal guarding invite NAME [--address ADDR]`: an invitation for
/// NAME's new device, naming NAME in field 9, so that it meets this
/// guardian in a relationship of its own. Like any invitation, it is kept
/// in the account space, so every device of this person answers it.
pub fn invite(d: &Arc<Daemon>, who: &str, at: Option<&str>) -> anyhow::Result<Json> {
    let g = find_guarded(d, who)?;
    let invitation = crate::contacts::invite_recovery(d, at, g.identity)?;
    Ok(json!({"code": invitation.to_text(), "name": g.name}))
}

/// The proposal this guardian's device makes for a recovery of `g`
/// (`identity.md#how-guardians-act`, step 1): parents the person
/// recognizes, the policy, and the person's hosts, those the person's
/// reach node names in this person's relationship with them, each matched
/// by its static key to a device key their log names. A host their log
/// does not name is left out.
fn proposal(d: &Daemon, g: &Guarded) -> anyhow::Result<SpaceOp> {
    let core = d.core();
    let other = core
        .others
        .get(&g.identity)
        .ok_or_else(|| anyhow::anyhow!("their log is not here"))?;
    let current = other.log.current_policy();
    anyhow::ensure!(
        current.as_ref().map(|p| p.entry) == Some(g.policy.entry),
        "their guardians have changed"
    );
    let st = other.log.state();
    let space = core
        .contacts()
        .into_iter()
        .find(|c| c.identity == g.identity && c.recovery_of.is_none())
        .map(|c| c.space);
    let reach = space
        .map(|s| core.reach_of(&s, &g.identity))
        .unwrap_or_default();
    let mut hosts: Vec<ProposedHost> = reach
        .into_iter()
        .filter_map(|r| {
            let k = st
                .keys
                .values()
                .find(|k| k.link_key.as_ref().map(|l| *l.x25519()) == Some(r.host))?;
            Some(ProposedHost {
                key: k.key,
                host: r.host,
                endpoints: r.endpoints,
            })
        })
        .collect();
    // Tests: a guardian who tries to bring in a device of their own.
    if std::env::var_os("CARDINAL_TEST_PROPOSE_OWN_DEVICE").is_some() {
        let at = d
            .endpoint
            .udp_addr()
            .or(d.endpoint.tcp_addr())
            .and_then(|a| cardinal_space::grant::Endpoint::parse(&a.to_string()));
        hosts.push(ProposedHost {
            key: d.keys.key(),
            host: *d.keys.link.public_key().x25519(),
            endpoints: at.into_iter().collect(),
        });
    }
    Ok(relationship::create_proposal(
        &g.identity,
        &other.log.recovery_parents(),
        &g.policy.entry,
        &hosts,
    ))
}

/// After a recovery relationship for `who` was made, on a guardian's
/// device: proposes the recovery in it, unless this person proposed one
/// there already, and carries the person's log, so that the new device
/// can check what it signs and, with no host, take the identity up from
/// it.
pub(crate) fn met_helper(d: &Arc<Daemon>, space: &SpaceId, who: &EntryId) {
    let Some(g) = guarded(d).into_iter().rev().find(|g| g.identity == *who) else {
        return;
    };
    let me = d.core().me();
    let proposed = {
        let core = d.core();
        core.spaces
            .get(space)
            .and_then(|h| h.space.as_ref())
            .is_some_and(|sp| {
                relationship::proposals(sp)
                    .iter()
                    .any(|p| Some(p.author) == me && p.identity == *who)
            })
    };
    if !proposed {
        match proposal(d, &g) {
            Ok(op) => {
                if let Err(e) = d.write_and_push(space, vec![op]) {
                    tracing::warn!("cannot propose the recovery of {}: {e:#}", g.name);
                }
            }
            Err(e) => tracing::warn!("cannot propose the recovery of {}: {e:#}", g.name),
        }
    }
    let log: Vec<Vec<u8>> = {
        let core = d.core();
        core.others
            .get(who)
            .map(|o| o.log.entries().map(IdentityEntry::encode).collect())
            .unwrap_or_default()
    };
    if let Err(e) = carry(d, space, who, &log) {
        tracing::warn!("cannot carry {}'s log to their new device: {e:#}", g.name);
    }
    tracing::info!("a recovery helper of {} is in touch", g.name);
}

/// After entries of a space arrived: if it is a recovery relationship for
/// someone this person guards, takes what the helper carried. Of the
/// person's own log only a `recover` is taken, alone in its entry, signed
/// by its new root, under the policy this person guards; of anyone else's,
/// what [`crate::core::Core::ingest_other`] keeps, the causal past of
/// another guardian's act. What is new here goes on to the person's
/// devices and hosts, as a guardian's act does.
pub fn on_space(d: &Arc<Daemon>, space: &SpaceId) {
    let (helper, who) = {
        let core = d.core();
        let Some(c) = core
            .contacts()
            .into_iter()
            .find(|c| c.space == *space && c.recovery_of.is_some())
        else {
            return;
        };
        (c.identity, c.recovery_of.expect("checked"))
    };
    let Some(g) = guarded(d).into_iter().rev().find(|g| g.identity == who) else {
        return;
    };
    let label = identity_log_label(&who);
    let new: Vec<Vec<u8>> = {
        let core = d.core();
        let Some(sp) = core.spaces.get(space).and_then(|h| h.space.as_ref()) else {
            return;
        };
        relationship::carried(sp)
            .into_iter()
            .filter(|c| c.author == helper && c.identity == who)
            .filter_map(|c| {
                let e = IdentityEntry::decode(&c.entry).ok()?;
                if core.has(&label, &e.id()) {
                    return None;
                }
                (e.identity() != who || is_recover_under(&e, &g.policy.entry)).then_some(c.entry)
            })
            .collect()
    };
    if new.is_empty() {
        return;
    }
    let taken: Vec<Vec<u8>> = {
        let mut core = d.core();
        if let Err(e) = core.ingest_other(who, &new) {
            tracing::debug!("what a recovery helper carried: {e:#}");
            return;
        }
        new.into_iter()
            .filter(|b| IdentityEntry::decode(b).is_ok_and(|e| core.has(&label, &e.id())))
            .collect()
    };
    if taken.is_empty() {
        return;
    }
    for b in &taken {
        if let Some(r) = IdentityEntry::decode(b)
            .ok()
            .filter(|e| e.identity() == who)
            .and_then(|e| recovery_of_entry(&e))
        {
            tracing::info!(
                "a recovery of {} was asked for; fingerprint {}",
                g.name,
                r.fingerprint()
            );
        }
    }
    observe(d);
    d.bump();
    let d2 = d.clone();
    d.rt.spawn(async move { deliver(&d2, &who, taken).await });
}

/// The `recover` an entry is, if it is one alone, signed by its new root.
fn recovery_of_entry(e: &IdentityEntry) -> Option<Recovery> {
    let [op] = e.ops() else {
        return None;
    };
    let OpBody::Recover {
        root,
        keep,
        link_key,
        policy,
        ..
    } = op.body()
    else {
        return None;
    };
    (e.signer() == *root).then(|| Recovery {
        entry: e.id(),
        root: *root,
        keep: keep.clone(),
        link_key: link_key.clone(),
        policy: *policy,
    })
}

fn is_recover_under(e: &IdentityEntry, policy: &EntryId) -> bool {
    recovery_of_entry(e).is_some_and(|r| r.policy == *policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cardinal_crypto::RecoveryPhrase;
    use cardinal_identity::{Created, DeviceKeys};

    #[test]
    fn a_fingerprint_two_recoveries_share_is_refused() {
        let one = "abandon ability able about above";
        let shown = vec![one.to_owned(), "zoo zone wrist youth young".to_owned()];
        assert_eq!(
            pick_fingerprint(&shown, "ABAN abil ABLE abou abov", "Ana").unwrap(),
            0
        );
        assert!(pick_fingerprint(&shown, "abandon ability able about absent", "Ana").is_err());
        let twice = vec![one.to_owned(), one.to_owned()];
        let e = pick_fingerprint(&twice, one, "Ana").unwrap_err();
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
