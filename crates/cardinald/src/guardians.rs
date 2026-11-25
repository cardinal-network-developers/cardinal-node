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
use cardinal_space::relationship;
use cardinal_space::{SpaceId, SpaceOp};
use cardinal_sync::identity_log_label;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};

use crate::core::{now_ms, short};
use crate::daemon::Daemon;
use crate::helper::Helper;
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
         only this one is shown until you say never to confirm it.",
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
    /// The personas a policy named, as `persona:policy` (hex), so that one
    /// a later policy no longer names is burned.
    #[serde(default)]
    named: BTreeSet<String>,
    /// The people (hex) whose current policy no longer names the persona
    /// this person guarded them through, and who are guarded through no
    /// other, to when it was seen: "Ana no longer needs you as a guardian".
    #[serde(default)]
    no_longer: BTreeMap<String, u64>,
    /// The copies this device took to hold for someone, as `person:label`
    /// (hex): dropped when the persona goes, even once the person's
    /// devices have taken back the node that named them.
    #[serde(default)]
    held: BTreeSet<String>,
}

/// One at a time: what is seen is read, added to, and written back.
static SEEN: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

pub fn delay_text(secs: u64) -> String {
    let (n, unit) = match secs {
        s if s % 86_400 == 0 && s > 0 => (s / 86_400, "day"),
        s if s % 3600 == 0 && s > 0 => (s / 3600, "hour"),
        s if s % 60 == 0 && s > 0 => (s / 60, "minute"),
        s => (s, "second"),
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

// ---- The person ----------------------------------------------------------

/// `cardinal guardians`: who guards this person, as their own devices know
/// it from the account space, and the policy as everyone sees it.
pub fn show(d: &Daemon) -> anyhow::Result<Json> {
    // whom this person asked, and who accepted, ready to be named
    let (asked, ready) = {
        let contacts: Vec<account::ContactRecord> = d
            .core()
            .contacts()
            .into_iter()
            .filter(|c| c.recovery_of.is_none() && !c.refused)
            .collect();
        let mut asked = Vec::new();
        let mut ready = Vec::new();
        for c in contacts {
            if persona_of(&d.core(), &c).is_some() {
                ready.push(c.petname.clone());
            } else if asked_already(d, &c) {
                asked.push(c.petname.clone());
            }
        }
        (asked, ready)
    };
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
    // whom each change names, and when this person made it
    let made: Vec<account::GuardiansRecord> = core
        .account()
        .and_then(|a| a.space.as_ref())
        .map(|sp| account::guardians_named(sp.state()))
        .unwrap_or_default();
    let contacts = core.contacts();
    let changes: Vec<Json> = policy
        .as_ref()
        .map(|cur| {
            changes_of(&ident.log, &cur.entry)
                .into_iter()
                .filter(|(id, _)| !st.in_effect.contains(id))
                .map(|(id, p)| {
                    let (names, since) = made
                        .iter()
                        .find(|g| g.policy == id)
                        .map(|g| {
                            let names: Vec<String> = g
                                .named
                                .iter()
                                .filter_map(|(c, _)| {
                                    contacts
                                        .iter()
                                        .find(|x| x.identity == *c)
                                        .map(|x| x.petname.clone())
                                })
                                .collect();
                            (names, g.made)
                        })
                        .unwrap_or_default();
                    let objected = objected(&ident.log, &id);
                    let wait = cur.delay.saturating_mul(if objected { 2 } else { 1 });
                    json!({
                        "fingerprint": change_fingerprint(&p),
                        "names": names,
                        "guardians": p.commitments.len(),
                        "threshold": p.threshold,
                        // the change's own delay, for recoveries under it,
                        // and the wait before its guardians confirm it,
                        // which is the current policy's
                        "delay": p.delay,
                        "delay_text": delay_text(p.delay),
                        "confirm_delay": wait,
                        "confirm_delay_text": delay_text(wait),
                        "confirmed": ident.log.confirmed_by(&id, cur, &others).len(),
                        "needed": cur.threshold,
                        // when this person made it, plus the wait: each
                        // guardian waits from when their device saw it
                        "waits_until_ms": since.map(|t| t.saturating_add(wait.saturating_mul(1000))),
                        "objected": objected,
                        "id": hex::encode(id),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let full: Vec<String> = core
        .contacts()
        .into_iter()
        .filter(|c| c.guardian)
        .filter(|c| {
            core.spaces
                .get(&c.space)
                .and_then(|h| h.space.as_ref())
                .is_some_and(|sp| {
                    relationship::held_full(sp)
                        .iter()
                        .any(|(a, l)| *a == c.identity && core.account_id() == Some(*l))
                })
        })
        .map(|c| c.petname)
        .collect();
    Ok(json!({
        "asked": asked,
        "ready": ready,
        "copy_full": full,
        "changes": changes,
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
    // One change at a time: a change under way takes effect, or the person
    // gives it up by objecting to it, before another is made.
    {
        let core = d.core();
        let ident = core
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone"))?;
        let st = ident.state();
        if let Some(cur) = ident.log.current_policy() {
            let pending = changes_of(&ident.log, &cur.entry)
                .into_iter()
                .find(|(id, _)| !st.in_effect.contains(id) && !objected(&ident.log, id));
            if let Some((_, p)) = pending {
                anyhow::bail!(
                    "a change of your guardians is under way (fingerprint \"{fp}\"): it must \
                     take effect first, or you give it up by objecting to it",
                    fp = change_fingerprint(&p)
                );
            }
        }
    }
    let mut chosen = Vec::new();
    for w in who {
        let c = crate::contacts::find(d, w)?;
        anyhow::ensure!(
            c.connects(),
            "{} is not someone you trust: a guardian must be",
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
    let (unguarded, named, missing) = {
        let core = d.core();
        let ident = core
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone"))?;
        let policy = ident
            .log
            .current_policy()
            .ok_or_else(|| anyhow::anyhow!("your identity has no recovery policy in effect"))?;
        // Each guardian is named by the persona they made for guarding this
        // person, in the relationship the two share (D79).
        let mut named = Vec::new();
        let mut missing = Vec::new();
        for c in &chosen {
            match persona_of(&core, c) {
                Some(p) => named.push(p),
                None => missing.push(c.clone()),
            }
        }
        (!policy.guarded(), named, missing)
    };
    if !missing.is_empty() {
        // Each who has no persona to be named with is asked, now: a
        // guardian named again accepts again, with a fresh one.
        for c in &missing {
            if !asked_already(d, c) {
                d.write_and_push(&c.space, vec![relationship::create_guardian_request()])?;
            }
        }
        let names: Vec<String> = missing.iter().map(|c| c.petname.clone()).collect();
        anyhow::bail!(
            "{} must accept being your guardian{} first. They have been asked; once they \
             have accepted, and your devices have been in touch with theirs, try again.",
            names.join(", "),
            if names.len() > 1 { "s" } else { "" }
        );
    }
    // The first guardians are named by the policy's controller, the root;
    // a change, by any key of this person's, and the guardians in office
    // decide it (`identity.md#guardian-decisions`).
    let root = match unguarded {
        true => Some(
            crate::recovery::signer(
                d,
                words,
                |_| false,
                || "your first guardians are named with your recovery words".to_owned(),
            )?
            .expect("asked for the words"),
        ),
        false => None,
    };
    let acc = d
        .core()
        .account_id()
        .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
    let pairs: Vec<([u8; 32], [u8; 32])> = chosen
        .iter()
        .zip(&named)
        .map(|(c, (p, _))| (c.identity, *p))
        .collect();
    let (entries, written) = {
        let mut core = d.core();
        let ident = core.identity.as_mut().expect("identity");
        let current = ident
            .enc
            .first()
            .map(|k| HybridKeyPair::from_secret_bytes(&k.secret_bytes()));
        let author = root.as_ref().unwrap_or(&d.keys.device.signing);
        let e1 = ident
            .log
            .set_guardians(author, &named, threshold, delay, true, current.as_ref())
            .map_err(|e| anyhow::anyhow!("cannot name these guardians: {e}"))?;
        // Whom it names, kept in the account before the entry itself, so
        // that a stop between the two never leaves a policy nobody here
        // can map to its guardians.
        let written = core.write(&acc, vec![account::create_guardians(&e1.id(), &pairs)])?;
        let ident = core.identity.as_mut().expect("identity");
        ident.record_own(&e1)?;
        let mut entries = vec![e1.encode()];
        if let Some(root) = &root {
            // After a change of guardians, a fresh encryption key, wrapped to
            // the new guardian key (`identity.md#the-identity-encryption-key`).
            // A change waits for its guardians: [`tend_person`] does it then.
            let mine = ident.state().power(&d.keys.key());
            let signer = if mine >= Some(Power::Admin) {
                &d.keys.device.signing
            } else {
                root
            };
            let fresh = HybridKeyPair::generate();
            let e2 = ident
                .log
                .set_encryption_key(signer, &fresh, current.as_ref())?;
            ident.record_own(&e2)?;
            entries.push(e2.encode());
        }
        (entries, written)
    };
    d.push(&acc, written.into_iter().map(|(_, b)| b).collect());
    d.identity_changed();
    d.push_identity(entries);
    // The first guardians are in office at once: marked, and given the
    // account, the same way a change's are once it is in effect.
    tend_person(d);
    tell_full(d);
    crate::recovering::tend_recovered(d);
    Ok(json!({
        "names": chosen.iter().map(|c| c.petname.clone()).collect::<Vec<_>>(),
        "threshold": threshold,
        "delay": delay,
        "delay_text": delay_text(delay),
        "pending": !unguarded,
    }))
}

/// The account setting by which a person's devices say a policy's
/// guardians were marked and given the account, and the key rotated.
pub const APPLIED_SETTING: &str = "guardians: applied ";

/// The policies this person named, by entry, with the contact and persona
/// of each guardian.
fn named_policies(core: &crate::core::Core) -> Vec<(EntryId, Vec<(EntryId, EntryId)>)> {
    let Some(acc) = core.account().and_then(|a| a.space.as_ref()) else {
        return Vec::new();
    };
    account::guardians_named(acc.state())
        .into_iter()
        .map(|g| (g.policy, g.named))
        .collect()
}

/// After this person's policy changed: once a change they made is in
/// effect, marks its guardians in the account, gives them the account,
/// takes it back from the others, and sets a fresh encryption key wrapped
/// to the new guardian key (`identity.md#the-identity-encryption-key`).
fn tend_person(d: &Arc<Daemon>) {
    let (current, named, applied, acc, admin, rotated_since) = {
        let core = d.core();
        let Some(ident) = core.identity.as_ref() else {
            return;
        };
        let st = ident.state();
        let admin = st.power(&d.keys.key()) >= Some(Power::Admin);
        let Some(current) = ident.log.current_policy().map(|p| p.entry) else {
            return;
        };
        let named = named_policies(&core)
            .into_iter()
            .find(|(p, _)| *p == current)
            .map(|(_, v)| v);
        let applied = core
            .account()
            .and_then(|a| a.space.as_ref())
            .is_some_and(|sp| {
                account::settings(sp.state()).iter().any(|(n, _)| {
                    n.strip_prefix(APPLIED_SETTING) == Some(hex::encode(current).as_str())
                })
            });
        // a fresh key after this policy already: never set twice
        let rotated_since = ident.log.entries().any(|e| {
            st.is_valid(&e.id())
                && ident.log.dag().is_ancestor(&current, &e.id())
                && e.ops()
                    .iter()
                    .any(|o| matches!(o.body(), OpBody::SetEncryptionKey { .. }))
        });
        (
            current,
            named,
            applied,
            core.account_id(),
            admin,
            rotated_since,
        )
    };
    // only an admin device, and once
    let (Some(named), false, Some(acc), true) = (named, applied, acc, admin) else {
        return;
    };
    // each named contact whose relationship holds the persona they gave
    let chosen: Vec<account::ContactRecord> = {
        let core = d.core();
        core.contacts()
            .into_iter()
            .filter(|c| {
                named.iter().any(|(id, persona)| {
                    *id == c.identity
                        && core
                            .spaces
                            .get(&c.space)
                            .and_then(|h| h.space.as_ref())
                            .is_some_and(|sp| {
                                relationship::guardian_personas(sp)
                                    .iter()
                                    .any(|n| n.author == c.identity && n.persona == *persona)
                            })
                })
            })
            .collect()
    };
    if !rotated_since {
        let rotated = {
            let mut core = d.core();
            let Some(ident) = core.identity.as_mut() else {
                return;
            };
            let current_key = ident
                .enc
                .first()
                .map(|k| HybridKeyPair::from_secret_bytes(&k.secret_bytes()));
            let fresh = HybridKeyPair::generate();
            match ident
                .log
                .set_encryption_key(&d.keys.device.signing, &fresh, current_key.as_ref())
                .map_err(anyhow::Error::from)
                .and_then(|e| ident.record_own(&e).map(|()| e))
            {
                Ok(e) => e.encode(),
                Err(e) => {
                    tracing::warn!("cannot set a fresh key for the new guardians: {e:#}");
                    return;
                }
            }
        };
        d.identity_changed();
        d.push_identity(vec![rotated]);
    }
    // each step done again harmlessly, should this stop before the end
    let r = mark_guardians(d, &chosen).and_then(|()| give_account(d, &chosen));
    if let Err(e) = r {
        tracing::warn!("giving the new guardians the account: {e:#}");
        return;
    }
    let _ = d.write_and_push(
        &acc,
        vec![account::create_setting(
            &format!("{APPLIED_SETTING}{}", hex::encode(current)),
            true,
        )],
    );
    tracing::info!("the new guardians are in office");
}

/// Tells the person, in the relationship, of each copy held for them that
/// reached the cap and no longer updates, once; and says so here.
fn tell_full(d: &Arc<Daemon>) {
    let me = d.core().me();
    let Some(me) = me else {
        return;
    };
    for p in my_personas(d) {
        let Some(who) = p.for_identity else {
            continue;
        };
        let todo: Option<(SpaceId, [u8; 32])> = {
            let core = d.core();
            let c = core
                .contacts()
                .into_iter()
                .find(|c| c.identity == who && c.recovery_of.is_none());
            c.and_then(|c| {
                let label = core.held_named_by(&who).into_iter().next()?;
                let full = core.held_full(&label);
                let told = core
                    .spaces
                    .get(&c.space)
                    .and_then(|h| h.space.as_ref())
                    .is_some_and(|sp| relationship::held_full(sp).contains(&(me, label)));
                (full && !told).then_some((c.space, label))
            })
        };
        if let Some((space, label)) = todo {
            tracing::warn!(
                "the copy held for {} is full ({} MiB) and no longer updates",
                short(&who),
                crate::core::HELD_CAP >> 20
            );
            let _ = d.write_and_push(&space, vec![relationship::create_held_full(&label)]);
        }
    }
}

/// Whether this person's request that `c` guard them waits for an answer:
/// newer than the last guardian persona node `c` wrote.
fn asked_already(d: &Daemon, c: &account::ContactRecord) -> bool {
    let core = d.core();
    let me = core.me();
    core.spaces
        .get(&c.space)
        .and_then(|h| h.space.as_ref())
        .is_some_and(|sp| {
            let asked = relationship::guardian_requests(sp)
                .into_iter()
                .filter(|(a, _)| Some(*a) == me)
                .map(|(_, at)| at)
                .max();
            matches!(asked, Some(a) if a > relationship::guardian_persona_at(sp, &c.identity))
        })
}

/// `cardinal guardians ask NAME`: asks a contact to guard this person, in
/// the relationship the two share. Their device shows it, and their
/// `guarding accept` answers it with a fresh persona.
pub fn ask(d: &Arc<Daemon>, who: &str) -> anyhow::Result<Json> {
    let c = crate::contacts::find(d, who)?;
    anyhow::ensure!(
        c.connects(),
        "{} is not someone you trust: a guardian must be",
        c.petname
    );
    d.write_and_push(&c.space, vec![relationship::create_guardian_request()])?;
    Ok(json!({"name": c.petname}))
}

/// The persona `c` guards this person through, from the guardian persona
/// node they wrote in the relationship the two share, and its encryption
/// key, from the log it carries.
fn persona_of(
    core: &crate::core::Core,
    c: &account::ContactRecord,
) -> Option<(EntryId, cardinal_crypto::HybridPublicKey)> {
    let sp = core.spaces.get(&c.space)?.space.as_ref()?;
    // a fresh one: never named by a policy of this person's that is in
    // effect or still under way; one named only by a change given up (an
    // objection, and never in effect) serves again
    let used: HashSet<EntryId> = {
        let ident = core.identity.as_ref()?;
        let st = ident.state();
        named_policies(core)
            .into_iter()
            .filter(|(p, _)| st.in_effect.contains(p) || !objected(&ident.log, p))
            .flat_map(|(_, v)| v.into_iter().map(|(_, p)| p))
            .collect()
    };
    let p = relationship::guardian_personas(sp)
        .into_iter()
        .find(|p| p.author == c.identity && !used.contains(&p.persona))?;
    let log = log_from(&p.log, &p.persona)?;
    let key = log.state().encryption_key.as_ref()?.public.clone();
    Some((p.persona, key))
}

/// A log from its entries, in any order.
pub(crate) fn log_from(entries: &[Vec<u8>], id: &EntryId) -> Option<IdentityLog> {
    let decoded: Vec<IdentityEntry> = entries
        .iter()
        .filter_map(|b| IdentityEntry::decode(b).ok())
        .collect();
    let genesis = decoded.iter().find(|e| e.is_genesis() && e.id() == *id)?;
    let mut log = IdentityLog::from_genesis(genesis.clone()).ok()?;
    for e in &decoded {
        if e.id() != *id {
            let _ = log.insert_any(e.clone());
        }
    }
    Some(log)
}

/// Gives each guardian a sealed copy of the account, which they cannot
/// read (D80): a held copy node naming it in the relationship the two
/// share, once; their devices then keep it current as the two sync.
fn give_account(d: &Arc<Daemon>, chosen: &[account::ContactRecord]) -> anyhow::Result<()> {
    let (acc, me) = {
        let core = d.core();
        (core.account_id(), core.me())
    };
    let (Some(acc), Some(me)) = (acc, me) else {
        return Ok(());
    };
    for c in chosen {
        let given = {
            let core = d.core();
            core.spaces
                .get(&c.space)
                .and_then(|h| h.space.as_ref())
                .is_some_and(|sp| relationship::held(sp).contains(&(me, acc)))
        };
        if !given {
            d.write_and_push(&c.space, vec![relationship::create_held(&acc)])?;
        }
        // and the copy itself, now, to whichever of their devices is in touch
        let (d2, who) = (d.clone(), c.identity);
        d.rt.spawn(async move { sync_label(&d2, &who, &acc).await });
    }
    Ok(())
}

/// After entries of a relationship space arrived: fetches the copies the
/// other member gives this person to hold there, if this person takes
/// them (a guardian through a persona, or a recovery helper).
pub fn held_named(d: &Arc<Daemon>, space: &SpaceId) {
    let (who, labels) = {
        let core = d.core();
        let Some(c) = core.contacts().into_iter().find(|c| c.space == *space) else {
            return;
        };
        (c.identity, core.held_taken(&c.identity))
    };
    if labels.is_empty() {
        return;
    }
    // Over a session as contacts: one an invitation opened reaches only the
    // relationship (`contact.md#accepting`). A session as contacts is
    // opened to the same device, which replaces it once it is up, and syncs
    // the copies; until then the invitation's stays.
    let (contact, inviting) = d.contact_and_inviting(&who);
    if contact.is_empty() {
        for s in inviting {
            let d2 = d.clone();
            d.rt.spawn(async move { replace_session(&d2, &who, s).await });
        }
        return;
    }
    for l in labels {
        let d2 = d.clone();
        d.rt.spawn(async move { sync_label(&d2, &who, &l).await });
    }
}

/// Opens a session as contacts with the device at the other end of `old`,
/// one of `who`'s, at the address it was reached at, and lets it replace
/// `old` once it is up. `old` stays if it cannot be opened.
async fn replace_session(d: &Arc<Daemon>, who: &EntryId, old: Session) {
    let static_key = old.peer_static();
    // one dial at a time to each device
    static DIALING: std::sync::Mutex<BTreeSet<[u8; 32]>> = std::sync::Mutex::new(BTreeSet::new());
    if !DIALING
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(static_key)
    {
        return;
    }
    replace_session_now(d, who, &old, static_key).await;
    DIALING
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&static_key);
}

async fn replace_session_now(d: &Arc<Daemon>, who: &EntryId, old: &Session, static_key: [u8; 32]) {
    let Some(addr) = old.remote_addr() else {
        return;
    };
    let key = {
        let core = d.core();
        core.others.get(who).and_then(|o| {
            o.log
                .state()
                .keys
                .values()
                .find_map(|k| k.link_key.clone().filter(|l| *l.x25519() == static_key))
        })
    };
    let Some(key) = key else {
        return;
    };
    match d.dial(|c| cardinal_link::Target::new(addr, c, &key)).await {
        Ok(s) => d.on_session(s),
        Err(e) => tracing::debug!("a session as contacts with {}: {e}", short(who)),
    }
}

/// Reconciles a set with `who`'s devices in touch, ten seconds at most
/// each.
async fn sync_label(d: &Arc<Daemon>, who: &EntryId, label: &[u8; 32]) {
    for s in d.sessions_of(who) {
        let r = tokio::time::timeout(Duration::from_secs(10), net::reconcile(d, &s, *label)).await;
        if !matches!(r, Ok(Ok(()))) {
            tracing::debug!("syncing a held copy with {}", short(&s.peer_static()));
        }
    }
}

/// Marks the guardians in the account space, and nobody else.
fn mark_guardians(d: &Arc<Daemon>, chosen: &[account::ContactRecord]) -> anyhow::Result<()> {
    let Some(acc) = d.core().account_id() else {
        return Ok(());
    };
    // each contact whose records say otherwise, merged if they are two
    let ops: Vec<_> = {
        let core = d.core();
        let mut whom: Vec<([u8; 32], bool)> = core
            .contacts()
            .into_iter()
            .filter(|c| c.recovery_of.is_none())
            .filter_map(|c| {
                let now = chosen.iter().any(|x| x.identity == c.identity);
                (now != c.guardian).then_some((c.identity, now))
            })
            .collect();
        whom.sort();
        whom.dedup();
        whom.into_iter()
            .flat_map(|(who, now)| core.contact_ops(&who, &[(account::GUARDIAN, Some(now.into()))]))
            .collect()
    };
    if !ops.is_empty() {
        d.write_and_push(&acc, ops)?;
    }
    // and the copy of the account, from those no longer guardians
    let (me, former): (Option<EntryId>, Vec<account::ContactRecord>) = {
        let core = d.core();
        let former = core
            .contacts()
            .into_iter()
            .filter(|c| c.recovery_of.is_none() && !chosen.iter().any(|x| x.identity == c.identity))
            .collect();
        (core.me(), former)
    };
    let Some(me) = me else {
        return Ok(());
    };
    for c in former {
        let node = {
            let core = d.core();
            core.spaces
                .get(&c.space)
                .and_then(|h| h.space.as_ref())
                .and_then(|sp| relationship::held_node(sp, &me, &acc))
        };
        if let Some(node) = node {
            d.write_and_push(&c.space, vec![cardinal_space::SpaceOp::delete(node)])?;
        }
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
        // a recovery under way, or a change of guardians
        let mut pending: Vec<(EntryId, String)> = ident
            .log
            .recoveries()
            .into_iter()
            .filter(|r| !st.in_effect.contains(&r.entry))
            .map(|r| (r.entry, r.fingerprint()))
            .collect();
        if let Some(cur) = ident.log.current_policy() {
            pending.extend(
                changes_of(&ident.log, &cur.entry)
                    .into_iter()
                    .filter(|(id, _)| !st.in_effect.contains(id))
                    .map(|(id, p)| (id, change_fingerprint(&p))),
            );
        }
        pending.retain(|(_, fp)| which.is_none_or(|w| same_fingerprint(w, fp)));
        let decision = match pending.as_slice() {
            [] => anyhow::bail!("no recovery or change of your guardians is under way"),
            [(id, _)] => *id,
            _ => anyhow::bail!("more than one is under way; give its fingerprint"),
        };
        let e = ident
            .log
            .append(&d.keys.device.signing, vec![IdentityOp::object(decision)])?;
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
//
// A guardian acts through a persona (D79): an identity made for guarding
// one person, kept in the guardian's account (`identity.md#personas`), and
// run on the device that made it as a service of its own (`helper.rs`).
// This service, the guardian's own device's, decides; the persona's signs,
// and meets recovery helpers.

/// Someone this person guards, as this device sees it: through which
/// persona, under which policy.
pub(crate) struct Guarded {
    pub identity: EntryId,
    pub name: String,
    pub persona: account::PersonaRecord,
    pub policy: Policy,
    pub position: u64,
    pub salt: [u8; 32],
    pub share: Option<cardinal_crypto::shamir::Share>,
}

/// This person's guardian personas that are not burned.
fn my_personas(d: &Daemon) -> Vec<account::PersonaRecord> {
    let core = d.core();
    let Some(acc) = core.account().and_then(|a| a.space.as_ref()) else {
        return Vec::new();
    };
    account::personas(acc.state())
        .into_iter()
        .filter(|p| p.purpose == account::GUARDIAN_PURPOSE && !p.burned)
        .collect()
}

/// The service of persona `id`, if this device runs it.
fn service(d: &Daemon, id: &EntryId) -> Option<Arc<Helper>> {
    d.personas
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(id)
        .cloned()
}

/// The persona's log: as its service here holds it, or else as this person
/// wrote it in the relationship with whom it guards.
fn persona_log(d: &Daemon, p: &account::PersonaRecord) -> Option<IdentityLog> {
    if let Some(h) = service(d, &p.identity) {
        let bytes = {
            let pc = h.d.core();
            pc.identity.as_ref().map(|i| crate::core::log_bytes(&i.log))
        };
        if let Some(bytes) = bytes {
            return log_from(&bytes, &p.identity);
        }
    }
    let core = d.core();
    let me = core.me()?;
    let who = p.for_identity?;
    let c = core
        .contacts()
        .into_iter()
        .find(|c| c.identity == who && c.recovery_of.is_none())?;
    let sp = core.spaces.get(&c.space)?.space.as_ref()?;
    let node = relationship::guardian_personas(sp)
        .into_iter()
        .find(|n| n.author == me && n.persona == p.identity)?;
    log_from(&node.log, &p.identity)
}

/// The persona's encryption keys, opened with its root's entropy.
fn persona_keys(p: &account::PersonaRecord, log: &IdentityLog) -> Vec<HybridKeyPair> {
    static OPENED: std::sync::Mutex<BTreeMap<EntryId, Vec<u8>>> =
        std::sync::Mutex::new(BTreeMap::new());
    let mut opened = OPENED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(secret) = opened.get(&p.identity) {
        if let Ok(b) = <[u8; 96]>::try_from(secret.as_slice()) {
            return vec![HybridKeyPair::from_secret_bytes(&b)];
        }
    }
    let phrase = cardinal_crypto::RecoveryPhrase::from_entropy(&p.entropy);
    match log.open_with_phrase(&phrase) {
        Ok(k) => {
            opened.insert(p.identity, k.secret_bytes().to_vec());
            log.key_chain(k)
        }
        Err(_) => Vec::new(),
    }
}

/// Whom this person guards: every contact whose policy holds a record,
/// sealed to this person's persona for them, that opens its commitment.
pub(crate) fn guarded(d: &Daemon) -> Vec<Guarded> {
    let mut out = Vec::new();
    for p in my_personas(d) {
        let Some(who) = p.for_identity else {
            continue;
        };
        let Some(plog) = persona_log(d, &p) else {
            continue;
        };
        let keys = persona_keys(&p, &plog);
        let core = d.core();
        let Some(c) = core
            .contacts()
            .into_iter()
            .find(|c| c.identity == who && c.recovery_of.is_none())
        else {
            continue;
        };
        let Some(other) = core.others.get(&who) else {
            continue;
        };
        let mut policies: Vec<Policy> = other.log.current_policy().into_iter().collect();
        // and the policy any recovery acts under, which a later change
        // may have replaced
        for r in other.log.recoveries() {
            if !policies.iter().any(|q| q.entry == r.policy) {
                policies.extend(other.log.policy(&r.policy));
            }
        }
        for policy in policies {
            if let Some(rec) = other.log.guardian_record(&policy, &p.identity, &keys) {
                out.push(Guarded {
                    identity: who,
                    name: c.petname.clone(),
                    persona: p.clone(),
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

/// `cardinal guarding accept NAME`: accepts being NAME's guardian. Makes a
/// persona for guarding them alone (D79), keeps it in the account, writes
/// its id and log in the relationship the two share, and runs it here.
pub async fn accept_role(d: &Arc<Daemon>, who: &str) -> anyhow::Result<Json> {
    let c = crate::contacts::find(d, who)?;
    anyhow::ensure!(
        c.connects(),
        "{} is not someone you trust: trust them first",
        c.petname
    );
    // One not named by any policy yet serves; a persona named before is
    // never offered again, so each change of guardians gets a fresh one.
    let seen = load_seen(d);
    let fresh = my_personas(d).into_iter().find(|p| {
        p.for_identity == Some(c.identity)
            && !seen
                .named
                .iter()
                .any(|n| n.starts_with(&format!("{}:", hex::encode(p.identity))))
    });
    if let Some(p) = fresh {
        // repaired, if the relationship lacks its node (a crash, or a write
        // that failed, between the two)
        let (me, written) = {
            let core = d.core();
            let me = core.me();
            let written = core
                .spaces
                .get(&c.space)
                .and_then(|h| h.space.as_ref())
                .is_some_and(|sp| {
                    relationship::guardian_personas(sp)
                        .iter()
                        .any(|n| Some(n.author) == me && n.persona == p.identity)
                });
            (me, written)
        };
        if !written && me.is_some() {
            if let Some(log) = persona_log(d, &p) {
                let bytes = crate::core::log_bytes(&log);
                d.write_and_push(
                    &c.space,
                    vec![relationship::create_guardian_persona(&p.identity, &bytes)],
                )?;
            }
        }
        return Ok(json!({"name": c.petname, "persona": hex::encode(p.identity), "already": true}));
    }
    let d2 = d.clone();
    let (entropy, id, log) =
        tokio::task::spawn_blocking(move || crate::helper::make_persona(&d2)).await??;
    let acc = d
        .core()
        .account_id()
        .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
    d.write_and_push(
        &acc,
        vec![account::create_persona(
            account::GUARDIAN_PURPOSE,
            &entropy,
            &id,
            Some(&c.identity),
        )],
    )?;
    d.write_and_push(
        &c.space,
        vec![relationship::create_guardian_persona(&id, &log)],
    )?;
    crate::helper::start_persona(d, &id).await?;
    tracing::info!("guarding {} through persona {}", c.petname, short(&id));
    Ok(json!({"name": c.petname, "persona": hex::encode(id), "already": false}))
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
    let plog = persona_log(d, &g.persona);
    let core = d.core();
    let Some(other) = core.others.get(&g.identity) else {
        return Vec::new();
    };
    let mine: Vec<&IdentityLog> = plog.iter().collect();
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

/// The most changes of a policy tracked at once: past it, later ones are
/// not shown, nor counted.
const MOST_CHANGES: usize = 8;

/// The changes of `policy` in `log` worth showing: `set_recovery` entries
/// that change it, well formed, and signed by a key in effect (or in
/// effect themselves), the first [`MOST_CHANGES`] in log order.
pub(crate) fn changes_of(log: &IdentityLog, policy: &EntryId) -> Vec<(EntryId, Policy)> {
    let st = log.state();
    log.entries()
        .filter(|e| {
            e.ops().iter().any(
                |o| matches!(o.body(), OpBody::SetRecovery { changes: Some(c), .. } if c == policy),
            )
        })
        .filter(|e| st.in_effect.contains(&e.id()) || st.power(&e.signer()).is_some())
        .filter_map(|e| Some((e.id(), log.policy(&e.id())?)))
        .take(MOST_CHANGES)
        .collect()
}

/// The five-word fingerprint of a change of guardians, read to the
/// guardians as a recovery's is: of its entry id and its commitments. Not
/// in the specification, which has a fingerprint for `recover` only.
pub fn change_fingerprint(p: &Policy) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"cardinal change fingerprint");
    h.update(&p.entry);
    for c in &p.commitments {
        h.update(c);
    }
    let d = h.finalize();
    let first: [u8; 8] = d.as_bytes()[..8].try_into().expect("eight bytes");
    let bits = u64::from_be_bytes(first);
    (0..5)
        .map(|i| cardinal_crypto::bip39::word(((bits >> (64 - 11 * (i + 1))) & 0x7ff) as u16))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A change of `g`'s person's policy, under the policy this person guards
/// them through: a decision the guardians confirm, without endorsing
/// (`identity.md#how-guardians-act`).
struct Change {
    entry: EntryId,
    policy: Policy,
    confirmed: BTreeSet<EntryId>,
    in_effect: bool,
    objected: bool,
}

fn changes(d: &Daemon, g: &Guarded) -> Vec<Change> {
    let plog = persona_log(d, &g.persona);
    let core = d.core();
    let Some(other) = core.others.get(&g.identity) else {
        return Vec::new();
    };
    let mine: Vec<&IdentityLog> = plog.iter().collect();
    let st = other.log.state();
    changes_of(&other.log, &g.policy.entry)
        .into_iter()
        .map(|(id, policy)| Change {
            entry: id,
            confirmed: other.log.confirmed_by(&id, &g.policy, &mine),
            in_effect: st.in_effect.contains(&id),
            objected: objected(&other.log, &id),
            policy,
        })
        .collect()
}

/// What a guardian is told before confirming a change of guardians.
pub fn change_caution(name: &str) -> String {
    format!(
        "Before you go on: this changes who can give {name}'s identity back. Check with \
         {name}, in person if you can, that they asked for it. Someone hurrying you is a \
         reason to wait."
    )
}

/// `cardinal guarding confirm-change NAME`: after the wait from when this
/// device saw it, and checking with the person, confirms the change of
/// their guardians under way (the first this device saw).
pub async fn confirm_change(
    d: &Arc<Daemon>,
    who: &str,
    fingerprint: Option<&str>,
    understood: bool,
) -> anyhow::Result<Json> {
    let c = crate::contacts::find(d, who)?;
    let current = {
        let core = d.core();
        core.others
            .get(&c.identity)
            .and_then(|o| o.log.current_policy())
            .map(|p| p.entry)
    };
    let g = guarded(d)
        .into_iter()
        .find(|g| g.identity == c.identity && Some(g.policy.entry) == current)
        .ok_or_else(|| anyhow::anyhow!("you do not guard {} under their policy now", c.petname))?;
    anyhow::ensure!(
        understood,
        "{} (Ask again saying you understood.)",
        change_caution(&g.name)
    );
    sync_own_log(d).await;
    observe(d);
    let seen = load_seen(d);
    let never = nevers(d);
    let mut all: Vec<Change> = changes(d, &g)
        .into_iter()
        .filter(|x| !x.in_effect && !never.contains(&x.entry))
        .collect();
    anyhow::ensure!(
        !all.is_empty(),
        "no change of {}'s guardians is under way",
        g.name
    );
    let ch = match fingerprint {
        Some(f) => {
            let fps: Vec<String> = all.iter().map(|x| change_fingerprint(&x.policy)).collect();
            let at = pick_fingerprint(&fps, f, &g.name)?;
            all.swap_remove(at)
        }
        None if all.len() == 1 => all.remove(0),
        None => anyhow::bail!(
            "more than one change of {}'s guardians is under way: give the fingerprint they \
             read you, of the one that is theirs",
            g.name
        ),
    };
    // Never two changes under one policy (DEVIATIONS.md): once this
    // guardian confirmed one not in effect, it confirms no other.
    if let Some(other) = changes(d, &g)
        .iter()
        .find(|x| x.entry != ch.entry && !x.in_effect && x.confirmed.contains(&g.persona.identity))
    {
        anyhow::bail!(
            "you confirmed another change of {}'s guardians ({}), not in effect: you confirm no \
             other under this policy",
            g.name,
            change_fingerprint(&other.policy)
        );
    }
    if ch.confirmed.contains(&g.persona.identity) {
        return Ok(list(d));
    }
    let since = seen
        .first
        .get(&hex::encode(ch.entry))
        .copied()
        .unwrap_or(u64::MAX);
    let wait = g
        .policy
        .delay
        .saturating_mul(if ch.objected { 2 } else { 1 });
    let from = since.saturating_add(wait.saturating_mul(1000));
    let now = now_ms();
    anyhow::ensure!(
        now >= from,
        "the wait is not over: you can confirm in {}",
        delay_text(from.saturating_sub(now).div_ceil(1000))
    );
    // the chain rule, as for a recovery: and, more strictly, never a second
    // change under the same policy (DEVIATIONS.md)
    let r = Recovery {
        entry: ch.entry,
        root: [0; 32],
        keep: Vec::new(),
        link_key: None,
        policy: g.policy.entry,
    };
    check_chain(d, &g, &r)?;
    act(
        d,
        &g,
        ch.entry,
        IdentityOp::confirm(ch.entry, g.position, g.salt, None),
    )
    .await?;
    Ok(list(d))
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
/// and when a threshold of guardians was first seen to endorse it, and
/// which personas a policy has named. Called whenever a log changes.
pub fn observe(d: &Daemon) {
    let _one = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    let mut seen = load_seen(d);
    let mut changed = false;
    for g in guarded(d) {
        for l in d.core().held_taken(&g.identity) {
            let item = format!("{}:{}", hex::encode(g.identity), hex::encode(l));
            if seen.held.insert(item) {
                changed = true;
            }
        }
        for ch in changes(d, &g) {
            if let std::collections::btree_map::Entry::Vacant(v) =
                seen.first.entry(hex::encode(ch.entry))
            {
                tracing::info!("a change of {}'s guardians was asked for", g.name);
                v.insert(now_ms());
                changed = true;
            }
        }
        let pair = format!(
            "{}:{}",
            hex::encode(g.persona.identity),
            hex::encode(g.policy.entry)
        );
        if seen.named.insert(pair) {
            changed = true;
        }
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

/// The recovery relationships for `who` a persona's service holds:
/// contacts there that are a recovery helper of theirs.
fn helpers_of(pd: &Daemon, who: &EntryId) -> Vec<account::ContactRecord> {
    let core = pd.core();
    let mut v: Vec<_> = core
        .contacts()
        .into_iter()
        .filter(|c| c.recovery_of == Some(*who) && !c.refused)
        .collect();
    v.sort_by_key(|c| c.space);
    v
}

/// `cardinal guarding`: whom this person guards, and the recovery of each
/// shown, with any others that wait behind it; and those this person
/// accepted to guard who have not named them yet.
pub fn list(d: &Daemon) -> Json {
    observe(d);
    let seen = load_seen(d);
    let all = guarded(d);
    let people: Vec<Json> = all
        .iter()
        .map(|g| {
            let s = shown(d, &seen, g);
            let me = g.persona.identity;
            let mine = |set: &BTreeSet<EntryId>| set.contains(&me);
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
                        "keeps_keys": !w.recovery.keep.is_empty(),
                        "caution": (!w.in_effect).then(|| caution(&g.name)),
                    })
                })
                .collect();
            let never: Vec<String> = s.never.iter().map(|w| w.recovery.fingerprint()).collect();
            let helpers = service(d, &g.persona.identity)
                .map_or(0, |h| helpers_of(&h.d, &g.identity).len());
            // where the persona's own service listens, for an invitation
            // to name (`guarding-invite` `at`): null if it does not run here
            let persona_at = service(d, &g.persona.identity).and_then(|h| {
                let a = h.d.endpoint.udp_addr().or(h.d.endpoint.tcp_addr())?;
                let ip = if a.ip().is_unspecified() {
                    crate::daemon::local_ips().into_iter().next()?
                } else {
                    a.ip()
                };
                Some(std::net::SocketAddr::new(ip, a.port()).to_string())
            });
            let account_copy = {
                let core = d.core();
                core.held_taken(&g.identity)
                    .iter()
                    .any(|l| core.set(l).iter().next().is_some())
            };
            json!({
                "name": g.name,
                "id": hex::encode(g.identity),
                "persona": hex::encode(g.persona.identity),
                "guardians": g.policy.commitments.len(),
                "threshold": g.policy.threshold,
                "delay": g.policy.delay,
                "delay_text": delay_text(g.policy.delay),
                "recoveries": recoveries,
                "waiting": s.waiting.len(),
                "warning": (!s.waiting.is_empty()).then(|| second_warning(&g.name, s.waiting.len())),
                "never": never,
                "helpers": helpers,
                "persona_at": persona_at,
                "account_copy": account_copy,
                "changes": changes_json(d, &seen, g),
            })
        })
        .collect();
    let (accepted, in_change): (Vec<String>, Vec<String>) = {
        let named: HashSet<EntryId> = all.iter().map(|g| g.persona.identity).collect();
        let personas = my_personas(d);
        let mut accepted = Vec::new();
        let mut in_change = Vec::new();
        for p in personas.iter().filter(|p| !named.contains(&p.identity)) {
            let Some(who) = p.for_identity else { continue };
            let waiting = named_in_change(d, p);
            let core = d.core();
            let Some(c) = core
                .contacts()
                .into_iter()
                .find(|c| c.identity == who && c.recovery_of.is_none())
            else {
                continue;
            };
            if waiting {
                in_change.push(c.petname);
            } else {
                accepted.push(c.petname);
            }
        }
        (accepted, in_change)
    };
    json!({
        "guarding": people,
        "accepted": accepted,
        "named_in_change": in_change,
        "no_longer_needed": no_longer_json(d, &seen),
        "asked": asked(d),
        "now_ms": now_ms(),
    })
}

/// Whether a change of the person's guardians under way names persona `p`:
/// its record for `p` opens.
fn named_in_change(d: &Daemon, p: &account::PersonaRecord) -> bool {
    let Some(who) = p.for_identity else {
        return false;
    };
    let Some(plog) = persona_log(d, p) else {
        return false;
    };
    let keys = persona_keys(p, &plog);
    let core = d.core();
    let Some(other) = core.others.get(&who) else {
        return false;
    };
    let Some(cur) = other.log.current_policy() else {
        return false;
    };
    let st = other.log.state();
    changes_of(&other.log, &cur.entry)
        .iter()
        .filter(|(id, _)| !st.in_effect.contains(id))
        .any(|(_, q)| other.log.guardian_record(q, &p.identity, &keys).is_some())
}

/// The changes of `g`'s person's guardians, as a guardian is shown them.
fn changes_json(d: &Daemon, seen: &Seen, g: &Guarded) -> Vec<Json> {
    changes(d, g)
        .iter()
        .map(|ch| {
            let since = seen.first.get(&hex::encode(ch.entry)).copied();
            let wait = g
                .policy
                .delay
                .saturating_mul(if ch.objected { 2 } else { 1 });
            json!({
                "id": hex::encode(&ch.entry[..8]),
                "fingerprint": change_fingerprint(&ch.policy),
                "never": nevers(d).contains(&ch.entry),
                "guardians": ch.policy.commitments.len(),
                "threshold": ch.policy.threshold,
                "delay": ch.policy.delay,
                "delay_text": delay_text(ch.policy.delay),
                "confirm_delay": wait,
                "confirm_delay_text": delay_text(wait),
                "confirmed": ch.confirmed.len(),
                "confirmed_by_me": ch.confirmed.contains(&g.persona.identity),
                "in_effect": ch.in_effect,
                "objected": ch.objected,
                "confirm_from_ms": since.map(|t| t.saturating_add(wait.saturating_mul(1000))),
                "caution": (!ch.in_effect).then(|| change_caution(&g.name)),
            })
        })
        .collect()
}

/// Those who asked this person to guard them, and have no answer yet: a
/// guardian request in the relationship newer than this person's last
/// guardian persona node there.
fn asked(d: &Daemon) -> Vec<String> {
    let core = d.core();
    let me = core.me();
    core.contacts()
        .into_iter()
        .filter(|c| c.recovery_of.is_none() && !c.refused)
        .filter(|c| {
            let Some(sp) = core.spaces.get(&c.space).and_then(|h| h.space.as_ref()) else {
                return false;
            };
            let asked = relationship::guardian_requests(sp)
                .into_iter()
                .filter(|(a, _)| *a == c.identity)
                .map(|(_, at)| at)
                .max();
            let answered = me.and_then(|me| relationship::guardian_persona_at(sp, &me));
            matches!(asked, Some(a) if a > answered)
        })
        .map(|c| c.petname)
        .collect()
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
         under way is not theirs, say never to confirm it, and this one is shown.",
        name = g.name
    );
    let mut shown: Vec<Wanted> = s.shown.into_iter().collect();
    let fps: Vec<String> = shown.iter().map(|w| w.recovery.fingerprint()).collect();
    let at = pick_fingerprint(&fps, fingerprint, &g.name)?;
    let w = shown.swap_remove(at);
    keeps_nothing(&w.recovery, &g.name)?;
    Ok(w)
}

/// Guardian software MUST NOT endorse or confirm a `recover` that keeps
/// any key (D80).
fn keeps_nothing(r: &Recovery, name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        r.keep.is_empty(),
        "that recovery of {name} keeps some of their old devices, which a thief may hold; \
         guardians never endorse or confirm one that does. Someone else may be trying to \
         take their identity."
    );
    Ok(())
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

/// Endorsing and confirming wait until the guardian was shown
/// [`caution`] and said to go on (`understood`), whatever names them.
fn heeded(g: &Guarded, understood: bool) -> anyhow::Result<()> {
    anyhow::ensure!(
        understood,
        "{} (Ask again saying you understood.)",
        caution(&g.name)
    );
    Ok(())
}

/// `guarding-caution`: what to show a guardian before they endorse or
/// confirm a recovery of `who`, however `who` is named.
pub fn caution_for(d: &Daemon, who: &str) -> anyhow::Result<Json> {
    let g = find_guarded(d, who)?;
    Ok(json!({"name": g.name, "caution": caution(&g.name)}))
}

/// `cardinal guarding endorse NAME FINGERPRINT`: after checking with the
/// person by whatever means they trust, says a recovery is wanted.
pub async fn endorse(
    d: &Arc<Daemon>,
    who: &str,
    fingerprint: &str,
    understood: bool,
) -> anyhow::Result<Json> {
    let g = find_guarded(d, who)?;
    heeded(&g, understood)?;
    let w = find_wanted(d, &g, fingerprint)?;
    if !w.endorsed.contains(&g.persona.identity) {
        act(
            d,
            &g,
            w.recovery.entry,
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
pub async fn confirm(
    d: &Arc<Daemon>,
    who: &str,
    fingerprint: &str,
    understood: bool,
) -> anyhow::Result<Json> {
    let g = find_guarded(d, who)?;
    heeded(&g, understood)?;
    // Own devices first, so this person's phone and laptop do not confirm
    // opposite decisions unawares, nor one said never to on the other.
    sync_own_log(d).await;
    observe(d);
    let w = find_wanted(d, &g, fingerprint)?;
    if w.confirmed.contains(&g.persona.identity) {
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
        w.recovery.entry,
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
    // a recovery, or a change of guardians
    let mut all: Vec<(EntryId, String, bool)> = wanted(d, &g)
        .iter()
        .map(|w| (w.recovery.entry, w.recovery.fingerprint(), w.in_effect))
        .collect();
    all.extend(
        changes(d, &g)
            .iter()
            .map(|c| (c.entry, change_fingerprint(&c.policy), c.in_effect)),
    );
    let fps: Vec<String> = all.iter().map(|x| x.1.clone()).collect();
    let (entry, _, in_effect) = all[pick_fingerprint(&fps, fingerprint, &g.name)?].clone();
    anyhow::ensure!(
        !in_effect,
        "that decision about {} is in effect already; nothing undoes it",
        g.name
    );
    if !nevers(d).contains(&entry) {
        let acc = d
            .core()
            .account_id()
            .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
        let name = format!("{NEVER_SETTING}{}", hex::encode(entry));
        d.write_and_push(&acc, vec![account::create_setting(&name, true)])?;
    }
    retire_moot(d);
    Ok(list(d))
}

/// The chain rule (`identity.md#guardian-decisions`): every decision under
/// the policy this guardian's persona confirmed before is in the new one's
/// past.
fn check_chain(d: &Daemon, g: &Guarded, recovery: &Recovery) -> anyhow::Result<()> {
    let plog = persona_log(d, &g.persona)
        .ok_or_else(|| anyhow::anyhow!("your persona for {} is not here", g.name))?;
    let core = d.core();
    let other = core.others.get(&g.identity).expect("guarded");
    chain_allows(&plog, &other.log, &g.salt, recovery, &g.name)
}

/// The chain rule, on this guardian's persona's log `mine` and the guarded
/// log `theirs`. A confirmation is under this policy if it carries this
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

/// Writes `op` in the persona's log, through its service, and delivers that
/// log up to it to the guarded person's devices and hosts, under the
/// person's label, and to every recovery helper of that recovery.
async fn act(
    d: &Arc<Daemon>,
    g: &Guarded,
    decision: EntryId,
    op: IdentityOp,
) -> anyhow::Result<()> {
    let h = service(d, &g.persona.identity).ok_or_else(|| {
        anyhow::anyhow!(
            "your persona for {} acts from the device on which you accepted being their \
             guardian; use that one",
            g.name
        )
    })?;
    let confirms = matches!(op.body(), OpBody::Confirm { .. });
    let log: Vec<Vec<u8>> = h
        .on(move |pd| async move {
            let (entry, log) = {
                let mut core = pd.core();
                let ident = core
                    .identity
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("the persona has no identity"))?;
                let e = ident.log.append(&pd.keys.device.signing, vec![op])?;
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
            pd.identity_changed();
            pd.push_identity(vec![entry.encode()]);
            Ok(log)
        })
        .await?;
    // Held here under their label too, so that whoever syncs it with this
    // device gets it.
    d.core().ingest_other(g.identity, &log)?;
    for (c, r) in helpers_with_recover(&h.d, &g.identity) {
        if r != Some(decision) {
            continue;
        }
        // with a confirm, this person's own log first, so that it is
        // there when the recovery is in effect for the new device
        if confirms {
            carry_own_log(d, &h, c.space).await;
        }
        let (space, who, log) = (c.space, g.identity, log.clone());
        if let Err(e) = h
            .on(move |pd| async move { carry(&pd, &space, &who, &log) })
            .await
        {
            tracing::debug!("carrying to a recovery helper: {e:#}");
        }
    }
    deliver(d, &g.identity, log).await;
    observe(d);
    retire_moot(d);
    Ok(())
}

/// Sends a guardian's persona's log, or a `recover`, under `guarded`'s
/// label to that person's devices in touch and this person's own.
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

/// Entries written in a space, by id.
pub(crate) type Written = Vec<(EntryId, Vec<u8>)>;

/// Writes in a relationship space, as `carried` nodes, each of `entries`
/// that this person has not carried there yet. `recovered` is whom the
/// recovery is of. Returns how many it carried, and the space entries
/// that carry them, by id.
pub(crate) fn carry(
    d: &Arc<Daemon>,
    space: &SpaceId,
    recovered: &EntryId,
    entries: &[Vec<u8>],
) -> anyhow::Result<(usize, Written)> {
    let ops: Vec<SpaceOp> = {
        let core = d.core();
        let Some(sp) = core.spaces.get(space).and_then(|h| h.space.as_ref()) else {
            return Ok((0, Vec::new()));
        };
        // what this person carried there already: what the other carried
        // counts as theirs, as a helper's `recover` must be its own
        let me = core.me();
        let mut there: HashSet<EntryId> = relationship::carried(sp)
            .iter()
            .filter(|c| Some(c.author) == me)
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
    let write = |batch: Vec<SpaceOp>| -> anyhow::Result<Written> {
        let written = d.core().write(space, batch)?;
        d.push(space, written.iter().map(|(_, b)| b.clone()).collect());
        d.bump();
        Ok(written)
    };
    let n = ops.len();
    let mut written = Vec::new();
    let mut batch = Vec::new();
    let mut size = 0;
    for op in ops {
        let len = op.record().encode().len();
        if !batch.is_empty() && size + len > CARRY_BATCH {
            written.extend(write(std::mem::take(&mut batch))?);
            size = 0;
        }
        size += len;
        batch.push(op);
    }
    if !batch.is_empty() {
        written.extend(write(batch)?);
    }
    Ok((n, written))
}

/// `cardinal guarding invite NAME [--address ADDR]`: an invitation for
/// NAME's new device, made by this person's persona for NAME and naming
/// NAME in field 9, so that it meets the persona in a relationship of its
/// own. It is the persona's: neither side learns the other's identity.
pub async fn invite(d: &Arc<Daemon>, who: &str, at: Option<&str>) -> anyhow::Result<Json> {
    let g = find_guarded(d, who)?;
    let h = service(d, &g.persona.identity).ok_or_else(|| {
        anyhow::anyhow!(
            "your persona for {} acts from the device on which you accepted being their \
             guardian; use that one",
            g.name
        )
    })?;
    let (at, recovered) = (at.map(str::to_owned), g.identity);
    let code = h
        .on(move |pd| async move {
            crate::contacts::invite_recovery(&pd, at.as_deref(), recovered).map(|i| i.to_text())
        })
        .await?;
    Ok(json!({"code": code, "name": g.name}))
}

/// `accept` of a helper's recovery invitation, on a guardian's device: the
/// persona for that person takes it up, through its service.
pub(crate) fn accept_recovery<'a>(
    d: &'a Arc<Daemon>,
    code: &'a str,
    who: &'a EntryId,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Json>> + Send + 'a>> {
    Box::pin(accept_recovery_now(d, code, who))
}

async fn accept_recovery_now(d: &Arc<Daemon>, code: &str, who: &EntryId) -> anyhow::Result<Json> {
    let g = guarded(d)
        .into_iter()
        .find(|g| g.identity == *who)
        .ok_or_else(|| anyhow::anyhow!("you do not guard them"))?;
    let h = service(d, &g.persona.identity).ok_or_else(|| {
        anyhow::anyhow!(
            "your persona for {} acts from the device on which you accepted being their \
             guardian; use that one",
            g.name
        )
    })?;
    let code = code.to_owned();
    let met = account::Met {
        how: account::MET_THEIR_INVITATION,
        ..Default::default()
    };
    let whom = *who;
    h.on(move |pd| async move {
        crate::contacts::accept_for(
            &pd,
            &code,
            None,
            account::Regard::default(),
            met,
            true,
            Some(whom),
        )
        .await
    })
    .await?;
    Ok(json!({"name": helper_petname(d, who), "recovery_of": hex::encode(who)}))
}

/// The proposal this guardian's persona makes for a recovery of `g`
/// (`identity.md#how-guardians-act`, step 1): parents the person
/// recognizes, and the policy. A `recover` keeps no old key (D80), so no
/// key is proposed.
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
    Ok(relationship::create_proposal(
        &g.identity,
        &other.log.recovery_parents(),
        &g.policy.entry,
    ))
}

/// After the persona met a recovery helper of `g`'s person: proposes the
/// recovery in that relationship, unless it proposed one there already,
/// and carries the person's log, which the new device signs against and
/// takes the identity up from.
async fn met_helper(d: &Arc<Daemon>, h: &Arc<Helper>, space: SpaceId, g: &Guarded) {
    let who = g.identity;
    let proposed = {
        let pc = h.d.core();
        let me = pc.me();
        pc.spaces
            .get(&space)
            .and_then(|x| x.space.as_ref())
            .is_some_and(|sp| {
                relationship::proposals(sp)
                    .iter()
                    .any(|p| Some(p.author) == me && p.identity == who)
            })
    };
    if !proposed {
        match proposal(d, g) {
            Ok(op) => {
                let r = h
                    .on(move |pd| async move { pd.write_and_push(&space, vec![op]).map(|_| ()) })
                    .await;
                if let Err(e) = r {
                    tracing::warn!("cannot propose the recovery of {}: {e:#}", g.name);
                    return;
                }
                tracing::info!("a recovery helper of {} is in touch", g.name);
            }
            Err(e) => {
                tracing::warn!("cannot propose the recovery of {}: {e:#}", g.name);
                return;
            }
        }
    }
    // With the logs held under its label: the confirmations by which a
    // change of guardians is in effect are entries of the guardians'
    // personas' logs, and without them the new device sees the old
    // policy in office, and no proposal under the current one would do.
    let log: Vec<Vec<u8>> = {
        let core = d.core();
        core.others
            .get(&who)
            .map(|o| crate::core::log_bytes(&o.log))
            .unwrap_or_default()
    };
    let r = h
        .on(move |pd| async move { carry(&pd, &space, &who, &log) })
        .await;
    if let Err(e) = r {
        tracing::warn!("cannot carry {}'s log to their new device: {e:#}", g.name);
    }
    // And this person's own log, under their own id, so that the new
    // device, taking the person's relationships up, knows this person's
    // devices: only once this guardian confirmed the recovery, which it
    // does at the end of the delay, so that a helper it did not confirm
    // learns nothing of the guardian.
    let confirmed = wanted(d, g)
        .iter()
        .any(|w| w.confirmed.contains(&g.persona.identity));
    if confirmed {
        carry_own_log(d, h, space).await;
    }
}

/// Carries this person's own log, under their own id, to a recovery
/// helper in `space`: once this guardian has confirmed.
async fn carry_own_log(d: &Arc<Daemon>, h: &Arc<Helper>, space: SpaceId) {
    let mine: Option<([u8; 32], Vec<Vec<u8>>)> = {
        let core = d.core();
        core.identity
            .as_ref()
            .map(|i| (i.id(), i.log.entries().map(IdentityEntry::encode).collect()))
    };
    if let Some((me, mine)) = mine {
        let r = h
            .on(move |pd| async move { carry(&pd, &space, &me, &mine) })
            .await;
        if let Err(e) = r {
            tracing::debug!("carrying this person's log to a helper: {e:#}");
        }
    }
}

/// What a helper carried in a recovery relationship, taken: of the
/// person's own log, its first `recover` alone, signed by its new root,
/// under the policy this person guards; of anyone else's, what
/// [`crate::core::Core::ingest_other`] keeps, the causal past of another
/// guardian's persona's act. What is new here goes on to the person's
/// devices and hosts, as an act does. The persona's acts on that recovery,
/// done before it reached the relationship, are carried into it now.
async fn take(d: &Arc<Daemon>, h: &Arc<Helper>, c: &account::ContactRecord, g: &Guarded) {
    let (helper, who, space) = (c.identity, g.identity, c.space);
    let label = identity_log_label(&who);
    let carried: Vec<relationship::Carried> = {
        let pc = h.d.core();
        pc.spaces
            .get(&space)
            .and_then(|x| x.space.as_ref())
            .map(relationship::carried)
            .unwrap_or_default()
    };
    let first = carried
        .iter()
        .filter(|x| x.author == helper && x.identity == who)
        .filter_map(|x| IdentityEntry::decode(&x.entry).ok())
        .find(|e| e.identity() == who && recovery_of_entry(e).is_some())
        .filter(|e| is_recover_under(e, &g.policy.entry));
    // and what its new root wrote after it, once in effect: the new device
    // taking the identity up, by which the guardian knows it is done
    let new_root = first.as_ref().and_then(recovery_of_entry).map(|r| r.root);
    let first = first.map(|e| e.id());
    if let Some(r) = first {
        let plog = persona_log(d, &g.persona);
        let mine = plog.map(|l| acts_on(&l, &r)).unwrap_or_default();
        if !mine.is_empty() {
            let r = h
                .on(move |pd| async move { carry(&pd, &space, &who, &mine) })
                .await;
            if let Err(e) = r {
                tracing::debug!("carrying to a recovery helper: {e:#}");
            }
        }
    }
    let new: Vec<Vec<u8>> = {
        let core = d.core();
        carried
            .into_iter()
            .filter(|x| x.author == helper && x.identity == who)
            .filter_map(|x| {
                let e = IdentityEntry::decode(&x.entry).ok()?;
                if core.has(&label, &e.id()) {
                    return None;
                }
                let by_new_root = new_root.is_some_and(|root| e.signer() == root);
                (e.identity() != who || Some(e.id()) == first || by_new_root).then_some(x.entry)
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
    // the person's devices as the log now names them: a new device after a
    // recovery is let in, as when the log comes by sync
    {
        let core = d.core();
        let states = core.connectable_states();
        let own = core.identity.as_ref().map(|i| i.state());
        drop(core);
        d.directory.update(own.as_deref(), &states);
        d.endpoint.recheck_peers();
    }
    d.bump();
    deliver(d, &who, taken).await;
}

/// The persona's acts on `decision`, with their causal past in its log.
fn acts_on(log: &IdentityLog, decision: &EntryId) -> Vec<Vec<u8>> {
    let acts: Vec<EntryId> = log
        .entries()
        .filter(|e| {
            e.ops().iter().any(|o| {
                matches!(o.body(), OpBody::Endorse { decision: x, .. }
                    | OpBody::Confirm { decision: x, .. } if x == decision)
            })
        })
        .map(|e| e.id())
        .collect();
    if acts.is_empty() {
        return Vec::new();
    }
    let mut past = log.dag().ancestors_of(&acts);
    past.extend(acts);
    log.entries()
        .filter(|e| past.contains(&e.id()))
        .map(IdentityEntry::encode)
        .collect()
}

/// A helper relationship and a set given in it.
type GivenKey = (SpaceId, [u8; 32]);

/// A set held for someone: its label and every sealed entry of it.
type HeldSet = ([u8; 32], Vec<Vec<u8>>);

/// Gives each recovery helper of `g`'s person what this guardian holds for
/// them (D80): the sealed account they gave, and the relationship space the
/// two share, copied into the persona's service and named there in a held
/// copy node, so that the helper fetches them as they change.
async fn give_held(d: &Arc<Daemon>, h: &Arc<Helper>, g: &Guarded) {
    // What has been given, by helper relationship and set: the count of
    // the set when it last went into the persona's service for it. Kept
    // only once that worked, so a helper met again, or a recovery started
    // over, is given everything.
    static GIVEN: std::sync::Mutex<BTreeMap<GivenKey, usize>> =
        std::sync::Mutex::new(BTreeMap::new());
    let helpers: Vec<SpaceId> = helpers_of(&h.d, &g.identity)
        .into_iter()
        .map(|c| c.space)
        .collect();
    let (account, labels, sets): (Option<[u8; 32]>, Vec<[u8; 32]>, Vec<HeldSet>) = {
        let core = d.core();
        let Some(c) = core
            .contacts()
            .into_iter()
            .find(|c| c.identity == g.identity && c.recovery_of.is_none())
        else {
            return;
        };
        // Tests: a guardian who gives back no account.
        let none =
            cfg!(debug_assertions) && std::env::var_os("CARDINAL_TEST_GIVE_NO_ACCOUNT").is_some();
        let account = core
            .held_taken(&g.identity)
            .into_iter()
            .next()
            .filter(|_| !none);
        let labels: Vec<[u8; 32]> = account.into_iter().chain([c.space]).collect();
        let given = GIVEN.lock().unwrap_or_else(|e| e.into_inner());
        let mut sets = Vec::new();
        for l in labels.iter().filter(|l| core.spaces.contains_key(*l)) {
            let ids: Vec<[u8; 32]> = core.set(l).iter().copied().collect();
            let stale = helpers
                .iter()
                .any(|sp| given.get(&(*sp, *l)) != Some(&ids.len()));
            if stale {
                sets.push((*l, ids.iter().filter_map(|id| core.get(l, id)).collect()));
            }
        }
        (account, labels, sets)
    };
    let counts: Vec<([u8; 32], usize)> = sets.iter().map(|(l, e)| (*l, e.len())).collect();
    let who = g.identity;
    let r = h
        .on(move |pd| async move {
            let mut changed = false;
            for (label, entries) in sets {
                let missing: Vec<Vec<u8>> = {
                    let pc = pd.core();
                    entries
                        .into_iter()
                        .filter(|b| {
                            cardinal_space::SealedEntry::decode(b)
                                .is_ok_and(|e| !pc.has(&label, &e.sealed_id()))
                        })
                        .collect()
                };
                if !missing.is_empty() {
                    tracing::debug!(
                        "the persona holds {} more of {}",
                        missing.len(),
                        short(&label)
                    );
                    pd.core().ingest_space(label, &missing)?;
                    pd.bump();
                    changed = true;
                }
            }
            // every helper is told of every set, whatever was given before
            let me = pd.core().me();
            for c in helpers_of(&pd, &who) {
                let named: Vec<[u8; 32]> = {
                    let pc = pd.core();
                    pc.spaces
                        .get(&c.space)
                        .and_then(|x| x.space.as_ref())
                        .map(|sp| {
                            relationship::held(sp)
                                .into_iter()
                                .filter(|(a, _)| Some(*a) == me)
                                .map(|(_, l)| l)
                                .collect()
                        })
                        .unwrap_or_default()
                };
                let ops: Vec<SpaceOp> = labels
                    .iter()
                    .filter(|l| !named.contains(*l) && pd.core().spaces.contains_key(*l))
                    .map(|l| {
                        if Some(*l) == account {
                            relationship::create_held_account(l)
                        } else {
                            relationship::create_held(l)
                        }
                    })
                    .collect();
                let wrote = !ops.is_empty();
                if wrote {
                    pd.write_and_push(&c.space, ops)?;
                }
                if changed || wrote {
                    for l in &labels {
                        let (pd2, who2, l) = (pd.clone(), c.identity, *l);
                        tokio::spawn(async move { sync_label(&pd2, &who2, &l).await });
                    }
                }
            }
            Ok(())
        })
        .await;
    match r {
        Ok(()) => {
            let mut given = GIVEN.lock().unwrap_or_else(|e| e.into_inner());
            for sp in &helpers {
                for (l, n) in &counts {
                    given.insert((*sp, *l), *n);
                }
            }
        }
        Err(e) => tracing::debug!("giving a recovery helper what is held: {e:#}"),
    }
}

/// The `recover` a recovery relationship is for: the first its helper
/// carried there. Any later one is not taken.
pub(crate) fn relationship_recover(
    sp: &cardinal_space::Space,
    helper: &EntryId,
    who: &EntryId,
) -> Option<IdentityEntry> {
    relationship::carried(sp)
        .into_iter()
        .filter(|c| c.author == *helper && c.identity == *who)
        .filter_map(|c| IdentityEntry::decode(&c.entry).ok())
        .find(|e| e.identity() == *who && recovery_of_entry(e).is_some())
}

/// The recovery relationships for `who` a persona's service holds, with the
/// `recover` each is for.
fn helpers_with_recover(
    pd: &Daemon,
    who: &EntryId,
) -> Vec<(account::ContactRecord, Option<EntryId>)> {
    let rels = helpers_of(pd, who);
    let core = pd.core();
    rels.into_iter()
        .map(|c| {
            let r = core
                .spaces
                .get(&c.space)
                .and_then(|h| h.space.as_ref())
                .and_then(|sp| relationship_recover(sp, &c.identity, who))
                .map(|e| e.id());
            (c, r)
        })
        .collect()
}

/// Retires a recovery relationship: the persona refuses its helper, so
/// nothing is carried into it, and it is trusted for nothing (sessions,
/// calls, delivery tokens) from now on.
fn retire(pd: &Arc<Daemon>, c: &account::ContactRecord) {
    let Some(acc) = pd.core().account_id() else {
        return;
    };
    let ops = vec![
        account::set_field(c.node, account::REFUSED, true),
        account::set_field(c.node, account::TRUSTED, false),
    ];
    match pd.write_and_push(&acc, ops) {
        Ok(_) => tracing::info!("retired a recovery relationship"),
        Err(e) => tracing::warn!("cannot retire a recovery relationship: {e:#}"),
    }
}

/// Retires the recovery relationships that can serve no more: those for a
/// recovery this person said never to, and, once a recovery of someone is
/// in effect, those for any other.
fn retire_moot(d: &Arc<Daemon>) {
    let never = nevers(d);
    for g in guarded(d) {
        let Some(h) = service(d, &g.persona.identity) else {
            continue;
        };
        let done: Option<EntryId> = wanted(d, &g)
            .iter()
            .find(|w| w.in_effect)
            .map(|w| w.recovery.entry);
        for (c, r) in helpers_with_recover(&h.d, &g.identity) {
            // one whose `recover` has not arrived yet may be the one in effect
            let moot = r.is_some_and(|r| never.contains(&r) || done.is_some_and(|d| d != r));
            if moot {
                let (pd, c) = (h.d.clone(), c.clone());
                drop(h.d.rt.spawn(async move { retire(&pd, &c) }));
            }
        }
    }
}

/// Burns the guardian personas whose purpose is over (D79, D81): one
/// that a policy named and that the person's current policy, which
/// descends from that one, no longer names. A persona that acted in a
/// recovery stays while the policy naming it is current. Its service stops
/// and goes; the account keeps it, burned, and its id is never used again.
/// Where no other persona guards the same person, this person is told "Ana
/// no longer needs you as a guardian".
async fn burn_spent(d: &Arc<Daemon>) {
    let seen = load_seen(d);
    let all = guarded(d);
    for p in my_personas(d) {
        let Some(who) = p.for_identity else {
            continue;
        };
        let mine: Vec<&Guarded> = all
            .iter()
            .filter(|g| g.persona.identity == p.identity)
            .collect();
        // A later policy, in effect, that no longer names it: known only
        // when that policy descends from one that named it, never from a
        // record that failed to open for another reason.
        let dropped = {
            let core = d.core();
            core.others.get(&who).is_some_and(|o| {
                let Some(current) = o.log.current_policy().map(|q| q.entry) else {
                    return false;
                };
                let was: Vec<EntryId> = seen
                    .named
                    .iter()
                    .filter_map(|n| {
                        let (per, pol) = n.split_once(':')?;
                        (per == hex::encode(p.identity)).then_some(())?;
                        hex::decode(pol).ok()?.try_into().ok()
                    })
                    .collect();
                !was.is_empty()
                    && !was.contains(&current)
                    && was.iter().any(|w| o.log.dag().is_ancestor(w, &current))
                    && !mine.iter().any(|g| g.policy.entry == current)
            })
        };
        if !dropped {
            continue;
        }
        let Some(acc) = d.core().account_id() else {
            return;
        };
        // What is held for the person, read before the persona is burned:
        // dropped only if no other persona for them stays, as a guardian
        // named again keeps it.
        let (held, others) = {
            let core = d.core();
            let others = core
                .account()
                .and_then(|a| a.space.as_ref())
                .is_some_and(|sp| {
                    account::personas(sp.state()).iter().any(|q| {
                        q.purpose == account::GUARDIAN_PURPOSE
                            && q.for_identity == Some(who)
                            && !q.burned
                            && q.identity != p.identity
                    })
                });
            let mut held = if others {
                Vec::new()
            } else {
                core.held_taken(&who)
            };
            // and what was taken for them before, which the person's
            // devices may have stopped naming already
            if !others {
                let mine = format!("{}:", hex::encode(who));
                for item in seen.held.iter().filter(|i| i.starts_with(&mine)) {
                    let l: Option<[u8; 32]> = hex::decode(&item[mine.len()..])
                        .ok()
                        .and_then(|b| b.try_into().ok());
                    if let Some(l) = l.filter(|l| !held.contains(l)) {
                        held.push(l);
                    }
                }
            }
            (held, others)
        };
        if let Err(e) = d.write_and_push(
            &acc,
            vec![account::set_field(p.node, account::BURNED, true)],
        ) {
            tracing::warn!("cannot burn a persona: {e:#}");
            continue;
        }
        // It leaves its spaces, and what was held for the person goes.
        if let Some(h) = service(d, &p.identity) {
            let r = h
                .on(|pd| async move {
                    let (me, rels) = {
                        let pc = pd.core();
                        let rels: Vec<SpaceId> = pc
                            .contacts()
                            .into_iter()
                            .filter(|c| c.recovery_of.is_some())
                            .map(|c| c.space)
                            .collect();
                        (pc.me(), rels)
                    };
                    if let Some(me) = me {
                        for sp in rels {
                            pd.write_and_push(&sp, relationship::leave_ops(&me))?;
                        }
                    }
                    Ok(())
                })
                .await;
            if let Err(e) = r {
                tracing::debug!("a burned persona leaving its spaces: {e:#}");
            }
        }
        crate::helper::stop_persona(d, &p.identity, true).await;
        {
            let mut core = d.core();
            for l in held {
                core.drop_held(&l);
            }
        }
        if !others {
            let _one = SEEN.lock().unwrap_or_else(|e| e.into_inner());
            let mut seen = load_seen(d);
            seen.no_longer
                .entry(hex::encode(who))
                .or_insert_with(now_ms);
            let mine = format!("{}:", hex::encode(who));
            seen.held.retain(|i| !i.starts_with(&mine));
            save_seen(d, &seen);
            drop(_one);
            d.bump();
        }
        tracing::info!("burned persona {}", short(&p.identity));
    }
}

/// The people whose current policy no longer names this person's guardian
/// persona for them, and whom no other persona of theirs guards, as a
/// window shows them: "Ana no longer needs you as a guardian". Each stays
/// listed until this person guards them again.
fn no_longer_json(d: &Daemon, seen: &Seen) -> Vec<Json> {
    let mine = my_personas(d);
    let core = d.core();
    seen.no_longer
        .iter()
        .filter_map(|(who, at)| {
            let id: EntryId = hex::decode(who).ok()?.try_into().ok()?;
            if mine.iter().any(|p| p.for_identity == Some(id)) {
                return None;
            }
            let name = core
                .contacts()
                .into_iter()
                .find(|c| c.identity == id && c.recovery_of.is_none())
                .map_or_else(|| account::short_key(&id), |c| c.petname);
            Some(json!({
                "name": name,
                "id": who,
                "at_ms": at,
                "text": format!("{name} no longer needs you as a guardian"),
            }))
        })
        .collect()
}

/// Starts the services of this person's guardian personas that this
/// device acts as, and tends them from then on: meets helpers, takes
/// what they carry, gives what is held, retires what is moot, and burns
/// what is spent.
pub fn start_personas(d: &Arc<Daemon>) {
    let d = d.clone();
    tokio::spawn(async move {
        loop {
            for p in my_personas(&d) {
                let here =
                    crate::core::has_identity(&crate::helper::persona_paths(&d.paths, &p.identity));
                if here && service(&d, &p.identity).is_none() {
                    if let Err(e) = crate::helper::start_persona(&d, &p.identity).await {
                        tracing::warn!("cannot start persona {}: {e:#}", short(&p.identity));
                    }
                }
            }
            tend(&d).await;
            if *d.stopping.borrow() {
                return;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}

/// One round of tending this person's personas.
async fn tend(d: &Arc<Daemon>) {
    let all = guarded(d);
    let mut done: HashSet<EntryId> = HashSet::new();
    for g in &all {
        if !done.insert(g.persona.identity) {
            continue;
        }
        let Some(h) = service(d, &g.persona.identity) else {
            continue;
        };
        let helpers = helpers_of(&h.d, &g.identity);
        for c in &helpers {
            met_helper(d, &h, c.space, g).await;
            take(d, &h, c, g).await;
        }
        // copies only for helpers, and only when they changed
        if !helpers.is_empty() {
            give_held(d, &h, g).await;
        }
    }
    tend_person(d);
    if !all.is_empty() {
        retire_moot(d);
    }
    burn_spent(d).await;
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

    /// A helper carries two `recover`s in one relationship: the first is
    /// the one the relationship is for, and the second is never taken.
    #[tokio::test]
    async fn a_relationship_is_for_its_helpers_first_recover_alone() {
        let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
        let (paths, config) = crate::testing::set_up(dirs[0].path());
        let d = Daemon::start(paths, config).await.unwrap();
        let (paths, _) = crate::testing::set_up(dirs[1].path());
        let keys = crate::keys::Keys::load_or_create(&paths.device_key()).unwrap();
        let mut bo = crate::core::Core::load(&paths, Arc::new(keys)).unwrap();
        let (me, them) = (d.core().me().unwrap(), bo.me().unwrap());
        let all = |c: &crate::core::Core| c.identity.as_ref().unwrap().all_entries();
        let (mine, theirs) = (all(&d.core()), all(&bo));
        d.core().ingest_other(them, &theirs).unwrap();
        bo.ingest_other(me, &mine).unwrap();
        let (rel, _) = d.core().create_relationship(&them).unwrap();
        // whom the recovery is of
        let (ana, _) = log(5);
        let recover = |n: u8| {
            let phrase = RecoveryPhrase::from_entropy(&[n; 32]);
            crate::recovering::recover_entry(
                &ana.id(),
                &[ana.id()],
                &phrase.root_signing_key(),
                &[],
                d.keys.link.public_key(),
                ana.id(),
                phrase.recovery_key_pair().public_key(),
            )
            .unwrap()
        };
        let (first, second) = (recover(6), recover(7));
        // the first in a batch with someone else's entry, as a helper does
        let (other, _) = log(8);
        let with: Vec<Vec<u8>> = vec![first.encode(), other.entries().next().unwrap().encode()];
        carry(&d, &rel, &ana.id(), &with).unwrap();
        carry(&d, &rel, &ana.id(), &[second.encode()]).unwrap();
        let core = d.core();
        let sp = core.spaces[&rel].space.as_ref().unwrap();
        assert_eq!(relationship::carried(sp).len(), 3);
        let found = relationship_recover(sp, &me, &ana.id()).unwrap();
        assert_eq!(found.id(), first.id());
        // and only what that member carried counts
        assert!(relationship_recover(sp, &them, &ana.id()).is_none());
    }

    /// A change of guardians is read out as five words, of its entry and
    /// whom it names.
    #[test]
    fn a_change_has_a_fingerprint_of_five_words() {
        let mut p = Policy {
            entry: [1; 32],
            commitments: vec![[2; 32], [3; 32]],
            threshold: 2,
            delay: 60,
            records: Vec::new(),
            guardian_key: None,
            changes: Some([9; 32]),
        };
        let a = change_fingerprint(&p);
        assert_eq!(a.split(' ').count(), 5);
        assert_eq!(a, change_fingerprint(&p));
        p.commitments.push([4; 32]);
        assert_ne!(a, change_fingerprint(&p));
    }

    /// Guardian software never endorses or confirms a `recover` that keeps
    /// a key (D80).
    #[test]
    fn a_recover_that_keeps_a_key_is_refused() {
        let mut r = Recovery {
            entry: [1; 32],
            root: [2; 32],
            keep: Vec::new(),
            link_key: None,
            policy: [3; 32],
        };
        assert!(keeps_nothing(&r, "Ana").is_ok());
        r.keep.push([4; 32]);
        let e = keeps_nothing(&r, "Ana").unwrap_err();
        assert!(
            e.to_string().contains("keeps some of their old devices"),
            "{e}"
        );
    }

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
