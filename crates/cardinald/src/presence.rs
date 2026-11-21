//! Trusted contacts find each other nearby (D74, `hosts.md#local-discovery`).
//!
//! Each identity keeps one **presence secret** in its account space (a
//! secret node with purpose `presence`) and gives it to each trusted
//! contact as field 2 of its reach node in the relationship they share. A
//! device advertises, beside its own-device tag `t=`, a tag `c=` made with
//! it; a contact's device that recognizes the tag connects to the address
//! as it would to one their host named, and only the session that follows
//! says whom it reached.
//!
//! What this module keeps:
//!
//! - a secret, made when the person first has a trusted contact to give it
//!   to, and made again when someone who was given it is refused or no
//!   longer trusted;
//! - field 2 of the person's reach node in each relationship with a
//!   trusted contact, set to the secret advertised with: of two made at
//!   the same moment, the one whose account node has the lowest id.
//!
//! Where a contact is refused or no longer trusted, field 2 of the
//! relationship with them is cleared as well as the secret renewed.
//!
//! A person may have two contact nodes for one identity, made at once on
//! two devices: they are one contact here, trusted only if every node says
//! so and none refuses them.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use cardinal_crypto::random_bytes;
use cardinal_encoding::Value;
use cardinal_space::entry::{NodeId, NodeKind, SpaceId, SpaceOp};
use cardinal_space::{account, relationship, ROOT};

use crate::core::Core;
use crate::daemon::Daemon;

/// The purpose a presence secret's account node gives.
pub const PURPOSE: &str = "presence";

/// Every presence secret in the account, by node id, lowest first.
pub fn secrets(core: &Core) -> Vec<(NodeId, [u8; 32])> {
    let Some(acc) = core.account().and_then(|h| h.space.as_ref()) else {
        return Vec::new();
    };
    let st = acc.state();
    let mut all: Vec<(NodeId, [u8; 32])> = st
        .children(&ROOT)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(account::SECRET) && !n.deleted)
        .filter(|n| n.field(1).and_then(Value::as_text) == Some(PURPOSE))
        .filter_map(|n| Some((n.id, n.field(2)?.as_bytes()?.try_into().ok()?)))
        .collect();
    all.sort();
    all
}

/// The secret this person's devices advertise with: of those the account
/// holds, the one whose node has the lowest id.
pub fn current(core: &Core) -> Option<[u8; 32]> {
    secrets(core).first().map(|(_, s)| *s)
}

/// Each contact once, by identity: whether this person trusts them (every
/// node for them trusted, none refused), and every relationship space
/// their nodes name.
pub fn by_identity(core: &Core) -> BTreeMap<[u8; 32], (bool, Vec<SpaceId>)> {
    let mut all: BTreeMap<[u8; 32], (bool, Vec<SpaceId>)> = BTreeMap::new();
    for c in core.contacts() {
        let e = all.entry(c.identity).or_insert((true, Vec::new()));
        e.0 &= c.connects();
        if !e.1.contains(&c.space) {
            e.1.push(c.space);
        }
    }
    all
}

/// The secret to put in `c=`, if the person has given it to anyone: a
/// device whose person has given it to nobody leaves `c=` out.
pub fn advertised(core: &Core) -> Option<[u8; 32]> {
    let secret = current(core)?;
    let me = core.me()?;
    let trusted = by_identity(core).into_values().filter(|(t, _)| *t);
    let given = trusted.flat_map(|(_, spaces)| spaces).any(|space| {
        let st = core.spaces.get(&space).and_then(|h| h.space.as_ref());
        st.is_some_and(|sp| relationship::presence_of(sp.state(), &me).contains(&secret))
    });
    given.then_some(secret)
}

/// Every presence secret each trusted contact gives this person, by
/// contact: what a `c=` tag is checked against, one keyed hash each.
pub fn of_contacts(core: &Core) -> Vec<([u8; 32], [u8; 32])> {
    let mut all = Vec::new();
    for (who, (trusted, spaces)) in by_identity(core) {
        if !trusted {
            continue;
        }
        for space in spaces {
            let Some(sp) = core.spaces.get(&space).and_then(|h| h.space.as_ref()) else {
                continue;
            };
            for s in relationship::presence_of(sp.state(), &who) {
                if !all.contains(&(who, s)) {
                    all.push((who, s));
                }
            }
        }
    }
    all
}

/// What [`keep`] is to write: a new secret in the account, and the
/// relationships whose field 2 is to be set to the current secret.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Due {
    /// The account's presence secret nodes to delete, and the new one to
    /// make, where a new one is due.
    pub renew: Option<(Vec<NodeId>, [u8; 32])>,
    /// Relationships to set field 2 in, with the secret to set.
    pub give: Vec<(SpaceId, [u8; 32])>,
    /// Relationships with someone refused or no longer trusted, where
    /// field 2 is to be cleared.
    pub clear: Vec<SpaceId>,
}

/// What is due now, with `fresh` making a new secret if one is.
pub fn due(core: &Core, fresh: impl FnOnce() -> [u8; 32]) -> Due {
    let Some(me) = core.me() else {
        return Due::default();
    };
    if core.account().and_then(|h| h.space.as_ref()).is_none() {
        return Due::default();
    }
    let held = secrets(core);
    let in_use: Vec<[u8; 32]> = held.iter().map(|(_, s)| *s).collect();
    let contacts = by_identity(core);
    // field 2 of this person's reach node in every relationship held,
    // ended or left too, and whether it can still be written in
    let mut given: HashMap<SpaceId, (Vec<[u8; 32]>, bool)> = HashMap::new();
    for (_, spaces) in contacts.values() {
        for space in spaces {
            let Some(sp) = core.spaces.get(space).and_then(|h| h.space.as_ref()) else {
                continue;
            };
            let open = !sp.ended() && !sp.has_left(&me);
            given.insert(*space, (relationship::presence_of(sp.state(), &me), open));
        }
    }
    let open = |space: &SpaceId| given.get(space).is_some_and(|(_, o)| *o);
    let trusted: Vec<SpaceId> = contacts
        .values()
        .filter(|(t, _)| *t)
        .flat_map(|(_, spaces)| spaces.iter().copied())
        .filter(|s| open(s))
        .collect();
    // Someone refused, or trusted no longer, who was given a secret still
    // in use, anywhere: a new one, which they are not given.
    let untrusted: Vec<SpaceId> = contacts
        .values()
        .filter(|(t, _)| !*t)
        .flat_map(|(_, spaces)| spaces.iter().copied())
        .collect();
    let lost = untrusted.iter().any(|space| {
        let had = given
            .get(space)
            .map(|(v, _)| v.as_slice())
            .unwrap_or_default();
        had.iter().any(|s| in_use.contains(s))
    });
    let mut clear: Vec<SpaceId> = Vec::new();
    for space in &untrusted {
        let set = given.get(space).is_some_and(|(v, o)| *o && !v.is_empty());
        if set && !clear.contains(space) {
            clear.push(*space);
        }
    }
    let mut out = Due {
        clear,
        ..Due::default()
    };
    let secret = if lost || (held.is_empty() && !trusted.is_empty()) {
        let new = fresh();
        out.renew = Some((held.iter().map(|(n, _)| *n).collect(), new));
        new
    } else {
        match held.first() {
            Some((_, s)) => *s,
            None => return out,
        }
    };
    for space in trusted {
        if given.get(&space).map(|(v, _)| v.as_slice()) != Some(&[secret][..]) {
            out.give.push((space, secret));
        }
    }
    out
}

/// Keeps the presence secret, and gives it where it is due (D74).
pub fn keep(d: &Arc<Daemon>) {
    let (due, account) = {
        let core = d.core();
        (due(&core, random_bytes), core.account_id())
    };
    let Some(account) = account else {
        return;
    };
    let me = match d.core().me() {
        Some(me) => me,
        None => return,
    };
    if let Some((old, new)) = &due.renew {
        let mut ops: Vec<SpaceOp> = old.iter().map(|n| SpaceOp::delete(*n)).collect();
        ops.push(crate::core::create_secret(PURPOSE, new));
        if let Err(e) = d.write_and_push(&account, ops) {
            tracing::warn!("cannot keep a new presence secret: {e:#}");
            return;
        }
        tracing::info!("a new presence secret, for the contacts you trust");
    }
    for space in due.clear {
        let op = relationship::set_presence(&me, None);
        if let Err(e) = d.write_and_push(&space, vec![op]) {
            tracing::debug!(
                "taking the presence secret back in {}: {e:#}",
                crate::core::short(&space)
            );
        }
    }
    for (space, secret) in due.give {
        let op = relationship::set_presence(&me, Some(secret));
        if let Err(e) = d.write_and_push(&space, vec![op]) {
            tracing::debug!(
                "giving the presence secret in {}: {e:#}",
                crate::core::short(&space)
            );
        }
    }
}
