//! Which space entries are valid, and who is a member
//! (`spaces.md#authors`, `spaces.md#evaluating-membership`).
//!
//! Two evaluations:
//!
//! - [`evaluate_single`]: native, for spaces whose only member identity is
//!   their creator (the account space and a personal files space). It is
//!   the `space` program of `model/rules.md` specialised by hand to one
//!   membership, and runs in time linear in the entries, plus a pass per
//!   removed signing key while entries wait to be witnessed. Spaces with
//!   other members get [`Error::Unsupported`].
//! - [`evaluate_full`]: the normative `space` program, executed by the
//!   identity crate's Datalog evaluator over facts derived as `world.py`
//!   derives them. Its graph facts are quadratic in the number of entries,
//!   so it suits small spaces and tests. A property test checks that the
//!   two agree on single-member spaces.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use cardinal_identity::dag::Dag;
use cardinal_identity::log::model_world;
use cardinal_identity::model::{self, hex_decode, hex_encode, intern_memberships, Op};
use cardinal_identity::{EntryId, IdentityLog, IdentityState, KeyId};

use crate::entry::{IdentityId, MembershipId, SpaceEntry, SpaceOpBody};
use crate::Error;

/// A membership: one identity, one role, for its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Membership {
    /// Its id.
    pub id: MembershipId,
    /// The member identity.
    pub identity: IdentityId,
    /// Role: 0 reader, 1 writer, 2 admin, 3 owner.
    pub role: u64,
}

/// The result of evaluating a space's entries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Validity {
    /// Valid entries.
    pub valid: HashSet<EntryId>,
    /// Entries whose signature counts as their author's.
    pub author_ok: HashSet<EntryId>,
    /// Memberships in effect.
    pub members: Vec<Membership>,
    /// Entries whose signing key was removed and which no witness keeps
    /// (yet); a later entry may witness them.
    pub unwitnessed: HashSet<EntryId>,
}

impl Validity {
    /// Whether an entry is valid.
    pub fn is_valid(&self, e: &EntryId) -> bool {
        self.valid.contains(e)
    }
}

fn genesis_of(dag: &Dag<SpaceEntry>) -> Option<&SpaceEntry> {
    dag.log_order().first().and_then(|g| dag.get(g))
}

/// The membership an entry is written under. The genesis entry carries no
/// field 9; it is written under the membership its `start` op creates.
pub fn membership_of(e: &SpaceEntry) -> Option<MembershipId> {
    if e.is_genesis() {
        e.genesis_membership()
    } else {
        e.membership()
    }
}

/// Native evaluation of a space whose only member identity is its creator.
pub fn evaluate_single(dag: &Dag<SpaceEntry>, author: &IdentityState) -> Result<Validity, Error> {
    let g = genesis_of(dag).ok_or(Error::Malformed("no genesis"))?;
    if !g.is_genesis() {
        return Err(Error::Malformed("no genesis"));
    }
    let owner = g.author();
    if author.identity != owner {
        return Err(Error::UnknownAuthor);
    }
    let i0 = g
        .genesis_membership()
        .ok_or(Error::Malformed("no start op"))?;
    for (_, e) in dag.iter() {
        if e.author() != owner {
            return Err(Error::Unsupported("an entry by another identity"));
        }
        if e.ops()
            .iter()
            .any(|o| matches!(o.body(), SpaceOpBody::AddMember { .. }))
        {
            return Err(Error::Unsupported("add_member"));
        }
    }
    let members = vec![Membership {
        id: i0,
        identity: owner,
        role: 3,
    }];
    let mut out = Validity {
        members: members.clone(),
        ..Validity::default()
    };
    if author.frozen {
        // a frozen author's entries count only as far as other, unfrozen
        // authors built on them; there are none
        return Ok(out);
    }
    let order = dag.log_order();
    let attrib: HashSet<EntryId> = order
        .iter()
        .filter(|x| {
            let e = dag.get(x).expect("entry");
            author.is_effective_at(&e.signer(), &e.author_head())
        })
        .copied()
        .collect();
    let mut ok: HashSet<EntryId> = attrib
        .iter()
        .filter(|x| !author.is_removed(&dag.get(x).expect("entry").signer()))
        .copied()
        .collect();
    // witnessing, to a fixpoint
    loop {
        let waiting: Vec<EntryId> = attrib
            .iter()
            .filter(|x| !ok.contains(*x))
            .copied()
            .collect();
        if waiting.is_empty() {
            break;
        }
        let keys: BTreeSet<KeyId> = waiting
            .iter()
            .map(|x| dag.get(x).expect("entry").signer())
            .collect();
        let mut grew = false;
        for k in keys {
            let mut from = Vec::new();
            let mut kept = Vec::new();
            for w in &ok {
                let we = dag.get(w).expect("entry");
                if we.signer() != k && !author.is_removed_at(&k, &we.author_head()) {
                    from.extend_from_slice(we.parents());
                }
                for op in we.ops() {
                    if let SpaceOpBody::Keep { key, entries } = op.body() {
                        if *key == k {
                            kept.extend_from_slice(entries);
                        }
                    }
                }
            }
            let mut covered = dag.ancestors_of(&from);
            covered.extend(dag.ancestors_of(&kept));
            for x in &waiting {
                if dag.get(x).expect("entry").signer() == k && covered.contains(x) {
                    ok.insert(*x);
                    grew = true;
                }
            }
        }
        if !grew {
            break;
        }
    }
    let bad3 = |e: &SpaceEntry| {
        e.ops().iter().any(|o| match o.body() {
            SpaceOpBody::Start { .. } => !e.is_genesis(),
            SpaceOpBody::RemoveMember { membership } => Some(*membership) != membership_of(e),
            SpaceOpBody::Unknown { number } => number.is_none_or(|n| n < 32),
            _ => false,
        })
    };
    // leaving: written under the membership, with a signature that counts
    let leaves: Vec<EntryId> = order
        .iter()
        .filter(|y| {
            let e = dag.get(y).expect("entry");
            ok.contains(*y)
                && membership_of(e) == Some(i0)
                && !bad3(e)
                && e.ops().iter().any(|o| match o.body() {
                    SpaceOpBody::RemoveMember { membership } => *membership == i0,
                    SpaceOpBody::Succeed { .. } => true,
                    _ => false,
                })
        })
        .copied()
        .collect();
    for x in order {
        let e = dag.get(x).expect("entry");
        if !(ok.contains(x) && membership_of(e) == Some(i0) && !bad3(e)) {
            continue;
        }
        let voided = leaves.iter().any(|y| {
            dag.is_ancestor(y, x)
                || (dag.concurrent(y, x) && dag.get(y).expect("entry").signer() == e.signer())
        });
        if !voided {
            out.valid.insert(*x);
        }
    }
    if !leaves.is_empty() {
        out.members.clear();
    }
    out.unwitnessed = attrib.difference(&ok).copied().collect();
    out.author_ok = ok;
    Ok(out)
}

/// Evaluates a space with the normative `space` program, given the
/// identity logs of its authors (and any logs their guardians'
/// confirmations need).
pub fn evaluate_full(dag: &Dag<SpaceEntry>, logs: &[&IdentityLog]) -> Result<Validity, Error> {
    let g = genesis_of(dag).ok_or(Error::Malformed("no genesis"))?;
    let space = g.id();
    let mut w = model_world(logs);
    let sym = |w: &mut model::World, b: &[u8]| w.sym(&hex_encode(b));
    let space_sym = sym(&mut w, &space);
    for (id, e) in dag.iter() {
        let ops = e
            .ops()
            .iter()
            .map(|o| match o.body() {
                SpaceOpBody::Start { .. } => Op::Create,
                SpaceOpBody::AddMember { identity, role } => Op::AddMember {
                    member: sym(&mut w, identity),
                    role: (*role).min(i64::MAX as u64) as i64,
                },
                SpaceOpBody::RemoveMember { membership } => Op::RemoveMember {
                    membership: sym(&mut w, membership),
                },
                SpaceOpBody::Keep { key, entries } => Op::Keep {
                    key: sym(&mut w, key),
                    entries: entries.iter().map(|x| sym(&mut w, x)).collect(),
                },
                SpaceOpBody::Succeed { .. } => Op::Succeed,
                SpaceOpBody::SetPolicy { .. } | SpaceOpBody::SetProtocol => Op::OwnerOnly,
                SpaceOpBody::Unknown { number } if number.is_none_or(|n| n < 32) => Op::Invalid,
                _ => Op::App,
            })
            .collect();
        let entry = model::Entry {
            id: sym(&mut w, id),
            log: space_sym,
            parents: e.parents().iter().map(|p| sym(&mut w, p)).collect(),
            signer: sym(&mut w, &e.signer()),
            ops,
            author: Some(sym(&mut w, &e.author())),
            head: Some(sym(&mut w, &e.author_head())),
            membership: membership_of(e).map(|m| sym(&mut w, &m)),
        };
        w.put(entry)
            .map_err(|_| Error::Malformed("space entries out of order"))?;
    }
    intern_memberships(&mut w);
    let ids = w.log_ids(space_sym);
    let r = model::evaluate_space(&w, space_sym, &ids, false, None);
    let id32 = |s: u32| -> EntryId { hex_decode(w.name(s)).try_into().unwrap_or([0; 32]) };
    let valid = r.unary("valid").into_iter().map(id32).collect();
    let author_ok: HashSet<EntryId> = r.unary("author_ok").into_iter().map(id32).collect();
    // memberships: created by add_member or start ops
    let mut created: BTreeMap<MembershipId, (IdentityId, u64)> = BTreeMap::new();
    for (id, e) in dag.iter() {
        for (n, o) in e.ops().iter().enumerate() {
            let m = crate::entry::derived_id(id, n);
            match o.body() {
                SpaceOpBody::Start { .. } => {
                    created.insert(m, (e.author(), 3));
                }
                SpaceOpBody::AddMember { identity, role } => {
                    created.insert(m, (*identity, *role));
                }
                _ => {}
            }
        }
    }
    let by_hex: HashMap<String, MembershipId> =
        created.keys().map(|m| (hex_encode(m), *m)).collect();
    let mut members = Vec::new();
    for s in r.unary("member") {
        if let Some(m) = by_hex.get(w.name(s)) {
            let (identity, role) = created[m];
            members.push(Membership {
                id: *m,
                identity,
                role,
            });
        }
    }
    members.sort();
    Ok(Validity {
        valid,
        author_ok,
        members,
        unwitnessed: HashSet::new(),
    })
}
