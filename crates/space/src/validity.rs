//! Which space entries are valid, and who is a member
//! (`spaces.md#authors`, `spaces.md#which-entries-are-valid`).
//!
//! A space only grows: members are added and roles are given, and nothing in
//! a space takes either away. So what an entry may do is settled by its own
//! causal past, and only a signature reaches it from outside: an identity
//! log that changes which keys count, a witness, or a `keep`.
//!
//! Two evaluations:
//!
//! - [`Judge`]: native, for every space. Each entry is judged once, when it
//!   arrives, from what is kept about its causal past, and again only when a
//!   signature it rests on starts or stops counting. An entry costs the same
//!   at the twenty-thousandth as at the twentieth.
//! - [`by_rules`]: the normative `space` program of `model/rules.md`,
//!   executed by the identity crate's Datalog evaluator over facts derived
//!   as `world.py` derives them. Its graph facts are quadratic in the number
//!   of entries. Nothing here calls it; property tests check the native
//!   evaluation against it on random histories.
//!
//! # How an entry is judged once
//!
//! Only two kinds of entry have anything resting on them: one that adds a
//! member, on which what that member writes afterwards rests, and one that
//! names a successor, on which the closing of what follows rests. Each such
//! entry gets a number, its *mark*, and every entry keeps the set of marks
//! in its causal past as a bit set: the union of its parents' sets, with a
//! parent's own mark where it has one. Most entries share their parent's
//! set outright. An author's roles in an entry's past are then the roles
//! given by the valid additions in its set that name the author, and the
//! space had ended there if the set holds the namings the rules ask for.
//! Neither needs a walk of the graph.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use cardinal_identity::dag::Dag;
use cardinal_identity::datalog::Val;
use cardinal_identity::log::model_world;
use cardinal_identity::model::{self, hex_decode, hex_encode, Op};
use cardinal_identity::{EntryId, IdentityLog, IdentityState, KeyId};

use crate::entry::{IdentityId, SpaceEntry, SpaceId, SpaceOpBody, ADMIN, OWNER, READER, WRITER};
use crate::state::reach_node_id;
use crate::Error;

/// A member: an identity, with a role a valid entry gave it. An identity
/// holds every role it was given, and may do what the highest allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Member {
    /// The member identity.
    pub identity: IdentityId,
    /// Role: 0 reader, 1 writer, 2 admin, 3 owner.
    pub role: u64,
}

/// The result of judging a space's entries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Validity {
    /// Valid entries.
    pub valid: HashSet<EntryId>,
    /// Entries whose signature counts as their author's.
    pub author_ok: HashSet<EntryId>,
    /// The members: each identity with each role a valid entry gave it,
    /// sorted.
    pub members: Vec<Member>,
    /// Entries whose signing key was in effect at the head they cite and has
    /// been removed since, which no witness or `keep` vouches for (yet).
    pub unwitnessed: HashSet<EntryId>,
    /// Entries that would be valid and use an extension critical for them,
    /// which this verifier does not know (`evolution.md#what-a-device-does-with-a-critical-extension-it-does-not-know`):
    /// they, and everything that descends from them, are not valid here
    /// until it does. Nothing here knows any extension.
    pub stalled: HashSet<EntryId>,
}

impl Validity {
    /// Whether an entry is valid.
    pub fn is_valid(&self, e: &EntryId) -> bool {
        self.valid.contains(e)
    }

    /// The highest role `who` holds, if they are a member.
    pub fn role_of(&self, who: &IdentityId) -> Option<u64> {
        let mine = self.members.iter().filter(|m| m.identity == *who);
        mine.map(|m| m.role).max()
    }

    /// The member identities, each once, sorted.
    pub fn identities(&self) -> Vec<IdentityId> {
        let mut v: Vec<IdentityId> = self.members.iter().map(|m| m.identity).collect();
        v.dedup();
        v
    }
}

// ------------------------------------------------------------ reading ops

/// What an op is to the rules: the op names of `world.py`, and two more for
/// ops the model leaves out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Start,
    Add,
    Leave,
    Succeed,
    Keep,
    /// Application data, and `rotate`: writers and up.
    App,
    /// The author's own reach node: any role.
    Reach,
    /// `set_policy` and `set_protocol`: the owner only.
    OwnerOnly,
    /// A control op this implementation does not define, or a malformed op:
    /// no role.
    Invalid,
    /// An extension op, before the protocol records say what it is.
    Ext([u8; 32]),
    /// An extension op a protocol record declares: it changes nothing
    /// about validity, so any member may write it. Where it is marked
    /// critical, the entry is opaque besides.
    Declared,
}

/// The protocol records an entry carries: its `start`'s, and each
/// `set_protocol`'s.
fn protocols(e: &SpaceEntry) -> Vec<cardinal_identity::Protocol> {
    let mut out = Vec::new();
    for op in e.ops() {
        let r = match op.body() {
            SpaceOpBody::Start {
                protocol: Some(p), ..
            } => Some(p),
            SpaceOpBody::SetProtocol => op.record().get(1).and_then(|v| v.as_record()),
            _ => None,
        };
        if let Some(p) = r.and_then(|r| cardinal_identity::Protocol::from_record(r).ok()) {
            out.push(p);
        }
    }
    out
}

/// The mark of extension `name` in these records: critical if any marks
/// it so, ignorable if all that name it say ignorable, `None` where none
/// declares it (`evolution.md#critical-and-ignorable`).
fn mark_in(records: &[cardinal_identity::Protocol], name: &[u8; 32]) -> Option<bool> {
    let mut mark = None;
    for p in records {
        for (n, critical) in &p.extensions {
            if n == name {
                mark = Some(mark.unwrap_or(false) || *critical);
            }
        }
    }
    mark
}

/// The mark of extension `name` for entry `id` of a space: what the
/// protocol records in its causal past, or in it, say. Only the records
/// the space's genesis holds, and those its owner wrote, count: only the
/// owner may write `set_protocol` (`evolution.md#declaring-what-you-speak`),
/// so no one else's declares anything, valid or not.
fn extension_mark(
    dag: &Dag<SpaceEntry>,
    genesis: Option<EntryId>,
    owner: Option<IdentityId>,
    id: &EntryId,
    e: &SpaceEntry,
    name: &[u8; 32],
) -> Option<bool> {
    let past = if e.is_genesis() {
        HashSet::new()
    } else {
        dag.ancestors_of(e.parents())
    };
    let mut records = Vec::new();
    let mine = std::iter::once((*id, e));
    let earlier = past.iter().filter_map(|x| Some((*x, dag.get(x)?)));
    for (x, xe) in mine.chain(earlier) {
        if Some(x) == genesis || (e.is_genesis() && x == *id) || Some(xe.author()) == owner {
            records.extend(protocols(xe));
        }
    }
    mark_in(&records, name)
}

/// What an op is to the rules, read from the entry alone
/// (`spaces.md#members-and-roles`). A `set` on its author's own reach node,
/// whose id follows from the author's, is the one op numbered 32 or above
/// that a reader may write. Every other such op is an application op,
/// whether or not the profile defines it.
fn class(e: &SpaceEntry, op: &SpaceOpBody) -> Class {
    match op {
        SpaceOpBody::Start { .. } => Class::Start,
        SpaceOpBody::AddMember { .. } => Class::Add,
        SpaceOpBody::Leave => Class::Leave,
        SpaceOpBody::Succeed { .. } => Class::Succeed,
        SpaceOpBody::Keep { .. } => Class::Keep,
        SpaceOpBody::SetPolicy { .. } | SpaceOpBody::SetProtocol => Class::OwnerOnly,
        SpaceOpBody::Unknown { number } if number.is_none_or(|n| n < 32) => Class::Invalid,
        SpaceOpBody::Extension { name } => Class::Ext(*name),
        SpaceOpBody::Set { node, .. } if *node == reach_node_id(&e.author()) => Class::Reach,
        _ => Class::App,
    }
}

/// The least role that may perform an op of a class outside a genesis, or
/// `None` if no role may (the roles table of `spaces.md#members-and-roles`).
fn least_role(class: Class, op: &SpaceOpBody, has_owner: bool) -> Option<u64> {
    match class {
        Class::Leave | Class::Keep | Class::Reach | Class::Declared => Some(READER),
        Class::App => Some(WRITER),
        // only a genesis names an owner
        Class::Add => match op {
            SpaceOpBody::AddMember { role, .. } if *role <= ADMIN => Some(ADMIN),
            _ => None,
        },
        Class::OwnerOnly => Some(OWNER),
        // the owner's alone; with no owner, every member's
        Class::Succeed => Some(if has_owner { OWNER } else { READER }),
        Class::Start | Class::Invalid | Class::Ext(_) => None,
    }
}

/// What a genesis says of its space (`genesis_shape` in `world.py`).
#[derive(Clone, Debug)]
struct Genesis {
    id: EntryId,
    /// Whether it is formed as `spaces.md#members-and-roles` requires.
    formed: bool,
    /// The owner it names, if it names exactly its own author as one.
    owner: Option<IdentityId>,
    /// Who must name a successor: the owner, or with no owner everyone the
    /// genesis names.
    deciders: Vec<IdentityId>,
    /// The members it names.
    adds: Vec<(IdentityId, u64)>,
    /// The highest role it gives each identity it names.
    top: HashMap<IdentityId, u64>,
}

impl Genesis {
    fn read(id: &EntryId, e: &SpaceEntry) -> Genesis {
        let author = e.author();
        let mut adds = Vec::new();
        let mut starts = 0;
        let mut others = Vec::new();
        let records = protocols(e);
        for op in e.ops() {
            let class = match class(e, op.body()) {
                Class::Ext(name) if mark_in(&records, &name).is_some() => Class::Declared,
                Class::Ext(_) => Class::Invalid,
                c => c,
            };
            match (class, op.body()) {
                (Class::Start, _) => starts += 1,
                (Class::Add, SpaceOpBody::AddMember { identity, role, .. }) => {
                    adds.push((*identity, *role))
                }
                (class, body) => others.push((class, body)),
            }
        }
        let mut top: HashMap<IdentityId, u64> = HashMap::new();
        for (m, r) in &adds {
            let t = top.entry(*m).or_insert(*r);
            *t = (*t).max(*r);
        }
        let owners: BTreeSet<IdentityId> = adds
            .iter()
            .filter(|(_, r)| *r == OWNER)
            .map(|(m, _)| *m)
            .collect();
        let owner = (owners.len() == 1 && owners.contains(&author)).then_some(author);
        let formed = starts == 1
            && top.contains_key(&author)
            && owners.iter().all(|m| *m == author)
            && adds.iter().filter(|(_, r)| *r == OWNER).count() <= 1
            && adds.iter().all(|(_, r)| *r <= OWNER)
            && (owner.is_some() || adds.iter().all(|(_, r)| *r < ADMIN))
            // besides `start` and `add_member`, only what the highest role
            // it gives its author may perform; never a `succeed`
            && others.iter().all(|(class, body)| {
                *class != Class::Succeed
                    && least_role(*class, body, true).is_some_and(|need| need <= top[&author])
            });
        let deciders = match owner {
            Some(o) => vec![o],
            None => {
                let named: BTreeSet<IdentityId> = adds.iter().map(|(m, _)| *m).collect();
                named.into_iter().collect()
            }
        };
        Genesis {
            id: *id,
            formed,
            owner,
            deciders,
            adds,
            top,
        }
    }
}

// --------------------------------------------------------------- bit sets

/// How many words a block of a set of marks holds.
const BLOCK: usize = 16;
/// How many marks that is.
const BLOCK_BITS: u32 = (BLOCK * 64) as u32;

/// A set of marks, in blocks that sets share. Every entry keeps the set of
/// marks in its causal past, and along a chain each differs from the one
/// before by a mark or two: kept flat, a chain of N marked entries held N
/// squared over sixteen bytes of them. Here a set that is made from
/// another holds the same blocks and its own copy of those that differ.
///
/// Bits are only ever set, a block that is there has a bit set, and the
/// vector never ends in a block that is not there: so equal sets are equal
/// vectors.
#[derive(Clone, Debug, Default)]
struct Bits(Vec<Shared>);

/// One block of a set of marks, if any of its marks is set.
type Shared = Option<Arc<[u64; BLOCK]>>;

impl PartialEq for Bits {
    fn eq(&self, other: &Bits) -> bool {
        let same = |(a, b): (&Shared, &Shared)| match (a, b) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b) || a == b,
            (None, None) => true,
            _ => false,
        };
        self.0.len() == other.0.len() && self.0.iter().zip(&other.0).all(same)
    }
}

impl Eq for Bits {}

impl Bits {
    fn get(&self, i: u32) -> bool {
        let block = self.0.get((i / BLOCK_BITS) as usize);
        let word = block
            .and_then(|b| b.as_ref())
            .map(|b| b[(i % BLOCK_BITS / 64) as usize]);
        word.is_some_and(|w| w >> (i % 64) & 1 == 1)
    }

    fn set(&mut self, i: u32) {
        if self.get(i) {
            return;
        }
        let at = (i / BLOCK_BITS) as usize;
        if self.0.len() <= at {
            self.0.resize(at + 1, None);
        }
        let block = self.0[at].get_or_insert_with(|| Arc::new([0; BLOCK]));
        // its own copy, if another set holds this block too
        Arc::make_mut(block)[(i % BLOCK_BITS / 64) as usize] |= 1 << (i % 64);
    }

    fn union_with(&mut self, other: &Bits) {
        if self.0.len() < other.0.len() {
            self.0.resize(other.0.len(), None);
        }
        for (mine, theirs) in self.0.iter_mut().zip(&other.0) {
            let Some(theirs) = theirs else { continue };
            match mine {
                // the same block, shared
                None => *mine = Some(theirs.clone()),
                Some(mine) if Arc::ptr_eq(mine, theirs) => {}
                Some(mine) => {
                    // a copy only if it brings something
                    if mine.iter().zip(theirs.iter()).any(|(a, b)| b & !a != 0) {
                        for (a, b) in Arc::make_mut(mine).iter_mut().zip(theirs.iter()) {
                            *a |= b;
                        }
                    }
                }
            }
        }
    }

    fn intersects(&self, other: &Bits) -> bool {
        let both = self.0.iter().zip(&other.0);
        let mut blocks = both.filter_map(|(a, b)| Some((a.as_ref()?, b.as_ref()?)));
        blocks.any(|(a, b)| a.iter().zip(b.iter()).any(|(a, b)| a & b != 0))
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// ------------------------------------------------------------- the judge

/// What an entry holds that the rules read, beyond its signature.
#[derive(Clone, Debug, Default)]
struct Marked {
    /// `add_member` ops: who, and the role.
    adds: Vec<(IdentityId, u64)>,
    /// `succeed` ops: the successors named.
    names: Vec<SpaceId>,
    /// `keep` ops: the key, and the entries listed.
    keeps: Vec<(KeyId, Vec<EntryId>)>,
}

/// What is kept about one entry.
#[derive(Clone, Debug)]
struct Info {
    /// The marks in its causal past.
    past: Arc<Bits>,
    /// Its own mark, if it adds a member or names a successor.
    mark: Option<u32>,
    /// The least role that may perform all of its ops; `None` if no role
    /// may. Not read for a genesis, which is judged by its shape.
    need: Option<u64>,
    /// It ends or begins a space: it holds a `succeed`, or it is a genesis
    /// whose `start` names a space it succeeds. Kept, never witnessed.
    structural: bool,
    /// Its signing key was in effect at the head it cites.
    attrib: bool,
    /// Its signature counts as its author's.
    ok: bool,
    /// It is valid.
    valid: bool,
    /// It names a successor, and that naming counts towards the end of the
    /// space: its author must name one, its signature counts, and a role
    /// the genesis gave its author may perform all of its ops.
    named: bool,
    /// It uses an extension critical for it, which this verifier does not
    /// know: valid by the rules, it is where this verifier stops. Its
    /// signature witnesses nothing, its `keep` ops keep nothing and its
    /// `succeed` names nothing here.
    opaque: bool,
    marked: Option<Box<Marked>>,
}

/// Judges the entries of one space as they arrive.
///
/// The graph is kept by the caller and passed to each call; an entry is
/// given to [`Judge::arrive`] once it and all of its ancestors are in the
/// graph, in the order they were added to it.
#[derive(Clone, Debug)]
pub struct Judge {
    info: HashMap<EntryId, Info>,
    /// Marked entries, by mark.
    marks: Vec<EntryId>,
    /// By identity: the marks of entries after the genesis that add it, and
    /// the role each gives.
    adds_of: HashMap<IdentityId, Vec<(u32, u64)>>,
    /// The marks of entries that name a successor.
    succeeds: Vec<u32>,
    /// Entries by author.
    by_author: HashMap<IdentityId, Vec<EntryId>>,
    /// Entries with a `leave`, by author.
    leaves: HashMap<IdentityId, Vec<EntryId>>,
    /// By author and signing key: entries whose key was in effect at the
    /// cited head and has been removed since, that nothing vouches for.
    waiting: HashMap<IdentityId, HashMap<KeyId, HashSet<EntryId>>>,
    /// By entry id: the entries whose `keep` ops list it, here or not yet.
    listed: HashMap<EntryId, Vec<EntryId>>,
    /// The evaluated identity logs of authors, as far as they are held.
    states: HashMap<IdentityId, Arc<IdentityState>>,
    genesis: Option<Genesis>,
    /// The genesis is valid: its signature counts and it is well formed.
    root: bool,
    validity: Validity,
}

impl Default for Judge {
    fn default() -> Judge {
        Judge::new()
    }
}

impl Judge {
    /// A judge for a space that holds no entries yet.
    pub fn new() -> Judge {
        Judge {
            info: HashMap::new(),
            marks: Vec::new(),
            adds_of: HashMap::new(),
            succeeds: Vec::new(),
            by_author: HashMap::new(),
            leaves: HashMap::new(),
            waiting: HashMap::new(),
            listed: HashMap::new(),
            states: HashMap::new(),
            genesis: None,
            root: false,
            validity: Validity::default(),
        }
    }

    /// What has been found.
    pub fn validity(&self) -> &Validity {
        &self.validity
    }

    /// The owner the genesis names, if it is well formed and names one.
    pub fn owner(&self) -> Option<IdentityId> {
        self.genesis.as_ref().filter(|g| g.formed)?.owner
    }

    /// Who must name a successor for the space to end: its owner, or with
    /// no owner every identity its genesis names.
    pub fn deciders(&self) -> &[IdentityId] {
        self.genesis.as_ref().map_or(&[], |g| &g.deciders)
    }

    fn marked(&self, id: &EntryId) -> Option<&Marked> {
        self.info.get(id)?.marked.as_deref()
    }

    // ---------------------------------------------------------- arrival

    /// Judges an entry that has just been added to `dag`. Returns the
    /// entries whose validity changed: the new one if it is valid, and any
    /// that its signature, as a witness or a `keep`, made count.
    ///
    /// # Panics
    ///
    /// If the entry or one of its parents is not in `dag`, or a parent was
    /// never given to this judge.
    pub fn arrive(&mut self, dag: &Dag<SpaceEntry>, id: &EntryId) -> Vec<EntryId> {
        let e = dag.get(id).expect("an entry that arrived is in the graph");
        let (author, key, head) = (e.author(), e.signer(), e.author_head());
        // A space has one genesis: its id is the space's. A second entry
        // without parents is nothing here, whatever it says.
        let genesis = e.is_genesis() && self.genesis.as_ref().is_none_or(|g| g.id == *id);
        if genesis && self.genesis.is_none() {
            self.genesis = Some(Genesis::read(id, e));
        }
        let has_owner = self.genesis.as_ref().is_some_and(|g| g.owner.is_some());
        // what it holds
        let mut marked = Marked::default();
        let mut need = (genesis || !e.is_genesis()).then_some(READER);
        let mut structural = false;
        let mut leave = false;
        let mut opaque = false;
        let (gid, owner) = (self.genesis.as_ref().map(|g| g.id), self.owner());
        for op in e.ops() {
            // An extension op is what the protocol records say: an op
            // nobody defined where none declares it, and otherwise nothing
            // to validity, opaque where marked critical, since nothing
            // here knows any extension (`evolution.md#critical-and-ignorable`).
            let class = match class(e, op.body()) {
                Class::Ext(name) => match extension_mark(dag, gid, owner, id, e, &name) {
                    None => Class::Invalid,
                    Some(critical) => {
                        opaque |= critical;
                        Class::Declared
                    }
                },
                c => c,
            };
            need = match (need, least_role(class, op.body(), has_owner)) {
                (Some(a), Some(b)) => Some(a.max(b)),
                _ => None,
            };
            match op.body() {
                SpaceOpBody::Start { succession, .. } => {
                    structural |= genesis && succession.succeeds.is_some()
                }
                SpaceOpBody::AddMember { identity, role, .. } => {
                    marked.adds.push((*identity, *role))
                }
                SpaceOpBody::Succeed { successor, .. } => {
                    marked.names.push(*successor);
                    structural = true;
                }
                SpaceOpBody::Keep { key, entries } => marked.keeps.push((*key, entries.clone())),
                SpaceOpBody::Leave => leave = true,
                _ => {}
            }
        }
        if opaque {
            // what this verifier cannot read vouches for nothing and ends
            // nothing
            marked.keeps.clear();
            marked.names.clear();
        }
        let past = if e.is_genesis() {
            Arc::new(Bits::default())
        } else {
            self.past_of(e.parents())
        };
        // a genesis is in every other entry's past, and needs no mark; an
        // opaque entry has one, so that what descends from it is judged
        // again when it comes to stop the verifier or stops doing so
        let rests = !marked.adds.is_empty() || !marked.names.is_empty() || opaque;
        let mark = (rests && !genesis).then(|| {
            self.marks.push(*id);
            (self.marks.len() - 1) as u32
        });
        if let Some(m) = mark {
            for (who, role) in &marked.adds {
                self.adds_of.entry(*who).or_default().push((m, *role));
            }
            if !marked.names.is_empty() {
                self.succeeds.push(m);
            }
        }
        for (_, entries) in &marked.keeps {
            for listed in entries {
                self.listed.entry(*listed).or_default().push(*id);
            }
        }
        self.by_author.entry(author).or_default().push(*id);
        if leave {
            self.leaves.entry(author).or_default().push(*id);
        }
        let nothing = marked.adds.is_empty() && marked.names.is_empty() && marked.keeps.is_empty();
        self.info.insert(
            *id,
            Info {
                past,
                mark,
                need,
                structural,
                attrib: false,
                ok: false,
                valid: false,
                named: false,
                opaque,
                marked: (!nothing).then(|| Box::new(marked)),
            },
        );

        // whether its signature counts
        let state = self.states.get(&author).cloned();
        let attrib = state
            .as_ref()
            .is_some_and(|st| st.is_effective_at(&key, &head));
        let removed = state.as_ref().is_some_and(|st| st.is_removed(&key));
        let ok = attrib && (!removed || self.kept_already(dag, id, &author, &key));
        let mut counted = Vec::new();
        if attrib && !ok {
            let of_author = self.waiting.entry(author).or_default();
            of_author.entry(key).or_default().insert(*id);
            self.validity.unwitnessed.insert(*id);
        }
        // a `keep` that was here first lists it: what waited on that
        for keeper in self.listed.get(id).cloned().unwrap_or_default() {
            if self.info.get(&keeper).is_some_and(|i| i.ok) {
                self.keep_from(dag, &keeper, Some(id), &mut counted);
            }
        }
        // What that has made count vouches in turn, as a witness and by
        // its own `keep` ops, exactly as it would had the `keep` come
        // last: validity does not turn on the order of arrival.
        for kept in counted.clone() {
            self.vouch_from(dag, kept, &mut counted);
        }
        if ok {
            let i = self.info.get_mut(id).expect("just added");
            i.attrib = true;
            i.ok = true;
            self.validity.author_ok.insert(*id);
            self.vouch_from(dag, *id, &mut counted);
        } else {
            self.info.get_mut(id).expect("just added").attrib = attrib;
        }
        // The new entry may have come to count through a `keep` just now,
        // and what it rests on may have come to count through it.
        counted.retain(|x| x != id);
        if counted.is_empty() {
            // nothing else moved: judge it where it stands
            let mut changed = Vec::new();
            if genesis {
                self.root = self.root_now();
            }
            let named = self.named_now(dag, id);
            let (valid, stops) = self.judge_now(dag, id);
            if stops {
                self.validity.stalled.insert(*id);
            }
            let i = self.info.get_mut(id).expect("just added");
            i.named = named;
            i.valid = valid;
            if valid {
                self.validity.valid.insert(*id);
                changed.push(*id);
                if mark.is_some() || genesis {
                    self.refresh_members();
                }
            }
            return changed;
        }
        counted.push(*id);
        self.rejudge(dag, counted)
    }

    /// The marks in the causal past of an entry with these parents.
    fn past_of(&self, parents: &[EntryId]) -> Arc<Bits> {
        let of = |p: &EntryId| self.info.get(p).expect("parents arrive first");
        if let [one] = parents {
            let i = of(one);
            if i.mark.is_none() {
                return i.past.clone();
            }
        }
        let mut bits = Bits::default();
        for p in parents {
            let i = of(p);
            bits.union_with(&i.past);
            if let Some(m) = i.mark {
                bits.set(m);
            }
        }
        // most merges add nothing to one side: share that side's set
        match parents.iter().find(|p| *of(p).past == bits) {
            Some(p) => of(p).past.clone(),
            None => Arc::new(bits),
        }
    }

    // ------------------------------------------------------- signatures

    /// Whether a `keep` already here, whose signature counts, lists the new
    /// entry `id` by `key`. (It has no descendants yet for one to list.)
    fn kept_already(
        &self,
        dag: &Dag<SpaceEntry>,
        id: &EntryId,
        author: &IdentityId,
        key: &KeyId,
    ) -> bool {
        let keepers = self.listed.get(id).map_or(&[][..], |v| v.as_slice());
        keepers.iter().any(|w| {
            let counts = self.info.get(w).is_some_and(|i| i.ok);
            let same = dag.get(w).is_some_and(|we| we.author() == *author);
            let keeps = self.marked(w).map_or(&[][..], |m| m.keeps.as_slice());
            counts && same && keeps.iter().any(|(k, es)| k == key && es.contains(id))
        })
    }

    fn count(&mut self, id: &EntryId, author: &IdentityId, key: &KeyId) {
        if let Some(i) = self.info.get_mut(id) {
            i.ok = true;
        }
        if let Some(of_author) = self.waiting.get_mut(author) {
            if let Some(of_key) = of_author.get_mut(key) {
                of_key.remove(id);
                if of_key.is_empty() {
                    of_author.remove(key);
                }
            }
            if of_author.is_empty() {
                self.waiting.remove(author);
            }
        }
        self.validity.unwitnessed.remove(id);
        self.validity.author_ok.insert(*id);
    }

    /// The entry `first` has come to count: everything that comes to count
    /// through it, as a witness or by its `keep` ops, and through those in
    /// turn. Adds them to `counted`.
    fn vouch_from(&mut self, dag: &Dag<SpaceEntry>, first: EntryId, counted: &mut Vec<EntryId>) {
        let mut todo = vec![first];
        while let Some(w) = todo.pop() {
            let before = counted.len();
            self.witness_from(dag, &w, counted);
            self.keep_from(dag, &w, None, counted);
            todo.extend_from_slice(&counted[before..]);
        }
    }

    /// Built on by another of the author's keys, while that key was still
    /// trusted: the entries of `w`'s author that wait and that `w`, whose
    /// signature counts, witnesses.
    fn witness_from(&mut self, dag: &Dag<SpaceEntry>, w: &EntryId, counted: &mut Vec<EntryId>) {
        if self.info.get(w).is_some_and(|i| i.opaque) {
            return;
        }
        let Some(we) = dag.get(w) else { return };
        let (author, key, head) = (we.author(), we.signer(), we.author_head());
        let (Some(waiting), Some(state)) = (self.waiting.get(&author), self.states.get(&author))
        else {
            return;
        };
        let mut found = Vec::new();
        // Where much waits, one walk from `w` answers for all of it.
        let many = waiting.values().map(|ys| ys.len()).sum::<usize>() > 16;
        let past = many.then(|| dag.ancestors(w));
        let built_on = |y: &EntryId| match &past {
            Some(past) => past.contains(y),
            None => dag.is_ancestor(y, w),
        };
        for (k, ys) in waiting {
            // a head that holds the removal of the key vouches for nothing
            // that key signed
            if *k == key || state.is_removed_at(k, &head) {
                continue;
            }
            for y in ys {
                let plain = self.info.get(y).is_some_and(|i| !i.structural);
                if plain && built_on(y) {
                    found.push((*y, *k));
                }
            }
        }
        for (y, k) in found {
            self.count(&y, &author, &k);
            counted.push(y);
        }
    }

    /// Listed, or an ancestor of an entry listed, by a `keep` of the
    /// author's: the entries of `w`'s author that wait and that the `keep`
    /// ops of `w`, whose signature counts, keep. With `only`, just through
    /// the listing of that one entry.
    fn keep_from(
        &mut self,
        dag: &Dag<SpaceEntry>,
        w: &EntryId,
        only: Option<&EntryId>,
        counted: &mut Vec<EntryId>,
    ) {
        let Some(keeps) = self.marked(w).map(|m| &m.keeps).filter(|k| !k.is_empty()) else {
            return;
        };
        let Some(author) = dag.get(w).map(|we| we.author()) else {
            return;
        };
        let Some(waiting) = self.waiting.get(&author) else {
            return;
        };
        let mut found = Vec::new();
        for (k, listed) in keeps {
            let Some(ys) = waiting.get(k) else { continue };
            let listed = listed.iter().filter(|l| only.is_none_or(|o| o == *l));
            // an entry that is not here yet keeps nothing until it is
            let listed: Vec<EntryId> = listed.filter(|l| dag.contains(l)).copied().collect();
            // One walk from what is listed answers for everything that
            // waits. Asking of each waiting entry against each listed one
            // is their product in walks, for one arriving entry.
            if ys.len() * listed.len() > 16 {
                let kept = dag.ancestors_of(&listed);
                found.extend(ys.iter().filter(|y| kept.contains(*y)).map(|y| (*y, *k)));
                continue;
            }
            for y in ys {
                if listed.iter().any(|l| l == y || dag.is_ancestor(y, l)) {
                    found.push((*y, *k));
                }
            }
        }
        for (y, k) in found {
            self.count(&y, &author, &k);
            counted.push(y);
        }
    }

    /// Takes the evaluated identity log of an author, as the verifier holds
    /// it now. Returns the entries whose validity changed.
    ///
    /// The signatures of that author's entries are worked out again from
    /// nothing, since a key that stops counting takes with it whatever its
    /// entries witnessed. Nobody else's are touched, and validity is judged
    /// again only for those entries and for what rests on them.
    pub fn set_state(&mut self, dag: &Dag<SpaceEntry>, state: Arc<IdentityState>) -> Vec<EntryId> {
        let author = state.identity;
        if self.states.get(&author).is_some_and(|old| **old == *state) {
            return Vec::new();
        }
        self.states.insert(author, state);
        self.recount(dag, &author)
    }

    /// Works out again, from nothing, which of one author's entries have a
    /// signature that counts, and judges again what changed and what rests
    /// on it.
    fn recount(&mut self, dag: &Dag<SpaceEntry>, author: &IdentityId) -> Vec<EntryId> {
        let author = *author;
        let entries = self.by_author.get(&author).cloned().unwrap_or_default();
        let Some(state) = self.states.get(&author).cloned() else {
            return Vec::new();
        };
        if entries.is_empty() {
            return Vec::new();
        }
        let sig = |x: &EntryId| {
            let e = dag.get(x).expect("entries judged are in the graph");
            (e.signer(), e.author_head())
        };
        let mut attrib: HashSet<EntryId> = HashSet::new();
        let mut ok: HashSet<EntryId> = HashSet::new();
        let mut waiting: HashMap<KeyId, HashSet<EntryId>> = HashMap::new();
        for x in &entries {
            let (key, head) = sig(x);
            if !state.is_effective_at(&key, &head) {
                continue;
            }
            attrib.insert(*x);
            if state.is_removed(&key) {
                waiting.entry(key).or_default().insert(*x);
            } else {
                ok.insert(*x);
            }
        }
        // Witnesses and keeps, to a fixpoint: one walk of the graph for
        // each key whose entries wait, and again while any came to count.
        loop {
            let mut grew = false;
            let keys: Vec<KeyId> = waiting.keys().copied().collect();
            for k in keys {
                let mut built_on = Vec::new();
                let mut kept = Vec::new();
                for w in &ok {
                    let (wkey, whead) = sig(w);
                    let opaque = self.info.get(w).is_some_and(|i| i.opaque);
                    if wkey != k && !opaque && !state.is_removed_at(&k, &whead) {
                        built_on.extend_from_slice(dag.parents(w));
                    }
                    for (key, listed) in self.marked(w).map_or(&[][..], |m| m.keeps.as_slice()) {
                        if *key == k {
                            kept.extend_from_slice(listed);
                        }
                    }
                }
                if built_on.is_empty() && kept.is_empty() {
                    continue;
                }
                let witnessed = dag.ancestors_of(&built_on);
                let kept = dag.ancestors_of(&kept);
                let ys = waiting.get_mut(&k).expect("a key that waits");
                let found: Vec<EntryId> = ys
                    .iter()
                    .filter(|y| {
                        let plain = self.info.get(*y).is_some_and(|i| !i.structural);
                        kept.contains(*y) || (plain && witnessed.contains(*y))
                    })
                    .copied()
                    .collect();
                for y in found {
                    ys.remove(&y);
                    ok.insert(y);
                    grew = true;
                }
                if ys.is_empty() {
                    waiting.remove(&k);
                }
            }
            if !grew {
                break;
            }
        }
        let mut flipped = Vec::new();
        for x in &entries {
            let i = self.info.get_mut(x).expect("entries judged are known");
            let (a, o) = (attrib.contains(x), ok.contains(x));
            if i.ok != o {
                flipped.push(*x);
            }
            i.attrib = a;
            i.ok = o;
            if o {
                self.validity.author_ok.insert(*x);
            } else {
                self.validity.author_ok.remove(x);
            }
            if a && !o {
                self.validity.unwitnessed.insert(*x);
            } else {
                self.validity.unwitnessed.remove(x);
            }
        }
        if waiting.is_empty() {
            self.waiting.remove(&author);
        } else {
            self.waiting.insert(author, waiting);
        }
        self.rejudge(dag, flipped)
    }

    // --------------------------------------------------------- validity

    fn root_now(&self) -> bool {
        let Some(g) = &self.genesis else { return false };
        g.formed && self.info.get(&g.id).is_some_and(|i| i.ok)
    }

    /// Whether the space had ended in a causal past that holds these marks:
    /// everyone who must name a successor has named the same one there.
    fn closed_in(&self, dag: &Dag<SpaceEntry>, past: &Bits) -> bool {
        let Some(g) = &self.genesis else { return false };
        if !self.root || self.succeeds.is_empty() || g.deciders.is_empty() {
            return false;
        }
        let behind = self.succeeds.iter().filter_map(|m| {
            let y = &self.marks[*m as usize];
            (past.get(*m) && self.info[y].named).then_some(y)
        });
        if g.deciders.len() == 1 {
            // the owner's `succeed`, whichever successor it names
            return behind.count() > 0;
        }
        let mut said: HashMap<SpaceId, HashSet<IdentityId>> = HashMap::new();
        for y in behind {
            let who = dag
                .get(y)
                .expect("marked entries are in the graph")
                .author();
            for s in self.marked(y).map_or(&[][..], |m| m.names.as_slice()) {
                said.entry(*s).or_default().insert(who);
            }
        }
        said.values().any(|who| who.len() >= g.deciders.len())
    }

    /// Whether `id`, which names a successor, counts towards the end of the
    /// space (`named` in the rules).
    fn named_now(&self, dag: &Dag<SpaceEntry>, id: &EntryId) -> bool {
        let (Some(g), Some(i)) = (&self.genesis, self.info.get(id)) else {
            return false;
        };
        let names = self.marked(id).is_some_and(|m| !m.names.is_empty());
        if !i.ok || !names || g.id == *id {
            return false;
        }
        let author = dag
            .get(id)
            .expect("entries judged are in the graph")
            .author();
        let by_genesis = g.top.get(&author);
        g.deciders.contains(&author)
            && i.need
                .is_some_and(|need| by_genesis.is_some_and(|r| *r >= need))
    }

    /// Whether `id` is valid here, and whether it is where this verifier
    /// stops: valid by the rules and opaque. An entry that stops it, and
    /// everything descending from one, is not valid here
    /// (`evolution.md#what-a-device-does-with-a-critical-extension-it-does-not-know`).
    fn judge_now(&self, dag: &Dag<SpaceEntry>, id: &EntryId) -> (bool, bool) {
        let by_rules = self.valid_now(dag, id);
        let Some(i) = self.info.get(id) else {
            return (false, false);
        };
        let gid = self.genesis.as_ref().map(|g| g.id);
        let behind = self.validity.stalled.iter().any(|s| {
            s != id
                && (Some(*s) == gid
                    || self
                        .info
                        .get(s)
                        .and_then(|x| x.mark)
                        .is_some_and(|m| i.past.get(m)))
        });
        (by_rules && !i.opaque && !behind, by_rules && i.opaque)
    }

    /// Whether `id` is valid by the rules, given what is held about its
    /// causal past.
    fn valid_now(&self, dag: &Dag<SpaceEntry>, id: &EntryId) -> bool {
        let (Some(g), Some(i)) = (&self.genesis, self.info.get(id)) else {
            return false;
        };
        if !self.root {
            return false;
        }
        if g.id == *id {
            return true;
        }
        let Some(need) = i.need.filter(|_| i.ok) else {
            return false;
        };
        let author = dag
            .get(id)
            .expect("entries judged are in the graph")
            .author();
        // a valid entry in its causal past gave its author a role that may
        // perform every op in it: the genesis, or an addition since
        let given = g.top.get(&author).is_some_and(|r| *r >= need)
            || self.adds_of.get(&author).is_some_and(|adds| {
                adds.iter().any(|(m, r)| {
                    *r >= need && i.past.get(*m) && self.info[&self.marks[*m as usize]].valid
                })
            });
        given && !self.closed_in(dag, &i.past)
    }

    /// Judges again the entries in `dirty`, whose signatures started or
    /// stopped counting, and whatever rests on them. Returns the entries
    /// whose validity changed.
    fn rejudge(&mut self, dag: &Dag<SpaceEntry>, dirty: Vec<EntryId>) -> Vec<EntryId> {
        if dirty.is_empty() {
            return Vec::new();
        }
        let mut todo: HashSet<EntryId> = dirty.into_iter().collect();
        // If the genesis starts or stops being valid, so does everything.
        let root = self.root_now();
        let all = root != self.root;
        self.root = root;
        let order = dag.log_order();
        let start = if all {
            0
        } else {
            let at = todo.iter().filter_map(|x| dag.position(x)).min();
            at.unwrap_or(order.len())
        };
        // The marks of entries that changed in what others rest on: an
        // addition that became valid or stopped being, a naming that came
        // to count or stopped. Log order puts them before what descends
        // from them.
        let mut moved = Bits::default();
        // a genesis that came to stop the verifier, or stopped doing so:
        // everything after it is judged again
        let mut all_after = false;
        let mut changed = Vec::new();
        let mut members = all;
        for z in &order[start..] {
            // an entry the graph released with this one, and not judged
            // yet, is judged when its turn comes
            let Some(past) = self.info.get(z).map(|i| &i.past) else {
                continue;
            };
            let hit = todo.remove(z)
                || all
                || all_after
                || (!moved.is_empty() && past.intersects(&moved));
            if !hit {
                if todo.is_empty() && moved.is_empty() && !all_after {
                    break;
                }
                continue;
            }
            let named = self.named_now(dag, z);
            let (valid, stops) = self.judge_now(dag, z);
            if stops != self.validity.stalled.contains(z) {
                if stops {
                    self.validity.stalled.insert(*z);
                } else {
                    self.validity.stalled.remove(z);
                }
                // what descends from it is judged again
                match self.info.get(z).and_then(|i| i.mark) {
                    Some(m) => moved.set(m),
                    None => all_after = true,
                }
            }
            let i = self.info.get_mut(z).expect("entries judged are known");
            let (was_valid, was_named) = (i.valid, i.named);
            i.valid = valid;
            i.named = named;
            if valid != was_valid {
                changed.push(*z);
                if valid {
                    self.validity.valid.insert(*z);
                } else {
                    self.validity.valid.remove(z);
                }
            }
            if let (Some(m), Some(marked)) = (i.mark, i.marked.as_deref()) {
                let adds = !marked.adds.is_empty() && valid != was_valid;
                let names = !marked.names.is_empty() && named != was_named;
                if adds || names {
                    moved.set(m);
                }
                members |= adds;
            }
        }
        if members {
            self.refresh_members();
        }
        changed
    }

    fn refresh_members(&mut self) {
        let mut members: BTreeSet<Member> = BTreeSet::new();
        if let Some(g) = self.genesis.as_ref().filter(|_| self.root) {
            for (identity, role) in &g.adds {
                members.insert(Member {
                    identity: *identity,
                    role: *role,
                });
            }
            for (identity, adds) in &self.adds_of {
                for (m, role) in adds {
                    if self.info[&self.marks[*m as usize]].valid {
                        members.insert(Member {
                            identity: *identity,
                            role: *role,
                        });
                    }
                }
            }
        }
        self.validity.members = members.into_iter().collect();
    }

    // ---------------------------------------------------------- results

    /// Whether the space had ended in the causal past of the entry `id`: it
    /// descends from the namings of one successor by everyone who must name
    /// it (`closed` in the rules).
    pub fn is_closed(&self, dag: &Dag<SpaceEntry>, id: &EntryId) -> bool {
        let past = self.info.get(id).map(|i| &i.past);
        past.is_some_and(|past| self.closed_in(dag, past))
    }

    /// Whether an entry with these parents would be written into a space
    /// that has ended.
    pub fn closes(&self, dag: &Dag<SpaceEntry>, parents: &[EntryId]) -> bool {
        if self.succeeds.is_empty() || parents.iter().any(|p| !self.info.contains_key(p)) {
            return false;
        }
        self.closed_in(dag, &self.past_of(parents))
    }

    /// The successors named, in valid entries, by everyone who must name
    /// one (`candidate` in the rules).
    pub fn candidates(&self, dag: &Dag<SpaceEntry>) -> BTreeSet<SpaceId> {
        let Some(g) = &self.genesis else {
            return BTreeSet::new();
        };
        let mut said: HashMap<SpaceId, HashSet<IdentityId>> = HashMap::new();
        for m in &self.succeeds {
            let y = &self.marks[*m as usize];
            let who = dag
                .get(y)
                .expect("marked entries are in the graph")
                .author();
            if !self.info[y].valid || !g.deciders.contains(&who) {
                continue;
            }
            for s in self.marked(y).map_or(&[][..], |m| m.names.as_slice()) {
                said.entry(*s).or_default().insert(who);
            }
        }
        let enough = |who: &HashSet<IdentityId>| who.len() >= g.deciders.len();
        let named = said.into_iter().filter(|(_, who)| enough(who));
        named.map(|(s, _)| s).collect()
    }

    /// The successor that stands: of those named, the one with the smallest
    /// id, compared as bytes.
    pub fn successor(&self, dag: &Dag<SpaceEntry>) -> Option<SpaceId> {
        self.candidates(dag).into_iter().next()
    }

    /// Whether `who` has left: it has a valid `leave` that no valid
    /// `add_member` of it descends from (`spaces.md#members-and-roles`).
    /// This is the member's statement, and changes nothing about what is
    /// valid.
    pub fn has_left(&self, dag: &Dag<SpaceEntry>, who: &IdentityId) -> bool {
        let leaves = self.leaves.get(who).map_or(&[][..], |v| v.as_slice());
        let adds = self.adds_of.get(who).map_or(&[][..], |v| v.as_slice());
        leaves.iter().any(|l| {
            self.info[l].valid
                && !adds.iter().any(|(m, _)| {
                    let add = &self.marks[*m as usize];
                    self.info[add].valid && dag.is_ancestor(l, add)
                })
        })
    }

    /// Every `leave` `who` wrote, valid or not, in the order they arrived.
    pub fn leaves_of(&self, who: &IdentityId) -> &[EntryId] {
        self.leaves.get(who).map_or(&[][..], |v| v.as_slice())
    }

    /// Each `leave` that stands: a valid one that no valid `add_member` of
    /// its author descends from, with who wrote it.
    pub fn standing_leaves(&self, dag: &Dag<SpaceEntry>) -> Vec<(IdentityId, EntryId)> {
        let mut out = Vec::new();
        for (who, leaves) in &self.leaves {
            let adds = self.adds_of.get(who).map_or(&[][..], |v| v.as_slice());
            for l in leaves.iter().filter(|l| self.info[*l].valid) {
                let back = adds.iter().any(|(m, _)| {
                    let add = &self.marks[*m as usize];
                    self.info[add].valid && dag.is_ancestor(l, add)
                });
                if !back {
                    out.push((*who, *l));
                }
            }
        }
        out
    }

    /// The identities added only after every one of `since`: those whom a
    /// valid entry after the genesis adds, where no addition that still
    /// brings them in is one of `since` or an ancestor of one. An addition
    /// that its member left after brings them in no longer, so someone who
    /// left and was added again has been added by the later entry
    /// (`hosts.md#telling-others-where-to-reach-you`); and whom the genesis
    /// names was there from the start, unless they left since. With
    /// nothing in `since`, everyone added after the genesis. Sorted.
    pub fn added_after(&self, dag: &Dag<SpaceEntry>, since: &[EntryId]) -> Vec<IdentityId> {
        let genesis = self.genesis.as_ref().filter(|g| g.formed);
        let mut out = Vec::new();
        for (who, adds) in &self.adds_of {
            let leaves = self.leaves.get(who).map_or(&[][..], |v| v.as_slice());
            let leaves: Vec<&EntryId> = leaves.iter().filter(|l| self.info[*l].valid).collect();
            if leaves.is_empty() && genesis.is_some_and(|g| g.top.contains_key(who)) {
                continue;
            }
            let adds = adds.iter().map(|(m, _)| &self.marks[*m as usize]);
            let left_after = |a: &&EntryId| leaves.iter().any(|l| dag.is_ancestor(a, l));
            let brings: Vec<&EntryId> = adds
                .filter(|a| self.info[*a].valid && !left_after(a))
                .collect();
            let before = |a: &&EntryId| since.iter().any(|s| dag.is_ancestor_or_self(a, s));
            if !brings.is_empty() && !brings.iter().any(before) {
                out.push(*who);
            }
        }
        out.sort();
        out
    }

    /// Each valid entry that adds a member, with whom it adds.
    pub fn valid_adds(&self) -> Vec<(IdentityId, EntryId)> {
        let mut out = Vec::new();
        // told from those taken already by looking it up: an admin sets
        // how many additions there are, and this runs whenever a space
        // where hosts are named is settled
        let mut seen = HashSet::new();
        for (who, adds) in &self.adds_of {
            for (m, _) in adds {
                let add = self.marks[*m as usize];
                if self.info[&add].valid && seen.insert((*who, add)) {
                    out.push((*who, add));
                }
            }
        }
        out
    }

    /// Whether `key` wrote something **not yet witnessed**
    /// (`spaces.md#authors`): an entry whose signature counts, that would
    /// stop counting were the key removed now. That is one that no entry of
    /// the same author under another key, whose signature counts, descends
    /// from, and that no `keep` for the key in such an entry covers, by
    /// listing it or one of its descendants. What ends or begins a space is
    /// left out: building on it keeps nothing, so nothing a device writes
    /// unasked would change the answer.
    pub fn unwitnessed_work(&self, dag: &Dag<SpaceEntry>, key: &KeyId) -> bool {
        let signer = |x: &EntryId| dag.get(x).map(|e| e.signer());
        let mut covered = Vec::new();
        let mut theirs = Vec::new();
        for entries in self.by_author.values() {
            let counts = entries.iter().filter(|x| self.info[*x].ok);
            let (by_key, by_others): (Vec<&EntryId>, Vec<&EntryId>) =
                counts.partition(|x| signer(x) == Some(*key));
            if by_key.is_empty() {
                continue;
            }
            for w in by_others {
                covered.extend_from_slice(dag.parents(w));
                let keeps = self.marked(w).map_or(&[][..], |m| m.keeps.as_slice());
                for (_, listed) in keeps.iter().filter(|(k, _)| k == key) {
                    covered.extend_from_slice(listed);
                }
            }
            theirs.extend(by_key.into_iter().filter(|x| !self.info[*x].structural));
        }
        if theirs.is_empty() {
            return false;
        }
        let witnessed = dag.ancestors_of(&covered);
        theirs.iter().any(|x| !witnessed.contains(*x))
    }

    /// Whether `who` has accepted the space (`spaces.md#holding-a-space`):
    /// they wrote something valid in it, its genesis or anything after.
    /// Leaving takes that back: for each valid `leave` of theirs they must
    /// have been added again by an entry that descends from it, and have
    /// written something valid that descends from that addition, or is it.
    pub fn accepted(&self, dag: &Dag<SpaceEntry>, who: &IdentityId) -> bool {
        let valid = |x: &&EntryId| self.info[*x].valid;
        let leaves: Vec<&EntryId> = match self.leaves.get(who) {
            Some(l) => l.iter().filter(valid).collect(),
            None => Vec::new(),
        };
        let entries = self.by_author.get(who).map_or(&[][..], |v| v.as_slice());
        // Nearly always nobody has left, and anything valid will do.
        if leaves.is_empty() {
            return entries.iter().any(|x| valid(&x));
        }
        // the latest first: what answers a leave is usually the last thing
        let wrote = || {
            entries
                .iter()
                .rev()
                .filter(|x| valid(x) && !leaves.contains(x))
        };
        let adds = self.adds_of.get(who).map_or(&[][..], |v| v.as_slice());
        let adds: Vec<&EntryId> = adds
            .iter()
            .map(|(m, _)| &self.marks[*m as usize])
            .filter(valid)
            .collect();
        leaves.iter().all(|l| {
            adds.iter()
                .any(|a| dag.is_ancestor(l, a) && wrote().any(|x| dag.is_ancestor_or_self(a, x)))
        })
    }
}

// ------------------------------------------------------- the rules, run

/// What the normative `space` program finds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ByRules {
    /// `valid`.
    pub valid: HashSet<EntryId>,
    /// `author_ok`.
    pub author_ok: HashSet<EntryId>,
    /// `member`, sorted.
    pub members: Vec<Member>,
    /// `closed`.
    pub closed: HashSet<EntryId>,
    /// `candidate`.
    pub candidates: BTreeSet<SpaceId>,
    /// `successor`.
    pub successor: Option<SpaceId>,
}

/// Evaluates a space with the normative `space` program, given the identity
/// logs of its authors (and any logs their guardians' confirmations need).
/// The cost is quadratic in the number of entries: this is the reference
/// the native evaluation is tested against, not something to run on a
/// space of any size.
pub fn by_rules(dag: &Dag<SpaceEntry>, logs: &[&IdentityLog]) -> Result<ByRules, Error> {
    let g = dag.log_order().first().and_then(|g| dag.get(g));
    let g = g.ok_or(Error::Malformed("no genesis"))?;
    let space = g.id();
    let mut w = model_world(logs);
    let sym = |w: &mut model::World, b: &[u8]| w.sym(&hex_encode(b));
    let space_sym = sym(&mut w, &space);
    let first = Genesis::read(&space, g);
    let owner = first.formed.then_some(first.owner).flatten();
    // entries that use an extension critical for them: opaque
    let mut opaque: Vec<EntryId> = Vec::new();
    for (id, e) in dag.iter() {
        let mut ops = Vec::new();
        for o in e.ops() {
            let class = match class(e, o.body()) {
                Class::Ext(name) => match extension_mark(dag, Some(space), owner, id, e, &name) {
                    None => Class::Invalid,
                    Some(critical) => {
                        if critical && !opaque.contains(id) {
                            opaque.push(*id);
                        }
                        Class::Declared
                    }
                },
                c => c,
            };
            ops.push(match (class, o.body()) {
                (_, SpaceOpBody::Start { succession, .. }) => Op::Start {
                    succeeds: succession.succeeds.as_ref().map(|x| sym(&mut w, x)),
                },
                (_, SpaceOpBody::AddMember { identity, role, .. }) => Op::AddMember {
                    member: sym(&mut w, identity),
                    role: (*role).min(i64::MAX as u64) as i64,
                },
                (_, SpaceOpBody::Keep { key, entries }) => Op::Keep {
                    key: sym(&mut w, key),
                    entries: entries.iter().map(|x| sym(&mut w, x)).collect(),
                },
                (_, SpaceOpBody::Succeed { successor, .. }) => Op::Succeed {
                    successor: sym(&mut w, successor),
                },
                (Class::Leave, _) => Op::Leave,
                (Class::OwnerOnly, _) => Op::OwnerOnly,
                // an op that changes nothing, which any member may write
                (Class::Reach | Class::Declared, _) => Op::Reach,
                (Class::Invalid | Class::Ext(_), _) => Op::Invalid,
                _ => Op::App,
            });
        }
        let entry = model::Entry {
            id: sym(&mut w, id),
            log: space_sym,
            parents: e.parents().iter().map(|p| sym(&mut w, p)).collect(),
            signer: sym(&mut w, &e.signer()),
            ops,
            author: Some(sym(&mut w, &e.author())),
            head: Some(sym(&mut w, &e.author_head())),
        };
        w.put(entry)
            .map_err(|_| Error::Malformed("space entries out of order"))?;
    }
    let ids = w.log_ids(space_sym);
    let mut r = model::evaluate_space(&w, space_sym, &ids);
    // As for an identity log (`evolution.md`): evaluated again without
    // each valid opaque entry and everything that descends from it.
    let id32 = |s: u32| -> [u8; 32] { hex_decode(w.name(s)).try_into().unwrap_or([0; 32]) };
    let valid: HashSet<EntryId> = r.unary("valid").into_iter().map(id32).collect();
    let stops: Vec<EntryId> = opaque.into_iter().filter(|x| valid.contains(x)).collect();
    // A signature counts or not whatever the entry holds: what is left out
    // keeps what the first evaluation found of it.
    let mut signed: HashSet<EntryId> = HashSet::new();
    if !stops.is_empty() {
        signed = r
            .unary("author_ok")
            .into_iter()
            .map(id32)
            .filter(|x| stops.iter().any(|o| dag.is_ancestor_or_self(o, x)))
            .collect();
        let rest: BTreeSet<_> = ids
            .iter()
            .copied()
            .filter(|s| {
                let x = id32(*s);
                !stops.iter().any(|o| dag.is_ancestor_or_self(o, &x))
            })
            .collect();
        r = model::evaluate_space(&w, space_sym, &rest);
    }
    let unary = |name: &str| r.unary(name).into_iter().map(id32);
    let mut members = Vec::new();
    for t in r.rel("member") {
        if let [Val::Sym(m), Val::Int(role)] = t {
            members.push(Member {
                identity: id32(*m),
                role: *role as u64,
            });
        }
    }
    members.sort();
    Ok(ByRules {
        valid: unary("valid").collect(),
        author_ok: unary("author_ok").chain(signed).collect(),
        members,
        closed: unary("closed").collect(),
        candidates: unary("candidate").collect(),
        successor: unary("successor").next(),
    })
}
