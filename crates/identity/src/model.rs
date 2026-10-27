//! Abstract entries, input facts, and evaluation of identity logs and
//! spaces: a faithful port of `core/model/world.py`.
//!
//! Entries here are plain records with symbols for ids and keys, exactly
//! the abstraction the model uses. Real entries ([`crate::entry`]) are
//! converted to these, so the facts the normative rules read are derived
//! by one piece of code, and the differential tests compare that code
//! against `world.py` on the fuzzer's histories.
//!
//! Costs: the graph facts (`anc`, `conc`, `later`) are quadratic in the
//! number of entries of a log, as in the model. That is fine for identity
//! logs, which are small; spaces with many entries and a single member use
//! a native evaluation in `cardinal-space` instead.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;

use crate::datalog::{evaluate, identity_program, space_program, Facts, Symbols, Val};

/// A symbol in a [`World`]'s table.
pub type Sym = u32;

/// An op, as `world.py` models it, plus a few the model leaves out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// `add_key`: power 1 device, 2 admin, 3 root.
    Add {
        /// The key.
        key: Sym,
        /// Its power.
        power: i64,
    },
    /// `remove_key`.
    Rem {
        /// The key.
        key: Sym,
    },
    /// `set_recovery`.
    Policy {
        /// The policy it changes (`None` in genesis).
        changes: Option<Sym>,
        /// Guardians known to the verifier (in the model, all of them; for
        /// real entries, those revealed by acting).
        guardians: Vec<Sym>,
        /// How many guardians the policy names.
        slots: usize,
        /// The threshold.
        threshold: i64,
        /// The controller of a policy naming no guardians.
        controller: Option<Sym>,
    },
    /// `recover`.
    Recover {
        /// The new root.
        root: Sym,
        /// Keys kept.
        keeps: Vec<Sym>,
        /// The policy it acts under.
        policy: Sym,
    },
    /// A guardian's `confirm` of a decision in another log.
    Confirm {
        /// The decision.
        decision: Sym,
    },
    /// A guardian's `endorse` (not in the model; any power, no effect).
    Endorse,
    /// `set_encryption_key`.
    Sek,
    /// `wrap` (not in the model; admin or root, no effect).
    Wrap,
    /// `object` (advisory).
    Object,
    /// `set_protocol`, declaring extensions.
    Protocol {
        /// Extension names declared.
        declares: Vec<Sym>,
    },
    /// An extension op.
    Ext {
        /// The extension's name.
        name: Sym,
        /// Whether it is critical.
        critical: bool,
    },
    /// A malformed op (not in the model): no power may sign it.
    Invalid,
    /// Space genesis (`start`); the author becomes an owner.
    Create,
    /// `add_member`.
    AddMember {
        /// The member identity.
        member: Sym,
        /// Role 0 reader .. 3 owner.
        role: i64,
    },
    /// `remove_member` of a membership id.
    RemoveMember {
        /// The membership.
        membership: Sym,
    },
    /// `succeed`.
    Succeed,
    /// `keep`.
    Keep {
        /// The removed key.
        key: Sym,
        /// Entries listed.
        entries: Vec<Sym>,
    },
    /// Application data; writers and up.
    App,
    /// A member's own reach node; anyone.
    Reach,
    /// An op only owners may write (`set_policy`, `set_protocol`; not in the
    /// model).
    OwnerOnly,
}

impl Op {
    /// The model's op name (`op_name` in `world.py`).
    pub fn name(&self) -> &'static str {
        match self {
            Op::Add { .. } => "add",
            Op::Rem { .. } => "rem",
            Op::Policy { .. } => "policy",
            Op::Recover { .. } => "recover",
            Op::Confirm { .. } => "confirm",
            Op::Endorse => "endorse",
            Op::Sek => "sek",
            Op::Wrap => "wrap",
            Op::Object => "object",
            Op::Protocol { .. } => "protocol",
            Op::Ext { critical: true, .. } => "extc",
            Op::Ext {
                critical: false, ..
            } => "exti",
            Op::Invalid => "invalid",
            Op::Create => "create",
            Op::AddMember { .. } => "add_member",
            Op::RemoveMember { .. } => "remove_member",
            Op::Succeed => "succeed",
            Op::Keep { .. } => "keep",
            Op::App => "app",
            Op::Reach => "reach",
            Op::OwnerOnly => "owner",
        }
    }
}

/// Which ops a key of each power may sign, decisions excepted (`ALLOWED`).
fn allowed(power: i64, name: &str) -> bool {
    match power {
        3 => matches!(
            name,
            "add"
                | "rem"
                | "sek"
                | "object"
                | "confirm"
                | "policy"
                | "protocol"
                | "exti"
                | "extc"
                | "wrap"
                | "endorse"
        ),
        2 => matches!(
            name,
            "add"
                | "rem"
                | "sek"
                | "object"
                | "confirm"
                | "protocol"
                | "exti"
                | "extc"
                | "wrap"
                | "endorse"
        ),
        1 => matches!(name, "confirm" | "exti" | "endorse"),
        _ => false,
    }
}

/// Which space ops each role may write (`ROLE_OPS`).
fn role_allows(role: i64, name: &str) -> bool {
    match role {
        3 => matches!(
            name,
            "create"
                | "add_member"
                | "remove_member"
                | "succeed"
                | "keep"
                | "app"
                | "reach"
                | "owner"
        ),
        2 => matches!(
            name,
            "add_member" | "remove_member" | "keep" | "app" | "reach"
        ),
        1 => matches!(name, "remove_member" | "keep" | "app" | "reach"),
        0 => matches!(name, "remove_member" | "keep" | "reach"),
        _ => false,
    }
}

/// An abstract entry of an identity log or a space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Its id.
    pub id: Sym,
    /// The identity id or space id.
    pub log: Sym,
    /// Parent ids.
    pub parents: Vec<Sym>,
    /// The signing key.
    pub signer: Sym,
    /// Ops.
    pub ops: Vec<Op>,
    /// Spaces only: the author identity.
    pub author: Option<Sym>,
    /// Spaces only: the cited head of the author's identity log.
    pub head: Option<Sym>,
    /// Spaces only: the membership the entry is written under.
    pub membership: Option<Sym>,
}

/// How memberships are named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipNames {
    /// `"<entry id>#<op index>"`, as in `world.py`.
    Model,
    /// The hex of `first16(BLAKE3(entry id || varint(i)))`, where the entry
    /// id symbol is the hex of the id (spaces.md).
    Real,
}

type CacheKey = (Sym, Vec<Sym>, Option<Vec<Sym>>);

/// A global set of entries across logs.
pub struct World {
    symbols: Symbols,
    entries: HashMap<Sym, Entry>,
    order: Vec<Sym>,
    names: MembershipNames,
    none: Sym,
    cache: RefCell<HashMap<CacheKey, Rc<IdentityResult>>>,
    active: RefCell<Vec<CacheKey>>,
}

/// An error adding an entry to a [`World`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorldError {
    /// An entry with this id is already present.
    Duplicate,
    /// A parent is missing, or in another log.
    MissingParent,
    /// A confirmation names an entry that is not present.
    MissingRef,
}

impl World {
    /// An empty world.
    pub fn new(names: MembershipNames) -> World {
        let mut symbols = Symbols::new();
        let none = symbols.intern("\u{0}None");
        World {
            symbols,
            entries: HashMap::new(),
            order: Vec::new(),
            names,
            none,
            cache: RefCell::new(HashMap::new()),
            active: RefCell::new(Vec::new()),
        }
    }

    /// Interns a symbol. Must not be called after evaluation starts
    /// (evaluation results are cached).
    pub fn sym(&mut self, s: &str) -> Sym {
        self.symbols.intern(s)
    }

    /// The symbol for `s`, if interned.
    pub fn get_sym(&self, s: &str) -> Option<Sym> {
        self.symbols.get(s)
    }

    /// The text of a symbol.
    pub fn name(&self, s: Sym) -> &str {
        self.symbols.name(s)
    }

    /// The symbol table.
    pub fn symbols(&self) -> &Symbols {
        &self.symbols
    }

    /// The symbol standing for Python's `None`.
    pub fn none(&self) -> Sym {
        self.none
    }

    /// Adds an entry. Its parents, in the same log, and the decisions it
    /// confirms must already be present.
    pub fn put(&mut self, e: Entry) -> Result<(), WorldError> {
        if self.entries.contains_key(&e.id) {
            return Err(WorldError::Duplicate);
        }
        for p in &e.parents {
            match self.entries.get(p) {
                Some(pe) if pe.log == e.log => {}
                _ => return Err(WorldError::MissingParent),
            }
        }
        for r in refs(&e) {
            if !self.entries.contains_key(&r) {
                return Err(WorldError::MissingRef);
            }
        }
        self.order.push(e.id);
        self.entries.insert(e.id, e);
        self.cache.borrow_mut().clear();
        Ok(())
    }

    /// The entry with id `x`.
    pub fn entry(&self, x: Sym) -> Option<&Entry> {
        self.entries.get(&x)
    }

    /// Every entry id, in insertion order.
    pub fn ids(&self) -> &[Sym] {
        &self.order
    }

    /// Every entry id, as a set.
    pub fn all(&self) -> BTreeSet<Sym> {
        self.order.iter().copied().collect()
    }

    /// The ids of the entries of log `log`.
    pub fn log_ids(&self, log: Sym) -> BTreeSet<Sym> {
        self.order
            .iter()
            .copied()
            .filter(|x| self.entries[x].log == log)
            .collect()
    }

    /// The causal closure of `ids`: parents, and decisions confirmed.
    pub fn closure(&self, ids: impl IntoIterator<Item = Sym>) -> BTreeSet<Sym> {
        let mut out = BTreeSet::new();
        let mut todo: Vec<Sym> = ids.into_iter().collect();
        while let Some(x) = todo.pop() {
            if out.contains(&x) {
                continue;
            }
            let Some(e) = self.entries.get(&x) else {
                continue;
            };
            out.insert(x);
            todo.extend(e.parents.iter().copied());
            todo.extend(refs(e));
        }
        out
    }

    fn membership_id(&self, entry: Sym, index: usize) -> String {
        match self.names {
            MembershipNames::Model => format!("{}#{index}", self.name(entry)),
            MembershipNames::Real => {
                let id = hex_decode(self.name(entry));
                let mut h = blake3::Hasher::new();
                h.update(&id);
                h.update(&cardinal_encoding::varint(index as u64));
                hex_encode(&h.finalize().as_bytes()[..16])
            }
        }
    }
}

/// Cross-log references: a confirmation names its decision.
fn refs(e: &Entry) -> impl Iterator<Item = Sym> + '_ {
    e.ops.iter().filter_map(|op| match op {
        Op::Confirm { decision } => Some(*decision),
        _ => None,
    })
}

/// Lowercase hex.
pub fn hex_encode(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

/// Decodes lowercase or uppercase hex; invalid input decodes to nothing.
pub fn hex_decode(s: &str) -> Vec<u8> {
    let v = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for p in b.chunks(2) {
        match (v(p[0]), v(p[1])) {
            (Some(h), Some(l)) => out.push(h << 4 | l),
            _ => return Vec::new(),
        }
    }
    out
}

// ------------------------------------------------------------ graph helpers

/// `anc[x]`: the strict ancestors of each entry, within one log.
pub fn ancestry(world: &World, ids: &BTreeSet<Sym>) -> HashMap<Sym, HashSet<Sym>> {
    let mut anc: HashMap<Sym, HashSet<Sym>> = HashMap::new();
    for x in log_order(world, ids) {
        let mut s = HashSet::new();
        for p in &world.entries[&x].parents {
            if let Some(pa) = anc.get(p) {
                s.insert(*p);
                s.extend(pa.iter().copied());
            }
        }
        anc.insert(x, s);
    }
    anc
}

/// Topological order; among ready entries, the smallest id (by symbol
/// text) first.
pub fn log_order(world: &World, ids: &BTreeSet<Sym>) -> Vec<Sym> {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    let mut children: HashMap<Sym, Vec<Sym>> = HashMap::new();
    let mut waiting: HashMap<Sym, usize> = HashMap::new();
    for &x in ids {
        let e = &world.entries[&x];
        let ps: Vec<Sym> = e
            .parents
            .iter()
            .copied()
            .filter(|p| ids.contains(p))
            .collect();
        waiting.insert(x, ps.len());
        for p in ps {
            children.entry(p).or_default().push(x);
        }
    }
    let key = |x: Sym| (world.name(x).to_owned(), x);
    let mut ready: BinaryHeap<Reverse<(String, Sym)>> = waiting
        .iter()
        .filter(|(_, &n)| n == 0)
        .map(|(&x, _)| Reverse(key(x)))
        .collect();
    let mut out = Vec::with_capacity(ids.len());
    while let Some(Reverse((_, x))) = ready.pop() {
        out.push(x);
        for &c in children.get(&x).map(|v| v.as_slice()).unwrap_or(&[]) {
            let w = waiting.get_mut(&c).expect("child");
            *w -= 1;
            if *w == 0 {
                ready.push(Reverse(key(c)));
            }
        }
    }
    out
}

fn s(x: Sym) -> Val {
    Val::Sym(x)
}

fn graph_facts(
    world: &World,
    ids: &BTreeSet<Sym>,
    prefix: &str,
    f: &mut Facts,
) -> HashMap<Sym, HashSet<Sym>> {
    let anc = ancestry(world, ids);
    let p = |k: &str| format!("{prefix}{k}");
    let (entry, ae, an, genesis, conc) = (p("entry"), p("ae"), p("anc"), p("genesis"), p("conc"));
    for k in [&entry, &ae, &an, &genesis, &conc] {
        f.declare(k);
    }
    let v: Vec<Sym> = ids.iter().copied().collect();
    for &x in &v {
        f.add(&entry, &[s(x)]);
        f.add(&ae, &[s(x), s(x)]);
        if world.entries[&x].parents.is_empty() {
            f.add(&genesis, &[s(x)]);
        }
        for &a in &anc[&x] {
            f.add(&an, &[s(a), s(x)]);
            f.add(&ae, &[s(a), s(x)]);
        }
    }
    for (i, &x) in v.iter().enumerate() {
        for &y in &v[i + 1..] {
            if !anc[&y].contains(&x) && !anc[&x].contains(&y) {
                f.add(&conc, &[s(x), s(y)]);
                f.add(&conc, &[s(y), s(x)]);
            }
        }
    }
    anc
}

// ------------------------------------------------------------ identity logs

/// The input facts of the `identity` program for log `ident` over `ids`
/// (`identity_facts`), without `confirm_ok`.
pub fn identity_facts(world: &World, ident: Sym, ids: &BTreeSet<Sym>) -> Facts {
    let own: BTreeSet<Sym> = ids
        .iter()
        .copied()
        .filter(|x| world.entries[x].log == ident)
        .collect();
    let mut f = Facts::new();
    let anc = graph_facts(world, &own, "", &mut f);
    let order = log_order(world, &own);
    f.declare("later");
    for (i, &a) in order.iter().enumerate() {
        for &b in &order[i + 1..] {
            f.add("later", &[s(a), s(b)]);
        }
    }
    for k in [
        "signer",
        "add",
        "readd",
        "rem",
        "selfrep",
        "is_selfrep",
        "badops",
        "policy",
        "change",
        "guardian",
        "threshold",
        "unguarded",
        "majority",
        "bad_policy",
        "ctrl",
        "recover",
        "keeps",
        "bad_decision",
        "sek",
        "confirm_ok",
    ] {
        f.declare(k);
    }
    // keys each entry names: added, or a recovery's new root
    let names_of: HashMap<Sym, HashSet<Sym>> = own
        .iter()
        .map(|&x| {
            let n = world.entries[&x]
                .ops
                .iter()
                .filter_map(|op| match op {
                    Op::Add { key, .. } => Some(*key),
                    Op::Recover { root, .. } => Some(*root),
                    _ => None,
                })
                .collect();
            (x, n)
        })
        .collect();
    for &x in &own {
        let e = &world.entries[&x];
        f.add("signer", &[s(x), s(e.signer)]);
        let names: Vec<&str> = e.ops.iter().map(Op::name).collect();
        let named_before: HashSet<Sym> = anc[&x]
            .iter()
            .flat_map(|a| names_of[a].iter().copied())
            .collect();
        let readd = e
            .ops
            .iter()
            .any(|op| matches!(op, Op::Add { key, .. } if named_before.contains(key)));
        if readd {
            f.add("readd", &[s(x)]);
        }
        for op in &e.ops {
            match op {
                Op::Add { key, power } => f.add("add", &[s(x), s(*key), Val::Int(*power)]),
                Op::Rem { key } => f.add("rem", &[s(x), s(*key)]),
                Op::Policy {
                    changes,
                    guardians,
                    slots,
                    threshold,
                    controller,
                } => {
                    f.add("policy", &[s(x)]);
                    if let Some(p) = changes {
                        f.add("change", &[s(x), s(*p)]);
                    }
                    for g in guardians {
                        f.add("guardian", &[s(x), s(*g)]);
                    }
                    f.add("threshold", &[s(x), Val::Int(*threshold)]);
                    let n = *slots as i64;
                    if n == 0 {
                        f.add("unguarded", &[s(x)]);
                        if changes.is_none() {
                            // genesis: its root controls
                            for o in &e.ops {
                                if let Op::Add { key, power: 3 } = o {
                                    f.add("ctrl", &[s(x), s(*key)]);
                                }
                            }
                        } else if let Some(c) = controller {
                            f.add("ctrl", &[s(x), s(*c)]);
                        }
                    } else if n / 2 < *threshold && *threshold <= n {
                        f.add("majority", &[s(x)]);
                    } else {
                        f.add("bad_policy", &[s(x)]);
                    }
                }
                Op::Recover {
                    root,
                    keeps,
                    policy,
                } => {
                    f.add("recover", &[s(x), s(*root), s(*policy)]);
                    for k in keeps {
                        f.add("keeps", &[s(x), s(*k)]);
                    }
                }
                Op::Sek => f.add("sek", &[s(x)]),
                _ => {}
            }
        }
        // a critical extension is used only after a set_protocol declares it
        let declared: HashSet<Sym> = anc[&x]
            .iter()
            .chain(std::iter::once(&x))
            .flat_map(|a| world.entries[a].ops.iter())
            .filter_map(|op| match op {
                Op::Protocol { declares } => Some(declares.iter().copied()),
                _ => None,
            })
            .flatten()
            .collect();
        let undeclared = e
            .ops
            .iter()
            .any(|op| matches!(op, Op::Ext { name, critical: true } if !declared.contains(name)));
        let decision = names.contains(&"recover") || names.contains(&"policy");
        if decision && !e.parents.is_empty() && e.ops.len() != 1 {
            f.add("bad_decision", &[s(x)]); // a decision is alone in its entry
        }
        if e.ops
            .iter()
            .any(|op| matches!(op, Op::Recover { root, .. } if named_before.contains(root)))
        {
            f.add("bad_decision", &[s(x)]); // a new root is a new key
        }
        // root replacement: exactly add root N and remove the signer
        let mut sorted = names.clone();
        sorted.sort_unstable();
        if (sorted == ["add", "rem"] || sorted == ["add", "protocol", "rem"])
            && !readd
            && e.ops
                .iter()
                .any(|op| matches!(op, Op::Add { power: 3, .. }))
            && e.ops
                .iter()
                .any(|op| matches!(op, Op::Rem { key } if *key == e.signer))
        {
            let n = e
                .ops
                .iter()
                .find_map(|op| match op {
                    Op::Add { key, .. } => Some(*key),
                    _ => None,
                })
                .expect("add");
            f.add("selfrep", &[s(x), s(e.signer), s(n)]);
            f.add("is_selfrep", &[s(x)]);
            continue;
        }
        // decisions are judged only as decisions, never as ordinary
        // entries; whether a removal targets a lower power is decided by
        // the rules
        for p in 1..=3 {
            let mut bad = decision || readd || undeclared || names.iter().any(|n| !allowed(p, n));
            for op in &e.ops {
                if let Op::Add { power, .. } = op {
                    if *power >= 3 || *power > p {
                        bad = true; // roots are added only by replacement
                    }
                }
            }
            if bad {
                f.add("badops", &[s(x), Val::Int(p)]);
            }
        }
    }
    f
}

/// `confirm_ok(G, D)`: a confirmation of D, judged in G's log as of its own
/// causal past.
fn confirm_facts(
    world: &World,
    ident: Sym,
    ids: &BTreeSet<Sym>,
    known: Option<&BTreeSet<Sym>>,
    f: &mut Facts,
) {
    let decisions: HashSet<Sym> = ids
        .iter()
        .copied()
        .filter(|x| world.entries[x].log == ident)
        .collect();
    for &c in ids {
        let e = &world.entries[&c];
        if e.log == ident {
            continue;
        }
        for op in &e.ops {
            if let Op::Confirm { decision } = op {
                if decisions.contains(decision) {
                    let past = world.closure([c]);
                    let r = evaluate_identity(world, e.log, &past, known);
                    if r.is_valid(c) && !r.frozen {
                        f.add("confirm_ok", &[s(e.log), s(*decision)]);
                    }
                }
            }
        }
    }
}

/// The relations an identity evaluation reports.
pub const IDENTITY_RESULTS: [&str; 17] = [
    "valid",
    "in_effect",
    "applied",
    "tainted",
    "effective",
    "effective_at",
    "removed",
    "removed_at",
    "removal",
    "root_eff",
    "current_policy",
    "current_key",
    "rec_removes",
    "key_added",
    "votes",
    "suspended",
    "kpow",
];

/// The result of evaluating an identity log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityResult {
    /// Each relation of [`IDENTITY_RESULTS`].
    pub rels: BTreeMap<&'static str, HashSet<Box<[Val]>>>,
    /// Whether the identity is frozen.
    pub frozen: bool,
    /// Whether the identity is contested.
    pub contested: bool,
    /// Valid entries using a critical extension the verifier lacks.
    pub stalled: BTreeSet<Sym>,
}

impl IdentityResult {
    /// The tuples of a reported relation.
    pub fn rel(&self, name: &str) -> impl Iterator<Item = &[Val]> {
        self.rels.get(name).into_iter().flatten().map(|t| &t[..])
    }

    /// Whether `name(tuple)` holds.
    pub fn has(&self, name: &str, tuple: &[Val]) -> bool {
        self.rels.get(name).is_some_and(|r| r.contains(tuple))
    }

    /// Whether entry `x` is valid.
    pub fn is_valid(&self, x: Sym) -> bool {
        self.has("valid", &[Val::Sym(x)])
    }

    /// The symbols of a unary relation.
    pub fn unary(&self, name: &str) -> BTreeSet<Sym> {
        self.rel(name)
            .filter_map(|t| match t {
                [Val::Sym(x)] => Some(*x),
                _ => None,
            })
            .collect()
    }
}

/// Evaluates identity `ident` over the causally closed set `ids`
/// (`evaluate_identity`). With `known`, a verifier that knows only those
/// extensions stops at valid entries using another critical extension.
///
/// # Panics
///
/// If an evaluation recurs, which hash links make impossible.
pub fn evaluate_identity(
    world: &World,
    ident: Sym,
    ids: &BTreeSet<Sym>,
    known: Option<&BTreeSet<Sym>>,
) -> Rc<IdentityResult> {
    let ids: BTreeSet<Sym> = ids
        .iter()
        .copied()
        .filter(|x| world.entries.contains_key(x))
        .collect();
    let key: CacheKey = (
        ident,
        ids.iter().copied().collect(),
        known.map(|k| k.iter().copied().collect()),
    );
    if let Some(r) = world.cache.borrow().get(&key) {
        return r.clone();
    }
    assert!(
        !world.active.borrow().contains(&key),
        "identity evaluation of {} recurs",
        world.name(ident)
    );
    world.active.borrow_mut().push(key.clone());
    let mut f = identity_facts(world, ident, &ids);
    confirm_facts(world, ident, &ids, known, &mut f);
    world.active.borrow_mut().pop();
    let rel = evaluate(identity_program(), &f, &world.symbols);
    let mut r = IdentityResult {
        rels: IDENTITY_RESULTS.iter().map(|&k| (k, rel.set(k))).collect(),
        frozen: rel.any("frozen"),
        contested: rel.any("contested"),
        stalled: BTreeSet::new(),
    };
    // A valid entry using a critical extension this verifier does not know
    // cannot be judged. The verifier stops there: it evaluates again
    // without that entry and everything descending from it (evolution.md).
    if let Some(known) = known {
        let opaque: BTreeSet<Sym> = r
            .unary("valid")
            .into_iter()
            .filter(|x| {
                world.entries[x].ops.iter().any(
                    |op| matches!(op, Op::Ext { name, critical: true } if !known.contains(name)),
                )
            })
            .collect();
        if !opaque.is_empty() {
            let own: BTreeSet<Sym> = ids
                .iter()
                .copied()
                .filter(|x| world.entries[x].log == ident)
                .collect();
            let anc = ancestry(world, &own);
            let cut: HashSet<Sym> = own
                .iter()
                .copied()
                .filter(|x| opaque.contains(x) || anc[x].iter().any(|a| opaque.contains(a)))
                .collect();
            let rest: BTreeSet<Sym> = ids.iter().copied().filter(|x| !cut.contains(x)).collect();
            let mut r2 = (*evaluate_identity(world, ident, &rest, Some(known))).clone();
            r2.stalled = opaque;
            r = r2;
        }
    }
    let r = Rc::new(r);
    world.cache.borrow_mut().insert(key, r.clone());
    r
}

// ------------------------------------------------------------------ spaces

/// The input facts of the `space` program (`space_facts`), without the
/// facts from identity logs.
pub fn space_facts(world: &World, space: Sym, ids: &BTreeSet<Sym>) -> (Facts, BTreeSet<Sym>) {
    let own: BTreeSet<Sym> = ids
        .iter()
        .copied()
        .filter(|x| world.entries[x].log == space)
        .collect();
    let mut f = Facts::new();
    graph_facts(world, &own, "s_", &mut f);
    for k in [
        "author",
        "skey",
        "cites",
        "mem",
        "incarnation",
        "inc_from",
        "adds",
        "s_rem",
        "replaces",
        "s_succeed",
        "s_keep",
        "s_badops",
    ] {
        f.declare(k);
    }
    // membership -> (identity, role, creating entry)
    let mut role: BTreeMap<Sym, (Sym, i64, Sym)> = BTreeMap::new();
    let mut mid: HashMap<(Sym, usize), Sym> = HashMap::new();
    for &x in &own {
        let e = &world.entries[&x];
        for (n, op) in e.ops.iter().enumerate() {
            let m = || {
                world
                    .get_sym(&world.membership_id(x, n))
                    .expect("membership ids are interned")
            };
            match op {
                Op::Create => {
                    let i = m();
                    mid.insert((x, n), i);
                    role.insert(i, (e.author.unwrap_or(world.none), 3, x));
                }
                Op::AddMember { member, role: r } => {
                    let i = m();
                    mid.insert((x, n), i);
                    role.insert(i, (*member, *r, x));
                }
                _ => {}
            }
        }
    }
    for (&i, &(m, r, x)) in &role {
        f.add("incarnation", &[s(i), s(m), Val::Int(r)]);
        f.add("inc_from", &[s(i), s(x)]);
        f.add("adds", &[s(x), s(i)]);
    }
    for &x in &own {
        let e = &world.entries[&x];
        f.add("author", &[s(x), s(e.author.unwrap_or(world.none))]);
        f.add("skey", &[s(x), s(e.signer)]);
        f.add("cites", &[s(x), s(e.head.unwrap_or(world.none))]);
        if let Some(m) = e.membership {
            f.add("mem", &[s(x), s(m)]);
        }
        let mut ended = Vec::new();
        let mut made = Vec::new();
        for (n, op) in e.ops.iter().enumerate() {
            match op {
                Op::RemoveMember { membership } => {
                    f.add("s_rem", &[s(x), s(*membership)]);
                    ended.push(*membership);
                }
                Op::AddMember { .. } => made.push(mid[&(x, n)]),
                Op::Succeed => f.add("s_succeed", &[s(x)]),
                Op::Keep { key, entries } => {
                    for t in entries {
                        f.add("s_keep", &[s(x), s(*key), s(*t)]);
                    }
                }
                _ => {}
            }
        }
        for i in &ended {
            for j in &made {
                if let (Some(ri), Some(rj)) = (role.get(i), role.get(j)) {
                    if ri.0 == rj.0 && rj.1 < ri.1 {
                        f.add("replaces", &[s(x), s(*i), s(*j)]);
                    }
                }
            }
        }
        for r in 0..=3 {
            let mut bad = false;
            for op in &e.ops {
                if !role_allows(r, op.name()) {
                    bad = true;
                } else {
                    match op {
                        Op::Create if !e.parents.is_empty() => bad = true,
                        Op::AddMember { role: q, .. } if !(*q < r || (*q == r && r >= 2)) => {
                            bad = true
                        }
                        Op::RemoveMember { membership } => {
                            let own_m = Some(*membership) == e.membership;
                            let tgt = role.get(membership);
                            if !own_m && tgt.is_none_or(|t| t.1 >= r) {
                                bad = true;
                            }
                        }
                        _ => {}
                    }
                }
            }
            if bad {
                f.add("s_badops", &[s(x), Val::Int(r)]);
            }
        }
    }
    (f, own)
}

/// Interns the membership ids of every `create` and `add_member` op, so
/// that space evaluation can name them.
pub fn intern_memberships(world: &mut World) {
    let mut names = Vec::new();
    for x in world.order.clone() {
        let e = &world.entries[&x];
        for (n, op) in e.ops.iter().enumerate() {
            if matches!(op, Op::Create | Op::AddMember { .. }) {
                names.push(world.membership_id(x, n));
            }
        }
    }
    for n in names {
        world.sym(&n);
    }
}

/// The relations a space evaluation reports.
pub const SPACE_RESULTS: [&str; 9] = [
    "valid",
    "member",
    "author_ok",
    "rm2",
    "rm1",
    "rm0",
    "leave",
    "closed",
    "ended",
];

/// The result of evaluating a space.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpaceResult {
    /// Each relation of [`SPACE_RESULTS`].
    pub rels: BTreeMap<&'static str, HashSet<Box<[Val]>>>,
    /// Entries of frozen authors kept because others built on them.
    pub kept_frozen: BTreeSet<Sym>,
}

impl SpaceResult {
    /// The symbols of a unary relation.
    pub fn unary(&self, name: &str) -> BTreeSet<Sym> {
        self.rels
            .get(name)
            .into_iter()
            .flatten()
            .filter_map(|t| match &t[..] {
                [Val::Sym(x)] => Some(*x),
                _ => None,
            })
            .collect()
    }
}

/// Evaluates space `space` over the closure of `ids` (`evaluate_space`).
///
/// A frozen author's entries count only as far as valid entries by authors
/// who are not frozen built on them, as judged with no author frozen; so a
/// space with a frozen author is evaluated twice. With `ignore_frozen`,
/// every author is treated as not frozen; `kept` fixes the frozen entries
/// kept. Membership ids must have been interned ([`intern_memberships`]).
pub fn evaluate_space(
    world: &World,
    space: Sym,
    ids: &BTreeSet<Sym>,
    ignore_frozen: bool,
    kept: Option<&BTreeSet<Sym>>,
) -> SpaceResult {
    let ids = world.closure(ids.iter().copied());
    let (mut f, own) = space_facts(world, space, &ids);
    let authors: BTreeSet<Sym> = own
        .iter()
        .map(|x| world.entries[x].author.unwrap_or(world.none))
        .collect();
    for k in [
        "id_effective_at",
        "id_removed",
        "id_removed_at",
        "id_frozen",
        "kept_frozen",
    ] {
        f.declare(k);
    }
    let everything = world.all();
    let mut frozen = BTreeSet::new();
    for &a in &authors {
        // the verifier's identity logs: everything it holds about the
        // author, including guardians' confirmations
        let r = evaluate_identity(world, a, &everything, None);
        for t in r.rel("effective_at") {
            f.add("id_effective_at", &[s(a), t[0], t[1]]);
        }
        for t in r.rel("removed") {
            f.add("id_removed", &[s(a), t[0]]);
        }
        for t in r.rel("removed_at") {
            f.add("id_removed_at", &[s(a), t[0], t[1]]);
        }
        if r.frozen && !ignore_frozen {
            f.add("id_frozen", &[s(a)]);
            frozen.insert(a);
        }
    }
    let author_of = |x: &Sym| world.entries[x].author.unwrap_or(world.none);
    let computed;
    let kept = match kept {
        Some(k) => Some(k),
        None if !frozen.is_empty() => {
            let nf = evaluate_space(world, space, &ids, true, None);
            let anc = ancestry(world, &own);
            let valid_nf: Vec<Sym> = nf
                .unary("valid")
                .into_iter()
                .filter(|x| !frozen.contains(&author_of(x)))
                .collect();
            computed = nf
                .unary("author_ok")
                .into_iter()
                .filter(|y| {
                    frozen.contains(&author_of(y)) && valid_nf.iter().any(|x| anc[x].contains(y))
                })
                .collect::<BTreeSet<Sym>>();
            Some(&computed)
        }
        None => None,
    };
    let mut kept_frozen = BTreeSet::new();
    for &y in kept.into_iter().flatten() {
        if own.contains(&y) {
            f.add("kept_frozen", &[s(y)]);
            kept_frozen.insert(y);
        }
    }
    let rel = evaluate(space_program(), &f, &world.symbols);
    SpaceResult {
        rels: SPACE_RESULTS.iter().map(|&k| (k, rel.set(k))).collect(),
        kept_frozen,
    }
}
