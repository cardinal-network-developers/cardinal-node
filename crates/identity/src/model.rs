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
//! logs, which are small. Spaces are judged natively in `cardinal-space`,
//! one entry at a time; the `space` program here is what that evaluation is
//! tested against.

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
    /// `start`: genesis only.
    Start {
        /// The space this one succeeds, if it names one.
        succeeds: Option<Sym>,
    },
    /// `add_member`.
    AddMember {
        /// The member identity.
        member: Sym,
        /// Role 0 reader, 1 writer, 2 admin; 3 owner, which only a genesis
        /// gives, and only to its own author.
        role: i64,
    },
    /// `leave`: a member's statement; changes no validity.
    Leave,
    /// `succeed`, naming the successor space.
    Succeed {
        /// The successor.
        successor: Sym,
    },
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
    /// An op only the owner may write (`set_policy`, `set_protocol`; not in
    /// the model).
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
            Op::Start { .. } => "start",
            Op::AddMember { .. } => "add_member",
            Op::Leave => "leave",
            Op::Succeed { .. } => "succeed",
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

/// Which space ops each role may write (`ROLE_OPS`). `start` is in none of
/// them: only a genesis holds one, and a genesis is judged by its shape.
fn role_allows(role: i64, name: &str) -> bool {
    match role {
        3 => matches!(
            name,
            "add_member" | "succeed" | "leave" | "keep" | "app" | "reach" | "owner"
        ),
        2 => matches!(name, "add_member" | "leave" | "keep" | "app" | "reach"),
        1 => matches!(name, "leave" | "keep" | "app" | "reach"),
        0 => matches!(name, "leave" | "keep" | "reach"),
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
}

type CacheKey = (Sym, Vec<Sym>, Option<Vec<Sym>>);

/// A global set of entries across logs.
pub struct World {
    symbols: Symbols,
    entries: HashMap<Sym, Entry>,
    order: Vec<Sym>,
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
    pub fn new() -> World {
        let mut symbols = Symbols::new();
        let none = symbols.intern("\u{0}None");
        World {
            symbols,
            entries: HashMap::new(),
            order: Vec::new(),
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
}

impl Default for World {
    fn default() -> World {
        World::new()
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
    only_genesis: Option<Sym>,
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
        // A space has one genesis, the entry whose id is the space's; an
        // identity log's is any entry without parents.
        if only_genesis.map_or(world.entries[&x].parents.is_empty(), |g| g == x) {
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
    identity_facts_with(world, ident, ids, None)
}

/// [`identity_facts`] where only the protocol records in `declarers`, and
/// in the entry itself, declare (`evolution.md#critical-and-ignorable`).
pub fn identity_facts_with(
    world: &World,
    ident: Sym,
    ids: &BTreeSet<Sym>,
    declarers: Option<&BTreeSet<Sym>>,
) -> Facts {
    let own: BTreeSet<Sym> = ids
        .iter()
        .copied()
        .filter(|x| world.entries[x].log == ident)
        .collect();
    let mut f = Facts::new();
    let anc = graph_facts(world, &own, "", None, &mut f);
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
            .filter(|a| declarers.is_none_or(|d| d.contains(*a)))
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

/// How many evaluations finding which protocol records count in an
/// identity log may take before the history is taken as one that does not
/// settle.
pub const DECLARER_ROUNDS: usize = 8;

/// Which protocol records count (`evolution.md#critical-and-ignorable`):
/// whether a record's entry is valid turns on the records before it, so
/// evaluation runs again with the records found to count until that holds
/// of what is found. `start` is every record that could count; `eval`
/// evaluates with those given as counting, and `found` reads which of
/// `start` count in a result. A history whose found records repeat a set
/// already seen, or have not settled after `rounds` evaluations, has no
/// answer that rules can give: it is evaluated once more with only the
/// records found in every round counting, and the second value is true, so
/// that the caller freezes what it judges rather than take one round's
/// answer. Every evaluation of identities and spaces goes through here, so
/// each finds the same.
pub fn settle_declarers<T: Ord + Clone, R>(
    start: BTreeSet<T>,
    rounds: usize,
    mut eval: impl FnMut(&BTreeSet<T>) -> R,
    found: impl Fn(&R) -> BTreeSet<T>,
) -> (R, bool) {
    let mut seen = vec![start.clone()];
    let mut now = start;
    let mut r = eval(&now);
    loop {
        let f = found(&r);
        if f == now {
            return (r, false);
        }
        let repeats = seen.contains(&f);
        seen.push(f.clone());
        if repeats || seen.len() > rounds {
            let every = seen
                .iter()
                .skip(1)
                .fold(seen[0].clone(), |a, b| a.intersection(b).cloned().collect());
            return (eval(&every), true);
        }
        now = f;
        r = eval(&now);
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
    // Only records in valid entries signed by admin and root keys declare,
    // and a record whose key the log never makes an admin or root never
    // does: evaluated again with those found so, until that holds of what
    // is found (`world.py`, [`settle_declarers`]).
    let mighty: HashSet<Sym> = ids
        .iter()
        .filter(|x| world.entries[x].log == ident)
        .flat_map(|x| world.entries[x].ops.iter())
        .filter_map(|op| match op {
            Op::Add { key, power } if *power >= 2 => Some(*key),
            Op::Recover { root, .. } => Some(*root),
            _ => None,
        })
        .collect();
    let protos: BTreeSet<Sym> = ids
        .iter()
        .copied()
        .filter(|x| world.entries[x].log == ident)
        .filter(|x| {
            world.entries[x]
                .ops
                .iter()
                .any(|op| matches!(op, Op::Protocol { .. }))
        })
        .filter(|x| mighty.contains(&world.entries[x].signer))
        .collect();
    let all_count = protos.len()
        == ids
            .iter()
            .filter(|x| world.entries[x].log == ident)
            .filter(|x| {
                world.entries[x]
                    .ops
                    .iter()
                    .any(|op| matches!(op, Op::Protocol { .. }))
            })
            .count();
    let found = |rel: &crate::datalog::Relations| -> BTreeSet<Sym> {
        let valid = rel.set("valid");
        let power: HashMap<Sym, i64> = rel
            .set("kpow")
            .iter()
            .filter_map(|t| match &t[..] {
                [Val::Sym(k), Val::Int(p)] => Some((*k, *p)),
                _ => None,
            })
            .collect();
        protos
            .iter()
            .copied()
            .filter(|x| valid.contains(&[Val::Sym(*x)][..]))
            .filter(|x| power.get(&world.entries[x].signer).is_some_and(|p| *p >= 2))
            .collect()
    };
    let (rel, unsettled) = settle_declarers(
        protos.clone(),
        DECLARER_ROUNDS,
        |d| {
            if all_count && *d == protos {
                return evaluate(identity_program(), &f, &world.symbols);
            }
            let mut g = identity_facts_with(world, ident, &ids, Some(d));
            confirm_facts(world, ident, &ids, known, &mut g);
            evaluate(identity_program(), &g, &world.symbols)
        },
        found,
    );
    let mut r = IdentityResult {
        rels: IDENTITY_RESULTS.iter().map(|&k| (k, rel.set(k))).collect(),
        frozen: unsettled || rel.any("frozen"),
        contested: unsettled || rel.any("contested"),
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

/// What a genesis says of its space (`genesis_shape`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisShape {
    /// The owner it names, if it names exactly its own author as one.
    pub owner: Option<Sym>,
    /// The identities it names, sorted by symbol text, each once.
    pub named: Vec<Sym>,
    /// Whether it is formed as `spaces.md#members-and-roles` requires.
    pub ok: bool,
}

/// The shape of the genesis `e` (`genesis_shape`).
pub fn genesis_shape(world: &World, e: &Entry) -> GenesisShape {
    let author = e.author.unwrap_or(world.none);
    let named: Vec<(Sym, i64)> = e
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::AddMember { member, role } => Some((*member, *role)),
            _ => None,
        })
        .collect();
    let owners: BTreeSet<Sym> = named
        .iter()
        .filter(|(_, r)| *r == 3)
        .map(|(m, _)| *m)
        .collect();
    let owner = (owners.len() == 1 && owners.contains(&author)).then_some(author);
    let mine: Vec<i64> = named
        .iter()
        .filter(|(m, _)| *m == author)
        .map(|(_, r)| *r)
        .collect();
    let starts = e
        .ops
        .iter()
        .filter(|op| matches!(op, Op::Start { .. }))
        .count();
    let ok = starts == 1
        && !mine.is_empty()
        && owners.iter().all(|m| *m == author)
        && named.iter().filter(|(_, r)| *r == 3).count() <= 1
        && named.iter().all(|(_, r)| (0..=3).contains(r))
        && (owner.is_some() || named.iter().all(|(_, r)| *r < 2))
        && {
            // besides `start` and `add_member`, only what the highest role it
            // gives its author may perform; never a `succeed`
            let top = mine.iter().copied().max().expect("its author is named");
            e.ops.iter().all(|op| {
                matches!(op, Op::Start { .. } | Op::AddMember { .. })
                    || (!matches!(op, Op::Succeed { .. }) && role_allows(top, op.name()))
            })
        };
    let mut first: Vec<Sym> = named.iter().map(|(m, _)| *m).collect();
    first.sort_by(|a, b| world.name(*a).cmp(world.name(*b)));
    first.dedup();
    GenesisShape {
        owner,
        named: first,
        ok,
    }
}

/// The input facts of the `space` program (`space_facts`), without the
/// facts from identity logs.
pub fn space_facts(world: &World, space: Sym, ids: &BTreeSet<Sym>) -> (Facts, BTreeSet<Sym>) {
    let own: BTreeSet<Sym> = ids
        .iter()
        .copied()
        .filter(|x| world.entries[x].log == space)
        .collect();
    let mut f = Facts::new();
    graph_facts(world, &own, "s_", Some(space), &mut f);
    for k in [
        "author",
        "skey",
        "cites",
        "adds",
        "s_names",
        "s_keep",
        "s_structural",
        "s_badops",
        "s_badgenesis",
        "decider",
        "quorum",
    ] {
        f.declare(k);
    }
    let mut owner = None;
    if own.contains(&space) {
        let shape = genesis_shape(world, &world.entries[&space]);
        owner = shape.owner;
        let deciders: Vec<Sym> = match owner {
            Some(o) => vec![o],
            None => shape.named,
        };
        for m in &deciders {
            f.add("decider", &[s(*m)]);
        }
        f.add("quorum", &[Val::Int(deciders.len() as i64)]);
        if !shape.ok {
            f.add("s_badgenesis", &[s(space)]);
        }
    }
    for &x in &own {
        let e = &world.entries[&x];
        f.add("author", &[s(x), s(e.author.unwrap_or(world.none))]);
        f.add("skey", &[s(x), s(e.signer)]);
        f.add("cites", &[s(x), s(e.head.unwrap_or(world.none))]);
        for op in &e.ops {
            match op {
                Op::AddMember { member, role } => {
                    f.add("adds", &[s(x), s(*member), Val::Int(*role)])
                }
                Op::Succeed { successor } => {
                    f.add("s_names", &[s(x), s(*successor)]);
                    f.add("s_structural", &[s(x)]);
                }
                Op::Start { succeeds: Some(_) } if e.parents.is_empty() => {
                    f.add("s_structural", &[s(x)]);
                }
                Op::Keep { key, entries } => {
                    for t in entries {
                        f.add("s_keep", &[s(x), s(*key), s(*t)]);
                    }
                }
                _ => {}
            }
        }
        if e.parents.is_empty() {
            continue; // a genesis is judged by its shape
        }
        for r in 0..=3 {
            let mut bad = false;
            for op in &e.ops {
                match op {
                    // the owner's alone; with no owner, every member's
                    Op::Succeed { .. } => bad = bad || (owner.is_some() && r != 3),
                    // includes a start outside a genesis
                    _ if !role_allows(r, op.name()) => bad = true,
                    // only a genesis names an owner
                    Op::AddMember { role, .. } if !(0..=2).contains(role) => bad = true,
                    _ => {}
                }
            }
            if bad {
                f.add("s_badops", &[s(x), Val::Int(r)]);
            }
        }
    }
    (f, own)
}

/// The relations a space evaluation reports.
pub const SPACE_RESULTS: [&str; 7] = [
    "valid",
    "member",
    "author_ok",
    "named",
    "closed",
    "candidate",
    "successor",
];

/// The result of evaluating a space.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpaceResult {
    /// Each relation of [`SPACE_RESULTS`].
    pub rels: BTreeMap<&'static str, HashSet<Box<[Val]>>>,
}

impl SpaceResult {
    /// The tuples of a reported relation.
    pub fn rel(&self, name: &str) -> impl Iterator<Item = &[Val]> {
        self.rels.get(name).into_iter().flatten().map(|t| &t[..])
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

/// Evaluates space `space` over the closure of `ids` (`evaluate_space`).
///
/// Whether an author is frozen is not asked: a frozen member's entries are
/// judged like anyone's.
pub fn evaluate_space(world: &World, space: Sym, ids: &BTreeSet<Sym>) -> SpaceResult {
    let ids = world.closure(ids.iter().copied());
    let (mut f, own) = space_facts(world, space, &ids);
    let authors: BTreeSet<Sym> = own
        .iter()
        .map(|x| world.entries[x].author.unwrap_or(world.none))
        .collect();
    for k in ["id_effective_at", "id_removed", "id_removed_at"] {
        f.declare(k);
    }
    let everything = world.all();
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
    }
    let rel = evaluate(space_program(), &f, &world.symbols);
    SpaceResult {
        rels: SPACE_RESULTS.iter().map(|&k| (k, rel.set(k))).collect(),
    }
}
