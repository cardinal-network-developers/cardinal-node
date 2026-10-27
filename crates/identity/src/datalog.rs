//! A small stratified Datalog: parser, stratification checker, evaluator.
//!
//! This is a port of `core/model/datalog.py`. The notation is described in
//! `core/model/rules.md`; programs are read from the ```` ```datalog ````
//! blocks of that file. The normative rules are never re-implemented by
//! hand: [`rules`] parses and checks the vendored copy of `rules.md`, and
//! the identity and space evaluations in [`crate::model`] execute it.
//!
//! Evaluation is naive bottom-up iteration to a fixpoint within each
//! stratum, with hash indexes built on demand for each pattern of bound
//! arguments. Every rule body is joined greedily: filters (`not`,
//! comparisons) run as soon as their variables are bound, then the positive
//! atom with the most bound arguments. `count` literals run last. The result
//! of a stratified program does not depend on any of these choices.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::rc::Rc;
use std::sync::OnceLock;

/// The vendored copy of `core/model/rules.md`.
pub const RULES_MD: &str = include_str!("../rules/rules.md");

/// A constant: an integer or an interned symbol.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Val {
    /// An integer.
    Int(i64),
    /// A symbol, interned in a [`Symbols`] table.
    Sym(u32),
}

/// An interner for symbols.
#[derive(Clone, Debug, Default)]
pub struct Symbols {
    map: HashMap<String, u32>,
    names: Vec<String>,
}

impl Symbols {
    /// An empty table.
    pub fn new() -> Symbols {
        Symbols::default()
    }

    /// The symbol for `s`, interning it if new.
    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(&n) = self.map.get(s) {
            return n;
        }
        let n = self.names.len() as u32;
        self.names.push(s.to_owned());
        self.map.insert(s.to_owned(), n);
        n
    }

    /// The symbol for `s`, if interned.
    pub fn get(&self, s: &str) -> Option<u32> {
        self.map.get(s).copied()
    }

    /// The text of symbol `n`.
    pub fn name(&self, n: u32) -> &str {
        self.names.get(n as usize).map_or("", |s| s.as_str())
    }

    /// `Val::Sym` of `s`, interning it.
    pub fn sym(&mut self, s: &str) -> Val {
        Val::Sym(self.intern(s))
    }
}

// ---------------------------------------------------------------- parsing

/// A term in a rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Term {
    /// A variable (a name starting with a capital letter or `_`).
    Var(String),
    /// An integer constant.
    Int(i64),
    /// A symbol constant (a lowercase name or a quoted string).
    Str(String),
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Term::Var(v) | Term::Str(v) => f.write_str(v),
            Term::Int(n) => write!(f, "{n}"),
        }
    }
}

/// `pred(args)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Atom {
    /// The predicate name.
    pub pred: String,
    /// The arguments.
    pub args: Vec<Term>,
}

/// A comparison operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmpOp {
    /// `=`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
}

impl CmpOp {
    fn parse(s: &str) -> Option<CmpOp> {
        Some(match s {
            "=" => CmpOp::Eq,
            "!=" => CmpOp::Ne,
            "<" => CmpOp::Lt,
            "<=" => CmpOp::Le,
            ">" => CmpOp::Gt,
            ">=" => CmpOp::Ge,
            _ => return None,
        })
    }

    fn holds(self, o: std::cmp::Ordering) -> bool {
        use std::cmp::Ordering::*;
        match self {
            CmpOp::Eq => o == Equal,
            CmpOp::Ne => o != Equal,
            CmpOp::Lt => o == Less,
            CmpOp::Le => o != Greater,
            CmpOp::Gt => o == Greater,
            CmpOp::Ge => o != Less,
        }
    }
}

/// A body literal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lit {
    /// A positive atom.
    Pos(Atom),
    /// `not atom`.
    Neg(Atom),
    /// `lhs op rhs`.
    Cmp(Term, CmpOp, Term),
    /// `count{vars : atoms} op rhs`.
    Count {
        /// The counted variables.
        vars: Vec<Term>,
        /// The conjunction counted over.
        atoms: Vec<Atom>,
        /// The comparison.
        op: CmpOp,
        /// The bound compared against.
        rhs: Term,
    },
}

/// `head :- body.` in a stratum.
#[derive(Clone, Debug)]
pub struct Rule {
    /// The head.
    pub head: Atom,
    /// The body.
    pub body: Vec<Lit>,
    /// The stratum's name.
    pub stratum: String,
    /// The source line, within the concatenated blocks.
    pub line: usize,
}

/// A parsed program.
#[derive(Clone, Debug, Default)]
pub struct Program {
    /// Its name, from `@program`.
    pub name: String,
    /// Input predicates and arities, from `@input`.
    pub inputs: BTreeMap<String, usize>,
    /// Strata, in order.
    pub strata: Vec<String>,
    /// The rules.
    pub rules: Vec<Rule>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tok {
    Op,
    Num,
    Str,
    Name,
}

fn tokenize(text: &str) -> Result<Vec<(Tok, String, usize)>, String> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let (mut i, mut line) = (0usize, 1usize);
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            if c == b'\n' {
                line += 1;
            }
            i += 1;
        } else if c == b'%' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if let Some(op) = [":-", "!=", "<=", ">="]
            .iter()
            .find(|op| text[i..].starts_with(*op))
        {
            out.push((Tok::Op, op.to_string(), line));
            i += 2;
        } else if b"(),.{}:<>=/@".contains(&c) {
            out.push((Tok::Op, (c as char).to_string(), line));
            i += 1;
        } else if c.is_ascii_digit() || (c == b'-' && i + 1 < b.len() && b[i + 1].is_ascii_digit())
        {
            let s = i;
            i += 1;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            out.push((Tok::Num, text[s..i].to_string(), line));
        } else if c == b'"' {
            let s = i;
            i += 1;
            while i < b.len() && b[i] != b'"' {
                i += 1;
            }
            if i >= b.len() {
                return Err(format!("line {line}: unterminated string"));
            }
            i += 1;
            let tok = &text[s..i];
            line += tok.matches('\n').count();
            out.push((Tok::Str, tok.to_string(), line));
        } else if c.is_ascii_alphabetic() || c == b'_' {
            let s = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.push((Tok::Name, text[s..i].to_string(), line));
        } else {
            let end = (i + 20).min(text.len());
            return Err(format!(
                "line {line}: cannot read {:?}",
                text.get(i..end).unwrap_or("")
            ));
        }
    }
    Ok(out)
}

struct Parser {
    toks: Vec<(Tok, String, usize)>,
    i: usize,
}

impl Parser {
    fn peek(&self, k: usize) -> Option<&(Tok, String, usize)> {
        self.toks.get(self.i + k)
    }

    fn peek_val(&self, k: usize) -> &str {
        self.peek(k).map(|t| t.1.as_str()).unwrap_or("")
    }

    fn take(&mut self, expect: Option<&str>) -> Result<(Tok, String, usize), String> {
        let tok = self
            .toks
            .get(self.i)
            .cloned()
            .ok_or_else(|| "unexpected end of program".to_string())?;
        if let Some(e) = expect {
            if tok.1 != e {
                return Err(format!("line {}: expected {e:?}, got {:?}", tok.2, tok.1));
            }
        }
        self.i += 1;
        Ok(tok)
    }

    fn term(&mut self) -> Result<Term, String> {
        let (kind, val, line) = self.take(None)?;
        match kind {
            Tok::Num => val
                .parse()
                .map(Term::Int)
                .map_err(|_| format!("line {line}: bad number")),
            Tok::Str => Ok(Term::Str(val[1..val.len() - 1].to_string())),
            Tok::Name => {
                let c = val.chars().next().unwrap_or('a');
                Ok(if c.is_ascii_uppercase() || c == '_' {
                    Term::Var(val)
                } else {
                    Term::Str(val)
                })
            }
            Tok::Op => Err(format!("line {line}: expected a term, got {val:?}")),
        }
    }

    fn atom(&mut self) -> Result<Atom, String> {
        let (kind, name, line) = self.take(None)?;
        if kind != Tok::Name {
            return Err(format!("line {line}: expected a predicate, got {name:?}"));
        }
        let mut args = Vec::new();
        if self.peek_val(0) == "(" {
            self.take(Some("("))?;
            args.push(self.term()?);
            while self.peek_val(0) == "," {
                self.take(Some(","))?;
                args.push(self.term()?);
            }
            self.take(Some(")"))?;
        }
        Ok(Atom { pred: name, args })
    }

    fn cmp_op(&mut self) -> Result<CmpOp, String> {
        let (_, v, line) = self.take(None)?;
        CmpOp::parse(&v).ok_or_else(|| format!("line {line}: expected a comparison, got {v:?}"))
    }

    fn literal(&mut self) -> Result<Lit, String> {
        let kind = self.peek(0).map(|t| t.0);
        let val = self.peek_val(0).to_string();
        if val == "not" {
            self.take(None)?;
            return Ok(Lit::Neg(self.atom()?));
        }
        if val == "count" && self.peek_val(1) == "{" {
            self.take(None)?;
            self.take(Some("{"))?;
            let mut vars = vec![self.term()?];
            while self.peek_val(0) == "," {
                self.take(Some(","))?;
                vars.push(self.term()?);
            }
            self.take(Some(":"))?;
            let mut atoms = vec![self.atom()?];
            while self.peek_val(0) == "," {
                self.take(Some(","))?;
                atoms.push(self.atom()?);
            }
            self.take(Some("}"))?;
            let op = self.cmp_op()?;
            let rhs = self.term()?;
            return Ok(Lit::Count {
                vars,
                atoms,
                op,
                rhs,
            });
        }
        if kind == Some(Tok::Name) && !["!=", "<", "<=", ">", ">=", "="].contains(&self.peek_val(1))
        {
            return Ok(Lit::Pos(self.atom()?));
        }
        let lhs = self.term()?;
        let op = self.cmp_op()?;
        let rhs = self.term()?;
        Ok(Lit::Cmp(lhs, op, rhs))
    }
}

/// Parses every `@program` in `text`.
pub fn parse(text: &str) -> Result<BTreeMap<String, Program>, String> {
    let mut p = Parser {
        toks: tokenize(text)?,
        i: 0,
    };
    let mut programs: BTreeMap<String, Program> = BTreeMap::new();
    let mut prog: Option<String> = None;
    let mut stratum: Option<String> = None;
    while p.i < p.toks.len() {
        let line = p.toks[p.i].2;
        if p.peek_val(0) == "@" {
            p.take(Some("@"))?;
            let directive = p.take(None)?.1;
            match directive.as_str() {
                "program" => {
                    let name = p.take(None)?.1;
                    programs.entry(name.clone()).or_insert_with(|| Program {
                        name: name.clone(),
                        ..Program::default()
                    });
                    prog = Some(name);
                    stratum = None;
                }
                "stratum" => {
                    let name = p.take(None)?.1;
                    let pr = prog
                        .as_ref()
                        .and_then(|n| programs.get_mut(n))
                        .ok_or_else(|| format!("line {line}: @stratum outside a @program"))?;
                    if pr.strata.contains(&name) {
                        return Err(format!("line {line}: stratum {name} declared twice"));
                    }
                    pr.strata.push(name.clone());
                    stratum = Some(name);
                }
                "input" => {
                    let pr = prog
                        .as_ref()
                        .and_then(|n| programs.get_mut(n))
                        .ok_or_else(|| format!("line {line}: @input outside a @program"))?;
                    while p.peek(0).map(|t| t.0) == Some(Tok::Name) && p.peek_val(1) == "/" {
                        let pred = p.take(None)?.1;
                        p.take(Some("/"))?;
                        let n = p.take(None)?;
                        let n: usize =
                            n.1.parse()
                                .map_err(|_| format!("line {}: bad arity", n.2))?;
                        pr.inputs.insert(pred, n);
                    }
                }
                d => return Err(format!("line {line}: unknown directive @{d}")),
            }
            continue;
        }
        let (Some(pn), Some(st)) = (prog.clone(), stratum.clone()) else {
            return Err(format!("line {line}: rule outside a @program/@stratum"));
        };
        let head = p.atom()?;
        let mut body = Vec::new();
        if p.peek_val(0) == ":-" {
            p.take(Some(":-"))?;
            body.push(p.literal()?);
            while p.peek_val(0) == "," {
                p.take(Some(","))?;
                body.push(p.literal()?);
            }
        }
        p.take(Some("."))?;
        programs.get_mut(&pn).expect("program").rules.push(Rule {
            head,
            body,
            stratum: st,
            line,
        });
    }
    Ok(programs)
}

/// Concatenates the ```` ```datalog ```` blocks of a Markdown file, joined
/// by newlines as `datalog.py` does.
pub fn datalog_blocks(markdown: &str) -> String {
    let mut blocks = Vec::new();
    let mut rest = markdown;
    while let Some(s) = rest.find("```datalog\n") {
        let body = &rest[s + "```datalog\n".len()..];
        match body.find("```") {
            Some(e) => {
                blocks.push(&body[..e]);
                rest = &body[e + 3..];
            }
            None => break,
        }
    }
    blocks.join("\n")
}

/// Parses the programs of a Markdown rules file.
pub fn read_rules(markdown: &str) -> Result<BTreeMap<String, Program>, String> {
    parse(&datalog_blocks(markdown))
}

/// The programs of the vendored `rules.md`, parsed and checked once.
///
/// # Panics
///
/// If the vendored rules do not parse or are not stratified; a unit test
/// guarantees they do and are.
pub fn rules() -> &'static BTreeMap<String, Program> {
    static RULES: OnceLock<BTreeMap<String, Program>> = OnceLock::new();
    RULES.get_or_init(|| {
        let progs = read_rules(RULES_MD).expect("vendored rules.md parses");
        for p in progs.values() {
            let errors = check(p);
            assert!(errors.is_empty(), "rules.md {}: {errors:?}", p.name);
        }
        progs
    })
}

/// The `identity` program.
pub fn identity_program() -> &'static Program {
    &rules()["identity"]
}

/// The `space` program.
pub fn space_program() -> &'static Program {
    &rules()["space"]
}

// ---------------------------------------------------- stratification check

fn vars_of(args: &[Term]) -> impl Iterator<Item = &str> {
    args.iter().filter_map(|a| match a {
        Term::Var(v) => Some(v.as_str()),
        _ => None,
    })
}

/// Returns a list of problems. An empty list means the program is
/// stratified, safe, and consistent.
pub fn check(prog: &Program) -> Vec<String> {
    let mut errors = Vec::new();
    let level: HashMap<&str, usize> = prog
        .strata
        .iter()
        .enumerate()
        .map(|(n, s)| (s.as_str(), n))
        .collect();
    let mut defined: HashMap<&str, &str> = HashMap::new();
    let mut arity: HashMap<String, usize> = prog.inputs.clone().into_iter().collect();

    let mut note_arity = |a: &Atom, line: usize, errors: &mut Vec<String>| {
        let n = a.args.len();
        let have = *arity.entry(a.pred.clone()).or_insert(n);
        if have != n {
            errors.push(format!(
                "line {line}: {} used with arity {n} and {have}",
                a.pred
            ));
        }
    };

    for r in &prog.rules {
        let p = r.head.pred.as_str();
        if prog.inputs.contains_key(p) {
            errors.push(format!(
                "line {}: {p} is an input and cannot be derived",
                r.line
            ));
        }
        let d = *defined.entry(p).or_insert(r.stratum.as_str());
        if d != r.stratum {
            errors.push(format!(
                "line {}: {p} is defined in strata {d} and {}",
                r.line, r.stratum
            ));
        }
        note_arity(&r.head, r.line, &mut errors);
    }

    let stratum_of = |pred: &str, line: usize, errors: &mut Vec<String>| -> isize {
        if prog.inputs.contains_key(pred) {
            return -1;
        }
        match defined.get(pred) {
            None => {
                errors.push(format!(
                    "line {line}: {pred} is neither an input nor derived"
                ));
                -1
            }
            Some(s) => level[s] as isize,
        }
    };

    for r in &prog.rules {
        let here = level[r.stratum.as_str()] as isize;
        let mut bound: HashSet<&str> = HashSet::new();
        for lit in &r.body {
            if let Lit::Pos(a) = lit {
                note_arity(a, r.line, &mut errors);
                if stratum_of(&a.pred, r.line, &mut errors) > here {
                    errors.push(format!(
                        "line {}: {} uses {} from a later stratum",
                        r.line, r.head.pred, a.pred
                    ));
                }
                bound.extend(vars_of(&a.args));
            }
        }
        for lit in &r.body {
            match lit {
                Lit::Pos(_) => {}
                Lit::Neg(a) => {
                    note_arity(a, r.line, &mut errors);
                    if stratum_of(&a.pred, r.line, &mut errors) >= here {
                        errors.push(format!(
                            "line {}: {} negates {}, which is not from an earlier stratum",
                            r.line, r.head.pred, a.pred
                        ));
                    }
                    let mut free: Vec<&str> =
                        vars_of(&a.args).filter(|v| !bound.contains(v)).collect();
                    free.sort();
                    free.dedup();
                    if !free.is_empty() {
                        errors.push(format!("line {}: unbound {free:?} under 'not'", r.line));
                    }
                }
                Lit::Cmp(l, _, rr) => {
                    for t in [l, rr] {
                        if let Term::Var(v) = t {
                            if !bound.contains(v.as_str()) {
                                errors.push(format!("line {}: unbound {v} in comparison", r.line));
                            }
                        }
                    }
                }
                Lit::Count {
                    vars, atoms, rhs, ..
                } => {
                    let mut inner: HashSet<&str> = HashSet::new();
                    for a in atoms {
                        note_arity(a, r.line, &mut errors);
                        if stratum_of(&a.pred, r.line, &mut errors) >= here {
                            errors.push(format!(
                                "line {}: {} counts {}, which is not from an earlier stratum",
                                r.line, r.head.pred, a.pred
                            ));
                        }
                        inner.extend(vars_of(&a.args));
                    }
                    for v in vars {
                        let ok = match v {
                            Term::Var(v) => inner.contains(v.as_str()),
                            _ => false,
                        };
                        if !ok {
                            errors.push(format!(
                                "line {}: counted {v} does not occur in the count",
                                r.line
                            ));
                        }
                    }
                    if let Term::Var(v) = rhs {
                        if !bound.contains(v.as_str()) {
                            errors.push(format!("line {}: unbound {v} in count", r.line));
                        }
                    }
                }
            }
        }
        let mut free: Vec<&str> = vars_of(&r.head.args)
            .filter(|v| !bound.contains(v))
            .collect();
        free.sort();
        free.dedup();
        if !free.is_empty() {
            errors.push(format!(
                "line {}: head variables {free:?} are not bound",
                r.line
            ));
        }
    }
    errors
}

// --------------------------------------------------------------- evaluation

/// Input facts: predicate name to tuples.
#[derive(Clone, Debug, Default)]
pub struct Facts {
    map: HashMap<String, HashSet<Box<[Val]>>>,
}

impl Facts {
    /// No facts.
    pub fn new() -> Facts {
        Facts::default()
    }

    /// Adds `pred(tuple)`.
    pub fn add(&mut self, pred: &str, tuple: &[Val]) {
        if let Some(s) = self.map.get_mut(pred) {
            s.insert(tuple.into());
        } else {
            self.map
                .entry(pred.to_owned())
                .or_default()
                .insert(tuple.into());
        }
    }

    /// Declares `pred` with no tuples (so lookups find an empty relation).
    pub fn declare(&mut self, pred: &str) {
        self.map.entry(pred.to_owned()).or_default();
    }

    /// The tuples of `pred`.
    pub fn get(&self, pred: &str) -> impl Iterator<Item = &[Val]> {
        self.map.get(pred).into_iter().flatten().map(|t| &t[..])
    }

    /// Whether `pred(tuple)` holds.
    pub fn contains(&self, pred: &str, tuple: &[Val]) -> bool {
        self.map.get(pred).is_some_and(|s| s.contains(tuple))
    }

    /// The number of tuples of `pred`.
    pub fn len(&self, pred: &str) -> usize {
        self.map.get(pred).map_or(0, |s| s.len())
    }

    /// Whether `pred` has no tuples.
    pub fn is_empty(&self, pred: &str) -> bool {
        self.len(pred) == 0
    }

    /// Removes and returns the tuples of `pred`.
    pub fn take(&mut self, pred: &str) -> HashSet<Box<[Val]>> {
        self.map.remove(pred).unwrap_or_default()
    }

    /// Replaces the tuples of `pred`.
    pub fn set(&mut self, pred: &str, tuples: HashSet<Box<[Val]>>) {
        self.map.insert(pred.to_owned(), tuples);
    }

    /// Predicate names present.
    pub fn preds(&self) -> impl Iterator<Item = &str> {
        self.map.keys().map(|s| s.as_str())
    }
}

#[derive(Clone, Copy, Debug)]
enum CTerm {
    Var(usize),
    Const(Val),
}

#[derive(Clone, Debug)]
struct CAtom {
    pred: usize,
    args: Vec<CTerm>,
}

#[derive(Clone, Debug)]
enum CLit {
    Pos(CAtom),
    Neg(CAtom),
    Cmp(CTerm, CmpOp, CTerm),
    Count {
        vars: Vec<usize>,
        atoms: Vec<CAtom>,
        op: CmpOp,
        rhs: CTerm,
    },
}

#[derive(Clone, Debug)]
struct CRule {
    head: CAtom,
    /// Positive literals and filters, joined.
    body: Vec<CLit>,
    /// Counts, checked after the join.
    counts: Vec<CLit>,
    nvars: usize,
}

type Index = HashMap<Box<[Val]>, Vec<u32>>;

#[derive(Default)]
struct Rel {
    tuples: Vec<Box<[Val]>>,
    set: HashSet<Box<[Val]>>,
    index: RefCell<HashMap<u64, Rc<Index>>>,
}

impl Rel {
    fn insert(&mut self, t: Box<[Val]>) -> bool {
        if self.set.contains(&t) {
            return false;
        }
        self.set.insert(t.clone());
        self.tuples.push(t);
        true
    }

    fn index(&self, mask: u64) -> Rc<Index> {
        if let Some(i) = self.index.borrow().get(&mask) {
            return i.clone();
        }
        let mut idx: Index = HashMap::new();
        for (n, t) in self.tuples.iter().enumerate() {
            let key: Box<[Val]> = t
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, v)| *v)
                .collect();
            idx.entry(key).or_default().push(n as u32);
        }
        let idx = Rc::new(idx);
        self.index.borrow_mut().insert(mask, idx.clone());
        idx
    }
}

struct Db<'s> {
    rels: Vec<Rel>,
    symbols: &'s Symbols,
}

impl Db<'_> {
    fn cmp(&self, a: Val, op: CmpOp, b: Val) -> bool {
        match (a, b) {
            (Val::Int(x), Val::Int(y)) => op.holds(x.cmp(&y)),
            (Val::Sym(x), Val::Sym(y)) => {
                if x == y {
                    op.holds(std::cmp::Ordering::Equal)
                } else {
                    match op {
                        CmpOp::Eq => false,
                        CmpOp::Ne => true,
                        _ => op.holds(self.symbols.name(x).cmp(self.symbols.name(y))),
                    }
                }
            }
            _ => matches!(op, CmpOp::Ne),
        }
    }

    fn value(t: CTerm, env: &[Option<Val>]) -> Val {
        match t {
            CTerm::Const(v) => v,
            CTerm::Var(i) => env[i].expect("bound variable"),
        }
    }

    fn mask_and_key(a: &CAtom, env: &[Option<Val>]) -> (u64, Vec<Val>) {
        let mut mask = 0u64;
        let mut key = Vec::new();
        for (n, t) in a.args.iter().enumerate() {
            match *t {
                CTerm::Const(v) => {
                    mask |= 1 << n;
                    key.push(v);
                }
                CTerm::Var(i) => {
                    if let Some(v) = env[i] {
                        mask |= 1 << n;
                        key.push(v);
                    }
                }
            }
        }
        (mask, key)
    }

    /// Calls `f` with each extension of `env` matching `a`.
    fn lookup(
        &self,
        a: &CAtom,
        env: &mut Vec<Option<Val>>,
        f: &mut dyn FnMut(&mut Vec<Option<Val>>),
    ) {
        let rel = &self.rels[a.pred];
        let (mask, key) = Self::mask_and_key(a, env);
        let full = if a.args.is_empty() {
            0
        } else {
            (1u64 << a.args.len()) - 1
        };
        if mask == full {
            if rel.set.contains(&key[..]) {
                f(env);
            }
            return;
        }
        let idx;
        let candidates: Box<dyn Iterator<Item = &Box<[Val]>>> = if mask == 0 {
            Box::new(rel.tuples.iter())
        } else {
            idx = rel.index(mask);
            match idx.get(&key[..]) {
                Some(ns) => Box::new(ns.iter().map(|&n| &rel.tuples[n as usize])),
                None => return,
            }
        };
        let mut newly = Vec::with_capacity(a.args.len());
        for t in candidates {
            newly.clear();
            let mut ok = true;
            for (n, term) in a.args.iter().enumerate() {
                if let CTerm::Var(i) = *term {
                    match env[i] {
                        Some(v) => {
                            if v != t[n] {
                                ok = false;
                                break;
                            }
                        }
                        None => {
                            env[i] = Some(t[n]);
                            newly.push(i);
                        }
                    }
                }
            }
            if ok {
                f(env);
            }
            for &i in &newly {
                env[i] = None;
            }
        }
    }

    fn holds(&self, a: &CAtom, env: &mut Vec<Option<Val>>) -> bool {
        let mut found = false;
        self.lookup(a, env, &mut |_| found = true);
        found
    }

    fn filter_ready(lit: &CLit, env: &[Option<Val>]) -> bool {
        let bound = |t: &CTerm| match t {
            CTerm::Var(i) => env[*i].is_some(),
            CTerm::Const(_) => true,
        };
        match lit {
            CLit::Neg(a) => a.args.iter().all(bound),
            CLit::Cmp(l, _, r) => bound(l) && bound(r),
            _ => false,
        }
    }

    fn filter(&self, lit: &CLit, env: &mut Vec<Option<Val>>) -> bool {
        match lit {
            CLit::Neg(a) => !self.holds(a, env),
            CLit::Cmp(l, op, r) => self.cmp(Self::value(*l, env), *op, Self::value(*r, env)),
            CLit::Count {
                vars,
                atoms,
                op,
                rhs,
            } => {
                let mut seen: HashSet<Vec<Val>> = HashSet::new();
                let lits: Vec<CLit> = atoms.iter().cloned().map(CLit::Pos).collect();
                let mut live = vec![true; lits.len()];
                self.solve(&lits, &mut live, env, &mut |e| {
                    seen.insert(vars.iter().map(|&v| e[v].expect("counted var")).collect());
                });
                let n = Val::Int(seen.len() as i64);
                self.cmp(n, *op, Self::value(*rhs, env))
            }
            CLit::Pos(_) => unreachable!(),
        }
    }

    fn solve(
        &self,
        lits: &[CLit],
        live: &mut Vec<bool>,
        env: &mut Vec<Option<Val>>,
        out: &mut dyn FnMut(&mut Vec<Option<Val>>),
    ) {
        // any ready filter first
        for n in 0..lits.len() {
            if !live[n] || matches!(lits[n], CLit::Pos(_)) {
                continue;
            }
            if Self::filter_ready(&lits[n], env) {
                if self.filter(&lits[n], env) {
                    live[n] = false;
                    self.solve(lits, live, env, out);
                    live[n] = true;
                }
                return;
            }
        }
        // otherwise the positive atom with the most bound arguments
        let mut best: Option<(usize, isize)> = None;
        for n in 0..lits.len() {
            if !live[n] {
                continue;
            }
            if let CLit::Pos(a) = &lits[n] {
                let s = a
                    .args
                    .iter()
                    .filter(|t| match t {
                        CTerm::Var(i) => env[*i].is_some(),
                        CTerm::Const(_) => true,
                    })
                    .count() as isize;
                if best.is_none_or(|(_, bs)| s > bs) {
                    best = Some((n, s));
                }
            }
        }
        let Some((n, _)) = best else {
            if live.iter().any(|&l| l) {
                panic!("unsafe rule body");
            }
            out(env);
            return;
        };
        let CLit::Pos(a) = &lits[n] else {
            unreachable!()
        };
        live[n] = false;
        self.lookup(a, env, &mut |e| self.solve(lits, live, e, out));
        live[n] = true;
    }
}

/// The relations computed by [`evaluate`].
pub struct Relations {
    names: HashMap<String, usize>,
    rels: Vec<Rel>,
}

impl Relations {
    /// The tuples of `pred` (empty if unknown).
    pub fn get(&self, pred: &str) -> impl Iterator<Item = &[Val]> {
        self.names
            .get(pred)
            .into_iter()
            .flat_map(|&n| self.rels[n].tuples.iter().map(|t| &t[..]))
    }

    /// Whether `pred(tuple)` holds.
    pub fn contains(&self, pred: &str, tuple: &[Val]) -> bool {
        self.names
            .get(pred)
            .is_some_and(|&n| self.rels[n].set.contains(tuple))
    }

    /// Whether `pred` has any tuple.
    pub fn any(&self, pred: &str) -> bool {
        self.names
            .get(pred)
            .is_some_and(|&n| !self.rels[n].tuples.is_empty())
    }

    /// The tuples of `pred`, as a set.
    pub fn set(&self, pred: &str) -> HashSet<Box<[Val]>> {
        self.get(pred).map(|t| t.into()).collect()
    }
}

fn compile(
    prog: &Program,
    preds: &mut HashMap<String, usize>,
    symbols: &Symbols,
) -> Vec<(usize, CRule)> {
    fn pred_id(preds: &mut HashMap<String, usize>, p: &str) -> usize {
        let n = preds.len();
        *preds.entry(p.to_owned()).or_insert(n)
    }
    let level: HashMap<&str, usize> = prog
        .strata
        .iter()
        .enumerate()
        .map(|(n, s)| (s.as_str(), n))
        .collect();
    let mut out = Vec::new();
    for r in &prog.rules {
        let mut vars: HashMap<String, usize> = HashMap::new();
        let mut term = |t: &Term, symbols: &Symbols| match t {
            Term::Var(v) => {
                let n = vars.len();
                CTerm::Var(*vars.entry(v.clone()).or_insert(n))
            }
            Term::Int(i) => CTerm::Const(Val::Int(*i)),
            Term::Str(s) => CTerm::Const(Val::Sym(symbols.get(s).unwrap_or(u32::MAX))),
        };
        let atom = |a: &Atom,
                    preds: &mut HashMap<String, usize>,
                    symbols: &Symbols,
                    term: &mut dyn FnMut(&Term, &Symbols) -> CTerm| CAtom {
            pred: pred_id(preds, &a.pred),
            args: a.args.iter().map(|t| term(t, symbols)).collect(),
        };
        let head = atom(&r.head, preds, symbols, &mut term);
        let mut body = Vec::new();
        let mut counts = Vec::new();
        // positive literals first, then other filters, then counts, as
        // datalog.py orders them
        for l in &r.body {
            if let Lit::Pos(a) = l {
                body.push(CLit::Pos(atom(a, preds, symbols, &mut term)));
            }
        }
        for l in &r.body {
            match l {
                Lit::Pos(_) => {}
                Lit::Neg(a) => body.push(CLit::Neg(atom(a, preds, symbols, &mut term))),
                Lit::Cmp(a, op, b) => {
                    let a = term(a, symbols);
                    let b = term(b, symbols);
                    body.push(CLit::Cmp(a, *op, b));
                }
                Lit::Count {
                    vars: cv,
                    atoms,
                    op,
                    rhs,
                } => {
                    let atoms: Vec<CAtom> = atoms
                        .iter()
                        .map(|a| atom(a, preds, symbols, &mut term))
                        .collect();
                    let cv = cv
                        .iter()
                        .map(|t| match term(t, symbols) {
                            CTerm::Var(i) => i,
                            CTerm::Const(_) => usize::MAX,
                        })
                        .collect();
                    let rhs = term(rhs, symbols);
                    counts.push(CLit::Count {
                        vars: cv,
                        atoms,
                        op: *op,
                        rhs,
                    });
                }
            }
        }
        let nvars = vars.len();
        out.push((
            level[r.stratum.as_str()],
            CRule {
                head,
                body,
                counts,
                nvars,
            },
        ));
    }
    out
}

/// Evaluates a checked program over input facts. Symbol constants in the
/// rules are looked up in `symbols`; one that is not there matches nothing.
/// Returns every relation.
pub fn evaluate(prog: &Program, facts: &Facts, symbols: &Symbols) -> Relations {
    let mut preds: HashMap<String, usize> = HashMap::new();
    for p in facts.preds() {
        let n = preds.len();
        preds.entry(p.to_owned()).or_insert(n);
    }
    let rules = compile(prog, &mut preds, symbols);
    let mut rels: Vec<Rel> = (0..preds.len()).map(|_| Rel::default()).collect();
    for (p, &n) in &preds {
        if let Some(ts) = facts.map.get(p) {
            for t in ts {
                rels[n].insert(t.clone());
            }
        }
    }
    let mut db = Db { rels, symbols };
    for stratum in 0..prog.strata.len() {
        let rules: Vec<&CRule> = rules
            .iter()
            .filter(|(s, _)| *s == stratum)
            .map(|(_, r)| r)
            .collect();
        loop {
            let mut new: Vec<(usize, Box<[Val]>)> = Vec::new();
            for r in &rules {
                let mut env = vec![None; r.nvars];
                let mut live = vec![true; r.body.len()];
                let db_ref = &db;
                db_ref.solve(&r.body, &mut live, &mut env, &mut |e| {
                    if r.counts.iter().all(|c| db_ref.filter(c, e)) {
                        let t: Box<[Val]> = r.head.args.iter().map(|&a| Db::value(a, e)).collect();
                        new.push((r.head.pred, t));
                    }
                });
            }
            let mut changed = Vec::new();
            for (p, t) in new {
                if db.rels[p].insert(t) {
                    changed.push(p);
                }
            }
            if changed.is_empty() {
                break;
            }
            for p in changed {
                db.rels[p].index.borrow_mut().clear();
            }
        }
    }
    Relations {
        names: preds,
        rels: db.rels,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendored_rules_are_stratified() {
        let progs = read_rules(RULES_MD).unwrap();
        for name in ["identity", "space"] {
            let p = &progs[name];
            assert!(check(p).is_empty(), "{name}: {:?}", check(p));
            assert!(!p.rules.is_empty());
        }
        assert_eq!(progs["identity"].strata.len(), 13);
        assert_eq!(progs["space"].strata.len(), 9);
    }

    #[test]
    fn vendored_rules_match_spec() {
        // The vendored copy must be byte-identical to core/model/rules.md
        // when the specification is checked out next to this repository.
        let Some(path) = crate::testutil::core_path("model/rules.md") else {
            eprintln!("core/model/rules.md not found; skipping");
            return;
        };
        let spec = std::fs::read(&path).unwrap();
        assert!(
            spec == RULES_MD.as_bytes(),
            "crates/identity/rules/rules.md differs from {}",
            path.display()
        );
    }

    fn eval(src: &str, facts: &[(&str, &[i64])]) -> (Relations, Symbols) {
        let progs = parse(src).unwrap();
        let p = progs.values().next().unwrap();
        assert!(check(p).is_empty(), "{:?}", check(p));
        let mut f = Facts::new();
        for (pred, t) in facts {
            let t: Vec<Val> = t.iter().map(|&x| Val::Int(x)).collect();
            f.add(pred, &t);
        }
        let s = Symbols::new();
        let r = evaluate(p, &f, &s);
        (r, s)
    }

    #[test]
    fn transitive_closure_and_negation() {
        let src = "@program t\n@input e/2 n/1\n@stratum a\n\
                   p(X,Y) :- e(X,Y).\np(X,Z) :- p(X,Y), e(Y,Z).\n\
                   @stratum b\nq(X) :- n(X), not p(X,X).\n\
                   big(X) :- n(X), count{Y : p(X,Y)} >= 2.\nnone :- n(X), X > 5.\n";
        let (r, _) = eval(
            src,
            &[
                ("e", &[1, 2]),
                ("e", &[2, 3]),
                ("e", &[3, 1]),
                ("e", &[4, 5]),
                ("n", &[1]),
                ("n", &[4]),
            ],
        );
        assert!(r.contains("p", &[Val::Int(1), Val::Int(1)]));
        assert!(r.contains("q", &[Val::Int(4)]));
        assert!(!r.contains("q", &[Val::Int(1)]));
        assert!(r.contains("big", &[Val::Int(1)]));
        assert!(!r.contains("big", &[Val::Int(4)]));
        assert!(!r.any("none"));
    }

    #[test]
    fn check_rejects_unstratified() {
        let src = "@program t\n@input e/1\n@stratum a\np(X) :- e(X), not q(X).\n\
                   q(X) :- e(X), not p(X).\n";
        let p = &parse(src).unwrap()["t"];
        let errs = check(p);
        assert_eq!(errs.len(), 2, "{errs:?}");
        let src = "@program t\n@input e/1\n@stratum a\np(X,Y) :- e(X).\n";
        assert!(!check(&parse(src).unwrap()["t"]).is_empty());
    }
}
