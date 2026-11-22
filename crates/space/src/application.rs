//! Application documents (`profiles.md#applications-normative`): what an
//! application's spaces hold, named by the hash of the document; families
//! of a root and its children; document nodes; translations; and the checks
//! the writer's own service makes of what a program asks to write.
//!
//! State never depends on any of this. A node that fits no document is in
//! the state like any other; only the writer's service refuses to sign
//! one, and a program is told when a node it is given does not fit.

use std::collections::{BTreeMap, HashMap, HashSet};

use cardinal_encoding::{varint, Record, Value};

use crate::entry::{NodeId, NodeKind};
use crate::state::{Node, State, ROOT};

/// The object kind of an application document (`encoding.md`, registry).
pub const DOCUMENT: u64 = 14;
/// The node kind of a document node, in every space of an application.
pub const DOCUMENT_NODE: u64 = 0;
/// The shared rules' author-owned field (`profiles.md#shared-rules-normative`).
pub const AUTHOR_OWNED: u64 = 15;

/// What a field holds (`profiles.md`, the types table).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    Text,
    Integer,
    Boolean,
    Bytes,
    Time,
    Node,
    Member,
    File,
    Record,
}

impl Type {
    fn from_u64(n: u64) -> Option<Type> {
        Some(match n {
            1 => Type::Text,
            2 => Type::Integer,
            3 => Type::Boolean,
            4 => Type::Bytes,
            5 => Type::Time,
            6 => Type::Node,
            7 => Type::Member,
            8 => Type::File,
            9 => Type::Record,
            _ => return None,
        })
    }

    /// The number a document gives it.
    pub fn number(self) -> u64 {
        self as u64 + 1
    }

    /// Whether `v` is one value of this type.
    pub fn holds(self, v: &Value) -> bool {
        match self {
            Type::Text => v.as_text().is_some(),
            Type::Integer | Type::Time => v.as_int().is_some(),
            Type::Boolean => v.as_bool().is_some(),
            Type::Bytes => v.as_bytes().is_some(),
            Type::Node => v.as_bytes().is_some_and(|b| b.len() == 16),
            Type::Member => v.as_bytes().is_some_and(|b| b.len() == 32),
            Type::File => v
                .as_record()
                .is_some_and(|r| crate::files::BlobRef::from_record(r).is_some()),
            Type::Record => v.as_record().is_some(),
        }
    }
}

/// A field a kind declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDef {
    pub key: u64,
    pub name: String,
    pub ty: Type,
    pub list: bool,
}

impl FieldDef {
    /// Whether `v` is a value of this field: one of its type, or a list of
    /// them for a list.
    pub fn holds(&self, v: &Value) -> bool {
        match self.list {
            false => self.ty.holds(v),
            true => v
                .as_list()
                .is_some_and(|items| items.iter().all(|x| self.ty.holds(x))),
        }
    }
}

/// Where a kind may be created.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Place {
    /// Under the root.
    Root,
    /// Under a node of this document's kind.
    Own(u64),
    /// Under a node of an ancestor's kind: its name, and the kind.
    Of([u8; 32], u64),
}

/// A kind a document declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KindDef {
    pub kind: u64,
    pub name: String,
    pub places: Vec<Place>,
    pub author_owned: bool,
    pub fields: Vec<FieldDef>,
}

impl KindDef {
    pub fn field(&self, key: u64) -> Option<&FieldDef> {
        self.fields.iter().find(|f| f.key == key)
    }
}

/// An application document, read and found well formed on its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    /// Its name: `BLAKE3` of its bytes.
    pub name: [u8; 32],
    /// Its bytes.
    pub bytes: Vec<u8>,
    /// Field 1, shown to people.
    pub title: String,
    /// Field 2, one sentence.
    pub sentence: String,
    /// Field 3, the application it adds to.
    pub parent: Option<[u8; 32]>,
    /// Field 4: whether a space may have members besides its owner, and
    /// the role given to those added.
    pub sharing: Option<(bool, u64)>,
    /// Field 5.
    pub kinds: Vec<KindDef>,
    /// Field 6.
    pub words: String,
    /// Field 7: the original, for a translation.
    pub translates: Option<[u8; 32]>,
    /// Field 8.
    pub language: Option<String>,
}

/// The name of a document of these bytes.
pub fn name_of(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// Whether text keeps the words' rules: UTF-8 (it is a `str`), no byte
/// order mark, every line ending in a line feed, single spaces only, no
/// space at either end of a line, and no control character but the line
/// feed.
pub fn words_ok(t: &str) -> bool {
    if t.is_empty() || t.starts_with('\u{feff}') || !t.ends_with('\n') {
        return false;
    }
    if t.chars().any(|c| c != '\n' && c.is_control()) || t.contains("  ") {
        return false;
    }
    t[..t.len() - 1]
        .split('\n')
        .all(|l| !l.starts_with(' ') && !l.ends_with(' '))
}

fn bad(why: &str) -> String {
    format!("a malformed application document: {why}")
}

fn text(r: &Record, k: u64, what: &str) -> Result<Option<String>, String> {
    match r.get(k) {
        None => Ok(None),
        Some(v) => v
            .as_text()
            .map(|t| Some(t.to_owned()))
            .ok_or_else(|| bad(&format!("{what} is not text"))),
    }
}

fn name32(r: &Record, k: u64, what: &str) -> Result<Option<[u8; 32]>, String> {
    match r.get(k) {
        None => Ok(None),
        Some(v) => v
            .as_bytes()
            .and_then(|b| b.try_into().ok())
            .map(Some)
            .ok_or_else(|| bad(&format!("{what} is not 32 bytes"))),
    }
}

fn opt_bool(r: &Record, k: u64, what: &str) -> Result<bool, String> {
    match r.get(k) {
        None => Ok(false),
        Some(v) => v
            .as_bool()
            .ok_or_else(|| bad(&format!("{what} is not a boolean"))),
    }
}

fn list<'a>(r: &'a Record, k: u64, what: &str) -> Result<&'a [Value], String> {
    match r.get(k) {
        None => Ok(&[]),
        Some(v) => v
            .as_list()
            .ok_or_else(|| bad(&format!("{what} is not a list"))),
    }
}

fn place(v: &Value) -> Result<Place, String> {
    if let Some(n) = v.as_uint() {
        return Ok(if n == 0 { Place::Root } else { Place::Own(n) });
    }
    let r = v
        .as_record()
        .ok_or_else(|| bad("a place is neither a kind nor a record"))?;
    let doc = name32(r, 1, "a place's document")?.ok_or_else(|| bad("a place names no document"))?;
    let kind = r
        .get(2)
        .and_then(Value::as_uint)
        .filter(|k| *k > 0)
        .ok_or_else(|| bad("a place names no kind"))?;
    Ok(Place::Of(doc, kind))
}

fn field_def(v: &Value) -> Result<FieldDef, String> {
    let r = v.as_record().ok_or_else(|| bad("a field is not a record"))?;
    let key = r
        .get(1)
        .and_then(Value::as_uint)
        .ok_or_else(|| bad("a field has no key"))?;
    if key == 0 || key == AUTHOR_OWNED || key >= 1 << 60 {
        return Err(bad(&format!("field key {key} may not be declared")));
    }
    let name = text(r, 2, "a field's name")?.ok_or_else(|| bad("a field has no name"))?;
    let ty = r
        .get(3)
        .and_then(Value::as_uint)
        .and_then(Type::from_u64)
        .ok_or_else(|| bad(&format!("field {key} has no type of the table")))?;
    Ok(FieldDef {
        key,
        name,
        ty,
        list: opt_bool(r, 4, "a field's list")?,
    })
}

fn kind_def(v: &Value) -> Result<KindDef, String> {
    let r = v.as_record().ok_or_else(|| bad("a kind is not a record"))?;
    let kind = r
        .get(1)
        .and_then(Value::as_uint)
        .filter(|k| *k > 0)
        .ok_or_else(|| bad("a kind is not an integer from 1"))?;
    let name = text(r, 2, "a kind's name")?.ok_or_else(|| bad("a kind has no name"))?;
    let places = list(r, 3, "where a kind goes")?
        .iter()
        .map(place)
        .collect::<Result<Vec<_>, _>>()?;
    let fields = list(r, 5, "a kind's fields")?
        .iter()
        .map(field_def)
        .collect::<Result<Vec<_>, _>>()?;
    let mut keys = HashSet::new();
    if !fields.iter().all(|f| keys.insert(f.key)) {
        return Err(bad(&format!("kind {kind} declares one key twice")));
    }
    Ok(KindDef {
        kind,
        name,
        places,
        author_owned: opt_bool(r, 4, "author-owned")?,
        fields,
    })
}

impl Document {
    /// Reads a document from its bytes, and checks all that can be checked
    /// of it alone: everything but the places that name an ancestor, which
    /// [`Family`] checks.
    pub fn parse(bytes: &[u8]) -> Result<Document, String> {
        let r = Record::decode(bytes).map_err(|e| bad(&format!("{e}")))?;
        if r.get(0).and_then(Value::as_uint) != Some(DOCUMENT) {
            return Err(bad("it is not of kind 14"));
        }
        let name = name_of(bytes);
        let title = text(&r, 1, "the name")?.ok_or_else(|| bad("it has no name"))?;
        let sentence = text(&r, 2, "the sentence")?.ok_or_else(|| bad("it has no sentence"))?;
        let parent = name32(&r, 3, "the parent")?;
        let sharing = match r.get(4) {
            None => None,
            Some(v) => {
                let s = v.as_record().ok_or_else(|| bad("sharing is not a record"))?;
                let shared = opt_bool(s, 1, "shared")?;
                let role = match s.get(2) {
                    None => 0,
                    Some(v) => v
                        .as_uint()
                        .filter(|r| *r <= 1)
                        .ok_or_else(|| bad("the role is neither 0 nor 1"))?,
                };
                Some((shared, role))
            }
        };
        let kinds = list(&r, 5, "the kinds")?
            .iter()
            .map(kind_def)
            .collect::<Result<Vec<_>, _>>()?;
        if kinds.is_empty() {
            return Err(bad("it has no kinds"));
        }
        let words = text(&r, 6, "the words")?.ok_or_else(|| bad("it has no words"))?;
        if !words_ok(&words) {
            return Err(bad("its words break the rules for words"));
        }
        let translates = name32(&r, 7, "what it translates")?;
        let language = text(&r, 8, "the language")?;
        let mut seen = HashSet::new();
        if !kinds.iter().all(|k| seen.insert(k.kind)) {
            return Err(bad("two kinds have one number"));
        }
        for k in &kinds {
            for p in &k.places {
                if let Place::Own(n) = p {
                    if !seen.contains(n) {
                        return Err(bad(&format!("kind {} goes under kind {n}, which it lacks", k.kind)));
                    }
                }
                if let Place::Of(doc, _) = p {
                    if *doc == name || parent.is_none() {
                        return Err(bad("a place names a document that is not an ancestor"));
                    }
                }
            }
        }
        if parent == Some(name) {
            return Err(bad("it is its own parent"));
        }
        if translates.is_some() && (language.is_none() || parent.is_some() || sharing.is_some()) {
            return Err(bad("a translation has a language, and no parent and no sharing"));
        }
        Ok(Document {
            name,
            bytes: bytes.to_vec(),
            title,
            sentence,
            parent,
            sharing,
            kinds,
            words,
            translates,
            language,
        })
    }

    /// How a space names this document's kind `n`: the integer of a root,
    /// `BLAKE3(name || varint(n))` of a child.
    pub fn node_kind(&self, n: u64) -> NodeKind {
        match self.parent {
            None => NodeKind::Uint(n),
            Some(_) => {
                let mut h = blake3::Hasher::new();
                h.update(&self.name);
                h.update(&varint(n));
                NodeKind::Named(*h.finalize().as_bytes())
            }
        }
    }

    pub fn kind(&self, n: u64) -> Option<&KindDef> {
        self.kinds.iter().find(|k| k.kind == n)
    }

    /// Whether this is a translation of `original`: the same kinds, places,
    /// marks, keys, types and lists, and only the names differ.
    pub fn translates_well(&self, original: &Document) -> bool {
        if self.translates != Some(original.name) || original.translates.is_some() {
            return false;
        }
        let shape = |d: &Document| {
            let mut v: Vec<_> = d
                .kinds
                .iter()
                .map(|k| {
                    let mut f: Vec<_> = k.fields.iter().map(|f| (f.key, f.ty, f.list)).collect();
                    f.sort_by_key(|x| x.0);
                    (k.kind, k.places.clone(), k.author_owned, f)
                })
                .collect();
            v.sort_by_key(|x| x.0);
            v
        };
        shape(self) == shape(original)
    }
}

/// What a kind of a space is: the document that declares it, and how.
#[derive(Clone, Debug)]
pub struct Known {
    pub document: [u8; 32],
    pub def: KindDef,
    /// Where nodes of it may be, as a space names the parents' kinds;
    /// `None` for the root.
    pub under: Vec<Option<NodeKind>>,
}

/// The documents a program implements, each with its ancestors, checked
/// together: every child's parent is among them, and every place that
/// names an ancestor names one of its kinds.
#[derive(Clone, Debug, Default)]
pub struct Family {
    docs: BTreeMap<[u8; 32], Document>,
    kinds: HashMap<NodeKind, Known>,
}

impl Family {
    /// Checks `docs` together. Translations are kept apart, each checked
    /// against its original.
    pub fn new(docs: Vec<Document>) -> Result<Family, String> {
        let mut all: BTreeMap<[u8; 32], Document> = BTreeMap::new();
        let mut translations = Vec::new();
        for d in docs {
            match d.translates {
                Some(_) => translations.push(d),
                None => {
                    all.insert(d.name, d);
                }
            }
        }
        // every parent here, and no cycle
        for d in all.values() {
            let mut seen = HashSet::from([d.name]);
            let mut at = d;
            while let Some(p) = at.parent {
                at = all
                    .get(&p)
                    .ok_or_else(|| format!("{} adds to an application not given", d.title))?;
                if !seen.insert(at.name) {
                    return Err(bad("its parents go round in a circle"));
                }
            }
        }
        for t in &translations {
            let o = t.translates.expect("a translation");
            let ok = all.get(&o).is_some_and(|o| t.translates_well(o));
            if !ok {
                return Err(format!(
                    "{} is not a translation of an application given",
                    t.title
                ));
            }
        }
        let mut kinds = HashMap::new();
        for d in all.values() {
            let ancestors = ancestors(&all, d);
            for k in &d.kinds {
                let mut under = Vec::new();
                for p in &k.places {
                    under.push(match p {
                        Place::Root => None,
                        Place::Own(n) => Some(d.node_kind(*n)),
                        Place::Of(doc, n) => {
                            let a = ancestors
                                .iter()
                                .find(|a| a.name == *doc)
                                .ok_or_else(|| bad("a place names a document that is not an ancestor"))?;
                            a.kind(*n)
                                .ok_or_else(|| bad("a place names a kind its document lacks"))?;
                            Some(a.node_kind(*n))
                        }
                    });
                }
                kinds.insert(
                    d.node_kind(k.kind),
                    Known {
                        document: d.name,
                        def: k.clone(),
                        under,
                    },
                );
            }
        }
        for t in translations {
            all.insert(t.name, t);
        }
        Ok(Family { docs: all, kinds })
    }

    /// The document of this name, given.
    pub fn document(&self, name: &[u8; 32]) -> Option<&Document> {
        self.docs.get(name)
    }

    /// Every document given, translations included.
    pub fn documents(&self) -> impl Iterator<Item = &Document> {
        self.docs.values()
    }

    /// The root of the family `name` is in.
    pub fn root_of(&self, name: &[u8; 32]) -> Option<[u8; 32]> {
        let mut at = self.docs.get(name)?;
        if let Some(o) = at.translates {
            at = self.docs.get(&o)?;
        }
        while let Some(p) = at.parent {
            at = self.docs.get(&p)?;
        }
        Some(at.name)
    }

    /// What a kind is, if one of these documents declares it.
    pub fn known(&self, kind: &NodeKind) -> Option<&Known> {
        self.kinds.get(kind)
    }

    /// These documents, but only those of the families whose roots are in
    /// `roots`.
    pub fn only(&self, roots: &[[u8; 32]]) -> Family {
        let keep = |n: &[u8; 32]| self.root_of(n).is_some_and(|r| roots.contains(&r));
        Family {
            docs: self
                .docs
                .iter()
                .filter(|(n, _)| keep(n))
                .map(|(n, d)| (*n, d.clone()))
                .collect(),
            kinds: self
                .kinds
                .iter()
                .filter(|(_, k)| keep(&k.document))
                .map(|(n, k)| (*n, k.clone()))
                .collect(),
        }
    }

    /// Whether a node of the state fits these documents: its kind is
    /// declared, it is where its kind goes, and every field it holds is
    /// declared and of its type, in every value it has.
    pub fn fits(&self, state: &State, n: &Node) -> bool {
        let Some(k) = self.known(&n.kind) else {
            return false;
        };
        let parent = parent_kind(state, &n.parent);
        if parent.is_none() || !k.under.contains(&parent.expect("checked")) {
            return false;
        }
        n.fields.iter().all(|(key, values)| {
            if *key == AUTHOR_OWNED {
                return k.def.author_owned;
            }
            let Some(f) = k.def.field(*key) else {
                return false;
            };
            values
                .iter()
                .all(|v| v.value.as_ref().is_none_or(|v| f.holds(v)))
        })
    }

    /// Whether the program knows a node: its kind, and every field it holds.
    fn knows(&self, n: &Node) -> bool {
        let Some(k) = self.known(&n.kind) else {
            return false;
        };
        n.fields
            .keys()
            .all(|key| (*key == AUTHOR_OWNED && k.def.author_owned) || k.def.field(*key).is_some())
    }
}

fn ancestors<'a>(all: &'a BTreeMap<[u8; 32], Document>, d: &Document) -> Vec<&'a Document> {
    let mut out = Vec::new();
    let mut at = d.parent;
    while let Some(p) = at {
        let Some(a) = all.get(&p) else { break };
        out.push(a);
        at = a.parent;
    }
    out
}

/// The kind of the node `parent` as a place: `Some(None)` for the root,
/// `Some(Some(kind))` for a node of the state, `None` for no node.
fn parent_kind(state: &State, parent: &NodeId) -> Option<Option<NodeKind>> {
    if *parent == ROOT {
        return Some(None);
    }
    state.node(parent).map(|p| Some(p.kind))
}

/// Why the writer's service refuses an op: its place in the write, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub at: usize,
    pub why: String,
}

/// The ops a program asked for, checked against its documents
/// (`profiles.md#what-the-writers-service-checks`), as records of the
/// shared ops with ids, members and files as the space holds them; parents
/// may be the index of an earlier `create` in the same write. Answers the
/// ops to write, with field 15 set on each `create` of an author-owned
/// kind, or which op is refused and why. `me` is whoever writes, for the
/// author-owned rule.
pub fn check(
    family: &Family,
    state: &State,
    me: &[u8; 32],
    ops: &[Record],
) -> Result<Vec<Record>, Refusal> {
    let mut out = Vec::new();
    // the kinds of the nodes this write makes, by their place
    let mut made: HashMap<usize, NodeKind> = HashMap::new();
    for (at, op) in ops.iter().enumerate() {
        let no = |why: String| Refusal { at, why };
        let number = op.get(0).and_then(Value::as_uint);
        let node = || -> Result<&Node, Refusal> {
            let id: NodeId = op
                .get(1)
                .and_then(Value::as_bytes)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| no("it names no node by its id".into()))?;
            state
                .node(&id)
                .ok_or_else(|| no("there is no such node".into()))
        };
        // where a create or a move puts a node, as a place
        let place = |made: &HashMap<usize, NodeKind>| -> Result<Option<NodeKind>, Refusal> {
            match op.get(2) {
                Some(Value::Bytes(b)) => {
                    let id: NodeId = b
                        .as_slice()
                        .try_into()
                        .map_err(|_| no("a parent is 16 bytes".into()))?;
                    match parent_kind(state, &id) {
                        Some(k) => Ok(k),
                        None => Err(no("its parent is no node".into())),
                    }
                }
                Some(v) => {
                    let i = v
                        .as_uint()
                        .ok_or_else(|| no("a parent is an id or an index".into()))?;
                    made.get(&(i as usize))
                        .filter(|_| (i as usize) < at)
                        .map(|k| Some(*k))
                        .ok_or_else(|| no(format!("no create comes at {i} before it")))
                }
                None => Err(no("it has no parent".into())),
            }
        };
        let own = |n: &Node| -> Result<(), Refusal> {
            if n.author_owned() && n.creator != *me {
                return Err(no("that node is its author's own".into()));
            }
            Ok(())
        };
        match number {
            Some(32) => {
                let kind = op
                    .get(1)
                    .and_then(kind_of)
                    .ok_or_else(|| no("it has no kind".into()))?;
                let k = family
                    .known(&kind)
                    .ok_or_else(|| no("no document of this program declares its kind".into()))?;
                let p = place(&made)?;
                if !k.under.contains(&p) {
                    return Err(no(format!("a {} does not go there", k.def.name)));
                }
                if op.get(3).and_then(Value::as_text).is_none() {
                    return Err(no("it has no name".into()));
                }
                let mut fields = match op.get(4) {
                    None => Record::new(),
                    Some(v) => v
                        .as_record()
                        .cloned()
                        .ok_or_else(|| no("its fields are not a record".into()))?,
                };
                for (key, v) in fields.iter() {
                    let f = k
                        .def
                        .field(*key)
                        .ok_or_else(|| no(format!("a {} has no field {key}", k.def.name)))?;
                    if !f.holds(v) {
                        return Err(no(format!("field {key} ({}) is not of its type", f.name)));
                    }
                }
                if k.def.author_owned {
                    fields.insert(AUTHOR_OWNED, 1u64);
                }
                if op.iter().any(|(k, _)| *k > 4) {
                    return Err(no("a create here has fields 1 to 4 only".into()));
                }
                made.insert(at, kind);
                out.push(op.clone().with(4, fields));
            }
            Some(33) => {
                let n = node()?;
                if !family.knows(n) {
                    return Err(no("this program does not know that node, or a field of it".into()));
                }
                own(n)?;
                let k = family.known(&n.kind).expect("known");
                let key = op
                    .get(2)
                    .and_then(Value::as_uint)
                    .ok_or_else(|| no("it names no field".into()))?;
                let f = k
                    .def
                    .field(key)
                    .ok_or_else(|| no(format!("a {} has no field {key}", k.def.name)))?;
                if let Some(v) = op.get(3) {
                    if !f.holds(v) {
                        return Err(no(format!("field {key} ({}) is not of its type", f.name)));
                    }
                }
                if op.iter().any(|(k, _)| *k > 3) {
                    return Err(no("a set here has fields 1 to 3 only".into()));
                }
                out.push(op.clone());
            }
            Some(34) => {
                let n = node()?;
                if !family.knows(n) {
                    return Err(no("this program does not know that node, or a field of it".into()));
                }
                own(n)?;
                let k = family.known(&n.kind).expect("known");
                let p = place(&made)?;
                if !k.under.contains(&p) {
                    return Err(no(format!("a {} does not go there", k.def.name)));
                }
                if op.get(3).and_then(Value::as_text).is_none() {
                    return Err(no("it has no name".into()));
                }
                out.push(op.clone());
            }
            Some(35) | Some(36) => {
                let n = node()?;
                if family.known(&n.kind).is_none() {
                    return Err(no("this program does not know that node's kind".into()));
                }
                own(n)?;
                if op.iter().any(|(k, _)| *k > 1) {
                    return Err(no("a delete or restore here has field 1 only".into()));
                }
                out.push(op.clone());
            }
            _ => return Err(no("a program writes create, set, move, delete and restore only".into())),
        }
    }
    Ok(out)
}

fn kind_of(v: &Value) -> Option<NodeKind> {
    if let Some(n) = v.as_uint() {
        return Some(NodeKind::Uint(n));
    }
    v.as_bytes()
        .and_then(|b| b.try_into().ok())
        .map(NodeKind::Named)
}

/// `create` of a document node for `doc`, under the root.
pub fn document_node(doc: &Document) -> Record {
    Record::new()
        .with(0, 32u64)
        .with(1, DOCUMENT_NODE)
        .with(2, ROOT)
        .with(3, doc.title.as_str())
        .with(4, Record::new().with(1, doc.name).with(2, doc.bytes.clone()))
}

/// The documents a space's document nodes hold, those whose bytes are the
/// name they stand for and are no malformed document.
pub fn documents_in(state: &State) -> Vec<Document> {
    let mut out: Vec<Document> = Vec::new();
    for n in state.children(&ROOT) {
        if n.kind != NodeKind::Uint(DOCUMENT_NODE) || n.deleted {
            continue;
        }
        let name = n.field(1).and_then(Value::as_bytes);
        let bytes = n.field(2).and_then(Value::as_bytes);
        let (Some(name), Some(bytes)) = (name, bytes) else {
            continue;
        };
        if name != name_of(bytes) || out.iter().any(|d| d.name[..] == *name) {
            continue;
        }
        if let Ok(d) = Document::parse(bytes) {
            out.push(d);
        }
    }
    out
}

/// The kinds of `family`'s child documents that the ops create, and whose
/// documents the space has no document node for yet: the document nodes
/// the writer's service adds to the entry.
pub fn documents_wanted(family: &Family, state: &State, ops: &[Record]) -> Vec<Document> {
    let held: HashSet<[u8; 32]> = documents_in(state).iter().map(|d| d.name).collect();
    let mut out: Vec<Document> = Vec::new();
    for op in ops {
        if op.get(0).and_then(Value::as_uint) != Some(32) {
            continue;
        }
        let Some(k) = op.get(1).and_then(kind_of).and_then(|k| family.known(&k)) else {
            continue;
        };
        let Some(d) = family.document(&k.document) else {
            continue;
        };
        if d.parent.is_some() && !held.contains(&d.name) && !out.iter().any(|o| o.name == d.name) {
            out.push(d.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(key: u64, name: &str, ty: u64) -> Record {
        Record::new().with(1, key).with(2, name).with(3, ty)
    }

    fn doc(parent: Option<[u8; 32]>, kinds: Vec<Record>) -> Vec<u8> {
        let r = Record::new()
            .with(0, DOCUMENT)
            .with(1, "Notes")
            .with(2, "Notes, kept together")
            .with_opt(3, parent)
            .with(4, Record::new().with(1, true).with(2, 1u64))
            .with(5, Value::list(kinds.into_iter().map(Value::Record)))
            .with(6, "A note has a text.\n")
            .with(8, "en");
        r.encode()
    }

    fn note() -> Record {
        Record::new()
            .with(1, 1u64)
            .with(2, "note")
            .with(3, Value::list([Value::from(0u64)]))
            .with(5, Value::list([Value::Record(field(1, "text", 1))]))
    }

    #[test]
    fn a_document_is_named_by_its_hash_and_read_back() {
        let b = doc(None, vec![note()]);
        let d = Document::parse(&b).unwrap();
        assert_eq!(d.name, *blake3::hash(&b).as_bytes());
        assert_eq!(d.node_kind(1), NodeKind::Uint(1));
        assert_eq!(d.kind(1).unwrap().fields[0].ty, Type::Text);
    }

    #[test]
    fn malformed_documents_are_none() {
        // not canonical: a trailing byte
        let mut b = doc(None, vec![note()]);
        b.push(0);
        assert!(Document::parse(&b).is_err());
        // key 15 is the shared rules'
        let k = note().with(5, Value::list([Value::Record(field(15, "x", 1))]));
        assert!(Document::parse(&doc(None, vec![k])).is_err());
        // a type not in the table
        let k = note().with(5, Value::list([Value::Record(field(1, "x", 10))]));
        assert!(Document::parse(&doc(None, vec![k])).is_err());
        // under a kind it lacks
        let k = note().with(3, Value::list([Value::from(7u64)]));
        assert!(Document::parse(&doc(None, vec![k])).is_err());
        // two kinds of one number
        assert!(Document::parse(&doc(None, vec![note(), note()])).is_err());
        // words with two spaces, or no line feed at the end
        for w in ["a  b\n", "a b", " a\n", "a\r\n"] {
            let r = Record::decode(&doc(None, vec![note()])).unwrap().with(6, w);
            assert!(Document::parse(&r.encode()).is_err(), "{w:?}");
        }
    }

    #[test]
    fn a_child_names_its_kinds_by_its_hash_and_needs_its_parent() {
        let root = Document::parse(&doc(None, vec![note()])).unwrap();
        let tag = Record::new()
            .with(1, 1u64)
            .with(2, "tag")
            .with(
                3,
                Value::list([Value::Record(Record::new().with(1, root.name).with(2, 1u64))]),
            )
            .with(5, Value::list([Value::Record(field(1, "text", 1))]));
        let child = Document::parse(&doc(Some(root.name), vec![tag])).unwrap();
        assert!(matches!(child.node_kind(1), NodeKind::Named(_)));
        assert!(Family::new(vec![child.clone()]).is_err());
        let f = Family::new(vec![root.clone(), child.clone()]).unwrap();
        let k = f.known(&child.node_kind(1)).unwrap();
        assert_eq!(k.under, vec![Some(NodeKind::Uint(1))]);
        assert_eq!(f.root_of(&child.name), Some(root.name));
    }

    #[test]
    fn a_translation_has_the_original_s_shape() {
        let root = Document::parse(&doc(None, vec![note()])).unwrap();
        let t = |kinds: Vec<Record>| {
            let r = Record::new()
                .with(0, DOCUMENT)
                .with(1, "Notizen")
                .with(2, "Notizen")
                .with(5, Value::list(kinds.into_iter().map(Value::Record)))
                .with(6, "Eine Notiz hat einen Text.\n")
                .with(7, root.name)
                .with(8, "de");
            Document::parse(&r.encode()).unwrap()
        };
        let good = t(vec![note().with(2, "Notiz")]);
        assert!(good.translates_well(&root));
        assert!(Family::new(vec![root.clone(), good]).is_ok());
        let other = t(vec![note().with(5, Value::list([Value::Record(field(1, "t", 2))]))]);
        assert!(!other.translates_well(&root));
        assert!(Family::new(vec![root, other]).is_err());
    }
}
