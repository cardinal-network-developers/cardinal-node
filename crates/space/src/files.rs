//! The files profile (`profiles.md#files`): folders, files, and links, and
//! the view a mount shows.

use std::collections::HashMap;

use cardinal_encoding::{Record, Value};
use cardinal_identity::{EntryId, KeyId};

use crate::entry::{derived_id, IdentityId, NodeId, NodeKind, SpaceOp, SpaceOpBody};
use crate::space::Space;
use crate::state::{Node, ROOT};

/// Folder kind.
pub const FOLDER: u64 = 1;
/// File kind.
pub const FILE: u64 = 2;
/// Link kind.
pub const LINK: u64 = 3;

/// File field 1: content.
pub const FILE_CONTENT: u64 = 1;
/// File field 2: mode bits.
pub const FILE_MODE: u64 = 2;
/// File field 3: modified time (display only).
pub const FILE_MTIME: u64 = 3;
/// Link field 1: target.
pub const LINK_TARGET: u64 = 1;

/// A blob reference (`blobs.md#references`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobRef {
    /// The chunk id, or the top index id.
    pub id: [u8; 32],
    /// The key.
    pub key: [u8; 32],
    /// Total plaintext length.
    pub size: u64,
    /// 0 for a single chunk; otherwise top index level + 1.
    pub levels: u64,
}

impl BlobRef {
    /// The record form.
    pub fn to_record(&self) -> Record {
        Record::new()
            .with(1, self.id)
            .with(2, self.key)
            .with(
                3,
                Value::Int(
                    cardinal_encoding::Int::from_u64(self.size)
                        .unwrap_or(cardinal_encoding::Int::MAX),
                ),
            )
            .with(4, self.levels as u32)
    }

    /// Reads the record form.
    pub fn from_record(r: &Record) -> Option<BlobRef> {
        Some(BlobRef {
            id: r.bytes_n(1).ok()?,
            key: r.bytes_n(2).ok()?,
            size: r.uint(3).ok()?,
            levels: r.uint(4).ok()?,
        })
    }
}

/// A file's content: a blob reference, or bytes under 1 KiB.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    /// Stored as a blob.
    Blob(BlobRef),
    /// Inline bytes.
    Inline(Vec<u8>),
}

impl Content {
    /// The value form.
    pub fn to_value(&self) -> Value {
        match self {
            Content::Blob(b) => Value::Record(b.to_record()),
            Content::Inline(b) => Value::Bytes(b.clone()),
        }
    }

    /// Reads the value form.
    pub fn from_value(v: &Value) -> Option<Content> {
        match v {
            Value::Bytes(b) => Some(Content::Inline(b.clone())),
            Value::Record(r) => BlobRef::from_record(r).map(Content::Blob),
            _ => None,
        }
    }

    /// The plaintext length.
    pub fn size(&self) -> u64 {
        match self {
            Content::Blob(b) => b.size,
            Content::Inline(b) => b.len() as u64,
        }
    }
}

/// `create` of a folder.
pub fn create_folder(parent: NodeId, name: &str) -> SpaceOp {
    SpaceOp::create(NodeKind::Uint(FOLDER), parent, name, Record::new())
}

/// `create` of a file.
pub fn create_file(
    parent: NodeId,
    name: &str,
    content: &Content,
    mode: u32,
    mtime_ms: Option<u64>,
) -> SpaceOp {
    let fields = Record::new()
        .with(FILE_CONTENT, content.to_value())
        .with(FILE_MODE, mode)
        .with_opt(
            FILE_MTIME,
            mtime_ms.and_then(|t| cardinal_encoding::Int::from_u64(t).map(Value::Int)),
        );
    SpaceOp::create(NodeKind::Uint(FILE), parent, name, fields)
}

/// `create` of a symbolic link.
pub fn create_link(parent: NodeId, name: &str, target: &str) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(LINK),
        parent,
        name,
        Record::new().with(LINK_TARGET, target),
    )
}

/// `set` of a file's content (settling any conflict it descends from).
pub fn set_content(node: NodeId, content: &Content) -> SpaceOp {
    SpaceOp::set(node, FILE_CONTENT, Some(content.to_value()))
}

/// `set` of a file's mode bits.
pub fn set_mode(node: NodeId, mode: u32) -> SpaceOp {
    SpaceOp::set(node, FILE_MODE, Some(Value::from(mode)))
}

/// `set` of a file's modified time.
pub fn set_mtime(node: NodeId, mtime_ms: u64) -> SpaceOp {
    SpaceOp::set(
        node,
        FILE_MTIME,
        cardinal_encoding::Int::from_u64(mtime_ms).map(Value::Int),
    )
}

/// The node id a `create` at position `index` of entry `entry` makes.
pub fn created_node(entry: &EntryId, index: usize) -> NodeId {
    derived_id(entry, index)
}

/// What a node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    /// A folder.
    Folder,
    /// A file.
    File,
    /// A symbolic link.
    Link,
    /// Something this profile does not define.
    Other,
}

impl FileKind {
    fn of(k: NodeKind) -> FileKind {
        match k {
            NodeKind::Uint(FOLDER) => FileKind::Folder,
            NodeKind::Uint(FILE) => FileKind::File,
            NodeKind::Uint(LINK) => FileKind::Link,
            _ => FileKind::Other,
        }
    }
}

/// One version of a field value, with who wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    /// The content (`None` if cleared or unreadable).
    pub content: Option<Content>,
    /// The entry that wrote it.
    pub entry: EntryId,
    /// The author identity.
    pub author: IdentityId,
    /// The device key that signed it.
    pub device: KeyId,
    /// The author's clock, display only.
    pub time: Option<u64>,
}

/// One name in a folder listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// The name to show, disambiguated.
    pub name: String,
    /// The node.
    pub node: NodeId,
    /// Its kind.
    pub kind: FileKind,
    /// For a conflict copy, the version it shows.
    pub conflict_version: Option<EntryId>,
}

/// What `stat` reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stat {
    /// The node.
    pub node: NodeId,
    /// Its kind.
    pub kind: FileKind,
    /// Its name.
    pub name: String,
    /// Its parent.
    pub parent: NodeId,
    /// Content size of the main version.
    pub size: Option<u64>,
    /// Mode bits, if settled.
    pub mode: Option<u64>,
    /// Modified time, if settled.
    pub mtime: Option<u64>,
    /// Number of content versions (more than one is a conflict).
    pub versions: usize,
    /// Someone deleted it while someone else was still changing it.
    pub delete_conflict: bool,
    /// Link target.
    pub target: Option<String>,
}

/// One change to a node.
#[derive(Clone, Debug, PartialEq)]
pub struct HistoryItem {
    /// The entry.
    pub entry: EntryId,
    /// The author identity.
    pub author: IdentityId,
    /// The device key that signed it.
    pub device: KeyId,
    /// The author's clock, display only.
    pub time: Option<u64>,
    /// The op.
    pub op: SpaceOpBody,
}

/// A path resolved to a node, or to one version of a file in conflict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// The node.
    pub node: NodeId,
    /// For a conflict copy, the version it names.
    pub version: Option<EntryId>,
}

fn split_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    }
}

/// The files view of a space.
pub struct Files<'a> {
    space: &'a Space,
    device_name: Box<dyn Fn(&KeyId) -> String + 'a>,
}

impl<'a> Files<'a> {
    /// The view, naming devices by the start of their key.
    pub fn new(space: &'a Space) -> Files<'a> {
        Files {
            space,
            device_name: Box::new(crate::account::short_key),
        }
    }

    /// The view, naming devices with `name` (normally from the account
    /// space, [`crate::account::device_name`]).
    pub fn with_device_names(space: &'a Space, name: impl Fn(&KeyId) -> String + 'a) -> Files<'a> {
        Files {
            space,
            device_name: Box::new(name),
        }
    }

    fn version(&self, entry: &EntryId, value: Option<&Value>) -> Version {
        let e = self.space.entry(entry);
        Version {
            content: value.and_then(Content::from_value),
            entry: *entry,
            author: e.map(|e| e.author()).unwrap_or_default(),
            device: e.map(|e| e.signer()).unwrap_or_default(),
            time: e.and_then(|e| e.time()),
        }
    }

    /// The content versions of a file, in log order of the entries that
    /// wrote them; the last is the one shown under the file's own name.
    pub fn content(&self, node: &NodeId) -> Vec<Version> {
        let Some(n) = self.space.state().node(node) else {
            return Vec::new();
        };
        let mut vs: Vec<Version> = n
            .values(FILE_CONTENT)
            .iter()
            .map(|v| self.version(&v.entry, v.value.as_ref()))
            .collect();
        let dag = self.space.dag();
        vs.sort_by_key(|v| dag.position(&v.entry));
        vs
    }

    /// The visible children of a folder, with display names: duplicates as
    /// `name (2)`, and each other version of a file in conflict as
    /// `name (conflict, <device>).ext`.
    pub fn list(&self, dir: &NodeId) -> Vec<DirEntry> {
        let st = self.space.state();
        let dag = self.space.dag();
        let mut kids: Vec<&Node> = st
            .children(dir)
            .into_iter()
            .filter(|n| !n.deleted)
            .collect();
        kids.sort_by_key(|n| (n.name.clone(), dag.position(&n.created_in), n.id));
        let mut seen: HashMap<&str, usize> = HashMap::new();
        let mut out = Vec::new();
        for n in kids {
            let k = seen.entry(n.name.as_str()).or_insert(0);
            *k += 1;
            let name = if *k == 1 {
                n.name.clone()
            } else {
                let (stem, ext) = split_ext(&n.name);
                format!("{stem} ({k}){ext}")
            };
            let kind = FileKind::of(n.kind);
            if kind == FileKind::File {
                let versions = self.content(&n.id);
                for v in versions.iter().rev().skip(1) {
                    let (stem, ext) = split_ext(&name);
                    out.push(DirEntry {
                        name: format!("{stem} (conflict, {}){ext}", (self.device_name)(&v.device)),
                        node: n.id,
                        kind,
                        conflict_version: Some(v.entry),
                    });
                }
            }
            out.push(DirEntry {
                name,
                node: n.id,
                kind,
                conflict_version: None,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Resolves a `/`-separated path of display names.
    pub fn resolve(&self, path: &str) -> Option<Resolved> {
        let mut cur = Resolved {
            node: ROOT,
            version: None,
        };
        for part in path.split('/').filter(|p| !p.is_empty()) {
            if cur.version.is_some() {
                return None;
            }
            let e = self.list(&cur.node).into_iter().find(|e| e.name == part)?;
            cur = Resolved {
                node: e.node,
                version: e.conflict_version,
            };
        }
        Some(cur)
    }

    /// The listing of the folder at `path`.
    pub fn list_path(&self, path: &str) -> Option<Vec<DirEntry>> {
        let r = self.resolve(path)?;
        if r.version.is_some() {
            return None;
        }
        Some(self.list(&r.node))
    }

    /// Facts about a node.
    pub fn stat(&self, node: &NodeId) -> Option<Stat> {
        let n = self.space.state().node(node)?;
        let versions = self.content(node);
        Some(Stat {
            node: n.id,
            kind: FileKind::of(n.kind),
            name: n.name.clone(),
            parent: n.parent,
            size: versions
                .last()
                .and_then(|v| v.content.as_ref())
                .map(Content::size),
            mode: n.field(FILE_MODE).and_then(|v| v.as_uint()),
            mtime: n.field(FILE_MTIME).and_then(|v| v.as_uint()),
            versions: versions.len(),
            delete_conflict: n.delete_conflict,
            target: if n.kind == NodeKind::Uint(LINK) {
                n.field(LINK_TARGET)
                    .and_then(|v| v.as_text())
                    .map(str::to_owned)
            } else {
                None
            },
        })
    }

    /// Every change to a node by an accepted entry, in log order.
    pub fn history(&self, node: &NodeId) -> Vec<HistoryItem> {
        let st = self.space.state();
        let mut out = Vec::new();
        for id in st.applied() {
            let e = self.space.entry(id).expect("entry");
            for (i, op) in e.ops().iter().enumerate() {
                let hit = match op.body() {
                    SpaceOpBody::Create { .. } => derived_id(id, i) == *node,
                    SpaceOpBody::Set { node: n, .. }
                    | SpaceOpBody::Move { node: n, .. }
                    | SpaceOpBody::Delete { node: n }
                    | SpaceOpBody::Restore { node: n } => n == node,
                    _ => false,
                };
                if hit {
                    out.push(HistoryItem {
                        entry: *id,
                        author: e.author(),
                        device: e.signer(),
                        time: e.time(),
                        op: op.body().clone(),
                    });
                }
            }
        }
        out
    }
}
