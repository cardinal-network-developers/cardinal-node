//! Who the person says they are, and what they call others (D71,
//! `profiles.md#account`).
//!
//! The name a person suggests for themselves is the account's self node,
//! not this device's name: invitations, the hello, introductions and groups
//! carry it. An account made before there was one has none until its
//! person sets their name, and until then this device's name is suggested,
//! as it always was.
//!
//! A contact's picture is this person's own: a copy of a file, kept as a
//! blob in the account space. Windows are given a file on this device to
//! open: [`start`] keeps one under the data directory for each picture.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use cardinal_blob::{BlobReader, BlobRef, NoFetch};
use cardinal_encoding::Value;
use cardinal_link::Priority;
use cardinal_space::account::{self, ContactRecord};
use serde_json::{json, Value as Json};

use crate::daemon::Daemon;
use crate::fetch::Fetcher;

/// The most a picture may be. It is copied whole into the account space,
/// which every device of the person keeps, so a photo straight from a
/// camera is about the most it is for.
const PICTURE_AT_MOST: u64 = 16 << 20;

/// The name the person suggests for themselves: the self node's, or, for
/// an account made before there was one, this device's name.
pub fn my_name(d: &Daemon) -> String {
    let set = d.core().self_name();
    set.unwrap_or_else(|| d.config().name.clone())
}

/// `me`: the name the person suggests for themselves, and with `name`
/// sets it, creating the self node where the account has none.
pub fn me(d: &Arc<Daemon>, name: Option<&str>) -> anyhow::Result<Json> {
    let Some(name) = name else {
        let set = d.core().self_name();
        let name = my_name(d);
        return Ok(json!({"name": name, "set": set.is_some()}));
    };
    let name = name.trim();
    anyhow::ensure!(!name.is_empty(), "a name cannot be empty");
    anyhow::ensure!(!name.contains('\n'), "a name is one line");
    let (acc, node) = {
        let core = d.core();
        let acc = core
            .account_id()
            .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
        let st = core
            .account()
            .and_then(|a| a.space.as_ref())
            .map(|s| s.state());
        (acc, st.and_then(account::self_node).map(|(n, _)| n))
    };
    let op = match node {
        Some(node) => account::set_field(node, 1, name),
        None => account::create_self(name),
    };
    d.write_and_push(&acc, vec![op])?;
    Ok(json!({"name": name, "set": true}))
}

/// What a window is given of a contact's name and picture: `name`, the
/// petname or else the name they suggest; `own`, whether it is this
/// person's petname; `suggested`; and `picture`, a file on this device,
/// where there is one and it is here.
pub fn shown(d: &Daemon, c: &ContactRecord) -> serde_json::Map<String, Json> {
    let mut m = serde_json::Map::new();
    m.insert("name".into(), json!(c.petname));
    m.insert("own".into(), json!(c.own));
    m.insert("suggested".into(), json!(c.suggested));
    if let Some(p) = c.picture.as_ref().and_then(|r| cached(d, r)) {
        m.insert("picture".into(), json!(p.display().to_string()));
    }
    m
}

/// Adds [`shown`] to an object describing a contact.
pub fn with_shown(d: &Daemon, c: &ContactRecord, mut v: Json) -> Json {
    if let Some(o) = v.as_object_mut() {
        o.extend(shown(d, c));
    }
    v
}

/// Endings of the files pictures are kept in, by what their bytes say.
const ENDINGS: [&str; 5] = ["jpg", "png", "gif", "webp", "img"];

fn ending(head: &[u8]) -> &'static str {
    if head.starts_with(&[0xff, 0xd8, 0xff]) {
        "jpg"
    } else if head.starts_with(b"\x89PNG") {
        "png"
    } else if head.starts_with(b"GIF8") {
        "gif"
    } else if head.len() >= 12 && &head[..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        "webp"
    } else {
        "img"
    }
}

/// The file on this device that holds a picture, if it is here.
fn cached(d: &Daemon, picture: &cardinal_encoding::Record) -> Option<PathBuf> {
    let b = BlobRef::from_record(picture).ok()?;
    let base = d.paths.pictures().join(hex::encode(b.id));
    ENDINGS
        .iter()
        .map(|e| base.with_extension(e))
        .find(|p| p.is_file())
}

/// Writes a picture out to its file, fetching from this person's devices
/// what is not here, with `fetch`.
fn write_cache<F: cardinal_blob::Fetch>(d: &Daemon, b: BlobRef, fetch: &F) -> anyhow::Result<()> {
    let dir = d.paths.pictures();
    std::fs::create_dir_all(&dir)?;
    let base = dir.join(hex::encode(b.id));
    let part = base.with_extension("part");
    let _ = std::fs::remove_file(&part);
    let mut out = std::fs::File::create(&part)?;
    let mut reader = BlobReader::new(&*d.store, fetch, b);
    let wrote = crate::contacts::write_out(&mut reader, &mut out);
    drop(out);
    if let Err(e) = wrote {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    let mut head = [0u8; 12];
    let n = {
        use std::io::Read;
        let mut f = std::fs::File::open(&part)?;
        f.read(&mut head)?
    };
    std::fs::rename(&part, base.with_extension(ending(&head[..n])))?;
    Ok(())
}

/// Sets this person's picture for a contact from a file: one of the one
/// folder, such as `People/Ana/beach.jpg`, or one on this device's disk.
/// It is copied into the account space, so it stays as it was whatever
/// happens to the file. An empty `from` clears it.
pub async fn set_picture(d: &Arc<Daemon>, who: &str, from: &str) -> anyhow::Result<Json> {
    let contact = crate::contacts::find(d, who)?;
    let acc = d
        .core()
        .account_id()
        .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
    let from = from.trim();
    if from.is_empty() {
        let op = cardinal_space::SpaceOp::set(contact.node, account::PICTURE, None);
        d.write_and_push(&acc, vec![op])?;
        return Ok(json!({"picture": null}));
    }
    // A file of the one folder is saved out first; one on the disk is read
    // where it is.
    let on_disk = Path::new(from);
    let (path, saved) = if on_disk.is_absolute() && on_disk.is_file() {
        (on_disk.to_path_buf(), false)
    } else {
        let dir = d.paths.pictures();
        std::fs::create_dir_all(&dir)?;
        let r: [u8; 8] = cardinal_crypto::random_bytes();
        let tmp = dir.join(format!("incoming-{}", hex::encode(r)));
        let to = tmp.display().to_string();
        crate::onefolder::save(d, from, &to)
            .await
            .map_err(|e| anyhow::anyhow!("{from} is not a file here: {e:#}"))?;
        (tmp, true)
    };
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let encoded = if size > PICTURE_AT_MOST {
        Err(anyhow::anyhow!(
            "that file is too big for a picture ({} MB at most)",
            PICTURE_AT_MOST >> 20
        ))
    } else {
        let paths = [path.display().to_string()];
        crate::contacts::encode_attachments(d, &acc, &paths).await
    };
    if saved {
        let _ = std::fs::remove_file(&path);
    }
    let attached = encoded?
        .pop()
        .ok_or_else(|| anyhow::anyhow!("nothing was read"))?;
    let blob = BlobRef::from_record(&attached.blob)?;
    let d2 = d.clone();
    tokio::task::spawn_blocking(move || write_cache(&d2, blob, &NoFetch)).await??;
    let op = account::set_field(contact.node, account::PICTURE, Value::Record(attached.blob));
    d.write_and_push(&acc, vec![op])?;
    let c = crate::contacts::find(d, who).unwrap_or(contact);
    Ok(Json::Object(shown(d, &c)))
}

/// Keeps a file on this device for each contact's picture, fetching it
/// from this person's other devices, and tells windows when one arrives.
pub fn start(d: Arc<Daemon>) {
    tokio::spawn(async move {
        let mut changed = d.changed.subscribe();
        loop {
            let missing: Vec<BlobRef> = {
                let contacts = d.core().contacts();
                contacts
                    .iter()
                    .filter_map(|c| c.picture.as_ref())
                    .filter(|r| cached(&d, r).is_none())
                    .filter_map(|r| BlobRef::from_record(r).ok())
                    .collect()
            };
            let mut got = false;
            for b in missing {
                let d2 = d.clone();
                let done = tokio::task::spawn_blocking(move || {
                    let fetcher = Fetcher::new(&d2, Priority::Interactive);
                    write_cache(&d2, b, &fetcher)
                })
                .await;
                match done {
                    Ok(Ok(())) => got = true,
                    Ok(Err(e)) => tracing::debug!("fetching a picture: {e:#}"),
                    Err(e) => tracing::debug!("fetching a picture: {e}"),
                }
            }
            if got {
                d.bump();
                // the change this makes is this task's own
                changed.borrow_and_update();
            }
            if *d.stopping.borrow() {
                return;
            }
            let wait = tokio::time::sleep(Duration::from_secs(30));
            tokio::select! {
                r = changed.changed() => if r.is_err() { return },
                _ = wait => {}
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    });
}
