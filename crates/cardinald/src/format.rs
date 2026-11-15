//! The store says which format it is.
//!
//! A change to what an id covers, or to what an entry holds, leaves old
//! entries that verify under no current rule. A device that opened such a
//! store would find nothing valid in it, show nothing, and keep every
//! object, because nothing it could read names them. So the data directory
//! holds a marker, the file `format`: one decimal number and a newline. It
//! is written when a store is made, and a store with another number, or
//! with none, is refused before anything in it is read or written.
//!
//! A directory that holds an identity, a space or an object and has no
//! marker is format 1: what 0.1.13 and earlier wrote.

use std::path::{Path, PathBuf};

use crate::paths::Paths;

/// The format this build writes and expects.
pub const FORMAT: u64 = 2;

/// What a data directory holds, as far as its format goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Store {
    /// Nothing yet: no marker, and no identity, space or object.
    Empty,
    /// A store of this build's format.
    Current,
    /// A store of another format: its number, if the marker gives one.
    Other(Option<u64>),
    /// A marker is there and cannot be read, so nothing says which format
    /// the store is. It may be one that works: nothing opens it, and
    /// nothing removes it without asking.
    Unreadable,
}

/// The marker's path.
pub fn marker(paths: &Paths) -> PathBuf {
    paths.home.join("format")
}

/// Whether a directory holds any regular file, at any depth.
fn holds_a_file(dir: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return false;
    };
    rd.flatten().any(|e| match e.file_type() {
        Ok(t) if t.is_dir() => holds_a_file(&e.path()),
        Ok(_) => true,
        Err(_) => false,
    })
}

/// Whether a data directory holds an identity, a space or an object.
pub fn holds_something(paths: &Paths) -> bool {
    let identity = std::fs::metadata(paths.identity_log()).is_ok_and(|m| m.len() > 0);
    let space = std::fs::read_dir(paths.spaces()).is_ok_and(|mut rd| rd.next().is_some());
    identity || space || holds_a_file(&paths.blobs().join("objects"))
}

/// Which format a data directory is, from its marker and from whether
/// anything is there. Nothing in the store itself is read.
pub fn of(paths: &Paths) -> Store {
    match std::fs::read_to_string(marker(paths)) {
        Ok(text) => match text.trim().parse::<u64>() {
            Ok(FORMAT) => Store::Current,
            Ok(n) => Store::Other(Some(n)),
            Err(_) => Store::Other(None),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if holds_something(paths) {
                Store::Other(Some(1))
            } else {
                Store::Empty
            }
        }
        // a marker that is there and cannot be read says nothing at all
        Err(_) => Store::Unreadable,
    }
}

/// Whether a data directory holds what the service's program may remove
/// without asking anyone: a store of another format, with an identity, a
/// space or an object to show that it is one. Not an empty directory,
/// where whatever has a name the service would use is somebody else's;
/// not a store this version reads; and not one whose marker cannot be
/// read, which may be either.
pub fn removable_unasked(paths: &Paths) -> bool {
    matches!(of(paths), Store::Other(_)) && holds_something(paths)
}

/// What to tell a person whose data directory has a marker that cannot be
/// read.
pub fn cannot_tell(home: &Path) -> String {
    format!(
        "Cardinal cannot tell which version wrote the data in {}: its `format` file is there \
         and cannot be read. Nothing was changed. Look at that file; `cardinal clear` removes \
         the data, and asks first.",
        home.display()
    )
}

/// Which version wrote a store of another format, as far as its marker
/// says: `earlier`, `later`, or `another`. For a client that says it in
/// its own words.
pub fn written_by(format: Option<u64>) -> &'static str {
    match format {
        Some(n) if n < FORMAT => "earlier",
        Some(_) => "later",
        None => "another",
    }
}

/// What a data directory holds, for a window to read when no service
/// answers there: which `store` (`empty`, `current`, `other`, or
/// `unreadable` where a marker is there and cannot be read), what it
/// `holds`, counted without reading any of it, and of another version's
/// who it was `written_by` and the `refusal` in words. `cardinal store`
/// and `cardinald --store` both print this, as one line.
pub fn says(paths: &Paths) -> serde_json::Value {
    let found = crate::clear::found(paths);
    let mut out = serde_json::json!({
        "store": "current",
        "holds": {
            "identity": found.identity,
            "spaces": found.spaces,
            "objects": found.objects.0,
            "bytes": found.objects.1,
            "unsaved": found.staged.0,
            "unsaved_bytes": found.staged.1,
            "local": found.local.0,
            "local_bytes": found.local.1,
            "other": found.other,
        },
    });
    match of(paths) {
        Store::Current => {}
        Store::Empty => out["store"] = serde_json::json!("empty"),
        Store::Other(n) => {
            out["store"] = serde_json::json!("other");
            out["written_by"] = serde_json::json!(written_by(n));
            out["refusal"] = serde_json::json!(refusal(&paths.home, n));
        }
        Store::Unreadable => {
            out["store"] = serde_json::json!("unreadable");
            out["refusal"] = serde_json::json!(cannot_tell(&paths.home));
        }
    }
    out
}

/// What to tell a person whose data directory this version cannot read:
/// which directory, who wrote it, that nothing was changed, and the two
/// things they can do.
pub fn refusal(home: &Path, format: Option<u64>) -> String {
    let by = match format {
        Some(n) if n < FORMAT => "an earlier version",
        Some(_) => "a later version",
        None => "another version",
    };
    format!(
        "The Cardinal data in {} was written by {by} of Cardinal, and this version cannot \
         read it. Nothing was changed. You can keep running the version that wrote it. Or \
         copy out the files you want with that version, then run `cardinal clear` and \
         `cardinal init` with this one to start again.",
        home.display()
    )
}

/// Refuses a store of another format, in plain words. To be called before
/// anything in the data directory is read or written.
pub fn check(paths: &Paths) -> anyhow::Result<()> {
    match of(paths) {
        Store::Empty | Store::Current => Ok(()),
        Store::Other(format) => anyhow::bail!("{}", refusal(&paths.home, format)),
        Store::Unreadable => anyhow::bail!("{}", cannot_tell(&paths.home)),
    }
}

/// Writes the marker: whatever makes a store calls this first.
pub fn write(paths: &Paths) -> std::io::Result<()> {
    std::fs::create_dir_all(&paths.home)?;
    crate::paths::write_private(&marker(paths), format!("{FORMAT}\n").as_bytes(), 0o600)?;
    // The name is as much a part of the marker as its bytes: a power cut
    // after set-up must not keep the identity and lose the marker, which
    // would make the store another version's.
    #[cfg(unix)]
    std::fs::File::open(&paths.home)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(dir: &tempfile::TempDir) -> Paths {
        Paths::at(dir.path())
    }

    #[test]
    fn an_empty_directory_is_no_store_yet() {
        let dir = tempfile::tempdir().unwrap();
        let paths = at(&dir);
        assert_eq!(of(&paths), Store::Empty);
        assert!(check(&paths).is_ok());
        // what a daemon makes before anyone is set up is not a store
        std::fs::write(paths.device_key(), b"{}").unwrap();
        std::fs::create_dir_all(paths.blobs().join("objects/ab/cd")).unwrap();
        std::fs::create_dir_all(paths.blobs().join("tmp")).unwrap();
        std::fs::create_dir_all(paths.spaces()).unwrap();
        std::fs::write(paths.identity_log(), b"").unwrap();
        assert_eq!(of(&paths), Store::Empty);
        // a directory that is not there is not one either
        assert_eq!(of(&Paths::at(&dir.path().join("none"))), Store::Empty);
    }

    #[test]
    fn the_marker_is_one_number_and_a_newline() {
        let dir = tempfile::tempdir().unwrap();
        let paths = at(&dir);
        write(&paths).unwrap();
        assert_eq!(std::fs::read(marker(&paths)).unwrap(), b"2\n");
        assert_eq!(of(&paths), Store::Current);
        assert!(check(&paths).is_ok());
    }

    #[test]
    fn what_holds_something_and_no_marker_is_format_one() {
        type Make = fn(&Paths);
        let made: [(&str, Make); 3] = [
            ("an identity", |p| {
                std::fs::write(p.identity_log(), b"x").unwrap()
            }),
            ("a space", |p| {
                std::fs::create_dir_all(p.spaces().join("00")).unwrap()
            }),
            ("an object", |p| {
                let dir = p.blobs().join("objects/ab/cd");
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join("abcd"), b"x").unwrap();
            }),
        ];
        for (what, make) in made {
            let dir = tempfile::tempdir().unwrap();
            let paths = at(&dir);
            make(&paths);
            assert_eq!(of(&paths), Store::Other(Some(1)), "{what}");
            let said = check(&paths).unwrap_err().to_string();
            // which directory, who wrote it, that this version cannot read
            // it, that nothing was changed, and the two things to do
            for part in [
                &*dir.path().display().to_string(),
                "an earlier version",
                "this version cannot read it",
                "Nothing was changed",
                "keep running the version that wrote it",
                "copy out the files you want with that version",
                "`cardinal clear`",
                "`cardinal init`",
            ] {
                assert!(said.contains(part), "{what}: {said:?} lacks {part:?}");
            }
            // with the marker it is this build's
            write(&paths).unwrap();
            assert_eq!(of(&paths), Store::Current, "{what}");
        }
    }

    #[test]
    fn another_number_is_another_format() {
        let dir = tempfile::tempdir().unwrap();
        let paths = at(&dir);
        for (text, found, by) in [
            ("1\n", Store::Other(Some(1)), "an earlier version"),
            ("3\n", Store::Other(Some(3)), "a later version"),
            ("12", Store::Other(Some(12)), "a later version"),
            ("two\n", Store::Other(None), "another version"),
            ("", Store::Other(None), "another version"),
        ] {
            std::fs::write(marker(&paths), text).unwrap();
            assert_eq!(of(&paths), found, "{text:?}");
            let said = check(&paths).unwrap_err().to_string();
            assert!(said.contains(by), "{text:?}: {said}");
            // and a client is told the same of it
            let Store::Other(n) = found else {
                unreachable!()
            };
            assert!(by.contains(written_by(n)), "{text:?}: {by}");
        }
    }
}
