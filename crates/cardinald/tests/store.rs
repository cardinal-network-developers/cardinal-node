//! What `cardinald` tells a client that starts it and has no `cardinal`
//! command: which store the data directory holds (`--store`), and its
//! removal (`--clear`). Each answers with one record in the base encoding,
//! numbered as a reply is, and nothing after it.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_cardinald");

fn cmd(home: &Path) -> Command {
    let mut c = Command::new(BIN);
    c.env("CARDINAL_HOME", home)
        .env("CARDINAL_SOCKET", home.join("control.sock"))
        .env("HOME", home);
    c
}

fn asked(home: &Path, what: &str) -> (Output, Value) {
    let out = cmd(home).arg(what).output().unwrap();
    let v = read(what, &out.stdout);
    (out, v)
}

/// What the program wrote: exactly one record, read by the table's names.
fn read(what: &str, said: &[u8]) -> Value {
    let r = cardinal_encoding::Record::decode(said)
        .unwrap_or_else(|e| panic!("not one record, and nothing after it: {said:?}: {e}"));
    assert!(r.get(0).is_some(), "key 0 is the status: {r:?}");
    cardinald::format::read_report(what, said).unwrap()
}

fn put(home: &Path, rel: &str, bytes: &[u8]) {
    let p = home.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

/// A data directory with one of everything in it, of this version.
fn full(home: &Path) {
    put(home, "device.key", b"key");
    put(home, "identity.log", b"log");
    put(home, "format", b"2\n");
    put(home, "spaces/aa/entries.log", b"entries");
    put(home, "spaces/bb/entries.log", b"entries");
    put(home, "blobs/objects/ab/cd/abcd", &[0; 10]);
    put(home, "blobs/objects/ab/ce/abce", &[0; 20]);
    put(home, "staging/1-1", &[0; 7]);
    put(home, "others/cc", b"log");
    put(home, "peers.json", b"{}");
    put(home, "local/notes/draft.txt", &[0; 5]);
    put(home, "config.toml", b"[daemon]\nname = \"here\"\n");
    put(home, "mine.txt", b"not the service's");
}

/// Every file there: its path, its length, and when it was last written.
fn everything(home: &Path) -> Vec<(PathBuf, u64, SystemTime)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, u64, SystemTime)>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let m = e.metadata().unwrap();
            if m.is_dir() {
                walk(&e.path(), out);
            } else {
                out.push((e.path(), m.len(), m.modified().unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(home, &mut out);
    out.sort();
    out
}

fn names(home: &Path) -> Vec<String> {
    let mut all: Vec<String> = std::fs::read_dir(home)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    all.sort();
    all
}

#[test]
fn it_says_which_store_is_there_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let (out, v) = asked(home, "--store");
    assert!(out.status.success());
    assert_eq!(v["store"], "empty", "{v}");
    assert_eq!(v["holds"]["identity"], false, "{v}");
    assert!(v.get("refusal").is_none(), "{v}");
    assert!(names(home).is_empty(), "asking made something");

    full(home);
    let before = everything(home);
    let (_, v) = asked(home, "--store");
    assert_eq!(v["store"], "current", "{v}");
    let holds = json!({
        "identity": true, "spaces": 2, "objects": 2, "bytes": 30, "unsaved": 1,
        "unsaved_bytes": 7, "local": 1, "local_bytes": 5, "other": true,
    });
    assert_eq!(v["holds"], holds);
    assert!(v.get("written_by").is_none(), "{v}");

    // What 0.1.13 left has no marker: an earlier version's, and said so in
    // the words the daemon refuses it with.
    std::fs::remove_file(home.join("format")).unwrap();
    let before_old = everything(home);
    assert_eq!(before_old.len(), before.len() - 1);
    for (marker, by) in [
        (None, "earlier"),
        (Some("1\n"), "earlier"),
        (Some("7\n"), "later"),
        (Some("two\n"), "another"),
    ] {
        if let Some(text) = marker {
            std::fs::write(home.join("format"), text).unwrap();
        }
        let (out, v) = asked(home, "--store");
        assert!(out.status.success(), "{marker:?}");
        assert_eq!(v["store"], "other", "{marker:?}: {v}");
        assert_eq!(v["written_by"], by, "{marker:?}: {v}");
        assert_eq!(v["holds"], holds, "{marker:?}");
        let said = v["refusal"].as_str().unwrap();
        for part in [
            &*home.display().to_string(),
            "this version cannot read it",
            "Nothing was changed",
        ] {
            assert!(said.contains(part), "{said:?} lacks {part:?}");
        }
        // and the service itself does not start on it
        let run = cmd(home).arg("--no-discovery").output().unwrap();
        assert!(!run.status.success(), "{marker:?}");
        let why = String::from_utf8_lossy(&run.stderr);
        assert!(why.contains("this version cannot read it"), "{why}");
    }
    std::fs::remove_file(home.join("format")).unwrap();
    assert_eq!(everything(home), before_old, "something was changed");
}

#[test]
fn it_clears_what_the_service_wrote_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    full(home);
    std::fs::remove_file(home.join("format")).unwrap();
    let (out, v) = asked(home, "--clear");
    assert!(out.status.success(), "{v}");
    assert_eq!(v, json!({"ok": true}));
    // The settings stay, and so does what is the person's own.
    assert_eq!(names(home), ["config.toml", "local", "mine.txt"]);
    assert!(home.join("local/notes/draft.txt").exists());
    let (_, v) = asked(home, "--store");
    assert_eq!(v["store"], "empty", "{v}");
    assert_eq!(v["holds"]["local"], 1, "{v}");
    // Again, there is nothing of another version's to remove: it says
    // so, and changes nothing.
    let (out, v) = asked(home, "--clear");
    assert!(!out.status.success(), "{v}");
    assert!(v["error"].as_str().unwrap().contains("Nothing was changed"));
    assert_eq!(names(home).len(), 3);
}

/// Nothing here asks the person first, so a store this version can read is
/// never removed this way, running or not.
#[test]
fn it_never_clears_a_store_that_works() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    full(home);
    let before = everything(home);
    let (out, v) = asked(home, "--clear");
    assert!(!out.status.success(), "{v}");
    assert_eq!(v["ok"], false, "{v}");
    let why = v["error"].as_str().unwrap();
    assert!(why.contains("Nothing was changed"), "{why}");
    assert!(why.contains("`cardinal clear`"), "{why}");
    assert_eq!(everything(home), before, "something was changed");
    let (_, v) = asked(home, "--store");
    assert_eq!(v["store"], "current", "{v}");
}

#[test]
fn it_clears_nothing_while_the_service_runs() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut child = cmd(home)
        .args(["--no-discovery", "--listen", &format!("127.0.0.1:{port}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while !home.join("control.sock").exists() {
        if start.elapsed() > Duration::from_secs(30) {
            let _ = child.kill();
            panic!("the service never started");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let (out, v) = asked(home, "--clear");
    // S11. And under another name for the directory, looking for the
    // socket where the service does not listen, so that nothing answers:
    // the directory is held, whatever it is called.
    let mut named = home.as_os_str().to_owned();
    named.push("/");
    let elsewhere = dir.path().join("elsewhere.sock");
    let kept = |home: &Path| -> Vec<(PathBuf, u64)> {
        let all = everything(home).into_iter();
        let stays = |p: &PathBuf| !p.ends_with("control.sock");
        all.filter(|(p, ..)| stays(p))
            .map(|(p, len, _)| (p, len))
            .collect()
    };
    let before = kept(home);
    let other = cmd(home)
        .env("CARDINAL_HOME", &named)
        .env("CARDINAL_SOCKET", &elsewhere)
        .arg("--clear")
        .output()
        .unwrap();
    let after = kept(home);
    let _ = child.kill();
    let _ = child.wait();
    assert!(!out.status.success(), "{v}");
    assert_eq!(v["ok"], false, "{v}");
    let why = v["error"].as_str().unwrap();
    assert!(
        why.contains("is running") && why.contains("Nothing was changed"),
        "{why}"
    );
    assert!(home.join("device.key").exists(), "its keys were removed");
    let v = read("--clear", &other.stdout);
    assert!(!other.status.success(), "{v}");
    assert_eq!(v["ok"], false, "{v}");
    let why = v["error"].as_str().unwrap();
    assert!(
        why.contains("is running") && why.contains("Nothing was changed"),
        "{why}"
    );
    // Every file that was there is there, none shorter: the service may
    // have written more meanwhile, and nothing was removed or replaced.
    for (path, len) in &before {
        let now = after.iter().find(|(p, _)| p == path);
        assert!(
            now.is_some_and(|(_, n)| n >= len),
            "{} went",
            path.display()
        );
    }
}

/// D5. `--clear` removes data this version cannot read, and nothing else:
/// nobody is asked first. A directory with no sign of Cardinal in it is
/// not that, whatever in it has a name the service would use.
#[test]
fn it_clears_nothing_where_there_is_no_store() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    put(home, "mailbox/x", b"someone's own");
    put(home, "staging/y", b"someone's own");
    put(home, "peers.json", b"someone's own");
    put(home, "blobs/tmp/z", b"someone's own");
    let before = everything(home);
    let (_, v) = asked(home, "--store");
    assert_eq!(v["store"], "empty", "{v}");
    let (out, v) = asked(home, "--clear");
    assert!(!out.status.success(), "{v}");
    assert_eq!(v["ok"], false, "{v}");
    let why = v["error"].as_str().unwrap();
    assert!(why.contains("Nothing was changed"), "{why}");
    assert_eq!(everything(home), before, "something was removed");
    // Nor in a directory that is not there, which stays not there.
    let none = home.join("none");
    let (out, v) = asked(&none, "--clear");
    assert!(!out.status.success(), "{v}");
    assert!(!none.exists());
}

/// D5. A marker that is there and cannot be read says nothing of which
/// version wrote the store. That is not "another version": the store may
/// be one that works. The service does not start on it, says that it
/// cannot tell, and does not clear it.
#[test]
fn a_marker_that_cannot_be_read_is_not_another_versions() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    full(home);
    std::fs::remove_file(home.join("format")).unwrap();
    std::fs::create_dir(home.join("format")).unwrap();
    let before = everything(home);
    let (out, v) = asked(home, "--store");
    assert!(out.status.success(), "{v}");
    assert_eq!(v["store"], "unreadable", "{v}");
    assert!(v.get("written_by").is_none(), "{v}");
    let why = v["refusal"].as_str().unwrap();
    assert!(
        why.contains("cannot tell") && why.contains("Nothing was changed"),
        "{why}"
    );
    assert!(why.contains(&*home.display().to_string()), "{why}");
    let (out, v) = asked(home, "--clear");
    assert!(!out.status.success(), "{v}");
    assert_eq!(v["ok"], false, "{v}");
    assert!(v["error"].as_str().unwrap().contains("cannot tell"), "{v}");
    let run = cmd(home).arg("--no-discovery").output().unwrap();
    assert!(!run.status.success());
    let why = String::from_utf8_lossy(&run.stderr);
    assert!(why.contains("cannot tell"), "{why}");
    assert_eq!(everything(home), before, "something was changed");
}
