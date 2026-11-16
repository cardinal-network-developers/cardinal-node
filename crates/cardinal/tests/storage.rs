//! What a data directory says of itself, and what is taken out of one: the
//! format marker (`format.rs`), `cardinal clear` (`clear.rs`), and the
//! objects that nothing names (`cleanup.rs`).
//!
//! Every daemon and command here runs on a directory of its own under a
//! temporary one, without a mount.

mod common;

use common::*;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

fn content(len: usize, seed: u64) -> Vec<u8> {
    let mut x: u64 = 0x9e3779b97f4a7c15 ^ seed;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Someone set up on one device, with a file in their folder.
fn set_up(root: &Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    // nothing is too new to count
    d.env
        .push(("CARDINAL_TEST_FREE_MIN_AGE_MS".into(), "0".into()));
    d.start_with(&["--no-mount"]);
    assert!(!d.home.join("format").exists(), "a marker before a store");
    d.cli(&["init", "--yes", "--name", name]);
    let file = root.join(format!("{name}-film.bin"));
    std::fs::write(&file, content(3 << 20, 7)).unwrap();
    d.cli(&["put", &file.display().to_string()]);
    d.cli(&["flush"]);
    d
}

/// Every file in a data directory but the test's own log and the control
/// socket: its path, its length, and when it was last written.
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
    out.retain(|(p, _, _)| !p.ends_with("daemon.log") && !p.ends_with("control.sock"));
    out.sort();
    out
}

fn names(home: &Path) -> Vec<String> {
    let mut all: Vec<String> = std::fs::read_dir(home)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "daemon.log" && n != "control.sock")
        .collect();
    all.sort();
    all
}

/// Runs the daemon on a directory it must refuse, and returns what it said.
fn refused_daemon(d: &Dev) -> String {
    let mut child = d
        .cmd()
        .args(["daemon", "--no-discovery", "--no-mount", "--listen"])
        .arg(format!("127.0.0.1:{}", d.port))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            panic!("the daemon ran on a store it cannot read");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success());
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn said(o: &std::process::Output) -> String {
    let (out, err) = (&o.stdout, &o.stderr);
    format!(
        "{}{}",
        String::from_utf8_lossy(out),
        String::from_utf8_lossy(err)
    )
}

/// In plain words: which directory, that an earlier version wrote it, that
/// this version cannot read it, that nothing was changed, and the two
/// things a person can do.
fn says_it_all(text: &str, home: &Path, by: &str) {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    for part in [
        &*home.display().to_string(),
        by,
        "this version cannot read it",
        "Nothing was changed",
        "keep running the version that wrote it",
        "copy out the files you want with that version",
        "`cardinal clear`",
        "`cardinal init`",
    ] {
        assert!(flat.contains(part), "{flat:?} lacks {part:?}");
    }
}

#[test]
fn a_store_of_another_format_is_refused_whole_and_can_be_cleared() {
    let root = tempfile::tempdir().unwrap();
    let mut ana = set_up(root.path(), "ana");
    // Whatever makes a store writes the marker: one number and a newline.
    assert_eq!(std::fs::read(ana.home.join("format")).unwrap(), b"2\n");
    assert!(ana.cli(&["files"]).contains("ana-film.bin"));
    ana.stop();

    // What 0.1.13 left: an identity, spaces and objects, and no marker.
    std::fs::remove_file(ana.home.join("format")).unwrap();
    let before = everything(&ana.home);
    assert!(before.len() > 5);
    says_it_all(&refused_daemon(&ana), &ana.home, "an earlier version");
    // Each command says the same, and not only that no daemon is running.
    for args in [&["status"][..], &["files"], &["init", "--yes"]] {
        let o = ana.try_cli(args);
        assert!(!o.status.success(), "{args:?}");
        says_it_all(&said(&o), &ana.home, "an earlier version");
        assert!(!said(&o).contains("not running"), "{args:?}");
    }
    assert_eq!(everything(&ana.home), before, "something was changed");
    // One command answers all the same, for a window to read: one line of
    // JSON saying which store is here and why it is refused.
    let line = ana.cli(&["store"]);
    assert_eq!(line.lines().count(), 1, "{line:?}");
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["store"], "other", "{v}");
    assert_eq!(v["written_by"], "earlier", "{v}");
    assert!(v["holds"]["spaces"].as_u64().unwrap() > 0, "{v}");
    says_it_all(
        v["refusal"].as_str().unwrap(),
        &ana.home,
        "an earlier version",
    );
    assert_eq!(everything(&ana.home), before, "something was changed");
    // One from a version yet to come is refused as surely.
    std::fs::write(ana.home.join("format"), "7\n").unwrap();
    says_it_all(&refused_daemon(&ana), &ana.home, "a later version");
    says_it_all(
        &said(&ana.try_cli(&["status"])),
        &ana.home,
        "a later version",
    );
    std::fs::remove_file(ana.home.join("format")).unwrap();
    assert_eq!(everything(&ana.home), before, "something was changed");

    // `cardinal clear` says what is there first, and without the word
    // removes nothing.
    let dry = ana.cli(&["clear", "--dry-run"]);
    for part in [
        &*ana.home.display().to_string(),
        "this device's keys",
        "2 spaces",
        "objects (",
        "It leaves your settings",
        "Nothing was removed.",
    ] {
        assert!(dry.contains(part), "{dry:?} lacks {part:?}");
    }
    assert_eq!(everything(&ana.home), before);
    // not even told not to ask
    let dry = ana.cli(&["clear", "--dry-run", "--yes", "--including-local"]);
    assert!(dry.contains("Nothing was removed."), "{dry}");
    assert_eq!(everything(&ana.home), before);
    let o = ana.cli_input(&["clear"], "yes\n");
    assert!(said(&o).contains("Nothing was removed."), "{}", said(&o));
    assert_eq!(everything(&ana.home), before);
    let o = ana.cli_input(&["clear"], "clear\n");
    assert!(
        o.status.success() && said(&o).contains("Removed."),
        "{}",
        said(&o)
    );
    assert_eq!(names(&ana.home), ["config.toml"]);
    let o = ana.try_cli(&["clear", "--yes"]);
    assert!(
        said(&o).contains("nothing of Cardinal's to remove"),
        "{}",
        said(&o)
    );

    // And a device is set up there again.
    ana.start_with(&["--no-mount"]);
    ana.cli(&["init", "--yes", "--name", "ana again"]);
    assert_eq!(std::fs::read(ana.home.join("format")).unwrap(), b"2\n");
    assert!(!ana.cli(&["files"]).contains("ana-film.bin"));
    assert!(ana.status()["identity"].is_string());
    ana.stop();
    // It starts again on what it made.
    ana.start_with(&["--no-mount"]);
    assert!(ana.status()["identity"].is_string());
}

#[test]
fn clear_waits_for_the_daemon_to_stop_and_leaves_what_is_the_persons_own() {
    let root = tempfile::tempdir().unwrap();
    let mut ana = set_up(root.path(), "ana");
    // Files kept on this device only: they exist nowhere else.
    std::fs::create_dir_all(ana.home.join("local/notes")).unwrap();
    std::fs::write(ana.home.join("local/notes/draft.txt"), b"mine").unwrap();
    std::fs::create_dir_all(ana.home.join("local-shared/Bo")).unwrap();
    std::fs::write(ana.home.join("local-shared/Bo/todo.txt"), b"mine too").unwrap();
    let before = everything(&ana.home);

    // Not while a daemon is running on it.
    let o = ana.try_cli(&["clear", "--yes", "--including-local"]);
    assert!(!o.status.success());
    let why = said(&o);
    assert!(why.contains("daemon is running") && why.contains("Nothing was changed"));
    assert!(ana.cli(&["files"]).contains("ana-film.bin"));
    ana.stop();
    assert_eq!(std::fs::read(ana.home.join("format")).unwrap(), b"2\n");
    let stopped = everything(&ana.home);
    assert!(stopped.len() >= before.len() - 1);

    // It says so of the files it leaves, and of the folder they are shown in.
    let out = ana.cli(&["clear", "--yes"]);
    let flat = out.split_whitespace().collect::<Vec<_>>().join(" ");
    for part in [
        "It leaves what is kept on this device only, 2 files (12 B) in",
        "local-shared: your own files, which exist nowhere else",
        "`--including-local` removes them too",
        "whose content is only on this device will be gone from this device",
        "Removed.",
    ] {
        assert!(flat.contains(part), "{flat:?} lacks {part:?}");
    }
    assert_eq!(names(&ana.home), ["config.toml", "local", "local-shared"]);
    assert_eq!(
        std::fs::read(ana.home.join("local/notes/draft.txt")).unwrap(),
        b"mine"
    );
    // Asked to, it removes them too, and says what they are.
    let out = ana.cli(&["clear", "--yes", "--including-local"]);
    let flat = out.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(flat.contains("It also removes what is kept on this device only, 2 files"));
    assert!(
        flat.contains("your own files, which exist nowhere else"),
        "{flat}"
    );
    assert_eq!(names(&ana.home), ["config.toml"]);
}

/// The object files of a store, smallest first.
fn objects(home: &Path) -> Vec<(u64, PathBuf)> {
    let mut all: Vec<(u64, PathBuf)> = everything(&home.join("blobs/objects"))
        .into_iter()
        .map(|(p, len, _)| (len, p))
        .collect();
    all.sort();
    all
}

/// Puts an object in a store that nothing names.
fn stray(home: &Path, bytes: &[u8]) -> PathBuf {
    let id = blake3::hash(bytes).to_hex().to_string();
    let dir = home.join("blobs/objects").join(&id[0..2]).join(&id[2..4]);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(&id), bytes).unwrap();
    dir.join(id)
}

#[test]
fn what_nothing_names_is_counted_and_deleted_only_when_that_is_sure() {
    let root = tempfile::tempdir().unwrap();
    let ana = set_up(root.path(), "ana");
    let held = objects(&ana.home);
    assert!(held.len() > 2, "a file of several chunks and their index");
    let out = ana.cli(&["free-space", "--unnamed"]);
    assert!(
        out.contains("Everything this device stores is named"),
        "{out}"
    );

    // Two objects nothing names: counted, and nothing is touched.
    let one = stray(&ana.home, &content(5000, 1));
    let two = stray(&ana.home, &content(7000, 2));
    let out = ana.cli(&["free-space", "--unnamed"]);
    assert!(out.contains("2 objects (12.0 kB)"), "{out}");
    assert!(out.contains("named by nothing"), "{out}");
    assert!(one.exists() && two.exists());
    assert_eq!(objects(&ana.home).len(), held.len() + 2);
    // `--delete` is only for `--unnamed`.
    assert!(!ana.try_cli(&["free-space", "--delete"]).status.success());

    // Deleted on the person's word, and nothing else goes: the file reads
    // back whole.
    let out = ana.cli(&["free-space", "--unnamed", "--delete"]);
    assert!(out.contains("Deleted 2 objects (12.0 kB)"), "{out}");
    assert!(!one.exists() && !two.exists());
    assert_eq!(objects(&ana.home), held);
    let back = root.path().join("back.bin");
    ana.cli(&["get", "ana-film.bin", &back.display().to_string()]);
    assert_eq!(std::fs::read(&back).unwrap(), content(3 << 20, 7));

    // An index the device does not hold: what it names cannot be told
    // from what nothing names, so the count may be too high, it says so,
    // and it deletes nothing.
    let index = &held[0].1;
    std::fs::remove_file(index).unwrap();
    let three = stray(&ana.home, &content(900, 3));
    let out = ana.cli(&["free-space", "--unnamed"]);
    let flat = out.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(flat.contains("That count may be too high"), "{flat}");
    assert!(flat.contains("1 indexes that entries name are not on this device"));
    let o = ana.try_cli(&["free-space", "--unnamed", "--delete"]);
    assert!(!o.status.success());
    assert!(said(&o).contains("nothing was deleted"), "{}", said(&o));
    assert!(three.exists());
    assert_eq!(objects(&ana.home).len(), held.len());
}

/// D4. `cardinal clear` never removes a store a daemon is running on,
/// whatever the directory is called this time and wherever this command
/// looks for the daemon's socket. Here the directory is named with a
/// trailing slash, and the command looks under a runtime directory the
/// daemon was not given, so nothing answers where it asks.
#[test]
fn clear_refuses_while_a_daemon_runs_however_the_directory_is_named() {
    let root = tempfile::tempdir().unwrap();
    let ana = set_up(root.path(), "ana");
    let run = root.path().join("run");
    std::fs::create_dir_all(&run).unwrap();
    let before = everything(&ana.home);
    let mut named = ana.home.clone().into_os_string();
    named.push("/");
    let o = ana
        .cmd()
        .env("CARDINAL_HOME", &named)
        .env_remove("CARDINAL_SOCKET")
        .env("XDG_RUNTIME_DIR", &run)
        .args(["clear", "--yes", "--including-local"])
        .output()
        .unwrap();
    let why = said(&o);
    assert!(!o.status.success(), "cleared under a running daemon: {why}");
    assert!(
        why.contains("daemon is running") && why.contains("Nothing was changed"),
        "{why}"
    );
    // Every file that was there is there, and none of them shorter: a
    // running service may have written more, and nothing was removed or
    // put in another's place. (The service's own `--clear`, which a
    // client runs, is tried the same way in `cardinald/tests/store.rs`.)
    let after = everything(&ana.home);
    for (path, len, _) in &before {
        let now = after.iter().find(|(p, ..)| p == path);
        assert!(
            now.is_some_and(|(_, n, _)| n >= len),
            "{} was removed or cut",
            path.display()
        );
    }
    assert!(ana.cli(&["files"]).contains("ana-film.bin"));
    assert!(ana.status()["identity"].is_string());
}

/// D7. A second service started on a data directory that one is running
/// on does not start, and touches nothing there: it would empty the
/// place where the first keeps objects it is still writing.
#[test]
fn a_second_daemon_on_the_same_directory_does_not_start() {
    let root = tempfile::tempdir().unwrap();
    let ana = set_up(root.path(), "ana");
    let waiting = ana.home.join("blobs/tmp/being-written");
    std::fs::create_dir_all(waiting.parent().unwrap()).unwrap();
    std::fs::write(&waiting, b"half an object").unwrap();
    // S9: nor does it write its own settings over the first one's.
    let settings = std::fs::read(ana.home.join("config.toml")).unwrap();
    let mut second = ana
        .cmd()
        .env("CARDINAL_SOCKET", root.path().join("second.sock"))
        .args(["daemon", "--no-discovery", "--no-mount", "--listen"])
        .arg(format!("127.0.0.1:{}", free_port()))
        .args(["--name", "other"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let until = Instant::now() + Duration::from_secs(10);
    let mut status = None;
    while status.is_none() && Instant::now() < until {
        status = second.try_wait().unwrap();
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = second.kill();
    let out = second.wait_with_output().unwrap();
    let why = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        waiting.exists(),
        "the second emptied what the first was writing"
    );
    assert!(
        status.is_some_and(|s| !s.success()),
        "a second daemon ran: {why}"
    );
    assert!(why.contains("already running"), "{why}");
    assert!(
        std::fs::read(ana.home.join("config.toml")).unwrap() == settings,
        "the second wrote its settings over the first's"
    );
    // The first goes on as it was.
    assert!(ana.cli(&["files"]).contains("ana-film.bin"));
}

/// D8. An old version that was freed is gone on purpose: its index is not
/// "missing", and what nothing names can still be told and deleted. It
/// used to count as an index an entry names that is not here, for good,
/// since the entry that wrote the version is always held.
#[test]
fn what_nothing_names_can_be_deleted_after_an_old_version_was_freed() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut ana = Dev::new(root.path(), "ana", free_port());
    for (k, v) in [
        ("CARDINAL_TEST_FREE_MIN_AGE_MS", "0"),
        ("CARDINAL_TEST_FREE_INTERVAL_MS", "500"),
    ] {
        ana.env.push((k.into(), v.into()));
    }
    ana.start();
    ana.cli(&["init", "--yes", "--name", "ana"]);
    ana.wait_mounted();
    // A file is written, and written over: its first content is an old
    // version, of several chunks under an index.
    let file = ana.mount.join("film.bin");
    for seed in [7, 8] {
        std::fs::write(&file, content(3 << 20, seed)).unwrap();
        ana.cli(&["flush"]);
    }
    wait("the old version is counted", 30, || {
        ana.cli(&["status"]).contains("Old versions: ")
    });
    let before = objects(&ana.home).len();
    let out = ana.cli(&["free-space", "--yes"]);
    assert!(
        objects(&ana.home).len() < before,
        "nothing was freed: {out}"
    );
    // Something nothing names.
    let one = stray(&ana.home, &content(5000, 1));
    let o = ana.try_cli(&["free-space", "--unnamed", "--delete"]);
    assert!(o.status.success(), "{}", said(&o));
    assert!(!one.exists(), "{}", said(&o));
    // The file is whole.
    assert_eq!(std::fs::read(&file).unwrap(), content(3 << 20, 8));
}

/// S1. A file that goes back to content this device freed as an old
/// version holds that content as its current one. Until the next hourly
/// pass the device still has it noted as freed, and what nothing names is
/// counted and deleted without it all the same. The pass is an hour away
/// here, as it is after a suspend.
#[test]
fn content_that_is_current_again_after_it_was_freed_is_named() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut ana = Dev::new(root.path(), "ana", free_port());
    for (k, v) in [
        ("CARDINAL_TEST_FREE_MIN_AGE_MS", "0"),
        ("CARDINAL_TEST_FREE_INTERVAL_MS", "3600000"),
    ] {
        ana.env.push((k.into(), v.into()));
    }
    ana.start();
    ana.cli(&["init", "--yes", "--name", "ana"]);
    ana.wait_mounted();
    let file = ana.mount.join("film.bin");
    let put = |seed: u64| {
        std::fs::write(&file, content(3 << 20, seed)).unwrap();
        ana.cli(&["flush"]);
    };
    // A, then B over it; A is freed as an old version.
    put(7);
    let first = objects(&ana.home).len();
    put(8);
    let both = objects(&ana.home).len();
    let out = ana.cli(&["free-space", "--yes"]);
    assert!(objects(&ana.home).len() < both, "nothing was freed: {out}");
    // The file goes back to A.
    put(7);
    let held = objects(&ana.home);
    assert!(held.len() >= first, "A is stored again");
    let out = ana.cli(&["free-space", "--unnamed"]);
    assert!(
        out.contains("Everything this device stores is named"),
        "the current content counts as named by nothing: {out}"
    );
    let o = ana.try_cli(&["free-space", "--unnamed", "--delete"]);
    assert!(o.status.success(), "{}", said(&o));
    assert_eq!(objects(&ana.home), held, "{}", said(&o));
    let back = root.path().join("back.bin");
    ana.cli(&["get", "film.bin", &back.display().to_string()]);
    assert_eq!(std::fs::read(&back).unwrap(), content(3 << 20, 7));
}

/// S9. A service holds its data directory from before it reads anything
/// there, and answers on its socket only once it has loaded. In between,
/// a command is told that it is starting, not that none is running; and
/// `cardinal init` sets nothing up beside it, on a directory another
/// process holds.
#[test]
fn a_service_that_is_still_starting_is_said_to_be_starting() {
    let root = tempfile::tempdir().unwrap();
    let mut ana = Dev::new(root.path(), "ana", free_port());
    ana.env
        .push(("CARDINAL_TEST_STARTING_WAIT_MS".into(), "300".into()));
    // What a service that has not bound its socket yet looks like.
    let paths = cardinald::paths::Paths::at(&ana.home);
    let held = cardinald::lock::take(&paths).unwrap().expect("free");
    for command in [&["status"][..], &["init", "--yes", "--name", "ana"]] {
        let o = ana.try_cli(command);
        let why = said(&o);
        let flat = why.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(!o.status.success(), "{command:?}: {flat}");
        assert!(flat.contains("is starting"), "{command:?}: {flat}");
        assert!(!flat.contains("is not running"), "{command:?}: {flat}");
        assert!(!flat.contains("recovery words"), "{command:?}: {flat}");
    }
    assert_eq!(names(&ana.home), Vec::<String>::new());
    // Once nothing holds it, the same command sets the device up.
    drop(held);
    ana.cli(&["init", "--yes", "--name", "ana"]);
    assert!(ana.home.join("identity.log").exists());
}
