//! A randomized stress test of the mount: devices write, overwrite,
//! rename and delete files, make and remove folders, and change
//! `.cardinalignore`, at the same time, with restarts and `free-space` in
//! between. After every round, when all are quiet, it checks:
//!
//! - every device shows the same synced items with the same content
//!   (local items, which only their device shows, aside);
//! - a restarted device shows exactly what it showed before, local items
//!   and their content included;
//! - `free-space` changes nothing a device shows;
//! - no file operation failed with an error other than the expected ones
//!   (a path another device just removed, a conflict copy that cannot be
//!   written), and no daemon panicked.
//!
//! Ignored by default (it takes minutes). Run with
//! `CARDINAL_STRESS_SEED=7 CARDINAL_STRESS_ROUNDS=20 cargo test -p cardinal
//! --test stress -- --ignored --nocapture`; the seed is printed, and the
//! same seed makes the same operations (their timing still varies).

mod common;

use common::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{Duration, Instant};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
}

const DIRS: &[&str] = &["", "a", "a/b", "c", "a/build", "c/build", "a/b/build"];
const NAMES: &[&str] = &[
    "x.txt", "y.txt", "z.bin", "t.tmp", "keep.tmp", "u.md", "v.o",
];
const IGNORES: &[&str] = &[
    "",
    "*.tmp\n",
    "build/\n*.tmp\n",
    "build/\n!keep.tmp\n*.tmp\n",
    "build/\n*.o\n",
];
const SIZES: &[usize] = &[0, 10, 900, 1500, 20_000, 70_000, 300_000];

fn content(rng: &mut Rng) -> Vec<u8> {
    let n = *rng.pick(SIZES);
    let mut x = rng.next() | 1;
    let mut v = Vec::with_capacity(n + 8);
    while v.len() < n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.truncate(n);
    v
}

/// A request on a daemon's control socket.
fn request(d: &Dev, req: Value) -> Value {
    let mut s = std::os::unix::net::UnixStream::connect(d.home.join("control.sock")).unwrap();
    let mut line = req.to_string();
    line.push('\n');
    s.write_all(line.as_bytes()).unwrap();
    let mut out = String::new();
    BufReader::new(s).read_line(&mut out).unwrap();
    serde_json::from_str(&out).unwrap()
}

/// Files under a mount, recursively (paths relative to it).
fn files(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() => stack.push(p),
                Ok(_) => out.push(p.strip_prefix(root).unwrap().display().to_string()),
                Err(_) => {}
            }
        }
    }
    out.sort();
    out
}

/// What a device shows: path -> (kind, local, content hash, node).
type View = BTreeMap<String, (String, bool, String, String)>;

fn view(d: &Dev) -> View {
    let t = request(d, json!({"cmd": "debug-tree"}));
    assert_eq!(t["ok"], true, "{t}");
    let mut out = View::new();
    for i in t["items"].as_array().unwrap() {
        let path = i["path"].as_str().unwrap().to_owned();
        let kind = i["kind"].as_str().unwrap().to_owned();
        let hash = match kind.as_str() {
            "file" | "conflict" => match std::fs::read(d.p(&path)) {
                Ok(b) => blake3::hash(&b).to_hex()[..16].to_owned(),
                Err(e) => format!("unreadable: {e}"),
            },
            _ => String::new(),
        };
        let node = i["node"].as_str().unwrap_or("").to_owned();
        out.insert(path, (kind, i["local"] == true, hash, node));
    }
    out
}

/// The synced part of a view, by node, kind and path with ` (n)` suffixes
/// dropped: a local item keeps its name on its device, where a synced one
/// with the same name shows as `name (2)`, so display names may differ.
fn synced(v: &View) -> BTreeMap<(String, String, String), String> {
    v.iter()
        .filter(|(_, (_, local, _, _))| !local)
        .map(|(p, (k, _, h, n))| ((n.clone(), k.clone(), plain(p)), h.clone()))
        .collect()
}

/// A path without ` (n)` suffixes (a name can carry two: one from the
/// space for duplicates, one from the mount for a local item's name).
fn plain(p: &str) -> String {
    fn strip(s: &str) -> Option<String> {
        let (stem, ext) = match s.rfind('.') {
            Some(i) if i > 0 && !s[i..].contains(')') => (&s[..i], &s[i..]),
            _ => (s, ""),
        };
        let open = stem.rfind(" (")?;
        let num = stem[open + 2..].strip_suffix(')')?;
        (!num.is_empty() && num.chars().all(|c| c.is_ascii_digit()))
            .then(|| format!("{}{ext}", &stem[..open]))
    }
    p.split('/')
        .map(|c| {
            let mut c = c.to_owned();
            while let Some(s) = strip(&c) {
                c = s;
            }
            c
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[test]
fn plain_names() {
    assert_eq!(plain("c (2)"), "c");
    assert_eq!(plain("c (2)/build"), "c/build");
    assert_eq!(plain("a/x (3).txt"), "a/x.txt");
    assert_eq!(
        plain("a/x (conflict, beta).txt"),
        "a/x (conflict, beta).txt"
    );
    assert_eq!(plain("c (2) (2)/y (3) (2).txt"), "c/y.txt");
}

/// Raw items of a device under the top folders `tops`, for a failure.
fn raw(d: &Dev, tops: &[String]) -> Vec<String> {
    let t = request(d, json!({"cmd": "debug-tree"}));
    let mut out: Vec<String> = t["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| {
            let p = plain(i["path"].as_str().unwrap_or(""));
            tops.iter()
                .any(|t| p == *t || p.starts_with(&format!("{t}/")))
        })
        .map(|i| i.to_string())
        .collect();
    out.sort();
    out
}

/// Flushes every device and waits until they agree on the files space and
/// have nothing pending, twice in a row. Returns how long it took. Writes
/// reach every online device at once; a missed one waits for the periodic
/// sync (every 3 minutes), so settling takes up to 4 minutes at worst.
fn quiesce(devs: &[&Dev]) -> Duration {
    let start = Instant::now();
    let mut stable = 0;
    while stable < 2 {
        for d in devs {
            d.cli(&["flush"]);
        }
        std::thread::sleep(Duration::from_millis(400));
        let trees: Vec<Value> = devs
            .iter()
            .map(|d| request(d, json!({"cmd": "debug-tree"})))
            .collect();
        let heads: Vec<&str> = trees
            .iter()
            .map(|t| t["heads"].as_str().unwrap_or(""))
            .collect();
        let quiet =
            trees.iter().all(|t| t["pending"] == false) && heads.windows(2).all(|w| w[0] == w[1]);
        stable = if quiet { stable + 1 } else { 0 };
        if !quiet && start.elapsed() > Duration::from_secs(15) {
            let pending: Vec<_> = trees.iter().map(|t| t["pending"].clone()).collect();
            eprintln!(
                "settling {:?}: heads {heads:?} pending {pending:?}",
                start.elapsed()
            );
            for (d, t) in devs
                .iter()
                .zip(&trees)
                .filter(|(_, t)| t["pending"] == true)
            {
                eprintln!(
                    "stuck on {}: deleted {} settle {} {}",
                    d.name, t["deleted"], t["settle"], t["stuck"]
                );
            }
        }
        assert!(
            start.elapsed() < Duration::from_secs(240),
            "devices did not settle: {heads:?} pending {:?}",
            trees
                .iter()
                .map(|t| t["pending"].clone())
                .collect::<Vec<_>>()
        );
    }
    start.elapsed()
}

/// Errors other devices or conflict copies explain.
fn expected(e: &std::io::Error) -> bool {
    // Through alpha, a file's data may not have reached anyone in reach yet.
    if e.raw_os_error() == Some(libc::EIO) {
        return std::env::var_os("CARDINAL_STRESS_LINE").is_some();
    }
    matches!(
        e.raw_os_error(),
        Some(libc::ENOENT)
            | Some(libc::EEXIST)
            | Some(libc::ENOTEMPTY)
            | Some(libc::ENOTDIR)
            | Some(libc::EISDIR)
            | Some(libc::EXDEV)
            | Some(libc::EPERM)
            | Some(libc::EACCES)
    )
}

fn one_op(rng: &mut Rng, d: &Dev) -> std::io::Result<String> {
    let root = d.mount.clone();
    let existing = files(&root);
    let path = |rng: &mut Rng| {
        let dir = *rng.pick(DIRS);
        let name = *rng.pick(NAMES);
        if dir.is_empty() {
            name.to_owned()
        } else {
            format!("{dir}/{name}")
        }
    };
    match rng.below(100) {
        0..=34 => {
            let p = path(rng);
            if let Some(parent) = root.join(&p).parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(root.join(&p), content(rng))?;
            Ok(format!("write {p}"))
        }
        35..=44 if !existing.is_empty() => {
            let p = rng.pick(&existing).clone();
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(root.join(&p))?;
            let off = rng.below(100_000) as u64;
            std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(off))?;
            f.write_all(&content(rng)[..])?;
            Ok(format!("overwrite {p} at {off}"))
        }
        45..=62 if !existing.is_empty() => {
            let src = rng.pick(&existing).clone();
            let dst = path(rng);
            if let Some(parent) = root.join(&dst).parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::rename(root.join(&src), root.join(&dst))?;
            Ok(format!("rename {src} -> {dst}"))
        }
        63..=74 if !existing.is_empty() => {
            let p = rng.pick(&existing).clone();
            std::fs::remove_file(root.join(&p))?;
            Ok(format!("delete {p}"))
        }
        75..=79 => {
            let dir = *rng.pick(&DIRS[1..]);
            std::fs::remove_dir_all(root.join(dir))?;
            Ok(format!("remove {dir}/"))
        }
        80..=86 => {
            let dir = *rng.pick(&["", "a", "c"]);
            let text = *rng.pick(IGNORES);
            std::fs::create_dir_all(root.join(dir))?;
            std::fs::write(root.join(dir).join(".cardinalignore"), text)?;
            Ok(format!("ignore in /{dir}: {text:?}"))
        }
        _ => {
            let dir = *rng.pick(&DIRS[1..]);
            std::fs::create_dir_all(root.join(dir))?;
            Ok(format!("mkdir {dir}"))
        }
    }
}

/// Every real file in a device's local storage is a local file it shows:
/// none left behind where nothing shows it.
fn check_storage(d: &Dev, round: usize) {
    let stored = files(&d.home.join("local"));
    let shown = view(d)
        .into_iter()
        .filter(|(_, (k, local, _, _))| *local && k == "file")
        .count();
    assert_eq!(
        stored.len(),
        shown,
        "round {round}: {} stores {stored:#?} but shows {shown} local files",
        d.name
    );
}

fn check_agree(devs: &[&Dev], round: usize) {
    // The same heads give the same state; a mount shows all of it.
    let trees: Vec<Value> = devs
        .iter()
        .map(|d| request(d, json!({"cmd": "debug-tree"})))
        .collect();
    for (d, t) in devs.iter().zip(&trees) {
        assert_eq!(
            t["state"], trees[0]["state"],
            "round {round}: {} state differs",
            d.name
        );
        assert_eq!(
            t["unshown"],
            json!([]),
            "round {round}: {} does not show",
            d.name
        );
    }
    let views: Vec<View> = devs.iter().map(|d| view(d)).collect();
    for (d, v) in devs.iter().zip(&views) {
        let bad: Vec<_> = v
            .iter()
            .filter(|(_, (_, _, h, _))| h.starts_with("unreadable"))
            .collect();
        assert!(
            bad.is_empty(),
            "round {round}: {} cannot read {bad:?}",
            d.name
        );
    }
    let first = synced(&views[0]);
    for (d, v) in devs.iter().zip(&views).skip(1) {
        let other = synced(v);
        if other != first {
            let only_a: Vec<_> = first
                .iter()
                .filter(|(k, x)| other.get(*k) != Some(x))
                .collect();
            let only_b: Vec<_> = other
                .iter()
                .filter(|(k, x)| first.get(*k) != Some(x))
                .collect();
            let tops: Vec<String> = only_a
                .iter()
                .chain(only_b.iter())
                .map(|(k, _)| k.2.split('/').next().unwrap_or("").to_owned())
                .collect();
            panic!(
                "round {round}: {} and {} differ:\n  {}: {only_a:?}\n  {}: {only_b:?}\n\
                 raw {}:\n{}\nraw {}:\n{}",
                devs[0].name,
                d.name,
                devs[0].name,
                d.name,
                devs[0].name,
                raw(devs[0], &tops).join("\n"),
                d.name,
                raw(d, &tops).join("\n"),
            );
        }
    }
}

#[test]
#[ignore]
fn stress() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let seed: u64 = std::env::var("CARDINAL_STRESS_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        });
    let rounds: usize = std::env::var("CARDINAL_STRESS_ROUNDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    eprintln!("stress: seed {seed}, {rounds} rounds");
    let mut rng = Rng(seed);
    let root = tempfile::tempdir().unwrap();
    let names = ["alpha", "beta", "gamma"];
    let mut devs: Vec<Dev> = names
        .iter()
        .map(|n| Dev::new(root.path(), n, free_port()))
        .collect();
    for d in devs.iter_mut() {
        d.env
            .push(("CARDINAL_TEST_FREE_MIN_AGE_MS".into(), "0".into()));
        d.env.push(("CARDINAL_TEST_PTRACE".into(), "1".into()));
    }
    devs[0].start();
    devs[0].cli(&["init", "--yes", "--name", "alpha"]);
    devs[0].wait_mounted();
    for i in 1..devs.len() {
        devs[i].start();
        pair(&devs[0], &devs[i]);
    }
    // Every device reaches every other directly (no discovery here), or
    // with CARDINAL_STRESS_LINE, only alpha, which they all paired with.
    if std::env::var_os("CARDINAL_STRESS_LINE").is_none() {
        for a in &devs {
            for b in &devs {
                if a.name != b.name {
                    a.cli(&["peer", "add", &format!("127.0.0.1:{}", b.port)]);
                }
            }
        }
    }
    let mut unexpected = Vec::new();
    let mut slow = Vec::new();
    for round in 0..rounds {
        let logged: Vec<usize> = devs.iter().map(|d| d.log().len()).collect();
        // A burst of operations on all devices at once.
        std::thread::scope(|s| {
            let handles: Vec<_> = devs
                .iter()
                .map(|d| {
                    let mut r = Rng(rng.next());
                    s.spawn(move || {
                        let mut bad = Vec::new();
                        for _ in 0..25 {
                            match one_op(&mut r, d) {
                                Ok(op) => eprintln!("op {round} {}: {op}", d.name),
                                Err(e) if expected(&e) => {}
                                Err(e) => bad.push(format!("{}: {e}", d.name)),
                            }
                            std::thread::sleep(Duration::from_millis(r.below(150) as u64));
                        }
                        bad
                    })
                })
                .collect();
            for h in handles {
                unexpected.extend(h.join().unwrap());
            }
        });
        let refs: Vec<&Dev> = devs.iter().collect();
        let took = quiesce(&refs);
        if took > Duration::from_secs(15) {
            slow.push(format!("round {round}: settled in {took:?}"));
            for (d, from) in devs.iter().zip(&logged) {
                let log = d.log();
                eprintln!(
                    "---- {} log, round {round} ----\n{}",
                    d.name,
                    log.get(*from..).unwrap_or(&log)
                );
            }
        }
        check_agree(&refs, round);
        for d in &devs {
            check_storage(d, round);
        }
        // Now and then: a restart, or freeing old versions, changes
        // nothing a device shows.
        let i = rng.below(devs.len());
        match rng.below(3) {
            0 => {
                eprintln!("restart {}", names[i]);
                let before = view(&devs[i]);
                devs[i].stop();
                devs[i].start();
                devs[i].wait_mounted();
                let refs: Vec<&Dev> = devs.iter().collect();
                quiesce(&refs);
                let after = view(&devs[i]);
                assert_eq!(
                    before, after,
                    "round {round}: {} changed across a restart",
                    names[i]
                );
            }
            1 => {
                eprintln!("free-space {}", names[i]);
                let before = view(&devs[i]);
                devs[i].cli(&["free-space", "--yes"]);
                let after = view(&devs[i]);
                assert_eq!(
                    before, after,
                    "round {round}: free-space changed {}",
                    names[i]
                );
            }
            _ => {}
        }
        let local: usize = devs
            .iter()
            .map(|d| view(d).values().filter(|x| x.1).count())
            .sum();
        eprintln!(
            "round {round}: {} synced items, {local} local",
            synced(&view(&devs[0])).len()
        );
    }
    for d in &devs {
        let log = d.log();
        assert!(!log.contains("panicked"), "{} panicked:\n{log}", d.name);
        for l in log.lines().filter(|l| l.contains("ERROR")) {
            eprintln!("{}: {l}", d.name);
        }
    }
    for s in &slow {
        eprintln!("slow: {s}");
    }
    assert!(unexpected.is_empty(), "unexpected errors: {unexpected:#?}");
}
