//! Two devices on one machine: two daemons with their own data
//! directories and ports, paired over loopback, each mounting the files
//! space. Exercises the first milestone end to end through the real
//! binary and the real FUSE mounts.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.
//! `CARDINAL_TEST_BIG_MB` sets the size of the large-file step (default
//! 500; 0 skips it).

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_cardinal");

struct Dev {
    name: &'static str,
    home: PathBuf,
    mount: PathBuf,
    port: u16,
    child: Option<Child>,
}

impl Dev {
    fn new(root: &Path, name: &'static str, port: u16) -> Dev {
        let home = root.join(name);
        let mount = root.join(format!("mnt-{name}"));
        std::fs::create_dir_all(&home).unwrap();
        Dev {
            name,
            home,
            mount,
            port,
            child: None,
        }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(BIN);
        c.env("CARDINAL_HOME", &self.home)
            .env("CARDINAL_SOCKET", self.home.join("control.sock"))
            .env("CARDINAL_LOG", "info,cardinald=debug");
        c
    }

    fn start(&mut self) {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.home.join("daemon.log"))
            .unwrap();
        let child = self
            .cmd()
            .args(["daemon", "--no-discovery", "--name", self.name])
            .arg("--listen")
            .arg(format!("127.0.0.1:{}", self.port))
            .arg("--mount")
            .arg(&self.mount)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        self.child = Some(child);
        wait(&format!("{} daemon up", self.name), 20, || {
            self.try_cli(&["status"]).status.success()
        });
    }

    fn try_cli(&self, args: &[&str]) -> Output {
        self.cmd().args(args).output().unwrap()
    }

    fn cli(&self, args: &[&str]) -> String {
        let o = self.try_cli(args);
        assert!(
            o.status.success(),
            "{} {:?} failed: {}{}",
            self.name,
            args,
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    fn status(&self) -> serde_json::Value {
        serde_json::from_str(&self.cli(&["status", "--json"])).unwrap()
    }

    fn wait_mounted(&self) {
        wait(&format!("{} mounted", self.name), 60, || {
            self.status()["mounted"].is_string()
        });
    }

    fn stop(&mut self) {
        let _ = self.try_cli(&["stop"]);
        if let Some(mut c) = self.child.take() {
            let start = Instant::now();
            loop {
                if c.try_wait().unwrap().is_some() {
                    break;
                }
                if start.elapsed() > Duration::from_secs(30) {
                    let _ = c.kill();
                    let _ = c.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    fn p(&self, rel: &str) -> PathBuf {
        self.mount.join(rel)
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.home.join("daemon.log")).unwrap_or_default()
    }
}

impl Drop for Dev {
    fn drop(&mut self) {
        self.stop();
        let _ = Command::new("fusermount3")
            .args(["-u", "-z"])
            .arg(&self.mount)
            .status();
        if std::thread::panicking() {
            eprintln!("---- {} log ----\n{}", self.name, self.log());
        }
    }
}

fn wait(what: &str, secs: u64, mut f: impl FnMut() -> bool) -> Duration {
    let start = Instant::now();
    loop {
        if f() {
            return start.elapsed();
        }
        if start.elapsed() > Duration::from_secs(secs) {
            panic!("timed out waiting for {what}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn dir_size(p: &Path) -> u64 {
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            match e.metadata() {
                Ok(m) if m.is_dir() => n += dir_size(&e.path()),
                Ok(m) => n += m.len(),
                Err(_) => {}
            }
        }
    }
    n
}

fn read(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists()
        && Command::new("fusermount3")
            .arg("-V")
            .output()
            .is_ok_and(|o| o.status.success())
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn pair(a: &Dev, b: &Dev) {
    let mut shower = b
        .cmd()
        .arg("pair")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(shower.stdout.take().unwrap());
    let (mut code, mut at) = (None, None);
    let mut line = String::new();
    while code.is_none() || at.is_none() {
        line.clear();
        assert!(out.read_line(&mut line).unwrap() > 0, "pair ended early");
        let l = line.trim();
        if let Some(c) = l.strip_prefix("cardinal pair ") {
            code = Some(c.to_owned());
        }
        if let Some(i) = l.find("--at ") {
            let rest = &l[i + 5..];
            let port = rest
                .trim_end_matches(|c: char| !c.is_ascii_digit())
                .rsplit(':')
                .next()
                .unwrap();
            at = Some(format!("127.0.0.1:{port}"));
        }
    }
    let (code, at) = (code.unwrap(), at.unwrap());
    let typed = a.cli(&["pair", &code, "--at", &at]);
    assert!(typed.contains("Added"), "{typed}");
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut out, &mut rest).unwrap();
    assert!(shower.wait().unwrap().success(), "{rest}");
    assert!(rest.contains("Done"), "{rest}");
}

#[test]
fn two_devices() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    let mut b = Dev::new(root.path(), "beta", free_port());
    a.start();
    b.start();

    // Set up A, add B.
    let out = a.cli(&["init", "--yes", "--name", "alpha"]);
    assert!(out.contains("Set up"), "{out}");
    a.wait_mounted();
    pair(&a, &b);
    b.wait_mounted();
    let devs = a.status()["devices"].clone();
    assert_eq!(devs.as_array().unwrap().len(), 2, "{devs}");

    // A file written on A appears on B.
    std::fs::write(a.p("hello.txt"), "hello from alpha\n").unwrap();
    wait("hello on B", 10, || {
        read(&b.p("hello.txt")).as_deref() == Some("hello from alpha\n")
    });

    // Latency: save on A to visible on B.
    let mut lat = Vec::new();
    for i in 0..10 {
        let data = format!("edit {i}\n");
        let t0 = Instant::now();
        std::fs::write(a.p("latency.txt"), &data).unwrap();
        wait("latency edit", 10, || {
            read(&b.p("latency.txt")).as_deref() == Some(&data)
        });
        lat.push(t0.elapsed());
        std::thread::sleep(Duration::from_millis(300));
    }
    lat.sort();
    eprintln!(
        "MEASURE save-to-visible latency on loopback: median {:?}, max {:?}",
        lat[lat.len() / 2],
        lat[lat.len() - 1]
    );
    assert!(lat[lat.len() / 2] < Duration::from_secs(1));

    // Folders, renames, deletes, both ways.
    std::fs::create_dir_all(a.p("docs/deep/er")).unwrap();
    std::fs::write(a.p("docs/deep/er/x.txt"), "x").unwrap();
    wait("nested file on B", 10, || {
        read(&b.p("docs/deep/er/x.txt")).as_deref() == Some("x")
    });
    std::fs::rename(b.p("docs"), b.p("papers")).unwrap();
    std::fs::remove_file(b.p("hello.txt")).unwrap();
    wait("rename and delete on A", 10, || {
        read(&a.p("papers/deep/er/x.txt")).as_deref() == Some("x")
            && !a.p("docs").exists()
            && !a.p("hello.txt").exists()
    });

    // An editor's atomic save (write a temporary file, rename it over)
    // is an edit of the file: it keeps its history.
    std::fs::write(a.p("notes.md"), "v1\n").unwrap();
    wait("notes v1 on B", 10, || {
        read(&b.p("notes.md")).as_deref() == Some("v1\n")
    });
    std::fs::write(a.p(".notes.md.tmp"), "v2\n").unwrap();
    std::fs::rename(a.p(".notes.md.tmp"), a.p("notes.md")).unwrap();
    wait("notes v2 on B", 10, || {
        read(&b.p("notes.md")).as_deref() == Some("v2\n")
    });
    let h = b.cli(&["history", b.p("notes.md").to_str().unwrap()]);
    assert!(h.contains("  1  ") && h.contains("  2  "), "{h}");
    b.cli(&["restore", "notes.md", "--version", "1"]);
    wait("restore on A", 10, || {
        read(&a.p("notes.md")).as_deref() == Some("v1\n")
    });

    // vim, with its swap file and default save.
    if Command::new("vim").arg("--version").output().is_ok() {
        std::fs::write(a.p("vim.txt"), "one\ntwo\n").unwrap();
        let st = Command::new("vim")
            .args([
                "-n",
                "-u",
                "NONE",
                "-i",
                "NONE",
                "-Es",
                "-c",
                "set swapfile",
                "-c",
                "set backupcopy=no",
                "-c",
                "%s/two/three/",
                "-c",
                "wq",
            ])
            .arg(a.p("vim.txt"))
            .status()
            .unwrap();
        assert!(st.success());
        wait("vim edit on B", 10, || {
            read(&b.p("vim.txt")).as_deref() == Some("one\nthree\n")
        });
    }

    // git: commit on A, log on B.
    if Command::new("git").arg("--version").output().is_ok() {
        let git = |dir: &Path, args: &[&str]| {
            let o = Command::new("git")
                .args(["-c", "user.name=t", "-c", "user.email=t@example.org"])
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                o.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            String::from_utf8_lossy(&o.stdout).into_owned()
        };
        std::fs::create_dir(a.p("repo")).unwrap();
        git(&a.p("repo"), &["init", "-q"]);
        for i in 0..3 {
            std::fs::write(a.p("repo/file.txt"), format!("line {i}\n")).unwrap();
            git(&a.p("repo"), &["add", "file.txt"]);
            git(
                &a.p("repo"),
                &["commit", "-q", "-m", &format!("commit {i}")],
            );
        }
        let log_a = git(&a.p("repo"), &["log", "--oneline"]);
        wait("git log on B", 20, || {
            Command::new("git")
                .args(["log", "--oneline"])
                .current_dir(b.p("repo"))
                .output()
                .is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout) == log_a)
        });
        git(&b.p("repo"), &["fsck", "--no-progress"]);
        let st = git(&b.p("repo"), &["status", "--porcelain"]);
        assert!(st.is_empty(), "B's checkout is clean: {st}");
    }

    // Concurrent edits while apart become two versions.
    std::fs::write(a.p("conflict.txt"), "base\n").unwrap();
    wait("base on B", 10, || {
        read(&b.p("conflict.txt")).as_deref() == Some("base\n")
    });
    a.stop();
    std::fs::write(b.p("conflict.txt"), "beta's edit\n").unwrap();
    b.cli(&["flush"]);
    b.stop();
    a.start();
    a.wait_mounted();
    std::fs::write(a.p("conflict.txt"), "alpha's edit\n").unwrap();
    a.cli(&["flush"]);
    // Persistence: A restarted and still has everything.
    assert_eq!(read(&a.p("papers/deep/er/x.txt")).as_deref(), Some("x"));
    b.start();
    b.wait_mounted();
    let copy_of = |d: &Dev| -> Option<String> {
        std::fs::read_dir(&d.mount)
            .ok()?
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .find(|n| n.starts_with("conflict (conflict, "))
    };
    wait("conflict copies on both", 30, || {
        copy_of(&a).is_some() && copy_of(&b).is_some()
    });
    let (ca, cb) = (copy_of(&a).unwrap(), copy_of(&b).unwrap());
    assert_eq!(ca, cb);
    let main = read(&a.p("conflict.txt")).unwrap();
    let other = read(&a.p(&ca)).unwrap();
    let mut both = [main.clone(), other.clone()];
    both.sort();
    assert_eq!(
        both,
        ["alpha's edit\n".to_string(), "beta's edit\n".to_string()]
    );
    assert_eq!(read(&b.p("conflict.txt")).unwrap(), main);
    let c = a.cli(&["conflicts"]);
    assert!(c.contains("conflict.txt"), "{c}");
    // Deleting the copy keeps the main version, everywhere.
    std::fs::remove_file(a.p(&ca)).unwrap();
    wait("conflict settled on B", 10, || {
        copy_of(&b).is_none() && read(&b.p("conflict.txt")).as_deref() == Some(main.as_str())
    });

    // A large file.
    let mb: u64 = std::env::var("CARDINAL_TEST_BIG_MB")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    if mb > 0 {
        let src = root.path().join("big.src");
        {
            use std::io::Write;
            let mut f = std::io::BufWriter::new(std::fs::File::create(&src).unwrap());
            let mut x: u64 = 0x9e3779b97f4a7c15;
            let mut buf = vec![0u8; 1 << 20];
            for _ in 0..mb {
                for c in buf.chunks_mut(8) {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    c.copy_from_slice(&x.to_le_bytes());
                }
                f.write_all(&buf).unwrap();
            }
        }
        let size = mb << 20;
        let base = dir_size(&b.home.join("blobs"));
        let t0 = Instant::now();
        std::fs::copy(&src, a.p("big.bin")).unwrap();
        let written = t0.elapsed();
        a.cli(&["flush"]);
        let committed = t0.elapsed();
        wait("big file listed on B", 600, || {
            std::fs::metadata(b.p("big.bin")).is_ok_and(|m| m.len() == size)
        });
        let listed = t0.elapsed();
        // the background fetch is done when B's store holds the content
        wait("big file fetched on B", 1800, || {
            dir_size(&b.home.join("blobs")) >= base + size
        });
        let fetched = t0.elapsed();
        let same = Command::new("cmp")
            .arg(&src)
            .arg(b.p("big.bin"))
            .status()
            .unwrap()
            .success();
        assert!(same, "big file differs on B");
        let read_back = t0.elapsed();
        let mbs = |d: Duration| mb as f64 / d.as_secs_f64();
        eprintln!(
            "MEASURE {mb} MiB: copy into mount {:?} ({:.1} MiB/s); committed at {:?} \
             ({:.1} MiB/s); listed on B at {:?}; all chunks on B at {:?} (transfer {:.1} MiB/s); \
             read back on B {:?} ({:.1} MiB/s)",
            written,
            mbs(written),
            committed,
            mbs(committed - written),
            listed,
            fetched,
            mbs(fetched - listed),
            read_back - fetched,
            mbs(read_back - fetched)
        );
    }
}
