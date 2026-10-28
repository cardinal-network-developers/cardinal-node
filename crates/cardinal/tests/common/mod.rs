//! Helpers shared by the end-to-end tests: daemons with their own data
//! directories and ports on one machine, driven through the real binary.

#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

pub const BIN: &str = env!("CARGO_BIN_EXE_cardinal");

pub struct Dev {
    pub name: &'static str,
    pub home: PathBuf,
    pub mount: PathBuf,
    pub port: u16,
    pub child: Option<Child>,
    /// Extra environment for the daemon and the command line.
    pub env: Vec<(String, String)>,
}

impl Dev {
    pub fn new(root: &Path, name: &'static str, port: u16) -> Dev {
        let home = root.join(name);
        let mount = root.join(format!("mnt-{name}"));
        std::fs::create_dir_all(&home).unwrap();
        Dev {
            name,
            home,
            mount,
            port,
            child: None,
            env: Vec::new(),
        }
    }

    pub fn cmd(&self) -> Command {
        let mut c = Command::new(BIN);
        c.env("CARDINAL_HOME", &self.home)
            .env("CARDINAL_SOCKET", self.home.join("control.sock"))
            .env("CARDINAL_LOG", "info,cardinald=debug");
        for (k, v) in &self.env {
            c.env(k, v);
        }
        c
    }

    pub fn start(&mut self) {
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

    pub fn try_cli(&self, args: &[&str]) -> Output {
        self.cmd().args(args).output().unwrap()
    }

    pub fn cli(&self, args: &[&str]) -> String {
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

    pub fn status(&self) -> serde_json::Value {
        serde_json::from_str(&self.cli(&["status", "--json"])).unwrap()
    }

    pub fn wait_mounted(&self) {
        wait(&format!("{} mounted", self.name), 60, || {
            self.status()["mounted"].is_string()
        });
    }

    pub fn stop(&mut self) {
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

    pub fn p(&self, rel: &str) -> PathBuf {
        self.mount.join(rel)
    }

    pub fn log(&self) -> String {
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

pub fn wait(what: &str, secs: u64, mut f: impl FnMut() -> bool) -> Duration {
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

pub fn dir_size(p: &Path) -> u64 {
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

pub fn read(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

pub fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists()
        && Command::new("fusermount3")
            .arg("-V")
            .output()
            .is_ok_and(|o| o.status.success())
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub fn pair(a: &Dev, b: &Dev) {
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
