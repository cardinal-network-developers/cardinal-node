//! Helpers shared by the end-to-end tests: daemons with their own data
//! directories and ports on one machine, driven through the real binary.

#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

pub const BIN: &str = env!("CARGO_BIN_EXE_cardinal");

/// A connection to a service's local interface, which speaks its requests
/// and replies by name (`cardinald::api`).
pub use cardinald::api::blocking::Client;

/// Asks the service on `socket`: `req` names the request in `cmd`, with its
/// arguments by name. The reply is by name too, with `ok`, and `error` when
/// it is not.
pub fn reply_at(socket: &Path, req: &serde_json::Value) -> serde_json::Value {
    let mut c = Client::connect(socket)
        .unwrap_or_else(|e| panic!("no service at {}: {e}", socket.display()));
    c.ask(req).unwrap_or_else(|e| panic!("{req}: {e:#}"))
}

/// A client's end of a call's media (`call-media`): frames by name, as
/// `{"audio": hex}` and, in a group, `from`; or `{"frame": hex, "format":
/// hex}`.
pub struct Media {
    c: Client,
    open: bool,
}

impl Media {
    /// Asks for the call's media; a receive then waits at most `wait`.
    /// Without a call the service says so and the connection carries
    /// nothing.
    pub fn open(d: &Dev, wait: Duration) -> Media {
        let mut c = d.connect();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let r = c.ask(&serde_json::json!({"cmd": "call-media"})).unwrap();
        c.set_read_timeout(Some(wait)).unwrap();
        Media {
            c,
            open: r["ok"] == true,
        }
    }

    /// How long a receive waits from now on.
    pub fn set_wait(&mut self, wait: Duration) {
        self.c.set_read_timeout(Some(wait)).unwrap();
    }

    /// Sends a frame; one the service no longer takes is lost, as a
    /// datagram is.
    pub fn send(&mut self, frame: &serde_json::Value) {
        if self.open {
            let _ = self.c.send_frame(frame);
        }
    }

    /// The next frame, or `None` when none came in time or the media ended.
    pub fn next(&mut self) -> Option<serde_json::Value> {
        if !self.open {
            return None;
        }
        self.c.frame().ok().flatten()
    }
}

/// [`reply_at`] a device's service.
pub fn reply(d: &Dev, req: &serde_json::Value) -> serde_json::Value {
    reply_at(&d.socket(), req)
}

/// [`reply`], which must be `ok`.
pub fn ask(d: &Dev, req: &serde_json::Value) -> serde_json::Value {
    let r = reply(d, req);
    assert_eq!(r["ok"], true, "{} asked {req}: {r}", d.name);
    r
}

pub struct Dev {
    pub name: &'static str,
    pub home: PathBuf,
    pub mount: PathBuf,
    pub port: u16,
    pub child: Option<Child>,
    /// The binary this device runs.
    pub bin: PathBuf,
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
            bin: BIN.into(),
            // Whether the test machine is plugged in is not under test.
            env: vec![(
                "CARDINAL_TEST_POWER_SUPPLIES".into(),
                "/nothing/here".into(),
            )],
        }
    }

    /// Where its service listens.
    pub fn socket(&self) -> PathBuf {
        self.home.join("control.sock")
    }

    /// A connection to its service.
    pub fn connect(&self) -> Client {
        Client::connect(&self.socket()).expect("the service listens")
    }

    pub fn cmd(&self) -> Command {
        let mut c = Command::new(&self.bin);
        c.env("CARDINAL_HOME", &self.home)
            .env("CARDINAL_SOCKET", self.home.join("control.sock"))
            .env("CARDINAL_LOG", "info,cardinald=debug");
        for (k, v) in &self.env {
            c.env(k, v);
        }
        c
    }

    pub fn start(&mut self) {
        self.start_with(&[]);
    }

    /// Starts the daemon with `args` too.
    pub fn start_with(&mut self, args: &[&str]) {
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
            .args(args)
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

    /// Runs the command line with `input` on its standard input.
    pub fn cli_input(&self, args: &[&str], input: &str) -> Output {
        let mut c = self
            .cmd()
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(&mut c.stdin.take().unwrap(), input.as_bytes()).unwrap();
        c.wait_with_output().unwrap()
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
        // A test may have paused it (SIGSTOP) and failed before going on:
        // a paused daemon never answers `stop`, and the test would hang.
        if let Some(c) = &self.child {
            let _ = Command::new("kill")
                .args(["-CONT", &c.id().to_string()])
                .status();
        }
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
    // A daemon takes the port on both carriers, and tests run side by side.
    static GIVEN: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());
    loop {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        let mut given = GIVEN.lock().unwrap();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() && !given.contains(&port) {
            given.push(port);
            return port;
        }
    }
}

pub fn pair(a: &Dev, b: &Dev) {
    let typed = pair_as(a, b, false, None);
    assert!(typed.contains("Added"), "{typed}");
}

/// Pairs `b` to `a`: `b` shows a code (asking to be an admin device if
/// `admin`), and `a` types it, with `stdin` as its input (the recovery
/// words, when `a` is not an admin device). Returns what `a` printed.
pub fn pair_as(a: &Dev, b: &Dev, admin: bool, stdin: Option<&str>) -> String {
    pair_with(a, b, admin, stdin, &[], &[])
}

/// [`pair_as`], with more arguments for the device that shows the code
/// (`shows`) and the one that types it (`types`).
pub fn pair_with(
    a: &Dev,
    b: &Dev,
    admin: bool,
    stdin: Option<&str>,
    shows: &[&str],
    types: &[&str],
) -> String {
    let mut shower = b.cmd();
    shower.arg("pair").args(shows);
    if admin {
        shower.arg("--admin");
    }
    let mut shower = shower
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
    let mut typing = vec!["pair", &code, "--at", &at];
    typing.extend_from_slice(types);
    let o = a.cli_input(&typing, stdin.unwrap_or(""));
    let typed = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(
        o.status.success(),
        "{typed}{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut out, &mut rest).unwrap();
    assert!(shower.wait().unwrap().success(), "{rest}");
    assert!(rest.contains("Done"), "{rest}");
    // Joining brings several spaces at once, each a reason to mount: the
    // files are mounted once.
    b.wait_mounted();
    assert!(!b.log().contains("cannot mount"), "{}", b.log());
    typed
}
