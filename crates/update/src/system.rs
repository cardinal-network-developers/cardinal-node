//! The outside world, behind traits so tests never touch the real user
//! session: running commands (`systemctl --user`, `loginctl`, the new
//! binary) and asking the user questions.

use std::ffi::OsStr;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::paths::{Paths, UNIT_NAME};

/// What a command did.
#[derive(Debug, Clone, Default)]
pub struct Output {
    /// Whether it exited with status zero.
    pub success: bool,
    /// Its standard output.
    pub stdout: String,
    /// Its standard error.
    pub stderr: String,
}

/// Runs external commands.
pub trait Runner {
    /// Runs `program` with `args`, waiting at most `timeout`. An `Err` means
    /// it could not be started (or timed out), not that it failed.
    fn run(&self, program: &OsStr, args: &[&OsStr], timeout: Duration) -> io::Result<Output>;
}

/// Runs commands for real.
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, program: &OsStr, args: &[&OsStr], timeout: Duration) -> io::Result<Output> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        // Drain pipes on threads so a chatty child cannot block.
        let mut out = child.stdout.take().unwrap();
        let mut err = child.stderr.take().unwrap();
        let t_out = std::thread::spawn(move || {
            let mut s = Vec::new();
            let _ = out.read_to_end(&mut s);
            s
        });
        let t_err = std::thread::spawn(move || {
            let mut s = Vec::new();
            let _ = err.read_to_end(&mut s);
            s
        });
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break s;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{} timed out", program.to_string_lossy()),
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        Ok(Output {
            success: status.success(),
            stdout: String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned(),
            stderr: String::from_utf8_lossy(&t_err.join().unwrap_or_default()).into_owned(),
        })
    }
}

/// Asks the user things.
pub trait Prompt {
    /// Shows `question` and reads one line, without its newline. `None`
    /// means nobody can answer (no terminal).
    fn ask(&self, question: &str) -> Option<String>;
}

/// Asks on the controlling terminal (`/dev/tty`), so it works even when
/// standard input is a pipe, as under `curl ... | sh`.
pub struct TtyPrompt;

impl Prompt for TtyPrompt {
    fn ask(&self, question: &str) -> Option<String> {
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()?;
        let mut w = &tty;
        w.write_all(question.as_bytes()).ok()?;
        w.flush().ok()?;
        let mut line = String::new();
        io::BufReader::new(&tty).read_line(&mut line).ok()?;
        Some(line.trim_end_matches(['\r', '\n']).to_string())
    }
}

/// Everything an operation needs from its environment.
pub struct Ctx<'a> {
    /// Where things go.
    pub paths: Paths,
    /// Runs commands.
    pub runner: &'a dyn Runner,
    /// Asks questions.
    pub prompt: &'a dyn Prompt,
    /// The key release manifests must be signed with.
    pub release_key: Option<[u8; 32]>,
    /// This binary's target triple.
    pub target: String,
    /// How long to wait for the service to come up after an update.
    pub health_timeout: Duration,
    /// How often to poll it, and how long it must stay up.
    pub health_poll: Duration,
    /// Whether downgrades are allowed (`CARDINAL_ALLOW_DOWNGRADE=1`).
    pub allow_downgrade: bool,
}

/// Command timeout for systemctl and friends.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

impl Ctx<'_> {
    /// Runs `systemctl --user <args>`.
    pub fn systemctl(&self, args: &[&str]) -> io::Result<Output> {
        let mut full: Vec<&OsStr> = vec![OsStr::new("--user")];
        full.extend(args.iter().map(OsStr::new));
        self.runner
            .run(OsStr::new("systemctl"), &full, COMMAND_TIMEOUT)
    }

    /// Runs `systemctl --user <args>`, turning failure into an error that
    /// carries systemctl's own message.
    pub fn systemctl_ok(&self, args: &[&str]) -> anyhow::Result<()> {
        let o = self
            .systemctl(args)
            .map_err(|e| anyhow::anyhow!("could not run systemctl: {e}"))?;
        if o.success {
            Ok(())
        } else {
            anyhow::bail!(
                "systemctl --user {} failed: {}",
                args.join(" "),
                o.stderr.trim()
            )
        }
    }

    /// Whether `systemctl --user` works here at all.
    pub fn have_user_systemd(&self) -> bool {
        self.systemctl(&["show-environment"])
            .map(|o| o.success)
            .unwrap_or(false)
    }

    /// The service's state (`active`, `inactive`, `failed`, ...).
    pub fn service_state(&self) -> String {
        match self.systemctl(&["is-active", UNIT_NAME]) {
            Ok(o) => {
                let s = o.stdout.trim();
                if s.is_empty() {
                    "unknown".to_string()
                } else {
                    s.to_string()
                }
            }
            Err(_) => "unknown".to_string(),
        }
    }

    /// Runs `binary version` and returns the version from its first line.
    pub fn binary_version(&self, binary: &Path) -> anyhow::Result<String> {
        let o = self
            .runner
            .run(
                binary.as_os_str(),
                &[OsStr::new("version")],
                Duration::from_secs(30),
            )
            .map_err(|e| anyhow::anyhow!("could not run {}: {e}", binary.display()))?;
        if !o.success {
            anyhow::bail!("{} version failed: {}", binary.display(), o.stderr.trim());
        }
        o.stdout
            .lines()
            .next()
            .and_then(|l| l.strip_prefix("cardinal "))
            .map(|v| v.trim().to_string())
            .ok_or_else(|| {
                anyhow::anyhow!("{} version printed something unexpected", binary.display())
            })
    }

    /// Waits until the service is active and stays active for one more
    /// poll, or `health_timeout` passes.
    pub fn wait_service_healthy(&self) -> Result<(), String> {
        let deadline = Instant::now() + self.health_timeout;
        let mut was_active = false;
        loop {
            let state = self.service_state();
            if state == "active" {
                if was_active {
                    return Ok(());
                }
                was_active = true;
            } else {
                was_active = false;
            }
            if Instant::now() >= deadline {
                return Err(state);
            }
            std::thread::sleep(self.health_poll);
        }
    }
}

/// Whether `name` is an executable somewhere on `PATH`.
pub fn on_path(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| {
        std::env::split_paths(&p).any(|d| {
            let f = d.join(name);
            f.is_file()
                && std::fs::metadata(&f)
                    .map(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o111 != 0)
                    .unwrap_or(false)
        })
    })
}

/// Whether directory `dir` is on `PATH`.
pub fn dir_on_path(dir: &Path) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d == dir))
}
