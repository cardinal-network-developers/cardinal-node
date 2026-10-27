//! Install, update, rollback, and uninstall against temporary directories,
//! with a fake `systemctl` so nothing touches the real user session.

use std::cell::RefCell;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cardinal_crypto::SigningKey;

use crate::manifest::{self, Artifact, Manifest};
use crate::ops::{self, UpdateOutcome};
use crate::paths::Paths;
use crate::system::{Ctx, Output, Prompt, Runner, SystemRunner};

const TARGET: &str = "x86_64-unknown-linux-gnu";

/// Fakes `systemctl` and `loginctl`; runs anything else (the fake
/// `cardinal` scripts) for real.
struct FakeRunner {
    calls: RefCell<Vec<String>>,
    /// The service reports `failed` while the installed binary contains
    /// this marker.
    bin: PathBuf,
    /// Whether the service is running before any command.
    running: RefCell<bool>,
    systemd: bool,
}

impl FakeRunner {
    fn new(paths: &Paths) -> FakeRunner {
        FakeRunner {
            calls: RefCell::new(Vec::new()),
            bin: paths.bin(),
            running: RefCell::new(true),
            systemd: true,
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    fn systemctl_calls(&self) -> Vec<String> {
        self.calls()
            .into_iter()
            .filter(|c| {
                c.starts_with("systemctl")
                    && !c.contains("is-active")
                    && !c.contains("show-environment")
            })
            .collect()
    }
}

fn ok(stdout: &str) -> io::Result<Output> {
    Ok(Output {
        success: true,
        stdout: stdout.into(),
        stderr: String::new(),
    })
}

impl Runner for FakeRunner {
    fn run(&self, program: &OsStr, args: &[&OsStr], timeout: Duration) -> io::Result<Output> {
        let line = std::iter::once(program)
            .chain(args.iter().copied())
            .map(|s| s.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        self.calls.borrow_mut().push(line);
        let args: Vec<String> = args.iter().map(|a| a.to_string_lossy().into()).collect();
        match program.to_str() {
            Some("systemctl") => {
                if !self.systemd {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "no systemctl"));
                }
                assert_eq!(args[0], "--user", "systemctl must only be used with --user");
                match args[1].as_str() {
                    "is-active" => {
                        let broken = fs::read_to_string(&self.bin)
                            .map(|s| s.contains("BROKEN"))
                            .unwrap_or(false);
                        let state = if !*self.running.borrow() {
                            "inactive"
                        } else if broken {
                            "failed"
                        } else {
                            "active"
                        };
                        Ok(Output {
                            success: state == "active",
                            stdout: format!("{state}\n"),
                            stderr: String::new(),
                        })
                    }
                    "start" | "restart" => {
                        *self.running.borrow_mut() = true;
                        ok("")
                    }
                    "disable" if args.iter().any(|a| a == "--now") => {
                        *self.running.borrow_mut() = false;
                        ok("")
                    }
                    _ => ok(""),
                }
            }
            Some("loginctl") => ok("no\n"),
            _ => {
                // Retry "text file busy": another test thread may briefly
                // hold a write descriptor to a script across its fork.
                let mut tries = 0;
                loop {
                    match SystemRunner.run(
                        program,
                        &args.iter().map(OsStr::new).collect::<Vec<_>>(),
                        timeout,
                    ) {
                        Err(e) if e.raw_os_error() == Some(26) && tries < 50 => {
                            tries += 1;
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        r => return r,
                    }
                }
            }
        }
    }
}

struct FakePrompt(Option<&'static str>);

impl Prompt for FakePrompt {
    fn ask(&self, _: &str) -> Option<String> {
        self.0.map(String::from)
    }
}

/// A fake `cardinal` binary: a script reporting `version`, plus `extra` so
/// otherwise identical versions differ.
fn script(version: &str, extra: &str) -> String {
    format!("#!/bin/sh\n# {extra}\nif [ \"$1\" = version ]; then echo \"cardinal {version}\"; exit 0; fi\nexit 1\n")
}

fn write_exe(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

struct Env {
    _dir: tempfile::TempDir,
    root: PathBuf,
    paths: Paths,
    key: SigningKey,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let paths = Paths::new(root.join("bin"), &root.join("data"), &root.join("config"));
        fs::create_dir_all(&paths.bin_dir).unwrap();
        Env {
            _dir: dir,
            root,
            paths,
            key: SigningKey::from_seed(&[42; 32]),
        }
    }

    fn install_fake(&self, version: &str) {
        write_exe(&self.paths.bin(), &script(version, "installed"));
        // Pretend `cardinal install` wrote the unit.
        fs::create_dir_all(&self.paths.unit_dir).unwrap();
        fs::write(self.paths.unit_file(), ops::unit_file_contents(&self.paths)).unwrap();
    }

    /// Publishes a release into directory `name` under the root; returns
    /// the directory.
    fn release(&self, name: &str, version: &str, binary: &str, key: &SigningKey) -> PathBuf {
        let dir = self.root.join(name);
        fs::create_dir_all(&dir).unwrap();
        let file = format!("cardinal-{version}-{TARGET}");
        fs::write(dir.join(&file), binary).unwrap();
        let m = Manifest {
            version: version.into(),
            commit: None,
            date: None,
            artifacts: vec![Artifact {
                target: TARGET.into(),
                file,
                size: binary.len() as u64,
                blake3: *blake3::hash(binary.as_bytes()).as_bytes(),
                sha256: Some({
                    use sha2::Digest;
                    sha2::Sha256::digest(binary.as_bytes()).into()
                }),
            }],
        };
        let text = m.render();
        fs::write(dir.join("manifest"), &text).unwrap();
        fs::write(
            dir.join("manifest.sig"),
            manifest::sign(key, text.as_bytes()),
        )
        .unwrap();
        dir
    }

    fn ctx<'a>(&self, runner: &'a FakeRunner, prompt: &'a FakePrompt) -> Ctx<'a> {
        Ctx {
            paths: self.paths.clone(),
            runner,
            prompt,
            release_key: Some(self.key.public_key()),
            target: TARGET.into(),
            health_timeout: Duration::from_millis(300),
            health_poll: Duration::from_millis(20),
            allow_downgrade: false,
        }
    }

    fn installed(&self) -> String {
        fs::read_to_string(self.paths.bin()).unwrap()
    }

    /// No temporary files left in the binary directory.
    fn assert_clean(&self) {
        for e in fs::read_dir(&self.paths.bin_dir).unwrap() {
            let n = e.unwrap().file_name().into_string().unwrap();
            assert!(!n.starts_with('.'), "leftover temporary {n}");
        }
    }
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn update_replaces_binary_and_restarts_service() {
    let env = Env::new();
    env.install_fake("0.1.0");
    let new = script("0.2.0", "new");
    let rel = env.release("rel", "0.2.0", &new, &env.key);
    let runner = FakeRunner::new(&env.paths);
    let prompt = FakePrompt(None);
    let ctx = env.ctx(&runner, &prompt);

    let out = ops::update(&ctx, Some(s(&rel)), false).unwrap();
    assert_eq!(out, UpdateOutcome::Updated("0.2.0".into()));
    assert_eq!(env.installed(), new);
    assert_eq!(
        fs::read_to_string(env.paths.previous_bin()).unwrap(),
        script("0.1.0", "installed")
    );
    assert_eq!(
        fs::metadata(env.paths.bin()).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(
        runner.systemctl_calls(),
        vec!["systemctl --user restart cardinal.service"]
    );
    env.assert_clean();

    // Again: nothing to do.
    let out = ops::update(&ctx, Some(s(&rel)), false).unwrap();
    assert_eq!(out, UpdateOutcome::UpToDate("0.2.0".into()));
}

#[test]
fn check_only_reports() {
    let env = Env::new();
    env.install_fake("0.1.0");
    let rel = env.release("rel", "0.2.0", &script("0.2.0", "new"), &env.key);
    let runner = FakeRunner::new(&env.paths);
    let prompt = FakePrompt(None);
    let ctx = env.ctx(&runner, &prompt);
    let out = ops::update(&ctx, Some(s(&rel)), true).unwrap();
    assert_eq!(out, UpdateOutcome::Available("0.2.0".into()));
    assert_eq!(env.installed(), script("0.1.0", "installed"));
    assert!(runner.systemctl_calls().is_empty());
}

#[test]
fn refuses_downgrade_unless_allowed() {
    let env = Env::new();
    env.install_fake("0.3.0");
    let old = script("0.2.0", "old");
    let rel = env.release("rel", "0.2.0", &old, &env.key);
    let runner = FakeRunner::new(&env.paths);
    let prompt = FakePrompt(None);
    let mut ctx = env.ctx(&runner, &prompt);

    let e = ops::update(&ctx, Some(s(&rel)), false).unwrap_err();
    assert!(format!("{e:#}").contains("refusing to downgrade"), "{e:#}");
    assert_eq!(env.installed(), script("0.3.0", "installed"));

    ctx.allow_downgrade = true;
    ops::update(&ctx, Some(s(&rel)), false).unwrap();
    assert_eq!(env.installed(), old);
}

#[test]
fn rejects_bad_signature() {
    let env = Env::new();
    env.install_fake("0.1.0");
    let impostor = SigningKey::from_seed(&[7; 32]);
    let rel = env.release("rel", "0.2.0", &script("0.2.0", "evil"), &impostor);
    let runner = FakeRunner::new(&env.paths);
    let prompt = FakePrompt(None);
    let ctx = env.ctx(&runner, &prompt);
    let e = ops::update(&ctx, Some(s(&rel)), false).unwrap_err();
    assert!(format!("{e:#}").contains("signature"), "{e:#}");
    assert_eq!(env.installed(), script("0.1.0", "installed"));

    // A build with no release key refuses every update.
    let mut ctx = env.ctx(&runner, &prompt);
    ctx.release_key = None;
    let good = env.release("good", "0.2.0", &script("0.2.0", "new"), &env.key);
    assert!(ops::update(&ctx, Some(s(&good)), false).is_err());
    assert!(runner.systemctl_calls().is_empty());
}

#[test]
fn rejects_hash_and_size_mismatch() {
    let env = Env::new();
    env.install_fake("0.1.0");
    let new = script("0.2.0", "new");
    let rel = env.release("rel", "0.2.0", &new, &env.key);
    let artifact = rel.join(format!("cardinal-0.2.0-{TARGET}"));
    let runner = FakeRunner::new(&env.paths);
    let prompt = FakePrompt(None);
    let ctx = env.ctx(&runner, &prompt);

    // Same size, different bytes.
    fs::write(&artifact, new.replace("new", "bad")).unwrap();
    let e = ops::update(&ctx, Some(s(&rel)), false).unwrap_err();
    assert!(format!("{e:#}").contains("BLAKE3"), "{e:#}");
    env.assert_clean();

    // Longer than the manifest says.
    fs::write(&artifact, format!("{new}#")).unwrap();
    let e = ops::update(&ctx, Some(s(&rel)), false).unwrap_err();
    assert!(format!("{e:#}").contains("larger than expected"), "{e:#}");

    // Shorter.
    fs::write(&artifact, &new[..new.len() - 1]).unwrap();
    let e = ops::update(&ctx, Some(s(&rel)), false).unwrap_err();
    assert!(format!("{e:#}").contains("bytes"), "{e:#}");

    assert_eq!(env.installed(), script("0.1.0", "installed"));
    assert!(!env.paths.previous_bin().exists());
    assert!(runner.systemctl_calls().is_empty());
    env.assert_clean();
}

#[test]
fn rejects_binary_that_lies_about_its_version() {
    let env = Env::new();
    env.install_fake("0.1.0");
    let rel = env.release("rel", "0.2.0", &script("0.9.9", "liar"), &env.key);
    let runner = FakeRunner::new(&env.paths);
    let prompt = FakePrompt(None);
    let ctx = env.ctx(&runner, &prompt);
    let e = ops::update(&ctx, Some(s(&rel)), false).unwrap_err();
    assert!(format!("{e:#}").contains("reports version 0.9.9"), "{e:#}");
    assert_eq!(env.installed(), script("0.1.0", "installed"));
    env.assert_clean();
}

#[test]
fn rolls_back_when_service_fails() {
    let env = Env::new();
    env.install_fake("0.1.0");
    let rel = env.release("rel", "0.2.0", &script("0.2.0", "BROKEN"), &env.key);
    let runner = FakeRunner::new(&env.paths);
    let prompt = FakePrompt(None);
    let ctx = env.ctx(&runner, &prompt);
    let e = ops::update(&ctx, Some(s(&rel)), false).unwrap_err();
    let msg = format!("{e:#}");
    assert!(msg.contains("Rolled back to 0.1.0"), "{msg}");
    assert!(msg.contains("state: failed"), "{msg}");
    assert_eq!(env.installed(), script("0.1.0", "installed"));
    // Restarted onto the new binary, then back onto the old one.
    assert_eq!(
        runner.systemctl_calls(),
        vec![
            "systemctl --user restart cardinal.service",
            "systemctl --user restart cardinal.service"
        ]
    );
    assert_eq!(ctx.service_state(), "active");
    env.assert_clean();
}

#[test]
fn stopped_service_is_not_started_by_update() {
    let env = Env::new();
    env.install_fake("0.1.0");
    let rel = env.release("rel", "0.2.0", &script("0.2.0", "new"), &env.key);
    let runner = FakeRunner::new(&env.paths);
    *runner.running.borrow_mut() = false;
    let prompt = FakePrompt(None);
    let ctx = env.ctx(&runner, &prompt);
    ops::update(&ctx, Some(s(&rel)), false).unwrap();
    assert!(runner.systemctl_calls().is_empty());
}

#[test]
fn default_sources() {
    let env = Env::new();
    let runner = FakeRunner::new(&env.paths);
    let prompt = FakePrompt(None);
    let ctx = env.ctx(&runner, &prompt);

    // A stable install with no configured source explains what to do.
    env.install_fake("0.1.0");
    let e = ops::update(&ctx, None, false).unwrap_err();
    assert!(format!("{e:#}").contains("no release source is configured"));

    // A dev install defaults to the dev release directory.
    env.install_fake("0.1.0-dev.1");
    let new = script("0.1.0-dev.2", "new");
    let dev = &env.paths.dev_releases;
    let made = env.release("dev", "0.1.0-dev.2", &new, &env.key);
    fs::create_dir_all(dev.parent().unwrap()).unwrap();
    fs::rename(made, dev).unwrap();
    ops::update(&ctx, None, false).unwrap();
    assert_eq!(env.installed(), new);

    // A configured source wins.
    let rel = env.release("rel", "0.1.0", &script("0.1.0", "stable"), &env.key);
    fs::create_dir_all(&env.paths.config_dir).unwrap();
    fs::write(
        env.paths.config_file(),
        format!("[update]\nsource = \"{}\"\n", s(&rel)),
    )
    .unwrap();
    assert_eq!(
        ops::update(&ctx, None, true).unwrap(),
        UpdateOutcome::Available("0.1.0".into())
    );
}

#[test]
fn install_is_idempotent_and_asks_before_replacing() {
    let env = Env::new();
    let exe = env.root.join("downloaded-cardinal");
    write_exe(&exe, &script("0.2.0", "exe"));
    let runner = FakeRunner::new(&env.paths);
    *runner.running.borrow_mut() = false;
    let prompt = FakePrompt(None);
    let ctx = env.ctx(&runner, &prompt);

    ops::install(&ctx, &exe, false).unwrap();
    assert_eq!(env.installed(), script("0.2.0", "exe"));
    let unit = fs::read_to_string(env.paths.unit_file()).unwrap();
    assert!(unit.contains(&format!("ExecStart=\"{}\" daemon", s(&env.paths.bin()))));
    assert!(unit.contains("Restart=on-failure"));
    assert!(env.paths.config_file().exists());
    assert_eq!(
        fs::metadata(&env.paths.data_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        runner.systemctl_calls(),
        vec![
            "systemctl --user daemon-reload",
            "systemctl --user enable cardinal.service",
            "systemctl --user start cardinal.service"
        ]
    );

    // Again: nothing changes, nothing is asked, the service is left alone.
    runner.calls.borrow_mut().clear();
    fs::write(env.paths.config_file(), "# mine\n").unwrap();
    ops::install(&ctx, &exe, false).unwrap();
    assert_eq!(
        fs::read_to_string(env.paths.config_file()).unwrap(),
        "# mine\n"
    );
    assert_eq!(
        runner.systemctl_calls(),
        vec![
            "systemctl --user daemon-reload",
            "systemctl --user enable cardinal.service"
        ]
    );

    // A different binary: refused without a terminal, unless forced.
    let other = env.root.join("other");
    write_exe(&other, &script("0.3.0", "other"));
    let e = ops::install(&ctx, &other, false).unwrap_err();
    assert!(format!("{e:#}").contains("--force"), "{e:#}");
    let yes = FakePrompt(Some("n"));
    let ctx_no = env.ctx(&runner, &yes);
    assert!(ops::install(&ctx_no, &other, false).is_err());
    assert_eq!(env.installed(), script("0.2.0", "exe"));

    runner.calls.borrow_mut().clear();
    ops::install(&ctx, &other, true).unwrap();
    assert_eq!(env.installed(), script("0.3.0", "other"));
    assert_eq!(
        fs::read_to_string(env.paths.previous_bin()).unwrap(),
        script("0.2.0", "exe")
    );
    // The running service is restarted onto the new binary.
    assert!(runner
        .systemctl_calls()
        .contains(&"systemctl --user restart cardinal.service".to_string()));
    env.assert_clean();
}

#[test]
fn install_without_systemd_still_installs() {
    let env = Env::new();
    let exe = env.root.join("exe");
    write_exe(&exe, &script("0.2.0", "exe"));
    let mut runner = FakeRunner::new(&env.paths);
    runner.systemd = false;
    let prompt = FakePrompt(None);
    let ctx = env.ctx(&runner, &prompt);
    ops::install(&ctx, &exe, false).unwrap();
    assert!(env.paths.bin().exists());
    assert!(env.paths.unit_file().exists());
}

#[test]
fn uninstall_keeps_data_and_purge_needs_confirmation() {
    let env = Env::new();
    let exe = env.root.join("exe");
    write_exe(&exe, &script("0.2.0", "exe"));
    let runner = FakeRunner::new(&env.paths);
    let none = FakePrompt(None);
    let ctx = env.ctx(&runner, &none);
    ops::install(&ctx, &exe, false).unwrap();
    fs::write(env.paths.data_dir.join("keys"), "precious").unwrap();

    // Purge without a terminal, or with the wrong answer, removes nothing.
    for answer in [None, Some("y"), Some("yes"), Some("DELETE")] {
        let p = FakePrompt(answer);
        let c = env.ctx(&runner, &p);
        assert!(ops::uninstall(&c, true).is_err());
        assert!(env.paths.bin().exists());
        assert!(env.paths.unit_file().exists());
    }

    // Plain uninstall keeps data.
    runner.calls.borrow_mut().clear();
    ops::uninstall(&ctx, false).unwrap();
    assert!(!env.paths.bin().exists());
    assert!(!env.paths.unit_file().exists());
    assert!(env.paths.data_dir.join("keys").exists());
    assert!(env.paths.config_file().exists());
    assert_eq!(
        runner.systemctl_calls()[0],
        "systemctl --user disable --now cardinal.service"
    );

    // Purge with the word deletes everything.
    let p = FakePrompt(Some("delete"));
    let c = env.ctx(&runner, &p);
    ops::uninstall(&c, true).unwrap();
    assert!(!env.paths.data_dir.exists());
    assert!(!env.paths.config_dir.exists());
}
