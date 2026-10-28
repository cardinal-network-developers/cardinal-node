//! `install`, `update`, and `uninstall`.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{anyhow, bail, Context};
use sha2::Digest;

use crate::build_info;
use crate::config::{Channel, UpdateConfig};
use crate::fsutil::{self, TempFile};
use crate::manifest::{self, Manifest};
use crate::paths::{Paths, UNIT_NAME};
use crate::source::Source;
use crate::system::{self, Ctx};
use crate::version::Version;

// ---------------------------------------------------------------------------
// Unit file.

/// Quotes a value for a systemd unit (`ExecStart=`, `Environment=`).
fn unit_quote(s: &str) -> String {
    let mut q = String::from("\"");
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                q.push('\\');
                q.push(c);
            }
            '%' => q.push_str("%%"),
            '$' => q.push_str("$$"),
            _ => q.push(c),
        }
    }
    q.push('"');
    q
}

/// The systemd user unit for `paths`.
pub fn unit_file_contents(paths: &Paths) -> String {
    let bin = paths.bin();
    format!(
        "# Written by `cardinal install`; rewritten on reinstall.\n\
         [Unit]\n\
         Description=Cardinal sync daemon\n\
         # Best effort: a user manager cannot see the system's network targets,\n\
         # so the daemon must (and does) retry connections on its own.\n\
         After=network-online.target\n\
         StartLimitIntervalSec=300\n\
         StartLimitBurst=5\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exec} daemon\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         TimeoutStopSec=30\n\
         KillMode=mixed\n\
         Environment={data}\n\
         Environment={config}\n\
         Environment=RUST_BACKTRACE=1\n\
         # No NoNewPrivileges=: mounting uses the setuid helper fusermount3.\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        exec = unit_quote(&bin.to_string_lossy()),
        data = unit_quote(&format!("CARDINAL_DATA_DIR={}", paths.data_dir.display())),
        config = unit_quote(&format!(
            "CARDINAL_CONFIG_DIR={}",
            paths.config_dir.display()
        )),
    )
}

// ---------------------------------------------------------------------------
// Install.

fn file_hash(p: &Path) -> std::io::Result<blake3::Hash> {
    let mut h = blake3::Hasher::new();
    h.update_reader(fs::File::open(p)?)?;
    Ok(h.finalize())
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn create_private_dir(p: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if !p.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(p)
            .with_context(|| format!("creating {}", p.display()))?;
    }
    Ok(())
}

/// Installs `exe` (normally the running binary) for the user.
pub fn install(ctx: &Ctx, exe: &Path, force: bool) -> anyhow::Result<()> {
    let paths = &ctx.paths;
    let bin = paths.bin();

    // Prerequisites: warn, never fail; the binary is still useful.
    if !Path::new("/dev/fuse").exists() {
        eprintln!(
            "warning: /dev/fuse does not exist; mounting will not work until the fuse \
             kernel module is available (try: sudo modprobe fuse)"
        );
    }
    if !system::on_path("fusermount3") {
        eprintln!(
            "warning: fusermount3 not found; install your distribution's fuse3 package \
             to mount spaces (e.g. `sudo apt install fuse3`)"
        );
    }

    // The binary.
    fs::create_dir_all(&paths.bin_dir)
        .with_context(|| format!("creating {}", paths.bin_dir.display()))?;
    let mut replaced = false;
    if same_file(exe, &bin) {
        println!("Binary already in place: {}", bin.display());
    } else if bin.exists() && file_hash(&bin).ok() == file_hash(exe).ok() {
        println!("Binary already installed: {}", bin.display());
    } else {
        if bin.exists() && !force {
            let old = ctx
                .binary_version(&bin)
                .unwrap_or_else(|_| "unknown version".into());
            let q = format!(
                "Replace installed cardinal {old} at {} with {}? [y/N] ",
                bin.display(),
                build_info::VERSION
            );
            match ctx.prompt.ask(&q) {
                Some(a) if matches!(a.trim(), "y" | "Y" | "yes") => {}
                Some(_) => bail!("not replacing the installed binary"),
                None => bail!(
                    "cardinal {old} is already installed at {}; rerun with --force to replace it",
                    bin.display()
                ),
            }
        }
        let mut t = TempFile::new_for(&bin, 0o755)?;
        let mut src = fs::File::open(exe).with_context(|| format!("opening {}", exe.display()))?;
        std::io::copy(&mut src, t.file())?;
        fsutil::swap_in(t, &bin, &paths.previous_bin())
            .with_context(|| format!("installing {}", bin.display()))?;
        replaced = true;
        println!("Installed {}", bin.display());
    }

    // Data and configuration.
    create_private_dir(&paths.data_dir)?;
    create_private_dir(&paths.config_dir)?;
    let cfg = paths.config_file();
    if !cfg.exists() {
        fsutil::write_atomic(&cfg, crate::config::template().as_bytes(), 0o600)
            .with_context(|| format!("writing {}", cfg.display()))?;
        println!("Wrote {}", cfg.display());
    }

    // The unit.
    fs::create_dir_all(&paths.unit_dir)?;
    let unit = paths.unit_file();
    let contents = unit_file_contents(paths);
    if fs::read_to_string(&unit).ok().as_deref() != Some(contents.as_str()) {
        fsutil::write_atomic(&unit, contents.as_bytes(), 0o644)
            .with_context(|| format!("writing {}", unit.display()))?;
        println!("Wrote {}", unit.display());
    }

    // The service.
    if ctx.have_user_systemd() {
        ctx.systemctl_ok(&["daemon-reload"])?;
        ctx.systemctl_ok(&["enable", UNIT_NAME])?;
        let state = ctx.service_state();
        if state == "active" && replaced {
            ctx.systemctl_ok(&["restart", UNIT_NAME])?;
        } else if state != "active" {
            ctx.systemctl_ok(&["start", UNIT_NAME])?;
        }
        println!(
            "Service {UNIT_NAME} enabled; state: {} (logs: journalctl --user -u cardinal)",
            ctx.service_state()
        );
        linger_hint(ctx);
    } else {
        eprintln!(
            "warning: `systemctl --user` is not available here (no user session bus?).\n\
             The unit was written to {}; once a user session exists run\n  \
             systemctl --user daemon-reload && systemctl --user enable --now {UNIT_NAME}\n\
             or run `cardinal daemon` yourself.",
            unit.display()
        );
    }

    if !system::dir_on_path(&paths.bin_dir) {
        eprintln!(
            "note: {} is not on your PATH. Add this to your shell profile:\n  \
             export PATH=\"{}:$PATH\"",
            paths.bin_dir.display(),
            paths.bin_dir.display()
        );
    }
    Ok(())
}

fn linger_hint(ctx: &Ctx) {
    let Some(user) = std::env::var_os("USER").filter(|u| !u.is_empty()) else {
        return;
    };
    let o = ctx.runner.run(
        "loginctl".as_ref(),
        &[
            "show-user".as_ref(),
            user.as_os_str(),
            "--property=Linger".as_ref(),
            "--value".as_ref(),
        ],
        std::time::Duration::from_secs(10),
    );
    if let Ok(o) = o {
        if o.success && o.stdout.trim() == "no" {
            println!(
                "note: the service stops when you log out. On a headless server, keep it \
                 running with:\n  loginctl enable-linger {}",
                user.to_string_lossy()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Update.

/// What `update` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// The installed version is current.
    UpToDate(String),
    /// `--check`: this version is available.
    Available(String),
    /// Installed this version.
    Updated(String),
}

/// The version of the installed binary, or this binary's if that fails.
fn installed_version(ctx: &Ctx) -> String {
    let bin = ctx.paths.bin();
    if bin.exists() {
        match ctx.binary_version(&bin) {
            Ok(v) => return v,
            Err(e) => eprintln!("warning: {e}; assuming version {}", build_info::VERSION),
        }
    }
    build_info::VERSION.to_string()
}

/// Where stable releases come from when no source is configured. GitHub
/// serves the newest release's assets under this stable URL. Later this
/// becomes a publisher's space (`later.md`, "Software distribution").
pub const DEFAULT_SOURCE: &str =
    "https://github.com/cardinal-network-developers/cardinal-node/releases/latest/download";

/// Where to fetch releases from.
pub fn resolve_source(ctx: &Ctx, from: Option<&str>, installed: &str) -> anyhow::Result<Source> {
    if let Some(f) = from {
        return Source::parse(f);
    }
    let cfg = UpdateConfig::load(&ctx.paths.config_file())?;
    if let Some(s) = cfg.source {
        return Source::parse(&s);
    }
    let channel = cfg
        .channel
        .unwrap_or(if build_info::is_dev_version(installed) {
            Channel::Dev
        } else {
            Channel::Stable
        });
    if channel == Channel::Dev {
        return Ok(Source::Dir(ctx.paths.dev_releases.clone()));
    }
    Source::parse(DEFAULT_SOURCE)
}

/// Fetches and verifies the manifest at `source`.
pub fn fetch_manifest(ctx: &Ctx, source: &Source) -> anyhow::Result<Manifest> {
    let key = ctx.release_key.ok_or_else(|| {
        anyhow!("this build has no release key compiled in, so it cannot verify updates")
    })?;
    let text = source.read("manifest", manifest::MAX_MANIFEST_LEN)?;
    let sig = source.read("manifest.sig", manifest::MAX_SIGNATURE_LEN)?;
    manifest::verify_and_parse(&key, &text, &sig)
        .with_context(|| format!("release manifest from {source}"))
}

/// Downloads `art` into a temporary file next to `dest`, checking size and
/// hashes.
fn download(source: &Source, art: &manifest::Artifact, dest: &Path) -> anyhow::Result<TempFile> {
    let mut t = TempFile::new_for(dest, 0o755)?;
    let mut r = source.open(&art.file, art.size)?;
    let mut b3 = blake3::Hasher::new();
    let mut s256 = sha2::Sha256::new();
    let mut n = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let k = r
            .read(&mut buf)
            .with_context(|| format!("downloading {}", art.file))?;
        if k == 0 {
            break;
        }
        b3.update(&buf[..k]);
        s256.update(&buf[..k]);
        t.file().write_all(&buf[..k])?;
        n += k as u64;
    }
    if n != art.size {
        bail!(
            "{} is {n} bytes, but the manifest says {}; refusing it",
            art.file,
            art.size
        );
    }
    if b3.finalize().as_bytes() != &art.blake3 {
        bail!(
            "{} does not match its BLAKE3 hash in the signed manifest; refusing it",
            art.file
        );
    }
    if let Some(h) = art.sha256 {
        if s256.finalize().as_slice() != h {
            bail!(
                "{} does not match its SHA-256 in the signed manifest; refusing it",
                art.file
            );
        }
    }
    t.finish()?;
    Ok(t)
}

/// `cardinal update`.
pub fn update(ctx: &Ctx, from: Option<&str>, check: bool) -> anyhow::Result<UpdateOutcome> {
    let paths = &ctx.paths;
    let bin = paths.bin();
    let installed = installed_version(ctx);
    let source = resolve_source(ctx, from, &installed)?;
    let m = fetch_manifest(ctx, &source)?;
    let art = m.artifact_for(&ctx.target).ok_or_else(|| {
        anyhow!(
            "release {} from {source} has no build for {}",
            m.version,
            ctx.target
        )
    })?;

    let have = Version::parse(&installed)?;
    let want = Version::parse(&m.version)?;
    if want == have {
        println!("cardinal {installed} is up to date (source: {source}).");
        return Ok(UpdateOutcome::UpToDate(installed));
    }
    if want < have {
        if !ctx.allow_downgrade {
            bail!(
                "the release at {source} is {}, older than the installed {installed}; \
                 refusing to downgrade (set CARDINAL_ALLOW_DOWNGRADE=1 to force)",
                m.version
            );
        }
        eprintln!(
            "warning: downgrading from {installed} to {} (CARDINAL_ALLOW_DOWNGRADE is set)",
            m.version
        );
    }
    if check {
        println!(
            "Update available: {installed} -> {} (source: {source}). Run `cardinal update` to install it.",
            m.version
        );
        return Ok(UpdateOutcome::Available(m.version));
    }
    if !bin.exists() {
        bail!(
            "cardinal is not installed at {}; run `cardinal install` first",
            bin.display()
        );
    }

    println!(
        "Downloading cardinal {} ({}) from {source}",
        m.version, art.target
    );
    let new = download(&source, art, &bin)?;

    // The new binary must run, and must be what the manifest says it is,
    // before it goes anywhere near the installed one.
    let reported = ctx
        .binary_version(new.path())
        .context("the downloaded binary does not run; installation unchanged")?;
    if reported != m.version {
        bail!(
            "the downloaded binary reports version {reported}, but the manifest says {}; \
             installation unchanged",
            m.version
        );
    }

    let managed = paths.unit_file().exists() && ctx.have_user_systemd();
    let was_running = managed
        && matches!(
            ctx.service_state().as_str(),
            "active" | "activating" | "reloading"
        );

    fsutil::swap_in(new, &bin, &paths.previous_bin())
        .with_context(|| format!("replacing {}", bin.display()))?;

    // Health check.
    let mut problem = match ctx.binary_version(&bin) {
        Ok(v) if v == m.version => None,
        Ok(v) => Some(format!("installed binary reports {v}")),
        Err(e) => Some(e.to_string()),
    };
    if problem.is_none() && was_running {
        if let Err(e) = ctx.systemctl_ok(&["restart", UNIT_NAME]) {
            problem = Some(e.to_string());
        } else if let Err(state) = ctx.wait_service_healthy() {
            problem = Some(format!(
                "the service did not stay active within {}s (state: {state})",
                ctx.health_timeout.as_secs()
            ));
        }
    }

    if let Some(problem) = problem {
        fsutil::roll_back(&bin, &paths.previous_bin())
            .with_context(|| format!("ROLLBACK FAILED; restore {} by hand", bin.display()))?;
        let mut restored = String::new();
        if was_running {
            match ctx.systemctl_ok(&["restart", UNIT_NAME]) {
                Ok(()) => restored = format!(" Service state: {}.", ctx.service_state()),
                Err(e) => restored = format!(" Restarting the service failed too: {e}."),
            }
        }
        bail!(
            "update to {} failed: {problem}. Rolled back to {installed}.{restored} \
             See `journalctl --user -u cardinal` for the new version's output.",
            m.version
        );
    }

    if was_running {
        println!(
            "Updated cardinal {installed} -> {}; service restarted and healthy.",
            m.version
        );
    } else if managed {
        println!(
            "Updated cardinal {installed} -> {}. The service was not running; start it with \
             `systemctl --user start {UNIT_NAME}`.",
            m.version
        );
    } else {
        println!("Updated cardinal {installed} -> {}.", m.version);
    }
    println!(
        "The previous binary is kept at {}.",
        paths.previous_bin().display()
    );
    Ok(UpdateOutcome::Updated(m.version))
}

// ---------------------------------------------------------------------------
// Uninstall.

/// `cardinal uninstall`.
pub fn uninstall(ctx: &Ctx, purge: bool) -> anyhow::Result<()> {
    let paths = &ctx.paths;
    if purge {
        eprintln!(
            "--purge permanently deletes this device's Cardinal data and keys:\n  {}\n  {}\n\
             Anything not synced to another device is lost for good. This cannot be undone.",
            paths.data_dir.display(),
            paths.config_dir.display()
        );
        match ctx.prompt.ask("Type \"delete\" to confirm: ") {
            Some(a) if a.trim() == "delete" => {}
            Some(_) => bail!("not confirmed; nothing was removed"),
            None => bail!("--purge must be confirmed on a terminal; nothing was removed"),
        }
    }

    let systemd = ctx.have_user_systemd();
    if systemd {
        // Fails harmlessly if the unit was never installed.
        let _ = ctx.systemctl(&["disable", "--now", UNIT_NAME]);
    }
    let unit = paths.unit_file();
    remove_file_if_exists(&unit)?;
    if systemd {
        let _ = ctx.systemctl(&["daemon-reload"]);
        let _ = ctx.systemctl(&["reset-failed", UNIT_NAME]);
    }
    remove_file_if_exists(&paths.bin())?;
    remove_file_if_exists(&paths.previous_bin())?;
    println!("Removed the cardinal service and binary.");

    if purge {
        for d in [&paths.data_dir, &paths.config_dir] {
            match fs::remove_dir_all(d) {
                Ok(()) => println!("Deleted {}", d.display()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("deleting {}", d.display())),
            }
        }
    } else {
        println!(
            "Kept your data in {} and settings in {}; `cardinal uninstall --purge` removes them.",
            paths.data_dir.display(),
            paths.config_dir.display()
        );
    }
    Ok(())
}

fn remove_file_if_exists(p: &Path) -> anyhow::Result<()> {
    match fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", p.display())),
    }
}
