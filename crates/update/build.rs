//! Embeds build information and the release public key.
//!
//! Environment overrides (each triggers a rebuild when it changes):
//!
//! - `CARDINAL_VERSION`: the version to report and compare against
//!   releases (default: the crate version). `scripts/dev-release.sh` sets
//!   it to a `-dev.<timestamp>` pre-release.
//! - `CARDINAL_GIT_COMMIT`: the commit to report (default: `git rev-parse`).
//! - `CARDINAL_BUILD_DATE`: the build date (default: today, UTC, or
//!   `SOURCE_DATE_EPOCH` when set).
//! - `CARDINAL_RELEASE_PUBKEY_FILE`: the release public key to embed
//!   (default: `packaging/release-key.pub` at the workspace root). Tests use
//!   this to build against a throwaway key.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace = manifest_dir.join("../..");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed=build.rs");
    for var in [
        "CARDINAL_VERSION",
        "CARDINAL_GIT_COMMIT",
        "CARDINAL_BUILD_DATE",
        "CARDINAL_RELEASE_PUBKEY_FILE",
        "SOURCE_DATE_EPOCH",
    ] {
        println!("cargo:rerun-if-env-changed={var}");
    }

    // Version.
    let version = env::var("CARDINAL_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| env::var("CARGO_PKG_VERSION").unwrap());
    if !version
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
        || !version.starts_with(|c: char| c.is_ascii_digit())
    {
        panic!("CARDINAL_VERSION {version:?} is not a semantic version");
    }
    println!("cargo:rustc-env=CARDINAL_VERSION={version}");

    // Target triple.
    println!(
        "cargo:rustc-env=CARDINAL_TARGET={}",
        env::var("TARGET").unwrap()
    );

    // Commit.
    let commit = env::var("CARDINAL_GIT_COMMIT")
        .ok()
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| git_commit(&workspace));
    println!("cargo:rustc-env=CARDINAL_GIT_COMMIT={commit}");

    // Date.
    let date = env::var("CARDINAL_BUILD_DATE")
        .ok()
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| {
            let secs = env::var("SOURCE_DATE_EPOCH")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or_else(|| {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                });
            civil_date(secs)
        });
    println!("cargo:rustc-env=CARDINAL_BUILD_DATE={date}");

    // Release public key.
    let key_path = env::var_os("CARDINAL_RELEASE_PUBKEY_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace.join("packaging/release-key.pub"));
    println!("cargo:rerun-if-changed={}", key_path.display());
    let key = match fs::read_to_string(&key_path) {
        Ok(text) => Some(
            parse_key(&text)
                .unwrap_or_else(|e| panic!("release public key {}: {e}", key_path.display())),
        ),
        Err(_) => {
            println!(
                "cargo:warning=no release public key at {}; this build cannot verify updates",
                key_path.display()
            );
            None
        }
    };
    let code = match key {
        Some(k) => format!("Some({k:?})"),
        None => "None".to_string(),
    };
    fs::write(
        out.join("release_key.rs"),
        format!("/// The embedded release public key.\npub const RELEASE_PUBLIC_KEY: Option<[u8; 32]> = {code};\n"),
    )
    .unwrap();
}

/// Parses a public key file: 64 hex digits, optionally surrounded by
/// whitespace, with `#` comment lines allowed.
fn parse_key(text: &str) -> Result<[u8; 32], String> {
    let hex: String = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if hex.len() != 64 {
        return Err(format!("expected 64 hex digits, found {}", hex.len()));
    }
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(key)
}

fn git_commit(workspace: &Path) -> String {
    let run = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(workspace)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    // Rebuild when HEAD moves.
    if let Some(dir) = run(&["rev-parse", "--absolute-git-dir"]) {
        println!("cargo:rerun-if-changed={dir}/HEAD");
        if let Some(r) = run(&["symbolic-ref", "-q", "HEAD"]) {
            println!("cargo:rerun-if-changed={dir}/{r}");
        }
    }
    match run(&["rev-parse", "--short=12", "HEAD"]) {
        Some(c) => {
            let dirty = run(&["status", "--porcelain", "--untracked-files=no"])
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            if dirty {
                format!("{c}-dirty")
            } else {
                c
            }
        }
        None => "unknown".to_string(),
    }
}

/// Days since the epoch to a proleptic Gregorian `YYYY-MM-DD` (Howard
/// Hinnant's `civil_from_days`).
fn civil_date(secs: u64) -> String {
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}
