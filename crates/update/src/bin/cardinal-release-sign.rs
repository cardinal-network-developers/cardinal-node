//! Release signing helper for `scripts/release.sh`.
//!
//! ```text
//! cardinal-release-sign keygen --secret KEY --public PUB
//! cardinal-release-sign manifest --version V [--commit C] [--date D] --out FILE TARGET=PATH...
//! cardinal-release-sign sign --secret KEY --public PUB MANIFEST
//! cardinal-release-sign verify --public PUB MANIFEST
//! cardinal-release-sign fingerprint --public PUB
//! ```
//!
//! Key files are hex text: the secret key file holds the 32-byte Ed25519
//! seed and is created with mode 0600; the public key file holds the
//! 32-byte public key.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use cardinal_crypto::{SigningKey, Zeroizing};
use cardinal_update::build_info::key_fingerprint;
use cardinal_update::manifest::{self, Artifact, Manifest};
use clap::{Parser, Subcommand};
use sha2::Digest;

#[derive(Parser)]
#[command(
    name = "cardinal-release-sign",
    about = "Sign Cardinal release manifests"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a release key pair. Refuses to overwrite an existing key.
    Keygen {
        #[arg(long)]
        secret: PathBuf,
        #[arg(long)]
        public: PathBuf,
    },
    /// Write a manifest for artifacts given as TARGET=PATH.
    Manifest {
        #[arg(long)]
        version: String,
        #[arg(long)]
        commit: Option<String>,
        #[arg(long)]
        date: Option<String>,
        #[arg(long)]
        out: PathBuf,
        #[arg(required = true)]
        artifacts: Vec<String>,
    },
    /// Sign MANIFEST, writing MANIFEST.sig. The secret key must match PUB
    /// (the key compiled into binaries), so a release can never be signed
    /// with a key that installed binaries do not trust.
    Sign {
        #[arg(long)]
        secret: PathBuf,
        #[arg(long)]
        public: PathBuf,
        manifest: PathBuf,
    },
    /// Verify MANIFEST against MANIFEST.sig and PUB.
    Verify {
        #[arg(long)]
        public: PathBuf,
        manifest: PathBuf,
    },
    /// Print the fingerprint of PUB, as `cardinal version` shows it.
    Fingerprint {
        #[arg(long)]
        public: PathBuf,
    },
}

fn read_hex32(path: &Path) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let text = Zeroizing::new(
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
    );
    let hex: Zeroizing<String> = Zeroizing::new(
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect(),
    );
    let mut out = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(hex.as_bytes(), &mut out[..])
        .map_err(|_| anyhow!("{} does not hold a 32-byte hex key", path.display()))?;
    Ok(out)
}

fn load_secret(path: &Path) -> anyhow::Result<SigningKey> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .with_context(|| format!("reading {}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        bail!(
            "{} is readable by others (mode {:o}); run chmod 600 on it",
            path.display(),
            mode & 0o777
        );
    }
    Ok(SigningKey::from_seed(&*read_hex32(path)?))
}

fn hash_file(path: &Path) -> anyhow::Result<(u64, [u8; 32], [u8; 32])> {
    let mut f = fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut b3 = blake3::Hasher::new();
    let mut s = sha2::Sha256::new();
    let mut n = 0u64;
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let k = f.read(&mut buf)?;
        if k == 0 {
            break;
        }
        b3.update(&buf[..k]);
        s.update(&buf[..k]);
        n += k as u64;
    }
    Ok((n, *b3.finalize().as_bytes(), s.finalize().into()))
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen { secret, public } => {
            if secret.exists() {
                bail!(
                    "{} already exists; refusing to overwrite a release key",
                    secret.display()
                );
            }
            if let Some(dir) = secret.parent() {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)?;
            }
            let key = SigningKey::generate();
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&secret)
                .with_context(|| format!("creating {}", secret.display()))?;
            let seed_hex = Zeroizing::new(hex::encode(*key.seed()));
            writeln!(f, "{}", *seed_hex)?;
            f.sync_all()?;
            fs::write(&public, format!("{}\n", hex::encode(key.public_key())))?;
            println!("fingerprint: {}", key_fingerprint(&key.public_key()));
        }
        Cmd::Manifest {
            version,
            commit,
            date,
            out,
            artifacts,
        } => {
            let mut list = Vec::new();
            for spec in artifacts {
                let (target, path) = spec
                    .split_once('=')
                    .ok_or_else(|| anyhow!("artifact {spec:?} is not TARGET=PATH"))?;
                let path = Path::new(path);
                let file = path
                    .file_name()
                    .and_then(|f| f.to_str())
                    .filter(|f| manifest::valid_file_name(f))
                    .ok_or_else(|| anyhow!("unusable artifact file name {}", path.display()))?
                    .to_string();
                let (size, blake3, sha256) = hash_file(path)?;
                list.push(Artifact {
                    target: target.to_string(),
                    file,
                    size,
                    blake3,
                    sha256: Some(sha256),
                });
            }
            let m = Manifest {
                version,
                commit,
                date,
                artifacts: list,
            };
            let text = m.render();
            // Make sure what we write is what binaries will accept.
            if Manifest::parse(&text)? != m {
                bail!("manifest does not round-trip");
            }
            fs::write(&out, text)?;
        }
        Cmd::Sign {
            secret,
            public,
            manifest: path,
        } => {
            let key = load_secret(&secret)?;
            let want = read_hex32(&public)?;
            if key.public_key() != *want {
                bail!(
                    "{} is not the secret key for {} (fingerprints {} vs {}); refusing to sign",
                    secret.display(),
                    public.display(),
                    key_fingerprint(&key.public_key()),
                    key_fingerprint(&want)
                );
            }
            let text = fs::read(&path)?;
            let sig = manifest::sign(&key, &text);
            manifest::verify_and_parse(&want, &text, sig.as_bytes())?;
            let mut sig_path = path.into_os_string();
            sig_path.push(".sig");
            fs::write(&sig_path, sig)?;
        }
        Cmd::Verify {
            public,
            manifest: path,
        } => {
            let key = read_hex32(&public)?;
            let text = fs::read(&path)?;
            let mut sig_path = path.clone().into_os_string();
            sig_path.push(".sig");
            let sig = fs::read(&sig_path)?;
            let m = manifest::verify_and_parse(&key, &text, &sig)?;
            println!(
                "ok: cardinal {} ({} artifacts)",
                m.version,
                m.artifacts.len()
            );
        }
        Cmd::Fingerprint { public } => {
            println!("{}", key_fingerprint(&*read_hex32(&public)?));
        }
    }
    Ok(())
}
