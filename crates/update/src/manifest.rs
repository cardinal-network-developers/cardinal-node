//! Release manifests and their detached signatures.
//!
//! A manifest is a small text file in a strict subset of TOML, so that
//! `install.sh` can read it with `sed`:
//!
//! ```text
//! # Cardinal release manifest; verify with manifest.sig.
//! format = 1
//! name = "cardinal"
//! version = "0.1.0"
//! commit = "d01c8fc1a2b3"
//! date = "2026-10-27"
//!
//! [artifact.x86_64-unknown-linux-musl]
//! file = "cardinal-0.1.0-x86_64-unknown-linux-musl"
//! size = 12345678
//! blake3 = "<64 hex digits>"
//! sha256 = "<64 hex digits>"
//! ```
//!
//! `manifest.sig` holds an Ed25519 signature, as 128 hex digits, over
//! [`SIGNING_CONTEXT`] followed by the manifest's exact bytes. The context
//! keeps a release signature from ever being valid for anything else.
//! Signatures are checked before the manifest is parsed.

use anyhow::{anyhow, bail, Context};

/// Domain separation prefix for manifest signatures.
pub const SIGNING_CONTEXT: &[u8] = b"cardinal release manifest v1\n";

/// The largest manifest we will read.
pub const MAX_MANIFEST_LEN: u64 = 64 * 1024;
/// The largest signature file we will read.
pub const MAX_SIGNATURE_LEN: u64 = 1024;

/// One downloadable binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    /// Target triple it runs on.
    pub target: String,
    /// File name, relative to the release source.
    pub file: String,
    /// Exact size in bytes.
    pub size: u64,
    /// BLAKE3 hash of the file.
    pub blake3: [u8; 32],
    /// SHA-256 of the file, for `install.sh` on systems without `b3sum`.
    pub sha256: Option<[u8; 32]>,
}

/// A parsed, verified release manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Release version.
    pub version: String,
    /// Commit the release was built from, if recorded.
    pub commit: Option<String>,
    /// Build date, if recorded.
    pub date: Option<String>,
    /// Binaries, in file order.
    pub artifacts: Vec<Artifact>,
}

/// Signs a manifest: returns the contents of `manifest.sig`.
pub fn sign(key: &cardinal_crypto::SigningKey, manifest: &[u8]) -> String {
    format!("{}\n", hex::encode(key.sign(&signing_message(manifest))))
}

/// Checks `sig_file` (the contents of `manifest.sig`) over `manifest`
/// against `public_key`, then parses the manifest.
pub fn verify_and_parse(
    public_key: &[u8; 32],
    manifest: &[u8],
    sig_file: &[u8],
) -> anyhow::Result<Manifest> {
    let sig_hex = std::str::from_utf8(sig_file)
        .ok()
        .map(str::trim)
        .ok_or_else(|| anyhow!("manifest.sig is not text"))?;
    let sig: [u8; 64] = hex::decode(sig_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| anyhow!("manifest.sig is not a 64-byte hex signature"))?;
    cardinal_crypto::verify(public_key, &signing_message(manifest), &sig).map_err(|_| {
        anyhow!(
            "the release manifest's signature is not valid for this binary's release key \
             ({}); refusing to use it",
            crate::build_info::key_fingerprint(public_key)
        )
    })?;
    let text = std::str::from_utf8(manifest).context("manifest is not UTF-8")?;
    Manifest::parse(text)
}

fn signing_message(manifest: &[u8]) -> Vec<u8> {
    let mut m = SIGNING_CONTEXT.to_vec();
    m.extend_from_slice(manifest);
    m
}

enum Value {
    Str(String),
    Int(u64),
}

impl Manifest {
    /// Parses manifest text. Unknown keys are ignored (for forward
    /// compatibility); anything that is not a comment, a section header, or
    /// a `key = "string"` / `key = integer` line is an error.
    pub fn parse(text: &str) -> anyhow::Result<Manifest> {
        let mut format = None;
        let mut version = None;
        let mut commit = None;
        let mut date = None;
        let mut artifacts: Vec<Artifact> = Vec::new();
        // Fields of the artifact section being read.
        struct Partial {
            target: String,
            file: Option<String>,
            size: Option<u64>,
            blake3: Option<[u8; 32]>,
            sha256: Option<[u8; 32]>,
        }
        let mut current: Option<Partial> = None;
        let finish = |p: Partial, out: &mut Vec<Artifact>| -> anyhow::Result<()> {
            let miss = |f: &str| anyhow!("manifest artifact {} lacks {f}", p.target);
            let a = Artifact {
                file: p.file.clone().ok_or_else(|| miss("file"))?,
                size: p.size.ok_or_else(|| miss("size"))?,
                blake3: p.blake3.ok_or_else(|| miss("blake3"))?,
                sha256: p.sha256,
                target: p.target,
            };
            if out.iter().any(|o| o.target == a.target) {
                bail!("manifest lists target {} twice", a.target);
            }
            out.push(a);
            Ok(())
        };
        let mut in_unknown_section = false;

        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim();
            let lineno = n + 1;
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix('[') {
                let name = rest
                    .strip_suffix(']')
                    .ok_or_else(|| anyhow!("manifest line {lineno}: bad section header"))?
                    .trim();
                if let Some(p) = current.take() {
                    finish(p, &mut artifacts)?;
                }
                in_unknown_section = false;
                match name.strip_prefix("artifact.") {
                    Some(target) if valid_target(target) => {
                        current = Some(Partial {
                            target: target.to_string(),
                            file: None,
                            size: None,
                            blake3: None,
                            sha256: None,
                        });
                    }
                    Some(_) => bail!("manifest line {lineno}: bad target triple"),
                    None => in_unknown_section = true,
                }
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| anyhow!("manifest line {lineno}: expected key = value"))?;
            let key = key.trim();
            let value = parse_value(value.trim())
                .ok_or_else(|| anyhow!("manifest line {lineno}: bad value"))?;
            if in_unknown_section {
                continue;
            }
            let want_str = |v: Value| match v {
                Value::Str(s) => Ok(s),
                Value::Int(_) => Err(anyhow!("manifest line {lineno}: {key} must be a string")),
            };
            match current.as_mut() {
                None => match key {
                    "format" => match value {
                        Value::Int(f) => format = Some(f),
                        Value::Str(_) => bail!("manifest line {lineno}: format must be a number"),
                    },
                    "name" => {
                        let name = want_str(value)?;
                        if name != "cardinal" {
                            bail!("manifest is for {name:?}, not cardinal");
                        }
                    }
                    "version" => version = Some(want_str(value)?),
                    "commit" => commit = Some(want_str(value)?),
                    "date" => date = Some(want_str(value)?),
                    _ => {}
                },
                Some(p) => match key {
                    "file" => {
                        let f = want_str(value)?;
                        if !valid_file_name(&f) {
                            bail!("manifest line {lineno}: unsafe artifact file name {f:?}");
                        }
                        p.file = Some(f);
                    }
                    "size" => match value {
                        Value::Int(s) => p.size = Some(s),
                        Value::Str(_) => bail!("manifest line {lineno}: size must be a number"),
                    },
                    "blake3" => p.blake3 = Some(parse_hash(&want_str(value)?, lineno)?),
                    "sha256" => p.sha256 = Some(parse_hash(&want_str(value)?, lineno)?),
                    _ => {}
                },
            }
        }
        if let Some(p) = current.take() {
            finish(p, &mut artifacts)?;
        }
        match format {
            Some(1) => {}
            Some(f) => bail!("manifest format {f} is newer than this binary understands"),
            None => bail!("manifest lacks a format line"),
        }
        let version = version.ok_or_else(|| anyhow!("manifest lacks a version"))?;
        crate::version::Version::parse(&version)?;
        if artifacts.is_empty() {
            bail!("manifest lists no artifacts");
        }
        Ok(Manifest {
            version,
            commit,
            date,
            artifacts,
        })
    }

    /// Renders a manifest in the canonical layout.
    pub fn render(&self) -> String {
        let mut s = String::from("# Cardinal release manifest; verify with manifest.sig.\nformat = 1\nname = \"cardinal\"\n");
        s += &format!("version = \"{}\"\n", self.version);
        if let Some(c) = &self.commit {
            s += &format!("commit = \"{c}\"\n");
        }
        if let Some(d) = &self.date {
            s += &format!("date = \"{d}\"\n");
        }
        for a in &self.artifacts {
            s += &format!(
                "\n[artifact.{}]\nfile = \"{}\"\nsize = {}\nblake3 = \"{}\"\n",
                a.target,
                a.file,
                a.size,
                hex::encode(a.blake3)
            );
            if let Some(h) = a.sha256 {
                s += &format!("sha256 = \"{}\"\n", hex::encode(h));
            }
        }
        s
    }

    /// The artifact that runs on `target`: an exact match, else a static
    /// musl build for the same architecture when `target` is glibc Linux.
    pub fn artifact_for(&self, target: &str) -> Option<&Artifact> {
        if let Some(a) = self.artifacts.iter().find(|a| a.target == target) {
            return Some(a);
        }
        let musl = target.strip_suffix("-linux-gnu")?.to_string() + "-linux-musl";
        self.artifacts.iter().find(|a| a.target == musl)
    }
}

fn parse_value(v: &str) -> Option<Value> {
    if let Some(inner) = v.strip_prefix('"') {
        let s = inner.strip_suffix('"')?;
        // No escapes, no embedded quotes, printable ASCII only.
        if s.bytes()
            .all(|b| (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\')
        {
            return Some(Value::Str(s.to_string()));
        }
        return None;
    }
    if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) {
        return v.parse().ok().map(Value::Int);
    }
    None
}

fn parse_hash(s: &str, lineno: usize) -> anyhow::Result<[u8; 32]> {
    hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| anyhow!("manifest line {lineno}: expected 64 hex digits"))
}

fn valid_target(t: &str) -> bool {
    !t.is_empty()
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// A plain file name: no directories, no leading dot, conservative bytes.
pub fn valid_file_name(f: &str) -> bool {
    !f.is_empty()
        && f.len() <= 255
        && !f.starts_with('.')
        && f.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cardinal_crypto::SigningKey;

    pub(crate) fn sample() -> Manifest {
        Manifest {
            version: "0.2.0".into(),
            commit: Some("abc123".into()),
            date: Some("2026-10-27".into()),
            artifacts: vec![
                Artifact {
                    target: "x86_64-unknown-linux-musl".into(),
                    file: "cardinal-0.2.0-x86_64-unknown-linux-musl".into(),
                    size: 3,
                    blake3: *blake3::hash(b"abc").as_bytes(),
                    sha256: Some([7; 32]),
                },
                Artifact {
                    target: "aarch64-unknown-linux-gnu".into(),
                    file: "cardinal-0.2.0-aarch64-unknown-linux-gnu".into(),
                    size: 4,
                    blake3: [1; 32],
                    sha256: None,
                },
            ],
        }
    }

    #[test]
    fn render_parse_round_trip() {
        let m = sample();
        assert_eq!(Manifest::parse(&m.render()).unwrap(), m);
    }

    #[test]
    fn signed_manifest_verifies() {
        let key = SigningKey::from_seed(&[9; 32]);
        let text = sample().render();
        let sig = sign(&key, text.as_bytes());
        let m = verify_and_parse(&key.public_key(), text.as_bytes(), sig.as_bytes()).unwrap();
        assert_eq!(m, sample());
    }

    #[test]
    fn signature_failures() {
        let key = SigningKey::from_seed(&[9; 32]);
        let other = SigningKey::from_seed(&[8; 32]);
        let text = sample().render();
        let sig = sign(&key, text.as_bytes());

        // Wrong key.
        assert!(verify_and_parse(&other.public_key(), text.as_bytes(), sig.as_bytes()).is_err());
        // Tampered manifest: change the version.
        let tampered = text.replace("0.2.0", "0.2.1");
        assert!(verify_and_parse(&key.public_key(), tampered.as_bytes(), sig.as_bytes()).is_err());
        // Even trailing whitespace is tampering.
        let ws = format!("{text}\n");
        assert!(verify_and_parse(&key.public_key(), ws.as_bytes(), sig.as_bytes()).is_err());
        // Malformed signature files.
        for bad in [&b""[..], b"zz", &[0xff; 10], b"00"] {
            assert!(verify_and_parse(&key.public_key(), text.as_bytes(), bad).is_err());
        }
        // A plain signature over the manifest without the context fails.
        let raw = hex::encode(key.sign(text.as_bytes()));
        assert!(verify_and_parse(&key.public_key(), text.as_bytes(), raw.as_bytes()).is_err());
    }

    #[test]
    fn target_selection() {
        let m = sample();
        assert_eq!(
            m.artifact_for("x86_64-unknown-linux-gnu").unwrap().target,
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(
            m.artifact_for("aarch64-unknown-linux-gnu").unwrap().target,
            "aarch64-unknown-linux-gnu"
        );
        assert!(m.artifact_for("aarch64-unknown-linux-musl").is_none());
        assert!(m.artifact_for("x86_64-pc-windows-gnu").is_none());
    }

    #[test]
    fn rejects_bad_manifests() {
        let good = sample().render();
        let cases = [
            good.replace("format = 1", "format = 2"),
            good.replace("format = 1\n", ""),
            good.replace("version = \"0.2.0\"", "version = \"two\""),
            good.replace("name = \"cardinal\"", "name = \"other\""),
            good.replace(
                "file = \"cardinal-0.2.0-x86_64-unknown-linux-musl\"",
                "file = \"../../.bashrc\"",
            ),
            good.replace("size = 3\n", ""),
            good.replace("size = 3", "size = \"3\""),
            good.replace("blake3 = \"", "blake3 = \"00"),
            good + "garbage\n",
            "format = 1\nversion = \"1.0.0\"\n".to_string(),
        ];
        for (i, c) in cases.iter().enumerate() {
            assert!(Manifest::parse(c).is_err(), "case {i} parsed:\n{c}");
        }
        // Unknown keys and sections are tolerated.
        let extra = sample()
            .render()
            .replace("format = 1\n", "format = 1\nnotes = \"hi\"\n")
            + "\n[future]\nthing = 3\n";
        assert_eq!(Manifest::parse(&extra).unwrap(), sample());
    }
}
