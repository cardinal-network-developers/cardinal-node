//! Where releases come from: a local directory or an HTTPS URL, each
//! holding `manifest`, `manifest.sig`, and the artifacts the manifest
//! names.
//!
//! Integrity comes from the manifest signature and hashes, not from the
//! transport; HTTPS is still required for remote sources so that what you
//! fetch (and that you fetch it) stays private. Plain `http://` is allowed
//! only for loopback addresses, for testing.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context};

/// A release source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A directory on this machine.
    Dir(PathBuf),
    /// A base URL; files are fetched from `<base>/<name>`.
    Url(String),
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::Dir(d) => write!(f, "{}", d.display()),
            Source::Url(u) => write!(f, "{u}"),
        }
    }
}

impl Source {
    /// Parses a source as given on the command line or in the config:
    /// `https://...`, `http://localhost...`, `file:///...`, or a path
    /// (`~/` is expanded).
    pub fn parse(s: &str) -> anyhow::Result<Source> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("file://") {
            return Ok(Source::Dir(PathBuf::from(rest)));
        }
        if s.starts_with("https://") {
            return Ok(Source::Url(s.trim_end_matches('/').to_string()));
        }
        if let Some(rest) = s.strip_prefix("http://") {
            let host = rest.split(['/', ':']).next().unwrap_or("");
            if matches!(host, "localhost" | "127.0.0.1") || rest.starts_with("[::1]") {
                return Ok(Source::Url(s.trim_end_matches('/').to_string()));
            }
            bail!("refusing plain http:// for a remote release source; use https://");
        }
        if s.contains("://") {
            bail!("unsupported release source {s:?}: use https:// or a directory");
        }
        let path = match s.strip_prefix("~/") {
            Some(rest) => {
                let home =
                    std::env::var_os("HOME").ok_or_else(|| anyhow::anyhow!("HOME is not set"))?;
                Path::new(&home).join(rest)
            }
            None => PathBuf::from(s),
        };
        Ok(Source::Dir(path))
    }

    /// Opens `name`, refusing to read more than `max` bytes from it.
    pub fn open(&self, name: &str, max: u64) -> anyhow::Result<Box<dyn Read>> {
        match self {
            Source::Dir(d) => {
                let p = d.join(name);
                let f =
                    std::fs::File::open(&p).with_context(|| format!("opening {}", p.display()))?;
                Ok(Box::new(Limited {
                    inner: f,
                    left: max,
                    what: p.display().to_string(),
                }))
            }
            Source::Url(base) => {
                let url = format!("{base}/{name}");
                let loopback = !base.starts_with("https://");
                let agent: ureq::Agent = ureq::Agent::config_builder()
                    .https_only(!loopback)
                    .timeout_connect(Some(Duration::from_secs(30)))
                    .timeout_recv_body(Some(Duration::from_secs(300)))
                    .user_agent(format!("cardinal/{}", crate::build_info::VERSION))
                    .build()
                    .into();
                let resp = agent
                    .get(&url)
                    .call()
                    .with_context(|| format!("fetching {url}"))?;
                let reader = resp.into_body().into_with_config().limit(max).reader();
                Ok(Box::new(Limited {
                    inner: reader,
                    left: max,
                    what: url,
                }))
            }
        }
    }

    /// Reads all of `name`, at most `max` bytes.
    pub fn read(&self, name: &str, max: u64) -> anyhow::Result<Vec<u8>> {
        let mut v = Vec::new();
        self.open(name, max)?
            .read_to_end(&mut v)
            .with_context(|| format!("reading {name} from {self}"))?;
        Ok(v)
    }
}

/// A reader that fails rather than return more than `left` bytes.
struct Limited<R> {
    inner: R,
    left: u64,
    what: String,
}

impl<R: Read> Read for Limited<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n as u64 > self.left {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} is larger than expected", self.what),
            ));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sources() {
        assert_eq!(
            Source::parse("https://ex.org/r/").unwrap(),
            Source::Url("https://ex.org/r".into())
        );
        assert_eq!(
            Source::parse("/srv/r").unwrap(),
            Source::Dir("/srv/r".into())
        );
        assert_eq!(
            Source::parse("file:///srv/r").unwrap(),
            Source::Dir("/srv/r".into())
        );
        assert!(Source::parse("http://ex.org/r").is_err());
        assert!(Source::parse("http://localhost:8000/r").is_ok());
        assert!(Source::parse("ftp://ex.org/r").is_err());
    }

    #[test]
    fn directory_reads_are_limited() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("f"), b"0123456789").unwrap();
        let s = Source::Dir(d.path().into());
        assert_eq!(s.read("f", 10).unwrap(), b"0123456789");
        assert!(s.read("f", 9).is_err());
        assert!(s.read("missing", 9).is_err());
    }
}
