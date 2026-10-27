//! Semantic version precedence (semver.org, section 11), enough to order
//! releases: `MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]`.

use std::cmp::Ordering;

/// A parsed semantic version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    core: [u64; 3],
    pre: Vec<Ident>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ident {
    Num(u64),
    Alpha(String),
}

impl Version {
    /// Parses `s`; build metadata after `+` is accepted and ignored.
    pub fn parse(s: &str) -> anyhow::Result<Version> {
        let bad = || anyhow::anyhow!("not a semantic version: {s:?}");
        let s_nobuild = s.split_once('+').map_or(s, |(v, _)| v);
        let (core, pre) = match s_nobuild.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (s_nobuild, None),
        };
        let parts: Vec<&str> = core.split('.').collect();
        if parts.len() != 3 {
            return Err(bad());
        }
        let mut nums = [0u64; 3];
        for (n, p) in nums.iter_mut().zip(&parts) {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            *n = p.parse().map_err(|_| bad())?;
        }
        let mut idents = Vec::new();
        if let Some(pre) = pre {
            for id in pre.split('.') {
                if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                    return Err(bad());
                }
                idents.push(if id.bytes().all(|b| b.is_ascii_digit()) {
                    Ident::Num(id.parse().map_err(|_| bad())?)
                } else {
                    Ident::Alpha(id.to_string())
                });
            }
        }
        Ok(Version {
            core: nums,
            pre: idents,
        })
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.core.cmp(&other.core).then_with(|| {
            match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                // A pre-release precedes its release.
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => {
                    for (a, b) in self.pre.iter().zip(&other.pre) {
                        let o = match (a, b) {
                            (Ident::Num(x), Ident::Num(y)) => x.cmp(y),
                            (Ident::Num(_), Ident::Alpha(_)) => Ordering::Less,
                            (Ident::Alpha(_), Ident::Num(_)) => Ordering::Greater,
                            (Ident::Alpha(x), Ident::Alpha(y)) => x.cmp(y),
                        };
                        if o != Ordering::Equal {
                            return o;
                        }
                    }
                    self.pre.len().cmp(&other.pre.len())
                }
            }
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn semver_precedence() {
        // The chain from semver.org section 11.
        let chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.1.0",
            "2.0.0",
        ];
        for w in chain.windows(2) {
            assert!(v(w[0]) < v(w[1]), "{} < {}", w[0], w[1]);
        }
        assert!(v("0.1.0-dev.20261027120000") < v("0.1.0-dev.20261027120001"));
        assert!(v("0.1.0-dev.20261027120000") < v("0.1.0"));
        assert_eq!(v("1.0.0+abc").cmp(&v("1.0.0+def")), Ordering::Equal);
    }

    #[test]
    fn rejects_garbage() {
        for s in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "a.b.c",
            "1.2.3-",
            "1.2.3-a..b",
            "1.2.x",
        ] {
            assert!(Version::parse(s).is_err(), "{s}");
        }
    }
}
