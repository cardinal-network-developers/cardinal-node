//! What this binary is: version, commit, date, target, release key.

include!(concat!(env!("OUT_DIR"), "/release_key.rs"));

/// The version this binary reports and compares releases against.
pub const VERSION: &str = env!("CARDINAL_VERSION");
/// The git commit it was built from (`-dirty` if the tree had changes).
pub const GIT_COMMIT: &str = env!("CARDINAL_GIT_COMMIT");
/// The build date, `YYYY-MM-DD` (UTC).
pub const BUILD_DATE: &str = env!("CARDINAL_BUILD_DATE");
/// The target triple it was built for.
pub const TARGET: &str = env!("CARDINAL_TARGET");

/// Whether this is a development build (`scripts/dev-release.sh`).
pub fn is_dev_build() -> bool {
    is_dev_version(VERSION)
}

/// Whether `version` is a development pre-release (`X.Y.Z-dev.N`).
pub fn is_dev_version(version: &str) -> bool {
    version
        .split_once('-')
        .is_some_and(|(_, pre)| pre == "dev" || pre.starts_with("dev."))
}

/// A short, human-comparable fingerprint of a release public key: the
/// first 16 bytes of its BLAKE3 hash, in groups of four hex digits.
pub fn key_fingerprint(key: &[u8; 32]) -> String {
    let h = blake3::hash(key);
    let hex = hex::encode(&h.as_bytes()[..16]);
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The `cardinal version` report.
pub fn report() -> String {
    let key = match RELEASE_PUBLIC_KEY {
        Some(k) => key_fingerprint(&k),
        None => "none (this build cannot verify updates)".to_string(),
    };
    format!(
        "cardinal {VERSION}\n\
         commit:      {GIT_COMMIT}\n\
         built:       {BUILD_DATE}\n\
         target:      {TARGET}\n\
         release key: {key}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_versions() {
        assert!(is_dev_version("0.1.0-dev.20261027120000"));
        assert!(is_dev_version("0.1.0-dev"));
        assert!(!is_dev_version("0.1.0"));
        assert!(!is_dev_version("0.1.0-rc.1"));
        assert!(!is_dev_version("0.1.0-devil"));
    }

    #[test]
    fn report_starts_with_version_line() {
        assert!(report().starts_with(&format!("cardinal {VERSION}\n")));
        assert_eq!(key_fingerprint(&[0; 32]).len(), 39);
    }
}
