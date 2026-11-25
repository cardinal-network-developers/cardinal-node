//! Locating the specification checkout, for tests.

use std::path::PathBuf;

/// The path of `rel` inside the specification repository (`core`), if it
/// can be found: `$CARDINAL_CORE`, or a `core` directory next to any
/// ancestor of this crate.
pub fn core_path(rel: &str) -> Option<PathBuf> {
    if let Ok(c) = std::env::var("CARDINAL_CORE") {
        let p = PathBuf::from(c).join(rel);
        return p.exists().then_some(p);
    }
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let p = dir.join("core").join(rel);
        if p.exists() {
            return Some(p);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Says why a test cannot run here, before it returns: a skip, said; or,
/// in the release tier (`CARDINAL_TEST_STRICT=1`, set by
/// `scripts/test-tier release`), a failure, since a release run must run
/// every test it counts.
pub fn skipping(why: &str) {
    let strict = std::env::var_os("CARDINAL_TEST_STRICT").is_some_and(|v| v == "1");
    assert!(!strict, "cannot run in the release tier: {why}");
    eprintln!("skipping: {why}");
}
