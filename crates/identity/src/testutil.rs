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
