//! The calendar's document, as the program gives it: one application
//! document of kind 14, with the words of `basics/calendar.md` (draft 1)
//! where the specification can be found (`$CARDINAL_CORE`, or a `core`
//! directory beside an ancestor of this crate).
//!
//! Being an integration test of this crate, it also has `cargo test
//! --workspace` build the binary, which `cardinal`'s tests drive.

use cardinal_encoding::{Record, Value};
use std::path::PathBuf;

fn core_path(rel: &str) -> Option<PathBuf> {
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

#[test]
fn the_document_is_the_one_basics_describes() {
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_cardinal-calendar"))
        .arg("document")
        .output()
        .unwrap();
    assert!(o.status.success());
    let r = Record::decode(&o.stdout).expect("one canonical record");
    assert_eq!(r.uint(0).unwrap(), 14);
    assert_eq!(r.text(1).unwrap(), "Calendar");
    assert_eq!(r.list(5).unwrap().len(), 3);
    let words = r.text(6).unwrap();
    let Some(spec) = core_path("basics/calendar.md") else {
        eprintln!("skipping the words: no specification checkout found");
        return;
    };
    let spec = std::fs::read_to_string(spec).unwrap();
    let block = spec
        .split("## The words")
        .nth(1)
        .and_then(|s| s.split("```\n").nth(1))
        .expect("the words block");
    assert_eq!(words, block, "the words differ from basics/calendar.md");
    let shared = r.record(4).unwrap();
    assert_eq!(shared.get(1), Some(&Value::from(1u64)));
}
