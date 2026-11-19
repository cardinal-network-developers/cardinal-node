//! A clipboard shared by a person's own devices (`basics/clipboard.md`):
//! copied on one, pasted on another, never sent to anyone else.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;
use std::io::{BufRead, BufReader, Write};

/// One request on the service's interface, as a window asks.
fn ask(d: &Dev, req: serde_json::Value) -> serde_json::Value {
    let mut s = std::os::unix::net::UnixStream::connect(d.home.join("control.sock")).unwrap();
    writeln!(s, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

#[test]
fn what_is_copied_on_one_device_is_pasted_on_another_and_nobody_elses() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut desk = Dev::new(root.path(), "desk", free_port());
    let mut laptop = Dev::new(root.path(), "laptop", free_port());
    let mut sam = Dev::new(root.path(), "sam", free_port());
    for d in [&mut desk, &mut laptop, &mut sam] {
        d.start();
    }
    desk.cli(&["init", "--yes", "--name", "Ana"]);
    desk.wait_mounted();
    pair(&desk, &laptop);
    sam.cli(&["init", "--yes", "--name", "Sam"]);
    sam.wait_mounted();
    let code = desk.cli(&[
        "invite",
        "--address",
        &format!("127.0.0.1:{}", desk.port),
        "--name",
        "Ana",
    ]);
    sam.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("the devices know each other", 30, || {
        desk.status()["devices"]
            .as_array()
            .is_some_and(|d| d.len() == 2)
            && laptop.status()["devices"]
                .as_array()
                .is_some_and(|d| d.len() == 2)
    });
    wait("Sam is connected", 30, || {
        desk.cli(&["contacts"]).contains("connected")
    });

    // Nothing copied yet: paste says so, and fails.
    let o = laptop.try_cli(&["clip", "paste"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("nothing copied"));

    // Copied on the desk, by argument: pasted on the laptop, exactly.
    let o = desk.try_cli(&["clip", "copy", "the result: 42"]);
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("Copied to 1 other device"));
    wait("the laptop has it", 10, || {
        laptop.try_cli(&["clip", "paste"]).stdout == b"the result: 42"
    });
    // And on the desk itself.
    assert_eq!(desk.try_cli(&["clip", "paste"]).stdout, b"the result: 42");

    // Piped, lines and all: the newest copy wins, from either side.
    let text = "line one\nline two\n";
    let o = laptop.cli_input(&["clip", "copy"], text);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    wait("the desk has the newer", 10, || {
        desk.try_cli(&["clip", "paste"]).stdout == text.as_bytes()
    });
    let said = ask(&desk, serde_json::json!({"cmd": "clip"}));
    assert_eq!(said["from"], "laptop", "{said}");

    // Someone else's device is not sent it.
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(!sam.try_cli(&["clip", "paste"]).status.success());

    // What does not belong on a clipboard is refused, and changes nothing.
    let big = "x".repeat(65 * 1024);
    let o = desk.cli_input(&["clip", "copy"], &big);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("share a file instead"));
    assert_eq!(laptop.try_cli(&["clip", "paste"]).stdout, text.as_bytes());
}
