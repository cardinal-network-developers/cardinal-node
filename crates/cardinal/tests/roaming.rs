//! A device is known by its keys, and its address is only a hint: one that
//! comes back from somewhere new is reached there from then on.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;

/// The address `from` lists for the device called `name`.
fn address_of(from: &Dev, name: &str) -> String {
    let v = from.status();
    let d = v["devices"].as_array().unwrap();
    let d = d.iter().find(|d| d["name"] == name).unwrap();
    d["addr"].as_str().unwrap_or_default().to_owned()
}

#[test]
fn a_device_that_connects_from_a_new_address_is_listed_there() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    let mut b = Dev::new(root.path(), "beta", free_port());
    a.start();
    a.cli(&["init", "--yes", "--name", "alpha"]);
    a.wait_mounted();
    b.start();
    pair(&a, &b);
    b.wait_mounted();
    let here = format!("127.0.0.1:{}", b.port);
    wait("alpha knows where beta is", 20, || {
        address_of(&a, "beta") == here
    });

    // Alpha's record goes out of date, as it does when beta moves while
    // alpha is away: nothing answers there, so only beta can bring them
    // together again.
    a.stop();
    let book = a.home.join("peers.json");
    let gone = format!("127.0.0.3:{}", b.port);
    let text = std::fs::read_to_string(&book).unwrap();
    assert!(text.contains(&here), "{text}");
    std::fs::write(&book, text.replace(&here, &gone)).unwrap();
    a.start();

    wait("alpha lists beta where it came from", 30, || {
        address_of(&a, "beta") == here
    });
}
