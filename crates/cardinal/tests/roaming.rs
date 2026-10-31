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

/// A device that knows of only one other is told where the rest are, and
/// reaches them itself: more ways back for a device that returns.
#[test]
fn a_device_is_told_where_its_other_devices_are() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    let mut b = Dev::new(root.path(), "beta", free_port());
    let mut c = Dev::new(root.path(), "gamma", free_port());
    a.start();
    a.cli(&["init", "--yes", "--name", "alpha"]);
    a.wait_mounted();
    b.start();
    pair(&a, &b);
    c.start();
    pair(&a, &c);
    b.wait_mounted();
    c.wait_mounted();
    wait("alpha knows where gamma is", 20, || {
        address_of(&a, "gamma").ends_with(&format!(":{}", c.port))
    });

    // Beta forgets everything but alpha, and hears the rest from it.
    b.stop();
    let at = format!("127.0.0.1:{}", a.port);
    let book = b.home.join("peers.json");
    let text = std::fs::read_to_string(&book).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let keep = |list: &serde_json::Value| list.as_array().unwrap().iter().any(|x| x == &at);
    v["addrs"]
        .as_object_mut()
        .unwrap()
        .retain(|_, list| keep(list));
    std::fs::write(&book, v.to_string()).unwrap();
    b.start();
    b.wait_mounted();
    // In its book only if alpha said so: introductions leave nothing there.
    let gamma = format!("127.0.0.1:{}", c.port);
    wait("beta is told where gamma is", 30, || {
        std::fs::read_to_string(&book).is_ok_and(|t| t.contains(&gamma))
    });
    wait("beta reaches gamma", 30, || {
        let s = b.status();
        let all = s["devices"].as_array().unwrap().clone();
        all.iter()
            .any(|d| d["name"] == "gamma" && d["online"] == true)
    });

    // It reached gamma itself: alpha can go.
    a.stop();
    std::fs::write(b.p("hello.txt"), "hello\n").unwrap();
    b.cli(&["flush"]);
    wait("gamma has it", 15, || {
        std::fs::read(c.p("hello.txt")).is_ok_and(|f| f == b"hello\n")
    });
}
