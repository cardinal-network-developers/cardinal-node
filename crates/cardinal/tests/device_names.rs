//! A device's name lives in its device node in the account space
//! (`profiles.md#account`), which only the person's own devices read and any
//! of them may set: `device-rename` sets it, from this device or another,
//! and every device of the person's then shows it.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing,
//! since pairing waits for the new device's folder.

mod common;

use common::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

fn reply(d: &Dev, req: &Value) -> Value {
    let mut s = UnixStream::connect(d.home.join("control.sock")).unwrap();
    writeln!(s, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn ask(d: &Dev, req: Value) -> Value {
    let r = reply(d, &req);
    assert_eq!(r["ok"], true, "{req} got {r}");
    r
}

fn refused(d: &Dev, req: Value) -> String {
    let r = reply(d, &req);
    assert_eq!(r["ok"], false, "{req} got {r}");
    r["error"].as_str().unwrap_or_default().to_owned()
}

/// What `devices` calls each device, this one first.
fn names(d: &Dev) -> Vec<String> {
    let v = ask(d, json!({"cmd": "devices"}));
    let mut all: Vec<(bool, String)> = v["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["this"] != true,
                x["name"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    all.sort();
    all.into_iter().map(|(_, n)| n).collect()
}

fn key_of(d: &Dev, this: bool) -> String {
    let v = ask(d, json!({"cmd": "devices"}));
    let found = v["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| (x["this"] == true) == this)
        .cloned()
        .unwrap();
    found["key"].as_str().unwrap().to_owned()
}

#[test]
fn a_device_is_renamed_from_any_of_the_persons_devices() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    let mut b = Dev::new(root.path(), "beta", free_port());
    a.start();
    b.start();
    a.cli(&["init", "--yes", "--name", "Ana"]);
    a.wait_mounted();
    pair(&a, &b);
    wait("both list both", 60, || {
        reply(&b, &json!({"cmd": "devices"}))["devices"]
            .as_array()
            .is_some_and(|d| d.len() == 2)
            && names(&a).len() == 2
            && names(&b).len() == 2
    });
    // The first device is named after its machine (here, the name it runs
    // with), not after its person, until renamed.
    assert_eq!(names(&a)[0], "alpha");

    // This device, by its own name.
    let r = ask(
        &a,
        json!({"cmd": "device-rename", "device": "alpha", "name": " Laptop "}),
    );
    assert_eq!(r["name"], "Laptop");
    assert_eq!(names(&a)[0], "Laptop");
    // The other device, by its key, from this one; and each sees both.
    let other = key_of(&a, false);
    ask(
        &a,
        json!({"cmd": "device-rename", "device": other, "name": "Phone"}),
    );
    assert_eq!(names(&a), ["Laptop", "Phone"]);
    wait("the other device sees both names", 30, || {
        names(&b) == ["Phone", "Laptop"]
    });
    // And from the other device, by name, back the other way.
    ask(
        &b,
        json!({"cmd": "device-rename", "device": "laptop", "name": "Desk"}),
    );
    wait("the first device sees its new name", 30, || {
        names(&a) == ["Desk", "Phone"]
    });
    // Its status agrees.
    let st = a.status();
    let mine = st["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["this"] == true)
        .cloned()
        .unwrap();
    assert_eq!(mine["name"], "Desk");

    // No two of a person's devices share a name, since a device is found by it.
    let taken = refused(
        &a,
        json!({"cmd": "device-rename", "device": "Desk", "name": "phone"}),
    );
    assert!(taken.contains("another of your devices"), "{taken}");
    // Changing only the case of its own name is no clash.
    ask(
        &a,
        json!({"cmd": "device-rename", "device": "Desk", "name": "desk"}),
    );
    let empty = refused(
        &a,
        json!({"cmd": "device-rename", "device": "desk", "name": "  "}),
    );
    assert!(empty.contains("empty"), "{empty}");
    let lines = refused(
        &a,
        json!({"cmd": "device-rename", "device": "desk", "name": "a\nb"}),
    );
    assert!(lines.contains("one line"), "{lines}");
    let nobody = refused(
        &a,
        json!({"cmd": "device-rename", "device": "toaster", "name": "Oven"}),
    );
    assert!(nobody.contains("no device called"), "{nobody}");
    let missing = refused(&a, json!({"cmd": "device-rename", "device": "desk"}));
    assert!(missing.contains("name"), "{missing}");
    // Renaming a device writes nothing about the person: the name others
    // are given stays.
    assert_eq!(ask(&a, json!({"cmd": "me"}))["name"], "Ana");
}

/// A machine is named after its host, whatever its person is called; the
/// command line renames it, by its current name, and says what it is
/// called now.
#[test]
fn the_command_line_renames_a_device() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    a.start();
    a.cli(&["init", "--yes", "--name", "Ana"]);
    a.wait_mounted();
    let out = a.cli(&["rename-device", "alpha", "Kitchen laptop"]);
    assert!(out.contains("Kitchen laptop"), "{out}");
    assert_eq!(names(&a), ["Kitchen laptop"]);
    let devices = a.cli(&["devices"]);
    assert!(devices.contains("Kitchen laptop"), "{devices}");
}
