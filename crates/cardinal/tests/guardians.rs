//! Guardians (`identity.md#guardians`): a person names some of the people
//! they trust, who are told by their own devices and nobody else is; and
//! when the person loses every admin device and the words, a threshold of
//! them, after checking with the person and waiting, give the identity back
//! to a new device, which gets everything back from the person's host.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use std::time::Duration;

use common::*;

/// The 24 words `cardinal init` printed, in order ("  1. word   9. ...").
fn words_from(init: &str) -> String {
    let mut words = vec![String::new(); 24];
    for line in init.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for pair in tokens.chunks(2) {
            if let [n, word] = pair {
                if let Some(n) = n.strip_suffix('.').and_then(|n| n.parse::<usize>().ok()) {
                    if (1..=24).contains(&n) {
                        words[n - 1] = (*word).to_owned();
                    }
                }
            }
        }
    }
    assert!(words.iter().all(|w| !w.is_empty()), "{init}");
    words.join(" ")
}

/// Someone with one device.
fn person(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start();
    d.cli(&["init", "--yes", "--name", name]);
    d.wait_mounted();
    d
}

/// `from` invites `to`, who accepts, calling them `as_name`.
fn meet(from: &Dev, to: &Dev, as_name: &str) {
    let at = format!("127.0.0.1:{}", from.port);
    let code = from.cli(&["invite", "--address", &at, "--name", as_name]);
    to.cli(&["accept", code.trim()]);
    wait("they know each other", 20, || {
        from.cli(&["contacts"]).contains(to.name)
    });
}

/// Names guardians on `who`, with the words on standard input.
fn name_guardians(who: &Dev, words: &str, args: &[&str]) -> std::process::Output {
    let mut a = vec!["guardians", "set"];
    a.extend_from_slice(args);
    who.cli_input(&a, words)
}

fn out(o: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn guardians_are_named_and_only_they_know() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut ana = Dev::new(root.path(), "ana", free_port());
    ana.start();
    let words = words_from(&ana.cli(&["init", "--yes", "--name", "ana"]));
    ana.wait_mounted();
    let bo = person(root.path(), "bo");
    let cy = person(root.path(), "cy");
    let di = person(root.path(), "di");
    meet(&ana, &bo, "Ana");
    meet(&ana, &cy, "Ana");
    meet(&ana, &di, "Ana");

    assert!(ana.cli(&["guardians"]).contains("no guardians"));
    // A guardian is a contact; and a majority must agree.
    let o = name_guardians(&ana, &words, &["bo", "nobody"]);
    assert!(
        !o.status.success() && out(&o).contains("no contact"),
        "{}",
        out(&o)
    );
    let o = name_guardians(&ana, &words, &["bo", "cy", "--threshold", "1"]);
    assert!(
        !o.status.success() && out(&o).contains("more than half"),
        "{}",
        out(&o)
    );
    // The first guardians take the words.
    let o = name_guardians(&ana, "", &["bo", "cy"]);
    assert!(!o.status.success(), "{}", out(&o));
    let o = name_guardians(&ana, &words, &["bo", "cy", "--delay", "3d"]);
    assert!(o.status.success(), "{}", out(&o));
    assert!(out(&o).contains("Your guardians are bo, cy"), "{}", out(&o));

    let shown = ana.cli(&["guardians"]);
    assert!(shown.contains("2 of your 2 guardians"), "{shown}");
    assert!(shown.contains("3 days"), "{shown}");
    assert!(shown.contains("Guardians: bo, cy"), "{shown}");

    // Each guardian's device finds out from ana's log; di is not one.
    for g in [&bo, &cy] {
        wait("the guardian knows", 30, || {
            g.cli(&["guarding"]).contains("Ana: one of 2 guardians")
        });
    }
    std::thread::sleep(Duration::from_secs(2));
    assert!(di.cli(&["guarding"]).contains("You guard nobody"));
    // Nobody but ana's own devices can ask for help for her.
    let o = di.try_cli(&["guarding", "code", "Ana"]);
    assert!(
        !o.status.success() && out(&o).contains("do not guard"),
        "{}",
        out(&o)
    );

    // Ana keeps working: a new key came with the guardians, and her
    // contacts still hear her.
    ana.cli(&["say", "di", "still here"]);
    wait("di reads it", 30, || {
        di.cli(&["messages", "Ana"]).contains("still here")
    });
}

/// The fingerprint `cardinal recover start` printed.
fn fingerprint_from(s: &str) -> String {
    s.lines()
        .map(str::trim)
        .find(|l| l.len() == 11 && l.as_bytes()[5] == b'-')
        .unwrap_or_else(|| panic!("no fingerprint in {s}"))
        .to_owned()
}

/// The line starting `name` of a recovery sheet.
fn field(sheet: &str, name: &str) -> String {
    sheet
        .lines()
        .find_map(|l| l.trim().strip_prefix(name))
        .unwrap_or_else(|| panic!("no {name} in {sheet}"))
        .trim()
        .to_owned()
}

/// The help code `cardinal guarding code` printed.
fn help_code(g: &Dev, who: &str) -> String {
    let at = format!("127.0.0.1:{}", g.port);
    let o = g.cli(&["guarding", "code", who, "--address", &at]);
    o.lines()
        .map(str::trim)
        .find(|l| l.starts_with("cardinal-help:"))
        .unwrap_or_else(|| panic!("no code in {o}"))
        .to_owned()
}

#[test]
fn guardians_give_an_identity_back() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    // Ana: a laptop, her admin device, and a host at home.
    let mut laptop = Dev::new(root.path(), "laptop", free_port());
    laptop.start();
    let words = words_from(&laptop.cli(&["init", "--yes", "--name", "ana"]));
    laptop.wait_mounted();
    let mut nuc = Dev::new(root.path(), "nuc", free_port());
    nuc.start();
    pair(&laptop, &nuc);
    let at = format!("127.0.0.1:{}", nuc.port);
    let shown = nuc.cli(&["host", "--address", &at]);
    let key = field(&shown, "Key:");
    std::fs::write(laptop.p("notes.txt"), "before the loss\n").unwrap();
    laptop.cli(&["flush"]);
    wait("the host holds the file", 30, || {
        read(&nuc.p("notes.txt")).as_deref() == Some("before the loss\n")
    });

    let bo = person(root.path(), "bo");
    let cy = person(root.path(), "cy");
    let di = person(root.path(), "di");
    for g in [&bo, &cy, &di] {
        meet(&laptop, g, "Ana");
    }
    let o = name_guardians(
        &laptop,
        &words,
        &["bo", "cy", "di", "--threshold", "2", "--delay", "6s"],
    );
    assert!(o.status.success(), "{}", out(&o));
    for g in [&bo, &cy, &di] {
        wait("the guardian knows", 30, || {
            g.cli(&["guarding"]).contains("Ana: one of 3 guardians")
        });
    }
    wait("the host has the guardians' policy", 30, || {
        nuc.cli(&["guardians"]).contains("2 of your 3 guardians")
    });

    // The laptop is stolen: what is written on it after this point is not
    // the person's.
    std::thread::sleep(Duration::from_millis(1100));
    let stolen_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string();
    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(laptop.p("notes.txt"), "the thief's\n").unwrap();
    laptop.cli(&["flush"]);
    wait("the host holds the thief's change", 30, || {
        read(&nuc.p("notes.txt")).as_deref() == Some("the thief's\n")
    });
    laptop.stop();
    drop(laptop);
    wait("bo reaches ana's host", 60, || {
        bo.cli(&["contacts"])
            .lines()
            .any(|l| l.starts_with("Ana") && l.contains("connected"))
    });

    // A new device, with only the sheet's host. Bo gives it a code.
    let mut new = Dev::new(root.path(), "new", free_port());
    new.start();
    let o = new.try_cli(&["recover", "finish", "--host", &at, "--key", &key]);
    assert!(
        !o.status.success() && out(&o).contains("no recovery is under way"),
        "{}",
        out(&o)
    );
    let started = new.cli(&["recover", "start", &help_code(&bo, "Ana"), "--key", &key]);
    let fp = fingerprint_from(&started);
    // Cy's code takes the same recovery to cy.
    let again = new.cli(&["recover", "start", &help_code(&cy, "Ana"), "--key", &key]);
    assert_eq!(fingerprint_from(&again), fp);
    assert!(new.cli(&["recover"]).contains(&fp));

    // Ana's host warns of it.
    wait("the host shows the recovery", 30, || {
        nuc.cli(&["guardians"])
            .contains(&format!("fingerprint {fp}"))
    });

    // A fingerprint that does not match is refused: someone else may be
    // asking.
    let o = bo.try_cli(&["guarding", "endorse", "Ana", "AAAAA-AAAAA"]);
    assert!(
        !o.status.success() && out(&o).contains("not the fingerprint"),
        "{}",
        out(&o)
    );
    // Confirming before enough have endorsed is refused.
    let o = bo.try_cli(&["guarding", "confirm", "Ana", &fp]);
    assert!(
        !o.status.success() && out(&o).contains("endorsed"),
        "{}",
        out(&o)
    );
    bo.cli(&["guarding", "endorse", "Ana", &fp.to_lowercase()]);
    cy.cli(&["guarding", "endorse", "Ana", &fp]);
    // Bo sees cy's endorsement through ana's host, and the wait starts.
    wait("bo sees the threshold", 30, || {
        bo.cli(&["guarding"]).contains("pending")
    });
    let o = bo.try_cli(&["guarding", "confirm", "Ana", &fp]);
    assert!(
        !o.status.success() && out(&o).contains("wait is not over"),
        "{}",
        out(&o)
    );
    // Not yet: the new device is not ana's.
    let o = new.try_cli(&["recover", "finish", "--host", &at, "--key", &key]);
    assert!(
        !o.status.success() && out(&o).contains("not all"),
        "{}",
        out(&o)
    );

    wait("bo's wait is over", 30, || {
        bo.try_cli(&["guarding", "confirm", "Ana", &fp])
            .status
            .success()
    });
    wait("cy's wait is over", 30, || {
        cy.try_cli(&["guarding", "confirm", "Ana", &fp])
            .status
            .success()
    });

    // The host now has ana's identity under the new root; the new device
    // joins through it.
    let mut finished = None;
    wait("the new device recovers", 60, || {
        let o = new.try_cli(&["recover", "finish", "--host", &at, "--key", &key]);
        if o.status.success() {
            finished = Some(String::from_utf8_lossy(&o.stdout).into_owned());
        }
        o.status.success()
    });
    let finished = finished.unwrap();
    assert!(finished.contains("Recovered"), "{finished}");
    let new_words = words_from(&finished);
    assert_ne!(new_words, words);
    new.wait_mounted();
    // What the lost laptop wrote is set aside until the person keeps it,
    // up to the point they choose: not what the thief wrote.
    wait("the laptop's work is listed", 40, || {
        new.cli(&["keep-work", "laptop"])
            .contains("changes of laptop are set aside")
            && !new.cli(&["keep-work", "laptop"]).starts_with("0 ")
    });
    let o = new.try_cli(&["keep-work", "bo", "--up-to", "all"]);
    assert!(!o.status.success(), "{}", out(&o));
    wait("the new device has the file", 40, || {
        new.cli(&["keep-work", "laptop", "--up-to", &stolen_at]);
        read(&new.p("notes.txt")).as_deref() == Some("before the loss\n")
    });
    // It works: changes go both ways.
    std::fs::write(new.p("after.txt"), "after\n").unwrap();
    new.cli(&["flush"]);
    wait("the host has the new file", 30, || {
        read(&nuc.p("after.txt")).as_deref() == Some("after\n")
    });
    // The lost laptop is gone from the identity, the host kept.
    let devices = new.cli(&["devices"]);
    assert!(!devices.contains("laptop"), "{devices}");
    assert!(devices.contains("nuc"), "{devices}");
    // The new words are the identity's: the old ones are not.
    let o = new.cli_input(&["recovery", "check"], &words);
    assert!(!o.status.success(), "{}", out(&o));
    let o = new.cli_input(&["recovery", "check"], &new_words);
    assert!(o.status.success(), "{}", out(&o));
    // Not checked here: that its contacts hear it soon. What the new
    // device writes reaches them through the host as other news does, and
    // in this setting that was not reliably within a minute (left open).
}
