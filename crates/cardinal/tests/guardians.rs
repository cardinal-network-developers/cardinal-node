//! Guardians (`identity.md#guardians`, D77): a person names some of the
//! people they trust, who are told by their own devices and nobody else is;
//! and when the person loses every admin device and the words, a threshold
//! of them, after checking with the person and waiting, give the identity
//! back to a new device. The new device meets each guardian through a
//! recovery helper, an identity of its own, by an invitation naming whom it
//! recovers; the helper carries the `recover` and the guardians' acts
//! between them, so guardians who are strangers see each other's.
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
    person_with(root, name, &[])
}

/// Someone with one device, whose service runs with `env`.
fn person_with(root: &std::path::Path, name: &'static str, env: &[(&str, &str)]) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.env
        .extend(env.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())));
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

/// The fingerprint `cardinal recover start` printed: five words on a line
/// of their own.
fn fingerprint_from(s: &str) -> String {
    s.lines()
        .map(str::trim)
        .find(|l| {
            let w: Vec<&str> = l.split(' ').collect();
            w.len() == 5 && w.iter().all(|w| w.chars().all(|c| c.is_ascii_lowercase()))
        })
        .unwrap_or_else(|| panic!("no fingerprint in {s}"))
        .to_owned()
}

/// The first invitation in what a command printed.
fn code_in(o: &str) -> String {
    o.lines()
        .map(str::trim)
        .find(|l| l.starts_with("cardinal:"))
        .unwrap_or_else(|| panic!("no invitation in {o}"))
        .to_owned()
}

/// The recovery invitation `g` makes for `who`'s new device.
fn recovery_invitation(g: &Dev, who: &str) -> String {
    let at = format!("127.0.0.1:{}", g.port);
    code_in(&g.cli(&["guarding", "invite", who, "--address", &at]))
}

/// `cardinal guarding VERB Ana FINGERPRINT --yes` on `g`.
fn guarding(g: &Dev, verb: &str, fp: &str) -> std::process::Output {
    let mut a = vec!["guarding", verb, "Ana"];
    a.extend(fp.split(' '));
    if verb != "never" {
        a.push("--yes");
    }
    g.try_cli(&a)
}

/// A fresh device, with no identity yet.
fn new_device(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start();
    d
}

/// Endorses, waits, and confirms on each of `gs`.
fn endorse_and_confirm(gs: &[&Dev], fp: &str) {
    for g in gs {
        let o = guarding(g, "endorse", fp);
        assert!(o.status.success(), "{}", out(&o));
        // the warning comes first, in plain words
        assert!(out(&o).contains("safest done in person"), "{}", out(&o));
    }
    for g in gs {
        wait("the guardian sees the threshold", 60, || {
            g.cli(&["guarding"]).contains("pending")
        });
    }
    for g in gs {
        wait("the guardian's wait is over", 60, || {
            guarding(g, "confirm", fp).status.success()
        });
    }
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
    // Nobody but a guardian can invite her new device.
    let o = di.try_cli(&["guarding", "invite", "Ana"]);
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

/// The hosts the recovery keeps come from the guardians: those the
/// person's reach node in their relationship names, checked against the
/// person's log. A guardian who slips in a device of their own does not
/// get it kept.
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
    nuc.cli(&["host", "--address", &at]);
    std::fs::write(laptop.p("notes.txt"), "before the loss\n").unwrap();
    laptop.cli(&["flush"]);
    wait("the host holds the file", 30, || {
        read(&nuc.p("notes.txt")).as_deref() == Some("before the loss\n")
    });

    // Bo means harm: his device proposes one of his own beside ana's host.
    let bo = person_with(
        root.path(),
        "bo",
        &[("CARDINAL_TEST_PROPOSE_OWN_DEVICE", "1")],
    );
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

    // A new device, with no sheet. Bo's invitation meets bo, cy's cy.
    let new = new_device(root.path(), "new");
    let o = new.try_cli(&["recover", "finish"]);
    assert!(
        !o.status.success() && out(&o).contains("no recovery is under way"),
        "{}",
        out(&o)
    );
    let started = new.cli(&["recover", "start", &recovery_invitation(&bo, "Ana")]);
    let fp = fingerprint_from(&started);
    // The recovery is asked for on bo's proposal.
    wait("the recovery is asked for", 30, || {
        new.cli(&["recover"]).contains("in touch:")
    });
    let again = new.cli(&["recover", "start", &recovery_invitation(&cy, "Ana")]);
    assert_eq!(fingerprint_from(&again), fp);
    assert!(new.cli(&["recover"]).contains(&fp));
    // The relationship is no contact on a guardian's devices.
    wait("bo's device shows the helper", 30, || {
        bo.cli(&["guarding"]).contains(&fp)
    });
    assert!(!bo.cli(&["contacts"]).to_lowercase().contains("recovery"));
    // The recovery keeps ana's host, and not bo's device.
    let shown = new.cli(&["recover"]);
    let kept: Vec<&str> = shown
        .lines()
        .skip_while(|l| !l.starts_with("Hosts your recovery kept"))
        .skip(1)
        .collect();
    assert_eq!(kept.len(), 1, "{shown}");
    assert!(
        new.log().contains("keeping 1 of the 2 hosts proposed"),
        "{}",
        new.log()
    );

    // Ana's host warns of it.
    wait("the host shows the recovery", 30, || {
        nuc.cli(&["guardians"])
            .contains(&format!("fingerprint \"{fp}\""))
    });

    // A fingerprint that does not match is refused: someone else may be
    // asking.
    let o = guarding(&bo, "endorse", "abandon ability able about above");
    assert!(
        !o.status.success() && out(&o).contains("not the fingerprint"),
        "{}",
        out(&o)
    );
    // Confirming before enough have endorsed is refused.
    let o = guarding(&bo, "confirm", &fp);
    assert!(
        !o.status.success() && out(&o).contains("endorsed"),
        "{}",
        out(&o)
    );
    // Typed as it is read out: case and four letters a word.
    let short: Vec<String> = fp
        .split(' ')
        .map(|w| w[..w.len().min(4)].to_uppercase())
        .collect();
    let o = guarding(&bo, "endorse", &short.join(" "));
    assert!(o.status.success(), "{}", out(&o));
    let o = guarding(&cy, "endorse", &fp);
    assert!(o.status.success(), "{}", out(&o));
    wait("bo sees the threshold", 30, || {
        bo.cli(&["guarding"]).contains("pending")
    });
    let o = guarding(&bo, "confirm", &fp);
    assert!(
        !o.status.success() && out(&o).contains("wait is not over"),
        "{}",
        out(&o)
    );
    // Not yet.
    let o = new.try_cli(&["recover", "finish"]);
    assert!(
        !o.status.success() && out(&o).contains("not all confirmed"),
        "{}",
        out(&o)
    );
    for g in [&bo, &cy] {
        wait("the guardian's wait is over", 30, || {
            guarding(g, "confirm", &fp).status.success()
        });
    }

    // The host now has ana's identity under the new root; the new device
    // joins through it, having found it from the guardians alone.
    let mut finished = None;
    wait("the new device recovers", 60, || {
        let o = new.try_cli(&["recover", "finish"]);
        if o.status.success() {
            finished = Some(String::from_utf8_lossy(&o.stdout).into_owned());
        }
        o.status.success()
    });
    let finished = finished.unwrap();
    assert!(finished.contains("Recovered, through"), "{finished}");
    assert!(finished.contains("Hosts your recovery kept"), "{finished}");
    let new_words = words_from(&finished);
    assert_ne!(new_words, words);
    assert!(!new.home.join("recovery-helper").exists());
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
    // The kept host is shown with when it was last heard from.
    let shown = new.cli(&["recover"]);
    assert!(
        shown.contains("nuc: in touch now") || shown.contains("nuc: last heard from"),
        "{shown}"
    );
    // The new words are the identity's: the old ones are not.
    let o = new.cli_input(&["recovery", "check"], &words);
    assert!(!o.status.success(), "{}", out(&o));
    let o = new.cli_input(&["recovery", "check"], &new_words);
    assert!(o.status.success(), "{}", out(&o));
}

/// A person with no host and no device left, guarded by two people who do
/// not know each other: each sees the other's endorsement only through the
/// new device, and the identity comes back from what they hold.
#[test]
fn strangers_recover_a_person_with_no_host() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut laptop = Dev::new(root.path(), "laptop", free_port());
    laptop.start();
    let words = words_from(&laptop.cli(&["init", "--yes", "--name", "ana"]));
    laptop.wait_mounted();
    let id = laptop.status()["identity"].as_str().unwrap().to_owned();
    let bo = person(root.path(), "bo");
    let cy = person(root.path(), "cy");
    meet(&laptop, &bo, "Ana");
    meet(&laptop, &cy, "Ana");
    let o = name_guardians(&laptop, &words, &["bo", "cy", "--delay", "4s"]);
    assert!(o.status.success(), "{}", out(&o));
    for g in [&bo, &cy] {
        wait("the guardian knows", 30, || {
            g.cli(&["guarding"]).contains("Ana: one of 2 guardians")
        });
    }
    laptop.stop();
    drop(laptop);

    let new = new_device(root.path(), "new");
    let fp = fingerprint_from(&new.cli(&["recover", "start", &recovery_invitation(&bo, "Ana")]));
    new.cli(&["recover", "start", &recovery_invitation(&cy, "Ana")]);
    for g in [&bo, &cy] {
        wait("the guardian sees the recovery", 30, || {
            g.cli(&["guarding"]).contains(&fp)
        });
    }
    // Strangers they stay.
    assert!(!bo.cli(&["contacts"]).contains("cy"));
    assert!(!cy.cli(&["contacts"]).contains("bo"));
    endorse_and_confirm(&[&bo, &cy], &fp);
    wait("the new device sees it in effect", 60, || {
        new.cli(&["recover"]).contains("have confirmed")
    });
    let o = new.try_cli(&["recover", "finish"]);
    assert!(o.status.success(), "{}", out(&o));
    let finished = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(
        finished.contains("from what your guardians hold"),
        "{finished}"
    );
    let new_words = words_from(&finished);
    assert!(!new.home.join("recovery-helper").exists());
    // The same identity, on this device, with new words.
    new.wait_mounted();
    assert_eq!(new.status()["identity"].as_str(), Some(id.as_str()));
    let o = new.cli_input(&["recovery", "check"], &new_words);
    assert!(o.status.success(), "{}", out(&o));
    let o = new.cli_input(&["recovery", "check"], &words);
    assert!(!o.status.success(), "{}", out(&o));
    std::fs::write(new.p("again.txt"), "again\n").unwrap();
    new.cli(&["flush"]);
    // The guardians see it done.
    for g in [&bo, &cy] {
        wait("the guardian sees it done", 30, || {
            g.cli(&["guarding"]).contains(": done")
        });
    }
}

/// Nobody finds guardians by asking: an invitation the new device makes,
/// taken to someone who is not a guardian, gets nothing back, and their
/// device tells them why. A guardian's device answers it.
#[test]
fn a_recovery_invitation_to_someone_who_is_not_a_guardian_gets_nothing_back() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut laptop = Dev::new(root.path(), "laptop", free_port());
    laptop.start();
    let words = words_from(&laptop.cli(&["init", "--yes", "--name", "ana"]));
    laptop.wait_mounted();
    let bo = person(root.path(), "bo");
    let cy = person(root.path(), "cy");
    let di = person(root.path(), "di");
    for g in [&bo, &cy, &di] {
        meet(&laptop, g, "Ana");
    }
    let o = name_guardians(&laptop, &words, &["bo", "cy", "--delay", "1d"]);
    assert!(o.status.success(), "{}", out(&o));
    for g in [&bo, &cy] {
        wait("the guardian knows", 30, || {
            g.cli(&["guarding"]).contains("Ana: one of 2 guardians")
        });
    }
    laptop.stop();
    drop(laptop);

    let new = new_device(root.path(), "new");
    new.cli(&["recover", "start", &recovery_invitation(&bo, "Ana")]);
    wait("bo is in touch", 30, || {
        new.cli(&["recover"]).contains("1 guardian(s) in touch")
    });
    // The new device's own invitation, for whoever is with the person.
    let code = code_in(&new.cli(&["recover", "invite"]));
    let o = di.try_cli(&["accept", &code]);
    assert!(
        !o.status.success() && out(&o).contains("not one of their guardians"),
        "{}",
        out(&o)
    );
    assert!(out(&o).contains("Nothing was sent back"), "{}", out(&o));
    std::thread::sleep(Duration::from_secs(3));
    assert!(new.cli(&["recover"]).contains("1 guardian(s) in touch"));
    assert!(!di.cli(&["contacts"]).to_lowercase().contains("recovery"));
    // Cy is a guardian: the same invitation meets cy.
    let o = cy.try_cli(&["accept", &code]);
    assert!(
        o.status.success() && out(&o).contains("recovery for Ana"),
        "{}",
        out(&o)
    );
    wait("cy is in touch", 30, || {
        new.cli(&["recover"]).contains("2 guardian(s) in touch")
    });
    let fp = fingerprint_from(&new.cli(&["recover", "start"]));
    wait("cy sees the recovery", 30, || {
        cy.cli(&["guarding"]).contains(&fp)
    });
}

/// A new device lost before the recovery is in effect is started over on
/// another. Guardians are shown one recovery of a person at a time, told
/// plainly when a second arrives, and once told never to confirm the old
/// one, never do.
#[test]
fn a_second_recovery_is_warned_of_and_starting_over_works() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut laptop = Dev::new(root.path(), "laptop", free_port());
    laptop.start();
    let words = words_from(&laptop.cli(&["init", "--yes", "--name", "ana"]));
    laptop.wait_mounted();
    let bo = person(root.path(), "bo");
    let cy = person(root.path(), "cy");
    meet(&laptop, &bo, "Ana");
    meet(&laptop, &cy, "Ana");
    let o = name_guardians(&laptop, &words, &["bo", "cy", "--delay", "4s"]);
    assert!(o.status.success(), "{}", out(&o));
    for g in [&bo, &cy] {
        wait("the guardian knows", 30, || {
            g.cli(&["guarding"]).contains("Ana: one of 2 guardians")
        });
    }
    laptop.stop();
    drop(laptop);

    // The first new device gets as far as one endorsement, and is lost.
    let mut first = new_device(root.path(), "first");
    let old = fingerprint_from(&first.cli(&["recover", "start", &recovery_invitation(&bo, "Ana")]));
    first.cli(&["recover", "start", &recovery_invitation(&cy, "Ana")]);
    wait("bo sees it", 30, || bo.cli(&["guarding"]).contains(&old));
    let o = guarding(&bo, "endorse", &old);
    assert!(o.status.success(), "{}", out(&o));
    wait("cy sees it", 30, || cy.cli(&["guarding"]).contains(&old));
    first.stop();
    drop(first);

    // Started over: a new root, a new helper, a new recover.
    let second = new_device(root.path(), "second");
    let fp = fingerprint_from(&second.cli(&["recover", "start", &recovery_invitation(&bo, "Ana")]));
    second.cli(&["recover", "start", &recovery_invitation(&cy, "Ana")]);
    assert_ne!(fp, old);
    // One is shown at a time, with a plain warning of the other.
    for g in [&bo, &cy] {
        wait("the guardian is warned of a second", 30, || {
            let shown = g.cli(&["guarding"]);
            shown.contains("WARNING: Another recovery of Ana arrived") && shown.contains(&old)
        });
        assert!(!g.cli(&["guarding"]).contains(&fp));
        let o = guarding(g, "endorse", &fp);
        assert!(
            !o.status.success() && out(&o).contains("waits while one is under way"),
            "{}",
            out(&o)
        );
    }
    // Told by the person, each guardian says never to the old one.
    for g in [&bo, &cy] {
        let o = guarding(g, "never", &old);
        assert!(o.status.success(), "{}", out(&o));
        let shown = g.cli(&["guarding"]);
        assert!(shown.contains(&fp), "{shown}");
        assert!(shown.contains("you said never to confirm it"), "{shown}");
        assert!(!shown.contains("WARNING"), "{shown}");
    }
    // And never does.
    for verb in ["endorse", "confirm"] {
        let o = guarding(&bo, verb, &old);
        assert!(
            !o.status.success() && out(&o).contains("never to confirm"),
            "{}",
            out(&o)
        );
    }
    endorse_and_confirm(&[&bo, &cy], &fp);
    wait("the second device recovers", 60, || {
        second.try_cli(&["recover", "finish"]).status.success()
    });
    second.wait_mounted();
    // The old one can never take effect now.
    let o = guarding(&cy, "confirm", &old);
    assert!(!o.status.success(), "{}", out(&o));
}
