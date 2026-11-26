//! Who learns a recovered person's new device (`identity.md#how-guardians-act`,
//! D77). A device answers only link keys it knows, and after a recovery by
//! guardians every device and host the person had is removed: an ordinary
//! contact answers the new device only once they hold the new root's first
//! entries, and the new device, which takes back only its guardians' logs,
//! reaches a contact only once it holds theirs.
//!
//! Each test is one scenario after a full recovery onto a new device, the
//! old one gone: Ana, guarded by Bo, who holds her account, and Eve, a
//! contact of hers and nobody's guardian. Those that show a hole are
//! ignored, with what they show: a decision on closing it is pending
//! (Daniel). Run them with `--ignored`.
//!
//! How long they watch, and why it is enough: nothing in the service
//! creates a path between two devices on a timer alone. What could carry
//! the new entries to Eve, or Eve's log to the new device, runs over a
//! session someone already has: the reconcile at a session's start, and
//! again every 180 s (`net.rs`, `serve`), the reach for a contact in use
//! every 30 s (`rendezvous.rs`, `REACH_EVERY`), and the redial of a known
//! device every few seconds while it is new. [`WATCH`] covers two resyncs
//! and more than ten reaches, both devices are turned to (a message each
//! way), and each side is restarted and watched again, which redoes every
//! session start.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use std::time::{Duration, Instant};

use common::*;
use serde_json::json;

/// How long each side is watched for a connection that never comes.
const WATCH: Duration = Duration::from_secs(400);

/// After each restart.
const WATCH_AGAIN: Duration = Duration::from_secs(200);

/// The 24 words `cardinal init` printed, in order.
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

fn out(o: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// The fingerprint `cardinal recover start` printed.
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

fn code_in(o: &str) -> String {
    o.lines()
        .map(str::trim)
        .find(|l| l.starts_with("cardinal:"))
        .unwrap_or_else(|| panic!("no invitation in {o}"))
        .to_owned()
}

fn guarding(g: &Dev, verb: &str, fp: &str) -> std::process::Output {
    let mut a = vec!["guarding", verb, "Ana"];
    a.extend(fp.split(' '));
    a.push("--yes");
    g.try_cli(&a)
}

/// Whether one of `d`'s sessions is with a device of `who` (as `d` names
/// them). An error, as for a contact whose log `d` does not hold, is no.
fn online(d: &Dev, who: &str) -> bool {
    let r = reply(d, &json!({"cmd": "contact-status", "who": who}));
    r["devices"]
        .as_array()
        .is_some_and(|x| x.iter().any(|x| x["online"] == true))
}

/// Whether `d` holds a message `text` from or to `who`.
fn has_message(d: &Dev, who: &str, text: &str) -> bool {
    let r = reply(d, &json!({"cmd": "messages", "who": who}));
    r["messages"]
        .as_array()
        .is_some_and(|m| m.iter().any(|m| m["text"] == text))
}

/// What the scenario adds before the loss and after the recovery.
#[derive(Default, Clone, Copy)]
struct Scenario {
    /// Ana, Bo and Eve share a group, made by Ana before the loss.
    group: bool,
    /// Eve has a host of her own, a second device of hers.
    eve_host: bool,
    /// Eve has a second, ordinary device.
    eve_phone: bool,
    /// After the recovery, Ana's new device is named her host.
    new_host: bool,
}

/// Everyone after the recovery: the new device of Ana's, Bo, Eve, and
/// Eve's second device if she has one.
struct After {
    _root: tempfile::TempDir,
    new: Dev,
    _bo: Dev,
    eve: Dev,
    eve2: Option<Dev>,
}

/// Ana's laptop, guarded by Bo; Eve, her contact; what `s` adds; the
/// laptop lost; a recovery by Bo onto a new device, finished, with Bo
/// knowing the new device.
fn recovered(s: Scenario) -> After {
    let root = tempfile::tempdir().unwrap();
    let mut laptop = Dev::new(root.path(), "laptop", free_port());
    laptop.start();
    let words = words_from(&laptop.cli(&["init", "--yes", "--name", "ana"]));
    laptop.wait_mounted();
    let bo = person(root.path(), "bo");
    let eve = person(root.path(), "eve");
    meet(&laptop, &bo, "Ana");
    meet(&laptop, &eve, "Ana");
    let eve2 = (s.eve_host || s.eve_phone).then(|| {
        let mut d = Dev::new(root.path(), "eve2", free_port());
        d.start();
        pair(&eve, &d);
        d.wait_mounted();
        if s.eve_host {
            let at = format!("127.0.0.1:{}", d.port);
            d.cli(&["host", "--address", &at]);
        }
        d
    });
    laptop.cli(&["say", "eve", "before the loss"]);
    wait("eve has ana's message", 60, || {
        has_message(&eve, "Ana", "before the loss")
    });
    if let Some(d) = &eve2 {
        wait("eve's second device has it", 60, || {
            has_message(d, "Ana", "before the loss")
        });
    }
    if s.group {
        let made = ask(
            &laptop,
            &json!({"cmd": "group-create", "name": "Garden club", "people": ["bo", "eve"]}),
        );
        let g = made["group"].as_str().unwrap().to_owned();
        for m in [&bo, &eve] {
            wait("the offer arrives", 60, || {
                let r = ask(m, &json!({"cmd": "groups"}));
                r["offers"]
                    .as_array()
                    .is_some_and(|o| o.iter().any(|x| x["name"] == "Garden club"))
            });
            ask(m, &json!({"cmd": "group-join", "group": g}));
        }
        for m in [&bo, &eve] {
            wait("the member sees the others", 60, || {
                let r = ask(m, &json!({"cmd": "group-members", "group": g}));
                r["members"].as_array().is_some_and(|x| x.len() == 3)
            });
        }
    }
    let o = bo.cli(&["guarding", "accept", "Ana"]);
    assert!(o.contains("accepted"), "{o}");
    wait("bo's persona reaches ana, and she names him", 30, || {
        laptop
            .cli_input(&["guardians", "set", "bo", "--delay", "4s"], &words)
            .status
            .success()
    });
    wait("bo knows", 30, || {
        bo.cli(&["guarding"]).contains("Ana: one of 1 guardians")
    });
    laptop.cli(&["say", "bo", "you guard me now"]);
    wait("bo holds the account", 60, || {
        bo.cli(&["guarding"]).contains("sealed copy of their account")
    });
    // what the laptop wrote has reached them before the loss
    std::thread::sleep(Duration::from_secs(3));
    laptop.stop();
    drop(laptop);

    let mut new = Dev::new(root.path(), "new", free_port());
    new.start();
    let invitation = code_in(&bo.cli(&["guarding", "invite", "Ana"]));
    let fp = fingerprint_from(&new.cli(&["recover", "start", &invitation]));
    wait("bo sees the recovery", 60, || {
        bo.cli(&["guarding"]).contains(&fp)
    });
    let o = guarding(&bo, "endorse", &fp);
    assert!(o.status.success(), "{}", out(&o));
    wait("bo's wait is over", 60, || {
        guarding(&bo, "confirm", &fp).status.success()
    });
    wait("the account is given back", 60, || {
        new.cli(&["recover"]).contains("your account among it")
    });
    let o = new.try_cli(&["recover", "finish"]);
    assert!(o.status.success(), "{}", out(&o));
    assert!(!out(&o).contains("have not heard"), "{}", out(&o));
    new.wait_mounted();
    wait("the new device and bo are in touch", 60, || online(&new, "bo"));
    if s.new_host {
        let at = format!("127.0.0.1:{}", new.port);
        new.cli(&["host", "--address", &at]);
    }
    // the new device knows eve, from the account given back
    wait("the new device lists eve", 30, || {
        new.cli(&["contacts"]).contains("eve")
    });
    After {
        _root: root,
        new,
        _bo: bo,
        eve,
        eve2,
    }
}

/// What was seen between the new device and Eve's devices.
#[derive(Debug, Default, PartialEq)]
struct Seen {
    /// The new device had a session with one of Eve's.
    new_to_eve: bool,
    /// One of Eve's had a session with a device of Ana's.
    eve_to_ana: bool,
    /// Eve's device holds what the new device said.
    to_eve: bool,
    /// The new device holds what Eve said.
    from_eve: bool,
}

impl Seen {
    fn all(&self) -> bool {
        self.new_to_eve && self.eve_to_ana && self.to_eve && self.from_eve
    }
}

/// Each says something to the other (which turns each to the other), and
/// what comes of it is watched for `long`, or until everything came.
fn watch(a: &After, round: &str, long: Duration) -> Seen {
    let to_eve = format!("from the new device, {round}");
    let from_eve = format!("from eve, {round}");
    a.new.cli(&["say", "eve", &to_eve]);
    a.eve.cli(&["say", "Ana", &from_eve]);
    let eves: Vec<&Dev> = std::iter::once(&a.eve).chain(a.eve2.as_ref()).collect();
    let mut seen = Seen::default();
    let began = Instant::now();
    while began.elapsed() < long {
        seen.new_to_eve |= online(&a.new, "eve");
        seen.eve_to_ana |= eves.iter().any(|d| online(d, "Ana"));
        seen.to_eve |= eves.iter().any(|d| has_message(d, "Ana", &to_eve));
        seen.from_eve |= has_message(&a.new, "eve", &from_eve);
        if seen.all() {
            break;
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    eprintln!("{round}: after {:?}: {seen:?}", began.elapsed());
    seen
}

/// Watches as [`watch`] does, then again after the new device restarts,
/// and again after Eve's do. Returns what each round saw.
fn watch_with_restarts(a: &mut After) -> [Seen; 3] {
    let first = watch(a, "first", WATCH);
    a.new.stop();
    a.new.start();
    a.new.wait_mounted();
    let second = watch(a, "after the new device restarted", WATCH_AGAIN);
    a.eve.stop();
    a.eve.start();
    a.eve.wait_mounted();
    if let Some(d) = a.eve2.as_mut() {
        d.stop();
        d.start();
        d.wait_mounted();
    }
    let third = watch(a, "after eve's restarted", WATCH_AGAIN);
    [first, second, third]
}

/// Whether nothing at all passed between the new device and Eve's, in
/// any round.
fn never(seen: &[Seen; 3]) -> bool {
    seen.iter().all(|s| *s == Seen::default())
}

/// Eve shares no group with anyone, has no host, and is nobody's guardian.
/// Shows a hole: the new device and Eve never connect, in either
/// direction, and neither message gets through, across both restarts. The
/// new device holds no log of Eve's (it takes back only its guardians'),
/// so it never dials her; Eve dials only Ana's removed devices, and stays
/// silent to the new one, whose link key she has never seen. Nobody holds
/// both and a space with her. Decision pending (Daniel, after the report
/// of 2026-11-25).
#[test]
#[ignore = "shows a hole, decision pending: a contact with no shared group never learns the recovered device"]
fn a_contact_with_no_shared_group_never_learns_the_new_device() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let mut a = recovered(Scenario::default());
    let seen = watch_with_restarts(&mut a);
    assert!(never(&seen), "{seen:?}");
}

/// Eve shares a group with Ana and Bo, the guardian who heard. Bo asks
/// nothing of anyone: the new device asks him for the spaces it lacks,
/// the group among them, and once it holds the group, Bo, a member with
/// both, reconciles each member's log with the other: Eve's to the new
/// device, Ana's new entries to Eve. The two then connect, and the
/// messages get through both ways.
#[test]
fn a_contact_in_a_group_with_a_guardian_learns_the_new_device() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let mut a = recovered(Scenario {
        group: true,
        ..Scenario::default()
    });
    let seen = watch(&a, "first", WATCH);
    assert!(seen.all(), "{seen:?}");
    // and again after both restart
    a.new.stop();
    a.new.start();
    a.eve.stop();
    a.eve.start();
    a.eve.wait_mounted();
    let seen = watch(&a, "after both restarted", WATCH_AGAIN);
    assert!(seen.all(), "{seen:?}");
}

/// Eve, in no group, and Ana names her new device a host after the
/// recovery. Shows a hole: nothing changes. The host's grant is written in
/// Ana's account alone; Eve would learn of it from the reach node in their
/// relationship, which the new device does not hold, and would answer it
/// only with its key in Ana's log as she holds it, which it is not.
/// Decision pending (Daniel).
#[test]
#[ignore = "shows a hole, decision pending: a host named after the recovery does not reach a contact"]
fn a_host_named_after_the_recovery_does_not_reach_a_contact() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let mut a = recovered(Scenario {
        new_host: true,
        ..Scenario::default()
    });
    let seen = watch_with_restarts(&mut a);
    assert!(never(&seen), "{seen:?}");
}

/// Eve has a host of her own, a second device of hers. Shows a hole: her
/// host is one of her devices, which holds Ana's log as her others do,
/// and answers only the keys in it. Decision pending (Daniel).
#[test]
#[ignore = "shows a hole, decision pending: a contact's own host does not learn the recovered device"]
fn a_contacts_own_host_does_not_learn_the_new_device() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let mut a = recovered(Scenario {
        eve_host: true,
        ..Scenario::default()
    });
    let seen = watch_with_restarts(&mut a);
    assert!(never(&seen), "{seen:?}");
}

/// Eve has a second, ordinary device. Shows a hole: neither of hers learns
/// the new device. Decision pending (Daniel).
#[test]
#[ignore = "shows a hole, decision pending: no device of a contact learns the recovered device"]
fn neither_of_a_contacts_devices_learns_the_new_device() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let mut a = recovered(Scenario {
        eve_phone: true,
        ..Scenario::default()
    });
    let seen = watch_with_restarts(&mut a);
    assert!(never(&seen), "{seen:?}");
}
