//! Calls with several people (D92 to D94): a group made for a call, a ring
//! that reaches someone the group is only offered to and whose answer
//! joins it, and a ring for some of a group that nobody passes on
//! (`profiles.md#calls-guidance`, `profiles.md#a-group-made-for-a-call`).
//!
//! Where a test needs a device to say on the wire what the node itself
//! never would, it stops that person's daemon and speaks for their device
//! with its real keys, as `group_call_attacks` does.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use cardinal_encoding::{Record, Value as Wire};
use cardinal_link::{
    Bind, CarrierKind, Endpoint, EndpointConfig, LocalIdentity, MemoryDirectory, Priority, Service,
    Session, Target,
};
use cardinald::keys::Keys;
use common::*;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;

const RING: u64 = 1;

fn reply(d: &Dev, req: &Value) -> Value {
    common::reply(d, req)
}

fn ask(d: &Dev, req: Value) -> Value {
    let r = reply(d, &req);
    assert_eq!(r["ok"], true, "{req} got {r}");
    r
}

fn refused(d: &Dev, req: Value) -> String {
    let r = reply(d, &req);
    assert_eq!(r["ok"], false, "{req} was not refused: {r}");
    r["error"].as_str().unwrap_or_default().to_owned()
}

fn person(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start_with(&["--no-mount"]);
    d.cli(&["init", "--yes", "--name", name]);
    // nobody here carries calls for others: what rings is the subject
    ask(
        &d,
        json!({"cmd": "conditions", "plugged_in": false, "metered": false}),
    );
    d
}

fn called(d: &Dev) -> String {
    let mut c = d.name.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

/// `a` invites `b`; each calls the other by name.
fn meet(a: &Dev, b: &Dev) {
    let at = format!("127.0.0.1:{}", a.port);
    let code = a.cli(&["invite", "--address", &at, "--name", &called(a)]);
    b.cli(&["accept", code.trim(), "--name", &called(a)]);
    wait("they meet", 30, || a.cli(&["contacts"]).contains(b.name));
    ask(
        a,
        json!({"cmd": "contact", "who": b.name, "name": called(b)}),
    );
}

/// Whether `d` has a session with its contact `name`.
fn in_touch(d: &Dev, name: &str) -> bool {
    let all = ask(d, json!({"cmd": "contacts"}))["contacts"].clone();
    all.as_array()
        .into_iter()
        .flatten()
        .any(|c| c["name"] == name && c["connected"] == true)
}

fn groups(d: &Dev) -> Value {
    ask(d, json!({"cmd": "groups"}))
}

fn offer(d: &Dev, g: &str) -> Option<Value> {
    let v = groups(d);
    let all = v["offers"].as_array().cloned().unwrap_or_default();
    all.into_iter().find(|o| o["group"] == g)
}

fn joined(d: &Dev, g: &str) -> Option<Value> {
    let v = groups(d);
    let all = v["groups"].as_array().cloned().unwrap_or_default();
    all.into_iter().find(|o| o["group"] == g)
}

/// A group `admin` makes with `others`, who join it; `extra` are fields of
/// the `group-create`.
fn group_with(admin: &Dev, others: &[&Dev], extra: Value) -> String {
    let people: Vec<String> = others.iter().map(|d| called(d)).collect();
    let mut req = json!({"cmd": "group-create", "name": "Call", "people": people});
    for (k, v) in extra.as_object().unwrap() {
        req[k] = v.clone();
    }
    let g = ask(admin, req)["group"].as_str().unwrap().to_owned();
    for d in others {
        wait("offered", 30, || offer(d, &g).is_some());
        ask(d, json!({"cmd": "group-join", "group": g}));
    }
    let all = others.len() + 1;
    wait("everyone sees everyone", 30, || {
        others.iter().chain([&admin]).all(|d| {
            let m = reply(d, &json!({"cmd": "group-members", "group": g}));
            m["members"].as_array().is_some_and(|m| m.len() == all)
        })
    });
    g
}

/// `admin` adds `who` to `g`, and waits until `who` holds it open as an
/// offer showing `members` members.
fn add(admin: &Dev, g: &str, who: &Dev, members: u64) {
    ask(
        admin,
        json!({"cmd": "group-add", "group": g, "people": [called(who)]}),
    );
    let open = || {
        offer(who, g).is_some_and(|o| o["members"] == members)
            && reply(who, &json!({"cmd": "group-members", "group": g}))["ok"] == true
    };
    for _ in 0..120 {
        if open() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!(
        "the offer is not held open: {:?} / {}",
        offer(who, g),
        reply(who, &json!({"cmd": "group-members", "group": g}))
    );
}

fn call(d: &Dev) -> Value {
    ask(d, json!({"cmd": "call"}))["call"].clone()
}

fn ended(d: &Dev) -> Value {
    ask(d, json!({"cmd": "call"}))["ended"].clone()
}

fn state(d: &Dev) -> String {
    call(d)["state"].as_str().unwrap_or_default().to_owned()
}

/// Nothing rings on `d` for a while.
fn rings_not(d: &Dev, what: &str) {
    for _ in 0..12 {
        assert!(call(d).is_null(), "{what}: {}", call(d));
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn entries(d: &Dev, g: &str) -> u64 {
    let at = d.home.join("spaces").join(g).join("entries.log");
    std::fs::metadata(at).map_or(0, |m| m.len())
}

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    let byte = |i: usize| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    std::array::from_fn(byte)
}

/// The full identity of `of`'s contact `name`, from the logs `of` holds.
fn identity_of(of: &Dev, name: &str) -> [u8; 32] {
    let all = ask(of, json!({"cmd": "contacts"}))["contacts"].clone();
    let short = all
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap()["identity"]
        .as_str()
        .unwrap()
        .to_owned();
    let dir = std::fs::read_dir(of.home.join("others")).unwrap();
    let full = dir
        .flatten()
        .map(|e| {
            e.file_name()
                .to_string_lossy()
                .split('.')
                .next()
                .unwrap()
                .to_owned()
        })
        .find(|n| n.starts_with(&short))
        .unwrap();
    unhex(&full)
}

/// A device this test speaks for, with its real keys, connected to one
/// other device.
struct Speaker {
    session: Session,
    _endpoint: Endpoint,
}

impl Speaker {
    async fn open(me: &Dev, me_id: [u8; 32], to: &Dev, to_id: [u8; 32]) -> Speaker {
        let keys = Keys::load_or_create(&me.home.join("device.key")).unwrap();
        let peer = Keys::load_or_create(&to.home.join("device.key")).unwrap();
        let directory = MemoryDirectory::new();
        let link = peer.link.public_key();
        directory.add_device(to_id, peer.key(), link.clone());
        let mut config = EndpointConfig::new(keys.link.clone(), directory);
        config.identity = Some(LocalIdentity {
            identity: me_id,
            signing_key: keys.signing.clone(),
        });
        config.connect_timeout = Duration::from_secs(3);
        let bind = Bind {
            udp: Some("127.0.0.1:0".parse().unwrap()),
            tcp: None,
        };
        let endpoint = Endpoint::bind(config, bind).await.unwrap();
        let addr: SocketAddr = format!("127.0.0.1:{}", to.port).parse().unwrap();
        let target = Target::new(addr, CarrierKind::Udp, link);
        let session = endpoint.connect(target).await.unwrap();
        Speaker {
            session,
            _endpoint: endpoint,
        }
    }

    /// A `ring` in `space` for call `id`, naming `caller`, with `3:` as
    /// given.
    async fn ring(&self, space: [u8; 32], id: [u8; 16], caller: [u8; 32], three: Option<Wire>) {
        let mut r = Record::new().with(0, RING).with(1, space).with(2, id);
        if let Some(f) = three {
            r = r.with(3, f);
        }
        r = r.with(4, caller);
        let mut st = self
            .session
            .open_stream(Service::EPHEMERAL, Priority::RealTime)
            .unwrap();
        st.send_message(&Wire::Record(r)).await.unwrap();
        st.shutdown().await.unwrap();
    }
}

/// D93, D94: in a group Cy has only been offered, a ring rings only from a
/// device of whoever offered it, naming them, never passed on, and with no
/// `3:` other than 1. It says who is calling and who looks after the
/// group, and that answering joins it. Saying no writes nothing and leaves
/// the offer. A ring for some rings again each time it is asked, and is
/// not passed on; a ring for the whole group rings once for a call.
#[test]
fn in_a_group_only_offered_only_its_adder_rings() {
    let root = tempfile::tempdir().unwrap();
    let mut ana = person(root.path(), "ana");
    let bo = person(root.path(), "bo");
    let cy = person(root.path(), "cy");
    meet(&ana, &bo);
    meet(&ana, &cy);
    meet(&bo, &cy);
    let g = group_with(&ana, &[&bo], json!({"for_call": true}));
    add(&ana, &g, &cy, 3);
    let space: [u8; 32] = unhex(&g);
    let ana_id = identity_of(&cy, "Ana");
    let bo_id = identity_of(&cy, "Bo");
    let o = offer(&cy, &g).unwrap();
    assert_eq!(o["for_call"], true, "{o}");
    assert!(o["last_call"].is_null(), "{o}");

    // Bo, a member who did not add Cy, calls the group: his ring reaches
    // Cy's device and does not ring there.
    wait("bo and cy in touch", 20, || in_touch(&bo, "Cy"));
    ask(&bo, json!({"cmd": "call-start", "group": g}));
    rings_not(&cy, "a ring from bo");
    ask(&bo, json!({"cmd": "call-end"}));

    let (cy_id, bo_at_ana) = (identity_of(&ana, "Cy"), identity_of(&ana, "Bo"));
    assert_eq!(bo_at_ana, bo_id);
    ana.stop();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let to_cy = rt.block_on(Speaker::open(&ana, ana_id, &cy, cy_id));
    let ana_bo = identity_of(&bo, "Ana");
    let to_bo = rt.block_on(Speaker::open(&ana, ana_bo, &bo, bo_id));

    // Ana rings Bo alone with a ring for the whole group: Bo rings and
    // passes it on to Cy, naming Ana; passed on, it does not ring there.
    rt.block_on(to_bo.ring(space, [1; 16], ana_bo, None));
    wait("bo rings", 10, || state(&bo) == "ringing");
    rings_not(&cy, "a ring bo passed on");
    ask(&bo, json!({"cmd": "call-end"}));

    // From Ana's own device: a `3:` other than 1, or another caller named,
    // and nothing rings.
    rt.block_on(to_cy.ring(space, [2; 16], ana_id, Some(Wire::from(2u64))));
    rt.block_on(to_cy.ring(space, [3; 16], ana_id, Some(Wire::from("1"))));
    rt.block_on(to_cy.ring(space, [4; 16], bo_id, None));
    rt.block_on(to_cy.ring(space, [5; 16], bo_id, Some(Wire::from(1u64))));
    rings_not(&cy, "odd rings");

    // A ring for some, naming Ana: it rings, says who and who looks after
    // the group, and that answering joins it. Bo is not rung by it.
    rt.block_on(to_cy.ring(space, [6; 16], ana_id, Some(Wire::from(1u64))));
    wait("cy rings", 10, || state(&cy) == "ringing");
    let c = call(&cy);
    assert_eq!(c["group"], g.as_str(), "{c}");
    assert_eq!(c["joins"], true, "{c}");
    assert_eq!(c["for_call"], true, "{c}");
    assert_eq!(c["caller"]["name"], "Ana", "{c}");
    let admins: Vec<&str> = c["admins"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["role"].as_str().unwrap())
        .collect();
    assert_eq!(admins, ["owner"], "{c}");
    assert_eq!(c["admins"][0]["name"], "Ana", "{c}");
    assert!(c["admins"][0].get("reach").is_none(), "{c}");
    assert_eq!(c["reach"]["ask"], false, "{c}");
    assert!(call(&bo).is_null(), "a ring for some was passed on");

    // Saying no writes nothing and leaves the offer.
    let before = entries(&cy, &g);
    ask(&cy, json!({"cmd": "call-end"}));
    assert_eq!(ended(&cy)["how"], "declined");
    assert!(ended(&cy)["at"].as_u64().unwrap() > 0);
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(entries(&cy, &g), before, "saying no wrote in the group");
    let o = offer(&cy, &g).expect("the offer stays");
    assert_eq!(o["last_call"]["how"], "declined", "{o}");
    assert!(joined(&cy, &g).is_none());

    // Asked again, the same call rings again.
    rt.block_on(to_cy.ring(space, [6; 16], ana_id, Some(Wire::from(1u64))));
    wait("cy rings again", 10, || state(&cy) == "ringing");
    ask(&cy, json!({"cmd": "call-end"}));

    // A ring for the whole group rings once for a call.
    rt.block_on(to_cy.ring(space, [7; 16], ana_id, None));
    wait("cy rings for the group", 10, || state(&cy) == "ringing");
    assert_eq!(call(&cy)["caller"]["name"], "Ana");
    ask(&cy, json!({"cmd": "call-end"}));
    rt.block_on(to_cy.ring(space, [7; 16], ana_id, None));
    rings_not(&cy, "a ring for the whole group, again");
}

/// D93, with the always-on device asked about: answering a ring in a group
/// only offered joins it, as `group-join` does. Without the answer about
/// the host it fails with the question, writes nothing, and the call goes
/// on ringing; with it, the person joins the group and the call.
#[test]
fn answering_joins_the_group_and_asks_about_the_host_first() {
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let bo = person(root.path(), "bo");
    let cy = person(root.path(), "cy");
    let at = format!("127.0.0.1:{}", cy.port);
    cy.cli(&["host", "--address", &at]);
    meet(&ana, &bo);
    meet(&ana, &cy);
    let g = group_with(&ana, &[&bo], json!({"for_call": true}));
    ask(&ana, json!({"cmd": "call-start", "group": g}));
    wait("bo rings", 20, || state(&bo) == "ringing");
    // Bo was rung by Ana's own device: who called is known
    assert_eq!(call(&bo)["caller"]["name"], "Ana", "{}", call(&bo));
    ask(&bo, json!({"cmd": "call-answer"}));
    wait("ana and bo linked", 20, || call(&ana)["linked"] == 1);

    // Ana adds Cy to the call: the group, and a ring for Cy alone.
    add(&ana, &g, &cy, 3);
    ask(
        &ana,
        json!({"cmd": "call-start", "group": g, "ring": ["Cy"]}),
    );
    wait("cy rings", 20, || state(&cy) == "ringing");
    let c = call(&cy);
    assert_eq!(c["joins"], true, "{c}");
    assert_eq!(c["reach"]["ask"], true, "{c}");
    assert_eq!(c["reach"]["who"], json!(["bo"]), "{c}");
    assert_eq!(state(&bo), "live", "bo was rung again");

    // Not answered about the host: refused with the question, nothing
    // written, still ringing.
    std::thread::sleep(Duration::from_secs(1));
    let before = entries(&cy, &g);
    let why = refused(&cy, json!({"cmd": "call-answer"}));
    assert!(why.contains("bo") && why.contains(&at), "{why}");
    assert_eq!(state(&cy), "ringing");
    assert!(joined(&cy, &g).is_none());
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(entries(&cy, &g), before);
    // `reach` on no group call is refused elsewhere; here it is the answer
    ask(&cy, json!({"cmd": "call-answer", "reach": false}));
    wait("cy joined", 20, || joined(&cy, &g).is_some());
    assert!(offer(&cy, &g).is_none());
    assert_eq!(joined(&cy, &g).unwrap()["for_call"], true);
    assert_eq!(state(&cy), "live");
    wait("cy linked", 20, || call(&cy)["linked"].as_u64() >= Some(1));
    let shared = &joined(&cy, &g).unwrap()["reach"];
    assert_eq!(shared["shared"], false, "{shared}");
    assert!(call(&cy).get("joins").is_none_or(Value::is_null));
}

/// D94, the request: `call-start` `ring` names members to ring, and is
/// refused, ringing nobody, for one who is not a member, has left, is the
/// person, or is not their contact, and when it is empty or comes with
/// `who`. A ring for some rings only them and is passed on by nobody. In a
/// joined group, who rang is said only where the ring came from the
/// caller's own device; who looks after it is the owner, then the admins.
#[test]
fn ringing_some_rings_only_them_and_refuses_the_rest() {
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let bo = person(root.path(), "bo");
    let cy = person(root.path(), "cy");
    let dee = person(root.path(), "dee");
    let eve = person(root.path(), "eve");
    meet(&bo, &ana);
    meet(&bo, &cy);
    meet(&bo, &dee);
    meet(&ana, &dee);
    meet(&ana, &eve);
    // Bo's group of Ana, Cy and Dee; Cy is not Ana's contact. Ana is an
    // admin.
    let g = group_with(&bo, &[&ana, &cy, &dee], json!({}));
    ask(
        &bo,
        json!({"cmd": "group-role", "group": g, "who": "Ana", "role": "admin"}),
    );
    wait("ana is an admin", 20, || {
        joined(&ana, &g).is_some_and(|x| x["admin"] == true)
    });
    // the name the group shows for Ana herself
    let me = "ana";
    for (req, what) in [
        (
            json!({"cmd": "call-start", "group": g, "ring": ["cy"]}),
            "not a contact",
        ),
        (
            json!({"cmd": "call-start", "group": g, "ring": ["Eve"]}),
            "not a member",
        ),
        (
            json!({"cmd": "call-start", "group": g, "ring": ["Nobody"]}),
            "nobody",
        ),
        (
            json!({"cmd": "call-start", "group": g, "ring": ["Bo", "cy"]}),
            "one not a contact",
        ),
        (
            json!({"cmd": "call-start", "group": g, "ring": []}),
            "empty",
        ),
        (
            json!({"cmd": "call-start", "who": "Bo", "group": g, "ring": ["Bo"]}),
            "with who",
        ),
        (
            json!({"cmd": "call-start", "group": g, "ring": [me]}),
            "you",
        ),
    ] {
        let why = refused(&ana, req);
        assert!(!why.is_empty(), "{what}");
        if what == "you" || what == "not a contact" {
            assert!(
                why.contains(if what == "you" { "you" } else { "contact" }),
                "{why}"
            );
        }
    }
    assert!(call(&ana).is_null(), "a refused request started a call");
    rings_not(&bo, "a refused request rang");

    // Dee leaves: ringing her is refused, saying she left.
    ask(&dee, json!({"cmd": "group-leave", "group": g}));
    wait("ana sees dee left", 30, || {
        let m = ask(&ana, json!({"cmd": "group-members", "group": g}));
        m["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["left"] == true)
    });
    let why = refused(
        &ana,
        json!({"cmd": "call-start", "group": g, "ring": ["Dee"]}),
    );
    assert!(why.contains("left"), "{why}");

    // Bo alone is rung; Cy, Bo's contact, is not, since nobody passes a
    // ring for some on.
    wait("bo and cy in touch", 20, || in_touch(&bo, "Cy"));
    ask(
        &ana,
        json!({"cmd": "call-start", "group": g, "ring": ["Bo"]}),
    );
    wait("bo rings", 20, || state(&bo) == "ringing");
    assert_eq!(call(&bo)["caller"]["name"], "Ana");
    rings_not(&cy, "a ring for some, passed on");
    ask(&bo, json!({"cmd": "call-end"}));
    ask(&ana, json!({"cmd": "call-end"}));

    // The whole group: Cy is rung only by Bo passing it on, so who called
    // is not said there; who looks after it is Bo, the owner, then Ana.
    std::thread::sleep(Duration::from_secs(1));
    ask(&ana, json!({"cmd": "call-start", "group": g}));
    wait("cy rings", 20, || state(&cy) == "ringing");
    let c = call(&cy);
    assert!(c["caller"].is_null(), "{c}");
    let roles: Vec<&str> = c["admins"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["role"].as_str().unwrap())
        .collect();
    assert_eq!(roles, ["owner", "admin"], "{c}");
    assert_eq!(c["admins"][0]["name"], "Bo", "{c}");
    assert_eq!(c["for_call"], false, "{c}");
    assert!(c["joins"].is_null(), "{c}");
    assert_eq!(call(&bo)["caller"]["name"], "Ana", "{}", call(&bo));
    for d in [&cy, &bo, &ana] {
        ask(d, json!({"cmd": "call-end"}));
    }
    // A call between two people takes no `reach`.
    ask(&bo, json!({"cmd": "call-start", "who": "Cy"}));
    wait("cy rings from bo", 20, || state(&cy) == "ringing");
    let why = refused(&cy, json!({"cmd": "call-answer", "reach": true}));
    assert!(why.contains("reach"), "{why}");
    assert_eq!(state(&cy), "ringing");
    ask(&cy, json!({"cmd": "call-end"}));
}

/// D93: a ring from the adder that comes before the offer, or before the
/// group has opened, is kept, and rings once the rest holds.
#[test]
fn a_ring_before_the_offer_rings_once_the_group_opens() {
    let root = tempfile::tempdir().unwrap();
    let mut ana = person(root.path(), "ana");
    let bo = person(root.path(), "bo");
    let mut cy = person(root.path(), "cy");
    meet(&ana, &bo);
    meet(&ana, &cy);
    let g = group_with(&ana, &[&bo], json!({"for_call": true}));
    let space: [u8; 32] = unhex(&g);
    let ana_id = identity_of(&cy, "Ana");
    let cy_id = identity_of(&ana, "Cy");
    // Cy is away while Ana adds him; then Ana is.
    cy.stop();
    ask(
        &ana,
        json!({"cmd": "group-add", "group": g, "people": ["Cy"]}),
    );
    std::thread::sleep(Duration::from_secs(1));
    ana.stop();
    cy.start_with(&["--no-mount"]);
    assert!(offer(&cy, &g).is_none());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let to_cy = rt.block_on(Speaker::open(&ana, ana_id, &cy, cy_id));
    rt.block_on(to_cy.ring(space, [9; 16], ana_id, Some(Wire::from(1u64))));
    rings_not(&cy, "before the offer");
    drop(to_cy);
    // Ana is back: the offer comes, the group opens, and it rings.
    ana.start_with(&["--no-mount"]);
    wait("the kept ring rings", 40, || state(&cy) == "ringing");
    let c = call(&cy);
    assert_eq!(c["id"], hex::encode([9u8; 16]), "{c}");
    assert_eq!(c["joins"], true, "{c}");
    assert_eq!(c["caller"]["name"], "Ana", "{c}");
    ask(&cy, json!({"cmd": "call-end"}));
    assert!(offer(&cy, &g).is_some());
}

/// D92: `last_call` is the device's own, kept across restarts.
#[test]
fn the_last_call_in_a_group_is_kept_across_a_restart() {
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let mut bo = person(root.path(), "bo");
    meet(&ana, &bo);
    let g = group_with(&ana, &[&bo], json!({"for_call": true}));
    assert!(joined(&bo, &g).unwrap()["last_call"].is_null());
    ask(&ana, json!({"cmd": "call-start", "group": g}));
    wait("bo rings", 20, || state(&bo) == "ringing");
    let id = call(&bo)["id"].clone();
    ask(&bo, json!({"cmd": "call-end"}));
    ask(&ana, json!({"cmd": "call-end"}));
    let last = joined(&bo, &g).unwrap()["last_call"].clone();
    assert_eq!(last["how"], "declined", "{last}");
    assert_eq!(last["id"], id, "{last}");
    assert_eq!(last["group"], g.as_str(), "{last}");
    assert!(last["at"].as_u64().unwrap() > 1_700_000_000_000, "{last}");
    let anas = joined(&ana, &g).unwrap()["last_call"].clone();
    assert_eq!(anas["how"], "cancelled", "{anas}");
    bo.stop();
    bo.start_with(&["--no-mount"]);
    assert_eq!(joined(&bo, &g).unwrap()["last_call"], last);
    // and the command line says it
    let out = bo.cli(&["groups"]);
    assert!(
        out.contains("made for a call") && out.contains("Last call: declined"),
        "{out}"
    );
}

/// D92: the mark is a genesis's alone. `group-set` `for_call` false keeps
/// the group, for everyone, and true is refused; on an ordinary group,
/// false writes nothing. A successor the node makes is a call group where
/// the group was one, and not otherwise. A group that does not share its
/// history takes nobody new, and nobody back.
#[test]
fn the_mark_is_set_only_by_a_genesis() {
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let bo = person(root.path(), "bo");
    let cy = person(root.path(), "cy");
    meet(&ana, &bo);
    meet(&ana, &cy);
    let g = group_with(&ana, &[&bo, &cy], json!({"for_call": true}));
    assert_eq!(hello_api(&ana), 3);
    for d in [&ana, &bo] {
        assert_eq!(joined(d, &g).unwrap()["for_call"], true);
    }
    // Taking someone out keeps it a call group: the successor's genesis
    // sets it again.
    let moved = ask(
        &ana,
        json!({"cmd": "group-remove", "group": g, "who": "Cy"}),
    );
    let g = moved["group"].as_str().unwrap().to_owned();
    wait("bo follows", 30, || joined(&bo, &g).is_some());
    assert_eq!(joined(&bo, &g).unwrap()["for_call"], true);
    // True is refused, with nothing written; a member who is not an admin
    // is refused too.
    std::thread::sleep(Duration::from_secs(1));
    let before = entries(&ana, &g);
    let why = refused(
        &ana,
        json!({"cmd": "group-set", "group": g, "for_call": true, "name": "X"}),
    );
    assert!(why.contains("group-create"), "{why}");
    refused(
        &bo,
        json!({"cmd": "group-set", "group": g, "for_call": false}),
    );
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(entries(&ana, &g), before);
    assert_eq!(joined(&ana, &g).unwrap()["name"], "Call");
    // Keep this group: for everyone, and for good.
    ana.cli(&["group", "keep", &g]);
    for d in [&ana, &bo] {
        wait("kept", 20, || joined(d, &g).unwrap()["for_call"] == false);
    }
    refused(
        &ana,
        json!({"cmd": "group-set", "group": g, "for_call": true}),
    );
    // false again, on what is ordinary now, writes nothing
    std::thread::sleep(Duration::from_secs(1));
    let before = entries(&ana, &g);
    ask(
        &ana,
        json!({"cmd": "group-set", "group": g, "for_call": false}),
    );
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(entries(&ana, &g), before);
    // A successor of a kept group is ordinary: lowering Bo to a reader
    // moves it.
    let moved = ask(
        &ana,
        json!({"cmd": "group-role", "group": g, "who": "Bo", "role": "reader"}),
    );
    let g2 = moved["group"].as_str().unwrap().to_owned();
    assert_ne!(g2, g);
    wait("bo follows", 30, || joined(&bo, &g2).is_some());
    assert_eq!(joined(&bo, &g2).unwrap()["for_call"], false);

    // A group that does not share its history: nobody added, nobody back.
    let n = ask(
        &ana,
        json!({"cmd": "group-create", "name": "Quiet", "people": ["Bo"], "history": false}),
    )["group"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(joined(&ana, &n).unwrap()["for_call"], false);
    std::thread::sleep(Duration::from_secs(1));
    let before = entries(&ana, &n);
    let why = refused(
        &ana,
        json!({"cmd": "group-add", "group": n, "people": ["Cy"]}),
    );
    assert!(why.contains("history"), "{why}");
    wait("bo offered quiet", 30, || offer(&bo, &n).is_some());
    ask(&bo, json!({"cmd": "group-join", "group": n}));
    ask(
        &ana,
        json!({"cmd": "group-leave", "group": n, "admins": ["Bo"]}),
    );
    let why = refused(&ana, json!({"cmd": "group-rejoin", "group": n}));
    assert!(why.contains("history"), "{why}");
    let _ = before;
    // the command line makes one
    let out = ana.cli(&["group", "create", "Talk", "Bo", "--for-call"]);
    let _ = out;
    wait("talk is a call group", 10, || {
        groups(&ana)["groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["name"] == "Talk" && x["for_call"] == true)
    });
}

fn hello_api(d: &Dev) -> u64 {
    ask(d, json!({"cmd": "hello"}))["api"].as_u64().unwrap()
}
