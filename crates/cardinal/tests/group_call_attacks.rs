//! Group calls against a member who means harm (`profiles.md#calls`): Mal is
//! in Ana's group, and this test speaks for his device with his real keys.
//! He cannot join a call of a group he is not in by naming his own group,
//! cannot speak as Bo, cannot get a frame he made up past Ana by sending it
//! straight, and cannot make Ana's device carry any number of calls.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use cardinal_encoding::{Record, Value};
use cardinal_link::{
    Bind, CarrierKind, Endpoint, EndpointConfig, LocalIdentity, MemoryDirectory, Priority, Service,
    Session, Target,
};
use cardinald::keys::Keys;
use common::*;
use serde_json::{json, Value as Json};
use tokio::io::AsyncWriteExt;

const RING: u64 = 1;
const JOIN: u64 = 4;

fn reply(d: &Dev, req: &Json) -> Json {
    common::reply(d, req)
}

fn ask(d: &Dev, req: Json) -> Json {
    let r = reply(d, &req);
    assert_eq!(r["ok"], true, "{req} got {r}");
    r
}

fn person(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start_with(&["--no-mount"]);
    d.cli(&["init", "--yes", "--name", name]);
    d
}

fn called(d: &Dev) -> String {
    let mut c = d.name.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

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

fn group(admin: &Dev, name: &str, others: &[&Dev]) -> [u8; 32] {
    let people: Vec<String> = others.iter().map(|d| called(d)).collect();
    let made = ask(
        admin,
        json!({"cmd": "group-create", "name": name, "people": people}),
    );
    let g = made["group"].as_str().unwrap().to_owned();
    for d in others {
        wait("offered", 30, || {
            let v = ask(d, json!({"cmd": "groups"}));
            v["offers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o["group"] == g.as_str())
        });
        ask(d, json!({"cmd": "group-join", "group": g}));
    }
    let all = others.len() + 1;
    wait("everyone sees everyone", 30, || {
        others.iter().chain([&admin]).all(|d| {
            let m = reply(d, &json!({"cmd": "group-members", "group": g}));
            m["members"].as_array().is_some_and(|m| m.len() == all)
        })
    });
    unhex(&g)
}

fn call(d: &Dev) -> Json {
    ask(d, json!({"cmd": "call"}))["call"].clone()
}

fn linked(d: &Dev) -> u64 {
    call(d)["linked"].as_u64().unwrap_or(0)
}

fn label(space: &[u8; 32], id: &[u8; 16]) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    h.update(space);
    h.update(id);
    h.finalize().as_bytes()[..16].try_into().unwrap()
}

fn voice_of(key: &[u8; 32]) -> [u8; 8] {
    blake3::hash(key).as_bytes()[..8].try_into().unwrap()
}

/// A frame of `voice` whose signature is made up.
fn made_up(voice: [u8; 8], n: u32) -> Vec<u8> {
    let mut f = voice.to_vec();
    f.extend_from_slice(&n.to_be_bytes());
    f.extend_from_slice(&[7u8; 64]);
    f.extend_from_slice(b"not what anyone said");
    f
}

/// Mal's device, as this test drives it, connected to Ana's.
struct Mal {
    session: Session,
    _endpoint: Endpoint,
}

impl Mal {
    async fn open(mal: &Dev, mal_id: [u8; 32], ana: &Dev, ana_id: [u8; 32]) -> Mal {
        let keys = Keys::load_or_create(&mal.home.join("device.key")).unwrap();
        let peer = Keys::load_or_create(&ana.home.join("device.key")).unwrap();
        let directory = MemoryDirectory::new();
        let link = peer.link.public_key();
        directory.add_device(ana_id, peer.key(), link.clone());
        let mut config = EndpointConfig::new(keys.link.clone(), directory);
        config.identity = Some(LocalIdentity {
            identity: mal_id,
            signing_key: keys.signing.clone(),
        });
        config.connect_timeout = Duration::from_secs(3);
        let bind = Bind {
            udp: Some("127.0.0.1:0".parse().unwrap()),
            tcp: None,
        };
        let endpoint = Endpoint::bind(config, bind).await.unwrap();
        let addr: SocketAddr = format!("127.0.0.1:{}", ana.port).parse().unwrap();
        let target = Target::new(addr, CarrierKind::Udp, link);
        let session = endpoint.connect(target).await.unwrap();
        Mal {
            session,
            _endpoint: endpoint,
        }
    }

    async fn signal(&self, kind: u64, space: [u8; 32], id: [u8; 16], flag: Option<u64>) {
        let Ok(mut st) = self
            .session
            .open_stream(Service::EPHEMERAL, Priority::RealTime)
        else {
            return;
        };
        let mut r = Record::new().with(0, kind).with(1, space).with(2, id);
        if let Some(f) = flag {
            r = r.with(3, f);
        }
        let _ = st.send_message(&Value::Record(r)).await;
        let _ = st.shutdown().await;
    }
}

#[test]
fn a_member_who_means_harm_gets_nowhere_on_a_group_call() {
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let bo = person(root.path(), "bo");
    let mut mal = person(root.path(), "mal");
    for d in [&ana, &bo, &mal] {
        ask(
            d,
            json!({"cmd": "conditions", "plugged_in": false, "metered": false}),
        );
    }
    meet(&ana, &bo);
    meet(&ana, &mal);
    let family = group(&ana, "Family", &[&bo, &mal]);
    let other = group(&ana, "Other", &[&bo]);
    let mal_id = identity_of(&ana, "Mal");
    let ana_id = identity_of(&mal, "Ana");
    let bo_voice = voice_of(
        &Keys::load_or_create(&bo.home.join("device.key"))
            .unwrap()
            .key(),
    );
    let mal_voice = voice_of(
        &Keys::load_or_create(&mal.home.join("device.key"))
            .unwrap()
            .key(),
    );
    mal.stop();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let m = rt.block_on(Mal::open(&mal, mal_id, &ana, ana_id));

    // A call in Other, which Mal is not in. Knowing its id, he names his own
    // group with it: Ana's device does not link him.
    ask(
        &ana,
        json!({"cmd": "call-start", "group": hex::encode(other)}),
    );
    wait("bo rings", 20, || call(&bo)["state"] == "ringing");
    ask(&bo, json!({"cmd": "call-answer"}));
    wait("ana links bo", 20, || linked(&ana) == 1);
    let other_call: [u8; 16] = unhex(call(&ana)["id"].as_str().unwrap());
    rt.block_on(m.signal(JOIN, family, other_call, Some(0)));
    rt.block_on(m.signal(JOIN, other, other_call, Some(0)));
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(linked(&ana), 1, "mal is not linked into a call of Other");
    ask(&ana, json!({"cmd": "call-end"}));
    ask(&bo, json!({"cmd": "call-end"}));

    // A call in Family, which he is in: he is linked, and once he passes on
    // a frame he made up, as Bo's or as his own, he is let go.
    ask(
        &ana,
        json!({"cmd": "call-start", "group": hex::encode(family)}),
    );
    wait("bo rings", 20, || call(&bo)["state"] == "ringing");
    ask(&bo, json!({"cmd": "call-answer"}));
    wait("ana links bo", 20, || linked(&ana) == 1);
    let family_call: [u8; 16] = unhex(call(&ana)["id"].as_str().unwrap());
    let sound = label(&family, &family_call);
    for (voice, what) in [(bo_voice, "as bo"), (mal_voice, "as himself")] {
        rt.block_on(m.signal(JOIN, family, family_call, Some(0)));
        wait("mal is linked", 10, || linked(&ana) == 2);
        let n = 4_000_000_000 + u32::from(voice[0]);
        let _ = m
            .session
            .send_datagram(sound, Priority::RealTime, made_up(voice, n));
        wait(&format!("mal, speaking {what}, is let go"), 10, || {
            linked(&ana) == 1
        });
    }
    ask(&ana, json!({"cmd": "call-end"}));
    ask(&bo, json!({"cmd": "call-end"}));

    // Rings in Family with made-up ids: Ana's device, plugged in, carries
    // one call there at most, and is not rung more than so often.
    ask(
        &ana,
        json!({"cmd": "conditions", "plugged_in": true, "metered": false}),
    );
    for i in 0..20u8 {
        rt.block_on(m.signal(RING, family, [i; 16], None));
    }
    std::thread::sleep(Duration::from_secs(1));
    let carrying = ana.status()["carrying_calls"].as_u64().unwrap();
    assert!(carrying <= 1, "carrying {carrying}");
}
