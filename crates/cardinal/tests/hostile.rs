//! A delivery token in the hands of someone who means harm: a client of its
//! own, with the real token, against a real host over real sockets, doing
//! what an honest device never would.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cardinal_crypto::{derive, HybridKeyPair, Purpose, SigningKey};
use cardinal_encoding::{Record, Value};
use cardinal_link::{
    Bind, CarrierKind, Endpoint, EndpointConfig, LocalIdentity, MemoryDirectory, Priority, Service,
    Session, Target,
};
use cardinal_sync::{BlobRequest, MemSet, Message, Reconciler};
use cardinald::mailbox::TOKEN_SESSIONS;
use common::*;
use tokio::io::AsyncWriteExt;

const ERROR: u64 = 0;
const NOT_PERMITTED: u64 = 1;
const DEPOSIT: u64 = 1;
const FETCH: u64 = 2;
const REGISTER: u64 = 4;
const REVOKE: u64 = 5;
const USAGE: u64 = 6;

fn hosted(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start();
    d.cli(&["init", "--yes", "--name", name]);
    d.wait_mounted();
    let at = format!("127.0.0.1:{}", d.port);
    d.cli(&["host", "--address", &at]);
    d
}

/// A host, and the token someone was given for it.
struct Their {
    addr: SocketAddr,
    host: [u8; 32],
    token: [u8; 16],
}

/// Bo accepts Ana's invitation, and what Bo was given is read off Ana's disk.
fn given_a_token(ana: &Dev, bo: &Dev) -> Their {
    let at = format!("127.0.0.1:{}", ana.port);
    let args = ["invite", "--address", &at, "--name", "Ana", "--hosts-only"];
    let code = ana.cli(&args).trim().to_owned();
    bo.cli(&["accept", &code, "--hosts-only"]);
    wait("ana lists bo", 20, || ana.cli(&["contacts"]).contains("bo"));

    let state = std::fs::read(ana.home.join("mailbox/state.json")).unwrap();
    let state: serde_json::Value = serde_json::from_slice(&state).unwrap();
    let token = state["active"][0].as_str().unwrap();
    let sheet = ana.cli(&["recovery", "sheet"]);
    let key = sheet.lines().find(|l| l.contains("Key:")).unwrap();
    let key = key.split_whitespace().last().unwrap();
    Their {
        addr: at.parse().unwrap(),
        host: cardinald::host::read_sheet_key(key).unwrap(),
        token: unhex(token),
    }
}

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    let byte = |i: usize| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    std::array::from_fn(byte)
}

/// The id of something in a blob store, which keeps them by id.
fn a_chunk(dir: &std::path::Path) -> [u8; 32] {
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if e.path().is_dir() {
                dirs.push(e.path());
            } else if name.len() == 64 {
                return unhex(&name);
            }
        }
    }
    panic!("no chunk in {}", dir.display());
}

fn spaces(d: &Dev) -> Vec<[u8; 32]> {
    let dir = std::fs::read_dir(d.home.join("spaces")).unwrap();
    let names = dir.flatten().map(|e| e.file_name());
    names.map(|n| unhex(n.to_str().unwrap())).collect()
}

/// Opens a session with the token, as someone new each time.
async fn open(t: &Their, identity: Option<LocalIdentity>) -> Option<(Endpoint, Session)> {
    let key = Arc::new(HybridKeyPair::generate());
    let mut config = EndpointConfig::new(key, MemoryDirectory::new());
    config.identity = identity;
    config.connect_timeout = Duration::from_secs(3);
    let bind = Bind {
        udp: Some("127.0.0.1:0".parse().unwrap()),
        tcp: None,
    };
    let endpoint = Endpoint::bind(config, bind).await.unwrap();
    let secret = derive(Purpose::Token, &t.token);
    let target = Target::invitation(t.addr, CarrierKind::Udp, t.host, &secret[..]);
    let session = endpoint.connect(target).await.ok()?;
    Some((endpoint, session))
}

/// One request, and its reply if there is one.
async fn ask(s: &Session, service: Service, ask: Record) -> Option<Record> {
    let exchange = async {
        let mut st = s.open_stream(service, Priority::Interactive).ok()?;
        st.send_message(&Value::Record(ask)).await.ok()?;
        st.shutdown().await.ok()?;
        let v = st.recv_message_max(1 << 20).await.ok()??;
        v.as_record().cloned()
    };
    tokio::time::timeout(Duration::from_secs(3), exchange)
        .await
        .ok()?
}

fn not_permitted(reply: Option<Record>) -> bool {
    reply.is_some_and(|r| {
        r.get(0).and_then(Value::as_uint) == Some(ERROR)
            && r.get(1).and_then(Value::as_uint) == Some(NOT_PERMITTED)
    })
}

/// What a reconcile says the host has and `have` lacks.
async fn reconcile(s: &Session, label: [u8; 32], have: MemSet) -> Vec<[u8; 32]> {
    let mut rec = Reconciler::new(label, have);
    let mut st = s.open_stream(Service::SYNC, Priority::Interactive).unwrap();
    let first = Value::Record(rec.initiate().to_record());
    st.send_message(&first).await.unwrap();
    while !rec.is_done() {
        let Ok(Ok(Some(v))) =
            tokio::time::timeout(Duration::from_secs(3), st.recv_message_max(1 << 22)).await
        else {
            break;
        };
        let Some(r) = v.as_record() else { break };
        let Ok(Message::Reconcile { ranges, .. }) = Message::from_record(r) else {
            break;
        };
        match rec.receive(&ranges).unwrap() {
            Some(reply) => st
                .send_message(&Value::Record(reply.to_record()))
                .await
                .unwrap(),
            None => break,
        }
    }
    let _ = st.shutdown().await;
    rec.take_wanted()
}

#[test]
fn a_token_opens_its_own_space_and_nothing_else() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let bo = hosted(root.path(), "bo");
    let private_file: Vec<u8> = (0..3_000_000u32).map(|n| (n * 7 % 251) as u8).collect();
    std::fs::write(ana.p("private.bin"), &private_file).unwrap();
    ana.cli(&["flush"]);
    let t = given_a_token(&ana, &bo);
    let chunk = a_chunk(&ana.home.join("blobs"));
    let theirs = spaces(&bo);
    let (shared, private): (Vec<_>, Vec<_>) =
        spaces(&ana).into_iter().partition(|s| theirs.contains(s));
    assert_eq!(shared.len(), 1, "one space between them");
    assert!(!private.is_empty());
    let shared = shared[0];

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (_endpoint, s) = open(&t, None).await.expect("a good token opens");

        assert!(!reconcile(&s, shared, MemSet::new()).await.is_empty());
        for label in &private {
            let wanted = reconcile(&s, *label, MemSet::new()).await;
            assert!(wanted.is_empty(), "read a private space");
        }

        // Having something the host lacks does not make it ask for that.
        let mut offered = MemSet::new();
        offered.insert([9; 32]);
        reconcile(&s, shared, offered).await;
        let asked = tokio::time::timeout(Duration::from_secs(2), s.accept_stream()).await;
        assert!(asked.is_err(), "the host asked a token holder for objects");

        // Nor does pushing it.
        let push = Message::Objects {
            label: shared,
            objects: vec![b"not an entry".to_vec()],
        };
        ask(&s, Service::SYNC, push.to_record()).await;

        // What only the owner may do.
        let fetch = Record::new().with(0, FETCH).with(1, 0u64);
        assert!(not_permitted(ask(&s, Service::MAILBOX, fetch).await));
        let list = Value::list([Value::Record(Record::new().with(1, [5u8; 16]))]);
        let register = Record::new().with(0, REGISTER).with(1, list);
        assert!(not_permitted(ask(&s, Service::MAILBOX, register).await));
        let list = Value::list([Value::from(t.token)]);
        let revoke = Record::new().with(0, REVOKE).with(1, list);
        assert!(not_permitted(ask(&s, Service::MAILBOX, revoke).await));

        // What only a person's own devices may ask for.
        let rendezvous = Record::new().with(0, 2u64).with(2, [1u8; 32]);
        assert!(not_permitted(
            ask(&s, Service::RENDEZVOUS, rendezvous).await
        ));
        let relay = Record::new().with(0, 1u64).with(2, [1u8; 32]);
        assert!(not_permitted(ask(&s, Service::RELAY, relay).await));
        let storage = Record::new().with(0, 2u64);
        assert!(ask(&s, Service::STORAGE, storage)
            .await
            .is_none_or(|r| { r.get(0).and_then(Value::as_uint) == Some(ERROR) }));
        let wanted = BlobRequest { ids: vec![chunk] };
        let mut blob = s.open_stream(Service::BLOB, Priority::Interactive).unwrap();
        blob.send_message_bytes(&wanted.encode()).await.unwrap();
        let _ = blob.shutdown().await;
        let got = tokio::time::timeout(Duration::from_secs(3), blob.recv_message_max(1 << 24));
        assert!(
            !matches!(got.await, Ok(Ok(Some(_)))),
            "read a private chunk"
        );
        let hello = Record::new().with(0, 1u64).with(1, [1u8; 32]).with(2, "x");
        assert!(ask(&s, Service::CONTACT, hello).await.is_none());

        // A deposit is what it may do, under this token and no other.
        let deposit = Record::new().with(0, DEPOSIT).with(1, t.token);
        let left = deposit.clone().with(2, &b"not an envelope"[..]);
        let reply = ask(&s, Service::MAILBOX, left).await.unwrap();
        assert_eq!(reply.get(0).and_then(Value::as_uint), Some(DEPOSIT));
        let other = Record::new().with(0, DEPOSIT).with(1, [5u8; 16]);
        let other = other.with(2, &b"x"[..]);
        assert!(not_permitted(ask(&s, Service::MAILBOX, other).await));

        // More than it may send is refused, and the rest of the session goes on.
        let mut long = s.open_stream(Service::SYNC, Priority::Interactive).unwrap();
        let huge = Value::from(vec![0u8; 1 << 20]);
        let _ = tokio::time::timeout(Duration::from_secs(2), long.send_message(&huge)).await;
        let usage = Record::new().with(0, USAGE);
        assert!(not_permitted(ask(&s, Service::MAILBOX, usage).await));
    });

    assert!(
        !ana.log().contains("bad object"),
        "a host took objects from a token holder: {}",
        ana.log()
    );
    // What was left that is no envelope is dropped, and holds nothing up.
    bo.cli(&["say", "Ana", "still here"]);
    wait("ana reads it", 20, || {
        ana.cli(&["messages", "bo"]).contains("still here")
    });
}

#[test]
fn one_token_holds_only_so_many_sessions() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let bo = hosted(root.path(), "bo");
    let t = given_a_token(&ana, &bo);

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut open_ones = Vec::new();
        for _ in 0..TOKEN_SESSIONS + 3 {
            open_ones.extend(open(&t, None).await);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        let mut answered = 0;
        for (_, s) in &open_ones {
            let usage = Record::new().with(0, USAGE);
            answered += usize::from(ask(s, Service::MAILBOX, usage).await.is_some());
        }
        assert_eq!(answered, TOKEN_SESSIONS);
    });
}

/// A session opened before the refusal, by someone who says who they are,
/// gets nowhere after it: not by the token, and not as an invitation.
#[test]
fn refusing_someone_ends_what_their_token_opened() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let bo = hosted(root.path(), "bo");
    let t = given_a_token(&ana, &bo);
    let contacts_before = ana.cli(&["contacts", "--all"]).lines().count();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let someone = LocalIdentity {
            identity: [7; 32],
            signing_key: Arc::new(SigningKey::from_seed(&[7; 32])),
        };
        let (_endpoint, s) = open(&t, Some(someone)).await.expect("a good token opens");
        let usage = Record::new().with(0, USAGE);
        assert!(ask(&s, Service::MAILBOX, usage.clone()).await.is_some());

        ana.cli(&["contact", "bo", "refuse"]);

        assert!(ask(&s, Service::MAILBOX, usage).await.is_none());
        let hello = Record::new().with(0, 1u64).with(1, [7u8; 32]).with(2, "x");
        assert!(ask(&s, Service::CONTACT, hello).await.is_none());
        assert!(
            open(&t, None).await.is_none(),
            "a revoked token still opens"
        );
    });
    let contacts = ana.cli(&["contacts", "--all"]).lines().count();
    assert_eq!(contacts, contacts_before);
}
