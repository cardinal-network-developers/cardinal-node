//! A delivery token in the hands of someone who means harm: a client of its
//! own, with the real token, against a real host over real sockets, doing
//! what an honest device never would.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cardinal_contact::{ContactMessage, EndpointAddr, Invitation};
use cardinal_crypto::{derive, HybridKeyPair, Purpose, SigningKey};
use cardinal_encoding::{Record, Value};
use cardinal_link::{
    Bind, CarrierKind, Endpoint, EndpointConfig, LocalIdentity, MemoryDirectory, Priority,
    SecretEntry, Service, Session, Target,
};
use cardinal_sync::{BlobRequest, MemSet, Message, Mode, Range, Reconciler};
use cardinald::keys::Keys;
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

/// Someone with a real device, who invited or accepted in the ordinary way.
fn contacts(ana: &Dev, bo: &Dev) {
    let at = format!("127.0.0.1:{}", ana.port);
    let code = ana.cli(&["invite", "--address", &at, "--name", "Ana"]);
    bo.cli(&["accept", code.trim()]);
    wait("the inviter lists them", 20, || {
        ana.cli(&["contacts"]).contains(bo.name)
    });
}

/// The identity of the one other person `d` knows.
fn other_person(d: &Dev) -> [u8; 32] {
    let mut names = std::fs::read_dir(d.home.join("others")).unwrap().flatten();
    let name = names.next().unwrap().file_name();
    let name = name.to_str().unwrap();
    unhex(name.split('.').next().unwrap())
}

/// A client of its own holding a real contact's keys: what modified software
/// could do with `who`'s standing. `who`'s daemon has to be stopped first.
struct Modified {
    keys: Keys,
    identity: [u8; 32],
    peer: Keys,
    peer_identity: [u8; 32],
    addr: SocketAddr,
}

impl Modified {
    fn of(who: &Dev, peer: &Dev) -> Modified {
        Modified {
            keys: Keys::load_or_create(&who.home.join("device.key")).unwrap(),
            identity: other_person(peer),
            peer: Keys::load_or_create(&peer.home.join("device.key")).unwrap(),
            peer_identity: other_person(who),
            addr: format!("127.0.0.1:{}", peer.port).parse().unwrap(),
        }
    }

    async fn open(&self) -> Option<(Endpoint, Session)> {
        let directory = MemoryDirectory::new();
        let link = self.peer.link.public_key();
        directory.add_device(self.peer_identity, self.peer.key(), link.clone());
        let mut config = EndpointConfig::new(self.keys.link.clone(), directory);
        config.identity = Some(LocalIdentity {
            identity: self.identity,
            signing_key: self.keys.signing.clone(),
        });
        config.connect_timeout = Duration::from_secs(3);
        let bind = Bind {
            udp: Some("127.0.0.1:0".parse().unwrap()),
            tcp: None,
        };
        let endpoint = Endpoint::bind(config, bind).await.unwrap();
        let target = Target::new(self.addr, CarrierKind::Udp, &link);
        let session = endpoint.connect(target).await.ok()?;
        Some((endpoint, session))
    }
}

#[test]
fn a_contact_opens_what_they_share_and_nothing_else() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let mut bo = hosted(root.path(), "bo");
    let private_file: Vec<u8> = (0..3_000_000u32).map(|n| (n * 7 % 251) as u8).collect();
    std::fs::write(ana.p("private.bin"), &private_file).unwrap();
    ana.cli(&["flush"]);
    contacts(&ana, &bo);
    bo.cli(&["say", "Ana", "an honest word"]);
    wait("ana reads it", 20, || {
        ana.cli(&["messages", "bo"]).contains("an honest word")
    });

    let chunk = a_chunk(&ana.home.join("blobs"));
    let theirs = spaces(&bo);
    let (shared, private): (Vec<_>, Vec<_>) =
        spaces(&ana).into_iter().partition(|s| theirs.contains(s));
    assert_eq!(shared.len(), 1, "one space between them");
    assert!(!private.is_empty());
    let shared = shared[0];
    let bo_as_modified = Modified::of(&bo, &ana);
    bo.stop();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (_endpoint, s) = bo_as_modified.open().await.expect("a contact connects");

        assert!(!reconcile(&s, shared, MemSet::new()).await.is_empty());
        for label in &private {
            let wanted = reconcile(&s, *label, MemSet::new()).await;
            assert!(wanted.is_empty(), "read a private space");
        }

        // Nothing goes into a space they are not in, not even as far as
        // being looked at.
        for label in &private {
            let push = Message::Objects {
                label: *label,
                objects: vec![b"not an entry".to_vec()],
            };
            ask(&s, Service::SYNC, push.to_record()).await;
        }

        // What only the owner may do.
        let fetch = Record::new().with(0, FETCH).with(1, 0u64);
        assert!(not_permitted(ask(&s, Service::MAILBOX, fetch).await));
        let list = Value::list([Value::Record(Record::new().with(1, [5u8; 16]))]);
        let register = Record::new().with(0, REGISTER).with(1, list);
        assert!(not_permitted(ask(&s, Service::MAILBOX, register).await));
        let usage = Record::new().with(0, USAGE);
        assert!(not_permitted(ask(&s, Service::MAILBOX, usage).await));

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

        // An invitation is over once it is over.
        let hello = Record::new().with(0, 1u64).with(1, [1u8; 32]).with(2, "x");
        assert!(ask(&s, Service::CONTACT, hello).await.is_none());
    });
    assert!(
        !ana.log().contains("bad object"),
        "a private space looked at what a contact pushed: {}",
        ana.log()
    );

    // Being refused ends it, and nothing they hold opens it again. A host
    // answers anyone, so that a lost device can restore, and then asks for
    // proof before anything else.
    ana.cli(&["contact", "bo", "refuse"]);
    rt.block_on(async {
        if let Some((_endpoint, s)) = bo_as_modified.open().await {
            let usage = Record::new().with(0, USAGE);
            assert!(ask(&s, Service::MAILBOX, usage).await.is_none());
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert!(s.is_closed(), "a refused contact kept a session");
        }
    });
    assert!(ana.status()["devices"].is_array());
}

/// RSS of a running process.
fn resident(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let line = status.lines().find(|l| l.starts_with("VmRSS:")).unwrap();
    let kib = line.split_whitespace().nth(1).unwrap();
    kib.parse::<u64>().unwrap() * 1024
}

/// Writes `count` messages of `claimed` bytes, each short of its end and
/// never let go, for as long as `within`.
async fn leave_unfinished(s: &Session, count: usize, claimed: usize, within: Duration) {
    let mut writers = Vec::new();
    for _ in 0..count {
        let mut st = s.open_stream(Service::SYNC, Priority::Interactive).unwrap();
        writers.push(tokio::spawn(async move {
            let mut message = Vec::new();
            cardinal_encoding::write_varint(claimed as u64, &mut message);
            message.resize(message.len() + claimed - 1024, 7);
            let _ = st.write_all(&message).await;
            std::future::pending::<()>().await;
            drop(st);
        }));
    }
    tokio::time::sleep(within).await;
    for w in writers {
        w.abort();
    }
}

/// The offers are small on purpose: this runs on a machine someone is using.
#[test]
fn a_contact_holds_only_so_much_memory() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let mut bo = hosted(root.path(), "bo");
    contacts(&ana, &bo);
    let bo_as_modified = Modified::of(&bo, &ana);
    bo.stop();
    let pid = ana.child.as_ref().unwrap().id();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (_endpoint, s) = bo_as_modified.open().await.expect("a contact connects");
        tokio::time::sleep(Duration::from_secs(1)).await;
        let before = resident(pid);

        // Too long to be read at all.
        leave_unfinished(&s, 96, 3 << 20, Duration::from_secs(10)).await;
        let grew = resident(pid).saturating_sub(before) >> 20;
        eprintln!("MEASURE 96 long messages, ana grew {grew} MiB");
        assert!(grew < 64, "a contact made a device hold {grew} MiB");
    });
    rt.block_on(async {
        let (_endpoint, s) = bo_as_modified.open().await.expect("a contact connects");
        tokio::time::sleep(Duration::from_secs(1)).await;
        let before = s.stats().bytes_sent;

        // Short enough, on more streams than are read at once. What a device
        // has not read holds up the session's window, so this much goes.
        leave_unfinished(&s, 128, 200 << 10, Duration::from_secs(6)).await;
        let went = (s.stats().bytes_sent - before) >> 20;
        eprintln!("MEASURE 128 short messages, {went} MiB got through");
        assert!(went < 14, "{went} MiB was read of 25 MiB");
    });
    assert!(ana.status()["devices"].is_array());
}

/// A message that wants no reply.
async fn tell(s: &Session, service: Service, message: Record) {
    if let Ok(mut st) = s.open_stream(service, Priority::Interactive) {
        let _ = st.send_message(&Value::Record(message)).await;
        let _ = st.shutdown().await;
    }
}

fn log_sizes(d: &Dev) -> Vec<u64> {
    let dir = std::fs::read_dir(d.home.join("spaces")).unwrap();
    let logs = dir.flatten().map(|e| e.path().join("entries.log"));
    let mut sizes: Vec<u64> = logs
        .map(|p| std::fs::metadata(p).map_or(0, |m| m.len()))
        .collect();
    sizes.sort_unstable();
    sizes
}

/// Opens a session with an invitation, saying it is `claim` with a key made
/// up on the spot.
async fn open_claiming(ana: &Dev, secret: &[u8], claim: [u8; 32]) -> Option<(Endpoint, Session)> {
    let sheet = ana.cli(&["recovery", "sheet"]);
    let key = sheet.lines().find(|l| l.contains("Key:")).unwrap();
    let key = key.split_whitespace().last().unwrap();
    let host = cardinald::host::read_sheet_key(key).unwrap();
    let addr: SocketAddr = format!("127.0.0.1:{}", ana.port).parse().unwrap();

    let mut config =
        EndpointConfig::new(Arc::new(HybridKeyPair::generate()), MemoryDirectory::new());
    config.identity = Some(LocalIdentity {
        identity: claim,
        signing_key: Arc::new(SigningKey::from_seed(&[42; 32])),
    });
    config.connect_timeout = Duration::from_secs(3);
    let bind = Bind {
        udp: Some("127.0.0.1:0".parse().unwrap()),
        tcp: None,
    };
    let endpoint = Endpoint::bind(config, bind).await.unwrap();
    let target = Target::invitation(addr, CarrierKind::Udp, host, secret);
    let session = endpoint.connect(target).await.ok()?;
    Some((endpoint, session))
}

fn a_code(ana: &Dev, also: &[&str]) -> Invitation {
    let at = format!("127.0.0.1:{}", ana.port);
    let mut args = vec!["invite", "--address", &at, "--name", "Ana"];
    args.extend(also);
    Invitation::from_text(ana.cli(&args).trim()).unwrap()
}

/// Who holds an invitation may become a contact. Whoever they say they are,
/// that is all it opens: not the inviter's spaces, not a contact's, and not
/// a place to leave anything.
#[test]
fn an_invitation_opens_nothing_else() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let bo = hosted(root.path(), "bo");
    std::fs::write(ana.p("private.txt"), "ana's\n").unwrap();
    ana.cli(&["flush"]);
    contacts(&ana, &bo);
    bo.cli(&["say", "Ana", "between us"]);
    wait("ana reads it", 20, || {
        ana.cli(&["messages", "bo"]).contains("between us")
    });
    let all = spaces(&ana);
    assert!(all.len() >= 3, "her own spaces, and the one with bo");
    let (ana_id, bo_id) = (other_person(&bo), other_person(&ana));
    let before = log_sizes(&ana);

    let attack = |rt: &tokio::runtime::Runtime, who: &str, code: Invitation, claim: [u8; 32]| {
        rt.block_on(async {
            let Some((_endpoint, s)) = open_claiming(&ana, &code.secret, claim).await else {
                return;
            };
            for label in &all {
                let wanted = reconcile(&s, *label, MemSet::new()).await;
                assert!(wanted.is_empty(), "{who} read {} entries", wanted.len());
                let junk = Message::Objects {
                    label: *label,
                    objects: vec![vec![7; 60_000]],
                };
                tell(&s, Service::SYNC, junk.to_record()).await;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        });
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    attack(
        &rt,
        "someone saying they are ana",
        a_code(&ana, &[]),
        ana_id,
    );
    attack(&rt, "someone saying they are bo", a_code(&ana, &[]), bo_id);
    attack(&rt, "someone new", a_code(&ana, &[]), [9; 32]);
    let hosts_only = a_code(&ana, &["--hosts-only"]);
    attack(&rt, "someone with a hosts-only code", hosts_only, ana_id);
    assert_eq!(log_sizes(&ana), before, "something was left in her spaces");

    // Refusal outlasts an invitation made before it. It is itself a write,
    // so what counts is what comes after.
    let spare = a_code(&ana, &[]);
    ana.cli(&["contact", "bo", "refuse"]);
    wait("the refusal is written", 10, || {
        ana.cli(&["contacts", "--all"]).contains("refused")
    });
    let before = log_sizes(&ana);
    attack(&rt, "someone refused", spare, bo_id);
    assert_eq!(log_sizes(&ana), before, "something was left in her spaces");
    assert!(!ana.log().contains("bad object"), "{}", ana.log());

    // Nor is it a way back in, used as it was meant to be.
    let spare = a_code(&ana, &[]);
    let out = bo.try_cli(&["accept", &spare.to_text()]);
    assert!(!out.status.success(), "a refused person was let back in");
    assert!(ana.cli(&["contacts", "--all"]).contains("refused"));
    assert!(!ana.cli(&["contacts"]).contains("bo"));
}

/// An invitation is also an invitation to be lied to. Someone sends Ana a
/// code naming a person she knows. Her device opens nothing to them, and
/// goes no further once that person's log says the device is not theirs.
#[test]
fn a_false_invitation_gets_nothing_from_who_accepts_it() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let bo = hosted(root.path(), "bo");
    std::fs::write(ana.p("private.txt"), "ana's\n").unwrap();
    ana.cli(&["flush"]);
    contacts(&ana, &bo);
    let all = spaces(&ana);
    let bo_id = other_person(&ana);
    let before = log_sizes(&ana);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let key = Arc::new(HybridKeyPair::generate());
    let responder = *key.public_key().x25519();
    let mut config = EndpointConfig::new(key, MemoryDirectory::new());
    config.identity = Some(LocalIdentity {
        identity: bo_id,
        signing_key: Arc::new(SigningKey::from_seed(&[42; 32])),
    });
    let addr: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let bind = Bind {
        udp: Some(addr),
        tcp: None,
    };
    let endpoint = rt.block_on(Endpoint::bind(config, bind)).unwrap();
    let endpoint_addr = EndpointAddr::new(CarrierKind::Udp, addr);
    let code = Invitation::new(bo_id, responder, endpoint_addr);
    endpoint.add_secret(SecretEntry::new(&code.secret));
    let text = code.to_text();

    let accepted = std::thread::scope(|scope| {
        let accepting = scope.spawn(|| ana.try_cli(&["accept", &text]));
        rt.block_on(async {
            let s = tokio::time::timeout(Duration::from_secs(10), endpoint.accept())
                .await
                .expect("ana dials")
                .expect("a session");
            for label in &all {
                let wanted = reconcile(&s, *label, MemSet::new()).await;
                assert!(wanted.is_empty(), "read {} entries", wanted.len());
                let junk = Message::Objects {
                    label: *label,
                    objects: vec![vec![7; 60_000]],
                };
                tell(&s, Service::SYNC, junk.to_record()).await;
            }

            // Far enough along for her to look at the log she holds.
            let mut hello = tokio::time::timeout(Duration::from_secs(10), s.accept_stream())
                .await
                .expect("she says hello")
                .expect("a stream");
            let _ = hello.recv_message_max(1 << 16).await;
            let genesis = ContactMessage::Genesis(b"a genesis".to_vec());
            let _ = hello
                .send_message(&Value::Record(genesis.to_record()))
                .await;
            if let Ok(Some(mut log)) =
                tokio::time::timeout(Duration::from_secs(10), s.accept_stream()).await
            {
                if let Ok(Some(v)) = log.recv_message_max(1 << 16).await {
                    let label = v.as_record().and_then(|r| Message::from_record(r).ok());
                    if let Some(Message::Reconcile { label, .. }) = label {
                        let nothing_new = Message::Reconcile {
                            label,
                            ranges: vec![Range {
                                upper: None,
                                mode: Mode::Skip,
                            }],
                        };
                        let _ = log
                            .send_message(&Value::Record(nothing_new.to_record()))
                            .await;
                    }
                }
                let _ = log.shutdown().await;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        accepting.join().unwrap()
    });
    let said = String::from_utf8_lossy(&accepted.stderr).into_owned()
        + &String::from_utf8_lossy(&accepted.stdout);
    assert!(!accepted.status.success(), "{said}");
    assert!(said.contains("not the one who invited you"), "{said}");
    assert_eq!(log_sizes(&ana), before, "something was left in her spaces");
    assert_eq!(spaces(&ana).len(), all.len(), "a space was made");
}

/// Sends a reconcile of `rounds` lists of ids this device has never seen,
/// and says how many were answered.
async fn offer_ids(s: &Session, label: [u8; 32], rounds: u64) -> u64 {
    const IDS: u64 = 7000;
    let mut st = s.open_stream(Service::SYNC, Priority::Interactive).unwrap();
    for round in 0..rounds {
        let ids = (0..IDS).map(|i| {
            let mut id = [1; 32];
            id[..8].copy_from_slice(&(round * IDS + i).to_be_bytes());
            id
        });
        let offer = Message::Reconcile {
            label,
            ranges: vec![Range {
                upper: None,
                mode: Mode::List(ids.collect()),
            }],
        };
        if st
            .send_message(&Value::Record(offer.to_record()))
            .await
            .is_err()
        {
            return round;
        }
        let reply = tokio::time::timeout(Duration::from_secs(3), st.recv_message_max(1 << 22));
        if !matches!(reply.await, Ok(Ok(Some(_)))) {
            return round;
        }
    }
    rounds
}

/// A reconcile learns what the other side has. What will never be fetched
/// is not kept, and what will be fetched is kept only so far.
#[test]
fn offers_of_ids_are_not_kept() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let bo = hosted(root.path(), "bo");
    let t = given_a_token(&ana, &bo);
    let pid = ana.child.as_ref().unwrap().id();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (_endpoint, s) = open(&t, None).await.expect("a good token opens");
        tokio::time::sleep(Duration::from_secs(1)).await;
        let before = resident(pid);
        let answered = offer_ids(&s, [3; 32], 400).await;
        let grew = resident(pid).saturating_sub(before) >> 20;
        eprintln!("MEASURE {answered} rounds of ids from a token, ana grew {grew} MiB");
        assert!(answered > 300, "stopped early at {answered}");
        assert!(grew < 40, "a token holder made a device keep {grew} MiB");
    });

    let carol = hosted(root.path(), "carol");
    let mut cy = hosted(root.path(), "cy");
    contacts(&carol, &cy);
    let theirs = spaces(&cy);
    let shared = spaces(&carol).into_iter().find(|s| theirs.contains(s));
    let cy_as_modified = Modified::of(&cy, &carol);
    cy.stop();
    rt.block_on(async {
        let (_endpoint, s) = cy_as_modified.open().await.expect("a contact connects");
        let answered = offer_ids(&s, shared.unwrap(), 40).await;
        eprintln!("MEASURE a contact was answered {answered} rounds of ids");
        assert!(answered < 20, "a contact was still heard after {answered}");
    });
}
