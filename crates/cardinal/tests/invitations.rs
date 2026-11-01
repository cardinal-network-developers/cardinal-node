//! An invitation in the hands of someone who means harm: a client of its
//! own, on either end, doing what an honest device never would. Neighbours
//! `hostile.rs`, which has the attacks on tokens and contacts.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cardinal_contact::{ContactMessage, EndpointAddr, Invitation};
use cardinal_crypto::{HybridKeyPair, SigningKey};
use cardinal_encoding::Value;
use cardinal_identity::{DeviceKeys, EntryBuilder, IdentityEntry, IdentityLog, IdentityOp};
use cardinal_link::{
    Bind, CarrierKind, Endpoint, EndpointConfig, LocalIdentity, MemoryDirectory, Priority,
    SecretEntry, Service, Session, Stream, Target,
};
use cardinal_space::{relationship, Profile, SealedEntry, Space, SpaceOp};
use cardinal_sync::{answer_want, identity_log_label, want_messages, MemSet, Message, Reconciler};
use cardinald::keys::Keys;
use common::*;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

fn hosted(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start();
    d.cli(&["init", "--yes", "--name", name]);
    d.wait_mounted();
    let at = format!("127.0.0.1:{}", d.port);
    d.cli(&["host", "--address", &at]);
    d
}

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    let byte = |i: usize| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    std::array::from_fn(byte)
}

fn spaces(d: &Dev) -> Vec<[u8; 32]> {
    let dir = std::fs::read_dir(d.home.join("spaces")).unwrap();
    let names = dir.flatten().map(|e| e.file_name());
    names.map(|n| unhex(n.to_str().unwrap())).collect()
}

fn contacts(ana: &Dev, bo: &Dev, also: &[&str]) {
    let at = format!("127.0.0.1:{}", ana.port);
    let mut args = vec!["invite", "--address", &at, "--name", "Ana"];
    args.extend(also);
    let code = ana.cli(&args);
    let mut args = vec!["accept", code.trim()];
    args.extend(also);
    bo.cli(&args);
    wait("the inviter lists them", 20, || {
        ana.cli(&["contacts"]).contains(bo.name)
    });
}

fn other_person(d: &Dev) -> [u8; 32] {
    let mut names = std::fs::read_dir(d.home.join("others")).unwrap().flatten();
    let name = names.next().unwrap().file_name();
    let name = name.to_str().unwrap();
    unhex(name.split('.').next().unwrap())
}

fn a_code(ana: &Dev, also: &[&str]) -> Invitation {
    let at = format!("127.0.0.1:{}", ana.port);
    let mut args = vec!["invite", "--address", &at, "--name", "Ana"];
    args.extend(also);
    Invitation::from_text(ana.cli(&args).trim()).unwrap()
}

fn resident(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let line = status.lines().find(|l| l.starts_with("VmRSS:")).unwrap();
    let kib = line.split_whitespace().nth(1).unwrap();
    kib.parse::<u64>().unwrap() * 1024
}

async fn tell(s: &Session, service: Service, message: cardinal_encoding::Record) {
    if let Ok(mut st) = s.open_stream(service, Priority::Interactive) {
        let _ = st.send_message(&Value::Record(message)).await;
        let _ = st.shutdown().await;
    }
}

/// What a reconcile says the other end has and `have` lacks.
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

/// Everything the other end will give of `label`.
async fn fetch(s: &Session, label: [u8; 32]) -> Vec<Vec<u8>> {
    let ids = reconcile(s, label, MemSet::new()).await;
    let mut got = Vec::new();
    for m in want_messages(label, &ids) {
        let mut st = s.open_stream(Service::SYNC, Priority::Interactive).unwrap();
        st.send_message(&Value::Record(m.to_record()))
            .await
            .unwrap();
        let _ = st.shutdown().await;
        while let Ok(Ok(Some(v))) =
            tokio::time::timeout(Duration::from_secs(3), st.recv_message_max(1 << 24)).await
        {
            if let Some(Ok(Message::Objects { objects, .. })) =
                v.as_record().map(Message::from_record)
            {
                got.extend(objects);
            }
        }
    }
    got
}

/// A person of her own, with a real identity log, run by a client that does
/// what it likes.
struct Mal {
    signing: Arc<SigningKey>,
    link: Arc<HybridKeyPair>,
    log: IdentityLog,
    enc: HybridKeyPair,
}

impl Mal {
    fn new() -> Mal {
        let device = DeviceKeys::generate();
        let signing = Arc::new(SigningKey::from_seed(&device.signing.seed()));
        let link = Arc::new(HybridKeyPair::from_secret_bytes(
            &device.link.secret_bytes(),
        ));
        let created = IdentityLog::create(&device).unwrap();
        Mal {
            signing,
            link,
            log: created.log,
            enc: created.encryption,
        }
    }

    fn id(&self) -> [u8; 32] {
        self.log.id()
    }

    fn sets(&self) -> Sets {
        let all = self.log.entries().map(|e| (e.id(), e.encode())).collect();
        let mut m = HashMap::new();
        m.insert(identity_log_label(&self.id()), all);
        Arc::new(Mutex::new(m))
    }

    async fn endpoint(&self, port: Option<u16>) -> Endpoint {
        endpoint(self.link.clone(), self.id(), self.signing.clone(), port).await
    }
}

async fn endpoint(
    link: Arc<HybridKeyPair>,
    identity: [u8; 32],
    signing: Arc<SigningKey>,
    port: Option<u16>,
) -> Endpoint {
    let mut config = EndpointConfig::new(link, MemoryDirectory::new());
    config.identity = Some(LocalIdentity {
        identity,
        signing_key: signing,
    });
    config.connect_timeout = Duration::from_secs(3);
    let addr: SocketAddr = format!("127.0.0.1:{}", port.unwrap_or(0)).parse().unwrap();
    let bind = Bind {
        udp: Some(addr),
        tcp: None,
    };
    Endpoint::bind(config, bind).await.unwrap()
}

type Sets = Arc<Mutex<HashMap<[u8; 32], Vec<([u8; 32], Vec<u8>)>>>>;

/// Sets whose reconcile is answered late: how an exchange is held open.
static STALL: Mutex<Vec<[u8; 32]>> = Mutex::new(Vec::new());

/// Answers what the other end asks of a session: reconciles and wants of
/// `sets`. Contact streams go to whoever is listening.
fn answer(s: Session, sets: Sets) -> mpsc::UnboundedReceiver<Stream> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(mut st) = s.accept_stream().await {
            if st.service() == Service::CONTACT {
                let _ = tx.send(st);
                continue;
            }
            if st.service() != Service::SYNC {
                continue;
            }
            let sets = sets.clone();
            tokio::spawn(async move {
                let Ok(Some(v)) = st.recv_message_max(1 << 24).await else {
                    return;
                };
                let Some(Ok(m)) = v.as_record().map(Message::from_record) else {
                    return;
                };
                match m {
                    Message::Reconcile { label, mut ranges } => {
                        if STALL.lock().unwrap().contains(&label) {
                            tokio::time::sleep(Duration::from_secs(10)).await;
                        }
                        let mut set = MemSet::new();
                        if let Some(items) = sets.lock().unwrap().get(&label) {
                            for (id, _) in items {
                                set.insert(*id);
                            }
                        }
                        let mut rec = Reconciler::new(label, set);
                        while let Ok(Some(reply)) = rec.receive(&ranges) {
                            let _ = st.send_message(&Value::Record(reply.to_record())).await;
                            if rec.is_done() {
                                break;
                            }
                            let Ok(Some(v)) = st.recv_message_max(1 << 24).await else {
                                break;
                            };
                            let Some(Ok(Message::Reconcile { ranges: r, .. })) =
                                v.as_record().map(Message::from_record)
                            else {
                                break;
                            };
                            ranges = r;
                        }
                        let _ = st.shutdown().await;
                    }
                    Message::Want { label, ids } => {
                        let items = sets
                            .lock()
                            .unwrap()
                            .get(&label)
                            .cloned()
                            .unwrap_or_default();
                        let msgs = answer_want(label, &ids, |id| {
                            items.iter().find(|(i, _)| i == id).map(|(_, b)| b.clone())
                        });
                        for m in msgs {
                            let _ = st.send_message(&Value::Record(m.to_record())).await;
                        }
                        let _ = st.shutdown().await;
                    }
                    _ => {}
                }
            });
        }
    });
    rx
}

async fn send_contact(st: &mut Stream, m: &ContactMessage) {
    st.send_message(&Value::Record(m.to_record()))
        .await
        .unwrap();
}

async fn recv_contact(st: &mut Stream) -> Option<ContactMessage> {
    let v = tokio::time::timeout(Duration::from_secs(20), st.recv_message_max(1 << 16))
        .await
        .ok()?
        .ok()??;
    ContactMessage::from_record(v.as_record()?).ok()
}

fn log_of(entries: &[Vec<u8>]) -> IdentityLog {
    let mut decoded: Vec<IdentityEntry> = entries
        .iter()
        .map(|b| IdentityEntry::decode(b).unwrap())
        .collect();
    let at = decoded.iter().position(IdentityEntry::is_genesis).unwrap();
    let mut log = IdentityLog::from_genesis(decoded.remove(at)).unwrap();
    for _ in 0..decoded.len() {
        for e in &decoded {
            let _ = log.insert(e.clone());
        }
    }
    log
}

/// An account space's id on `d`, read from what the device holds.
fn account_of(d: &Dev) -> [u8; 32] {
    let keys = Keys::load_or_create(&d.home.join("device.key")).unwrap();
    let _ = keys;
    // The smallest space id that is not a relationship would do; the test
    // only needs something to get below.
    spaces(d).into_iter().min().unwrap()
}

/// A code that names Mal, sent to Ana, is all this takes. Nobody lies about
/// who they are: Mal is who the code says, and her device is in her log.
#[test]
fn a_false_genesis_is_taken_for_the_account_space() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let bo = hosted(root.path(), "bo");
    contacts(&ana, &bo, &[]);
    bo.cli(&["say", "Ana", "between us"]);
    wait("ana reads it", 20, || {
        ana.cli(&["messages", "bo"]).contains("between us")
    });
    assert!(ana.cli(&["contacts"]).contains("bo"));
    let below = account_of(&ana);
    let spaces_before = spaces(&ana);
    eprintln!("BEFORE contacts: {}", ana.cli(&["contacts"]));

    let mal = Mal::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let port = free_port();
    let endpoint = rt.block_on(mal.endpoint(Some(port)));
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let responder = *mal.link.public_key().x25519();
    let mut code = Invitation::new(
        mal.id(),
        responder,
        EndpointAddr::new(CarrierKind::Udp, addr),
    );
    code.name = Some("A stranger".into());
    endpoint.add_secret(SecretEntry::new(&code.secret));
    let text = code.to_text();
    let sets = mal.sets();

    let fake: Arc<Mutex<Option<[u8; 32]>>> = Arc::new(Mutex::new(None));
    let accepted = std::thread::scope(|scope| {
        let accepting = scope.spawn(|| ana.try_cli(&["accept", &text]));
        rt.block_on(async {
            let s = tokio::time::timeout(Duration::from_secs(10), endpoint.accept())
                .await
                .expect("ana dials")
                .expect("a session");
            let mut streams = answer(s.clone(), sets.clone());

            // Her log is open to any invitation, which gives her key.
            let ana_id = s.peer_identity().unwrap().identity;
            let her_log = log_of(&fetch(&s, identity_log_label(&ana_id)).await);
            let her_key = her_log.state().encryption_key.clone().unwrap().public;

            // A genesis with the account profile, ground to sort first.
            let mine = mal.enc.public_key().clone();
            let (space, sealed) = (0u64..)
                .map(|t| {
                    let ops = vec![SpaceOp::add_member(ana_id, relationship::OWNER)];
                    Space::create_with(
                        Profile::ACCOUNT,
                        cardinal_space::Policy::default(),
                        &mal.log,
                        &mal.signing,
                        &[&mine, &her_key],
                        ops,
                        Some(t),
                    )
                    .unwrap()
                })
                .find(|(s, _)| s.id() < below)
                .unwrap();
            let bytes = sealed.encode();
            *fake.lock().unwrap() = Some(space.id());
            sets.lock()
                .unwrap()
                .insert(space.id(), vec![(sealed.sealed_id(), bytes.clone())]);

            let mut st = tokio::time::timeout(Duration::from_secs(10), streams.recv())
                .await
                .expect("she says hello")
                .expect("a stream");
            let hello = recv_contact(&mut st).await;
            eprintln!("HELLO {hello:?}");
            send_contact(&mut st, &ContactMessage::Genesis(bytes)).await;
            let done = recv_contact(&mut st).await;
            eprintln!("DONE {done:?}");

            // What is in that space now, as Mal can read it.
            let label = space.id();
            tokio::time::sleep(Duration::from_secs(2)).await;
            let sealed_seen = fetch(&s, label).await;
            eprintln!("MAL HOLDS {} entries of the fake space", sealed_seen.len());
            let mut mine = space;
            let keys = [&mal.enc];
            let mut opened = 0;
            for b in &sealed_seen {
                let e = SealedEntry::decode(b).unwrap();
                if mine.receive(e, &keys).is_ok() {
                    opened += 1;
                }
            }
            eprintln!("MAL OPENED {opened}");
            for (id, e) in mine.dag().iter() {
                eprintln!(
                    "  entry {:02x?} author {:02x?} ops {:?}",
                    &id[..4],
                    &e.author()[..4],
                    e.ops()
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        accepting.join().unwrap()
    });
    let said = String::from_utf8_lossy(&accepted.stderr).into_owned()
        + &String::from_utf8_lossy(&accepted.stdout);
    eprintln!("ACCEPT status={} said: {said}", accepted.status);
    let after = spaces(&ana);
    eprintln!(
        "spaces before {} after {}",
        spaces_before.len(),
        after.len()
    );
    eprintln!("AFTER contacts --all: {}", ana.cli(&["contacts", "--all"]));
    let msgs = ana.try_cli(&["messages", "bo"]);
    eprintln!(
        "AFTER messages bo: {}{}",
        String::from_utf8_lossy(&msgs.stdout),
        String::from_utf8_lossy(&msgs.stderr)
    );
    let status = ana.cli(&["status"]);
    eprintln!("AFTER status: {status}");
    let shadowed_live = !ana.cli(&["contacts", "--all"]).contains("bo");
    // And it outlives a restart.
    let mut ana = ana;
    ana.stop();
    ana.start();
    ana.wait_mounted();
    let after_restart = ana.cli(&["contacts", "--all"]);
    eprintln!("AFTER RESTART contacts --all: {after_restart}");
    let shadowed_after = !after_restart.contains("bo");
    eprintln!("account space shadowed live={shadowed_live} after_restart={shadowed_after}");
    assert!(
        ana.cli(&["contacts", "--all"]).contains("bo"),
        "ana no longer knows bo (account space shadowed by a fake genesis)"
    );
}

fn ana_addr(ana: &Dev) -> SocketAddr {
    format!("127.0.0.1:{}", ana.port).parse().unwrap()
}

/// Opens a session with an invitation, saying it is `claim`.
async fn open_claiming(
    code: &Invitation,
    addr: SocketAddr,
    claim: [u8; 32],
) -> (Endpoint, Session) {
    let link = Arc::new(HybridKeyPair::generate());
    let signing = Arc::new(SigningKey::from_seed(&[42; 32]));
    let endpoint = endpoint(link, claim, signing, None).await;
    let target = Target::invitation(addr, CarrierKind::Udp, code.responder_static, &code.secret);
    let session = endpoint.connect(target).await.unwrap();
    (endpoint, session)
}

/// A retired device, or anyone who ever held her sealed entries, has a
/// genesis wrapped for her. Sent as a relationship, it opens that space.
#[test]
fn an_old_genesis_opens_a_private_space() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    std::fs::write(ana.p("private.txt"), "ana's\n").unwrap();
    ana.cli(&["flush"]);
    let private = spaces(&ana);
    assert_eq!(private.len(), 2, "her account and her files");
    let target = private[0];
    let (_, records) = cardinald::applog::AppendLog::open(
        &ana.home
            .join("spaces")
            .join(hex(&target))
            .join("entries.log"),
    )
    .unwrap();
    let held_before = records.len();
    let genesis = records
        .iter()
        .map(|(_, b)| b)
        .find(|b| SealedEntry::decode(b).is_ok_and(|s| s.wraps().is_some()))
        .unwrap()
        .clone();

    let mal = Mal::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let port = free_port();
    let endpoint = rt.block_on(mal.endpoint(Some(port)));
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let responder = *mal.link.public_key().x25519();
    let code = Invitation::new(
        mal.id(),
        responder,
        EndpointAddr::new(CarrierKind::Udp, addr),
    );
    endpoint.add_secret(SecretEntry::new(&code.secret));
    let text = code.to_text();
    let sets = mal.sets();

    let read = std::thread::scope(|scope| {
        let accepting = scope.spawn(|| ana.try_cli(&["accept", &text]));
        let read = rt.block_on(async {
            let s = tokio::time::timeout(Duration::from_secs(10), endpoint.accept())
                .await
                .expect("ana dials")
                .expect("a session");
            let mut streams = answer(s.clone(), sets.clone());
            let before = fetch(&s, target).await;
            assert!(before.is_empty(), "nothing yet");
            STALL.lock().unwrap().push(target);
            let mut st = streams.recv().await.expect("hello");
            recv_contact(&mut st).await;
            send_contact(&mut st, &ContactMessage::Genesis(genesis)).await;
            // Long enough for her to have taken it.
            tokio::time::sleep(Duration::from_secs(2)).await;
            let got = fetch(&s, target).await;
            let junk = Message::Objects {
                label: target,
                objects: vec![vec![7; 1000]],
            };
            tell(&s, Service::SYNC, junk.to_record()).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            got.len()
        });
        let out = accepting.join().unwrap();
        eprintln!(
            "ACCEPT {} {}{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        read
    });
    eprintln!("MAL READ {read} of {held_before} sealed entries of a private space");
    let (_, after) = cardinald::applog::AppendLog::open(
        &ana.home
            .join("spaces")
            .join(hex(&target))
            .join("entries.log"),
    )
    .unwrap();
    eprintln!("the space now holds {} records", after.len());
    eprintln!("contacts --all: {}", ana.cli(&["contacts", "--all"]));
    assert_eq!(read, 0, "a stranger read a private space");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One code, one session: as many spaces as the holder likes, and two contact
/// records, which refusing then only half covers.
#[test]
fn one_code_makes_one_exchange() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let code = a_code(&ana, &[]);
    let before = spaces(&ana).len();
    let addr = ana_addr(&ana);

    let mal = Mal::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let endpoint = mal.endpoint(None).await;
        let target =
            Target::invitation(addr, CarrierKind::Udp, code.responder_static, &code.secret);
        let s = endpoint.connect(target).await.unwrap();
        let _streams = answer(s.clone(), mal.sets());

        let mut open = Vec::new();
        for i in 0..6 {
            let mut st = s
                .open_stream(Service::CONTACT, Priority::Interactive)
                .unwrap();
            let hello = ContactMessage::Hello {
                identity: mal.id(),
                name: "mal".into(),
            };
            send_contact(&mut st, &hello).await;
            let genesis = recv_contact(&mut st).await;
            eprintln!(
                "exchange {i}: {}",
                matches!(genesis, Some(ContactMessage::Genesis(_)))
            );
            open.push(st);
        }
        let made = spaces(&ana).len() - before;
        eprintln!("MADE {made} spaces with one code");

        assert_eq!(made, 1, "one code made {made} spaces");
        assert_eq!(ana.cli(&["contacts", "--all"]), "", "nobody finished");
    });
}

/// What arrives for a log not held yet is kept in memory, whoever sends it.
#[test]
fn an_invitation_fills_memory_with_what_arrives() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let code = a_code(&ana, &[]);
    let addr = ana_addr(&ana);
    let pid = ana.child.as_ref().unwrap().id();
    let claim = [9u8; 32];
    let label = identity_log_label(&claim);

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (_endpoint, s) = open_claiming(&code, addr, claim).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        let before = resident(pid);
        // 64 MiB, in pieces of a size any invitation may send.
        for i in 0..320u32 {
            let junk = Message::Objects {
                label,
                objects: vec![vec![(i % 251) as u8; 200_000]],
            };
            tell(&s, Service::SYNC, junk.to_record()).await;
            if i % 16 == 15 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        tokio::time::sleep(Duration::from_secs(4)).await;
        let grew = resident(pid).saturating_sub(before) >> 20;
        eprintln!("MEASURE 64 MiB of pushes, ana grew {grew} MiB");
        s.close("bye");
        tokio::time::sleep(Duration::from_secs(4)).await;
        let kept = resident(pid).saturating_sub(before) >> 20;
        eprintln!("MEASURE session closed, ana still holds {kept} MiB");
        assert!(
            grew < 32,
            "an invitation held {grew} MiB of a device's memory"
        );
    });
}

/// `ingest_other` decodes and verifies all that has arrived, every time,
/// with the core locked.
#[test]
fn an_invitation_holds_the_core_lock() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let code = a_code(&ana, &[]);
    let addr = ana_addr(&ana);
    let claim = [9u8; 32];
    let label = identity_log_label(&claim);
    let key = SigningKey::from_seed(&[43; 32]);
    let batch: Vec<Vec<u8>> = (0..1400u32)
        .map(|i| {
            let mut gone = [0u8; 32];
            gone[..4].copy_from_slice(&i.to_be_bytes());
            EntryBuilder::new(claim, &[claim])
                .op(IdentityOp::remove_key(gone))
                .sign(&key)
                .unwrap()
                .encode()
        })
        .collect();
    let size: usize = batch.iter().map(Vec::len).sum();
    eprintln!("a batch is {size} bytes");
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (_endpoint, s) = open_claiming(&code, addr, claim).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        for round in 0..40 {
            let m = Message::Objects {
                label,
                objects: batch.clone(),
            };
            tell(&s, Service::SYNC, m.to_record()).await;
            if round % 10 == 9 {
                let t = Instant::now();
                ana.cli(&["contacts"]);
                eprintln!(
                    "MEASURE after {} pushes, `contacts` took {:?}",
                    round + 1,
                    t.elapsed()
                );
            }
        }
        let t = Instant::now();
        tokio::time::sleep(Duration::from_secs(1)).await;
        ana.cli(&["contacts"]);
        eprintln!("MEASURE at the end, `contacts` took {:?}", t.elapsed());
        s.close("bye");
    });
}

/// Someone saying they are Bo adds to Ana's copy of Bo's log, and from there
/// to Bo's own.
#[test]
fn a_claim_writes_into_a_contacts_log() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let mut bo = hosted(root.path(), "bo");
    contacts(&ana, &bo, &[]);
    let bo_id = other_person(&ana);
    let copy = ana.home.join("others").join(hex(&bo_id));
    let own = bo.home.join("identity.log");
    let (copy_before, own_before) = (
        std::fs::metadata(&copy).unwrap().len(),
        std::fs::metadata(&own).unwrap().len(),
    );
    let code = a_code(&ana, &[]);
    let addr = ana_addr(&ana);
    let label = identity_log_label(&bo_id);
    let key = SigningKey::from_seed(&[44; 32]);
    let junk: Vec<Vec<u8>> = (0..200u32)
        .map(|i| {
            let mut gone = [0u8; 32];
            gone[..4].copy_from_slice(&i.to_be_bytes());
            EntryBuilder::new(bo_id, &[bo_id])
                .op(IdentityOp::remove_key(gone))
                .sign(&key)
                .unwrap()
                .encode()
        })
        .collect();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (_endpoint, s) = open_claiming(&code, addr, bo_id).await;
        let m = Message::Objects {
            label,
            objects: junk.clone(),
        };
        tell(&s, Service::SYNC, m.to_record()).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        eprintln!("session after the push: closed={}", s.is_closed());
        s.close("bye");
    });
    let copy_after = std::fs::metadata(&copy).unwrap().len();
    eprintln!("ANA'S COPY OF BO'S LOG {copy_before} -> {copy_after} bytes");
    eprintln!("contacts: {}", ana.cli(&["contacts"]));

    // Their next session takes it to him.
    bo.stop();
    bo.start();
    wait("bo is back", 30, || {
        ana.cli(&["contacts"]).contains("connected")
    });
    std::thread::sleep(Duration::from_secs(5));
    let own_after = std::fs::metadata(&own).unwrap().len();
    eprintln!("BO'S OWN LOG {own_before} -> {own_after} bytes");
    assert_eq!(
        copy_after, copy_before,
        "an unproven claim wrote to a contact's log"
    );
}

/// The inviter records whatever name the other end suggests, and a name finds
/// the first who has it.
#[test]
fn a_suggested_name_takes_the_real_contacts_place() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let bo = hosted(root.path(), "bo");
    contacts(&ana, &bo, &[]);
    let bo_id = other_person(&ana);
    let mal = (0..)
        .map(|_| Mal::new())
        .find(|m| hex(&m.id()) < hex(&bo_id))
        .unwrap();
    let code = a_code(&ana, &[]);
    let addr = ana_addr(&ana);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let endpoint = mal.endpoint(None).await;
        let target =
            Target::invitation(addr, CarrierKind::Udp, code.responder_static, &code.secret);
        let s = endpoint.connect(target).await.unwrap();
        let sets = mal.sets();
        let _streams = answer(s.clone(), sets.clone());
        let mut st = s
            .open_stream(Service::CONTACT, Priority::Interactive)
            .unwrap();
        let hello = ContactMessage::Hello {
            identity: mal.id(),
            name: "bo".into(),
        };
        send_contact(&mut st, &hello).await;
        let Some(ContactMessage::Genesis(g)) = recv_contact(&mut st).await else {
            panic!("no genesis");
        };
        let sealed = SealedEntry::decode(&g).unwrap();
        let mut space = Space::open_genesis(&sealed, &[&mal.enc], None).unwrap();
        let id = space.id();
        send_contact(&mut st, &ContactMessage::Done).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        eprintln!("CONTACTS:\n{}", ana.cli(&["contacts"]));
        let out = ana.try_cli(&["say", "bo", "for bo alone"]);
        assert!(!out.status.success(), "which bo was never asked");
        let told = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(told.contains("more than one contact"), "{told}");
        tokio::time::sleep(Duration::from_secs(2)).await;
        let got = fetch(&s, id).await;
        let mut said = false;
        for b in got {
            let _ = space.receive(SealedEntry::decode(&b).unwrap(), &[&mal.enc]);
        }
        for (_, e) in space.dag().iter() {
            for op in e.ops() {
                if format!("{:?}", op).contains("for bo alone") {
                    said = true;
                }
            }
        }
        eprintln!("MAL READ THE MESSAGE: {said}");
        assert!(
            !said,
            "what ana wrote to bo went to someone who called themselves bo"
        );
    });
}
