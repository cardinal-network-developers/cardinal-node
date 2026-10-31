//! Lost everything (`hosts.md#restore`): alpha and the always-on device
//! hold the files. Alpha is gone for good. A new device with only the 24
//! words and the recovery sheet gets everything back, can make changes, and
//! manages the devices; and nobody without the words gets anything.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use std::sync::Arc;
use std::time::Duration;

use cardinal_crypto::{HybridKeyPair, RecoveryPhrase, SigningKey};
use cardinal_encoding::{Record, Value};
use cardinal_link::{
    Bind, CarrierKind, Endpoint, EndpointConfig, LinkError, MemoryDirectory, Priority, Service,
    Session, Target,
};
use cardinal_sync::Message;
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

/// The line starting `name` of a recovery sheet.
fn field(sheet: &str, name: &str) -> String {
    sheet
        .lines()
        .find_map(|l| l.trim().strip_prefix(name))
        .unwrap_or_else(|| panic!("no {name} in {sheet}"))
        .trim()
        .to_owned()
}

#[test]
fn a_new_device_gets_everything_back_from_the_words_and_the_sheet() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    let mut host = Dev::new(root.path(), "nuc", free_port());
    a.start();
    let init = a.cli(&["init", "--yes", "--name", "alpha"]);
    let words = words_from(&init);
    a.wait_mounted();
    host.start();
    pair(&a, &host);
    host.wait_mounted();

    // Files, one big enough to be stored as chunks, and a change to it.
    let big: Vec<u8> = (0..3_000_000u32).map(|n| (n * 7 % 251) as u8).collect();
    std::fs::create_dir(a.p("photos")).unwrap();
    std::fs::write(a.p("notes.txt"), "version 1\n").unwrap();
    std::fs::write(a.p("photos/big.bin"), &big).unwrap();
    a.cli(&["flush"]);
    std::fs::write(a.p("notes.txt"), "version 2\n").unwrap();
    a.cli(&["flush"]);

    let at = format!("127.0.0.1:{}", host.port);
    let shown = host.cli(&["host", "--address", &at]);
    assert_eq!(field(&shown, "Address:"), at, "{shown}");
    let key = field(&shown, "Key:");
    wait("the host holds the files", 40, || {
        std::fs::read(host.p("photos/big.bin")).is_ok_and(|b| b == big)
            && std::fs::read(host.p("notes.txt")).is_ok_and(|b| b == b"version 2\n")
    });
    wait("alpha knows of the host", 20, || {
        a.cli(&["recovery", "sheet"]).contains(&key)
    });

    // Every other device is gone, and the host has restarted since.
    a.stop();
    drop(a);
    host.stop();
    host.start();
    host.wait_mounted();

    // Wrong words get nothing, and the host tells them nothing.
    let mut stranger = Dev::new(root.path(), "stranger", free_port());
    stranger.start();
    let other = "abandon ".repeat(23) + "art";
    let o = stranger.cli_input(
        &["recovery", "restore", "--host", &at, "--key", &key],
        &other,
    );
    assert!(!o.status.success(), "{o:?}");
    let told = String::from_utf8_lossy(&o.stderr).to_string();
    assert!(
        told.contains("does not know these recovery words"),
        "{told}"
    );
    // A wrong key is caught before anything is sent.
    let typo = key.replacen(|c: char| c.is_ascii_digit(), "x", 1);
    let o = stranger.cli_input(
        &["recovery", "restore", "--host", &at, "--key", &typo],
        &words,
    );
    assert!(!o.status.success(), "{o:?}");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("mistyped"),
        "{o:?}"
    );

    // Someone else's key, and an address with nobody there. A person told
    // which one it is knows what to check.
    let other = cardinald::host::sheet_key(&[5; 32]);
    let o = stranger.cli_input(
        &["recovery", "restore", "--host", &at, "--key", &other],
        &words,
    );
    assert!(!o.status.success(), "{o:?}");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("does not answer to that key"),
        "{o:?}"
    );
    let nobody = format!("127.0.0.1:{}", free_port());
    let o = stranger.cli_input(
        &["recovery", "restore", "--host", &nobody, "--key", &key],
        &words,
    );
    assert!(!o.status.success(), "{o:?}");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("nothing is listening"),
        "{o:?}"
    );

    // A new device, with the words and the sheet.
    let mut new = Dev::new(root.path(), "new", free_port());
    new.start();
    let done = new.cli_input(
        &["recovery", "restore", "--host", &at, "--key", &key],
        &words,
    );
    assert!(
        String::from_utf8_lossy(&done.stdout).contains("Restored"),
        "{done:?}"
    );
    new.wait_mounted();
    wait("the new device has the files", 40, || {
        std::fs::read(new.p("notes.txt")).is_ok_and(|b| b == b"version 2\n")
            && std::fs::read(new.p("photos/big.bin")).is_ok_and(|b| b == big)
    });
    // With their history.
    let h = new.cli(&["history", &new.p("notes.txt").display().to_string()]);
    assert!(h.contains("  2 "), "{h}");

    // And it is a working device: changes go both ways.
    std::fs::write(new.p("after.txt"), "written after the loss\n").unwrap();
    new.cli(&["flush"]);
    wait("the host has the new file", 20, || {
        std::fs::read(host.p("after.txt")).is_ok_and(|b| b == b"written after the loss\n")
    });
    std::fs::write(host.p("back.txt"), "and back\n").unwrap();
    host.cli(&["flush"]);
    wait("the new device has the host's file", 20, || {
        std::fs::read(new.p("back.txt")).is_ok_and(|b| b == b"and back\n")
    });

    // It manages devices: the lost one can go, with the words, as it was
    // an admin device.
    let o = new.cli_input(&["remove-device", "alpha"], &words);
    assert!(o.status.success(), "{o:?}");
    let shown = new.cli(&["devices"]);
    assert!(!shown.contains("alpha"), "{shown}");

    // The sheet survives the loss too: the new device can print it.
    assert!(new.cli(&["recovery", "sheet"]).contains(&key));
}

/// A session with an unknown device, as a stranger's software would open
/// one: it needs only what is on a recovery sheet.
async fn stranger_session(host: &Dev, key: &str) -> (Endpoint, Result<Session, LinkError>) {
    let dir = MemoryDirectory::new();
    let mut c = EndpointConfig::new(Arc::new(HybridKeyPair::generate()), dir);
    c.connect_timeout = Duration::from_secs(3);
    let e = Endpoint::bind(
        c,
        Bind {
            udp: None,
            tcp: Some("127.0.0.1:0".parse().unwrap()),
        },
    )
    .await
    .unwrap();
    let addr = format!("127.0.0.1:{}", host.port).parse().unwrap();
    let key = cardinald::host::read_sheet_key(key).unwrap();
    let s = e.connect(Target::public(addr, CarrierKind::Tcp, key)).await;
    (e, s)
}

/// Waits until the host has closed a session.
async fn closed(s: &Session) -> bool {
    for _ in 0..300 {
        if s.is_closed() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// The host accepts sessions from strangers, for restore. Until one proves
/// the root key it gets nothing, whatever it asks for.
#[test]
fn a_stranger_gets_nothing_before_it_proves_the_root_key() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut host = Dev::new(root.path(), "nuc", free_port());
    host.start();
    let init = host.cli(&["init", "--yes", "--name", "nuc"]);
    host.wait_mounted();
    let words = words_from(&init);
    let at = format!("127.0.0.1:{}", host.port);
    let shown = host.cli(&["host", "--address", &at]);
    let key = field(&shown, "Key:");
    let phrase = RecoveryPhrase::parse(&words).unwrap();
    let identity_label =
        |s: &Session| cardinal_sync::identity_log_label(&s.peer_identity().unwrap().identity);

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Chunks, which a device serves to anyone it has a session with.
        let (_e, s) = stranger_session(&host, &key).await;
        let s = s.unwrap();
        let mut st = s.open_stream(Service::BLOB, Priority::Interactive).unwrap();
        let ask = Record::new()
            .with(0, 1u64)
            .with(1, Value::list(vec![[7u8; 32]]));
        st.send_message(&Value::Record(ask)).await.unwrap();
        assert!(closed(&s).await, "asking for chunks ends the session");

        // Reconciling, which names the sets.
        let (_e, s) = stranger_session(&host, &key).await;
        let s = s.unwrap();
        let label = identity_label(&s);
        let mut st = s.open_stream(Service::SYNC, Priority::Interactive).unwrap();
        let ask = Message::Want {
            label,
            ids: vec![[7u8; 32]],
        };
        st.send_message(&Value::Record(ask.to_record()))
            .await
            .unwrap();
        assert!(closed(&s).await, "asking for the log ends the session");

        // Any other storage op.
        let (_e, s) = stranger_session(&host, &key).await;
        let s = s.unwrap();
        let mut st = s
            .open_stream(Service::STORAGE, Priority::Interactive)
            .unwrap();
        let ask = Record::new().with(0, 2u64);
        st.send_message(&Value::Record(ask)).await.unwrap();
        assert!(closed(&s).await, "listing ends the session");

        // A proof by the wrong key, a forged one, and one replayed from
        // another session are refused, and the session stays unproven.
        let sign = |s: &Session, k: &SigningKey| {
            let mut msg = b"cardinal restore".to_vec();
            msg.extend_from_slice(&s.handshake_hash());
            k.sign(&msg)
        };
        let prove = |s: &Session, key: [u8; 32], signature: [u8; 64]| {
            let s = s.clone();
            async move {
                let mut st = s
                    .open_stream(Service::STORAGE, Priority::Interactive)
                    .unwrap();
                let ask = Record::new().with(0, 5u64).with(1, key).with(2, signature);
                st.send_message(&Value::Record(ask)).await.unwrap();
                let v = st.recv_message_max(4096).await.unwrap().unwrap();
                v.as_record().unwrap().get(0).unwrap().as_uint().unwrap()
            }
        };
        let (_e, s) = stranger_session(&host, &key).await;
        let s = s.unwrap();
        let real = phrase.root_signing_key();
        let other = SigningKey::from_seed(&[9; 32]);
        assert_eq!(
            prove(&s, other.public_key(), sign(&s, &other)).await,
            0,
            "wrong key"
        );
        assert_eq!(
            prove(&s, real.public_key(), sign(&s, &other)).await,
            0,
            "forged"
        );
        let (_e2, s2) = stranger_session(&host, &key).await;
        let replayed = sign(&s2.unwrap(), &real);
        assert_eq!(prove(&s, real.public_key(), replayed).await, 0, "replayed");
        let label = identity_label(&s);
        let mut st = s.open_stream(Service::SYNC, Priority::Interactive).unwrap();
        let ask = Message::Want {
            label,
            ids: vec![[7u8; 32]],
        };
        st.send_message(&Value::Record(ask.to_record()))
            .await
            .unwrap();
        assert!(closed(&s).await, "still unproven");

        // The real proof works, on its own session.
        let (_e, s) = stranger_session(&host, &key).await;
        let s = s.unwrap();
        assert_eq!(prove(&s, real.public_key(), sign(&s, &real)).await, 5);
    });

    // No longer a host: no session at all.
    host.cli(&["host", "--off"]);
    rt.block_on(async {
        let (_e, s) = stranger_session(&host, &key).await;
        assert!(s.is_err(), "the address looks unused again");
    });
}
