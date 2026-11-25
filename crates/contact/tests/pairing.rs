//! Pairing two in-process devices over loopback, then opening the link
//! session the pairing authorizes; and discovery over loopback multicast.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cardinal_contact::ble::{BoxChannel, MemoryEther, Radio};
use cardinal_contact::discovery::{
    advertise_device, advertise_pairing, find_pairing, DeviceBrowser,
};
use cardinal_contact::mdns::{open_socket, MdnsConfig};
use cardinal_contact::pairing::{
    is_pairing_message, pair_typer_on, proof_message, read_message, POWER_ADMIN, POWER_DEVICE,
};
use cardinal_contact::{
    pair_typer, ContactError, DeviceEnroller, EndpointAddr, LocalDevice, NewDevice, PairRole,
    PairingCode, Shower,
};
use cardinal_crypto::{verify, HybridKeyPair, SigningKey};
use cardinal_link::{
    Bind, CarrierKind, Endpoint, EndpointConfig, LocalIdentity, MemoryDirectory, Priority, Service,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Dev {
    key: Arc<HybridKeyPair>,
    signing: Arc<SigningKey>,
    identity: Option<[u8; 32]>,
    endpoint: Endpoint,
}

async fn dev(n: u8, identity: Option<[u8; 32]>) -> Dev {
    let key = Arc::new(HybridKeyPair::from_seed(&[n; 32]));
    let signing = Arc::new(SigningKey::from_seed(&[n; 32]));
    let mut c = EndpointConfig::new(key.clone(), MemoryDirectory::new());
    c.identity = identity.map(|identity| LocalIdentity {
        identity,
        signing_key: signing.clone(),
    });
    c.connect_timeout = Duration::from_secs(3);
    let endpoint = Endpoint::bind(
        c,
        Bind {
            udp: None,
            tcp: Some("127.0.0.1:0".parse().unwrap()),
        },
    )
    .await
    .unwrap();
    Dev {
        key,
        signing,
        identity,
        endpoint,
    }
}

impl Dev {
    fn local(&self, name: &str) -> LocalDevice {
        LocalDevice {
            identity: self.identity,
            signing_key: self.signing.clone(),
            link_key: self.key.public_key().clone(),
            link_endpoint: EndpointAddr::new(CarrierKind::Tcp, self.endpoint.tcp_addr().unwrap()),
            name: name.into(),
            adds_at: self.identity.map(|_| POWER_DEVICE),
        }
    }
}

#[derive(Default)]
struct RecordingEnroller(Mutex<Vec<NewDevice>>);

impl DeviceEnroller for RecordingEnroller {
    fn enroll(&self, device: &NewDevice) -> Result<(), String> {
        self.0.lock().unwrap().push(device.clone());
        Ok(())
    }
}

#[tokio::test]
async fn add_own_device_by_pairing() {
    let admin = dev(1, Some([0xaa; 32])).await;
    let fresh = dev(2, None).await;

    let shower = Shower::bind(
        fresh.local("new laptop"),
        "127.0.0.1:0".parse().unwrap(),
        None,
    )
    .await
    .unwrap();
    let code = shower.code().clone();
    let typed = PairingCode::parse(&code.to_string()).unwrap();
    let addr = shower.local_addr().unwrap();
    let me = admin.local("desktop");
    let (s, t) = tokio::join!(
        shower.run(),
        pair_typer(&me, &typed, addr, Duration::from_secs(5))
    );
    let (s, t) = (s.unwrap(), t.unwrap());
    assert_eq!(s.joins_at, Some(POWER_DEVICE), "the new device was told");
    assert_eq!(s.role, PairRole::Shower);
    assert_eq!(t.role, PairRole::Typer);
    assert_eq!(*s.link_secret, *t.link_secret);
    assert_eq!(s.peer.name, "desktop");
    assert_eq!(t.peer.name, "new laptop");
    assert_eq!(s.peer.identity, Some([0xaa; 32]));
    assert_eq!(t.peer.identity, None);

    // What the identity layer needs to append add_key.
    let nd = t.new_device.clone().expect("new device");
    assert!(nd.verify());
    assert_eq!(nd.identity, [0xaa; 32]);
    assert_eq!(nd.signing_key, fresh.signing.public_key());
    assert_eq!(nd.link_key, *fresh.key.public_key());
    assert_eq!(nd.power, POWER_DEVICE);
    verify(
        &nd.signing_key,
        &proof_message(&nd.identity, &nd.signing_key, nd.power, &nd.link_key),
        &nd.proof,
    )
    .unwrap();
    let op = nd.add_key_op();
    assert_eq!(op.uint(0).unwrap(), 1);
    assert_eq!(op.uint(2).unwrap(), POWER_DEVICE);
    let enroller = RecordingEnroller::default();
    enroller.enroll(&nd).unwrap();
    assert_eq!(enroller.0.lock().unwrap().len(), 1);

    // The link session the pairing authorizes: the typer initiates with
    // derive("invite", K); the new device has no identity yet.
    fresh.endpoint.add_secret(s.secret_entry());
    let (st, ss) = tokio::join!(
        admin.endpoint.connect(t.link_target().unwrap()),
        fresh.endpoint.accept()
    );
    let (st, ss) = (st.unwrap(), ss.unwrap());
    assert!(
        st.peer_identity().is_none(),
        "the new device has no identity"
    );
    let pi = ss.peer_identity().unwrap();
    assert_eq!(pi.identity, [0xaa; 32]);
    assert_eq!(pi.signing_key, admin.signing.public_key());
    assert!(!pi.verified_by_log, "provisional until the log arrives");
    assert!(st.stats().rekeys >= 1);

    let mut stream = st.open_stream(Service::SYNC, Priority::Background).unwrap();
    stream.write_all(b"identity log").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut r = ss.accept_stream().await.unwrap();
    let mut got = Vec::new();
    r.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"identity log");
}

#[tokio::test]
async fn wrong_code_fails_after_allowed_attempts() {
    let admin = dev(3, Some([0xbb; 32])).await;
    let fresh = dev(4, None).await;
    let mut shower = Shower::bind(fresh.local("phone"), "127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    shower.attempt_timeout = Duration::from_secs(2);
    let code = shower.code().clone();
    let addr = shower.local_addr().unwrap();
    let run = tokio::spawn(shower.run());
    for i in 0..3u16 {
        let mut wrong = code.clone();
        wrong.words[2] = (wrong.words[2] + 1 + i) % 2048;
        let r = pair_typer(
            &admin.local("desktop"),
            &wrong,
            addr,
            Duration::from_secs(3),
        )
        .await;
        assert!(
            matches!(r, Err(ContactError::WrongCode)),
            "attempt {i}: {r:?}"
        );
    }
    let r = tokio::time::timeout(Duration::from_secs(3), run)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(r, Err(ContactError::TooManyAttempts)), "{r:?}");
    // The right code no longer works: the shower has stopped.
    let r = pair_typer(&admin.local("desktop"), &code, addr, Duration::from_secs(1)).await;
    assert!(r.is_err());
}

#[tokio::test]
async fn meeting_a_person_exchanges_no_proofs() {
    let ana = dev(5, Some([0x0a; 32])).await;
    let ben = dev(6, Some([0x0b; 32])).await;
    let shower = Shower::bind(ben.local("Ben"), "127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    let code = shower.code().clone();
    let addr = shower.local_addr().unwrap();
    let me = ana.local("Ana");
    let (s, t) = tokio::join!(
        shower.run(),
        pair_typer(&me, &code, addr, Duration::from_secs(5))
    );
    let (s, t) = (s.unwrap(), t.unwrap());
    assert!(t.new_device.is_none());
    assert!(s.peer.proof.is_none() && t.peer.proof.is_none());
    ben.endpoint.add_secret(s.secret_entry());
    let (a, b) = tokio::join!(
        ana.endpoint.connect(t.link_target().unwrap()),
        ben.endpoint.accept()
    );
    assert_eq!(a.unwrap().peer_identity().unwrap().identity, [0x0b; 32]);
    assert_eq!(b.unwrap().peer_identity().unwrap().identity, [0x0a; 32]);
}

/// Says why a test cannot run here, before it returns: a skip, said; or,
/// in the release tier (`CARDINAL_TEST_STRICT=1`, set by
/// `scripts/test-tier release`), a failure.
fn skipping(why: &str) {
    let strict = std::env::var_os("CARDINAL_TEST_STRICT").is_some_and(|v| v == "1");
    assert!(!strict, "cannot run in the release tier: {why}");
    eprintln!("skipping: {why}");
}

/// Multicast on loopback, on a private port (and the next one); `None` if
/// unavailable here. Run side by side with other binaries, the port is the
/// first of the block `scripts/test-tier` gave this one
/// (`CARDINAL_TEST_PORTS`), which no other binary uses.
async fn loopback_mdns() -> Option<MdnsConfig> {
    let port = match std::env::var("CARDINAL_TEST_PORTS") {
        Ok(v) => v
            .split_once('-')
            .and_then(|(a, _)| a.parse::<u16>().ok())
            .unwrap_or_else(|| panic!("CARDINAL_TEST_PORTS={v} is not first-last")),
        Err(_) => 20000 + (std::process::id() % 20000) as u16,
    };
    let cfg = MdnsConfig {
        group: Ipv4Addr::new(224, 0, 0, 251),
        port,
        interface: Ipv4Addr::LOCALHOST,
    };
    let a = open_socket(&cfg).ok()?;
    let b = open_socket(&cfg).ok()?;
    a.send_to(b"probe", SocketAddr::from((cfg.group, cfg.port)))
        .await
        .ok()?;
    let mut buf = [0u8; 16];
    match tokio::time::timeout(Duration::from_millis(500), b.recv_from(&mut buf)).await {
        Ok(Ok((5, _))) => Some(cfg),
        _ => None,
    }
}

#[tokio::test]
async fn discovery_on_loopback_multicast() {
    let Some(cfg) = loopback_mdns().await else {
        skipping("multicast on loopback is unavailable");
        return;
    };
    let secret = [0x5c; 32];
    let other = [0x77; 32];
    let _ad = advertise_device(cfg, &secret, 4567, Duration::from_millis(300)).unwrap();
    let mut mine = DeviceBrowser::start(cfg, &[other, secret], Duration::from_millis(300)).unwrap();
    let found = tokio::time::timeout(Duration::from_secs(5), mine.next())
        .await
        .expect("found")
        .unwrap();
    assert_eq!(found.addr.port(), 4567);
    assert_eq!(found.secret_index, 1);
    // A stranger without the secret recognizes nothing.
    let mut stranger = DeviceBrowser::start(cfg, &[other], Duration::from_millis(300)).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(1500), stranger.next())
            .await
            .is_err()
    );

    // The pairing advertisement.
    let _p = advertise_pairing(cfg, 42, 9999, Duration::from_millis(300)).unwrap();
    let _q = advertise_pairing(cfg, 7, 8888, Duration::from_millis(300)).unwrap();
    let addr = find_pairing(cfg, 42, Duration::from_secs(5)).await.unwrap();
    assert_eq!(addr.port(), 9999);
}

#[tokio::test]
async fn pairing_found_by_mdns() {
    let Some(cfg) = loopback_mdns().await else {
        skipping("multicast on loopback is unavailable");
        return;
    };
    let cfg = MdnsConfig {
        port: cfg.port + 1,
        ..cfg
    };
    let admin = dev(7, Some([0xcc; 32])).await;
    let fresh = dev(8, None).await;
    let shower = Shower::bind(fresh.local("tablet"), "127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    let code = shower.code().clone();
    let _ad = advertise_pairing(
        cfg,
        code.channel,
        shower.local_addr().unwrap().port(),
        Duration::from_millis(300),
    )
    .unwrap();
    let typer = async {
        let addr = find_pairing(cfg, code.channel, Duration::from_secs(5)).await?;
        pair_typer(&admin.local("desktop"), &code, addr, Duration::from_secs(5)).await
    };
    let (s, t) = tokio::join!(shower.run(), typer);
    assert!(s.is_ok() && t.unwrap().new_device.is_some());
}

#[tokio::test]
async fn the_admin_names_the_power_and_the_new_device_signs_exactly_that() {
    let admin = dev(9, Some([0xdd; 32])).await;
    let fresh = dev(10, None).await;
    let shower = Shower::bind(fresh.local("server"), "127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    let code = shower.code().clone();
    let addr = shower.local_addr().unwrap();
    let mut me = admin.local("desktop");
    me.adds_at = Some(POWER_ADMIN);
    let (s, t) = tokio::join!(
        shower.run(),
        pair_typer(&me, &code, addr, Duration::from_secs(5))
    );
    let (s, t) = (s.unwrap(), t.unwrap());
    assert_eq!(s.joins_at, Some(POWER_ADMIN));
    let nd = t.new_device.unwrap();
    assert_eq!(nd.power, POWER_ADMIN);
    assert!(nd.verify());
    // The same proof does not stand for another power.
    let other = cardinal_contact::NewDevice {
        power: POWER_DEVICE,
        ..nd
    };
    assert!(!other.verify());
}

#[tokio::test]
async fn a_typer_that_names_no_power_ends_the_pairing() {
    let admin = dev(11, Some([0xde; 32])).await;
    let fresh = dev(12, None).await;
    let shower = Shower::bind(fresh.local("phone"), "127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    let code = shower.code().clone();
    let addr = shower.local_addr().unwrap();
    let mut me = admin.local("desktop");
    me.adds_at = None;
    let (s, t) = tokio::join!(
        shower.run(),
        pair_typer(&me, &code, addr, Duration::from_secs(2))
    );
    assert!(
        matches!(s, Err(ContactError::Malformed(w)) if w.contains("power")),
        "{s:?}"
    );
    assert!(t.is_err());
}

/// A shower over Bluetooth: channels opened to `radio`'s PSM whose first
/// message is pairing's go to the shower, the others nowhere.
async fn ble_shower(
    shower: Shower,
    radio: &cardinal_contact::ble::MemoryRadio,
) -> (
    u16,
    tokio::task::JoinHandle<Result<cardinal_contact::Paired, ContactError>>,
) {
    let mut l = radio.listen().await.unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let psm = l.psm;
    tokio::spawn(async move {
        let _guard = l.guard;
        while let Some((_, mut ch)) = l.incoming.recv().await {
            let Ok(first) = read_message(&mut ch).await else {
                continue;
            };
            if is_pairing_message(&first) {
                let _ = tx.send((ch, first)).await;
            }
        }
    });
    (psm, tokio::spawn(shower.with_channels(rx).run()))
}

#[tokio::test]
async fn pairing_over_bluetooth_and_the_link_session_on_the_same_channel() {
    let admin = dev(13, Some([0xe1; 32])).await;
    let fresh = dev(14, None).await;
    let ether = MemoryEther::new();
    let (near, far) = (ether.radio(), ether.radio());
    let shower = Shower::bind(fresh.local("phone"), "127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    let code = shower.code().clone();
    let (psm, run) = ble_shower(shower, &far).await;
    let mut ch: BoxChannel = near.connect(far.addr(), psm).await.unwrap();
    let t = pair_typer_on(
        &admin.local("laptop"),
        &code,
        &mut ch,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let mut s = run.await.unwrap().unwrap();
    assert_eq!(s.joins_at, Some(POWER_DEVICE));
    assert!(t.new_device.as_ref().unwrap().verify());
    // The link session runs over the same channel.
    fresh.endpoint.add_secret(s.secret_entry());
    let on_s = fresh
        .endpoint
        .attach(s.channel.take().unwrap(), CarrierKind::Ble, "pairing");
    let on_t = admin.endpoint.attach(ch, CarrierKind::Ble, "pairing");
    let (a, b) = tokio::join!(
        admin
            .endpoint
            .connect_on(&on_t, t.target_on(CarrierKind::Ble)),
        fresh.endpoint.accept()
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(on_s.carries(&b));
    assert_eq!(b.peer_identity().unwrap().identity, [0xe1; 32]);
    let mut st = a.open_stream(Service::SYNC, Priority::Background).unwrap();
    st.write_all(b"identity log").await.unwrap();
    st.shutdown().await.unwrap();
    let mut r = b.accept_stream().await.unwrap();
    let mut got = Vec::new();
    r.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"identity log");
}

#[tokio::test]
async fn three_wrong_codes_over_bluetooth_and_the_lan_together_end_the_code() {
    let admin = dev(15, Some([0xe2; 32])).await;
    let fresh = dev(16, None).await;
    let ether = MemoryEther::new();
    let (near, far) = (ether.radio(), ether.radio());
    let mut shower = Shower::bind(fresh.local("phone"), "127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    shower.attempt_timeout = Duration::from_secs(2);
    let code = shower.code().clone();
    let addr = shower.local_addr().unwrap();
    let (psm, run) = ble_shower(shower, &far).await;
    let wrong = |i: u16| {
        let mut w = code.clone();
        w.words[0] = (w.words[0] + 1 + i) % 2048;
        w
    };
    // Two wrong over Bluetooth, each closing its channel.
    for i in 0..2 {
        let mut ch = near.connect(far.addr(), psm).await.unwrap();
        let r = pair_typer_on(
            &admin.local("laptop"),
            &wrong(i),
            &mut ch,
            Duration::from_secs(3),
        )
        .await;
        assert!(matches!(r, Err(ContactError::WrongCode)), "{i}: {r:?}");
    }
    // The third, on the LAN, is the last.
    let r = pair_typer(
        &admin.local("laptop"),
        &wrong(2),
        addr,
        Duration::from_secs(3),
    )
    .await;
    assert!(matches!(r, Err(ContactError::WrongCode)), "{r:?}");
    let r = tokio::time::timeout(Duration::from_secs(3), run)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(r, Err(ContactError::TooManyAttempts)), "{r:?}");
    // The right code finds nobody now.
    let late = near.connect(far.addr(), psm).await;
    if let Ok(mut ch) = late {
        let r = pair_typer_on(
            &admin.local("laptop"),
            &code,
            &mut ch,
            Duration::from_secs(1),
        )
        .await;
        assert!(r.is_err());
    }
}

#[tokio::test]
async fn a_right_code_over_bluetooth_after_two_wrong_ones_pairs() {
    let admin = dev(17, Some([0xe3; 32])).await;
    let fresh = dev(18, None).await;
    let ether = MemoryEther::new();
    let (near, far) = (ether.radio(), ether.radio());
    let shower = Shower::bind(fresh.local("phone"), "127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    let code = shower.code().clone();
    let (psm, run) = ble_shower(shower, &far).await;
    for i in 0..2u16 {
        let mut w = code.clone();
        w.words[1] = (w.words[1] + 1 + i) % 2048;
        let mut ch = near.connect(far.addr(), psm).await.unwrap();
        let r = pair_typer_on(&admin.local("laptop"), &w, &mut ch, Duration::from_secs(3)).await;
        assert!(matches!(r, Err(ContactError::WrongCode)), "{r:?}");
    }
    let mut ch = near.connect(far.addr(), psm).await.unwrap();
    let t = pair_typer_on(
        &admin.local("laptop"),
        &code,
        &mut ch,
        Duration::from_secs(5),
    )
    .await;
    assert!(t.unwrap().new_device.is_some());
    assert!(run.await.unwrap().is_ok());
}
