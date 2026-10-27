//! Pairing two in-process devices over loopback, then opening the link
//! session the pairing authorizes; and discovery over loopback multicast.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cardinal_contact::discovery::{
    advertise_device, advertise_pairing, find_pairing, DeviceBrowser,
};
use cardinal_contact::mdns::{open_socket, MdnsConfig};
use cardinal_contact::pairing::{proof_message, POWER_DEVICE};
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
            join_power: POWER_DEVICE,
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

/// Multicast on loopback, on a private port; `None` if unavailable here.
async fn loopback_mdns() -> Option<MdnsConfig> {
    let port = 20000 + (std::process::id() % 20000) as u16;
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
        eprintln!("skipping: multicast on loopback is unavailable");
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
        eprintln!("skipping: multicast on loopback is unavailable");
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
