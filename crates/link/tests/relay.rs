//! Two devices that cannot reach each other, through a host that can reach
//! both (`hosts.md#relay`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cardinal_crypto::{HybridKeyPair, SigningKey};
use cardinal_link::{
    Bind, CarrierKind, Endpoint, EndpointConfig, LocalIdentity, MemoryDirectory, Priority, Service,
    Session, Target,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Device {
    key: Arc<HybridKeyPair>,
    endpoint: Endpoint,
}

async fn device(n: u8, dir: &Arc<MemoryDirectory>, tcp: bool) -> Device {
    let key = Arc::new(HybridKeyPair::from_seed(&[n; 32]));
    let id = LocalIdentity {
        identity: [0xaa; 32],
        signing_key: Arc::new(SigningKey::from_seed(&[n; 32])),
    };
    dir.add_device(
        id.identity,
        id.signing_key.public_key(),
        key.public_key().clone(),
    );
    let mut c = EndpointConfig::new(key.clone(), dir.clone());
    c.identity = Some(id);
    c.connect_timeout = Duration::from_secs(3);
    c.handshake_retry = Duration::from_millis(200);
    let loopback: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint = Endpoint::bind(
        c,
        Bind {
            udp: Some(loopback),
            tcp: tcp.then_some(loopback),
        },
    )
    .await
    .unwrap();
    Device { key, endpoint }
}

/// A session from `d` to the host, and the host's side of it.
async fn to_host(d: &Device, host: &Device, carrier: CarrierKind) -> (Session, Session) {
    let at = match carrier {
        CarrierKind::Udp => host.endpoint.udp_addr().unwrap(),
        CarrierKind::Tcp => host.endpoint.tcp_addr().unwrap(),
    };
    let t = Target::new(at, carrier, host.key.public_key());
    let (a, b) = tokio::join!(d.endpoint.connect(t), host.endpoint.accept());
    (a.unwrap(), b.unwrap())
}

async fn relayed_pair(carrier: CarrierKind) {
    let dir = MemoryDirectory::new();
    let host = device(1, &dir, true).await;
    let a = device(2, &dir, false).await;
    let b = device(3, &dir, false).await;
    let (a_host, host_a) = to_host(&a, &host, carrier).await;
    let (_b_host, host_b) = to_host(&b, &host, CarrierKind::Udp).await;

    let channel = 77;
    host.endpoint.relay_open(channel, &host_a, &host_b);
    let t = Target::new(
        host_a.remote_addr().unwrap(),
        CarrierKind::Udp,
        b.key.public_key(),
    )
    .through(&a_host, channel);
    let (s, r) = tokio::join!(a.endpoint.connect(t), b.endpoint.accept());
    let (s, r) = (s.unwrap(), r.unwrap());
    assert!(s.is_relayed());
    assert!(r.is_relayed());

    // Both ways, and more than fits in the windows.
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    let mut out = s.open_stream(Service::BLOB, Priority::Background).unwrap();
    let sent = data.clone();
    let send = tokio::spawn(async move {
        out.write_all(&sent).await.unwrap();
        out.shutdown().await.unwrap();
    });
    let mut rx = r.accept_stream().await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), rx.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    send.await.unwrap();
    assert!(got == data);

    let mut back = r.open_stream(Service::SYNC, Priority::Interactive).unwrap();
    back.write_all(b"back").await.unwrap();
    back.shutdown().await.unwrap();
    let mut rx = s.accept_stream().await.unwrap();
    let mut got = Vec::new();
    rx.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"back");

    // Closing the channel ends what it carried.
    host.endpoint.relay_close(channel);
    let mut out = s.open_stream(Service::SYNC, Priority::Interactive).unwrap();
    out.write_all(b"lost").await.unwrap();
    let nothing = tokio::time::timeout(Duration::from_millis(500), r.accept_stream()).await;
    assert!(nothing.is_err());
}

#[tokio::test]
async fn two_devices_talk_through_a_host() {
    relayed_pair(CarrierKind::Udp).await;
}

/// A device on a network that blocks UDP can still use a host, over TCP. The
/// host's other leg can lose packets, so the session must recover them.
#[tokio::test]
async fn a_leg_of_the_relay_can_be_tcp() {
    relayed_pair(CarrierKind::Tcp).await;
}

/// A host forwards only for the two paths a channel belongs to.
#[tokio::test]
async fn a_channel_is_no_use_to_a_third_party() {
    let dir = MemoryDirectory::new();
    let host = device(1, &dir, false).await;
    let a = device(2, &dir, false).await;
    let b = device(3, &dir, false).await;
    let c = device(4, &dir, false).await;
    let (_a_host, host_a) = to_host(&a, &host, CarrierKind::Udp).await;
    let (_b_host, host_b) = to_host(&b, &host, CarrierKind::Udp).await;
    let (c_host, _host_c) = to_host(&c, &host, CarrierKind::Udp).await;

    host.endpoint.relay_open(9, &host_a, &host_b);
    let t = Target::new(
        host_a.remote_addr().unwrap(),
        CarrierKind::Udp,
        b.key.public_key(),
    )
    .through(&c_host, 9)
    .within(Duration::from_millis(600));
    assert!(c.endpoint.connect(t).await.is_err());
}

/// A direct session wins whichever came first: a relay is for when there is
/// no other way, and both ends can tell which is which.
#[tokio::test]
async fn a_direct_session_beats_one_through_a_host() {
    let dir = MemoryDirectory::new();
    let host = device(1, &dir, false).await;
    let a = device(2, &dir, false).await;
    let b = device(3, &dir, false).await;
    let (a_host, host_a) = to_host(&a, &host, CarrierKind::Udp).await;
    let (_b_host, host_b) = to_host(&b, &host, CarrierKind::Udp).await;
    host.endpoint.relay_open(5, &host_a, &host_b);
    let relayed = |d: &Device| {
        Target::new(
            host_a.remote_addr().unwrap(),
            CarrierKind::Udp,
            d.key.public_key(),
        )
        .through(&a_host, 5)
    };
    let direct = Target::new(
        b.endpoint.udp_addr().unwrap(),
        CarrierKind::Udp,
        b.key.public_key(),
    );

    // Relayed first, then direct: direct takes over.
    let (s, r) = tokio::join!(a.endpoint.connect(relayed(&b)), b.endpoint.accept());
    let (through, _r) = (s.unwrap(), r.unwrap());
    let (s, r) = tokio::join!(a.endpoint.connect(direct.clone()), b.endpoint.accept());
    let (first, _other) = (s.unwrap(), r.unwrap());
    assert!(!first.is_relayed());
    tokio::time::timeout(Duration::from_secs(2), through.closed())
        .await
        .unwrap();

    // Direct first, then relayed: direct stays.
    let (s, _r) = tokio::join!(a.endpoint.connect(relayed(&b)), async {
        tokio::time::timeout(Duration::from_millis(500), b.endpoint.accept()).await
    });
    assert!(s.is_err(), "the relayed session lost");
    assert!(!first.is_closed());
}
