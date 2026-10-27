//! Unit tests of the session core, with two cores wired back to back in
//! memory and time under the test's control.

use super::*;
use crate::directory::MemoryDirectory;
use crate::handshake::{
    finish_initiation, initiate, receive_initiation, respond, InitiationParams,
};
use cardinal_crypto::{HybridKeyPair, SigningKey};

struct Pair {
    a: Conn,
    b: Conn,
    now: Instant,
}

fn ids() -> (LocalIdentity, LocalIdentity) {
    (
        LocalIdentity {
            identity: [0xaa; 32],
            signing_key: Arc::new(SigningKey::from_seed(&[1; 32])),
        },
        LocalIdentity {
            identity: [0xbb; 32],
            signing_key: Arc::new(SigningKey::from_seed(&[2; 32])),
        },
    )
}

fn pair_with(
    config: SessionConfig,
    a_id: Option<LocalIdentity>,
    b_id: Option<LocalIdentity>,
    b_admission: Admission,
) -> Pair {
    let ka = HybridKeyPair::from_seed(b"a");
    let kb = HybridKeyPair::from_seed(b"b");
    let dir = MemoryDirectory::new();
    if let Some(i) = &a_id {
        dir.add_device(
            i.identity,
            i.signing_key.public_key(),
            ka.public_key().clone(),
        );
    }
    if let Some(i) = &b_id {
        dir.add_device(
            i.identity,
            i.signing_key.public_key(),
            kb.public_key().clone(),
        );
    }
    let p = InitiationParams {
        local: &ka,
        remote_x25519: *kb.public_key().x25519(),
        remote_kem: Some(kb.public_key().kem()),
        secret: None,
        counter: 10,
        sender_index: 1,
    };
    let pending = initiate(&p, &[3; 32], [0; 3], |k| k.encapsulate()).unwrap();
    let r = receive_initiation(&kb, pending.packet(), |_| true, &[], false).unwrap();
    let (kb_keys, resp) = respond(r, Some(ka.public_key().kem()), 2, &[4; 32], |k| {
        k.encapsulate()
    })
    .unwrap();
    let done = finish_initiation(pending, &ka, &resp[..]).unwrap();
    let now = Instant::now();
    let mk = |role, li, ri, keys, peer: &HybridKeyPair, id, adm, path| {
        Conn::new(
            ConnParams {
                role,
                local_index: li,
                remote_index: ri,
                keys,
                peer_static: *peer.public_key().x25519(),
                peer_link_key: Some(peer.public_key().clone()),
                local_identity: id,
                directory: dir.clone(),
                admission: adm,
                path: Path::Mem(path),
                initiation_counter: 10,
                config: config.clone(),
                signals: Arc::new(Signals::default()),
            },
            now,
        )
    };
    let a = mk(
        Role::Initiator,
        1,
        2,
        done.keys,
        &kb,
        a_id,
        Admission::Known,
        1,
    );
    let b = mk(Role::Responder, 2, 1, kb_keys, &ka, b_id, b_admission, 2);
    Pair { a, b, now }
}

fn pair() -> Pair {
    let (a, b) = ids();
    pair_with(SessionConfig::default(), Some(a), Some(b), Admission::Known)
}

impl Pair {
    /// Moves packets both ways until both sides are quiet. Returns the
    /// number of packets moved.
    fn pump(&mut self) -> usize {
        let mut moved = 0;
        loop {
            let mut any = false;
            while let Some((_, p)) = self.a.poll_transmit(self.now) {
                let mut v = p.to_vec();
                self.b.recv_packet(&mut v, &Path::Mem(2), self.now);
                any = true;
                moved += 1;
            }
            while let Some((_, p)) = self.b.poll_transmit(self.now) {
                let mut v = p.to_vec();
                self.a.recv_packet(&mut v, &Path::Mem(1), self.now);
                any = true;
                moved += 1;
            }
            if !any {
                // Let delayed acks go out.
                self.now += MAX_ACK_DELAY;
                let more = self
                    .a
                    .poll_transmit(self.now)
                    .map(|(_, p)| (true, p))
                    .or_else(|| self.b.poll_transmit(self.now).map(|(_, p)| (false, p)));
                match more {
                    Some((true, p)) => {
                        let mut v = p.to_vec();
                        self.b.recv_packet(&mut v, &Path::Mem(2), self.now);
                    }
                    Some((false, p)) => {
                        let mut v = p.to_vec();
                        self.a.recv_packet(&mut v, &Path::Mem(1), self.now);
                    }
                    None => return moved,
                }
            }
        }
    }
}

fn write_all(c: &mut Conn, id: u64, data: &[u8]) -> usize {
    let w = std::task::Waker::noop();
    let mut cx = Context::from_waker(w);
    match c.stream_write(id, &mut cx, data) {
        Poll::Ready(Ok(n)) => n,
        other => panic!("{other:?}"),
    }
}

fn read_all(c: &mut Conn, id: u64) -> Vec<u8> {
    let w = std::task::Waker::noop();
    let mut cx = Context::from_waker(w);
    let mut out = Vec::new();
    loop {
        let mut buf = [0u8; 4096];
        let mut rb = tokio::io::ReadBuf::new(&mut buf);
        match c.stream_read(id, &mut cx, &mut rb) {
            Poll::Ready(Ok(())) if rb.filled().is_empty() => return out,
            Poll::Ready(Ok(())) => out.extend_from_slice(rb.filled()),
            Poll::Pending => return out,
            Poll::Ready(Err(e)) => panic!("{e}"),
        }
    }
}

#[test]
fn establishes_with_proofs_and_first_rekey() {
    let mut p = pair();
    assert!(!p.a.established && !p.b.established);
    // The responder sends nothing before the initiator's first packet.
    assert!(p.b.poll_transmit(p.now).is_none());
    p.pump();
    assert!(p.a.established, "initiator established");
    assert!(p.b.established, "responder established");
    assert_eq!(p.a.stats().rekeys, 1);
    assert_eq!(p.b.stats().rekeys, 1);
    assert_eq!(p.a.key_phase(), 1);
    assert_eq!(p.b.key_phase(), 1);
    assert_eq!(p.a.peer_identity.unwrap().identity, [0xbb; 32]);
    assert_eq!(p.b.peer_identity.unwrap().identity, [0xaa; 32]);
    assert!(p.b.peer_identity.unwrap().verified_by_log);
    let ev = p.b.drain_events();
    assert!(matches!(ev[0], ConnEvent::Confirmed { counter: 10 }));
    assert!(ev.iter().any(|e| matches!(e, ConnEvent::Established)));
}

#[test]
fn proof_comes_first_then_rekey() {
    let mut p = pair();
    let (_, first) = p.a.poll_transmit(p.now).unwrap();
    let (_, second) = p.a.poll_transmit(p.now).unwrap();
    let mut first = first.to_vec();
    let mut second = second.to_vec();
    // Decrypt with the responder to look at the frames.
    let r1 = p.b.recv_cur.open(0, &mut first).unwrap();
    let f1 = decode_frames(&first[r1]).unwrap();
    assert!(matches!(f1[0], Frame::DeviceProof(Some(_))));
    let r2 = p.b.recv_cur.open(1, &mut second).unwrap();
    let f2 = decode_frames(&second[r2]).unwrap();
    assert!(matches!(f2[0], Frame::Rekey(_)));
    assert!(
        second.len() > packet::DATA_MAX_LEN,
        "rekey packet is oversized"
    );
    assert!(second.len() + 16 <= DATA_MAX_LEN_REKEY + 16);
}

#[test]
fn stream_transfer_and_flow_control() {
    let mut p = pair();
    p.pump();
    let id =
        p.a.open_stream(Service::SYNC, Priority::Background)
            .unwrap();
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i * 7) as u8).collect();
    let mut sent = 0;
    let mut got = Vec::new();
    let mut bid = None;
    let mut rounds = 0;
    while got.len() < data.len() {
        rounds += 1;
        assert!(rounds < 10_000);
        if sent < data.len() {
            sent += write_all(&mut p.a, id, &data[sent..]);
            if sent == data.len() {
                p.a.stream_finish(id);
            }
        }
        // Only up to the windows can be in flight before the reader reads.
        p.pump();
        if bid.is_none() {
            if let Some((i, svc, pri)) = p.b.accept_stream() {
                assert_eq!(svc, Service::SYNC);
                assert_eq!(pri, Priority::Background);
                bid = Some(i);
            }
        }
        if let Some(i) = bid {
            assert!(p.b.streams[&i].recv_highest - p.b.streams[&i].recv_read <= STREAM_WINDOW);
            got.extend(read_all(&mut p.b, i));
        }
    }
    assert_eq!(got, data);
}

#[test]
fn tampered_packets_are_dropped() {
    let mut p = pair();
    p.pump();
    let id =
        p.a.open_stream(Service::BLOB, Priority::Interactive)
            .unwrap();
    write_all(&mut p.a, id, b"hello");
    let (_, pkt) = p.a.poll_transmit(p.now).unwrap();
    for i in [0usize, 1, 5, 9, 20, pkt.len() - 1] {
        let mut v = pkt.to_vec();
        v[i] ^= 0x40;
        assert!(!p.b.recv_packet(&mut v, &Path::Mem(2), p.now), "byte {i}");
    }
    let dropped = p.b.stats().packets_dropped;
    assert!(dropped >= 5);
    let mut v = pkt.to_vec();
    assert!(p.b.recv_packet(&mut v, &Path::Mem(2), p.now));
}

#[test]
fn replayed_packets_are_dropped() {
    let mut p = pair();
    p.pump();
    p.a.control.push_back(Frame::Ping);
    let (_, pkt) = p.a.poll_transmit(p.now).unwrap();
    let mut v = pkt.to_vec();
    assert!(p.b.recv_packet(&mut v, &Path::Mem(2), p.now));
    let mut v = pkt.to_vec();
    assert!(!p.b.recv_packet(&mut v, &Path::Mem(2), p.now));
    // Reordering within the window is fine; far behind it is not.
    let mut held = Vec::new();
    for _ in 0..3 {
        p.a.control.push_back(Frame::Ping);
        held.push(p.a.poll_transmit(p.now).unwrap().1);
    }
    for pkt in held.iter().rev() {
        let mut v = pkt.to_vec();
        assert!(p.b.recv_packet(&mut v, &Path::Mem(2), p.now));
    }
    let old = held[0].clone();
    for _ in 0..crate::keys::REPLAY_WINDOW + 5 {
        p.a.control.push_back(Frame::Padding(vec![]));
        let (_, pkt) = p.a.poll_transmit(p.now).unwrap();
        let mut v = pkt.to_vec();
        p.b.recv_packet(&mut v, &Path::Mem(2), p.now);
    }
    let mut v = old.to_vec();
    assert!(!p.b.recv_packet(&mut v, &Path::Mem(2), p.now));
}

#[test]
fn periodic_rekey_switches_phase_and_keeps_data_flowing() {
    let config = SessionConfig {
        rekey_interval: Duration::from_secs(1),
        ..SessionConfig::default()
    };
    let (ia, ib) = ids();
    let mut p = pair_with(config, Some(ia), Some(ib), Admission::Known);
    p.pump();
    let id =
        p.a.open_stream(Service::SYNC, Priority::Background)
            .unwrap();
    let mut expected = Vec::new();
    let mut got = Vec::new();
    let mut bid = None;
    for round in 0..6u8 {
        let chunk = vec![round; 5000];
        write_all(&mut p.a, id, &chunk);
        expected.extend_from_slice(&chunk);
        p.pump();
        if bid.is_none() {
            bid = p.b.accept_stream().map(|x| x.0);
        }
        got.extend(read_all(&mut p.b, bid.unwrap()));
        // Hold a packet sealed in the current phase for later.
        p.now += Duration::from_millis(1100);
        p.a.handle_timeout(p.now);
        p.pump();
    }
    assert_eq!(got, expected);
    assert_eq!(p.a.stats().rekeys, 7);
    assert_eq!(p.b.stats().rekeys, 7);
    assert_eq!(p.a.key_phase(), p.b.key_phase());
    assert_eq!(*p.a.ck, *p.b.ck);
}

#[test]
fn previous_phase_accepted_for_five_seconds() {
    let config = SessionConfig {
        rekey_interval: Duration::from_secs(1),
        ..SessionConfig::default()
    };
    let (ia, ib) = ids();
    let mut p = pair_with(config, Some(ia), Some(ib), Admission::Known);
    p.pump();
    // Two packets from the responder in the current phase, delivered late.
    p.b.control.push_back(Frame::Ping);
    let (_, late1) = p.b.poll_transmit(p.now).unwrap();
    p.b.control.push_back(Frame::Ping);
    let (_, late2) = p.b.poll_transmit(p.now).unwrap();
    p.now += Duration::from_millis(1100);
    p.a.handle_timeout(p.now);
    p.pump();
    assert_eq!(p.a.stats().rekeys, 2);
    assert_ne!(late1[1], p.a.key_phase());
    let mut v = late1.to_vec();
    assert!(
        p.a.recv_packet(&mut v, &Path::Mem(1), p.now),
        "accepted within 5 s"
    );
    p.now += Duration::from_secs(6);
    let mut v = late2.to_vec();
    assert!(
        !p.a.recv_packet(&mut v, &Path::Mem(1), p.now),
        "refused after 5 s"
    );
}

#[test]
fn data_before_proofs_is_refused() {
    let mut p = pair();
    // Hand-build a packet with a stream frame from the initiator before
    // anything else.
    let frames = [Frame::Stream(StreamFrame {
        id: 1,
        offset: 0,
        data: Bytes::from_static(b"early"),
        fin: false,
        service: Some(Service::SYNC),
        priority: None,
    })];
    let pkt = p.a.seal_frames(&frames, p.now);
    let mut v = pkt.to_vec();
    p.b.recv_packet(&mut v, &Path::Mem(2), p.now);
    assert!(
        p.b.is_closed(),
        "a reliable carrier never reorders, so this is a violation"
    );
}

#[test]
fn bad_device_proof_closes() {
    // The responder's directory does not list the initiator's identity.
    let (ia, ib) = ids();
    let stranger = LocalIdentity {
        identity: [0xcc; 32],
        signing_key: Arc::new(SigningKey::from_seed(&[9; 32])),
    };
    let mut p = pair_with(
        SessionConfig::default(),
        Some(ia),
        Some(ib),
        Admission::Known,
    );
    p.a.local_identity = Some(stranger);
    p.a.control.clear();
    let proof = p.a.own_proof();
    p.a.control.push_back(proof);
    p.a.start_rekey(p.now);
    p.pump();
    assert!(matches!(p.b.close, Some(CloseReason::Identity)));
    assert!(!p.a.established);
}

#[test]
fn empty_proof_only_with_secret() {
    let (_, ib) = ids();
    let p_known = {
        let mut p = pair_with(
            SessionConfig::default(),
            None,
            Some(ib.clone()),
            Admission::Known,
        );
        p.pump();
        p
    };
    assert!(matches!(p_known.b.close, Some(CloseReason::Identity)));
    let mut p = pair_with(
        SessionConfig::default(),
        None,
        Some(ib),
        Admission::Secret {
            id: 1,
            expected: ExpectedPeer::default(),
        },
    );
    p.pump();
    assert!(p.b.established);
    assert!(p.b.peer_identity.is_none());
}

#[test]
fn datagrams_and_priority_order() {
    let mut p = pair();
    p.pump();
    let bg =
        p.a.open_stream(Service::SYNC, Priority::Background)
            .unwrap();
    write_all(&mut p.a, bg, &vec![1u8; 100_000]);
    let mut rx = p.b.subscribe([7; 16], Priority::RealTime);
    p.a.send_datagram([7; 16], Priority::RealTime, Bytes::from_static(b"voice"))
        .unwrap();
    // The very next packet carries the real-time datagram ahead of the
    // background stream.
    let (_, pkt) = p.a.poll_transmit(p.now).unwrap();
    let mut v = pkt.to_vec();
    let r = p.b.recv_cur.open(packet::read_u64(&v, 8), &mut v.clone());
    assert!(r.is_some());
    let mut copy = pkt.to_vec();
    let rng =
        p.b.recv_cur
            .open(packet::read_u64(&copy, 8), &mut copy)
            .unwrap();
    let frames = decode_frames(&copy[rng]).unwrap();
    let pos_dgram = frames
        .iter()
        .position(|f| matches!(f, Frame::Datagram { .. }))
        .unwrap();
    if let Some(pos_stream) = frames.iter().position(|f| matches!(f, Frame::Stream(_))) {
        assert!(pos_dgram < pos_stream);
    }
    p.b.recv_packet(&mut v, &Path::Mem(2), p.now);
    assert_eq!(rx.try_recv().unwrap(), Bytes::from_static(b"voice"));
}

#[test]
fn reset_and_close() {
    let mut p = pair();
    p.pump();
    let id =
        p.a.open_stream(Service::SYNC, Priority::Interactive)
            .unwrap();
    write_all(&mut p.a, id, b"abc");
    p.pump();
    let (bid, _, _) = p.b.accept_stream().unwrap();
    p.a.stream_reset(id, 7);
    p.pump();
    assert_eq!(p.b.streams.get(&bid).and_then(|s| s.reset_remote), Some(7));
    p.a.close_local(CloseReason::Local("done".into()));
    p.pump();
    assert_eq!(p.b.close, Some(CloseReason::Remote("done".into())));
}

#[test]
fn path_challenge_moves_session() {
    let mut p = pair();
    p.pump();
    p.a.control.push_back(Frame::Ping);
    let (_, pkt) = p.a.poll_transmit(p.now).unwrap();
    let mut v = pkt.to_vec();
    // Arrives from a new address.
    assert!(p.b.recv_packet(&mut v, &Path::Mem(99), p.now));
    assert!(p.b.path.same(&Path::Mem(2)), "not moved before validation");
    let (to, chal) = p.b.poll_transmit(p.now).unwrap();
    assert!(to.same(&Path::Mem(99)));
    let mut v = chal.to_vec();
    p.a.recv_packet(&mut v, &Path::Mem(1), p.now);
    let (to, resp) = p.a.poll_transmit(p.now).unwrap();
    assert!(to.same(&Path::Mem(1)));
    let mut v = resp.to_vec();
    p.b.recv_packet(&mut v, &Path::Mem(99), p.now);
    assert!(p.b.path.same(&Path::Mem(99)), "moved after validation");
}

#[test]
#[ignore]
fn micro_costs() {
    let n = 100_000;
    let k = DirKey::new(&[1; 32], 0);
    let mut buf = vec![0u8; 1200];
    let t = std::time::Instant::now();
    for i in 0..n {
        k.seal(1, i, &mut buf);
    }
    println!(
        "seal: {:.2} us/packet",
        t.elapsed().as_secs_f64() * 1e6 / n as f64
    );
    for size in [64usize, 256, 1200, 16384] {
        let mut buf = vec![0u8; size];
        let t = std::time::Instant::now();
        for i in 0..10_000u64 {
            k.seal(1, i, &mut buf);
        }
        println!(
            "seal {size}: {:.2} us",
            t.elapsed().as_secs_f64() * 1e6 / 10_000.0
        );
        let key = [1u8; 32];
        let t = std::time::Instant::now();
        for _ in 0..10_000u64 {
            std::hint::black_box(cardinal_crypto::aead::chacha20poly1305_encrypt(
                &key,
                &[0; 12],
                &[],
                &buf,
            ));
        }
        println!(
            "crypto crate {size}: {:.2} us",
            t.elapsed().as_secs_f64() * 1e6 / 10_000.0
        );
        let t = std::time::Instant::now();
        for _ in 0..10_000u64 {
            std::hint::black_box(blake3::hash(&buf));
        }
        println!(
            "blake3 {size}: {:.2} us",
            t.elapsed().as_secs_f64() * 1e6 / 10_000.0
        );
    }
    let mut frame = Vec::new();
    encode_stream_frame(&mut frame, 1, 1 << 30, &[7u8; 1150], false, None, None);
    let t = std::time::Instant::now();
    for _ in 0..n {
        std::hint::black_box(decode_frames(&frame).unwrap());
    }
    println!(
        "decode: {:.2} us/frame",
        t.elapsed().as_secs_f64() * 1e6 / n as f64
    );
    let mut d: VecDeque<u8> = VecDeque::new();
    let data = vec![1u8; 256 * 1024];
    let t = std::time::Instant::now();
    for _ in 0..1000 {
        d.extend(&data[..]);
        while d.len() > 1150 {
            std::hint::black_box(copy_range(&d, 0, 1150));
            d.drain(..1150);
        }
    }
    println!(
        "deque: {:.2} MB/s",
        256.0 * 1024.0 * 1000.0 / t.elapsed().as_secs_f64() / 1e6
    );
}

/// Speed of the core alone, without carriers or tasks.
#[test]
#[ignore]
fn core_throughput() {
    let mut p = pair();
    p.pump();
    let id =
        p.a.open_stream(Service::BLOB, Priority::Background)
            .unwrap();
    let chunk = vec![0x5au8; 256 * 1024];
    let total = 256 * 1024 * 1024usize;
    let start = std::time::Instant::now();
    let mut sent = 0;
    let mut got = 0;
    let mut bid = None;
    while got < total {
        if sent < total {
            sent += write_all(&mut p.a, id, &chunk[..(total - sent).min(chunk.len())]);
        }
        while let Some((_, pkt)) = p.a.poll_transmit(p.now) {
            let mut v = pkt.to_vec();
            p.b.recv_packet(&mut v, &Path::Mem(2), p.now);
        }
        if bid.is_none() {
            bid = p.b.accept_stream().map(|x| x.0);
        }
        if let Some(i) = bid {
            got += read_all(&mut p.b, i).len();
        }
        while let Some((_, pkt)) = p.b.poll_transmit(p.now) {
            let mut v = pkt.to_vec();
            p.a.recv_packet(&mut v, &Path::Mem(1), p.now);
        }
    }
    let secs = start.elapsed().as_secs_f64();
    println!("core: {:.1} MB/s", total as f64 / secs / 1e6);
}
