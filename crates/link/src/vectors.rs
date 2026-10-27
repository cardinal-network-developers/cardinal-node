//! Generates and checks `vectors/link.json`: handshakes with fixed
//! randomness, a data packet, a rekey, and a cookie reply.
//!
//! Run `CARDINAL_WRITE_VECTORS=1 cargo test -p cardinal-link vectors` to
//! rewrite the file after an intentional change.

use cardinal_crypto::kem::KemSecretKey;
use cardinal_crypto::{HybridKeyPair, KemPublicKey, SigningKey};
use serde_json::{json, Value as Json};

use crate::frame::{encode_frames, DeviceProof, Frame, DEVICE_PROOF_DOMAIN};
use crate::handshake::{
    finish_initiation, initiate, receive_initiation, rekey, respond, secret_hint, InitiationParams,
};
use crate::keys::DirKey;
use crate::packet::{self, init, resp};

fn fixed(label: &str, n: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(b"cardinal test vector ");
    h.update(label.as_bytes());
    let mut out = vec![0u8; n];
    h.finalize_xof().fill(&mut out);
    out
}

fn fixed32(label: &str) -> [u8; 32] {
    fixed(label, 32).try_into().unwrap()
}

fn hx(b: impl AsRef<[u8]>) -> String {
    hex::encode(b)
}

fn check_or_write(name: &str, value: Json) {
    let text = serde_json::to_string_pretty(&value).unwrap() + "\n";
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(name);
    if std::env::var_os("CARDINAL_WRITE_VECTORS").is_some() {
        std::fs::write(&path, text).unwrap();
        return;
    }
    let existing = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; run with CARDINAL_WRITE_VECTORS=1", path.display()));
    assert!(
        existing == text,
        "{} is out of date with the implementation",
        path.display()
    );
}

struct Case {
    name: &'static str,
    secret: Option<Vec<u8>>,
    initiation_kem: bool,
    response_kem: bool,
}

fn handshake_case(c: &Case) -> Json {
    let i = HybridKeyPair::from_seed(&fixed32("link initiator static seed"));
    let r = HybridKeyPair::from_seed(&fixed32("link responder static seed"));
    let e = fixed32("link initiator ephemeral");
    let f = fixed32("link responder ephemeral");
    let m1 = fixed32("link initiation encapsulation m");
    let m2 = fixed32("link response encapsulation m");
    let random_hint: [u8; 3] = fixed("link random hint", 3).try_into().unwrap();
    let counter = 1_767_225_600_000u64; // 2026-01-01 in milliseconds.
    let (si, sr) = (0x0102_0304u32, 0x0a0b_0c0du32);
    let p = InitiationParams {
        local: &i,
        remote_x25519: *r.public_key().x25519(),
        remote_kem: c.initiation_kem.then(|| r.public_key().kem()),
        secret: c.secret.as_deref(),
        counter,
        sender_index: si,
    };
    let pending = initiate(&p, &e, random_hint, |k| k.encapsulate_deterministic(&m1)).unwrap();
    let initiation = *pending.packet();
    assert!(packet::check_mac1(
        &initiation,
        init::MAC1,
        &packet::mac1_key(r.public_key().x25519())
    ));
    let secrets: Vec<&[u8]> = c.secret.iter().map(|s| &s[..]).collect();
    let ipub = *i.public_key().x25519();
    let recv = receive_initiation(&r, &initiation, |k| *k == ipub, &secrets, false).unwrap();
    let (rkeys, response) = respond(
        recv,
        c.response_kem.then(|| i.public_key().kem()),
        sr,
        &f,
        |k| k.encapsulate_deterministic(&m2),
    )
    .unwrap();
    let done = finish_initiation(pending, &i, &response[..]).unwrap();
    assert_eq!(done.keys.h, rkeys.h);
    assert_eq!(
        *done.keys.initiator_to_responder,
        *rkeys.initiator_to_responder
    );
    let mut j = json!({
        "name": c.name,
        "counter": counter,
        "initiator_sender_index": si,
        "responder_sender_index": sr,
        "initiator_ephemeral_private": hx(e),
        "responder_ephemeral_private": hx(f),
        "initiation_kem_m": if c.initiation_kem { Json::from(hx(m1)) } else { Json::Null },
        "response_kem_m": if c.response_kem { Json::from(hx(m2)) } else { Json::Null },
        "random_hint": hx(random_hint),
        "initiation": hx(initiation),
        "response": hx(&response[..]),
        "h": hx(done.keys.h),
        "ck": hx(*done.keys.ck),
        "initiator_to_responder_key": hx(*done.keys.initiator_to_responder),
        "responder_to_initiator_key": hx(*done.keys.responder_to_initiator),
    });
    if let Some(s) = &c.secret {
        j["secret"] = Json::from(hx(s));
        j["secret_hint_unmasked"] = Json::from(hx(secret_hint(s)));
    }
    j
}

#[test]
fn link_vectors() {
    let i = HybridKeyPair::from_seed(&fixed32("link initiator static seed"));
    let r = HybridKeyPair::from_seed(&fixed32("link responder static seed"));
    let cases = [
        Case {
            name: "known devices, no secret",
            secret: None,
            initiation_kem: true,
            response_kem: true,
        },
        Case {
            name: "secret (a token-derived secret toward a host)",
            secret: Some(fixed("link token secret", 32)),
            initiation_kem: true,
            response_kem: true,
        },
        Case {
            name: "invitation: no ML-KEM key for the responder, initiator unknown to it",
            secret: Some(fixed("link invitation secret", 16)),
            initiation_kem: false,
            response_kem: false,
        },
    ];
    let handshakes: Vec<Json> = cases.iter().map(handshake_case).collect();

    // A first data packet: the initiator's device proof, counter 0, phase 0.
    let k_i2r: [u8; 32] = hex::decode(
        handshakes[0]["initiator_to_responder_key"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let h: [u8; 32] = hex::decode(handshakes[0]["h"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let signer = SigningKey::from_seed(&fixed32("link device signing seed"));
    let identity = fixed32("link identity id");
    let mut msg = DEVICE_PROOF_DOMAIN.to_vec();
    msg.extend_from_slice(&h);
    let proof = Frame::DeviceProof(Some(DeviceProof {
        identity,
        signing_key: signer.public_key(),
        signature: signer.sign(&msg),
    }));
    let plaintext = encode_frames(&[proof]);
    let mut pkt = vec![0u8; 16];
    pkt.extend_from_slice(&plaintext);
    pkt.extend_from_slice(&[0u8; 16]);
    DirKey::new(&k_i2r, 0).seal(0x0a0b_0c0d, 0, &mut pkt);

    // A rekey: the initiator's ephemeral ML-KEM key from a fixed seed, the
    // responder's encapsulation randomness fixed.
    let ck: [u8; 32] = hex::decode(handshakes[0]["ck"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let kem_seed: [u8; 64] = fixed("link rekey ML-KEM seed", 64).try_into().unwrap();
    let kem = KemSecretKey::from_seed(&kem_seed);
    let pk = kem.public_key().as_bytes().to_vec();
    let m = fixed32("link rekey encapsulation m");
    let (ct, ss) = KemPublicKey::from_bytes(&pk)
        .unwrap()
        .encapsulate_deterministic(&m);
    assert_eq!(*kem.decapsulate(&ct).unwrap(), *ss);
    let (i2r, r2i, ck2) = rekey(&ck, &ss);
    let rekey_frame = encode_frames(&[Frame::Rekey(pk.clone())]);
    let reply_frame = encode_frames(&[Frame::RekeyReply(ct.to_vec())]);

    // A cookie reply and the retransmitted initiation's mac2.
    let initiation = hex::decode(handshakes[0]["initiation"].as_str().unwrap()).unwrap();
    let cookie_secret = fixed32("link cookie rotating secret");
    let source: std::net::SocketAddr = "192.0.2.7:51820".parse().unwrap();
    let cookie = packet::make_cookie(&cookie_secret, &source);
    let nonce: [u8; 24] = fixed("link cookie nonce", 24).try_into().unwrap();
    let reply = packet::cookie_reply(
        r.public_key().x25519(),
        0x0102_0304,
        &initiation[init::MAC1..init::MAC2],
        &cookie,
        &nonce,
    );
    let mac2 = packet::mac2(&cookie, &initiation[..init::MAC2]);
    let _ = resp::MAC1;

    check_or_write(
        "link.json",
        json!({
            "description": "Link handshake (link.md#handshake) with fixed randomness. Static link keys are HybridKeyPair::from_seed(seed) (crypto.md#hybrid-public-keys). Ephemeral X25519 private keys are given; ML-KEM encapsulations use ML-KEM.Encaps_internal with the given m. Packets are hex. The hint is masked with first3(keyed_hash(ck, \"hint\")) when a secret is used, else the given random bytes. Integers are little-endian. mac2 is zero in handshakes; the cookie section shows a cookie reply (type 3, 3 zero bytes, receiver index, 24-byte nonce, XChaCha20-Poly1305 of the 16-byte cookie under H(\"cardinal 1 cookie\" || responder static) with the initiation's mac1 as associated data) and the mac2 of the first initiation under that cookie (the cookie zero-padded to a 32-byte BLAKE3 key).",
            "initiator_static_seed": hx(fixed32("link initiator static seed")),
            "responder_static_seed": hx(fixed32("link responder static seed")),
            "initiator_link_key": hx(i.public_key().encode()),
            "responder_link_key": hx(r.public_key().encode()),
            "handshakes": handshakes,
            "data_packet": {
                "description": "The initiator's first data packet of the first handshake: one device proof frame, counter 0, phase 0, receiver index = responder's index.",
                "device_signing_seed": hx(fixed32("link device signing seed")),
                "identity": hx(identity),
                "plaintext": hx(&plaintext),
                "packet": hx(&pkt),
            },
            "rekey": {
                "description": "Rekey after the first handshake: ck from it, the initiator's ephemeral ML-KEM key from the given seed (d || z), encapsulation randomness m. New keys = derive(\"rekey\", ck || ss) split 32/32; new ck = first32(derive(\"rekey\", ck || ss || \"ck\")).",
                "ck": hx(ck),
                "kem_seed": hx(kem_seed),
                "encapsulation_m": hx(m),
                "rekey_frame": hx(&rekey_frame),
                "rekey_reply_frame": hx(&reply_frame),
                "shared_secret": hx(*ss),
                "initiator_to_responder_key": hx(*i2r),
                "responder_to_initiator_key": hx(*r2i),
                "new_ck": hx(*ck2),
            },
            "cookie": {
                "rotating_secret": hx(cookie_secret),
                "source": source.to_string(),
                "source_bytes": hx([192u8, 0, 2, 7, 0x6c, 0xca]),
                "cookie": hx(cookie),
                "nonce": hx(nonce),
                "cookie_reply": hx(reply),
                "initiation_mac2": hx(mac2),
            },
        }),
    );
}
