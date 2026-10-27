//! The handshake (`link.md#handshake`): Noise IK with an ML-KEM step and an
//! optional secret, written out without the Noise framework.
//!
//! These functions are pure: every random input is an argument, so the
//! handshake can be reproduced from fixed values (`vectors/link.json`). The
//! [`Endpoint`](crate::Endpoint) supplies fresh randomness.

use cardinal_crypto::aead::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};
use cardinal_crypto::kem::CIPHERTEXT_LEN;
use cardinal_crypto::x25519::is_all_zero;
use cardinal_crypto::{
    derive_into_parts, hash, keyed_hash, HybridKeyPair, KemPublicKey, Purpose, X25519Secret,
};
use zeroize::Zeroizing;

use crate::packet::{self, init, resp, INITIATION_LEN, RESPONSE_LEN};

/// The protocol label hashed into the initial chaining key.
pub const LABEL: &[u8] = b"cardinal 1 handshake";

/// Why a handshake message was rejected. Rejections are silent on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeError {
    /// Wrong length or type.
    Malformed,
    /// An AEAD tag did not verify.
    Decrypt,
    /// A Diffie-Hellman result was all zeros (a low-order point).
    LowOrder,
    /// The static key is not accepted and no secret matched.
    Rejected,
}

/// An ML-KEM encapsulation: `(ciphertext, shared secret)`.
pub type Encapsulation = ([u8; CIPHERTEXT_LEN], Zeroizing<[u8; 32]>);

/// The Noise symmetric state: chaining key, handshake hash, and the current
/// encryption key.
#[derive(Clone)]
pub(crate) struct SymmetricState {
    ck: Zeroizing<[u8; 32]>,
    h: [u8; 32],
    k: Option<Zeroizing<[u8; 32]>>,
}

impl SymmetricState {
    fn new() -> SymmetricState {
        let ck = hash(LABEL);
        SymmetricState {
            ck: Zeroizing::new(ck),
            h: ck,
            k: None,
        }
    }

    /// `h = H(h || x)`.
    fn mix_hash(&mut self, x: &[u8]) {
        self.h = cardinal_crypto::hash_parts(&[&self.h, x]);
    }

    /// `o = 64 bytes of derive("handshake", ck || x)`; `ck = o[..32]`,
    /// `k = o[32..]`.
    fn mix_key(&mut self, x: &[u8]) {
        let mut o = Zeroizing::new([0u8; 64]);
        derive_into_parts(Purpose::Handshake, &[&self.ck[..], x], &mut o[..]);
        self.ck.copy_from_slice(&o[..32]);
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&o[32..]);
        self.k = Some(k);
    }

    /// `c = ChaCha20-Poly1305(k, 0, h, p)`; `MixHash(c)`. Each `k`
    /// encrypts at most once.
    fn encrypt(&mut self, p: &[u8]) -> Vec<u8> {
        let k = self.k.take().expect("MixKey before Encrypt");
        let c = chacha20poly1305_encrypt(&k, &[0u8; 12], &self.h, p);
        self.mix_hash(&c);
        c
    }

    fn decrypt(&mut self, c: &[u8]) -> Result<Zeroizing<Vec<u8>>, HandshakeError> {
        let k = self.k.take().ok_or(HandshakeError::Decrypt)?;
        let p = chacha20poly1305_decrypt(&k, &[0u8; 12], &self.h, c)
            .map_err(|_| HandshakeError::Decrypt)?;
        self.mix_hash(c);
        Ok(Zeroizing::new(p))
    }

    fn mix_dh(&mut self, secret: &X25519Secret, public: &[u8; 32]) -> Result<(), HandshakeError> {
        let shared = secret.diffie_hellman(public);
        if is_all_zero(&shared) {
            return Err(HandshakeError::LowOrder);
        }
        self.mix_key(&shared[..]);
        Ok(())
    }

    /// The mask of the secret hint: `first3(keyed_hash(ck, "hint"))`.
    fn hint_mask(&self) -> [u8; 3] {
        keyed_hash(&self.ck, b"hint")[..3]
            .try_into()
            .expect("3 bytes")
    }

    fn split(&self) -> Keys {
        let mut o = Zeroizing::new([0u8; 64]);
        derive_into_parts(Purpose::Handshake, &[&self.ck[..], b"split"], &mut o[..]);
        let mut i2r = Zeroizing::new([0u8; 32]);
        let mut r2i = Zeroizing::new([0u8; 32]);
        i2r.copy_from_slice(&o[..32]);
        r2i.copy_from_slice(&o[32..]);
        Keys {
            ck: self.ck.clone(),
            h: self.h,
            initiator_to_responder: i2r,
            responder_to_initiator: r2i,
        }
    }
}

/// `first3(H(p))`, the unmasked hint of a secret.
pub fn secret_hint(secret: &[u8]) -> [u8; 3] {
    hash(secret)[..3].try_into().expect("3 bytes")
}

/// The result of a completed handshake.
#[derive(Clone)]
pub struct Keys {
    /// The final chaining key (input to the rekey).
    pub ck: Zeroizing<[u8; 32]>,
    /// The handshake hash after the response (signed by `device proof`).
    pub h: [u8; 32],
    /// The initiator-to-responder transport key.
    pub initiator_to_responder: Zeroizing<[u8; 32]>,
    /// The responder-to-initiator transport key.
    pub responder_to_initiator: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys").finish_non_exhaustive()
    }
}

/// What the initiator needs to build an initiation.
pub struct InitiationParams<'a> {
    /// The initiator's link key pair.
    pub local: &'a HybridKeyPair,
    /// The responder's X25519 static key.
    pub remote_x25519: [u8; 32],
    /// The responder's ML-KEM key, unless connecting with an invitation.
    pub remote_kem: Option<&'a KemPublicKey>,
    /// The secret of step 5, if any.
    pub secret: Option<&'a [u8]>,
    /// The counter.
    pub counter: u64,
    /// The initiator's index for this session.
    pub sender_index: u32,
}

/// The initiator's state between initiation and response.
pub struct PendingInitiation {
    state: SymmetricState,
    ephemeral: X25519Secret,
    remote_x25519: [u8; 32],
    sender_index: u32,
    packet: Box<[u8; INITIATION_LEN]>,
}

impl PendingInitiation {
    /// The initiation packet (mac2 zero unless a cookie was applied).
    pub fn packet(&self) -> &[u8; INITIATION_LEN] {
        &self.packet
    }

    /// The sender index.
    pub fn sender_index(&self) -> u32 {
        self.sender_index
    }

    /// The responder's static key.
    pub fn remote_x25519(&self) -> &[u8; 32] {
        &self.remote_x25519
    }

    /// The initiation's mac1, the associated data of a cookie reply.
    pub fn mac1(&self) -> [u8; 16] {
        self.packet[init::MAC1..init::MAC2]
            .try_into()
            .expect("16 bytes")
    }

    /// Recomputes mac2 with a cookie received in a cookie reply.
    pub fn apply_cookie(&mut self, cookie: &[u8; 16]) {
        let m = packet::mac2(cookie, &self.packet[..init::MAC2]);
        self.packet[init::MAC2..].copy_from_slice(&m);
    }
}

/// Builds an initiation (initiator steps 1–7).
///
/// `ephemeral` is the ephemeral private key, `random_hint` the hint used
/// when there is no secret, and `encaps` performs the ML-KEM encapsulation.
pub fn initiate(
    p: &InitiationParams<'_>,
    ephemeral: &[u8; 32],
    random_hint: [u8; 3],
    encaps: impl FnOnce(&KemPublicKey) -> Encapsulation,
) -> Result<PendingInitiation, HandshakeError> {
    let mut s = SymmetricState::new();
    let counter = p.counter.to_le_bytes();
    // 1.
    s.mix_hash(&p.remote_x25519);
    s.mix_hash(&counter);
    // 2.
    let e = X25519Secret::from_bytes(ephemeral);
    let e_pub = e.public_key();
    s.mix_hash(&e_pub);
    // 3.
    let mut ct = [0u8; CIPHERTEXT_LEN];
    if let Some(kem) = p.remote_kem {
        let (c, ss) = encaps(kem);
        ct = c;
        s.mix_hash(&ct);
        s.mix_key(&ss[..]);
    }
    // 4.
    s.mix_dh(&e, &p.remote_x25519)?;
    let hint = match p.secret {
        Some(secret) => xor3(secret_hint(secret), s.hint_mask()),
        None => random_hint,
    };
    // 5.
    if let Some(secret) = p.secret {
        s.mix_key(secret);
    }
    // 6.
    let enc_static = s.encrypt(&p.local.public_key().x25519()[..]);
    // 7.
    s.mix_dh(p.local.x25519(), &p.remote_x25519)?;

    let mut pkt = Box::new([0u8; INITIATION_LEN]);
    pkt[0] = packet::TYPE_INITIATION;
    pkt[init::HINT..init::HINT + 3].copy_from_slice(&hint);
    pkt[init::SENDER..init::SENDER + 4].copy_from_slice(&p.sender_index.to_le_bytes());
    pkt[init::COUNTER..init::COUNTER + 8].copy_from_slice(&counter);
    pkt[init::EPHEMERAL..init::EPHEMERAL + 32].copy_from_slice(&e_pub);
    pkt[init::KEM_CT..init::STATIC].copy_from_slice(&ct);
    pkt[init::STATIC..init::MAC1].copy_from_slice(&enc_static);
    packet::seal_macs(
        &mut pkt[..],
        init::MAC1,
        &packet::mac1_key(&p.remote_x25519),
        None,
    );
    Ok(PendingInitiation {
        state: s,
        ephemeral: e,
        remote_x25519: p.remote_x25519,
        sender_index: p.sender_index,
        packet: pkt,
    })
}

/// The outcome of the initiator's processing of a response.
#[derive(Debug)]
pub struct InitiatorDone {
    /// Transport keys and handshake hash.
    pub keys: Keys,
    /// The responder's index.
    pub remote_index: u32,
    /// Whether the responder encapsulated to the initiator's ML-KEM key.
    pub response_kem: bool,
}

/// Processes a response (the initiator's mirror of responder steps 1–5).
/// mac1 must already have been checked.
pub fn finish_initiation(
    pending: PendingInitiation,
    local: &HybridKeyPair,
    packet: &[u8],
) -> Result<InitiatorDone, HandshakeError> {
    if packet.len() != RESPONSE_LEN || packet[0] != packet::TYPE_RESPONSE {
        return Err(HandshakeError::Malformed);
    }
    if packet::read_u32(packet, resp::RECEIVER) != pending.sender_index {
        return Err(HandshakeError::Malformed);
    }
    let mut s = pending.state;
    let f: [u8; 32] = packet[resp::EPHEMERAL..resp::EPHEMERAL + 32]
        .try_into()
        .expect("32 bytes");
    s.mix_hash(&f);
    s.mix_dh(&pending.ephemeral, &f)?;
    s.mix_dh(local.x25519(), &f)?;
    let ct = &packet[resp::KEM_CT..resp::EMPTY];
    let response_kem = ct.iter().any(|&b| b != 0);
    if response_kem {
        let ss = local
            .kem()
            .decapsulate(ct)
            .map_err(|_| HandshakeError::Decrypt)?;
        s.mix_hash(ct);
        s.mix_key(&ss[..]);
    }
    let empty = s.decrypt(&packet[resp::EMPTY..resp::MAC1])?;
    if !empty.is_empty() {
        return Err(HandshakeError::Malformed);
    }
    Ok(InitiatorDone {
        keys: s.split(),
        remote_index: packet::read_u32(packet, resp::SENDER),
        response_kem,
    })
}

/// A decrypted initiation, before the responder replies.
pub struct ReceivedInitiation {
    state: SymmetricState,
    /// The initiator's X25519 static key.
    pub initiator_static: [u8; 32],
    /// The initiator's ephemeral key.
    pub initiator_ephemeral: [u8; 32],
    /// The initiator's index.
    pub sender_index: u32,
    /// The counter (not yet trustworthy; see `link.md`).
    pub counter: u64,
    /// Which candidate secret matched, if any (an index into the slice
    /// passed to [`receive_initiation`]).
    pub secret: Option<usize>,
    /// Whether the initiation carried an ML-KEM ciphertext.
    pub initiation_kem: bool,
}

/// Decrypts an initiation (responder side of initiator steps 1–7). mac1
/// must already have been checked.
///
/// `accept` says whether a static key is acceptable without a secret.
/// `secrets` are the candidate secrets (invitations, tokens); only those
/// whose hint matches are tried. A zero ML-KEM ciphertext requires a
/// secret unless `allow_public` is set (the public and restore cases of
/// `hosts.md`).
pub fn receive_initiation(
    local: &HybridKeyPair,
    packet: &[u8],
    accept: impl Fn(&[u8; 32]) -> bool,
    secrets: &[&[u8]],
    allow_public: bool,
) -> Result<ReceivedInitiation, HandshakeError> {
    if packet.len() != INITIATION_LEN || packet[0] != packet::TYPE_INITIATION {
        return Err(HandshakeError::Malformed);
    }
    let mut s = SymmetricState::new();
    s.mix_hash(local.public_key().x25519());
    s.mix_hash(&packet[init::COUNTER..init::COUNTER + 8]);
    let e: [u8; 32] = packet[init::EPHEMERAL..init::EPHEMERAL + 32]
        .try_into()
        .expect("32 bytes");
    s.mix_hash(&e);
    let ct = &packet[init::KEM_CT..init::STATIC];
    let initiation_kem = ct.iter().any(|&b| b != 0);
    if initiation_kem {
        let ss = local
            .kem()
            .decapsulate(ct)
            .map_err(|_| HandshakeError::Decrypt)?;
        s.mix_hash(ct);
        s.mix_key(&ss[..]);
    }
    s.mix_dh(local.x25519(), &e)?;
    let enc_static = &packet[init::STATIC..init::MAC1];

    let mut found: Option<(SymmetricState, [u8; 32], Option<usize>)> = None;
    // Without a secret first.
    {
        let mut t = s.clone();
        if let Ok(st) = t.decrypt(enc_static) {
            let st: [u8; 32] = st[..].try_into().map_err(|_| HandshakeError::Malformed)?;
            if (initiation_kem || allow_public) && accept(&st) {
                found = Some((t, st, None));
            } else {
                return Err(HandshakeError::Rejected);
            }
        }
    }
    if found.is_none() {
        let mut hint: [u8; 3] = packet[init::HINT..init::HINT + 3]
            .try_into()
            .expect("3 bytes");
        hint = xor3(hint, s.hint_mask());
        for (i, secret) in secrets.iter().enumerate() {
            if secret_hint(secret) != hint {
                continue;
            }
            let mut t = s.clone();
            t.mix_key(secret);
            if let Ok(st) = t.decrypt(enc_static) {
                let st: [u8; 32] = st[..].try_into().map_err(|_| HandshakeError::Malformed)?;
                found = Some((t, st, Some(i)));
                break;
            }
        }
    }
    let (mut t, initiator_static, secret) = found.ok_or(HandshakeError::Rejected)?;
    t.mix_dh(local.x25519(), &initiator_static)?;
    Ok(ReceivedInitiation {
        state: t,
        initiator_static,
        initiator_ephemeral: e,
        sender_index: packet::read_u32(packet, init::SENDER),
        counter: packet::read_u64(packet, init::COUNTER),
        secret,
        initiation_kem,
    })
}

/// Builds the response (responder steps 1–5). `initiator_kem` is the
/// initiator's ML-KEM key if known.
pub fn respond(
    r: ReceivedInitiation,
    initiator_kem: Option<&KemPublicKey>,
    sender_index: u32,
    ephemeral: &[u8; 32],
    encaps: impl FnOnce(&KemPublicKey) -> Encapsulation,
) -> Result<(Keys, Box<[u8; RESPONSE_LEN]>), HandshakeError> {
    let mut s = r.state;
    let f = X25519Secret::from_bytes(ephemeral);
    let f_pub = f.public_key();
    s.mix_hash(&f_pub);
    s.mix_dh(&f, &r.initiator_ephemeral)?;
    s.mix_dh(&f, &r.initiator_static)?;
    let mut ct = [0u8; CIPHERTEXT_LEN];
    if let Some(kem) = initiator_kem {
        let (c, ss) = encaps(kem);
        ct = c;
        s.mix_hash(&ct);
        s.mix_key(&ss[..]);
    }
    let empty = s.encrypt(&[]);
    let mut pkt = Box::new([0u8; RESPONSE_LEN]);
    pkt[0] = packet::TYPE_RESPONSE;
    pkt[resp::SENDER..resp::SENDER + 4].copy_from_slice(&sender_index.to_le_bytes());
    pkt[resp::RECEIVER..resp::RECEIVER + 4].copy_from_slice(&r.sender_index.to_le_bytes());
    pkt[resp::EPHEMERAL..resp::EPHEMERAL + 32].copy_from_slice(&f_pub);
    pkt[resp::KEM_CT..resp::EMPTY].copy_from_slice(&ct);
    pkt[resp::EMPTY..resp::MAC1].copy_from_slice(&empty);
    packet::seal_macs(
        &mut pkt[..],
        resp::MAC1,
        &packet::mac1_key(&r.initiator_static),
        None,
    );
    Ok((s.split(), pkt))
}

/// `(initiator-to-responder key, responder-to-initiator key, new ck)`.
pub type RekeyKeys = (
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
);

/// Transport keys and new chaining key after a post-quantum rekey:
/// 64 bytes of `derive("rekey", ck || ss)` split as the handshake's, and
/// `ck' = first32(derive("rekey", ck || ss || "ck"))`.
pub fn rekey(ck: &[u8; 32], ss: &[u8; 32]) -> RekeyKeys {
    let mut o = Zeroizing::new([0u8; 64]);
    derive_into_parts(Purpose::Rekey, &[ck, ss], &mut o[..]);
    let mut i2r = Zeroizing::new([0u8; 32]);
    let mut r2i = Zeroizing::new([0u8; 32]);
    i2r.copy_from_slice(&o[..32]);
    r2i.copy_from_slice(&o[32..]);
    let mut new_ck = Zeroizing::new([0u8; 32]);
    derive_into_parts(Purpose::Rekey, &[ck, ss, b"ck"], &mut new_ck[..]);
    (i2r, r2i, new_ck)
}

fn xor3(a: [u8; 3], b: [u8; 3]) -> [u8; 3] {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2]]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(seed: &str) -> HybridKeyPair {
        HybridKeyPair::from_seed(seed.as_bytes())
    }

    fn run(secret: Option<&[u8]>, kem: bool) -> (Keys, Keys) {
        let i = kp("initiator");
        let r = kp("responder");
        let p = InitiationParams {
            local: &i,
            remote_x25519: *r.public_key().x25519(),
            remote_kem: kem.then(|| r.public_key().kem()),
            secret,
            counter: 77,
            sender_index: 5,
        };
        let pending = initiate(&p, &[1u8; 32], [9, 9, 9], |k| k.encapsulate()).unwrap();
        let pkt = *pending.packet();
        assert!(packet::check_mac1(
            &pkt,
            init::MAC1,
            &packet::mac1_key(r.public_key().x25519())
        ));
        let ipub = *i.public_key().x25519();
        let secrets: Vec<&[u8]> = vec![b"other secret", secret.unwrap_or(b"none")];
        let recv = receive_initiation(&r, &pkt, |k| *k == ipub, &secrets, false).unwrap();
        assert_eq!(recv.initiator_static, ipub);
        assert_eq!(recv.counter, 77);
        assert_eq!(recv.secret, secret.map(|_| 1));
        let (rk, resp_pkt) = respond(recv, Some(i.public_key().kem()), 6, &[2u8; 32], |k| {
            k.encapsulate()
        })
        .unwrap();
        let done = finish_initiation(pending, &i, &resp_pkt[..]).unwrap();
        assert_eq!(done.remote_index, 6);
        (done.keys, rk)
    }

    #[test]
    fn both_sides_agree() {
        for (secret, kem) in [
            (None, true),
            (Some(&b"invitation secret"[..]), true),
            (Some(&b"invitation secret"[..]), false),
        ] {
            let (a, b) = run(secret, kem);
            assert_eq!(a.h, b.h);
            assert_eq!(*a.ck, *b.ck);
            assert_eq!(*a.initiator_to_responder, *b.initiator_to_responder);
            assert_eq!(*a.responder_to_initiator, *b.responder_to_initiator);
            assert_ne!(*a.initiator_to_responder, *a.responder_to_initiator);
        }
    }

    #[test]
    fn unknown_static_without_secret_is_rejected() {
        let i = kp("initiator");
        let r = kp("responder");
        let p = InitiationParams {
            local: &i,
            remote_x25519: *r.public_key().x25519(),
            remote_kem: Some(r.public_key().kem()),
            secret: None,
            counter: 1,
            sender_index: 1,
        };
        let pending = initiate(&p, &[1u8; 32], [0; 3], |k| k.encapsulate()).unwrap();
        assert_eq!(
            receive_initiation(&r, pending.packet(), |_| false, &[], false).err(),
            Some(HandshakeError::Rejected)
        );
    }

    #[test]
    fn zero_kem_requires_secret() {
        let i = kp("initiator");
        let r = kp("responder");
        let p = InitiationParams {
            local: &i,
            remote_x25519: *r.public_key().x25519(),
            remote_kem: None,
            secret: None,
            counter: 1,
            sender_index: 1,
        };
        let pending = initiate(&p, &[1u8; 32], [0; 3], |k| k.encapsulate()).unwrap();
        assert!(receive_initiation(&r, pending.packet(), |_| true, &[], false).is_err());
        assert!(receive_initiation(&r, pending.packet(), |_| true, &[], true).is_ok());
    }

    #[test]
    fn tampered_counter_fails() {
        let i = kp("initiator");
        let r = kp("responder");
        let p = InitiationParams {
            local: &i,
            remote_x25519: *r.public_key().x25519(),
            remote_kem: Some(r.public_key().kem()),
            secret: None,
            counter: 1,
            sender_index: 1,
        };
        let pending = initiate(&p, &[1u8; 32], [0; 3], |k| k.encapsulate()).unwrap();
        let mut pkt = *pending.packet();
        pkt[init::COUNTER] ^= 1;
        assert!(receive_initiation(&r, &pkt, |_| true, &[], false).is_err());
    }
}
