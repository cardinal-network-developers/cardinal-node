//! Pairing two devices in the same place (`contact.md#pairing`).
//!
//! The device that **shows** the code listens on UDP and advertises
//! `_cardinal-pair._udp`; the device where the code is **typed** finds it
//! and starts. The exchange, one UDP datagram per message:
//!
//! 1. typer → shower: `{0: 1, 1: CPace share}` (the typer is the CPace
//!    initiator);
//! 2. shower → typer: `{0: 1, 1: share}`, then `{0: 2, 1: tag}`;
//! 3. typer → shower: `{0: 2, 1: tag}`; a wrong tag ends the attempt, and
//!    after three failed attempts the shower stops using the code;
//! 4. typer, then shower: `{0: 3, 1: nonce, 2: ciphertext}` carrying each
//!    side's identity id (if any), signing key, link key, link endpoint,
//!    suggested name, and, from a device without an identity, the proof of
//!    possession for joining the other's identity.
//!
//! Both then open a link session with `derive("invite", K)` as the secret
//! ([`Paired::secret_entry`], [`Paired::link_target`]).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use cardinal_crypto::aead::{xchacha20poly1305_decrypt, xchacha20poly1305_encrypt_random};
use cardinal_crypto::{
    ct_eq, derive, hash_parts, keyed_hash_parts, verify, Cpace, CpaceRole, HybridPublicKey,
    Purpose, SigningKey,
};
use cardinal_encoding::{write_varint, Record};
use cardinal_link::{ExpectedPeer, SecretEntry, Target};
use tokio::net::UdpSocket;
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::code::PairingCode;
use crate::endpoint::EndpointAddr;
use crate::ContactError;

/// How many failed attempts a code survives.
pub const MAX_ATTEMPTS: u32 = 3;
/// Power values (`identity.md#keys-and-powers`).
pub const POWER_DEVICE: u64 = 1;
/// Admin power.
pub const POWER_ADMIN: u64 = 2;

const OP_SHARE: u64 = 1;
const OP_TAG: u64 = 2;
const OP_INFO: u64 = 3;
const RETRANSMIT: Duration = Duration::from_millis(300);

/// What this device tells the other side.
#[derive(Clone)]
pub struct LocalDevice {
    /// Identity id, if this device has one.
    pub identity: Option<[u8; 32]>,
    /// The device signing key.
    pub signing_key: Arc<SigningKey>,
    /// The device's link key.
    pub link_key: HybridPublicKey,
    /// Where its link endpoint listens.
    pub link_endpoint: EndpointAddr,
    /// The name it suggests for itself.
    pub name: String,
    /// If this device has no identity: the power its proof of possession
    /// asks for (device unless the person says otherwise).
    pub join_power: u64,
}

/// What the other side told us.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// Its identity id, if any.
    pub identity: Option<[u8; 32]>,
    /// Its device signing key.
    pub signing_key: [u8; 32],
    /// Its full link key.
    pub link_key: HybridPublicKey,
    /// Its link endpoint.
    pub endpoint: EndpointAddr,
    /// Its suggested name.
    pub name: String,
    /// Its proof of possession for joining our identity, if it has none.
    pub proof: Option<[u8; 64]>,
}

/// A device to add to this device's identity: everything the identity
/// layer needs for an `add_key` op.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewDevice {
    /// The identity it joins (the proof's binding).
    pub identity: [u8; 32],
    /// Its signing key.
    pub signing_key: [u8; 32],
    /// The power its proof asks for.
    pub power: u64,
    /// Its link key.
    pub link_key: HybridPublicKey,
    /// The proof of possession.
    pub proof: [u8; 64],
    /// Its suggested name (for the account space, never the log).
    pub name: String,
}

impl NewDevice {
    /// The `add_key` op record: `{0: 1, 1: signing key, 2: power, 3: link
    /// key, 5: proof}` (`identity.md#operations`).
    pub fn add_key_op(&self) -> Record {
        Record::new()
            .with(0, 1u64)
            .with(1, self.signing_key)
            .with(2, self.power)
            .with(3, self.link_key.to_record())
            .with(5, self.proof)
    }

    /// Checks the proof.
    pub fn verify(&self) -> bool {
        verify(
            &self.signing_key,
            &proof_message(
                &self.identity,
                &self.signing_key,
                self.power,
                &self.link_key,
            ),
            &self.proof,
        )
        .is_ok()
    }
}

/// The identity layer's side of adding a device: the daemon implements it
/// by appending `add_key` (and a `wrap` of the identity encryption key) to
/// the log and sending the log to the new device.
pub trait DeviceEnroller: Send + Sync {
    /// Adds the device. Called on an admin device after a successful
    /// pairing with a device that has no identity.
    fn enroll(&self, device: &NewDevice) -> Result<(), String>;
}

/// `"cardinal add key" || binding || signing key || varint(power) ||
/// encoding of link key` (`identity.md#operations`).
pub fn proof_message(
    binding: &[u8; 32],
    signing_key: &[u8; 32],
    power: u64,
    link_key: &HybridPublicKey,
) -> Vec<u8> {
    let mut m = b"cardinal add key".to_vec();
    m.extend_from_slice(binding);
    m.extend_from_slice(signing_key);
    write_varint(power, &mut m);
    m.extend_from_slice(&link_key.encode());
    m
}

/// Which side of the pairing this device was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairRole {
    /// Typed the code (CPace initiator, link initiator).
    Typer,
    /// Showed the code.
    Shower,
}

/// A completed pairing.
pub struct Paired {
    /// Our role.
    pub role: PairRole,
    /// The other device.
    pub peer: PeerInfo,
    /// `derive("invite", K)`: the secret for the link session.
    pub link_secret: Zeroizing<[u8; 32]>,
    /// On the typer, when the shower has no identity and gave a valid
    /// proof: the device to add.
    pub new_device: Option<NewDevice>,
}

impl std::fmt::Debug for Paired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Paired")
            .field("role", &self.role)
            .field("peer", &self.peer.name)
            .finish_non_exhaustive()
    }
}

impl Paired {
    fn expected(&self) -> ExpectedPeer {
        ExpectedPeer {
            identity: self.peer.identity,
            signing_key: Some(self.peer.signing_key),
            no_identity: self.peer.identity.is_none(),
        }
    }

    /// For the shower: the secret its link endpoint accepts from the typer.
    pub fn secret_entry(&self) -> SecretEntry {
        SecretEntry {
            secret: Zeroizing::new(self.link_secret.to_vec()),
            uses: Some(1),
            peer_link_key: Some(self.peer.link_key.clone()),
            expected: self.expected(),
        }
    }

    /// For the typer: where and how to open the link session.
    pub fn link_target(&self) -> Result<Target, ContactError> {
        let addr = self
            .peer
            .endpoint
            .socket_addr()
            .ok_or(ContactError::Malformed("link endpoint is a host name"))?;
        Ok(
            Target::new(addr, self.peer.endpoint.carrier, &self.peer.link_key)
                .with_secret(&self.link_secret[..])
                .expect(self.expected()),
        )
    }
}

/// `BLAKE3("cardinal 1 pair" || channel as varint || shower endpoint ||
/// typer endpoint)`.
pub fn session_id(channel: u16, shower: &EndpointAddr, typer: &EndpointAddr) -> [u8; 32] {
    let mut ch = Vec::new();
    write_varint(channel as u64, &mut ch);
    hash_parts(&[b"cardinal 1 pair", &ch, &shower.encode(), &typer.encode()])
}

fn confirm_tag(k: &[u8; 32], own_share: &[u8]) -> [u8; 32] {
    keyed_hash_parts(k, &[b"cardinal 1 pair confirm", own_share])
}

fn msg(op: u64, f1: &[u8]) -> Vec<u8> {
    Record::new().with(0, op).with(1, f1.to_vec()).encode()
}

fn parse(bytes: &[u8]) -> Option<(u64, Record)> {
    let r = Record::decode(bytes).ok()?;
    Some((r.uint(0).ok()?, r))
}

fn seal_info(k: &[u8; 32], local: &LocalDevice, proof: Option<[u8; 64]>) -> Vec<u8> {
    let plain = Record::new()
        .with_opt(1, local.identity)
        .with(2, local.signing_key.public_key())
        .with(3, local.link_key.to_record())
        .with(4, local.link_endpoint.to_record())
        .with(5, local.name.as_str())
        .with_opt(6, proof)
        .encode();
    let key = derive(Purpose::Pair, k);
    let (nonce, ct) = xchacha20poly1305_encrypt_random(&key, &[], &plain);
    Record::new()
        .with(0, OP_INFO)
        .with(1, nonce)
        .with(2, ct)
        .encode()
}

fn open_info(k: &[u8; 32], r: &Record) -> Result<PeerInfo, ContactError> {
    let bad = |_| ContactError::Malformed("pairing info");
    let nonce = r.bytes_n::<24>(1).map_err(bad)?;
    let ct = r.bytes(2).map_err(bad)?;
    let key = derive(Purpose::Pair, k);
    let plain = Zeroizing::new(
        xchacha20poly1305_decrypt(&key, &nonce, &[], ct)
            .map_err(|_| ContactError::Malformed("pairing info decryption"))?,
    );
    let p = Record::decode(&plain).map_err(|_| ContactError::Malformed("pairing info"))?;
    Ok(PeerInfo {
        identity: p.opt_bytes_n::<32>(1).map_err(bad)?,
        signing_key: p.bytes_n::<32>(2).map_err(bad)?,
        link_key: HybridPublicKey::from_record(p.record(3).map_err(bad)?)
            .map_err(|_| ContactError::Malformed("pairing link key"))?,
        endpoint: EndpointAddr::from_record(p.record(4).map_err(bad)?)?,
        name: p.opt_text(5).map_err(bad)?.unwrap_or_default().to_string(),
        proof: p.opt_bytes_n::<64>(6).map_err(bad)?,
    })
}

fn make_proof(local: &LocalDevice, peer_identity: Option<[u8; 32]>) -> Option<[u8; 64]> {
    match (local.identity, peer_identity) {
        (None, Some(id)) => Some(local.signing_key.sign(&proof_message(
            &id,
            &local.signing_key.public_key(),
            local.join_power,
            &local.link_key,
        ))),
        _ => None,
    }
}

/// The local address a socket uses to reach `peer`.
async fn local_ip_toward(peer: SocketAddr) -> std::io::Result<IpAddr> {
    let unspec: SocketAddr = match peer {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let s = UdpSocket::bind(unspec).await?;
    s.connect(peer).await?;
    Ok(s.local_addr()?.ip())
}

struct ShowerAttempt {
    from: SocketAddr,
    peer_share: Vec<u8>,
    k: Zeroizing<[u8; 32]>,
    replies: Vec<Vec<u8>>,
    confirmed: bool,
    started: Instant,
}

/// The showing side of a pairing.
pub struct Shower {
    socket: UdpSocket,
    code: PairingCode,
    local: LocalDevice,
    /// How long an attempt may stay unfinished before it counts as failed.
    pub attempt_timeout: Duration,
    /// How long to give up entirely.
    pub overall_timeout: Duration,
}

impl Shower {
    /// Binds the pairing socket. Advertise [`local_addr`](Shower::local_addr)
    /// with [`crate::discovery::advertise_pairing`].
    pub async fn bind(
        local: LocalDevice,
        addr: SocketAddr,
        code: Option<PairingCode>,
    ) -> std::io::Result<Shower> {
        Ok(Shower {
            socket: UdpSocket::bind(addr).await?,
            code: code.unwrap_or_else(PairingCode::generate),
            local,
            attempt_timeout: Duration::from_secs(10),
            overall_timeout: Duration::from_secs(600),
        })
    }

    /// The code to show.
    pub fn code(&self) -> &PairingCode {
        &self.code
    }

    /// The pairing socket's address.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Runs until a typer pairs, or the code has failed [`MAX_ATTEMPTS`]
    /// times ([`ContactError::TooManyAttempts`]: show a new code).
    pub async fn run(self) -> Result<Paired, ContactError> {
        let deadline = Instant::now() + self.overall_timeout;
        let port = self.socket.local_addr()?.port();
        let pw = self.code.password();
        let mut failures = 0u32;
        let mut attempt: Option<ShowerAttempt> = None;
        let mut buf = vec![0u8; 4096];
        loop {
            let wait_until = match &attempt {
                Some(a) => (a.started + self.attempt_timeout).min(deadline),
                None => deadline,
            };
            let r = tokio::time::timeout_at(wait_until, self.socket.recv_from(&mut buf)).await;
            let (n, from) = match r {
                Ok(r) => r?,
                Err(_) => {
                    if Instant::now() >= deadline {
                        return Err(ContactError::Timeout);
                    }
                    if attempt.take().is_some_and(|a| !a.confirmed) {
                        failures += 1;
                        if failures >= MAX_ATTEMPTS {
                            return Err(ContactError::TooManyAttempts);
                        }
                    }
                    continue;
                }
            };
            let Some((op, rec)) = parse(&buf[..n]) else {
                continue;
            };
            match op {
                OP_SHARE => {
                    let Ok(share) = rec.bytes(1) else { continue };
                    if let Some(a) = &attempt {
                        if a.from == from && a.peer_share == share {
                            for m in &a.replies {
                                let _ = self.socket.send_to(m, from).await;
                            }
                            continue;
                        }
                        if !a.confirmed {
                            // A new attempt abandons the old one.
                            failures += 1;
                            if failures >= MAX_ATTEMPTS {
                                return Err(ContactError::TooManyAttempts);
                            }
                        }
                    }
                    let me = EndpointAddr::new(
                        cardinal_link::CarrierKind::Udp,
                        SocketAddr::new(local_ip_toward(from).await?, port),
                    );
                    let typer = EndpointAddr::new(cardinal_link::CarrierKind::Udp, from);
                    let sid = session_id(self.code.channel, &me, &typer);
                    let cp = Cpace::start(CpaceRole::Responder, &pw, b"", &sid, b"");
                    let own_share = *cp.share();
                    let Ok(isk) = cp.finish(share, b"") else {
                        attempt = None;
                        continue;
                    };
                    let k = isk.key32();
                    let replies = vec![
                        msg(OP_SHARE, &own_share),
                        msg(OP_TAG, &confirm_tag(&k, &own_share)),
                    ];
                    for m in &replies {
                        let _ = self.socket.send_to(m, from).await;
                    }
                    attempt = Some(ShowerAttempt {
                        from,
                        peer_share: share.to_vec(),
                        k,
                        replies,
                        confirmed: false,
                        started: Instant::now(),
                    });
                }
                OP_TAG => {
                    let Some(a) = &mut attempt else { continue };
                    if a.from != from || a.confirmed {
                        continue;
                    }
                    let Ok(tag) = rec.bytes(1) else { continue };
                    if ct_eq(tag, &confirm_tag(&a.k, &a.peer_share)) {
                        a.confirmed = true;
                    } else {
                        attempt = None;
                        failures += 1;
                        if failures >= MAX_ATTEMPTS {
                            return Err(ContactError::TooManyAttempts);
                        }
                    }
                }
                OP_INFO => {
                    let Some(a) = &attempt else { continue };
                    if a.from != from || !a.confirmed {
                        continue;
                    }
                    let Ok(peer) = open_info(&a.k, &rec) else {
                        continue;
                    };
                    if peer.identity.is_none() && self.local.identity.is_none() {
                        return Err(ContactError::NoIdentity);
                    }
                    let proof = make_proof(&self.local, peer.identity);
                    let reply = seal_info(&a.k, &self.local, proof);
                    let _ = self.socket.send_to(&reply, from).await;
                    let link_secret = derive(Purpose::Invite, &a.k[..]);
                    // Keep answering retransmissions for a little while.
                    let socket = self.socket;
                    let (k_from, reply2) = (from, reply);
                    tokio::spawn(async move {
                        let mut b = vec![0u8; 4096];
                        let end = Instant::now() + Duration::from_secs(5);
                        while let Ok(Ok((n, f))) =
                            tokio::time::timeout_at(end, socket.recv_from(&mut b)).await
                        {
                            if f == k_from && parse(&b[..n]).is_some_and(|(op, _)| op == OP_INFO) {
                                let _ = socket.send_to(&reply2, f).await;
                            }
                        }
                    });
                    return Ok(Paired {
                        role: PairRole::Shower,
                        peer,
                        link_secret,
                        new_device: None,
                    });
                }
                _ => {}
            }
        }
    }
}

/// The typing side: pairs with the shower at `shower` using `code`.
/// Fails with [`ContactError::WrongCode`] if the codes differ.
pub async fn pair_typer(
    local: &LocalDevice,
    code: &PairingCode,
    shower: SocketAddr,
    timeout: Duration,
) -> Result<Paired, ContactError> {
    if local.identity.is_none() {
        return Err(ContactError::NoIdentity);
    }
    let deadline = Instant::now() + timeout;
    let unspec: SocketAddr = match shower {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(unspec).await?;
    socket.connect(shower).await?;
    let me = EndpointAddr::new(cardinal_link::CarrierKind::Udp, socket.local_addr()?);
    let them = EndpointAddr::new(cardinal_link::CarrierKind::Udp, shower);
    let sid = session_id(code.channel, &them, &me);
    let cp = Cpace::start(CpaceRole::Initiator, &code.password(), b"", &sid, b"");
    let own_share = *cp.share();
    let first = msg(OP_SHARE, &own_share);
    let mut buf = vec![0u8; 4096];

    // Steps 1-2: our share out; their share and tag back.
    let mut cp = Some(cp);
    let mut k: Option<Zeroizing<[u8; 32]>> = None;
    let mut their_share = Vec::new();
    let mut their_tag: Option<Vec<u8>> = None;
    while k.is_none() || their_tag.is_none() {
        socket.send(&first).await?;
        let resend = (Instant::now() + RETRANSMIT).min(deadline);
        while let Ok(r) = tokio::time::timeout_at(resend, socket.recv(&mut buf)).await {
            let n = r?;
            match parse(&buf[..n]) {
                Some((OP_SHARE, rec)) if k.is_none() => {
                    let Ok(share) = rec.bytes(1) else { continue };
                    let c = cp.take().expect("cpace");
                    k = Some(
                        c.finish(share, b"")
                            .map_err(|_| ContactError::WrongCode)?
                            .key32(),
                    );
                    their_share = share.to_vec();
                }
                Some((OP_TAG, rec)) => {
                    if let Ok(t) = rec.bytes(1) {
                        their_tag = Some(t.to_vec());
                    }
                }
                _ => {}
            }
            if k.is_some() && their_tag.is_some() {
                break;
            }
        }
        if Instant::now() >= deadline {
            return Err(ContactError::Timeout);
        }
    }
    let k = k.expect("k");
    // Step 3: our tag, always, so a wrong code counts against the code.
    let tag_msg = msg(OP_TAG, &confirm_tag(&k, &own_share));
    socket.send(&tag_msg).await?;
    if !ct_eq(
        their_tag.as_deref().unwrap_or_default(),
        &confirm_tag(&k, &their_share),
    ) {
        return Err(ContactError::WrongCode);
    }
    // Step 4: our information, then theirs.
    let info = seal_info(&k, local, None);
    let peer = loop {
        socket.send(&tag_msg).await?;
        socket.send(&info).await?;
        let resend = (Instant::now() + RETRANSMIT).min(deadline);
        let mut got = None;
        while let Ok(r) = tokio::time::timeout_at(resend, socket.recv(&mut buf)).await {
            let n = r?;
            if let Some((OP_INFO, rec)) = parse(&buf[..n]) {
                if let Ok(p) = open_info(&k, &rec) {
                    got = Some(p);
                    break;
                }
            }
        }
        if let Some(p) = got {
            break p;
        }
        if Instant::now() >= deadline {
            return Err(ContactError::Timeout);
        }
    };
    let new_device = match (peer.identity, peer.proof, local.identity) {
        (None, Some(proof), Some(id)) => {
            let found = [POWER_DEVICE, POWER_ADMIN].into_iter().find_map(|power| {
                let d = NewDevice {
                    identity: id,
                    signing_key: peer.signing_key,
                    power,
                    link_key: peer.link_key.clone(),
                    proof,
                    name: peer.name.clone(),
                };
                d.verify().then_some(d)
            });
            Some(found.ok_or(ContactError::BadProof)?)
        }
        (None, None, _) => return Err(ContactError::BadProof),
        _ => None,
    };
    Ok(Paired {
        role: PairRole::Typer,
        peer,
        link_secret: derive(Purpose::Invite, &k[..]),
        new_device,
    })
}
