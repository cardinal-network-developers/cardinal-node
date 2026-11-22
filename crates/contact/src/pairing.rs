//! Pairing two devices in the same place (`contact.md#pairing`).
//!
//! The device that **shows** the code advertises its channel and listens:
//! on a local network on UDP, `_cardinal-pair._udp` with `c=<channel>`, one
//! datagram a message; over Bluetooth by a tag made from the channel alone
//! ([`crate::ble::pairing_key`]), on an L2CAP channel, each message
//! prefixed by its length as link packets are. The device where the code
//! is **typed** finds it and starts. Both carriers run the same exchange,
//! against the same count of failed attempts:
//!
//! 1. typer → shower: `{0: 4, 1: r}`, 16 random bytes; the shower answers
//!    `{0: 4, 1: r}` with its own. CPace's session identifier is
//!    `BLAKE3("cardinal 1 pair" || varint(channel) || shower's r || typer's
//!    r)`: no addresses;
//! 2. typer → shower: `{0: 1, 1: CPace share}` (the typer is the CPace
//!    initiator); shower → typer: `{0: 1, 1: share}`, then `{0: 2, 1: tag}`;
//! 3. typer → shower: `{0: 2, 1: tag}`; a wrong tag ends the attempt, and
//!    after three failed attempts the shower stops using the code;
//! 4. typer, then shower: `{0: 3, 1: nonce, 2: ciphertext}` carrying each
//!    side's identity id (if any), signing key, link key, link endpoint,
//!    suggested name, from the typer the power it adds a device with no
//!    identity at (7), and from a device without an identity the proof of
//!    possession for joining the other's identity at exactly that power.
//!
//! Both then open a link session with `derive("invite", K)` as the secret
//! ([`Paired::secret_entry`], [`Paired::link_target`]); over Bluetooth on
//! the same channel ([`Paired::channel`], [`Paired::target_on`]).

use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use cardinal_crypto::aead::{xchacha20poly1305_decrypt, xchacha20poly1305_encrypt_random};
use cardinal_crypto::{
    ct_eq, derive, hash_parts, keyed_hash_parts, random_bytes, verify, Cpace, CpaceRole,
    HybridPublicKey, Purpose, SigningKey,
};
use cardinal_encoding::{write_varint, Record};
use cardinal_link::{ExpectedPeer, SecretEntry, Target};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::ble::BoxChannel;
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
const OP_START: u64 = 4;
/// Bytes of each side's random value.
pub const RANDOM_LEN: usize = 16;
const RETRANSMIT: Duration = Duration::from_millis(300);
/// The longest pairing message read.
const MAX_MESSAGE: usize = 4096;
/// Starts kept at once, from different senders: a start is no guess.
const MAX_STARTS: usize = 16;
/// Channels being read at once.
const MAX_CHANNELS: usize = 4;
/// How long a channel may go without a message.
const CHANNEL_QUIET: Duration = Duration::from_secs(15);

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
    /// On a typer adding a device: the power it adds a shower with no
    /// identity at, [`POWER_DEVICE`] or [`POWER_ADMIN`], sent in field 7.
    /// The new device signs for exactly that.
    pub adds_at: Option<u64>,
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
    /// From a typer: the power it adds this device at, if this has no
    /// identity (field 7).
    pub power: Option<u64>,
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
    /// On a shower with no identity: the power it signed for, the one the
    /// typer named, to show its person ("This device will join as ...").
    pub joins_at: Option<u64>,
    /// The channel the pairing ran over, where it ran over one (Bluetooth):
    /// the link session runs over it next, attached on both sides.
    pub channel: Option<BoxChannel>,
}

impl std::fmt::Debug for Paired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Paired")
            .field("role", &self.role)
            .field("peer", &self.peer.name)
            .field("joins_at", &self.joins_at)
            .field("channel", &self.channel.is_some())
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

    /// For the typer over a channel: the link session over it, once
    /// attached (`Endpoint::connect_on`, which uses no address).
    pub fn target_on(&self, carrier: cardinal_link::CarrierKind) -> Target {
        let nowhere = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        Target::new(nowhere, carrier, &self.peer.link_key)
            .with_secret(&self.link_secret[..])
            .expect(self.expected())
    }

    /// For the typer: where and how to open the link session.
    pub fn link_target(&self) -> Result<Target, ContactError> {
        // Not malformed: an endpoint this version cannot use, for its
        // carrier or its address, or a host name.
        let endpoint = &self.peer.endpoint;
        let at = endpoint.socket_addr().zip(endpoint.carrier());
        let (addr, carrier) = at.ok_or(ContactError::Unusable("link endpoint"))?;
        Ok(Target::new(addr, carrier, &self.peer.link_key)
            .with_secret(&self.link_secret[..])
            .expect(self.expected()))
    }
}

/// `BLAKE3("cardinal 1 pair" || varint(channel) || shower's random ||
/// typer's random)`.
pub fn session_id(channel: u16, shower: &[u8; RANDOM_LEN], typer: &[u8; RANDOM_LEN]) -> [u8; 32] {
    let mut ch = Vec::new();
    write_varint(channel as u64, &mut ch);
    hash_parts(&[b"cardinal 1 pair", &ch, shower, typer])
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

/// Whether a message that opens a channel is pairing's: a record, whose
/// header's low three bits are 5, where a link packet's first byte is its
/// type, 1 to 4 on a channel of its own (`carriers/ble.md`, Finding): the
/// first is an initiation, and relayed packets go only through a host.
pub fn is_pairing_message(first: &[u8]) -> bool {
    first.first().is_some_and(|b| b & 7 == 5)
}

/// The associated data of the information a side sends: its role, so that
/// neither side's message can be sent back to it as the other's.
fn info_label(from: PairRole) -> &'static [u8] {
    match from {
        PairRole::Typer => b"cardinal 1 pair typer",
        PairRole::Shower => b"cardinal 1 pair shower",
    }
}

fn seal_info(
    k: &[u8; 32],
    local: &LocalDevice,
    proof: Option<[u8; 64]>,
    from: PairRole,
) -> Vec<u8> {
    let plain = Record::new()
        .with_opt(1, local.identity)
        .with(2, local.signing_key.public_key())
        .with(3, local.link_key.to_record())
        .with(4, local.link_endpoint.to_record())
        .with(5, local.name.as_str())
        .with_opt(6, proof)
        .with_opt(7, local.adds_at)
        .encode();
    let key = derive(Purpose::Pair, k);
    let (nonce, ct) = xchacha20poly1305_encrypt_random(&key, info_label(from), &plain);
    Record::new()
        .with(0, OP_INFO)
        .with(1, nonce)
        .with(2, ct)
        .encode()
}

fn open_info(k: &[u8; 32], r: &Record, from: PairRole) -> Result<PeerInfo, ContactError> {
    let bad = |_| ContactError::Malformed("pairing info");
    let nonce = r.bytes_n::<24>(1).map_err(bad)?;
    let ct = r.bytes(2).map_err(bad)?;
    let key = derive(Purpose::Pair, k);
    let plain = Zeroizing::new(
        xchacha20poly1305_decrypt(&key, &nonce, info_label(from), ct)
            .map_err(|_| ContactError::Malformed("pairing info decryption"))?,
    );
    let p = Record::decode(&plain).map_err(|_| ContactError::Malformed("pairing info"))?;
    Ok(PeerInfo {
        identity: p.opt_bytes_n::<32>(1).map_err(bad)?,
        signing_key: p.bytes_n::<32>(2).map_err(bad)?,
        link_key: HybridPublicKey::from_record(p.record(3).map_err(bad)?)
            .map_err(|_| ContactError::Malformed("pairing link key"))?,
        endpoint: EndpointAddr::from_record(p.record(4).map_err(bad)?),
        name: p.opt_text(5).map_err(bad)?.unwrap_or_default().to_string(),
        proof: p.opt_bytes_n::<64>(6).map_err(bad)?,
        power: p.opt_uint(7).map_err(bad)?,
    })
}

/// The proof a device with no identity signs, for joining the typer's
/// identity at the power the typer named.
fn make_proof(local: &LocalDevice, peer: &PeerInfo) -> Result<Option<[u8; 64]>, ContactError> {
    match (local.identity, peer.identity) {
        (None, Some(id)) => {
            let power = match peer.power {
                Some(p @ (POWER_DEVICE | POWER_ADMIN)) => p,
                Some(_) => return Err(ContactError::Malformed("pairing power")),
                None => return Err(ContactError::Malformed("pairing info without a power")),
            };
            Ok(Some(local.signing_key.sign(&proof_message(
                &id,
                &local.signing_key.public_key(),
                power,
                &local.link_key,
            ))))
        }
        _ => Ok(None),
    }
}

/// The local address a socket uses to reach `peer`.
async fn bind_toward(peer: SocketAddr) -> std::io::Result<UdpSocket> {
    let unspec: SocketAddr = match peer {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let s = UdpSocket::bind(unspec).await?;
    s.connect(peer).await?;
    Ok(s)
}

/// Reads one message from a channel: its length, little-endian, then it.
pub async fn read_message(ch: &mut BoxChannel) -> std::io::Result<Vec<u8>> {
    let n = ch.read_u16_le().await? as usize;
    if n > MAX_MESSAGE {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut b = vec![0u8; n];
    ch.read_exact(&mut b).await?;
    Ok(b)
}

/// Writes one message to a channel, prefixed by its length.
async fn write_messages(ch: &mut BoxChannel, ms: &[Vec<u8>]) -> std::io::Result<()> {
    let mut out = Vec::new();
    for m in ms {
        out.extend_from_slice(&(m.len() as u16).to_le_bytes());
        out.extend_from_slice(m);
    }
    ch.write_all(&out).await?;
    ch.flush().await
}

/// Who a message came from, on the shower.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum From {
    Udp(SocketAddr),
    Channel(u64),
}

struct Started {
    from: From,
    typer: [u8; RANDOM_LEN],
    shower: [u8; RANDOM_LEN],
}

struct ShowerAttempt {
    from: From,
    peer_share: Vec<u8>,
    k: Zeroizing<[u8; 32]>,
    replies: Vec<Vec<u8>>,
    confirmed: bool,
    started: Instant,
}

/// What a message did, on the shower.
enum Heard {
    /// Answer with these, if anything.
    Answer(Vec<Vec<u8>>),
    /// The attempt on this channel failed: close it.
    Failed,
    /// Paired: send the last answer, and done.
    Done(Box<Paired>, Vec<u8>),
}

/// The shower's side of the exchange, whatever carries it: one attempt at
/// a time, counting failures against the code.
struct ShowerState {
    code: PairingCode,
    local: LocalDevice,
    pw: Zeroizing<Vec<u8>>,
    failures: u32,
    starts: VecDeque<Started>,
    attempt: Option<ShowerAttempt>,
}

impl ShowerState {
    fn fail(&mut self) -> Result<(), ContactError> {
        self.failures += 1;
        if self.failures >= MAX_ATTEMPTS {
            return Err(ContactError::TooManyAttempts);
        }
        Ok(())
    }

    /// An attempt not finished in time counts as failed.
    fn expire(&mut self, now: Instant, within: Duration) -> Result<(), ContactError> {
        if self
            .attempt
            .as_ref()
            .is_some_and(|a| !a.confirmed && a.started + within <= now)
        {
            self.attempt = None;
            self.fail()?;
        }
        Ok(())
    }

    fn deadline(&self, within: Duration) -> Option<Instant> {
        self.attempt
            .as_ref()
            .filter(|a| !a.confirmed)
            .map(|a| a.started + within)
    }

    fn heard(&mut self, from: From, bytes: &[u8]) -> Result<Heard, ContactError> {
        let Some((op, rec)) = parse(bytes) else {
            return Ok(Heard::Answer(Vec::new()));
        };
        match op {
            OP_START => {
                let Ok(typer) = rec.bytes_n::<RANDOM_LEN>(1) else {
                    return Ok(Heard::Answer(Vec::new()));
                };
                // The same start again: the same answer.
                if let Some(s) = self
                    .starts
                    .iter()
                    .find(|s| s.from == from && s.typer == typer)
                {
                    return Ok(Heard::Answer(vec![msg(OP_START, &s.shower)]));
                }
                self.starts.retain(|s| s.from != from);
                if self.starts.len() >= MAX_STARTS {
                    self.starts.pop_front();
                }
                let shower: [u8; RANDOM_LEN] = random_bytes();
                self.starts.push_back(Started {
                    from,
                    typer,
                    shower,
                });
                Ok(Heard::Answer(vec![msg(OP_START, &shower)]))
            }
            OP_SHARE => {
                let Ok(share) = rec.bytes(1) else {
                    return Ok(Heard::Answer(Vec::new()));
                };
                if let Some(a) = &self.attempt {
                    if a.from == from && a.peer_share == share {
                        return Ok(Heard::Answer(a.replies.clone()));
                    }
                }
                // A share only after a start, which gave the session id.
                let Some(s) = self.starts.iter().find(|s| s.from == from) else {
                    return Ok(Heard::Answer(Vec::new()));
                };
                let sid = session_id(self.code.channel, &s.shower, &s.typer);
                if self.attempt.take().is_some() {
                    // A new attempt abandons the old one, which counts as
                    // failed whether or not its tag was right: else one
                    // who knows the code could take attempts without end.
                    self.fail()?;
                }
                let cp = Cpace::start(CpaceRole::Responder, &self.pw, b"", &sid, b"");
                let own_share = *cp.share();
                let Ok(isk) = cp.finish(share, b"") else {
                    return Ok(Heard::Failed);
                };
                let k = isk.key32();
                let replies = vec![
                    msg(OP_SHARE, &own_share),
                    msg(OP_TAG, &confirm_tag(&k, &own_share)),
                ];
                self.attempt = Some(ShowerAttempt {
                    from,
                    peer_share: share.to_vec(),
                    k,
                    replies: replies.clone(),
                    confirmed: false,
                    started: Instant::now(),
                });
                Ok(Heard::Answer(replies))
            }
            OP_TAG => {
                let Some(a) = &mut self.attempt else {
                    return Ok(Heard::Answer(Vec::new()));
                };
                if a.from != from || a.confirmed {
                    return Ok(Heard::Answer(Vec::new()));
                }
                let Ok(tag) = rec.bytes(1) else {
                    return Ok(Heard::Answer(Vec::new()));
                };
                if ct_eq(tag, &confirm_tag(&a.k, &a.peer_share)) {
                    a.confirmed = true;
                    Ok(Heard::Answer(Vec::new()))
                } else {
                    self.attempt = None;
                    self.fail()?;
                    Ok(Heard::Failed)
                }
            }
            OP_INFO => {
                let Some(a) = &self.attempt else {
                    return Ok(Heard::Answer(Vec::new()));
                };
                if a.from != from || !a.confirmed {
                    return Ok(Heard::Answer(Vec::new()));
                }
                let Ok(peer) = open_info(&a.k, &rec, PairRole::Typer) else {
                    return Ok(Heard::Answer(Vec::new()));
                };
                if peer.identity.is_none() && self.local.identity.is_none() {
                    return Err(ContactError::NoIdentity);
                }
                // Without a power, or with another value, the attempt ends,
                // and the pairing with it: the person sees why.
                let proof = make_proof(&self.local, &peer)?;
                let joins_at = proof.and(peer.power);
                let reply = seal_info(&a.k, &self.local, proof, PairRole::Shower);
                let link_secret = derive(Purpose::Invite, &a.k[..]);
                Ok(Heard::Done(
                    Box::new(Paired {
                        role: PairRole::Shower,
                        peer,
                        link_secret,
                        new_device: None,
                        joins_at,
                        channel: None,
                    }),
                    reply,
                ))
            }
            _ => Ok(Heard::Answer(Vec::new())),
        }
    }
}

/// The showing side of a pairing.
pub struct Shower {
    socket: UdpSocket,
    code: PairingCode,
    local: LocalDevice,
    channels: Option<mpsc::Receiver<(BoxChannel, Vec<u8>)>>,
    /// How long an attempt may stay unfinished before it counts as failed.
    pub attempt_timeout: Duration,
    /// How long to give up entirely.
    pub overall_timeout: Duration,
}

/// A channel read to its next message.
type ChannelRead = (u64, BoxChannel, std::io::Result<Vec<u8>>);

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
            channels: None,
            attempt_timeout: Duration::from_secs(10),
            overall_timeout: Duration::from_secs(600),
        })
    }

    /// Takes pairing over channels too, as they come, each with the first
    /// message already read from it ([`is_pairing_message`]): over
    /// Bluetooth, to the device advertising [`crate::ble::pairing_key`].
    /// The failed attempts on both carriers count against the one code.
    pub fn with_channels(mut self, channels: mpsc::Receiver<(BoxChannel, Vec<u8>)>) -> Shower {
        self.channels = Some(channels);
        self
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
        let within = self.attempt_timeout;
        let mut state = ShowerState {
            pw: Zeroizing::new(self.code.password()),
            code: self.code,
            local: self.local,
            failures: 0,
            starts: VecDeque::new(),
            attempt: None,
        };
        let socket = self.socket;
        let mut incoming = self.channels;
        let mut reads: tokio::task::JoinSet<ChannelRead> = tokio::task::JoinSet::new();
        let mut next_channel = 0u64;
        let mut buf = vec![0u8; MAX_MESSAGE];
        let read_next = |reads: &mut tokio::task::JoinSet<ChannelRead>, id, mut ch: BoxChannel| {
            reads.spawn(async move {
                let r = tokio::time::timeout(CHANNEL_QUIET, read_message(&mut ch)).await;
                let r = r.unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into()));
                (id, ch, r)
            });
        };
        loop {
            let wake = state.deadline(within).unwrap_or(deadline).min(deadline);
            tokio::select! {
                r = socket.recv_from(&mut buf) => {
                    let (n, from) = r?;
                    match state.heard(From::Udp(from), &buf[..n])? {
                        Heard::Answer(ms) => {
                            for m in ms {
                                let _ = socket.send_to(&m, from).await;
                            }
                        }
                        Heard::Failed => {}
                        Heard::Done(paired, reply) => {
                            let _ = socket.send_to(&reply, from).await;
                            // Keep answering retransmissions for a little while.
                            tokio::spawn(async move {
                                let mut b = vec![0u8; MAX_MESSAGE];
                                let end = Instant::now() + Duration::from_secs(5);
                                while let Ok(Ok((n, f))) =
                                    tokio::time::timeout_at(end, socket.recv_from(&mut b)).await
                                {
                                    if f == from
                                        && parse(&b[..n]).is_some_and(|(op, _)| op == OP_INFO)
                                    {
                                        let _ = socket.send_to(&reply, f).await;
                                    }
                                }
                            });
                            return Ok(*paired);
                        }
                    }
                }
                ch = async {
                    match incoming.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    let Some((ch, first)) = ch else {
                        incoming = None;
                        continue;
                    };
                    if reads.len() >= MAX_CHANNELS {
                        continue; // dropped, and so closed
                    }
                    next_channel += 1;
                    // Its first message, as if it had just been read.
                    let id = next_channel;
                    reads.spawn(async move { (id, ch, Ok(first)) });
                }
                Some(r) = reads.join_next(), if !reads.is_empty() => {
                    let Ok((id, mut ch, read)) = r else { continue };
                    let Ok(m) = read else { continue };
                    match state.heard(From::Channel(id), &m)? {
                        Heard::Answer(ms) => {
                            if ms.is_empty() || write_messages(&mut ch, &ms).await.is_ok() {
                                read_next(&mut reads, id, ch);
                            }
                        }
                        Heard::Failed => {}
                        Heard::Done(paired, reply) => {
                            write_messages(&mut ch, &[reply]).await?;
                            let mut paired = *paired;
                            paired.channel = Some(ch);
                            return Ok(paired);
                        }
                    }
                }
                _ = tokio::time::sleep_until(wake) => {
                    if Instant::now() >= deadline {
                        return Err(ContactError::Timeout);
                    }
                    state.expire(Instant::now(), within)?;
                }
            }
        }
    }
}

/// What a typer speaks over: a UDP socket connected to the shower, or a
/// channel.
enum Wire<'a> {
    Udp(UdpSocket),
    Channel(&'a mut BoxChannel),
}

impl Wire<'_> {
    async fn send(&mut self, ms: &[Vec<u8>]) -> std::io::Result<()> {
        match self {
            Wire::Udp(s) => {
                for m in ms {
                    s.send(m).await?;
                }
                Ok(())
            }
            Wire::Channel(ch) => write_messages(ch, ms).await,
        }
    }

    /// The next message, or `None` once `until` passed.
    async fn recv(&mut self, until: Instant) -> std::io::Result<Option<Vec<u8>>> {
        match self {
            Wire::Udp(s) => {
                let mut b = vec![0u8; MAX_MESSAGE];
                match tokio::time::timeout_at(until, s.recv(&mut b)).await {
                    Ok(r) => {
                        b.truncate(r?);
                        Ok(Some(b))
                    }
                    Err(_) => Ok(None),
                }
            }
            Wire::Channel(ch) => match tokio::time::timeout_at(until, read_message(ch)).await {
                Ok(r) => r.map(Some),
                Err(_) => Ok(None),
            },
        }
    }

    /// Sends `ms`, then takes what comes until `take` has what it wants:
    /// over UDP sending again every [`RETRANSMIT`], over a channel once.
    async fn ask<T>(
        &mut self,
        ms: &[Vec<u8>],
        deadline: Instant,
        mut take: impl FnMut(u64, &Record) -> Result<Option<T>, ContactError>,
    ) -> Result<T, ContactError> {
        let resend = matches!(self, Wire::Udp(_));
        loop {
            self.send(ms).await?;
            let until = if resend {
                (Instant::now() + RETRANSMIT).min(deadline)
            } else {
                deadline
            };
            while let Some(m) = self.recv(until).await? {
                if let Some((op, rec)) = parse(&m) {
                    if let Some(t) = take(op, &rec)? {
                        return Ok(t);
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err(ContactError::Timeout);
            }
        }
    }
}

/// The typing side over UDP: pairs with the shower at `shower` using
/// `code`. Fails with [`ContactError::WrongCode`] if the codes differ.
pub async fn pair_typer(
    local: &LocalDevice,
    code: &PairingCode,
    shower: SocketAddr,
    timeout: Duration,
) -> Result<Paired, ContactError> {
    if local.identity.is_none() {
        return Err(ContactError::NoIdentity);
    }
    let mut wire = Wire::Udp(bind_toward(shower).await?);
    typer(local, code, &mut wire, timeout).await
}

/// The typing side over a channel to the shower (Bluetooth): the same
/// exchange, each message prefixed by its length. The channel then carries
/// the link session ([`Paired::target_on`]).
pub async fn pair_typer_on(
    local: &LocalDevice,
    code: &PairingCode,
    channel: &mut BoxChannel,
    timeout: Duration,
) -> Result<Paired, ContactError> {
    if local.identity.is_none() {
        return Err(ContactError::NoIdentity);
    }
    typer(local, code, &mut Wire::Channel(channel), timeout).await
}

async fn typer(
    local: &LocalDevice,
    code: &PairingCode,
    wire: &mut Wire<'_>,
    timeout: Duration,
) -> Result<Paired, ContactError> {
    let deadline = Instant::now() + timeout;
    // Step 1: each side's random value, for the session id.
    let mine: [u8; RANDOM_LEN] = random_bytes();
    let theirs = wire
        .ask(&[msg(OP_START, &mine)], deadline, |op, rec| {
            Ok((op == OP_START)
                .then(|| rec.bytes_n::<RANDOM_LEN>(1).ok())
                .flatten())
        })
        .await?;
    let sid = session_id(code.channel, &theirs, &mine);
    let cp = Cpace::start(CpaceRole::Initiator, &code.password(), b"", &sid, b"");
    let own_share = *cp.share();

    // Step 2: our share out; their share and tag back.
    let mut cp = Some(cp);
    let mut k: Option<Zeroizing<[u8; 32]>> = None;
    let mut their_share = Vec::new();
    let mut their_tag: Option<Vec<u8>> = None;
    wire.ask(&[msg(OP_SHARE, &own_share)], deadline, |op, rec| {
        match op {
            OP_SHARE if k.is_none() => {
                if let Ok(share) = rec.bytes(1) {
                    let c = cp.take().expect("cpace");
                    let isk = c.finish(share, b"").map_err(|_| ContactError::WrongCode)?;
                    k = Some(isk.key32());
                    their_share = share.to_vec();
                }
            }
            OP_TAG => {
                if let Ok(t) = rec.bytes(1) {
                    their_tag = Some(t.to_vec());
                }
            }
            _ => {}
        }
        Ok((k.is_some() && their_tag.is_some()).then_some(()))
    })
    .await?;
    let k = k.expect("k");
    // Step 3: our tag, always, so a wrong code counts against the code.
    let tag_msg = msg(OP_TAG, &confirm_tag(&k, &own_share));
    wire.send(std::slice::from_ref(&tag_msg)).await?;
    if !ct_eq(
        their_tag.as_deref().unwrap_or_default(),
        &confirm_tag(&k, &their_share),
    ) {
        return Err(ContactError::WrongCode);
    }
    // Step 4: our information, with the power we add a new device at; then
    // theirs. Over UDP the tag goes again with it, in case it was lost.
    let info = seal_info(&k, local, None, PairRole::Typer);
    let ms = match wire {
        Wire::Udp(_) => vec![tag_msg, info],
        Wire::Channel(_) => vec![info],
    };
    let peer = wire
        .ask(&ms, deadline, |op, rec| {
            Ok((op == OP_INFO)
                .then(|| open_info(&k, rec, PairRole::Shower).ok())
                .flatten())
        })
        .await?;
    let new_device = match (peer.identity, peer.proof, local.identity) {
        (None, Some(proof), Some(id)) => {
            // Signed for exactly the power named, or refused.
            let power = local.adds_at.ok_or(ContactError::BadProof)?;
            let d = NewDevice {
                identity: id,
                signing_key: peer.signing_key,
                power,
                link_key: peer.link_key.clone(),
                proof,
                name: peer.name.clone(),
            };
            Some(d.verify().then_some(d).ok_or(ContactError::BadProof)?)
        }
        (None, None, _) => return Err(ContactError::BadProof),
        _ => None,
    };
    Ok(Paired {
        role: PairRole::Typer,
        peer,
        link_secret: derive(Purpose::Invite, &k[..]),
        new_device,
        joins_at: None,
        channel: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cardinal_crypto::HybridKeyPair;

    fn device(n: u8, identity: Option<[u8; 32]>, adds_at: Option<u64>) -> LocalDevice {
        LocalDevice {
            identity,
            signing_key: Arc::new(SigningKey::from_seed(&[n; 32])),
            link_key: HybridKeyPair::from_seed(&[n; 32]).public_key().clone(),
            link_endpoint: EndpointAddr::new(
                cardinal_link::CarrierKind::Tcp,
                "127.0.0.1:1".parse().unwrap(),
            ),
            name: format!("d{n}"),
            adds_at,
        }
    }

    #[test]
    fn the_session_id_takes_no_address() {
        let (a, b) = ([1; RANDOM_LEN], [2; RANDOM_LEN]);
        assert_eq!(session_id(4, &a, &b), session_id(4, &a, &b));
        assert_ne!(session_id(4, &a, &b), session_id(4, &b, &a));
        assert_ne!(session_id(4, &a, &b), session_id(5, &a, &b));
        let mut ch = Vec::new();
        write_varint(4, &mut ch);
        assert_eq!(
            session_id(4, &a, &b),
            hash_parts(&[b"cardinal 1 pair", &ch, &a, &b])
        );
    }

    #[test]
    fn pairing_messages_are_told_from_link_packets_by_their_first_byte() {
        assert!(is_pairing_message(&msg(OP_START, &[0; RANDOM_LEN])));
        assert!(is_pairing_message(&msg(OP_SHARE, &[0; 32])));
        for t in 1..=4u8 {
            assert!(!is_pairing_message(&[t, 0, 0, 0]), "link packet type {t}");
        }
        assert!(!is_pairing_message(&[]));
    }

    /// The review of 2026-11-22: an attempt that passed its tag check and
    /// is then displaced by a new one counts as failed, as an unconfirmed
    /// one does, so even one who knows the code gets three attempts.
    #[test]
    fn a_displaced_confirmed_attempt_counts_as_failed() {
        let code = PairingCode::generate();
        let mut state = ShowerState {
            pw: Zeroizing::new(code.password()),
            code: code.clone(),
            local: device(2, None, None),
            failures: 0,
            starts: VecDeque::new(),
            attempt: None,
        };
        let confirmed = |state: &mut ShowerState, port: u16| -> Result<(), ContactError> {
            let from = From::Udp(SocketAddr::from(([127, 0, 0, 1], port)));
            let typer: [u8; RANDOM_LEN] = random_bytes();
            let Heard::Answer(a) = state.heard(from, &msg(OP_START, &typer))? else {
                panic!("a start is answered")
            };
            let (_, r) = parse(&a[0]).unwrap();
            let shower = r.bytes_n::<RANDOM_LEN>(1).unwrap();
            let sid = session_id(code.channel, &shower, &typer);
            let cp = Cpace::start(CpaceRole::Initiator, &code.password(), b"", &sid, b"");
            let share = *cp.share();
            let Heard::Answer(a) = state.heard(from, &msg(OP_SHARE, &share))? else {
                panic!("a share is answered")
            };
            let (_, r) = parse(&a[0]).unwrap();
            let k = cp.finish(r.bytes(1).unwrap(), b"").unwrap().key32();
            state.heard(from, &msg(OP_TAG, &confirm_tag(&k, &share)))?;
            assert!(state.attempt.as_ref().unwrap().confirmed);
            Ok(())
        };
        confirmed(&mut state, 1).unwrap();
        assert_eq!(state.failures, 0);
        confirmed(&mut state, 2).unwrap();
        assert_eq!(state.failures, 1, "the first, displaced, failed");
        confirmed(&mut state, 3).unwrap();
        assert!(matches!(
            confirmed(&mut state, 4),
            Err(ContactError::TooManyAttempts)
        ));
    }

    /// Each side's information is sealed for its direction: the typer's
    /// sent back to it does not open as the shower's.
    #[test]
    fn pairing_information_is_sealed_for_its_direction() {
        let k = [7u8; 32];
        let local = device(3, Some([9; 32]), Some(POWER_DEVICE));
        let (_, rec) = parse(&seal_info(&k, &local, None, PairRole::Typer)).unwrap();
        assert!(open_info(&k, &rec, PairRole::Typer).is_ok());
        assert!(open_info(&k, &rec, PairRole::Shower).is_err());
    }

    /// A shower that signs for admin power whatever the typer named.
    #[tokio::test]
    async fn a_proof_for_another_power_than_named_is_refused() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let code = PairingCode::generate();
        let local = device(2, None, None);
        let mut state = ShowerState {
            pw: Zeroizing::new(code.password()),
            code: code.clone(),
            local: local.clone(),
            failures: 0,
            starts: VecDeque::new(),
            attempt: None,
        };
        let rogue = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_MESSAGE];
            loop {
                let (n, from) = socket.recv_from(&mut buf).await.unwrap();
                let m = buf[..n].to_vec();
                if parse(&m).is_some_and(|(op, _)| op == OP_INFO) {
                    if let Some(a) = state.attempt.as_ref().filter(|a| a.confirmed) {
                        let (_, rec) = parse(&m).unwrap();
                        let peer = open_info(&a.k, &rec, PairRole::Typer).unwrap();
                        assert_eq!(peer.power, Some(POWER_DEVICE));
                        let proof = local.signing_key.sign(&proof_message(
                            &peer.identity.unwrap(),
                            &local.signing_key.public_key(),
                            POWER_ADMIN,
                            &local.link_key,
                        ));
                        let reply = seal_info(&a.k, &local, Some(proof), PairRole::Shower);
                        socket.send_to(&reply, from).await.unwrap();
                        continue;
                    }
                }
                if let Ok(Heard::Answer(ms)) = state.heard(From::Udp(from), &m) {
                    for r in ms {
                        socket.send_to(&r, from).await.unwrap();
                    }
                }
            }
        });
        let admin = device(1, Some([0xaa; 32]), Some(POWER_DEVICE));
        let r = pair_typer(&admin, &code, addr, Duration::from_secs(5)).await;
        assert!(matches!(r, Err(ContactError::BadProof)), "{r:?}");
        rogue.abort();
    }
}
