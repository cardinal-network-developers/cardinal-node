//! The session core: a synchronous state machine for one session. It
//! decrypts and processes packets, builds outgoing packets, and keeps
//! streams, flow control, acknowledgements, retransmission, rekeys, device
//! proofs, and paths. The [`Session`](crate::Session) driver and the
//! carriers move bytes in and out; nothing here performs I/O.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use bytes::Bytes;
use cardinal_crypto::{kem::KemSecretKey, random_bytes, verify, HybridPublicKey, KemPublicKey};
use tokio::sync::{mpsc, Notify};
use zeroize::Zeroizing;

use crate::carrier::Path;
use crate::directory::{ExpectedPeer, LocalIdentity, PeerDirectory, PeerIdentity};
use crate::frame::{
    decode_frames, encode_stream_frame, encode_stream_frame_parts, stream_frame_overhead, AckRange,
    DeviceProof, Frame, Priority, Service, StreamFrame, DEVICE_PROOF_DOMAIN,
};
use crate::handshake::{self, Keys};
use crate::keys::{DirKey, RangeSet, ReplayWindow};
use crate::packet::{
    self, DATA_HEADER_LEN, DATA_MAX_LEN_REKEY, DATA_MIN_LEN, MAX_PLAINTEXT, TAG_LEN,
};

/// Initial per-stream window (`link.md#streams`).
pub const STREAM_WINDOW: u64 = 256 * 1024;
/// Initial per-session window.
pub const SESSION_WINDOW: u64 = 1024 * 1024;
/// Bytes an application may buffer in one stream before writes wait.
const SEND_BUFFER: usize = 1024 * 1024;
/// How long the previous key phase is accepted after a switch.
const PREV_KEY_LIFETIME: Duration = Duration::from_secs(5);
/// Longest an acknowledgement is delayed.
const MAX_ACK_DELAY: Duration = Duration::from_millis(10);
/// Ranges kept for acknowledgements.
const MAX_ACK_RANGES: usize = 32;
/// Limit on streams the peer may have open at once.
const MAX_INCOMING_STREAMS: usize = 4096;
/// Packets in flight on unreliable carriers (a fixed window; there is no
/// congestion control yet).
const MAX_IN_FLIGHT: usize = 128;
/// Queued outgoing datagrams per priority class before the oldest drop.
const MAX_DATAGRAM_QUEUE: usize = 1024;
/// Queued incoming datagrams per channel before new ones drop.
pub(crate) const CHANNEL_QUEUE: usize = 1024;

/// Which side of the handshake this device was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Sent the initiation.
    Initiator,
    /// Answered it.
    Responder,
}

/// Timing parameters of a session.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// The initiator rekeys after this much time with activity
    /// (`link.md`: two minutes).
    pub rekey_interval: Duration,
    /// ... or after this many packets (`link.md`: 2^40).
    pub rekey_packets: u64,
    /// A session is closed after this long without traffic (`link.md`:
    /// three minutes).
    pub idle_timeout: Duration,
    /// If set, a ping is sent after this long without sending, to hold NAT
    /// mappings open (`link.md`: 25 seconds for reachability sessions).
    pub keepalive: Option<Duration>,
    /// How long the handshake, proofs, and first rekey may take.
    pub establish_timeout: Duration,
}

impl Default for SessionConfig {
    fn default() -> SessionConfig {
        SessionConfig {
            rekey_interval: Duration::from_secs(120),
            rekey_packets: 1 << 40,
            idle_timeout: Duration::from_secs(180),
            keepalive: None,
            establish_timeout: Duration::from_secs(15),
        }
    }
}

/// How the session was admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The peer's static key is known to the directory.
    Known,
    /// The handshake used a secret (invitation, pairing, token); the value
    /// is the secret's id at the endpoint that issued it, or 0 on the
    /// initiator's side.
    Secret {
        /// Secret id.
        id: u64,
        /// Who may complete it.
        expected: ExpectedPeer,
    },
    /// A public-service or restore session without a secret
    /// (`hosts.md`).
    Public,
}

/// Session counters.
#[derive(Clone, Copy, Debug, Default)]
pub struct SessionStats {
    /// Data packets sent.
    pub packets_sent: u64,
    /// Data packets received and authenticated.
    pub packets_received: u64,
    /// Bytes of data packets sent.
    pub bytes_sent: u64,
    /// Bytes of data packets received.
    pub bytes_received: u64,
    /// Packets dropped: failed authentication, replays, malformed.
    pub packets_dropped: u64,
    /// Completed rekeys, including the mandatory first one.
    pub rekeys: u64,
    /// Packets declared lost (unreliable carriers only).
    pub packets_lost: u64,
    /// The current key phase (0 or 1).
    pub key_phase: u8,
    /// Smoothed round-trip time, unreliable carriers only.
    pub srtt: Option<Duration>,
}

/// Why a session closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// Closed by this device, with a reason.
    Local(String),
    /// Closed by the peer, with its reason.
    Remote(String),
    /// No traffic for the idle timeout.
    Idle,
    /// The session was not established in time.
    Timeout,
    /// The peer violated the protocol.
    Protocol(String),
    /// The carrier failed.
    Carrier,
    /// The peer's device proof was not acceptable, or its key is no
    /// longer effective.
    Identity,
    /// Replaced by a newer session with the same peer.
    Replaced,
    /// The endpoint shut down.
    EndpointClosed,
}

impl std::fmt::Display for CloseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloseReason::Local(r) => write!(f, "closed locally: {r}"),
            CloseReason::Remote(r) => write!(f, "closed by peer: {r}"),
            CloseReason::Idle => f.write_str("idle"),
            CloseReason::Timeout => f.write_str("not established in time"),
            CloseReason::Protocol(r) => write!(f, "protocol violation: {r}"),
            CloseReason::Carrier => f.write_str("carrier failed"),
            CloseReason::Identity => f.write_str("device proof rejected"),
            CloseReason::Replaced => f.write_str("replaced by a newer session"),
            CloseReason::EndpointClosed => f.write_str("endpoint closed"),
        }
    }
}

/// Things the owner of a session must act on, drained after each call.
#[derive(Debug)]
pub(crate) enum ConnEvent {
    /// The responder saw its first authenticated data packet: the
    /// initiation's counter is now confirmed.
    Confirmed { counter: u64 },
    /// Both proofs verified and the first rekey completed.
    Established,
    /// The session closed.
    Closed(CloseReason),
}

/// Wakeups shared between the core and its handles.
#[derive(Default)]
pub(crate) struct Signals {
    /// Something to send, or timers changed (single waiter: the driver).
    pub driver: Notify,
    /// Established, closed, or a new incoming stream (many waiters).
    pub state: Notify,
}

enum RekeyState {
    Idle,
    /// Initiator: sent `rekey`, waiting for the reply.
    Sent {
        kem: Box<KemSecretKey>,
        pk: Vec<u8>,
    },
    /// Responder: replied, waiting for the first packet in the new phase.
    Replied {
        pk_hash: [u8; 32],
        ct: Vec<u8>,
    },
}

/// A frame that may need resending if its packet is lost.
#[derive(Clone, Debug)]
enum Retx {
    Stream {
        id: u64,
        off: u64,
        len: u64,
        fin: bool,
    },
    Window(u64),
    Control(Frame),
}

struct SentPacket {
    time: Instant,
    frames: Vec<Retx>,
}

#[derive(Default)]
struct StreamState {
    service: Option<Service>,
    priority: Option<Priority>,
    local: bool,
    // Send side.
    send_buf: VecDeque<u8>,
    send_base: u64,
    send_next: u64,
    send_max: u64,
    fin_requested: bool,
    fin_sent: bool,
    fin_acked: bool,
    retx_fin: bool,
    acked: RangeSet,
    retx: RangeSet,
    write_waker: Option<Waker>,
    // Receive side.
    recv_ready: VecDeque<Bytes>,
    recv_read: u64,
    recv_contig: u64,
    recv_highest: u64,
    recv_ooo: BTreeMap<u64, Bytes>,
    recv_max: u64,
    recv_fin: Option<u64>,
    read_waker: Option<Waker>,
    // Lifecycle.
    reset_remote: Option<u64>,
    reset_local: bool,
    handle_dropped: bool,
    announced: bool,
}

impl StreamState {
    fn send_end(&self) -> u64 {
        self.send_base + self.send_buf.len() as u64
    }

    fn priority(&self) -> Priority {
        self.priority.unwrap_or(Priority::Interactive)
    }

    fn send_done(&self, reliable: bool) -> bool {
        self.reset_local
            || self.reset_remote.is_some()
            || (self.fin_sent && (reliable || self.fin_acked) && self.send_buf.is_empty())
    }

    fn recv_done(&self) -> bool {
        self.reset_local
            || self.reset_remote.is_some()
            || self.recv_fin.is_some_and(|f| self.recv_read >= f)
    }
}

struct Challenge {
    path: Path,
    data: [u8; 8],
    sent_at: Option<Instant>,
    tries: u32,
}

/// Parameters for a new session core.
pub(crate) struct ConnParams {
    pub role: Role,
    pub local_index: u32,
    pub remote_index: u32,
    pub keys: Keys,
    pub peer_static: [u8; 32],
    pub peer_link_key: Option<HybridPublicKey>,
    pub local_identity: Option<LocalIdentity>,
    pub directory: Arc<dyn PeerDirectory>,
    pub admission: Admission,
    pub path: Path,
    pub initiation_counter: u64,
    pub config: SessionConfig,
    pub signals: Arc<Signals>,
}

pub(crate) struct Conn {
    pub role: Role,
    #[allow(dead_code)]
    pub local_index: u32,
    remote_index: u32,
    pub peer_static: [u8; 32],
    pub peer_link_key: Option<HybridPublicKey>,
    pub handshake_hash: [u8; 32],
    pub admission: Admission,
    pub initiation_counter: u64,
    ck: Zeroizing<[u8; 32]>,
    config: SessionConfig,
    directory: Arc<dyn PeerDirectory>,
    pub signals: Arc<Signals>,
    events: Vec<ConnEvent>,

    // Keys.
    send_key: DirKey,
    recv_cur: DirKey,
    recv_prev: Option<(DirKey, Instant)>,
    recv_next: Option<DirKey>,
    send_next_key: Option<DirKey>,
    send_counter: u64,
    replay: ReplayWindow,
    rekey: RekeyState,
    last_rekey: Instant,
    activity_since_rekey: bool,
    packets_since_rekey: u64,

    // Identity.
    local_identity: Option<LocalIdentity>,
    own_proof_sent: bool,
    peer_proof_done: bool,
    pub peer_identity: Option<PeerIdentity>,
    confirmed: bool,
    initial_rekey_done: bool,
    pub established: bool,
    pub established_at: Option<Instant>,
    created: Instant,

    // Reliability.
    reliable: bool,
    control: VecDeque<Frame>,
    pending_window: HashSet<u64>,
    sent: BTreeMap<u64, SentPacket>,
    largest_acked: Option<u64>,
    srtt: Option<Duration>,
    rttvar: Duration,
    pto_count: u32,
    recv_ranges: RangeSet,
    largest_recv_time: Option<Instant>,
    unacked_eliciting: u32,
    ack_due: Option<Instant>,

    // Streams.
    streams: BTreeMap<u64, StreamState>,
    next_local_stream: u64,
    highest_peer_stream: u64,
    incoming: VecDeque<u64>,
    rr_cursor: [u64; 3],
    session_send_max: u64,
    session_sent: u64,
    session_recv_max: u64,
    session_recv_total: u64,
    session_consumed: u64,

    // Datagrams.
    channels: HashMap<[u8; 16], (Priority, mpsc::Sender<Bytes>)>,
    dgram_out: [VecDeque<([u8; 16], Bytes)>; 3],

    // Paths.
    pub path: Path,
    challenge: Option<Challenge>,
    path_responses: Vec<(Path, [u8; 8])>,
    pub observed_by_peer: Option<std::net::SocketAddr>,

    // Lifecycle.
    pub close: Option<CloseReason>,
    close_frame: Option<String>,
    last_recv: Instant,
    last_send: Instant,
    pub stats: SessionStats,
    scratch: Vec<u8>,
}

impl Conn {
    pub fn new(p: ConnParams, now: Instant) -> Conn {
        let (send, recv) = match p.role {
            Role::Initiator => (
                &p.keys.initiator_to_responder,
                &p.keys.responder_to_initiator,
            ),
            Role::Responder => (
                &p.keys.responder_to_initiator,
                &p.keys.initiator_to_responder,
            ),
        };
        let reliable = p.path.is_reliable();
        let mut c = Conn {
            role: p.role,
            local_index: p.local_index,
            remote_index: p.remote_index,
            peer_static: p.peer_static,
            peer_link_key: p.peer_link_key,
            handshake_hash: p.keys.h,
            admission: p.admission,
            initiation_counter: p.initiation_counter,
            ck: p.keys.ck.clone(),
            config: p.config,
            directory: p.directory,
            signals: p.signals,
            events: Vec::new(),
            send_key: DirKey::new(send, 0),
            recv_cur: DirKey::new(recv, 0),
            recv_prev: None,
            recv_next: None,
            send_next_key: None,
            send_counter: 0,
            replay: ReplayWindow::new(),
            rekey: RekeyState::Idle,
            last_rekey: now,
            activity_since_rekey: false,
            packets_since_rekey: 0,
            local_identity: p.local_identity,
            own_proof_sent: false,
            peer_proof_done: false,
            peer_identity: None,
            confirmed: p.role == Role::Initiator,
            initial_rekey_done: false,
            established: false,
            established_at: None,
            created: now,
            reliable,
            control: VecDeque::new(),
            pending_window: HashSet::new(),
            sent: BTreeMap::new(),
            largest_acked: None,
            srtt: None,
            rttvar: Duration::from_millis(50),
            pto_count: 0,
            recv_ranges: RangeSet::new(),
            largest_recv_time: None,
            unacked_eliciting: 0,
            ack_due: None,
            streams: BTreeMap::new(),
            next_local_stream: if p.role == Role::Initiator { 1 } else { 2 },
            highest_peer_stream: 0,
            incoming: VecDeque::new(),
            rr_cursor: [0; 3],
            session_send_max: SESSION_WINDOW,
            session_sent: 0,
            session_recv_max: SESSION_WINDOW,
            session_recv_total: 0,
            session_consumed: 0,
            channels: HashMap::new(),
            dgram_out: Default::default(),
            path: p.path,
            challenge: None,
            path_responses: Vec::new(),
            observed_by_peer: None,
            close: None,
            close_frame: None,
            last_recv: now,
            last_send: now,
            stats: SessionStats::default(),
            scratch: Vec::with_capacity(packet::MAX_DATAGRAM),
        };
        if c.role == Role::Initiator {
            // Device proof first, then the mandatory post-quantum rekey.
            let proof = c.own_proof();
            c.control.push_back(proof);
            c.start_rekey(now);
        }
        c
    }

    fn own_proof(&self) -> Frame {
        Frame::DeviceProof(self.local_identity.as_ref().map(|id| {
            let mut msg = DEVICE_PROOF_DOMAIN.to_vec();
            msg.extend_from_slice(&self.handshake_hash);
            DeviceProof {
                identity: id.identity,
                signing_key: id.signing_key.public_key(),
                signature: id.signing_key.sign(&msg),
            }
        }))
    }

    fn start_rekey(&mut self, now: Instant) {
        let kem = KemSecretKey::generate();
        let pk = kem.public_key().as_bytes().to_vec();
        self.control.push_back(Frame::Rekey(pk.clone()));
        self.rekey = RekeyState::Sent {
            kem: Box::new(kem),
            pk,
        };
        self.last_rekey = now;
        self.activity_since_rekey = false;
    }

    pub fn drain_events(&mut self) -> Vec<ConnEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn is_closed(&self) -> bool {
        self.close.is_some()
    }

    /// Whether everything that must go out before the session ends (the
    /// close frame) has gone.
    pub fn is_drained(&self) -> bool {
        self.close.is_some() && self.close_frame.is_none()
    }

    #[cfg(test)]
    pub fn key_phase(&self) -> u8 {
        self.send_key.phase
    }

    pub fn stats(&self) -> SessionStats {
        let mut s = self.stats;
        s.key_phase = self.send_key.phase;
        s.srtt = self.srtt;
        s
    }

    fn wake_all(&mut self) {
        for s in self.streams.values_mut() {
            if let Some(w) = s.read_waker.take() {
                w.wake();
            }
            if let Some(w) = s.write_waker.take() {
                w.wake();
            }
        }
        self.signals.state.notify_waiters();
        self.signals.driver.notify_one();
    }

    /// Closes the session, sending a `close` frame.
    pub fn close_local(&mut self, reason: CloseReason) {
        if self.close.is_some() {
            return;
        }
        let text = match &reason {
            CloseReason::Local(r) => r.clone(),
            other => other.to_string(),
        };
        // Before confirmation the responder may not send at all.
        if self.confirmed {
            self.close_frame = Some(text);
        }
        self.close = Some(reason.clone());
        self.channels.clear();
        self.events.push(ConnEvent::Closed(reason));
        self.wake_all();
    }

    fn close_silently(&mut self, reason: CloseReason) {
        if self.close.is_some() {
            return;
        }
        self.close = Some(reason.clone());
        self.channels.clear();
        self.events.push(ConnEvent::Closed(reason));
        self.wake_all();
    }

    fn maybe_establish(&mut self, now: Instant) {
        if self.established
            || self.close.is_some()
            || !self.peer_proof_done
            || !self.own_proof_sent
            || !self.initial_rekey_done
        {
            return;
        }
        self.established = true;
        self.established_at = Some(now);
        if let Some(addr) = self.path.remote_addr() {
            self.control.push_back(Frame::ObservedAddress(addr));
        }
        self.events.push(ConnEvent::Established);
        self.signals.state.notify_waiters();
        self.signals.driver.notify_one();
    }

    // ------------------------------------------------------------------
    // Receiving.

    /// Processes a data packet. Returns whether it authenticated.
    pub fn recv_packet(&mut self, pkt: &mut [u8], path: &Path, now: Instant) -> bool {
        if self.close.is_some() {
            return false;
        }
        if pkt.len() < DATA_MIN_LEN
            || pkt.len() > DATA_MAX_LEN_REKEY
            || pkt[0] != packet::TYPE_DATA
            || pkt[1] > 1
            || pkt[2..4] != [0, 0]
        {
            self.stats.packets_dropped += 1;
            return false;
        }
        let counter = packet::read_u64(pkt, 8);
        if !self.replay.check(counter) {
            self.stats.packets_dropped += 1;
            return false;
        }
        let phase = pkt[1];
        let mut opened = None;
        let mut via_next = false;
        if phase == self.recv_cur.phase {
            opened = self.recv_cur.open(counter, pkt);
        }
        if opened.is_none() {
            if let Some(next) = &self.recv_next {
                if next.phase == phase {
                    opened = next.open(counter, pkt);
                    via_next = opened.is_some();
                }
            }
        }
        if opened.is_none() {
            if let Some((prev, exp)) = &self.recv_prev {
                if prev.phase == phase && now < *exp {
                    opened = prev.open(counter, pkt);
                }
            }
        }
        let Some(range) = opened else {
            self.stats.packets_dropped += 1;
            return false;
        };
        self.replay.update(counter);
        self.stats.packets_received += 1;
        self.stats.bytes_received += pkt.len() as u64;
        self.last_recv = now;
        self.activity_since_rekey = true;

        if via_next {
            // Responder: the initiator has switched; switch too.
            let next = self.recv_next.take().expect("next key");
            let old = std::mem::replace(&mut self.recv_cur, next);
            self.recv_prev = Some((old, now + PREV_KEY_LIFETIME));
            if let Some(sk) = self.send_next_key.take() {
                self.send_key = sk;
            }
            self.rekey = RekeyState::Idle;
            self.stats.rekeys += 1;
            self.last_rekey = now;
            self.packets_since_rekey = 0;
            self.initial_rekey_done = true;
        }

        if !self.confirmed {
            // The first authenticated data packet proves the initiator
            // holds its private key: confirm its counter, then answer with
            // our own device proof.
            self.confirmed = true;
            self.events.push(ConnEvent::Confirmed {
                counter: self.initiation_counter,
            });
            let proof = self.own_proof();
            self.control.push_front(proof);
        }

        let frames = match decode_frames(&pkt[range]) {
            Ok(f) => f,
            Err(e) => {
                self.close_local(CloseReason::Protocol(e.to_string()));
                return true;
            }
        };
        self.maybe_establish(now);
        if !self.established && frames.iter().any(|f| !f.allowed_before_proofs()) {
            // Data that overtook a device proof on an unreliable carrier.
            // Not acknowledged, so it will be resent.
            if self.reliable {
                self.close_local(CloseReason::Protocol("frame before device proof".into()));
            }
            self.maybe_establish(now);
            return true;
        }

        let eliciting = frames.iter().any(Frame::is_ack_eliciting);
        let mut urgent = false;
        for f in frames {
            if matches!(
                f,
                Frame::Rekey(_)
                    | Frame::RekeyReply(_)
                    | Frame::DeviceProof(_)
                    | Frame::PathChallenge(_)
                    | Frame::Ping
            ) {
                urgent = true;
            }
            self.on_frame(f, path, now);
            if self.close.is_some() {
                return true;
            }
        }

        // Acknowledgement state.
        self.recv_ranges.insert(counter, counter + 1);
        while self.recv_ranges.len() > MAX_ACK_RANGES {
            self.recv_ranges.pop_lowest();
        }
        if self.recv_ranges.iter_desc().next().map(|(_, e)| e - 1) == Some(counter) {
            self.largest_recv_time = Some(now);
        }
        if eliciting {
            self.unacked_eliciting += 1;
            let every = if self.reliable { 32 } else { 2 };
            if urgent || self.unacked_eliciting >= every {
                self.ack_due = Some(now);
            } else if self.ack_due.is_none() {
                self.ack_due = Some(now + MAX_ACK_DELAY);
            }
        }

        // A packet from a new address: validate the path before moving.
        if !path.same(&self.path) && self.challenge.as_ref().is_none_or(|c| !c.path.same(path)) {
            self.challenge = Some(Challenge {
                path: path.clone(),
                data: random_bytes::<8>(),
                sent_at: None,
                tries: 0,
            });
        }
        self.maybe_establish(now);
        // Wake the driver only when there is something for it: an ack due
        // now, a newly armed ack timer, or queued frames.
        if self.ack_due.is_some_and(|d| d <= now)
            || (eliciting && self.unacked_eliciting == 1)
            || !self.control.is_empty()
            || !self.pending_window.is_empty()
            || !self.path_responses.is_empty()
            || self.challenge.as_ref().is_some_and(|c| c.sent_at.is_none())
            || !self.sent.is_empty()
            || self.has_stream_work()
        {
            self.signals.driver.notify_one();
        }
        true
    }

    fn on_frame(&mut self, f: Frame, path: &Path, now: Instant) {
        match f {
            Frame::Padding(_) | Frame::Ping | Frame::Unknown(_) => {}
            Frame::Ack {
                largest,
                delay_us,
                ranges,
            } => self.on_ack(largest, delay_us, &ranges, now),
            Frame::Stream(s) => {
                if let Err(e) = self.on_stream_frame(s) {
                    self.close_local(CloseReason::Protocol(e.into()));
                }
            }
            Frame::Reset { id, reason } => self.on_reset(id, reason),
            Frame::Window { id, max } => {
                if id == 0 {
                    self.session_send_max = self.session_send_max.max(max);
                } else if let Some(s) = self.streams.get_mut(&id) {
                    s.send_max = s.send_max.max(max);
                }
            }
            Frame::Datagram { channel, data } => {
                if let Some((_, tx)) = self.channels.get(&channel) {
                    let _ = tx.try_send(data);
                }
            }
            Frame::PathChallenge(d) => self.path_responses.push((path.clone(), d)),
            Frame::PathResponse(d) => {
                if let Some(c) = &self.challenge {
                    if c.data == d && c.path.same(path) {
                        let c = self.challenge.take().expect("challenge");
                        self.path = c.path;
                        if let Some(addr) = self.path.remote_addr() {
                            self.control.push_back(Frame::ObservedAddress(addr));
                        }
                    }
                }
            }
            Frame::ObservedAddress(a) => self.observed_by_peer = Some(a),
            Frame::Rekey(pk) => self.on_rekey(pk),
            Frame::RekeyReply(ct) => self.on_rekey_reply(&ct, now),
            Frame::Close(reason) => {
                self.close_silently(CloseReason::Remote(reason));
            }
            Frame::DeviceProof(p) => self.on_device_proof(p),
        }
    }

    fn on_device_proof(&mut self, p: Option<DeviceProof>) {
        if self.peer_proof_done {
            return;
        }
        let expected = match &self.admission {
            Admission::Secret { expected, .. } => Some(expected.clone()),
            Admission::Public => Some(ExpectedPeer::default()),
            Admission::Known => None,
        };
        let ok = match p {
            // An empty proof: the peer has no identity yet. Acceptable only
            // in a session opened with a secret that did not name one.
            None => expected.as_ref().is_some_and(|e| e.identity.is_none()),
            Some(p) => {
                let mut msg = DEVICE_PROOF_DOMAIN.to_vec();
                msg.extend_from_slice(&self.handshake_hash);
                if verify(&p.signing_key, &msg, &p.signature).is_err() {
                    false
                } else if self.directory.verify_device(
                    &p.identity,
                    &p.signing_key,
                    &self.peer_static,
                ) {
                    self.peer_identity = Some(PeerIdentity {
                        identity: p.identity,
                        signing_key: p.signing_key,
                        verified_by_log: true,
                    });
                    true
                } else if let Some(e) = expected {
                    let ok = !e.no_identity
                        && e.identity.is_none_or(|i| i == p.identity)
                        && e.signing_key.is_none_or(|k| k == p.signing_key);
                    if ok {
                        self.peer_identity = Some(PeerIdentity {
                            identity: p.identity,
                            signing_key: p.signing_key,
                            verified_by_log: false,
                        });
                    }
                    ok
                } else {
                    false
                }
            }
        };
        if ok {
            self.peer_proof_done = true;
        } else {
            self.close_local(CloseReason::Identity);
        }
    }

    /// Re-checks the peer's device proof against the directory (after the
    /// peer's log changed). Returns false if the session was closed.
    pub fn recheck_identity(&mut self) -> bool {
        let Some(pi) = self.peer_identity else {
            return true;
        };
        let ok = self
            .directory
            .verify_device(&pi.identity, &pi.signing_key, &self.peer_static);
        if ok {
            if let Some(p) = &mut self.peer_identity {
                p.verified_by_log = true;
            }
        } else if pi.verified_by_log {
            self.close_local(CloseReason::Identity);
            return false;
        }
        true
    }

    fn on_rekey(&mut self, pk: Vec<u8>) {
        if self.role != Role::Responder {
            self.close_local(CloseReason::Protocol("rekey from responder".into()));
            return;
        }
        let pk_hash = cardinal_crypto::hash(&pk);
        match &self.rekey {
            RekeyState::Replied { pk_hash: h, ct } if *h == pk_hash => {
                // A retransmitted rekey: resend the same reply.
                let ct = ct.clone();
                self.control.push_back(Frame::RekeyReply(ct));
                return;
            }
            RekeyState::Replied { .. } => return,
            _ => {}
        }
        let Ok(kem) = KemPublicKey::from_bytes(&pk) else {
            self.close_local(CloseReason::Protocol("rekey key".into()));
            return;
        };
        let (ct, ss) = kem.encapsulate();
        let (i2r, r2i, ck) = handshake::rekey(&self.ck, &ss);
        self.ck = ck;
        self.recv_next = Some(DirKey::new(&i2r, self.recv_cur.phase ^ 1));
        self.send_next_key = Some(DirKey::new(&r2i, self.send_key.phase ^ 1));
        self.rekey = RekeyState::Replied {
            pk_hash,
            ct: ct.to_vec(),
        };
        self.control.push_back(Frame::RekeyReply(ct.to_vec()));
    }

    fn on_rekey_reply(&mut self, ct: &[u8], now: Instant) {
        let RekeyState::Sent { kem, .. } = &self.rekey else {
            return; // A duplicate.
        };
        let Ok(ss) = kem.decapsulate(ct) else {
            self.close_local(CloseReason::Protocol("rekey reply".into()));
            return;
        };
        let (i2r, r2i, ck) = handshake::rekey(&self.ck, &ss);
        self.ck = ck;
        let phase = self.send_key.phase ^ 1;
        self.send_key = DirKey::new(&i2r, phase);
        let old = std::mem::replace(&mut self.recv_cur, DirKey::new(&r2i, phase));
        // The responder switches as soon as it sees our next packet; its
        // packets in the old phase are accepted for five seconds.
        self.recv_prev = Some((old, now + PREV_KEY_LIFETIME));
        self.rekey = RekeyState::Idle;
        self.stats.rekeys += 1;
        self.last_rekey = now;
        self.packets_since_rekey = 0;
        self.initial_rekey_done = true;
        // Answer at once in the new phase so the responder switches.
        self.ack_due = Some(now);
    }

    fn on_ack(&mut self, largest: u64, delay_us: u64, ranges: &[AckRange], now: Instant) {
        if self.reliable || self.sent.is_empty() {
            return;
        }
        // Expand ranges.
        let mut acked: Vec<(u64, u64)> = Vec::new(); // inclusive
        let mut prev_low = largest.saturating_add(1);
        for r in ranges {
            if r.length == 0 {
                break;
            }
            let Some(top) = prev_low.checked_sub(r.gap + 1) else {
                break;
            };
            let Some(low) = (top + 1).checked_sub(r.length) else {
                break;
            };
            acked.push((low, top));
            prev_low = low;
        }
        let mut newly = Vec::new();
        for &(lo, hi) in &acked {
            let keys: Vec<u64> = self.sent.range(lo..=hi).map(|(k, _)| *k).collect();
            for k in keys {
                if let Some(p) = self.sent.remove(&k) {
                    newly.push((k, p));
                }
            }
        }
        if newly.is_empty() {
            return;
        }
        if self.largest_acked.is_none_or(|l| largest > l) {
            self.largest_acked = Some(largest);
        }
        if let Some((k, p)) = newly.iter().max_by_key(|(k, _)| *k) {
            if *k == largest {
                let sample = now
                    .saturating_duration_since(p.time)
                    .saturating_sub(Duration::from_micros(delay_us.min(1_000_000)));
                match self.srtt {
                    None => {
                        self.srtt = Some(sample);
                        self.rttvar = sample / 2;
                    }
                    Some(s) => {
                        let diff = s.abs_diff(sample);
                        self.rttvar = (self.rttvar * 3 + diff) / 4;
                        self.srtt = Some((s * 7 + sample) / 8);
                    }
                }
            }
        }
        self.pto_count = 0;
        for (_, p) in newly {
            for r in p.frames {
                if let Retx::Stream { id, off, len, fin } = r {
                    if let Some(s) = self.streams.get_mut(&id) {
                        s.acked.insert(off, off + len);
                        if fin {
                            s.fin_acked = true;
                        }
                        advance_send_base(s);
                    }
                }
            }
        }
        self.detect_lost(now);
        self.gc_streams();
    }

    fn pto(&self) -> Duration {
        let srtt = self.srtt.unwrap_or(Duration::from_millis(100));
        let base = srtt + (self.rttvar * 4).max(Duration::from_millis(1)) + MAX_ACK_DELAY;
        base.max(Duration::from_millis(10)) * (1u32 << self.pto_count.min(6))
    }

    fn detect_lost(&mut self, now: Instant) {
        if self.sent.is_empty() {
            return;
        }
        let srtt = self.srtt.unwrap_or(Duration::from_millis(100));
        let time_thresh = (srtt * 9 / 8).max(Duration::from_millis(1));
        let pto = self.pto();
        let largest = self.largest_acked;
        let lost: Vec<u64> = self
            .sent
            .iter()
            .filter(|(k, p)| {
                let by_ack = largest
                    .is_some_and(|l| **k < l && (l - **k >= 3 || p.time + time_thresh <= now));
                by_ack || p.time + pto <= now
            })
            .map(|(k, _)| *k)
            .collect();
        let any_pto = self.sent.values().any(|p| p.time + pto <= now);
        if any_pto {
            self.pto_count += 1;
        }
        for k in lost {
            let p = self.sent.remove(&k).expect("sent");
            self.stats.packets_lost += 1;
            for r in p.frames {
                self.requeue(r);
            }
        }
    }

    fn requeue(&mut self, r: Retx) {
        match r {
            Retx::Stream { id, off, len, fin } => {
                if let Some(s) = self.streams.get_mut(&id) {
                    if s.reset_local || s.reset_remote.is_some() {
                        return;
                    }
                    let start = off.max(s.send_base);
                    if start < off + len {
                        s.retx.insert(start, off + len);
                    }
                    if fin && !s.fin_acked {
                        s.retx_fin = true;
                    }
                }
            }
            Retx::Window(id) => {
                self.pending_window.insert(id);
            }
            Retx::Control(f) => {
                let relevant = match &f {
                    Frame::Rekey(pk) => {
                        matches!(&self.rekey, RekeyState::Sent { pk: p, .. } if p == pk)
                    }
                    Frame::RekeyReply(ct) => {
                        matches!(&self.rekey, RekeyState::Replied { ct: c, .. } if c == ct)
                    }
                    Frame::Reset { id, .. } => self.streams.contains_key(id),
                    _ => true,
                };
                if relevant {
                    self.control.push_back(f);
                }
            }
        }
    }

    fn on_reset(&mut self, id: u64, reason: u64) {
        if let Some(s) = self.streams.get_mut(&id) {
            if s.reset_remote.is_none() {
                s.reset_remote = Some(reason);
                let unread: u64 = s.recv_ready.iter().map(|b| b.len() as u64).sum();
                s.recv_ready.clear();
                s.recv_ooo.clear();
                self.session_consumed += unread;
                s.send_buf.clear();
                s.retx = RangeSet::new();
                if let Some(w) = s.read_waker.take() {
                    w.wake();
                }
                if let Some(w) = s.write_waker.take() {
                    w.wake();
                }
            }
        }
        self.gc_streams();
    }

    fn on_stream_frame(&mut self, f: StreamFrame) -> Result<(), &'static str> {
        if f.id == 0 {
            return Err("stream id 0");
        }
        let local_parity = if self.role == Role::Initiator { 1 } else { 0 };
        let is_local = f.id % 2 == local_parity;
        if !self.streams.contains_key(&f.id) {
            if is_local || f.id <= self.highest_peer_stream {
                return Ok(()); // A stream that has ended.
            }
            let open = self.streams.values().filter(|s| !s.local).count();
            if open >= MAX_INCOMING_STREAMS {
                self.control.push_back(Frame::Reset {
                    id: f.id,
                    reason: 1,
                });
                self.highest_peer_stream = f.id;
                return Ok(());
            }
            self.highest_peer_stream = f.id;
            self.streams.insert(
                f.id,
                StreamState {
                    send_max: STREAM_WINDOW,
                    recv_max: STREAM_WINDOW,
                    ..Default::default()
                },
            );
        }
        let s = self.streams.get_mut(&f.id).expect("stream");
        if s.reset_local || s.reset_remote.is_some() {
            return Ok(());
        }
        let len = f.data.len() as u64;
        let end = f.offset.checked_add(len).ok_or("offset overflow")?;
        if end > s.recv_max {
            return Err("stream flow control");
        }
        if let Some(fin) = s.recv_fin {
            if end > fin || (f.fin && end != fin) {
                return Err("data after fin");
            }
        }
        if f.fin {
            if end < s.recv_highest {
                return Err("fin below received data");
            }
            s.recv_fin = Some(end);
        }
        if end > s.recv_highest {
            self.session_recv_total += end - s.recv_highest;
            s.recv_highest = end;
            if self.session_recv_total > self.session_recv_max {
                return Err("session flow control");
            }
        }
        if f.offset == 0 && s.service.is_none() {
            s.service = f.service;
            if s.priority.is_none() {
                s.priority = f.priority;
            }
        }
        // Insert the data.
        let mut readable = false;
        if end > s.recv_contig {
            if f.offset <= s.recv_contig {
                let skip = (s.recv_contig - f.offset) as usize;
                s.recv_ready.push_back(f.data.slice(skip..));
                s.recv_contig = end;
                readable = true;
                while let Some((&o, _)) = s.recv_ooo.first_key_value() {
                    if o > s.recv_contig {
                        break;
                    }
                    let d = s.recv_ooo.remove(&o).expect("entry");
                    let dend = o + d.len() as u64;
                    if dend > s.recv_contig {
                        let skip = (s.recv_contig - o) as usize;
                        s.recv_ready.push_back(d.slice(skip..));
                        s.recv_contig = dend;
                    }
                }
            } else {
                let keep = s
                    .recv_ooo
                    .get(&f.offset)
                    .is_none_or(|old| old.len() < f.data.len());
                if keep {
                    s.recv_ooo.insert(f.offset, f.data);
                }
            }
        }
        if f.fin || readable {
            readable = true;
        }
        if s.handle_dropped {
            let n: u64 = s.recv_ready.iter().map(|b| b.len() as u64).sum();
            s.recv_ready.clear();
            s.recv_read += n;
            self.session_consumed += n;
            self.update_session_window();
        } else if readable {
            if let Some(w) = s.read_waker.take() {
                w.wake();
            }
        }
        let s = self.streams.get_mut(&f.id).expect("stream");
        if !is_local && !s.announced && s.service.is_some() {
            s.announced = true;
            self.incoming.push_back(f.id);
            self.signals.state.notify_waiters();
        }
        self.gc_streams();
        Ok(())
    }

    fn update_session_window(&mut self) {
        if self.session_recv_max - self.session_consumed < SESSION_WINDOW / 2 {
            self.session_recv_max = self.session_consumed + SESSION_WINDOW;
            self.pending_window.insert(0);
            self.signals.driver.notify_one();
        }
    }

    fn gc_streams(&mut self) {
        let reliable = self.reliable;
        let dead: Vec<u64> = self
            .streams
            .iter()
            .filter(|(_, s)| {
                s.handle_dropped
                    && s.send_done(reliable)
                    && s.recv_done()
                    && (s.announced || s.local)
            })
            .map(|(k, _)| *k)
            .collect();
        for k in dead {
            self.streams.remove(&k);
        }
    }

    // ------------------------------------------------------------------
    // Application side.

    pub fn open_stream(&mut self, service: Service, priority: Priority) -> Option<u64> {
        if !self.established || self.close.is_some() {
            return None;
        }
        let id = self.next_local_stream;
        self.next_local_stream += 2;
        self.streams.insert(
            id,
            StreamState {
                service: Some(service),
                priority: Some(priority),
                local: true,
                send_max: STREAM_WINDOW,
                recv_max: STREAM_WINDOW,
                announced: true,
                ..Default::default()
            },
        );
        Some(id)
    }

    pub fn accept_stream(&mut self) -> Option<(u64, Service, Priority)> {
        while let Some(id) = self.incoming.pop_front() {
            if let Some(s) = self.streams.get(&id) {
                return Some((id, s.service.expect("announced"), s.priority()));
            }
        }
        None
    }

    pub fn stream_read(
        &mut self,
        id: u64,
        cx: &mut Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let closed = self.close.clone();
        let Some(s) = self.streams.get_mut(&id) else {
            return Poll::Ready(Err(std::io::ErrorKind::NotConnected.into()));
        };
        if s.reset_remote.is_some() {
            return Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()));
        }
        let mut n = 0u64;
        while out.remaining() > 0 {
            let Some(front) = s.recv_ready.front_mut() else {
                break;
            };
            let take = front.len().min(out.remaining());
            out.put_slice(&front[..take]);
            n += take as u64;
            if take == front.len() {
                s.recv_ready.pop_front();
            } else {
                *front = front.slice(take..);
            }
        }
        if n > 0 {
            s.recv_read += n;
            if s.recv_fin.is_none() && s.recv_max - s.recv_read < STREAM_WINDOW / 2 {
                s.recv_max = s.recv_read + STREAM_WINDOW;
                self.pending_window.insert(id);
                self.signals.driver.notify_one();
            }
            self.session_consumed += n;
            self.update_session_window();
            self.gc_streams();
            return Poll::Ready(Ok(()));
        }
        if s.recv_fin.is_some_and(|f| s.recv_read >= f) {
            return Poll::Ready(Ok(())); // End of stream.
        }
        if closed.is_some() {
            return Poll::Ready(Err(std::io::ErrorKind::ConnectionAborted.into()));
        }
        s.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    pub fn stream_write(
        &mut self,
        id: u64,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.close.is_some() {
            return Poll::Ready(Err(std::io::ErrorKind::ConnectionAborted.into()));
        }
        let Some(s) = self.streams.get_mut(&id) else {
            return Poll::Ready(Err(std::io::ErrorKind::NotConnected.into()));
        };
        if s.reset_remote.is_some() || s.reset_local {
            return Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()));
        }
        if s.fin_requested {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        let space = SEND_BUFFER.saturating_sub(s.send_buf.len());
        if space == 0 {
            s.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = space.min(data.len());
        s.send_buf.extend(&data[..n]);
        self.signals.driver.notify_one();
        Poll::Ready(Ok(n))
    }

    /// Waits until everything written has been handed to the carrier.
    pub fn stream_flush(&mut self, id: u64, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.close.is_some() {
            return Poll::Ready(Err(std::io::ErrorKind::ConnectionAborted.into()));
        }
        let Some(s) = self.streams.get_mut(&id) else {
            return Poll::Ready(Ok(()));
        };
        if s.reset_remote.is_some() || s.send_next >= s.send_end() {
            return Poll::Ready(Ok(()));
        }
        s.write_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    pub fn stream_finish(&mut self, id: u64) {
        if let Some(s) = self.streams.get_mut(&id) {
            if !s.fin_requested && !s.reset_local && s.reset_remote.is_none() {
                s.fin_requested = true;
                self.signals.driver.notify_one();
            }
        }
    }

    pub fn stream_reset(&mut self, id: u64, reason: u64) {
        if let Some(s) = self.streams.get_mut(&id) {
            if s.reset_local || s.reset_remote.is_some() {
                return;
            }
            s.reset_local = true;
            let unread: u64 = s.recv_ready.iter().map(|b| b.len() as u64).sum();
            s.recv_ready.clear();
            s.recv_ooo.clear();
            s.send_buf.clear();
            s.retx = RangeSet::new();
            self.session_consumed += unread;
            self.control.push_back(Frame::Reset { id, reason });
            self.signals.driver.notify_one();
        }
        self.gc_streams();
    }

    pub fn stream_dropped(&mut self, id: u64) {
        let Some(s) = self.streams.get_mut(&id) else {
            return;
        };
        s.handle_dropped = true;
        let unfinished_send = !s.fin_requested && !s.reset_local && s.reset_remote.is_none();
        if unfinished_send {
            self.stream_reset(id, 0);
        } else {
            // Discard what will never be read.
            let unread: u64 = s.recv_ready.iter().map(|b| b.len() as u64).sum();
            s.recv_ready.clear();
            s.recv_read += unread;
            self.session_consumed += unread;
            self.update_session_window();
        }
        self.gc_streams();
    }

    pub fn subscribe(&mut self, label: [u8; 16], priority: Priority) -> mpsc::Receiver<Bytes> {
        let (tx, rx) = mpsc::channel(CHANNEL_QUEUE);
        self.channels.insert(label, (priority, tx));
        rx
    }

    pub fn send_datagram(
        &mut self,
        label: [u8; 16],
        priority: Priority,
        data: Bytes,
    ) -> Result<(), crate::LinkError> {
        if self.close.is_some() {
            return Err(crate::LinkError::Closed(
                self.close.clone().expect("closed"),
            ));
        }
        if data.len() > crate::MAX_DATAGRAM_PAYLOAD {
            return Err(crate::LinkError::TooLarge);
        }
        let q = &mut self.dgram_out[priority as usize];
        if q.len() >= MAX_DATAGRAM_QUEUE {
            q.pop_front();
        }
        q.push_back((label, data));
        self.signals.driver.notify_one();
        Ok(())
    }

    // ------------------------------------------------------------------
    // Timers.

    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.is_drained() {
            return None;
        }
        let mut t: Vec<Instant> = Vec::new();
        if !self.established {
            t.push(self.created + self.config.establish_timeout);
        }
        t.push(self.last_recv + self.config.idle_timeout);
        if let Some(a) = self.ack_due {
            t.push(a);
        }
        if let Some(k) = self.config.keepalive {
            if self.established {
                t.push(self.last_send + k);
            }
        }
        if self.role == Role::Initiator && self.established {
            t.push(self.last_rekey + self.config.rekey_interval);
        }
        if let Some(p) = self.sent.values().next() {
            t.push(p.time + self.pto());
        }
        if let Some(c) = &self.challenge {
            if let Some(s) = c.sent_at {
                t.push(s + Duration::from_secs(1));
            }
        }
        t.into_iter().min()
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        if self.close.is_some() {
            return;
        }
        if !self.established && now >= self.created + self.config.establish_timeout {
            self.close_local(CloseReason::Timeout);
            return;
        }
        if now >= self.last_recv + self.config.idle_timeout {
            self.close_local(CloseReason::Idle);
            return;
        }
        if self.path.is_closed() && self.challenge.is_none() {
            self.close_silently(CloseReason::Carrier);
            return;
        }
        if let Some(k) = self.config.keepalive {
            if self.established && now >= self.last_send + k {
                self.control.push_back(Frame::Ping);
            }
        }
        if self.role == Role::Initiator
            && self.established
            && matches!(self.rekey, RekeyState::Idle)
            && ((now >= self.last_rekey + self.config.rekey_interval && self.activity_since_rekey)
                || self.packets_since_rekey >= self.config.rekey_packets)
        {
            self.start_rekey(now);
        }
        if let Some(c) = &mut self.challenge {
            if c.sent_at.is_some_and(|s| now >= s + Duration::from_secs(1)) {
                if c.tries >= 3 {
                    self.challenge = None;
                } else {
                    c.sent_at = None;
                }
            }
        }
        self.detect_lost(now);
    }

    // ------------------------------------------------------------------
    // Sending.

    fn has_stream_work(&self) -> bool {
        if !self.established {
            return false;
        }
        let session_credit = self.session_send_max.saturating_sub(self.session_sent);
        self.streams.values().any(|s| {
            !s.retx.is_empty()
                || s.retx_fin
                || (s.send_next < s.send_end() && s.send_next < s.send_max && session_credit > 0)
                || (s.fin_requested && !s.fin_sent && s.send_next == s.send_end())
        })
    }

    /// Builds the next packet to send, if any.
    pub fn poll_transmit(&mut self, now: Instant) -> Option<(Path, Bytes)> {
        if !self.confirmed {
            return None;
        }
        if let Some(reason) = self.close_frame.take() {
            let frames = [Frame::Close(reason)];
            let path = self.path.clone();
            return Some((path, self.seal_frames(&frames, now)));
        }
        if self.close.is_some() {
            return None;
        }
        // Path validation goes to the new path.
        if let Some(c) = &mut self.challenge {
            if c.sent_at.is_none() {
                c.sent_at = Some(now);
                c.tries += 1;
                let frame = Frame::PathChallenge(c.data);
                let path = c.path.clone();
                return Some((path, self.seal_frames(&[frame], now)));
            }
        }
        if let Some((path, d)) = self.path_responses.pop() {
            return Some((path, self.seal_frames(&[Frame::PathResponse(d)], now)));
        }

        let unreliable_full = !self.reliable && self.sent.len() >= MAX_IN_FLIGHT;
        let ack_wanted = self.ack_due.is_some_and(|d| d <= now);
        let other_work = !self.control.is_empty()
            || (!unreliable_full
                && (!self.pending_window.is_empty()
                    || (self.established && self.dgram_out.iter().any(|q| !q.is_empty()))
                    || self.has_stream_work()));
        if !ack_wanted && !other_work {
            return None;
        }

        let mut buf = std::mem::take(&mut self.scratch);
        buf.clear();
        buf.resize(DATA_HEADER_LEN, 0);
        let mut budget = MAX_PLAINTEXT;
        let mut retx: Vec<Retx> = Vec::new();
        let mut eliciting = false;

        // Acknowledgement, whenever there is something to acknowledge.
        if self.unacked_eliciting > 0 || ack_wanted {
            if let Some(f) = self.ack_frame(now) {
                f.encode_into(&mut buf);
                self.unacked_eliciting = 0;
                self.ack_due = None;
            }
        }

        // Control frames, in order.
        while let Some(f) = self.control.front() {
            if !self.established && !f.allowed_before_proofs() {
                break;
            }
            let len = f.encoded_len();
            let used = buf.len() - DATA_HEADER_LEN;
            if matches!(f, Frame::Rekey(_)) && used + len > budget {
                // The rekey frame does not fit in an ordinary packet; it
                // travels alone in a packet of up to 1224 bytes.
                if used == 0
                    || (used + len <= DATA_MAX_LEN_REKEY - DATA_MIN_LEN && self.only_ack(&buf))
                {
                    budget = DATA_MAX_LEN_REKEY - DATA_MIN_LEN;
                } else {
                    break;
                }
            }
            if used + len > budget {
                break;
            }
            let f = self.control.pop_front().expect("front");
            f.encode_into(&mut buf);
            if f.is_ack_eliciting() {
                eliciting = true;
            }
            if matches!(f, Frame::DeviceProof(_)) {
                self.own_proof_sent = true;
            }
            match &f {
                Frame::Ping
                | Frame::PathChallenge(_)
                | Frame::PathResponse(_)
                | Frame::Close(_) => {}
                _ => retx.push(Retx::Control(f)),
            }
            if budget > MAX_PLAINTEXT {
                break;
            }
        }

        if self.established && budget == MAX_PLAINTEXT && !unreliable_full {
            // Window updates.
            let ids: Vec<u64> = self.pending_window.iter().copied().collect();
            for id in ids {
                let max = if id == 0 {
                    self.session_recv_max
                } else if let Some(s) = self.streams.get(&id) {
                    s.recv_max
                } else {
                    self.pending_window.remove(&id);
                    continue;
                };
                let f = Frame::Window { id, max };
                if buf.len() - DATA_HEADER_LEN + f.encoded_len() > budget {
                    break;
                }
                f.encode_into(&mut buf);
                self.pending_window.remove(&id);
                eliciting = true;
                retx.push(Retx::Window(id));
            }
            // Priority classes in order: datagrams, then streams.
            for class in 0..3 {
                while let Some((label, data)) = self.dgram_out[class].front() {
                    let f = Frame::Datagram {
                        channel: *label,
                        data: data.clone(),
                    };
                    let len = f.encoded_len();
                    if buf.len() - DATA_HEADER_LEN + len > budget {
                        break;
                    }
                    f.encode_into(&mut buf);
                    self.dgram_out[class].pop_front();
                    eliciting = true;
                }
                self.fill_streams(class, &mut buf, budget, &mut retx, &mut eliciting);
            }
        }

        if buf.len() == DATA_HEADER_LEN {
            self.scratch = buf;
            return None;
        }
        let pkt = self.seal_buf(&mut buf, now);
        self.scratch = buf;
        if !self.reliable && eliciting {
            self.sent.insert(
                self.send_counter - 1,
                SentPacket {
                    time: now,
                    frames: retx,
                },
            );
        }
        if eliciting {
            self.packets_since_rekey += 1;
            self.activity_since_rekey = true;
        }
        self.maybe_establish(now);
        Some((self.path.clone(), pkt))
    }

    fn only_ack(&self, buf: &[u8]) -> bool {
        buf.len() - DATA_HEADER_LEN <= 64
    }

    fn fill_streams(
        &mut self,
        class: usize,
        buf: &mut Vec<u8>,
        budget: usize,
        retx: &mut Vec<Retx>,
        eliciting: &mut bool,
    ) {
        let reliable = self.reliable;
        let ids: Vec<u64> = {
            let cursor = self.rr_cursor[class];
            let after = self.streams.range(cursor + 1..).map(|(k, _)| *k);
            let before = self.streams.range(..=cursor).map(|(k, _)| *k);
            after
                .chain(before)
                .filter(|k| self.streams[k].priority() as usize == class)
                .collect()
        };
        for id in ids {
            loop {
                let room = budget.saturating_sub(buf.len() - DATA_HEADER_LEN);
                if room < 24 {
                    return;
                }
                let session_credit = self.session_send_max.saturating_sub(self.session_sent);
                let s = self.streams.get_mut(&id).expect("stream");
                if s.reset_local || s.reset_remote.is_some() {
                    break;
                }
                // Retransmissions first.
                let first_retx = s.retx.iter().next();
                if let Some((start, end)) = first_retx {
                    let svc = (start == 0).then_some(s.service).flatten();
                    let pri = (start == 0).then_some(s.priority).flatten();
                    let fin_here = s.fin_sent && s.retx_fin && end == s.send_end();
                    let over = stream_frame_overhead(
                        id,
                        start,
                        (end - start) as usize,
                        fin_here,
                        svc,
                        pri,
                    );
                    let len = ((end - start) as usize).min(room.saturating_sub(over + 2));
                    if len == 0 {
                        return;
                    }
                    let fin = fin_here && start + len as u64 == end;
                    let (d1, d2) = range_slices(&s.send_buf, (start - s.send_base) as usize, len);
                    encode_stream_frame_parts(buf, id, start, d1, d2, fin, svc, pri);
                    s.retx.remove(start, start + len as u64);
                    if fin {
                        s.retx_fin = false;
                    }
                    retx.push(Retx::Stream {
                        id,
                        off: start,
                        len: len as u64,
                        fin,
                    });
                    *eliciting = true;
                    self.rr_cursor[class] = id;
                    continue;
                }
                if s.retx_fin && s.fin_sent && s.send_next == s.send_end() {
                    let off = s.send_end();
                    encode_stream_frame(buf, id, off, &[], true, None, None);
                    s.retx_fin = false;
                    retx.push(Retx::Stream {
                        id,
                        off,
                        len: 0,
                        fin: true,
                    });
                    *eliciting = true;
                    continue;
                }
                // New data.
                let avail = s.send_end() - s.send_next;
                let credit = s.send_max.saturating_sub(s.send_next).min(session_credit);
                let want_fin = s.fin_requested && !s.fin_sent;
                if (avail == 0 || credit == 0) && !(want_fin && avail == 0) {
                    break;
                }
                let start = s.send_next;
                let svc = (start == 0).then_some(s.service).flatten();
                let pri = (start == 0).then_some(s.priority).flatten();
                let over = stream_frame_overhead(
                    id,
                    start,
                    avail.min(credit) as usize,
                    want_fin,
                    svc,
                    pri,
                );
                let len = (avail.min(credit) as usize).min(room.saturating_sub(over + 2));
                if len == 0 && avail > 0 {
                    return;
                }
                let fin = want_fin && start + len as u64 == s.send_end();
                let (d1, d2) = range_slices(&s.send_buf, (start - s.send_base) as usize, len);
                encode_stream_frame_parts(buf, id, start, d1, d2, fin, svc, pri);
                s.send_next += len as u64;
                self.session_sent += len as u64;
                if fin {
                    s.fin_sent = true;
                }
                if reliable {
                    // The carrier delivers it; nothing to keep.
                    s.send_buf.drain(..len);
                    s.send_base += len as u64;
                    if s.send_buf.len() <= SEND_BUFFER / 2 {
                        if let Some(w) = s.write_waker.take() {
                            w.wake();
                        }
                    }
                } else {
                    retx.push(Retx::Stream {
                        id,
                        off: start,
                        len: len as u64,
                        fin,
                    });
                }
                *eliciting = true;
                self.rr_cursor[class] = id;
                if fin {
                    break;
                }
                // One frame per stream per pass, for fairness.
                break;
            }
        }
        if reliable {
            self.gc_streams();
        }
    }

    fn ack_frame(&self, now: Instant) -> Option<Frame> {
        let mut it = self.recv_ranges.iter_desc();
        let (s0, e0) = it.next()?;
        let largest = e0 - 1;
        let mut ranges = vec![AckRange {
            gap: 0,
            length: e0 - s0,
        }];
        let mut prev_low = s0;
        for (s, e) in it {
            ranges.push(AckRange {
                gap: prev_low - e,
                length: e - s,
            });
            prev_low = s;
        }
        let delay = self
            .largest_recv_time
            .map(|t| now.saturating_duration_since(t).as_micros() as u64)
            .unwrap_or(0);
        Some(Frame::Ack {
            largest,
            delay_us: delay,
            ranges,
        })
    }

    fn seal_frames(&mut self, frames: &[Frame], now: Instant) -> Bytes {
        let mut buf = Vec::with_capacity(packet::MAX_DATAGRAM);
        buf.resize(DATA_HEADER_LEN, 0);
        for f in frames {
            f.encode_into(&mut buf);
        }
        self.seal_buf(&mut buf, now)
    }

    fn seal_buf(&mut self, buf: &mut Vec<u8>, now: Instant) -> Bytes {
        buf.resize(buf.len() + TAG_LEN, 0);
        let counter = self.send_counter;
        self.send_counter += 1;
        self.send_key.seal(self.remote_index, counter, buf);
        self.stats.packets_sent += 1;
        self.stats.bytes_sent += buf.len() as u64;
        self.last_send = now;
        Bytes::copy_from_slice(buf)
    }
}

fn advance_send_base(s: &mut StreamState) {
    if let Some(end) = s.acked.end_of_run(s.send_base) {
        let n = (end - s.send_base) as usize;
        let n = n.min(s.send_buf.len());
        s.send_buf.drain(..n);
        s.send_base += n as u64;
        s.acked.remove_below(s.send_base);
        s.retx.remove_below(s.send_base);
        if let Some(w) = s.write_waker.take() {
            w.wake();
        }
    }
}

/// The bytes `[start, start + len)` of a deque as at most two slices.
fn range_slices(buf: &VecDeque<u8>, start: usize, len: usize) -> (&[u8], &[u8]) {
    let (a, b) = buf.as_slices();
    if start >= a.len() {
        let s = start - a.len();
        (&b[s..s + len], &[])
    } else if start + len <= a.len() {
        (&a[start..start + len], &[])
    } else {
        (&a[start..], &b[..start + len - a.len()])
    }
}

#[cfg(test)]
fn copy_range(buf: &VecDeque<u8>, start: usize, len: usize) -> Vec<u8> {
    let (a, b) = range_slices(buf, start, len);
    [a, b].concat()
}

#[cfg(test)]
mod tests;
