//! The endpoint: binds carriers, answers handshakes (or stays silent),
//! opens sessions, and routes packets to sessions by index.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cardinal_crypto::{random_bytes, HybridKeyPair, HybridPublicKey, KemPublicKey};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{broadcast, mpsc, oneshot, Notify};
use tokio::task::AbortHandle;
use zeroize::Zeroizing;

use crate::carrier::{spawn_tcp, spawn_udp, CarrierKind, Ingress, Path};
use crate::conn::{
    Admission, CloseReason, Conn, ConnEvent, ConnParams, Role, SessionConfig, Signals,
};
use crate::directory::{ExpectedPeer, LocalIdentity, PeerDirectory, PeerIdentity};
use crate::handshake::{self, InitiationParams, PendingInitiation};
use crate::packet::{self, init, resp, COOKIE_REPLY_LEN, INITIATION_LEN, RESPONSE_LEN};
use crate::session::{drive, Session, SessionInner};
use crate::LinkError;

/// When to answer initiations with a cookie reply instead of a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CookiePolicy {
    /// Never (mac2 is ignored).
    Never,
    /// Always require mac2 (for tests).
    Always,
    /// Require mac2 when more than this many initiations arrived in the
    /// last second.
    UnderLoad(u32),
}

/// Endpoint configuration.
#[derive(Clone)]
pub struct EndpointConfig {
    /// This device's link key pair.
    pub link_key: Arc<HybridKeyPair>,
    /// The identity layer.
    pub directory: Arc<dyn PeerDirectory>,
    /// This device's identity, if it has one yet.
    pub identity: Option<LocalIdentity>,
    /// Session timing.
    pub session: SessionConfig,
    /// Cookie policy.
    pub cookies: CookiePolicy,
    /// Accept handshakes from unknown keys without a secret (hosts with a
    /// public label, and restore; `hosts.md`). Such sessions report
    /// [`Admission::Public`].
    pub allow_public: bool,
    /// How often an unanswered initiation is resent over UDP.
    pub handshake_retry: Duration,
    /// How long [`Endpoint::connect`] tries before giving up.
    pub connect_timeout: Duration,
}

impl EndpointConfig {
    /// A configuration with defaults.
    pub fn new(link_key: Arc<HybridKeyPair>, directory: Arc<dyn PeerDirectory>) -> EndpointConfig {
        EndpointConfig {
            link_key,
            directory,
            identity: None,
            session: SessionConfig::default(),
            cookies: CookiePolicy::UnderLoad(200),
            allow_public: false,
            handshake_retry: Duration::from_secs(1),
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// Addresses to listen on.
#[derive(Clone, Copy, Debug, Default)]
pub struct Bind {
    /// UDP (personal devices listen only on UDP).
    pub udp: Option<SocketAddr>,
    /// TCP (hosts may also listen on TCP).
    pub tcp: Option<SocketAddr>,
}

/// Where and to whom to connect.
#[derive(Clone)]
pub struct Target {
    /// The peer's address.
    pub addr: SocketAddr,
    /// The carrier.
    pub carrier: CarrierKind,
    /// The peer's X25519 static key.
    pub peer_x25519: [u8; 32],
    /// The peer's ML-KEM key; `None` when connecting with an invitation
    /// that carries only the X25519 key.
    pub peer_kem: Option<KemPublicKey>,
    /// The secret of handshake step 5, if any.
    pub secret: Option<Zeroizing<Vec<u8>>>,
    /// Who the peer must prove to be when its log is not known yet.
    pub expected: ExpectedPeer,
    /// A public-service or restore session: nothing but the address and
    /// X25519 key is known of the peer, and this device has no secret.
    pub public: bool,
}

impl Target {
    /// A peer whose full link key is known.
    pub fn new(addr: SocketAddr, carrier: CarrierKind, peer: &HybridPublicKey) -> Target {
        Target {
            addr,
            carrier,
            peer_x25519: *peer.x25519(),
            peer_kem: Some(peer.kem().clone()),
            secret: None,
            expected: ExpectedPeer::default(),
            public: false,
        }
    }

    /// A public-service or restore session (`hosts.md`): only the X25519
    /// key, and no secret. The first rekey is what gives it post-quantum
    /// protection.
    pub fn public(addr: SocketAddr, carrier: CarrierKind, peer_x25519: [u8; 32]) -> Target {
        Target {
            addr,
            carrier,
            peer_x25519,
            peer_kem: None,
            secret: None,
            expected: ExpectedPeer::default(),
            public: true,
        }
    }

    /// An invitation: only the X25519 key and a secret.
    pub fn invitation(
        addr: SocketAddr,
        carrier: CarrierKind,
        peer_x25519: [u8; 32],
        secret: &[u8],
    ) -> Target {
        Target {
            addr,
            carrier,
            peer_x25519,
            peer_kem: None,
            secret: Some(Zeroizing::new(secret.to_vec())),
            expected: ExpectedPeer::default(),
            public: false,
        }
    }

    /// Adds a secret.
    pub fn with_secret(mut self, secret: &[u8]) -> Target {
        self.secret = Some(Zeroizing::new(secret.to_vec()));
        self
    }

    /// Sets who the peer must prove to be.
    pub fn expect(mut self, expected: ExpectedPeer) -> Target {
        self.expected = expected;
        self
    }
}

/// A secret this endpoint accepts in handshakes (an invitation, a pairing
/// key, a delivery token's derived secret).
#[derive(Clone)]
pub struct SecretEntry {
    /// The bytes mixed in at handshake step 5.
    pub secret: Zeroizing<Vec<u8>>,
    /// Remaining uses; `None` for unlimited. A use is counted when a
    /// session's counter is confirmed.
    pub uses: Option<u32>,
    /// The initiator's full link key, if known (pairing), so the response
    /// encapsulates to it. If set, only this key may use the secret.
    pub peer_link_key: Option<HybridPublicKey>,
    /// Who the initiator must prove to be.
    pub expected: ExpectedPeer,
}

impl SecretEntry {
    /// A single-use secret.
    pub fn new(secret: &[u8]) -> SecretEntry {
        SecretEntry {
            secret: Zeroizing::new(secret.to_vec()),
            uses: Some(1),
            peer_link_key: None,
            expected: ExpectedPeer::default(),
        }
    }
}

/// Endpoint events.
#[derive(Clone, Debug)]
pub enum EndpointEvent {
    /// A session completed its handshake, proofs, and first rekey.
    Established {
        /// Peer static key.
        peer_static: [u8; 32],
        /// Peer identity, if it has one.
        identity: Option<PeerIdentity>,
        /// Whether this device initiated it.
        initiator: bool,
    },
    /// A session closed.
    Closed {
        /// Peer static key.
        peer_static: [u8; 32],
        /// Why.
        reason: CloseReason,
    },
}

struct Attempt {
    target: Target,
    path: Path,
    tx: Mutex<Option<oneshot::Sender<Arc<SessionInner>>>>,
    cookie: Mutex<Option<[u8; 16]>>,
    resend: Notify,
}

struct PendingEntry {
    init: PendingInitiation,
    attempt: Arc<Attempt>,
}

#[derive(Default)]
struct State {
    sessions: HashMap<u32, Arc<SessionInner>>,
    pending: HashMap<u32, PendingEntry>,
    secrets: BTreeMap<u64, SecretEntry>,
    next_secret_id: u64,
    confirmed: HashMap<[u8; 32], u64>,
    last_counter: u64,
    recent_initiations: VecDeque<Instant>,
}

struct CookieSecret {
    current: [u8; 32],
    previous: [u8; 32],
    rotated: Instant,
}

pub(crate) struct EndpointInner {
    config: EndpointConfig,
    allow_public: AtomicBool,
    identity: RwLock<Option<LocalIdentity>>,
    mac1_key: [u8; 32],
    state: Mutex<State>,
    cookie: Mutex<CookieSecret>,
    accept_tx: mpsc::UnboundedSender<Session>,
    accept_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Session>>,
    events: broadcast::Sender<EndpointEvent>,
    udp: Option<Arc<UdpSocket>>,
    udp_addr: Option<SocketAddr>,
    tcp_addr: Option<SocketAddr>,
    tasks: Mutex<Vec<AbortHandle>>,
    closed: AtomicBool,
    weak: Weak<EndpointInner>,
    /// Sessions with readers to wake at the end of a carrier batch.
    deferred: Mutex<Vec<Arc<SessionInner>>>,
}

/// Forwards carrier packets to the endpoint without keeping it alive.
struct WeakIngress(Weak<EndpointInner>);

impl Ingress for WeakIngress {
    fn ingress(&self, packet: &mut [u8], path: &Path) {
        if let Some(ep) = self.0.upgrade() {
            ep.handle_packet(packet, path);
        }
    }

    fn flush(&self) {
        if let Some(ep) = self.0.upgrade() {
            let list = std::mem::take(&mut *lock(&ep.deferred));
            for s in list {
                s.flush_wakes();
            }
        }
    }
}

/// A link endpoint: one device's listening and connecting point.
#[derive(Clone)]
pub struct Endpoint {
    inner: Arc<EndpointInner>,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("udp", &self.inner.udp_addr)
            .field("tcp", &self.inner.tcp_addr)
            .finish()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Endpoint {
    /// Binds the carriers and starts answering handshakes.
    pub async fn bind(config: EndpointConfig, bind: Bind) -> std::io::Result<Endpoint> {
        let udp = match bind.udp {
            Some(a) => Some(Arc::new(UdpSocket::bind(a).await?)),
            None => None,
        };
        let tcp = match bind.tcp {
            Some(a) => Some(TcpListener::bind(a).await?),
            None => None,
        };
        let udp_addr = udp.as_ref().map(|u| u.local_addr()).transpose()?;
        let tcp_addr = tcp.as_ref().map(|t| t.local_addr()).transpose()?;
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        let (events, _) = broadcast::channel(256);
        let mac1_key = packet::mac1_key(config.link_key.public_key().x25519());
        let identity = RwLock::new(config.identity.clone());
        let inner = Arc::new_cyclic(|weak| EndpointInner {
            allow_public: AtomicBool::new(config.allow_public),
            config,
            identity,
            mac1_key,
            state: Mutex::new(State {
                next_secret_id: 1,
                ..Default::default()
            }),
            cookie: Mutex::new(CookieSecret {
                current: random_bytes(),
                previous: random_bytes(),
                rotated: Instant::now(),
            }),
            accept_tx,
            accept_rx: tokio::sync::Mutex::new(accept_rx),
            events,
            udp: udp.clone(),
            udp_addr,
            tcp_addr,
            tasks: Mutex::new(Vec::new()),
            closed: AtomicBool::new(false),
            weak: weak.clone(),
            deferred: Mutex::new(Vec::new()),
        });
        if let Some(u) = udp {
            let h = spawn_udp(u, Arc::new(WeakIngress(Arc::downgrade(&inner))));
            lock(&inner.tasks).push(h.abort_handle());
        }
        if let Some(l) = tcp {
            let weak = Arc::downgrade(&inner);
            let h = tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = l.accept().await else {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    };
                    let Some(ep) = weak.upgrade() else { break };
                    let (_, abort) = spawn_tcp(stream, Arc::new(WeakIngress(weak.clone())));
                    lock(&ep.tasks).push(abort);
                }
            });
            lock(&inner.tasks).push(h.abort_handle());
        }
        Ok(Endpoint { inner })
    }

    /// The bound UDP address.
    pub fn udp_addr(&self) -> Option<SocketAddr> {
        self.inner.udp_addr
    }

    /// The bound TCP address.
    pub fn tcp_addr(&self) -> Option<SocketAddr> {
        self.inner.tcp_addr
    }

    /// This device's link public key.
    pub fn link_key(&self) -> &HybridPublicKey {
        self.inner.config.link_key.public_key()
    }

    /// Sets (or clears) this device's identity for future sessions, e.g.
    /// once a newly paired device has been added to a log.
    pub fn set_identity(&self, identity: Option<LocalIdentity>) {
        *self
            .inner
            .identity
            .write()
            .unwrap_or_else(|e| e.into_inner()) = identity;
    }

    /// Sets [`EndpointConfig::allow_public`]. Sessions open now stay open.
    pub fn set_allow_public(&self, allow: bool) {
        self.inner.allow_public.store(allow, Ordering::Relaxed);
    }

    /// Registers a secret (invitation, pairing key, token secret).
    /// Returns its id.
    pub fn add_secret(&self, entry: SecretEntry) -> u64 {
        let mut s = lock(&self.inner.state);
        let id = s.next_secret_id;
        s.next_secret_id += 1;
        s.secrets.insert(id, entry);
        id
    }

    /// Withdraws a secret.
    pub fn remove_secret(&self, id: u64) {
        lock(&self.inner.state).secrets.remove(&id);
    }

    /// The confirmed counter for a static key (see `link.md#handshake`).
    /// A daemon persists these with [`set_confirmed_counter`](Endpoint::set_confirmed_counter).
    pub fn confirmed_counter(&self, static_x25519: &[u8; 32]) -> Option<u64> {
        lock(&self.inner.state)
            .confirmed
            .get(static_x25519)
            .copied()
    }

    /// Restores a confirmed counter.
    pub fn set_confirmed_counter(&self, static_x25519: [u8; 32], counter: u64) {
        let mut s = lock(&self.inner.state);
        let e = s.confirmed.entry(static_x25519).or_insert(0);
        *e = (*e).max(counter);
    }

    /// The last initiation counter used; persist it and restore with
    /// [`set_last_counter`](Endpoint::set_last_counter).
    pub fn last_counter(&self) -> u64 {
        lock(&self.inner.state).last_counter
    }

    /// Restores the last initiation counter.
    pub fn set_last_counter(&self, c: u64) {
        let mut s = lock(&self.inner.state);
        s.last_counter = s.last_counter.max(c);
    }

    /// Subscribes to endpoint events.
    pub fn events(&self) -> broadcast::Receiver<EndpointEvent> {
        self.inner.events.subscribe()
    }

    /// Waits for the next session a peer opened (after its handshake,
    /// proofs, and first rekey). `None` once the endpoint is closed.
    pub async fn accept(&self) -> Option<Session> {
        let mut rx = self.inner.accept_rx.lock().await;
        loop {
            let s = rx.recv().await?;
            if !s.is_closed() {
                return Some(s);
            }
        }
    }

    /// The open sessions.
    pub fn sessions(&self) -> Vec<Session> {
        lock(&self.inner.state)
            .sessions
            .values()
            .filter(|s| s.lock().established)
            .map(|s| Session { inner: s.clone() })
            .collect()
    }

    /// Re-checks every session's peer proof against the directory, closing
    /// sessions whose peer key is no longer effective
    /// (`link.md#identity-binding`).
    pub fn recheck_peers(&self) {
        for s in self.sessions() {
            s.recheck_identity();
        }
    }

    /// Opens a session: handshake, device proofs, and the first rekey.
    pub async fn connect(&self, target: Target) -> Result<Session, LinkError> {
        let ep = &self.inner;
        if ep.closed.load(Ordering::Relaxed) {
            return Err(LinkError::Closed(CloseReason::EndpointClosed));
        }
        let deadline = tokio::time::Instant::now() + ep.config.connect_timeout;
        let path = match target.carrier {
            CarrierKind::Udp => {
                let socket = ep.udp.clone().ok_or(LinkError::NoCarrier)?;
                Path::Udp {
                    socket,
                    addr: target.addr,
                }
            }
            CarrierKind::Tcp => {
                let stream = tokio::time::timeout_at(deadline, TcpStream::connect(target.addr))
                    .await
                    .map_err(|_| LinkError::Timeout)??;
                let (path, abort) = spawn_tcp(stream, Arc::new(WeakIngress(Arc::downgrade(ep))));
                lock(&ep.tasks).push(abort);
                path
            }
        };
        let (tx, mut rx) = oneshot::channel();
        let attempt = Arc::new(Attempt {
            target,
            path: path.clone(),
            tx: Mutex::new(Some(tx)),
            cookie: Mutex::new(None),
            resend: Notify::new(),
        });
        let mut indexes = Vec::new();
        let result = loop {
            let (index, pkt) = ep.new_initiation(&attempt)?;
            indexes.push(index);
            let _ = path.send(bytes::Bytes::copy_from_slice(&pkt[..])).await;
            let retry = tokio::time::Instant::now() + ep.config.handshake_retry;
            let retry = if path.is_reliable() {
                deadline
            } else {
                retry.min(deadline)
            };
            tokio::select! {
                r = &mut rx => break r.map_err(|_| LinkError::Timeout),
                _ = attempt.resend.notified() => continue,
                _ = tokio::time::sleep_until(retry) => {
                    if tokio::time::Instant::now() >= deadline {
                        break Err(LinkError::Timeout);
                    }
                }
            }
        };
        {
            let mut s = lock(&ep.state);
            for i in indexes {
                s.pending.remove(&i);
            }
        }
        let inner = result?;
        let session = Session { inner };
        match tokio::time::timeout_at(deadline, session.wait_admitted()).await {
            Ok(Ok(())) => Ok(session),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                session.close("timeout");
                Err(LinkError::Timeout)
            }
        }
    }

    /// Closes every session and stops listening.
    pub fn close(&self) {
        self.inner.shutdown();
    }

    /// Closes like [`close`](Self::close), but first waits, at most
    /// `limit`, for every session to hand its `close` frame to its
    /// carrier, and a moment for the carrier to write it. A process that
    /// exits right after `close` sends nothing, and its peers keep a dead
    /// session until it times out.
    pub async fn close_gracefully(&self, limit: Duration) {
        let inner = &self.inner;
        if inner.close_sessions() {
            let deadline = tokio::time::Instant::now() + limit;
            // A session leaves the table once its driver has sent the
            // close frame.
            while !lock(&inner.state).sessions.is_empty() && tokio::time::Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            // Carrier writers flush as soon as their queues drain.
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        inner.stop_carriers();
    }
}

impl Drop for EndpointInner {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl EndpointInner {
    fn shutdown(&self) {
        if self.close_sessions() {
            self.stop_carriers();
        }
    }

    /// Stops taking packets and closes every session, each sending its
    /// peer a `close` frame. False if the endpoint was closed already.
    fn close_sessions(&self) -> bool {
        if self.closed.swap(true, Ordering::Relaxed) {
            return false;
        }
        let sessions: Vec<Arc<SessionInner>> =
            lock(&self.state).sessions.values().cloned().collect();
        for s in sessions {
            let events = {
                let mut c = s.lock();
                c.close_local(CloseReason::EndpointClosed);
                c.drain_events()
            };
            s.handle_events(events);
        }
        true
    }

    fn stop_carriers(&self) {
        // Give drivers a moment to send close frames, then stop carriers.
        let tasks: Vec<AbortHandle> = std::mem::take(&mut *lock(&self.tasks));
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                for t in tasks {
                    t.abort();
                }
            });
        } else {
            for t in tasks {
                t.abort();
            }
        }
    }

    fn identity(&self) -> Option<LocalIdentity> {
        self.identity
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn new_index(s: &State) -> u32 {
        loop {
            let i = u32::from_le_bytes(random_bytes::<4>());
            if i != 0 && !s.sessions.contains_key(&i) && !s.pending.contains_key(&i) {
                return i;
            }
        }
    }

    fn new_initiation(
        &self,
        attempt: &Arc<Attempt>,
    ) -> Result<(u32, Box<[u8; INITIATION_LEN]>), LinkError> {
        let mut s = lock(&self.state);
        let index = Self::new_index(&s);
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let counter = (s.last_counter + 1).max(now_ms);
        s.last_counter = counter;
        let t = &attempt.target;
        let params = InitiationParams {
            local: &self.config.link_key,
            remote_x25519: t.peer_x25519,
            remote_kem: t.peer_kem.as_ref(),
            secret: t.secret.as_deref().map(|v| &v[..]),
            counter,
            sender_index: index,
        };
        let e = Zeroizing::new(random_bytes::<32>());
        let mut init = handshake::initiate(&params, &e, random_bytes(), |k| k.encapsulate())
            .map_err(|_| LinkError::Rejected)?;
        if let Some(c) = *lock(&attempt.cookie) {
            init.apply_cookie(&c);
        }
        let pkt = Box::new(*init.packet());
        s.pending.insert(
            index,
            PendingEntry {
                init,
                attempt: attempt.clone(),
            },
        );
        Ok((index, pkt))
    }

    pub(crate) fn remove_session(&self, index: u32) {
        lock(&self.state).sessions.remove(&index);
    }

    fn handle_packet(&self, pkt: &mut [u8], path: &Path) {
        if self.closed.load(Ordering::Relaxed) || pkt.is_empty() {
            return;
        }
        match pkt[0] {
            packet::TYPE_DATA => {
                if pkt.len() < packet::DATA_MIN_LEN {
                    return;
                }
                let idx = packet::read_u32(pkt, 4);
                let s = lock(&self.state).sessions.get(&idx).cloned();
                if let Some(s) = s {
                    if s.recv(pkt, path) {
                        let mut d = lock(&self.deferred);
                        if !d.iter().any(|x| Arc::ptr_eq(x, &s)) {
                            d.push(s);
                        }
                    }
                }
            }
            packet::TYPE_INITIATION => self.on_initiation(pkt, path),
            packet::TYPE_RESPONSE => self.on_response(pkt, path),
            packet::TYPE_COOKIE_REPLY => self.on_cookie_reply(pkt),
            packet::TYPE_RELAYED => {
                if let Some((channel, _)) = packet::parse_relayed(pkt) {
                    let relayed = Path::Relayed {
                        via: Box::new(path.clone()),
                        channel,
                    };
                    let inner = &mut pkt[packet::RELAY_HEADER_LEN..];
                    if inner.first() != Some(&packet::TYPE_RELAYED) {
                        self.handle_packet(inner, &relayed);
                    }
                }
            }
            _ => {}
        }
    }

    fn under_load(&self, now: Instant) -> bool {
        let mut s = lock(&self.state);
        s.recent_initiations.push_back(now);
        while s
            .recent_initiations
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(1))
        {
            s.recent_initiations.pop_front();
        }
        match self.config.cookies {
            CookiePolicy::Never => false,
            CookiePolicy::Always => true,
            CookiePolicy::UnderLoad(n) => s.recent_initiations.len() > n as usize,
        }
    }

    fn cookie_secrets(&self, now: Instant) -> ([u8; 32], [u8; 32]) {
        let mut c = lock(&self.cookie);
        if now.duration_since(c.rotated) > Duration::from_secs(120) {
            c.previous = c.current;
            c.current = random_bytes();
            c.rotated = now;
        }
        (c.current, c.previous)
    }

    fn on_initiation(&self, pkt: &mut [u8], path: &Path) {
        if pkt.len() != INITIATION_LEN || !packet::check_mac1(pkt, init::MAC1, &self.mac1_key) {
            return; // Silence.
        }
        let now = Instant::now();
        if self.under_load(now) {
            let source = path
                .remote_addr()
                .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
            let (cur, prev) = self.cookie_secrets(now);
            let ok = [cur, prev]
                .iter()
                .any(|sec| packet::check_mac2(pkt, init::MAC1, &packet::make_cookie(sec, &source)));
            if !ok {
                let cookie = packet::make_cookie(&cur, &source);
                let reply = packet::cookie_reply(
                    self.config.link_key.public_key().x25519(),
                    packet::read_u32(pkt, init::SENDER),
                    &pkt[init::MAC1..init::MAC2],
                    &cookie,
                    &random_bytes(),
                );
                debug_assert_eq!(reply.len(), COOKIE_REPLY_LEN);
                path.try_send(bytes::Bytes::copy_from_slice(&reply));
                return;
            }
        }
        // Candidate secrets.
        let secrets: Vec<(u64, SecretEntry)> = lock(&self.state)
            .secrets
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let secret_bytes: Vec<&[u8]> = secrets.iter().map(|(_, e)| &e.secret[..]).collect();
        let dir = &self.config.directory;
        let allow_public = self.allow_public.load(Ordering::Relaxed);
        let Ok(recv) = handshake::receive_initiation(
            &self.config.link_key,
            pkt,
            |k| allow_public || dir.link_key(k).is_some(),
            &secret_bytes,
            allow_public,
        ) else {
            return; // Silence.
        };
        let secret = recv.secret.map(|i| &secrets[i]);
        // Admission and the initiator's full key.
        let known = dir.link_key(&recv.initiator_static);
        let (admission, initiator_key) = match secret {
            Some((id, entry)) => {
                if let Some(k) = &entry.peer_link_key {
                    if *k.x25519() != recv.initiator_static {
                        return;
                    }
                }
                (
                    Admission::Secret {
                        id: *id,
                        expected: entry.expected.clone(),
                    },
                    entry.peer_link_key.clone().or(known),
                )
            }
            None if known.is_some() && recv.initiation_kem => (Admission::Known, known),
            None => (Admission::Public, known),
        };
        // The counter must exceed the confirmed counter.
        let mut st = lock(&self.state);
        if st
            .confirmed
            .get(&recv.initiator_static)
            .is_some_and(|c| recv.counter <= *c)
        {
            return;
        }
        let index = Self::new_index(&st);
        let counter = recv.counter;
        let initiator_static = recv.initiator_static;
        let remote_index = recv.sender_index;
        let f = Zeroizing::new(random_bytes::<32>());
        let Ok((keys, response)) = handshake::respond(
            recv,
            initiator_key.as_ref().map(|k| k.kem()),
            index,
            &f,
            |k| k.encapsulate(),
        ) else {
            return;
        };
        let signals = Arc::new(Signals::default());
        let conn = Conn::new(
            ConnParams {
                role: Role::Responder,
                local_index: index,
                remote_index,
                keys,
                peer_static: initiator_static,
                peer_link_key: initiator_key,
                local_identity: self.identity(),
                directory: self.config.directory.clone(),
                admission,
                path: path.clone(),
                initiation_counter: counter,
                config: self.config.session.clone(),
                signals: signals.clone(),
            },
            now,
        );
        let inner = Arc::new(SessionInner {
            conn: Mutex::new(conn),
            signals,
            local_index: index,
            peer_static: initiator_static,
            role: Role::Responder,
            endpoint: self.weak.clone(),
        });
        st.sessions.insert(index, inner.clone());
        drop(st);
        tokio::spawn(drive(inner));
        path.try_send(bytes::Bytes::copy_from_slice(&response[..]));
    }

    fn on_response(&self, pkt: &mut [u8], path: &Path) {
        if pkt.len() != RESPONSE_LEN || !packet::check_mac1(pkt, resp::MAC1, &self.mac1_key) {
            return;
        }
        let idx = packet::read_u32(pkt, resp::RECEIVER);
        let entry = {
            let mut s = lock(&self.state);
            // Only the first response for an attempt counts.
            match s.pending.get(&idx) {
                Some(e) if lock(&e.attempt.tx).is_some() => s.pending.remove(&idx),
                _ => None,
            }
        };
        let Some(PendingEntry { init, attempt }) = entry else {
            return;
        };
        let counter = packet::read_u64(init.packet(), init::COUNTER);
        let Ok(done) = handshake::finish_initiation(init, &self.config.link_key, pkt) else {
            return;
        };
        let t = &attempt.target;
        let admission = if t.secret.is_some() {
            Admission::Secret {
                id: 0,
                expected: t.expected.clone(),
            }
        } else if t.public {
            Admission::Public
        } else {
            Admission::Known
        };
        let peer_link_key = t
            .peer_kem
            .clone()
            .map(|k| HybridPublicKey::new(t.peer_x25519, k))
            .or_else(|| self.config.directory.link_key(&t.peer_x25519));
        let now = Instant::now();
        let signals = Arc::new(Signals::default());
        // The path the response came on (equal to the attempt's path).
        let path = if path.same(&attempt.path) {
            attempt.path.clone()
        } else {
            path.clone()
        };
        let conn = Conn::new(
            ConnParams {
                role: Role::Initiator,
                local_index: idx,
                remote_index: done.remote_index,
                keys: done.keys,
                peer_static: t.peer_x25519,
                peer_link_key,
                local_identity: self.identity(),
                directory: self.config.directory.clone(),
                admission,
                path,
                initiation_counter: counter,
                config: self.config.session.clone(),
                signals: signals.clone(),
            },
            now,
        );
        let inner = Arc::new(SessionInner {
            conn: Mutex::new(conn),
            signals,
            local_index: idx,
            peer_static: t.peer_x25519,
            role: Role::Initiator,
            endpoint: self.weak.clone(),
        });
        lock(&self.state).sessions.insert(idx, inner.clone());
        tokio::spawn(drive(inner.clone()));
        let tx = lock(&attempt.tx).take();
        if let Some(tx) = tx {
            let _ = tx.send(inner);
        }
    }

    fn on_cookie_reply(&self, pkt: &mut [u8]) {
        if pkt.len() != COOKIE_REPLY_LEN {
            return;
        }
        let idx = packet::read_u32(pkt, packet::cookie::RECEIVER);
        let s = lock(&self.state);
        let Some(e) = s.pending.get(&idx) else {
            return;
        };
        if let Some(c) = packet::open_cookie_reply(pkt, e.init.remote_x25519(), &e.init.mac1()) {
            *lock(&e.attempt.cookie) = Some(c);
            e.attempt.resend.notify_one();
        }
    }

    pub(crate) fn on_session_event(&self, s: &Arc<SessionInner>, e: ConnEvent) {
        match e {
            ConnEvent::Confirmed { counter } => {
                let admission = s.lock().admission.clone();
                let mut st = lock(&self.state);
                let c = st.confirmed.entry(s.peer_static).or_insert(0);
                *c = (*c).max(counter);
                if let Admission::Secret { id, .. } = admission {
                    if let Some(entry) = st.secrets.get_mut(&id) {
                        if let Some(u) = &mut entry.uses {
                            *u = u.saturating_sub(1);
                            if *u == 0 {
                                st.secrets.remove(&id);
                            }
                        }
                    }
                }
            }
            ConnEvent::Established => {
                if !self.supersede(s) {
                    return;
                }
                // Only now may `connect` return it: a session that loses
                // to a simultaneous one must never reach the caller.
                s.lock().admitted = true;
                s.signals.state.notify_waiters();
                let identity = s.lock().peer_identity;
                let _ = self.events.send(EndpointEvent::Established {
                    peer_static: s.peer_static,
                    identity,
                    initiator: s.role == Role::Initiator,
                });
                if s.role == Role::Responder {
                    let _ = self.accept_tx.send(Session { inner: s.clone() });
                }
            }
            ConnEvent::Closed(reason) => {
                let _ = self.events.send(EndpointEvent::Closed {
                    peer_static: s.peer_static,
                    reason,
                });
            }
        }
    }

    /// When a session with a peer is established while another is open:
    /// a newer session from the same initiator replaces the older one; of
    /// two simultaneous sessions (established within 10 seconds of each
    /// other), the one initiated by the device with the smaller static key
    /// survives (`link.md#identity-binding`).
    /// Returns whether `new` survives.
    fn supersede(&self, new: &Arc<SessionInner>) -> bool {
        let others: Vec<Arc<SessionInner>> = lock(&self.state)
            .sessions
            .values()
            .filter(|o| o.local_index != new.local_index && o.peer_static == new.peer_static)
            .cloned()
            .collect();
        let local_static = *self.config.link_key.public_key().x25519();
        let initiator_static = |s: &SessionInner| match s.role {
            Role::Initiator => local_static,
            Role::Responder => s.peer_static,
        };
        let new_at = new.lock().established_at;
        let mut survives = true;
        for o in others {
            let (o_est, o_at) = {
                let c = o.lock();
                (c.established && !c.is_closed(), c.established_at)
            };
            if !o_est {
                continue;
            }
            let simultaneous = o.role != new.role
                && match (o_at, new_at) {
                    (Some(a), Some(b)) => {
                        a.max(b).duration_since(a.min(b)) < Duration::from_secs(10)
                    }
                    _ => false,
                };
            let loser = if simultaneous {
                if initiator_static(&o) < initiator_static(new) {
                    new.clone()
                } else {
                    o.clone()
                }
            } else {
                o.clone()
            };
            if loser.local_index == new.local_index {
                survives = false;
            }
            let events = {
                let mut c = loser.lock();
                c.close_local(CloseReason::Replaced);
                c.drain_events()
            };
            for e in events {
                if let ConnEvent::Closed(reason) = e {
                    let _ = self.events.send(EndpointEvent::Closed {
                        peer_static: loser.peer_static,
                        reason,
                    });
                }
            }
            if !survives {
                break;
            }
        }
        survives
    }
}
