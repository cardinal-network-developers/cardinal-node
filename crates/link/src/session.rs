//! Session, stream, and channel handles, and the task that drives a
//! session's timers and transmissions.

use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use cardinal_crypto::HybridPublicKey;
use cardinal_encoding::{decode, read_varint, write_varint, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

use crate::carrier::Path;
use crate::conn::{Admission, CloseReason, Conn, ConnEvent, Role, SessionStats, Signals};
use crate::directory::PeerIdentity;
use crate::endpoint::EndpointInner;
use crate::frame::{Priority, Service};
use crate::LinkError;

/// Largest message [`Stream::recv_message`] accepts by default.
pub const DEFAULT_MAX_MESSAGE: usize = 16 * 1024 * 1024;

pub(crate) struct SessionInner {
    pub conn: Mutex<Conn>,
    pub signals: Arc<Signals>,
    pub local_index: u32,
    pub peer_static: [u8; 32],
    pub role: Role,
    pub endpoint: Weak<EndpointInner>,
}

impl SessionInner {
    pub fn lock(&self) -> MutexGuard<'_, Conn> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Processes an incoming data packet. Returns whether some reader
    /// waits for [`flush_wakes`](Self::flush_wakes).
    pub fn recv(self: &Arc<Self>, pkt: &mut [u8], path: &Path) -> bool {
        let (events, deferred) = {
            let mut c = self.lock();
            c.recv_packet(pkt, path, Instant::now());
            (c.drain_events(), c.has_deferred_wakes())
        };
        self.handle_events(events);
        deferred
    }

    /// Wakes the readers whose wake-up waited for the end of a batch.
    pub fn flush_wakes(&self) {
        let wakers = self.lock().take_deferred_wakes();
        for w in wakers {
            w.wake();
        }
    }

    pub fn handle_events(self: &Arc<Self>, events: Vec<ConnEvent>) {
        if events.is_empty() {
            return;
        }
        if let Some(ep) = self.endpoint.upgrade() {
            for e in events {
                ep.on_session_event(self, e);
            }
        }
    }
}

/// Runs a session: sends what the core produces and fires its timers.
pub(crate) async fn drive(inner: Arc<SessionInner>) {
    const BATCH: usize = 32;
    loop {
        loop {
            let (out, events) = {
                let mut c = inner.lock();
                let now = Instant::now();
                let mut out: Vec<(Path, Bytes)> = Vec::new();
                while out.len() < BATCH {
                    match c.poll_transmit(now) {
                        Some(p) => out.push(p),
                        None => break,
                    }
                }
                (out, c.drain_events())
            };
            inner.handle_events(events);
            if out.is_empty() {
                break;
            }
            // Group consecutive packets for the same path.
            let mut groups: Vec<(Path, Vec<Bytes>)> = Vec::new();
            for (path, pkt) in out {
                match groups.last_mut() {
                    Some((p, v)) if p.same(&path) => v.push(pkt),
                    _ => groups.push((path, vec![pkt])),
                }
            }
            for (path, pkts) in groups {
                if path.send_batch(pkts).await.is_err() && path.is_closed() {
                    let events = {
                        let mut c = inner.lock();
                        if c.path.same(&path) {
                            c.handle_timeout(Instant::now());
                        }
                        c.drain_events()
                    };
                    inner.handle_events(events);
                }
            }
        }
        let (timeout, drained) = {
            let c = inner.lock();
            (c.poll_timeout(), c.is_drained())
        };
        if drained {
            break;
        }
        let notified = inner.signals.driver.notified();
        match timeout {
            Some(t) => {
                tokio::select! {
                    _ = notified => {}
                    _ = tokio::time::sleep_until(t.into()) => {
                        let events = {
                            let mut c = inner.lock();
                            c.handle_timeout(Instant::now());
                            c.drain_events()
                        };
                        inner.handle_events(events);
                    }
                }
            }
            None => notified.await,
        }
    }
    let path = inner.lock().path.clone();
    path.close();
    if let Some(ep) = inner.endpoint.upgrade() {
        ep.remove_session(inner.local_index);
    }
}

/// An established, authenticated session with one peer device.
#[derive(Clone)]
pub struct Session {
    pub(crate) inner: Arc<SessionInner>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("index", &self.inner.local_index)
            .field("peer", &crate::directory::hex8(&self.inner.peer_static))
            .field("role", &self.inner.role)
            .finish()
    }
}

impl Session {
    /// The peer's X25519 static key.
    pub fn peer_static(&self) -> [u8; 32] {
        self.inner.peer_static
    }

    /// The peer's full link key, if known (absent only in invitation
    /// sessions whose initiator was unknown to the responder).
    pub fn peer_link_key(&self) -> Option<HybridPublicKey> {
        self.inner.lock().peer_link_key.clone()
    }

    /// The peer's verified device proof; `None` if the peer has no
    /// identity (an invitee or new device, or a public/restore session).
    pub fn peer_identity(&self) -> Option<PeerIdentity> {
        self.inner.lock().peer_identity
    }

    /// The handshake hash `h` (signed in device proofs and `prove`).
    pub fn handshake_hash(&self) -> [u8; 32] {
        self.inner.lock().handshake_hash
    }

    /// Whether this device initiated the session.
    pub fn role(&self) -> Role {
        self.inner.role
    }

    /// How the session was admitted.
    pub fn admission(&self) -> Admission {
        self.inner.lock().admission.clone()
    }

    /// Counters, the key phase, and the round-trip estimate.
    pub fn stats(&self) -> SessionStats {
        self.inner.lock().stats()
    }

    /// The address of the current path, if it has one.
    pub fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.lock().path.remote_addr()
    }

    /// The address the peer says our packets come from (`observed
    /// address`).
    pub fn observed_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.lock().observed_by_peer
    }

    /// Why the session closed, if it has.
    pub fn close_reason(&self) -> Option<CloseReason> {
        self.inner.lock().close.clone()
    }

    /// Flow-control state, for diagnosing stalls.
    #[doc(hidden)]
    pub fn debug_flow(&self) -> String {
        self.inner.lock().debug_flow()
    }

    /// Opens a stream for a service.
    pub fn open_stream(&self, service: Service, priority: Priority) -> Result<Stream, LinkError> {
        let mut c = self.inner.lock();
        if let Some(r) = &c.close {
            return Err(LinkError::Closed(r.clone()));
        }
        let id = c
            .open_stream(service, priority)
            .ok_or(LinkError::NotEstablished)?;
        Ok(Stream {
            inner: self.inner.clone(),
            id,
            service,
            priority,
        })
    }

    /// Waits for the peer to open a stream. `None` once the session closes.
    pub async fn accept_stream(&self) -> Option<Stream> {
        loop {
            let notified = self.inner.signals.state.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut c = self.inner.lock();
                if let Some((id, service, priority)) = c.accept_stream() {
                    return Some(Stream {
                        inner: self.inner.clone(),
                        id,
                        service,
                        priority,
                    });
                }
                if c.is_closed() {
                    return None;
                }
            }
            notified.await;
        }
    }

    /// Joins a datagram channel: datagrams the peer sends with this label
    /// arrive on the returned channel, and datagrams sent on it use
    /// `priority`. Joining the same label again replaces the earlier
    /// channel's receiver.
    pub fn channel(&self, label: [u8; 16], priority: Priority) -> Channel {
        let rx = self.inner.lock().subscribe(label, priority);
        Channel {
            inner: self.inner.clone(),
            label,
            priority,
            rx,
        }
    }

    /// Sends one datagram without joining the channel.
    pub fn send_datagram(
        &self,
        label: [u8; 16],
        priority: Priority,
        data: impl Into<Bytes>,
    ) -> Result<(), LinkError> {
        self.inner
            .lock()
            .send_datagram(label, priority, data.into())
    }

    /// Closes the session with a reason the peer sees.
    pub fn close(&self, reason: &str) {
        let events = {
            let mut c = self.inner.lock();
            c.close_local(CloseReason::Local(reason.to_string()));
            c.drain_events()
        };
        self.inner.handle_events(events);
    }

    /// Whether the session has closed.
    pub fn is_closed(&self) -> bool {
        self.inner.lock().is_closed()
    }

    /// Waits until the session closes.
    pub async fn closed(&self) -> CloseReason {
        loop {
            let notified = self.inner.signals.state.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(r) = self.close_reason() {
                return r;
            }
            notified.await;
        }
    }

    /// Re-checks the peer's device proof against the directory (call when
    /// the peer's identity log changed). Returns false if this closed the
    /// session.
    pub fn recheck_identity(&self) -> bool {
        let (ok, events) = {
            let mut c = self.inner.lock();
            let ok = c.recheck_identity();
            (ok, c.drain_events())
        };
        self.inner.handle_events(events);
        ok
    }

    /// Waits until the session is established and the endpoint has kept
    /// it over any other session with the same peer (`supersede` in
    /// `endpoint.rs`); a session that loses is closed as replaced.
    pub(crate) async fn wait_admitted(&self) -> Result<(), LinkError> {
        loop {
            let notified = self.inner.signals.state.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let c = self.inner.lock();
                if let Some(r) = &c.close {
                    return Err(LinkError::Closed(r.clone()));
                }
                if c.admitted {
                    return Ok(());
                }
            }
            notified.await;
        }
    }
}

/// A reliable, ordered byte stream within a session. Reading and writing
/// work through [`AsyncRead`] and [`AsyncWrite`]; `shutdown` sends `fin`.
/// Dropping a stream whose sending side is unfinished resets it.
pub struct Stream {
    inner: Arc<SessionInner>,
    id: u64,
    service: Service,
    priority: Priority,
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream")
            .field("id", &self.id)
            .field("service", &self.service)
            .field("priority", &self.priority)
            .finish()
    }
}

impl Stream {
    /// The stream id.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The service named by the stream's first frame.
    pub fn service(&self) -> Service {
        self.service
    }

    /// The priority class.
    pub fn priority(&self) -> Priority {
        self.priority
    }

    /// Aborts the stream in both directions.
    pub fn reset(&mut self, reason: u64) {
        self.inner.lock().stream_reset(self.id, reason);
    }

    /// Sends `fin` after the data written so far.
    pub fn finish(&mut self) {
        self.inner.lock().stream_finish(self.id);
    }

    /// Writes one message: its length as a varint, then the encoded value
    /// (`link.md#streams`).
    pub async fn send_message(&mut self, value: &Value) -> std::io::Result<()> {
        let body = value.encode();
        let mut out = Vec::with_capacity(body.len() + 10);
        write_varint(body.len() as u64, &mut out);
        out.extend_from_slice(&body);
        self.write_all(&out).await
    }

    /// Writes one message already encoded: its length as a varint, then
    /// `body` (which must be one encoded value).
    pub async fn send_message_bytes(&mut self, body: &[u8]) -> std::io::Result<()> {
        let mut prefix = Vec::with_capacity(10);
        write_varint(body.len() as u64, &mut prefix);
        self.write_all(&prefix).await?;
        self.write_all(body).await
    }

    /// Reads one message; `None` at the end of the stream.
    pub async fn recv_message(&mut self) -> std::io::Result<Option<Value>> {
        self.recv_message_max(DEFAULT_MAX_MESSAGE).await
    }

    /// [`recv_message`](Stream::recv_message) with a size limit.
    pub async fn recv_message_max(&mut self, max: usize) -> std::io::Result<Option<Value>> {
        match self.recv_message_bytes_max(max).await? {
            None => Ok(None),
            Some(body) => decode(&body)
                .map(Some)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())),
        }
    }

    /// Reads one message without decoding it: its encoded bytes, for
    /// callers that decode the record themselves; `None` at the end of
    /// the stream.
    pub async fn recv_message_bytes_max(&mut self, max: usize) -> std::io::Result<Option<Vec<u8>>> {
        let mut prefix = Vec::with_capacity(10);
        loop {
            let mut b = [0u8; 1];
            let n = self.read(&mut b).await?;
            if n == 0 {
                if prefix.is_empty() {
                    return Ok(None);
                }
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            prefix.push(b[0]);
            if b[0] & 0x80 == 0 {
                break;
            }
            if prefix.len() > 9 {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
        }
        let (len, _) = read_varint(&prefix, 0)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        if len as usize > max {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "message too large",
            ));
        }
        let mut body = vec![0u8; len as usize];
        self.read_exact(&mut body).await?;
        Ok(Some(body))
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let id = self.id;
        self.inner.lock().stream_read(id, cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let id = self.id;
        self.inner.lock().stream_write(id, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let id = self.id;
        self.inner.lock().stream_flush(id, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let id = self.id;
        self.inner.lock().stream_finish(id);
        Poll::Ready(Ok(()))
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.inner.lock().stream_dropped(self.id);
    }
}

/// A datagram channel: unreliable, unordered messages under a 16-byte
/// label (`link.md#datagrams`).
pub struct Channel {
    inner: Arc<SessionInner>,
    label: [u8; 16],
    priority: Priority,
    rx: mpsc::Receiver<Bytes>,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("label", &crate::directory::hex8(&self.label))
            .field("priority", &self.priority)
            .finish()
    }
}

impl Channel {
    /// The label.
    pub fn label(&self) -> [u8; 16] {
        self.label
    }

    /// Sends a datagram of at most [`MAX_DATAGRAM_PAYLOAD`](crate::MAX_DATAGRAM_PAYLOAD) bytes.
    pub fn send(&self, data: impl Into<Bytes>) -> Result<(), LinkError> {
        self.inner
            .lock()
            .send_datagram(self.label, self.priority, data.into())
    }

    /// Receives the next datagram; `None` once the session closes.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.rx.recv().await
    }
}
