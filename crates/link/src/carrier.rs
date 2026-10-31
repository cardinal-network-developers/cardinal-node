//! Carriers (`link.md#carriers`): anything that delivers datagrams of up to
//! 1232 bytes. Above this module nothing can tell which carrier was used.
//!
//! - **TCP**: each packet is prefixed by its length as a 16-bit integer
//!   (little-endian, like every integer in `link.md`).
//! - **UDP**: one packet per datagram. Reliable streams over UDP use a
//!   simple retransmission scheme without congestion control; see the
//!   crate documentation.
//! - **Relay**: packets wrapped in the 8-byte relay header and sent to a
//!   host over another carrier.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Notify};

use crate::packet::{self, MAX_DATAGRAM};

/// Which carrier a target is reached over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CarrierKind {
    /// UDP (endpoint carrier 1).
    Udp,
    /// TCP (endpoint carrier 2).
    Tcp,
}

/// Something that consumes packets arriving on a carrier.
pub(crate) trait Ingress: Send + Sync + 'static {
    fn ingress(&self, packet: &mut [u8], path: &Path);

    /// Called when the carrier has passed on everything it has read for
    /// now: wakes readers whose wake-up was deferred.
    fn flush(&self) {}
}

/// A TCP connection carrying packets.
pub(crate) struct TcpPath {
    id: u64,
    peer: SocketAddr,
    tx: mpsc::Sender<Bytes>,
    closed: AtomicBool,
    /// Tells the writer to send what is queued and end the connection.
    finish: Notify,
}

impl TcpPath {
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.finish.notify_one();
    }
}

/// Ends the connection when the reader stops, however it stops.
struct CloseOnDrop(Arc<TcpPath>);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// Where a packet came from, and where replies go.
#[derive(Clone)]
pub(crate) enum Path {
    Udp {
        socket: Arc<Udp>,
        addr: SocketAddr,
    },
    Tcp(Arc<TcpPath>),
    Relayed {
        via: Box<Path>,
        channel: u32,
    },
    /// An in-memory path for unit tests of the session core.
    #[cfg(test)]
    Mem(u64),
}

impl std::fmt::Debug for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Path::Udp { addr, .. } => write!(f, "udp:{addr}"),
            Path::Tcp(t) => write!(f, "tcp#{}:{}", t.id, t.peer),
            Path::Relayed { via, channel } => write!(f, "relay#{channel} via {via:?}"),
            #[cfg(test)]
            Path::Mem(i) => write!(f, "mem#{i}"),
        }
    }
}

impl Path {
    /// Whether two paths are the same.
    pub fn same(&self, other: &Path) -> bool {
        match (self, other) {
            (Path::Udp { addr: a, .. }, Path::Udp { addr: b, .. }) => a == b,
            (Path::Tcp(a), Path::Tcp(b)) => a.id == b.id,
            (
                Path::Relayed {
                    via: a,
                    channel: ca,
                },
                Path::Relayed {
                    via: b,
                    channel: cb,
                },
            ) => ca == cb && a.same(b),
            #[cfg(test)]
            (Path::Mem(a), Path::Mem(b)) => a == b,
            _ => false,
        }
    }

    /// The carrier, if the path has one of the kinds a peer can be asked
    /// for.
    pub fn carrier(&self) -> Option<CarrierKind> {
        match self {
            Path::Udp { .. } => Some(CarrierKind::Udp),
            Path::Tcp(_) => Some(CarrierKind::Tcp),
            Path::Relayed { via, .. } => via.carrier(),
            #[cfg(test)]
            Path::Mem(_) => None,
        }
    }

    /// Whether packets go through a host.
    pub fn is_relayed(&self) -> bool {
        matches!(self, Path::Relayed { .. })
    }

    /// The remote socket address, if the path has one.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        match self {
            Path::Udp { addr, .. } => Some(*addr),
            Path::Tcp(t) => Some(t.peer),
            Path::Relayed { via, .. } => via.remote_addr(),
            #[cfg(test)]
            Path::Mem(_) => None,
        }
    }

    /// Whether the carrier itself delivers every packet in order, so the
    /// session need not retransmit.
    pub fn is_reliable(&self) -> bool {
        match self {
            Path::Tcp(_) => true,
            Path::Udp { .. } => false,
            // Whatever carries this leg, the host's other leg may lose it.
            Path::Relayed { .. } => false,
            #[cfg(test)]
            Path::Mem(_) => true,
        }
    }

    /// Whether the path is known to be dead.
    pub fn is_closed(&self) -> bool {
        match self {
            Path::Tcp(t) => t.closed.load(Ordering::Relaxed),
            Path::Relayed { via, .. } => via.is_closed(),
            _ => false,
        }
    }

    /// Ends the connection under this path, if it has one of its own,
    /// once what was sent has gone. A relay's belongs to the host's session.
    pub fn close(&self) {
        if let Path::Tcp(t) = self {
            t.close();
        }
    }

    /// Sends a packet.
    pub async fn send(&self, packet: Bytes) -> std::io::Result<()> {
        match self {
            Path::Udp { socket, addr } => socket.send_to(&packet, *addr).await,
            Path::Tcp(t) => {
                t.tx.send(frame_tcp(&[packet]))
                    .await
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            Path::Relayed { via, channel } => {
                let mut b = BytesMut::with_capacity(packet.len() + packet::RELAY_HEADER_LEN);
                b.put_slice(&packet::relay_header(*channel));
                b.put_slice(&packet);
                Box::pin(via.send(b.freeze())).await
            }
            #[cfg(test)]
            Path::Mem(_) => Ok(()),
        }
    }

    /// Sends several packets; over TCP they are written in one batch.
    pub async fn send_batch(&self, packets: Vec<Bytes>) -> std::io::Result<()> {
        match self {
            Path::Tcp(t) => {
                t.tx.send(frame_tcp(&packets))
                    .await
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            _ => {
                for p in packets {
                    self.send(p).await?;
                }
                Ok(())
            }
        }
    }

    /// Sends without waiting; drops the packet if the carrier is busy.
    pub fn try_send(&self, packet: Bytes) {
        match self {
            Path::Udp { socket, addr } => socket.try_send_to(&packet, *addr),
            Path::Tcp(t) => {
                let _ = t.tx.try_send(frame_tcp(&[packet]));
            }
            Path::Relayed { via, channel } => {
                let mut b = BytesMut::with_capacity(packet.len() + packet::RELAY_HEADER_LEN);
                b.put_slice(&packet::relay_header(*channel));
                b.put_slice(&packet);
                via.try_send(b.freeze());
            }
            #[cfg(test)]
            Path::Mem(_) => {}
        }
    }
}

/// Frames packets for TCP: each prefixed by its length as a little-endian
/// u16.
fn frame_tcp(packets: &[Bytes]) -> Bytes {
    let total: usize = packets.iter().map(|p| p.len() + 2).sum();
    let mut b = BytesMut::with_capacity(total);
    for p in packets {
        b.put_u16_le(p.len() as u16);
        b.put_slice(p);
    }
    b.freeze()
}

/// A UDP socket. Tests can put a simulated NAT in front of one: then all of
/// its traffic goes through `gateway`, each datagram after the address it is
/// to or from, and nothing else gets in, as with a device behind a router.
pub(crate) struct Udp {
    socket: UdpSocket,
    gateway: Option<SocketAddr>,
}

/// An IPv4 address and a little-endian port, ahead of a datagram.
const GATEWAY_HEADER: usize = 6;

fn gateway_header(addr: SocketAddr) -> [u8; GATEWAY_HEADER] {
    let mut h = [0u8; GATEWAY_HEADER];
    if let SocketAddr::V4(a) = addr {
        h[..4].copy_from_slice(&a.ip().octets());
        h[4..].copy_from_slice(&a.port().to_le_bytes());
    }
    h
}

impl Udp {
    pub(crate) fn new(socket: UdpSocket, gateway: Option<SocketAddr>) -> Udp {
        Udp { socket, gateway }
    }

    pub(crate) fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    async fn send_to(&self, packet: &[u8], addr: SocketAddr) -> std::io::Result<()> {
        match self.gateway {
            None => self.socket.send_to(packet, addr).await.map(|_| ()),
            Some(gateway) => {
                let wrapped = [&gateway_header(addr)[..], packet].concat();
                self.socket.send_to(&wrapped, gateway).await.map(|_| ())
            }
        }
    }

    fn try_send_to(&self, packet: &[u8], addr: SocketAddr) {
        let _ = match self.gateway {
            None => self.socket.try_send_to(packet, addr),
            Some(gateway) => {
                let wrapped = [&gateway_header(addr)[..], packet].concat();
                self.socket.try_send_to(&wrapped, gateway)
            }
        };
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        loop {
            let (n, from) = self.socket.recv_from(buf).await?;
            let Some(gateway) = self.gateway else {
                return Ok((n, from));
            };
            if from != gateway || n < GATEWAY_HEADER {
                continue;
            }
            let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_le_bytes([buf[4], buf[5]]);
            buf.copy_within(GATEWAY_HEADER..n, 0);
            return Ok((n - GATEWAY_HEADER, SocketAddr::from((ip, port))));
        }
    }
}

static NEXT_TCP_ID: AtomicU64 = AtomicU64::new(1);

/// How long a TCP connection may stay silent before it is dropped.
pub(crate) const TCP_IDLE: Duration = Duration::from_secs(200);

/// Starts reading and writing packets on a TCP connection.
pub(crate) fn spawn_tcp(
    stream: TcpStream,
    ingress: Arc<dyn Ingress>,
) -> (Path, tokio::task::AbortHandle) {
    let _ = stream.set_nodelay(true);
    let peer = stream
        .peer_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    let (rx_half, tx_half) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Bytes>(64);
    let tp = Arc::new(TcpPath {
        id: NEXT_TCP_ID.fetch_add(1, Ordering::Relaxed),
        peer,
        tx,
        closed: AtomicBool::new(false),
        finish: Notify::new(),
    });
    let path = Path::Tcp(tp.clone());

    // Writer: batches arrive already length-prefixed; flush when the
    // queue drains.
    let wtp = tp.clone();
    tokio::spawn(async move {
        let mut w = BufWriter::with_capacity(256 * 1024, tx_half);
        'outer: loop {
            // The writer holds a sender itself, so the queue never ends on
            // its own: only `finish` ends the connection.
            let p = tokio::select! {
                biased;
                p = rx.recv() => p,
                _ = wtp.finish.notified() => None,
            };
            let Some(p) = p else {
                break;
            };
            let mut next = Some(p);
            while let Some(p) = next.take() {
                if w.write_all(&p).await.is_err() {
                    break 'outer;
                }
                if let Ok(p) = rx.try_recv() {
                    next = Some(p);
                }
            }
            if w.flush().await.is_err() {
                break;
            }
        }
        wtp.closed.store(true, Ordering::Relaxed);
        let _ = w.shutdown().await;
    });

    // Reader.
    let rpath = path.clone();
    let reader = tokio::spawn(async move {
        let _close = CloseOnDrop(tp);
        let mut r = BufReader::with_capacity(256 * 1024, rx_half);
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let mut len = [0u8; 2];
            match tokio::time::timeout(TCP_IDLE, r.read_exact(&mut len)).await {
                Ok(Ok(_)) => {}
                _ => break,
            }
            let n = u16::from_le_bytes(len) as usize;
            if n == 0 || n > MAX_DATAGRAM {
                break;
            }
            if r.read_exact(&mut buf[..n]).await.is_err() {
                break;
            }
            ingress.ingress(&mut buf[..n], &rpath);
            // Wake deferred readers unless another whole packet is
            // already buffered.
            let b = r.buffer();
            if b.len() < 2 || b.len() < 2 + u16::from_le_bytes([b[0], b[1]]) as usize {
                ingress.flush();
            }
        }
    });
    (path, reader.abort_handle())
}

/// Starts receiving packets on a UDP socket.
pub(crate) fn spawn_udp(
    socket: Arc<Udp>,
    ingress: Arc<dyn Ingress>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, addr)) => {
                    if n == 0 || n > MAX_DATAGRAM {
                        continue;
                    }
                    let path = Path::Udp {
                        socket: socket.clone(),
                        addr,
                    };
                    ingress.ingress(&mut buf[..n], &path);
                    ingress.flush();
                }
                Err(e) => {
                    // ICMP errors (connection refused) surface here on some
                    // platforms; they are not fatal for the socket.
                    if e.kind() == std::io::ErrorKind::ConnectionReset
                        || e.kind() == std::io::ErrorKind::ConnectionRefused
                    {
                        continue;
                    }
                    if Arc::strong_count(&socket) <= 1 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    })
}
