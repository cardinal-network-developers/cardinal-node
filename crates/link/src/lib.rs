//! Link sessions of the Cardinal protocol (`spec/link.md`): an
//! authenticated, encrypted session between two devices that carries
//! reliable streams and unreliable datagrams, schedules traffic by
//! priority, and never answers a stranger.
//!
//! # Use
//!
//! An [`Endpoint`] binds carriers and accepts or opens [`Session`]s. A
//! session is returned only once the handshake, both `device proof` frames,
//! and the mandatory post-quantum rekey have completed. Streams
//! ([`Session::open_stream`], [`Session::accept_stream`]) implement
//! tokio's `AsyncRead`/`AsyncWrite`; datagram channels
//! ([`Session::channel`]) carry unreliable messages under 16-byte labels.
//! The identity layer is reached through the [`PeerDirectory`] trait.
//!
//! # What is implemented
//!
//! - Packets exactly as `link.md` lays them out: initiation (1216 bytes),
//!   response (1180), cookie reply (64), data (32–1200, see below), relayed
//!   header; random 32-bit indexes; `mac1`, `mac2`, rotating cookies.
//! - The handshake key schedule (Noise IK with ML-KEM-768 and an optional
//!   secret), the masked secret hint, the zero-ciphertext invitation case,
//!   and the confirmed-counter rule (a counter is confirmed only by the
//!   first authenticated data packet).
//! - Transport keys, ChaCha20-Poly1305 data packets with the 16-byte header
//!   as associated data, a 4096-counter replay window updated only after
//!   authentication, key phases (the previous phase accepted for 5 s).
//! - `device proof` first, then the mandatory `rekey`; periodic rekeys by
//!   the initiator every two minutes of activity or 2^40 packets.
//! - Frames 1–14, streams with per-stream and per-session flow control,
//!   datagram channels, priority classes (real-time first, then
//!   interactive, then background, in scheduling order), acknowledgements,
//!   path challenge/response and roaming, observed address, keepalive and
//!   idle timeout, simultaneous-session resolution.
//! - Carriers: TCP (length-prefixed packets, `link.md#carriers`) and UDP.
//!
//! # Experimental: reliable streams over UDP
//!
//! Over TCP the carrier delivers every packet in order, so streams never
//! retransmit. Over UDP, lost frames are resent in new packets (as the
//! specification requires) using packet-threshold and timeout loss
//! detection with a fixed window of 128 packets in flight. **There is no
//! congestion control and no pacing**: `link.md#priority` requires both,
//! plus a delay-based controller and a LEDBAT-style limit for background
//! traffic. Until those exist, use UDP for handshakes, datagrams, and
//! light stream traffic, and TCP for bulk transfer.
pub mod carrier;
mod conn;
pub mod directory;
mod endpoint;
pub mod frame;
pub mod handshake;
mod keys;
pub mod packet;
mod session;
#[cfg(test)]
mod vectors;

pub use carrier::CarrierKind;
pub use conn::{
    Admission, CloseReason, Role, SessionConfig, SessionStats, SESSION_WINDOW, STREAM_WINDOW,
};
pub use directory::{ExpectedPeer, LocalIdentity, MemoryDirectory, PeerDirectory, PeerIdentity};
pub use endpoint::{
    Bind, CookiePolicy, Endpoint, EndpointConfig, EndpointEvent, SecretEntry, Target,
};
pub use frame::{Priority, Service};
pub use session::{Channel, Session, Stream, DEFAULT_MAX_MESSAGE};

/// Largest datagram payload a channel can send in one packet.
pub const MAX_DATAGRAM_PAYLOAD: usize = 1140;

/// Errors from the link.
#[derive(Debug)]
pub enum LinkError {
    /// The session or endpoint closed.
    Closed(CloseReason),
    /// The session is not established yet.
    NotEstablished,
    /// A datagram larger than [`MAX_DATAGRAM_PAYLOAD`].
    TooLarge,
    /// No answer in time (strangers get none).
    Timeout,
    /// The handshake could not be built.
    Rejected,
    /// The endpoint has no carrier of the requested kind.
    NoCarrier,
    /// An I/O error.
    Io(std::io::Error),
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkError::Closed(r) => write!(f, "session closed: {r}"),
            LinkError::NotEstablished => f.write_str("session not established"),
            LinkError::TooLarge => f.write_str("datagram too large"),
            LinkError::Timeout => f.write_str("timed out"),
            LinkError::Rejected => f.write_str("handshake rejected"),
            LinkError::NoCarrier => f.write_str("no carrier of that kind"),
            LinkError::Io(e) => write!(f, "i/o: {e}"),
        }
    }
}

impl std::error::Error for LinkError {}

impl From<std::io::Error> for LinkError {
    fn from(e: std::io::Error) -> LinkError {
        LinkError::Io(e)
    }
}
