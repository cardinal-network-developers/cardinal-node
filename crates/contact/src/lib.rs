//! How connections start (`spec/contact.md`): pairing devices with a short
//! code and CPace, LAN discovery (`spec/hosts.md#local-discovery`), and the
//! invitation record.
//!
//! - [`code`]: codes like `4-amber-harbor-quiet`.
//! - [`pairing`]: the pairing exchange over UDP ([`pairing::Shower`],
//!   [`pairing::pair_typer`]); its result opens a link session with the
//!   pairing secret and, when the shower has no identity, yields the
//!   [`pairing::NewDevice`] an admin device adds with `add_key`.
//! - [`discovery`] over a minimal [`mdns`]: rotating, unlinkable tags only
//!   holders of the discovery secret recognize.
//! - [`invitation`]: the invitation record and its `cardinal:` text form,
//!   and `contact` service messages.
pub mod code;
pub mod discovery;
pub mod endpoint;
pub mod invitation;
pub mod mdns;
pub mod pairing;

pub use code::PairingCode;
pub use endpoint::{Address, EndpointAddr};
pub use invitation::{ContactMessage, Invitation};
pub use pairing::{
    pair_typer, DeviceEnroller, LocalDevice, NewDevice, PairRole, Paired, PeerInfo, Shower,
};

/// Errors from pairing, discovery, and invitations.
#[derive(Debug)]
pub enum ContactError {
    /// A code that does not parse.
    BadCode,
    /// The other side used a different code.
    WrongCode,
    /// The code failed too often; show a new one.
    TooManyAttempts,
    /// No answer in time.
    Timeout,
    /// Neither side has an identity (or the typer has none).
    NoIdentity,
    /// The new device's proof of possession is missing or invalid.
    BadProof,
    /// A malformed message or record.
    Malformed(&'static str),
    /// An I/O error.
    Io(std::io::Error),
}

impl std::fmt::Display for ContactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContactError::BadCode => f.write_str("not a pairing code"),
            ContactError::WrongCode => f.write_str("the codes do not match"),
            ContactError::TooManyAttempts => {
                f.write_str("too many failed attempts; new code needed")
            }
            ContactError::Timeout => f.write_str("timed out"),
            ContactError::NoIdentity => f.write_str("no identity to pair into"),
            ContactError::BadProof => f.write_str("invalid proof of possession"),
            ContactError::Malformed(w) => write!(f, "malformed {w}"),
            ContactError::Io(e) => write!(f, "i/o: {e}"),
        }
    }
}

impl std::error::Error for ContactError {}

impl From<std::io::Error> for ContactError {
    fn from(e: std::io::Error) -> ContactError {
        ContactError::Io(e)
    }
}
