//! Kinds: key `0` of every stored or transferable object
//! (`encoding.md#kinds`, `encoding.md#registry-of-core-kinds`).

use std::fmt;

use crate::value::Value;

/// The kind of an object: a small core integer or a 32-byte extension name.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// A core kind from the registry (see the constants in this module).
    Core(u64),
    /// An application or extension kind: BLAKE3 of its defining document.
    Named([u8; 32]),
}

impl Kind {
    /// Reads a kind from a value: an unsigned integer or exactly 32 bytes.
    pub fn from_value(v: &Value) -> Option<Kind> {
        match v {
            Value::Int(i) => i.as_u64().map(Kind::Core),
            Value::Bytes(b) => <[u8; 32]>::try_from(b.as_slice()).ok().map(Kind::Named),
            _ => None,
        }
    }

    /// The name of a core kind, if it is in the registry.
    pub fn core_name(self) -> Option<&'static str> {
        match self {
            Kind::Core(n) => core_kind_name(n),
            Kind::Named(_) => None,
        }
    }
}

impl fmt::Debug for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Kind::Core(n) => match core_kind_name(*n) {
                Some(name) => write!(f, "Kind({n}: {name})"),
                None => write!(f, "Kind({n})"),
            },
            Kind::Named(h) => {
                write!(f, "Kind(h'")?;
                for b in h {
                    write!(f, "{b:02x}")?;
                }
                write!(f, "')")
            }
        }
    }
}

/// Signed object (`encoding.md`).
pub const SIGNED_OBJECT: u64 = 1;
/// Identity entry (`identity.md`).
pub const IDENTITY_ENTRY: u64 = 2;
/// Sealed entry (`spaces.md`).
pub const SEALED_ENTRY: u64 = 3;
/// Space entry (`spaces.md`).
pub const SPACE_ENTRY: u64 = 4;
/// Blob index (`blobs.md`).
pub const BLOB_INDEX: u64 = 5;
/// Invitation (`contact.md`).
pub const INVITATION: u64 = 6;
/// Envelope payload (`hosts.md#envelopes`).
pub const ENVELOPE_PAYLOAD: u64 = 7;
/// Join request (`contact.md#when-the-inviter-is-offline`).
pub const JOIN_REQUEST: u64 = 8;
/// Host grant (`hosts.md#grants`).
pub const HOST_GRANT: u64 = 9;
/// Public address (`contact.md#following`).
pub const PUBLIC_ADDRESS: u64 = 10;
/// Envelope (`hosts.md#envelopes`).
pub const ENVELOPE: u64 = 11;
/// Bundle (`sync.md#sneakernet-and-delay-tolerant-carriage`).
pub const BUNDLE: u64 = 12;
/// Canonical state (`state.md#canonical-state`).
pub const CANONICAL_STATE: u64 = 13;
/// Kinds 14 through 63 are reserved for the specification until the base
/// is frozen.
pub const RESERVED: std::ops::RangeInclusive<u64> = 14..=63;

/// The registry name of core kind `n`, if assigned.
pub fn core_kind_name(n: u64) -> Option<&'static str> {
    Some(match n {
        SIGNED_OBJECT => "signed object",
        IDENTITY_ENTRY => "identity entry",
        SEALED_ENTRY => "sealed entry",
        SPACE_ENTRY => "space entry",
        BLOB_INDEX => "blob index",
        INVITATION => "invitation",
        ENVELOPE_PAYLOAD => "envelope payload",
        JOIN_REQUEST => "join request",
        HOST_GRANT => "host grant",
        PUBLIC_ADDRESS => "public address",
        ENVELOPE => "envelope",
        BUNDLE => "bundle",
        CANONICAL_STATE => "canonical state",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_value() {
        assert_eq!(Kind::from_value(&Value::from(3u32)), Some(Kind::Core(3)));
        assert_eq!(
            Kind::from_value(&Value::from([7u8; 32])),
            Some(Kind::Named([7; 32]))
        );
        assert_eq!(Kind::from_value(&Value::from([7u8; 16])), None);
        assert_eq!(Kind::from_value(&Value::from(-1i32)), None);
        assert_eq!(Kind::from_value(&Value::from("x")), None);
        assert_eq!(Kind::Core(5).core_name(), Some("blob index"));
        assert_eq!(Kind::Core(14).core_name(), None);
        assert_eq!(Value::from(Kind::Named([1; 32])), Value::from([1u8; 32]));
    }
}
