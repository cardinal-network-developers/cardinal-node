//! Invitations (`contact.md#invitations`) and `contact` service messages.

use cardinal_crypto::random_bytes;
use cardinal_encoding::Record;

use crate::endpoint::EndpointAddr;
use crate::ContactError;

/// The invitation kind.
pub const KIND_INVITATION: u64 = 6;

/// An invitation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invitation {
    /// The inviter's identity.
    pub inviter: [u8; 32],
    /// X25519 key of the endpoint.
    pub responder_static: [u8; 32],
    /// An inviter device, or a host.
    pub endpoint: EndpointAddr,
    /// The secret mixed into the handshake.
    pub secret: [u8; 16],
    /// Token registered at the host, if the endpoint is a host.
    pub token: Option<[u8; 16]>,
    /// Uses (default 1).
    pub uses: u64,
    /// The name the inviter suggests for themselves.
    pub name: Option<String>,
    /// Only this identity may use it.
    pub for_identity: Option<[u8; 32]>,
}

impl Invitation {
    /// A new single-use invitation with a fresh secret.
    pub fn new(
        inviter: [u8; 32],
        responder_static: [u8; 32],
        endpoint: EndpointAddr,
    ) -> Invitation {
        Invitation {
            inviter,
            responder_static,
            endpoint,
            secret: random_bytes(),
            token: None,
            uses: 1,
            name: None,
            for_identity: None,
        }
    }

    /// The record.
    pub fn to_record(&self) -> Record {
        Record::new()
            .with(0, KIND_INVITATION)
            .with(1, self.inviter)
            .with(2, self.responder_static)
            .with(3, self.endpoint.to_record())
            .with(4, self.secret)
            .with_opt(5, self.token)
            .with_opt(6, (self.uses != 1).then_some(self.uses))
            .with_opt(7, self.name.as_deref())
            .with_opt(8, self.for_identity)
    }

    /// Reads the record.
    pub fn from_record(r: &Record) -> Result<Invitation, ContactError> {
        let bad = |_| ContactError::Malformed("invitation");
        if r.uint(0).map_err(bad)? != KIND_INVITATION {
            return Err(ContactError::Malformed("not an invitation"));
        }
        Ok(Invitation {
            inviter: r.bytes_n(1).map_err(bad)?,
            responder_static: r.bytes_n(2).map_err(bad)?,
            endpoint: EndpointAddr::from_record(r.record(3).map_err(bad)?)?,
            secret: r.bytes_n(4).map_err(bad)?,
            token: r.opt_bytes_n(5).map_err(bad)?,
            uses: r.opt_uint(6).map_err(bad)?.unwrap_or(1),
            name: r.opt_text(7).map_err(bad)?.map(str::to_string),
            for_identity: r.opt_bytes_n(8).map_err(bad)?,
        })
    }

    /// `cardinal:` followed by the unpadded lowercase base32 of the record.
    pub fn to_text(&self) -> String {
        format!("cardinal:{}", base32_encode(&self.to_record().encode()))
    }

    /// Parses the text form.
    pub fn from_text(s: &str) -> Result<Invitation, ContactError> {
        let body = s
            .trim()
            .strip_prefix("cardinal:")
            .ok_or(ContactError::Malformed("invitation prefix"))?;
        let bytes = base32_decode(body).ok_or(ContactError::Malformed("invitation base32"))?;
        let r = Record::decode(&bytes).map_err(|_| ContactError::Malformed("invitation"))?;
        Invitation::from_record(&r)
    }
}

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// RFC 4648 base32, lowercase, without padding.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let mut acc: u64 = 0;
    let mut bits = 0;
    for &b in data {
        acc = (acc << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decodes [`base32_encode`]'s output (case-insensitive). Rejects
/// non-zero trailing bits.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut acc: u64 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let c = c.to_ascii_lowercase();
        let v = ALPHABET.iter().position(|&a| a == c)? as u64;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits >= 5 || acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

/// `contact` service messages (`contact.md`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContactMessage {
    /// `{0: 1, 1: identity id, 2: suggested name}`.
    Hello {
        /// Identity id.
        identity: [u8; 32],
        /// Suggested name.
        name: String,
    },
    /// `{0: 2, 1: sealed genesis entry of the relationship space}`.
    Genesis(Vec<u8>),
    /// `{0: 3}`.
    Done,
}

impl ContactMessage {
    /// The record.
    pub fn to_record(&self) -> Record {
        match self {
            ContactMessage::Hello { identity, name } => Record::new()
                .with(0, 1u64)
                .with(1, *identity)
                .with(2, name.as_str()),
            ContactMessage::Genesis(g) => Record::new().with(0, 2u64).with(1, g.clone()),
            ContactMessage::Done => Record::new().with(0, 3u64),
        }
    }

    /// Reads the record.
    pub fn from_record(r: &Record) -> Result<ContactMessage, ContactError> {
        let bad = |_| ContactError::Malformed("contact message");
        Ok(match r.uint(0).map_err(bad)? {
            1 => ContactMessage::Hello {
                identity: r.bytes_n(1).map_err(bad)?,
                name: r.opt_text(2).map_err(bad)?.unwrap_or_default().to_string(),
            },
            2 => ContactMessage::Genesis(r.bytes(1).map_err(bad)?.to_vec()),
            3 => ContactMessage::Done,
            _ => return Err(ContactError::Malformed("contact op")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cardinal_link::CarrierKind;

    #[test]
    fn base32() {
        // RFC 4648 test vectors, lowercased and unpadded.
        for (i, o) in [
            ("", ""),
            ("f", "my"),
            ("fo", "mzxq"),
            ("foo", "mzxw6"),
            ("foob", "mzxw6yq"),
            ("fooba", "mzxw6ytb"),
            ("foobar", "mzxw6ytboi"),
        ] {
            assert_eq!(base32_encode(i.as_bytes()), o);
            assert_eq!(base32_decode(o).unwrap(), i.as_bytes());
        }
        assert!(base32_decode("mz").is_none(), "non-zero trailing bits");
        assert!(base32_decode("m1").is_none());
    }

    #[test]
    fn invitation_text_round_trip() {
        let mut inv = Invitation::new(
            [1; 32],
            [2; 32],
            EndpointAddr::new(CarrierKind::Udp, "192.0.2.9:4433".parse().unwrap()),
        );
        inv.name = Some("Ana".into());
        inv.for_identity = Some([3; 32]);
        let t = inv.to_text();
        assert!(t.starts_with("cardinal:"));
        assert!(t.len() < 260, "{}", t.len());
        assert_eq!(Invitation::from_text(&t).unwrap(), inv);
        for m in [
            ContactMessage::Hello {
                identity: [4; 32],
                name: "Ben".into(),
            },
            ContactMessage::Genesis(vec![1, 2, 3]),
            ContactMessage::Done,
        ] {
            assert_eq!(ContactMessage::from_record(&m.to_record()).unwrap(), m);
        }
    }
}
