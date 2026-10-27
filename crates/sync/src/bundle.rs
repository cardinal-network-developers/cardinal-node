//! Bundles for sneakernet and delay-tolerant carriage
//! (`sync.md#sneakernet-and-delay-tolerant-carriage`).
//!
//! A bundle is a file holding one record: `{0: 12, 1: list of objects
//! messages}`, or `{0: 12, 2: recipient identity id, 3: sealed record}`
//! where the sealed record is the encoded list sealed to the recipient's
//! encryption key with context `"bundle"`. The receiver imports the objects
//! exactly as if they had been fetched.

use cardinal_crypto::{open, seal, HybridKeyPair, HybridPublicKey, Sealed};
use cardinal_encoding::kind::BUNDLE;
use cardinal_encoding::{decode, Kind, Record, SchemaError, Value};

use crate::{Id, Message, SyncError};

/// The sealing context of bundles.
pub const BUNDLE_CONTEXT: &[u8] = b"bundle";

/// A bundle, as read from or written to a file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bundle {
    /// Objects messages in the clear (the objects are self-verifying and
    /// usually already encrypted).
    Plain(Vec<Message>),
    /// Objects messages sealed to one identity.
    Sealed {
        /// The recipient identity's id.
        recipient: Id,
        /// The sealed encoded list of objects messages.
        sealed: Sealed,
    },
}

fn check_objects(messages: &[Message]) -> Result<(), SyncError> {
    if messages
        .iter()
        .all(|m| matches!(m, Message::Objects { .. }))
    {
        Ok(())
    } else {
        Err(SyncError::Bundle("a bundle holds only objects messages"))
    }
}

fn messages_value(messages: &[Message]) -> Value {
    Value::List(messages.iter().map(|m| m.to_record().into()).collect())
}

fn messages_from(list: &[Value]) -> Result<Vec<Message>, SyncError> {
    let msgs = list
        .iter()
        .map(|v| {
            v.as_record()
                .ok_or(SyncError::Bundle("bundle items must be records"))
                .and_then(Message::from_record)
        })
        .collect::<Result<Vec<_>, _>>()?;
    check_objects(&msgs)?;
    Ok(msgs)
}

impl Bundle {
    /// A bundle in the clear. Every message must be an objects message.
    pub fn plain(messages: Vec<Message>) -> Result<Bundle, SyncError> {
        check_objects(&messages)?;
        Ok(Bundle::Plain(messages))
    }

    /// A bundle sealed to `recipient`, whose encryption key is `key`.
    pub fn sealed(
        recipient: Id,
        key: &HybridPublicKey,
        messages: &[Message],
    ) -> Result<Bundle, SyncError> {
        check_objects(messages)?;
        let plaintext = messages_value(messages).encode();
        Ok(Bundle::Sealed {
            recipient,
            sealed: seal(key, &plaintext, BUNDLE_CONTEXT),
        })
    }

    /// The recipient of a sealed bundle.
    pub fn recipient(&self) -> Option<&Id> {
        match self {
            Bundle::Plain(_) => None,
            Bundle::Sealed { recipient, .. } => Some(recipient),
        }
    }

    /// The record form.
    pub fn to_record(&self) -> Record {
        let r = Record::new().with(0, BUNDLE);
        match self {
            Bundle::Plain(msgs) => r.with(1, messages_value(msgs)),
            Bundle::Sealed { recipient, sealed } => {
                r.with(2, *recipient).with(3, sealed.to_record())
            }
        }
    }

    /// The file contents.
    pub fn encode(&self) -> Vec<u8> {
        self.to_record().encode()
    }

    /// Reads a bundle file.
    pub fn decode(bytes: &[u8]) -> Result<Bundle, SyncError> {
        let r = Record::decode(bytes)?;
        let kind = r.kind()?;
        if kind != Kind::Core(BUNDLE) {
            return Err(SchemaError::WrongKind {
                expected: Kind::Core(BUNDLE),
                found: kind,
            }
            .into());
        }
        match (r.opt_list(1)?, r.opt_bytes_n::<32>(2)?) {
            (Some(list), None) => Ok(Bundle::Plain(messages_from(list)?)),
            (None, Some(recipient)) => Ok(Bundle::Sealed {
                recipient,
                sealed: Sealed::from_record(r.record(3)?)?,
            }),
            _ => Err(SyncError::Bundle("a bundle is either plain or sealed")),
        }
    }

    /// The objects messages: directly for a plain bundle, or by opening a
    /// sealed one with the recipient's key pair.
    pub fn messages(&self, key: Option<&HybridKeyPair>) -> Result<Vec<Message>, SyncError> {
        match self {
            Bundle::Plain(msgs) => Ok(msgs.clone()),
            Bundle::Sealed { sealed, .. } => {
                let key = key.ok_or(SyncError::Bundle("sealed bundle needs a key"))?;
                let plaintext = open(key, sealed, BUNDLE_CONTEXT)?;
                match decode(&plaintext)? {
                    Value::List(list) => messages_from(&list),
                    _ => Err(SyncError::Bundle("sealed bundle must hold a list")),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn objects() -> Vec<Message> {
        vec![
            Message::Objects {
                label: [1; 32],
                objects: vec![b"one".to_vec(), b"two".to_vec()],
            },
            Message::Objects {
                label: [2; 32],
                objects: vec![vec![9; 1000]],
            },
        ]
    }

    #[test]
    fn plain_round_trip() {
        let b = Bundle::plain(objects()).unwrap();
        let back = Bundle::decode(&b.encode()).unwrap();
        assert_eq!(back, b);
        assert_eq!(back.messages(None).unwrap(), objects());
        assert!(Bundle::plain(vec![Message::Want {
            label: [0; 32],
            ids: vec![]
        }])
        .is_err());
    }

    #[test]
    fn sealed_round_trip() {
        let kp = HybridKeyPair::from_seed(&[4; 32]);
        let other = HybridKeyPair::from_seed(&[5; 32]);
        let b = Bundle::sealed([7; 32], kp.public_key(), &objects()).unwrap();
        let back = Bundle::decode(&b.encode()).unwrap();
        assert_eq!(back.recipient(), Some(&[7; 32]));
        assert_eq!(back.messages(Some(&kp)).unwrap(), objects());
        assert!(back.messages(Some(&other)).is_err());
        assert!(back.messages(None).is_err());
    }
}
