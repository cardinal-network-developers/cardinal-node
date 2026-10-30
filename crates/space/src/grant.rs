//! Host grants (`hosts.md#grants`): a device's signed statement that it
//! serves an identity, and where. A person's always-on device grants itself
//! to its own identity, and the account space records the grant.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use cardinal_crypto::{HybridPublicKey, SigningKey};
use cardinal_encoding::kind::HOST_GRANT;
use cardinal_encoding::{Kind, ObjectSignature, Record, SignedObject, Value};
use cardinal_identity::KeyId;

/// The mailbox service.
pub const MAILBOX: u64 = 3;
/// The rendezvous service.
pub const RENDEZVOUS: u64 = 4;
/// The relay service.
pub const RELAY: u64 = 5;
/// The storage service.
pub const STORAGE: u64 = 6;

const TCP: u64 = 2;

/// Where a host listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// An address, or a host name for one that changes.
    pub host: String,
    /// The TCP port.
    pub port: u16,
}

impl Endpoint {
    /// Reads `host:port`, with an IPv6 address in brackets.
    pub fn parse(s: &str) -> Option<Endpoint> {
        let (host, port) = s.rsplit_once(':')?;
        let host = host.strip_prefix('[').unwrap_or(host);
        let host = host.strip_suffix(']').unwrap_or(host);
        if host.is_empty() {
            return None;
        }
        Some(Endpoint {
            host: host.to_owned(),
            port: port.parse().ok()?,
        })
    }

    fn to_record(&self) -> Record {
        let address = match self.host.parse::<IpAddr>() {
            Ok(IpAddr::V4(a)) => Value::from(a.octets().to_vec()),
            Ok(IpAddr::V6(a)) => Value::from(a.octets().to_vec()),
            Err(_) => Value::from(self.host.as_str()),
        };
        Record::new()
            .with(1, TCP)
            .with(2, address)
            .with(3, self.port as u64)
    }

    fn from_record(r: &Record) -> Option<Endpoint> {
        let v = r.get(2)?;
        let host = match (v.as_text(), v.as_bytes()) {
            (Some(t), _) => t.to_owned(),
            (_, Some(b)) => match b.len() {
                4 => IpAddr::from(<[u8; 4]>::try_from(b).ok()?).to_string(),
                16 => IpAddr::from(<[u8; 16]>::try_from(b).ok()?).to_string(),
                _ => return None,
            },
            _ => return None,
        };
        Some(Endpoint {
            host,
            port: r.get(3)?.as_uint()?.try_into().ok()?,
        })
    }

    /// The address, if it is not a host name.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        Some(SocketAddr::new(self.host.parse().ok()?, self.port))
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// A host grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The host's identity.
    pub host: [u8; 32],
    /// The identity it serves.
    pub served: [u8; 32],
    /// Its services.
    pub services: Vec<u64>,
    /// Bytes of storage granted; 0 when there is no limit.
    pub storage_bytes: u64,
    /// Days unrenewed storage is kept; 0 when there is no limit.
    pub retention_days: u64,
    /// Where it listens.
    pub endpoints: Vec<Endpoint>,
    /// The link key of the serving device.
    pub link_key: HybridPublicKey,
}

impl Grant {
    /// The signed object, as bytes.
    pub fn sign(&self, key: &SigningKey) -> Vec<u8> {
        let inner = Record::new()
            .with(0, HOST_GRANT)
            .with(1, self.host)
            .with(2, self.served)
            .with(3, Value::list(self.services.iter().copied()))
            .with(4, Value::list(Vec::<Record>::new()))
            .with(5, self.storage_bytes)
            .with(6, self.retention_days)
            .with(
                7,
                Value::list(self.endpoints.iter().map(Endpoint::to_record)),
            )
            .with(8, self.link_key.to_record());
        let mut o = SignedObject::new(inner);
        let signature = key.sign(&o.signing_message());
        o.add_signature(ObjectSignature::new(key.public_key(), signature));
        o.encode()
    }

    /// Reads a signed grant, if it is one and its signature holds. Returns
    /// who signed it: whether that key may speak for the host is for the
    /// host identity's log to say.
    pub fn open(bytes: &[u8]) -> Option<(Grant, KeyId)> {
        let o = SignedObject::decode(bytes).ok()?;
        cardinal_crypto::verify_object(&o).ok()?;
        let signer = o.signatures().first()?.key;
        let r = o.inner();
        if r.kind().ok()? != Kind::Core(HOST_GRANT) {
            return None;
        }
        let id = |k: u64| -> Option<[u8; 32]> { r.get(k)?.as_bytes()?.try_into().ok() };
        let grant = Grant {
            host: id(1)?,
            served: id(2)?,
            services: r
                .get(3)?
                .as_list()?
                .iter()
                .map(Value::as_uint)
                .collect::<Option<_>>()?,
            storage_bytes: r.get(5)?.as_uint()?,
            retention_days: r.get(6)?.as_uint()?,
            endpoints: r
                .get(7)?
                .as_list()?
                .iter()
                .filter_map(|e| Endpoint::from_record(e.as_record()?))
                .collect(),
            link_key: HybridPublicKey::from_record(r.get(8)?.as_record()?).ok()?,
        };
        Some((grant, signer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cardinal_crypto::HybridKeyPair;

    fn grant() -> Grant {
        Grant {
            host: [1; 32],
            served: [1; 32],
            services: vec![STORAGE],
            storage_bytes: 0,
            retention_days: 0,
            endpoints: vec![
                Endpoint::parse("192.168.1.20:7171").unwrap(),
                Endpoint::parse("[fd00::20]:7171").unwrap(),
                Endpoint::parse("nuc.example.org:7171").unwrap(),
            ],
            link_key: HybridKeyPair::from_seed(&[3; 32]).public_key().clone(),
        }
    }

    #[test]
    fn a_grant_reads_back_with_its_signer() {
        let key = SigningKey::from_seed(&[2; 32]);
        let (read, signer) = Grant::open(&grant().sign(&key)).unwrap();
        assert_eq!(read, grant());
        assert_eq!(signer, key.public_key());
        assert_eq!(read.endpoints[0].to_string(), "192.168.1.20:7171");
        assert_eq!(read.endpoints[1].to_string(), "[fd00::20]:7171");
        assert_eq!(read.endpoints[2].socket_addr(), None);
    }

    #[test]
    fn a_changed_grant_does_not_open() {
        let key = SigningKey::from_seed(&[2; 32]);
        let mut bytes = grant().sign(&key);
        let at = bytes.len() / 2;
        bytes[at] ^= 1;
        assert_eq!(Grant::open(&bytes), None);
    }

    #[test]
    fn addresses_read_from_what_a_person_types() {
        let e = Endpoint::parse("nuc.lan:7171").unwrap();
        assert_eq!((e.host.as_str(), e.port), ("nuc.lan", 7171));
        assert_eq!(Endpoint::parse("nuc.lan"), None);
        assert_eq!(Endpoint::parse(":7171"), None);
        assert_eq!(Endpoint::parse("nuc.lan:99999"), None);
    }
}
