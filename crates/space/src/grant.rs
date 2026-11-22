//! Host grants (`hosts.md#grants`): a device's signed statement that it
//! serves an identity, and where. A person's always-on device grants itself
//! to its own identity, and the account space records the grant.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use cardinal_crypto::{HybridPublicKey, SigningKey};
use cardinal_encoding::kind::HOST_GRANT;
use cardinal_encoding::{Kind, Record, SignedObject, Value};
use cardinal_identity::KeyId;

/// The mailbox service.
pub const MAILBOX: u64 = 3;
/// The rendezvous service.
pub const RENDEZVOUS: u64 = 4;
/// The relay service.
pub const RELAY: u64 = 5;
/// The storage service.
pub const STORAGE: u64 = 6;

const UDP: u64 = 1;
const TCP: u64 = 2;

/// Where a host listens (`hosts.md#grants`): `{1: carrier, 2: address, 3:
/// port}`, held as it came. The carrier is 1 for UDP, 2 for TCP, or the
/// 8-byte name of one defined elsewhere, and only its document says what
/// the other fields hold then. Under UDP and TCP the address is a host
/// name as text, or bytes: 4 an IPv4 address, 16 an IPv6 address, and any
/// other length an address of a network this version does not know.
///
/// An endpoint this version cannot use gives no address
/// ([`socket_addr`](Self::socket_addr)), and is skipped by whoever looks
/// for one. It is never a reason to take what holds it for malformed, and
/// it is written again as it was read, field for field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    record: Record,
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
        let port: u16 = port.parse().ok()?;
        let address = match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(a)) => Value::from(a.octets().to_vec()),
            Ok(IpAddr::V6(a)) => Value::from(a.octets().to_vec()),
            Err(_) => Value::from(host),
        };
        let record = Record::new()
            .with(1, TCP)
            .with(2, address)
            .with(3, port as u64);
        Some(Endpoint { record })
    }

    /// The record, as it came.
    pub fn to_record(&self) -> Record {
        self.record.clone()
    }

    /// Takes the record as it is. Whether it can be used is asked
    /// afterwards: one that cannot is kept all the same.
    pub fn from_record(r: &Record) -> Endpoint {
        Endpoint { record: r.clone() }
    }

    /// Whether the carrier is one this version knows: UDP or TCP.
    fn known_carrier(&self) -> bool {
        matches!(self.record.get(1).and_then(Value::as_uint), Some(UDP | TCP))
    }

    /// The address or host name, if this version can use the endpoint.
    pub fn host(&self) -> Option<String> {
        if !self.known_carrier() {
            return None;
        }
        let v = self.record.get(2)?;
        match (v.as_text(), v.as_bytes()) {
            (Some(t), _) => Some(t.to_owned()),
            (_, Some(b)) => match b.len() {
                4 => Some(IpAddr::from(<[u8; 4]>::try_from(b).ok()?).to_string()),
                16 => Some(IpAddr::from(<[u8; 16]>::try_from(b).ok()?).to_string()),
                _ => None,
            },
            _ => None,
        }
    }

    /// The port, if this version can use the endpoint.
    pub fn port(&self) -> Option<u16> {
        if !self.known_carrier() {
            return None;
        }
        self.record.get(3)?.as_uint()?.try_into().ok()
    }

    /// Whether this version can use it: a carrier and an address it knows.
    pub fn usable(&self) -> bool {
        self.host().is_some() && self.port().is_some()
    }

    /// The address, if this version can use the endpoint and it is not a
    /// host name.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        Some(SocketAddr::new(self.host()?.parse().ok()?, self.port()?))
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.host(), self.port()) {
            (Some(host), Some(port)) if host.contains(':') => write!(f, "[{host}]:{port}"),
            (Some(host), Some(port)) => write!(f, "{host}:{port}"),
            _ => write!(f, "(an address this version cannot use)"),
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
    /// Bytes of storage granted: `None`, the field left out, when there is
    /// no limit; 0 is none at all.
    pub storage_bytes: Option<u64>,
    /// Days an unfetched envelope or unrenewed storage is kept: `None`, the
    /// field left out, when there is no limit; 0 is not at all.
    pub retention_days: Option<u64>,
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
            .with_opt(5, self.storage_bytes)
            .with_opt(6, self.retention_days)
            .with(
                7,
                Value::list(self.endpoints.iter().map(Endpoint::to_record)),
            )
            .with(8, self.link_key.to_record());
        let mut o = SignedObject::new(inner);
        key.sign_object(&mut o);
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
        let limit = |k: u64| -> Option<Option<u64>> {
            match r.get(k) {
                None => Some(None),
                Some(v) => v.as_uint().map(Some),
            }
        };
        let grant = Grant {
            host: id(1)?,
            served: id(2)?,
            services: r
                .get(3)?
                .as_list()?
                .iter()
                .map(Value::as_uint)
                .collect::<Option<_>>()?,
            // left out, no limit; there, a uint, or it is no grant
            storage_bytes: limit(5)?,
            retention_days: limit(6)?,
            endpoints: r
                .get(7)?
                .as_list()?
                .iter()
                .filter_map(|e| Some(Endpoint::from_record(e.as_record()?)))
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
            storage_bytes: None,
            retention_days: None,
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

    /// `hosts.md#grants`: storage bytes and retention left out mean no
    /// limit, and 0 means none; a value of another type is no grant.
    #[test]
    fn a_limit_left_out_is_none_and_zero_is_zero() {
        let key = SigningKey::from_seed(&[2; 32]);
        let open = |g: &Grant| Grant::open(&g.sign(&key)).unwrap().0;
        let unlimited = grant();
        let read = open(&unlimited);
        assert_eq!((read.storage_bytes, read.retention_days), (None, None));
        let inner = SignedObject::decode(&unlimited.sign(&key)).unwrap();
        assert!(inner.inner().get(5).is_none() && inner.inner().get(6).is_none());
        let zero = Grant {
            storage_bytes: Some(0),
            retention_days: Some(0),
            ..grant()
        };
        let read = open(&zero);
        assert_eq!((read.storage_bytes, read.retention_days), (Some(0), Some(0)));
        let some = Grant {
            storage_bytes: Some(1 << 30),
            retention_days: Some(30),
            ..grant()
        };
        assert_eq!(open(&some), some);
        let g = grant();
        let wrong = Record::new()
            .with(0, HOST_GRANT)
            .with(1, g.host)
            .with(2, g.served)
            .with(3, Value::list(g.services.iter().copied()))
            .with(4, Value::list(Vec::<Record>::new()))
            .with(5, "a lot")
            .with(7, Value::list(Vec::<Record>::new()))
            .with(8, g.link_key.to_record());
        let mut o = SignedObject::new(wrong);
        key.sign_object(&mut o);
        assert_eq!(Grant::open(&o.encode()), None);
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
        assert_eq!(
            (e.host().as_deref(), e.port()),
            (Some("nuc.lan"), Some(7171))
        );
        assert!(e.usable());
        assert_eq!(Endpoint::parse("nuc.lan"), None);
        assert_eq!(Endpoint::parse(":7171"), None);
        assert_eq!(Endpoint::parse("nuc.lan:99999"), None);
    }

    /// D68 (`hosts.md#grants`). An endpoint this version cannot use, for
    /// its carrier or for its address, does not make a grant malformed: it
    /// is skipped where a host is looked for, and kept as it came.
    #[test]
    fn an_endpoint_that_cannot_be_used_is_skipped_and_kept() {
        let key = SigningKey::from_seed(&[2; 32]);
        let radio = Record::new()
            .with(1, [0x52u8; 8])
            .with(2, "anything its document says")
            .with(7, 9u64);
        let other_network = Record::new()
            .with(1, 2u64)
            .with(2, vec![7u8; 6])
            .with(3, 7171u64);
        let udp = Record::new()
            .with(1, 1u64)
            .with(2, vec![192u8, 0, 2, 1])
            .with(3, 7171u64);
        let given = [radio, other_network, udp];
        let g = grant();
        let inner = Record::new()
            .with(0, HOST_GRANT)
            .with(1, g.host)
            .with(2, g.served)
            .with(3, Value::list(g.services.iter().copied()))
            .with(4, Value::list(Vec::<Record>::new()))
            .with(7, Value::list(given.iter().cloned()))
            .with(8, g.link_key.to_record());
        let mut o = SignedObject::new(inner);
        key.sign_object(&mut o);
        let (read, _) = Grant::open(&o.encode()).expect("it is taken for malformed");
        // each is there, in order, as it came
        let kept: Vec<Record> = read.endpoints.iter().map(Endpoint::to_record).collect();
        assert_eq!(kept, given);
        // and only the one that can be used gives an address
        let usable: Vec<SocketAddr> = read
            .endpoints
            .iter()
            .filter_map(Endpoint::socket_addr)
            .collect();
        assert_eq!(usable, ["192.0.2.1:7171".parse().unwrap()]);
        // signed again, the grant says what it said
        assert_eq!(read.sign(&key), o.encode());
    }
}
