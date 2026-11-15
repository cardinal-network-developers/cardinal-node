//! Endpoint records (`hosts.md#grants`): `{1: carrier, 2: address, 3:
//! port}`. The carrier is 1 for UDP, 2 for TCP, or the 8-byte name of one
//! defined elsewhere; under UDP and TCP the address is bytes (4 an IPv4
//! address, 16 an IPv6 address, any other length a network this version
//! does not know) or a host name as text.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use cardinal_encoding::{Record, Value};
use cardinal_link::CarrierKind;

/// The address part of an endpoint this version can use.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Address {
    /// An IP address.
    Ip(IpAddr),
    /// A host name.
    Name(String),
}

/// An endpoint record, held as it came. One this version cannot use, for
/// its carrier or for its address, gives no carrier and no address: it is
/// skipped, never a reason to take what holds it for malformed, and written
/// again as it was read.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EndpointAddr {
    record: Record,
}

impl EndpointAddr {
    /// An endpoint for a socket address.
    pub fn new(carrier: CarrierKind, addr: SocketAddr) -> EndpointAddr {
        let address: Value = match addr.ip() {
            IpAddr::V4(v) => Value::from(v.octets()),
            IpAddr::V6(v) => Value::from(v.octets()),
        };
        EndpointAddr::of(carrier, address, addr.port())
    }

    /// An endpoint for a host name.
    pub fn named(carrier: CarrierKind, name: &str, port: u16) -> EndpointAddr {
        EndpointAddr::of(carrier, Value::from(name), port)
    }

    fn of(carrier: CarrierKind, address: Value, port: u16) -> EndpointAddr {
        let carrier = match carrier {
            CarrierKind::Udp => 1u64,
            CarrierKind::Tcp => 2,
        };
        let record = Record::new()
            .with(1, carrier)
            .with(2, address)
            .with(3, port as u64);
        EndpointAddr { record }
    }

    /// The carrier, if it is one this version knows.
    pub fn carrier(&self) -> Option<CarrierKind> {
        match self.record.get(1).and_then(Value::as_uint) {
            Some(1) => Some(CarrierKind::Udp),
            Some(2) => Some(CarrierKind::Tcp),
            _ => None,
        }
    }

    /// The address, if the carrier is known and the address is one this
    /// version can use.
    pub fn address(&self) -> Option<Address> {
        self.carrier()?;
        match self.record.get(2)? {
            Value::Bytes(b) if b.len() == 4 => {
                let b = <[u8; 4]>::try_from(&b[..]).ok()?;
                Some(Address::Ip(IpAddr::V4(Ipv4Addr::from(b))))
            }
            Value::Bytes(b) if b.len() == 16 => {
                let b = <[u8; 16]>::try_from(&b[..]).ok()?;
                Some(Address::Ip(IpAddr::V6(Ipv6Addr::from(b))))
            }
            Value::Text(t) => Some(Address::Name(t.clone())),
            _ => None,
        }
    }

    /// The port, if the carrier is known.
    pub fn port(&self) -> Option<u16> {
        self.carrier()?;
        u16::try_from(self.record.get(3)?.as_uint()?).ok()
    }

    /// The socket address, if this version can use the endpoint and its
    /// address is an IP address.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self.address()? {
            Address::Ip(ip) => Some(SocketAddr::new(ip, self.port()?)),
            Address::Name(_) => None,
        }
    }

    /// The record form, as it came.
    pub fn to_record(&self) -> Record {
        self.record.clone()
    }

    /// The canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        self.record.encode()
    }

    /// Takes the record as it is. Whether it can be used is asked
    /// afterwards.
    pub fn from_record(r: &Record) -> EndpointAddr {
        EndpointAddr { record: r.clone() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for e in [
            EndpointAddr::new(CarrierKind::Udp, "192.0.2.1:7000".parse().unwrap()),
            EndpointAddr::new(CarrierKind::Tcp, "[2001:db8::2]:443".parse().unwrap()),
            EndpointAddr::named(CarrierKind::Tcp, "host.example", 443),
        ] {
            let r = Record::decode(&e.encode()).unwrap();
            assert_eq!(EndpointAddr::from_record(&r), e);
        }
        let e = EndpointAddr::named(CarrierKind::Tcp, "host.example", 443);
        assert_eq!(e.address(), Some(Address::Name("host.example".into())));
        assert_eq!((e.port(), e.socket_addr()), (Some(443), None));
    }

    /// D68. A carrier named by hash, a carrier number nobody set aside, an
    /// address of a length this version does not know: none can be used,
    /// and each is kept as it came.
    #[test]
    fn what_cannot_be_used_is_kept() {
        let ip = Value::from([192u8, 0, 2, 1]);
        for r in [
            Record::new()
                .with(1, [0x52u8; 8])
                .with(2, "by its document"),
            Record::new()
                .with(1, 3u64)
                .with(2, ip.clone())
                .with(3, 7u64),
            Record::new()
                .with(1, 1u64)
                .with(2, vec![7u8; 6])
                .with(3, 7u64),
            Record::new().with(1, 1u64).with(2, ip).with(3, 70_000u64),
        ] {
            let e = EndpointAddr::from_record(&r);
            assert_eq!(e.socket_addr(), None, "{r:?}");
            assert_eq!(e.to_record(), r);
            assert_eq!(Record::decode(&e.encode()).unwrap(), r);
        }
    }
}
