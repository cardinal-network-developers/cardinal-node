//! Endpoint records (`hosts.md#grants`): `{1: carrier (1 UDP, 2 TCP), 2:
//! address (4 or 16 bytes, or a host name as text), 3: port}`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use cardinal_encoding::{Record, Value};
use cardinal_link::CarrierKind;

use crate::ContactError;

/// The address part of an endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Address {
    /// An IP address.
    Ip(IpAddr),
    /// A host name.
    Name(String),
}

/// An endpoint record.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EndpointAddr {
    /// The carrier.
    pub carrier: CarrierKind,
    /// The address.
    pub address: Address,
    /// The port.
    pub port: u16,
}

impl EndpointAddr {
    /// An endpoint for a socket address.
    pub fn new(carrier: CarrierKind, addr: SocketAddr) -> EndpointAddr {
        EndpointAddr {
            carrier,
            address: Address::Ip(addr.ip()),
            port: addr.port(),
        }
    }

    /// The socket address, if the address is an IP address.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match &self.address {
            Address::Ip(ip) => Some(SocketAddr::new(*ip, self.port)),
            Address::Name(_) => None,
        }
    }

    /// The record form.
    pub fn to_record(&self) -> Record {
        let carrier = match self.carrier {
            CarrierKind::Udp => 1u64,
            CarrierKind::Tcp => 2,
        };
        let address: Value = match &self.address {
            Address::Ip(IpAddr::V4(v)) => Value::from(v.octets()),
            Address::Ip(IpAddr::V6(v)) => Value::from(v.octets()),
            Address::Name(n) => Value::from(n.as_str()),
        };
        Record::new()
            .with(1, carrier)
            .with(2, address)
            .with(3, self.port as u64)
    }

    /// The canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        self.to_record().encode()
    }

    /// Reads the record form.
    pub fn from_record(r: &Record) -> Result<EndpointAddr, ContactError> {
        let bad = |_| ContactError::Malformed("endpoint");
        let carrier = match r.uint(1).map_err(bad)? {
            1 => CarrierKind::Udp,
            2 => CarrierKind::Tcp,
            _ => return Err(ContactError::Malformed("endpoint carrier")),
        };
        let address = match r.get(2) {
            Some(Value::Bytes(b)) if b.len() == 4 => Address::Ip(IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&b[..]).expect("4"),
            ))),
            Some(Value::Bytes(b)) if b.len() == 16 => Address::Ip(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&b[..]).expect("16"),
            ))),
            Some(Value::Text(t)) => Address::Name(t.clone()),
            _ => return Err(ContactError::Malformed("endpoint address")),
        };
        let port = u16::try_from(r.uint(3).map_err(bad)?)
            .map_err(|_| ContactError::Malformed("endpoint port"))?;
        Ok(EndpointAddr {
            carrier,
            address,
            port,
        })
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
            EndpointAddr {
                carrier: CarrierKind::Tcp,
                address: Address::Name("host.example".into()),
                port: 443,
            },
        ] {
            let r = Record::decode(&e.encode()).unwrap();
            assert_eq!(EndpointAddr::from_record(&r).unwrap(), e);
        }
    }
}
