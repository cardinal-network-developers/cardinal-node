//! Frames (`link.md#frames`): the plaintext of a data packet is a sequence
//! of encoded records, each a frame whose key 0 is its type.
//!
//! Frames are encoded through [`cardinal_encoding::Record`] except stream
//! frames, which are written directly into the packet buffer on the hot
//! path; a test checks the two produce identical bytes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::Bytes;
use cardinal_encoding::varint::varint_len;
use cardinal_encoding::{decode_prefix, read_varint, write_varint, Record, Value};

/// Frame type numbers.
pub mod types {
    /// padding
    pub const PADDING: u64 = 1;
    /// ping
    pub const PING: u64 = 2;
    /// ack
    pub const ACK: u64 = 3;
    /// stream
    pub const STREAM: u64 = 4;
    /// reset
    pub const RESET: u64 = 5;
    /// window
    pub const WINDOW: u64 = 6;
    /// datagram
    pub const DATAGRAM: u64 = 7;
    /// path challenge
    pub const PATH_CHALLENGE: u64 = 8;
    /// path response
    pub const PATH_RESPONSE: u64 = 9;
    /// observed address
    pub const OBSERVED_ADDRESS: u64 = 10;
    /// rekey
    pub const REKEY: u64 = 11;
    /// rekey reply
    pub const REKEY_REPLY: u64 = 12;
    /// close
    pub const CLOSE: u64 = 13;
    /// device proof
    pub const DEVICE_PROOF: u64 = 14;
}

/// The service a stream speaks, named by its first frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Service {
    /// A core service number (1 sync, 2 blob, ... 8 contact).
    Core(u64),
    /// An application's own protocol, named by 32 bytes.
    App([u8; 32]),
}

impl Service {
    /// sync (`sync.md`).
    pub const SYNC: Service = Service::Core(1);
    /// blob transfer.
    pub const BLOB: Service = Service::Core(2);
    /// mailbox (`hosts.md`).
    pub const MAILBOX: Service = Service::Core(3);
    /// rendezvous.
    pub const RENDEZVOUS: Service = Service::Core(4);
    /// relay.
    pub const RELAY: Service = Service::Core(5);
    /// storage.
    pub const STORAGE: Service = Service::Core(6);
    /// ephemeral messages (`spaces.md`).
    pub const EPHEMERAL: Service = Service::Core(7);
    /// contact (`contact.md`).
    pub const CONTACT: Service = Service::Core(8);

    fn to_value(self) -> Value {
        match self {
            Service::Core(n) => Value::from(n),
            Service::App(b) => Value::from(b),
        }
    }

    fn from_value(v: &Value) -> Option<Service> {
        if let Some(n) = v.as_uint() {
            return Some(Service::Core(n));
        }
        v.as_bytes()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(Service::App)
    }
}

/// Priority classes (`link.md#priority`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// Calls and games: sent first.
    RealTime = 0,
    /// A person is waiting.
    Interactive = 1,
    /// Sync, backup, prefetch: spare capacity only.
    Background = 2,
}

impl Priority {
    /// From the wire value; unknown values are treated as background.
    pub fn from_u64(v: u64) -> Priority {
        match v {
            0 => Priority::RealTime,
            1 => Priority::Interactive,
            _ => Priority::Background,
        }
    }
}

/// An ack range `{1: gap, 2: length}`: counting down from the largest
/// counter, `gap` unacknowledged counters, then `length` acknowledged ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckRange {
    /// Unacknowledged counters skipped before this range.
    pub gap: u64,
    /// Acknowledged counters in this range (at least 1).
    pub length: u64,
}

/// A `device proof` frame body. `None` in [`Frame::DeviceProof`] is the
/// empty proof `{0: 14}`, sent by a device without an identity (see
/// DEVIATIONS.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceProof {
    /// Identity id.
    pub identity: [u8; 32],
    /// Device signing key.
    pub signing_key: [u8; 32],
    /// Ed25519 signature over `"cardinal device proof" || h`.
    pub signature: [u8; 64],
}

/// The prefix signed in a device proof.
pub const DEVICE_PROOF_DOMAIN: &[u8] = b"cardinal device proof";

/// A stream frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamFrame {
    /// Stream id.
    pub id: u64,
    /// Offset of the first byte.
    pub offset: u64,
    /// Data.
    pub data: Bytes,
    /// Whether this frame ends the stream.
    pub fin: bool,
    /// Service (offset 0 only).
    pub service: Option<Service>,
    /// Priority (offset 0 only).
    pub priority: Option<Priority>,
}

/// A frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// 1: padding.
    Padding(Vec<u8>),
    /// 2: ping.
    Ping,
    /// 3: ack.
    Ack {
        /// Largest counter received.
        largest: u64,
        /// Delay between receiving `largest` and sending this ack, in µs.
        delay_us: u64,
        /// Ranges, the first describing the run that ends at `largest`.
        ranges: Vec<AckRange>,
    },
    /// 4: stream.
    Stream(StreamFrame),
    /// 5: reset.
    Reset {
        /// Stream id.
        id: u64,
        /// Reason code.
        reason: u64,
    },
    /// 6: window.
    Window {
        /// Stream id, or 0 for the session.
        id: u64,
        /// Maximum offset.
        max: u64,
    },
    /// 7: datagram.
    Datagram {
        /// 16-byte channel label.
        channel: [u8; 16],
        /// Data.
        data: Bytes,
    },
    /// 8: path challenge.
    PathChallenge([u8; 8]),
    /// 9: path response.
    PathResponse([u8; 8]),
    /// 10: observed address.
    ObservedAddress(SocketAddr),
    /// 11: rekey, carrying an ML-KEM public key.
    Rekey(Vec<u8>),
    /// 12: rekey reply, carrying an ML-KEM ciphertext.
    RekeyReply(Vec<u8>),
    /// 13: close.
    Close(String),
    /// 14: device proof (`None`: the sender has no identity).
    DeviceProof(Option<DeviceProof>),
    /// A frame of a type this implementation does not know. It is
    /// acknowledged and otherwise ignored.
    Unknown(u64),
}

/// Frame decoding error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameError(pub &'static str);

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid frame: {}", self.0)
    }
}

impl std::error::Error for FrameError {}

impl Frame {
    /// Whether receiving this frame obliges the receiver to acknowledge.
    pub fn is_ack_eliciting(&self) -> bool {
        !matches!(
            self,
            Frame::Ack { .. } | Frame::Padding(_) | Frame::Close(_)
        )
    }

    /// Whether this frame may be sent before both device proofs are
    /// verified.
    pub fn allowed_before_proofs(&self) -> bool {
        matches!(
            self,
            Frame::DeviceProof(_)
                | Frame::Rekey(_)
                | Frame::RekeyReply(_)
                | Frame::Ack { .. }
                | Frame::Padding(_)
                | Frame::Close(_)
        )
    }

    /// The record form.
    pub fn to_record(&self) -> Record {
        let r = Record::new();
        match self {
            Frame::Padding(b) => r.with(0, types::PADDING).with(1, b.clone()),
            Frame::Ping => r.with(0, types::PING),
            Frame::Ack {
                largest,
                delay_us,
                ranges,
            } => r
                .with(0, types::ACK)
                .with(1, *largest)
                .with(2, *delay_us)
                .with(
                    3,
                    Value::list(
                        ranges
                            .iter()
                            .map(|g| Value::from(Record::new().with(1, g.gap).with(2, g.length))),
                    ),
                ),
            Frame::Stream(s) => r
                .with(0, types::STREAM)
                .with(1, s.id)
                .with(2, s.offset)
                .with(3, s.data.to_vec())
                .with_opt(4, s.fin.then_some(1u64))
                .with_opt(5, s.service.map(Service::to_value))
                .with_opt(6, s.priority.map(|p| p as u64)),
            Frame::Reset { id, reason } => r.with(0, types::RESET).with(1, *id).with(2, *reason),
            Frame::Window { id, max } => r.with(0, types::WINDOW).with(1, *id).with(2, *max),
            Frame::Datagram { channel, data } => r
                .with(0, types::DATAGRAM)
                .with(1, *channel)
                .with(2, data.to_vec()),
            Frame::PathChallenge(b) => r.with(0, types::PATH_CHALLENGE).with(1, *b),
            Frame::PathResponse(b) => r.with(0, types::PATH_RESPONSE).with(1, *b),
            Frame::ObservedAddress(a) => {
                let ip = match a.ip() {
                    IpAddr::V4(v) => v.octets().to_vec(),
                    IpAddr::V6(v) => v.octets().to_vec(),
                };
                r.with(0, types::OBSERVED_ADDRESS)
                    .with(1, ip)
                    .with(2, a.port() as u64)
            }
            Frame::Rekey(k) => r.with(0, types::REKEY).with(1, k.clone()),
            Frame::RekeyReply(c) => r.with(0, types::REKEY_REPLY).with(1, c.clone()),
            Frame::Close(reason) => r.with(0, types::CLOSE).with(1, reason.as_str()),
            Frame::DeviceProof(None) => r.with(0, types::DEVICE_PROOF),
            Frame::DeviceProof(Some(p)) => r
                .with(0, types::DEVICE_PROOF)
                .with(1, p.identity)
                .with(2, p.signing_key)
                .with(3, p.signature),
            Frame::Unknown(t) => r.with(0, *t),
        }
    }

    /// Appends the encoding to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Frame::Stream(s) => {
                encode_stream_frame(out, s.id, s.offset, &s.data, s.fin, s.service, s.priority)
            }
            other => other.to_record().encode_into(out),
        }
    }

    /// The encoded length.
    pub fn encoded_len(&self) -> usize {
        match self {
            Frame::Stream(s) => {
                stream_frame_overhead(s.id, s.offset, s.data.len(), s.fin, s.service, s.priority)
                    + s.data.len()
            }
            other => other.to_record().encoded_len(),
        }
    }

    /// Reads a frame from its record.
    pub fn from_record(r: &Record) -> Result<Frame, FrameError> {
        let t = r.uint(0).map_err(|_| FrameError("type"))?;
        let bad = |what| move |_| FrameError(what);
        Ok(match t {
            types::PADDING => Frame::Padding(
                r.opt_bytes(1)
                    .map_err(bad("padding"))?
                    .unwrap_or_default()
                    .to_vec(),
            ),
            types::PING => Frame::Ping,
            types::ACK => {
                let mut ranges = Vec::new();
                for v in r.opt_list(3).map_err(bad("ack ranges"))?.unwrap_or(&[]) {
                    let g = v.as_record().ok_or(FrameError("ack range"))?;
                    ranges.push(AckRange {
                        gap: g.opt_uint(1).map_err(bad("ack gap"))?.unwrap_or(0),
                        length: g.opt_uint(2).map_err(bad("ack length"))?.unwrap_or(0),
                    });
                }
                Frame::Ack {
                    largest: r.uint(1).map_err(bad("ack largest"))?,
                    delay_us: r.opt_uint(2).map_err(bad("ack delay"))?.unwrap_or(0),
                    ranges,
                }
            }
            types::STREAM => {
                let service = match r.get(5) {
                    Some(v) => Some(Service::from_value(v).ok_or(FrameError("service"))?),
                    None => None,
                };
                Frame::Stream(StreamFrame {
                    id: r.uint(1).map_err(bad("stream id"))?,
                    offset: r.opt_uint(2).map_err(bad("stream offset"))?.unwrap_or(0),
                    data: Bytes::copy_from_slice(
                        r.opt_bytes(3)
                            .map_err(bad("stream data"))?
                            .unwrap_or_default(),
                    ),
                    fin: r.opt_bool(4).map_err(bad("stream fin"))?.unwrap_or(false),
                    service,
                    priority: r
                        .opt_uint(6)
                        .map_err(bad("stream priority"))?
                        .map(Priority::from_u64),
                })
            }
            types::RESET => Frame::Reset {
                id: r.uint(1).map_err(bad("reset id"))?,
                reason: r.opt_uint(2).map_err(bad("reset reason"))?.unwrap_or(0),
            },
            types::WINDOW => Frame::Window {
                id: r.uint(1).map_err(bad("window id"))?,
                max: r.uint(2).map_err(bad("window max"))?,
            },
            types::DATAGRAM => Frame::Datagram {
                channel: r.bytes_n::<16>(1).map_err(bad("datagram channel"))?,
                data: Bytes::copy_from_slice(r.bytes(2).map_err(bad("datagram data"))?),
            },
            types::PATH_CHALLENGE => {
                Frame::PathChallenge(r.bytes_n::<8>(1).map_err(bad("path challenge"))?)
            }
            types::PATH_RESPONSE => {
                Frame::PathResponse(r.bytes_n::<8>(1).map_err(bad("path response"))?)
            }
            types::OBSERVED_ADDRESS => {
                let ip = r.bytes(1).map_err(bad("observed address"))?;
                let port = r.uint(2).map_err(bad("observed port"))?;
                let port = u16::try_from(port).map_err(|_| FrameError("observed port"))?;
                let ip = match ip.len() {
                    4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(ip).expect("4"))),
                    16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(ip).expect("16"))),
                    _ => return Err(FrameError("observed address length")),
                };
                Frame::ObservedAddress(SocketAddr::new(ip, port))
            }
            types::REKEY => Frame::Rekey(r.bytes(1).map_err(bad("rekey"))?.to_vec()),
            types::REKEY_REPLY => {
                Frame::RekeyReply(r.bytes(1).map_err(bad("rekey reply"))?.to_vec())
            }
            types::CLOSE => Frame::Close(
                r.opt_text(1)
                    .map_err(bad("close reason"))?
                    .unwrap_or_default()
                    .to_string(),
            ),
            types::DEVICE_PROOF => {
                if r.get(1).is_none() && r.get(2).is_none() && r.get(3).is_none() {
                    Frame::DeviceProof(None)
                } else {
                    Frame::DeviceProof(Some(DeviceProof {
                        identity: r.bytes_n::<32>(1).map_err(bad("proof identity"))?,
                        signing_key: r.bytes_n::<32>(2).map_err(bad("proof key"))?,
                        signature: r.bytes_n::<64>(3).map_err(bad("proof signature"))?,
                    }))
                }
            }
            other => Frame::Unknown(other),
        })
    }
}

/// Decodes a stream frame without building a record, or returns `None`
/// to fall back to the general decoder (which also rejects what this
/// one does not accept). Returns the frame and its length.
fn fast_stream_frame(input: &[u8]) -> Option<(Frame, usize)> {
    let mut pos = 0;
    let mut next = |input: &[u8]| -> Option<u64> {
        let (v, n) = read_varint(input.get(pos..)?, pos).ok()?;
        pos += n;
        Some(v)
    };
    let header = next(input)?;
    if header & 7 != 5 {
        return None;
    }
    let fields = header >> 3;
    if fields != 4 {
        return None;
    }
    // Exactly {0: 4, 1: id, 2: offset, 3: data}.
    if next(input)? != 0 || next(input)? != types::STREAM << 3 {
        return None;
    }
    if next(input)? != 1 {
        return None;
    }
    let id = next(input)?;
    if id & 7 != 0 || next(input)? != 2 {
        return None;
    }
    let offset = next(input)?;
    if offset & 7 != 0 || next(input)? != 3 {
        return None;
    }
    let h = next(input)?;
    if h & 7 != 2 {
        return None;
    }
    let len = (h >> 3) as usize;
    let data = input.get(pos..pos.checked_add(len)?)?;
    Some((
        Frame::Stream(StreamFrame {
            id: id >> 3,
            offset: offset >> 3,
            data: Bytes::copy_from_slice(data),
            fin: false,
            service: None,
            priority: None,
        }),
        pos + len,
    ))
}

/// Decodes a packet plaintext into frames.
pub fn decode_frames(mut input: &[u8]) -> Result<Vec<Frame>, FrameError> {
    let mut out = Vec::new();
    while !input.is_empty() {
        if let Some((f, n)) = fast_stream_frame(input) {
            out.push(f);
            input = &input[n..];
            continue;
        }
        let (v, n) = decode_prefix(input).map_err(|_| FrameError("encoding"))?;
        let r = v.as_record().ok_or(FrameError("not a record"))?;
        out.push(Frame::from_record(r)?);
        input = &input[n..];
    }
    Ok(out)
}

/// Encodes a list of frames.
pub fn encode_frames(frames: &[Frame]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in frames {
        f.encode_into(&mut out);
    }
    out
}

fn uint_len(v: u64) -> usize {
    varint_len(v << 3)
}

fn stream_field_count(fin: bool, service: Option<Service>, priority: Option<Priority>) -> u64 {
    4 + fin as u64 + service.is_some() as u64 + priority.is_some() as u64
}

/// Bytes a stream frame adds around `len` bytes of data.
pub fn stream_frame_overhead(
    id: u64,
    offset: u64,
    len: usize,
    fin: bool,
    service: Option<Service>,
    priority: Option<Priority>,
) -> usize {
    let n = stream_field_count(fin, service, priority);
    let mut size = varint_len((n << 3) | 5);
    size += 1 + uint_len(types::STREAM);
    size += 1 + uint_len(id);
    size += 1 + uint_len(offset);
    size += 1 + varint_len(((len as u64) << 3) | 2);
    if fin {
        size += 1 + uint_len(1);
    }
    match service {
        Some(Service::Core(s)) => size += 1 + uint_len(s),
        Some(Service::App(_)) => size += 1 + varint_len((32 << 3) | 2) + 32,
        None => {}
    }
    if let Some(p) = priority {
        size += 1 + uint_len(p as u64);
    }
    size
}

/// Writes a stream frame directly (canonical, identical to the record
/// encoding).
pub fn encode_stream_frame(
    out: &mut Vec<u8>,
    id: u64,
    offset: u64,
    data: &[u8],
    fin: bool,
    service: Option<Service>,
    priority: Option<Priority>,
) {
    encode_stream_frame_parts(out, id, offset, data, &[], fin, service, priority)
}

/// [`encode_stream_frame`] with the data in two pieces.
#[allow(clippy::too_many_arguments)]
pub fn encode_stream_frame_parts(
    out: &mut Vec<u8>,
    id: u64,
    offset: u64,
    data: &[u8],
    data2: &[u8],
    fin: bool,
    service: Option<Service>,
    priority: Option<Priority>,
) {
    let n = stream_field_count(fin, service, priority);
    write_varint((n << 3) | 5, out);
    write_varint(0, out);
    write_varint(types::STREAM << 3, out);
    write_varint(1, out);
    write_varint(id << 3, out);
    write_varint(2, out);
    write_varint(offset << 3, out);
    write_varint(3, out);
    write_varint((((data.len() + data2.len()) as u64) << 3) | 2, out);
    out.extend_from_slice(data);
    out.extend_from_slice(data2);
    if fin {
        write_varint(4, out);
        write_varint(1 << 3, out);
    }
    match service {
        Some(Service::Core(s)) => {
            write_varint(5, out);
            write_varint(s << 3, out);
        }
        Some(Service::App(b)) => {
            write_varint(5, out);
            write_varint((32 << 3) | 2, out);
            out.extend_from_slice(&b);
        }
        None => {}
    }
    if let Some(p) = priority {
        write_varint(6, out);
        write_varint((p as u64) << 3, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> Vec<Frame> {
        vec![
            Frame::Padding(vec![0; 5]),
            Frame::Ping,
            Frame::Ack {
                largest: 1000,
                delay_us: 25,
                ranges: vec![
                    AckRange { gap: 0, length: 10 },
                    AckRange { gap: 3, length: 1 },
                ],
            },
            Frame::Stream(StreamFrame {
                id: 1,
                offset: 0,
                data: Bytes::from_static(b"hello"),
                fin: false,
                service: Some(Service::SYNC),
                priority: Some(Priority::Background),
            }),
            Frame::Stream(StreamFrame {
                id: 300,
                offset: 1 << 40,
                data: Bytes::from(vec![7u8; 1000]),
                fin: true,
                service: None,
                priority: None,
            }),
            Frame::Stream(StreamFrame {
                id: 2,
                offset: 0,
                data: Bytes::new(),
                fin: true,
                service: Some(Service::App([3; 32])),
                priority: Some(Priority::RealTime),
            }),
            Frame::Stream(StreamFrame {
                id: 7,
                offset: 123_456_789,
                data: Bytes::from(vec![9u8; 1100]),
                fin: false,
                service: None,
                priority: None,
            }),
            Frame::Reset { id: 5, reason: 2 },
            Frame::Window {
                id: 0,
                max: 1 << 20,
            },
            Frame::Datagram {
                channel: [1; 16],
                data: Bytes::from_static(b"media"),
            },
            Frame::PathChallenge([1; 8]),
            Frame::PathResponse([2; 8]),
            Frame::ObservedAddress("192.0.2.1:4433".parse().unwrap()),
            Frame::ObservedAddress("[2001:db8::1]:9".parse().unwrap()),
            Frame::Rekey(vec![4; 1184]),
            Frame::RekeyReply(vec![5; 1088]),
            Frame::Close("bye".into()),
            Frame::DeviceProof(None),
            Frame::DeviceProof(Some(DeviceProof {
                identity: [1; 32],
                signing_key: [2; 32],
                signature: [3; 64],
            })),
        ]
    }

    #[test]
    fn round_trip_and_fast_path_matches_record() {
        let frames = samples();
        for f in &frames {
            let mut fast = Vec::new();
            f.encode_into(&mut fast);
            assert_eq!(fast, f.to_record().encode(), "{f:?}");
            assert_eq!(fast.len(), f.encoded_len(), "{f:?}");
        }
        let bytes = encode_frames(&frames);
        assert_eq!(decode_frames(&bytes).unwrap(), frames);
    }

    #[test]
    fn rekey_frame_size() {
        // An ML-KEM-768 public key in a rekey frame: 1190 bytes, more than
        // fits in a 1200-byte data packet (1168 bytes of plaintext).
        assert_eq!(Frame::Rekey(vec![0; 1184]).encoded_len(), 1190);
        const { assert!(1190 > crate::packet::MAX_PLAINTEXT) };
        const { assert!(1190 + 32 <= crate::packet::DATA_MAX_LEN_REKEY) };
    }

    #[test]
    fn rejects_non_canonical() {
        let mut b = Frame::Ping.to_record().encode();
        b.push(0xff);
        assert!(decode_frames(&b).is_err());
        assert!(decode_frames(&[0x00]).is_err());
    }
}
