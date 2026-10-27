//! Packet formats (`link.md#packets`): sizes, offsets, `mac1`/`mac2`, and
//! cookie replies. Integers are little-endian.

use cardinal_crypto::{ct_eq, hash_parts, keyed_hash};

/// Largest datagram any carrier must deliver.
pub const MAX_DATAGRAM: usize = 1232;
/// Initiation packet length.
pub const INITIATION_LEN: usize = 1216;
/// Response packet length.
pub const RESPONSE_LEN: usize = 1180;
/// Cookie reply length.
pub const COOKIE_REPLY_LEN: usize = 64;
/// Header of a data packet, authenticated as associated data.
pub const DATA_HEADER_LEN: usize = 16;
/// AEAD tag length.
pub const TAG_LEN: usize = 16;
/// Smallest data packet: a header and an empty ciphertext.
pub const DATA_MIN_LEN: usize = DATA_HEADER_LEN + TAG_LEN;
/// Largest ordinary data packet (`link.md`: data is 32–1200 bytes).
pub const DATA_MAX_LEN: usize = 1200;
/// Largest data packet this implementation sends: only a packet carrying
/// nothing but a `rekey` frame exceeds [`DATA_MAX_LEN`], because an
/// ML-KEM-768 public key does not fit in 1200 bytes. 1224 bytes plus the
/// 8-byte relay header is exactly [`MAX_DATAGRAM`]. See DEVIATIONS.md.
pub const DATA_MAX_LEN_REKEY: usize = MAX_DATAGRAM - RELAY_HEADER_LEN;
/// Largest plaintext of an ordinary data packet.
pub const MAX_PLAINTEXT: usize = DATA_MAX_LEN - DATA_MIN_LEN;
/// Relay header length (`hosts.md#relay`).
pub const RELAY_HEADER_LEN: usize = 8;

/// Packet type bytes.
pub const TYPE_INITIATION: u8 = 1;
/// Response.
pub const TYPE_RESPONSE: u8 = 2;
/// Cookie reply.
pub const TYPE_COOKIE_REPLY: u8 = 3;
/// Data.
pub const TYPE_DATA: u8 = 4;
/// Relayed.
pub const TYPE_RELAYED: u8 = 5;

/// Field offsets of an initiation.
pub mod init {
    /// Secret hint (3 bytes after the type byte).
    pub const HINT: usize = 1;
    /// Sender index.
    pub const SENDER: usize = 4;
    /// Counter.
    pub const COUNTER: usize = 8;
    /// Ephemeral X25519 key.
    pub const EPHEMERAL: usize = 16;
    /// ML-KEM ciphertext.
    pub const KEM_CT: usize = 48;
    /// Encrypted static key.
    pub const STATIC: usize = 1136;
    /// mac1.
    pub const MAC1: usize = 1184;
    /// mac2.
    pub const MAC2: usize = 1200;
}

/// Field offsets of a response.
pub mod resp {
    /// Sender index.
    pub const SENDER: usize = 4;
    /// Receiver index.
    pub const RECEIVER: usize = 8;
    /// Ephemeral X25519 key.
    pub const EPHEMERAL: usize = 12;
    /// ML-KEM ciphertext.
    pub const KEM_CT: usize = 44;
    /// Encrypted empty payload.
    pub const EMPTY: usize = 1132;
    /// mac1.
    pub const MAC1: usize = 1148;
    /// mac2.
    pub const MAC2: usize = 1164;
}

/// Field offsets of a cookie reply: type and three zero bytes, receiver
/// index, a 24-byte nonce, and the 16-byte cookie encrypted with
/// XChaCha20-Poly1305 (32 bytes), as in WireGuard.
pub mod cookie {
    /// Receiver index (the initiation's sender index).
    pub const RECEIVER: usize = 4;
    /// Nonce.
    pub const NONCE: usize = 8;
    /// Encrypted cookie.
    pub const COOKIE: usize = 32;
}

/// Reads a little-endian u32.
pub fn read_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

/// Reads a little-endian u64.
pub fn read_u64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

/// `m1 = H("cardinal 1 mac1" || static)`, the mac1 key of the packet's
/// receiver.
pub fn mac1_key(receiver_static: &[u8; 32]) -> [u8; 32] {
    hash_parts(&[b"cardinal 1 mac1", receiver_static])
}

/// `H("cardinal 1 cookie" || static)`, the key that encrypts cookie
/// replies from the holder of `static`.
pub fn cookie_key(responder_static: &[u8; 32]) -> [u8; 32] {
    hash_parts(&[b"cardinal 1 cookie", responder_static])
}

/// `first16(BLAKE3.keyed_hash(m1, bytes))`.
pub fn mac1(key: &[u8; 32], bytes: &[u8]) -> [u8; 16] {
    keyed_hash(key, bytes)[..16].try_into().expect("16 bytes")
}

/// `first16(BLAKE3.keyed_hash(cookie, bytes))`. The 16-byte cookie is
/// padded with 16 zero bytes to a BLAKE3 key (see DEVIATIONS.md).
pub fn mac2(cookie: &[u8; 16], bytes: &[u8]) -> [u8; 16] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(cookie);
    keyed_hash(&key, bytes)[..16].try_into().expect("16 bytes")
}

/// Fills in mac1 and mac2 of a handshake packet whose mac1 starts at
/// `mac1_at` (mac2 follows it and ends the packet).
pub fn seal_macs(packet: &mut [u8], mac1_at: usize, m1: &[u8; 32], cookie: Option<&[u8; 16]>) {
    let m = mac1(m1, &packet[..mac1_at]);
    packet[mac1_at..mac1_at + 16].copy_from_slice(&m);
    let m2 = match cookie {
        Some(c) => mac2(c, &packet[..mac1_at + 16]),
        None => [0u8; 16],
    };
    packet[mac1_at + 16..mac1_at + 32].copy_from_slice(&m2);
}

/// Checks mac1 of a handshake packet.
pub fn check_mac1(packet: &[u8], mac1_at: usize, m1: &[u8; 32]) -> bool {
    let m = mac1(m1, &packet[..mac1_at]);
    ct_eq(&m, &packet[mac1_at..mac1_at + 16])
}

/// Checks mac2 against a cookie.
pub fn check_mac2(packet: &[u8], mac1_at: usize, cookie: &[u8; 16]) -> bool {
    let m = mac2(cookie, &packet[..mac1_at + 16]);
    ct_eq(&m, &packet[mac1_at + 16..mac1_at + 32])
}

/// The cookie for a source address: `first16(keyed_hash(secret, address))`,
/// where the address is its 4 or 16 IP bytes followed by the port as a
/// little-endian u16 (see DEVIATIONS.md).
pub fn make_cookie(secret: &[u8; 32], source: &std::net::SocketAddr) -> [u8; 16] {
    let mut a = match source.ip() {
        std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
        std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    a.extend_from_slice(&source.port().to_le_bytes());
    keyed_hash(secret, &a)[..16].try_into().expect("16 bytes")
}

/// Builds a cookie reply to an initiation with the given sender index and
/// mac1.
pub fn cookie_reply(
    responder_static: &[u8; 32],
    receiver_index: u32,
    initiation_mac1: &[u8],
    cookie_value: &[u8; 16],
    nonce: &[u8; 24],
) -> [u8; COOKIE_REPLY_LEN] {
    let mut out = [0u8; COOKIE_REPLY_LEN];
    out[0] = TYPE_COOKIE_REPLY;
    out[cookie::RECEIVER..cookie::RECEIVER + 4].copy_from_slice(&receiver_index.to_le_bytes());
    out[cookie::NONCE..cookie::NONCE + 24].copy_from_slice(nonce);
    let ct = cardinal_crypto::aead::xchacha20poly1305_encrypt(
        &cookie_key(responder_static),
        nonce,
        initiation_mac1,
        cookie_value,
    );
    out[cookie::COOKIE..].copy_from_slice(&ct);
    out
}

/// Opens a cookie reply, given the mac1 of the initiation it answers.
pub fn open_cookie_reply(
    packet: &[u8],
    responder_static: &[u8; 32],
    initiation_mac1: &[u8],
) -> Option<[u8; 16]> {
    if packet.len() != COOKIE_REPLY_LEN || packet[0] != TYPE_COOKIE_REPLY {
        return None;
    }
    let nonce: [u8; 24] = packet[cookie::NONCE..cookie::NONCE + 24].try_into().ok()?;
    let pt = cardinal_crypto::aead::xchacha20poly1305_decrypt(
        &cookie_key(responder_static),
        &nonce,
        initiation_mac1,
        &packet[cookie::COOKIE..],
    )
    .ok()?;
    pt.try_into().ok()
}

/// The relay header `5, 0, 0, 0, channel (u32)`.
pub fn relay_header(channel: u32) -> [u8; RELAY_HEADER_LEN] {
    let mut h = [0u8; RELAY_HEADER_LEN];
    h[0] = TYPE_RELAYED;
    h[4..8].copy_from_slice(&channel.to_le_bytes());
    h
}

/// Splits a relayed packet into its channel and inner packet.
pub fn parse_relayed(packet: &[u8]) -> Option<(u32, &[u8])> {
    if packet.len() <= RELAY_HEADER_LEN || packet[0] != TYPE_RELAYED || packet[1..4] != [0, 0, 0] {
        return None;
    }
    Some((read_u32(packet, 4), &packet[RELAY_HEADER_LEN..]))
}

/// The 16-byte data header.
pub fn data_header(phase: u8, receiver: u32, counter: u64) -> [u8; DATA_HEADER_LEN] {
    let mut h = [0u8; DATA_HEADER_LEN];
    h[0] = TYPE_DATA;
    h[1] = phase;
    h[4..8].copy_from_slice(&receiver.to_le_bytes());
    h[8..16].copy_from_slice(&counter.to_le_bytes());
    h
}

/// The ChaCha20-Poly1305 nonce of a data packet: 4 zero bytes, then the
/// counter.
pub fn data_nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_sums() {
        assert_eq!(init::MAC2 + 16, INITIATION_LEN);
        assert_eq!(init::STATIC + 48, init::MAC1);
        assert_eq!(init::KEM_CT + 1088, init::STATIC);
        assert_eq!(resp::MAC2 + 16, RESPONSE_LEN);
        assert_eq!(resp::KEM_CT + 1088, resp::EMPTY);
        assert_eq!(cookie::COOKIE + 32, COOKIE_REPLY_LEN);
        const { assert!(DATA_MAX_LEN_REKEY + RELAY_HEADER_LEN <= MAX_DATAGRAM) };
        const { assert!(INITIATION_LEN + RELAY_HEADER_LEN <= MAX_DATAGRAM) };
    }

    #[test]
    fn cookie_round_trip() {
        let s = [7u8; 32];
        let mac = [9u8; 16];
        let c = [3u8; 16];
        let p = cookie_reply(&s, 42, &mac, &c, &[1u8; 24]);
        assert_eq!(read_u32(&p, 4), 42);
        assert_eq!(open_cookie_reply(&p, &s, &mac), Some(c));
        assert_eq!(open_cookie_reply(&p, &s, &[0u8; 16]), None);
    }

    #[test]
    fn macs() {
        let mut p = vec![1u8; INITIATION_LEN];
        let k = mac1_key(&[5u8; 32]);
        seal_macs(&mut p, init::MAC1, &k, None);
        assert!(check_mac1(&p, init::MAC1, &k));
        assert_eq!(&p[init::MAC2..], &[0u8; 16]);
        seal_macs(&mut p, init::MAC1, &k, Some(&[2u8; 16]));
        assert!(check_mac2(&p, init::MAC1, &[2u8; 16]));
        p[3] ^= 1;
        assert!(!check_mac1(&p, init::MAC1, &k));
    }
}
