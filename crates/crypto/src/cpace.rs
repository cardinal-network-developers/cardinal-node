//! CPace over Ristretto255 with SHA-512 (`CPACE-RISTR255-SHA512`), following
//! draft-irtf-cfrg-cpace-21 (April 2026), sections 6 to 8.3 and appendix A.
//!
//! Group operations use `curve25519-dalek`; SHA-512 is RustCrypto `sha2`.
//! The construction:
//!
//! - `generator_string(DSI, PRS, CI, sid, 128) = lv_cat(DSI, PRS,
//!   zero_bytes(len_zpad), CI, sid)`, with `DSI = "CPaceRistretto255"` and
//!   `len_zpad = max(0, 128 - 1 - len(prepend_len(PRS)) -
//!   len(prepend_len(DSI)))`; `lv_cat` prefixes each part with its LEB128
//!   length.
//! - `g = element_derivation(SHA-512(generator_string))` (RFC 9496
//!   one-way map, `RistrettoPoint::from_uniform_bytes`).
//! - `sample_scalar`: 32 random bytes with the bits above bit 251 cleared,
//!   read little-endian.
//! - `Y = encode(y * g)`; `K = scalar_mult_vfy(y, Y_peer)`, aborting if the
//!   peer's share does not decode or `K` is the identity.
//! - `ISK = SHA-512(lv_cat("CPaceRistretto255_ISK", sid, K) ||
//!   transcript)`, with `transcript_ir(Ya, ADa, Yb, ADb) = lv_cat(Ya, ADa)
//!   || lv_cat(Yb, ADb)` in initiator-responder mode (A is the initiator)
//!   and `transcript_oc` (ordered concatenation) in symmetric mode.
//!
//! The draft's appendix B.3 test vectors are checked in this module's tests.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::random::random_bytes;
use crate::Error;

/// The domain-separation identifier of the Ristretto255 group.
pub const DSI: &[u8] = b"CPaceRistretto255";
/// SHA-512's input block size `s_in_bytes`.
const S_IN_BYTES: usize = 128;
/// The length of a CPace share (an encoded Ristretto255 element).
pub const SHARE_LEN: usize = 32;
/// The length of the intermediate session key ISK.
pub const ISK_LEN: usize = 64;

/// Which transcript a party builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Party A in initiator-responder mode (`transcript_ir`, own share first).
    Initiator,
    /// Party B in initiator-responder mode (`transcript_ir`, peer share first).
    Responder,
    /// Either party in the symmetric setting (`transcript_oc`).
    Symmetric,
}

fn prepend_len(data: &[u8], out: &mut Vec<u8>) {
    let mut len = data.len();
    loop {
        if len < 128 {
            out.push(len as u8);
        } else {
            out.push(((len & 0x7f) as u8) | 0x80);
        }
        len >>= 7;
        if len == 0 {
            break;
        }
    }
    out.extend_from_slice(data);
}

fn lv_cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        prepend_len(p, &mut out);
    }
    out
}

fn prepend_len_size(n: usize) -> usize {
    let mut len = n;
    let mut size = 1;
    while len >= 128 {
        len >>= 7;
        size += 1;
    }
    size + n
}

/// `generator_string(DSI, PRS, CI, sid, s_in_bytes)`.
fn generator_string(prs: &[u8], ci: &[u8], sid: &[u8]) -> Zeroizing<Vec<u8>> {
    let len_zpad =
        S_IN_BYTES.saturating_sub(1 + prepend_len_size(prs.len()) + prepend_len_size(DSI.len()));
    let zpad = vec![0u8; len_zpad];
    Zeroizing::new(lv_cat(&[DSI, prs, &zpad, ci, sid]))
}

/// `G.calculate_generator(H, PRS, CI, sid)`.
fn calculate_generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> RistrettoPoint {
    let gen_str = generator_string(prs, ci, sid);
    let mut h = Zeroizing::new([0u8; 64]);
    h.copy_from_slice(&Sha512::digest(&gen_str[..]));
    RistrettoPoint::from_uniform_bytes(&h)
}

/// `G.sample_scalar()`: 32 random bytes with the top four bits cleared.
fn sample_scalar() -> Scalar {
    let mut b = Zeroizing::new(random_bytes::<32>());
    b[31] &= 0x0f;
    Scalar::from_bytes_mod_order(*b)
}

fn lexicographically_larger(a: &[u8], b: &[u8]) -> bool {
    // Byte-wise comparison where a longer string with an equal prefix is
    // larger: exactly slice ordering.
    a > b
}

fn o_cat(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = b"oc".to_vec();
    if lexicographically_larger(a, b) {
        out.extend_from_slice(a);
        out.extend_from_slice(b);
    } else {
        out.extend_from_slice(b);
        out.extend_from_slice(a);
    }
    out
}

fn transcript_ir(ya: &[u8], ada: &[u8], yb: &[u8], adb: &[u8]) -> Vec<u8> {
    let mut t = lv_cat(&[ya, ada]);
    t.extend(lv_cat(&[yb, adb]));
    t
}

fn transcript_oc(ya: &[u8], ada: &[u8], yb: &[u8], adb: &[u8]) -> Vec<u8> {
    o_cat(&lv_cat(&[ya, ada]), &lv_cat(&[yb, adb]))
}

/// One party's CPace state between sending its share and receiving the
/// peer's. The secret scalar is zeroized on drop.
pub struct Cpace {
    role: Role,
    y: Scalar,
    share: [u8; SHARE_LEN],
    sid: Vec<u8>,
    ad: Vec<u8>,
}

impl Cpace {
    /// Starts a CPace run: computes this party's share from the password
    /// related string `prs`, channel identifier `ci`, session identifier
    /// `sid`, and this party's associated data `ad`.
    pub fn start(role: Role, prs: &[u8], ci: &[u8], sid: &[u8], ad: &[u8]) -> Cpace {
        Cpace::with_scalar(role, prs, ci, sid, ad, sample_scalar())
    }

    /// [`start`](Cpace::start) with a caller-chosen scalar (little-endian,
    /// reduced mod the group order). For reproducible test vectors only.
    #[cfg(any(test, feature = "test-rng"))]
    pub fn start_deterministic(
        role: Role,
        prs: &[u8],
        ci: &[u8],
        sid: &[u8],
        ad: &[u8],
        scalar: &[u8; 32],
    ) -> Cpace {
        Cpace::with_scalar(
            role,
            prs,
            ci,
            sid,
            ad,
            Scalar::from_bytes_mod_order(*scalar),
        )
    }

    fn with_scalar(role: Role, prs: &[u8], ci: &[u8], sid: &[u8], ad: &[u8], y: Scalar) -> Cpace {
        let g = calculate_generator(prs, ci, sid);
        let share = (y * g).compress().to_bytes();
        Cpace {
            role,
            y,
            share,
            sid: sid.to_vec(),
            ad: ad.to_vec(),
        }
    }

    /// This party's share `Y`, to send with its associated data.
    pub fn share(&self) -> &[u8; SHARE_LEN] {
        &self.share
    }

    /// Completes the run with the peer's share and associated data,
    /// returning the intermediate session key ISK. Aborts if the peer's
    /// share is not a valid encoding or yields the identity.
    pub fn finish(self, peer_share: &[u8], peer_ad: &[u8]) -> Result<Isk, Error> {
        let peer: [u8; SHARE_LEN] = peer_share.try_into().map_err(|_| Error::CpaceAbort)?;
        let point = CompressedRistretto(peer)
            .decompress()
            .ok_or(Error::CpaceAbort)?;
        let k = self.y * point;
        if k == RistrettoPoint::identity() {
            return Err(Error::CpaceAbort);
        }
        let k = Zeroizing::new(k.compress().to_bytes());
        let transcript = match self.role {
            Role::Initiator => transcript_ir(&self.share, &self.ad, &peer, peer_ad),
            Role::Responder => transcript_ir(&peer, peer_ad, &self.share, &self.ad),
            Role::Symmetric => transcript_oc(&self.share, &self.ad, &peer, peer_ad),
        };
        let mut dsi_isk = DSI.to_vec();
        dsi_isk.extend_from_slice(b"_ISK");
        let mut h = Sha512::new();
        h.update(lv_cat(&[&dsi_isk, &self.sid, &k[..]]));
        h.update(&transcript);
        let mut isk = [0u8; ISK_LEN];
        isk.copy_from_slice(&h.finalize());
        Ok(Isk(isk))
    }
}

impl Drop for Cpace {
    fn drop(&mut self) {
        self.y.zeroize();
    }
}

impl std::fmt::Debug for Cpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cpace")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

/// The CPace intermediate session key (64 bytes), zeroized on drop.
pub struct Isk([u8; ISK_LEN]);

impl Isk {
    /// The 64 bytes of ISK.
    pub fn as_bytes(&self) -> &[u8; ISK_LEN] {
        &self.0
    }

    /// The first 32 bytes of ISK: the pairing key `K` of `contact.md`
    /// (see DEVIATIONS.md for this reading).
    pub fn key32(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0[..32].try_into().expect("32 bytes"))
    }
}

impl Drop for Isk {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Isk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Isk(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.split_whitespace().collect::<String>()).unwrap()
    }

    #[test]
    fn appendix_a_utilities() {
        let mut out = Vec::new();
        prepend_len(b"", &mut out);
        assert_eq!(out, h("00"));
        let mut out = Vec::new();
        prepend_len(b"1234", &mut out);
        assert_eq!(out, h("0431323334"));
        let r128: Vec<u8> = (0..128).collect();
        let mut out = Vec::new();
        prepend_len(&r128, &mut out);
        assert_eq!(&out[..3], &h("800100")[..]);
        assert_eq!(prepend_len_size(127), 128);
        assert_eq!(prepend_len_size(128), 130);
        assert_eq!(
            lv_cat(&[b"1234", b"5", b"", b"678"]),
            h("043132333401350003363738")
        );
        assert!(!lexicographically_larger(b"\0", b"\0\0"));
        assert!(lexicographically_larger(b"\x01", b"\0\0"));
        assert!(lexicographically_larger(b"\0\0", b"\0"));
        assert!(!lexicographically_larger(b"\0\0", b"\x01"));
        assert!(!lexicographically_larger(b"\0\x01", b"\x01"));
        assert!(!lexicographically_larger(b"ABCD", b"BCD"));
        assert_eq!(o_cat(b"ABCD", b"BCD"), h("6f6342434441424344"));
        assert_eq!(o_cat(b"BCD", b"ABCDE"), h("6f634243444142434445"));
        assert_eq!(
            transcript_ir(b"123", b"PartyA", b"234", b"PartyB"),
            h("03313233065061727479410332333406506172747942")
        );
        assert_eq!(
            transcript_ir(b"3456", b"PartyA", b"2345", b"PartyB"),
            h("043334353606506172747941043233343506506172747942")
        );
        assert_eq!(
            transcript_oc(b"123", b"PartyA", b"234", b"PartyB"),
            h("6f6303323334065061727479420331323306506172747941")
        );
        assert_eq!(
            transcript_oc(b"3456", b"PartyA", b"2345", b"PartyB"),
            h("6f63043334353606506172747941043233343506506172747942")
        );
    }

    /// draft-irtf-cfrg-cpace-21 appendix B.3.
    #[test]
    fn appendix_b3_ristretto255_sha512() {
        let prs = b"Password";
        let ci = h("0b415f696e69746961746f720b425f726573706f6e646572");
        let sid = h("7e4b4791d6a8ef019b936c79fb7f2c57");

        let gen_str = generator_string(prs, &ci, &sid);
        assert_eq!(
            &gen_str[..],
            &h("11435061636552697374726574746f3235350850617373776f726464
                00000000000000000000000000000000000000000000000000000000
                00000000000000000000000000000000000000000000000000000000
                00000000000000000000000000000000000000000000000000000000
                00000000000000000000000000000000180b415f696e69746961746f
                720b425f726573706f6e646572107e4b4791d6a8ef019b936c79fb7f
                2c57")[..]
        );
        assert_eq!(
            Sha512::digest(&gen_str[..]).to_vec(),
            h("da6d3ddc8802fca9058755ffd3ebde08a9c2c74945901a258482a288
               b6663af06bf645c93cd1c51512307199c80e84908916d983b34af772
               05f90851a657ee27")
        );
        let g = calculate_generator(prs, &ci, &sid);
        assert_eq!(
            g.compress().to_bytes().to_vec(),
            h("222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56")
        );

        let ya: [u8; 32] = h("da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08")
            .try_into()
            .unwrap();
        let yb: [u8; 32] = h("d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d")
            .try_into()
            .unwrap();
        let a = Cpace::start_deterministic(Role::Initiator, prs, &ci, &sid, b"ADa", &ya);
        let b = Cpace::start_deterministic(Role::Responder, prs, &ci, &sid, b"ADb", &yb);
        assert_eq!(
            a.share().to_vec(),
            h("d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b9157")
        );
        assert_eq!(
            b.share().to_vec(),
            h("3ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f7258")
        );
        let (sa, sb) = (*a.share(), *b.share());
        let isk_ir = h("b69effbf61b51d56401c0f65601abe428de8206feaaf0e32198896dc
                        ae7b35cd2b38950a39dfd5d4a79164614c2984f7daa460b588c1e80c
                        3fa2068af7900447");
        assert_eq!(a.finish(&sb, b"ADb").unwrap().as_bytes().to_vec(), isk_ir);
        assert_eq!(b.finish(&sa, b"ADa").unwrap().as_bytes().to_vec(), isk_ir);

        let isk_oc = h("544199d71f62f8d9a1fee55727e24fe4a45844593c2b6013c4fa3969
                        d0e5debb2244675c0b43397cbb68d342b01fc0f98fc961469a25134d
                        e9f0f813c1a57476");
        let a = Cpace::start_deterministic(Role::Symmetric, prs, &ci, &sid, b"ADa", &ya);
        let b = Cpace::start_deterministic(Role::Symmetric, prs, &ci, &sid, b"ADb", &yb);
        assert_eq!(a.finish(&sb, b"ADb").unwrap().as_bytes().to_vec(), isk_oc);
        assert_eq!(b.finish(&sa, b"ADa").unwrap().as_bytes().to_vec(), isk_oc);
    }

    /// draft-irtf-cfrg-cpace-21 appendix B.3.10 and B.3.11.
    #[test]
    fn appendix_b3_scalar_mult_vfy() {
        let s: [u8; 32] = h("7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88cf538a05")
            .try_into()
            .unwrap();
        let x: [u8; 32] = h("2c3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c")
            .try_into()
            .unwrap();
        let p = CompressedRistretto(x).decompress().unwrap();
        assert_eq!(
            (Scalar::from_bytes_mod_order(s) * p)
                .compress()
                .to_bytes()
                .to_vec(),
            h("7c13645fe790a468f62c39beb7388e541d8405d1ade69d1778c5fe3e7f6b600e")
        );
        // Invalid encoding and the identity both abort.
        let invalid = h("2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c");
        let c = Cpace::start_deterministic(Role::Initiator, b"pw", b"", b"sid", b"", &s);
        assert_eq!(c.finish(&invalid, b"").unwrap_err(), Error::CpaceAbort);
        let c = Cpace::start_deterministic(Role::Initiator, b"pw", b"", b"sid", b"", &s);
        assert_eq!(c.finish(&[0u8; 32], b"").unwrap_err(), Error::CpaceAbort);
        let c = Cpace::start(Role::Initiator, b"pw", b"", b"sid", b"");
        assert_eq!(c.finish(&[0u8; 31], b"").unwrap_err(), Error::CpaceAbort);
    }

    #[test]
    fn random_runs_agree_only_on_same_password() {
        let a = Cpace::start(Role::Initiator, b"amber harbor quiet", b"", b"sid", b"");
        let b = Cpace::start(Role::Responder, b"amber harbor quiet", b"", b"sid", b"");
        let (sa, sb) = (*a.share(), *b.share());
        assert_eq!(
            a.finish(&sb, b"").unwrap().as_bytes(),
            b.finish(&sa, b"").unwrap().as_bytes()
        );

        let a = Cpace::start(Role::Initiator, b"amber harbor quiet", b"", b"sid", b"");
        let b = Cpace::start(Role::Responder, b"amber harbor quite", b"", b"sid", b"");
        let (sa, sb) = (*a.share(), *b.share());
        assert_ne!(
            a.finish(&sb, b"").unwrap().as_bytes(),
            b.finish(&sa, b"").unwrap().as_bytes()
        );

        let a = Cpace::start(Role::Initiator, b"pw", b"", b"sid1", b"");
        let b = Cpace::start(Role::Responder, b"pw", b"", b"sid2", b"");
        let (sa, sb) = (*a.share(), *b.share());
        assert_ne!(
            a.finish(&sb, b"").unwrap().as_bytes(),
            b.finish(&sa, b"").unwrap().as_bytes()
        );
    }

    #[test]
    fn long_password_has_no_padding() {
        let prs = vec![b'x'; 200];
        let s = generator_string(&prs, b"", b"");
        // DSI (1 + 17) + PRS (2 + 200) + empty zpad (1) + CI (1) + sid (1).
        assert_eq!(s.len(), 18 + 202 + 3);
    }
}
