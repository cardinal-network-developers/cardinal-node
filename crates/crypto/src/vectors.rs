//! Generates and checks the cryptographic test vectors in `vectors/`.
//!
//! Run `CARDINAL_WRITE_VECTORS=1 cargo test -p cardinal-crypto vectors` to
//! rewrite the files after an intentional change; otherwise each test fails
//! if its file differs from what this implementation produces.

use cardinal_encoding::{decode, Record, SignedObject};
use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::edwards::CompressedEdwardsY;
use serde_json::{json, Value as Json};

use crate::aead::{chacha20poly1305_encrypt, xchacha20poly1305_encrypt};
use crate::bip39::{entropy_to_words, RecoveryPhrase};
use crate::cpace::{Cpace, Role};
use crate::seal::{open, seal_deterministic};
use crate::{
    derive, derive_into, derive_parts, hash, keyed_hash, verify, HybridKeyPair, Purpose,
    SigningKey, X25519Secret,
};

fn check_or_write(name: &str, value: Json) {
    let text = serde_json::to_string_pretty(&value).unwrap() + "\n";
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(name);
    if std::env::var_os("CARDINAL_WRITE_VECTORS").is_some() {
        std::fs::write(&path, text).unwrap();
        return;
    }
    let existing = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; run with CARDINAL_WRITE_VECTORS=1", path.display()));
    assert!(
        existing == text,
        "{} is out of date with the implementation",
        path.display()
    );
}

fn hx(b: impl AsRef<[u8]>) -> String {
    hex::encode(b)
}

/// Deterministic test inputs: `BLAKE3("cardinal test vector " || label)`
/// extended to `n` bytes.
fn fixed(label: &str, n: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(b"cardinal test vector ");
    h.update(label.as_bytes());
    let mut out = vec![0u8; n];
    h.finalize_xof().fill(&mut out);
    out
}

fn fixed32(label: &str) -> [u8; 32] {
    fixed(label, 32).try_into().unwrap()
}

#[test]
fn derive_vectors() {
    let material = b"cardinal test material";
    let mut derivations = Vec::new();
    for p in Purpose::ALL {
        let mut long = [0u8; 96];
        derive_into(p, material, &mut long);
        derivations.push(json!({
            "purpose": p.as_str(),
            "context": p.context(),
            "material_hex": hx(material),
            "derive": hx(*derive(p, material)),
            "derive_96": hx(long),
        }));
    }
    let key = fixed32("keyed hash key");
    check_or_write(
        "derive.json",
        json!({
            "description": "derive(purpose, material) = BLAKE3.derive_key(\"cardinal 1 \" || purpose, material); 'derive' is the 32-byte output, 'derive_96' the first 96 bytes of the extended output (used for hybrid keys from a seed). hash = BLAKE3, keyed_hash = BLAKE3 keyed mode.",
            "derivations": derivations,
            "hash": [
                { "input_hex": "", "output": hx(hash(b"")) },
                { "input_hex": hx(b"cardinal"), "output": hx(hash(b"cardinal")) },
            ],
            "keyed_hash": [
                { "key": hx(key), "input_hex": hx(b"cardinal 1 pair confirm"), "output": hx(keyed_hash(&key, b"cardinal 1 pair confirm")) },
            ],
        }),
    );
}

#[test]
fn hybrid_vectors() {
    let mut cases = Vec::new();
    for label in ["hybrid seed 1", "hybrid seed 2"] {
        let seed = fixed(label, 32);
        let kp = HybridKeyPair::from_seed(&seed);
        let secret = kp.secret_bytes();
        let public = kp.public_key();
        cases.push(json!({
            "seed": hx(&seed),
            "x25519_private": hx(&secret[..32]),
            "mlkem_seed_d_z": hx(&secret[32..]),
            "x25519_public": hx(public.x25519()),
            "mlkem_encapsulation_key": hx(public.kem().as_bytes()),
            "public_key_record": hx(public.encode()),
            "fingerprint": hx(public.fingerprint()),
        }));
    }
    check_or_write(
        "hybrid.json",
        json!({
            "description": "Hybrid key pairs from a seed (crypto.md#hybrid-public-keys): 96 bytes of derive(\"hybrid key\", seed); the first 32 are the X25519 private key, the next 64 the ML-KEM-768 KeyGen_internal seed d || z. The public key record is {1: x25519 public, 2: ML-KEM-768 encapsulation key}; the fingerprint is BLAKE3 of its encoding.",
            "cases": cases,
        }),
    );
}

#[test]
fn seal_vectors() {
    let mut cases = Vec::new();
    for (label, plaintext, context) in [
        (
            "seal 1",
            b"a sealed secret".to_vec(),
            b"cardinal test context".to_vec(),
        ),
        ("seal 2", Vec::new(), Vec::new()),
        (
            "seal 3",
            fixed("seal 3 plaintext", 100),
            Record::new().with(0, 3u32).encode(),
        ),
    ] {
        let recipient_seed = fixed(&format!("{label} recipient"), 32);
        let kp = HybridKeyPair::from_seed(&recipient_seed);
        let e = fixed32(&format!("{label} ephemeral"));
        let m = fixed32(&format!("{label} mlkem m"));
        let sealed = seal_deterministic(kp.public_key(), &plaintext, &context, &e, &m);

        // Intermediates, recomputed step by step from crypto.md#sealing.
        let eph = X25519Secret::from_bytes(&e);
        let (ct, ss_kem) = kp.public_key().kem().encapsulate_deterministic(&m);
        let ss_dh = eph.diffie_hellman(kp.public_key().x25519());
        let fp = kp.public_key().fingerprint();
        let k = derive_parts(
            Purpose::Seal,
            &[
                &ss_kem[..],
                &ss_dh[..],
                &eph.public_key(),
                &ct,
                &fp,
                &hash(&context),
            ],
        );
        assert_eq!(sealed.ephemeral, eph.public_key());
        assert_eq!(*sealed.kem_ciphertext, ct);
        assert_eq!(
            sealed.ciphertext,
            chacha20poly1305_encrypt(&k, &[0; 12], &context, &plaintext)
        );
        assert_eq!(&open(&kp, &sealed, &context).unwrap()[..], &plaintext[..]);

        cases.push(json!({
            "recipient_seed": hx(&recipient_seed),
            "recipient_fingerprint": hx(fp),
            "plaintext": hx(&plaintext),
            "context": hx(&context),
            "ephemeral_private": hx(e),
            "mlkem_m": hx(m),
            "ephemeral_public": hx(eph.public_key()),
            "ss_kem": hx(&ss_kem[..]),
            "ss_dh": hx(&ss_dh[..]),
            "key": hx(&k[..]),
            "sealed_record": hx(sealed.encode()),
        }));
    }
    check_or_write(
        "seal.json",
        json!({
            "description": "seal(recipient, plaintext, context) per crypto.md#sealing with fixed randomness: the ephemeral X25519 private key and the ML-KEM-768 Encaps_internal randomness m. The recipient is the hybrid key pair from 'recipient_seed' (see hybrid.json). key = derive(\"seal\", ss_kem || ss_dh || E || ct || fingerprint || BLAKE3(context)); the AEAD is ChaCha20-Poly1305 with a zero nonce and aad = context. 'sealed_record' is {1: E, 2: ct, 3: c}.",
            "cases": cases,
        }),
    );
}

#[test]
fn aead_vectors() {
    let key = fixed32("aead key");
    let nonce12: [u8; 12] = fixed("aead nonce 12", 12).try_into().unwrap();
    let nonce24: [u8; 24] = fixed("aead nonce 24", 24).try_into().unwrap();
    let aad = b"associated data";
    let pt = b"plaintext for the AEAD vectors";
    check_or_write(
        "aead.json",
        json!({
            "description": "ChaCha20-Poly1305 (RFC 8439) and XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha); ciphertext includes the 16-byte tag.",
            "chacha20poly1305": [{
                "key": hx(key), "nonce": hx(nonce12), "aad": hx(aad), "plaintext": hx(pt),
                "ciphertext": hx(chacha20poly1305_encrypt(&key, &nonce12, aad, pt)),
            }],
            "xchacha20poly1305": [{
                "key": hx(key), "nonce": hx(nonce24), "aad": hx(aad), "plaintext": hx(pt),
                "ciphertext": hx(xchacha20poly1305_encrypt(&key, &nonce24, aad, pt)),
            }],
        }),
    );
}

/// The low-order non-canonical point encodings used by ZIP-215's test set
/// (as in `ed25519-zebra`'s tests): two with a non-canonical sign bit on
/// x = 0, then those from non-canonical y encodings, first six only.
fn low_order_non_canonical_encodings() -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    let mut y1 = [0u8; 32];
    y1[0] = 1;
    y1[31] = 0x80;
    out.push(y1);
    let mut ym1 = [0xffu8; 32];
    ym1[0] = 0xec;
    out.push(ym1);
    for i in 0..19u8 {
        let mut x = [0xffu8; 32];
        x[0] = 237 + i;
        x[31] = 0x7f;
        if CompressedEdwardsY(x).decompress().is_some() {
            out.push(x);
        }
        x[31] |= 0x80;
        if CompressedEdwardsY(x).decompress().is_some() {
            out.push(x);
        }
    }
    out.truncate(6);
    out
}

#[test]
fn ed25519_vectors() {
    // Ordinary signatures.
    let mut signing = Vec::new();
    for (label, msg) in [
        ("ed25519 1", b"".to_vec()),
        ("ed25519 2", b"cardinal".to_vec()),
    ] {
        let seed = fixed32(label);
        let sk = SigningKey::from_seed(&seed);
        let sig = sk.sign(&msg);
        verify(&sk.public_key(), &msg, &sig).unwrap();
        signing.push(json!({ "seed": hx(seed), "public_key": hx(sk.public_key()), "message": hx(&msg), "signature": hx(sig) }));
    }

    // A signed object with two signatures.
    let mut obj = SignedObject::new(Record::new().with(0, 2u32).with(1, "signed body"));
    let a = SigningKey::from_seed(&fixed32("object signer a"));
    let b = SigningKey::from_seed(&fixed32("object signer b"));
    a.sign_object(&mut obj);
    b.sign_object(&mut obj);
    crate::verify_object(&obj).unwrap();
    let signed_object = json!({
        "signer_seeds": [hx(fixed32("object signer a")), hx(fixed32("object signer b"))],
        "body": hx(obj.body()),
        "id": hx(obj.id()),
        "signing_message": hx(obj.signing_message()),
        "encoding": hx(obj.encode()),
        "text": decode(&obj.encode()).unwrap().to_string(),
    });

    // ZIP-215 edge cases: every pair of small-order encodings (canonical and
    // non-canonical) for A and R with S = 0 is valid under ZIP-215.
    let encodings: Vec<[u8; 32]> = EIGHT_TORSION
        .iter()
        .map(|p| p.compress().to_bytes())
        .chain(low_order_non_canonical_encodings())
        .collect();
    assert_eq!(encodings.len(), 14);
    let mut zip215 = Vec::new();
    for a_bytes in &encodings {
        for r_bytes in &encodings {
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(r_bytes);
            let valid = verify(a_bytes, b"Zcash", &sig).is_ok();
            assert!(valid, "ZIP-215 small-order case must verify");
            zip215.push(json!({ "public_key": hx(a_bytes), "message": hx(b"Zcash"), "signature": hx(sig), "valid": valid }));
        }
    }
    // Invalid: S not reduced (S = l), and S + l for a real signature.
    let l: [u8; 32] =
        hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
            .unwrap()
            .try_into()
            .unwrap();
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&encodings[0]);
    sig[32..].copy_from_slice(&l);
    assert!(verify(&encodings[0], b"Zcash", &sig).is_err());
    zip215.push(json!({ "public_key": hx(encodings[0]), "message": hx(b"Zcash"), "signature": hx(sig), "valid": false, "note": "S = l (not canonical)" }));
    let sk = SigningKey::from_seed(&fixed32("ed25519 1"));
    let mut sig = sk.sign(b"m");
    let mut carry = 0u16;
    for i in 0..32 {
        let v = u16::from(sig[32 + i]) + u16::from(l[i]) + carry;
        sig[32 + i] = v as u8;
        carry = v >> 8;
    }
    assert!(verify(&sk.public_key(), b"m", &sig).is_err());
    zip215.push(json!({ "public_key": hx(sk.public_key()), "message": hx(b"m"), "signature": hx(sig), "valid": false, "note": "S + l of a valid signature" }));
    // Invalid: A does not decode to a curve point.
    let bad_a = {
        let mut x = [0u8; 32];
        x[0] = 2;
        assert!(CompressedEdwardsY(x).decompress().is_none());
        x
    };
    let sig = sk.sign(b"m");
    assert!(verify(&bad_a, b"m", &sig).is_err());
    zip215.push(json!({ "public_key": hx(bad_a), "message": hx(b"m"), "signature": hx(sig), "valid": false, "note": "A is not a point" }));

    check_or_write(
        "ed25519.json",
        json!({
            "description": "Ed25519 (RFC 8032) signing and ZIP-215 verification (crypto.md#signature-verification). 'zip215' cases MUST verify exactly as 'valid' says. The first 196 are every pair of small-order encodings (the eight canonical torsion points and six non-canonical encodings) for A and R with S = 0, message 'Zcash', all valid under ZIP-215 and many invalid under strict RFC 8032 checks. 'signed_object' shows encoding.md#signed-objects: id = BLAKE3(body), each signature over \"cardinal sig 1\" || id, sorted by key.",
            "signing": signing,
            "signed_object": signed_object,
            "zip215": zip215,
        }),
    );
}

#[test]
fn cpace_vectors() {
    let mut cases = Vec::new();
    for (label, prs, ci, sid, ada, adb) in [
        (
            "pairing shape",
            b"amber harbor quiet".to_vec(),
            Vec::new(),
            hash(b"example session").to_vec(),
            Vec::new(),
            Vec::new(),
        ),
        (
            "with ci and ad",
            b"Password".to_vec(),
            b"channel".to_vec(),
            fixed("cpace sid", 16),
            b"ADa".to_vec(),
            b"ADb".to_vec(),
        ),
    ] {
        let mut ya = fixed32(&format!("{label} ya"));
        ya[31] &= 0x0f;
        let mut yb = fixed32(&format!("{label} yb"));
        yb[31] &= 0x0f;
        let a = Cpace::start_deterministic(Role::Initiator, &prs, &ci, &sid, &ada, &ya);
        let b = Cpace::start_deterministic(Role::Responder, &prs, &ci, &sid, &adb, &yb);
        let (sa, sb) = (*a.share(), *b.share());
        let isk = a.finish(&sb, &adb).unwrap();
        assert_eq!(isk.as_bytes(), b.finish(&sa, &ada).unwrap().as_bytes());
        cases.push(json!({
            "name": label,
            "prs": hx(&prs), "ci": hx(&ci), "sid": hx(&sid), "ada": hx(&ada), "adb": hx(&adb),
            "ya": hx(ya), "yb": hx(yb),
            "Ya": hx(sa), "Yb": hx(sb),
            "isk_ir": hx(isk.as_bytes()),
            "pairing_key_K": hx(&isk.key32()[..]),
        }));
    }
    check_or_write(
        "cpace.json",
        json!({
            "description": "CPace over Ristretto255 with SHA-512, initiator-responder mode (transcript_ir), per draft-irtf-cfrg-cpace-21 (whose appendix B.3 vectors this implementation also passes). Scalars are little-endian. pairing_key_K is the first 32 bytes of ISK, the reading of contact.md's K recorded in DEVIATIONS.md.",
            "cases": cases,
        }),
    );
}

#[test]
fn bip39_vectors() {
    let mut cases = Vec::new();
    for entropy in [[0u8; 32], [0xffu8; 32], fixed32("bip39 entropy")] {
        let p = RecoveryPhrase::from_entropy(&entropy);
        let words = entropy_to_words(&entropy).join(" ");
        assert_eq!(*p.to_words(), words);
        let recovery = p.recovery_key_pair();
        cases.push(json!({
            "entropy": hx(entropy),
            "phrase": words,
            "root_seed": hx(&p.root_seed()[..]),
            "root_public_key": hx(p.root_signing_key().public_key()),
            "recovery_seed": hx(&p.recovery_seed()[..]),
            "recovery_public_key_fingerprint": hx(recovery.public_key().fingerprint()),
        }));
    }
    check_or_write(
        "bip39.json",
        json!({
            "description": "Recovery phrase (identity.md#recovery-phrase): 256 bits of entropy as 24 BIP-39 English words with BIP-39's checksum; no PBKDF2. root_seed = derive(\"root key\", entropy) is the RFC 8032 secret of the root Ed25519 key. recovery_seed = derive(\"recovery key\", entropy) seeds the recovery hybrid key pair (see hybrid.json).",
            "cases": cases,
        }),
    );
}
