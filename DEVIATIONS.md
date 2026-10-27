# Deviations and readings of the specification

The specification in `../core` is the authority. This file records every
place where this implementation departs from it, and every place where the
specification was ambiguous and a reading had to be chosen. Each entry
should eventually be resolved by changing either the code or the spec.

## Encoding (`spec/encoding.md`)

- **Spec ambiguity: how nesting depth is counted.** "Nesting depth MUST NOT
  exceed 32" does not say what depth a scalar has. Chose: a scalar has
  depth 0, and a list or record has depth one more than its deepest item.
  So 32 nested lists around an integer are accepted and 33 are rejected
  (`vectors/encoding.json`, "depth 32 (maximum)" and "depth 33").
- **Spec ambiguity: which JSON string escaping the text rendering uses.**
  "text = JSON string" allows several escapings of one string. Chose the
  minimal escaping of RFC 8259, which is what `serde_json` and most JSON
  serializers produce: `"` and `\` are escaped; U+0008, U+0009, U+000A,
  U+000C, U+000D use `\b \t \n \f \r`; other characters below U+0020 use
  `\u00xx` with lowercase hex; everything else, including DEL and non-ASCII,
  is written as itself.
- **Spec ambiguity: whether a signed object's body must itself be
  canonical.** The table says the body is "the canonical encoding of the
  inner record". Chose: reading a signed object rejects it unless the body
  decodes as exactly one canonical record. An empty signature list is
  structurally valid; whether the signers suffice is the caller's question.
- **Spec ambiguity: unknown fields in signature records.** Chose to preserve
  them like any other unknown field (they are outside the id, so this does
  not affect what was signed).

## Cryptography (`spec/crypto.md`)

- **Spec ambiguity: "96 bytes of `derive(...)`" when `derive` outputs 32
  bytes.** Chose the BLAKE3 extended output of the same derivation: the
  first 96 bytes of `BLAKE3.derive_key(context, material)` read as an XOF.
  Its first 32 bytes equal `derive`'s output (`vectors/derive.json`,
  `derive_96`).
- **Spec ambiguity: how the root Ed25519 key is "generated from" the root
  key seed.** Chose: the 32-byte seed is the RFC 8032 private key (the
  "secret" that is hashed with SHA-512 and clamped), so any standard
  library reproduces it.
- **Spec ambiguity: unknown fields in a hybrid public key record.** Chose to
  preserve them; they are part of the encoding and therefore of the
  fingerprint.
- **Spec ambiguity: validation of ML-KEM encapsulation keys.** Chose to
  apply the FIPS 203 encapsulation-key input check (every coefficient less
  than q) when a hybrid public key is parsed, and to reject keys that fail.
- **Spec ambiguity: low-order X25519 points.** The spec does not say whether
  an all-zero X25519 output must be rejected. Chose not to reject it inside
  `seal`/`open` (the ML-KEM secret and the AEAD still protect the result);
  `x25519::is_all_zero` is available for protocols that need contributory
  behaviour, such as the link handshake.
- **Spec ambiguity: recovery phrase input.** Chose to accept any whitespace
  between words and to ignore ASCII case when parsing a phrase; the
  checksum is still required. Output is lowercase words joined by single
  spaces.

## CPace (`spec/crypto.md`, `spec/contact.md#pairing`)

- **Draft version.** CPace follows draft-irtf-cfrg-cpace-21 (April 2026),
  the latest at the time of writing, suite `CPACE-RISTR255-SHA512`. The
  draft's appendix A utility vectors and appendix B.3 Ristretto255 vectors
  (generator, shares, K, ISK in both initiator-responder and symmetric
  modes, invalid-point handling) pass in `crates/crypto/src/cpace.rs`.
- **Spec ambiguity: CPace's output is 64 bytes, but contact.md uses `K` as
  a BLAKE3 key** (`BLAKE3.keyed_hash(K, ...)` needs exactly 32 bytes).
  Chose: `K` is the first 32 bytes of ISK, used for the confirmation tag,
  `derive("pair", K)`, and `derive("invite", K)` alike (`Isk::key32`).
- **Spec ambiguity: the CPace channel identifier CI.** contact.md names the
  password, associated data, and session identifier, but not CI. Chose an
  empty CI (the session identifier already binds both endpoints).
- **Spec ambiguity: password encoding.** Chose PRS = the UTF-8 bytes of the
  three lowercase words joined by single spaces. The words are ASCII, so
  RFC 8265 preparation changes nothing.

## Implementation notes (not deviations)

- Ed25519 verification uses `ed25519-zebra`, which implements ZIP-215
  exactly: canonical `S` required, non-canonical `A` and `R` accepted, and
  the cofactored equation decides. `vectors/ed25519.json` includes the 196
  small-order ZIP-215 cases (all valid) and non-canonical-`S` rejections.
- ML-KEM-768 uses RustCrypto `ml-kem` 0.3 (final FIPS 203). It passes the
  accumulated known-answer test from Go's `crypto/mlkem` (100 iterations in
  the default test run, 10 000 under `--ignored`). The C2SP/CCTV accumulated
  hashes target the FIPS 203 draft and do not apply.
- The `test-rng` feature of `cardinal-crypto` exposes variants of `seal`,
  ML-KEM encapsulation, and CPace that take their randomness as arguments.
  They exist only for reproducible vectors and must never be enabled in a
  build that ships.
