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

## Blobs (`spec/blobs.md`)

- **Spec ambiguity: the gear table's range.** "for `i` in `0..255`" reads
  as 255 entries, but the table is indexed by a byte. Chose all 256 byte
  values, `i` in `0..=255` (`vectors/blob.json`, `gear_table_blake3`).
- **Spec ambiguity: the level of an index above level 0.** "otherwise the
  level of the indexes they name" would give an index naming level-0
  indexes level 0, the same as one naming chunks. Chose one more than the
  level of the indexes it names, which agrees with the reference's
  "levels = top index level + 1".
- **Spec ambiguity: "plaintext length" of an entry naming an index.**
  Chose the number of blob bytes beneath that index, not the length of the
  index's own encoding: it is what a reader needs to seek without fetching
  every lower index. Readers reject a tree whose lengths do not add up to
  the parent's (and to the reference's `size`) or whose levels do not
  match their position.
- **Spec ambiguity: the empty blob.** The chunking loop yields no chunks
  for empty content. Chose: an empty blob is one empty chunk (its
  ciphertext is the 16-byte tag), `size = 0`, `levels = 0`
  (`vectors/blob.json`, `empty_blob_reference`). Content under 1 KiB
  should be inline anyway.
- **Spec ambiguity: the key of an index.** "Encrypted and identified the
  same way as a chunk" is read as: the index's canonical encoding is the
  plaintext `m`, with `k = keyed_hash(convergence secret, m)`, zero nonce,
  empty associated data, `id = BLAKE3(c)`, under the writer's current
  epoch, even when its entries reuse chunk references of an older epoch.
- **Reading: index validation.** An index must hold 1 to 3,000 entries;
  unknown fields of indexes and references are ignored. References with
  more than 8 levels are rejected (8 levels of 3,000 exceed 2^92 chunks).

## Sync (`spec/sync.md`)

- **Spec ambiguity: what "continues in the next message" means.** A
  reconcile message must cover all ids, so a reply cannot simply be cut
  off. Chose: every message gets exactly one reply. When a reply nears
  64 KiB, the remaining received ranges are answered with this side's own
  fingerprint of the same range (or an empty list if it holds none there),
  without splitting, so the peer does the splitting next round; if even
  that does not fit, everything from there to the end becomes one range
  (a list if this side holds at most 32 ids there, else a fingerprint).
  A "you lack" list that does not fit is cut at the first id not sent,
  which becomes the range's upper bound. Termination is unchanged: a side
  that receives only skips replies nothing. Large differences therefore
  cost round trips in proportion to the bytes exchanged (about 1.3 KiB per
  differing id at a million ids: 10,000 differences each way take about
  290 round trips). A future spec revision could allow several messages
  per turn.
- **Reading: split points.** A range of `c > 32` ids is split at positions
  `floor(c * i / 16)`; each subrange's upper bound is the full 32-byte id
  at the next split position, and the last keeps the received bound. The
  first range starts at the beginning of the id space, so the all-zero id
  is included.
- **Reading: what a "list" teaches.** On receiving a list, a side records
  the listed ids it lacks as wanted, besides replying "you lack". Listed
  and "you lack" ids outside their range are ignored. Skip ranges carry
  no payload; list and "you lack" ranges always carry one, possibly empty.
  Adjacent skips in a reply are merged.
- **Spec ambiguity: "list of object bytes".** Chose a list of byte strings,
  each the stored encoding of one object (objects travel as their
  original bytes, `encoding.md#unknown-fields`). An `objects` message is
  packed up to 64 KiB; an object larger than that travels alone.
- **Spec ambiguity: bundle contents.** Chose: field 1 is a list of
  `objects` message records embedded as records; the sealed form seals
  the canonical encoding of that same list (a top-level list value).
  Bundles holding any other message are rejected.
- **Spec observation: additive fingerprints are not collision resistant.**
  Two ranges with the same count and the same id sum mod 2^256 have the
  same fingerprint, whatever the ids. Honest ids are BLAKE3 outputs and do
  not collide in practice, but a peer able to choose many objects (and so
  ids) can search for sets whose sums match (a generalized birthday
  problem) and hide ids from a reconciliation. The property tests use
  hash ids for this reason; artificial ids that differ only in their top
  byte collide trivially.

## Implementation notes: blobs and sync

- `FsStore` keeps objects at `objects/ab/cd/<64 hex>`, written to `tmp/`
  and hard-linked into place (a link fails if the object exists, so
  concurrent writers never double-count). One process should own a store
  directory: opening it clears `tmp/` and recounts usage by scanning.
  `Fsync::Deferred` (the writer syncs once per blob, in parallel) is the
  intended default for the daemon.
- `MemSet` keeps sorted blocks of at most 512 ids with lazily rebuilt
  prefix sums, so a range fingerprint costs two binary searches and at
  most a few hundred 256-bit additions at any set size.
## Identity (`spec/identity.md`, `model/rules.md`, `model/world.py`)

- **Validity is the model, executed.** `cardinal-identity` embeds a port of
  `model/datalog.py` (parser, stratification check, naive bottom-up
  evaluator) and runs the `identity` and `space` programs of a vendored,
  byte-identical copy of `model/rules.md` (`crates/identity/rules/rules.md`,
  checked by a unit test against `../core`). Input facts are derived by a
  line-by-line port of `world.py` (`model.rs`). A differential test runs
  `model/scenarios.py` and fuzzer histories through both Python and Rust
  and compares every reported relation.
- **Model gaps: ops the model does not name.** `world.py`'s `ALLOWED` has
  no `wrap` or `endorse`. Chose: `wrap` may be signed by admin and root keys
  (as the op table says) and has no effect on the rules; `endorse` may be
  signed by any key of the guardian and has no effect. A malformed op, or an
  op number this implementation does not define, may be signed by no key, so
  its entry is invalid but stays in the graph.
- **Spec ambiguity: what an invalid proof of possession does.** "Verifiers
  MUST reject an `add_key` without a valid proof." Chose: the op reads as
  one no key may sign, so the whole entry is invalid (rather than dropping
  the entry from the graph, which would strand its descendants). The same
  applies to an `add_key` of a device or admin key without a link key, of a
  root without a recovery public key, or with a power outside 1–3.
- **Spec ambiguity: the proof message for a key without a link key.** Roots
  have no link key; chose to append nothing for "encoding of link key".
- **Spec ambiguity: contexts in the genesis entry.** Wraps, recovery wraps,
  and key chains use `"..." || identity id`, but the genesis entry's id
  depends on them. Chose, as the proof of possession does, the genesis root
  key in place of the identity id for seals made in the genesis entry.
- **Spec ambiguity: the wrapped "encryption private key material".** Chose
  the hybrid key pair's 96-byte secret: X25519 private key then the ML-KEM
  seed `d || z` (`HybridKeyPair::secret_bytes`).
- **Spec ambiguity: the genesis protocol record and critical extensions.**
  "Declared first" names `set_protocol`; chose that the genesis protocol
  record (field 5) also declares the extensions it lists.
- **Spec ambiguity: whether an unknown extension op is critical.** Only the
  extension's document says. A verifier that lacks the document treats it
  as critical, and evaluates with an empty set of known extensions, so it
  stops at valid entries that use one (`IdentityState::stalled`).
- **Not checked: wrap completeness.** "`set_encryption_key` MUST include a
  wrap for every device and admin key effective in the entry's causal past"
  is not a validity rule in `model/rules.md`; it is not enforced on
  received entries. Entries this implementation writes satisfy it.
- **Guardians from commitments.** `guardian(P, G)` holds when some
  `endorse` or `confirm` in G's log of a decision under P opens the
  commitment at its position. The number of guardians for `majority`,
  `bad_policy` and `unguarded` is the number of commitments, not of
  revealed guardians. A confirmation of a decision the verifier does not
  hold counts for nothing.
- **Parents of a new entry are sorted** by id; received entries may list
  them in any order but not twice.

## Spaces (`spec/spaces.md`)

- **Spec ambiguity: the genesis entry's membership.** Field 9 is absent in
  genesis, but the `space` rules need `mem(G, I)` for the genesis to be
  valid (`world.py` gives the genesis its own membership). Chose: the
  genesis entry is written under the membership its `start` op creates.
- **Model mapping of space ops.** `rotate` and every profile op (32 and up)
  count as `app` (writers and up); `set_policy` and `set_protocol` are
  owner-only; unknown control ops are allowed to no role. Reach nodes are
  not distinguished yet (they would be `reach`).
- **Membership evaluation.** Spaces whose only member identity is their
  creator are evaluated natively (linear, incremental); a property test
  checks this agrees with the `space` program. Any `add_member`, or an
  entry by another identity, makes native evaluation return
  `Error::Unsupported`; `Space::evaluate_full` runs the normative program,
  whose graph facts are quadratic in the number of entries.
- **Wraps hash.** `BLAKE3` of the encoding of the list value of sealed
  records, exactly as carried in sealed-entry field 4.
- **Unknown fields of a sealed entry** (beyond 0–5) are preserved but not
  bound by the AEAD; only fields 0, 1, and 2 are associated data, as
  specified.
- **The cited author log head** written by this implementation is the last
  entry in log order at which the signing key is in effect.

## State (`spec/state.md`, `spec/profiles.md`)

- **Spec ambiguity: "or in the entry itself".** A node may be named by an
  op after its `create` in the same entry; an op before the `create`
  rejects the entry.
- **Spec ambiguity: what a delete deletes.** Chose: a delete of N flags N
  and every node beneath N in the delete's causal past that no concurrent
  op touched; N is flagged delete conflict if touched. A `restore` of N
  clears N and the nodes beneath it that the same delete flagged. Views
  hide everything beneath a deleted node.
- **Spec ambiguity: cleared fields.** A `set` without a value is a value
  of the register like any other (it supersedes and can conflict). In the
  canonical state it is `{1: entry id}` with no field 2.
- **Spec ambiguity: the root in the canonical state.** The root node has
  no kind, position, or creator and is omitted.
- **Profile restrictions (a reading of "a profile may restrict").** Files:
  kinds 1–3 only, under the root or a folder. Account: placement under a
  space node, storage label and token under a host node, invitation use
  under an invitation node, everything else under the root. Creating or
  moving against this, or an unknown profile op, rejects the entry for
  state. Other profiles are unrestricted.
- **File content and conflict copies.** The version "last in log order" is
  the value whose writing entry is last in log order; same-name siblings
  are ordered by the log position of their creating entry.
- **Cost of state updates.** An entry that descends from every applied
  entry is applied incrementally. Anything else (an entry concurrent with
  applied ones, a control op other than `rotate`, an author's identity log
  changing) recomputes validity and state from scratch: O(n log n) plus
  O(n) per `delete`, since each delete replays positions in its causal past
  and scans concurrent entries. `state.md#cost` asks for recomputation
  "only for the nodes it touches"; that is not done yet.
