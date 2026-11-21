# Deviations and readings of the specification

The specification in `../core` is the authority. This file records every
place where this implementation departs from it, and every place where the
specification was ambiguous and a reading had to be chosen. Each entry
should eventually be resolved by changing either the code or the spec.

## Behind the specification: a space only grows

`../core` changed on its branch `grow-only-spaces` (decisions D56 to D58).
This implementation follows it as far as one space goes: the rules, the
formats, who is a member, and which entries are valid, judged natively one
entry at a time ([Spaces](#spaces-specspacesmd), below). It does not yet
follow it across two spaces. What still differs:

- **No migration.** The formats changed and nothing converts what was
  written before: an id now covers who signed, a genesis names its own
  author with `add_member`, an entry no longer names a membership, and op
  4 is `leave`. Nothing 0.1.13 or earlier wrote is valid here. Such a data
  directory is refused whole and left as it is, and has to be set up
  again ([The store's format](#daemon-mount-and-cli-cardinald-cardinal),
  `docs/install.md`, "Upgrading").
- **Succession.** Nothing here writes a `succeed`, makes a successor, or
  follows one. What one space's validity needs of it is built: a `succeed`
  that counts closes what descends from it, a space with no owner ends when
  every member has named the same successor, the successor that stands is
  the smallest named, and a `succeed` or a successor's genesis by a removed
  key counts only if a `keep` lists it. The rest is not: the state at the
  cut, the initial state of a successor, following or showing a successor
  as an offer, posting work again, the trail, `keep` for a succession made
  by a device that is then retired or lost, the space node's field 4 in the
  account space, tokens and storage labels that serve a successor, and what
  a device does with a successor that is public where the old space was
  not (Following's condition 5, "Made public"). With the initial state
  go two rules of `state.md` and `spaces.md` that nothing here can reach
  yet: the nodes a successor's initial state carried need no `create`
  (here a node exists by its `create`, the root and the reach nodes
  aside), and an op posted again that named its parent by index is given
  the index its `create` has in the new entry (here nothing posts again).
  The
  fields that exist for it are read, written and kept, and mean nothing yet:
  fields 3, 4 and 6 to 9 of `start`, fields 2 and 3 of `succeed`, and
  `was` on `create`. A device that receives a `succeed` that ends a space
  stops writing in it, says nothing to its person, and goes nowhere.
- **Taking someone out of a group** is a succession, so `group-remove` fails
  with a message saying that it cannot be done yet, and changes nothing.
  Lowering an admin is the same. Nothing in the local interface makes
  anyone an admin either, though the rules are there for one who is.
- **A member who can no longer be trusted.** A frozen identity's entries are
  judged like anyone's, devices open no session with it, it is left out of
  the next epoch this device starts, and this device starts one rather
  than write under an epoch the frozen member began, or one that reached
  it before it learned of the freeze. But a new epoch is still wrapped for
  whoever a frozen admin added, heard of before the freeze or not, nothing
  offers the owner a succession without it, and nothing shows the members
  it added.
- **A conversation shows its messages in log order.** `profiles.md` now has
  a device show messages in the order they became valid on it, so that one
  written with old parents appears when it arrives and not among what was
  already read. `relationship::messages` still sorts by log order.

The specification then answered what building this found (decisions D59 to
D61, and the commits beside them): what an id covers, a reach node that is
never created, and when to rotate. This implementation follows those
answers now, and the readings it had to choose in doing so are recorded
below, each under its section.

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
- **An object with several signers.** Who signs is settled before anyone
  does (`encoding.md#signed-objects`): `SignedObject::sign_with` takes all
  the keys at once and replaces whatever signatures were there, and there
  is no way to add one signer to an object and keep its id.
- **Reading: where a signature that does not verify is refused.** "A
  device that can check it rejects it." Entries and grants are checked
  when they are decoded, so an object with a bad signature is never held
  as an entry. Reading a signed object alone (`SignedObject::decode`)
  checks its shape and not its signatures.

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
- **The Ed25519 vectors** (`vectors/ed25519.json`,
  `crypto.md#signature-verification`). ZIP-215's 196 published cases are
  kept as signatures to reject, marked `zip215_alone`: each has a key of
  small order. What only ZIP-215's rules accept under a key that is not of
  small order was made here, 28 cases: 14 with an `R` of small order in
  each of its encodings, six of them not canonical; 7 with an `R` that has
  a part of small order, which only the cofactored equation accepts; and 7
  under a key with a part of small order, which is not a key of small
  order. The check for a key of small order is in `verify`, so it holds
  for every signature: entries, grants, device proofs, proofs of
  possession, and release manifests.
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

- **A contact is served only what this person put in what they share.**
  `sync.md#blob-transfer` serves any peer with a session, since an id is the
  right to fetch it. Here a person's own devices get anything, and a contact
  only the chunks and indexes of this person's attachments, and of content
  this person wrote in the shared folder, in the space shared with them, so
  one who knew the id of a private chunk would still not get it. What a
  contact put there themselves comes from their devices. In a group, a
  member who is a contact gets every file the group's messages carry that
  this device holds, whoever sent it, since members who do not know each
  other get files through one who knows both, who keeps them.
- **What current state references** (`blobs.md#retention`,
  `fetch::state_blobs`). Every blob reference, found by its shape at any
  depth, in every value a field holds now (each of them where a field is
  in conflict), of every node that is neither deleted nor beneath a
  deleted one, whatever its kind and wherever it is. A device that keeps
  everything fetches all of it: besides the files and attachments it
  shows, the content of kinds it does not know, in its files space from
  its own devices, in a relationship from the other person's, and in a
  group through a member it knows (`fetch::wanted`). A device that keeps
  on demand fetches none of that: nothing there can open it. The hourly
  pass counts all of it as current, so none is freed as an old version,
  and the copy checks sample it with the rest.
  - **Reading: a deleted node.** A deleted node is still a node of the
    state, and "a field of one of its nodes" could take it in. Chose: what
    a deleted node holds, or one beneath it, is not current, as the
    content of a deleted file is not. It is kept as an old version only
    where it is a file's content; see the next.
  - **Not done: old values of kinds nobody knows.** What such a field
    held before is not current and is not known to the hourly pass as an
    old version either (`known_blobs` reads file content alone), so on a
    device that fetched it, it stays until `cardinal clear`. It is named,
    so `free-space --unnamed` leaves it too.
  - **Reading: a full holder.** Retention here is one setting for the
    device (`retention` in `config.toml`), not one per space.
  - **Reading: what a contact is served** follows what they now fetch: in
    a relationship, also every reference in a value this person wrote
    there, and in a group everything its state references (see the first
    item of this section).
  - A record that only looks like a reference is fetched like one, and
    stays wanted for as long as nobody has it. In the account space
    nothing is looked for.
- **Shared files come from the two people's own devices, while online.**
  A device with full retention keeps every file of a shared folder and every
  attachment as they arrive, and one on demand keeps images up to 16 MiB, so
  a person's always-on device soon holds what they were sent. A host keeps no
  copy for someone else, and `storage` `allow` is not used. Their chunks are
  never freed, by `free-space` or otherwise. A media type comes from the
  file's ending.
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

- **Notices reach only this person's devices.** `sync.md#notices` is
  implemented for a person's own devices, which are all a device has
  sessions with here. Neighbours (about six random sessions in a large
  space) and deposits for offline members wait for sharing and hosts.
  Notices that would reach a mailbox go nowhere, and a device that was
  offline catches up by reconciling when it returns.
- **Reading: how long news waits.** `sync.md#notices` lets a device wait a
  moment. Chose 30 ms, long enough to gather what arrives together. A notice
  covering news from two peers goes to both, since each lacks the other's.

## Implementation notes: blobs and sync

- `FsStore` keeps objects at `objects/ab/cd/<64 hex>`, written to `tmp/`
  and hard-linked into place (a link fails if the object exists, so
  concurrent writers never double-count). One process should own a store
  directory: opening it clears `tmp/` and recounts usage by scanning.
  `Fsync::Deferred` (the writer syncs once per blob, in parallel) is the
  intended default for the daemon. Under it a put waits in `tmp/`,
  readable through a pending map, until the sync flushes its data and only
  then links it (`blobs.md#storing`). A put flushes everything waiting once
  256 objects wait, and the daemon flushes what waits every second, so
  chunks read on demand do not stay in `tmp/`. Storing an id again checks
  the length held and replaces a chunk cut short; a reader checks every
  chunk it reads from the store against its id, drops one that fails and
  fetches it again. The `blob` service flushes before it answers for an
  object still waiting.
- `MemSet` keeps sorted blocks of at most 512 ids with lazily rebuilt
  prefix sums, so a range fingerprint costs two binary searches and at
  most a few hundred 256-bit additions at any set size.
- **Background fetch order** (`cardinald/src/fetch.rs`, `sched.rs`). Each
  device fetches in its own order, with no coordination and nothing on
  the wire: the wanted files, in their natural order, are split into runs
  of about 4 MiB (a few consecutive small files, or about 64 consecutive
  chunks of a larger file), each ranked by BLAKE3 keyed with the device's
  signing key over the run's first object id. Files are listed in their
  groups' rank order and the scheduler asks for the lowest-ranked run it
  holds first; reads through the mount stay in file order. Devices that
  fetch the same new content at once then take different parts from the
  source and much of the rest from each other. That needs fresh "not
  held" answers: an object a device lacked more than 250 ms ago is asked
  of it again before it goes to a device at least twice as slow to
  answer (the 30 s memory alone kept a fast neighbour, asked early while
  it had nothing, out of a short fetch). With a slow source and two fast
  devices fetching 84 MiB at once (`cardinal/tests/fetch_order.rs`), the
  source sent 2.0x the data before and 1.1-1.25x after; the rest is the
  two devices asking for the same run at about the same time, which
  matters less the longer the fetch.
## Identity (`spec/identity.md`, `model/rules.md`, `model/world.py`)

- **An identity log's validity is the model, executed.** `cardinal-identity`
  embeds a port of `model/datalog.py` (parser, stratification check, naive
  bottom-up evaluator) and runs the `identity` program of a vendored,
  byte-identical copy of `model/rules.md` (`crates/identity/rules/rules.md`,
  checked by a unit test against `../core`). Input facts are derived by a
  line-by-line port of `world.py` (`model.rs`). A differential test runs
  `model/scenarios.py` and fuzzer histories through both Python and Rust
  and compares every reported relation, for the `space` program as well,
  which nothing but tests runs ([Spaces](#spaces-specspacesmd)).
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

## Guardians (`spec/identity.md#recovery`, `#personas`, `spec/hosts.md#restore`)

`cardinal guardians set`, `cardinal guarding`, and `cardinal recover`
(`cardinald/src/guardians.rs`, `recovering.rs`, `helper.rs`,
`identity/src/guardians.rs`). What is built: naming the first guardians,
a guardian finding its own record, the recovery helper (D77) meeting each
guardian through an invitation with field 9 in a relationship of its
own, a recovery proposed by a guardian's device and signed by the new
device, the `recover` and every guardian's acts carried between the
guardians by the new device, endorsements, the wait, confirmations with
shares, one recovery of a person shown at a time, starting over, and the
new device taking the identity up from what the guardians hold, keeping
none of the old devices; guardians acting through personas (D78, D79),
burned once spent; and the guardians keeping a sealed copy of the
account, given back in a recovery with their relationships (D80). What
differs or was read:

- **Reading: changing guardians.** `cardinal guardians set` under a
  policy naming guardians writes a `set_recovery` signed by this device's
  key, naming fresh personas (each guardian, asked again, accepts with a
  persona no policy of this person's named: the person's devices keep
  which contact each policy named in an account setting, `"guardians:
  named "` and the policy's id, `contact:persona,...`). The guardians in
  office confirm it with `cardinal guarding confirm-change NAME`, after the
  policy's delay from when their device first saw it (doubled after an
  objection), and with no share. Once it is in effect the person's devices
  mark the new guardians, give them the account, take it back from the
  others (deleting their held copy node), and set a fresh encryption key
  wrapped to the new guardian key (`"guardians: applied "` notes it); the
  personas the new policy no longer names are burned. The same serves for
  the new root's first `set_recovery` after a recovery: the personas that
  acted are not burned until a policy no longer names them (or 30 days
  after the recovery took effect and the new device took it up), since
  "the guardians who just acted confirm it". **Reading of the chain
  rule:** a guardian confirms no decision under a policy unless every
  decision it confirmed under it is in the new one's past; the "dead"
  part, which lets a guardian move on from a split vote between two
  changes, is not built, so such a guardian waits. **Not built:** a change
  back to naming no guardians, and the alerts.
- **Reading: asking someone to be a guardian.** `cardinal guardians ask
  NAME` writes a guardian request in the relationship (kind 67, this
  implementation's); `cardinal guarding` shows it until a guardian persona
  node of this person's is newer, and `cardinal guarding accept NAME`
  answers it. Accepting without a request works too.
- **Was not built until this round: changing guardians.** Only the first
  guardians, under a policy naming none, could be named. A `set_recovery` under a policy naming
  guardians is a decision the guardians confirm; guardian software here
  confirms recoveries only, so `cardinal guardians set` refuses once there
  are guardians. With it go the "dead" part of the chain rule (which only
  concerns changes), asking a new guardian to accept the role
  ("SHOULD still ask"), and the `set_recovery` with a new guardian key and
  shares that the new root SHOULD append after a recovery.
- **Not built: alerts.** "Each guardian's software alerts the person's
  devices" is not a message of its own: the person's devices hold the
  `recover` and the guardians' acts in their own log's set, and
  `cardinal guardians` shows a recovery under way as a warning, with how
  many endorsed and confirmed. Contacts are not shown it.
- **Reading: personas and their services (D78, D79).** A persona's
  service is a second service inside the device's, with its own data
  directory, its own device keys and an identity, on a runtime of its own,
  with no control socket, mount, discovery, port mapping or release check,
  listening on the device's address at a port of its own; the device's own
  service drives it. As the spec has it, it shares no presence secret and
  its devices advertise nothing for it: it keeps none (`presence::keep`),
  has no `c=` and no Bluetooth, and never names itself as a host
  (`outside::tick`, D72/D76), though the helper and a guardian's persona
  trust each other. A recovery's relationship, where one is in a person's
  own account, is no trusted contact for the presence secret either. It has account and files spaces of its own, which it
  shares with nobody: the invitation and relationship machinery needs an
  account (the spec says a persona "is in no space but those its purpose
  makes"). A new device's **recovery helper** is one, held alone in
  `recovery-helper` with no words, started by `cardinal recover start` and
  dropped when the recovery is finished or given up. A **guardian
  persona** is made by `cardinal guarding accept NAME`: 32 random bytes,
  its root made from them as a recovery phrase's, a log whose first device
  key is the service's, under `personas/<id>`; the account keeps a persona
  node (kind 16: purpose `guardian`, the entropy, the id, `for` NAME), and
  the relationship with NAME a guardian persona node (kind 11: the id and
  the log). **Not built:** a guardian's other devices running the persona.
  Only the device that accepted runs it, and endorsing, confirming and
  inviting are refused elsewhere, saying so; the spec has each device add
  a device key of its own to the persona's log. Its encryption key is
  opened with the root's entropy. The policy's commitments and sealed
  records name the persona; `cardinal guardians set` refuses a contact
  with no guardian persona node for this person ("has not accepted"). The
  person is asked out of band. `cardinal guarding` lists those accepted
  but not named yet.
- **Reading: burning a persona (and see changing guardians, above).** "Burned once a recovery it acted in is
  in effect": once such a recovery is in effect **and** the new device has
  taken it up (the person's log shows a valid entry by the new root other
  than the `recover`, which the helper carries to the guardians before it
  goes), or 30 days after this device saw it in effect; burning at once
  could take away the last confirmation, and its share, before the new
  device got it. "When the policy no longer names it": only when the
  current policy descends from one that named it (this device remembers
  which, `persona:policy`, in `guarding.json`) and does not, never from a
  record that failed to open for another reason. Burning writes `leave`
  in the persona's recovery relationships, sets account persona field 5,
  stops the service and removes its directory, and drops the copies held
  for the person. `cardinal guarding accept` repairs a relationship that
  lacks the persona's node (a crash between the two writes).
- **Reading: how a relationship is marked "recovery for" the person.**
  The spec says guardian software shows it so, never as a contact, but
  gives the account's contact node no field for it. Chose: contact field
  13, the identity recovered (32 bytes), written by both sides when the
  contact is recorded from an invitation with field 9; on a guardian's
  side the contact is in the persona's service, never the guardian's own
  account. Such a contact is trusted (sessions open) and takes no
  introductions, and is left out of `contacts`, `conversations`, lookups by
  name, the one folder and calls. Neither side may be the person
  recovered, nor already a contact. The persona **retires** a relationship
  (refuses its helper: no sessions, no calls, its delivery tokens revoked,
  nothing carried into it) once the guardian said never to its `recover`,
  or once another recovery of that person is in effect; one whose
  `recover` has not arrived yet is not retired, since it may be the one in
  effect.
- **Reading: what travels through a recovery relationship.** The spec
  says the `recover` and the endorsements travel through the
  relationships, not how. Chose two relationship node kinds of this
  implementation's, both author-owned and read as their author created
  them, numbered past the spec's relationship kinds (which reach 11) and
  apart from the account's (which reach 16): 64, a **recovery proposal**
  by the guardian's persona (`1: identity recovered; 2: parents; 3:
  policy`), and 65, a **carried entry** (`1: identity recovered; 2: an
  identity entry`), one identity
  entry each, written by either side, in entries of at most 32 KiB, and
  only where its writer has not carried the same entry there already (what
  the other side carried counts as theirs). On meeting a helper, the
  guardian's device writes its proposal (once per space) and carries the
  person's own log, which the new device signs against and takes the
  identity up from. On a guardian's side all of this is the persona's,
  in its service's relationships, tended every second by the guardian's
  own service, which holds the person's log and decides. A relationship is for one `recover`: the first its
  helper carried there; a guardian's device takes no other from it. The
  new device carries its `recover`, and of anyone else's log only what the
  carried log keeps attached (the causal pasts of acts on the person's
  log), to every guardian, every second while the helper's state changes
  (it remembers what it carried where, and syncs a relationship with the
  guardian's devices in touch after carrying into it), and once more
  before dropping the helper. A guardian's device carries its acts on a
  recovery only into that recovery's relationships, and catches up with
  those done before the helper's `recover` reached it there (as when the
  person's host passed it on first). It takes from the helper, of the
  person's own log, only that `recover`, alone in its entry, signed by its
  new root, under the policy it guards; of anyone else's, what
  `ingest_other` keeps; and delivers what is new to the person's devices
  and hosts, as its own acts.
- **Reading: who makes the invitation.** `cardinal guarding invite NAME`
  makes one through the persona's service (its identity, its address,
  kept in its account; trusted, no introductions), and its use proposes:
  the guardian acted by making it. `cardinal recover invite` makes one on
  the new device, which a guardian takes up with `cardinal accept`; their
  own service checks they guard that person and hands it to the persona's
  service, whose relationship it becomes. That invitation needs field 9,
  the identity id, which the new device learns from a guardian's
  invitation used first, or from `--identity ID` (a guardian's `guarding`
  shows it).
- **Reading: no probing.** Only the person's own `accept` (and a helper,
  for a guardian's invitation) takes an invitation with field 9; an
  introduction never does, whether tended unasked or said yes to. A device
  asked to `accept` one that does not guard that identity (by the records
  it holds now) refuses, tells its person why, and dials nothing. A
  helper's service refuses an invitation without field 9.
- **A recovery keeps no old key (D80).** The `recover` names no key to
  keep, hosts included, and guardian software refuses to endorse or
  confirm one that keeps any (`keeps_keys` in `guarding`). The new device
  signs on the first proposal (in the order it met the guardians) that
  acts under the carried log's current policy and whose parents the
  carried log holds, all valid or in effect and descending from that
  policy; any other is passed over. The device and admin keys in effect as
  of those parents are the devices to pair again when no account comes
  back.
- **Reading: the sealed account copy (D80).** "Give each guardian's
  persona a sealed copy of the account space ... keep it current through
  the relationship": the person's devices write, in the relationship with
  each guardian named, a **held copy** node (relationship kind 66, this
  implementation's: `1: label`, author-owned), naming the account space;
  the guardian's own devices then hold that space's sealed entries, never
  opened, as a space they cannot open, synced with the person over
  sessions as contacts (an invitation's session reaches only the
  relationship, and is replaced once a session as contacts is up). The
  person's devices let a guardian fetch the account only where they named
  it so; a guardian's devices take it only from someone they guard through
  a persona, and only the first set that person named (a stolen device
  naming more gets nothing more), at most 64 MiB of it; a helper takes at
  most two from each persona, the account and that guardian's
  relationship. A person's devices give the account only to contacts the
  account marks as guardians now. Chunks are left out. The persona's
  service is given fresh copies only while it has helpers, and only when a
  set grew. In a recovery the persona's service is
  given copies of the sealed account and of the relationship space the
  guardian shares with the person, names both in held copy nodes in each
  helper's relationship, and lets the helper fetch them; the helper takes
  what a persona names. **Readings:** the account copy is held by the
  guardian's own devices for the persona, as the spec says, but synced
  over the guardian's own relationship with the person; the copy is as
  fresh as the last sync.
- **Reading: the fingerprint.** "Five words from the BIP-39 English list,
  the first 55 bits of `BLAKE3("cardinal recovery fingerprint" || field 1
  || field 3)`": field 1 is the root's 32 bytes; field 3, a hybrid public
  key record, is its canonical encoding (the bytes `encode` gives, as the
  sealed share's link key is), and nothing when absent. The 55 bits are
  read most significant first and cut into five 11-bit word indexes in
  order, as BIP-39 maps bits to words; shown joined by single spaces.
  The guardian types what the person reads: case and separators do not
  matter, and four letters or more of a word stand for it (they tell every
  BIP-39 word apart). The spec does not say how "||" encodes a record
  field, nor the bit order.
- **Reading: one recovery at a time, and starting over.** A guardian's
  device shows, of a person's recoveries under the policy it guards, one
  in effect if there is one, else the first it saw (`guarding.json` keeps
  when it first saw each), leaving out those the guardian said never to;
  the others wait, counted, with a plain warning, and endorsing or
  confirming one of them is refused. `cardinal guarding never NAME
  FINGERPRINT` writes an account setting, `"guardians: never confirm "`
  and the decision's id in hex, true, so every device of the guardian
  keeps to it; one never said is never endorsed or confirmed, and the next
  is shown. Confirming syncs the account with the guardian's own devices
  in touch first, with the log. `cardinal recover cancel` gives a recovery
  up on the new device (words, `recover` and helper go).
- **Reading: the warning.** The service refuses `guarding-endorse` and
  `guarding-confirm` unless the request says the guardian understood;
  `guarding-caution` gives the text, whichever way the person is named.
  `cardinal guarding endorse|confirm` prints it and asks for "yes" unless
  `--yes`: "Before you go on: this gives whoever holds that new device
  NAME's whole identity. It is safest done in person. Over the phone or a
  video call, go ahead only when you are sure of the voice and the face,
  and after asking something only NAME would know. Someone hurrying you is
  a reason to wait."
- **Reading: what is sealed in a record and in a confirmation.** The
  guardian record `{1: i, 2: salt, 3: {1: i, 2: 32 bytes}}` is sealed as
  its encoding; `confirm` field 4 seals the share record `{1: i, 2: 32
  bytes}` alone, to the `recover`'s link key, with the context
  `"recovery share" || identity id`. Shamir shares split `g` itself; the
  guardian key is the hybrid key pair from the seed `g`.
- **Reading: "with the guardian's log up to it".** The guardian sends the
  causal past of its act, genesis first, in one `objects` message under the
  guarded identity's label to that person's devices in touch (and its own
  devices), and keeps it under that label itself. Receivers hold other
  identities' entries under a label as attached logs
  (`IdentityLog::attach`), evaluate the log with them, serve them with the
  set, and name their heads in notices, so that another guardian, who need
  not know this one, gets them from the person's host. Only the causal
  past of an `endorse` or `confirm` naming a decision in the log, whose
  position and salt open that decision's policy's commitment for its
  writer, is kept; other identities' entries wait for such an act, at
  most 512, the oldest dropped, and are neither evaluated, stored nor
  served. A confirmation makes evaluation wait only for a decision of
  another log, and only when its signer is a key its own log names.
- **Reading: the delay's clock.** A guardian's wait starts when its own
  device first saw a threshold of endorsements (kept in `guarding.json`),
  and doubles if a valid `object` naming the recovery is in the log by the
  time it confirms. Guardians who are strangers see each other's
  endorsements through the new device, which carries them, or through the
  person's host.
- **Reading: syncing the guardian's own log before confirming.** Each own
  device in touch is reconciled, ten seconds at most each; a device that is
  not in touch is not waited for.
- **Reading: the new device's root key meanwhile.** The new phrase is
  generated by `cardinal recover start` and kept, with the identity, the
  signed `recover` and the devices to pair again, in `recovering.json`
  (mode 0600) until `cardinal recover finish` succeeds, which shows the
  words; the spec says nothing about keeping it. `finish` marks it
  `finishing` before it makes the device the person's: if it stops after
  that and before the end, the next `cardinal recover` shows the words
  once, then removes the file and the helper.
- **Reading: what the new device does on finishing.** Once the log the
  guardians carried shows the recovery in effect, the device makes, on
  that log and signed by the new root, one entry adding itself as admin
  with a wrap (the current key opened from the newest recovery wrap to the
  guardian key rebuilt from the shares, the current key's, else the
  policy's field 6) and one `set_encryption_key` with a fresh key whose
  chain carries the current one, and takes up the sets the guardians gave
  back: the account and their relationships with the person, opened with
  that chain. Every entry of them was written by keys the recovery
  removed, so all of it is set aside until kept: the device keeps it whole
  (a `keep` per removed key, of all it wrote there), since the spec says
  contacts, spaces and settings come back; what a thief wrote with a
  stolen device before the copy was last synced comes back with it. With
  no account among them, new account and files spaces are made, as
  `cardinal init` makes them, and only on the person's word
  (`--without-account`): otherwise `finish` refuses until a guardian has
  given the account back. `finish` marks itself first; a `cardinal
  recover` after one cut short takes up the copies from the helper's
  store, keeps them and makes the spaces if need be, and only then shows
  the words and drops the helper. What the removed devices wrote
  elsewhere is set aside, as after any recovery that kept none of them,
  and `finish` lists each with how much, and asks when they were lost:
  `keep-work DEVICE --up-to TIME`, by that device's own clock, or
  `--lost-at` at once (D77: "a device and a time"); the account and
  relationships given back stay kept whole. The words for the new root are shown, and
  "Pair your other devices again" with the devices the account remembers
  (else the keys removed), which `cardinal recover` keeps showing from
  `recovered.json`. Other spaces, the files space among them, come back
  only as their other holders are reached.
- **Reading: what contacts are told.** `contacts` says, for a contact
  whose log shows a recovery in effect, "was recovered by guardians they
  chose, after DELAY. If in doubt, check with them in person." whenever it
  lists them, not once. The spec gives "on" the date of the policy, but an
  identity entry carries no time, so no date is given.
- **Reading: keeping a lost device's work after a recovery.** A recovery
  that kept none of the old keys leaves everything they wrote unwitnessed,
  every space's genesis included; the spec lets the person keep "those
  the person recognizes, up to the point they choose". `cardinal
  keep-work DEVICE` lists that device's set-aside entries with the time
  each says it was written, and `--up-to TIME|all` writes, in each space,
  a `keep` listing the latest of those written by then, on every head of
  the graph, valid or set aside (with nothing valid there is nothing else
  to build on), sealed under the current epoch or a head's. Only a device
  or admin key the person's own log named and has removed, and only the
  person's own entries, can be kept. The point is the device's own clock,
  which a thief controls: entries with no time are kept only with `all`.
  `cardinal status --json` gives per space how many entries are valid and
  set aside.
- **Fixed on the way: a contact's log arriving as heads only.** A notice
  too big to carry its entries names heads; a contact's log whose new
  head's parents were missing was left waiting. Such a log now reports
  missing parents, and the rest is reconciled.
- **Decisions are not `valid`.** The rules judge `set_recovery` and
  `recover` only as decisions, so `IdentityState` now also reports
  `in_effect`, and proposals and wrap lookups use it.

## Spaces (`spec/spaces.md`)

- **Validity is judged natively, one entry at a time** (`validity.rs`).
  Each entry is judged when it and its ancestors are all here, from what is
  kept about its causal past, and again only when a signature it rests on
  starts or stops counting: an identity log that changes which keys count,
  a witness, a `keep`. The normative `space` program is run only by tests:
  property tests compare everything it reports with the native result, on
  random histories of several people with thieves, strangers and removed
  devices, in the order written, in random orders with comparisons on the
  way, and with identity logs arriving late and changing under entries
  already judged. The histories include entries their author signed
  twice, bodies signed again by another key, and `set`s on reach nodes,
  one's own and other people's. Fifteen flaws put into the native
  evaluation one at a time were each caught by that comparison, again
  after ids came to cover the signer and reach nodes stopped being
  created. (A sixteenth was in choosing among the signed forms of one
  entry, which no longer exists.) What the comparison cannot catch is a
  wrong reading of an op, since the rules program is given the same
  reading: which op is a reader's is tested case by case instead.
- **What an entry costs** (`tests/cost.rs`, optimized, on one laptop, three
  runs after ids came to cover the signer and nonces the whole signed
  object). In a two-person space, taking an entry that builds on
  everything held (opening it, checking its signature, judging it,
  applying it) took 61 to 67 µs at the 200th entry, 52 to 60 µs at the
  2,000th and 60 to 66 µs at the 20,000th: about 60 µs, and the same at
  any size. It was about 50 µs when an id was the hash of the body alone.
  Running the whole program once, which is what every entry in a shared
  space cost before, took 14 ms at 100 entries, 105 ms at 200, 0.4 s at
  400 and 1.9 s at 800. The graph keeps its log order by putting each
  entry in its place, where it used to work the order out again whenever
  an entry did not descend from every head. An entry held to be invalid
  is a head for good, since nobody builds on it, so with one in the space
  every later entry used to pay for that; now it takes 67 µs at the 200th,
  72 µs at the 2,000th and 70 µs at the 20,000th. What still grows with
  the space is an entry written at the same time as another: it
  recomputes the state ([State](#state-specstatemd-specprofilesmd)),
  0.7 ms at 200 entries, 10 ms at 2,000 and 145 ms at 20,000.
- **An entry signed again** has the same id and another sealed form. The
  first form to arrive is opened, judged and applied; a later one is
  opened and checked like any sealed entry, kept, and offered in
  reconciliation, and nothing is judged again
  (`Space::receive`, `tests/validity.rs`).
- **What only a member can reject, a member keeps**
  (`spaces.md#entries-and-sealed-entries`). Any holder refuses what any
  holder can check, which is never stored. What only a member can check
  (the nonce, the signature, the wraps hash, the open key) is stored and
  reconciled like any object, and is no entry: it is not in the graph, is
  never judged, and nothing can name it. The wraps hash is taken over
  field 4 as it came, so a wrap someone added a key to fails it, and a
  field 4 that lists no wraps is still a field 4.
- **Public is the genesis's to say** (`spaces.md#control-operations`,
  `Space::is_public`). Field 2 of the policy is read once, from the
  `start` of the genesis, and kept apart from the rest of the policy:
  nothing written later reaches it, a valid `set_policy` of the owner's
  included (`tests/space.rs`), and one in the genesis itself beside the
  `start`. A genesis is held to it like any entry.
- **A reader's one op.** A `set` whose node is `reach_node_id(author)`
  (`validity.rs`, `class`), of any field, in any profile, an account space
  included.
- **Spec ambiguity: who owns a personal space.** `profiles.md` says an
  account space has "one identity: yourself" and a files space "usually
  yourself", and gives neither a role. Chose: the genesis names its author
  as owner, so that the person alone can add someone to a files space and
  succeed either.
- **Spec ambiguity: "reserved".** Entry field 9 is reserved, and nothing
  says what a device does on meeting one. Chose: a field this
  implementation does not know, accepted, ignored and kept. (Control op 3,
  "not used", is allowed to no role, as the specification now says.)
- **Reading: which fields an op must have** (`spaces.md#control-operations`,
  "An op is what its table says only if it is written as the table says").
  The tables do not mark them. Here an op must have: `start` its profile;
  `add_member` the identity and the role; `set_policy` the policy;
  `set_protocol` the protocol record; `keep` the key; `succeed` the
  successor; `create` the kind and the parent; `set` the node and the key;
  `move`, `delete` and `restore` the node. A name that is absent is the
  empty name, a bool that is absent is false, and a list that is absent
  is empty. Every field that is there has its table's type, or the op is
  one nobody defined; `checkpoint` (37), which nothing here writes or
  reads, has none it must have, and its frontier, state root and state
  blob are typed like the rest. Where a node id belongs and something else stands,
  the op is read as one nobody defined too: it is a writer's op either
  way, and its entry is not accepted for state either way.
- **Spec ambiguity: a `leave` with fields.** `leave` has none. Chose: one
  that carries any is still a `leave`, and they are kept like any unknown
  field. (What 0.1.13 wrote as `remove_member` reads this way.)
- **Model mapping of space ops.** `rotate` and every profile op (32 and up,
  known or not) but the author's own reach node count as `app` (writers and
  up); `set_policy` and `set_protocol` are the owner's alone, in a genesis
  too; control ops this implementation does not define, extension ops, and
  malformed ops are allowed to no role. An `add_member` outside a genesis
  with a role above admin is allowed to no role, whether it names an owner
  or a role there is not (`rules.md` says so only of an owner; `world.py`
  of both).
- **Writing into a space that has ended** (`spaces.md#ending-a-space`).
  Once an entry on the valid heads would be closed, `Space::write` refuses
  anything but an entry with no ops, or with `keep` ops only. In a space
  with no owner the end is where the heads together hold every member's
  naming of one successor, though no single head does.
- **Not yet witnessed** (`spaces.md#authors`, `Space::has_unwitnessed`).
  What ends or begins a space is left out of the answer, though it too is
  not yet witnessed until a `keep` lists it: the answer decides whether a
  device being retired writes an empty entry, which keeps none of those,
  and the `keep` for each succession it made is not written yet (above).
- **Spec ambiguity: what else changes an entry later.** "Only a signature
  changes an entry later": an identity log, a witness, a `keep`. A `keep`
  can also be held before an entry it lists, and then that entry arriving
  is what makes its ancestors count. It is handled, and is one more thing
  that reaches an entry from outside its causal past.
- **Parents are the valid heads.** A new entry's parents are each valid
  entry that no other valid entry descends from, kept as entries arrive; an
  entry held to be invalid is never one. With nothing valid to build on,
  which is a space whose genesis does not count yet, nothing is written.
- **Wraps hash.** `BLAKE3` of the encoding of the list value of sealed
  records, exactly as carried in sealed-entry field 4.
- **The cited author log head** written by this implementation is the last
  entry in log order at which the signing key is in effect.
- **Not applied: `set_policy` and `set_protocol`.** They are judged, and the
  policy a space runs under is still the one its genesis gave it. Whether
  it is public would be the genesis's to say even if they were applied.

## State (`spec/state.md`, `spec/profiles.md`)

- **A node made in the same entry** (`state.md#a-node-made-in-the-same-entry`,
  `entry.rs`, `tests/index.rs`, `vectors/state.json`). Field 2 of `create`
  and of `move` may hold an unsigned integer, the place of an earlier
  `create` in the same entry. It becomes the id in the one place an entry
  is read (`SpaceEntry::from_signed`), which a built entry goes through as
  well, so nothing after that step holds an index: an op's parsed form has
  the id and its record the bytes as written. An op read outside an entry
  that holds an index names no parent (`SpaceOp::from_record`). What names
  nothing parses as an op of that number that nobody defines: it is a
  profile op for validity, so a writer's entry is valid and a reader's is
  not, and it is not accepted for state.
  - **Reading: integers.** An index is read at the full width an integer
    has (below 2^60), and compared with the op's own place before it is
    used for anything. A negative integer, text, a list, and bytes of any
    length but 16 name nothing.
  - **Reading: "at which there is no `create`".** Asked of the parsed op:
    an op numbered 32 whose own fields are wrong is not one. Nothing can
    tell the difference, since such an op puts its entry out of the state
    by itself. For the same reason the test for a `create` at the index
    changes no result: the id derived for an op that creates nothing is
    the id of no node. It is kept because the specification states it.
  - **Reading: a `move` under a node the entry creates, and a cycle.** A
    `move` whose index names a node that the entry then moves under the
    moved node is a cycle like any other: the entry is accepted, and the
    merge skips the move that would close it.
- **A delete reads the ops before it in its own entry**
  (`state.md#deletion-yields-to-concurrent-work`). What is beneath the
  deleted node is what the delete's causal past and the `create`s and
  `move`s before it in its entry put there, in both ways the state is
  worked out and in the definition the tests compare them with
  (`State::compute_by_definition`). So `[move Photos under G, delete G]`
  takes Photos, and a concurrent edit of Photos keeps G, as with two
  entries.
- **Reach nodes** (`state.md#nodes`). A reach node is in no registry of
  created nodes, so an op that names one is refused exactly as an op that
  names a node nobody created, with one exception: a `set` by the identity
  whose reach node it is. Nothing here asks whether sixteen bytes are some
  identity's reach node, which could not be answered without knowing every
  identity; both reasons reject the entry, so the answer is never needed.
  A `set` written beside, and a cleared field, behave as on any node.
- **Spec ambiguity: what a delete deletes.** Chose: a delete of N flags N
  and every node beneath N in the delete's causal past that no concurrent
  op touched; N is flagged delete conflict if touched. A `restore` of N
  clears N and the nodes beneath it that the same delete flagged. Views
  hide everything beneath a deleted node.
- **Any kind, anywhere** (`state.md#operations`). A `create` is accepted
  whatever its kind and wherever it puts the node, and the files and
  account profiles reject nothing for kind or place any more. What shows a
  space steps over what it has no meaning for, with everything beneath
  it: the files view lists only folders, files and links, and only in the
  root or in folders all the way up (`Files::list`, `Files::belongs`); a
  conversation is a conversation node at the top, a message a message in
  it, a reaction a reaction under a message; an account's devices,
  contacts, hosts and spaces are those at the top, and a placement one
  under a space node. An op the profile does not define still puts its
  entry out of the state.
  A `move` is accepted wherever it takes a node, a cycle aside, which the
  merge skips. Conflicts in nodes the folder does not show are not listed
  by `cardinal conflicts` or counted in `status`.
- **File content and conflict copies.** The version "last in log order" is
  the value whose writing entry is last in log order; same-name siblings
  are ordered by the log position of their creating entry.
- **Cost of state updates.** A valid entry that descends from every valid
  entry is applied incrementally, and one that is not valid changes nothing.
  A valid entry concurrent with one already applied, and any change in
  which entries are valid, recomputes the state from scratch: O(n log n)
  plus O(n) per `delete`, since each delete replays positions in its causal
  past and scans concurrent entries. `state.md#cost` asks for recomputation
  "only for the nodes it touches"; that is not done yet. Validity itself is
  not recomputed ([Spaces](#spaces-specspacesmd)).
- **Written beside.** A `set` written beside adds its value and supersedes
  none; a `delete` written beside deletes nothing and flags the node delete
  conflict, and does nothing on a node that is already deleted. Nothing here
  writes either: they belong to posting work again after a succession.
## Link (`spec/link.md`)

Deviations:

- **Deviation: a data packet carrying a `rekey` frame is up to 1224 bytes,
  not 1200.** An ML-KEM-768 public key is 1184 bytes, so a `rekey` frame
  encodes to 1190 bytes, which does not fit in the 1168 bytes of plaintext
  a 1200-byte data packet allows. The packet carrying it holds nothing else
  (at most a small ack) and is at most 1224 bytes, which with the 8-byte
  relay header is exactly the 1232-byte carrier limit
  (`packet::DATA_MAX_LEN_REKEY`). Every other data packet stays within
  1200. The spec should either raise the data limit to 1224 or split the
  key across two frames.
- **Deviation: a device without an identity sends an empty `device proof`
  frame `{0: 14}` instead of omitting it.** The spec omits the proof in
  invitation sessions whose invitee has no identity; but a receiver cannot
  tell "no proof will come" from "the proof is late" (on UDP the proof and
  the following `rekey` travel in different packets, since together they
  exceed a packet). An empty proof is explicit, keeps "device proof first"
  true for every session, and is accepted only in sessions opened with a
  secret (or the public case) whose expectation names no identity.
- **Stricter reading: application data waits for the first rekey.** The
  spec forbids frames other than proofs, rekey, ack, and padding until both
  proofs are verified. This implementation also holds streams and
  datagrams until the mandatory post-quantum rekey has completed, so no
  application byte is ever protected only by the handshake keys (which, in
  invitation sessions, have no ML-KEM component). This costs one round
  trip at session start. `close` is also allowed before the proofs.

Readings of ambiguous text:

- **Counter in the transcript.** `MixHash(counter)` hashes the 8 bytes of
  the counter as they appear on the wire (little-endian).
- **mac1 of a response.** `m1` is defined with `R.x25519`. Read as "the
  static key of the packet's receiver", as in WireGuard: a response's mac1
  is keyed with `H("cardinal 1 mac1" || I.x25519)`.
- **mac2 key.** `keyed_hash(cookie, ...)` needs a 32-byte key and the
  cookie is 16 bytes: the cookie is followed by 16 zero bytes.
- **Cookie layout and input.** A cookie reply is WireGuard's: type 3 and
  three zero bytes, the initiation's sender index, a 24-byte random nonce,
  and the encrypted 16-byte cookie (32 bytes). The source address hashed
  into the cookie is its 4 or 16 IP bytes followed by the port as a
  little-endian u16. The rotating secret changes every two minutes; the
  previous one is still accepted. The initiator retransmits the same
  initiation with mac2 set.
- **Data nonce.** "4 zero bytes ∥ counter": the counter is little-endian.
- **Low-order points.** Any all-zero X25519 result in the handshake aborts
  it (contributory behaviour).
- **Zero ML-KEM ciphertext in a response.** The initiator accepts it (the
  responder does not know the invitee's ML-KEM key); the session relies on
  the rekey.
- **How the two sides switch key phase.** The responder sends `rekey
  reply` in the old phase, installs the new receive key, and switches its
  sending key on the first packet that authenticates under the new receive
  key. The initiator switches both directions when it processes the reply
  and acknowledges at once, so that first packet follows immediately. The
  previous phase is accepted for 5 seconds after each side's switch.
  Retransmitted `rekey` frames get the same reply (same ciphertext).
- **Rekey timing.** "Every two minutes of activity": two minutes since the
  last rekey, provided at least one packet was sent or received since. The
  2^40 count is of ack-eliciting packets sent.
- **Ack ranges.** Ranges are listed from the largest counter down. For
  each `{1: gap, 2: length}`, `gap` is the number of unacknowledged
  counters between the previous range (or, for the first range, the
  largest counter plus one) and this range, and `length` the number of
  acknowledged counters in it. Unlike QUIC, neither is stored minus one;
  the first range always has gap 0.
- **What is acknowledged.** Datagram frames are ack-eliciting but never
  retransmitted. Unknown frame types are acknowledged and ignored.
  Acknowledgements are sent after 32 ack-eliciting packets on reliable
  carriers (2 on UDP), at once for rekey, proof, path, and ping frames, and
  otherwise within 10 ms.
- **Reliable carriers.** Over TCP, packets are never lost, so stream data
  is released as soon as it is packetized and nothing is retransmitted;
  acks are still sent and accepted.
- **Stream frame fields.** Offset and data are always present (offset 0
  and empty data are encoded, not omitted); `fin` is present only when
  true (as 1); `service` and `priority` are on every frame at offset 0,
  including resent ones. A stream whose first-arriving frame is not at
  offset 0 is surfaced to the application once the offset-0 frame names
  its service.
- **`reset`** aborts the stream in both directions (there is no separate
  stop-sending frame). Dropping a stream handle whose sending side is not
  finished resets it with reason 0.
- **Session window.** The session limit counts, as QUIC's MAX_DATA, the sum
  over streams of the highest offset received. Windows are raised when
  half of the window has been consumed.
- **Identity binding when the peer's log is not known yet.** In sessions
  opened with a secret (invitations, pairing), a device proof whose
  signature verifies but whose identity log is not held is accepted
  provisionally if it matches what the secret's issuer expected
  (`ExpectedPeer`: the invitation's `for` identity, the inviter identity,
  the pairing signing key). `PeerIdentity::verified_by_log` says which;
  `Endpoint::recheck_peers` upgrades provisional proofs once the log
  arrives and closes sessions whose verified key is no longer effective.
- **Simultaneous sessions.** "The device with the smaller static key" is
  the bytewise-smaller X25519 key. The rule applies when sessions with the
  same peer initiated by different sides are established within 10 seconds
  of each other; otherwise the newer session replaces the older (a
  reconnect).
- **Paths.** A packet that authenticates from a new path triggers a path
  challenge there (retried up to 3 times, a second apart); the session
  moves when the response arrives from that path. `observed address` is
  sent once when the session is established and after each move.
- **Idle and keepalive.** The idle timeout sends a `close` frame. The
  keepalive interval is a per-endpoint setting (off by default).
- **Unanswered pings (the spec is silent).** A session with keepalive
  closes when something that wants an answer has gone 10 seconds with
  nothing heard, asking again every second. The three-minute idle timeout
  alone left a device listed as online, and stopped it being dialled, for
  that long after a network change. Sessions without keepalive follow the
  spec.
- **Persistence of counters.** The initiation counter and the confirmed
  counters are kept in memory; the daemon persists them through
  `Endpoint::{last_counter, set_last_counter, confirmed_counter,
  set_confirmed_counter}`.
- **TCP framing** follows `link.md#carriers`: a 16-bit length prefix,
  little-endian like every integer in link.md.
- **Every device listens on TCP too.** `link.md#carriers` has personal
  devices listen only on UDP, because a TCP port shows up to scanners. Devices
  dial UDP first and give it two seconds; TCP stays for older devices and
  networks that block UDP.
- **Congestion control** (`link.md#priority`, `cc.rs`). One window for the
  session, answering to loss and to queueing delay beyond 60 ms; a LEDBAT-style
  limit with a 25 ms target for background traffic; a token-bucket pacer,
  because timers here are about a millisecond. Real-time traffic skips the
  window, as "never queued behind other classes" asks. A loss with almost no
  queue counts for less, so that a radio link is not read as a full one.
  Background traffic stands back briefly every 30 seconds so a flow that
  started late does not take the queue for the path. Being delay-based, a
  session gives way to loss-based traffic sharing a deep queue.

Not implemented yet (the next milestone):

- Multiple simultaneous paths, choosing the path by smoothed RTT, and
  duplicating real-time traffic across paths. A session uses one validated
  path at a time.
- Delivery tokens as a secret source, and the public and restore cases
  beyond the `allow_public` switch (`prove` is not implemented at this layer).
- Local radio carriers.

## Contact (`spec/contact.md`, `spec/hosts.md#local-discovery`)

- **Spec bug: the example code is not made of BIP-39 words.**
  `4-amber-harbor-quiet`: "amber" and "quiet" are not in the BIP-39
  English list (only "harbor" is). Codes here use only list words, e.g.
  `4-anchor-harbor-quit`; the parser rejects other words. Parsing accepts
  any case and spaces or hyphens between the parts.
- **Spec ambiguity: the endpoints in the session identifier.** Chose: the
  shower's endpoint is `{1: 1 (UDP), 2: the shower's IP address on the
  route toward the typer, 3: the advertised pairing port}`, and the
  typer's is `{1: 1, 2: the typer's IP address, 3: its pairing socket's
  port}`, i.e. the UDP addresses each side's datagrams carry. This breaks
  through NAT or on multi-homed hosts where the two sides see different
  addresses; the spec could bind the advertised record instead.
- **Spec ambiguity: the confirmation order.** The shower sends its share
  and then its tag at once; the typer always sends its tag, even when the
  shower's tag is wrong, so that a wrong code counts against the code.
- **What counts as a failed attempt.** A wrong typer tag, or an attempt
  in which the shower sent its tag and no valid typer tag followed (another
  typer started, or 10 seconds passed). After three, `Shower::run` returns
  `TooManyAttempts` and the caller shows a new code.
- **Spec ambiguity: the power in the proof of possession.** The proof
  binds a power, but the pairing message carries none, and the admin
  decides the power afterwards. Chose: the new device signs for
  `LocalDevice::join_power` (device by default); the typer verifies against
  device power, then admin, and reports which in `NewDevice::power`. The
  spec should carry the power or fix it to device.
- **Proofs only from a device without an identity.** When two people meet,
  neither sends a proof (a proof would let the other list your device in
  their own log). A typer must have an identity.
- **Pairing info encryption.** XChaCha20-Poly1305 with a random nonce and
  empty associated data. The info message (it carries a full link key) is
  about 1450 bytes, more than the link's 1232: it relies on the LAN's MTU
  or IP fragmentation.
- **Retransmission.** Lost pairing datagrams are retransmitted every 300
  ms by the typer; the shower answers duplicates with its earlier replies.
- **The link session after pairing.** The typer initiates to the shower's
  link endpoint (info field 4) with both full link keys and the single-use
  secret `derive("invite", K)`; each side expects the other's signing key
  (and identity, if any) from the pairing.
- **mDNS** is a minimal DNS-SD over IPv4 multicast: unsolicited
  announcements (PTR, SRV, TXT, and A when known), answers to PTR queries,
  and browsing; no probing, conflict resolution, known-answer
  suppression, or IPv6. Instance and host names are random and, for
  device discovery, change with every refresh along with the nonce. A
  browser uses the packet's source address when there is no A record.
- **Trusted contacts find each other nearby** (D74,
  `hosts.md#local-discovery`, `presence.rs`, `daemon.rs`
  `start_discovery`, `rendezvous.rs` `found_nearby`). On the LAN here;
  over Bluetooth in the next entry.
  - **Spec gap: the purpose `presence`** is not in `crypto.md`'s table of
    derivation purposes. It is used as `hosts.md` writes it,
    `derive("presence", secret)`, context `cardinal 1 presence`, and is
    left out of `Purpose::ALL` and the derivation vectors until the table
    has it.
  - **Reading: the secret node's purpose** is the text `presence`, as the
    discovery secret's is `discovery`.
  - **When a secret is made.** When the person first has a trusted
    contact whose relationship is open on the device, and again when
    someone refused or no longer trusted holds, in field 2 of the
    person's reach node in their relationship, a secret still in the
    account. A new one deletes every presence secret node and creates
    one, in one entry. Each device does this on its own at its next look
    (the delivery loop), so two that act at once leave two, as the text
    allows.
  - **Taken back.** Field 2 in the relationship with someone refused or
    no longer trusted is cleared (a `set` with no value), as well as the
    secret renewed. Whether someone holds a secret still in use is read
    from field 2 in every relationship with them held here, ended or
    left too, where nothing more is written. Trusted again, they are
    given the one in use.
  - **Reading: two contact nodes for one identity** (made at once on two
    devices) are one contact: trusted only if every node says trusted
    and none refused.
  - **Reading: "accept every value a contact gave"** is every value field
    2 of their reach node holds now in the relationship, two where two of
    their devices set it at the same moment; not values set before.
  - **`c=` is left out** until the person has given the secret to a
    trusted contact, and the advertisement is made again within two
    seconds of that changing.
  - **What is taken from the network.** Only a packet from the local
    link counts (link-local, or a subnet the device has a route to with
    no gateway; loopback only where a test runs discovery there), and
    only its source address is dialled, whatever its records name. At
    most four instances are read from one packet, each once. Own devices'
    `t=` is checked first, always; only the first `c=` of an instance is
    checked, and at most eight from one source in ten seconds. The keys
    of the contacts' tags are derived once for the state they come from.
  - **What a match does.** Each of the contact's devices with no session
    is dialled at that address and the advertised port (the TCP link
    port, as for own devices), UDP first, until the first answers. A
    contact is tried at one address at most once in 10 seconds, at most
    three times a minute at any addresses, and one try at a time, apart
    from the looks through hosts: a replayed tag costs a try and no
    more. Tries are kept apart from the looks too: `contact-status`
    `nearby_tries`, and in `cardinal contacts NAME` "Where their tag was
    seen on the local network", say "found on the local network" only
    once a session opened. Nothing anywhere says a contact is nearby
    from a tag.
  - **`contact-status` gives `nearby`**: `you_give_secret` and
    `they_give_secret`, whether each reach node in the relationship holds
    one.
- **Bluetooth Low Energy** (`carriers/ble.md`, D74; `contact/src/ble.rs`,
  `cardinald/src/bluetooth.rs`, `bluez.rs`, `link` `Endpoint::attach`). The
  draft as written: the UUID, service data of the PSM (little-endian) and
  17-byte tags of types 1, 2 and 3, a legacy form of PSM, type, `nonce (4)
  || first6`, L2CAP LE credit-based channels with packets length-prefixed
  as over TCP, and the person's three states. Readings:
  - **Purpose `one-time`** is used as `crypto.md` (draft) lists it,
    context `cardinal 1 one-time`, and like `presence` kept out of
    `Purpose::ALL` and its vectors until published.
  - **The service UUID is in the advertisement too**, as a 128-bit UUID
    list, in the extended form as in the legacy one: scanners filter on
    it (BlueZ's discovery filter and Android's `ScanFilter` match the UUID
    list, not service data keys). The extended form is then flags, the
    UUID list and the service data: 3 + 18 + 18 + 2 + 17n bytes, 92 with
    three tags. At most eight tags (`MAX_TAGS`).
  - **Legacy form on BlueZ** goes in `ScanResponseServiceData`, which
    BlueZ has only with `--experimental`; without it the advertisement
    carries the UUID and no tag, and nobody finds the device. Used where
    the adapter's `SupportedCapabilities` `MaxAdvLen` is too short for
    the full form, or the full one is refused.
  - **Both forms at once where the radio has room** (spec question): a
    device that sends the extended form sends the legacy one beside it,
    as a second advertising set (BlueZ: a second registration; Android: a
    second `AdvertisingSet`), so that a phone whose scanner sees only
    legacy advertisements still finds it. Where the second is refused,
    only the extended one goes. The draft says which form to use, not
    whether both.
  - **Which tag in a legacy advertisement:** the keys take turns, one per
    refresh (each counted apart from anything else the radio numbers).
    While there is a one-time tag, one has every other turn, since whoever
    holds the invitation is looking now; and the advertisement is made
    again every 10 s instead of 30 s. Someone accepting looks for 60 s.
  - **BlueZ only with privacy on.** Without the controller's privacy
    (`Privacy = device` in `/etc/bluetooth/main.conf`), BlueZ advertises
    and opens channels from the adapter's fixed public address, which
    would let anyone follow the computer whatever the tags do. Privacy is
    read from the kernel's management interface (Read Controller
    Information, current settings bit 13; no privilege needed), and where
    that cannot be read, from `main.conf`; without it the radio is not
    used, and `why_not` says how to turn it on. Android advertises and
    connects from resolvable private addresses already.
  - **Reading: tag types are bytes.** An unknown type is kept and matches
    nothing; a short tag matches only `keyed_hash(k, nonce4)[..6]`.
  - **One channel, every key at once.** A tag says whose device, not
    which: own devices' (type 1) or a contact's (type 2) device is dialled
    by opening one channel and starting a handshake to each of the
    person's devices without a session at once on it
    (`Endpoint::connect_on`); only the one at the other end can answer,
    and the others give up. Over a LAN each is dialled in turn instead.
  - **Limits.** A contact at one place once in 10 s, and three times a
    minute on each carrier: a tag replayed over Bluetooth does not use up
    the tries on the LAN, nor the other way, and each carrier has its own
    one-try-at-a-time. A place where a contact's tag led to a session
    before (the last 64 kept), or a LAN address the peer book has for one
    of their devices, does not count against the minute. Own devices'
    tag: at one address once in 10 s, and three times a minute at all
    addresses, since a recorded tag can be played again from a new
    address each time. Bluetooth tries of own devices are counted apart
    from the tries over IP, and never hold those up. The same
    advertisement from one address is looked at again only after 2 s (a
    radio reports it many times a second), of at most 512 addresses kept;
    at most 50 advertisements are looked at a second, whoever sends them;
    the keys they are checked against are derived once for the state they
    come from, as on the LAN.
  - **Channels others open:** at most 16 at once and 2 from one address;
    when all are taken, the oldest with no session over it gives way. A
    channel with no session over it for 10 s is closed, from its start or
    after its session ended or moved. Over any stream carrier (TCP too),
    the rest of a packet must come within 20 s of its length.
  - **Reading: a session over Bluetooth is not direct enough.** It holds
    only while the two are in range, so own devices and contacts reached
    over Bluetooth alone go on being looked for over IP, and a direct
    session over IP replaces one over Bluetooth whichever came first, as
    a direct session replaces one through a host
    (`link.md#identity-binding`, extended: relayed, then Bluetooth, then
    direct over IP). Both ends can tell which a session is.
  - **Type 3 is advertised only by the device an invitation names**
    (`responder_static`), and only while it is outstanding. An invitation
    naming the person's host leads to the host's key, which no device in
    range has, so nothing advertises it (spec question).
  - **Accepting an invitation** dials its address first, as before; when
    that fails, or the invitation has no IP address, and Bluetooth is on,
    it looks for the type-3 tag for 30 s and runs the invitation's
    handshake over a channel to the device that has it. The invitation's
    endpoint is left as it was; with no address at all `invite` still
    fails ("no address to give").
  - **Pairing codes carry no one-time secret** (33 bits, for CPace), so
    no type-3 tag is made from one: offline, 2^33 keyed hashes recover
    the code from the tag, and whoever has it can pair. Pairing over
    Bluetooth is not done (spec question).
  - **Endpoints**: carrier the 8-byte name, address the 6 bytes, port the
    PSM (`EndpointAddr::ble`). The record does not say random or public;
    read as random. Never written in a reach node, and not yet passed in
    rendezvous.
  - **"On while open"** is while a client watches with
    `{"cmd": "watch", "window": true}`; a watch without it does not count
    (Android's service watches with no window open). With `open` and no
    window, a CLI-only device has Bluetooth off.
  - **Android's bridge socket** (`CARDINAL_BLE_BRIDGE`) is mode 0600, each
    connection's peer must be of the service's user, and the connection
    that drives the radio says so in its first line (`{"control": true}`).
  - **Channels are opened at security level low**, with no Bluetooth
    pairing (Android: the insecure L2CAP calls): the link session proves
    and encrypts.
  - **The setting is this device's** (`config.toml` `bluetooth`), not the
    account's: each device has its own radio and battery.
- **Reach: what goes where** (`profiles.md#reach`, `relationship.rs`).
  Field 1 holds host entries; field 2 the presence secret, only in a
  relationship; any other field of the node is untouched by a `set` of
  one field, as state keeps fields apart. A host entry's fields beyond
  1, 2 and 3 are kept as they came (`Reach::extra`) and written again
  with the entry.
- **Invitations.** The `uses` field is omitted when it is 1 (the default).
  Base32 is RFC 4648 lowercase without padding; decoding accepts any case
  and rejects non-zero trailing bits.

## Link implementation notes

- Throughput, one stream over loopback TCP, release build, on an
  i7-8650U held at 0.9–1.0 GHz by its power governor and shared with other
  builds: 35–40 MB/s for 512 MiB–1 GiB. The session core alone (both ends
  in one thread, no I/O) does about the same, so the cost is per packet
  (two AEAD operations and bookkeeping per ~1150 bytes), not the carrier.
  RustCrypto's AVX2 Poly1305 backend has a large fixed cost per message on
  this machine (about 6 µs at 0.9 GHz); building with `RUSTFLAGS='--cfg
  poly1305_backend="soft"'` makes sealing a 1200-byte packet about twice as
  fast. Worth revisiting before tuning anything else.

- **Spec ambiguity: flow control of a reset stream.** The `reset` frame
  carries no final size (QUIC's RESET_STREAM does), so a receiver that
  resets a stream cannot tell how much more data the peer sent before it
  saw the reset. That data counts against the peer's session credit; if the
  receiver drops it without counting it, the credit leaks away and the
  session eventually stalls. Chosen without a wire
  change: a stream reset locally is kept until the peer's `fin` or `reset`
  arrives, and data arriving for it meanwhile is counted as received and
  consumed; a side that receives a `reset` while it was still sending
  answers with a `reset` of its own, so the other side knows the last of
  the data has arrived. On reliable carriers this is exact. On UDP, data
  lost before the reset is never resent and its credit is still lost.
  Suggest: give `reset` a final-size field.
- **Reading: streams whose first frames arrive out of order.** `link.md`
  does not say whether a frame for a peer stream id below the highest one
  seen, never seen before, opens that stream or belongs to one that ended.
  Streams get ids when opened but send when written, so a later stream
  often writes first. This implementation used to drop such frames as
  belonging to an ended stream: the request on that stream was lost, and
  the blob fetcher waited for its 20 s timeout (the stalls seen while
  syncing a large folder). Chosen, as QUIC: a new id opens every lower
  unseen id of the peer's parity; their first frames are accepted later.
- **Deferred reader wake-ups.** A stream reader waiting for more than is
  ready is woken once 32 KiB (or what it asked for) is ready, at the end
  of the stream, or when the carrier has passed on every packet it has
  buffered, not on every packet. Local only.
- Per-packet cost, measured again (same machine, loaded by parallel
  builds): sealing a 64-byte packet takes 5.2 µs with the AVX2 Poly1305
  backend and 1.3 µs with the soft one; a 1200-byte packet 9.2 vs 7.8 µs;
  the session core alone moves 52 MB/s vs 61 MB/s. The soft backend is
  still not forced (it is a global build flag and slows the large-message
  AEAD of blob chunks).

## Daemon, mount, and CLI (`cardinald`, `cardinal`)

- **The store's format** (`format.rs`; not in the specification). The data
  directory holds `format`, one decimal number and a newline: 2. Whatever
  makes a store writes it first: `init`, pairing in as a new device, and
  restoring all install an identity through one function. A directory with
  an identity, a space or an object and no marker is format 1. The daemon,
  `init`, and anything else that opens the store refuse another format
  before reading or writing anything in it, in words that name the
  directory, say an earlier (or later) version wrote it, that this one
  cannot read it and changed nothing, and what to do; every command says
  the same when no daemon answers. A marker that is not a number is
  another version's. **Reading: a marker that cannot be read** (it is a
  directory, or may not be opened) says nothing, and the store may be one
  that works: nothing starts on it, `--store` says `unreadable` with the
  reason in words, and `cardinald --clear` refuses it. `apps.md` gives
  the service's program "data this version cannot read" to remove: here
  that is a store of another format with an identity, a space or an
  object in it, and never a directory that holds no store, whatever in
  it has a name the service would use. `cardinal clear` removes any of
  these, and asks first.
- **One process on a data directory** (`lock.rs`; not in the
  specification). A service holds an exclusive lock on its data directory
  (on the directory itself, so that nothing is written to take it; on
  Windows on a file `lock` in it) from before it reads anything there
  until it exits,
  and a second one on the same directory does not start. `cardinal clear`
  and `cardinald --clear` take the same lock, so neither removes a store a
  service is running on, whatever the directory was called this time and
  wherever the command looks for the socket. The data directory is taken
  by its canonical path, so the socket's name does not turn on a trailing
  slash or a link. On Windows the lock is a file opened sharing nothing,
  which is written and has never been run.
  - **Limit: a data directory on a network file system.** The lock is
    `flock` on the directory. On Linux NFS a directory's `flock` is, as
    far as its documentation says, local to the machine (not checked
    against a kernel here), so two machines that share a home over NFS
    can each run a service on the same data, and each would empty
    `blobs/tmp` and cut log tails under the other. Nothing here detects
    that. Where a file system refuses the lock instead (some FUSE, 9p and
    CIFS mounts), the service does not start and says that the directory
    cannot be locked and to keep the data on a local disk.
  - **Who takes it, and when.** The service takes it before it reads or
    saves its settings. `cardinal init` with no service running holds it
    while it writes the identity and the first spaces; with one running
    it writes under that service's hold and tells it to load, as before.
    A command that finds the directory held and nothing answering on the
    socket says a service is starting (or listens elsewhere), and `init`
    waits up to 15 seconds for it. A directory that cannot be opened to
    look is an error, not "no service".
- **`cardinal clear`** (`clear.rs`) removes what the node wrote in the
  data directory, by name and without reading it, so it works on a store
  of any format: the keys, the identity log, the spaces, the objects,
  files being written, other people's logs, the mailbox, the state files
  and the marker. It leaves `config.toml`, anything there the node did not
  write, and the files kept on this device only, which it removes with
  `--including-local`. Those are `local/` and also `local-shared/`, which
  holds the same kind of file for folders shared with someone. It refuses
  while a daemon answers on that directory, says what is there first, and
  without `--yes` asks for the word `clear`. The marker goes first and the
  identity log last, so that an interrupted clear leaves a directory that
  nothing opens and that clearing again finishes.
  On Unix it leaves anything called `lock` there: the node never writes
  one (0.1.13 removed it, a folder too).
- **A client that starts the service itself** (`bin/cardinald.rs`; not in
  the specification). A phone and Windows have no `cardinal` command to
  say why the service did not start, or to clear a store. `cardinald
  --store` answers in one line of JSON and starts nothing: `store`
  (`empty`, `current`, `other`), what the directory `holds` as `clear`
  counts it, and for another version's store `written_by` (`earlier`,
  `later`, `another`) and the `refusal` in the daemon's words. `cardinald
  --clear` removes what `cardinal clear` removes, never the files kept on
  this device only, answers `ok` or an `error`, and refuses while a
  service answers on that directory. It also refuses a store this version
  can read: nothing in it asks the person, so it cannot remove one that
  works. The client says what will be removed and asks first
  (`clients.md`).
- **Objects that nothing names** (`cleanup.rs`, `cardinal free-space
  --unnamed [--delete]`). An object is named if it is reachable, through
  indexes at every level, from a blob reference anywhere in any op of any
  entry this device could open in any space it holds: valid or not,
  waiting for its parents or not. That takes in current values, every
  value of a field in conflict, and every old version, kept or not: an
  old version past its keep period is still named, and `free-space`
  frees it, so the two passes never delete the same thing. What is being
  written is covered as in the hourly pass: no commit runs meanwhile, and
  nothing stored or read in the last hour is counted. The count may be
  too high, and nothing is deleted, when a space is held and not open,
  when entries of a space cannot be opened yet, or when an index that an
  entry names is missing or unreadable. On a device that keeps files on
  demand most indexes are missing, so there it can only count.

- **What a flush promises** (`profiles.md#mapping-to-a-disk-guidance`). An
  `fsync` through the mount flushes the staging file and, the first time
  or when anything recorded changed, appends a record to `staging/journal`
  (the path, the staging file, the mode, the node and the versions it was
  written over), flushed with the staging directory; `fsyncdir` writes the
  journal again from where everything recorded is now. A mount starting up
  takes up every staging file the journal names: as an edit of its node
  over the recorded versions, so a version from elsewhere is kept beside
  it, or as a new file at its path (`name (recovered)` if the name is
  taken). It writes the journal again naming what it took up, and removes
  staging files nothing names. An unmount that cannot commit names every
  dirty staging file in the journal and keeps it. Staging file names carry
  a random part, so a restart never reuses one. Writes never flushed are
  lost in a crash, as on a disk. A crash between a commit and the journal
  being written again can bring a new file back once more, as `name
  (recovered)`: a duplicate, not a loss.
- **Dropping a chunk** (`blobs.md#dropping-a-chunk`). Only this person's own
  devices with full retention are checked, through the copy-check sessions
  (`copies.rs`); storage hosts are not asked yet, so a person whose only
  full holder is a host keeps everything on an on-demand device. The check
  fetches each chunk back, 16 at a time. What could not be dropped is in
  `cardinal status` under `old.only_here`, and `old.unchecked` says no full
  holder was reachable; `cardinal free-space` says either. No client shows
  them yet.

- **What its person may not change** (`profiles.md#mapping-to-a-disk-guidance`,
  `fs/tree.rs`, `fs/ops.rs`, `fs/commit.rs`). A node created author-owned
  by someone else is shown without write permission, and writing,
  truncating, changing its mode or time, renaming, replacing or removing
  it fails with `EACCES`; something may still be made under it. The commit
  path leaves such a node out of every entry. After each entry it writes
  for a folder it checks that the entry is valid and accepted for state.
  If it is not, nothing the entry carried is marked committed: files stay
  dirty with their staging files, and are not written again until they
  change. **Reading: "tells them".** The daemon logs an error, `status`
  has the count in `not_saved`, and `cardinal status` says so. Every
  change in the entry is held back, not only the one that was at fault,
  which the device cannot tell.
  - **What waits with it.** A file or folder put in a new folder that is
    held back has nowhere to go: it is held back too, counted, and neither
    written nor encoded until the folder changes (a rename), when the
    folder and everything held back beneath it are tried again.
  - **A delete or a settled conflict** that such an entry carried is
    undone, since nothing of it is kept: the file is back at the next
    refresh. `status` counts these in `not_saved` and by themselves in
    `not_saved_undone`, until a commit goes through with nothing refused.
    One that was behind such an entry and was not written, or in a commit
    that failed, stays and is written by the next.
  - **A conflict in a file that is someone else's to change** is not
    settled from here: renaming the copy onto the file fails with
    `EACCES`, as deleting the copy does, and the commit path leaves such a
    settle out.
  - **Not kept across a restart:** the count starts at zero, and what was
    flushed is written once more.
- **A new folder and what is in it are one entry** (`fs/commit.rs`,
  `state.md#a-node-made-in-the-same-entry`). What a burst puts in a folder
  the same burst makes names it by the place of its `create`: new files
  and folders, and existing ones moved in. In a round what is new is
  written first, each in the order it was made here, and what is moved or
  edited after. A burst too large for one entry (96 KiB of ops) is cut,
  and what comes after a cut names by id what an earlier entry made. One
  case still takes a second entry: something new that was put under a
  folder made after it. Everything else that writes entries (`Core::write`
  and its callers) cuts ops into entries without regard to indexes, and
  none of it writes one.
- **Spec ambiguity: which device shows the pairing code.** `contact.md`
  and `experience.md` have the new device show the code and an admin type
  it; this is what is implemented (`cardinal pair` on the new device,
  `cardinal pair <code>` on the admin). The proof of possession only works
  that way round.
- **Discovery advertises the TCP port.** `hosts.md#local-discovery`
  advertises "this device's link endpoint". UDP and TCP use the same port
  here, so the SRV port is both.
- **The pairing endpoint may be unspecified.** A device listening on
  `0.0.0.0` sends that in pairing info field 4; the typer substitutes the
  address it reached the pairing socket at.
- **Spec ambiguity: how a device learns which spaces exist.** sync.md
  reconciles sets both sides are entitled to, but a new device knows no
  space ids. Here a device that receives a `reconcile` (or `heads`) for an
  unknown label *from one of its own devices* answers as if empty and then
  fetches the set, creating the space. The spec could say this, or have
  the account space list every space (it does list the files space).
- **Replacing a file by rename is an edit.** `rename(tmp, file)` over an
  existing file writes `set` of content on the replaced file's node and
  deletes the temporary node, so editors' atomic saves keep history and
  produce conflict copies. `profiles.md#files` does not say how renames
  onto an existing name map to ops.
- **Settling a conflict of three or more versions.** Deleting one conflict
  copy writes a `set` of the main version, which also drops the other
  copies (they remain in history). A `set` cannot keep two of three values.
- **Not implemented: `rotate_after`.** No epoch is started for the number of
  entries written under one (`spaces.md#when-to-rotate`, a SHOULD).
- **Retired and lost devices.** `cardinal remove-device` treats a device as
  retired (`spaces.md#authors`): it syncs with every device it can reach,
  the one going away first, and witnesses what that device wrote. With
  `--lost` it witnesses nothing, and the removal's parents leave out what
  the key wrote that no other key built on (`identity.md`). Three things are
  not implemented yet: showing the person those entries to choose from, the
  `keep` op from the command line, and showing the keys a removed key added,
  which identity.md requires when writing a removal.
- **Telling a removed device.** The spec does not say. The device doing the
  removal delivers the removal to it before closing the session, because
  nobody answers it afterwards and until then it can pass the news on. A
  device that hears it was removed stops writing. One that was offline at
  the time never hears.
- **When a new epoch is due** (`spaces.md#when-to-rotate`, `core.rs`,
  `Reached`). A device keeps, with each epoch whose key it holds, what it
  held when it first held that key: the fingerprint of the encryption key
  of each member who has not left, and whom it knew to be frozen, in
  `spaces/<id>/epochs.json`. A member added by an entry that descends
  from the one that started the epoch joins the record with the first key
  the device holds for them. Any other member the record has no key for
  calls for a new epoch as soon as the device holds a key for them: it did
  not hold their identity log when the epoch reached it, or a `leave` of
  theirs has since stopped counting (`Space::added_since_epoch`). An epoch
  with no record there reaches the device now. Its next write starts a new epoch when,
  against the record of the current one, the key of a member who would be
  given the next one has changed, or it has learned that one is frozen;
  when the entries say so (a `leave` the epoch's first entry does not
  descend from, an `add_member` written under another epoch that it does
  not descend from); when the epoch was begun by a member it would leave
  out; or when the current epoch's wraps do not open with this identity's
  own current key. A device that cannot open the current key yet does not
  rotate; it could not tell, and its writes are held to the epoch it
  knows. A reader starts none. An addition made while one is due starts it
  in the same entry.
  - **What one changed key costs.** A device records what *it* holds when
    an epoch reaches it, not what the epoch's writer held. If the writer
    wrapped for a member's new key and this device hears of that key only
    afterwards, it starts another epoch for a change the current one
    already has. Counted in a group of ten with one device each, where
    one member's key changes and every device writes once after it hears
    (`core.rs`, `what_one_changed_key_costs_in_epochs`, ignored): one
    epoch of ten wraps where every device hears before the new epoch
    reaches it; ten epochs, a hundred wraps, where the new epoch reaches
    each device before it hears; and between two and eight epochs, seven
    at the median, over twelve orders drawn at random.
  - **Reading: "descends from the one that started the epoch".** An
    `add_member` in the entry that starts the epoch counts too, since that
    entry wraps the key for whom it adds; so does the genesis for everyone
    it names. Read strictly, a device that joined a new group before it
    held every other member's log would start an epoch for each log as it
    came.
  - **Not written down: "the record says so".** Nothing marks a member
    the record has no key for. Having no key there and no addition since
    the epoch started is the mark.
  - **Spec ambiguity: an `add_member` of someone who was a member
    already.** "A member's `add_member` was written under another epoch,
    and the entry that started the current epoch does not descend from
    it" is true of a second addition of someone the epoch was wrapped
    for, made beside the rotation, though they were given the key. Chose:
    the rule as written, for any valid `add_member` of a member who has
    not left; it costs one epoch.
- **Retention: old versions for a while.** `full` keeps every chunk of
  current state, and also the chunks of deleted files and replaced
  versions for `keep_old` (30 days by default), so they can be restored;
  `history` is `keep_old = forever`, and the placement records 2 then.
  The period counts from when this device first saw a blob stop being
  current (`old-versions.json`), not from entry times, which are other
  devices' clocks. Only objects reachable from an expired blob and from
  no current or kept one are deleted; objects no blob names are left
  alone, and nothing stored or read in the last hour is deleted.
  `cardinal free-space` deletes every old version on this device now.
  Restoring a version first makes sure all of it is on this device,
  fetching what is missing, and refuses when no online device has it.
- **Spec ambiguity: what a local change has "seen".** `state.md` decides
  supersession and delete conflicts by entry ancestry, and an entry's
  parents are normally all current heads. A device that holds an entry
  from elsewhere but has not *shown* it yet (it arrived in the quiet
  period before a commit, or the file had local changes so the mount
  kept the local view) would, by citing every head, claim to have seen
  it: a local edit would silently supersede the remote one, a local
  delete would win over a remote edit. Here such local ops are written in
  an entry whose parents are the latest entries that do not descend from
  the unseen ones (`Space::write_concurrent`), so the result is the
  conflict copy or delete conflict the spec asks for. The spec could say
  that parents are what the author had *seen*, not merely held, and that
  writing with older parents is legitimate (`spaces.md` only notes
  backdating in the context of memberships). When the current epoch began
  after the unseen entry, or a rotation is due, the change is written
  normally instead (an old-epoch entry could expose new content to a
  removed device), with a warning.
- **A file edited here and deleted elsewhere, unseen,** is created again as
  a new node rather than kept as a delete conflict of the old one (as
  before); nothing is lost, but its history starts over.
- **Spec ambiguity: a device that refuses a blob request.** `sync.md`
  lets a device refuse requests over its rate limits but gives no reply for
  "busy", only "not held". The fetcher treats "not held" as "this device
  lacks it" for 30 s and asks the others; a refusal by silence ends in the
  20 s timeout. Suggest a "busy, retry later" item.
- **Choosing which device to ask for blobs** is local policy (`sched.rs`):
  per-device throughput and latency estimates, work in proportion to
  throughput, hedged requests when a device is slow. A hedge makes a
  second device send the same objects; the spec does not limit this.
- **Implementation-specific link service: `speedtest`.** `cardinal
  speedtest` runs over the application service
  `BLAKE3("cardinal-node speedtest 1")` (`speedtest.rs`), which no spec
  defines and other implementations need not offer: round trips, then a
  fixed length of data each way, from memory. It is served only on
  sessions with the person's own devices, one test at a time, for a
  length the serving device sets (it resets a test that runs over), and
  for at most two minutes in any ten; other requests are refused with a
  reply, and devices without the service reset the stream. A link-level
  measurement could instead be a core service, or `ping` frames with
  padding.

## Other people (`spec/contact.md`, `spec/profiles.md#relationship`)

The first step of sharing: two people connect and talk. Much of what the spec
asks for around that is not built yet.

### Read markers are the person's to give (`profiles.md#relationship`)

- **The setting** is a setting node (kind 6) named `read markers`, value
  false when off (`settings.rs`, request `read-markers`). It is off if any
  value of any node of that name says false. Off, no device of the
  person's creates or moves a marker, in a relationship or a group, and
  `mark-read` says why it wrote nothing. Markers written before stay.
- **The private read position** (core 1a6f754): with markers off,
  `mark-read` sets field 6 of the account's node for the space (made if
  there is none) to the last message read, and answers `{marked: false,
  kept, why}`. `unread`, in `conversations` and `groups`, counts from the
  marker and from every value of field 6 together: a message is read if
  either comes after it. A client withdraws a notice when another device
  of the person's moves it, from the `changed` event and the new count.
- The command line has no switch for it yet; clients set it.

### Names and pictures (D71, `profiles.md#account`)

- **An account made before the self node** has none. Until its person sets
  a name (`me` with `name`, `cardinal me NAME`), invitations, the hello,
  introductions and groups suggest the device's configured name, as 0.1.15
  did. Setting it creates the node from whichever device it is set on.
- **Who is named when nobody says.** `setup-finish` without `name`, and
  `cardinal init --yes` without `--name`, name the person after their
  login: the full name `/etc/passwd` gives it, or the login itself, or, with
  neither, the machine's name. `cardinal init` without `--yes` asks. The
  device is named after its machine (`/etc/hostname`, `COMPUTERNAME`), or
  `device` / `--device-name`.
- **Field 12 is recorded when the contact is made**, from the invitation or
  the hello (an introduction's invitation carries the introduced person's
  own name), and is not kept up to date afterwards from what is heard.
  Contacts made by 0.1.15 and earlier have none: they show the petname, or
  the start of the id where it is cleared.
- **A contact made before field 12 was kept** is introduced, and offered to
  a group, under the petname, which began as the name they suggested.
- **A picture is copied whole, not made smaller,** and at most 16 MiB. It is
  encoded with the account space's current epoch key, as an attachment is
  in its space, and the reference is field 11. Each device keeps a copy as
  a file under the data directory (`pictures/<blob id>.<ending by content>`)
  for windows to open, fetching it from the person's other devices in the
  background; the listing gives `picture` only once that file is there. The
  account space's other blobs are not fetched ahead of need. `picture`
  names a file of the one folder, or an absolute path on this device; the
  command line makes a relative path that exists absolute. A picture a
  contact suggests for themselves is not known here (the card is a Basic).
- **Where windows are given a contact's name** they also get `own`,
  `suggested` and `picture`: `contacts`, `conversations`, and contacts among
  `group-members`; `call` and a group's `messages` give `picture`.

- **One call at a time.** A call needs a session with the other person, so
  someone reached through hosts only cannot be called, and a group call
  reaches only the members linked by sessions, through hosts never. A device
  links with every member device it has a session with: the sound settles onto
  two of them per voice, but each link still hears an empty `have` every two
  seconds, which a group of hundreds who all know each other would feel.
  Nothing wakes a sleeping phone: `ring` goes only to devices that are online.
- **Whether a network is metered is known only on Android**
  (`hosts.md#devices-that-help`). Linux takes no network to be metered, so a
  laptop plugged in on a phone's hotspot helps others. On Windows the service
  cannot read the power supply itself: it helps until the window says the
  machine is on battery, and the window cannot tell it about metering.
- **A read marker covers what the device writing it had seen.** `profiles.md`
  says field 1 is the last message read, which is still what is written, but a
  message counts as read if the entry that wrote the marker descends from it. A
  message that arrives in the moment between a client's last look and its
  `mark-read` therefore counts as read.
- **A contact can ring five times in two minutes.** Past that a ring finds this
  person busy, and nothing rings; `profiles.md#calls-guidance` sets no limit. A
  ring from a contact gives way to a call this person makes, and refusing them
  ends it. Two people ringing each other at once each find the other busy.
- **A message can read as `sent` with a very long backlog.** A reconcile that
  stops at its limit of wanted ids still counts as confirming.
- **On Windows the client's pipe trusts whoever holds its name.** Another account
  on the machine could take the name while no daemon runs, and the client would
  talk to it, recovery words included. The cure is a pipe with its own access
  list and a client that checks its owner, which needs a Windows machine to test.
- **Read markers are always written.** `profiles.md` has no setting to keep them
  back, so reading a conversation tells the other person. Messages written
  before 0.1.13 lack the author-owned field, so anyone in the space could change
  those, though no software here offers it.
- **An invitation names the person's own host, which answers it as one of
  their devices.** Invitations are kept in the account space, and every device
  of the person lets their holders in, so the host answers one while the device
  that made it is off, and a restart loses none. `contact.md#accepting` has an
  invitation to a host carry a token and send the invitee on to an inviter
  device through rendezvous. Here the host is an inviter device itself, so the
  invitation names it as one, with no token. With no host, it names the device
  that made it. Join requests, front doors and `for` are not implemented, and
  `uses` is always 1. An invitation lasts 30 days, by the clock of the device
  that made it, which is this software's local policy.
- **An invitation node also says how its user will be regarded**, in fields 6
  and 7 as a contact node does, which `profiles.md#account` does not list.
- **Whoever invites is not asked for a petname.** `contact.md#accepting` has
  each device ask its person. The inviter's device records the name the other
  person gave in `hello`, from their self node, as the petname and as field
  12, and its person can change or clear it afterwards with `contact`. The
  one accepting takes the invitation's suggested name as the petname unless
  they give another (`cardinal accept --name`), so a contact starts with a
  petname of the person's own (`own` true) either way. A new name another contact already has is
  refused, where `contact.md#who-a-person-knows` asks for a warning, because the
  command line finds people by name.
- **Both people must be online to connect.** A device finds a trusted
  contact's devices at addresses it has seen, and through the hosts their reach
  nodes name: every 30 seconds while any device in their log has no session with
  it, and at once, for up to 12 seconds, when a call is made with no session at
  all. A device of theirs that is gone for good keeps this up, at the cost of an
  ask to their host and a word to each of their present devices. A host names at
  most 8 devices, each with its addresses, so a trusted contact's host could aim
  this person's devices at that many places every 30 seconds. Nobody can look
  for someone with no host, so they can be rung only while one of their devices
  holds the session it found, which their devices keep looking for.
- **Spec gap: which identity's log comes first.** `contact.md#accepting` has
  both sides reconcile logs before `genesis`. Here the inviter fetches the
  invitee's log before creating the space, and the invitee fetches the
  inviter's after receiving `genesis`.
- **Spec gap: the conversation is not its creator's alone.** `profiles.md`
  makes messages, reactions and read markers author-owned, but not the
  conversation node, so a contact can delete or move it, which hides every
  message until it is restored.
- **Groups are made with an owner and writers only.** Nothing makes anyone
  an admin or a reader. A group is offered only
  to the creator's or an admin's contacts, since the offer goes in a
  relationship space. Software does not warn when a refused identity is
  added to a group with this person (`contact.md#who-a-person-knows`), and
  members who are nobody's contact here are shown by the name the group
  gives them, with no warning when it matches someone else's. Groups are
  not in the one folder.
- **A profile's members.** The rules judge every space alike, whatever its
  profile: a space offered as a group is taken as it is. One whose genesis
  names no owner is a group nobody can add to and that all its first
  members end together. Only a relationship is checked, by whoever is
  invited into it (`contact.md#accepting`, step 4;
  `Core::accept_relationship`): the genesis is valid by the inviter's log
  and written by the inviter, its profile is the relationship's, it is
  not public, its `add_member` ops are exactly two, one for each of the
  two as a writer, and the space is not held already. Other ops in the
  genesis are not looked at: the conversation is one, and nothing says
  there may be no others. An offer of a group says if the group is
  public (`public` in `groups`, on each group and each offer).
- **Leaving a group** (`spaces.md#members-and-roles`). `group-leave` writes
  `leave`, and in the same entry sets this person's reach node to an empty
  list (`relationship::leave_ops`). From then on the device finds no such
  group and writes nothing in it, and if it is a host it ends the tokens
  its person gave out there. The others show that the member left (`left`
  in `group-members`), send them nothing more of the group, leave them out
  of its calls, and whoever writes next starts a new epoch in that entry,
  not wrapped for them. A reader cannot start one, and waits for a writer.
  - **What the device keeps.** The member's software "keeps or deletes
    what it holds of it as its person chooses". Here it keeps it, and
    nothing asks: it must go on holding the space to learn that it was
    added again, and what it holds stays named, so `cardinal free-space
    --unnamed` leaves it alone.
  - **Added again** (`spaces.md#holding-a-space`, `Judge::accepted`).
    Someone added again is offered the group again, and is in it once
    they write something valid that descends from that addition, once
    more after each time they leave. What another of their devices wrote
    meanwhile, without the addition in its past, accepts nothing.
  - Leaving forgets the answer about hosts: the account's node for the
    group goes, "no hosts here" and "not this host here" with it (D75),
    and an offer always asks where there is a host to name and someone
    who is not a contact. A `leave` whose entry does not empty the reach node is a
    `leave` all the same.
  - A token ended on leaving never comes back. Joining again sets the
    reach node again, with new tokens.
  - Someone who left still asks the others for the group when they meet,
    and is given nothing.
- **Contacts are not told apart from members by more than this device's account
  space.** A device opens a session with a contact's devices only for what they
  share (`spaces.md#holding-a-space`), and notices for a set go only to contacts
  who are entitled to it.
- **Through hosts only works in a relationship space, with hosts that are a
  person's own.** Each person's reach node gives the other a token, and they
  leave entries in each other's mailboxes. An entry too long for an envelope
  goes as a `heads` message, and is fetched from the writer's host. Someone with
  no host of their own cannot be told anything, so every five minutes they fetch
  from the other's host, and what they write that is too long for an envelope
  waits for a connection.
- **Silence is only as good as the carrier.** Over UDP an untrusted device hears
  nothing, as the spec asks. A device also listening on TCP accepts the
  connection before it can stay silent, so TCP shows that something is there,
  though not how anyone is regarded.
- **No introductions keeps someone out of introductions, and nothing more.**
  Contacts do not help each other meet as hosts yet, and no application
  passes things along over several hops, so there is nothing else for it to
  stop. An introduction asked for outside a group waits for the introducer
  to make one by hand; only a group's are made unasked. An introduction's
  invitation names the introduced person's host if they have one, and the
  device that said yes if not, which someone elsewhere cannot reach.
- **Which space is the account** (`profiles.md#account`, `Core::account`).
  The space with the account profile whose genesis this identity wrote,
  that counts, and that names it as owner and nobody else; the files space
  is found the same way where the account does not name one yet. A space
  a contact offers with the account or the relationship profile is still
  fetched and held, as any offered space is until it is opened and its
  profile is known. It is then never shown as an offer, cannot be joined,
  and nothing is written in it; nothing removes it from the disk.
- **Refuse is for contacts.** `member seen` nodes do not exist yet. Nothing
  warns when someone refused is added to a group with this person, except
  where their hosts are named there ([Hosts](#hosts-spechostsmd), "Whoever
  is added later, or refused while there"). A host revokes its tokens for someone
  refused as soon as the account space reaches it, wherever the refusal was
  made, and gives them new ones if it is taken back.
- **A contact can fill a disk.** A device stores an entry before it judges it,
  so a contact, or a host someone fetches from, can send junk that is kept. A
  token holder cannot: a host takes no objects from one, and nor does a device
  from someone using an invitation. The same goes for identity logs, and there
  it costs more: junk in a log travels to its owner and their contacts, and
  evaluating a log is quadratic in what it holds (a minute at 2000 entries).
- **A log can name any link key.** `add_key` proves the signing key and not the
  link key, so a log can list a device it does not hold. It gains nothing: a
  handshake proves the static key and a device proof names the identity, so a
  session is matched to the identity that proved itself, and a key can have
  more than one claimant.
- **A removed device can pass as itself to a stranger.** Each side of an
  invitation checks the other's device against a log that device served, so
  one removed from its identity can show a copy from before.
- **A contact's memory limit is per session.** A session serves 32 of a
  contact's streams at once, each opening with at most 256 KiB, and a
  reconcile learns at most 65,536 ids before fetching them, so one holds a few
  MiB of a device's memory for each stream. Someone can add devices to their
  own identity, and each gets a session.
- **A host counts itself as having fetched nothing.** Taking envelopes in
  records the host as a fetcher that never acknowledges, so acknowledgements
  from the owner's other devices free nothing and retention does. Nothing asks
  a host for envelopes yet except itself, which lets go of them one by one.
## Hosts (`spec/hosts.md`)

- **Only a person's own device is a host.** A device with `cardinal host`
  grants itself to its own identity, the case `hosts.md#grants` calls the
  common one. It holds spaces as any of the person's devices does, under
  their space ids, not random labels, and it can read them. Hosts that
  cannot read what they store are not implemented.
- **A host's mailbox has one quota class, set in the code:** 256 envelopes
  waiting and 1024 deposits a day per token, kept 30 days. A grant has no
  `classes`. `usage` is served and nothing asks for it.
- **A host collects its own mailbox.** It is one of the owner's devices, and
  what it takes in reaches the others by sync, so they do not poll it, which
  costs a device on a metered connection nothing. `fetch` and `ack` are served
  for the day a host is not its owner's, and nothing else uses them yet.
- **An envelope says nothing of who left it, but its session has a key.** A
  depositor sends no device proof, so a host does not learn the identity. It
  does see the device's static key, the same each time, so a host run by
  someone else could link deposits. This matters only once such hosts exist.
- **Tokens do not rotate with epochs.** A device removed from one person keeps
  the other's token, until that person refuses and restores them. A deposit is
  bounded by the token's quota, and it can open nothing.
- **Someone with no host cannot pass on a log or a new epoch** to someone
  through hosts only: neither fits a mailbox, and there is no host to fetch them
  from. What they write after adding or removing a device waits for a connection.
- **A session opened with a token is limited in the code:** four at a time for
  one token, eight streams each, and 256 KiB for a sync message, since a holder
  can make keys and streams without limit. An envelope that cannot be opened yet
  waits, one at a time and up to the token's quota, and the host fetches what it
  needs at most once a minute.
- **Whether a reach node names its person's hosts** (D68, D75,
  `hosts.md#telling-others-where-to-reach-you`, `core.rs` `Telling`,
  `mailbox.rs` `write_reach`, `say_reach`, `share_reach`,
  `take_out_host`, `groups.rs`, `account.rs` `hosts_no`). To everyone
  else the list is the answer; the person's own devices also read the
  account: kind 2 field 5, "no hosts here", and kind 14, "not this host
  here", under the space's node.
  - **The person's no** (`contact NAME no-hosts`, `group-reach` with
    `share` false, `group-join` with `reach` false, or joining with a
    host and no yes) is noted on the device (`pending-no.json` beside
    the mailbox), then recorded in the account, then the empty list
    written, and the note taken out. A write that fails, or a crash,
    leaves the note, and the next look finishes the no. Where the
    account has no node for the space (a relationship or group, which
    this version did not give one before) one is made, named after the
    contact or the group.
  - **The person's yes** (`contact NAME name-hosts`, `group-reach` with
    `share` true, `group-join` with a yes) takes out "no hosts here" and
    every "not this host here" for the space, then names every host it
    can. Reading: a yes names all the person's hosts, so it clears the
    record for all of them, those it cannot reach now included.
  - **Taking one host out by hand** (`contact NAME no-host DEVICE`,
    `group-reach` with `share` false and `host`; `cardinal group reach G
    keep --host DEVICE`) records "not this host here" for its static key
    and writes the list without it. A list left empty that way is not a
    no: the person's other hosts still name themselves there.
  - **Reading: a record in conflict.** "No hosts here" counts if any
    value of field 5 on any node for the space is true: a no is never
    overridden. A yes clears the field on every node.
  - **Unasked, a host names itself** where the person is in the space,
    every other member is a contact (a trusted one, for a device that
    named itself, D72), and the account says neither "no hosts here" nor
    "not this host here" for it: in a relationship or a group alike, and
    to an empty list too. A list never set is the joining, and names
    every host of theirs not recorded as a no. No device adds another to
    a list already set.
  - **The list says which record it rests on** (not in the text). The
    list a no writes, and the one taking a host out writes, carry beside
    them in the reach node an extension field `no-record` (key: the
    first 7 bytes of the name, `evolution.md#fields-in-a-base-node`),
    `{1: the id of the account entry that records the no}`. A host names
    itself to a list that is set only once its account holds every entry
    that field names; then it goes by the record. The two are in two
    spaces and may arrive in either order, through different devices: a
    host that had the list and not the record would otherwise fill in a
    no, for good. A list emptied with no such field (by mistake, or
    before this) is filled at once. The field names an account entry to
    every member, which says nothing of what is in it. **Spec question:**
    should the spec carry this, or tie the list to the record otherwise?
  - **A `set` key wider than 32 bits** was written cut down to 32 bits by
    `SpaceOp::set`, which an extension's key (56 bits) is. It is written
    whole now.
  - **A device writes the list when it has something to say.** Joining
    with nothing to name, on meeting, at a look, or by `group-join`, writes
    nothing in the space at all (Daniel: "a device writes when it has
    something useful to say"). A group joined so is kept as joined in
    the account: a space node for it that is not a decline
    (`Core::is_joined`), until the person writes there, which accepts it
    as before. Leaving deletes that node, and with it any "no hosts here"
    and "not this host here", so an offer made again asks afresh.
    `profiles.md#group` still says joining "sets their reach node, which
    is the first entry of theirs"; that line is to be fixed in core. A
    yes by hand with no host reachable is kept on the device as before,
    against the list as it is, unset or not, and writes nothing.
  - **Lists emptied before D75** have no record, so a host fills them in.
    A no said with 0.1.17 or earlier is not kept: say it again. There
    are no users whose data that touches: 0.1.13 made older data
    unreadable, and the field 5 that versions before D68 wrote (their
    yes as true) is from before that.
  - **What `groups` gives** in `reach` also has `said_no`.
- **`conversations` gives `reach` for each person** too, shaped as a
  group's: `shared`, `waiting`, `said_no`, and `named`, the hosts the
  relationship's list names by the device names `no-host` takes (or the
  start of the key in hex, for a host that is no longer the person's).
- **`nearby`** in `conversations` and `contacts` (D74): a session with
  one of their devices that is direct and whose address is on the local
  link, now. Never from a tag.
  - **On its own, a device changes only its own entry** (D70,
    `mailbox.rs` `keep_own_entry`, `Core::own_entry_due`): a host sets a
    token where the one its entry has is not active, and changed
    addresses; a device that is a host no longer takes itself out, when
    `host --off` is said on it and at every look after. Nothing takes out
    another device's entry, and nothing writes only to make two lists
    one: `former_hosts`, `reach_due`, `reach_settled` and
    `reach_is_settled` are gone. Whoever writes starts from the list as
    read, each host once, the others unchanged.
  - **Reading: one host in two lists** (`relationship::reach_of`). A host
    is told by its static key. Named in both lists, or twice in one, it is
    read once, where it first stands reading the later list first, with
    the endpoints and token it has there. The text says a host named in
    both "is one host" and not which entry is read.
  - **Not quite "unchanged".** What a device writes of another's entry
    is the endpoints, the key, the token and any other fields as it read
    them (D74). A host whose endpoint list holds something that is no
    record, or whose key or token is not of its length, is not read and
    so not written again.
  - **Reading: every token serves** (`Core::space_of_token`,
    `Core::tokens_given`, `relationship::reach_ever`). The space of a
    token is looked for in the list as read and then in every value the
    person ever set there, so what is left under a token the list names
    no longer is opened. A no, leaving, and refusing a contact revoke
    every token this host ever gave in that space, whether hosting is on
    at that moment or not. A host that needs a token for a space gives
    one it gave there before that is still active, and makes a new one
    only if none is.
  - **Reading: "takes itself out when it stops serving"** is done when
    both the device's own setting and its own account say it is no host;
    while only one does (the moment `host` or `host --off` is being
    carried out) it waits. A device whose grant another device removed,
    and whose own setting still says host, keeps its entry: nothing here
    lets one device stop another being a host.
  - **Reading: a yes to two lists.** `group-reach` with `share` true where
    the node holds two lists writes the list as read, once, even with no
    host to add: the text has them become one when "the person says yes
    or no".
  - **A write decided before a wait is looked at again** (`mailbox.rs`
    `Decided`, `set_as_decided`; not in the text). What software sets on
    its own is decided, then a token is registered, which may wait on
    another device, then the list is written. If the entries that set the
    list, or anything `Telling` reads, changed meanwhile, nothing is
    written, the token is revoked, and the next look decides afresh. The
    person's own act (`group-join`, `group-reach`) is not checked this
    way: it is the later act.
  - **A write of the list that fails** (a log that cannot be written, a
    space that has ended) revokes the tokens registered for it and is put
    off for that space: a minute, doubling to an hour, until one works.
    Not saved: a restart tries again at once.
  - **Reading: `ask` once joined.** A list that is set, empty or not, is
    the person's answer, so `ask` is true only for an offer, or where they
    are in the space and never set it. A person who takes up a host later
    is not asked by `groups`: the client asks once, when the host is set
    up (`clients.md`), and `group-reach` is the answer.
  - **A yes that cannot be finished** (`core.rs` `KeptYes`,
    `kept-yes.json` beside the space's entries): kept where `group-join`
    shares, or `group-reach` or `name-hosts` says yes, and no host can be
    reached for a token. Whoever made a group among contacts keeps none:
    their hosts name themselves there once they can (D75). It holds
    the entries whose lists the reach node held then, and stands while
    the node holds exactly those. `write_reach` names the hosts once a
    token is registered. `groups` gives `reach.waiting` too, so that a
    window can still say so after a restart; `apps.md` gives it only in
    the replies.
  - **Reading: so that a no can be later than a kept yes,** a no writes
    an empty list even where the list is empty already. Without that
    entry a yes kept on another device would be finished after the person
    said no.
  - **Whoever is added while a yes waits** is told of when it is finished
    (R6): the kept yes notes the additions that counted when it was kept,
    and anyone added since who is not a contact goes in `reach.added`,
    though the entry that names the host has their addition in its past.
    A note kept by 0.1.13 has no such list and is finished as before.
  - **A yes kept for a host that then stops serving** is given up.
- **Whoever is added later** (D69, `hosts.md`, "A yes is to the space, and
  to whoever it comes to hold"). Where this person's reach node names their
  hosts, `groups` names in `reach.added` each member who is not their
  contact, came while the hosts were named, and of whom this device has
  not told them; `cardinal groups` says who can see what, and how to stop.
  Nothing waits for it: the list is kept current all the while.
  `group-reach`, with `share` true or false, notes everyone added so far
  as told of on this device, and with `share` true and nothing to add to
  the list writes nothing in the group.
  - **The note** is `arrivals.json` beside the space's entries
    (`core.rs` `Arrivals`), per device, never synced. A device set up
    later, or one whose note is lost, tells of everyone who came while the
    hosts were named.
  - **Reading: who is a contact** is judged when the device first sees the
    addition with the hosts named. Someone who was a contact then and is
    refused later is not told of as added.
  - **Refusing someone** is asked about as part of refusing and is not
    tracked: `contact` with `setting` `refuse` answers with `reach`, the
    groups that person is in where this person's hosts are named, each
    with `group`, `name` and `what`. `cardinal contact NAME refuse` prints
    them. Only the device refused on asks. The relationship with the person
    refused is not among them, and its reach node is not kept current
    while they are refused.
  - **Spec gap: only groups have a way to be told or to answer.** Any
    other space shared with someone who is not a contact is not something
    this build makes.
- **A device that can be reached names itself** (D72,
  `hosts.md#a-device-that-can-be-reached-names-itself`, `outside.rs`).
  - **Only the router's address counts as outside.** The address a
    router gives by PCP, NAT-PMP or UPnP is named; a forwarded port or a
    public address is named only by `cardinal host --address`, which makes
    an explicit host, whose endpoints stay what the person gave and to
    which none of this applies. Addresses on the device's own interfaces
    are not looked at: a global IPv6 address behind a firewall would name
    a device nobody reaches.
  - **Turned off** stops asking the router, gives the port back, and the
    device takes itself out. Two switches (D76): `cardinal router off`
    (`router` with `on` false) writes a setting node (kind 6, name `ask
    routers`, value false) in the account, for every device of the
    person's; `cardinal router off --this-device` (`this_device` true)
    sets this device's `port_mapping`. Asking needs both on. **Reading:**
    the text's "each device has its own setting ... and one switch turns
    off asking any router" is read as one switch for all the person's
    devices; a setting that any value says false is off. `router on`
    turns the account's switch on and this device's too. There is no
    separate switch for asking without naming. `cardinal host --off`
    also forgets what the device named itself at, so it names itself
    again only from the next address, and only where every other member
    is trusted.
  - **Only on the person's networks** (D76, `networks.rs`). A network is
    its default gateway's hardware address, read from `/proc/net/route`
    and `/proc/net/arp`; where the neighbour table has no complete entry
    yet, one empty datagram to the gateway's discard port (9) makes one,
    and nothing is asked of the router. The account keeps a network node
    (kind 15): field 1 the six bytes of the address, field 2 mine, field
    3 the name the person gave (`--name`), else none.
    - **Reading: two answers at once** for one network, a yes and a no,
      are a no, as no is the default. A network with no node is not
      answered, which is a no too.
    - **Where the router cannot be told** (no default route, or a system
      that does not say which is the gateway: Windows, Android), no
      network can be marked, so no router is asked there, ever (Daniel,
      2026-11-21). Before D76 UPnP found one by itself on such systems.
      Where no complete neighbour entry is there, an empty datagram to
      the gateway's port 9 is sent, and the table read again, three
      times, waiting longer each time.
    - **A network is its gateway's hardware address alone** (Daniel,
      2026-11-21). One that copies it passes for the person's network:
      the device asks that router for a port and names the address it
      gives, so the person's trusted contacts dial an address the copier
      holds. That gains metadata (their addresses as they dial), and no
      more: the session proves the device's key. Accepted.
    - **The switches are looked at every second** by the port-mapping
      loop, which runs as long as the service does: turned off on another
      device, it gives its port back; turned on there, it asks again.
    - **Off the person's networks** the device asks nothing and sends the
      router nothing. A mapping it held on its own network is let go
      without a word (it lapses at the old router), the addresses it named
      stay named, and it names no new one. The loop looks every second for
      another network, or a mark, and asks at once on one marked as theirs.
    - **For clients**: `status` and `network` give `network`: `known`,
      `router`, `name`, `answered`, `mine`, `ask` (a known network not
      answered for, on a device whose switches are on: show the quiet
      "Is this your network?") and `routers`. `network` with `mine` true
      or false (and `name`) answers for the network the device is on now.
      `router` in `status` gives `this_device`, `everywhere` and `network`
      too.
    - **Tests** name the router's address with
      `CARDINAL_TEST_ROUTER_MAC` (or `none`), beside
      `CARDINAL_TEST_GATEWAY`.
  - **Told apart by what it serves.** Its grant offers mailbox,
    rendezvous and relay, and no storage; an explicit host's always
    offers storage. Every device of the person reads it that way, since
    the format has nothing else to say it: a grant without storage is
    named unasked only among trusted contacts, by whichever device sets
    the list. It is not on the recovery sheet. Its mailbox has the one
    quota class there is (above), not a smaller one.
  - **"Never where its person said no"** (D75) is the account's record:
    a device that named itself adds itself unasked wherever every other
    member is trusted and the record says no no, to an empty list too.
  - **When it takes itself out** of a list it leaves empty, that is no
    no: named again, it names itself there again.
  - **The month is kept on the device** (`outside.json`): the addresses it
    names and when each was last its own, saved at most hourly.
  - **Not in the text: an address is named only once it has held, and
    seldom.** The router must have given it for ten minutes, and after
    the first, at most one new address is named a day (the newest waits
    till then). A device on the network answering as a router, or a
    router giving a new address at each short renewal, would otherwise
    have it write in the account and in every space where it is named,
    every renewal, and send trusted contacts to addresses it chose.
    Where the gateway is known, UPnP is taken only from it; where it is
    not (Windows, Android), from the first device to answer, and only
    the hold and the day bound what that can do. What a router says of
    its own address outside is believed.
  - **Not in the text: where a member stops being trusted,** a device that
    named itself gives that space no new address or token: where it
    would, it takes itself out instead. While nothing changes its entry
    stays, as the person's agreement does.
  - **A mapping where another of the person's devices is reached** (a
    host's grant endpoints, or an address in the peer book) is given back
    with lifetime 0, and one other port outside is asked for, the same
    each time for a device and port; if that clashes too, there is no
    mapping, and status says why.
  - **The outside address an own device presents** is kept in the peer
    book after the address it was last reached at.
  - **Deposited reach nodes.** Nothing here deposits the reach node for a
    new address on its own: the entry that writes it goes to contacts'
    mailboxes as every entry does.
- **An endpoint this version cannot use** (D68, `hosts.md#grants`,
  `grant.rs` `Endpoint`, contact `EndpointAddr`) is held as the record it
  came in and written again as it is. An entry of an endpoint list that is
  no record is dropped, which the text does not speak of.
  - **A host name is kept and shown, and never dialled** from a grant or a
    reach list: only `cardinal restore` resolves one.
- **A new host does not tell contacts it is there** unless a mailbox of theirs
  can carry the reach node. Someone through hosts only who had no host when
  they were invited stays out of reach of the other until then.
- **Join requests are not implemented**, so an invitation still needs its
  inviter online.
- **Rendezvous and relay with a token are a host's, for its own person.**
  Every device of a person offers both to the others, host or not, as D49 has
  it, and a host serves trusted contacts with the token their reach node gives.
  Trusted contacts are not hosts for each other: there are no grants to another
  identity.
- **Rendezvous and relay answer with codes the spec does not list.**
  `hosts.md#service-messages` has 1 not permitted, 2 full, 3 unknown and 4
  malformed. Here 4 means a device that is not present, and 5 one that will
  not relay (on battery) or a token holder asking again within a second, and a
  request missing a field is answered 3.
- **A token's relay counts nothing.** There is one quota class, so relayed bytes
  count against no limit. What bounds a holder is the four sessions a token may
  hold, and a device's agreement.
- **A trusted contact may use a token on the session it has.** The link keeps
  one session between two devices, so a contact connected to the host directly
  asks there, with the token in the request, instead of opening another.
- **Which devices refuse to relay.** `hosts.md#help-from-a-persons-own-devices`
  asks a device on battery or a metered connection to. Here one on battery
  does. Nothing here can tell that a connection is metered.
- **One path at a time.** A relay is meant to be another path of a session,
  abandoned when a direct one validates. Here a direct session replaces the
  relayed one, which `link.md#identity-binding` allows, and a device looks for
  one once a minute.
- **A host's address must be a literal to be used day to day.** Devices dial
  the addresses in a grant, but never a name in one: names are for the
  recovery sheet. A device that reaches none of its own devices, because they
  have all moved, waits to meet one on a local network.
- **Storage ops.** Only `prove` (op 5). `drop`, `list`, `allow` and `public`
  are answered with error 3, unknown.
- **Restore step 5 differs.** A restoring device does not list labels and
  open sets itself. Once it has added itself to the log it reconnects as one
  of the person's devices, and the host's ordinary sync brings every set.
  That needs a host that is one of those devices.
- **A session that proves the root key** may sync only the identity log,
  though `hosts.md#restore` calls it an owner session: that is all the steps
  need, until the device reconnects as itself.
- **Reading: a failed `prove`** is answered with error 1, not permitted, and
  the session stays open until `PROVE_WITHIN` (30 seconds) passes. Any other
  request before a proof closes it, as the spec says.
- **Spec ambiguity: a grant with no limit.** `hosts.md#grants` does not say
  how to state one. Chose 0 storage bytes and 0 days of retention, for a
  person's own device, which keeps what it holds.
- **Spec ambiguity: how the sheet writes a host's key.** It says only "the
  address and static key". Chose lower-case Crockford base 32 of the 32-byte
  X25519 key and the first 3 bytes of its BLAKE3 hash, in groups of 4, so
  that a mistyped key is caught at once instead of looking like a host that
  is down. Reading ignores case and separators, and takes `o` as 0 and `i`
  and `l` as 1.

## Counting copies (`spec/blobs.md#counting-copies`)

- **Spec ambiguity: which devices "should keep" a space.** Chosen:
  devices in effect in the identity log whose placement (account kind 7)
  under the files space's node says retention 0 (full) or 2 (history),
  plus this device when its own setting is full. Placements are written
  at `init` and when a device joins, and now also updated when a device's
  retention changes (`cardinal retention`, or `config.toml` at the next
  start); a device running 0.1.3 or earlier may still show the retention
  it had when it was set up. Host grants are not counted yet.
- **Spec ambiguity: what checks sample, and from when.** "Chunks chosen
  at random from those the holder should keep": chosen from the blobs of
  the current state (every version of a file in conflict), weighted by
  size, then down the indexes this device holds in proportion to the
  bytes beneath, sometimes stopping at an index (indexes are kept too),
  else the top id. All current content is sampled, whatever its age.
- **Reading: "once the checker has had it for a while".** A piece is old
  when this device first saw its blob more than an hour ago: first seen
  is the birth time of the top object in the store (its modification
  time where the file system has no birth time; reads touch that, which
  only delays it), or when this run first saw the reference. The age is
  the blob's, not the chunk's: a chunk an old file and a new file share
  is old if either is. So the count is still of copies of everything
  older than an hour, and status says so.
- **Reading: what a check comes to.** A piece that comes back and hashes
  to its id counts for the holder at any age. One "not held" counts
  against it only if it is old; one that does not hash to its id always
  does. With nothing against it, a check passes if every old piece asked
  for came, or, where none asked for was old, if every piece came.
  Otherwise it is neither a pass nor a failure: the holder lacks only
  what is new, and stands as it stood. The text does not say what a
  check of new pieces alone, some of them not held, comes to.
- **Reading: "still copying" and "missing pieces".** `state` is `copying`
  for a holder that has answered a check and never passed one, whether
  its last check found old pieces missing, damaged ones, or only new
  ones not there yet; `missing` for one that passed and whose last check
  then found pieces missing or damaged. `failed` is now only a holder
  that left two checks in a row unanswered, which the text keeps apart
  ("better asked again than failed at once"), and `unchecked` one that
  has answered none. This device says the same of itself.
- **Readings: failing, "recently".** A check with no answer
  (timed out; a closed session is not a check) fails only when it is
  the second in a row: the spec suggests asking again rather than
  failing at once, and leaves how often to each device. A passed check
  counts for 7 days while the holder is not checked again (an offline
  laptop), and status gives its time. Results are persisted
  (`copies.json`), so a restart neither drops offline holders nor shows
  them as unchecked.
- **Only the files space.** Checks sample it alone: what its folder
  shows, and whatever else its current state references. Checks ask for chunks and indexes only: content under
  1 KiB lives in entries, which every device holds.
