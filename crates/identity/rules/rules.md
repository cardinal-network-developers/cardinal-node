# Authority rules

Status: draft. **Normative.** These rules define which identity entries and
which space entries are valid, which keys are in effect, who is a member of
a space, which space succeeds it, and when an identity is frozen.
[identity.md](../spec/identity.md) and [spaces.md](../spec/spaces.md)
explain them in prose; where the prose and these rules disagree, these rules
win.

They are written as a small logic program, so that two properties can be
checked by machine instead of argued:

- **A unique answer.** The program is *stratified*: it is divided into
  layers, each layer only adds facts, and a rule may say "not" only about
  facts from an earlier layer. A stratified program has exactly one result
  for any set of entries, whatever order they arrived in. The checker in
  [check.py](check.py) verifies this for the rules below.
- **No hidden clock.** The inputs are facts about entries and nothing else.
  No input depends on when or in what order a device received anything.

## Notation

A rule `head :- a, b, not c.` means: `head` holds whenever `a` and `b` hold
and `c` does not. Names starting with a capital letter are variables.
`count{G : p(G), q(G)} >= T` counts the distinct `G` for which the listed
facts hold. `X != Y` and `P < 3` compare values. `%` starts a comment.

`@input` lists the facts computed directly from entries (defined in the
tables below). `@stratum` starts a layer. A predicate is defined in exactly
one layer. Positive uses may refer to the same or earlier layers; `not` and
`count` only to earlier ones.

The reference implementation is [datalog.py](datalog.py) (about 300 lines)
and the inputs are computed by [world.py](world.py).

## Identity logs

### Inputs

All facts are about the entries of one identity log, except `confirm_ok`,
which comes from guardians' logs.

| Fact | Meaning |
|---|---|
| `entry(E)`, `genesis(E)` | E is an entry of the log; E is its genesis |
| `anc(A,B)`, `ae(A,B)` | A is an ancestor of B; A is B or an ancestor of B |
| `conc(A,B)` | A and B are concurrent |
| `later(A,B)` | B comes after A in log order |
| `signer(E,K)` | E is signed by key K. An entry has one signer: its id covers it ([encoding.md](../spec/encoding.md#signed-objects)) |
| `add(E,K,P)` | E contains `add_key` of K with power P (1 device, 2 admin, 3 root) |
| `readd(E)` | E contains `add_key` of a key already named in E's causal past, by an `add_key` or as a recovery's new root |
| `rem(E,K)` | E contains `remove_key` of K |
| `selfrep(E,R,N)`, `is_selfrep(E)` | E is a root replacement: signed by R, its ops are exactly `add_key` of root N and `remove_key` of R, and at most one `set_protocol` |
| `badops(E,P)` | E contains an op that a key of power P may not perform ([table](../spec/identity.md#operations)), adds a key at a power above P or a root, contains `readd`, is a decision, or uses an [extension](../spec/evolution.md) that no protocol record in its causal past or in E declares (extensions marked critical, and `set_protocol`, need admin power). A record in E's past declares only where its entry is valid and signed by an admin or root key: whether it is turns on the records before it, so the log is evaluated again with the records found to count until that holds of what is found (`evaluate_identity`). Whether a removal goes down in power is decided by the rules (`bad`) |
| `policy(E)` | E carries `set_recovery` |
| `change(D,P)` | D is a `set_recovery` after genesis, naming P as the policy it changes |
| `guardian(P,G)`, `threshold(P,T)`, `unguarded(P)` | the guardians and threshold of policy P; P names no guardians. The log holds [commitments](../spec/identity.md#hidden-guardians); a verifier learns G when G's confirmation reveals the salt, and a confirmation that does not open a commitment counts for nothing, so the model names guardians directly |
| `majority(P)`, `bad_policy(P)` | P names guardians and its threshold is more than half of them and no more than all; P names guardians and its threshold is not |
| `ctrl(P,R)` | P names no guardians and R controls it: the genesis root for the genesis policy, otherwise field 8 |
| `recover(D,N,P)`, `keeps(D,K)` | D is a `recover` naming new root N under policy P; it keeps key K |
| `bad_decision(D)` | D is a decision after genesis that is not alone in its entry, or a `recover` naming a key already named in its causal past |
| `confirm_ok(G,D)` | guardian G has a valid confirmation of decision D (below) |
| `sek(E)` | E contains `set_encryption_key` |

**Confirmations.** A confirmation is an entry in the *guardian's own*
identity log. `confirm_ok(G,D)` holds if some entry `C` of G's log names
`D`, and `C` is valid and G is not frozen when G's log is evaluated over
`C`'s causal past. That past is strictly smaller than the set being
evaluated, so this recursion always ends, even when two people guard each
other. A confirmation is judged as of when it was made, and nothing later
in the guardian's log changes it: not a removal of the confirming key, and
not the guardian being frozen. Votes are counted per guardian, not per key.

### Rules

```datalog
@program identity

@input entry/1 genesis/1 anc/2 ae/2 conc/2 later/2 signer/2
@input add/3 readd/1 rem/2 selfrep/3 is_selfrep/1 badops/2
@input policy/1 change/2 guardian/2 threshold/2 unguarded/1 majority/1 bad_policy/1 ctrl/2
@input recover/3 keeps/2 bad_decision/1 confirm_ok/2 sek/1

% ---- Layer 1: shapes. Facts read straight off the entries.
@stratum shape
power0(K,P) :- add(E,K,P), not readd(E).
power0(N,3) :- recover(D,N,P).
ambiguous(K) :- power0(K,P1), power0(K,P2), P1 != P2.
under(D,P) :- change(D,P).
under(D,P) :- recover(D,N,P).
replaced0(R,X) :- selfrep(Y,R,N), anc(Y,X).
root_add_entry(R,G) :- genesis(G), add(G,R,3).
root_add_entry(N,Y) :- selfrep(Y,R,N).
root_add_entry(N,D) :- recover(D,N,P).
% who may change a policy that names no guardians: the root it names as
% controller, and each root that replaced that one in turn
croot(P,R,X) :- ctrl(P,R), ae(P,X).
croot(P,N,X) :- selfrep(Y,R,N), croot(P,R,Y), anc(Y,X).
named_in(K,X) :- add(E,K,Q), ae(E,X).
named_in(N,X) :- recover(D,N,P), ae(D,X).
rem_in(K,X) :- rem(Y,K), anc(Y,X).

% ---- Layer 2: votes. Powers, who signed what, how many guardians agreed.
@stratum votes
kpow(K,P) :- power0(K,P), not ambiguous(K).
kept_key(D,K) :- keeps(D,K), kpow(K,P), P < 3.
bad(X,P) :- badops(X,P).
% removals go strictly down
bad(X,3) :- rem(X,K), kpow(K,3), not is_selfrep(X).
bad(X,2) :- rem(X,K), kpow(K,Q), Q >= 2.
votes(D) :- under(D,P), majority(P), threshold(P,T),
            count{G : guardian(P,G), confirm_ok(G,D)} >= T.
signer_ok(D) :- recover(D,N,P), signer(D,N).
signer_ok(D) :- change(D,P), majority(P), signer(D,K), named_in(K,D), not rem_in(K,D),
                not replaced0(K,D).
signer_ok(D) :- change(D,P), unguarded(P), signer(D,R), croot(P,R,D), not replaced0(R,D).
approved(D) :- votes(D).
approved(D) :- change(D,P), unguarded(P).

% ---- Layer 3: guardian decisions in effect.
@stratum decisions
live(P) :- genesis(P), policy(P), not bad_policy(P).
live(D) :- change(D,P), in_effect(D).
in_effect(D) :- under(D,P), live(P), anc(P,D), signer_ok(D), approved(D),
                not bad_decision(D), not bad_policy(D).
replaced_policy(P) :- change(S,P), in_effect(S).

% ---- Layer 4: evidence that guardians decided both ways.
@stratum taint
tainted(D1) :- in_effect(D1), in_effect(D2), under(D1,P), under(D2,P), conc(D1,D2).
tainted(D) :- in_effect(S), change(S,P), in_effect(D), under(D,P), anc(S,D).
chg_in(P,Y) :- change(S,P), in_effect(S), ae(S,Y).

% ---- Layer 5: what recoveries remove. A tainted decision stays in effect,
% and freezes the identity, but is not applied.
@stratum recovery
applied(D) :- in_effect(D), not tainted(D).
rec_removes(D,K) :- applied(D), recover(D,N,P), add(E,K,Q), ae(E,D), K != N,
                    not kept_key(D,K).
rec_removes(D,K) :- applied(D), recover(D,N,P), recover(D0,K,P0), applied(D0),
                    anc(D0,D), K != N.
kept_over(Y,K) :- rem(Y,K), kept_key(D,K), applied(D), ae(Y,D).
% a recovery keeps keys, not work done without knowledge of it
rec_conc(X) :- applied(D), recover(D,N,P), conc(X,D).
gone3(R,X) :- replaced0(R,X).
gone3(K,X) :- rec_removes(D,K), anc(D,X).
revoked3(X) :- signer(X,K), rec_removes(D,K), not ae(X,D).
revoked3(X) :- signer(X,R), selfrep(Y,R,N), Y != X, not ae(X,Y), not is_selfrep(X).

% ---- Layer 6: roots.
@stratum roots
root_in(R,X) :- genesis(G), add(G,R,3), anc(G,X), not bad_policy(G).
root_in(N,X) :- selfrep(Y,R,N), valid3(Y), anc(Y,X).
root_in(N,X) :- recover(D,N,P), applied(D), anc(D,X).
valid3(G) :- genesis(G), not bad_policy(G).
valid3(X) :- signer(X,R), kpow(R,3), root_in(R,X), not gone3(R,X), not revoked3(X),
             not rec_conc(X), not bad(X,3).
root_added(R) :- genesis(G), add(G,R,3), not bad_policy(G).
root_added(N) :- selfrep(Y,R,N), valid3(Y).
root_added(N) :- recover(D,N,P), applied(D).
root_removed(R) :- selfrep(Y,R,N), valid3(Y).
root_removed(K) :- rec_removes(D,K), kpow(K,3).

% ---- Layer 7: contests. More than one root is in effect.
@stratum contest
root_eff(R) :- root_added(R), not root_removed(R).
contested :- root_eff(R1), root_eff(R2), R1 != R2.
% while contested, the contestants' ops other than root replacements wait
suspended(X) :- contested, signer(X,R), root_eff(R), not is_selfrep(X).
after_fork(E) :- sek(E), contested, root_eff(R), root_add_entry(R,Y), not ae(E,Y).

% ---- Layer 8: root ops in effect, and admin removals.
@stratum rootops
rop(X) :- valid3(X), not suspended(X).
adm_rm(K,Y) :- rem(Y,K), kpow(K,2), rop(Y), not kept_over(Y,K).
adm_rm(K,D) :- rec_removes(D,K), kpow(K,2).
gone2(K,X) :- adm_rm(K,Y), anc(Y,X).
revoked2(X) :- signer(X,K), adm_rm(K,Y), not ae(X,Y).

% ---- Layer 9: admins.
@stratum admins
adm_in(K,X) :- add(E,K,2), rop(E), anc(E,X).
adm_in(K,X) :- add(E,K,2), valid2(E), anc(E,X).
adm_in(K,X) :- kept_key(D,K), applied(D), kpow(K,2), anc(D,X).
valid2(X) :- signer(X,K), kpow(K,2), adm_in(K,X), not gone2(K,X), not revoked2(X),
             not rec_conc(X), not bad(X,2).

% ---- Layer 10: device removals.
@stratum device_removals
dev_rm(K,Y) :- rem(Y,K), kpow(K,1), rop(Y), not kept_over(Y,K).
dev_rm(K,Y) :- rem(Y,K), kpow(K,1), valid2(Y), not kept_over(Y,K).
dev_rm(K,D) :- rec_removes(D,K), kpow(K,1).
gone1(K,X) :- dev_rm(K,Y), anc(Y,X).
revoked1(X) :- signer(X,K), dev_rm(K,Y), not ae(X,Y).

% ---- Layer 11: devices.
@stratum devices
dev_in(K,X) :- add(E,K,1), rop(E), anc(E,X).
dev_in(K,X) :- add(E,K,1), valid2(E), anc(E,X).
dev_in(K,X) :- kept_key(D,K), applied(D), kpow(K,1), anc(D,X).
valid1(X) :- signer(X,K), kpow(K,1), dev_in(K,X), not gone1(K,X), not revoked1(X),
             not rec_conc(X), not bad(X,1).

% ---- Layer 12: keys, policies, freezing.
@stratum keys
valid(X) :- rop(X).
valid(X) :- valid2(X).
valid(X) :- valid1(X).
key_added(K,E) :- add(E,K,P), kpow(K,P), P < 3, rop(E).
key_added(K,E) :- add(E,K,P), kpow(K,P), P < 3, valid2(E).
key_added(K,D) :- kept_key(D,K), applied(D).
removal(K,Y) :- adm_rm(K,Y).
removal(K,Y) :- dev_rm(K,Y).
removed(K) :- removal(K,Y).
removed_at(K,H) :- removal(K,Y), ae(Y,H).
current_policy(P) :- live(P), not replaced_policy(P).
% F1: guardians who decided both ways
frozen :- tainted(D).
% F2: a root contest that no guardians can settle: the controller of a policy
% naming no guardians replaced itself twice, concurrently, and on both sides
% that policy was still in effect
frozen :- live(P), unguarded(P), selfrep(Y1,R,N1), selfrep(Y2,R,N2), conc(Y1,Y2),
          croot(P,R,Y1), croot(P,R,Y2), not chg_in(P,Y1), not chg_in(P,Y2).
sek_ok(E) :- sek(E), valid(E), not after_fork(E).
newer_key(E) :- sek_ok(E), sek_ok(E2), later(E,E2).

% ---- Layer 13: results.
@stratum outcome
effective(K) :- key_added(K,E), not removed(K).
effective_at(K,H) :- key_added(K,E), ae(E,H), not removed_at(K,H).
current_key(E) :- sek_ok(E), not newer_key(E).
```

### Reading the rules

- **Layers follow authority.** Powers and guardians' decisions (layers 1–3)
  depend only on guardians' confirmations and on the shape of entries.
  Evidence that guardians decided both ways (4) depends on decisions. Roots
  (6) depend on decisions. Admins (9) depend on roots. Devices (11) depend
  on admins. A key's entries are invalidated only by a removal from a
  strictly higher layer, so nothing can loop.
- **Powers** (`kpow`): a key's power is the one its first `add_key` gives
  it. An `add_key` of a key already named in its causal past is invalid
  (`readd`), and a key first named at two powers concurrently never counts
  (`ambiguous`). Removals must go strictly down (`bad`); a root replacing
  itself is the one exception.
- **Revocation** (`revoked1`–`revoked3`): an entry by a removed key is valid
  only if it is an ancestor of the removal. Entries descending from the
  removal fail authorization (`gone`). Backdating gains nothing.
- **Recoveries** remove every key added in their causal past that they do
  not keep, and every earlier recovery's root. Every entry concurrent with a
  recovery that is applied is invalid, whoever signed it: a recovery keeps
  keys, not work done without knowledge of it. A kept key's earlier removal,
  in the recovery's past, no longer counts (`kept_over`). Later removals
  apply normally.
- **Policies without guardians** are changed by their controller
  (`croot`): the root the policy names, or the genesis root for the genesis
  policy, and each root that replaced it in turn. This depends only on the
  shape of entries, so a root that a recovery removed never controls a
  policy named after it.
- **Contests** (`contested`): two roots in effect at once, which only
  concurrent root replacements can cause. The contestants' other ops wait
  (`suspended`), and so does the encryption key (`after_fork`). Guardians
  end a contest by recovery.
- **Decisions only accumulate.** Whether a decision is in effect never
  depends on the absence of anything, so a decision in effect stays in
  effect as entries arrive. Confirmations can arrive in any order, so a rule
  that ignored a decision because of a change approved later would undo it.
  Instead, two decisions under one policy that do not know each other, or a
  decision under a policy that had already been changed in its own past, are
  evidence of misbehaving guardians (`tainted`). They freeze the identity,
  and they are not applied (`applied`), so that guardians acting on a policy
  they agreed to replace cannot take the identity's keys away.
- **Freezing** (`frozen`) is evidence that no rule can settle. It is
  monotone: adding entries never unfreezes an identity (the fuzzer checks
  this). The second rule needs care: it compares the controller's two
  replacements against changes of the policy in their own causal pasts,
  which depend only on the shape of entries once the policy is in effect.
- **Extensions.** An op from an [extension](../spec/evolution.md) has no
  effect in these rules; it matters only through `badops` (undeclared, or
  marked critical and below admin power). Whether it is critical is the mark
  a protocol record in its causal past gives it, never the extension's own
  document, so verifiers with and without the extension agree on it. A
  verifier that lacks an extension marked critical evaluates the
  program once, takes the valid entries that use it as *opaque*, and
  evaluates again without them and their descendants (`evaluate_identity`
  with `known`). Each pass is this program, so each has one result; the two
  together give one result for each set of known extensions.

## Spaces

A space only grows ([spaces.md](../spec/spaces.md)): members are added and
roles are given, and nothing in a space takes either away. So these rules
have no layers by role, and no rule about what was written at the same time
as something else. The only "not" that reaches past an entry's own author is
the end of the space.

### Inputs

Facts about the entries of one space, plus the evaluated identity logs of
its authors.

| Fact | Meaning |
|---|---|
| `s_entry(X)`, `s_anc`, `s_ae` | as for identity logs |
| `s_genesis(X)` | X is the space's genesis: the entry whose id is the space's. An entry has no parents only if it is the genesis of its own space ([spaces.md](../spec/spaces.md#entries-and-sealed-entries)), so a space has one |
| `author(X,A)`, `skey(X,K)`, `cites(X,H)` | X's author identity, signing key, and cited head of the author's log. An entry has one signing key: its id covers it ([encoding.md](../spec/encoding.md#signed-objects)) |
| `adds(X,M,R)` | X contains `add_member` of identity M with role R (0 reader, 1 writer, 2 admin, 3 owner) |
| `s_names(X,S)` | X contains `succeed` naming the space S |
| `s_keep(X,K,E)` | X contains `keep` for key K, listing entry E |
| `s_structural(X)` | X ends or begins a space: it contains a `succeed`, or it is a genesis whose `start` names a space it succeeds |
| `s_badops(X,R)` | X contains an op that role R may not perform ([table](../spec/spaces.md#members-and-roles)). Outside a genesis, `start`, and an `add_member` whose role is not 0, 1 or 2, are allowed to no role. `succeed` is allowed to the owner, or, in a space with no owner, to every role |
| `s_badgenesis(G)` | the genesis G is not formed as [spaces.md](../spec/spaces.md#members-and-roles) requires: it does not hold exactly one `start`; it does not name its author; it names an owner who is not its author, or names an owner twice; it names a role outside 0 to 3; it names no owner and names an admin; or it holds a `succeed`, or, besides `start` and `add_member`, an op that the highest role it gives its author may not perform |
| `decider(M)`, `quorum(N)` | who must name a successor, and how many of them: the owner the genesis names, and 1; or, when it names no owner, every identity it names, and their number |
| `id_effective_at(A,K,H)`, `id_removed(A,K)`, `id_removed_at(A,K,H)` | `effective_at`, `removed`, `removed_at` from A's identity log |

Whether an author is frozen is not an input. A frozen member's entries are
judged like anyone's ([spaces.md](../spec/spaces.md#a-member-who-can-no-longer-be-trusted)).

### Rules

```datalog
@program space

@input s_entry/1 s_genesis/1 s_anc/2 s_ae/2
@input author/2 skey/2 cites/2
@input adds/3 s_names/2 s_keep/3 s_structural/1 s_badops/2 s_badgenesis/1 decider/1 quorum/1
@input id_effective_at/3 id_removed/2 id_removed_at/3

% ---- Layer 1: authors. Depends only on identity logs, never on members.
@stratum authors
attrib(X) :- author(X,A), skey(X,K), cites(X,H), id_effective_at(A,K,H).
author_ok(X) :- attrib(X), author(X,A), skey(X,K), not id_removed(A,K).
author_ok(X) :- attrib(X), witnessed(X).
% built on by another of the author's keys, while that key was still trusted;
% a succeed, and a successor's genesis, are never witnessed this way
witnessed(X) :- author(X,A), skey(X,K), not s_structural(X), s_anc(X,W), author(W,A),
                skey(W,K2), K2 != K, author_ok(W), cites(W,H), not id_removed_at(A,K,H).
% listed, or an ancestor of an entry listed, by a keep of the author's that
% another key signed: a keep for its own key keeps nothing
witnessed(X) :- author(X,A), skey(X,K), s_keep(W,K,E), s_ae(X,E), author(W,A), author_ok(W),
                skey(W,K2), K2 != K.
root(G) :- s_genesis(G), author_ok(G), not s_badgenesis(G).
% who named which successor, and which entries have that naming behind them
named(M,S,Y) :- s_names(Y,S), author(Y,M), decider(M), author_ok(Y), s_genesis(G),
                adds(G,M,R), not s_badops(Y,R).
namer(M,S) :- named(M,S,Y).
named_before(M,S,X) :- named(M,S,Y), s_anc(Y,X).

% ---- Layer 2: the end of the space. A successor is named once everyone who
% must name it has; what descends from all of those namings is closed.
@stratum closing
agreed(S) :- root(G), namer(M,S), quorum(N), count{D : namer(D,S)} >= N.
closed(X) :- agreed(S), s_entry(X), quorum(N), count{D : named_before(D,S,X)} >= N.

% ---- Layer 3: members. Roles are only given, so this layer has no "not"
% about members: an entry is judged by what its own causal past gave its author.
@stratum members
valid(G) :- root(G).
role_in(M,R,X) :- adds(E,M,R), valid(E), s_anc(E,X).
valid(X) :- author(X,A), role_in(A,R,X), author_ok(X), not s_badops(X,R), not closed(X).
vnamer(M,S) :- s_names(Y,S), author(Y,M), decider(M), valid(Y).

% ---- Layer 4: which successor stands.
@stratum successors
candidate(S) :- vnamer(M,S), quorum(N), count{D : vnamer(D,S)} >= N.
beaten(S) :- candidate(S), candidate(T), T < S.

% ---- Layer 5: results.
@stratum outcome
member(M,R) :- adds(E,M,R), valid(E).
successor(S) :- candidate(S), not beaten(S).
```

### Reading the rules

- **Authors first.** Whether a signature counts (`author_ok`) depends only on
  the author's identity log: the key was in effect at the cited head, and
  either it is still in effect or the entry is witnessed by another of the
  author's keys, or listed in a `keep`. Members never enter into it, so
  witnessing cannot loop through them. A witness or a `keep` counts by its
  own signature alone, so it works in a space that has closed.
- **What ends or begins a space is kept, never witnessed**
  (`s_structural`). Building on an entry is something a device does without
  its person. So a `succeed`, and the genesis of a successor, by a key that
  has been removed count only if a `keep` lists them, however much was
  built on them: a succession made by a device that is later lost can
  always be undone, and one that is to last was kept on purpose.
- **Roles are only given** (`role_in`). An identity holds, in an entry's
  causal past, every role a valid entry there gave it. An entry is valid if
  one of those roles may perform all of its ops. There is no removal and no
  lowering, so nothing written beside an entry or after it changes what its
  author could do, and this layer needs no "not" about members.
- **One owner, or none.** Only a genesis names an owner, and only its own
  author (`s_badgenesis`, `s_badops`). The owner alone names a successor.
  A genesis that names no owner names no admins either, so nobody can add
  to it, and all of its members must name a successor (`decider`,
  `quorum`).
- **The end of the space** (`closed`). An entry that descends from the
  namings of one successor by everyone who must name it is invalid. In a
  space with an owner that is every entry that descends from the owner's
  `succeed`. Entries that do not descend from it stay valid: their authors
  had not seen it.
- **Two steps, one meaning.** `closed` is worked out from namings whose
  signatures count (`named`), before validity, and the successor from
  namings that are valid (`vnamer`), after it. They differ only in namings
  that are themselves closed, and a closed naming closes nothing new:
  whatever descends from it already descends from what closed it. So an
  invalid `succeed` names nothing, and the rules stay in layers.
- **Which successor stands** (`successor`). Two devices of an owner can each
  name a successor before hearing of the other. Each closes what descends
  from it, and of the successors named the one with the smallest id stands.
- **What can still change an entry.** Only signatures: a key removed, a
  recovery, a witness, a `keep`. A signature that stops counting voids its
  entry and what rested on it: the members it added, and what they wrote. A
  `succeed` whose signature comes to count closes what descends from it.
  Nothing else in a space reaches an entry from outside its own causal
  past, which is what the fuzzer's property M checks.
- **Leaving** is not in these rules. A `leave` is a member's statement and
  changes nothing about what is valid.
- **Across spaces.** Whether a device follows a successor, and what it
  posts again there, is what software does with these results
  ([spaces.md](../spec/spaces.md#succession)). The rules judge one space.
