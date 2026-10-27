# Authority rules

Status: draft. **Normative.** These rules define which identity entries and
which space entries are valid, which keys and memberships are in effect, and
when an identity is frozen. [identity.md](../spec/identity.md) and
[spaces.md](../spec/spaces.md) explain them in prose; where the prose and
these rules disagree, these rules win.

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
| `signer(E,K)` | E is signed by key K |
| `add(E,K,P)` | E contains `add_key` of K with power P (1 device, 2 admin, 3 root) |
| `readd(E)` | E contains `add_key` of a key already named in E's causal past, by an `add_key` or as a recovery's new root |
| `rem(E,K)` | E contains `remove_key` of K |
| `selfrep(E,R,N)`, `is_selfrep(E)` | E is a root replacement: signed by R, its ops are exactly `add_key` of root N and `remove_key` of R, and at most one `set_protocol` |
| `badops(E,P)` | E contains an op that a key of power P may not perform ([table](../spec/identity.md#operations)), adds a key at a power above P or a root, contains `readd`, is a decision, or uses a critical [extension](../spec/evolution.md) that no `set_protocol` in its causal past declares (critical extensions and `set_protocol` need admin power). Whether a removal goes down in power is decided by the rules (`bad`) |
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
- **Extensions.** An op from a critical [extension](../spec/evolution.md)
  has no effect in these rules; it matters only through `badops` (undeclared,
  or below admin power). A verifier that lacks the extension evaluates the
  program once, takes the valid entries that use it as *opaque*, and
  evaluates again without them and their descendants (`evaluate_identity`
  with `known`). Each pass is this program, so each has one result; the two
  together give one result for each set of known extensions.

## Spaces

### Inputs

Facts about the entries of one space, plus the evaluated identity logs of
its authors.

| Fact | Meaning |
|---|---|
| `s_entry(X)`, `s_genesis(X)`, `s_anc`, `s_ae`, `s_conc` | as for identity logs |
| `author(X,A)`, `skey(X,K)`, `cites(X,H)` | X's author identity, signing key, and cited head of the author's log |
| `mem(X,I)` | X names membership I as its author's ([spaces.md](../spec/spaces.md#memberships)) |
| `incarnation(I,M,R)`, `inc_from(I,E)` | membership I is identity M with role R (0 reader … 3 owner), created by entry E |
| `adds(X,I)` | X creates membership I (genesis creates its author's, as owner) |
| `s_rem(X,I)` | X ends membership I |
| `replaces(Y,I,J)` | Y ends I and creates J for the same identity with a lower role |
| `s_succeed(X)` | X contains `succeed` |
| `s_keep(X,K,E)` | X contains `keep` for key K, listing entry E |
| `s_badops(X,R)` | X contains an op that role R may not perform |
| `id_effective_at(A,K,H)`, `id_removed(A,K)`, `id_removed_at(A,K,H)`, `id_frozen(A)` | `effective_at`, `removed`, `removed_at`, `frozen` from A's identity log |
| `kept_frozen(X)` | X is by a frozen author, and when this program is evaluated with no author treated as frozen, X's signature counts and X is in the causal past of a valid entry by an author who is not frozen |

### Rules

```datalog
@program space

@input s_entry/1 s_genesis/1 s_anc/2 s_ae/2 s_conc/2
@input author/2 skey/2 cites/2 mem/2
@input incarnation/3 inc_from/2 adds/2 s_rem/2 replaces/3 s_succeed/1 s_keep/3 s_badops/2
@input id_effective_at/3 id_removed/2 id_removed_at/3 id_frozen/1 kept_frozen/1

% ---- Layer 1: authors. Depends only on identity logs, never on membership.
@stratum authors
attrib(X) :- author(X,A), skey(X,K), cites(X,H), id_effective_at(A,K,H), not id_frozen(A).
author_ok(X) :- attrib(X), author(X,A), skey(X,K), not id_removed(A,K).
author_ok(X) :- attrib(X), witnessed(X).
% a frozen author's entries count only as far as others' valid entries built on them
author_ok(X) :- kept_frozen(X).
witnessed(X) :- author(X,A), skey(X,K), s_anc(X,W), author(W,A), skey(W,K2), K2 != K,
                author_ok(W), cites(W,H), not id_removed_at(A,K,H).
witnessed(X) :- author(X,A), skey(X,K), s_keep(W,K,E), s_ae(X,E), author(W,A), author_ok(W).
% only a membership's own identity ends it by leaving or succeeding
own_end(Y,I) :- mem(Y,I), incarnation(I,M,R), author(Y,M), inc_from(I,E), s_ae(E,Y),
                author_ok(Y).
leave(Y,I) :- s_rem(Y,I), own_end(Y,I), incarnation(I,M,R), not s_badops(Y,R).
leave(Y,I) :- s_succeed(Y), own_end(Y,I), incarnation(I,M,3), not s_badops(Y,3).
% after leaving, nothing counts; around it, only work by the same key is void
left_before(I,X) :- leave(Y,I), s_anc(Y,X).
left_conc(I,X) :- leave(Y,I), s_conc(Y,X), skey(Y,K), skey(X,K).
lowered(Y,I,X) :- replaces(Y,I,J), incarnation(J,M,R), s_entry(X), not s_badops(X,R).

% ---- Layer 2: owners. Nobody can remove an owner; owners can only leave.
@stratum owners
inc_ok3(I) :- s_genesis(G), adds(G,I), incarnation(I,A,3).
inc_ok3(I) :- adds(X,I), incarnation(I,M,3), v3(X).
v3(X) :- mem(X,I), incarnation(I,A,3), author(X,A), inc_ok3(I), inc_from(I,E), s_ae(E,X),
         author_ok(X), not left_before(I,X), not left_conc(I,X), not s_badops(X,3).
owner_live(X) :- inc_ok3(I), inc_from(I,E), s_ae(E,X), s_entry(X), not left_before(I,X).
closing(Y) :- s_succeed(Y), v3(Y).

% ---- Layer 3: admins, removed only by owners or by leaving.
@stratum admin_removals
closed(X) :- closing(Y), s_anc(Y,X), not owner_live(X).
rm2(I,Y) :- s_rem(Y,I), incarnation(I,M,2), v3(Y).
gone2(I,X) :- rm2(I,Y), s_anc(Y,X).
clash2(I,X) :- rm2(I,Y), s_conc(Y,X), not lowered(Y,I,X).

@stratum admins
inc_ok2(I) :- adds(X,I), incarnation(I,M,2), v3(X).
inc_ok2(I) :- adds(X,I), incarnation(I,M,2), v2(X).
v2(X) :- mem(X,I), incarnation(I,A,2), author(X,A), inc_ok2(I), inc_from(I,E), s_anc(E,X),
         author_ok(X), not gone2(I,X), not clash2(I,X), not left_before(I,X),
         not left_conc(I,X), not closed(X), not s_badops(X,2).

% ---- Layer 4: writers, removed by owners, admins, or by leaving.
@stratum writer_removals
rm1(I,Y) :- s_rem(Y,I), incarnation(I,M,1), v3(Y).
rm1(I,Y) :- s_rem(Y,I), incarnation(I,M,1), v2(Y).
gone1(I,X) :- rm1(I,Y), s_anc(Y,X).
clash1(I,X) :- rm1(I,Y), s_conc(Y,X), not lowered(Y,I,X).

@stratum writers
inc_ok1(I) :- adds(X,I), incarnation(I,M,1), v3(X).
inc_ok1(I) :- adds(X,I), incarnation(I,M,1), v2(X).
v1(X) :- mem(X,I), incarnation(I,A,1), author(X,A), inc_ok1(I), inc_from(I,E), s_anc(E,X),
         author_ok(X), not gone1(I,X), not clash1(I,X), not left_before(I,X),
         not left_conc(I,X), not closed(X), not s_badops(X,1).

% ---- Layer 5: readers.
@stratum reader_removals
rm0(I,Y) :- s_rem(Y,I), incarnation(I,M,0), v3(Y).
rm0(I,Y) :- s_rem(Y,I), incarnation(I,M,0), v2(Y).
gone0(I,X) :- rm0(I,Y), s_anc(Y,X).
clash0(I,X) :- rm0(I,Y), s_conc(Y,X), not lowered(Y,I,X).
ended(I) :- leave(Y,I).
ended(I) :- rm2(I,Y).
ended(I) :- rm1(I,Y).
ended(I) :- rm0(I,Y).

@stratum readers
inc_ok0(I) :- adds(X,I), incarnation(I,M,0), v3(X).
inc_ok0(I) :- adds(X,I), incarnation(I,M,0), v2(X).
v0(X) :- mem(X,I), incarnation(I,A,0), author(X,A), inc_ok0(I), inc_from(I,E), s_anc(E,X),
         author_ok(X), not gone0(I,X), not clash0(I,X), not left_before(I,X),
         not left_conc(I,X), not closed(X), not s_badops(X,0).

% ---- Layer 6: results.
@stratum outcome
valid(X) :- v3(X).
valid(X) :- v2(X).
valid(X) :- v1(X).
valid(X) :- v0(X).
member(I) :- inc_ok3(I), not ended(I).
member(I) :- inc_ok2(I), not ended(I).
member(I) :- inc_ok1(I), not ended(I).
member(I) :- inc_ok0(I), not ended(I).
```

### Reading the rules

- **Authors first.** Whether a signature counts (`author_ok`) depends only on
  the author's identity log: the key was in effect at the cited head, and
  either it is still in effect or the entry is witnessed by another of the
  author's keys, or listed in a `keep`. Membership never enters into it, so
  witnessing cannot loop through membership.
- **Frozen authors** (`kept_frozen`): the program is evaluated once as if no
  author were frozen, and a frozen author's entries then count only if they
  are in the causal past of a valid entry by an author who is not frozen.
  The second evaluation uses the first only as input, so it cannot loop.
  Nobody who is not a valid member can keep a frozen author's entries.
- **Memberships, not identities, hold roles.** Each `add_member` creates a
  membership with a fixed role, named by its entry and the op's position,
  and each entry names the membership it writes under. Changing a role ends
  one membership and creates another in the same entry (`replaces`). Adding
  someone who is already a member creates a second membership and changes
  nothing about the first.
- **Layers follow roles.** An entry under a membership is invalidated only by
  an end of that membership written by a strictly higher role, or by the
  member leaving. Entries concurrent with an end by a higher role are
  invalid, unless the end was a lowering of role and the entry was allowed
  under the new role (`lowered`). Entries descending from any end fail
  authorization.
- **Leaving** (`leave`) is written by the membership's own identity, under
  that membership, after it was created, with a signature that counts.
  Around a leave, only entries signed by the same key are void
  (`left_conc`), so a stolen device cannot erase its owner's other work by
  backdating a leave or `succeed`.
- **Closing.** After an owner's `succeed`, entries whose past has no owner
  left are invalid.
