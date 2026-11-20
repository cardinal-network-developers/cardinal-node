//! Guardians (`identity.md#guardians`): naming them by hidden commitments,
//! a guardian finding its own record, endorsing and confirming in its own
//! log, and the new device rebuilding the guardian key from the shares in
//! their confirmations (`identity.md#data-recovery`).
//!
//! What a set of entries means is decided by evaluation alone
//! ([`crate::log`]); this module writes entries and reads what they carry.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use cardinal_crypto::shamir::{self, Share};
use cardinal_crypto::{
    open, random_bytes, seal, HybridKeyPair, HybridPublicKey, Sealed, SigningKey,
};
use cardinal_encoding::Record;
use zeroize::Zeroizing;

use crate::entry::{EntryBuilder, EntryId, IdentityEntry, IdentityOp, KeyId, OpBody};
use crate::log::{guardian_commitment, IdentityLog, RECOVERY_WRAP_CONTEXT};
use crate::Error;

/// Context prefix of a sealed guardian record and of a sealed share.
pub const RECOVERY_SHARE_CONTEXT: &[u8] = b"recovery share";

/// The recommended delay: seven days.
pub const DEFAULT_DELAY: u64 = 7 * 24 * 60 * 60;

/// The most guardians a policy may name: a share's x is one byte.
pub const MAX_GUARDIANS: usize = 32;

/// The most sets of shares tried when rebuilding a guardian key.
pub const MAX_COMBINATIONS: usize = 20_000;

fn context(prefix: &[u8], binding: &[u8; 32]) -> Vec<u8> {
    [prefix, binding].concat()
}

/// A guardian's record, sealed to the guardian in `set_recovery` field 4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardianRecord {
    /// Position of the guardian's commitment, from 1.
    pub position: u64,
    /// The commitment's salt.
    pub salt: [u8; 32],
    /// The guardian's share of the guardian key, when the policy has one.
    pub share: Option<Share>,
}

fn share_record(s: &Share) -> Record {
    Record::new().with(1, s.x as u64).with(2, &s.y[..])
}

fn share_from(r: &Record) -> Result<Share, Error> {
    let x = r.uint(1)?;
    let x = u8::try_from(x).map_err(|_| Error::Malformed("share index"))?;
    let y: [u8; 32] = r.bytes_n(2)?;
    Ok(Share {
        x,
        y: Zeroizing::new(y),
    })
}

impl GuardianRecord {
    /// The record.
    pub fn to_record(&self) -> Record {
        Record::new()
            .with(1, self.position)
            .with(2, self.salt)
            .with_opt(3, self.share.as_ref().map(share_record))
    }

    /// Reads one.
    pub fn from_record(r: &Record) -> Result<GuardianRecord, Error> {
        Ok(GuardianRecord {
            position: r.uint(1)?,
            salt: r.bytes_n(2)?,
            share: match r.opt_record(3)? {
                Some(s) => Some(share_from(s)?),
                None => None,
            },
        })
    }
}

/// What a `set_recovery` says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// The entry it is in.
    pub entry: EntryId,
    /// One commitment per guardian.
    pub commitments: Vec<[u8; 32]>,
    /// The threshold.
    pub threshold: u64,
    /// The delay in seconds.
    pub delay: u64,
    /// Sealed guardian records, in the order of the commitments.
    pub records: Vec<Sealed>,
    /// The guardian public key, for data recovery.
    pub guardian_key: Option<HybridPublicKey>,
    /// The policy it changes.
    pub changes: Option<EntryId>,
}

impl Policy {
    /// Whether it names guardians.
    pub fn guarded(&self) -> bool {
        !self.commitments.is_empty()
    }
}

/// What a `recover` says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    /// The entry.
    pub entry: EntryId,
    /// The new root key.
    pub root: KeyId,
    /// Keys kept.
    pub keep: Vec<KeyId>,
    /// The link key that receives shares.
    pub link_key: Option<HybridPublicKey>,
    /// The policy it acts under.
    pub policy: EntryId,
}

impl Recovery {
    /// The short fingerprint a guardian checks with the person before
    /// endorsing and confirming: of `recover` fields 1 and 3
    /// (`identity.md#how-guardians-act`). Ten characters of Crockford's
    /// base 32, in two groups.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.root, self.link_key.as_ref())
    }
}

/// The fingerprint of a new root and the link key that receives shares.
pub fn fingerprint(root: &KeyId, link: Option<&HybridPublicKey>) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"cardinal recovery fingerprint");
    h.update(root);
    if let Some(l) = link {
        h.update(&l.encode());
    }
    let d = h.finalize();
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let bytes = &d.as_bytes()[..7];
    let (mut acc, mut bits) = (0u64, 0);
    let mut out = String::new();
    for b in bytes {
        acc = (acc << 8) | *b as u64;
        bits += 8;
        while bits >= 5 && out.replace('-', "").len() < 10 {
            bits -= 5;
            if out.len() == 5 {
                out.push('-');
            }
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    out
}

/// Reads a fingerprint however it was typed: case, spaces and dashes do
/// not matter, nor letters that read like digits.
pub fn same_fingerprint(typed: &str, shown: &str) -> bool {
    let norm = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                c => c,
            })
            .collect()
    };
    !typed.trim().is_empty() && norm(typed) == norm(shown)
}

/// A guardian's act about a decision, found in their log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Act {
    /// The guardian's identity.
    pub guardian: EntryId,
    /// The entry in the guardian's log.
    pub entry: EntryId,
    /// Position of the guardian's commitment.
    pub position: u64,
    /// A `confirm` (else an `endorse`).
    pub confirm: bool,
    /// The sealed share a `confirm` of a recovery carries.
    pub share: Option<Sealed>,
}

impl IdentityLog {
    /// The policy a `set_recovery` in `entry` sets.
    pub fn policy(&self, entry: &EntryId) -> Option<Policy> {
        let e = self.get(entry)?;
        e.ops().iter().find_map(|o| match o.body() {
            OpBody::SetRecovery {
                commitments,
                threshold,
                delay,
                guardian_records,
                guardian_key,
                changes,
                ..
            } => Some(Policy {
                entry: *entry,
                commitments: commitments.clone(),
                threshold: *threshold,
                delay: *delay,
                records: guardian_records.clone(),
                guardian_key: guardian_key.clone(),
                changes: *changes,
            }),
            _ => None,
        })
    }

    /// The policy in effect and not replaced. Where evaluation leaves more
    /// than one, the last in log order.
    pub fn current_policy(&self) -> Option<Policy> {
        let st = self.state();
        let current: HashSet<EntryId> = st.current_policies.iter().copied().collect();
        let last = self
            .entries()
            .map(|e| e.id())
            .filter(|id| current.contains(id))
            .last()?;
        self.policy(&last)
    }

    /// The `recover` in `entry`.
    pub fn recovery(&self, entry: &EntryId) -> Option<Recovery> {
        let e = self.get(entry)?;
        recovery_of(e)
    }

    /// Every `recover` entry held.
    pub fn recoveries(&self) -> Vec<Recovery> {
        self.entries().filter_map(recovery_of).collect()
    }

    /// Names guardians: a `set_recovery` changing the current policy, with
    /// a commitment and a sealed record for each of `guardians` (their
    /// identity and encryption key), `threshold`, and `delay`. With `data`,
    /// the policy has a guardian key whose shares the records carry, and
    /// a recovery wrap of `current`, the current encryption key, to it.
    ///
    /// Under a policy naming no guardians this is signed by its controller,
    /// a root; under one naming guardians, by any key, and the guardians
    /// decide.
    pub fn set_guardians(
        &mut self,
        author: &SigningKey,
        guardians: &[(EntryId, HybridPublicKey)],
        threshold: u64,
        delay: u64,
        data: bool,
        current: Option<&HybridKeyPair>,
    ) -> Result<IdentityEntry, Error> {
        let n = guardians.len() as u64;
        if guardians.is_empty() || guardians.len() > MAX_GUARDIANS {
            return Err(Error::Malformed("between one and 32 guardians"));
        }
        if threshold * 2 <= n || threshold > n {
            return Err(Error::Malformed(
                "the threshold must be more than half of the guardians, and no more than all",
            ));
        }
        let distinct: BTreeSet<&EntryId> = guardians.iter().map(|(g, _)| g).collect();
        if distinct.len() != guardians.len() || distinct.contains(&self.id()) {
            return Err(Error::Malformed("each guardian once, and not oneself"));
        }
        let policy = self
            .current_policy()
            .ok_or(Error::NotAuthorized("no recovery policy is in effect"))?;
        let st = self.state();
        let me = author.public_key();
        if policy.guarded() {
            if st.power(&me).is_none() {
                return Err(Error::NotAuthorized("the key is not in effect"));
            }
        } else if !st.roots.contains_key(&me) {
            return Err(Error::NotAuthorized(
                "only the root, from the recovery words, names the first guardians",
            ));
        }
        let id = self.id();
        let g = Zeroizing::new(random_bytes::<32>());
        let shares = if data {
            Some(shamir::split(&g, threshold as usize, guardians.len()).expect("checked"))
        } else {
            None
        };
        let gk = HybridKeyPair::from_seed(&g[..]);
        let mut commitments = Vec::new();
        let mut records = Vec::new();
        for (i, (guardian, enc)) in guardians.iter().enumerate() {
            let salt: [u8; 32] = random_bytes();
            commitments.push(guardian_commitment(&salt, guardian));
            let record = GuardianRecord {
                position: i as u64 + 1,
                salt,
                share: shares.as_ref().map(|s| s[i].clone()),
            };
            records.push(seal(
                enc,
                &record.to_record().encode(),
                &context(RECOVERY_SHARE_CONTEXT, &id),
            ));
        }
        let mut wraps = Vec::new();
        if data {
            if let Some(cur) = current {
                if st.encryption_key.as_ref().map(|k| &k.public) != Some(cur.public_key()) {
                    return Err(Error::WrongKey);
                }
                wraps.push(seal(
                    gk.public_key(),
                    &cur.secret_bytes()[..],
                    &context(RECOVERY_WRAP_CONTEXT, &id),
                ));
            }
        }
        let op = IdentityOp::set_recovery(
            &commitments,
            threshold,
            delay,
            &records,
            data.then(|| gk.public_key()),
            &wraps,
            Some(policy.entry),
            None,
        );
        self.append(author, vec![op])
    }

    /// The guardian record sealed to `me` in `policy`, opened with one of
    /// `keys` (the guardian identity's encryption keys) and checked
    /// against its commitment.
    pub fn guardian_record(
        &self,
        policy: &Policy,
        me: &EntryId,
        keys: &[HybridKeyPair],
    ) -> Option<GuardianRecord> {
        let ctx = context(RECOVERY_SHARE_CONTEXT, &self.id());
        for sealed in &policy.records {
            for k in keys {
                let Ok(pt) = open(k, sealed, &ctx) else {
                    continue;
                };
                let Ok(r) = Record::decode(&pt) else { continue };
                let Ok(rec) = GuardianRecord::from_record(&r) else {
                    continue;
                };
                let at = rec.position as usize;
                if at >= 1
                    && at <= policy.commitments.len()
                    && policy.commitments[at - 1] == guardian_commitment(&rec.salt, me)
                {
                    return Some(rec);
                }
            }
        }
        None
    }

    /// Parents a guardian's device proposes for a `recover`: the latest
    /// valid entries, leaving out changes of the policy that are not in
    /// effect (`identity.md#how-guardians-act`).
    pub fn recovery_parents(&self) -> Vec<EntryId> {
        let st = self.state();
        let current: HashSet<EntryId> = st.current_policies.iter().copied().collect();
        let pending = |e: &IdentityEntry| {
            !e.is_genesis()
                && e.ops()
                    .iter()
                    .any(|o| matches!(o.body(), OpBody::SetRecovery { .. }))
                && !current.contains(&e.id())
        };
        let candidates: HashSet<EntryId> = self
            .entries()
            .filter(|e| {
                (st.is_valid(&e.id()) || st.in_effect.contains(&e.id()) || e.is_genesis())
                    && !pending(e)
            })
            .map(|e| e.id())
            .collect();
        let mut out: Vec<EntryId> = candidates
            .iter()
            .filter(|id| {
                !self
                    .dag()
                    .children(id)
                    .iter()
                    .any(|c| candidates.contains(c))
            })
            .copied()
            .collect();
        out.sort();
        out
    }

    /// A `recover` entry of this identity, signed by `new_root`.
    pub fn recover_entry(
        &self,
        parents: &[EntryId],
        new_root: &SigningKey,
        keep: &[KeyId],
        link: &HybridPublicKey,
        policy: EntryId,
        recovery_key: &HybridPublicKey,
    ) -> Result<IdentityEntry, Error> {
        EntryBuilder::new(self.id(), parents)
            .op(IdentityOp::recover(
                new_root.public_key(),
                keep,
                link,
                policy,
                recovery_key,
            ))
            .sign(new_root)
    }

    /// What guardians of `policy` have done about `decision`, as far as
    /// the logs attached here and `others` show: each act whose commitment
    /// opens, in an entry valid in its own log.
    pub fn acts(&self, decision: &EntryId, policy: &Policy, others: &[&IdentityLog]) -> Vec<Act> {
        let mut out = Vec::new();
        let mut seen: HashSet<EntryId> = HashSet::new();
        for log in self.attached().chain(others.iter().copied()) {
            let st = log.state();
            for e in log.entries() {
                if !seen.insert(e.id()) || !st.is_valid(&e.id()) {
                    continue;
                }
                for op in e.ops() {
                    let (d, position, salt, confirm, share) = match op.body() {
                        OpBody::Endorse {
                            decision,
                            position,
                            salt,
                        } => (decision, *position, salt, false, None),
                        OpBody::Confirm {
                            decision,
                            position,
                            salt,
                            share,
                        } => (decision, *position, salt, true, share.clone()),
                        _ => continue,
                    };
                    let at = position as usize;
                    if d != decision
                        || at == 0
                        || at > policy.commitments.len()
                        || policy.commitments[at - 1] != guardian_commitment(salt, &log.id())
                    {
                        continue;
                    }
                    out.push(Act {
                        guardian: log.id(),
                        entry: e.id(),
                        position,
                        confirm,
                        share,
                    });
                }
            }
        }
        out
    }

    /// Guardians who endorsed or confirmed `decision` (a confirmation says a
    /// recovery is wanted too).
    pub fn endorsed_by(
        &self,
        decision: &EntryId,
        policy: &Policy,
        others: &[&IdentityLog],
    ) -> BTreeSet<EntryId> {
        self.acts(decision, policy, others)
            .into_iter()
            .map(|a| a.guardian)
            .collect()
    }

    /// Guardians who confirmed `decision`.
    pub fn confirmed_by(
        &self,
        decision: &EntryId,
        policy: &Policy,
        others: &[&IdentityLog],
    ) -> BTreeSet<EntryId> {
        self.acts(decision, policy, others)
            .into_iter()
            .filter(|a| a.confirm)
            .map(|a| a.guardian)
            .collect()
    }

    /// Seals a guardian's share to the link key a recovery names, for its
    /// `confirm`.
    pub fn seal_share(&self, recovery: &Recovery, share: &Share) -> Result<Sealed, Error> {
        let link = recovery
            .link_key
            .as_ref()
            .ok_or(Error::Malformed("the recovery names no link key"))?;
        Ok(seal(
            link,
            &share_record(share).encode(),
            &context(RECOVERY_SHARE_CONTEXT, &self.id()),
        ))
    }

    /// The new device's part: the guardian key of the policy `recovery`
    /// acts under, rebuilt from the shares in the guardians' confirmations,
    /// opened with `link`, the link key the recovery names.
    pub fn rebuild_guardian_key(
        &self,
        recovery: &Recovery,
        link: &HybridKeyPair,
    ) -> Result<HybridKeyPair, Error> {
        let policy = self
            .policy(&recovery.policy)
            .ok_or(Error::Malformed("the policy is not here"))?;
        let want = policy.guardian_key.clone().ok_or(Error::NoEncryptionKey)?;
        let ctx = context(RECOVERY_SHARE_CONTEXT, &self.id());
        // One share per guardian, at the guardian's own position: a share
        // claiming another position is not theirs to give. Shares come
        // only from confirmations; an endorsement carries none.
        let mut by_x: BTreeMap<u8, Share> = BTreeMap::new();
        let mut guardians: BTreeSet<EntryId> = BTreeSet::new();
        for act in self.acts(&recovery.entry, &policy, &[]) {
            if !act.confirm || guardians.contains(&act.guardian) {
                continue;
            }
            let Some(sealed) = act.share else { continue };
            let Ok(pt) = open(link, &sealed, &ctx) else {
                continue;
            };
            let Ok(r) = Record::decode(&pt) else { continue };
            let Ok(s) = share_from(&r) else { continue };
            if s.x as u64 != act.position || by_x.contains_key(&s.x) {
                continue;
            }
            guardians.insert(act.guardian);
            by_x.insert(s.x, s);
        }
        let shares: Vec<Share> = by_x.into_values().collect();
        let t = policy.threshold as usize;
        if shares.len() < t || t == 0 {
            return Err(Error::NoEncryptionKey);
        }
        // Any threshold of them rebuilds it; a wrong share spoils only the
        // sets it is in. With one share per guardian there are at most
        // C(n, t) sets; the search stops after MAX_COMBINATIONS anyway.
        let mut pick: Vec<usize> = (0..t).collect();
        let mut tried = 0usize;
        loop {
            tried += 1;
            if tried > MAX_COMBINATIONS {
                return Err(Error::WrongKey);
            }
            let chosen: Vec<Share> = pick.iter().map(|i| shares[*i].clone()).collect();
            if let Some(g) = shamir::combine(&chosen) {
                let kp = HybridKeyPair::from_seed(&g[..]);
                if kp.public_key() == &want {
                    return Ok(kp);
                }
            }
            // next combination
            let mut i = t;
            loop {
                if i == 0 {
                    return Err(Error::WrongKey);
                }
                i -= 1;
                if pick[i] < shares.len() - t + i {
                    pick[i] += 1;
                    for j in i + 1..t {
                        pick[j] = pick[j - 1] + 1;
                    }
                    break;
                }
            }
        }
    }

    /// Opens the newest encryption key wrapped to a guardian key: from the
    /// current key's recovery wraps, else from the policy's own wrap.
    pub fn open_with_guardian_key(
        &self,
        guardian_key: &HybridKeyPair,
        policy: &EntryId,
    ) -> Result<HybridKeyPair, Error> {
        let ctx = context(RECOVERY_WRAP_CONTEXT, &self.id());
        let try_open = |sealed: &[Sealed]| {
            sealed.iter().find_map(|s| {
                let pt = open(guardian_key, s, &ctx).ok()?;
                let secret: Zeroizing<[u8; cardinal_crypto::hybrid::SECRET_LEN]> =
                    Zeroizing::new(pt[..].try_into().ok()?);
                Some(HybridKeyPair::from_secret_bytes(&secret))
            })
        };
        let st = self.state();
        // newest first, in log order reversed
        let order: Vec<&IdentityEntry> = self.entries().collect();
        for e in order.iter().rev() {
            if !st.is_valid(&e.id()) && !st.in_effect.contains(&e.id()) {
                continue;
            }
            for op in e.ops() {
                let (sealed, public) = match op.body() {
                    OpBody::SetEncryptionKey {
                        recovery_wraps,
                        public,
                        ..
                    } => (recovery_wraps, Some(public)),
                    OpBody::SetRecovery { recovery_wraps, .. } if e.id() == *policy => {
                        (recovery_wraps, None)
                    }
                    _ => continue,
                };
                if let Some(kp) = try_open(sealed) {
                    if public.is_none_or(|p| p == kp.public_key()) {
                        return Ok(kp);
                    }
                }
            }
        }
        Err(Error::NoEncryptionKey)
    }
}

fn recovery_of(e: &IdentityEntry) -> Option<Recovery> {
    e.ops().iter().find_map(|o| match o.body() {
        OpBody::Recover {
            root,
            keep,
            link_key,
            policy,
            ..
        } => Some(Recovery {
            entry: e.id(),
            root: *root,
            keep: keep.clone(),
            link_key: link_key.clone(),
            policy: *policy,
        }),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::{evaluate_together, Created, DeviceKeys};
    use crate::Power;
    use cardinal_crypto::RecoveryPhrase;

    struct Person {
        log: IdentityLog,
        device: DeviceKeys,
        enc: HybridKeyPair,
        phrase: RecoveryPhrase,
    }

    fn person(n: u8) -> Person {
        let device = DeviceKeys::generate();
        let Created {
            log,
            phrase,
            encryption,
        } = IdentityLog::create_with(
            RecoveryPhrase::from_entropy(&[n; 32]),
            &device,
            HybridKeyPair::generate(),
        )
        .unwrap();
        Person {
            log,
            device,
            enc: encryption,
            phrase,
        }
    }

    /// A person with three guardians, two of whom suffice, and a guardian key.
    fn guarded() -> (Person, Vec<Person>) {
        let mut p = person(1);
        let gs: Vec<Person> = (2..5).map(person).collect();
        let named: Vec<(EntryId, HybridPublicKey)> = gs
            .iter()
            .map(|g| (g.log.id(), g.enc.public_key().clone()))
            .collect();
        let root = p.phrase.root_signing_key();
        let enc = HybridKeyPair::from_secret_bytes(&p.enc.secret_bytes());
        p.log
            .set_guardians(&root, &named, 2, 60, true, Some(&enc))
            .unwrap();
        (p, gs)
    }

    #[test]
    fn the_first_guardians_take_effect_at_once_and_stay_hidden() {
        let (p, gs) = guarded();
        let policy = p.log.current_policy().unwrap();
        assert!(policy.guarded());
        assert_eq!(
            (policy.commitments.len(), policy.threshold, policy.delay),
            (3, 2, 60)
        );
        // the log names nobody: each guardian finds its own record
        for (i, g) in gs.iter().enumerate() {
            let rec = p
                .log
                .guardian_record(&policy, &g.log.id(), std::slice::from_ref(&g.enc))
                .unwrap();
            assert_eq!(rec.position, i as u64 + 1);
            assert!(rec.share.is_some());
        }
        let stranger = person(9);
        assert!(p
            .log
            .guardian_record(&policy, &stranger.log.id(), &[stranger.enc])
            .is_none());
        // another guardian's key does not open a record as someone else
        assert!(p
            .log
            .guardian_record(&policy, &gs[0].log.id(), std::slice::from_ref(&gs[1].enc))
            .is_none());
    }

    #[test]
    fn only_the_root_names_the_first_guardians_and_only_a_majority() {
        let mut p = person(1);
        let g = person(2);
        let h = person(3);
        let named = vec![
            (g.log.id(), g.enc.public_key().clone()),
            (h.log.id(), h.enc.public_key().clone()),
        ];
        let enc = HybridKeyPair::from_secret_bytes(&p.enc.secret_bytes());
        assert!(matches!(
            p.log
                .set_guardians(&p.device.signing, &named, 2, 0, true, Some(&enc)),
            Err(Error::NotAuthorized(_))
        ));
        let root = p.phrase.root_signing_key();
        assert!(p
            .log
            .set_guardians(&root, &named, 1, 0, true, Some(&enc))
            .is_err());
        assert!(p
            .log
            .set_guardians(&root, &named, 3, 0, true, Some(&enc))
            .is_err());
        assert!(p
            .log
            .set_guardians(&root, &named, 2, 0, true, Some(&enc))
            .is_ok());
    }

    #[test]
    fn a_new_encryption_key_is_wrapped_to_the_guardian_key() {
        let (mut p, _) = guarded();
        let new = HybridKeyPair::generate();
        let cur = HybridKeyPair::from_secret_bytes(&p.enc.secret_bytes());
        p.log
            .set_encryption_key(&p.device.signing, &new, Some(&cur))
            .unwrap();
        let st = p.log.state();
        let e = p
            .log
            .get(&st.encryption_key.as_ref().unwrap().entry)
            .unwrap();
        let n = e
            .ops()
            .iter()
            .find_map(|o| match o.body() {
                OpBody::SetEncryptionKey { recovery_wraps, .. } => Some(recovery_wraps.len()),
                _ => None,
            })
            .unwrap();
        assert_eq!(n, 2, "to the phrase and to the guardian key");
    }

    /// Guardian `g` acts on `decision` in its own log, with its record.
    fn act(
        g: &mut Person,
        p: &IdentityLog,
        decision: &EntryId,
        confirm: bool,
    ) -> Vec<IdentityEntry> {
        let policy = p.current_policy().unwrap();
        let rec = p
            .guardian_record(&policy, &g.log.id(), std::slice::from_ref(&g.enc))
            .unwrap();
        let op = if confirm {
            let r = p.recovery(decision).unwrap();
            let share = p.seal_share(&r, rec.share.as_ref().unwrap()).unwrap();
            IdentityOp::confirm(*decision, rec.position, rec.salt, Some(&share))
        } else {
            IdentityOp::endorse(*decision, rec.position, rec.salt)
        };
        g.log.append(&g.device.signing, vec![op]).unwrap();
        g.log.entries().cloned().collect()
    }

    #[test]
    fn guardians_recover_an_identity_and_its_data() {
        let (mut p, mut gs) = guarded();
        let old_root = p.phrase.root_signing_key().public_key();
        let enc_public = p.log.state().encryption_key.clone().unwrap().public;
        // the new device
        let phrase = RecoveryPhrase::from_entropy(&[42; 32]);
        let new_root = phrase.root_signing_key();
        let link = HybridKeyPair::generate();
        let policy = p.log.current_policy().unwrap();
        let parents = p.log.recovery_parents();
        let rec = p
            .log
            .recover_entry(
                &parents,
                &new_root,
                &[],
                link.public_key(),
                policy.entry,
                phrase.recovery_key_pair().public_key(),
            )
            .unwrap();
        let decision = rec.id();
        p.log.insert(rec).unwrap();
        let r = p.log.recovery(&decision).unwrap();
        assert_eq!(r.fingerprint().len(), 11);
        assert!(same_fingerprint(
            &r.fingerprint().to_lowercase(),
            &r.fingerprint()
        ));
        // nothing happens until a threshold confirms
        assert!(p.log.state().roots.contains_key(&old_root));
        for g in gs.iter_mut() {
            for e in act(g, &p.log, &decision, false) {
                let _ = p.log.attach(e);
            }
        }
        assert_eq!(p.log.endorsed_by(&decision, &policy, &[]).len(), 3);
        assert!(p.log.state().roots.contains_key(&old_root));
        for e in act(&mut gs[0], &p.log, &decision, true) {
            let _ = p.log.attach(e);
        }
        assert!(
            p.log.state().roots.contains_key(&old_root),
            "one is not enough"
        );
        assert!(p.log.rebuild_guardian_key(&r, &link).is_err());
        // the second arrives out of order: confirmation before genesis
        let mut second = act(&mut gs[1], &p.log, &decision, true);
        second.reverse();
        for e in second {
            let _ = p.log.attach(e);
        }
        let st = p.log.state();
        assert_eq!(
            st.roots.keys().copied().collect::<Vec<_>>(),
            vec![new_root.public_key()]
        );
        assert!(st.keys.is_empty(), "no key was kept: {:?}", st.keys);
        assert_eq!(p.log.confirmed_by(&decision, &policy, &[]).len(), 2);
        // and the data: the guardian key from the shares opens the
        // encryption key
        let gk = p.log.rebuild_guardian_key(&r, &link).unwrap();
        let enc = p.log.open_with_guardian_key(&gk, &policy.entry).unwrap();
        assert_eq!(enc.public_key(), &enc_public);
        // the new root adds the new device
        let device = DeviceKeys::generate();
        p.log
            .add_key(
                &new_root,
                &device.request(&p.log.id(), Power::Admin),
                Some(&enc),
            )
            .unwrap();
        assert_eq!(p.log.state().power(&device.key()), Some(Power::Admin));
        // evaluated beside the guardians' own logs, the same
        let logs: Vec<&IdentityLog> = vec![&p.log, &gs[0].log, &gs[1].log];
        let together = evaluate_together(&logs);
        assert_eq!(together[0].roots, p.log.state().roots);
        assert_eq!(together[0].keys, p.log.state().keys);
    }

    /// A guardian who confirms with shares at other guardians' positions
    /// spoils nothing: only the share at its own position is its own.
    #[test]
    fn a_share_at_another_guardians_position_is_not_taken() {
        let (mut p, mut gs) = guarded();
        // the bad one is the guardian whose log is read first
        gs.sort_by_key(|g| g.log.id());
        let enc_public = p.log.state().encryption_key.clone().unwrap().public;
        let phrase = RecoveryPhrase::from_entropy(&[42; 32]);
        let link = HybridKeyPair::generate();
        let policy = p.log.current_policy().unwrap();
        let rec = p
            .log
            .recover_entry(
                &p.log.recovery_parents(),
                &phrase.root_signing_key(),
                &[],
                link.public_key(),
                policy.entry,
                phrase.recovery_key_pair().public_key(),
            )
            .unwrap();
        let decision = rec.id();
        p.log.insert(rec).unwrap();
        let r = p.log.recovery(&decision).unwrap();
        let mut positions = Vec::new();
        for g in &gs {
            let rec = p
                .log
                .guardian_record(&policy, &g.log.id(), std::slice::from_ref(&g.enc))
                .unwrap();
            positions.push((rec.position, rec.salt));
        }
        // the bad guardian: junk at each honest guardian's position
        let (own, salt) = positions[0];
        let mut ops = Vec::new();
        for (x, _) in &positions[1..] {
            let junk = Share {
                x: *x as u8,
                y: Zeroizing::new([9; 32]),
            };
            let sealed = p.log.seal_share(&r, &junk).unwrap();
            ops.push(IdentityOp::confirm(decision, own, salt, Some(&sealed)));
        }
        let bad = &mut gs[0];
        for op in ops {
            bad.log.append(&bad.device.signing, vec![op]).unwrap();
        }
        for e in gs[0].log.entries().cloned().collect::<Vec<_>>() {
            let _ = p.log.attach(e);
        }
        for g in gs.iter_mut().skip(1) {
            for e in act(g, &p.log, &decision, true) {
                let _ = p.log.attach(e);
            }
        }
        assert!(p.log.state().in_effect.contains(&decision));
        let gk = p.log.rebuild_guardian_key(&r, &link).unwrap();
        let enc = p.log.open_with_guardian_key(&gk, &policy.entry).unwrap();
        assert_eq!(enc.public_key(), &enc_public);
    }

    #[test]
    fn a_guardian_without_the_record_reveals_nothing() {
        let (mut p, _) = guarded();
        let phrase = RecoveryPhrase::from_entropy(&[42; 32]);
        let link = HybridKeyPair::generate();
        let policy = p.log.current_policy().unwrap();
        let rec = p
            .log
            .recover_entry(
                &p.log.recovery_parents(),
                &phrase.root_signing_key(),
                &[],
                link.public_key(),
                policy.entry,
                phrase.recovery_key_pair().public_key(),
            )
            .unwrap();
        let decision = rec.id();
        p.log.insert(rec).unwrap();
        // someone who is not a guardian claims a position
        let mut s = person(7);
        s.log
            .append(
                &s.device.signing,
                vec![IdentityOp::confirm(decision, 1, [0; 32], None)],
            )
            .unwrap();
        for e in s.log.entries().cloned().collect::<Vec<_>>() {
            let _ = p.log.attach(e);
        }
        assert!(p.log.endorsed_by(&decision, &policy, &[]).is_empty());
    }
}
