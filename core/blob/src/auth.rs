//! Signatures of sync ID operations and their checks at a node that cannot read the sync ID
//! (spec/sync-ids.md §6, spec/wire.md §9, §11.2): stamps, deposits, deletes by the sync ID delete key
//! or by a delete-key signature.

use crate::blob::{Level, Prefix};
use crate::cbor::{get_bytes, get_uint};
use crate::step::Step;
use crate::Error;
use osis_base::cbor::encode;
use osis_base::format::{DELETE_ADMIN, DELETE_WRITER};
use osis_base::{BlobId, SyncId, Value};
use osis_crypto::{DeleteSecret, Domain, RoleKey, Signature, SigningSecret, VerifyingKey, verify_delete};

/// Digest of a stamp, deposit or publish authorization: BLAKE3 of canonical
/// `[sync_id, blob_id, wrap]`.
pub fn entry_digest(sync_id: &SyncId, blob: &BlobId, wrap: &[u8]) -> [u8; 32] {
    osis_base::hash::hash(&encode(&Value::List(vec![Value::bytes(&sync_id.0), Value::bytes(&blob.0), Value::bytes(wrap)])))
}

/// A stamp: the sync ID write key's signature under `"osis v1 stamp"`, or `"osis v1 role
/// entry"` for an entry deletes are judged by (`role`: a role commit or a request).
pub fn sign_stamp(write: &SigningSecret, sync_id: &SyncId, blob: &BlobId, wrap: &[u8], role: bool) -> Signature {
    write.sign(entry_domain(Domain::Stamp, role), &entry_digest(sync_id, blob, wrap))
}

/// Which domain a good stamp or deposit signature verified under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signed {
    /// `"osis v1 stamp"` or `"osis v1 deposit"`.
    Plain,
    /// `"osis v1 role entry"`: an entry deletes are judged by.
    RoleEntry,
}

/// Checks a stamp against the head's write key, under either domain; an altered wrap fails.
pub fn verify_stamp(head_write: &VerifyingKey, sync_id: &SyncId, blob: &BlobId, wrap: &[u8], stamp: &Signature) -> Result<Signed, Error> {
    verify_entry(head_write, Domain::Stamp, &entry_digest(sync_id, blob, wrap), stamp).ok_or(Error::Verify("stamp"))
}

/// Which domain of an entry's signature verifies.
fn verify_entry(key: &VerifyingKey, plain: Domain, d: &[u8; 32], sig: &Signature) -> Option<Signed> {
    if key.verify(plain, d, sig).is_ok() {
        return Some(Signed::Plain);
    }
    key.verify(Domain::RoleEntry, d, sig).is_ok().then_some(Signed::RoleEntry)
}

/// A deposit signature by the deposit key under `"osis v1 deposit"`, or `"osis v1 role entry"`
/// for a request (`role`).
pub fn sign_deposit(deposit: &SigningSecret, sync_id: &SyncId, blob: &BlobId, wrap: &[u8], role: bool) -> Signature {
    deposit.sign(entry_domain(Domain::Deposit, role), &entry_digest(sync_id, blob, wrap))
}

/// Checks a deposit's signature against the head's deposit key, under either domain; an
/// altered wrap fails.
pub fn verify_deposit(head_deposit: &VerifyingKey, sync_id: &SyncId, blob: &BlobId, wrap: &[u8], sig: &Signature) -> Result<Signed, Error> {
    verify_entry(head_deposit, Domain::Deposit, &entry_digest(sync_id, blob, wrap), sig).ok_or(Error::Verify("deposit"))
}

/// The signing domain of an entry's stamp or deposit signature (`plain`: `Stamp` or
/// `Deposit`): `RoleEntry` for one deletes are judged by.
fn entry_domain(plain: Domain, role: bool) -> Domain {
    if role { Domain::RoleEntry } else { plain }
}

/// The role key a delete by delete keys at `levels` needs beside them (spec/sync-ids.md §6): the
/// write key when any is level 3, else the sync key; the delete key with no level.
pub fn key_for_levels(levels: &[Level]) -> Result<RoleKey, Error> {
    if levels.iter().any(|l| !(DELETE_ADMIN..=DELETE_WRITER).contains(l)) {
        return Err(Error::Malformed("delete level"));
    }
    Ok(if levels.is_empty() {
        RoleKey::Delete
    } else if levels.contains(&DELETE_WRITER) {
        RoleKey::Write
    } else {
        RoleKey::Sync
    })
}

/// The delete keys among `held` that a Delete by levels of a blob with `prefix` and blind `hb`
/// signs with (spec/sync-ids.md §6, spec/crypto.md §7): one per level, each matching a
/// commitment at its level, every group covered, the role key their levels need (`key_for_levels`)
/// one `may` holds; of such choices the fewest signatures, then the highest levels (the least
/// right). `None`: no such choice (a group none of `held` matches, an empty group, no role key).
/// Brute force over the held keys matching at each level: a rare path.
pub fn cover_levels<'a>(prefix: &Prefix, hb: &[u8; 16], held: &'a [(Level, DeleteSecret)], may: impl Fn(RoleKey) -> bool) -> Option<Vec<(Level, &'a DeleteSecret)>> {
    let groups = prefix.groups().len();
    // per level, each held key matching a commitment there with the groups it covers
    let mut opts: [Vec<(&'a DeleteSecret, Vec<bool>)>; 3] = Default::default();
    for (level, d) in held {
        let Some(slot) = (DELETE_ADMIN..=DELETE_WRITER).contains(level).then(|| usize::from(level - DELETE_ADMIN)).and_then(|i| opts.get_mut(i)) else { continue };
        let blinded = osis_crypto::blind(&d.verifying_key(), prefix.salt(), hb).to_bytes();
        let covers: Vec<bool> = (0..groups).map(|gi| prefix.key_at(gi, *level) == Some(blinded)).collect();
        if covers.iter().any(|c| *c) && !slot.iter().any(|(_, c)| *c == covers) {
            slot.push((d, covers));
        }
    }
    let pick = |l: usize, i: usize| -> Option<(Level, &'a DeleteSecret, &Vec<bool>)> { i.checked_sub(1).and_then(|i| opts.get(l)?.get(i)).map(|(d, c)| (DELETE_ADMIN + l as u8, *d, c)) };
    let n = |l: usize| opts.get(l).map_or(0, Vec::len) + 1;
    let mut best: Option<Vec<(Level, &'a DeleteSecret)>> = None;
    for a in 0..n(0) {
        for b in 0..n(1) {
            for c in 0..n(2) {
                let chosen: Vec<_> = [pick(0, a), pick(1, b), pick(2, c)].into_iter().flatten().collect();
                let covered = (0..groups).all(|gi| chosen.iter().any(|(_, _, cov)| cov.get(gi).copied().unwrap_or(false)));
                let levels: Vec<Level> = chosen.iter().map(|x| x.0).collect();
                if groups == 0 || !covered || !key_for_levels(&levels).is_ok_and(&may) {
                    continue;
                }
                let better = best.as_ref().is_none_or(|b| {
                    let bl: Vec<Level> = b.iter().map(|x| x.0).collect();
                    (levels.len(), std::cmp::Reverse(levels.clone())) < (bl.len(), std::cmp::Reverse(bl))
                });
                if better {
                    best = Some(chosen.iter().map(|(l, d, _)| (*l, *d)).collect());
                }
            }
        }
    }
    best
}

/// A delete item `[blob_id, [[level, dsig]*], sig]` (spec/wire.md §11.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteItem {
    pub blob: BlobId,
    /// Signatures by delete keys, each under the blob's blinded key at its level in a commitment
    /// group (spec/crypto.md §7); levels ascending, distinct. Empty: by the sync ID delete key.
    pub by: Vec<(Level, Signature)>,
    pub sig: Signature,
}

/// Digest of a delete: BLAKE3 of canonical `[sync_id, blob_id, [level*]]` (spec/wire.md, Delete; the
/// conformance vectors sign it with each delete key).
pub fn delete_digest(sync_id: &SyncId, blob: &BlobId, levels: &[Level]) -> [u8; 32] {
    let v = Value::List(vec![Value::bytes(&sync_id.0), Value::bytes(&blob.0), Value::List(levels.iter().map(|l| Value::Int(i64::from(*l))).collect())]);
    osis_base::hash::hash(&encode(&v))
}

impl DeleteItem {
    /// Signed by the head's delete key alone.
    pub fn sign(delete: &SigningSecret, sync_id: &SyncId, blob: BlobId) -> DeleteItem {
        let sig = delete.sign(Domain::Delete, &delete_digest(sync_id, &blob, &[]));
        DeleteItem { blob, by: Vec::new(), sig }
    }

    /// Signed by the delete keys `dks` (one per level used, levels distinct) under the blob's
    /// prefix `salt` and its blind `hb` (a commit blob's header blind, a linked blob's link
    /// blind), and by the role key `key_for_levels` names.
    pub fn sign_by(key: &SigningSecret, dks: &[(Level, &DeleteSecret)], salt: &[u8; 16], hb: &[u8; 16], sync_id: &SyncId, blob: BlobId) -> Result<DeleteItem, Error> {
        let mut dks: Vec<(Level, &DeleteSecret)> = dks.to_vec();
        dks.sort_by_key(|(l, _)| *l);
        let levels: Vec<Level> = dks.iter().map(|(l, _)| *l).collect();
        if !levels.is_sorted_by(|a, b| a < b) || levels.is_empty() {
            return Err(Error::Malformed("delete levels"));
        }
        let d = delete_digest(sync_id, &blob, &levels);
        let by = dks.iter().map(|(l, dk)| (*l, dk.sign(salt, hb, &d))).collect();
        Ok(DeleteItem { blob, by, sig: key.sign(Domain::Delete, &d) })
    }

    /// The levels signed, ascending.
    pub fn levels(&self) -> Vec<Level> {
        self.by.iter().map(|(l, _)| *l).collect()
    }

    /// The check at a node that cannot read the sync ID, against its head and the entry's blob prefix (none: unknown framing, no
    /// commitments): without levels the delete key; with them, each delete-key signature under
    /// a group's commitment at its level, every group covered by one, and the role key the
    /// levels need (spec/sync-ids.md §6).
    pub fn verify(&self, head: &Step, prefix: Option<&Prefix>) -> Result<(), Error> {
        let levels = self.levels();
        let d = delete_digest(&head.sync_id, &self.blob, &levels);
        let role = key_for_levels(&levels)?;
        if !self.by.is_empty() {
            if !levels.is_sorted_by(|a, b| a < b) {
                return Err(Error::Malformed("delete levels"));
            }
            let prefix = prefix.ok_or(Error::Verify("no commitments"))?;
            let groups = prefix.groups();
            let mut covered = vec![false; groups.len()];
            for (level, dsig) in &self.by {
                let mut any = false;
                for (gi, c) in covered.iter_mut().enumerate() {
                    if prefix.key_at(gi, *level).is_some_and(|k| verify_delete(&k, &d, dsig).is_ok()) {
                        *c = true;
                        any = true;
                    }
                }
                if !any {
                    return Err(Error::Verify("delete-key signature"));
                }
            }
            if !covered.iter().all(|c| *c) {
                return Err(Error::Verify("a commitment group without a signature"));
            }
            if covered.is_empty() {
                return Err(Error::Verify("no commitment group"));
            }
        }
        head.keys.get(role).verify(Domain::Delete, &d, &self.sig).map_err(|_| Error::Verify("delete signature"))
    }

    pub fn to_value(&self) -> Value {
        let by = Value::List(self.by.iter().map(|(l, s)| Value::List(vec![Value::Int(i64::from(*l)), Value::bytes(&s.0)])).collect());
        Value::List(vec![Value::bytes(&self.blob.0), by, Value::bytes(&self.sig.0)])
    }

    pub fn from_value(v: &Value) -> Result<DeleteItem, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("delete item")) };
        let [blob, by, sig] = items.as_slice() else { return Err(Error::Malformed("delete item")) };
        Ok(DeleteItem {
            blob: BlobId(get_bytes(blob, "delete blob")?),
            by: by_from_value(by)?,
            sig: Signature(get_bytes(sig, "delete signature")?),
        })
    }
}

/// `[[level, dsig]*]`: levels ascending and distinct, within 1..=3.
fn by_from_value(v: &Value) -> Result<Vec<(Level, Signature)>, Error> {
    let Value::List(xs) = v else { return Err(Error::Malformed("delete levels")) };
    let mut out: Vec<(Level, Signature)> = Vec::with_capacity(xs.len());
    for x in xs {
        let Value::List(p) = x else { return Err(Error::Malformed("delete level")) };
        let [l, s] = p.as_slice() else { return Err(Error::Malformed("delete level")) };
        let l = u8::try_from(get_uint(l, "delete level")?).ok().filter(|l| (DELETE_ADMIN..=DELETE_WRITER).contains(l)).ok_or(Error::Malformed("delete level"))?;
        if out.last().is_some_and(|(p, _)| *p >= l) {
            return Err(Error::Malformed("delete levels not ascending"));
        }
        out.push((l, Signature(get_bytes(s, "delete-key signature")?)));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::step::tests::{Secrets, THING};
    use crate::step::{genesis, register};
    use osis_crypto::{Epoch, SeededRng, Secret32, role_key};

    fn epoch(n: u64) -> Epoch {
        Epoch::new(n, [n as u8; 32]).unwrap()
    }

    // spec/sync-ids.md §6, spec/wire.md §11.2: stamps and deposits verify
    // under their own key and domain only.
    #[test]
    fn entry_signatures() {
        let g = Secrets::new(30);
        let mut rng = SeededRng::from_u64(0);
        let (s0, _) = register(&genesis(&g.admin).0, &g.delete(), g.keys(), &[], (&THING, epoch(0), &g.read), g.sync_at(), &mut rng).unwrap();
        let (l, b, w) = (s0.sync_id, BlobId([1; 32]), [2u8; 49]);
        let write = role_key(RoleKey::Write, &g.write);
        let stamp = sign_stamp(&write, &l, &b, &w, false);
        assert_eq!(verify_stamp(&s0.keys.write, &l, &b, &w, &stamp).unwrap(), Signed::Plain);
        assert_eq!(verify_stamp(&s0.keys.write, &l, &b, &w, &sign_stamp(&write, &l, &b, &w, true)).unwrap(), Signed::RoleEntry, "a role entry's stamp says so");
        assert!(verify_stamp(&s0.keys.sync, &l, &b, &w, &stamp).is_err());
        let mut altered = w;
        altered[48] ^= 1;
        assert!(verify_stamp(&s0.keys.write, &l, &b, &altered, &stamp).is_err(), "a stamp binds the wrap");
        let digest = entry_digest(&l, &b, &w);
        assert!(s0.keys.write.verify(Domain::Deposit, &digest, &stamp).is_err());
        let dep = osis_crypto::deposit_key(&g.deposit, &l);
        s0.keys.deposit.verify(Domain::Deposit, &digest, &sign_deposit(&dep, &l, &b, &w, false)).unwrap();
    }

    // spec/sync-ids.md §6 (Delete): the keys `cover_levels` picks sign a Delete the
    // store's check takes (the oracle: `DeleteItem::verify`), whatever subset of the keys is held;
    // it picks none exactly when no held choice covers every group under a role key held, else the
    // best such choice (fewest signatures, then least right). Two
    // groups (two things' writes by one author: level 2 shared, levels 1 and 3 per thing) and an
    // empty one.
    #[test]
    fn cover_levels_signs_what_the_store_takes() {
        let g = Secrets::new(40);
        let mut rng = SeededRng::from_u64(0);
        let (s0, _) = register(&genesis(&g.admin).0, &g.delete(), g.keys(), &[], (&THING, epoch(0), &g.read), g.sync_at(), &mut rng).unwrap();
        let l = s0.sync_id;
        let (sync, write) = (role_key(RoleKey::Sync, &g.sync), role_key(RoleKey::Write, &g.write));
        let dk = |b: u8| DeleteSecret::write(&Secret32::from_bytes([b; 32]));
        let (a1, b1, author, a3, b3) = (dk(1), dk(2), dk(3), dk(4), dk(5));
        let (salt, hb, b) = ([5u8; 16], [7u8; 16], BlobId([9; 32]));
        let vk = |l: u8, d: &DeleteSecret| (l, d.verifying_key());
        let two = Prefix::for_groups(salt, &hb, None, &[vec![vk(1, &a1), vk(2, &author), vk(3, &a3)], vec![vk(1, &b1), vk(2, &author), vk(3, &b3)]]).unwrap();
        let empty = Prefix::for_groups(salt, &hb, None, &[vec![vk(2, &author)], vec![]]).unwrap();
        let all: [(Level, u8); 5] = [(1, 1), (1, 2), (2, 3), (3, 4), (3, 5)];
        for prefix in [&two, &empty] {
            for mask in 0u32..1 << all.len() {
                let held: Vec<(Level, DeleteSecret)> = all.iter().enumerate().filter(|(i, _)| mask & 1 << i != 0).map(|(_, (l, d))| (*l, dk(*d))).collect();
                for (role_keys, name) in [(vec![RoleKey::Sync, RoleKey::Write], "both"), (vec![RoleKey::Sync], "sync"), (vec![RoleKey::Write], "write")] {
                    let picked = cover_levels(prefix, &hb, &held, |r| role_keys.contains(&r));
                    // the best verifying choice among the held keys, under a role key held: fewest
                    // signatures, then the highest levels
                    let mut best: Option<(usize, std::cmp::Reverse<Vec<Level>>)> = None;
                    for sub in 1u32..1 << held.len() {
                        let dks: Vec<(Level, &DeleteSecret)> = held.iter().enumerate().filter(|(i, _)| sub & 1 << i != 0).map(|(_, (l, d))| (*l, d)).collect();
                        let levels: Vec<Level> = dks.iter().map(|x| x.0).collect();
                        let Ok(role) = key_for_levels(&levels) else { continue };
                        if !role_keys.contains(&role) || levels.windows(2).any(|w| w[0] == w[1]) {
                            continue;
                        }
                        let key = if role == RoleKey::Write { &write } else { &sync };
                        if DeleteItem::sign_by(key, &dks, &salt, &hb, &l, b).is_ok_and(|x| x.verify(&s0, Some(prefix)).is_ok()) {
                            let rank = (levels.len(), std::cmp::Reverse(levels));
                            best = Some(best.map_or(rank.clone(), |b| b.min(rank)));
                        }
                    }
                    match picked {
                        Some(dks) => {
                            let levels: Vec<Level> = dks.iter().map(|x| x.0).collect();
                            let role = key_for_levels(&levels).unwrap();
                            assert!(role_keys.contains(&role), "held {mask:#b} {name}: picked keys need a role key not held");
                            let key = if role == RoleKey::Write { &write } else { &sync };
                            assert!(DeleteItem::sign_by(key, &dks, &salt, &hb, &l, b).unwrap().verify(&s0, Some(prefix)).is_ok(), "held {mask:#b} {name}: picked keys refused");
                            assert_eq!(Some((levels.len(), std::cmp::Reverse(levels))), best, "held {mask:#b} {name}: not the fewest signatures, then least right");
                        }
                        None => assert!(best.is_none(), "held {mask:#b} {name}: a covering choice exists"),
                    }
                }
            }
        }
        // the author's own key covers both groups in one signature, with the sync key alone
        let held = vec![(2, dk(3)), (3, dk(4)), (3, dk(5))];
        assert_eq!(cover_levels(&two, &hb, &held, |_| true).map(|d| d.iter().map(|x| x.0).collect::<Vec<_>>()), Some(vec![2]));
    }

    // spec/sync-ids.md §6, spec/crypto.md §7: delete by the sync ID delete key; by a level's delete
    // key with the role key the level needs; a wrong level, a forged or unblinded key, a
    // missing commitment fail; layouts round trip.
    #[test]
    fn deletes() {
        let g = Secrets::new(40);
        let mut rng = SeededRng::from_u64(0);
        let (s0, _) = register(&genesis(&g.admin).0, &g.delete(), g.keys(), &[], (&THING, epoch(0), &g.read), g.sync_at(), &mut rng).unwrap();
        let l = s0.sync_id;
        let (sync, write) = (role_key(RoleKey::Sync, &g.sync), role_key(RoleKey::Write, &g.write));
        let salt = [5u8; 16];
        let (d2, d3) = (DeleteSecret::write(&Secret32::from_bytes([1; 32])), DeleteSecret::write(&Secret32::from_bytes([2; 32])));
        let hb = [7u8; 16];
        let prefix = Prefix::for_keys(salt, &hb, None, &[(2, d2.verifying_key()), (3, d3.verifying_key())]).unwrap();
        let b = BlobId([9; 32]);
        let by = |key: &SigningSecret, dks: &[(Level, &DeleteSecret)], salt: &[u8; 16], hb: &[u8; 16]| DeleteItem::sign_by(key, dks, salt, hb, &l, b).unwrap();
        DeleteItem::sign(&g.delete(), &l, b).verify(&s0, None).unwrap();
        by(&sync, &[(2, &d2)], &salt, &hb).verify(&s0, Some(&prefix)).unwrap();
        by(&write, &[(3, &d3)], &salt, &hb).verify(&s0, Some(&prefix)).unwrap();
        // level 3 needs the write key, level 2 the sync key; both levels at once the write key
        assert!(by(&sync, &[(3, &d3)], &salt, &hb).verify(&s0, Some(&prefix)).is_err());
        assert!(by(&write, &[(2, &d2)], &salt, &hb).verify(&s0, Some(&prefix)).is_err());
        by(&write, &[(2, &d2), (3, &d3)], &salt, &hb).verify(&s0, Some(&prefix)).unwrap();
        assert!(by(&sync, &[(2, &d2), (3, &d3)], &salt, &hb).verify(&s0, Some(&prefix)).is_err());
        // a key at another level, a forged key, another salt, no prefix
        assert!(by(&sync, &[(2, &d3)], &salt, &hb).verify(&s0, Some(&prefix)).is_err());
        assert!(by(&sync, &[(1, &d2)], &salt, &hb).verify(&s0, Some(&prefix)).is_err());
        let forged = DeleteSecret::write(&Secret32::from_bytes([3; 32]));
        assert!(by(&sync, &[(2, &forged)], &salt, &hb).verify(&s0, Some(&prefix)).is_err());
        assert!(by(&sync, &[(2, &d2)], &[6; 16], &hb).verify(&s0, Some(&prefix)).is_err());
        assert!(by(&sync, &[(2, &d2)], &salt, &[9; 16]).verify(&s0, Some(&prefix)).is_err(), "another header's blind");
        assert!(by(&sync, &[(2, &d2)], &salt, &hb).verify(&s0, None).is_err());
        // a signature that verifies under no group, beside one that does, refuses the item
        let mut extra = by(&sync, &[(2, &d2)], &salt, &hb);
        extra.by.push((3, forged.sign(&salt, &hb, &[0; 32])));
        assert!(extra.verify(&s0, Some(&prefix)).is_err());
        // the sync-ID-key signature binds the levels: moved to level 3 it fails
        let mut moved = by(&sync, &[(2, &d2)], &salt, &hb);
        moved.by = moved.by.iter().map(|(_, s)| (3, *s)).collect();
        assert!(moved.verify(&s0, Some(&prefix)).is_err());
        assert!(DeleteItem::sign(&sync, &l, b).verify(&s0, None).is_err());
        // groups (spec/sync-ids.md §6): a Delete needs a signature under every group; an empty group
        // blocks a Delete by level; no group refuses one; the author key shared by both
        // groups covers both with one signature
        let d1 = DeleteSecret::write(&Secret32::from_bytes([4; 32]));
        let two = Prefix::for_groups(salt, &hb, None, &[vec![(2, d2.verifying_key()), (3, d3.verifying_key())], vec![(1, d1.verifying_key()), (2, d2.verifying_key())]]).unwrap();
        assert!(by(&write, &[(3, &d3)], &salt, &hb).verify(&s0, Some(&two)).is_err());
        by(&write, &[(1, &d1), (3, &d3)], &salt, &hb).verify(&s0, Some(&two)).unwrap();
        by(&sync, &[(2, &d2)], &salt, &hb).verify(&s0, Some(&two)).unwrap();
        let nobody = Prefix::for_groups(salt, &hb, None, &[vec![(2, d2.verifying_key())], vec![]]).unwrap();
        assert!(by(&sync, &[(2, &d2)], &salt, &hb).verify(&s0, Some(&nobody)).is_err());
        let none = Prefix::new(salt, None, vec![]).unwrap();
        assert!(by(&sync, &[(2, &d2)], &salt, &hb).verify(&s0, Some(&none)).is_err());
        let item = by(&sync, &[(2, &d2)], &salt, &hb);
        assert_eq!(DeleteItem::from_value(&item.to_value()).unwrap(), item);
        let mut v = item.to_value();
        if let Value::List(x) = &mut v {
            x[2] = Value::List(vec![Value::List(vec![Value::Int(4), Value::bytes(&[0; 64])])]);
        }
        assert!(DeleteItem::from_value(&v).is_err());
        let mut v = item.to_value();
        if let Value::List(x) = &mut v {
            x[2] = Value::List(vec![Value::List(vec![Value::Int(3), Value::bytes(&[0; 64])]), Value::List(vec![Value::Int(2), Value::bytes(&[0; 64])])]);
        }
        assert!(DeleteItem::from_value(&v).is_err(), "levels not ascending");
        assert!(key_for_levels(&[0]).is_err());
    }
}
