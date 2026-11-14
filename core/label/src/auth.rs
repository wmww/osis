//! Signatures of label operations and their checks at a node that cannot read the label
//! (spec/sync-ids.md §6, spec/wire.md §9, §11.2): stamps, deposits, deletes by the label delete key
//! or by a delete-key signature.

use crate::blob::{Level, Prefix};
use crate::cbor::{get_bytes, get_uint};
use crate::step::Step;
use crate::Error;
use osis_base::cbor::encode;
use osis_base::format::{DELETE_ADMIN, DELETE_WRITER};
use osis_base::{BlobId, CommitId, SyncId, Tid, Value};
use osis_crypto::{DeleteSecret, Domain, LabelRole, Signature, SigningSecret, VerifyingKey, verify_delete};

/// Digest of a stamp, deposit or publish authorization: BLAKE3 of canonical
/// `[sync_id, blob_id, wrap]`.
pub fn entry_digest(label: &SyncId, blob: &BlobId, wrap: &[u8]) -> [u8; 32] {
    osis_base::hash::hash(&encode(&Value::List(vec![Value::bytes(&label.0), Value::bytes(&blob.0), Value::bytes(wrap)])))
}

/// A stamp: the label write key's signature under `"osis v1 upload"`, or `"osis v1 role
/// entry"` for an entry deletes are judged by (`role`: a role commit or a request).
pub fn sign_stamp(write: &SigningSecret, label: &SyncId, blob: &BlobId, wrap: &[u8], role: bool) -> Signature {
    write.sign(entry_domain(Domain::Stamp, role), &entry_digest(label, blob, wrap))
}

/// Checks a stamp against the head's write key, under either domain; an altered wrap fails.
/// Whether it is a role entry's (`"osis v1 role entry"`).
pub fn verify_stamp(head_write: &VerifyingKey, label: &SyncId, blob: &BlobId, wrap: &[u8], stamp: &Signature) -> Result<bool, Error> {
    verify_entry(head_write, Domain::Stamp, &entry_digest(label, blob, wrap), stamp).ok_or(Error::Verify("stamp"))
}

/// Which domain of an entry's signature verifies: `Some(true)` a role entry's.
fn verify_entry(key: &VerifyingKey, plain: Domain, d: &[u8; 32], sig: &Signature) -> Option<bool> {
    if key.verify(plain, d, sig).is_ok() {
        return Some(false);
    }
    key.verify(Domain::RoleEntry, d, sig).is_ok().then_some(true)
}

/// A deposit signature by the deposit key under `"osis v1 deposit"`, or `"osis v1 role entry"`
/// for a request (`role`).
pub fn sign_deposit(deposit: &SigningSecret, label: &SyncId, blob: &BlobId, wrap: &[u8], role: bool) -> Signature {
    deposit.sign(entry_domain(Domain::Deposit, role), &entry_digest(label, blob, wrap))
}

/// Checks a deposit's signature against the head's deposit key, under either domain; an
/// altered wrap fails. Whether it is a role entry's.
pub fn verify_deposit(head_deposit: &VerifyingKey, label: &SyncId, blob: &BlobId, wrap: &[u8], sig: &Signature) -> Result<bool, Error> {
    verify_entry(head_deposit, Domain::Deposit, &entry_digest(label, blob, wrap), sig).ok_or(Error::Verify("deposit"))
}

/// Digest of a removal signature (spec/wire.md §9 position 5): BLAKE3 of canonical
/// `[sync_id, recipient, commit_id, epoch]`, `epoch` the newest sync epoch number the sender
/// boxed the recipient at.
pub fn removal_digest(s: &SyncId, recipient: &Tid, commit: &CommitId, epoch: u64) -> [u8; 32] {
    osis_base::hash::hash(&encode(&Value::List(vec![Value::bytes(&s.0), Value::bytes(recipient.as_bytes()), Value::bytes(&commit.0), Value::uint(epoch)])))
}

/// A removal signature by a step's delete key under `"osis v1 removal"`.
pub fn sign_removal(delete: &SigningSecret, s: &SyncId, recipient: &Tid, commit: &CommitId, epoch: u64) -> Signature {
    delete.sign(Domain::Removal, &removal_digest(s, recipient, commit, epoch))
}

/// Checks a removal signature against a step's delete key.
pub fn verify_removal(delete: &VerifyingKey, s: &SyncId, recipient: &Tid, commit: &CommitId, epoch: u64, sig: &Signature) -> Result<(), Error> {
    delete.verify(Domain::Removal, &removal_digest(s, recipient, commit, epoch), sig).map_err(|_| Error::Verify("removal"))
}

/// The signing domain of an entry's stamp or deposit signature (`plain`: `Stamp` or
/// `Deposit`): `RoleEntry` for one deletes are judged by.
fn entry_domain(plain: Domain, role: bool) -> Domain {
    if role { Domain::RoleEntry } else { plain }
}

/// The label key a delete by delete keys at `levels` needs beside them (spec/sync-ids.md §6): the
/// write key when any is level 3, else the sync key; the delete key with no level.
pub fn key_for_levels(levels: &[Level]) -> Result<LabelRole, Error> {
    if levels.iter().any(|l| !(DELETE_ADMIN..=DELETE_WRITER).contains(l)) {
        return Err(Error::Malformed("delete level"));
    }
    Ok(if levels.is_empty() {
        LabelRole::Delete
    } else if levels.contains(&DELETE_WRITER) {
        LabelRole::Write
    } else {
        LabelRole::Sync
    })
}

/// A delete item `[blob_id, [[level, dsig]*], sig]` (spec/wire.md §11.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteItem {
    pub blob: BlobId,
    /// Signatures by delete keys, each under the blob's blinded key at its level in a commitment
    /// group (spec/crypto.md §7); levels ascending, distinct. Empty: by the label delete key.
    pub by: Vec<(Level, Signature)>,
    pub sig: Signature,
}

/// Digest of a delete: BLAKE3 of canonical `[sync_id, blob_id, [level*]]`.
pub fn delete_digest(label: &SyncId, blob: &BlobId, levels: &[Level]) -> [u8; 32] {
    let v = Value::List(vec![Value::bytes(&label.0), Value::bytes(&blob.0), Value::List(levels.iter().map(|l| Value::Int(i64::from(*l))).collect())]);
    osis_base::hash::hash(&encode(&v))
}

impl DeleteItem {
    /// Signed by the head's delete key alone.
    pub fn sign(delete: &SigningSecret, label: &SyncId, blob: BlobId) -> DeleteItem {
        let sig = delete.sign(Domain::Delete, &delete_digest(label, &blob, &[]));
        DeleteItem { blob, by: Vec::new(), sig }
    }

    /// Signed by the delete keys `dks` (one per level used, levels distinct) under the blob's
    /// prefix `salt` and its blind `hb` (a commit blob's header blind, a linked blob's link
    /// blind), and by the label key `key_for_levels` names.
    pub fn sign_by(key: &SigningSecret, dks: &[(Level, &DeleteSecret)], salt: &[u8; 16], hb: &[u8; 16], label: &SyncId, blob: BlobId) -> Result<DeleteItem, Error> {
        let mut dks: Vec<(Level, &DeleteSecret)> = dks.to_vec();
        dks.sort_by_key(|(l, _)| *l);
        let levels: Vec<Level> = dks.iter().map(|(l, _)| *l).collect();
        if !levels.is_sorted_by(|a, b| a < b) || levels.is_empty() {
            return Err(Error::Malformed("delete levels"));
        }
        let d = delete_digest(label, &blob, &levels);
        let by = dks.iter().map(|(l, dk)| (*l, dk.sign(salt, hb, &d))).collect();
        Ok(DeleteItem { blob, by, sig: key.sign(Domain::Delete, &d) })
    }

    /// The levels signed, ascending.
    pub fn levels(&self) -> Vec<Level> {
        self.by.iter().map(|(l, _)| *l).collect()
    }

    /// The check at a node that cannot read the label, against its head and the entry's blob prefix (none: unknown framing, no
    /// commitments): without levels the delete key; with them, each delete-key signature under
    /// a group's commitment at its level, every group covered by one, and the label key the
    /// levels need (spec/sync-ids.md §6).
    pub fn verify(&self, head: &Step, prefix: Option<&Prefix>) -> Result<(), Error> {
        let levels = self.levels();
        let d = delete_digest(&head.label, &self.blob, &levels);
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
    use crate::step::tests::{Group, TG};
    use crate::step::{Parent, register};
    use osis_crypto::{Epoch, SeededRng, Secret32, label_role_key};
    use proptest::prelude::*;

    fn epoch(n: u64) -> Epoch {
        Epoch::new(n, [n as u8; 32]).unwrap()
    }

    // spec/sync-ids.md §6, spec/wire.md §11.2: stamps and deposits verify
    // under their own key and domain only.
    #[test]
    fn entry_signatures() {
        let g = Group::new(30);
        let mut rng = SeededRng::from_u64(0);
        let (s0, _) = register(Parent::Genesis(&g.delete()), g.keys(), &[], (&TG, epoch(0), &g.read), g.sync_at(), &mut rng).unwrap();
        let (l, b, w) = (s0.label, BlobId([1; 32]), [2u8; 49]);
        let write = label_role_key(LabelRole::Write, &g.write);
        let stamp = sign_stamp(&write, &l, &b, &w, false);
        assert!(!verify_stamp(&s0.keys.write, &l, &b, &w, &stamp).unwrap());
        assert!(verify_stamp(&s0.keys.write, &l, &b, &w, &sign_stamp(&write, &l, &b, &w, true)).unwrap(), "a role entry's stamp says so");
        assert!(verify_stamp(&s0.keys.sync, &l, &b, &w, &stamp).is_err());
        let digest = entry_digest(&l, &b, &w);
        assert!(s0.keys.write.verify(Domain::Deposit, &digest, &stamp).is_err());
        let dep = osis_crypto::deposit_key(&g.deposit, &l);
        s0.keys.deposit.verify(Domain::Deposit, &digest, &sign_deposit(&dep, &l, &b, &w, false)).unwrap();
    }

    // spec/sync-ids.md §6, spec/crypto.md §7: delete by the label delete key; by a level's delete
    // key with the label key the level needs; a wrong level, a forged or unblinded key, a
    // missing commitment fail; layouts round trip.
    #[test]
    fn deletes() {
        let g = Group::new(40);
        let mut rng = SeededRng::from_u64(0);
        let (s0, _) = register(Parent::Genesis(&g.delete()), g.keys(), &[], (&TG, epoch(0), &g.read), g.sync_at(), &mut rng).unwrap();
        let l = s0.label;
        let (sync, write) = (label_role_key(LabelRole::Sync, &g.sync), label_role_key(LabelRole::Write, &g.write));
        let salt = [5u8; 16];
        let (d2, d3) = (DeleteSecret::derive(&Secret32::from_bytes([1; 32])), DeleteSecret::derive(&Secret32::from_bytes([2; 32])));
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
        let forged = DeleteSecret::derive(&Secret32::from_bytes([3; 32]));
        assert!(by(&sync, &[(2, &forged)], &salt, &hb).verify(&s0, Some(&prefix)).is_err());
        assert!(by(&sync, &[(2, &d2)], &[6; 16], &hb).verify(&s0, Some(&prefix)).is_err());
        assert!(by(&sync, &[(2, &d2)], &salt, &[9; 16]).verify(&s0, Some(&prefix)).is_err(), "another header's blind");
        assert!(by(&sync, &[(2, &d2)], &salt, &hb).verify(&s0, None).is_err());
        // a signature that verifies under no group, beside one that does, refuses the item
        let mut extra = by(&sync, &[(2, &d2)], &salt, &hb);
        extra.by.push((3, forged.sign(&salt, &hb, &[0; 32])));
        assert!(extra.verify(&s0, Some(&prefix)).is_err());
        // the label-key signature binds the levels: moved to level 3 it fails
        let mut moved = by(&sync, &[(2, &d2)], &salt, &hb);
        moved.by = moved.by.iter().map(|(_, s)| (3, *s)).collect();
        assert!(moved.verify(&s0, Some(&prefix)).is_err());
        assert!(DeleteItem::sign(&sync, &l, b).verify(&s0, None).is_err());
        // groups (spec/sync-ids.md §6): a Delete needs a signature under every group; an empty group
        // blocks a Delete by level; no group refuses one; the author key shared by both
        // groups covers both with one signature
        let d1 = DeleteSecret::derive(&Secret32::from_bytes([4; 32]));
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

    proptest! {
        // spec/sync-ids.md §6: a stamp binds the wrap: any altered wrap byte fails.
        #[test]
        fn stamp_binds_wrap(i in 0usize..49, x in 1u8..=255) {
            let write = label_role_key(LabelRole::Write, &Secret32::from_bytes([1; 32]));
            let (l, b, w) = (SyncId([1; 16]), BlobId([2; 32]), [3u8; 49]);
            let stamp = sign_stamp(&write, &l, &b, &w, false);
            let mut w2 = w;
            w2[i] ^= x;
            prop_assert!(verify_stamp(&write.verifying_key(), &l, &b, &w2, &stamp).is_err());
            prop_assert!(verify_stamp(&write.verifying_key(), &l, &b, &w, &stamp).is_ok());
        }
    }
}
