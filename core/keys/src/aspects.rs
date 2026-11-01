//! `keys.0` and `secrets.0` contents and the writes rotations, grants and re-seals make to them
//! (spec/crypto.md §3, §4; types: osis-schema `core_types`).

use crate::epoch::{ActorEpochs, ROLES, SUITE, Superseded};
use crate::Error;
use osis_base::{CommitId, Role};
use osis_crypto::{DeleteSecret, Epoch, Secret32, role_kem};
use osis_schema::core_types::{self as ct, BoxKey, HistoryKey, KemKey, Keys, Keyset, SecretBox, Secrets, SigningKey};
use std::collections::{BTreeMap, BTreeSet};

pub fn to_schema(e: &Epoch) -> ct::Epoch {
    ct::Epoch { n: e.n(), nonce: *e.nonce() }
}

pub fn from_schema(e: &ct::Epoch) -> Result<Epoch, Error> {
    Ok(Epoch::new(e.n, e.nonce)?)
}

pub fn box_key(holder: osis_base::Tid, role: Role, epoch: &Epoch) -> BoxKey {
    BoxKey { holder, role, epoch: to_schema(epoch) }
}

pub fn history_key(role: Role, epoch: &Epoch) -> HistoryKey {
    HistoryKey { role, epoch: to_schema(epoch) }
}

/// The keyset of a role epoch: its KEM public key `kdf("kem", secret)` and delete key
/// (spec/crypto.md §3, §7).
pub fn keyset(epoch: &Epoch, secret: &Secret32) -> Keyset {
    Keyset {
        epoch: to_schema(epoch),
        kem_key: KemKey::X25519MlKem768(role_kem(secret).public().as_bytes().to_vec()),
        suite: SUITE,
        delete_key: SigningKey::Ed25519(DeleteSecret::derive(secret).verifying_key().to_bytes().to_vec()),
    }
}

/// A write to `secrets.0`: boxes put, boxes removed, history boxes put (spec/crypto.md §4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretsWrite {
    pub boxes: BTreeMap<BoxKey, SecretBox>,
    /// Each removed box with the commits that wrote the records removed (their dots, in a
    /// received delta; empty in a write being made).
    pub removed: BTreeMap<BoxKey, BTreeSet<CommitId>>,
    pub history: BTreeMap<HistoryKey, Vec<u8>>,
}

impl SecretsWrite {
    /// Applies the write: removals first (they name only boxes held when it was made), then puts.
    /// Two concurrent writes apply in either order to the same state, since each removes only
    /// boxes keyed at epochs it superseded, never the other's new ones.
    pub fn apply(&self, s: &mut Secrets) {
        for k in self.removed.keys() {
            s.boxes.remove(k);
        }
        s.boxes.extend(self.boxes.iter().map(|(k, v)| (k.clone(), v.clone())));
        s.history.extend(self.history.iter().map(|(k, v)| (k.clone(), v.clone())));
    }

    /// Appends a later write: its puts and removals win over this one's.
    pub fn extend(&mut self, other: SecretsWrite) {
        for k in &other.boxes {
            self.removed.remove(k.0);
        }
        for k in other.removed.keys() {
            self.boxes.remove(k);
        }
        self.boxes.extend(other.boxes);
        for (k, by) in other.removed {
            self.removed.entry(k).or_default().extend(by);
        }
        self.history.extend(other.history);
    }

    pub fn is_empty(&self) -> bool {
        self.boxes.is_empty() && self.removed.is_empty() && self.history.is_empty()
    }

    /// The epochs this write introduces per role and what each supersedes as the write itself
    /// says, the same at every node (spec/crypto.md §4): a history box written for (r, e) with
    /// the epochs of the boxes of r it removes, each with the commits that wrote the records
    /// removed there. A grant or re-seal re-writes history boxes and
    /// removes nothing, so it supersedes nothing. What e's history box lists supersedes too, for
    /// a node that opens it (`open_histories`). Superseded epochs not below e are kept here;
    /// `RoleEpochs` drops them.
    pub fn rotations(&self) -> Result<Vec<(Role, Epoch, Superseded)>, Error> {
        let mut out = Vec::new();
        for k in self.history.keys() {
            let e = from_schema(&k.epoch)?;
            let mut sup = Superseded::new();
            for (b, by) in self.removed.iter().filter(|(b, _)| b.role == k.role) {
                sup.entry(from_schema(&b.epoch)?).or_default().extend(by.iter().copied());
            }
            out.push((k.role, e, sup));
        }
        Ok(out)
    }

    /// Records the epochs the write names in `epochs` (a received commit's delta). What its
    /// rotations supersede is the commit's claims' (`claimed`). Establishes nothing.
    pub fn observe(&self, epochs: &mut ActorEpochs) -> Result<(), Error> {
        for (r, e, _) in self.rotations()? {
            epochs.role_mut(r).observe(e);
        }
        for k in self.boxes.keys() {
            epochs.role_mut(k.role).observe(from_schema(&k.epoch)?);
        }
        Ok(())
    }

    /// The rotations this write makes as part of a rotation commit: its history boxes at the
    /// epochs whose keyset the commit's `keys.0` write `keys` sets. A grant or re-seal re-writes
    /// history boxes but writes no keyset, so it makes none (spec/crypto.md §4).
    pub fn rotation_commit(&self, keys: &KeysWrite) -> Result<Vec<(Role, Epoch, Superseded)>, Error> {
        Ok(self.rotations()?.into_iter().filter(|(r, e, _)| keys.keysets.get(r).is_some_and(|ks| ks.epoch == to_schema(e))).collect())
    }

    /// The held commit `commit` carrying this write (and `keys.0` write `keys`) is applied and
    /// valid (`valid`), or held and invalid: records its rotations as claims by it, and when
    /// valid its epochs, then recomputes establishment (spec/crypto.md §4: an invalid commit's
    /// epochs count for nothing but the chain passing through them). Returns whether
    /// establishment or a claim recorded changed (persist then).
    pub fn claimed(&self, epochs: &mut ActorEpochs, commit: CommitId, keys: &KeysWrite, valid: bool) -> Result<bool, Error> {
        if valid {
            self.observe(epochs)?;
        }
        let mut recorded = false;
        for (r, e, sup) in self.rotation_commit(keys)? {
            recorded |= epochs.role_mut(r).set_claim(e, commit, valid, sup);
        }
        Ok(epochs.establish() | recorded)
    }
}

/// Every (role, epoch) the `secrets.0` state keys (box and history keys).
fn keyed(s: &Secrets) -> Result<Vec<(Role, Epoch)>, Error> {
    s.boxes.keys().map(|k| (k.role, &k.epoch)).chain(s.history.keys().map(|k| (k.role, &k.epoch))).map(|(r, e)| Ok((r, from_schema(e)?))).collect()
}

/// Records every epoch the applied `secrets.0` state names (box and history keys). Establishes
/// nothing (spec/crypto.md §4: a box or history box names an epoch without establishing it).
pub fn observe_secrets(s: &Secrets, epochs: &mut ActorEpochs) -> Result<(), Error> {
    for (r, e) in keyed(s)? {
        epochs.role_mut(r).observe(e);
    }
    Ok(())
}

/// A held compaction snapshot of `secrets.0` (`s`, its pages joined) keys these epochs: they are
/// established (`Snapshot`, spec/crypto.md §4). Returns whether anything changed (an epoch's
/// snapshot mark or establishment): what the caller persists.
pub fn snapshot_keyed(s: &Secrets, epochs: &mut ActorEpochs) -> Result<bool, Error> {
    let mut changed = false;
    for (r, e) in keyed(s)? {
        changed |= epochs.role_mut(r).set_snapshot(e);
    }
    Ok(epochs.establish() | changed)
}

/// The `secrets.0` compaction gate (spec/crypto.md §4): every epoch the state `s` keys is
/// established, so the snapshot vouches for nothing this node did not verify.
pub fn may_compact_secrets(s: &Secrets, epochs: &ActorEpochs) -> Result<bool, Error> {
    Ok(keyed(s)?.iter().all(|(r, e)| epochs.role(*r).is_established(e)))
}

/// Records the suite each keyset of `keys.0` names for its epoch. Establishes nothing.
pub fn observe_keys(k: &Keys, epochs: &mut ActorEpochs) -> Result<(), Error> {
    for r in ROLES {
        if let Some(ks) = keyset_of(k, r) {
            epochs.role_mut(r).set_suite(from_schema(&ks.epoch)?, ks.suite);
        }
    }
    Ok(())
}

/// A write to `keys.0` by a rotation: the rotated roles' keysets (spec/crypto.md §3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeysWrite {
    pub keysets: BTreeMap<Role, Keyset>,
}

impl KeysWrite {
    pub fn apply(&self, k: &mut Keys) {
        for (r, ks) in &self.keysets {
            let slot = match r {
                Role::Read => &mut k.read,
                Role::Write => &mut k.write,
                Role::Admin => &mut k.admin,
            };
            *slot = Some(ks.clone());
        }
    }
}

/// The keyset of `role` in `keys.0`.
pub fn keyset_of(k: &Keys, role: Role) -> Option<&Keyset> {
    match role {
        Role::Read => k.read.as_ref(),
        Role::Write => k.write.as_ref(),
        Role::Admin => k.admin.as_ref(),
    }
}
