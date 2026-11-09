//! `keys.0` and `secrets.0` contents and the writes rotations, grants and re-seals make to them
//! (spec/crypto.md §3, §4; types: osis-schema `core_types`).

use crate::epoch::{ActorEpochs, SUITE};
use crate::names::Names;
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

/// The keyset of a role epoch: its KEM public key `kdf("kem", secret)`, delete key and
/// possession key (spec/crypto.md §3, §7, §4), listing `supersedes` and the digest of the
/// rotation's `names` (§4), with no possession proofs yet (`produce::rotate` adds them).
pub fn keyset(epoch: &Epoch, secret: &Secret32, supersedes: &BTreeSet<Epoch>, names: &Names) -> Keyset {
    Keyset {
        epoch: to_schema(epoch),
        kem_key: KemKey::X25519MlKem768(role_kem(secret).public().as_bytes().to_vec()),
        suite: SUITE,
        delete_key: SigningKey::Ed25519(DeleteSecret::derive(secret).verifying_key().to_bytes().to_vec()),
        supersedes: supersedes.iter().map(to_schema).collect(),
        possession_key: SigningKey::Ed25519(crate::possession::possession_key(secret).to_bytes().to_vec()),
        names: names.digest(),
        proofs: BTreeMap::new(),
    }
}

/// What the rotation writing keyset `ks` supersedes, as its keyset lists it (spec/crypto.md §4).
fn superseded_of(ks: &Keyset) -> Result<BTreeSet<Epoch>, Error> {
    ks.supersedes.iter().map(from_schema).collect()
}

/// A write to `secrets.0`: boxes put, boxes removed, history boxes put (spec/crypto.md §4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretsWrite {
    pub boxes: BTreeMap<BoxKey, SecretBox>,
    pub removed: BTreeSet<BoxKey>,
    pub history: BTreeMap<HistoryKey, Vec<u8>>,
}

impl SecretsWrite {
    /// Applies the write: removals first (they name only boxes held when it was made), then puts.
    /// Two concurrent writes apply in either order to the same state, since each removes only
    /// boxes keyed at epochs it superseded, never the other's new ones.
    pub fn apply(&self, s: &mut Secrets) {
        for k in &self.removed {
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
        for k in &other.removed {
            self.boxes.remove(k);
        }
        self.boxes.extend(other.boxes);
        self.removed.extend(other.removed);
        self.history.extend(other.history);
    }

    pub fn is_empty(&self) -> bool {
        self.boxes.is_empty() && self.removed.is_empty() && self.history.is_empty()
    }

    /// Records the epochs the write names in `epochs` (a received commit's delta): its box and
    /// history keys. What a rotation supersedes is its commit's (`rotated`). Establishes nothing.
    pub fn observe(&self, epochs: &mut ActorEpochs) -> Result<(), Error> {
        for k in self.history.keys() {
            epochs.role_mut(k.role).observe(from_schema(&k.epoch)?);
        }
        for k in self.boxes.keys() {
            epochs.role_mut(k.role).observe(from_schema(&k.epoch)?);
        }
        Ok(())
    }

    /// The rotations this write makes as part of a rotation commit (spec/crypto.md §4): each
    /// keyset the commit's `keys.0` write `keys` sets whose epoch this write puts a history box
    /// at, with what that keyset lists as superseded. A grant or re-seal re-writes history boxes
    /// but writes no keyset, so it makes none. Superseded epochs not below e are kept here;
    /// `RoleEpochs` drops them.
    pub fn rotation_commit(&self, keys: &KeysWrite) -> Result<Vec<(Role, Epoch, BTreeSet<Epoch>)>, Error> {
        let mut out = Vec::new();
        for (r, ks) in &keys.keysets {
            if self.history.contains_key(&HistoryKey { role: *r, epoch: ks.epoch.clone() }) {
                out.push((*r, from_schema(&ks.epoch)?, superseded_of(ks)?));
            }
        }
        Ok(out)
    }

    /// The held commit `commit` carrying this write (and `keys.0` write `keys`) is applied and
    /// valid: records its epochs and its rotations (spec/crypto.md §4). An invalid commit's
    /// epochs count for nothing, so it is never recorded. Establishes nothing (the caller's
    /// view does, `ActorEpochs::establish`). Returns whether a rotation recorded is new.
    pub fn rotated(&self, epochs: &mut ActorEpochs, commit: CommitId, keys: &KeysWrite) -> Result<bool, Error> {
        self.observe(epochs)?;
        let mut recorded = false;
        for (r, e, sup) in self.rotation_commit(keys)? {
            recorded |= epochs.role_mut(r).set_rotation(e, commit, sup);
        }
        Ok(recorded)
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

/// Held valid compaction snapshot `commit` of `secrets.0` (`s`, its pages joined) keys these
/// epochs (spec/crypto.md §4: a base of establishment). Returns whether anything changed: what
/// the caller persists.
pub fn snapshot_keyed(s: &Secrets, commit: CommitId, epochs: &mut ActorEpochs) -> Result<bool, Error> {
    let mut changed = false;
    for (r, e) in keyed(s)? {
        changed |= epochs.role_mut(r).set_snapshot(e, commit);
    }
    Ok(changed)
}

/// The `secrets.0` compaction gate (spec/crypto.md §4): every epoch the state `s` keys is
/// established, so the snapshot vouches for nothing this node did not verify.
pub fn may_compact_secrets(s: &Secrets, epochs: &ActorEpochs) -> Result<bool, Error> {
    Ok(keyed(s)?.iter().all(|(r, e)| epochs.role(*r).is_established(e)))
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
