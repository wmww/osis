//! `/keys` and `/secrets` contents and the writes rotations, grants and re-seals make to them
//! (spec/crypto.md §3, §4; types: osis-schema `core_types`).

use crate::epoch::{ActorEpochs, SUITE};
use crate::Error;
use osis_base::Role;
use osis_crypto::{DeleteSecret, Epoch, Secret32, role_kem};
use osis_schema::core_types::{self as ct, BoxKey, HistoryKey, KemKey, Keys, Keyset, SecretBox, Secrets, SigningKey};
use std::collections::{BTreeMap, BTreeSet};

pub fn to_schema(e: &Epoch) -> ct::Epoch {
    ct::Epoch { n: e.n(), nonce: *e.nonce() }
}

pub fn from_schema(e: &ct::Epoch) -> Result<Epoch, Error> {
    Ok(Epoch::new(e.n, e.nonce)?)
}

pub fn box_key(member: osis_base::Tid, role: Role, epoch: &Epoch) -> BoxKey {
    BoxKey { member, role, epoch: to_schema(epoch) }
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

/// Records the keysets of the actor's `/keys` (`RoleEpochs::set_keyset`): the keyset of an
/// epoch names the KEM and delete keys derived from its genuine secret (spec/crypto.md §3), so
/// a planted secret for a published epoch never stays. Returns (anything changed, a held secret
/// dropped).
pub fn check_keysets(epochs: &mut ActorEpochs, keys: &Keys) -> (bool, bool) {
    let mut out = (false, false);
    for r in crate::epoch::ROLES {
        let Some(ks) = keyset_of(keys, r) else { continue };
        let Ok(e) = from_schema(&ks.epoch) else { continue };
        let (c, d) = epochs.role_mut(r).set_keyset(e, ks);
        out = (out.0 | c, out.1 | d);
    }
    out
}

/// A write to `/secrets`: boxes put, boxes removed, history boxes put (spec/crypto.md §4).
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

    /// The epochs this write introduces per role and what each supersedes: a history box
    /// written for (r, e) with the boxes of r it removes at earlier epochs and, from `keys`
    /// (the commit's `/keys` write and the keysets held before it), the keyset epoch of r it
    /// replaces; the latter covers an actor whose members are all key actors (their boxes are
    /// keyed at their top role, so a rotation of a lower role removes none). A grant or re-seal
    /// re-writes history boxes and removes nothing, so it supersedes nothing.
    pub fn rotations(&self, keys: Option<(&KeysWrite, &Keys)>) -> Result<Vec<(Role, Epoch, BTreeSet<Epoch>)>, Error> {
        let mut out = Vec::new();
        for k in self.history.keys() {
            let e = from_schema(&k.epoch)?;
            let mut sup = BTreeSet::new();
            for b in self.removed.iter().filter(|b| b.role == k.role) {
                let old = from_schema(&b.epoch)?;
                if old.n() < e.n() {
                    sup.insert(old);
                }
            }
            if let Some((w, prev)) = keys
                && w.keysets.get(&k.role).is_some_and(|ks| ks.epoch == k.epoch)
                && let Some(old) = keyset_of(prev, k.role)
            {
                let old = from_schema(&old.epoch)?;
                if old.n() < e.n() {
                    sup.insert(old);
                }
            }
            out.push((k.role, e, sup));
        }
        Ok(out)
    }

    /// Records the write's epochs and rotations in `epochs` (a received commit's delta; `keys` as
    /// for `rotations`). Establishes nothing: see `applied`.
    pub fn observe(&self, epochs: &mut ActorEpochs, keys: Option<(&KeysWrite, &Keys)>) -> Result<(), Error> {
        for (r, e, sup) in self.rotations(keys)? {
            epochs.role_mut(r).rotation(e, sup);
        }
        for k in self.boxes.keys() {
            epochs.role_mut(k.role).observe(from_schema(&k.epoch)?);
        }
        Ok(())
    }

    /// The rotations this write makes as part of a rotation commit: its history boxes at the
    /// epochs whose keyset the commit's `/keys` write sets (`keys`: that write and the keysets
    /// held before it). A grant or re-seal re-writes history boxes but writes no keyset, so it
    /// makes none (spec/crypto.md §4).
    pub fn rotation_commit(&self, keys: (&KeysWrite, &Keys)) -> Result<Vec<(Role, Epoch, BTreeSet<Epoch>)>, Error> {
        let w = keys.0;
        Ok(self.rotations(Some(keys))?.into_iter().filter(|(r, e, _)| w.keysets.get(r).is_some_and(|ks| ks.epoch == to_schema(e))).collect())
    }

    /// The commit carrying this write (and `keys`) is applied and valid: records its epochs, marks
    /// its rotations applied with their history boxes (`RoleEpochs::set_history`), records the
    /// keysets its `/keys` write publishes (`check_keysets`) and recomputes establishment
    /// (spec/crypto.md §4). Returns whether establishment or anything recorded changed (persist
    /// then; reopen the history boxes when the actor holds candidates).
    pub fn applied(&self, epochs: &mut ActorEpochs, keys: (&KeysWrite, &Keys)) -> Result<bool, Error> {
        self.observe(epochs, Some(keys))?;
        let mut recorded = false;
        for (r, e, sup) in self.rotation_commit(keys)? {
            epochs.role_mut(r).set_applied(e, sup);
            if let Some(ct) = self.history.get(&history_key(r, &e)) {
                recorded |= epochs.role_mut(r).set_history(e, ct);
            }
        }
        let mut published = Keys::default();
        keys.0.apply(&mut published);
        recorded |= check_keysets(epochs, &published).0;
        Ok(epochs.establish() | recorded)
    }
}

/// Every (role, epoch) the `/secrets` state keys (box and history keys).
fn keyed(s: &Secrets) -> Result<Vec<(Role, Epoch)>, Error> {
    s.boxes.keys().map(|k| (k.role, &k.epoch)).chain(s.history.keys().map(|k| (k.role, &k.epoch))).map(|(r, e)| Ok((r, from_schema(e)?))).collect()
}

/// Records every epoch the applied `/secrets` state names (box and history keys). Establishes
/// nothing (spec/crypto.md §4: a box or history box names an epoch without establishing it).
pub fn observe_secrets(s: &Secrets, epochs: &mut ActorEpochs) -> Result<(), Error> {
    for (r, e) in keyed(s)? {
        epochs.role_mut(r).observe(e);
    }
    Ok(())
}

/// A held compaction snapshot of `/secrets` (`s`, its pages joined) keys these epochs: they are
/// established (`Snapshot`, spec/crypto.md §4). Returns whether establishment changed.
pub fn snapshot_keyed(s: &Secrets, epochs: &mut ActorEpochs) -> Result<bool, Error> {
    for (r, e) in keyed(s)? {
        epochs.role_mut(r).set_snapshot(e);
    }
    Ok(epochs.establish())
}

/// The `/secrets` compaction gate (spec/crypto.md §4): every epoch the state `s` keys is
/// established, so the snapshot vouches for nothing this node did not verify.
pub fn may_compact_secrets(s: &Secrets, epochs: &ActorEpochs) -> Result<bool, Error> {
    Ok(keyed(s)?.iter().all(|(r, e)| epochs.role(*r).is_established(e)))
}

/// Records the suite each keyset of `/keys` names for its epoch. Establishes nothing.
pub fn observe_keys(k: &Keys, epochs: &mut ActorEpochs) -> Result<(), Error> {
    for (r, ks) in [(Role::Read, &k.read), (Role::Write, &k.write), (Role::Admin, &k.admin)] {
        if let Some(ks) = ks {
            epochs.role_mut(r).set_suite(from_schema(&ks.epoch)?, ks.suite);
        }
    }
    Ok(())
}

/// A write to `/keys` by a rotation: the rotated roles' keysets (spec/crypto.md §3).
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

/// The keyset of `role` in `/keys`.
pub fn keyset_of(k: &Keys, role: Role) -> Option<&Keyset> {
    match role {
        Role::Read => k.read.as_ref(),
        Role::Write => k.write.as_ref(),
        Role::Admin => k.admin.as_ref(),
    }
}
