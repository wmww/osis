//! `/keys` and `/secrets` contents and the writes rotations, grants and re-seals make to them
//! (spec/crypto.md §3, §4; types: osis-schema `core_types`).

use crate::epoch::{ActorEpochs, SUITE};
use crate::Error;
use osis_core::Role;
use osis_crypto::{Epoch, Secret32, role_kem};
use osis_schema::core_types::{self as ct, BoxKey, HistoryKey, KemKey, Keys, Keyset, SecretBox, Secrets};
use std::collections::{BTreeMap, BTreeSet};

pub fn to_schema(e: &Epoch) -> ct::Epoch {
    ct::Epoch { n: e.n(), nonce: *e.nonce() }
}

pub fn from_schema(e: &ct::Epoch) -> Result<Epoch, Error> {
    Ok(Epoch::new(e.n, e.nonce)?)
}

pub fn box_key(member: osis_core::Tid, role: Role, epoch: &Epoch) -> BoxKey {
    BoxKey { member, role, epoch: to_schema(epoch) }
}

pub fn history_key(role: Role, epoch: &Epoch) -> HistoryKey {
    HistoryKey { role, epoch: to_schema(epoch) }
}

/// The keyset of a role epoch: its KEM public key `kdf("kem", secret)` (spec/crypto.md §3).
pub fn keyset(epoch: &Epoch, secret: &Secret32) -> Keyset {
    Keyset { epoch: to_schema(epoch), kem_key: KemKey::X25519MlKem768(role_kem(secret).public().as_bytes().to_vec()), suite: SUITE }
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

    pub fn extend(&mut self, other: SecretsWrite) {
        for k in &other.boxes {
            self.removed.remove(k.0);
        }
        self.boxes.extend(other.boxes);
        self.removed.extend(other.removed);
        self.history.extend(other.history);
    }

    pub fn is_empty(&self) -> bool {
        self.boxes.is_empty() && self.removed.is_empty() && self.history.is_empty()
    }

    /// The epochs this write introduces per role and what each supersedes: a history box
    /// written for (r, e) with the boxes of r it removes at earlier epochs. A grant or re-seal
    /// re-writes history boxes and removes nothing, so it supersedes nothing.
    pub fn rotations(&self) -> Result<Vec<(Role, Epoch, BTreeSet<Epoch>)>, Error> {
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
            out.push((k.role, e, sup));
        }
        Ok(out)
    }

    /// Records the write's epochs and rotations in `epochs` (an applied commit's delta).
    pub fn observe(&self, epochs: &mut ActorEpochs) -> Result<(), Error> {
        for (r, e, sup) in self.rotations()? {
            epochs.role_mut(r).rotation(e, sup);
        }
        for k in self.boxes.keys() {
            epochs.role_mut(k.role).observe(from_schema(&k.epoch)?);
        }
        Ok(())
    }
}

/// Records every epoch a `/secrets` state names (box and history keys), e.g. after a snapshot.
pub fn observe_secrets(s: &Secrets, epochs: &mut ActorEpochs) -> Result<(), Error> {
    for k in s.boxes.keys() {
        epochs.role_mut(k.role).observe(from_schema(&k.epoch)?);
    }
    for k in s.history.keys() {
        epochs.role_mut(k.role).observe(from_schema(&k.epoch)?);
    }
    Ok(())
}

/// Records the suite each keyset of `/keys` names for its epoch.
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
