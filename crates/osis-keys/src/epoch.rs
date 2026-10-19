//! Per-role epochs of one actor as a node holds them (spec/crypto.md §4): forks kept, current =
//! not superseded by a held rotation, newest = greatest n, ties by lowest nonce.

use osis_core::{Role, Tid};
use osis_crypto::{Epoch, Secret32, key_actor_role_secret, thing_role_secret};
use std::collections::{BTreeMap, BTreeSet};

/// Suite 1, the only suite (spec/crypto.md §8).
pub const SUITE: u64 = 1;

pub const ROLES: [Role; 3] = [Role::Read, Role::Write, Role::Admin];

/// Is `a` newer than `b`: greater n, or equal n and lower nonce.
pub fn is_newer(a: &Epoch, b: &Epoch) -> bool {
    a.n() > b.n() || (a.n() == b.n() && a.nonce() < b.nonce())
}

/// The newest of `epochs`.
pub fn newest_of<'a>(epochs: impl IntoIterator<Item = &'a Epoch>) -> Option<Epoch> {
    epochs.into_iter().fold(None, |best: Option<Epoch>, e| match best {
        Some(b) if !is_newer(e, &b) => Some(b),
        _ => Some(*e),
    })
}

/// What a node knows of one epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochInfo {
    /// Suite ID (from the keyset that named it; 1 until one is seen).
    pub suite: u64,
    /// Epochs the rotation of this one superseded (removed boxes, or listed in its history box).
    pub supersedes: BTreeSet<Epoch>,
    /// Its rotation commit is applied and valid. False while pending or invalid (spec/crypto.md
    /// §4): kept for reading, never encrypted under, supersedes nothing. An epoch first seen in a
    /// commit (`SecretsWrite::observe`) starts false until the caller marks it (`set_usable`);
    /// one seen in the applied `/secrets` state (`observe_secrets`) or made by this node's own
    /// rotation (`Rotation::record`) starts true.
    pub usable: bool,
    pub secret: Option<Secret32>,
}

impl Default for EpochInfo {
    fn default() -> EpochInfo {
        EpochInfo { suite: SUITE, supersedes: BTreeSet::new(), usable: false, secret: None }
    }
}

/// The epochs of one role of one actor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoleEpochs {
    map: BTreeMap<Epoch, EpochInfo>,
}

impl RoleEpochs {
    /// Records that epoch `e` exists (a box or history key names it).
    pub fn observe(&mut self, e: Epoch) -> &mut EpochInfo {
        self.map.entry(e).or_default()
    }

    /// Records the rotation that created `e` and what it superseded.
    pub fn rotation(&mut self, e: Epoch, supersedes: impl IntoIterator<Item = Epoch>) {
        let info = self.observe(e);
        info.supersedes.extend(supersedes.into_iter().filter(|s| s.n() < e.n()));
    }

    pub fn set_secret(&mut self, e: Epoch, secret: Secret32) {
        self.observe(e).secret = Some(secret);
    }

    pub fn set_usable(&mut self, e: Epoch, usable: bool) {
        self.observe(e).usable = usable;
    }

    pub fn set_suite(&mut self, e: Epoch, suite: u64) {
        self.observe(e).suite = suite;
    }

    pub fn get(&self, e: &Epoch) -> Option<&EpochInfo> {
        self.map.get(e)
    }

    pub fn secret(&self, e: &Epoch) -> Option<&Secret32> {
        self.map.get(e).and_then(|i| i.secret.as_ref())
    }

    /// Every known epoch, ascending.
    pub fn epochs(&self) -> impl Iterator<Item = (&Epoch, &EpochInfo)> {
        self.map.iter()
    }

    /// Every held secret, ascending by epoch.
    pub fn held(&self) -> impl Iterator<Item = (Epoch, &Secret32)> {
        self.map.iter().filter_map(|(e, i)| i.secret.as_ref().map(|s| (*e, s)))
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Greatest n known, of any epoch.
    pub fn max_n(&self) -> Option<u64> {
        self.map.keys().map(Epoch::n).max()
    }

    /// Superseded by a usable held rotation.
    pub fn superseded(&self, e: &Epoch) -> bool {
        self.map.values().any(|i| i.usable && i.supersedes.contains(e))
    }

    /// Current epochs: usable and not superseded, ascending.
    pub fn current(&self) -> Vec<Epoch> {
        self.map.iter().filter(|(e, i)| i.usable && !self.superseded(e)).map(|(e, _)| *e).collect()
    }

    pub fn is_current(&self, e: &Epoch) -> bool {
        self.map.get(e).is_some_and(|i| i.usable) && !self.superseded(e)
    }

    /// The newest current epoch.
    pub fn newest(&self) -> Option<Epoch> {
        newest_of(&self.current())
    }

    /// The newest current epoch whose secret is held.
    pub fn newest_held(&self) -> Option<(Epoch, &Secret32)> {
        let cur: Vec<Epoch> = self.current().into_iter().filter(|e| self.secret(e).is_some()).collect();
        let e = newest_of(&cur)?;
        self.secret(&e).map(|s| (e, s))
    }

    /// The newest epoch whose secret is held, current or not (a stranded node's heartbeat,
    /// spec/permissions.md §4).
    pub fn newest_secret(&self) -> Option<(Epoch, &Secret32)> {
        let e = newest_of(self.held().map(|(e, _)| e).collect::<Vec<_>>().iter())?;
        self.secret(&e).map(|s| (e, s))
    }

    /// Held secrets, newest first (a reader tries them in this order, spec/crypto.md §5).
    pub fn held_newest_first(&self) -> Vec<(Epoch, &Secret32)> {
        let mut v: Vec<(Epoch, &Secret32)> = self.held().collect();
        v.sort_by(|a, b| if is_newer(&a.0, &b.0) { std::cmp::Ordering::Less } else if a.0 == b.0 { std::cmp::Ordering::Equal } else { std::cmp::Ordering::Greater });
        v
    }

    /// Forgets every secret (spec/permissions.md §3: a node that lost read access drops them).
    pub fn drop_secrets(&mut self) {
        for i in self.map.values_mut() {
            i.secret = None;
        }
    }
}

/// The epochs of the three roles of one actor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActorEpochs {
    pub read: RoleEpochs,
    pub write: RoleEpochs,
    pub admin: RoleEpochs,
}

impl ActorEpochs {
    pub fn role(&self, r: Role) -> &RoleEpochs {
        match r {
            Role::Read => &self.read,
            Role::Write => &self.write,
            Role::Admin => &self.admin,
        }
    }

    pub fn role_mut(&mut self, r: Role) -> &mut RoleEpochs {
        match r {
            Role::Read => &mut self.read,
            Role::Write => &mut self.write,
            Role::Admin => &mut self.admin,
        }
    }

    /// A key actor's role secrets `kdf("role <role>", seed)`, each at `Epoch::ZERO`, never
    /// rotated (spec/crypto.md §3).
    pub fn key_actor(seed: &Secret32) -> ActorEpochs {
        let mut a = ActorEpochs::default();
        for r in ROLES {
            a.role_mut(r).set_secret(Epoch::ZERO, key_actor_role_secret(seed, r));
            a.role_mut(r).set_usable(Epoch::ZERO, true);
        }
        a
    }

    /// A plain thing's derived role secrets `kdf("thing <role>", owner's secret, tid)`, at the
    /// owner's epochs, forks and flags included (spec/crypto.md §3). Epochs whose owner secret is
    /// not held are known without a secret.
    pub fn derived(owner: &ActorEpochs, tid: &Tid) -> ActorEpochs {
        let mut a = owner.clone();
        for r in ROLES {
            for info in a.role_mut(r).map.values_mut() {
                info.secret = info.secret.as_ref().map(|s| thing_role_secret(s, r, tid));
            }
        }
        a
    }

    pub fn drop_secrets(&mut self) {
        for r in ROLES {
            self.role_mut(r).drop_secrets();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(n: u64, nonce: u8) -> Epoch {
        Epoch::new(n, [nonce; 16]).unwrap()
    }

    // spec/crypto.md §4: current = not superseded by a held rotation; newest = greatest n, ties by
    // lowest nonce; forks kept.
    #[test]
    fn current_and_newest() {
        let mut r = RoleEpochs::default();
        r.set_secret(ep(1, 0), Secret32::from_bytes([1; 32]));
        r.rotation(ep(2, 5), [ep(1, 0)]);
        r.rotation(ep(2, 3), [ep(1, 0)]);
        for e in [ep(1, 0), ep(2, 5), ep(2, 3)] {
            r.set_usable(e, true);
        }
        assert_eq!(r.current(), vec![ep(2, 3), ep(2, 5)]);
        assert_eq!(r.newest(), Some(ep(2, 3)));
        assert_eq!(r.newest_held(), None);
        assert_eq!(r.newest_secret().map(|x| x.0), Some(ep(1, 0)));
        r.set_secret(ep(2, 5), Secret32::from_bytes([2; 32]));
        assert_eq!(r.newest_held().map(|x| x.0), Some(ep(2, 5)));
        r.rotation(ep(3, 9), [ep(2, 5)]);
        r.set_usable(ep(3, 9), true);
        assert_eq!(r.current(), vec![ep(2, 3), ep(3, 9)]);
        assert_eq!(r.newest(), Some(ep(3, 9)));
        // An unusable rotation (pending or invalid) supersedes nothing and is not current.
        r.rotation(ep(4, 1), [ep(3, 9), ep(2, 3)]);
        r.set_usable(ep(4, 1), false);
        assert_eq!(r.current(), vec![ep(2, 3), ep(3, 9)]);
        r.set_usable(ep(4, 1), true);
        assert_eq!(r.current(), vec![ep(4, 1)]);
        let order: Vec<Epoch> = r.held_newest_first().into_iter().map(|x| x.0).collect();
        assert_eq!(order, vec![ep(2, 5), ep(1, 0)]);
    }

    // spec/crypto.md §3: derived secrets take the owner's epochs; a key actor's are fixed.
    #[test]
    fn derived_and_key_actor() {
        let seed = Secret32::from_bytes([7; 32]);
        let k = ActorEpochs::key_actor(&seed);
        assert_eq!(k.admin.current(), vec![Epoch::ZERO]);
        let t = Tid::from_bytes([3; 15]);
        let d = ActorEpochs::derived(&k, &t);
        let want = thing_role_secret(&key_actor_role_secret(&seed, Role::Write), Role::Write, &t);
        assert_eq!(d.write.secret(&Epoch::ZERO), Some(&want));
        let mut owner = ActorEpochs::default();
        owner.read.set_secret(ep(1, 1), Secret32::from_bytes([1; 32]));
        owner.read.set_secret(ep(1, 2), Secret32::from_bytes([2; 32]));
        owner.read.observe(ep(2, 0));
        for e in [ep(1, 1), ep(1, 2), ep(2, 0)] {
            owner.read.set_usable(e, true);
        }
        let d = ActorEpochs::derived(&owner, &t);
        assert_eq!(d.read.current(), owner.read.current());
        assert_eq!(d.read.held().count(), 2);
    }
}
