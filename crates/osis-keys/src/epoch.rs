//! Per-role epochs of one actor as a node holds them (spec/crypto.md §4): forks kept,
//! established (own, fixed, derived, chain of applied rotation commits, snapshot), current =
//! established and not superseded by an established rotation, newest = greatest n, ties by lowest
//! nonce.

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

/// How an epoch got established at this node (spec/crypto.md §4). `Own`, `Fixed` and `Derived`
/// are set directly; `Chain` and `Snapshot` are computed by `RoleEpochs::establish`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Provenance {
    /// This node's own rotation.
    Own,
    /// A key actor's fixed epoch.
    Fixed,
    /// Derived from an established epoch of the owner (a plain thing).
    Derived,
    /// Its rotation commit is applied and valid and every epoch it supersedes is established.
    Chain,
    /// A held compaction snapshot of `/secrets` keys a box or history box with it.
    Snapshot,
}

impl Provenance {
    /// Set directly, never recomputed.
    pub fn sticky(self) -> bool {
        matches!(self, Provenance::Own | Provenance::Fixed | Provenance::Derived)
    }

    /// A re-seal may box an epoch of this provenance (spec/permissions.md §3: established
    /// through rotation commits; not by a snapshot alone).
    pub fn reseals(self) -> bool {
        matches!(self, Provenance::Own | Provenance::Chain)
    }
}

/// What a node knows of one epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochInfo {
    /// Suite ID (from the keyset that named it; 1 until one is seen).
    pub suite: u64,
    /// Epochs its rotation superseded: from its rotation commit (removed boxes, replaced keyset)
    /// and from its opened history box (everything listed). Counts only once established.
    pub supersedes: BTreeSet<Epoch>,
    /// Its rotation commit is applied and valid: the epochs that commit supersedes (the chain
    /// condition of `establish`).
    pub applied: Option<BTreeSet<Epoch>>,
    /// A held `/secrets` compaction snapshot keys it.
    pub snapshot: bool,
    /// Established (spec/crypto.md §4): persisted, never inferred from the applied `/secrets`
    /// state. Unestablished epochs are kept for reading only: never current, supersede nothing,
    /// never encrypted under, never put in a history box.
    pub established: Option<Provenance>,
    pub secret: Option<Secret32>,
    /// `secret` was learned only from an unchecked box (a pending or invalid commit, or a history
    /// box opened with such a secret): kept for reading, never encrypted under, until an applied
    /// valid box carries it (spec/crypto.md §4).
    pub reading_only: bool,
}

impl Default for EpochInfo {
    fn default() -> EpochInfo {
        EpochInfo { suite: SUITE, supersedes: BTreeSet::new(), applied: None, snapshot: false, established: None, secret: None, reading_only: false }
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

    /// Sets `e`'s secret from a checked source (an applied valid box, a history box opened with
    /// such a secret, an own rotation); replaces a reading-only one.
    pub fn set_secret(&mut self, e: Epoch, secret: Secret32) {
        let info = self.observe(e);
        info.secret = Some(secret);
        info.reading_only = false;
    }

    /// Records a secret learned only from an unchecked box (spec/crypto.md §4): kept for reading
    /// when `e` holds none; never replaces a secret.
    pub fn set_reading_secret(&mut self, e: Epoch, secret: Secret32) {
        let info = self.observe(e);
        if info.secret.is_none() {
            info.secret = Some(secret);
            info.reading_only = true;
        }
    }

    /// Whether `e`'s secret is held only for reading (`set_reading_secret`).
    pub fn is_reading_only(&self, e: &Epoch) -> bool {
        self.map.get(e).is_some_and(|i| i.secret.is_some() && i.reading_only)
    }

    /// Sets `e`'s provenance directly (`Own`, `Fixed`, `Derived`; `Chain` and `Snapshot` set
    /// here are recomputed by the next `establish`).
    pub fn set_established(&mut self, e: Epoch, p: Provenance) {
        self.observe(e).established = Some(p);
    }

    /// Records that `e`'s rotation commit is applied and valid, superseding `supersedes`
    /// (`SecretsWrite::rotations`). Call `establish` after.
    pub fn set_applied(&mut self, e: Epoch, supersedes: impl IntoIterator<Item = Epoch>) {
        let sup: BTreeSet<Epoch> = supersedes.into_iter().filter(|s| s.n() < e.n()).collect();
        let info = self.observe(e);
        info.supersedes.extend(sup.iter().copied());
        info.applied.get_or_insert_with(BTreeSet::new).extend(sup);
    }

    /// `e`'s rotation commit is no longer applied (found invalid). Call `establish` after.
    pub fn unset_applied(&mut self, e: &Epoch) {
        if let Some(i) = self.map.get_mut(e) {
            i.applied = None;
        }
    }

    /// Records that a held `/secrets` compaction snapshot keys `e`. Call `establish` after.
    pub fn set_snapshot(&mut self, e: Epoch) {
        self.observe(e).snapshot = true;
    }

    /// Recomputes `Chain` and `Snapshot` establishment (spec/crypto.md §4), a fixpoint: an epoch
    /// whose rotation commit is applied is `Chain` once every epoch that commit supersedes is
    /// established; else `Snapshot` when a held snapshot keys it. Sticky provenances stay.
    /// Returns whether anything changed.
    pub fn establish(&mut self) -> bool {
        let before: Vec<Option<Provenance>> = self.map.values().map(|i| i.established).collect();
        for i in self.map.values_mut() {
            if !i.established.is_some_and(Provenance::sticky) {
                i.established = i.snapshot.then_some(Provenance::Snapshot);
            }
        }
        loop {
            let ready: Vec<Epoch> = self
                .map
                .iter()
                .filter(|(_, i)| !matches!(i.established, Some(p) if p.sticky() || p == Provenance::Chain))
                .filter(|(_, i)| i.applied.as_ref().is_some_and(|sup| sup.iter().all(|s| self.is_established(s))))
                .map(|(e, _)| *e)
                .collect();
            if ready.is_empty() {
                break;
            }
            for e in ready {
                self.observe(e).established = Some(Provenance::Chain);
            }
        }
        self.map.values().map(|i| i.established).ne(before)
    }

    pub fn is_established(&self, e: &Epoch) -> bool {
        self.provenance(e).is_some()
    }

    pub fn provenance(&self, e: &Epoch) -> Option<Provenance> {
        self.map.get(e).and_then(|i| i.established)
    }

    pub fn set_suite(&mut self, e: Epoch, suite: u64) {
        self.observe(e).suite = suite;
    }

    pub fn get(&self, e: &Epoch) -> Option<&EpochInfo> {
        self.map.get(e)
    }

    /// `e`'s secret when it may be encrypted under (not reading-only).
    pub fn secret(&self, e: &Epoch) -> Option<&Secret32> {
        self.map.get(e).filter(|i| !i.reading_only).and_then(|i| i.secret.as_ref())
    }

    /// `e`'s secret for reading: any held, reading-only included (opening a label, unwrapping,
    /// opening history boxes).
    pub fn reading_secret(&self, e: &Epoch) -> Option<&Secret32> {
        self.map.get(e).and_then(|i| i.secret.as_ref())
    }

    /// Every known epoch, ascending.
    pub fn epochs(&self) -> impl Iterator<Item = (&Epoch, &EpochInfo)> {
        self.map.iter()
    }

    /// Every held secret that may be encrypted under (not reading-only), ascending by epoch.
    pub fn held(&self) -> impl Iterator<Item = (Epoch, &Secret32)> {
        self.map.iter().filter(|(_, i)| !i.reading_only).filter_map(|(e, i)| i.secret.as_ref().map(|s| (*e, s)))
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Greatest n known, of any epoch.
    pub fn max_n(&self) -> Option<u64> {
        self.map.keys().map(Epoch::n).max()
    }

    /// Superseded by an established rotation.
    pub fn superseded(&self, e: &Epoch) -> bool {
        self.map.values().any(|i| i.established.is_some() && i.supersedes.contains(e))
    }

    /// Current epochs: established and not superseded, ascending.
    pub fn current(&self) -> Vec<Epoch> {
        self.map.iter().filter(|(e, i)| i.established.is_some() && !self.superseded(e)).map(|(e, _)| *e).collect()
    }

    pub fn is_current(&self, e: &Epoch) -> bool {
        self.is_established(e) && !self.superseded(e)
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

    /// The newest established epoch whose secret is held, current or not (a stranded node's
    /// heartbeat, spec/permissions.md §4).
    pub fn newest_secret(&self) -> Option<(Epoch, &Secret32)> {
        let e = newest_of(self.held().map(|(e, _)| e).filter(|e| self.is_established(e)).collect::<Vec<_>>().iter())?;
        self.secret(&e).map(|s| (e, s))
    }

    /// Whether the newest current epoch is established by a snapshot alone: a re-sealer does not
    /// re-seal at it and may rotate instead (spec/permissions.md §3).
    pub fn newest_is_snapshot(&self) -> bool {
        self.newest().is_some_and(|e| self.provenance(&e) == Some(Provenance::Snapshot))
    }

    /// Held established secrets, ascending by epoch: what a history box carries (spec/crypto.md
    /// §4).
    pub fn held_established(&self) -> impl Iterator<Item = (Epoch, &Secret32)> {
        self.held().filter(|(e, _)| self.is_established(e))
    }

    /// Held secrets, newest first (a reader tries them in this order, spec/crypto.md §5).
    /// Reading-only secrets included.
    pub fn held_newest_first(&self) -> Vec<(Epoch, &Secret32)> {
        let mut v: Vec<(Epoch, &Secret32)> = self.map.iter().filter_map(|(e, i)| i.secret.as_ref().map(|s| (*e, s))).collect();
        v.sort_by(|a, b| if is_newer(&a.0, &b.0) { std::cmp::Ordering::Less } else if a.0 == b.0 { std::cmp::Ordering::Equal } else { std::cmp::Ordering::Greater });
        v
    }

    /// Forgets every secret (spec/permissions.md §3: a node that lost read access drops them).
    pub fn drop_secrets(&mut self) {
        for i in self.map.values_mut() {
            i.secret = None;
            i.reading_only = false;
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
            a.role_mut(r).set_established(Epoch::ZERO, Provenance::Fixed);
        }
        a
    }

    /// A plain thing's derived role secrets `kdf("thing <role>", owner's secret, tid)`, at the
    /// owner's epochs, forks included (spec/crypto.md §3); established (`Derived`) where the
    /// owner's is. Epochs whose owner secret is not held are known without a secret.
    pub fn derived(owner: &ActorEpochs, tid: &Tid) -> ActorEpochs {
        let mut a = owner.clone();
        for r in ROLES {
            for info in a.role_mut(r).map.values_mut() {
                info.secret = info.secret.as_ref().map(|s| thing_role_secret(s, r, tid));
                info.established = info.established.map(|_| Provenance::Derived);
                info.applied = None;
                info.snapshot = false;
            }
        }
        a
    }

    /// `RoleEpochs::establish` for every role. Returns whether anything changed.
    pub fn establish(&mut self) -> bool {
        let mut changed = false;
        for r in ROLES {
            changed |= self.role_mut(r).establish();
        }
        changed
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
            r.set_established(e, Provenance::Own);
        }
        assert_eq!(r.current(), vec![ep(2, 3), ep(2, 5)]);
        assert_eq!(r.newest(), Some(ep(2, 3)));
        assert_eq!(r.newest_held(), None);
        assert_eq!(r.newest_secret().map(|x| x.0), Some(ep(1, 0)));
        r.set_secret(ep(2, 5), Secret32::from_bytes([2; 32]));
        assert_eq!(r.newest_held().map(|x| x.0), Some(ep(2, 5)));
        r.rotation(ep(3, 9), [ep(2, 5)]);
        r.set_established(ep(3, 9), Provenance::Own);
        assert_eq!(r.current(), vec![ep(2, 3), ep(3, 9)]);
        assert_eq!(r.newest(), Some(ep(3, 9)));
        // An unestablished rotation (not applied, pending or invalid) supersedes nothing and is not
        // current.
        r.rotation(ep(4, 1), [ep(3, 9), ep(2, 3)]);
        assert_eq!(r.current(), vec![ep(2, 3), ep(3, 9)]);
        r.set_applied(ep(4, 1), [ep(3, 9), ep(2, 3)]);
        assert!(r.establish());
        assert_eq!(r.current(), vec![ep(4, 1)]);
        assert_eq!(r.provenance(&ep(4, 1)), Some(Provenance::Chain));
        r.unset_applied(&ep(4, 1));
        assert!(r.establish());
        assert_eq!(r.current(), vec![ep(2, 3), ep(3, 9)]);
        let order: Vec<Epoch> = r.held_newest_first().into_iter().map(|x| x.0).collect();
        assert_eq!(order, vec![ep(2, 5), ep(1, 0)]);
    }

    // spec/crypto.md §4: chain establishment is a fixpoint over applied rotation commits, in any
    // arrival order; a snapshot keying an epoch establishes it; a chain through an unestablished
    // epoch does not.
    #[test]
    fn establish_fixpoint() {
        let mut r = RoleEpochs::default();
        r.set_established(ep(1, 0), Provenance::Own);
        // e3 then e2 applied (reorder): e3 waits for e2.
        r.set_applied(ep(3, 0), [ep(2, 0)]);
        assert!(!r.establish());
        assert_eq!(r.current(), vec![ep(1, 0)]);
        r.set_applied(ep(2, 0), [ep(1, 0)]);
        assert!(r.establish());
        assert_eq!(r.current(), vec![ep(3, 0)]);
        assert_eq!(r.provenance(&ep(2, 0)), Some(Provenance::Chain));
        // A chain whose base is unknown here: established only once a snapshot keys the base.
        let mut s = RoleEpochs::default();
        s.set_applied(ep(5, 0), [ep(4, 0)]);
        s.establish();
        assert!(s.current().is_empty());
        s.set_snapshot(ep(4, 0));
        s.establish();
        assert_eq!(s.provenance(&ep(4, 0)), Some(Provenance::Snapshot));
        assert_eq!(s.provenance(&ep(5, 0)), Some(Provenance::Chain));
        assert!(!s.newest_is_snapshot());
        s.set_snapshot(ep(6, 0));
        s.rotation(ep(6, 0), [ep(5, 0)]);
        s.establish();
        assert!(s.newest_is_snapshot());
        // A snapshot-keyed epoch whose commit then applies is chain-established.
        s.set_applied(ep(6, 0), [ep(5, 0)]);
        s.establish();
        assert_eq!(s.provenance(&ep(6, 0)), Some(Provenance::Chain));
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
            owner.read.set_established(e, Provenance::Chain);
        }
        owner.read.observe(ep(3, 0));
        let d = ActorEpochs::derived(&owner, &t);
        assert_eq!(d.read.current(), owner.read.current());
        assert_eq!(d.read.provenance(&ep(1, 1)), Some(Provenance::Derived));
        assert_eq!(d.read.provenance(&ep(3, 0)), None);
        assert_eq!(d.read.held().count(), 2);
    }
}
