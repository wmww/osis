//! Per-role epochs of one actor as a node holds them (spec/crypto.md §4): forks kept,
//! established (own, fixed, derived, chain of applied rotation commits, snapshot), current =
//! established and not superseded by an established rotation, newest = greatest order n, ties by
//! lowest nonce.

use osis_base::{CommitId, Role, Tid};
use osis_crypto::{Epoch, Secret32, key_actor_role_secret, thing_role_secret};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

/// Suite 1, the only suite (spec/crypto.md §8).
pub const SUITE: u64 = 1;

pub const ROLES: [Role; 3] = [Role::Read, Role::Write, Role::Admin];

/// Sorts as `e` by age: greater n, then lower nonce, is newer.
fn by_n(e: &Epoch) -> (u64, Reverse<[u8; 32]>) {
    (e.n(), Reverse(*e.nonce()))
}

/// Is `a` newer than `b` by n: greater n, or equal n and lower nonce.
pub fn is_newer(a: &Epoch, b: &Epoch) -> bool {
    by_n(a) > by_n(b)
}

/// The newest of `epochs` by n.
pub fn newest_of<'a>(epochs: impl IntoIterator<Item = &'a Epoch>) -> Option<Epoch> {
    epochs.into_iter().max_by_key(|e| by_n(e)).copied()
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
    /// The applied valid rotation commits that claim it, each with the epochs it supersedes (the
    /// chain condition of `establish`): a holder may re-claim an epoch in a later commit, and
    /// invalidating that one leaves the others.
    pub applied: BTreeMap<CommitId, BTreeSet<Epoch>>,
    /// A held `/secrets` compaction snapshot keys it.
    pub snapshot: bool,
    /// Established (spec/crypto.md §4): persisted, never inferred from the applied `/secrets`
    /// state. Unestablished epochs are kept for reading only: never current, supersede nothing,
    /// never encrypted under, never put in a history box.
    pub established: Option<Provenance>,
    /// Its secret: the one it names (spec/crypto.md §4, every source is checked by the nonce
    /// rule before it gets here).
    pub secret: Option<Secret32>,
    /// The pending commits the secret is known from, when known only from such (their boxes, or
    /// history boxes opened with a secret so known): non-empty, the secret is kept for reading,
    /// never encrypted under, until an applied valid box or a history box opened with a secret
    /// not so known carries it (spec/crypto.md §4). Such epochs are bounded per role
    /// (`MAX_READING`, `MAX_READING_PER_AUTHOR`); dropped with their last source commit
    /// (`drop_reading_from`).
    pub reading: BTreeSet<Unchecked>,
    /// A derived epoch's order n where it differs from its n: the owner epoch's (past the cap,
    /// `derived_n`). It orders (`RoleEpochs::is_newer`) by this, so derived epochs order as the
    /// owner's (spec/crypto.md §3, §4).
    pub order: Option<u64>,
}

impl Default for EpochInfo {
    fn default() -> EpochInfo {
        EpochInfo { suite: SUITE, supersedes: BTreeSet::new(), applied: BTreeMap::new(), snapshot: false, established: None, secret: None, reading: BTreeSet::new(), order: None }
    }
}

impl EpochInfo {
    /// Its secret is known only from pending commits.
    pub fn is_reading_only(&self) -> bool {
        self.secret.is_some() && !self.reading.is_empty()
    }

    /// Its secret when it may be encrypted under (not reading-only).
    pub fn checked(&self) -> Option<&Secret32> {
        self.secret.as_ref().filter(|_| self.reading.is_empty())
    }
}

/// The source of a reading-only secret: the unchecked commit and its author node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Unchecked {
    pub author: Tid,
    pub commit: CommitId,
}

/// The author recorded for a reading-only secret whose commit's author has no chain the node
/// knows (throwaway identities share one budget).
pub const UNKNOWN_AUTHOR: Tid = Tid::from_bytes([0; 15]);

/// Most epochs held through reading-only secrets per role of one actor, and per author node
/// (local policy: each costs a KEM or DH per open, claim and inbox blob, since wraps name no
/// epoch).
pub const MAX_READING: usize = 256;
pub const MAX_READING_PER_AUTHOR: usize = 64;

/// The greatest n an epoch established by chain or snapshot may have without an established
/// epoch at n-1 or above (spec/crypto.md §4): leaves 2^62 rotations before n+1 overflows the
/// int range, far above any genuine first n (derived epochs are capped below it).
pub const MAX_FREE_N: u64 = 1 << 62;

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

    /// Sets `e`'s secret, known from a source that is no pending commit (an applied valid box, a
    /// history box opened with such a secret, an entry box, an own rotation, derivation): it may
    /// be encrypted under once `e` is established.
    pub fn set_secret(&mut self, e: Epoch, secret: Secret32) {
        let info = self.observe(e);
        info.secret = Some(secret);
        info.reading.clear();
    }

    /// Records a secret known only from pending commit `from` (spec/crypto.md §4): reading-only.
    /// A new such epoch is refused once the role holds `MAX_READING` of them or `from`'s author
    /// `MAX_READING_PER_AUTHOR` (authors whose chain the node does not know share
    /// `UNKNOWN_AUTHOR`, one budget).
    pub fn set_reading_secret(&mut self, e: Epoch, secret: Secret32, from: Unchecked) {
        match self.map.get_mut(&e) {
            Some(i) if i.checked().is_some() => return,
            Some(i) if i.secret.is_some() => {
                i.reading.insert(from);
                return;
            }
            _ => {}
        }
        let reading = self.map.values().filter(|i| i.is_reading_only());
        let (total, mine) = reading.fold((0, 0), |(t, m), i| (t + 1, m + usize::from(i.reading.iter().any(|u| u.author == from.author))));
        if total >= MAX_READING || mine >= MAX_READING_PER_AUTHOR {
            return;
        }
        let info = self.observe(e);
        info.secret = Some(secret);
        info.reading.insert(from);
    }

    /// Drops `commit` as a source of reading-only secrets (it applied, or was dropped as bad
    /// input); a secret it was the last source of goes. Returns whether any source went.
    pub fn drop_reading_from(&mut self, commit: &CommitId) -> bool {
        let mut touched = Vec::new();
        for (e, i) in self.map.iter_mut() {
            let n = i.reading.len();
            i.reading.retain(|u| u.commit != *commit);
            if i.reading.len() != n {
                if i.reading.is_empty() {
                    i.secret = None;
                }
                touched.push(*e);
            }
        }
        for e in &touched {
            self.drop_bare(e);
        }
        !touched.is_empty()
    }

    /// Drops `e`'s entry if it holds nothing (known only from a reading-only secret just
    /// dropped): nothing from an unchecked source outlives it.
    fn drop_bare(&mut self, e: &Epoch) {
        if self.map.get(e).is_some_and(|i| *i == EpochInfo::default()) {
            self.map.remove(e);
        }
    }

    /// The pending commits `e`'s reading-only secret is known from (empty when it is not one).
    pub fn reading_sources(&self, e: &Epoch) -> BTreeSet<Unchecked> {
        self.map.get(e).map(|i| i.reading.clone()).unwrap_or_default()
    }

    /// Whether `e`'s secret is held only for reading (`set_reading_secret`).
    pub fn is_reading_only(&self, e: &Epoch) -> bool {
        self.map.get(e).is_some_and(EpochInfo::is_reading_only)
    }

    /// Sets `e`'s provenance directly (`Own`, `Fixed`, `Derived`; `Chain` and `Snapshot` set
    /// here are recomputed by the next `establish`).
    pub fn set_established(&mut self, e: Epoch, p: Provenance) {
        self.observe(e).established = Some(p);
    }

    /// Records that rotation commit `commit`, applied and valid, claims `e`, superseding
    /// `supersedes` (`SecretsWrite::rotations`). Call `establish` after. Returns whether it is
    /// new.
    pub fn set_applied(&mut self, e: Epoch, commit: CommitId, supersedes: impl IntoIterator<Item = Epoch>) -> bool {
        let sup: BTreeSet<Epoch> = supersedes.into_iter().filter(|s| s.n() < e.n()).collect();
        let info = self.observe(e);
        info.supersedes.extend(sup.iter().copied());
        let prev = info.applied.insert(commit, sup.clone());
        prev.is_none_or(|p| p != sup)
    }

    /// Rotation commit `commit` is no longer applied (found invalid): the epochs it claimed keep
    /// their other claimants. Call `establish` after.
    pub fn unset_applied(&mut self, commit: &CommitId) {
        for i in self.map.values_mut() {
            i.applied.remove(commit);
        }
    }

    /// Records that a held `/secrets` compaction snapshot keys `e`; whether that is new. Call
    /// `establish` after.
    pub fn set_snapshot(&mut self, e: Epoch) -> bool {
        !std::mem::replace(&mut self.observe(e).snapshot, true)
    }

    /// Recomputes `Chain` and `Snapshot` establishment (spec/crypto.md §4), a fixpoint: an epoch
    /// whose rotation commit is applied is `Chain` once every epoch that commit supersedes is
    /// established; else `Snapshot` when a held snapshot keys it. Either only within headroom
    /// (`within_headroom`). Sticky provenances stay. Returns whether anything changed.
    pub fn establish(&mut self) -> bool {
        let before: Vec<Option<Provenance>> = self.map.values().map(|i| i.established).collect();
        for i in self.map.values_mut() {
            if !i.established.is_some_and(Provenance::sticky) {
                i.established = None;
            }
        }
        loop {
            let ready: Vec<(Epoch, Provenance)> = self
                .map
                .iter()
                // unestablished, or by snapshot (a chain beats it)
                .filter(|(_, i)| matches!(i.established, None | Some(Provenance::Snapshot)))
                .filter_map(|(e, i)| {
                    let chain = i.applied.values().any(|sup| sup.iter().all(|s| self.is_established(s)));
                    let p = if chain {
                        Provenance::Chain
                    } else if i.snapshot && i.established.is_none() {
                        Provenance::Snapshot
                    } else {
                        return None;
                    };
                    self.within_headroom(e).then_some((*e, p))
                })
                .collect();
            if ready.is_empty() {
                break;
            }
            for (e, p) in ready {
                self.observe(e).established = Some(p);
            }
        }
        self.map.values().map(|i| i.established).ne(before)
    }

    /// Whether `e` may be established by chain or snapshot (spec/crypto.md §4): n at most
    /// `MAX_FREE_N`, or an established epoch other than `e` has n at least n-1. Every established
    /// n is so at most `MAX_FREE_N` plus the number of rotations, so n+1 never overflows.
    fn within_headroom(&self, e: &Epoch) -> bool {
        e.n() <= MAX_FREE_N || self.map.iter().any(|(x, i)| x != e && i.established.is_some() && x.n() + 1 >= e.n())
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
        self.map.get(e).and_then(EpochInfo::checked)
    }

    /// `e`'s secret for reading, reading-only included (opening a label, unwrapping, opening
    /// history boxes).
    pub fn reading_secret(&self, e: &Epoch) -> Option<&Secret32> {
        self.map.get(e).and_then(|i| i.secret.as_ref())
    }

    /// Every known epoch, ascending.
    pub fn epochs(&self) -> impl Iterator<Item = (&Epoch, &EpochInfo)> {
        self.map.iter()
    }

    /// Every held secret that may be encrypted under (not reading-only), ascending by epoch.
    pub fn held(&self) -> impl Iterator<Item = (Epoch, &Secret32)> {
        self.map.iter().filter_map(|(e, i)| i.checked().map(|s| (*e, s)))
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Superseded by an established rotation.
    pub fn superseded(&self, e: &Epoch) -> bool {
        self.map.values().any(|i| i.established.is_some() && i.supersedes.contains(e))
    }

    /// Current epochs: established and not superseded, ascending.
    pub fn current(&self) -> Vec<Epoch> {
        self.map.keys().filter(|e| self.is_current(e)).copied().collect()
    }

    pub fn is_current(&self, e: &Epoch) -> bool {
        self.is_established(e) && !self.superseded(e)
    }

    /// `e`'s order n (spec/crypto.md §4): a derived epoch's is the owner epoch's, any other's
    /// its n.
    pub fn order(&self, e: &Epoch) -> u64 {
        self.map.get(e).and_then(|i| i.order).unwrap_or(e.n())
    }

    /// Sorts as `e` by age (spec/crypto.md §4): greater order n, then `by_n`, is newer.
    fn by_order(&self, e: &Epoch) -> (u64, (u64, Reverse<[u8; 32]>)) {
        (self.order(e), by_n(e))
    }

    /// Whether `a` is newer than `b` (spec/crypto.md §4): greater order n, then lower nonce.
    /// `is_newer` where no derived epoch sits past the cap.
    pub fn is_newer(&self, a: &Epoch, b: &Epoch) -> bool {
        self.by_order(a) > self.by_order(b)
    }

    /// The newest of `held` (epochs of this role, with their secrets).
    fn newest_with<'a>(&self, held: impl Iterator<Item = (Epoch, &'a Secret32)>) -> Option<(Epoch, &'a Secret32)> {
        held.max_by_key(|(e, _)| self.by_order(e))
    }

    /// The newest current epoch.
    pub fn newest(&self) -> Option<Epoch> {
        self.current().into_iter().max_by_key(|e| self.by_order(e))
    }

    /// The newest current epoch whose secret is held.
    pub fn newest_held(&self) -> Option<(Epoch, &Secret32)> {
        self.newest_with(self.held().filter(|(e, _)| self.is_current(e)))
    }

    /// The newest established epoch whose secret is held, current or not (a stranded node's
    /// heartbeat, spec/permissions.md §4).
    pub fn newest_secret(&self) -> Option<(Epoch, &Secret32)> {
        self.newest_with(self.held_established())
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

    /// Held secrets, newest first (a reader tries them in this order, spec/crypto.md §5),
    /// reading-only ones included.
    pub fn held_newest_first(&self) -> Vec<(Epoch, &Secret32)> {
        let mut v: Vec<(Epoch, &Secret32)> = self.map.iter().filter_map(|(e, i)| i.secret.as_ref().map(|s| (*e, s))).collect();
        v.sort_by_key(|(e, _)| Reverse(self.by_order(e)));
        v
    }
}

/// The n of the epochs derived from an owner epoch at `n` (spec/crypto.md §3): the owner's, capped
/// so that a thing's own chain starts at most at `MAX_FREE_N` and a member holding no secret of
/// the owner establishes it within headroom, whatever n a writer of the owner jumped to. Derived
/// epochs still order as the owner's (`EpochInfo::order`): a re-registrar steps a plain group's
/// labels on each owner rotation, a writer picks the owner's newest fork.
fn derived_n(n: u64) -> u64 {
    n.min(MAX_FREE_N - 1)
}

/// The nonce of the placeholder `ActorEpochs::derived` keeps for owner epoch `e` whose secret is
/// not held: a hash of all of `e` (local only), so distinct owner epochs never share one even
/// when made-up ones share a nonce or are capped to one n.
fn placeholder_nonce(e: &Epoch) -> [u8; 32] {
    osis_base::hash::derive_key("osis v1 derived placeholder", &[e.n().to_le_bytes().as_slice(), e.nonce()].concat())
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

    /// A plain thing's derived role secrets `kdf("thing <role>", owner's secret, tid)`, one per
    /// epoch of the owner, forks included, each at the epoch with n `derived_n` of the owner's
    /// that the nonce rule gives it (spec/crypto.md §3). Established (`Derived`) where the
    /// owner's is. An owner epoch whose secret is not held stays known as a placeholder at that
    /// n (`placeholder_nonce`) that no secret names, so that what it supersedes stays superseded.
    pub fn derived(owner: &ActorEpochs, tid: &Tid) -> ActorEpochs {
        let mut a = ActorEpochs::default();
        for r in ROLES {
            let o = owner.role(r);
            let ids: BTreeMap<Epoch, (Epoch, Option<Secret32>)> = o
                .map
                .iter()
                .map(|(e, i)| {
                    let ds = i.secret.as_ref().map(|s| thing_role_secret(s, r, tid));
                    let n = derived_n(e.n());
                    let de = match &ds {
                        Some(s) => Epoch::derive(tid, r, n, s),
                        None => Epoch::new(n, placeholder_nonce(e)),
                    };
                    // never falls back: n is below the cap, within the int range
                    let de = de.unwrap_or(*e);
                    (*e, (de, ds))
                })
                .collect();
            let id = |e: &Epoch| ids.get(e).map_or(*e, |x| x.0);
            for (e, i) in &o.map {
                let Some((de, ds)) = ids.get(e) else { continue };
                let info = EpochInfo {
                    suite: i.suite,
                    // past the cap two owner epochs with one secret derive one epoch: it never
                    // supersedes itself
                    supersedes: i.supersedes.iter().map(id).filter(|x| x != de).collect(),
                    applied: BTreeMap::new(),
                    snapshot: false,
                    established: i.established.map(|_| Provenance::Derived),
                    secret: ds.clone(),
                    reading: i.reading.clone(),
                    order: Some(o.order(e)).filter(|&x| x != de.n()),
                };
                a.role_mut(r).map.insert(*de, info);
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

    /// `RoleEpochs::unset_applied` for every role.
    pub fn unset_applied(&mut self, commit: &CommitId) {
        for r in ROLES {
            self.role_mut(r).unset_applied(commit);
        }
    }

    /// `RoleEpochs::drop_reading_from` for every role.
    pub fn drop_reading_from(&mut self, commit: &CommitId) -> bool {
        let mut any = false;
        for r in ROLES {
            any |= self.role_mut(r).drop_reading_from(commit);
        }
        any
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(n: u64, nonce: u8) -> Epoch {
        Epoch::new(n, [nonce; 32]).unwrap()
    }

    fn cid(b: u8) -> CommitId {
        CommitId([b; 32])
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
        r.set_applied(ep(4, 1), cid(1), [ep(3, 9), ep(2, 3)]);
        assert!(r.establish());
        assert_eq!(r.current(), vec![ep(4, 1)]);
        assert_eq!(r.provenance(&ep(4, 1)), Some(Provenance::Chain));
        // a re-claim of e4 by another commit, then invalidated, leaves e4's rotation applied
        r.set_applied(ep(4, 1), cid(2), [ep(3, 9)]);
        r.unset_applied(&cid(2));
        assert!(!r.establish());
        assert_eq!(r.provenance(&ep(4, 1)), Some(Provenance::Chain));
        r.unset_applied(&cid(1));
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
        r.set_applied(ep(3, 0), cid(3), [ep(2, 0)]);
        assert!(!r.establish());
        assert_eq!(r.current(), vec![ep(1, 0)]);
        r.set_applied(ep(2, 0), cid(2), [ep(1, 0)]);
        assert!(r.establish());
        assert_eq!(r.current(), vec![ep(3, 0)]);
        assert_eq!(r.provenance(&ep(2, 0)), Some(Provenance::Chain));
        // A chain whose base is unknown here: established only once a snapshot keys the base.
        let mut s = RoleEpochs::default();
        s.set_applied(ep(5, 0), cid(5), [ep(4, 0)]);
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
        s.set_applied(ep(6, 0), cid(6), [ep(5, 0)]);
        s.establish();
        assert_eq!(s.provenance(&ep(6, 0)), Some(Provenance::Chain));
    }

    // spec/crypto.md §3: derived secrets take the owner's n at the epochs the nonce rule names;
    // a key actor's are fixed; an owner epoch without a secret stays a placeholder, so what it
    // supersedes stays superseded.
    #[test]
    fn derived_and_key_actor() {
        let seed = Secret32::from_bytes([7; 32]);
        let k = ActorEpochs::key_actor(&seed);
        assert_eq!(k.admin.current(), vec![Epoch::ZERO]);
        let t = Tid::from_bytes([3; 15]);
        let d = ActorEpochs::derived(&k, &t);
        let want = thing_role_secret(&key_actor_role_secret(&seed, Role::Write), Role::Write, &t);
        let dz = Epoch::derive(&t, Role::Write, 0, &want).unwrap();
        assert_eq!(d.write.current(), vec![dz]);
        assert_eq!(d.write.secret(&dz), Some(&want));
        let mut owner = ActorEpochs::default();
        owner.read.set_secret(ep(1, 1), Secret32::from_bytes([1; 32]));
        owner.read.set_secret(ep(1, 2), Secret32::from_bytes([2; 32]));
        owner.read.rotation(ep(2, 0), [ep(1, 1)]);
        for e in [ep(1, 1), ep(1, 2), ep(2, 0)] {
            owner.read.set_established(e, Provenance::Chain);
        }
        owner.read.observe(ep(3, 0));
        let d = ActorEpochs::derived(&owner, &t);
        let de = |b: u8| Epoch::derive(&t, Role::Read, 1, &thing_role_secret(&Secret32::from_bytes([b; 32]), Role::Read, &t)).unwrap();
        let ph = |e: Epoch| Epoch::new(e.n(), placeholder_nonce(&e)).unwrap();
        assert_eq!(d.read.current(), vec![de(2), ph(ep(2, 0))]);
        assert!(d.read.superseded(&de(1)));
        assert_eq!(d.read.provenance(&de(1)), Some(Provenance::Derived));
        assert_eq!(d.read.provenance(&ph(ep(3, 0))), None);
        assert_eq!(d.read.held().count(), 2);
    }

    // spec/crypto.md §3: derived epochs keep the owner's n below the cap, so each owner rotation
    // gives a newer derived epoch (a plain group's labels are stepped on it, spec/sync.md §5);
    // owner epochs past the cap (a writer of the owner jumped them) all derive at the cap, so a
    // thing's own chain starts at most at `MAX_FREE_N`; placeholders there stay distinct.
    #[test]
    fn derived_n_follows_owner_below_cap() {
        let t = Tid::from_bytes([3; 15]);
        for b in 0..32u8 {
            let mut owner = ActorEpochs::default();
            let s = |x: u8| Secret32::from_bytes([x; 32]);
            owner.read.set_secret(ep(1, 1), s(b));
            owner.read.set_secret(ep(2, 2), s(b ^ 0x80));
            owner.read.rotation(ep(2, 2), [ep(1, 1)]);
            for e in [ep(1, 1), ep(2, 2)] {
                owner.read.set_established(e, Provenance::Chain);
            }
            let d = ActorEpochs::derived(&owner, &t);
            let old = Epoch::derive(&t, Role::Read, 1, &thing_role_secret(&s(b), Role::Read, &t)).unwrap();
            assert!(crate::is_newer(&d.read.newest().unwrap(), &old));
        }
        let mut owner = ActorEpochs::default();
        for (i, n) in [MAX_FREE_N - 2, MAX_FREE_N + 5, MAX_FREE_N + 6].into_iter().enumerate() {
            owner.read.set_secret(ep(n, 1), Secret32::from_bytes([i as u8; 32]));
            owner.read.set_established(ep(n, 1), Provenance::Chain);
        }
        owner.read.observe(ep(MAX_FREE_N + 7, 9));
        owner.read.observe(ep(MAX_FREE_N + 8, 9));
        let d = ActorEpochs::derived(&owner, &t);
        let ns: Vec<u64> = d.read.epochs().map(|(e, _)| e.n()).collect();
        assert_eq!(ns, [MAX_FREE_N - 2, MAX_FREE_N - 1, MAX_FREE_N - 1, MAX_FREE_N - 1, MAX_FREE_N - 1]);
        // one secret at two owner epochs past the cap, the later superseding the earlier: one
        // derived epoch, still current
        let mut owner = ActorEpochs::default();
        let (a, b) = (ep(MAX_FREE_N + 10, 1), ep(MAX_FREE_N + 11, 2));
        for e in [a, b] {
            owner.read.set_secret(e, Secret32::from_bytes([7; 32]));
            owner.read.set_established(e, Provenance::Chain);
        }
        owner.read.rotation(b, [a]);
        let d = ActorEpochs::derived(&owner, &t);
        assert_eq!(d.read.current().len(), 1);
    }

    // spec/crypto.md §4: a secret known only from pending commits is reading-only, one per
    // epoch with every source; it goes with its last source; a checked one replaces it.
    #[test]
    fn reading_only_sources() {
        let mut r = RoleEpochs::default();
        let u = |b: u8| Unchecked { author: Tid::from_bytes([b; 15]), commit: cid(b) };
        let s = Secret32::from_bytes([1; 32]);
        r.set_reading_secret(ep(1, 1), s.clone(), u(1));
        r.set_reading_secret(ep(1, 1), s.clone(), u(2));
        assert!(r.is_reading_only(&ep(1, 1)) && r.secret(&ep(1, 1)).is_none());
        assert_eq!(r.reading_secret(&ep(1, 1)), Some(&s));
        assert!(r.drop_reading_from(&cid(1)));
        assert!(r.is_reading_only(&ep(1, 1)));
        assert!(r.drop_reading_from(&cid(2)));
        assert!(r.get(&ep(1, 1)).is_none());
        r.set_reading_secret(ep(1, 1), s.clone(), u(1));
        r.set_secret(ep(1, 1), s.clone());
        assert_eq!(r.secret(&ep(1, 1)), Some(&s));
        r.set_reading_secret(ep(1, 1), s.clone(), u(3));
        assert!(!r.drop_reading_from(&cid(3)) && r.secret(&ep(1, 1)).is_some());
    }
}
