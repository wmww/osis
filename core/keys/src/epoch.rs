//! Per-role epochs of one actor as a node holds them (spec/crypto.md §4): forks kept,
//! established (fixed, derived, or a held rotation commit or snapshot with its names met), current =
//! established and not superseded by an established rotation, newest = greatest order n, ties by
//! lowest nonce.

use crate::names::{Held, Names};
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

/// How an epoch got established at this node (spec/crypto.md §4). `Fixed` and `Derived` are set
/// directly; `Rotated` is computed by `RoleEpochs::establish`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Provenance {
    /// A key actor's fixed epoch.
    Fixed,
    /// Derived from an established epoch of the owner (a plain thing).
    Derived,
    /// A valid rotation commit of it (this node's own included) or a `secrets.0` compaction
    /// snapshot keying it is held, within headroom, and, its secret held, some history entry of
    /// it has its names met.
    Rotated,
}

impl Provenance {
    /// Set directly, never recomputed.
    pub fn sticky(self) -> bool {
        matches!(self, Provenance::Fixed | Provenance::Derived)
    }
}

/// What a node knows of one epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochInfo {
    /// Suite ID (from the keyset that named it; 1 until one is seen).
    pub suite: u64,
    /// Epochs its opened history box lists (and its rotator's own record). With its rotation
    /// commits' lists (`superseded_epochs`), what it supersedes; counts only once established.
    pub supersedes: BTreeSet<Epoch>,
    /// The held valid rotation commits of it (writing its keyset and history box), each with the
    /// epochs its keyset lists: a holder may re-write an epoch's keyset in a later commit, and
    /// one found invalid leaves the others.
    pub rotations: BTreeMap<CommitId, BTreeSet<Epoch>>,
    /// A held `secrets.0` compaction snapshot keys it.
    pub snapshot: bool,
    /// The names of each history entry of it opened under its secret (spec/crypto.md §4).
    pub names: BTreeSet<Names>,
    /// Established (spec/crypto.md §4): `Fixed` and `Derived` set and persisted; `Rotated`
    /// computed from the held state (`RoleEpochs::establish`), never persisted. Unestablished
    /// epochs are kept for reading only: never current, supersede nothing, never encrypted
    /// under, never put in a history box.
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
        EpochInfo {
            suite: SUITE,
            supersedes: BTreeSet::new(),
            rotations: BTreeMap::new(),
            snapshot: false,
            names: BTreeSet::new(),
            established: None,
            secret: None,
            reading: BTreeSet::new(),
            order: None,
        }
    }
}

impl EpochInfo {
    /// What it supersedes (spec/crypto.md §4): the epochs its valid rotation commits' keysets
    /// list, and those its opened history box lists. A function of the held rotation commits, so
    /// one found invalid leaves nothing behind.
    pub fn superseded_epochs(&self) -> BTreeSet<Epoch> {
        self.supersedes.iter().chain(self.rotations.values().flatten()).copied().collect()
    }

    /// Its secret is known only from pending commits.
    pub fn is_reading_only(&self) -> bool {
        self.secret.is_some() && !self.reading.is_empty()
    }

    /// Its secret when it may be encrypted under (not reading-only).
    pub fn checked(&self) -> Option<&Secret32> {
        self.secret.as_ref().filter(|_| self.reading.is_empty())
    }

    /// A valid rotation commit of it or a `secrets.0` snapshot keying it is held (spec/crypto.md
    /// §4): the base of `Rotated`, before headroom and names.
    pub fn rotated(&self) -> bool {
        !self.rotations.is_empty() || self.snapshot
    }

    /// Invariant (R9): an epoch whose secret is held is used (encrypted under, boxed, put in a
    /// history box) only once some history entry of it has every name met: every departure from
    /// the actor its rotator held is applied here, so this node's roster has those holders
    /// departed and its holder computation boxes none of them.
    /// The rotator names from its own
    /// timeline, so the epochs its history box carries had their names met there, and those names
    /// are among its own: no chain of other rotators' word is followed. An entry is written under
    /// the epoch's secret, so only its holders write one (they could leak it anyway). A secret not
    /// held needs nothing (nothing is boxed or encrypted under it).
    fn names_met(&self, held: &dyn Held) -> bool {
        self.checked().is_none() || self.met_names(held).next().is_some()
    }

    /// The names of its history entries whose names are all met under `held`: what a node relies
    /// on it for (spec/crypto.md §4, covers).
    pub fn met_names<'a>(&'a self, held: &'a dyn Held) -> impl Iterator<Item = &'a Names> + 'a {
        self.names.iter().filter(move |n| n.met(held))
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

/// The greatest n an epoch established by a rotation commit or snapshot may have without an established
/// epoch at n-1 or above (spec/crypto.md §4): leaves 2^62 rotations before n+1 overflows the
/// int range, far above any genuine first n (derived epochs are capped below it).
pub const MAX_FREE_N: u64 = 1 << 62;

/// Whether `e` may be established by a rotation commit or snapshot (spec/crypto.md §4), `est` the epochs
/// established so far: n at most `MAX_FREE_N`, or an established epoch other than `e` has n at
/// least n-1. Every established n is so at most `MAX_FREE_N` plus the number of rotations, so
/// n+1 never overflows.
fn within_headroom(est: &BTreeMap<Epoch, Provenance>, e: &Epoch) -> bool {
    e.n() <= MAX_FREE_N || est.keys().any(|x| x != e && x.n() + 1 >= e.n())
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

    /// Sets `e`'s provenance directly (`Fixed`, `Derived`; `Rotated` set here is recomputed by
    /// the next `establish`).
    pub fn set_established(&mut self, e: Epoch, p: Provenance) {
        self.observe(e).established = Some(p);
    }

    /// Records that held valid rotation commit `commit` writes `e`'s keyset, listing `supersedes`
    /// (`SecretsWrite::rotation_commit`). Only one below `e`'s n count. Returns whether it is new.
    pub fn set_rotation(&mut self, e: Epoch, commit: CommitId, supersedes: BTreeSet<Epoch>) -> bool {
        let list: BTreeSet<Epoch> = supersedes.into_iter().filter(|s| s.n() < e.n()).collect();
        self.observe(e).rotations.insert(commit, list.clone()) != Some(list)
    }

    /// Rotation commit `commit` was found invalid: it no longer counts for the epochs it rotated
    /// to; their other rotation commits stay.
    pub fn invalidate(&mut self, commit: &CommitId) {
        for i in self.map.values_mut() {
            i.rotations.remove(commit);
        }
    }

    /// Records that a held `secrets.0` compaction snapshot keys `e`; whether that is new.
    pub fn set_snapshot(&mut self, e: Epoch) -> bool {
        !std::mem::replace(&mut self.observe(e).snapshot, true)
    }

    /// Records the names of a history entry of `e` opened under its secret.
    pub fn add_names(&mut self, e: Epoch, names: Names) {
        self.observe(e).names.insert(names);
    }

    /// Computes `Rotated` establishment (spec/crypto.md §4) from the held state: a valid rotation
    /// commit or a `secrets.0` snapshot keying it held (`EpochInfo::rotated`), within headroom
    /// (`within_headroom`, a fixpoint over the established set), and its names met under `held`
    /// where its secret is held (`EpochInfo::names_met`). Sticky provenances stay. Returns
    /// whether anything changed.
    pub fn establish(&mut self, held: &dyn Held) -> bool {
        let mut est: BTreeMap<Epoch, Provenance> = self.map.iter().filter_map(|(e, i)| i.established.filter(|p| p.sticky()).map(|p| (*e, p))).collect();
        let base: Vec<Epoch> = self.map.iter().filter(|(e, i)| !est.contains_key(*e) && i.rotated() && i.names_met(held)).map(|(e, _)| *e).collect();
        loop {
            let ready: Vec<Epoch> = base.iter().filter(|e| !est.contains_key(*e) && within_headroom(&est, e)).copied().collect();
            if ready.is_empty() {
                break;
            }
            est.extend(ready.into_iter().map(|e| (e, Provenance::Rotated)));
        }
        let mut changed = false;
        for (e, i) in self.map.iter_mut() {
            if !i.established.is_some_and(Provenance::sticky) {
                let p = est.get(e).copied();
                changed |= i.established != p;
                i.established = p;
            }
        }
        changed
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
        self.map.values().any(|i| i.established.is_some() && i.superseded_epochs().contains(e))
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

    /// Sorts as `e` by age (spec/crypto.md §4): greater order n, then `by_n`, is newer. One order
    /// n holds one n among established epochs (a derived map's n is a function of its order n);
    /// the n tie-break only orders reading-only epochs of an invalid rotation kept beside derived
    /// ones (a reader's try order).
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

    /// The epoch a rotation to `e` is wrapped under (spec/crypto.md §5): what `e` supersedes whose
    /// secret is held, the greatest n, ties by lowest nonce.
    pub fn wrapped_under(&self, e: &Epoch) -> Option<(Epoch, &Secret32)> {
        let info = self.get(e)?;
        info.superseded_epochs().iter().filter_map(|s| self.secret(s).map(|x| (*s, x))).max_by_key(|(s, _)| by_n(s))
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

    /// How many secrets are held, reading-only ones included.
    pub fn secret_count(&self) -> usize {
        self.map.values().filter(|i| i.secret.is_some()).count()
    }

    /// Whether any secret is held, reading-only ones included.
    pub fn holds_any(&self) -> bool {
        self.map.values().any(|i| i.secret.is_some())
    }
}

/// The n of the epochs derived from an owner epoch at `n` (spec/crypto.md §3): the owner's, capped
/// so that a thing's own chain starts at most at `MAX_FREE_N` and a holder holding no secret of
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

    /// Whether any role's secret is held, reading-only ones included.
    pub fn holds_any(&self) -> bool {
        ROLES.iter().any(|r| self.role(*r).holds_any())
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
                    supersedes: i.superseded_epochs().iter().map(id).filter(|x| x != de).collect(),
                    rotations: BTreeMap::new(),
                    snapshot: false,
                    names: BTreeSet::new(),
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
    pub fn establish(&mut self, held: &dyn Held) -> bool {
        let mut changed = false;
        for r in ROLES {
            changed |= self.role_mut(r).establish(held);
        }
        changed
    }

    /// The record behind an established view: `Rotated` cleared (computed by `establish`, never
    /// stored), `Fixed` and `Derived` kept.
    pub fn into_record(mut self) -> ActorEpochs {
        for r in ROLES {
            for i in self.role_mut(r).map.values_mut() {
                i.established = i.established.filter(|p| p.sticky());
            }
        }
        self
    }

    /// `RoleEpochs::invalidate` for every role.
    pub fn invalidate(&mut self, commit: &CommitId) {
        for r in ROLES {
            self.role_mut(r).invalidate(commit);
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
    use crate::names::AllHeld;

    fn ep(n: u64, nonce: u8) -> Epoch {
        Epoch::new(n, [nonce; 32]).unwrap()
    }

    fn cid(b: u8) -> CommitId {
        CommitId([b; 32])
    }

    fn set(es: &[Epoch]) -> BTreeSet<Epoch> {
        es.iter().copied().collect()
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
            r.set_established(e, Provenance::Fixed);
        }
        assert_eq!(r.current(), vec![ep(2, 3), ep(2, 5)]);
        assert_eq!(r.newest(), Some(ep(2, 3)));
        assert_eq!(r.newest_held(), None);
        assert_eq!(r.newest_secret().map(|x| x.0), Some(ep(1, 0)));
        r.set_secret(ep(2, 5), Secret32::from_bytes([2; 32]));
        assert_eq!(r.newest_held().map(|x| x.0), Some(ep(2, 5)));
        r.rotation(ep(3, 9), [ep(2, 5)]);
        r.set_established(ep(3, 9), Provenance::Fixed);
        assert_eq!(r.current(), vec![ep(2, 3), ep(3, 9)]);
        assert_eq!(r.newest(), Some(ep(3, 9)));
        // An unestablished rotation (not applied, pending or invalid) supersedes nothing and is not
        // current.
        r.rotation(ep(4, 1), [ep(3, 9), ep(2, 3)]);
        assert_eq!(r.current(), vec![ep(2, 3), ep(3, 9)]);
        r.set_rotation(ep(4, 1), cid(1), set(&[ep(3, 9), ep(2, 3)]));
        assert!(r.establish(&AllHeld));
        assert_eq!(r.current(), vec![ep(4, 1)]);
        assert_eq!(r.provenance(&ep(4, 1)), Some(Provenance::Rotated));
        // a second rotation commit of e4, then invalidated, leaves e4's rotation applied
        r.set_rotation(ep(4, 1), cid(2), set(&[ep(3, 9)]));
        r.invalidate(&cid(2));
        assert!(!r.establish(&AllHeld));
        assert_eq!(r.provenance(&ep(4, 1)), Some(Provenance::Rotated));
        r.invalidate(&cid(1));
        assert!(r.establish(&AllHeld));
        assert_eq!(r.current(), vec![ep(2, 3), ep(3, 9)]);
        let order: Vec<Epoch> = r.held_newest_first().into_iter().map(|x| x.0).collect();
        assert_eq!(order, vec![ep(2, 5), ep(1, 0)]);
    }

    /// Holds the named commits whose first byte is in `have`, and the departing commit when
    /// `departed`.
    struct Holding {
        have: BTreeSet<u8>,
        departed: bool,
    }

    impl Held for Holding {
        fn met(&self, n: &crate::Name) -> bool {
            self.have.contains(&n.key.commit.0[0])
        }
        fn departed(&self, _: &crate::Own) -> bool {
            self.departed
        }
    }

    fn names(cs: &[u8], departs: bool) -> Names {
        let t = Tid::from_bytes([5; 15]);
        let list = cs.iter().map(|c| crate::Name { thing: t, key: crate::Key { ts: u64::from(*c), node: t, commit: cid(*c) } }).collect();
        Names { list, departs: departs.then_some(crate::Own { ts: 99, node: t }) }
    }

    // spec/crypto.md §4 (established; names): an epoch established by its rotation commit or a
    // snapshot, whose secret is held, is established only once some history entry's names are
    // met, its departing commit included. A secret not held needs no names. No chain: a rotation
    // commit establishes its epoch whatever its predecessors.
    #[test]
    fn names_gate_establishment() {
        let mut r = RoleEpochs::default();
        r.set_rotation(ep(3, 0), cid(3), set(&[ep(2, 0)]));
        let none = Holding { have: BTreeSet::new(), departed: false };
        r.establish(&none);
        assert_eq!(r.current(), vec![ep(3, 0)], "no secret: established by its commit alone, e2 never seen");
        r.set_secret(ep(3, 0), Secret32::from_bytes([3; 32]));
        r.establish(&none);
        assert!(!r.is_established(&ep(3, 0)), "secret held, no history entry opened");
        r.add_names(ep(3, 0), names(&[7, 8], true));
        r.establish(&none);
        assert!(!r.is_established(&ep(3, 0)));
        let some = Holding { have: [7].into(), departed: true };
        r.establish(&some);
        assert!(!r.is_established(&ep(3, 0)), "8 not held");
        r.establish(&Holding { have: [7, 8].into(), departed: false });
        assert!(!r.is_established(&ep(3, 0)), "the departing commit not held");
        let all = Holding { have: [7, 8].into(), departed: true };
        r.establish(&all);
        assert!(r.is_established(&ep(3, 0)));
        // another entry (a forger holding e3) with fewer names: any entry met suffices
        r.add_names(ep(3, 0), names(&[7], false));
        r.establish(&Holding { have: [7].into(), departed: false });
        assert!(r.is_established(&ep(3, 0)));
        // by snapshot alone, alike
        let mut x = RoleEpochs::default();
        x.set_snapshot(ep(4, 0));
        x.set_secret(ep(4, 0), Secret32::from_bytes([4; 32]));
        x.add_names(ep(4, 0), names(&[7], true));
        x.establish(&Holding { have: [7].into(), departed: false });
        assert!(!x.is_established(&ep(4, 0)));
        x.establish(&Holding { have: [7].into(), departed: true });
        assert!(x.is_established(&ep(4, 0)));
        // a reading-only secret needs no names (it is never used)
        let mut y = RoleEpochs::default();
        y.set_rotation(ep(2, 0), cid(2), BTreeSet::new());
        y.set_reading_secret(ep(2, 0), Secret32::from_bytes([2; 32]), Unchecked { author: Tid::from_bytes([1; 15]), commit: cid(1) });
        y.establish(&none);
        assert!(y.is_established(&ep(2, 0)));
    }

    // spec/crypto.md §4 (headroom): an epoch past 2^62 is established only beside an established
    // one at n-1 or above.
    #[test]
    fn headroom() {
        let mut r = RoleEpochs::default();
        let (a, b) = (ep(MAX_FREE_N + 1, 0), ep(MAX_FREE_N + 2, 0));
        r.set_rotation(b, cid(2), BTreeSet::new());
        r.establish(&AllHeld);
        assert!(!r.is_established(&b));
        r.set_rotation(a, cid(1), BTreeSet::new());
        r.establish(&AllHeld);
        assert!(!r.is_established(&a) && !r.is_established(&b));
        r.set_rotation(ep(MAX_FREE_N, 0), cid(3), BTreeSet::new());
        r.establish(&AllHeld);
        assert!(r.is_established(&a) && r.is_established(&b));
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
            owner.read.set_established(e, Provenance::Rotated);
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
                owner.read.set_established(e, Provenance::Rotated);
            }
            let d = ActorEpochs::derived(&owner, &t);
            let old = Epoch::derive(&t, Role::Read, 1, &thing_role_secret(&s(b), Role::Read, &t)).unwrap();
            assert!(crate::is_newer(&d.read.newest().unwrap(), &old));
        }
        let mut owner = ActorEpochs::default();
        for (i, n) in [MAX_FREE_N - 2, MAX_FREE_N + 5, MAX_FREE_N + 6].into_iter().enumerate() {
            owner.read.set_secret(ep(n, 1), Secret32::from_bytes([i as u8; 32]));
            owner.read.set_established(ep(n, 1), Provenance::Rotated);
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
            owner.read.set_established(e, Provenance::Rotated);
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

    // Differential against the hand-written folds the ordering keys replaced: equal on random
    // role epochs (forks, orders, provenances, reading-only secrets). `held_newest_first` differs
    // only where one order n holds two n (the `order_ties_by_n` arm), which a derived map never
    // has (its n is a function of its order n).
    #[test]
    fn ordering_keys_match_folds() {
        fn old_is_newer(a: &Epoch, b: &Epoch) -> bool {
            a.n() > b.n() || (a.n() == b.n() && a.nonce() < b.nonce())
        }
        fn old_newest_of<'a>(es: impl IntoIterator<Item = &'a Epoch>) -> Option<Epoch> {
            es.into_iter().fold(None, |best: Option<Epoch>, e| match best {
                Some(b) if !old_is_newer(e, &b) => Some(b),
                _ => Some(*e),
            })
        }
        fn old_r_is_newer(r: &RoleEpochs, a: &Epoch, b: &Epoch) -> bool {
            let (x, y) = (r.order(a), r.order(b));
            x > y || (x == y && old_is_newer(a, b))
        }
        fn old_r_newest_of(r: &RoleEpochs, es: &[Epoch]) -> Option<Epoch> {
            es.iter().fold(None, |best: Option<Epoch>, e| match best {
                Some(b) if !old_r_is_newer(r, e, &b) => Some(b),
                _ => Some(*e),
            })
        }
        fn old_held_newest_first(r: &RoleEpochs) -> Vec<Epoch> {
            let mut v: Vec<Epoch> = r.map.iter().filter(|(_, i)| i.secret.is_some()).map(|(e, _)| *e).collect();
            v.sort_by_key(|e| (std::cmp::Reverse(r.order(e)), *e.nonce()));
            v
        }
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut rnd = |m: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % m
        };
        let u = |b: u8| Unchecked { author: Tid::from_bytes([b; 15]), commit: cid(b) };
        let mut tie_diffs = 0;
        for case in 0..20000 {
            let free = case % 2 == 1;
            let base = if rnd(3) == 0 { MAX_FREE_N - 3 } else { 0 };
            let mut r = RoleEpochs::default();
            let mut es = Vec::new();
            for _ in 0..1 + rnd(7) {
                let e = ep(base + rnd(4), rnd(3) as u8);
                es.push(e);
                let i = r.observe(e);
                // order n: free, or a function of n as in a derived map (capped n, owner's order)
                i.order = match (free, rnd(3)) {
                    (true, 0) => Some(base + rnd(5)),
                    (false, 0) => Some(e.n() * 3 + 7),
                    _ => None,
                };
                if !free && i.order.is_none() {
                    i.order = Some(e.n() * 3 + 7);
                }
                i.established = [None, Some(Provenance::Fixed), Some(Provenance::Rotated), Some(Provenance::Derived)][rnd(4) as usize];
                match rnd(3) {
                    0 => r.set_secret(e, Secret32::from_bytes([rnd(250) as u8; 32])),
                    1 => r.set_reading_secret(e, Secret32::from_bytes([rnd(250) as u8; 32]), u(1)),
                    _ => {}
                }
            }
            for _ in 0..rnd(3) {
                let (a, b) = (es[rnd(es.len() as u64) as usize], es[rnd(es.len() as u64) as usize]);
                r.rotation(a, [b]);
            }
            for a in &es {
                for b in &es {
                    assert_eq!(is_newer(a, b), old_is_newer(a, b));
                    assert_eq!(r.is_newer(a, b), old_r_is_newer(&r, a, b));
                }
            }
            assert_eq!(newest_of(&es), old_newest_of(&es));
            assert_eq!(r.newest(), old_r_newest_of(&r, &r.current()));
            let cur_held: Vec<Epoch> = r.current().into_iter().filter(|e| r.secret(e).is_some()).collect();
            assert_eq!(r.newest_held().map(|x| x.0), old_r_newest_of(&r, &cur_held));
            let est_held: Vec<Epoch> = r.held_established().map(|(e, _)| e).collect();
            assert_eq!(r.newest_secret().map(|x| x.0), old_r_newest_of(&r, &est_held));
            let new: Vec<Epoch> = r.held_newest_first().into_iter().map(|x| x.0).collect();
            let old = old_held_newest_first(&r);
            if free && new != old {
                tie_diffs += 1;
                // order_ties_by_n: some two held epochs share an order n and differ in n
                assert!(old.iter().any(|a| old.iter().any(|b| r.order(a) == r.order(b) && a.n() != b.n())));
            } else {
                assert_eq!(new, old, "case {case}");
            }
        }
        assert!(tie_diffs > 0);
    }
}
