//! Per-role epochs of one actor as a node holds them (spec/crypto.md §4): forks kept,
//! established (fixed, derived, or a held rotation commit or snapshot with its names met), current =
//! established and not superseded by an established rotation, newest = greatest order n, ties by
//! lowest nonce.

use crate::names::{Held, Names};
use osis_base::{CommitId, Role, Tid};
use osis_crypto::{Epoch, RoleSecret, Secret32, link_key_role_secret, thing_role_secret};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

/// Suite 1, the only suite (spec/crypto.md §8).
pub const SUITE: u64 = 1;

pub const ROLES: [Role; 4] = Role::ALL;

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
    /// Set by construction: a link key's first epochs, from its seed (`ActorEpochs::link_key`).
    Fixed,
    /// Derived from an established epoch of the mint admin (a dependent thing).
    Derived,
    /// A valid rotation commit of it (this node's own included) or a `secrets.0` compaction
    /// snapshot keying it is held, within headroom, and, its secret held, some history entry of
    /// it has its names met.
    Rotated,
}

impl Provenance {
    /// Set directly (`Fixed` in the record, `Derived` by the view from the mint admin), never
    /// recomputed by `establish`.
    pub fn sticky(self) -> bool {
        matches!(self, Provenance::Fixed | Provenance::Derived)
    }
}

/// What a node knows of one epoch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EpochInfo {
    /// Epochs the live entries of its history box list, opened under its secret (a derived
    /// epoch's: what its source supersedes). With its rotation commits' lists
    /// (`superseded_epochs`), what it supersedes; counts only once established. Set whole with
    /// `names` (`RoleEpochs::set_history`): a function of the entries live now, so an entry that
    /// leaves the state (stripped as invalid, overwritten) leaves nothing behind.
    pub supersedes: BTreeSet<Epoch>,
    /// The held valid rotation commits of it (writing its keyset and history box), each with the
    /// epochs its keyset lists: a holder may re-write an epoch's keyset in a later commit, and
    /// one found invalid leaves the others.
    pub rotations: BTreeMap<CommitId, BTreeSet<Epoch>>,
    /// The held valid `secrets.0` compaction snapshots keying it; one found invalid leaves the
    /// others.
    pub snapshots: BTreeSet<CommitId>,
    /// The names of each live entry of its history box opened under its secret (spec/crypto.md
    /// §4), set with `supersedes`.
    pub names: BTreeSet<Names>,
    /// The greatest floor a live entry of its history box opened under its secret writes
    /// (spec/crypto.md §4, Floors), set with `supersedes`; none opened: `None`.
    pub floor: Option<u64>,
    /// At admin, the actor's genesis seed (spec/crypto.md §3 Genesis seed): what a live entry of
    /// its history box opened under its secret carries (the least, where entries differ), set
    /// with `supersedes`; a derived epoch's, from its base epoch's (`ActorEpochs::derived`).
    pub genesis: Option<Secret32>,
    /// Established (spec/crypto.md §4): `Fixed` and `Derived` set and persisted; `Rotated`
    /// computed from the held state (`RoleEpochs::establish`), never persisted. Unestablished
    /// epochs are kept for reading only: never current, supersede nothing, never encrypted
    /// under, never put in a history box.
    pub established: Option<Provenance>,
    /// Its secret: the one it names (spec/crypto.md §4, every source is checked by the nonce
    /// rule before it gets here), held with its KEM key pair.
    pub secret: Option<RoleSecret>,
    /// Its roles secret (spec/crypto.md §4, Roles secrets) when known apart from its secret: from
    /// a history entry opened. It opens the role parts and wraps sealed under the epoch, nothing
    /// else; never encrypted under. Known only from pending commits (`roles_reading`
    /// non-empty), it is for opening alone, as a reading-only secret is.
    pub roles: Option<Secret32>,
    /// The pending commits the roles secret is known from, when known only from such: `reading`
    /// for `roles`, each secret going with its own last source.
    pub roles_reading: BTreeSet<Unchecked>,
    /// The pending commits the secret is known from, when known only from such (their boxes, or
    /// history boxes opened with a secret so known): non-empty, the secret is kept for reading,
    /// never encrypted under, until an applied valid box or a history box opened with a secret
    /// not so known carries it (spec/crypto.md §4). Such epochs are bounded per role
    /// (`MAX_READING`, `MAX_READING_PER_AUTHOR`); dropped with their last source commit
    /// (`drop_reading_from`).
    pub reading: BTreeSet<Unchecked>,
    /// A derived epoch's order n where it differs from its n: the base epoch's (past the cap,
    /// `derived_n`). It orders (`RoleEpochs::is_newer`) by this, so derived epochs order as the
    /// mint admin's (spec/crypto.md §3, §4).
    pub order: Option<u64>,
    /// Foreign at this node (spec/crypto.md §4 Holder actors, Foreign): its rotation commit boxes
    /// a holder actor at a keyset held invalid or foreign here. Set on the view
    /// (`RoleEpochs::set_foreign`), never stored. It supersedes nothing here (`superseding`) and
    /// is never the newest (nobody here encrypts under it), but stays current where nothing
    /// else supersedes it.
    pub foreign: bool,
}

impl EpochInfo {
    /// What it supersedes (spec/crypto.md §4): the epochs its valid rotation commits' keysets
    /// list, and those the live entries of its history box list. A function of the held rotation
    /// commits and live entries, so one found invalid leaves nothing behind.
    pub fn superseded_epochs(&self) -> BTreeSet<Epoch> {
        self.superseded_iter().copied().collect()
    }

    /// `superseded_epochs`, unsorted and possibly repeated.
    fn superseded_iter(&self) -> impl Iterator<Item = &Epoch> {
        self.supersedes.iter().chain(self.rotations.values().flatten())
    }

    /// What it supersedes at this node (spec/crypto.md §4, Supersedes): `superseded_epochs`,
    /// nothing where it is foreign. What its commit lists (`superseded_epochs`) is alike at every
    /// node; whether that supersedes is the node's.
    fn superseding(&self) -> impl Iterator<Item = &Epoch> {
        self.superseded_iter().filter(|_| !self.foreign)
    }

    /// `superseding` names `e`.
    fn supersedes(&self, e: &Epoch) -> bool {
        !self.foreign && (self.supersedes.contains(e) || self.rotations.values().any(|r| r.contains(e)))
    }

    /// Its secret, or its roles secret, is known only from pending commits.
    pub fn is_reading_only(&self) -> bool {
        (self.secret.is_some() && !self.reading.is_empty()) || (self.roles.is_some() && !self.roles_reading.is_empty())
    }

    /// The pending commits its secret or its roles secret is known from.
    pub fn sources(&self) -> impl Iterator<Item = &Unchecked> {
        self.reading.iter().chain(&self.roles_reading)
    }

    /// Its secret when it may be encrypted under (not reading-only).
    pub fn checked(&self) -> Option<&RoleSecret> {
        self.secret.as_ref().filter(|_| self.reading.is_empty())
    }

    /// Its roles secret when it may be encrypted under (`RoleEpochs::checked_roles`).
    pub fn checked_roles(&self) -> Option<Secret32> {
        self.checked().map(|s| osis_crypto::roles_secret(s)).or_else(|| self.roles.clone().filter(|_| self.roles_reading.is_empty()))
    }

    /// A valid rotation commit of it or a `secrets.0` snapshot keying it is held (spec/crypto.md
    /// §4): the base of `Rotated`, before headroom and names.
    pub fn rotated(&self) -> bool {
        !self.rotations.is_empty() || !self.snapshots.is_empty()
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

    /// The names of its history entries whose names are all met under `held`: what establishes
    /// it (spec/crypto.md §4, established).
    pub fn met_names<'a>(&'a self, held: &'a dyn Held) -> impl Iterator<Item = &'a Names> + 'a {
        self.names.iter().filter(move |n| n.met(held))
    }

    /// The names it (epoch `e` of role `r`) covers departures by (spec/crypto.md §4, covers):
    /// those of a history entry whose names are met and whose digest a held valid keyset of `e`
    /// publishes by an author holding `r` (`Held::publishes`). An entry by anyone else, or by a
    /// rotator since lowered below `r`, covers nothing.
    pub fn covering_names<'a>(&'a self, r: Role, e: &'a Epoch, held: &'a dyn Held) -> impl Iterator<Item = &'a Names> + 'a {
        self.met_names(held).filter(move |n| held.publishes(r, e, &n.digest()))
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
/// (local policy: each costs a KEM or DH per open, claim and sealed fire, since wraps name no
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
    /// The floors of the read role (spec/crypto.md §4, Floors) as this node reads them, set on
    /// the view (`set_floors`), never stored. `None`: no floors (every other role, a record):
    /// every floor 0, the carry and boxing rules pass everything.
    floors: Option<Box<Floors>>,
}

/// Floors as a node reads them (spec/crypto.md §4, Floors).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Floors {
    /// Per epoch with a known floor (a live entry of its history box opened, or fixed or
    /// derived): the greatest those entries write, at most its n.
    known: BTreeMap<Epoch, u64>,
    /// Per epoch whose maker's floor is known: that floor (its newest grant's).
    makers: BTreeMap<Epoch, u64>,
    /// This node's own floor on the actor.
    own: u64,
}

impl RoleEpochs {
    /// Records that epoch `e` exists (a box or history key names it).
    pub fn observe(&mut self, e: Epoch) -> &mut EpochInfo {
        self.map.entry(e).or_default()
    }

    /// Sets what `e`'s history box says (spec/crypto.md §4): the names of its live entries, the
    /// epochs they list (only those below `e`'s n count) and the greatest floor they write,
    /// replacing what it said before.
    pub fn set_history(&mut self, e: Epoch, names: BTreeSet<Names>, listed: impl IntoIterator<Item = Epoch>, floor: Option<u64>) {
        let info = self.observe(e);
        info.names = names;
        info.supersedes = listed.into_iter().filter(|s| s.n() < e.n()).collect();
        info.floor = floor;
    }

    /// `e`'s history box says nothing (no live entry opened under its secret held): it names and
    /// lists nothing.
    pub fn clear_history(&mut self, e: &Epoch) {
        if let Some(i) = self.map.get_mut(e) {
            i.names.clear();
            i.supersedes.clear();
            i.floor = None;
            i.genesis = None;
        }
    }

    /// Sets the genesis seed `e`'s history box carries (spec/crypto.md §3 Genesis seed), with
    /// `set_history`.
    pub fn set_genesis(&mut self, e: Epoch, genesis: Option<Secret32>) {
        self.observe(e).genesis = genesis;
    }

    /// The genesis seed this role's epochs carry (`ActorEpochs::genesis`): the least any carries.
    pub fn genesis(&self) -> Option<&Secret32> {
        self.map.values().filter_map(|i| i.genesis.as_ref()).min_by(|a, b| a.expose().cmp(b.expose()))
    }

    /// Sets `e`'s secret, known from a source that is no pending commit (an applied valid box, a
    /// history box opened with such a secret, an entry, an own rotation, derivation): it may
    /// be encrypted under once `e` is established.
    pub fn set_secret(&mut self, e: Epoch, secret: impl Into<RoleSecret>) {
        let info = self.observe(e);
        info.secret = Some(secret.into());
        info.reading.clear();
        // the roles secret derives from it
        info.roles = None;
        info.roles_reading.clear();
    }

    /// Sets `e`'s roles secret, from a history entry opened under a secret not reading-only. One
    /// whose checked secret is held keeps none apart (it derives from the secret), as when the
    /// secret came second (`set_secret`): the record is the same in either order.
    pub fn set_roles(&mut self, e: Epoch, roles: Secret32) {
        if self.map.get(&e).is_some_and(|i| i.checked().is_some()) {
            return;
        }
        let info = self.observe(e);
        info.roles = Some(roles);
        info.roles_reading.clear();
    }

    /// Records a roles secret known only from pending commit `from` (a history entry opened under
    /// a reading-only secret): for opening alone, within the reading-only bounds
    /// (`set_reading_secret`); it goes with its last source.
    pub fn set_reading_roles(&mut self, e: Epoch, roles: Secret32, from: Unchecked) {
        match self.map.get_mut(&e) {
            Some(i) if i.checked_roles().is_some() => return,
            Some(i) if i.secret.is_some() || i.roles.is_some() => {
                i.roles.get_or_insert(roles);
                i.roles_reading.insert(from);
                return;
            }
            _ => {}
        }
        if !self.reading_room(&from) {
            return;
        }
        let info = self.observe(e);
        info.roles = Some(roles);
        info.roles_reading.insert(from);
    }

    /// `e`'s roles secret: derived from its secret when held (reading-only included), else as a
    /// history entry carried it.
    pub fn roles_secret(&self, e: &Epoch) -> Option<Secret32> {
        let i = self.map.get(e)?;
        i.secret.as_ref().map(|s| osis_crypto::roles_secret(s)).or_else(|| i.roles.clone())
    }

    /// `e`'s roles secret when it may be encrypted under: from its secret (not reading-only), else
    /// as a history entry opened under a secret not reading-only carried it.
    pub fn checked_roles(&self, e: &Epoch) -> Option<Secret32> {
        self.map.get(e).and_then(EpochInfo::checked_roles)
    }

    /// The roles secret of every epoch whose secret (not reading-only) or roles secret is held,
    /// ascending: what a history entry carries of the epochs below its own (spec/crypto.md §4).
    pub fn held_roles(&self) -> Vec<(Epoch, Secret32)> {
        self.map.iter().filter_map(|(e, i)| i.checked_roles().map(|r| (*e, r))).collect()
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
        if !self.reading_room(&from) {
            return;
        }
        let info = self.observe(e);
        info.secret = Some(secret.into());
        info.reading.insert(from);
    }

    /// Whether a new epoch known only from `from` fits the reading-only bounds.
    fn reading_room(&self, from: &Unchecked) -> bool {
        let reading = self.map.values().filter(|i| i.is_reading_only());
        let (total, mine) = reading.fold((0, 0), |(t, m), i| (t + 1, m + usize::from(i.sources().any(|u| u.author == from.author))));
        total < MAX_READING && mine < MAX_READING_PER_AUTHOR
    }

    /// Drops `commit` as a source of reading-only secrets (it applied, or was dropped as bad
    /// input); a secret it was the last source of goes. Returns whether any source went.
    pub fn drop_reading_from(&mut self, commit: &CommitId) -> bool {
        let mut touched = Vec::new();
        for (e, i) in self.map.iter_mut() {
            // each secret goes with its own last source
            let (a, b) = (drop_source(&mut i.reading, commit), drop_source(&mut i.roles_reading, commit));
            if a == Some(true) {
                i.secret = None;
            }
            if b == Some(true) {
                i.roles = None;
            }
            if a.is_some() || b.is_some() {
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
    /// (`SecretsWrite::rotation_commit`). Only epochs below `e`'s n count. Returns whether it is
    /// new.
    pub fn set_rotation(&mut self, e: Epoch, commit: CommitId, supersedes: BTreeSet<Epoch>) -> bool {
        let list: BTreeSet<Epoch> = supersedes.into_iter().filter(|s| s.n() < e.n()).collect();
        self.observe(e).rotations.insert(commit, list.clone()) != Some(list)
    }

    /// Rotation commit or compaction snapshot `commit` was found invalid: it no longer counts for
    /// the epochs it rotated to or keys; their other commits stay.
    pub fn invalidate(&mut self, commit: &CommitId) {
        for i in self.map.values_mut() {
            i.rotations.remove(commit);
            i.snapshots.remove(commit);
        }
    }

    /// Records that held valid `secrets.0` compaction snapshot `commit` keys `e`; whether that is
    /// new.
    pub fn set_snapshot(&mut self, e: Epoch, commit: CommitId) -> bool {
        self.observe(e).snapshots.insert(commit)
    }

    /// Computes `Rotated` establishment (spec/crypto.md §4) from the held state: a valid rotation
    /// commit or a `secrets.0` snapshot keying it held (`EpochInfo::rotated`), within headroom
    /// (`within_headroom`, a fixpoint over the established set), and its names met under `held`
    /// where its secret is held (`EpochInfo::names_met`). Sticky provenances stay. Returns
    /// whether anything changed.
    pub fn establish(&mut self, held: &dyn Held) -> bool {
        let est = self.established_by(|i| i.names_met(held));
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

    /// The established epochs with their provenance, `met` standing for the names condition:
    /// sticky ones, and those rotated (`EpochInfo::rotated`) and `met`, within headroom (a
    /// fixpoint over the set).
    fn established_by(&self, met: impl Fn(&EpochInfo) -> bool) -> BTreeMap<Epoch, Provenance> {
        let mut est: BTreeMap<Epoch, Provenance> = self.map.iter().filter_map(|(e, i)| i.established.filter(|p| p.sticky()).map(|p| (*e, p))).collect();
        let base: Vec<Epoch> = self.map.iter().filter(|(e, i)| !est.contains_key(*e) && i.rotated() && met(i)).map(|(e, _)| *e).collect();
        loop {
            let ready: Vec<Epoch> = base.iter().filter(|e| !est.contains_key(*e) && within_headroom(&est, e)).copied().collect();
            if ready.is_empty() {
                return est;
            }
            est.extend(ready.into_iter().map(|e| (e, Provenance::Rotated)));
        }
    }

    /// Unsuperseded epochs (spec/crypto.md §4): those current with the names condition of
    /// establishment dropped, as a node holding none of the role's secrets counts them (but for
    /// what the history boxes it opens list), ascending. One unsuperseded and not current here
    /// has names this node does not meet, yet is current wherever its secret is not held: a
    /// rotation lists it, and its maker withdraws it.
    pub fn unsuperseded(&self) -> Vec<Epoch> {
        let est = self.established_names_aside();
        let superseded: BTreeSet<&Epoch> = est.keys().filter_map(|e| self.map.get(e)).flat_map(EpochInfo::superseding).collect();
        est.into_keys().filter(|e| !superseded.contains(e)).collect()
    }

    /// The epochs established with the names condition dropped (spec/crypto.md §4): what a node
    /// holding none of the role's secrets counts established, and what a `secrets.0` compaction
    /// snapshot may key (`unvouched`).
    pub fn established_names_aside(&self) -> BTreeMap<Epoch, Provenance> {
        self.established_by(|_| true)
    }

    pub fn is_established(&self, e: &Epoch) -> bool {
        self.provenance(e).is_some()
    }

    pub fn provenance(&self, e: &Epoch) -> Option<Provenance> {
        self.map.get(e).and_then(|i| i.established)
    }

    pub fn get(&self, e: &Epoch) -> Option<&EpochInfo> {
        self.map.get(e)
    }

    /// `e`'s secret when it may be encrypted under (not reading-only).
    pub fn secret(&self, e: &Epoch) -> Option<&RoleSecret> {
        self.map.get(e).and_then(EpochInfo::checked)
    }

    /// `e`'s secret for reading, reading-only included (opening a sync ID, unwrapping, opening
    /// history boxes).
    pub fn reading_secret(&self, e: &Epoch) -> Option<&RoleSecret> {
        self.map.get(e).and_then(|i| i.secret.as_ref())
    }

    /// Every known epoch, ascending.
    pub fn epochs(&self) -> impl Iterator<Item = (&Epoch, &EpochInfo)> {
        self.map.iter()
    }

    /// Every held secret that may be encrypted under (not reading-only), ascending by epoch.
    pub fn held(&self) -> impl Iterator<Item = (Epoch, &RoleSecret)> {
        self.map.iter().filter_map(|(e, i)| i.checked().map(|s| (*e, s)))
    }

    /// Superseded by an established rotation.
    pub fn superseded(&self, e: &Epoch) -> bool {
        self.map.values().any(|i| i.established.is_some() && i.supersedes(e))
    }

    /// Current epochs: established, not superseded, and not below this node's own floor
    /// (spec/crypto.md §4, Current), ascending.
    pub fn current(&self) -> Vec<Epoch> {
        let superseded: BTreeSet<&Epoch> = self.map.values().filter(|i| i.established.is_some()).flat_map(EpochInfo::superseding).collect();
        self.map.iter().filter(|(e, i)| i.established.is_some() && !superseded.contains(e) && self.at_own_floor(e)).map(|(e, _)| *e).collect()
    }

    pub fn is_current(&self, e: &Epoch) -> bool {
        self.is_established(e) && !self.superseded(e) && self.at_own_floor(e)
    }

    /// Sets the floors this node reads (spec/crypto.md §4, Floors): `makers` the floor of each
    /// epoch's maker where it is known, `own` this node's. Each epoch's floor is the greatest its
    /// live history entries opened here write (only a holder of its secret writes one, so no
    /// other party sets it), at most its n; a fixed epoch's, or one an independent thing
    /// adopted from its mint admin, is 0 (a dependent thing's view reads its base epochs' floors,
    /// `derived`); one with no entry opened has none known.
    pub fn set_floors(&mut self, makers: BTreeMap<Epoch, u64>, own: u64) {
        let known = self
            .map
            .iter()
            .filter_map(|(e, i)| if i.established.is_some_and(Provenance::sticky) { Some((*e, 0)) } else { i.floor.map(|w| (*e, w.min(e.n()))) })
            .collect();
        self.floors = Some(Box::new(Floors { known, makers, own }));
    }

    /// Whether floors are read for this role (the read role of an actor's view).
    pub fn has_floors(&self) -> bool {
        self.floors.is_some()
    }

    /// `e`'s floor as this node reads it (spec/crypto.md §4, Floors): 0 where unknown.
    pub fn floor(&self, e: &Epoch) -> u64 {
        self.floors.as_ref().and_then(|f| f.known.get(e)).copied().unwrap_or(0)
    }

    /// This node's own floor on the actor (0 without floors).
    pub fn own_floor(&self) -> u64 {
        self.floors.as_ref().map_or(0, |f| f.own)
    }

    fn at_own_floor(&self, e: &Epoch) -> bool {
        self.floors.as_ref().is_none_or(|f| self.floor(e) >= f.own)
    }

    /// The boxing rule (spec/crypto.md §4): a holder of floor `holder` may be boxed at `e`.
    pub fn allows(&self, e: &Epoch, holder: u64) -> bool {
        self.floors.is_none() || self.floor(e) >= holder
    }

    /// The carry rule (spec/crypto.md §4): an entry at epoch `e` may carry `f`'s secret: `f`'s
    /// floor is at least `e`'s and at least the floor of `e`'s maker. Never where `e`'s floor or
    /// its maker's is unknown here.
    pub fn carries(&self, e: &Epoch, f: &Epoch) -> bool {
        let Some(fl) = &self.floors else { return true };
        let (Some(fe), Some(fm)) = (fl.known.get(e), fl.makers.get(e)) else { return false };
        let ff = self.floor(f);
        ff >= *fe && ff >= *fm
    }

    /// The **dropped** epochs (spec/crypto.md §4, Floors): established, secret held, listed by a
    /// held rotation that may not carry it (the carry rule at that rotation's epoch: what a cut
    /// lists, a fork beside a cut that a later rotation lists). No history entry carries them on;
    /// a grant with history boxes them, a holder of one boxes it to a holder lacking it (the tip
    /// add). Ascending.
    pub fn dropped(&self) -> Vec<Epoch> {
        if self.floors.is_none() {
            return Vec::new();
        }
        self.held_established()
            .map(|(f, _)| f)
            .filter(|f| !self.is_current(f) && self.map.iter().any(|(e, i)| i.rotations.values().any(|l| l.contains(f)) && !self.carries(e, f)))
            .collect()
    }

    /// The carry rule for the entry of the epoch a rotation makes, of floor `floor` (its own epoch
    /// is not in the view yet). Its maker's floor is at most `floor`, the greatest of its maker's
    /// and its holders' (`rotate`), so `floor` alone decides.
    pub fn carries_into(&self, floor: u64, f: &Epoch) -> bool {
        self.floors.is_none() || self.floor(f) >= floor
    }

    /// `e`'s order n (spec/crypto.md §4): a derived epoch's is the base epoch's, any other's
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
    fn newest_with<'a>(&self, held: impl Iterator<Item = (Epoch, &'a RoleSecret)>) -> Option<(Epoch, &'a RoleSecret)> {
        held.max_by_key(|(e, _)| self.by_order(e))
    }

    /// What the epochs `given` supersede (spec/crypto.md §4), together; `None` when one of them is
    /// not held to tell.
    pub fn superseded_by<'a>(&self, given: impl IntoIterator<Item = &'a Epoch>) -> Option<BTreeSet<Epoch>> {
        given.into_iter().try_fold(BTreeSet::new(), |mut out, e| {
            out.extend(self.get(e)?.superseded_iter());
            Some(out)
        })
    }

    /// The epoch a commit giving the epochs `given` is wrapped under (spec/crypto.md §5): of what
    /// they supersede, among those `keep` keeps (whose secret, or roles secret, is held), the one
    /// with the greatest n, ties by lowest nonce.
    pub fn wrapped_under<'a>(&self, given: impl IntoIterator<Item = &'a Epoch>, keep: impl Fn(&Epoch) -> bool) -> Option<Epoch> {
        self.superseded_by(given)?.into_iter().filter(|s| keep(s)).max_by_key(by_n)
    }

    /// The newest current epoch that is not foreign (spec/crypto.md §4, Newest).
    pub fn newest(&self) -> Option<Epoch> {
        self.current().into_iter().filter(|e| !self.is_foreign(e)).max_by_key(|e| self.by_order(e))
    }

    /// Marks `e` foreign at this node (spec/crypto.md §4 Holder actors, Foreign; on the view).
    pub fn set_foreign(&mut self, e: &Epoch) {
        if let Some(i) = self.map.get_mut(e) {
            i.foreign = true;
        }
    }

    /// Whether `e` is foreign at this node (`EpochInfo::foreign`).
    pub fn is_foreign(&self, e: &Epoch) -> bool {
        self.map.get(e).is_some_and(|i| i.foreign)
    }

    /// Whether the secret of every current epoch is held, and there is one (what a holder reaches
    /// once every history add has settled; a rotation needs none of them, spec/crypto.md §4).
    pub fn holds_current(&self) -> bool {
        let cur = self.current();
        !cur.is_empty() && cur.iter().all(|e| self.secret(e).is_some())
    }

    /// The names a history box of `e` (this role `r`) written here carries (spec/crypto.md §4,
    /// History box): those of a met entry bound to a held valid keyset of `e`, else of any met
    /// entry; none when no entry is met (the epoch is not established with its secret held).
    pub fn history_names(&self, r: Role, e: &Epoch, held: &dyn Held) -> Option<Names> {
        let i = self.get(e)?;
        i.covering_names(r, e, held).next().or_else(|| i.met_names(held).next()).cloned()
    }

    /// The newest current epoch whose secret is held, not foreign (spec/crypto.md §4, Newest).
    pub fn newest_held(&self) -> Option<(Epoch, &RoleSecret)> {
        let current = self.current();
        self.newest_with(self.held().filter(|(e, _)| current.binary_search(e).is_ok() && !self.is_foreign(e)))
    }

    /// The newest established epoch whose secret is held, current or not.
    pub fn newest_secret(&self) -> Option<(Epoch, &RoleSecret)> {
        self.newest_with(self.held_established())
    }

    /// Held established secrets, ascending by epoch: what a history box carries (spec/crypto.md
    /// §4).
    pub fn held_established(&self) -> impl Iterator<Item = (Epoch, &RoleSecret)> {
        self.held().filter(|(e, _)| self.is_established(e))
    }

    /// Held secrets, newest first (a reader tries them in this order, spec/crypto.md §5),
    /// reading-only ones included.
    pub fn held_newest_first(&self) -> Vec<(Epoch, &RoleSecret)> {
        let mut v: Vec<(Epoch, &RoleSecret)> = self.map.iter().filter_map(|(e, i)| i.secret.as_ref().map(|s| (*e, s))).collect();
        v.sort_by_key(|(e, _)| Reverse(self.by_order(e)));
        v
    }

    /// What opens a wrap or section sealed under an epoch of this role (spec/crypto.md §5), newest
    /// first: per epoch its secret, if held (reading-only included), then its roles secret.
    pub fn opening_newest_first(&self) -> Vec<Secret32> {
        let mut v: Vec<(Epoch, &EpochInfo)> = self.map.iter().filter(|(_, i)| i.secret.is_some() || i.roles.is_some()).map(|(e, i)| (*e, i)).collect();
        v.sort_by_key(|(e, _)| Reverse(self.by_order(e)));
        v.into_iter().flat_map(|(_, i)| i.secret.as_ref().map(|s| s.secret().clone()).into_iter().chain(i.secret.as_ref().map(|s| osis_crypto::roles_secret(s)).or_else(|| i.roles.clone()))).collect()
    }

    /// Whether any secret is held, reading-only ones included.
    pub fn holds_any(&self) -> bool {
        self.map.values().any(|i| i.secret.is_some())
    }
}

/// Drops `commit` from `from`: `None` when it was not there, else whether `from` is now empty.
fn drop_source(from: &mut BTreeSet<Unchecked>, commit: &CommitId) -> Option<bool> {
    let n = from.len();
    from.retain(|u| u.commit != *commit);
    (from.len() != n).then_some(from.is_empty())
}

/// The n of the epochs derived from a base epoch at `n` (spec/crypto.md §3): the mint admin's, capped
/// so that a thing's own chain starts at most at `MAX_FREE_N` and a holder holding no secret of
/// the mint admin establishes it within headroom, whatever n a writer of the mint admin jumped to. Derived
/// epochs still order as the mint admin's (`EpochInfo::order`): a re-registrar steps a dependent's
/// sync IDs on each mint admin rotation, a writer picks the mint admin's newest fork.
fn derived_n(n: u64) -> u64 {
    n.min(MAX_FREE_N - 1)
}

/// The nonce of the placeholder `ActorEpochs::derived` keeps for base epoch `e` whose secret is
/// not held: a hash of all of `e` (local only), so distinct base epochs never share one even
/// when made-up ones share a nonce or are capped to one n.
fn placeholder_nonce(e: &Epoch) -> [u8; 32] {
    osis_base::hash::derive_key("osis v1 derived placeholder", &[e.n().to_le_bytes().as_slice(), e.nonce()].concat())
}

/// The epochs of the four roles of one actor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActorEpochs {
    pub sync: RoleEpochs,
    pub read: RoleEpochs,
    pub write: RoleEpochs,
    pub admin: RoleEpochs,
}

impl ActorEpochs {
    /// The actor's genesis seed as its admin epochs here carry it (spec/crypto.md §3 Genesis
    /// seed): every admin writes the same one; where entries differ, the least.
    pub fn genesis(&self) -> Option<&Secret32> {
        self.admin.genesis()
    }

    pub fn role(&self, r: Role) -> &RoleEpochs {
        match r {
            Role::Sync => &self.sync,
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
            Role::Sync => &mut self.sync,
            Role::Read => &mut self.read,
            Role::Write => &mut self.write,
            Role::Admin => &mut self.admin,
        }
    }

    /// Link key `tid`'s first epochs (spec/crypto.md §3): its minting commit's rotation from
    /// none, each role's secret `kdf("role <role>", seed)` at n 1 by the nonce rule. What the
    /// seed alone opens, from a store holding nothing else (spec/permissions.md §7).
    pub fn link_key(tid: &Tid, seed: &Secret32) -> ActorEpochs {
        let mut a = ActorEpochs::default();
        for r in ROLES {
            let s = link_key_role_secret(seed, r);
            // n 1 is far below the cap
            let Ok(e) = Epoch::derive(tid, r, 1, &s) else { continue };
            a.role_mut(r).set_secret(e, s);
            a.role_mut(r).set_established(e, Provenance::Fixed);
        }
        a
    }

    /// The epoch and secret of role `r` of dependent thing `tid` derived from mint admin epoch `e`
    /// with secret `s` (spec/crypto.md §3): one entry of `derived`.
    pub fn derived_epoch(tid: &Tid, r: Role, e: &Epoch, s: &Secret32) -> (Epoch, Secret32) {
        let ds = thing_role_secret(s, r, tid);
        // never falls back: n is below the cap, within the int range
        let de = Epoch::derive(tid, r, derived_n(e.n()), &ds).unwrap_or(*e);
        (de, ds)
    }

    /// A dependent thing's derived role secrets `kdf("thing <role>", mint admin's secret, tid)`, one per
    /// epoch of the mint admin, forks included, each at the epoch with n `derived_n` of the mint admin's
    /// that the nonce rule gives it (spec/crypto.md §3). Established (`Derived`) where the
    /// mint admin's is. A base epoch whose secret is not held stays known as a placeholder at that
    /// n (`placeholder_nonce`) that no secret names, so that what it supersedes stays superseded.
    pub fn derived(base: &ActorEpochs, tid: &Tid) -> ActorEpochs {
        let mut a = ActorEpochs::default();
        for r in ROLES {
            let o = base.role(r);
            let ids: BTreeMap<Epoch, (Epoch, Option<Secret32>)> = o
                .map
                .iter()
                .map(|(e, i)| match &i.secret {
                    Some(s) => {
                        let (de, ds) = ActorEpochs::derived_epoch(tid, r, e, s);
                        (*e, (de, Some(ds)))
                    }
                    // never falls back: n is below the cap, within the int range
                    None => (*e, (Epoch::new(derived_n(e.n()), placeholder_nonce(e)).unwrap_or(*e), None)),
                })
                .collect();
            let id = |e: &Epoch| ids.get(e).map_or(*e, |x| x.0);
            for (e, i) in &o.map {
                let Some((de, ds)) = ids.get(e) else { continue };
                let info = EpochInfo {
                    // past the cap two base epochs with one secret derive one epoch: it never
                    // supersedes itself
                    supersedes: i.superseding().map(id).filter(|x| x != de).collect(),
                    established: i.established.map(|_| Provenance::Derived),
                    secret: ds.clone().map(RoleSecret::new),
                    reading: i.reading.clone(),
                    order: Some(o.order(e)).filter(|&x| x != de.n()),
                    foreign: i.foreign,
                    // g(X) = kdf("sync genesis", g(mint admin), tid) (spec/crypto.md §3)
                    genesis: i.genesis.as_ref().map(|g| osis_crypto::genesis_seed(g, tid)),
                    ..EpochInfo::default()
                };
                a.role_mut(r).map.insert(*de, info);
            }
            // a dependent thing's content is the mint admin's: each derived epoch reads its base
            // epoch's floor (spec/crypto.md §4, Floors), so what a cut keeps from a holder
            // stays kept on every dependent thing below it
            if let Some(f) = &o.floors {
                let through = |m: &BTreeMap<Epoch, u64>| m.iter().filter_map(|(e, x)| ids.get(e).map(|d| (d.0, *x))).collect();
                a.role_mut(r).floors = Some(Box::new(Floors { known: through(&f.known), makers: through(&f.makers), own: f.own }));
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

    /// The record behind an established view: `Rotated` and `Derived` cleared (computed from
    /// what the node holds, never stored), `Fixed` kept.
    pub fn into_record(mut self) -> ActorEpochs {
        for r in ROLES {
            self.role_mut(r).floors = None;
            for i in self.role_mut(r).map.values_mut() {
                i.established = i.established.filter(|p| *p == Provenance::Fixed);
                i.foreign = false;
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
    // spec/crypto.md §4 (Roles secrets): a roles secret from a pending commit's entry opens, is
    // carried by no entry this node writes, and goes with its last source; one from a checked
    // entry is held for good.
    #[test]
    fn reading_roles_open_and_go_with_their_source() {
        let mut r = RoleEpochs::default();
        let u = Unchecked { author: Tid::from_bytes([1; 15]), commit: cid(1) };
        let (e, f) = (ep(1, 1), ep(2, 2));
        let rs = |b: u8| Secret32::from_bytes([b; 32]);
        r.set_reading_roles(e, rs(7), u);
        assert!(r.roles_secret(&e).is_some() && r.opening_newest_first().len() == 1);
        assert!(r.held_roles().is_empty(), "a reading-only roles secret is carried on");
        r.set_roles(f, rs(8));
        assert_eq!(r.held_roles().iter().map(|x| x.0).collect::<Vec<_>>(), vec![f]);
        assert!(r.drop_reading_from(&u.commit));
        assert!(r.get(&e).is_none() && r.roles_secret(&f).is_some());
    }

    // spec/crypto.md §4 (Reading-only secrets; Roles secrets): each secret goes with its own last
    // source. An epoch's secret known from a pending commit and its roles secret from a checked
    // history entry: the commit going leaves the roles secret held, as a record that never saw
    // the commit holds it (the engine's live index against its rebuild).
    #[test]
    fn a_checked_roles_secret_outlives_the_pending_source_of_its_epochs_secret() {
        let u = Unchecked { author: Tid::from_bytes([1; 15]), commit: cid(1) };
        let e = ep(6, 6);
        let (s, rs) = (Secret32::from_bytes([1; 32]), Secret32::from_bytes([2; 32]));
        let mut rebuilt = RoleEpochs::default();
        rebuilt.set_roles(e, rs.clone());
        for pending_first in [true, false] {
            let mut live = RoleEpochs::default();
            if pending_first {
                live.set_reading_secret(e, s.clone(), u);
                live.set_roles(e, rs.clone());
            } else {
                live.set_roles(e, rs.clone());
                live.set_reading_secret(e, s.clone(), u);
            }
            assert_eq!(live.checked_roles(&e), Some(rs.clone()), "checked while its secret is reading-only");
            assert!(live.drop_reading_from(&u.commit));
            assert_eq!(live, rebuilt, "pending first: {pending_first}");
        }
    }

    // spec/crypto.md §4 (Roles secrets): an epoch's roles secret derives from its secret, so a
    // node holding the checked secret keeps no roles secret apart, whichever came first: a live
    // index that took the secret (a box) before a history entry carrying the roles secret is the
    // record its store rebuilds, taking them the other way round.
    #[test]
    fn a_roles_secret_beside_its_checked_secret_is_kept_alike_in_either_order() {
        let e = ep(3, 3);
        let s = Secret32::from_bytes([1; 32]);
        let rs = osis_crypto::roles_secret(&s);
        let mut live = RoleEpochs::default();
        live.set_secret(e, s.clone());
        live.set_roles(e, rs.clone());
        let mut rebuilt = RoleEpochs::default();
        rebuilt.set_roles(e, rs.clone());
        rebuilt.set_secret(e, s);
        assert_eq!(live, rebuilt);
        assert_eq!(live.checked_roles(&e), Some(rs));
    }

    #[test]
    fn current_and_newest() {
        let mut r = RoleEpochs::default();
        r.set_secret(ep(1, 0), Secret32::from_bytes([1; 32]));
        r.set_history(ep(2, 5), BTreeSet::new(), [ep(1, 0)], None);
        r.set_history(ep(2, 3), BTreeSet::new(), [ep(1, 0)], None);
        for e in [ep(1, 0), ep(2, 5), ep(2, 3)] {
            r.set_established(e, Provenance::Fixed);
        }
        assert_eq!(r.current(), vec![ep(2, 3), ep(2, 5)]);
        assert_eq!(r.newest(), Some(ep(2, 3)));
        assert_eq!(r.newest_held(), None);
        assert_eq!(r.newest_secret().map(|x| x.0), Some(ep(1, 0)));
        r.set_secret(ep(2, 5), Secret32::from_bytes([2; 32]));
        assert_eq!(r.newest_held().map(|x| x.0), Some(ep(2, 5)));
        r.set_history(ep(3, 9), BTreeSet::new(), [ep(2, 5)], None);
        r.set_established(ep(3, 9), Provenance::Fixed);
        assert_eq!(r.current(), vec![ep(2, 3), ep(3, 9)]);
        assert_eq!(r.newest(), Some(ep(3, 9)));
        // An unestablished rotation (not applied, pending or invalid) supersedes nothing and is not
        // current.
        r.set_history(ep(4, 1), BTreeSet::new(), [ep(3, 9), ep(2, 3)], None);
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

    /// Holds the named commits whose first byte is in `have`; every rotator holds its role.
    struct Holding {
        have: BTreeSet<u8>,
    }

    impl Held for Holding {
        fn met(&self, n: &crate::Name) -> bool {
            self.have.contains(&n.key.commit.0[0])
        }
        fn holds(&self, _: &Tid, _: Role) -> bool {
            true
        }
        fn departed(&self, o: &crate::Own) -> bool {
            u8::try_from(o.ts).is_ok_and(|b| self.have.contains(&b))
        }
        fn marks(&self, o: &crate::Own, k: &crate::Key) -> bool {
            o.ts == k.ts && o.author == k.node
        }
        fn publishes(&self, _: Role, _: &Epoch, _: &crate::NamesDigest) -> bool {
            true
        }
    }

    /// Names of the commits `cs`; `own`: the entry's rotation commit departs, by its `ts`.
    fn names(cs: &[u8], own: Option<u8>) -> Names {
        let t = Tid::from_bytes([5; 15]);
        let list = cs.iter().map(|c| crate::Name::applied(crate::Key { ts: u64::from(*c), node: t, commit: cid(*c) }, t)).collect();
        Names { list, departs: own.map(|ts| crate::Own { ts: u64::from(ts), author: t, blind: [0; 16] }) }
    }

    // spec/crypto.md §4 (established; names): an epoch established by its rotation commit or a
    // snapshot, whose secret is held, is established only once some history entry's names are
    // met, its departing commit included. A secret not held needs no names. No chain: a rotation
    // commit establishes its epoch whatever its predecessors.
    #[test]
    fn names_gate_establishment() {
        let mut r = RoleEpochs::default();
        r.set_rotation(ep(3, 0), cid(3), set(&[ep(2, 0)]));
        let none = Holding { have: BTreeSet::new() };
        r.establish(&none);
        assert_eq!(r.current(), vec![ep(3, 0)], "no secret: established by its commit alone, e2 never seen");
        r.set_secret(ep(3, 0), Secret32::from_bytes([3; 32]));
        r.establish(&none);
        assert!(!r.is_established(&ep(3, 0)), "secret held, no history entry opened");
        r.set_history(ep(3, 0), [names(&[7, 8], Some(3))].into(), [], None);
        r.establish(&none);
        assert!(!r.is_established(&ep(3, 0)));
        r.establish(&Holding { have: [3, 7].into() });
        assert!(!r.is_established(&ep(3, 0)), "8 not held");
        r.establish(&Holding { have: [7, 8].into() });
        assert!(!r.is_established(&ep(3, 0)), "the departing commit not held");
        let all = Holding { have: [3, 7, 8].into() };
        r.establish(&all);
        assert!(r.is_established(&ep(3, 0)));
        // another entry (a forger holding e3) with fewer names: any entry met suffices
        r.set_history(ep(3, 0), [names(&[7, 8], Some(3)), names(&[7], None)].into(), [], None);
        r.establish(&Holding { have: [7].into() });
        assert!(r.is_established(&ep(3, 0)));
        // by snapshot alone, alike
        let mut x = RoleEpochs::default();
        x.set_snapshot(ep(4, 0), CommitId([4; 32]));
        x.set_secret(ep(4, 0), Secret32::from_bytes([4; 32]));
        x.set_history(ep(4, 0), [names(&[7], Some(4))].into(), [], None);
        x.establish(&Holding { have: [7].into() });
        assert!(!x.is_established(&ep(4, 0)));
        x.establish(&Holding { have: [4, 7].into() });
        assert!(x.is_established(&ep(4, 0)));
        // a reading-only secret needs no names (it is never used)
        let mut y = RoleEpochs::default();
        y.set_rotation(ep(2, 0), cid(2), BTreeSet::new());
        y.set_reading_secret(ep(2, 0), Secret32::from_bytes([2; 32]), Unchecked { author: Tid::from_bytes([1; 15]), commit: cid(1) });
        y.establish(&none);
        assert!(y.is_established(&ep(2, 0)));
    }

    // spec/crypto.md §4 (Foreign): a foreign epoch supersedes nothing (what it lists stays
    // current), stays current itself until a rotation that is not foreign lists it, is never the
    // newest, and a derived epoch of it supersedes nothing either. What its commit lists is
    // unchanged (`superseded_by`: what a commit giving it wraps under).
    #[test]
    fn foreign_supersedes_nothing() {
        let mut r = RoleEpochs::default();
        let (e1, e2, e3) = (ep(1, 1), ep(2, 2), ep(3, 3));
        r.set_rotation(e1, cid(1), BTreeSet::new());
        r.set_rotation(e2, cid(2), set(&[e1]));
        for e in [e1, e2] {
            r.set_secret(e, Secret32::from_bytes([e.n() as u8; 32]));
            r.set_history(e, [names(&[], None)].into(), [], None);
        }
        r.establish(&AllHeld);
        assert_eq!(r.current(), vec![e2]);
        r.set_foreign(&e2);
        assert_eq!(r.current(), vec![e1, e2], "e2 lists e1, superseding nothing");
        assert!(!r.superseded(&e1) && r.unsuperseded().contains(&e1));
        assert_eq!((r.newest(), r.newest_held().map(|x| x.0)), (Some(e1), Some(e1)), "never the newest");
        assert_eq!(r.superseded_by([&e2]), Some(set(&[e1])), "its commit's list stands");
        r.set_rotation(e3, cid(3), set(&[e1, e2]));
        r.establish(&AllHeld);
        assert_eq!(r.current(), vec![e3], "a rotation that is not foreign supersedes it");
        let mut a = ActorEpochs { read: r, ..Default::default() };
        a.read.set_foreign(&e3);
        assert_eq!(a.read.current(), vec![e1, e2, e3]);
        let d = ActorEpochs::derived(&a, &Tid::from_bytes([9; 15]));
        assert_eq!(d.read.current().len(), 3, "derived from foreign epochs: they supersede nothing");
    }

    // spec/crypto.md §4 (Established): headroom, e's n at most 2^62: an epoch past 2^62 is established only beside an established
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

    // spec/crypto.md §3: derived secrets take the mint admin's n at the epochs the nonce rule names;
    // a link key's are its seed's at n 1; a base epoch without a secret stays a placeholder, so
    // what it supersedes stays superseded.
    #[test]
    fn derived_and_link_key() {
        let seed = Secret32::from_bytes([7; 32]);
        let l = Tid::from_bytes([4; 15]);
        let k = ActorEpochs::link_key(&l, &seed);
        let ka = Epoch::derive(&l, Role::Admin, 1, &link_key_role_secret(&seed, Role::Admin)).unwrap();
        assert_eq!(k.admin.current(), vec![ka]);
        let t = Tid::from_bytes([3; 15]);
        let d = ActorEpochs::derived(&k, &t);
        let want = thing_role_secret(&link_key_role_secret(&seed, Role::Write), Role::Write, &t);
        let dz = Epoch::derive(&t, Role::Write, 1, &want).unwrap();
        assert_eq!(d.write.current(), vec![dz]);
        assert_eq!(d.write.secret(&dz).map(|s| s.secret()), Some(&want));
        let mut base = ActorEpochs::default();
        base.read.set_secret(ep(1, 1), Secret32::from_bytes([1; 32]));
        base.read.set_secret(ep(1, 2), Secret32::from_bytes([2; 32]));
        base.read.set_history(ep(2, 0), BTreeSet::new(), [ep(1, 1)], None);
        for e in [ep(1, 1), ep(1, 2), ep(2, 0)] {
            base.read.set_established(e, Provenance::Rotated);
        }
        base.read.observe(ep(3, 0));
        let d = ActorEpochs::derived(&base, &t);
        let de = |b: u8| Epoch::derive(&t, Role::Read, 1, &thing_role_secret(&Secret32::from_bytes([b; 32]), Role::Read, &t)).unwrap();
        let ph = |e: Epoch| Epoch::new(e.n(), placeholder_nonce(&e)).unwrap();
        assert_eq!(d.read.current(), vec![de(2), ph(ep(2, 0))]);
        assert!(d.read.superseded(&de(1)));
        assert_eq!(d.read.provenance(&de(1)), Some(Provenance::Derived));
        assert_eq!(d.read.provenance(&ph(ep(3, 0))), None);
        assert_eq!(d.read.held().count(), 2);
    }

    // spec/crypto.md §3: derived epochs keep the mint admin's n below the cap, so each mint admin rotation
    // gives a newer derived epoch (a dependent's sync IDs are stepped on it, spec/sync-ids.md §6);
    // base epochs past the cap (a writer of the mint admin jumped them) all derive at the cap, so a
    // thing's own chain starts at most at `MAX_FREE_N`; placeholders there stay distinct.
    #[test]
    fn derived_n_follows_base_below_cap() {
        let t = Tid::from_bytes([3; 15]);
        for b in 0..32u8 {
            let mut base = ActorEpochs::default();
            let s = |x: u8| Secret32::from_bytes([x; 32]);
            base.read.set_secret(ep(1, 1), s(b));
            base.read.set_secret(ep(2, 2), s(b ^ 0x80));
            base.read.set_history(ep(2, 2), BTreeSet::new(), [ep(1, 1)], None);
            for e in [ep(1, 1), ep(2, 2)] {
                base.read.set_established(e, Provenance::Rotated);
            }
            let d = ActorEpochs::derived(&base, &t);
            let old = Epoch::derive(&t, Role::Read, 1, &thing_role_secret(&s(b), Role::Read, &t)).unwrap();
            assert!(crate::is_newer(&d.read.newest().unwrap(), &old));
        }
        let mut base = ActorEpochs::default();
        for (i, n) in [MAX_FREE_N - 2, MAX_FREE_N + 5, MAX_FREE_N + 6].into_iter().enumerate() {
            base.read.set_secret(ep(n, 1), Secret32::from_bytes([i as u8; 32]));
            base.read.set_established(ep(n, 1), Provenance::Rotated);
        }
        base.read.observe(ep(MAX_FREE_N + 7, 9));
        base.read.observe(ep(MAX_FREE_N + 8, 9));
        let d = ActorEpochs::derived(&base, &t);
        let ns: Vec<u64> = d.read.epochs().map(|(e, _)| e.n()).collect();
        assert_eq!(ns, [MAX_FREE_N - 2, MAX_FREE_N - 1, MAX_FREE_N - 1, MAX_FREE_N - 1, MAX_FREE_N - 1]);
        // one secret at two base epochs past the cap, the later superseding the earlier: one
        // derived epoch, still current
        let mut base = ActorEpochs::default();
        let (a, b) = (ep(MAX_FREE_N + 10, 1), ep(MAX_FREE_N + 11, 2));
        for e in [a, b] {
            base.read.set_secret(e, Secret32::from_bytes([7; 32]));
            base.read.set_established(e, Provenance::Rotated);
        }
        base.read.set_history(b, BTreeSet::new(), [a], None);
        let d = ActorEpochs::derived(&base, &t);
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
        assert_eq!(r.reading_secret(&ep(1, 1)).map(|x| x.secret()), Some(&s));
        assert!(r.drop_reading_from(&cid(1)));
        assert!(r.is_reading_only(&ep(1, 1)));
        assert!(r.drop_reading_from(&cid(2)));
        assert!(r.get(&ep(1, 1)).is_none());
        r.set_reading_secret(ep(1, 1), s.clone(), u(1));
        r.set_secret(ep(1, 1), s.clone());
        assert_eq!(r.secret(&ep(1, 1)).map(|x| x.secret()), Some(&s));
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
                // order n: free, or a function of n as in a derived map (capped n, mint admin's order)
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
                r.set_history(a, BTreeSet::new(), [b], None);
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

#[cfg(test)]
mod current_oracle {
    use super::*;

    /// spec/crypto.md §4 Current, stated directly: established, and no established epoch's
    /// `superseded_epochs` names it (no transitivity; self- and cyclic supersedes included).
    fn superseded_by_spec(r: &RoleEpochs, e: &Epoch) -> bool {
        r.map.values().any(|i| i.established.is_some() && i.superseded_epochs().contains(e))
    }

    // `current`, `superseded` and `newest_held` agree with the spec's definition over random epoch
    // sets: forks (one n, several nonces), cycles, self-supersedes, unestablished supersessors,
    // supersedes of unknown epochs, and lists split between history box and rotation commits.
    #[test]
    fn current_matches_spec_definition() {
        let mut s = 0u64;
        let mut next = |m: u64| {
            s = s.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (z ^ (z >> 31)) % m
        };
        let pool: Vec<Epoch> = (1..=4).flat_map(|n| (0..2).map(move |c| Epoch::new(n, [c; 32]).unwrap())).collect();
        for _ in 0..4000 {
            let mut r = RoleEpochs::default();
            for e in &pool {
                if next(3) == 0 {
                    continue;
                }
                let pick = |next: &mut dyn FnMut(u64) -> u64| pool.iter().filter(|_| next(4) == 0).copied().collect::<BTreeSet<Epoch>>();
                let mut i = EpochInfo { supersedes: pick(&mut next), ..Default::default() };
                for c in 0..next(3) {
                    i.rotations.insert(CommitId([c as u8; 32]), pick(&mut next));
                }
                i.established = [None, Some(Provenance::Fixed), Some(Provenance::Rotated)][next(3) as usize];
                i.secret = (next(2) == 0).then(|| Secret32::from_bytes([e.n() as u8; 32]).into());
                r.map.insert(*e, i);
            }
            let want: Vec<Epoch> = r.map.keys().filter(|e| r.is_established(e) && !superseded_by_spec(&r, e)).copied().collect();
            assert_eq!(r.current(), want, "{r:?}");
            for e in &pool {
                assert_eq!(r.superseded(e), superseded_by_spec(&r, e));
                assert_eq!(r.is_current(e), want.contains(e));
            }
            let held = r.held().filter(|(e, _)| want.contains(e)).max_by_key(|(e, _)| r.by_order(e)).map(|x| x.0);
            assert_eq!(r.newest_held().map(|x| x.0), held);
        }
    }
}
