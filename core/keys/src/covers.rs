//! Departures and the covers rule (spec/crypto.md §4), the box judgement of a holder actor's
//! keyset (spec/permissions.md §3, Left out), re-seal triggers (spec/permissions.md §3).

use crate::aspects::{box_key, from_schema};
use crate::epoch::{ActorEpochs, ROLES};
use crate::names::{Held, Name, Names};
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{Role, Tid, WallMs};
use osis_crypto::Epoch;
use osis_schema::core_types::{SecretBox, Secrets};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A departure as seen from an actor A (spec/crypto.md §4): `holder` left roles `from` and above
/// of the last actor of `via`, or of A itself when `via` is empty. `via[0]` is a holder (or the
/// owner) of A, `via[1]` a holder of `via[0]`, and so on: a departure inside a holder. It
/// concerns A's roles `from` up to `upto`: those it held, at most the role of each hop on the
/// next. `at`: the name a rotation knowing it writes (the commit its timeline attributes it to);
/// `None` when none does (a box holder the timeline never showed), so no epoch covers it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Departure {
    pub via: Via,
    pub holder: Tid,
    pub from: Role,
    pub upto: Role,
    pub at: Option<Name>,
}

/// A departure's chain of actors: a list sharing its tail with the departure it was made
/// `inside` of, so prepending is O(1) and the departures found along one chain hold one hop each.
/// Compares, orders and hashes as the sequence of actors (as a `Vec` would).
#[derive(Clone, Default)]
pub struct Via(Option<Arc<Hop>>);

struct Hop {
    actor: Tid,
    last: Tid,
    len: usize,
    rest: Via,
}

impl Via {
    /// `x` followed by `rest`, sharing it.
    pub fn prepend(x: Tid, rest: &Via) -> Via {
        let (last, len) = rest.0.as_ref().map_or((x, 1), |h| (h.last, h.len + 1));
        Via(Some(Arc::new(Hop { actor: x, last, len, rest: rest.clone() })))
    }

    pub fn len(&self) -> usize {
        self.0.as_ref().map_or(0, |h| h.len)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    pub fn first(&self) -> Option<&Tid> {
        self.0.as_ref().map(|h| &h.actor)
    }

    pub fn last(&self) -> Option<&Tid> {
        self.0.as_ref().map(|h| &h.last)
    }

    pub fn get(&self, i: usize) -> Option<&Tid> {
        self.iter().nth(i)
    }

    /// The first actor and the rest of the chain (shared, not copied).
    pub fn split_first(&self) -> Option<(&Tid, &Via)> {
        self.0.as_ref().map(|h| (&h.actor, &h.rest))
    }

    pub fn contains(&self, t: &Tid) -> bool {
        self.iter().any(|x| x == t)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Tid> {
        let mut cur = self.0.as_deref();
        std::iter::from_fn(move || {
            let h = cur?;
            cur = h.rest.0.as_deref();
            Some(&h.actor)
        })
    }

    pub fn to_vec(&self) -> Vec<Tid> {
        self.iter().copied().collect()
    }

    /// An identity per hop (its address while held), first to last: chains sharing a tail
    /// yield the same identities for it. For measuring sharing.
    pub fn hop_ids(&self) -> impl Iterator<Item = usize> {
        let mut cur = self.0.as_deref();
        std::iter::from_fn(move || {
            let h = cur?;
            cur = h.rest.0.as_deref();
            Some(std::ptr::from_ref(h) as usize)
        })
    }
}

impl Drop for Via {
    // iterative: a recursive drop of a long unshared chain would exhaust the stack
    fn drop(&mut self) {
        let mut next = self.0.take();
        while let Some(h) = next {
            // `into_inner` (not `try_unwrap`): of two racing last owners, exactly one unwraps
            next = Arc::into_inner(h).and_then(|mut hop| hop.rest.0.take());
        }
    }
}

impl FromIterator<Tid> for Via {
    fn from_iter<I: IntoIterator<Item = Tid>>(it: I) -> Via {
        let v: Vec<Tid> = it.into_iter().collect();
        v.into_iter().rev().fold(Via::default(), |rest, x| Via::prepend(x, &rest))
    }
}

impl From<Vec<Tid>> for Via {
    fn from(v: Vec<Tid>) -> Via {
        v.into_iter().collect()
    }
}

impl PartialEq for Via {
    fn eq(&self, other: &Via) -> bool {
        match (&self.0, &other.0) {
            (Some(a), Some(b)) if Arc::ptr_eq(a, b) => true,
            _ => self.len() == other.len() && self.iter().eq(other.iter()),
        }
    }
}

impl Eq for Via {}

impl PartialEq<Vec<Tid>> for Via {
    fn eq(&self, other: &Vec<Tid>) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl PartialEq<[Tid]> for Via {
    fn eq(&self, other: &[Tid]) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl Ord for Via {
    fn cmp(&self, other: &Via) -> std::cmp::Ordering {
        self.iter().cmp(other.iter())
    }
}

impl PartialOrd for Via {
    fn partial_cmp(&self, other: &Via) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::hash::Hash for Via {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_usize(self.len());
        for t in self.iter() {
            t.hash(state);
        }
    }
}

impl std::fmt::Debug for Via {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl Departure {
    /// Holder `holder` of A removed, demoted below `from`, or past its `until`; up to admin, no
    /// name yet.
    pub fn holder(holder: Tid, from: Role) -> Departure {
        Departure { via: Via::default(), holder, from, upto: Role::Admin, at: None }
    }

    /// The same departure attributed to `at`.
    pub fn at(self, at: Option<Name>) -> Departure {
        Departure { at, ..self }
    }

    /// The same departure concerning roles up to `upto` only.
    pub fn upto(self, upto: Role) -> Departure {
        Departure { upto, ..self }
    }

    /// `inner`, a departure from actor X, seen from an actor X is a holder (or the owner) of.
    pub fn inside(x: Tid, inner: &Departure) -> Departure {
        Departure { via: Via::prepend(x, &inner.via), ..inner.clone() }
    }

    /// `inner` seen from an actor X holds `role` on: `inside`, concerning roles up to `role` (a
    /// role-r box is sealed to role r of its holder); `None` when that leaves none.
    pub fn through(x: Tid, role: Role, inner: &Departure) -> Option<Departure> {
        let upto = inner.upto.min(role);
        (upto >= inner.from).then(|| Departure::inside(x, inner).upto(upto))
    }

    /// Whether it concerns role `r`.
    pub fn concerns(&self, r: Role) -> bool {
        self.from <= r && r <= self.upto
    }

    /// The departure an edge change makes: `old` and `new` are the holder's roles before and
    /// after (none = no edge, or `until` passed).
    pub fn of_change(holder: Tid, old: Option<Role>, new: Option<Role>) -> Option<Departure> {
        let from = match new {
            None => Role::Read,
            Some(Role::Read) => Role::Write,
            Some(Role::Write) => Role::Admin,
            Some(Role::Admin) => return None,
        };
        old.filter(|o| *o >= from).map(|o| Departure::holder(holder, from).upto(o))
    }

    /// The roles it concerns: a role-r box is sealed to role r of its holder at every hop.
    pub fn roles(&self) -> BTreeSet<Role> {
        ROLES.into_iter().filter(|r| self.concerns(*r)).collect()
    }
}

/// `until <= wall_ms` of the corrected clock (spec/crypto.md §4): the edge counts as removed.
pub fn expired(until: Option<WallMs>, now: WallMs) -> bool {
    until.is_some_and(|u| u <= now)
}

/// What the node holds of the actors on a departure's chain: their `secrets.0` and epochs
/// (keysets from their `keys.0` included, `observe_keys`).
pub trait HeldActors {
    fn secrets(&self, actor: &Tid) -> Option<&Secrets>;
    fn epochs(&self, actor: &Tid) -> Option<&ActorEpochs>;
}

/// In-memory `HeldActors`.
#[derive(Clone, Debug, Default)]
pub struct MemoryHeldActors {
    pub map: BTreeMap<Tid, (Arc<Secrets>, ActorEpochs)>,
}

impl HeldActors for MemoryHeldActors {
    fn secrets(&self, actor: &Tid) -> Option<&Secrets> {
        self.map.get(actor).map(|x| &*x.0)
    }
    fn epochs(&self, actor: &Tid) -> Option<&ActorEpochs> {
        self.map.get(actor).map(|x| &x.1)
    }
}

/// The box judgement of a holder actor's keyset (spec/permissions.md §3, Left out): whether
/// epoch `e` of role `r` of an actor (whose `secrets.0` is given), boxed to, keeps `d` out by its
/// boxes. A holder's departure: `e` holds no box for it. A departure inside holder M: M's box in
/// `e` names the newest keyset epoch of M for `r` the node holds, and that epoch of M keeps the
/// rest of the departure out, and so on down the chain (a loop: chains have no depth bound).
/// Missing knowledge of a chain actor counts as not. It only chooses the key a box is sealed to;
/// whether an epoch may be encrypted under is `covers` (by names).
pub fn keeps_out(secrets: &Secrets, r: Role, e: &Epoch, d: &Departure, held: &dyn HeldActors) -> bool {
    if !d.concerns(r) {
        return true;
    }
    let (mut secrets, mut e, mut via) = (secrets, *e, d.via.clone());
    while let Some((m, rest)) = via.split_first() {
        let (m, rest) = (*m, rest.clone());
        let named = match secrets.boxes.get(&box_key(m, r, &e)) {
            None => return true,
            Some(SecretBox::Sealed(s)) => match &s.keyset {
                // A key actor has no holders: nothing departs inside it.
                None => return true,
                Some(k) => from_schema(k),
            },
            Some(SecretBox::Symmetric(s)) => from_schema(&s.epoch),
        };
        let (Ok(k), Some(me), Some(ms)) = (named, held.epochs(&m), held.secrets(&m)) else { return false };
        if me.role(r).newest() != Some(k) {
            return false;
        }
        (secrets, e, via) = (ms, k, rest);
    }
    !secrets.boxes.contains_key(&box_key(d.holder, r, &e))
}

/// Whether names `n` of an epoch of `actor` name `d` (spec/crypto.md §4): its name is among
/// them, or it is a departure from `actor` made by the rotation commit itself (its departs mark).
pub fn named(n: &Names, actor: &Tid, d: &Departure) -> bool {
    d.at.is_some_and(|at| n.list.contains(&at) || (at.thing == *actor && n.departs.is_some_and(|o| o.ts == at.key.ts && o.node == at.key.node)))
}

/// The covers rule (spec/crypto.md §4): epoch `e` of role `r` of `actor` covers `d` when `d`
/// does not concern `r`, or a history entry of `e` with its names met under `held` names
/// it. Boxes decide nothing: an epoch is relied on only for what its rotator held.
pub fn covers(actor: &Tid, epochs: &ActorEpochs, r: Role, e: &Epoch, d: &Departure, held: &dyn Held) -> bool {
    !d.concerns(r) || epochs.role(r).get(e).is_some_and(|i| i.met_names(held).any(|n| named(n, actor, d)))
}

/// The known departures epoch `e` of role `r` does not cover. A node that may rotate `r`
/// rotates first when this is non-empty (spec/crypto.md §4), after the intermediate actors of a
/// departure inside a holder where it may (`Plan::required` is top-down); the rotation commit's
/// own wrap is the one exception (`Rotation::wrap_epoch`).
pub fn uncovered<'a>(actor: &Tid, epochs: &ActorEpochs, r: Role, e: &Epoch, departures: &'a [Departure], held: &dyn Held) -> Vec<&'a Departure> {
    departures.iter().filter(|d| !covers(actor, epochs, r, e, d, held)).collect()
}

/// Whether a node that may rotate `r` may encrypt under `e`: established and current (an epoch
/// whose rotation commit is not applied, pending or invalid never is), and covering every known
/// departure. Opening a label and reading are not encrypting under (any held secret).
pub fn may_encrypt_under(actor: &Tid, epochs: &ActorEpochs, r: Role, e: &Epoch, departures: &[Departure], held: &dyn Held) -> bool {
    epochs.role(r).is_current(e) && uncovered(actor, epochs, r, e, departures, held).is_empty()
}

/// The roles of an actor a node must rotate before encrypting under each role's newest held
/// epoch: those whose newest held current epoch is uncovered, among `may_rotate`.
pub fn rotate_first(actor: &Tid, epochs: &ActorEpochs, roles: &BTreeSet<Role>, may_rotate: &BTreeSet<Role>, departures: &[Departure], held: &dyn Held) -> BTreeSet<Role> {
    roles
        .iter()
        .filter(|r| may_rotate.contains(r))
        .filter(|r| match epochs.role(**r).newest_held() {
            Some((e, _)) => !may_encrypt_under(actor, epochs, **r, &e, departures, held),
            None => false,
        })
        .copied()
        .collect()
}

/// A current holder as a re-sealer sees it: role on the actor (an owner: admin) and `until`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Holder {
    pub holder: Tid,
    pub role: Role,
    pub until: Option<WallMs>,
}

/// Re-seal trigger (spec/permissions.md §3): holders lacking a box at a current epoch of a role
/// they hold, with the roles to re-seal (`box_holder`). Never a holder
/// whose `until` is within `MAX_DRIFT`. The caller decides after a sync pass of the actor's
/// labels that fetched everything, and only for roles it may rotate.
pub fn reseal_needed(secrets: &Secrets, epochs: &ActorEpochs, holders: &[Holder], now: WallMs) -> Vec<(Tid, BTreeSet<Role>)> {
    let mut out = Vec::new();
    for m in holders {
        if m.until.is_some_and(|u| u.0 <= now.0.saturating_add(MAX_DRIFT_MS)) {
            continue;
        }
        let roles: BTreeSet<Role> = ROLES.into_iter().filter(|r| *r <= m.role).filter(|r| !reseal_missing(secrets, epochs, &m.holder, *r).is_empty()).collect();
        if !roles.is_empty() {
            out.push((m.holder, roles));
        }
    }
    out
}

/// The current epochs of `r` at which the re-seal trigger finds `holder` without a box
/// (`reseal_needed`).
pub fn reseal_missing(secrets: &Secrets, epochs: &ActorEpochs, holder: &Tid, r: Role) -> Vec<Epoch> {
    epochs.role(r).current().into_iter().filter(|e| !secrets.boxes.contains_key(&box_key(*holder, r, e))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid_x() -> Tid {
        Tid::from_bytes([7; 15])
    }

    // spec/crypto.md §4: a departure is a removal, a demotion below r, or `until` passing; it
    // concerns the roles it left, at most the role of each hop on the next.
    #[test]
    fn departures() {
        let m = Tid::from_bytes([1; 15]);
        assert_eq!(Departure::of_change(m, Some(Role::Admin), Some(Role::Read)), Some(Departure::holder(m, Role::Write)));
        assert_eq!(Departure::of_change(m, Some(Role::Read), None), Some(Departure::holder(m, Role::Read).upto(Role::Read)));
        assert_eq!(Departure::of_change(m, Some(Role::Read), Some(Role::Write)), None);
        assert_eq!(Departure::of_change(m, None, None), None);
        assert_eq!(Departure::holder(m, Role::Write).roles(), [Role::Write, Role::Admin].into_iter().collect());
        assert_eq!(Departure::holder(m, Role::Read).upto(Role::Write).roles(), [Role::Read, Role::Write].into_iter().collect());
        let w = Departure::holder(m, Role::Read).upto(Role::Write);
        assert_eq!(Departure::through(tid_x(), Role::Read, &w).map(|d| d.roles()), Some([Role::Read].into_iter().collect()));
        assert_eq!(Departure::through(tid_x(), Role::Read, &Departure::holder(m, Role::Write)), None);
        let x = Tid::from_bytes([2; 15]);
        let d = Departure::inside(x, &Departure::inside(m, &Departure::holder(m, Role::Read)));
        assert_eq!(d.via, vec![x, m]);
        assert_eq!((d.via.first(), d.via.get(1), d.via.last(), d.via.len()), (Some(&x), Some(&m), Some(&m), 2));
    }

    // `Via` compares and orders as the `Vec` of its actors; `inside` shares the inner chain.
    #[test]
    fn via_is_a_shared_vec() {
        let t = |i: u8| Tid::from_bytes([i; 15]);
        let vs: Vec<Vec<Tid>> = vec![vec![], vec![t(1)], vec![t(1), t(2)], vec![t(1), t(3)], vec![t(2)], vec![t(2), t(1), t(1)]];
        for a in &vs {
            for b in &vs {
                let (va, vb) = (Via::from(a.clone()), Via::from(b.clone()));
                assert_eq!(va.cmp(&vb), a.cmp(b));
                assert_eq!(va == vb, a == b);
                assert_eq!(va.to_vec(), *a);
                assert_eq!(va.last(), a.last());
            }
        }
        let inner = Departure::inside(t(2), &Departure::holder(t(9), Role::Read));
        let outer = Departure::inside(t(1), &inner);
        assert_eq!(outer.via.hop_ids().nth(1), inner.via.hop_ids().next());
        assert_eq!(outer.via.split_first().map(|(x, rest)| (*x, rest.clone())), Some((t(1), inner.via.clone())));
        // dropping a long unshared chain does not recurse
        let long: Via = (0..200_000u32).map(|i| Tid::from_bytes([(i % 251) as u8; 15])).collect();
        assert_eq!(long.len(), 200_000);
        drop(long);
        assert!(expired(Some(WallMs(5)), WallMs(5)) && !expired(Some(WallMs(6)), WallMs(5)) && !expired(None, WallMs(5)));
    }
}
