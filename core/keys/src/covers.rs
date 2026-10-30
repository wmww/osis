//! Departures and the covers rule (spec/crypto.md §4), re-seal triggers (spec/permissions.md §3).

use crate::aspects::{box_key, from_schema};
use crate::epoch::{ActorEpochs, Provenance, ROLES};
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{Role, Tid, WallMs};
use osis_crypto::Epoch;
use osis_schema::core_types::{BoxKey, SecretBox, Secrets};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A departure as seen from an actor A (spec/crypto.md §4): `member` left roles `from` and above
/// of the last actor of `via`, or of A itself when `via` is empty. `via[0]` is a member (or the
/// owner) of A, `via[1]` a member of `via[0]`, and so on: a departure inside a member.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Departure {
    pub via: Via,
    pub member: Tid,
    pub from: Role,
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
    /// Member `member` of A removed, demoted below `from`, or past its `until`.
    pub fn member(member: Tid, from: Role) -> Departure {
        Departure { via: Via::default(), member, from }
    }

    /// `inner`, a departure from actor X, seen from an actor X is a member (or the owner) of.
    pub fn inside(x: Tid, inner: &Departure) -> Departure {
        Departure { via: Via::prepend(x, &inner.via), member: inner.member, from: inner.from }
    }

    /// The departure an edge change makes: `old` and `new` are the member's roles before and
    /// after (none = no edge, or `until` passed).
    pub fn of_change(member: Tid, old: Option<Role>, new: Option<Role>) -> Option<Departure> {
        let from = match new {
            None => Role::Read,
            Some(Role::Read) => Role::Write,
            Some(Role::Write) => Role::Admin,
            Some(Role::Admin) => return None,
        };
        (old >= Some(from)).then_some(Departure::member(member, from))
    }

    /// The roles it concerns: a role-r box is sealed to role r of its member at every hop.
    pub fn roles(&self) -> BTreeSet<Role> {
        ROLES.into_iter().filter(|r| *r >= self.from).collect()
    }
}

/// `until <= wall_ms` of the corrected clock (spec/crypto.md §4): the edge counts as removed.
pub fn expired(until: Option<WallMs>, now: WallMs) -> bool {
    until.is_some_and(|u| u <= now)
}

/// What the node holds of the actors on a departure's chain: their `/secrets` and epochs
/// (keysets from their `/keys` included, `observe_keys`).
pub trait HeldActors {
    fn secrets(&self, actor: &Tid) -> Option<&Secrets>;
    fn epochs(&self, actor: &Tid) -> Option<&ActorEpochs>;
    /// Whether a key-actor box keyed at a higher role whose key epoch is no longer current (a
    /// grant raced by a rotation of that role only) carries role `r` at epoch `e`: the commit that
    /// wrote it knew `e` (`Carries`). Such a box still hands its holder the lower role's secret.
    fn stale_box_carries(&self, _key: &BoxKey, _r: Role, _e: &Epoch) -> bool {
        false
    }
}

/// In-memory `HeldActors`.
#[derive(Clone, Debug, Default)]
pub struct MemoryHeldActors {
    pub map: BTreeMap<Tid, (Secrets, ActorEpochs)>,
    /// `HeldActors::stale_box_carries` answers: (box key, role, epoch) it carries.
    pub stale: BTreeSet<(BoxKey, Role, Epoch)>,
}

impl HeldActors for MemoryHeldActors {
    fn secrets(&self, actor: &Tid) -> Option<&Secrets> {
        self.map.get(actor).map(|x| &x.0)
    }
    fn epochs(&self, actor: &Tid) -> Option<&ActorEpochs> {
        self.map.get(actor).map(|x| &x.1)
    }
    fn stale_box_carries(&self, key: &BoxKey, r: Role, e: &Epoch) -> bool {
        self.stale.contains(&(key.clone(), r, *e))
    }
}

/// Whether a key-actor box keyed at a higher role (`key`) carries role `r` at epoch `e`; it
/// cannot be opened to check. `None`: assume it does.
pub type Carries<'a> = Option<&'a dyn Fn(&BoxKey, Role, &Epoch) -> bool>;

/// The boxes of `member` that may carry role `r` at epoch `e`: its box at (r, e), and a
/// key-actor box (sealed, no keyset) keyed at a higher role's current epoch, which carries the
/// roles below it (spec/crypto.md §4) where `carries` says so; with `stale`, also such a box at
/// a superseded epoch of the higher role where `stale` says it carries (r, e).
fn boxes_for(secrets: &Secrets, epochs: &ActorEpochs, member: &Tid, r: Role, e: &Epoch, carries: Carries, stale: Option<&dyn HeldActors>) -> bool {
    let exact = box_key(*member, r, e);
    secrets.boxes.iter().any(|(k, b)| {
        k.member == *member
            && (*k == exact
                || (k.role > r
                    && matches!(b, SecretBox::Sealed(s) if s.keyset.is_none())
                    && (from_schema(&k.epoch).is_ok_and(|ke| epochs.role(k.role).is_current(&ke)) && carries.is_none_or(|f| f(k, r, e))
                        || stale.is_some_and(|h| h.stale_box_carries(k, r, e)))))
    })
}

/// Does epoch `e` of role `r` (of the actor whose `/secrets` and epochs are given) cover `d`?
/// A member's departure: `e` holds no box for it (a key actor's box keyed higher counts). A
/// departure inside member M: M's box in `e` names the newest keyset epoch of M for `r` the node
/// holds, and that epoch of M covers the rest of the departure, and so on down the chain (a loop:
/// chains have no depth bound). Missing knowledge of a chain actor counts as not covered.
pub fn covers(secrets: &Secrets, epochs: &ActorEpochs, r: Role, e: &Epoch, d: &Departure, held: &dyn HeldActors) -> bool {
    if r < d.from {
        return true;
    }
    let (mut secrets, mut epochs, mut e) = (secrets, epochs, *e);
    for m in d.via.iter() {
        let named = match secrets.boxes.get(&box_key(*m, r, &e)) {
            None => return true,
            Some(SecretBox::Sealed(s)) => match &s.keyset {
                // A key actor has no members: nothing departs inside it.
                None => return true,
                Some(k) => from_schema(k),
            },
            Some(SecretBox::Symmetric(s)) => from_schema(&s.epoch),
        };
        let (Ok(k), Some(me), Some(ms)) = (named, held.epochs(m), held.secrets(m)) else { return false };
        if me.role(r).newest() != Some(k) {
            return false;
        }
        (secrets, epochs, e) = (ms, me, k);
    }
    !boxes_for(secrets, epochs, &d.member, r, &e, None, Some(held))
}

/// The known departures epoch `e` of role `r` does not cover. A node that may rotate `r`
/// rotates first when this is non-empty (spec/crypto.md §4), after the intermediate actors of a
/// departure inside a member where it may (`Plan::required` is top-down); the rotation commit's
/// own wrap is the one exception (`Rotation::wrap_epoch`).
pub fn uncovered<'a>(secrets: &Secrets, epochs: &ActorEpochs, r: Role, e: &Epoch, departures: &'a [Departure], held: &dyn HeldActors) -> Vec<&'a Departure> {
    departures.iter().filter(|d| !covers(secrets, epochs, r, e, d, held)).collect()
}

/// Whether a node that may rotate `r` may encrypt under `e`: established and current (an epoch
/// whose rotation commit is not applied, pending or invalid never is), and covering every known
/// departure. Opening a label and reading are not encrypting under (any held secret).
pub fn may_encrypt_under(secrets: &Secrets, epochs: &ActorEpochs, r: Role, e: &Epoch, departures: &[Departure], held: &dyn HeldActors) -> bool {
    epochs.role(r).is_current(e) && uncovered(secrets, epochs, r, e, departures, held).is_empty()
}

/// The roles of an actor a node must rotate before encrypting under each role's newest held
/// epoch: those whose newest held current epoch is uncovered, among `may_rotate`.
pub fn rotate_first(
    secrets: &Secrets,
    epochs: &ActorEpochs,
    roles: &BTreeSet<Role>,
    may_rotate: &BTreeSet<Role>,
    departures: &[Departure],
    held: &dyn HeldActors,
) -> BTreeSet<Role> {
    roles
        .iter()
        .filter(|r| may_rotate.contains(r))
        .filter(|r| match epochs.role(**r).newest_held() {
            Some((e, _)) => !may_encrypt_under(secrets, epochs, **r, &e, departures, held),
            None => false,
        })
        .copied()
        .collect()
}

/// A current member as a re-sealer sees it: role on the actor (an owner: admin) and `until`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member {
    pub member: Tid,
    pub role: Role,
    pub until: Option<WallMs>,
}

/// Re-seal trigger (spec/permissions.md §3): members lacking a box at a current epoch of a role
/// they hold, established through its rotation commit (`Chain`, `Own`; not a snapshot alone, see
/// `RoleEpochs::newest_is_snapshot`), with the roles to re-seal (`reseal_member`). Never a member whose `until` is within `MAX_DRIFT`.
/// `carries(key, r, e)`: whether the commit that wrote a key actor's box keyed at a higher role
/// knew epoch e of r (its `/secrets` write names e, or it is ordered after e's rotation); only
/// then does that box count for (r, e). The caller decides after a sync pass of the actor's
/// labels that fetched everything, and only for roles it may rotate.
pub fn reseal_needed(
    secrets: &Secrets,
    epochs: &ActorEpochs,
    members: &[Member],
    now: WallMs,
    carries: &dyn Fn(&BoxKey, Role, &Epoch) -> bool,
) -> Vec<(Tid, BTreeSet<Role>)> {
    let mut out = Vec::new();
    for m in members {
        if m.until.is_some_and(|u| u.0 <= now.0.saturating_add(MAX_DRIFT_MS)) {
            continue;
        }
        let roles: BTreeSet<Role> = ROLES
            .into_iter()
            .filter(|r| *r <= m.role)
            .filter(|r| {
                let re = epochs.role(*r);
                re.current()
                    .iter()
                    .filter(|e| re.provenance(e).is_some_and(Provenance::reseals))
                    .any(|e| !boxes_for(secrets, epochs, &m.member, *r, e, Some(carries), None))
            })
            .collect();
        if !roles.is_empty() {
            out.push((m.member, roles));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/crypto.md §4: a departure is a removal, a demotion below r, or `until` passing.
    #[test]
    fn departures() {
        let m = Tid::from_bytes([1; 15]);
        assert_eq!(Departure::of_change(m, Some(Role::Admin), Some(Role::Read)), Some(Departure::member(m, Role::Write)));
        assert_eq!(Departure::of_change(m, Some(Role::Read), None), Some(Departure::member(m, Role::Read)));
        assert_eq!(Departure::of_change(m, Some(Role::Read), Some(Role::Write)), None);
        assert_eq!(Departure::of_change(m, None, None), None);
        assert_eq!(Departure::member(m, Role::Write).roles(), [Role::Write, Role::Admin].into_iter().collect());
        let x = Tid::from_bytes([2; 15]);
        let d = Departure::inside(x, &Departure::inside(m, &Departure::member(m, Role::Read)));
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
        let inner = Departure::inside(t(2), &Departure::member(t(9), Role::Read));
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
