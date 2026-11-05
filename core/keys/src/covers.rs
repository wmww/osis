//! Departures from an actor and the covers rule (spec/crypto.md §4), merge (a current epoch that
//! does not cover; a fork, by its merger), re-seal triggers (spec/permissions.md §3). A departure is
//! from the actor itself: what departs inside a holder actor reaches the actor only as that
//! holder's new keyset (`members`).

use crate::aspects::box_key;
use crate::epoch::{ActorEpochs, ROLES};
use crate::names::{Held, Name, Names};
use osis_base::{Role, Tid};
use osis_crypto::Epoch;
use osis_schema::core_types::Secrets;
use std::collections::BTreeSet;

/// A departure from an actor A (spec/crypto.md §4): `holder` left roles `from` up to `upto` of A.
/// `at`: the name a rotation knowing it writes (the commit its timeline attributes it to); `None`
/// when none does (a box holder the timeline never showed), so no epoch covers it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Departure {
    pub holder: Tid,
    pub from: Role,
    pub upto: Role,
    pub at: Option<Name>,
}

impl Departure {
    /// Holder `holder` of A removed or demoted below `from`; up to admin, no name yet.
    pub fn holder(holder: Tid, from: Role) -> Departure {
        Departure { holder, from, upto: Role::Admin, at: None }
    }

    /// The same departure attributed to `at`.
    pub fn at(self, at: Option<Name>) -> Departure {
        Departure { at, ..self }
    }

    /// The same departure concerning roles up to `upto` only.
    pub fn upto(self, upto: Role) -> Departure {
        Departure { upto, ..self }
    }

    /// Whether it concerns role `r`.
    pub fn concerns(&self, r: Role) -> bool {
        self.from <= r && r <= self.upto
    }

    /// The departure an edge change makes: `old` and `new` are the holder's roles before and
    /// after (none = no edge).
    pub fn of_change(holder: Tid, old: Option<Role>, new: Option<Role>) -> Option<Departure> {
        let from = match new {
            None => Role::Read,
            Some(Role::Read) => Role::Write,
            Some(Role::Write) => Role::Admin,
            Some(Role::Admin) => return None,
        };
        old.filter(|o| *o >= from).map(|o| Departure::holder(holder, from).upto(o))
    }

    /// The roles it concerns.
    pub fn roles(&self) -> BTreeSet<Role> {
        ROLES.into_iter().filter(|r| self.concerns(*r)).collect()
    }
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

/// The known departures epoch `e` of role `r` does not cover.
pub fn uncovered<'a>(actor: &Tid, epochs: &ActorEpochs, r: Role, e: &Epoch, departures: &'a [Departure], held: &dyn Held) -> Vec<&'a Departure> {
    departures.iter().filter(|d| !covers(actor, epochs, r, e, d, held)).collect()
}

/// Whether a node that may rotate `r` may encrypt under `e` as far as departures go: established
/// and current (an epoch whose rotation commit is not applied, pending or invalid never is), and
/// covering every known departure. Holder actors' keysets are `members::stale`'s.
pub fn may_encrypt_under(actor: &Tid, epochs: &ActorEpochs, r: Role, e: &Epoch, departures: &[Departure], held: &dyn Held) -> bool {
    epochs.role(r).is_current(e) && uncovered(actor, epochs, r, e, departures, held).is_empty()
}

/// Merge (spec/crypto.md §4, encrypting under), for any node that may rotate `r`: whether some
/// current epoch of `r`, not only the newest, does not cover a known departure.
///
/// Invariant: a fork made by a rotator that did not know a departure stays current beside the
/// knowing epoch, and may win the (n, nonce) order; a holder actor anchored on it (`members::
/// seal_keyset`) never moves to the knowing one. A node knowing the departure supersedes every
/// current epoch with one rotation, so this ends once each knowing node's rotations are held.
/// An epoch whose secret it lacks covers nothing here (its history box does not open): that
/// rotation supersedes it too.
pub fn merge_due(actor: &Tid, epochs: &ActorEpochs, r: Role, departures: &[Departure], held: &dyn Held) -> bool {
    epochs.role(r).current().iter().any(|e| !uncovered(actor, epochs, r, e, departures, held).is_empty())
}

/// The maker of an epoch as a node sees it (`fork_merger`): whether it is this node, and
/// whether it may rotate the role now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Maker {
    pub me: bool,
    pub may_rotate: bool,
}

/// Merge of a fork (spec/crypto.md §4, encrypting under): whether `r` has more than one current
/// epoch and this node is its merger: it made (`maker`; `None`: unknown) a current epoch other
/// than the newest, or no maker of one may rotate `r`. The merger rotates, listing every
/// current epoch.
///
/// Invariant: a holder actor's boxes at A's current epochs anchor it (`members::seal_keyset`);
/// A forked across two keysets of M, neither listing the other, anchors M at both, and only a
/// keyset of M listing both (M's merge) can seal M again. Nodes holding the same fork agree on
/// its newest epoch, so its maker never merges beside another maker: two nodes merging alike
/// would fork again on every round of a sync that delivers both merges together. The merges of
/// nodes holding different forks fork again at most once per epoch made concurrently.
pub fn fork_merger(epochs: &ActorEpochs, r: Role, maker: impl Fn(&Epoch) -> Option<Maker>) -> bool {
    let rs = epochs.role(r);
    let cur = rs.current();
    let Some(newest) = rs.newest() else { return false };
    if cur.len() < 2 {
        return false;
    }
    let others: Vec<Option<Maker>> = cur.iter().filter(|e| **e != newest).map(&maker).collect();
    others.iter().flatten().any(|m| m.me) || !others.iter().flatten().any(|m| m.may_rotate)
}

/// A current holder as a re-sealer sees it: its role on the actor (an owner: admin).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Holder {
    pub holder: Tid,
    pub role: Role,
}

/// Re-seal trigger (spec/permissions.md §3): holders lacking a box at a current epoch of a role
/// they hold, with the roles to re-seal (`box_holder`). The caller decides after a sync pass of
/// the actor's labels that fetched everything, and only for roles it may rotate.
pub fn reseal_needed(secrets: &Secrets, epochs: &ActorEpochs, holders: &[Holder]) -> Vec<(Tid, BTreeSet<Role>)> {
    let mut out = Vec::new();
    for m in holders {
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

    // spec/crypto.md §4: a departure is a removal or a demotion below r; it concerns the roles it left.
    #[test]
    fn departures() {
        let m = Tid::from_bytes([1; 15]);
        assert_eq!(Departure::of_change(m, Some(Role::Admin), Some(Role::Read)), Some(Departure::holder(m, Role::Write)));
        assert_eq!(Departure::of_change(m, Some(Role::Read), None), Some(Departure::holder(m, Role::Read).upto(Role::Read)));
        assert_eq!(Departure::of_change(m, Some(Role::Read), Some(Role::Write)), None);
        assert_eq!(Departure::of_change(m, None, None), None);
        assert_eq!(Departure::holder(m, Role::Write).roles(), [Role::Write, Role::Admin].into_iter().collect());
        assert_eq!(Departure::holder(m, Role::Read).upto(Role::Write).roles(), [Role::Read, Role::Write].into_iter().collect());
    }
}
