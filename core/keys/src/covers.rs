//! Departures from an actor and the covers rule (spec/crypto.md §4), merge (a current epoch that
//! does not cover; a fork, by its merger), re-seal triggers (spec/permissions.md §3). A departure is
//! from the actor itself: what departs inside a holder actor reaches the actor only as that
//! holder's new keyset (`members`).

use crate::aspects::box_key;
use crate::epoch::{ActorEpochs, ROLES};
use crate::names::{Held, Key, Name, Names};
use osis_base::{Role, Tid};
use osis_crypto::Epoch;
use osis_schema::core_types::Secrets;
use std::collections::BTreeSet;

/// A departure from an actor A (spec/crypto.md §4): `holder` left roles `from` up to `upto` of A.
/// `edge`: its edge into A as this node holds it, when that edge shows the departure; `None` for
/// a box holder or maker the edge does not show departed, which no epoch covers.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Departure {
    pub holder: Tid,
    pub from: Role,
    pub upto: Role,
    pub edge: Option<EdgeLog>,
}

/// A holder's edge into an actor as a node holds it (spec/crypto.md §4, Edge writes): its grant
/// for keys before the first held write (`start`: the record edge, else none) and the held
/// writes on it, their commits resolved, in key order.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EdgeLog {
    pub start: Option<Role>,
    pub writes: Vec<EdgeWrite>,
}

/// One held write on a holder's edge: its commit's key, the role it gives for keys (none for a
/// removal or a retain value), whether it applies here; `takes`: it applies here, or would over
/// the edge the newest write before it that applies here and gives more set (the start when
/// none does: a second finalize of a grant another write removed first); `stands`: it
/// applies here, or would over the start or the edge some applied write before it set (only
/// the edge it meets differs: a finalize of a grant renewed since; how a named write is met,
/// `Held::met`); `counts`: it applies nothing here and its author held write on the actor just
/// before its point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EdgeWrite {
    pub key: Key,
    pub role: Option<Role>,
    pub applied: bool,
    pub takes: bool,
    pub stands: bool,
    pub counts: bool,
}

impl EdgeLog {
    /// The holder's grant for keys now: the role the newest applied write gives, else `start`.
    pub fn now(&self) -> Option<Role> {
        self.writes.iter().rev().find(|w| w.applied).map_or(self.start, |w| w.role)
    }

    /// The most the edge gave its holder: `start`, and each write that applies or counts.
    pub fn most(&self) -> Option<Role> {
        self.writes.iter().filter(|w| w.applied || w.counts).map(|w| w.role).fold(self.start, Option::max)
    }

    /// The names a rotation writes of this edge (spec/crypto.md §4, Names): each applied write
    /// lowering the holder (giving less than the edge gave just before it), and each write that
    /// applies nothing, counts and gives a role, void.
    pub fn names(&self, holder: Tid) -> impl Iterator<Item = Name> + '_ {
        let mut had = self.start;
        self.writes.iter().filter_map(move |w| {
            if w.applied {
                let lowered = w.role < had;
                had = w.role;
                lowered.then_some(Name::applied(w.key, holder))
            } else {
                (w.counts && w.role.is_some()).then_some(Name::void(w.key, holder))
            }
        })
    }

    /// The tail for role `r` (spec/crypto.md §4, Covers): the writes after the newest applied
    /// one giving `r` or more (all of them when none does), and whether one does or `start` gives
    /// `r` (so a tail write must take the holder below `r`).
    fn tail(&self, r: Role) -> (&[EdgeWrite], bool) {
        match self.writes.iter().rposition(|w| w.applied && w.role >= Some(r)) {
            Some(i) => (self.writes.get(i + 1..).unwrap_or_default(), true),
            None => (&self.writes, self.start >= Some(r)),
        }
    }
}

impl Departure {
    /// Holder `holder` of A removed or demoted below `from`, up to admin; no edge shows it.
    pub fn holder(holder: Tid, from: Role) -> Departure {
        Departure { holder, from, upto: Role::Admin, edge: None }
    }

    /// The same departure, shown by `edge`.
    pub fn edge(self, edge: EdgeLog) -> Departure {
        Departure { edge: Some(edge), ..self }
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
            None => Role::Sync,
            Some(Role::Sync) => Role::Read,
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

    /// The newest write an epoch of `r` covering it names (spec/crypto.md §4, Covers): the latest
    /// of the earliest tail write that may take the holder below `r` and every tail write giving
    /// `r` or more that counts; `None` when no edge shows it or none is needed. An epoch whose
    /// rotator held nothing ordered after it covers nothing.
    pub fn newest_needed(&self, r: Role) -> Option<Key> {
        self.needed(r).into_iter().max()
    }

    /// Every write an epoch of `r` covering it names (spec/crypto.md §4, Covers): the earliest
    /// tail write that may take the holder below `r`, when one is needed, and every tail write
    /// giving `r` or more that counts; empty when no edge shows it.
    pub fn needed(&self, r: Role) -> Vec<Key> {
        let Some(edge) = &self.edge else { return Vec::new() };
        let (tail, held) = edge.tail(r);
        let below = tail.iter().find(|w| w.role < Some(r) && w.takes).filter(|_| held).map(|w| w.key);
        tail.iter().filter(|w| w.role >= Some(r) && w.counts).map(|w| w.key).chain(below).collect()
    }
}

/// Whether names `n` of an epoch pin `d`'s holder below `r` (spec/crypto.md §4, Covers): over
/// the tail of its edge for `r`, every write giving `r` or more that counts is named void, and,
/// unless the edge held the holder below `r` before the tail, a tail write taking it below `r`
/// (`EdgeWrite::takes`) is named applied, or is the rotation commit's own (its departs mark, by
/// the commit's `ts`, author and `blind`), that author holding `r` under `held`.
///
/// Invariant: a node where the names are met, the rotator included, holds the holder at `r` or
/// more on nothing this node holds: it holds the write taking the holder below `r`, which
/// applies there over whatever the tail leaves before it (or is invalid there for something
/// this node has not received), and judges void every later write this node holds that would
/// raise it back (a void name is met only where its write applies nothing). A write that does
/// not count (its author held less than write at its point) is not pinned: a reader's writes
/// force no rotation (the stated limit).
pub fn pins(n: &Names, r: Role, d: &Departure, held: &dyn Held) -> bool {
    let Some(edge) = &d.edge else { return false };
    let (tail, held_r) = edge.tail(r);
    let named = |w: &EdgeWrite| n.list.contains(&Name::applied(w.key, d.holder)) || (n.departs.is_some_and(|o| held.marks(&o, &w.key)) && held.holds(&w.key.node, r));
    let below = !held_r || tail.iter().any(|w| w.role < Some(r) && w.takes && named(w));
    below && tail.iter().filter(|w| w.role >= Some(r) && w.counts).all(|w| n.list.contains(&Name::void(w.key, d.holder)))
}

/// The covers rule (spec/crypto.md §4): epoch `e` of role `r` of `actor` covers `d` when `d`
/// does not concern `r`, or a history entry of `e` bound to a held valid keyset of `e` by an
/// author holding `r`, its names met (`EpochInfo::covering_names`), pins `d`'s holder below `r`
/// (`pins`). Boxes decide nothing: an epoch is relied on only for what its rotator held.
///
/// Invariant: what covers a departure is unforgeable by the departed party. A history entry
/// counts only as the keyset body (a rotation commit's, or a compaction snapshot's) that
/// publishes its names' digest, and only while that body's author, and for the entry's own
/// departure its rotation commit's signer, holds the role: a leaver holding the secret can write
/// entries, backdate a rotation naming its own self-removal, or rotate in the self-removal
/// itself, and each is its own (so it must hold the role, which it does not), or nobody's (an
/// entry no keyset commits to). A rotator that is no leaver naming a departure it holds while
/// boxing the departed party could hand it the secret anyway (the stated limit).
pub fn covers(epochs: &ActorEpochs, r: Role, e: &Epoch, d: &Departure, held: &dyn Held) -> bool {
    !d.concerns(r) || epochs.role(r).get(e).is_some_and(|i| i.covering_names(r, e, held).any(|n| pins(n, r, d, held)))
}

/// The known departures epoch `e` of role `r` does not cover.
pub fn uncovered<'a>(epochs: &ActorEpochs, r: Role, e: &Epoch, departures: &'a [Departure], held: &dyn Held) -> Vec<&'a Departure> {
    departures.iter().filter(|d| !covers(epochs, r, e, d, held)).collect()
}

/// A current holder as a re-sealer sees it: its role on the actor.
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
        assert_eq!(Departure::of_change(m, Some(Role::Read), None), Some(Departure::holder(m, Role::Sync).upto(Role::Read)), "a reader leaves sync too");
        assert_eq!(Departure::of_change(m, Some(Role::Read), Some(Role::Sync)), Some(Departure::holder(m, Role::Read).upto(Role::Read)));
        assert_eq!(Departure::of_change(m, Some(Role::Sync), None), Some(Departure::holder(m, Role::Sync).upto(Role::Sync)));
        assert_eq!(Departure::of_change(m, Some(Role::Read), Some(Role::Write)), None);
        assert_eq!(Departure::of_change(m, None, None), None);
        assert_eq!(Departure::holder(m, Role::Write).roles(), [Role::Write, Role::Admin].into_iter().collect());
        assert_eq!(Departure::holder(m, Role::Read).upto(Role::Write).roles(), [Role::Read, Role::Write].into_iter().collect());
    }
}
