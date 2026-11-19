//! Vouches (spec/permissions.md §5.1 Vouches): which held `vouches.0` entries count, judged in
//! the **first walk** (steps 1 to 5 under the trust set, every vouch disregarded). The second
//! walk is the same walk over the same input with each counting entry's commit read as listed
//! by its removal's frontier (`walk::Input::listed`, read by audits, seeds and disputes alike):
//! one mechanism with a different "listed" input, never a parallel path.
//!
//! The interface is plain values: the held vouches and role parts (`Held`), and what the
//! counting rule reads of the first walk (`FirstWalk`), so another walk can implement it.
//!
//! Invariant the second walk relies on: the counting entries are a function of the first walk
//! and the held vouches alone, and the first walk reads no vouch, so nothing the second walk
//! does feeds back into which entries count (no fixpoint, no order dependence).
//!
//! Who writes each input (every one untrusted): a vouch's author, `ts`, thing and entries are
//! its signer's word, and any holder, a removed party included, may sign any number at any key
//! and stamp any `ts`. Nothing here trusts them: an entry counts only through the first walk's
//! own answers (R applied as an explicit lowering, c's author and order, the voucher able to
//! write c itself at the vouch's position and after every later lowering of it). A removal key
//! that is not held, or not such a lowering, costs one lookup for all its entries.

use crate::held::HeldSet;
use crate::types::{Edge, Frontier, Point, RoleCommit};
use osis_base::{CommitId, Role, Tid, Ts};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The entries one commit's `vouches.0` delta on `thing` creates (`put_new`; a write into an
/// entry it did not create says nothing, spec/permissions.md §5.1 Vouches): removal commit ID
/// to the commits it lists. The node adapts held deltas into these.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Vouch {
    pub id: CommitId,
    pub ts: Ts,
    /// Signing node: the voucher.
    pub author: Tid,
    pub thing: Tid,
    pub entries: Vec<(CommitId, Arc<Frontier>)>,
}

impl Vouch {
    /// Its position: the start of its `ts` (spec/permissions.md §5.2 Position).
    pub fn position(&self) -> Point {
        Point::start(self.ts)
    }
}

/// A held role commit's role-class parts that are not edge writes, each by thing with the role
/// its aspect requires (spec/permissions.md §1, §3): what "W could write c" asks of them. An
/// edge commit's edge writes come from `HeldSet::edge_commits`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RoleParts {
    pub id: CommitId,
    pub ts: Ts,
    pub author: Tid,
    pub parts: Vec<(Tid, Role)>,
}

/// The held vouches of a component, indexed by removal, with the role parts of the commits
/// they list.
#[derive(Clone, Default)]
pub(crate) struct Held {
    /// As held, per thing (whether the held set still holds the same).
    on: BTreeMap<Tid, Vec<Arc<Vouch>>>,
    /// Entry `.1` of vouch `.0`, per removal key.
    by_removal: BTreeMap<CommitId, Vec<(Arc<Vouch>, usize)>>,
    parts: BTreeMap<CommitId, Arc<RoleParts>>,
    /// The removal keys held as role commits (`note_commit`): the only ones whose entries can
    /// count, so a write never scans keys of removals not held.
    held_keys: BTreeSet<CommitId>,
}

impl Held {
    /// The vouches `held` holds on `things` and the role parts of what they list.
    pub fn gather(held: &dyn HeldSet, things: &BTreeSet<Tid>) -> Held {
        let mut h = Held::default();
        for t in things {
            let vs = held.vouches(t);
            if vs.is_empty() {
                continue;
            }
            for v in &vs {
                for (k, (r, list)) in v.entries.iter().enumerate() {
                    h.by_removal.entry(*r).or_default().push((v.clone(), k));
                    for c in list.commits() {
                        if !h.parts.contains_key(c)
                            && let Some(p) = held.role_parts(c)
                        {
                            h.parts.insert(*c, p);
                        }
                    }
                }
            }
            h.on.insert(*t, vs);
        }
        h
    }

    pub fn is_empty(&self) -> bool {
        self.on.is_empty()
    }

    /// Notes a role commit now held: a removal some vouch is keyed by.
    pub fn note_commit(&mut self, id: &CommitId) {
        if self.by_removal.contains_key(id) {
            self.held_keys.insert(*id);
        }
    }

    /// Whether a vouch is keyed by `id`.
    pub fn names_removal(&self, id: &CommitId) -> bool {
        self.by_removal.contains_key(id)
    }

    /// Whether an entry may count: one is keyed by a held removal.
    pub fn keyed(&self) -> bool {
        !self.held_keys.is_empty()
    }

    /// Whether `held` holds exactly these vouches on `thing`.
    pub fn same_on(&self, thing: &Tid, held: &[Arc<Vouch>]) -> bool {
        self.on.get(thing).map_or(&[][..], Vec::as_slice) == held
    }

}

/// An applied explicit write of the first walk lowering a grant held by another than its
/// author (spec/permissions.md §5.1 Vouches; a lowering of its author's own grant is a
/// self-removal, never explicit): its point, holder and frontier.
#[derive(Clone, Debug)]
pub(crate) struct Lowering {
    pub point: Point,
    pub holder: Tid,
    pub frontier: Option<Arc<Frontier>>,
}

/// `new` takes something from `old`: absent where `old` was not, or lower in some component
/// (role, invite, `until`; a higher floor withholds history).
pub(crate) fn takes_from(new: Option<&Edge>, old: Option<&Edge>) -> bool {
    match (new, old) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(n), Some(o)) => {
            let until_lower = match (n.until, o.until) {
                (Some(a), Some(b)) => a < b,
                (Some(_), None) => true,
                (None, _) => false,
            };
            n.role < o.role || n.invite < o.invite || until_lower || n.floor.unwrap_or(0) > o.floor.unwrap_or(0)
        }
    }
}

/// A listed commit c as "W could write c" reads it: its edge writes and other role-class parts.
pub(crate) struct Listed<'a> {
    pub edges: Option<&'a RoleCommit>,
    pub parts: &'a [(Tid, Role)],
}

/// Which state of the first walk "W could write c" is judged in.
#[derive(Clone, Copy)]
pub(crate) enum State {
    /// Just before this point (a vouch's position).
    Before(Point),
    /// Just after this applied write's commit took effect (a later lowering of the voucher).
    After(Point),
}

/// What the counting rule reads of the first walk.
pub(crate) trait FirstWalk {
    /// The applied explicit lowerings of other holders' grants, in walk order.
    fn lowerings(&self) -> Vec<Lowering>;
    /// "W could write c" in `state` (spec/permissions.md §5.1 Vouches): each edge write of c
    /// applies as W's there, and W holds the role each other part requires.
    fn could_write(&self, w: &Tid, c: &Listed<'_>, state: State) -> bool;
}

#[cfg(debug_assertions)]
thread_local! {
    /// Vouch entries judged on this thread (`entries_judged`).
    static JUDGED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Vouch entries (a listed commit of a vouch keyed by a held removal R that applies as an
/// explicit lowering) judged on this thread so far (scale checks). Debug builds only, as
/// `commits_walked`.
#[doc(hidden)]
#[allow(clippy::panic)]
pub fn entries_judged() -> u64 {
    #[cfg(debug_assertions)]
    return JUDGED.with(|m| m.get());
    #[cfg(not(debug_assertions))]
    panic!("entries_judged counts in debug builds only");
}

/// The counting entries (removal to the commits they list), spec/permissions.md §5.1 Vouches:
/// an entry of vouch V by W keyed by R listing c counts iff, in the first walk, R applies an
/// explicit write lowering a grant of X (not R's author), c is X's and ordered before R, V's
/// position is after R, W could write c at V's position, and W could write c just after each
/// later lowering Q of W's grant by another author whose frontier does not list V.
pub(crate) fn counting(first: &dyn FirstWalk, held: &Held, commits: &BTreeMap<CommitId, Arc<RoleCommit>>) -> BTreeMap<CommitId, BTreeSet<CommitId>> {
    let mut out: BTreeMap<CommitId, BTreeSet<CommitId>> = BTreeMap::new();
    if !held.keyed() {
        return out;
    }
    let lowerings = first.lowerings();
    let mut by_point: BTreeMap<CommitId, Vec<&Lowering>> = BTreeMap::new();
    let mut of_holder: BTreeMap<Tid, Vec<&Lowering>> = BTreeMap::new();
    for l in &lowerings {
        by_point.entry(l.point.commit).or_default().push(l);
        of_holder.entry(l.holder).or_default().push(l);
    }
    for r in &held.held_keys {
        let Some(rs) = by_point.get(r) else { continue };
        let Some(rp) = rs.first().map(|l| l.point) else { continue };
        let victims: BTreeSet<Tid> = rs.iter().map(|l| l.holder).collect();
        for (v, k) in held.by_removal.get(r).into_iter().flatten() {
            let Some((_, list)) = v.entries.get(*k) else { continue };
            let pos = v.position();
            if pos <= rp {
                continue;
            }
            // later lowerings of W not listing V (walk order: by point); by another author than
            // W, as every `Lowering` is
            let later: Vec<Point> = of_holder.get(&v.author).into_iter().flatten().filter(|q| q.point > pos && !q.frontier.as_ref().is_some_and(|f| f.covers(&v.id))).map(|q| q.point).collect();
            for c in list.commits() {
                #[cfg(debug_assertions)]
                JUDGED.with(|m| m.set(m.get() + 1));
                let edges = commits.get(c).map(|x| &**x);
                let parts = held.parts.get(c);
                let (author, position) = match (edges, parts) {
                    (Some(e), _) => (e.author, e.point()),
                    (None, Some(p)) => (p.author, Point::start(p.ts)),
                    (None, None) => continue,
                };
                let listed = Listed { edges, parts: parts.map_or(&[][..], |p| p.parts.as_slice()) };
                if !victims.contains(&author) || position >= rp || !first.could_write(&v.author, &listed, State::Before(pos)) {
                    continue;
                }
                if later.iter().all(|q| first.could_write(&v.author, &listed, State::After(*q))) {
                    out.entry(*r).or_default().insert(*c);
                }
            }
        }
    }
    out
}
