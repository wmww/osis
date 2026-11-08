//! Layer 2 (spec/permissions.md §5.2): per-delta validity of content and of the
//! role-class writes judged like content.

use crate::graph::{EdgesAt, View};
use crate::timeline::{At, Timeline};
use crate::walk::Demotion;
use crate::types::{earliest, Edge, Point};
use osis_base::{CommitId, Role, Tid, Ts, WallMs};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A node's roles replayed over the history up to change `pos` (`first_held_uncached`), and
/// the first change after which it held the replayed role on each thing (`None`: from the
/// beginning).
pub(crate) struct Replay {
    pos: usize,
    best: BTreeMap<Tid, Role>,
    expires: Option<WallMs>,
    first: BTreeMap<Tid, Option<Point>>,
}

/// Validity of one delta.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Validity {
    Valid,
    /// `by`: the explicit demotion whose frontier misses it, if any.
    Invalid { by: Option<Point> },
}

impl Timeline {
    /// §5.2: is a delta on `thing` of the commit at `at` (its author node, `ts` and commit ID)
    /// valid, addenda aside (`Vouching`)? `required` is the role its aspect needs: write for
    /// content, the aspect's role for `secrets.0`, `keys.0`, `label.0`. A re-grant (the author
    /// holds `required` at the end of the timeline) validates every write; otherwise a write
    /// made while holding the role stands unless a valid explicit demotion below it follows,
    /// and else only if the frontier of such a demotion, in any order, lists its commit.
    pub fn delta_valid(&self, at: Point, thing: &Tid, required: Role) -> Validity {
        let key = (at, *thing, required);
        if let Some(v) = self.memo.valid.lock().ok().and_then(|m| m.get(&key).copied()) {
            return v;
        }
        let v = self.delta_valid_uncached(at, thing, required);
        if let Ok(mut m) = self.memo.valid.lock() {
            m.insert(key, v);
        }
        v
    }

    /// Where `node`'s deltas on `thing` needing `required` start being valid whatever their
    /// commit (`delta_valid`'s re-grant case): `Some(None)` every one, `Some(Some(p))`
    /// those at or after `p`, `None` no such bound (judge each with `delta_valid`). For judging
    /// many deltas of one author at once.
    pub fn valid_from(&self, node: &Tid, thing: &Tid, required: Role) -> Option<Option<Point>> {
        if self.role(node, thing, At::END) >= Some(required) { self.first_held(node, thing, required) } else { None }
    }

    fn delta_valid_uncached(&self, at: Point, thing: &Tid, required: Role) -> Validity {
        let x = at.node;
        // A re-grant makes valid *again*: only writes from the first point X held `required`
        // on the thing.
        if self.valid_from(&x, thing, required).is_some_and(|s| s.is_none_or(|p| p <= at)) {
            return Validity::Valid;
        }
        let held = self.role(&x, thing, At::before(at)) >= Some(required);
        let dems: Vec<&Demotion> = self.demotions(&x, thing).iter().filter(|d| d.below == required).collect();
        let later = dems.iter().any(|d| d.point > at);
        if held && !later {
            return Validity::Valid;
        }
        // a frontier is what its demoter had received: every demotion's saves what it lists,
        // whatever the order (§5.2)
        if dems.iter().any(|d| d.frontier.as_ref().is_some_and(|f| f.covers(&at.commit))) {
            return Validity::Valid;
        }
        Validity::Invalid { by: dems.last().map(|d| d.point) }
    }

    /// The addenda on `thing` that count (§5.2, Addenda): the least fixpoint of "valid as its
    /// author's plain delta on the thing, by `delta_valid` or by a counting addendum", kept to
    /// those whose author held write on the thing at their key. `addenda`: every held addendum
    /// delta on `thing`, a write of its author as itself (one acting for another actor is no
    /// addendum), listing what its body says while held and nothing otherwise: its validity
    /// never depends on its body.
    pub fn vouching(&self, thing: &Tid, addenda: &[Addendum]) -> Vouching {
        // (addendum, its author held write at its key, valid so far)
        let mut st: Vec<(&Addendum, bool, bool)> = addenda.iter().map(|a| (a, self.role(&a.point.node, thing, At::before(a.point)) >= Some(Role::Write), false)).collect();
        loop {
            let mut changed = false;
            for i in 0..st.len() {
                let Some(&(a, _, valid)) = st.get(i) else { break };
                if valid {
                    continue;
                }
                let v = self.delta_valid(a.point, thing, Role::Write) == Validity::Valid || st.iter().any(|(b, w, bv)| *bv && *w && self.vouches(thing, b, a.point));
                if v && let Some(x) = st.get_mut(i) {
                    x.2 = true;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let counting = st.iter().filter(|(_, w, v)| *w && *v).map(|(a, _, _)| (*a).clone()).collect();
        Vouching { thing: *thing, valid: st.iter().filter(|(_, _, v)| *v).map(|(a, _, _)| a.point.commit).collect(), counting }
    }

    /// Whether addendum `a` (counting) vouches for the write at `at` on `thing`: an entry of it
    /// names an explicit demotion of `at.node` below write on the thing ordered after `at` and
    /// before `a`, and lists `at`'s commit.
    fn vouches(&self, thing: &Tid, a: &Addendum, at: Point) -> bool {
        a.point > at
            && a.entries.iter().any(|(removal, lists)| lists.contains(&at.commit) && self.demotions(&at.node, thing).iter().any(|d| d.below == Role::Write && d.point.commit == *removal && at < d.point && d.point < a.point))
    }


    /// Where `x` first held `required` on `thing`: `Some(None)` from the beginning, `Some(p)`
    /// from the change at `p`, `None` never.
    pub fn first_held(&self, x: &Tid, thing: &Tid, required: Role) -> Option<Option<Point>> {
        let key = (*x, *thing, required);
        // debug builds compare every answer, memoized ones (some carried over `extend`) too
        if let Some(v) = self.memo.first_held.lock().ok().and_then(|m| m.get(&key).copied()) {
            #[cfg(debug_assertions)]
            debug_assert_eq!(v, self.first_held_replayed(x, thing, required));
            return v;
        }
        let v = self.first_held_uncached(x, thing, required);
        #[cfg(debug_assertions)]
        debug_assert_eq!(v, self.first_held_replayed(x, thing, required));
        if let Ok(mut m) = self.memo.first_held.lock() {
            m.insert(key, v);
        }
        v
    }

    /// Replays `x`'s roles over the history: a change of an edge out of something `x` does not
    /// reach changes none of them; a wider edge raises them in place; only an edge that may
    /// have carried a role narrowing, or one expiring, searches again. Between two searches
    /// roles only fall (edges expire), so the first change after which they hold is found.
    /// The replay is kept per (node, role) and goes on where it stopped, recording each
    /// thing at the first change after which the node holds the role on it, so the queries
    /// of one node replay the history once.
    fn first_held_uncached(&self, x: &Tid, thing: &Tid, required: Role) -> Option<Option<Point>> {
        let mut replays = self.memo.replays.lock().unwrap_or_else(|e| e.into_inner());
        let r = replays.entry((*x, required)).or_insert_with(|| {
            let edges = EdgesAt::new(&self.input.records, &crate::graph::INITIAL);
            let (best, expires) = View::at(&edges, Some(Ts::default())).roles_expiring(x);
            let first = best.iter().filter(|(_, r)| **r >= required).map(|(t, _)| (*t, None)).collect();
            Replay { pos: 0, best, expires, first }
        });
        if let Some(p) = r.first.get(thing) {
            return Some(*p);
        }
        let mut edges = EdgesAt::new(&self.input.records, &crate::graph::INITIAL);
        let mut pos = 0;
        while let Some(c) = self.walked.history.get(r.pos) {
            let i = r.pos;
            r.pos += 1;
            // `best` is exact while nothing expired, else at least the roles
            let Some(&level) = r.best.get(&c.holder) else { continue };
            let ts = c.point.ts;
            self.advance(&mut edges, pos, i);
            let old = edges.get(&c.holder, &c.target).copied();
            edges.set(c.holder, c.target, c.edge);
            pos = i + 1;
            let view = View::at(&edges, Some(ts));
            let gives = |e: Option<Edge>| e.filter(|e| e.alive_at(Some(ts))).map(|e| level.min(e.role));
            let (was, now, cur) = (gives(old), gives(c.edge), r.best.get(&c.target).copied());
            if r.expires.is_some_and(|u| ts.wall_ms() >= u) || (was.is_some() && was >= cur && now < was) {
                (r.best, r.expires) = view.roles_expiring(x);
                for (t, role) in &r.best {
                    if *role >= required {
                        r.first.entry(*t).or_insert(Some(c.point));
                    }
                }
            } else if now > cur {
                let (raised, until) = view.roles_raised_expiring(&r.best, &[c.holder]);
                for (t, role) in &raised {
                    if *role >= required {
                        r.first.entry(*t).or_insert(Some(c.point));
                    }
                }
                r.best.extend(raised);
                r.expires = earliest(r.expires, until);
            }
            r.expires = earliest(r.expires, c.edge.and_then(|e| e.until));
            if let Some(p) = r.first.get(thing) {
                return Some(*p);
            }
        }
        // replayed to the end: only `first` is read again
        r.best = BTreeMap::new();
        None
    }

    /// `first_held_uncached` by a search at every change (debug check).
    #[cfg(debug_assertions)]
    fn first_held_replayed(&self, x: &Tid, thing: &Tid, required: Role) -> Option<Option<Point>> {
        let mut edges = crate::graph::Edges::default();
        let holds = |edges: &crate::graph::Edges, ts: Ts| View::new(&self.input.records, edges, Some(ts)).roles_from(x).get(thing).copied() >= Some(required);
        if holds(&edges, Ts::default()) {
            return Some(None);
        }
        for c in &self.walked.history {
            edges.set(&self.input.records, c.holder, c.target, c.edge);
            if holds(&edges, c.point.ts) {
                return Some(Some(c.point));
            }
        }
        None
    }
}


/// An addendum delta held on a thing (spec/permissions.md §5.2, Addenda): a plain write of its
/// author at `point`, with the entries its body says.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Addendum {
    pub point: Point,
    pub entries: Vec<AddendumEntry>,
}

/// One addendum entry: the removal's commit ID and the commit IDs listed for it.
pub type AddendumEntry = (CommitId, Arc<BTreeSet<CommitId>>);

/// The addenda on one thing that count (`Timeline::vouching`).
#[derive(Clone, Debug)]
pub struct Vouching {
    thing: Tid,
    /// Addenda valid as their author's plain delta (the fixpoint).
    valid: BTreeSet<CommitId>,
    /// Of those, the ones whose author held write on the thing at their key.
    counting: Vec<Addendum>,
}

impl Vouching {
    /// Whether the addendum of commit `c` is valid as its author's delta on the thing.
    pub fn valid(&self, c: &CommitId) -> bool {
        self.valid.contains(c)
    }

    /// The counting addenda vouching for the part at `at` on the thing: each witness and the
    /// addendum's key. A commit's Acting check is its part on its header actor, vouched for on
    /// that actor's timeline.
    pub fn witnesses<'a>(&'a self, tl: &'a Timeline, at: Point) -> impl Iterator<Item = (Tid, Point)> + 'a {
        self.counting.iter().filter(move |a| tl.vouches(&self.thing, a, at)).map(|a| (a.point.node, a.point))
    }

    pub fn is_empty(&self) -> bool {
        self.counting.is_empty()
    }
}
