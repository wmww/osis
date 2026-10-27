//! Layer 2 (spec/permissions.md §5.2): per-delta validity of content and of the
//! membership-class writes judged like content, and the node-form overlap rule
//! (spec/commits.md §4).

use crate::graph::{EdgesAt, View};
use crate::timeline::{At, Timeline};
use crate::types::{Dots, Edge, Point};
use osis_core::{CommitId, Role, Tid, Ts, WallMs};
use std::collections::{BTreeMap, BTreeSet};

/// Validity of one delta.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Validity {
    Valid,
    /// `by`: the explicit demotion whose frontier misses it, if any.
    Invalid { by: Option<Point> },
}

impl Timeline {
    /// §5.2: is the delta of the commit at `at` (its author node, `ts` and commit ID) on
    /// `(thing, ak)` with `dots` valid? `required` is the role its aspect needs: write for
    /// content, the aspect's role for `/secrets`, `/keys`, `/label`, `/moved`, `/was`.
    /// A re-grant (the author holds `required` at the end of the timeline) validates every
    /// write; otherwise a write made while holding the role stands unless a valid explicit
    /// demotion below it (a ledger tenure with a frontier included) follows, and else only if
    /// the newest such demotion's frontier covers its dots.
    pub fn delta_valid(&self, at: Point, thing: &Tid, ak: &str, dots: Dots, required: Role) -> Validity {
        let key = (at, *thing, ak.to_string(), dots, required);
        if let Some(v) = self.memo.valid.lock().ok().and_then(|m| m.get(&key).copied()) {
            return v;
        }
        let v = self.delta_valid_uncached(at, thing, ak, dots, required);
        if let Ok(mut m) = self.memo.valid.lock() {
            m.insert(key, v);
        }
        v
    }

    /// Where `node`'s deltas on `thing` needing `required` start being valid whatever their
    /// `ak` and dots (`delta_valid`'s re-grant case): `Some(None)` every one, `Some(Some(p))`
    /// those at or after `p`, `None` no such bound (judge each with `delta_valid`). For judging
    /// many deltas of one author at once.
    pub fn valid_from(&self, node: &Tid, thing: &Tid, required: Role) -> Option<Option<Point>> {
        if self.role(node, thing, At::END) >= Some(required) { self.first_held(node, thing, required) } else { None }
    }

    fn delta_valid_uncached(&self, at: Point, thing: &Tid, ak: &str, dots: Dots, required: Role) -> Validity {
        let x = at.node;
        // A re-grant makes valid *again*: only writes from the start of X's first tenure of
        // `required` on the thing.
        if self.role(&x, thing, At::END) >= Some(required) && self.first_held(&x, thing, required).is_some_and(|s| s.is_none_or(|p| p <= at)) {
            return Validity::Valid;
        }
        let held = self.role(&x, thing, At::before(at)) >= Some(required);
        let newest = self.demotions(&x, thing).iter().rfind(|d| d.below == required);
        match newest {
            Some(d) if held && d.point < at => Validity::Valid,
            None if held => Validity::Valid,
            Some(d) => {
                if d.frontier.as_ref().is_some_and(|f| f.covers(thing, ak, &x, dots, &at.commit)) {
                    Validity::Valid
                } else {
                    Validity::Invalid { by: Some(d.point) }
                }
            }
            None => Validity::Invalid { by: None },
        }
    }
}

impl Timeline {
    /// Where `x` first held `required` on `thing`: `Some(None)` from the beginning, `Some(p)`
    /// from the change at `p`, `None` never.
    fn first_held(&self, x: &Tid, thing: &Tid, required: Role) -> Option<Option<Point>> {
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
    fn first_held_uncached(&self, x: &Tid, thing: &Tid, required: Role) -> Option<Option<Point>> {
        let holds = |best: &BTreeMap<Tid, Role>| best.get(thing).copied() >= Some(required);
        let mut edges = EdgesAt::new(&self.walked.initial);
        let (mut best, mut expires) = View::at(&self.input.owners, &edges, Some(Ts::default())).roles_expiring(x);
        if holds(&best) {
            return Some(None);
        }
        let mut pos = 0;
        for (i, c) in self.walked.history.iter().enumerate() {
            // `best` is exact while nothing expired, else at least the roles
            let Some(&level) = best.get(&c.member) else { continue };
            let ts = c.point.ts;
            self.advance(&mut edges, pos, i);
            let old = edges.get(&c.member, &c.target).copied();
            edges.set(c.member, c.target, c.edge);
            pos = i + 1;
            let view = View::at(&self.input.owners, &edges, Some(ts));
            let gives = |e: Option<Edge>| e.filter(|e| e.alive_at(Some(ts))).map(|e| level.min(e.role));
            let (was, now, cur) = (gives(old), gives(c.edge), best.get(&c.target).copied());
            if expires.is_some_and(|u| ts.wall_ms() >= u) || (was.is_some() && was >= cur && now < was) {
                (best, expires) = view.roles_expiring(x);
            } else if now > cur {
                let (raised, until) = view.roles_raised_expiring(&best, &[c.member]);
                best.extend(raised);
                expires = earliest(expires, until);
            }
            expires = earliest(expires, c.edge.and_then(|e| e.until));
            if holds(&best) {
                return Some(Some(c.point));
            }
        }
        None
    }

    /// `first_held_uncached` by a search at every change (debug check).
    #[cfg(debug_assertions)]
    fn first_held_replayed(&self, x: &Tid, thing: &Tid, required: Role) -> Option<Option<Point>> {
        let mut edges = self.walked.initial.clone();
        let holds = |edges: &crate::graph::Edges, ts: Ts| View::new(&self.input.owners, edges, Some(ts)).roles_from(x).get(thing).copied() >= Some(required);
        if holds(&edges, Ts::default()) {
            return Some(None);
        }
        for c in &self.walked.history {
            edges.set(c.member, c.target, c.edge);
            if holds(&edges, c.point.ts) {
                return Some(Some(c.point));
            }
        }
        None
    }
}

fn earliest(a: Option<WallMs>, b: Option<WallMs>) -> Option<WallMs> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// One commit's node-form range on one aspect.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Range {
    pub commit: CommitId,
    pub node: Tid,
    pub tid: Tid,
    pub ak: String,
    pub lo: u64,
    pub hi: u64,
}

/// spec/commits.md §4, §5.2: commits by one node whose node-form ranges on one aspect overlap
/// are all invalid. Returns the voided commit IDs. A commit listed twice with one range is one.
pub fn overlapping(ranges: impl IntoIterator<Item = Range>) -> BTreeSet<CommitId> {
    type Key = (Tid, Tid, String);
    let mut groups: BTreeMap<Key, BTreeSet<(u64, u64, CommitId)>> = BTreeMap::new();
    for r in ranges {
        if r.lo < r.hi {
            groups.entry((r.node, r.tid, r.ak)).or_default().insert((r.lo, r.hi, r.commit));
        }
    }
    let mut out = BTreeSet::new();
    for set in groups.values() {
        let mut active: Vec<(u64, CommitId)> = Vec::new();
        for &(lo, hi, c) in set {
            active.retain(|&(h, _)| h > lo);
            let mut hit = false;
            for &(_, other) in &active {
                if other != c {
                    out.insert(other);
                    hit = true;
                }
            }
            if hit {
                out.insert(c);
            }
            active.push((hi, c));
        }
    }
    out
}
