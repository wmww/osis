//! Layer 2 (spec/permissions.md §5.2): per-delta validity of content and of the
//! membership-class writes judged like content, and the node-form overlap rule
//! (spec/commits.md §4).

use crate::timeline::{At, Timeline};
use crate::types::{Dots, Point};
use osis_core::{CommitId, Role, Tid};
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
        let x = at.node;
        if self.role(&x, thing, At::END) >= Some(required) {
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
    let mut groups: BTreeMap<(Tid, Tid, String), BTreeSet<(u64, u64, CommitId)>> = BTreeMap::new();
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
