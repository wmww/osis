//! What a demotion's frontier must cover (spec/permissions.md §5.1, "Frontier"), read from the
//! settled walk with the demotion: for each node it demotes, the things whose role-class and
//! admin-only (`^`) aspects it puts in question (a fall below a role, and the things holding
//! the edge writes its audit drops) and the things whose every aspect it puts in question (a
//! fall below write). The node lists the commit IDs it had received there (§5.1: what it had
//! received as of T).

use crate::timeline::Timeline;
use crate::types::{Frontier, RoleCommit};
use crate::walk;
use osis_base::{Role, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The aspects a demotion puts in question, per demoted node.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DemotionScope {
    /// Node -> things whose role-class and admin-only aspects the frontier lists its commits on.
    pub roles: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Node -> things on whose every aspect the frontier lists its commits.
    pub content: BTreeMap<Tid, BTreeSet<Tid>>,
}

impl DemotionScope {
    pub fn is_empty(&self) -> bool {
        self.roles.is_empty() && self.content.is_empty()
    }

    /// Whether this scope holds every aspect `o` names.
    pub fn covers(&self, o: &DemotionScope) -> bool {
        let sub = |a: &BTreeMap<Tid, BTreeSet<Tid>>, b: &BTreeMap<Tid, BTreeSet<Tid>>| b.iter().all(|(x, s)| a.get(x).is_some_and(|m| m.is_superset(s)));
        sub(&self.roles, &o.roles) && sub(&self.content, &o.content)
    }

    /// Adds every aspect `o` names.
    pub fn join(&mut self, o: DemotionScope) {
        for (mine, theirs) in [(&mut self.roles, o.roles), (&mut self.content, o.content)] {
            for (x, s) in theirs {
                mine.entry(x).or_default().extend(s);
            }
        }
    }
}

impl Timeline {
    /// What role commit `r` (not held here; an explicit demotion with its frontier) puts in
    /// question in the settled walk with it appended: per node, where its class falls at `r`
    /// that thing and the targets of its applied writes attributed there (self-removals through
    /// it), the targets of its edge writes `r`'s audit drops, and where it falls below a role
    /// (`roles`); where it falls below write (`content`). Empty when `r` demotes nobody or does
    /// not apply.
    ///
    /// The walk decides, not a standing computed beside it: `r`'s audit can drop a write that
    /// held up another standing (a grant by the demoted node, its own self-grant), so what `r`
    /// puts in question depends on its frontier. A demoter therefore builds its frontier from a
    /// scope S and asks again until the answer for that frontier is inside S (`covers`; S only
    /// grows, so this ends); then no write it received on an aspect `r` puts in question is
    /// dropped: a dropped one would have its target in the answer, so in S, so its receipt
    /// listed. Starting from the answer for `all_held` keeps the walk from re-walking the drops
    /// of an empty frontier.
    pub fn demotion_scope(&self, r: RoleCommit) -> DemotionScope {
        let p = r.point();
        let r = [Arc::new(r)];
        let tl = match self.copy().append(&r, &[]) {
            Ok(tl) => tl,
            // a commit `append` does not place (`Input::can_append`): walk with it from scratch
            Err(tl) => {
                let mut input = tl.input;
                input.append(&r);
                let out = walk::run(&input);
                Timeline::from_outcome(input, out)
            }
        };
        let mut out = DemotionScope::default();
        for ((x, n), ds) in &tl.walked.demotions {
            for d in ds.iter().filter(|d| d.point == p) {
                out.roles.entry(*x).or_default().insert(*n);
                if d.below == Role::Write {
                    out.content.entry(*x).or_default().insert(*n);
                }
            }
        }
        for ((x, n), fs) in &tl.walked.falls {
            if fs.iter().any(|f| f.point == p) {
                let ids = tl.walked.by_author_target.get(&(*x, *n)).into_iter().flatten();
                let on = ids.filter_map(|w| tl.walked.applied.get(w)).map(|a| a.target);
                out.roles.entry(*x).or_default().extend(on.chain([*n]));
            }
        }
        for (w, _) in tl.dropped().iter().filter(|(_, at)| **at == p) {
            let on = tl.input.commits.get(&w.0).and_then(|c| Some((c.author, c.ops.get(usize::try_from(w.1).ok()?)?.target)));
            if let Some((x, t)) = on {
                out.roles.entry(x).or_default().insert(t);
            }
        }
        out
    }

    /// A frontier listing every edge write held here (`demotion_scope` as if the demoter had
    /// received them all).
    pub fn all_held(&self) -> Frontier {
        Frontier { commits: self.input.commits.keys().copied().collect() }
    }
}
