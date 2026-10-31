//! Tied grants (spec/permissions.md §2): an edge whose member is a group G, tied to G's placement
//! of the target T. Written together with the placement (`Osis::share_into`); once a node's
//! applied state holds G's `/group` without T, the tied edge is to be removed by a node that may
//! (the obligation node-sync runs, `SyncEngine::untie_unplaced`): explicitly by an admin of T,
//! else as a self-removal by an admin of G. One way only: a stale placement never re-grants.

use super::{Demotion, Done, PreSync, now_ts};
use crate::engine::Engine;
use crate::error::Result;
use osis_base::{Role, Tid};
use std::collections::BTreeSet;

/// How this node may remove a tied edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Untie {
    /// A self-removal through admin on the group: no frontier, no rotation, no pre-sync.
    SelfRemoval,
    /// An explicit demotion by an admin of the target: after the pre-sync of `presync_scope`.
    Explicit,
}

impl Engine {
    /// Whether `group`'s `/group` lists `t` as an item or subgroup; `None` when this node holds
    /// no `/group` of it (it cannot judge, so it holds no obligation).
    pub fn placed_in(&self, t: &Tid, group: &Tid) -> Option<bool> {
        self.core.ix.groups.defs.get(group).map(|(items, subs)| items.contains(t) || subs.contains(t))
    }

    /// Whether this node may grant `member` `role` on `target` now (spec/permissions.md §2):
    /// admin on the target, or an effective invite of at least `role` with no current edge of
    /// the member (an invite grant).
    pub fn may_grant(&self, target: &Tid, member: &Tid, role: Role) -> bool {
        let me = self.tid();
        if self.core.role_now(&me, target) == Some(Role::Admin) {
            return true;
        }
        let at = osis_perm::At::now(now_ts(&self.core));
        let Some(tl) = self.core.timelines.get(target) else { return false };
        !tl.roster(target, at).contains_key(member) && tl.invite(&me, target, at).is_some_and(|i| role <= i)
    }

    /// How this node may remove `member`'s edge on `target` now, if at all: a self-removal
    /// (admin on the member actor its only authority for it, spec/permissions.md §2), or an
    /// explicit demotion (admin on the target).
    pub fn may_remove(&self, target: &Tid, member: &Tid) -> Option<Untie> {
        let me = self.tid();
        if crate::apply::validity::self_removal(&self.core, &me, target, member, now_ts(&self.core)) {
            return Some(Untie::SelfRemoval);
        }
        (self.core.role_now(&me, target) == Some(Role::Admin)).then_some(Untie::Explicit)
    }

    /// The tied edges whose placement this node's applied state lacks (`placed_in` is
    /// `Some(false)`), as (target, group): those of every group in `groups` (from the targets it
    /// is named on as a member) and every tied edge on a thing in `targets`; with `all`, of
    /// every group this node holds a `/group` of.
    pub fn tied_unplaced(&self, groups: &BTreeSet<Tid>, targets: &BTreeSet<Tid>, all: bool) -> BTreeSet<(Tid, Tid)> {
        let defs = &self.core.ix.groups.defs;
        let mut pairs: BTreeSet<(Tid, Tid)> = BTreeSet::new();
        let gs: Box<dyn Iterator<Item = &Tid>> = if all { Box::new(defs.keys()) } else { Box::new(groups.iter()) };
        for g in gs {
            pairs.extend(self.core.ix.held.named_on(g).map(|t| (*t, *g)));
        }
        for t in targets {
            pairs.extend(self.core.ix.held.members_of(t).map(|g| (*t, *g)));
        }
        let mut out = BTreeSet::new();
        let mut last: Option<(Tid, std::collections::BTreeMap<Tid, osis_perm::Edge>)> = None;
        for (t, g) in pairs {
            if self.placed_in(&t, &g) != Some(false) {
                continue;
            }
            if last.as_ref().is_none_or(|(x, _)| *x != t) {
                last = Some((t, self.core.roster_of(&t)));
            }
            if last.as_ref().is_some_and(|(_, r)| r.get(&g).is_some_and(|e| e.tied)) {
                out.insert((t, g));
            }
        }
        out
    }

    /// Removes `group`'s tied edge on `t` (spec/permissions.md §2): an explicit demotion
    /// (stamped as pre-synced: the caller synced first) or a self-removal, as `may_remove` says.
    pub fn untie(&mut self, t: &Tid, group: &Tid) -> Result<Done> {
        self.demote(t, &Demotion { member: *group, new: None, presync: PreSync::Synced })
    }
}
