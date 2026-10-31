//! Tied grants (spec/permissions.md §2): an edge whose member is a group G, tied to G's placement
//! of the target T, named by the `/group` element's creation stamp. Written after the placement
//! (`Osis::share_into`); once a node's state of G's `/group` holds that element dead, the tied
//! edge is to be removed by a node that may (the obligation node-sync runs,
//! `SyncEngine::untie_unplaced`): explicitly by an admin of T, else as a self-removal by an admin
//! of G. An element not held yet is on its way: nothing. One way only: a stale placement never
//! re-grants.

use super::{Demotion, Done, PreSync, ak, now_ts};
use crate::engine::Engine;
use crate::error::Result;
use osis_base::{Role, Tid, Value};
use osis_crdt::{Held, Source, SourceKind, Stamp};
use osis_perm::{Tie, TieSource};
use osis_schema::AspectKey;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

/// How this node may remove a tied edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Untie {
    /// A self-removal through admin on the group: no frontier, no rotation, no pre-sync.
    SelfRemoval,
    /// An explicit demotion by an admin of the target: after the pre-sync of `presync_scope`.
    Explicit,
}

pub fn tie_ct(t: Tie) -> ct::Tie {
    let source = match t.src {
        TieSource::Node(n) => ct::Source::Node(n),
        TieSource::Commit(c) => ct::Source::Commit(c),
    };
    ct::Tie { ts: t.ts, source, ctr: t.ctr, subgroup: t.subgroup }
}

pub fn tie_perm(t: ct::Tie) -> Tie {
    let src = match t.source {
        ct::Source::Node(n) => TieSource::Node(n),
        ct::Source::Commit(c) => TieSource::Commit(c),
    };
    Tie { ts: t.ts, src, ctr: t.ctr, subgroup: t.subgroup }
}

fn stamp_of(t: &Tie) -> Stamp {
    let src = match t.src {
        TieSource::Node(n) => Source::node(n),
        TieSource::Commit(c) => Source::commit(c),
    };
    Stamp::new(t.ts, src, t.ctr)
}

/// The `/group` struct field of the items (0) or subgroups (1) set.
fn field(subgroup: bool) -> u64 {
    u64::from(subgroup)
}

impl Engine {
    /// The live element placing `t` in `group`'s items (or subgroups) here, as a tie: the one of
    /// greatest creation stamp; `None` when there is none.
    pub fn placement(&mut self, t: &Tid, group: &Tid, subgroup: bool) -> Result<Option<Tie>> {
        let Some(st) = self.state(group, &ak(ct::GROUP.ak())?)? else { return Ok(None) };
        let Some(s) = st.set_live_elem(field(subgroup), &Value::Tid(*t)) else { return Ok(None) };
        let src = match s.dot.src.kind() {
            SourceKind::Node(n) => TieSource::Node(*n),
            SourceKind::Commit(c) => TieSource::Commit(*c),
            SourceKind::Derived(_) => return Ok(None),
        };
        Ok(Some(Tie { ts: s.ts, src, ctr: s.dot.ctr, subgroup }))
    }

    /// Whether `group`'s current tied edge on `t` names a placement this node holds dead
    /// (spec/crdt.md §4.2, §5.5: a tombstone, or pruned by a later reset). One not held is on
    /// its way, whatever else the node holds.
    pub fn tie_dead(&mut self, t: &Tid, group: &Tid) -> Result<bool> {
        Ok(self.ties_dead(BTreeSet::from([(*t, *group)]))?.contains(&(*t, *group)))
    }

    /// Of `pairs` (target, group), those whose current tied edge names a placement held dead.
    fn ties_dead(&mut self, pairs: BTreeSet<(Tid, Tid)>) -> Result<BTreeSet<(Tid, Tid)>> {
        let mut ties: Vec<(Tid, Tid, Tie)> = Vec::new();
        let mut last: Option<(Tid, std::collections::BTreeMap<Tid, osis_perm::Edge>)> = None;
        for (t, g) in pairs {
            if last.as_ref().is_none_or(|(x, _)| *x != t) {
                last = Some((t, self.core.roster_of(&t)));
            }
            if let Some(tie) = last.as_ref().and_then(|(_, r)| r.get(&g)?.tied) {
                ties.push((t, g, tie));
            }
        }
        if ties.is_empty() {
            return Ok(BTreeSet::new());
        }
        // by group: one state read each
        ties.sort_by_key(|(_, g, _)| *g);
        let gak = ak(ct::GROUP.ak())?;
        self.run(|tx| {
            let mut out = BTreeSet::new();
            for (t, g, tie) in &ties {
                let Some(st) = tx.state(g, &gak)? else { continue };
                if st.set_elem(field(tie.subgroup), &stamp_of(tie)) == Held::Dead {
                    out.insert((*t, *g));
                }
            }
            Ok(out)
        })
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

    /// The tied edges whose placement this node holds dead (`tie_dead`), as (target, group):
    /// those of every group in `groups` (from the targets it is named on as a member) and every
    /// tied edge on a thing in `targets`; with `all`, of every group this node holds a `/group`
    /// of.
    pub fn tied_unplaced(&mut self, groups: &BTreeSet<Tid>, targets: &BTreeSet<Tid>, all: bool) -> Result<BTreeSet<(Tid, Tid)>> {
        let defs = &self.core.ix.groups.defs;
        let mut pairs: BTreeSet<(Tid, Tid)> = BTreeSet::new();
        let gs: Box<dyn Iterator<Item = &Tid>> = if all { Box::new(defs.keys()) } else { Box::new(groups.iter()) };
        for g in gs {
            pairs.extend(self.core.ix.held.named_on(g).map(|t| (*t, *g)));
        }
        for t in targets {
            pairs.extend(self.core.ix.held.members_of(t).map(|g| (*t, *g)));
        }
        self.ties_dead(pairs)
    }

    /// Removes `group`'s tied edge on `t` (spec/permissions.md §2): an explicit demotion
    /// (stamped as pre-synced: the caller synced first) or a self-removal, as `may_remove` says.
    pub fn untie(&mut self, t: &Tid, group: &Tid) -> Result<Done> {
        self.demote(t, &Demotion { member: *group, new: None, presync: PreSync::Synced })
    }
}
