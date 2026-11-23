//! Receipts (spec/permissions.md §5.1, notes/revocation.md): what a demotion's
//! frontier lists, by commit ID only. A held commit counts as received at its meta's receipt
//! time. Pending and parked commits are not received; snapshot frontiers and `Absorbed` are no
//! receipts (spec/crdt.md §8).

use crate::engine::{Core, Engine};
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid, Ts, WallMs};
use osis_commit::Header;
use osis_schema::core_types::{Frontier, is_role_class};
use std::collections::{BTreeMap, BTreeSet};

/// The held snapshots of `(tid, ak)`, any validity (bodies held, or dropped and still standing in,
/// `Dropped::stands_in`): ID and `ts`.
fn held_snapshots<'a>(core: &'a crate::engine::Core, tid: &'a Tid, ak: &'a Ak) -> impl Iterator<Item = (CommitId, Ts)> + 'a {
    let k = (*tid, ak.clone());
    let held = core.ix.snapshots.get(&k).into_iter().flatten().map(|x| (x.1, x.0));
    let kept = core.ix.dropped_snapshots.get(&k).into_iter().flatten().filter_map(move |s| Some((*s, core.ix.commits.get(s)?.view.ts)));
    held.chain(kept)
}

/// Whether a held snapshot valid here is stamped after the delta's commit: a suspect flag about the
/// delta is settled while one is (spec/permissions.md §4; `retention::suspect`). Rule 5's "any
/// later snapshot": no frontier can say more, since one holding nothing of the delta's session
/// or commit is all a writer that held the delta may have left.
pub(crate) fn settled(core: &crate::engine::Core, h: &Header, ai: usize) -> bool {
    let Some(a) = h.aspects.get(ai) else { return false };
    held_snapshots(core, &a.tid, &a.ak).any(|(s, ts)| ts > h.ts && crate::apply::copies::snapshot_valid(core, &s, &a.tid, &a.ak))
}

impl Engine {
    /// The frontier a demotion stamped now must embed (spec/permissions.md §5.1), by commit ID:
    /// per aspect the scope puts in question and per demoted node, that node's commits this
    /// node received by `as_of` (at their meta's receipt time; bodies held, dropped or compacted
    /// alike; memory commits as durable ones, a forgotten one not received); and, where it falls
    /// below write, its held commits acting for that thing; and every purge request whose right
    /// may rest on a role it puts in question (`retention::requests_resting_on`). This node's own receipts only. A demotion stamps it as
    /// of now; an earlier `as_of` gives the frontier as of then.
    pub fn frontier(&mut self, scope: &DemotionScope, as_of: WallMs) -> Result<Frontier> {
        Ok(self.frontier_and_requests(scope, as_of)?.0)
    }

    /// `frontier_and_requests` fitted to the list bound (`fit`): what is left out of content the
    /// demoter's own addenda list instead.
    pub(crate) fn frontier_fitted(&mut self, scope: &DemotionScope, as_of: WallMs, keep: &BTreeSet<CommitId>) -> Result<Frontier> {
        let (mut f, content, requests) = self.frontier_and_requests(scope, as_of)?;
        f.commits.extend(keep.iter().copied());
        let out: Vec<CommitId> = content.into_iter().chain(requests).filter(|c| !keep.contains(c)).collect();
        fit(&mut f, &out, self.core.list_bound);
        Ok(f)
    }

    /// The (demoted node, thing, aspect) triples `scope` puts in question (spec/permissions.md
    /// §5.1): role-class and admin-only (`^`) aspects for a fall below admin, every aspect for a
    /// fall below write.
    fn scope_aspects(&self, scope: &DemotionScope) -> Vec<(Tid, Tid, Ak)> {
        let admin_class = |ak: &Ak| is_role_class(ak.as_str()) || ak.admin_only();
        let mut aspects: Vec<(Tid, Tid, Ak)> = Vec::new();
        for (node, things) in &scope.roles {
            for ((t, ak), _) in things.iter().flat_map(|t| self.core.aspects_of(t)).filter(|((_, ak), _)| admin_class(ak)) {
                aspects.push((*node, *t, ak.clone()));
            }
        }
        for (node, things) in &scope.content {
            for ((t, ak), _) in things.iter().flat_map(|t| self.core.aspects_of(t)) {
                aspects.push((*node, *t, ak.clone()));
            }
        }
        aspects.sort();
        aspects.dedup();
        aspects
    }

    /// The demoter's own cover (spec/permissions.md §5.1, Own cover): the frontier lists every
    /// received commit of the demoted nodes this node still holds, so only what it no longer
    /// holds the ID of needs another word. For each aspect `scope` puts in question whose state
    /// holds a live write of a demoted node that stands only through a cover (a session write
    /// of the node, or a commit-form write, whose commit is not held here: forgotten under a
    /// cover, or never received), this node writes a fresh compaction snapshot from its whole
    /// state, which the frontier names. An aspect this node may not snapshot writes none.
    pub(crate) fn own_cover(&mut self, scope: &DemotionScope) -> Result<BTreeSet<CommitId>> {
        let mut by_aspect: BTreeMap<(Tid, Ak), BTreeSet<Tid>> = BTreeMap::new();
        for (node, t, ak) in self.scope_aspects(scope) {
            if crate::retention::snapshot::compacted(&ak) && !ak.ephemeral() {
                by_aspect.entry((t, ak)).or_default().insert(node);
            }
        }
        self.run(|tx| {
            let mut named = BTreeSet::new();
            for ((t, ak), nodes) in &by_aspect {
                if !crate::retention::snapshot::carried_only(tx, t, ak, &|x| nodes.contains(x), None)? {
                    continue;
                }
                if crate::retention::snapshot::may_snapshot(tx, t, ak, false, tx.core.hlc.peek())? == crate::engine::write::MayWrite::Yes
                    && let Some(s) = crate::retention::snapshot::write_own_cover(tx, t, ak)?
                {
                    named.insert(s);
                }
            }
            Ok(named)
        })
    }

    /// `frontier`, the plain-content commits it lists (what addenda may list, received last
    /// first) and the requests it lists (received last first): what `fit` leaves out when it is
    /// over the list bound, in that order.
    pub(crate) fn frontier_and_requests(&mut self, scope: &DemotionScope, as_of: WallMs) -> Result<(Frontier, Vec<CommitId>, Vec<CommitId>)> {
        let admin_class = |ak: &Ak| is_role_class(ak.as_str()) || ak.admin_only();
        let aspects = self.scope_aspects(scope);
        self.run(|tx| {
            let mut f = Frontier::default();
            // (received, commit) of the plain-content commits: those addenda may list
            let mut content: Vec<(std::cmp::Reverse<u64>, CommitId)> = Vec::new();
            for (node, t, ak) in aspects.iter().cloned() {
                let plain = !admin_class(&ak);
                for c in tx.core.held_on(&(t, ak.clone())) {
                    let Some(m) = tx.core.ix.commits.get(&c) else { continue };
                    if m.view.signer == node && m.received.0 <= as_of.0 {
                        f.commits.insert(c);
                        if plain && m.view.kind != osis_commit::Kind::Role && !m.view.purges {
                            content.push((std::cmp::Reverse(m.received.0), c));
                        }
                    }
                }
            }
            // a request's right ends with the role unless the frontier lists it (spec/permissions.md
            // §6): one this node received stays rightful, whatever became of its body and on
            // whatever aspect its own delta lies
            let mut requests = Vec::new();
            for (node, things) in &scope.roles {
                for pc in crate::retention::requests_resting_on(tx.core, node, things) {
                    let Some(m) = tx.core.ix.commits.get(&pc) else { continue };
                    if m.received.0 <= as_of.0 {
                        f.commits.insert(pc);
                        requests.push((std::cmp::Reverse(m.received.0), pc));
                    }
                }
            }
            requests.sort();
            requests.dedup();
            content.sort();
            content.dedup();
            Ok((f, content.into_iter().map(|x| x.1).collect(), requests.into_iter().map(|x| x.1).collect()))
        })
    }
}

/// Leaves out of frontier `f` as many of `out` (in order) as it takes to fit `max` encoded bytes
/// (spec/permissions.md §5.1): first the plain-content commits received last, which the
/// demoter's own addenda list instead (`flows::addenda`), then the purge requests received last,
/// each losing its right, so that requests never make a role holder impossible to demote (a
/// hostile holder's flood is what it received last). What is over `max` without them stays over:
/// `build` refuses it.
pub(crate) fn fit(f: &mut Frontier, out: &[CommitId], max: usize) {
    let size = |f: &Frontier| osis_base::cbor::encoded_len(&osis_schema::Codec::to_value(f));
    let each = osis_base::cbor::encoded_len(&osis_base::Value::bytes(&[0u8; 32]));
    let mut left = out.iter();
    let mut now = size(f);
    while now > max {
        for _ in 0..(now - max).div_ceil(each) {
            let Some(c) = left.next() else { return };
            f.commits.remove(c);
        }
        now = size(f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    // spec/permissions.md §5.1: over the bound the requests received last go first, never another
    // listed commit; with none left it stays over, for `build` to refuse.
    #[test]
    fn frontier_over_the_bound_leaves_out_requests_spec_perm_5_1() {
        let id = |i: u32| {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_be_bytes());
            CommitId(b)
        };
        let size = |f: &Frontier| osis_base::cbor::encoded_len(&osis_schema::Codec::to_value(f));
        let all = Frontier { commits: (0..2000).map(id).collect() };
        let requests: Vec<CommitId> = (1000..2000).rev().map(id).collect();
        let mut f = all.clone();
        fit(&mut f, &requests, size(&all));
        assert_eq!(f, all, "it fits");
        let max = size(&Frontier { commits: (0..1500).map(id).collect() });
        fit(&mut f, &requests, max);
        assert!(size(&f) <= max);
        assert_eq!(f.commits, (0..1500).map(id).collect::<BTreeSet<_>>(), "the oldest requests stay");
        fit(&mut f, &requests, 100);
        assert_eq!(f.commits, (0..1000).map(id).collect::<BTreeSet<_>>(), "only requests go");
    }
}

/// What a lowering puts in question, per signer: the things its commits resting on the lowered
/// edges write (`scope_of`).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DemotionScope {
    /// Signer -> things whose role-class and admin-only aspects the frontier lists its commits on.
    pub roles: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Signer -> things on whose every aspect the frontier lists its commits.
    pub content: BTreeMap<Tid, BTreeSet<Tid>>,
}

impl DemotionScope {
    pub fn is_empty(&self) -> bool {
        self.roles.is_empty() && self.content.is_empty()
    }
}

/// What lowering the edges `edges` (holder, target) puts in question (spec/permissions.md §5.1
/// Frontier): every commit with a part resting on one of them. Of those held, their signers and
/// the things they write (an edge-class part by its path, a delta along it:
/// `osis_perm::paths::Paths::resting`). Of those not held (forgotten under a cover, or never
/// received: Own cover), who could have signed one and where: whatever reaches the holder by held
/// grants and records, on whatever the target reaches. The frontier lists each signer's received
/// commits on those things: every commit resting on the edges, and those of the same signers
/// there along other paths, which a list names to no effect.
pub(crate) fn scope_of(core: &Core, edges: &[(Tid, Tid)]) -> DemotionScope {
    let mut scope = DemotionScope::default();
    for (holder, target) in edges {
        for c in core.timelines.paths().resting(holder, target) {
            let Some(m) = core.ix.commits.get(&c) else { continue };
            let things: BTreeSet<Tid> = m.view.aspects.iter().map(|a| a.tid).collect();
            scope.roles.entry(m.view.signer).or_default().extend(things.iter().copied());
            scope.content.entry(m.view.signer).or_default().extend(things);
        }
        let below = core.ix.held.reach(&BTreeSet::from([*target]));
        for signer in core.ix.held.upstream(&BTreeSet::from([*holder])) {
            scope.roles.entry(signer).or_default().extend(below.iter().copied());
            scope.content.entry(signer).or_default().extend(below.iter().copied());
        }
    }
    scope
}
