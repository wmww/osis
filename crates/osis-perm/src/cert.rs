//! Chain certificates (spec/permissions.md §4): which held records establish a node's
//! authority on a thing at a point, closed under authors, with every held demotion of the
//! chain; and verification from certificates alone.
//!
//! Readings: the things on the chain are those on any path from the node to the thing at the
//! point (edges alive then, any role, owner links); "every held demotion" is every held edge
//! write between two things of the chain and every held roster snapshot of one, applied or
//! not, at any time (a superset: a demotion that was itself dropped can still have dropped a
//! write, drops being sticky).

use crate::graph::View;
use crate::held::{HeldSet, MemoryHeldSet};
use crate::timeline::{At, Timeline};
use crate::types::{Point, RosterSnapshot, WriteId};
use osis_core::{CommitId, Role, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The certificate records of a chain.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Certificates {
    /// Things whose `/created` record goes along.
    pub created: BTreeSet<Tid>,
    /// Membership commits (edge writes) that go along whole.
    pub commits: BTreeSet<CommitId>,
    /// Roster snapshots, projected to these members' roster and ledger entries.
    pub snapshots: BTreeMap<CommitId, BTreeSet<Tid>>,
    /// Actors whose current `/keys` commit goes along.
    pub keys: BTreeSet<Tid>,
}

impl Timeline {
    /// Things on any path from `node` to `thing` just before `at`.
    fn chain_things(&self, node: &Tid, thing: &Tid, at: Point) -> BTreeSet<Tid> {
        let edges = self.edges_at(Some(at));
        let view = View { owners: &self.owners, edges: &edges, ts: Some(at.ts) };
        let reach = view.roles_from(node);
        let to = view.reach_backward(thing);
        let mut c: BTreeSet<Tid> = reach.keys().filter(|t| to.contains(t)).copied().collect();
        c.insert(*node);
        c.insert(*thing);
        c
    }

    /// The chain certificates of `node` for a write on `thing` at `at` (§4).
    pub fn certificates(&self, node: &Tid, thing: &Tid, at: Point) -> Certificates {
        self.closure(vec![(*node, *thing, at)])
    }

    /// What a verifier needs to judge edge write `id` as this timeline does: its author's
    /// chains to the target and to the member (a self-removal's authority) and the member's
    /// chain to the target with that edge's history.
    pub fn write_certificates(&self, id: &WriteId) -> Option<Certificates> {
        let (seeds, own) = match id {
            WriteId::Op(c, k) => {
                let cm = self.commits.get(c)?;
                let op = cm.ops.get(usize::try_from(*k).ok()?)?;
                let p = cm.point();
                (vec![(cm.author, op.target, p), (cm.author, op.member, p), (op.member, op.target, p)], cm.id)
            }
            WriteId::Snapshot(c) => {
                let s = self.snaps.get(c)?;
                (vec![(s.author, s.thing, s.point())], s.id)
            }
        };
        let mut out = self.closure(seeds);
        if self.commits.contains_key(&own) {
            out.commits.insert(own);
        } else if let Some(s) = self.snaps.get(&own) {
            out.snapshots.entry(own).or_default().extend(s.roster.keys().chain(s.ledger.iter().map(|t| &t.member)).copied());
        }
        Some(out)
    }

    fn closure(&self, mut todo: Vec<(Tid, Tid, Point)>) -> Certificates {
        let mut out = Certificates::default();
        let mut seen: BTreeSet<(Tid, Tid, Point)> = BTreeSet::new();
        while let Some((n, t, p)) = todo.pop() {
            if !seen.insert((n, t, p)) {
                continue;
            }
            let chain = self.chain_things(&n, &t, p);
            for c in &chain {
                // /created of each thing on the chain and of its owners up to the key actor.
                out.created.insert(*c);
                let (up, top) = self.owners.chain(c);
                out.created.extend(up);
                out.created.extend(top);
                if self.owners.owner(c).is_some() {
                    out.keys.insert(*c);
                }
            }
            for cm in self.commits.values() {
                if cm.ops.iter().any(|o| chain.contains(&o.member) && chain.contains(&o.target)) && out.commits.insert(cm.id) {
                    for o in &cm.ops {
                        todo.push((cm.author, o.target, cm.point()));
                        todo.push((cm.author, o.member, cm.point()));
                    }
                }
            }
            for s in self.snaps.values().filter(|s| chain.contains(&s.thing)) {
                let members: BTreeSet<Tid> = s.roster.keys().chain(s.ledger.iter().map(|x| &x.member)).filter(|m| chain.contains(m)).copied().collect();
                let entry = out.snapshots.entry(s.id).or_default();
                let fresh = entry.is_empty();
                entry.extend(members);
                if fresh {
                    todo.push((s.author, s.thing, s.point()));
                }
            }
        }
        out
    }

    /// The certificate records as a held set (snapshots projected); `created` supplies the
    /// creation records.
    pub fn certificate_set(&self, certs: &Certificates, created: &dyn HeldSet) -> MemoryHeldSet {
        let mut h = MemoryHeldSet::new();
        for t in &certs.created {
            if let Some(r) = created.created(t) {
                h.created.insert(*t, r);
            }
        }
        for id in &certs.commits {
            if let Some(c) = self.commits.get(id) {
                h.add_commit((**c).clone());
            }
        }
        for (id, members) in &certs.snapshots {
            if let Some(s) = self.snaps.get(id) {
                h.add_snapshot(project(s, members));
            }
        }
        h
    }
}

/// A roster snapshot projected to some members' entries (§6: a certificate copy).
pub fn project(s: &Arc<RosterSnapshot>, members: &BTreeSet<Tid>) -> RosterSnapshot {
    let mut p = (**s).clone();
    p.roster.retain(|m, _| members.contains(m));
    p.ledger.retain(|t| members.contains(&t.member));
    p
}

/// Verifies from certificates alone (§4) that `node`, a key actor whose tid commits to its
/// key, held `required` on `thing` just before `at`. The signature is the caller's.
pub fn verify(certs: &dyn HeldSet, node: &Tid, thing: &Tid, at: Point, required: Role) -> bool {
    let tl = Timeline::evaluate(certs);
    tl.owners().is_key(node) && tl.role(node, thing, At::before(at)) >= Some(required)
}
