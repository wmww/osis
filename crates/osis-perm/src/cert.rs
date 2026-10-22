//! Chain certificates (spec/permissions.md §4): which held records establish a node's
//! authority on a thing at a point, closed under authors, with every held demotion of the
//! chain; and verification from certificates alone.
//!
//! Readings: the things on the chain are those on any path from the node to the thing at the
//! point (edges alive then, any role, owner links); "every held demotion" is every held edge
//! write between two things of the chain and every held roster snapshot of one, applied or
//! not, at any time (a superset: a demotion that was itself dropped can still have dropped a
//! write, drops being sticky).

use crate::graph::{Edges, View};
use crate::held::{HeldSet, MemoryHeldSet};
use crate::timeline::{At, Timeline};
use crate::types::{Point, RosterSnapshot, WriteId};
use osis_core::{CommitId, Role, Tid};
use std::borrow::Cow;
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

/// `roles_from` per node at one point.
type Reach = BTreeMap<Tid, BTreeMap<Tid, Role>>;

/// Held membership commits by the (member, target) of their edge writes and roster snapshots
/// by thing, so a closure step costs what its chain touches, not the held history.
#[derive(Default)]
pub(crate) struct CertIndex {
    by_edge: BTreeMap<(Tid, Tid), Vec<CommitId>>,
    by_thing: BTreeMap<Tid, Vec<CommitId>>,
}

impl Timeline {
    fn cert_index(&self) -> &CertIndex {
        self.memo.certs.get_or_init(|| {
            let mut x = CertIndex::default();
            for cm in self.commits.values() {
                for o in &cm.ops {
                    x.by_edge.entry((o.member, o.target)).or_default().push(cm.id);
                }
            }
            for s in self.snaps.values() {
                x.by_thing.entry(s.thing).or_default().push(s.id);
            }
            x
        })
    }

    /// Things on any path from `node` to `thing` just before `at`, given the edge state there
    /// and a cache of `roles_from` at that point.
    fn chain_things(&self, node: &Tid, thing: &Tid, at: Point, edges: &Edges, reach: &mut Reach) -> BTreeSet<Tid> {
        let view = View::new(&self.owners, edges, Some(at.ts));
        let reach = reach.entry(*node).or_insert_with(|| view.roles_from(node));
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

    fn closure(&self, seeds: Vec<(Tid, Tid, Point)>) -> Certificates {
        let mut out = Certificates::default();
        let index = self.cert_index();
        // latest point first, keeping the edge state while the point stays the same; a step
        // can queue a later point, so a point's state may be built again when the walk returns
        let mut todo: BTreeSet<(Point, Tid, Tid)> = seeds.into_iter().map(|(n, t, p)| (p, n, t)).collect();
        let mut seen: BTreeSet<(Point, Tid, Tid)> = BTreeSet::new();
        let mut at: Option<(Point, Cow<'_, Edges>, Reach)> = None;
        while let Some((p, n, t)) = todo.pop_last() {
            if !seen.insert((p, n, t)) {
                continue;
            }
            if at.as_ref().is_none_or(|a| a.0 != p) {
                at = Some((p, self.edges_at(Some(p)), BTreeMap::new()));
            }
            let Some((_, edges, reach)) = at.as_mut() else { continue };
            let chain = self.chain_things(&n, &t, p, edges, reach);
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
            let pairs = chain.iter().flat_map(|m| chain.iter().map(move |t| (*m, *t)));
            for id in pairs.filter_map(|e| index.by_edge.get(&e)).flatten() {
                if let Some(cm) = self.commits.get(id).filter(|_| out.commits.insert(*id)) {
                    for o in &cm.ops {
                        todo.insert((cm.point(), cm.author, o.target));
                        todo.insert((cm.point(), cm.author, o.member));
                    }
                }
            }
            for s in chain.iter().filter_map(|t| index.by_thing.get(t)).flatten().filter_map(|id| self.snaps.get(id)) {
                let members: BTreeSet<Tid> = s.roster.keys().chain(s.ledger.iter().map(|x| &x.member)).filter(|m| chain.contains(m)).copied().collect();
                let entry = out.snapshots.entry(s.id).or_default();
                let fresh = entry.is_empty();
                entry.extend(members);
                if fresh {
                    todo.insert((s.point(), s.author, s.thing));
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
