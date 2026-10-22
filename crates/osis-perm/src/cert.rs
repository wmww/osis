//! Chain certificates (spec/permissions.md §4): which held records establish a node's
//! authority on a thing at a point, closed under authors, with every held demotion of the
//! chain; and verification from certificates alone.
//!
//! Readings: the things on the chain are those on any path from the node to the thing at the
//! point (edges alive then, any role, owner links); "every held demotion" is every held edge
//! write between two things of the chain and every held roster snapshot of one, applied or
//! not, at any time (a superset: a demotion that was itself dropped can still have dropped a
//! write, drops being sticky); each later one that may demote the node (a static check, applied
//! or not) brings the node's chain for the same thing at its point, since whether its class fell
//! depends on its other paths there.

use crate::graph::{EdgesAt, View};
use crate::held::{HeldSet, MemoryHeldSet};
use crate::timeline::{At, Timeline};
use crate::types::{Edge, Point, RosterSnapshot, WriteId};
use crate::walk;
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

/// A held value of an edge: its point, the value, the commit (none for a snapshot roster).
type EdgeValue = (Point, Option<Edge>, Option<CommitId>);

/// A processed closure state's point and chain.
type Chain = (Point, BTreeSet<Tid>);

/// `roles_from` per node and `reach_backward` per thing at one point.
type Reach = (BTreeMap<Tid, BTreeMap<Tid, Role>>, BTreeMap<Tid, BTreeSet<Tid>>);

/// Held membership commits by the member and target of their edge writes and roster snapshots
/// by thing, so a closure step costs what its chain touches, not the held history.
#[derive(Default)]
pub(crate) struct CertIndex {
    /// By member, then target: the commits writing that edge, by point.
    by_edge: BTreeMap<Tid, BTreeMap<Tid, Vec<EdgeWrite>>>,
    by_thing: BTreeMap<Tid, Vec<CommitId>>,
    /// Things with a held edge write or roster snapshot on them: the only key actors a path
    /// can pass through.
    entered: BTreeSet<Tid>,
}

/// A held commit writing an edge.
struct EdgeWrite {
    commit: Arc<crate::types::MembershipCommit>,
    /// It has a write that may demote (below an earlier value of its edge).
    audit: bool,
}

impl Timeline {
    fn cert_index(&self) -> &CertIndex {
        self.memo.certs.get_or_init(|| {
            let mut x = CertIndex::default();
            let mut audits: BTreeSet<CommitId> = BTreeSet::new();
            // A static check, so a demotion dropped in a later round counts too: a write below
            // the join of every earlier held value on its edge (snapshot rosters included).
            let mut values: BTreeMap<(Tid, Tid), Vec<EdgeValue>> = BTreeMap::new();
            for cm in self.commits.values() {
                for o in &cm.ops {
                    values.entry((o.member, o.target)).or_default().push((cm.point(), o.edge, Some(cm.id)));
                }
            }
            for s in self.snaps.values() {
                for (m, e) in &s.roster {
                    values.entry((*m, s.thing)).or_default().push((s.point(), Some(*e), None));
                }
            }
            for mut v in values.into_values() {
                v.sort_by_key(|x| x.0);
                let mut restored: Option<Edge> = None;
                for (p, e, id) in v {
                    if let Some(id) = id.filter(|_| walk::exceeds(restored, e, p.ts)) {
                        audits.insert(id);
                    }
                    if let Some(e) = e.filter(|e| e.alive_at(Some(p.ts))) {
                        restored = Some(walk::join(restored, e));
                    }
                }
            }
            for cm in self.commits.values() {
                for o in &cm.ops {
                    let w = EdgeWrite { commit: cm.clone(), audit: audits.contains(&cm.id) };
                    x.by_edge.entry(o.member).or_default().entry(o.target).or_default().push(w);
                    x.entered.insert(o.target);
                }
            }
            for ws in x.by_edge.values_mut().flat_map(|m| m.values_mut()) {
                ws.sort_by_key(|w| w.commit.point());
            }
            for s in self.snaps.values() {
                x.by_thing.entry(s.thing).or_default().push(s.id);
                x.entered.insert(s.thing);
            }
            x
        })
    }

    /// Things on any path from `node` to `thing` just before `at`, given the edge state there
    /// and a cache of `roles_from` at that point.
    fn chain_things(&self, node: &Tid, thing: &Tid, at: Point, edges: &EdgesAt<'_>, reach: &mut Reach) -> BTreeSet<Tid> {
        let view = View::at(&self.owners, edges, Some(at.ts));
        let from = reach.0.entry(*node).or_insert_with(|| view.roles_from(node));
        let to = reach.1.entry(*thing).or_insert_with(|| view.reach_backward(thing));
        let mut c: BTreeSet<Tid> = from.keys().filter(|t| to.contains(t)).copied().collect();
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
        let mut at: Option<(Point, EdgesAt<'_>, Reach)> = None;
        // n's chains at later demotions go in rounds, so each round visits a point once
        let mut later: BTreeSet<(Point, Tid, Tid)> = BTreeSet::new();
        let mut on_chains: BTreeSet<Tid> = BTreeSet::new();
        // edges whose commits are in
        let mut edges_in: BTreeSet<(Tid, Tid)> = BTreeSet::new();
        let mut covered: BTreeMap<(Tid, Tid), Vec<Chain>> = BTreeMap::new();
        loop {
            let Some((p, n, t)) = todo.pop_last() else {
                if later.is_empty() {
                    break;
                }
                todo.append(&mut later);
                continue;
            };
            if !seen.insert((p, n, t)) {
                continue;
            }
            if at.as_ref().is_none_or(|a| a.0 != p) {
                at = Some((p, self.edges_at(Some(p)), Reach::default()));
            }
            let Some((_, edges, reach)) = at.as_mut() else { continue };
            let chain = self.chain_things(&n, &t, p, edges, reach);
            // what an earlier state of (n, t) with a chain containing this one added covers
            // all this one would: its later writes, commits, things and snapshot members
            let done = covered.entry((n, t)).or_default();
            if done.iter().any(|(q, c)| *q <= p && chain.is_subset(c)) {
                continue;
            }
            done.push((p, chain.clone()));
            for c in &chain {
                if !on_chains.insert(*c) {
                    continue;
                }
                // /created of each thing on the chain and of its owners up to the key actor.
                out.created.insert(*c);
                let (up, top) = self.owners.chain(c);
                out.created.extend(up);
                out.created.extend(top);
                if self.owners.owner(c).is_some() {
                    out.keys.insert(*c);
                }
            }
            // A later write on the chain that lowered its edge may demote n: n's chain at its
            // point goes along too, so the verifier sees whether n's class fell (another path
            // may keep it). Earlier ones are covered from the states of n's earlier writes.
            let on_chain = chain.iter().filter_map(|m| index.by_edge.get(m).map(|x| (*m, x)));
            for (m, tg, ws) in on_chain.flat_map(|(m, x)| x.iter().filter(|(tg, _)| chain.contains(tg)).map(move |(tg, ws)| (m, *tg, ws))) {
                // n reaches a key actor other than itself only through an edge on it
                let reaches = |m: &Tid| *m == n || !self.owners.is_key(m) || index.entered.contains(m);
                for w in ws.get(ws.partition_point(|w| w.commit.point() <= p)..).unwrap_or_default() {
                    if w.audit && w.commit.ops.iter().any(|o| reaches(&o.member)) {
                        later.insert((w.commit.point(), n, t));
                    }
                }
                if edges_in.insert((m, tg)) {
                    for cm in ws.iter().map(|w| &w.commit) {
                        if out.commits.insert(cm.id) {
                            for o in &cm.ops {
                                todo.insert((cm.point(), cm.author, o.target));
                                todo.insert((cm.point(), cm.author, o.member));
                            }
                        }
                    }
                }
            }
            for s in chain.iter().filter_map(|t| index.by_thing.get(t)).flatten().filter_map(|id| self.snaps.get(id)) {
                let members: BTreeSet<Tid> = s.roster.keys().chain(s.ledger.iter().map(|x| &x.member)).filter(|m| chain.contains(m)).copied().collect();
                let entry = out.snapshots.entry(s.id).or_default();
                let fresh = entry.is_empty();
                entry.extend(members);
                // the snapshot, and each ledger entry with a frontier at its own key, may demote n
                let ends = s.ledger.iter().filter(|e| e.frontier.is_some()).map(|e| e.until);
                for q in ends.chain([s.point()]).filter(|q| *q > p) {
                    later.insert((q, n, t));
                }
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
