//! Chain certificates (spec/permissions.md §4): every held record on an edge between two
//! things on any path that ever existed from a node to a thing, every roster snapshot of those
//! things, closed under authors; and verification from certificates alone.
//!
//! "Ever existed" is over every edge any held write, roster or ledger tenure can set
//! (`Input::ever`) and owner links (`Input::ever_forward`, `ever_back`), whatever the walk
//! applied or when: a superset of the paths any walk of any round had at any point, so no
//! point and no replay is needed.

use crate::held::{HeldSet, MemoryHeldSet};
use crate::timeline::{At, Timeline};
use crate::types::{MembershipCommit, Point, RosterSnapshot, WriteId};
use osis_base::{CommitId, Role, Tid};
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

/// Held membership commits by the member and target of their edge writes and roster snapshots
/// by thing.
#[derive(Default)]
pub(crate) struct CertIndex {
    by_edge: BTreeMap<Tid, BTreeMap<Tid, Vec<Arc<MembershipCommit>>>>,
    by_thing: BTreeMap<Tid, Vec<Arc<RosterSnapshot>>>,
}

impl Timeline {
    fn cert_index(&self) -> &CertIndex {
        self.memo.certs.get_or_init(|| {
            let mut x = CertIndex::default();
            for cm in self.input.commits.values() {
                for o in &cm.ops {
                    x.by_edge.entry(o.member).or_default().entry(o.target).or_default().push(cm.clone());
                }
            }
            for s in self.input.snaps.values() {
                x.by_thing.entry(s.thing).or_default().push(s.clone());
            }
            x
        })
    }

    /// The chain certificates of `node` for writes on `thing` (§4).
    pub fn certificates(&self, node: &Tid, thing: &Tid) -> Certificates {
        self.closure(vec![(*node, *thing)])
    }

    /// What a verifier needs to judge edge write `id` as this timeline does: its author's
    /// chains to the target and to the member (a self-removal's authority) and the member's
    /// chain to the target with that edge's history.
    pub fn write_certificates(&self, id: &WriteId) -> Option<Certificates> {
        let (seeds, own) = match id {
            WriteId::Op(c, k) => {
                let cm = self.input.commits.get(c)?;
                let op = cm.ops.get(usize::try_from(*k).ok()?)?;
                (vec![(cm.author, op.target), (cm.author, op.member), (op.member, op.target)], cm.id)
            }
            WriteId::Snapshot(c) => {
                let s = self.input.snaps.get(c)?;
                (vec![(s.author, s.thing)], s.id)
            }
        };
        let mut out = self.closure(seeds);
        if self.input.commits.contains_key(&own) {
            out.commits.insert(own);
        } else if let Some(s) = self.input.snaps.get(&own) {
            out.snapshots.entry(own).or_default().extend(s.roster.keys().chain(s.ledger.iter().map(|t| &t.member)).copied());
        }
        Some(out)
    }

    fn closure(&self, seeds: Vec<(Tid, Tid)>) -> Certificates {
        let mut out = Certificates::default();
        let index = self.cert_index();
        let mut todo: BTreeSet<(Tid, Tid)> = seeds.into_iter().collect();
        let mut seen: BTreeSet<(Tid, Tid)> = BTreeSet::new();
        let mut ups: BTreeMap<Tid, BTreeSet<Tid>> = BTreeMap::new();
        let mut downs: BTreeMap<Tid, BTreeSet<Tid>> = BTreeMap::new();
        let mut on_paths: BTreeSet<Tid> = BTreeSet::new();
        let mut edges_in: BTreeSet<(Tid, Tid)> = BTreeSet::new();
        while let Some((n, t)) = todo.pop_first() {
            if !seen.insert((n, t)) {
                continue;
            }
            let up = ups.entry(n).or_insert_with(|| self.input.ever_forward([n]));
            let down = downs.entry(t).or_insert_with(|| self.input.ever_back([t]));
            let mut things: BTreeSet<Tid> = up.intersection(down).copied().collect();
            things.insert(n);
            things.insert(t);
            for c in &things {
                if !on_paths.insert(*c) {
                    continue;
                }
                // /created of each thing and of its owners up to the key actor
                out.created.insert(*c);
                let (up, top) = self.input.owners.chain(c);
                out.created.extend(up);
                out.created.extend(top);
                if self.input.owners.owner(c).is_some() {
                    out.keys.insert(*c);
                }
            }
            for (m, by_target) in things.iter().filter_map(|m| index.by_edge.get(m).map(|x| (*m, x))) {
                for (tg, ws) in by_target.iter().filter(|(tg, _)| things.contains(tg)) {
                    if !edges_in.insert((m, *tg)) {
                        continue;
                    }
                    for cm in ws {
                        if out.commits.insert(cm.id) {
                            for o in &cm.ops {
                                todo.insert((cm.author, o.target));
                                todo.insert((cm.author, o.member));
                            }
                        }
                    }
                }
            }
            for s in things.iter().filter_map(|x| index.by_thing.get(x)).flatten() {
                let members = s.roster.keys().chain(s.ledger.iter().map(|x| &x.member)).filter(|m| things.contains(m));
                out.snapshots.entry(s.id).or_default().extend(members);
                todo.insert((s.author, s.thing));
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
            if let Some(c) = self.input.commits.get(id) {
                h.add_commit((**c).clone());
            }
        }
        for (id, members) in &certs.snapshots {
            if let Some(s) = self.input.snaps.get(id) {
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
