//! Chain certificates (spec/permissions.md §4): every held record on an edge between two
//! things on any path that ever existed from a node to a thing, closed under authors; and
//! verification from certificates alone.
//!
//! "Ever existed" is over every edge any held write or first admin record can set
//! (`Input::ever`) and record links (`Input::ever_forward`, `ever_back`), whatever the walk
//! applied or when: a superset of the paths any walk had at any point, so no point and no
//! replay is needed.

use crate::held::{HeldSet, MemoryHeldSet};
use crate::timeline::{At, Timeline};
use crate::types::{RoleCommit, Point, WriteId};
use osis_base::{CommitId, Role, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The certificate records of a chain.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Certificates {
    /// Things whose `created.0` record goes along.
    pub created: BTreeSet<Tid>,
    /// Role commits (edge writes) that go along whole.
    pub commits: BTreeSet<CommitId>,
    /// Actors whose current `keys.0` commit goes along.
    pub keys: BTreeSet<Tid>,
}

/// Held role commits by the holder and target of their edge writes.
#[derive(Default)]
pub(crate) struct CertIndex {
    by_edge: BTreeMap<Tid, BTreeMap<Tid, Vec<Arc<RoleCommit>>>>,
}

impl Timeline {
    fn cert_index(&self) -> &CertIndex {
        self.memo.certs.get_or_init(|| {
            let mut x = CertIndex::default();
            for cm in self.input.commits.values() {
                for o in &cm.ops {
                    x.by_edge.entry(o.holder).or_default().entry(o.target).or_default().push(cm.clone());
                }
            }
            x
        })
    }

    /// What `n` ever reaches: O(what it reaches) once while this timeline stands.
    fn forward_of(&self, n: &Tid) -> Arc<BTreeSet<Tid>> {
        if let Some(x) = self.memo.forward.lock().ok().and_then(|m| m.get(n).cloned()) {
            return x;
        }
        self.memo.forward_walks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let x = Arc::new(self.input.ever_forward([*n]));
        if let Ok(mut m) = self.memo.forward.lock() {
            m.insert(*n, x.clone());
        }
        x
    }

    /// The chain certificates of `node` for writes on `thing` (§4).
    pub fn certificates(&self, node: &Tid, thing: &Tid) -> Certificates {
        self.closure(vec![(*node, *thing)])
    }

    /// What a verifier needs to judge edge write `id` as this timeline does: its author's
    /// chains to the target and to the holder (a self-removal's authority) and the holder's
    /// chain to the target with that edge's history.
    pub fn write_certificates(&self, id: &WriteId) -> Option<Certificates> {
        let cm = self.input.commits.get(&id.0)?;
        let op = cm.ops.get(usize::try_from(id.1).ok()?)?;
        let mut out = self.closure(vec![(cm.author, op.target), (cm.author, op.holder), (op.holder, op.target)]);
        out.commits.insert(cm.id);
        Some(out)
    }

    fn closure(&self, seeds: Vec<(Tid, Tid)>) -> Certificates {
        let mut out = Certificates::default();
        let index = self.cert_index();
        let mut todo: BTreeSet<(Tid, Tid)> = seeds.into_iter().collect();
        let mut seen: BTreeSet<(Tid, Tid)> = BTreeSet::new();
        let mut ups: BTreeMap<Tid, Arc<BTreeSet<Tid>>> = BTreeMap::new();
        let mut downs: BTreeMap<Tid, BTreeSet<Tid>> = BTreeMap::new();
        let mut on_paths: BTreeSet<Tid> = BTreeSet::new();
        let mut edges_in: BTreeSet<(Tid, Tid)> = BTreeSet::new();
        while let Some((n, t)) = todo.pop_first() {
            if !seen.insert((n, t)) {
                continue;
            }
            let up = ups.entry(n).or_insert_with(|| self.forward_of(&n));
            let down = downs.entry(t).or_insert_with(|| self.input.ever_back([t]));
            let mut things: BTreeSet<Tid> = up.intersection(down).copied().collect();
            things.insert(n);
            things.insert(t);
            for c in &things {
                if !on_paths.insert(*c) {
                    continue;
                }
                // created.0 of each thing and of its records up to the top (or as far as a
                // verifier walks to find a chain too deep)
                out.created.extend(osis_base::record_chain(*c, |x| self.input.records.link(x)).filter_map(|s| s.thing()));
                if self.input.records.link(c).is_some() {
                    out.keys.insert(*c);
                }
            }
            for (m, by_target) in things.iter().filter_map(|m| index.by_edge.get(m).map(|x| (*m, x))) {
                // a holder's edges may be many, the things on these paths few
                for (tg, ws) in things.iter().filter_map(|tg| by_target.get(tg).map(|ws| (tg, ws))) {
                    if !edges_in.insert((m, *tg)) {
                        continue;
                    }
                    for cm in ws {
                        if out.commits.insert(cm.id) {
                            for o in &cm.ops {
                                todo.insert((cm.author, o.target));
                                todo.insert((cm.author, o.holder));
                            }
                        }
                    }
                }
            }
        }
        out
    }

    /// The certificate records as a held set; `created` supplies the creation records.
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
        h
    }
}

/// Verifies from certificates alone (§4) that `node`, a key actor whose tid commits to its
/// key, held `required` on `thing` just before `at`. The signature is the caller's.
pub fn verify(certs: &dyn HeldSet, node: &Tid, thing: &Tid, at: Point, required: Role) -> bool {
    let tl = Timeline::evaluate(certs);
    tl.records().is_key(node) && tl.role(node, thing, At::before(at)) >= Some(required)
}
