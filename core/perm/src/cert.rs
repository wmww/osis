//! Chain certificates (spec/permissions.md §4): every held chained edge write between two
//! things on any path from a node to a thing, closed under authors; and verification from
//! certificates alone.
//!
//! A write is chained when its author could have had the authority it needs, over record edges
//! and the edges chained writes before it set, applied or not, never removed (`Chained`): a
//! superset of the paths any walk had at any point (every applied write is chained: its
//! authority runs over edges earlier applied writes set), so no point and no replay is needed;
//! a function of the held set alone, which only grows with it (an earlier write only adds
//! edges); and holding no write of an author no record or chained write gave authority, so no
//! such author makes honest nodes log another actor's roster.

use crate::graph::Records;
use crate::held::{HeldSet, MemoryHeldSet};
use crate::timeline::{At, Timeline};
use crate::types::{EdgeOp, RoleCommit, Point, WriteId};
use crate::walk::Input;
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

/// The chained edge writes (spec/permissions.md §4) and the edges they set.
#[derive(Clone, Default)]
pub(crate) struct CertIndex {
    /// Commits with a chained write, by the holder and target of that write.
    by_edge: BTreeMap<Tid, BTreeMap<Tid, Vec<Arc<RoleCommit>>>>,
    writes: BTreeSet<WriteId>,
    /// The edges chained writes set: holder to targets, target to holders.
    targets: BTreeMap<Tid, BTreeSet<Tid>>,
    holders: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Target to the holders of an admin edge a chained write set (`crate::trust`, who a
    /// demotion demotes).
    pub(crate) admins: BTreeMap<Tid, BTreeSet<Tid>>,
}

/// The edges chained writes on their targets set, by target: the holders whose edge some such
/// write set at each role or above (`Role` order), and those some such write gave an invite.
#[derive(Default)]
struct Chained {
    at: BTreeMap<(Tid, Role), BTreeSet<Tid>>,
    invites: BTreeMap<Tid, BTreeSet<Tid>>,
}

impl Chained {
    fn add(&mut self, holder: Tid, target: Tid, role: Role, invite: bool) {
        for r in [Role::Sync, Role::Read, Role::Write, Role::Admin].into_iter().filter(|r| *r <= role) {
            self.at.entry((target, r)).or_default().insert(holder);
        }
        if invite {
            self.invites.entry(target).or_default().insert(holder);
        }
    }

    /// Whether `a` is one of `from` or reaches one over record edges and edges at `min` or above.
    fn reaches(&self, records: &Records, a: &Tid, from: impl IntoIterator<Item = Tid>, min: Role) -> bool {
        let mut seen: BTreeSet<Tid> = from.into_iter().collect();
        let mut stack: Vec<Tid> = seen.iter().copied().collect();
        while let Some(x) = stack.pop() {
            count_chain_step();
            if x == *a {
                return true;
            }
            for y in records.mint_admin(&x).into_iter().chain(self.at.get(&(x, min)).into_iter().flatten().copied()) {
                if seen.insert(y) {
                    stack.push(y);
                }
            }
        }
        false
    }

    /// The authority `a` could have had for `op` (§2, §5.1 step 2): `Some(true)` on its target
    /// (admin, or an invite for a grant), so the write sets its edge here; `Some(false)` admin
    /// on its holder (a self-removal) or, for a removal, write on its target (a finalize), which
    /// only lower an edge some write on the target set; `None` none.
    fn could(&self, records: &Records, a: &Tid, op: &EdgeOp) -> Option<bool> {
        if op.holder == op.target {
            return None;
        }
        let removal = op.edge.as_ref().is_none_or(|e| e.says_retain());
        let invited = || !removal && self.reaches(records, a, self.invites.get(&op.target).into_iter().flatten().copied(), Role::Sync);
        if self.reaches(records, a, [op.target], Role::Admin) || invited() {
            return Some(true);
        }
        (self.reaches(records, a, [op.holder], Role::Admin) || (removal && self.reaches(records, a, [op.target], Role::Write))).then_some(false)
    }
}

impl CertIndex {
    /// The chained writes of `input`, in one pass in timeline order (§5.1 step 1): each write
    /// whose author could have had the authority it needs over the edges chained writes of
    /// earlier commits set (`could`). O(edge writes × what a search from a target visits).
    pub(crate) fn of(input: &Input) -> CertIndex {
        let mut list: Vec<&Arc<RoleCommit>> = input.commits.values().collect();
        list.sort_by_key(|c| c.point());
        let (mut g, mut x) = (Chained::default(), CertIndex::default());
        for c in list {
            // each write against the edges before its commit (§5.1 step 4)
            let judged: Vec<(WriteId, &EdgeOp, bool)> = c
                .ops
                .iter()
                .enumerate()
                .filter_map(|(k, op)| Some((WriteId(c.id, u32::try_from(k).ok()?), op, g.could(&input.records, &c.author, op)?)))
                .collect();
            for (id, op, sets) in judged {
                x.writes.insert(id);
                let on = x.by_edge.entry(op.holder).or_default().entry(op.target).or_default();
                if on.last().is_none_or(|l| l.id != c.id) {
                    on.push(c.clone());
                }
                if let (true, Some(e)) = (sets, &op.edge) {
                    g.add(op.holder, op.target, e.role, e.invite.is_some());
                    x.targets.entry(op.holder).or_default().insert(op.target);
                    x.holders.entry(op.target).or_default().insert(op.holder);
                    if e.role == Role::Admin {
                        x.admins.entry(op.target).or_default().insert(op.holder);
                    }
                }
            }
        }
        x
    }

    /// What any of `seeds` (included) reaches (`forward`) or is reached by over record edges
    /// and the edges chained writes set.
    pub(crate) fn reach(&self, records: &Records, seeds: impl IntoIterator<Item = Tid>, forward: bool) -> BTreeSet<Tid> {
        let mut seen: BTreeSet<Tid> = seeds.into_iter().collect();
        let mut stack: Vec<Tid> = seen.iter().copied().collect();
        while let Some(e) = stack.pop() {
            let next: Vec<Tid> = if forward {
                records.mint_admin_of(&e).iter().chain(self.targets.get(&e).into_iter().flatten()).copied().collect()
            } else {
                records.mint_admin(&e).into_iter().chain(self.holders.get(&e).into_iter().flatten().copied()).collect()
            };
            for y in next {
                if seen.insert(y) {
                    stack.push(y);
                }
            }
        }
        seen
    }
}

#[cfg(debug_assertions)]
thread_local! {
    /// Things the chained-write searches visited on this thread (`chain_steps`).
    static CHAIN_STEPS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn count_chain_step() {
    #[cfg(debug_assertions)]
    CHAIN_STEPS.with(|m| m.set(m.get() + 1));
}

/// Things the chained-write searches (`CertIndex::of`) on this thread visited so far (scale
/// checks). Debug builds only, as `commits_walked`.
#[doc(hidden)]
#[allow(clippy::panic)]
pub fn chain_steps() -> u64 {
    #[cfg(debug_assertions)]
    return CHAIN_STEPS.with(|m| m.get());
    #[cfg(not(debug_assertions))]
    panic!("chain_steps counts in debug builds only");
}

impl Timeline {
    /// The chained writes of this timeline's held set, once while it stands.
    pub(crate) fn cert_index(&self) -> &Arc<CertIndex> {
        self.memo.certs.get_or_init(|| Arc::new(CertIndex::of(&self.input)))
    }

    /// Whether `w` is a chained write (§4).
    #[doc(hidden)]
    pub fn is_chained(&self, w: &WriteId) -> bool {
        self.cert_index().writes.contains(w)
    }

    /// What `n` reaches over chained edges: O(what it reaches) once while this timeline stands.
    fn forward_of(&self, n: &Tid) -> Arc<BTreeSet<Tid>> {
        if let Some(x) = self.memo.forward.lock().ok().and_then(|m| m.get(n).cloned()) {
            return x;
        }
        self.memo.forward_walks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let x = Arc::new(self.cert_index().reach(&self.input.records, [*n], true));
        // counted: tests read how much a chain walk reaches
        osis_base::costs::count("perm: chain reach walked", x.len() as u64);
        if let Ok(mut m) = self.memo.forward.lock() {
            m.insert(*n, x.clone());
        }
        x
    }

    /// The chain certificates of `node` for writes on `thing` (§4): once per pair while this
    /// timeline stands.
    pub fn certificates(&self, node: &Tid, thing: &Tid) -> Certificates {
        let key = (*node, *thing);
        if let Some(x) = self.memo.certificates.lock().ok().and_then(|m| m.get(&key).cloned()) {
            return x;
        }
        let x = self.closure(vec![key]);
        if let Ok(mut m) = self.memo.certificates.lock() {
            m.insert(key, x.clone());
        }
        x
    }

    /// Every actor's chain certificates for writes on any of `targets` (§4): the union of
    /// `certificates(n, t)` over each `t` and each `n` that reaches it. The things on those
    /// paths are exactly what reaches a target, so this is one backward walk and the chained
    /// writes among what it found, closed under authors (an author on no path adds its own record
    /// and keys). O(what reaches the targets and the edge writes among it).
    pub fn certificates_into(&self, targets: &BTreeSet<Tid>) -> Certificates {
        let mut out = Certificates::default();
        let index = self.cert_index();
        let on = index.reach(&self.input.records, targets.iter().copied(), false);
        let mut things: BTreeSet<Tid> = on.clone();
        for m in &on {
            let Some(by_target) = index.by_edge.get(m) else { continue };
            for (tg, ws) in by_target {
                if !on.contains(tg) {
                    continue;
                }
                for cm in ws {
                    out.commits.insert(cm.id);
                    things.insert(cm.author);
                }
            }
        }
        for c in &things {
            out.created.extend(osis_base::record_chain(*c, |x| self.input.records.link(x)).filter_map(|s| s.thing()));
            if self.input.records.link(c).is_some() {
                out.keys.insert(*c);
            }
        }
        out
    }

    /// Every thing that reaches `thing` over any held edge write, `thing` included: a superset of
    /// what `certificates(_, thing)` and `certificates_into` of it read (the held inputs of these
    /// and the records of what they name): a path into `thing`, and whether a write on it is
    /// chained, lie within it.
    pub fn ever_into(&self, thing: &Tid) -> BTreeSet<Tid> {
        self.input.ever_back([*thing])
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
            let down = downs.entry(t).or_insert_with(|| index.reach(&self.input.records, [t], false));
            // the things on its paths to `t` (none when it reaches no `t`: nothing of `t` goes)
            // and itself
            let mut things: BTreeSet<Tid> = up.intersection(down).copied().collect();
            things.insert(n);
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
                            for (k, o) in cm.ops.iter().enumerate() {
                                if u32::try_from(k).is_ok_and(|k| index.writes.contains(&WriteId(cm.id, k))) {
                                    todo.insert((cm.author, o.target));
                                    todo.insert((cm.author, o.holder));
                                }
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
/// key, held `required` on `thing` just before its commit at `at` (at the start of its `ts`,
/// §5.2 Position). The signature is the caller's.
pub fn verify(certs: &dyn HeldSet, node: &Tid, thing: &Tid, at: Point, required: Role) -> bool {
    let tl = Timeline::evaluate(certs);
    tl.records().is_key(node) && tl.role(node, thing, At::before(Point::start(at.ts))) >= Some(required)
}
