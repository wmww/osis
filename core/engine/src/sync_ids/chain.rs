//! Chain certificates (spec/permissions.md §4): every held chained edge write between two things
//! on a path from a thing to a thing, closed under signers, read off the walk's chained-ness per
//! edge write (`osis_perm::Timeline::is_chained`) and the records.

use crate::engine::Core;
use osis_base::{CommitId, Tid};
use osis_perm::{RoleCommit, WriteId};
use std::collections::{BTreeMap, BTreeSet};

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

/// The chained edge writes held and the edges they set.
struct Index<'a> {
    core: &'a Core,
    /// Holder -> target -> the commits with a chained write on that edge.
    by_edge: BTreeMap<Tid, BTreeMap<Tid, Vec<&'a RoleCommit>>>,
    writes: BTreeSet<WriteId>,
    /// The edges chained writes set, both ways.
    targets: BTreeMap<Tid, BTreeSet<Tid>>,
    holders: BTreeMap<Tid, BTreeSet<Tid>>,
}

impl<'a> Index<'a> {
    /// Over every held edge write. O(the held edge writes).
    fn of(core: &'a Core) -> Index<'a> {
        let tl = core.timelines.unstamped();
        let mut x = Index { core, by_edge: BTreeMap::new(), writes: BTreeSet::new(), targets: BTreeMap::new(), holders: BTreeMap::new() };
        let things = tl.things();
        for t in things {
            for (w, c, op) in tl.held_on_owned(t) {
                if !tl.is_chained(&w) {
                    continue;
                }
                x.writes.insert(w);
                let on = x.by_edge.entry(op.holder).or_default().entry(op.target).or_default();
                if !on.iter().any(|l| l.id == c.id) {
                    on.push(c);
                }
                if op.edge.is_some_and(|e| !e.says_retain()) {
                    x.targets.entry(op.holder).or_default().insert(op.target);
                    x.holders.entry(op.target).or_default().insert(op.holder);
                }
            }
        }
        x
    }

    /// What `seeds` reach (`forward`) or what reaches them over record edges and the edges
    /// chained writes set.
    fn reach(&self, seeds: impl IntoIterator<Item = Tid>, forward: bool) -> BTreeSet<Tid> {
        let records = self.core.timelines.unstamped().records();
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

    /// The record chain and keys of each of `things`.
    fn records_of(&self, things: impl IntoIterator<Item = Tid>, out: &mut Certificates) {
        let records = self.core.timelines.unstamped().records();
        for c in things {
            out.created.extend(osis_base::record_chain(c, |x| records.link(x)).filter_map(|s| s.thing()));
            if records.link(&c).is_some() {
                out.keys.insert(c);
            }
        }
    }

    fn closure(&self, seeds: Vec<(Tid, Tid)>) -> Certificates {
        let mut out = Certificates::default();
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
            let up = ups.entry(n).or_insert_with(|| self.reach([n], true));
            let down = downs.entry(t).or_insert_with(|| self.reach([t], false));
            let mut things: BTreeSet<Tid> = up.intersection(down).copied().collect();
            things.insert(n);
            let fresh: Vec<Tid> = things.iter().copied().filter(|c| on_paths.insert(*c)).collect();
            self.records_of(fresh, &mut out);
            for (m, by_target) in things.iter().filter_map(|m| self.by_edge.get(m).map(|x| (*m, x))) {
                for (tg, ws) in things.iter().filter_map(|tg| by_target.get(tg).map(|ws| (tg, ws))) {
                    if !edges_in.insert((m, *tg)) {
                        continue;
                    }
                    for cm in ws {
                        if out.commits.insert(cm.id) {
                            for (k, o) in (0u32..).zip(&cm.ops) {
                                if self.writes.contains(&WriteId(cm.id, k)) {
                                    todo.insert((cm.signer, o.target));
                                    todo.insert((cm.signer, o.holder));
                                }
                            }
                        }
                    }
                }
            }
        }
        out
    }
}

/// The chain certificates of `node` for writes on `thing` (§4).
pub(crate) fn certificates(core: &Core, node: &Tid, thing: &Tid) -> Certificates {
    let out = Index::of(core).closure(vec![(*node, *thing)]);
    read(core, &[*thing], &out, Some(node));
    out
}

/// Stamps what certificates `out` for writes on `things` read: the held inputs of every thing
/// that ever reaches one of them (a path into it, and whether a write on it is chained, lie
/// within those) and of each thing whose record goes along; `node`'s too.
fn read(core: &Core, things: &[Tid], out: &Certificates, node: Option<&Tid>) {
    let into = core.ix.held.upstream(&things.iter().copied().collect());
    for t in into.iter().chain(&out.created).chain(node) {
        core.timelines.read_ever(t);
    }
}

/// Every thing's chain certificates for writes on `thing` (§4): the union of `certificates(n,
/// thing)` over each `n` that reaches it: one backward walk and the chained writes among what it
/// found, closed under signers (a signer on no path adds its own record and keys).
pub(crate) fn certificates_into(core: &Core, thing: &Tid) -> Certificates {
    let x = Index::of(core);
    let mut out = Certificates::default();
    let on = x.reach([*thing], false);
    let mut things: BTreeSet<Tid> = on.clone();
    for m in &on {
        let Some(by_target) = x.by_edge.get(m) else { continue };
        for (tg, ws) in by_target {
            if !on.contains(tg) {
                continue;
            }
            for cm in ws {
                out.commits.insert(cm.id);
                things.insert(cm.signer);
            }
        }
    }
    x.records_of(things, &mut out);
    read(core, &[*thing], &out, None);
    out
}

/// What a verifier needs to judge edge write `id` as this node does: its signer's chains to the
/// target and to the holder (a self-removal's authority) and the holder's chain to the target
/// with that edge's history.
pub(crate) fn write_certificates(core: &Core, id: &WriteId) -> Option<Certificates> {
    let (signer, holder, target) = core.timelines.unstamped().edge_op(id)?;
    let mut out = Index::of(core).closure(vec![(signer, target), (signer, holder), (holder, target)]);
    out.commits.insert(id.0);
    read(core, &[target, holder], &out, Some(&signer));
    Some(out)
}
