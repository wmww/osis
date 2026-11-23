//! Chain certificates (Interim (issues/chains-retired.md)): every held chained edge write between two things
//! on a path from a thing to a thing, closed under signers, read off the walk's chained-ness per
//! edge write (`osis_perm::Timeline::is_chained`) and the records. Interim (issues/stated-path-certificates.md): along the stated
//! path alone.

use crate::engine::Core;
use osis_base::{CommitId, Tid};
use osis_perm::{EdgeOp, RoleCommit, Timeline, WriteId};
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

/// The chained edge writes held and the edges they set, read off the timeline by target as a
/// search reaches each thing: a certificate costs the things on its paths, not the held set.
struct Index<'a> {
    tl: &'a Timeline,
}

impl<'a> Index<'a> {
    fn of(core: &'a Core) -> Index<'a> {
        Index { tl: core.timelines().unstamped() }
    }

    /// The chained edge writes held on `t`.
    fn chained_on(&self, t: Tid) -> impl Iterator<Item = (WriteId, &'a RoleCommit, &'a EdgeOp)> + 'a {
        let tl = self.tl;
        tl.held_on_owned(t).filter(move |(w, _, _)| tl.is_chained(w))
    }

    /// The holders of the edges into `t` that chained writes set.
    fn holders(&self, t: Tid) -> impl Iterator<Item = Tid> + 'a {
        self.chained_on(t).filter(|(_, _, op)| op.edge.is_some_and(|e| !e.says_retain())).map(|(_, _, op)| op.holder)
    }

    /// What reaches `seeds` over record edges and the edges chained writes set.
    fn reach(&self, seeds: impl IntoIterator<Item = Tid>) -> BTreeSet<Tid> {
        let records = self.tl.records();
        let mut seen: BTreeSet<Tid> = seeds.into_iter().collect();
        let mut stack: Vec<Tid> = seen.iter().copied().collect();
        while let Some(e) = stack.pop() {
            let next: Vec<Tid> = records.mint_admin(&e).into_iter().chain(self.holders(e)).collect();
            for y in next {
                if seen.insert(y) {
                    stack.push(y);
                }
            }
        }
        seen
    }

    /// What lies on a path from `n` to a thing `t` (`down`: `reach([t])`): what `n` reaches of
    /// `down`, `n` among it. A thing on such a path reaches that thing, so the
    /// search stays inside `down`, walked by its members' own edges: O(`down`), not O(what `n`
    /// reaches), which for an account root is every thing it minted.
    fn between(&self, n: Tid, down: &BTreeSet<Tid>) -> BTreeSet<Tid> {
        let records = self.tl.records();
        let mut next: BTreeMap<Tid, Vec<Tid>> = BTreeMap::new();
        for y in down {
            for p in records.mint_admin(y).into_iter().chain(self.holders(*y)) {
                if down.contains(&p) {
                    next.entry(p).or_default().push(*y);
                }
            }
        }
        let mut seen = BTreeSet::from([n]);
        let mut stack = vec![n];
        while let Some(e) = stack.pop() {
            for y in next.get(&e).into_iter().flatten() {
                if seen.insert(*y) {
                    stack.push(*y);
                }
            }
        }
        seen
    }

    /// The record chain and keys of each of `things`.
    fn records_of(&self, things: impl IntoIterator<Item = Tid>, out: &mut Certificates) {
        let records = self.tl.records();
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
        let mut downs: BTreeMap<Tid, BTreeSet<Tid>> = BTreeMap::new();
        let mut on_paths: BTreeSet<Tid> = BTreeSet::new();
        while let Some((n, t)) = todo.pop_first() {
            if !seen.insert((n, t)) {
                continue;
            }
            let down = downs.entry(t).or_insert_with(|| self.reach([t]));
            let things = self.between(n, down);
            let fresh: Vec<Tid> = things.iter().copied().filter(|c| on_paths.insert(*c)).collect();
            self.records_of(fresh, &mut out);
            // the commits with a chained write on an edge between two of them, each taken once
            // (every op of a held role commit is held on its target)
            for tg in &things {
                for (_, cm, _) in self.chained_on(*tg).filter(|(_, _, op)| things.contains(&op.holder)) {
                    if out.commits.insert(cm.id) {
                        for (k, o) in (0u32..).zip(&cm.ops) {
                            if self.tl.is_chained(&WriteId(cm.id, k)) {
                                todo.insert((cm.signer, o.target));
                                todo.insert((cm.signer, o.holder));
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
        core.timelines().read_ever(t);
    }
}

/// Every thing's chain certificates for writes on `thing` (§4): the union of `certificates(n,
/// thing)` over each `n` that reaches it: one backward walk and the chained writes among what it
/// found, closed under signers (a signer on no path adds its own record and keys).
pub(crate) fn certificates_into(core: &Core, thing: &Tid) -> Certificates {
    let x = Index::of(core);
    let mut out = Certificates::default();
    let on = x.reach([*thing]);
    let mut things: BTreeSet<Tid> = on.clone();
    for tg in &on {
        for (_, cm, _) in x.chained_on(*tg).filter(|(_, _, op)| on.contains(&op.holder)) {
            out.commits.insert(cm.id);
            things.insert(cm.signer);
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
    let (signer, holder, target) = core.timelines().unstamped().edge_op(id)?;
    let mut out = Index::of(core).closure(vec![(signer, target), (signer, holder), (holder, target)]);
    out.commits.insert(id.0);
    read(core, &[target, holder], &out, Some(&signer));
    Some(out)
}
