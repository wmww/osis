//! What the trees of a thing's held bodies and live states link (`Engine::tree_refs`): what a
//! dropped body's chunk is judged against (spec/sync.md §1, §7: a blob goes only when nothing held
//! links it; a reused chunk or a snapshot's value is in no chunk list of the bodies linking it).
//!
//! Kept per thing once asked, by source (a held commit's parts on the thing, an aspect's state),
//! with a count per blob of the sources whose trees hold it, so a question costs a lookup per
//! blob asked plus the sources changed since the last. A source goes stale where what it reads
//! changes: its commit's record or leftovers written (`Tx::put_commit`, `Tx::remove_commit`,
//! `leftover`), its state written (`Core::wrote`, `Core::state_changed`), a node blob its walk
//! lacked now held (checked at each question), the thing's dedup secret changed (rebuilt). Only
//! answers from committed data are kept: a question is a transaction of its own that writes
//! nothing, and a mark from a rolled back transaction stays (one extra walk).

use super::large::{Trees, links_in, tree_blobs};
use super::{Engine, Tx, records};
use crate::error::Result;
use osis_base::{Ak, BlobId, CommitId, Link, Tid};
use osis_crdt::Fragment;
use osis_crypto::Secret32;
use std::collections::{BTreeMap, BTreeSet};

/// `Engine::tree_refs` per thing asked (`Core::tree_refs`).
#[derive(Clone, Debug, Default)]
pub struct TreeRefs {
    things: BTreeMap<Tid, ThingRefs>,
    /// The kept things each commit's trees count toward.
    by_commit: BTreeMap<CommitId, BTreeSet<Tid>>,
}

/// What a thing's trees are read from.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Source {
    State(Ak),
    Body(CommitId),
}

#[derive(Clone, Debug)]
struct ThingRefs {
    /// The dedup secret the trees were verified with.
    dedup: Secret32,
    /// Each source's trees, where they link anything.
    trees: BTreeMap<Source, Trees>,
    /// How many sources' trees hold each blob.
    refs: BTreeMap<BlobId, u32>,
    /// Sources whose trees lack a node blob.
    incomplete: BTreeSet<Source>,
    /// Sources changed since their trees were read.
    stale: BTreeSet<Source>,
    /// Questions answered (debug builds compare the kept answer with a fresh one at 1, 4, 16, ...).
    asked: u64,
}

impl ThingRefs {
    fn new(dedup: Secret32) -> Self {
        ThingRefs { dedup, trees: BTreeMap::new(), refs: BTreeMap::new(), incomplete: BTreeSet::new(), stale: BTreeSet::new(), asked: 0 }
    }

    /// Sets `s`'s trees (empty: it links nothing).
    fn set(&mut self, s: Source, t: Trees) {
        if let Some(old) = self.trees.remove(&s) {
            for b in &old.blobs {
                if let Some(n) = self.refs.get_mut(b) {
                    *n -= 1;
                    if *n == 0 {
                        self.refs.remove(b);
                    }
                }
            }
        }
        self.incomplete.remove(&s);
        if t.blobs.is_empty() && t.missing.is_empty() {
            return;
        }
        for b in &t.blobs {
            *self.refs.entry(*b).or_default() += 1;
        }
        if !t.missing.is_empty() {
            self.incomplete.insert(s.clone());
        }
        self.trees.insert(s, t);
    }
}

impl TreeRefs {
    /// Commit `c`'s record or a leftover of it was written or removed; `things`: those its
    /// header names (for a record written).
    pub(crate) fn record_moved(&mut self, c: &CommitId, things: impl IntoIterator<Item = Tid>) {
        if self.things.is_empty() {
            return;
        }
        let mut ts: BTreeSet<Tid> = things.into_iter().collect();
        ts.extend(self.by_commit.get(c).into_iter().flatten().copied());
        for t in ts {
            if let Some(x) = self.things.get_mut(&t) {
                x.stale.insert(Source::Body(*c));
            }
        }
    }

    /// The state of `(t, ak)` was written.
    pub(crate) fn state_moved(&mut self, t: &Tid, ak: &Ak) {
        if let Some(x) = self.things.get_mut(t) {
            x.stale.insert(Source::State(ak.clone()));
        }
    }

    fn set(&mut self, t: Tid, s: Source, trees: Trees) {
        let Some(x) = self.things.get_mut(&t) else { return };
        if let Source::Body(c) = &s {
            let linked = !trees.blobs.is_empty() || !trees.missing.is_empty();
            match (linked, self.by_commit.get_mut(c)) {
                (true, Some(ts)) => {
                    ts.insert(t);
                }
                (true, None) => {
                    self.by_commit.insert(*c, BTreeSet::from([t]));
                }
                (false, Some(ts)) => {
                    ts.remove(&t);
                    if ts.is_empty() {
                        self.by_commit.remove(c);
                    }
                }
                (false, None) => {}
            }
        }
        x.set(s, trees);
    }
}

/// The trees of source `s` of thing `t`, through the node and page blobs held.
fn trees_of(tx: &mut Tx<'_>, t: &Tid, dedup: &Secret32, s: &Source) -> Result<Trees> {
    let mut roots: Vec<Link> = Vec::new();
    match s {
        Source::State(ak) => {
            if let Some(v) = tx.state(t, ak)?.and_then(Fragment::read) {
                links_in(&v, &mut roots);
            }
        }
        Source::Body(c) => {
            let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(Trees::default()) };
            let on = |ai: usize| h.aspects.get(ai).is_some_and(|a| a.tid == *t);
            let parts = crate::apply::held_parts_at(tx, c, &on)?;
            crate::costs::count("tree refs: parts read", parts.len() as u64);
            for (_, d) in parts {
                d.fragment().values(&mut |v| links_in(v, &mut roots));
            }
        }
    }
    roots.sort_unstable_by_key(|l| l.blob);
    roots.dedup();
    let mut out = Trees::default();
    tree_blobs(tx, dedup, &roots, &mut out)?;
    crate::costs::count("tree refs: tree blobs", out.blobs.len() as u64);
    Ok(out)
}

/// Every source of thing `t`: each aspect with a state or a held commit, each commit held on it.
fn sources(tx: &mut Tx<'_>, t: &Tid) -> Result<BTreeSet<Source>> {
    let mut out = BTreeSet::new();
    let prefix = [records::ASPECTS, t.as_bytes()].concat();
    tx.scan(&prefix, |k, _| {
        out.insert(Source::State(records::Rd::new(k).ak()?));
        Ok(())
    })?;
    for ((_, ak), cs) in tx.core.aspects_of(t) {
        out.insert(Source::State(ak.clone()));
        out.extend(cs.iter().map(|(_, c)| Source::Body(*c)));
    }
    Ok(out)
}

/// Every source's trees, read fresh.
fn fresh(tx: &mut Tx<'_>, t: &Tid, dedup: &Secret32) -> Result<BTreeMap<Source, Trees>> {
    let mut out = BTreeMap::new();
    for s in sources(tx, t)? {
        let x = trees_of(tx, t, dedup, &s)?;
        out.insert(s, x);
    }
    Ok(out)
}

impl Engine {
    /// The blobs among `blobs` that a tree of `tid`'s live states or of a body held on its
    /// aspects links (deltas, snapshots, leftovers), and the node blobs those trees link and this
    /// node does not hold (`missing`: what lies below them is unknown until they are fetched).
    /// Costs a lookup per blob plus the sources changed since the last question (`TreeRefs`);
    /// the first question about a thing reads every source.
    pub fn tree_refs(&mut self, tid: &Tid, blobs: &BTreeSet<BlobId>) -> Result<Trees> {
        let t = *tid;
        self.run(|tx| {
            let Some(dedup) = tx.core.dedup(&t) else {
                tx.core.tree_refs.things.remove(&t);
                return Ok(Trees::default());
            };
            let kept = tx.core.tree_refs.things.get(&t).filter(|x| x.dedup == dedup);
            let todo: Option<BTreeSet<Source>> = match kept {
                None => None,
                Some(x) => {
                    let mut todo = x.stale.clone();
                    // a node blob a walk lacked, held now
                    for s in &x.incomplete {
                        if !todo.contains(s) && x.trees.get(s).into_iter().flat_map(|y| &y.missing).try_fold(false, |a, b| Ok::<_, crate::error::Error>(a || tx.blobs.held(b)?))? {
                            todo.insert(s.clone());
                        }
                    }
                    Some(todo)
                }
            };
            match todo {
                None => {
                    let all = fresh(tx, &t, &dedup)?;
                    for c in tx.core.tree_refs.things.get(&t).into_iter().flat_map(|x| x.trees.keys()).filter_map(|s| if let Source::Body(c) = s { Some(*c) } else { None }).collect::<Vec<_>>() {
                        tx.core.tree_refs.set(t, Source::Body(c), Trees::default());
                    }
                    tx.core.tree_refs.things.insert(t, ThingRefs::new(dedup.clone()));
                    for (s, x) in all {
                        tx.core.tree_refs.set(t, s, x);
                    }
                }
                Some(todo) => {
                    let mut got = Vec::new();
                    for s in &todo {
                        got.push((s.clone(), trees_of(tx, &t, &dedup, s)?));
                    }
                    for (s, x) in got {
                        tx.core.tree_refs.set(t, s, x);
                    }
                    if let Some(x) = tx.core.tree_refs.things.get_mut(&t) {
                        x.stale.retain(|s| !todo.contains(s));
                    }
                }
            }
            #[cfg(debug_assertions)]
            check(tx, &t, &dedup)?;
            let Some(x) = tx.core.tree_refs.things.get(&t) else { return Ok(Trees::default()) };
            Ok(Trees {
                blobs: blobs.iter().filter(|b| x.refs.contains_key(b)).copied().collect(),
                missing: x.incomplete.iter().filter_map(|s| x.trees.get(s)).flat_map(|y| y.missing.iter().copied()).collect(),
            })
        })
    }
}

/// Debug builds, at the 1st, 4th, 16th, ... question about a thing: the kept trees are what a
/// fresh read gives (a source changed with no mark leaves a chunk it links unprotected).
#[cfg(debug_assertions)]
fn check(tx: &mut Tx<'_>, t: &Tid, dedup: &Secret32) -> Result<()> {
    let Some(x) = tx.core.tree_refs.things.get_mut(t) else { return Ok(()) };
    x.asked += 1;
    if !x.asked.is_power_of_two() || x.asked.trailing_zeros() % 2 != 0 {
        return Ok(());
    }
    let all = crate::costs::paused(|| crate::engine::memo::unrecorded(|| fresh(tx, t, dedup)))?;
    let all: BTreeMap<Source, Trees> = all.into_iter().filter(|(_, y)| !y.blobs.is_empty() || !y.missing.is_empty()).collect();
    let Some(x) = tx.core.tree_refs.things.get(t) else { return Ok(()) };
    assert_eq!(x.trees, all, "tree refs of {t:?} kept apart from a fresh read");
    Ok(())
}
