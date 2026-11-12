//! What the trees of a thing's held bodies and live states link (`Engine::tree_refs`): what a
//! dropped body's chunk is judged against (spec/sync.md §1, §7: a blob goes only when nothing held
//! links it; a reused chunk or a snapshot's value is in no chunk list of the bodies linking it).
//!
//! Each source's trees (a held commit's parts on the thing, an aspect's state) are a memo
//! (`Core::tree_refs`): read again only when its record, leftovers, header or state moved. Blob
//! presence has no stamp (issues/derived-state-recomputed.md, step 1): node blobs are immutable,
//! so a walk differs only where a node it lacked is held now, which each question checks of the
//! kept answer before asking.

use super::Tx;
use super::large::{Trees, links_in, tree_blobs};
use super::memo::Memo;
use super::records;
use crate::error::Result;
use osis_base::{Ak, BlobId, CommitId, Link, Tid};
use osis_crdt::Fragment;
use std::collections::BTreeSet;
use std::sync::Arc;

/// What a thing's trees are read from.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Source {
    State(Ak),
    Body(CommitId),
}

/// The trees of source `s` of thing `t`, through the node and page blobs held.
fn trees_of(tx: &mut Tx<'_>, t: &Tid, s: &Source) -> Result<Trees> {
    let Some(dedup) = tx.core.dedup(t) else { return Ok(Trees::default()) };
    let mut roots: Vec<Link> = Vec::new();
    match s {
        Source::State(ak) => {
            if let Some(v) = tx.state(t, ak)?.and_then(Fragment::read) {
                links_in(&v, &mut roots);
            }
        }
        Source::Body(c) => {
            let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(Trees::default()) };
            let on: Vec<usize> = m.header.aspects.iter().enumerate().filter(|(ai, a)| a.tid == *t && m.holds(*ai)).map(|(ai, _)| ai).collect();
            crate::costs::count("tree refs: parts read", on.len() as u64);
            for ai in on {
                roots.extend(crate::retention::freed::part_links(tx, c, ai)?);
            }
        }
    }
    roots.sort_unstable_by_key(|l| l.blob);
    roots.dedup();
    let mut out = Trees::default();
    tree_blobs(tx, &dedup, &roots, &mut out)?;
    crate::costs::count("tree refs: tree blobs", out.blobs.len() as u64);
    Ok(out)
}

/// Every source of thing `t`: each aspect with a state or a held commit, each commit held on it
/// unless `states` (the states alone).
fn sources(tx: &mut Tx<'_>, t: &Tid, states: bool) -> Result<BTreeSet<Source>> {
    let mut out = BTreeSet::new();
    let prefix = [records::ASPECTS, t.as_bytes()].concat();
    tx.scan(&prefix, |k, _| {
        out.insert(Source::State(records::Rd::new(k).ak()?));
        Ok(())
    })?;
    for ((_, ak), cs) in tx.core.aspects_of(t) {
        out.insert(Source::State(ak.clone()));
        if !states {
            out.extend(cs.iter().map(|(_, c)| Source::Body(*c)));
        }
    }
    Ok(out)
}

/// The answer from each source's trees (`trees`): the blobs among `blobs` one links, and the
/// node blobs they lack.
fn answer(trees: impl IntoIterator<Item = Arc<Trees>>, blobs: &BTreeSet<BlobId>) -> Trees {
    let mut out = Trees::default();
    for x in trees {
        out.blobs.extend(blobs.iter().filter(|b| x.blobs.contains(b)));
        out.missing.extend(x.missing.iter().copied());
    }
    out
}

/// `Engine::tree_refs` in transaction `tx`.
pub(crate) fn tree_refs_in(tx: &mut Tx<'_>, t: &Tid, blobs: &BTreeSet<BlobId>) -> Result<Trees> {
    refs_in(tx, t, blobs, false, &|_| false)
}

/// `tree_refs_in` of the sources of `t` but those `gone` names (lost access: the forgotten
/// aspects' states and bodies, still indexed while the forget runs, `retention::freed::lost`).
pub(crate) fn kept_refs_in(tx: &mut Tx<'_>, t: &Tid, blobs: &BTreeSet<BlobId>, gone: &dyn Fn(&Source) -> bool) -> Result<Trees> {
    refs_in(tx, t, blobs, false, gone)
}

/// Every source of thing `t`, states and bodies.
pub(crate) fn sources_of(tx: &mut Tx<'_>, t: &Tid) -> Result<BTreeSet<Source>> {
    sources(tx, t, false)
}

/// `tree_refs_in` of the live states of `t` alone: what a drop of every body linking the rest
/// would leave linked (the compaction trigger's weighing, `retention::compact`).
pub(crate) fn state_refs_in(tx: &mut Tx<'_>, t: &Tid, blobs: &BTreeSet<BlobId>) -> Result<Trees> {
    refs_in(tx, t, blobs, true, &|_| false)
}

fn refs_in(tx: &mut Tx<'_>, t: &Tid, blobs: &BTreeSet<BlobId>, states: bool, gone: &dyn Fn(&Source) -> bool) -> Result<Trees> {
    let t = *t;
    let mut got = Vec::new();
    for s in sources(tx, &t, states)?.into_iter().filter(|s| !gone(s)) {
        let k = (t, s);
        // a node a kept walk lacked, held now
        if let Some(x) = tx.core.tree_refs.held(&k) {
            for b in &x.missing {
                if tx.blobs.held(b)? {
                    tx.core.tree_refs.forget(&k);
                    break;
                }
            }
        }
        got.push(Memo::get_in(tx, |tx| &tx.core.tree_refs, &k, |tx| trees_of(tx, &k.0, &k.1).map(Arc::new))?);
    }
    let out = answer(got, blobs);
    // debug builds, at every question: a kept answer that differs from a fresh read leaves
    // a linked chunk unprotected (questions come with dropped chunks, rarely)
    #[cfg(debug_assertions)]
    {
        let fresh = crate::costs::paused(|| {
            crate::engine::memo::unrecorded(|| -> Result<Trees> {
                let mut all = Vec::new();
                for s in sources(tx, &t, states)?.into_iter().filter(|s| !gone(s)) {
                    all.push(Arc::new(trees_of(tx, &t, &s)?));
                }
                Ok(answer(all, blobs))
            })
        })?;
        assert_eq!(out, fresh, "tree refs of {t:?} kept apart from a fresh read");
    }
    Ok(out)
}

impl super::Engine {
    /// The blobs among `blobs` that a tree of `tid`'s live states or of a body held on it links
    /// (deltas, snapshots, leftovers), and the node blobs those trees link and this node does not
    /// hold (`missing`: what lies below them is unknown until they are fetched). Costs a memo hit
    /// per source and a lookup per blob, plus a read of each source that moved.
    pub fn tree_refs(&mut self, tid: &Tid, blobs: &BTreeSet<BlobId>) -> Result<Trees> {
        self.run(|tx| tree_refs_in(tx, tid, blobs))
    }
}
