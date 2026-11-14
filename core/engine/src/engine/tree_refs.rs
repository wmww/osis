//! What the trees of a thing's held bodies and live states link (`Engine::tree_refs`): what a
//! dropped body's chunk is judged against (spec/sync.md §1, §7: a blob goes only when nothing held
//! links it, by any body or state of its thing: a reused chunk or a snapshot's value included).
//!
//! Kept by what moved, never walked whole (`Reach`, per thing: one over its live states, one over
//! its held bodies): a count per link (by what opens it: blob, hash, key) of the times it is
//! linked, from a source's roots and from the nodes counted (a node's links count while it does). Each source's roots (the links its values
//! hold) are a memo (`Core::tree_roots`), read again only when its record, leftovers, header or
//! state moved; a question first counts each source whose roots moved since they were counted:
//! the roots it linked and unlinked, and below them only the nodes counted for the first time or
//! no longer (a node is immutable, so an unchanged subtree's count moves only at its top). So an
//! edit costs a question its changed tree path and a memo hit per source, whatever the value's
//! size. A node not held when counted is `missing` until it is, checked at each question.
//!
//! Debug builds compare every answer with a fresh walk of every source (`walked`), which is also
//! the rare lost-access question's answer (`kept_refs_in`).

use super::Tx;
use super::blobs::TxBlobs;
use super::large::{Trees, below, links_in, tree_blobs};
use osis_base::memo::Memo;
use super::records;
use crate::error::{Error, Result};
use osis_base::{Ak, BlobId, CommitId, Link, Tid};
use osis_crdt::Fragment;
use osis_crypto::Secret32;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

/// What a thing's trees are read from.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Source {
    State(Ak),
    Body(CommitId),
}

/// The roots of source `s` of thing `t`: the links its values hold.
fn roots_of(tx: &mut Tx<'_>, t: &Tid, s: &Source) -> Result<Vec<Link>> {
    let mut roots: Vec<Link> = Vec::new();
    match s {
        Source::State(ak) => {
            if let Some(v) = tx.state(t, ak)?.and_then(Fragment::read) {
                links_in(&v, &mut roots);
            }
        }
        Source::Body(c) => {
            let Some(on) = tx.core.ix.commits.get(c).map(|m| m.view.aspects_on(t).filter(|ai| m.holds(*ai)).collect::<Vec<usize>>()) else { return Ok(roots) };
            osis_base::costs::count("tree refs: parts read", on.len() as u64);
            for ai in on {
                roots.extend(crate::retention::freed::part_links(tx, c, ai)?);
            }
        }
    }
    roots.sort_unstable_by_key(|l| l.blob);
    roots.dedup();
    Ok(roots)
}

/// The trees of source `s` of thing `t`, walked whole through the node and page blobs held.
fn trees_of(tx: &mut Tx<'_>, t: &Tid, s: &Source) -> Result<Trees> {
    let Some(dedup) = tx.core.dedup(t) else { return Ok(Trees::default()) };
    let roots = roots_of(tx, t, s)?;
    let mut out = Trees::default();
    tree_blobs(tx, &dedup, &roots, &mut out)?;
    osis_base::costs::count("tree refs: blobs read", out.blobs.len() as u64);
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

/// What one counted link's read found.
#[derive(Clone, Debug, Default)]
enum Read {
    /// Not read: every link to it counted is a chunk's (a level-1 node's child).
    #[default]
    No,
    /// The links it holds, with whether they are chunks (none for a chunk, or bytes that are not
    /// the node or page its link names).
    Kids(Vec<(Link, bool)>),
    /// Not held.
    Missing,
}

/// What a read of a link depends on: its blob, its content hash and its key. Two links to one
/// blob that differ in these are counted apart (one may open what the other cannot).
type Opens = (BlobId, [u8; 32], [u8; 32]);

fn opens(l: &Link) -> Opens {
    (l.blob, l.hash, l.key)
}

/// One counted link.
#[derive(Clone, Debug)]
struct Counted {
    /// What it is read with.
    link: Link,
    /// Times counted.
    refs: u64,
    /// Those not as a chunk: it is read while one is.
    inner: u64,
    read: Read,
}

/// The trees under the roots of some sources of a thing, counted (the module doc).
#[derive(Clone, Debug, Default)]
pub(crate) struct Reach {
    /// The roots counted, by source.
    roots: HashMap<Source, Arc<Vec<Link>>>,
    /// Every link counted (by blob first: `links_to`).
    links: BTreeMap<Opens, Counted>,
    /// The counted links read while not held.
    missing: BTreeSet<Opens>,
}

/// A thing's two reaches: its live states', its held bodies'.
#[derive(Clone, Debug, Default)]
pub(crate) struct ThingReach {
    states: Reach,
    bodies: Reach,
}

impl Reach {
    /// Counts the roots of `now` (every source of its kind, through `Core::tree_roots`) where they
    /// moved since counted (the old roots down, the new up: `count` sums them, so the roots kept
    /// move nothing), then reads the missing nodes held now.
    fn update(&mut self, tx: &mut Tx<'_>, t: &Tid, dedup: Option<&Secret32>, now: BTreeSet<Source>) -> Result<()> {
        // a thing with no dedup secret has no trees here (`trees_of`)
        let now = if dedup.is_some() { now } else { BTreeSet::new() };
        let mut moved: Vec<(Link, bool, i64)> = Vec::new();
        let gone: Vec<Source> = self.roots.keys().filter(|s| !now.contains(s)).cloned().collect();
        for s in gone {
            if let Some(old) = self.roots.remove(&s) {
                moved.extend(old.iter().map(|l| (*l, false, -1)));
            }
        }
        for s in now {
            let k = (*t, s);
            let new = Memo::get_in(tx, |tx| &tx.core.tree_roots, &k, |tx| roots_of(tx, &k.0, &k.1).map(Arc::new))?;
            if let Some(old) = self.roots.get(&k.1) {
                if Arc::ptr_eq(old, &new) {
                    continue;
                }
                moved.extend(old.iter().map(|l| (*l, false, -1)));
            }
            moved.extend(new.iter().map(|l| (*l, false, 1)));
            self.roots.insert(k.1, new);
        }
        if let Some(d) = dedup {
            self.count(tx, d, moved)?;
            // a node a read lacked, held now
            let mut kids = Vec::new();
            for o in self.missing.clone() {
                if !tx.blobs.held(&o.0)? {
                    continue;
                }
                let Some(c) = self.links.get_mut(&o) else { continue };
                c.read = read(tx, d, &c.link)?;
                if let Read::Kids(k) = &c.read {
                    kids.extend(k.iter().map(|(k, chunk)| (*k, *chunk, 1)));
                    self.missing.remove(&o);
                }
            }
            self.count(tx, d, kids)?;
        } else {
            self.links.clear();
            self.missing.clear();
        }
        Ok(())
    }

    /// Counts `links` (each with whether it is a chunk, and by how much), and below them what that
    /// changes, a level at a time: a link first counted as no chunk is read and its links counted
    /// up, one no longer counted so has them counted down. A level's changes are summed per link
    /// first, so the links a new node shares with the one it replaced move no count.
    fn count(&mut self, tx: &mut Tx<'_>, dedup: &Secret32, links: Vec<(Link, bool, i64)>) -> Result<()> {
        let mut level = links;
        while !level.is_empty() {
            // per link: (link, times counted, those not as a chunk)
            let mut sums: BTreeMap<Opens, (Link, i64, i64)> = BTreeMap::new();
            for (l, chunk, n) in level.drain(..) {
                let x = sums.entry(opens(&l)).or_insert((l, 0, 0));
                x.1 += n;
                x.2 += if chunk { 0 } else { n };
            }
            for (o, (l, refs, inner)) in sums {
                if refs == 0 && inner == 0 {
                    continue;
                }
                osis_base::costs::count("tree refs: links counted", 1);
                let c = self.links.entry(o).or_insert_with(|| Counted { link: l, refs: 0, inner: 0, read: Read::No });
                let was = c.inner;
                let moved = |x: u64, n: i64| x.checked_add_signed(n).ok_or(Error::Corrupt("tree refs: a link counted down below zero"));
                (c.refs, c.inner) = (moved(c.refs, refs)?, moved(c.inner, inner)?);
                if was == 0 && c.inner > 0 {
                    c.read = read(tx, dedup, &c.link)?;
                    match &c.read {
                        Read::Kids(k) => level.extend(k.iter().map(|(k, chunk)| (*k, *chunk, 1))),
                        Read::Missing => {
                            self.missing.insert(o);
                        }
                        Read::No => {}
                    }
                } else if was > 0 && c.inner == 0 {
                    match std::mem::take(&mut c.read) {
                        Read::Kids(k) => level.extend(k.into_iter().map(|(k, chunk)| (k, chunk, -1))),
                        Read::Missing => {
                            self.missing.remove(&o);
                        }
                        Read::No => {}
                    }
                }
                if c.refs == 0 {
                    self.links.remove(&o);
                }
            }
        }
        Ok(())
    }

    /// Whether a counted link names blob `b`.
    fn links_to(&self, b: &BlobId) -> bool {
        self.links.range((*b, [0; 32], [0; 32])..=(*b, [u8::MAX; 32], [u8::MAX; 32])).next().is_some()
    }

    fn is_empty(&self) -> bool {
        self.roots.is_empty() && self.links.is_empty()
    }
}

/// The blob of `link`, read one step down (`large::below`).
fn read(tx: &mut Tx<'_>, dedup: &Secret32, link: &Link) -> Result<Read> {
    osis_base::costs::count("tree refs: blobs read", 1);
    let mut blobs = TxBlobs::new(&mut tx.blobs, tx.txn.is_memory());
    match below(&mut blobs, dedup, link) {
        Ok(Some((chunks, kids))) => Ok(Read::Kids(kids.into_iter().map(|k| (k, chunks)).collect())),
        Ok(None) => Ok(Read::Kids(Vec::new())),
        Err(Error::Data(osis_commit::Error::Missing)) => Ok(Read::Missing),
        Err(e) => Err(e),
    }
}

/// `Engine::tree_refs` in transaction `tx`.
pub(crate) fn tree_refs_in(tx: &mut Tx<'_>, t: &Tid, blobs: &BTreeSet<BlobId>) -> Result<Trees> {
    refs_in(tx, t, blobs, false)
}

/// `tree_refs_in` of the live states of `t` alone: what a drop of every body linking the rest
/// would leave linked (the compaction trigger's weighing, `retention::compact`).
pub(crate) fn state_refs_in(tx: &mut Tx<'_>, t: &Tid, blobs: &BTreeSet<BlobId>) -> Result<Trees> {
    refs_in(tx, t, blobs, true)
}

/// `tree_refs_in` of the sources of `t` but those `gone` names (lost access: the forgotten
/// aspects' states and bodies, still indexed while the forget runs, `retention::freed::lost`):
/// a rare question, answered by a fresh walk.
pub(crate) fn kept_refs_in(tx: &mut Tx<'_>, t: &Tid, blobs: &BTreeSet<BlobId>, gone: &dyn Fn(&Source) -> bool) -> Result<Trees> {
    walked(tx, t, blobs, false, gone)
}

/// Every source of thing `t`, states and bodies.
pub(crate) fn sources_of(tx: &mut Tx<'_>, t: &Tid) -> Result<BTreeSet<Source>> {
    sources(tx, t, false)
}

/// The answer of a fresh walk of every source of `t` (the states alone if `states`) but those
/// `gone` names: the blobs among `blobs` one links, and the node blobs they lack.
fn walked(tx: &mut Tx<'_>, t: &Tid, blobs: &BTreeSet<BlobId>, states: bool, gone: &dyn Fn(&Source) -> bool) -> Result<Trees> {
    let all = walked_all(tx, t, states, gone)?;
    Ok(Trees { blobs: blobs.intersection(&all.blobs).copied().collect(), missing: all.missing })
}

/// Every blob a fresh walk of those sources reaches, and the node blobs they lack.
fn walked_all(tx: &mut Tx<'_>, t: &Tid, states: bool, gone: &dyn Fn(&Source) -> bool) -> Result<Trees> {
    let mut out = Trees::default();
    for s in sources(tx, t, states)?.into_iter().filter(|s| !gone(s)) {
        let x = trees_of(tx, t, &s)?;
        out.blobs.extend(x.blobs);
        out.missing.extend(x.missing);
    }
    Ok(out)
}

fn refs_in(tx: &mut Tx<'_>, t: &Tid, blobs: &BTreeSet<BlobId>, states: bool) -> Result<Trees> {
    counted(tx, t, states, |rs| Trees { blobs: blobs.iter().filter(|b| rs.iter().any(|x| x.links_to(b))).copied().collect(), missing: whole(rs).missing })
}

/// Every blob the trees of `t`'s live states link, and the node blobs they lack
/// (`Engine::live_trees`).
pub(crate) fn live_trees_in(tx: &mut Tx<'_>, t: &Tid) -> Result<Trees> {
    counted(tx, t, true, whole)
}

/// Every blob counted in `rs`, and the node blobs not held.
fn whole(rs: &[&Reach]) -> Trees {
    let mut all = Trees::default();
    for x in rs {
        all.blobs.extend(x.links.keys().map(|o| o.0));
        all.missing.extend(x.missing.iter().map(|o| o.0));
    }
    all
}

/// What `answer` makes of the reaches of `t`'s sources (its live states alone if `states`),
/// counted up to now.
fn counted<T>(tx: &mut Tx<'_>, t: &Tid, states: bool, answer: impl FnOnce(&[&Reach]) -> T) -> Result<T> {
    let t = *t;
    let (st, bodies): (BTreeSet<Source>, BTreeSet<Source>) = sources(tx, &t, states)?.into_iter().partition(|s| matches!(s, Source::State(_)));
    let dedup = tx.core.dedup(&t);
    // taken out while it is counted: a failure drops it, read anew at the next question
    let mut r = tx.core.tree_reach.remove(&t).unwrap_or_default();
    tx.core.reach_log.push(t);
    r.states.update(tx, &t, dedup.as_ref(), st)?;
    if !states {
        r.bodies.update(tx, &t, dedup.as_ref(), bodies)?;
    }
    let asked: Vec<&Reach> = [Some(&r.states), (!states).then_some(&r.bodies)].into_iter().flatten().collect();
    let out = answer(&asked);
    // debug builds, at every question: what is counted differs from a fresh walk (any blob, not
    // only those asked: a count gone wrong shows at once) leaves a linked chunk unprotected
    #[cfg(debug_assertions)]
    let counted = whole(&asked);
    if !(r.states.is_empty() && r.bodies.is_empty()) {
        tx.core.tree_reach.insert(t, r);
    }
    #[cfg(debug_assertions)]
    {
        let fresh = osis_base::costs::paused(|| osis_base::memo::unrecorded(|| walked_all(tx, &t, states, &|_| false)))?;
        assert_eq!(counted, fresh, "tree refs of {t:?} counted apart from a fresh walk");
    }
    Ok(out)
}

impl super::Engine {
    /// The blobs among `blobs` that a tree of `tid`'s live states or of a body held on it links
    /// (deltas, snapshots, leftovers), and the node blobs those trees link and this node does not
    /// hold (`missing`: what lies below them is unknown until they are fetched). Costs a memo hit
    /// per source and a lookup per blob, plus the tree paths a source's roots moved by.
    pub fn tree_refs(&mut self, tid: &Tid, blobs: &BTreeSet<BlobId>) -> Result<Trees> {
        self.run(|tx| tree_refs_in(tx, tid, blobs))
    }
}
