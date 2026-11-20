//! What a commit needs held, found by walking what it links (spec/sync-streams.md §5, spec/sync-compaction.md §2 caps;
//! spec/commits.md §4): a header list given by link needs its whole chunk tree; a part needs its
//! pages (followed: a page's links are pages or value roots) and, for the memory gate, its
//! large values' roots (not followed: their chunks are fetched after, `Walks::trees`). A held
//! blob is told apart by its shape: a tree node parses as one (`osis_commit::tree::parse_node`),
//! anything else a link reaches from a delta or page is a page. A hostile writer's blob of the
//! wrong shape only fails its own commit, which judges every link it resolves.
//!
//! A paged position's link pages are checked as they come by the one tree rule the decoders
//! apply (`osis_crdt::LinkTree`, spec/wire.md §6): a page that cannot lie in the canonical tree
//! stops the walk of that tree (nothing more of it is fetched; the commit's judging refuses it,
//! its decoder checking the held pages past any missing one). Invariant: fetch rounds for a
//! position are at most about log2 of the pages its author delivered, plus two, whatever the
//! tree's shape; positions nest at most `MAX_VALUE_DEPTH + 1` deep (deeper, no decoder accepts
//! the delta), and a tree node's children lie a level below it. Who writes the input: any writer
//! of a commit a node waits for.
//!
//! node-sync asks what waiting commits lack (`Engine::blob_wants`): each commit's walk is kept
//! (`Walks`, memory only) and taken further from its missing blobs as they arrive, so a fill of
//! a large paged commit costs each page one walk step, not one per batch.

use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, CommitId, Link, LinkSite};
use osis_crdt::{LinkTree, TreePlace};
use osis_commit::CommitBlob;
use std::collections::{BTreeMap, BTreeSet};

/// What a link is known to be before its blob is opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum At {
    /// In a non-empty array of links only, in a delta or page: a paged position's page (spec/crdt.md §8), or a
    /// large value's root (a value holding links only reads alike).
    Page(Pos),
    /// Any other link in a delta or page: a large value's root, never a page.
    Lone,
    /// A header list's tree node at this level (0: the root, any level): its whole tree is walked.
    Node(u64),
    /// A large value's tree node below its root, at this level. One held when first reached is
    /// taken as whole (it came with the tree that linked it before, whose walk fetched what lies
    /// below), so an edit reusing most of a value walks only the nodes it brings.
    Tree(u64),
    /// A chunk: never opened.
    Chunk,
}

/// Where a page link lies: its position's tree (an index into `Walk::shapes`), its place there,
/// and how many positions' trees it lies in (the delta's own: 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pos {
    tree: usize,
    place: TreePlace,
    nest: usize,
}

/// A paged position's tree as walked so far.
#[derive(Clone, Debug)]
struct Shape {
    rule: LinkTree,
    /// A page it holds cannot lie in the canonical tree: nothing more of it is fetched.
    refused: bool,
}

/// One commit's walk.
#[derive(Clone, Debug, Default)]
pub(crate) struct Walk {
    /// Every blob reached, held or not.
    pub reached: BTreeSet<BlobId>,
    /// Reached and not held: where the walk stopped.
    missing: BTreeMap<BlobId, (Link, At)>,
    /// Large values' roots reached and held.
    pub roots: Vec<Link>,
    /// The paged positions' trees reached.
    shapes: Vec<Shape>,
    /// Whether value trees are walked below their roots (an applied memory commit's, whose
    /// chunks are fetched at once: spec/sync-compaction.md §2).
    trees: bool,
}

impl Walk {
    /// Blobs reached and not held.
    pub fn missing(&self) -> impl Iterator<Item = &BlobId> {
        self.missing.keys()
    }
}

/// Walks kept for node-sync (`Engine::blob_wants`): of pending commits waiting for blobs, and
/// of applied memory commits from others until their trees are whole. A cache of the store:
/// each walk is checked against what is held as it goes on, and done again whole when it finds
/// nothing missing while its commit still waits (a header resolved since, a page gone).
#[derive(Clone, Debug, Default)]
pub(crate) struct Walks {
    walks: BTreeMap<CommitId, Walk>,
    /// Applied memory commits from others whose value trees may not be whole here.
    trees: BTreeSet<CommitId>,
}

impl Walks {
    /// Memory commit `id` passed its gate: its value trees are fetched once it applies.
    pub fn trees_of(&mut self, id: CommitId) {
        self.trees.insert(id);
    }
}

/// Takes `stack` as far as the held blobs go, into `w`. `on_page` sees each page reached (its
/// blob, its plaintext); a page that is not one CBOR value is `BadInput`.
fn extend(tx: &mut Tx<'_>, w: &mut Walk, mut stack: Vec<(Link, At)>, on_page: &mut super::memory::PageVisit<'_>) -> Result<()> {
    while let Some((link, at)) = stack.pop() {
        if !w.reached.insert(link.blob) {
            continue;
        }
        step(tx, w, link, at, false, &mut stack, on_page)?;
    }
    Ok(())
}

/// One reached link: missing, or opened and followed as far as `w` follows. `arrived`: it was
/// missing when reached.
fn step(tx: &mut Tx<'_>, w: &mut Walk, link: Link, at: At, arrived: bool, stack: &mut Vec<(Link, At)>, on_page: &mut super::memory::PageVisit<'_>) -> Result<()> {
    if let At::Page(p) = at
        && w.shapes.get(p.tree).is_none_or(|s| s.refused)
    {
        return Ok(());
    }
    if at == At::Chunk || matches!(at, At::Tree(_)) && !arrived {
        if !tx.blobs.held(&link.blob)? {
            w.missing.insert(link.blob, (link, at));
        }
        return Ok(());
    }
    let Some(blob) = tx.blobs.get(&link.blob)? else {
        w.missing.insert(link.blob, (link, at));
        return Ok(());
    };
    osis_base::costs::count("reach: blobs opened", 1);
    // bytes that do not open under the link are no blob of it: the commit's own judging fails
    let Ok((_, pt)) = osis_blob::open(&blob, &osis_crypto::Secret32::from_bytes(link.key)) else { return Ok(()) };
    if let Ok((level, kids)) = osis_blob::tree::parse_node(&pt) {
        match at {
            // a level-k node links level k - 1 nodes (spec/wire.md §6): no other is followed
            At::Node(want) | At::Tree(want) if want != 0 && want != level => return Ok(()),
            At::Page(_) | At::Lone => {
                w.roots.push(link);
                if !w.trees {
                    return Ok(());
                }
            }
            _ => {}
        }
        let below = match (level <= 1, at) {
            (true, _) => At::Chunk,
            (false, At::Node(_)) => At::Node(level - 1),
            (false, _) => At::Tree(level - 1),
        };
        stack.extend(kids.into_iter().map(|(l, _)| (l, below)));
        return Ok(());
    }
    let At::Page(p) = at else { return Ok(()) };
    on_page(&blob, &pt)?;
    let mut sites = Vec::new();
    sites_of(&pt, &mut sites).map_err(|_| Error::BadInput("page not one CBOR value"))?;
    let Some(shape) = w.shapes.get_mut(p.tree) else { return Ok(()) };
    let fits = match sites.as_slice() {
        [LinkSite::List { links, top: true }] => shape.rule.link_page(p.place, links).map(|()| {
            let n = links.len();
            stack.extend(links.iter().enumerate().map(|(i, l)| (*l, At::Page(Pos { place: TreePlace::of(Some(p.place), i, n), ..p }))));
        }),
        _ => shape.rule.leaf(p.place).map(|()| push_sites(w, sites, p.nest + 1, stack)),
    };
    if fits.is_err() {
        refuse(w, p.tree);
    }
    Ok(())
}

/// The links in `bytes` (a delta or page), each with where it sits.
fn sites_of(bytes: &[u8], out: &mut Vec<LinkSite>) -> std::result::Result<(), osis_base::DecodeError> {
    let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, bytes.len());
    osis_base::visit_link_sites(bytes, &limits, &mut |s| out.push(s))
}

/// The links of a delta (`nest` 1) or of a leaf page lying in `nest - 1` positions' trees, to
/// walk: each list a position's tree of its own (a value's links alike), unless nested deeper
/// than any delta a decoder accepts (each paged position holding another adds a read level,
/// spec/crdt.md §3.3 rule 7).
fn push_sites(w: &mut Walk, sites: Vec<LinkSite>, nest: usize, stack: &mut Vec<(Link, At)>) {
    for s in sites {
        match s {
            LinkSite::Lone(l) => stack.push((l, At::Lone)),
            LinkSite::List { .. } if nest > osis_base::format::MAX_VALUE_DEPTH + 1 => {}
            LinkSite::List { links, .. } => {
                let tree = w.shapes.len();
                w.shapes.push(Shape { rule: LinkTree::new(osis_crdt::PageParams::wire()), refused: false });
                let n = links.len();
                stack.extend(links.into_iter().enumerate().map(|(i, l)| (l, At::Page(Pos { tree, place: TreePlace::of(None, i, n), nest }))));
            }
        }
    }
}

/// Position tree `tree` cannot be the canonical one: nothing more of it is fetched.
fn refuse(w: &mut Walk, tree: usize) {
    if let Some(s) = w.shapes.get_mut(tree) {
        s.refused = true;
    }
    w.missing.retain(|_, (_, at)| !matches!(at, At::Page(p) if p.tree == tree));
}

/// The walk of `blob`: while its header lists given by link do not resolve from what is held,
/// their trees; else its parts' pages and value roots (below them too with `trees`). A part
/// that is not one CBOR value links nothing (its commit's judging refuses it).
pub(crate) fn walk(tx: &mut Tx<'_>, blob: &CommitBlob, trees: bool, on_page: &mut super::memory::PageVisit<'_>) -> Result<Walk> {
    if !blob.header.is_resolved() && !resolves(tx, blob)? {
        let mut w = Walk { trees, ..Walk::default() };
        let stack = osis_commit::ListField::ALL.into_iter().filter_map(|f| blob.header.links.get(f).copied()).map(|l| (l, At::Node(0))).collect();
        extend(tx, &mut w, stack, on_page)?;
        return Ok(w);
    }
    let deltas: Vec<&[u8]> = blob.parts.iter().map(|p| p.delta.as_slice()).collect();
    walk_deltas(tx, &deltas, trees, on_page)
}

/// The walk of `deltas`' links: pages followed, value roots (below them too with `trees`). A
/// delta that is not one CBOR value links nothing (its commit's judging refuses it).
pub(crate) fn walk_deltas(tx: &mut Tx<'_>, deltas: &[&[u8]], trees: bool, on_page: &mut super::memory::PageVisit<'_>) -> Result<Walk> {
    let mut w = Walk { trees, ..Walk::default() };
    let mut stack = Vec::new();
    for d in deltas {
        let mut sites = Vec::new();
        if sites_of(d, &mut sites).is_ok() {
            push_sites(&mut w, sites, 1, &mut stack);
        }
    }
    extend(tx, &mut w, stack, on_page)?;
    Ok(w)
}

/// Whether `blob`'s header lists resolve from the blobs held (bad lists count as resolving:
/// nothing more to fetch, its judging refuses them).
fn resolves(tx: &mut Tx<'_>, blob: &CommitBlob) -> Result<bool> {
    let Some(dedup) = tx.core.dedup(&blob.header.signer) else { return Ok(true) };
    let mut h = blob.header.clone();
    match h.resolve(&mut crate::engine::blobs::TxBlobs::new(&mut tx.blobs, tx.txn.is_memory()), &dedup) {
        Err(e) if super::is_missing_page(&e) => Ok(false),
        _ => Ok(true),
    }
}

/// `w` taken on from its missing blobs held now.
fn refresh(tx: &mut Tx<'_>, w: &mut Walk) -> Result<()> {
    let mut arrived = Vec::new();
    for (b, x) in &w.missing {
        if tx.blobs.held(b)? {
            arrived.push(*x);
        }
    }
    let mut stack = Vec::new();
    for (link, at) in arrived {
        w.missing.remove(&link.blob);
        step(tx, w, link, at, true, &mut stack, &mut |_, _| Ok(()))?;
    }
    extend(tx, w, stack, &mut |_, _| Ok(()))
}

/// Bad bytes stop a kept walk where they are: the commit's own judging refuses them.
fn quiet(r: Result<()>) -> Result<()> {
    match r {
        Err(Error::BadInput(_)) => Ok(()),
        r => r,
    }
}

/// The kept walk of commit `id` (stored as `blob`), taken on to what is held now. A first walk
/// (a walk kept while it waited stops at roots: applied, its trees are walked afresh), and of a
/// waiting commit (not `trees`) one that lacks nothing while it still waits, is done whole.
fn kept(tx: &mut Tx<'_>, id: &CommitId, blob: &CommitBlob, trees: bool) -> Result<Walk> {
    let (mut w, fresh) = match tx.core.walks.walks.remove(id).filter(|w| w.trees == trees) {
        Some(mut w) => {
            quiet(refresh(tx, &mut w))?;
            (w, false)
        }
        None => (Walk { trees, ..Walk::default() }, true),
    };
    if fresh || !trees && w.missing.is_empty() {
        w = match walk(tx, blob, trees, &mut |_, _| Ok(())) {
            Err(Error::BadInput(_)) => Walk { trees, ..Walk::default() },
            r => r?,
        };
    }
    tx.core.walks.walks.insert(*id, w.clone());
    Ok(w)
}

/// Whether pending commit `id` (stored as `blob`) lacks a blob its walk reaches.
pub(crate) fn lacks(tx: &mut Tx<'_>, id: &CommitId, blob: &CommitBlob) -> Result<bool> {
    Ok(!kept(tx, id, blob, false)?.missing.is_empty())
}

/// What waiting commits need (`Engine::blob_wants`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Wants {
    /// Every blob their walks reach, held or not: what their unvouched entries keep.
    pub reached: BTreeSet<BlobId>,
    /// Reached and not held: to fetch.
    pub missing: BTreeSet<BlobId>,
}

impl Engine {
    /// The blobs commits here wait for (spec/sync-streams.md §5, spec/sync-compaction.md §2): of each pending commit waiting
    /// for blobs, its header lists' trees while they do not resolve, then its pages and its
    /// large values' roots; of each memory commit from others applied here, its value trees
    /// (fetched at once: they are held in memory at peers). Costs the blobs that arrived since
    /// the last call, and a whole walk of a commit whose walk lacks nothing while it still waits.
    pub fn blob_wants(&mut self) -> Result<Wants> {
        let waiting: Vec<CommitId> = self.core.ix.pend_on.get(&super::Wake::Blobs).into_iter().flatten().copied().collect();
        if waiting.is_empty() && self.core.walks.trees.is_empty() {
            self.core.walks.walks.clear();
            return Ok(Wants::default());
        }
        self.run(|tx| {
            let mut out = Wants::default();
            let trees: Vec<CommitId> = tx.core.walks.trees.iter().copied().filter(|c| !waiting.contains(c)).collect();
            let keep: BTreeSet<CommitId> = waiting.iter().chain(&trees).copied().collect();
            tx.core.walks.walks.retain(|c, _| keep.contains(c));
            for id in &waiting {
                let Some(b) = tx.txn.get_pending(id)?.and_then(|p| CommitBlob::decode_stored(&p.bytes).ok()) else { continue };
                let w = kept(tx, id, &b, false)?;
                out.reached.extend(w.reached);
                out.missing.extend(w.missing.into_keys());
            }
            for id in &trees {
                let memory = tx.core.ix.commits.get(id).is_some_and(|m| m.view.memory);
                let blob = if memory { tx.get_commit(id)? } else { None };
                let Some(blob) = blob else {
                    tx.core.walks.trees.remove(id);
                    tx.core.walks.walks.remove(id);
                    continue;
                };
                let w = kept(tx, id, &blob, true)?;
                if w.missing.is_empty() {
                    tx.core.walks.trees.remove(id);
                    tx.core.walks.walks.remove(id);
                }
                out.reached.extend(w.reached);
                out.missing.extend(w.missing.into_keys());
            }
            Ok(out)
        })
    }
}

/// The bytes under `roots` not held here, as their held nodes state them (a node not held
/// counts its length in its parent, a held one below a root none, `At::Tree`): what a memory commit's large values may still bring
/// (spec/sync-compaction.md §2 caps). Each distinct blob once. Lengths are claims: the tree reader refuses a
/// liar at its first mismatch (spec/wire.md §6), and each chunk is charged its bytes on arrival.
pub(crate) fn unheld_bytes(tx: &mut Tx<'_>, roots: &[Link]) -> Result<u64> {
    let mut seen = BTreeSet::new();
    let mut sum = 0u64;
    // (link, its length as its parent states it, whether it is a chunk)
    let mut stack: Vec<(Link, Option<u64>, bool)> = roots.iter().map(|l| (*l, None, false)).collect();
    while let Some((l, len, chunk)) = stack.pop() {
        if !seen.insert(l.blob) {
            continue;
        }
        if chunk {
            if !tx.blobs.held(&l.blob)? {
                sum = sum.saturating_add(len.unwrap_or(0));
            }
            continue;
        }
        // a node below a root held here came with the tree that linked it before (`At::Tree`)
        if len.is_some() && tx.blobs.held(&l.blob)? {
            continue;
        }
        osis_base::costs::count("reach: blobs opened", 1);
        let node = tx.blobs.get(&l.blob)?.and_then(|b| osis_blob::open(&b, &osis_crypto::Secret32::from_bytes(l.key)).ok()).and_then(|(_, pt)| osis_blob::tree::parse_node(&pt).ok());
        match node {
            Some((level, kids)) => stack.extend(kids.into_iter().map(|(k, n)| (k, Some(n), level <= 1))),
            None => sum = sum.saturating_add(len.unwrap_or(0)),
        }
    }
    Ok(sum)
}
