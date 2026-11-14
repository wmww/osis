//! What a commit needs held, found by walking what it links (spec/sync-streams.md §5, spec/sync-compaction.md §2 caps;
//! spec/commits.md §4): a header list given by link needs its whole chunk tree; a part needs its
//! pages (followed: a page's links are pages or value roots) and, for the memory gate, its
//! large values' roots (not followed: their chunks are fetched after, `Walks::trees`). A held
//! blob is told apart by its shape: a tree node parses as one (`osis_commit::tree::parse_node`),
//! anything else a link reaches from a delta or page is a page. A hostile writer's blob of the
//! wrong shape only fails its own commit, which judges every link it resolves.
//!
//! node-sync asks what waiting commits lack (`Engine::blob_wants`): each commit's walk is kept
//! (`Walks`, memory only) and taken further from its missing blobs as they arrive, so a fill of
//! a large paged commit costs each page one walk step, not one per batch.

use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, CommitId, Link};
use osis_commit::CommitBlob;
use std::collections::{BTreeMap, BTreeSet};

/// What a link is known to be before its blob is opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum At {
    /// Linked from a delta or page: a page, or a large value's root.
    Linked,
    /// A header list's tree node: its whole tree is walked.
    Node,
    /// A large value's tree node below its root. One held when first reached is taken as whole
    /// (it came with the tree that linked it before, whose walk fetched what lies below), so an
    /// edit reusing most of a value walks only the nodes it brings.
    Tree,
    /// A chunk: never opened.
    Chunk,
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
    if at == At::Chunk || at == At::Tree && !arrived {
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
    let Ok((_, pt)) = osis_label::open(&blob, &osis_crypto::Secret32::from_bytes(link.key)) else { return Ok(()) };
    if let Ok((level, kids)) = osis_label::tree::parse_node(&pt) {
        if at == At::Linked {
            w.roots.push(link);
            if !w.trees {
                return Ok(());
            }
        }
        let below = match (level <= 1, at) {
            (true, _) => At::Chunk,
            (false, At::Node) => At::Node,
            (false, _) => At::Tree,
        };
        stack.extend(kids.into_iter().map(|(l, _)| (l, below)));
        return Ok(());
    }
    if at == At::Linked {
        on_page(&blob, &pt)?;
        links_of(&pt, stack).map_err(|_| Error::BadInput("page not one CBOR value"))?;
    }
    Ok(())
}

fn links_of(bytes: &[u8], stack: &mut Vec<(Link, At)>) -> std::result::Result<(), osis_base::DecodeError> {
    let limits = osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: bytes.len() };
    osis_base::visit_links(bytes, &limits, &mut |l| stack.push((l, At::Linked)))
}

/// The walk of `blob`: while its header lists given by link do not resolve from what is held,
/// their trees; else its parts' pages and value roots (below them too with `trees`). A part
/// that is not one CBOR value links nothing (its commit's judging refuses it).
pub(crate) fn walk(tx: &mut Tx<'_>, blob: &CommitBlob, trees: bool, on_page: &mut super::memory::PageVisit<'_>) -> Result<Walk> {
    if !blob.header.is_resolved() && !resolves(tx, blob)? {
        let mut w = Walk { trees, ..Walk::default() };
        let stack = osis_commit::ListField::ALL.into_iter().filter_map(|f| blob.header.links.get(f).copied()).map(|l| (l, At::Node)).collect();
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
        let _ = links_of(d, &mut stack);
    }
    extend(tx, &mut w, stack, on_page)?;
    Ok(w)
}

/// Whether `blob`'s header lists resolve from the blobs held (bad lists count as resolving:
/// nothing more to fetch, its judging refuses them).
fn resolves(tx: &mut Tx<'_>, blob: &CommitBlob) -> Result<bool> {
    let Some(dedup) = tx.core.dedup(&blob.header.actor) else { return Ok(true) };
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
    /// (fetched at once: they are held in memory at hosts). Costs the blobs that arrived since
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
        let node = tx.blobs.get(&l.blob)?.and_then(|b| osis_label::open(&b, &osis_crypto::Secret32::from_bytes(l.key)).ok()).and_then(|(_, pt)| osis_label::tree::parse_node(&pt).ok());
        match node {
            Some((level, kids)) => stack.extend(kids.into_iter().map(|(k, n)| (k, Some(n), level <= 1))),
            None => sum = sum.saturating_add(len.unwrap_or(0)),
        }
    }
    Ok(sum)
}
