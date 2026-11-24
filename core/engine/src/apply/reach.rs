//! What a commit needs held, found by walking what it links (spec/sync-streams.md §5, spec/sync-compaction.md §2 caps;
//! spec/commits.md §4): a header list given by link needs its whole chunk tree; a part needs its
//! pages (followed: a page's links are pages or value roots) and, for the memory gate, its
//! large values' roots (not followed: their chunks are fetched once it applies, `Slot::Trees`). A held
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
//! Blob waits (notes/sync-facade.md, Blob waits): each waiting slot keeps its walk's frontier
//! (`Walks`, memory only): the blobs it lacks, each with where it lies, and the position trees
//! they lie in; nothing of what it reached and holds (that is the store's). Indexed by the blobs
//! it lacks; a blob newly held takes on only the walks lacking it, from that blob (`advance`), and
//! a commit is examined only when a slot of it lacks nothing. A pass (a walk's first, or an
//! advance) reaches each blob once; one pass does not know what an earlier one reached, which only
//! a blob linked twice in one delta could reach again: a page linked twice is refused by the
//! decoders (`osis_crdt` `fetch_page`), and a value's nodes reached again are a held check each.
//! Invariants: memory is O(the blobs a slot lacks), so W commits over one held tree keep W
//! frontiers, never W copies of the tree (who writes the input: any writer of commits a node keeps
//! pending); a fill of P pages, each linked once, costs O(P) walk steps and one checked decode per
//! part, whatever batching or order the node serving the pages picks (who drives it: any peer
//! serving them); a pass costs at most the held blobs it reaches, each once.

use crate::engine::{Engine, Tx};
use crate::error::Result;
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
    /// Any other link in a delta or page: a large value's root, never a page; in a leaf page of
    /// this position's tree (`None`: in the delta).
    Lone(Option<usize>),
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

impl At {
    /// The position tree a link lies in, for a page or a large value's root in a leaf page.
    fn tree(self) -> Option<usize> {
        match self {
            At::Page(p) => Some(p.tree),
            At::Lone(t) => t,
            _ => None,
        }
    }
}

/// A paged position's tree as walked so far.
#[derive(Clone, Debug)]
struct Shape {
    rule: LinkTree,
    /// A page it holds cannot lie in the canonical tree, or the tree whose leaf holds it is
    /// refused: nothing more of it is fetched.
    refused: bool,
    /// The tree whose leaf page holds this position (`None`: the delta's own).
    parent: Option<usize>,
    /// The blobs lacked in it (`missing`) and the trees kept in its leaves: kept while some.
    refs: usize,
}

/// One walk: where it stopped. Between passes it keeps only its frontier, so its memory follows
/// what it lacks, never what it reached.
#[derive(Clone, Debug, Default)]
pub(crate) struct Walk {
    /// Reached and not held: where the walk stopped.
    missing: BTreeMap<BlobId, (Link, At)>,
    /// Large values' roots reached and held in the last pass (a kept walk keeps none).
    pub roots: Vec<Link>,
    /// The paged positions' trees by number (numbered as reached, so a nested tree after the
    /// tree holding it): between passes those a lacked blob lies in, and the trees holding them.
    shapes: BTreeMap<usize, Shape>,
    /// The next tree's number.
    trees_reached: usize,
    /// Trees whose `refs` fell to 0 in the running pass: dropped at its end (`prune`).
    idle: Vec<usize>,
    /// Whether value trees are walked below their roots (an applied memory commit's, whose
    /// chunks are fetched at once: spec/sync-compaction.md §2).
    trees: bool,
    /// Whether a large value's root standing alone is lacked (a memory commit's gate needs its
    /// roots; a durable part's decoders need none: spec/sync-streams.md §5, fetched lazily).
    lone: bool,
    /// Blobs `missing` gained (`true`) or lost since `Walks` indexed it, in order.
    moved: Vec<(BlobId, bool)>,
}

impl Walk {
    fn new(trees: bool, lone: bool) -> Walk {
        Walk { trees, lone, ..Walk::default() }
    }

    /// Whether position tree `t` is refused.
    fn refused(&self, t: usize) -> bool {
        self.shapes.get(&t).is_some_and(|s| s.refused)
    }

    fn hold_tree(&mut self, t: usize) {
        if let Some(s) = self.shapes.get_mut(&t) {
            s.refs = s.refs.saturating_add(1);
        }
    }

    fn release_tree(&mut self, t: usize) {
        if let Some(s) = self.shapes.get_mut(&t) {
            s.refs = s.refs.saturating_sub(1);
            if s.refs == 0 {
                self.idle.push(t);
            }
        }
    }

    /// The end of a pass: trees nothing lacked lies in go, and with them their hold on the tree
    /// holding them. O(the trees released).
    fn prune(&mut self) {
        while let Some(t) = self.idle.pop() {
            if self.shapes.get(&t).is_some_and(|s| s.refs == 0)
                && let Some(p) = self.shapes.remove(&t).and_then(|s| s.parent)
            {
                self.release_tree(p);
            }
        }
    }

    /// Blobs reached and not held.
    pub fn missing(&self) -> impl Iterator<Item = &BlobId> {
        self.missing.keys()
    }

    fn lack(&mut self, link: Link, at: At) {
        if let std::collections::btree_map::Entry::Vacant(e) = self.missing.entry(link.blob) {
            e.insert((link, at));
            self.moved.push((link.blob, true));
            if let Some(t) = at.tree() {
                self.hold_tree(t);
            }
        }
    }

    fn unlack(&mut self, b: &BlobId) -> Option<(Link, At)> {
        let x = self.missing.remove(b)?;
        self.moved.push((*b, false));
        if let Some(t) = x.1.tree() {
            self.release_tree(t);
        }
        Some(x)
    }

    /// Entries a kept walk holds (tests: its memory, in links and trees).
    #[cfg(test)]
    fn entries(&self) -> usize {
        self.missing.len() + self.shapes.len() + self.roots.len()
    }
}

/// Where a kept walk lies in its commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Slot {
    /// Its header lists given by link, while they do not resolve.
    Header,
    /// Part `ai`'s pages and value roots, while it waits for them.
    Part(usize),
    /// Applied memory part `ai`'s value trees, until held whole (fetched at once).
    Trees(usize),
}

impl Slot {
    /// The slots a pending copy waits on (all but `Trees`).
    fn pending_of(c: CommitId) -> std::ops::Range<(CommitId, Slot)> {
        (c, Slot::Header)..(c, Slot::Trees(0))
    }
}

/// Slots a blob held since the last round was wanted by, with the blob, by commit.
pub(crate) type Arrived = BTreeMap<CommitId, BTreeSet<(Slot, BlobId)>>;

/// The kept walks of blob waits (notes/sync-facade.md, Blob waits): memory only, a slot kept
/// only while its walk lacks a blob. A function of the commits and the blobs held; derived again
/// at open (every pending commit examined), and after a failed step or transaction for the
/// commits it touched (`rolled_back`, then `lost`).
#[derive(Clone, Debug, Default)]
pub(crate) struct Walks {
    kept: BTreeMap<(CommitId, Slot), Walk>,
    /// Each blob a kept walk lacks, and the slots lacking it: the wake index.
    wanted: BTreeMap<BlobId, BTreeSet<(CommitId, Slot)>>,
    /// Blobs that came to be wanted since `Engine::take_wanted` last took them.
    newly: BTreeSet<BlobId>,
    /// Slots a blob held since the last round was wanted by, with the blob (`held`).
    arrived: Arrived,
    /// Commits whose walks a failed step or transaction dropped: examined at the next round
    /// (pending), or their trees walked again (an applied memory commit).
    lost: BTreeSet<CommitId>,
    /// Memory commits admitted since the last round: their trees are walked once applied.
    trees_due: BTreeSet<CommitId>,
    /// Commits whose walks changed in the running transaction (`forget_since`).
    log: Vec<CommitId>,
    /// Commits given walks or unpended in the running transaction: their pending slots go at
    /// its end if they do not pend then (`settle`).
    unsettled: BTreeSet<CommitId>,
}

impl Walks {
    /// Memory commit `id` passed its gate: its value trees are fetched once it applies.
    pub fn trees_of(&mut self, id: CommitId) {
        self.trees_due.insert(id);
    }

    /// Takes `w`'s moves into the index under `(c, s)`.
    fn index(&mut self, c: CommitId, s: Slot, w: &mut Walk) {
        for (b, add) in w.moved.drain(..) {
            if add {
                self.newly.insert(b);
                self.wanted.entry(b).or_default().insert((c, s));
            } else if let Some(x) = self.wanted.get_mut(&b) {
                x.remove(&(c, s));
                if x.is_empty() {
                    self.wanted.remove(&b);
                }
            }
        }
    }

    /// `w` is slot `s` of `c`'s walk from now on: kept while it lacks a blob.
    fn put(&mut self, c: CommitId, s: Slot, mut w: Walk) {
        self.unkeep(c, s);
        self.log.push(c);
        if !matches!(s, Slot::Trees(_)) {
            self.unsettled.insert(c);
        }
        if w.missing.is_empty() {
            return;
        }
        w.roots = Vec::new();
        w.moved = w.missing.keys().map(|b| (*b, true)).collect();
        self.index(c, s, &mut w);
        self.kept.insert((c, s), w);
    }

    /// Slot `s` of `c` keeps no walk, its index entries gone.
    fn unkeep(&mut self, c: CommitId, s: Slot) -> bool {
        let Some(mut w) = self.kept.remove(&(c, s)) else { return false };
        w.moved = w.missing.keys().map(|b| (*b, false)).collect();
        self.index(c, s, &mut w);
        true
    }

    /// Slot `s` of `c` waits no more (judged otherwise).
    pub fn drop_slot(&mut self, c: CommitId, s: Slot) {
        if self.unkeep(c, s) {
            self.log.push(c);
        }
    }

    /// `c` pends no more: its pending slots go at the transaction's end unless it pends again.
    pub fn unpended(&mut self, c: &CommitId) {
        self.unsettled.insert(*c);
    }

    /// `c` pends no more: the walks of its pending copy go.
    fn drop_pending(&mut self, c: &CommitId) {
        let slots: Vec<Slot> = self.kept.range(Slot::pending_of(*c)).map(|(k, _)| k.1).collect();
        for s in slots {
            self.drop_slot(*c, s);
        }
    }

    /// `c` is forgotten: all its walks go.
    pub fn drop_all(&mut self, c: &CommitId) {
        let slots: Vec<Slot> = self.kept.range((*c, Slot::Header)..=(*c, Slot::Trees(usize::MAX))).map(|(k, _)| k.1).collect();
        for s in slots {
            self.drop_slot(*c, s);
        }
        self.trees_due.remove(c);
    }

    /// `c`'s header resolved: its pending slots other than parts `parts` go (parts no longer in
    /// its pending copy).
    pub fn keep_parts(&mut self, c: &CommitId, parts: &BTreeSet<usize>) {
        let gone: Vec<Slot> = self.kept.range(Slot::pending_of(*c)).filter_map(|(k, _)| if let Slot::Part(ai) = k.1 { (!parts.contains(&ai)).then_some(k.1) } else { Some(k.1) }).collect();
        for s in gone {
            self.drop_slot(*c, s);
        }
    }

    /// Whether slot `s` of `c` keeps a walk: it lacks a blob, so judging it now cannot end its wait.
    pub fn waits(&self, c: &CommitId, s: Slot) -> bool {
        self.kept.contains_key(&(*c, s))
    }

    /// Whether `c`'s pending copy lacks a blob a walk of it reaches.
    pub fn lacks(&self, c: &CommitId) -> bool {
        self.kept.range(Slot::pending_of(*c)).next().is_some()
    }

    /// Blob `b` is held here now (its transaction committed): the slots wanting it are due.
    pub fn held(&mut self, b: &BlobId) {
        for (c, s) in self.wanted.get(b).into_iter().flatten() {
            self.arrived.entry(*c).or_default().insert((*s, *b));
        }
    }

    /// Whether any walk is kept.
    pub fn any(&self) -> bool {
        !self.kept.is_empty()
    }

    /// Whether a kept walk lacks blob `b`.
    pub fn wants(&self, b: &BlobId) -> bool {
        self.wanted.contains_key(b)
    }

    /// Whether a round has work here (`Engine::next_timer`).
    pub fn due(&self) -> bool {
        !self.arrived.is_empty() || !self.lost.is_empty() || !self.trees_due.is_empty()
    }

    /// Takes what is due for a round: the arrivals, the lost commits, the trees to walk.
    pub fn take_due(&mut self) -> (Arrived, BTreeSet<CommitId>) {
        let mut lost = std::mem::take(&mut self.lost);
        lost.append(&mut self.trees_due);
        (std::mem::take(&mut self.arrived), lost)
    }

    /// `log`'s length (`Core::mark`).
    pub fn mark(&self) -> usize {
        self.log.len()
    }

    /// A step or transaction from `n` failed: the walks of the commits it touched go, those
    /// commits due again (`lost`) where a round has work for them (`rolled_back`).
    fn forget_since(&mut self, n: usize) {
        for c in self.log.split_off(n.min(self.log.len())) {
            let slots: Vec<Slot> = self.kept.range((c, Slot::Header)..=(c, Slot::Trees(usize::MAX))).map(|(k, _)| k.1).collect();
            for s in slots {
                self.unkeep(c, s);
            }
            self.lost.insert(c);
        }
    }

    /// The running transaction committed.
    pub fn committed(&mut self) {
        self.log.clear();
    }

    /// Entries the kept walks hold (tests: walk memory, in links and trees).
    #[cfg(test)]
    pub fn kept_entries(&self) -> usize {
        self.kept.values().map(Walk::entries).sum()
    }
}

/// Takes `stack` as far as the held blobs go, into `w`: one pass, reaching each blob once (`seen`:
/// those it reached already), a blob `w` lacks not again. `on_page` sees each page reached (its
/// blob, its plaintext).
fn extend(tx: &mut Tx<'_>, w: &mut Walk, mut stack: Vec<(Link, At)>, mut seen: BTreeSet<BlobId>, on_page: &mut super::memory::PageVisit<'_>) -> Result<()> {
    while let Some((link, at)) = stack.pop() {
        if w.missing.contains_key(&link.blob) || !seen.insert(link.blob) {
            continue;
        }
        step(tx, w, link, at, false, &mut stack, on_page)?;
    }
    w.prune();
    Ok(())
}

/// One reached link: missing, or opened and followed as far as `w` follows. `arrived`: it was
/// missing when reached. Bytes it cannot follow (not opening under the link, a page not one CBOR
/// value, a node of the wrong level, a page `LinkTree` refuses) end that branch: the commit's
/// judging refuses them.
fn step(tx: &mut Tx<'_>, w: &mut Walk, link: Link, at: At, arrived: bool, stack: &mut Vec<(Link, At)>, on_page: &mut super::memory::PageVisit<'_>) -> Result<()> {
    if let At::Page(p) = at
        && w.shapes.get(&p.tree).is_none_or(|s| s.refused)
    {
        return Ok(());
    }
    if at == At::Chunk || matches!(at, At::Tree(_)) && !arrived {
        if !tx.blobs.held(&link.blob)? {
            w.lack(link, at);
        }
        return Ok(());
    }
    if let At::Lone(t) = at
        && (!w.lone || t.is_some_and(|t| w.refused(t)))
    {
        return Ok(());
    }
    let Some(blob) = tx.blobs.get(&link.blob)? else {
        w.lack(link, at);
        return Ok(());
    };
    osis_base::costs::count("reach: blobs opened", 1);
    let Ok((_, pt)) = osis_blob::open(&blob, &osis_crypto::Secret32::from_bytes(link.key)) else { return Ok(()) };
    if let Ok((level, kids)) = osis_blob::tree::parse_node(&pt) {
        match at {
            // a level-k node links level k - 1 nodes (spec/wire.md §6): no other is followed
            At::Node(want) | At::Tree(want) if want != 0 && want != level => return Ok(()),
            At::Page(_) | At::Lone(_) => {
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
    if sites_of(&pt, &mut sites).is_err() {
        return Ok(());
    }
    let Some(shape) = w.shapes.get_mut(&p.tree) else { return Ok(()) };
    let fits = match sites.as_slice() {
        [LinkSite::List { links, top: true }] => shape.rule.link_page(p.place, links).map(|()| {
            let n = links.len();
            stack.extend(links.iter().enumerate().map(|(i, l)| (*l, At::Page(Pos { place: TreePlace::of(Some(p.place), i, n), ..p }))));
        }),
        _ => shape.rule.leaf(p.place).map(|()| push_sites(w, sites, p.nest + 1, Some(p.tree), stack)),
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
fn push_sites(w: &mut Walk, sites: Vec<LinkSite>, nest: usize, parent: Option<usize>, stack: &mut Vec<(Link, At)>) {
    for s in sites {
        match s {
            LinkSite::Lone(l) => stack.push((l, At::Lone(parent))),
            LinkSite::List { .. } if nest > osis_base::format::MAX_VALUE_DEPTH + 1 => {}
            LinkSite::List { links, .. } => {
                let tree = w.trees_reached;
                w.trees_reached = tree.saturating_add(1);
                w.shapes.insert(tree, Shape { rule: LinkTree::new(osis_crdt::PageParams::wire()), refused: false, parent, refs: 0 });
                if let Some(p) = parent {
                    w.hold_tree(p);
                }
                w.idle.push(tree);
                let n = links.len();
                stack.extend(links.into_iter().enumerate().map(|(i, l)| (l, At::Page(Pos { tree, place: TreePlace::of(None, i, n), nest }))));
            }
        }
    }
}

/// Position tree `tree` cannot be the canonical one: nothing more of it, nor of the positions
/// nested in its leaves, is fetched. The decoders refuse it whatever is missing in it or below
/// it (`osis_crdt` `walk_tree`), so what the walk lacks after is one set whatever order its
/// pages came in.
fn refuse(w: &mut Walk, tree: usize) {
    if let Some(s) = w.shapes.get_mut(&tree) {
        s.refused = true;
    }
    // a nested tree comes after the tree holding it
    let after: Vec<usize> = w.shapes.range(tree + 1..).map(|(t, _)| *t).collect();
    for i in after {
        let below = w.shapes.get(&i).and_then(|s| s.parent).is_some_and(|p| w.refused(p));
        if let Some(s) = w.shapes.get_mut(&i).filter(|_| below) {
            s.refused = true;
        }
    }
    let gone: Vec<BlobId> = w.missing.iter().filter(|(_, (_, at))| matches!(at, At::Page(Pos { tree: t, .. }) | At::Lone(Some(t)) if w.refused(*t))).map(|(b, _)| *b).collect();
    for b in gone {
        w.unlack(&b);
    }
}

/// The walk of `blob`'s header lists given by link: their whole trees.
fn header_walk(tx: &mut Tx<'_>, blob: &CommitBlob) -> Result<Walk> {
    let mut w = Walk::new(false, false);
    let stack = osis_commit::ListField::ALL.into_iter().filter_map(|f| blob.header.links.get(f).copied()).map(|l| (l, At::Node(0))).collect();
    extend(tx, &mut w, stack, BTreeSet::new(), &mut |_, _| Ok(()))?;
    Ok(w)
}

/// The walk of `deltas`' links: pages followed, value roots standing alone with `lone` (below
/// them too with `trees`). A delta that is not one CBOR value links nothing (its commit's
/// judging refuses it).
pub(crate) fn walk_deltas(tx: &mut Tx<'_>, deltas: &[&[u8]], trees: bool, lone: bool, on_page: &mut super::memory::PageVisit<'_>) -> Result<Walk> {
    let mut w = Walk::new(trees, lone);
    let mut stack = Vec::new();
    for d in deltas {
        let mut sites = Vec::new();
        if sites_of(d, &mut sites).is_ok() {
            push_sites(&mut w, sites, 1, None, &mut stack);
        }
    }
    extend(tx, &mut w, stack, BTreeSet::new(), on_page)?;
    Ok(w)
}

/// Pending commit `id`'s header lists did not resolve (`blob`): their walk kept until they may.
/// One pass over the list nodes held.
pub(crate) fn wait_header(tx: &mut Tx<'_>, id: &CommitId, blob: &CommitBlob) -> Result<()> {
    let w = header_walk(tx, blob)?;
    debug_assert!(w.missing().next().is_some(), "header lists of {id:?} missing a blob no walk reaches");
    tx.core.walks.put(*id, Slot::Header, w);
    Ok(())
}

/// Part `ai` of pending commit `id` (`delta`) waits for its pages (and, of a `memory` commit, its
/// values' roots): its walk kept until it lacks nothing. One pass over the pages held.
pub(crate) fn wait_part(tx: &mut Tx<'_>, id: &CommitId, ai: usize, delta: &[u8], memory: bool) -> Result<()> {
    let w = walk_deltas(tx, &[delta], false, memory, &mut |_, _| Ok(()))?;
    tx.core.walks.put(*id, Slot::Part(ai), w);
    Ok(())
}

/// `wait_part` of a part its judging found missing a page: its walk must lack one, or nothing
/// would wake it (the walk and the decoders apply one tree rule, notes/decode-bounds.md).
pub(crate) fn judged_waiting(tx: &mut Tx<'_>, id: &CommitId, ai: usize, delta: &[u8], memory: bool) -> Result<()> {
    wait_part(tx, id, ai, delta, memory)?;
    debug_assert!(tx.core.walks.waits(id, Slot::Part(ai)), "part {ai} of {id:?} judged missing a page its walk does not lack");
    Ok(())
}

/// Memory commit `id` (`blob`, its header resolved): whether a part of it lacks a blob, each
/// such part's walk kept.
pub(crate) fn wait_parts(tx: &mut Tx<'_>, id: &CommitId, blob: &CommitBlob) -> Result<bool> {
    for p in &blob.parts {
        wait_part(tx, id, p.ai, &p.delta, true)?;
    }
    Ok(tx.core.walks.lacks(id))
}

/// Applied memory commit `id`'s value trees: walked, each part's kept until held whole.
fn wait_trees(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    if !tx.core.ix.commits.get(id).is_some_and(|m| m.view.memory) {
        return Ok(());
    }
    let Some(blob) = tx.get_commit(id)? else { return Ok(()) };
    for p in &blob.parts {
        let w = walk_deltas(tx, &[&p.delta], true, true, &mut |_, _| Ok(()))?;
        tx.core.walks.put(*id, Slot::Trees(p.ai), w);
    }
    Ok(())
}

/// The end of a transaction: the pending slots of commits that do not pend go.
pub(crate) fn settle(core: &mut crate::engine::Core) {
    for c in std::mem::take(&mut core.walks.unsettled) {
        if !core.ix.pending.contains_key(&c) {
            core.walks.drop_pending(&c);
        }
    }
}

/// Takes `c`'s walks on from the blobs held for them since they last moved (`Walks::held`):
/// a commit about to be judged sees what the transaction held. Whether a pending slot came to
/// lack nothing.
pub(crate) fn take_on(tx: &mut Tx<'_>, c: &CommitId) -> Result<bool> {
    let Some(a) = tx.core.walks.arrived.remove(c) else { return Ok(false) };
    advance(tx, c, &a)
}

/// Takes `c`'s walks on from the blobs that arrived for them (`Walks::held`): O(those blobs'
/// links and the held blobs below them), never a pass over what each walk held before. Whether a slot of its pending copy
/// came to lack nothing (it may be judged now). A slot lacking nothing goes.
pub(crate) fn advance(tx: &mut Tx<'_>, c: &CommitId, arrived: &BTreeSet<(Slot, BlobId)>) -> Result<bool> {
    let mut ready = false;
    let slots: BTreeSet<Slot> = arrived.iter().map(|x| x.0).collect();
    for s in slots {
        let Some(mut w) = tx.core.walks.kept.remove(&(*c, s)) else { continue };
        tx.core.walks.log.push(*c);
        osis_base::costs::count("reach: walks advanced", 1);
        let mut stack = Vec::new();
        let mut seen = BTreeSet::new();
        let mut r = Ok(());
        for (_, b) in arrived.range((s, BlobId([0; 32]))..=(s, BlobId([0xff; 32]))) {
            if let Some((link, at)) = w.unlack(b) {
                seen.insert(*b);
                r = step(tx, &mut w, link, at, true, &mut stack, &mut |_, _| Ok(()));
                if r.is_err() {
                    break;
                }
            }
        }
        let r = r.and_then(|()| extend(tx, &mut w, stack, seen, &mut |_, _| Ok(())));
        w.roots = Vec::new();
        tx.core.walks.index(*c, s, &mut w);
        if let Err(e) = r {
            // a store error: the walk is unknown, the commit examined again (`lost`)
            tx.core.walks.kept.insert((*c, s), w);
            tx.core.walks.unkeep(*c, s);
            tx.core.walks.lost.insert(*c);
            return Err(e);
        }
        match w.missing.is_empty() {
            true => ready |= !matches!(s, Slot::Trees(_)),
            false => drop(tx.core.walks.kept.insert((*c, s), w)),
        }
    }
    Ok(ready)
}

/// A step or transaction from walks' log length `n` failed and `core` is rolled back: the walks
/// of the commits it touched go, each a round has work for (`round`: pending, or an applied
/// memory commit) due again; one the failure took away is due nowhere, as are trees asked of it
/// (`trees_of`). Else a transaction failing every time it is tried (a sealed fire refused,
/// `Engine::ingest_sealed_fire`) leaves a round due that finds nothing, so the next timer is now
/// and a driver ticking at it tries the transaction again: a loop.
pub(crate) fn rolled_back(core: &mut crate::engine::Core, n: usize) {
    core.walks.forget_since(n);
    let ix = &core.ix;
    let known = |c: &CommitId| ix.pending.contains_key(c) || ix.commits.get(c).is_some_and(|m| m.view.memory);
    core.walks.lost.retain(known);
    core.walks.trees_due.retain(known);
}

/// The start of a `reexamine` round: the walks the arrivals reached taken on, the lost commits'
/// trees walked again. The pending commits to examine: a slot of theirs lacks nothing, or their
/// walks were lost (examining derives them).
pub(crate) fn round(tx: &mut Tx<'_>, arrived: Arrived, lost: BTreeSet<CommitId>) -> Result<BTreeSet<CommitId>> {
    let mut out = BTreeSet::new();
    for (c, blobs) in arrived {
        if advance(tx, &c, &blobs)? {
            out.insert(c);
        }
    }
    for c in lost {
        match tx.core.ix.pending.contains_key(&c) {
            true => drop(out.insert(c)),
            false => wait_trees(tx, &c)?,
        }
    }
    out.retain(|c| tx.core.ix.pending.contains_key(c));
    Ok(out)
}

/// What waiting commits need (`Engine::blob_wants`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Wants {
    /// Reached and not held: to fetch.
    pub missing: BTreeSet<BlobId>,
}

impl Engine {
    /// The blobs commits here wait for (spec/sync-streams.md §5, spec/sync-compaction.md §2 caps): of each pending commit waiting
    /// for blobs, its header lists' trees while they do not resolve, then its waiting parts'
    /// pages and large values' roots; of each memory commit from others applied here, its value
    /// trees (fetched at once: they are held in memory at peers). The whole set: O(its size).
    pub fn blob_wants(&mut self) -> Result<Wants> {
        Ok(Wants { missing: self.core.walks.wanted.keys().copied().collect() })
    }

    /// The blobs commits here came to wait for since the last call and still do: what a holder
    /// of blobs outside the engine's store (sync's own store) looks up once, so a blob it took
    /// before any walk named it (a chunk arriving ahead of the node above it) is handed over when
    /// the walk reaches it. O(the blobs newly wanted).
    pub fn take_wanted(&mut self) -> Vec<BlobId> {
        let w = &mut self.core.walks;
        std::mem::take(&mut w.newly).into_iter().filter(|b| w.wanted.contains_key(b)).collect()
    }

    /// Whether a commit here waits for blob `b` (`blob_wants`, one blob: O(log)).
    pub fn wants_blob(&self, b: &BlobId) -> bool {
        self.core.walks.wants(b)
    }

    /// Debug builds: the blob waits' index is exactly what the kept walks lack, each kept slot's
    /// commit pends (or is an applied memory commit, for its trees), and no kept walk lacks a
    /// blob held here whose arrival is not noted for the next round (a lost wake). With
    /// `fresh`, each pending slot's walk equals one derived afresh from its stored copy (the
    /// drop-time check: one pass over every waiting commit's pages).
    #[cfg(debug_assertions)]
    pub(crate) fn check_walks(&mut self, fresh: bool) -> Result<()> {
        let w = &self.core.walks;
        let mut index: BTreeMap<BlobId, BTreeSet<(CommitId, Slot)>> = BTreeMap::new();
        for ((c, s), walk) in &w.kept {
            assert!(!walk.missing.is_empty(), "blob waits: a kept walk of {c:?} {s:?} lacks nothing");
            // only the frontier: each tree kept holds what a lacked blob lies in
            assert!(walk.idle.is_empty() && walk.roots.is_empty(), "blob waits: a kept walk of {c:?} {s:?} holds more than its frontier");
            let mut refs: BTreeMap<usize, usize> = BTreeMap::new();
            for t in walk.missing.values().filter_map(|x| x.1.tree()).chain(walk.shapes.values().filter_map(|x| x.parent)) {
                *refs.entry(t).or_default() += 1;
            }
            let held: BTreeMap<usize, usize> = walk.shapes.iter().map(|(t, x)| (*t, x.refs)).collect();
            assert!(refs == held, "blob waits: a kept walk of {c:?} {s:?} keeps trees held {held:?}, lacked in or under {refs:?}");
            for b in walk.missing.keys() {
                index.entry(*b).or_default().insert((*c, *s));
            }
            match s {
                Slot::Trees(_) => assert!(self.core.ix.commits.get(c).is_some_and(|m| m.view.memory), "blob waits: trees kept for {c:?}, no applied memory commit"),
                _ => assert!(self.core.ix.pending.contains_key(c), "blob waits: a walk kept for {c:?} {s:?}, not pending"),
            }
        }
        assert!(index == w.wanted, "blob waits: the index is not what the kept walks lack");
        let lacking: Vec<((CommitId, Slot), BlobId, bool)> = w.kept.iter().flat_map(|(k, walk)| walk.missing.iter().map(move |(b, (_, at))| (*k, *b, *at == At::Chunk || matches!(at, At::Tree(_))))).collect();
        let arrived = w.arrived.clone();
        let pending: Vec<((CommitId, Slot), BTreeSet<BlobId>)> = w.kept.iter().filter(|(k, _)| !matches!(k.1, Slot::Trees(_))).map(|(k, walk)| (*k, walk.missing.keys().copied().collect())).collect();
        osis_base::costs::paused(|| osis_base::memo::unrecorded(|| self.read(|tx| {
            for ((c, s), b, chunk) in &lacking {
                let held = if *chunk { tx.blobs.held(b)? } else { tx.blobs.len(b)?.is_some() };
                assert!(!held || arrived.get(c).is_some_and(|x| x.contains(&(*s, *b))), "blob waits: {c:?} {s:?} lacks {b:?}, held here, its arrival not noted (a lost wake)");
            }
            if !fresh {
                return Ok(());
            }
            for ((c, s), kept) in &pending {
                let Some(p) = tx.txn.get_pending(c)? else { continue };
                let Ok(blob) = CommitBlob::decode_stored(&p.bytes) else { continue };
                let delta = match s {
                    Slot::Part(ai) => blob.part(*ai).map(|p| p.delta.as_slice()),
                    _ => None,
                };
                assert!(!matches!(s, Slot::Part(_)) || delta.is_some(), "blob waits: {c:?} keeps a walk for {s:?}, not in its pending copy");
                let again = match delta {
                    Some(d) => walk_deltas(tx, &[d], false, blob.header.ephemeral.is_some(), &mut |_, _| Ok(()))?,
                    None => header_walk(tx, &blob)?,
                };
                let again: BTreeSet<BlobId> = again.missing.keys().copied().collect();
                // a slot with a noted arrival is behind until the round takes it on
                if !arrived.get(c).is_some_and(|x| x.iter().any(|x| x.0 == *s)) {
                    assert!(again == *kept, "blob waits: {c:?} {s:?} kept {kept:?}, derived afresh {again:?}");
                }
            }
            Ok(())
        })))
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
