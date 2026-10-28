//! A sequence's placement for a node keeping it in its store beside the sequence's pages
//! (osis-node, notes/node.md Paged state): the cached placement (`seq_lin::Lin`) in its stored
//! form (a top, the rows of each block by arena id, the dot map's chunks by first dot), loaded
//! in part, with the rows, chunks and records an operation needs loaded on a miss.
//!
//! A placement loaded in part (`SeqPlace::from_top`) has every block and chunk a stub until
//! filled; attached to a sequence whose records are loaded in part (`Fragment::set_seq_place`,
//! the loaded pages' dot ranges given by `cover`), a join follows it and an op by index resolves
//! through it as through a whole one, except that whatever looks at a stub or at a record
//! outside the cover is a miss (`misses`): the follow fails (the sequence drops the placement)
//! and an op's result is void. The caller loads what was missed and runs it again; what it
//! writes back is `diff` against the placement as stored.

use crate::fragment::Fragment;
use crate::seq_lin::Lin;
use crate::stamp::Dot;
use std::sync::Arc;

/// A placed node of the stored form: its first element, element count, whether it is a
/// creation chain, the element its chosen edge names (`None`: HEAD, `END` or a virtual anchor),
/// whether that edge names HEAD, whether it is visible, and its depth less its block's shift.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaceRow {
    pub dot: Dot,
    pub span: u64,
    pub created: bool,
    pub parent: Option<Dot>,
    pub head: bool,
    pub shown: bool,
    pub depth: i64,
}

/// A block of the stored form: arena id, rows, visible rows, least row depth (unshifted) and
/// depth shift.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaceBlock {
    pub id: usize,
    pub len: usize,
    pub shown: usize,
    pub min: i64,
    pub shift: i64,
}

/// Everything of a placement but its rows and dot-map entries: the block size, the dot map's
/// entry count, the anchors naming no element, the nodes on broken cycles (§6.2), the blocks in
/// order, the first dots of the dot map's chunks after the first, and a stamp at or above every
/// position write's (`None`: unknown; a write stamped above it skips its anchor's children's
/// records).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaceTop {
    pub cap: usize,
    pub map_len: usize,
    pub waiting: Vec<Dot>,
    pub cyc: Vec<Dot>,
    pub blocks: Vec<PlaceBlock>,
    pub chunks: Vec<Dot>,
    pub newest: Option<crate::stamp::Stamp>,
}

/// What a placement changed against the one it descends from (`SeqPlace::diff`): the loaded
/// blocks to write (by id), the blocks gone, the loaded dot-map chunks to write (by first dot,
/// `None` the first) and whether the chunk list changed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlaceDiff {
    pub blocks: Vec<usize>,
    pub gone: Vec<usize>,
    pub chunks: Vec<Option<Dot>>,
    pub dir: bool,
}

/// What a placement held in part missed since the last call: blocks by id, dot-map chunks by
/// first dot, record ranges outside the cover, every record; work units its follows charged
/// (rows and blocks looked at, about one per row of a whole pass).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlaceMisses {
    pub blocks: Vec<usize>,
    pub chunks: Vec<Option<Dot>>,
    pub recs: Vec<(Dot, Dot)>,
    /// Every record (presence of a sequence whose loaded records show no write, an edit whose
    /// read differs from its base near the change, a whole pass).
    pub all: bool,
    /// `all` from a whole pass over the records held (`Partial::whole_pass`: a layered follow or
    /// a placement failing for a reason other than a miss), not a look at every record.
    pub whole: bool,
    pub work: usize,
}

impl PlaceMisses {
    pub fn any(&self) -> bool {
        !self.blocks.is_empty() || !self.chunks.is_empty() || !self.recs.is_empty() || self.all
    }
}

/// A sequence's placement (§6), shared by copies.
#[derive(Clone, Debug)]
pub struct SeqPlace(pub(crate) Arc<Lin>);

impl SeqPlace {
    pub fn top(&self) -> PlaceTop {
        self.0.top()
    }
    /// Block `id`'s rows in order; `None` for a stub or no such block.
    pub fn rows(&self, id: usize) -> Option<Vec<PlaceRow>> {
        self.0.rows_of(id)
    }
    /// The entries (row's first dot, block id) of the dot-map chunk starting at `lo` (`None`:
    /// the first chunk); `None` for a stub.
    pub fn chunk(&self, lo: Option<&Dot>) -> Option<Vec<(Dot, usize)>> {
        self.0.chunk_of(lo)
    }
    /// A placement loaded in part (every block and chunk a stub); `None` if `t` is inconsistent.
    pub fn from_top(t: &PlaceTop) -> Option<SeqPlace> {
        Lin::from_top(t).map(|l| SeqPlace(Arc::new(l)))
    }
    /// Loads stub block `id`'s rows; `false` if they do not fit its counts (damaged).
    pub fn fill(&mut self, id: usize, rows: Vec<PlaceRow>) -> bool {
        Arc::make_mut(&mut self.0).fill(id, rows)
    }
    /// Loads a stub chunk's entries; `false` if they do not fit (damaged).
    pub fn fill_chunk(&mut self, lo: Option<&Dot>, e: Vec<(Dot, usize)>) -> bool {
        Arc::make_mut(&mut self.0).fill_chunk(lo, e)
    }
    /// The stub blocks and chunks.
    pub fn stubs(&self) -> (Vec<usize>, Vec<Option<Dot>>) {
        self.0.stubs()
    }
    /// Whether everything is loaded; then it is a whole placement (no misses, no cover).
    pub fn complete(&mut self) -> bool {
        self.0.partial().is_none() || Arc::make_mut(&mut self.0).complete()
    }
    /// Whether it is held in part.
    pub fn is_partial(&self) -> bool {
        self.0.partial().is_some()
    }
    /// Sets the dot ranges `[lo, hi)` (`None` unbounded) whose records are loaded.
    pub fn cover(&self, ranges: Vec<(Option<Dot>, Option<Dot>)>) {
        if let Some(p) = self.0.partial() {
            p.set_cover(ranges);
        }
    }
    /// What was missed since the last call, by this placement and its copies.
    pub fn misses(&self) -> PlaceMisses {
        let Some(p) = self.0.partial() else { return PlaceMisses::default() };
        let m = p.take();
        PlaceMisses { blocks: m.blocks.into_iter().collect(), chunks: m.chunks.into_iter().collect(), recs: m.recs, all: m.all, whole: m.whole, work: m.work }
    }
    /// What changed against `old`; `None` if it does not descend from `old` (a whole pass or
    /// load since).
    pub fn diff(&self, old: &SeqPlace) -> Option<PlaceDiff> {
        self.0.diff(&old.0)
    }
    /// Placed nodes, hidden ones included.
    pub fn len(&self) -> usize {
        self.0.p.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Visible elements.
    pub fn shown(&self) -> usize {
        self.0.p.shown()
    }
    /// The visible elements `r` (by index, clamped), in order; misses noted.
    pub fn visible(&self, r: std::ops::Range<usize>) -> Vec<Dot> {
        self.0.p.vis_range(r).into_iter().map(|x| x.dot.clone()).collect()
    }
    /// The same placement (chars aside), both loaded whole (tests, checks).
    pub fn same(&self, o: &SeqPlace) -> bool {
        self.0.same(&o.0)
    }
    /// Every element in order, hidden ones included, with its visibility (tests, checks).
    pub fn order(&self) -> Vec<(Dot, bool)> {
        self.0.p.iter().flat_map(|r| (0..r.span).map(move |i| (crate::seq_span::nth(&r.dot, i), r.shown))).collect()
    }
}

impl Fragment {
    /// The placement of the sequence here (a whole pass if none is cached; cached from then on).
    pub fn seq_place(&self) -> Option<SeqPlace> {
        match self {
            Fragment::Seq(s) => Some(SeqPlace(s.lin())),
            _ => None,
        }
    }
    /// The placement cached by the sequence here, if any.
    pub fn seq_place_cached(&self) -> Option<SeqPlace> {
        match self {
            Fragment::Seq(s) => s.lin_cached().map(SeqPlace),
            _ => None,
        }
    }
    /// Caches `p` as the placement of the sequence here (`None`: drops it). A text's visible
    /// chars come from `fill_chars`.
    pub fn set_seq_place(&mut self, p: Option<SeqPlace>) {
        if let Fragment::Seq(s) = self {
            s.set_lin(p.map(|p| p.0));
        }
    }
    /// Loads into `p` (for a text) the visible chars of its loaded rows from the records here.
    pub fn fill_chars(&self, p: &mut SeqPlace) {
        if let Fragment::Seq(s) = self
            && s.text
        {
            Arc::make_mut(&mut p.0).fill_chars(s.elems());
        }
    }
    /// Follows a copy of `p` through joining `delta` (the delta's fragment at this sequence)
    /// into the sequence here, which stays as it is: whether it followed. A placement held in
    /// part notes what it missed, so the caller can load it before the join itself.
    pub fn dry_follow(&self, delta: &Fragment, p: &SeqPlace) -> bool {
        match (self, delta) {
            (Fragment::Seq(s), Fragment::Seq(d)) => crate::seq::dry_follow(s, d, p.0.clone()),
            _ => false,
        }
    }
}
