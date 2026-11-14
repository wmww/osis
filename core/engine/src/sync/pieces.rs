//! The linked blobs of a body (spec/sync-judgement.md §1: the chunk, tree-node and page blobs its
//! deltas link and the chunk trees of its header lists given by link go under every sync ID the
//! body does, as the same blobs with a filler wrap), one step at a time: a body's roots
//! (`Engine::piece_roots`), then what lies one step below each held node (`Engine::piece_below`).
//! A node is immutable (content-addressed), so what lies below it is a memo over whether it is
//! held alone: a body sharing most of its tree with another reads only its new nodes.

use super::PartSet;
use crate::engine::Engine;
use crate::error::Result;
use osis_base::memo::Memo;
use osis_base::{BlobId, CommitId, Link, Tid};
use std::sync::Arc;

/// One link to a piece: the link, the thing whose dedup secret checks its content hash (none: a
/// header list's tree, checked by its commit), and whether it is known to be a chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PieceLink {
    link: Link,
    thing: Option<Tid>,
    leaf: bool,
}

impl PieceLink {
    pub fn new(link: Link, thing: Option<Tid>, leaf: bool) -> PieceLink {
        PieceLink { link, thing, leaf }
    }

    pub fn blob(&self) -> BlobId {
        self.link.blob
    }
}

impl Engine {
    /// The links of the body of held commit `c` made of `parts` (`Engine::piece_roots`).
    pub(crate) fn piece_roots_now(&mut self, c: &CommitId, parts: &PartSet) -> Result<Vec<PieceLink>> {
        let c = *c;
        let parts = parts.clone();
        self.read(|tx| {
            let Some(m) = tx.core.ix.commits.get(&c).cloned() else { return Ok(Vec::new()) };
            let mut out = Vec::new();
            for ai in parts.iter().copied().filter(|ai| m.holds(*ai)) {
                let Some(t) = m.header.aspects.get(ai).map(|a| a.tid) else { continue };
                out.extend(crate::retention::freed::part_links(tx, &c, ai)?.into_iter().map(|l| PieceLink::new(l, Some(t), false)));
            }
            if let Some(blob) = tx.get_commit(&c)? {
                out.extend(osis_commit::ListField::ALL.into_iter().filter_map(|f| blob.header.links.get(f).copied()).map(|l| PieceLink::new(l, None, false)));
            }
            out.sort_unstable();
            out.dedup();
            Ok(out)
        })
    }

    /// What lies one step below piece `p` (`Engine::piece_below`), through the memo.
    pub(crate) fn piece_below_now(&mut self, p: &PieceLink) -> Result<Option<Arc<Vec<PieceLink>>>> {
        Memo::get_in(self, |e| &e.core.pieces_below, p, |e| e.piece_below_read(p))
    }

    fn piece_below_read(&mut self, p: &PieceLink) -> Result<Option<Arc<Vec<PieceLink>>>> {
        let p = *p;
        self.read(|tx| {
            if !tx.blobs.held(&p.link.blob)? {
                return Ok(None);
            }
            if p.leaf {
                return Ok(Some(Arc::default()));
            }
            let Some(bytes) = tx.blobs.get(&p.link.blob)? else { return Ok(Some(Arc::default())) };
            osis_base::costs::count("pieces: nodes decoded", 1);
            let dedup = p.thing.and_then(|t| tx.core.dedup(&t));
            let kids = match crate::engine::large::kids_of(dedup.as_ref(), &p.link, &bytes) {
                Some((leaf, kids)) => kids.into_iter().map(|k| PieceLink::new(k, p.thing, leaf)).collect(),
                None => Vec::new(),
            };
            Ok(Some(Arc::new(kids)))
        })
    }
}
