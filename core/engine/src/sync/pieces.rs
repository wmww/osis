//! The linked blobs of a body (spec/sync-judgement.md §1: the chunk, tree-node and page blobs its
//! deltas link and the chunk trees of its header lists given by link go under every sync ID the
//! body does, as the same blobs with a filler wrap): what this node holds of them and what it
//! lacks. Walked through the held node and page blobs, so the answer moves as a blob is held or
//! released (`blobs::Cipher` stamps each by ID).

use super::PartSet;
use crate::engine::{Engine, Tx};
use crate::error::Result;
use osis_base::{BlobId, CommitId, Link};
use osis_crypto::Secret32;
use std::collections::BTreeSet;
use std::sync::Arc;

/// The linked blobs ("pieces") of a body, as far as the held node and page blobs reach.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pieces {
    /// Held by the engine.
    pub held: BTreeSet<BlobId>,
    /// Linked and not held; what lies below a node not held is unknown until it is.
    pub missing: BTreeSet<BlobId>,
}

/// One link to walk: the dedup secret its content hash is checked under (none: a header list's
/// tree, checked by its commit), and whether it is known to be a chunk.
type Todo = (Link, Option<Secret32>, bool);

fn walk(tx: &mut Tx<'_>, mut stack: Vec<Todo>) -> Result<Pieces> {
    let mut out = Pieces::default();
    let mut seen = BTreeSet::new();
    while let Some((l, dedup, leaf)) = stack.pop() {
        if !seen.insert(l.blob) {
            continue;
        }
        if !tx.blobs.held(&l.blob)? {
            out.missing.insert(l.blob);
            continue;
        }
        out.held.insert(l.blob);
        if leaf {
            continue;
        }
        let Some(bytes) = tx.blobs.get(&l.blob)? else { continue };
        if let Some((leaf, kids)) = crate::engine::large::kids_of(dedup.as_ref(), &l, &bytes) {
            stack.extend(kids.into_iter().map(|k| (k, dedup.clone(), leaf)));
        }
    }
    osis_base::costs::count("pieces: blobs walked", seen.len() as u64);
    Ok(out)
}

impl Engine {
    /// The pieces of the body of held commit `c` made of `parts` (`Engine::pieces`).
    pub(crate) fn pieces_now(&mut self, c: &CommitId, parts: &PartSet) -> Result<Arc<Pieces>> {
        let c = *c;
        let parts = parts.clone();
        self.read(|tx| {
            let Some(m) = tx.core.ix.commits.get(&c).cloned() else { return Ok(Arc::default()) };
            let mut stack: Vec<Todo> = Vec::new();
            for ai in parts.iter().copied().filter(|ai| m.holds(*ai)) {
                let Some(t) = m.header.aspects.get(ai).map(|a| a.tid) else { continue };
                let dedup = tx.core.dedup(&t);
                stack.extend(crate::retention::freed::part_links(tx, &c, ai)?.into_iter().map(|l| (l, dedup.clone(), false)));
            }
            if let Some(blob) = tx.get_commit(&c)? {
                stack.extend(osis_commit::ListField::ALL.into_iter().filter_map(|f| blob.header.links.get(f).copied()).map(|l| (l, None, false)));
            }
            Ok(Arc::new(walk(tx, stack)?))
        })
    }
}
