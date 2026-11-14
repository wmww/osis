//! The pieces followed under each S (spec/sync-judgement.md §1): every piece the must-hold bodies
//! here link, one `Effects` key per (S, piece blob), each judged on its own (`judge::piece`). A
//! piece acts while something links it: a must-hold body (its roots) or an acting node one step
//! above. A node is immutable, so a body sharing most of its tree with one followed already
//! adds only its new nodes: a small edit to a large value judges the pieces it wrote, not its
//! tree. Keyed by blob, not link: an edit's new node may link a reused chunk by another link
//! (another delete-key claim), the same blob.
//!
//! A held piece nothing links any more stays followed, dormant (judged as it moves, acting on
//! nothing), until its blob is released here: a reader that holds an edit's body before its new
//! nodes drops the old tree and takes it up again as they arrive, without judging it again.
//! Bound: one key per held piece some must-hold body under S linked here; a restart follows only
//! what must-hold bodies link.

use super::judge::{Act, PieceJudged};
use osis_base::memo::Effects;
use osis_base::{BlobId, CommitId, SyncId};
use osis_engine::sync::PieceLink;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// What links a piece under S.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Linker {
    /// A must-hold body, and whether its pieces are repaired (an own body a repair did not write).
    Body { c: CommitId, repairs: bool },
    /// An acting node one step above.
    Node(BlobId),
}

/// One followed piece: the link it is walked by (the first that linked it), what links it (none:
/// dormant), its last judgement, and the acts taken on it since it last woke.
#[derive(Clone, Debug)]
struct Linked {
    link: PieceLink,
    by: BTreeSet<Linker>,
    judged: Option<PieceJudged>,
    done: BTreeSet<Act>,
}

impl Linked {
    fn kids(&self) -> Arc<Vec<PieceLink>> {
        self.judged.as_ref().map(|j| j.kids.clone()).unwrap_or_default()
    }
    fn lost(&self) -> bool {
        self.judged.as_ref().is_some_and(|j| j.acts.iter().any(|a| matches!(a, Act::Repair(_))))
    }
}

pub(crate) type Key = (SyncId, BlobId);

/// Per own body, its lost pieces to repair in one commit.
pub(crate) type Repairs = BTreeMap<CommitId, BTreeSet<BlobId>>;

#[derive(Clone)]
pub(crate) struct Pieces {
    pub judged: Effects<Key, PieceJudged>,
    linked: BTreeMap<Key, Linked>,
    /// Pieces judged, woken or gone dormant since the last `acts`.
    touched: BTreeSet<Key>,
    /// Lost pieces a linker joined since the last `acts`: repaired in the bodies over them.
    relinked: BTreeSet<Key>,
}

impl Default for Pieces {
    fn default() -> Self {
        Pieces { judged: Effects::new("read: pieces"), linked: BTreeMap::new(), touched: BTreeSet::new(), relinked: BTreeSet::new() }
    }
}

impl Pieces {
    /// Body `c`'s links moved from `was` (roots, repairs) to `now`: what it links under S follows.
    pub fn body(&mut self, s: &SyncId, c: &CommitId, was: (&[PieceLink], bool), now: (&[PieceLink], bool)) {
        if was == now {
            return;
        }
        let (old, new) = (Linker::Body { c: *c, repairs: was.1 }, Linker::Body { c: *c, repairs: now.1 });
        for p in now.0 {
            self.link(s, p, new);
        }
        let kept: BTreeSet<BlobId> = now.0.iter().map(PieceLink::blob).collect();
        for p in was.0 {
            if old != new || !kept.contains(&p.blob()) {
                self.unlink((*s, p.blob()), old);
            }
        }
    }

    /// How many pieces are followed, acting or dormant.
    pub fn followed(&self) -> usize {
        self.linked.len()
    }

    /// The link followed piece `k` is walked by (`None`: not followed; a key dropped while due is
    /// not judged).
    pub fn link_of(&self, k: &Key) -> Option<PieceLink> {
        self.linked.get(k).map(|e| e.link)
    }

    /// A settled piece: an acting one's kids follow what lies below it; a dormant one no longer
    /// held is dropped.
    pub fn settled(&mut self, k: &Key, now: PieceJudged) {
        let Some(e) = self.linked.get_mut(k) else { return };
        self.touched.insert(*k);
        let was = e.kids();
        let held = now.held;
        e.judged = Some(now);
        if e.by.is_empty() {
            if !held {
                self.linked.remove(k);
                self.judged.unwant(k);
            }
            return;
        }
        let kids = e.kids();
        if was == kids {
            return;
        }
        let by = Linker::Node(k.1);
        for p in kids.iter() {
            self.link(&k.0, p, by);
        }
        let kept: BTreeSet<BlobId> = kids.iter().map(PieceLink::blob).collect();
        for p in was.iter().filter(|p| !kept.contains(&p.blob())) {
            self.unlink((k.0, p.blob()), by);
        }
    }

    /// `by` links piece `p` under S: followed from now on; a dormant one wakes, and what lies below
    /// it with it.
    fn link(&mut self, s: &SyncId, p: &PieceLink, by: Linker) {
        let mut todo = vec![(*p, by)];
        while let Some((p, by)) = todo.pop() {
            let k = (*s, p.blob());
            let e = self.linked.entry(k).or_insert_with(|| Linked { link: p, by: BTreeSet::new(), judged: None, done: BTreeSet::new() });
            if e.judged.is_none() && e.by.is_empty() {
                self.judged.want(k);
            }
            let woke = e.by.is_empty();
            if !e.by.insert(by) {
                continue;
            }
            if e.lost() {
                self.relinked.insert(k);
            }
            if woke {
                self.touched.insert(k);
                todo.extend(e.kids().iter().map(|kid| (*kid, Linker::Node(k.1))));
            }
        }
    }

    /// `by` no longer links `k`: a piece nothing links goes dormant (dropped if not held), and so,
    /// in turn, what lies below it.
    fn unlink(&mut self, k: Key, by: Linker) {
        let mut todo = vec![(k, by)];
        while let Some((k, by)) = todo.pop() {
            let Some(e) = self.linked.get_mut(&k) else { continue };
            if !e.by.remove(&by) || !e.by.is_empty() {
                continue;
            }
            self.touched.insert(k);
            todo.extend(e.kids().iter().map(|p| ((k.0, p.blob()), Linker::Node(k.1))));
            if !e.judged.as_ref().is_some_and(|j| j.held) {
                self.linked.remove(&k);
                self.judged.unwant(&k);
            }
        }
    }

    /// What the pieces touched since the last call newly call for (an acting piece's acts not
    /// taken since it woke), with the pieces of each own body over a lost one to repair
    /// (spec/sync-ids.md §1 Repair: a body's pieces in one commit; again when a body comes to link
    /// one already lost).
    pub fn acts(&mut self) -> (Vec<(Key, Act)>, Repairs) {
        let mut out = Vec::new();
        let mut lost = std::mem::take(&mut self.relinked);
        for k in std::mem::take(&mut self.touched) {
            let Some(e) = self.linked.get_mut(&k) else { continue };
            let now: BTreeSet<Act> = match &e.judged {
                Some(j) if !e.by.is_empty() => j.acts.clone(),
                _ => BTreeSet::new(),
            };
            for a in now.difference(&e.done) {
                match a {
                    Act::Repair(_) => drop(lost.insert(k)),
                    a => out.push((k, a.clone())),
                }
            }
            e.done = now;
        }
        (out, self.repairs(&lost))
    }

    /// The pieces of `lost` to repair, per own body over them a repair did not write.
    fn repairs(&self, lost: &BTreeSet<Key>) -> Repairs {
        let mut out = Repairs::new();
        for k in lost {
            let mut seen = BTreeSet::new();
            let mut todo = vec![*k];
            while let Some(at) = todo.pop() {
                if !seen.insert(at) {
                    continue;
                }
                for by in self.linked.get(&at).map(|e| &e.by).into_iter().flatten() {
                    match by {
                        Linker::Body { c, repairs: true } => drop(out.entry(*c).or_default().insert(k.1)),
                        Linker::Body { .. } => {}
                        Linker::Node(b) => todo.push((at.0, *b)),
                    }
                }
            }
        }
        out
    }
}
