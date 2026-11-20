//! The permission walk along stated paths (notes/perm-paths.md; draft spec
//! notes/a1-spec/permissions.md §1, §2, §5.1): every edge-class part (edge writes, vouches) is
//! judged along the one path its commit states for its thing, in key order, each lowering judged
//! once. Not yet called by the engine (A1 steps 2 and 3b wire it in).
//!
//! The input is plain structs, independent of the header's types; the output is per part
//! (`Status`), per edge (history, point queries, final values), the trusted writes left void,
//! the dispute set and, per update, `Changed`.

mod walk;

use crate::types::{Edge, Frontier, WriteId};
use osis_base::{CommitId, Role, Tid, Ts};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub use walk::{Counts, History, Key};

/// A held role commit's edge-class parts.
#[derive(Clone, Debug)]
pub struct Commit {
    pub id: CommitId,
    pub ts: Ts,
    pub signer: Tid,
    /// In the header's order: a part's index here is its `WriteId` index.
    pub parts: Vec<Part>,
}

/// One edge-class part: what it writes on `on`, along the path the commit states for `on`.
#[derive(Clone, Debug)]
pub struct Part {
    pub on: Tid,
    /// [A1..Ak]: the things between the signer and `on` (draft §1 Path).
    pub path: Vec<Tid>,
    pub kind: PartKind,
}

#[derive(Clone, Debug)]
pub enum PartKind {
    Edge(EdgeWrite),
    /// A `vouches.0` entry (draft §5.1 Vouches): walked as an edge-class part; its entries are
    /// read by step 3b.
    Vouch { removal: CommitId, list: Frontier },
}

/// A `roles.0` write on `holder`'s grant.
#[derive(Clone, Debug)]
pub struct EdgeWrite {
    pub holder: Tid,
    /// `None`: a removal.
    pub value: Option<Edge>,
    /// A removal of another holder's grant with none that is no self-removal is a finalize.
    pub frontier: Option<Arc<Frontier>>,
    /// The holder whose edge on `on` is the remaining admin the write names (header `remains`).
    pub remains: Option<Tid>,
    /// The adminless mark (header flags bit 1).
    pub adminless: bool,
}

/// What the settled walk did with a part.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Applied,
    /// Applied as an invite grant (draft §2).
    Invited,
    /// A lowering judged void: its drops would take its authority or its remaining admin.
    Void,
    /// In D: put in question by a lowering, or a trusted write's seed.
    Dropped,
    /// Held, applying in no pass.
    Unapplied,
}

/// What an update changed: the parts whose status changed, and per edge (holder, target) the
/// earliest key from which its history changed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Changed {
    pub parts: BTreeSet<WriteId>,
    pub edges: BTreeMap<(Tid, Tid), Key>,
}

/// The walk over a held set of role commits, under a trust set.
#[derive(Clone)]
pub struct Paths {
    w: walk::Walk,
}

impl Paths {
    /// An empty held set over `records` (thing to mint admin) and `trust`.
    pub fn new(records: &BTreeMap<Tid, Tid>, trust: BTreeSet<WriteId>) -> Paths {
        Paths { w: walk::Walk::new(records, trust) }
    }

    /// The settled walk of `commits` from scratch.
    pub fn evaluate(records: &BTreeMap<Tid, Tid>, trust: BTreeSet<WriteId>, commits: &[Commit]) -> Paths {
        let mut p = Paths::new(records, trust);
        p.add(commits);
        p
    }

    /// Adds held commits (a commit already held is ignored) and settles the walk again.
    pub fn add(&mut self, commits: &[Commit]) -> Changed {
        self.w.add(commits)
    }

    /// Replaces the trust set and settles from scratch.
    pub fn set_trust(&mut self, trust: BTreeSet<WriteId>) -> Changed {
        self.w.set_trust(trust)
    }

    pub fn status(&self, id: &WriteId) -> Option<Status> {
        self.w.status(id)
    }

    /// Every held part's status.
    pub fn statuses(&self) -> BTreeMap<WriteId, Status> {
        self.w.statuses()
    }

    /// The part's key (draft §5.1 step 1).
    pub fn key(&self, id: &WriteId) -> Option<Key> {
        self.w.key_of(id)
    }

    /// The applied writes on (holder, target) in key order.
    pub fn history(&self, holder: &Tid, target: &Tid) -> History {
        self.w.history(holder, target)
    }

    /// Every edge with an applied write, and every record edge, with its history (empty for a
    /// record edge nothing wrote).
    pub fn histories(&self) -> BTreeMap<(Tid, Tid), History> {
        self.w.histories()
    }

    /// The value of (holder, target) just before `key`: the last applied write before it, else
    /// the record edge's admin, else none.
    pub fn value_before(&self, holder: &Tid, target: &Tid, key: &Key) -> Option<Edge> {
        self.w.value_before(holder, target, key)
    }

    /// The role (holder, target) gives just before `key`, its `until` read at `key`'s `ts`.
    pub fn role_before(&self, holder: &Tid, target: &Tid, key: &Key) -> Option<Role> {
        self.w.role_before(holder, target, key)
    }

    /// The final role of each edge the settled walk set (and each record edge), every `until`
    /// counted removed, and the invite it gives.
    pub fn finals(&self) -> BTreeMap<(Tid, Tid), (Option<Role>, Option<Role>)> {
        self.w.finals()
    }

    /// Trusted writes the settled walk does not apply (void: their seeds lost).
    pub fn void_trusted(&self) -> BTreeSet<WriteId> {
        self.w.void_trusted()
    }

    /// The held lowerings whose trust would change what applies or the final roles
    /// (draft §5.1 Trust set, dispute; `Candidates::Explicit`): one walk per candidate.
    pub fn disputes(&self) -> BTreeSet<WriteId> {
        self.w.disputes()
    }

    /// Work done since construction.
    pub fn counts(&self) -> Counts {
        self.w.counts
    }
}
