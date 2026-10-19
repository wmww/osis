//! Undo, redo and history (notes/api.md Undo; spec/commits.md §7). Stacks are derived from the
//! held commits in scope, so they work across devices: a commit is undone while an undo of it
//! is in effect; one at even undo depth (an original or a redo) is a change, odd an undo.

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::write::Committed;
use osis_core::{Ak, CommitId, Tid, Ts};
use osis_node::Mutation;
use std::collections::{BTreeMap, BTreeSet};

/// What undo and history range over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UndoScope {
    /// Every aspect of a thing (a document).
    Thing(Tid),
    /// These aspects (a form).
    Aspects(Vec<(Tid, Ak)>),
    /// The group and every thing in it, transitively (a folder).
    Group(Tid),
}

/// History paging.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryQuery {
    pub limit: usize,
    /// Only entries strictly older than this.
    pub before: Option<Ts>,
}

impl Default for HistoryQuery {
    fn default() -> HistoryQuery {
        HistoryQuery { limit: 100, before: None }
    }
}

/// Why an entry can no longer be undone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// Its body was dropped (compaction, keep-at-most, purge): spec/crdt.md §4.6.
    Compacted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryState {
    Undoable,
    Undone,
    Dropped(DropReason),
}

/// One change in scope, anyone's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryEntry {
    pub commit: CommitId,
    pub actor: Tid,
    /// The authoring node.
    pub node: Tid,
    pub ts: Ts,
    /// Aspects it touched in scope.
    pub aspects: Vec<(Tid, Ak)>,
    /// The commit it undoes, if it is an undo or redo.
    pub undoes: Option<CommitId>,
    pub state: EntryState,
}

struct Change {
    id: CommitId,
    node: Tid,
    actor: Tid,
    ts: Ts,
    undoes: Option<CommitId>,
    active: bool,
    depth: usize,
}

impl Osis {
    fn scope_aspects(&self, s: &UndoScope) -> Result<Vec<(Tid, Ak)>> {
        let all = || -> Result<Vec<(Tid, Ak)>> { self.engine(|e| e.all_aspects()).map_err(Error::from) };
        Ok(match s {
            UndoScope::Aspects(v) => v.iter().map(|(t, a)| (self.read(|r| r.resolve(*t)), a.clone())).collect(),
            UndoScope::Thing(t) => {
                let t = self.read(|r| r.resolve(*t));
                all()?.into_iter().filter(|(x, _)| *x == t).collect()
            }
            UndoScope::Group(g) => {
                let g = self.read(|r| r.resolve(*g));
                all()?.into_iter().filter(|(x, _)| *x == g || self.groups_of(*x).contains(&g)).collect()
            }
        })
    }

    /// Changes in scope, newest first, with whether each is in effect and its undo depth.
    fn scope_changes(&self, scope: &[(Tid, Ak)]) -> Vec<Change> {
        let raw = self.engine(|e| e.changes(scope));
        let mut out: Vec<Change> = raw.into_iter().map(|(id, node, actor, ts, undoes)| Change { id, node, actor, ts, undoes, active: true, depth: 0 }).collect();
        // undoers are newer: newest first decides activity; oldest first decides depth
        let mut undone: BTreeSet<CommitId> = BTreeSet::new();
        for c in out.iter_mut() {
            c.active = !undone.contains(&c.id);
            if c.active && let Some(u) = c.undoes {
                undone.insert(u);
            }
        }
        let mut depth: BTreeMap<CommitId, usize> = BTreeMap::new();
        for c in out.iter_mut().rev() {
            c.depth = c.undoes.and_then(|u| depth.get(&u)).map_or(0, |d| d + 1);
            depth.insert(c.id, c.depth);
        }
        out
    }

    fn undo_target(&self, scope: &UndoScope, redo: bool) -> Result<Option<CommitId>> {
        let me = self.me();
        let aks = self.scope_aspects(scope)?;
        Ok(self.scope_changes(&aks).into_iter().find(|c| c.actor == me && c.active && (c.depth % 2 == 1) == redo).map(|c| c.id))
    }

    fn undo_one(&self, target: CommitId) -> Result<Option<Committed>> {
        let mut m = Mutation::new();
        m.act_as(self.me()).undo(target);
        self.engine(|e| match e.commit(m)? {
            Some(id) => Ok(Some(Committed { commit: id, ts: e.header(&id).map(|h| h.ts).unwrap_or_default() })),
            None => Ok(None),
        })
    }

    /// Undoes this actor's newest change in effect in scope; `None` when there is none.
    pub fn undo(&self, scope: &UndoScope) -> Result<Option<Committed>> {
        match self.undo_target(scope, false)? {
            Some(c) => self.undo_one(c),
            None => Ok(None),
        }
    }

    /// Redoes this actor's newest undo in effect in scope; `None` when there is none.
    pub fn redo(&self, scope: &UndoScope) -> Result<Option<Committed>> {
        match self.undo_target(scope, true)? {
            Some(c) => self.undo_one(c),
            None => Ok(None),
        }
    }

    /// Undoes any held change this node may write (an admin reverting someone else's).
    pub fn undo_commit(&self, id: CommitId) -> Result<Option<Committed>> {
        if self.engine(|e| e.header(&id)).is_none() {
            return Err(Error::Invalid("unknown commit".into()));
        }
        self.undo_one(id)
    }

    /// Everyone's changes in scope, newest first.
    pub fn history(&self, scope: &UndoScope, q: HistoryQuery) -> Result<Vec<HistoryEntry>> {
        let aks = self.scope_aspects(scope)?;
        let in_scope: BTreeSet<&(Tid, Ak)> = aks.iter().collect();
        let changes = self.scope_changes(&aks);
        self.engine(|e| {
            let mut out = Vec::new();
            for c in changes.into_iter().filter(|c| q.before.is_none_or(|b| c.ts < b)).take(q.limit) {
                let Some(h) = e.header(&c.id) else { continue };
                let aspects: Vec<(Tid, Ak)> = h.aspects.iter().map(|a| (a.tid, a.ak.clone())).filter(|k| in_scope.contains(k)).collect();
                let dropped = aspects.iter().any(|(t, a)| !e.holds_body(&c.id, t, a));
                let state = if !c.active {
                    EntryState::Undone
                } else if dropped {
                    EntryState::Dropped(DropReason::Compacted)
                } else {
                    EntryState::Undoable
                };
                out.push(HistoryEntry { commit: c.id, actor: c.actor, node: c.node, ts: c.ts, aspects, undoes: c.undoes, state });
            }
            Ok(out)
        })
    }
}
