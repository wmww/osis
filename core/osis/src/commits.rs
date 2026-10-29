//! The commit query, and undo, redo and revert over it (notes/api.md Commits; spec/commits.md
//! §7, spec/crdt.md §4.6). Everything is derived from the held commits, nothing is stored: a
//! revert is a commit naming the commit it reverts; a commit is in effect while no revert in
//! effect names it; undo and redo pick a commit by query and revert it.

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::watch::{CommitInfo, lock};
use crate::write::Committed;
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_commit::Kind;
use osis_node::Mutation;
use osis_node::undo::HeldCommit;
use std::collections::{BTreeMap, BTreeSet};

/// Which aspects a query, undo or redo ranges over; resolved when used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Every aspect of a thing (a document).
    Thing(Tid),
    /// These aspects (a form).
    Aspects(Vec<(Tid, Ak)>),
    /// The group and every thing in it, transitively (a folder).
    Group(Tid),
}

/// What a commit is, from its header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommitKind {
    /// A content change.
    Change,
    /// A content commit reverting another (an undo, or a redo: a revert of a revert).
    Revert,
    /// A membership change (grants, removals, rotations, labels).
    Membership,
    /// A compaction or roster snapshot.
    Snapshot,
    /// An import after a move.
    Import,
}

/// A filter over the held commits. Empty fields match everything; results are newest first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommitQuery {
    pub scope: Option<Scope>,
    /// By any of these actors.
    pub actors: Vec<Tid>,
    /// Of any of these kinds.
    pub kinds: Vec<CommitKind>,
    /// Reverts of this commit.
    pub reverts: Option<CommitId>,
    /// The commit this one reverts.
    pub reverted_by: Option<CommitId>,
    pub in_effect: Option<bool>,
    /// `ts >= since`.
    pub since: Option<Ts>,
    /// `ts < until`.
    pub until: Option<Ts>,
    /// Paging: only commits after this one in result order (older).
    pub after: Option<CommitId>,
    pub limit: Option<usize>,
}

impl CommitQuery {
    pub fn new() -> CommitQuery {
        CommitQuery::default()
    }
    pub fn scope(mut self, s: Scope) -> Self {
        self.scope = Some(s);
        self
    }
    pub fn actor(mut self, a: Tid) -> Self {
        self.actors.push(a);
        self
    }
    pub fn kind(mut self, k: CommitKind) -> Self {
        self.kinds.push(k);
        self
    }
    pub fn reverts(mut self, c: CommitId) -> Self {
        self.reverts = Some(c);
        self
    }
    pub fn reverted_by(mut self, c: CommitId) -> Self {
        self.reverted_by = Some(c);
        self
    }
    pub fn in_effect(mut self, b: bool) -> Self {
        self.in_effect = Some(b);
        self
    }
    pub fn since(mut self, ts: Ts) -> Self {
        self.since = Some(ts);
        self
    }
    pub fn until(mut self, ts: Ts) -> Self {
        self.until = Some(ts);
        self
    }
    pub fn after(mut self, c: CommitId) -> Self {
        self.after = Some(c);
        self
    }
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }
}

/// Why a commit cannot be reverted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// A body of it was dropped (compaction, keep-at-most, purge): spec/crdt.md §4.6.
    Compacted,
    /// Reverting it writes nothing: everything it wrote was superseded since (spec/crdt.md §4.6).
    Superseded,
}

/// One held commit, attributed by its own signed header only (a change known only from a
/// snapshot has no entry: notes/api.md Attribution), with its relations among held commits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitEntry {
    pub commit: CommitInfo,
    pub kind: CommitKind,
    /// The commit it reverts.
    pub reverts: Option<CommitId>,
    /// Held reverts of it, oldest first.
    pub reverted_by: Vec<CommitId>,
    /// No revert in effect reverts it.
    pub in_effect: bool,
    /// Aspects it validly touches (in the query's scope, if any).
    pub aspects: Vec<(Tid, Ak)>,
    /// A body in `aspects` is gone: reverting fails `NotUndoable(Compacted)`.
    pub dropped: bool,
}

fn kind_of(h: &osis_commit::Header) -> CommitKind {
    match h.kind {
        Kind::Content if h.undoes.is_some() => CommitKind::Revert,
        Kind::Content => CommitKind::Change,
        Kind::Membership => CommitKind::Membership,
        Kind::ContentSnapshot | Kind::MembershipSnapshot | Kind::RosterSnapshot => CommitKind::Snapshot,
        Kind::Import => CommitKind::Import,
    }
}

/// Query results before filtering, with what undo and redo need: the revert depth (0 for a
/// change, odd for an undo, even above 0 for a redo).
struct Found {
    entry: CommitEntry,
    depth: usize,
}

impl Osis {
    fn scope_aspects(&self, s: &Scope) -> Result<Vec<(Tid, Ak)>> {
        let all = || -> Result<Vec<(Tid, Ak)>> { self.engine(|e| e.all_aspects()).map_err(Error::from) };
        Ok(match s {
            Scope::Aspects(v) => v.iter().map(|(t, a)| (self.read(|r| r.resolve(*t)), a.clone())).collect(),
            Scope::Thing(t) => {
                let t = self.read(|r| r.resolve(*t));
                all()?.into_iter().filter(|(x, _)| *x == t).collect()
            }
            Scope::Group(g) => {
                let g = self.read(|r| r.resolve(*g));
                all()?.into_iter().filter(|(x, _)| *x == g || self.groups_of(*x).contains(&g)).collect()
            }
        })
    }

    /// The held commits in `scope`, newest first, with relations judged over every held commit
    /// that can revert one of them (a revert touches only aspects its target touched).
    fn found(&self, scope: Option<&Scope>) -> Result<Vec<Found>> {
        let aks = scope.map(|s| self.scope_aspects(s)).transpose()?;
        Ok(self.engine(|e| {
            let base = e.held_commits(aks.as_deref());
            let related: Vec<HeldCommit> = match &aks {
                Some(_) => {
                    let touched: BTreeSet<(Tid, Ak)> = base.iter().flat_map(|c| c.header.aspects.iter().map(|a| (a.tid, a.ak.clone()))).collect();
                    e.held_commits(Some(&touched.into_iter().collect::<Vec<_>>()))
                }
                None => base.clone(),
            };
            // reverters per commit, oldest first; in effect decided newest first (reverters are
            // newer than what they revert)
            let mut by: BTreeMap<CommitId, Vec<CommitId>> = BTreeMap::new();
            for c in related.iter().rev() {
                if let Some(t) = c.header.undoes.filter(|_| c.header.kind == Kind::Content) {
                    by.entry(t).or_default().push(c.id);
                }
            }
            let mut out_of: BTreeSet<CommitId> = BTreeSet::new();
            for c in &related {
                if !out_of.contains(&c.id)
                    && let Some(t) = c.header.undoes
                {
                    out_of.insert(t);
                }
            }
            // revert depth: one more than the target's; a commit reverting nothing (or not held) is 0
            let mut depth: BTreeMap<CommitId, usize> = BTreeMap::new();
            let mut depth_of = |id: CommitId| {
                let (mut chain, mut cur) = (Vec::new(), id);
                let hit = loop {
                    if let Some(d) = depth.get(&cur) {
                        break Some(*d);
                    }
                    chain.push(cur);
                    match e.header(&cur).and_then(|h| h.undoes) {
                        Some(u) => cur = u,
                        None => break None,
                    }
                };
                let mut next = hit.map_or(0, |d| d + 1);
                for c in chain.iter().rev() {
                    depth.insert(*c, next);
                    next += 1;
                }
                depth.get(&id).copied().unwrap_or_default()
            };
            base.into_iter()
                .map(|c| {
                    let h = &c.header;
                    let entry = CommitEntry {
                        commit: CommitInfo { id: c.id, actor: h.actor, node: h.author, ts: h.ts, received: c.received },
                        kind: kind_of(h),
                        reverts: h.undoes,
                        reverted_by: by.remove(&c.id).unwrap_or_default(),
                        in_effect: !out_of.contains(&c.id),
                        dropped: c.aspects.iter().any(|a| !a.2 && a.1.as_str() != "/created"),
                        aspects: c.aspects.into_iter().map(|(t, a, _)| (t, a)).collect(),
                    };
                    Found { depth: depth_of(c.id), entry }
                })
                .collect()
        }))
    }

    /// Held commits matching `q`, newest first (by `ts`, then ID).
    pub fn commits(&self, q: &CommitQuery) -> Result<Vec<CommitEntry>> {
        let mut found = self.found(q.scope.as_ref())?;
        if let Some(a) = q.after {
            match found.iter().position(|f| f.entry.commit.id == a) {
                Some(i) => drop(found.drain(..=i)),
                None => return Err(Error::Invalid("`after` names no commit in the query's scope".into())),
            }
        }
        Ok(found
            .into_iter()
            .map(|f| f.entry)
            .filter(|e| {
                (q.actors.is_empty() || q.actors.contains(&e.commit.actor))
                    && (q.kinds.is_empty() || q.kinds.contains(&e.kind))
                    && q.reverts.is_none_or(|c| e.reverts == Some(c))
                    && q.reverted_by.is_none_or(|c| e.reverted_by.contains(&c))
                    && q.in_effect.is_none_or(|b| e.in_effect == b)
                    && q.since.is_none_or(|t| e.commit.ts >= t)
                    && q.until.is_none_or(|t| e.commit.ts < t)
            })
            .take(q.limit.unwrap_or(usize::MAX))
            .collect())
    }

    /// Undoes this actor's newest change in effect in `scope` (a redo counts as a change): reverts
    /// it. `None` when there is none, `NotUndoable` when it cannot be reverted (nothing older is
    /// undone instead).
    pub fn undo(&self, scope: &Scope) -> Result<Option<Committed>> {
        self.step(scope, false)
    }

    /// Redoes this actor's newest undo in effect in `scope`, unless a new change of this actor
    /// came after it there: reverts the undo. `None` when there is none.
    pub fn redo(&self, scope: &Scope) -> Result<Option<Committed>> {
        self.step(scope, true)
    }

    /// Reverts any held change or revert this node may write (an admin reverting someone else's).
    pub fn revert(&self, id: CommitId) -> Result<Committed> {
        let _g = lock(&self.inner.undo);
        self.revert_one(id)
    }

    /// Undo or redo, serialized under one lock: choose by query, then revert.
    fn step(&self, scope: &Scope, redo: bool) -> Result<Option<Committed>> {
        let _g = lock(&self.inner.undo);
        let me = self.me();
        let found = self.found(Some(scope))?;
        let mut mine = found.iter().filter(|f| f.entry.commit.actor == me && matches!(f.entry.kind, CommitKind::Change | CommitKind::Revert));
        let target = if redo {
            mine.take_while(|f| f.entry.kind == CommitKind::Revert).find(|f| f.entry.in_effect && f.depth % 2 == 1)
        } else {
            mine.find(|f| f.entry.in_effect && f.depth % 2 == 0)
        };
        target.map(|f| self.revert_one(f.entry.commit.id)).transpose()
    }

    /// The revert of `target`, or why there is none (never a partial revert).
    fn revert_one(&self, target: CommitId) -> Result<Committed> {
        let mut m = Mutation::new();
        m.act_as(self.me()).undo(target);
        let blocked = |reason| Error::NotUndoable { commit: target, reason };
        self.engine(|e| {
            let h = e.header(&target).ok_or_else(|| Error::Invalid("unknown commit".into()))?;
            if h.kind != Kind::Content {
                return Err(Error::Invalid("only changes and reverts are reverted".into()));
            }
            if h.aspects.iter().any(|a| a.ak.as_str() != "/created" && !e.holds_body(&target, &a.tid, &a.ak)) {
                return Err(blocked(DropReason::Compacted));
            }
            match e.commit(m)? {
                Some(id) => Ok(Committed { commit: id, ts: e.header(&id).map(|h| h.ts).unwrap_or_default() }),
                None => Err(blocked(DropReason::Superseded)),
            }
        })
    }
}
