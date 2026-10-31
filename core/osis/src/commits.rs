//! The commit query, and undo, redo and revert over it (notes/api.md Commits; spec/commits.md
//! §7, spec/crdt.md §4.6). Everything is derived from the held commits and this session's
//! ephemeral undo log (notes/ephemeral.md), nothing is stored: a revert is a change naming the
//! change it reverts; a change is in effect while no revert in effect names it; undo and redo
//! pick a change by query (`CommitQuery::next`) and revert it. Reverting a thing's creation
//! deletes the thing (spec/crdt.md §4.6).

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::watch::{CommitInfo, lock};
use crate::write::Committed;
use osis_base::{Ak, Tid, Ts};
use osis_commit::Kind;
use osis_node::ChangeId;
use osis_node::ephemeral::Reverted;
use osis_node::undo::HeldCommit;
use std::collections::{BTreeMap, BTreeSet};

/// Which aspects a query, undo or redo ranges over; resolved when used. `Thing` and `Group`
/// cover durable aspects and ephemeral things (and `/placed`); an
/// ephemeral aspect of a durable thing (a cursor, a selection) is in scope only when named by
/// `Aspects`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Every aspect of a thing (a document).
    Thing(Tid),
    /// These aspects (a form).
    Aspects(Vec<(Tid, Ak)>),
    /// The group and every thing in it, transitively (a folder).
    Group(Tid),
}

/// What a change is, from its header or the ephemeral undo log.
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
    /// An own ephemeral-only batch of this session: a change, or a revert (`reverts`).
    Ephemeral,
}

/// The change `undo` or `redo` would revert (`CommitQuery::next`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    Undo,
    Redo,
}

/// A filter over the held commits and this session's ephemeral changes. Empty fields match
/// everything; results are newest first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommitQuery {
    pub scope: Option<Scope>,
    /// By any of these actors.
    pub actors: Vec<Tid>,
    /// Of any of these kinds.
    pub kinds: Vec<CommitKind>,
    /// Reverts of this change.
    pub reverts: Option<ChangeId>,
    /// The change this one reverts.
    pub reverted_by: Option<ChangeId>,
    pub in_effect: Option<bool>,
    /// `ts >= since`.
    pub since: Option<Ts>,
    /// `ts < until`.
    pub until: Option<Ts>,
    /// Paging: only changes after this one in result order (older).
    pub after: Option<ChangeId>,
    pub limit: Option<usize>,
    /// Only the change `undo` (or `redo`) of `scope` would revert now: none or one. Fails as
    /// that call would without choosing one (`NotUndoable`: the newest own ephemeral change in
    /// scope left the undo log). Needs `scope`; not with `after`.
    pub next: Option<Next>,
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
    pub fn reverts(mut self, c: impl Into<ChangeId>) -> Self {
        self.reverts = Some(c.into());
        self
    }
    pub fn reverted_by(mut self, c: impl Into<ChangeId>) -> Self {
        self.reverted_by = Some(c.into());
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
    pub fn after(mut self, c: impl Into<ChangeId>) -> Self {
        self.after = Some(c.into());
        self
    }
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }
    pub fn next(mut self, n: Next) -> Self {
        self.next = Some(n);
        self
    }
}

/// Why a change cannot be reverted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// A body of it was dropped (compaction, keep-at-most, purge: spec/crdt.md §4.6), or an
    /// ephemeral change left the undo log (`Config::ephemeral_history`).
    Compacted,
    /// Reverting it writes nothing: everything it wrote was superseded since (spec/crdt.md §4.6).
    Superseded,
}

/// One change: a held commit, attributed by its own signed header only (a change known only
/// from a snapshot has no entry: notes/api.md Attribution), or an own ephemeral change of this
/// session; with its relations among them. A batch with both halves is its commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitEntry {
    pub commit: CommitInfo,
    pub kind: CommitKind,
    /// The change it reverts.
    pub reverts: Option<ChangeId>,
    /// Known reverts of it, oldest first.
    pub reverted_by: Vec<ChangeId>,
    /// No revert in effect reverts it.
    pub in_effect: bool,
    /// Aspects it validly touches (in the query's scope, if any), its ephemeral ones included.
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

/// The change a commit header reverts.
fn undoes(h: &osis_commit::Header) -> Option<ChangeId> {
    h.undoes.filter(|_| h.kind == Kind::Content).map(ChangeId::Commit)
}

/// A resolved scope.
type Aspects = Vec<(Tid, Ak)>;

/// Query results before filtering, with what undo and redo need: the revert depth (0 for a
/// change, odd for an undo, even above 0 for a redo).
struct Found {
    entry: CommitEntry,
    depth: usize,
}

impl Osis {
    fn scope_aspects(&self, s: &Scope) -> Result<Vec<(Tid, Ak)>> {
        let things = |keep: &dyn Fn(&osis_node::Engine, &Tid) -> bool| -> Result<Vec<(Tid, Ak)>> {
            self.engine(|e| {
                let mut out: Vec<(Tid, Ak)> = e.all_aspects()?.into_iter().filter(|(t, _)| keep(e, t)).collect();
                out.extend(e.ephemeral_scope_keys().into_iter().filter(|(t, _)| keep(e, t)));
                Ok::<_, osis_node::Error>(out)
            })
            .map_err(Error::from)
        };
        Ok(match s {
            Scope::Aspects(v) => v.iter().map(|(t, a)| (self.read(|r| r.resolve(*t)), a.clone())).collect(),
            Scope::Thing(t) => {
                let t = self.read(|r| r.resolve(*t));
                things(&|_, x| *x == t)?
            }
            Scope::Group(g) => {
                let g = self.read(|r| r.resolve(*g));
                things(&|e, x| *x == g || e.groups_of(x).contains(&g))?
            }
        })
    }

    /// The changes in `scope`, newest first, with relations judged over every held commit that
    /// can revert one of them (a revert touches aspects its target touched: undoing a creation
    /// resets every held aspect of the thing, the ones its creation wrote among them) and every
    /// logged ephemeral change. Also the scope's aspects.
    fn found(&self, scope: Option<&Scope>) -> Result<(Vec<Found>, Option<Aspects>)> {
        let aks = scope.map(|s| self.scope_aspects(s)).transpose()?;
        let found = self.engine(|e| {
            let base = e.held_commits(aks.as_deref());
            let related: Vec<HeldCommit> = match &aks {
                Some(_) => {
                    let touched: BTreeSet<(Tid, Ak)> = base.iter().flat_map(|c| c.header.aspects.iter().map(|a| (a.tid, a.ak.clone()))).collect();
                    e.held_commits(Some(&touched.into_iter().collect::<Vec<_>>()))
                }
                None => base.clone(),
            };
            let log = e.ephemeral_log();
            let in_scope: Option<BTreeSet<&(Tid, Ak)>> = aks.as_ref().map(|a| a.iter().collect());
            // the entries: held commits in scope, then logged changes with an aspect in scope
            // (a batch with both halves joins its commit's entry)
            let mut entries: BTreeMap<(Ts, ChangeId), CommitEntry> = BTreeMap::new();
            let mut at: BTreeMap<ChangeId, Ts> = BTreeMap::new();
            for c in base {
                let h = &c.header;
                let id = ChangeId::Commit(c.id);
                at.insert(id, h.ts);
                entries.insert(
                    (h.ts, id),
                    CommitEntry {
                        commit: CommitInfo { id, actor: h.actor, node: h.author, ts: h.ts, received: c.received },
                        kind: kind_of(h),
                        reverts: undoes(h),
                        reverted_by: Vec::new(),
                        in_effect: true,
                        dropped: c.aspects.iter().any(|a| !a.2 && a.1.as_str() != "/created"),
                        aspects: c.aspects.into_iter().map(|(t, a, _)| (t, a)).collect(),
                    },
                );
            }
            for l in &log {
                let asp: Vec<(Tid, Ak)> = l.aspects.iter().filter(|k| in_scope.as_ref().is_none_or(|s| s.contains(k))).cloned().collect();
                if asp.is_empty() {
                    continue;
                }
                if let Some(ts) = at.get(&l.id)
                    && let Some(en) = entries.get_mut(&(*ts, l.id))
                {
                    en.aspects.extend(asp);
                    continue;
                }
                let (kind, actor, node, ts) = match l.id {
                    ChangeId::Commit(c) => match e.header(&c) {
                        Some(h) => (kind_of(&h), h.actor, h.author, h.ts),
                        None => continue,
                    },
                    ChangeId::Ephemeral(_) => (CommitKind::Ephemeral, l.actor, e.tid(), l.ts),
                };
                at.insert(l.id, ts);
                entries.insert((ts, l.id), CommitEntry { commit: CommitInfo { id: l.id, actor, node, ts, received: l.received }, kind, reverts: l.reverts, reverted_by: Vec::new(), in_effect: true, dropped: false, aspects: asp });
            }
            // relations over the related commits and the whole log, oldest first
            let mut rel: BTreeMap<(Ts, ChangeId), Option<ChangeId>> = related.iter().map(|c| ((c.header.ts, ChangeId::Commit(c.id)), undoes(&c.header))).collect();
            for l in &log {
                let ts = match l.id {
                    ChangeId::Commit(c) => e.header(&c).map_or(l.ts, |h| h.ts),
                    ChangeId::Ephemeral(_) => l.ts,
                };
                let r = rel.entry((ts, l.id)).or_default();
                *r = r.or(l.reverts);
            }
            let mut by: BTreeMap<ChangeId, Vec<ChangeId>> = BTreeMap::new();
            for ((_, id), r) in &rel {
                if let Some(t) = r {
                    by.entry(*t).or_default().push(*id);
                }
            }
            // in effect decided newest first (reverters are newer than what they revert)
            let mut out_of: BTreeSet<ChangeId> = BTreeSet::new();
            for ((_, id), r) in rel.iter().rev() {
                if !out_of.contains(id)
                    && let Some(t) = r
                {
                    out_of.insert(*t);
                }
            }
            let reverts: BTreeMap<ChangeId, Option<ChangeId>> = rel.iter().map(|((_, id), r)| (*id, *r)).collect();
            // revert depth: one more than the target's; a change reverting nothing (or not
            // known) is 0
            let mut depth: BTreeMap<ChangeId, usize> = BTreeMap::new();
            let mut depth_of = |id: ChangeId| {
                let (mut chain, mut cur) = (Vec::new(), id);
                let hit = loop {
                    if let Some(d) = depth.get(&cur) {
                        break Some(*d);
                    }
                    chain.push(cur);
                    let next = match reverts.get(&cur) {
                        Some(r) => *r,
                        None => cur.commit().and_then(|c| e.header(&c)).and_then(|h| undoes(&h)),
                    };
                    match next {
                        Some(u) => cur = u,
                        None => break None,
                    }
                };
                for (d, c) in (hit.map_or(0, |d| d + 1)..).zip(chain.iter().rev()) {
                    depth.insert(*c, d);
                }
                depth.get(&id).copied().unwrap_or_default()
            };
            entries
                .into_values()
                .rev()
                .map(|mut entry| {
                    let id = entry.commit.id;
                    entry.reverted_by = by.remove(&id).unwrap_or_default();
                    entry.in_effect = !out_of.contains(&id);
                    Found { depth: depth_of(id), entry }
                })
                .collect()
        });
        Ok((found, aks))
    }

    /// Changes matching `q`, newest first (by `ts`, then ID).
    pub fn commits(&self, q: &CommitQuery) -> Result<Vec<CommitEntry>> {
        let (mut found, aks) = self.found(q.scope.as_ref())?;
        if let Some(n) = q.next {
            if q.scope.is_none() || q.after.is_some() {
                return Err(Error::Invalid("`next` needs a scope and takes no `after`".into()));
            }
            found = self.pick(found, aks.as_deref().unwrap_or_default(), n)?.into_iter().collect();
        }
        if let Some(a) = q.after {
            match found.iter().position(|f| f.entry.commit.id == a) {
                Some(i) => drop(found.drain(..=i)),
                None => return Err(Error::Invalid("`after` names no change in the query's scope".into())),
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

    /// Reverts any held change or revert this node may write (an admin reverting someone
    /// else's), or an own ephemeral change of this session (with both halves, a batch reverts
    /// as one). An ephemeral change without a log here (another node's, or from before a
    /// restart) is `Invalid`.
    pub fn revert(&self, id: ChangeId) -> Result<Committed> {
        let _g = lock(&self.inner.undo);
        self.revert_one(id)
    }

    /// Undo or redo, serialized under one lock: choose by query, then revert.
    fn step(&self, scope: &Scope, redo: bool) -> Result<Option<Committed>> {
        let _g = lock(&self.inner.undo);
        let q = CommitQuery::new().scope(scope.clone()).next(if redo { Next::Redo } else { Next::Undo });
        self.commits(&q)?.first().map(|e| self.revert_one(e.commit.id)).transpose()
    }

    /// The change undo (redo) of the scope of `found` (with aspects `aks`) reverts: this
    /// actor's newest change in effect (a redo counts as a change); for redo its newest undo in
    /// effect, unless a new change of this actor came after it.
    fn pick(&self, found: Vec<Found>, aks: &[(Tid, Ak)], n: Next) -> Result<Option<Found>> {
        let me = self.me();
        let redo = n == Next::Redo;
        let mut mine = found.into_iter().filter(|f| f.entry.commit.actor == me && matches!(f.entry.kind, CommitKind::Change | CommitKind::Revert | CommitKind::Ephemeral));
        let target = if redo {
            mine.take_while(|f| f.depth > 0).find(|f| f.entry.in_effect && f.depth % 2 == 1)
        } else {
            mine.find(|f| f.entry.in_effect && f.depth % 2 == 0)
        };
        // a newer own ephemeral change that left the undo log: it cannot be reverted, and
        // nothing older is instead (for redo: a change clears redo)
        let gone = self.engine(|e| e.ephemeral_dropped(aks));
        if let Some((ts, id, revert)) = gone
            && target.as_ref().is_none_or(|f| f.entry.commit.ts < ts)
        {
            return if redo && !revert { Ok(None) } else { Err(Error::NotUndoable { commit: id, reason: DropReason::Compacted }) };
        }
        Ok(target)
    }

    /// The revert of `target`, or why there is none (never a partial revert).
    fn revert_one(&self, target: ChangeId) -> Result<Committed> {
        let me = self.me();
        let blocked = |reason| Error::NotUndoable { commit: target, reason };
        self.engine(|e| {
            if let ChangeId::Commit(c) = target {
                let h = e.header(&c).ok_or_else(|| Error::Invalid("unknown commit".into()))?;
                if h.kind != Kind::Content {
                    return Err(Error::Invalid("only changes and reverts are reverted".into()));
                }
                if h.aspects.iter().any(|a| a.ak.as_str() != "/created" && !e.body_not_dropped(&c, &a.tid, &a.ak)) {
                    return Err(blocked(DropReason::Compacted));
                }
            }
            match e.revert_change(target, me)? {
                Reverted::Written(w) => Ok(Committed { id: w.id, ts: w.ts }),
                Reverted::Superseded => Err(blocked(DropReason::Superseded)),
                Reverted::Compacted => Err(blocked(DropReason::Compacted)),
            }
        })
    }
}
