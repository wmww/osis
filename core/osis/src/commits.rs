//! The commit query, and undo, redo and revert over it (notes/api.md Commits; spec/commits.md
//! §7, spec/crdt.md §4.6). Everything is derived from the held commits and this session's
//! ephemeral undo log (notes/ephemeral.md), nothing is stored: a revert is a change naming the
//! change it reverts; a change is in effect while no revert in effect names it; undo and redo
//! pick a change (`undo_target`, `redo_target`) and revert it. Reverting a thing's creation
//! deletes the thing (spec/crdt.md §4.6).

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::read::Stamp;
use crate::watch::lock;
use crate::write::Committed;
use osis_base::{Ak, Tid, Ts};
use osis_commit::Kind;
use osis_node::ChangeId;
use osis_node::ephemeral::Reverted;
use osis_node::undo::HeldCommit;
use std::collections::{BTreeMap, BTreeSet};

/// Which aspects a query, undo or redo ranges over; resolved when used. `Thing` and `Group`
/// cover durable aspects and ephemeral things (and `placed.0~`); an
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
    /// A role change (grants, removals, rotations, labels).
    Role,
    /// A compaction or roster snapshot.
    Snapshot,
    /// An own ephemeral-only batch of this session: a change, or a revert (`reverts`).
    Ephemeral,
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
/// from a snapshot has no entry), or an own ephemeral change of this
/// session; with its relations among them. A batch with both halves is its commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitEntry {
    pub commit: Stamp,
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
    /// Of `aspects`, those a purge request dropped, with the earliest such request held: the change
    /// is a tombstone there (spec/commits.md §5). Lasting for a permanent delta, also at a new device.
    pub purged: Vec<(Tid, Ak, ChangeId)>,
}

fn kind_of(h: &osis_commit::Header) -> CommitKind {
    match h.kind {
        Kind::Content if h.undoes.is_some() => CommitKind::Revert,
        k => kind_of_commit(k),
    }
}

/// What a commit of kind `k` is, a revert aside (an undo is a content commit).
pub(crate) fn kind_of_commit(k: Kind) -> CommitKind {
    match k {
        Kind::Content => CommitKind::Change,
        Kind::Role => CommitKind::Role,
        Kind::ContentSnapshot | Kind::RoleSnapshot | Kind::RosterSnapshot => CommitKind::Snapshot,
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
        // acting as an actor: of what it may read only
        let acting = self.acting;
        let shown = |e: &osis_node::Engine, t: &Tid| acting.is_none_or(|a| e.readable_by(&a, t));
        let things = |keep: &dyn Fn(&osis_node::Engine, &Tid) -> bool| -> Result<Vec<(Tid, Ak)>> {
            self.engine(|e| {
                // an ephemeral aspect of a durable thing (a cursor) is in scope only when named
                let mut out: Vec<(Tid, Ak)> = e.all_aspects()?.into_iter().filter(|(t, a)| a.lifetime() == crate::Lifetime::Durable && keep(e, t) && shown(e, t)).collect();
                out.extend(e.ephemeral_scope_keys().into_iter().filter(|(t, _)| keep(e, t) && shown(e, t)));
                Ok::<_, osis_node::Error>(out)
            })
            .map_err(Error::from)
        };
        Ok(match s {
            Scope::Aspects(v) => self.engine(|e| v.iter().filter(|(t, _)| shown(e, t)).cloned().collect()),
            Scope::Thing(t) => things(&|_, x| x == t)?,
            Scope::Group(g) => {
                let g = *g;
                // acting as an actor: a group it may not read names nothing, not even an item it
                // reads (that would tell the group from an unknown tid)
                if self.read_local(|r| r.hidden(g)) {
                    return Ok(Vec::new());
                }
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
            let mut purges: BTreeMap<(Tid, Ak), BTreeMap<osis_base::CommitId, osis_base::CommitId>> = BTreeMap::new();
            for c in base {
                let h = &c.header;
                let id = ChangeId::Commit(c.id);
                at.insert(id, h.ts);
                let mut purged = Vec::new();
                for (t, a, _) in c.aspects.iter().filter(|a| !a.2) {
                    let on = match purges.entry((*t, a.clone())) {
                        std::collections::btree_map::Entry::Occupied(x) => x.into_mut(),
                        std::collections::btree_map::Entry::Vacant(x) => x.insert(e.purged_on(t, a)?),
                    };
                    if let Some(by) = on.get(&c.id) {
                        purged.push((*t, a.clone(), ChangeId::Commit(*by)));
                    }
                }
                entries.insert(
                    (h.ts, id),
                    CommitEntry {
                        commit: Stamp { id, actor: h.actor, node: h.author, ts: h.ts, received: c.received },
                        kind: kind_of(h),
                        reverts: undoes(h),
                        reverted_by: Vec::new(),
                        in_effect: true,
                        dropped: c.aspects.iter().any(|a| !a.2 && a.1.as_str() != "created.0"),
                        purged,
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
                entries.insert((ts, l.id), CommitEntry { commit: Stamp { id: l.id, actor, node, ts, received: l.received }, kind, reverts: l.reverts, reverted_by: Vec::new(), in_effect: true, dropped: false, purged: Vec::new(), aspects: asp });
            }
            // acting as an actor: only the aspects it may read; a change touching none is unknown
            if let Some(a) = self.acting {
                entries.retain(|_, en| {
                    en.aspects.retain(|(t, _)| e.readable_by(&a, t));
                    en.purged.retain(|(t, _, _)| e.readable_by(&a, t));
                    !en.aspects.is_empty()
                });
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
            Ok::<Vec<Found>, osis_node::Error>(
                entries
                    .into_values()
                    .rev()
                    .map(|mut entry| {
                        let id = entry.commit.id;
                        entry.reverted_by = by.remove(&id).unwrap_or_default();
                        entry.in_effect = !out_of.contains(&id);
                        Found { depth: depth_of(id), entry }
                    })
                    .collect(),
            )
        })?;
        Ok((found, aks))
    }

    /// Changes matching `q`, newest first (by `ts`, then ID).
    pub fn commits(&self, q: &CommitQuery) -> Result<Vec<CommitEntry>> {
        if let crate::sources::Source::Remote(r) = self.route_scope(q.scope.as_ref())? {
            let v = r.call(crate::port::method::COMMITS, vec![crate::port::codec::query_v(q)])?;
            return crate::port::codec::Args::of(vec![v]).list()?.into_iter().map(crate::port::codec::entry).collect();
        }
        let (mut found, _) = self.found(q.scope.as_ref())?;
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

    /// The change `undo` of `scope` would revert now: none or one. Fails as `undo` would, choosing
    /// none (`NotUndoable`: the newest own ephemeral change in scope left the undo log).
    pub fn undo_target(&self, scope: &Scope) -> Result<Option<CommitEntry>> {
        self.target(scope, false)
    }

    /// The change `redo` of `scope` would revert now: none or one, as `undo_target`.
    pub fn redo_target(&self, scope: &Scope) -> Result<Option<CommitEntry>> {
        self.target(scope, true)
    }

    fn target(&self, scope: &Scope, redo: bool) -> Result<Option<CommitEntry>> {
        if let crate::sources::Source::Remote(r) = self.route_scope(Some(scope))? {
            let m = if redo { crate::port::method::REDO_TARGET } else { crate::port::method::UNDO_TARGET };
            let v = r.call(m, vec![crate::port::codec::scope_v(scope)])?;
            return crate::port::codec::Args::of(vec![v]).opt()?.map(crate::port::codec::entry).transpose();
        }
        let (found, aks) = self.found(Some(scope))?;
        Ok(self.pick(found, aks.as_deref().unwrap_or_default(), redo)?.map(|f| f.entry))
    }

    /// Undoes this actor's newest change in effect in `scope` (a redo counts as a change): reverts
    /// it. `None` when there is none, `NotUndoable` when it cannot be reverted (nothing older is
    /// undone instead).
    pub fn undo(&self, scope: &Scope) -> Result<Option<Committed>> {
        if let crate::sources::Source::Remote(r) = self.route_write_scope(scope)? {
            let v = r.call_once(crate::port::method::UNDO, vec![crate::port::codec::scope_v(scope)])?;
            return crate::port::codec::Args::of(vec![v]).opt()?.map(crate::port::codec::committed).transpose();
        }
        self.step(scope, false)
    }

    /// Redoes this actor's newest undo in effect in `scope`, unless a new change of this actor
    /// came after it there: reverts the undo. `None` when there is none.
    pub fn redo(&self, scope: &Scope) -> Result<Option<Committed>> {
        if let crate::sources::Source::Remote(r) = self.route_write_scope(scope)? {
            let v = r.call_once(crate::port::method::REDO, vec![crate::port::codec::scope_v(scope)])?;
            return crate::port::codec::Args::of(vec![v]).opt()?.map(crate::port::codec::committed).transpose();
        }
        self.step(scope, true)
    }

    /// Reverts any held change or revert this node may write (an admin reverting someone
    /// else's), or an own ephemeral change of this session (with both halves, a batch reverts
    /// as one). An ephemeral change without a log here (another node's, or from before a
    /// restart) is `Invalid`.
    pub fn revert(&self, id: ChangeId) -> Result<Committed> {
        if let crate::sources::Source::Remote(r) = self.route_write_change(id)? {
            return crate::port::codec::committed(r.call_once(crate::port::method::REVERT, vec![crate::port::codec::change_v(&id)])?);
        }
        let _g = lock(&self.inner.undo);
        self.revert_one(id)
    }

    /// Undo or redo, serialized under one lock: choose by query, then revert.
    fn step(&self, scope: &Scope, redo: bool) -> Result<Option<Committed>> {
        let _g = lock(&self.inner.undo);
        self.target(scope, redo)?.map(|e| self.revert_one(e.commit.id)).transpose()
    }

    /// The change undo (redo) of the scope of `found` (with aspects `aks`) reverts: this
    /// actor's newest change in effect (a redo counts as a change); for redo its newest undo in
    /// effect, unless a new change of this actor came after it.
    fn pick(&self, found: Vec<Found>, aks: &[(Tid, Ak)], redo: bool) -> Result<Option<Found>> {
        let me = self.me();
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
        self.locked(|l| {
            // what the revert writes is still this engine's (a move since the route was decided)
            self.guard_change(l, target)?;
            let e = l.engine();
            if let ChangeId::Commit(c) = target {
                let h = e.header(&c).filter(|h| self.acting.is_none_or(|a| h.aspects.iter().any(|x| e.readable_by(&a, &x.tid)))).ok_or_else(|| Error::Invalid("unknown commit".into()))?;
                if h.kind != Kind::Content {
                    return Err(Error::Invalid("only changes and reverts are reverted".into()));
                }
                // of what the actor may not read, not asked: `revert_as` refuses it whichever
                if h.aspects.iter().any(|a| a.ak.as_str() != "created.0" && self.acting.is_none_or(|x| e.readable_by(&x, &a.tid)) && !e.body_not_dropped(&c, &a.tid, &a.ak)) {
                    return Err(blocked(DropReason::Compacted));
                }
            }
            if let Some(a) = self.acting {
                // an ephemeral change of what it may not read: as one with no log here
                if let ChangeId::Ephemeral(_) = target
                    && !e.ephemeral_log().iter().filter(|l| l.id == target).all(|l| l.aspects.iter().any(|(t, _)| e.readable_by(&a, t)))
                {
                    return Err(blocked(DropReason::Compacted));
                }
            }
            let r = match self.acting {
                Some(a) => e.revert_as(target, a)?,
                None => e.revert_change(target, me)?,
            };
            match r {
                Reverted::Written(w) => Ok(Committed::of(w)),
                Reverted::Superseded => Err(blocked(DropReason::Superseded)),
                Reverted::Compacted => Err(blocked(DropReason::Compacted)),
            }
        })
    }
}
