//! The commit query, and undo, redo and revert over it (notes/api.md Commits; spec/commits.md
//! §7, spec/crdt.md §4.6). Everything is derived from the held commits and this session's
//! ephemeral undo log (notes/ephemeral.md), nothing is stored: a revert is a commit naming the
//! commit it reverts; a commit is in effect while no revert in effect names it; undo and redo
//! pick a commit (`undo_target`, `redo_target`) and revert it. Reverting a thing's creation
//! deletes the thing (spec/crdt.md §4.6).

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::read::Stamp;
use crate::watch::lock;
use crate::write::Commit;
use crate::commit_id::CommitId;
use osis_base::{Ak, Tid, Ts, Time};
use osis_commit::Kind;
use osis_node::BatchId as RawChange;
use osis_node::ephemeral::Reverted;
use osis_node::undo::HeldCommit;
use std::collections::{BTreeMap, BTreeSet};

/// Which aspects a query, undo or redo ranges over; resolved when used. `Thing` and `Group`
/// cover durable aspects, drafts and memberships in memory; an
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

/// What a commit is, from its header or the ephemeral undo log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommitKind {
    /// Content written.
    Content,
    /// A content commit reverting another (an undo, or a redo: a revert of a revert).
    Revert,
    /// Who holds which role, and what keeps that working.
    Role,
    /// Older commits tidied into one, which then stands in for them. It names who made it, not who
    /// wrote what it carries: commits known only from it have no entry of their own.
    Snapshot,
    /// An own ephemeral commit of this session, a revert too (`reverts`).
    Ephemeral,
}

/// A filter over the held commits and this session's ephemeral commits. Empty fields match
/// everything; results are newest first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommitQuery {
    /// Which aspects.
    pub scope: Option<Scope>,
    /// By any of these actors.
    pub actors: Vec<Tid>,
    /// Of any of these kinds.
    pub kinds: Vec<CommitKind>,
    /// Reverts of this commit.
    pub reverts: Option<CommitId>,
    /// The commit this one reverts.
    pub reverted_by: Option<CommitId>,
    /// Whether no revert in effect reverts it.
    pub in_effect: Option<bool>,
    /// Written at this time or later. Several commits can share a moment: to page, use `after`.
    pub since: Option<Time>,
    /// Written before this time.
    pub until: Option<Time>,
    /// Paging: only commits after this one in result order (older).
    pub after: Option<CommitId>,
    /// At most this many.
    pub limit: Option<usize>,
}

/// Why a commit cannot be reverted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotUndoableReason {
    /// What it wrote is no longer here (tidied up, past `Retention::at_most` or purged), or an ephemeral
    /// commit left the undo memory (`Config::ephemeral_undo_bytes`).
    ContentGone,
    /// Reverting it writes nothing: everything it wrote was overwritten since.
    Superseded,
}

/// One commit held here, attributed by what it signs itself (a commit known only from a
/// `CommitKind::Snapshot` has no entry), or an own ephemeral commit of this session; with what
/// reverted what among them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitEntry {
    /// Which commit, who wrote it and when.
    pub commit: Stamp,
    /// What kind of commit it is.
    pub kind: CommitKind,
    /// The commit it reverts.
    pub reverts: Option<CommitId>,
    /// Known reverts of it, oldest first.
    pub reverted_by: Vec<CommitId>,
    /// No revert in effect reverts it.
    pub in_effect: bool,
    /// Aspects it validly touches (in the query's scope, if any), its ephemeral ones included.
    pub aspects: Vec<(Tid, Ak)>,
    /// What it wrote on one of `aspects` is gone: reverting fails `NotUndoable(ContentGone)`.
    pub content_gone: bool,
    /// Of `aspects`, those a purge took it from, with the earliest such purge held: the commit stays
    /// listed there, its content gone.
    pub purged: Vec<(Tid, Ak, CommitId)>,
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
        Kind::Content => CommitKind::Content,
        Kind::Role => CommitKind::Role,
        Kind::ContentSnapshot | Kind::RoleSnapshot => CommitKind::Snapshot,
    }
}

/// The commit a commit header reverts.
fn undoes(h: &osis_commit::Header) -> Option<CommitId> {
    h.undoes.filter(|_| h.kind == Kind::Content).map(CommitId::commit)
}

/// A resolved scope.
type Aspects = Vec<(Tid, Ak)>;

/// Query results before filtering, with what undo and redo need: the revert depth (0 for a
/// commit, odd for an undo, even above 0 for a redo).
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

    /// The commits in `scope`, newest first, with relations judged over every held commit that
    /// can revert one of them (a revert touches aspects its target touched: undoing a creation
    /// resets every held aspect of the thing, the ones its creation wrote among them) and every
    /// logged ephemeral commit. Also the scope's aspects.
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
            // the entries: held commits in scope, then logged commits with an aspect in scope
            // (a commit keeping a draft joins its entry)
            let mut entries: BTreeMap<(Ts, CommitId), CommitEntry> = BTreeMap::new();
            let mut at: BTreeMap<CommitId, Ts> = BTreeMap::new();
            let mut purges: BTreeMap<(Tid, Ak), BTreeMap<osis_base::CommitId, osis_base::CommitId>> = BTreeMap::new();
            for c in base {
                let h = &c.header;
                let id = CommitId::commit(c.id);
                at.insert(id, h.ts);
                let mut purged = Vec::new();
                for (t, a, _) in c.aspects.iter().filter(|a| !a.2) {
                    let on = match purges.entry((*t, a.clone())) {
                        std::collections::btree_map::Entry::Occupied(x) => x.into_mut(),
                        std::collections::btree_map::Entry::Vacant(x) => x.insert(e.purged_on(t, a)?),
                    };
                    if let Some(by) = on.get(&c.id) {
                        purged.push((*t, a.clone(), CommitId::commit(*by)));
                    }
                }
                entries.insert(
                    (h.ts, id),
                    CommitEntry {
                        commit: Stamp::new(id, h.actor, h.author, h.ts, c.received),
                        kind: kind_of(h),
                        reverts: undoes(h),
                        reverted_by: Vec::new(),
                        in_effect: true,
                        content_gone: c.aspects.iter().any(|a| !a.2 && a.1.as_str() != "created.0"),
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
                let id = CommitId(l.id);
                if let Some(ts) = at.get(&id)
                    && let Some(en) = entries.get_mut(&(*ts, id))
                {
                    en.aspects.extend(asp);
                    continue;
                }
                let (kind, actor, node, ts) = match l.id {
                    RawChange::Commit(c) => match e.header(&c) {
                        Some(h) => (kind_of(&h), h.actor, h.author, h.ts),
                        None => continue,
                    },
                    RawChange::Ephemeral(_) => (CommitKind::Ephemeral, l.actor, e.tid(), l.ts),
                };
                at.insert(id, ts);
                entries.insert((ts, id), CommitEntry { commit: Stamp::new(id, actor, node, ts, l.received), kind, reverts: l.reverts.map(CommitId), reverted_by: Vec::new(), in_effect: true, content_gone: false, purged: Vec::new(), aspects: asp });
            }
            // acting as an actor: only the aspects it may read; a commit touching none is unknown
            if let Some(a) = self.acting {
                entries.retain(|_, en| {
                    en.aspects.retain(|(t, _)| e.readable_by(&a, t));
                    en.purged.retain(|(t, _, _)| e.readable_by(&a, t));
                    !en.aspects.is_empty()
                });
            }
            // relations over the related commits and the whole log, oldest first
            let mut rel: BTreeMap<(Ts, CommitId), Option<CommitId>> = related.iter().map(|c| ((c.header.ts, CommitId::commit(c.id)), undoes(&c.header))).collect();
            for l in &log {
                let ts = match l.id {
                    RawChange::Commit(c) => e.header(&c).map_or(l.ts, |h| h.ts),
                    RawChange::Ephemeral(_) => l.ts,
                };
                let r = rel.entry((ts, CommitId(l.id))).or_default();
                *r = r.or(l.reverts.map(CommitId));
            }
            let mut by: BTreeMap<CommitId, Vec<CommitId>> = BTreeMap::new();
            for ((_, id), r) in &rel {
                if let Some(t) = r {
                    by.entry(*t).or_default().push(*id);
                }
            }
            // in effect decided newest first (reverters are newer than what they revert)
            let mut out_of: BTreeSet<CommitId> = BTreeSet::new();
            for ((_, id), r) in rel.iter().rev() {
                if !out_of.contains(id)
                    && let Some(t) = r
                {
                    out_of.insert(*t);
                }
            }
            let reverts: BTreeMap<CommitId, Option<CommitId>> = rel.iter().map(|((_, id), r)| (*id, *r)).collect();
            // revert depth: one more than the target's; a commit reverting nothing (or not
            // known) is 0
            let mut depth: BTreeMap<CommitId, usize> = BTreeMap::new();
            let mut depth_of = |id: CommitId| {
                let (mut chain, mut cur) = (Vec::new(), id);
                let hit = loop {
                    if let Some(d) = depth.get(&cur) {
                        break Some(*d);
                    }
                    chain.push(cur);
                    let next = match reverts.get(&cur) {
                        Some(r) => *r,
                        None => cur.0.commit().and_then(|c| e.header(&c)).and_then(|h| undoes(&h)),
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

    /// Commits matching `q`, newest first.
    pub fn commits(&self, q: &CommitQuery) -> Result<Vec<CommitEntry>> {
        if let crate::sources::Source::Node(r) = self.source_scope(q.scope.as_ref())? {
            let v = r.call(crate::port::method::COMMITS, vec![crate::port::codec::query_v(q)])?;
            return crate::port::codec::Args::of(vec![v]).list()?.into_iter().map(crate::port::codec::entry).collect();
        }
        let (mut found, _) = self.found(q.scope.as_ref())?;
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
                    && q.since.is_none_or(|t| e.commit.written >= t)
                    && q.until.is_none_or(|t| e.commit.written < t)
            })
            .take(q.limit.unwrap_or(usize::MAX))
            .collect())
    }

    /// The commit `undo` of `scope` would revert now: none or one. Fails as `undo` would, choosing
    /// none (`NotUndoable`: the newest own ephemeral commit in scope left the undo log).
    pub fn undo_target(&self, scope: &Scope) -> Result<Option<CommitEntry>> {
        self.target(scope, false)
    }

    /// The commit `redo` of `scope` would revert now: none or one, as `undo_target`.
    pub fn redo_target(&self, scope: &Scope) -> Result<Option<CommitEntry>> {
        self.target(scope, true)
    }

    fn target(&self, scope: &Scope, redo: bool) -> Result<Option<CommitEntry>> {
        if let crate::sources::Source::Node(r) = self.source_scope(Some(scope))? {
            let m = if redo { crate::port::method::REDO_TARGET } else { crate::port::method::UNDO_TARGET };
            let v = r.call(m, vec![crate::port::codec::scope_v(scope)])?;
            return crate::port::codec::Args::of(vec![v]).opt()?.map(crate::port::codec::entry).transpose();
        }
        let (found, aks) = self.found(Some(scope))?;
        Ok(self.pick(found, aks.as_deref().unwrap_or_default(), redo)?.map(|f| f.entry))
    }

    /// Undoes this actor's newest commit in effect in `scope` (a redo counts as a commit): reverts
    /// it. `None` when there is none, `NotUndoable` when it cannot be reverted (nothing older is
    /// undone instead).
    pub fn undo(&self, scope: &Scope) -> Result<Option<Commit>> {
        if let crate::sources::Source::Node(r) = self.source_write_scope(scope)? {
            let v = r.call_once(crate::port::method::UNDO, vec![crate::port::codec::scope_v(scope)])?;
            return crate::port::codec::Args::of(vec![v]).opt()?.map(crate::port::codec::commit).transpose();
        }
        self.step(scope, false)
    }

    /// Redoes this actor's newest undo in effect in `scope`, unless a new commit of this actor
    /// came after it there: reverts the undo. `None` when there is none.
    pub fn redo(&self, scope: &Scope) -> Result<Option<Commit>> {
        if let crate::sources::Source::Node(r) = self.source_write_scope(scope)? {
            let v = r.call_once(crate::port::method::REDO, vec![crate::port::codec::scope_v(scope)])?;
            return crate::port::codec::Args::of(vec![v]).opt()?.map(crate::port::codec::commit).transpose();
        }
        self.step(scope, true)
    }

    /// Reverts any held commit or revert this node may write (an admin reverting someone
    /// else's), or an own ephemeral commit of this session. An ephemeral commit without a log here (another node's, or from before a
    /// restart) is `Invalid`.
    pub fn revert(&self, id: CommitId) -> Result<Commit> {
        if let crate::sources::Source::Node(r) = self.source_write_commit(id.0)? {
            return crate::port::codec::commit(r.call_once(crate::port::method::REVERT, vec![crate::port::codec::commit_id_v(&id)])?);
        }
        let _g = lock(&self.inner.undo);
        self.revert_one(id)
    }

    /// Undo or redo, serialized under one lock: choose by query, then revert.
    fn step(&self, scope: &Scope, redo: bool) -> Result<Option<Commit>> {
        let _g = lock(&self.inner.undo);
        self.target(scope, redo)?.map(|e| self.revert_one(e.commit.id)).transpose()
    }

    /// The commit undo (redo) of the scope of `found` (with aspects `aks`) reverts: this
    /// actor's newest commit in effect (a redo counts as a commit); for redo its newest undo in
    /// effect, unless a new commit of this actor came after it.
    fn pick(&self, found: Vec<Found>, aks: &[(Tid, Ak)], redo: bool) -> Result<Option<Found>> {
        let me = self.me();
        let mut mine = found.into_iter().filter(|f| f.entry.commit.actor == me && matches!(f.entry.kind, CommitKind::Content | CommitKind::Revert | CommitKind::Ephemeral));
        let target = if redo {
            mine.take_while(|f| f.depth > 0).find(|f| f.entry.in_effect && f.depth % 2 == 1)
        } else {
            mine.find(|f| f.entry.in_effect && f.depth % 2 == 0)
        };
        // a newer own ephemeral commit that left the undo log: it cannot be reverted, and
        // nothing older is instead (for redo: a commit clears redo)
        let gone = self.engine(|e| e.ephemeral_dropped(aks));
        if let Some((ts, id, revert)) = gone
            && target.as_ref().is_none_or(|f| f.entry.commit.ts < ts)
        {
            return if redo && !revert { Ok(None) } else { Err(Error::NotUndoable { commit: CommitId(id), reason: NotUndoableReason::ContentGone }) };
        }
        Ok(target)
    }

    /// The revert of `target`, or why there is none (never a partial revert).
    fn revert_one(&self, target: CommitId) -> Result<Commit> {
        let me = self.me();
        let blocked = |reason| Error::NotUndoable { commit: target, reason };
        self.locked(|l| {
            // what the revert writes is still this engine's (a move since the source was decided)
            self.guard_commit(l, target.0)?;
            let e = l.engine();
            if let RawChange::Commit(c) = target.0 {
                let h = e.header(&c).filter(|h| self.acting.is_none_or(|a| h.aspects.iter().any(|x| e.readable_by(&a, &x.tid)))).ok_or_else(|| Error::Invalid("unknown commit".into()))?;
                if h.kind != Kind::Content {
                    return Err(Error::Invalid("only changes and reverts are reverted".into()));
                }
                // of what the actor may not read, not asked: `revert_as` refuses it whichever
                if h.aspects.iter().any(|a| a.ak.as_str() != "created.0" && self.acting.is_none_or(|x| e.readable_by(&x, &a.tid)) && !e.body_not_dropped(&c, &a.tid, &a.ak)) {
                    return Err(blocked(NotUndoableReason::ContentGone));
                }
            }
            if let Some(a) = self.acting {
                // an ephemeral commit of what it may not read: as one with no log here
                if let RawChange::Ephemeral(_) = target.0
                    && !e.ephemeral_log().iter().filter(|l| l.id == target.0).all(|l| l.aspects.iter().any(|(t, _)| e.readable_by(&a, t)))
                {
                    return Err(blocked(NotUndoableReason::ContentGone));
                }
            }
            let r = match self.acting {
                Some(a) => e.revert_as(target.0, a)?,
                None => e.revert_batch(target.0, me)?,
            };
            match r {
                Reverted::Written(w) => Ok(Commit::of(w)),
                Reverted::Superseded => Err(blocked(NotUndoableReason::Superseded)),
                Reverted::Compacted => Err(blocked(NotUndoableReason::ContentGone)),
            }
        })
    }
}
