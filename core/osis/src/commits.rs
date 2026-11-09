//! Commits (notes/api.md Commits; spec/commits.md §7, spec/crdt.md §4.6): one `Commit` for every
//! commit the API shows, listed at an address (a value aspect's or a scope's writes, a signal's
//! fires) and heard by that address's listener; and undo, redo and revert. A part of a commit is
//! listed while it is in its aspect's read, kept by history until its keep bound, a purge
//! tombstone, or this node's own invalid write; a commit is listed at an address while it has a
//! listed part there. Nothing is stored for it: a revert is a commit naming the commit it
//! reverts; a commit is in effect while no revert in effect names it; undo and redo pick a commit
//! (`undo_target`, `redo_target`) and revert it. Reverting a thing's creation deletes the thing.

use crate::commit_id::{CommitFrom, CommitId, CommitPos};
use crate::error::{Error, Result};
use crate::handle::{Inner, Osis};
use crate::read::{AspectRef, Reader, Stamp, ak_of, lenient};
use crate::sources::Source;
use crate::watch::{Delivery, Filter, Subscription, lock};
use osis_base::{Ak, Tid, Ts, Value};
use osis_commit::Kind;
use osis_node::engine::listing::{CommitRow, PartBody};
use osis_node::undo::Reverted;
use osis_schema::{AspectKey, SignalKey, ValueKey};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Weak;

/// Commits of a page at most. Resource bound against a caller asking for everything at once under
/// the engine lock: past it a page ends early and says `more`. 0 would read nothing, infinity a
/// whole scope in one call.
#[doc(hidden)]
pub const COMMIT_PAGE: usize = 256;

/// Which aspects a listing, a listener, undo or redo ranges over; resolved when used. `Thing` and
/// `Group` cover durable value aspects; an ephemeral aspect (a cursor, a selection) is in scope
/// only when named by `Aspects`. A signal is in none: its fires are listed at its key.
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
    /// Content written.
    Content,
    /// A content commit reverting another (an undo, or a redo: a revert of a revert).
    Revert,
    /// Who holds which role, and what keeps that working.
    Role,
    /// Older commits tidied into one, which then stands in for them. It names who made it, not who
    /// wrote what it carries: commits known only from it are not listed.
    Snapshot,
}

/// A page of commits to list: where it starts, how many at most, and filters. Empty filters match
/// everything.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommitQuery {
    /// Where the page starts, and which way it goes.
    pub from: CommitFrom,
    /// At most this many (`None`: as many as a page holds).
    pub limit: Option<usize>,
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
}

/// A page of commits, in the direction asked for.
#[derive(Clone, Debug, PartialEq)]
pub struct CommitPage {
    /// The commits, in the order asked for.
    pub commits: Vec<Commit>,
    /// More commits may lie that way: past `limit`, a page's cap or the read limit.
    pub more: bool,
    /// Past the last commit there is nothing this node knows of. `false`: a sync carrying the
    /// address is mid-pass with a connected node or this node never finished one there, so commits
    /// may yet arrive anywhere, older ones too: not fetched, not absent. `true` says nothing of
    /// nodes not connected, and stays true offline.
    pub complete: bool,
}

/// What a commit listener hears.
#[derive(Clone, Debug, PartialEq)]
pub enum CommitEvent {
    /// This commit reads otherwise at the address: new (late ones too), a part turned valid or
    /// invalid, a body arrived, purged, dropped; or an ephemeral signal fired, as it arrived
    /// (nobody holds it: no page shows it). `None`: it is not listed there (any more).
    Commit {
        /// The commit.
        id: CommitId,
        /// It as it reads now.
        commit: Option<Commit>,
    },
    /// Events may have been missed: a connection to the node dropped or came back, or a commit
    /// did not fit. Read the pages shown again; the subscription goes on.
    Reread,
    /// The subscription is over (its group's source moved, or the node ended it): subscribe again.
    Ended(Error),
}

/// What is here of a part's body.
#[derive(Clone, Debug, PartialEq)]
pub enum Body<T> {
    /// Its value, as the commit wrote it (`None`: the write holds no whole value of the key's
    /// type, a removal or a path write, or it does not read as that type: a `Mismatch`
    /// diagnostic).
    Held(Option<T>),
    /// Held, and above `AppConfig::read_limit`.
    TooLarge {
        /// The limit it is above.
        limit: u64,
    },
    /// Purged, on every honest node: the part stays to say so.
    Purged {
        /// The purge.
        by: CommitId,
        /// Who made it (`None`: not known here).
        actor: Option<Tid>,
    },
    /// Not on this node yet: known of, and still to arrive. Not an absence.
    NotFetched,
}

/// One aspect's part of a commit: what it wrote there.
#[derive(Clone, Debug, PartialEq)]
pub struct Part<T> {
    /// Valid here, now: it may change (a listener says when). The commit's actor is verified
    /// exactly when it is. An invalid part is listed only where this node wrote it.
    pub valid: bool,
    /// What is here of what it wrote.
    pub body: Body<T>,
}

/// Reports a typed read's `Mismatch` at the node a commit was read from. Not part of what a
/// commit is: commits compare equal whatever it holds.
#[derive(Clone, Default)]
struct Reporter(Option<Weak<Inner>>);

impl PartialEq for Reporter {
    fn eq(&self, _: &Reporter) -> bool {
        true
    }
}

impl std::fmt::Debug for Reporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("..")
    }
}

/// A commit: who made it and when, what kind, what reverts what, and its parts the caller may
/// read that are listed (on any thing, value or signal).
#[derive(Clone, Debug, PartialEq)]
pub struct Commit {
    /// Which commit, who made it and when.
    pub stamp: Stamp,
    /// What kind of commit it is.
    pub kind: CommitKind,
    /// The commit it reverts.
    pub reverts: Option<CommitId>,
    /// Known reverts of it, oldest first.
    pub reverted_by: Vec<CommitId>,
    /// No revert in effect reverts it.
    pub in_effect: bool,
    parts: Vec<(Tid, Ak, Part<Value>)>,
    report: Reporter,
}

impl Commit {
    /// Its place, for `CommitFrom::Before` and `After`.
    pub fn pos(&self) -> CommitPos {
        self.stamp.pos()
    }

    /// Its part on `k` of `t`, decoded as `k`'s type (`None`: no listed part there).
    pub fn at<K: AspectKey>(&self, t: Tid, k: K) -> Option<Part<K::T>> {
        let ak = ak_of(&k).ok()?;
        let (_, _, p) = self.parts.iter().find(|(pt, pa, _)| *pt == t && *pa == ak)?;
        let body = match &p.body {
            Body::Held(v) => Body::Held(v.as_ref().and_then(|v| {
                lenient(t, &ak, k.decode(v), |d| {
                    if let Some(i) = self.report.0.as_ref().and_then(Weak::upgrade) {
                        Osis::internal(i).engine(|e| e.report(d));
                    }
                })
            })),
            Body::TooLarge { limit } => Body::TooLarge { limit: *limit },
            Body::Purged { by, actor } => Body::Purged { by: *by, actor: *actor },
            Body::NotFetched => Body::NotFetched,
        };
        Some(Part { valid: p.valid, body })
    }

    /// Every part, untyped.
    pub fn parts(&self) -> impl Iterator<Item = (Tid, &Ak, &Part<Value>)> {
        self.parts.iter().map(|(t, a, p)| (*t, a, p))
    }

    /// What its bodies take of a page's byte bound.
    fn bytes(&self) -> usize {
        self.parts.iter().fold(0usize, |n, (_, _, p)| {
            n.saturating_add(match &p.body {
                Body::Held(Some(v)) => osis_base::cbor::encode(v).len(),
                Body::TooLarge { .. } => usize::MAX,
                _ => 0,
            })
        })
    }

    /// A commit read from another node (`port::codec`), parts and all.
    pub(crate) fn of_parts(stamp: Stamp, kind: CommitKind, reverts: Option<CommitId>, reverted_by: Vec<CommitId>, in_effect: bool, parts: Vec<(Tid, Ak, Part<Value>)>) -> Commit {
        Commit { stamp, kind, reverts, reverted_by, in_effect, parts, report: Reporter::default() }
    }

    /// `of_parts`' arguments back (`port::codec`).
    pub(crate) fn raw_parts(&self) -> &[(Tid, Ak, Part<Value>)] {
        &self.parts
    }

    /// Reports mismatches at `db`'s node (a commit read through another node).
    pub(crate) fn reporting(mut self, db: &Osis) -> Commit {
        self.report = Reporter(Some(std::sync::Arc::downgrade(&db.inner)));
        self
    }
}

/// What a commit is, from its header's kind and whether it reverts one.
fn kind_of(k: Kind, reverts: bool) -> CommitKind {
    match k {
        Kind::Content if reverts => CommitKind::Revert,
        Kind::Content => CommitKind::Content,
        Kind::Role => CommitKind::Role,
        Kind::ContentSnapshot | Kind::RoleSnapshot => CommitKind::Snapshot,
    }
}

/// Where commits are listed and heard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Address {
    /// The value aspects of a scope (an aspect's: `Scope::Aspects` naming it).
    Writes(Scope),
    /// A signal's fires.
    Fired(Tid, Ak),
}

impl Address {
    /// The things it is on.
    pub(crate) fn things(&self) -> Vec<Tid> {
        match self {
            Address::Writes(Scope::Thing(t) | Scope::Group(t)) | Address::Fired(t, _) => vec![*t],
            Address::Writes(Scope::Aspects(v)) => v.iter().map(|(t, _)| *t).collect::<BTreeSet<_>>().into_iter().collect(),
        }
    }

    /// Whether a part on `ak` of `tid` is at this address (`in_group`: whether `tid` is the
    /// group or in it, asked only for a group's scope).
    pub(crate) fn holds(&self, tid: Tid, ak: &Ak, in_group: impl FnOnce(Tid) -> bool) -> bool {
        match self {
            Address::Fired(t, a) => *t == tid && a == ak && ak.signal(),
            Address::Writes(_) if ak.signal() => false,
            Address::Writes(Scope::Aspects(v)) => v.iter().any(|(t, a)| *t == tid && a == ak),
            Address::Writes(Scope::Thing(t)) => *t == tid && !ak.ephemeral(),
            Address::Writes(Scope::Group(g)) => !ak.ephemeral() && in_group(*g),
        }
    }
}

/// Relations judged for a listing, each commit's once.
#[derive(Default)]
struct Relations {
    reverters: HashMap<CommitId, Vec<CommitId>>,
    in_effect: HashMap<CommitId, bool>,
}

impl Relations {
    fn reverters(&mut self, e: &osis_node::Engine, c: CommitId) -> Vec<CommitId> {
        self.reverters.entry(c).or_insert_with(|| e.reverters(&c.0).into_iter().map(CommitId).collect()).clone()
    }

    /// No revert in effect reverts it (reverts are newer than what they revert, so this ends).
    fn in_effect(&mut self, e: &osis_node::Engine, c: CommitId) -> bool {
        if let Some(b) = self.in_effect.get(&c) {
            return *b;
        }
        let b = !self.reverters(e, c).into_iter().any(|r| self.in_effect(e, r));
        self.in_effect.insert(c, b);
        b
    }
}

/// `row` as a `Commit` (`limit`: the bound its links materialize under). A link whose value
/// cannot be read here reads as not fetched, a store failure aside.
fn commit_of(r: &mut Reader<'_>, rel: &mut Relations, row: CommitRow, limit: usize) -> Result<Commit> {
    let id = CommitId(row.id);
    let mut parts = Vec::with_capacity(row.parts.len());
    for p in row.parts {
        let body = match p.body {
            PartBody::Held(None) => Body::Held(None),
            PartBody::Held(Some(v)) => match r.materialized(&p.tid, &p.ak, row.id, v, limit) {
                Ok(v) => Body::Held(Some(v)),
                Err(Error::TooLarge { .. }) => Body::TooLarge { limit: limit as u64 },
                Err(e @ Error::Storage(_)) => return Err(e),
                Err(_) => Body::NotFetched,
            },
            PartBody::TooLarge => Body::TooLarge { limit: limit as u64 },
            PartBody::Purged(by) => Body::Purged { by: CommitId(by), actor: r.e.header(&by).map(|h| h.actor) },
            PartBody::Dropped | PartBody::NotFetched => Body::NotFetched,
        };
        parts.push((p.tid, p.ak, Part { valid: p.valid, body }));
    }
    let reverted_by = rel.reverters(r.e, id);
    let in_effect = rel.in_effect(r.e, id);
    Ok(Commit {
        stamp: Stamp::new(id, row.actor, row.node, row.ts, row.received),
        kind: kind_of(row.kind, row.undoes.is_some()),
        reverts: row.undoes.map(CommitId),
        reverted_by,
        in_effect,
        parts,
        report: Reporter::default(),
    })
}

/// Whether `c` passes `q`'s filters.
fn matches(q: &CommitQuery, c: &Commit) -> bool {
    (q.actors.is_empty() || q.actors.contains(&c.stamp.actor))
        && (q.kinds.is_empty() || q.kinds.contains(&c.kind))
        && q.reverts.is_none_or(|x| c.reverts == Some(x))
        && q.reverted_by.is_none_or(|x| c.reverted_by.contains(&x))
        && q.in_effect.is_none_or(|b| c.in_effect == b)
}

/// The undo and redo candidates of a scope, newest first: with the revert depth (0 for a commit,
/// odd for an undo, even above 0 for a redo).
struct Found {
    id: CommitId,
    actor: Tid,
    kind: CommitKind,
    in_effect: bool,
    depth: usize,
}

impl Osis {
    /// The value aspects of `s` the caller may read.
    fn scope_aspects(&self, s: &Scope) -> Result<Vec<(Tid, Ak)>> {
        // acting as an actor: of what it may read only
        let acting = self.acting;
        let shown = |e: &osis_node::Engine, t: &Tid| acting.is_none_or(|a| e.readable_by(&a, t));
        let things = |keep: &dyn Fn(&osis_node::Engine, &Tid) -> bool| -> Result<Vec<(Tid, Ak)>> {
            self.engine(|e| {
                // an ephemeral aspect of a durable thing (a cursor) is in scope only when named
                e.all_aspects().map(|v| v.into_iter().filter(|(t, a)| !a.ephemeral() && !a.signal() && keep(e, t) && shown(e, t)).collect::<Vec<(Tid, Ak)>>())
            })
            .map_err(Error::from)
        };
        Ok(match s {
            Scope::Aspects(v) => self.engine(|e| v.iter().filter(|(t, a)| !a.signal() && shown(e, t)).cloned().collect()),
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

    /// The aspects an address lists at.
    fn address_aspects(&self, a: &Address) -> Result<Vec<(Tid, Ak)>> {
        match a {
            Address::Writes(s) => self.scope_aspects(s),
            Address::Fired(t, ak) => Ok(if ak.signal() && !self.read_local(|r| r.hidden(*t)) { vec![(*t, ak.clone())] } else { Vec::new() }),
        }
    }

    /// Where calls at `a` go.
    pub(crate) fn source_address(&self, a: &Address) -> Result<Source> {
        match a {
            Address::Writes(s) => self.source_scope(Some(s)),
            Address::Fired(t, _) => Ok(self.source(*t)),
        }
    }

    /// A page of the commits listed at `a` at this engine, at most `budget` bytes of bodies.
    pub(crate) fn listing_here(&self, a: &Address, q: &CommitQuery, budget: usize) -> Result<CommitPage> {
        let aks = self.address_aspects(a)?;
        let (mat, actor) = (self.inner.limit, self.acting);
        let budget = budget.min(mat);
        let limit = q.limit.unwrap_or(COMMIT_PAGE);
        let (cut, limit) = (limit > COMMIT_PAGE, limit.min(COMMIT_PAGE));
        self.locked(|l| {
            let complete = a.things().into_iter().all(|t| crate::share::fetched(l, t));
            let mut r = Reader { e: l.engine(), limit: mat, actor };
            let shown = move |e: &mut osis_node::Engine, t: &Tid| actor.is_none_or(|a| e.readable_by(&a, t));
            let (mut commits, mut more, mut used, mut from) = (Vec::new(), false, 0usize, q.from.into());
            let mut rel = Relations::default();
            'walk: loop {
                let places = r.e.places(&aks, from, 64);
                let Some(last) = places.last() else { break };
                from = if q.from.newer() { osis_node::engine::listing::CommitFrom::After(*last) } else { osis_node::engine::listing::CommitFrom::Before(*last) };
                for p in places {
                    if !r.e.listed_at(&p.id, &aks)? {
                        continue;
                    }
                    drop(osis_node::costs::span("listing: commit read"));
                    let Some(row) = r.e.commit_row(&p.id, &shown, budget)? else { continue };
                    let c = commit_of(&mut r, &mut rel, row, budget)?;
                    // links count once materialized: a page fits what a reply carries
                    let bytes = c.bytes();
                    if !matches(q, &c) {
                        continue;
                    }
                    if commits.len() == limit || used > budget {
                        more = true;
                        break 'walk;
                    }
                    used = used.saturating_add(bytes);
                    commits.push(c);
                }
            }
            more |= cut && commits.len() == limit;
            let report = Reporter(Some(std::sync::Arc::downgrade(&self.inner)));
            let commits = commits.into_iter().map(|c| Commit { report: report.clone(), ..c }).collect();
            Ok(CommitPage { commits, more, complete })
        })
    }

    /// Commit `id` at this engine with every listed part the caller may read; `None` when it is
    /// not held here.
    pub(crate) fn commit_here(&self, id: CommitId) -> Result<Option<Commit>> {
        let (mat, actor) = (self.inner.limit, self.acting);
        let c = self.locked(|l| commit_in(&mut Reader { e: l.engine(), limit: mat, actor }, id))?;
        Ok(c.map(|c| c.reporting(self)))
    }

    /// What a listener at `a` is told of `id` at this engine: the commit read now, or `fired`, an
    /// ephemeral signal's commit as it arrived (nobody holds it); `None` when it is not listed at
    /// `a` the caller may read.
    pub(crate) fn commit_told_here(&self, a: &Address, id: CommitId, fired: Option<CommitRow>) -> Result<Option<Commit>> {
        let (mat, actor) = (self.inner.limit, self.acting);
        let c = self.locked(|l| {
            let mut r = Reader { e: l.engine(), limit: mat, actor };
            // a group the caller may not read names nothing (`scope_aspects`)
            if let Address::Writes(Scope::Group(g)) = a
                && r.hidden(*g)
            {
                return Ok(None);
            }
            // the commit's aspects at `a` the caller may read: judged from the commit, never from
            // the whole scope
            let at = |r: &Reader<'_>, t: Tid, k: &Ak| !r.hidden(t) && a.holds(t, k, |g| t == g || r.e.groups_of(&t).contains(&g));
            let row = match fired {
                Some(mut row) => {
                    row.parts.retain(|p| !r.hidden(p.tid));
                    if !row.parts.iter().any(|p| at(&r, p.tid, &p.ak)) {
                        return Ok(None);
                    }
                    row
                }
                None => {
                    let Some(h) = r.e.header(&id.0) else { return Ok(None) };
                    let aks: Vec<(Tid, Ak)> = h.aspects.iter().filter(|x| at(&r, x.tid, &x.ak)).map(|x| (x.tid, x.ak.clone())).collect();
                    if !r.e.listed_at(&id.0, &aks)? {
                        return Ok(None);
                    }
                    let shown = move |e: &mut osis_node::Engine, t: &Tid| actor.is_none_or(|a| e.readable_by(&a, t));
                    match r.e.commit_row(&id.0, &shown, mat)? {
                        Some(row) => row,
                        None => return Ok(None),
                    }
                }
            };
            commit_of(&mut r, &mut Relations::default(), row, mat).map(Some)
        })?;
        Ok(c.map(|c| c.reporting(self)))
    }

    /// A page of the commits listed at `a`, wherever it is read.
    pub(crate) fn listing(&self, a: &Address, q: &CommitQuery) -> Result<CommitPage> {
        match self.source_address(a)? {
            Source::Node(r) => self.node_listing(&r, a, q),
            Source::Local => self.listing_here(a, q, usize::MAX),
        }
    }

    /// Calls `f` for each commit that reads otherwise at `a`, wherever it is read.
    pub(crate) fn on_commits(&self, a: Address, mut f: crate::port::client::CallbackOf<CommitEvent>) -> Result<Subscription> {
        if let Source::Node(r) = self.source_address(&a)? {
            return self.node_on_commits(&r, a, f);
        }
        // the dispatcher's handle acts for no one: read as this one does
        let acting = self.acting;
        Ok(self.subscribe(Filter::Commits(a.clone()), false, move |_| {
            Box::new(move |db, d| match d {
                // what it may not read is not told: an event would tell the commit is there
                Delivery::Commit { tids, .. } if acting.is_some_and(|x| !db.engine(|e| tids.iter().any(|t| e.readable_by(&x, t)))) => {}
                Delivery::Commit { id, fired, .. } => {
                    let told = match acting {
                        Some(x) => db.act_as(x).commit_told_here(&a, id, fired),
                        None => db.commit_told_here(&a, id, fired),
                    };
                    match told {
                        Ok(commit) => f(db, CommitEvent::Commit { id, commit }),
                        Err(e) => f(db, CommitEvent::Ended(e)),
                    }
                }
                Delivery::Moved => f(db, CommitEvent::Ended(crate::sources::moved())),
                _ => {}
            })
        }))
    }

    /// A page of the commits listed in `scope`: those with a listed part on one of its value
    /// aspects, each with every listed part the caller may read. A page costs the commits it
    /// walks, however long the history. An unknown thing, or one the caller may not read, has
    /// none.
    pub fn writes(&self, scope: &Scope, q: &CommitQuery) -> Result<CommitPage> {
        self.listing(&Address::Writes(scope.clone()), q)
    }

    /// Calls `f` for each commit that reads otherwise in `scope` (`writes`), one call per commit,
    /// with the commit as it reads then. Subscribe first, then read pages: nothing after the
    /// subscription is missed, and an event repeating what a page showed is harmless.
    pub fn on_write(&self, scope: &Scope, f: impl FnMut(&Osis, CommitEvent) + Send + 'static) -> Result<Subscription> {
        self.on_commits(Address::Writes(scope.clone()), Box::new(f))
    }

    /// The commit `undo` of `scope` would revert now: none or one. `NotUndoable{ContentGone}` when
    /// it writes back content no kept history holds, as `undo` would be (nothing older instead).
    pub fn undo_target(&self, scope: &Scope) -> Result<Option<Commit>> {
        self.target(scope, false)
    }

    /// The commit `redo` of `scope` would revert now: none or one, as `undo_target`.
    pub fn redo_target(&self, scope: &Scope) -> Result<Option<Commit>> {
        self.target(scope, true)
    }

    fn target(&self, scope: &Scope, redo: bool) -> Result<Option<Commit>> {
        if let Source::Node(r) = self.source_scope(Some(scope))? {
            let m = if redo { crate::port::method::REDO_TARGET } else { crate::port::method::UNDO_TARGET };
            let v = r.call(m, vec![crate::port::codec::scope_v(scope)])?;
            return crate::port::codec::Args::of(vec![v]).opt()?.map(|v| crate::port::codec::commit(v).map(|c| c.reporting(self))).transpose();
        }
        let Some(c) = self.target_id(scope, redo)? else { return Ok(None) };
        self.commit_here(c)
    }

    /// `target`'s commit at this engine.
    fn target_id(&self, scope: &Scope, redo: bool) -> Result<Option<CommitId>> {
        let found = self.found(scope)?;
        let Some(f) = self.pick(found, redo) else { return Ok(None) };
        let c = f.id;
        self.locked(|l| {
            let e = l.engine();
            let gone = Error::NotUndoable { commit: c, reason: NotUndoableReason::ContentGone };
            let r = match self.acting {
                Some(a) => e.check_revertible_as(c.0, a),
                None => e.check_revertible(&c.0),
            };
            match r {
                Ok(()) => Ok(Some(c)),
                Err(osis_node::Error::ContentGone(_)) => Err(gone),
                Err(x) => Err(x.into()),
            }
        })
    }

    /// The held commits validly touching `scope`, newest first, with relations judged over every
    /// held commit that can revert one of them (on their `Engine::revert_reach`).
    fn found(&self, scope: &Scope) -> Result<Vec<Found>> {
        let aks = self.scope_aspects(scope)?;
        let found = self.engine(|e| {
            let base = e.held_commits(Some(&aks));
            let touched: BTreeSet<(Tid, Ak)> = base.iter().flat_map(|c| e.revert_reach(&c.id)).collect();
            let related = e.held_commits(Some(&touched.into_iter().collect::<Vec<_>>()));
            let undoes = |h: &osis_commit::Header| h.undoes.filter(|_| h.kind == Kind::Content).map(CommitId);
            // relations over the related commits, oldest first
            let rel: BTreeMap<(Ts, CommitId), Option<CommitId>> = related.iter().map(|c| ((c.header.ts, CommitId(c.id)), undoes(&c.header))).collect();
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
                        None => e.header(&cur.0).and_then(|h| undoes(&h)),
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
            base.into_iter()
                .map(|c| {
                    let id = CommitId(c.id);
                    Found { id, actor: c.header.actor, kind: kind_of(c.header.kind, undoes(&c.header).is_some()), in_effect: !out_of.contains(&id), depth: depth_of(id) }
                })
                .collect::<Vec<_>>()
        });
        Ok(found)
    }

    /// Undoes this actor's newest commit in effect in `scope` (a redo counts as a commit): reverts
    /// it. `None` when there is none, `NotUndoable` when it cannot be reverted (nothing older is
    /// undone instead).
    pub fn undo(&self, scope: &Scope) -> Result<Option<Commit>> {
        if let Source::Node(r) = self.source_write_scope(scope)? {
            let v = r.call_once(crate::port::method::UNDO, vec![crate::port::codec::scope_v(scope)])?;
            return crate::port::codec::Args::of(vec![v]).opt()?.map(|v| crate::port::codec::commit(v).map(|c| c.reporting(self))).transpose();
        }
        self.step(scope, false)
    }

    /// Redoes this actor's newest undo in effect in `scope`, unless a new commit of this actor
    /// came after it there: reverts the undo. `None` when there is none.
    pub fn redo(&self, scope: &Scope) -> Result<Option<Commit>> {
        if let Source::Node(r) = self.source_write_scope(scope)? {
            let v = r.call_once(crate::port::method::REDO, vec![crate::port::codec::scope_v(scope)])?;
            return crate::port::codec::Args::of(vec![v]).opt()?.map(|v| crate::port::codec::commit(v).map(|c| c.reporting(self))).transpose();
        }
        self.step(scope, true)
    }

    /// Reverts any held commit or revert, durable or ephemeral, this node may write (an admin
    /// reverting someone else's).
    pub fn revert(&self, id: CommitId) -> Result<Commit> {
        if let Source::Node(r) = self.source_write_commit(id.0)? {
            return crate::port::codec::commit(r.call_once(crate::port::method::REVERT, vec![crate::port::codec::commit_id_v(&id)])?).map(|c| c.reporting(self));
        }
        let _g = lock(&self.inner.undo);
        self.revert_one(id)
    }

    /// Undo or redo, serialized under one lock: choose by query, then revert.
    fn step(&self, scope: &Scope, redo: bool) -> Result<Option<Commit>> {
        let _g = lock(&self.inner.undo);
        self.target_id(scope, redo)?.map(|c| self.revert_one(c)).transpose()
    }

    /// The commit undo (redo) of the scope of `found` reverts: this actor's newest commit in
    /// effect (a redo counts as a commit); for redo its newest undo in effect, unless a new commit
    /// of this actor came after it.
    fn pick(&self, found: Vec<Found>, redo: bool) -> Option<Found> {
        let me = self.me();
        let mut mine = found.into_iter().filter(|f| f.actor == me && matches!(f.kind, CommitKind::Content | CommitKind::Revert));
        if redo {
            mine.take_while(|f| f.depth > 0).find(|f| f.in_effect && f.depth % 2 == 1)
        } else {
            mine.find(|f| f.in_effect && f.depth % 2 == 0)
        }
    }

    /// The revert of `target`, or why there is none (never a partial revert).
    fn revert_one(&self, target: CommitId) -> Result<Commit> {
        let me = self.me();
        let blocked = |reason| Error::NotUndoable { commit: target, reason };
        let (mat, actor) = (self.inner.limit, self.acting);
        let c = self.locked(|l| {
            // what the revert writes is still this engine's (a move since the source was decided)
            self.guard_commit(l, target.0)?;
            let e = l.engine();
            let c = target.0;
            let h = e.header(&c).filter(|h| self.acting.is_none_or(|a| h.aspects.iter().any(|x| e.readable_by(&a, &x.tid)))).ok_or_else(|| Error::Invalid("unknown commit".into()))?;
            if h.kind != Kind::Content {
                return Err(Error::Invalid("only changes and reverts are reverted".into()));
            }
            let r = match self.acting {
                Some(a) => e.revert_as(c, a)?,
                None => e.revert_commit(c, me)?,
            };
            match r {
                Reverted::Written(w) => written_in(&mut Reader { e: l.engine(), limit: mat, actor }, w, me),
                Reverted::Superseded => Err(blocked(NotUndoableReason::Superseded)),
                Reverted::ContentGone => Err(blocked(NotUndoableReason::ContentGone)),
            }
        })?;
        Ok(c.reporting(self))
    }
}

/// Commit `id` read in `r`, every listed part the reader may read; `None` when not held.
pub(crate) fn commit_in(r: &mut Reader<'_>, id: CommitId) -> Result<Option<Commit>> {
    let actor = r.actor;
    let shown = move |e: &mut osis_node::Engine, t: &Tid| actor.is_none_or(|a| e.readable_by(&a, t));
    let limit = r.limit;
    match r.e.commit_row(&id.0, &shown, limit)? {
        Some(row) => commit_of(r, &mut Relations::default(), row, limit).map(Some),
        None => Ok(None),
    }
}

/// The commit a write just made, as a listing then shows it; one nobody holds (an ephemeral
/// signal's) with no parts: no listing shows it.
pub(crate) fn written_in(r: &mut Reader<'_>, w: osis_node::Written, actor: Tid) -> Result<Commit> {
    let id = CommitId(w.id);
    if let Some(c) = commit_in(r, id)? {
        return Ok(c);
    }
    Ok(Commit { stamp: Stamp::new(id, actor, r.e.tid(), w.ts, w.ts.wall_ms()), kind: CommitKind::Content, reverts: None, reverted_by: Vec::new(), in_effect: true, parts: Vec::new(), report: Reporter::default() })
}

/// Why a commit cannot be reverted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotUndoableReason {
    /// Reverting it writes back content no kept history holds: what it replaced (a register or
    /// value set), with no history kept or past its keep bound, or what it wrote itself is no
    /// longer here (tidied up, or purged).
    ContentGone,
    /// Reverting it writes nothing: everything it wrote was overwritten since, or is a fire of a
    /// signal (a signal reads absent before and after it).
    Superseded,
}

impl<K: ValueKey> AspectRef<'_, K> {
    /// A page of the commits listed at this value aspect (as `Osis::writes` of
    /// `Scope::Aspects` naming it): those with a listed part here, each with every listed part
    /// the caller may read (`Commit::at` reads this one typed). A dynamic key of a signal lists
    /// nothing.
    pub fn writes(&self, q: &CommitQuery) -> Result<CommitPage> {
        self.db.listing(&Address::Writes(Scope::Aspects(vec![(self.tid, ak_of(&self.key)?)])), q)
    }

    /// Calls `f` for each commit that reads otherwise at this value aspect (`writes`), one call
    /// per commit, with the commit as it reads then. Subscribe first, then read pages.
    pub fn on_write(&self, f: impl FnMut(&Osis, CommitEvent) + Send + 'static) -> Result<Subscription> {
        self.db.on_commits(Address::Writes(Scope::Aspects(vec![(self.tid, ak_of(&self.key)?)])), Box::new(f))
    }
}

impl<K: SignalKey> AspectRef<'_, K> {
    /// A page of this signal's fires, as `writes`. A dynamic key of a value aspect lists nothing.
    pub fn fired(&self, q: &CommitQuery) -> Result<CommitPage> {
        self.db.listing(&Address::Fired(self.tid, ak_of(&self.key)?), q)
    }

    /// Calls `f` for each fire of this signal that reads otherwise (`fired`), as `on_write`.
    /// Each fire of an ephemeral signal is one call, local ones too, with the commit as it
    /// arrived.
    pub fn on_fire(&self, f: impl FnMut(&Osis, CommitEvent) + Send + 'static) -> Result<Subscription> {
        self.db.on_commits(Address::Fired(self.tid, ak_of(&self.key)?), Box::new(f))
    }
}
