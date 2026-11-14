//! Judgement for read sync IDs (spec/sync-judgement.md §1-§5, spec/sync-compaction.md §1,
//! spec/sync-set.md §3).
//!
//! Principle: a reader's store of S holds what its own judgement says S needs; a body leaves it
//! only for a reason every holder sees after one exchange; a node acts at a peer only over what
//! that peer's stream showed (`known`), deletes there only by a Delete signed for the right, and
//! every delete and every logging again is bounded by a change of ground (the peer's head, or a
//! held part falling here). Models: core/test/tla/net/NetHold.tla, NetDestroy.tla.
//!
//! Per (S, commit) a judgement (`judge::body`) gives the body's `Verdict` (must-hold, may-hold,
//! must-not-hold, unjudged) and what the own store calls for: it logs what S must hold and drops
//! what is must-not-hold or covered and dropped (no delete key needed). Per (S, commit, source)
//! keeping S unread a second judgement (`judge::toward`) gives what that source calls for: deletes
//! (carriers in its `known`, role entries first), deposits (not a writer there), or logging again
//! once past a delete, its stand durable in the source's record. Between readers nothing but
//! streams. Per S a destruction judgement (`judge::doom`): told, emptying (the destroying requests
//! kept until their expiry), then forgetting; or, untold past the window, forgetting deleting
//! nothing.
//!
//! Work follows change: each judgement is an `Effects` key over the ground's per-key memo
//! values, stamped rows and read's clock (`Ground`), and read acts only on what a new value adds,
//! once judging reached its fixpoint; nothing re-judges every commit of S per step. A source is
//! judged by what its stream shows (`seen_added`), and for a non-writer there by every must-hold
//! body as it joins. State: the effects, the clock and three stamped maps (verdicts, own role
//! commits S must hold, S told destroyed); nothing durable of its own (stands live in the store's
//! record rows), so a start judges every held commit once.

pub mod ground;
mod judge;
mod live;
mod pieces;
mod views;

pub use ground::{BlobInfo, Facts, Ground, PieceAt, RecordsMissing, Seen, SrcView};
pub use live::Live;

use crate::opens::Opens;
use crate::session::{Incoming, Sessions};
use crate::store::{Source, Stand};
use crate::streams::Streams;
use crate::types::{ConnId, Cx, Error, Result};
use judge::{Act, Doom, Judged, Mine, Toward};
use osis_base::memo::{Clock, Effects, Stamped};
use osis_base::{BlobId, CommitId, SyncId, Tid, WallMs};
use osis_engine::sync::BodyMeta;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A body's verdict at S (spec/sync-judgement.md §2).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Must,
    May,
    MustNot(Why),
    Unjudged,
}

/// Why a body is must-not-hold (spec/sync-judgement.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Why {
    Purged,
    Expired,
    OutsideRequired,
    CardSuperseded,
    CardEnded,
    /// A destroyed thing's sync ID being emptied (§5).
    Emptied,
}

#[derive(Clone)]
pub struct Read {
    /// The time as judgements read it: an answer valid until `t` moves when the clock reaches it.
    clock: Clock,
    bodies: Effects<CommitId, Arc<BTreeMap<SyncId, BodyMeta>>>,
    /// Each commit's bodies as `bodies` last settled them, and the same per (S, commit): what a
    /// judgement reads (`Mine::meta`), so a body coming or going at one sync ID moves the
    /// judgements of that pair alone.
    settled: BTreeMap<CommitId, Arc<BTreeMap<SyncId, BodyMeta>>>,
    metas: Stamped<(SyncId, CommitId), BodyMeta>,
    judged: Effects<(SyncId, CommitId), Judged>,
    toward: Effects<(SyncId, CommitId, Source), Toward>,
    dooms: Effects<SyncId, (Doom, BTreeSet<Act>)>,
    /// Per S, the records it carries as certificates that no own record blob carries
    /// (spec/permissions.md §4): one record blob of them is logged as they move.
    records: Effects<SyncId, Arc<RecordsMissing>>,
    /// Per S, whether this node's step of S is due with the rotations it registers logged here
    /// (`Ground::step_ready`): issued then, whatever connections are open.
    steps: Effects<SyncId, bool>,
    /// Per freed link (blob, thing), what it calls for under each S carrying its thing, and
    /// whether an entry of it is still known (spec/sync-compaction.md §1 Freed links).
    freed: Effects<(BlobId, Tid), judge::Freed>,
    /// The pieces the must-hold bodies link, per (S, piece) (spec/sync-judgement.md §1).
    pieces: pieces::Pieces,
    verdicts: Stamped<(SyncId, CommitId), Verdict>,
    /// Own role commits S must hold (§3 Role entries first).
    roles: Stamped<SyncId, BTreeSet<CommitId>>,
    /// S told destroyed, and its destroying requests (kept until their expiry).
    told: Stamped<SyncId, Arc<BTreeSet<CommitId>>>,
    /// The engine's commits held, followed from the first settle (`Live`).
    commits: Option<osis_base::memo::Feed<CommitId>>,
    /// The sources of each S, as opens moved them.
    views: views::Views,
    /// Cursors over streams' `known` rows and the views, from the first settle (`Live`).
    feeds: live::Feeds,
}

impl Default for Read {
    fn default() -> Self {
        Read {
            clock: Clock::default(),
            bodies: Effects::new("read: bodies"),
            settled: BTreeMap::new(),
            metas: Stamped::default(),
            judged: Effects::new("read: judged"),
            toward: Effects::new("read: toward"),
            dooms: Effects::new("read: doom"),
            records: Effects::new("read: records"),
            steps: Effects::new("read: steps"),
            freed: Effects::new("read: freed"),
            pieces: pieces::Pieces::default(),
            verdicts: Stamped::default(),
            roles: Stamped::default(),
            told: Stamped::default(),
            commits: None,
            views: views::Views::default(),
            feeds: live::Feeds::default(),
        }
    }
}

impl std::fmt::Debug for Read {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Read").field("verdicts", &self.verdicts.len()).finish_non_exhaustive()
    }
}

/// The first value a settle saw for each key it moved, and the last: acts go on the difference
/// once the judgements reach their fixpoint.
type Moved<K, V> = BTreeMap<K, (Option<V>, V)>;

fn note<K: Ord, V>(moved: &mut Moved<K, V>, k: K, was: Option<V>, now: V) {
    match moved.get_mut(&k) {
        Some(m) => m.1 = now,
        None => {
            moved.insert(k, (was, now));
        }
    }
}

impl Read {
    /// The product's step: over the engine, store, opens' members and streams' `known`. Entries
    /// to fetch again (a body counting missing again) go to `fetches`, for streams.
    #[allow(clippy::too_many_arguments)]
    pub fn settle(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, streams: &Streams, status: &crate::status::Status, unread: &crate::unread::Unread, fetches: &mut Vec<(ConnId, SyncId, osis_base::BlobId)>) -> Result<bool> {
        let mut commits = self.commits.take();
        let mut feeds = std::mem::take(&mut self.feeds);
        let views = std::mem::take(&mut self.views);
        let r = self.settle_on(&mut Live { cx, sessions, opens, streams, status, unread, commits: &mut commits, views: &views, feeds: &mut feeds, fetches });
        self.commits = commits;
        self.feeds = feeds;
        self.views = views;
        r
    }

    /// A member joined or left a connection's shared set (opens' word, through the driver).
    pub fn moved(&mut self, m: &crate::opens::Moved, opens: &Opens) {
        self.views.moved(m, opens);
    }

    /// One settle over `g`: whether anything acted. Judging runs to a fixpoint (a verdict moving
    /// the own role commits re-judges what waits on them) before anything acts, so the order the
    /// keys come in (a start judges every one) never lets an act skip a rule.
    pub fn settle_on(&mut self, g: &mut impl Ground) -> Result<bool> {
        let added = match g.commits_added() {
            Err(e) if not_built(&e) => return Ok(false),
            r => r?,
        };
        self.clock.set(g.now().0);
        for c in added {
            self.bodies.want(c);
        }
        for c in self.bodies.due() {
            let Some((_, now)) = self.bodies.try_settle(&c, || g.bodies(&c))? else { continue };
            let was = self.settled.insert(c, now.clone()).unwrap_or_default();
            for s in was.keys().filter(|s| !now.contains_key(*s)) {
                self.metas.remove(&(*s, c));
            }
            for (s, m) in now.iter().filter(|(s, m)| was.get(*s) != Some(*m)) {
                self.metas.insert((*s, c), m.clone());
            }
            for s in now.keys() {
                self.judged.want((*s, c));
                self.dooms.want(*s);
                self.records.want(*s);
                self.steps.want(*s);
            }
            // a sync ID no longer carrying it stays followed until nothing of it is left there
        }
        let mut acted = false;
        for s in self.dooms.due() {
            let told_before = self.told.contains_key(&s);
            let mine = Mine { verdicts: &self.verdicts, roles: &self.roles, told: &self.told, clock: &self.clock, metas: &self.metas };
            let Some((was, (doom, acts))) = self.dooms.try_settle(&s, || judge::doom(g, &mine, told_before, &s))? else { continue };
            let before = was.map(|(_, a)| a).unwrap_or_default();
            acted = true;
            match &doom {
                Doom::Told { requests } if self.told.get(&s) != Some(requests) => {
                    self.told.insert(s, requests.clone());
                }
                Doom::Told { .. } => {}
                _ if self.told.contains_key(&s) => {
                    self.told.remove(&s);
                }
                _ => {}
            }
            for a in acts.difference(&before).cloned().collect::<Vec<_>>() {
                self.act(g, &s, None, a)?;
            }
        }
        // the records each S carries, as one record blob of those its own store lacks, while a
        // reader can pull it (spec/permissions.md §4, spec/sync-judgement.md §3 Own store)
        for s in self.records.due() {
            if !g.reads(&s)? {
                self.records.unwant(&s);
                continue;
            }
            // pullable read inside: a sync ID a reader cannot pull yet is due again once it can
            let Some((_, now)) = self.records.try_settle(&s, || records_missing(g, &s).map(Arc::new))? else { continue };
            if !now.gone.is_empty() {
                g.forget_record_blobs(&s, &now.gone)?;
                acted = true;
            }
            if !now.records.is_empty() {
                g.log_records(&s, &now.records)?;
                acted = true;
            }
        }
        // the step due of each S, once the rotations it registers are logged here (spec/sync-ids.md
        // §6 Steps); tried again whenever what it read moves while ready (a role blocked here
        // issues nothing until the rotation that unblocks it)
        for s in self.steps.due() {
            if !g.reads(&s)? {
                self.steps.unwant(&s);
                continue;
            }
            let mut ready = false;
            self.steps.try_settle(&s, || {
                ready = g.step_ready(&s)?;
                Ok::<bool, crate::types::Error>(ready)
            })?;
            if ready && g.issue_step(&s)? {
                acted = true;
            }
        }
        // the own judgement of each body, to its fixpoint
        let mut judged: Moved<(SyncId, CommitId), Judged> = BTreeMap::new();
        loop {
            let due = self.judged.due();
            if due.is_empty() {
                break;
            }
            for k in due {
                let (s, c) = k;
                let mine = Mine { verdicts: &self.verdicts, roles: &self.roles, told: &self.told, clock: &self.clock, metas: &self.metas };
                let Some((was, now)) = self.judged.try_settle(&k, || judge::body(g, &mine, &s, &c))? else { continue };
                if self.verdicts.get(&k) != Some(&now.verdict) {
                    self.verdicts.insert(k, now.verdict.clone());
                    // a non-writer gives a must-hold body to each store source lacking it
                    if now.verdict == Verdict::Must {
                        for at in self.giving_to(g, &s)? {
                            self.toward.want((s, c, at));
                        }
                    }
                }
                self.set_role(&s, &c, now.role && !now.idle);
                if now.idle {
                    self.judged.unwant(&k);
                    self.verdicts.remove(&k);
                }
                let links = |j: &Judged| (j.roots.to_vec(), j.repairs);
                let (old, new) = (was.as_ref().map(links).unwrap_or_default(), links(&now));
                self.pieces.body(&s, &c, (&old.0, old.1), (&new.0, new.1), &now.fresh);
                note(&mut judged, k, was, now);
            }
        }
        // each piece the must-hold bodies link, to its fixpoint (a node judged held follows what
        // lies below it)
        loop {
            let due = self.pieces.judged.due();
            if due.is_empty() {
                break;
            }
            for k in due {
                let Some(p) = self.pieces.link_of(&k) else { continue };
                let Some((_, now)) = self.pieces.judged.try_settle(&k, || judge::piece(g, &k.0, &p))? else { continue };
                self.pieces.settled(&k, now);
            }
        }
        for ((s, c), (was, now)) in judged {
            acted = true;
            let before = was.map(|w| w.acts).unwrap_or_default();
            for a in now.acts.difference(&before).cloned().collect::<Vec<_>>() {
                self.act(g, &s, Some(&c), a)?;
            }
        }
        // what the pieces newly call for; a lost one is repaired in the own bodies over it, each
        // body's in one commit
        let (acts, repairs) = self.pieces.acts();
        for ((s, _), a) in acts {
            acted = true;
            self.act(g, &s, None, a)?;
        }
        for (c, b) in repairs {
            acted = true;
            g.repair(&c, &b)?;
        }
        // what each body calls for at each source keeping S unread: the rows a source's stream
        // wrote, and a source joining or moving (a non-writer there gives every must-hold body)
        for (at, s, c) in g.seen_added()? {
            self.toward.want((s, c, at));
        }
        for (s, at) in g.sources_added()? {
            if self.giving_to(g, &s)?.contains(&at) {
                let must: Vec<CommitId> = self.verdicts.range((s, CommitId([0; 32]))..=(s, CommitId([0xff; 32]))).filter(|(_, v)| **v == Verdict::Must).map(|((_, c), _)| *c).collect();
                for c in must {
                    self.toward.want((s, c, at));
                }
            }
        }
        let mut toward: Moved<(SyncId, CommitId, Source), Toward> = BTreeMap::new();
        loop {
            let due = self.toward.due();
            if due.is_empty() {
                break;
            }
            for k in due {
                let (s, c, at) = k;
                let mine = Mine { verdicts: &self.verdicts, roles: &self.roles, told: &self.told, clock: &self.clock, metas: &self.metas };
                let Some((was, now)) = self.toward.try_settle(&k, || judge::toward(g, &mine, &s, &c, &at))? else { continue };
                if now.idle {
                    self.toward.unwant(&k);
                }
                note(&mut toward, k, was, now);
            }
        }
        for ((s, c, _), (was, now)) in toward {
            acted = true;
            let before = was.map(|w| w.acts).unwrap_or_default();
            for a in now.acts.difference(&before).cloned().collect::<Vec<_>>() {
                self.act(g, &s, Some(&c), a)?;
            }
        }
        // freed links: dropped here and deleted at the sources keeping S unread that show them,
        // until no entry of them is known
        for k in g.freed_added()? {
            self.freed.want(k);
        }
        for k in self.freed.due() {
            let Some((was, (acts, known))) = self.freed.try_settle(&k, || judge::freed(g, &k.0, &k.1))? else { continue };
            acted = true;
            let before = was.map(|w| w.0).unwrap_or_default();
            for (s, a) in acts.difference(&before).cloned().collect::<Vec<_>>() {
                self.act(g, &s, None, a)?;
            }
            if !known {
                self.freed.unwant(&k);
                g.freed_done(&k.0, &k.1)?;
            }
        }
        Ok(acted)
    }

    /// The store sources of S where this node is no writer at their head (it gives them what it
    /// must hold; a writer's store is pulled).
    fn giving_to(&self, g: &mut impl Ground, s: &SyncId) -> Result<Vec<Source>> {
        let creds = g.credentials(s)?;
        let writer = |h: &osis_label::StepId| creds.as_ref().and_then(|c| c.keys.get(h)).is_some_and(|k| k.write.is_some());
        Ok(g.sources(s)?.iter().filter(|x| x.store && !x.head.is_some_and(|h| writer(&h))).map(|x| x.at).collect())
    }

    /// Answers to its own requests: a Delete's codes reach `known` through the source's stream,
    /// so nothing is taken from them here.
    pub fn on_message(&mut self, cx: &mut Cx, sessions: &mut Sessions, conn: ConnId, m: Incoming) {
        let _ = (cx, sessions, conn, m);
    }

    /// For status and inbox (stamped read).
    pub fn verdict(&self, s: &SyncId, c: &CommitId) -> Option<Verdict> {
        self.verdicts.get(&(*s, *c)).cloned()
    }

    /// Tests: the pieces followed, acting or dormant (spec/sync-judgement.md §1).
    #[doc(hidden)]
    pub fn pieces_followed(&self) -> usize {
        self.pieces.followed()
    }

    /// When a judgement read up to a time (an expiry) moves next.
    pub fn next_wake(&self) -> Option<WallMs> {
        self.clock.next().map(WallMs)
    }

    fn set_role(&mut self, s: &SyncId, c: &CommitId, on: bool) {
        let has = self.roles.get(s).is_some_and(|r| r.contains(c));
        if has == on {
            return;
        }
        let mut r = self.roles.get(s).cloned().unwrap_or_default();
        if on {
            r.insert(*c);
        } else {
            r.remove(c);
        }
        if r.is_empty() {
            self.roles.remove(s);
        } else {
            self.roles.insert(*s, r);
        }
    }

    fn act(&mut self, g: &mut impl Ground, s: &SyncId, c: Option<&CommitId>, a: Act) -> Result<()> {
        osis_base::costs::count("read: acts", 1);
        match (a, c) {
            (Act::Log, Some(c)) => {
                g.log_own(s, c, false)?;
            }
            (Act::DropOwn(b), Some(c)) => g.drop_own(s, &b, c)?,
            (Act::Lift(b), _) => g.lift(s, &b)?,
            (Act::Fetch { at, conn, blob }, _) => {
                if let Some(src) = g.source(s, &at)?.filter(|x| x.conn == conn) {
                    g.fetch(&src, s, &blob)?;
                }
            }
            (Act::Delete { at, conn, head, blob }, _) => {
                let Some(src) = g.source(s, &at)?.filter(|x| x.conn == conn) else { return Ok(()) };
                let key = g.credentials(s)?.and_then(|cr| cr.keys.get(&head).and_then(|k| k.delete.clone()));
                if let Some(key) = key {
                    g.delete(&src, s, &blob, &key)?;
                }
            }
            (Act::Deposit { at, conn, blob }, Some(c)) => {
                if let Some(src) = g.source(s, &at)?.filter(|x| x.conn == conn) {
                    g.deposit(&src, s, c, &blob)?;
                }
            }
            (Act::Again { at, head, fall, old, .. }, Some(c)) => {
                // a fresh encryption under this sync ID alone; its stand first, durably
                if let Some(logged) = g.log_own(s, c, true)? {
                    g.set_stand(&at, s, c, &Stand { at: g.now(), logged, head, fall })?;
                    for b in old {
                        g.drop_own(s, &b, c)?;
                    }
                }
            }
            (Act::Forget, _) => g.forget(s)?,
            (Act::LogPiece(b), _) => g.log_piece(s, &b)?,
            (Act::TakePiece(b), _) => g.take_piece(s, &b)?,
            (Act::Repair(_), _) => {}
            (Act::DropPiece(b), _) => g.drop_piece(s, &b)?,
            (Act::DeleteFreed { at, conn, head, blob, thing }, _) => {
                let Some(src) = g.source(s, &at)?.filter(|x| x.conn == conn) else { return Ok(()) };
                g.delete_freed(&src, s, &head, &blob, &thing)?;
            }
            (_, None) => {}
        }
        Ok(())
    }
}

/// Settles `k` with `f`; a failure leaves `k` due and is returned.
/// `Ground::records_missing` while a reader can pull S, else nothing (`pullable` read inside, so
/// S is due again once it can).
fn records_missing(g: &mut impl Ground, s: &SyncId) -> Result<RecordsMissing> {
    match g.pullable(s)? {
        true => g.records_missing(s),
        false => Ok(RecordsMissing::default()),
    }
}

/// A part of the facade or of another module read needs is not built: read does nothing until
/// it is.
fn not_built(e: &Error) -> bool {
    matches!(e, Error::NotBuilt(_) | Error::Engine(osis_engine::Error::NotBuilt(_)))
}
