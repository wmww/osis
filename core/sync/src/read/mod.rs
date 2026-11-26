//! Judgement for read sync IDs (spec/sync-judgement.md §1-§5, spec/sync-compaction.md §1,
//! spec/sync-set.md §3).
//!
//! Principle: a reader's store of S holds what its own judgement says S needs; a body leaves it
//! only for a reason every holder sees after one exchange; a node acts at a peer only over what
//! that peer's stream showed (`known`), deletes there only by a Delete signed for the right, and
//! every delete and every logging again is bounded by a change of ground (the peer's head, or a
//! held part falling here). Models: core/test/tla/net/NetHold.tla.
//!
//! Per (S, commit) a judgement (`judge::body`) gives the body's `Verdict` (must-hold, may-hold,
//! must-not-hold, unjudged) and what the own store calls for: it logs what S must hold and drops
//! what is must-not-hold or covered and dropped (no delete key needed). Per (S, commit, source)
//! keeping S unread a second judgement (`judge::toward`) gives what that source calls for: deletes
//! (carriers in its `known`, role entries first), deposits (not a writer there), or logging again
//! once past a delete, its stand durable in the source's record. Between readers nothing but
//! streams.
//!
//! Work follows change: each judgement is an `Effects` key over the ground's per-key memo
//! values, stamped rows and read's clock (`Ground`), and read acts only on what a new value adds,
//! once judging reached its fixpoint; nothing re-judges every commit of S per step. A source is
//! judged by what its stream shows (`seen_added`), and for a non-writer there by every must-hold
//! body as it joins. State: the effects, the clock and two stamped maps (verdicts, own role
//! commits S must hold); nothing durable of its own (stands live in the store's
//! record rows), so a start judges every held commit once.

pub mod ground;
mod judge;
mod live;
mod owed;
mod pieces;

pub use ground::{BlobInfo, CertBlobsMissing, SyncCopiesDue, Facts, Ground, PieceAt, Seen, SrcView, StepReady};
pub use live::Live;

/// What read asks a source for on a connection, outside any message (spec/sync-judgement.md §3
/// Dropped bodies): an entry its stream showed, or a body by its commit ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ask {
    Entry(BlobId),
    Body(CommitId),
}

/// An entry of S read gives the source on a connection as a Deposit item of itself, signed for
/// the source's head (spec/sync-judgement.md §3 Giving a body), by inbox's offers.
pub type Give = (ConnId, SyncId, BlobId, osis_blob::StepId);

use crate::opens::Opens;
use crate::session::{Incoming, Sessions};
use crate::store::{Source, Stand};
use crate::streams::Streams;
use crate::types::{ConnId, Cx, Result};
use judge::{Act, Judged, Mine, Toward};
use osis_base::memo::{Clock, Effects, Stamped};
use osis_base::{BlobId, CommitId, SyncId, Tid, WallMs};
use osis_engine::sync::{BodyId, BodyMeta};
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
}

#[derive(Clone)]
pub struct Read {
    /// The time as judgements read it: an answer valid until `t` moves when the clock reaches it.
    clock: Clock,
    bodies: Effects<CommitId, Arc<osis_engine::sync::Bodies>>,
    /// Each commit's bodies as `bodies` last settled them, and the same per (S, body): what a
    /// judgement reads (`Mine::meta`), so a body coming or going at one sync ID moves the
    /// judgements of that pair alone.
    settled: BTreeMap<CommitId, Arc<osis_engine::sync::Bodies>>,
    metas: Stamped<(SyncId, BodyId), BodyMeta>,
    judged: Effects<(SyncId, BodyId), Judged>,
    /// Per (S, thing) whose minting copies are in S's required set (`BodyMeta::mints`), each
    /// copy's place among the thing's mintings (`judge::mintings`), and the same per (S, minting,
    /// thing) (`Mine::mints`), so one minting moving re-judges the copies whose place moved alone.
    mintings: Effects<(SyncId, Tid), Arc<BTreeMap<CommitId, judge::Mint>>>,
    mints: Stamped<(SyncId, CommitId, Tid), judge::Mint>,
    toward: Effects<(SyncId, BodyId, Source), Toward>,
    /// Per S, the records S carries as certificates that no own certificate blob carries
    /// (spec/permissions.md §4, spec/sync-judgement.md §1): one record blob of them is logged as
    /// they move.
    cert_blobs: Effects<SyncId, Arc<CertBlobsMissing>>,
    /// Per S, the sync copies S carries set against their logs in the own store: each missing
    /// one logged, a duplicate or one carried no more unlogged (`Ground::sync_copies_due`).
    sync_copies: Effects<SyncId, Arc<SyncCopiesDue>>,
    /// Per S, whether this node's step of S is due with the rotations it registers logged here
    /// (`Ground::step_ready`): issued then, whatever connections are open.
    steps: Effects<SyncId, bool>,
    /// Per S whose deposit-only step is due, the pass place it came due at: a complete pass
    /// begun after it ends before it is issued (`StepReady::AfterPass`).
    step_since: BTreeMap<SyncId, u64>,
    /// Per freed link (blob, thing), what it calls for under each S carrying its thing, and
    /// whether an entry of it is still known (spec/sync-compaction.md §1 Freed links).
    freed: Effects<(BlobId, Tid), judge::Freed>,
    /// The pieces the must-hold bodies link, per (S, piece) (spec/sync-judgement.md §1).
    pieces: pieces::Pieces,
    /// Per held commit, what it calls for in the engine: covered parts dropped, then forgotten
    /// (spec/commits.md §5 Covered, Forgetting; `judge::local`).
    local: Effects<CommitId, judge::Local>,
    verdicts: Stamped<(SyncId, BodyId), Verdict>,
    /// Own role commits S must hold (§3 Role entries first: what a delete waits for).
    roles: Stamped<SyncId, BTreeSet<BodyId>>,
    /// Every role commit or request S must hold here, own or pulled (§3 Role entries first: what
    /// a logging again waits for); read only where one is due.
    held_roles: Stamped<SyncId, BTreeSet<BodyId>>,
    /// Per (S, body), the pass place an entry of it last came into the own store of S; per
    /// commit, the pass place what its bodies read last moved; per S, the newest place a
    /// judgement outside S's required set waits a complete pass after (`judge::outside`, status
    /// runs it: `passes_wanted`).
    arrived: Stamped<(SyncId, BodyId), u64>,
    moved: Stamped<CommitId, u64>,
    waits: Stamped<SyncId, u64>,
    /// Per S whose certificate blobs are followed, the pass place they were first followed at:
    /// what a new reader logs of them waits for a complete pass begun after it, unless S's
    /// first sync here ended (`cert_blobs_missing`).
    cert_since: BTreeMap<SyncId, u64>,
    /// The engine's commits held, followed from the first settle (`Live`).
    commits: Option<osis_base::memo::Feed<CommitId>>,
    /// The acts owed each source, carried out on its record's connection (`read/owed.rs`).
    owed: owed::Owed,
    /// Cursors over streams' `known` rows and opens' sources, from the first settle (`Live`).
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
            mintings: Effects::new("read: mintings"),
            mints: Stamped::default(),
            toward: Effects::new("read: toward"),
            cert_blobs: Effects::new("read: certificate blobs"),
            sync_copies: Effects::new("read: sync copies"),
            steps: Effects::new("read: steps"),
            step_since: BTreeMap::new(),
            freed: Effects::new("read: freed"),
            pieces: pieces::Pieces::default(),
            local: Effects::new("read: local"),
            verdicts: Stamped::default(),
            roles: Stamped::default(),
            held_roles: Stamped::default(),
            arrived: Stamped::default(),
            moved: Stamped::default(),
            waits: Stamped::default(),
            cert_since: BTreeMap::new(),
            commits: None,
            owed: owed::Owed::default(),
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
    /// to fetch again (a body counting missing again) go to `fetches`, for streams; entries given
    /// a source as deposits to `gives`, for inbox.
    #[allow(clippy::too_many_arguments)]
    pub fn settle(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, streams: &Streams, status: &crate::status::Status, unread: &crate::unread::Unread, fetches: &mut Vec<(ConnId, SyncId, Ask)>, gives: &mut Vec<Give>) -> Result<bool> {
        let mut commits = self.commits.take();
        let mut feeds = std::mem::take(&mut self.feeds);
        let r = osis_base::costs::scoped("read", || self.settle_on(&mut Live { cx, sessions, opens, streams, status, unread, commits: &mut commits, feeds: &mut feeds, fetches, gives }));
        self.commits = commits;
        self.feeds = feeds;
        r
    }

    /// `conn` ended: what it carried unanswered goes on its record's next connection.
    pub fn closed(&mut self, conn: ConnId) {
        self.owed.closed(conn);
    }

    /// Tests: the acts owed sources and not done (`read/owed.rs`).
    #[doc(hidden)]
    pub fn owed_pending(&self) -> usize {
        self.owed.pending()
    }

    /// Follows S's record blob, unless already followed.
    fn follow_cert_blobs(&mut self, g: &mut impl Ground, s: &SyncId) {
        if !self.cert_blobs.wants(s) {
            self.cert_since.insert(*s, g.place());
            self.cert_blobs.want(*s);
            self.sync_copies.want(*s);
        }
    }

    /// One settle over `g`: whether anything acted. Judging runs to a fixpoint (a verdict moving
    /// the own role commits re-judges what waits on them) before anything acts, so the order the
    /// keys come in (a start judges every one) never lets an act skip a rule.
    pub fn settle_on(&mut self, g: &mut impl Ground) -> Result<bool> {
        g.refresh()?;
        let added = g.commits_added();
        self.clock.set(g.now().0);
        for c in added {
            self.bodies.want(c);
        }
        let place = g.place();
        // a wait a complete pass ended is over (the judgements waiting read the pass themselves)
        let waits: Vec<(SyncId, u64)> = self.waits.iter().map(|(s, w)| (*s, *w)).collect();
        for (s, w) in waits {
            if g.passed(&s, w) {
                self.waits.remove(&s);
            }
        }
        for c in self.bodies.due() {
            let Some((_, now)) = self.bodies.try_settle(&c, || g.bodies(&c))? else { continue };
            // what it read moved: a judgement outside S waits a pass begun after now (a body read
            // again unchanged moves nothing)
            self.moved.insert(c, place);
            let was = self.settled.insert(c, now.clone()).unwrap_or_default();
            let id = |on: &Option<Tid>| BodyId { commit: c, on: *on };
            for (s, on) in was.keys().filter(|k| !now.contains_key(*k)) {
                self.metas.remove(&(*s, id(on)));
            }
            for ((s, on), m) in now.iter().filter(|(k, m)| was.get(*k) != Some(*m)) {
                self.metas.insert((*s, id(on)), m.clone());
            }
            for ((s, _), m) in now.iter() {
                for t in &m.mints {
                    self.mintings.want((*s, *t));
                }
            }
            self.local.want(c);
            for (s, on) in now.keys() {
                self.judged.want((*s, id(on)));
                self.follow_cert_blobs(g, s);
                self.steps.want(*s);
            }
            // a sync ID no longer carrying it stays followed until nothing of it is left there
        }
        // every entry held under S is judged under S, a body there or not (spec/sync-judgement.md
        // §2: one of a commit S carries no body of is outside the required set)
        // and every entry a source's stream shows (spec/sync-judgement.md §3 What a source
        // holds): what it calls for there is that source's (`toward`), and its own judgement
        // keeps it (a start replays every row, so what is owed at a source away is owed again)
        let seen: Vec<(Source, SyncId, BodyId)> = g.seen_added()?;
        let mut shown = Vec::new();
        for (_, s, c) in &seen {
            if g.holds(&c.commit) {
                shown.push((*s, *c));
            }
        }
        for k in g.entries_added()?.into_iter().chain(shown) {
            self.arrived.insert(k, place);
            self.judged.want(k);
        }
        for (at, s, c) in seen {
            self.toward.want((s, c, at));
        }
        // a sync ID coming to be read: a judgement while it was not (it joined the engine's sync
        // set before the store's holdings) left its keys unfollowed
        for s in g.holdings_moved() {
            if !g.reads(&s) {
                continue;
            }
            for (k, _) in self.metas.range((s, BodyId::unit(CommitId([0; 32])))..).take_while(|(k, _)| k.0 == s) {
                self.judged.want(*k);
            }
            self.follow_cert_blobs(g, &s);
            self.steps.want(s);
        }
        let mut acted = false;
        // the records each S carries, as one record blob of those its own store lacks, while a
        // reader can pull it (spec/permissions.md §4, spec/sync-judgement.md §3 Own store)
        let mut unread = BTreeSet::new();
        for s in self.cert_blobs.due() {
            if !g.reads(&s) {
                self.cert_blobs.unwant(&s);
                self.cert_since.remove(&s);
                unread.insert(s);
                continue;
            }
            // pullable read inside: a sync ID a reader cannot pull yet is due again once it can
            let since = self.cert_since.get(&s).copied().unwrap_or(0);
            let Some((was, now)) = self.cert_blobs.try_settle(&s, || cert_blobs_missing(g, &s, since).map(Arc::new))? else { continue };
            if let Some(w) = now.wait {
                wait_pass(&mut self.waits, s, w);
            }
            // one S needs no more leaves the own store, no tombstone (spec/sync-judgement.md §3
            // Own store); what the engine kept of it goes once no source shows it either
            for b in &now.unneeded {
                g.unlog(&s, b)?;
                acted = true;
            }
            if !now.gone.is_empty() {
                g.forget_cert_blobs(&s, &now.gone)?;
                acted = true;
            }
            // a winner the own store lacks, fetched where shown (spec/permissions.md §4)
            let before = was.as_ref().map(|w| w.fetch.clone()).unwrap_or_default();
            for (at, blob) in before.difference(&now.fetch) {
                self.owed.remove(&(s, None, Act::Fetch { at: *at, blob: *blob }));
            }
            for (at, blob) in now.fetch.difference(&before).copied().collect::<Vec<_>>() {
                self.act(g, &s, None, Act::Fetch { at, blob })?;
                acted = true;
            }
            let before = was.map(|w| w.deletes.clone()).unwrap_or_default();
            for (at, head, blob) in before.difference(&now.deletes) {
                self.owed.remove(&(s, None, Act::Delete { at: *at, head: *head, blob: *blob, full: false }));
            }
            for (at, head, blob) in now.deletes.difference(&before).copied().collect::<Vec<_>>() {
                self.act(g, &s, None, Act::Delete { at, head, blob, full: false })?;
                acted = true;
            }
            for b in &now.stale {
                g.restamp(&s, b)?;
                acted = true;
            }
            if !now.missing.is_empty() {
                g.log_cert_blob(&s, &now.missing)?;
                acted = true;
            }
        }
        // the sync copies and notices each S carries, one blob of each content, while a reader
        // can pull it (spec/permissions.md §4 Logging certificates, Notices)
        for s in self.sync_copies.due() {
            if !g.reads(&s) {
                self.sync_copies.unwant(&s);
                continue;
            }
            let since = self.cert_since.get(&s).copied().unwrap_or(0);
            let Some((_, now)) = self.sync_copies.try_settle(&s, || sync_copies_due(g, &s, since).map(Arc::new))? else { continue };
            if let Some(w) = now.wait {
                wait_pass(&mut self.waits, s, w);
            }
            for b in &now.unneeded {
                g.unlog(&s, b)?;
                acted = true;
            }
            for b in &now.logged_deposits {
                g.drop_blob(&s, b)?;
                acted = true;
            }
            for b in &now.stale {
                g.restamp(&s, b)?;
                acted = true;
            }
            for k in &now.missing {
                g.log_sync_copy(&s, k)?;
                acted = true;
            }
        }
        // the step due of each S, once the rotations it registers are logged here (spec/sync-ids.md
        // §6 Steps); tried again whenever what it read moves while ready (a role blocked here
        // issues nothing until the rotation that unblocks it)
        for s in self.steps.due() {
            if !g.reads(&s) {
                self.steps.unwant(&s);
                self.step_since.remove(&s);
                continue;
            }
            let (mut ready, mut since) = (false, None);
            let at = &mut self.step_since;
            self.steps.try_settle(&s, || {
                ready = match g.step_ready(&s)? {
                    StepReady::No => {
                        at.remove(&s);
                        false
                    }
                    StepReady::Now => true,
                    StepReady::AfterPass => {
                        let w = *at.entry(s).or_insert(place);
                        since = Some(w);
                        g.passed(&s, w)
                    }
                };
                Ok::<bool, crate::types::Error>(ready)
            })?;
            // status runs the pass a deposit-only step waits for (`passes_wanted`)
            if let Some(w) = since.filter(|_| !ready) {
                wait_pass(&mut self.waits, s, w);
            }
            if ready && g.issue_step(&s)? {
                self.step_since.remove(&s);
                acted = true;
            }
        }
        // each thing's minting copies by standing, before the bodies that read them (it reads
        // the engine, the own store and the bodies alone)
        for k in self.mintings.due() {
            let (s, t) = k;
            let metas = &self.metas;
            let Some((was, now)) = self.mintings.try_settle(&k, || judge::mintings(g, metas, &s, &t))? else { continue };
            let was = was.unwrap_or_default();
            for c in was.keys().filter(|c| !now.contains_key(*c)) {
                self.mints.remove(&(s, *c, t));
            }
            for (c, m) in now.iter() {
                self.mints.insert((s, *c, t), *m);
            }
            if now.is_empty() {
                self.mintings.unwant(&k);
            }
        }
        // the own judgement of each body, to its fixpoint, then its acts; again while acting on
        // the own store moved what a judgement reads, so each value kept is judged after its own
        // acts (an own entry logged and then dropped by another module before the next settle,
        // a forgotten commit's, reads as the same value and would never be logged again).
        // Bounded (debug builds, `LoopGuard`): a round runs again only for a judgement whose
        // value its acts moved, each moving once for what came in and once after its own acts, so
        // at most twice the judgements moved and one more; at infinity two judgements undoing each
        // other's acts hang the node with no settle round to catch it
        let mut guard = osis_base::loop_guard::LoopGuard::new("read: judgements and their acts (Read::settle_on)");
        let mut keys = BTreeSet::new();
        loop {
            let mut judged: Moved<(SyncId, BodyId), Judged> = BTreeMap::new();
            loop {
                g.refresh()?;
                let due = self.judged.due();
                if due.is_empty() {
                    break;
                }
                for k in due {
                    let (s, c) = k;
                    let mine = Mine { verdicts: &self.verdicts, roles: &self.roles, held_roles: &self.held_roles, clock: &self.clock, metas: &self.metas, mints: &self.mints, arrived: &self.arrived, moved: &self.moved };
                    let Some((was, now)) = self.judged.try_settle(&k, || judge::body(g, &mine, &s, &c))? else { continue };
                    if self.verdicts.get(&k) != Some(&now.verdict) {
                        #[cfg(debug_assertions)]
                        osis_base::trace::note(|| format!("verdict {s:?} {c:?}: {:?} -> {:?} ({})", self.verdicts.get(&k).unwrap_or(&Verdict::Unjudged), now.verdict, judge::last_why()));
                        self.verdicts.insert(k, now.verdict.clone());
                        // what it calls for at each source whose stream shows it, up now or away (a
                        // start judges every body: what the sources showed before is judged then)
                        for at in g.shown_at(&s, &c)? {
                            self.toward.want((s, c, at));
                        }
                        // a must-hold body given to each store source lacking it
                        if now.verdict == Verdict::Must {
                            for at in self.giving_to(g, &s, now.held_role)? {
                                self.toward.want((s, c, at));
                            }
                        }
                    }
                    set_in(&mut self.roles, &s, &c, now.role && !now.idle);
                    set_in(&mut self.held_roles, &s, &c, now.held_role && !now.idle);
                    if let Some(w) = now.wait {
                        wait_pass(&mut self.waits, s, w);
                    }
                    if now.idle {
                        if !g.reads(&s) {
                            unread.insert(s);
                        }
                        self.judged.unwant(&k);
                        g.unfollow_facts(&s, &c);
                        self.verdicts.remove(&k);
                        self.arrived.remove(&k);
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
            if judged.is_empty() {
                break;
            }
            // what is logged together goes in its commits' `ts` order, so the own ones in the order
            // they were made (spec/sync-judgement.md §3 Own store: a removal before what was
            // written after it, spec/permissions.md §3)
            let mut judged: Vec<_> = judged.into_iter().collect();
            judged.sort_by_cached_key(|((s, c), _)| (g.ts(&c.commit), *s, *c));
            let moved: Vec<(SyncId, BodyId)> = judged.iter().map(|(k, _)| *k).take(4).collect();
            keys.extend(judged.iter().map(|(k, _)| *k));
            for ((s, c), (was, now)) in judged {
                acted = true;
                self.react(g, &s, c, &was.map(|w| w.acts).unwrap_or_default(), &now.acts)?;
            }
            let n = keys.len() as u64;
            guard.round(moved, || (2 * n + 1, format!("{n} judgements moved")));
        }
        // what the pieces newly call for, and no longer; a lost one is repaired in the own bodies
        // over it, each body's in one commit
        let (acts, gone, repairs) = self.pieces.acts();
        for ((s, _), a) in gone {
            self.owed.remove(&(s, None, a));
        }
        for ((s, _), a) in acts {
            acted = true;
            self.act(g, &s, None, a)?;
        }
        for (c, b) in repairs {
            acted = true;
            g.repair(&c, &b)?;
        }
        // what each body calls for at each source keeping S unread: the rows a source's stream
        // wrote, and a source joining or moving (`giving_to`: a non-writer there gives every
        // must-hold body, a writer its role commits)
        for (s, at) in g.sources_added() {
            let (all, roles) = (self.giving_to(g, &s, false)?.contains(&at), self.giving_to(g, &s, true)?.contains(&at));
            if roles {
                let held = self.held_roles.get(&s).cloned().unwrap_or_default();
                let must: Vec<BodyId> = self.verdicts.range((s, BodyId::unit(CommitId([0; 32])))..).take_while(|(k, _)| k.0 == s).filter(|(c, v)| **v == Verdict::Must && (all || held.contains(&c.1))).map(|((_, c), _)| *c).collect();
                for c in must {
                    self.toward.want((s, c, at));
                }
            }
        }
        let mut toward: Moved<(SyncId, BodyId, Source), Toward> = BTreeMap::new();
        loop {
            let due = self.toward.due();
            if due.is_empty() {
                break;
            }
            for k in due {
                let (s, c, at) = k;
                let mine = Mine { verdicts: &self.verdicts, roles: &self.roles, held_roles: &self.held_roles, clock: &self.clock, metas: &self.metas, mints: &self.mints, arrived: &self.arrived, moved: &self.moved };
                let Some((was, now)) = self.toward.try_settle(&k, || judge::toward(g, &mine, &s, &c, &at))? else { continue };
                if now.idle {
                    self.toward.unwant(&k);
                }
                note(&mut toward, k, was, now);
            }
        }
        for ((s, c, _), (was, now)) in toward {
            acted = true;
            self.react(g, &s, c, &was.map(|w| w.acts).unwrap_or_default(), &now.acts)?;
        }
        // freed links: dropped here and deleted at the sources keeping S unread that show them,
        // until no entry of them is known
        for k in g.freed_added() {
            self.freed.want(k);
        }
        for k in self.freed.due() {
            let Some((was, (acts, known))) = self.freed.try_settle(&k, || judge::freed(g, &k.0, &k.1))? else { continue };
            acted = true;
            let before = was.map(|w| w.0).unwrap_or_default();
            for (s, a) in before.difference(&acts) {
                self.owed.remove(&(*s, None, a.clone()));
            }
            for (s, a) in acts.difference(&before).cloned().collect::<Vec<_>>() {
                self.act(g, &s, None, a)?;
            }
            if !known {
                self.freed.unwant(&k);
                g.freed_done(&k.0, &k.1)?;
            }
        }
        // covered parts dropped; commits forgotten once no entry of them is known here, in one
        // engine transaction; a commit no longer held leaves read
        let mut forget = Vec::new();
        for c in self.local.due() {
            let at: Vec<(SyncId, Option<Tid>)> = self.settled.get(&c).map(|m| m.keys().copied().collect()).unwrap_or_default();
            let Some((_, now)) = self.local.try_settle(&c, || judge::local(g, &c, &at))? else { continue };
            match now {
                judge::Local::Gone => {
                    self.local.unwant(&c);
                    g.unfollow_fate(&c);
                    self.bodies.unwant(&c);
                    self.moved.remove(&c);
                    for (s, on) in self.settled.remove(&c).into_iter().flat_map(|m| m.keys().copied().collect::<Vec<_>>()) {
                        self.metas.remove(&(s, BodyId { commit: c, on }));
                    }
                }
                judge::Local::Drop(parts) => {
                    for (t, ak) in parts.iter() {
                        g.drop_body(&c, t, ak)?;
                    }
                    acted = true;
                }
                judge::Local::Forget => forget.push(c),
                judge::Local::Kept => {}
            }
        }
        if !forget.is_empty() {
            g.forget_commits(&forget)?;
            acted = true;
        }
        for s in unread {
            self.owed.forget(&s);
        }
        // what is owed each source goes on its record's connection: a new act, or a take,
        // agreement or `full` moving where it goes
        for at in self.owed.due() {
            acted |= self.deliver(g, at)?;
        }
        Ok(acted)
    }

    /// Body `c`'s acts at S moved from `before` to `now`: those toward a source no longer
    /// called for are owed no more, the new ones carried out.
    fn react(&mut self, g: &mut impl Ground, s: &SyncId, c: BodyId, before: &BTreeSet<Act>, now: &BTreeSet<Act>) -> Result<()> {
        for a in before.difference(now).filter(|a| a.toward().is_some()) {
            self.owed.remove(&(*s, Some(c), a.clone()));
        }
        for a in now.difference(before) {
            self.act(g, s, Some(&c), a.clone())?;
        }
        Ok(())
    }

    /// Carries out what is owed `at` and not done on the connection its record is on now, once
    /// its digests agreed; one owed only while full only where the source told so there.
    fn deliver(&mut self, g: &mut impl Ground, at: Source) -> Result<bool> {
        if !self.owed.by.contains_key(&at) {
            return Ok(false);
        }
        let fulls = self.owed.full_wanted(&at);
        let mut on: owed::On = (None, Arc::default());
        self.owed.on.try_settle(&at, || {
            let conn = g.connected(&at);
            let full = conn.map(|c| fulls.iter().copied().filter(|s| g.told_full(c, s)).collect()).unwrap_or_default();
            on = (conn, Arc::new(full));
            Ok::<_, crate::types::Error>(on.clone())
        })?;
        let (Some(conn), full) = on else { return Ok(false) };
        let todo: Vec<owed::Key> = self.owed.by.get(&at).into_iter().flatten().filter(|(k, st)| !matches!(st, owed::State::Done) && **st != owed::State::Sent(conn) && (!k.2.needs_full() || full.contains(&k.0))).map(|(k, _)| k.clone()).collect();
        let mut acted = false;
        for k in todo {
            osis_base::costs::count("read: acts", 1);
            let st = self.carry(g, conn, at, &k)?;
            if let Some(x) = self.owed.by.get_mut(&at).and_then(|m| m.get_mut(&k)) {
                *x = st;
            }
            acted = true;
        }
        Ok(acted)
    }

    /// Act `k` owed `at`, carried out on `conn`: where it stands after.
    fn carry(&mut self, g: &mut impl Ground, conn: ConnId, at: Source, k: &owed::Key) -> Result<owed::State> {
        let (s, c, a) = k;
        // a Delete it cannot sign now goes nowhere: tried again on the next connection, as one refused
        let sent = |id: Option<crate::session::RequestId>, owed: &mut owed::Owed| {
            if let Some(id) = id {
                owed.sent(conn, id, at, k.clone());
            }
            owed::State::Sent(conn)
        };
        Ok(match (a, c) {
            (Act::Fetch { blob, .. }, _) => {
                g.fetch(conn, s, blob)?;
                owed::State::Sent(conn)
            }
            (Act::Want { .. }, Some(c)) => {
                g.want(conn, s, &c.commit)?;
                owed::State::Sent(conn)
            }
            (Act::Delete { head, blob, .. }, _) => {
                let id = g.delete(conn, s, head, blob)?;
                sent(id, &mut self.owed)
            }
            (Act::DeleteFreed { head, blob, thing, .. }, _) => {
                let id = g.delete_freed(conn, s, head, blob, thing)?;
                sent(id, &mut self.owed)
            }
            // offered on this connection (inbox's offers), again on the next while owed
            (Act::Deposit { head, blob, .. }, Some(c)) => match g.deposit(conn, s, c, head, blob)? {
                true => owed::State::Sent(conn),
                false => owed::State::Done,
            },
            (Act::Again { head, fall, old, .. }, Some(c)) => {
                // a fresh encryption under this sync ID alone; its stand first, durably
                if let Some(logged) = g.log_own(s, c, true, &[])? {
                    g.set_stand(&at, s, c, &Stand { at: g.now(), logged, head: *head, fall: *fall })?;
                    for b in old {
                        g.drop_own(s, b, c)?;
                    }
                }
                owed::State::Done
            }
            _ => owed::State::Done,
        })
    }

    /// The store sources of S this node gives a must-hold body (a role commit: `role`) it lacks
    /// (`judge::toward`): where this node is no writer at their head, every one; where it is, a
    /// role commit alone (its entry may be pinned under a step's parent, `Ground::stands`;
    /// anything else stands under the head, and the source pulls it).
    fn giving_to(&self, g: &mut impl Ground, s: &SyncId, role: bool) -> Result<Vec<Source>> {
        let creds = g.credentials(s)?;
        let writer = |h: &osis_blob::StepId| creds.as_ref().and_then(|c| c.keys.get(h)).is_some_and(|k| k.write.is_some());
        Ok(g.sources(s).iter().filter(|x| x.store && (role || !x.head.is_some_and(|h| writer(&h)))).map(|x| x.at).collect())
    }

    /// Answers to its own requests: a Delete taken (its one item answered 0) is done; refused,
    /// whatever the code, it goes again on the source's next connection (the codes reach `known`
    /// through the source's stream, so nothing else is taken from them here).
    pub fn on_message(&mut self, conn: ConnId, m: Incoming) {
        if let Incoming::Reply(_, id, reply) = m {
            let taken = matches!(&reply, osis_proto::Msg::Status { codes, .. } if !codes.is_empty() && codes.iter().all(|c| c.0 == 0));
            self.answered(conn, id, taken);
        }
    }

    /// The answer to read's request `id` on `conn` came, taken or refused (`on_message`).
    pub fn answered(&mut self, conn: ConnId, id: crate::session::RequestId, taken: bool) {
        self.owed.answered(conn, id, taken);
    }

    /// Per S, the pass place a complete pass must begin after for a judgement outside S's
    /// required set to be final (`judge::outside`): status runs it. A stamped read, whole.
    pub fn passes_wanted(&self) -> BTreeMap<SyncId, u64> {
        self.waits.iter().map(|(s, w)| (*s, *w)).collect()
    }

    /// The verdict of commit `c`'s sync unit body under `s`: for status and inbox (stamped read).
    pub fn verdict(&self, s: &SyncId, c: &CommitId) -> Option<Verdict> {
        self.body_verdict(s, &BodyId::unit(*c))
    }

    /// The verdict of body `c` under `s`: a commit's sync unit body or one of its certificate
    /// copies (stamped read).
    pub fn body_verdict(&self, s: &SyncId, c: &BodyId) -> Option<Verdict> {
        self.verdicts.get(&(*s, *c)).cloned()
    }

    /// Tests: the bodies judged must-hold, by S (unstamped).
    #[doc(hidden)]
    pub fn must_bodies(&self) -> Vec<(SyncId, BodyId)> {
        self.verdicts.iter().filter(|(_, v)| **v == Verdict::Must).map(|(k, _)| *k).collect()
    }

    /// Tests: the pieces followed, acting or dormant (spec/sync-judgement.md §1).
    #[doc(hidden)]
    pub fn pieces_followed(&self) -> usize {
        self.pieces.followed()
    }

    /// Tests: the minting copies ranked, one per (S, minting, thing) in S's required set as a
    /// minting copy (spec/commits.md §5 A thing's mintings travel with its record).
    #[doc(hidden)]
    pub fn mintings_ranked(&self) -> usize {
        self.mints.len()
    }

    /// Tests: whether thing `t`'s minting copies under `s` are followed.
    #[doc(hidden)]
    pub fn ranks_thing(&self, s: &SyncId, t: &Tid) -> bool {
        self.mintings.wants(&(*s, *t))
    }

    /// When a judgement read up to a time (an expiry) moves next.
    pub fn next_wake(&self) -> Option<WallMs> {
        self.clock.next().map(WallMs)
    }


    /// Act `a` of a judgement under S: on the own store or the engine at once; toward a source,
    /// owed it (`deliver`).
    fn act(&mut self, g: &mut impl Ground, s: &SyncId, c: Option<&BodyId>, a: Act) -> Result<()> {
        if a.toward().is_some() {
            self.owed.add((*s, c.copied(), a));
            return Ok(());
        }
        osis_base::costs::count("read: acts", 1);
        match (a, c) {
            (Act::Log, Some(c)) => {
                g.log_own(s, c, false, &[])?;
            }
            (Act::Rewrite(old), Some(c)) => {
                g.log_own(s, c, false, &old)?;
                for b in old {
                    g.drop_own(s, &b, c)?;
                }
            }
            (Act::Restamp(b), _) => g.restamp(s, &b)?,
            (Act::DropOwn(b), Some(c)) => g.drop_own(s, &b, c)?,
            (Act::Unlog(b), _) => g.unlog(s, &b)?,
            (Act::Lift(b), _) => g.lift(s, &b)?,
            (Act::Take(b), _) => g.take(s, &b)?,
            (Act::LogPiece(b), _) => g.log_piece(s, &b)?,
            (Act::TakePiece(b), _) => g.take_piece(s, &b)?,
            (Act::Repair(_), _) => {}
            (Act::DropBlob(b), _) => g.drop_blob(s, &b)?,
            (Act::Fetch { .. } | Act::Want { .. } | Act::Delete { .. } | Act::Deposit { .. } | Act::Again { .. } | Act::DeleteFreed { .. }, _) | (_, None) => {}
        }
        Ok(())
    }
}

/// Body `c` in or out of `set`'s bodies of S.
fn set_in(set: &mut Stamped<SyncId, BTreeSet<BodyId>>, s: &SyncId, c: &BodyId, on: bool) {
    let has = set.get(s).is_some_and(|r| r.contains(c));
    if has == on {
        return;
    }
    let mut r = set.get(s).cloned().unwrap_or_default();
    if on {
        r.insert(*c);
    } else {
        r.remove(c);
    }
    if r.is_empty() {
        set.remove(s);
    } else {
        set.insert(*s, r);
    }
}

/// S's judgements outside its required set wait for a complete pass begun after place `w`: the
/// newest such place is kept (`passes_wanted`).
fn wait_pass(waits: &mut Stamped<SyncId, u64>, s: SyncId, w: u64) {
    if waits.get(&s).is_none_or(|x| *x < w) {
        waits.insert(s, w);
    }
}

/// `Ground::sync_copies_due` while a reader can pull S, else nothing, its missing ones waiting
/// as `cert_blobs_missing`'s do (a source's blob, pulled, may carry them).
fn sync_copies_due(g: &mut impl Ground, s: &SyncId, since: u64) -> Result<SyncCopiesDue> {
    let mut x = g.sync_copies_due(s)?;
    if !x.missing.is_empty() && !g.first_synced(s)? && !g.passed(s, since) {
        x.missing.clear();
        x.wait = Some(since);
    }
    if x == SyncCopiesDue::default() || g.pullable(s)? {
        return Ok(x);
    }
    Ok(SyncCopiesDue::default())
}

/// `Ground::cert_blobs_missing` while a reader can pull S, else nothing (`pullable` read inside,
/// so S is due again once it can; read only where there is something to do, so a source flip
/// moves no key with nothing to do).
fn cert_blobs_missing(g: &mut impl Ground, s: &SyncId, since: u64) -> Result<CertBlobsMissing> {
    let mut x = g.cert_blobs_missing(s)?;
    // logged here only once S's first sync here ended, or a complete pass of S begun after S's
    // certificate blobs were first followed did (none connected to sync it from: at once): a
    // source's blob, pulled, carries them (spec/sync-judgement.md §3 Own store)
    if !x.missing.is_empty() && !g.first_synced(s)? && !g.passed(s, since) {
        x.missing.clear();
        x.wait = Some(since);
    }
    if x == CertBlobsMissing::default() || g.pullable(s)? {
        return Ok(x);
    }
    Ok(CertBlobsMissing::default())
}
