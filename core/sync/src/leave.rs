//! Leaving the sync set and releasing what left the node closure (spec/sync-set.md §3), and the
//! sync IDs this node syncs.
//!
//! `leave` alone follows the engine's sync set (per sync ID, `Engine::sync_held`) and writes what
//! this node syncs into the store (`Store::set_holdings`): the sync set, and each sync ID that
//! left it while it waits to stop. Every other module follows that (crate::set), so a waiting
//! sync ID stays open, served, logged into, judged and counted as before until it stops.
//!
//! The rule, read or kept unread alike, whatever made S leave: S that left waits for a complete
//! pass of it begun after it left, unless it has no source (no absent peer is waited for; what
//! made it leave may be undone by what that pass brings, such as a rotation's thing list arriving
//! after the rotation), then judges again: the node's keys must still let it hold S as it did
//! (`Engine::sync_holder`), else it stops at once (its secrets lost, a removal), unless a role
//! commit on its thing waits for its lists (`Ground::uncounted_role`): then once more, for a pass
//! with a source. Then it stops: its thing is released (if read and still out of the node
//! closure) and its store shredded. Synced again before then, it is kept as it was.
//!
//! A thing that left the node closure (`Engine::left_closure`) is released the same way: once
//! each sync ID that carried it when it left has had a complete pass begun after, or has no
//! source; one that left the local part, at once. Its unsynced writes go with it.
//!
//! One derived value (`out`): the sync IDs out of the sync set that this node syncs or holds rows
//! of, one `Effects` key each. The first settle wants every one stored (a start, or a restart of
//! the modules: the store is the truth), later ones each S the sync set loses. S has left only
//! with an entry (as synced, else as its keys hold it) and once this node has joined an account
//! (`Engine::sync_rooted`); rows of another account's inbox it deposits to never leave. Nothing
//! here is durable.

use crate::set::Held;
use crate::types::{Holding, Result};
use osis_base::memo::{Effects, Feed, Stamped};
use osis_base::{SyncId, Tid};
use std::collections::{BTreeMap, BTreeSet};

/// What leave reads and does (the product's is `Live`; a test's a table).
pub trait Ground {
    /// The sync IDs that entered the engine's sync set since `f`'s last read (its first: every
    /// one; `Engine::sync_held_added`; a superset is fine).
    fn held_added(&mut self, f: &mut Option<Feed<SyncId>>) -> Result<Vec<SyncId>>;
    /// S's entry of the engine's sync set (`Engine::sync_held`), read per sync ID.
    fn sync_held(&mut self, s: &SyncId) -> Result<Option<Held>>;
    /// Whether the node closure holds `t` (`Engine::in_sync_things`), read per thing.
    fn in_sync_things(&mut self, t: &Tid) -> Result<bool>;
    /// S's entry in the sync IDs this node syncs (`Store::synced`).
    fn synced(&mut self, s: &SyncId) -> Option<Held>;
    /// Sets it (`Store::set_holdings`; `None`: not synced).
    fn set_synced(&mut self, s: &SyncId, now: Option<Held>) -> Result<()>;
    /// The sync IDs whose store holds rows (`Store::held_ids`) or that are listed synced.
    fn stored(&mut self) -> Result<BTreeSet<SyncId>>;
    /// S's thing and how this node's keys let it hold S, whatever lists it (`Engine::sync_holder`).
    fn holder(&mut self, s: &SyncId) -> Result<Option<Held>>;
    /// Whether S has a source now (`Status::sourced`): a pass with none ends at once.
    fn sourced(&mut self, s: &SyncId) -> bool;
    /// Shreds S's rows (`Store::shred`), the engine's notes of S's copies first (`Engine::shredding`).
    fn shred(&mut self, s: &SyncId) -> Result<()>;
    /// Whether a role commit on `t` is held but uncounted, its epoch revoked and no list naming
    /// it held (`Engine::uncounted_role_on`).
    fn uncounted_role(&mut self, t: &Tid) -> bool;
    /// The pass place now (`Engine::pass_place`): when S left, in the order passes begin.
    fn pass_seq(&mut self) -> u64;
    /// A complete pass of S begun after pass place `since` ended (status's, spec/sync-status.md §1).
    fn passed(&mut self, s: &SyncId, since: u64) -> bool;
    /// This node has joined an account (`Engine::sync_rooted`): before, its sync set is empty for
    /// want of an account root, and nothing it holds counts as left.
    fn rooted(&mut self) -> bool;
    /// The things that left the node closure and are not released yet, each with the sync units
    /// that held it when it left (`Engine::left_closure`), a stamped read.
    fn left(&mut self) -> Result<BTreeMap<Tid, BTreeSet<Tid>>>;
    /// The sync IDs this node syncs for sync unit `u` (`Engine::thing_sync`, read or unread).
    fn unit_ids(&mut self, u: &Tid) -> Result<Vec<SyncId>>;
    /// Releases `ts` (`Engine::released`: those still outside the node closure), then unlogs this
    /// node's own entries of the commits that went whole, under every sync ID naming their
    /// blobs: no judgement reaches a commit no longer held. O(the blobs of what went).
    fn release(&mut self, ts: &BTreeSet<Tid>) -> Result<()>;
}

/// A leaving S: its entry when it left, and the complete pass it waits for.
#[derive(Clone, Debug, PartialEq)]
struct Left {
    held: Held,
    /// The pass place a complete pass of S must begin after.
    since: u64,
    /// The pass must have a source (`pass_sourced`): S lost its holder while a role commit on
    /// its thing waits for its lists, so `since` is the place that was seen at.
    sourced: bool,
}

/// A sync ID out of the sync set: its judgement.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum Wait {
    /// Nothing left: S is not this node's to leave (rows of another account's inbox it deposits
    /// to, no entry and no holder), or this node has joined no account yet (pairing: its
    /// sync set is empty for want of one, not because anything left).
    #[default]
    Not,
    /// It left and waits for a complete pass begun after it left.
    Waiting,
    /// A complete pass of S since it left, or none with no source: it stops.
    Done,
    /// After that pass, this node's keys no longer hold S as they did: it stops at once.
    Lost,
}

#[derive(Clone)]
pub struct Leave {
    /// Per sync ID of the engine's sync set, its entry; one that leaves is followed no more.
    set: Effects<SyncId, Option<Held>>,
    set_feed: Option<Feed<SyncId>>,
    /// The first settle is done: it wants every sync ID the store holds rows of or syncs, as a
    /// feed's first read lists everything; later ones, each sync ID that leaves the sync set.
    started: bool,
    /// Per sync ID out of the sync set that this node syncs or holds rows of, its judgement.
    out: Effects<SyncId, Wait>,
    /// Per leaving S, its entry when it left and the pass place it waits for a complete pass
    /// begun after (`Engine::pass_place`): status runs it (`passes_wanted`), which the wait
    /// reads. Stamped: status follows it whole.
    leaving: Stamped<SyncId, Left>,
    /// Per thing that left the node closure and waits to be released: the pass place it left
    /// at and the sync IDs that carried it then, each waiting for a complete pass begun after
    /// (status runs it, `passes_wanted`). Stamped: status follows it whole.
    releasing: Stamped<Tid, (u64, Vec<SyncId>)>,
    /// Judgements of a sync ID out of the sync set made (tests: what a change costs).
    judged: u64,
}

impl Default for Leave {
    fn default() -> Leave {
        Leave { set: Effects::new("leave: sync set"), set_feed: None, started: false, out: Effects::new("leave: out of the sync set"), leaving: Stamped::default(), releasing: Stamped::default(), judged: 0 }
    }
}

impl std::fmt::Debug for Leave {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Leave").field("leaving", &self.leaving.iter().collect::<Vec<_>>()).finish_non_exhaustive()
    }
}

impl Leave {
    /// Follows the sync set into what this node syncs, and stops each sync ID that left it once
    /// a complete pass after it left ended, or at once with no source (spec/sync-set.md §3).
    /// Whether it acted.
    pub fn settle(&mut self, g: &mut impl Ground) -> Result<bool> {
        let mut acted = false;
        for s in g.held_added(&mut self.set_feed)? {
            self.set.want(s);
        }
        for s in self.set.due() {
            let Some((was, now)) = self.set.try_settle(&s, || g.sync_held(&s))? else { continue };
            match now {
                Some(h) => {
                    // synced again before it stopped: kept as it was
                    self.out.unwant(&s);
                    self.leaving.remove(&s);
                    if g.synced(&s).as_ref() != Some(&h) {
                        g.set_synced(&s, Some(h))?;
                        acted = true;
                    }
                }
                None => {
                    self.set.unwant(&s);
                    // only what was in the sync set left it: the feed also lists one that
                    // entered and left between two settles
                    if was.is_some() {
                        self.out.want(s);
                    }
                }
            }
        }
        if !self.started {
            // what this node held before its start (or a restart of the modules) and its sync set
            // does not: left while it was down, or waiting still
            for s in g.stored()? {
                if !self.set.wants(&s) {
                    self.out.want(s);
                }
            }
            self.started = true;
        }
        // the sync IDs that stop in this settle, and the things whose local copies go with them
        let mut stopped = Vec::new();
        let mut forget = BTreeSet::new();
        for s in self.out.due() {
            self.judged += 1;
            let leaving = &mut self.leaving;
            let Some((_, now)) = self.out.try_settle(&s, || judge(g, &s, leaving))? else { continue };
            let Some(Left { held: (things, h), .. }) = self.leaving.get(&s).cloned() else { continue };
            match now {
                Wait::Not => {}
                Wait::Waiting => {
                    // held before the start, not synced yet: synced while it waits
                    if g.synced(&s).is_none() {
                        g.set_synced(&s, Some((things, h)))?;
                        acted = true;
                    }
                }
                Wait::Done | Wait::Lost => {
                    if now == Wait::Done && h == Holding::Read {
                        forget.extend(things);
                    }
                    stopped.push(s);
                }
            }
        }
        // each thing that left the node closure, released once the pass in flight with its
        // connected sources of each sync ID that carried it ended (spec/sync-set.md §3)
        let left = g.left()?;
        for t in self.releasing.keys().copied().collect::<Vec<_>>() {
            if !left.contains_key(&t) {
                self.releasing.remove(&t);
            }
        }
        for (t, units) in left {
            let (since, ids) = match self.releasing.get(&t) {
                Some(x) => x.clone(),
                None => {
                    let mut ids = Vec::new();
                    for u in &units {
                        ids.extend(g.unit_ids(u)?);
                    }
                    let x = (g.pass_seq(), ids);
                    self.releasing.insert(t, x.clone());
                    x
                }
            };
            if ids.iter().all(|s| !g.sourced(s) || g.passed(s, since)) {
                forget.insert(t);
            }
        }
        // one release for every thing that goes, before the shreds, so a crash between finds the
        // rows at the next start and does both again
        if !forget.is_empty() {
            g.release(&forget)?;
            for t in &forget {
                self.releasing.remove(t);
            }
            acted = true;
        }
        for s in stopped {
            g.shred(&s)?;
            g.set_synced(&s, None)?;
            self.leaving.remove(&s);
            self.out.unwant(&s);
            acted = true;
        }
        Ok(acted)
    }

    /// Whether S left the sync set and waits to stop.
    pub fn waits(&self, s: &SyncId) -> bool {
        self.leaving.contains_key(s)
    }

    /// Per leaving S, the pass place it left at: a complete pass begun after is wanted (status
    /// runs it). A stamped read, whole.
    pub fn passes_wanted(&self) -> BTreeMap<SyncId, u64> {
        let mut out: BTreeMap<SyncId, u64> = self.leaving.iter().map(|(s, l)| (*s, l.since)).collect();
        for (since, ids) in self.releasing.values() {
            for s in ids {
                let e = out.entry(*s).or_insert(*since);
                *e = (*e).max(*since);
            }
        }
        out
    }

    /// Whether S's wanted pass must have a source: no pass of S ends with none meanwhile
    /// (spec/sync-set.md §3: lacking a list is waiting). A stamped read of S.
    pub fn pass_sourced(&self, s: &SyncId) -> bool {
        self.leaving.get(s).is_some_and(|l| l.sourced)
    }

    /// Tests only: the judgements of a sync ID out of the sync set made so far.
    #[doc(hidden)]
    pub fn judged(&self) -> u64 {
        self.judged
    }
}

/// S, out of the sync set: whether it left (its entry: as synced, else as this node's keys hold
/// it; neither, or no account joined yet: not), noting when it first did; then a complete
/// pass since it left, then its own keys.
fn judge(g: &mut impl Ground, s: &SyncId, leaving: &mut Stamped<SyncId, Left>) -> Result<Wait> {
    let holder = g.holder(s)?;
    let left = match leaving.get(s) {
        Some(x) => x.clone(),
        None => {
            let Some(held) = g.synced(s).or_else(|| holder.clone()) else { return Ok(Wait::Not) };
            if !g.rooted() {
                return Ok(Wait::Not);
            }
            let x = Left { held, since: g.pass_seq(), sourced: false };
            leaving.insert(*s, x.clone());
            x
        }
    };
    let things = &left.held.0;
    let mut in_set = false;
    for t in things {
        in_set |= g.in_sync_things(t)?;
    }
    // lists give S back only while one of its things is in the closure: leaving it (a release,
    // this node's removal) ends the pass with a source unwaited
    let moot = left.sourced && !in_set;
    // a pass with no source ends at once: no absent peer is waited for
    if !moot && g.sourced(s) && !g.passed(s, left.since) {
        return Ok(Wait::Waiting);
    }
    if holder.as_ref() != Some(&left.held) {
        // a role commit on one of S's things uncounted for want of its lists (a revocation taken
        // before them): one complete pass with a source, begun now, fetches them before S is
        // judged lost
        let mut uncounted = false;
        for t in things {
            uncounted |= g.uncounted_role(t) && g.in_sync_things(t)?;
        }
        if !left.sourced && uncounted {
            leaving.insert(*s, Left { since: g.pass_seq(), sourced: true, ..left });
            return Ok(Wait::Waiting);
        }
        return Ok(Wait::Lost);
    }
    Ok(Wait::Done)
}

/// The product's ground: the engine's facade, the store and status.
pub struct Live<'a, 'b> {
    pub cx: &'a mut crate::types::Cx<'b>,
    pub status: &'a crate::status::Status,
}

impl Ground for Live<'_, '_> {
    fn held_added(&mut self, f: &mut Option<Feed<SyncId>>) -> Result<Vec<SyncId>> {
        Ok(self.cx.engine.sync_held_added(f)?)
    }
    fn sync_held(&mut self, s: &SyncId) -> Result<Option<Held>> {
        Ok(self.cx.engine.sync_held(s)?)
    }
    fn in_sync_things(&mut self, t: &Tid) -> Result<bool> {
        Ok(self.cx.engine.in_sync_things(t)?)
    }
    fn synced(&mut self, s: &SyncId) -> Option<Held> {
        self.cx.store.synced(s)
    }
    fn set_synced(&mut self, s: &SyncId, now: Option<Held>) -> Result<()> {
        self.cx.store.set_holdings(&[(*s, now)])
    }
    fn stored(&mut self) -> Result<BTreeSet<SyncId>> {
        let mut ids = self.cx.store.held_ids()?;
        ids.extend(self.cx.store.syncs().into_keys());
        Ok(ids)
    }
    fn holder(&mut self, s: &SyncId) -> Result<Option<Held>> {
        Ok(self.cx.engine.sync_holder(s)?)
    }
    fn sourced(&mut self, s: &SyncId) -> bool {
        self.status.sourced(s)
    }
    fn shred(&mut self, s: &SyncId) -> Result<()> {
        let alone = self.cx.store.alone_under(s)?;
        self.cx.engine.shredding(&alone)?;
        self.cx.store.shred(s)
    }
    fn uncounted_role(&mut self, t: &Tid) -> bool {
        self.cx.engine.uncounted_role_on(t)
    }
    fn pass_seq(&mut self) -> u64 {
        self.cx.engine.pass_place()
    }
    fn rooted(&mut self) -> bool {
        self.cx.engine.sync_rooted()
    }
    fn passed(&mut self, s: &SyncId, since: u64) -> bool {
        self.status.passed_since(s, since)
    }
    fn left(&mut self) -> Result<BTreeMap<Tid, BTreeSet<Tid>>> {
        Ok(self.cx.engine.left_closure())
    }
    fn unit_ids(&mut self, u: &Tid) -> Result<Vec<SyncId>> {
        Ok(match self.cx.engine.thing_sync(u)? {
            osis_engine::sync::ThingSync::Read(v) | osis_engine::sync::ThingSync::Unread(v) => v,
            _ => Vec::new(),
        })
    }
    fn release(&mut self, ts: &BTreeSet<Tid>) -> Result<()> {
        release(self.cx.engine, ts)
    }
}

/// `Ground::release` (`Engine::released`: the store's own entries of what it forgets go with it).
pub(crate) fn release(engine: &mut osis_engine::Engine, ts: &BTreeSet<Tid>) -> Result<()> {
    Ok(engine.released(ts)?)
}

/// Each of this node's own commits with an entry under read S is held elsewhere: one of its
/// entries there recorded so (`Store::elsewhere`, status's durable mark, spec/sync-status.md §2).
/// Stamped reads.
pub(crate) fn own_elsewhere(engine: &mut osis_engine::Engine, store: &crate::store::Store, s: &SyncId) -> Result<bool> {
    for c in engine.own_commits(s)?.iter() {
        let mut entries = 0;
        let mut held = false;
        for b in engine.commit_blobs(c)?.iter() {
            if store.entry(s, b)?.is_some() {
                entries += 1;
                held |= store.elsewhere(s, b)?;
            }
        }
        if entries > 0 && !held {
            return Ok(false);
        }
    }
    Ok(true)
}
