//! Leaving the sync set (spec/sync-set.md §3), and the sync IDs this node syncs.
//!
//! `leave` alone follows the engine's sync set (per sync ID, `Engine::sync_held`) and writes what this node syncs into
//! the store (`Store::set_holdings`): the sync set, and each sync ID that left it while it waits
//! to stop. Every other module follows that (crate::set), so a waiting sync ID stays open,
//! served, logged into, judged and counted as before until it stops (§3: it stays a member of its
//! shared sets as before).
//!
//! The rule, read or kept unread alike, whatever made S leave: S that left waits first for a
//! complete pass of it begun after it left (spec/sync-set.md §3: what made it leave may be undone
//! by what that pass brings, such as a rotation's thing list arriving after the rotation), then
//! judges again: the node's keys must still let it hold S as it did (`Engine::sync_holder`), else
//! it stops at once (its secrets lost, a removal), unless a role commit on its thing waits for
//! its lists (`Ground::uncounted_role`): then once more, for a pass with a source; then it waits until what this node logged
//! itself under S is elsewhere (read: each own commit with an entry under S held elsewhere,
//! status's durable mark, `Store::elsewhere`; kept unread: each own entry present at a source,
//! `Sources`), or no peer is to be waited for on S (`Opens::waited`: none has S open or in its
//! kept record, none the rosters name has a record not acknowledging S), then stops: read and still read
//! here (unsyncing), its thing's local copy is forgotten first. Synced again before then, it is
//! kept as it was. Meanwhile the engine answers for it by its thing's held read secrets
//! (`Engine::read_credentials`, `open_entry`).
//!
//! One derived value (`out`): the sync IDs out of the sync set that this node syncs or holds rows
//! of, one `Effects` key each. The first settle wants every one stored (a start, or a restart of
//! the modules: the store is the truth), later ones each S the sync set loses. S has left only
//! with an entry (as synced, else as its keys hold it) and once this node knows its synced group
//! (`Engine::sync_rooted`); rows of another account's inbox it deposits to never leave. Work
//! follows change: the sync set per key; each leaving S judged over its own commits or entries
//! (O(own writes under S)). Nothing here is durable.

use crate::set::Held;
use crate::types::{Holding, Result};
use osis_base::memo::{Effects, Feed, Stamped};
use osis_base::{BlobId, SyncId, Tid};
use std::collections::{BTreeMap, BTreeSet};

/// Whether a source of S showed `b` present by its stream (spec/sync-set.md §3: what a node
/// keeping S unread waits for before leaving). Stamped reads, so a waiting S is judged again when
/// presence moves.
pub trait Sources {
    fn present(&self, s: &SyncId, b: &BlobId) -> bool;
}

/// What leave reads and does (the product's is `Live`; a test's a table).
pub trait Ground {
    /// The sync IDs that entered the engine's sync set since `f`'s last read (its first: every
    /// one; `Engine::sync_held_added`; a superset is fine).
    fn held_added(&mut self, f: &mut Option<Feed<SyncId>>) -> Result<Vec<SyncId>>;
    /// S's entry of the engine's sync set (`Engine::sync_held`), read per sync ID.
    fn sync_held(&mut self, s: &SyncId) -> Result<Option<Held>>;
    /// Whether the synced group's closure holds `t` (`Engine::in_sync_things`), read per thing.
    fn in_sync_things(&mut self, t: &Tid) -> Result<bool>;
    /// S's entry in the sync IDs this node syncs (`Store::synced`).
    fn synced(&mut self, s: &SyncId) -> Option<Held>;
    /// Sets it (`Store::set_holdings`; `None`: not synced).
    fn set_synced(&mut self, s: &SyncId, now: Option<Held>) -> Result<()>;
    /// The sync IDs whose store holds rows (`Store::held_ids`) or that are listed synced.
    fn stored(&mut self) -> Result<BTreeSet<SyncId>>;
    /// S's thing and how this node's keys let it hold S, whatever lists it (`Engine::sync_holder`).
    fn holder(&mut self, s: &SyncId) -> Result<Option<Held>>;
    /// Read: each of this node's own commits with an entry under S is held elsewhere: one of its
    /// entries there recorded so (`Store::elsewhere`, status's durable mark, spec/sync-status.md §2).
    fn own_elsewhere(&mut self, s: &SyncId) -> Result<bool>;
    /// Kept unread: each entry this node logged itself under S is present at a source.
    fn own_present(&mut self, s: &SyncId) -> Result<bool>;
    /// Some peer is to be waited for on S (`Opens::waited`): S open there or in its kept record,
    /// or the rosters say it may hold S and its record has not acknowledged S. With none,
    /// nothing could take its own writes.
    fn waited(&mut self, s: &SyncId) -> Result<bool>;
    fn shred(&mut self, s: &SyncId) -> Result<()>;
    /// Whether a role commit on `t` is held but uncounted, its epoch revoked and no list naming
    /// it held (`Engine::uncounted_role_on`).
    fn uncounted_role(&mut self, t: &Tid) -> bool;
    /// The pass place now (`Engine::pass_place`): when S left, in the order passes begin.
    fn pass_seq(&mut self) -> u64;
    /// A complete pass of S begun after pass place `since` ended (status's, spec/sync-status.md §1).
    fn passed(&mut self, s: &SyncId, since: u64) -> bool;
    /// This node knows the group whose closure it syncs (`Engine::sync_rooted`): before, its sync
    /// set is empty for want of it, and nothing it holds counts as left.
    fn rooted(&mut self) -> bool;
    /// Forgets the local copies of `ts`, every thing whose sync ID stopped in one settle
    /// (`Engine::forget_local`: one forgetting), then unlogs this node's own entries of the
    /// commits that forgot whole, under every sync ID naming their blobs: no judgement reaches a
    /// commit no longer held, and reopened (a start parks every entry not opening to a held
    /// commit) it would come back. O(the blobs of what forgot) beside the engine's forgetting.
    fn forget_local(&mut self, ts: &BTreeSet<Tid>) -> Result<()>;
}

/// A leaving S: its entry when it left, and the complete pass it waits for.
#[derive(Clone, Copy, Debug, PartialEq)]
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
    /// to, no entry and no holder), or this node does not know its synced group yet (pairing:
    /// its sync set is empty for want of it, not because anything left).
    #[default]
    Not,
    /// It left and waits: for a complete pass begun after it left, then for its own writes.
    Waiting,
    /// A complete pass of S since it left, then what it logged itself is elsewhere, or no peer
    /// shares S to take it: it stops.
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
    /// Judgements of a sync ID out of the sync set made (tests: what a change costs).
    judged: u64,
}

impl Default for Leave {
    fn default() -> Leave {
        Leave { set: Effects::new("leave: sync set"), set_feed: None, started: false, out: Effects::new("leave: out of the sync set"), leaving: Stamped::default(), judged: 0 }
    }
}

impl std::fmt::Debug for Leave {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Leave").field("leaving", &self.leaving.iter().collect::<Vec<_>>()).finish_non_exhaustive()
    }
}

impl Leave {
    /// Follows the sync set into what this node syncs, and stops each sync ID that left it once
    /// a complete pass after it left ended and what it logged itself there is elsewhere
    /// (spec/sync-set.md §3). Whether it acted.
    pub fn settle(&mut self, g: &mut impl Ground) -> Result<bool> {
        let mut acted = false;
        for s in g.held_added(&mut self.set_feed)? {
            self.set.want(s);
        }
        for s in self.set.due() {
            let Some((_, now)) = self.set.try_settle(&s, || g.sync_held(&s))? else { continue };
            match now {
                Some(h) => {
                    // synced again before it stopped: kept as it was
                    self.out.unwant(&s);
                    self.leaving.remove(&s);
                    if g.synced(&s) != Some(h) {
                        g.set_synced(&s, Some(h))?;
                        acted = true;
                    }
                }
                None => {
                    self.set.unwant(&s);
                    self.out.want(s);
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
            let Some((_, now)) = run(&mut self.out, &s, || judge(g, &s, leaving))? else { continue };
            let Some(&Left { held: (t, h), .. }) = self.leaving.get(&s) else { continue };
            match now {
                Wait::Not => {}
                Wait::Waiting => {
                    // held before the start, not synced yet: synced while it waits
                    if g.synced(&s).is_none() {
                        g.set_synced(&s, Some((t, h)))?;
                        acted = true;
                    }
                }
                Wait::Done | Wait::Lost => {
                    if now == Wait::Done && h == Holding::Read {
                        forget.insert(t);
                    }
                    stopped.push(s);
                }
            }
        }
        // unsyncing: one forgetting for every thing whose sync ID stopped, before the shreds,
        // so a crash between finds the rows at the next start and does both again
        if !forget.is_empty() {
            g.forget_local(&forget)?;
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
        self.leaving.iter().map(|(s, l)| (*s, l.since)).collect()
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
/// it; neither, or no synced group known yet: not), noting when it first did; then a complete
/// pass since it left, then its own keys, then its own writes.
fn judge(g: &mut impl Ground, s: &SyncId, leaving: &mut Stamped<SyncId, Left>) -> Result<Wait> {
    let holder = g.holder(s)?;
    let left = match leaving.get(s) {
        Some(x) => *x,
        None => {
            let Some(held) = g.synced(s).or(holder) else { return Ok(Wait::Not) };
            if !g.rooted() {
                return Ok(Wait::Not);
            }
            let x = Left { held, since: g.pass_seq(), sourced: false };
            leaving.insert(*s, x);
            x
        }
    };
    let held = left.held;
    // lists give S back only while its thing is in the closure: leaving it (an unsync, this
    // node's removal) ends the pass with a source unwaited
    let moot = left.sourced && !g.in_sync_things(&held.0)?;
    if !moot && !g.passed(s, left.since) {
        return Ok(Wait::Waiting);
    }
    if holder != Some(held) {
        // a role commit on S's thing uncounted for want of its lists (a revocation taken before
        // them): one complete pass with a source, begun now, fetches them before S is judged lost
        if !left.sourced && g.uncounted_role(&held.0) && g.in_sync_things(&held.0)? {
            leaving.insert(*s, Left { since: g.pass_seq(), sourced: true, ..left });
            return Ok(Wait::Waiting);
        }
        return Ok(Wait::Lost);
    }
    let done = match held.1 {
        Holding::Read => g.own_elsewhere(s)?,
        Holding::Unread => g.own_present(s)?,
    } || !g.waited(s)?;
    Ok(if done { Wait::Done } else { Wait::Waiting })
}

/// `Effects::settle` with a failing function: the key stays due, the error goes up.
fn run<K: std::hash::Hash + Eq + Clone, V: Clone + PartialEq + Default>(fx: &mut Effects<K, V>, k: &K, f: impl FnOnce() -> Result<V>) -> Result<Option<(Option<V>, V)>> {
    let mut failed = None;
    let moved = fx.settle(k, || {
        f().unwrap_or_else(|e| {
            failed = Some(e);
            V::default()
        })
    });
    if let Some(e) = failed {
        fx.unwant(k);
        fx.want(k.clone());
        return Err(e);
    }
    Ok(moved)
}

/// The product's ground: the engine's facade, the store and what sources showed (streams).
pub struct Live<'a, 'b> {
    pub cx: &'a mut crate::types::Cx<'b>,
    pub sources: &'a dyn Sources,
    pub opens: &'a crate::opens::Opens,
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
    fn own_elsewhere(&mut self, s: &SyncId) -> Result<bool> {
        for c in self.cx.engine.own_commits(s)?.iter() {
            let mut entries = 0;
            let mut held = false;
            for b in self.cx.engine.commit_blobs(c)?.iter() {
                if self.cx.store.entry(s, b)?.is_some() {
                    entries += 1;
                    held |= self.cx.store.elsewhere(s, b)?;
                }
            }
            if entries > 0 && !held {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn own_present(&mut self, s: &SyncId) -> Result<bool> {
        Ok(self.cx.store.entries(s)?.into_iter().filter(|e| e.own).all(|e| self.sources.present(s, &e.blob)))
    }
    fn waited(&mut self, s: &SyncId) -> Result<bool> {
        self.opens.waited(self.cx.engine, self.cx.store, s, true)
    }
    fn shred(&mut self, s: &SyncId) -> Result<()> {
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
    fn forget_local(&mut self, ts: &BTreeSet<Tid>) -> Result<()> {
        forget_local(self.cx.engine, self.cx.store, ts)
    }
}

/// `Ground::forget_local` (`Engine::forget_local`, then each own entry naming a blob of a commit
/// it forgot whole is unlogged); also an unsync of a thing kept after its share ended
/// (`Node::unsync`).
pub(crate) fn forget_local(engine: &mut osis_engine::Engine, store: &mut crate::store::Store, ts: &BTreeSet<Tid>) -> Result<()> {
    let gone = engine.forget_local(ts)?;
    for b in &gone {
        for s in store.naming(b)? {
            if store.entry(&s, b)?.is_some_and(|e| e.own) {
                osis_base::costs::count("leave: own entries unlogged", 1);
                store.unlog_entry(&s, b)?;
            }
        }
    }
    Ok(())
}
