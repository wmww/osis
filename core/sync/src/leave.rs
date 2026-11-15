//! Leaving the sync set (spec/sync-set.md §3), and the sync IDs this node syncs.
//!
//! `leave` alone follows the engine's sync set (`SetFollow`) and writes what this node syncs into
//! the store (`Store::set_holdings`): the sync set, and each sync ID that left it while it waits
//! to stop. Every other module follows that (crate::set), so a waiting sync ID stays open,
//! served, logged into, judged and counted as before until it stops (§3: it stays a member of its
//! shared sets as before).
//!
//! The rule, read or kept unread alike, whatever made S leave: S that left waits first for a
//! complete pass of it begun after it left (spec/sync-set.md §3: what made it leave may be undone
//! by what that pass brings, such as a rotation's thing list arriving after the rotation), then
//! judges again: the node's keys must still let it hold S as it did (`Engine::sync_holder`), else
//! it stops at once (its secrets lost, a removal); then it waits until what this node logged
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

use crate::set::{Held, SetFollow, SetGround};
use crate::types::{Holding, Result};
use osis_base::memo::{Effects, Stamped};
use osis_base::{BlobId, SyncId, Tid};
use std::collections::{BTreeMap, BTreeSet};

/// Whether a source of S showed `b` present by its stream (spec/sync-set.md §3: what a node
/// keeping S unread waits for before leaving). Stamped reads, so a waiting S is judged again when
/// presence moves.
pub trait Sources {
    fn present(&self, s: &SyncId, b: &BlobId) -> bool;
}

/// What leave reads and does (the product's is `Live`; a test's a table).
pub trait Ground: SetGround {
    /// S's entry in the sync IDs this node syncs (`Store::synced`).
    fn synced(&mut self, s: &SyncId) -> Option<Held>;
    /// Sets it (`Store::set_holdings`; `None`: not synced).
    fn set_synced(&mut self, s: &SyncId, now: Option<Held>);
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
    /// The pass place now (`Engine::pass_place`): when S left, in the order passes begin.
    fn pass_seq(&mut self) -> u64;
    /// A complete pass of S begun after pass place `since` ended (status's, spec/sync-status.md §1).
    fn passed(&mut self, s: &SyncId, since: u64) -> Result<bool>;
    /// This node knows the group whose closure it syncs (`Engine::sync_rooted`): before, its sync
    /// set is empty for want of it, and nothing it holds counts as left.
    fn rooted(&mut self) -> Result<bool>;
    /// Forgets `t`'s local copy (`Engine::forget_local`), then unlogs this node's own entries,
    /// under every sync ID it holds, of the commits that forgot whole: no judgement reaches a
    /// commit no longer held, and reopened (a start parks every entry not opening to a held
    /// commit) it would come back. O(entries held), on this rare path alone.
    fn forget_local(&mut self, t: &Tid) -> Result<()>;
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
    set: SetFollow,
    /// The first settle is done: it wants every sync ID the store holds rows of or syncs, as a
    /// feed's first read lists everything; later ones, each sync ID that leaves the sync set.
    started: bool,
    /// Per sync ID out of the sync set that this node syncs or holds rows of, its judgement.
    out: Effects<SyncId, Wait>,
    /// Per leaving S, its entry when it left and the pass place it left at
    /// (`Engine::pass_place`): status runs a complete pass of it begun after (`passes_wanted`),
    /// which the wait reads. Stamped: status follows it whole.
    leaving: Stamped<SyncId, (Held, u64)>,
    /// Judgements of a sync ID out of the sync set made (tests: what a change costs).
    judged: u64,
}

impl Default for Leave {
    fn default() -> Leave {
        Leave { set: SetFollow::new("leave: sync set"), started: false, out: Effects::new("leave: out of the sync set"), leaving: Stamped::default(), judged: 0 }
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
        for (s, now) in self.set.settle(g)? {
            match now {
                Some(h) => {
                    // synced again before it stopped: kept as it was
                    self.out.unwant(&s);
                    self.leaving.remove(&s);
                    if g.synced(&s) != Some(h) {
                        g.set_synced(&s, Some(h));
                        acted = true;
                    }
                }
                None => self.out.want(s),
            }
        }
        if !self.started {
            // what this node held before its start (or a restart of the modules) and its sync set
            // does not: left while it was down, or waiting still
            for s in g.stored()? {
                if !self.set.holds(&s) {
                    self.out.want(s);
                }
            }
            self.started = true;
        }
        for s in self.out.due() {
            self.judged += 1;
            let leaving = &mut self.leaving;
            let Some((_, now)) = run(&mut self.out, &s, || judge(g, &s, leaving))? else { continue };
            let Some(&((t, h), _)) = self.leaving.get(&s) else { continue };
            match now {
                Wait::Not => {}
                Wait::Waiting => {
                    // held before the start, not synced yet: synced while it waits
                    if g.synced(&s).is_none() {
                        g.set_synced(&s, Some((t, h)));
                        acted = true;
                    }
                }
                Wait::Done | Wait::Lost => {
                    // unsyncing: forgotten before the shred, so a crash between finds the rows
                    // at the next start and does both again
                    if now == Wait::Done && h == Holding::Read {
                        g.forget_local(&t)?;
                    }
                    g.shred(&s)?;
                    g.set_synced(&s, None);
                    self.leaving.remove(&s);
                    self.out.unwant(&s);
                    acted = true;
                }
            }
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
        self.leaving.iter().map(|(s, (_, since))| (*s, *since)).collect()
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
fn judge(g: &mut impl Ground, s: &SyncId, leaving: &mut Stamped<SyncId, (Held, u64)>) -> Result<Wait> {
    let holder = g.holder(s)?;
    let (held, since) = match leaving.get(s) {
        Some(x) => *x,
        None => {
            let Some(held) = g.synced(s).or(holder) else { return Ok(Wait::Not) };
            if !g.rooted()? {
                return Ok(Wait::Not);
            }
            let x = (held, g.pass_seq());
            leaving.insert(*s, x);
            x
        }
    };
    if !g.passed(s, since)? {
        return Ok(Wait::Waiting);
    }
    if holder != Some(held) {
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

impl SetGround for Live<'_, '_> {
    fn sync_things(&mut self) -> Result<std::sync::Arc<BTreeSet<Tid>>> {
        Ok(self.cx.engine.sync_things()?)
    }
    fn thing_sync(&mut self, t: &Tid) -> Result<osis_engine::sync::ThingSync> {
        Ok(self.cx.engine.thing_sync(t)?)
    }
}

impl Ground for Live<'_, '_> {
    fn synced(&mut self, s: &SyncId) -> Option<Held> {
        self.cx.store.synced(s)
    }
    fn set_synced(&mut self, s: &SyncId, now: Option<Held>) {
        self.cx.store.set_holdings(&[(*s, now)]);
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
    fn pass_seq(&mut self) -> u64 {
        self.cx.engine.pass_place()
    }
    fn rooted(&mut self) -> Result<bool> {
        Ok(self.cx.engine.sync_rooted()?)
    }
    fn passed(&mut self, s: &SyncId, since: u64) -> Result<bool> {
        Ok(self.status.passed_since(s, since))
    }
    fn forget_local(&mut self, t: &Tid) -> Result<()> {
        self.cx.engine.forget_local(t)?;
        for (s, _) in self.cx.store.syncs() {
            for e in self.cx.store.entries(&s)?.into_iter().filter(|e| e.own) {
                if let Some(c) = self.cx.engine.blob_commit(&e.blob)?
                    && !self.cx.engine.holds_commit(&c)
                    && !self.cx.engine.pends(&c)
                {
                    self.cx.store.unlog_entry(&s, &e.blob)?;
                }
            }
        }
        Ok(())
    }
}
