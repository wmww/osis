//! Leaving the sync set (spec/sync-set.md §3), and the sync IDs this node syncs.
//!
//! `leave` alone follows the engine's sync set (`SetFollow`) and writes what this node syncs into
//! the store (`Store::set_holdings`): the sync set, and each sync ID that left it while it waits
//! to stop. Every other module follows that (crate::set), so a waiting sync ID stays open,
//! served, logged into, judged and counted as before until it stops (§3: it stays a member of its
//! shared sets as before).
//!
//! The rule, read or kept unread alike: S that left waits until what this node logged itself
//! under S is elsewhere (read: each own commit with an entry under S held elsewhere, status's
//! durable mark on one of its entries, `Store::elsewhere`; kept unread: each own entry present at
//! a source, `Sources`), or no peer shares S to take it (no source now, no kept record holding S
//! as a member: `Opens::shared`), then stops: read and still read here (unsyncing), its thing's local copy
//! is forgotten first. While it waits, the node's keys must still let it hold S as it did
//! (`Engine::sync_holder`): once they do not (its secrets lost, a removal), it stops at once.
//! Synced again before then, it is kept as it was.
//!
//! Work follows change: the sync set per key; each waiting S judged through its own `Effects`
//! key over its own commits or entries (O(own writes under S)). At a start, every sync ID with
//! rows in the store, not synced, that this node's keys still hold (`Engine::sync_holder`), left
//! while the node was down: it waits as above (the store is the truth after a restart). Nothing of
//! this module's is durable.

use crate::set::{Held, SetFollow, SetGround};
use crate::types::{Holding, Result};
use osis_base::memo::Effects;
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
    /// The sync IDs whose store holds rows (`Store::held_ids`).
    fn stored(&mut self) -> Result<BTreeSet<SyncId>>;
    /// S's thing and how this node's keys let it hold S, whatever lists it (`Engine::sync_holder`).
    fn holder(&mut self, s: &SyncId) -> Result<Option<Held>>;
    /// Read: each of this node's own commits with an entry under S is held elsewhere: one of its
    /// entries there recorded so (`Store::elsewhere`, status's durable mark, spec/sync-status.md §2).
    fn own_elsewhere(&mut self, s: &SyncId) -> Result<bool>;
    /// Kept unread: each entry this node logged itself under S is present at a source.
    fn own_present(&mut self, s: &SyncId) -> Result<bool>;
    /// Some peer shares S with this node: a source now, or a kept record holding S as a member
    /// (`Opens::shared`). With none, nothing could take its own writes.
    fn shared(&mut self, s: &SyncId) -> Result<bool>;
    fn shred(&mut self, s: &SyncId) -> Result<()>;
    /// Forgets `t`'s local copy (`Engine::forget_local`).
    fn forget_local(&mut self, t: &Tid) -> Result<()>;
}

/// A waiting S's judgement.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum Wait {
    #[default]
    Waiting,
    /// What it logged itself is elsewhere, or no peer shares S to take it: it stops.
    Done,
    /// This node's keys no longer hold S as they did: it stops at once.
    Lost,
}

#[derive(Clone)]
pub struct Leave {
    set: SetFollow,
    /// The start's sweep of the store is done.
    swept: bool,
    /// Sync IDs that left the sync set and wait, each with its entry when it left.
    waiting: BTreeMap<SyncId, Held>,
    wait: Effects<SyncId, Wait>,
    /// Judgements of a waiting S made (tests: what a change costs).
    judged: u64,
}

impl Default for Leave {
    fn default() -> Leave {
        Leave { set: SetFollow::new("leave: sync set"), swept: false, waiting: BTreeMap::new(), wait: Effects::new("leave: own writes elsewhere"), judged: 0 }
    }
}

impl std::fmt::Debug for Leave {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Leave").field("waiting", &self.waiting).finish_non_exhaustive()
    }
}

impl Leave {
    /// Follows the sync set into what this node syncs, and stops each sync ID that left it once
    /// what it logged itself there is elsewhere (spec/sync-set.md §3). Whether it acted.
    pub fn settle(&mut self, g: &mut impl Ground) -> Result<bool> {
        let mut acted = false;
        for (s, now) in self.set.settle(g)? {
            match now {
                Some(h) => {
                    // synced again before it stopped: kept as it was
                    if self.waiting.remove(&s).is_some() {
                        self.wait.unwant(&s);
                    }
                    if g.synced(&s) != Some(h) {
                        g.set_synced(&s, Some(h));
                        acted = true;
                    }
                }
                None => {
                    if let Some(h) = g.synced(&s) {
                        self.waiting.insert(s, h);
                        self.wait.want(s);
                    }
                }
            }
        }
        if !self.swept {
            // rows of a sync ID not synced that this node's keys still hold: it left while the
            // node was down (another account's inbox this node deposits to is none)
            for s in g.stored()? {
                if g.synced(&s).is_some() {
                    continue;
                }
                if let Some(h) = g.holder(&s)? {
                    g.set_synced(&s, Some(h));
                    self.waiting.insert(s, h);
                    self.wait.want(s);
                    acted = true;
                }
            }
            self.swept = true;
        }
        for s in self.wait.due() {
            let Some(&(t, h)) = self.waiting.get(&s) else {
                self.wait.unwant(&s);
                continue;
            };
            self.judged += 1;
            let Some((_, now)) = run(&mut self.wait, &s, || judge(g, &s, (t, h)))? else { continue };
            if now == Wait::Waiting {
                continue;
            }
            // unsyncing: forgotten before the shred, so a crash between finds the rows at the
            // next start and does both again
            if now == Wait::Done && h == Holding::Read {
                g.forget_local(&t)?;
            }
            g.shred(&s)?;
            g.set_synced(&s, None);
            self.waiting.remove(&s);
            self.wait.unwant(&s);
            acted = true;
        }
        Ok(acted)
    }

    /// Whether S left the sync set and waits to stop.
    pub fn waits(&self, s: &SyncId) -> bool {
        self.waiting.contains_key(s)
    }

    /// Tests only: the judgements of a waiting S made so far.
    #[doc(hidden)]
    pub fn judged(&self) -> u64 {
        self.judged
    }
}

/// Waiting S's judgement, reading its own keys only.
fn judge(g: &mut impl Ground, s: &SyncId, held: Held) -> Result<Wait> {
    if g.holder(s)? != Some(held) {
        return Ok(Wait::Lost);
    }
    let done = match held.1 {
        Holding::Read => g.own_elsewhere(s)?,
        Holding::Unread => g.own_present(s)?,
    } || !g.shared(s)?;
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
        self.cx.store.held_ids()
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
    fn shared(&mut self, s: &SyncId) -> Result<bool> {
        self.opens.shared(self.cx.store, s)
    }
    fn shred(&mut self, s: &SyncId) -> Result<()> {
        self.cx.store.shred(s)
    }
    fn forget_local(&mut self, t: &Tid) -> Result<()> {
        Ok(self.cx.engine.forget_local(t)?)
    }
}
