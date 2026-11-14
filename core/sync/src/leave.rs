//! Leaving the sync set, read side (spec/sync-set.md §3): a read sync ID that left the set is
//! shredded once each of this node's own commits with an entry under it is held elsewhere, and when
//! its thing left the synced group's closure while still read here (unsyncing), the thing's local
//! copy is forgotten first. Kept unread leaving is `unread`'s.
//!
//! Work follows change: the sync set through one `Effects` key, diffed on change; each leaving S
//! judged through its own key over S's own commits and status's durable held-elsewhere marks on
//! their entries (O(own commits under S)). Status judges S no more once it left, so the marks are
//! what the node knew when S left. At a start, every sync ID with rows in the store, outside the sync set,
//! whose thing reads it here counts as leaving (the store is the truth after a restart): nothing
//! of this module's is durable.

use crate::types::{Holding, Result};
use osis_base::memo::Effects;
use osis_base::{SyncId, Tid};
use osis_engine::sync::SyncSet;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// What leave reads and does (the product's is `Live`; a test's a table).
pub trait Ground {
    fn sync_set(&mut self) -> Result<Arc<SyncSet>>;
    /// The sync IDs whose store holds rows (`Store::held_ids`).
    fn stored(&mut self) -> Result<BTreeSet<SyncId>>;
    /// The thing owning S by its `sync.0` (`Engine::sync_owner`).
    fn owner(&mut self, s: &SyncId) -> Result<Option<Tid>>;
    /// Whether this node reads `t` under S (`Engine::thing_sync`, whatever lists `t`): it still
    /// holds a read secret of `t`, so S left because `t` left the synced group's closure.
    fn reads(&mut self, t: &Tid, s: &SyncId) -> Result<bool>;
    /// `unread` follows S (listed, or leaving and waiting).
    fn unread_keeps(&self, s: &SyncId) -> bool;
    /// Each of this node's own commits with an entry under S is held elsewhere: one of its
    /// entries there recorded so (`Store::elsewhere`, status's durable mark, spec/sync-status.md §2).
    fn own_elsewhere(&mut self, s: &SyncId) -> Result<bool>;
    fn shred(&mut self, s: &SyncId) -> Result<()>;
    /// Forgets `t`'s local copy (`Engine::forget_local`).
    fn forget_local(&mut self, t: &Tid) -> Result<()>;
}

#[derive(Clone)]
pub struct Leave {
    set: Effects<(), Arc<SyncSet>>,
    /// The sync IDs read here as last settled, each with its thing.
    read: BTreeMap<SyncId, Tid>,
    /// The start's sweep of the store is done.
    swept: bool,
    /// Read sync IDs that left while their thing is still read here, waiting for their own
    /// entries to be elsewhere, each with its thing.
    leaving: BTreeMap<SyncId, Tid>,
    elsewhere: Effects<SyncId, bool>,
    /// Judgements of a leaving S made (tests: what a change costs).
    judged: u64,
}

impl Default for Leave {
    fn default() -> Leave {
        let mut set = Effects::new("leave: sync set");
        set.want(());
        Leave { set, read: BTreeMap::new(), swept: false, leaving: BTreeMap::new(), elsewhere: Effects::new("leave: own entries elsewhere"), judged: 0 }
    }
}

impl std::fmt::Debug for Leave {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Leave").field("leaving", &self.leaving).finish_non_exhaustive()
    }
}

impl Leave {
    /// Follows the sync set and stops each read sync ID that left it once its own entries are
    /// elsewhere (spec/sync-set.md §3). Whether it acted.
    pub fn settle(&mut self, g: &mut impl Ground) -> Result<bool> {
        let mut acted = false;
        if !self.set.due().is_empty()
            && let Some((_, set)) = run(&mut self.set, &(), || g.sync_set())?
        {
            let gone: Vec<(SyncId, Tid)> = self.read.iter().filter(|(s, _)| !matches!(set.ids.get(*s), Some((_, Holding::Read)))).map(|(s, t)| (*s, *t)).collect();
            for (s, t) in gone {
                self.read.remove(&s);
                // lowered to kept unread is no leaving (spec/sync.md §3)
                if !set.ids.contains_key(&s) && !g.unread_keeps(&s) {
                    acted |= self.left(g, s, t)?;
                }
            }
            for (s, (t, h)) in &set.ids {
                if *h == Holding::Read {
                    self.read.insert(*s, *t);
                }
            }
            // synced again before it stopped: kept as it was
            let back: Vec<SyncId> = self.leaving.keys().filter(|s| set.ids.contains_key(*s)).copied().collect();
            for s in back {
                self.leaving.remove(&s);
                self.elsewhere.unwant(&s);
            }
            if !self.swept {
                // a read sync ID's rows outside the sync set: it left while the node was down
                // (another account's inbox this node deposits to, or one kept unread, is none)
                for s in g.stored()? {
                    if set.ids.contains_key(&s) || self.leaving.contains_key(&s) || g.unread_keeps(&s) {
                        continue;
                    }
                    let Some(t) = g.owner(&s)? else { continue };
                    if g.reads(&t, &s)? {
                        acted |= self.left(g, s, t)?;
                    }
                }
                self.swept = true;
            }
        }
        for s in self.elsewhere.due() {
            let Some(&t) = self.leaving.get(&s) else {
                self.elsewhere.unwant(&s);
                continue;
            };
            self.judged += 1;
            let Some((_, now)) = run(&mut self.elsewhere, &s, || g.own_elsewhere(&s))? else { continue };
            if now {
                // forgotten before the shred: a crash between finds the rows at the next start
                g.forget_local(&t)?;
                g.shred(&s)?;
                self.leaving.remove(&s);
                self.elsewhere.unwant(&s);
                acted = true;
            }
        }
        Ok(acted)
    }

    /// S left the sync set: still read here (unsyncing), it waits for its own entries to be
    /// elsewhere; else (no secret of it held) it stops at once.
    fn left(&mut self, g: &mut impl Ground, s: SyncId, t: Tid) -> Result<bool> {
        if g.reads(&t, &s)? {
            self.leaving.insert(s, t);
            self.elsewhere.want(s);
            return Ok(false);
        }
        g.shred(&s)?;
        Ok(true)
    }

    /// Tests only: the judgements of a leaving S made so far.
    #[doc(hidden)]
    pub fn judged(&self) -> u64 {
        self.judged
    }
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

/// The product's ground: the engine's facade, the store and unread.
pub struct Live<'a, 'b> {
    pub cx: &'a mut crate::types::Cx<'b>,
    pub unread: &'a crate::unread::Unread,
}

impl Ground for Live<'_, '_> {
    fn sync_set(&mut self) -> Result<Arc<SyncSet>> {
        Ok(self.cx.engine.sync_set()?)
    }
    fn stored(&mut self) -> Result<BTreeSet<SyncId>> {
        self.cx.store.held_ids()
    }
    fn owner(&mut self, s: &SyncId) -> Result<Option<Tid>> {
        Ok(self.cx.engine.sync_owner(s)?)
    }
    fn reads(&mut self, t: &Tid, s: &SyncId) -> Result<bool> {
        Ok(matches!(self.cx.engine.thing_sync(t)?, osis_engine::sync::ThingSync::Read(ids) if ids.contains(s)))
    }
    fn unread_keeps(&self, s: &SyncId) -> bool {
        self.unread.keeps(s)
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
    fn shred(&mut self, s: &SyncId) -> Result<()> {
        self.cx.store.shred(s)
    }
    fn forget_local(&mut self, t: &Tid) -> Result<()> {
        Ok(self.cx.engine.forget_local(t)?)
    }
}
