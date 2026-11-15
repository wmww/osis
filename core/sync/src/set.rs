//! What a node syncs, in two layers.
//!
//! - The engine's sync set followed per key (spec/sync-set.md §2, `SetFollow`): each thing that
//!   may have entered the synced group's closure (`Engine::things_entered`) is followed through
//!   its own `Effects` key, whether the closure holds it and its `thing_sync`, so a closure change
//!   or a change of one thing's keys costs what moved, never the closure. `leave` alone follows it.
//! - The sync IDs this node syncs: the sync set, and each sync ID that left it while it waits to
//!   stop (spec/sync-set.md §3: it stays a member of its shared sets as before). `leave` writes
//!   them into the store (`Store::set_holdings`); every other module (store, opens, dials, read,
//!   unread, streams, status) follows them there, each by its own `SyncsFollow` (the store's feed
//!   of moved sync IDs) or by stamped reads (`Store::synced`, `Store::holding`), never the
//!   engine's sync set. So a leaving sync ID is synced everywhere until `leave` stops it.
//!
//! An S two things name (two records naming one sync ID, or a read thing and a record) is held
//! as `Engine::sync_set` folds it: read by the greatest thing reading it, else kept unread by the
//! least thing keeping it.

use crate::store::Store;
use crate::types::{Holding, Result};
use osis_base::memo::{Effects, Feed};
use osis_base::{SyncId, Tid};
use osis_engine::Engine;
use osis_engine::sync::{ThingSync, ThingsFeed};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// One sync ID's entry of the sync set: its thing and how it is held.
pub type Held = (Tid, Holding);

/// What `SetFollow` reads (the product's is the engine; a test's a table).
pub trait SetGround {
    /// The things that may have entered the synced group's closure since `f`'s last read
    /// (`Engine::things_entered`; a superset is fine).
    fn things_entered(&mut self, f: &mut ThingsFeed) -> Result<Vec<Tid>>;
    /// Whether the closure holds `t` (`Engine::in_sync_things`), read per thing.
    fn in_sync_things(&mut self, t: &Tid) -> Result<bool>;
    /// The closure whole (`Engine::sync_things`): debug builds check the followed set by it.
    fn sync_things(&mut self) -> Result<Arc<BTreeSet<Tid>>>;
    /// How this node syncs thing `t` (`Engine::thing_sync`).
    fn thing_sync(&mut self, t: &Tid) -> Result<ThingSync>;
}

impl SetGround for Engine {
    fn things_entered(&mut self, f: &mut ThingsFeed) -> Result<Vec<Tid>> {
        Ok(Engine::things_entered(self, f)?)
    }
    fn in_sync_things(&mut self, t: &Tid) -> Result<bool> {
        Ok(Engine::in_sync_things(self, t)?)
    }
    fn sync_things(&mut self) -> Result<Arc<BTreeSet<Tid>>> {
        Ok(Engine::sync_things(self)?)
    }
    fn thing_sync(&mut self, t: &Tid) -> Result<ThingSync> {
        Ok(Engine::thing_sync(self, t)?)
    }
}

/// One module's cursor over the sync IDs this node syncs (the store's `syncs_feed`): what moved
/// since its last settle, O(moved). Its first settle lists every one.
#[derive(Clone, Default)]
pub struct SyncsFollow {
    feed: Option<Feed<SyncId>>,
    seen: BTreeMap<SyncId, Held>,
}

impl SyncsFollow {
    /// The sync IDs whose entry moved since the last call, each with its entry then and now
    /// (`None`: not synced).
    pub fn settle(&mut self, store: &Store) -> Vec<(SyncId, Option<Held>, Option<Held>)> {
        let ids: BTreeSet<SyncId> = match self.feed.as_mut() {
            Some(f) => f.added().into_iter().collect(),
            None => {
                self.feed = Some(store.syncs_feed());
                store.syncs().into_keys().chain(self.seen.keys().copied()).collect()
            }
        };
        let mut out = Vec::new();
        for s in ids {
            let now = store.synced(&s);
            let was = match now {
                Some(h) => self.seen.insert(s, h),
                None => self.seen.remove(&s),
            };
            if was != now {
                out.push((s, was, now));
            }
        }
        out
    }
}

impl std::fmt::Debug for SyncsFollow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncsFollow").field("seen", &self.seen).finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct SetFollow {
    entered: ThingsFeed,
    /// Per thing of the closure, how it is synced (`None`: out of the closure, followed no more).
    thing: Effects<Tid, Option<ThingSync>>,
    /// The things followed with a value in the closure, as last settled.
    things: BTreeSet<Tid>,
    /// The sync IDs each thing is synced under, as last settled.
    ids_of: BTreeMap<Tid, Vec<(SyncId, Holding)>>,
    /// Per sync ID, every thing naming it.
    by_sync: BTreeMap<SyncId, BTreeMap<Tid, Holding>>,
    held: BTreeMap<SyncId, Held>,
    /// Sync IDs whose things moved and whose entry is not judged yet (kept over a failed settle).
    touched: BTreeSet<SyncId>,
    /// Debug builds: the closure last compared with `things`, compared again once it moves.
    #[cfg(debug_assertions)]
    checked: Option<Arc<BTreeSet<Tid>>>,
}

impl SetFollow {
    pub fn new(name: &'static str) -> SetFollow {
        SetFollow { entered: ThingsFeed::default(), thing: Effects::new(name), things: BTreeSet::new(), ids_of: BTreeMap::new(), by_sync: BTreeMap::new(), held: BTreeMap::new(), touched: BTreeSet::new(), #[cfg(debug_assertions)] checked: None }
    }

    /// Whether `s` is in the sync set, as last settled.
    pub fn holds(&self, s: &SyncId) -> bool {
        self.held.contains_key(s)
    }

    /// The sync IDs whose entry moved since the last call, each with its entry now (`None`: it
    /// left the sync set). O(what moved): each thing that may have entered is followed, each
    /// followed thing whose place or keys moved is settled again (spec/sync-set.md §2 Cost).
    pub fn settle(&mut self, g: &mut impl SetGround) -> Result<Vec<(SyncId, Option<Held>)>> {
        let mut touched = std::mem::take(&mut self.touched);
        let out = self.settle_into(g, &mut touched);
        if out.is_err() {
            self.touched = touched;
        }
        out
    }

    fn settle_into(&mut self, g: &mut impl SetGround, touched: &mut BTreeSet<SyncId>) -> Result<Vec<(SyncId, Option<Held>)>> {
        let entered = g.things_entered(&mut self.entered)?;
        osis_base::costs::count("sync set: entered", entered.len() as u64);
        for t in entered {
            self.thing.want(t);
        }
        let due = self.thing.due();
        #[cfg(debug_assertions)]
        let moved = !due.is_empty();
        osis_base::costs::count("sync set: settled", due.len() as u64);
        for t in due {
            let Some((_, now)) = self.thing.try_settle(&t, || if g.in_sync_things(&t)? { g.thing_sync(&t).map(Some) } else { Ok(None) })? else { continue };
            let ids = match now {
                None => {
                    self.thing.unwant(&t);
                    self.things.remove(&t);
                    Vec::new()
                }
                Some(now) => {
                    self.things.insert(t);
                    match now {
                        ThingSync::Read(ids) => ids.into_iter().map(|s| (s, Holding::Read)).collect(),
                        ThingSync::Unread(ids) => ids.into_iter().map(|s| (s, Holding::Unread)).collect(),
                        ThingSync::Unsyncable | ThingSync::Plain => Vec::new(),
                    }
                }
            };
            self.moved(&t, ids, touched);
        }
        // a thing entering or leaving that no key moved for shows as the closure moving alone
        #[cfg(debug_assertions)]
        {
            let all = osis_base::costs::paused(|| g.sync_things())?;
            if moved || !self.checked.as_ref().is_some_and(|c| Arc::ptr_eq(c, &all)) {
                debug_assert_eq!(self.things, *all, "the followed sync set differs from the closure derived anew");
                self.checked = Some(all);
            }
        }
        let mut out = Vec::new();
        for s in std::mem::take(touched) {
            let now = self.by_sync.get(&s).and_then(fold);
            let was = match now {
                Some(h) => self.held.insert(s, h),
                None => self.held.remove(&s),
            };
            if was != now {
                out.push((s, now));
            }
        }
        Ok(out)
    }

    fn moved(&mut self, t: &Tid, ids: Vec<(SyncId, Holding)>, touched: &mut BTreeSet<SyncId>) {
        for (s, _) in self.ids_of.remove(t).unwrap_or_default() {
            if let Some(m) = self.by_sync.get_mut(&s) {
                m.remove(t);
                if m.is_empty() {
                    self.by_sync.remove(&s);
                }
            }
            touched.insert(s);
        }
        for (s, h) in &ids {
            self.by_sync.entry(*s).or_default().insert(*t, *h);
            touched.insert(*s);
        }
        if !ids.is_empty() {
            self.ids_of.insert(*t, ids);
        }
    }
}

/// `Engine::sync_set`'s fold of the things naming one sync ID.
fn fold(m: &BTreeMap<Tid, Holding>) -> Option<Held> {
    m.iter().rev().find(|(_, h)| **h == Holding::Read).or_else(|| m.iter().find(|(_, h)| **h == Holding::Unread)).map(|(t, h)| (*t, *h))
}

impl std::fmt::Debug for SetFollow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetFollow").field("held", &self.held).finish_non_exhaustive()
    }
}
