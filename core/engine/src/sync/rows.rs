//! The sync set kept per sync ID (spec/sync-set.md §2): each thing that may have entered the
//! closure (`Engine::things_entered`) followed through its own `Effects` key (whether the closure
//! holds it, and its `thing_sync`), folded per sync ID into a stamped row, so a reader of one
//! sync ID's holding, or of the read things, moves with what moved and costs that, never the
//! closure. `Engine::sync_set` folds the whole for listing.

use super::{Holding, ThingSync, ThingsFeed};
use crate::Engine;
use crate::error::Result;
use osis_base::memo::{Effects, Feed, Stamped, StampedSet, Unrecorded};
use osis_base::{SyncId, Tid};
use std::collections::{BTreeMap, BTreeSet};

/// One sync ID's entry of the sync set: its thing and how it is held.
pub type Held = (Tid, Holding);

#[derive(Clone)]
pub(crate) struct SyncRows {
    entered: ThingsFeed,
    /// Per thing that entered, how it is synced (`None`: out of the closure, followed no more).
    thing: Effects<Tid, Option<ThingSync>>,
    /// The sync IDs each thing is synced under, as last settled.
    ids_of: BTreeMap<Tid, Vec<(SyncId, Holding)>>,
    /// Per sync ID, every thing naming it.
    by_sync: BTreeMap<SyncId, BTreeMap<Tid, Holding>>,
    /// Per sync ID of the sync set, its entry (`Engine::sync_set`'s fold), read per sync ID.
    pub(crate) held: Stamped<SyncId, Held>,
    /// `held`'s keys: a feed gives the sync IDs entering it.
    ids: StampedSet<SyncId>,
    /// The things holding a read sync ID (read per thing; a feed gives those added), and how many
    /// each holds.
    pub(crate) read: StampedSet<Tid>,
    read_count: BTreeMap<Tid, usize>,
    /// Debug builds: the things followed in the closure, and the closure last compared with them.
    #[cfg(debug_assertions)]
    things: BTreeSet<Tid>,
    #[cfg(debug_assertions)]
    checked: Option<std::sync::Arc<BTreeSet<Tid>>>,
}

impl Default for SyncRows {
    fn default() -> Self {
        SyncRows {
            entered: ThingsFeed::default(),
            thing: Effects::new("sync: set rows"),
            ids_of: BTreeMap::new(),
            by_sync: BTreeMap::new(),
            held: Stamped::default(),
            ids: StampedSet::default(),
            read: StampedSet::default(),
            read_count: BTreeMap::new(),
            #[cfg(debug_assertions)]
            things: BTreeSet::new(),
            #[cfg(debug_assertions)]
            checked: None,
        }
    }
}

/// `Engine::sync_set`'s fold of the things naming one sync ID: read by the greatest thing reading
/// it, else kept unread by the least thing keeping it.
fn fold(m: &BTreeMap<Tid, Holding>) -> Option<Held> {
    m.iter().rev().find(|(_, h)| **h == Holding::Read).or_else(|| m.iter().find(|(_, h)| **h == Holding::Unread)).map(|(t, h)| (*t, *h))
}

impl SyncRows {
    /// Thing `t` is synced under `ids` now: the sync IDs it named before and names now are
    /// folded again.
    fn moved(&mut self, t: &Tid, ids: Vec<(SyncId, Holding)>) {
        let mut touched = BTreeSet::new();
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
        for s in touched {
            let now = self.by_sync.get(&s).and_then(fold);
            // read unrecorded: `follow_rows` runs outside every reader
            let old = self.held.get(&s).copied();
            if old == now {
                continue;
            }
            match now {
                Some(h) => {
                    self.held.insert(s, h);
                    self.ids.insert(s);
                }
                None => {
                    self.held.remove(&s);
                    self.ids.remove(&s);
                }
            }
            if let Some((x, Holding::Read)) = old {
                self.uncount(&x);
            }
            if let Some((x, Holding::Read)) = now {
                let n = self.read_count.entry(x).or_default();
                *n += 1;
                if *n == 1 {
                    self.read.insert(x);
                }
            }
        }
    }

    fn uncount(&mut self, x: &Tid) {
        if let Some(n) = self.read_count.get_mut(x) {
            *n -= 1;
            if *n == 0 {
                self.read_count.remove(x);
                self.read.remove(x);
            }
        }
    }
}

impl Engine {
    /// Brings the sync set's rows up to date: work in proportion to the things that may have
    /// entered and those whose place or keys moved (spec/sync-set.md §2 Cost).
    pub(crate) fn follow_rows(&mut self) -> Result<()> {
        let _u = Unrecorded::start();
        let mut r = std::mem::take(&mut self.core.sync_rows);
        let out = self.follow_rows_in(&mut r);
        self.core.sync_rows = r;
        out
    }

    fn follow_rows_in(&mut self, r: &mut SyncRows) -> Result<()> {
        let entered = self.things_entered(&mut r.entered)?;
        osis_base::costs::count("sync set: entered", entered.len() as u64);
        for t in entered {
            r.thing.want(t);
        }
        let due = r.thing.due();
        #[cfg(debug_assertions)]
        let moved = !due.is_empty();
        osis_base::costs::count("sync set: settled", due.len() as u64);
        for t in due {
            let Some((_, now)) = r.thing.try_settle(&t, || if self.in_sync_things(&t)? { self.thing_sync(&t).map(Some) } else { Ok(None) })? else { continue };
            #[cfg(debug_assertions)]
            if now.is_some() {
                r.things.insert(t);
            } else {
                r.things.remove(&t);
            }
            let ids = match now {
                None => {
                    r.thing.unwant(&t);
                    Vec::new()
                }
                Some(ThingSync::Read(ids)) => ids.into_iter().map(|s| (s, Holding::Read)).collect(),
                Some(ThingSync::Unread(ids)) => ids.into_iter().map(|s| (s, Holding::Unread)).collect(),
                Some(ThingSync::Unsyncable | ThingSync::Plain) => Vec::new(),
            };
            r.moved(&t, ids);
        }
        // a thing entering or leaving that no key moved for shows as the closure moving alone
        #[cfg(debug_assertions)]
        {
            let all = osis_base::costs::paused(|| self.sync_things())?;
            if moved || !r.checked.as_ref().is_some_and(|c| std::sync::Arc::ptr_eq(c, &all)) {
                debug_assert_eq!(r.things, *all, "the followed sync set differs from the closure derived anew");
                r.checked = Some(all);
            }
        }
        Ok(())
    }

    /// Sync ID `s`'s entry of the sync set (`sync_set`'s), read per sync ID.
    pub fn sync_held(&mut self, s: &SyncId) -> Result<Option<Held>> {
        self.follow_rows()?;
        Ok(self.core.sync_rows.held.get(s).copied())
    }

    /// The sync IDs that entered the sync set since `f`'s last read (its first: every one), each
    /// read by `sync_held`, which moves when it leaves or its entry changes. A reload replaces
    /// the rows both read: a follower starts again (`f` at `None`).
    pub fn sync_held_added(&mut self, f: &mut Option<Feed<SyncId>>) -> Result<Vec<SyncId>> {
        self.follow_rows()?;
        let ids = &self.core.sync_rows.ids;
        Ok(match f {
            Some(f) => f.added(),
            None => {
                *f = Some(ids.feed());
                ids.iter().copied().collect()
            }
        })
    }
}
