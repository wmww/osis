//! The sync set followed per key (spec/sync-set.md §2): the synced group's closure
//! (`Engine::sync_things`) through one `Effects` key, diffed on change, and each thing's
//! `thing_sync` through its own, so a change of one thing's keys moves that thing's sync IDs
//! alone and a closure change costs O(closure). Each module that acts on the sync set (store,
//! opens, the driver's dials) keeps its own `SetFollow` and reads what moved since its last
//! settle; none reads the whole `sync_set` per step.
//!
//! An S two things name (two records naming one sync ID, or a read thing and a record) is held
//! as `Engine::sync_set` folds it: read by the greatest thing reading it, else kept unread by the
//! least thing keeping it.

use crate::types::{Holding, Result};
use osis_base::memo::Effects;
use osis_base::{SyncId, Tid};
use osis_engine::Engine;
use osis_engine::sync::ThingSync;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// One sync ID's entry of the sync set: its thing and how it is held.
pub type Held = (Tid, Holding);

#[derive(Clone)]
pub struct SetFollow {
    closure: Effects<(), Arc<BTreeSet<Tid>>>,
    things: BTreeSet<Tid>,
    thing: Effects<Tid, ThingSync>,
    /// The sync IDs each thing is synced under, as last settled.
    ids_of: BTreeMap<Tid, Vec<(SyncId, Holding)>>,
    /// Per sync ID, every thing naming it.
    by_sync: BTreeMap<SyncId, BTreeMap<Tid, Holding>>,
    held: BTreeMap<SyncId, Held>,
}

impl SetFollow {
    pub fn new(name: &'static str) -> SetFollow {
        let mut closure = Effects::new(name);
        closure.want(());
        SetFollow { closure, things: BTreeSet::new(), thing: Effects::new(name), ids_of: BTreeMap::new(), by_sync: BTreeMap::new(), held: BTreeMap::new() }
    }

    /// The sync IDs whose entry moved since the last call, each with its entry now (`None`: it
    /// left the sync set).
    pub fn settle(&mut self, engine: &mut Engine) -> Result<Vec<(SyncId, Option<Held>)>> {
        let mut touched: BTreeSet<SyncId> = BTreeSet::new();
        if !self.closure.due().is_empty() {
            let mut failed = None;
            let moved = self.closure.settle(&(), || {
                engine.sync_things().unwrap_or_else(|e| {
                    failed = Some(e);
                    Arc::default()
                })
            });
            if let Some(e) = failed {
                self.closure.unwant(&());
                self.closure.want(());
                return Err(e.into());
            }
            if let Some((_, now)) = moved {
                let gone: Vec<Tid> = self.things.iter().filter(|t| !now.contains(*t)).copied().collect();
                for t in gone {
                    self.things.remove(&t);
                    self.thing.unwant(&t);
                    self.moved(&t, Vec::new(), &mut touched);
                }
                for t in now.iter() {
                    if self.things.insert(*t) {
                        self.thing.want(*t);
                    }
                }
            }
        }
        for t in self.thing.due() {
            let mut failed = None;
            let moved = self.thing.settle(&t, || {
                engine.thing_sync(&t).unwrap_or_else(|e| {
                    failed = Some(e);
                    ThingSync::Plain
                })
            });
            if let Some(e) = failed {
                self.thing.unwant(&t);
                self.thing.want(t);
                return Err(e.into());
            }
            let Some((_, now)) = moved else { continue };
            let ids = match now {
                ThingSync::Read(ids) => ids.into_iter().map(|s| (s, Holding::Read)).collect(),
                ThingSync::Unread(ids) => ids.into_iter().map(|s| (s, Holding::Unread)).collect(),
                ThingSync::Unsyncable | ThingSync::Plain => Vec::new(),
            };
            self.moved(&t, ids, &mut touched);
        }
        let mut out = Vec::new();
        for s in touched {
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

    /// S's entry as of the last settle.
    pub fn get(&self, s: &SyncId) -> Option<Held> {
        self.held.get(s).copied()
    }

    /// The whole sync set as of the last settle.
    pub fn held(&self) -> &BTreeMap<SyncId, Held> {
        &self.held
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
