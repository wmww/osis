//! What the store follows of the engine (notes/sync-boundary.md, store): the sync set per key
//! (`SetFollow`), the node's caps, and the served path of each sync ID read here (its thing's
//! `sync.0` record, spec/sync-ids.md §5), each an `Effects` value, so a step costs what moved.

use super::Store;
use crate::set::SetFollow;
use crate::types::{Holding, Result};
use osis_base::memo::Effects;
use osis_base::{SyncId, Tid, WallMs};
use osis_crypto::Epoch;
use osis_engine::Engine;
use osis_engine::sync::{Caps, Path};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct Follow {
    set: SetFollow,
    caps: Effects<(), Arc<Caps>>,
    /// Per sync ID read here, its thing and its recorded path.
    paths: Effects<(SyncId, Tid), Option<Arc<Path>>>,
    /// Per sync ID read here, the epochs of its current read secrets: held entries that did not
    /// open are opened again as they move.
    creds: Effects<SyncId, Vec<Epoch>>,
    read: BTreeMap<SyncId, Tid>,
}

impl Default for Follow {
    fn default() -> Follow {
        let mut caps = Effects::new("store: caps");
        caps.want(());
        Follow { set: SetFollow::new("store: sync set"), caps, paths: Effects::new("store: paths"), creds: Effects::new("store: read secrets"), read: BTreeMap::new() }
    }
}

impl std::fmt::Debug for Follow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Follow").field("set", &self.set).finish_non_exhaustive()
    }
}

impl Follow {
    /// Follows what moved, then the store's own time (`Store::settle_at`): whether anything
    /// acted.
    pub fn settle(&mut self, engine: &mut Engine, store: &mut Store, now: WallMs) -> Result<bool> {
        let moved = self.set.settle(engine)?;
        let mut acted = !moved.is_empty();
        // kept unread to read opens what is there (spec/sync-judgement.md §6 Read and unread move):
        // every entry held, once
        let raised: Vec<SyncId> = moved.iter().filter(|(s, now)| matches!(now, Some((_, Holding::Read))) && store.holding(s) == Some(Holding::Unread)).map(|(s, _)| *s).collect();
        for (s, now) in &moved {
            if let Some(t) = self.read.remove(s) {
                self.paths.unwant(&(*s, t));
                self.creds.unwant(s);
            }
            if let Some((t, Holding::Read)) = now {
                self.read.insert(*s, *t);
                self.paths.want((*s, *t));
                self.creds.want(*s);
            }
        }
        // opened before the store holds S read: a failure on the way restarts the modules, whose
        // fresh follow finds S still kept unread in the store and opens it all again
        for s in raised {
            for e in store.entries(&s)? {
                if let Some(bytes) = store.bytes(&e.blob)? {
                    engine.open_entry(&s, &e.blob, &e.wrap, &bytes)?;
                }
            }
        }
        store.set_holdings(&moved);
        if !self.caps.due().is_empty() {
            let mut failed = None;
            let r = self.caps.settle(&(), || {
                engine.caps().unwrap_or_else(|e| {
                    failed = Some(e);
                    Arc::default()
                })
            });
            if let Some(e) = failed {
                self.caps.unwant(&());
                self.caps.want(());
                return Err(e.into());
            }
            if let Some((_, c)) = r {
                store.set_caps(&c);
                acted = true;
            }
        }
        for (s, t) in self.paths.due() {
            let mut failed = None;
            let r = self.paths.settle(&(s, t), || match engine.sync_ids(&t) {
                Ok(ids) => ids.iter().find(|o| o.id == s && !o.hint).map(|o| o.path.clone()),
                Err(e) => {
                    failed = Some(e);
                    None
                }
            });
            if let Some(e) = failed {
                self.paths.unwant(&(s, t));
                self.paths.want((s, t));
                return Err(e.into());
            }
            if let Some((_, Some(p))) = r {
                store.serve_path(&s, &p)?;
                acted = true;
            }
        }
        // an entry kept because it did not open is opened as read secrets arrive
        // (spec/sync-streams.md §4 Fill order; a start tries each once)
        for s in self.creds.due() {
            let mut failed = None;
            let r = self.creds.settle(&s, || match engine.read_credentials(&s) {
                Ok(c) => c.map(|c| c.read_secrets.iter().map(|(e, _)| *e).collect()).unwrap_or_default(),
                Err(e) => {
                    failed = Some(e);
                    Vec::new()
                }
            });
            if let Some(e) = failed {
                self.creds.unwant(&s);
                self.creds.want(s);
                return Err(e.into());
            }
            let Some((was, now)) = r else { continue };
            if was.is_some_and(|w| now.iter().all(|e| w.contains(e))) {
                continue;
            }
            acted |= open_unopened(engine, store, &s)?;
        }
        acted |= store.settle_at(now)?;
        Ok(acted)
    }
}

/// Opens S's held entries the engine has not opened (kept as they did not open, or a peer's);
/// one that opens is off its peer budget (spec/sync-ids.md §5). Whether one opened.
fn open_unopened(engine: &mut Engine, store: &mut Store, s: &SyncId) -> Result<bool> {
    let mut opened = false;
    for e in store.entries(s)? {
        if e.own || engine.blob_commit(&e.blob)?.is_some() {
            continue;
        }
        let Some(bytes) = store.bytes(&e.blob)? else { continue };
        if matches!(engine.open_entry(s, &e.blob, &e.wrap, &bytes)?, osis_engine::sync::Opened::Commit(..) | osis_engine::sync::Opened::Linked) {
            store.uncharge(s, &e.blob)?;
            opened = true;
        }
    }
    Ok(opened)
}
