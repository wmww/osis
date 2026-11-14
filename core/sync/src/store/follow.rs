//! What the store follows of the engine (notes/sync-store.md): the sync set per key
//! (`SetFollow`), the node's caps, and the served path of each sync ID read here (its thing's
//! `sync.0` record, spec/sync-ids.md §5), each an `Effects` value, so a step costs what moved;
//! and the entries carrying a commit that pends here (`Carriers`).

use super::Store;
use crate::set::SetFollow;
use crate::types::{Holding, Result};
use osis_base::memo::{Effects, Feed};
use osis_base::{BlobId, CommitId, SyncId, Tid, WallMs};
use osis_crypto::Epoch;
use osis_engine::Engine;
use osis_engine::sync::{Caps, Opened, Path};
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
    carriers: Carriers,
}

/// The entries carrying a commit that pends here (spec/commits.md §4 Pending storage): the
/// engine keeps its pending copy only while an entry of it is in the store, an unstamped one
/// charged to the peer that brought it (spec/sync-ids.md §5 Peer budget), so what one peer makes
/// pend is bounded by its own budget. A blob no entry names any more lets its commit's pending
/// copy go once no blob of it is named (`release`); a commit held here takes its entries off
/// their peers' budgets. Nothing kept but the feeds' cursors: a start sweeps every pending commit
/// once.
#[derive(Clone, Default)]
struct Carriers {
    unnamed: Option<Feed<BlobId>>,
    commits: Option<Feed<CommitId>>,
}

/// Whether an open left the entry's commit pending here: the entry is kept as its carrier.
pub(crate) fn pends(engine: &mut Engine, o: &Opened) -> bool {
    matches!(o, Opened::Commit(c, _) if engine.pends(c))
}

/// Commit `c`'s pending copy goes when no entry in the store names a blob of it (spec/commits.md
/// §4 Pending storage: kept only while something carries it). A commit that came by no entry here
/// (an inbox payload, a node's pairing) names no blob, and is left.
pub(crate) fn release(engine: &mut Engine, store: &Store, c: &CommitId) -> Result<()> {
    if !engine.pends(c) {
        return Ok(());
    }
    let blobs = engine.commit_blobs(c)?;
    if blobs.is_empty() {
        return Ok(());
    }
    for b in blobs.iter() {
        if store.named(b)? {
            return Ok(());
        }
    }
    engine.forget_pending(c)?;
    Ok(())
}

impl Carriers {
    fn settle(&mut self, engine: &mut Engine, store: &mut Store) -> Result<bool> {
        let mut acted = false;
        match self.unnamed.as_mut() {
            Some(f) => {
                for b in f.added() {
                    if let Some(c) = engine.blob_commit(&b)? {
                        release(engine, store, &c)?;
                    }
                }
            }
            None => {
                self.unnamed = Some(store.unnamed_feed());
                for (c, _) in engine.pending() {
                    release(engine, store, &c)?;
                }
            }
        }
        // a kept copy of a commit proved junk (spec/commits.md §4 Copies: the node judges again
        // the copies of the commit it holds as blobs): every entry naming a blob of it opens again
        for c in engine.take_redeliver() {
            acted |= reopen(engine, store, &c)?;
            engine.redelivered(&c)?;
        }
        let held = match self.commits.as_mut() {
            Some(f) => f.added(),
            None => {
                self.commits = Some(engine.commit_feed());
                Vec::new()
            }
        };
        for c in held {
            if !engine.holds_commit(&c) || engine.pends(&c) {
                continue;
            }
            for b in engine.commit_blobs(&c)?.iter() {
                for s in store.naming(b)? {
                    if store.entry(&s, b)?.is_some_and(|e| !e.own && e.stamp.is_none()) {
                        store.uncharge(&s, b)?;
                        acted = true;
                    }
                }
            }
        }
        Ok(acted)
    }
}

impl Default for Follow {
    fn default() -> Follow {
        let mut caps = Effects::new("store: caps");
        caps.want(());
        Follow { set: SetFollow::new("store: sync set"), caps, paths: Effects::new("store: paths"), creds: Effects::new("store: read secrets"), read: BTreeMap::new(), carriers: Carriers::default() }
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
                // read no more: its complete passes and record blobs go with it (a pass of it
                // again when read again)
                if !matches!(now, Some((_, Holding::Read))) {
                    engine.forget_read(s)?;
                }
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
        acted |= self.carriers.settle(engine, store)?;
        acted |= store.settle_at(now)?;
        Ok(acted)
    }
}

/// Opens again every entry in the store naming a blob of commit `c` (`Engine::take_redeliver`).
/// Whether one opened.
fn reopen(engine: &mut Engine, store: &mut Store, c: &CommitId) -> Result<bool> {
    let mut opened = false;
    for b in engine.commit_blobs(c)?.iter() {
        let Some(bytes) = store.bytes(b)? else { continue };
        for s in store.naming(b)? {
            let Some(e) = store.entry(&s, b)? else { continue };
            engine.open_entry(&s, b, &e.wrap, &bytes)?;
            opened = true;
        }
    }
    Ok(opened)
}

/// Opens S's held entries whose commit is neither held nor pending here (kept as they did not
/// open, or a peer's); one that gives something held is off its peer budget (spec/sync-ids.md
/// §5). Whether one opened.
fn open_unopened(engine: &mut Engine, store: &mut Store, s: &SyncId) -> Result<bool> {
    let mut opened = false;
    for e in store.entries(s)? {
        if e.own || engine.blob_commit(&e.blob)?.is_some_and(|c| engine.holds_commit(&c) || engine.pends(&c)) {
            continue;
        }
        let Some(bytes) = store.bytes(&e.blob)? else { continue };
        let o = engine.open_entry(s, &e.blob, &e.wrap, &bytes)?;
        if pends(engine, &o) {
            continue;
        }
        if matches!(o, Opened::Commit(..) | Opened::Linked) {
            store.uncharge(s, &e.blob)?;
            opened = true;
        }
    }
    Ok(opened)
}
