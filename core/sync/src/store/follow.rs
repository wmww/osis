//! What the store follows of the engine (notes/sync-store.md): the sync set per key
//! (`SetFollow`), the node's caps, and the served path of each sync ID read here (its thing's
//! `sync.0` record, spec/sync-ids.md §5), each an `Effects` value, so a step costs what moved;
//! and the held entries whose commit the engine could not judge yet, opened again as commits
//! arrive (`Awaiting`).

use super::Store;
use crate::set::SetFollow;
use crate::types::{Holding, Result};
use osis_base::memo::{Effects, Feed};
use osis_base::{BlobId, CommitId, SyncId, Tid, WallMs};
use osis_crypto::Epoch;
use osis_engine::Engine;
use osis_engine::sync::{Caps, Opened, Path};
use osis_engine::{Ingested, Reason};
use std::collections::{BTreeMap, BTreeSet};
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
    awaiting: Awaiting,
}

/// Held entries that opened to a commit the engine could not judge and kept nothing of
/// (`Ingested::Awaits`: its author's chain, or a record, not held yet): opened again whenever
/// a commit is held here, until it gives something held or leaves the store (spec/commits.md
/// §4 Unjudgeable: fetched again when what it awaits arrives; the entry stays in the store
/// meanwhile, an unstamped one charged to its peer, spec/sync-ids.md §5 Peer budget). The set
/// is memory: a start opens every held entry whose commit is not held once (`open_unopened`),
/// which finds them again.
#[derive(Clone, Default)]
struct Awaiting {
    /// Entries the store took from now on (`Store::entry_feed`), and commits held from now on
    /// (`Engine::commit_feed`); both start at the first settle.
    entries: Option<Feed<(SyncId, BlobId)>>,
    commits: Option<Feed<CommitId>>,
    set: BTreeSet<(SyncId, BlobId)>,
}

/// Whether an open left the entry's commit unjudged (nothing of it kept).
pub(crate) fn awaits(o: &Opened) -> bool {
    matches!(o, Opened::Commit(_, Ingested::Awaits(_, Reason::MissingChain(_) | Reason::UnknownCreated(_))))
}

impl Awaiting {
    /// Takes up entries the store took that opened to an unjudged commit, then, when a commit
    /// was held since the last settle, opens each again. Whether one opened.
    fn settle(&mut self, engine: &mut Engine, store: &mut Store) -> Result<bool> {
        let entries = self.entries.get_or_insert_with(|| store.entry_feed());
        for (s, b) in entries.added() {
            // a body the store took (streams' pull, open_unopened) that opened to a commit the
            // engine holds nothing of: it awaits
            let Some(e) = store.entry(&s, &b)? else { continue };
            if !e.own && engine.blob_commit(&b)?.is_some_and(|c| !engine.holds_commit(&c)) {
                self.set.insert((s, b));
            }
        }
        let held = match self.commits.as_mut() {
            Some(f) => !f.added().is_empty(),
            None => {
                self.commits = Some(engine.commit_feed());
                false
            }
        };
        if !held || self.set.is_empty() {
            return Ok(false);
        }
        let mut opened = false;
        for (s, b) in std::mem::take(&mut self.set) {
            let (Some(e), Some(bytes)) = (store.entry(&s, &b)?, store.bytes(&b)?) else { continue };
            let o = engine.open_entry(&s, &b, &e.wrap, &bytes)?;
            if awaits(&o) {
                self.set.insert((s, b));
            } else if matches!(o, Opened::Commit(..)) {
                store.uncharge(&s, &b)?;
                opened = true;
            }
        }
        Ok(opened)
    }
}

impl Default for Follow {
    fn default() -> Follow {
        let mut caps = Effects::new("store: caps");
        caps.want(());
        Follow { set: SetFollow::new("store: sync set"), caps, paths: Effects::new("store: paths"), creds: Effects::new("store: read secrets"), read: BTreeMap::new(), awaiting: Awaiting::default() }
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
                // read no more: its complete passes go with it (a pass of it again when read again)
                if !matches!(now, Some((_, Holding::Read))) {
                    engine.forget_pass(s)?;
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
                if let Some(bytes) = store.bytes(&e.blob)?
                    && awaits(&engine.open_entry(&s, &e.blob, &e.wrap, &bytes)?)
                {
                    self.awaiting.set.insert((s, e.blob));
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
            acted |= open_unopened(engine, store, &s, &mut self.awaiting.set)?;
        }
        acted |= self.awaiting.settle(engine, store)?;
        acted |= store.settle_at(now)?;
        Ok(acted)
    }
}

/// Opens S's held entries whose commit is not held here (kept as they did not open, or awaiting
/// a chain, or a peer's); one that gives something held is off its peer budget (spec/sync-ids.md
/// §5), one whose commit is still unjudged joins `awaiting`. Whether one opened.
fn open_unopened(engine: &mut Engine, store: &mut Store, s: &SyncId, awaiting: &mut BTreeSet<(SyncId, BlobId)>) -> Result<bool> {
    let mut opened = false;
    for e in store.entries(s)? {
        if e.own || engine.blob_commit(&e.blob)?.is_some_and(|c| engine.holds_commit(&c)) {
            continue;
        }
        let Some(bytes) = store.bytes(&e.blob)? else { continue };
        let o = engine.open_entry(s, &e.blob, &e.wrap, &bytes)?;
        if awaits(&o) {
            awaiting.insert((*s, e.blob));
        } else if matches!(o, Opened::Commit(..) | Opened::Linked) {
            store.uncharge(s, &e.blob)?;
            opened = true;
        }
    }
    Ok(opened)
}
