//! What the store follows (notes/sync-store.md): the sync IDs this node syncs
//! (`SyncsFollow`), the engine's caps, and the served path of each sync ID read here (its thing's
//! `sync.0` record, spec/sync-ids.md §5), each an `Effects` value, so a step costs what moved;
//! the entries that did not open, parked under their sync ID's read secrets (`parked`); and the
//! entries carrying a commit that pends here (`Carriers`).

use super::Store;
use crate::set::SyncsFollow;
use crate::types::{Holding, Result};
use osis_base::memo::{Effects, Feed};
use osis_base::{BlobId, CommitId, SyncId, Tid, WallMs};
use osis_crypto::Epoch;
use osis_engine::Engine;
use osis_engine::sync::{Caps, Opened, Path};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Clone)]
pub struct Follow {
    set: SyncsFollow,
    caps: Effects<(), Arc<Caps>>,
    /// Per sync ID read here, its thing and its recorded path.
    paths: Effects<(SyncId, Tid), Option<Arc<Path>>>,
    /// Per sync ID read here, the epochs of its current read secrets: what opens a parked entry.
    creds: Effects<SyncId, Vec<Epoch>>,
    /// Per sync ID read here, its entries that did not open (neither held nor pending here): each
    /// parked under the one thing it awaits, S's read secrets (notes/sync.md Arriving early), and
    /// opened again only as those move. Found by the store's entry feed and at S's start.
    parked: BTreeMap<SyncId, BTreeSet<BlobId>>,
    entries: Option<Feed<(SyncId, BlobId)>>,
    read: BTreeMap<SyncId, Tid>,
    carriers: Carriers,
}

/// The entries carrying a commit that pends here (spec/commits.md §4 Pending storage): the
/// engine keeps its pending copy only while an entry of it is in the store, an unstamped one
/// charged to the peer that brought it (spec/sync-ids.md §5 Peer budget), so what one peer makes
/// pend is bounded by its own budget. A blob no entry names any more lets its commit's pending
/// copy go once no blob of it is named (`release`); a commit held here and pending no more (an
/// applied one's waiting parts joined too) takes its entries off their peers' budgets. Nothing kept but the feeds' cursors: a start sweeps every pending commit
/// once.
#[derive(Clone, Default)]
struct Carriers {
    unnamed: Option<Feed<BlobId>>,
    /// Commits held, and held commits that pended no more (their waiting parts joined).
    commits: Option<(Feed<CommitId>, Feed<CommitId>)>,
    /// Record blobs whose loose records were all learned (`Engine::loose_feed`).
    loose: Option<Feed<BlobId>>,
    /// Waiting memory commits woken (`Engine::memory_woken_feed`).
    woken: Option<Feed<CommitId>>,
}

/// `Engine::open_entry` of entry `b` of read S, an ephemeral commit within the room S's memory
/// cap leaves (`Store::memory_room`); one held, its entry here counts at what it costs held. The
/// one way sync opens an entry.
pub(crate) fn open_entry(engine: &mut Engine, store: &Store, s: &SyncId, b: &BlobId, wrap: &crate::types::Wrap, bytes: &[u8]) -> Result<Opened> {
    let o = engine.open_entry(s, b, wrap, bytes, store.memory_room(s))?;
    if let Opened::Commit(c, _) = &o
        && engine.holds_memory(c)
    {
        store.set_memory_charge(s, b, engine.memory_charge(c)?);
    }
    Ok(o)
}

/// Waiting memory commit `c`, woken by what it awaited, applied within the room of a read sync
/// ID an entry of it is under, its carrier's own count included (spec/sync-compaction.md §2
/// Caps: checked again each time it is applied). One still waiting stays; one past the room is
/// thrown out with nothing of it kept, its carriers released as their blobs go unnamed.
fn apply_waiting(engine: &mut Engine, store: &Store, c: &CommitId) -> Result<bool> {
    if !engine.memory_pending(c) {
        return Ok(false);
    }
    for b in engine.commit_blobs(c)?.iter() {
        for s in store.naming(b)? {
            if store.holding(&s) != Some(Holding::Read) {
                continue;
            }
            let own = match store.entry(&s, b)? {
                Some(e) if !e.role => store.blob_len(b)?.unwrap_or(0).saturating_add(super::ENTRY_OVERHEAD),
                _ => 0,
            };
            let applied = engine.apply_waiting_memory(c, store.memory_room(&s).saturating_add(own))?;
            return Ok(matches!(applied, Some(osis_engine::Ingested::Applied(_))));
        }
    }
    Ok(false)
}

/// Whether an open of entry `b` left its commit pending here, or a record it carries loose: the
/// entry is kept as its carrier.
pub(crate) fn pends(engine: &mut Engine, b: &BlobId, o: &Opened) -> bool {
    match o {
        Opened::Commit(c, _) => engine.pends(c),
        Opened::Records(_) => engine.carries_loose(b),
        _ => false,
    }
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
                    engine.forget_carrier(&b);
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
        // a waiting memory commit applies only here, within its sync ID's room
        match self.woken.as_mut() {
            Some(f) => {
                for c in f.added() {
                    acted |= apply_waiting(engine, store, &c)?;
                }
            }
            None => self.woken = Some(engine.memory_woken_feed()),
        }
        let held = match self.commits.as_mut() {
            Some((f, u)) => f.added().into_iter().chain(u.added()).collect(),
            None => {
                self.commits = Some((engine.commit_feed(), engine.unpended_feed()));
                Vec::new()
            }
        };
        let mut given: Vec<BlobId> = Vec::new();
        for c in held {
            if !engine.holds_commit(&c) || engine.pends(&c) {
                continue;
            }
            given.extend(engine.commit_blobs(&c)?.iter().copied());
        }
        // a record blob whose records were all learned (spec/commits.md §4 Pending storage)
        match self.loose.as_mut() {
            Some(f) => given.extend(f.added().into_iter().filter(|b| !engine.carries_loose(b))),
            None => self.loose = Some(engine.loose_feed()),
        }
        for b in &given {
            for s in store.naming(b)? {
                if store.entry(&s, b)?.is_some_and(|e| !e.own) {
                    store.uncharge(&s, b)?;
                    acted = true;
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
        Follow { set: SyncsFollow::default(), caps, paths: Effects::new("store: paths"), creds: Effects::new("store: read secrets"), parked: BTreeMap::new(), entries: None, read: BTreeMap::new(), carriers: Carriers::default() }
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
        // entries added or gone since: parked or unparked before any read secret is looked at,
        // so a secret that came after an entry failed to open finds it parked
        match self.entries.as_mut() {
            Some(f) => {
                for (s, b) in f.added() {
                    if self.read.contains_key(&s) {
                        let e = store.entry(&s, &b)?;
                        park(engine, self.parked.entry(s).or_default(), &b, e.as_ref())?;
                    }
                }
            }
            None => self.entries = Some(store.entry_feed()),
        }
        let moved = self.set.settle(store);
        let mut acted = !moved.is_empty();
        // kept unread to read opens what is there (spec/sync-judgement.md §6 Read and unread move):
        // every entry held, once (after a restart, S's start parks what did not open, below)
        let raised: Vec<SyncId> = moved.iter().filter(|(_, was, now)| matches!(was, Some((_, Holding::Unread))) && matches!(now, Some((_, Holding::Read)))).map(|(s, _, _)| *s).collect();
        for (s, _, now) in &moved {
            if let Some(t) = self.read.remove(s) {
                self.paths.unwant(&(*s, t));
                self.creds.unwant(s);
                self.parked.remove(s);
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
        for s in raised {
            for e in store.entries(&s)? {
                if let Some(bytes) = store.bytes(&e.blob)? {
                    open_entry(engine, store, &s, &e.blob, &e.wrap, &bytes)?;
                }
            }
        }
        // S read from now on (a start, a grant): its entries that did not open are parked once
        for (s, _, now) in &moved {
            if matches!(now, Some((_, Holding::Read))) {
                let parked = self.parked.entry(*s).or_default();
                for e in store.entries(s)? {
                    park(engine, parked, &e.blob, Some(&e))?;
                }
            }
        }
        if !self.caps.due().is_empty()
            && let Some((_, c)) = self.caps.try_settle(&(), || engine.caps())?
        {
            store.set_caps(&c);
            acted = true;
        }
        for (s, t) in self.paths.due() {
            let r = self.paths.try_settle(&(s, t), || Ok::<_, osis_engine::Error>(engine.sync_ids(&t)?.iter().find(|o| o.id == s && !o.hint).map(|o| o.path.clone())))?;
            if let Some((_, Some(p))) = r {
                store.serve_path(&s, &p)?;
                charge_unvouched(engine, store, &s)?;
                acted = true;
            }
        }
        // a parked entry is opened as read secrets arrive (spec/sync-streams.md §4 Fill order;
        // S's first settle tries each once)
        for s in self.creds.due() {
            let r = self.creds.try_settle(&s, || Ok::<_, osis_engine::Error>(engine.read_credentials(&s)?.map(|c| c.read_secrets.iter().map(|(e, _)| *e).collect()).unwrap_or_default()))?;
            let Some((was, now)) = r else { continue };
            if was.is_some_and(|w| now.iter().all(|e| w.contains(e))) {
                continue;
            }
            if let Some(parked) = self.parked.get_mut(&s) {
                acted |= open_parked(engine, store, parked, &s)?;
            }
        }
        acted |= self.carriers.settle(engine, store)?;
        acted |= store.settle_at(now)?;
        Ok(acted)
    }
}

impl Follow {
    /// Tests: the entries of a read S that opened to a commit neither held nor pending here yet
    /// are not parked, by a full scan of every read S's entries (as `Engine::lost_wakes` is for
    /// the engine's parking place): empty when a new read secret, opening the parked entries
    /// alone, opens what opening every entry would. An entry that never opened to a commit is
    /// parked by the feed or S's start and unparked only by `open_parked`, as it opens to
    /// something no later read secret changes (records taken, bad bytes, a linked or inbox blob).
    pub fn lost_parks(&self, engine: &mut Engine, store: &Store) -> Result<Vec<(SyncId, BlobId)>> {
        let mut parked = self.parked.clone();
        // entries the feed has not yet given (a clone of the cursor reads on alone)
        if let Some(mut f) = self.entries.clone() {
            for (s, b) in f.added() {
                if self.read.contains_key(&s) {
                    park(engine, parked.entry(s).or_default(), &b, store.entry(&s, &b)?.as_ref())?;
                }
            }
        }
        let mut lost = Vec::new();
        for s in self.read.keys() {
            for e in store.entries(s)? {
                if engine.blob_commit(&e.blob)?.is_some() && waits(engine, &e)? && !parked.get(s).is_some_and(|p| p.contains(&e.blob)) {
                    lost.push((*s, e.blob));
                }
            }
        }
        Ok(lost)
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
            open_entry(engine, store, &s, b, &e.wrap, &bytes)?;
            opened = true;
        }
    }
    Ok(opened)
}

/// Charges S's peer entries kept as carriers (their commit pending, or a record loose) whose
/// stamp no longer vouches under S's served head to the peer that brought them
/// (`Store::charge_unvouched`): a stamp vouches only under the head, otherwise the entry is
/// charged (spec/sync-ids.md §5 Peer budget). One past its peer's budget, or whose peer went, is
/// not kept, and its pending copy goes as its blob goes unnamed (`Carriers`). At a start and each
/// move of the head: O(entries of S).
fn charge_unvouched(engine: &mut Engine, store: &mut Store, s: &SyncId) -> Result<()> {
    for e in store.entries(s)? {
        if e.own || e.stamp.is_none() {
            continue;
        }
        let carries = match engine.blob_commit(&e.blob)? {
            Some(c) => engine.pends(&c) && !engine.holds_commit(&c),
            None => engine.carries_loose(&e.blob),
        };
        if carries {
            store.charge_unvouched(s, &e.blob)?;
        }
    }
    Ok(())
}

/// Whether entry `b` of S waits for a read secret: a peer's entry whose commit is neither held
/// nor pending here (it did not open, or what it opened to was thrown out).
fn waits(engine: &mut Engine, e: &crate::types::Entry) -> Result<bool> {
    Ok(!e.own && !engine.blob_commit(&e.blob)?.is_some_and(|c| engine.holds_commit(&c) || engine.pends(&c)))
}

/// Parks entry `b` (`e`: held now) if it waits for a read secret, else unparks it (gone, or
/// taken).
fn park(engine: &mut Engine, parked: &mut BTreeSet<BlobId>, b: &BlobId, e: Option<&crate::types::Entry>) -> Result<()> {
    match e {
        Some(e) if waits(engine, e)? => parked.insert(*b),
        _ => parked.remove(b),
    };
    Ok(())
}

/// Opens S's parked entries, the only ones a read secret of S may open; one that gives something
/// held is off its peer budget (spec/sync-ids.md §5); one that opened to anything but a commit
/// thrown out is unparked.
/// Whether one opened. O(S's parked entries), never S's entries.
fn open_parked(engine: &mut Engine, store: &mut Store, parked: &mut BTreeSet<BlobId>, s: &SyncId) -> Result<bool> {
    let mut opened = false;
    osis_base::costs::count("store: parked examined", parked.len() as u64);
    for b in parked.clone() {
        let Some(e) = store.entry(s, &b)? else {
            parked.remove(&b);
            continue;
        };
        let Some(bytes) = store.bytes(&b)? else { continue };
        let o = open_entry(engine, store, s, &b, &e.wrap, &bytes)?;
        // still parked: what does not open yet, and a commit opened but thrown out
        let still = match o {
            Opened::NotOpen => true,
            Opened::Commit(..) => waits(engine, &e)?,
            _ => false,
        };
        if !still {
            parked.remove(&b);
        }
        if pends(engine, &b, &o) {
            continue;
        }
        if matches!(o, Opened::Commit(..) | Opened::Linked | Opened::Records(_)) {
            store.uncharge(s, &b)?;
            opened = true;
        }
    }
    Ok(opened)
}
