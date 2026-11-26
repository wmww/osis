//! What the store follows (notes/sync-store.md): the sync IDs this node syncs
//! (`SyncsFollow`), the engine's caps, and the served path of each sync ID read here (its thing's
//! `sync.0` record, spec/sync-ids.md §5), each an `Effects` value, so a step costs what moved;
//! the entries that did not open, parked under the read secrets that may open them (`Parked`);
//! and the entries carrying a commit that pends here (`Carriers`).

use super::Store;
use crate::set::SyncsFollow;
use crate::types::{Holding, Result};
use osis_base::memo::{Effects, Feed, Removals};
use osis_base::{BlobId, CommitId, SyncId, Tid, WallMs};
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
    /// Per awaited value, the read secrets it names, current or not, and whether they open its
    /// sections whole: what opens a parked entry.
    creds: Effects<Awaits, Keys>,
    /// The entries of the sync IDs read here that wait for a read secret, each parked under what
    /// it awaits (notes/sync.md Arriving early) and opened again only as that moves. Found by the
    /// store's entry feed and at S's start.
    parked: Parked,
    entries: Option<Feed<(SyncId, BlobId)>>,
    /// What `awaits` reads of an entry moving with no entry of the store moving: its commit
    /// held or pending no more, or its blob noted no more (`awaits`: a commit neither held nor
    /// pending, or a peer entry of a blob naming no commit, waits for S).
    unheld: Option<Unheld>,
    /// The sync IDs pulled anew (`Store::anew_feed`): a pull anew fetches what is not held, so
    /// what is held and parked opens again here (spec/sync-judgement.md §3 Dropped bodies: it
    /// opens again each entry its store still holds).
    anew: Option<Feed<SyncId>>,
    read: BTreeMap<SyncId, BTreeSet<Tid>>,
    carriers: Carriers,
}

/// The engine's cursors over what `awaits` reads (`Follow::unheld`).
#[derive(Clone)]
struct Unheld {
    commits: Removals<CommitId>,
    pending: Removals<CommitId>,
    blobs: Removals<BlobId>,
}

impl Unheld {
    fn new(engine: &Engine) -> Unheld {
        Unheld { commits: engine.unheld_feed(), pending: engine.unpending_feed(), blobs: engine.unnoted_feed() }
    }

    /// The blobs whose entries are judged again: those of each commit held or pending no more
    /// (forgotten with lost access, its blobs still noted), and each blob noted no more (its
    /// commit forgotten whole: a peer entry of it stays under a read S, and waits for S).
    fn moved(&mut self, engine: &mut Engine) -> Result<BTreeSet<BlobId>> {
        let mut out: BTreeSet<BlobId> = self.blobs.removed().into_iter().collect();
        for c in self.commits.removed().into_iter().chain(self.pending.removed()) {
            out.extend(engine.commit_blobs(&c)?.iter().copied());
        }
        Ok(out)
    }
}

/// What an awaited value opens with: its read secrets, and whether they open whole (a thing's
/// sections open whole only while this node holds it, `Engine::section_keys`; S's entries
/// while one of S's things is held whole, `Engine::held_whole`).
type Keys = (bool, Vec<osis_crypto::Secret32>);

/// A read secret an entry waits for: one of S's (`Engine::opening_secrets`: its wrap opened
/// to nothing held or pending here), or one of a thing's (`Engine::section_keys`: a section of
/// its held commit's blob holding a missing part on that thing did not open, for want of a
/// secret or because this node does not hold the thing, spec/sync-judgement.md §1 Sealed
/// sections).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Awaits {
    Sync(SyncId),
    Thing(Tid),
}

/// The parked entries by what they await, and what each awaits. `Sync(S)` is followed while S
/// is read; `Thing(t)` while an entry awaits it.
#[derive(Clone, Default)]
struct Parked {
    under: BTreeMap<Awaits, BTreeSet<(SyncId, BlobId)>>,
    of: BTreeMap<(SyncId, BlobId), BTreeSet<Awaits>>,
}

impl Parked {
    /// Parks entry `b` of S under `now`, unparked from whatever else it awaited.
    fn set(&mut self, creds: &mut Effects<Awaits, Keys>, s: SyncId, b: BlobId, now: BTreeSet<Awaits>) {
        let was = match now.is_empty() {
            true => self.of.remove(&(s, b)).unwrap_or_default(),
            false => self.of.insert((s, b), now.clone()).unwrap_or_default(),
        };
        for a in was.difference(&now) {
            if let Some(xs) = self.under.get_mut(a) {
                xs.remove(&(s, b));
                if xs.is_empty() {
                    self.under.remove(a);
                    if matches!(a, Awaits::Thing(_)) {
                        creds.unwant(a);
                    }
                }
            }
        }
        for a in now.difference(&was) {
            self.under.entry(*a).or_default().insert((s, b));
            if matches!(a, Awaits::Thing(_)) {
                creds.want(*a);
            }
        }
    }

    /// Every entry of S unparked (S read no more).
    fn forget(&mut self, creds: &mut Effects<Awaits, Keys>, s: SyncId) {
        let lo = (s, BlobId([0; 32]));
        let keys: Vec<(SyncId, BlobId)> = self.of.range(lo..).take_while(|(k, _)| k.0 == s).map(|(k, _)| *k).collect();
        for (s, b) in keys {
            self.set(creds, s, b, BTreeSet::new());
        }
    }
}

/// The entries carrying a commit that pends here (spec/commits.md §4 Pending storage): the
/// engine keeps its pending copy only while an entry of it is in the store, an unstamped one
/// charged to the peer that brought it (spec/sync-ids.md §5 Peer budget), so what one peer makes
/// pend is bounded by its own budget. A blob no entry names any more lets its commit's pending
/// entry carrier go once no blob of it is named (`release`); a commit held here and pending no more (an
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

/// Blob `b`'s bytes held here: made again by the engine where it keeps the blob's seal
/// (`Engine::regenerate`, notes/slim-design.md B), else as the store keeps them. The one way sync
/// reads a blob's bytes.
pub fn blob_bytes(engine: &mut Engine, store: &Store, b: &BlobId) -> Result<Option<Vec<u8>>> {
    if let Some(v) = engine.regenerate(b)? {
        return Ok(Some(v));
    }
    store.kept_bytes(b)
}

/// `Engine::open_entry` of entry `b` of read S, an ephemeral commit within the room S's memory
/// cap leaves (`Store::memory_room`); one held, its entry here counts at what it costs held. The
/// one way sync opens an entry.
pub(crate) fn open_entry(engine: &mut Engine, store: &Store, s: &SyncId, b: &BlobId, wrap: &crate::types::Wrap, bytes: &[u8]) -> Result<Opened> {
    let o = engine.open_entry(s, b, wrap, bytes, store.memory_room(s)?)?;
    if let Opened::Commit(c, _) = &o
        && engine.holds_memory(c)
    {
        store.set_memory_charge(b, engine.memory_charge(c)?)?;
    }
    Ok(o)
}

/// `open_entry` of held entry `b` of S opened again: one opening bad now (a blob opened before
/// its header lists resolved, its prefix then refused; a part checked once its record came) is no
/// blob of its commit and is not kept (spec/commits.md §4; spec/sync-judgement.md §3 Own store),
/// as a pulled one opening bad never is: it leaves the store with no tombstone.
fn open_held(engine: &mut Engine, store: &mut Store, s: &SyncId, b: &BlobId, wrap: &crate::types::Wrap, bytes: &[u8]) -> Result<Opened> {
    let o = open_entry(engine, store, s, b, wrap, bytes)?;
    if matches!(o, Opened::Bad) {
        store.unlog_entry(s, b)?;
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
            let own = store.counted(&s, b)?;
            let applied = engine.apply_waiting_memory(c, store.memory_room(&s)?.saturating_add(own))?;
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

/// Commit `c`'s entry carrier goes when no entry in the store names a blob of it (spec/commits.md
/// §4 Pending storage: kept only while something carries it; `Engine::release_entry`, whose
/// other carriers, fires and reports, the engine follows itself).
pub(crate) fn release(engine: &mut Engine, store: &Store, c: &CommitId) -> Result<()> {
    if !engine.pends(c) {
        return Ok(());
    }
    for b in engine.commit_blobs(c)?.iter() {
        if store.named(b)? {
            return Ok(());
        }
    }
    engine.release_entry(c)?;
    Ok(())
}

impl Carriers {
    fn settle(&mut self, engine: &mut Engine, store: &mut Store) -> Result<bool> {
        let mut acted = false;
        match self.unnamed.as_mut() {
            Some(f) => {
                for b in f.added() {
                    engine.forget_carrier(&b);
                    if !store.named(&b)? {
                        engine.unnamed_blob(&b, !store.tombstoned_under(&b)?.is_empty())?;
                        engine.unnamed_copy(&b)?;
                    }
                    if let Some(c) = engine.blob_commit(&b) {
                        release(engine, store, &c)?;
                    }
                }
            }
            None => {
                self.unnamed = Some(store.unnamed_feed());
                // a sync copy or notice row whose entry went before a crash let the engine follow
                for b in engine.copy_blobs() {
                    if !store.named(&b)? {
                        engine.unnamed_copy(&b)?;
                    }
                }
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
        Follow { set: SyncsFollow::default(), caps, paths: Effects::new("store: paths"), creds: Effects::new("store: read secrets"), parked: Parked::default(), entries: None, unheld: None, anew: None, read: BTreeMap::new(), carriers: Carriers::default() }
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
                    park_read(engine, store, &self.read, &mut self.parked, &mut self.creds, s, b)?;
                }
            }
            None => self.entries = Some(store.entry_feed()),
        }
        // a commit forgotten (lost access) leaves its own entries waiting for it to open again,
        // one forgotten whole its peer entries; a blob of it no entry names keeps no note
        // (`Engine::unnamed_blob`)
        match self.unheld.as_mut() {
            Some(u) => {
                for b in u.moved(engine)? {
                    let naming = store.naming(&b)?;
                    if naming.is_empty() {
                        engine.unnamed_blob(&b, !store.tombstoned_under(&b)?.is_empty())?;
                    }
                    for s in naming {
                        park_read(engine, store, &self.read, &mut self.parked, &mut self.creds, s, b)?;
                    }
                }
            }
            None => self.unheld = Some(Unheld::new(engine)),
        }
        let moved = self.set.settle(store);
        let mut acted = !moved.is_empty();
        for (s, _, now) in &moved {
            if let Some(ts) = self.read.remove(s) {
                for t in ts {
                    self.paths.unwant(&(*s, t));
                }
                self.creds.unwant(&Awaits::Sync(*s));
                self.parked.forget(&mut self.creds, *s);
                // read no more: its complete passes and record blobs go with it (a pass of it
                // again when read again)
                if !now.as_ref().is_some_and(|(_, h)| h.opens()) {
                    engine.forget_read(s)?;
                }
            }
            if let Some((ts, _)) = now.as_ref().filter(|(_, h)| h.opens()) {
                self.read.insert(*s, ts.clone());
                for t in ts {
                    self.paths.want((*s, *t));
                }
                self.creds.want(Awaits::Sync(*s));
            }
        }
        // S read from now on (a start, a grant, raised from kept unread): its entries that did not
        // open are parked once, and its read secrets' first settle opens them (spec/sync-judgement.md
        // §6 Read and unread move: raised to read opens what is held)
        for (s, _, now) in &moved {
            if now.as_ref().is_some_and(|(_, h)| h.opens()) {
                for e in store.entries(s)? {
                    park(engine, &mut self.parked, &mut self.creds, *s, e.blob, Some(&e));
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
        match self.anew.as_mut() {
            Some(f) => {
                for s in f.added() {
                    if self.read.contains_key(&s) {
                        acted |= open_parked_of(engine, store, &mut self.parked, &mut self.creds, s)?;
                    }
                }
            }
            None => {
                let (f, r) = store.anew_feed();
                r?;
                self.anew = Some(f);
            }
        }
        // a parked entry is opened as read secrets arrive (spec/sync-streams.md §4 Fill order;
        // S's first settle tries each once; a thing's, once it names a secret)
        // an entry of S whose commit is neither held nor pending, thrown out while S's things
        // were not held whole (spec/commits.md §4 Outside the node closure: before their
        // keysets arrive), opens again as one comes to be: no pull brings a blob held
        let read = &self.read;
        for a in self.creds.due() {
            let r = self.creds.try_settle(&a, || match a {
                Awaits::Sync(s) => engine.opening_secrets(&s).map(|v| (read.get(&s).is_some_and(|ts| ts.iter().any(|t| engine.held_whole(t))), v)),
                Awaits::Thing(t) => Ok(engine.section_keys(&t)),
            })?;
            let Some((was, now)) = r else { continue };
            let was = match (was, a) {
                (None, Awaits::Thing(_)) => Some((false, Vec::new())),
                (w, _) => w,
            };
            // opened again by a secret it did not have, or as its thing comes to be held
            let (whole, keys) = &now;
            if was.is_some_and(|(ww, w)| (ww || !whole || keys.is_empty()) && keys.iter().all(|e| w.contains(e))) {
                continue;
            }
            acted |= open_parked(engine, store, &mut self.parked, &mut self.creds, &a)?;
        }
        // a blob a waiting commit came to want that the store holds already (taken unopened
        // before any walk named it: a chunk fetched ahead of the node above it) is handed over,
        // as one arriving wanted is (`Engine::open_entry`); what the walk wants next comes at
        // the next settle
        let mut wanted = Vec::new();
        for b in engine.take_wanted() {
            if let Some(bytes) = blob_bytes(engine, store, &b)? {
                wanted.push((b, bytes));
            }
        }
        if !wanted.is_empty() {
            engine.put_blobs(wanted)?;
            acted = true;
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
    /// something no later read secret changes (records taken, bad bytes, a linked blob).
    pub fn lost_parks(&self, engine: &mut Engine, store: &Store) -> Result<Vec<(SyncId, BlobId)>> {
        let mut parked = self.parked.clone();
        let mut creds = self.creds.clone();
        // entries the feed has not yet given (a clone of the cursor reads on alone)
        if let Some(mut f) = self.entries.clone() {
            for (s, b) in f.added() {
                park_read(engine, store, &self.read, &mut parked, &mut creds, s, b)?;
            }
        }
        if let Some(mut u) = self.unheld.clone() {
            for b in u.moved(engine)? {
                for s in store.naming(&b)? {
                    park_read(engine, store, &self.read, &mut parked, &mut creds, s, b)?;
                }
            }
        }
        let mut lost = Vec::new();
        for s in self.read.keys() {
            for e in store.entries(s)? {
                if engine.blob_commit(&e.blob).is_none() {
                    continue;
                }
                let a = awaits(engine, s, &e);
                if !a.is_empty() && parked.of.get(&(*s, e.blob)).is_none_or(|p| !a.is_subset(p)) {
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
        let Some(bytes) = blob_bytes(engine, store, b)? else { continue };
        for s in store.naming(b)? {
            let Some(e) = store.entry(&s, b)? else { continue };
            open_held(engine, store, &s, b, &e.wrap, &bytes)?;
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
        let carries = match engine.blob_commit(&e.blob) {
            Some(c) => engine.pends(&c) && !engine.holds_commit(&c),
            None => engine.carries_loose(&e.blob),
        };
        if carries {
            store.charge_unvouched(s, &e.blob)?;
        }
    }
    Ok(())
}

/// What entry `e` of S waits for: S's read secrets when its commit is neither held nor pending
/// here (it did not open, what it opened to was thrown out, or, an own log, the commit was
/// forgotten with lost access and opens again when access returns); the read secrets of each
/// thing a section of its blob did not open on, held from another blob or not (one held may be
/// dropped later with no move of the entry: `Engine::blob_awaits_secrets`; a sibling's account rotation, its seed under a D epoch
/// established only once the rotation's header and list count; a commit held from a certificate
/// copy, the rest of which opens once its thing's secrets arrive). An own entry naming no commit
/// (a certificate blob sealed here from what is held) waits for nothing.
fn awaits(engine: &mut Engine, s: &SyncId, e: &crate::types::Entry) -> BTreeSet<Awaits> {
    match engine.blob_commit(&e.blob) {
        Some(c) => {
            let mut a: BTreeSet<Awaits> = engine.blob_awaits_secrets(&e.blob).into_iter().map(Awaits::Thing).collect();
            if !engine.holds_commit(&c) && !engine.pends(&c) {
                a.insert(Awaits::Sync(*s));
            }
            a
        }
        None if !e.own => BTreeSet::from([Awaits::Sync(*s)]),
        None => BTreeSet::new(),
    }
}

/// Parks entry `b` of S (`e`: held now) under what it waits for, else unparks it (gone, or
/// taken).
fn park(engine: &mut Engine, parked: &mut Parked, creds: &mut Effects<Awaits, Keys>, s: SyncId, b: BlobId, e: Option<&crate::types::Entry>) {
    let now = match e {
        Some(e) => awaits(engine, &s, e),
        None => BTreeSet::new(),
    };
    parked.set(creds, s, b, now);
}

/// `park` of entry `b` of S as the store holds it, where S is read.
fn park_read(engine: &mut Engine, store: &Store, read: &BTreeMap<SyncId, BTreeSet<Tid>>, parked: &mut Parked, creds: &mut Effects<Awaits, Keys>, s: SyncId, b: BlobId) -> Result<()> {
    if read.contains_key(&s) {
        park(engine, parked, creds, s, b, store.entry(&s, &b)?.as_ref());
    }
    Ok(())
}

/// Opens the entries parked under `a`, the only ones its read secrets may open; one that gives
/// something held is off its peer budget (spec/sync-ids.md §5); each is parked again under what
/// it still waits for. Whether one opened. O(the entries parked under `a`), never S's entries.
fn open_parked(engine: &mut Engine, store: &mut Store, parked: &mut Parked, creds: &mut Effects<Awaits, Keys>, a: &Awaits) -> Result<bool> {
    let xs: Vec<(SyncId, BlobId)> = parked.under.get(a).map(|x| x.iter().copied().collect()).unwrap_or_default();
    open_these(engine, store, parked, creds, xs)
}

/// Opens again every parked entry of S, whatever it awaits (S pulled anew, spec/sync-judgement.md
/// §3 Dropped bodies: a strong newly reaching a thing whose record is not held, so a held blob's
/// section of it may give the record now, §1 Sealed sections).
fn open_parked_of(engine: &mut Engine, store: &mut Store, parked: &mut Parked, creds: &mut Effects<Awaits, Keys>, s: SyncId) -> Result<bool> {
    let lo = (s, BlobId([0; 32]));
    let xs: Vec<(SyncId, BlobId)> = parked.of.range(lo..).take_while(|(k, _)| k.0 == s).map(|(k, _)| *k).collect();
    open_these(engine, store, parked, creds, xs)
}

fn open_these(engine: &mut Engine, store: &mut Store, parked: &mut Parked, creds: &mut Effects<Awaits, Keys>, xs: Vec<(SyncId, BlobId)>) -> Result<bool> {
    let mut opened = false;
    osis_base::costs::count("store: parked examined", xs.len() as u64);
    for (s, b) in xs {
        let Some(e) = store.entry(&s, &b)? else {
            parked.set(creds, s, b, BTreeSet::new());
            continue;
        };
        let Some(bytes) = blob_bytes(engine, store, &b)? else { continue };
        let o = open_held(engine, store, &s, &b, &e.wrap, &bytes)?;
        // still parked: what does not open yet, and a commit opened but thrown out or with a
        // section still sealed on a part it lacks
        let still = match o {
            Opened::NotOpen => parked.of.get(&(s, b)).cloned().unwrap_or_default(),
            Opened::Commit(..) => awaits(engine, &s, &e),
            _ => BTreeSet::new(),
        };
        parked.set(creds, s, b, still);
        if pends(engine, &b, &o) {
            continue;
        }
        // a sync copy stays charged unless stamped (`streams::opening`)
        if matches!(o, Opened::Commit(..) | Opened::Linked | Opened::Records(_)) {
            store.uncharge(&s, &b)?;
            opened = true;
        }
    }
    Ok(opened)
}
