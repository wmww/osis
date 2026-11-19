//! What a sync ID carries of a commit, for readers (spec/sync-judgement.md §1-§2,
//! spec/sync-inbox.md §4): each read sync ID's body of a held commit, the facts its judgement
//! reads, this node's own commits under it, entries opened and sealed (the parts each blob holds),
//! fresh encryptions (`seal_body`, spec/crypto.md §5 Passing on), and whether a writer may promote
//! a deposit. The must-hold / may-hold / must-not-hold rule itself is `read`'s; these are its
//! inputs.

use super::{BlobOf, BodyFacts, BodyMeta, HeldBlob, Loss, Opened, PartSet, Promote, SealedSet, Strip, ThingSync, Wrap};
use crate::engine::{DropFor, Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, CommitId, Role, SyncId, Tid, WallMs};
use osis_crypto::NodeRng;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// `bp/` + commit ID + blob ID: flags (one byte: 1 a per-sync-ID copy, 2 unchecked), its prefix
/// salt (16 bytes), the count of aspects its sections list (u32) and those (u32 each), the count of
/// parts it holds (u32) and those, then the digest of each section it holds that this node did not
/// open (32 bytes each; `BlobOf`).
pub(crate) const BLOB_PARTS: &[u8] = b"bp/";

/// Loads the blob parts (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || Error::Corrupt("blob parts");
    let mut parts = Vec::new();
    tx.scan(BLOB_PARTS, |k, v| {
        let c = CommitId(k.get(..32).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let b = BlobId(k.get(32..).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let (copy, rest) = v.split_first().ok_or_else(bad)?;
        let (salt, rest) = rest.split_first_chunk::<16>().ok_or_else(bad)?;
        let (ais, rest) = indices(rest).ok_or_else(bad)?;
        let (ps, sealed) = indices(rest).ok_or_else(bad)?;
        let sealed: SealedSet = sealed.chunks(32).map(|x| x.try_into().map_err(|_| bad())).collect::<Result<_>>()?;
        parts.push((b, BlobOf { commit: c, parts: ps, sealed, copy: copy & 1 != 0, unchecked: copy & 2 != 0, salt: *salt, ais }));
        Ok(())
    })?;
    for (b, row) in parts {
        tx.core.ix.commit_blobs.insert(row.commit, b);
        tx.core.ix.blob_parts.insert(b, Arc::new(row));
    }
    Ok(())
}

/// A count (u32) of indices (u32 each) at the start of `rest`, and what follows.
fn indices(rest: &[u8]) -> Option<(PartSet, &[u8])> {
    let (n, rest) = rest.split_first_chunk::<4>()?;
    let (xs, rest) = rest.split_at_checked(u32::from_be_bytes(*n) as usize * 4)?;
    Some((xs.as_chunks::<4>().0.iter().map(|x| u32::from_be_bytes(*x) as usize).collect(), rest))
}

/// Notes blob `b` as this node opened or sealed it (`row`), in place of what an earlier opening
/// noted (opened again once more is checked, `BlobOf::unchecked`).
pub(crate) fn note_blob(tx: &mut Tx<'_>, b: &BlobId, row: BlobOf) -> Result<()> {
    match tx.core.ix.blob_parts.get(b) {
        Some(old) if **old == row => return Ok(()),
        Some(_) => unnote_blob(tx, b)?,
        None => {}
    }
    // a memory commit's rows are memory, gone with it at a restart
    let mut v = vec![u8::from(row.copy) | u8::from(row.unchecked) << 1];
    v.extend(row.salt);
    v.extend((row.ais.len() as u32).to_be_bytes());
    v.extend(row.ais.iter().flat_map(|p| (*p as u32).to_be_bytes()));
    v.extend((row.parts.len() as u32).to_be_bytes());
    v.extend(row.parts.iter().flat_map(|p| (*p as u32).to_be_bytes()));
    v.extend(row.sealed.iter().flatten());
    let c = row.commit;
    let k = [BLOB_PARTS, &c.0, &b.0].concat();
    tx.in_class(tx.is_memory_commit(&c), |tx| Ok(tx.txn.put_local(&k, &v, Shred::No)?))?;
    tx.core.ix.blob_parts.insert(*b, Arc::new(row));
    tx.core.ix.commit_blobs.insert(c, *b);
    Ok(())
}

/// Blob `b`'s row goes, from where it was noted (its commit forgotten, or the blob opened again
/// bad).
fn unnote_blob(tx: &mut Tx<'_>, b: &BlobId) -> Result<()> {
    let Some(row) = tx.core.ix.blob_parts.get(b).cloned() else { return Ok(()) };
    let c = row.commit;
    tx.core.ix.blob_parts.remove(b);
    tx.core.ix.commit_blobs.remove(&c, b);
    // from either class: a row noted while its commit was pending went durable, one noted once
    // a memory commit was held went to memory
    let k = [BLOB_PARTS, &c.0, &b.0].concat();
    for memory in [false, true] {
        tx.in_class(memory, |tx| Ok(tx.txn.remove_local(&k, Shred::No)?))?;
    }
    Ok(())
}

/// Commit `c` is forgotten (`apply::unindex_commit`, a release): its blob parts go with it, in
/// its transaction, and so do the store's own entries of its blobs under every sync ID once the
/// engine's store committed (`CipherTx::forgot`): an own entry logs a commit held here. Losing
/// access keeps the rows, so its own entries wait for it to open again.
pub(crate) fn forget(tx: &mut Tx<'_>, c: &CommitId) -> Result<()> {
    let blobs: Vec<BlobId> = tx.core.ix.commit_blobs.get(c).into_iter().flatten().copied().collect();
    let memory = tx.is_memory_commit(c);
    for b in blobs {
        unnote_blob(tx, &b)?;
        tx.blobs.forgot(&b, memory);
    }
    Ok(())
}

/// Part `ai` of `c` (meta `m`) leaves every blob of its commit (spec/sync-judgement.md §2 Per
/// blob; `Engine::blob_gone`): its body is gone here other than while invalid (no right deletes
/// that one, and its blobs are its refetch source, spec/permissions.md §6). One dropped as covered
/// only on an aspect a held setting puts under purge on replace (`Kept::purges`), while a held
/// valid snapshot of its aspect reaches it by its tables (`reachers`): a node that never held it
/// then counts it covered too, not missing (spec/commits.md §5 Covered). Elsewhere its blobs keep
/// it: a new reader joins it and judges the cover itself, as a snapshot covering the reacher may
/// name no session left without a write (spec/crdt.md §8 Absence), so tables prove nothing for
/// good. One dropped under own replaces alone goes only with its whole commit.
pub(crate) fn strips(core: &crate::engine::Core, c: &CommitId, m: &crate::engine::Meta, ai: usize) -> bool {
    match m.dropped(ai) {
        Some(d) if d.why == DropFor::Invalid => false,
        Some(d) if d.as_cover() => m.view.aspects.get(ai).is_some_and(|a| crate::retention::history::of(core, &a.tid, &a.ak).purges()) && !reachers(core, c, m, ai).is_empty(),
        _ => m.body_gone(ai),
    }
}

/// The held valid snapshots of part `ai`'s aspect whose tables reach it (`snapshot::reaches`):
/// what a node lacking the part counts it covered by. One must be shown at a source before a
/// blob stripped of it is deleted there.
pub(crate) fn reachers(core: &crate::engine::Core, c: &CommitId, m: &crate::engine::Meta, ai: usize) -> BTreeSet<CommitId> {
    let Some(a) = m.view.aspects.get(ai) else { return BTreeSet::new() };
    let carries = |s: &CommitId| core.ix.commits.get(s).is_some_and(|sm| sm.view.kind.is_compaction() && sm.aspect(&a.tid, &a.ak).is_some_and(|sai| sm.valid_at(sai) && !sm.body_gone(sai) && !sm.missing(sai)));
    core.ix.snapshots.get(&(a.tid, a.ak.clone())).into_iter().flatten().filter(|x| x.1 != *c && carries(&x.1) && crate::retention::snapshot::reaches((&x.2, &x.3), &m.header, c, a.hi)).map(|x| x.1).collect()
}

impl Engine {
    /// The things whose sync IDs may carry a body of commit `c`: those its parts are on, the
    /// sync units holding them, and for a `sync.0` or `created.0` part on a thing with a sync ID its
    /// publisher (`Engine::publisher`, spec/sync-ids.md §2): the one rule `sync_id_bodies_meta`'s
    /// walk of a sync ID follows too.
    fn body_things(&mut self, c: &CommitId) -> BTreeSet<Tid> {
        let Some(v) = self.core.ix.commits.get(c).map(|m| m.view.clone()) else { return BTreeSet::new() };
        let mut out = BTreeSet::new();
        for a in v.aspects.iter() {
            out.insert(a.tid);
            out.extend(self.units_holding(&a.tid));
            if matches!(a.ak.as_str(), "sync.0" | "created.0") {
                out.extend(self.publisher(&a.tid));
            }
        }
        out
    }

    /// Per sync ID this node reads whose required set holds a body of commit `c`: that body
    /// (spec/sync-judgement.md §1: parts, expiry, fetch order, a per-sync-ID copy or the shared
    /// blob, a lasting header alone, or a certificate copy, `certificate_bodies`). A memo
    /// (`Core::sync_bodies`): read's bodies and each judgement's held blobs ask it.
    pub fn sync_bodies(&mut self, c: &CommitId) -> Result<Arc<BTreeMap<SyncId, BodyMeta>>> {
        self.follow_bodies()?;
        osis_base::memo::Memo::get_in(self, |e| &e.core.sync_bodies, c, |e| e.sync_bodies_read(c))
    }

    /// Brings the per-entry values a body reads (`published`, `certified`) up to date before a
    /// memo of bodies is asked: a hit asks neither, and its reads of them hold only once they are
    /// (notes/engine.md, Derived values: Per-key rows).
    fn follow_bodies(&mut self) -> Result<()> {
        self.follow_read_things()?;
        self.follow_published();
        self.follow_certificates()?;
        Ok(())
    }

    /// `sync_bodies` read anew.
    fn sync_bodies_read(&mut self, c: &CommitId) -> Result<Arc<BTreeMap<SyncId, BodyMeta>>> {
        let mut out = BTreeMap::new();
        for g in self.body_things(c) {
            let ThingSync::Read(ids) = self.thing_sync_now(&g)? else { continue };
            if let Some(meta) = self.closure_body(&g, c)? {
                for s in &ids {
                    let was = out.remove(s);
                    out.insert(*s, join_body(was, meta.clone()));
                }
            }
        }
        self.certificate_bodies(c, &mut out)?;
        Ok(Arc::new(out))
    }

    /// Commit `c`'s body at read sync ID `s` (`sync_bodies`' entry for `s`), a read of that pair
    /// alone (`sync_body_now`).
    pub fn sync_body(&mut self, s: &SyncId, c: &CommitId) -> Result<Option<BodyMeta>> {
        self.sync_body_now(s, c)
    }

    /// Commit `c`'s body at read sync ID `s` (`sync_bodies`' entry for `s`), read from `s`'s
    /// thing alone: a body coming or going at another sync ID moves nothing here. A memo
    /// (`Core::sync_body`): each judgement of a body asks it from several facade calls.
    pub(crate) fn sync_body_now(&mut self, s: &SyncId, c: &CommitId) -> Result<Option<BodyMeta>> {
        self.follow_bodies()?;
        osis_base::memo::Memo::get_in(self, |e| &e.core.sync_body, &(*s, *c), |e| e.sync_body_read(s, c))
    }

    /// `sync_body_now` read anew.
    /// `s`'s body of `c` is judged for each thing reading `s` (`read_things`), their bodies
    /// joined (`join_body`).
    fn sync_body_read(&mut self, s: &SyncId, c: &CommitId) -> Result<Option<BodyMeta>> {
        let mut out: Option<BodyMeta> = None;
        for t in self.read_things_of(s)? {
            if let Some(meta) = self.body_for(&t, c)? {
                out = Some(join_body(out, meta));
            }
        }
        Ok(out)
    }

    /// Commit `c`'s body under read thing `t`'s sync IDs: its closure body, else its certificate
    /// body.
    fn body_for(&mut self, t: &Tid, c: &CommitId) -> Result<Option<BodyMeta>> {
        let closure = match self.body_things(c).contains(t) {
            true => self.closure_body(t, c)?,
            false => None,
        };
        let cert = match self.certified_of(c, t)? {
            Some(named) => self.certificate_body(c, t, &named)?,
            None => None,
        };
        Ok(match (closure, cert) {
            (Some(b), Some(x)) => Some(with_certificates(b, x)),
            (b, x) => b.or(x),
        })
    }

    /// The thing reading `s` whose body of `c` `s` carries (`body_for`), under whose keys that
    /// body is sealed, logged and promoted.
    fn body_thing(&mut self, s: &SyncId, c: &CommitId) -> Result<Option<Tid>> {
        for t in self.read_things_of(s)? {
            if self.body_for(&t, c)?.is_some() {
                return Ok(Some(t));
            }
        }
        Ok(None)
    }

    /// Commit `c`'s closure body under read thing `g`'s sync IDs, if any.
    fn closure_body(&mut self, g: &Tid, c: &CommitId) -> Result<Option<BodyMeta>> {
        let ctx = self.body_ctx(g);
        let last = self.bodies_under(&ctx, c, true)?.pop();
        Ok(last.map(|b| BodyMeta { parts: b.parts.iter().copied().collect(), expires: b.expires.map(WallMs), order: b.order, copy: b.to_sync_id, certificate: false, header_only: b.parts.is_empty(), mints: BTreeSet::new() }))
    }

    /// Adds to `out` the certificate bodies of commit `c` (spec/sync-judgement.md §1-§2,
    /// spec/permissions.md §4): per read sync ID, the held parts of it the sync ID's certificates
    /// name (`sync_certificates`) that its closure's bodies do not carry, as a copy; else, a
    /// header the certificates name, as a header-only copy. Only a commit with a part
    /// certificates are made of (an edge write, keys, a card, a record) or a request is asked, so
    /// content never reads the certificates. Where a sync ID carries a closure body of `c` too,
    /// the two are its one body there (`with_certificates`).
    fn certificate_bodies(&mut self, c: &CommitId, out: &mut BTreeMap<SyncId, BodyMeta>) -> Result<()> {
        let closure: BTreeSet<SyncId> = out.keys().copied().collect();
        for (t, named, ids) in self.certified(c)? {
            let Some(meta) = self.certificate_body(c, &t, &named)? else { continue };
            for s in ids {
                let was = out.remove(&s);
                let joined = match was {
                    Some(b) if closure.contains(&s) && !b.certificate => with_certificates(b, meta.clone()),
                    was => join_body(was, meta.clone()),
                };
                out.insert(s, joined);
            }
        }
        Ok(())
    }

    /// The certificate body of commit `c` under read thing `t`'s sync IDs, from what `t`'s
    /// certificates name of it (`certificate_bodies`).
    fn certificate_body(&mut self, c: &CommitId, t: &Tid, named: &super::certified::Named) -> Result<Option<BodyMeta>> {
        let Some(h) = self.header(c) else { return Ok(None) };
        if h.purge.is_empty() && !h.aspects.iter().any(|a| matches!(a.ak.as_str(), "roles.0" | "keys.0" | "node.0" | "reach.0" | "created.0")) {
            return Ok(None);
        }
        let id = *c;
        let parts: PartSet = match named.parts.is_empty() {
            false => {
                let held: PartSet = osis_base::memo::Memo::get_in(self, |e| &e.core.bodies, &id, |e| e.body_with(&id, false))?.map(|b| b.parts.into_iter().collect()).unwrap_or_default();
                let ctx = self.body_ctx(t);
                let carried = self.body_carried(&ctx, &h);
                named.parts.iter().copied().filter(|ai| held.contains(ai) && !carried.contains(ai)).collect()
            }
            true => PartSet::new(),
        };
        if parts.is_empty() && !named.header && named.mints.is_empty() {
            return Ok(None);
        }
        let (expires, order) = (osis_commit::blob_expiry(&h).map(WallMs), crate::sync_ids::fetch_order(&h));
        let header_only = parts.is_empty();
        // a header copy that is a request goes as one, whatever it mints
        let mints = if header_only && !named.header { named.mints.clone() } else { BTreeSet::new() };
        Ok(Some(BodyMeta { parts, expires, order, copy: true, certificate: true, header_only, mints }))
    }

    /// The things reading `s` here: those of `s`'s things (`sync_things_of`) whose
    /// `ThingSync::Read` lists it. What arrives under `s` is judged for each. Kept per sync ID
    /// from its first ask (`Core::read_things`, a `memo::Cutoff`): what it is derived from (the
    /// things naming `s`, their sync IDs and holdings) moves at every ticket, link or `sync.0`
    /// of them, its answer far less often, and every judgement at `s` reads it.
    pub(crate) fn read_things_of(&mut self, s: &SyncId) -> Result<Vec<Tid>> {
        Ok(osis_base::memo::Cutoff::get_in(self, |e| &e.core.read_things, s, |e, s| e.read_things_now(s))?.to_vec())
    }

    /// `read_things_of` derived anew.
    pub(crate) fn read_things_now(&mut self, s: &SyncId) -> Result<Arc<Vec<Tid>>> {
        let mut out = Vec::new();
        for t in self.sync_things_of(s)? {
            if matches!(self.thing_sync_now(&t)?, ThingSync::Read(ids) if ids.contains(s)) {
                out.push(t);
            }
        }
        Ok(Arc::new(out))
    }

    /// The things whose read secrets open and act for `s` here: those reading it, else those of
    /// its things whose read secrets are held. Sync keeps syncing a sync ID that left its sync
    /// set until a complete pass after it left (spec/sync-set.md §3: opening what arrives by the
    /// read secrets of S's thing it still holds), so what a reader of `s` acts with stands as
    /// long as those secrets do; a lost reader's go with its drop, which waits for that pass.
    pub(crate) fn opening_things(&mut self, s: &SyncId) -> Result<Vec<Tid>> {
        let read = self.read_things_of(s)?;
        if !read.is_empty() {
            return Ok(read);
        }
        let mut out = self.sync_things_of(s)?;
        out.retain(|t| self.core.epochs(t).is_some_and(|e| e.role(osis_base::Role::Read).holds_any()));
        Ok(out)
    }

    /// The facts the judgement of `c`'s body under `s` reads (spec/sync-judgement.md §2): whether
    /// it is in the required set and a closure body; a part of it dropped here and why; a delta
    /// before its keep-at-least bound; covered by held valid snapshots of its aspects under `s`
    /// (`None` while one stamped after it cannot be judged); a lasting header alone. What the
    /// store shows (snapshots under `s` this node does not hold, other blobs of the commit, a
    /// certificate's author's other blobs) is the judgement's to add: `sole_certificate` is false
    /// here.
    pub fn body_facts(&mut self, s: &SyncId, c: &CommitId) -> Result<BodyFacts> {
        let Some(b) = self.sync_body_now(s, c)? else { return Ok(BodyFacts { required: false, closure: false, dropped: None, invalid: false, kept: false, hosts_from: 0, covered: Some(false), sole_certificate: false, lasting_header: false }) };
        let (Some(m), Some(h)) = (self.core.ix.commits.get(c).cloned(), self.header(c)) else { return Err(Error::UnknownCommit(*c)) };
        // dropped here: no part of the body held (a part dropped beside a held one leaves the
        // body judged by what is held)
        let dropped = if b.parts.iter().all(|ai| m.dropped(*ai).is_some()) { b.parts.iter().find_map(|ai| m.dropped(*ai).map(|d| d.why)) } else { None };
        let bad = |ai: usize| m.dropped_invalid(ai) || (m.holds(ai) && !m.valid_at(ai));
        // a request holding a right over some delta is in force whatever its parts are
        // (`Engine::forgettable`): a re-grant gives it force with its parts still invalid
        let invalid = !m.view.kind.is_role() && b.parts.iter().any(|ai| bad(*ai)) && b.parts.iter().all(|ai| bad(*ai) || m.dropped(*ai).is_some_and(|d| d.why == DropFor::Cover)) && (!m.view.purges || crate::retention::purge::drops_nothing(&self.core, c, &h));
        let keeps = self.part_keeps(c)?;
        // a bound still ahead wakes the judgement when it passes
        let kept = b.parts.iter().any(|ai| keeps.get(*ai).is_some_and(|k| self.core.time.until(Some(*k)) < *k));
        // a dropped part's own bound as it dropped (`Dropped::hosts_from`), a held one's keep
        // bound plus `MAX_DRIFT` (spec/commits.md §5 Keep at least)
        let hosts_from = b.parts.iter().map(|ai| match m.dropped(*ai) {
            Some(d) => d.hosts_from,
            None => keeps.get(*ai).filter(|k| **k > 0).map_or(0, |k| k.saturating_add(osis_base::format::MAX_DRIFT_MS)),
        }).max().unwrap_or(0);
        let mut covered = Some(!b.parts.is_empty());
        for ai in &b.parts {
            // a signal's delta is never joined: never established uncovered
            if h.aspects.get(*ai).is_none_or(|a| a.ak.signal()) {
                continue;
            }
            let this = self.part_covered(c, &h, *ai)?;
            covered = match (covered, this) {
                (Some(x), Some(y)) => Some(x && y),
                _ => None,
            };
        }
        Ok(BodyFacts { required: true, closure: !b.certificate, dropped, invalid, kept, hosts_from, covered, sole_certificate: false, lasting_header: b.header_only })
    }

    /// Whether held snapshots of its aspect, or its author's own replaces, cover delta `ai` of `c`
    /// (header `h`): `None` while a snapshot stamped after it cannot be judged
    /// (spec/sync-judgement.md §2 established uncovered). A
    /// signal's delta is never joined, so never covered.
    pub(crate) fn part_covered(&mut self, c: &CommitId, h: &osis_commit::Header, ai: usize) -> Result<Option<bool>> {
        let Some(a) = h.aspects.get(ai) else { return Ok(Some(false)) };
        if a.ak.signal() {
            return Ok(Some(false));
        }
        // dropped as covered: covered while its chain of covers carries it, else it is missing
        // again (`retention::uncover`), so no join of a later snapshot is asked
        if self.core.ix.commits.get(c).and_then(|m| m.dropped(ai)).is_some_and(|d| d.as_cover()) {
            return Ok(Some(true));
        }
        // its author's own replaces cover it by the same test (spec/commits.md §5 Own replaces)
        if let Some(q) = crate::retention::snapshot::own_covers(&self.core, c, &a.tid, &a.ak).first().copied()
            && self.covered(&q, c, &a.tid, &a.ak)? == Some(true)
        {
            return Ok(Some(true));
        }
        let snaps: Vec<CommitId> = self.core.ix.snapshots.get(&(a.tid, a.ak.clone())).into_iter().flatten().map(|x| x.1).filter(|x| x != c).collect();
        let mut this = Some(false);
        for x in snaps {
            match self.covered(&x, c, &a.tid, &a.ak)? {
                Some(true) => return Ok(Some(true)),
                None if self.header(&x).is_none_or(|sh| sh.ts > h.ts) => this = None,
                _ => {}
            }
        }
        Ok(this)
    }

    /// Blob `b` as this node opened or sealed it.
    pub fn blob_of(&self, b: &BlobId) -> Option<Arc<BlobOf>> {
        self.core.ix.blob_parts.get(b).cloned()
    }

    /// Sync ID S is about to be shredded, and `blobs` are those no other sync ID's entry or
    /// tombstone names (spec/sync-set.md §3, Nothing of R stays): what this node noted of each
    /// that only S's entries own goes. A per-sync-ID copy is S's (sealed for its sync ID's thing,
    /// spec/sync-judgement.md §1), whether its commit is held or not; a blob of a commit neither
    /// held nor pending (forgotten with lost access, its entries parked for the access to return)
    /// is its entries'. A shared blob of a held commit stays the commit's, and openings under S's
    /// thing go with the thing (`sync_ids::opened::forget_thing`). Before the shred, so a crash
    /// between does both again.
    pub fn shredding(&mut self, blobs: &[BlobId]) -> Result<()> {
        let ix = &self.core.ix;
        let gone: Vec<BlobId> = blobs.iter().filter(|b| ix.blob_parts.get(b).is_some_and(|x| x.copy || !(ix.commits.contains_key(&x.commit) || ix.pending.contains_key(&x.commit)))).copied().collect();
        if gone.is_empty() {
            return Ok(());
        }
        self.run(|tx| {
            for b in &gone {
                unnote_blob(tx, b)?;
            }
            Ok(())
        })
    }

    /// No entry names blob `b` any more (the store's `unnamed_feed`): what this node noted of it
    /// goes where its commit is neither held nor pending (forgotten with lost access, its notes
    /// kept for its entries alone: spec/sync-set.md §3, Nothing of R stays). A held or pending
    /// commit's blob stays the commit's.
    pub fn unnamed_blob(&mut self, b: &BlobId) -> Result<()> {
        let ix = &self.core.ix;
        if !ix.blob_parts.get(b).is_some_and(|x| !(ix.commits.contains_key(&x.commit) || ix.pending.contains_key(&x.commit))) {
            return Ok(());
        }
        let b = *b;
        self.run(|tx| unnote_blob(tx, &b))
    }

    /// The parts blob `b` holds of its commit, as this node opened or sealed it.
    pub fn blob_parts(&self, b: &BlobId) -> Option<PartSet> {
        self.core.ix.blob_parts.get(b).map(|x| x.parts.clone())
    }

    /// Whether held blob `b` carries a part of its commit that strips (`strips`: its body gone
    /// here, purged, past its bounds, destroyed, or dropped as covered under purge on replace by a snapshot reaching it;
    /// spec/sync-judgement.md §2 per blob: must-not-hold, whatever sync ID it is under). `false`
    /// for a blob not opened or sealed here.
    pub fn blob_gone(&self, b: &BlobId) -> bool {
        let Some(x) = self.core.ix.blob_parts.get(b) else { return false };
        let Some(m) = self.core.ix.commits.get(&x.commit) else { return false };
        x.parts.iter().any(|ai| strips(&self.core, &x.commit, m, *ai))
    }

    /// Held blob `b` as a strip leaves it (`blob_gone`), to be deleted at a peer once each part
    /// of it held here has another blob of the commit there as its carrier
    /// (spec/sync-compaction.md §1 Carriers), and each part it strips as covered a snapshot
    /// reaching it there, `MAX_DRIFT` past its keep bound. `None` unless it is gone here.
    pub fn strip_of(&self, b: &BlobId) -> Option<Strip> {
        let x = self.core.ix.blob_parts.get(b)?;
        let m = self.core.ix.commits.get(&x.commit)?;
        if !self.blob_gone(b) {
            return None;
        }
        let live = x.parts.iter().copied().filter(|ai| m.holds(*ai) && !m.body_gone(*ai)).collect();
        let mut covers = Vec::new();
        let mut from = 0;
        for (ai, d) in x.parts.iter().filter_map(|ai| Some((*ai, m.dropped(*ai)?))).filter(|(_, d)| d.as_cover()) {
            let r = reachers(&self.core, &x.commit, m, ai);
            if !r.is_empty() {
                covers.push(r);
                from = from.max(d.hosts_from);
            }
        }
        Some(Strip { live, covers, from })
    }

    /// How held blob `b` of a commit loses to held blob `o` of it under `s` (spec/sync-judgement.md
    /// §2 Per blob), neither stripping (`blob_gone`), `o` of `b`'s kind and carrying every part of
    /// `b` this node holds; `stands`: whether each may stand as the body's log (an entry holding
    /// the body, no deposit awaiting promotion). `Needed`: `o` also carries each part of `b` and
    /// each section of `b` this node did not open (over what it checked, spec/sync-compaction.md
    /// §1 Duplicates) and a part only a blob carries (`blob_only`) that `b` lacks: `b` is
    /// must-not-hold, deleted at a source showing `o`. `Spare`: `o` may stand and lacks a section
    /// of `b` this node did not open, or carries the same sections under a lower blob ID (readers
    /// logging one rewrite at once), or under any where `b` may not stand: `b` leaves the own log
    /// and is no blob logged verbatim, never deleted at a peer for it.
    pub fn blob_loses(&mut self, s: &SyncId, b: &BlobId, o: &BlobId, stands: (bool, bool)) -> Result<Option<Loss>> {
        let (Some(x), Some(y)) = (self.core.ix.blob_parts.get(b).cloned(), self.core.ix.blob_parts.get(o).cloned()) else { return Ok(None) };
        if o == b || y.commit != x.commit || !y.of_kind(x.copy) || self.blob_gone(b) || self.blob_gone(o) {
            return Ok(None);
        }
        let c = x.commit;
        let Some(m) = self.core.ix.commits.get(&c) else { return Ok(None) };
        if x.parts.iter().any(|ai| m.holds(*ai) && !strips(&self.core, &c, m, *ai) && !y.parts.contains(ai)) {
            return Ok(None);
        }
        // a blob of the other kind holds no body here (a certificate copy beside the shared blob
        // carries parts S's readers cannot open there, whatever this node opens of it)
        let body_kind = self.sync_body_now(s, &c)?.is_some_and(|meta| x.of_kind(meta.copy));
        if body_kind && x.parts.is_subset(&y.parts) && y.parts.len() > x.parts.len() && x.sealed.is_subset(&y.sealed) && let Some(only) = self.blob_only(s, &c)? && y.parts.difference(&x.parts).any(|ai| only.contains(ai)) {
            return Ok(Some(Loss::Needed));
        }
        let same = y.parts == x.parts && y.sealed == x.sealed && y.ais == x.ais;
        Ok((stands.1 && (!x.sealed.is_subset(&y.sealed) || (same && (!stands.0 || o < b)))).then_some(Loss::Spare))
    }

    /// Whether held blob `b` loses to another of `others` (`blob_loses`, each taken to stand).
    fn loses_among(&mut self, s: &SyncId, b: &BlobId, others: &[BlobId]) -> Result<bool> {
        for o in others {
            if self.blob_loses(s, b, o, (true, true))?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether blob `b`, as opened or sealed here, is a per-sync-ID copy.
    pub(crate) fn blob_copy_now(&self, b: &BlobId) -> Option<bool> {
        self.core.ix.blob_parts.get(b).map(|x| x.copy)
    }

    /// `c`'s body under `s` as a fresh encryption, with its wrap for `s` (spec/sync-judgement.md
    /// §1, §4: logging again, a non-writer's deposit, a body with no held encryption): the one
    /// place sync encrypts a body (spec/crypto.md §5 Passing on). A per-sync-ID copy is one
    /// section under its blob key (`seal_to`); else `Engine::seal` with every section of every
    /// held genuine blob of `c` (`held`: shared blobs opened or sealed here, never a copy's), so
    /// what this node may not encrypt under an epoch of its choosing goes as it came. The wrap is
    /// `wrap_secret`'s for the parts the blob carries. `None`: nothing may be made now (a part
    /// the body needs, or its header, this node read only under an epoch not established here).
    /// A held blob not tombstoned under `s` is the store's to log verbatim (`rewrap`).
    pub fn seal_body(&mut self, s: &SyncId, c: &CommitId, held: &[HeldBlob], rng: &mut dyn NodeRng) -> Result<Option<(crate::sync_ids::Sealed, Wrap)>> {
        let Some(t) = self.body_thing(s, c)? else { return Ok(None) };
        // what a strip leaves of the body: its parts whose bodies are not gone here
        let meta = self.sync_body_now(s, c)?.map(|mut m| {
            if let Some(cm) = self.core.ix.commits.get(c) {
                m.parts.retain(|ai| !strips(&self.core, c, cm, *ai));
            }
            m
        });
        if let Some(meta) = meta.as_ref().filter(|m| m.certificate) {
            return self.seal_certificate(&t, c, meta, rng);
        }
        let ctx = self.body_ctx(&t);
        let Some(b) = self.commit_bodies_under(&ctx, c)?.into_iter().next() else { return Ok(None) };
        // certificates joined into the closure body (`with_certificates`): one copy of both
        if let Some(meta) = meta.as_ref().filter(|m| m.copy && m.parts.iter().any(|p| !b.parts.contains(p))) {
            return self.seal_certificate(&t, c, meta, rng);
        }
        let class = match self.core.ix.commits.get(c).is_some_and(|m| m.view.memory) {
            true => osis_blob::Class::Ephemeral,
            false => osis_blob::Class::Durable,
        };
        let (sealed, unopened) = match b.to_sync_id {
            true => (self.seal_to(&b, class, rng)?, SealedSet::new()),
            false => {
                let (sections, unopened) = self.held_sections(c, held);
                (self.seal(&b, class, &sections, rng)?, unopened)
            }
        };
        let Some(sealed) = sealed else { return Ok(None) };
        if b.parts.iter().any(|p| !sealed.parts.contains(p)) {
            return Ok(None);
        }
        let Some(w) = self.wrap_secret(&t, Some((c, &sealed.parts)))? else { return Ok(None) };
        let wrap = osis_crypto::wrap(&w, &sealed.id, &sealed.key, b.order)?;
        // a section copied verbatim that this node never opened counts by its bytes, whatever of
        // its parts it holds from another blob (spec/sync-compaction.md §1 Only what the node checked)
        let mut row = BlobOf { commit: *c, parts: sealed.parts.iter().copied().collect(), sealed: sealed.unopened.clone(), copy: b.to_sync_id, unchecked: false, salt: sealed.salt, ais: sealed.ais.iter().copied().collect() };
        if !unopened.is_empty() {
            let env = osis_commit::Envelope::decode(&osis_blob::open(&sealed.blob, &sealed.key)?.1)?;
            for sec in env.sections.iter().filter(|sec| unopened.contains(&sec.digest())) {
                row.sealed.insert(sec.digest());
                row.parts.retain(|ai| !sec.ais.contains(ai));
            }
        }
        let bid = sealed.id;
        self.run(|tx| note_blob(tx, &bid, row))?;
        Ok(Some((sealed, wrap)))
    }

    /// Whether this node may log `c`'s body under `s` now (spec/sync-judgement.md §2 Loggable;
    /// what read's must-hold reads, so a judgement moves when it does), as the sync store's log
    /// would: a held blob of `c` passed on verbatim under a wrap for `s` (`rewrap`), else a
    /// fresh encryption (`seal_body`): a copy or certificate of parts all held, or each
    /// part of the body sealed here (`section_secret`) or carried by a held genuine section; in
    /// each case wrapped for `s` as `wrap_secret` says for the parts the blob carries. Only the
    /// blobs of `held` (bytes in the sync store) count as passed on or carried.
    pub fn may_log(&mut self, s: &SyncId, c: &CommitId, held_blobs: &[BlobId]) -> Result<bool> {
        let Some(t) = self.body_thing(s, c)? else { return Ok(false) };
        let Some(meta) = self.sync_body_now(s, c)? else { return Ok(false) };
        let Some(h) = self.header(c) else { return Ok(false) };
        let held: BTreeSet<usize> = match self.core.ix.commits.get(c) {
            Some(m) => m.hold.iter().enumerate().filter(|(_, x)| matches!(x, crate::engine::Hold::Body { .. })).map(|(ai, _)| ai).collect(),
            None => return Ok(false),
        };
        // the body's parts whose bodies are not gone here: a strip logs the rest
        let body: Vec<usize> = match self.core.ix.commits.get(c) {
            Some(m) => meta.parts.iter().copied().filter(|ai| !strips(&self.core, c, m, *ai)).collect(),
            None => return Ok(false),
        };
        // verbatim: a held genuine blob (a certificate copy of exactly the body's parts for a
        // certificate), never for a per-sync-ID copy's body
        let mut carried = BTreeSet::new();
        for b in held_blobs {
            let Some(row) = self.core.ix.blob_parts.get(b).filter(|x| x.commit == *c).cloned() else { continue };
            if self.blob_gone(b) || self.loses_among(s, b, held_blobs)? {
                continue;
            }
            if !row.copy {
                carried.extend(row.parts.iter().copied().filter(|ai| held.contains(ai)));
            }
            let fits = (meta.certificate && row.copy && row.parts == meta.parts) || (!row.copy && !meta.copy);
            let parts: Vec<usize> = row.parts.iter().copied().collect();
            if fits && self.wrap_secret(&t, Some((c, &parts)))?.is_some() {
                return Ok(true);
            }
        }
        // a fresh encryption
        let ctx = self.body_ctx(&t);
        let copy = meta.certificate || meta.copy || self.commit_bodies_under(&ctx, c)?.first().is_some_and(|b| b.to_sync_id);
        let sealed: Vec<usize> = match copy || body.is_empty() {
            // one section of the body's parts under its blob key; a header alone, none
            true => body.clone(),
            // per section (thing, role-class or not), sealed here or carried as held
            false => {
                let mut of_thing: BTreeMap<Tid, Vec<usize>> = BTreeMap::new();
                let mut sections: BTreeMap<(Tid, bool), Vec<usize>> = BTreeMap::new();
                for ai in &held {
                    let Some(a) = h.aspects.get(*ai) else { continue };
                    of_thing.entry(a.tid).or_default().push(*ai);
                    sections.entry((a.tid, osis_keys::under_roles(a.ak.as_str()))).or_default().push(*ai);
                }
                let mut sealed = carried;
                for ((tid, _), parts) in &sections {
                    if parts.iter().all(|ai| sealed.contains(ai)) {
                        continue;
                    }
                    let all = of_thing.get(tid).cloned().unwrap_or_default();
                    if self.section_secret(c, &h, tid, &all, parts).is_some() {
                        sealed.extend(parts.iter().copied());
                    }
                }
                sealed.into_iter().collect()
            }
        };
        if body.iter().any(|ai| !held.contains(ai) || !sealed.contains(ai)) {
            return Ok(false);
        }
        Ok(self.wrap_secret(&t, Some((c, &sealed)))?.is_some())
    }

    /// The sections of commit `c`'s held genuine blobs among `held` (each opened by its entry's
    /// wrap under a read secret of its sync ID's thing): shared blobs of `c` opened or sealed
    /// here, never a copy (a section under its blob key is never copied into another encryption,
    /// spec/sync-judgement.md §1). Opened or not; one per aspect set, those this node opened
    /// first (a forger's section it could not open never stands in for a genuine one it did),
    /// then largest first, none sharing an aspect with one taken (a commit's sections never
    /// overlap). A section it did not open goes only where every shared blob of `c` it opened,
    /// its bytes held or not, lists its aspects:
    /// one a strip left out was left out by a node that opened it, and of the blobs of a commit
    /// the one with fewer sections wins (spec/sync-judgement.md §2), so rewrites stripping
    /// different parts this node cannot open meet in one blob. With the digests of those taken
    /// that it did not open (`BlobOf::sealed`).
    fn held_sections(&mut self, c: &CommitId, held: &[HeldBlob]) -> (Vec<osis_commit::Section>, SealedSet) {
        let mut all = Vec::new();
        let mut opened = SealedSet::new();
        for h in held {
            let b = osis_blob::blob_id(&h.bytes);
            let Some(row) = self.core.ix.blob_parts.get(&b).filter(|x| x.commit == *c && !x.copy).cloned() else { continue };
            let Ok(things) = self.read_things_of(&h.sync_id) else { continue };
            let Some((_, key)) = things.iter().find_map(|t| osis_blob::unwrap_any(self.read_secrets(t).iter(), &b, &h.wrap)) else { continue };
            let Ok((_, pt)) = osis_blob::open(&h.bytes, &key) else { continue };
            let Ok(env) = osis_commit::Envelope::decode(&pt) else { continue };
            if env.id() != *c {
                continue;
            }
            for sec in env.sections.into_iter().filter(|sec| osis_crypto::unwrap_section(&key, c, &sec.wrap).is_err()) {
                let d = sec.digest();
                if !row.sealed.contains(&d) {
                    opened.insert(d);
                }
                all.push((d, sec));
            }
        }
        // every shared blob of it this node opened lists its sections, its bytes held or not (one
        // that left as stripped still shows what a strip left out)
        let listed: Vec<PartSet> = self.core.ix.commit_blobs.get(c).into_iter().flatten().filter_map(|b| self.core.ix.blob_parts.get(b)).filter(|x| !x.copy).map(|x| x.ais.clone()).collect();
        all.retain(|(d, sec)| opened.contains(d) || listed.iter().all(|ais| sec.ais.iter().all(|ai| ais.contains(ai))));
        all.sort_by_key(|(d, sec)| (!opened.contains(d), std::cmp::Reverse(sec.ais.len())));
        let mut seen = BTreeSet::new();
        all.retain(|(_, sec)| sec.ais.iter().all(|ai| !seen.contains(ai)) && {
            seen.extend(sec.ais.iter().copied());
            true
        });
        let unopened = all.iter().map(|(d, _)| *d).filter(|d| !opened.contains(d)).collect();
        (all.into_iter().map(|(_, sec)| sec).collect(), unopened)
    }

    /// Certificate body `meta` of commit `c` under a sync ID of thing `t`, sealed (spec/sync-
    /// judgement.md §1 Certificate blobs): its parts in one section under the blob key (none: a
    /// header-only copy), wrapped as `wrap_secret` says for those parts (spec/crypto.md §5).
    fn seal_certificate(&mut self, t: &Tid, c: &CommitId, meta: &BodyMeta, rng: &mut dyn NodeRng) -> Result<Option<(crate::sync_ids::Sealed, Wrap)>> {
        let Some(m) = self.core.ix.commits.get(c).cloned() else { return Ok(None) };
        let parts: Vec<usize> = meta.parts.iter().copied().collect();
        let b = crate::sync_ids::Body { commit: *c, parts: parts.clone(), expires: meta.expires.map(|e| e.0), blind: m.header.blind, plaintext: Vec::new(), role_commit: m.header.kind.is_role(), order: meta.order, to_sync_id: true };
        let class = if m.view.memory { osis_blob::Class::Ephemeral } else { osis_blob::Class::Durable };
        let Some(sealed) = self.seal_to(&b, class, rng)? else { return Ok(None) };
        if parts.iter().any(|p| !sealed.parts.contains(p)) {
            return Ok(None);
        }
        let Some(w) = self.wrap_secret(t, Some((c, &parts)))? else { return Ok(None) };
        let wrap = osis_crypto::wrap(&w, &sealed.id, &sealed.key, meta.order)?;
        let row = BlobOf { commit: *c, parts: meta.parts.clone(), sealed: SealedSet::new(), copy: true, unchecked: false, salt: sealed.salt, ais: sealed.ais.iter().copied().collect() };
        let bid = sealed.id;
        self.run(|tx| note_blob(tx, &bid, row))?;
        Ok(Some((sealed, wrap)))
    }

    /// A wrap for `to` of held blob `b` of commit `c`, whose entry under `from` has wrap
    /// `from_wrap` (spec/sync-judgement.md §3 Own store: a held blob logged verbatim under a wrap
    /// for S): the blob key and order from that wrap, wrapped as `wrap_secret` says for the parts
    /// `b` carries (spec/crypto.md §5 Passing on). `None` when either wrap's epoch is not held, when
    /// `b` is not a shared blob opened or sealed here, or when `to`'s body of `c` is no shared
    /// blob's: a per-sync-ID copy is never shared with another sync ID, and only a copy holds a
    /// copy's body (spec/sync-judgement.md §1 Per-sync-ID copies). A certificate copy of exactly
    /// the parts `to`'s certificate body names is the one blob wrapped under each sync ID needing
    /// them, wrapped as `wrap_secret` says for those parts (§1 Certificate blobs).
    pub fn rewrap(&mut self, c: &CommitId, b: &BlobId, from: &SyncId, from_wrap: &Wrap, to: &SyncId) -> Result<Option<Wrap>> {
        // a certificate copy of the same parts is one blob wrapped under each sync ID needing
        // them (spec/sync-judgement.md §1 Certificate blobs); a per-sync-ID copy never is shared,
        // even as a certificate of the same parts elsewhere: `from` holds `b` as a certificate too
        let Some(meta) = self.sync_body_now(to, c)? else { return Ok(None) };
        let from_certificate = self.sync_body_now(from, c)?.is_some_and(|m| m.certificate && m.parts == meta.parts);
        let certificate = meta.certificate && from_certificate && self.blob_copy_now(b) == Some(true) && self.blob_parts(b).as_ref() == Some(&meta.parts);
        if !certificate && (self.blob_copy_now(b) != Some(false) || meta.copy) {
            return Ok(None);
        }
        let Some(tt) = self.body_thing(to, c)? else { return Ok(None) };
        let from_things = self.read_things_of(from)?;
        let Some((key, order)) = from_things.iter().find_map(|t| self.read_secrets(t).iter().find_map(|x| osis_crypto::unwrap_order(x, b, from_wrap).ok())) else { return Ok(None) };
        let parts: Vec<usize> = self.blob_parts(b).map(|p| p.into_iter().collect()).unwrap_or_default();
        let Some(w) = self.wrap_secret(&tt, Some((c, &parts)))? else { return Ok(None) };
        Ok(Some(osis_crypto::wrap(&w, b, &key, order)?))
    }

    /// Opens entry `blob` (`bytes`, its `wrap`) logged under `s` and takes what it holds
    /// (spec/sync-ids.md §5, spec/sync-inbox.md §2): a sealed fire under an inbox of this node's;
    /// a commit blob whose wrap opens under a held read secret of `s`'s thing, opened
    /// (`open_commit`, each section's opening kept) and ingested, the epoch its wrap opened under
    /// kept as an opening of its header (`note_unwrapped`); a chunk, tree node or page a held commit is
    /// waiting for, stored.
    /// A blob opening bad is no blob of its commit here, whatever an earlier opening noted (one
    /// opened again once its parts can be checked, `BlobOf::unchecked`).
    pub fn open_entry(&mut self, s: &SyncId, blob: &BlobId, wrap: &Wrap, bytes: &[u8], room: u64) -> Result<Opened> {
        let o = self.open_entry_once(s, blob, wrap, bytes, room)?;
        if matches!(o, Opened::Bad) && self.core.ix.blob_parts.contains_key(blob) {
            self.run(|tx| unnote_blob(tx, blob))?;
        }
        Ok(o)
    }

    fn open_entry_once(&mut self, s: &SyncId, blob: &BlobId, wrap: &Wrap, bytes: &[u8], room: u64) -> Result<Opened> {
        if osis_blob::blob_id(bytes) != *blob {
            return Ok(Opened::Bad);
        }
        let wants = self.blob_wants()?;
        if wants.missing.contains(blob) {
            self.put_blobs(vec![(*blob, bytes.to_vec())])?;
            return Ok(Opened::Linked);
        }
        // judged for each of `s`'s things: the one whose held read secret opens the wrap
        let things = self.opening_things(s)?;
        let Some((t, key)) = things.iter().find_map(|t| osis_blob::unwrap_any(self.read_secrets(t).iter(), blob, wrap).map(|(_, k)| (*t, k))) else {
            // a wrap no held secret opens: a sealed fire's filler, opened by the read KEM key
            // (spec/sync-inbox.md §4 A sealed fire) of whichever thing it is sealed to
            for t in &things {
                match self.open_sealed_fire(t, blob, bytes)? {
                    Opened::NotOpen => {}
                    o => return Ok(o),
                }
            }
            return Ok(Opened::NotOpen);
        };
        let opened = match self.open_commit(bytes, &key) {
            Ok(o) => o,
            Err(e) if osis_base::Classified::class(&e) == osis_base::ErrorClass::Local => return Err(e),
            Err(_) => {
                // a record blob (spec/wire.md §3): its records taken; a list blob (§4): its
                // thing lists
                // thing lists, each kept as a certificate blob of the own store under `s`
                // (`certblobs`): one any node logged counts as this node's own
                // its prefix a certificate blob's (`CertBlob::of`), else bad input
                let Ok((_, pt)) = osis_blob::open(bytes, &key) else { return Ok(Opened::Bad) };
                if super::certblobs::CertBlob::of(bytes, &key, BTreeSet::new()).is_none() {
                    return Ok(Opened::Bad);
                }
                if let Some(tids) = self.take_record_blob(blob, &pt)? {
                    let Some(c) = super::certblobs::CertBlob::of(bytes, &key, tids.clone()) else { return Ok(Opened::Bad) };
                    self.note_cert_blob(s, None, blob, c)?;
                    return Ok(Opened::Records(tids));
                }
                return Ok(match self.take_list_blob(blob, &pt)? {
                    Some(r) => {
                        // lists kept loose count once their rotation holds them (opened again)
                        if !self.carries_loose(blob) {
                            let things = osis_commit::thing_list::decode_list_blob(&pt).unwrap_or_default().iter().map(|c| c.list.thing).collect();
                            let Some(c) = super::certblobs::CertBlob::of(bytes, &key, things) else { return Ok(Opened::Bad) };
                            self.note_cert_blob(s, Some(r), blob, c)?;
                        }
                        Opened::Lists(r)
                    }
                    None => Opened::Bad,
                });
            }
        };
        let id = opened.commit.id();
        // spec/permissions.md §3 (Lost access): a copy carrying content of a thing the independent of S's thing
        // may not read now (left by a revocation since it was placed) gives nothing: none of it is
        // taken (its parts come from a body under their own thing's sync ID)
        if opened.copy && !self.copy_stale(&t, &opened.commit).is_empty() {
            return Ok(Opened::NotOpen);
        }
        // the epoch the wrap opened under: whoever unwraps an entry reads the header
        // (`sync_ids::opened::header_passes`)
        if let Some((e, _)) = self.read_epochs(&t, &[]).into_iter().find(|(_, x)| osis_crypto::unwrap(x, blob, wrap).is_ok()) {
            self.note_unwrapped(&id, &t, &e);
            // a copy's content came under that epoch alone (its section opens under the blob
            // key): an opening of each of its parts under that epoch of S's thing, which counts
            // for a wrap under an epoch of S's thing (`sync_ids::opened::opened_under_wrap`) and
            // never as one of the part's thing
            if opened.copy && opened.commit.header.is_resolved() {
                self.note_opened(&opened.commit.header, &[(t, e, opened.commit.parts.iter().collect())]);
            }
        }
        // the records minted in sections of things not held here, taken alone
        // (spec/sync-judgement.md §1 Sealed sections): a held strong may bring the thing in
        if !opened.records.is_empty() {
            self.learn_records(opened.records.clone())?;
        }
        let parts: PartSet = opened.parts().into_iter().collect();
        // an ephemeral commit is held in memory, within the room S's cap leaves
        // (spec/sync-compaction.md §2 Holding, Caps); a relay-only one is never an entry
        let ingested = match opened.commit.header.ephemeral {
            None => self.ingest(&opened.plaintext, Vec::new()),
            Some(osis_commit::EphClass::Plain) => self.ingest_memory(&opened.plaintext, room),
            Some(osis_commit::EphClass::Relay) => return Ok(Opened::Bad),
        };
        let ingested = match ingested {
            Ok(i) => i,
            Err(e) if osis_base::Classified::class(&e) == osis_base::ErrorClass::Local => return Err(e),
            Err(_) => return Ok(Opened::Bad),
        };
        // a part that does not hash to its header entry is no part of the commit (spec/commits.md
        // §4): the blob is no encryption of it, whatever the engine took of it (a forged copy of
        // a held commit is a duplicate to apply), so no reader keeps, serves or stamps it. A
        // part whose thing's record is not held is unchecked: counted by its section's bytes
        // until the commit stops pending, when the blob opens again (`BlobOf::unchecked`)
        let h = self.header(&id);
        let mut unchecked = BTreeSet::new();
        for p in &opened.commit.parts {
            let Some(a) = h.as_ref().and_then(|h| h.aspects.get(p.ai)) else {
                unchecked.insert(p.ai);
                continue;
            };
            match self.core.created(&a.tid) {
                None => {
                    unchecked.insert(p.ai);
                }
                Some(r) if osis_crypto::delta_hash(&osis_crypto::dedup_secret(r.nonce()), &p.delta) != a.hash => return Ok(Opened::Bad),
                Some(_) => {}
            }
        }
        // a section not opened, or holding a part not checked, counts by its bytes alone
        // (spec/sync-compaction.md §1 Duplicates)
        let mut sealed: SealedSet = opened.sealed.iter().map(|s| s.digest()).collect();
        let mut parts = parts;
        for sec in opened.sections.iter().filter(|sec| !opened.sealed.contains(sec) && sec.ais.iter().any(|ai| unchecked.contains(ai))) {
            sealed.insert(sec.digest());
            parts.retain(|ai| !sec.ais.contains(ai));
        }
        // a blob opened before its header lists resolve here checked no commitment of its prefix
        // and opened no section (spec/commits.md §4): it opens again, checked, once they do
        let row = BlobOf { commit: id, parts, sealed, copy: opened.copy, unchecked: !unchecked.is_empty() || h.is_none(), salt: opened.salt, ais: opened.ais.iter().copied().collect() };
        let b = *blob;
        self.run(|tx| note_blob(tx, &b, row))?;
        Ok(Opened::Commit(id, ingested))
    }

    /// Whether a writer may promote deposited commit `c` under `s` (spec/sync-inbox.md §4): only
    /// once it holds `c` applied, with a body `s` must hold, and its author held write on `s`'s
    /// actor at `c`'s `ts` (as this node judges it), or it fires an open signal; then with the author's chain for those parts
    /// to log beside it (`NotYet` while that chain is not complete here). `Never` when `s` carries
    /// nothing of `c` or its author lacked write then.
    pub fn promotable(&mut self, s: &SyncId, c: &CommitId) -> Result<Promote> {
        let Some(t) = self.body_thing(s, c)? else { return Ok(Promote::Never) };
        if !self.core.ix.commits.contains_key(c) || self.core.ix.pending.contains_key(c) {
            return Ok(Promote::NotYet);
        }
        let ctx = self.body_ctx(&t);
        let Some(b) = self.commit_bodies_under(&ctx, c)?.into_iter().next() else { return Ok(Promote::Never) };
        let Some(h) = self.header(c) else { return Ok(Promote::NotYet) };
        let actor = self.core.reader_of(&t);
        // a fire of an open signal is promoted whatever its author's role (spec/sync-inbox.md §4)
        let open = b.parts.iter().all(|ai| h.aspects.get(*ai).is_some_and(|a| a.ak.open()));
        if !open && crate::engine::write::role_of(&self.core, &h.author, &actor, h.ts) < Some(Role::Write) || !self.judged_valid(c, &b.parts) {
            return Ok(Promote::Never);
        }
        let parts: crate::sync_ids::Parts = b.parts.iter().copied().collect();
        Ok(match self.author_chain(c, &parts) {
            Some(chain) => Promote::Yes { chain },
            None => Promote::NotYet,
        })
    }
}

/// Two bodies of one commit under one sync ID, from different things reading it, as one: a
/// closure body over a certificate (where a sync ID carries a closure body of a commit, that is
/// its one body there), else their parts and minted records together, the later expiry, the
/// earlier fetch order. The same whatever order they come in.
/// Closure body `b` of a commit with certificate body `x` of it under the same sync ID: one
/// body (spec/sync-judgement.md §1 One blob per commit). Parts the certificates name beyond the
/// closure's are of things outside the sync unit (an account's `keys.0` in the commit making its
/// profile), whose sections its readers cannot open: the body is then a per-sync-ID copy of both
/// (§1 Per-sync-ID copies), its readers opening every part under the blob key.
fn with_certificates(b: BodyMeta, x: BodyMeta) -> BodyMeta {
    if x.parts.is_subset(&b.parts) {
        return b;
    }
    BodyMeta { parts: b.parts.union(&x.parts).copied().collect(), copy: true, header_only: false, ..b }
}

fn join_body(a: Option<BodyMeta>, b: BodyMeta) -> BodyMeta {
    let Some(a) = a else { return b };
    if a == b {
        return a;
    }
    match (a.certificate, b.certificate) {
        (true, false) => return b,
        (false, true) => return a,
        _ => {}
    }
    let expires = match (a.expires, b.expires) {
        (Some(x), Some(y)) => Some(x.max(y)),
        _ => None,
    };
    BodyMeta {
        parts: a.parts.union(&b.parts).copied().collect(),
        expires,
        order: a.order.min(b.order),
        copy: a.copy || b.copy,
        certificate: a.certificate,
        header_only: a.header_only && b.header_only,
        mints: a.mints.union(&b.mints).copied().collect(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    
    
    
    

}
