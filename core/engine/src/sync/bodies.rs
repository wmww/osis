//! What a sync ID carries of a commit, for readers (spec/sync-judgement.md §1-§2,
//! spec/sync-inbox.md §4): each read sync ID's body of a held commit, the facts its judgement
//! reads, this node's own commits under it, entries opened and sealed (the parts each blob holds),
//! fresh encryptions (`seal_body`, spec/crypto.md §5 Passing on), and whether a writer may promote
//! a deposit. The must-hold / may-hold / must-not-hold rule itself is `read`'s; these are its
//! inputs.

use super::{BlobOf, BodyFacts, BodyMeta, HeldBlob, Opened, PartSet, Promote, SealedSet, ThingSync, Wrap};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, CommitId, Role, SyncId, Tid, WallMs};
use osis_crypto::NodeRng;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// `bp/` + commit ID + blob ID: flags (one byte: 1 a per-sync-ID copy, 2 unchecked), the count of parts it holds (u32), those parts (u32 each), then the digest of
/// each section it holds that this node did not open (32 bytes each; `BlobOf`).
pub(crate) const BLOB_PARTS: &[u8] = b"bp/";

/// Loads the blob parts (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || Error::Corrupt("blob parts");
    let mut parts = Vec::new();
    tx.scan(BLOB_PARTS, |k, v| {
        let c = CommitId(k.get(..32).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let b = BlobId(k.get(32..).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let (copy, rest) = v.split_first().ok_or_else(bad)?;
        let (n, rest) = rest.split_first_chunk::<4>().ok_or_else(bad)?;
        let (ps, sealed) = rest.split_at_checked(u32::from_be_bytes(*n) as usize * 4).ok_or_else(bad)?;
        let ps: PartSet = ps.chunks(4).map(|x| x.try_into().map(u32::from_be_bytes).map(|n| n as usize).map_err(|_| bad())).collect::<Result<_>>()?;
        let sealed: SealedSet = sealed.chunks(32).map(|x| x.try_into().map_err(|_| bad())).collect::<Result<_>>()?;
        parts.push((b, BlobOf { commit: c, parts: ps, sealed, copy: copy & 1 != 0, unchecked: copy & 2 != 0 }));
        Ok(())
    })?;
    for (b, row) in parts {
        tx.core.ix.commit_blobs.insert(row.commit, b);
        tx.core.ix.blob_parts.insert(b, Arc::new(row));
    }
    Ok(())
}

/// Notes blob `b` as this node opened or sealed it (`row`), in place of what an earlier opening
/// noted (opened again once more is checked, `BlobOf::unchecked`).
pub(super) fn note_blob(tx: &mut Tx<'_>, b: &BlobId, row: BlobOf) -> Result<()> {
    match tx.core.ix.blob_parts.get(b) {
        Some(old) if **old == row => return Ok(()),
        Some(_) => unnote_blob(tx, b)?,
        None => {}
    }
    // a memory commit's rows are memory, gone with it at a restart
    let mut v = vec![u8::from(row.copy) | u8::from(row.unchecked) << 1];
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

/// Commit `c` is forgotten (`apply::unindex_commit`): its blob parts go with it, in its
/// transaction.
pub(crate) fn forget(tx: &mut Tx<'_>, c: &CommitId) -> Result<()> {
    let blobs: Vec<BlobId> = tx.core.ix.commit_blobs.get(c).into_iter().flatten().copied().collect();
    for b in blobs {
        unnote_blob(tx, &b)?;
    }
    Ok(())
}

impl Engine {
    /// The things whose sync IDs may carry a body of commit `c`: those its parts are on, the
    /// groups enclosing them, and for a `sync.0` or `created.0` part on a labeled thing its
    /// publisher (`Engine::publisher`, spec/sync-ids.md §2): the one rule `label_bodies_meta`'s
    /// walk of a label follows too.
    fn body_things(&mut self, c: &CommitId) -> Result<BTreeSet<Tid>> {
        let Some(v) = self.core.ix.commits.get(c).map(|m| m.view.clone()) else { return Ok(BTreeSet::new()) };
        let mut out = BTreeSet::new();
        for a in v.aspects.iter() {
            out.insert(a.tid);
            out.extend(self.enclosing(&a.tid));
            if matches!(a.ak.as_str(), "sync.0" | "created.0") {
                out.extend(self.publisher(&a.tid));
            }
        }
        Ok(out)
    }

    /// Per sync ID this node reads whose required set holds a body of commit `c`: that body
    /// (spec/sync-judgement.md §1: parts, expiry, fetch order, a per-sync-ID copy or the shared
    /// blob, a lasting header alone, or a certificate copy, `certificate_bodies`).
    pub(crate) fn sync_bodies_now(&mut self, c: &CommitId) -> Result<Arc<BTreeMap<SyncId, BodyMeta>>> {
        let mut out = BTreeMap::new();
        for g in self.body_things(c)? {
            let ThingSync::Read(ids) = self.thing_sync_now(&g)? else { continue };
            if let Some(meta) = self.closure_body(&g, c)? {
                for s in &ids {
                    out.insert(*s, meta.clone());
                }
            }
        }
        self.certificate_bodies(c, &mut out)?;
        Ok(Arc::new(out))
    }

    /// Commit `c`'s body at read sync ID `s` (`sync_bodies`' entry for `s`), read from `s`'s
    /// thing alone: a body coming or going at another sync ID moves nothing here.
    pub(crate) fn sync_body_now(&mut self, s: &SyncId, c: &CommitId) -> Result<Option<BodyMeta>> {
        let Some(t) = self.read_thing(s)? else { return Ok(None) };
        if self.body_things(c)?.contains(&t)
            && let Some(meta) = self.closure_body(&t, c)?
        {
            return Ok(Some(meta));
        }
        let Some(named) = self.certified_of(c, &t)? else { return Ok(None) };
        self.certificate_body(c, &t, &named)
    }

    /// Commit `c`'s closure body under read thing `g`'s sync IDs, if any.
    fn closure_body(&mut self, g: &Tid, c: &CommitId) -> Result<Option<BodyMeta>> {
        let ctx = self.body_ctx(g);
        let last = self.bodies_under(&ctx, c, true)?.pop();
        Ok(last.map(|b| BodyMeta { parts: b.parts.iter().copied().collect(), expires: b.expires.map(WallMs), order: b.order, copy: b.to_label, certificate: false, header_only: b.parts.is_empty(), mints: BTreeSet::new() }))
    }

    /// Adds to `out` the certificate bodies of commit `c` (spec/sync-judgement.md §1-§2,
    /// spec/permissions.md §4): per read sync ID carrying no closure body of `c`, the held parts
    /// of it the sync ID's certificates name (`sync_certificates`) that its closure's bodies do
    /// not carry, as a copy; else, a header the certificates name, as a header-only copy. Only a
    /// commit with a part certificates are made of (an edge write, keys, a card, a record) or a
    /// request is asked, so content never reads the certificates. Where a sync ID carries a
    /// closure body of `c`, that body is its one body there (`certificate_reading`).
    fn certificate_bodies(&mut self, c: &CommitId, out: &mut BTreeMap<SyncId, BodyMeta>) -> Result<()> {
        let closure: BTreeSet<SyncId> = out.keys().copied().collect();
        for (t, named, ids) in self.certified(c)? {
            let ids: Vec<SyncId> = ids.into_iter().filter(|s| !closure.contains(s)).collect();
            if ids.is_empty() {
                continue;
            }
            let Some(meta) = self.certificate_body(c, &t, &named)? else { continue };
            for s in ids {
                out.insert(s, meta.clone());
            }
        }
        Ok(())
    }

    /// The certificate body of commit `c` under read thing `t`'s sync IDs, from what `t`'s
    /// certificates name of it (`certificate_bodies`).
    fn certificate_body(&mut self, c: &CommitId, t: &Tid, named: &super::certified::Named) -> Result<Option<BodyMeta>> {
        let Some(h) = self.header(c) else { return Ok(None) };
        if !h.has_request() && !h.aspects.iter().any(|a| matches!(a.ak.as_str(), "roles.0" | "keys.0" | "node.0" | "reach.0" | "created.0")) {
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
        let (expires, order) = (osis_commit::blob_expiry(&h).map(WallMs), crate::labeling::fetch_order(&h));
        let header_only = parts.is_empty();
        // a header copy that is a request goes as one, whatever it mints
        let mints = if header_only && !named.header { named.mints.clone() } else { BTreeSet::new() };
        Ok(Some(BodyMeta { parts, expires, order, copy: true, certificate: true, header_only, mints }))
    }

    /// The thing whose read sync ID `s` is here (`ThingSync::Read`).
    pub(crate) fn read_thing(&mut self, s: &SyncId) -> Result<Option<Tid>> {
        let Some(t) = self.sync_owner_of(s)? else { return Ok(None) };
        Ok(matches!(self.thing_sync_now(&t)?, ThingSync::Read(ids) if ids.contains(s)).then_some(t))
    }

    /// The thing whose read secrets open and act for `s` here: the one reading it, else its owner
    /// while a read secret of it is held. Sync keeps syncing a sync ID that left its sync set
    /// until a complete pass after it left (spec/sync-set.md §3: opening what arrives by the read
    /// secrets of S's thing it still holds), so what a reader of `s` acts with stands as long
    /// as those secrets do; a lost reader's go with its drop, which waits for that pass.
    pub(crate) fn opening_thing(&mut self, s: &SyncId) -> Result<Option<Tid>> {
        if let Some(t) = self.read_thing(s)? {
            return Ok(Some(t));
        }
        let Some(t) = self.sync_owner_of(s)? else { return Ok(None) };
        Ok(self.core.epochs(&t).is_some_and(|e| e.role(osis_base::Role::Read).holds_any()).then_some(t))
    }

    /// The facts the judgement of `c`'s body under `s` reads (spec/sync-judgement.md §2): whether
    /// it is in the required set and a closure body; a part of it dropped here and why; a delta
    /// before its keep-at-least bound; covered by held valid snapshots of its aspects under `s`
    /// (`None` while one stamped after it cannot be judged); a lasting header alone. What the
    /// store shows (snapshots under `s` this node does not hold, other blobs of the commit, a
    /// certificate's author's other blobs) is the judgement's to add: `sole_certificate` is false
    /// here.
    pub(crate) fn body_facts_now(&mut self, s: &SyncId, c: &CommitId) -> Result<BodyFacts> {
        let Some(b) = self.sync_body_now(s, c)? else { return Ok(BodyFacts { required: false, closure: false, dropped: None, kept: false, hosts_from: 0, covered: Some(false), sole_certificate: false, lasting_header: false }) };
        let (Some(m), Some(h)) = (self.core.ix.commits.get(c).cloned(), self.header(c)) else { return Err(Error::UnknownCommit(*c)) };
        // dropped here: no part of the body held (a part dropped beside a held one leaves the
        // body judged by what is held)
        let dropped = if b.parts.iter().all(|ai| m.dropped(*ai).is_some()) { b.parts.iter().find_map(|ai| m.dropped(*ai).map(|d| d.why)) } else { None };
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
        Ok(BodyFacts { required: true, closure: !b.certificate, dropped, kept, hosts_from, covered, sole_certificate: false, lasting_header: b.header_only })
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

    /// This node's commits (written here) and the own self-removals sync waits on
    /// (`waiting_removals`, a sibling's among them) with a body under `s` (spec/sync-status.md
    /// §2): O(things on `s`'s closure + its account's and node's commits on them + removals
    /// waiting).
    pub(crate) fn own_commits_now(&mut self, s: &SyncId) -> Result<Arc<BTreeSet<CommitId>>> {
        let Some(t) = self.read_thing(s)? else { return Ok(Arc::new(BTreeSet::new())) };
        let closure = self.closure(&t);
        let authors: Vec<Tid> = self.core.me().into_iter().chain([self.core.id.tid()]).collect();
        let ix = &self.core.ix;
        let mut own = BTreeSet::new();
        for x in closure.iter() {
            for a in &authors {
                own.extend(ix.by_thing.get(&(*x, *a)).into_iter().flatten().filter(|c| ix.commits.get(*c).is_some_and(|m| m.origin == crate::events::Origin::Local)));
            }
        }
        own.extend(ix.held_wait.iter());
        let ctx = self.body_ctx(&t);
        let mut out = BTreeSet::new();
        for c in own {
            if !self.commit_bodies_under(&ctx, &c)?.is_empty() {
                out.insert(c);
            }
        }
        Ok(Arc::new(out))
    }

    /// Blob `b` as this node opened or sealed it.
    pub(crate) fn blob_of_now(&self, b: &BlobId) -> Option<Arc<BlobOf>> {
        self.core.ix.blob_parts.get(b).cloned()
    }

    /// The parts blob `b` holds of its commit, as this node opened or sealed it.
    pub(crate) fn blob_parts_now(&self, b: &BlobId) -> Option<PartSet> {
        self.core.ix.blob_parts.get(b).map(|x| x.parts.clone())
    }

    /// Whether held blob `b` holds a part of its commit this node dropped for good (spec/sync-
    /// judgement.md §1: a delta it holds that the node dropped makes the blob must-not-hold,
    /// whatever sync ID it is under): purged, past its bounds, expired, destroyed. A part dropped
    /// as covered (it leaves by the carriers rule, spec/sync-compaction.md §1) or while invalid
    /// (no right deletes it) does not count. `false` for a blob not opened or sealed here.
    pub(crate) fn blob_dropped_now(&self, b: &BlobId) -> bool {
        let Some(x) = self.core.ix.blob_parts.get(b) else { return false };
        let Some(m) = self.core.ix.commits.get(&x.commit) else { return false };
        x.parts.iter().any(|ai| m.dropped(*ai).is_some_and(|d| matches!(d.why, crate::engine::DropFor::Other | crate::engine::DropFor::Destroyed)))
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
    pub(crate) fn seal_body_now(&mut self, s: &SyncId, c: &CommitId, held: &[HeldBlob], rng: &mut dyn NodeRng) -> Result<Option<(crate::labeling::Sealed, Wrap)>> {
        let Some(t) = self.read_thing(s)? else { return Ok(None) };
        if let Some(meta) = self.sync_body_now(s, c)?.filter(|m| m.certificate) {
            return self.seal_certificate(&t, c, &meta, rng);
        }
        let ctx = self.body_ctx(&t);
        let Some(b) = self.commit_bodies_under(&ctx, c)?.into_iter().next() else { return Ok(None) };
        let class = match self.core.ix.commits.get(c).is_some_and(|m| m.view.memory) {
            true => osis_label::Class::Ephemeral,
            false => osis_label::Class::Durable,
        };
        let (sealed, unopened) = match b.to_label {
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
        let mut row = BlobOf { commit: *c, parts: sealed.parts.iter().copied().collect(), sealed: sealed.unopened.clone(), copy: b.to_label, unchecked: false };
        if !unopened.is_empty() {
            let env = osis_commit::Envelope::decode(&osis_label::open(&sealed.blob, &sealed.key)?.1)?;
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
    /// would: a held blob of `c` passed on verbatim under a wrap for `s` (`rewrap_now`), else a
    /// fresh encryption (`seal_body_now`): a copy or certificate of parts all held, or each
    /// part of the body sealed here (`section_secret`) or carried by a held genuine section; in
    /// each case wrapped for `s` as `wrap_secret` says for the parts the blob carries. Only the
    /// blobs of `held` (bytes in the sync store) count as passed on or carried.
    pub(crate) fn may_log_now(&mut self, s: &SyncId, c: &CommitId, held_blobs: &[BlobId]) -> Result<bool> {
        let Some(t) = self.read_thing(s)? else { return Ok(false) };
        let Some(meta) = self.sync_body_now(s, c)? else { return Ok(false) };
        let Some(h) = self.header(c) else { return Ok(false) };
        let held: BTreeSet<usize> = match self.core.ix.commits.get(c) {
            Some(m) => m.hold.iter().enumerate().filter(|(_, x)| matches!(x, crate::engine::Hold::Body { .. })).map(|(ai, _)| ai).collect(),
            None => return Ok(false),
        };
        let body: Vec<usize> = meta.parts.iter().copied().collect();
        // verbatim: a held genuine blob (a certificate copy of exactly the body's parts for a
        // certificate), never for a per-sync-ID copy's body
        let mut carried = BTreeSet::new();
        for b in held_blobs {
            let Some(row) = self.core.ix.blob_parts.get(b).filter(|x| x.commit == *c).cloned() else { continue };
            if self.blob_dropped_now(b) {
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
        let copy = meta.certificate || self.commit_bodies_under(&ctx, c)?.first().is_some_and(|b| b.to_label);
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
    /// overlap). With the digests of those taken that it did not open (`BlobOf::sealed`).
    fn held_sections(&mut self, c: &CommitId, held: &[HeldBlob]) -> (Vec<osis_commit::Section>, SealedSet) {
        let mut all = Vec::new();
        let mut opened = SealedSet::new();
        for h in held {
            let b = osis_label::blob_id(&h.bytes);
            let Some(row) = self.core.ix.blob_parts.get(&b).filter(|x| x.commit == *c && !x.copy).cloned() else { continue };
            let Ok(Some(t)) = self.read_thing(&h.sync_id) else { continue };
            let Some((_, key)) = osis_label::unwrap_any(self.read_secrets(&t).iter(), &b, &h.wrap) else { continue };
            let Ok((_, pt)) = osis_label::open(&h.bytes, &key) else { continue };
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
    fn seal_certificate(&mut self, t: &Tid, c: &CommitId, meta: &BodyMeta, rng: &mut dyn NodeRng) -> Result<Option<(crate::labeling::Sealed, Wrap)>> {
        let Some(m) = self.core.ix.commits.get(c).cloned() else { return Ok(None) };
        let parts: Vec<usize> = meta.parts.iter().copied().collect();
        let b = crate::labeling::Body { commit: *c, parts: parts.clone(), expires: meta.expires.map(|e| e.0), blind: m.header.blind, plaintext: Vec::new(), role_commit: m.header.kind.is_role(), order: meta.order, to_label: true };
        let class = if m.view.memory { osis_label::Class::Ephemeral } else { osis_label::Class::Durable };
        let Some(sealed) = self.seal_to(&b, class, rng)? else { return Ok(None) };
        if parts.iter().any(|p| !sealed.parts.contains(p)) {
            return Ok(None);
        }
        let Some(w) = self.wrap_secret(t, Some((c, &parts)))? else { return Ok(None) };
        let wrap = osis_crypto::wrap(&w, &sealed.id, &sealed.key, meta.order)?;
        let row = BlobOf { commit: *c, parts: meta.parts.clone(), sealed: SealedSet::new(), copy: true, unchecked: false };
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
    pub(crate) fn rewrap_now(&mut self, c: &CommitId, b: &BlobId, from: &SyncId, from_wrap: &Wrap, to: &SyncId) -> Result<Option<Wrap>> {
        // a certificate copy of the same parts is one blob wrapped under each sync ID needing
        // them (spec/sync-judgement.md §1 Certificate blobs); a per-sync-ID copy never is shared,
        // even as a certificate of the same parts elsewhere: `from` holds `b` as a certificate too
        let Some(meta) = self.sync_body_now(to, c)? else { return Ok(None) };
        let from_certificate = self.sync_body_now(from, c)?.is_some_and(|m| m.certificate && m.parts == meta.parts);
        let certificate = meta.certificate && from_certificate && self.blob_copy_now(b) == Some(true) && self.blob_parts_now(b).as_ref() == Some(&meta.parts);
        if !certificate && (self.blob_copy_now(b) != Some(false) || meta.copy) {
            return Ok(None);
        }
        let (Some(tf), Some(tt)) = (self.read_thing(from)?, self.read_thing(to)?) else { return Ok(None) };
        let Some((key, order)) = self.read_secrets(&tf).iter().find_map(|x| osis_crypto::unwrap_order(x, b, from_wrap).ok()) else { return Ok(None) };
        let parts: Vec<usize> = self.blob_parts_now(b).map(|p| p.into_iter().collect()).unwrap_or_default();
        let Some(w) = self.wrap_secret(&tt, Some((c, &parts)))? else { return Ok(None) };
        Ok(Some(osis_crypto::wrap(&w, b, &key, order)?))
    }

    /// Opens entry `blob` (`bytes`, its `wrap`) logged under `s` and takes what it holds
    /// (spec/sync-ids.md §5, spec/sync-inbox.md §2): an inbox blob under an inbox of this node's;
    /// a commit blob whose wrap opens under a held read secret of `s`'s thing, opened
    /// (`open_commit`, each section's opening kept) and ingested, the epoch its wrap opened under
    /// kept as an opening of its header (`note_unwrapped`); a chunk, tree node or page a held commit is
    /// waiting for, stored.
    /// A blob opening bad is no blob of its commit here, whatever an earlier opening noted (one
    /// opened again once its parts can be checked, `BlobOf::unchecked`).
    pub(crate) fn open_entry_now(&mut self, s: &SyncId, blob: &BlobId, wrap: &Wrap, bytes: &[u8], room: u64) -> Result<Opened> {
        let o = self.open_entry_once(s, blob, wrap, bytes, room)?;
        if matches!(o, Opened::Bad) && self.core.ix.blob_parts.contains_key(blob) {
            self.run(|tx| unnote_blob(tx, blob))?;
        }
        Ok(o)
    }

    fn open_entry_once(&mut self, s: &SyncId, blob: &BlobId, wrap: &Wrap, bytes: &[u8], room: u64) -> Result<Opened> {
        if osis_label::blob_id(bytes) != *blob {
            return Ok(Opened::Bad);
        }
        if self.inbox_actors().contains_key(s) && let Some(o) = self.take_inbox_bytes(s, blob, bytes, false)? {
            return Ok(Opened::Inbox(o));
        }
        let wants = self.blob_wants()?;
        if wants.missing.contains(blob) {
            self.put_blobs(vec![(*blob, bytes.to_vec())])?;
            return Ok(Opened::Linked);
        }
        let Some(t) = self.opening_thing(s)? else { return Ok(Opened::NotOpen) };
        let Some((_, key)) = osis_label::unwrap_any(self.read_secrets(&t).iter(), blob, wrap) else { return Ok(Opened::NotOpen) };
        let opened = match self.open_commit(bytes, &key) {
            Ok(o) => o,
            Err(e) if osis_base::Classified::class(&e) == osis_base::ErrorClass::Local => return Err(e),
            Err(_) => {
                // a record blob (spec/wire.md §3): its records taken; a list blob (§4): its
                // thing lists
                let Ok((_, pt)) = osis_label::open(bytes, &key) else { return Ok(Opened::Bad) };
                if let Some(tids) = self.take_record_blob(blob, &pt)? {
                    return Ok(Opened::Records(tids));
                }
                return Ok(match self.take_list_blob(blob, &pt)? {
                    Some(r) => Opened::Lists(r),
                    None => Opened::Bad,
                });
            }
        };
        let id = opened.commit.id();
        // spec/permissions.md §3 (Lost access): a copy carrying content of a thing S's group actor
        // may not read now (left by a revocation since it was placed) gives nothing: none of it is
        // taken (its parts come from a body under their own thing's sync ID)
        if opened.copy && !self.copy_stale(&t, &opened.commit).is_empty() {
            return Ok(Opened::NotOpen);
        }
        // the epoch the wrap opened under: whoever unwraps an entry reads the header
        // (`labeling::opened::header_passes`)
        if let Some((e, _)) = self.read_epochs(&t, &[]).into_iter().find(|(_, x)| osis_crypto::unwrap(x, blob, wrap).is_ok()) {
            self.note_unwrapped(&id, &t, &e);
            // a copy's content came under that epoch alone (its section opens under the blob
            // key): an opening of each of its parts under it, which counts only for a part of
            // S's thing (`labeling::opened::passes_on`), so content read from a copy of another
            // thing's sync ID never passes on under an epoch of the part's thing
            if opened.copy && opened.commit.header.is_resolved() {
                self.note_opened(&opened.commit.header, &[(e, opened.commit.parts.iter().collect())]);
            }
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
        let row = BlobOf { commit: id, parts, sealed, copy: opened.copy, unchecked: !unchecked.is_empty() };
        let b = *blob;
        self.run(|tx| note_blob(tx, &b, row))?;
        Ok(Opened::Commit(id, ingested))
    }

    /// Whether a writer may promote deposited commit `c` under `s` (spec/sync-inbox.md §4): only
    /// once it holds `c` applied, with a body `s` must hold, and its author held write on `s`'s
    /// actor at `c`'s `ts` (as this node judges it); then with the author's chain for those parts
    /// to log beside it (`NotYet` while that chain is not complete here). `Never` when `s` carries
    /// nothing of `c` or its author lacked write then.
    pub(crate) fn promotable_now(&mut self, s: &SyncId, c: &CommitId) -> Result<Promote> {
        let Some(t) = self.read_thing(s)? else { return Ok(Promote::Never) };
        if !self.core.ix.commits.contains_key(c) || self.core.ix.pending.contains_key(c) {
            return Ok(Promote::NotYet);
        }
        let ctx = self.body_ctx(&t);
        let Some(b) = self.commit_bodies_under(&ctx, c)?.into_iter().next() else { return Ok(Promote::Never) };
        let Some(h) = self.header(c) else { return Ok(Promote::NotYet) };
        let actor = self.group_actor(&t);
        if crate::engine::write::role_of(&self.core, &h.author, &actor, h.ts) < Some(Role::Write) || !self.judged_valid(c, &b.parts) {
            return Ok(Promote::Never);
        }
        let parts: crate::labeling::Parts = b.parts.iter().copied().collect();
        Ok(match self.author_chain(c, &parts) {
            Some(chain) => Promote::Yes { chain },
            None => Promote::NotYet,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::Mutation;
    use crate::local_peer::LocalPeer;
    use crate::sync::ThingSync;
    use osis_base::WallMs;

    // spec/sync-ids.md §2 (The nearest actor with a home sync ID): it carries a labeled thing's
    // `sync.0`, an account counting as its devices actor D; a thing an account owns, given
    // secrets of its own outside D's closure, has its `sync.0` commit's body under D's sync ID,
    // as D's label walk lists it.
    #[test]
    fn an_account_things_sync_0_goes_under_d_spec_sync_ids_2() {
        let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let e = &mut lp.peers[0].engine;
        let a = e.create_account().unwrap().0;
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a.account);
        e.commit(m).unwrap();
        let done = e.give_own_secrets(&t).unwrap();
        assert!(!e.closure(&a.devices).contains(&t));
        let ThingSync::Read(d_ids) = e.thing_sync(&a.devices).unwrap() else { panic!("D read here") };
        let walked: std::collections::BTreeSet<_> = e.label_bodies_meta(&a.devices).unwrap().into_iter().map(|b| b.commit).collect();
        let sync0 = osis_base::Ak::new("sync.0").unwrap();
        let c = *done.commits.iter().find(|c| e.core.ix.commits.get(c).is_some_and(|m| m.view.aspects.iter().any(|x| x.tid == t && x.ak == sync0))).unwrap();
        assert!(walked.contains(&c), "D's walk lists the commit");
        let bodies = e.sync_bodies(&c).unwrap();
        assert!(d_ids.iter().all(|s| bodies.contains_key(s)), "a body under D's sync IDs");
    }
}
