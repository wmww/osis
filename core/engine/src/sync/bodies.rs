//! What a sync ID carries of a commit, for readers (spec/sync-judgement.md §1-§2,
//! spec/sync-inbox.md §4): each read sync ID's body of a held commit, the facts its judgement
//! reads, this node's own commits under it, entries opened and sealed (the parts each blob holds),
//! fresh encryptions (`seal_body`, spec/crypto.md §5 Passing on), and whether a writer may promote
//! a deposit. The must-hold / may-hold / must-not-hold rule itself is `read`'s; these are its
//! inputs.

use super::{BodyFacts, BodyMeta, HeldBlob, Opened, PartSet, Promote, ThingSync, Wrap};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, CommitId, Role, SyncId, Tid, WallMs};
use osis_crypto::NodeRng;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// `bp/` + commit ID + blob ID: whether an opened or sealed blob of the commit is a per-sync-ID
/// copy (one byte), then the parts it holds (`blob_parts`, `blob_copy`).
pub(crate) const BLOB_PARTS: &[u8] = b"bp/";

/// Loads the blob parts (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || Error::Corrupt("blob parts");
    let mut parts = Vec::new();
    tx.scan(BLOB_PARTS, |k, v| {
        let c = CommitId(k.get(..32).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let b = BlobId(k.get(32..).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let (copy, rest) = v.split_first().ok_or_else(bad)?;
        let ps: PartSet = rest.chunks(4).map(|x| x.try_into().map(u32::from_be_bytes).map(|n| n as usize).map_err(|_| bad())).collect::<Result<_>>()?;
        parts.push((c, b, ps, *copy != 0));
        Ok(())
    })?;
    for (c, b, ps, copy) in parts {
        tx.core.ix.blob_parts.insert(b, Arc::new((c, ps, copy)));
        tx.core.ix.commit_blobs.insert(c, b);
    }
    Ok(())
}

pub(super) fn note_blob(tx: &mut Tx<'_>, b: &BlobId, c: &CommitId, parts: &PartSet, copy: bool) -> Result<()> {
    if tx.core.ix.blob_parts.contains_key(b) {
        return Ok(());
    }
    // a memory commit's rows are memory, gone with it at a restart
    let v: Vec<u8> = std::iter::once(u8::from(copy)).chain(parts.iter().flat_map(|p| (*p as u32).to_be_bytes())).collect();
    let k = [BLOB_PARTS, &c.0, &b.0].concat();
    tx.in_class(tx.is_memory_commit(c), |tx| Ok(tx.txn.put_local(&k, &v, Shred::No)?))?;
    tx.core.ix.blob_parts.insert(*b, Arc::new((*c, parts.clone(), copy)));
    tx.core.ix.commit_blobs.insert(*c, *b);
    Ok(())
}

/// Commit `c` is forgotten (`apply::unindex_commit`): its blob parts go with it, in its
/// transaction.
pub(crate) fn forget(tx: &mut Tx<'_>, c: &CommitId) -> Result<()> {
    let blobs: Vec<BlobId> = tx.core.ix.commit_blobs.get(c).into_iter().flatten().copied().collect();
    tx.in_class(tx.is_memory_commit(c), |tx| {
        for b in blobs {
            tx.core.ix.commit_blobs.remove(c, &b);
            tx.core.ix.blob_parts.remove(&b);
            tx.txn.remove_local(&[BLOB_PARTS, &c.0, &b.0].concat(), Shred::No)?;
        }
        Ok(())
    })
}

impl Engine {
    /// The things whose sync IDs may carry a body of commit `c`: those its parts are on, the
    /// groups enclosing them, and for a `sync.0` or `created.0` part the nearest actor up its
    /// thing's record chain with a home sync ID (spec/sync-ids.md §2).
    fn body_things(&mut self, c: &CommitId) -> Result<BTreeSet<Tid>> {
        let Some(v) = self.core.ix.commits.get(c).map(|m| m.view.clone()) else { return Ok(BTreeSet::new()) };
        let mut out = BTreeSet::new();
        for a in v.aspects.iter() {
            out.insert(a.tid);
            out.extend(self.enclosing(&a.tid));
            if matches!(a.ak.as_str(), "sync.0" | "created.0") {
                for x in self.core.standing_chain(&a.tid).into_iter().filter(|x| *x != a.tid) {
                    if !self.owned_sync_ids(&x)?.is_empty() {
                        out.insert(x);
                        break;
                    }
                }
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
            let ctx = self.body_ctx(&g);
            for b in self.bodies_under(&ctx, c, true)? {
                let meta = BodyMeta { parts: b.parts.iter().copied().collect(), expires: b.expires.map(WallMs), order: b.order, copy: b.to_label, certificate: false, header_only: b.parts.is_empty() };
                for s in &ids {
                    out.insert(*s, meta.clone());
                }
            }
        }
        self.certificate_bodies(c, &mut out)?;
        Ok(Arc::new(out))
    }

    /// Adds to `out` the certificate bodies of commit `c` (spec/sync-judgement.md §1-§2,
    /// spec/permissions.md §4): per read sync ID carrying no closure body of `c`, the held parts
    /// of it the sync ID's certificates name (`sync_certificates`) that its closure's bodies do
    /// not carry, as a copy; else, a header the certificates name, as a header-only copy. Only a
    /// commit with a part certificates are made of (an edge write, keys, a card, a record) or a
    /// request is asked, so content never reads the certificates. Where a sync ID carries a
    /// closure body of `c`, that body is its one body there (`certificate_reading`).
    fn certificate_bodies(&mut self, c: &CommitId, out: &mut BTreeMap<SyncId, BodyMeta>) -> Result<()> {
        let Some(h) = self.header(c) else { return Ok(()) };
        if !h.has_request() && !h.aspects.iter().any(|a| matches!(a.ak.as_str(), "roles.0" | "keys.0" | "node.0" | "reach.0" | "created.0")) {
            return Ok(());
        }
        let id = *c;
        let held: PartSet = osis_base::memo::Memo::get_in(self, |e| &e.core.bodies, &id, |e| e.body_with(&id, false))?.map(|b| b.parts.into_iter().collect()).unwrap_or_default();
        let (expires, order) = (osis_commit::blob_expiry(&h).map(WallMs), crate::labeling::fetch_order(&h));
        let closure: BTreeSet<SyncId> = out.keys().copied().collect();
        for (t, named, ids) in self.certified(c)? {
            let ids: Vec<SyncId> = ids.into_iter().filter(|s| !closure.contains(s)).collect();
            if ids.is_empty() {
                continue;
            }
            let parts: PartSet = match named.parts.is_empty() {
                false => {
                    let ctx = self.body_ctx(&t);
                    let carried = self.body_carried(&ctx, &h);
                    named.parts.iter().copied().filter(|ai| held.contains(ai) && !carried.contains(ai)).collect()
                }
                true => PartSet::new(),
            };
            if parts.is_empty() && !named.header {
                continue;
            }
            let header_only = parts.is_empty();
            let meta = BodyMeta { parts, expires, order, copy: true, certificate: true, header_only };
            for s in ids {
                out.insert(s, meta.clone());
            }
        }
        Ok(())
    }

    /// The thing whose read sync ID `s` is here (`ThingSync::Read`).
    pub(crate) fn read_thing(&mut self, s: &SyncId) -> Result<Option<Tid>> {
        let owner = match self.sync_owner_of(s)? {
            Some(t) => Some(t),
            None => self.core.ix.destroyed_sync_ids.iter().find(|(_, v)| v.iter().any(|o| o.id == *s)).map(|(t, _)| *t),
        };
        let Some(t) = owner else { return Ok(None) };
        Ok(matches!(self.thing_sync_now(&t)?, ThingSync::Read(ids) if ids.contains(s)).then_some(t))
    }

    /// The facts the judgement of `c`'s body under `s` reads (spec/sync-judgement.md §2): whether
    /// it is in the required set and a closure body; a part of it dropped here and why; a delta
    /// before its keep-at-least bound; covered by held valid snapshots of its aspects under `s`
    /// (`None` while one stamped after it cannot be judged); a lasting header alone. What the
    /// store shows (snapshots under `s` this node does not hold, other blobs of the commit, a
    /// certificate's author's other blobs) is the judgement's to add: `sole_certificate` is false
    /// here.
    pub(crate) fn body_facts_now(&mut self, s: &SyncId, c: &CommitId) -> Result<BodyFacts> {
        let bodies = self.sync_bodies_now(c)?;
        let Some(b) = bodies.get(s) else { return Ok(BodyFacts { required: false, closure: false, dropped: None, kept: false, covered: Some(false), sole_certificate: false, lasting_header: false }) };
        let (Some(m), Some(h)) = (self.core.ix.commits.get(c).cloned(), self.header(c)) else { return Err(Error::UnknownCommit(*c)) };
        let dropped = b.parts.iter().find_map(|ai| m.dropped(*ai).map(|d| d.why));
        let now = self.now().0;
        let keeps = self.part_keeps(c)?;
        let kept = b.parts.iter().any(|ai| keeps.get(*ai).is_some_and(|k| *k > now));
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
        Ok(BodyFacts { required: true, closure: !b.certificate, dropped, kept, covered, sole_certificate: false, lasting_header: b.header_only })
    }

    /// Whether held snapshots of its aspect cover delta `ai` of `c` (header `h`): `None` while one
    /// stamped after it cannot be judged (spec/sync-judgement.md §2 established uncovered). A
    /// signal's delta is never joined, so never covered.
    pub(crate) fn part_covered(&mut self, c: &CommitId, h: &osis_commit::Header, ai: usize) -> Result<Option<bool>> {
        let Some(a) = h.aspects.get(ai) else { return Ok(Some(false)) };
        if a.ak.signal() {
            return Ok(Some(false));
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

    /// This node's commits (written here) with a body under `s` (spec/sync-status.md §2):
    /// O(things on `s`'s closure + its account's and node's commits on them).
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
        let ctx = self.body_ctx(&t);
        let mut out = BTreeSet::new();
        for c in own {
            if !self.commit_bodies_under(&ctx, &c)?.is_empty() {
                out.insert(c);
            }
        }
        Ok(Arc::new(out))
    }

    /// This node's own certificates under `s` (spec/permissions.md §4): its account's and its
    /// own cards and the chain certificates for `s`'s thing, the commits with the parts to log.
    pub(crate) fn own_certificates_now(&mut self, s: &SyncId) -> Result<Arc<crate::labeling::Certs>> {
        let Some(t) = self.read_thing(s)? else { return Ok(Arc::default()) };
        Ok(Arc::new(self.certificates(&t)))
    }

    /// The parts blob `b` holds of its commit, as this node opened or sealed it.
    pub(crate) fn blob_parts_now(&self, b: &BlobId) -> Option<PartSet> {
        self.core.ix.blob_parts.get(b).map(|x| x.1.clone())
    }

    /// Whether held blob `b` holds a part of its commit this node dropped for good (spec/sync-
    /// judgement.md §1: a delta it holds that the node dropped makes the blob must-not-hold,
    /// whatever sync ID it is under): purged, past its bounds, expired, destroyed. A part dropped
    /// as covered (it leaves by the carriers rule, spec/sync-compaction.md §1) or while invalid
    /// (no right deletes it) does not count. `false` for a blob not opened or sealed here.
    pub(crate) fn blob_dropped_now(&self, b: &BlobId) -> bool {
        let Some(x) = self.core.ix.blob_parts.get(b) else { return false };
        let Some(m) = self.core.ix.commits.get(&x.0) else { return false };
        x.1.iter().any(|ai| m.dropped(*ai).is_some_and(|d| matches!(d.why, crate::engine::DropFor::Other | crate::engine::DropFor::Destroyed)))
    }

    /// Whether blob `b`, as opened or sealed here, is a per-sync-ID copy.
    pub(crate) fn blob_copy_now(&self, b: &BlobId) -> Option<bool> {
        self.core.ix.blob_parts.get(b).map(|x| x.2)
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
        if let Some(meta) = self.sync_bodies_now(c)?.get(s).filter(|m| m.certificate).cloned() {
            return self.seal_certificate(&t, c, &meta, rng);
        }
        let ctx = self.body_ctx(&t);
        let Some(b) = self.commit_bodies_under(&ctx, c)?.into_iter().next() else { return Ok(None) };
        let class = match self.core.ix.commits.get(c).is_some_and(|m| m.view.memory) {
            true => osis_label::Class::Ephemeral,
            false => osis_label::Class::Durable,
        };
        let sealed = match b.to_label {
            true => self.seal_to(&b, class, rng)?,
            false => {
                let sections = self.held_sections(c, held);
                self.seal(&b, class, &sections, rng)?
            }
        };
        let Some(sealed) = sealed else { return Ok(None) };
        if b.parts.iter().any(|p| !sealed.parts.contains(p)) {
            return Ok(None);
        }
        let Some(w) = self.wrap_secret(&t, Some((c, &sealed.parts)))? else { return Ok(None) };
        let wrap = osis_crypto::wrap(&w, &sealed.id, &sealed.key, b.order)?;
        let (id, ps) = (*c, sealed.parts.iter().copied().collect::<PartSet>());
        let (bid, copy) = (sealed.id, b.to_label);
        self.run(|tx| note_blob(tx, &bid, &id, &ps, copy))?;
        Ok(Some((sealed, wrap)))
    }

    /// The sections of commit `c`'s held genuine blobs among `held` (each opened by its entry's
    /// wrap under a read secret of its sync ID's thing): shared blobs of `c` opened or sealed
    /// here, never a copy (a section under its blob key is never copied into another encryption,
    /// spec/sync-judgement.md §1). Opened or not; one per aspect set, largest first, none sharing
    /// an aspect with one taken (a commit's sections never overlap).
    fn held_sections(&mut self, c: &CommitId, held: &[HeldBlob]) -> Vec<osis_commit::Section> {
        let mut all = Vec::new();
        for h in held {
            let b = osis_label::blob_id(&h.bytes);
            if self.core.ix.blob_parts.get(&b).is_none_or(|x| x.0 != *c || x.2) {
                continue;
            }
            let Ok(Some(t)) = self.read_thing(&h.sync_id) else { continue };
            let Some((_, key)) = osis_label::unwrap_any(self.read_secrets(&t).iter(), &b, &h.wrap) else { continue };
            let Ok((_, pt)) = osis_label::open(&h.bytes, &key) else { continue };
            let Ok(env) = osis_commit::Envelope::decode(&pt) else { continue };
            if env.id() != *c {
                continue;
            }
            all.extend(env.sections.into_iter().filter(|sec| osis_crypto::unwrap_section(&key, c, &sec.wrap).is_err()));
        }
        all.sort_by_key(|sec| std::cmp::Reverse(sec.ais.len()));
        let mut seen = BTreeSet::new();
        all.retain(|sec| sec.ais.iter().all(|ai| !seen.contains(ai)) && {
            seen.extend(sec.ais.iter().copied());
            true
        });
        all
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
        let (id, bid, ps) = (*c, sealed.id, meta.parts.clone());
        self.run(|tx| note_blob(tx, &bid, &id, &ps, true))?;
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
        let bodies = self.sync_bodies_now(c)?;
        let Some(meta) = bodies.get(to).cloned() else { return Ok(None) };
        let from_certificate = bodies.get(from).is_some_and(|m| m.certificate && m.parts == meta.parts);
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
    pub(crate) fn open_entry_now(&mut self, s: &SyncId, blob: &BlobId, wrap: &Wrap, bytes: &[u8]) -> Result<Opened> {
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
        let Some(t) = self.read_thing(s)? else { return Ok(Opened::NotOpen) };
        let Some((_, key)) = osis_label::unwrap_any(self.read_secrets(&t).iter(), blob, wrap) else { return Ok(Opened::NotOpen) };
        let opened = match self.open_commit(bytes, &key) {
            Ok(o) => o,
            Err(e) if osis_base::Classified::class(&e) == osis_base::ErrorClass::Local => return Err(e),
            Err(_) => {
                // a record blob (spec/wire.md §3): its records taken
                let Ok((_, pt)) = osis_label::open(bytes, &key) else { return Ok(Opened::Bad) };
                return Ok(match self.take_record_blob(blob, &pt)? {
                    Some(tids) => Opened::Records(tids),
                    None => Opened::Bad,
                });
            }
        };
        let id = opened.commit.id();
        // the epoch the wrap opened under: whoever unwraps an entry reads the header
        // (`labeling::opened::header_passes`)
        if let Some((e, _)) = self.read_epochs(&t, &[]).into_iter().find(|(_, x)| osis_crypto::unwrap(x, blob, wrap).is_ok()) {
            self.note_unwrapped(&id, &t, &e);
        }
        let parts: PartSet = opened.parts().into_iter().collect();
        let ingested = match self.ingest(&opened.plaintext, Vec::new()) {
            Ok(i) => i,
            Err(e) if osis_base::Classified::class(&e) == osis_base::ErrorClass::Local => return Err(e),
            Err(_) => return Ok(Opened::Bad),
        };
        let b = *blob;
        self.run(|tx| note_blob(tx, &b, &id, &parts, opened.copy))?;
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
