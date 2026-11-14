//! What a sync ID carries of a commit, for readers (spec/sync-judgement.md §1-§2,
//! spec/sync-inbox.md §4): each read sync ID's body of a held commit, the facts its judgement
//! reads, this node's own commits under it, entries opened and sealed (the epoch each section is
//! sealed under kept per commit and thing), and whether a writer may promote a deposit. The
//! must-hold / may-hold / must-not-hold rule itself is `read`'s; these are its inputs.

use super::{BodyFacts, BodyMeta, Opened, PartSet, Promote, ThingSync, Wrap};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, CommitId, Role, SyncId, Tid, WallMs};
use osis_crypto::{Epoch, NodeRng, Secret32};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// `se/` + commit ID + tid: the read epoch commit's section of a thing is sealed under, as this
/// node sealed or opened it (`section_epoch`).
pub(crate) const SECTION_EPOCHS: &[u8] = b"se/";
/// `bp/` + commit ID + blob ID: the parts an opened or sealed blob of the commit holds
/// (`blob_parts`).
pub(crate) const BLOB_PARTS: &[u8] = b"bp/";

/// Loads the section epochs and blob parts (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || Error::Corrupt("section epoch");
    let mut rows = Vec::new();
    tx.scan(SECTION_EPOCHS, |k, v| {
        let c = CommitId(k.get(..32).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let t = Tid::from_bytes(k.get(32..).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let e = osis_base::decode(&v, &osis_base::Limits { max_depth: 4, max_bytes: v.len() }).map_err(|_| bad())?;
        rows.push(((c, t), Epoch::from_wire(&e).map_err(|_| bad())?));
        Ok(())
    })?;
    tx.core.ix.section_epochs.extend(rows);
    let mut parts = Vec::new();
    tx.scan(BLOB_PARTS, |k, v| {
        let c = CommitId(k.get(..32).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let b = BlobId(k.get(32..).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let ps: PartSet = v.chunks(4).map(|x| x.try_into().map(u32::from_be_bytes).map(|n| n as usize).map_err(|_| bad())).collect::<Result<_>>()?;
        parts.push((c, b, ps));
        Ok(())
    })?;
    for (c, b, ps) in parts {
        tx.core.ix.blob_parts.insert(b, Arc::new((c, ps)));
        tx.core.ix.commit_blobs.insert(c, b);
    }
    Ok(())
}

fn note_section(tx: &mut Tx<'_>, c: &CommitId, t: &Tid, e: &Epoch) -> Result<()> {
    if tx.core.ix.section_epochs.get(&(*c, *t)) == Some(e) {
        return Ok(());
    }
    // a memory commit's rows are memory, gone with it at a restart
    let k = [SECTION_EPOCHS, &c.0, t.as_bytes()].concat();
    tx.in_class(tx.is_memory_commit(c), |tx| Ok(tx.txn.put_local(&k, &osis_base::encode(&e.to_wire()), Shred::No)?))?;
    tx.core.ix.section_epochs.insert((*c, *t), *e);
    Ok(())
}

fn note_blob(tx: &mut Tx<'_>, b: &BlobId, c: &CommitId, parts: &PartSet) -> Result<()> {
    if tx.core.ix.blob_parts.contains_key(b) {
        return Ok(());
    }
    let v: Vec<u8> = parts.iter().flat_map(|p| (*p as u32).to_be_bytes()).collect();
    let k = [BLOB_PARTS, &c.0, &b.0].concat();
    tx.in_class(tx.is_memory_commit(c), |tx| Ok(tx.txn.put_local(&k, &v, Shred::No)?))?;
    tx.core.ix.blob_parts.insert(*b, Arc::new((*c, parts.clone())));
    tx.core.ix.commit_blobs.insert(*c, *b);
    Ok(())
}

/// Commit `c` is forgotten (`apply::unindex_commit`): its section epochs and blob parts go
/// with it, in its transaction.
pub(crate) fn forget(tx: &mut Tx<'_>, c: &CommitId) -> Result<()> {
    let tids: Vec<Tid> = tx.core.ix.section_epochs.range((*c, Tid::from_bytes([0; 15]))..=(*c, Tid::from_bytes([0xff; 15]))).map(|((_, t), _)| *t).collect();
    let blobs: Vec<BlobId> = tx.core.ix.commit_blobs.get(c).into_iter().flatten().copied().collect();
    tx.in_class(tx.is_memory_commit(c), |tx| {
        for t in tids {
            tx.core.ix.section_epochs.remove(&(*c, t));
            tx.txn.remove_local(&[SECTION_EPOCHS, &c.0, t.as_bytes()].concat(), Shred::No)?;
        }
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

    /// Per sync ID this node reads whose closure body of commit `c` its actor may read: that body
    /// (spec/sync-judgement.md §1: parts, expiry, fetch order, a per-sync-ID copy or the shared
    /// blob, a lasting header alone). This node's own certificates are `own_certificates`.
    pub(crate) fn sync_bodies_now(&mut self, c: &CommitId) -> Result<Arc<BTreeMap<SyncId, BodyMeta>>> {
        let mut out = BTreeMap::new();
        for g in self.body_things(c)? {
            let ThingSync::Read(ids) = self.thing_sync_now(&g)? else { continue };
            let ctx = self.body_ctx(&g);
            for b in self.commit_bodies_under(&ctx, c)? {
                let meta = BodyMeta { parts: b.parts.iter().copied().collect(), expires: b.expires.map(WallMs), order: b.order, copy: b.to_label, certificate: false, header_only: b.parts.is_empty() };
                for s in &ids {
                    out.insert(*s, meta.clone());
                }
            }
        }
        Ok(Arc::new(out))
    }

    /// The thing whose read sync ID `s` is here (`ThingSync::Read`).
    fn read_thing(&mut self, s: &SyncId) -> Result<Option<Tid>> {
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
            let Some(a) = h.aspects.get(*ai) else { continue };
            // a signal's delta is never joined: never established uncovered
            if a.ak.signal() {
                continue;
            }
            let snaps: Vec<CommitId> = self.core.ix.snapshots.get(&(a.tid, a.ak.clone())).into_iter().flatten().map(|x| x.1).filter(|x| x != c).collect();
            let mut this = Some(false);
            for x in snaps {
                match self.covered(&x, c, &a.tid, &a.ak)? {
                    Some(true) => {
                        this = Some(true);
                        break;
                    }
                    None if self.header(&x).is_none_or(|sh| sh.ts > h.ts) => this = None,
                    _ => {}
                }
            }
            covered = match (covered, this) {
                (Some(x), Some(y)) => Some(x && y),
                _ => None,
            };
        }
        Ok(BodyFacts { required: true, closure: !b.certificate, dropped, kept, covered, sole_certificate: false, lasting_header: b.header_only })
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

    /// The read epoch commit `c`'s section of thing `t`, and its wrap under a sync ID of `t`, are
    /// re-sealed under (the security rule of fresh encryptions, spec/crypto.md §5): the epoch it
    /// was written under, as this node opened a blob of it (a section of `t`, else the wrap it
    /// opened under) or sealed it; for a commit written here and never sealed, the epoch it is written under now
    /// (`wrap_secret`'s). Only an epoch established here, whose secret is held: else `None`, and
    /// nothing is sealed (a node holding a newer epoch without the removal that made it must not
    /// seal under it, nor seal another writer's section under an epoch it was not written under).
    /// The one place a fresh encryption picks a section's epoch.
    fn section_epoch(&mut self, c: &CommitId, t: &Tid, parts: &[usize]) -> Result<Option<(Epoch, Secret32)>> {
        let e = match self.core.ix.section_epochs.get(&(*c, *t)).copied() {
            Some(e) => e,
            None if self.core.ix.commits.get(c).is_some_and(|m| m.origin == crate::events::Origin::Local) => {
                let Some(s) = self.wrap_secret(t, Some((c, parts)))? else { return Ok(None) };
                let Some(e) = self.epochs(t).and_then(|x| x.read.epochs().map(|(e, _)| *e).find(|e| x.read.secret(e).is_some_and(|k| k.expose() == s.expose()))) else { return Ok(None) };
                e
            }
            None => return Ok(None),
        };
        let Some(ep) = self.epochs(t) else { return Ok(None) };
        if !ep.read.is_established(&e) {
            return Ok(None);
        }
        Ok(ep.read.secret(&e).map(|s| (e, s.clone())))
    }

    /// `c`'s body under `s` as a fresh encryption, with its wrap for `s` (spec/sync-judgement.md
    /// §1, §4: logging again, a non-writer's deposit, a body with no held encryption): a per-sync-
    /// ID copy one section under its blob key; else each section under the epoch it was written
    /// under (`section_epoch`), refused (`None`) when one is not established here. A held blob not
    /// tombstoned under `s` is the store's to log verbatim; it never comes here.
    pub(crate) fn seal_body_now(&mut self, s: &SyncId, c: &CommitId, rng: &mut dyn NodeRng) -> Result<Option<(crate::labeling::Sealed, Wrap)>> {
        let Some(t) = self.read_thing(s)? else { return Ok(None) };
        let ctx = self.body_ctx(&t);
        let Some(b) = self.commit_bodies_under(&ctx, c)?.into_iter().next() else { return Ok(None) };
        let class = match self.core.ix.commits.get(c).is_some_and(|m| m.view.memory) {
            true => osis_label::Class::Ephemeral,
            false => osis_label::Class::Durable,
        };
        let sealed = if b.to_label {
            self.seal_to(&b, class, rng)?
        } else {
            let pt = self.body_plaintext(&b)?;
            if pt.is_empty() {
                return Ok(None);
            }
            let blob = osis_commit::CommitBlob::decode_stored(&pt)?;
            let resolved = self.resolved_header(&blob);
            let things: Vec<Tid> = resolved.aspects.iter().map(|a| a.tid).collect();
            let mut by: BTreeMap<Tid, Vec<usize>> = BTreeMap::new();
            for p in &blob.parts {
                if let Some(t) = things.get(p.ai) {
                    by.entry(*t).or_default().push(p.ai);
                }
            }
            let mut secrets: BTreeMap<Tid, (Epoch, Secret32, Vec<Tid>)> = BTreeMap::new();
            for (x, ps) in &by {
                let Some((e, k)) = self.section_epoch(c, x, ps)? else { return Ok(None) };
                secrets.insert(*x, (e, k, self.section_chain_of(x)));
            }
            let env = osis_commit::seal_commit(&blob, |ai| things.get(ai).copied(), |x, _| secrets.get(&(*x)?).map(|(_, k, ch)| (k.clone(), ch.clone())), &[], rng)?;
            let sealed = crate::labeling::frame_envelope(&env, &resolved, class, rng, &blob)?;
            if b.parts.iter().any(|p| !sealed.parts.contains(p)) {
                return Ok(None);
            }
            let id = *c;
            self.run(|tx| {
                for (x, (e, _, _)) in &secrets {
                    note_section(tx, &id, x, e)?;
                }
                Ok(())
            })?;
            Some(sealed)
        };
        let Some(sealed) = sealed else { return Ok(None) };
        // the wrap (a copy's only key) by the same rule as a section: the epoch the commit was
        // written under at S's thing, never this node's newest (spec/crypto.md §5)
        let Some((_, w)) = self.section_epoch(c, &t, &b.parts)? else { return Ok(None) };
        let wrap = osis_crypto::wrap(&w, &sealed.id, &sealed.key, b.order)?;
        let (id, ps) = (*c, sealed.parts.iter().copied().collect::<PartSet>());
        let bid = sealed.id;
        self.run(|tx| note_blob(tx, &bid, &id, &ps))?;
        Ok(Some((sealed, wrap)))
    }

    /// Opens entry `blob` (`bytes`, its `wrap`) logged under `s` and takes what it holds
    /// (spec/sync-ids.md §5, spec/sync-inbox.md §2): an inbox blob under an inbox of this node's;
    /// a commit blob whose wrap opens under a held read secret of `s`'s thing, ingested, each
    /// section's epoch kept (`section_epoch`); a chunk, tree node or page a held commit is
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
        let secrets = self.read_secrets(&t);
        let Some((i, key)) = osis_label::unwrap_any(secrets.iter(), blob, wrap) else { return Ok(Opened::NotOpen) };
        let opened = match self.open_commit(bytes, &key) {
            Ok(o) => o,
            Err(e) if osis_base::Classified::class(&e) == osis_base::ErrorClass::Local => return Err(e),
            Err(_) => return Ok(Opened::Bad),
        };
        let id = opened.commit.id();
        let parts: PartSet = opened.parts().into_iter().collect();
        let ingested = match self.ingest(&opened.plaintext, Vec::new()) {
            Ok(i) => i,
            Err(e) if osis_base::Classified::class(&e) == osis_base::ErrorClass::Local => return Err(e),
            Err(_) => return Ok(Opened::Bad),
        };
        if !opened.copy {
            self.note_section_epochs(&id, bytes, &key)?;
        }
        // no section of S's thing gave its epoch (a copy, or sections on other things only): the
        // epoch the entry's wrap opened under
        let wrapped = match self.core.ix.section_epochs.get(&(id, t)) {
            Some(_) => None,
            None => secrets.get(i).and_then(|x| self.epochs(&t).and_then(|ep| ep.read.epochs().map(|(e, _)| *e).find(|e| ep.read.reading_secret(e).is_some_and(|y| y.expose() == x.expose())))),
        };
        let b = *blob;
        self.run(|tx| {
            if let Some(e) = &wrapped {
                note_section(tx, &id, &t, e)?;
            }
            note_blob(tx, &b, &id, &parts)
        })?;
        Ok(Opened::Commit(id, ingested))
    }

    /// Keeps, per section of commit blob `bytes` (blob key `key`) on a thing this node reads, the
    /// read epoch whose secret unwraps it (`section_epoch`).
    fn note_section_epochs(&mut self, id: &CommitId, bytes: &[u8], key: &Secret32) -> Result<()> {
        let (_, pt) = osis_label::open(bytes, key)?;
        let env = osis_commit::Envelope::decode(&pt)?;
        let Some(h) = self.header(id) else { return Ok(()) };
        let mut found = Vec::new();
        for sec in &env.sections {
            let Some(t) = sec.ais.first().and_then(|ai| h.aspects.get(*ai)).map(|a| a.tid) else { continue };
            let Some(ep) = self.epochs(&t) else { continue };
            if let Some(e) = ep.read.epochs().map(|(e, _)| *e).find(|e| ep.read.secret(e).is_some_and(|s| osis_crypto::unwrap_section(s, id, &sec.wrap).is_ok())) {
                found.push((t, e));
            }
        }
        let c = *id;
        self.run(|tx| {
            for (t, e) in &found {
                note_section(tx, &c, t, e)?;
            }
            Ok(())
        })
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
