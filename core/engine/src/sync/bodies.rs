//! What a sync ID carries of a commit, for readers (spec/sync-judgement.md §1-§2,
//! spec/sync-inbox.md §4): each read sync ID's body of a held commit, the facts its judgement
//! reads, this node's own commits under it, entries opened and sealed (the parts each blob holds),
//! fresh encryptions (`seal_body`, spec/crypto.md §5 Passing on), and whether a writer may promote
//! a deposit. The must-hold / may-hold / must-not-hold rule itself is `read`'s; these are its
//! inputs.

use super::{BlobOf, BodyFacts, BodyId, BodyMeta, HeldBlob, Loss, Opened, PartSet, Promote, SealedSet, Strip, ThingSync, Wrap};
use crate::engine::{DropFor, Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, CommitId, Role, SyncId, Tid, WallMs};
use osis_crypto::NodeRng;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// `bp/` + commit ID + blob ID: flags (one byte: 1 a per-sync-ID copy, 2 unchecked), its prefix
/// salt (16 bytes), the aspects its sections list and the parts it holds (each a count, u32, then
/// u32 each), the digests of the sections it holds that this node did not open (a count, then 32
/// bytes each; `BlobOf`), then its seal (`BlobSeal`): absent, or the blob's length (u64), key (32
/// bytes) and each section (`seal_bytes`).
pub(crate) const BLOB_PARTS: &[u8] = b"bp/";

/// Loads the blob parts (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || Error::Corrupt("blob parts");
    let mut parts = Vec::new();
    tx.scan(BLOB_PARTS, |k, v| {
        let c = CommitId(k.get(..32).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let b = BlobId(k.get(32..).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        parts.push((b, decode_row(c, &v).ok_or_else(bad)?));
        Ok(())
    })?;
    for (b, row) in parts {
        tx.core.ix.commit_blobs.insert(row.commit, b);
        tx.core.ix.blob_parts.insert(b, Arc::new(row));
    }
    Ok(())
}

/// A `bp/` row's value.
fn encode_row(row: &BlobOf) -> Vec<u8> {
    let mut v = vec![u8::from(row.copy) | u8::from(row.unchecked) << 1];
    v.extend(row.salt);
    put_indices(&mut v, row.ais.iter().copied());
    put_indices(&mut v, row.parts.iter().copied());
    v.extend((row.sealed.len() as u32).to_be_bytes());
    v.extend(row.sealed.iter().flatten());
    if let Some(seal) = &row.seal {
        v.extend(seal.len.to_be_bytes());
        v.extend(seal.key.expose());
        v.extend((seal.blocks.len() as u32).to_be_bytes());
        for b in &seal.blocks {
            b.write(&mut v);
        }
        for s in &seal.sections {
            seal_bytes(&mut v, s);
        }
    }
    v
}

/// One section of a seal: 0, its aspect list, its chain (a count byte, then tids), its nonce and
/// key; or 1, the section's canonical bytes (length u32 first).
fn seal_bytes(v: &mut Vec<u8>, s: &osis_commit::SectionSeal) {
    match s {
        osis_commit::SectionSeal::Keyed { ais, chain, nonce, key } => {
            v.push(0);
            put_indices(v, ais.iter().copied());
            v.push(chain.len() as u8);
            chain.iter().for_each(|t| v.extend(t.as_bytes()));
            v.extend(nonce);
            v.extend(key.expose());
        }
        osis_commit::SectionSeal::Verbatim(sec) => {
            v.push(1);
            let b = sec.to_bytes();
            v.extend((b.len() as u32).to_be_bytes());
            v.extend(b);
        }
    }
}

/// `encode_row` read back.
fn decode_row(commit: CommitId, v: &[u8]) -> Option<BlobOf> {
    let (flags, rest) = v.split_first()?;
    let (salt, rest) = rest.split_first_chunk::<16>()?;
    let (ais, rest) = indices(rest)?;
    let (parts, rest) = indices(rest)?;
    let (n, rest) = rest.split_first_chunk::<4>()?;
    let (sealed, mut rest) = rest.split_at_checked(u32::from_be_bytes(*n) as usize * 32)?;
    let sealed: SealedSet = sealed.as_chunks::<32>().0.iter().copied().collect();
    let seal = match rest.split_first_chunk::<8>() {
        None if rest.is_empty() => None,
        None => return None,
        Some((len, r)) => {
            let (key, r) = r.split_first_chunk::<32>()?;
            let (n, mut r) = r.split_first_chunk::<4>()?;
            let mut blocks = Vec::new();
            for _ in 0..u32::from_be_bytes(*n) {
                let (b, len) = osis_blob::ClaimBlock::parse(r).ok()?;
                blocks.push(b);
                r = r.get(len..)?;
            }
            rest = r;
            let mut sections = Vec::new();
            while let Some((tag, r)) = rest.split_first() {
                let (s, r) = match tag {
                    0 => {
                        let (ais, r) = indices(r)?;
                        let (n, r) = r.split_first()?;
                        let (chain, r) = r.split_at_checked(*n as usize * 15)?;
                        let chain = chain.as_chunks::<15>().0.iter().map(|t| Tid::from_bytes(*t)).collect();
                        let (nonce, r) = r.split_first_chunk::<{ osis_crypto::SECTION_NONCE_LEN }>()?;
                        let (k, r) = r.split_first_chunk::<32>()?;
                        (osis_commit::SectionSeal::Keyed { ais: ais.into_iter().collect(), chain, nonce: *nonce, key: osis_crypto::Secret32::from_bytes(*k) }, r)
                    }
                    1 => {
                        let (n, r) = r.split_first_chunk::<4>()?;
                        let (b, r) = r.split_at_checked(u32::from_be_bytes(*n) as usize)?;
                        (osis_commit::SectionSeal::Verbatim(osis_commit::Section::from_bytes(b).ok()?), r)
                    }
                    _ => return None,
                };
                sections.push(s);
                rest = r;
            }
            Some(Arc::new(super::BlobSeal { len: u64::from_be_bytes(*len), key: osis_crypto::Secret32::from_bytes(*key), sections, blocks }))
        }
    };
    Some(BlobOf { commit, parts, sealed, copy: flags & 1 != 0, unchecked: flags & 2 != 0, salt: *salt, ais, seal })
}

/// A count (u32) then each index (u32).
fn put_indices(v: &mut Vec<u8>, xs: impl ExactSizeIterator<Item = usize>) {
    v.extend((xs.len() as u32).to_be_bytes());
    xs.for_each(|p| v.extend((p as u32).to_be_bytes()));
}

/// A count (u32) of indices (u32 each) at the start of `rest`, and what follows.
fn indices(rest: &[u8]) -> Option<(PartSet, &[u8])> {
    let (n, rest) = rest.split_first_chunk::<4>()?;
    let (xs, rest) = rest.split_at_checked(u32::from_be_bytes(*n) as usize * 4)?;
    Some((xs.as_chunks::<4>().0.iter().map(|x| u32::from_be_bytes(*x) as usize).collect(), rest))
}

/// Notes blob `b` as this node opened or sealed it (`row`), in place of what an earlier opening
/// noted (opened again once more is checked, `BlobOf::unchecked`). A blob with a seal is the
/// engine's to make again (`Cipher::made`): the store keeps no bytes of it; one losing its seal is
/// made a last time and its bytes kept again (`hand_back`), before what it was made from changes.
pub(crate) fn note_blob(tx: &mut Tx<'_>, b: &BlobId, row: BlobOf) -> Result<()> {
    put_row(tx, b, row, true)
}

/// `note_blob`; a blob losing its seal is made a last time only where `named` (its bytes kept
/// again for the entries naming it), else its bytes go with it.
fn put_row(tx: &mut Tx<'_>, b: &BlobId, mut row: BlobOf, named: bool) -> Result<()> {
    let old = tx.core.ix.blob_parts.get(b).cloned();
    // a seal is kept only where it makes its blob again from the commit as held, checked once as
    // it is noted (`unseal` keeps it so while what it reads stays): not where a part it keyed is
    // held here only in a blob (dropped, or never taken), nor where the copy held carries other
    // signatures; nor for a blob opened unchecked (its prefix not checked against the header's
    // lists)
    if let Some(s) = row.seal.clone()
        && (row.unchecked || (old.as_ref().is_none_or(|o| o.seal.as_ref() != Some(&s)) && regenerate_in(tx, b, &row)?.is_none()))
    {
        row.seal = None;
    }
    if old.as_deref() == Some(&row) {
        return Ok(());
    }
    if let Some(old) = &old {
        if old.seal.is_some() && row.seal.is_none() {
            match named {
                true => hand_back(tx, b, old)?,
                false => tx.blobs.unmade(b, None, old.seal.as_ref().map_or(0, |s| s.len), tx.is_memory_commit(&old.commit)),
            }
        }
        remove_row(tx, b, old)?;
    }
    // a memory commit's rows are memory, gone with it at a restart
    let v = encode_row(&row);
    let c = row.commit;
    let k = [BLOB_PARTS, &c.0, &b.0].concat();
    let memory = tx.is_memory_commit(&c);
    tx.in_class(memory, |tx| Ok(tx.txn.put_local(&k, &v, Shred::No)?))?;
    if let Some(s) = &row.seal
        && !old.is_some_and(|o| o.seal.is_some())
    {
        tx.blobs.made(b, s.len, memory);
    }
    tx.core.ix.blob_parts.insert(*b, Arc::new(row));
    tx.core.ix.commit_blobs.insert(c, *b);
    Ok(())
}

/// Blob `b` (noted as `row`, with a seal) is made again no more: made a last time from the commit
/// as held now, its bytes are kept again in the store (`Cipher::unmade`), wherever its entries
/// still name it.
fn hand_back(tx: &mut Tx<'_>, b: &BlobId, row: &BlobOf) -> Result<()> {
    let Some(seal) = &row.seal else { return Ok(()) };
    let bytes = regenerate_in(tx, b, row)?;
    debug_assert!(bytes.is_some(), "blob {b:?} of {:?} not made again as its seal goes", row.commit);
    let memory = tx.is_memory_commit(&row.commit);
    tx.blobs.unmade(b, bytes, seal.len, memory);
    Ok(())
}

/// Commit `c`'s record is about to be written as `record` (`None`: removed), its pending copy as
/// stored: `unseal` with the commit as it will be held.
pub(crate) fn unseal_record(tx: &mut Tx<'_>, c: &CommitId, record: Option<&osis_commit::CommitBlob>) -> Result<()> {
    if !sealed_any(tx, c) {
        return Ok(());
    }
    let future = whole(record.cloned(), pending_copy(tx, c)?);
    unseal(tx, c, future.as_ref())
}

/// Commit `c`'s pending copy is about to be written as `pending` (`None`: removed), its record as
/// stored: `unseal` with the commit as it will be held.
pub(crate) fn unseal_pending(tx: &mut Tx<'_>, c: &CommitId, pending: Option<&osis_commit::CommitBlob>) -> Result<()> {
    if !sealed_any(tx, c) {
        return Ok(());
    }
    let future = whole(tx.get_commit(c)?.map(|r| (*r).clone()), pending.cloned());
    unseal(tx, c, future.as_ref())
}

/// Whether a blob of `c` has a seal.
fn sealed_any(tx: &Tx<'_>, c: &CommitId) -> bool {
    tx.core.ix.commit_blobs.get(c).into_iter().flatten().any(|b| tx.core.ix.blob_parts.get(b).is_some_and(|r| r.seal.is_some()))
}

/// Commit `c` is about to be held as `future` (`None`: neither its record nor a pending copy
/// stays): each seal of `c`'s blobs keeps keyed only the sections whose parts stay as held, each
/// other one verbatim as it is made now (`kept_seal`), so a part leaving the record (dropped as
/// covered or invalid, stripped) leaves its blob made again from the record and its section's
/// ciphertext; where the header, signatures or path keys change, or `c` is no longer held, the
/// seal goes (`note_blob`: made a last time first), shredded: its keys would open the blob's
/// bytes wherever they still are, so a commit no longer held stays unrecoverable. Called before
/// the record or pending copy is written.
fn unseal(tx: &mut Tx<'_>, c: &CommitId, future: Option<&osis_commit::CommitBlob>) -> Result<()> {
    let now = held_commit_whole(tx, c)?;
    let blobs: Vec<BlobId> = tx.core.ix.commit_blobs.get(c).into_iter().flatten().copied().collect();
    for b in blobs {
        let Some(row) = tx.core.ix.blob_parts.get(&b).cloned() else { continue };
        let Some(s) = &row.seal else { continue };
        let seal = match (&now, future) {
            (Some(n), Some(f)) if n.header == f.header && n.sigs == f.sigs && n.keys == f.keys => kept_seal(tx, c, s, n, f),
            _ => None,
        };
        if seal.as_ref() == Some(s) {
            continue;
        }
        note_blob(tx, &b, BlobOf { seal, ..(*row).clone() })?;
    }
    Ok(())
}

/// Seal `s` of a blob of commit `c`, held as `now`, for `c` about to be held as `future` with the
/// same header, signatures and path keys: each keyed section listing a part `future` lacks or
/// holds otherwise is kept verbatim, its ciphertext as made from `now`. `None` where `now` does
/// not make the blob's sections.
fn kept_seal(tx: &mut Tx<'_>, c: &CommitId, s: &Arc<super::BlobSeal>, now: &osis_commit::CommitBlob, future: &osis_commit::CommitBlob) -> Option<Arc<super::BlobSeal>> {
    let moves = |x: &osis_commit::SectionSeal| matches!(x, osis_commit::SectionSeal::Keyed { .. }) && x.ais().iter().any(|ai| now.part(*ai).is_none() || now.part(*ai) != future.part(*ai));
    if !s.sections.iter().any(moves) {
        return Some(s.clone());
    }
    let resolved = resolved_header(tx, c, now)?;
    let env = osis_commit::regenerate(now, &resolved, &s.sections).ok()?;
    let sections = s.sections.iter().zip(env.sections).map(|(x, made)| if moves(x) { osis_commit::SectionSeal::Verbatim(made) } else { x.clone() }).collect();
    Some(Arc::new(super::BlobSeal { sections, ..(**s).clone() }))
}

/// Commit `c`'s pending copy, decoded (a parked one as received).
fn pending_copy(tx: &mut Tx<'_>, c: &CommitId) -> Result<Option<osis_commit::CommitBlob>> {
    Ok(tx.txn.get_pending(c)?.and_then(|p| match p.kind {
        osis_store::PendingKind::Parked => osis_commit::CommitBlob::decode(&p.bytes).ok(),
        _ => osis_commit::CommitBlob::decode_stored(&p.bytes).ok(),
    }))
}

/// Blob `b`'s row goes, from where it was noted (its commit forgotten, or the blob opened again
/// bad); one with a seal is made a last time first (`hand_back`).
fn unnote_blob(tx: &mut Tx<'_>, b: &BlobId) -> Result<()> {
    let Some(row) = tx.core.ix.blob_parts.get(b).cloned() else { return Ok(()) };
    hand_back(tx, b, &row)?;
    remove_row(tx, b, &row)
}

/// Blob `b`'s row `row` goes, from the index and from either class: a row noted while its commit
/// was pending went durable, one noted once a memory commit was held went to memory.
fn remove_row(tx: &mut Tx<'_>, b: &BlobId, row: &BlobOf) -> Result<()> {
    let c = row.commit;
    tx.core.ix.blob_parts.remove(b);
    tx.core.ix.commit_blobs.remove(&c, b);
    let k = [BLOB_PARTS, &c.0, &b.0].concat();
    for memory in [false, true] {
        tx.in_class(memory, |tx| Ok(tx.txn.remove_local(&k, Shred::Yes)?))?;
    }
    Ok(())
}

/// Blob `b` (noted as `row`) made again, byte for byte, from its seal and the commit as held now
/// (its record's parts and its pending copy's; notes/slim-design.md B). `None`: no seal (not a
/// commit blob, or none kept), or the commit as held does not give `b`.
pub(crate) fn regenerate_in(tx: &mut Tx<'_>, b: &BlobId, row: &BlobOf) -> Result<Option<Vec<u8>>> {
    let Some(seal) = row.seal.clone() else { return Ok(None) };
    let Some(cb) = held_commit_whole(tx, &row.commit)? else { return Ok(None) };
    let Some(resolved) = resolved_header(tx, &row.commit, &cb) else { return Ok(None) };
    let Ok(env) = osis_commit::regenerate(&cb, &resolved, &seal.sections) else { return Ok(None) };
    let ais = env.ais();
    let groups = osis_commit::prefix_groups(&resolved, ais.iter().copied())?;
    let prefix = osis_blob::Prefix::for_delete_keys(row.salt, &cb.header.blind, osis_commit::prefix_expiry(&resolved, &ais).map(WallMs), &groups)?.with_class(osis_blob::Class::of_marker(resolved.ephemeral)).with_blocks(seal.blocks.clone())?;
    let (_, blob) = osis_blob::frame_under(osis_crypto::BlobKey::of_blob(seal.key.clone()), &prefix, &env.encode())?;
    Ok((osis_blob::blob_id(&blob) == *b).then_some(blob))
}

/// Commit `c`'s header, held as `cb`, with its lists resolved: the held meta's, else resolved
/// here (`None`: not resolvable).
fn resolved_header(tx: &mut Tx<'_>, c: &CommitId, cb: &osis_commit::CommitBlob) -> Option<Arc<osis_commit::Header>> {
    let resolved = match tx.core.ix.commits.get(c) {
        Some(m) if !cb.header.is_resolved() => m.header.clone(),
        _ => Arc::new(cb.header.clone()),
    };
    if resolved.is_resolved() {
        return Some(resolved);
    }
    let mut h = (*resolved).clone();
    crate::apply::resolve_held(tx, &mut h).then(|| Arc::new(h))
}

/// Commit `c` as held here (`whole`).
fn held_commit_whole(tx: &mut Tx<'_>, c: &CommitId) -> Result<Option<osis_commit::CommitBlob>> {
    let record = tx.get_commit(c)?.map(|r| (*r).clone());
    Ok(whole(record, pending_copy(tx, c)?))
}

/// A commit as held from its `record` and `pending` copy: the record's parts with those of the
/// pending copy (an applied commit's waiting parts, or a pending commit's).
fn whole(record: Option<osis_commit::CommitBlob>, pending: Option<osis_commit::CommitBlob>) -> Option<osis_commit::CommitBlob> {
    let (mut out, pending) = match (record, pending) {
        (Some(r), p) => (r, p),
        (None, Some(p)) => (p, None),
        (None, None) => return None,
    };
    if let Some(p) = pending {
        for part in p.parts {
            if out.part(part.ai).is_none() {
                out.parts.push(part);
            }
        }
        for (i, k) in p.keys {
            out.keys.entry(i).or_insert(k);
        }
        out.parts.sort_by_key(|p| p.ai);
    }
    Some(out)
}

/// Commit `c` is forgotten (`apply::unindex_commit`, a release): its blob parts go with it, in
/// its transaction, and so do the store's own entries of its blobs under every sync ID once the
/// engine's store committed (`CipherStore::forgot`): an own entry logs a commit held here. Losing
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

/// Part `ai` of meta `m` leaves every blob of its commit (spec/sync-judgement.md §2 Per blob;
/// `Engine::blob_gone`): its body is gone here other than while invalid (no right deletes that
/// one, and its blobs are its refetch source, spec/permissions.md §6). One dropped as covered once
/// marked so (`Dropped::strips`: `strip_due`, or a purge request standing on it). A function of the
/// record alone: a strip is written.
pub(crate) fn strips(m: &crate::engine::Meta, ai: usize) -> bool {
    match m.dropped(ai) {
        Some(d) if d.why == DropFor::Invalid => false,
        Some(d) if d.as_cover() => d.strips,
        _ => m.body_gone(ai),
    }
}

/// Whether part `ai` of `c` (meta `m`), dropped as covered and not marked to strip, strips now
/// (`retention::replace::settle_none` marks it, `Dropped::strips`): its aspect is under purge on
/// replace by a held setting (`Kept::purges`) and a held valid snapshot of it reaches the part by
/// its tables (`reachers`): a node that never held it then counts it covered too, not missing
/// (spec/commits.md §5 Covered). Elsewhere its blobs keep it: a new reader joins it and judges the
/// cover itself, as a snapshot covering the reacher may name no session left without a write
/// (spec/crdt.md §8 Absence), so tables prove nothing for good. One dropped under own replaces
/// alone goes only with its whole commit.
pub(crate) fn strip_due(core: &crate::engine::Core, c: &CommitId, m: &crate::engine::Meta, ai: usize) -> bool {
    m.dropped(ai).is_some_and(|d| d.as_cover() && !d.strips) && m.view.aspects.get(ai).is_some_and(|a| crate::retention::history::of(core, &a.tid, &a.ak).purges()) && !reachers(core, c, m, ai).is_empty()
}

/// The held valid snapshots of part `ai`'s aspect whose tables reach it (`snapshot::reaches`):
/// what a node lacking the part counts it covered by. One must be shown at a source before a
/// blob stripped of it is deleted there.
pub(crate) fn reachers(core: &crate::engine::Core, c: &CommitId, m: &crate::engine::Meta, ai: usize) -> BTreeSet<CommitId> {
    let Some(a) = m.view.aspects.get(ai) else { return BTreeSet::new() };
    let carries = |s: &CommitId| core.ix.commits.get(s).is_some_and(|sm| sm.view.kind.is_compaction() && sm.aspect(&a.tid, &a.ak).is_some_and(|sai| sm.valid_at(sai) && !sm.body_gone(sai) && !sm.missing(sai)));
    core.ix.snapshots.get(&(a.tid, a.ak.clone())).into_iter().flatten().filter(|x| x.1 != *c && carries(&x.1) && crate::retention::snapshot::reaches((&x.2, &x.3), &m.header, c, a.hi)).map(|x| x.1).collect()
}

/// A commit under one read thing's sync IDs (`Engine::bodies_for`): its closure body, its
/// certificate copy per thing, and the header-only copy its certificates name.
type ThingBodies = (Option<BodyMeta>, Vec<(Tid, BodyMeta)>, Option<BodyMeta>);

impl Engine {
    /// The things whose sync IDs may carry a body of commit `c`: those its parts are on and the
    /// sync units holding them (spec/sync-judgement.md §1).
    fn body_things(&mut self, c: &CommitId) -> BTreeSet<Tid> {
        let Some(v) = self.core.ix.commits.get(c).map(|m| m.view.clone()) else { return BTreeSet::new() };
        let mut out = BTreeSet::new();
        for a in v.aspects.iter() {
            out.insert(a.tid);
            out.extend(self.units_holding(&a.tid));
        }
        out
    }

    /// The bodies of commit `c` under the sync IDs this node reads (spec/sync-judgement.md §1,
    /// spec/permissions.md §4 Copies): per (sync ID, thing), its sync unit body (no thing: parts,
    /// expiry, fetch order, a per-sync-ID copy or the shared blob, or a header alone) and its
    /// certificate copy on each thing outside the sync unit (`bodies_at`). Kept per commit from
    /// its first ask (`Core::sync_bodies`, a `memo::Cutoff`, refreshed by `follow`): a reader moves
    /// only when the bodies do; `unfollow_fate` lets a commit go.
    pub fn sync_bodies(&mut self, c: &CommitId) -> Result<Arc<super::Bodies>> {
        self.follow_bodies()?;
        osis_base::memo::Cutoff::get_in(self, |e| &e.core.sync_bodies, c, |e, c| e.sync_bodies_read(c))
    }

    /// Brings the per-entry values a body reads (the read things, `certified`) up to date before
    /// the bodies are: they go due only once those rows are written (notes/engine.md, Derived
    /// values: Per-key rows).
    fn follow_bodies(&mut self) -> Result<()> {
        self.follow_read_things()?;
        self.follow_certificates()?;
        Ok(())
    }

    /// `sync_bodies` read anew: `bodies_at` each read sync ID of a thing that may carry one.
    pub(super) fn sync_bodies_read(&mut self, c: &CommitId) -> Result<Arc<super::Bodies>> {
        let mut things = self.body_things(c);
        things.extend(self.certified(c)?.into_iter().map(|x| x.0));
        let mut ids = BTreeSet::new();
        for g in things {
            if let ThingSync::Read(x) = self.thing_sync(&g)? {
                ids.extend(x);
            }
        }
        let mut out = BTreeMap::new();
        for s in ids {
            for (on, meta) in self.bodies_at(&s, c)? {
                out.insert((s, on), meta);
            }
        }
        Ok(Arc::new(out.into_iter().collect()))
    }

    /// Body `b` at read sync ID `s`: its entry in `sync_bodies`, a read of its own row
    /// (`Core::sync_body_rows`), unfollowed with the commit's (`unfollow_fate`).
    pub fn sync_body(&mut self, s: &SyncId, b: &BodyId) -> Result<Option<BodyMeta>> {
        self.follow_bodies()?;
        osis_base::memo::Cutoff::get_in(self, |e| &e.core.sync_body_rows, &(b.commit, *s, b.on), |e, k| e.sync_body_read(k))
    }

    /// `sync_body` read anew: `bodies_at` S alone, so a commit carried under many sync IDs (an
    /// account's chain, certified in each unit it holds a role in) costs a row what its own S
    /// holds, never every S of the commit.
    pub(super) fn sync_body_read(&mut self, (c, s, on): &(CommitId, SyncId, Option<Tid>)) -> Result<Option<BodyMeta>> {
        Ok(self.bodies_at(s, c)?.remove(on))
    }

    /// Whether `x` is outside `s`'s sync unit as its bodies read it: no thing reading `s` carries
    /// a part on `x` in its sync unit body (`body_carried`). Only then does `s` carry a
    /// certificate copy on `x`, and a held copy of parts on `x` alone is that copy's blob.
    fn outside(&mut self, s: &SyncId, x: &Tid) -> Result<bool> {
        for t in self.read_things_of(s)? {
            let ctx = self.body_ctx(&t);
            if ctx.holds(&self.core, x) && self.reads(&ctx, x) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The bodies of commit `c` under read sync ID `s`, judged for each thing reading `s`
    /// (`read_things_of`) and joined (`join_body`): the sync unit body (key `None`: a closure
    /// body, else a header the certificates name alone, while no copy carries it), and per thing
    /// outside the sync unit (`outside`) the certificate copy of the parts on it the certificates
    /// name (spec/permissions.md §4 Copies).
    fn bodies_at(&mut self, s: &SyncId, c: &CommitId) -> Result<BTreeMap<Option<Tid>, BodyMeta>> {
        let mut out: BTreeMap<Option<Tid>, BodyMeta> = BTreeMap::new();
        let mut put = |on: Option<Tid>, meta: BodyMeta| {
            let was = out.remove(&on);
            out.insert(on, join_body(was, meta));
        };
        for t in self.read_things_of(s)? {
            let (closure, copies, header) = self.bodies_for(&t, c)?;
            let mut copied = false;
            for (x, meta) in copies {
                if self.outside(s, &x)? {
                    copied = true;
                    put(Some(x), meta);
                }
            }
            if let Some(b) = closure {
                put(None, b);
            } else if let Some(h) = header.filter(|_| !copied) {
                put(None, h);
            }
        }
        Ok(out)
    }

    /// Commit `c` under read thing `t`'s sync IDs: its closure body; per thing, the certificate
    /// copy of the held parts on it `t`'s certificates name that the closure body does not
    /// carry; and the header-only copy its certificates name (a rotation, a request, a minting),
    /// which goes where no other body of the commit does. Only a commit with a part certificates
    /// are made of (a role-class part, `sync.0` steps placing listed delete keys among them; a
    /// card; a record) or a request has copies, so content never reads the certificates.
    fn bodies_for(&mut self, t: &Tid, c: &CommitId) -> Result<ThingBodies> {
        let closure = match self.body_things(c).contains(t) {
            true => self.closure_body(t, c)?,
            false => None,
        };
        let none = |closure| Ok((closure, Vec::new(), None));
        let Some(h) = self.header(c) else { return none(closure) };
        if h.purge.is_empty() && !h.aspects.iter().any(|a| osis_schema::core_types::is_role_class(a.ak.as_str()) || a.ak.as_str() == "created.0") {
            return none(closure);
        }
        let Some(named) = self.certified_of(c, t)? else { return none(closure) };
        let (expires, order) = (osis_commit::blob_expiry(&h).map(WallMs), crate::sync_ids::fetch_order(&h));
        let mut by: BTreeMap<Tid, PartSet> = BTreeMap::new();
        if !named.parts.is_empty() {
            let ctx = self.body_ctx(t);
            let carried = self.body_carried(&ctx, &h);
            // each named part's hold read alone: held as its body (what the record carries)
            let held = |ai: &usize| self.core.ix.commits.get(c).is_some_and(|m| matches!(m.hold(*ai), Some(crate::engine::Hold::Body { .. })));
            for ai in named.parts.iter().filter(|ai| !carried.contains(ai) && held(ai)) {
                if let Some(a) = h.aspects.get(*ai) {
                    by.entry(a.tid).or_default().insert(*ai);
                }
            }
        }
        let copies = by.into_iter().map(|(x, parts)| (x, BodyMeta { parts, expires, order, copy: true, certificate: true, header_only: false, mints: BTreeSet::new() })).collect();
        // a header copy that is a request goes as one, whatever it mints
        let header = (named.header || !named.mints.is_empty()).then(|| BodyMeta { parts: PartSet::new(), expires, order, copy: true, certificate: true, header_only: true, mints: if named.header { BTreeSet::new() } else { named.mints.clone() } });
        Ok((closure, copies, header))
    }

    /// The thing reading `s` whose body `b` `s` carries (`bodies_for`), under whose keys that
    /// body is sealed, logged and promoted.
    fn body_thing(&mut self, s: &SyncId, b: &BodyId) -> Result<Option<Tid>> {
        for t in self.read_things_of(s)? {
            let (closure, copies, header) = self.bodies_for(&t, &b.commit)?;
            let has = match b.on {
                None => closure.is_some() || header.is_some(),
                Some(x) => copies.iter().any(|(y, _)| *y == x),
            };
            if has {
                return Ok(Some(t));
            }
        }
        Ok(None)
    }

    /// The body held blob `b` is an entry of under `s` (spec/permissions.md §4 Copies): a copy
    /// holding parts on one thing alone, that thing outside `s`'s sync unit (`outside`), is the
    /// certificate copy on it; any other blob of the commit is of its sync unit body. `None`
    /// for a blob not opened or sealed here.
    pub fn blob_body(&mut self, s: &SyncId, b: &BlobId) -> Result<Option<BodyId>> {
        let Some(row) = self.core.ix.blob_parts.get(b).cloned() else { return Ok(None) };
        let mut on = None;
        if row.copy && !row.parts.is_empty() && let Some(h) = self.header(&row.commit) {
            let things: BTreeSet<Tid> = row.parts.iter().filter_map(|ai| h.aspects.get(*ai)).map(|a| a.tid).collect();
            if let (1, Some(x)) = (things.len(), things.first()) && self.outside(s, x)? {
                on = Some(*x);
            }
        }
        Ok(Some(BodyId { commit: row.commit, on }))
    }

    /// Commit `c`'s closure body under read thing `g`'s sync IDs, if any.
    fn closure_body(&mut self, g: &Tid, c: &CommitId) -> Result<Option<BodyMeta>> {
        let ctx = self.body_ctx(g);
        let last = self.bodies_under(&ctx, c, true)?.pop();
        Ok(last.map(|b| BodyMeta { parts: b.parts.iter().copied().collect(), expires: b.expires.map(WallMs), order: b.order, copy: b.to_sync_id, certificate: false, header_only: b.parts.is_empty(), mints: BTreeSet::new() }))
    }

    /// The things reading `s` here: those of `s`'s things (`sync_things_of`) whose
    /// `ThingSync::Read` lists it. What arrives under `s` is judged for each. Kept per sync ID
    /// from its first ask (`Core::read_things`, a `memo::Cutoff`): what it is derived from (the
    /// things naming `s`, their sync IDs and holdings) moves at every link or `sync.0`
    /// of them, its answer far less often, and every judgement at `s` reads it.
    pub(crate) fn read_things_of(&mut self, s: &SyncId) -> Result<Vec<Tid>> {
        Ok(osis_base::memo::Cutoff::get_in(self, |e| &e.core.read_things, s, |e, s| e.read_things_now(s))?.to_vec())
    }

    /// `read_things_of` derived anew.
    pub(crate) fn read_things_now(&mut self, s: &SyncId) -> Result<Arc<Vec<Tid>>> {
        let mut out = Vec::new();
        for t in self.sync_things_of(s)? {
            if matches!(self.thing_sync(&t)?, ThingSync::Read(ids) if ids.contains(s)) {
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
    /// certificate's author's other blobs) is the judgement's to add.
    pub fn body_facts(&mut self, s: &SyncId, id: &BodyId) -> Result<BodyFacts> {
        let c = &id.commit;
        let Some(b) = self.sync_body(s, id)? else { return Ok(BodyFacts { required: false, closure: false, dropped: None, invalid: false, kept: false, peer_delete_from: 0, covered: Some(false), lasting_header: false }) };
        let Some(h) = self.header(c) else { return Err(Error::UnknownCommit(*c)) };
        let keeps = self.part_keeps(c)?;
        let Some(m) = self.core.ix.commits.get(c) else { return Err(Error::UnknownCommit(*c)) };
        // dropped here: no part of the body held (a part dropped beside a held one leaves the
        // body judged by what is held)
        let dropped = if b.parts.iter().all(|ai| m.dropped(*ai).is_some()) { b.parts.iter().find_map(|ai| m.dropped(*ai).map(|d| d.why)) } else { None };
        // Invariant: a part judged on missing evidence (unjudgeable: a record, an edge write or
        // the step placing a listed delete key not held) is never judged invalid for it
        // (spec/commits.md §4 Unjudgeable): held so, it waits, and its body stays logged
        let bad = |ai: usize| m.dropped_invalid(ai) || (m.holds(ai) && !m.valid_at(ai) && !crate::apply::unjudgeable(&self.core, c, &h, &m.view, ai));
        // a request holding a right over some delta is in force whatever its parts are
        // (`Engine::forgettable`): a re-grant gives it force with its parts still invalid
        let invalid = !m.view.kind.is_role() && b.parts.iter().any(|ai| bad(*ai)) && b.parts.iter().all(|ai| bad(*ai) || m.dropped(*ai).is_some_and(|d| d.why == DropFor::Cover)) && (!m.view.purges || crate::retention::purge::drops_nothing(&self.core, c, &h));
        // a bound still ahead wakes the judgement when it passes
        let kept = b.parts.iter().any(|ai| keeps.get(*ai).is_some_and(|k| self.core.time.until(Some(*k)) < *k));
        // a dropped part's own bound as it dropped (`Dropped::peer_delete_from`), a held one's keep
        // bound plus `MAX_DRIFT` (spec/commits.md §5 Keep at least)
        let peer_delete_from = b.parts.iter().map(|ai| match m.dropped(*ai) {
            Some(d) => d.peer_delete_from,
            None => keeps.get(*ai).filter(|k| **k > 0).map_or(0, |k| k.saturating_add(osis_base::format::MAX_DRIFT_MS)),
        }).max().unwrap_or(0);
        // a kept body is must-hold whatever covers it (spec/sync-judgement.md §2): its coverage,
        // which every later write of its aspects may move, is not judged
        let mut covered = Some(!b.parts.is_empty() && !kept);
        for ai in b.parts.iter().filter(|_| !kept) {
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
        Ok(BodyFacts { required: true, closure: !b.certificate, dropped, invalid, kept, peer_delete_from, covered, lasting_header: b.header_only })
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
    /// kept for its entries alone: spec/sync-set.md §3, Nothing of R stays), or it is a copy no
    /// tombstone names either (`tombstoned`: sealed for the sync IDs whose entries named it, so a
    /// certificate copy its sync IDs need no more leaves nothing; a tombstone of it is still
    /// found by its row). A held or pending commit's shared blob stays the commit's, its seal
    /// gone: a blob nothing names is made again for nobody (its bytes would have gone with its last
    /// entry).
    pub fn unnamed_blob(&mut self, b: &BlobId, tombstoned: bool) -> Result<()> {
        let ix = &self.core.ix;
        let Some(row) = ix.blob_parts.get(b).cloned() else { return Ok(()) };
        let b = *b;
        if (row.copy && !tombstoned) || !(ix.commits.contains_key(&row.commit) || ix.pending.contains_key(&row.commit)) {
            return self.run(|tx| unnote_blob(tx, &b));
        }
        if row.seal.is_none() {
            return Ok(());
        }
        self.run(|tx| put_row(tx, &b, BlobOf { seal: None, ..(*row).clone() }, false))
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
        x.parts.iter().any(|ai| strips(m, *ai))
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
                from = from.max(d.peer_delete_from);
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
        // blobs of two bodies of the commit (its sync unit body, a certificate copy) compare as none
        let Some(id) = self.blob_body(s, b)? else { return Ok(None) };
        if self.blob_body(s, o)? != Some(id) {
            return Ok(None);
        }
        let Some(m) = self.core.ix.commits.get(&c) else { return Ok(None) };
        if x.parts.iter().any(|ai| m.holds(*ai) && !strips(m, *ai) && !y.parts.contains(ai)) {
            return Ok(None);
        }
        // a blob of the other kind holds no body here (a certificate copy beside the shared blob
        // carries parts S's readers cannot open there, whatever this node opens of it)
        let body_kind = self.sync_body(s, &id)?.is_some_and(|meta| x.of_kind(meta.copy));
        if body_kind && x.parts.is_subset(&y.parts) && y.parts.len() > x.parts.len() && x.sealed.is_subset(&y.sealed) && let Some(only) = self.blob_only(s, &id)? && y.parts.difference(&x.parts).any(|ai| only.contains(ai)) {
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
    /// §1, §4: logging again, a body with no held encryption): the one
    /// place sync encrypts a body (spec/crypto.md §5 Passing on). A per-sync-ID copy is one
    /// section under its blob key (`seal_to`); else `Engine::seal` with every section of every
    /// held genuine blob of `c` (`held`: shared blobs opened or sealed here, never a copy's), so
    /// what this node may not encrypt under an epoch of its choosing goes as it came. The wrap is
    /// `wrap_secret`'s for the parts the blob carries. `None`: nothing may be made now (a part
    /// the body needs, or its header, this node read only under an epoch not established here).
    /// A held blob not tombstoned under `s` is the store's to log verbatim (`rewrap`).
    pub fn seal_body(&mut self, s: &SyncId, id: &BodyId, held: &[HeldBlob], rng: &mut dyn NodeRng) -> Result<Option<(crate::sync_ids::Sealed, Wrap)>> {
        let c = &id.commit;
        let Some(t) = self.body_thing(s, id)? else { return Ok(None) };
        // what a strip leaves of the body: its parts whose bodies are not gone here
        let meta = self.sync_body(s, id)?.map(|mut m| {
            if let Some(cm) = self.core.ix.commits.get(c) {
                m.parts.retain(|ai| !strips(cm, *ai));
            }
            m
        });
        if let Some(meta) = meta.as_ref().filter(|m| m.certificate) {
            return self.seal_certificate(&t, c, meta, rng);
        }
        let ctx = self.body_ctx(&t);
        let Some(mut b) = self.commit_bodies_under(&ctx, c)?.into_iter().next() else { return Ok(None) };
        let class = match self.core.ix.commits.get(c).is_some_and(|m| m.view.memory) {
            true => osis_blob::Class::Ephemeral,
            false => osis_blob::Class::Durable,
        };
        let (sealed, unopened) = match b.to_sync_id {
            true => (self.seal_to(&b, class, rng)?, SealedSet::new()),
            false => {
                let (sections, unopened) = self.held_sections(c, held);
                // the body's parts held only in a held blob (dropped here stripping nothing) are
                // sealed from it as the ones held as bodies are
                let m = self.core.ix.commits.get(c);
                let want: BTreeSet<usize> = meta.iter().flat_map(|x| x.parts.iter().copied()).filter(|ai| !m.is_some_and(|m| matches!(m.hold(*ai), Some(crate::engine::Hold::Body { .. })))).collect();
                if !want.is_empty() {
                    b.plaintext = self.with_blob_parts(&b, held, &want)?;
                }
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
        let mut row = BlobOf { commit: *c, parts: sealed.parts.iter().copied().collect(), sealed: sealed.unopened.clone(), copy: b.to_sync_id, unchecked: false, salt: sealed.salt, ais: sealed.ais.iter().copied().collect(), seal: sealed.seal.clone() };
        if !unopened.is_empty() {
            let env = osis_commit::Envelope::decode(&osis_blob::open_commit(&sealed.blob, &sealed.key)?.1)?;
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
    /// part of the body (held as its body, or opened in a held genuine blob) sealed here
    /// (`section_secret`) or carried by a held genuine section none of whose parts strips; in
    /// each case wrapped for `s` as `wrap_secret` says for the parts the blob carries. Only the
    /// blobs of `held` (bytes in the sync store) count as passed on or carried.
    pub fn may_log(&mut self, s: &SyncId, id: &BodyId, held_blobs: &[BlobId]) -> Result<bool> {
        let c = &id.commit;
        let Some(t) = self.body_thing(s, id)? else { return Ok(false) };
        let Some(meta) = self.sync_body(s, id)? else { return Ok(false) };
        let Some(h) = self.header(c) else { return Ok(false) };
        if !self.core.ix.commits.contains_key(c) {
            return Ok(false);
        }
        // the body's parts whose bodies are not gone here: a strip logs the rest
        let body: Vec<usize> = match self.core.ix.commits.get(c) {
            Some(m) => meta.parts.iter().copied().filter(|ai| !strips(m, *ai)).collect(),
            None => return Ok(false),
        };
        // verbatim: a held genuine blob (a certificate copy of exactly the body's parts for a
        // certificate), never for a per-sync-ID copy's body
        // a fresh encryption's parts beside those held as bodies: the body's parts a held genuine
        // blob opened here (`with_blob_parts`); `carried`: those in a section of one that goes as
        // it came, none of its parts stripping (`seal`'s held sections)
        let mut opened = BTreeSet::new();
        let mut carried = BTreeSet::new();
        for b in held_blobs {
            let Some(row) = self.core.ix.blob_parts.get(b).filter(|x| x.commit == *c).cloned() else { continue };
            if self.loses_among(s, b, held_blobs)? {
                continue;
            }
            if !row.copy {
                let m = self.core.ix.commits.get(c);
                let strip = |ai: &usize| m.is_some_and(|m| strips(m, *ai));
                opened.extend(row.parts.iter().copied().filter(|ai| meta.parts.contains(ai) && !strip(ai)));
                let mut sections: BTreeMap<(Tid, bool), Vec<usize>> = BTreeMap::new();
                for ai in &row.parts {
                    let Some(a) = h.aspects.get(*ai) else { continue };
                    sections.entry((a.tid, osis_keys::under_roles(a.ak.as_str()))).or_default().push(*ai);
                }
                for parts in sections.values().filter(|ps| !ps.iter().any(strip)) {
                    carried.extend(parts.iter().copied());
                }
            }
            if self.blob_gone(b) {
                continue;
            }
            let fits = (meta.certificate && row.copy && row.parts == meta.parts) || (!row.copy && !meta.copy);
            let parts: Vec<usize> = row.parts.iter().copied().collect();
            if fits && self.wrap_secret(&t, Some((c, &parts)))?.is_some() {
                return Ok(true);
            }
        }
        // a fresh encryption: of every part held, as its body or in a held blob, whatever the body
        let held: BTreeSet<usize> = match self.core.ix.commits.get(c) {
            Some(m) => m.hold_all().iter().enumerate().filter(|(_, x)| matches!(x, crate::engine::Hold::Body { .. })).map(|(ai, _)| ai).chain(opened).collect(),
            None => return Ok(false),
        };
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

    /// Body `b`'s plaintext with the parts of `want` that a held genuine blob of its commit
    /// among `held` opens here (`open_commit`): what this node holds of them, in blob bytes.
    fn with_blob_parts(&mut self, b: &crate::sync_ids::Body, held: &[HeldBlob], want: &BTreeSet<usize>) -> Result<Vec<u8>> {
        let pt = self.body_plaintext(b)?;
        if pt.is_empty() {
            return Ok(pt);
        }
        let mut cb = osis_commit::CommitBlob::decode_stored(&pt)?;
        for h in held {
            let id = osis_blob::blob_id(&h.bytes);
            if !self.core.ix.blob_parts.get(&id).is_some_and(|x| x.commit == b.commit && !x.copy) {
                continue;
            }
            let Ok(things) = self.read_things_of(&h.sync_id) else { continue };
            let Some((_, key)) = things.iter().find_map(|t| osis_blob::unwrap_any(self.read_secrets(t).iter(), &id, &h.wrap)) else { continue };
            let Ok(o) = self.open_commit(&h.bytes, &key) else { continue };
            if o.commit.id() != b.commit {
                continue;
            }
            for p in o.commit.parts {
                if want.contains(&p.ai) && !cb.parts.iter().any(|x| x.ai == p.ai) {
                    cb.parts.push(p);
                }
            }
            for (i, k) in o.commit.keys {
                cb.keys.entry(i).or_insert(k);
            }
        }
        cb.parts.sort_by_key(|p| p.ai);
        Ok(cb.encode())
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
            let Ok((_, pt)) = osis_blob::open_commit(&h.bytes, &key) else { continue };
            let Ok(env) = osis_commit::Envelope::decode(&pt) else { continue };
            if env.id() != *c {
                continue;
            }
            for sec in env.sections.into_iter().filter(|sec| !sec.opens_under(c, &key)) {
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
        let b = crate::sync_ids::Body { commit: *c, parts: parts.clone(), expires: meta.expires.map(|e| e.0), blind: m.header.blind, plaintext: Vec::new(), order: meta.order, to_sync_id: true };
        let class = if m.view.memory { osis_blob::Class::Ephemeral } else { osis_blob::Class::Durable };
        let Some(sealed) = self.seal_to(&b, class, rng)? else { return Ok(None) };
        if parts.iter().any(|p| !sealed.parts.contains(p)) {
            return Ok(None);
        }
        let Some(w) = self.wrap_secret(t, Some((c, &parts)))? else { return Ok(None) };
        let wrap = osis_crypto::wrap(&w, &sealed.id, &sealed.key, meta.order)?;
        let row = BlobOf { commit: *c, parts: meta.parts.clone(), sealed: SealedSet::new(), copy: true, unchecked: false, salt: sealed.salt, ais: sealed.ais.iter().copied().collect(), seal: sealed.seal.clone() };
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
    pub fn rewrap(&mut self, id: &BodyId, b: &BlobId, from: &SyncId, from_wrap: &Wrap, to: &SyncId) -> Result<Option<Wrap>> {
        let c = &id.commit;
        // a certificate copy of the same parts is one blob wrapped under each sync ID needing
        // them (spec/sync-judgement.md §1 Certificate blobs); a per-sync-ID copy never is shared,
        // even as a certificate of the same parts elsewhere: `from` holds `b` as a certificate too
        let Some(meta) = self.sync_body(to, id)? else { return Ok(None) };
        let from_certificate = self.sync_body(from, id)?.is_some_and(|m| m.certificate && m.parts == meta.parts);
        let certificate = meta.certificate && from_certificate && self.blob_copy_now(b) == Some(true) && self.blob_parts(b).as_ref() == Some(&meta.parts);
        if !certificate && (self.blob_copy_now(b) != Some(false) || meta.copy) {
            return Ok(None);
        }
        let Some(tt) = self.body_thing(to, id)? else { return Ok(None) };
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
    pub fn open_entry(&mut self, s: &SyncId, blob: &BlobId, wrap: &Wrap, bytes: &[u8], pages: &[Vec<u8>], room: u64) -> Result<Opened> {
        let o = self.open_entry_once(s, blob, wrap, bytes, pages, room)?;
        if matches!(o, Opened::Bad) && self.core.ix.blob_parts.contains_key(blob) {
            self.run(|tx| unnote_blob(tx, blob))?;
        }
        Ok(o)
    }

    fn open_entry_once(&mut self, s: &SyncId, blob: &BlobId, wrap: &Wrap, bytes: &[u8], pages: &[Vec<u8>], room: u64) -> Result<Opened> {
        if osis_blob::blob_id(bytes) != *blob {
            return Ok(Opened::Bad);
        }
        // a blob a waiting commit lacks (`reach::Walks`: one lookup, never the whole set)
        if self.wants_blob(blob) {
            self.put_blobs(vec![(*blob, bytes.to_vec())])?;
            return Ok(Opened::Linked);
        }
        // judged for each of `s`'s things: the one whose held read secret opens the wrap
        let things = self.opening_things(s)?;
        let unwrapped = things.iter().find_map(|t| osis_blob::unwrap_any(self.read_secrets(t).iter(), blob, wrap).map(|(_, k)| (*t, k)));
        let (t, key, section) = match unwrapped {
            Some((t, key)) => (t, key, None),
            None => {
                // a wrap no held secret opens: a sealed fire's filler, opened by the read KEM key
                // (spec/sync-inbox.md §4 A sealed fire) of whichever thing it is sealed to
                for t in &things {
                    match self.open_sealed_fire(t, blob, bytes)? {
                        Opened::NotOpen => {}
                        o => return Ok(o),
                    }
                }
                // else a claim of a holder this node reaches S's thing through (spec/sync-ids.md
                // §3 Taking a claim)
                match self.took(s, bytes, &[], pages)? {
                    Some((thing, key, section)) => (thing, key, Some(section)),
                    None => return Ok(Opened::NotOpen),
                }
            }
        };
        self.opened_entry(s, blob, wrap, bytes, room, t, &key, section.as_slice())
    }

    /// Entry `blob` of S kept unread here, its bytes `bytes`: an entry of a holder this node
    /// reaches S's thing through found in it by its claim at a step of `path` (S's registered
    /// path) or one known here, in it or its claim pages `pages` (spec/wire.md §5), taken
    /// (spec/sync-ids.md §3 Taking a claim): a sync holder's
    /// secret kept, a read holder's commit opened as `open_entry` opens one.
    pub fn take_unread_entry(&mut self, s: &SyncId, blob: &BlobId, wrap: &Wrap, bytes: &[u8], pages: &[Vec<u8>], path: &[osis_blob::Step]) -> Result<Opened> {
        match self.took(s, bytes, path, pages)? {
            Some((thing, key, section)) => self.opened_entry(s, blob, wrap, bytes, 0, thing, &key, &[section]),
            None => Ok(Opened::NotOpen),
        }
    }

    /// `take_claims`, each sync holder's secret noted: the read claim's thing and keys, if any.
    fn took(&mut self, s: &SyncId, bytes: &[u8], path: &[osis_blob::Step], pages: &[Vec<u8>]) -> Result<Option<(Tid, osis_crypto::Secret32, osis_crypto::Secret32)>> {
        let took = self.take_claims(s, bytes, path, pages)?;
        for (thing, holder) in took.sync {
            self.took_sync_claim(s, thing, holder)?;
        }
        Ok(took.read)
    }

    /// `open_entry` of a blob whose key `key` (and section keys `section`, an entry's) is found,
    /// opened for S's thing `t`.
    #[allow(clippy::too_many_arguments)]
    fn opened_entry(&mut self, s: &SyncId, blob: &BlobId, wrap: &Wrap, bytes: &[u8], room: u64, t: Tid, key: &osis_crypto::Secret32, section: &[osis_crypto::Secret32]) -> Result<Opened> {
        let key = key.clone();
        let opened = match self.open_commit_by(bytes, &key, section) {
            Ok(o) => o,
            Err(e) if osis_base::Classified::class(&e) == osis_base::ErrorClass::Local => return Err(e),
            Err(_) => {
                // a record blob (spec/wire.md §3): its records taken, kept as a certificate blob
                // of the own store under `s` (`certblobs`): one any node logged counts as this
                // node's own; its prefix a certificate blob's (`CertBlob::of`), else bad input
                let Ok((_, pt)) = osis_blob::open(bytes, &key) else { return Ok(Opened::Bad) };
                if super::certblobs::CertBlob::of(bytes, &key, BTreeSet::new()).is_none() {
                    return Ok(Opened::Bad);
                }
                // a sync-only cut under `t` (spec/wire.md §4, framed as a record blob is):
                // taken under `t`, for its sync ID alone (`sync_ids::unread`)
                if osis_commit::SyncOnlyCut::is_shaped(&pt) {
                    return Ok(if self.take_sync_cut(&t, blob, &pt)? { Opened::SyncOnlyCut } else { Opened::Bad });
                }
                if let Some(tids) = self.take_record_blob(blob, &pt)? {
                    let Some(c) = super::certblobs::CertBlob::of(bytes, &key, tids.clone()) else { return Ok(Opened::Bad) };
                    self.note_cert_blob(s, blob, c)?;
                    return Ok(Opened::Records(tids));
                }
                return Ok(Opened::Bad);
            }
        };
        let id = opened.commit.id();
        // spec/permissions.md §3 (Lost access): a copy carrying content of a thing the independent of S's thing
        // may not read now (left by a revocation since it was logged) gives nothing: none of it is
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
        let parts: PartSet = opened.parts().into_iter().collect();
        // an ephemeral commit is held in memory, within the room S's cap leaves
        // (spec/sync-compaction.md §2 Holding, Caps); a relay-only one is never an entry. The
        // records minted in sections of things not held here are taken alone with it
        // (spec/sync-judgement.md §1 Sealed sections): a held strong may bring the thing in
        let ingested = match opened.commit.header.ephemeral {
            None => self.ingest_carrying(&opened.plaintext, Vec::new(), opened.records.clone()),
            Some(osis_commit::EphClass::Plain) => {
                if !opened.records.is_empty() {
                    self.learn_records(opened.records.clone())?;
                }
                self.ingest_memory(&opened.plaintext, room)
            }
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
        let seal = Some(Arc::new(super::BlobSeal { len: bytes.len() as u64, key: key.clone(), sections: opened.seals.clone(), blocks: opened.blocks.clone() }));
        let row = BlobOf { commit: id, parts, sealed, copy: opened.copy, unchecked: !unchecked.is_empty() || h.is_none(), salt: opened.salt, ais: opened.ais.iter().copied().collect(), seal };
        let b = *blob;
        self.run(|tx| note_blob(tx, &b, row))?;
        Ok(Opened::Commit(id, ingested))
    }

    /// Whether a writer may promote deposited commit `c` under `s` (spec/sync-inbox.md §4): only
    /// once it holds `c` applied, with a body `s` must hold, and its author held write on `s`'s
    /// actor at `c`'s `ts` (as this node judges it), or it fires an external signal valid here; then with the evidence for those parts
    /// to log beside it (`NotYet` while that evidence is not complete here). `Never` when `s` carries
    /// nothing of `c` or its author lacked write then.
    pub fn promotable(&mut self, s: &SyncId, c: &CommitId) -> Result<Promote> {
        let Some(t) = self.body_thing(s, &BodyId::unit(*c))? else { return Ok(Promote::Never) };
        if !self.core.ix.commits.contains_key(c) || self.core.ix.pending.contains_key(c) {
            return Ok(Promote::NotYet);
        }
        let ctx = self.body_ctx(&t);
        let Some(b) = self.commit_bodies_under(&ctx, c)?.into_iter().next() else { return Ok(Promote::Never) };
        let Some(h) = self.header(c) else { return Ok(Promote::NotYet) };
        let actor = self.core.reader_of(&t);
        // a fire of an external signal is promoted whatever its author's role while valid: a
        // stranger's only while the thing's current setting enables it (`judged_valid`,
        // spec/sync-inbox.md §4, spec/permissions.md §5.2 External fires)
        let external = b.parts.iter().all(|ai| h.aspects.get(*ai).is_some_and(|a| a.ak.external()));
        if !external && crate::engine::write::role_of(&self.core, &h.signer, &actor, h.ts) < Some(Role::Write) || !self.judged_valid(c, &b.parts) {
            return Ok(Promote::Never);
        }
        let parts: crate::sync_ids::Parts = b.parts.iter().copied().collect();
        Ok(Promote::Yes { evidence: self.evidence_of(c, &parts)? })
    }
}

/// Two readings of one body under one sync ID, from different things reading it, as one: a
/// closure body over a certificate (where a sync ID carries a closure body of a commit, that is
/// its sync unit body there), else their parts and minted records together, the later expiry, the
/// earlier fetch order. The same whatever order they come in.
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

impl Engine {
    /// Held blob `b` made again, byte for byte, from its seal (`BlobOf::seal`) and the commit as
    /// held here (`regenerate_in`). `None`: no seal (not a commit blob, or none kept), or the commit
    /// as held no longer gives it: its bytes are the store's (`osis_sync::store::blob_bytes`).
    pub fn regenerate(&mut self, b: &BlobId) -> Result<Option<Vec<u8>>> {
        let Some(row) = self.core.ix.blob_parts.get(b).filter(|r| r.seal.is_some()).cloned() else { return Ok(None) };
        self.read(|tx| regenerate_in(tx, b, &row))
    }

    /// The parts that strip now (`strip_due`) but are not marked so (`Dropped::strips`), on an
    /// aspect whose purge-on-replace re-judge is not pending (`Core::none_due`): none, as every
    /// strip is written in the transaction that makes it true. Debug builds check it at the end of
    /// every engine's history.
    #[doc(hidden)]
    pub fn unwritten_strips(&self) -> Vec<(CommitId, usize)> {
        let core = &self.core;
        core.ix.commits.iter().flat_map(|(c, m)| (0..m.view.aspects.len()).filter(move |ai| strip_due(core, c, m, *ai) && m.view.aspects.get(*ai).is_some_and(|a| !core.none_due.contains(&(a.tid, a.ak.clone())))).map(move |ai| (*c, ai))).collect()
    }

    /// Every blob with a seal is made again (`regenerate`), to the bytes the store keeps where
    /// it keeps any: how many were, and each that was not, described. Debug builds check it at
    /// the end of every engine's history.
    #[doc(hidden)]
    pub fn check_seals(&mut self) -> (usize, Vec<String>) {
        let rows: Vec<(BlobId, Arc<BlobOf>)> = self.core.ix.blob_parts.iter().filter(|(_, r)| r.seal.is_some()).map(|(b, r)| (*b, r.clone())).collect();
        let (mut made, mut out) = (0, Vec::new());
        for (b, row) in rows {
            let kept = self.read(|tx| tx.blobs.get(&b)).ok().flatten();
            match self.regenerate(&b) {
                Ok(Some(r)) if kept.is_none_or(|k| k == r) => made += 1,
                r => {
                    let c = row.commit;
                    let m = self.core.ix.commits.get(&c);
                    let holds: Vec<String> = row.seal.iter().flat_map(|s| s.sections.iter()).filter(|s| matches!(s, osis_commit::SectionSeal::Keyed { .. })).flat_map(|s| s.ais().to_vec()).map(|ai| format!("{ai}:{:?}", m.and_then(|m| m.hold(ai)))).collect();
                    let pending = self.core.ix.pending.contains_key(&c);
                    out.push(format!("blob {b:?} of {c:?} copy {} unchecked {} held {} pending {pending} keyed parts [{}]: {}", row.copy, row.unchecked, m.is_some(), holds.join(", "), match r { Ok(Some(_)) => "differs".to_string(), Ok(None) => "not made again".to_string(), Err(e) => format!("{e:?}") }));
                }
            }
        }
        (made, out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    
    
    
    

}
