//! Receiving commits (spec/commits.md §4; spec/versioning.md §2; spec/crdt.md §2.2): decode,
//! verify, dedup by commit ID, pending reasons and parking, re-examination, atomic apply in one
//! store transaction (membership before content), late deltas of applied commits. Loading the
//! engine's indexes from the store lives here too, since it replays what apply records.

mod atomic;
mod waits;
pub(crate) mod keys;
pub(crate) mod receipt;
pub(crate) mod validity;
#[cfg(test)]
mod tests_linked;
#[cfg(test)]
mod tests_order;

pub(crate) use waits::Waits;
pub(crate) use atomic::{Unmerge, apply_verified, forget_snapshot, index_commit, note_gives, ingest_secrets_keys, invalid_of, rebuild, strip_copies_where, unmerge_fell};

use crate::engine::blobs::TxBlobs;
use crate::engine::{Engine, Meta, Tx, decode_commit_record, records};
use crate::error::{Error, Result};
use crate::events::{Diagnostic, DiagnosticKind, Origin};
use osis_commit::{CommitBlob, Decoded, Header, Kind, MAX_LIST_BYTES, delta_ctx, verify_part};
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{BlobId, Classified, CommitId, CreationRecord, ErrorClass, Tid, Value, WallMs};
use osis_crdt::Interner;
use osis_crypto::{VerifyingKey, dedup_secret};
use osis_label::BlobReader;
use osis_store::{PendingKind, Shred};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Why a commit is pending (spec/commits.md §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The `/created` record (key) of the author or of a thing on an owner chain is missing.
    MissingChain(Tid),
    /// The `/created` record of a thing whose delta it holds or that it syncs is unknown.
    UnknownCreated(Tid),
    /// `ts` more than `MAX_DRIFT` ahead of the corrected clock.
    Drift,
    /// A delta under a thing this node syncs has not arrived (atomic apply).
    WaitDeltas,
    /// A page of a paged delta or a blob of a linked header list has not arrived.
    WaitBlobs,
    /// Parked: part of it is not interpretable by this build (spec/versioning.md §2).
    Parked,
    /// Stored pending; not examined since the node opened.
    Unexamined,
}

/// What `ingest` did with a commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ingested {
    Applied(CommitId),
    /// Already held (nothing new in it).
    Duplicate(CommitId),
    Pending(CommitId, Reason),
    /// Kept as bytes: this build cannot interpret part of it (spec/versioning.md §2).
    Parked(CommitId),
}

pub(crate) enum Exam {
    Ready(Vec<(usize, usize, Decoded)>),
    Pending(Reason),
    Parked,
}

/// Commit ID of a blob whose header this build cannot decode: BLAKE3 of the header value.
fn raw_id(bytes: &[u8]) -> Result<CommitId> {
    let lim = osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: bytes.len() };
    let v = osis_base::decode(bytes, &lim).map_err(|_| Error::BadInput("commit blob"))?;
    let Value::List(items) = v else { return Err(Error::BadInput("commit blob")) };
    let h = items.first().ok_or(Error::BadInput("commit blob"))?;
    Ok(CommitId(osis_base::hash::hash(&osis_base::encode(h))))
}

fn is_missing_page(e: &osis_commit::Error) -> bool {
    matches!(e, osis_commit::Error::Delta(osis_crdt::Error::Page(osis_crdt::PageError::Missing)) | osis_commit::Error::Missing)
}

/// Creation records a commit carries on `/created` (decoded without a hash check; the part is
/// verified later under the record's own dedup secret).
fn carried_records(h: &Header, blob: &CommitBlob, id: &CommitId) -> Result<BTreeMap<Tid, CreationRecord>> {
    let mut out = BTreeMap::new();
    let mut interner = Interner::new();
    for p in &blob.parts {
        let Some(a) = h.aspects.get(p.ai) else { continue };
        if a.ak.as_str() != osis_commit::retention::CREATED {
            continue;
        }
        let cx = delta_ctx(h, id, p.ai, &mut interner)?;
        let d = osis_crdt::decode_delta(&p.delta, &cx, &mut interner, None)?;
        let v = d.fragment.read().ok_or(Error::BadInput("empty /created"))?;
        let rec = CreationRecord::from_value(&v).ok_or(Error::BadInput("/created is not a creation record"))?;
        if rec.tid() != a.tid {
            return Err(Error::BadInput("/created does not hash to its tid"));
        }
        if !crate::engine::write::is_minting(&d.fragment, &rec) {
            return Err(Error::BadInput("/created is not one minting of its record"));
        }
        out.insert(a.tid, rec);
    }
    Ok(out)
}

/// Whether a missing delta of commit `id` makes it wait (atomic apply, spec/commits.md §4).
fn waits_for_deltas(tx: &mut Tx<'_>, h: &Header, id: &CommitId, missing: impl Iterator<Item = (usize, usize)>) -> Result<bool> {
    for (ai, _) in missing {
        // expired, purged or dropped deltas count as held (dropped: a held valid snapshot
        // stamped after it claims its counters, spec/crdt.md §8)
        if let Some(a) = h.aspects.get(ai)
            && tx.core.ix.syncing.contains(&a.tid)
            && !a.expires.is_some_and(|t| t <= tx.now().0)
            && !crate::retention::known_purged(tx, h, id, ai)?
            && !(h.form == osis_commit::Form::Node && h.kind.has_own_writes() && (receipt::get(tx, &a.tid, &a.ak)?.holds(&h.author, a.lo, a.hi) || receipt::claimed(tx.core, &a.tid, &a.ak, &h.author, a.hi.saturating_sub(1), h.ts)))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A pending commit in `Engine::reexamine`: read and decoded, or still waiting for deltas
/// when last examined (`Core::waits`).
enum Turn {
    Read(Box<CommitBlob>),
    Waiting((bool, osis_base::Ts)),
}

/// Checks a commit and decodes its parts, or says why it waits.
pub(crate) fn examine(tx: &mut Tx<'_>, blob: &mut CommitBlob, id: &CommitId, skip: &BTreeSet<(usize, usize)>) -> Result<Exam> {
    if !blob.header.is_resolved() {
        let Some(dedup) = tx.core.dedup(&blob.header.actor) else { return Ok(Exam::Pending(Reason::UnknownCreated(blob.header.actor))) };
        match blob.header.resolve(&mut TxBlobs::new(&mut tx.txn), &dedup, MAX_LIST_BYTES) {
            Ok(()) => {}
            Err(e) if is_missing_page(&e) => return Ok(Exam::Pending(Reason::WaitBlobs)),
            Err(e) => return Err(e.into()),
        }
    }
    let h = blob.header.clone();
    let carried = carried_records(&h, blob, id)?;
    let held: BTreeMap<Tid, CreationRecord> = h.aspects.iter().map(|a| a.tid).chain([h.author, h.actor]).filter_map(|t| tx.core.created(&t).map(|r| (t, r.clone()))).collect();
    let chain_rec = |t: &Tid, core: &crate::engine::Core| -> Option<CreationRecord> { core.created(t).cloned().or_else(|| carried.get(t).cloned()) };
    let record = |t: &Tid| -> Option<CreationRecord> { held.get(t).cloned().or_else(|| carried.get(t).cloned()) };
    let Some(author) = record(&h.author) else { return Ok(Exam::Pending(Reason::MissingChain(h.author))) };
    let CreationRecord::KeyActor { public_key, .. } = &author else { return Err(Error::BadInput("author is not a key actor")) };
    let vk = VerifyingKey::from_slice(public_key)?;
    {
        let _s = crate::costs::span("examine: signature");
        osis_commit::verify_signature(id, &blob.signature, &vk)?;
    }
    h.validate()?;
    // the bound is for received commits (spec/crdt.md §2.2): this node's own are as far ahead
    // as its HLC, which a clock correction moving back must not turn against them
    if h.author != tx.core.id.tid() && h.ts.wall_ms().0 > tx.now().0.saturating_add(MAX_DRIFT_MS) {
        return Ok(Exam::Pending(Reason::Drift));
    }
    // only things whose deltas it holds or syncs gate the commit: a thing it neither holds a
    // delta of nor syncs (another's private thing in a mixed commit) is not applied here
    let held_ais: BTreeSet<usize> = blob.parts.iter().map(|p| p.ai).collect();
    for (ai, a) in h.aspects.iter().enumerate() {
        if !held_ais.contains(&ai) && !tx.core.ix.syncing.contains(&a.tid) {
            continue;
        }
        if record(&a.tid).is_none() {
            return Ok(Exam::Pending(Reason::UnknownCreated(a.tid)));
        }
        // the owner chain up to a key actor (spec/permissions.md §4)
        // a chain deeper than `MAX_OWNER_DEPTH` is not waited for further: its deltas are
        // invalid (`validity::too_deep`, spec/permissions.md §1)
        let mut cur = a.tid;
        let mut chain = vec![cur];
        for _ in 0..=osis_base::format::MAX_OWNER_DEPTH {
            match chain_rec(&cur, tx.core) {
                Some(CreationRecord::Thing { owner, .. }) => {
                    cur = owner;
                    chain.push(cur);
                }
                Some(CreationRecord::KeyActor { .. }) => break,
                None => return Ok(Exam::Pending(Reason::MissingChain(cur))),
            }
        }
        // the author's chain certificates: it is on the owner chain, or held edge writes lead
        // from it to the chain (a revoked author keeps its certificates and still applies,
        // judged invalid)
        if !chain.contains(&h.author) && !validity::reaches(tx.core, &h.author, &chain) {
            return Ok(Exam::Pending(Reason::MissingChain(h.author)));
        }
    }
    // an import applies only to a copy its author created (spec/permissions.md §7; tests let a
    // local writer break this, to test receivers); it waits for the copy's record even where it
    // holds no part of it, since its header alone names the claim for carried writes
    if h.kind == osis_commit::Kind::Import && !(tx.core.skip_writer_rules && h.author == tx.core.id.tid()) {
        for a in &h.aspects {
            match record(&a.tid) {
                None => return Ok(Exam::Pending(Reason::UnknownCreated(a.tid))),
                Some(CreationRecord::Thing { creator: Some(c), .. }) if c == h.author => {}
                Some(_) => return Err(Error::BadInput("an import into a thing its author did not create")),
            }
        }
    }
    // a part that does not hash to its header entry is dropped alone (spec/commits.md §4)
    let bad: Vec<(usize, usize)> = blob
        .parts
        .iter()
        .filter(|p| {
            let Some(a) = h.aspects.get(p.ai) else { return true };
            let Some(want) = a.hashes.get(p.di) else { return true };
            record(&a.tid).is_some_and(|r| osis_crypto::delta_hash(&dedup_secret(r.nonce()), &p.delta) != *want)
        })
        .map(|p| (p.ai, p.di))
        .collect();
    if !bad.is_empty() {
        blob.parts.retain(|p| !bad.contains(&(p.ai, p.di)));
        let now = tx.now();
        tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::BadInput, tids: Vec::new(), commit: Some(*id), peer: Some(h.author), detail: "delta hash".into() }, now);
    }
    for (t, rec) in &carried {
        if let Some(held) = tx.core.created(t)
            && held != rec
        {
            let now = tx.now();
            tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::CollidingRecord, tids: vec![*t], commit: Some(*id), peer: Some(h.author), detail: String::new() }, now);
        }
    }
    if waits_for_deltas(tx, &h, id, blob.missing().into_iter().filter(|x| !skip.contains(x)))? {
        return Ok(Exam::Pending(Reason::WaitDeltas));
    }
    let mut out = Vec::with_capacity(blob.parts.len());
    let mut interner = Interner::new();
    for p in &blob.parts {
        if skip.contains(&(p.ai, p.di)) {
            continue;
        }
        let a = h.aspects.get(p.ai).ok_or(Error::BadInput("part index"))?;
        let dedup = record(&a.tid).map(|r| dedup_secret(r.nonce())).ok_or(Error::UnknownThing(a.tid))?;
        let mut blobs = TxBlobs::new(&mut tx.txn);
        let mut reader = BlobReader::new(&dedup, &mut blobs);
        match verify_part(&h, id, p, &dedup, &mut interner, Some(&mut reader)) {
            Ok(d) => out.push((p.ai, p.di, d)),
            Err(e) if e.class() == ErrorClass::Parked => return Ok(Exam::Parked),
            Err(e) if is_missing_page(&e) => return Ok(Exam::Pending(Reason::WaitBlobs)),
            Err(e) => return Err(e.into()),
        }
    }
    // a roster snapshot's tenures are judged by their frontiers: linked ones are fetched first
    // (tests let a local writer break these rules, to test receivers)
    if !(tx.core.skip_writer_rules && h.author == tx.core.id.tid()) {
        validity::check_roster_parts(&h, &out)?;
        validity::check_members_parts(&h, id, &out)?;
        if !validity::linked_frontiers(tx, &h, &validity::EdgeParts::of(&h, &out))?.waiting.is_empty() {
            return Ok(Exam::Pending(Reason::WaitBlobs));
        }
    }
    Ok(Exam::Ready(out))
}

/// Applies or stores one decoded commit blob.
fn ingest_blob(tx: &mut Tx<'_>, mut blob: CommitBlob, origin: Origin) -> Result<Ingested> {
    // an ephemeral commit is never stored (`Engine::ingest_ephemeral`)
    if blob.header.ephemeral.is_some() {
        return Err(Error::BadInput("an ephemeral commit on the durable path"));
    }
    let id = blob.id();
    if tx.core.ix.commits.contains_key(&id) {
        return late_parts(tx, &id, blob);
    }
    if tx.core.ix.pending.contains_key(&id)
        && let Some((PendingKind::Pending, old)) = tx.txn.get_pending(&id)?
        && let Ok(old) = CommitBlob::decode(&old)
    {
        blob = merge_parts(old, blob);
    }
    let received = tx.now();
    let inline = blob.header.is_resolved();
    let _s = crate::costs::span("examine");
    match examine(tx, &mut blob, &id, &BTreeSet::new())? {
        Exam::Ready(parts) => {
            tx.core.touch();
            let was_pending = tx.core.ix.pending.remove(&id).is_some();
            tx.core.waits.unpended(&id);
            if was_pending {
                tx.txn.remove_pending(&id, Shred::Yes)?;
            }
            apply_verified(tx, &blob, parts, origin, received)?;
            if was_pending {
                keys::forget_unchecked(tx, &id)?;
            }
            Ok(Ingested::Applied(id))
        }
        Exam::Pending(r) => {
            tx.core.touch();
            tx.txn.put_pending(&id, PendingKind::Pending, &blob.encode())?;
            tx.core.ix.pending.insert(id, r.clone());
            tx.core.waits.pended(&id);
            keys::read_pending_boxes(tx, &blob, &id)?;
            let now = tx.now().0;
            waits::note(tx.core, id, &blob, inline, &r, now);
            Ok(Ingested::Pending(id, r))
        }
        Exam::Parked => {
            tx.core.touch();
            tx.txn.put_pending(&id, PendingKind::Parked, &blob.encode())?;
            tx.core.ix.pending.insert(id, Reason::Parked);
            tx.core.waits.pended(&id);
            Ok(Ingested::Parked(id))
        }
    }
}

fn merge_parts(mut a: CommitBlob, b: CommitBlob) -> CommitBlob {
    for p in b.parts {
        if let Err(i) = a.parts.binary_search_by_key(&(p.ai, p.di), |x| (x.ai, x.di)) {
            a.parts.insert(i, p);
        }
    }
    a
}

/// A delta of an already applied commit, arriving later, is joined on arrival (spec/commits.md
/// §4); dropped parts stay dropped. Late deltas that wait (their thing's `/created`, chain or
/// pages) are kept pending under the commit's ID and joined once they apply.
fn late_parts(tx: &mut Tx<'_>, id: &CommitId, mut blob: CommitBlob) -> Result<Ingested> {
    let held = tx.get_commit(id)?.ok_or(Error::Corrupt("commit record"))?;
    let meta = tx.core.ix.commits.get(id).cloned().ok_or(Error::Corrupt("commit index"))?;
    let mut skip: BTreeSet<(usize, usize)> = held.parts.iter().map(|p| (p.ai, p.di)).collect();
    for ai in meta.dropped.keys() {
        skip.extend((0..meta.header.aspects.get(*ai).map_or(0, |a| a.hashes.len())).map(|di| (*ai, di)));
    }
    if tx.core.ix.pending.contains_key(id)
        && let Some((PendingKind::Pending, old)) = tx.txn.get_pending(id)?
        && let Ok(old) = CommitBlob::decode(&old)
    {
        blob = merge_parts(old, blob);
    }
    blob.parts.retain(|p| !skip.contains(&(p.ai, p.di)));
    if blob.parts.is_empty() {
        tx.core.waits.unpended(id);
        if tx.core.ix.pending.remove(id).is_some() {
            tx.core.touch();
            tx.txn.remove_pending(id, Shred::Yes)?;
        }
        return Ok(Ingested::Duplicate(*id));
    }
    let mut merged = merge_parts(held, blob.clone());
    merged.header = (*meta.header).clone();
    let _s = crate::costs::span("examine");
    match examine(tx, &mut merged, id, &skip)? {
        Exam::Ready(parts) => {
            tx.core.waits.unpended(id);
            if tx.core.ix.pending.remove(id).is_some() {
                tx.core.touch();
                tx.txn.remove_pending(id, Shred::Yes)?;
            }
            atomic::join_late(tx, id, &merged, parts)?;
            Ok(Ingested::Applied(*id))
        }
        Exam::Pending(r) => {
            tx.core.touch();
            tx.txn.put_pending(id, PendingKind::Pending, &blob.encode())?;
            tx.core.ix.pending.insert(*id, r.clone());
            tx.core.waits.pended(id);
            Ok(Ingested::Pending(*id, r))
        }
        Exam::Parked => Ok(Ingested::Parked(*id)),
    }
}

/// Applies a commit this node just built (no signature check: it signed it).
pub(crate) fn apply_local(tx: &mut Tx<'_>, blob: &CommitBlob, received: WallMs) -> Result<()> {
    let id = blob.id();
    let mut b = blob.clone();
    match examine(tx, &mut b, &id, &BTreeSet::new())? {
        Exam::Ready(parts) => {
            // writer-side rules: a received commit is judged by perm instead
            if !tx.core.skip_writer_rules {
                validity::check_content_rules(tx.core, &b.header, &parts)?;
            }
            apply_verified(tx, &b, parts, Origin::Local, received)?;
            // never emit a delta others would un-merge
            if !tx.core.skip_writer_rules && tx.core.ix.commits.get(&id).is_some_and(|m| m.valid.iter().any(|v| !v)) {
                return Err(Error::Permission { tid: b.header.aspects.first().map_or(b.header.author, |a| a.tid) });
            }
            Ok(())
        }
        _ => Err(Error::Misuse("own commit not applicable")),
    }
}

impl Engine {
    /// Whether every delta of `blob` hashes to its entry in the commit's header (the applied,
    /// resolved one when held; spec/commits.md §4): a blob of a held commit is otherwise never
    /// checked, its parts being skipped as held. `None` while a thing's `/created` (its dedup
    /// secret) or the resolved header is unknown (or fails to decode).
    pub fn parts_genuine(&self, blob: &CommitBlob) -> Option<bool> {
        let h = match self.core.ix.commits.get(&blob.id()) {
            Some(m) => m.header.decoded()?,
            None if blob.header.is_resolved() => Arc::new(blob.header.clone()),
            None => return None,
        };
        for p in &blob.parts {
            let Some(want) = h.aspects.get(p.ai).and_then(|a| a.hashes.get(p.di)) else { return Some(false) };
            let a = h.aspects.get(p.ai)?;
            let r = self.core.created(&a.tid)?;
            if osis_crypto::delta_hash(&dedup_secret(r.nonce()), &p.delta) != *want {
                return Some(false);
            }
        }
        Some(true)
    }

    /// Receives a commit blob's plaintext (`CommitBlobPlaintext`, spec/wire.md §4) with the page,
    /// chunk and header-list blobs it references (ciphertexts by ID). Bad input is reported as
    /// a diagnostic and returned as an error; nothing of it is stored.
    pub fn ingest(&mut self, bytes: &[u8], blobs: Vec<(BlobId, Vec<u8>)>) -> Result<Ingested> {
        self.ingest_from(bytes, blobs, None)
    }

    /// `ingest`, attributing diagnostics to `peer`.
    pub fn ingest_from(&mut self, bytes: &[u8], blobs: Vec<(BlobId, Vec<u8>)>, peer: Option<Tid>) -> Result<Ingested> {
        let _s = crate::costs::span("ingest");
        let r = self.run(|tx| {
            for (id, b) in blobs {
                if osis_label::blob_id(&b) == id {
                    tx.txn.put_blob(&id, b)?;
                }
            }
            match CommitBlob::decode(bytes) {
                Ok(blob) => ingest_blob(tx, blob, Origin::Remote),
                Err(e) if e.class() == ErrorClass::Parked => {
                    let id = raw_id(bytes)?;
                    tx.core.touch();
                    tx.txn.put_pending(&id, PendingKind::Parked, bytes)?;
                    tx.core.ix.pending.insert(id, Reason::Parked);
                    tx.core.waits.pended(&id);
                    Ok(Ingested::Parked(id))
                }
                Err(e) => Err(e.into()),
            }
        });
        match &r {
            Err(e) if e.class() == ErrorClass::BadInput => {
                let now = self.now();
                self.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::BadInput, tids: Vec::new(), commit: raw_id(bytes).ok(), peer, detail: e.to_string() }, now);
            }
            Ok(Ingested::Applied(_)) => self.reexamine()?,
            _ => {}
        }
        r
    }

    /// Re-examines pending and parked commits until none applies (after new certificates or
    /// `/created` records, a change of what this node syncs, time passing, or an upgrade).
    /// Membership commits are tried first. A commit whose examination's inputs have not changed
    /// since it was last examined is left out (`apply::waits`).
    pub fn reexamine(&mut self) -> Result<()> {
        let _s = crate::costs::span("reexamine");
        loop {
            let now = self.core.now().0;
            let ids = {
                let _s = crate::costs::span("reexamine: candidates");
                waits::candidates(&mut self.core, now)
            };
            #[cfg(debug_assertions)]
            self.check_unchanged(&ids);
            if ids.is_empty() {
                return Ok(());
            }
            let _s = crate::costs::span("reexamine: round");
            let progressed = self.run(|tx| {
                // a delta wait (`Core::waits`) is judged where its turn comes, without reading
                // it; the others are read and decoded first
                let mut blobs: Vec<(CommitId, Turn)> = Vec::new();
                for id in ids {
                    if let Some(w) = tx.core.waits.get(&id) {
                        blobs.push((id, Turn::Waiting(w.key)));
                        continue;
                    }
                    let Some((_, bytes)) = tx.txn.get_pending(&id)? else {
                        tx.core.ix.pending.remove(&id);
                        tx.core.waits.unpended(&id);
                        continue;
                    };
                    match CommitBlob::decode(&bytes) {
                        Ok(b) => blobs.push((id, Turn::Read(Box::new(b)))),
                        Err(_) => continue, // still unreadable by this build
                    }
                }
                blobs.sort_by_key(|(_, x)| match x {
                    Turn::Read(b) => (!b.header.kind.is_membership(), b.header.ts),
                    Turn::Waiting(k) => *k,
                });
                tx.core.touch();
                let mut progressed = false;
                for (id, b) in blobs {
                    let b = match b {
                        Turn::Read(b) => *b,
                        Turn::Waiting(_) if waits::still_waits(tx, &id)? => continue,
                        Turn::Waiting(_) => {
                            let Some((_, bytes)) = tx.txn.get_pending(&id)? else {
                                tx.core.ix.pending.remove(&id);
                                tx.core.waits.unpended(&id);
                                continue;
                            };
                            match CommitBlob::decode(&bytes) {
                                Ok(b) => b,
                                Err(_) => continue,
                            }
                        }
                    };
                    let things: Vec<Tid> = if b.header.kind.is_membership() { b.header.aspects.iter().map(|a| a.tid).collect() } else { Vec::new() };
                    match ingest_blob(tx, b, Origin::Remote) {
                        Ok(Ingested::Applied(_)) => progressed = true,
                        Ok(_) => {}
                        Err(e) if e.class() == ErrorClass::BadInput => {
                            tx.txn.remove_pending(&id, Shred::Yes)?;
                            tx.core.ix.pending.remove(&id);
                            tx.core.waits.unpended(&id);
                            keys::forget_unchecked(tx, &id)?;
                            // secrets read from its boxes go unless something else reads them
                            crate::rotation::mark_lost_due(tx, things)?;
                            let now = tx.now();
                            tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::BadInput, tids: Vec::new(), commit: Some(id), peer: None, detail: e.to_string() }, now);
                        }
                        Err(e) => return Err(e),
                    }
                }
                Ok(progressed)
            })?;
            if !progressed {
                return Ok(());
            }
        }
    }

    /// Checks that examining each pending commit but `candidates` again (in a transaction
    /// rolled back) gives the reason `Core::waits` kept it waiting for.
    #[cfg(debug_assertions)]
    fn check_unchanged(&mut self, candidates: &[CommitId]) {
        let ids: Vec<CommitId> = self.core.ix.pending.keys().filter(|id| !candidates.contains(id)).copied().collect();
        if ids.is_empty() {
            return;
        }
        let r: Result<()> = self.run(|tx| {
            for id in &ids {
                let Some((_, bytes)) = tx.txn.get_pending(id)? else { continue };
                let Ok(mut b) = CommitBlob::decode(&bytes) else { continue };
                let want = tx.core.ix.pending.get(id).cloned();
                match examine(tx, &mut b, id, &BTreeSet::new()) {
                    Ok(Exam::Pending(r)) => debug_assert_eq!(Some(r), want, "pending commit {id:?} left out of reexamine"),
                    Ok(Exam::Ready(_)) => debug_assert!(false, "pending commit {id:?} left out of reexamine would apply"),
                    Ok(Exam::Parked) => debug_assert!(false, "pending commit {id:?} left out of reexamine would park"),
                    Err(e) => debug_assert!(false, "pending commit {id:?} left out of reexamine: {e}"),
                }
            }
            Err(Error::Misuse("check only"))
        });
        debug_assert!(matches!(r, Err(Error::Misuse(_))), "{r:?}");
    }

    /// Starts or stops syncing `tid`: atomic apply waits only for deltas of synced things
    /// (spec/commits.md §4). Re-examines pending commits.
    pub fn set_syncing(&mut self, tid: Tid, on: bool) -> Result<()> {
        self.run(|tx| {
            tx.core.touch();
            // what pending commits wait for depends on what this node syncs
            if tx.core.ix.syncing.contains(&tid) != on {
                tx.core.waits.wake_thing(&tid);
            }
            let k = [records::SYNCING, tid.as_bytes()].concat();
            if on {
                tx.txn.put_local(&k, &[], Shred::No)?;
                tx.core.ix.syncing.insert(tid);
            } else {
                tx.txn.remove_local(&k, Shred::No)?;
                tx.core.ix.syncing.remove(&tid);
            }
            Ok(())
        })?;
        self.reexamine()
    }

    /// Pending and parked commits with their reasons (parked ones as `Unexamined`).
    pub fn pending(&self) -> Vec<(CommitId, Reason)> {
        self.core.ix.pending.iter().map(|(k, v)| (*k, v.clone())).collect()
    }

    /// The actors a label of `thing` known only by a hint is for (spec/sync.md §5: claims on a
    /// step not verified yet): its applied members and the members its applied `/secrets` boxes
    /// (one may read it through an actor a rotation boxed, with no grant held), and those that
    /// `inbox`, the pending commits of the inbox blobs that named the label, grant or box on it;
    /// those this node is or holds secrets of.
    pub fn hint_actors(&mut self, thing: &Tid, inbox: &[CommitId]) -> Result<std::collections::BTreeSet<Tid>> {
        let mut out: std::collections::BTreeSet<Tid> = self.get_typed(thing, &osis_schema::core_types::MEMBERS)?.unwrap_or_default().into_keys().collect();
        out.extend(self.get_typed(thing, &osis_schema::core_types::SECRETS)?.unwrap_or_default().boxes.into_keys().map(|k| k.member));
        for c in inbox {
            if !self.core.ix.pending.contains_key(c) {
                continue;
            }
            if let Some(b) = self.commit_bytes(c)?.and_then(|b| CommitBlob::decode(&b).ok()) {
                out.extend(keys::pending_grantees(&b, c, thing));
                for (a, w) in keys::pending_secrets_writes(&b, c) {
                    if a == *thing {
                        out.extend(w.boxes.into_keys().map(|k| k.member));
                    }
                }
            }
        }
        let me = self.core.id.tid();
        out.retain(|t| *t == me || self.core.ix.secrets.contains_key(t));
        Ok(out)
    }

    /// The stored bytes of a held commit (applied: its current blob; pending or parked: as
    /// received), for relaying.
    pub fn commit_bytes(&mut self, id: &CommitId) -> Result<Option<Vec<u8>>> {
        let id = *id;
        self.run(|tx| {
            if let Some(b) = tx.get_commit(&id)? {
                return Ok(Some(b.encode()));
            }
            Ok(tx.txn.get_pending(&id)?.map(|x| x.1))
        })
    }

    /// The blob ciphertext `id`, if held (pages, chunks, header-list trees).
    pub fn blob(&mut self, id: &BlobId) -> Result<Option<Vec<u8>>> {
        let id = *id;
        self.run(|tx| Ok(tx.txn.get_blob(&id)?))
    }

    /// IDs of applied commits, in (`ts`, ID) order.
    pub fn commit_ids(&self) -> Vec<CommitId> {
        let mut v: Vec<(osis_base::Ts, CommitId)> = self.core.ix.commits.iter().map(|(id, m)| (m.view.ts, *id)).collect();
        v.sort();
        v.into_iter().map(|x| x.1).collect()
    }

    /// The header of an applied commit (none if its stored bytes fail to decode: `LazyHeader`).
    pub fn header(&self, id: &CommitId) -> Option<Arc<Header>> {
        self.core.ix.commits.get(id).and_then(|m| m.header.decoded())
    }

    /// The commit that created `tid`: the oldest held commit carrying its `/created` that is
    /// valid here (no durable snapshot carries `/created`, spec/commits.md §2).
    /// `/created` is kept forever, so every node reading the thing gets that commit; until it
    /// is here (only a snapshot held) `None`.
    pub fn creation(&self, tid: &Tid) -> Option<Creation> {
        if let Some(e) = self.ephemeral_thing(tid) {
            return Some(Creation { commit: None, ts: e.ts, node: e.node, actor: e.actor, received: e.received });
        }
        let ak = osis_base::Ak::new("/created").ok()?;
        self.core.ix.by_aspect.get(&(*tid, ak.clone()))?.iter().find_map(|(_, id)| {
            let m = self.core.ix.commits.get(id)?;
            let ai = m.header.aspects.iter().position(|a| a.tid == *tid && a.ak == ak)?;
            (m.valid.get(ai).copied().unwrap_or(false)).then(|| Creation { commit: Some(*id), ts: m.header.ts, node: m.header.author, actor: m.header.actor, received: m.received })
        })
    }

    /// The thing's last content change: of the held content commits (changes, reverts,
    /// imports) validly writing one of its aspects other than `/created`, `/group` and the
    /// membership-class ones, the one shown latest by `min(ts, received)` (an author's clock may
    /// run ahead; `received` is this node's), else its creation. Snapshots are no change, and
    /// ephemeral writes do not count (an ephemeral thing reports its creation).
    pub fn changed(&self, tid: &Tid) -> Option<Creation> {
        let shown = |c: &Creation| c.ts.wall_ms().min(c.received);
        let mut best = self.creation(tid);
        let aspects = self.core.ix.by_aspect.range((*tid, osis_base::Ak::MIN)..).take_while(|((t, _), _)| t == tid);
        for ((_, ak), ids) in aspects {
            let a = ak.as_str();
            if a == "/created" || a == "/group" || osis_schema::core_types::is_membership_class(a) {
                continue;
            }
            for (ts, id) in ids.iter().rev() {
                // shown <= ts: nothing older can be shown later than the best so far
                if best.as_ref().is_some_and(|b| ts.wall_ms() <= shown(b)) {
                    break;
                }
                let Some(m) = self.core.ix.commits.get(id) else { continue };
                let valid = m.header.aspects.iter().enumerate().any(|(ai, x)| x.tid == *tid && x.ak == *ak && m.valid.get(ai).copied().unwrap_or(false));
                if !matches!(m.header.kind, Kind::Content | Kind::Import) || !valid {
                    continue;
                }
                let c = Creation { commit: Some(*id), ts: m.header.ts, node: m.header.author, actor: m.header.actor, received: m.received };
                if best.as_ref().is_none_or(|b| shown(&c) > shown(b)) {
                    best = Some(c);
                }
            }
        }
        best
    }
}

/// Rebuilds the engine's indexes from the store (open, and after forgetting): from the persisted
/// index when this build wrote it (`engine::index`: commit metas with their validity, the
/// indexes derived from membership bodies, perm's reading of each membership commit; no part is
/// decoded), else from every commit record, re-judging every delta. Returns whether it rebuilt
/// (the persisted index is then to be written).
/// Rebuilds `(tid, ak)` from its held bodies under the current judgments, and what it derives.
pub(crate) fn rejoin(tx: &mut Tx<'_>, tid: &Tid, ak: &osis_base::Ak) -> Result<()> {
    atomic::rebuild(tx, tid, ak)?;
    atomic::observe_state(tx, tid, ak)
}

/// Loads the in-memory indexes; `Some(aspects)` when they were rebuilt from the commit records:
/// the aspects whose judgments differ from what the replaced index held (their states follow
/// the old judgments until rebuilt; every aspect with something invalid when that index does
/// not decode).
pub(crate) fn load(tx: &mut Tx<'_>, rebuild: bool) -> Result<Option<Vec<(Tid, osis_base::Ak)>>> {
    if let Some(b) = tx.txn.get_local(records::HLC)?
        && let Ok(a) = <[u8; 8]>::try_from(b.as_slice())
        && let Some(ts) = osis_base::Ts::from_u64(u64::from_be_bytes(a))
    {
        tx.core.hlc.observe(ts);
    }
    let mut created = Vec::new();
    tx.scan(records::CREATED, |_, v| {
        let lim = osis_base::Limits { max_depth: 8, max_bytes: v.len() };
        let rec = osis_base::decode(&v, &lim).ok().and_then(|v| CreationRecord::from_value(&v)).ok_or(Error::Corrupt("creation record"))?;
        created.push(rec);
        Ok(())
    })?;
    for r in created {
        tx.core.ix.held.create(r);
    }
    let mut syncing = Vec::new();
    tx.scan(records::SYNCING, |k, _| {
        syncing.push(Tid::from_bytes(k.try_into().map_err(|_| Error::Corrupt("syncing"))?));
        Ok(())
    })?;
    tx.core.ix.syncing.extend(syncing);
    let mut void = Vec::new();
    tx.scan(records::VOID, |k, _| {
        void.push(CommitId(k.try_into().map_err(|_| Error::Corrupt("void"))?));
        Ok(())
    })?;
    tx.core.ix.void.extend(void);
    let mut vl = Vec::new();
    tx.scan(records::VALUELESS, |k, v| {
        vl.push((k.to_vec(), v));
        Ok(())
    })?;
    for (k, v) in vl {
        let mut r = records::Rd::new(&k);
        let (tid, ak) = (r.tid()?, r.ak()?);
        tx.core.ix.valueless.insert((tid, ak), crate::retention::decode_owned(&v)?);
    }
    let mut secrets = Vec::new();
    tx.scan(b"k/", |k, v| {
        let t = Tid::from_bytes(k.try_into().map_err(|_| Error::Corrupt("secrets"))?);
        secrets.push((t, crate::engine::secrets::decode_epochs(&v)?));
        Ok(())
    })?;
    tx.core.ix.secrets.extend(secrets);
    let mut schemas = Vec::new();
    tx.scan(records::SCHEMAS, |_, v| {
        let bad = |_| Error::Corrupt("schema");
        let v = osis_base::decode(&v, &osis_base::Limits::default()).map_err(bad)?;
        schemas.push(osis_schema::Schema::from_value(&v).map_err(|_| Error::Corrupt("schema"))?);
        Ok(())
    })?;
    tx.core.schemas.extend(schemas.into_iter().map(|s| (s.id, std::sync::Arc::new(s))));
    let fast = !rebuild && crate::engine::index::current(tx)?;
    let old = if fast { None } else { crate::engine::index::old_judgments(tx) };
    if fast {
        {
            let _s = crate::costs::span("open: index");
            crate::engine::index::load(tx)?;
        }
        let _s = crate::costs::span("open: adapt");
        // perm's inputs: the edge writes of the membership commits, oldest first, from what the
        // index keeps of their bodies
        let mut edges = crate::engine::index::load_edges(tx)?;
        let mut ids: Vec<(osis_base::Ts, CommitId)> = tx.core.ix.commits.iter().filter(|(_, m)| m.view.kind.is_membership()).map(|(id, m)| (m.view.ts, *id)).collect();
        ids.sort();
        for (_, id) in ids {
            // the view, not the header (decoded only for a roster snapshot's linked frontiers)
            let Some(v) = tx.core.ix.commits.get(&id).map(|m| m.view.clone()) else { continue };
            let parts = edges.remove(&id).ok_or(Error::Corrupt("edges row missing"))?;
            // every row is what its record reads now (rewritten with it: late parts, drops)
            #[cfg(debug_assertions)]
            debug_assert_eq!(parts, edge_parts(tx, &id)?, "node/edges row of {id:?} is stale");
            validity::add_membership(tx, &v, None, &id, &parts)?;
        }
        drop(_s);
    } else {
        // applied commits
        let mut recs = Vec::new();
        tx.scan(records::COMMIT, |_, v| {
            recs.push(decode_commit_record(&v)?);
            Ok(())
        })?;
        let mut bodies = Vec::new();
        let mut snaps = Vec::new();
        for (head, mut blob) in recs {
            if !blob.header.is_resolved()
                && let Some(dedup) = tx.core.dedup(&blob.header.actor)
            {
                blob.header.resolve(&mut TxBlobs::new(&mut tx.txn), &dedup, MAX_LIST_BYTES).map_err(|_| Error::Corrupt("header lists"))?;
            }
            let id = blob.id();
            let h = Arc::new(blob.header.clone());
            let valid = vec![true; h.aspects.len()];
            let missing = (0..h.aspects.len()).filter(|ai| !blob.parts.iter().any(|p| p.ai == *ai) && !head.dropped.contains_key(ai)).collect();
            let m = Meta::new(h.clone(), valid, head, missing);
            // what a dropped part judged, kept in its record (`Dropped::role`)
            for (ai, d) in &m.dropped {
                if let Some(r) = d.role {
                    tx.core.ix.rotation_role.insert((id, *ai), r);
                }
                if d.overreach {
                    tx.core.ix.grant_overreach.insert((id, *ai));
                }
                if let Some(a) = h.aspects.get(*ai) {
                    for (r, e) in &d.intros {
                        keys::note_intro(tx.core, &h, &a.tid, *r, *e);
                    }
                }
            }
            atomic::index_commit(tx.core, &id, &m.view);
            validity::note_imports(tx.core, &id, &h, &[]).map_err(|_| Error::Corrupt("commit imports"))?;
            tx.core.ix.commits.insert(id, m);
            atomic::note_gives(tx.core, &id);
            if blob.header.kind.is_compaction() {
                snaps.push(blob.clone());
            }
            if blob.header.kind.is_membership() {
                bodies.push(blob);
            }
        }
        // snapshots: their frontiers (the bodies carrying a write, `retention::carriers`) and
        // the writes they carry whose own delta was never received
        for blob in snaps {
            let id = blob.id();
            let mut b = blob.clone();
            if let Exam::Ready(parts) = examine_stored(tx, &mut b, &id)? {
                for (ai, _, d) in parts {
                    if let (Some(a), Decoded::Snapshot(s)) = (b.header.aspects.get(ai), d) {
                        validity::note_carried(tx.core, &a.tid, &a.ak, &id, &s.fragment);
                        atomic::note_snapshot(tx.core, &a.tid, &a.ak, b.header.ts, &id, (s.frontiers, s.absorbed.into_iter().collect()));
                    }
                }
            }
        }
        // perm inputs from membership bodies, oldest first
        bodies.sort_by_key(|b| b.header.ts);
        for blob in bodies {
            let id = blob.id();
            let mut b = blob.clone();
            if let Exam::Ready(parts) = examine_stored(tx, &mut b, &id)? {
                validity::note_required(tx.core, &b.header, &id, &parts);
                for (ai, _, d) in &parts {
                    if let (Some(a), Decoded::Delta(d)) = (b.header.aspects.get(*ai), d) {
                        match a.ak.as_str() {
                            "/secrets" => keys::note_box_keys(tx.core, &b.header, &a.tid, &d.fragment),
                            "/keys" => keys::note_keysets(tx.core, &b.header, &a.tid, &d.fragment),
                            _ => {}
                        }
                    }
                }
                let v = tx.core.ix.commits.get(&id).map(|m| m.view.clone()).ok_or(Error::Corrupt("commit meta"))?;
                validity::add_membership(tx, &v, Some(&b.header), &id, &validity::EdgeParts::of(&b.header, &parts))?;
            }
        }
    }
    // a commit read before the record it needs (a nested edge write `ts`-ordered before its
    // grant: another node's clock) is derived now, as it was when that record arrived
    validity::resolve_unresolved(tx)?;
    if fast {
        let _s = crate::costs::span("open: walks");
        crate::engine::index::update_timelines_saved(tx)?;
    } else {
        tx.core.update_timelines();
    }
    crate::rotation::load_lost_due(tx)?;
    crate::retention::load_deaths_due(tx)?;
    let mut pend = Vec::new();
    let mut after: Option<CommitId> = None;
    loop {
        let page = tx.txn.pending(after.as_ref(), 256)?;
        let n = page.len();
        for (id, k, _) in page {
            pend.push((id, k));
            after = Some(id);
        }
        if n < 256 {
            break;
        }
    }
    for (id, k) in pend {
        tx.core.ix.pending.insert(id, if k == PendingKind::Parked { Reason::Parked } else { Reason::Unexamined });
    }
    // derived indexes from states (secrets, own keys: persisted, read again on a rebuild)
    let mut aspects = Vec::new();
    tx.scan(crate::engine::records::ASPECTS, |k, _| {
        let mut r = records::Rd::new(k);
        aspects.push((r.tid()?, r.ak()?));
        Ok(())
    })?;
    for (tid, ak) in aspects {
        match ak.as_str() {
            // definitions first, derived once below
            "/group" => {
                let v = tx.state(&tid, &ak)?.and_then(osis_crdt::Fragment::read);
                tx.core.ix.groups.set_def(tid, atomic::group_def(v));
            }
            "/secrets" | "/keys" if fast => {}
            _ => atomic::observe_state(tx, &tid, &ak)?,
        }
    }
    tx.core.ix.groups.rebuild();
    if fast {
        // every delta's validity is persisted: nothing to re-judge
        tx.core.stale_things.clear();
        tx.core.stale_commits.clear();
        tx.core.stale_all = false;
    } else {
        tx.core.stale_all = true;
        validity::rejudge_all(tx, false)?;
    }
    if fast {
        return Ok(None);
    }
    // aspects whose judgments changed with the rules (or that hold anything invalid when the
    // old judgments are unknown)
    let mut stale: BTreeSet<(Tid, osis_base::Ak)> = BTreeSet::new();
    for (id, m) in tx.core.ix.commits.iter() {
        for (ai, a) in m.view.aspects.iter().enumerate() {
            let now = m.valid.get(ai).copied().unwrap_or(false);
            let was = old.as_ref().map(|o| o.get(id).and_then(|v| v.get(ai)).copied().unwrap_or(true));
            if was.map_or(!now, |w| w != now) {
                stale.insert((a.tid, a.ak.clone()));
            }
        }
    }
    stale.retain(|(_, ak)| !matches!(ak.as_str(), "/members" | "/tenures" | "/created"));
    Ok(Some(stale.into_iter().collect()))
}

/// Decodes a stored (already verified) commit's parts.
fn examine_stored(tx: &mut Tx<'_>, blob: &mut CommitBlob, id: &CommitId) -> Result<Exam> {
    let h = blob.header.clone();
    let mut out = Vec::new();
    let mut interner = Interner::new();
    for p in &blob.parts {
        let a = h.aspects.get(p.ai).ok_or(Error::Corrupt("part index"))?;
        let dedup = tx.core.dedup(&a.tid).ok_or(Error::Corrupt("dedup"))?;
        let mut blobs = TxBlobs::new(&mut tx.txn);
        let mut reader = BlobReader::new(&dedup, &mut blobs);
        out.push((p.ai, p.di, verify_part(&h, id, p, &dedup, &mut interner, Some(&mut reader)).map_err(|_| Error::Corrupt("stored delta"))?));
    }
    Ok(Exam::Ready(out))
}

/// What perm's adaptation reads of a held membership commit: its held `/members` and `/tenures`
/// parts.
pub(crate) fn edge_parts(tx: &mut Tx<'_>, id: &CommitId) -> Result<validity::EdgeParts> {
    let Some(h) = tx.core.ix.commits.get(id).map(|m| m.header.clone()) else { return Ok(validity::EdgeParts::default()) };
    let Some(blob) = tx.get_commit(id)? else { return Ok(validity::EdgeParts::default()) };
    edge_parts_of(tx, id, &h, blob)
}

/// `edge_parts` of a commit record's blob (`h`: its resolved header).
pub(crate) fn edge_parts_of(tx: &mut Tx<'_>, id: &CommitId, h: &Header, mut blob: CommitBlob) -> Result<validity::EdgeParts> {
    blob.header = h.clone();
    blob.parts.retain(|p| h.aspects.get(p.ai).is_some_and(|a| matches!(a.ak.as_str(), "/members" | "/tenures")));
    match examine_stored(tx, &mut blob, id)? {
        Exam::Ready(v) => Ok(validity::EdgeParts::of(h, &v)),
        _ => Ok(validity::EdgeParts::default()),
    }
}

/// Decoded parts of a held commit on aspect `ai`.
pub(crate) fn held_parts(tx: &mut Tx<'_>, id: &CommitId, ai: usize) -> Result<Vec<Decoded>> {
    Ok(held_parts_at(tx, id, &|x| x == ai)?.into_iter().map(|x| x.2).collect())
}

/// Decoded parts of a held commit on the aspects `keep` selects, with their indexes.
pub(crate) fn held_parts_at(tx: &mut Tx<'_>, id: &CommitId, keep: &dyn Fn(usize) -> bool) -> Result<Vec<(usize, usize, Decoded)>> {
    let Some(mut blob) = tx.get_commit(id)? else { return Ok(Vec::new()) };
    if let Some(m) = tx.core.ix.commits.get(id) {
        blob.header = (*m.header).clone();
    }
    blob.parts.retain(|p| keep(p.ai));
    match examine_stored(tx, &mut blob, id)? {
        Exam::Ready(v) => Ok(v),
        _ => Ok(Vec::new()),
    }
}

/// A commit as a thing's time (`Engine::creation`, `Engine::changed`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Creation {
    /// `None` while the thing is ephemeral (notes/ephemeral.md).
    pub commit: Option<CommitId>,
    pub ts: osis_base::Ts,
    pub node: Tid,
    pub actor: Tid,
    pub received: WallMs,
}

#[cfg(test)]
mod tests {
    use crate::local_peer::LocalPeer;
    use crate::{Ingested, Mutation};
    use osis_base::{Ak, Role, Value, WallMs};
    use osis_crdt::{Op, PathOp, PathSeg};
    use osis_schema::Codec;
    use osis_schema::core_types as ct;

    // spec/permissions.md §5.1; spec/commits.md §2: the membership content rules bind writers
    // only; a received commit breaking them is applied and judged by perm per edge write, so
    // delivery order cannot change the held set.
    #[test]
    fn content_rules_writer_side_only_spec_perm_5_1() {
        let mut lp = LocalPeer::new(2, 900, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let p0 = &mut lp.peers[0];
        let me = p0.engine.tid();
        let mut m = Mutation::new();
        let t = p0.engine.new_thing(&mut m, me);
        m.set(t, &Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        p0.commit(m).unwrap();
        let b = lp.peers[1].engine.tid();
        let c = osis_base::Tid::from_bytes([7; 15]);
        let mut m = Mutation::new();
        for x in [b, c] {
            let e = ct::Edge { role: Role::Write, until: None, invite: None, since: None };
            m.op(t, &ct::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(x))], op: Op::Set(e.to_value()) }).unwrap();
        }
        lp.peers[0].engine.core.skip_writer_rules = true;
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
        for p in lp.packages(0).unwrap() {
            if p.id != id {
                lp.deliver(1, &p).unwrap();
            }
        }
        assert_eq!(lp.deliver(1, &pk).unwrap(), Ingested::Applied(id));
        assert_eq!(lp.peers[1].engine.roster(&t), lp.peers[0].engine.roster(&t));
        assert_eq!(lp.peers[1].engine.role_on(&t), Some(Role::Write));
    }

    // spec/permissions.md §1 (an owner holds admin on what it owns; owner chains within
    // MAX_OWNER_DEPTH), §5: a writer creates A under X, B under A and C under B in one commit;
    // the commit is valid wherever applied. Owned by a thing the writer may not write, the same
    // tree fails the local check, as does a chain of new things past MAX_OWNER_DEPTH.
    #[test]
    fn tree_created_in_one_commit_spec_perm_1() {
        let mut lp = LocalPeer::new(2, 901, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (a0, a1) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
        let reg = Ak::new("/x/a").unwrap();
        let mut things = Vec::new();
        for _ in 0..2 {
            let mut m = Mutation::new();
            let t = lp.peers[0].engine.new_thing(&mut m, a0);
            m.set(t, &reg, &Value::Int(0)).unwrap();
            lp.peers[0].commit(m).unwrap();
            things.push(t);
        }
        let (x, y) = (things[0], things[1]);
        let mut m = Mutation::new();
        let e = ct::Edge { role: Role::Write, until: None, invite: None, since: None };
        m.op(x, &ct::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(a1))], op: Op::Set(e.to_value()) }).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.sync_all().unwrap();
        let p1 = &mut lp.peers[1];
        let mut m = Mutation::new();
        let a = p1.engine.new_thing(&mut m, x);
        let b = p1.engine.new_thing(&mut m, a);
        let c = p1.engine.new_thing(&mut m, b);
        for (i, t) in [a, b, c].into_iter().enumerate() {
            m.set(t, &reg, &Value::Int(i as i64 + 1)).unwrap();
        }
        let id = p1.commit(m).unwrap().unwrap();
        let pk = p1.engine.package(&id).unwrap().unwrap();
        assert_eq!(lp.deliver(0, &pk).unwrap(), Ingested::Applied(id));
        let p0 = &mut lp.peers[0];
        assert!(p0.engine.core.ix.commits.get(&id).unwrap().valid.iter().all(|v| *v));
        assert!(p0.engine.pending().is_empty());
        for (i, t) in [a, b, c].into_iter().enumerate() {
            assert!(p0.engine.creation(&t).is_some());
            assert_eq!(p0.engine.get(&t, &reg).unwrap(), Some(Value::Int(i as i64 + 1)));
        }
        // the owner's tree: the last thing's delete keys derive from its owner's secrets
        // through the two created above it (spec/crypto.md §3, §7)
        let mut m = Mutation::new();
        let d = p0.engine.new_thing(&mut m, x);
        let e = p0.engine.new_thing(&mut m, d);
        let f = p0.engine.new_thing(&mut m, e);
        m.set(f, &reg, &Value::Int(4)).unwrap();
        m.retention(f, &reg, osis_schema::Retention { by: osis_schema::PurgeBy::Writer, ..Default::default() }).unwrap();
        let id = p0.commit(m).unwrap().unwrap();
        let h = p0.engine.header(&id).unwrap();
        let wf = h.aspects.iter().find(|w| w.tid == f && w.ak == reg).unwrap();
        let levels: Vec<u8> = wf.keys.iter().map(|i| h.keys[*i].level).collect();
        assert_eq!(levels, [1, 2, 3]);
        // a writer of X gets no admin on what it creates below X: no edges there
        let adm = ct::Edge { role: Role::Admin, until: None, invite: None, since: None };
        for depth in [1, 3] {
            let p1 = &mut lp.peers[1];
            let mut m = Mutation::new();
            let mut cur = x;
            for _ in 0..depth {
                cur = p1.engine.new_thing(&mut m, cur);
            }
            m.op(cur, &ct::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(a1))], op: Op::Set(adm.to_value()) }).unwrap();
            assert!(matches!(p1.commit(m), Err(crate::Error::Permission { .. })), "depth {depth}");
        }
        // under Y (no role there) the tree is refused
        let p1 = &mut lp.peers[1];
        let mut m = Mutation::new();
        let a = p1.engine.new_thing(&mut m, y);
        p1.engine.new_thing(&mut m, a);
        assert!(matches!(p1.commit(m), Err(crate::Error::Permission { .. })));
        let mut m = Mutation::new();
        let a = p1.engine.new_thing(&mut m, x);
        let b = p1.engine.new_thing(&mut m, y);
        p1.engine.new_thing(&mut m, a);
        p1.engine.new_thing(&mut m, b);
        assert!(matches!(p1.commit(m), Err(crate::Error::Permission { .. })));
        // a chain of new things: at the cap it commits, one deeper is refused before signing
        for (extra, ok) in [(0, true), (1, false)] {
            let p0 = &mut lp.peers[0];
            let before = p0.engine.commit_ids().len();
            let mut m = Mutation::new();
            let mut cur = a0;
            for _ in 0..osis_base::format::MAX_OWNER_DEPTH + extra {
                cur = p0.engine.new_thing(&mut m, cur);
            }
            m.set(cur, &reg, &Value::Int(7)).unwrap();
            let r = p0.commit(m);
            assert_eq!(r.is_ok(), ok, "{r:?}");
            if !ok {
                assert!(matches!(r, Err(crate::Error::Permission { tid }) if tid == cur));
                assert_eq!(p0.engine.commit_ids().len(), before);
            }
        }
    }

    // a header held as bytes that fail to decode (hash or format: `LazyHeader`) reads as none
    // outside a transaction, and every later transaction fails as corrupt, never a default
    #[test]
    fn failed_lazy_header_is_corrupt() {
        let mut lp = LocalPeer::new(1, 902, WallMs(1_700_000_000_000)).unwrap();
        let p0 = &mut lp.peers[0];
        let me = p0.engine.tid();
        let mut m = Mutation::new();
        let t = p0.engine.new_thing(&mut m, me);
        m.set(t, &Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        let id = p0.commit(m).unwrap().unwrap();
        let blob = p0.engine.run(|tx| tx.get_commit(&id)).unwrap().unwrap();
        let c = &mut p0.engine.core;
        let mut meta = c.ix.commits.get(&id).unwrap().clone();
        meta.header = crate::engine::LazyHeader::stored(id, vec![0x80].into(), meta.view.clone(), c.header_fault.clone());
        c.ix.commits.insert(id, meta);
        assert!(p0.engine.header(&id).is_none());
        assert_eq!(p0.engine.parts_genuine(&blob), None);
        let mut m = Mutation::new();
        m.set(t, &Ak::new("/x/a").unwrap(), &Value::Int(2)).unwrap();
        assert!(matches!(p0.engine.commit(m), Err(crate::Error::Corrupt(_))));
        assert!(matches!(p0.engine.commit(Mutation::new()), Err(crate::Error::Corrupt(_))));
    }
}
