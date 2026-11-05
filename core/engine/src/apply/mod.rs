//! Receiving commits (spec/commits.md §4; spec/versioning.md §2; spec/crdt.md §2.2): decode,
//! verify, dedup by commit ID, pending reasons and parking, re-examination, apply in one
//! store transaction (role before content), late deltas of applied commits. Loading the
//! engine's indexes from the store lives here too, since it replays what apply records.

mod atomic;
pub(crate) mod copies;
pub(crate) mod free;
pub(crate) mod memory;
mod waits;
pub(crate) mod keys;
pub(crate) mod receipt;
pub(crate) mod validity;
#[cfg(test)]
mod tests_validity;
#[cfg(test)]
mod tests_linked;
#[cfg(test)]
mod tests_order;
#[cfg(test)]
mod oracle;
#[cfg(test)]
mod tests_paged;

pub(crate) use free::unindex_commit;
pub use memory::PART_OVERHEAD;
pub(crate) use waits::Waits;
#[cfg(debug_assertions)]
pub(crate) use atomic::check_rebuilt;
pub(crate) use atomic::{Unmerge, apply_verified, carries_any, forget_snapshot, index_commit, note_stands_in, ingest_secrets_keys, invalid_of, rebuild, rebuilt, strip_valueless};

use crate::engine::blobs::TxBlobs;
use crate::engine::{Engine, Meta, Tx, decode_commit_record, records};
use crate::error::{Error, Result};
use crate::events::{Diagnostic, DiagnosticKind, Origin};
use osis_commit::{CommitBlob, Decoded, Header, Kind, delta_ctx, verify_part};
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{BlobId, ChainStep, Classified, CommitId, CreationRecord, ErrorClass, Tid, Value, WallMs};
use osis_crdt::Interner;
use osis_crypto::{VerifyingKey, dedup_secret};
use osis_label::BlobReader;
use osis_store::{PendingKind, Shred};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Why a commit is pending (spec/commits.md §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The `created.0` record (key) of the author or of a thing on an owner chain is missing.
    MissingChain(Tid),
    /// The `created.0` record of a thing whose part it holds is unknown.
    UnknownCreated(Tid),
    /// `ts` more than `MAX_DRIFT` ahead of the corrected clock.
    Drift,
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
    /// A memory commit not held nor kept waiting: its parts could cost more decoded than the
    /// room given (`Engine::ingest_memory`), found before decoding them.
    TooLarge(CommitId),
}

pub(crate) enum Exam {
    /// `Parts::waiting`: the parts that wait alone, taken out of the blob.
    Ready(Parts),
    /// Every part waits: the first reason and any other (`waits::note` may keep them).
    Pending(Reason, Vec<Reason>),
    Parked,
}

/// Parts of an examined commit that wait alone (`examine`): the first reason, the others, and which.
#[derive(Default)]
struct Aside {
    reason: Option<Reason>,
    others: Vec<Reason>,
    keys: BTreeSet<(usize, usize)>,
}

impl Aside {
    /// `keys` wait for `r`.
    fn add(&mut self, r: Reason, keys: impl IntoIterator<Item = (usize, usize)>) {
        let before = self.keys.len();
        self.keys.extend(keys);
        if self.keys.len() > before {
            match &self.reason {
                None => self.reason = Some(r),
                Some(x) if *x != r && !self.others.contains(&r) => self.others.push(r),
                Some(_) => {}
            }
        }
    }
    /// The verdict when no part is left to apply.
    fn verdict(self) -> Exam {
        match self.reason {
            Some(Reason::Parked) if self.others.is_empty() => Exam::Parked,
            Some(r) => Exam::Pending(r, self.others),
            None => Exam::Parked,
        }
    }
}

/// Parts `examine` set aside: stored pending under the commit's ID while the rest apply.
pub(crate) struct Waiting {
    pub parts: Vec<osis_commit::Part>,
    pub reason: Reason,
    /// Any other reason.
    pub others: Vec<Reason>,
}

impl Waiting {
    fn copy(&self) -> Waiting {
        Waiting { parts: self.parts.clone(), reason: self.reason.clone(), others: self.others.clone() }
    }
}

/// A part `examine` checked and keeps no content of: apply streams it again, one page at a
/// time (issues/durable-decode-bound.md).
pub(crate) struct Streamed {
    pub ai: usize,
    pub di: usize,
    /// Its thing's dedup secret (its hash, its pages' keys).
    pub dedup: osis_crypto::Secret32,
    /// A snapshot's frontiers and `Absorbed`.
    pub gives: Option<crate::engine::Gives>,
}

/// A commit's examined parts. Those of role-class aspects and `created.0` are decoded whole:
/// their readers (perm's edges, rotations, creation records) read them whole, and they hold
/// rosters of thousands, not millions; the rest are streamed.
#[derive(Default)]
pub(crate) struct Parts {
    pub whole: Vec<(usize, usize, Decoded)>,
    pub streamed: Vec<Streamed>,
    /// Held parts that wait alone (spec/commits.md §4).
    pub waiting: Option<Waiting>,
    /// Why the first part judged bad was (`examine`): dropped alone, or for a commit this node
    /// writes a refusal.
    pub bad: Option<Error>,
    /// Aspects of the parts in `whole` held value-less while they waited
    /// (`retention::strip_purged`): held so once joined (`retention::stripped_joined`).
    pub stripped: Vec<usize>,
}

impl Parts {
    /// The parts joined from stripped deltas (`stripped`): aspect and fragment.
    pub(crate) fn stripped_joined(&self) -> Vec<(usize, osis_crdt::Fragment)> {
        self.whole.iter().filter(|x| self.stripped.contains(&x.0)).map(|(ai, _, d)| (*ai, d.fragment().clone())).collect()
    }

    /// Whether a part of aspect `ai` is held.
    pub(crate) fn has(&self, ai: usize) -> bool {
        self.whole.iter().any(|p| p.0 == ai) || self.streamed.iter().any(|p| p.ai == ai)
    }
    /// The aspects with a part.
    pub(crate) fn ais(&self) -> BTreeSet<usize> {
        self.whole.iter().map(|p| p.0).chain(self.streamed.iter().map(|p| p.ai)).collect()
    }
}

/// The storage class of a commit's aspects: a key's lifetime marker, alike at every node
/// (spec/commits.md §2). A part on an aspect of another is never applied, by anyone.
fn class_of(h: &Header) -> osis_base::Lifetime {
    if h.ephemeral.is_some() { osis_base::Lifetime::Ephemeral } else { osis_base::Lifetime::Durable }
}

/// Whether a part of aspect `ak` is decoded whole (`Parts`).
fn whole_part(ak: &str) -> bool {
    osis_schema::core_types::is_role_class(ak) || ak == osis_commit::retention::CREATED
}

/// Commit ID of a blob whose header this build cannot decode: BLAKE3 of the header value.
fn raw_id(bytes: &[u8]) -> Result<CommitId> {
    let lim = osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: bytes.len() };
    let v = osis_base::decode(bytes, &lim).map_err(|_| Error::BadInput("commit blob"))?;
    let Value::List(items) = v else { return Err(Error::BadInput("commit blob")) };
    let h = items.first().ok_or(Error::BadInput("commit blob"))?;
    Ok(CommitId(osis_base::hash::hash(&osis_base::encode(h))))
}

pub(crate) fn is_missing_page(e: &osis_commit::Error) -> bool {
    matches!(e, osis_commit::Error::Delta(osis_crdt::Error::Page(osis_crdt::PageError::Missing)) | osis_commit::Error::Missing)
}

/// The creation record a durable `created.0` part `p` mints, decoded without a hash check (the part
/// is verified later under the record's own dedup secret): a record hashes to its tid, so no relay
/// can forge one.
fn minted_record(h: &Header, id: &CommitId, p: &osis_commit::Part, tid: &Tid, interner: &mut Interner) -> Result<CreationRecord> {
    let cx = delta_ctx(h, id, p.ai, interner)?;
    let d = osis_crdt::decode_delta(&p.delta, &cx, interner, None)?;
    let v = d.fragment.read().ok_or(Error::BadInput("empty created.0"))?;
    let rec = CreationRecord::from_value(&v).ok_or(Error::BadInput("created.0 is not a creation record"))?;
    if rec.tid() != *tid {
        return Err(Error::BadInput("created.0 does not hash to its tid"));
    }
    if !crate::engine::write::is_minting(&d.fragment, &rec) {
        return Err(Error::BadInput("created.0 is not one minting of its record"));
    }
    Ok(rec)
}

/// Creation records a commit carries: a durable one's on `created.0` (`minted_record`; a part giving
/// none gives nothing here, and is judged alone in `examine` once it can be), an ephemeral one's
/// beside its deltas (a record hashes to its tid, spec/commits.md §2).
pub(crate) fn carried_records(h: &Header, blob: &CommitBlob, id: &CommitId) -> BTreeMap<Tid, CreationRecord> {
    let mut out = BTreeMap::new();
    if h.ephemeral.is_some() {
        for r in blob.parts.iter().flat_map(|p| &p.records) {
            out.insert(r.tid(), r.clone());
        }
        return out;
    }
    let mut interner = Interner::new();
    for p in &blob.parts {
        let Some(a) = h.aspects.get(p.ai) else { continue };
        if a.ak.as_str() != osis_commit::retention::CREATED {
            continue;
        }
        if let Ok(rec) = minted_record(h, id, p, &a.tid, &mut interner) {
            out.insert(a.tid, rec);
        }
    }
    out
}

fn check_signature(tx: &mut Tx<'_>, blob: &CommitBlob, id: &CommitId, vk: &VerifyingKey) -> Result<()> {
    let _s = crate::costs::span("examine: signature");
    if let Err(e) = osis_commit::verify_signature(id, &blob.signature, vk) {
        // the first copy's signature, kept while the author was away: a true copy may be held
        if tx.core.ix.pending.contains_key(id) {
            tx.core.redeliver.insert(*id);
        }
        return Err(e.into());
    }
    Ok(())
}

/// The stored bytes of pending commit `id`, decoded: `None` when they are gone (it pends no
/// more) or still unreadable by this build.
fn read_pending(tx: &mut Tx<'_>, id: &CommitId) -> Result<Option<CommitBlob>> {
    let _s = crate::costs::span("reexamine: read pending");
    let Some((_, bytes)) = tx.txn.get_pending(id)? else {
        tx.core.ix.pending.remove(id);
        tx.core.waits.unpended(id);
        return Ok(None);
    };
    Ok(CommitBlob::decode_stored(&bytes).ok())
}

/// Checks a commit and decodes its parts, or says why it waits.
///
/// Invariant (delivery-shape independence, spec/commits.md §4): what applies is a function of the
/// parts held and everything else held, never of which came first or which came together. One rule
/// gives that: the header's faults refuse the commit (every copy has the header), and each part is
/// judged by itself, from the signed header, its own bytes and held data:
/// - it does not hash to its header entry: not that part (junk from anyone). Dropped, nothing kept
///   of it: a true copy is still taken. Before its thing's record comes the hash cannot be read and
///   the pending blob keeps the first copy of each slot, junk or not, and its signature likewise; the
///   commit is named when one proves junk (`Core::redeliver`), and node-sync ingests the commit's other
///   entries again (`SyncEngine::redeliver`). So this holds at the node, not at one `Engine::ingest`.
/// - it hashes but is bad by itself (`judge_part`): the author signed garbage, and those bytes are
///   the only ones that can ever hash there, so no later copy can differ and no mark is needed. It
///   never applies and is dropped alone.
/// - it waits (its thing's record or chain, its pages, a linked frontier, parked): alone. The
///   commit's other parts apply; it joins when its wait ends.
///
/// Every wait only ends as the held set grows, so the applied parts are the least fixpoint of a
/// monotone rule, one result for every order (`parts::split_delivery_*`, `parts::parts_differential_*`
/// play them).
pub(crate) fn examine(tx: &mut Tx<'_>, blob: &mut CommitBlob, id: &CommitId, skip: &BTreeSet<(usize, usize)>) -> Result<Exam> {
    if !blob.header.is_resolved() {
        // a held author's signature first: a false one costs no list. An author's record carried
        // by this commit waits for the lists: only the aspects say which part holds it
        if let Some(CreationRecord::KeyActor { public_key, .. }) = tx.core.created_for(&blob.header.author, false) {
            let vk = VerifyingKey::from_slice(public_key)?;
            check_signature(tx, blob, id, &vk)?;
        }
        let Some(dedup) = tx.core.dedup(&blob.header.actor) else { return Ok(Exam::Pending(Reason::UnknownCreated(blob.header.actor), Vec::new())) };
        match blob.header.resolve(&mut TxBlobs::new(&mut tx.txn), &dedup) {
            Ok(()) => {}
            Err(e) if is_missing_page(&e) => return Ok(Exam::Pending(Reason::WaitBlobs, Vec::new())),
            Err(e) => return Err(e.into()),
        }
    }
    let h = blob.header.clone();
    let carried = carried_records(&h, blob, id);
    // a durable commit sees durable records only: one on a thing held as memory class waits for
    // the commit persisting it
    let memory = h.ephemeral.is_some();
    let held: BTreeMap<Tid, CreationRecord> = h.aspects.iter().map(|a| a.tid).chain([h.author, h.actor]).filter_map(|t| tx.core.created_for(&t, memory).map(|r| (t, r.clone()))).collect();
    let chain_rec = |t: &Tid, core: &crate::engine::Core| -> Option<CreationRecord> { core.created_for(t, memory).cloned().or_else(|| carried.get(t).cloned()) };
    let record = |t: &Tid| -> Option<CreationRecord> { held.get(t).cloned().or_else(|| carried.get(t).cloned()) };
    let Some(author) = record(&h.author) else { return Ok(Exam::Pending(Reason::MissingChain(h.author), Vec::new())) };
    let CreationRecord::KeyActor { public_key, .. } = &author else { return Err(Error::BadInput("author is not a key actor")) };
    let vk = VerifyingKey::from_slice(public_key)?;
    check_signature(tx, blob, id, &vk)?;
    h.validate()?;
    // a frontier that does not decode is bad input, never a demotion without one (spec/wire.md
    // §4 field 12)
    if h.frontier.is_some() && validity::header_frontier(&h).is_none() {
        return Err(Error::BadInput("a frontier that is not a frontier"));
    }
    // the bound is for received commits (spec/crdt.md §2.2): this node's own are as far ahead
    // as its HLC, which a clock correction moving back must not turn against them
    if h.author != tx.core.id.tid() && h.ts.wall_ms().0 > tx.now().0.saturating_add(MAX_DRIFT_MS) {
        return Ok(Exam::Pending(Reason::Drift, Vec::new()));
    }
    // the slots a held purge request emptied while they waited (`retention::strip_purged`; perhaps just
    // now, before the commit is first stored): the part's leftover, checked when kept, joins in
    // their place, once per aspect
    let emptied = crate::retention::emptied();
    let mut stripped: BTreeMap<usize, Decoded> = BTreeMap::new();
    for p in blob.parts.iter().filter(|p| p.delta == emptied) {
        if let Some(a) = h.aspects.get(p.ai)
            && !stripped.contains_key(&p.ai)
            && let Some(l) = crate::retention::leftover::get(tx, &a.tid, &a.ak, id, p.ai)?
        {
            stripped.insert(p.ai, Decoded::Delta(osis_crdt::Delta { nonce: [0; osis_crdt::NONCE_LEN], fragment: l.fragment }));
        }
    }
    let stripped_ais: BTreeSet<usize> = stripped.keys().copied().collect();
    let kept = |p: &osis_commit::Part| p.delta == emptied && stripped_ais.contains(&p.ai);
    // a part that does not hash to its header entry is no part of this commit, and one on an aspect
    // of the wrong storage class (core keys are unmarked but `placed.0~`) is never applied: dropped
    // alone, before anything reads what is held (spec/commits.md §4)
    let junk: Vec<(usize, usize)> = blob
        .parts
        .iter()
        .filter(|p| !kept(p))
        .filter(|p| {
            let Some(a) = h.aspects.get(p.ai) else { return true };
            let Some(want) = a.hashes.get(p.di) else { return true };
            a.ak.lifetime() != class_of(&h) || record(&a.tid).is_some_and(|r| osis_crypto::delta_hash(&dedup_secret(r.nonce()), &p.delta) != *want)
        })
        .map(|p| (p.ai, p.di))
        .collect();
    // a copy holding only what does not hash is no copy of it: refused, as if it never came
    let only_junk = !blob.parts.is_empty() && junk.len() == blob.parts.len() && blob.parts.iter().any(|p| h.aspects.get(p.ai).is_none_or(|a| a.ak.lifetime() == class_of(&h)));
    if !junk.is_empty() {
        // a slot's stored first copy, kept while it could not be checked: a true copy may be held. Not a
        // copy just come (it kept nothing out), nor a part of the wrong class (it has no true copy)
        let kept_out = |p: &osis_commit::Part| junk.contains(&(p.ai, p.di)) && h.aspects.get(p.ai).is_none_or(|a| a.ak.lifetime() == class_of(&h));
        if tx.core.ix.pending.contains_key(id) && tx.txn.get_pending(id)?.and_then(|(_, b)| CommitBlob::decode_stored(&b).ok()).is_some_and(|b| b.parts.iter().any(kept_out)) {
            tx.core.redeliver.insert(*id);
        }
        blob.parts.retain(|p| !junk.contains(&(p.ai, p.di)));
        let now = tx.now();
        tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::BadInput, tids: Vec::new(), commit: Some(*id), peer: Some(h.author), detail: "delta hash".into() }, now);
    }
    if only_junk {
        return Err(Error::BadInput("delta hash"));
    }
    // a part waits alone, for its thing's record, owner chain or the author's reach
    let mut aside = Aside::default();
    for (ai, a) in h.aspects.iter().enumerate() {
        let keys: Vec<(usize, usize)> = blob.parts.iter().filter(|p| p.ai == ai).map(|p| (p.ai, p.di)).filter(|x| !skip.contains(x)).collect();
        if keys.is_empty() {
            continue;
        }
        if let Some(wait) = thing_wait(tx.core, &h, a, &record, &chain_rec) {
            aside.add(wait, keys);
        }
    }
    for (t, rec) in &carried {
        if let Some(held) = tx.core.created(t)
            && held != rec
        {
            let now = tx.now();
            tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::CollidingRecord, tids: vec![*t], commit: Some(*id), peer: Some(h.author), detail: String::new() }, now);
        }
    }
    let mut out = Parts::default();
    let mut interner = Interner::new();
    // tests let a local writer break the writer rules, to test receivers
    let rules = !(tx.core.skip_writer_rules && h.author == tx.core.id.tid());
    let mut bad: Vec<(usize, usize)> = Vec::new();
    for p in &blob.parts {
        if skip.contains(&(p.ai, p.di)) || aside.keys.contains(&(p.ai, p.di)) {
            continue;
        }
        let a = h.aspects.get(p.ai).ok_or(Error::BadInput("part index"))?;
        if kept(p) {
            if let Some(d) = stripped.remove(&p.ai) {
                out.whole.push((p.ai, p.di, d));
                out.stripped.push(p.ai);
            }
            continue;
        }
        let dedup = record(&a.tid).map(|r| dedup_secret(r.nonce())).ok_or(Error::UnknownThing(a.tid))?;
        let wait = match judge_part(tx, &h, id, p, a, &dedup, rules, &mut interner, &mut out) {
            Ok(Judged::Good) => continue,
            Ok(Judged::Blobs | Judged::Frontier) => Reason::WaitBlobs,
            Err(e) if e.class() == ErrorClass::Parked => Reason::Parked,
            Err(e) if e.class() == ErrorClass::BadInput => {
                bad.push((p.ai, p.di));
                out.bad.get_or_insert(e);
                continue;
            }
            Err(e) => return Err(e),
        };
        aside.add(wait, [(p.ai, p.di)]);
    }
    if !bad.is_empty() {
        // only bad parts: refused, nothing stored
        if rules && out.ais().is_empty() && aside.keys.is_empty() {
            return Err(out.bad.take().unwrap_or(Error::BadInput("a bad part")));
        }
        blob.parts.retain(|p| !bad.contains(&(p.ai, p.di)));
        let detail = out.bad.as_ref().map(|e| e.to_string()).unwrap_or_default();
        let now = tx.now();
        tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::BadInput, tids: Vec::new(), commit: Some(*id), peer: Some(h.author), detail }, now);
    }
    // every held part waits: the commit (or, already applied, these parts) keeps waiting
    if !aside.keys.is_empty() && out.ais().is_empty() {
        return Ok(aside.verdict());
    }
    if let Some(reason) = aside.reason {
        let (parts, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut blob.parts).into_iter().partition(|p| aside.keys.contains(&(p.ai, p.di)));
        blob.parts = rest;
        out.waiting = Some(Waiting { parts, reason, others: aside.others });
    }
    // what joins of an emptied slot is the part's leftover: no stored copy holds it
    blob.parts.retain(|p| p.delta != emptied || !h.aspects.get(p.ai).is_some_and(|_| out.stripped.contains(&p.ai)));
    Ok(Exam::Ready(out))
}

/// What judging a part alone found, short of bad (`judge_part`'s `Err`, `Parked` among those).
enum Judged {
    /// In `out`.
    Good,
    /// A page is not held.
    Blobs,
    /// A linked frontier's blob is not held.
    Frontier,
}

/// Judges part `p` by itself, from the signed header, its bytes and held data; a good one goes in
/// `out`. Bad input is about this part alone (`examine`). `rules`: the writer rules hold.
#[allow(clippy::too_many_arguments)]
fn judge_part(tx: &mut Tx<'_>, h: &Header, id: &CommitId, p: &osis_commit::Part, a: &osis_commit::AspectEntry, dedup: &osis_crypto::Secret32, rules: bool, interner: &mut Interner, out: &mut Parts) -> Result<Judged> {
    if rules && h.ephemeral.is_none() && a.ak.as_str() == osis_commit::retention::CREATED {
        minted_record(h, id, p, &a.tid, interner)?;
    }
    let mut blobs = TxBlobs::new(&mut tx.txn);
    let mut paged = BlobReader::new(dedup, &mut blobs);
    // a memory commit's parts hold everything inline (spec/crdt.md §8)
    let mut unpaged = osis_crdt::Unpaged;
    let reader: &mut dyn osis_crdt::PageSource = if h.ephemeral.is_some() { &mut unpaged } else { &mut paged };
    // a snapshot's carried writes stamped after the commit (spec/crdt.md §8: a node's next stamp
    // exceeds every stamp it holds, §2.2)
    let carries = h.kind.delta_kind() == osis_crdt::DeltaKind::Snapshot;
    let mut late = false;
    #[cfg(test)]
    let whole = whole_part(a.ak.as_str()) || tx.core.whole_apply;
    #[cfg(not(test))]
    let whole = whole_part(a.ak.as_str());
    let r = if whole {
        verify_part(h, id, p, dedup, interner, Some(reader)).map(|d| {
            late = carries && d.fragment().max_ts().is_some_and(|t| t > h.ts);
            Some(d)
        })
    } else {
        // the full check, keeping nothing: apply streams it again
        let mut each = |f: osis_crdt::Fragment| {
            late |= carries && f.max_ts().is_some_and(|t| t > h.ts);
            Ok(())
        };
        osis_commit::stream_part(h, id, p, dedup, interner, Some(reader), &mut each).map(|gives| {
            out.streamed.push(Streamed { ai: p.ai, di: p.di, dedup: dedup.clone(), gives: gives.map(|x| (x.frontiers, x.absorbed.into_iter().collect())) });
            None
        })
    };
    let decoded = match r {
        Ok(d) => d,
        Err(e) if is_missing_page(&e) => return Ok(Judged::Blobs),
        // an oversize value in a part is the part's fault, not this node's
        Err(osis_commit::Error::TooLarge(_)) => return Err(Error::BadInput("a part too large")),
        Err(e) => return Err(e.into()),
    };
    if late {
        out.streamed.retain(|s| (s.ai, s.di) != (p.ai, p.di));
        return Err(Error::BadInput("carried write stamped after its commit"));
    }
    let Some(d) = decoded else { return Ok(Judged::Good) };
    let part = (p.ai, p.di, d);
    if rules {
        validity::check_holders_parts(h, id, std::slice::from_ref(&part))?;
        if !validity::linked_frontiers(tx, h, &validity::EdgeParts::of(h, std::slice::from_ref(&part)))?.waiting.is_empty() {
            return Ok(Judged::Frontier);
        }
    }
    out.whole.push(part);
    Ok(Judged::Good)
}

/// What thing `a.tid` waits for: its `created.0` record, the owner chain up to a key actor, the
/// author's chain certificates (spec/permissions.md §4). A function of the thing, not of the part.
fn thing_wait(
    core: &crate::engine::Core,
    h: &Header,
    a: &osis_commit::AspectEntry,
    record: &dyn Fn(&Tid) -> Option<CreationRecord>,
    chain_rec: &dyn Fn(&Tid, &crate::engine::Core) -> Option<CreationRecord>,
) -> Option<Reason> {
    if record(&a.tid).is_none() {
        return Some(Reason::UnknownCreated(a.tid));
    }
    let mut chain = vec![a.tid];
    // a chain deeper than `MAX_OWNER_DEPTH` is not waited for further: its deltas are invalid
    // (`validity::too_deep`, spec/permissions.md §1)
    for step in osis_base::owner_chain(a.tid, |t| chain_rec(t, core).map(|r| r.owner_link())) {
        match step {
            ChainStep::Up { owner, .. } => chain.push(owner),
            ChainStep::Key(_) | ChainStep::TooDeep => {}
            // its first admin's edge leads to it, the record perhaps not held yet (its creation)
            ChainStep::Ownerless { admin, .. } => chain.push(admin),
            ChainStep::Unknown(t) => return Some(Reason::MissingChain(t)),
        }
    }
    // it is on the owner chain, or held edge writes lead from it to the chain (a revoked author
    // keeps its certificates and still applies, judged invalid)
    (!chain.contains(&h.author) && !validity::reaches(core, &h.author, &chain)).then_some(Reason::MissingChain(h.author))
}

/// Applies or stores one decoded commit blob.
/// A memory commit (session-form content or commit-form snapshot, spec/commits.md §2-§3) is applied as memory work: every row it
/// derives stays in the store's memory overlay, pending ones included.
fn ingest_blob(tx: &mut Tx<'_>, blob: CommitBlob, origin: Origin) -> Result<Ingested> {
    match (blob.header.ephemeral, blob.header.form) {
        (None, _) => ingest_class(tx, blob, origin),
        (Some(osis_commit::EphClass::Plain), osis_commit::Form::Session(_) | osis_commit::Form::Commit) => tx.in_class(true, |tx| ingest_class(tx, blob, origin)),
        // relay-only commits are delivered, never held (`Engine::ingest_relay`)
        _ => Err(Error::BadInput("a relay-only commit on the commit path")),
    }
}

fn ingest_class(tx: &mut Tx<'_>, mut blob: CommitBlob, origin: Origin) -> Result<Ingested> {
    let id = blob.id();
    // a kept copy takes no new content (spec/permissions.md §3, Keep)
    if !tx.core.ix.kept.is_empty() {
        let n = blob.parts.len();
        blob = crate::rotation::without_frozen(tx.core, blob);
        if n > 0 && blob.parts.is_empty() {
            return Ok(Ingested::Duplicate(id));
        }
    }
    if tx.core.ix.commits.contains_key(&id) {
        return late_parts(tx, &id, blob);
    }
    blob = with_pending(tx, &id, blob)?;
    let received = tx.now();
    let inline = blob.header.is_resolved();
    let _s = crate::costs::span("examine");
    let out = match examine(tx, &mut blob, &id, &BTreeSet::new())? {
        Exam::Ready(parts) => {
            let w = parts.waiting.as_ref().map(Waiting::copy);
            let was_pending = unpend(tx, &id)?;
            apply_verified(tx, &blob, parts, origin, received)?;
            // what a part still waiting read of its boxes may be what opens what it waits for
            match w {
                Some(w) => pend_aside(tx, &id, &blob, w)?,
                None if was_pending => keys::forget_unchecked(tx, &id)?,
                None => {}
            }
            Ingested::Applied(id)
        }
        Exam::Pending(r, others) => {
            // parts past their expiry (or a memory commit's purged ones) count as never received: examined again without them
            let (h, n) = (blob.header.clone(), blob.parts.len());
            crate::retention::pending_drops(tx, &id, &mut blob, &h)?;
            if blob.parts.len() != n {
                return ingest_class(tx, blob, origin);
            }
            pend(tx, &id, PendingKind::Pending, &blob.encode(), r.clone())?;
            keys::read_pending_boxes(tx, &blob, &id)?;
            let now = tx.now().0;
            waits::note(tx.core, id, &blob, inline, &r, &others, now);
            Ingested::Pending(id, r)
        }
        Exam::Parked => {
            let (h, n) = (blob.header.clone(), blob.parts.len());
            crate::retention::pending_drops(tx, &id, &mut blob, &h)?;
            if blob.parts.len() != n {
                return ingest_class(tx, blob, origin);
            }
            pend(tx, &id, PendingKind::Parked, &blob.encode(), Reason::Parked)?;
            Ingested::Parked(id)
        }
    };
    Ok(out)
}

/// Keeps commit `id` pending (`bytes` as stored) for `reason`.
fn pend(tx: &mut Tx<'_>, id: &CommitId, kind: PendingKind, bytes: &[u8], reason: Reason) -> Result<()> {
    tx.core.touch();
    tx.txn.put_pending(id, kind, bytes)?;
    tx.core.ix.pending.insert(*id, reason);
    tx.core.waits.pended(id);
    Ok(())
}

/// Keeps the parts of applied commit `id` that wait alone pending under its ID. `applied`: its
/// blob. The `reexamine` an applied commit is followed by reads their boxes (`late_parts`).
fn pend_aside(tx: &mut Tx<'_>, id: &CommitId, applied: &CommitBlob, w: Waiting) -> Result<()> {
    let mut rest = applied.clone();
    rest.parts = w.parts;
    // a part past its expiry counts as never received, a purged one is held value-less (`retention::pending_drops`)
    let h = rest.header.clone();
    crate::retention::pending_drops(tx, id, &mut rest, &h)?;
    if rest.parts.is_empty() {
        return Ok(());
    }
    let kind = if w.reason == Reason::Parked { PendingKind::Parked } else { PendingKind::Pending };
    pend(tx, id, kind, &rest.encode(), w.reason.clone())?;
    // its boxes are not read yet: `reexamine` comes for them, and notes the wait then
    if rest.parts.iter().any(|p| rest.header.aspects.get(p.ai).is_some_and(|a| a.ak.as_str() == "secrets.0")) {
        return Ok(());
    }
    let now = tx.now().0;
    waits::note(tx.core, *id, &rest, true, &w.reason, &w.others, now);
    Ok(())
}

/// Commit `id` pends no more: its stored bytes go. Whether it was pending.
fn unpend(tx: &mut Tx<'_>, id: &CommitId) -> Result<bool> {
    tx.core.waits.unpended(id);
    let was = tx.core.ix.pending.remove(id).is_some();
    if was {
        tx.core.touch();
        tx.txn.remove_pending(id, Shred::Yes)?;
    }
    Ok(was)
}

/// `blob` with the parts the stored pending copy of `id` holds: a slot keeps its first copy, and the
/// commit its first signature, until they can be checked (`examine`). A differing copy goes, its bytes
/// still in its label entry; only its boxes are read now (spec/crypto.md §4): the keys in them may open
/// what the commit waits for, and nothing checks whose they are until then.
fn with_pending(tx: &mut Tx<'_>, id: &CommitId, mut blob: CommitBlob) -> Result<CommitBlob> {
    if tx.core.ix.pending.contains_key(id)
        && let Some((_, old)) = tx.txn.get_pending(id)?
        && let Ok(mut old) = CommitBlob::decode_stored(&old)
    {
        // what a true copy is judged by below; while the header's lists are away a `created.0` copy
        // cannot prove itself and is discarded like any other (issues/linked-header-junk-record.md)
        if !old.header.is_resolved()
            && let Some(dedup) = tx.core.dedup(&old.header.actor)
        {
            let mut h = old.header.clone();
            if h.resolve(&mut TxBlobs::new(&mut tx.txn), &dedup).is_ok() {
                old.header = h;
            }
        }
        // a slot the header does not list has no true copy: a sender could grow the blob by them
        if old.header.is_resolved() {
            let h = old.header.clone();
            blob.parts.retain(|p| h.aspects.get(p.ai).is_some_and(|a| a.hashes.get(p.di).is_some()));
        }
        let mut others: Vec<osis_commit::Part> = Vec::new();
        let mut rest = Vec::new();
        for p in std::mem::take(&mut blob.parts) {
            match old.parts.binary_search_by_key(&(p.ai, p.di), |x| (x.ai, x.di)).ok().and_then(|i| old.parts.get_mut(i)) {
                Some(x) if x.delta == p.delta => {}
                // a true `created.0` part proves itself: it is what any other part here waits for
                Some(x) if proves_itself(&old.header, id, &p) => *x = p,
                Some(_) => others.push(p),
                None => rest.push(p),
            }
        }
        blob.parts = rest;
        if !others.is_empty() {
            keys::read_pending_boxes(tx, &CommitBlob { header: old.header.clone(), signature: old.signature, parts: others }, id)?;
        }
        let signature = blob.signature;
        let mut merged = merge_parts(old, blob);
        // a true copy's signature replaces the first once its author is known here, by what this copy
        // brought (its `created.0`) or by anything else
        if signature != merged.signature {
            let carried = carried_records(&merged.header, &merged, id);
            let memory = merged.header.ephemeral.is_some();
            let author = tx.core.created_for(&merged.header.author, memory).cloned().or_else(|| carried.get(&merged.header.author).cloned());
            if let Some(CreationRecord::KeyActor { public_key, .. }) = author
                && VerifyingKey::from_slice(&public_key).is_ok_and(|vk| osis_commit::verify_signature(id, &signature, &vk).is_ok())
            {
                merged.signature = signature;
            }
        }
        return Ok(merged);
    }
    Ok(blob)
}

/// Whether durable `created.0` part `p` is its commit's: its record hashes to its thing's tid, and the
/// record's nonce keys the hash in the signed header. Needs nothing else held.
fn proves_itself(h: &Header, id: &CommitId, p: &osis_commit::Part) -> bool {
    let Some(a) = h.aspects.get(p.ai).filter(|a| h.ephemeral.is_none() && a.ak.as_str() == osis_commit::retention::CREATED) else { return false };
    let Some(want) = a.hashes.get(p.di) else { return false };
    minted_record(h, id, p, &a.tid, &mut Interner::new()).is_ok_and(|r| osis_crypto::delta_hash(&dedup_secret(r.nonce()), &p.delta) == *want)
}

/// Every slot of aspect `ai`.
fn out_of(h: &Header, ai: usize) -> impl Iterator<Item = (usize, usize)> {
    (0..h.aspects.get(ai).map_or(0, |a| a.hashes.len())).map(move |di| (ai, di))
}

/// `a` with the parts of `b` on slots it lacks.
fn merge_parts(mut a: CommitBlob, b: CommitBlob) -> CommitBlob {
    for p in b.parts {
        if let Err(i) = a.parts.binary_search_by_key(&(p.ai, p.di), |x| (x.ai, x.di)) {
            a.parts.insert(i, p);
        }
    }
    a
}

/// A delta of an already applied commit, arriving later, is joined on arrival (spec/commits.md
/// §4); dropped and stripped parts stay so, but for those a copy may replace
/// (`retention::takes_late`). Late deltas that wait
/// (their thing's `created.0`, chain or pages) are kept pending under the commit's ID and
/// joined once they apply.
fn late_parts(tx: &mut Tx<'_>, id: &CommitId, mut blob: CommitBlob) -> Result<Ingested> {
    let (held, skip) = held_and_skip(tx, id)?;
    blob = with_pending(tx, id, blob)?;
    blob.parts.retain(|p| !skip.contains(&(p.ai, p.di)));
    if blob.parts.is_empty() {
        crate::retention::forget_waiting_leftovers(tx, id)?;
        unpend(tx, id)?;
        return Ok(Ingested::Duplicate(*id));
    }
    let mut merged = merge_parts(held, blob.clone());
    let _s = crate::costs::span("examine");
    let out = match examine(tx, &mut merged, id, &skip)? {
        Exam::Ready(parts) => {
            let w = parts.waiting.as_ref().map(Waiting::copy);
            let was_pending = unpend(tx, id)?;
            let ais = parts.ais();
            let gave: BTreeSet<usize> = tx.core.ix.commits.get(id).map(|m| ais.iter().copied().filter(|ai| m.dropped.get(ai).is_some_and(|d| d.gave)).collect()).unwrap_or_default();
            crate::retention::reopen_late(tx, id, &ais)?;
            atomic::join_late(tx, id, &merged, parts, &gave)?;
            // a body back and judged again (dropped for its keep bounds, uncovered, gone at its
            // expiry while pending): whatever the aspect lacked for it is in, held or not
            for ai in ais {
                if let Some(a) = merged.header.aspects.get(ai) {
                    crate::retention::suspect::body_back(tx, id, ai, &a.tid, &a.ak)?;
                }
            }
            match w {
                Some(w) => pend_aside(tx, id, &merged, w)?,
                None if was_pending => keys::forget_unchecked(tx, id)?,
                None => {}
            }
            Ingested::Applied(*id)
        }
        Exam::Pending(r, others) => {
            // what `examine` dropped of the waiting parts goes from the stored copy too
            blob.parts.retain(|p| merged.parts.binary_search_by_key(&(p.ai, p.di), |x| (x.ai, x.di)).is_ok());
            let n = blob.parts.len();
            crate::retention::pending_drops(tx, id, &mut blob, &merged.header)?;
            if blob.parts.len() != n {
                return late_parts(tx, id, blob);
            }
            pend(tx, id, PendingKind::Pending, &blob.encode(), r.clone())?;
            keys::read_pending_boxes(tx, &blob, id)?;
            let now = tx.now().0;
            waits::note(tx.core, *id, &merged, true, &r, &others, now);
            // a late `tenures.0` part alone, its linked frontier away, takes its snapshot out of
            // the walk as it would have with the part applied beside it
            atomic::leave_walk(tx, id, &blob.parts)?;
            Ingested::Pending(*id, r)
        }
        Exam::Parked => {
            let n = blob.parts.len();
            crate::retention::pending_drops(tx, id, &mut blob, &merged.header)?;
            if blob.parts.len() != n {
                return late_parts(tx, id, blob);
            }
            pend(tx, id, PendingKind::Parked, &blob.encode(), Reason::Parked)?;
            Ingested::Parked(*id)
        }
    };
    Ok(out)
}

/// Applied commit `id`'s stored blob (its resolved header), and the parts a late copy brings
/// nothing for: those held, those dropped for good.
fn held_and_skip(tx: &mut Tx<'_>, id: &CommitId) -> Result<(CommitBlob, BTreeSet<(usize, usize)>)> {
    let mut held = tx.get_commit(id)?.ok_or(Error::Corrupt("commit record"))?;
    let meta = tx.core.ix.commits.get(id).cloned().ok_or(Error::Corrupt("commit index"))?;
    let mut skip: BTreeSet<(usize, usize)> = held.parts.iter().map(|p| (p.ai, p.di)).collect();
    for ai in meta.dropped.keys().chain(meta.stripped.iter()) {
        if !crate::retention::takes_late(tx, id, *ai)? {
            skip.extend((0..meta.header.aspects.get(*ai).map_or(0, |a| a.hashes.len())).map(|di| (*ai, di)));
        }
    }
    held.header = (*meta.header).clone();
    Ok((held, skip))
}

/// Applies a commit this node just built (no signature check: it signed it).
pub(crate) fn apply_local(tx: &mut Tx<'_>, blob: &CommitBlob, received: WallMs) -> Result<()> {
    let id = blob.id();
    let mut b = blob.clone();
    match examine(tx, &mut b, &id, &BTreeSet::new())? {
        Exam::Ready(parts) if parts.waiting.is_some() => Err(Error::Misuse("own commit not applicable")),
        // a node never writes a part others would drop
        Exam::Ready(Parts { bad: Some(e), .. }) if !tx.core.skip_writer_rules => Err(e),
        Exam::Ready(parts) => {
            // writer-side rules: a received commit is judged by perm instead
            if !tx.core.skip_writer_rules {
                validity::check_content_rules(tx.core, &b.header, &parts.whole)?;
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
    /// Frees the memory things among `things` (`free::free`: records, the memory commits all of
    /// whose things are freed, their aspects' memory rows). Tests until local ephemeral writes
    /// are memory commits (issues/eph-unify.md step 3).
    #[doc(hidden)]
    pub fn free_memory(&mut self, things: &BTreeSet<Tid>) -> Result<()> {
        self.run(|tx| {
            tx.set_memory();
            free::free(tx, things)
        })
    }

    /// Whether `blob` is a true copy of its commit: every delta hashes to its entry in the commit's
    /// header (the applied, resolved one when held; spec/commits.md §4) and its signature verifies: a
    /// blob of a held commit is otherwise never checked, its parts being skipped as held. `Some(false)`
    /// as soon as anything that can be checked here fails, with the records `examine` would read
    /// (those carried included), so a copy `examine` drops anything of is never `None`. `None` while
    /// nothing failed but a thing's `created.0` (its dedup secret), the author's or the resolved
    /// header is unknown (or fails to decode).
    pub fn parts_genuine(&mut self, blob: &CommitBlob) -> Option<bool> {
        let id = blob.id();
        let h = match self.core.ix.commits.get(&id) {
            Some(m) => m.header.decoded()?,
            None => {
                let mut h = blob.header.clone();
                if !h.is_resolved() {
                    self.run(|tx| {
                        let Some(dedup) = tx.core.dedup(&h.actor) else { return Err(Error::Misuse("not resolved")) };
                        Ok(h.resolve(&mut TxBlobs::new(&mut tx.txn), &dedup)?)
                    })
                    .ok()?;
                }
                Arc::new(h)
            }
        };
        let pending: Vec<osis_commit::Part> = self.run(|tx| Ok(tx.txn.get_pending(&id)?.and_then(|(_, b)| CommitBlob::decode_stored(&b).ok()).map(|b| b.parts))).ok().flatten().unwrap_or_default();
        let mut all = blob.clone();
        all.parts.extend(pending);
        let carried = carried_records(&h, &all, &id);
        let record = |core: &crate::engine::Core, t: &Tid| core.created(t).cloned().or_else(|| carried.get(t).cloned());
        let mut known = true;
        for p in &blob.parts {
            let Some(a) = h.aspects.get(p.ai) else { return Some(false) };
            let Some(want) = a.hashes.get(p.di) else { return Some(false) };
            match record(&self.core, &a.tid) {
                Some(r) if osis_crypto::delta_hash(&dedup_secret(r.nonce()), &p.delta) != *want => return Some(false),
                Some(_) => {}
                None => known = false,
            }
        }
        match record(&self.core, &h.author) {
            Some(CreationRecord::KeyActor { public_key, .. }) => {
                let vk = VerifyingKey::from_slice(&public_key).ok()?;
                if osis_commit::verify_signature(&id, &blob.signature, &vk).is_err() {
                    return Some(false);
                }
            }
            Some(_) => return Some(false),
            None => known = false,
        }
        known.then_some(true)
    }

    /// The commits with a part or signature of a pending copy proved junk since the last call, when a
    /// true copy the first one kept out may be held by the sync layer (`with_pending`).
    pub fn take_redeliver(&mut self) -> BTreeSet<CommitId> {
        std::mem::take(&mut self.core.redeliver)
    }

    /// Names commit `id` for `take_redeliver`.
    pub fn name_redeliver(&mut self, id: CommitId) {
        self.core.redeliver.insert(id);
    }

    /// The slots of commit `id` no copy need bring here: those held, applied or pending, and those
    /// counting as never received (spec/commits.md §5), its body dropped or past its expiry, which
    /// only a new copy brings back (`SyncEngine::redeliver`).
    pub fn settled_slots(&mut self, id: &CommitId) -> Result<BTreeSet<(usize, usize)>> {
        let id = *id;
        self.run(|tx| {
            let now = tx.now().0;
            let mut out: BTreeSet<(usize, usize)> = BTreeSet::new();
            let pending = tx.txn.get_pending(&id)?.and_then(|(_, b)| CommitBlob::decode_stored(&b).ok());
            if let Some(b) = &pending {
                out.extend(b.parts.iter().map(|p| (p.ai, p.di)));
                for ai in 0..b.header.aspects.len() {
                    if crate::retention::pending_expired(tx, &b.header, ai) {
                        out.extend(out_of(&b.header, ai));
                    }
                }
            }
            if let Some(b) = tx.get_commit(&id)? {
                out.extend(b.parts.iter().map(|p| (p.ai, p.di)));
            }
            if let Some(m) = tx.core.ix.commits.get(&id) {
                let ais: Vec<usize> = (0..m.header.aspects.len()).filter(|ai| m.dropped.contains_key(ai) || m.header.aspects.get(*ai).and(m.header.expires).is_some_and(|t| t <= now)).collect();
                for ai in ais {
                    out.extend(out_of(&m.header, ai));
                }
            }
            Ok(out)
        })
    }

    /// Whether copy `copy` of commit `id` holds a part that went from the node (spec/commits.md §5:
    /// dropped from the applied commit or held as its leftover while value-less, held pending past
    /// its expiry, or held pending value-less or gone for a request, `retention::strip_purged`)
    /// and nothing a copy may still be needed for (`SyncEngine::redeliver`):
    /// its every other part went too, is applied, or, where parts of it wait, is in the pending copy
    /// alike or provably does not hash to its header entry. Node-sync then forgets the copy's blob and
    /// key; one that may hold the only true copy of a part a junk copy holds the slot of stays until
    /// that is judged, as does every copy of a commit named for redelivery.
    pub fn spent_copy(&mut self, id: &CommitId, copy: &CommitBlob) -> Result<bool> {
        if self.core.redeliver.contains(id) {
            return Ok(false);
        }
        self.run(|tx| {
            let meta = tx.core.ix.commits.get(id).cloned();
            let pending = if tx.core.ix.pending.contains_key(id) { tx.txn.get_pending(id)?.and_then(|(_, b)| CommitBlob::decode_stored(&b).ok()) } else { None };
            let Some(h) = meta.as_ref().map(|m| (*m.header).clone()).or_else(|| pending.as_ref().map(|b| b.header.clone())) else { return Ok(false) };
            let applied: BTreeSet<(usize, usize)> = match &meta {
                Some(_) => tx.get_commit(id)?.map(|b| b.parts.iter().map(|p| (p.ai, p.di)).collect()).unwrap_or_default(),
                None => BTreeSet::new(),
            };
            let mut gone = false;
            for p in &copy.parts {
                if meta.as_ref().is_some_and(|m| m.dropped.contains_key(&p.ai) || m.stripped.contains(&p.ai) && crate::retention::valueless(tx.core, id, p.ai)) || pending.is_some() && (crate::retention::pending_expired(tx, &h, p.ai) || pending.as_ref().map(|b| crate::retention::waiting_stripped(tx, b, id, p.ai)).transpose()?.unwrap_or(false) || pending.as_ref().is_some_and(|b| !b.parts.iter().any(|q| q.ai == p.ai)) && crate::retention::known_purged(tx, &h, id, p.ai)?) {
                    gone = true;
                    continue;
                }
                // applied, or nothing of the commit waits: no copy of it is needed
                let Some(held) = pending.as_ref().filter(|_| !applied.contains(&(p.ai, p.di))) else { continue };
                if held.parts.iter().any(|q| (q.ai, q.di) == (p.ai, p.di) && q.delta == p.delta) {
                    continue;
                }
                let junk = match h.aspects.get(p.ai).map(|a| (a.hashes.get(p.di), tx.core.created(&a.tid))) {
                    None | Some((None, _)) => true,
                    Some((Some(want), Some(r))) => osis_crypto::delta_hash(&dedup_secret(r.nonce()), &p.delta) != *want,
                    Some((Some(_), None)) => false,
                };
                if !junk {
                    return Ok(false);
                }
            }
            Ok(gone)
        })
    }

    /// Whether commit `id` is named for redelivery (`take_redeliver` has not taken it yet).
    pub fn redeliver_named(&self, id: &CommitId) -> bool {
        self.core.redeliver.contains(id)
    }

    /// Receives a commit blob's plaintext (`CommitBlobPlaintext`, spec/wire.md §4) with the page,
    /// chunk and header-list blobs it references (ciphertexts by ID). Bad input is reported as
    /// a diagnostic and returned as an error; nothing of it is stored.
    pub fn ingest(&mut self, bytes: &[u8], blobs: Vec<(BlobId, Vec<u8>)>) -> Result<Ingested> {
        self.ingest_from(bytes, blobs, None)
    }

    /// `ingest`, attributing diagnostics to `peer`.
    pub fn ingest_from(&mut self, bytes: &[u8], blobs: Vec<(BlobId, Vec<u8>)>, peer: Option<Tid>) -> Result<Ingested> {
        self.ingest_class(bytes, blobs, peer, None)
    }

    /// Receives a memory commit (session form, spec/commits.md §2-§3) through the commit path,
    /// every row it derives in memory. `room`: what holding it may cost, as `memory_charge`
    /// counts it (the node cap, spec/sync.md §9 Caps): when its parts not held here could cost
    /// more decoded (`memory::part_bound`, from their bytes alone) it is `TooLarge`, nothing of
    /// it decoded, held or kept waiting. Hidden: no production caller until received ephemeral
    /// commits leave `ingest_ephemeral` (issues/eph-unify.md step B); `ingest` refuses them so a
    /// writer cannot slip one in through the durable lane meanwhile.
    #[doc(hidden)]
    pub fn ingest_memory(&mut self, bytes: &[u8], room: u64) -> Result<Ingested> {
        self.ingest_class(bytes, Vec::new(), None, Some(room))
    }

    /// `room`: a memory commit's (`ingest_memory`); `None` on the durable path.
    fn ingest_class(&mut self, bytes: &[u8], blobs: Vec<(BlobId, Vec<u8>)>, peer: Option<Tid>, room: Option<u64>) -> Result<Ingested> {
        let memory = room.is_some();
        let _s = crate::costs::span("ingest");
        let mut fresh = false;
        let r = self.run(|tx| {
            let decoded = CommitBlob::decode(bytes);
            if matches!(&decoded, Ok(b) if b.header.ephemeral.is_some() != memory) {
                return Err(Error::BadInput(if memory { "a durable commit on the memory path" } else { "an ephemeral commit on the durable path" }));
            }
            // a memory commit links no blob and stores nothing durable (spec/commits.md §2)
            if let Some(room) = room {
                tx.set_memory();
                if let Ok(b) = &decoded
                    && memory::new_parts_bound(tx, b)? > room
                {
                    return Ok(Ingested::TooLarge(b.id()));
                }
            } else {
                fresh = tx.store_blobs(blobs)?;
            }
            match decoded {
                Ok(blob) => ingest_blob(tx, blob, Origin::Remote),
                Err(e) if e.class() == ErrorClass::Parked => {
                    let id = raw_id(bytes)?;
                    pend(tx, &id, PendingKind::Parked, bytes, Reason::Parked)?;
                    Ok(Ingested::Parked(id))
                }
                Err(e) => Err(e.into()),
            }
        });
        if fresh && r.is_ok() {
            self.blobs_stored();
        }
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
    /// `created.0` records, a change of what this node syncs, time passing, or an upgrade).
    /// Role commits are tried first. A commit whose examination's inputs have not changed
    /// since it was last examined is left out (`apply::waits`).
    /// Pending commits `reexamine` read again so far (scale checks).
    pub fn examined(&self) -> u64 {
        self.core.waits.examined
    }

    pub fn reexamine(&mut self) -> Result<()> {
        if self.core.frozen_pending {
            return Ok(());
        }
        let _s = crate::costs::span("reexamine");
        loop {
            let now = self.core.now().0;
            let ids = {
                let _s = crate::costs::span("reexamine: candidates");
                waits::candidates(&mut self.core, now)
            };
            #[cfg(debug_assertions)]
            if self.recheck(format!("check_unchanged {ids:?}")) {
                self.check_unchanged(&ids);
            }
            if ids.is_empty() {
                return Ok(());
            }
            let _s = crate::costs::span("reexamine: round");
            let progressed = self.run(|tx| {
                let mut blobs: Vec<(CommitId, CommitBlob)> = Vec::new();
                for id in ids {
                    tx.core.waits.examined += 1;
                    if let Some(b) = read_pending(tx, &id)? {
                        blobs.push((id, b));
                    }
                }
                blobs.sort_by_key(|(_, b)| (!b.header.kind.is_role(), b.header.ts));
                tx.core.touch();
                let mut progressed = false;
                for (id, b) in blobs {
                    let things: Vec<Tid> = if b.header.kind.is_role() { b.header.aspects.iter().map(|a| a.tid).collect() } else { Vec::new() };
                    match ingest_blob(tx, b, Origin::Remote) {
                        Ok(Ingested::Applied(_)) => progressed = true,
                        Ok(_) => {}
                        Err(e) if e.class() == ErrorClass::BadInput => {
                            tx.txn.remove_pending(&id, Shred::Yes)?;
                            crate::retention::forget_waiting_leftovers(tx, &id)?;
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
        // a look only: what it finds is named when the commit's turn comes
        let named = self.core.redeliver.clone();
        let r: Result<()> = self.run(|tx| {
            for id in &ids {
                let Some((_, bytes)) = tx.txn.get_pending(id)? else { continue };
                let Ok(mut b) = CommitBlob::decode_stored(&bytes) else { continue };
                let want = tx.core.ix.pending.get(id).cloned();
                // parts of an applied commit are examined with it, as `late_parts` does
                let skip = if tx.core.ix.commits.contains_key(id) {
                    let (held, skip) = held_and_skip(tx, id)?;
                    b = merge_parts(held, b);
                    skip
                } else {
                    BTreeSet::new()
                };
                for (a, s, from) in keys::pending_boxes(tx, &b, id)? {
                    debug_assert!(tx.core.waits.is_refused(id) || tx.core.ingest_view(&a, &s, Some(from), &osis_keys::HistoryAlts::new()).is_none(), "pending commit {id:?} left out of reexamine: its boxes teach {a:?} something");
                }
                match examine(tx, &mut b, id, &skip) {
                    Ok(Exam::Pending(r, _)) => debug_assert_eq!(Some(r), want, "pending commit {id:?} left out of reexamine"),
                    Ok(Exam::Ready(_)) => debug_assert!(false, "pending commit {id:?} left out of reexamine would apply"),
                    Ok(Exam::Parked) => debug_assert!(false, "pending commit {id:?} left out of reexamine would park"),
                    // no wait is woken by a record that only proves stored copies junk, a commit waiting
                    // for another record or for deltas: they go when the wait ends (`examine`) or a copy
                    // comes, the reason being unchanged by them
                    Err(Error::BadInput("delta hash")) => {}
                    Err(e) => debug_assert!(false, "pending commit {id:?} left out of reexamine: {e}"),
                }
            }
            Err(Error::Misuse("check only"))
        });
        self.core.redeliver = named;
        debug_assert!(matches!(r, Err(Error::Misuse(_))), "{r:?}");
    }

    /// Starts or stops syncing `tid` and what its `group.0` holds, now and as it changes.
    pub fn set_syncing(&mut self, tid: Tid, on: bool) -> Result<()> {
        self.run(|tx| {
            tx.core.touch();
            let k = [records::SYNCING, tid.as_bytes()].concat();
            if on {
                tx.txn.put_local(&k, &[], Shred::No)?;
                tx.core.ix.syncing.insert(tid);
            } else {
                tx.txn.remove_local(&k, Shred::No)?;
                tx.core.ix.syncing.remove(&tid);
            }
            Ok(())
        })
    }

    /// Pending and parked commits with their reasons (parked ones as `Unexamined`).
    pub fn pending(&self) -> Vec<(CommitId, Reason)> {
        self.core.ix.pending.iter().map(|(k, v)| (*k, v.clone())).collect()
    }

    /// The actors a label of `thing` known only by a hint is for (spec/sync.md §5: claims on a
    /// step not verified yet): its applied holders and the holders its applied `secrets.0` boxes
    /// (one may read it through an actor a rotation boxed, with no grant held), and those that
    /// `inbox`, the pending commits of the inbox blobs that named the label, grant or box on it;
    /// those this node is or holds secrets of.
    pub fn hint_actors(&mut self, thing: &Tid, inbox: &[CommitId]) -> Result<std::collections::BTreeSet<Tid>> {
        let mut out: std::collections::BTreeSet<Tid> = self.get_typed(thing, &osis_schema::core_types::ROLES)?.unwrap_or_default().into_keys().collect();
        out.extend(self.get_typed(thing, &osis_schema::core_types::SECRETS)?.unwrap_or_default().boxes.into_keys().map(|k| k.holder));
        for c in inbox {
            if !self.core.ix.pending.contains_key(c) {
                continue;
            }
            if let Some(b) = self.commit_bytes(c)?.and_then(|b| CommitBlob::decode_stored(&b).ok()) {
                out.extend(keys::pending_grantees(&b, c, thing));
                for (a, w) in keys::pending_secrets_writes(&b, c) {
                    if a == *thing {
                        out.extend(w.boxes.into_keys().map(|k| k.holder));
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

    /// IDs of applied durable commits (no memory commit), in (`ts`, ID) order.
    pub fn commit_ids(&self) -> Vec<CommitId> {
        let mut v: Vec<(osis_base::Ts, CommitId)> = self.core.ix.commits.iter().filter(|(_, m)| !m.view.memory).map(|(id, m)| (m.view.ts, *id)).collect();
        v.sort();
        v.into_iter().map(|x| x.1).collect()
    }

    /// The header of an applied commit (none if its stored bytes fail to decode: `LazyHeader`).
    pub fn header(&self, id: &CommitId) -> Option<Arc<Header>> {
        self.core.ix.commits.get(id).and_then(|m| m.header.decoded())
    }

    /// The commit that created `tid`: the oldest held commit carrying its `created.0` that is
    /// valid here (no durable snapshot carries `created.0`, spec/commits.md §2).
    /// `created.0` is kept forever, so every node reading the thing gets that commit; until it
    /// is here (only a snapshot held) `None`.
    pub fn creation(&self, tid: &Tid) -> Option<Creation> {
        if let Some(e) = self.ephemeral_thing(tid) {
            return Some(Creation { commit: None, ts: e.ts, node: e.node, actor: e.actor, received: e.received });
        }
        if self.core.ix.held.is_memory(tid) {
            return None;
        }
        let ak = osis_base::Ak::new("created.0").ok()?;
        self.core.ix.by_aspect.get(&(*tid, ak.clone()))?.iter().find_map(|(_, id)| {
            let m = self.core.ix.commits.get(id)?;
            let ai = m.aspect(tid, &ak)?;
            (m.valid_at(ai)).then(|| Creation { commit: Some(*id), ts: m.header.ts, node: m.header.author, actor: m.header.actor, received: m.received })
        })
    }

    /// The thing's last content change: of the held content commits (changes, reverts) validly writing one of its aspects other than `created.0`, `group.0` and the
    /// role-class ones, the one shown latest by `min(ts, received)` (an author's clock may
    /// run ahead; `received` is this node's), else its creation. Snapshots are no change, and
    /// ephemeral writes do not count (an ephemeral thing reports its creation).
    pub fn changed(&self, tid: &Tid) -> Option<Creation> {
        let shown = |c: &Creation| c.ts.wall_ms().min(c.received);
        let mut best = self.creation(tid);
        let aspects = self.core.ix.by_aspect.range((*tid, osis_base::Ak::MIN)..).take_while(|((t, _), _)| t == tid);
        for ((_, ak), ids) in aspects {
            let a = ak.as_str();
            if a == "group.0" || !osis_schema::core_types::is_content(a) {
                continue;
            }
            for (ts, id) in ids.iter().rev() {
                // shown <= ts: nothing older can be shown later than the best so far
                if best.as_ref().is_some_and(|b| ts.wall_ms() <= shown(b)) {
                    break;
                }
                let Some(m) = self.core.ix.commits.get(id) else { continue };
                let valid = m.aspect(tid, ak).is_some_and(|ai| m.valid_at(ai));
                if m.header.kind != Kind::Content || !valid {
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

/// Rebuilds `(tid, ak)` from its held bodies under the current judgments, and what it derives.
pub(crate) fn rejoin(tx: &mut Tx<'_>, tid: &Tid, ak: &osis_base::Ak) -> Result<()> {
    atomic::rebuild(tx, tid, ak, &[], false)?;
    atomic::observe_state(tx, tid, ak)
}

/// Loads the in-memory indexes from the store (open, and after forgetting): from the persisted
/// index when this build wrote it (`engine::index`: commit metas with their validity, the
/// indexes derived from role bodies, perm's reading of each role commit; no part is decoded),
/// else from every commit record, re-judging every delta. `Some(aspects)` when they were
/// rebuilt from the commit records: the aspects whose judgments differ from what the replaced
/// index held (their states follow the old judgments until rebuilt; every aspect with something
/// invalid when that index does not decode).
pub(crate) fn load(tx: &mut Tx<'_>, rebuild: bool) -> Result<Option<Vec<(Tid, osis_base::Ak)>>> {
    if let Some(b) = tx.txn.get_local(records::HLC)?
        && let Ok(a) = <[u8; 8]>::try_from(b.as_slice())
        && let Some(ts) = osis_base::Ts::from_u64(u64::from_be_bytes(a))
    {
        tx.core.hlc.observe(ts);
    }
    let mut created = Vec::new();
    tx.scan(records::CREATED, |k, v| {
        let lim = osis_base::Limits { max_depth: 8, max_bytes: v.len() };
        let rec = osis_base::decode(&v, &lim).ok().and_then(|v| CreationRecord::from_value(&v)).ok_or(Error::Corrupt("creation record"))?;
        created.push((k.to_vec(), rec));
        Ok(())
    })?;
    for (k, r) in created {
        // a reload at run time sees the memory overlay's records too
        match tx.txn.is_memory_local(&[records::CREATED, &k].concat()) {
            true => tx.core.ix.held.create_memory(r),
            false => tx.core.ix.held.create(r),
        }
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
    // the `keys.0` parts that wrote a keyset, kept once their bodies dropped or went missing
    let mut parts = Vec::new();
    tx.scan(records::OWN_KEYS, |k, _| {
        let bad = || Error::Corrupt("own keys");
        let (t, c) = k.split_at_checked(15).ok_or_else(bad)?;
        parts.push((Tid::from_bytes(t.try_into().map_err(|_| bad())?), CommitId(c.try_into().map_err(|_| bad())?)));
        Ok(())
    })?;
    for (t, c) in parts {
        tx.core.ix.keyset_parts.insert(t, c);
    }
    // one record per AK; a schema's AKs share one `Arc`
    let mut schemas = BTreeMap::new();
    let mut parsed: BTreeMap<Vec<u8>, std::sync::Arc<osis_schema::Schema>> = BTreeMap::new();
    tx.scan(records::SCHEMAS, |k, v| {
        let ak = std::str::from_utf8(k).map_err(|_| Error::Corrupt("schema key"))?.to_string();
        let s = match parsed.get(&v) {
            Some(s) => s.clone(),
            None => {
                let bad = |_| Error::Corrupt("schema");
                let value = osis_base::decode(&v, &osis_base::Limits::default()).map_err(bad)?;
                let s = std::sync::Arc::new(osis_schema::Schema::from_value(&value).map_err(|_| Error::Corrupt("schema"))?);
                parsed.insert(v, s.clone());
                s
            }
        };
        schemas.insert(ak, s);
        Ok(())
    })?;
    tx.core.schemas.extend(schemas);
    let fast = !rebuild && crate::engine::index::current(tx)?;
    let old = if fast { None } else { crate::engine::index::old_judgments(tx) };
    if fast {
        {
            let _s = crate::costs::span("open: index");
            crate::engine::index::load(tx)?;
        }
        let _s = crate::costs::span("open: adapt");
        // perm's inputs: the edge writes of the role commits, oldest first, from what the
        // index keeps of their bodies
        let mut edges = crate::engine::index::load_edges(tx)?;
        let mut ids: Vec<(osis_base::Ts, CommitId)> = tx.core.ix.commits.iter().filter(|(_, m)| m.view.kind.is_role()).map(|(id, m)| (m.view.ts, *id)).collect();
        ids.sort();
        for (_, id) in ids {
            // the view, not the header (decoded only for a roster snapshot's linked frontiers)
            let Some(v) = tx.core.ix.commits.get(&id).map(|m| m.view.clone()) else { continue };
            let parts = edges.remove(&id).ok_or(Error::Corrupt("edges row missing"))?;
            // every row is what its record reads now (rewritten with it: late parts, drops)
            #[cfg(debug_assertions)]
            debug_assert_eq!(parts, edge_parts(tx, &id)?, "node/edges row of {id:?} is stale");
            validity::add_role_commit(tx, &v, None, &id, &parts)?;
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
                blob.header.resolve(&mut TxBlobs::new(&mut tx.txn), &dedup).map_err(|_| Error::Corrupt("header lists"))?;
            }
            let id = blob.id();
            let h = Arc::new(blob.header.clone());
            let valid = vec![true; h.aspects.len()];
            let missing = (0..h.aspects.len()).filter(|ai| !blob.parts.iter().any(|p| p.ai == *ai) && !head.dropped.contains_key(ai) && !head.stripped.contains(ai)).collect();
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
                    keys::note_keysets(tx.core, &h, &a.tid, &d.keysets);
                }
            }
            atomic::index_commit(tx.core, &id, &m.view);
            tx.core.put_meta(id, m);
            atomic::note_stands_in(tx.core, &id);
            if blob.header.kind.is_compaction() {
                snaps.push(blob.clone());
            }
            if blob.header.kind.is_role() || blob.header.aspects.iter().any(|a| a.ak.as_str() == osis_commit::retention::REQUIRED) {
                bodies.push(blob);
            }
        }
        // snapshots: their frontiers (the bodies carrying a write, `retention::carriers`) and
        // the writes they carry whose own delta was never received
        // (a part a piece at a time)
        for blob in snaps {
            let id = blob.id();
            // a part held as its leftover has no slot in the blob (`retention::leftover`)
            let stripped = tx.core.ix.commits.get(&id).map(|m| m.stripped.clone()).unwrap_or_default();
            let ais: BTreeSet<usize> = blob.parts.iter().map(|p| p.ai).chain(stripped).collect();
            for ai in ais {
                let Some(a) = blob.header.aspects.get(ai) else { continue };
                let mut carried: BTreeMap<osis_crdt::Source, BTreeSet<u64>> = BTreeMap::new();
                let keys = a.ak.as_str() == "keys.0";
                for g in each_held_piece(tx, &id, ai, &mut |tx, f| {
                    if keys {
                        keys::note_keysets(tx.core, &blob.header, &a.tid, &keys::keysets_of(&blob.header, ai, std::slice::from_ref(&f)));
                    }
                    for (src, ctrs) in copies::carried_of(tx.core, &a.tid, &a.ak, &f) {
                        carried.entry(src).or_default().extend(ctrs);
                    }
                    Ok(())
                })?
                .into_iter()
                .flatten()
                {
                    copies::note_carried_of(tx.core, &a.tid, &a.ak, &id, std::mem::take(&mut carried));
                    atomic::note_snapshot(tx.core, &a.tid, &a.ak, blob.header.ts, &id, g);
                }
            }
        }
        // perm inputs from role bodies, oldest first
        bodies.sort_by_key(|b| b.header.ts);
        for blob in bodies {
            let id = blob.id();
            let b = blob;
            let parts = examine_stored(tx, &b, &id)?;
            validity::note_required(tx.core, &b.header, &id, &parts);
            validity::note_required_rules(tx.core, &b.header, &id, &parts);
            if !b.header.kind.is_role() {
                continue;
            }
            for (ai, _, d) in &parts {
                if let (Some(a), Decoded::Delta(d)) = (b.header.aspects.get(*ai), d) {
                    match a.ak.as_str() {
                        "secrets.0" => keys::note_boxes_to(tx.core, &a.tid, &d.fragment),
                        "keys.0" => keys::note_keysets(tx.core, &b.header, &a.tid, &keys::keysets_of(&b.header, *ai, std::slice::from_ref(&d.fragment))),
                        _ => {}
                    }
                }
            }
            let v = tx.core.ix.commits.get(&id).map(|m| m.view.clone()).ok_or(Error::Corrupt("commit meta"))?;
            validity::add_role_commit(tx, &v, Some(&b.header), &id, &validity::EdgeParts::of(&b.header, &parts))?;
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
    crate::rotation::load_kept(tx)?;
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
    // with every commit's validity (a rebuild's re-judging below re-derives what flips)
    let things: BTreeSet<Tid> = tx.core.ix.keyset_parts.keys().copied().collect();
    keys::refresh_own_keys(tx, &things, false)?;
    // derived indexes from states (secrets: persisted, read again on a rebuild)
    let mut aspects = Vec::new();
    tx.scan(crate::engine::records::ASPECTS, |k, _| {
        let mut r = records::Rd::new(k);
        aspects.push((r.tid()?, r.ak()?));
        Ok(())
    })?;
    for (tid, ak) in aspects {
        match ak.as_str() {
            // definitions first, derived once below
            "group.0" => {
                let v = tx.state(&tid, &ak)?.and_then(osis_crdt::Fragment::read);
                tx.core.ix.groups.set_def(tid, atomic::group_def(v));
            }
            "secrets.0" | "keys.0" if fast => {}
            _ => atomic::observe_state(tx, &tid, &ak)?,
        }
    }
    tx.core.ix.groups.rebuild();
    if fast {
        // every delta's validity is persisted: nothing to re-judge
        tx.core.stale_things.clear();
        tx.core.stale_authors.clear();
        tx.core.stale_under.clear();
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
            let now = m.valid_at(ai);
            let was = old.as_ref().map(|o| o.get(id).and_then(|v| v.get(ai)).copied().unwrap_or(true));
            if was.map_or(!now, |w| w != now) {
                stale.insert((a.tid, a.ak.clone()));
            }
        }
    }
    stale.retain(|(_, ak)| !validity::perm_ak(ak.as_str()));
    Ok(Some(stale.into_iter().collect()))
}

/// Decodes a stored (already verified) commit's parts whole.
fn examine_stored(tx: &mut Tx<'_>, blob: &CommitBlob, id: &CommitId) -> Result<Vec<(usize, usize, Decoded)>> {
    let h = blob.header.clone();
    let mut out = Vec::new();
    let mut interner = Interner::new();
    for p in &blob.parts {
        let a = h.aspects.get(p.ai).ok_or(Error::Corrupt("part index"))?;
        let dedup = tx.core.dedup(&a.tid).ok_or(Error::Corrupt("dedup"))?;
        let mut blobs = TxBlobs::new(&mut tx.txn);
        let mut paged = BlobReader::new(&dedup, &mut blobs);
        let mut unpaged = osis_crdt::Unpaged;
        let reader: &mut dyn osis_crdt::PageSource = if h.ephemeral.is_some() { &mut unpaged } else { &mut paged };
        out.push((p.ai, p.di, verify_part(&h, id, p, &dedup, &mut interner, Some(reader)).map_err(|_| Error::Corrupt("stored delta"))?));
    }
    Ok(out)
}

/// What perm's adaptation reads of a held role commit: its held `roles.0` and `tenures.0`
/// parts.
pub(crate) fn edge_parts(tx: &mut Tx<'_>, id: &CommitId) -> Result<validity::EdgeParts> {
    let Some(h) = tx.core.ix.commits.get(id).map(|m| m.header.clone()) else { return Ok(validity::EdgeParts::default()) };
    let Some(blob) = tx.get_commit(id)? else { return Ok(validity::EdgeParts::default()) };
    edge_parts_of(tx, id, &h, blob)
}

/// `edge_parts` of a commit record's blob (`h`: its resolved header).
pub(crate) fn edge_parts_of(tx: &mut Tx<'_>, id: &CommitId, h: &Header, mut blob: CommitBlob) -> Result<validity::EdgeParts> {
    blob.header = h.clone();
    blob.parts.retain(|p| h.aspects.get(p.ai).is_some_and(|a| validity::edge_ak(a.ak.as_str())));
    Ok(validity::EdgeParts::of(h, &examine_stored(tx, &blob, id)?))
}

/// Decoded parts of a held commit on aspect `ai`.
pub(crate) fn held_parts(tx: &mut Tx<'_>, id: &CommitId, ai: usize) -> Result<Vec<Decoded>> {
    Ok(held_parts_at(tx, id, &|x| x == ai)?.into_iter().map(|x| x.2).collect())
}

/// The fragments of a held commit's parts on aspect `ai`.
pub(crate) fn held_fragments(tx: &mut Tx<'_>, id: &CommitId, ai: usize) -> Result<Vec<osis_crdt::Fragment>> {
    Ok(held_parts(tx, id, ai)?.into_iter().map(Decoded::into_fragment).collect())
}

/// Streams the held parts of commit `id` on aspect `ai`, in part order, a piece at a time
/// (`atomic::stream_stored`: the skeleton, then its pages; joining the pieces is joining the
/// part): what reads a part element by element holds about one page of it. Per part streamed,
/// a snapshot's frontiers and `Absorbed`. A stripped part (`Meta::stripped`) is its leftover,
/// one piece (`retention::leftover`).
pub(crate) fn each_held_piece(tx: &mut Tx<'_>, id: &CommitId, ai: usize, f: &mut dyn FnMut(&mut Tx<'_>, osis_crdt::Fragment) -> Result<()>) -> Result<Vec<Option<crate::engine::Gives>>> {
    let Some(m) = tx.core.ix.commits.get(id).cloned() else { return Ok(Vec::new()) };
    let h = m.header.clone();
    let Some(a) = h.aspects.get(ai) else { return Ok(Vec::new()) };
    if m.stripped.contains(&ai) {
        let Some(l) = crate::retention::leftover::get(tx, &a.tid, &a.ak, id, ai)? else { return Err(Error::Corrupt("leftover missing")) };
        f(tx, l.fragment)?;
        return Ok(vec![l.gives]);
    }
    let Some(mut blob) = tx.get_commit(id)? else { return Ok(Vec::new()) };
    blob.parts.retain(|p| p.ai == ai);
    if blob.parts.is_empty() {
        return Ok(Vec::new());
    }
    let dedup = tx.core.dedup(&a.tid).ok_or(Error::Corrupt("dedup"))?;
    let mut out = Vec::new();
    for p in &blob.parts {
        out.push(atomic::stream_stored(tx, &h, id, p, &dedup, f)?);
    }
    Ok(out)
}

/// Whether commit `id` holds a body on aspect `ai` to read (what `each_held_piece` reads): a
/// part in its stored blob, or its leftover.
pub(crate) fn stores_part(tx: &mut Tx<'_>, id: &CommitId, ai: usize) -> Result<bool> {
    if tx.core.ix.commits.get(id).is_some_and(|m| m.stripped.contains(&ai)) {
        return Ok(true);
    }
    Ok(tx.get_commit(id)?.is_some_and(|b| b.parts.iter().any(|p| p.ai == ai)))
}

/// Decoded parts of a held commit on the aspects `keep` selects, with their indexes (a
/// stripped part as its leftover, at delta index 0).
pub(crate) fn held_parts_at(tx: &mut Tx<'_>, id: &CommitId, keep: &dyn Fn(usize) -> bool) -> Result<Vec<(usize, usize, Decoded)>> {
    let Some(mut blob) = tx.get_commit(id)? else { return Ok(Vec::new()) };
    let Some(m) = tx.core.ix.commits.get(id).cloned() else { return Ok(Vec::new()) };
    blob.header = (*m.header).clone();
    blob.parts.retain(|p| keep(p.ai));
    let mut out = examine_stored(tx, &blob, id)?;
    for ai in m.stripped.iter().copied().filter(|ai| keep(*ai)) {
        let Some(a) = m.header.aspects.get(ai) else { continue };
        let Some(l) = crate::retention::leftover::get(tx, &a.tid, &a.ak, id, ai)? else { return Err(Error::Corrupt("leftover missing")) };
        let d = match l.gives {
            None => Decoded::Delta(osis_crdt::Delta { nonce: [0; osis_crdt::NONCE_LEN], fragment: l.fragment }),
            Some((frontiers, absorbed)) => Decoded::Snapshot(osis_crdt::Snapshot { nonce: [0; osis_crdt::NONCE_LEN], fragment: l.fragment, frontiers, absorbed: absorbed.into_iter().collect() }),
        };
        let at = out.partition_point(|x| (x.0, x.1) < (ai, 0));
        out.insert(at, (ai, 0, d));
    }
    Ok(out)
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

    // spec/permissions.md §5.1; spec/commits.md §2: the role content rules bind writers
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
        m.set(t, &Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        p0.commit(m).unwrap();
        let b = lp.peers[1].engine.tid();
        let c = osis_base::Tid::from_bytes([7; 15]);
        let mut m = Mutation::new();
        for x in [b, c] {
            let e = ct::Edge { role: Role::Write, until: None, invite: None, since: None, tied: None, keyset: None };
            m.op(t, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(x))], op: Op::Set(e.to_value()) }).unwrap();
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
        let reg = Ak::new("x:a.0").unwrap();
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
        let e = ct::Edge { role: Role::Write, until: None, invite: None, since: None, tied: None, keyset: None };
        m.op(x, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(a1))], op: Op::Set(e.to_value()) }).unwrap();
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
        let adm = ct::Edge { role: Role::Admin, until: None, invite: None, since: None, tied: None, keyset: None };
        for depth in [1, 3] {
            let p1 = &mut lp.peers[1];
            let mut m = Mutation::new();
            let mut cur = x;
            for _ in 0..depth {
                cur = p1.engine.new_thing(&mut m, cur);
            }
            m.op(cur, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(a1))], op: Op::Set(adm.to_value()) }).unwrap();
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
        m.set(t, &Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        let id = p0.commit(m).unwrap().unwrap();
        let blob = p0.engine.run(|tx| tx.get_commit(&id)).unwrap().unwrap();
        let c = &mut p0.engine.core;
        let mut meta = c.ix.commits.get(&id).unwrap().clone();
        meta.header = crate::engine::LazyHeader::stored(id, vec![0x80].into(), meta.view.clone(), c.header_fault.clone());
        c.ix.commits.insert(id, meta);
        assert!(p0.engine.header(&id).is_none());
        assert_eq!(p0.engine.parts_genuine(&blob), None);
        let mut m = Mutation::new();
        m.set(t, &Ak::new("x:a.0").unwrap(), &Value::Int(2)).unwrap();
        assert!(matches!(p0.engine.commit(m), Err(crate::Error::Corrupt(_))));
        assert!(matches!(p0.engine.commit(Mutation::new()), Err(crate::Error::Corrupt(_))));
    }
}
