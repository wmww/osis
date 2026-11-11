//! Receiving commits (spec/commits.md §4; spec/versioning.md §2; spec/crdt.md §2.2): decode,
//! verify, dedup by commit ID, pending reasons and parking, re-examination, apply in one
//! store transaction (role before content), late deltas of applied commits. Loading the
//! engine's indexes from the store lives here too, since it replays what apply records.

pub(crate) mod atomic;
pub(crate) mod copies;
pub(crate) mod unindex;
pub(crate) mod memory;
mod waits;
pub mod keys;
pub(crate) mod receipt;
pub(crate) mod validity;
#[cfg(test)]
mod tests_validity;
#[cfg(test)]
mod tests_addenda;
#[cfg(test)]
mod tests_order;
#[cfg(test)]
mod oracle;
#[cfg(test)]
mod tests_paged;
#[cfg(test)]
mod tests_steps;
#[cfg(test)]
mod tests_account;

pub(crate) use keys::keyset_changed;
pub(crate) use unindex::unindex_commit;
pub use memory::PART_OVERHEAD;
pub(crate) use waits::Waits;
#[cfg(debug_assertions)]
pub(crate) use atomic::{check_rebuilt, TxChange};
pub(crate) use atomic::{Unmerge, apply_verified, carries_any, forget_snapshot, index_commit, note_stands_in, ingest_secrets_keys, observe_state, rebuild, rejudged, run_batched, strip_valueless};

use crate::engine::blobs::TxBlobs;
use crate::engine::{Engine, Meta, Step, Tx, decode_commit_record, records};
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
    /// Unjudgeable (never pending, `Ingested::Awaits`): the record of the author or of a thing on
    /// a record chain is missing, or nothing leads from the author to the thing.
    MissingChain(Tid),
    /// Unjudgeable: the record of a thing whose part it holds, or of the actor, is unknown.
    UnknownCreated(Tid),
    /// `ts` more than `MAX_DRIFT` ahead of the wall clock.
    Drift,
    /// A page of a paged delta or a blob of a linked header list has not arrived.
    WaitBlobs,
    /// Parked: part of it is not interpretable by this build (spec/versioning.md §2).
    Parked,
    /// Stored pending; not examined since the node opened.
    Unexamined,
    /// An account's commit at an epoch whose minting rotation is not held (spec/permissions.md
    /// §5.5).
    Epoch(CommitId),
}

/// What `ingest` did with a commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ingested {
    Applied(CommitId),
    /// Already held (nothing new in it).
    Duplicate(CommitId),
    Pending(CommitId, Reason),
    /// Nothing kept: it cannot be judged yet (`Reason::MissingChain`, `UnknownCreated`). Its boxes
    /// were read; node-sync fetches it again when what it awaits arrives (notes/expiry-creation-design.md §3).
    Awaits(CommitId, Reason),
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
    /// A part or the commit cannot be judged and nothing else applies: thrown out (`Ingested::Awaits`).
    Awaits(Reason),
    Parked,
}

/// Parts of an examined commit that wait alone (`examine`): the first reason, the others, and which.
#[derive(Default)]
struct Aside {
    reason: Option<Reason>,
    others: Vec<Reason>,
    keys: BTreeSet<usize>,
}

impl Aside {
    /// `keys` wait for `r`.
    fn add(&mut self, r: Reason, keys: impl IntoIterator<Item = usize>) {
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
    /// Its thing's dedup secret (its hash, its pages' keys).
    pub dedup: osis_crypto::Secret32,
    /// A snapshot's frontiers and `Absorbed`.
    pub gives: Option<crate::engine::Gives>,
}

/// A commit's examined parts. Those of role-class aspects, `created.0` and `addenda.0` are
/// decoded whole: their readers (perm's edges, rotations, creation records, the addenda index)
/// read them whole, and they hold rosters of thousands, or a frontier's worth of commit IDs, not
/// millions of elements; the rest are streamed.
#[derive(Default)]
pub(crate) struct Parts {
    pub whole: Vec<(usize, Decoded)>,
    pub streamed: Vec<Streamed>,
    /// Held parts that wait alone (spec/commits.md §4).
    pub waiting: Option<Waiting>,
    /// Parts the commit applies without: unjudgeable, thrown out (`Ingested::Awaits`), with the
    /// parts themselves, whose boxes are read before they go.
    pub unjudged: BTreeMap<usize, Reason>,
    pub unjudged_parts: Vec<osis_commit::Part>,
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
        self.whole.iter().filter(|x| self.stripped.contains(&x.0)).map(|(ai, d)| (*ai, d.fragment().clone())).collect()
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

/// Whether a content commit of the memory class (`memory`) or the durable one may carry `ak`,
/// alike at every node (spec/commits.md §2): its `+` marker is the class, and an ephemeral
/// signal is in neither (it travels in a relay-only commit, spec/sync.md §9). A part on an
/// aspect of another class is never applied, by anyone.
pub(crate) fn fits_class(ak: &osis_base::Ak, memory: bool) -> bool {
    ak.ephemeral() == memory && !(memory && ak.signal())
}

/// `fits_class` for a received part's header entry `a`; a signal's part is in no compaction
/// snapshot; `replaces` only on a durable signal's part of a durable commit (spec/commits.md §2,
/// §5 Signals).
fn fits_part(a: &osis_commit::AspectEntry, memory: bool, snapshot: bool) -> bool {
    fits_class(&a.ak, memory) && !(a.ak.signal() && snapshot) && (a.replaces.is_none() || (!memory && !snapshot && crate::engine::edits::durable_signal(&a.ak)))
}

/// Whether a part of aspect `ak` is decoded whole (`Parts`).
fn whole_part(ak: &str) -> bool {
    osis_schema::core_types::is_role_class(ak) || osis_schema::core_types::is_addenda(ak) || ak == osis_commit::retention::CREATED
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

/// Creation records a durable commit carries on `created.0` (`minted_record`; a part giving none
/// gives nothing here, and is judged alone in `examine` once it can be). An ephemeral one carries
/// none (spec/commits.md §2).
pub(crate) fn carried_records(h: &Header, blob: &CommitBlob, id: &CommitId) -> BTreeMap<Tid, CreationRecord> {
    let mut out = BTreeMap::new();
    if h.ephemeral.is_some() {
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

/// The key that signs a commit of `h` by `author` (spec/wire.md §4): a key actor's own; an
/// account's, the key of the epoch the header names (its first by the creation record, another
/// by the held rotation minting it). `Ok(None)`: that rotation is not held, so the commit is
/// pending. Bad input: an author that is no key actor, an epoch or inner signature on a commit
/// by another than an account or none on one, a rotation by another than an account, a merge
/// signature count other than the rotation's names.
pub(crate) fn author_key(core: &crate::engine::Core, h: &osis_commit::Header, sigs: &osis_commit::Sigs, author: &CreationRecord) -> Result<Option<VerifyingKey>> {
    let CreationRecord::KeyActor { public_key, account, .. } = author else { return Err(Error::BadInput("author is not a key actor")) };
    if *account != h.epoch.is_some() || *account != sigs.inner.is_some() || (!*account && h.rotation.is_some()) {
        return Err(Error::BadInput("epoch or inner signature on a commit by another than an account, or none on one"));
    }
    if sigs.merge.len() != h.rotation.as_ref().map_or(0, |r| r.names.len()) {
        return Err(Error::BadInput("a merge signature count other than the rotation's names"));
    }
    epoch_key(core, &h.author, h.epoch, public_key)
}

/// The key of `author`'s epoch `epoch` (`None`: a plain key actor's key), `public_key` its
/// creation record's. `Ok(None)`: a rotation not held.
fn epoch_key(core: &crate::engine::Core, author: &Tid, epoch: Option<CommitId>, public_key: &[u8]) -> Result<Option<VerifyingKey>> {
    match epoch {
        None => Ok(Some(VerifyingKey::from_slice(public_key)?)),
        Some(e) if e == osis_commit::FIRST_EPOCH => Ok(Some(VerifyingKey::from_slice(public_key)?)),
        Some(e) => Ok(core.rotation(author, &e).map(|r| r.signing_key)),
    }
}

/// Whether `sigs` are `author`'s for commit `id` at epoch `epoch` (`None` for a key actor other
/// than an account, spec/wire.md §4), from what is held: `false` when that cannot be told.
pub fn signed_at(core: &crate::engine::Core, id: &CommitId, author: &Tid, epoch: Option<CommitId>, sigs: &osis_commit::Sigs) -> bool {
    let Some(CreationRecord::KeyActor { public_key, account, .. }) = core.created(author) else { return false };
    if *account != epoch.is_some() || *account != sigs.inner.is_some() {
        return false;
    }
    epoch_key(core, author, epoch, public_key).ok().flatten().is_some_and(|vk| osis_commit::verify_signature(id, sigs, &vk).is_ok())
}

/// Whether `blob`'s signature is its author's (`author_key`), the author's record from `record`:
/// `None` when that cannot be told yet (no record, an epoch not held).
pub(crate) fn signed_by_author(core: &crate::engine::Core, blob: &CommitBlob, id: &CommitId, record: Option<&CreationRecord>) -> Option<bool> {
    match author_key(core, &blob.header, &blob.sigs, record?) {
        Ok(Some(vk)) => Some(osis_commit::verify_signature(id, &blob.sigs, &vk).is_ok()),
        Ok(None) => None,
        Err(_) => Some(false),
    }
}

fn check_signature(tx: &mut Tx<'_>, blob: &CommitBlob, id: &CommitId, vk: &VerifyingKey) -> Result<()> {
    let _s = crate::costs::span("examine: signature");
    if let Err(e) = osis_commit::verify_signature(id, &blob.sigs, vk) {
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
    expire_stored(tx, id)?;
    let Some((_, bytes)) = tx.txn.get_pending(id)? else {
        tx.core.ix.pending.remove(id);
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
/// monotone rule, one result for every order (osis-node `order::held_set_decides` plays them).
pub(crate) fn examine(tx: &mut Tx<'_>, blob: &mut CommitBlob, id: &CommitId, skip: &BTreeSet<usize>, origin: Origin) -> Result<Exam> {
    if !blob.header.is_resolved() {
        // a held author's signature first: a false one costs no list. An author's record carried
        // by this commit waits for the lists: only the aspects say which part holds it
        if let Some(rec) = tx.core.created(&blob.header.author).cloned()
            && let Some(vk) = author_key(tx.core, &blob.header, &blob.sigs, &rec)?
        {
            check_signature(tx, blob, id, &vk)?;
        }
        let Some(dedup) = tx.core.dedup(&blob.header.actor) else { return Ok(Exam::Awaits(Reason::UnknownCreated(blob.header.actor))) };
        match blob.header.resolve(&mut TxBlobs::new(&mut tx.txn), &dedup) {
            Ok(()) => {}
            Err(e) if is_missing_page(&e) => return Ok(Exam::Pending(Reason::WaitBlobs, Vec::new())),
            Err(e) => return Err(e.into()),
        }
    }
    let h = blob.header.clone();
    let carried = carried_records(&h, blob, id);
    let held: BTreeMap<Tid, CreationRecord> = h.aspects.iter().map(|a| a.tid).chain([h.author, h.actor]).filter_map(|t| tx.core.created(&t).map(|r| (t, r.clone()))).collect();
    let chain_rec = |t: &Tid, core: &crate::engine::Core| -> Option<CreationRecord> { core.created(t).cloned().or_else(|| carried.get(t).cloned()) };
    let record = |t: &Tid| -> Option<CreationRecord> { held.get(t).cloned().or_else(|| carried.get(t).cloned()) };
    let Some(author) = record(&h.author) else { return Ok(Exam::Awaits(Reason::MissingChain(h.author))) };
    if record(&h.actor).is_none() {
        return Ok(Exam::Awaits(Reason::UnknownCreated(h.actor)));
    }
    // a part it cannot judge (its thing's record, record chain or the author's reach) goes; with
    // every held part such the commit is unjudgeable, never pending (spec/commits.md §4): thrown
    // out before a missing epoch or a `ts` ahead could keep its bytes
    let mut unjudged: BTreeMap<usize, Reason> = BTreeMap::new();
    for (ai, a) in h.aspects.iter().enumerate() {
        if skip.contains(&ai) || !blob.parts.iter().any(|p| p.ai == ai) {
            continue;
        }
        if let Some(wait) = thing_wait(tx.core, &h, a, &record, &chain_rec) {
            unjudged.insert(ai, wait);
        }
    }
    let unjudgeable = unjudged.values().next().cloned().filter(|_| blob.parts.iter().all(|p| skip.contains(&p.ai) || unjudged.contains_key(&p.ai)));
    let Some(vk) = author_key(tx.core, &h, &blob.sigs, &author)? else {
        if let Some(r) = unjudgeable {
            return Ok(throw_out(tx, id, &unjudged, r));
        }
        return Ok(Exam::Pending(Reason::Epoch(h.epoch.unwrap_or(osis_commit::FIRST_EPOCH)), Vec::new()));
    };
    check_signature(tx, blob, id, &vk)?;
    h.validate()?;
    // a frontier that does not decode is bad input, never a demotion without one (spec/wire.md
    // §4 field 12)
    if h.frontier.is_some() && validity::header_frontier(&h).is_none() {
        return Err(Error::BadInput("a frontier that is not a frontier"));
    }
    if let Some(r) = unjudgeable {
        return Ok(throw_out(tx, id, &unjudged, r));
    }
    // the bound is for received commits, a sibling node's too (spec/crdt.md §2.2): this node's
    // own are as far ahead as its HLC, which a wall clock set back must not turn against them
    if origin != Origin::Local && h.ts.wall_ms().0 > tx.now().0.saturating_add(MAX_DRIFT_MS) {
        return Ok(Exam::Pending(Reason::Drift, Vec::new()));
    }
    // the slots a held purge request emptied while they waited (`retention::strip_purged`; perhaps just
    // now, before the commit is first stored): the part's leftover, checked when kept, joins in
    // their place
    let emptied = crate::retention::emptied();
    let mut stripped: BTreeMap<usize, Decoded> = BTreeMap::new();
    for p in blob.parts.iter().filter(|p| p.delta == emptied) {
        if let Some(a) = h.aspects.get(p.ai)
            && let Some(l) = crate::retention::leftover::get(tx, &a.tid, &a.ak, id, p.ai)?
        {
            stripped.insert(p.ai, Decoded::Delta(osis_crdt::Delta { nonce: [0; osis_crdt::NONCE_LEN], fragment: l.fragment }));
        }
    }
    let stripped_ais: BTreeSet<usize> = stripped.keys().copied().collect();
    let kept = |p: &osis_commit::Part| p.delta == emptied && stripped_ais.contains(&p.ai);
    // a part that does not hash to its header entry is no part of this commit, and one on an aspect
    // of the wrong storage class is never applied: dropped
    // alone, before anything reads what is held (spec/commits.md §4)
    let junk: Vec<usize> = blob
        .parts
        .iter()
        .filter(|p| !kept(p))
        .filter(|p| {
            let Some(a) = h.aspects.get(p.ai) else { return true };
            !fits_part(a, h.ephemeral.is_some(), h.kind.is_compaction()) || record(&a.tid).is_some_and(|r| osis_crypto::delta_hash(&dedup_secret(r.nonce()), &p.delta) != a.hash)
        })
        .map(|p| p.ai)
        .collect();
    // a copy holding only what does not hash is no copy of it: refused, as if it never came
    let only_junk = !blob.parts.is_empty() && junk.len() == blob.parts.len() && blob.parts.iter().any(|p| h.aspects.get(p.ai).is_none_or(|a| fits_part(a, h.ephemeral.is_some(), h.kind.is_compaction())));
    if !junk.is_empty() {
        // a slot's stored first copy, kept while it could not be checked: a true copy may be held. Not a
        // copy just come (it kept nothing out), nor a part of the wrong class (it has no true copy)
        let kept_out = |p: &osis_commit::Part| junk.contains(&p.ai) && h.aspects.get(p.ai).is_none_or(|a| fits_part(a, h.ephemeral.is_some(), h.kind.is_compaction()));
        if tx.core.ix.pending.contains_key(id) && tx.txn.get_pending(id)?.and_then(|(_, b)| CommitBlob::decode_stored(&b).ok()).is_some_and(|b| b.parts.iter().any(kept_out)) {
            tx.core.redeliver.insert(*id);
        }
        blob.parts.retain(|p| !junk.contains(&p.ai));
        unjudged.retain(|ai, _| !junk.contains(ai));
        let now = tx.now();
        tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::BadInput, tids: Vec::new(), commit: Some(*id), peer: Some(h.author), detail: "delta hash".into() }, now);
    }
    if only_junk {
        return Err(Error::BadInput("delta hash"));
    }
    let mut aside = Aside::default();
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
    let rules = !(tx.core.skip_writer_rules && Some(h.author) == tx.core.me());
    let mut bad: Vec<usize> = Vec::new();
    for p in &blob.parts {
        if skip.contains(&p.ai) || unjudged.contains_key(&p.ai) {
            continue;
        }
        let a = h.aspects.get(p.ai).ok_or(Error::BadInput("part index"))?;
        if kept(p) {
            if let Some(d) = stripped.remove(&p.ai) {
                out.whole.push((p.ai, d));
                out.stripped.push(p.ai);
            }
            continue;
        }
        let dedup = record(&a.tid).map(|r| dedup_secret(r.nonce())).ok_or(Error::UnknownThing(a.tid))?;
        // one step: a part set aside or bad leaves nothing of its judging
        let wait = match tx.step(Step::Part, |tx| judge_part(tx, &h, id, p, a, &dedup, rules, &mut interner)) {
            Ok(Judged::Whole(part)) => {
                out.whole.push(part);
                continue;
            }
            Ok(Judged::Streamed(s)) => {
                out.streamed.push(s);
                continue;
            }
            Ok(Judged::Blobs) => Reason::WaitBlobs,
            Err(e) if e.class() == ErrorClass::Parked => Reason::Parked,
            Err(e) if e.class() == ErrorClass::BadInput => {
                bad.push(p.ai);
                out.bad.get_or_insert(e);
                continue;
            }
            Err(e) => return Err(e),
        };
        aside.add(wait, [p.ai]);
    }
    if !bad.is_empty() {
        // only bad parts: refused, nothing stored
        if rules && out.ais().is_empty() && aside.keys.is_empty() && unjudged.is_empty() {
            return Err(out.bad.take().unwrap_or(Error::BadInput("a bad part")));
        }
        blob.parts.retain(|p| !bad.contains(&p.ai));
        let detail = out.bad.as_ref().map(|e| e.to_string()).unwrap_or_default();
        let now = tx.now();
        tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::BadInput, tids: Vec::new(), commit: Some(*id), peer: Some(h.author), detail }, now);
    }
    // nothing else applies and a part cannot be judged: thrown out whole
    if out.ais().is_empty() && let Some(r) = unjudged.values().next().cloned() {
        return Ok(throw_out(tx, id, &unjudged, r));
    }
    // every held part waits: the commit (or, already applied, these parts) keeps waiting
    if !aside.keys.is_empty() && out.ais().is_empty() {
        return Ok(aside.verdict());
    }
    let (gone, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut blob.parts).into_iter().partition(|p| unjudged.contains_key(&p.ai));
    blob.parts = rest;
    out.unjudged = unjudged;
    out.unjudged_parts = gone;
    if let Some(reason) = aside.reason {
        let (parts, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut blob.parts).into_iter().partition(|p| aside.keys.contains(&p.ai));
        blob.parts = rest;
        out.waiting = Some(Waiting { parts, reason, others: aside.others });
    }
    // what joins of an emptied slot is the part's leftover: no stored copy holds it
    blob.parts.retain(|p| p.delta != emptied || !h.aspects.get(p.ai).is_some_and(|_| out.stripped.contains(&p.ai)));
    Ok(Exam::Ready(out))
}

/// Commit `id` thrown out whole, its parts unjudgeable for `unjudged` (the entry names `first`):
/// judged afresh when any one of the records comes, as a part on another thing may apply
/// (spec/commits.md §4).
fn throw_out(tx: &mut Tx<'_>, id: &CommitId, unjudged: &BTreeMap<usize, Reason>, first: Reason) -> Exam {
    tx.core.waits.awaits_records(*id, unjudged.values().filter_map(|r| match r {
        Reason::MissingChain(t) | Reason::UnknownCreated(t) => Some(*t),
        _ => None,
    }));
    Exam::Awaits(first)
}

/// What judging a part alone found, short of bad (`judge_part`'s `Err`, `Parked` among those).
enum Judged {
    /// Good, decoded whole.
    Whole((usize, Decoded)),
    /// Good, to stream at apply.
    Streamed(Streamed),
    /// A page is not held.
    Blobs,
}

/// Judges part `p` by itself, from the signed header, its bytes and held data. Bad input is about
/// this part alone (`examine`). `rules`: the writer rules hold.
#[allow(clippy::too_many_arguments)]
fn judge_part(tx: &mut Tx<'_>, h: &Header, id: &CommitId, p: &osis_commit::Part, a: &osis_commit::AspectEntry, dedup: &osis_crypto::Secret32, rules: bool, interner: &mut Interner) -> Result<Judged> {
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
            Judged::Whole((p.ai, d))
        })
    } else {
        // the full check, keeping nothing: apply streams it again
        let mut each = |f: osis_crdt::Fragment| {
            late |= carries && f.max_ts().is_some_and(|t| t > h.ts);
            Ok(())
        };
        osis_commit::stream_part(h, id, p, dedup, interner, Some(reader), &mut each)
            .map(|gives| Judged::Streamed(Streamed { ai: p.ai, dedup: dedup.clone(), gives: gives.map(|x| (x.frontiers, x.absorbed.into_iter().collect())) }))
    };
    let judged = match r {
        Ok(d) => d,
        Err(e) if is_missing_page(&e) => return Ok(Judged::Blobs),
        // an oversize value in a part is the part's fault, not this node's
        Err(osis_commit::Error::TooLarge(_)) => return Err(Error::BadInput("a part too large")),
        Err(e) => return Err(e.into()),
    };
    if late {
        return Err(Error::BadInput("carried write stamped after its commit"));
    }
    if rules && let Judged::Whole(part) = &judged {
        validity::check_holders_parts(h, id, std::slice::from_ref(part))?;
    }
    Ok(judged)
}

/// What thing `a.tid` waits for: its `created.0` record, the record chain up to a key actor, the
/// author's chain certificates (spec/permissions.md §4). A function of the thing, not of the part.
fn thing_wait(
    core: &crate::engine::Core,
    h: &Header,
    a: &osis_commit::AspectEntry,
    record: &dyn Fn(&Tid) -> Option<CreationRecord>,
    chain_rec: &dyn Fn(&Tid, &crate::engine::Core) -> Option<CreationRecord>,
) -> Option<Reason> {
    // an ended thing is unknown, but for what judges its ending written before it
    // (`retention::end`); an ending by expiry keeps no record but for a dependent
    let ended = |id: &CommitId| !crate::retention::end::judges_ending(a.ak.as_str()) || a.ak.as_str() != osis_commit::retention::CREATED && crate::retention::end::Ending::of(core, &a.tid).is_some_and(|e| e.after(h, id));
    if record(&a.tid).is_none() || core.ended(&a.tid) && ended(&h.id()) {
        return Some(Reason::UnknownCreated(a.tid));
    }
    let mut chain = vec![a.tid];
    // a chain deeper than `MAX_CHAIN_DEPTH` is not waited for further: its deltas are invalid
    // (`validity::too_deep`, spec/permissions.md §1)
    for step in osis_base::record_chain(a.tid, |t| chain_rec(t, core).map(|r| r.record_link())) {
        match step {
            ChainStep::Up { admin: up, .. } => chain.push(up),
            ChainStep::Key(_) | ChainStep::TooDeep => {}
            ChainStep::Unknown(t) => return Some(Reason::MissingChain(t)),
        }
    }
    // it is on the record chain, or held edge writes lead from it to the chain (a revoked author
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
    // the stored copy as the clock leaves it, ticks or not
    expire_stored(tx, &id)?;
    // a kept copy takes no new content (spec/permissions.md §3, Retain)
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
    let _s = crate::costs::span("examine");
    let out = match examine(tx, &mut blob, &id, &BTreeSet::new(), origin)? {
        Exam::Ready(parts) => {
            let w = parts.waiting.as_ref().map(Waiting::copy);
            tx.core.waits.unawaits(&id);
            let waits = settle_waits(tx, &id, &parts.unjudged);
            read_unjudged_boxes(tx, &blob, &id, &parts.unjudged_parts)?;
            unpend(tx, &id)?;
            apply_verified(tx, &blob, parts, origin, received)?;
            // what a part still waiting read of its boxes may be what opens what it waits for
            match w {
                Some(w) => pend_aside(tx, &id, &blob, w)?,
                None if !waits && settled_boxes(tx, &id) => keys::forget_unchecked(tx, &id)?,
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
            let _ = others;
            Ingested::Pending(id, r)
        }
        Exam::Awaits(r) => {
            keys::read_pending_boxes(tx, &blob, &id)?;
            tx.core.waits.awaits(id, blob.header.aspects.iter().map(|a| a.tid).collect());
            Ingested::Awaits(id, r)
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

/// Notes the slots of `id` it applied without (`Awaiting`), and whether any.
fn settle_waits(tx: &mut Tx<'_>, id: &CommitId, unjudged: &BTreeMap<usize, Reason>) -> bool {
    for r in unjudged.values() {
        let held = matches!(r, Reason::MissingChain(t) if tx.core.created(t).is_some());
        tx.core.waits.slot_waits(held, *id, r);
    }
    !unjudged.is_empty()
}

/// Reads the boxes of the parts of `blob` an applied commit goes on without.
fn read_unjudged_boxes(tx: &mut Tx<'_>, blob: &CommitBlob, id: &CommitId, parts: &[osis_commit::Part]) -> Result<()> {
    if parts.is_empty() {
        return Ok(());
    }
    keys::read_pending_boxes(tx, &CommitBlob { header: blob.header.clone(), sigs: blob.sigs.clone(), parts: parts.to_vec() }, id)
}

/// Whether `id` gave reading-only secrets that may go now: no `secrets.0` part of it is missing
/// (a part thrown out earlier: its boxes may open what it awaits).
fn settled_boxes(tx: &Tx<'_>, id: &CommitId) -> bool {
    tx.core.waits.read_any(id) && !tx.core.ix.commits.get(id).is_some_and(|m| m.missing.iter().any(|ai| m.header.aspects.get(*ai).is_some_and(|a| a.ak.as_str() == "secrets.0")))
}

/// Keeps commit `id` pending (`bytes` as stored) for `reason`.
fn pend(tx: &mut Tx<'_>, id: &CommitId, kind: PendingKind, bytes: &[u8], reason: Reason) -> Result<()> {
    tx.core.touch();
    tx.txn.put_pending(id, kind, bytes)?;
    tx.core.ix.pending.insert(*id, reason);
    tx.core.pended.insert(*id);
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
    Ok(())
}

/// Commit `id` pends no more: its stored bytes go. Whether it was pending.
fn unpend(tx: &mut Tx<'_>, id: &CommitId) -> Result<bool> {
    let was = tx.core.ix.pending.remove(id).is_some();
    if was {
        tx.core.touch();
        tx.txn.remove_pending(id, Shred::Yes)?;
    }
    Ok(was)
}

/// The parts of the stored pending copy of `id` past their expiry go, as their timers take them
/// (`retention::expire_waiting`): what applies is a function of the arrivals and the clock, never
/// of when ticks ran.
fn expire_stored(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    if !tx.core.ix.pending.contains_key(id) {
        return Ok(());
    }
    let Some((_, bytes)) = tx.txn.get_pending(id)? else { return Ok(()) };
    let Ok(old) = CommitBlob::decode_stored(&bytes) else { return Ok(()) };
    if old.header.expires.is_none_or(|t| t > tx.now().0) {
        return Ok(());
    }
    let mut h = match tx.core.ix.commits.get(id) {
        Some(m) => (*m.header).clone(),
        None => old.header.clone(),
    };
    // a header whose lists are away is judged once they come (`retention::pending_drops`)
    if !h.is_resolved()
        && let Some(dedup) = tx.core.dedup(&h.actor)
    {
        let mut r = h.clone();
        if r.resolve(&mut TxBlobs::new(&mut tx.txn), &dedup).is_ok() {
            h = r;
        }
    }
    // a memory commit's copy is memory work, as its ingest is (`ingest_blob`)
    let memory = h.ephemeral.is_some();
    tx.in_class(memory, |tx| crate::retention::expire_waiting(tx, id, &old, &h))
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
            blob.parts.retain(|p| p.ai < h.aspects.len());
        }
        let mut others: Vec<osis_commit::Part> = Vec::new();
        let mut rest = Vec::new();
        for p in std::mem::take(&mut blob.parts) {
            match old.parts.binary_search_by_key(&p.ai, |x| x.ai).ok().and_then(|i| old.parts.get_mut(i)) {
                Some(x) if x.delta == p.delta => {}
                Some(_) => others.push(p),
                None => rest.push(p),
            }
        }
        blob.parts = rest;
        if !others.is_empty() {
            keys::read_pending_boxes(tx, &CommitBlob { header: old.header.clone(), sigs: old.sigs.clone(), parts: others }, id)?;
        }
        let sigs = blob.sigs.clone();
        let mut merged = merge_parts(old, blob);
        // a true copy's signatures replace the first once its author is known here, by what this
        // copy brought (its `created.0`) or by anything else
        if sigs != merged.sigs {
            let carried = carried_records(&merged.header, &merged, id);
            let author = tx.core.created(&merged.header.author).cloned().or_else(|| carried.get(&merged.header.author).cloned());
            let copy = CommitBlob { header: merged.header.clone(), sigs: sigs.clone(), parts: Vec::new() };
            if signed_by_author(tx.core, &copy, id, author.as_ref()) == Some(true) {
                merged.sigs = sigs;
            }
        }
        return Ok(merged);
    }
    Ok(blob)
}

/// `a` with the parts of `b` on slots it lacks.
fn merge_parts(mut a: CommitBlob, b: CommitBlob) -> CommitBlob {
    for p in b.parts {
        if let Err(i) = a.parts.binary_search_by_key(&p.ai, |x| x.ai) {
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
    blob.parts.retain(|p| !skip.contains(&p.ai));
    if blob.parts.is_empty() {
        crate::retention::forget_waiting_leftovers(tx, id)?;
        unpend(tx, id)?;
        return Ok(Ingested::Duplicate(*id));
    }
    let mut merged = merge_parts(held, blob.clone());
    let _s = crate::costs::span("examine");
    let out = match examine(tx, &mut merged, id, &skip, Origin::Remote)? {
        Exam::Ready(parts) => {
            let w = parts.waiting.as_ref().map(Waiting::copy);
            let waits = settle_waits(tx, id, &parts.unjudged);
            read_unjudged_boxes(tx, &merged, id, &parts.unjudged_parts)?;
            unpend(tx, id)?;
            let ais = parts.ais();
            crate::retention::reopen_late(tx, id, &ais)?;
            atomic::join_late(tx, id, &merged, parts)?;
            // a body back and judged again (uncovered, missing after its purge fell, gone at its
            // expiry while pending): whatever the aspect lacked for it is in, held or not
            for ai in ais {
                if let Some(a) = merged.header.aspects.get(ai) {
                    crate::retention::suspect::body_back(tx, id, ai, &a.tid, &a.ak)?;
                }
            }
            match w {
                Some(w) => pend_aside(tx, id, &merged, w)?,
                None if !waits && settled_boxes(tx, id) => keys::forget_unchecked(tx, id)?,
                None => {}
            }
            Ingested::Applied(*id)
        }
        Exam::Pending(r, others) => {
            // what `examine` dropped of the waiting parts goes from the stored copy too
            blob.parts.retain(|p| merged.parts.binary_search_by_key(&p.ai, |x| x.ai).is_ok());
            let n = blob.parts.len();
            crate::retention::pending_drops(tx, id, &mut blob, &merged.header)?;
            if blob.parts.len() != n {
                return late_parts(tx, id, blob);
            }
            pend(tx, id, PendingKind::Pending, &blob.encode(), r.clone())?;
            keys::read_pending_boxes(tx, &blob, id)?;
            let _ = others;
            Ingested::Pending(*id, r)
        }
        // the waiting parts are thrown out; the commit stays applied
        Exam::Awaits(r) => {
            keys::read_pending_boxes(tx, &blob, id)?;
            let held = matches!(&r, Reason::MissingChain(t) if tx.core.created(t).is_some());
            tx.core.waits.slot_waits(held, *id, &r);
            Ingested::Awaits(*id, r)
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
fn held_and_skip(tx: &mut Tx<'_>, id: &CommitId) -> Result<(CommitBlob, BTreeSet<usize>)> {
    let mut held = Arc::unwrap_or_clone(tx.get_commit(id)?.ok_or(Error::Corrupt("commit record"))?);
    let meta = tx.core.ix.commits.get(id).cloned().ok_or(Error::Corrupt("commit index"))?;
    let mut skip: BTreeSet<usize> = held.parts.iter().map(|p| p.ai).collect();
    for ai in meta.dropped.keys().chain(meta.stripped.iter()) {
        if !crate::retention::takes_late(tx, id, *ai)? {
            skip.insert(*ai);
        }
    }
    held.header = (*meta.header).clone();
    Ok((held, skip))
}

/// Applies a commit this node just built (no signature check: it signed it).
pub(crate) fn apply_local(tx: &mut Tx<'_>, blob: &CommitBlob, received: WallMs) -> Result<()> {
    let id = blob.id();
    let mut b = blob.clone();
    match examine(tx, &mut b, &id, &BTreeSet::new(), Origin::Local)? {
        Exam::Ready(parts) if parts.waiting.is_some() => Err(Error::Misuse("own commit not applicable: a part waits")),
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
        Exam::Awaits(r) | Exam::Pending(r, _) => Err(Error::Misuse(match r {
            Reason::MissingChain(_) => "own commit not applicable: a record on its chain is missing",
            Reason::Epoch(_) => "own commit not applicable: its epoch's rotation is missing",
            Reason::UnknownCreated(_) => "own commit not applicable: a thing's record is unknown",
            Reason::Drift => "own commit not applicable: ts drift",
            Reason::WaitBlobs => "own commit not applicable: blobs missing",
            Reason::Parked | Reason::Unexamined => "own commit not applicable: parked",
        })),
        Exam::Parked => Err(Error::Misuse("own commit not applicable: parked")),
    }
}

impl Engine {
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
            match record(&self.core, &a.tid) {
                Some(r) if osis_crypto::delta_hash(&dedup_secret(r.nonce()), &p.delta) != a.hash => return Some(false),
                Some(_) => {}
                None => known = false,
            }
        }
        match signed_by_author(&self.core, blob, &id, record(&self.core, &h.author).as_ref()) {
            Some(true) => {}
            Some(false) => return Some(false),
            None => known = false,
        }
        known.then_some(true)
    }

    /// The commits with a part or signature of a pending copy proved junk since the last call, when a
    /// true copy the first one kept out may be held by the sync layer (`with_pending`).
    pub fn take_redeliver(&mut self) -> BTreeSet<CommitId> {
        std::mem::take(&mut self.core.redeliver)
    }

    /// Commits stored pending since the last call (node-sync's `sweep_pending`).
    pub fn take_pended(&mut self) -> BTreeSet<CommitId> {
        std::mem::take(&mut self.core.pended)
    }

    /// Names commit `id` for `take_redeliver`.
    pub fn name_redeliver(&mut self, id: CommitId) {
        self.core.redeliver.insert(id);
    }

    /// The slots of commit `id` no copy need bring here: those held, applied or pending, and those
    /// counting as never received (spec/commits.md §5), its body dropped or past its expiry, which
    /// only a new copy brings back (`SyncEngine::redeliver`).
    pub fn settled_slots(&mut self, id: &CommitId) -> Result<BTreeSet<usize>> {
        let id = *id;
        self.run(|tx| {
            let now = tx.now().0;
            let mut out: BTreeSet<usize> = BTreeSet::new();
            let pending = tx.txn.get_pending(&id)?.and_then(|(_, b)| CommitBlob::decode_stored(&b).ok());
            if let Some(b) = &pending {
                out.extend(b.parts.iter().map(|p| p.ai));
                out.extend((0..b.header.aspects.len()).filter(|ai| crate::retention::pending_expired(tx, &b.header, *ai)));
            }
            if let Some(b) = tx.get_commit(&id)? {
                out.extend(b.parts.iter().map(|p| p.ai));
            }
            if let Some(m) = tx.core.ix.commits.get(&id) {
                out.extend((0..m.header.aspects.len()).filter(|ai| m.dropped.contains_key(ai) || m.header.expires.is_some_and(|t| t <= now)));
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
            let applied: BTreeSet<usize> = match &meta {
                Some(_) => tx.get_commit(id)?.map(|b| b.parts.iter().map(|p| p.ai).collect()).unwrap_or_default(),
                None => BTreeSet::new(),
            };
            let mut gone = false;
            for p in &copy.parts {
                if meta.as_ref().is_some_and(|m| m.dropped.contains_key(&p.ai) || m.stripped.contains(&p.ai) && crate::retention::valueless(tx.core, id, p.ai)) || pending.is_some() && (crate::retention::pending_expired(tx, &h, p.ai) || pending.as_ref().map(|b| crate::retention::waiting_stripped(tx, b, id, p.ai)).transpose()?.unwrap_or(false) || pending.as_ref().is_some_and(|b| !b.parts.iter().any(|q| q.ai == p.ai)) && crate::retention::known_purged(tx, &h, id, p.ai)?) {
                    gone = true;
                    continue;
                }
                // applied, or nothing of the commit waits: no copy of it is needed
                let Some(held) = pending.as_ref().filter(|_| !applied.contains(&p.ai)) else { continue };
                if held.parts.iter().any(|q| q.ai == p.ai && q.delta == p.delta) {
                    continue;
                }
                let junk = match h.aspects.get(p.ai).map(|a| (a, tx.core.created(&a.tid))) {
                    None => true,
                    Some((a, Some(r))) => osis_crypto::delta_hash(&dedup_secret(r.nonce()), &p.delta) != a.hash,
                    Some((_, None)) => false,
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

    /// Receives raw creation records (a record blob, an inbox payload's, spec/permissions.md §4):
    /// a record proves itself by its hash, so it needs no commit. Returns how many were new; what
    /// awaited them is judged again.
    pub fn learn_records(&mut self, records: Vec<CreationRecord>) -> Result<usize> {
        let n = self.run(|tx| {
            let mut n = 0;
            for r in records {
                n += usize::from(atomic::learn_record(tx, r)?);
            }
            if n > 0 {
                tx.core.update_timelines();
                atomic::rejudged(tx, true)?;
            }
            Ok(n)
        })?;
        if n > 0 {
            self.reexamine()?;
        }
        Ok(n)
    }

    /// `ingest`, attributing diagnostics to `peer`.
    pub fn ingest_from(&mut self, bytes: &[u8], blobs: Vec<(BlobId, Vec<u8>)>, peer: Option<Tid>) -> Result<Ingested> {
        self.ingest_class(bytes, blobs, peer, None, &[])
    }

    /// `ingest_from` of an account's rotation with list blobs that came with it (under the
    /// same label, spec/sync.md §3): the thing lists of this rotation among them that verify are
    /// held in the same transaction, before it applies, so what they name never reads as
    /// unlisted here. Others are left (`hold_lists`).
    pub fn ingest_with_lists(&mut self, bytes: &[u8], blobs: Vec<(BlobId, Vec<u8>)>, peer: Option<Tid>, lists: &[Vec<u8>]) -> Result<Ingested> {
        self.ingest_class(bytes, blobs, peer, None, lists)
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
        self.ingest_class(bytes, Vec::new(), None, Some(room), &[])
    }

    /// `room`: a memory commit's (`ingest_memory`); `None` on the durable path.
    fn ingest_class(&mut self, bytes: &[u8], blobs: Vec<(BlobId, Vec<u8>)>, peer: Option<Tid>, room: Option<u64>, lists: &[Vec<u8>]) -> Result<Ingested> {
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
                fresh = !tx.store_blobs(blobs)?.is_empty();
            }
            if let Ok(b) = &decoded
                && let Some(root) = b.header.rotation.as_ref().map(|r| r.list_root)
                && !tx.core.ix.commits.contains_key(&b.id())
            {
                let id = b.id();
                let certs: Vec<osis_commit::thing_list::ThingCert> = lists.iter().filter_map(|l| osis_commit::thing_list::decode_list_blob(l).ok()).flatten().filter(|c| c.rotation == id && crate::flows::lists::verifies(c, &root)).collect();
                crate::flows::lists::keep_certs(tx, &certs)?;
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
    /// Forgets reading-only secrets sourced from `id`: it was judged bad or its last entry left.
    pub fn forget_awaiting(&mut self, id: &CommitId) -> Result<()> {
        self.core.waits.unawaits(id);
        if !self.core.waits.read_any(id) {
            return Ok(());
        }
        let id = *id;
        self.run(|tx| keys::forget_unchecked(tx, &id))
    }

    /// Whether a commit on `t` cannot be judged here yet.
    pub fn awaits_on(&self, t: &Tid) -> bool {
        self.core.waits.awaits_on(t)
    }

    /// Commit `id`'s last entry left: what it was noted under goes.
    pub fn no_entry_left(&mut self, id: &CommitId) {
        self.core.waits.unawaits(id);
    }

    /// Drops the stored pending copy of durable commit `id` (a pending or parked commit, or an
    /// applied one's parts that wait alone): the last entry carrying it left (node-sync's
    /// `sweep_pending`, notes/node-sync.md Unjudged input). Its parts count as never received;
    /// the next entry carrying it brings it back. Whether there was one.
    pub fn forget_pending(&mut self, id: &CommitId) -> Result<bool> {
        if !self.core.ix.pending.contains_key(id) {
            return Ok(false);
        }
        let id = *id;
        self.run(|tx| {
            // a memory commit's copy is the memory lane's, under its own share
            let Some((_, bytes)) = tx.txn.get_pending(&id)? else { return Ok(false) };
            let things: Vec<Tid> = CommitBlob::decode_stored(&bytes).ok().filter(|b| b.header.kind.is_role()).map(|b| b.header.aspects.iter().map(|a| a.tid).collect()).unwrap_or_default();
            tx.core.touch();
            crate::retention::forget_waiting_leftovers(tx, &id)?;
            tx.txn.remove_pending(&id, Shred::Yes)?;
            tx.core.ix.pending.remove(&id);
            tx.core.waits.unawaits(&id);
            keys::forget_unchecked(tx, &id)?;
            // secrets read from its boxes go unless something else reads them
            crate::rotation::mark_lost_due(tx, things)?;
            Ok(true)
        })
    }

    /// The commits reading-only secrets came from (node-sync's sweep of entries gone).
    pub fn reading_sources(&self) -> Vec<CommitId> {
        self.core.waits.sources().iter().copied().collect()
    }

    pub fn examined(&self) -> u64 {
        self.core.waits.examined
    }

    pub fn reexamine(&mut self) -> Result<()> {
        let _s = crate::costs::span("reexamine");
        loop {
            waits::wake(&mut self.core);
            let ids: Vec<CommitId> = self.core.ix.pending.keys().copied().collect();
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
                    // one step: a commit refused leaves nothing of its examination or apply
                    match tx.step(Step::Commit, |tx| ingest_blob(tx, b, Origin::Remote)) {
                        Ok(Ingested::Applied(_)) => progressed = true,
                        Ok(_) => {}
                        Err(e) if e.class() == ErrorClass::BadInput => {
                            tx.txn.remove_pending(&id, Shred::Yes)?;
                            crate::retention::forget_waiting_leftovers(tx, &id)?;
                            tx.core.ix.pending.remove(&id);
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
    /// step not verified yet): its applied holders, the holders its applied `secrets.0` boxes
    /// (one may read it through an actor a rotation boxed, with no grant held), and `named`,
    /// what the inbox blobs that named the label say of it (`keys::inbox_named`); those this
    /// node is or holds secrets of.
    pub fn hint_actors(&mut self, thing: &Tid, named: impl IntoIterator<Item = Tid>) -> Result<std::collections::BTreeSet<Tid>> {
        let mut out: std::collections::BTreeSet<Tid> = self.get_typed(thing, &osis_schema::core_types::ROLES)?.unwrap_or_default().into_keys().collect();
        out.extend(self.get_typed(thing, &osis_schema::core_types::SECRETS)?.unwrap_or_default().boxes.into_keys().map(|k| k.holder));
        out.extend(named);
        let me = self.core.me();
        out.retain(|t| Some(*t) == me || self.core.ix.secrets.contains_key(t));
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
        let ak = osis_base::Ak::new("created.0").ok()?;
        self.core.ix.by_aspect.get(&(*tid, ak.clone()))?.iter().find_map(|(_, id)| {
            let m = self.core.ix.commits.get(id)?;
            let ai = m.aspect(tid, &ak)?;
            (m.valid_at(ai)).then(|| Creation { commit: *id, ts: m.header.ts, node: m.header.author, actor: m.header.actor, received: m.received })
        })
    }

    /// The thing's last content change: of the held content commits (changes, reverts) validly writing one of its aspects other than `created.0`, `group.0` and the
    /// role-class ones, the one shown latest by `min(ts, received)` (an author's clock may
    /// run ahead; `received` is this node's), else its creation. Snapshots are no change, and
    /// ephemeral writes do not count.
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
                let c = Creation { commit: *id, ts: m.header.ts, node: m.header.author, actor: m.header.actor, received: m.received };
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
    atomic::rebuild(tx, tid, ak)?;
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
    crate::sides::load(tx)?;
    let mut created = Vec::new();
    tx.scan(records::CREATED, |k, v| {
        let lim = osis_base::Limits { max_depth: 8, max_bytes: v.len() };
        let rec = osis_base::decode(&v, &lim).ok().and_then(|v| CreationRecord::from_value(&v)).ok_or(Error::Corrupt("creation record"))?;
        created.push((k.to_vec(), rec));
        Ok(())
    })?;
    for (_, r) in created {
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
    let mut due = Vec::new();
    tx.scan(records::ADDENDA_DUE, |k, _| {
        due.push(CommitId(k.try_into().map_err(|_| Error::Corrupt("addenda due"))?));
        Ok(())
    })?;
    tx.core.ix.addenda_due.extend(due);
    let mut due = Vec::new();
    tx.scan(records::ROTATIONS_DUE, |k, _| {
        due.push(CommitId(k.try_into().map_err(|_| Error::Corrupt("listings due"))?));
        Ok(())
    })?;
    tx.core.ix.rotations_due.extend(due);
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
    let mut forgotten = Vec::new();
    tx.scan(records::FORGOTTEN, |k, v| {
        let bad = || Error::Corrupt("forgotten row");
        let mut r = records::Rd::new(k);
        let (tid, ak) = (r.tid()?, r.ak()?);
        let ts = v.try_into().map_err(|_| bad()).and_then(|b: [u8; 8]| osis_base::Ts::from_u64(u64::from_be_bytes(b)).ok_or_else(bad))?;
        forgotten.push(((tid, ak), ts));
        Ok(())
    })?;
    for (k, ts) in forgotten {
        tx.core.ix.forgotten.insert(k, ts);
    }
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
            // the view, not the header
            let Some(v) = tx.core.ix.commits.get(&id).map(|m| m.view.clone()) else { continue };
            let parts = edges.remove(&id).ok_or(Error::Corrupt("edges row missing"))?;
            // every row is what its record reads now (rewritten with it: late parts, drops)
            #[cfg(debug_assertions)]
            debug_assert_eq!(parts, edge_parts(tx, &id)?, "node/edges row of {id:?} is stale");
            validity::add_role_commit(tx.core, &v, &id, &parts);
        }
        // what each addendum says, from its row
        for (id, parts) in crate::engine::index::load_addenda(tx)? {
            let Some(v) = tx.core.ix.commits.get(&id).map(|m| m.view.clone()) else { continue };
            validity::index_addenda(tx.core, osis_perm::Point { ts: v.ts, node: v.author, commit: id }, &parts);
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
                if let Some(x) = &d.shown {
                    validity::note_shown(tx.core, &id, *ai, x.clone());
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
            if blob.header.kind.is_role() || blob.header.aspects.iter().any(|a| a.ak.as_str() == osis_commit::retention::RETENTION || osis_schema::core_types::is_addenda(a.ak.as_str())) {
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
                let keys = a.ak.as_str() == "keys.0";
                if let Some(g) = each_held_piece(tx, &id, ai, &mut |tx, f| {
                    if keys {
                        keys::note_keysets(tx.core, &blob.header, &a.tid, &keys::keysets_of(&blob.header, ai, std::slice::from_ref(&f)));
                    }
                    Ok(())
                })?
                .flatten()
                {
                    atomic::note_snapshot(tx.core, &a.tid, &a.ak, blob.header.ts, &id, g);
                }
            }
        }
        // what is a whole replace (`Meta::whole`), from each held plain body
        let plain: Vec<CommitId> = tx.core.ix.commits.iter().filter(|(_, m)| m.view.kind == Kind::Content && !m.view.memory).map(|(id, _)| *id).collect();
        for id in plain {
            for (ai, d) in held_parts_at(tx, &id, &|_| true)? {
                let Some(mut m) = tx.core.ix.commits.get(&id).cloned() else { continue };
                if m.view.aspects.get(ai).is_some_and(|a| crate::retention::snapshot::own_aspect(&a.ak)) && matches!(&d, Decoded::Delta(x) if crate::retention::snapshot::replaces(&x.fragment)) {
                    m.whole.insert(ai);
                    tx.core.put_meta(id, m);
                }
            }
        }
        // perm inputs from role bodies, oldest first
        bodies.sort_by_key(|b| b.header.ts);
        for blob in bodies {
            let id = blob.id();
            let b = blob;
            let parts = examine_stored(tx, &b, &id)?;
            atomic::note_rotation_sigs(tx.core, &b.header, &id, &b.sigs);
            validity::note_required(tx.core, &b.header, &id, &parts);
            validity::note_settings(tx.core, &b.header, &id, &parts);
            validity::note_addenda(tx.core, &b.header, &id, &parts);
            if !b.header.kind.is_role() {
                continue;
            }
            for (ai, d) in &parts {
                if let (Some(a), Decoded::Delta(d)) = (b.header.aspects.get(*ai), d) {
                    match a.ak.as_str() {
                        "secrets.0" => keys::note_boxes_to(tx.core, &a.tid, &d.fragment),
                        "keys.0" => keys::note_keysets(tx.core, &b.header, &a.tid, &keys::keysets_of(&b.header, *ai, std::slice::from_ref(&d.fragment))),
                        _ => {}
                    }
                }
            }
            let v = tx.core.ix.commits.get(&id).map(|m| m.view.clone()).ok_or(Error::Corrupt("commit meta"))?;
            validity::add_role_commit(tx.core, &v, &id, &validity::EdgeParts::of(&b.header, &parts));
        }
    }
    // which role commits of accounts count (spec/permissions.md §5.5), before any timeline
    crate::flows::account::refresh_epochs(tx)?;
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
            // a state-list row is a state (`Tx::derive`)
            "label.0" => {
                tx.core.ix.labeled.insert(tid);
            }
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
    crate::engine::edits::rebuild(tx)?;
    Ok(Some(stale.into_iter().collect()))
}

/// Rebuilds what node-sync's wakes read after a load (`waits::Awaiting`, the commits reading-only
/// secrets came from). From held headers: a missing slot whose record is held may wait for reach
/// (no search at load; a wake only costs a look at the commit's entries).
pub(crate) fn load_awaiting(core: &mut crate::engine::Core) {
    // a load is no arrival: what the index replayed wakes nothing
    core.ix.held.take_records();
    core.ix.held.take_moved();
    waits::load_reading(core);
    let slots: Vec<(CommitId, Tid)> = core.ix.commits.iter().flat_map(|(c, m)| m.missing.iter().filter_map(|ai| m.header.aspects.get(*ai)).map(|a| (*c, a.tid)).collect::<Vec<_>>()).collect();
    for (c, t) in slots {
        let known = core.created(&t).is_some();
        let r = if known { Reason::MissingChain(t) } else { Reason::UnknownCreated(t) };
        core.waits.slot_waits(known, c, &r);
    }
}

/// The delta of part `p` of a blob `examine` accepted (`Exam::Ready`), or of a stored commit
/// record, as checked bytes, to read decode-only. A record holds only parts `examine` checked in
/// full: bad, junk, unjudged and waiting parts leave the blob before `Tx::put_commit`, and every
/// rewrite of a record only removes parts. The engine's one `Checked::verified` (tools/policy.py).
fn checked(p: &osis_commit::Part) -> osis_crdt::Checked<'_> {
    osis_crdt::Checked::verified(&p.delta)
}

/// Decodes the parts of a stored commit record (or of one about to be stored: a blob `examine`
/// accepted) whole, decode-only (`checked`, `osis_commit::read_part_whole`).
fn examine_stored(tx: &mut Tx<'_>, blob: &CommitBlob, id: &CommitId) -> Result<Vec<(usize, Decoded)>> {
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
        out.push((p.ai, osis_commit::read_part_whole(&h, id, p.ai, checked(p), &mut interner, Some(reader)).map_err(|_| Error::Corrupt("stored delta"))?));
    }
    Ok(out)
}

/// What perm's adaptation reads of a held role commit: its held `roles.0` parts.
pub(crate) fn edge_parts(tx: &mut Tx<'_>, id: &CommitId) -> Result<validity::EdgeParts> {
    let Some(h) = tx.core.ix.commits.get(id).map(|m| m.header.clone()) else { return Ok(validity::EdgeParts::default()) };
    let Some(blob) = tx.get_commit(id)? else { return Ok(validity::EdgeParts::default()) };
    edge_parts_of(tx, id, &h, Arc::unwrap_or_clone(blob))
}

/// `edge_parts` of a commit record's blob (`h`: its resolved header).
pub(crate) fn edge_parts_of(tx: &mut Tx<'_>, id: &CommitId, h: &Header, mut blob: CommitBlob) -> Result<validity::EdgeParts> {
    blob.header = h.clone();
    blob.parts.retain(|p| h.aspects.get(p.ai).is_some_and(|a| validity::edge_ak(a.ak.as_str())));
    Ok(validity::EdgeParts::of(h, &examine_stored(tx, &blob, id)?))
}

/// The decoded part of a held commit on aspect `ai`.
pub(crate) fn held_part(tx: &mut Tx<'_>, id: &CommitId, ai: usize) -> Result<Option<Decoded>> {
    Ok(held_parts_at(tx, id, &|x| x == ai)?.pop().map(|x| x.1))
}

/// The fragment of a held commit's part on aspect `ai`.
pub(crate) fn held_fragment(tx: &mut Tx<'_>, id: &CommitId, ai: usize) -> Result<Option<osis_crdt::Fragment>> {
    Ok(held_part(tx, id, ai)?.map(Decoded::into_fragment))
}

/// Streams the held part of commit `id` on aspect `ai` a piece at a time (`atomic::stream_stored`:
/// the skeleton, then its pages; joining the pieces is joining the part): what reads a part
/// element by element holds about one page of it. `None` when no part is held, else a snapshot's
/// frontiers and `Absorbed`. A stripped part (`Meta::stripped`) is its leftover, one piece
/// (`retention::leftover`).
pub(crate) fn each_held_piece(tx: &mut Tx<'_>, id: &CommitId, ai: usize, f: &mut dyn FnMut(&mut Tx<'_>, osis_crdt::Fragment) -> Result<()>) -> Result<Option<Option<crate::engine::Gives>>> {
    let Some(m) = tx.core.ix.commits.get(id).cloned() else { return Ok(None) };
    let h = m.header.clone();
    let Some(a) = h.aspects.get(ai) else { return Ok(None) };
    if m.stripped.contains(&ai) {
        let Some(l) = crate::retention::leftover::get(tx, &a.tid, &a.ak, id, ai)? else { return Err(Error::Corrupt("leftover missing")) };
        f(tx, l.fragment)?;
        return Ok(Some(l.gives));
    }
    let Some(blob) = tx.get_commit(id)? else { return Ok(None) };
    let Some(p) = blob.parts.iter().find(|p| p.ai == ai) else { return Ok(None) };
    let dedup = tx.core.dedup(&a.tid).ok_or(Error::Corrupt("dedup"))?;
    Ok(Some(atomic::stream_stored(tx, &h, id, ai, checked(p), &dedup, f)?))
}

/// Whether commit `id` holds a body on aspect `ai` to read (what `each_held_piece` reads): a
/// part in its stored blob, or its leftover.
pub(crate) fn stores_part(tx: &mut Tx<'_>, id: &CommitId, ai: usize) -> Result<bool> {
    if tx.core.ix.commits.get(id).is_some_and(|m| m.stripped.contains(&ai)) {
        return Ok(true);
    }
    Ok(tx.get_commit(id)?.is_some_and(|b| b.parts.iter().any(|p| p.ai == ai)))
}

/// Decoded parts of a held commit on the aspects `keep` selects, with their aspect indexes (a
/// stripped part as its leftover).
pub(crate) fn held_parts_at(tx: &mut Tx<'_>, id: &CommitId, keep: &dyn Fn(usize) -> bool) -> Result<Vec<(usize, Decoded)>> {
    let Some(stored) = tx.get_commit(id)? else { return Ok(Vec::new()) };
    let Some(m) = tx.core.ix.commits.get(id).cloned() else { return Ok(Vec::new()) };
    // each stored part decoded once per write of the record (`Core::decoded`)
    let mut out = Vec::new();
    for p in stored.parts.iter().filter(|p| keep(p.ai)) {
        let fresh = |tx: &mut Tx<'_>| -> Result<Decoded> {
            let one = CommitBlob { header: (*m.header).clone(), sigs: stored.sigs.clone(), parts: vec![p.clone()] };
            drop(crate::costs::span("part decode"));
            examine_stored(tx, &one, id)?.pop().map(|x| x.1).ok_or(Error::Corrupt("stored delta"))
        };
        let d = match tx.core.decoded.part(id, p.ai) {
            Some(d) => {
                #[cfg(debug_assertions)]
                if tx.recheck(format!("commit part {id:?} {}", p.ai)) {
                    assert_eq!(crate::costs::paused(|| fresh(tx))?, *d, "decoded part {} of {id:?} went stale", p.ai);
                }
                d
            }
            None => {
                let d = Arc::new(fresh(tx)?);
                tx.core.decoded.keep_part(*id, p.ai, d.clone());
                d
            }
        };
        out.push((p.ai, (*d).clone()));
    }
    for ai in m.stripped.iter().copied().filter(|ai| keep(*ai)) {
        let Some(a) = m.header.aspects.get(ai) else { continue };
        let Some(l) = crate::retention::leftover::get(tx, &a.tid, &a.ak, id, ai)? else { return Err(Error::Corrupt("leftover missing")) };
        let d = match l.gives {
            None => Decoded::Delta(osis_crdt::Delta { nonce: [0; osis_crdt::NONCE_LEN], fragment: l.fragment }),
            Some((frontiers, absorbed)) => Decoded::Snapshot(osis_crdt::Snapshot { nonce: [0; osis_crdt::NONCE_LEN], fragment: l.fragment, frontiers, absorbed: absorbed.into_iter().collect() }),
        };
        let at = out.partition_point(|x| x.0 < ai);
        out.insert(at, (ai, d));
    }
    Ok(out)
}

/// A commit as a thing's time (`Engine::creation`, `Engine::changed`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Creation {
    pub commit: CommitId,
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
        let me = p0.engine.me();
        let mut m = Mutation::new();
        let t = p0.engine.new_thing(&mut m, me);
        m.set(t, &Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        p0.commit(m).unwrap();
        let b = lp.peers[1].engine.me();
        let c = osis_base::Tid::from_bytes([7; 15]);
        let mut m = Mutation::new();
        for x in [b, c] {
            let e = ct::Edge { role: Role::Write, until: None, invite: None, tied: None };
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

    // spec/permissions.md §1 (a first admin holds admin on its things; record chains within
    // MAX_CHAIN_DEPTH), §5: a writer creates A under X, B under A and C under B in one commit;
    // the commit is valid wherever applied. Under a first admin the writer may not write, the same
    // tree fails the local check, as does a chain of new things past MAX_CHAIN_DEPTH.
    #[test]
    fn tree_created_in_one_commit_spec_perm_1() {
        let mut lp = LocalPeer::new(2, 901, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (a0, a1) = (lp.peers[0].engine.me(), lp.peers[1].engine.me());
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
        let e = ct::Edge { role: Role::Write, until: None, invite: None, tied: None };
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
        // the first admin's tree: the last thing's delete keys derive from its base actor's secrets
        // through the two created above it (spec/crypto.md §3, §7)
        let mut m = Mutation::new();
        let d = p0.engine.new_thing(&mut m, x);
        let e = p0.engine.new_thing(&mut m, d);
        let f = p0.engine.new_thing(&mut m, e);
        m.set(f, &reg, &Value::Int(4)).unwrap();
        m.retention(f, &reg, osis_schema::Retention { by: osis_schema::PurgeBy::Writer }).unwrap();
        let id = p0.commit(m).unwrap().unwrap();
        let h = p0.engine.header(&id).unwrap();
        let wf = h.aspects.iter().find(|w| w.tid == f && w.ak == reg).unwrap();
        let levels: Vec<u8> = wf.keys.iter().map(|i| h.keys[*i].level).collect();
        assert_eq!(levels, [1, 2, 3]);
        // a writer of X gets no admin on what it creates below X: no edges there
        let adm = ct::Edge { role: Role::Admin, until: None, invite: None, tied: None };
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
            for _ in 0..osis_base::format::MAX_CHAIN_DEPTH + extra {
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
        let me = p0.engine.me();
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
