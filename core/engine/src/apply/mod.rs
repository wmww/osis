//! Receiving commits (spec/commits.md §4; spec/versioning.md §2; spec/crdt.md §2.2): decode,
//! verify, dedup by commit ID, pending reasons and parking, re-examination, apply in one
//! store transaction (role before content), late deltas of applied commits. Loading the
//! engine's indexes from the store lives here too, since it replays what apply records.

pub(crate) mod atomic;
pub mod carriers;
pub(crate) mod copies;
pub(crate) mod unindex;
pub(crate) mod memory;
pub(crate) mod reach;
mod waits;
pub mod keys;
pub(crate) mod receipt;
pub(crate) mod validity;
pub(crate) mod paths;

#[cfg(test)]
mod tests_validity;
#[cfg(test)]
mod tests_addenda;
#[cfg(test)]
mod oracle;
#[cfg(test)]
mod tests_paged;
#[cfg(test)]
mod tests_steps;
#[cfg(test)]
mod tests_failed_writes;
#[cfg(test)]
mod tests_faults;

pub(crate) use unindex::{unindex_commit, unindex_unreceived, unjudge_part};
pub use waits::Wake;
pub(crate) use waits::{awaited, awaits_record, next_at, pending_left, set_pending};
pub use memory::PART_OVERHEAD;
pub(crate) use waits::Waits;
#[cfg(debug_assertions)]
pub(crate) use atomic::{check_rebuilt, check_states};
pub(crate) use atomic::{apply_verified, carries_any, each_held_valid_piece, forget_snapshot, index_commit, note_carried, ingest_secrets_keys, observe_state, rebuild, rejudged, remove_in_place, run_batched, shred_covered, remove_gone_writes};
#[cfg(debug_assertions)]
pub(crate) use atomic::joined_without;

use crate::engine::blobs::TxBlobs;
use crate::engine::{Engine, Meta, Step, Tx, decode_commit_record, records};
use crate::error::{Error, Result};
use crate::events::{Diagnostic, DiagnosticKind, Origin};
use osis_commit::{CommitBlob, Decoded, Header, Kind, delta_ctx, verify_part};
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{BlobId, ChainStep, Classified, CommitId, CreationRecord, ErrorClass, Tid, Value, WallMs};
use osis_crdt::Interner;
use osis_crypto::{VerifyingKey, dedup_secret};
use osis_blob::BlobReader;
use osis_store::{PendingKind, Shred};
use std::borrow::Cow;
use std::cell::OnceCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Why a commit is pending (spec/commits.md §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// Unjudgeable: the record of the author or of a thing on a record chain is missing, or nothing
    /// leads from the author to the thing.
    MissingChain(Tid),
    /// Unjudgeable: the record of a thing whose part it holds, or of the actor, is unknown.
    UnknownCreated(Tid),
    /// Unjudgeable: a content part on a thing the node does not hold whole (outside the node
    /// closure, spec/commits.md §4 Outside the node closure), until it enters.
    Outside(Tid),
    /// Unjudgeable: its commit lists for this thing a delete key no held step up its record
    /// chain places (spec/crypto.md §7 Checked keys), until the steps move.
    Miskeyed(Tid),
    /// `ts` more than `MAX_DRIFT` ahead of the wall clock.
    Drift,
    /// A page of a paged delta or a blob of a linked header list has not arrived.
    WaitBlobs,
    /// Parked: part of it is not interpretable by this build (spec/versioning.md §2).
    Parked,
    /// Stored pending; not examined since the node opened.
    Unexamined,
    /// Set aside: applying it failed for a fault of this node (`Error::is_fault`: a broken
    /// invariant of this build), never a judgment of the commit; examined again at the next open
    /// (`set_aside`).
    Fault,
}

/// What `ingest` did with a commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ingested {
    Applied(CommitId),
    /// Already held (nothing new in it).
    Duplicate(CommitId),
    /// Kept pending: the commit, or parts of an applied one (`Engine::pends`).
    Pending(CommitId, Reason),
    /// Kept as bytes: this build cannot interpret part of it (spec/versioning.md §2).
    Parked(CommitId),
    /// A memory commit not held nor kept waiting: its parts could cost more decoded than the
    /// room given (`Engine::ingest_memory`), found before decoding them.
    TooLarge(CommitId),
}

// one per examined commit, moved straight into a match
#[allow(clippy::large_enum_variant)]
pub(crate) enum Exam {
    /// `Parts::waiting`: the parts that wait alone, taken out of the blob.
    Ready(Parts),
    /// The commit itself waits (its header lists, its epoch, drift): never for its parts.
    Pending(Reason),
    /// The commit, or every held part of it, cannot be judged yet: it pends whole, parked under
    /// what each part awaits (`pend_unjudgeable`).
    Awaits(Reason),
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
}

/// Parts `examine` set aside: stored pending under the commit's ID while the rest apply.
pub(crate) struct Waiting {
    pub parts: Vec<osis_commit::Part>,
    /// The entry keys of the things only these parts are on (`CommitBlob::keys`).
    pub keys: BTreeMap<usize, [u8; 32]>,
    pub reason: Reason,
    /// Any other reason.
    pub others: Vec<Reason>,
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

/// A commit's decoded parts, with what is read of them, each read once on first ask: each
/// `keys.0` part's keysets (`keys::KeysBody`) and perm's reading of its `roles.0` parts
/// (`validity::PermParts`, also its record's `node/perm` row). A part may come as several
/// deltas (pages of one rotation): each entry is read alone.
pub(crate) struct PartsRead<'a> {
    h: &'a Header,
    parts: &'a [(usize, Decoded)],
    keys: Cow<'a, [OnceCell<keys::KeysBody>]>,
    perm: OnceCell<validity::PermParts>,
}

impl<'a> PartsRead<'a> {
    pub(crate) fn of(h: &'a Header, parts: &'a [(usize, Decoded)]) -> Self {
        PartsRead { h, parts, keys: parts.iter().map(|_| OnceCell::new()).collect(), perm: OnceCell::new() }
    }

    /// The first `n` parts, sharing what is read of their `keys.0` parts.
    pub(crate) fn first(&self, n: usize) -> PartsRead<'_> {
        PartsRead { h: self.h, parts: self.parts.get(..n).unwrap_or(self.parts), keys: Cow::Borrowed(self.keys.get(..n).unwrap_or(&self.keys)), perm: OnceCell::new() }
    }

    /// The parts: part index and decoded delta or snapshot.
    pub(crate) fn all(&self) -> &'a [(usize, Decoded)] {
        self.parts
    }

    /// Entry `i` of the parts read, if it is a `keys.0` part.
    pub(crate) fn keys(&self, i: usize) -> Option<&keys::KeysBody> {
        let (ai, d) = self.parts.get(i)?;
        if !self.h.aspects.get(*ai).is_some_and(|a| a.ak.as_str() == "keys.0") {
            return None;
        }
        Some(self.keys.get(i)?.get_or_init(|| keys::KeysBody::of(d.fragment())))
    }

    /// What perm's adaptation reads of the `roles.0` parts.
    pub(crate) fn perm(&self) -> &validity::PermParts {
        self.perm.get_or_init(|| validity::PermParts::of(self.h, self.parts))
    }
}

/// A commit's examined parts. Those of role-class aspects, `created.0` and `addenda.0` are
/// decoded whole: their readers (perm's edges, rotations, creation records, the addenda index)
/// read them whole, and they hold rosters of thousands, or a frontier's worth of commit IDs, not
/// millions of elements; the rest are streamed.
pub(crate) struct Parts {
    /// The commit's signature, checked (`signature`).
    pub signed: osis_commit::Signed,
    pub whole: Vec<(usize, Decoded)>,
    pub streamed: Vec<Streamed>,
    /// Held parts that wait alone (spec/commits.md §4): for pages, parked, or unjudgeable.
    pub waiting: Option<Waiting>,
    /// Why the first part judged bad was (`examine`): dropped alone, or for a commit this node
    /// writes a refusal.
    pub bad: Option<Error>,
    /// Aspects of the parts in `whole` gone while they waited
    /// (`retention::strip_purged`): held so once joined (`retention::stripped_joined`).
    pub stripped: Vec<usize>,
}

impl Parts {
    /// The parts joined from stripped deltas (`stripped`): aspect and part.
    pub(crate) fn stripped_joined(&self) -> Vec<(usize, Decoded)> {
        self.whole.iter().filter(|x| self.stripped.contains(&x.0)).cloned().collect()
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
/// signal is in neither (it travels in a relay-only commit, spec/sync-compaction.md §2). A part on an
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

/// Whether a part of aspect `ak` is decoded whole (`Parts`): a card aspect's part is judged by its body
/// (`validity::note_cards`).
fn whole_part(ak: &str) -> bool {
    osis_schema::core_types::is_role_class(ak) || osis_schema::core_types::is_addenda(ak) || ak == osis_commit::retention::CREATED || osis_schema::core_types::card_of(ak).is_some()
}

/// Commit ID of a blob whose header this build cannot decode: BLAKE3 of the header value.
fn raw_id(bytes: &[u8]) -> Result<CommitId> {
    let lim = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, bytes.len());
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
    // a minting never extends a thing: its commit ends with the record (spec/commits.md §5 Destruction)
    if rec.expires() != h.expires {
        return Err(Error::BadInput("created.0 in a commit not expiring with its record"));
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

/// The key a commit with header `h` is signed by, its signer's record `author` (spec/wire.md §4
/// field 1): the key the header names (its second form), else the record's. Bad input, the
/// commit invalid whole at every reader alike: a second form naming the record's own key, or a
/// first form on a thing whose record holds none.
///
/// Invariant: the one source of a commit's key. Its signature is checked under this key and
/// the walk rests the commit on this key's hop (`validity::signing_key`), so the key a part's
/// right is judged by is exactly the key its signature verified with. Who writes each input: the
/// header is the commit's sender's (a forged second form names a key it holds no signature
/// of, and fails the check); the record is fixed by the signer's tid.
pub(crate) fn commit_key(h: &Header, author: &CreationRecord) -> Result<VerifyingKey> {
    Ok(VerifyingKey::from_slice(&named_key(h.key, author)?.0)?)
}

/// `commit_key` of a header naming `named` (`None`: the first form).
fn named_key(named: Option<osis_base::SignKey>, author: &CreationRecord) -> Result<osis_base::SignKey> {
    Ok(match (named, author.key()) {
        (Some(k), Some(r)) if k == r => return Err(Error::BadInput("a signer's second form naming its record's key")),
        (Some(k), _) => k,
        (None, Some(r)) => r,
        (None, None) => return Err(Error::BadInput("a signer's first form on a thing whose record holds no key")),
    })
}

/// Whether `sigs` are commit `id`'s signatures under `key` (spec/crypto.md §2): their verdict, or
/// `None`. The one door to a commit's signature check, so a node checks each commit's once.
///
/// Invariant: a commit is treated as verified only if these exact signature bytes verified under
/// this exact key. A verdict (`osis_commit::Signed`) is a hash of the key, the signed digest and
/// the signature, made only by a check, by the signer, or kept with the commit: the held commit's
/// (`Meta::signed`, the verdict on the signatures its record holds) and `known` (one this
/// ingest already reached, or the signer's own) answer only when they are the verdict on exactly
/// these bytes and key; a copy with other signature bytes, or a key resolved otherwise since
/// (another record or epoch key for its author), is checked anew.
pub(crate) fn signature(core: &crate::engine::Core, id: &CommitId, sigs: &osis_commit::Sigs, key: &VerifyingKey, known: Option<osis_commit::Signed>) -> Option<osis_commit::Signed> {
    // the held verdict only spares the check, its answer is the check's: read unrecorded, so no
    // memo asking moves with the commit's meta
    let held = osis_base::memo::unrecorded(|| core.ix.commits.get(id).map(|m| m.signed()));
    if let Some(s) = known.into_iter().chain(held).find(|s| s.vouches(id, sigs, key)) {
        return Some(s);
    }
    osis_commit::verify_signature(id, sigs, key).ok()
}

/// Whether `sigs` are the signature of commit `id` (header `h`) by its key (`commit_key`), from
/// what is held: `false` when that cannot be told.
pub fn signed_at(core: &crate::engine::Core, id: &CommitId, h: &Header, sigs: &osis_commit::Sigs) -> bool {
    let Some(r) = core.created(&h.signer) else { return false };
    commit_key(h, r).is_ok_and(|vk| signature(core, id, sigs, &vk, None).is_some())
}

/// Whether `blob`'s signature is by its key (`commit_key`), the signer's record from `record`,
/// `known` a verdict kept for it (`signature`): `None` when that cannot be told yet (no record).
pub(crate) fn signed_by_author(core: &crate::engine::Core, blob: &CommitBlob, id: &CommitId, record: Option<&CreationRecord>, known: Option<osis_commit::Signed>) -> Option<bool> {
    match commit_key(&blob.header, record?) {
        Ok(vk) => Some(signature(core, id, &blob.sigs, &vk, known).is_some()),
        Err(_) => Some(false),
    }
}

/// The verdict a stored pending copy keeps on its signatures (`pend`): this node's own.
pub(crate) fn kept_verdict(p: &osis_store::Pending) -> Option<osis_commit::Signed> {
    p.verdict.map(osis_commit::Signed::from_kept)
}

/// `signature` of `blob`, bad input when it fails.
fn check_signature(tx: &mut Tx<'_>, blob: &CommitBlob, id: &CommitId, vk: &VerifyingKey, known: Option<osis_commit::Signed>) -> Result<osis_commit::Signed> {
    let _s = osis_base::costs::span("examine: signature");
    let Some(s) = signature(tx.core, id, &blob.sigs, vk, known) else {
        // the first copy's signature, kept while the author was away: a true copy may be held
        if tx.core.ix.pending.contains_key(id) {
            tx.core.redeliver.insert(*id);
        }
        return Err(osis_commit::Error::BadSignature.into());
    };
    Ok(s)
}

/// The stored bytes of pending commit `id`, decoded: `None` when they are gone (it pends no
/// more) or still unreadable by this build. A parked row may hold the bytes as received
/// (`park`): decoded as a peer's, checked canonical, before anything applies from them.
fn read_pending(tx: &mut Tx<'_>, id: &CommitId) -> Result<Option<CommitBlob>> {
    let _s = osis_base::costs::span("reexamine: read pending");
    expire_stored(tx, id)?;
    let Some(osis_store::Pending { kind, bytes, .. }) = tx.txn.get_pending(id)? else {
        set_pending(tx.core, id, None);
        return Ok(None);
    };
    let decode = if kind == PendingKind::Parked { CommitBlob::decode } else { CommitBlob::decode_stored };
    Ok(decode(&bytes).ok())
}

/// The things the node closure comes to read whole since the last call wake the parts waiting for them
/// (`Reason::Outside`, spec/commits.md §4 Outside the node closure): each such commit is
/// examined again in this transaction, at its end (`Engine::run`), an ephemeral one woken for
/// node-sync's room (`apply_waiting_memory`); each held commit on such a thing missing a part
/// on it that a blob of it opened is named for redelivery (`Engine::take_redeliver`). How many
/// were examined. The first call reads every thing awaited so and every held commit. O(what
/// entered and the commits on it).
pub(crate) fn wake_entered(tx: &mut Tx<'_>) -> Result<usize> {
    let mut opened: Vec<CommitId> = Vec::new();
    let came: BTreeSet<Tid> = match tx.core.entered.as_mut() {
        Some(f) => f.added().into_iter().map(|(_, t)| t).collect(),
        None => {
            tx.core.entered = Some(tx.core.ix.closure.member_feed());
            // what entered before a restart and was not opened again since
            let core = &*tx.core;
            opened.extend(core.ix.commits.keys().filter(|c| core.ix.commits.get(c).is_some_and(|m| m.view.aspects.iter().any(|a| crate::retention::needed::whole(core, &a.tid) && missing_opened(core, c, &a.tid)))).copied());
            tx.core.ix.pend_on.keys().filter_map(|w| if let Wake::Enters(t) = w { Some(*t) } else { None }).collect()
        }
    };
    let mut ids: BTreeSet<CommitId> = BTreeSet::new();
    // a thing come to be held for keys takes the parts it is judged by, its other content
    // waiting on (`retention::needed::applies_on`)
    for t in std::mem::take(&mut tx.core.keys_came) {
        if tx.core.ix.closure.for_keys(&t) {
            ids.extend(tx.core.ix.pend_on.get(&Wake::Enters(t)).into_iter().flatten().copied());
        }
    }
    for t in came.iter().filter(|t| crate::retention::needed::whole(tx.core, t)) {
        ids.extend(tx.core.ix.pend_on.get(&Wake::Enters(*t)).into_iter().flatten().copied());
        // a held commit missing a part on `t` that a blob of it opened here (taken out as outside
        // the node closure, its pass since ended: `unreceive_outside`): its entries open again
        // (spec/sync-streams.md §4), as no pull brings a blob held
        opened.extend(tx.core.on_thing(t).filter(|c| missing_opened(tx.core, c, t)));
    }
    tx.core.redeliver.extend(opened);
    let mut n = 0;
    for id in ids {
        if !tx.core.ix.pending.contains_key(&id) {
            continue;
        }
        tx.core.waits.examined += 1;
        n += 1;
        if !tx.core.memory_waits.contains(&id) {
            let Some(b) = read_pending(tx, &id)? else { continue };
            if b.header.ephemeral.is_none() {
                retry_pending(tx, id, b)?;
                continue;
            }
            tx.core.memory_waits.insert(id);
        }
        tx.core.waits.memory_woken.wrote_added(&id, true, true);
    }
    Ok(n)
}

/// Whether held commit `c` counts missing a part on `t` that a blob of it opened here.
fn missing_opened(core: &crate::engine::Core, c: &CommitId, t: &Tid) -> bool {
    let Some(m) = core.ix.commits.get(c) else { return false };
    let blobs: Vec<_> = core.ix.commit_blobs.get(c).into_iter().flatten().filter_map(|b| core.ix.blob_parts.get(b)).collect();
    m.view.aspects.iter().enumerate().any(|(ai, a)| a.tid == *t && m.missing(ai) && blobs.iter().any(|x| x.parts.contains(&ai)))
}

/// Whether a member entered the node closure since `wake_entered` last looked (its feed, read
/// without moving it) and is a member still: one a failed step's rollback took out again is not,
/// so a write that fails and stays due brings no other round. O(what was logged since).
pub(crate) fn entering(tx: &Tx<'_>) -> bool {
    let cl = &tx.core.ix.closure;
    tx.core.keys_came.iter().any(|t| cl.for_keys(t)) || tx.core.entered.as_ref().is_some_and(|f| f.clone().added().iter().any(|(c, t)| cl.members(c).is_some_and(|m| m.contains(t))))
}

/// The parts waiting for `t` to enter the node closure count as never received: no sync ID the
/// node syncs carries them (spec/commits.md §4 Pending storage, `retention::needed::uncarried`),
/// or `t` went whole. Each leaves its commit's stored copy; a copy left with no part goes, as does
/// a commit nothing of which applied; one with other parts waiting is examined again.
pub(crate) fn unreceive_outside(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    let ids: Vec<CommitId> = tx.core.ix.pend_on.get(&Wake::Enters(*t)).into_iter().flatten().copied().collect();
    for id in ids {
        let Some(mut b) = read_pending(tx, &id)? else { continue };
        let things: Vec<Tid> = match tx.core.ix.commits.get(&id).map(|m| m.view.aspects.iter().map(|a| a.tid).collect()) {
            Some(things) => things,
            None if resolve_held(tx, &mut b.header) => b.header.aspects.iter().map(|a| a.tid).collect(),
            None => continue,
        };
        let ais: BTreeSet<usize> = b.parts.iter().map(|p| p.ai).filter(|ai| things.get(*ai) == Some(t)).collect();
        let Some(rest) = crate::retention::take_parts(tx, &id, &ais)? else { continue };
        tx.core.touch();
        if rest.parts.is_empty() {
            drop_pending(tx, &id)?;
            continue;
        }
        tx.core.waits.examined += 1;
        if rest.header.ephemeral.is_none() {
            retry_pending(tx, id, rest)?;
        } else {
            tx.core.memory_waits.insert(id);
            tx.core.waits.memory_woken.wrote_added(&id, true, true);
        }
    }
    Ok(())
}

/// Learns `records` in transaction `tx` (`Engine::learn_records`): how many were new.
fn learn_records_in(tx: &mut Tx<'_>, records: Vec<CreationRecord>) -> Result<usize> {
    let mut n = 0;
    for r in records {
        n += usize::from(atomic::learn_record(tx, r)?);
    }
    if n > 0 {
        atomic::rejudged(tx, true)?;
    }
    Ok(n)
}

/// Examines pending commit `id` (stored as `b`) again as one step: a commit refused leaves
/// nothing of its examination or apply, and bad input forgets it. `None` when it was bad.
fn retry_pending(tx: &mut Tx<'_>, id: CommitId, b: CommitBlob) -> Result<Option<Ingested>> {
    let things: Vec<Tid> = if b.header.kind.is_role() { b.header.aspects.iter().map(|a| a.tid).collect() } else { Vec::new() };
    match tx.step(Step::Commit, |tx| ingest_blob(tx, b, Origin::Remote)) {
        Ok(out) => Ok(Some(out)),
        // one bad commit never rolls back the round beside it (`set_aside`)
        Err(e) if e.is_fault() => Ok(Some(set_aside(tx, &id, None, &e)?)),
        Err(e) if e.class() == ErrorClass::BadInput => {
            // a kept first copy proved junk (named in `examine`): a true copy may be held, so the
            // name and what was opened of the commit stay for its carriers to bring it again
            // (`Engine::redelivered` lets them go after)
            if tx.core.redeliver.contains(&id) {
                crate::retention::forget_waiting_leftovers(tx, &id)?;
                unpend(tx, &id)?;
            } else {
                drop_pending(tx, &id)?;
            }
            keys::forget_unchecked(tx, &id)?;
            // secrets read from its boxes go unless something else reads them
            crate::rotation::touch_held(tx, things);
            tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::BadInput, tids: Vec::new(), commit: Some(id), peer: None, detail: e.to_string() }, tx.core.hlc.mono());
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Whether pending commit `b` still waits for what can make it wait without anything else
/// arriving: a blob its kept walks lack (`reach::Walks::lacks`: header lists, pages, value roots), its
/// `ts`. `false` when it may apply (or be refused) now.
fn still_waits(tx: &mut Tx<'_>, b: &CommitBlob) -> bool {
    let id = b.id();
    if tx.core.walks.lacks(&id) {
        return true;
    }
    if !b.header.is_resolved() {
        return false;
    }
    b.header.ts.wall_ms().0 > tx.now().0.saturating_add(MAX_DRIFT_MS)
}

/// Resolves the header lists of `blob` from held blobs: `false` when they wait for a blob, their
/// walk lacking one (notes/sync-facade.md, Blob waits), or a page found missing (noted,
/// `reach::wait_header`).
pub(crate) fn resolve_lists(tx: &mut Tx<'_>, blob: &mut CommitBlob, id: &CommitId, dedup: &osis_crypto::Secret32) -> Result<bool> {
    if tx.core.walks.waits(id, reach::Slot::Header) {
        return Ok(false);
    }
    match blob.header.resolve(&mut TxBlobs::new(&mut tx.blobs, tx.txn.is_memory()), dedup) {
        Ok(()) => Ok(true),
        Err(e) if is_missing_page(&e) => {
            reach::wait_header(tx, id, blob)?;
            Ok(false)
        }
        Err(e) => Err(e.into()),
    }
}

/// Resolves the header lists of `h` from held blobs where its signer's record and every list are
/// here, else leaves it as it was. Whether it is resolved.
pub(crate) fn resolve_held(tx: &mut Tx<'_>, h: &mut Header) -> bool {
    if !h.is_resolved()
        && let Some(dedup) = tx.core.dedup(&h.signer)
    {
        let mut r = h.clone();
        if r.resolve(&mut TxBlobs::new(&mut tx.blobs, tx.txn.is_memory()), &dedup).is_ok() {
            *h = r;
        }
    }
    h.is_resolved()
}

/// Checks a commit and decodes its parts, or says why it waits. `known`: its signature's
/// verdict, as reached before (`signature`) and after, so a commit left pending keeps it.
///
/// Invariant (delivery-shape independence, spec/commits.md §4): what applies is a function of the
/// parts held and everything else held, never of which came first or which came together. One rule
/// gives that: the header's faults refuse the commit (every copy has the header), and each part is
/// judged by itself, from the signed header, its own bytes and held data:
/// - it does not hash to its header entry: not that part (junk from anyone). Dropped, nothing kept
///   of it: a true copy is still taken. While its header lists are not resolved the hash cannot be
///   read and the pending blob keeps the first copy of each slot, junk or not, and an unverified
///   signature likewise; the commit is named when one proves junk (`Core::redeliver`), and sync ingests the commit's other
///   entries again. So this holds at the node, not at one `Engine::ingest`.
/// - it hashes but is bad by itself (`judge_part`): the author signed garbage, and those bytes are
///   the only ones that can ever hash there, so no later copy can differ and no mark is needed. It
///   never applies and is dropped alone.
/// - it waits (its pages, parked): alone. The commit's other parts apply, and its header with
///   none: it joins when its wait ends.
/// - it cannot be judged yet (its thing's record or chain, the author's reach): it waits alone
///   as well, parked under what it awaits; with every held part so the commit pends whole.
///
/// Every wait only ends as the held set grows, so the applied parts are the least fixpoint of a
/// monotone rule, one result for every order (`tests/it` `order::held_set_decides` plays them).
pub(crate) fn examine(tx: &mut Tx<'_>, blob: &mut CommitBlob, id: &CommitId, skip: &BTreeSet<usize>, origin: Origin, known: &mut Option<osis_commit::Signed>) -> Result<Exam> {
    // its blob waits taken on from what arrived for them (this transaction's holds among them)
    reach::take_on(tx, id)?;
    if !blob.header.is_resolved() {
        // a held author's signature first: a false one costs no list. An author's record carried
        // by this commit waits for the lists: only the aspects say which part holds it
        if let Some(rec) = tx.core.created(&blob.header.signer).cloned()
            && let Ok(vk) = commit_key(&blob.header, &rec)
        {
            *known = Some(check_signature(tx, blob, id, &vk, *known)?);
        }
        let Some(dedup) = tx.core.dedup(&blob.header.signer) else { return Ok(Exam::Awaits(Reason::UnknownCreated(blob.header.signer))) };
        if !resolve_lists(tx, blob, id, &dedup)? {
            return Ok(Exam::Pending(Reason::WaitBlobs));
        }
    }
    // a split commit's parts whose thing's path key no opened encryption carried, or whose entry
    // opens to a bad path, hold nothing (spec/wire.md §4 `Split`): every held part's path is known
    blob.settle_paths();
    let h = blob.header.clone();
    let carried = carried_records(&h, blob, id);
    // the record of its purge author, a member of every thing's path
    let acting = h.purge_author();
    let held: BTreeMap<Tid, CreationRecord> = h.aspects.iter().map(|a| a.tid).chain([h.signer, acting]).filter_map(|t| tx.core.created(&t).map(|r| (t, r.clone()))).collect();
    let chain_rec = |t: &Tid, core: &crate::engine::Core| -> Option<CreationRecord> { core.created(t).cloned().or_else(|| carried.get(t).cloned()) };
    let record = |t: &Tid| -> Option<CreationRecord> { held.get(t).cloned().or_else(|| carried.get(t).cloned()) };
    let author = match header_wait(&h, &record) {
        Ok(a) => a,
        Err(r) => return Ok(Exam::Awaits(r)),
    };
    // a part it cannot judge (its thing's record, record chain or the author's reach) waits; with
    // every held part such the commit is unjudgeable (spec/commits.md §4), found before a missing
    // epoch or a `ts` ahead names another wait
    let mut unjudged: BTreeMap<usize, Reason> = BTreeMap::new();
    let hostile = origin == Origin::Local && tx.core.skip_writer_rules;
    // Invariant: a received part whose commit lists for its thing a key no held step places is
    // held only as any unjudgeable part, under Pending storage and its bounds on unvouched input
    // (spec/commits.md §4), never applied as a body, so made-up keys grow no store past those
    // bounds. A node's own commit listing one applies its part invalid and is refused
    // (`apply_local`)
    let wrong = if origin == Origin::Local { BTreeSet::new() } else { tx.core.wrong_keys(&h) };
    for (ai, a) in h.aspects.iter().enumerate() {
        if skip.contains(&ai) || blob.part(ai).is_none() {
            continue;
        }
        // a hostile writer (tests) applies its own commits whatever path they state
        let path = match blob.path(&a.tid) {
            Some(osis_commit::ThingPath::Known(p)) if !hostile => Some(p),
            _ => None,
        };
        if let Some(wait) = thing_wait(tx.core, &h, id, a, path.as_ref().map(|p| (p.to(&a.tid), p.direct)), &record, &chain_rec) {
            unjudged.insert(ai, wait);
        } else if origin == Origin::Remote && record(&a.tid).is_some() && !crate::retention::needed::applies_on(tx.core, &a.tid, &a.ak) {
            // nothing but certificates applies on a thing outside the node closure: content waits
            // until it enters (a node's own commits write only what it holds, `check_written`)
            unjudged.insert(ai, Reason::Outside(a.tid));
        } else if a.ak.as_str() != osis_commit::retention::CREATED && wrong.contains(&a.tid) {
            // a minting's `created.0` needs no authority (spec/permissions.md §1)
            unjudged.insert(ai, Reason::Miskeyed(a.tid));
        }
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
            stripped.insert(p.ai, leftover_part(l));
        }
    }
    let stripped_ais: BTreeSet<usize> = stripped.keys().copied().collect();
    let kept = |p: &osis_commit::Part| p.delta == emptied && stripped_ais.contains(&p.ai);
    // a part that does not hash to its header entry is no part of this commit, and one on an aspect
    // of the wrong storage class is never applied: dropped
    // alone, before anything reads what is held (spec/commits.md §4)
    let fits = |a: &osis_commit::AspectEntry| fits_part(a, h.ephemeral.is_some(), h.kind.is_compaction());
    let junk: Vec<usize> = blob
        .parts
        .iter()
        .filter(|p| !kept(p))
        .filter(|p| {
            let Some(a) = h.aspects.get(p.ai) else { return true };
            !fits(a) || record(&a.tid).is_some_and(|r| osis_crypto::delta_hash(&dedup_secret(r.nonce()), &p.delta) != a.hash)
        })
        .map(|p| p.ai)
        .collect();
    // a copy holding only what does not hash is no copy of it: refused, as if it never came
    let only_junk = !blob.parts.is_empty() && junk.len() == blob.parts.len() && blob.parts.iter().any(|p| h.aspects.get(p.ai).is_none_or(fits));
    if !junk.is_empty() {
        // a slot's stored first copy, kept while it could not be checked: a true copy may be held. Not a
        // copy just come (it kept nothing out), nor a part of the wrong class (it has no true copy)
        let kept_out = |p: &osis_commit::Part| junk.contains(&p.ai) && h.aspects.get(p.ai).is_none_or(fits);
        if tx.core.ix.pending.contains_key(id) && tx.txn.get_pending(id)?.and_then(|p| CommitBlob::decode_stored(&p.bytes).ok()).is_some_and(|b| b.parts.iter().any(kept_out)) {
            tx.core.redeliver.insert(*id);
        }
        blob.parts.retain(|p| !junk.contains(&p.ai));
        unjudged.retain(|ai, _| !junk.contains(ai));
        tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::BadInput, tids: Vec::new(), commit: Some(*id), peer: Some(h.signer), detail: "delta hash".into() }, tx.core.hlc.mono());
    }
    if only_junk {
        return Err(Error::BadInput("delta hash"));
    }
    // the walks of parts no longer in it (junk, expired, stripped) go
    tx.core.walks.keep_parts(id, &blob.parts.iter().map(|p| p.ai).filter(|ai| !skip.contains(ai)).collect());
    let unjudgeable = unjudged.values().next().cloned().filter(|_| blob.parts.iter().all(|p| skip.contains(&p.ai) || unjudged.contains_key(&p.ai)));
    let vk = commit_key(&blob.header, &author)?;
    let signed = check_signature(tx, blob, id, &vk, *known)?;
    *known = Some(signed);
    h.validate()?;
    if let Some(r) = unjudgeable {
        return Ok(pend_unjudgeable(tx, id, &unjudged, r));
    }
    // the bound is for received commits, a sibling node's too (spec/crdt.md §2.2): this node's
    // own are as far ahead as its HLC, which a wall clock set back must not turn against them
    if origin != Origin::Local && h.ts.wall_ms().0 > tx.now().0.saturating_add(MAX_DRIFT_MS) {
        note_unjudged(tx, id, &unjudged);
        return Ok(Exam::Pending(Reason::Drift));
    }
    let mut aside = Aside::default();
    for (t, rec) in &carried {
        if let Some(held) = tx.core.created(t)
            && held != rec
        {
            tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::CollidingRecord, tids: vec![*t], commit: Some(*id), peer: Some(h.signer), detail: String::new() }, tx.core.hlc.mono());
        }
    }
    let mut out = Parts { signed, whole: Vec::new(), streamed: Vec::new(), waiting: None, bad: None, stripped: Vec::new() };
    let mut interner = Interner::new();
    // tests let a local writer break the writer rules, to test receivers
    let rules = !(tx.core.skip_writer_rules && h.signer == tx.core.tid());
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
        // its pages' walk lacks a blob: it waits, not decoded again (notes/sync-facade.md, Blob
        // waits). Invariant: a part is decoded while waiting for pages only when its walk lacks
        // nothing, so filling it costs O(its pages) whatever the batching a server picks
        if tx.core.walks.waits(id, reach::Slot::Part(p.ai)) {
            aside.add(Reason::WaitBlobs, [p.ai]);
            continue;
        }
        let dedup = record(&a.tid).map(|r| dedup_secret(r.nonce())).ok_or(Error::UnknownThing(a.tid))?;
        // one step: a part set aside or bad leaves nothing of its judging
        let judged = tx.step(Step::Part, |tx| judge_part(tx, &h, id, p, a, &dedup, rules, &mut interner));
        match &judged {
            Ok(Judged::Blobs) => reach::judged_waiting(tx, id, p.ai, &p.delta, h.ephemeral.is_some())?,
            _ => tx.core.walks.drop_slot(*id, reach::Slot::Part(p.ai)),
        }
        let wait = match judged {
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
    // an edge part whose every write rests on an edge not arrived cannot be judged either
    let edges = if hostile { Vec::new() } else { edge_unreached(tx.core, &h, id, &out.whole, &chain_rec) };
    for ai in edges {
        out.whole.retain(|x| x.0 != ai);
        unjudged.insert(ai, Reason::MissingChain(h.signer));
    }
    if !bad.is_empty() {
        // only bad parts beside parts of it awaiting a record (`note_unjudged`): unjudgeable,
        // as it would be judged with them
        if out.ais().is_empty() && aside.keys.is_empty() && unjudged.is_empty()
            && let Some(t) = tx.core.waits.records_of(id).iter().find(|t| tx.core.created(t).is_none())
        {
            return Ok(Exam::Awaits(Reason::UnknownCreated(*t)));
        }
        // only bad parts: refused, nothing stored
        if rules && out.ais().is_empty() && aside.keys.is_empty() && unjudged.is_empty() {
            return Err(out.bad.take().unwrap_or(Error::BadInput("a bad part")));
        }
        blob.parts.retain(|p| !bad.contains(&p.ai));
        let detail = out.bad.as_ref().map(|e| e.to_string()).unwrap_or_default();
        tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::BadInput, tids: Vec::new(), commit: Some(*id), peer: Some(h.signer), detail }, tx.core.hlc.mono());
    }
    // nothing else held and a part cannot be judged: unjudgeable
    if out.ais().is_empty() && aside.keys.is_empty() && let Some(r) = unjudged.values().next().cloned() {
        return Ok(pend_unjudgeable(tx, id, &unjudged, r));
    }
    // nothing waits for a part, the header included (spec/commits.md §4): with every held part
    // waiting the commit applies as its header, the parts waiting under its ID. A part it cannot
    // judge waits so too, for what it awaits (spec/commits.md §4 Unjudgeable, Pending storage)
    for (ai, r) in unjudged {
        aside.add(r, [ai]);
    }
    if let Some(reason) = aside.reason {
        let (parts, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut blob.parts).into_iter().partition(|p| aside.keys.contains(&p.ai));
        blob.parts = rest;
        // a thing whose every held part waits keeps its entry's key with the waiting copy alone:
        // the applied record decides paths by what joins, whichever copy came first
        let on = |p: &osis_commit::Part| h.aspects.get(p.ai).map(|a| a.tid);
        let aside_only = |t: &Tid| parts.iter().any(|p| on(p) == Some(*t)) && !blob.parts.iter().any(|p| on(p) == Some(*t));
        let things = h.things();
        let keys: BTreeMap<usize, [u8; 32]> = blob.keys.iter().filter(|(i, _)| things.get(**i).is_some_and(aside_only)).map(|(i, k)| (*i, *k)).collect();
        blob.keys.retain(|i, _| !keys.contains_key(i));
        out.waiting = Some(Waiting { parts, keys, reason, others: aside.others });
    }
    // what joins of an emptied slot is the part's leftover: no stored copy holds it
    blob.parts.retain(|p| p.delta != emptied || !h.aspects.get(p.ai).is_some_and(|_| out.stripped.contains(&p.ai)));
    Ok(Exam::Ready(out))
}

/// The parts of commit `id`, pending for another reason, it cannot judge (`unjudged`) stay in the
/// stored copy with the rest of it (spec/commits.md §4 Unjudgeable, Pending storage), the records
/// they await noted (`waits`).
fn note_unjudged(tx: &mut Tx<'_>, id: &CommitId, unjudged: &BTreeMap<usize, Reason>) {
    if !unjudged.is_empty() {
        tx.core.waits.parts_await(*id, unjudged.values());
    }
}

/// A part's leftover as the part joins: a snapshot's with its frontiers, `Absorbed` and facts.
pub(crate) fn leftover_part(l: crate::retention::leftover::Leftover) -> Decoded {
    match l.gives {
        None => Decoded::Delta(osis_crdt::Delta { nonce: [0; osis_crdt::NONCE_LEN], fragment: l.fragment }),
        Some((frontiers, absorbed, facts)) => Decoded::Snapshot(osis_crdt::Snapshot { nonce: [0; osis_crdt::NONCE_LEN], fragment: l.fragment, frontiers, absorbed: absorbed.into_iter().collect(), facts }),
    }
}

/// Commit `id` unjudgeable, its held parts for `unjudged` (its reason names `first`): examined
/// again when any one of the records comes, as a part on another thing may apply
/// (spec/commits.md §4).
fn pend_unjudgeable(tx: &mut Tx<'_>, id: &CommitId, unjudged: &BTreeMap<usize, Reason>, first: Reason) -> Exam {
    tx.core.waits.parts_await(*id, unjudged.values());
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
    let mut blobs = TxBlobs::new(&mut tx.blobs, tx.txn.is_memory());
    let mut paged = BlobReader::judging(dedup, h, a.tid, &mut blobs);
    let reader: &mut dyn osis_crdt::PageSource = &mut paged;
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
            .map(|gives| Judged::Streamed(Streamed { ai: p.ai, dedup: dedup.clone(), gives: gives.map(|x| (x.frontiers, x.absorbed.into_iter().collect(), x.facts)) }))
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
        keys::check_left_out(h, part)?;
    }
    Ok(judged)
}

/// The signer's record of commit `h`, else what it waits for whole: that record, or the record
/// of its purge author, a member of every thing's path.
// Interim (issues/stated-path-certificates.md): the spec waits for every listed thing's record
// and those up its chain; this waits for the purge author's alone (`thing_wait`'s hops read a
// listed thing's record only where a hop needs it)
fn header_wait(h: &Header, record: &dyn Fn(&Tid) -> Option<CreationRecord>) -> std::result::Result<CreationRecord, Reason> {
    let author = record(&h.signer).ok_or(Reason::MissingChain(h.signer))?;
    let acting = h.purge_author();
    record(&acting).map(|_| author).ok_or(Reason::UnknownCreated(acting))
}

/// What thing `a.tid` waits for: its `created.0` record, the record chain up to its top, an
/// edge write on each edge of the path stated for it (spec/commits.md §4 Unjudgeable). A function of the thing, not of the part.
fn thing_wait(
    core: &crate::engine::Core,
    h: &Header,
    id: &CommitId,
    a: &osis_commit::AspectEntry,
    path: Option<(&[Tid], osis_base::format::PathMarks)>,
    record: &dyn Fn(&Tid) -> Option<CreationRecord>,
    chain_rec: &dyn Fn(&Tid, &crate::engine::Core) -> Option<CreationRecord>,
) -> Option<Reason> {
    // a destroyed thing is unknown, but for what judges its destruction written before it and its
    // edge writes whatever their stamp (`retention::destroy`); a minting never restores it, so one
    // waits while it is destroyed
    let destroyed = || {
        !crate::retention::destroy::judges_destruction(a.ak.as_str())
            || a.ak.as_str() == osis_commit::retention::CREATED
            || !validity::edge_ak(a.ak.as_str()) && crate::retention::destroy::Destruction::of(core, &a.tid).is_some_and(|e| e.after(h))
    };
    if record(&a.tid).is_none() || core.destroyed(&a.tid) && destroyed() {
        return Some(Reason::UnknownCreated(a.tid));
    }
    // a chain deeper than `MAX_CHAIN_DEPTH` is not waited for further: its deltas are invalid
    // (`validity::too_deep`, spec/permissions.md §1)
    for step in osis_base::record_chain(a.tid, |t| chain_rec(t, core).map(|r| r.record_link())) {
        match step {
            ChainStep::Unknown(t) => return Some(Reason::MissingChain(t)),
            ChainStep::TooDeep => return None,
            ChainStep::Up { .. } | ChainStep::Key(_) => {}
        }
    }
    // every edge of the path stated for the thing is a record edge or has a held edge write
    // ordered before the part; an external fire needs no path (spec/permissions.md §5.2 External
    // fires), and a path not opened here holds no part. An edge part is read here as a
    // self-removal after every edge write of its commit, the least any edge write needs (its path
    // to the holder it ends at): `examine` reads its writes once decoded (`edge_unreached`)
    let (along, direct) = path.filter(|_| !a.ak.external())?;
    let edge = validity::edge_ak(a.ak.as_str());
    let at = if edge { validity::Place::Write(osis_perm::Point { ts: h.ts, node: h.signer, commit: *id }, None) } else { validity::Place::Start(h.ts) };
    validity::unreached(core, h.signer, h.key, along, direct, &a.tid, edge, edge, at, &|t| chain_rec(t, core)).then_some(Reason::MissingChain(h.signer))
}

/// The decoded `roles.0` parts among `whole` whose every edge write is unjudgeable
/// (spec/commits.md §4, `validity::writes_unreached`). `skip`: parts held before, read by what the
/// index holds of them (`Indexes::unresolved`).
fn edge_unreached(core: &crate::engine::Core, h: &Header, id: &CommitId, whole: &[(usize, Decoded)], chain_rec: &dyn Fn(&Tid, &crate::engine::Core) -> Option<CreationRecord>) -> Vec<usize> {
    if !matches!(h.path, osis_commit::Paths::One(_)) {
        return Vec::new();
    }
    // nothing written on a thing too deep applies (spec/permissions.md §1): judged as it is
    let deep = |t: &Tid| matches!(osis_base::record_chain(*t, |x| chain_rec(x, core).map(|r| r.record_link())).end(), ChainStep::TooDeep);
    let whole: Vec<(usize, Decoded)> = whole.iter().filter(|(ai, _)| h.aspects.get(*ai).is_some_and(|a| validity::edge_ak(a.ak.as_str()) && !deep(&a.tid))).cloned().collect();
    let perm = validity::PermParts::of(h, &whole);
    let known = !core.ix.unresolved.contains(id) && perm.edges.iter().all(|(ai, es)| validity::resolved(core, h, id, *ai, es));
    let record = |t: &Tid| chain_rec(t, core);
    perm.edges.iter().filter(|(ai, es)| validity::writes_unreached(core, h, id, *ai, es, known, &record)).map(|x| x.0).collect()
}

/// Whether part `ai` of an applied commit (`h`, its view `view`), held or not, cannot be judged
/// here (spec/commits.md §4 Unjudgeable): what `examine` waits for, read from the held records
/// (`header_wait`, `thing_wait`), its thing's path opens nowhere here (a split commit's,
/// spec/wire.md §4 `Split`), or its commit lists for its thing a key no held step places
/// (`Core::miskeyed`: a wrong key and a step whose `sync.0` write is not held read alike; never
/// its `created.0`, which needs no authority). Its
/// validity flag reads false meanwhile, but it is not judged invalid
/// (`retention::drops_invalid`).
pub(crate) fn unjudgeable(core: &crate::engine::Core, id: &CommitId, h: &Header, view: &crate::engine::View, ai: usize) -> bool {
    let Some(a) = h.aspects.get(ai) else { return false };
    let held = |t: &Tid| core.created(t).cloned();
    let path = validity::stated(h, view, &a.tid);
    header_wait(h, &held).is_err()
        || view.paths.as_deref().is_some_and(|p| !p.contains_key(&a.tid))
        || thing_wait(core, h, id, a, path.as_ref().map(|p| (p.0.as_slice(), p.1)), &held, &|t, core| core.created(t).cloned()).is_some()
        || (a.ak.as_str() != osis_commit::retention::CREATED && core.miskeyed(id, &a.tid))
}

/// Applies or stores one decoded commit blob.
/// A memory commit (session-form content or commit-form snapshot, spec/commits.md §2-§3) is applied as memory work: every row it
/// derives stays in the store's memory overlay, pending ones included.
fn ingest_blob(tx: &mut Tx<'_>, blob: CommitBlob, origin: Origin) -> Result<Ingested> {
    let planted = tx.core.apply_fault.is_some_and(|c| c == blob.id());
    let out = ingest_blob_class(tx, blob, origin);
    if planted {
        return out.and(Err(Error::Corrupt("a planted fault (tests)")));
    }
    out
}

fn ingest_blob_class(tx: &mut Tx<'_>, blob: CommitBlob, origin: Origin) -> Result<Ingested> {
    match (blob.header.ephemeral, blob.header.form) {
        (None, _) => ingest_class(tx, blob, origin),
        (Some(osis_commit::EphClass::Plain), osis_commit::Form::Session(_) | osis_commit::Form::Commit) => tx.in_class(true, |tx| ingest_class(tx, blob, origin)),
        // relay-only commits are delivered, never held
        _ => Err(Error::BadInput("a relay-only commit on the commit path")),
    }
}

/// Takes commit `blob` (ID `id`) as a carrier brings it, not as a re-examination: a copy that
/// brings nothing (`rearrival`) costs a lookup, else `ingest_blob` judges it. `blobs`: blobs new
/// here came with it (pages, header lists), which may be what it waits for.
fn arrive(tx: &mut Tx<'_>, id: &CommitId, blob: CommitBlob, blobs: bool) -> Result<Ingested> {
    if !blobs && let Some(out) = rearrival(tx, id, &blob)? {
        return Ok(out);
    }
    ingest_blob(tx, blob, Origin::Remote)
}

/// Tells the app that received commit `id` (on `things`) failed to apply for fault `e` of this
/// node (`set_aside`).
fn tell_fault(core: &mut crate::engine::Core, id: Option<CommitId>, things: Vec<Tid>, e: &Error) {
    core.events.diagnostic(Diagnostic { kind: DiagnosticKind::Fault, tids: things, commit: id, peer: None, detail: e.to_string() }, core.hlc.mono());
}

/// Received commit `id` failed to apply for a fault of this node (`e`), never a judgment of it
/// (spec/commits.md §4 No local error from peer bytes): it pends set aside (`Reason::Fault`),
/// counted as not received like any pending commit, so nothing this node holds, writes or
/// claims reads it, and examined again only at the next open (an upgrade may apply it); the
/// app is told. Its stored copy stays if it had one, else `bytes` (as it came) are kept.
///
/// Where: a round's examinations each run as a step (`retry_pending`), so a fault leaves the
/// round's others applying; an arrival's transaction failing with a fault is followed by one that
/// only sets the commit aside (`Engine::set_aside_arrival`: its transaction-end work included, and
/// a streamed apply keeps spilling, which a step around it would stop).
fn set_aside(tx: &mut Tx<'_>, id: &CommitId, bytes: Option<&[u8]>, e: &Error) -> Result<Ingested> {
    let mut things = Vec::new();
    if !tx.core.ix.pending.contains_key(id) {
        let Some(b) = bytes.map(CommitBlob::decode).transpose()? else { return Err(Error::Misuse("set aside: no copy")) };
        things = b.header.aspects.iter().map(|a| a.tid).collect();
        pend(tx, id, PendingKind::Pending, None, &b.encode(), Reason::Fault, Some(&b.header))?;
    }
    // what its parts awaited wakes it no more: an open does
    tx.core.waits.unawaits(id);
    set_pending(tx.core, id, Some((Reason::Fault, None)));
    tell_fault(tx.core, Some(*id), things, e);
    Ok(Ingested::Pending(*id, Reason::Fault))
}

/// What a copy of commit `id` held or pending here returns when it brings nothing: each part it
/// carries is held as its body (an applied commit's) or is the stored pending copy's part byte
/// for byte, under the stored copy's signatures, that copy not past its expiry (`expire_stored`)
/// and no clock wake of it due (`Wake::At`: its `ts` came within reach before a tick ran).
/// Ingesting it would end where it began (the stored copy, its receipt, its wait); a carrier it
/// came by is still noted (`carriers::taken`, after). `None`: it may bring something, so
/// `ingest_blob` judges it. Bytes decide, not a part's hash in the header: a pending commit may
/// await the record whose dedup secret that hash is under, and a part differing from the stored
/// one (forged, or the true one where junk came first) is judged (`with_pending`). A parked
/// copy has its own path (`park`), and a memory commit is `memory_gate`'s: an arrival brings a room.
fn rearrival(tx: &mut Tx<'_>, id: &CommitId, blob: &CommitBlob) -> Result<Option<Ingested>> {
    if blob.header.ephemeral.is_some() {
        return Ok(None);
    }
    let held: BTreeSet<usize> = tx.core.ix.commits.get(id).map(|m| blob.parts.iter().map(|p| p.ai).filter(|ai| matches!(m.hold(*ai), Some(crate::engine::Hold::Body { .. }))).collect()).unwrap_or_default();
    let Some(reason) = tx.core.ix.pending.get(id).cloned() else {
        let applied = tx.core.ix.commits.contains_key(id) && held.len() == blob.parts.len();
        return Ok(applied.then_some(Ingested::Duplicate(*id)));
    };
    // a clock wake due and not yet run (its `ts` within reach, before a tick): examined now
    let now = tx.now().0;
    if tx.core.ix.pend_keys.get(id).is_some_and(|ws| ws.iter().any(|w| matches!(w, Wake::At(t) if *t <= now))) {
        return Ok(None);
    }
    let Some(stored) = tx.txn.get_pending(id)? else { return Ok(None) };
    if stored.kind != osis_store::PendingKind::Pending {
        return Ok(None);
    }
    let Ok(old) = CommitBlob::decode_stored(&stored.bytes) else { return Ok(None) };
    if old.sigs != blob.sigs || old.header.expires.is_some_and(|t| t <= now) {
        return Ok(None);
    }
    let same = blob.parts.iter().all(|p| held.contains(&p.ai) || old.part(p.ai).is_some_and(|x| x.delta == p.delta));
    Ok(same.then_some(Ingested::Pending(*id, reason)))
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
    if tx.core.memory_tx
        && origin == Origin::Remote
        && tx.core.ix.commits.contains_key(&id)
        && let Some(out) = memory::memory_gate(tx, &mut blob, &id, &mut None)?
    {
        return Ok(out);
    }
    if tx.core.ix.commits.contains_key(&id) {
        return late_parts(tx, &id, blob);
    }
    let (merged, mut known) = with_pending(tx, &id, blob)?;
    blob = merged;
    if tx.core.memory_tx
        && origin == Origin::Remote
        && let Some(out) = memory::memory_gate(tx, &mut blob, &id, &mut known)?
    {
        return Ok(out);
    }
    let received = first_received(tx, &id)?;
    let _s = osis_base::costs::span("examine");
    let exam = examine(tx, &mut blob, &id, &BTreeSet::new(), origin, &mut known)?;
    let out = match exam {
        Exam::Ready(mut parts) => {
            let w = parts.waiting.take();
            tx.core.waits.unawaits(&id);
            unpend(tx, &id)?;
            apply_verified(tx, &blob, parts, origin, received)?;
            // what a part still waiting read of its boxes may be what opens what it waits for
            match w {
                Some(w) => pend_aside(tx, &id, &blob, w)?,
                None if settled_boxes(tx, &id) => keys::forget_unchecked(tx, &id)?,
                None => {}
            }
            Ingested::Applied(id)
        }
        Exam::Pending(r) | Exam::Awaits(r) => {
            // parts past their expiry (or purged ones that cannot be stripped) count as never
            // received: examined again without them. One that awaits stays pending as any commit
            // that waits, its signature's verdict with it, while a carrier holds it
            // (spec/commits.md §4 Unjudgeable, Pending storage): every arrival that applies
            // examines it again (`reexamine`)
            let (h, n) = (blob.header.clone(), blob.parts.len());
            crate::retention::pending_drops(tx, &id, &mut blob, &h)?;
            if blob.parts.len() != n {
                return ingest_class(tx, blob, origin);
            }
            pend(tx, &id, PendingKind::Pending, known, &blob.encode(), r.clone(), Some(&blob.header))?;
            keys::read_pending_boxes(tx, &blob, &id)?;
            Ingested::Pending(id, r)
        }
    };
    Ok(out)
}

/// What the waiting parts `w` of applied commit `id` await on their things, noted
/// (`Waits::parts_await`): its pending copy parks under each (`waits::wakes_of`), whatever its
/// first reason.
fn note_awaited(tx: &mut Tx<'_>, id: &CommitId, w: &Waiting) {
    tx.core.waits.unawaits(id);
    tx.core.waits.parts_await(*id, std::iter::once(&w.reason).chain(&w.others));
}

/// Whether `id` gave reading-only secrets that may go now: no `secrets.0` part of it is missing
/// (a part waiting: its boxes may open what it awaits).
fn settled_boxes(tx: &Tx<'_>, id: &CommitId) -> bool {
    tx.core.waits.read_any(id) && !tx.core.ix.commits.get(id).is_some_and(|m| m.missing_parts().any(|ai| m.header.aspects.get(ai).is_some_and(|a| a.ak.as_str() == "secrets.0")))
}

/// Keeps commit `id` pending (`bytes` as stored) for `reason`, with its signature's verdict if
/// one was reached (`signature`): no re-examination checks those bytes again.
/// `h`: its header, where it decoded (`waits::wakes_of`).
#[allow(clippy::too_many_arguments)]
fn pend(tx: &mut Tx<'_>, id: &CommitId, kind: PendingKind, signed: Option<osis_commit::Signed>, bytes: &[u8], reason: Reason, h: Option<&Header>) -> Result<()> {
    tx.core.touch();
    let received = first_received(tx, id)?;
    tx.txn.put_pending(id, kind, signed.map(osis_commit::Signed::to_bytes), received.0, bytes)?;
    // unchanged at a look that keeps it waiting: what read it holds (`Core::waiting_carried`)
    set_pending(tx.core, id, Some((reason, h)));
    Ok(())
}

/// When commit `id` was received (spec/permissions.md §5.1 Received: its header decrypted and
/// its signature verified, whether or not its deltas are held, applied or stored): at its first
/// arrival, kept with its applied copy (`Meta::received`) or its pending one, else now.
fn first_received(tx: &mut Tx<'_>, id: &CommitId) -> Result<WallMs> {
    if let Some(m) = tx.core.ix.commits.get(id) {
        return Ok(m.received);
    }
    if tx.core.ix.pending.contains_key(id)
        && let Some(p) = tx.txn.get_pending(id)?
    {
        return Ok(WallMs(p.received));
    }
    Ok(tx.now())
}

/// Keeps commit `id` parked (`bytes` as stored, spec/versioning.md §2), telling the app the first
/// time it parks (`tell_parked`).
fn park(tx: &mut Tx<'_>, id: &CommitId, bytes: &[u8], things: Vec<Tid>, peer: Option<Tid>, h: Option<&Header>) -> Result<()> {
    tell_parked(tx, id, things, peer);
    pend(tx, id, PendingKind::Parked, None, bytes, Reason::Parked, h)
}

/// Tells the app commit `id` waits for a newer format, unless it already waited for one: an update
/// may read it. Called before `id` pends for `Reason::Parked`, whether alone or with other reasons.
/// `things`: what its header names, `peer`: its author, or who sent it when the header does not
/// decode.
fn tell_parked(tx: &mut Tx<'_>, id: &CommitId, things: Vec<Tid>, peer: Option<Tid>) {
    if tx.core.ix.pending.get(id) == Some(&Reason::Parked) {
        return;
    }
    tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::Parked, tids: things, commit: Some(*id), peer, detail: "from a newer format".into() }, tx.core.hlc.mono());
}

/// Keeps the parts of applied commit `id` that wait alone pending under its ID, parked under
/// what each awaits (`note_awaited`), their boxes read as any pending copy's. `applied`: its blob.
fn pend_aside(tx: &mut Tx<'_>, id: &CommitId, applied: &CommitBlob, w: Waiting) -> Result<()> {
    note_awaited(tx, id, &w);
    let mut rest = applied.clone();
    rest.parts = w.parts;
    rest.keys.extend(w.keys);
    // a part past its expiry counts as never received, a purged one is gone (`retention::pending_drops`)
    let h = rest.header.clone();
    crate::retention::pending_drops(tx, id, &mut rest, &h)?;
    if rest.parts.is_empty() {
        return Ok(());
    }
    if w.reason == Reason::Parked {
        return park(tx, id, &rest.encode(), rest.header.aspects.iter().map(|a| a.tid).collect(), Some(rest.header.signer), Some(&rest.header));
    }
    // the applied commit's held verdict answers for these signatures (`signature`)
    pend(tx, id, PendingKind::Pending, None, &rest.encode(), w.reason.clone(), Some(&rest.header))?;
    keys::read_pending_boxes(tx, &rest, id)
}

/// Commit `id` pends no more: its stored bytes go. Whether it was pending.
fn unpend(tx: &mut Tx<'_>, id: &CommitId) -> Result<bool> {
    let was = tx.core.ix.pending.contains_key(id);
    // a blob of it opened with a part not checked against the header (its record not held then)
    // opens again, now checked (`sync::BlobOf::unchecked`)
    if was && tx.core.ix.commit_blobs.get(id).into_iter().flatten().any(|b| tx.core.ix.blob_parts.get(b).is_some_and(|x| x.unchecked)) {
        tx.core.redeliver.insert(*id);
    }
    if was {
        set_pending(tx.core, id, None);
        tx.core.touch();
        tx.txn.remove_pending(id, Shred::Yes)?;
    }
    Ok(was)
}

/// The stored pending copy of `id` goes, with the leftovers its parts kept while they waited
/// (read from it: first). Whether it was pending.
fn drop_pending(tx: &mut Tx<'_>, id: &CommitId) -> Result<bool> {
    crate::retention::forget_waiting_leftovers(tx, id)?;
    // nothing of it held: no copy of it is needed again, nor its signers' chains for it
    if !tx.core.ix.commits.contains_key(id) {
        pending_left(tx.core, id);
    }
    let was = unpend(tx, id)?;
    if !tx.core.ix.commits.contains_key(id) {
        tx.core.redeliver.remove(id);
        crate::sync_ids::opened::forget(tx, id)?;
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
    let Some(osis_store::Pending { bytes, .. }) = tx.txn.get_pending(id)? else { return Ok(()) };
    let Ok(old) = CommitBlob::decode_stored(&bytes) else { return Ok(()) };
    if old.header.expires.is_none_or(|t| t > tx.now().0) {
        return Ok(());
    }
    let mut h = match tx.core.ix.commits.get(id) {
        Some(m) => (*m.header).clone(),
        None => old.header.clone(),
    };
    // a header whose lists are away is judged once they come (`retention::pending_drops`)
    resolve_held(tx, &mut h);
    // a memory commit's copy is memory work, as its ingest is (`ingest_blob`)
    let memory = h.ephemeral.is_some();
    tx.in_class(memory, |tx| crate::retention::expire_waiting(tx, id, &old, &h))
}

/// `blob` with the parts the stored pending copy of `id` holds: a slot keeps its first copy, and the
/// commit its first signature, until they can be checked (`examine`). A differing copy goes, its bytes
/// still in its sync ID entry; only its boxes are read now (spec/crypto.md §4): the keys in them may open
/// what the commit waits for, and nothing checks whose they are until then. With it, the verdict
/// on the merged copy's signatures kept with the stored copy or reached here, if any (`signature`).
fn with_pending(tx: &mut Tx<'_>, id: &CommitId, mut blob: CommitBlob) -> Result<(CommitBlob, Option<osis_commit::Signed>)> {
    if tx.core.ix.pending.contains_key(id)
        && let Some(stored) = tx.txn.get_pending(id)?
        && let Ok(mut old) = CommitBlob::decode_stored(&stored.bytes)
    {
        let mut verdict = kept_verdict(&stored);
        // a slot the header does not list has no true copy: a sender could grow the blob by them
        if resolve_held(tx, &mut old.header) {
            let n = old.header.aspects.len();
            blob.parts.retain(|p| p.ai < n);
        }
        let mut others: Vec<osis_commit::Part> = Vec::new();
        let mut rest = Vec::new();
        for p in std::mem::take(&mut blob.parts) {
            let proven = proves(tx.core, &old, id, &p);
            match old.parts.binary_search_by_key(&p.ai, |x| x.ai).ok() {
                Some(i) if old.parts.get(i).is_some_and(|x| x.delta == p.delta) => {}
                // a copy that proves itself against its header entry (by its thing's record held,
                // or the record it carries) replaces a kept first copy that does not: a commit
                // kept while it awaits a record is never held back by junk that came first
                Some(i) if proven && old.parts.get(i).is_some_and(|x| !proves(tx.core, &old, id, x)) => {
                    if let Some(x) = old.parts.get_mut(i) {
                        others.push(std::mem::replace(x, p));
                    }
                }
                Some(_) => others.push(p),
                None => rest.push(p),
            }
        }
        blob.parts = rest;
        if !others.is_empty() {
            keys::read_pending_boxes(tx, &CommitBlob { header: old.header.clone(), sigs: old.sigs.clone(), parts: others, keys: blob.keys.clone() }, id)?;
        }
        let sigs = blob.sigs.clone();
        let mut merged = merge_parts(old, blob);
        // a true copy's signatures replace the first once its author is known here, by what this
        // copy brought (its `created.0`) or by anything else: other bytes than the kept ones,
        // so checked as such
        if sigs != merged.sigs {
            let carried = carried_records(&merged.header, &merged, id);
            let author = tx.core.created(&merged.header.signer).cloned().or_else(|| carried.get(&merged.header.signer).cloned());
            if let Some(author) = author
                && let Ok(vk) = commit_key(&merged.header, &author)
                && let Some(s) = signature(tx.core, id, &sigs, &vk, None)
            {
                merged.sigs = sigs;
                verdict = Some(s);
            }
        }
        return Ok((merged, verdict));
    }
    Ok((blob, None))
}

/// Whether part `p` of commit `id` (`of`: a copy with a resolved header) hashes to its header
/// entry under its thing's record, held or carried by `p` itself (a `created.0` proves itself).
fn proves(core: &crate::engine::Core, of: &CommitBlob, id: &CommitId, p: &osis_commit::Part) -> bool {
    let h = &of.header;
    let Some(a) = h.aspects.get(p.ai).filter(|_| h.is_resolved()) else { return false };
    let record = core.created(&a.tid).cloned().or_else(|| carried_records(h, &CommitBlob { header: h.clone(), sigs: of.sigs.clone(), parts: vec![p.clone()], keys: of.keys.clone() }, id).remove(&a.tid));
    record.is_some_and(|r| osis_crypto::delta_hash(&dedup_secret(r.nonce()), &p.delta) == a.hash)
}

/// `a` with the parts of `b` on slots it lacks, and the path keys of `b`'s things. Each key either
/// holds is the one its header entry commits to (`CommitBlob::check_paths`, `Envelope::open`), so
/// a key both hold is one key, and the merge is the same in either order.
fn merge_parts(mut a: CommitBlob, b: CommitBlob) -> CommitBlob {
    for (i, k) in b.keys {
        let held = a.keys.entry(i).or_insert(k);
        debug_assert_eq!(*held, k, "two keys accepted for one entry");
    }
    for p in b.parts {
        if let Err(i) = a.parts.binary_search_by_key(&p.ai, |x| x.ai) {
            a.parts.insert(i, p);
        }
    }
    a
}

/// A delta of an already applied commit, arriving later, is joined on arrival (spec/commits.md
/// §4); dropped and stripped parts stay so, but for those a copy may replace
/// (`retention::takes_late`). Late deltas that wait (their pages, parked, unjudgeable) are kept
/// pending under the commit's ID and joined once they apply.
fn late_parts(tx: &mut Tx<'_>, id: &CommitId, mut blob: CommitBlob) -> Result<Ingested> {
    let (held, skip) = held_and_skip(tx, id)?;
    let (pending, mut known) = with_pending(tx, id, blob)?;
    blob = pending;
    blob.parts.retain(|p| !skip.contains(&p.ai));
    if blob.parts.is_empty() {
        drop_pending(tx, id)?;
        return Ok(Ingested::Duplicate(*id));
    }
    let mut merged = merge_parts(held, blob.clone());
    let _s = osis_base::costs::span("examine");
    let out = match examine(tx, &mut merged, id, &skip, Origin::Remote, &mut known)? {
        // nothing joins: the late parts keep waiting under the applied commit
        Exam::Ready(Parts { waiting: Some(w), whole, streamed, .. }) if whole.is_empty() && streamed.is_empty() => {
            note_awaited(tx, id, &w);
            blob.parts = w.parts;
            let n = blob.parts.len();
            crate::retention::pending_drops(tx, id, &mut blob, &merged.header)?;
            if blob.parts.len() != n {
                return late_parts(tx, id, blob);
            }
            let things = blob.header.aspects.iter().map(|a| a.tid).collect();
            if w.reason == Reason::Parked && w.others.is_empty() {
                park(tx, id, &blob.encode(), things, Some(blob.header.signer), Some(&blob.header))?;
                return Ok(Ingested::Parked(*id));
            }
            if w.reason == Reason::Parked {
                tell_parked(tx, id, things, Some(blob.header.signer));
            }
            pend(tx, id, PendingKind::Pending, known, &blob.encode(), w.reason.clone(), Some(&blob.header))?;
            keys::read_pending_boxes(tx, &blob, id)?;
            Ingested::Pending(*id, w.reason)
        }
        Exam::Ready(mut parts) => {
            let w = parts.waiting.take();
            tx.core.waits.unawaits(id);
            unpend(tx, id)?;
            let ais = parts.ais();
            crate::retention::reopen_late(tx, id, &ais)?;
            atomic::join_late(tx, id, &merged, parts)?;
            match w {
                Some(w) => pend_aside(tx, id, &merged, w)?,
                None if settled_boxes(tx, id) => keys::forget_unchecked(tx, id)?,
                None => {}
            }
            Ingested::Applied(*id)
        }
        // every late part waits (`Exam::Awaits`: none can be judged, each one's record noted by
        // `pend_unjudgeable`) or the commit's header does: kept pending under the applied commit
        Exam::Pending(r) | Exam::Awaits(r) => {
            // what `examine` dropped of the late parts goes from the stored copy too
            blob.parts.retain(|p| merged.parts.binary_search_by_key(&p.ai, |x| x.ai).is_ok());
            let n = blob.parts.len();
            crate::retention::pending_drops(tx, id, &mut blob, &merged.header)?;
            if blob.parts.len() != n {
                return late_parts(tx, id, blob);
            }
            pend(tx, id, PendingKind::Pending, known, &blob.encode(), r.clone(), Some(&blob.header))?;
            keys::read_pending_boxes(tx, &blob, id)?;
            Ingested::Pending(*id, r)
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
    for ai in (0..meta.parts()).filter(|ai| meta.body_gone(*ai)) {
        if !crate::retention::takes_late(tx, id, ai) {
            skip.insert(ai);
        }
    }
    held.header = (*meta.header).clone();
    Ok((held, skip))
}

/// Applies a commit this node just built, `signed` its signature's verdict (no signature
/// check: it signed it).
pub(crate) fn apply_local(tx: &mut Tx<'_>, blob: &CommitBlob, signed: osis_commit::Signed, received: WallMs) -> Result<()> {
    let id = blob.id();
    let mut b = blob.clone();
    // a path stating an edge nobody granted its signer gives it nothing (`thing_wait`)
    let h = blob.header.clone();
    let ungranted = |ai: usize| Error::Permission { tid: h.aspects.get(ai).map_or(h.signer, |a| a.tid), needs: osis_base::Role::Write };
    match examine(tx, &mut b, &id, &BTreeSet::new(), Origin::Local, &mut Some(signed))? {
        Exam::Ready(Parts { waiting: Some(w), .. }) if w.reason == Reason::MissingChain(h.signer) => Err(ungranted(w.parts.first().map_or(0, |p| p.ai))),
        Exam::Awaits(Reason::MissingChain(s)) if s == h.signer => Err(ungranted(0)),
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
            if !tx.core.skip_writer_rules && tx.core.ix.commits.get(&id).is_some_and(|m| m.valid().iter().any(|v| !v)) {
                return Err(Error::Permission { tid: b.header.aspects.first().map_or(b.header.signer, |a| a.tid), needs: osis_base::Role::Write });
            }
            Ok(())
        }
        Exam::Awaits(r) | Exam::Pending(r) => Err(Error::Misuse(match r {
            Reason::MissingChain(_) => "own commit not applicable: a record on its chain is missing",
            Reason::UnknownCreated(_) => "own commit not applicable: a thing's record is unknown",
            Reason::Outside(_) => "own commit not applicable: a thing outside the node closure",
            Reason::Miskeyed(_) => "own commit not applicable: a delete key no step places",
            Reason::Drift => "own commit not applicable: ts drift",
            Reason::WaitBlobs => "own commit not applicable: blobs missing",
            Reason::Parked | Reason::Unexamined | Reason::Fault => "own commit not applicable: parked",
        })),
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
            None => Arc::new(self.held_resolved(blob.header.clone())?),
        };
        let pending: Vec<osis_commit::Part> = self.run(|tx| Ok(tx.txn.get_pending(&id)?.and_then(|p| CommitBlob::decode_stored(&p.bytes).ok()).map(|b| b.parts))).ok().flatten().unwrap_or_default();
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
        match signed_by_author(&self.core, blob, &id, record(&self.core, &h.signer).as_ref(), None) {
            Some(true) => {}
            Some(false) => return Some(false),
            None => known = false,
        }
        known.then_some(true)
    }

    /// `h` with its lists resolved from held blobs (`resolve_held`, in a transaction kept only
    /// when they resolve): `None` while one is away.
    pub(crate) fn held_resolved(&mut self, mut h: Header) -> Option<Header> {
        if !h.is_resolved() {
            self.run(|tx| if resolve_held(tx, &mut h) { Ok(()) } else { Err(Error::Misuse("not resolved")) }).ok()?;
        }
        Some(h)
    }

    /// The commits whose held entries the sync layer opens again, named since the last call: a
    /// part or signature of a pending copy proved junk, when a true copy the first one kept out
    /// may be held (`with_pending`); a held commit missing a part a blob of it opened on a thing
    /// come to be held whole (`wake_entered`).
    pub fn take_redeliver(&mut self) -> BTreeSet<CommitId> {
        std::mem::take(&mut self.core.redeliver)
    }

    /// The carriers of commit `id`, named by `take_redeliver`, were opened again: what was kept
    /// of it for that (its opened blobs) goes unless it is held or pending now.
    pub fn redelivered(&mut self, id: &CommitId) -> Result<()> {
        if self.core.ix.commits.contains_key(id) || self.core.ix.pending.contains_key(id) || self.core.redeliver.contains(id) {
            return Ok(());
        }
        let id = *id;
        self.run(|tx| crate::sync_ids::opened::forget(tx, &id))
    }

    /// Whether copy `copy` of commit `id` holds a part that went from the node (spec/commits.md §5:
    /// dropped from the applied commit or held as its leftover while gone, held pending past
    /// its expiry, or gone while pending for a request, `retention::strip_purged`)
    /// and nothing a copy may still be needed for:
    /// its every other part went too, is applied, or, where parts of it wait, is in the pending copy
    /// alike, or provably does not hash to its header entry. Node-sync then forgets the copy's blob and key; one holding a true copy the
    /// node lacks stays, as does every copy of a commit named for redelivery.
    pub fn spent_copy(&mut self, id: &CommitId, copy: &CommitBlob) -> Result<bool> {
        if self.core.redeliver.contains(id) {
            return Ok(false);
        }
        self.read(|tx| {
            let meta = tx.core.ix.commits.get(id).cloned();
            let pending = if tx.core.ix.pending.contains_key(id) { tx.txn.get_pending(id)?.and_then(|p| CommitBlob::decode_stored(&p.bytes).ok()) } else { None };
            let Some(h) = meta.as_ref().map(|m| (*m.header).clone()).or_else(|| pending.as_ref().map(|b| b.header.clone())) else { return Ok(false) };
            let applied: BTreeSet<usize> = match &meta {
                Some(_) => tx.get_commit(id)?.map(|b| b.parts.iter().map(|p| p.ai).collect()).unwrap_or_default(),
                None => BTreeSet::new(),
            };
            let mut gone = false;
            for p in &copy.parts {
                if meta.as_ref().is_some_and(|m| m.is_dropped(p.ai) || m.stripped(p.ai) && crate::retention::is_gone(tx.core, id, p.ai)) || pending.is_some() && (crate::retention::pending_expired(tx, &h, p.ai) || pending.as_ref().map(|b| crate::retention::waiting_stripped(tx, b, id, p.ai)).transpose()?.unwrap_or(false) || pending.as_ref().is_some_and(|b| !b.parts.iter().any(|q| q.ai == p.ai)) && crate::retention::known_purged(tx, &h, id, p.ai)?) {
                    gone = true;
                    continue;
                }
                // applied, or nothing of the commit waits: no copy of it is needed
                let Some(held) = pending.as_ref().filter(|_| !applied.contains(&p.ai)) else { continue };
                if held.parts.iter().any(|q| q.ai == p.ai && q.delta == p.delta) {
                    continue;
                }
                // junk; one on a thing whose record is away may be the true copy of a slot the
                // pending copy holds unchecked
                let junk = match h.aspects.get(p.ai).map(|a| (a, tx.core.created(&a.tid))) {
                    None => true,
                    Some((_, None)) => false,
                    Some((a, Some(r))) => osis_crypto::delta_hash(&dedup_secret(r.nonce()), &p.delta) != a.hash,
                };
                if !junk {
                    return Ok(false);
                }
            }
            Ok(gone)
        })
    }

    /// Receives a commit blob's plaintext (`CommitBlobPlaintext`, spec/wire.md §4) with the page,
    /// chunk and header-list blobs it references (ciphertexts by ID). Bad input is reported as
    /// a diagnostic and returned as an error; nothing of it is stored.
    pub fn ingest(&mut self, bytes: &[u8], blobs: Vec<(BlobId, Vec<u8>)>) -> Result<Ingested> {
        self.ingest_class(bytes, blobs, None, None)
    }

    /// `ingest_valid` of a commit with `pages`, the blobs its deltas link that travel with it
    /// (a piece's, spec/wire.md §9): none of them kept unless the commit is, nothing kept where
    /// one is no blob its deltas link.
    pub(crate) fn ingest_valid_paged(&mut self, bytes: &[u8], pages: &[Vec<u8>], from: Option<carriers::Carrier>) -> Result<Option<Ingested>> {
        self.ingest_kept_paged(bytes, pages, from, |core, id, ais, out| matches!(out, Ingested::Parked(_)) || (matches!(out, Ingested::Applied(_)) && !crate::sync_ids::judged_valid(core, id, ais)))
    }

    /// `ingest` of a commit taken only for what it proves here (a fire's carried commit, a
    /// stranded report's holder keys, spec/permissions.md §4), carried by `from` while it pends
    /// (`carriers`; `None`: by nothing, so nothing of it pends past this transaction): one that
    /// applies with a part it brings judged invalid or an edge write not applied
    /// (`judged_valid`) keeps nothing, as if never received (`None`), and so does one this build
    /// would park.
    pub fn ingest_valid(&mut self, bytes: &[u8], from: Option<carriers::Carrier>) -> Result<Option<Ingested>> {
        self.ingest_kept(bytes, from, |core, id, ais, out| matches!(out, Ingested::Parked(_)) || (matches!(out, Ingested::Applied(_)) && !crate::sync_ids::judged_valid(core, id, ais)))
    }

    /// A sealed fire's bundle taken whole or not at all (spec/sync-inbox.md §4 A sealed fire):
    /// `records` and `evidence` (spec/permissions.md §4) then `fire`, each with the pages of
    /// `pages` its deltas link (`split_pages`; one linked by none refuses it all), in one transaction
    /// kept only when the fire applies valid, or waits for the clock to reach its stamp
    /// (`Pending(fire, Reason::Drift)`, as any commit ahead of the clock), and no evidence commit
    /// brought is parked or applies invalid; else nothing of it is written (`None`), so a
    /// stranger's records and evidence are learned only with a fire that checks out or waits. Decode errors of `fire` are the caller's. Its
    /// transaction failing for a fault of this node (`Error::is_fault`) keeps nothing either, and
    /// judges nothing: `Pending(fire, Reason::Fault)`, told to the app.
    pub(crate) fn ingest_sealed_fire(&mut self, records: Vec<CreationRecord>, evidence: &[Vec<u8>], fire: CommitBlob, pages: &[Vec<u8>]) -> Result<Option<Ingested>> {
        let mut blobs = Vec::new();
        for c in evidence {
            match CommitBlob::decode(c) {
                Ok(b) if b.header.ephemeral.is_none() => blobs.push(b),
                _ => return Ok(None),
            }
        }
        let ids: Vec<CommitId> = blobs.iter().map(|b| b.id()).chain([fire.id()]).collect();
        let id = fire.id();
        let ais: Vec<usize> = fire.parts.iter().map(|p| p.ai).collect();
        let mut refused = false;
        let mut applied = false;
        let r = self.run(|tx| {
            learn_records_in(tx, records)?;
            // the pages travel with the commits linking them, the evidence's included
            let all: Vec<&CommitBlob> = blobs.iter().chain([&fire]).collect();
            let Some(mut split) = split_pages(tx, &all, pages)? else {
                refused = true;
                return Err(Error::Misuse("refused"));
            };
            let fire_pages = split.pop().unwrap_or_default();
            for (b, pages) in blobs.into_iter().zip(split) {
                if !pages.is_empty() && !store_pages(tx, &b, &pages)? {
                    refused = true;
                    return Err(Error::Misuse("refused"));
                }
                let (c, parts): (CommitId, Vec<usize>) = (b.id(), b.parts.iter().map(|p| p.ai).collect());
                match arrive(tx, &c, b, false) {
                    Ok(Ingested::Parked(_)) => refused = true,
                    Ok(Ingested::Applied(_)) if !crate::sync_ids::judged_valid(tx.core, &c, &parts) => refused = true,
                    Ok(Ingested::Applied(_)) => applied = true,
                    Ok(_) => {}
                    Err(e) if e.class() == ErrorClass::Local => return Err(e),
                    Err(_) => refused = true,
                }
                if refused {
                    return Err(Error::Misuse("refused"));
                }
            }
            if !fire_pages.is_empty() && !store_pages(tx, &fire, &fire_pages)? {
                refused = true;
                return Err(Error::Misuse("refused"));
            }
            let out = match arrive(tx, &id, fire, false) {
                Ok(o) => o,
                Err(e) if e.class() == ErrorClass::Local => return Err(e),
                Err(_) => Ingested::Parked(id),
            };
            // one stamped ahead of the clock waits as any commit does (spec/commits.md §4), its
            // entry carrying it: judged when the clock reaches it
            let waits = matches!(out, Ingested::Pending(_, Reason::Drift));
            if !waits && (!matches!(out, Ingested::Applied(_) | Ingested::Duplicate(_)) || !crate::sync_ids::judged_valid(tx.core, &id, &ais)) {
                refused = true;
                // rolled back
                return Err(Error::Misuse("refused"));
            }
            applied |= matches!(out, Ingested::Applied(_));
            for c in &ids {
                crate::sync_ids::opened::persist(tx, c)?;
                // the fire's own entry carries it; it carries its chain
                carriers::taken(tx, c, Some(if *c == id { carriers::Carrier::Entry } else { carriers::Carrier::Fire(id) }))?;
            }
            Ok(out)
        });
        for c in &ids {
            self.openings_done(c);
        }
        // (a refusal rolls back by an error of its own)
        if !refused
            && let Err(e) = &r
            && e.is_fault()
        {
            tell_fault(&mut self.core, Some(id), Vec::new(), e);
            return Ok(Some(Ingested::Pending(id, Reason::Fault)));
        }
        if refused {
            return Ok(None);
        }
        if r.is_ok() && applied {
            self.reexamine()?;
        }
        r.map(Some)
    }

    /// `f` of this node's state with `records` and `copies` taken in as any receipt takes them in
    /// (verified, applied, the sides their receipt records, spec/permissions.md §5.1 Held first),
    /// all of it undone after: a trial, for one judgement alone (spec/sync-opens.md §2). A copy
    /// that is bad input or does not apply is as if not received. Invariant: nothing of the
    /// trial stays (the transaction rolls back), so a peer's copies change nothing this node holds.
    pub(crate) fn trial<T>(&mut self, records: Vec<CreationRecord>, copies: Vec<CommitBlob>, f: impl FnOnce(&mut crate::engine::Core) -> T) -> Result<T> {
        let mut out = None;
        let r = self.run(|tx| {
            learn_records_in(tx, records)?;
            for b in copies {
                let id = b.id();
                match arrive(tx, &id, b, false) {
                    Err(e) if e.class() == ErrorClass::Local => return Err(e),
                    _ => {}
                }
            }
            tx.core.update_timelines();
            out = Some(f(tx.core));
            // rolled back
            Err::<(), _>(Error::Misuse("trial"))
        });
        match (out, r) {
            (Some(v), _) => Ok(v),
            (None, Err(e)) => Err(e),
            (None, Ok(())) => Err(Error::Misuse("trial")),
        }
    }

    /// `ingest` keeping nothing of a commit `refuse` objects to (its outcome, judged in the
    /// transaction, which is then rolled back): `None` for those. One kept is carried by `from`.
    fn ingest_kept(&mut self, bytes: &[u8], from: Option<carriers::Carrier>, refuse: impl Fn(&crate::engine::Core, &CommitId, &[usize], &Ingested) -> bool) -> Result<Option<Ingested>> {
        self.ingest_kept_paged(bytes, &[], from, refuse)
    }

    fn ingest_kept_paged(&mut self, bytes: &[u8], pages: &[Vec<u8>], from: Option<carriers::Carrier>, refuse: impl Fn(&crate::engine::Core, &CommitId, &[usize], &Ingested) -> bool) -> Result<Option<Ingested>> {
        let blob = match CommitBlob::decode(bytes) {
            Ok(b) if b.header.ephemeral.is_none() => b,
            Ok(_) => return Err(Error::BadInput("an ephemeral commit on the durable path")),
            Err(e) if e.class() == ErrorClass::Parked => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let id = blob.id();
        let ais: Vec<usize> = blob.parts.iter().map(|p| p.ai).collect();
        let mut refused = false;
        let r = self.run(|tx| {
            if !pages.is_empty() && !store_pages(tx, &blob, pages)? {
                refused = true;
                return Err(Error::Misuse("refused"));
            }
            let out = arrive(tx, &id, blob, false)?;
            refused = refuse(tx.core, &id, &ais, &out);
            if refused {
                // rolled back
                return Err(Error::Misuse("refused"));
            }
            crate::sync_ids::opened::persist(tx, &id)?;
            carriers::taken(tx, &id, from)?;
            Ok(out)
        });
        let set_aside = Ingested::Pending(id, Reason::Fault);
        // (a refusal rolls back by an error of its own)
        let r = match r {
            r if refused => r,
            Err(e) if e.is_fault() && refuse(&self.core, &id, &ais, &set_aside) => {
                tell_fault(&mut self.core, Some(id), Vec::new(), &e);
                refused = true;
                Ok(set_aside)
            }
            Err(e) if e.is_fault() => self.set_aside_arrival(&id, bytes, from, &e),
            r => r,
        };
        // written where kept, or nothing of it is kept (`sync_ids::opened`)
        self.openings_done(&id);
        if refused {
            return Ok(None);
        }
        if let Ok(Ingested::Applied(_)) = &r {
            self.reexamine()?;
        }
        r.map(Some)
    }

    /// Receives raw creation records (a record blob, an inbox payload's, spec/permissions.md §4):
    /// a record proves itself by its hash, so it needs no commit. Returns how many were new; what
    /// awaited them is judged again.
    pub fn learn_records(&mut self, records: Vec<CreationRecord>) -> Result<usize> {
        let n = self.run(|tx| learn_records_in(tx, records))?;
        if n > 0 {
            self.reexamine()?;
        }
        Ok(n)
    }

    /// Tests: examines every pending commit, as a full scan would (`waits::Waits::every_due`),
    /// from the state the engine's calls left (no `reexamine` first: one would apply what a wake
    /// left due and hide it): the commits that applied then, each a wake the index missed.
    #[doc(hidden)]
    pub fn lost_wakes(&mut self) -> Result<Vec<CommitId>> {
        let before: Vec<CommitId> = self.core.ix.pending.keys().copied().collect();
        self.core.waits.every_due = true;
        self.reexamine()?;
        Ok(before.into_iter().filter(|c| !self.core.ix.pending.contains_key(c) && self.core.ix.commits.contains_key(c)).collect())
    }

    /// Learns the loose records something here came to await, with the loose records on their
    /// record chains (spec/commits.md §4 Pending storage). Whether one was learned.
    fn promote_loose(&mut self) -> Result<bool> {
        let due = self.core.waits.loose.take_due();
        let seeds: Vec<Tid> = due.into_iter().filter(|t| self.core.waits.loose.get(t).is_some() && waits::awaits_record(&self.core, t)).collect();
        if seeds.is_empty() {
            return Ok(false);
        }
        let recs = crate::sync::with_chains(&self.core, seeds, &BTreeMap::new());
        // the due records were taken outside its transaction (`run_taken`)
        let n = self.run_taken(|tx| learn_records_in(tx, recs));
        Ok(n? > 0)
    }

    /// The transaction taking received commit `id` (`bytes`, as it came) failed for fault `e` of
    /// this node: one that only sets it aside (`set_aside`), carried by `carrier` (`None`: a
    /// memory commit, or by nothing). An error here (the same fault again, outside the commit)
    /// is the node's.
    fn set_aside_arrival(&mut self, id: &CommitId, bytes: &[u8], carrier: Option<carriers::Carrier>, e: &Error) -> Result<Ingested> {
        let memory = CommitBlob::decode(bytes).is_ok_and(|b| b.header.ephemeral.is_some());
        self.run(|tx| {
            if memory {
                tx.set_memory();
            }
            let out = set_aside(tx, id, Some(bytes), e)?;
            crate::sync_ids::opened::persist(tx, id)?;
            carriers::taken(tx, id, carrier)?;
            Ok(out)
        })
    }

    /// Receives a memory commit (session form, spec/commits.md §2-§3) through the commit path,
    /// every row it derives in memory. `room`: what holding it may cost, as `memory_charge`
    /// counts it (the node cap, spec/sync-compaction.md §2 caps): it waits undecoded until its header lists,
    /// pages and value roots are held (`reach::wait_parts`), and when its parts not held here could
    /// cost more (`memory::new_parts_bound`, from their bytes, their pages' and their values'
    /// roots) it is `TooLarge`, nothing
    /// of it decoded, held or kept waiting (`memory::memory_gate`). One that waits is applied
    /// only by `apply_waiting_memory`, within the room then. Sync reaches it through
    /// `open_entry`; `ingest` refuses an ephemeral commit.
    pub fn ingest_memory(&mut self, bytes: &[u8], room: u64) -> Result<Ingested> {
        self.ingest_class(bytes, Vec::new(), None, Some(room))
    }

    /// `room`: a memory commit's (`ingest_memory`); `None` on the durable path.
    fn ingest_class(&mut self, bytes: &[u8], blobs: Vec<(BlobId, Vec<u8>)>, peer: Option<Tid>, room: Option<u64>) -> Result<Ingested> {
        let memory = room.is_some();
        let _s = osis_base::costs::span("ingest");
        let mut fresh = false;
        let mut seen = None;
        self.core.memory_room = room;
        let r = self.run(|tx| {
            let decoded = CommitBlob::decode(bytes);
            seen = decoded.as_ref().ok().map(CommitBlob::id);
            if matches!(&decoded, Ok(b) if b.header.ephemeral.is_some() != memory) {
                return Err(Error::BadInput(if memory { "a durable commit on the memory path" } else { "an ephemeral commit on the durable path" }));
            }
            // a memory commit stores nothing durable; it is decoded only within `room`
            // (`memory::memory_gate`)
            if room.is_some() {
                tx.set_memory();
            } else {
                fresh = !tx.store_blobs(blobs)?.is_empty();
            }
            match decoded {
                Ok(blob) => {
                    let id = blob.id();
                    let out = arrive(tx, &id, blob, fresh)?;
                    crate::sync_ids::opened::persist(tx, &id)?;
                    // an entry carries it (a memory commit's copy is the memory lane's)
                    if !memory {
                        carriers::taken(tx, &id, Some(carriers::Carrier::Entry))?;
                    }
                    Ok(out)
                }
                Err(e) if e.class() == ErrorClass::Parked => {
                    let id = raw_id(bytes)?;
                    // the same bytes parked again bring nothing
                    if !tx.core.ix.pending.contains_key(&id) || tx.txn.get_pending(&id)?.is_none_or(|p| p.bytes != bytes) {
                        park(tx, &id, bytes, Vec::new(), peer, None)?;
                    }
                    if !memory {
                        carriers::taken(tx, &id, Some(carriers::Carrier::Entry))?;
                    }
                    Ok(Ingested::Parked(id))
                }
                Err(e) => Err(e.into()),
            }
        });
        self.core.memory_room = None;
        if fresh && r.is_ok() {
            self.blobs_stored();
        }
        let r = match (r, seen) {
            // a memory commit's copy is the memory lane's
            (Err(e), Some(id)) if e.is_fault() => self.set_aside_arrival(&id, bytes, (!memory).then_some(carriers::Carrier::Entry), &e),
            (r, _) => r,
        };
        // written where kept, or nothing of it is kept (`sync_ids::opened`)
        if let Some(id) = seen {
            self.openings_done(&id);
        }
        match &r {
            Err(e) if e.class() == ErrorClass::BadInput => {
                self.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::BadInput, tids: Vec::new(), commit: raw_id(bytes).ok(), peer, detail: e.to_string() }, self.core.hlc.mono());
            }
            Ok(Ingested::Applied(_)) => self.reexamine()?,
            // it awaits a record kept loose: learned now (`promote_loose`); blobs it brought end
            // other commits' waits (`reach::Walks`)
            _ if self.core.waits.loose.has_due() || self.core.walks.due() => self.reexamine()?,
            _ => {}
        }
        r
    }

    /// Forgets reading-only secrets sourced from `id`: it was judged bad or its last entry left.
    pub fn forget_awaiting(&mut self, id: &CommitId) -> Result<()> {
        self.core.waits.unawaits(id);
        if !self.core.waits.read_any(id) {
            return Ok(());
        }
        let id = *id;
        self.run(|tx| keys::forget_unchecked(tx, &id))
    }

    /// No entry in the sync store names a blob of commit `id` any more (sync's
    /// `store::follow::release`, or a test standing in for it): that carrier goes, and with its
    /// last carrier its pending copy (`carriers`). Whether the copy went.
    pub fn release_entry(&mut self, id: &CommitId) -> Result<bool> {
        if !self.core.ix.pending.contains_key(id) {
            return Ok(false);
        }
        let id = *id;
        self.run(|tx| carriers::entry_gone(tx, &id))?;
        Ok(!self.core.ix.pending.contains_key(&id))
    }

    /// The carriers of pending commit `id` (`carriers`).
    pub fn pending_carriers(&self, id: &CommitId) -> Vec<carriers::Carrier> {
        self.core.ix.carriers.get(id).into_iter().flatten().copied().collect()
    }

    /// Pending commits `reexamine` read again so far (scale checks).
    pub fn examined(&self) -> u64 {
        self.core.waits.examined
    }

    /// Re-examines the pending commits parked under what arrived since (`Wake`: a record, the
    /// role inputs moving, the clock, an open; a blob a slot of theirs lacked last, once it
    /// lacks nothing: `reach::round`) until none applies; nothing else is read.
    /// Loose records something now awaits are learned first (`promote_loose`). Role commits are
    /// tried first.
    pub fn reexamine(&mut self) -> Result<()> {
        let _s = osis_base::costs::span("reexamine");
        loop {
            self.promote_loose()?;
            // the commits parked under what arrived, and those whose boxes the reading-only
            // budget has room for now: examined again (`waits::wake`)
            let ids = waits::wake(&mut self.core);
            // the blob waits the arrivals since reached, taken on in the round (`reach::round`)
            let (arrived, lost) = self.core.walks.take_due();
            if ids.is_empty() && arrived.is_empty() && lost.is_empty() {
                return Ok(());
            }
            let _s = osis_base::costs::span("reexamine: round");
            #[cfg(test)]
            let fail = std::mem::take(&mut self.fail_round);
            let progressed = self.run_taken(|tx| {
                #[cfg(test)]
                if fail {
                    return Err(Error::Corrupt("a round failing (tests)"));
                }
                let mut ids = ids;
                ids.append(&mut reach::round(tx, arrived, lost)?);
                if ids.is_empty() {
                    return Ok(false);
                }
                let mut blobs: Vec<(CommitId, CommitBlob)> = Vec::new();
                let pending = &tx.core.ix.pending;
                tx.core.memory_waits.retain(|id| pending.contains_key(id));
                for id in ids {
                    // a memory commit waits for node-sync, which applies it within its sync ID's
                    // room (`apply_waiting_memory`): woken, it is stamped for it
                    if !tx.core.memory_waits.contains(&id) {
                        tx.core.waits.examined += 1;
                        let Some(b) = read_pending(tx, &id)? else { continue };
                        if b.header.ephemeral.is_none() {
                            blobs.push((id, b));
                            continue;
                        }
                        tx.core.memory_waits.insert(id);
                    }
                    tx.core.waits.memory_woken.wrote_added(&id, true, true);
                }
                blobs.sort_by_key(|(_, b)| (!b.header.kind.is_role(), b.header.ts));
                tx.core.touch();
                let mut progressed = false;
                for (id, b) in blobs {
                    progressed |= matches!(retry_pending(tx, id, b)?, Some(Ingested::Applied(_)));
                }
                Ok(progressed)
            })?;
            // a commit examined again may now await a record kept loose (`set_pending` named it
            // due): learned at the next round's `promote_loose`, though nothing applied
            if !progressed && !self.core.waits.loose.has_due() {
                return Ok(());
            }
        }
    }

    /// Applies waiting memory commit `id` (pending for its blobs, its `ts` or an epoch) if its
    /// wait is over, within `room`, what holding it may cost under its sync ID's cap now
    /// (spec/sync-compaction.md §2 caps, `memory::memory_gate`): `TooLarge` when its bound passes it, nothing
    /// of it kept. `None` when it is not waiting here. Waiting memory commits are applied only
    /// so, never by `reexamine`: the room is node-sync's.
    pub fn apply_waiting_memory(&mut self, id: &CommitId, room: u64) -> Result<Option<Ingested>> {
        if !self.core.ix.pending.contains_key(id) {
            self.core.memory_waits.remove(id);
            return Ok(None);
        }
        let id = *id;
        self.core.memory_room = Some(room);
        let r = self.run(|tx| {
            tx.set_memory();
            let Some(b) = read_pending(tx, &id)? else { return Ok(None) };
            // one whose wait cannot be over is not tried: a commit that keeps waiting costs a
            // step no examination, store write or cache
            if still_waits(tx, &b) {
                return Ok(Some(Ingested::Pending(id, tx.core.ix.pending.get(&id).cloned().unwrap_or(Reason::Unexamined))));
            }
            tx.core.touch();
            retry_pending(tx, id, b)
        });
        self.core.memory_room = None;
        if !self.core.ix.pending.contains_key(&id) {
            self.core.memory_waits.remove(&id);
        }
        if let Ok(Some(Ingested::Applied(_))) = &r {
            self.reexamine()?;
        }
        r
    }

    /// A cursor over waiting memory commits woken by what they awaited (a blob, their `ts`, an
    /// epoch): each is applied only by `apply_waiting_memory`, within the room its sync ID's cap
    /// leaves then (spec/sync-compaction.md §2 Caps).
    pub fn memory_woken_feed(&self) -> osis_base::memo::Feed<CommitId> {
        self.core.waits.memory_woken.feed()
    }

    /// Pending and parked commits with their reasons (`Unexamined` from a load until examined).
    pub fn pending(&self) -> Vec<(CommitId, Reason)> {
        self.core.ix.pending.iter().map(|(k, v)| (*k, v.clone())).collect()
    }

    /// The stored bytes of a held commit (applied: its current blob; pending or parked: as
    /// received), for relaying.
    pub fn commit_bytes(&mut self, id: &CommitId) -> Result<Option<Vec<u8>>> {
        let id = *id;
        self.read(|tx| {
            if let Some(b) = tx.get_commit(&id)? {
                return Ok(Some(b.encode()));
            }
            Ok(tx.txn.get_pending(&id)?.map(|p| p.bytes))
        })
    }

    /// The blob ciphertext `id`, if held (pages, chunks, header-list trees).
    pub fn blob(&mut self, id: &BlobId) -> Result<Option<Vec<u8>>> {
        let id = *id;
        self.read(|tx| tx.blobs.get(&id))
    }

    /// Whether commit `id` is applied, not pending, with the body of every part held: a copy
    /// delivered again can bring nothing (`late_parts`).
    pub(crate) fn holds_whole(&self, id: &CommitId) -> bool {
        !self.core.ix.pending.contains_key(id) && self.core.ix.commits.get(id).is_some_and(|m| m.hold_all().iter().all(|h| matches!(h, crate::engine::Hold::Body { .. })))
    }

    /// IDs of applied durable commits (no memory commit), in (`ts`, ID) order.
    pub fn commit_ids(&self) -> Vec<CommitId> {
        let mut v: Vec<(osis_base::Ts, CommitId)> = self.core.ix.commits.iter().filter(|(_, m)| !m.view.memory).map(|(id, m)| (m.view.ts, *id)).collect();
        v.sort();
        v.into_iter().map(|x| x.1).collect()
    }

    /// The one purge author of held commit `id` (spec/permissions.md §6).
    pub fn commit_purge_author(&self, id: &CommitId) -> Option<Tid> {
        self.core.ix.commits.get(id).map(|m| m.view.purge_author)
    }

    /// What this node opened of held split commit `id`'s paths (`View::paths`); `None` where its
    /// path is in the clear.
    pub fn commit_paths(&self, id: &CommitId) -> Option<Arc<crate::engine::Decided>> {
        self.core.ix.commits.get(id).and_then(|m| m.view.paths.clone())
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
            let purge_author = m.valid_at(ai).then_some(m.view.purge_author)?;
            Some(Creation { commit: *id, ts: m.header.ts, node: m.header.signer, purge_author, received: m.received })
        })
    }

    /// The thing's last content change: of the held content commits (changes, reverts) validly writing one of its aspects other than `created.0` and the
    /// role-class ones, the one shown latest by `min(ts, received)` (an author's clock may
    /// run ahead; `received` is this node's), else its creation. Snapshots are no change, and
    /// ephemeral writes do not count.
    pub fn changed(&self, tid: &Tid) -> Option<Creation> {
        let shown = |c: &Creation| c.ts.wall_ms().min(c.received);
        let mut best = self.creation(tid);
        let aspects = self.core.aspects_of(tid);
        for ((_, ak), ids) in aspects {
            let a = ak.as_str();
            if !osis_schema::core_types::is_content(a) {
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
                let purge_author = m.view.purge_author;
                let c = Creation { commit: *id, ts: m.header.ts, node: m.header.signer, purge_author, received: m.received };
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
    tx.scan(records::CREATED, |_, v| {
        let lim = osis_base::Limits::new(8, v.len());
        created.push(osis_base::decode(&v, &lim).ok().and_then(|v| CreationRecord::from_value(&v)).ok_or(Error::Corrupt("creation record"))?);
        Ok(())
    })?;
    for r in created {
        tx.core.ix.held.create(r);
    }
    let void = tx.scan_keys(records::VOID, "void", CommitId)?;
    tx.core.ix.void.extend(void);
    crate::retention::freed::load(tx)?;
    crate::sync::held::load(tx)?;
    crate::sync::setting::load(tx)?;
    crate::sync::stranded::load(tx)?;
    crate::sync::falls::load(tx)?;
    crate::sync::bodies::load(tx)?;
    carriers::load(tx)?;
    crate::flows::inbox::load_carried(tx)?;
    crate::sync::certblobs::load(tx)?;
    crate::sync::notices::load(tx)?;
    crate::sync_ids::unread::load(tx)?;
    crate::sync_ids::opened::load(tx)?;
    crate::rotation::merge::load(tx)?;
    crate::retention::load_owed(tx)?;
    let mut vl = Vec::new();
    tx.scan(records::GONE, |k, v| {
        vl.push((k.to_vec(), v));
        Ok(())
    })?;
    for (k, v) in vl {
        let mut r = records::Rd::new(&k);
        let (tid, ak) = (r.tid()?, r.ak()?);
        tx.core.ix.gone.insert((tid, ak), crate::retention::decode_owned(&v)?);
    }
    let mut secrets = Vec::new();
    tx.scan(crate::engine::records::SECRETS, |k, v| {
        let t = Tid::from_bytes(k.try_into().map_err(|_| Error::Corrupt("secrets"))?);
        secrets.push((t, crate::engine::secrets::decode_epochs(&v)?));
        Ok(())
    })?;
    tx.core.ix.secrets.extend(secrets);
    // the `keys.0` parts that wrote a keyset, kept once their bodies dropped or went missing
    let mut parts = Vec::new();
    tx.scan(records::OWN_SECRETS, |k, _| {
        let bad = || Error::Corrupt("own secrets");
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
    crate::retention::names::load(tx)?;
    crate::retention::handed::load(tx)?;
    let fast = !rebuild && crate::engine::index::current(tx)?;
    let old = if fast { None } else { crate::engine::index::old_judgments(tx) };
    if fast {
        {
            let _s = osis_base::costs::span("open: index");
            crate::engine::index::load(tx)?;
        }
        let _s = osis_base::costs::span("open: adapt");
        // perm's inputs: the edge writes of the role commits, oldest first, from what the
        // index keeps of their bodies
        let mut edges = crate::engine::index::load_perm(tx)?;
        let mut ids: Vec<(osis_base::Ts, CommitId)> = tx.core.ix.commits.iter().filter(|(_, m)| m.view.kind.is_role()).map(|(id, m)| (m.view.ts, *id)).collect();
        ids.sort();
        for (_, id) in ids {
            // the view, not the header
            let Some((v, path)) = tx.core.ix.commits.get(&id).map(|m| (m.view.clone(), m.header.path.clone())) else { continue };
            // every row is what its record reads now (rewritten with it: late parts, drops;
            // `Engine::check_index` compares them)
            let parts = edges.remove(&id).ok_or(Error::Corrupt("edges row missing"))?;
            validity::hold_role_commit(tx.core, &v, &path, &id, &parts);
        }
        // what each addendum says, from its row
        for (id, parts) in crate::engine::index::load_addenda(tx)? {
            let Some(v) = tx.core.ix.commits.get(&id).map(|m| m.view.clone()) else { continue };
            validity::index_addenda(tx.core, osis_perm::Point { ts: v.ts, node: v.signer, commit: id }, &parts);
        }
        drop(_s);
    } else {
        // applied commits, each record decoded once per write of it (`Core::decoded`, kept as
        // `Tx::get_commit` reads it)
        let mut recs = Vec::new();
        tx.scan(records::COMMIT, |k, v| {
            recs.push((CommitId(k.try_into().map_err(|_| Error::Corrupt("commit record key"))?), v.to_vec()));
            Ok(())
        })?;
        let mut bodies = Vec::new();
        let mut snaps = Vec::new();
        for (id, bytes) in recs {
            let at = tx.commit_stamp(&id);
            let (head, stored) = match tx.core.decoded.record_read(&id, at, &bytes) {
                Some(b) => (crate::engine::index::parse_head(&bytes)?.0, b),
                None => {
                    let (head, b) = decode_commit_record(&bytes)?;
                    let b = Arc::new(b);
                    tx.core.decoded.keep_record(id, at, b.clone(), &bytes);
                    (head, b)
                }
            };
            let blob = Arc::unwrap_or_clone(stored);
            if blob.id() != id {
                return Err(Error::Corrupt("commit record key"));
            }
            let h = Arc::new(blob.header.clone());
            let valid = vec![true; h.aspects.len()];
            let missing = (0..h.aspects.len()).filter(|ai| blob.part(*ai).is_none() && !head.dropped.contains_key(ai) && !head.stripped.contains(ai)).collect();
            // the paths of a split commit's things as the held keys and secrets open them, again
            // as the secrets load (`paths::refresh`)
            let m = Meta::new(h.clone(), paths::decided(tx.core, &h, &blob.keys), valid, head, missing);
            // what a dropped part judged, kept in its record (`Dropped::role`)
            for (ai, d) in m.dropped_parts() {
                if let Some(r) = d.role {
                    tx.core.ix.rotation_role.insert((id, ai), r);
                }
                if d.overreach {
                    tx.core.ix.overreach.insert((id, ai));
                }
            }
            atomic::index_commit(tx.core, &id, &m.view);
            tx.core.note_keys_of(&id, &m.header);
            tx.core.put_meta(id, m);
            if blob.header.kind.is_compaction() {
                snaps.push(blob.clone());
            }
            if blob.header.kind.is_role() || blob.header.aspects.iter().any(|a| a.ak.as_str() == osis_commit::retention::RETENTION || osis_schema::core_types::card_of(a.ak.as_str()).is_some() || osis_schema::core_types::is_addenda(a.ak.as_str())) {
                bodies.push(blob);
            }
        }
        // snapshots: their frontiers (the bodies carrying a write, `retention::carriers`) and
        // the writes they carry whose own delta was never received
        // (a part a piece at a time)
        for blob in snaps {
            let id = blob.id();
            // a part held as its leftover has no slot in the blob (`retention::leftover`)
            let stripped: Vec<usize> = tx.core.ix.commits.get(&id).map(|m| m.stripped_parts().collect()).unwrap_or_default();
            let ais: BTreeSet<usize> = blob.parts.iter().map(|p| p.ai).chain(stripped).collect();
            for ai in ais {
                let Some(a) = blob.header.aspects.get(ai) else { continue };
                let mut carried = crate::retention::snapshot::Carried::default();
                if let Some(g) = each_held_piece(tx, &id, ai, &mut |_, f| {
                    carried.add(&f);
                    Ok(())
                })?
                .flatten()
                {
                    atomic::note_snapshot(tx.core, &a.tid, &a.ak, blob.header.ts, &id, g);
                    atomic::note_carried(tx.core, &a.tid, &a.ak, &id, ai, carried);
                }
            }
        }
        // what is a whole replace (`Hold::Body::whole`), from each held plain body on an own aspect
        let plain: Vec<(CommitId, Arc<crate::engine::View>)> = tx.core.ix.commits.iter().filter(|(_, m)| m.view.kind == Kind::Content && !m.view.memory).map(|(id, m)| (*id, m.view.clone())).collect();
        for (id, view) in plain {
            let own = |ai: usize| view.aspects.get(ai).is_some_and(|a| crate::retention::snapshot::own_aspect(&a.ak));
            let whole: BTreeSet<usize> = held_parts_at(tx, &id, &own)?.into_iter().filter(|(_, d)| matches!(d, Decoded::Delta(x) if crate::retention::snapshot::replaces(&x.fragment))).map(|(ai, _)| ai).collect();
            if let Some(mut m) = tx.core.ix.commits.get(&id).cloned().filter(|_| !whole.is_empty()) {
                for ai in whole {
                    m.set_whole(ai);
                }
                tx.core.put_meta(id, m);
            }
        }
        // perm inputs from role bodies, oldest first
        bodies.sort_by_key(|b| b.header.ts);
        for b in bodies {
            let id = b.id();
            let at = tx.commit_stamp(&id);
            let mut parts = Vec::new();
            for p in &b.parts {
                parts.push((p.ai, (*decoded_part(tx, &b.header, &id, at, p)?).clone()));
            }
            let read = PartsRead::of(&b.header, &parts);
            validity::note_required(tx.core, &b.header, &id, &read);
            if let Some(view) = tx.core.ix.commits.get(&id).map(|m| m.view.clone()) {
                validity::note_cards(tx.core, &b.header, &view, &id, &parts);
            }
            validity::note_settings(tx.core, &b.header, &id, &parts);
            validity::note_addenda(tx.core, &b.header, &id, &parts);
            if !b.header.kind.is_role() {
                continue;
            }
            for (ai, d) in &parts {
                if let (Some(a), Decoded::Delta(d)) = (b.header.aspects.get(*ai), d)
                    && a.ak.as_str() == "secrets.0"
                {
                    keys::note_boxes_to(tx.core, &a.tid, &d.fragment);
                }
            }
            let (v, path) = tx.core.ix.commits.get(&id).map(|m| (m.view.clone(), m.header.path.clone())).ok_or(Error::Corrupt("commit meta"))?;
            validity::hold_role_commit(tx.core, &v, &path, &id, read.perm());
            #[cfg(debug_assertions)]
            tx.core.rebuilt_perm.insert(id, read.perm().clone());
        }
    }
    // the role commits given to the walk at once (held one by one, each update would judge the
    // grants anew)
    tx.core.update_timelines();
    // which things are independent, before any box opens: what a box gives is judged by the
    // node's role on its actor (`rotation::role_here`), which reads the actor a thing's secrets
    // derive from (with every commit's validity; a rebuild's re-judging below re-derives what
    // flips)
    let things: BTreeSet<Tid> = tx.core.ix.keyset_parts.keys().copied().collect();
    keys::refresh_independent(tx, &things, false)?;
    // a commit read before the record it needs (a nested edge write `ts`-ordered before its
    // grant: another node's clock) is derived now, as it was when that record arrived
    validity::resolve_unresolved(tx)?;
    if fast {
        let _s = osis_base::costs::span("open: walks");
        crate::engine::index::update_timelines_loaded(tx)?;
    }
    crate::rotation::load_lost(tx)?;
    crate::rotation::load_kept(tx)?;
    crate::flows::inbox::load(tx)?;
    crate::flows::inbox::load_sent(tx)?;
    crate::retention::leaving::load(tx)?;
    let mut pend = Vec::new();
    tx.each_pending(|id, p| pend.push((id, p.kind)))?;
    for (id, k) in pend {
        set_pending(tx.core, &id, Some((if k == PendingKind::Parked { Reason::Parked } else { Reason::Unexamined }, None)));
    }
    // each examined once by the open's `reexamine`
    tx.core.waits.open_due = true;
    crate::retention::destroy::load(tx, fast)?;
    // derived indexes from states (secrets: persisted, read again on a rebuild)
    let mut aspects = Vec::new();
    tx.scan(crate::engine::records::ASPECTS, |k, _| {
        let mut r = records::Rd::new(k);
        aspects.push((r.tid()?, r.ak()?));
        Ok(())
    })?;
    for (tid, ak) in aspects {
        match ak.as_str() {
            // what observing a `keys.0` state derives is the delete hints it ends, which a load
            // reads from the index or not at all (a rebuild holds none to end)
            "keys.0" => {}
            "secrets.0" if fast => {}
            // seeds are judged by D's epochs established, known only once loaded: the open
            // takes them up after (`Engine::take_account`), a reload keeps those held
            "account.0" => {}
            // a state-list row is a state (`Tx::derive`)
            "sync.0" => {
                tx.core.ix.sync_recorded.insert(tid);
                if let Some(f) = tx.state(&tid, &ak)?.cloned() {
                    let ids = crate::sync::recorded_ids(&f);
                    for s in &ids {
                        tx.core.ix.sync_recorders.insert(*s, tid);
                    }
                    if !ids.is_empty() {
                        tx.core.ix.sync_recorded_ids.insert(tid, ids);
                    }
                    tx.core.steps_recorded(&tid, Some(&f));
                }
            }
            _ => atomic::observe_state(tx, &tid, &ak)?,
        }
    }
    if fast {
        // every delta's validity is persisted: nothing to re-judge
        tx.core.stale_things.clear();
        tx.core.stale_authors.clear();
        tx.core.stale_under.clear();
        tx.core.stale_commits.clear();
        tx.core.stale_all = false;
        for t in tx.core.ix.keys_due.iter().copied().collect::<Vec<_>>() {
            tx.core.ix.keys_due.remove(&t);
        }
    } else {
        tx.core.stale_all = true;
        validity::rejudge_all(tx, false)?;
        // the held keysets and boxes from the valid `keys.0` and `secrets.0` parts, now judged
        // (nothing judges by them before)
        let actors: BTreeSet<Tid> = tx.core.ix.commits.values().flat_map(|m| m.view.aspects.iter().filter(|a| matches!(a.ak.as_str(), "keys.0" | "secrets.0")).map(|a| a.tid)).collect();
        keys::rebuild_keysets(tx, &actors)?;
    }
    // the split commits' paths the loaded secrets open (`paths::refresh`); persisted, as decided
    if fast {
        paths::follow_loaded(tx);
    } else {
        paths::refresh(tx);
    }
    // what addenda are owed is re-derived, never kept (`flows::addenda`)
    crate::flows::addenda::all_due(tx.core);
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

/// Rebuilds what the waits read after a load: the commits reading-only secrets came from. A load
/// is no arrival: what the index replayed wakes nothing.
pub(crate) fn load_waits(core: &mut crate::engine::Core) {
    core.ix.held.take_records();
    core.ix.held.take_moved();
    waits::load_reading(core);
}

/// Bytes to read decode-only, as checked: the delta of a part of a blob `examine` accepted
/// (`Exam::Ready`) or of a stored commit record, or a stored state, state page or leftover body
/// (`state::encode`'s snapshot bytes). A record holds only parts `examine` checked in full: bad,
/// junk, unjudged and waiting parts leave the blob before `Tx::put_commit`, and every rewrite of a
/// record only removes parts; a state is this node's own encoding, canonical as written. The
/// engine's one `Checked::verified` (tools/policy.py).
pub(crate) fn checked(bytes: &[u8]) -> osis_crdt::Checked<'_> {
    osis_crdt::Checked::verified(bytes)
}

/// Decodes the parts of a stored commit record (or of one about to be stored: a blob `examine`
/// accepted) whole, decode-only (`checked`, `osis_commit::read_part_whole`).
fn examine_stored<'p>(tx: &mut Tx<'_>, h: &Header, parts: impl IntoIterator<Item = &'p osis_commit::Part>, id: &CommitId) -> Result<Vec<(usize, Decoded)>> {
    let mut out = Vec::new();
    let mut interner = Interner::new();
    for p in parts {
        let a = h.aspects.get(p.ai).ok_or(Error::Corrupt("part index"))?;
        let dedup = tx.core.dedup(&a.tid).ok_or(Error::Corrupt("dedup"))?;
        let mut blobs = TxBlobs::new(&mut tx.blobs, tx.txn.is_memory());
        let mut paged = BlobReader::new(&dedup, &mut blobs);
        let reader: &mut dyn osis_crdt::PageSource = &mut paged;
        out.push((p.ai, osis_commit::read_part_whole(h, id, p.ai, checked(&p.delta), &mut interner, Some(reader)).map_err(|_| Error::Corrupt("stored delta"))?));
    }
    Ok(out)
}

/// What perm's adaptation reads of a held role commit: its held `roles.0` parts.
pub(crate) fn perm_parts(tx: &mut Tx<'_>, id: &CommitId) -> Result<validity::PermParts> {
    // the header decoded only for a held record
    let Some(h) = tx.core.ix.commits.get(id).map(|m| m.header.clone()) else { return Ok(validity::PermParts::default()) };
    let Some(blob) = tx.get_commit(id)? else { return Ok(validity::PermParts::default()) };
    perm_parts_of(tx, id, &h, &blob)
}

/// `perm_parts` of a commit record's blob (`h`: its resolved header).
pub(crate) fn perm_parts_of(tx: &mut Tx<'_>, id: &CommitId, h: &Header, blob: &CommitBlob) -> Result<validity::PermParts> {
    let perm = blob.parts.iter().filter(|p| h.aspects.get(p.ai).is_some_and(|a| validity::edge_ak(a.ak.as_str())));
    Ok(validity::PermParts::of(h, &examine_stored(tx, h, perm, id)?))
}

/// The decoded part of a held commit on aspect `ai`.
pub(crate) fn held_part(tx: &mut Tx<'_>, id: &CommitId, ai: usize) -> Result<Option<Decoded>> {
    Ok(held_parts_at(tx, id, &|x| x == ai)?.pop().map(|x| x.1))
}

/// The fragment of a held commit's part on aspect `ai`.
pub(crate) fn held_fragment(tx: &mut Tx<'_>, id: &CommitId, ai: usize) -> Result<Option<osis_crdt::Fragment>> {
    Ok(held_part(tx, id, ai)?.map(Decoded::into_fragment))
}

/// The join of the held parts of commit `id` among `ais` (an aspect's pieces, spec/wire.md §4
/// Pieces: they join as its one delta); `None` where none is held.
pub(crate) fn held_joined(tx: &mut Tx<'_>, id: &CommitId, ais: impl IntoIterator<Item = usize>) -> Result<Option<osis_crdt::Fragment>> {
    let mut out: Option<osis_crdt::Fragment> = None;
    for ai in ais {
        let Some(f) = held_fragment(tx, id, ai)? else { continue };
        match &mut out {
            Some(o) => {
                o.join(f);
            }
            None => out = Some(f),
        }
    }
    Ok(out)
}

/// The fragment of the part of commit `id` on aspect `ai` its record holds (never a leftover):
/// what a state stored as that body reads (`engine::state::Stored::Body`).
pub(crate) fn stored_fragment(tx: &mut Tx<'_>, id: &CommitId, ai: usize) -> Result<Option<osis_crdt::Fragment>> {
    let Some(stored) = tx.get_commit(id)? else { return Ok(None) };
    let Some(p) = stored.part(ai) else { return Ok(None) };
    let Some(header) = tx.core.ix.commits.get(id).map(|m| m.header.clone()) else { return Ok(None) };
    let at = tx.commit_stamp(id);
    Ok(Some((*decoded_part(tx, &header, id, at, p)?).clone().into_fragment()))
}

/// Streams the held part of commit `id` on aspect `ai` a piece at a time (`atomic::stream_stored`:
/// the skeleton, then its pages; joining the pieces is joining the part): what reads a part
/// element by element holds about one page of it. `None` when no part is held, else a snapshot's
/// frontiers and `Absorbed`. A stripped part (`Hold::Leftover`) is its leftover, one piece
/// (`retention::leftover`).
pub(crate) fn each_held_piece(tx: &mut Tx<'_>, id: &CommitId, ai: usize, f: &mut dyn FnMut(&mut Tx<'_>, osis_crdt::Fragment) -> Result<()>) -> Result<Option<Option<crate::engine::Gives>>> {
    each_held_page(tx, id, ai, None, &mut |tx, p| f(tx, atomic::piece_fragment(p)))
}

/// `each_held_piece` handing over the pieces themselves, only the pages `want` names (a
/// stripped part's leftover is one skeleton).
pub(crate) fn each_held_page(tx: &mut Tx<'_>, id: &CommitId, ai: usize, want: Option<osis_crdt::Want<'_>>, f: &mut dyn FnMut(&mut Tx<'_>, osis_crdt::Piece) -> Result<()>) -> Result<Option<Option<crate::engine::Gives>>> {
    let Some((h, stripped)) = tx.core.ix.commits.get(id).map(|m| (m.header.clone(), m.stripped(ai))) else { return Ok(None) };
    let Some(a) = h.aspects.get(ai) else { return Ok(None) };
    if stripped {
        let Some(l) = crate::retention::leftover::get(tx, &a.tid, &a.ak, id, ai)? else { return Err(Error::Corrupt("leftover missing")) };
        f(tx, osis_crdt::Piece::Skeleton(l.fragment))?;
        return Ok(Some(l.gives));
    }
    let Some(blob) = tx.get_commit(id)? else { return Ok(None) };
    let Some(p) = blob.part(ai) else { return Ok(None) };
    let dedup = tx.core.dedup(&a.tid).ok_or(Error::Corrupt("dedup"))?;
    // counted with its pages (`atomic::SharedPages`)
    osis_base::costs::count("stream: bytes", p.delta.len() as u64);
    Ok(Some(atomic::stream_stored(tx, &h, id, ai, checked(&p.delta), &dedup, want, f)?))
}

/// The held part of commit `id` on aspect `ai` at `at`'s positions (`Fragment::positions_at`), with
/// what `each_held_piece` returns: its skeleton and the pages holding them (`PageIndex`, found
/// by the first read of the part and kept per write of its record, `Core::decoded`), so a read
/// costs the root and `at`'s pages, flat in the part's size.
pub(crate) fn held_part_at(tx: &mut Tx<'_>, id: &CommitId, ai: usize, at: &osis_crdt::Fragment) -> Result<(osis_crdt::Fragment, Option<Option<crate::engine::Gives>>)> {
    let stored = if tx.core.ix.commits.get(id).is_some_and(|m| m.stripped(ai)) { None } else { tx.get_commit(id)?.and_then(|b| b.part(ai).cloned()) };
    let stamp = tx.commit_stamp(id);
    let mut kept = stored.as_ref().and_then(|p| tx.core.decoded.page_index(id, stamp, p));
    // a paged part's index is stored beside it since its apply: a session streams no page to
    // find the pages of a position
    if kept.is_none()
        && let Some(p) = &stored
        && let Some(x) = stored_page_index(tx, id, ai)?
    {
        let x = Arc::new(x);
        tx.core.decoded.keep_page_index(*id, stamp, p, x.clone());
        kept = Some(x);
    }
    // a part with no pages is its skeleton: read decoded once per write of its record, not
    // streamed whole at each read
    if let Some(p) = &stored
        && kept.as_ref().is_some_and(|k| k.unpaged())
        && let Some(h) = tx.core.ix.commits.get(id).map(|m| m.header.clone())
    {
        let d = decoded_part(tx, &h, id, stamp, p)?;
        let gives = match &*d {
            Decoded::Snapshot(x) => Some((x.frontiers.clone(), x.absorbed.iter().map(|(c, t)| (*c, *t)).collect(), x.facts.clone())),
            Decoded::Delta(_) => None,
        };
        return Ok((d.fragment().positions_at(at), Some(gives)));
    }
    let wanted = kept.as_ref().map(|k| k.wanted(at));
    let want = wanted.as_ref().map(|w| move |path: &[osis_crdt::Step], x: &[usize]| w.wants(path, x));
    let mut part = osis_crdt::Fragment::default();
    let mut index = (stored.is_some() && kept.is_none()).then(osis_crdt::PageIndex::default);
    let gives = each_held_page(tx, id, ai, want.as_ref().map(|w| w as osis_crdt::Want<'_>), &mut |_, p| {
        if let Some(x) = &mut index {
            x.add(&p);
        }
        part.join(atomic::piece_fragment(p).positions_at(at));
        Ok(())
    })?;
    if let (Some(p), Some(x), Some(_)) = (&stored, index, &gives) {
        tx.core.decoded.keep_page_index(*id, stamp, p, Arc::new(x));
    }
    Ok((part, gives))
}

/// The root of the held part of commit `id` on aspect `ai`: its skeleton, no page read (a
/// stripped part's leftover whole). What its root's own writes read (a whole reset).
pub(crate) fn held_root(tx: &mut Tx<'_>, id: &CommitId, ai: usize) -> Result<Option<osis_crdt::Fragment>> {
    let mut root = None;
    let none = |_: &[osis_crdt::Step], _: &[usize]| false;
    let held = each_held_page(tx, id, ai, Some(&none), &mut |_, p| {
        if let osis_crdt::Piece::Skeleton(f) = p {
            root = Some(f);
        }
        Ok(())
    })?;
    Ok(held.and(root))
}

fn page_index_key(id: &CommitId, ai: usize) -> Vec<u8> {
    [crate::engine::records::PAGE_INDEX, &id.0[..], &(ai as u32).to_be_bytes()].concat()
}

/// The stored page index of part `ai` of commit `id` (`put_page_index`), if it has one: a paged
/// part applied here.
pub(crate) fn stored_page_index(tx: &mut Tx<'_>, id: &CommitId, ai: usize) -> Result<Option<osis_crdt::PageIndex>> {
    match tx.txn.get_local(&page_index_key(id, ai))? {
        Some(b) => Ok(Some(osis_crdt::PageIndex::from_bytes(&b)?)),
        None => Ok(None),
    }
}

/// Keeps the page index of paged part `ai` of commit `id`, in the commit's class.
pub(crate) fn put_page_index(tx: &mut Tx<'_>, id: &CommitId, ai: usize, x: &osis_crdt::PageIndex) -> Result<()> {
    let memory = tx.is_memory_commit(id);
    let (k, v) = (page_index_key(id, ai), x.to_bytes());
    tx.in_class(memory, |tx| Ok(tx.txn.put_local(&k, &v, osis_store::Shred::No)?))
}

/// Forgets the page index of part `ai` of commit `id` (its body goes), every part's with `None`.
pub(crate) fn remove_page_index(tx: &mut Tx<'_>, id: &CommitId, ai: Option<usize>) -> Result<()> {
    match ai {
        Some(ai) => drop(tx.txn.remove_local(&page_index_key(id, ai), osis_store::Shred::Yes)?),
        None => {
            let prefix = [crate::engine::records::PAGE_INDEX, &id.0[..]].concat();
            for (k, _) in tx.txn.scan_local(&prefix, &[], usize::MAX)? {
                tx.txn.remove_local(&k, osis_store::Shred::Yes)?;
            }
        }
    }
    Ok(())
}

/// Whether commit `id` holds a body on aspect `ai` to read (what `each_held_piece` reads): a
/// part in its stored blob, or its leftover.
pub(crate) fn stores_part(tx: &mut Tx<'_>, id: &CommitId, ai: usize) -> Result<bool> {
    if tx.core.ix.commits.get(id).is_some_and(|m| m.stripped(ai)) {
        return Ok(true);
    }
    Ok(tx.get_commit(id)?.is_some_and(|b| b.part(ai).is_some()))
}

/// Decoded parts of a held commit on the aspects `keep` selects, with their part indexes (a
/// stripped part as its leftover).
pub(crate) fn held_parts_at(tx: &mut Tx<'_>, id: &CommitId, keep: &dyn Fn(usize) -> bool) -> Result<Vec<(usize, Decoded)>> {
    let Some(stored) = tx.commit_for_parts(id, keep)? else { return Ok(Vec::new()) };
    let Some((header, stripped)) = tx.core.ix.commits.get(id).map(|m| (m.header.clone(), (0..m.parts()).filter(|ai| keep(*ai) && m.stripped(*ai)).collect::<Vec<_>>())) else { return Ok(Vec::new()) };
    // each stored part decoded once per write of the record (`Core::decoded`)
    let at = tx.commit_stamp(id);
    let mut out = Vec::new();
    for p in stored.parts.iter().filter(|p| keep(p.ai)) {
        let d = decoded_part(tx, &header, id, at, p)?;
        out.push((p.ai, (*d).clone()));
    }
    // cost tests: bodies read, decoded or kept
    osis_base::costs::count("part read", out.len() as u64);
    for ai in stripped {
        let Some(a) = header.aspects.get(ai) else { continue };
        let Some(l) = crate::retention::leftover::get(tx, &a.tid, &a.ak, id, ai)? else { return Err(Error::Corrupt("leftover missing")) };
        let d = leftover_part(l);
        let at = out.partition_point(|x| x.0 < ai);
        out.insert(at, (ai, d));
    }
    Ok(out)
}

/// Stored part `p` of commit `id` (header `header`, record stamp `at`) decoded, once per write
/// of the record (`Core::decoded`).
fn decoded_part(tx: &mut Tx<'_>, header: &Header, id: &CommitId, at: u64, p: &osis_commit::Part) -> Result<Arc<Decoded>> {
    if let Some(d) = tx.core.decoded.part(id, at, p) {
        return Ok(d);
    }
    drop(osis_base::costs::span("part decode"));
    let d = Arc::new(examine_stored(tx, header, [p], id)?.pop().map(|x| x.1).ok_or(Error::Corrupt("stored delta"))?);
    tx.core.decoded.keep_part(*id, at, p, d.clone());
    Ok(d)
}

/// A commit as a thing's time (`Engine::creation`, `Engine::changed`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Creation {
    pub commit: CommitId,
    pub ts: osis_base::Ts,
    pub node: Tid,
    pub purge_author: Tid,
    pub received: WallMs,
}

/// Stores `pages`, the blobs commit `b`'s deltas link that travel with it (a sealed fire's or a
/// piece's, spec/wire.md §9): `false` where one is no blob its deltas link (bad input: the caller
/// rolls the transaction back, keeping none of them).
fn store_pages(tx: &mut Tx<'_>, b: &CommitBlob, pages: &[Vec<u8>]) -> Result<bool> {
    let pages: Vec<(osis_base::BlobId, Vec<u8>)> = pages.iter().map(|p| (osis_blob::blob_id(p), p.clone())).collect();
    let given: BTreeSet<osis_base::BlobId> = pages.iter().map(|p| p.0).collect();
    tx.store_blobs(pages)?;
    let mut linked = crate::engine::large::Trees::default();
    for p in &b.parts {
        let Some(dedup) = b.header.aspects.get(p.ai).and_then(|a| tx.core.dedup(&a.tid)) else { continue };
        crate::engine::large::tree_blobs(tx, &dedup, &crate::engine::large::delta_roots(&p.delta), &mut linked)?;
    }
    Ok(given.is_subset(&linked.blobs))
}

/// `pages`, a piece's or a sealed fire's (spec/wire.md §9: every blob its commits' deltas link),
/// split among `commits` (`commits[i]` gets the pages its deltas link, reached through `pages`
/// and the blobs held, the order given), so each is taken with its own. `None` where a page is
/// linked by none of them (bad input: nothing of the payload is taken). Records of the things
/// they write are learned by then (a link's content hash is keyed by the thing's dedup secret).
/// Invariant (security): the payload is anyone's to make; a blob is kept only as a page of a
/// commit kept with it (`store_pages` per commit, rolled back with it), never on its own.
pub(crate) fn split_pages(tx: &mut Tx<'_>, commits: &[&CommitBlob], pages: &[Vec<u8>]) -> Result<Option<Vec<Vec<Vec<u8>>>>> {
    let given: BTreeMap<BlobId, &Vec<u8>> = pages.iter().map(|p| (osis_blob::blob_id(p), p)).collect();
    let mut out = Vec::new();
    let mut linked = BTreeSet::new();
    for b in commits {
        let mut reached = BTreeSet::new();
        for p in &b.parts {
            let Some(dedup) = b.header.aspects.get(p.ai).and_then(|a| tx.core.dedup(&a.tid)) else { continue };
            let mut stack: Vec<(osis_base::Link, bool)> = crate::engine::large::delta_roots(&p.delta).into_iter().map(|l| (l, false)).collect();
            let mut held = TxBlobs::new(&mut tx.blobs, tx.txn.is_memory());
            while let Some((l, leaf)) = stack.pop() {
                if !reached.insert(l.blob) || leaf {
                    continue;
                }
                let o = crate::engine::large::opens(&l);
                let below = match given.get(&l.blob) {
                    Some(bytes) => crate::engine::large::kids_of(Some(&dedup), &o, bytes),
                    None => crate::engine::large::below(&mut held, &dedup, &o).ok().flatten(),
                };
                if let Some((chunks, kids)) = below {
                    stack.extend(kids.into_iter().map(|k| (k, chunks)));
                }
            }
        }
        out.push(pages.iter().filter(|p| reached.contains(&osis_blob::blob_id(p))).cloned().collect());
        linked.extend(reached);
    }
    Ok(given.keys().all(|id| linked.contains(id)).then_some(out))
}

#[cfg(test)]
mod tests {
    // spec/wire.md §4 field 1: the first form names the record's key, the second any other; a
    // second form naming the record's key, or a first form on a record holding none, is invalid
    // whole (two encodings of one signing, or none)
    #[test]
    fn a_signer_form_names_one_key_spec_wire_4() {
        use osis_base::{CreationRecord, SignKey, Tid};
        let keyed = CreationRecord::with_key(osis_base::SignKey([3; 32]), [0; 32]);
        let minted = CreationRecord::with_admin(Tid::from_bytes([1; 15]), [0; 32]);
        let (own, other) = (SignKey([3; 32]), SignKey([4; 32]));
        assert_eq!(super::named_key(None, &keyed).ok(), Some(own));
        assert_eq!(super::named_key(Some(other), &keyed).ok(), Some(other));
        assert_eq!(super::named_key(Some(other), &minted).ok(), Some(other));
        assert!(super::named_key(Some(own), &keyed).is_err(), "the record's key in the second form");
        assert!(super::named_key(None, &minted).is_err(), "the first form with no record key");
    }

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
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
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
            let e = ct::Edge { role: Role::Write, until: None, may_grant: false, retain: false, floor: None };
            m.op(t, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Weak(x))], op: Op::Set(e.to_value()) }).unwrap();
        }
        lp.peers[0].engine.core.skip_writer_rules = true;
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        // a grant from outside b's account: fired, as the edge writers do
        lp.peers[0].engine.run(|tx| crate::flows::inbox::fire_copy(tx, b, id, t)).unwrap();
        lp.hold_fires(true);
        let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
        for p in lp.packages_for(0, 1).unwrap() {
            if p.id != id {
                lp.deliver(1, &p).unwrap();
            }
        }
        assert_eq!(lp.deliver(1, &pk).unwrap(), Ingested::Applied(id));
        lp.hold_fires(false);
        lp.pass_fires(1).unwrap();
        assert_eq!(lp.peers[1].engine.roster(&t), lp.peers[0].engine.roster(&t));
    }

    // spec/permissions.md §1 (record edge; record chain; max_chain_depth), §5: a writer mints A with admin X, B with admin A and C with admin B in one
    // commit; the commit is valid wherever applied. With a mint admin the writer may not write,
    // the same chain fails the local check, as does a chain of new things past MAX_CHAIN_DEPTH.
    #[test]
    fn tree_created_in_one_commit_spec_perm_1() {
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (a0, a1) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
        let reg = Ak::new("x:a.0").unwrap();
        let mut things = Vec::new();
        for _ in 0..2 {
            let mut m = Mutation::new();
            let t = lp.peers[0].engine.new_thing(&mut m, a0);
            m.set(t, &reg, &Value::Int(0)).unwrap();
            lp.peers[0].commit(m).unwrap();
            lp.hold(t);
            things.push(t);
        }
        let (x, y) = (things[0], things[1]);
        // peer 1 writes in x, which it holds: it opens it
        lp.peers[0].engine.grant(&x, &a1, &ct::Edge { role: Role::Write, until: None, may_grant: false, retain: false, floor: None }).unwrap();
        lp.sync_all().unwrap();
        let p1 = &mut lp.peers[1];
        p1.engine.hold(osis_base::Strong(x)).unwrap();
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
        assert!(p0.engine.core.ix.commits.get(&id).unwrap().valid().iter().all(|v| *v));
        assert!(p0.engine.pending().is_empty());
        for (i, t) in [a, b, c].into_iter().enumerate() {
            assert!(p0.engine.creation(&t).is_some());
            assert_eq!(p0.engine.get(&t, &reg).unwrap(), Some(Value::Int(i as i64 + 1)));
        }
        // the mint admin's tree: the last thing's delete keys derive from its mint admin's secrets
        // through the two created above it (spec/crypto.md §3, §7)
        let mut m = Mutation::new();
        let d = p0.engine.new_thing(&mut m, x);
        let e = p0.engine.new_thing(&mut m, d);
        let f = p0.engine.new_thing(&mut m, e);
        m.set(f, &reg, &Value::Int(4)).unwrap();
        m.purge_by(f, &reg, osis_schema::PurgeBy::Writer).unwrap();
        let id = p0.commit(m).unwrap().unwrap();
        let h = p0.engine.header(&id).unwrap();
        let wf = h.aspects.iter().find(|w| w.tid == f && w.ak == reg).unwrap();
        let levels: Vec<u8> = wf.keys.iter().map(|i| h.keys[*i].level).collect();
        assert_eq!(levels, [1, 2, 3]);
        // a writer of X gets no admin on what it creates below X: no edges there
        let adm = ct::Edge { role: Role::Admin, until: None, may_grant: false, retain: false, floor: None };
        for depth in [1, 3] {
            let p1 = &mut lp.peers[1];
            let mut m = Mutation::new();
            let mut cur = x;
            for _ in 0..depth {
                cur = m.create(p1.engine.thing_record(cur, None));
            }
            m.op(cur, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Weak(a1))], op: Op::Set(adm.to_value()) }).unwrap();
            assert!(matches!(p1.commit(m), Err(crate::Error::Permission { .. })), "depth {depth}");
        }
        // with admin Y (no role there) the chain is refused
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
            // from the account: its root would be a step of the chain
            let mut cur = p0.engine.tid();
            for _ in 0..osis_base::format::MAX_CHAIN_DEPTH + extra {
                cur = p0.engine.new_thing(&mut m, cur);
            }
            m.set(cur, &reg, &Value::Int(7)).unwrap();
            let r = p0.commit(m);
            assert_eq!(r.is_ok(), ok, "{r:?}");
            if !ok {
                assert!(matches!(r, Err(crate::Error::Permission { tid, .. }) if tid == cur));
                assert_eq!(p0.engine.commit_ids().len(), before);
            }
        }
    }

    // spec/crypto.md §2: a node checks each commit's signature once. Invariant (`signature`): a
    // commit is treated as verified only if these exact signature bytes verified under the key
    // that signed them. The writer checks none (it signed them); a receiver one per commit, at n
    // and 10n commits, asked again (`parts_genuine`, `signed_at`) or after a restart none; a copy
    // with forged signature bytes after the genuine one, and the genuine bytes under another key,
    // are refused.
    #[test]
    fn a_commit_signature_is_checked_once_per_node_spec_crypto_2() {
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let ak = Ak::new("x:a.0").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        lp.peers[0].commit(m).unwrap();
        lp.share(0, t);
        lp.sync_all().unwrap();
        let verifies = || osis_base::costs::take().iter().find(|c| c.0 == osis_crypto::Domain::Commit.verify_cost()).map_or(0, |c| c.2);
        let held = |lp: &mut LocalPeer, id: &osis_base::CommitId| (*lp.peers[1].engine.run(|tx| tx.get_commit(id)).unwrap().unwrap()).clone();
        let mut ids = Vec::new();
        for (round, n) in [3, 30].into_iter().enumerate() {
            verifies();
            let mut new = Vec::new();
            for i in 0..n {
                let mut m = Mutation::new();
                m.set(t, &ak, &Value::Int(i)).unwrap();
                new.push(lp.peers[0].commit(m).unwrap().unwrap());
            }
            assert_eq!(verifies(), 0, "the writer signed them");
            for id in &new {
                let pk = lp.peers[0].engine.package(id).unwrap().unwrap();
                assert_eq!(lp.deliver(1, &pk).unwrap(), Ingested::Applied(*id));
                let b = held(&mut lp, id);
                assert_eq!(lp.peers[1].engine.parts_genuine(&b), Some(true));
                assert!(super::signed_at(&lp.peers[1].engine.core, id, &b.header, &b.sigs));
            }
            assert_eq!(verifies(), n as u64, "round {round}: one per commit at the receiver");
            ids.extend(new);
        }
        lp.peers[1].restart(7).unwrap();
        verifies();
        for id in &ids {
            let b = held(&mut lp, id);
            assert_eq!(lp.peers[1].engine.parts_genuine(&b), Some(true));
        }
        assert_eq!(verifies(), 0, "kept with the record across a restart");
        let other = lp.peers[1].engine.tid();
        for id in &ids {
            let genuine = held(&mut lp, id);
            let mut forged = genuine.clone();
            forged.sigs.signature.0[0] ^= 1;
            let e = &mut lp.peers[1].engine;
            assert_eq!(e.parts_genuine(&forged), Some(false), "forged signature bytes");
            assert!(!super::signed_at(&e.core, id, &genuine.header, &forged.sigs));
            assert!(super::signed_at(&e.core, id, &genuine.header, &genuine.sigs));
            let as_other = osis_commit::Header { signer: other, ..genuine.header.clone() };
            assert!(!super::signed_at(&e.core, id, &as_other, &genuine.sigs), "the genuine bytes under another key");
        }
    }

    // spec/crypto.md §2: a pending commit's signature is checked once too, kept with its pending
    // copy: re-examinations (one after every applied commit) and its apply check none again; a
    // restart keeps it as well. A copy with forged signature bytes is checked anew and replaces
    // nothing.
    #[test]
    fn a_pending_commits_signature_is_checked_once_spec_crypto_2() {
        use osis_commit::CommitBlob;
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let ak = Ak::new("x:a.0").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        lp.peers[0].commit(m).unwrap();
        lp.share(0, t);
        lp.sync_all().unwrap();
        let verifies = || osis_base::costs::take().iter().find(|c| c.0 == osis_crypto::Domain::Commit.verify_cost()).map_or(0, |c| c.2);
        lp.peers[0].clock.advance(2 * osis_base::format::MAX_DRIFT_MS);
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Int(1)).unwrap();
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
        let mut forged = pk.clone();
        let mut b = CommitBlob::decode(&forged.bytes).unwrap();
        b.sigs.signature.0[0] ^= 1;
        forged.bytes = b.encode();
        verifies();
        assert!(matches!(lp.deliver(1, &pk).unwrap(), Ingested::Pending(_, super::Reason::Drift)));
        for _ in 0..5 {
            lp.peers[1].reexamine().unwrap();
        }
        assert_eq!(verifies(), 1, "checked once while it waits");
        lp.peers[1].restart(7).unwrap();
        lp.peers[1].reexamine().unwrap();
        assert_eq!(verifies(), 0, "kept with its pending copy across a restart");
        assert!(matches!(lp.deliver(1, &forged).unwrap(), Ingested::Pending(..)), "the stored copy's signatures stay");
        assert_eq!(verifies(), 1, "forged signature bytes are checked as such");
        lp.peers[1].clock.advance(2 * osis_base::format::MAX_DRIFT_MS);
        lp.peers[1].tick().unwrap();
        assert!(lp.peers[1].engine.pending().is_empty());
        assert_eq!(verifies(), 0, "applied on the kept verdict");
        let held = (*lp.peers[1].engine.run(|tx| tx.get_commit(&id)).unwrap().unwrap()).clone();
        assert_eq!(held.sigs, CommitBlob::decode(&pk.bytes).unwrap().sigs, "applied with the genuine signatures");
    }

    // a header held as bytes that fail to decode (hash or format: `LazyHeader`) reads as none
    // outside a transaction, and every later transaction fails as corrupt, never a default
    #[test]
    fn failed_lazy_header_is_corrupt() {
        let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
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
