//! Copies of a pending commit that cannot be told apart yet. A delta hash needs its thing's record
//! (the dedup secret) and a signature its author's: before those come, any relay's junk under a
//! commit ID looks like the author's bytes, and a commit ID's header is fixed but its signature and
//! parts are not.
//!
//! Invariant (spec/commits.md §4): what a relay sends never keeps out what the author signed. The
//! pending blob holds the first copy of each slot and of the signature; a different copy is kept
//! here (`Spare`). As soon as a record or author key is held the slot or signature is settled: the
//! copy that checks stays, the others go. No copy can win by coming first or last, so what applies
//! reads no order of the copies.
//!
//! Bound: `MAX_COPIES_BYTES`. Past it a further copy is refused, never one held in exchange: a flood
//! evicts nothing, and what it kept out is taken when it comes again, the flood's room freed once the
//! record comes. Memory commits keep no copies: nothing charges them to the node's memory cap, their
//! records ride beside their deltas, and the sender resends.

use super::carried_records;
use crate::engine::blobs::TxBlobs;
use crate::engine::{Tx, records};
use crate::error::{Error, Result};
use crate::events::{Diagnostic, DiagnosticKind};
use osis_base::{CommitId, CreationRecord, Tid, Value};
use osis_commit::{CommitBlob, Header, Part};
use osis_crypto::{Signature, VerifyingKey, dedup_secret};
use osis_store::Shred;
use std::collections::BTreeMap;

/// Resource bound against a hostile relay: bytes of unsettled copies kept per commit. Room for a true
/// copy of the largest blob beside as much junk. 0: first copy wins until it can be checked, then a
/// true one must come again (safe, as a flood past this is). Infinity: a relay fills the disk with
/// copies of one signed header.
const MAX_COPIES_BYTES: usize = 2 * osis_base::format::MAX_BLOB;

/// The unsettled copies of a pending commit, beside the first ones in its pending blob.
#[derive(Default)]
pub(super) struct Spare {
    signatures: Vec<Signature>,
    parts: Vec<Part>,
}

impl Spare {
    pub(super) fn is_empty(&self) -> bool {
        self.signatures.is_empty() && self.parts.is_empty()
    }
    fn bytes(&self) -> usize {
        self.signatures.len() * 64 + self.parts.iter().map(|p| p.delta.len() + 16).sum::<usize>()
    }
    fn encode(&self) -> Vec<u8> {
        let sigs = self.signatures.iter().map(Signature::to_value).collect();
        let parts = self.parts.iter().map(|p| Value::List(vec![Value::Int(p.ai as i64), Value::Int(p.di as i64), Value::Bytes(p.delta.clone()), Value::List(p.records.iter().map(CreationRecord::to_value).collect())])).collect();
        osis_base::encode(&Value::List(vec![Value::List(sigs), Value::List(parts)]))
    }
    fn decode(b: &[u8]) -> Option<Spare> {
        let lim = osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: b.len() };
        let Value::List(v) = osis_base::decode(b, &lim).ok()? else { return None };
        let [Value::List(sigs), Value::List(parts)] = v.as_slice() else { return None };
        let signatures = sigs.iter().map(|s| Signature::from_value(s).ok()).collect::<Option<Vec<_>>>()?;
        let parts = parts
            .iter()
            .map(|p| {
                let Value::List(p) = p else { return None };
                let [Value::Int(ai), Value::Int(di), Value::Bytes(delta), Value::List(rs)] = p.as_slice() else { return None };
                let records = rs.iter().map(CreationRecord::from_value).collect::<Option<Vec<_>>>()?;
                Some(Part { ai: usize::try_from(*ai).ok()?, di: usize::try_from(*di).ok()?, delta: delta.clone(), records })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Spare { signatures, parts })
    }
}

fn key(id: &CommitId) -> Vec<u8> {
    [records::COPIES, &id.0[..]].concat()
}

pub(super) fn read(tx: &mut Tx<'_>, id: &CommitId) -> Result<Spare> {
    Ok(tx.txn.get_local(&key(id))?.and_then(|b| Spare::decode(&b)).unwrap_or_default())
}

/// The copies of commit `id` go: it pends no more.
pub(crate) fn clear(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    tx.txn.remove_local(&key(id), Shred::Yes)?;
    Ok(())
}

fn store(tx: &mut Tx<'_>, id: &CommitId, s: &Spare) -> Result<()> {
    if s.is_empty() {
        return clear(tx, id);
    }
    tx.txn.put_local(&key(id), &s.encode(), Shred::Yes)?;
    Ok(())
}

/// The dedup secret `h`'s `t` is hashed under, as far as known: its record held, or carried by a
/// `created.0` copy (self-certifying).
fn record_of(tx: &Tx<'_>, h: &Header, carried: &BTreeMap<Tid, CreationRecord>, t: &Tid) -> Option<CreationRecord> {
    tx.core.created_for(t, h.ephemeral.is_some()).cloned().or_else(|| carried.get(t).cloned())
}

/// Stored pending copy `old` of commit `id` with new copy `new` merged: each slot's copy that checks
/// where it can be checked, the others kept (`Spare`) while it cannot. Whether unsettled copies remain.
pub(super) fn merge(tx: &mut Tx<'_>, id: &CommitId, mut old: CommitBlob, new: CommitBlob) -> Result<(CommitBlob, bool)> {
    let mut spare = read(tx, id)?;
    let keeps = old.header.ephemeral.is_none();
    let mut refused = false;
    let room = |s: &Spare, n: usize| s.bytes().saturating_add(n) <= MAX_COPIES_BYTES;
    if new.signature != old.signature && keeps && !spare.signatures.contains(&new.signature) {
        if room(&spare, 64) {
            spare.signatures.push(new.signature);
        } else {
            refused = true;
        }
    }
    for p in new.parts {
        match old.parts.binary_search_by_key(&(p.ai, p.di), |x| (x.ai, x.di)) {
            Err(i) => old.parts.insert(i, p),
            Ok(i) if old.parts.get(i).is_some_and(|x| x.delta == p.delta) => {}
            Ok(_) if !keeps || spare.parts.iter().any(|x| (x.ai, x.di, &x.delta) == (p.ai, p.di, &p.delta)) => {}
            Ok(_) if room(&spare, p.delta.len() + 16) => spare.parts.push(p),
            Ok(_) => refused = true,
        }
    }
    if refused {
        let now = tx.now();
        tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::BadInput, tids: Vec::new(), commit: Some(*id), peer: None, detail: "too many unsettled copies: this one refused".into() }, now);
    }
    if spare.is_empty() {
        return Ok((old, false));
    }
    settle(tx, id, &mut old, &mut spare)?;
    store(tx, id, &spare)?;
    Ok((old, !spare.is_empty()))
}

/// Settles what can be checked now.
fn settle(tx: &mut Tx<'_>, id: &CommitId, blob: &mut CommitBlob, spare: &mut Spare) -> Result<()> {
    // a linked list resolves as in `examine`; until it does neither can read the hashes
    if !blob.header.is_resolved() {
        let Some(dedup) = tx.core.dedup(&blob.header.actor) else { return Ok(()) };
        match blob.header.resolve(&mut TxBlobs::new(&mut tx.txn), &dedup, osis_commit::MAX_LIST_BYTES) {
            Ok(()) => {}
            Err(e) if super::is_missing_page(&e) => return Ok(()),
            Err(e) => return Err(e.into()),
        }
    }
    let h = blob.header.clone();
    let mut all = blob.clone();
    all.parts.extend(spare.parts.iter().cloned());
    let carried = carried_records(&h, &all, id);
    let mut kept = Vec::new();
    for p in std::mem::take(&mut spare.parts) {
        let check = h.aspects.get(p.ai).and_then(|a| Some((a, a.hashes.get(p.di)?))).and_then(|(a, want)| Some((record_of(tx, &h, &carried, &a.tid)?, *want)));
        let Some((rec, want)) = check else {
            kept.push(p);
            continue;
        };
        // the true copy takes the slot; a slot's other copies are junk
        if osis_crypto::delta_hash(&dedup_secret(rec.nonce()), &p.delta) == want
            && let Ok(i) = blob.parts.binary_search_by_key(&(p.ai, p.di), |x| (x.ai, x.di))
            && let Some(slot) = blob.parts.get_mut(i)
        {
            *slot = p;
        }
    }
    spare.parts = kept;
    if !spare.signatures.is_empty()
        && let Some(CreationRecord::KeyActor { public_key, .. }) = record_of(tx, &h, &carried, &h.author)
    {
        let vk = VerifyingKey::from_slice(&public_key).map_err(|_| Error::BadInput("author key"))?;
        if let Some(s) = spare.signatures.iter().find(|s| osis_commit::verify_signature(id, s, &vk).is_ok()) {
            blob.signature = *s;
        }
        spare.signatures.clear();
    }
    Ok(())
}

/// Reads the boxes of the unsettled copies of pending commit `id`, as of its first ones: a true
/// `secrets.0` copy kept here may be what opens the record it waits for.
pub(super) fn read_boxes(tx: &mut Tx<'_>, id: &CommitId, blob: &CommitBlob) -> Result<()> {
    let spare = read(tx, id)?;
    if !spare.parts.is_empty() {
        let copies = CommitBlob { header: blob.header.clone(), signature: blob.signature, parts: spare.parts };
        super::keys::read_pending_boxes(tx, &copies, id)?;
    }
    Ok(())
}

/// Keeps only the copies of what still pends of `id`: its slots still in the pending blob.
pub(super) fn trim(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    let Some(Ok(blob)) = tx.txn.get_pending(id)?.map(|(_, b)| CommitBlob::decode(&b)) else { return clear(tx, id) };
    let mut spare = read(tx, id)?;
    spare.parts.retain(|p| blob.parts.binary_search_by_key(&(p.ai, p.di), |x| (x.ai, x.di)).is_ok());
    store(tx, id, &spare)
}
