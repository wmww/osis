//! Parts held while their commit waits (spec/commits.md §5): past their expiry they go, named by a
//! held purge request they are held value-less.

use crate::engine::DropFor;
use super::{T_EXPIRY, drop_part_for, known_purged, make_valueless, suspect};
use crate::engine::records;
use crate::engine::Tx;
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid};
use osis_commit::{Decoded, Header};
use osis_crdt::Fragment;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// Whether part `ai` of a commit (header `h`), held while it waits, is past its expiry: it goes
/// from the node (spec/commits.md §5).
pub(crate) fn pending_expired(tx: &Tx<'_>, h: &Header, ai: usize) -> bool {
    h.aspects.get(ai).is_some_and(|a| a.expires.is_some_and(|t| t <= tx.now().0))
}

/// Parts of commit `id` held pending (stored as `blob`, header `h`) whose expiry has passed count
/// as never received (spec/commits.md §5: no copy past T): they leave the stored copy before it
/// is kept, and their aspects are flagged suspect (`suspect`: their non-value writes never join
/// here, where a node that applied them before T keeps them). The others get a timer doing the
/// same at T (`hold_valueless`). One a held purge request names is held value-less instead
/// (`strip_purged`), as an applied one is: the request is a held commit, so nodes holding the same
/// commits read alike; one applied later wakes the commit (`on_apply`). A header whose aspects
/// are not resolved yet is judged once they are. The commit's other parts apply when they would
/// have with the part held, but a part past its expiry never decides that
/// (`apply::waits_without_expired`): a commit left with no part waits for its things like one with
/// a held part (`apply::examine`).
pub(crate) fn pending_drops(tx: &mut Tx<'_>, id: &CommitId, blob: &mut osis_commit::CommitBlob, h: &Header) -> Result<()> {
    let ais: BTreeSet<usize> = blob.parts.iter().map(|p| p.ai).collect();
    for ai in ais {
        let Some(a) = h.aspects.get(ai) else { continue };
        if pending_expired(tx, h, ai) {
            blob.parts.retain(|p| p.ai != ai);
            strip_pending(tx, id, ai, true)?;
            suspect::raise(tx, &a.tid, &a.ak, suspect::Why::PendingExpiry, &[(*id, ai)])?;
            continue;
        }
        if let Some(t) = a.expires {
            tx.put_timer(t, id, ai, T_EXPIRY)?;
        }
        if !known_purged(tx, h, id, ai)? {
            continue;
        }
        if h.ephemeral.is_some() {
            // a memory delta purged vanishes whole (`memory::vanish`), as if never received
            blob.parts.retain(|p| p.ai != ai);
            strip_pending(tx, id, ai, false)?;
        } else {
            strip_purged(tx, id, blob, h, ai)?;
        }
    }
    Ok(())
}

/// The parts of aspect `ai` of pending commit `id` (in `blob`, header `h`) that a held purge
/// request names: held value-less from now on (spec/commits.md §5). Each is checked and decoded
/// as `apply::examine` would, its value-carrying writes stripped (spec/crdt.md §4.7) and the
/// result kept (`records::STRIPPED`); its slot in `blob` and the stored copy holds an empty delta
/// (`emptied`). `examine` joins the kept delta in its place, and `stripped_joined` drops it once
/// joined, as a purge drops an applied part. One not readable yet (its thing's record or a page
/// away) waits as received and is stripped once it is; a bad one is `examine`'s. A snapshot has
/// no values of its own: kept whole, dropped once applied (`purge_one`), as is an import a request
/// reaches only through another import of its origin (`drop_gone`).
fn strip_purged(tx: &mut Tx<'_>, id: &CommitId, blob: &mut osis_commit::CommitBlob, h: &Header, ai: usize) -> Result<()> {
    let o = super::writes_of(tx.core, h, id, ai);
    if o.is_empty() {
        return Ok(());
    }
    let Some(dedup) = h.aspects.get(ai).and_then(|a| tx.core.dedup(&a.tid)) else { return Ok(()) };
    let mut done = BTreeSet::new();
    for p in blob.parts.iter_mut().filter(|p| p.ai == ai && p.delta != emptied()) {
        let mut interner = osis_crdt::Interner::new();
        let mut blobs = crate::engine::blobs::TxBlobs::new(&mut tx.txn);
        let mut reader = osis_label::BlobReader::new(&dedup, &mut blobs);
        let Ok(Decoded::Delta(mut d)) = osis_commit::verify_part(h, id, p, &dedup, &mut interner, Some(&mut reader)) else { continue };
        d.fragment.strip(&|x| o.iter().any(|y| y.owns(x)));
        let v = [&d.nonce[..], &crate::engine::state::encode(&d.fragment)?].concat();
        tx.txn.put_local(&records::stripped_key(id, ai, p.di), &v, Shred::No)?;
        p.delta = emptied();
        done.insert(p.di);
    }
    if done.is_empty() {
        return Ok(());
    }
    tx.core.touch();
    // node-sync forgets the blobs holding it (`Engine::spent_copy`)
    tx.core.mark_changed(*id);
    // the stored copy, shredded
    if tx.core.ix.pending.contains_key(id)
        && let Some((kind, bytes)) = tx.txn.get_pending(id)?
        && let Ok(mut b) = osis_commit::CommitBlob::decode_stored(&bytes)
    {
        for p in b.parts.iter_mut().filter(|p| p.ai == ai && done.contains(&p.di)) {
            p.delta = emptied();
        }
        tx.txn.remove_pending(id, Shred::Yes)?;
        tx.txn.put_pending(id, kind, &b.encode())?;
    }
    Ok(())
}

/// The parts of aspect `ai` waiting in the stored pending copy of applied commit `c` (aside), a
/// purge request naming them just applied (`purge_one`): held as `pending_drops` holds them.
pub(super) fn purge_pending(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    let Some(h) = tx.core.ix.commits.get(c).map(|m| (*m.header).clone()).filter(|_| tx.core.ix.pending.contains_key(c)) else { return Ok(()) };
    if h.ephemeral.is_some() {
        return strip_pending(tx, c, ai, false);
    }
    let Some((_, bytes)) = tx.txn.get_pending(c)? else { return Ok(()) };
    let Ok(mut blob) = osis_commit::CommitBlob::decode_stored(&bytes) else { return Ok(()) };
    strip_purged(tx, c, &mut blob, &h, ai)
}

/// What the slot of a part held value-less holds in the pending copy (`strip_purged`): an empty
/// delta, which never hashes to a header entry.
pub(crate) fn emptied() -> Vec<u8> {
    osis_base::encode(&osis_base::Value::List(Vec::new()))
}

/// The stripped deltas kept for pending commit `id` (`strip_purged`), by slot.
pub(crate) fn stripped_of(tx: &mut Tx<'_>, id: &CommitId) -> Result<BTreeMap<(usize, usize), Decoded>> {
    let mut out = BTreeMap::new();
    tx.scan(&[records::STRIPPED, &id.0[..]].concat(), |k, v| {
        let (Some(ai), Some(di)) = (k.get(..4), k.get(4..8)) else { return Err(Error::Corrupt("stripped key")) };
        let (Some(n), Some(f)) = (v.get(..osis_crdt::NONCE_LEN), v.get(osis_crdt::NONCE_LEN..)) else { return Err(Error::Corrupt("stripped delta")) };
        let d = osis_crdt::Delta { nonce: n.try_into().map_err(|_| Error::Corrupt("stripped delta"))?, fragment: crate::engine::state::decode(f)? };
        let slot = |b: &[u8]| b.try_into().map(|x| u32::from_be_bytes(x) as usize).map_err(|_| Error::Corrupt("stripped key"));
        out.insert((slot(ai)?, slot(di)?), Decoded::Delta(d));
        Ok(())
    })?;
    Ok(out)
}

/// Whether slot `(ai, di)` of pending commit `id` is held value-less (`strip_purged`).
pub(crate) fn is_stripped(tx: &mut Tx<'_>, id: &CommitId, ai: usize, di: usize) -> Result<bool> {
    Ok(tx.txn.get_local(&records::stripped_key(id, ai, di))?.is_some())
}

/// Forgets the stripped deltas kept for aspect `ai` of `id` (every aspect: `None`).
pub(crate) fn forget_stripped(tx: &mut Tx<'_>, id: &CommitId, ai: Option<usize>) -> Result<()> {
    let prefix = [records::STRIPPED, &id.0[..], &ai.map(|x| (x as u32).to_be_bytes().to_vec()).unwrap_or_default()].concat();
    let mut keys = Vec::new();
    tx.scan(&prefix, |k, _| {
        keys.push([&prefix[..], k].concat());
        Ok(())
    })?;
    for k in keys {
        tx.txn.remove_local(&k, Shred::Yes)?;
    }
    Ok(())
}

/// The parts of commit `id` just joined from stripped deltas (`strip_purged`: aspect, fragment):
/// held value-less and dropped, as a purge leaves an applied part, the stripped deltas their
/// residue; their kept records go. A purge that fell while they waited is judged again next
/// (`rejudge_purges`).
pub(crate) fn stripped_joined(tx: &mut Tx<'_>, id: &CommitId, joined: &[(usize, Fragment)], changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let ais: BTreeSet<usize> = joined.iter().map(|x| x.0).collect();
    for ai in ais {
        let kept: Vec<Fragment> = joined.iter().filter(|x| x.0 == ai).map(|x| x.1.clone()).collect();
        if let Some(k) = make_valueless(tx, id, ai, &kept)? {
            changed.insert(k);
        }
        drop_part_for(tx, id, ai, DropFor::Purge)?;
        forget_stripped(tx, id, Some(ai))?;
        if let Some(h) = tx.core.ix.commits.get(id).map(|m| m.header.clone())
            && let Some(a) = h.aspects.get(ai)
            && !known_purged(tx, &h, id, ai)?
        {
            tx.core.stale_things.insert(a.tid);
        }
    }
    Ok(())
}

/// Part `ai` of the stored pending copy of `c` (waiting or parked), if any, goes (`pending_drops`,
/// `hold_valueless`), flagged suspect (`flag`); node-sync then forgets the blobs holding it
/// (`mark_changed`).
pub(super) fn strip_pending(tx: &mut Tx<'_>, c: &CommitId, ai: usize, flag: bool) -> Result<()> {
    // also of a commit no longer pending: `apply::pend_aside` judges its parts after `unpend`
    forget_stripped(tx, c, Some(ai))?;
    if !tx.core.ix.pending.contains_key(c) {
        return Ok(());
    }
    let Some((kind, bytes)) = tx.txn.get_pending(c)? else { return Ok(()) };
    let Ok(mut blob) = osis_commit::CommitBlob::decode_stored(&bytes) else { return Ok(()) };
    let n = blob.parts.len();
    blob.parts.retain(|p| p.ai != ai);
    if blob.parts.len() == n {
        return Ok(());
    }
    tx.core.touch();
    tx.core.mark_changed(*c);
    tx.txn.remove_pending(c, Shred::Yes)?;
    tx.txn.put_pending(c, kind, &blob.encode())?;
    // examined again: what it waits for may have changed
    tx.core.waits.pended(c);
    if flag && let Some(a) = blob.header.aspects.get(ai) {
        suspect::raise(tx, &a.tid, &a.ak, suspect::Why::PendingExpiry, &[(*c, ai)])?;
    }
    Ok(())
}
