//! Parts held while their commit waits (spec/commits.md §5): past their expiry they go, named by a
//! held purge request they are held value-less, what was stripped of them kept as the part's
//! leftover (`leftover`) until it joins.

use super::{T_EXPIRY, counts_as_purged, known_purged, leftover, make_leftover, suspect, writes_of};
use crate::engine::Tx;
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid};
use osis_commit::{Decoded, Header};
use osis_crdt::Fragment;
use osis_store::Shred;
use std::collections::BTreeSet;

/// Whether part `ai` of a commit (header `h`), held while it waits, is past its expiry: it goes
/// from the node (spec/commits.md §5).
pub(crate) fn pending_expired(tx: &Tx<'_>, h: &Header, ai: usize) -> bool {
    h.aspects.get(ai).and(h.expires).is_some_and(|t| t <= tx.now().0)
}

/// Parts of commit `id` held pending (stored as `blob`, header `h`) whose expiry has passed count
/// as never received (spec/commits.md §5: no copy past T): they leave the stored copy before it
/// is kept, and their aspects are flagged suspect (`suspect`: their non-value writes never join
/// here, where a node that applied them before T keeps them). The others get a timer doing the
/// same at T (`hold_valueless`). One a held purge request names is held value-less instead
/// (`strip_purged`), as an applied one is: the request is a held commit, so nodes holding the same
/// commits read alike; one applied later wakes the commit (`on_apply`). A header whose aspects
/// are not resolved yet is judged once they are.
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
        if let Some(t) = h.expires {
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
/// result joined into the part's leftover (`records::LEFTOVER`); its slot in `blob` and the
/// stored copy holds an empty delta (`emptied`). `examine` joins the leftover in its place, and
/// `stripped_joined` holds the part as it once joined, as a purge holds an applied part. One with
/// a page away, or parked (this build cannot read it), cannot be stripped: it goes, and its aspect
/// is flagged, its non-value writes joining only through a copy or a snapshot, as those of a part
/// missing when purged. Invariant: no part a held purge request names is held with its values. One with its thing's record away cannot occur: no right can stand
/// without it (`holds_right`), spec/commits.md §5 states the limit. A bad one is `examine`'s. A snapshot has
/// no values of its own: kept whole, dropped once applied (`purge_one`).
fn strip_purged(tx: &mut Tx<'_>, id: &CommitId, blob: &mut osis_commit::CommitBlob, h: &Header, ai: usize) -> Result<()> {
    let o = super::writes_of(h, id, ai);
    if o.is_empty() {
        return Ok(());
    }
    let Some(a) = h.aspects.get(ai) else { return Ok(()) };
    let Some(dedup) = tx.core.dedup(&a.tid) else { return Ok(()) };
    let (mut done, mut gone) = (BTreeSet::new(), BTreeSet::new());
    let mut kept: Option<Fragment> = leftover::get(tx, &a.tid, &a.ak, id, ai)?.map(|l| l.fragment);
    for p in blob.parts.iter_mut().filter(|p| p.ai == ai && p.delta != emptied()) {
        let mut interner = osis_crdt::Interner::new();
        let mut blobs = crate::engine::blobs::TxBlobs::new(&mut tx.txn);
        let mut paged = osis_label::BlobReader::new(&dedup, &mut blobs);
        let mut unpaged = osis_crdt::Unpaged;
        let reader: &mut dyn osis_crdt::PageSource = if h.ephemeral.is_some() { &mut unpaged } else { &mut paged };
        let mut d = match osis_commit::verify_part(h, id, p, &dedup, &mut interner, Some(reader)) {
            Ok(Decoded::Delta(d)) => d,
            // what cannot be stripped goes (spec/commits.md §5; parked: spec/versioning.md §2)
            Err(e) if crate::apply::is_missing_page(&e) || osis_base::Classified::class(&e) == osis_base::ErrorClass::Parked => {
                gone.insert(p.di);
                continue;
            }
            _ => continue,
        };
        d.fragment.strip(&|x| o.iter().any(|y| y.owns(x)));
        kept.get_or_insert_default().join(d.fragment);
        p.delta = emptied();
        done.insert(p.di);
    }
    if done.is_empty() && gone.is_empty() {
        return Ok(());
    }
    if let Some(f) = kept.filter(|_| !done.is_empty()) {
        leftover::put(tx, &a.tid, &a.ak, id, ai, &leftover::Leftover { fragment: f, gives: None })?;
    }
    blob.parts.retain(|p| !(p.ai == ai && gone.contains(&p.di)));
    if !gone.is_empty() {
        suspect::raise(tx, &a.tid, &a.ak, suspect::Why::Uncovered, &[(*id, ai)])?;
        tx.core.waits.pended(id);
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
        b.parts.retain(|p| !(p.ai == ai && gone.contains(&p.di)));
        tx.txn.remove_pending(id, Shred::Yes)?;
        tx.txn.put_pending(id, kind, &b.encode())?;
    }
    Ok(())
}

/// Commit `id` (header `h`) applies without parts `missing`. One a request names (`counts_as_purged`)
/// but does not drop may have gone with a page away, its request falling while the commit waited
/// (`strip_purged`): a live part, so node-sync fetches it (`Changed::undropped`).
pub(crate) fn fetch_fallen(tx: &mut Tx<'_>, h: &Header, id: &CommitId, missing: &BTreeSet<usize>) -> Result<()> {
    for ai in missing {
        if !known_purged(tx, h, id, *ai)? && counts_as_purged(tx, h, id, *ai)? {
            if let Some(ch) = &mut tx.core.changed {
                ch.undropped.insert(*id);
            }
            break;
        }
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

/// Whether part `ai` of commit `id`, whose stored pending copy is `pending`, is held value-less
/// while it waits (`strip_purged`): its slot there emptied, its leftover kept, the part not joined
/// (`Meta::stripped`). The emptied slot tells it from a leftover set aside at a fall for a missing
/// part of the applied commit (`unstrip`), which no copy of the part replaces until one joins.
pub(crate) fn waiting_stripped(tx: &mut Tx<'_>, pending: &osis_commit::CommitBlob, id: &CommitId, ai: usize) -> Result<bool> {
    if tx.core.ix.commits.get(id).is_some_and(|m| m.stripped.contains(&ai)) || !pending.parts.iter().any(|p| p.ai == ai && p.delta == emptied()) {
        return Ok(false);
    }
    let Some(a) = pending.header.aspects.get(ai) else { return Ok(false) };
    leftover::has(tx, &a.tid, &a.ak, id, ai)
}

/// Forgets the leftover kept for waiting part `ai` of commit `id` (header `h`) not yet applied.
/// An applied commit's goes only when a copy joins whole (`forget_joined_leftovers`): a stripped
/// part's is its body, and a missing part's (set aside at its purge's fall, or what a waiting part
/// was stripped to) is adopted when the part is held value-less again (`make_leftover`), at expiry
/// as on a rise, as at a node that held the part throughout.
fn forget_waiting_leftover(tx: &mut Tx<'_>, h: &Header, id: &CommitId, ai: usize) -> Result<()> {
    if tx.core.ix.commits.contains_key(id) {
        return Ok(());
    }
    let Some(a) = h.aspects.get(ai) else { return Ok(()) };
    leftover::remove(tx, &a.tid, &a.ak, id, ai)
}

/// Forgets the leftovers kept for parts `ais` of commit `id` (header `h`) that just joined whole
/// (a waiting part's, or one set aside at its purge's fall).
pub(crate) fn forget_joined_leftovers(tx: &mut Tx<'_>, h: &Header, id: &CommitId, ais: &BTreeSet<usize>) -> Result<()> {
    for ai in ais {
        if tx.core.ix.commits.get(id).is_some_and(|m| m.stripped.contains(ai)) {
            continue;
        }
        if let Some(a) = h.aspects.get(*ai) {
            leftover::remove(tx, &a.tid, &a.ak, id, *ai)?;
        }
    }
    Ok(())
}

/// Forgets every leftover kept for the parts of commit `id` not yet applied (`forget_waiting_leftover`).
pub(crate) fn forget_waiting_leftovers(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    let h = match tx.core.ix.commits.get(id) {
        Some(m) => (*m.header).clone(),
        None => match tx.txn.get_pending(id)?.and_then(|(_, b)| osis_commit::CommitBlob::decode_stored(&b).ok()) {
            Some(b) => b.header,
            None => return Ok(()),
        },
    };
    for ai in 0..h.aspects.len() {
        forget_waiting_leftover(tx, &h, id, ai)?;
    }
    Ok(())
}

/// The parts of commit `id` just joined from their leftovers (`strip_purged`: aspect, fragment):
/// held value-less as a purge leaves an applied part, the leftover their body. A purge that fell
/// while they waited is judged again next (`rejudge_purges`).
pub(crate) fn stripped_joined(tx: &mut Tx<'_>, id: &CommitId, joined: &[(usize, Fragment)], changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let ais: BTreeSet<usize> = joined.iter().map(|x| x.0).collect();
    for ai in ais {
        let kept: Vec<Fragment> = joined.iter().filter(|x| x.0 == ai).map(|x| x.1.clone()).collect();
        let Some(h) = tx.core.ix.commits.get(id).map(|m| m.header.clone()) else { continue };
        let own = writes_of(&h, id, ai);
        if let Some(k) = make_leftover(tx, id, ai, &own, &kept)? {
            changed.insert(k);
        }
        if let Some(a) = h.aspects.get(ai)
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
    if !tx.core.ix.pending.contains_key(c) {
        return Ok(());
    }
    let Some((kind, bytes)) = tx.txn.get_pending(c)? else { return Ok(()) };
    let Ok(mut blob) = osis_commit::CommitBlob::decode_stored(&bytes) else { return Ok(()) };
    forget_waiting_leftover(tx, &blob.header, c, ai)?;
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
