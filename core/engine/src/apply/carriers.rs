//! What carries a pending commit (spec/commits.md §4 Pending storage): per commit that pends
//! here, or holds a part that waits, the set of its carriers, persisted with it: an entry of it
//! in the sync store, a fire held here that carries it, the newest stranded report on a sync ID
//! whose holder keys carry it.
//!
//! Invariant: at the end of every durable storage transaction, a commit pends here only while
//! its carrier set is not empty, and a commit pending no more has none. Every path taking a
//! commit names what it came from (`taken`): `Engine::ingest` and its siblings an entry, which
//! sync (or a test standing in for it) lets go with `Engine::release_entry`; `ingest_valid` a
//! fire, a report or nothing. A carrier goes in one place each: an entry by `release_entry`
//! (sync's `store::follow::release`, once no entry in its store names a blob of the commit); a
//! fire with its commit (`fire_gone`, from `apply::unindex`); a report when a newer one on its
//! sync ID is taken (`report_taken`) or its holder or actor goes (`reports_gone`, beside the
//! re-seal asks). The transaction where the last goes, or that took the commit from nothing,
//! forgets its pending copy (`settle`): its parts count as never received.
//!
//! Who supplies a carrier: an entry, any peer, within its unvouched budget (spec/sync-ids.md §5);
//! a fire, anyone holding the inbox's public key record (a stranger), within the inbox's deposit
//! budget while unpromoted and the inbox's history setting once held; a report, anyone, but it
//! carries only what `take_holder_keys` takes along a current holder's chain, one report per
//! sync ID. Each carried commit is bytes of its carrier, so what pends for fires and reports is
//! bounded by the fires and reports held.

use crate::engine::Tx;
use crate::error::{Error, Result};
use osis_base::{CommitId, SyncId, Tid};
use osis_store::Shred;

/// `pc/` + commit ID + carrier (`Carrier::encode`): a carrier of a pending commit.
const CARRIERS: &[u8] = b"pc/";

/// One carrier of a pending commit (spec/commits.md §4 Pending storage).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Carrier {
    /// An entry in the sync store whose blob opened as the commit: the store says when the last
    /// goes (`Engine::release_entry`).
    Entry,
    /// A fire held here (by its commit) whose value carries the commit.
    Fire(CommitId),
    /// The newest stranded report taken on `sync_id` (a Stranded message), naming `holder`, a
    /// holder of `actor`, the sync ID's thing's independent: ordered by actor first, so an
    /// actor's reports are one range.
    Report { actor: Tid, sync_id: SyncId, holder: Tid },
}

impl Carrier {
    fn encode(&self) -> Vec<u8> {
        match self {
            Carrier::Entry => vec![0],
            Carrier::Fire(f) => [&[1u8][..], &f.0].concat(),
            Carrier::Report { actor, sync_id, holder } => [&[2u8][..], actor.as_bytes(), &sync_id.0, holder.as_bytes()].concat(),
        }
    }
    fn decode(v: &[u8]) -> Option<Carrier> {
        match v.split_first()? {
            (0, []) => Some(Carrier::Entry),
            (1, f) => Some(Carrier::Fire(CommitId(f.try_into().ok()?))),
            (2, r) if r.len() == 46 => Some(Carrier::Report { actor: Tid::from_bytes(r.get(..15)?.try_into().ok()?), sync_id: SyncId(r.get(15..31)?.try_into().ok()?), holder: Tid::from_bytes(r.get(31..)?.try_into().ok()?) }),
            _ => None,
        }
    }
    /// Whether it is followed by what it is (`Indexes::carrying`): a fire or a report.
    fn followed(&self) -> bool {
        !matches!(self, Carrier::Entry)
    }
}

fn key(c: &CommitId, k: &Carrier) -> Vec<u8> {
    [CARRIERS, &c.0, &k.encode()].concat()
}

/// Loads the carriers (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || Error::Corrupt("pending carrier");
    let rows = tx.scan_rows(CARRIERS, |k, _| {
        let c = CommitId(k.get(..32).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        Ok((c, Carrier::decode(k.get(32..).ok_or_else(bad)?).ok_or_else(bad)?))
    })?;
    for (c, k) in rows {
        insert(tx, c, k);
    }
    Ok(())
}

fn insert(tx: &mut Tx<'_>, c: CommitId, k: Carrier) {
    tx.core.ix.carriers.insert(c, k);
    if k.followed() {
        tx.core.ix.carrying.insert(k, c);
    }
}

/// Commit `c` was taken from `from` (`None`: from nothing): a carrier of it while it pends here,
/// judged at the transaction's end (`settle`). A fire carries only while its commit is held.
pub(crate) fn taken(tx: &mut Tx<'_>, c: &CommitId, from: Option<Carrier>) -> Result<()> {
    tx.core.carriers_due.insert(*c);
    let Some(k) = from else { return Ok(()) };
    if !tx.core.ix.pending.contains_key(c) || tx.core.ix.carriers.contains(c, &k) {
        return Ok(());
    }
    if let Carrier::Fire(f) = k
        && !tx.core.ix.commits.contains_key(&f)
    {
        return Ok(());
    }
    insert(tx, *c, k);
    tx.txn.put_local(&key(c, &k), &[], Shred::No)?;
    Ok(())
}

/// Carrier `k` of `c` goes; `c` is judged at the transaction's end (`settle`).
fn remove(tx: &mut Tx<'_>, c: &CommitId, k: &Carrier) -> Result<()> {
    tx.core.carriers_due.insert(*c);
    if !tx.core.ix.carriers.remove(c, k) {
        return Ok(());
    }
    if k.followed() {
        tx.core.ix.carrying.remove(k, c);
    }
    tx.txn.remove_local(&key(c, k), Shred::No)?;
    Ok(())
}

/// Commit `id` is forgotten: it carries nothing as a fire any more.
pub(crate) fn fire_gone(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    let k = Carrier::Fire(*id);
    let carried: Vec<CommitId> = tx.core.ix.carrying.get(&k).into_iter().flatten().copied().collect();
    for c in carried {
        remove(tx, &c, &k)?;
    }
    Ok(())
}

/// `actor`'s reports and what each carries, in order.
fn reports_of(tx: &Tx<'_>, actor: &Tid) -> Vec<(Carrier, CommitId)> {
    let lo = Carrier::Report { actor: *actor, sync_id: SyncId([0; 16]), holder: Tid::from_bytes([0; 15]) };
    let hi = Carrier::Report { actor: *actor, sync_id: SyncId([0xff; 16]), holder: Tid::from_bytes([0xff; 15]) };
    tx.core.ix.carrying.range(lo..=hi).flat_map(|(k, cs)| cs.iter().map(|c| (*k, *c))).collect()
}

/// Report `k` was taken, carrying `ids`: it replaces every earlier report on its sync ID (spec/commits.md
/// §4 Pending storage: the newest per sync ID), and what `k` itself carried before that it does
/// not carry now.
pub(crate) fn report_taken(tx: &mut Tx<'_>, k: &Carrier, ids: &std::collections::BTreeSet<CommitId>) -> Result<()> {
    let Carrier::Report { actor, sync_id, .. } = k else { return Ok(()) };
    for (x, c) in reports_of(tx, actor) {
        let Carrier::Report { sync_id: s, .. } = x else { continue };
        if s == *sync_id && (x != *k || !ids.contains(&c)) {
            remove(tx, &c, &x)?;
        }
    }
    Ok(())
}

/// `actor`'s reports naming a holder `keep` refuses go (beside its re-seal asks,
/// `sync::stranded::drop_asks`: a holder no longer current, every one once this node loses the
/// actor).
pub(crate) fn reports_gone(tx: &mut Tx<'_>, actor: &Tid, keep: &impl Fn(&Tid) -> bool) -> Result<()> {
    for (x, c) in reports_of(tx, actor) {
        if let Carrier::Report { holder, .. } = x
            && !keep(&holder)
        {
            remove(tx, &c, &x)?;
        }
    }
    Ok(())
}

/// Carrier `Entry` of `c` goes (no entry in the store names a blob of it any more).
pub(crate) fn entry_gone(tx: &mut Tx<'_>, c: &CommitId) -> Result<()> {
    remove(tx, c, &Carrier::Entry)
}

/// Judges the commits whose carriers moved or that were taken or stopped pending this
/// transaction: one pending with no carrier is forgotten, as never received (`forget`); one
/// pending no more loses its carriers. Run to a fixpoint: forgetting stops it pending.
pub(crate) fn settle(tx: &mut Tx<'_>) -> Result<()> {
    while let Some(c) = tx.core.carriers_due.pop_first() {
        if tx.core.ix.pending.contains_key(&c) {
            if !tx.core.ix.carriers.contains_key(&c) {
                forget(tx, &c)?;
            }
            continue;
        }
        let ks: Vec<Carrier> = tx.core.ix.carriers.get(&c).into_iter().flatten().copied().collect();
        for k in ks {
            remove(tx, &c, &k)?;
        }
        tx.core.carriers_due.remove(&c);
    }
    Ok(())
}

/// Drops the stored pending copy of durable commit `id` (a pending or parked commit, or an
/// applied one's parts that wait alone): its last carrier left, or it came from none. Its parts
/// count as never received; the next carrier bringing it brings it back. A memory commit's copy
/// is the memory lane's, and stays. Whether there was one.
pub(crate) fn forget(tx: &mut Tx<'_>, id: &CommitId) -> Result<bool> {
    let Some(osis_store::Pending { bytes, .. }) = tx.txn.get_pending(id)? else { return Ok(false) };
    let blob = osis_commit::CommitBlob::decode_stored(&bytes).ok();
    // what it writes on had something forgotten: a strong reaching it later pulls anew
    // (`Core::brought`)
    for a in blob.iter().flat_map(|b| &b.header.aspects) {
        tx.core.brought.remove(&a.tid);
    }
    let things: Vec<Tid> = blob.filter(|b| b.header.kind.is_role()).map(|b| b.header.aspects.iter().map(|a| a.tid).collect()).unwrap_or_default();
    super::drop_pending(tx, id)?;
    tx.core.waits.unawaits(id);
    super::keys::forget_unchecked(tx, id)?;
    // secrets read from its boxes go unless something else reads them
    crate::rotation::touch_held(tx, things);
    Ok(true)
}
