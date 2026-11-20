//! A forgotten commit's name (spec/commits.md §5 Forgetting, Purge): a commit forgotten here whose
//! writes a held snapshot still carries keeps, per such aspect, its stamp and purge facts from its
//! header (`Name`), so a purge naming it by ID finds the copies (`Core::purge_item`) and a request
//! naming its stamp is judged by its own facts, as by its header (`purge::rejudge_carried`,
//! `check_request`). It goes once no held snapshot of the aspect carries a write stamped with it:
//! a held snapshot leaving (`atomic::forget_snapshot`) or the commit held again marks the aspect
//! (`Core::forgotten_names_due`), judged at the transaction's end (`settle_due`). Only a
//! value-carrying write not past its expiry keeps one: a purge acts on values alone, so a
//! removal's tombstone keeps none, nor an expired write held value-less. So names are bounded by the live values held snapshots carry; a dead write's goes with
//! the last snapshot holding it. Durable rows `records::FORGOTTEN_NAMES`; an ephemeral aspect's in memory, as its
//! data.
//!
//! Only the header binds an ID to a stamp: a node that never held it (a late joiner) has no name
//! and resolves no ID, though the request, naming the stamp, still reaches its copies there.
//! Rejected: snapshots carrying ID → stamp (the snapshot writer's word, so a writer could steer a
//! purge by ID onto another's write wherever the header is gone).

use super::purge::Target;
use crate::engine::records::{self, Rd, Wr};
use crate::engine::{Core, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, PurgeBy, Tid, Ts};
use osis_crdt::{Source, SourceKind};
use osis_store::Shred;
use std::collections::BTreeSet;

/// A forgotten commit's stamp and purge facts on one aspect, from its header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name {
    pub ts: Ts,
    /// Its own source (spec/crdt.md §2.1).
    pub src: Source,
    pub actor: Tid,
    pub by: PurgeBy,
    pub expires: Option<u64>,
}

impl Name {
    /// The delta it names on `(tid, ak)`, as a request judges it.
    pub(crate) fn target(&self, tid: Tid, ak: Ak) -> Target {
        Target { tid, ak, ts: self.ts, src: self.src.clone(), actor: self.actor, by: self.by, expires: self.expires, own_writes: true }
    }

    fn encode(&self) -> Vec<u8> {
        let w = Wr::new().u64(self.ts.to_u64()).u8(self.by as u8).raw(self.actor.as_bytes());
        let w = match self.expires {
            Some(e) => w.u8(1).u64(e),
            None => w.u8(0),
        };
        match self.src.kind() {
            SourceKind::Session(s) => w.u8(0).raw(&s.to_bytes()),
            SourceKind::Commit(c) => w.u8(1).raw(&c.0),
            // an own source is never derived
            SourceKind::Derived(_) => w.u8(2),
        }
        .take()
    }

    fn decode(b: &[u8]) -> Result<Name> {
        let bad = || Error::Corrupt("forgotten name");
        let mut r = Rd::new(b);
        let ts = Ts::from_u64(r.u64()?).ok_or_else(bad)?;
        let by = PurgeBy::from_id(r.u8()?.into()).ok_or_else(bad)?;
        let actor = r.tid()?;
        let expires = match r.u8()? {
            0 => None,
            1 => Some(r.u64()?),
            _ => return Err(bad()),
        };
        let src = match r.u8()? {
            0 => Source::session(osis_crdt::Session::from_bytes(&r.arr()?)),
            1 => Source::commit(CommitId(r.arr()?)),
            _ => return Err(bad()),
        };
        r.end()?;
        Ok(Name { ts, src, actor, by, expires })
    }
}

fn key(tid: &Tid, ak: &Ak, c: &CommitId) -> Vec<u8> {
    [records::aspect_key(records::FORGOTTEN_NAMES, tid, ak).as_slice(), &c.0].concat()
}

/// Commit `id`, being forgotten: a name on each aspect it has writes of its own on where a
/// snapshot is held (one may carry them; `settle_due` keeps it only if one does).
pub(crate) fn note(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    let Some((h, acting)) = tx.core.ix.commits.get(id).map(|m| (m.header.clone(), m.view.acting.clone())) else { return Ok(()) };
    // past its expiry a write has no value for a purge to act on
    if !h.kind.has_own_writes() || h.expires.is_some_and(|t| t <= tx.now().0) {
        return Ok(());
    }
    let src = h.form.own_source(h.signer, *id);
    for a in &h.aspects {
        let k = (a.tid, a.ak.clone());
        if tx.core.ix.snapshots.get(&k).is_none_or(|v| v.is_empty()) {
            continue;
        }
        // Interim (notes/a1-spec/README.md step 4): the purge author is the thing it acts on
        let Some(acting) = acting.on(&a.tid) else { continue };
        let n = Name { ts: h.ts, src: src.clone(), actor: acting, by: a.retention.by, expires: h.expires };
        let row = n.encode();
        tx.in_class(a.ak.ephemeral(), |tx| Ok(tx.txn.put_local(&key(&a.tid, &a.ak, id), &row, Shred::No)?))?;
        tx.core.ix.forgotten_names.insert(k.clone(), *id, n);
        tx.core.forgotten_names_due.insert(k);
    }
    Ok(())
}

/// The held snapshots of `(tid, ak)` changed: its names are judged at the transaction's end.
pub(crate) fn snapshots_moved(core: &mut Core, tid: &Tid, ak: &Ak) {
    let k = (*tid, ak.clone());
    if core.ix.forgotten_names.get(&k).is_some() {
        core.forgotten_names_due.insert(k);
    }
}

/// Commit `id` held again: its header decides from now on, its names go at the transaction's end.
pub(crate) fn held_again(core: &mut Core, id: &CommitId, aspects: &[crate::engine::AspectView]) {
    for a in aspects {
        let k = (a.tid, a.ak.clone());
        if core.ix.forgotten_names.get(&k).is_some_and(|m| m.contains_key(id)) {
            core.forgotten_names_due.insert(k);
        }
    }
}

/// The stamps `(ts, origin source)` of every value-carrying write (spec/crdt.md §4.7) the held
/// snapshots of `(tid, ak)` carry, value-less ones included, valid or not: one body read each. A
/// purge acts only on values, so a reset, flag, position write or value removal (a set
/// element's tombstone among them) needs no name.
fn carried(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<BTreeSet<(Ts, Source)>> {
    let snaps: Vec<CommitId> = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    let mut out = BTreeSet::new();
    for s in snaps {
        let Some(sai) = super::held_part(tx.core, &s, tid, ak) else { continue };
        let memory = tx.is_memory_commit(&s);
        tx.in_class(memory, |tx| {
            crate::apply::each_held_piece(tx, &s, sai, &mut |_, f| {
                let mut valued = BTreeSet::new();
                f.valueless_dots(&mut valued);
                f.each_valued(&mut |d| _ = valued.insert(d.clone()));
                out.extend(f.writes().into_iter().filter(|(d, _)| valued.contains(d)).filter_map(|(d, ts)| Some((ts?, osis_crdt::fact_source(&d.src)))));
                Ok(())
            })
        })?;
    }
    Ok(out)
}

/// Judges the names on the aspects marked this transaction: one goes once no held snapshot of
/// its aspect carries a write stamped with it, or its commit is held again.
pub(crate) fn settle_due(tx: &mut Tx<'_>) -> Result<()> {
    for (tid, ak) in std::mem::take(&mut tx.core.forgotten_names_due) {
        let names: Vec<(CommitId, Name)> = tx.core.ix.forgotten_names.get(&(tid, ak.clone())).map(|m| m.iter().map(|(c, n)| (*c, n.clone())).collect()).unwrap_or_default();
        if names.is_empty() {
            continue;
        }
        let carried = carried(tx, &tid, &ak)?;
        let now = tx.now().0;
        for (c, n) in names {
            if tx.core.ix.commits.contains_key(&c) || !carried.contains(&(n.ts, n.src.clone())) || n.expires.is_some_and(|t| t <= now) {
                drop_name(tx, &tid, &ak, &c)?;
            }
        }
    }
    Ok(())
}

fn drop_name(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId) -> Result<()> {
    tx.core.ix.forgotten_names.remove(&(*tid, ak.clone()), c);
    tx.in_class(ak.ephemeral(), |tx| Ok(tx.txn.remove_local(&key(tid, ak, c), Shred::Yes).map(|_| ())?))
}

/// Every name on `(tid, ak)` goes, as on a node that never held a part of it.
pub(crate) fn forget_aspect(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let cs: Vec<CommitId> = tx.core.ix.forgotten_names.get(&(*tid, ak.clone())).map(|m| m.keys().copied().collect()).unwrap_or_default();
    for c in cs {
        drop_name(tx, tid, ak, &c)?;
    }
    Ok(())
}

/// The names kept at the last stop.
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let mut rows = Vec::new();
    tx.scan(records::FORGOTTEN_NAMES, |k, v| {
        let mut r = Rd::new(k);
        let (tid, ak, c) = (r.tid()?, r.ak()?, CommitId(r.arr()?));
        r.end()?;
        rows.push(((tid, ak), c, Name::decode(&v)?));
        Ok(())
    })?;
    for (k, c, n) in rows {
        tx.core.ix.forgotten_names.insert(k, c, n);
    }
    Ok(())
}

impl Core {
    /// The name of forgotten commit `c` on `(tid, ak)`, if kept.
    pub(crate) fn forgotten_name(&self, c: &CommitId, tid: &Tid, ak: &Ak) -> Option<&Name> {
        self.ix.forgotten_names.get(&(*tid, ak.clone()))?.get(c)
    }

    /// The names on `(tid, ak)` stamped `ts` with own source `src`, as the deltas they name.
    pub(crate) fn forgotten_by_stamp(&self, tid: &Tid, ak: &Ak, ts: Ts, src: &Source) -> Vec<Target> {
        self.ix.forgotten_names.get(&(*tid, ak.clone())).into_iter().flatten().filter(|(_, n)| n.ts == ts && n.src == *src).map(|(_, n)| n.target(*tid, ak.clone())).collect()
    }

    /// Every name on `(tid, ak)`, as the deltas they name.
    pub(crate) fn forgotten_on(&self, tid: &Tid, ak: &Ak) -> Vec<Target> {
        self.ix.forgotten_names.get(&(*tid, ak.clone())).into_iter().flatten().map(|(_, n)| n.target(*tid, ak.clone())).collect()
    }
}
