//! The trust store (notes/disputes.md, Detection and sides): this node's sides in admin disputes,
//! durable in one local record (`records::SIDES`), fed to the walk as its trust set. With the
//! `osis` API the one home of dispute types outside osis-perm (the coherence rule;
//! tools/policy.py).
//!
//! A side is recorded once per dispute (R, holder): by default at detection, or by
//! `Engine::choose`. The default is held first (spec/permissions.md §5.1 Sides): R is trusted
//! iff the reading before the update that brought its dispute applied it. A node holds its own
//! writes first, so sides with itself. A recorded side stays until chosen otherwise; a trusted
//! write the walk cannot apply is void there.

use crate::engine::journal::{JMap, Journaled};
use crate::engine::{records, Core, Tx};
use crate::error::{Error, Result};
use crate::events::Event;
use osis_base::{CommitId, Tid, Value};
use osis_perm::WriteId;
use std::collections::{BTreeMap, BTreeSet};

/// The side taken in one dispute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Side {
    /// R (the author's removal) is trusted; else the walk's side (the holder's).
    pub trust: bool,
    /// Taken by `Engine::choose`, not by default.
    pub chosen: bool,
}

/// An open dispute as the engine reports it (`Engine::disputes`, `Event::DisputeDetected`):
/// `author`'s edge write `op` of `commit`, lowering `holder` on `target`, which held writes
/// `author` had not received void; trusting it turns that around.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisputeInfo {
    pub commit: CommitId,
    pub op: u32,
    pub holder: Tid,
    pub target: Tid,
    pub author: Tid,
    /// The side taken here, if any (none: the walk's, nothing recorded).
    pub side: Option<Side>,
}

/// The sides recorded per admin dispute, journaled (`Engine::run` persists them when the
/// transaction changed any).
#[derive(Clone, Default)]
pub struct Sides {
    map: JMap<(WriteId, Tid), Side>,
}

impl Sides {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Sides> {
        let bad = || Error::Corrupt("sides");
        let Some(Value::List(items)) = Value::from_bytes(bytes) else { return Err(bad()) };
        let mut map = JMap::default();
        for it in items {
            let Value::List(f) = it else { return Err(bad()) };
            match f.as_slice() {
                [Value::Bytes(c), Value::Int(op), holder @ Value::Bytes(_), Value::Int(flags)] => {
                    let commit = CommitId(c.as_slice().try_into().map_err(|_| bad())?);
                    let op = u32::try_from(*op).map_err(|_| bad())?;
                    let holder = Tid::from_bytes(holder.as_array().ok_or_else(bad)?);
                    map.insert((WriteId(commit, op), holder), Side { trust: flags & 1 == 1, chosen: flags & 2 == 2 });
                }
                _ => return Err(bad()),
            }
        }
        map.commit();
        Ok(Sides { map })
    }

    fn encode(&self) -> Vec<u8> {
        let items: Vec<Value> = self.map.iter().map(|((w, m), s)| Value::List(vec![Value::Bytes(w.0 .0.to_vec()), Value::Int(i64::from(w.1)), Value::bytes(m.as_bytes()), Value::Int(i64::from(s.trust) | i64::from(s.chosen) << 1)])).collect();
        Value::List(items).to_bytes()
    }

    /// The trust set: the ops of the sides that trust R.
    pub(crate) fn trust(&self) -> BTreeSet<WriteId> {
        self.map.iter().filter(|(_, s)| s.trust).map(|(k, _)| k.0).collect()
    }

    pub(crate) fn get(&self, op: WriteId, holder: Tid) -> Option<Side> {
        self.map.get(&(op, holder)).copied()
    }

    fn set(&mut self, op: WriteId, holder: Tid, side: Side) {
        self.map.insert((op, holder), side);
    }

    /// The journals' lengths (`Core::rollback_to`).
    pub(crate) fn journaled(&self) -> usize {
        self.map.journaled()
    }

    /// Whether the running transaction changed a side.
    fn changed(&self) -> bool {
        self.map.changed()
    }
}

impl Journaled for Sides {
    type Mark = usize;
    fn commit(&mut self) {
        self.map.commit();
    }
    fn mark(&mut self) -> usize {
        self.map.mark()
    }
    fn rollback_to(&mut self, m: usize) {
        self.map.rollback_to(m);
    }
    #[cfg(test)]
    fn contents(&self) -> String {
        self.map.contents()
    }
}

/// Records a default side for every dispute held after the timeline update that reported `c`
/// and not recorded yet (spec/permissions.md §5.1 Sides, Held first: trusted iff the reading
/// before the update applied it, other than as a may-grant grant; a lowering that came with the
/// update takes none), feeds the trust set to the walk when a side trusts, and reports each
/// (`Event::DisputeDetected`).
pub(crate) fn after_update(core: &mut Core, c: &osis_perm::Changed) {
    if c.ops.is_empty() {
        return;
    }
    let found = core.timelines_mut().aside().disputes();
    let mut trusts = false;
    for op in found {
        // Interim (notes/accounts-switch-brief.md): a dispute over a key's grant is told and
        // chosen once `signers.0` writes are built
        let Some((author, osis_base::Holder::Thing(holder), target)) = core.timelines().edge_op(&op) else { continue };
        if core.sides.get(op, holder).is_some() {
            continue;
        }
        let was = if c.ops.contains(&op) { c.was_applied.contains(&op) } else { core.timelines().is_applied(&op) };
        let trust = !c.fresh.contains(&op.0) && was && core.timelines().way(&op) != Some(osis_perm::paths::Way::MayGrant);
        core.sides.set(op, holder, Side { trust, chosen: false });
        trusts |= trust;
        core.events.queue(Event::DisputeDetected { commit: op.0, op: op.1, holder, target, author, trust });
    }
    if trusts {
        feed(core);
    }
}

/// After a rollback restored the sides: the walk's trust set follows them (the stale flags the
/// rollback clears; validity flags are restored with the commits).
pub(crate) fn restored(core: &mut Core) {
    let trust = core.sides.trust();
    core.timelines_mut().change(|t| t.set_trust(&trust));
}

/// Feeds the recorded sides to the walk as its trust set; the things whose validity may have
/// changed wait for `rejudge_all` as after any timeline change.
fn feed(core: &mut Core) {
    let trust = core.sides.trust();
    let changed = core.timelines_mut().change(|t| t.set_trust(&trust));
    core.timelines_changed(changed);
}

/// Writes the record when the running transaction changed the sides.
pub(crate) fn persist(tx: &mut Tx<'_>) -> Result<()> {
    if tx.core.sides.changed() {
        let bytes = tx.core.sides.encode();
        tx.txn.put_local(records::SIDES, &bytes, osis_store::Shred::No)?;
    }
    Ok(())
}

/// Reads the record at open and gives the walk its trust set before anything is evaluated.
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    if let Some(b) = tx.txn.get_local(records::SIDES)? {
        tx.core.sides = Sides::decode(&b)?;
        let trust = tx.core.sides.trust();
        if !trust.is_empty() {
            tx.core.timelines_mut().change(|t| t.set_trust(&trust));
        }
    }
    Ok(())
}

impl crate::engine::Engine {
    /// The disputes this node knows: the open ones (trusting a removal closes its dispute: the
    /// walk then applies it), and every side recorded whose removal is still held, each with the
    /// side taken here; at most `max` open ones are listed: (disputes, those left out). Reads a
    /// copy of the timeline (each candidate's trust is switched on and back).
    pub fn disputes(&self, max: usize) -> (Vec<DisputeInfo>, usize) {
        let mut out: BTreeMap<(WriteId, Tid), DisputeInfo> = BTreeMap::new();
        let mut tl: osis_perm::Timeline = (**self.core.timelines()).clone();
        let open = tl.disputes();
        let left = open.len().saturating_sub(max);
        for op in open.into_iter().take(max) {
            let Some((author, osis_base::Holder::Thing(holder), target)) = tl.edge_op(&op) else { continue };
            out.insert((op, holder), DisputeInfo { commit: op.0, op: op.1, holder, target, author, side: self.core.sides.get(op, holder) });
        }
        for ((op, holder), side) in self.core.sides.map.iter() {
            if out.contains_key(&(*op, *holder)) {
                continue;
            }
            if let Some((author, osis_base::Holder::Thing(h), target)) = tl.edge_op(op).filter(|x| x.1 == osis_base::Holder::Thing(*holder)) {
                out.insert((*op, *holder), DisputeInfo { commit: op.0, op: op.1, holder: h, target, author, side: Some(*side) });
            }
        }
        (out.into_values().collect(), left)
    }

    /// Takes a side in the dispute over edge write `op` of `commit` lowering `holder`: trust
    /// it (the author's side) or not (the walk's). Stays until chosen again. `UnknownCommit`
    /// when no held edge write is that.
    pub fn choose(&mut self, commit: CommitId, op: u32, holder: Tid, trust: bool) -> Result<()> {
        let w = WriteId(commit, op);
        if !self.core.timelines().edge_op(&w).is_some_and(|(_, h, _)| h == osis_base::Holder::Thing(holder)) {
            return Err(Error::UnknownCommit(commit));
        }
        self.run(|tx| {
            tx.core.sides.set(w, holder, Side { trust, chosen: true });
            feed(tx.core);
            crate::apply::atomic::rejudged(tx, true)?;
            Ok(())
        })
    }
    /// Takes the walk's side in every dispute held where this node trusts the author, as a user
    /// choosing it would (engine tests settling under the walk). How many sides changed.
    #[cfg(test)]
    pub(crate) fn take_walk_sides(&mut self) -> usize {
        let (ds, _) = self.disputes(usize::MAX);
        let trusted: Vec<DisputeInfo> = ds.into_iter().filter(|d| d.side.is_some_and(|s| s.trust)).collect();
        for d in &trusted {
            self.choose(d.commit, d.op, d.holder, false).unwrap_or_else(|e| panic!("choose: {e:?}"));
        }
        trusted.len()
    }
}
