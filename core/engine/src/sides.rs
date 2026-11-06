//! The trust store (notes/owner-removal-plan.md step 4): this node's sides in admin disputes,
//! durable in one local record (`records::SIDES`), fed to the walk as its trust set. With the
//! `osis` API the one home of dispute types outside osis-perm (the coherence rule;
//! tools/policy.py).
//!
//! A side is recorded once per dispute (R, M): at detection by default (`default_side`), or by
//! `Engine::choose`. The default: the side this node's own standing exists on, when it exists
//! on one side only; else first received: R is trusted iff it applied here before the write
//! that voids it arrived (`Detected::stood`). A node that wrote R holds it first, so sides
//! with itself. A recorded side stays until chosen otherwise, so switching back and forth
//! returns to the same trust set; a trusted write the walk cannot apply is void there (a
//! shrink round per evaluation, and no fast path for a component a trusted op names: step 3's
//! cost, stated in notes/owner-removal-plan.md).

use crate::engine::{records, Core, Tx};
use crate::error::{Error, Result};
use crate::events::{Diagnostic, DiagnosticKind, Event};
use osis_base::{CommitId, Tid, Value};
use osis_perm::{Detected, Trust, WriteId};
use std::collections::BTreeMap;

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

/// The sides recorded, journaled per transaction.
#[derive(Default, Clone)]
pub struct Sides {
    map: BTreeMap<(WriteId, Tid), Side>,
    /// The map before the running transaction changed it (persisted and cleared by
    /// `Engine::run`, restored by a rollback).
    before: Option<BTreeMap<(WriteId, Tid), Side>>,
}

impl Sides {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Sides> {
        let bad = || Error::Corrupt("sides");
        let Some(Value::List(items)) = Value::from_bytes(bytes) else { return Err(bad()) };
        let mut map = BTreeMap::new();
        for it in items {
            let Value::List(f) = it else { return Err(bad()) };
            let [Value::Bytes(c), Value::Int(op), Value::Tid(holder), Value::Int(flags)] = f.as_slice() else { return Err(bad()) };
            let commit = CommitId(c.as_slice().try_into().map_err(|_| bad())?);
            let op = u32::try_from(*op).map_err(|_| bad())?;
            map.insert((WriteId(commit, op), *holder), Side { trust: flags & 1 == 1, chosen: flags & 2 == 2 });
        }
        Ok(Sides { map, before: None })
    }

    fn encode(&self) -> Vec<u8> {
        let items = self.map.iter().map(|((w, m), s)| Value::List(vec![Value::Bytes(w.0 .0.to_vec()), Value::Int(i64::from(w.1)), Value::Tid(*m), Value::Int(i64::from(s.trust) | i64::from(s.chosen) << 1)])).collect();
        Value::List(items).to_bytes()
    }

    /// The trust set: the ops of the sides that trust R.
    pub(crate) fn trust(&self) -> Trust {
        Trust { ops: self.map.iter().filter(|(_, s)| s.trust).map(|(k, _)| k.0).collect() }
    }

    pub(crate) fn get(&self, op: WriteId, holder: Tid) -> Option<Side> {
        self.map.get(&(op, holder)).copied()
    }

    fn set(&mut self, op: WriteId, holder: Tid, side: Side) {
        if self.before.is_none() {
            self.before = Some(self.map.clone());
        }
        self.map.insert((op, holder), side);
    }

    /// Ends the running transaction's changes: kept.
    pub(crate) fn commit(&mut self) {
        self.before = None;
    }

    /// Undoes the running transaction's changes.
    pub(crate) fn rollback(&mut self) {
        if let Some(b) = self.before.take() {
            self.map = b;
        }
    }
}

/// The default side of a newly detected dispute: the side this node's own standing exists on
/// when it exists on one side only, else first received (R trusted iff it stood here first).
fn default_side(d: &Detected) -> bool {
    match d.standing {
        (false, true) => true,
        (true, false) => false,
        _ => d.stood,
    }
}

/// Records a default side for every dispute the last timeline update detected and not recorded
/// yet, feeds the trust set to the walk when a side trusts, reports each (`Event::DisputeDetected`)
/// and the candidates left unexamined (`DiagnosticKind::DisputesUnexamined`).
pub(crate) fn after_update(core: &mut Core) {
    let (found, unexamined) = core.timelines.take_detected();
    let mut trusts = false;
    for d in found {
        let (op, holder) = (d.dispute.op, d.dispute.holder);
        if core.sides.get(op, holder).is_some() {
            continue;
        }
        let trust = default_side(&d);
        core.sides.set(op, holder, Side { trust, chosen: false });
        trusts |= trust;
        core.events.queue(Event::DisputeDetected { commit: op.0, op: op.1, holder, target: d.target, author: d.author, trust });
    }
    if trusts {
        feed(core);
    }
    if unexamined > 0 {
        let now = core.now();
        core.events.diagnostic(Diagnostic { kind: DiagnosticKind::DisputesUnexamined, tids: Vec::new(), commit: None, peer: None, detail: format!("{unexamined} contestable role writes arrived or stopped applying beyond what one update examines: the dispute list shows them, with no side taken by default") }, now);
    }
}

/// Feeds the recorded sides to the walk as its trust set; the things whose validity may have
/// changed wait for `rejudge_all` as after any timeline change.
fn feed(core: &mut Core) {
    let trust = core.sides.trust();
    let changed = core.timelines.set_trust(&core.ix.held, trust);
    core.timelines_changed(changed);
    core.role_changed();
}

/// Writes the record when the running transaction changed the sides.
pub(crate) fn persist(tx: &mut Tx<'_>) -> Result<()> {
    if tx.core.sides.before.is_some() {
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
            tx.core.timelines.set_trust(&tx.core.ix.held, trust);
        }
    }
    Ok(())
}

impl crate::engine::Engine {
    /// The open disputes in every held timeline, each with the side taken here, examining at
    /// most `max` candidates by a walk (a removed admin can sign any number; those past the
    /// bound are counted, not listed): (disputes, unexamined).
    pub fn disputes(&self, max: usize) -> (Vec<DisputeInfo>, usize) {
        let mut out = Vec::new();
        let mut left = 0;
        let mut budget = max;
        for tl in self.core.timelines.each() {
            let (ds, l) = tl.disputes_up_to(budget);
            budget = budget.saturating_sub(ds.len());
            left += l;
            for d in ds {
                let Some((author, holder, target)) = tl.edge_op(&d.op) else { continue };
                out.push(DisputeInfo { commit: d.op.0, op: d.op.1, holder, target, author, side: self.core.sides.get(d.op, d.holder) });
            }
        }
        (out, left)
    }

    /// Takes a side in the dispute over edge write `op` of `commit` lowering `holder`: trust
    /// it (the author's side) or not (the walk's). Stays until chosen again. `UnknownCommit`
    /// when no held edge write is that.
    pub fn choose(&mut self, commit: CommitId, op: u32, holder: Tid, trust: bool) -> Result<()> {
        let w = WriteId(commit, op);
        if !self.core.timelines.each().any(|tl| tl.edge_op(&w).is_some_and(|(_, h, _)| h == holder)) {
            return Err(Error::UnknownCommit(commit));
        }
        self.run(|tx| {
            tx.core.sides.set(w, holder, Side { trust, chosen: true });
            feed(tx.core);
            crate::apply::atomic::rejudged(tx, true)?;
            Ok(())
        })
    }
}
