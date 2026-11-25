//! The trust store (notes/disputes.md, Detection and sides): this node's sides in admin disputes,
//! durable in one local record (`records::SIDES`), fed to the walk as its trust set. With the
//! `osis` API the one home of dispute types outside osis-perm (the coherence rule;
//! tools/policy.py).
//!
//! A side is recorded per dispute (R, holder) by default or by `Engine::choose`
//! (spec/permissions.md §5.1 Sides): R trusted where this node made it (its own), or where an
//! update brought another party's seed of R while the reading before applied R (held first);
//! with no order between R and its seeds, nothing, the dispute only told. A recorded side stays
//! until chosen otherwise; a trusted write the walk cannot apply is void there.

use crate::engine::journal::{JMap, Journaled};
use crate::engine::{records, Core, Tx};
use crate::error::{Error, Result};
use crate::events::{Event, Origin};
use osis_base::{CommitId, Holder, Tid, Value};
use crate::engine::index::Rec;
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
    /// A thing, or a key (a dispute over a key's grant, spec/permissions.md §2 Key grants).
    pub holder: Holder,
    pub target: Tid,
    pub author: Tid,
    /// The side taken here, if any (none: the walk's, nothing recorded).
    pub side: Option<Side>,
}

/// The sides recorded per admin dispute, journaled (`Engine::run` persists them when the
/// transaction changed any). `None`: the dispute was told and no side is recorded (no order).
#[derive(Clone, Default)]
pub struct Sides {
    map: JMap<(WriteId, Holder), Option<Side>>,
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
                    let holder = <Holder as Rec>::from(holder).ok_or_else(bad)?;
                    let side = (flags & 4 == 0).then_some(Side { trust: flags & 1 == 1, chosen: flags & 2 == 2 });
                    map.insert((WriteId(commit, op), holder), side);
                }
                _ => return Err(bad()),
            }
        }
        map.commit();
        Ok(Sides { map })
    }

    fn encode(&self) -> Vec<u8> {
        let flags = |s: &Option<Side>| s.map_or(4, |s| i64::from(s.trust) | i64::from(s.chosen) << 1);
        let items: Vec<Value> = self.map.iter().map(|((w, m), s)| Value::List(vec![Value::Bytes(w.0 .0.to_vec()), Value::Int(i64::from(w.1)), m.to(), Value::Int(flags(s))])).collect();
        Value::List(items).to_bytes()
    }

    /// The trust set: the ops of the sides that trust R.
    pub(crate) fn trust(&self) -> BTreeSet<WriteId> {
        self.map.iter().filter(|(_, s)| s.is_some_and(|s| s.trust)).map(|(k, _)| k.0).collect()
    }

    /// The sides that trust R, each with its holder.
    pub(crate) fn trusted(&self) -> Vec<(WriteId, Holder)> {
        self.map.iter().filter(|(_, s)| s.is_some_and(|s| s.trust)).map(|(k, _)| *k).collect()
    }

    /// The side recorded in dispute (R, holder).
    pub(crate) fn get(&self, op: WriteId, holder: Holder) -> Option<Side> {
        self.map.get(&(op, holder)).copied().flatten()
    }

    /// Whether dispute (R, holder) was told.
    fn told(&self, op: WriteId, holder: Holder) -> bool {
        self.map.contains_key(&(op, holder))
    }

    fn set(&mut self, op: WriteId, holder: Holder, side: Option<Side>) {
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

/// Records the default side of every dispute held after the timeline update that reported `c`
/// that has no side recorded (spec/permissions.md §5.1 Sides), feeds the trust set to the walk
/// when one trusts, and reports each dispute once (`Event::DisputeDetected`). R is trusted when
/// this node made it (Its own: decided at the first update where trusting it matters, which
/// reads as recording it when made), or when the update brought another party's seed of R and
/// the reading before applied R, other than as a may-grant grant (Held first); else nothing is
/// recorded (No order), and a later update bringing a seed may still record it.
pub(crate) fn after_update(core: &mut Core, c: &osis_perm::Changed) {
    if c.ops.is_empty() {
        return;
    }
    let found = core.timelines_mut().aside().disputes();
    let mut trusts = false;
    for op in found {
        let Some((author, holder, target)) = core.timelines().edge_op(&op) else { continue };
        if core.sides.get(op, holder).is_some() {
            continue;
        }
        // Invariant: only `apply::apply_local` (a commit this engine built) gives `Local`, and it
        // is kept in the commit's record, so a reopened node reads its own alike; a copy of
        // its commit reaching it from outside is another party's (Its own). Read lazily, it
        // stands for a record made when R was made only while nothing drops an unchosen record
        // ("cannot stand beside", not read: notes/perm-paths.md); once that is built, record own
        // lowerings at commit instead.
        let own = core.ix.commits.get(&op.0).is_some_and(|m| m.origin == Origin::Local);
        let trust = own || held_first(core, c, op);
        let told = core.sides.told(op, holder);
        if trust || !told {
            core.sides.set(op, holder, trust.then_some(Side { trust, chosen: false }));
        }
        trusts |= trust;
        if !told {
            core.events.queue(Event::DisputeDetected { commit: op.0, op: op.1, holder, target, author, trust });
        }
    }
    if trusts {
        feed(core);
    }
}

/// Held first (spec/permissions.md §5.1 Sides): the update `c` brought a commit of another party
/// that is a seed of R (`op`), held before as R was, and the reading before applied R other than
/// as a may-grant grant.
fn held_first(core: &mut Core, c: &osis_perm::Changed, op: WriteId) -> bool {
    if c.fresh.contains(&op.0) || core.timelines().way(&op) == Some(osis_perm::paths::Way::MayGrant) {
        return false;
    }
    let was = if c.ops.contains(&op) { c.was_applied.contains(&op) } else { core.timelines().is_applied(&op) };
    if !was {
        return false;
    }
    let seeds = core.timelines_mut().aside().seed_commits(&op);
    seeds.iter().any(|s| c.fresh.contains(s) && core.ix.commits.get(s).is_some_and(|m| m.origin == Origin::Remote))
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
        let mut out: BTreeMap<(WriteId, Holder), DisputeInfo> = BTreeMap::new();
        let mut tl: osis_perm::Timeline = (**self.core.timelines()).clone();
        let open = tl.disputes();
        let left = open.len().saturating_sub(max);
        for op in open.into_iter().take(max) {
            let Some((author, holder, target)) = tl.edge_op(&op) else { continue };
            out.insert((op, holder), DisputeInfo { commit: op.0, op: op.1, holder, target, author, side: self.core.sides.get(op, holder) });
        }
        for ((op, holder), side) in self.core.sides.map.iter() {
            if out.contains_key(&(*op, *holder)) {
                continue;
            }
            if let Some((author, h, target)) = tl.edge_op(op).filter(|x| x.1 == *holder) {
                out.insert((*op, *holder), DisputeInfo { commit: op.0, op: op.1, holder: h, target, author, side: *side });
            }
        }
        (out.into_values().collect(), left)
    }

    /// Records `ws` as trusted, as this node's own sides (a pairer's trust records,
    /// spec/permissions.md §8 Pairing), feeds the walk and judges again.
    pub(crate) fn adopt_trust(&mut self, ws: &[(WriteId, Holder)]) -> Result<()> {
        self.run(|tx| {
            for (w, h) in ws {
                tx.core.sides.set(*w, *h, Some(Side { trust: true, chosen: true }));
            }
            feed(tx.core);
            crate::apply::atomic::rejudged(tx, true).map(drop)
        })
    }

    /// Takes a side in the dispute over edge write `op` of `commit` lowering `holder`: trust
    /// it (the author's side) or not (the walk's). Stays until chosen again. `UnknownCommit`
    /// when no held edge write is that.
    pub fn choose(&mut self, commit: CommitId, op: u32, holder: Holder, trust: bool) -> Result<()> {
        let w = WriteId(commit, op);
        if !self.core.timelines().edge_op(&w).is_some_and(|(_, h, _)| h == holder) {
            return Err(Error::UnknownCommit(commit));
        }
        self.run(|tx| {
            tx.core.sides.set(w, holder, Some(Side { trust, chosen: true }));
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::flows::Demotion;
    use crate::local_peer::LocalPeer;
    use crate::rotation::tests::{edge, synced, target_thing};
    use osis_base::{Role, Tid};

    /// Admins H (peer 1) and X (peer 2) of g (peer 0's); X removes H, every peer holding it.
    fn removed_h() -> (LocalPeer, Tid, Vec<Tid>) {
        let mut lp = synced(3);
        let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
        let g = target_thing(&mut lp, 0);
        for i in [1, 2] {
            lp.peers[0].engine.grant(&g, &tids[i], &edge(Role::Admin)).unwrap();
        }
        lp.sync_all().unwrap();
        lp.advance(1_000);
        lp.peers[2].engine.demote(&g, &Demotion { holder: tids[1], new: None, retain: None }).unwrap();
        lp.sync_all().unwrap();
        (lp, g, tids)
    }

    // spec/permissions.md §5.1 Sides (Its own; No order): H, holding X's removal of it, writes its
    // counter-removal of X, its list leaving X's removal out (The list). H records its own
    // lowering trusted, so its seeds take X's removal and H stands. Peer 0 held X's removal
    // before H's: it records nothing, the dispute told with no side, and reads the walk's side.
    // As roles-model `a_remover_sides_with_its_own_removal`.
    #[test]
    fn a_remover_sides_with_its_own_counter_removal_spec_permissions_5_1() {
        let (mut lp, g, tids) = removed_h();
        assert!(!lp.peers[1].engine.roster(&g).contains_key(&tids[1]), "H removed at H");
        lp.advance(1_000);
        // the writer's check refuses a removed admin's lowering: written past it
        let mut m = crate::Mutation::new();
        lp.peers[1].engine.run(|tx| crate::flows::edges::removal(tx, &mut m, g, tids[2])).unwrap();
        m.frontier(osis_perm::Frontier::new(Vec::<osis_base::CommitId>::new()));
        m.unchecked();
        lp.peers[1].engine.core.skip_writer_rules = true;
        lp.peers[1].commit(m).unwrap().unwrap();
        lp.peers[1].engine.core.skip_writer_rules = false;
        let e = &mut lp.peers[1].engine;
        let r = e.roster(&g);
        assert!(r.contains_key(&tids[1]) && !r.contains_key(&tids[2]), "H sides with its own removal: {r:?}");
        let (ds, _) = e.disputes(64);
        assert!(ds.iter().any(|d| d.author == tids[1] && d.side.is_some_and(|s| s.trust)), "{ds:?}");
        lp.sync_all().unwrap();
        let r = lp.peers[0].engine.roster(&g);
        assert!(!r.contains_key(&tids[1]) && r.contains_key(&tids[2]), "peer 0: the walk's side: {r:?}");
        let (ds, _) = lp.peers[0].engine.disputes(64);
        assert!(ds.iter().any(|d| d.author == tids[1] && d.side.is_none()), "no order, no side: {ds:?}");
    }
}
