//! What waits for sync's word (spec/sync-status.md §1-§3): self-removals whose lost secrets drop
//! once sync is done waiting for the removal (spec/permissions.md §3 Lost access), and complete passes:
//! the sync IDs some rule waits on a pass of (`passes_wanted`), and the last pass noted per sync
//! ID, which the re-seal and history-add triggers and history completeness read.
//!
//! Passes and role arrivals are ordered by one count, the pass place (`Core::place`): a role
//! commit applied from elsewhere takes the next place, and so does each pass begun
//! (`Engine::begin_pass`). A pass counts for what arrived at place `n` only when it began at a
//! place above `n` (spec/permissions.md §3 Complete pass: a Pull sent before a commit arrived
//! ends no pass after it), whatever the clock reads.
//!
//! A rule that waits for a pass after its cause (a tied grant's explicit demotion, the
//! lost-access drop) waits for one begun after the place this node first judged the cause at
//! (`Cause`), not after the newest role arrival: role commits arriving faster than a pass ends
//! never hold it off. The place is kept while the cause holds and forgotten once it does not.

use super::{Holding, ThingSync};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{CommitId, SyncId, Tid};
use std::collections::BTreeMap;
use osis_store::Shred;
use std::collections::BTreeSet;
use std::sync::Arc;

/// `hw/` + commit ID: a self-removal sync waits on.
pub(crate) const WAITING: &[u8] = b"hw/";
/// `cp/` + sync ID: the place the last complete pass of it noted began at (u64 BE).
const PASSES: &[u8] = b"cp/";
/// `ra/` + actor: the place the newest role commit on it applied from elsewhere arrived at (u64
/// BE).
const ARRIVALS: &[u8] = b"ra/";

/// `jc/` + cause: the place this node first judged it at (u64 BE).
const CAUSES: &[u8] = b"jc/";

/// A cause a rule waits a complete pass after (spec/permissions.md §2 Tied grants, §3 Lost access).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Cause {
    /// Read access to the actor lost by every path (`lost_due`).
    Lost(Tid),
    /// Tied grant (target, group) held dead, removable here as an explicit demotion.
    Tie(Tid, Tid),
}

impl Cause {
    fn key(&self) -> Vec<u8> {
        match self {
            Cause::Lost(a) => [CAUSES, b"l", a.as_bytes()].concat(),
            Cause::Tie(t, g) => [CAUSES, b"t", t.as_bytes(), g.as_bytes()].concat(),
        }
    }

    fn from_key(k: &[u8]) -> Option<Cause> {
        let tid = |b: &[u8]| Some(Tid::from_bytes(b.try_into().ok()?));
        match k.split_first()? {
            (b'l', a) => Some(Cause::Lost(tid(a)?)),
            (b't', r) => {
                let (t, g) = r.split_at_checked(r.len() / 2)?;
                Some(Cause::Tie(tid(t)?, tid(g)?))
            }
            _ => None,
        }
    }
}

/// The role aspects whose commits from elsewhere a complete pass must follow.
const ROLE_ASPECTS: [&str; 3] = ["roles.0", "secrets.0", "keys.0"];

/// Loads the waiting self-removals, the complete passes noted, the role arrivals and the causes
/// judged (an open or reload); the pass place goes on from the highest stored.
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let ids = tx.scan_keys(WAITING, "held elsewhere wait", CommitId)?;
    tx.core.ix.held_wait.extend(ids);
    let bad = || Error::Corrupt("complete pass");
    let place = |v: &[u8]| v.try_into().map(u64::from_be_bytes).map_err(|_| bad());
    let mut rows = Vec::new();
    tx.scan(PASSES, |k, v| {
        rows.push((SyncId(k.get(..).ok_or_else(bad)?.try_into().map_err(|_| bad())?), place(v.get(..).ok_or_else(bad)?)?));
        Ok(())
    })?;
    let mut arrivals = Vec::new();
    tx.scan(ARRIVALS, |k, v| {
        arrivals.push((Tid::from_bytes(k.get(..).ok_or_else(bad)?.try_into().map_err(|_| bad())?), place(v.get(..).ok_or_else(bad)?)?));
        Ok(())
    })?;
    let mut causes = Vec::new();
    tx.scan(CAUSES, |k, v| {
        causes.push((Cause::from_key(k).ok_or_else(bad)?, place(v.get(..).ok_or_else(bad)?)?));
        Ok(())
    })?;
    let top = rows.iter().map(|x| x.1).chain(arrivals.iter().map(|x| x.1)).chain(causes.iter().map(|x| x.1)).max().unwrap_or(0);
    tx.core.place = tx.core.place.max(top);
    tx.core.ix.passes.extend(rows);
    tx.core.ix.role_arrivals.extend(arrivals);
    tx.core.ix.cause_at.extend(causes);
    Ok(())
}

/// Role commit `c`, applied from elsewhere in this transaction (or late parts of it), arrived:
/// each actor whose `roles.0`, `secrets.0` or `keys.0` it writes takes the next pass place.
pub(crate) fn note_arrival(tx: &mut Tx<'_>, h: &osis_commit::Header) -> Result<()> {
    let actors: BTreeSet<Tid> = h.aspects.iter().filter(|a| ROLE_ASPECTS.contains(&a.ak.as_str())).map(|a| a.tid).collect();
    if actors.is_empty() {
        return Ok(());
    }
    tx.core.place += 1;
    let at = tx.core.place;
    for a in actors {
        tx.txn.put_local(&[ARRIVALS, a.as_bytes()].concat(), &at.to_be_bytes(), Shred::No)?;
        tx.core.ix.role_arrivals.insert(a, at);
    }
    Ok(())
}

/// Role commit `c`, applied in this transaction with edge writes on `rosters`, waits for sync
/// (held elsewhere, or no peer to take it) when it is an own self-removal
/// (`rotation::own_self_removal`): at every node of the account alike, the one that made it and
/// the siblings that apply it (spec/permissions.md §3 Lost access: whichever node of the account
/// made it). The secrets it lost stay meanwhile: the node must still seal it under the sync IDs
/// it leaves.
pub(crate) fn wait_if_own(tx: &mut Tx<'_>, c: &CommitId, rosters: &BTreeSet<Tid>) -> Result<()> {
    if rosters.is_empty() || tx.core.ix.held_wait.contains(c) || !crate::rotation::own_self_removal(tx.core, c, rosters) {
        return Ok(());
    }
    tx.core.ix.held_wait.insert(*c);
    tx.txn.put_local(&[WAITING, &c.0].concat(), &[], Shred::No)?;
    Ok(())
}

impl Engine {
    /// The self-removals sync waits on (spec/sync-status.md §2).
    pub(crate) fn waiting_removals_now(&self) -> Arc<BTreeSet<CommitId>> {
        Arc::new(self.core.ix.held_wait.iter().copied().collect())
    }

    /// Sync is done waiting for `c` (held elsewhere, or no peer shares where it goes): each
    /// actor lost with no own self-removal behind it still waiting drops (`lost_leaving`, per
    /// actor: one that cannot be placed holds back nothing else; spec/permissions.md §3 Lost
    /// access). The drop goes first: a crash before `c` leaves the wait finds it waiting, and
    /// sync tells it done again.
    pub(crate) fn removal_done_now(&mut self, c: &CommitId) -> Result<()> {
        if !self.core.ix.held_wait.contains(c) {
            return Ok(());
        }
        let leaving = self.lost_leaving()?;
        let wait = &self.core.ix.held_wait;
        let ready: Vec<Tid> = leaving.actors.iter().filter(|(_, cs)| cs.iter().all(|x| x == c || !wait.contains(x))).map(|(a, _)| *a).collect();
        if !ready.is_empty() {
            self.forget_lost(crate::rotation::LostScope::Only(&ready))?;
        }
        let c = *c;
        self.run(|tx| {
            if tx.core.ix.held_wait.remove(&c) {
                tx.txn.remove_local(&[WAITING, &c.0].concat(), Shred::No)?;
            }
            Ok(())
        })
    }

    /// A complete pass of `s` begun at place `began` ended (spec/sync-status.md §1): kept
    /// durably, the last one alone per sync ID, while this node reads `s` (`forget_read`).
    pub(crate) fn note_complete_pass_now(&mut self, s: &SyncId, began: u64) -> Result<()> {
        if self.core.ix.passes.get(s).is_some_and(|b| *b >= began) || !self.reads_now(s)? {
            return Ok(());
        }
        let s = *s;
        self.run(|tx| {
            tx.txn.put_local(&[PASSES, &s.0].concat(), &began.to_be_bytes(), Shred::No)?;
            tx.core.ix.passes.insert(s, began);
            Ok(())
        })
    }

    /// This node reads `s` (its sync set holds it read).
    fn reads_now(&mut self, s: &SyncId) -> Result<bool> {
        Ok(self.sync_set()?.ids.get(s).is_some_and(|(_, h)| *h == Holding::Read))
    }

    /// `s` is read here no more: its passes go with it, so a sync ID read again wants a pass of
    /// its own (history read since it left is not here), and so do the certificate blobs sealed
    /// under it (`certblobs`: read logs them again if it reads `s` again).
    pub(crate) fn forget_read_now(&mut self, s: &SyncId) -> Result<()> {
        if !self.core.ix.passes.contains_key(s) && !super::certblobs::any(&self.core, s) {
            return Ok(());
        }
        let s = *s;
        self.run(|tx| {
            tx.txn.remove_local(&[PASSES, &s.0].concat(), Shred::No)?;
            tx.core.ix.passes.remove(&s);
            super::certblobs::forget(tx, &s)
        })
    }

    /// What `forget_read_now` drops, of each sync ID not read here (one left while the node was
    /// down): `Engine::forget_unread`.
    pub(crate) fn forget_unread_now(&mut self) -> Result<()> {
        let gone: BTreeSet<SyncId> = self.core.ix.passes.keys().chain(self.core.ix.cert_blobs.keys().map(|k| &k.0)).copied().collect();
        for s in gone {
            if !self.reads_now(&s)? {
                self.forget_read_now(&s)?;
            }
        }
        Ok(())
    }

    /// The sync IDs some rule waits on a complete pass of, each with the place the pass must
    /// begin after; one whose last complete pass began after it is not listed. A memo over the role commits held, the sync set, the ties and the passes noted:
    /// derived again at an open, so a restart wants what it wanted.
    /// - spec/permissions.md §3 Complete pass: the newest role commit applied here from elsewhere
    ///   on S's actor;
    /// - spec/permissions.md §3 Lost access: the loss of S's actor, from when it was judged
    ///   (`Cause::Lost`);
    /// - spec/permissions.md §2 Tied grants: every sync ID of a tie's demotion scope
    ///   (`tied_wants`), from when the tie was judged dead (`Cause::Tie`);
    /// - spec/sync-status.md §3 History complete: one pass of every sync ID read here.
    pub(crate) fn passes_wanted_now(&mut self) -> Result<Arc<BTreeMap<SyncId, u64>>> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.passes_wanted, &(), |e| e.passes_wanted_fresh())
    }

    fn passes_wanted_fresh(&mut self) -> Result<Arc<BTreeMap<SyncId, u64>>> {
        let mut out: BTreeMap<SyncId, u64> = BTreeMap::new();
        let mut want = |s: SyncId, since: u64| {
            let e = out.entry(s).or_insert(since);
            *e = (*e).max(since);
        };
        let set = self.sync_set()?;
        for (s, (t, holding)) in set.ids.iter() {
            if *holding != Holding::Read {
                continue;
            }
            want(*s, 0);
            let a = self.core.reader_of(t);
            // after the newest role commit on S's actor from elsewhere: what the re-seal trigger
            // waits on (`complete_pass`)
            if let Some(at) = self.role_arrival(&a) {
                want(*s, at);
            }
            // after the loss of S's actor was judged: what the lost-access drop waits on
            // (`lost_passed`)
            if let Some(at) = self.cause_place(&Cause::Lost(a)) {
                want(*s, at);
            }
            // a stranded report's re-seal ask (spec/permissions.md §3, §4): met at a pass's end
            if let Some(at) = self.asked_at(&self.core.reader_of(t)) {
                want(*s, at);
            }
        }
        for (since, ids) in self.tied_wants()? {
            for s in ids {
                want(s, since);
            }
        }
        out.retain(|s, since| self.core.ix.passes.get(s).is_none_or(|b| b <= since));
        Ok(Arc::new(out))
    }

    /// The place the newest role commit on `actor` (`roles.0`, `secrets.0`, `keys.0`) applied
    /// here from elsewhere arrived at (spec/permissions.md §3: a Pull sent before it ends no pass
    /// after it).
    pub(crate) fn role_arrival(&self, actor: &Tid) -> Option<u64> {
        self.core.ix.role_arrivals.get(actor).copied()
    }

    /// The place this node first judged `c` at, while it holds.
    pub(crate) fn cause_place(&self, c: &Cause) -> Option<u64> {
        self.core.ix.cause_at.get(c).copied()
    }

    /// `c` holds here (`holds`): the place it was first judged at, noted now (the place now) if
    /// it was not; or it holds no more, and its place is forgotten (a later cause is judged
    /// afresh). Kept durably: a restart waits for what it waited for.
    pub(crate) fn judge_cause(&mut self, c: Cause, holds: bool) -> Result<u64> {
        match (self.cause_place(&c), holds) {
            (Some(at), true) => Ok(at),
            (None, false) => Ok(0),
            (_, true) => {
                let at = self.core.place;
                self.run(|tx| {
                    tx.txn.put_local(&c.key(), &at.to_be_bytes(), Shred::No)?;
                    tx.core.ix.cause_at.insert(c, at);
                    Ok(at)
                })
            }
            (Some(_), false) => self.run(|tx| {
                tx.txn.remove_local(&c.key(), Shred::No)?;
                tx.core.ix.cause_at.remove(&c);
                Ok(0)
            }),
        }
    }

    /// At an open: forgets each cause whose subject went while the node was down or before its
    /// follower judged it again (a loss of an actor no longer held, a tie whose group holds no
    /// edge on its target): rows `jc/` stay bounded by what is held.
    pub(crate) fn forget_gone_causes(&mut self) -> Result<()> {
        let gone: Vec<Cause> = self.core.ix.cause_at.keys().filter(|c| match c {
            Cause::Lost(a) => !self.core.ix.secrets.contains_key(a),
            Cause::Tie(t, g) => !self.core.ix.held.holders_of(t).any(|x| x == g),
        }).copied().collect();
        for c in gone {
            self.judge_cause(c, false)?;
        }
        Ok(())
    }

    /// The tied grants on `t` judged dead and removable explicitly here: their places kept, every
    /// other tie on `t` forgotten (`judge_cause`).
    pub(crate) fn judge_ties(&mut self, t: &Tid, now: &BTreeSet<Tid>) -> Result<()> {
        let gone: Vec<Tid> = self.core.ix.cause_at.keys().filter_map(|c| match c {
            Cause::Tie(x, g) if x == t && !now.contains(g) => Some(*g),
            _ => None,
        }).collect();
        for g in gone {
            self.judge_cause(Cause::Tie(*t, g), false)?;
        }
        for g in now {
            self.judge_cause(Cause::Tie(*t, *g), true)?;
        }
        Ok(())
    }

    /// Whether a complete pass of each of `ids` noted here began after pass place `since` (one
    /// begun at it is not after it): the one comparison every rule waiting on a pass makes.
    pub(crate) fn passed_after<'a>(&self, mut ids: impl Iterator<Item = &'a SyncId>, since: u64) -> bool {
        ids.all(|s| self.core.ix.passes.get(s).is_some_and(|b| *b > since))
    }

    /// Begins a complete pass: the next pass place, which the pass is noted with
    /// (`note_complete_pass_now`) and leaving compares with.
    pub(crate) fn begin_pass_now(&mut self) -> u64 {
        self.core.place += 1;
        self.core.place
    }

    /// The pass place the newest re-seal ask on `actor` from a stranded report was taken at
    /// (`sync::stranded`).
    fn asked_at(&self, actor: &Tid) -> Option<u64> {
        self.core.ix.reseal_asks.iter().filter(|((a, _), k)| a == actor && !k.met).map(|(_, k)| k.at).max()
    }

    /// spec/permissions.md §2 Tied grants: per tied grant (G, T) this node holds dead and would
    /// remove as an explicit demotion (`may_remove`, as `untie_due` reads it), the sync IDs whose
    /// bodies carry a thing of the demotion's pre-sync scope, from where it was judged dead.
    fn tied_wants(&mut self) -> Result<Vec<(u64, BTreeSet<SyncId>)>> {
        let mut out = Vec::new();
        for (t, g) in self.tied_unplaced(&BTreeSet::new(), &BTreeSet::new(), true)? {
            if self.may_remove(&t, &g)? != Some(crate::flows::Untie::Explicit) {
                continue;
            }
            out.extend(self.tie_scope(&t, &g)?);
        }
        Ok(out)
    }

    /// The sync IDs tied grant (`t`, `g`)'s explicit demotion waits a complete pass of, and the
    /// pass place each pass must begin after: where this node judged the tie dead (`Cause::Tie`,
    /// noted by `untie_due`; `None` before) (spec/permissions.md §2 Tied grants).
    fn tie_scope(&mut self, t: &Tid, g: &Tid) -> Result<Option<(u64, BTreeSet<SyncId>)>> {
        let Some(since) = self.cause_place(&Cause::Tie(*t, *g)) else { return Ok(None) };
        Ok(Some((since, self.demotion_scope_sync_ids(t)?)))
    }

    /// Whether every pass tied grant (`t`, `g`)'s explicit demotion waits (`tie_scope`) is noted.
    pub(crate) fn tie_passes_done(&mut self, t: &Tid, g: &Tid) -> Result<bool> {
        let Some((since, ids)) = self.tie_scope(t, g)? else { return Ok(false) };
        Ok(self.passed_after(ids.iter(), since))
    }

    /// The read sync IDs whose bodies carry a thing of a demotion's pre-sync scope on `t`
    /// (spec/permissions.md §2, §5.3: the things the demoted authority gave write on, read as `t`
    /// and the things it encloses; spec/sync-judgement.md §1: a thing travels under the sync IDs
    /// of itself and of the groups enclosing it). Only those this node's sync set reads: a pass
    /// of another is never noted (`note_complete_pass_now`), so waiting on it would wait forever.
    fn demotion_scope_sync_ids(&mut self, t: &Tid) -> Result<BTreeSet<SyncId>> {
        let mut things: BTreeSet<Tid> = self.closure(t).iter().copied().collect();
        things.insert(*t);
        for x in things.clone() {
            things.extend(self.enclosing(&x));
        }
        let mut out = BTreeSet::new();
        for x in things {
            if let ThingSync::Read(ids) = self.thing_sync_now(&x)? {
                out.extend(ids);
            }
        }
        let set = self.sync_set()?;
        out.retain(|s| set.ids.get(s).is_some_and(|(_, h)| *h == Holding::Read));
        Ok(out)
    }

    /// Whether each sync ID of `actor` read here had a complete pass begun after the newest role
    /// commit on it applied from elsewhere (spec/permissions.md §3 Complete pass: the re-seal
    /// trigger waits for one). False for an actor with no sync ID read here.
    pub(crate) fn complete_pass(&mut self, actor: &Tid) -> Result<bool> {
        let ThingSync::Read(ids) = self.thing_sync_now(actor)? else { return Ok(false) };
        let since = self.role_arrival(actor).max(self.asked_at(actor)).unwrap_or(0);
        Ok(!ids.is_empty() && self.passed_after(ids.iter(), since))
    }

    /// spec/sync-status.md §3 History complete for `thing`: a complete pass of every sync ID
    /// carrying it (its own and its enclosing groups' read here) noted.
    pub(crate) fn history_complete_now(&mut self, thing: &Tid) -> Result<bool> {
        let ids = self.carrying_now(thing, true)?;
        Ok(!ids.is_empty() && ids.iter().all(|s| self.core.ix.passes.contains_key(s)))
    }

    /// The sync IDs carrying `thing`: its own and its enclosing groups', read here (`read`), or
    /// read or kept unread.
    pub(crate) fn carrying_now(&mut self, thing: &Tid, read: bool) -> Result<BTreeSet<SyncId>> {
        let mut ids = BTreeSet::new();
        for x in std::iter::once(*thing).chain(self.enclosing(thing)) {
            match self.thing_sync_now(&x)? {
                ThingSync::Read(v) => ids.extend(v),
                ThingSync::Unread(v) if !read => ids.extend(v),
                _ => {}
            }
        }
        Ok(ids)
    }
}
