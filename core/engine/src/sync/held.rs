//! What waits for sync's word (spec/sync-status.md §1-§3): self-removals whose lost secrets drop
//! once sync is done waiting for the removal (spec/permissions.md §3 Lost access), and complete passes:
//! the sync IDs some rule waits on a pass of (`passes_wanted`), and the last pass noted per sync
//! ID, which the re-seal and history-add triggers and history completeness read.

use super::{Holding, ThingSync};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, SyncId, Tid, WallMs};
use std::collections::BTreeMap;
use osis_store::Shred;
use std::collections::BTreeSet;
use std::sync::Arc;

/// `hw/` + commit ID: a self-removal sync waits on.
pub(crate) const WAITING: &[u8] = b"hw/";
/// `cp/` + sync ID: when the last complete pass of it noted began (engine ms, u64 BE).
const PASSES: &[u8] = b"cp/";

/// The role aspects whose commits from elsewhere a complete pass must follow.
const ROLE_ASPECTS: [&str; 3] = ["roles.0", "secrets.0", "keys.0"];

/// Loads the waiting self-removals and the complete passes noted (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let ids = tx.scan_keys(WAITING, "held elsewhere wait", CommitId)?;
    tx.core.ix.held_wait.extend(ids);
    let bad = || Error::Corrupt("complete pass");
    let mut rows = Vec::new();
    tx.scan(PASSES, |k, v| {
        let s = SyncId(k.get(..).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        rows.push((s, WallMs(u64::from_be_bytes(v.get(..).ok_or_else(bad)?.try_into().map_err(|_| bad())?))));
        Ok(())
    })?;
    tx.core.ix.passes.extend(rows);
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

    /// A complete pass of `s` begun at `began` (engine ms) ended (spec/sync-status.md §1): kept
    /// durably, the last one alone per sync ID, while this node reads `s` (`forget_read`).
    pub(crate) fn note_complete_pass_now(&mut self, s: &SyncId, began: WallMs) -> Result<()> {
        if self.core.ix.passes.get(s).is_some_and(|b| *b >= began) || !self.reads_now(s)? {
            return Ok(());
        }
        let s = *s;
        self.run(|tx| {
            tx.txn.put_local(&[PASSES, &s.0].concat(), &began.0.to_be_bytes(), Shred::No)?;
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
        if !self.core.ix.passes.contains_key(s) && !self.core.ix.cert_blobs.contains_key(s) {
            return Ok(());
        }
        let s = *s;
        self.run(|tx| {
            tx.txn.remove_local(&[PASSES, &s.0].concat(), Shred::No)?;
            tx.core.ix.passes.remove(&s);
            super::certblobs::forget(tx, &s)
        })
    }

    /// At an open: what `forget_read_now` drops, of each sync ID not read here (one left while
    /// the node was down).
    pub(crate) fn forget_unread(&mut self) -> Result<()> {
        let gone: BTreeSet<SyncId> = self.core.ix.passes.keys().chain(self.core.ix.cert_blobs.keys()).copied().collect();
        for s in gone {
            if !self.reads_now(&s)? {
                self.forget_read_now(&s)?;
            }
        }
        Ok(())
    }

    /// The sync IDs some rule waits on a complete pass of, each with the moment (engine ms) the
    /// pass must begin at or after; one whose last complete pass began at or after it is not
    /// listed. A memo over the role commits held, the sync set, the ties and the passes noted:
    /// derived again at an open, so a restart wants what it wanted.
    /// - spec/permissions.md §3 Complete pass: the newest role commit of S's actor applied here
    ///   from elsewhere;
    /// - spec/permissions.md §2 Tied grants: every sync ID of a tie's demotion scope
    ///   (`tied_wants`), from the last role commit of G or T applied from elsewhere;
    /// - spec/sync-status.md §3 History complete: one pass of every sync ID read here.
    pub(crate) fn passes_wanted_now(&mut self) -> Result<Arc<BTreeMap<SyncId, WallMs>>> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.passes_wanted, &(), |e| e.passes_wanted_fresh())
    }

    fn passes_wanted_fresh(&mut self) -> Result<Arc<BTreeMap<SyncId, WallMs>>> {
        let mut out: BTreeMap<SyncId, WallMs> = BTreeMap::new();
        let mut want = |s: SyncId, since: WallMs| {
            let e = out.entry(s).or_insert(since);
            *e = (*e).max(since);
        };
        let set = self.sync_set()?;
        for (s, (t, holding)) in set.ids.iter() {
            if *holding != Holding::Read {
                continue;
            }
            want(*s, WallMs(0));
            if let Some(at) = self.role_arrival(&self.core.reader_of(t)) {
                want(*s, at);
            }
        }
        for (since, ids) in self.tied_wants()? {
            for s in ids {
                want(s, since);
            }
        }
        out.retain(|s, since| self.core.ix.passes.get(s).is_none_or(|b| b < since));
        Ok(Arc::new(out))
    }

    /// When the newest role commit on `actor` (`roles.0`, `secrets.0`, `keys.0`) applied here
    /// from elsewhere arrived, engine ms (spec/permissions.md §3: a Pull sent before it ends no
    /// pass after it).
    fn role_arrival(&self, actor: &Tid) -> Option<WallMs> {
        let ix = &self.core.ix;
        ROLE_ASPECTS
            .iter()
            .filter_map(|a| Ak::new(*a).ok())
            .flat_map(|ak| ix.by_aspect.get(&(*actor, ak)).into_iter().flatten().map(|x| x.1).collect::<Vec<_>>())
            .filter_map(|c| ix.commits.get(&c).filter(|m| m.origin == crate::events::Origin::Remote).map(|m| m.received))
            .max()
    }

    /// spec/permissions.md §2 Tied grants: per tied grant (G, T) this node holds dead and would
    /// remove as an explicit demotion (`may_remove`, as `untie_due` reads it), the sync IDs whose
    /// bodies carry a thing of the demotion's pre-sync scope, from the last role commit of G or T
    /// applied from elsewhere.
    fn tied_wants(&mut self) -> Result<Vec<(WallMs, BTreeSet<SyncId>)>> {
        let mut out = Vec::new();
        for (t, g) in self.tied_unplaced(&BTreeSet::new(), &BTreeSet::new(), true)? {
            if self.may_remove(&t, &g)? != Some(crate::flows::Untie::Explicit) {
                continue;
            }
            out.push(self.tie_scope(&t, &g)?);
        }
        Ok(out)
    }

    /// The sync IDs tied grant (`t`, `g`)'s explicit demotion waits a complete pass of, and the
    /// moment each pass must begin at or after: the last role commit of G or T applied from
    /// elsewhere (spec/permissions.md §2 Tied grants).
    fn tie_scope(&mut self, t: &Tid, g: &Tid) -> Result<(WallMs, BTreeSet<SyncId>)> {
        let since = self.role_arrival(g).max(self.role_arrival(t)).unwrap_or(WallMs(0));
        Ok((since, self.demotion_scope_sync_ids(t)?))
    }

    /// Whether every pass tied grant (`t`, `g`)'s explicit demotion waits (`tie_scope`) is noted.
    pub(crate) fn tie_passes_done(&mut self, t: &Tid, g: &Tid) -> Result<bool> {
        let (since, ids) = self.tie_scope(t, g)?;
        Ok(ids.iter().all(|s| self.core.ix.passes.get(s).is_some_and(|b| *b >= since)))
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

    /// Whether each sync ID of `actor` read here had a complete pass begun at or after the newest
    /// role commit on it applied from elsewhere (spec/permissions.md §3 Complete pass: the re-seal
    /// trigger waits for one). False for an actor with no sync ID read here.
    pub(crate) fn complete_pass(&mut self, actor: &Tid) -> Result<bool> {
        let ThingSync::Read(ids) = self.thing_sync_now(actor)? else { return Ok(false) };
        let since = self.role_arrival(actor).unwrap_or(WallMs(0));
        Ok(!ids.is_empty() && ids.iter().all(|s| self.core.ix.passes.get(s).is_some_and(|b| *b >= since)))
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
