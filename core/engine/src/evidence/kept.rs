//! The engine's one evidence derivation (`Kept`), brought up to date with what moved since the
//! last ask (`Engine::kept_evidence`): each held commit's copies (`held::copy_parts`), each held
//! record's mint admin, each read thing as a sync ID and each thing of its unit, followed per key
//! (`memo::Effects`), so a change costs what it moved and never the held set. `held::derive` over
//! the same inputs is the oracle (`Engine::check_evidence`; debug builds compare at the 1st, 2nd,
//! 4th, ... follow).

use super::Part;
use super::held::{Ev, Key32, copy_parts};
use crate::Engine;
use crate::error::Result;
use crate::sync::units::Ctx;
use osis_base::memo::{Effects, Feed, Quiet, Unrecorded};
use osis_base::{CommitId, Tid};
use std::collections::BTreeMap;
use std::sync::Arc;

/// One commit's copies: per thing its parts there.
type Parts = Arc<BTreeMap<Tid, Vec<Part<Tid, Key32>>>>;

/// What gives the keys to follow from the first follow on.
#[derive(Clone)]
struct Feeds {
    held: Feed<CommitId>,
    records: Feed<Tid>,
    read: Feed<Tid>,
    members: Feed<(Ctx, Tid)>,
}

/// The derivation, handed to each ask's reader. A copy of the engine gets one of its own: its
/// stamps are the copy's (`osis_base::copying`), as what the copy's followers read must be.
struct Own(Arc<Ev>);

impl Clone for Own {
    fn clone(&self) -> Self {
        Own(Arc::new((*self.0).clone()))
    }
}

#[derive(Clone)]
pub(crate) struct Kept {
    ev: Own,
    feeds: Option<Feeds>,
    /// Per held commit, its copies as the derivation holds them.
    copies: Effects<CommitId, Parts>,
    /// Per thing whose record is held, its mint admin.
    mint: Effects<Tid, Option<Tid>>,
    /// Per read thing (`SyncRows::read`), whether it is one: a sync ID of the derivation.
    sids: Effects<Tid, bool>,
    /// Per (read thing, thing), whether the first's sync unit holds the second.
    units: Effects<(Tid, Tid), bool>,
    quiet: Quiet,
    /// Commits whose copies were read (`held::copy_parts`) so far: what a count test reads.
    pub(crate) read: u64,
    #[cfg(debug_assertions)]
    follows: u64,
}

impl Default for Kept {
    fn default() -> Self {
        Kept {
            ev: Own(Arc::new(Ev::new(super::Config { keys_open: true }))),
            feeds: None,
            copies: Effects::new("evidence: copies"),
            mint: Effects::new("evidence: records"),
            sids: Effects::new("evidence: sync IDs"),
            units: Effects::new("evidence: units"),
            quiet: Quiet::default(),
            read: 0,
            #[cfg(debug_assertions)]
            follows: 0,
        }
    }
}

impl Kept {
    fn idle(&self) -> bool {
        self.copies.idle() && self.mint.idle() && self.sids.idle() && self.units.idle()
    }
}

impl Engine {
    /// The evidence derivation over the held set, each read thing a sync ID with its sync unit
    /// (spec/permissions.md §4 Evidence of a sync ID), up to date.
    pub(crate) fn kept_evidence(&mut self) -> Result<Arc<Ev>> {
        self.follow_rows()?;
        let k = &self.core.evidence;
        if k.feeds.is_some() && k.quiet.holds(k.idle()) {
            return Ok(k.ev.0.clone());
        }
        let _u = Unrecorded::start();
        let from = Quiet::begin();
        let mut k = std::mem::take(&mut self.core.evidence);
        let out = self.follow_evidence(&mut k);
        k.quiet.ended(from, out.is_ok());
        let ev = k.ev.0.clone();
        self.core.evidence = k;
        out?;
        #[cfg(debug_assertions)]
        {
            self.core.evidence.follows += 1;
            if self.core.evidence.follows.is_power_of_two() {
                let differs = osis_base::costs::paused(|| self.kept_differs(&ev))?;
                debug_assert_eq!(differs, None, "the kept evidence derivation differs from the one derived anew");
            }
        }
        Ok(ev)
    }

    fn follow_evidence(&mut self, k: &mut Kept) -> Result<()> {
        let Kept { ev, feeds, copies, mint, sids, units, read: copies_read, .. } = k;
        let ev = Arc::make_mut(&mut ev.0);
        let (held, records, read, members) = match feeds.as_mut() {
            Some(f) => (f.held.added(), f.records.added(), f.read.added(), f.members.added()),
            None => {
                let (ix, rows) = (&self.core.ix, &self.core.sync_rows);
                *feeds = Some(Feeds { held: ix.commits.feed(), records: ix.held.records_feed(), read: rows.read.feed(), members: ix.closure.member_feed() });
                (ix.commits.keys().copied().collect(), ix.held.things().copied().collect(), rows.read.iter().copied().collect(), Vec::new())
            }
        };
        // the sync IDs: a read thing, with its unit as it stands; a unit's later members by the feed
        for g in read {
            sids.want(g);
        }
        for g in sids.due() {
            let Some((_, now)) = sids.settle(&g, || self.core.sync_rows.read.contains(&g)) else { continue };
            if now {
                ev.add_sid(g, g);
                units.want((g, g));
                for t in self.core.ix.closure.members(&Ctx::Read(g)).into_iter().flatten() {
                    units.want((g, *t));
                }
            } else {
                ev.remove_sid(&g);
                sids.unwant(&g);
            }
        }
        for (c, t) in members {
            if let Ctx::Read(g) = c {
                units.want((g, t));
            }
        }
        for (g, t) in units.due() {
            let holds = || self.core.sync_rows.read.contains(&g) && self.core.ix.closure.unit_holds(&g, &t);
            let Some((_, now)) = units.settle(&(g, t), holds) else { continue };
            if now {
                ev.join(&g, t);
            } else {
                ev.leave(&g, t);
                units.unwant(&(g, t));
            }
        }
        // the record edges
        for t in records {
            mint.want(t);
        }
        for t in mint.due() {
            let Some((was, now)) = mint.settle(&t, || self.core.ix.held.created(&t).and_then(|r| r.mint_admin())) else { continue };
            if let Some(m) = was.flatten() {
                ev.remove_record(&(m, t));
            }
            match now {
                Some(m) => ev.add_record((m, t)),
                // a record is its thing's for good: one held again comes by the feed
                None => mint.unwant(&t),
            }
        }
        // the copies
        for c in held {
            copies.want(c);
        }
        for c in copies.due() {
            *copies_read += 1;
            let Some((was, now)) = copies.try_settle(&c, || self.read(|tx| copy_parts(tx, &c)).map(Arc::new))? else { continue };
            let was = was.unwrap_or_default();
            ev.forget_all(was.keys().filter(|t| !now.contains_key(*t)).map(|t| (c, *t)));
            for (t, parts) in now.iter() {
                if was.get(t) != Some(parts) {
                    ev.add((c, *t), parts.clone());
                }
            }
            if now.is_empty() && !self.core.ix.commits.contains_key(&c) {
                copies.unwant(&c);
            }
        }
        Ok(())
    }

    /// The first difference between `ev` and the derivation built from nothing over the held
    /// set and the read things' units (`held::derive`), and `ev`'s own check (tests, debug builds).
    pub(crate) fn kept_differs(&mut self, ev: &Ev) -> Result<Option<String>> {
        let read: Vec<Tid> = self.core.sync_rows.read.iter().copied().collect();
        let sids: Vec<(Tid, Tid, Vec<Tid>)> = read.iter().map(|g| (*g, *g, self.sync_unit(g).iter().copied().collect())).collect();
        let anew = self.evidence(&sids)?;
        if let Err(e) = ev.check() {
            return Ok(Some(e));
        }
        for g in &read {
            let (a, b) = (ev.required(g).map(|r| r.keys().collect::<Vec<_>>()), anew.required(g).map(|r| r.keys().collect::<Vec<_>>()));
            if a != b {
                return Ok(Some(format!("sync ID {g:?}: kept {a:?}, derived anew {b:?}")));
            }
            if ev.edges(g) != anew.edges(g) {
                return Ok(Some(format!("sync ID {g:?}: kept edges {:?}, derived anew {:?}", ev.edges(g), anew.edges(g))));
            }
        }
        if ev.copies() != anew.copies() || ev.records() != anew.records() {
            return Ok(Some("the kept copies or record edges are not the held ones".into()));
        }
        let extra: Vec<Tid> = ev.sids().filter(|g| !read.contains(g)).collect();
        Ok((!extra.is_empty()).then(|| format!("kept sync IDs {extra:?} are not read")))
    }
}
