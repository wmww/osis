//! Lifecycle duties the engine judges and sync drives, each as an `Effects` value over what makes
//! it due (notes/sync-driver.md, Duties).
//!
//! - **Lifetimes** (spec/commits.md §5 Lifetimes): the engine's judgment (`Engine::judge_lifetimes`)
//!   runs when its work list or the rights mark moved (`Engine::lifetimes_due`, stamped), and its
//!   held things again when a sync ID this node syncs is newly heard out. A group is heard out
//!   when every sync ID this node syncs of it is: one with no peer to wait for (`Opens::waited`:
//!   none has it open or in its kept record, none the rosters name has a record not acknowledging
//!   it; as a leave's wait reads it) at once, else once its
//!   sources are (spec/sync-status.md §1, `Status::heard_out`); a group with none here is at once
//!   (a thing under no sync ID is judged at once). So a node alone (one device, no contact
//!   sharing the group) releases at once, and one whose sharing peers are away releases nothing
//!   under what they share.
//!
//! - **Role duties** (spec/permissions.md §2 Finalize, §3 Required rotation and Lost access):
//!   per actor this node holds secrets of, one `Effects` key over `Engine::role_duty_due` (a
//!   value derived from the state: the finalize or rotation this node owes before it next
//!   encrypts there, whatever made it due, own commits included, and the memo clock up to the
//!   next `until`): `Engine::ensure_rotated` writes it when it settles true. Then, on a second
//!   key per held actor, the lost-access drop (spec/permissions.md §3 Lost access): once
//!   `Engine::lost_due` (lost by every path, no own self-removal waiting, not by an `until`
//!   alone; the clock read to the next `until`) and `Engine::lost_passed` (a complete pass of its
//!   sync IDs begun after the newest role commit that could have caused it: it keeps syncing until
//!   then, and what that pass brings may give it back) both hold, `Engine::drop_lost` judges
//!   and drops it. A loss by an `until` alone (`Engine::lost_timed`, spec/permissions.md §2) on
//!   the same key drops once each sync ID of the actor read here is heard out for it
//!   (`Hears::timed_heard`: with a source, a complete pass begun after the loss ended and what
//!   this node logged itself there is elsewhere; no peer to be waited for on it; or a source
//!   refuses it), or
//!   at its wait's end (`LOST_HEARD_WAIT_MS`, read on the memo clock). One key over `Engine::copies_due` judges the kept copies again
//!   (`Engine::rejudge_copies`) where a role commit moved what one hangs on.
//! - **Joiner's leave** (spec/permissions.md §7): per thing named a holder, whether it is a link
//!   this account joined whose K's edge on its target ended (`Engine::joined_link_ended`); one
//!   that became so is left (`Engine::leave_link`).
//! - **Tied grants** (spec/permissions.md §2): per thing named a holder, the groups whose tied
//!   edge on it this node removes now (`Engine::untie_due`: the tie held dead, a self-removal at
//!   once, an explicit demotion once its scope's complete passes are noted); each is removed
//!   (`Engine::untie`).
//!
//! The last two (holder duties) follow every thing a holder is named on (`Engine::role_things`,
//! then its feed): what each value reads is stamped (records, timelines, placements, passes, the
//! clock up to the next `until`), so a thing is judged again only when one of those moves. A
//! holder duty's write refused for any reason but a store failure is tried again at the next move
//! of what the value read. A thing named a holder no more is followed no more (`untie_due` reads
//! its holders, so it is due then).
//!
//! State: the sync IDs synced here with their things (`SyncsFollow`), each one's heard-out value
//! and whether one became heard out since the last judgment. Bounded by the sync IDs synced; the
//! holder duties, two values per thing named a holder here (unwanted when its last holder goes). A restart settles every key afresh
//! (every held thing is judged again once heard out, every holder duty once).

use crate::set::SyncsFollow;
use crate::store::Store;
use crate::types::Result;
use osis_base::memo::{Effects, Feed};
use osis_base::{SyncId, Tid};
use osis_engine::Engine;
use std::collections::{BTreeMap, BTreeSet};

/// What life reads of sync per sync ID: stamped reads, so a duty is due again when one moves.
pub trait Hears {
    /// S heard out now (no peer to wait for on S counts as heard out): lifetimes.
    fn heard_out(&mut self, engine: &mut Engine, s: &SyncId) -> Result<bool>;
    /// A loss by an `until` alone heard S out (spec/permissions.md §2): with a source of S, a
    /// complete pass of S begun after the loss ended (`passed`) and each own commit with an
    /// entry under S is held elsewhere; or no peer is to be waited for on S; or a source refuses
    /// S.
    fn timed_heard(&mut self, engine: &mut Engine, s: &SyncId, passed: bool) -> Result<bool>;
}

#[derive(Clone)]
pub struct Life {
    syncs: SyncsFollow,
    /// Per thing, the sync IDs this node syncs of it.
    ids: BTreeMap<Tid, BTreeSet<SyncId>>,
    /// Per sync ID synced, whether it is heard out, as last settled.
    heard: Effects<SyncId, bool>,
    heard_now: BTreeMap<SyncId, bool>,
    /// `Engine::lifetimes_due` (work due, things held), as last settled.
    due: Effects<(), (bool, bool)>,
    last: (bool, bool),
    /// A sync ID became heard out since the last judgment: the held things are judged again.
    newly: bool,
    /// `Engine::copies_due`, as last settled.
    copies: Effects<(), bool>,
    /// Per actor held, whether its drop is due and its pass done (`lost_due`, `lost_passed`).
    lost: Effects<Tid, bool>,
    /// The actors whose secrets the engine comes to hold (`None` before the first settle: every
    /// one held then is wanted).
    actors: Option<Feed<Tid>>,
    /// Per actor held, `Engine::role_duty_due` as last settled.
    owed: Effects<Tid, bool>,
    /// The (holder, thing) pairs named since the last settle (`Engine::role_things`); `None`
    /// before the first.
    pairs: Option<Feed<(Tid, Tid)>>,
    /// Per thing named a holder: a link this account joined that ended (`joined_link_ended`).
    leaves: Effects<Tid, bool>,
    /// Per thing named a holder: the groups whose tied edge on it this node removes now
    /// (`untie_due`).
    unties: Effects<Tid, BTreeSet<Tid>>,
}

impl Default for Life {
    fn default() -> Life {
        let mut due = Effects::new("life: lifetimes due");
        due.want(());
        let mut copies = Effects::new("life: kept copies");
        copies.want(());
        Life { syncs: SyncsFollow::default(), ids: BTreeMap::new(), heard: Effects::new("life: heard out"), heard_now: BTreeMap::new(), due, last: (false, false), newly: false, copies, lost: Effects::new("life: lost access"), actors: None, owed: Effects::new("life: role duty owed"), pairs: None, leaves: Effects::new("life: joiner's leave"), unties: Effects::new("life: tied grants") }
    }
}

impl std::fmt::Debug for Life {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Life").field("last", &self.last).field("newly", &self.newly).finish_non_exhaustive()
    }
}

impl Life {
    /// Follows what moved; runs each duty when due. `heard_out(s)`: S heard out now (stamped
    /// reads; no peer to wait for on S counts as heard out). Whether one ran (the engine's rows moved:
    /// the next round settles them).
    pub fn settle(&mut self, engine: &mut Engine, store: &Store, hears: &mut impl Hears) -> Result<bool> {
        // the role duties first: a finalize or rotation goes before anything encrypts again,
        // then the lost-access drop
        if self.owe(engine)? {
            return Ok(true);
        }
        if self.drop_lost(engine, hears)? {
            return Ok(true);
        }
        if !self.copies.due().is_empty()
            && let Some((_, true)) = self.copies.settle(&(), || engine.copies_due())
        {
            // a store failure fails the step (due again after its restart); any other error is
            // this duty's alone: parked until what its value read moves (`isolate`)
            match isolate(engine.rejudge_copies()) {
                Ok(Some(_)) => return Ok(true),
                Ok(None) => {}
                Err(e) => {
                    // due again at the next settle (the failing step restarts anyway)
                    self.copies.unwant(&());
                    self.copies.want(());
                    return Err(e);
                }
            }
        }
        let acted = self.holders(engine)?;
        Ok(self.lifetimes(engine, store, hears)? || acted)
    }

    /// Writes the role commits this node owes on each held actor whose `role_duty_due` moved
    /// and settles true; whether any ran. O(actors added and keys moved).
    fn owe(&mut self, engine: &mut Engine) -> Result<bool> {
        let added = match &mut self.actors {
            Some(f) => f.added(),
            None => {
                self.actors = Some(engine.held_actors_feed());
                engine.held_actors()
            }
        };
        for a in added {
            self.owed.want(a);
            self.lost.want(a);
        }
        let mut ran = false;
        // one actor's error is its own: a store failure fails the step, any other parks that
        // actor's key (settled, judged again when what it read moves) and the others go on
        for a in self.owed.due() {
            match self.owed.try_settle(&a, || isolate(engine.role_duty_due(&a)).map(|v| v.unwrap_or(false)))? {
                Some((_, true)) => match isolate(engine.ensure_rotated(&a)) {
                    Ok(done) => ran |= done.is_some(),
                    Err(e) => {
                        // due again at the next settle (the failing step restarts anyway)
                        self.owed.unwant(&a);
                        self.owed.want(a);
                        return Err(e);
                    }
                },
                // no longer held: wanted again when it is (the feed)
                Some((_, false)) if !engine.held_actors_has(&a) => self.owed.unwant(&a),
                _ => {}
            }
        }
        Ok(ran)
    }

    /// Drops each held actor whose drop settles due (`lost_now`: `lost_due` and `lost_passed`, or
    /// a loss by an `until` alone heard out or past its wait; `Engine::drop_lost`); whether one
    /// dropped (the engine's rows moved: the next round settles them).
    /// O(actors added and keys moved).
    fn drop_lost(&mut self, engine: &mut Engine, hears: &mut impl Hears) -> Result<bool> {
        for a in self.lost.due() {
            match self.lost.try_settle(&a, || lost_now(engine, hears, &a))? {
                Some((_, true)) => match isolate(engine.drop_lost(&a)) {
                    Ok(Some(true)) => return Ok(true),
                    Ok(_) => {}
                    Err(e) => {
                        self.lost.unwant(&a);
                        self.lost.want(a);
                        return Err(e);
                    }
                },
                Some((_, false)) if !engine.held_actors_has(&a) => self.lost.unwant(&a),
                _ => {}
            }
        }
        Ok(false)
    }

    fn lifetimes(&mut self, engine: &mut Engine, store: &Store, hears: &mut impl Hears) -> Result<bool> {
        for (s, was, now) in self.syncs.settle(store) {
            if let Some((t, _)) = was
                && let Some(ids) = self.ids.get_mut(&t)
            {
                ids.remove(&s);
                if ids.is_empty() {
                    self.ids.remove(&t);
                }
            }
            match now {
                Some((t, _)) => {
                    self.ids.entry(t).or_default().insert(s);
                    self.heard.want(s);
                }
                None => {
                    self.heard.unwant(&s);
                    self.heard_now.remove(&s);
                }
            }
        }
        for s in self.heard.due() {
            if let Some((was, now)) = self.heard.try_settle(&s, || hears.heard_out(engine, &s))? {
                self.newly |= now && was != Some(true);
                self.heard_now.insert(s, now);
            }
        }
        if !self.due.due().is_empty()
            && let Some((_, v)) = self.due.try_settle(&(), || engine.lifetimes_due())?
        {
            self.last = v;
        }
        let (work, held) = self.last;
        if !work && !(held && self.newly) {
            return Ok(false);
        }
        let (ids, heard_now) = (&self.ids, &self.heard_now);
        // a group is heard out when every sync ID synced of it is (none: at once)
        let heard = |g: &Tid| ids.get(g).is_none_or(|ss| ss.iter().all(|s| heard_now.get(s) == Some(&true)));
        engine.judge_lifetimes(&heard, self.newly)?;
        self.newly = false;
        Ok(true)
    }

    /// The holder duties: each thing named a holder whose value moved, a joined link that ended
    /// left, the tied edges due removed; a thing named a holder no more is followed no more.
    /// Whether it wrote.
    fn holders(&mut self, engine: &mut Engine) -> Result<bool> {
        let added: Vec<Tid> = match &mut self.pairs {
            Some(f) => f.added().into_iter().map(|(_, t)| t).collect(),
            None => {
                let (f, all) = engine.role_things();
                self.pairs = Some(f);
                all.into_iter().collect()
            }
        };
        for t in added {
            self.leaves.want(t);
            self.unties.want(t);
        }
        let mut acted = false;
        // `untie_due` reads the thing's holders, so its key is due when the last one goes
        for t in self.unties.due() {
            if !engine.named_a_holder(&t) {
                // judged once more with no holder: the engine forgets its ties' places (`jc/`)
                isolate(engine.untie_due(&t))?;
                self.unties.unwant(&t);
                self.leaves.unwant(&t);
                continue;
            }
            // acted on whenever judged, not only when it changed: a write refused is tried again
            // when what the value read moves
            let mut gs = BTreeSet::new();
            self.unties.try_settle(&t, || isolate(engine.untie_due(&t)).map(|v| v.unwrap_or_default()).inspect(|v| gs.clone_from(v)))?;
            for g in gs {
                acted |= wrote(engine.untie(&t, &g))?;
            }
        }
        for k in self.leaves.due() {
            let mut ended = false;
            self.leaves.settle(&k, || {
                ended = engine.joined_link_ended(&k);
                ended
            });
            if ended {
                acted |= wrote(engine.leave_link(&k))?;
            }
        }
        Ok(acted)
    }

    /// Tests: whether a holder duty follows `t`.
    #[doc(hidden)]
    pub fn holder_duties_follow(&self, t: &Tid) -> bool {
        self.leaves.wants(t) || self.unties.wants(t)
    }
}

/// Held actor `a`'s drop is due (`Life::drop_lost`): lost, its complete pass done; or lost by an
/// `until` alone (spec/permissions.md §2) and past its wait or each sync ID of it heard out. An
/// engine error but a store failure is this actor's alone (`isolate`: not due).
fn lost_now(engine: &mut Engine, hears: &mut impl Hears, a: &Tid) -> Result<bool> {
    if isolate(engine.lost_due(a))? == Some(true) {
        return Ok(isolate(engine.lost_passed(a))?.unwrap_or(false));
    }
    let Some(Some(t)) = isolate(engine.lost_timed(a))? else { return Ok(false) };
    if engine.reached(t.wait_end) {
        return Ok(true);
    }
    for (s, passed) in &t.ids {
        if !hears.timed_heard(engine, s, *passed)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// One duty's engine result, isolated: a store failure goes up (the step fails and restarts);
/// any other error is that duty's alone, `None` (its key parked until what it read moves).
fn isolate<T>(r: std::result::Result<T, osis_engine::Error>) -> Result<Option<T>> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e @ osis_engine::Error::Store(_)) => Err(e.into()),
        Err(_) => Ok(None),
    }
}

/// A duty's write: a store failure fails the step; any other refusal writes nothing (the value
/// is judged again when what it read moves). Whether it wrote.
fn wrote<T>(r: std::result::Result<T, osis_engine::Error>) -> Result<bool> {
    match r {
        Ok(_) => Ok(true),
        Err(e @ osis_engine::Error::Store(_)) => Err(e.into()),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::isolate;

    // spec: none (failure isolation, notes/sync-driver.md Failures): one duty's engine error is
    // its own: a store failure goes up (the step fails and restarts), any other parks that duty
    // alone (`None`) so the others run.
    #[test]
    fn a_duty_error_is_its_own_unless_the_store_failed() {
        assert_eq!(isolate(Ok::<u8, osis_engine::Error>(1)).unwrap(), Some(1));
        assert_eq!(isolate(Err::<u8, _>(osis_engine::Error::Misuse("one actor"))).unwrap(), None);
        assert!(isolate(Err::<u8, _>(osis_engine::Error::Store(osis_store::Error::Corrupt("disk")))).is_err());
    }
}
