//! Lifecycle duties the engine judges and sync drives, each as an `Effects` value over what makes
//! it due (notes/sync-driver.md, Duties).
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
//!   this node logged itself there is elsewhere; or no peer to be waited for on it), or at its
//!   wait's end (`LOST_HEARD_WAIT_MS`, read on the memo clock). One key over `Engine::copies_due` judges the kept copies again
//!   (`Engine::rejudge_copies`) where a role commit moved what one hangs on.
//! - **Joiner's leave** (spec/permissions.md §7): per thing named a holder, whether it is a link
//!   this account joined whose K's edge on its target ended (`Engine::joined_link_ended`); one
//!   that became so is left (`Engine::leave_link`).
//!
//! The joiner's leave follows every thing a holder is named on (`Engine::role_things`, then its
//! feed): what each value reads is stamped (records, timelines, passes, the clock up to the next
//! `until`), so a thing is judged again only when one of those moves. A holder duty's write refused for any reason but a store failure is tried again at the next move
//! of what the value read. A thing named a holder no more is followed no more.
//!
//! State: one value per thing named a holder here (unwanted when its last holder goes) and per
//! held actor. A restart settles every key afresh.

use crate::types::Result;
use osis_base::memo::{Effects, Feed};
use osis_base::{SyncId, Tid};
use osis_engine::Engine;

/// What life reads of sync per sync ID: stamped reads, so a duty is due again when one moves.
pub trait Hears {
    /// A loss by an `until` alone heard S out (spec/permissions.md §2): with a source of S, a
    /// complete pass of S begun after the loss ended (`passed`) and each own commit with an
    /// entry under S is held elsewhere; or no peer is to be waited for on S.
    fn timed_heard(&mut self, engine: &mut Engine, s: &SyncId, passed: bool) -> Result<bool>;
}

#[derive(Clone)]
pub struct Life {
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
}

impl Default for Life {
    fn default() -> Life {
        let mut copies = Effects::new("life: kept copies");
        copies.want(());
        Life { copies, lost: Effects::new("life: lost access"), actors: None, owed: Effects::new("life: role duty owed"), pairs: None, leaves: Effects::new("life: joiner's leave") }
    }
}

impl std::fmt::Debug for Life {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Life").finish_non_exhaustive()
    }
}

impl Life {
    /// Follows what moved; runs each duty when due. Whether one ran (the engine's rows moved:
    /// the next round settles them).
    pub fn settle(&mut self, engine: &mut Engine, hears: &mut impl Hears) -> Result<bool> {
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
        self.holders(engine)
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

    /// The holder duty: each thing named a holder whose value moved, a joined link that ended
    /// left; a thing named a holder no more is followed no more.
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
        }
        let mut acted = false;
        for k in self.leaves.due() {
            if !engine.named_a_holder(&k) {
                self.leaves.unwant(&k);
                continue;
            }
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
        self.leaves.wants(t)
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
