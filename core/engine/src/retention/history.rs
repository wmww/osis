//! The one door to a body's history (spec/commits.md §5 The setting, History): what history keeps
//! of a replaced body of an aspect of a thing, and until when. Every reader of a body's history
//! asks here: keep bounds and when a body was replaced (`bounds`), listing, undo, purge on
//! replace (`replace`), memory compaction, permanence, and node-sync's kept bodies (through
//! `Engine::part_keeps`, `permanent`). Its source is the thing's current setting
//! (`validity::setting_now`: the newest held valid `retention^.0` body) read for the AK. Purge on
//! replace carries its past as a floor, joined over every held valid setting
//! (`osis_commit::retention::joined_floor`; a writer writes the join, `carry_floors`), so a
//! setting written by an admin that never held a concurrent purging one loses nothing here; while
//! the older settings still add to the join they are kept (`retention^.0` in history for good).
//! A fixed-retention
//! aspect has no setting: `ROLE_KEEP` after replaced for a role-class aspect or `addenda.0`
//! (compactor policy), no history for `purge.0`.

use crate::engine::Core;
use osis_base::format::ROLE_KEEP_MS;
use osis_base::{Ak, Tid};
use osis_commit::FOREVER;
use osis_commit::retention::Opt;

/// When a body never leaves history.
pub(crate) const NEVER: u64 = u64::MAX;

/// What history keeps of the bodies of one aspect of a thing (`of`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Kept {
    /// The current setting's entry for the AK (purge on replace reading as no history on a signal).
    opt: Opt,
    /// Its `purge_before` joined over the held settings (0: none): a body holding a dead write
    /// stamped before it is under purge on replace.
    floor: u64,
    /// Fixed retention: `ROLE_KEEP` after replaced (role-class, `addenda.0`).
    role: bool,
}

impl Default for Kept {
    fn default() -> Kept {
        Kept { opt: Opt::None, floor: 0, role: false }
    }
}

/// What history keeps of the bodies of `(tid, ak)`: the current setting read for `ak`, with the
/// floor joined over every held valid setting. `retention^.0` itself is kept for good while the
/// older settings add to the join (`floors_unabsorbed`: no setting carries it yet, so no cover
/// may drop them and sync holds them as must-hold). O(the thing's held settings).
pub(crate) fn of(core: &Core, tid: &Tid, ak: &Ak) -> Kept {
    let a = ak.as_str();
    if osis_commit::retention::role_kept(a) {
        return Kept { role: true, ..Kept::default() };
    }
    if osis_commit::retention::fixed_retention(a).is_some() {
        return Kept::default();
    }
    let all = crate::apply::validity::settings(core, tid);
    let Some((_, s)) = all.last() else { return Kept::default() };
    let held: Vec<(u64, &osis_schema::core_types::RetentionSetting)> = all.iter().map(|(p, x)| (p.ts.wall_ms().0, &**x)).collect();
    if a == osis_commit::retention::RETENTION && osis_commit::retention::floors_unabsorbed(&held) {
        return Kept { opt: Opt::Keep { after: 0, until: FOREVER }, ..Kept::default() };
    }
    let o = Opt::of(s.entry(ak));
    // a fire is history from its own `ts`: purge on replace reads as no history there
    let opt = if ak.signal() && o == Opt::Purge { Opt::None } else { o };
    Kept { opt, floor: osis_commit::retention::joined_floor(&held, Some(ak)), ..Kept::default() }
}

/// Whether delta `a` of `h` is permanent (spec/commits.md §5): durable, no expiry, an aspect with
/// no fixed retention, and a body of it replaced now would never leave history. It leaves by
/// purge request, and leaves its header behind for good.
pub(crate) fn permanent(core: &Core, h: &osis_commit::Header, a: &osis_commit::AspectEntry) -> bool {
    h.ephemeral.is_none() && h.expires.is_none() && osis_commit::retention::fixed_retention(a.ak.as_str()).is_none() && of(core, &a.tid, &a.ak).forever(h.ts.wall_ms().0)
}

impl Kept {
    /// Whether a body whose oldest dead write is stamped at wall ms `written` is under the floor.
    fn floored(&self, written: u64) -> bool {
        written < self.floor
    }

    /// The wall ms before which a body replaced at wall ms `replaced`, its oldest dead write
    /// stamped at `written`, is in history (0: never in it, as when replaced under no history,
    /// purge on replace or before the floor); `None`: not replaced, so in no history (a live body
    /// is in the state).
    pub(crate) fn leaves_at(&self, replaced: Option<u64>, written: u64) -> u64 {
        let Some(r) = replaced else { return 0 };
        if self.role {
            return r.saturating_add(ROLE_KEEP_MS);
        }
        match self.opt {
            Opt::Keep { after, until } if !self.floored(written) => {
                let o = r.saturating_add(after).max(until);
                if o > r { o } else { 0 }
            }
            _ => 0,
        }
    }

    /// Until when a live body of the aspect written at wall ms `written` is kept (spec/commits.md
    /// §5 Kept while live; 0: not kept, so a cover drops it at once): while a replacement of it
    /// would be kept. For good for role-class bodies.
    pub(crate) fn live_until(&self, written: u64) -> u64 {
        if self.role {
            return NEVER;
        }
        match self.opt {
            Opt::Keep { after, .. } if after > 0 && !self.floored(written) => NEVER,
            Opt::Keep { until, .. } if !self.floored(written) => until,
            _ => 0,
        }
    }

    /// Whether when a body leaves depends on when it was replaced (only then is it dated,
    /// `bounds::part_replaced_at`): role bodies, or the current setting keeps history.
    pub(crate) fn dated(&self) -> bool {
        self.role || self.keeps()
    }

    /// Whether the current setting keeps history (`dated`, but for role bodies' fixed keep).
    pub(crate) fn keeps(&self) -> bool {
        matches!(self.opt, Opt::Keep { .. })
    }

    /// Whether a replaced body whose oldest dead write is stamped at wall ms `written` is under
    /// purge on replace: the entry purges on replace, or `written` is before its floor.
    pub(crate) fn purge_on_replace(&self, written: u64) -> bool {
        !self.role && (self.opt == Opt::Purge || self.floored(written))
    }

    /// Whether a body of the aspect may be under purge on replace.
    pub(crate) fn purges(&self) -> bool {
        !self.role && (self.opt == Opt::Purge || self.floor > 0)
    }

    /// The floor (0: none): a body none of whose writes is stamped before it is under purge on
    /// replace only if the entry is.
    pub(crate) fn floor(&self) -> u64 {
        self.floor
    }

    /// Whether a body written at wall ms `written` is in history at `now` whenever it was
    /// replaced (it is replaced no earlier than written): an absolute bound past `now`. Judged
    /// without dating it.
    pub(crate) fn kept_whenever_replaced(&self, written: u64, now: u64) -> bool {
        matches!(self.opt, Opt::Keep { until, .. } if until > now && !self.floored(written))
    }

    /// Whether a body written at wall ms `written`, replaced at any time, would never leave
    /// history.
    pub(crate) fn forever(&self, written: u64) -> bool {
        matches!(self.opt, Opt::Keep { until, .. } if until >= FOREVER && !self.floored(written))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kept_by_the_current_setting_spec_commits_5() {
        // a role-class body is kept `ROLE_KEEP` after replaced, whatever the settings
        let role = Kept { role: true, ..Kept::default() };
        assert!(role.dated() && !role.keeps() && !role.purges());
        assert_eq!(role.leaves_at(Some(20), 0), 20 + ROLE_KEEP_MS);
        assert_eq!(role.leaves_at(None, 0), 0);
        assert_eq!(role.live_until(0), NEVER);
        let k = Kept { opt: Opt::Keep { until: 100, after: 50 }, ..Kept::default() };
        assert_eq!(k.leaves_at(None, 0), 0);
        assert_eq!(k.live_until(0), NEVER);
        assert_eq!(k.leaves_at(Some(20), 0), 100);
        assert_eq!(k.leaves_at(Some(70), 0), 120);
        // purge on replace keeps nothing
        let p = Kept { opt: Opt::Purge, ..Kept::default() };
        assert!(p.purge_on_replace(20) && !p.keeps() && !p.dated());
        assert_eq!(p.leaves_at(Some(20), 0), 0);
        assert_eq!(p.live_until(0), 0);
        // a keep after purge on replace: what is written before its floor is under purge
        let f = Kept { opt: Opt::Keep { until: FOREVER, after: 0 }, floor: 30, ..Kept::default() };
        assert!(f.purges() && f.purge_on_replace(29) && !f.purge_on_replace(30));
        assert_eq!(f.leaves_at(Some(40), 29), 0);
        assert_eq!(f.leaves_at(Some(40), 30), FOREVER);
        assert!(f.forever(30) && !f.forever(29));
        assert_eq!(f.live_until(29), 0);
    }
}
