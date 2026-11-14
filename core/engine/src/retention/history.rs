//! The one door to a body's history (spec/commits.md §5 The setting, History): what history keeps
//! of a replaced body of an aspect of a thing, and until when. Every reader of a body's history
//! asks here: keep bounds and when a body was replaced (`bounds`), listing, undo, purge on
//! replace (`replace`), memory compaction, permanence, and node-sync's kept bodies (through
//! `Engine::part_keeps`, `permanent`). Its source is the thing's timeline
//! (`osis_commit::retention::Timeline`): its held valid `retention^.0` settings in key order
//! (`validity::Judge::settings`), each read for the AK. A fixed-retention aspect has no timeline:
//! `ROLE_KEEP` after replaced for a role-class aspect or `addenda.0` (compactor policy), never
//! out of history for `created.0` and `retention^.0`, no history for `purge.0` and `released.0`.

use crate::engine::Core;
use osis_base::format::ROLE_KEEP_MS;
use osis_base::{Ak, Tid};
use osis_commit::FOREVER;
use osis_commit::retention::{Opt, Timeline};

/// What history keeps of the bodies of one aspect of a thing (`of`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Kept {
    /// The thing's timeline for the AK (empty for a fixed-retention aspect).
    tl: Timeline,
    /// Fixed retention: `ROLE_KEEP` after replaced (role-class, `addenda.0`).
    role: bool,
    /// Fixed retention: never out of history (`created.0`, `retention^.0`).
    always: bool,
}

/// What history keeps of the bodies of `(tid, ak)`: the thing's timeline read for `ak`. Cost:
/// O(the thing's held settings).
pub(crate) fn of(core: &Core, tid: &Tid, ak: &Ak) -> Kept {
    let a = ak.as_str();
    if osis_commit::retention::role_kept(a) {
        return Kept { role: true, ..Kept::default() };
    }
    if osis_commit::retention::fixed_retention(a).is_some() {
        return Kept { always: !osis_commit::retention::destroying_request(a), ..Kept::default() };
    }
    let settings = crate::apply::validity::settings(core, tid);
    // a fire is history from its own `ts`: purge on replace reads as no history there
    let signal = ak.signal();
    let tl = Timeline::new(settings.iter().map(|(p, s)| {
        let o = Opt::of(s.entry(ak));
        (p.ts.wall_ms().0, if signal && o == Opt::Purge { Opt::None } else { o })
    }));
    Kept { tl, ..Kept::default() }
}

/// The setting in force on `tid` now as one setting reads alone (spec/commits.md §5 One way): the
/// newest valid one held, with each `keep` the one-way rule voids (an earlier setting purging that
/// AK on replace) written as no history, for each AK any held setting names and for the default.
/// What a grant without history writes again under its cut (spec/crypto.md §4, Floors): its
/// holder opens no earlier setting. `None` without a setting.
pub(crate) fn in_force_alone(core: &Core, tid: &Tid) -> Option<osis_schema::core_types::RetentionSetting> {
    use osis_schema::History;
    let all = crate::apply::validity::settings(core, tid);
    let ((_, last), earlier) = all.split_last()?;
    let keeps = |e: Option<&osis_schema::core_types::RetentionEntry>| matches!(e.and_then(|x| x.history), Some(History::Keep { .. }));
    let purged = |e: Option<&osis_schema::core_types::RetentionEntry>| matches!(e.and_then(|x| x.history), Some(History::PurgeOnReplace));
    let mut out = (**last).clone();
    let aks: std::collections::BTreeSet<Ak> = all.iter().flat_map(|(_, s)| s.rules.keys().cloned()).collect();
    for k in aks {
        if keeps(last.entry(&k)) && earlier.iter().any(|(_, s)| purged(s.entry(&k))) {
            let e = last.entry(&k).cloned().map(|e| osis_schema::core_types::RetentionEntry { history: None, ..e });
            out.rules.extend(e.map(|e| (k, e)));
        }
    }
    if keeps(last.default.as_ref()) && earlier.iter().any(|(_, s)| purged(s.default.as_ref())) {
        out.default = out.default.map(|e| osis_schema::core_types::RetentionEntry { history: None, ..e });
    }
    Some(out)
}

/// Whether delta `a` of `h` is permanent (spec/commits.md §5): durable, no expiry, an aspect with
/// no fixed retention, and a body of its AK replaced now would never leave history. It leaves
/// by purge request, and leaves its header behind for good.
pub(crate) fn permanent(core: &Core, h: &osis_commit::Header, a: &osis_commit::AspectEntry, now: u64) -> bool {
    h.ephemeral.is_none() && h.expires.is_none() && osis_commit::retention::fixed_retention(a.ak.as_str()).is_none() && of(core, &a.tid, &a.ak).forever(now)
}

impl Kept {
    /// The wall ms before which a body replaced at wall ms `replaced` is in history (0: never in
    /// it, as when replaced under no history or purge on replace); `None`: not replaced, so in
    /// no history (a live body is in the state).
    pub(crate) fn leaves_at(&self, replaced: Option<u64>) -> u64 {
        if self.always {
            return FOREVER;
        }
        let Some(r) = replaced else { return 0 };
        if self.role {
            return r.saturating_add(ROLE_KEEP_MS);
        }
        self.tl.kept_until(r)
    }

    /// Until when a live body of the aspect is kept (spec/commits.md §5 Kept while live; 0: not
    /// kept, so a cover drops it at once): for good for fixed retention that keeps one (role-class,
    /// `created.0`, `retention^.0`), else the timeline's `live_until`.
    pub(crate) fn live_until(&self) -> u64 {
        if self.always || self.role {
            return osis_commit::retention::NEVER;
        }
        self.tl.live_until()
    }

    /// Whether when a body leaves depends on when it was replaced (only then is it dated,
    /// `bounds::part_replaced_at`): some setting keeps history.
    pub(crate) fn dated(&self) -> bool {
        self.role || self.tl.keeps()
    }

    /// Whether some setting keeps history (`dated`, but for role bodies' fixed keep).
    pub(crate) fn keeps(&self) -> bool {
        self.tl.keeps()
    }

    /// Whether a body replaced at wall ms `r` is under purge on replace: the entry in force then
    /// says so.
    pub(crate) fn purge_on_replace(&self, r: u64) -> bool {
        self.tl.in_force(r) == Opt::Purge
    }

    /// Whether a body written at wall ms `written` is in history at `now` whenever it was
    /// replaced (it is replaced no earlier than written): an absolute bound past `now` in force
    /// from then on, with no later setting. Judged without dating it.
    pub(crate) fn kept_whenever_replaced(&self, written: u64, now: u64) -> bool {
        self.always || (self.settled_from(written) && matches!(self.tl.in_force(written), Opt::Keep { until, .. } if until > now))
    }

    /// Whether no setting is stamped after wall ms `t`: what is in force at `t` is in force from
    /// then on.
    pub(crate) fn settled_from(&self, t: u64) -> bool {
        self.tl.spans().iter().all(|x| x.0 <= t)
    }

    /// Whether some setting purges on replace (a body of the aspect may be under it).
    pub(crate) fn purges(&self) -> bool {
        self.tl.purges()
    }

    /// Whether a body replaced at wall ms `now` would never leave history.
    pub(crate) fn forever(&self, now: u64) -> bool {
        self.always || self.tl.kept_until(now) >= FOREVER
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kept_by_timeline_spec_commits_5() {
        // a role-class body is kept `ROLE_KEEP` after replaced, whatever the settings
        let role = Kept { role: true, ..Kept::default() };
        assert!(role.dated() && !role.keeps() && !role.purges());
        assert_eq!(role.leaves_at(Some(20)), 20 + ROLE_KEEP_MS);
        assert_eq!(role.leaves_at(None), 0);
        assert_eq!(role.live_until(), osis_commit::retention::NEVER);
        let k = Kept { tl: Timeline::new([(0, Opt::Keep { until: 100, after: 50 })]), ..Kept::default() };
        assert_eq!(k.leaves_at(None), 0);
        assert_eq!(k.live_until(), osis_commit::retention::NEVER);
        assert_eq!(k.leaves_at(Some(20)), 100);
        assert_eq!(k.leaves_at(Some(70)), 120);
        // purge on replace keeps nothing
        let p = Kept { tl: Timeline::new([(10, Opt::Purge)]), ..Kept::default() };
        assert!(p.purge_on_replace(20) && !p.purge_on_replace(5) && !p.keeps() && !p.dated());
        assert_eq!(p.leaves_at(Some(20)), 0);
        assert_eq!(p.live_until(), 0);
        assert!(Kept { tl: Timeline::new([(10, Opt::Keep { until: FOREVER, after: 0 })]), ..Kept::default() }.forever(20));
        assert!(Kept { always: true, ..Kept::default() }.forever(0));
    }
}
