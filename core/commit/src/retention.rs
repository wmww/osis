//! Retention and expiry: fixed tables, write defaults, keep bounds (spec/commits.md §5, §6).

use crate::header::{FOREVER, Header};
use crate::Error;
use osis_base::format::{DELETE_ADMIN, DELETE_AUTHOR, DELETE_WRITER, ROLE_KEEP_MS};
use osis_base::Ts;
use osis_schema::core_types::{is_addenda, is_role_class};
use osis_schema::{AspectDefaults, History, PurgeBy, Retention};

/// The fixed retention of role-class deltas: `admin` (each node keeps a replaced one
/// `ROLE_KEEP`, `role_kept`).
pub const ROLE_RETENTION: Retention = Retention { by: PurgeBy::Admin };

/// `nobody`: the fixed retention of `retention^.0`, never out of history.
pub const KEPT_RETENTION: Retention = Retention { by: PurgeBy::Nobody };

/// The retention of every delta of an ephemeral commit: `writer` (spec/commits.md §2).
pub const EPHEMERAL_RETENTION: Retention = Retention { by: PurgeBy::Writer };

/// The AK of the creation record.
pub const CREATED: &str = "created.0";

/// The AK of a thing's history setting (spec/commits.md §5 The setting).
pub const RETENTION: &str = "retention^.0";

/// The AK of the delta a purge request with nothing to reset carries.
pub const PURGE: &str = "purge.0";

/// Role-class aspects and `addenda.0`: fixed `ROLE_RETENTION`, each replaced delta kept
/// `ROLE_KEEP` after replaced.
pub fn role_kept(ak: &str) -> bool {
    is_role_class(ak) || is_addenda(ak)
}

/// Fixed retention of an AK, if it has one (role-class aspects, `addenda.0`, `retention^.0`,
/// `purge.0`): no setting governs it.
pub fn fixed_retention(ak: &str) -> Option<Retention> {
    if ak == RETENTION {
        Some(KEPT_RETENTION)
    } else if ak == PURGE {
        // a commit carrying a request carries no `expires` from a setting
        Some(Retention { by: PurgeBy::AuthorOrAdmin })
    } else if role_kept(ak) {
        // an addendum is kept like a role commit: the judgment reads its delta, never a snapshot
        Some(ROLE_RETENTION)
    } else {
        None
    }
}

/// Whether a delta of `ak` may carry retention `r` (spec/commits.md §5): `nobody` only on
/// `created.0` and with fixed retention.
pub(crate) fn allowed(ak: &str, r: &Retention) -> Result<(), &'static str> {
    match r.refusal() {
        Some(m) if ak != CREATED && fixed_retention(ak).is_none() => Err(m),
        _ => Ok(()),
    }
}

/// Retention of a write: the fixed one, else the commit's override, else the schema's default
/// for the AK, else the untyped default (`author_or_admin`). An override that disagrees with a
/// fixed retention is refused, and so is `nobody` but on `created.0`.
pub fn write_retention(ak: &str, defaults: Option<&AspectDefaults>, set: Option<Retention>) -> Result<Retention, Error> {
    let r = match (fixed_retention(ak), set) {
        (Some(f), Some(s)) if f != s => return Err(Error::Build("retention of this aspect is fixed")),
        (Some(f), _) => return Ok(f),
        (None, Some(s)) => s,
        (None, None) => defaults.map(|d| d.retention).unwrap_or_default(),
    };
    allowed(ak, &r).map(|()| r).map_err(Error::Build)
}

/// Whether a setting's entry is one a writer can follow (spec/commits.md §5 The setting): an
/// expiry above 0 and below forever, history bounds within range (`until` at most `FOREVER`,
/// `after` below it).
pub fn entry_fits(e: &osis_schema::core_types::RetentionEntry) -> bool {
    let history = match e.history {
        Some(History::Keep { until, after }) => until.is_none_or(|t| t <= FOREVER) && after.is_none_or(|d| d < FOREVER),
        _ => true,
    };
    history && e.expires.is_none_or(|d| d > 0 && d < FOREVER)
}

/// Retention of a compaction-snapshot delta (spec/commits.md §5): an aspect with fixed retention
/// keeps it; any other is `writer` (its history is the thing's setting).
pub fn snapshot_retention(ak: &str) -> Retention {
    fixed_retention(ak).unwrap_or(Retention { by: PurgeBy::Writer })
}

/// Expiry of a write: an explicit T, else the schema's default duration from the write's `ts`.
/// Aspects with fixed retention never expire. A T above 2^63 - 1 is refused.
pub fn write_expires(ak: &str, ts: Ts, defaults: Option<&AspectDefaults>, set: Option<u64>) -> Result<Option<u64>, Error> {
    if fixed_retention(ak).is_some() {
        return Ok(None);
    }
    let t = match set {
        Some(t) => Some(t),
        None => defaults.and_then(|d| d.expires).map(|dur| ts.wall_ms().0.checked_add(dur).ok_or(Error::Build("expiry out of range"))).transpose()?,
    };
    if t.is_some_and(|t| t > FOREVER) {
        return Err(Error::Build("expiry out of range"));
    }
    // a `ts` ahead of the clock (a peer's fast clock read) has passed a short expiry: just after it
    Ok(t.map(|t| t.max(ts.wall_ms().0.saturating_add(1))))
}

/// Floor on keeping the blobs of a commit carrying a purge request: `wall_ms(ts) +
/// ROLE_KEEP`, whatever its deltas' bounds, ending at the commit's expiry.
pub fn purge_keep_until(h: &Header) -> Option<u64> {
    (!h.purge.is_empty()).then(|| h.ts.wall_ms().0.saturating_add(ROLE_KEEP_MS).min(h.expires.unwrap_or(u64::MAX)))
}

/// Delete levels a delta of retention `r` calls for (spec/crypto.md §7).
pub(crate) fn delete_levels(r: &Retention) -> &'static [u8] {
    match r.by {
        PurgeBy::Nobody => &[],
        PurgeBy::Admin => &[DELETE_ADMIN],
        PurgeBy::AuthorOrAdmin => &[DELETE_ADMIN, DELETE_AUTHOR],
        PurgeBy::Writer => &[DELETE_ADMIN, DELETE_AUTHOR, DELETE_WRITER],
    }
}

/// What one setting's entry says of an AK's replaced bodies (spec/commits.md §5 The setting).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opt {
    /// No history promised.
    None,
    /// Kept `after` ms past replaced and/or until wall ms `until`, the later (a missing bound
    /// counts as 0; `until` `FOREVER`: for good).
    Keep { after: u64, until: u64 },
    /// Purge on replace.
    Purge,
}

impl Opt {
    /// What entry `e` says (none: no history promised).
    pub fn of(e: Option<&osis_schema::core_types::RetentionEntry>) -> Opt {
        match e.and_then(|e| e.history) {
            Some(History::Keep { until, after }) => Opt::Keep { after: after.unwrap_or(0), until: until.unwrap_or(0) },
            Some(History::PurgeOnReplace) => Opt::Purge,
            None => Opt::None,
        }
    }
}

/// One AK's timeline (spec/commits.md §5 In force): the held valid settings of its thing in key
/// order, each as its entry for the AK reads under the one-way rule (where an earlier one purges
/// on replace, a later keep reads as no history), from its own wall ms.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Timeline(Vec<(u64, Opt)>);

/// When a body never leaves history: no setting ends it.
pub const NEVER: u64 = u64::MAX;

impl Timeline {
    /// From the settings in key order, each at its wall ms with its entry for the AK.
    pub fn new(settings: impl IntoIterator<Item = (u64, Opt)>) -> Timeline {
        let mut purged = false;
        Timeline(
            settings
                .into_iter()
                .map(|(t, o)| match o {
                    Opt::Purge => {
                        purged = true;
                        (t, o)
                    }
                    Opt::Keep { .. } if purged => (t, Opt::None),
                    o => (t, o),
                })
                .collect(),
        )
    }

    /// Whether no setting promises anything (every body leaves history when replaced).
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|x| x.1 == Opt::None)
    }

    /// The moment a body replaced at wall ms `r` leaves history (spec/commits.md §5 History): the
    /// first t >= r at which the setting in force (before the first: none) does not keep it;
    /// `NEVER` if none ends it.
    pub fn out(&self, r: u64) -> u64 {
        let mut best = NEVER;
        let mut from = 0;
        let mut opt = Opt::None;
        for i in 0..=self.0.len() {
            let to = self.0.get(i).map_or(NEVER, |x| x.0);
            let bound = match opt {
                Opt::Keep { after, until } => r.saturating_add(after).max(until),
                _ => r,
            };
            let e = bound.max(from).max(r);
            if e < to {
                best = best.min(e);
            }
            if let Some(x) = self.0.get(i) {
                (from, opt) = *x;
            }
        }
        best
    }

    /// The wall ms before which a body replaced at `r` is in history: `out(r)` when a setting
    /// keeps it past `r`, else 0 (a body replaced under no history, or purge on replace, is out
    /// when replaced, whenever that is).
    pub fn kept_until(&self, r: u64) -> u64 {
        let o = self.out(r);
        if o > r { o } else { 0 }
    }

    /// What is in force at wall ms `t` (the newest with its wall ms at or before `t`).
    pub fn in_force(&self, t: u64) -> Opt {
        self.0.iter().rev().find(|x| x.0 <= t).map_or(Opt::None, |x| x.1)
    }

    /// Whether some setting keeps a body (the timeline dates bodies by when they were replaced).
    pub fn keeps(&self) -> bool {
        self.0.iter().any(|x| matches!(x.1, Opt::Keep { .. }))
    }

    /// Whether some setting purges on replace.
    pub fn purges(&self) -> bool {
        self.0.iter().any(|x| x.1 == Opt::Purge)
    }

    /// The settings, as they read, in key order.
    pub fn spans(&self) -> &[(u64, Opt)] {
        &self.0
    }
}

#[cfg(test)]
mod timeline_tests {
    use super::*;

    fn keep(after: u64, until: u64) -> Opt {
        Opt::Keep { after, until }
    }

    // spec/commits.md §5 History: a setting acts from its own stamp; bodies leave in replaced order
    #[test]
    fn out_from_each_settings_stamp_spec_commits_5() {
        let none = Timeline::new([]);
        assert_eq!(none.out(5), 5);
        assert_eq!(none.kept_until(5), 0);
        let t = Timeline::new([(10, keep(5, 0))]);
        // replaced before the setting: out when replaced, nothing later reaches it
        assert_eq!(t.out(4), 4);
        assert_eq!(t.kept_until(4), 0);
        assert_eq!(t.out(12), 17);
        // a shortening at 20 ends what is still in history then
        let t = Timeline::new([(10, keep(50, 0)), (20, Opt::None)]);
        assert_eq!(t.out(12), 20);
        assert_eq!(t.out(25), 25);
        // a later extension reaches only what is still in history
        let t = Timeline::new([(10, keep(5, 0)), (30, keep(100, 0))]);
        assert_eq!(t.out(12), 17);
        assert_eq!(t.out(28), 128);
        // forever
        assert_eq!(Timeline::new([(10, keep(0, FOREVER))]).out(12), FOREVER);
        assert_eq!(Timeline::new([(10, keep(0, FOREVER))]).in_force(9), Opt::None);
    }

    // spec/commits.md §5 One way: once purge on replace, a later keep keeps nothing
    #[test]
    fn purge_then_keep_keeps_nothing_spec_commits_5() {
        let t = Timeline::new([(10, Opt::Purge), (20, keep(100, FOREVER))]);
        assert_eq!(t.in_force(25), Opt::None);
        assert_eq!(t.kept_until(25), 0);
        assert_eq!(t.in_force(15), Opt::Purge);
        assert_eq!(t.kept_until(15), 0);
        // purge on replace keeps nothing even replaced ahead of any clock
        assert_eq!(Timeline::new([(10, Opt::Purge)]).kept_until(1_000), 0);
    }
}
