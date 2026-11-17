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

/// The retention of every delta of an ephemeral commit: `writer` (spec/commits.md §2).
pub const EPHEMERAL_RETENTION: Retention = Retention { by: PurgeBy::Writer };

/// The AK of the creation record.
pub const CREATED: &str = "created.0";

/// The AK of a thing's history setting (spec/commits.md §5 The setting).
pub const RETENTION: &str = "retention^.0";

/// The AK of the delta a purge request with nothing to reset carries.
pub const PURGE: &str = "purge.0";

/// Whether a delta of `ak` is a destroying request's, what tells another node its thing was
/// destroyed (spec/commits.md §5 Destruction): a purge's `purge.0`.
pub fn destroying_request(ak: &str) -> bool {
    ak == PURGE
}

/// Role-class aspects and `addenda.0`: fixed `ROLE_RETENTION`, each replaced delta kept
/// `ROLE_KEEP` after replaced.
pub fn role_kept(ak: &str) -> bool {
    is_role_class(ak) || is_addenda(ak)
}

/// Fixed retention of an AK, if it has one (role-class aspects, `addenda.0`, `purge.0`): no
/// setting governs it.
pub fn fixed_retention(ak: &str) -> Option<Retention> {
    if destroying_request(ak) {
        // a commit carrying a request carries no `expires` from a setting
        Some(Retention { by: PurgeBy::AuthorOrAdmin })
    } else if role_kept(ak) {
        // an addendum is kept like a role commit: the judgment reads its delta, never a snapshot
        Some(ROLE_RETENTION)
    } else {
        None
    }
}

/// Retention of a write: the fixed one, else the commit's override, else the schema's default
/// for the AK, else the untyped default (`admin`). An override that disagrees with a
/// fixed retention is refused.
pub fn write_retention(ak: &str, defaults: Option<&AspectDefaults>, set: Option<Retention>) -> Result<Retention, Error> {
    match (fixed_retention(ak), set) {
        (Some(f), Some(s)) if f != s => Err(Error::Build("retention of this aspect is fixed")),
        (Some(f), _) => Ok(f),
        (None, Some(s)) => Ok(s),
        (None, None) => Ok(defaults.map(|d| d.retention).unwrap_or_default()),
    }
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
        PurgeBy::Admin => &[DELETE_ADMIN],
        PurgeBy::AuthorOrAdmin => &[DELETE_ADMIN, DELETE_AUTHOR],
        PurgeBy::Writer => &[DELETE_ADMIN, DELETE_AUTHOR, DELETE_WRITER],
    }
}

/// What a setting's entry says of an AK's replaced bodies (spec/commits.md §5 The setting).
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

/// The `purge_before` an entry carries for its AKs: `wall` where it purges on replace (the writer
/// replacing it stamps the floor), else its own.
fn carried(e: &osis_schema::core_types::RetentionEntry, wall: u64) -> Option<u64> {
    match e.history {
        Some(History::PurgeOnReplace) => Some(e.purge_before.map_or(wall, |f| f.max(wall))),
        _ => e.purge_before,
    }
}

/// Fills the floors of setting `s` a writer writes at wall ms `wall` while `prev` is its current
/// setting (spec/commits.md §5 One way): each entry's `purge_before` is at least the one the
/// entry governing its AKs in `prev` carries (`wall` where that one purges on replace); the
/// floors of AKs losing their own entry go to the default, one with no history if there is none.
/// So content written while purge on replace governed it stays under purge on replace in every
/// later setting.
pub fn carry_floors(s: &mut osis_schema::core_types::RetentionSetting, prev: Option<&osis_schema::core_types::RetentionSetting>, wall: u64) {
    let Some(prev) = prev else { return };
    let max = |a: Option<u64>, b: Option<u64>| a.max(b);
    for (ak, e) in s.rules.iter_mut() {
        e.purge_before = max(e.purge_before, prev.entry(ak).and_then(|p| carried(p, wall)));
    }
    let lost = prev.rules.iter().filter(|(ak, _)| !s.rules.contains_key(*ak)).map(|(_, e)| carried(e, wall));
    let floor = prev.default.iter().map(|e| carried(e, wall)).chain(lost).max().flatten();
    if floor.is_some() {
        let d = s.default.get_or_insert_with(Default::default);
        d.purge_before = max(d.purge_before, floor);
    }
}

#[cfg(test)]
mod floor_tests {
    use super::*;
    use osis_base::Ak;
    use osis_schema::core_types::{RetentionEntry, RetentionSetting};

    fn ak(s: &str) -> Ak {
        Ak::new(s).unwrap()
    }

    // spec/commits.md §5 One way: a writer replacing purge on replace stamps the floor; every
    // later setting carries it, an AK losing its own entry on the default
    #[test]
    fn floors_carried_spec_commits_5() {
        let keep = RetentionEntry { history: Some(History::FOREVER), ..Default::default() };
        let p = RetentionSetting::of(ak("x.0"), History::PurgeOnReplace);
        let mut k = RetentionSetting::from_iter([(ak("x.0"), keep)]);
        carry_floors(&mut k, Some(&p), 30);
        assert_eq!(k.rules[&ak("x.0")].purge_before, Some(30));
        assert_eq!(k.default, None);
        let mut k2 = RetentionSetting::from_iter([(ak("x.0"), keep)]);
        carry_floors(&mut k2, Some(&k), 50);
        assert_eq!(k2.rules[&ak("x.0")].purge_before, Some(30));
        // x.0 falls to the default: the default carries its floor
        let mut d = RetentionSetting { default: Some(keep), ..Default::default() };
        carry_floors(&mut d, Some(&k2), 60);
        assert_eq!(d.default.unwrap().purge_before, Some(30));
        let mut none = RetentionSetting::default();
        carry_floors(&mut none, Some(&p), 70);
        assert_eq!(none.default, Some(RetentionEntry { purge_before: Some(70), ..Default::default() }));
        // no purge before: nothing to carry
        let mut fresh = RetentionSetting::default();
        carry_floors(&mut fresh, Some(&RetentionSetting::of(ak("x.0"), History::FOREVER)), 10);
        assert_eq!(fresh, RetentionSetting::default());
    }
}
