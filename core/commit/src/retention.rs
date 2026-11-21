//! Retention and expiry: fixed tables, write defaults, keep bounds (spec/commits.md §5, §6).

use crate::header::{FOREVER, Header};
use crate::Error;
use osis_base::format::{DELETE_ADMIN, DELETE_AUTHOR, DELETE_WRITER, ROLE_KEEP_MS};
use osis_base::Ts;
use osis_base::Ak;
use osis_schema::core_types::{is_addenda, is_role_class, RetentionEntry, RetentionSetting};
use osis_schema::{AspectDefaults, History, PurgeBy};

/// The fixed retention of role-class deltas: `admin` (each node keeps a replaced one
/// `ROLE_KEEP`, `role_kept`).
pub const ROLE_RETENTION: PurgeBy = PurgeBy::Admin;

/// The retention of every delta of an ephemeral commit: `writer` (spec/commits.md §2).
pub const EPHEMERAL_RETENTION: PurgeBy = PurgeBy::Writer;

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
pub fn fixed_retention(ak: &str) -> Option<PurgeBy> {
    if destroying_request(ak) {
        // a commit carrying a request carries no `expires` from a setting
        Some(PurgeBy::AuthorOrAdmin)
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
pub fn write_retention(ak: &str, defaults: Option<&AspectDefaults>, set: Option<PurgeBy>) -> Result<PurgeBy, Error> {
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
pub fn entry_fits(e: &RetentionEntry) -> bool {
    let history = match e.history {
        Some(History::Keep { until, after }) => until.is_none_or(|t| t <= FOREVER) && after.is_none_or(|d| d < FOREVER),
        _ => true,
    };
    history && e.expires.is_none_or(|d| d > 0 && d < FOREVER)
}

/// Retention of a compaction-snapshot delta (spec/commits.md §5): an aspect with fixed retention
/// keeps it; any other is `writer` (its history is the thing's setting).
pub fn snapshot_retention(ak: &str) -> PurgeBy {
    fixed_retention(ak).unwrap_or(PurgeBy::Writer)
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
pub(crate) fn delete_levels(r: &PurgeBy) -> &'static [u8] {
    match r {
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
    pub fn of(e: Option<&RetentionEntry>) -> Opt {
        match e.and_then(|e| e.history) {
            Some(History::Keep { until, after }) => Opt::Keep { after: after.unwrap_or(0), until: until.unwrap_or(0) },
            Some(History::PurgeOnReplace) => Opt::Purge,
            None => Opt::None,
        }
    }
}

/// The entry governing `ak` in `s` (`None`: an AK no setting names, so the default).
fn governing<'a>(s: &'a RetentionSetting, ak: Option<&Ak>) -> Option<&'a RetentionEntry> {
    ak.map_or(s.default.as_ref(), |ak| s.entry(ak))
}

/// The `purge_before` of `ak` (`None`: an AK no setting names) joined over `held`, each setting
/// with the `ts` of the write it carries, in key order (spec/commits.md §5 One way): the greatest
/// of every held setting's floor there and, for each one but the newest whose entry there purges
/// on replace, the `ts` of the next held one, unless a held floor there is already past its own
/// (every floor is the `ts` of a setting written after the purging one, so it already covers what
/// was replaced while that one was in force). `Ts::ZERO`: none. O(held).
pub fn joined_floor(held: &[(Ts, &RetentionSetting)], ak: Option<&Ak>) -> Ts {
    let base = held.iter().filter_map(|(_, s)| governing(s, ak)?.purge_before).max().unwrap_or(Ts::ZERO);
    let purges = |s: &RetentionSetting| governing(s, ak).is_some_and(|e| e.history == Some(History::PurgeOnReplace));
    held.iter().zip(held.iter().skip(1)).filter(|(a, _)| purges(a.1) && base <= a.0).map(|(_, b)| b.0).fold(base, Ts::max)
}

/// Whether some floor joined over `held` is past the one its newest setting carries: a setting
/// written by an admin that did not hold a purging one, so the older settings still add to the
/// join (spec/commits.md §5 One way: kept until a setting carries it).
pub fn floors_unabsorbed(held: &[(Ts, &RetentionSetting)]) -> bool {
    let Some((_, cur)) = held.last() else { return false };
    let own = |ak: Option<&Ak>| governing(cur, ak).and_then(|e| e.purge_before).unwrap_or(Ts::ZERO);
    let named = held.iter().flat_map(|(_, s)| s.rules.keys());
    named.map(Some).chain([None]).any(|ak| joined_floor(held, ak) > own(ak))
}

/// Fills the floors of setting `s` a writer writes at `ts` holding the valid settings `held` (in
/// key order, each before it; spec/commits.md §5 One way): each entry's `purge_before` is at
/// least the floor of its AKs joined over `held` and `s`; the default's at least that of every AK
/// `held` names that `s` does not, and of those none names (one with no history if there is
/// none). So content written while purge on replace governed it, by any admin's setting the
/// writer holds, stays under purge on replace in every later setting.
pub fn carry_floors(s: &mut RetentionSetting, held: &[(Ts, &RetentionSetting)], ts: Ts) {
    let new = s.clone();
    let all: Vec<(Ts, &RetentionSetting)> = held.iter().copied().chain([(ts, &new)]).collect();
    for (ak, e) in s.rules.iter_mut() {
        let f = joined_floor(&all, Some(ak));
        e.purge_before = e.purge_before.max((f > Ts::ZERO).then_some(f));
    }
    let lost = held.iter().flat_map(|(_, x)| x.rules.keys()).filter(|ak| !new.rules.contains_key(*ak));
    let floor = lost.map(|ak| joined_floor(&all, Some(ak))).fold(joined_floor(&all, None), Ts::max);
    if floor > Ts::ZERO {
        let d = s.default.get_or_insert_with(Default::default);
        d.purge_before = d.purge_before.max(Some(floor));
    }
}

#[cfg(test)]
mod floor_tests {
    use super::*;

    fn ak(s: &str) -> Ak {
        Ak::new(s).unwrap()
    }

    fn t(n: u64) -> Ts {
        Ts::from_u64(n).unwrap()
    }

    // spec/commits.md §5 One way: a writer replacing purge on replace stamps the floor; every
    // later setting carries it, an AK losing its own entry on the default
    #[test]
    fn floors_carried_spec_commits_5() {
        let keep = RetentionEntry { history: Some(History::FOREVER), ..Default::default() };
        let p = RetentionSetting::of(ak("x.0"), History::PurgeOnReplace);
        let mut k = RetentionSetting::from_iter([(ak("x.0"), keep)]);
        carry_floors(&mut k, &[(t(10), &p)], t(30));
        assert_eq!(k.rules[&ak("x.0")].purge_before, Some(t(30)));
        assert_eq!(k.default, None);
        let mut k2 = RetentionSetting::from_iter([(ak("x.0"), keep)]);
        carry_floors(&mut k2, &[(t(10), &p), (t(30), &k)], t(50));
        assert_eq!(k2.rules[&ak("x.0")].purge_before, Some(t(30)));
        // x.0 falls to the default: the default carries its floor
        let mut d = RetentionSetting { default: Some(keep), ..Default::default() };
        carry_floors(&mut d, &[(t(50), &k2)], t(60));
        assert_eq!(d.default.unwrap().purge_before, Some(t(30)));
        let mut none = RetentionSetting::default();
        carry_floors(&mut none, &[(t(10), &p)], t(70));
        assert_eq!(none.default, Some(RetentionEntry { purge_before: Some(t(70)), ..Default::default() }));
        // no purge before: nothing to carry
        let mut fresh = RetentionSetting::default();
        carry_floors(&mut fresh, &[(t(10), &RetentionSetting::of(ak("x.0"), History::FOREVER))], t(10));
        assert_eq!(fresh, RetentionSetting::default());
    }

    // spec/commits.md §5 One way: concurrent admins: a keep written without the purging setting
    // carries no floor, yet a node holding both joins one at the keep's stamp, whichever order it
    // holds them in; a setting written holding both carries it, and then the older add nothing
    #[test]
    fn floors_join_over_concurrent_settings_spec_commits_5() {
        let keep = RetentionEntry { history: Some(History::FOREVER), ..Default::default() };
        let p = RetentionSetting::of(ak("x.0"), History::PurgeOnReplace);
        let mut k = RetentionSetting::from_iter([(ak("x.0"), keep)]);
        carry_floors(&mut k, &[], t(30));
        assert_eq!(k.rules[&ak("x.0")].purge_before, None);
        let held = [(t(10), &p), (t(30), &k)];
        assert_eq!(joined_floor(&held, Some(&ak("x.0"))), t(30));
        assert_eq!(joined_floor(&held, Some(&ak("y.0"))), Ts::ZERO, "another AK: no purge there");
        assert!(floors_unabsorbed(&held));
        let mut c = RetentionSetting::from_iter([(ak("x.0"), keep)]);
        carry_floors(&mut c, &held, t(50));
        assert_eq!(c.rules[&ak("x.0")].purge_before, Some(t(30)));
        for held in [&[(t(10), &p), (t(30), &k), (t(50), &c)][..], &[(t(10), &p), (t(50), &c)], &[(t(50), &c)]] {
            assert_eq!(joined_floor(held, Some(&ak("x.0"))), t(30));
            assert!(!floors_unabsorbed(held));
        }
    }

    // spec/commits.md §5 One way: floors are whole `ts`, so two settings in one ms stay ordered:
    // a keep right after a purge in the same ms floors past the purge's own `ts`, and a node that
    // holds the purge and a later setting carrying that floor, but not the keep, joins the keep's
    // `ts`, not the later setting's
    #[test]
    fn floors_order_settings_within_one_ms_spec_commits_5() {
        let keep = RetentionEntry { history: Some(History::FOREVER), ..Default::default() };
        let ms = |w: u64, l: u64| Ts::make(osis_base::WallMs(w), l).unwrap();
        let p = RetentionSetting::of(ak("x.0"), History::PurgeOnReplace);
        let mut k = RetentionSetting::from_iter([(ak("x.0"), keep)]);
        carry_floors(&mut k, &[(ms(10, 0), &p)], ms(10, 1));
        assert_eq!(k.rules[&ak("x.0")].purge_before, Some(ms(10, 1)));
        let mut z = RetentionSetting::from_iter([(ak("x.0"), keep)]);
        carry_floors(&mut z, &[(ms(10, 0), &p), (ms(10, 1), &k)], ms(20, 0));
        assert_eq!(joined_floor(&[(ms(10, 0), &p), (ms(20, 0), &z)], Some(&ak("x.0"))), ms(10, 1));
        assert!(!floors_unabsorbed(&[(ms(10, 0), &p), (ms(20, 0), &z)]));
    }
}
