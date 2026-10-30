//! Retention and expiry: fixed tables, write defaults, keep bounds (spec/commits.md §5, §6).

use crate::header::{FOREVER, Header, Kind};
use crate::Error;
use osis_base::format::{AT_MOST_GRACE_MS, DELETE_ADMIN, DELETE_AUTHOR, DELETE_WRITER, MEMBERSHIP_KEEP_MS};
use osis_base::Ts;
use osis_schema::core_types::is_membership_class;
use osis_schema::{AspectDefaults, Bound, PurgeBy, Retention};

/// The fixed retention of membership deltas: `admin`, kept at least `MEMBERSHIP_KEEP` after
/// replaced.
pub const MEMBERSHIP_RETENTION: Retention =
    Retention { by: PurgeBy::Admin, at_least: Bound { abs: None, rel: Some(MEMBERSHIP_KEEP_MS) }, at_most: Bound { abs: None, rel: None } };

/// The fixed retention of `/created`: `nobody`, kept forever.
pub const CREATED_RETENTION: Retention =
    Retention { by: PurgeBy::Nobody, at_least: Bound { abs: Some(FOREVER), rel: None }, at_most: Bound { abs: None, rel: None } };

/// The AK of the creation record.
pub const CREATED: &str = "/created";

/// Fixed retention of an AK, if it has one (membership-class aspects, `/created`).
pub fn fixed_retention(ak: &str) -> Option<Retention> {
    if ak == CREATED {
        Some(CREATED_RETENTION)
    } else if is_membership_class(ak) {
        Some(MEMBERSHIP_RETENTION)
    } else {
        None
    }
}

/// A relative keep-at-most bound exists only under `writer`.
pub fn check_retention(r: &Retention) -> Result<(), Error> {
    if r.at_most.rel.is_some() && r.by != PurgeBy::Writer {
        return Err(Error::Invalid("relative keep at most needs purgeable by writer"));
    }
    Ok(())
}

/// Retention of a write: the fixed one, else the commit's override, else the schema's default
/// for the AK, else the untyped default (`author`, no bounds). An override that disagrees with a
/// fixed retention is refused.
pub fn write_retention(ak: &str, defaults: Option<&AspectDefaults>, set: Option<Retention>) -> Result<Retention, Error> {
    let r = match (fixed_retention(ak), set) {
        (Some(f), Some(s)) if f != s => return Err(Error::Build("retention of this aspect is fixed")),
        (Some(f), _) => f,
        (None, Some(s)) => s,
        (None, None) => defaults.map(|d| d.retention).unwrap_or_default(),
    };
    check_retention(&r).map_err(|_| Error::Build("relative keep at most needs purgeable by writer"))?;
    Ok(r)
}

/// Retention of a compaction-snapshot delta (spec/commits.md §5): an aspect with fixed retention
/// keeps it; any other is `writer` with, over `own` (the retentions standing for the writes the
/// snapshot carries live), the longest relative keep at least (no absolute one), and the
/// strictest keep at most: the shortest relative bound and the earliest absolute bound after
/// `now` (the snapshot's wall ms; one at or before it counts as a relative bound of 0).
pub fn snapshot_retention(ak: &str, own: impl IntoIterator<Item = Retention>, now: u64) -> Retention {
    if let Some(f) = fixed_retention(ak) {
        return f;
    }
    let (mut at_least, mut at_most) = (Bound::default(), Bound::default());
    for r in own {
        at_least.rel = at_least.rel.max(r.at_least.rel);
        // an absolute bound already passed counts as 0 after replaced: the write outlived its
        // bound only by being live, and its content goes as it dies
        let m = r.at_most;
        let passed = m.abs.is_some_and(|t| t <= now);
        at_most.rel = match (at_most.rel, if passed { Some(0) } else { m.rel }) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        at_most.abs = match (at_most.abs, m.abs.filter(|_| !passed)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }
    Retention { by: PurgeBy::Writer, at_least, at_most }
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
    Ok(t)
}

/// Keep-at-least bound of a body (wall ms; 0 = none): the later of `abs` and last death plus
/// `rel`. A body with no dead writes is past a relative bound.
pub fn keep_at_least(r: &Retention, last_death: Option<u64>) -> u64 {
    let rel = match (r.at_least.rel, last_death) {
        (Some(d), Some(t)) => t.saturating_add(d),
        _ => 0,
    };
    r.at_least.abs.unwrap_or(0).max(rel)
}

/// Keep-at-most bound of a body (wall ms): the earlier of `abs` and first death plus `rel`;
/// `None` while neither applies.
pub fn keep_at_most(r: &Retention, first_death: Option<u64>) -> Option<u64> {
    let rel = r.at_most.rel.zip(first_death).map(|(d, t)| t.saturating_add(d));
    match (r.at_most.abs, rel) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Floor on keeping the blobs of a commit carrying a purge request: `wall_ms(ts) +
/// MEMBERSHIP_KEEP`, whatever its deltas' bounds.
pub fn purge_keep_until(h: &Header) -> Option<u64> {
    (!h.purge.is_empty()).then(|| h.ts.wall_ms().0.saturating_add(MEMBERSHIP_KEEP_MS))
}

/// What a node must do with a body of `h` holding deltas of retention `r`, given the first and
/// last deaths of its writes so far (spec/commits.md §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keep {
    /// Before this wall ms the body leaves only by purge request (0 = no floor).
    pub at_least: u64,
    /// By this wall ms every node drops the body.
    pub at_most: Option<u64>,
}

/// Effective keep bounds: keep at most wins over keep at least, except the purge-request floor,
/// which wins over both. Expiry (applied by the caller) beats everything. While the body has a
/// live write (`live`), a relative keep at most D counts as D plus `AT_MOST_GRACE_MS` (the next
/// compaction, which covers it, usually drops it first).
pub fn body_keep(h: &Header, r: &Retention, first_death: Option<u64>, last_death: Option<u64>, live: bool) -> Keep {
    let mut r = *r;
    if live {
        r.at_most.rel = r.at_most.rel.map(|d| d.saturating_add(AT_MOST_GRACE_MS));
    }
    let r = &r;
    let most = keep_at_most(r, first_death);
    let mut least = keep_at_least(r, last_death);
    if let Some(m) = most {
        least = least.min(m);
    }
    match purge_keep_until(h) {
        Some(p) => Keep { at_least: least.max(p), at_most: most.map(|m| m.max(p)) },
        None => Keep { at_least: least, at_most: most },
    }
}

/// Delete levels a delta of retention `r` calls for (spec/crypto.md §7); level 2 is omitted for
/// an import.
pub fn delete_levels(r: &Retention, kind: Kind) -> &'static [u8] {
    let import = kind == Kind::Import;
    match r.by {
        PurgeBy::Nobody => &[],
        PurgeBy::Admin => &[DELETE_ADMIN],
        PurgeBy::Author if import => &[DELETE_ADMIN],
        PurgeBy::Author => &[DELETE_ADMIN, DELETE_AUTHOR],
        PurgeBy::Writer if import => &[DELETE_ADMIN, DELETE_WRITER],
        PurgeBy::Writer => &[DELETE_ADMIN, DELETE_AUTHOR, DELETE_WRITER],
    }
}
