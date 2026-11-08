//! Retention and expiry: fixed tables, write defaults, keep bounds (spec/commits.md §5, §6).

use crate::header::{AspectEntry, FOREVER, Header};
use crate::Error;
use osis_base::format::{DELETE_ADMIN, DELETE_AUTHOR, DELETE_WRITER, ROLE_KEEP_MS};
use osis_base::Ts;
use osis_schema::core_types::{is_addenda, is_role_class};
use osis_schema::{AspectDefaults, History, PurgeBy, Retention};

/// The fixed retention of role-class deltas: `admin`, no history promised (each node keeps a
/// replaced one `ROLE_KEEP`, `keep_rule`).
pub const ROLE_RETENTION: Retention = Retention { by: PurgeBy::Admin, history: None };

/// The fixed retention of `created.0`: `nobody`, kept forever.
pub const CREATED_RETENTION: Retention = Retention { by: PurgeBy::Nobody, history: Some(History::FOREVER) };

/// The retention of every delta of an ephemeral commit: `writer`, no history promised
/// (spec/commits.md §2).
pub const EPHEMERAL_RETENTION: Retention = Retention { by: PurgeBy::Writer, history: None };

/// The AK of the creation record.
pub const CREATED: &str = "created.0";

/// The AK of a thing's required retention.
pub const REQUIRED: &str = "required^.0";

/// The AK of the delta a purge request with nothing to reset carries.
pub const PURGE: &str = "purge.0";

/// Role-class aspects and `addenda.0`: fixed `ROLE_RETENTION`, each replaced delta kept
/// `ROLE_KEEP` after replaced.
fn role_kept(ak: &str) -> bool {
    is_role_class(ak) || is_addenda(ak)
}

/// Fixed retention of an AK, if it has one (role-class aspects, `addenda.0`, `created.0`, `required^.0`,
/// `purge.0`).
pub fn fixed_retention(ak: &str) -> Option<Retention> {
    if ak == CREATED || ak == REQUIRED {
        Some(CREATED_RETENTION)
    } else if ak == PURGE {
        // no required retention reaches it: a required expiry would forbid every purge request
        // (a commit with one carries no `expires`)
        Some(Retention { by: PurgeBy::AuthorOrAdmin, history: None })
    } else if role_kept(ak) {
        // an addendum is kept like a role commit: the judgment reads its delta, never a snapshot
        Some(ROLE_RETENTION)
    } else {
        None
    }
}

/// A retention a delta may carry (spec/commits.md §5, spec/wire.md §4): purge on replace only
/// under `writer`, `nobody` only kept forever.
pub(crate) fn check_retention(r: &Retention) -> Result<(), Error> {
    r.refusal().map_or(Ok(()), |m| Err(Error::Invalid(m)))
}

/// Retention of a write: the fixed one, else the commit's override, else the schema's default
/// for the AK, else the untyped default (`author_or_admin`, no history promised); canonical
/// (`Retention::canonical`). An override that disagrees with a fixed retention is refused.
pub fn write_retention(ak: &str, defaults: Option<&AspectDefaults>, set: Option<Retention>) -> Result<Retention, Error> {
    let r = match (fixed_retention(ak), set.map(Retention::canonical)) {
        (Some(f), Some(s)) if f != s => return Err(Error::Build("retention of this aspect is fixed")),
        (Some(f), _) => f,
        (None, Some(s)) => s,
        (None, None) => defaults.map(|d| d.retention.canonical()).unwrap_or_default(),
    };
    check_retention(&r).map_err(|e| match e {
        Error::Invalid(m) => Error::Build(m),
        e => e,
    })?;
    // `after` at 2^63 - 1 ms is a saturated duration (forever is `until`'s)
    if let Some(History::Keep { until, after }) = r.history
        && (until.is_some_and(|t| t > FOREVER) || after.is_some_and(|d| d >= FOREVER))
    {
        return Err(Error::Build("history bound out of range"));
    }
    Ok(r)
}

/// Retention of a compaction-snapshot delta (spec/commits.md §5): an aspect with fixed retention
/// keeps it; any other is `writer`, purge on replace when any of `own` (the retentions standing
/// for the writes the snapshot carries live) is, else kept for the longest `after` among them
/// (no `until`), else no history promised.
pub fn snapshot_retention(ak: &str, own: impl IntoIterator<Item = Retention>) -> Retention {
    if let Some(f) = fixed_retention(ak) {
        return f;
    }
    let mut after = 0;
    for r in own {
        match r.history {
            Some(History::PurgeOnReplace) => return Retention { by: PurgeBy::Writer, history: Some(History::PurgeOnReplace) },
            Some(History::Keep { after: Some(d), .. }) => after = after.max(d),
            _ => {}
        }
    }
    Retention { by: PurgeBy::Writer, history: (after > 0).then_some(History::Keep { until: None, after: Some(after) }) }
}

/// The keep-at-least bound a node applies to a body of delta `a` (spec/commits.md §5 Keep
/// bounds): the history mode's, and for a role-class aspect or `addenda.0`, kept `ROLE_KEEP`
/// after replaced. Purge on replace has none: it limits nothing, the replacing writer's cover
/// drops the body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeepRule {
    /// Kept until this wall ms (`FOREVER`: for good).
    pub until: Option<u64>,
    /// Kept this long after replaced (ms, above 0).
    pub after: Option<u64>,
}

impl KeepRule {
    pub fn of(ak: &str, r: &Retention) -> KeepRule {
        let role = role_kept(ak).then_some(ROLE_KEEP_MS);
        match r.history {
            Some(History::PurgeOnReplace) => KeepRule { until: None, after: None },
            Some(History::Keep { until, after }) => KeepRule { until, after: after.filter(|d| *d > 0).max(role) },
            None => KeepRule { until: None, after: role },
        }
    }

    /// Of an aspect entry of a header.
    pub fn of_aspect(a: &AspectEntry) -> KeepRule {
        KeepRule::of(a.ak.as_str(), &a.retention)
    }

    /// Whether the bound counts from when the body was replaced.
    pub fn relative(&self) -> bool {
        self.after.is_some()
    }

    /// Kept for good.
    pub fn forever(&self) -> bool {
        self.until == Some(FOREVER)
    }
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
/// ROLE_KEEP`, whatever its deltas' bounds.
pub(crate) fn purge_keep_until(h: &Header) -> Option<u64> {
    (!h.purge.is_empty()).then(|| h.ts.wall_ms().0.saturating_add(ROLE_KEEP_MS))
}

/// Before which wall ms a body of `h` holding deltas of aspect `a`'s class leaves only by purge
/// request or expiry (spec/commits.md §5 Keep bounds; 0: no floor): the later of its absolute T,
/// D after `replaced` (wall ms, when the body was replaced; `None`: not replaced, so past a
/// relative bound) and the purge-request floor.
pub fn body_keep(h: &Header, a: &AspectEntry, replaced: Option<u64>) -> u64 {
    let k = KeepRule::of_aspect(a);
    let rel = match (k.after, replaced) {
        (Some(d), Some(t)) => t.saturating_add(d),
        _ => 0,
    };
    k.until.unwrap_or(0).max(rel).max(purge_keep_until(h).unwrap_or(0))
}

/// Delete levels a delta of retention `r` calls for (spec/crypto.md §7).
pub(crate) fn delete_levels(r: &Retention) -> &'static [u8] {
    match r.by {
        PurgeBy::Nobody => &[],
        PurgeBy::Admin => &[DELETE_ADMIN],
        PurgeBy::Author => &[DELETE_AUTHOR],
        PurgeBy::AuthorOrAdmin => &[DELETE_ADMIN, DELETE_AUTHOR],
        PurgeBy::Writer => &[DELETE_ADMIN, DELETE_AUTHOR, DELETE_WRITER],
    }
}
