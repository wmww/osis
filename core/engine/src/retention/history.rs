//! The one door to a body's history (spec/commits.md §5): what history keeps of a replaced body
//! of an aspect of a thing, and until when. Every reader of a body's history asks here: keep
//! bounds and when a body was replaced (`bounds`), listing, undo, purge on replace (`View`'s
//! flags, `replace`), snapshots (`snapshot::cannot_keep`, the D of a carrying snapshot), memory
//! compaction, permanence, and node-sync's kept bodies (through `Engine::body_keeps`,
//! `keeps_unreplaced`, `permanent`). Its source is the part's own header entry: the wire's
//! history mode, and `ROLE_KEEP` after replaced for a role-class aspect or `addenda.0`.

use osis_base::format::ROLE_KEEP_MS;
use osis_commit::{AspectEntry, FOREVER, Header};
use osis_schema::History;

/// What history keeps of the bodies of one aspect of a thing (`of`). The default keeps nothing
/// (no history promised).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Kept {
    /// Kept until this wall ms (`FOREVER`: for good).
    until: Option<u64>,
    /// Kept this long after replaced (ms, above 0).
    after: Option<u64>,
    /// Out of history once replaced; the replacing writer covers it (`replace`).
    purge_on_replace: bool,
}

/// What history keeps of a body of aspect entry `a` (its thing `a.tid`, AK `a.ak`).
pub(crate) fn of(a: &AspectEntry) -> Kept {
    let role = osis_commit::retention::role_kept(a.ak.as_str()).then_some(ROLE_KEEP_MS);
    match a.retention.history {
        Some(History::PurgeOnReplace) => Kept { purge_on_replace: true, ..Kept::default() },
        Some(History::Keep { until, after }) => Kept { until, after: after.filter(|d| *d > 0).max(role), purge_on_replace: false },
        None => Kept { after: role, ..Kept::default() },
    }
}

/// Whether aspect `a` of `h` is a permanent delta (spec/commits.md §5): history kept forever, no
/// expiry, on an aspect with no fixed retention, in a durable commit. It leaves by purge request,
/// and leaves its header behind for good.
pub(crate) fn permanent(h: &Header, a: &AspectEntry) -> bool {
    h.ephemeral.is_none() && h.expires.is_none() && of(a).forever() && osis_commit::retention::fixed_retention(a.ak.as_str()).is_none()
}

impl Kept {
    /// The wall ms before which a body replaced at wall ms `replaced` is in history (0: never in
    /// it); `None`: not replaced, so only an absolute bound counts. Purge on replace keeps none.
    pub(crate) fn leaves_at(self, replaced: Option<u64>) -> u64 {
        let rel = self.after.zip(replaced).map_or(0, |(d, t)| t.saturating_add(d));
        self.until.unwrap_or(0).max(rel)
    }

    /// Whether when a body leaves depends on when it was replaced (only then is it dated,
    /// `bounds::replaced_at`).
    pub(crate) fn dated(self) -> bool {
        self.after.is_some()
    }

    /// How long a body is kept after replaced (ms, 0: not by that).
    pub(crate) fn after(self) -> u64 {
        self.after.unwrap_or(0)
    }

    /// Whether any history is kept, until a time or after replaced.
    pub(crate) fn keeps(self) -> bool {
        self.until.is_some() || self.after.is_some()
    }

    /// Kept for good.
    pub(crate) fn forever(self) -> bool {
        self.until == Some(FOREVER)
    }

    /// Whether a replaced body is purged on replace.
    pub(crate) fn purge_on_replace(self) -> bool {
        self.purge_on_replace
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_base::{Ak, PurgeBy, Tid};
    use osis_commit::retention::ROLE_RETENTION;
    use osis_schema::Retention;

    fn entry(ak: &str, r: Retention) -> AspectEntry {
        AspectEntry { tid: Tid::from_bytes([3; 15]), ak: Ak::new(ak).unwrap(), lo: 1, hi: 2, retention: r, keys: vec![], hash: [0; 32], replaces: None }
    }

    #[test]
    fn kept_by_mode_spec_commits_5() {
        // a role-class body is kept `ROLE_KEEP` after replaced, its retention promising none
        let role = of(&entry("keys.0", ROLE_RETENTION));
        assert!(role.dated() && role.keeps() && !role.purge_on_replace());
        assert_eq!(role.leaves_at(Some(20)), 20 + ROLE_KEEP_MS);
        assert_eq!(of(&entry("app:x.0", ROLE_RETENTION)), Kept::default());
        let k = of(&entry("app:title.0", Retention { by: PurgeBy::Writer, history: Some(History::Keep { until: Some(100), after: Some(50) }) }));
        assert_eq!(k.leaves_at(None), 100);
        assert_eq!(k.leaves_at(Some(20)), 100);
        assert_eq!(k.leaves_at(Some(70)), 120);
        // purge on replace keeps nothing
        let p = of(&entry("app:title.0", Retention { by: PurgeBy::Writer, history: Some(History::PurgeOnReplace) }));
        assert!(p.purge_on_replace() && !p.keeps() && !p.dated());
        assert_eq!(p.leaves_at(Some(20)), 0);
        assert!(of(&entry("app:title.0", Retention { by: PurgeBy::Nobody, history: Some(History::FOREVER) })).forever());
    }
}
