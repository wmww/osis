//! Abstract grant-write records the node hands perm (spec/permissions.md §5.1; core types of
//! spec/data-model.md §9). The node adapts commit headers and deltas into these; perm parses no
//! bytes. Every record is untrusted: perm never panics on one.

use osis_base::{CommitId, Holder, Role, SignKey, Tid, Ts, Time};
use std::collections::BTreeSet;
use std::sync::Arc;

/// Position in the joint order (spec/permissions.md §5.1 step 1): (`ts`, author node, commit
/// ID): the write's key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Point {
    pub ts: Ts,
    pub node: Tid,
    pub commit: CommitId,
}

/// A `roles.0` grant value (spec/data-model.md §9 `grant`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Grant {
    pub role: Role,
    /// The grant counts as removed from `wall_ms(t) >= until` (spec/permissions.md §2).
    pub until: Option<Time>,
    /// The may-grant flag (spec/permissions.md §2): its holder may add new holders up to its role.
    pub may_grant: bool,
    /// With `until`: its passing says retain (spec/permissions.md §3, Retain).
    pub retain: bool,
    /// Granted without history: the read n the holder reads from (spec/crypto.md §4, Floors);
    /// `None` is 0.
    pub floor: Option<u64>,
}

impl Grant {
    pub fn new(role: Role) -> Grant {
        Grant { role, until: None, may_grant: false, retain: false, floor: None }
    }
    /// The value a removal saying retain writes (spec/permissions.md §3): `until` 0, gone at every
    /// clock.
    pub fn kept_end() -> Grant {
        Grant { until: Some(osis_base::Time(0)), ..Grant::new(osis_base::Role::Read) }
    }
    /// Whether this value is a removal's saying retain.
    pub fn says_retain(&self) -> bool {
        self.until == Some(osis_base::Time(0))
    }
    /// Whether this value, once it has no alive value after it, ended saying retain: a removal's
    /// saying so, or one whose `until` passed written to retain (spec/permissions.md §3, Retain).
    pub fn ends_retaining(&self) -> bool {
        self.says_retain() || self.until.is_some() && self.retain
    }
    /// Alive at `ts`; `None` is the end of time, where every grant with an `until` is gone.
    pub fn alive_at(&self, ts: Option<Ts>) -> bool {
        match (self.until, ts) {
            (None, _) => true,
            (Some(u), Some(ts)) => ts.wall_ms() < u,
            (Some(_), None) => false,
        }
    }
}

/// `new` removes `old` or lowers it in every component (role, may-grant flag, `until`; a floor at least
/// the old one: a lower floor hands history): the shape of a self-removal (spec/permissions.md §2).
pub fn lowers(new: Option<&Grant>, old: Option<&Grant>) -> bool {
    match (new, old) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(n), Some(o)) => {
            let until_le = match (n.until, o.until) {
                (_, None) => true,
                (None, Some(_)) => false,
                (Some(a), Some(b)) => a <= b,
            };
            n.role <= o.role && n.may_grant <= o.may_grant && until_le && n.floor.unwrap_or(0) >= o.floor.unwrap_or(0)
        }
    }
}

/// What a demoter had received (spec/permissions.md §5.1; spec/data-model.md §9 `frontier`):
/// commit IDs of the commits resting on the lowered hop that the demoter received,
/// ascending and distinct (shared with the header that carried them: 32 B an ID).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Frontier(Arc<[CommitId]>);

impl Frontier {
    /// The frontier of `ids`, in any order.
    pub fn new(ids: impl IntoIterator<Item = CommitId>) -> Frontier {
        let ids: BTreeSet<CommitId> = ids.into_iter().collect();
        Frontier(ids.into_iter().collect())
    }

    /// The frontier of `ids`, ascending and distinct already (a header's).
    pub fn of_sorted(ids: Arc<[CommitId]>) -> Frontier {
        debug_assert!(ids.is_sorted_by(|a, b| a < b), "frontier IDs ascending and distinct");
        Frontier(ids)
    }

    /// Its commit IDs, ascending.
    pub fn commits(&self) -> &[CommitId] {
        &self.0
    }

    /// Its commit IDs, shared (what a header carries).
    pub fn ids(&self) -> Arc<[CommitId]> {
        self.0.clone()
    }

    /// Whether the frontier covers the writes of `commit`: it lists the commit's ID.
    pub fn covers(&self, commit: &CommitId) -> bool {
        self.0.binary_search(commit).is_ok()
    }
}

/// One `roles.0` grant write of a role commit: the grant of `holder` on `target`, `None`
/// for a removal.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GrantOp {
    pub target: Tid,
    /// A thing (`roles.0`) or a key (`signers.0`).
    pub holder: Holder,
    pub grant: Option<Grant>,
}

/// The grant writes of a role commit (spec/commits.md §2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RoleCommit {
    pub id: CommitId,
    pub ts: Ts,
    /// Its signer (header field 1): the thing it is signed as, and the key that signed it.
    pub signer: Tid,
    pub key: SignKey,
    /// The things its one stated path lists and the hops it marks direct (spec/wire.md §4
    /// `Path`).
    pub listed: Vec<Tid>,
    pub direct: osis_base::format::PathMarks,
    /// Its frontier (an explicit lowering's list, spec/permissions.md §5.1), resolved from its
    /// link if large.
    pub frontier: Option<Arc<Frontier>>,
    pub ops: Vec<GrantOp>,
}

impl RoleCommit {
    pub fn point(&self) -> Point {
        Point { ts: self.ts, node: self.signer, commit: self.id }
    }

    /// The things between its signer and `t` along which it writes `t` (spec/permissions.md §1
    /// Path): the listed things, less the last where that is `t`.
    pub fn path_to(&self, t: &Tid) -> &[Tid] {
        match self.listed.split_last() {
            Some((last, rest)) if last == t => rest,
            _ => &self.listed,
        }
    }
}

/// A part's identity: part `.1` of commit `.0`, in its holder's numbering (`paths::Commit`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct WriteId(pub CommitId, pub u32);

/// The earlier of two optional expiries.
pub(crate) fn earliest(a: Option<Time>, b: Option<Time>) -> Option<Time> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Puts `k` in `s` or takes it out (`on`); whether it was in.
pub(crate) fn mark<K: Ord>(s: &mut BTreeSet<K>, k: K, on: bool) -> bool {
    if on { !s.insert(k) } else { s.remove(&k) }
}
