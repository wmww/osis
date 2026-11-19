//! Abstract edge-write records the node hands perm (spec/permissions.md §5.1; core types of
//! spec/data-model.md §9). The node adapts commit headers and deltas into these; perm parses no
//! bytes. Every record is untrusted: perm never panics on one.

use osis_base::{CommitId, Role, Tid, Ts, WallMs};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Position in the joint order (spec/permissions.md §5.1 step 1): (`ts`, author node, commit
/// ID): the write's key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Point {
    pub ts: Ts,
    pub node: Tid,
    pub commit: CommitId,
}

impl Point {
    /// The start of `ts`: the zero tid and commit ID order it before every write at that `ts`.
    /// An expiry by `until` takes effect there (spec/permissions.md §3, Retain), and layer 2
    /// judges a commit there (§5.2, Position).
    pub fn start(ts: Ts) -> Point {
        Point { ts, node: Tid::from_bytes([0; 15]), commit: CommitId([0; 32]) }
    }
}

/// A `roles.0` edge value (spec/data-model.md §9 `edge`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Edge {
    pub role: Role,
    /// The edge counts as removed from `wall_ms(t) >= until` (spec/permissions.md §2).
    pub until: Option<WallMs>,
    pub invite: Option<Role>,
    /// With `until`: its passing says retain (spec/permissions.md §3, Retain).
    pub retain: bool,
    /// Granted without history: the read n the holder reads from (spec/crypto.md §4, Floors);
    /// `None` is 0.
    pub floor: Option<u64>,
}

impl Edge {
    pub fn new(role: Role) -> Edge {
        Edge { role, until: None, invite: None, retain: false, floor: None }
    }
    /// The value a removal saying retain writes (spec/permissions.md §3): `until` 0, gone at every
    /// clock.
    pub fn kept_end() -> Edge {
        Edge { until: Some(osis_base::WallMs(0)), ..Edge::new(osis_base::Role::Read) }
    }
    /// Whether this value is a removal's saying retain.
    pub fn says_retain(&self) -> bool {
        self.until == Some(osis_base::WallMs(0))
    }
    /// Whether this value, once it has no alive value after it, ended saying retain: a removal's
    /// saying so, or one whose `until` passed written to retain (spec/permissions.md §3, Retain).
    pub fn ends_retaining(&self) -> bool {
        self.says_retain() || self.until.is_some() && self.retain
    }
    /// Alive at `ts`; `None` is the end of time, where every edge with an `until` is gone.
    pub fn alive_at(&self, ts: Option<Ts>) -> bool {
        match (self.until, ts) {
            (None, _) => true,
            (Some(u), Some(ts)) => ts.wall_ms() < u,
            (Some(_), None) => false,
        }
    }
}

/// `new` removes `old` or lowers it in every component (role, invite, `until`; a floor at least
/// the old one: a lower floor hands history): the shape of a self-removal (spec/permissions.md §2).
pub fn lowers(new: Option<&Edge>, old: Option<&Edge>) -> bool {
    match (new, old) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(n), Some(o)) => {
            let until_le = match (n.until, o.until) {
                (_, None) => true,
                (None, Some(_)) => false,
                (Some(a), Some(b)) => a <= b,
            };
            n.role <= o.role && n.invite <= o.invite && until_le && n.floor.unwrap_or(0) >= o.floor.unwrap_or(0)
        }
    }
}

/// What a demoter had received (spec/permissions.md §5.1; spec/data-model.md §9 `frontier`):
/// commit IDs of the demoted nodes' commits the demoter received, and of its chain writes,
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

/// One `roles.0` edge write of a role commit: the edge of `holder` on `target`, `None`
/// for a removal.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EdgeOp {
    pub target: Tid,
    pub holder: Tid,
    pub edge: Option<Edge>,
}

/// The edge writes of a role commit (spec/commits.md §2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RoleCommit {
    pub id: CommitId,
    pub ts: Ts,
    /// Its signer (header field 1); a role commit states the empty path (Interim,
    /// notes/a1-spec/README.md step 3: until the walk reads paths).
    pub signer: Tid,
    /// The demoter's frontier (explicit demotions only), resolved from its link if large.
    pub frontier: Option<Arc<Frontier>>,
    pub ops: Vec<EdgeOp>,
}

impl RoleCommit {
    pub fn point(&self) -> Point {
        Point { ts: self.ts, node: self.signer, commit: self.id }
    }

    /// Whether `o` is this record as an input to the walk: every field, frontiers by their
    /// sizes (fixed by the commit ID, `HeldSet`), as the saved-walk tag covers it. A record can
    /// grow under its ID (a part that arrives late).
    pub(crate) fn same_input(&self, o: &RoleCommit) -> bool {
        (self.id, self.ts, self.signer, &self.ops) == (o.id, o.ts, o.signer, &o.ops) && same_frontier(&self.frontier, &o.frontier)
    }
}

/// Frontiers as the walk's input compares them: by their sizes (`RoleCommit::same_input`).
fn same_frontier(a: &Option<Arc<Frontier>>, b: &Option<Arc<Frontier>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b) || a.commits().len() == b.commits().len(),
        _ => false,
    }
}

/// An edge write's identity: op `.1` of role commit `.0`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct WriteId(pub CommitId, pub u32);

impl WriteId {
    pub fn commit(&self) -> CommitId {
        self.0
    }
}

/// The `roles.0` AK.
pub const ROLES: &str = "roles.0";

/// Sets `k` to `v` in `m` (`None`: removes it); the value before.
pub(crate) fn put<K: Ord, V>(m: &mut BTreeMap<K, V>, k: K, v: Option<V>) -> Option<V> {
    match v {
        Some(v) => m.insert(k, v),
        None => m.remove(&k),
    }
}

/// Pops the last element of `m[k]`, removing the entry once empty.
pub(crate) fn pop<K: Ord, V>(m: &mut BTreeMap<K, Vec<V>>, k: &K) {
    if let Some(v) = m.get_mut(k) {
        v.pop();
        if v.is_empty() {
            m.remove(k);
        }
    }
}

/// The earlier of two optional expiries.
pub(crate) fn earliest(a: Option<WallMs>, b: Option<WallMs>) -> Option<WallMs> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Puts `k` in `s` or takes it out (`on`); whether it was in.
pub(crate) fn mark<K: Ord>(s: &mut BTreeSet<K>, k: K, on: bool) -> bool {
    if on { !s.insert(k) } else { s.remove(&k) }
}
