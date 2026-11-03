//! Abstract edge-write records the node hands perm (spec/permissions.md §5.1, §6; core types of
//! spec/data-model.md §9). The node adapts commit headers and deltas into these; perm parses no
//! bytes. Every record is untrusted: perm never panics on one.

use osis_base::{CommitId, Role, Tid, Ts, WallMs};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Position in the joint order (spec/permissions.md §5.1 step 1): (`ts`, author node, commit
/// ID). Also the key of a write in rosters and ledgers: `edge_key` (spec/data-model.md §9).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Point {
    pub ts: Ts,
    pub node: Tid,
    pub commit: CommitId,
}

impl Point {
    /// The key of an expiry by `until` at its first `ts` (spec/permissions.md §6): the zero
    /// tid and commit ID order it before every write at that `ts`.
    pub fn expiry(ts: Ts) -> Point {
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
    /// Roster snapshots only: key of the write that established a write+ edge.
    pub since: Option<Point>,
    /// The placement of the target in its holder group this edge is tied to
    /// (spec/permissions.md §2): carried, never an authority.
    pub tied: Option<Tie>,
    /// A holder actor's edge: the key of its `keys.0` commit the last grant or raise sealed to
    /// (spec/crypto.md §4); carried by every later write of the edge and by roster snapshots,
    /// never an authority.
    pub keyset: Option<Point>,
}

/// The `group.0` element a tied edge names (spec/permissions.md §2): its creation stamp (`ts`,
/// dot source, counter, spec/crdt.md §2) and the set it is in.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Tie {
    pub ts: Ts,
    pub src: TieSource,
    pub ctr: u64,
    pub subgroup: bool,
}

/// A dot's source (spec/crdt.md §2.1): a placement is durable, never `Derived`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum TieSource {
    Commit(CommitId),
    /// A session of the node: its 16-byte nonce.
    Session(Tid, [u8; 16]),
}

impl Edge {
    pub fn new(role: Role) -> Edge {
        Edge { role, until: None, invite: None, since: None, tied: None, keyset: None }
    }
    /// The value a removal saying keep writes (spec/permissions.md §3): `until` 0, gone at every
    /// clock. `keyset`: the standing edge's, so that it lowers (§2).
    pub fn kept_end(keyset: Option<Point>) -> Edge {
        Edge { until: Some(osis_base::WallMs(0)), keyset, ..Edge::new(osis_base::Role::Read) }
    }
    /// Whether this value is a removal's saying keep.
    pub fn says_keep(&self) -> bool {
        self.until == Some(osis_base::WallMs(0))
    }
    /// Alive at `ts`; `None` is the end of time, where every edge with an `until` is gone.
    pub fn alive_at(&self, ts: Option<Ts>) -> bool {
        match (self.until, ts) {
            (None, _) => true,
            (Some(u), Some(ts)) => ts.wall_ms() < u,
            (Some(_), None) => false,
        }
    }
    /// Well formed: invite at most the role (spec/permissions.md §2).
    pub fn well_formed(&self) -> bool {
        self.invite.is_none_or(|i| i <= self.role)
    }
}

/// `new` removes `old` or lowers it in every component (role, invite, `until`) keeping its
/// `keyset`: the shape of a self-removal (spec/permissions.md §2). A changed `keyset` is not: a
/// holder actor's member could otherwise point the boxers bound by it (spec/crypto.md §4) at a
/// keyset of its own choice.
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
            n.role <= o.role && n.invite <= o.invite && until_le && n.keyset == o.keyset
        }
    }
}

/// What a demoter had received (spec/permissions.md §5.1; spec/data-model.md §9 `frontier`).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Frontier {
    /// Commit IDs of the demoted nodes' commits the demoter received, and of its chain writes.
    pub commits: BTreeSet<CommitId>,
}

impl Frontier {
    /// Whether the frontier covers the writes of `commit`: it lists the commit's ID.
    pub fn covers(&self, commit: &CommitId) -> bool {
        self.commits.contains(commit)
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

/// The edge writes of a role commit (spec/commits.md §2), roster snapshots excluded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RoleCommit {
    pub id: CommitId,
    pub ts: Ts,
    /// Signing node.
    pub author: Tid,
    /// Actor the node acts for (header field 2).
    pub actor: Tid,
    /// The demoter's frontier (explicit demotions only), resolved from its link if large.
    pub frontier: Option<Arc<Frontier>>,
    pub ops: Vec<EdgeOp>,
}

impl RoleCommit {
    pub fn point(&self) -> Point {
        Point { ts: self.ts, node: self.author, commit: self.id }
    }

    /// Whether `o` is this record as an input to the walk: every field, frontiers by their
    /// sizes (fixed by the commit ID, `HeldSet`), as the saved-walk tag covers it. A record can
    /// grow under its ID (a part that arrives late).
    pub(crate) fn same_input(&self, o: &RoleCommit) -> bool {
        (self.id, self.ts, self.author, self.actor, &self.ops) == (o.id, o.ts, o.author, o.actor, &o.ops) && same_frontier(&self.frontier, &o.frontier)
    }
}

/// Frontiers as the walk's input compares them: by their sizes (`RoleCommit::same_input`).
fn same_frontier(a: &Option<Arc<Frontier>>, b: &Option<Arc<Frontier>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b) || a.commits.len() == b.commits.len(),
        _ => false,
    }
}

/// A tenure ledger entry (spec/data-model.md §9 `tenure`; spec/permissions.md §6).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Tenure {
    pub holder: Tid,
    pub role: Role,
    pub since: Option<Point>,
    pub until: Point,
    pub frontier: Option<Arc<Frontier>>,
}

/// A roster snapshot of `thing` (spec/permissions.md §6): its `roles.0` and `tenures.0` state.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RosterSnapshot {
    pub id: CommitId,
    pub ts: Ts,
    pub author: Tid,
    pub actor: Tid,
    pub thing: Tid,
    pub roster: BTreeMap<Tid, Edge>,
    pub ledger: Vec<Tenure>,
}

impl RosterSnapshot {
    pub fn point(&self) -> Point {
        Point { ts: self.ts, node: self.author, commit: self.id }
    }

    /// `RoleCommit::same_input` for a roster snapshot (its `tenures.0` part may arrive
    /// after its `roles.0` part).
    pub(crate) fn same_input(&self, o: &RosterSnapshot) -> bool {
        (self.id, self.ts, self.author, self.actor, self.thing, &self.roster) == (o.id, o.ts, o.author, o.actor, o.thing, &o.roster)
            && self.ledger.len() == o.ledger.len()
            && self.ledger.iter().zip(&o.ledger).all(|(a, b)| (a.holder, a.role, a.since, a.until) == (b.holder, b.role, b.since, b.until) && same_frontier(&a.frontier, &b.frontier))
    }
}

/// An edge write's identity: op `index` of a role commit, or a roster snapshot.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum WriteId {
    Op(CommitId, u32),
    Snapshot(CommitId),
}

impl WriteId {
    pub fn commit(&self) -> CommitId {
        match self {
            WriteId::Op(c, _) | WriteId::Snapshot(c) => *c,
        }
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
