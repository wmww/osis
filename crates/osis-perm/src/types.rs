//! Abstract edge-write records the node hands perm (spec/permissions.md §5.1, §6; core types of
//! spec/data-model.md §9). The node adapts commit headers and deltas into these; perm parses no
//! bytes. Every record is untrusted: perm never panics on one.

use osis_core::{CommitId, Role, Tid, Ts, WallMs};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// (`ts`, author node) of a write: `edge_key` (spec/data-model.md §9).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct EdgeKey {
    pub ts: Ts,
    pub node: Tid,
}

/// Position in the joint order (spec/permissions.md §5.1 step 1): (`ts`, author node, commit ID).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Point {
    pub ts: Ts,
    pub node: Tid,
    pub commit: CommitId,
}

impl Point {
    pub fn key(&self) -> EdgeKey {
        EdgeKey { ts: self.ts, node: self.node }
    }
    /// The first position with this edge key: where perm places a ledger event keyed by it.
    pub fn first_at(key: EdgeKey) -> Point {
        Point { ts: key.ts, node: key.node, commit: CommitId([0; 32]) }
    }
}

/// A `/members` edge value (spec/data-model.md §9 `edge`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Edge {
    pub role: Role,
    /// The edge counts as removed from `wall_ms(t) >= until` (spec/permissions.md §2).
    pub until: Option<WallMs>,
    pub invite: Option<Role>,
    /// Roster snapshots only: key of the write that established a write+ edge.
    pub since: Option<EdgeKey>,
}

impl Edge {
    pub fn new(role: Role) -> Edge {
        Edge { role, until: None, invite: None, since: None }
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

/// `new` removes `old` or lowers it in every component (role, invite, `until`): the shape of a
/// self-removal (spec/permissions.md §2).
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
            n.role <= o.role && n.invite <= o.invite && until_le
        }
    }
}

/// The dots of a write on one aspect (spec/commits.md §3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Dots {
    /// Node form: counters `[lo, hi)` of the author node on the aspect.
    Node { lo: u64, hi: u64 },
    /// Commit form: dots `(commit ID, index)`.
    Commit,
}

/// What a demoter had received (spec/permissions.md §5.1; spec/data-model.md §9 `frontier`).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Frontier {
    /// tid -> AK -> author node -> counter up to which (inclusive) writes were received
    /// contiguously.
    pub writes: BTreeMap<Tid, BTreeMap<String, BTreeMap<Tid, u64>>>,
    /// Commit IDs of commit-form writes received.
    pub commits: BTreeSet<CommitId>,
}

impl Frontier {
    /// Whether the frontier covers the dots `dots` of commit `commit` by `node` on `(tid, ak)`.
    /// A node-form range is covered when its last counter is; an empty range (a commit with no
    /// own writes, such as an import) only by its commit ID.
    pub fn covers(&self, tid: &Tid, ak: &str, node: &Tid, dots: Dots, commit: &CommitId) -> bool {
        match dots {
            Dots::Node { lo, hi } if lo < hi => {
                let got = self.writes.get(tid).and_then(|m| m.get(ak)).and_then(|m| m.get(node));
                got.is_some_and(|&c| c >= hi - 1)
            }
            _ => self.commits.contains(commit),
        }
    }
}

/// One `/members` edge write of a membership commit: the edge of `member` on `target`, `None`
/// for a removal.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EdgeOp {
    pub target: Tid,
    pub member: Tid,
    pub edge: Option<Edge>,
    /// The commit's dots on `(target, /members)`.
    pub dots: Dots,
}

/// The edge writes of a membership commit (spec/commits.md §2), roster snapshots excluded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MembershipCommit {
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

impl MembershipCommit {
    pub fn point(&self) -> Point {
        Point { ts: self.ts, node: self.author, commit: self.id }
    }
}

/// A tenure ledger entry (spec/data-model.md §9 `tenure`; spec/permissions.md §6).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Tenure {
    pub member: Tid,
    pub role: Role,
    pub since: Option<EdgeKey>,
    pub until: EdgeKey,
    pub frontier: Option<Arc<Frontier>>,
}

/// A roster snapshot of `thing` (spec/permissions.md §6): its `/members` and `/tenures` state.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RosterSnapshot {
    pub id: CommitId,
    pub ts: Ts,
    pub author: Tid,
    pub actor: Tid,
    pub thing: Tid,
    /// The commit's dots on `(thing, /members)`.
    pub dots: Dots,
    pub roster: BTreeMap<Tid, Edge>,
    pub ledger: Vec<Tenure>,
}

impl RosterSnapshot {
    pub fn point(&self) -> Point {
        Point { ts: self.ts, node: self.author, commit: self.id }
    }
}

/// An edge write's identity: op `index` of a membership commit, or a roster snapshot.
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

/// The `/members` AK.
pub const MEMBERS: &str = "/members";
