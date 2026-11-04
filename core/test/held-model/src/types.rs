//! Input types: what a node holds. Abstract on purpose: ids are small integers, values are `u32`.

pub type CommitId = u32;
pub type NodeId = u32;
pub type ThingId = u32;
pub type Val = u32;

/// `ts` units per wall millisecond (spec/crdt.md §2.2: `ts = wall_ms * 2^16 + logical`).
pub const MS: u64 = 1 << 16;
pub fn wall(ts: u64) -> u64 {
    ts / MS
}
pub const HOUR: u64 = 3_600_000;
/// spec/wire.md §1 constants, in wall ms.
pub const MAX_DRIFT: u64 = HOUR;
pub const AT_MOST_GRACE: u64 = HOUR;
pub const ROLE_KEEP: u64 = 90 * 24 * HOUR;
/// An absolute keep-at-least of forever (`abs` forever).
pub const FOREVER: u64 = u64::MAX;

/// Commit-form dot only (spec/crdt.md §2.1): the commit and a counter. Orders by commit ID, then counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dot {
    pub commit: CommitId,
    pub ctr: u32,
}

/// `(ts, dot)`, ordered by ts then dot (spec/crdt.md §2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Stamp {
    pub ts: u64,
    pub dot: Dot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AspectKind {
    /// A root register (`set`, `remove_aspect`, `replace`).
    Register,
    /// A map of keys to registers (`put`, write into an entry, `remove`, `remove_aspect`).
    Map,
    /// Text (`insert`, `delete`, `remove_aspect`); no moves, no undelete.
    Text,
}

/// An aspect key: a name plus the markers an AK carries (spec/data-model.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Aspect {
    pub name: u32,
    pub kind: AspectKind,
    /// `^`: writes need admin (spec/permissions.md §5.2).
    pub admin_only: bool,
}

impl Aspect {
    /// `roles.0`: carries edge writes only (role commits).
    pub const ROLES: Aspect = Aspect { name: 0, kind: AspectKind::Map, admin_only: true };
    pub const fn reg(name: u32) -> Aspect {
        Aspect { name, kind: AspectKind::Register, admin_only: false }
    }
    pub const fn map(name: u32) -> Aspect {
        Aspect { name, kind: AspectKind::Map, admin_only: false }
    }
    pub const fn text(name: u32) -> Aspect {
        Aspect { name, kind: AspectKind::Text, admin_only: false }
    }
    pub const fn admin_reg(name: u32) -> Aspect {
        Aspect { name, kind: AspectKind::Register, admin_only: true }
    }
}

/// One write (spec/crdt.md §1). Value fields are `None` when held value-less (spec/crdt.md §4.7).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    /// Register: the root value.
    Set { value: Option<Val> },
    /// Any kind: the aspect root's reset (`remove_aspect`; with a `Set` at the same stamp, `replace`).
    Reset,
    /// Map: entry creation; the entry is the write's dot; the key is the creation's value.
    Create { key: Option<Val> },
    /// Map: the entry's register write. `key` is the record's repeat of the entry's key, a copy of the
    /// creation's value, owned by the creation's delta.
    SetIn { entry: Dot, key: Option<Val>, value: Option<Val> },
    /// Map: element reset of an entry (a removal; keyless form).
    Remove { entry: Dot },
    /// Text: element creation; the element is the write's dot; `anchor` None is HEAD.
    Insert { anchor: Option<Dot>, ch: Option<Val> },
    /// Text: deleted-flag write `true` on an element.
    Delete { elem: Dot },
    /// Text: a bare anchor record (no write). Only snapshots and the node's own state carry it;
    /// its stamp is `(0, element dot)`.
    Anchor,
}

/// A write's identity: stamp, op kind, and the element it targets (its own dot for non-targeted ops).
pub type WriteId = (Stamp, u8, Dot);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Write {
    pub stamp: Stamp,
    pub op: Op,
}

impl Write {
    pub fn id(&self) -> WriteId {
        let s = self.stamp;
        match &self.op {
            Op::Set { .. } => (s, 0, s.dot),
            Op::Reset => (s, 1, s.dot),
            Op::Create { .. } => (s, 2, s.dot),
            Op::SetIn { entry, .. } => (s, 3, *entry),
            Op::Remove { entry } => (s, 4, *entry),
            Op::Insert { .. } => (s, 5, s.dot),
            Op::Delete { elem } => (s, 6, *elem),
            Op::Anchor => (s, 7, s.dot),
        }
    }
    /// The commit whose delta owns the write (attribution by dot, spec/crdt.md §4.7).
    pub fn owner(&self) -> CommitId {
        self.stamp.dot.commit
    }
    /// The value fields with the commit owning each (a `SetIn` key is the entry creation's).
    pub fn values(&self) -> Vec<(CommitId, Option<Val>)> {
        let own = self.owner();
        match &self.op {
            Op::Set { value } => vec![(own, *value)],
            Op::Create { key } => vec![(own, *key)],
            Op::SetIn { entry, key, value } => vec![(entry.commit, *key), (own, *value)],
            Op::Insert { ch, .. } => vec![(own, *ch)],
            _ => vec![],
        }
    }
    /// Strips every value field whose owning commit `drop` names.
    pub fn strip(&mut self, drop: impl Fn(CommitId) -> bool) {
        let own = self.owner();
        match &mut self.op {
            Op::Set { value } if drop(own) => *value = None,
            Op::Create { key } if drop(own) => *key = None,
            Op::SetIn { entry, key, value } => {
                if drop(entry.commit) {
                    *key = None;
                }
                if drop(own) {
                    *value = None;
                }
            }
            Op::Insert { ch, .. } if drop(own) => *ch = None,
            _ => {}
        }
    }
    /// Joins another copy of the same write: field-wise, a value over none, then the greater
    /// (spec/crdt.md §4.1 copy order).
    pub fn join_copy(&mut self, o: &Write) {
        match (&mut self.op, &o.op) {
            (Op::Set { value: a }, Op::Set { value: b }) => *a = (*a).max(*b),
            (Op::Create { key: a }, Op::Create { key: b }) => *a = (*a).max(*b),
            (Op::SetIn { key: ka, value: va, .. }, Op::SetIn { key: kb, value: vb, .. }) => {
                *ka = (*ka).max(*kb);
                *va = (*va).max(*vb);
            }
            (Op::Insert { anchor: aa, ch: ca }, Op::Insert { anchor: ab, ch: cb }) => {
                *aa = (*aa).max(*ab);
                *ca = (*ca).max(*cb);
            }
            _ => {}
        }
    }
    /// Text: the element record the write is on.
    pub fn elem(&self) -> Option<Dot> {
        match &self.op {
            Op::Insert { .. } | Op::Anchor => Some(self.stamp.dot),
            Op::Delete { elem } => Some(*elem),
            _ => None,
        }
    }
    pub fn fits(&self, kind: AspectKind) -> bool {
        matches!(
            (kind, &self.op),
            (_, Op::Reset)
                | (AspectKind::Register, Op::Set { .. })
                | (AspectKind::Map, Op::Create { .. } | Op::SetIn { .. } | Op::Remove { .. })
                | (AspectKind::Text, Op::Insert { .. } | Op::Delete { .. } | Op::Anchor)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    Read,
    Write,
    Admin,
}

/// One edge write in `roles.0` (spec/permissions.md §2): `role` None is a removal.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EdgeWrite {
    pub holder: NodeId,
    pub role: Option<Role>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Delta {
    Writes(Vec<Write>),
    Edge(EdgeWrite),
}

/// What the node holds of one part's body.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Body {
    Held(Delta),
    /// Never received (or counting as never received).
    Missing,
    /// Dropped for its keep bounds or as covered: counts as held for atomic apply (spec/commits.md
    /// §4), contributes nothing; its live writes, if any, are in [`Held::own_state`].
    Dropped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PurgeBy {
    Nobody,
    Admin,
    Author,
    AuthorOrAdmin,
    Writer,
}

/// spec/commits.md §5 retention. Times are wall ms; durations are ms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Retention {
    pub by: PurgeBy,
    pub least_abs: Option<u64>,
    pub least_rel: Option<u64>,
    pub most_abs: Option<u64>,
    /// Keep at most 0 after replaced.
    pub most_zero: bool,
}

impl Retention {
    /// The untyped default: `author_or_admin`, no bounds.
    pub const PLAIN: Retention =
        Retention { by: PurgeBy::AuthorOrAdmin, least_abs: None, least_rel: None, most_abs: None, most_zero: false };
    pub const WRITER: Retention = Retention { by: PurgeBy::Writer, ..Retention::PLAIN };
    pub const ROLE: Retention = Retention { by: PurgeBy::Admin, least_rel: Some(ROLE_KEEP), ..Retention::PLAIN };
    pub fn with_by(self, by: PurgeBy) -> Retention {
        Retention { by, ..self }
    }
    pub fn has_most(&self) -> bool {
        self.most_abs.is_some() || self.most_zero
    }
    /// spec/commits.md §5 Carrier only.
    pub fn carrier_only(&self) -> bool {
        (self.least_abs.is_some() || self.least_rel.is_some_and(|d| d > 0)) && self.has_most()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Part {
    pub thing: ThingId,
    pub aspect: Aspect,
    pub retention: Retention,
    pub body: Body,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommitKind {
    Content,
    Role,
    /// A compaction snapshot: its writes are copies under their own stamps.
    Snapshot,
}

/// spec/commits.md §5 Purge: what a request names (deltas of commits with a smaller `ts`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PurgeItem {
    Commit(CommitId),
    Aspect { thing: ThingId, aspect: Aspect },
    Author { thing: ThingId, aspect: Aspect, author: NodeId },
}

/// A commit: its header (always held once the commit is in the input) and its parts' bodies.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Commit {
    pub id: CommitId,
    /// Author node; it acts for itself (no acting-for in this model).
    pub author: NodeId,
    pub ts: u64,
    /// `expires: T`, wall ms.
    pub expires: Option<u64>,
    pub kind: CommitKind,
    /// Header aspect-list order; one part per aspect, but a role commit has one per edge write.
    pub parts: Vec<Part>,
    pub purge: Vec<PurgeItem>,
    /// Demotions only: commit IDs the author had received (spec/permissions.md §5.1).
    pub frontier: Option<Vec<CommitId>>,
}

/// A position in the role timeline's order: `(ts, author node, commit ID)` (spec/permissions.md §6).
pub type Key = (u64, NodeId, CommitId);

impl Commit {
    pub fn key(&self) -> Key {
        (self.ts, self.author, self.id)
    }
    pub fn lists(&self, c: CommitId) -> bool {
        self.frontier.as_ref().is_some_and(|f| f.contains(&c))
    }
}

/// A thing: its owner is a node holding owner-chain (admin) authority, never removable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Thing {
    pub id: ThingId,
    pub owner: NodeId,
}

/// A write the node's state holds while no held body does (a body dropped for its keep bounds
/// left it, spec/commits.md §5 Never received; "own state counts as a snapshot", spec/crdt.md §4.6).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StateWrite {
    pub thing: ThingId,
    pub aspect: Aspect,
    pub write: Write,
}

/// Everything the model's output is a function of.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Held {
    /// The node's corrected clock, wall ms.
    pub now: u64,
    /// The node itself (for "may drop" judgments that need the right).
    pub me: NodeId,
    pub things: Vec<Thing>,
    /// Commit IDs are unique.
    pub commits: Vec<Commit>,
    pub own_state: Vec<StateWrite>,
}
