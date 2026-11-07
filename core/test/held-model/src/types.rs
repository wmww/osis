//! Input types: what a node holds. Abstract on purpose: ids are small integers, values are `u32`.

pub type CommitId = u32;
/// Things, actors and nodes share one id space (spec/permissions.md §1: an actor is a thing; a
/// node is a key actor). `NodeId` names a signer, `ThingId` a target.
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
    /// `required.0^` (spec/commits.md §5 Required retention).
    pub const REQUIRED: Aspect = Aspect { name: 8, kind: AspectKind::Register, admin_only: true };
    /// `addenda.0` (spec/permissions.md §5.2 Addenda).
    pub const ADDENDA: Aspect = Aspect { name: 10, kind: AspectKind::Map, admin_only: false };
    /// Role-class or fixed retention: answers to no required retention (spec/commits.md §5).
    pub fn fixed(&self) -> bool {
        matches!(self.name, 0 | 8 | 9 | 10)
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
    /// Text: deleted-flag write `false` (an undelete, spec/crdt.md §5.7) carrying a copy of the
    /// element's char, owned by the element's creating delta (spec/crdt.md §4.7).
    Undelete { elem: Dot, ch: Option<Val> },
    /// Text: a bare anchor record (no write). Only snapshots carry it;
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
            Op::Undelete { elem, .. } => (s, 8, *elem),
        }
    }
    /// The commit whose delta carries the write (attribution by dot, spec/crdt.md §4.7).
    pub fn origin(&self) -> CommitId {
        self.stamp.dot.commit
    }
    /// The value fields with the commit carrying each (a `SetIn` key is the entry creation's).
    pub fn values(&self) -> Vec<(CommitId, Option<Val>)> {
        let own = self.origin();
        match &self.op {
            Op::Set { value } => vec![(own, *value)],
            Op::Create { key } => vec![(own, *key)],
            Op::SetIn { entry, key, value } => vec![(entry.commit, *key), (own, *value)],
            Op::Insert { ch, .. } => vec![(own, *ch)],
            Op::Undelete { elem, ch } => vec![(elem.commit, *ch)],
            _ => vec![],
        }
    }
    /// Strips every value field whose carrying commit `drop` names.
    pub fn strip(&mut self, drop: impl Fn(CommitId) -> bool) {
        let own = self.origin();
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
            Op::Undelete { elem, ch } if drop(elem.commit) => *ch = None,
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
            (Op::Undelete { ch: a, .. }, Op::Undelete { ch: b, .. }) => *a = (*a).max(*b),
            _ => {}
        }
    }
    /// Text: the element record the write is on.
    pub fn elem(&self) -> Option<Dot> {
        match &self.op {
            Op::Insert { .. } | Op::Anchor => Some(self.stamp.dot),
            Op::Delete { elem } | Op::Undelete { elem, .. } => Some(*elem),
            _ => None,
        }
    }
    pub fn fits(&self, kind: AspectKind) -> bool {
        matches!(
            (kind, &self.op),
            (_, Op::Reset)
                | (AspectKind::Register, Op::Set { .. })
                | (AspectKind::Map, Op::Create { .. } | Op::SetIn { .. } | Op::Remove { .. })
                | (AspectKind::Text, Op::Insert { .. } | Op::Delete { .. } | Op::Undelete { .. } | Op::Anchor)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    Read,
    Write,
    Admin,
}

/// One edge write in `roles.0` (spec/permissions.md §2): `role` None is a removal (erase); a
/// value with `until` 0 is a removal saying retain. `until` is wall ms; `invite` at most `role`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EdgeWrite {
    pub holder: NodeId,
    pub role: Option<Role>,
    pub invite: Option<Role>,
    pub until: Option<u64>,
}

impl EdgeWrite {
    pub const fn role(holder: NodeId, role: Option<Role>) -> EdgeWrite {
        EdgeWrite { holder, role, invite: None, until: None }
    }
}

/// One entry of a `required.0^` setting (spec/commits.md §5 Required retention): `aspect` None is
/// the default (every AK with no entry of its own), else an aspect name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rule {
    pub aspect: Option<u32>,
    pub retention: Retention,
    /// Expiry as a duration from the commit's `wall_ms(ts)`, ms.
    pub expiry: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Delta {
    Writes(Vec<Write>),
    Edge(EdgeWrite),
    /// A whole `required.0^` setting (its `rules`; `keep` is not modeled).
    Required(Vec<Rule>),
    /// `addenda.0` entries: per entry the removal's commit and the commits it lists.
    Addenda(Vec<(CommitId, Vec<CommitId>)>),
}

/// What the node holds of one part's body.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Body {
    Held(Delta),
    /// Never received (or counting as never received).
    Missing,
    /// Dropped here as covered by that snapshot commit's part on the aspect, or a snapshot dropped
    /// as named by that purge request: it contributes nothing while the cover stands (valid, not
    /// purged, held or dropped covered itself) or the request drops it; once not, the body counts
    /// as never received and is fetched again (`Outcome::uncovered`).
    /// Its commit applied when it was held, so it counts as a held part that does not wait
    /// (arrival order is not modeled).
    Dropped(CommitId),
    /// Held as bytes the node cannot interpret (spec/versioning.md §2): the part waits.
    Parked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PurgeBy {
    Nobody,
    Admin,
    Author,
    AuthorOrAdmin,
    Writer,
}

/// spec/commits.md §5 history mode of a write's body (the issue retention-modes). `PurgeOnReplace`:
/// gone once replaced (a writer applying a kill of any of its writes covers it in that transaction;
/// `writer` only). `Keep`: kept at least until wall ms `until` (0: no absolute bound; `FOREVER`)
/// and/or until `after` ms past the earliest valid replacing write the node holds (0: no
/// relative bound), the later; both 0 is convenient (no promise). The bound limits every node's
/// covered drop alike (a function of the held set) and what `history()` shows. Expiry and purge
/// act whatever the mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum History {
    PurgeOnReplace,
    Keep { until: u64, after: u64 },
}

impl History {
    pub const CONVENIENT: History = History::Keep { until: 0, after: 0 };
}

/// spec/commits.md §5 retention: who may purge the body and its history mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Retention {
    pub by: PurgeBy,
    pub history: History,
}

impl Retention {
    /// The untyped default: `author_or_admin`, convenient.
    pub const PLAIN: Retention = Retention { by: PurgeBy::AuthorOrAdmin, history: History::CONVENIENT };
    pub const WRITER: Retention = Retention { by: PurgeBy::Writer, ..Retention::PLAIN };
    /// Gone once replaced.
    pub const PURGE_ON_REPLACE: Retention = Retention { by: PurgeBy::Writer, history: History::PurgeOnReplace };
    /// Role-class: `admin`; the model drops no role body (ROLE_KEEP is compactor policy).
    pub const ROLE: Retention = Retention { by: PurgeBy::Admin, ..Retention::PLAIN };
    /// `created.0` and `required.0^` (spec/commits.md §5 Fixed retention): kept for good.
    pub const FIXED: Retention = Retention { by: PurgeBy::Nobody, history: History::Keep { until: FOREVER, after: 0 } };
    pub fn with_by(self, by: PurgeBy) -> Retention {
        Retention { by, ..self }
    }
    /// Kept until wall ms `t`.
    pub fn until(self, t: u64) -> Retention {
        let after = match self.history {
            History::Keep { after, .. } => after,
            History::PurgeOnReplace => 0,
        };
        Retention { history: History::Keep { until: t, after }, ..self }
    }
    /// Kept until `d` ms after replaced.
    pub fn after(self, d: u64) -> Retention {
        let until = match self.history {
            History::Keep { until, .. } => until,
            History::PurgeOnReplace => 0,
        };
        Retention { history: History::Keep { until, after: d }, ..self }
    }
    /// The wall ms before which the body is must-hold at every node (the absolute bound).
    pub fn kept_until(&self) -> u64 {
        match self.history {
            History::PurgeOnReplace => 0,
            History::Keep { until, .. } => until,
        }
    }
    /// The relative bound: ms after the earliest replacing write, 0 for none.
    pub fn kept_after(&self) -> u64 {
        match self.history {
            History::PurgeOnReplace => 0,
            History::Keep { after, .. } => after,
        }
    }
    /// Whether the mode promises any history (shown by `history()` while kept).
    pub fn keeps(&self) -> bool {
        self.kept_until() > 0 || self.kept_after() > 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Part {
    pub thing: ThingId,
    pub aspect: Aspect,
    pub retention: Retention,
    pub body: Body,
    /// The commits whose values this node stripped from the held body (it holds its leftover); one
    /// no longer held value-less makes the body count as never received (spec/permissions.md §6).
    pub stripped: std::collections::BTreeSet<CommitId>,
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
    /// That commit's delta on that aspect (spec/wire.md §4 `[commit_id, tid, ak]`).
    Commit { commit: CommitId, thing: ThingId, aspect: Aspect },
    Aspect { thing: ThingId, aspect: Aspect },
    Author { thing: ThingId, aspect: Aspect, author: NodeId },
}

/// A commit: its header (always held once the commit is in the input) and its parts' bodies.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Commit {
    pub id: CommitId,
    /// Author node (the signer).
    pub author: NodeId,
    /// The header's actor (spec/permissions.md §5.2 Acting); the author when it acts for itself.
    pub actor: NodeId,
    pub ts: u64,
    /// `expires: T`, wall ms.
    pub expires: Option<u64>,
    pub kind: CommitKind,
    /// Header aspect-list order; one part per aspect, but a role commit has one per edge write.
    pub parts: Vec<Part>,
    pub purge: Vec<PurgeItem>,
    /// Demotions only: commit IDs the author had received (spec/permissions.md §5.1).
    pub frontier: Option<Vec<CommitId>>,
    /// `undoes` (spec/commits.md §7).
    pub undoes: Option<CommitId>,
}

/// A position in the role timeline's order: `(ts, author node, commit ID)` (spec/permissions.md §5.1).
pub type Key = (u64, NodeId, CommitId);

impl Commit {
    pub fn key(&self) -> Key {
        (self.ts, self.author, self.id)
    }
    pub fn lists(&self, c: CommitId) -> bool {
        self.frontier.as_ref().is_some_and(|f| f.contains(&c))
    }
    pub fn is_role(&self) -> bool {
        self.kind == CommitKind::Role
    }
}

/// What a creation record puts above its thing (spec/permissions.md §1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordLink {
    /// A key actor (node, link key, recovery key): admin of itself.
    Key,
    /// Its first admin (a key actor or a thing that is an actor): holds its record edge.
    Admin(NodeId),
}

/// A known creation record. A thing, node or actor not listed has an unknown record
/// (spec/commits.md §4: it waits).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Thing {
    pub id: ThingId,
    pub link: RecordLink,
}

/// Everything the model's output is a function of.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Held {
    /// The node's corrected clock, wall ms.
    pub now: u64,
    /// The node itself (for "may drop" judgments that need the right).
    pub me: NodeId,
    /// Every creation record the node knows, key actors' included.
    pub things: Vec<Thing>,
    /// Commit IDs are unique.
    pub commits: Vec<Commit>,
}
