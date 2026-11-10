//! Input types: what a node holds. Abstract on purpose: ids are small integers; values are
//! crdt-model fragments.

pub use crdt_model::stamp::{Dot, Source, Stamp};
pub use crdt_model::state::Frag;
pub use crdt_model::value::Value;
pub use crate::thing_history::{Opt, NEVER};

pub type CommitId = u32;
/// Things, actors and nodes share one id space (spec/permissions.md §1: an actor is a thing; a
/// node is a key actor). `NodeId` names a signer, `ThingId` a target.
pub type NodeId = u32;
pub type ThingId = u32;

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

/// An aspect key: a name plus the markers an AK carries (spec/data-model.md §2). Its encodings
/// are its fragments' own (a write of another encoding joins as spec/crdt.md §7 says).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Aspect {
    pub name: u32,
    /// `^`: writes need admin (spec/permissions.md §5.2).
    pub admin_only: bool,
    /// `~`: a signal, no current value (spec/data-model.md §2). Durable here (the model has no
    /// ephemeral data): each write is history from the moment it is written, kept until its
    /// keep bound, expiry or purge, never joined into a state; parts carry one root register write.
    pub signal: bool,
}

impl Aspect {
    /// `roles.0`: carries edge writes only (role commits).
    pub const ROLES: Aspect = Aspect { name: 0, admin_only: true, signal: false };
    pub const fn plain(name: u32) -> Aspect {
        Aspect { name, admin_only: false, signal: false }
    }
    pub const fn admin(name: u32) -> Aspect {
        Aspect { name, admin_only: true, signal: false }
    }
    /// A signal `name~0`.
    pub const fn signal(name: u32) -> Aspect {
        Aspect { name, admin_only: false, signal: true }
    }
    /// `retention^.0`: the thing's history setting (issues/thing-history.md; `Delta::Retention`).
    pub const RETENTION: Aspect = Aspect { name: 8, admin_only: true, signal: false };
    /// `addenda.0` (spec/permissions.md §5.2 Addenda).
    pub const ADDENDA: Aspect = Aspect { name: 10, admin_only: false, signal: false };
    /// `created.0`: a thing's creation, the write that makes it exist (`Delta::Created`).
    pub const CREATED: Aspect = Aspect { name: 13, admin_only: false, signal: false };
    /// Role-class or fixed retention (`roles.0`, `retention^.0`, `purge.0`, `addenda.0`,
    /// `created.0`): governed by no setting, never out of history, never covered.
    pub fn fixed(&self) -> bool {
        matches!(self.name, 0 | 8 | 9 | 10 | 13)
    }
}

/// The dot source of commit-form commit `id` (spec/crdt.md §2.1): its ID, here the label in the
/// last four bytes, so sources order as labels do.
pub fn commit_source(id: CommitId) -> Source {
    let mut b = [0u8; 32];
    b[28..].copy_from_slice(&id.to_be_bytes());
    Source::Commit(b)
}

/// A stamp of commit-form commit `c` (spec/crdt.md §2.2).
pub fn stamp(ts: u64, c: CommitId, ctr: u64) -> Stamp {
    Stamp { ts, dot: Dot { source: commit_source(c), ctr } }
}

/// Counters `[lo, hi)` of `source` on one aspect belong to `commit` (spec/crdt.md §2.4: a header's
/// dot form and counter range per aspect). A commit no range names is commit form
/// (`commit_source`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DotRange {
    pub source: Source,
    pub thing: ThingId,
    pub aspect: Aspect,
    pub lo: u64,
    pub hi: u64,
    pub commit: CommitId,
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

/// One entry of a `retention^.0` setting (issues/thing-history.md, The setting): what it promises
/// for replaced content of the AKs it governs, and the expiry default a writer fills in
/// (`wall_ms(ts)` + duration; only the writer reads it: a commit is valid with the expiry it
/// carries).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SettingEntry {
    pub history: Opt,
    pub expires: Option<u64>,
}

/// A whole `retention^.0` setting: per aspect name its entry, and the default entry for every
/// AK with none (`retain`, the removal default, is not modeled).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Setting {
    pub rules: Vec<(u32, SettingEntry)>,
    pub default: Option<SettingEntry>,
}

impl Setting {
    /// The entry governing aspect `name`: its own, else the default.
    pub fn entry(&self, name: u32) -> Option<SettingEntry> {
        self.rules.iter().find(|r| r.0 == name).map(|r| r.1).or(self.default)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Delta {
    /// A content or snapshot fragment (spec/crdt.md §3).
    Writes(Frag),
    Edge(EdgeWrite),
    /// A whole `retention^.0` setting (on `Aspect::RETENTION`, fixed retention).
    Retention(Setting),
    /// `addenda.0` entries: per entry the removal's commit and the commits it lists.
    Addenda(Vec<(CommitId, Vec<CommitId>)>),
    /// A `created.0` write minting its part's thing's record (on `Aspect::CREATED`): the thing
    /// exists while one is held live (notes/expiry-creation-design.md §3).
    Created(RecordLink),
}

/// What the node holds of one part's body.
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// Who may purge a write (spec/commits.md §5): admins always may. `Nobody` is fixed retention's
/// only (`created.0`, `retention^.0`); content has the other three (Decisions 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PurgeBy {
    Nobody,
    Admin,
    AuthorOrAdmin,
    Writer,
}

/// A write's retention on the wire: who may purge it. What replaced content is kept is the
/// thing's setting (`Delta::Retention`), never the write's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Retention {
    pub by: PurgeBy,
}

impl Retention {
    /// The untyped default: `author_or_admin`.
    pub const PLAIN: Retention = Retention { by: PurgeBy::AuthorOrAdmin };
    pub const WRITER: Retention = Retention { by: PurgeBy::Writer };
    pub const ADMIN: Retention = Retention { by: PurgeBy::Admin };
    /// Role-class: `admin`; the model drops no role body (ROLE_KEEP is compactor policy).
    pub const ROLE: Retention = Retention::ADMIN;
    /// `created.0` and `retention^.0` (fixed retention): nobody may purge them.
    pub const FIXED: Retention = Retention { by: PurgeBy::Nobody };
    pub fn with_by(self, by: PurgeBy) -> Retention {
        Retention { by }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub thing: ThingId,
    pub aspect: Aspect,
    pub retention: Retention,
    pub body: Body,
    /// The commits whose values this node stripped from the held body (it holds its leftover); one
    /// no longer held value-less makes the body count as never received (spec/permissions.md §6).
    pub stripped: std::collections::BTreeSet<CommitId>,
    /// A signal edit's claim (`edits::listing`, notes/signal-edits-design.md): the fire this part replaces.
    pub replaces: Option<CommitId>,
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// `secrets.0` boxes it carries for the node (`fetch`): each opens with the node's own key
    /// and may be forged (it then opens nothing).
    pub boxes: Vec<KeyBox>,
}

/// A box: on `thing`'s `secrets.0` part, the label key it hands over. Forged boxes name a key no
/// label has.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyBox {
    pub thing: ThingId,
    pub key: Label,
}

/// A label, and the key that opens it (one id: a node holding a label's key can open its entries).
pub type Label = u32;

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
    /// A key actor (node, link key): admin of itself.
    Key,
    /// Its first admin (a key actor or a thing that is an actor): holds its record edge.
    Admin(NodeId),
}

impl RecordLink {
    /// The first admin the record names; a key actor has none.
    pub fn first_admin(self) -> Option<NodeId> {
        match self {
            RecordLink::Key => None,
            RecordLink::Admin(a) => Some(a),
        }
    }
}

/// A creation record: identity (its tid hashes it), apart from existence (`Delta::Created`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Record {
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
    /// Creation records the node knows without a held creation: key actors' and the raw records
    /// a dependent's record chain carries (spec/permissions.md §1). A held creation's record is
    /// known too (`model::records`); an input may list it here as well. A record is identity: a
    /// thing exists while a creation of it joins, or, no held commit listing a creation of it,
    /// while its record alone is known.
    pub records: Vec<Record>,
    /// Commit IDs are unique.
    pub commits: Vec<Commit>,
    /// Session-form dot ranges (and any commit-form commit not labelled by `commit_source`).
    pub dots: Vec<DotRange>,
}
