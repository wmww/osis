//! Input types: what a node holds. Abstract on purpose: ids are small integers; values are
//! crdt-model fragments.

pub use crdt_model::stamp::{Dot, Source, Stamp};
pub use crdt_model::state::Frag;
pub use crdt_model::value::Value;
pub use crate::thing_history::{Opt, NEVER};
use std::collections::BTreeMap;

pub type CommitId = u32;
/// Things, actors and nodes share one id space (spec/permissions.md §1: a holder is a thing; a
/// node signs as its node thing, minted with its key). `NodeId` names a signer, `ThingId` a target.
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
    /// `@` before the `~`: an external signal (spec/data-model.md §2), fired by parties holding no
    /// write where the setting enables it (`Held::external_fires`).
    pub external: bool,
}

impl Aspect {
    /// `roles.0`: carries edge writes only (role commits).
    pub const ROLES: Aspect = Aspect { name: 0, admin_only: true, signal: false, external: false };
    pub const fn plain(name: u32) -> Aspect {
        Aspect { name, admin_only: false, signal: false, external: false }
    }
    pub const fn admin(name: u32) -> Aspect {
        Aspect { name, admin_only: true, signal: false, external: false }
    }
    /// A signal `name~0`.
    pub const fn signal(name: u32) -> Aspect {
        Aspect { name, admin_only: false, signal: true, external: false }
    }
    /// An external signal `name@~0`.
    pub const fn external(name: u32) -> Aspect {
        Aspect { name, admin_only: false, signal: true, external: true }
    }
    /// `retention^.0`: the thing's history setting (spec/commits.md §5 The setting; `Delta::Retention`).
    pub const RETENTION: Aspect = Aspect { name: 8, admin_only: true, signal: false, external: false };
    /// `addenda.0` (spec/permissions.md §5.2 Addenda).
    pub const ADDENDA: Aspect = Aspect { name: 10, admin_only: false, signal: false, external: false };
    /// `created.0`: a thing's creation, the write that makes it exist (`Delta::Created`).
    pub const CREATED: Aspect = Aspect { name: 13, admin_only: false, signal: false, external: false };
    /// Role-class or fixed retention (`roles.0`, `purge.0`, `addenda.0`, `created.0`): governed
    /// by no setting, never out of history, never covered.
    pub fn fixed(&self) -> bool {
        matches!(self.name, 0 | 9 | 10 | 13)
    }
}

/// The dot source of commit-form commit `id` (spec/crdt.md §2.1): its ID, here the sync ID in the
/// last four bytes, so sources order as sync IDs do.
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

/// Sync and read judge alike here (neither writes); sync is in the lattice so a node's roster
/// translates whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    Sync,
    Read,
    Write,
    Admin,
}

/// One edge write in `roles.0` (spec/permissions.md §2): `role` None is a removal (erase); a
/// value with `until` 0 is a removal saying retain. `until` is wall ms; `may_grant` is the
/// may-grant flag (its holder may add holders up to the grant's role).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EdgeWrite {
    pub holder: NodeId,
    pub role: Option<Role>,
    pub may_grant: bool,
    pub until: Option<u64>,
}

impl EdgeWrite {
    pub const fn role(holder: NodeId, role: Option<Role>) -> EdgeWrite {
        EdgeWrite { holder, role, may_grant: false, until: None }
    }
}

/// One entry of a `retention^.0` setting (spec/commits.md §5 The setting): what it promises
/// for replaced content of the AKs it governs, and the expiry default a writer fills in
/// (`wall_ms(ts)` + duration; only the writer reads it: a commit is valid with the expiry it
/// carries).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SettingEntry {
    pub history: Opt,
    pub expires: Option<u64>,
    /// `purge_before`: a body holding a dead write whose `ts` is before this one is under purge on
    /// replace (0: none). Joined over the held settings (`Setting::joined_floor`); a writer writes
    /// the join (`Setting::written_after`).
    pub purge_before: u64,
}

/// A whole `retention^.0` setting: per aspect name its entry, and the default entry for every
/// AK with none (`retain`, the removal default, is not modeled). `written`: the `ts` of the
/// setting write a snapshot's body carries (`None`: the body's own commit's).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Setting {
    pub rules: Vec<(u32, SettingEntry)>,
    pub default: Option<SettingEntry>,
    pub written: Option<u64>,
}

impl Setting {
    /// The entry governing aspect `name`: its own, else the default.
    pub fn entry(&self, name: u32) -> Option<SettingEntry> {
        self.rules.iter().find(|r| r.0 == name).map(|r| r.1).or(self.default)
    }

    /// The entry governing aspect `a`: an external signal's is its own only, the default never
    /// (spec/commits.md §5 The setting).
    pub fn entry_of(&self, a: Aspect) -> Option<SettingEntry> {
        if a.external {
            self.rules.iter().find(|r| r.0 == a.name).map(|r| r.1)
        } else {
            self.entry(a.name)
        }
    }

    /// The entry governing aspect `name` (`None`: an aspect no setting names, so the default).
    fn governing(&self, name: Option<u32>) -> Option<SettingEntry> {
        name.map_or(self.default, |n| self.entry(n))
    }

    /// The `purge_before` of aspect `name` (`None`: one no setting names) joined over `held`,
    /// each setting with the `ts` of the write it carries, ordered by key (spec/commits.md §5
    /// One way): the greatest of every held setting's floor there and, for each one but the
    /// newest whose entry there purges on replace, the stamp of the next held one, unless a held
    /// floor there is already past its own stamp (`thing_history::joined_floor`).
    pub fn joined_floor(held: &[(u64, &Setting)], name: Option<u32>) -> u64 {
        let base = held.iter().filter_map(|(_, s)| s.governing(name)).map(|e| e.purge_before).max().unwrap_or(0);
        let purges = |s: &Setting| s.governing(name).is_some_and(|e| e.history == Opt::Purge);
        held.windows(2).filter(|w| purges(w[0].1) && base <= w[0].0).map(|w| w[1].0).fold(base, u64::max)
    }

    /// `self` as a writer holding `held` (ordered by key) writes it at `ts`, after each
    /// (spec/commits.md §5 One way): each entry's `purge_before` is at least the floor of its AK
    /// joined over `held` and `self`; the default's at least that of every AK `self` names not
    /// and of those no setting names (a default with no history if there is none).
    pub fn written_after(mut self, held: &[(u64, &Setting)], ts: u64) -> Setting {
        let all: Vec<(u64, &Setting)> = held.iter().copied().chain([(ts, &self)]).collect();
        let own: Vec<u64> = self.rules.iter().map(|(n, _)| Setting::joined_floor(&all, Some(*n))).collect();
        let lost = held.iter().flat_map(|(_, s)| s.rules.iter().map(|r| r.0)).filter(|n| !self.rules.iter().any(|x| x.0 == *n));
        let floor = lost.map(|n| Setting::joined_floor(&all, Some(n))).fold(Setting::joined_floor(&all, None), u64::max);
        for ((_, e), f) in self.rules.iter_mut().zip(own) {
            e.purge_before = e.purge_before.max(f);
        }
        if floor > 0 {
            let d = self.default.get_or_insert(SettingEntry { history: Opt::None, expires: None, purge_before: 0 });
            d.purge_before = d.purge_before.max(floor);
        }
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Delta {
    /// A content or snapshot fragment (spec/crdt.md §3).
    Writes(Frag),
    Edge(EdgeWrite),
    /// A whole `retention^.0` setting (on `Aspect::RETENTION`).
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
    /// Dropped here as covered by that snapshot commit's part on the aspect: it contributes
    /// nothing while the cover stands (valid, held or dropped covered itself); once not, the body
    /// counts as never received and is fetched again (`Outcome::uncovered`).
    /// Its commit applied when it was held, so it counts as a held part that does not wait
    /// (arrival order is not modeled).
    Dropped(CommitId),
    /// Held as bytes the node cannot interpret (spec/versioning.md §2): the part waits.
    Parked,
}

/// Who may purge a write, its purge-by (spec/commits.md §5): admins always may. What replaced
/// content is kept is the thing's setting (`Delta::Retention`), never the write's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PurgeBy {
    Admin,
    AuthorOrAdmin,
    Writer,
}

impl PurgeBy {
    /// The three sets a content write may name (Tess's decision 2, notes/engine-retention-history.md).
    pub const ALL: [PurgeBy; 3] = [PurgeBy::Admin, PurgeBy::AuthorOrAdmin, PurgeBy::Writer];
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub thing: ThingId,
    pub aspect: Aspect,
    pub purge_by: PurgeBy,
    pub body: Body,
    /// The commits whose writes this node removed from the held body as gone (it holds its
    /// leftover); one no longer gone makes the body count as never received (spec/permissions.md §6).
    pub stripped: std::collections::BTreeSet<CommitId>,
    /// A signal edit's claim (`edits::listing`, notes/signal-edits-design.md): the fire this part replaces.
    pub replaces: Option<CommitId>,
    /// The delete keys its commit lists for it and the steps it records (spec/crypto.md §7).
    pub keys: Keys,
}

/// A delete key, by identity (spec/crypto.md §7).
pub type KeyId = u64;

/// A listed key's level: 1, a step's delete key; 3, its write key (level 2 is not checked).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyLevel {
    Admin,
    Writer,
}

/// A step a `sync.0` body records (spec/sync-ids.md §2): its ID, its parent's (none for a
/// genesis step) and the keys it bears. Its signature is taken as verifying under its parent's
/// delete key: no forged step is modelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StepRec {
    pub id: u64,
    pub parent: Option<u64>,
    pub delete: KeyId,
    pub write: KeyId,
}

impl StepRec {
    pub fn bears(&self, level: KeyLevel) -> KeyId {
        match level {
            KeyLevel::Admin => self.delete,
            KeyLevel::Writer => self.write,
        }
    }
}

/// A part's delete keys (spec/crypto.md §7 Checked keys): the level-1 and level-3 keys its commit
/// lists for its delta, and, on a `sync.0` part, the steps its body records. A part listing none
/// is not checked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Keys {
    pub listed: Vec<(KeyLevel, KeyId)>,
    pub steps: Vec<StepRec>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommitKind {
    Content,
    Role,
    /// A compaction snapshot: its writes are copies under their own stamps.
    Snapshot,
}

/// The path a commit states for one thing it writes (spec/permissions.md §1 Path): the things
/// [A1..Ak] it writes it along, and the hops it marks direct (by index: hop 0 joins the thing
/// signed as to the next member).
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Path {
    pub things: Vec<ThingId>,
    pub direct: Vec<usize>,
}

impl Path {
    pub fn along(things: &[ThingId]) -> Path {
        Path { things: things.to_vec(), direct: vec![] }
    }
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
    /// The signing node (spec/wire.md §4 field 1).
    pub signer: NodeId,
    /// Its purge author (spec/permissions.md §6): the thing signed as, or a thing its path lists; a
    /// member of the path of every thing it writes (a part whose path leaves it out holds nothing).
    pub author: ThingId,
    /// The path it states for each thing it writes (spec/permissions.md §1 Path); none listed for
    /// a thing with no entry.
    pub paths: BTreeMap<ThingId, Path>,
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
    /// Snapshots only: marked as its signer's own cover (spec/wire.md §4 field 17 bit 0,
    /// spec/permissions.md §5.1 Own cover): only its signer drops a held body under it.
    pub own_cover: bool,
    /// `secrets.0` boxes it carries for the node (`fetch`): each opens with the node's own key
    /// and may be forged (it then opens nothing).
    pub boxes: Vec<KeyBox>,
}

/// A box: on `thing`'s `secrets.0` part, the role key it hands over. Forged boxes name a key no
/// sync ID has.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyBox {
    pub thing: ThingId,
    pub key: SyncId,
}

/// A sync ID, and the key that opens it (one id: a node holding a sync ID's key can open its entries).
pub type SyncId = u32;

/// A position in the role timeline's order: `(ts, author node, commit ID)` (spec/permissions.md §5.1).
pub type Key = (u64, NodeId, CommitId);

impl Commit {
    pub fn key(&self) -> Key {
        (self.ts, self.signer, self.id)
    }
    pub fn is_role(&self) -> bool {
        self.kind == CommitKind::Role
    }
    /// Stating `things` as the path of every thing it writes.
    pub fn along(mut self, things: &[ThingId]) -> Commit {
        self.paths = self.parts.iter().map(|p| (p.thing, Path::along(things))).chain(self.purge.iter().map(|it| match *it {
            PurgeItem::Commit { thing, .. } | PurgeItem::Aspect { thing, .. } | PurgeItem::Author { thing, .. } => (thing, Path::along(things)),
        })).collect();
        self
    }
}

/// What a creation record puts above its thing (spec/permissions.md §1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordLink {
    /// Minted with a key (a node thing, a link key): the key holds admin on it.
    Key,
    /// Its mint admin: holds its record edge.
    Admin(NodeId),
}

impl RecordLink {
    /// The mint admin the record names; a thing minted with a key has none.
    pub fn mint_admin(self) -> Option<NodeId> {
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

/// Which commits count when two commits of one session overlap: counter ranges on one aspect
/// that intersect (spec/commits.md §4: both are invalid). A void commit is invalid whole but
/// for `created.0`. `model::evaluate_with` takes it; `evaluate` judges by `Held`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Overlap {
    /// The spec's rule as written and built: every applied commit counts, whatever its
    /// validity; a void commit is void for every judgment (its addenda vouch for nothing, its
    /// setting is none, its purge requests drop nothing).
    #[default]
    Held,
    /// S3's rule as a last layer: the deltas on the aspect must both be valid by every other
    /// rule, judged with no overlap anywhere (`Outcome::otherwise`); no other judgment reads
    /// the result (a void commit's addenda, setting and purge requests still count).
    Valid,
    /// A probe: these commits are void, for every judgment as under `Held`. `Outcome::otherwise`
    /// then gives which pairs a rule reading those verdicts finds (`overlap::consistent`).
    Given(std::collections::BTreeSet<CommitId>),
}

/// When a fire of an external signal by a party holding no write on the thing (one its author's
/// authority does not make valid, spec/permissions.md §5.2) is valid. `Any` is the default so that
/// comparisons with an engine without the rule (osis-engine `tests/it/held.rs`) leave it off.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ExternalFires {
    /// Whatever the setting.
    #[default]
    Any,
    /// The rule (spec/permissions.md §5.2 External fires): iff the thing's current setting
    /// (spec/commits.md §5 In force) has an entry of its own naming the signal.
    Enabled,
    /// Rejected variant, a negative control: the setting with the greatest key below the fire's.
    /// A fire stamped back to before a disabling setting stays valid, and one stamped between two
    /// settings turns invalid when the older one drops.
    AtKey,
    /// Negative control: the last enabling setting in input order (arrival order).
    Arrival,
}

/// Everything the model's output is a function of.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Held {
    /// The node's wall clock, ms.
    pub now: u64,
    /// The node itself (for "may drop" judgments that need the right).
    pub me: NodeId,
    /// Creation records the node knows without a held creation: things minted with a key and the raw records
    /// a dependent's record chain carries (spec/permissions.md §1). A held creation's record is
    /// known too (`model::records`); an input may list it here as well. A record is identity: a
    /// thing exists while a creation of it joins, or, no held commit listing a creation of it,
    /// while its record alone is known.
    pub records: Vec<Record>,
    /// Commit IDs are unique.
    pub commits: Vec<Commit>,
    /// Session-form dot ranges (and any commit-form commit not labelled by `commit_source`).
    pub dots: Vec<DotRange>,
    /// The external-fire rule this judgment follows.
    pub external_fires: ExternalFires,
}
