//! What `read` stands on (`Ground`): the engine's judgement of what S carries, read per (S,
//! commit) as memo values; the own store's entries of S per commit; each source's stream of S
//! (`known`, per commit and source); and the acts read does. Every value read is a memo or a
//! stamped read, so `Effects` follows it, and each feed (`*_added`) is a cursor over an index's
//! own log; `Live` is the product's, a test's ground is a table of stamped values.

use crate::store::{Source, Stand};
use crate::types::{ConnId, Entry, Result};
use osis_base::{BlobId, CommitId, SyncId, WallMs};
use osis_crypto::SigningSecret;
use osis_engine::sync::{BodyFacts, BodyMeta, Destruction, PartSet, ReadCredentials};
use osis_label::StepId;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::Why;

/// The engine's facts about one body at S (spec/sync-judgement.md §2-§3): the facade's
/// `BodyFacts` and what the judgement reads beside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facts {
    pub body: BodyFacts,
    /// A must-not-hold condition only the engine judges (purged, a strict subset, a superseded
    /// or ended card), if any.
    pub must_not: Option<Why>,
    /// This node's own commit (`own_commits`).
    pub own: bool,
    /// A role commit or request (spec/sync-judgement.md §3 Role entries first).
    pub role: bool,
    /// Per delta needing a carrier (holding a live write, kept, or dropped as covered and not
    /// purged), the commits whose entries under S would carry it (spec/sync-compaction.md §1
    /// Carriers): one of each set must be held where the body leaves. Empty: none needed.
    pub carriers: Vec<BTreeSet<CommitId>>,
    /// Snapshots of the body's aspects stamped later than it that this node does not hold
    /// (forgotten, dropped), each with whether this node judged it invalid (spec/sync-judgement.md
    /// §2 established uncovered).
    pub later_unheld: Vec<(CommitId, bool)>,
    /// §3 Neither: a delete that removed the body from S stands (each delta only a blob carries
    /// is held by another blob of the commit, no purge request names one without dropping it).
    pub neither: bool,
    /// The body counts as never received again (spec/sync-judgement.md §3 Dropped bodies).
    pub missing: bool,
}

/// One source of S on a connection up now (spec/sync-opens.md §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SrcView {
    /// Where its rows live: its record, else the connection.
    pub at: Source,
    pub conn: ConnId,
    /// It keeps S unread (a store source); else it reads S.
    pub store: bool,
    /// Its head for S, as its stream or open showed.
    pub head: Option<StepId>,
    /// It is full for S (spec/sync-streams.md §4 Full).
    pub full: bool,
    /// Its stream shows a role commit this node does not hold (spec/sync-judgement.md §3 Role
    /// entries first: deletes toward it wait while it does).
    pub role_unheld: bool,
}

/// What a source's stream showed of one commit's entries under S (`known`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    /// Present there and not removed since.
    pub present: BTreeSet<BlobId>,
    /// Deleted there as this node saw (a deletion event, or a refusal as tombstoned), within
    /// `TOMBSTONE_LIFETIME`.
    pub deleted: BTreeSet<BlobId>,
}

/// What the node holds of one blob (spec/sync-compaction.md §1 Duplicates): `None` while its
/// bytes are not held (an entry without bytes is no duplicate).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobInfo {
    pub parts: PartSet,
    /// A per-sync-ID copy (spec/sync-judgement.md §1).
    pub copy: bool,
}

/// What read stands on and what it does.
pub trait Ground {
    /// Commits the engine came to hold since the last call (all of them at the first: a start).
    fn commits_added(&mut self) -> Result<Vec<CommitId>>;
    /// Per sync ID of the sync set, `c`'s body there (`Engine::sync_bodies`).
    fn bodies(&mut self, c: &CommitId) -> Result<Arc<BTreeMap<SyncId, BodyMeta>>>;
    fn facts(&mut self, s: &SyncId, c: &CommitId) -> Result<Facts>;
    /// Falls of held parts on `c`'s aspects so far (`Engine::fall_mark`, summed over them).
    fn fall_mark(&mut self, s: &SyncId, c: &CommitId) -> Result<u64>;
    fn credentials(&mut self, s: &SyncId) -> Result<Option<Arc<ReadCredentials>>>;
    /// S's thing's destruction, when S is a destroyed thing's own sync ID.
    fn destruction(&mut self, s: &SyncId) -> Result<Option<Arc<Destruction>>>;
    /// S is in the sync set, read here: read judges nothing else.
    fn reads(&mut self, s: &SyncId) -> Result<bool>;
    /// No group of S's closure holds a part of its `group.0` as a header only (spec/sync-judgement.md
    /// §2 outside the required set, §3 Header-only parts): until then nothing is judged outside it.
    fn closure_settled(&mut self, s: &SyncId) -> Result<bool>;
    /// A reader can pull S from here: this node publishes `reach.0`, or a connection shares S
    /// (spec/sync-judgement.md §3 Own store).
    fn pullable(&mut self, s: &SyncId) -> Result<bool>;
    /// The time (not followed: `Read` follows it through its clock).
    fn now(&self) -> WallMs;

    /// The entries of `c` in this node's own store of S.
    fn own(&mut self, s: &SyncId, c: &CommitId) -> Result<Vec<Entry>>;
    /// This node's own tombstones of `c`'s entries under S.
    fn own_tombstones(&mut self, s: &SyncId, c: &CommitId) -> Result<Vec<BlobId>>;
    /// No entry of S in the own store.
    fn own_empty(&mut self, s: &SyncId) -> Result<bool>;
    fn blob(&mut self, b: &BlobId) -> Result<Option<BlobInfo>>;
    /// Held blob `b` holds a part this node dropped for good (purged, past its bounds, expired,
    /// destroyed): must-not-hold wherever it is logged (spec/sync-judgement.md §1).
    fn dropped(&mut self, b: &BlobId) -> Result<bool>;

    /// The sources of S on connections up now.
    fn sources(&mut self, s: &SyncId) -> Result<Arc<Vec<SrcView>>>;
    /// One source of S, if up now (read per source, so a source's change moves its rows alone).
    fn source(&mut self, s: &SyncId, at: &Source) -> Result<Option<SrcView>>;
    /// Sources of S whose view was written (joined or changed) since the last call.
    fn sources_added(&mut self) -> Result<Vec<(SyncId, Source)>>;
    fn seen(&mut self, at: &Source, s: &SyncId, c: &CommitId) -> Result<Seen>;
    /// `known` rows written since the last call (a source's stream showed an entry of the commit,
    /// or its removal).
    fn seen_added(&mut self) -> Result<Vec<(Source, SyncId, CommitId)>>;
    /// Some source's stream shows an entry of `c` under S present.
    fn present_anywhere(&mut self, s: &SyncId, c: &CommitId) -> Result<bool>;
    /// Every entry of S the source's stream shows present (emptying).
    fn seen_all(&mut self, at: &Source, s: &SyncId) -> Result<BTreeSet<BlobId>>;
    /// A delete at a source of S is known within its tombstone (`TOMBSTONE_LIFETIME`).
    fn deletes_known(&mut self, s: &SyncId) -> Result<bool>;
    /// Every source of S heard out (spec/sync-status.md §1).
    fn heard_out(&mut self, s: &SyncId) -> Result<bool>;
    fn stand(&mut self, at: &Source, s: &SyncId, c: &CommitId) -> Result<Option<Stand>>;

    /// Logs `c`'s body under S in the own store; its blob, or `None` when it cannot be logged here.
    /// Not `fresh`: a held blob of it not tombstoned under S, verbatim under a wrap for S, else a
    /// fresh encryption. `fresh` (logged again once, §4): always a fresh encryption. A fresh
    /// encryption is `Engine::seal_body`'s alone (each section under the epoch it was written
    /// under, never this node's newest; refused when that epoch is not established here).
    fn log_own(&mut self, s: &SyncId, c: &CommitId, fresh: bool) -> Result<Option<BlobId>>;
    /// The entry leaves the own log, its tombstone noting `c`.
    fn drop_own(&mut self, s: &SyncId, b: &BlobId, c: &CommitId) -> Result<()>;
    fn lift(&mut self, s: &SyncId, b: &BlobId) -> Result<()>;
    /// A Delete of `b` at the source, signed by `key` (its head's delete key).
    fn delete(&mut self, at: &SrcView, s: &SyncId, b: &BlobId, key: &SigningSecret) -> Result<()>;
    /// `c`'s body given to a source this node does not stamp for (spec/sync-judgement.md §3
    /// Reader that is not a writer): own entry `b` relayed under its stamp when the source's head
    /// write key verifies it, else a fresh encryption (`Engine::seal_body`) deposited.
    fn deposit(&mut self, at: &SrcView, s: &SyncId, c: &CommitId, b: &BlobId) -> Result<()>;
    fn set_stand(&mut self, at: &Source, s: &SyncId, c: &CommitId, stand: &Stand) -> Result<()>;
    /// A destroyed thing's sync ID left (§5: emptied and heard out, held with no delete key, or
    /// untold): its store shredded, then `Engine::forget_destroyed`.
    fn forget(&mut self, s: &SyncId) -> Result<()>;
}
