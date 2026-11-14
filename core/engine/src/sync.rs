//! The engine's facade for sync (`osis_sync`; notes/sync-boundary.md, What sync calls on the
//! engine): what sync reads of plaintext and judgement, per sync ID, and the few commands it gives.
//! Sync reaches the engine only through these methods (and the opening, writing and clock calls
//! any node makes); the engine calls nothing of sync's. Every value call is meant to be a memo,
//! so a sync effect that reads one depends on exactly what the engine read.
//!
//! Not built (each returns `Error::NotBuilt` naming itself): every call marked replace or new in
//! the boundary note's table, until the engine is reshaped for it. Built: `ingest_relay`,
//! `wants`, `freed`, `next_timer`, `tick`, `set_now`, `known_actor`, `provers`, `key_open`.

use crate::apply::reach::Wants;
use crate::engine::DropFor;
use crate::ephemeral::EphCommit;
use crate::error::{Error, Result};
use crate::labeling::{Certs, HeadKeys, Sealed};
use crate::{Engine, Ingested};
use osis_base::{Ak, BlobId, CommitId, CreationRecord, Role, SyncId, Tid, WallMs};
use osis_crypto::{Epoch, NodeRng, Secret32, Signature, SigningSecret, WRAP_LEN};
use osis_label::{Address, Step, StepId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// An entry's wrap, or a random filler (spec/sync-ids.md §5).
pub type Wrap = [u8; WRAP_LEN];

/// The parts (aspect indexes) a blob holds.
pub type PartSet = BTreeSet<usize>;

/// The steps of a sync ID from its genesis step to its head, each with its claim set while held
/// (spec/sync-ids.md §5 Path).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Path {
    pub steps: Vec<(Step, Option<osis_label::ClaimSet>)>,
}

/// What `open_entry` did with an entry's blob.
#[derive(Debug)]
pub enum Opened {
    /// A commit blob: opened with a held read secret and taken.
    Commit(CommitId, Ingested),
    /// A chunk, tree node or page a held commit links: stored.
    Linked,
    /// An inbox blob, opened and taken.
    Inbox(InboxOpened),
    /// No held secret opens it (or nothing held links it).
    NotOpen,
    /// It opened and is bad (its sender is to blame).
    Bad,
}

/// What taking an inbox blob did (spec/sync-inbox.md §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxOpened {
    pub commit: CommitId,
    pub taken: Taken,
    /// Sync IDs of things whose box in the blob opened (spec/sync-inbox.md §2 hints).
    pub hints: Vec<(Tid, SyncId)>,
    /// The address the payload names to dial.
    pub dial: Option<Address>,
}

/// Whether the inbox blob's grant applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Taken {
    /// Applied here.
    Applied,
    /// Waits for the user (an invitation, spec/sync-set.md §4).
    Waiting,
    /// Not for this node, or refused.
    Refused,
}

/// One sync ID's body of a commit: what S carries of it (spec/sync-judgement.md §1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyMeta {
    pub parts: PartSet,
    pub expires: Option<WallMs>,
    /// Fetch order (spec/wire.md §5).
    pub order: u64,
    /// A per-sync-ID copy, not the shared blob.
    pub copy: bool,
    /// A certificate copy.
    pub certificate: bool,
    pub header_only: bool,
}

/// The facts the judgement of one body at one sync ID reads (spec/sync-judgement.md §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyFacts {
    /// In S's required set.
    pub required: bool,
    /// A closure body (not a certificate or inbox blob).
    pub closure: bool,
    /// Dropped here, and why.
    pub dropped: Option<DropFor>,
    /// A delta of it is kept (before its keep-at-least bound).
    pub kept: bool,
    /// Covered by a held valid snapshot under S; `None` while that cannot be judged yet.
    pub covered: Option<bool>,
    /// A certificate blob whose author has no other blob under S.
    pub sole_certificate: bool,
    /// The lasting header of a commit lasting on a thing of the closure.
    pub lasting_header: bool,
}

/// A destroyed thing's emptying (spec/sync-judgement.md §5): its destroying requests, by expiry alone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Destruction {
    pub requests: Vec<CommitId>,
}

/// Whether a writer may promote a deposited commit (spec/sync-inbox.md §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Promote {
    /// Yes, with its author's chain to log beside it.
    Yes { chain: Certs },
    NotYet,
    Never,
}

/// The node's sync set (spec/sync-set.md §2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncSet {
    pub ids: BTreeMap<SyncId, (Tid, Holding)>,
    /// Things in the synced group's closure with no sync ID this node may hold.
    pub unsyncable: BTreeSet<Tid>,
}

/// How a node holds a sync ID (spec/sync.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Holding {
    Read,
    Unread,
}

/// A sync ID a thing owns, with its recorded path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedSyncId {
    pub id: SyncId,
    pub path: Arc<Path>,
    /// A hint: held while the node holds no sync secret of the thing's own (spec/sync-ids.md §4).
    pub hint: bool,
}

/// What a reader of S opens and acts with (spec/sync-opens.md §4, spec/sync-ids.md §3).
#[derive(Clone, Default)]
pub struct ReadCredentials {
    /// The recorded path's newest step.
    pub head: Option<Step>,
    /// The role keys held per recorded step.
    pub keys: BTreeMap<StepId, HeadKeys>,
    /// Current read secrets (the engine's history-less floors).
    pub read_secrets: Vec<(Epoch, Secret32)>,
    /// Static entries of S's roster (link keys).
    pub statics: BTreeSet<[u8; 32]>,
}

/// The secrets an entry box held (spec/sync-ids.md §3 Entry boxes).
#[derive(Clone)]
pub struct EntryBoxSecrets {
    pub read: (Epoch, Secret32),
    pub superseded: Option<(Epoch, Secret32)>,
    pub sync: (Epoch, Secret32),
}

/// A thing this node keeps a sync record of (spec/sync.md §3 Kept unread).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncRecord {
    pub sync_ids: Vec<SyncId>,
    pub secrets: BTreeMap<Epoch, Secret32>,
}

/// J of a peer for S (spec/sync-opens.md §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum J {
    Reader,
    SyncHolder,
    Departed,
    Unknown,
}

/// A removal notice held in this node's inbox (spec/wire.md §9 position 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemovalNotice {
    pub sync_id: SyncId,
    pub sig: Signature,
    pub recipient: Tid,
    pub commit: CommitId,
}

/// An invitation waiting for the user (spec/sync-set.md §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invitation {
    pub thing: Tid,
    pub role: Role,
    pub from: Tid,
    pub taken: bool,
}

/// `caps^.0` of this node (spec/sync-ids.md §5 Caps).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Caps {
    pub policy: BTreeMap<String, u64>,
    pub things: BTreeMap<Tid, ThingCaps>,
}

/// One thing's limits in place of the policy's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThingCaps {
    pub entries: u64,
    pub bytes: u64,
}

fn not_built<T>(what: &'static str) -> Result<T> {
    Err(Error::NotBuilt(what))
}

impl Engine {
    // Ingest

    /// Opens an entry's wrap with a held read secret and takes what the blob holds.
    pub fn open_entry(&mut self, s: &SyncId, blob: &BlobId, wrap: &Wrap, bytes: &[u8]) -> Result<Opened> {
        let _ = (s, blob, wrap, bytes);
        not_built("open_entry")
    }

    /// A relay-only commit (spec/sync-compaction.md §2): `Some` when new here (passed on).
    pub fn ingest_relay(&mut self, bytes: &[u8]) -> Result<Option<EphCommit>> {
        let blob = osis_commit::CommitBlob::decode(bytes)?;
        let id = blob.id();
        let kept = blob.clone();
        Ok(self.ingest_relay_blob(blob)?.then_some(EphCommit { id, blob: kept }))
    }

    /// What to fetch: pages and header lists before apply.
    pub fn wants(&mut self) -> Result<Arc<Wants>> {
        Ok(Arc::new(self.blob_wants()?))
    }

    // Held parts and bodies

    /// Per sync ID of the sync set whose required set holds a body of `c`: that body.
    pub fn sync_bodies(&mut self, c: &CommitId) -> Result<Arc<BTreeMap<SyncId, BodyMeta>>> {
        let _ = c;
        not_built("sync_bodies")
    }

    pub fn body_facts(&mut self, s: &SyncId, c: &CommitId) -> Result<BodyFacts> {
        let _ = (s, c);
        not_built("body_facts")
    }

    /// The parts an opened blob holds.
    pub fn blob_parts(&mut self, b: &BlobId) -> Result<Option<PartSet>> {
        let _ = b;
        not_built("blob_parts")
    }

    /// `c`'s body under `s` sealed, with its wrap for `s`.
    pub fn seal_body(&mut self, s: &SyncId, c: &CommitId, rng: &mut dyn NodeRng) -> Result<Option<(Sealed, Wrap)>> {
        let _ = (s, c, rng);
        not_built("seal_body")
    }

    /// Falls of held parts on the aspect so far (durable; spec/sync-judgement.md §4 compares marks).
    pub fn fall_mark(&mut self, thing: &Tid, ak: &Ak) -> Result<u64> {
        let _ = (thing, ak);
        not_built("fall_mark")
    }

    /// This node's commits and self-removals with a body under `s` (spec/sync-status.md §2).
    pub fn own_commits(&mut self, s: &SyncId) -> Result<Arc<BTreeSet<CommitId>>> {
        let _ = s;
        not_built("own_commits")
    }

    pub fn destruction(&mut self, thing: &Tid) -> Result<Option<Arc<Destruction>>> {
        let _ = thing;
        not_built("destruction")
    }

    /// Drops a destroyed thing's secrets, last (spec/sync-judgement.md §5).
    pub fn forget_destroyed(&mut self, thing: &Tid) -> Result<()> {
        let _ = thing;
        not_built("forget_destroyed")
    }

    pub fn promotable(&mut self, s: &SyncId, c: &CommitId) -> Result<Promote> {
        let _ = (s, c);
        not_built("promotable")
    }

    /// Whether `b` is a freed link's blob.
    pub fn freed(&mut self, b: &BlobId) -> Result<bool> {
        self.is_freed(b)
    }

    // Keys and secrets for a sync ID

    pub fn sync_set(&mut self) -> Result<Arc<SyncSet>> {
        not_built("sync_set")
    }

    pub fn sync_ids(&mut self, thing: &Tid) -> Result<Arc<Vec<OwnedSyncId>>> {
        let _ = thing;
        not_built("sync_ids")
    }

    pub fn read_credentials(&mut self, s: &SyncId) -> Result<Option<Arc<ReadCredentials>>> {
        let _ = s;
        not_built("read_credentials")
    }

    /// The claim key from this node's own read KEM key and the step key (spec/sync-ids.md §3).
    pub fn claim_key(&mut self, s: &SyncId, step: &StepId) -> Result<Option<SigningSecret>> {
        let _ = (s, step);
        not_built("claim_key")
    }

    /// Opens an entry box for a key actor this node acts for (a link).
    pub fn open_entry_box(&mut self, s: &SyncId, step: &Step, entry: &[u8; 32], sealed: &[u8]) -> Result<Option<EntryBoxSecrets>> {
        let _ = (s, step, entry, sealed);
        not_built("open_entry_box")
    }

    pub fn sync_records(&mut self) -> Result<Arc<BTreeMap<Tid, SyncRecord>>> {
        not_built("sync_records")
    }

    pub fn drop_sync_record(&mut self, thing: &Tid) -> Result<()> {
        let _ = thing;
        not_built("drop_sync_record")
    }

    // Grants, removals, peers

    pub fn judge_peer(&mut self, s: &SyncId, proven: &[Tid]) -> Result<J> {
        let _ = (s, proven);
        not_built("judge_peer")
    }

    pub fn covers_departures(&mut self, s: &SyncId, epoch: Epoch) -> Result<bool> {
        let _ = (s, epoch);
        not_built("covers_departures")
    }

    /// Whether actor `a` is known here (spec/sync-opens.md §2).
    pub fn known_actor(&mut self, a: &Tid) -> bool {
        self.core.judge([*a]).known()
    }

    /// The account key this node proves with on a connection (spec/sync-opens.md §2): its signing
    /// key at its newest epoch, with the account's record. Connection proofs themselves are
    /// osis-proto's (`Prover`).
    pub fn provers(&mut self) -> Result<Option<(SigningSecret, CreationRecord)>> {
        self.account_prover()
    }

    /// Whether `key` is `record`'s actor's key at an epoch open here (a connection proof's key).
    pub fn key_open(&mut self, record: &CreationRecord, key: &[u8; 32]) -> bool {
        self.account_key_open(record, key)
    }

    pub fn deliveries(&mut self) -> Result<Arc<BTreeSet<(CommitId, Tid)>>> {
        not_built("deliveries")
    }

    pub fn delivery_taken(&mut self, c: &CommitId, holder: &Tid) -> Result<bool> {
        let _ = (c, holder);
        not_built("delivery_taken")
    }

    pub fn inbox_blob(&mut self, c: &CommitId, holder: &Tid, rng: &mut dyn NodeRng) -> Result<Option<Sealed>> {
        let _ = (c, holder, rng);
        not_built("inbox_blob")
    }

    pub fn take_inbox(&mut self, s: &SyncId, blob: &BlobId, accepted: bool) -> Result<InboxOpened> {
        let _ = (s, blob, accepted);
        not_built("take_inbox")
    }

    pub fn removal_notices(&mut self) -> Result<Arc<Vec<RemovalNotice>>> {
        not_built("removal_notices")
    }

    pub fn invitations(&mut self) -> Result<Arc<Vec<Invitation>>> {
        not_built("invitations")
    }

    pub fn waiting_held_elsewhere(&mut self) -> Result<Arc<BTreeSet<CommitId>>> {
        not_built("waiting_held_elsewhere")
    }

    pub fn held_elsewhere(&mut self, c: &CommitId) -> Result<()> {
        let _ = c;
        not_built("held_elsewhere")
    }

    pub fn note_complete_pass(&mut self, actor: &Tid, began: WallMs) -> Result<()> {
        let _ = (actor, began);
        not_built("note_complete_pass")
    }

    // Timers and config

    /// Moves the memo clock to `now`.
    pub fn set_now(&mut self, now: WallMs) {
        self.core.time.set(now.0);
    }

    pub fn caps(&mut self) -> Result<Arc<Caps>> {
        not_built("caps")
    }
}
