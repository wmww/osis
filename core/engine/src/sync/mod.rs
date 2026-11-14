//! The engine's facade for sync (`osis_sync`; notes/sync-facade.md): what sync reads of
//! plaintext and judgement, per sync ID, and the few commands it gives. Sync reaches the engine
//! only through these methods (and the opening, writing and clock calls any node makes); the
//! engine calls nothing of sync's. Every value call is a memo or reads stamped rows, so a sync
//! effect that reads one depends on exactly what the engine read; a value derived from one
//! whose reads move far more often than it does is kept per key instead, brought up to date by
//! `follow`.
//!
//! Not built (each returns `Error::NotBuilt` naming itself): `prove_rotations`,
//! `take_rotations`.

pub(crate) mod bodies;
pub(crate) mod certified;
pub(crate) mod deliveries;
pub(crate) mod dial;
pub(crate) mod facts;
pub(crate) mod falls;
pub(crate) mod held;
pub(crate) mod inbox;
pub(crate) mod pieces;
pub use pieces::PieceLink;
pub(crate) mod certblobs;
pub use certblobs::Carried;
pub(crate) use certblobs::with_chains;
pub(crate) mod records;
mod relay;
pub use relay::{Relay, RelayOpened};
mod set;
mod signing;
#[cfg(test)]
mod tests_facts;

pub use inbox::WaitingBlob;
pub use osis_label::DialHint;

use crate::apply::reach::Wants;
use crate::engine::DropFor;
use crate::error::{Error, Result};
use crate::labeling::{Certs, HeadKeys, Sealed};
use crate::{Engine, Ingested};
use osis_base::{Ak, BlobId, CommitId, CreationRecord, Role, SyncId, Tid, WallMs};
use osis_crypto::{Epoch, NodeRng, Secret32, SigningSecret, WRAP_LEN};
use osis_label::{Address, Step, StepId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// An entry's wrap, or a random filler (spec/sync-ids.md §5).
pub type Wrap = [u8; WRAP_LEN];

/// The parts (aspect indexes) a blob holds.
pub type PartSet = BTreeSet<usize>;

/// A blob of a commit held in the sync store, with an entry's wrap of it under a sync ID: what a
/// fresh encryption copies sections from (`Engine::seal_body`).
#[derive(Clone, Debug)]
pub struct HeldBlob {
    pub sync_id: SyncId,
    pub wrap: Wrap,
    pub bytes: Vec<u8>,
}

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
    /// A record blob (spec/wire.md §3): its records learned.
    Records(BTreeSet<Tid>),
    /// A list blob (spec/wire.md §4, List tree): the thing lists of this rotation held, or kept
    /// loose until it is.
    Lists(CommitId),
    /// No held secret opens it (or nothing held links it).
    NotOpen,
    /// It opened and is bad (its sender is to blame).
    Bad,
}

/// What taking an inbox blob did (spec/sync-inbox.md §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxOpened {
    /// The role commit (`None`: a stranded notice, no role commit to take).
    pub commit: Option<CommitId>,
    pub taken: Taken,
    /// Sync IDs of things whose box in the blob opened (spec/sync-inbox.md §2 hints).
    pub hints: Vec<(Tid, SyncId)>,
    /// The sending node's dial hint (spec/wire.md §9 position 4), for dialing only.
    pub dial: Option<DialHint>,
}

/// Whether the inbox blob's grant applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Taken {
    /// Applied here.
    Applied,
    /// Waits for the user (an invitation, spec/sync-set.md §4).
    Waiting,
    /// A boxes payload (or a blob boxing sync alone), held as an offer: never taken
    /// (spec/sync-inbox.md §2; spec/sync.md §3).
    Offered,
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
    /// Wall ms from which a right holder may delete it at peers keeping S unread once covered
    /// and dropped: `MAX_DRIFT` past the latest keep-at-least bound of its parts (0: at once;
    /// spec/commits.md §5 Keep at least, spec/sync-compaction.md §1).
    pub hosts_from: u64,
    /// Covered by a held valid snapshot under S; `None` while that cannot be judged yet.
    pub covered: Option<bool>,
    /// A certificate blob whose author has no other blob under S.
    pub sole_certificate: bool,
    /// The lasting header of a commit lasting on a thing of the closure.
    pub lasting_header: bool,
}

/// A must-not-hold condition only the engine judges (spec/sync-judgement.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MustNot {
    Purged,
    CardSuperseded,
    CardEnded,
}

/// What `read` judges one body at a sync ID on beside `BodyFacts` (`read_facts`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadFacts {
    pub body: BodyFacts,
    pub must_not: Option<MustNot>,
    /// Written here.
    pub own: bool,
    /// Written here by a repair (`Engine::relink`): the blobs it encrypted afresh, never repaired
    /// by way of it (spec/sync-ids.md §1 Repair); empty for any other commit.
    pub repair_fresh: Arc<BTreeSet<BlobId>>,
    /// A role commit or a purge request (spec/sync-judgement.md §3 Role entries first).
    pub role: bool,
    /// Per delta needing a carrier, the commits one of which must be held where the body leaves
    /// (spec/sync-compaction.md §1 Carriers).
    pub carriers: Vec<BTreeSet<CommitId>>,
    /// Snapshots of its aspects stamped later than it that this node does not hold, each with
    /// whether it was judged invalid (spec/sync-judgement.md §2 established uncovered).
    pub later_unheld: Vec<(CommitId, bool)>,
    /// It counts as never received again (spec/sync-judgement.md §3 Dropped bodies).
    pub missing: bool,
}

/// A destroyed thing keeping nothing whose secrets are held for deletes alone
/// (spec/sync-judgement.md §5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Destruction {
    /// Its destroying requests; none: destroyed by expiry alone (told at once).
    pub requests: Vec<CommitId>,
    /// Its own sync IDs, emptied once told.
    pub sync_ids: Vec<SyncId>,
    /// The held commits keyed by it (a part on it or acting for it): their entries anywhere are
    /// deleted by its keys before `forget_destroyed`.
    pub keyed: BTreeSet<CommitId>,
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

/// How this node syncs one thing of its synced group's closure (spec/sync-set.md §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThingSync {
    /// Read: its home sync ID (a destroyed thing being emptied: its own sync IDs).
    Read(Vec<SyncId>),
    /// Kept unread: the sync IDs its sync record names.
    Unread(Vec<SyncId>),
    /// Secrets of its own, neither a read nor a sync secret held (`Unsyncable`).
    Unsyncable,
    /// No secrets of its own: it travels under the sync IDs of the groups holding it.
    Plain,
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
    /// The signing keys of the key actors this node acts for on S (the link it redeems): their
    /// static entries are tested (spec/sync-opens.md §4).
    pub acting: Vec<osis_crypto::SigningSecret>,
    /// A digest of S's roster as J judges it (its reader actor's holders for keys, each with its
    /// role): moves with every grant, change or removal, rotated or not (spec/sync-opens.md §4).
    pub roster: [u8; 32],
    /// The sync proof (spec/sync-ids.md §2) of each recorded step whose sync key this node holds,
    /// deepest first: the head's is what a reader shows, the rest what the walk tests
    /// (spec/sync-ids.md §6 Walk).
    pub proofs: Vec<(StepId, [u8; 32])>,
    /// The sync key of each sync secret of S's thing held here, newest first, with its epoch:
    /// tested after the recorded steps' credentials (spec/sync-ids.md §6 Test).
    pub sync_keys: Vec<(Epoch, SigningSecret)>,
}

/// The secrets an entry box held (spec/sync-ids.md §3 Entry boxes).
#[derive(Clone)]
pub struct EntryBoxSecrets {
    pub read: (Epoch, Secret32),
    pub superseded: Option<(Epoch, Secret32)>,
    pub sync: (Epoch, Secret32),
}

/// A static entry's grant opened, not yet learned (`Engine::open_grant`).
#[derive(Clone)]
pub struct OpenedGrant {
    /// S's thing.
    pub thing: Tid,
    /// The head's sync key the box's sync secret derives: the answer's `sig` verifies under it.
    pub key: [u8; 32],
    pub secrets: EntryBoxSecrets,
}

/// The keys this node signs entries of a sync ID with (spec/sync-inbox.md §2-§4).
#[derive(Clone, Default)]
pub struct Signers {
    /// Its head's write key, established here: stamps.
    pub stamp: Option<SigningSecret>,
    /// The deposit key its head bears, from a held deposit seed.
    pub deposit: Option<SigningSecret>,
    /// Its head's delete key, established here: clearing deposits.
    pub delete: Option<SigningSecret>,
}

/// A thing this node keeps unread, as its account's sync record and the boxes payloads held give
/// it (spec/sync.md §3 Sync record).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncRecord {
    /// The kept sync IDs (`kept^.0` on D).
    pub sync_ids: Vec<SyncId>,
    /// The held sync secrets: the recorded ones and those of the boxes payloads held.
    pub secrets: BTreeMap<Epoch, Secret32>,
    /// Which of `secrets` are recorded.
    pub recorded: BTreeSet<Epoch>,
    /// The dial hints of the boxes payloads held whose sync IDs are kept (spec/sync-inbox.md
    /// §2), distinct: for dialing only (spec/sync-opens.md §1). Every one, so an accepted
    /// forger's hint hides no granter's.
    pub dials: Vec<DialHint>,
}

/// J of a peer for S (spec/sync-opens.md §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum J {
    Reader,
    SyncHolder,
    Departed,
    Unknown,
}

/// An invitation waiting for the user (spec/sync-set.md §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invitation {
    pub thing: Tid,
    pub role: Role,
    /// The granting account, where this node can tell it (spec/sync-inbox.md §2).
    pub from: Option<Tid>,
    pub taken: bool,
    /// The account acted on it before (`acted^.0` on D): accepted, filed elsewhere or unsynced.
    pub acted: bool,
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

/// The sync IDs a `sync.0` state records, owned or not.
pub(crate) fn recorded_ids(f: &osis_crdt::Fragment) -> BTreeSet<SyncId> {
    use osis_schema::RawKey;
    f.read().and_then(|v| osis_schema::core_types::SYNC.decode(&v).ok()).map(|m| m.into_keys().collect()).unwrap_or_default()
}

fn not_built<T>(what: &'static str) -> Result<T> {
    Err(Error::NotBuilt(what))
}

impl Engine {
    // Ingest

    /// Opens an entry's wrap with a held read secret and takes what the blob holds. `room`: what
    /// holding an ephemeral commit may cost under S's cap now (`ingest_memory`; `TooLarge`
    /// past it); a durable blob ignores it.
    pub fn open_entry(&mut self, s: &SyncId, blob: &BlobId, wrap: &Wrap, bytes: &[u8], room: u64) -> Result<Opened> {
        self.open_entry_now(s, blob, wrap, bytes, room)
    }

    /// What to fetch: pages and header lists before apply.
    pub fn wants(&mut self) -> Result<Arc<Wants>> {
        Ok(Arc::new(self.blob_wants()?))
    }

    // Held parts and bodies

    /// Brings the facade values kept per entry (`Core::published`, per labeled thing; each read
    /// thing's certificates per piece and commit, `certified`) up to date with what moved since
    /// the last call: whether any entry moved. Each refreshes itself when asked, but an `Effects`
    /// key that read an entry goes due only once the entry is written, so a module calls this
    /// before its `due()` (the driver, before each module's settle and until it moves nothing).
    /// Not done at each transaction's end: the read things come from the sync set, a whole walk,
    /// so a burst of n transactions between two sync steps would cost n walks, not one
    /// (notes/engine.md).
    pub fn follow(&mut self) -> Result<bool> {
        let moved = self.follow_published();
        Ok(self.follow_certificates()? | moved)
    }

    /// Per sync ID of the sync set whose required set holds a body of `c`: that body.
    pub fn sync_bodies(&mut self, c: &CommitId) -> Result<Arc<BTreeMap<SyncId, BodyMeta>>> {
        self.sync_bodies_now(c)
    }

    pub fn body_facts(&mut self, s: &SyncId, c: &CommitId) -> Result<BodyFacts> {
        self.body_facts_now(s, c)
    }

    /// What `read` judges `c`'s body under `s` on beside `BodyFacts` (`ReadFacts`).
    pub fn read_facts(&mut self, s: &SyncId, c: &CommitId) -> Result<ReadFacts> {
        self.read_facts_now(s, c)
    }

    /// Whether held blob `b` is must-not-hold under `s` as a strict subset of another blob of its
    /// commit among `held`, the blobs of it held under `s` (spec/sync-judgement.md §2).
    pub fn strict_subset(&mut self, s: &SyncId, b: &BlobId, held: &BTreeSet<BlobId>) -> Result<bool> {
        self.strict_subset_now(s, b, held)
    }

    /// Whether a delete that removed `c`'s body from `s` stands where `there` are the blobs of `c`
    /// still held (spec/sync-judgement.md §3 Neither): the body is then neither logged nor relayed
    /// there. False whatever `there` holds while the judgement is not established.
    pub fn neither(&mut self, s: &SyncId, c: &CommitId, there: &BTreeSet<BlobId>) -> Result<bool> {
        self.neither_now(s, c, there)
    }

    /// Falls of held parts on `c`'s aspects so far, summed over them (a body's stand mark).
    pub fn body_fall_mark(&mut self, c: &CommitId) -> Result<u64> {
        Ok(self.body_fall_mark_now(c))
    }

    /// A cursor over the commits held from now on (`memo::Feed`; a start lists `commit_ids`).
    pub fn commit_feed(&self) -> osis_base::memo::Feed<CommitId> {
        self.core.ix.commits.feed()
    }

    /// A cursor over the held commits that pended no more from now on (their waiting parts
    /// joined or went, `memo::Feed`): each may be judged again (`pends`).
    pub fn unpended_feed(&self) -> osis_base::memo::Feed<CommitId> {
        self.core.waits.unpended.feed()
    }

    /// The records `s` carries as certificates (spec/permissions.md §4): a record blob of those
    /// no record blob in the own store carries is logged there.
    pub fn certificate_records(&mut self, s: &SyncId) -> Result<Arc<BTreeSet<Tid>>> {
        self.certificate_records_now(s)
    }

    /// The thing lists `s` carries (spec/sync-judgement.md §1 List blobs), per rotation the
    /// things whose lists go: a list blob of those no list blob of that rotation in the own store
    /// carries is logged there.
    pub fn certificate_lists(&mut self, s: &SyncId) -> Result<Arc<BTreeMap<CommitId, BTreeSet<Tid>>>> {
        self.certificate_lists_now(s)
    }

    /// Whether a record blob (`r` none) or a list blob of rotation `r` can be sealed under `s`
    /// now: what is missing there waits for it.
    pub fn cert_wrap(&mut self, s: &SyncId, r: Option<&CommitId>) -> Result<bool> {
        self.cert_wrap_now(s, r)
    }

    /// Certificate blob `b` sealed here under `s` is in the own store no more: its row goes.
    pub fn forget_cert_blob(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        let (s, b) = (*s, *b);
        self.run(|tx| certblobs::forget_blob(tx, &s, &b))
    }

    /// The certificate blobs (record and list blobs) sealed here under `s`, each with what it
    /// carries.
    pub fn cert_blobs(&mut self, s: &SyncId) -> Result<Arc<BTreeMap<BlobId, Carried>>> {
        Ok(self.cert_blobs_now(s))
    }

    /// A record blob of `records` under `s` (spec/wire.md §3), its bytes and wrap.
    pub fn seal_records(&mut self, s: &SyncId, records: &BTreeSet<Tid>, rng: &mut dyn NodeRng) -> Result<Option<(BlobId, Vec<u8>, Wrap)>> {
        self.seal_records_now(s, records, rng)
    }

    /// A list blob of rotation `r`'s thing lists for `things` under `s` (spec/wire.md §4, List
    /// tree), its bytes and wrap.
    pub fn seal_lists(&mut self, s: &SyncId, r: &CommitId, things: &BTreeSet<Tid>, rng: &mut dyn NodeRng) -> Result<Option<(BlobId, Vec<u8>, Wrap)>> {
        self.seal_lists_now(s, r, things, rng)
    }

    /// This node's own certificates under `s` (spec/permissions.md §4), to log there.
    pub fn own_certificates(&mut self, s: &SyncId) -> Result<Arc<Certs>> {
        self.own_certificates_now(s)
    }

    /// The parts an opened or sealed blob holds (as opened or sealed here).
    pub fn blob_parts(&mut self, b: &BlobId) -> Result<Option<PartSet>> {
        Ok(self.blob_parts_now(b))
    }

    /// Whether held blob `b` holds a part of its commit dropped here (spec/sync-judgement.md §1:
    /// the blob is must-not-hold wherever it is logged).
    pub fn blob_dropped(&mut self, b: &BlobId) -> Result<bool> {
        Ok(self.blob_dropped_now(b))
    }

    /// `c`'s body under `s` as a fresh encryption, with its wrap for `s`: the one place sync
    /// encrypts a body (spec/crypto.md §5 Passing on). `held`: every blob of `c` the store holds
    /// bytes of, each with an entry's wrap (its sections go as they came where this node may not
    /// encrypt them). `None`: nothing may be made now; ask again when keys change.
    pub fn seal_body(&mut self, s: &SyncId, c: &CommitId, held: &[HeldBlob], rng: &mut dyn NodeRng) -> Result<Option<(Sealed, Wrap)>> {
        self.seal_body_now(s, c, held, rng)
    }

    /// A wrap for `to` of held blob `b` of commit `c`, from its entry's wrap under `from`: the
    /// held blob logged verbatim under another sync ID (`None`: an epoch not held, or a
    /// per-sync-ID copy on either side, which is never shared).
    pub fn rewrap(&mut self, c: &CommitId, b: &BlobId, from: &SyncId, from_wrap: &Wrap, to: &SyncId) -> Result<Option<Wrap>> {
        self.rewrap_now(c, b, from, from_wrap, to)
    }

    /// Falls of held parts on the aspect so far (durable; spec/sync-judgement.md §4 compares marks).
    pub fn fall_mark(&mut self, thing: &Tid, ak: &Ak) -> Result<u64> {
        Ok(self.fall_mark_now(thing, ak))
    }

    /// This node's commits and self-removals with a body under `s` (spec/sync-status.md §2).
    pub fn own_commits(&mut self, s: &SyncId) -> Result<Arc<BTreeSet<CommitId>>> {
        self.own_commits_now(s)
    }

    /// The destroyed things whose secrets are held for deletes alone (`destruction` of each).
    pub fn destructions(&mut self) -> Result<Arc<BTreeSet<Tid>>> {
        Ok(self.destroyed_now())
    }

    /// A destroyed thing's emptying (spec/sync-judgement.md §5); `None` unless `thing` is one.
    pub fn destruction(&mut self, thing: &Tid) -> Result<Option<Arc<Destruction>>> {
        self.destruction_now(thing)
    }

    /// Sync emptied `thing`'s own sync IDs and knows no entry keyed by it: its secrets drop, last
    /// (spec/sync-judgement.md §5).
    pub fn forget_destroyed(&mut self, thing: &Tid) -> Result<()> {
        self.forget_destroyed_now(thing)
    }

    /// Forgets this node's local copy of `t`, unsynced (spec/sync-set.md §3 Unsyncing): the
    /// content of `t` and of each thing whose secrets are `t`'s, but those this node's synced
    /// group's closure holds; their role-class aspects (`secrets.0` included) and secrets stay,
    /// and what arrives again counts as never received. Decodes every commit header (rare).
    pub fn forget_local(&mut self, t: &Tid) -> Result<()> {
        let closure = match self.sync_root()? {
            Some(root) => self.closure(&root),
            None => Arc::default(),
        };
        let core = &self.core;
        let mut things: BTreeSet<Tid> = core.ix.by_aspect.keys().map(|(x, _)| *x).filter(|x| core.secret_actor(x) == Some(*t)).collect();
        things.insert(*t);
        things.retain(|x| !closure.contains(x));
        if things.is_empty() {
            return Ok(());
        }
        let f = self.run(|tx| crate::retention::forget::forget(tx, crate::retention::forget::Scope::Local(&things), &BTreeMap::new()))?;
        if !f.things.is_empty() {
            self.reload()?;
            self.reexamine()?;
        }
        Ok(())
    }

    pub fn promotable(&mut self, s: &SyncId, c: &CommitId) -> Result<Promote> {
        self.promotable_now(s, c)
    }

    /// Whether `b` is a freed link's blob.
    pub fn freed(&mut self, b: &BlobId) -> Result<bool> {
        self.is_freed(b)
    }

    /// The links of `c`'s body made of `parts` (spec/sync-judgement.md §1: the tree roots and pages
    /// its deltas link, its header-list trees): where its pieces start.
    pub fn piece_roots(&mut self, c: &CommitId, parts: &PartSet) -> Result<Vec<PieceLink>> {
        self.piece_roots_now(c, parts)
    }

    /// What lies one step below piece `p`: `None` while its blob is not held; a node's or page's
    /// links; nothing for a chunk. A memo per link (a node is immutable): moves only as the blob
    /// is held or released.
    pub fn piece_below(&mut self, p: &PieceLink) -> Result<Option<Arc<Vec<PieceLink>>>> {
        self.piece_below_now(p)
    }

    /// Takes a piece's bytes (a blob a held body links, `pieces`' missing) from a store entry:
    /// held here from now on (`put_blobs`).
    pub fn take_piece(&mut self, b: &BlobId, bytes: Vec<u8>) -> Result<()> {
        if osis_label::blob_id(&bytes) != *b {
            return Ok(());
        }
        self.put_blobs(vec![(*b, bytes)])
    }

    /// Freed links judged freed (spec/sync-compaction.md §1 Freed links), whole: a start lists
    /// them, then follows `freed_feed` and `freed_link` per row.
    pub fn freed_rows(&mut self) -> Vec<(BlobId, Tid)> {
        self.core.ix.freed.keys().copied().collect()
    }

    /// A cursor over the freed links judged from now on (`memo::Feed`).
    pub fn freed_feed(&self) -> osis_base::memo::Feed<(BlobId, Tid)> {
        self.core.ix.freed.feed()
    }

    /// Freed link `b` of thing `t`, while judged freed and in the set (stamped).
    pub fn freed_link(&mut self, b: &BlobId, t: &Tid) -> Option<Arc<crate::retention::freed::Freed>> {
        self.core.ix.freed.get(&(*b, *t)).cloned()
    }

    // Keys and secrets for a sync ID

    /// The node's sync set (spec/sync-set.md §2), whole: `sync_things` and `thing_sync` of each.
    /// For listing; a module follows `sync_things` and `thing_sync` per thing.
    pub fn sync_set(&mut self) -> Result<Arc<SyncSet>> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.sync_set, &(), |e| e.sync_set_now())
    }

    /// Sync ID `s`'s thing and how this node's keys let it hold `s` (read or kept unread),
    /// whatever lists the thing: `sync_set`'s entry for `s` while the synced group's closure holds
    /// the thing, and what a sync ID leaving the sync set is held as while it waits
    /// (spec/sync-set.md §3). Reads only `s`'s owner's keys.
    pub fn sync_holder(&mut self, s: &SyncId) -> Result<Option<(Tid, Holding)>> {
        self.sync_holder_now(s)
    }

    /// The things the sync set is judged over: the synced group's closure (the same `Arc` while
    /// it does not change) and destroyed things being emptied.
    pub fn sync_things(&mut self) -> Result<Arc<BTreeSet<Tid>>> {
        self.sync_things_now()
    }

    /// How this node syncs thing `t` (read, kept unread, unsyncable, plain); reads only `t`'s keys.
    pub fn thing_sync(&mut self, t: &Tid) -> Result<ThingSync> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.thing_sync, t, |e| e.thing_sync_now(t))
    }

    /// The sync IDs held here carrying thing `t` (spec/sync-status.md §3: a wait on a thing):
    /// its own and its enclosing groups', read or kept unread (spec/sync-judgement.md §1: a thing
    /// travels under the sync IDs of itself and of the groups enclosing it).
    pub fn carrying(&mut self, t: &Tid) -> Result<BTreeSet<SyncId>> {
        Ok(self.carrying_now(t, false)?.into_iter().collect())
    }

    /// The thing owning sync ID `s` here by its `sync.0`.
    pub fn sync_owner(&mut self, s: &SyncId) -> Result<Option<Tid>> {
        self.sync_owner_of(s)
    }

    /// The sync IDs `thing` owns by its `sync.0` (spec/sync-ids.md §4 Owner), each with its
    /// recorded path; hints while this node holds no sync secret of the thing's own.
    pub fn sync_ids(&mut self, thing: &Tid) -> Result<Arc<Vec<OwnedSyncId>>> {
        self.owned_sync_ids(thing)
    }

    /// What this node opens and acts with as a reader of `s` (`None`: it does not read `s`).
    pub fn read_credentials(&mut self, s: &SyncId) -> Result<Option<Arc<ReadCredentials>>> {
        self.read_credentials_now(s)
    }

    /// The rotation commits superseding read epoch `e` of read sync ID `s` (spec/sync-opens.md §6:
    /// a member opened by `e`'s read secret ends at the highest of their entries in S).
    pub fn rotations_superseding(&mut self, s: &SyncId, e: &Epoch) -> Result<Vec<CommitId>> {
        self.rotations_superseding_now(s, e)
    }

    /// The claim key from this node's own read KEM key and the step key (spec/sync-ids.md §3).
    pub fn claim_key(&mut self, s: &SyncId, step: &StepId) -> Result<Option<SigningSecret>> {
        self.claim_key_now(s, step)
    }

    /// Opens a static entry's grant (spec/sync-opens.md §5): `steps` verify from S's genesis step
    /// (`verify_path`: its delete key hashes to `s`) and pass through the newest step of S recorded
    /// here; a key actor this node holds has static entry `entry` and opens the head's entry box
    /// (spec/sync-ids.md §3 Entry boxes), each secret naming its epoch of S's thing; the box's sync
    /// secret derives the head's sync key. Returns that key and the box, learning nothing: the
    /// caller verifies the answer's signature under the key, then `learn_grant`. `None` when any
    /// check fails or S is no sync ID this node reads.
    pub fn open_grant(&mut self, s: &SyncId, entry: &[u8; 32], steps: &[Step], b: &osis_schema::core_types::SecretBox) -> Result<Option<OpenedGrant>> {
        if osis_label::verify_path(s, steps).is_err() {
            return Ok(None);
        }
        let Some(head) = steps.last() else { return Ok(None) };
        let Some(c) = self.read_credentials(s)? else { return Ok(None) };
        // a step older than the newest known here proves nothing (spec/sync-opens.md §4)
        if let Some(known) = &c.head
            && !steps.iter().any(|st| st.id() == known.id())
        {
            return Ok(None);
        }
        let Some((thing, _)) = self.sync_holder(s)? else { return Ok(None) };
        let ids: Vec<Arc<crate::identity::Identity>> = self.core.key_actors.values().cloned().collect();
        let Some(id) = ids.iter().find(|id| osis_crypto::static_entry(s, &id.keys().signing.verifying_key()) == *entry) else { return Ok(None) };
        let Ok(item) = osis_label::open_entry_box(b, head, &id.keys().kem, &thing) else { return Ok(None) };
        let key = osis_crypto::label_role_key(osis_crypto::LabelRole::Sync, &item.sync.1).verifying_key().to_bytes();
        if key != head.keys.sync.to_bytes() {
            return Ok(None);
        }
        Ok(Some(OpenedGrant { thing, key, secrets: EntryBoxSecrets { read: (item.epoch, item.secret), superseded: item.earlier, sync: item.sync } }))
    }

    /// Learns an opened grant's secrets (`learn_secret`), once its answer's signature verified.
    pub fn learn_grant(&mut self, g: &OpenedGrant) -> Result<()> {
        let x = &g.secrets;
        self.learn_secret(&g.thing, osis_base::Role::Read, x.read.0, x.read.1.clone())?;
        if let Some((e, v)) = &x.superseded {
            self.learn_secret(&g.thing, osis_base::Role::Read, *e, v.clone())?;
        }
        self.learn_secret(&g.thing, osis_base::Role::Sync, x.sync.0, x.sync.1.clone())?;
        Ok(())
    }

    /// The sync records of things this node keeps unread (spec/sync.md §3): each thing's kept
    /// sync IDs and held sync secrets by epoch. Whole: a start lists them, then follows
    /// `sync_record_feed` and `sync_record` per thing.
    pub fn sync_records(&mut self) -> Result<Arc<BTreeMap<Tid, SyncRecord>>> {
        Ok(self.sync_records_now())
    }

    /// `thing`'s sync record; reads only its key (an `Effects` value per thing).
    pub fn sync_record(&mut self, thing: &Tid) -> Result<Option<Arc<SyncRecord>>> {
        Ok(self.sync_record_now(thing))
    }

    /// A cursor over the things whose sync record is made from now on (`memo::Feed`).
    pub fn sync_record_feed(&self) -> osis_base::memo::Feed<Tid> {
        self.core.ix.sync_records.feed()
    }

    /// Records the held sync secrets of `thing` that a step on this node's path of a kept sync ID
    /// of it bears (`borne`: those steps' sync keys) in the account's sync record (spec/sync.md
    /// §3 A recorded secret). Returns whether it wrote.
    pub fn record_borne(&mut self, thing: &Tid, borne: &BTreeSet<[u8; 32]>) -> Result<bool> {
        self.record_borne_now(thing, borne)
    }

    /// The account's sync record of `thing` keeps closed sync ID `s` no more (spec/sync.md §3,
    /// spec/sync-judgement.md §6 Closes), its entry going whole once it keeps none. Returns
    /// whether it wrote.
    pub fn close_kept(&mut self, thing: &Tid, s: &SyncId) -> Result<bool> {
        self.close_kept_now(thing, s)
    }

    // Grants, removals, peers

    /// J of a peer's proven actors for `s` (spec/sync-opens.md §4), from the rosters held here:
    /// a reader of `s`'s thing, a holder of sync alone, departed (every grant path ended), or
    /// unknown. `Unknown` for a sync ID this node does not read.
    pub fn judge_peer(&mut self, s: &SyncId, proven: &[Tid]) -> Result<J> {
        let Some(t) = self.sync_owner_of(s)? else { return Ok(J::Unknown) };
        let reader = self.core.reader_of(&t);
        Ok(match self.core.judge(proven.iter().copied()).of(&t) {
            crate::labeling::Judgment::Holder => J::Reader,
            crate::labeling::Judgment::Departed => J::Departed,
            crate::labeling::Judgment::Unknown if proven.iter().any(|x| self.core.role_now(x, &reader) == Some(osis_base::Role::Sync)) => J::SyncHolder,
            crate::labeling::Judgment::Unknown => J::Unknown,
        })
    }

    /// Whether read epoch `epoch` of `s`'s thing covers every departure this node knows from it
    /// (spec/sync-opens.md §4: a departed peer opens by a read secret only of an epoch that does
    /// not cover its departure). False for a sync ID this node does not read.
    pub fn covers_departures(&mut self, s: &SyncId, epoch: Epoch) -> Result<bool> {
        let Some(t) = self.sync_owner_of(s)? else { return Ok(false) };
        let a = self.core.reader_of(&t);
        let deps = self.departures(&a)?;
        Ok(!self.read(|tx| crate::rotation::uncovered(tx, &a, osis_base::Role::Read, &epoch, &deps))?)
    }

    /// The keys this node proves with on a connection, in proof order (spec/wire.md §11.2 Prove):
    /// its own node key first when `own_node` (the peer is a node of its account), then its
    /// account at its open epoch while it holds that epoch's seed, then the key actors it acts for
    /// (link keys) by ascending tid. Each with its creation record; signing and checking proofs is
    /// osis-proto's (`Prover`).
    pub fn provers(&mut self, own_node: bool) -> Result<Vec<(SigningSecret, CreationRecord)>> {
        let mut out = Vec::new();
        if own_node {
            out.push((self.core.id.keys().signing.clone(), self.core.id.record().clone()));
        }
        out.extend(self.account_prover()?);
        out.extend(self.core.key_actors.values().map(|k| (k.keys().signing.clone(), k.record().clone())));
        Ok(out)
    }

    /// Whether this node publishes `reach.0` (a reader can pull from it, spec/sync-judgement.md
    /// §3 Own store).
    pub fn publishes_reach(&mut self) -> Result<bool> {
        let me = self.core.id.tid();
        Ok(self.get_typed(&me, &osis_schema::core_types::REACH)?.is_some())
    }

    /// Whether `t` is another node of this node's account (spec/sync-opens.md §2: a node proof
    /// counts as the peer's node only then).
    pub fn own_node(&mut self, t: &Tid) -> bool {
        self.core.own_node(t)
    }

    /// Whether dialable key `key` is, by the `reach.0` held here, another node of this node's
    /// account (spec/sync-opens.md §2: a dialer proves its node key only to such a key). O(the
    /// account's nodes): asked once per connection dialed.
    pub fn own_node_key(&mut self, key: &[u8; 32]) -> Result<bool> {
        let Some((_, d)) = self.core.account_devices() else { return Ok(false) };
        for (n, _) in self.core.key_holders(&d) {
            if self.core.own_node(&n) && self.get_typed(&n, &osis_schema::core_types::REACH)?.is_some_and(|r| r.dialable == *key) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The signed rotations of this node's account a verifier may lack, each a header-only copy
    /// (a `CommitBlobPlaintext` value with no sections), for a Prove (spec/sync-opens.md §2).
    pub fn prove_rotations(&mut self) -> Result<Vec<osis_base::Value>> {
        not_built("prove_rotations")
    }

    /// Takes the rotations a peer's Prove carried (header-only copies of its account's rotation
    /// commits), judged by spec/permissions.md §5.4, before its proofs are judged.
    pub fn take_rotations(&mut self, rotations: Vec<osis_base::Value>) -> Result<()> {
        let _ = rotations;
        not_built("take_rotations")
    }

    /// Whether `key` is `record`'s actor's key at an epoch open here (a connection proof's key).
    pub fn key_open(&mut self, record: &CreationRecord, key: &[u8; 32]) -> bool {
        self.account_key_open(record, key)
    }

    /// The nodes this node may dial for S (spec/sync-opens.md §1 Whom to dial), each at the
    /// address it is known by here: of S read, the nodes of each account holding a role on S's
    /// thing by that account's dial list (`dial^.0` on its profile); of S kept unread, its granting
    /// node (the newest grant's dial hint, kept in the sync record, spec/sync-inbox.md §2); either
    /// way this node's own other nodes whose synced group's closure holds S's thing, by their
    /// `reach.0` (the driver never dials its own key). A memo per sync ID; for dialing only, never
    /// proof.
    pub fn dial_peers(&mut self, s: &SyncId) -> Result<Arc<Vec<Address>>> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.dial_peers, s, |e| e.dial_peers_now(s))
    }

    /// The inbox deliveries owed and not seen taken (spec/sync-inbox.md §2), whole: a start lists
    /// them, then follows `delivery_feed` and `delivery_taken` per delivery. A delivery to a node
    /// (pairing) is its commit sent over a connection; to an actor, `inbox_blob`.
    pub fn deliveries(&mut self) -> Result<Arc<BTreeSet<(CommitId, Tid)>>> {
        self.deliveries_now()
    }

    /// A cursor over the deliveries owed from now on (`memo::Feed`).
    pub fn delivery_feed(&self) -> osis_base::memo::Feed<(CommitId, Tid)> {
        self.core.ix.owed_inbox.feed()
    }

    /// Whether this node saw `holder` take delivery `c` (a commit of the holder's on a thing it
    /// names; an open the blob names at this node is sync's to see). Reads only its keys.
    pub fn delivery_taken(&mut self, c: &CommitId, holder: &Tid) -> Result<bool> {
        self.delivery_taken_now(c, holder)
    }

    /// Sync stops delivering `c` to `holder`: it saw the holder take it (`delivery_taken`, or an
    /// open of a sync ID the blob names by the holder), or gave up re-sending. The row goes: a
    /// delivery is owed from its commit's transaction to here, or until its commit is forgotten.
    pub fn delivered(&mut self, c: &CommitId, holder: &Tid) -> Result<()> {
        let (c, h) = (*c, *holder);
        self.run(|tx| deliveries::drop_owed(tx, &c, &h))
    }

    /// The inbox blob of delivery (`c`, `holder`), sealed now (spec/wire.md §9): `None` for a
    /// node holder (sent `c` itself) or one whose inbox key is not known here.
    pub fn inbox_blob(&mut self, c: &CommitId, holder: &Tid, rng: &mut dyn NodeRng) -> Result<Option<Vec<u8>>> {
        self.inbox_blob_now(c, holder, rng)
    }

    /// The sync IDs delivery (`c`, `holder`)'s blob names (spec/wire.md §9 position 1): an open
    /// of one by the holder shows it took the delivery (spec/sync-inbox.md §2 Re-send).
    pub fn delivery_names(&mut self, c: &CommitId, holder: &Tid) -> Result<Arc<Vec<SyncId>>> {
        self.delivery_names_now(c, holder)
    }

    /// The keys this node signs entries of `s` with; `actor`: the actor whose deposit seed
    /// signs a deposit to its inbox when this node records no head of `s`.
    pub fn signers(&mut self, s: &SyncId, actor: Option<&Tid>) -> Result<Signers> {
        self.signers_now(s, actor)
    }

    /// Whether a held blob, as opened or sealed here, is a per-sync-ID copy (spec/sync-judgement.md
    /// §1; `None`: not opened or sealed here).
    pub fn blob_copy(&mut self, b: &BlobId) -> Result<Option<bool>> {
        Ok(self.blob_copy_now(b))
    }

    /// The commit a held blob opened or was sealed as (`blob_parts`' row).
    pub fn blob_commit(&mut self, b: &BlobId) -> Result<Option<CommitId>> {
        Ok(self.core.ix.blob_parts.get(b).map(|x| x.0))
    }

    /// Whether commit `c` is held here (applied or judged).
    pub fn holds_commit(&mut self, c: &CommitId) -> bool {
        self.core.ix.commits.contains_key(c)
    }

    /// Whether commit `c`, or parts of it, pend here (spec/commits.md §4: kept only while
    /// something carries it, `forget_pending` once nothing does).
    pub fn pends(&mut self, c: &CommitId) -> bool {
        self.core.ix.pending.contains_key(c)
    }

    /// The blobs of commit `c` opened or sealed here.
    pub fn commit_blobs(&mut self, c: &CommitId) -> Result<Arc<Vec<BlobId>>> {
        Ok(Arc::new(self.core.ix.commit_blobs.get(c).into_iter().flatten().copied().collect()))
    }

    /// The role commits recorded step `step` of `s` depends on (spec/sync-ids.md §6 Steps): a
    /// store source must hold each before the step is registered there.
    pub fn step_needs(&mut self, s: &SyncId, step: &StepId) -> Result<Arc<Vec<CommitId>>> {
        self.step_needs_now(s, step)
    }

    /// The step due of `s` here (spec/sync-ids.md §6 Steps, spec/permissions.md §3): `Some` with
    /// the role commits it would register (the rotations of the newest sync, write and admin
    /// epochs and of those they supersede) when this node is an admin of S's thing holding an
    /// epoch newer than its recorded head registers, or a refreshed deposit seed. Sync issues it
    /// (`issue_due_step`) once each of those commits is logged under S here, so they are stamped
    /// under the head a store keeping S unread holds.
    pub fn due_step(&mut self, s: &SyncId) -> Result<Option<Arc<Vec<CommitId>>>> {
        let Some(t) = self.sync_owner_of(s)? else { return Ok(None) };
        // the head and deposit seed as `issue_due_step` reads them (one derivation, `step_due`)
        let Some(due) = self.read(|tx| crate::flows::sync_ids::step_due(tx, &t, s, false))? else { return Ok(None) };
        let epochs = due.epochs;
        let mut out = std::collections::BTreeSet::new();
        for r in [Role::Sync, Role::Write, Role::Admin] {
            let re = epochs.role(r);
            let Some(info) = re.newest().and_then(|e| re.get(&e)) else { continue };
            out.extend(info.rotations.keys().copied());
            for x in &info.supersedes {
                if let Some(i) = re.get(x) {
                    out.extend(i.rotations.keys().copied());
                }
            }
        }
        Ok(Some(Arc::new(out.into_iter().collect())))
    }

    /// Issues the step due of `s` (`due_step`, `issue_step`), recorded in its thing's `sync.0`.
    pub fn issue_due_step(&mut self, s: &SyncId) -> Result<Option<Step>> {
        let Some(t) = self.sync_owner_of(s)? else { return Ok(None) };
        Ok(self.issue_step(&t, s, false)?.map(|(st, _)| st))
    }

    /// The commits logged with role commit `c` wherever it is logged (spec/crypto.md §4 Carried).
    pub fn logged_with(&mut self, c: &CommitId) -> Result<Arc<Vec<CommitId>>> {
        Ok(Arc::new(self.logged_with_now(c)?))
    }

    /// The inbox sync ID of actor `a` (spec/sync-inbox.md §1): the one its `keys.0` names.
    pub fn inbox_of(&mut self, a: &Tid) -> Option<SyncId> {
        self.inbox(a)
    }

    /// Takes the inbox blob `blob` held under `s` (its bytes from the ciphertext store), or
    /// judges it again (spec/sync-inbox.md §2 Taking); `vouched`: a writer of the inbox stamped
    /// it in place (a node of the account took it). A boxes payload is held as an offer, never
    /// taken. `None`: its bytes are not held or nothing here opens it.
    pub fn take_inbox(&mut self, s: &SyncId, blob: &BlobId, vouched: bool) -> Result<Option<InboxOpened>> {
        osis_base::costs::count("inbox: take", 1);
        let b = *blob;
        let Some(bytes) = self.run(|tx| tx.blobs.get(&b))? else { return Ok(None) };
        self.take_inbox_bytes(s, blob, &bytes, vouched)
    }

    /// The invitations waiting for the user (spec/sync-set.md §4).
    pub fn invitations(&mut self) -> Result<Arc<Vec<Invitation>>> {
        self.invitations_now()
    }

    /// This node's self-removals sync waits on (spec/sync-status.md §2): the secrets they gave
    /// up drop once sync is done with each.
    pub fn waiting_removals(&mut self) -> Result<Arc<BTreeSet<CommitId>>> {
        Ok(self.waiting_removals_now())
    }

    /// Sync is done waiting for self-removal `c`: held elsewhere, or no peer but this account's
    /// own nodes shares a sync ID it goes under (spec/permissions.md §3 Lost access).
    pub fn removal_done(&mut self, c: &CommitId) -> Result<()> {
        self.removal_done_now(c)
    }

    /// The sync IDs some engine rule waits on a complete pass of, each with the moment the pass
    /// must begin at or after, on the engine's clock (`pass_clock`); a memo value, so status
    /// follows it with `Effects` (spec/permissions.md §2-§3, spec/sync-status.md §3).
    pub fn passes_wanted(&mut self) -> Result<Arc<BTreeMap<SyncId, WallMs>>> {
        self.passes_wanted_now()
    }

    /// The engine's clock, the one a complete pass's `began` is read on: a pass begun at `began`
    /// counts for a want at `since` only when `began >= since`.
    pub fn pass_clock(&self) -> WallMs {
        self.now()
    }

    /// What sync's role duties follow per thing (`osis_sync::life`: `joined_link_ended`,
    /// `untie_due`): a cursor over the (holder, thing) pairs named from now on, and every thing
    /// a holder is named on now.
    pub fn role_things(&self) -> (osis_base::memo::Feed<(Tid, Tid)>, BTreeSet<Tid>) {
        let held = &self.core.ix.held;
        (held.pairs_feed(), held.holders().flat_map(|h| held.named_on(h)).copied().collect())
    }

    /// Whether `t` is named a holder on now (`role_things`): a thing that is no longer has no
    /// holder duty to follow (stamped: moves when its last holder goes).
    pub fn named_a_holder(&self, t: &Tid) -> bool {
        self.core.ix.held.holders_of(t).next().is_some()
    }

    /// A complete pass of `s` begun at `began` (`pass_clock`) ended (spec/sync-status.md §1):
    /// kept durably, the last per sync ID; the re-seal and history-add trigger (`pass_end`) and
    /// history completeness read it.
    pub fn note_complete_pass(&mut self, s: &SyncId, began: WallMs) -> Result<()> {
        self.note_complete_pass_now(s, began)
    }

    /// Sync ID `s` is read here no more (it left the sync set, or is kept unread): its noted
    /// passes go, so reading it again wants a fresh pass, and so do the record blobs sealed under
    /// it. An open does the same for every sync ID not read.
    pub fn forget_read(&mut self, s: &SyncId) -> Result<()> {
        self.forget_read_now(s)
    }

    /// History complete for `thing` (spec/sync-status.md §3): a complete pass of every sync ID
    /// carrying it noted here.
    pub fn history_complete(&mut self, thing: &Tid) -> Result<bool> {
        self.history_complete_now(thing)
    }

    // Timers and config

    /// When the memo clock next moves a value read with an `until` (`memo::Clock::next`): the
    /// driver folds it into the node's wake.
    pub fn clock_next(&self) -> Option<WallMs> {
        self.core.time.next().map(WallMs)
    }

    /// Moves the memo clock to `now`.
    pub fn set_now(&mut self, now: WallMs) {
        self.core.time.set(now.0);
    }

    /// `caps^.0` of this node (spec/sync-ids.md §5 Caps).
    pub fn caps(&mut self) -> Result<Arc<Caps>> {
        self.caps_now()
    }
}
