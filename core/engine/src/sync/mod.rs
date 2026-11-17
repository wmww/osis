//! The engine's facade for sync (`osis_sync`; notes/sync-facade.md): what sync reads of
//! plaintext and judgement, per sync ID, and the few commands it gives. Sync reaches the engine
//! only through these methods (and the opening, writing and clock calls any node makes); the
//! engine calls nothing of sync's. Every value call is a memo or reads stamped rows, so a sync
//! effect that reads one depends on exactly what the engine read; a value derived from one
//! whose reads move far more often than it does is kept per key instead, brought up to date by
//! `follow`.

pub(crate) mod bodies;
pub(crate) mod certified;
pub(crate) mod dial;
pub(crate) mod facts;
pub(crate) mod falls;
pub(crate) mod held;
pub(crate) mod listed;
pub(crate) mod own;
pub(crate) mod rows;
pub use rows::Held;
pub(crate) mod pieces;
pub use pieces::PieceLink;
pub(crate) mod certblobs;
pub use certblobs::{CertBlobs, CertKind};
pub(crate) use certblobs::with_chains;
mod relay;
pub use relay::{Relay, RelayOpened};
pub(crate) mod set;
pub(crate) mod setting;
mod signing;
pub(crate) mod stranded;
pub(crate) mod tickets;
pub(crate) mod units;
pub use stranded::Stranding;
pub use crate::flows::inbox::{FireId, SealedFireOut};
#[cfg(test)]
mod tests_facts;
#[cfg(test)]
mod tests_tickets;

pub use osis_blob::DialHint;

use crate::apply::reach::Wants;
use crate::engine::DropFor;
use crate::error::{Error, Result};
use crate::sync_ids::{Certs, HeadKeys};
use crate::{Engine, Ingested};
use osis_base::{Ak, BlobId, CommitId, CreationRecord, Role, SyncId, Tid, WallMs};
use osis_crypto::{Epoch, Secret32, SigningSecret, WRAP_LEN};
use osis_blob::{Address, Step, StepId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// An entry's wrap, or a random filler (spec/sync-ids.md §5).
pub type Wrap = [u8; WRAP_LEN];

/// The parts (aspect indexes) a blob holds.
pub type PartSet = BTreeSet<usize>;

/// The sections of a blob this node did not open, each by its digest (`Section::digest`): all a
/// node checked of them (spec/sync-compaction.md §1 Duplicates).
pub type SealedSet = BTreeSet<[u8; 32]>;

/// A blob of a commit as this node opened or sealed it (`bp/` row, `Engine::blob_of`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobOf {
    pub commit: CommitId,
    /// The parts it opened (or sealed) of the commit.
    pub parts: PartSet,
    /// The sections it holds that this node did not open, or opened but could not check a part
    /// of against the header (its thing's record not held): by their bytes alone.
    pub sealed: SealedSet,
    /// A per-sync-ID copy (spec/sync-judgement.md §1).
    pub copy: bool,
    /// A section is in `sealed` only for want of a record: the blob opens again once its
    /// commit stops pending (`apply::unpend`, through `take_redeliver`).
    pub unchecked: bool,
    /// Its prefix salt and the aspects its sections list: with the header, the commitments its
    /// prefix bears, kept past its bytes for a Delete by levels (spec/sync-judgement.md §3
    /// Dropped bodies).
    pub salt: [u8; 16],
    pub ais: PartSet,
}

impl BlobOf {
    /// Of the body kind `copy` (a per-sync-ID copy or the shared blob): a blob of no section, a
    /// header alone, is of either, as its bytes tell neither (spec/wire.md §4: a header-only copy
    /// has no section), so opening it again under another sync ID changes nothing it holds.
    pub(crate) fn of_kind(&self, copy: bool) -> bool {
        self.copy == copy || self.ais.is_empty()
    }
}

/// A commitment group's delete keys (level, key), with the thing whose chain holds its level-1
/// and level-3 secrets.
pub(crate) type DeleteGroup = (Tid, Vec<(u8, [u8; 32])>);

/// What a Delete by levels of a blob signs for (spec/crypto.md §7, spec/sync-ids.md §6): the
/// commitments its prefix bears as this node computes them (from the keys its header or link
/// names; a blob framed otherwise refuses the signature), its blind, and the delete secrets held
/// here for those keys, with their levels.
pub struct DeleteBasis {
    pub prefix: osis_blob::Prefix,
    pub blind: [u8; 16],
    pub held: Vec<(u8, osis_crypto::DeleteSecret)>,
}

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
    pub steps: Vec<(Step, Option<osis_blob::ClaimSet>)>,
}

/// What `open_entry` did with an entry's blob.
#[derive(Debug)]
pub enum Opened {
    /// A commit blob: opened with a held read secret and taken.
    Commit(CommitId, Ingested),
    /// A chunk, tree node or page a held commit links: stored.
    Linked,
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
    /// A header-only certificate copy of a held minting of these things, whose records go under
    /// the sync ID (its closure lacks them): sync judges it by its standing among each thing's
    /// mintings (`Engine::mintings_of`, spec/commits.md §5 A thing's mintings travel with its
    /// record). Empty for any other body.
    pub mints: BTreeSet<Tid>,
}

/// The facts the judgement of one body at one sync ID reads (spec/sync-judgement.md §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyFacts {
    /// In S's required set.
    pub required: bool,
    /// A closure body (not a certificate or sealed fire).
    pub closure: bool,
    /// Dropped here, and why.
    pub dropped: Option<DropFor>,
    /// Judged invalid here: no part of it valid, each invalid (dropped as invalid, or held: an own
    /// commit) or dropped as covered, one at least invalid; never a role commit's (the timeline
    /// reads edge writes of any validity), nor one carrying a request in force
    /// (`purge::drops_nothing`). Its entries leave the own store with no tombstone and
    /// are never deleted at a peer (spec/sync-judgement.md §3 Own store, Deletes).
    pub invalid: bool,
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

/// A held blob as a strip leaves it (`Engine::strip_of`): what a delete of it at a peer waits for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Strip {
    /// Its parts held here: each carried there by another blob of the commit.
    pub live: PartSet,
}

/// What forgetting and covers make of a held commit (`Engine::held_fate`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldFate {
    /// The engine would forget it once no entry of it is known (`Engine::forgettable`).
    pub forgettable: bool,
    /// Its held parts that drop as covered now (`Engine::covered_drops`); none asked where
    /// `forgettable`.
    pub drops: Arc<Vec<(Tid, Ak)>>,
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
    pub ids: BTreeMap<SyncId, Held>,
    /// Things in N's closure with no sync ID this node may hold.
    pub unsyncable: BTreeSet<Tid>,
}

/// The sync set's rows' cursor over the things that may have entered `Engine::sync_things`
/// (`Engine::things_entered`); unstarted until its first read.
#[derive(Default)]
pub(crate) struct ThingsFeed(Option<Entered>);

impl Clone for ThingsFeed {
    // a copy reads everything again at its first read
    fn clone(&self) -> ThingsFeed {
        ThingsFeed(None)
    }
}

impl std::fmt::Debug for ThingsFeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ThingsFeed")
    }
}

/// `ThingsFeed`'s cursor: over the things the sync set's walk reaches.
pub(crate) struct Entered {
    held: osis_base::memo::Feed<Tid>,
}

/// How this node syncs one thing of N's closure (spec/sync-set.md §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThingSync {
    /// Read: its home sync ID.
    Read(Vec<SyncId>),
    /// Kept unread: by a ticket for the sync role (spec/sync.md).
    Unread(Vec<SyncId>),
    /// Secrets of its own, neither a read nor a sync secret held (`Unsyncable`).
    Unsyncable,
    /// No secrets of its own: it travels under the sync IDs of the sync units holding it.
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
    /// The sync proof (spec/sync-ids.md §2) of each recorded step whose sync key this node holds,
    /// deepest first: the head's is what a reader shows, the rest what the walk tests
    /// (spec/sync-ids.md §6 Walk).
    pub proofs: Vec<(StepId, [u8; 32])>,
    /// The sync key of each sync secret of S's thing held here, newest first, with its epoch:
    /// tested after the recorded steps' credentials (spec/sync-ids.md §6 Test).
    pub sync_keys: Vec<(Epoch, SigningSecret)>,
}

type PublicCredentials<'a> = (Option<StepId>, &'a BTreeMap<StepId, HeadKeys>, &'a [(Epoch, Secret32)], &'a BTreeSet<[u8; 32]>, Vec<osis_crypto::VerifyingKey>, &'a [(StepId, [u8; 32])], Vec<(Epoch, osis_crypto::VerifyingKey)>);

impl ReadCredentials {
    /// What tells two apart (`Engine::read_credentials` is a memo): signing keys by their public
    /// halves, read secrets as they are (`Secret32` compares, and prints redacted).
    fn public(&self) -> PublicCredentials<'_> {
        let acting = self.acting.iter().map(SigningSecret::verifying_key).collect();
        let sync_keys = self.sync_keys.iter().map(|(e, k)| (*e, k.verifying_key())).collect();
        (self.head.as_ref().map(Step::id), &self.keys, &self.read_secrets, &self.statics, acting, &self.proofs, sync_keys)
    }
}

impl PartialEq for ReadCredentials {
    fn eq(&self, o: &ReadCredentials) -> bool {
        self.public() == o.public()
    }
}

impl std::fmt::Debug for ReadCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.public().fmt(f)
    }
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

/// Who may hold a sync ID besides this node, by the rosters (`Engine::roster_holders`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RosterHolders {
    /// Anyone may: S kept unread (its granters are not named here).
    pub anyone: bool,
    /// This account's other nodes syncing S's thing.
    pub nodes: BTreeSet<Tid>,
    /// The accounts other than this one holding a role on S's thing.
    pub accounts: BTreeSet<Tid>,
}

impl RosterHolders {
    /// Some node other than this one may hold S.
    pub fn any(&self) -> bool {
        self.anyone || !self.nodes.is_empty() || !self.accounts.is_empty()
    }

    /// A peer proving `proven` may hold S: one of them is a holder named here.
    pub fn may_hold(&self, proven: &[Tid]) -> bool {
        self.anyone || proven.iter().any(|x| self.nodes.contains(x) || self.accounts.contains(x))
    }
}

/// J of a peer for S (spec/sync-opens.md §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum J {
    Reader,
    SyncHolder,
    Departed,
    Unknown,
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

impl Engine {
    // Ingest

    /// What to fetch: pages and header lists before apply.
    pub fn wants(&mut self) -> Result<Arc<Wants>> {
        Ok(Arc::new(self.blob_wants()?))
    }

    // Held parts and bodies

    /// Brings the facade values kept per entry (`Core::published`, per thing with a sync ID;
    /// `Core::wrap_blocks`, per actor and walk; `Core::held_writes_rows`, per aspect; each read
    /// thing's certificates per piece and commit, `certified`; its thing lists per rotation,
    /// `listed`; `Core::read_facts`, per sync ID and commit; `Core::held_fates`, per commit) up to date with what moved since
    /// the last call: whether any entry moved. Each refreshes itself when asked, but an `Effects`
    /// key that read an entry goes due only once the entry is written, so a module calls this
    /// before its `due()` (the driver, before each module's settle and until it moves nothing).
    /// Not done at each transaction's end: the read things come from the sync set, a whole walk,
    /// so a burst of n transactions between two sync steps would cost n walks, not one
    /// (notes/engine.md).
    pub fn follow(&mut self) -> Result<bool> {
        let moved = self.take_ticket_fires()? | self.follow_published();
        self.follow_rows()?;
        let moved = osis_base::memo::Cutoff::refresh_in(self, |e| &e.core.pass_wanted, |e, s| e.pass_wanted_fresh(s))? | moved;
        self.follow_own()?;
        let moved = osis_base::memo::Cutoff::refresh_in(self, |e| &e.core.wrap_blocks, |e, (a, walk)| e.wrap_blocked_read(a, *walk))? | moved;
        let moved = self.follow_held_writes()? | moved;
        // `listed` follows `certified` first: one follow of each
        let moved = self.follow_lists()? | moved;
        // a body's facts read every value above
        let moved = osis_base::memo::Cutoff::refresh_in(self, |e| &e.core.read_facts, |e, (s, c)| e.read_facts_now(s, c))? | moved;
        Ok(osis_base::memo::Cutoff::refresh_in(self, |e| &e.core.held_fates, |e, c| e.held_fate_now(c))? | moved)
    }

    /// What `read` judges `c`'s body under `s` on beside `BodyFacts` (`ReadFacts`). Kept per
    /// (sync ID, commit) from its first ask (`Core::read_facts`, a `memo::Cutoff`, refreshed by
    /// `follow`): a reader moves only when the facts do; `unfollow_facts` lets a key go.
    pub fn read_facts(&mut self, s: &SyncId, c: &CommitId) -> Result<ReadFacts> {
        osis_base::memo::Cutoff::get_in(self, |e| &e.core.read_facts, &(*s, *c), |e, (s, c)| e.read_facts_now(s, c))
    }

    /// Stops keeping `c`'s facts under `s` (`read_facts`): its judgement went idle.
    pub fn unfollow_facts(&mut self, s: &SyncId, c: &CommitId) {
        self.core.read_facts.unfollow(&(*s, *c));
    }

    /// What forgetting and covers make of commit `c` (`HeldFate`): `None` once it is not held.
    /// Kept per commit from its first ask (`Core::held_fates`, a `memo::Cutoff`, refreshed by
    /// `follow`), so a reader moves only when the fate does; `unfollow_fate` lets a key go.
    pub fn held_fate(&mut self, c: &CommitId) -> Result<Option<HeldFate>> {
        osis_base::memo::Cutoff::get_in(self, |e| &e.core.held_fates, c, |e, c| e.held_fate_now(c))
    }

    /// Stops keeping `c`'s fate (`held_fate`): it left read.
    pub fn unfollow_fate(&mut self, c: &CommitId) {
        self.core.held_fates.unfollow(c);
    }

    /// `held_fate` derived anew.
    fn held_fate_now(&mut self, c: &CommitId) -> Result<Option<HeldFate>> {
        if !self.core.ix.commits.contains_key(c) {
            return Ok(None);
        }
        let forgettable = self.forgettable(c)?;
        let drops = if forgettable { Vec::new() } else { self.covered_drops(c)? };
        Ok(Some(HeldFate { forgettable, drops: Arc::new(drops) }))
    }

    /// A cursor over the commits held from now on (`memo::Feed`; a start lists `commit_ids`).
    pub fn commit_feed(&self) -> osis_base::memo::Feed<CommitId> {
        self.core.ix.commits.feed()
    }

    /// A cursor over the commits this node stops holding from now on (`memo::Removals`):
    /// forgotten whole, or unindexed to be held again.
    pub fn unheld_feed(&self) -> osis_base::memo::Removals<CommitId> {
        self.core.ix.commits.removals()
    }

    /// A cursor over the blobs this node comes to open or seal from now on (`blob_commit` names
    /// their commit; `memo::Feed`, a blob noted again included).
    pub fn blob_feed(&self) -> osis_base::memo::Feed<BlobId> {
        self.core.ix.blob_parts.feed()
    }

    /// A cursor over the held commits that pended no more from now on (their waiting parts
    /// joined or went, `memo::Feed`): each may be judged again (`pends`).
    pub fn unpended_feed(&self) -> osis_base::memo::Feed<CommitId> {
        self.core.waits.unpended.feed()
    }

    /// Certificate blob `b` of kind `r` sealed here under `s` is in the own store no more: its
    /// row goes.
    pub fn forget_cert_blob(&mut self, s: &SyncId, r: CertKind, b: &BlobId) -> Result<()> {
        let (s, b) = (*s, *b);
        self.run(|tx| certblobs::forget_blob(tx, &s, r, &b))
    }

    /// Whether `b` is a freed link's blob.
    pub fn freed(&mut self, b: &BlobId) -> Result<bool> {
        self.is_freed(b)
    }

    /// Takes a piece's bytes (a blob a held body links, `pieces`' missing) from a store entry:
    /// held here from now on (`put_blobs`).
    pub fn take_piece(&mut self, b: &BlobId, bytes: Vec<u8>) -> Result<()> {
        if osis_blob::blob_id(&bytes) != *b {
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

    /// What a Delete by levels of commit blob `b` signs for (`DeleteBasis`): the groups of the
    /// aspects its sections list, under its salt and its header's blind. `None`: `b` names no
    /// commit held here.
    pub fn blob_delete_basis(&mut self, b: &BlobId) -> Option<DeleteBasis> {
        let row = self.core.ix.blob_parts.get(b)?.clone();
        let h = self.header(&row.commit)?;
        let mut groups: Vec<DeleteGroup> = Vec::new();
        for a in row.ais.iter().filter_map(|ai| h.aspects.get(*ai)) {
            let keys: Vec<(u8, [u8; 32])> = a.keys.iter().filter_map(|i| h.keys.get(*i)).map(|k| (k.level, k.key)).collect();
            if !groups.iter().any(|(_, g)| *g == keys) {
                groups.push((a.tid, keys));
            }
        }
        self.delete_basis(row.salt, h.blind, &h.actor, &groups)
    }

    /// A `DeleteBasis` of a blob with prefix `salt` and blind `blind` whose groups are `groups`
    /// (each with the thing whose chain holds its level-1 and level-3 secrets), `author` the actor
    /// whose chain holds level 2 (spec/crypto.md §7). `None`: a key that is no Ed25519 point.
    pub(crate) fn delete_basis(&self, salt: [u8; 16], blind: [u8; 16], author: &Tid, groups: &[DeleteGroup]) -> Option<DeleteBasis> {
        let mut keyed = Vec::with_capacity(groups.len());
        for (_, keys) in groups {
            keyed.push(keys.iter().map(|(l, k)| Some((*l, osis_crypto::VerifyingKey::from_bytes(k).ok()?))).collect::<Option<Vec<_>>>()?);
        }
        let prefix = osis_blob::Prefix::for_groups(salt, &blind, None, &keyed).ok()?;
        let author = self.core.delete_chain(author);
        let mut held: Vec<(u8, osis_crypto::DeleteSecret)> = Vec::new();
        for (t, keys) in groups {
            let thing = self.core.delete_chain(t);
            for (l, k) in keys {
                if !held.iter().any(|(hl, d)| hl == l && d.verifying_key().to_bytes() == *k) {
                    held.extend(crate::engine::Core::delete_secret(*l, k, &thing, &author).map(|d| (*l, d)));
                }
            }
        }
        Some(DeleteBasis { prefix, blind, held })
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

    /// How this node syncs thing `t` (read, kept unread, unsyncable, plain); reads only `t`'s keys.
    pub fn thing_sync(&mut self, t: &Tid) -> Result<ThingSync> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.thing_sync, t, |e| e.thing_sync_now(t))
    }

    /// The sync IDs held here carrying thing `t` (spec/sync-status.md §3: a wait on a thing):
    /// its own and those of the sync units holding it, read or kept unread (spec/sync-set.md §2:
    /// what a sync ID carries).
    pub fn carrying(&mut self, t: &Tid) -> Result<BTreeSet<SyncId>> {
        Ok(self.carrying_now(t, false)?.into_iter().collect())
    }

    /// Whether this node has joined an account (made or paired). Before (a node pairing), its
    /// node closure reaches no account root, so its sync set is empty for want of one, not
    /// because anything left it: nothing it holds counts as left. A node removed from its
    /// account since has no account, and everything it held has left.
    pub fn sync_rooted(&mut self) -> bool {
        self.core.account.get().is_some()
    }

    /// Sync ID `s`'s things here (`sync_things_of`): its owner by a held `sync.0`, or every
    /// thing whose held tickets name it.
    pub fn sync_owners(&mut self, s: &SyncId) -> Result<Vec<Tid>> {
        self.sync_things_of(s)
    }

    /// The sync IDs `thing` owns by its `sync.0` (spec/sync-ids.md §4 Owner), each with its
    /// recorded path; hints while this node holds no sync secret of the thing's own.
    pub fn sync_ids(&mut self, thing: &Tid) -> Result<Arc<Vec<OwnedSyncId>>> {
        self.owned_sync_ids(thing)
    }

    /// Every read secret an entry of `s` is tried under (`open_entry`): held, current or not, its
    /// thing's and those derived from its first admin's. A parked entry waits on these alone.
    pub fn opening_secrets(&mut self, s: &SyncId) -> Result<Vec<osis_crypto::Secret32>> {
        let mut out = Vec::new();
        for t in self.opening_things(s)? {
            out.extend(self.read_secrets(&t));
        }
        Ok(out)
    }

    /// What this node opens and acts with as a reader of `s` (`None`: it does not read `s`): also
    /// for a sync ID it left while a read secret of its thing is held, which sync keeps syncing
    /// until a complete pass after it left (spec/sync-set.md §3).
    pub fn read_credentials(&mut self, s: &SyncId) -> Result<Option<Arc<ReadCredentials>>> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.read_credentials, s, |e| e.read_credentials_now(s))
    }

    /// Opens a static entry's grant (spec/sync-opens.md §5): `steps` verify from S's genesis step
    /// (`verify_path`: its delete key hashes to `s`) and pass through the newest step of S recorded
    /// here; a key actor this node holds has static entry `entry` and opens the head's entry box
    /// (spec/sync-ids.md §3 Entry boxes), each secret naming its epoch of S's thing; the box's sync
    /// secret derives the head's sync key. Returns that key and the box, learning nothing: the
    /// caller verifies the answer's signature under the key, then `learn_grant`. `None` when any
    /// check fails or S is no sync ID this node reads.
    pub fn open_grant(&mut self, s: &SyncId, entry: &[u8; 32], steps: &[Step], b: &osis_schema::core_types::SecretBox) -> Result<Option<OpenedGrant>> {
        if osis_blob::verify_path(s, steps).is_err() {
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
        let Some((things, _)) = self.sync_holder(s)? else { return Ok(None) };
        let ids: Vec<Arc<crate::identity::Identity>> = self.core.key_actors.values().cloned().collect();
        let Some(id) = ids.iter().find(|id| osis_crypto::static_entry(s, &id.keys().signing.verifying_key()) == *entry) else { return Ok(None) };
        // the box names the thing it is of: whichever of S's things opens it
        let Some((thing, item)) = things.iter().find_map(|t| osis_blob::open_entry_box(b, head, &id.keys().kem, t).ok().map(|i| (*t, i))) else { return Ok(None) };
        let key = osis_crypto::role_key(osis_crypto::RoleKey::Sync, &item.sync.1).verifying_key().to_bytes();
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

    // Grants, removals, peers

    /// J of a peer's proven actors for `s` (spec/sync-opens.md §4), from the rosters held here:
    /// a reader of one of `s`'s things, else a holder of sync alone on one, else departed from one
    /// (every grant path ended), else unknown. `Unknown` for a sync ID this node does not read.
    pub fn judge_peer(&mut self, s: &SyncId, proven: &[Tid]) -> Result<J> {
        let rank = |j: &J| match j {
            J::Reader => 3,
            J::SyncHolder => 2,
            J::Departed => 1,
            J::Unknown => 0,
        };
        let mut out = J::Unknown;
        for t in self.sync_things_of(s)? {
            let reader = self.core.reader_of(&t);
            let j = match self.core.judge(proven.iter().copied()).of(&t) {
                crate::sync_ids::Judgment::Holder => J::Reader,
                crate::sync_ids::Judgment::Departed => J::Departed,
                crate::sync_ids::Judgment::Unknown if proven.iter().any(|x| self.core.role_now(x, &reader) == Some(osis_base::Role::Sync)) => J::SyncHolder,
                crate::sync_ids::Judgment::Unknown => J::Unknown,
            };
            if rank(&j) > rank(&out) {
                out = j;
            }
        }
        Ok(out)
    }

    /// Whether read epoch `epoch` of one of `s`'s things covers every departure this node knows
    /// from it (spec/sync-opens.md §4: a departed peer opens by a read secret only of an epoch
    /// that does not cover its departure). False for a sync ID this node does not read.
    pub fn covers_departures(&mut self, s: &SyncId, epoch: Epoch) -> Result<bool> {
        for t in self.sync_things_of(s)? {
            let a = self.core.reader_of(&t);
            let deps = self.departures(&a)?;
            if !self.read(|tx| crate::rotation::uncovered(tx, &a, osis_base::Role::Read, &epoch, &deps))? {
                return Ok(true);
            }
        }
        Ok(false)
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
        let Some((_, d)) = self.core.account_and_root() else { return Ok(false) };
        for (n, _) in self.core.key_holders(&d) {
            if self.core.own_node(&n) && self.get_typed(&n, &osis_schema::core_types::REACH)?.is_some_and(|r| r.dialable == *key) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The signed rotations of this node's account a verifier may lack, each a header-only copy
    /// (a `CommitBlobPlaintext` value with no sections), for a Prove or Proved (spec/sync-opens.md §2):
    /// what holding the epoch it proves at needs (`AccountView::proving_chain`), each after what
    /// it needs, so a verifier takes them in one pass (`take_rotations`); a session sends the
    /// newest a message fits. Never a line beside it: a removed node's forks, held here, would
    /// crowd the message's room.
    pub fn prove_rotations(&mut self) -> Result<Vec<osis_base::Value>> {
        let Some(p) = self.core.account.get() else { return Ok(Vec::new()) };
        let rots = self.core.account_view(&p).map(|v| v.proving_chain()).unwrap_or_default();
        let mut out = Vec::new();
        // a merge goes as one of its certificates
        let v = self.core.account_view(&p);
        for r in rots.into_iter().filter_map(|e| v.as_ref().and_then(|v| v.minting(&e).first().copied())) {
            let Some(c) = self.read(|tx| tx.get_commit(&r))? else { continue };
            let pt = osis_commit::rewrite(&c, |_| true).encode();
            out.push(osis_base::cbor::decode(&pt, &osis_base::cbor::Limits::DEFAULT).map_err(|_| Error::Corrupt("rotation header"))?);
        }
        Ok(out)
    }

    /// Takes the rotations a peer's Prove or Proved carried (header-only copies of account rotation
    /// commits), judged by spec/permissions.md §5.4 like any received, in the order given,
    /// before its proofs are judged. Nothing carries them (spec/commits.md §4 Pending storage),
    /// so of an account a node keeps only what it holds the account's chain by: the rotations
    /// that count once all are taken, and, while no rotation held before is in a rejection with
    /// a counting one, the tips the Warning names (`AccountView::contested`, the versions its
    /// user may choose); each with what it needs (`AccountView::needed`). Every other one (a
    /// fork beside the followed line, one that would pend, a second dispute while one is told)
    /// keeps nothing, as if never received: decided in a trial of all of them together
    /// (`ingest_trial`) before anything is written. Anything else (not a rotation, a part
    /// carried, bad input) is skipped.
    pub fn take_rotations(&mut self, rotations: Vec<osis_base::Value>) -> Result<()> {
        let mut fresh: Vec<(Vec<u8>, osis_commit::CommitBlob)> = Vec::new();
        let mut of: BTreeMap<Tid, BTreeSet<CommitId>> = BTreeMap::new();
        for v in rotations {
            let b = osis_base::cbor::encode(&v);
            let Ok(c) = osis_commit::CommitBlob::decode(&b) else { continue };
            let id = c.id();
            if c.header.rotation.is_none() || !c.parts.is_empty() || self.core.ix.commits.contains_key(&id) || !of.entry(c.header.author).or_default().insert(id) {
                continue;
            }
            fresh.push((b, c));
        }
        if fresh.is_empty() {
            return Ok(());
        }
        let blobs: Vec<osis_commit::CommitBlob> = fresh.iter().map(|(_, c)| c.clone()).collect();
        let kept = self.ingest_trial(&blobs, |core| {
            let mut out = BTreeSet::new();
            for (p, ids) in &of {
                let Some(v) = core.account_view(p) else { continue };
                // by epoch: a merge certificate is its merge's
                let epochs: BTreeSet<CommitId> = ids.iter().filter_map(|r| v.epoch_of(r)).collect();
                let mut roots: Vec<CommitId> = epochs.iter().filter(|r| v.rotation_counts(r)).copied().collect();
                // the Warning's first rise: once it is told by what was held, a Prove adds no line
                if !v.rotation_ids().iter().any(|r| !epochs.contains(r) && v.contests(r)) {
                    roots.extend(v.contested().iter().filter(|r| epochs.contains(r)));
                }
                out.extend(v.needed(roots).into_iter().flat_map(|e| v.minting(&e)).filter(|r| ids.contains(r)));
            }
            out
        })?;
        for (b, c) in &fresh {
            if !kept.contains(&c.id()) {
                continue;
            }
            match self.ingest_uncarried(b) {
                Err(e) if osis_base::Classified::class(&e) == osis_base::ErrorClass::Local => return Err(e),
                _ => {}
            }
        }
        Ok(())
    }

    /// Whether `key` is `record`'s actor's key at an epoch open here (a connection proof's key).
    pub fn key_open(&mut self, record: &CreationRecord, key: &[u8; 32]) -> bool {
        self.account_key_open(record, key)
    }

    /// Whether `key`, with which account `account` proved before, is at an epoch open here now
    /// (a record's account judged again, spec/sync-opens.md §3): `key_open` by the account's
    /// creation record; an account this node holds nothing of had no epoch closed here.
    pub fn account_key_counts(&mut self, account: &Tid, key: &[u8; 32]) -> bool {
        match self.core.created(account).cloned() {
            Some(r) => self.account_key_open(&r, key),
            None => true,
        }
    }

    /// [for Fathom's review] Whether `key`, with which account `account` proved before, is the
    /// signing key of an epoch that a counting rotation of the chain this node follows for the
    /// account supersedes while carrying a removal (spec/permissions.md §5.5 Revoked: such a
    /// record is waited for no more). An account this node holds nothing of: not. O(log) on the
    /// account's chain, a memo.
    pub fn account_key_revoked(&mut self, account: &Tid, key: &[u8; 32]) -> bool {
        self.core.account_view(account).is_some_and(|v| v.revoked(key))
    }

    /// The nodes this node may dial for S (spec/sync-opens.md §1 Whom to dial), each at the
    /// address it is known by here: of S read, the nodes of each account holding a role on S's
    /// thing by that account's dial list (`dial^.0` on its profile); of S kept unread, its ticket's
    /// issuer (the ticket's profile, spec/data-model.md §8); either way this node's own other
    /// nodes whose node closure holds S's thing, by their
    /// `reach.0` (the driver never dials its own key). A memo per sync ID; for dialing only, never
    /// proof.
    pub fn dial_peers(&mut self, s: &SyncId) -> Result<Arc<Vec<Address>>> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.dial_peers, s, |e| e.dial_peers_now(s))
    }

    /// The nodes other than this one that may hold S, by the rosters and records held here
    /// (spec/sync-status.md §3 held by no other node; spec/sync-set.md §3 the peers a leave waits
    /// for): of S read, the accounts other than this one holding a role on S's thing and the
    /// other nodes of this account whose node closure holds it; S kept unread, anyone
    /// (its granters, whom the rosters do not name). The nodes `dial_peers` lists, by who they
    /// are, whether or not an address is known. A memo per sync ID.
    pub fn roster_holders(&mut self, s: &SyncId) -> Result<Arc<RosterHolders>> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.roster_holders, s, |e| e.roster_holders_now(s))
    }

    /// The commit a held blob opened or was sealed as (`blob_parts`' row).
    pub fn blob_commit(&mut self, b: &BlobId) -> Option<CommitId> {
        self.core.ix.blob_parts.get(b).map(|x| x.commit)
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

    /// The step due of `s` here (spec/sync-ids.md §6 Steps, spec/permissions.md §3): `Some` with
    /// the role commits it would register (the rotations of the newest sync, write and admin
    /// epochs and of those they supersede) when this node is an admin of S's thing holding an
    /// epoch newer than its recorded head registers, or a refreshed deposit seed. Sync issues it
    /// (`issue_due_step`) once each of those commits is logged under S here, so they are stamped
    /// under the head a store keeping S unread holds.
    pub fn due_step(&mut self, s: &SyncId) -> Result<Option<Arc<Vec<CommitId>>>> {
        let Some((t, _)) = self.recorded_owner(s)? else { return Ok(None) };
        // the head and deposit seed as `issue_due_step` reads them (one derivation, `step_due`)
        let Some(due) = self.read(|tx| crate::flows::sync_ids::step_due(tx, &t, s, false))? else { return Ok(None) };
        let epochs = due.epochs;
        let mut out = std::collections::BTreeSet::new();
        for r in [Role::Sync, Role::Write, Role::Admin] {
            let re = epochs.role(r);
            let Some(info) = re.newest().and_then(|e| re.get(&e)) else { continue };
            out.extend(info.rotations.keys().copied());
            for x in info.superseded_epochs() {
                if let Some(i) = re.get(&x) {
                    out.extend(i.rotations.keys().copied());
                }
            }
        }
        Ok(Some(Arc::new(out.into_iter().collect())))
    }

    /// Issues the step due of `s` (`due_step`, `issue_step`), recorded in its thing's `sync.0`.
    pub fn issue_due_step(&mut self, s: &SyncId) -> Result<Option<Step>> {
        let Some((t, _)) = self.recorded_owner(s)? else { return Ok(None) };
        Ok(self.issue_step(&t, s, false)?.map(|(st, _)| st))
    }

    /// The commits logged with role commit `c` wherever it is logged (spec/crypto.md §4 Carried).
    pub fn logged_with(&mut self, c: &CommitId) -> Result<Arc<Vec<CommitId>>> {
        Ok(Arc::new(self.logged_with_now(c)?))
    }

    /// The commits logged with role commit `c` under the sync IDs it goes under (spec/crypto.md
    /// §4 Carried, names): the held rotation commits of the keysets its boxes to holder actors
    /// name, and of those its keysets record holder actors were left out at; and, for a rotation,
    /// the held commits its names point to (each epoch it introduces, as its history entries
    /// opened here name them).
    pub(crate) fn logged_with_now(&mut self, c: &CommitId) -> Result<Vec<CommitId>> {
        let Some(h) = self.header(c) else { return Ok(Vec::new()) };
        let id = *c;
        let mut out = Vec::new();
        for a in h.aspects.iter().filter(|a| a.ak.as_str() == "keys.0").map(|a| a.tid).collect::<BTreeSet<Tid>>() {
            let Some(ep) = self.epochs(&a) else { continue };
            for r in osis_keys::ROLES {
                for (e, info) in ep.role(r).epochs() {
                    if self.core.ix.epoch_intro.get(&(a, r, *e)).is_some_and(|x| x.1 == id) {
                        out.extend(info.names.iter().flat_map(|n| n.list.iter().map(|x| x.key.commit)).filter(|x| self.core.ix.commits.contains_key(x)));
                    }
                }
            }
        }
        let actors: BTreeSet<Tid> = h.aspects.iter().filter(|a| a.ak.as_str() == "secrets.0").map(|a| a.tid).collect();
        for a in actors {
            let (Some(si), ki) = (h.aspect_index(&a, "secrets.0"), h.aspect_index(&a, "keys.0")) else { continue };
            let (w, k) = self.read(|tx| {
                let w = crate::apply::held_fragment(tx, &id, si)?.map(|f| crate::apply::keys::secrets_write(&f));
                let k = match ki {
                    Some(ki) => crate::apply::held_fragment(tx, &id, ki)?.map(|f| crate::apply::keys::keys_write(&f)),
                    None => None,
                };
                Ok((w, k))
            })?;
            if let Some(w) = w {
                out.extend(crate::rotation::members::carried(&self.core, &w, k.as_ref()));
            }
        }
        out.sort();
        out.dedup();
        out.retain(|x| x != c);
        Ok(out)
    }


    /// Begins a complete pass: the next pass place, one count with the role commits' arrivals
    /// from elsewhere, so a pass begun at place `p` counts for a want at `since` only when
    /// `p > since`.
    pub fn begin_pass(&mut self) -> u64 {
        self.begin_pass_now()
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

    /// Whether a role commit on `t` is held here but does not count, its epoch revoked and no
    /// held word (a thing list, a listing) naming it yet (spec/permissions.md §5.5): what may give
    /// this node its role on `t` again once the lists arrive.
    /// Stamped per thing: moves as one counts or arrives.
    pub fn uncounted_role_on(&self, t: &Tid) -> bool {
        self.core.ix.held.uncounted_on(t)
    }

    /// The pass place the newest role commit on `actor` applied from elsewhere arrived at.
    pub fn role_arrival_place(&self, actor: &Tid) -> Option<u64> {
        self.role_arrival(actor)
    }

    /// Causes a pass wait runs from, kept (rows `jc/`; bound checks).
    pub fn causes_judged(&self) -> usize {
        self.core.ix.cause_at.len()
    }

    /// The pass place now: a pass begun after this call begins above it.
    pub fn pass_place(&self) -> u64 {
        self.core.place
    }

    /// A complete pass of `s` begun at place `began` (`begin_pass`) ended (spec/sync-status.md
    /// §1): kept durably, the last per sync ID; the re-seal and history-add trigger (`pass_end`)
    /// and history completeness read it.
    pub fn note_complete_pass(&mut self, s: &SyncId, began: u64) -> Result<()> {
        self.note_complete_pass_now(s, began)
    }

    // Timers and config

    /// When the memo clock next moves a value read with an `until` (`memo::Clock::next`): the
    /// driver folds it into the node's wake.
    pub fn clock_next(&self) -> Option<WallMs> {
        self.core.time.next().map(WallMs)
    }

    /// Whether the memo clock reached `t`, read up to `t`: a value judged by it moves when `t`
    /// passes, and `clock_next` wakes the driver then.
    pub fn reached(&self, t: WallMs) -> bool {
        self.core.time.until(Some(t.0)) >= t.0
    }

    /// Moves the memo clock to `now`.
    pub fn set_now(&mut self, now: WallMs) {
        self.core.time.set(now.0);
    }

}

#[cfg(test)]
mod tests_clock {
    use crate::local_peer::LocalPeer;
    use osis_base::WallMs;

    // `reached` (sync's deadlines, e.g. a link's follow time, spec/sync-inbox.md §6): read before
    // `t`, it sets a wake at `t`, and holds once the clock is there.
    #[test]
    fn reached_wakes_at_its_time_spec_sync_inbox_6() {
        let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let e = &mut lp.peers[0].engine;
        let now = e.now();
        e.set_now(now);
        let t = WallMs(now.0 + 10_000);
        assert!(!e.reached(t));
        assert_eq!(e.clock_next(), Some(t), "a wake at t");
        e.set_now(t);
        assert!(e.reached(t));
    }
}
