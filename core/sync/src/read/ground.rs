//! What `read` stands on (`Ground`): the engine's judgement of what S carries, read per (S,
//! commit) as memo values; the own store's entries of S per commit; each source's stream of S
//! (`known`, per commit and source); and the acts read does. Every value read is a memo or a
//! stamped read, so `Effects` follows it, and each feed (`*_added`) is a cursor over an index's
//! own log; `Live` is the product's, a test's ground is a table of stamped values.

use crate::store::{Source, Stand};
use crate::types::{ConnId, Entry, Result};
use osis_base::{BlobId, CommitId, SyncId, Tid, WallMs};
use osis_crypto::SigningSecret;
use osis_engine::retention::Minting;
use osis_engine::sync::{BodyFacts, BodyMeta, CertKind, Destruction, PartSet, PieceLink, ReadCredentials, SealedSet};
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
    /// An own commit a repair wrote: the blobs it encrypted afresh, never repaired by way of it
    /// (spec/sync-ids.md §1 Repair); empty for any other commit.
    pub repair_fresh: Arc<BTreeSet<BlobId>>,
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
    /// The parts this node opened (or sealed) of it.
    pub parts: PartSet,
    /// The sections it holds that this node did not open, by digest: compared by bytes alone.
    pub sealed: SealedSet,
    /// A per-sync-ID copy (spec/sync-judgement.md §1).
    pub copy: bool,
}

/// What read stands on and what it does.
pub trait Ground {
    /// Commits the engine came to hold since the last call (all of them at the first: a start).
    fn commits_added(&mut self) -> Result<Vec<CommitId>>;
    /// Entries of a read S in the own store whose commit this node holds, since the last call (all
    /// of them at the first: a start): an entry added or changed, its blob coming to name a
    /// commit (opened or sealed here), or that commit coming to be held. Each is judged under S
    /// whether or not S carries a body of it (spec/sync-judgement.md §2: one it carries none of is
    /// outside the required set). An entry of a commit not held (pending, parked) is not judged:
    /// unjudged blobs are kept within the pending bounds (§1 Unjudged blobs).
    fn entries_added(&mut self) -> Result<Vec<(SyncId, CommitId)>>;
    /// The pass place now (`Engine::pass_place`): a complete pass of S counts for what happened
    /// here only when begun after it (spec/sync-status.md §1).
    fn place(&mut self) -> u64;
    /// A complete pass of S begun after pass place `since` ended (`Status::passed_since`; a
    /// stamped read).
    fn passed(&mut self, s: &SyncId, since: u64) -> Result<bool>;
    /// Entry `b` of S leaves the own store with no tombstone (judged outside S's required set
    /// here: judged so wrongly, it is logged or pulled again once required).
    fn unlog(&mut self, s: &SyncId, b: &BlobId) -> Result<()>;
    /// Per sync ID of the sync set, `c`'s body there (`Engine::sync_bodies`).
    fn bodies(&mut self, c: &CommitId) -> Result<Arc<BTreeMap<SyncId, BodyMeta>>>;
    fn facts(&mut self, s: &SyncId, c: &CommitId) -> Result<Facts>;
    /// Thing `t`'s held mintings with their standings and expiries (`Engine::mintings_of`,
    /// spec/commits.md §5 A thing's mintings travel with its record).
    fn mintings(&mut self, t: &Tid) -> Result<Arc<Vec<Minting>>>;
    /// Falls of held parts on `c`'s aspects so far (`Engine::fall_mark`, summed over them).
    fn fall_mark(&mut self, s: &SyncId, c: &CommitId) -> Result<u64>;
    fn credentials(&mut self, s: &SyncId) -> Result<Option<Arc<ReadCredentials>>>;
    /// S's thing's destruction, when S is a destroyed thing's own sync ID.
    fn destruction(&mut self, s: &SyncId) -> Result<Option<Arc<Destruction>>>;
    /// This node syncs S read (`Store::holding`: the sync set, or leaving and waiting): read judges
    /// nothing else.
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
    /// Whether entry `e` of `c`'s body under S stands as this node's log of it
    /// (spec/sync-judgement.md §3 Own store: stamped where it writes S): where it holds S's head
    /// write key, one stamped under that key (or a role commit a recorded step registers, stamped
    /// under that step's parent, spec/sync-ids.md §6 Steps), own or a peer's alike; anywhere
    /// else, any entry held.
    fn stands(&mut self, s: &SyncId, c: &CommitId, e: &Entry) -> Result<bool> {
        let _ = (s, c, e);
        Ok(true)
    }
    /// Entry `b` of S stamped in place under S's head write key: the same blob and wrap, a new
    /// stamp, this node's own from then on (off any peer budget).
    fn restamp(&mut self, s: &SyncId, b: &BlobId) -> Result<()>;
    /// This node's own tombstones of `c`'s entries under S.
    fn own_tombstones(&mut self, s: &SyncId, c: &CommitId) -> Result<Vec<BlobId>>;
    /// Every entry of S in the own store, whatever it names (a forgotten commit's included).
    fn own_all(&mut self, s: &SyncId) -> Result<BTreeSet<BlobId>>;
    fn blob(&mut self, b: &BlobId) -> Result<Option<BlobInfo>>;
    /// Held blob `b` holds a part this node dropped for good (purged, past its bounds, expired,
    /// destroyed): must-not-hold wherever it is logged (spec/sync-judgement.md §1).
    fn dropped(&mut self, b: &BlobId) -> Result<bool>;
    /// Held blob `b` is a strict subset of another of `held`, the blobs of its commit held under S
    /// (`Engine::strict_subset`, spec/sync-judgement.md §2): must-not-hold.
    fn strict_subset(&mut self, s: &SyncId, b: &BlobId, held: &BTreeSet<BlobId>) -> Result<bool>;
    /// `there`, the blobs of `c` held at a place, carry what only a blob carries of its body and
    /// no purge request reopens it (`Engine::neither`, spec/sync-judgement.md §3 Neither): a delete
    /// of it there stands, and nothing of it is relayed there.
    fn neither(&mut self, s: &SyncId, c: &CommitId, there: &BTreeSet<BlobId>) -> Result<bool>;

    /// The sources of S on connections up now.
    fn sources(&mut self, s: &SyncId) -> Result<Arc<Vec<SrcView>>>;
    /// Where each source of S up now is reached, reading nothing of its streams' rows: what a
    /// fetch needs (a piece reading `sources` would move with every source's head and full row,
    /// read at its absent stamp, so a removal in that row's bucket would judge every piece).
    fn reached(&mut self, s: &SyncId) -> Result<Vec<(Source, ConnId)>> {
        Ok(self.sources(s)?.iter().map(|x| (x.at, x.conn)).collect())
    }
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
    /// Every source of S heard out (spec/sync-status.md §1), at once with no peer sharing S
    /// (`Status::heard_out_or_alone`).
    fn heard_out(&mut self, s: &SyncId) -> Result<bool>;
    fn stand(&mut self, at: &Source, s: &SyncId, c: &CommitId) -> Result<Option<Stand>>;

    /// Logs `c`'s body under S in the own store; its blob, or `None` when it cannot be logged here.
    /// Not `fresh`: a held blob of it not tombstoned under S, verbatim under a wrap for S, else a
    /// fresh encryption. `fresh` (logged again once, §4): always a fresh encryption. A fresh
    /// encryption is `Engine::seal_body`'s alone, given every held blob of the commit
    /// (spec/crypto.md §5 Passing on: refused while it may not be made).
    fn log_own(&mut self, s: &SyncId, c: &CommitId, fresh: bool) -> Result<Option<BlobId>>;
    /// The entry leaves the own log, its tombstone noting `c`.
    fn drop_own(&mut self, s: &SyncId, b: &BlobId, c: &CommitId) -> Result<()>;
    fn lift(&mut self, s: &SyncId, b: &BlobId) -> Result<()>;
    /// Entry `b` of S fetched from the source (streams' Fetch, spec/sync-judgement.md §3 Dropped
    /// bodies): a body counting missing again.
    fn fetch(&mut self, at: &SrcView, s: &SyncId, b: &BlobId) -> Result<()>;
    /// A Delete of `b` at the source, signed by `key` (its head's delete key).
    fn delete(&mut self, at: &SrcView, s: &SyncId, b: &BlobId, key: &SigningSecret) -> Result<()>;
    /// Registers at the source the closing step of its head `head` (spec/wire.md §8), signed by
    /// `key`, that head's delete key (spec/sync-judgement.md §5 Emptying).
    fn close(&mut self, at: &SrcView, s: &SyncId, head: &StepId, key: &SigningSecret) -> Result<()>;
    /// `c`'s body given to a source this node does not stamp for (spec/sync-judgement.md §3
    /// Reader that is not a writer): own entry `b` relayed under its stamp when the source's head
    /// write key verifies it, else a fresh encryption (`Engine::seal_body`) deposited.
    fn deposit(&mut self, at: &SrcView, s: &SyncId, c: &CommitId, b: &BlobId) -> Result<()>;
    fn set_stand(&mut self, at: &Source, s: &SyncId, c: &CommitId, stand: &Stand) -> Result<()>;
    /// A destroyed thing's sync ID left (§5: emptied and heard out, held with no delete key, or
    /// untold): its store shredded, then `Engine::forget_destroyed`.
    fn forget(&mut self, s: &SyncId) -> Result<()>;

    /// Of kind `r` (records: `None`; a rotation's thing lists: `Some(r)`), what S carries as
    /// certificates that no own certificate blob of that kind there carries (spec/permissions.md
    /// §4 Logging certificates: the records missing; spec/sync-judgement.md §1 List blobs), and
    /// the certificate blobs of that kind sealed here under S that the own store holds no more,
    /// and those it holds.
    fn cert_blobs_missing(&mut self, s: &SyncId, r: CertKind) -> Result<CertBlobsMissing> {
        let _ = (s, r);
        Ok(CertBlobsMissing::default())
    }
    /// The rotations with a thing list S carries (`Engine::list_rotations`): where read starts
    /// following S's list blobs.
    fn list_rotations(&mut self, s: &SyncId) -> Result<Vec<CommitId>> {
        let _ = s;
        Ok(Vec::new())
    }
    /// The (S, rotation) pairs whose S came to carry a list of the rotation since the last call
    /// (`Engine::lists_feed`, per read sync ID of the thing).
    fn lists_added(&mut self) -> Result<Vec<(SyncId, CommitId)>> {
        Ok(Vec::new())
    }
    /// Certificate blobs of kind `r` sealed here under S that the own store holds no more: what
    /// the engine keeps of them goes.
    fn forget_cert_blobs(&mut self, s: &SyncId, r: CertKind, gone: &BTreeSet<osis_base::BlobId>) -> Result<()> {
        let _ = (s, r, gone);
        Ok(())
    }
    /// Logs one certificate blob of kind `r` under S in the own store (a fresh encryption): a
    /// record blob of records `tids`, or a list blob of rotation `r`'s thing lists for `tids`.
    fn log_cert_blob(&mut self, s: &SyncId, r: CertKind, tids: &BTreeSet<osis_base::Tid>) -> Result<()> {
        let _ = (s, r, tids);
        Ok(())
    }
    /// The links of `c`'s body at S, where its pieces start (`Engine::piece_roots`;
    /// spec/sync-judgement.md §1).
    fn piece_roots(&mut self, s: &SyncId, c: &CommitId) -> Result<Arc<Vec<PieceLink>>> {
        let _ = (s, c);
        Ok(Arc::default())
    }
    /// What lies one step below piece `p`: `None` while it is not held (`Engine::piece_below`).
    fn piece_below(&mut self, p: &PieceLink) -> Result<Option<Arc<Vec<PieceLink>>>> {
        let _ = p;
        Ok(None)
    }
    /// What the own store has of piece `b` under S.
    fn piece(&mut self, s: &SyncId, b: &BlobId) -> Result<PieceAt> {
        let _ = (s, b);
        Ok(PieceAt::Absent)
    }
    /// The source's stream shows piece `b` under S present.
    fn piece_shown(&mut self, at: &Source, s: &SyncId, b: &BlobId) -> Result<bool> {
        let _ = (at, s, b);
        Ok(false)
    }
    /// The source's stream showed piece `b` under S deleted (a Deleted event, or a refusal as
    /// tombstoned).
    fn piece_deleted(&mut self, at: &Source, s: &SyncId, b: &BlobId) -> Result<bool> {
        let _ = (at, s, b);
        Ok(false)
    }
    /// Logs held piece `b` under S in the own store (filler wrap; a peer's entry of it becomes
    /// own, off its peer budget).
    fn log_piece(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        let _ = (s, b);
        Ok(())
    }
    /// The engine opens entry `b` of S again from the store (its body counts missing again).
    fn take(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        let _ = (s, b);
        Ok(())
    }
    /// The engine takes piece `b` from the store's entry of it under S (`Engine::take_piece`).
    fn take_piece(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        let _ = (s, b);
        Ok(())
    }
    /// Repairs pieces `b` of own commit `c` in one commit (spec/sync-ids.md §1 Repair,
    /// `Engine::relink`).
    fn repair(&mut self, c: &CommitId, b: &BTreeSet<BlobId>) -> Result<()> {
        let _ = (c, b);
        Ok(())
    }
    /// Freed links judged freed since the last call (all of them at the first: a start).
    fn freed_added(&mut self) -> Result<Vec<(BlobId, Tid)>> {
        Ok(Vec::new())
    }
    /// Freed link `b` of thing `t` is in the set.
    fn freed_link(&mut self, b: &BlobId, t: &Tid) -> Result<bool> {
        let _ = (b, t);
        Ok(false)
    }
    /// The sync IDs read here carrying thing `t` (`Engine::carrying`).
    fn carrying(&mut self, t: &Tid) -> Result<BTreeSet<SyncId>> {
        let _ = t;
        Ok(BTreeSet::new())
    }
    /// The own store's entry `b` under S, of a blob naming no commit, leaves: a freed link's
    /// piece, a record blob under an emptied S.
    fn drop_blob(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        let _ = (s, b);
        Ok(())
    }
    /// A Delete of freed link `b` of `t` at the source, by the head's delete key where its held
    /// prefix bore the link, else by level (spec/sync-compaction.md §1 Freed links).
    fn delete_freed(&mut self, at: &SrcView, s: &SyncId, head: &StepId, b: &BlobId, t: &Tid) -> Result<()> {
        let _ = (at, s, head, b, t);
        Ok(())
    }
    /// Freed link `b` of `t` leaves the set: no entry of it is known here.
    fn freed_done(&mut self, b: &BlobId, t: &Tid) -> Result<()> {
        let _ = (b, t);
        Ok(())
    }
    /// Commit `c` as the engine judges it for forgetting (spec/commits.md §5 Forgetting,
    /// `Engine::forgettable`): `None` once it is not held, else whether the engine would forget
    /// it once no entry of it is known.
    fn forgettable(&mut self, c: &CommitId) -> Result<Option<bool>> {
        let _ = c;
        Ok(Some(false))
    }
    /// The sync IDs where an entry or a tombstone of a blob of `c` is held here (`Store::naming`,
    /// `Store::tombstoned_under`), whatever sync IDs carry a body of it now.
    fn known_under(&mut self, c: &CommitId) -> Result<BTreeSet<SyncId>> {
        let _ = c;
        Ok(BTreeSet::new())
    }
    /// The held parts of `c` that drop as covered now (`Engine::covered_drops`).
    fn covered_drops(&mut self, c: &CommitId) -> Result<Vec<(Tid, osis_base::Ak)>> {
        let _ = c;
        Ok(Vec::new())
    }
    /// Drops part `(t, ak)` of `c` as covered (`Engine::drop_body`).
    fn drop_body(&mut self, c: &CommitId, t: &Tid, ak: &osis_base::Ak) -> Result<()> {
        let _ = (c, t, ak);
        Ok(())
    }
    /// Forgets commits `cs`, IDs included (`Engine::forget_commits`).
    fn forget_commits(&mut self, cs: &[CommitId]) -> Result<()> {
        let _ = cs;
        Ok(())
    }
    /// Whether this node's step of S is due and each role commit it registers is logged under S
    /// in the own store (spec/sync-ids.md §6 Steps: issued after logging the rotations it
    /// registers, so they are stamped under the head a store keeping S unread holds).
    fn step_ready(&mut self, s: &SyncId) -> Result<bool> {
        let _ = s;
        Ok(false)
    }
    /// Issues the step due of S (`step_ready`): whether one was issued.
    fn issue_step(&mut self, s: &SyncId) -> Result<bool> {
        let _ = s;
        Ok(false)
    }
}

/// What the own store has of a piece under S (`Ground::piece`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PieceAt {
    Absent,
    /// Logged by this node, stamped as it logs now (`Ground::stands`'s head rule).
    Own,
    /// A peer's entry (pulled, not yet taken).
    Peer,
    /// Tombstoned: never logged again under that blob ID.
    Tombstoned,
}

/// `Ground::cert_blobs_missing`, of one kind under one S.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertBlobsMissing {
    /// Records, or things whose lists of the rotation, S carries that no own certificate blob of
    /// the kind carries: one blob of them is logged.
    pub missing: BTreeSet<osis_base::Tid>,
    /// Certificate blobs of the kind sealed here under S that the own store holds no more.
    pub gone: BTreeSet<osis_base::BlobId>,
    /// Certificate blobs of the kind sealed here under S that the own store holds.
    pub held: BTreeSet<osis_base::BlobId>,
    /// Of `held`, those not stamped under S's head write key where this node holds it
    /// (`Ground::stands`): stamped in place.
    pub stale: BTreeSet<osis_base::BlobId>,
}
