//! What `read` stands on (`Ground`): the engine's judgement of what S carries, read per (S,
//! commit) as memo values; the own store's entries of S per commit; each source's stream of S
//! (`known`, per commit and source); and the acts read does. Every value read is a memo or a
//! stamped read, so `Effects` follows it, and each feed (`*_added`) is a cursor over an index's
//! own log; `Live` is the product's, a test's ground is a table of stamped values.

use crate::store::{Source, Stand};
use crate::session::RequestId;
use crate::types::{ConnId, Entry, Result};
use osis_base::{BlobId, CommitId, SyncId, Tid, Ts, WallMs};
use osis_engine::retention::Minting;
use osis_engine::sync::{BodyFacts, BodyId, BodyMeta, Loss, PartSet, PieceLink, ReadCredentials, SealedSet, Strip};
use osis_blob::StepId;
use std::collections::BTreeSet;
use std::sync::Arc;

use super::Why;

/// The engine's facts about one body at S (spec/sync-judgement.md §2-§3): the facade's
/// `BodyFacts` and what the judgement reads beside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facts {
    pub body: BodyFacts,
    /// A must-not-hold condition only the engine judges (purged, a superseded
    /// or ended card), if any.
    pub must_not: Option<Why>,
    /// This node's own commit (`own_commits`).
    pub own: bool,
    /// An own commit a repair wrote: the blobs it encrypted afresh, never repaired by way of it
    /// (spec/sync-ids.md §1 Repair); empty for any other commit.
    pub repair_fresh: Arc<BTreeSet<BlobId>>,
    /// A role commit or request (spec/sync-judgement.md §3 Role entries first).
    pub role: bool,
    /// Snapshots of the body's aspects stamped later than it that this node does not hold
    /// (forgotten, dropped), each with whether this node judged it invalid (spec/sync-judgement.md
    /// §2 established uncovered).
    pub later_unheld: Vec<(CommitId, bool)>,
    /// The body counts as never received again (spec/sync-judgement.md §3 Dropped bodies).
    pub missing: bool,
}

/// One source of S (spec/sync-opens.md §4): a member S of a record in memory, connected or not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SrcView {
    /// Where its rows live: its record, else the connection.
    pub at: Source,
    /// It keeps S unread (a store source); else it reads S.
    pub store: bool,
    /// Its head for S, as its stream last named it.
    pub head: Option<StepId>,
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
    fn commits_added(&mut self) -> Vec<CommitId>;
    /// Entries of a read S in the own store whose commit this node holds, since the last call (all
    /// of them at the first: a start): an entry added or changed, its blob coming to name a
    /// commit (opened or sealed here), or that commit coming to be held. Each is judged under S
    /// whether or not S carries a body of it (spec/sync-judgement.md §2: one it carries none of is
    /// outside the required set). An entry of a commit not held (pending, parked) is not judged:
    /// unjudged blobs are kept within the pending bounds (§1 Unjudged blobs).
    fn entries_added(&mut self) -> Result<Vec<(SyncId, BodyId)>>;
    /// The pass place now (`Engine::pass_place`): a complete pass of S counts for what happened
    /// here only when begun after it (spec/sync-status.md §1).
    fn place(&mut self) -> u64;
    /// A complete pass of S begun after pass place `since` ended (`Status::passed_since`; a
    /// stamped read).
    fn passed(&mut self, s: &SyncId, since: u64) -> bool;
    /// Entry `b` of S leaves the own store with no tombstone (judged outside S's required set
    /// here: judged so wrongly, it is logged or pulled again once required).
    fn unlog(&mut self, s: &SyncId, b: &BlobId) -> Result<()>;
    /// Per sync ID of the sync set, `c`'s bodies there (`Engine::sync_bodies`): its sync unit
    /// body (no thing) and its certificate copy on each thing outside the sync unit.
    fn bodies(&mut self, c: &CommitId) -> Result<Arc<osis_engine::sync::Bodies>>;
    fn facts(&mut self, s: &SyncId, c: &BodyId) -> Result<Facts>;
    /// `c`'s body under S taken as covered: per delta needing a carrier (holding a live write,
    /// kept, or dropped as covered and not purged), the commits whose entries under S would
    /// carry it (spec/sync-compaction.md §1 Carriers, `Engine::carriers`): one of each set must
    /// be held where the body leaves. Empty: none needed. Asked only where an entry of the body
    /// would leave: it moves with every snapshot extending the body's chain of covers.
    fn carriers(&mut self, s: &SyncId, c: &BodyId) -> Result<Vec<BTreeSet<CommitId>>>;
    /// `c`'s judgement under S went idle: what `facts` keeps of it may go (`Engine::unfollow_facts`).
    fn unfollow_facts(&mut self, s: &SyncId, c: &BodyId) {
        let _ = (s, c);
    }
    /// Brings the ground's rows kept per key up to date before judging (a judgement depends on a
    /// row as last refreshed).
    fn refresh(&mut self) -> Result<()> {
        Ok(())
    }
    /// Thing `t`'s held mintings with their standings and expiries (`Engine::mintings_of`,
    /// spec/commits.md §5 A thing's mintings travel with its record).
    fn mintings(&mut self, t: &Tid) -> Arc<Vec<Minting>>;
    /// Falls of held parts on `c`'s aspects so far (`Engine::fall_mark`, summed over them).
    fn fall_mark(&mut self, s: &SyncId, c: &BodyId) -> u64;
    fn credentials(&mut self, s: &SyncId) -> Result<Option<Arc<ReadCredentials>>>;
    /// This node syncs S read (`Store::holding`: the sync set, or leaving and waiting): read judges
    /// nothing else.
    fn reads(&mut self, s: &SyncId) -> bool;
    /// Sync IDs whose holding moved since the last call (none at the first: a start judges every
    /// body): one coming to be read judges its bodies, which a judgement while it was not read
    /// left unfollowed.
    fn holdings_moved(&mut self) -> Vec<SyncId>;
    /// No thing of S's sync unit holds a part that may hold a strong as a header only
    /// (spec/sync-judgement.md §2 outside the required set, §3 Header-only parts): until then
    /// nothing is judged outside it.
    fn unit_settled(&mut self, s: &SyncId) -> Result<bool>;
    /// A reader can pull S from here: this node publishes a `dial.0` entry, or a connection shares S
    /// (spec/sync-judgement.md §3 Own store).
    fn pullable(&mut self, s: &SyncId) -> Result<bool>;
    /// S's first sync here ended (`Store::first_synced`, spec/sync-streams.md §5; a stamped read),
    /// or S's thing was made here (nothing to sync first).
    fn first_synced(&mut self, s: &SyncId) -> Result<bool>;
    /// This node may log `c`'s body under S now (`Engine::may_log`, spec/sync-judgement.md §2
    /// Loggable): must-hold only while it may.
    fn may_log(&mut self, s: &SyncId, c: &BodyId) -> Result<bool>;
    /// The time (not followed: `Read` follows it through its clock).
    fn now(&self) -> WallMs;

    /// The entries of `c` in this node's own store of S.
    fn own(&mut self, s: &SyncId, c: &BodyId) -> Result<Vec<Entry>>;
    /// Whether entry `e` of `c`'s body under S stands as this node's log of it
    /// (spec/sync-judgement.md §3 Own store: stamped where it writes S): where it holds S's head
    /// write key, one stamped under that key (or a role commit a recorded step registers, stamped
    /// under that step's parent, spec/sync-ids.md §6 Steps), own or a peer's alike; anywhere
    /// else, any entry held.
    fn stands(&mut self, s: &SyncId, c: &BodyId, e: &Entry) -> Result<bool> {
        let _ = (s, c, e);
        Ok(true)
    }
    /// Whether blob `b` holds `meta`, S's body of its commit as read settled it
    /// (`Engine::body_held_by`): only such an entry is the body's log; a certificate copy of fewer
    /// parts is not.
    fn holds_body(&mut self, meta: &BodyMeta, b: &BlobId) -> Result<bool> {
        let _ = (meta, b);
        Ok(true)
    }
    /// Whether a peer's deposited entry `b` of `c` under S is promoted (spec/sync-inbox.md §4,
    /// `inbox::promotion`): stamped in place as this node's log of the body.
    fn promotion(&mut self, s: &SyncId, c: &BodyId, b: &BlobId) -> Result<crate::inbox::Promotion> {
        let _ = (s, c, b);
        Ok(crate::inbox::Promotion::Yes)
    }
    /// Entry `b` of S stamped in place under S's head write key: the same blob and wrap, a new
    /// stamp, this node's own from then on (off any peer budget).
    fn restamp(&mut self, s: &SyncId, b: &BlobId) -> Result<()>;
    /// This node's own tombstones of `c`'s entries under S.
    fn own_tombstones(&mut self, s: &SyncId, c: &BodyId) -> Result<Vec<BlobId>>;
    fn blob(&mut self, b: &BlobId) -> Result<Option<BlobInfo>>;
    /// Held blob `b` carries a part that strips here (purged, past its bounds, destroyed, dropped
    /// as covered by a snapshot reaching it; `Engine::strip_of`): must-not-hold wherever it is logged
    /// (spec/sync-judgement.md §2 per blob), with what a delete of it at a peer waits for.
    fn gone(&mut self, b: &BlobId) -> Option<Strip>;
    /// Held blob `b` loses to `o`, another held blob of its commit, under S (`Engine::blob_loses`,
    /// spec/sync-judgement.md §2 Per blob); `stands`: whether each may stand as the body's log.
    fn loses(&mut self, s: &SyncId, b: &BlobId, o: &BlobId, stands: (bool, bool)) -> Result<Option<Loss>>;
    /// `there`, the blobs of `c` held at a place, carry what only a blob carries of its body and
    /// no purge request reopens it (`Engine::neither`, spec/sync-judgement.md §3 Neither): a delete
    /// of it there stands, and nothing of it is relayed there.
    fn neither(&mut self, s: &SyncId, c: &BodyId, there: &BTreeSet<BlobId>) -> Result<bool>;

    /// The sources of S, up or away: a member S of each record in memory (a take or a release
    /// moves none).
    fn sources(&mut self, s: &SyncId) -> Arc<Vec<SrcView>>;
    /// The sources of S, reading nothing of their streams' rows: what a fetch needs (a piece
    /// reading `sources` would move with every source's head row, read at its absent stamp, so a
    /// removal in that row's bucket would judge every piece).
    fn reached(&mut self, s: &SyncId) -> Vec<Source> {
        self.sources(s).iter().map(|x| x.at).collect()
    }
    /// One source of S (read per source, so a source's change moves its rows alone).
    fn source(&mut self, s: &SyncId, at: &Source) -> Option<SrcView>;
    /// The connection holding `at`'s record once its digests agreed: where what is owed there
    /// goes (`read/owed.rs`).
    fn connected(&mut self, at: &Source) -> Option<ConnId>;
    /// The peer on `conn` told it is full for S (spec/sync-streams.md §4 Full).
    fn told_full(&mut self, conn: ConnId, s: &SyncId) -> bool;
    /// Commit `c` is held here (applied or judged): one that is not is not judged (spec/sync-judgement.md
    /// §1 Unjudged blobs).
    fn holds(&mut self, c: &CommitId) -> bool;
    /// Whether source `at` keeps S unread, as it last joined S, up now or away (kept with what its
    /// stream showed). Moves only when that changes, never as it comes and goes.
    fn kept_at(&mut self, s: &SyncId, at: &Source) -> bool;
    /// The source's head for S, as its stream last named it, up now or away.
    fn head_at(&mut self, s: &SyncId, at: &Source) -> Option<StepId>;
    /// The sources, up now or away, whose stream shows an entry of `c` under S present (one
    /// showing it deleted only is never idle there, so its verdict moving judges it again).
    fn shown_at(&mut self, s: &SyncId, c: &BodyId) -> Result<BTreeSet<Source>>;
    /// Sources of S whose view was written (joined or changed) since the last call.
    fn sources_added(&mut self) -> Vec<(SyncId, Source)>;
    fn seen(&mut self, at: &Source, s: &SyncId, c: &BodyId) -> Result<Seen>;
    /// `known` rows written since the last call (a source's stream showed an entry of the commit,
    /// or its removal); at the first call (a start) every row, presence and deletes seen alike.
    fn seen_added(&mut self) -> Result<Vec<(Source, SyncId, BodyId)>>;
    /// Some source's stream shows an entry of `c` under S present.
    fn present_anywhere(&mut self, s: &SyncId, c: &BodyId) -> Result<bool>;
    /// Every source of S heard out (spec/sync-status.md §1), at once with no peer to wait for on S
    /// (`Status::heard_out_or_alone`).
    fn heard_out(&mut self, s: &SyncId) -> Result<bool>;
    fn stand(&mut self, at: &Source, s: &SyncId, c: &BodyId) -> Result<Option<Stand>>;

    /// Held commit `c`'s `ts` (`Engine::commit_ts`): what is logged together goes in this order.
    fn ts(&mut self, c: &CommitId) -> Option<Ts>;
    /// Logs `c`'s body under S in the own store; its blob, or `None` when it cannot be logged here.
    /// Not `fresh`: a held blob of it not tombstoned under S, verbatim under a wrap for S, else a
    /// fresh encryption. `fresh` (logged again once, §4): always a fresh encryption. A fresh
    /// encryption is `Engine::seal_body`'s alone, given every held blob of the commit
    /// (spec/crypto.md §5 Passing on: refused while it may not be made).
    /// `skip`: entries it replaces, never logged verbatim.
    fn log_own(&mut self, s: &SyncId, c: &BodyId, fresh: bool, skip: &[BlobId]) -> Result<Option<BlobId>>;
    /// The entry leaves the own log, its tombstone noting `c`.
    fn drop_own(&mut self, s: &SyncId, b: &BlobId, c: &BodyId) -> Result<()>;
    fn lift(&mut self, s: &SyncId, b: &BlobId) -> Result<()>;
    /// Entry `b` of S fetched on `conn` (streams' Fetch, spec/sync-judgement.md §3 Dropped
    /// bodies): a body counting missing again.
    fn fetch(&mut self, conn: ConnId, s: &SyncId, b: &BlobId) -> Result<()>;
    /// Commit `c`'s body under S asked for by ID on `conn` (streams' Want, spec/sync-judgement.md
    /// §3 Asked by ID): a body counting missing.
    fn want(&mut self, conn: ConnId, s: &SyncId, c: &osis_base::CommitId) -> Result<()>;
    /// The Delete of commit blob `b` this node can sign for a source on `head` (`Live::delete_item`):
    /// by the head's delete key, else by the delete keys of levels it holds. `None`: it holds
    /// neither, and the entry stays there until a holder connects or it expires.
    fn delete_item(&mut self, s: &SyncId, head: &StepId, b: &BlobId) -> Result<Option<osis_blob::DeleteItem>>;
    /// A Delete of `b` on `conn` (`delete_item`): the request, if one went.
    fn delete(&mut self, conn: ConnId, s: &SyncId, head: &StepId, b: &BlobId) -> Result<Option<RequestId>>;
    /// `c`'s body given to the source on `conn`, on `head`, that this node does not stamp for
    /// (spec/sync-judgement.md §3 Reader that is not a writer): own entry `b` relayed under its
    /// stamp when the head's write key verifies it, else a fresh encryption
    /// (`Engine::seal_body`) deposited.
    fn deposit(&mut self, conn: ConnId, head: Option<StepId>, s: &SyncId, c: &BodyId, b: &BlobId) -> Result<()>;
    fn set_stand(&mut self, at: &Source, s: &SyncId, c: &BodyId, stand: &Stand) -> Result<()>;

    /// What S carries as certificates that no certificate blob in the own store carries,
    /// whoever logged it (spec/permissions.md §4 Logging certificates: the records missing), and
    /// what becomes of each such blob the engine noted under S.
    fn cert_blobs_missing(&mut self, s: &SyncId) -> Result<CertBlobsMissing> {
        let _ = s;
        Ok(CertBlobsMissing::default())
    }
    /// Certificate blobs sealed here under S that the own store holds no more: what the engine
    /// keeps of them goes.
    fn forget_cert_blobs(&mut self, s: &SyncId, gone: &BTreeSet<osis_base::BlobId>) -> Result<()> {
        let _ = (s, gone);
        Ok(())
    }
    /// Logs one record blob of records `tids` under S in the own store (a fresh encryption).
    fn log_cert_blob(&mut self, s: &SyncId, tids: &BTreeSet<osis_base::Tid>) -> Result<()> {
        let _ = (s, tids);
        Ok(())
    }
    /// The links of `c`'s body of `parts`, where its pieces start (`Engine::piece_roots`;
    /// spec/sync-judgement.md §1).
    fn piece_roots(&mut self, c: &CommitId, parts: &osis_engine::sync::PartSet) -> Result<Arc<Vec<PieceLink>>> {
        let _ = (c, parts);
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
    /// The source's stream shows blob `b` under S present (a piece, a freed link, a certificate
    /// blob).
    fn blob_shown(&mut self, at: &Source, s: &SyncId, b: &BlobId) -> bool {
        let _ = (at, s, b);
        false
    }
    /// The source's stream showed blob `b` under S deleted (a Deleted event, or a refusal as
    /// tombstoned).
    fn blob_deleted(&mut self, at: &Source, s: &SyncId, b: &BlobId) -> Result<bool> {
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
    fn freed_added(&mut self) -> Vec<(BlobId, Tid)> {
        Vec::new()
    }
    /// Freed link `b` of thing `t` is in the set.
    fn freed_link(&mut self, b: &BlobId, t: &Tid) -> bool {
        let _ = (b, t);
        false
    }
    /// The sync IDs read here carrying thing `t` (`Engine::carrying`).
    fn carrying(&mut self, t: &Tid) -> Result<BTreeSet<SyncId>> {
        let _ = t;
        Ok(BTreeSet::new())
    }
    /// The own store's entry `b` under S, of a blob naming no commit, leaves: a freed link's
    /// piece.
    fn drop_blob(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        let _ = (s, b);
        Ok(())
    }
    /// A Delete of freed link `b` of `t` on `conn`, by the head's delete key where its held
    /// prefix bore the link, else by level (spec/sync-compaction.md §1 Freed links): the
    /// request, if one went.
    fn delete_freed(&mut self, conn: ConnId, s: &SyncId, head: &StepId, b: &BlobId, t: &Tid) -> Result<Option<RequestId>> {
        let _ = (conn, s, head, b, t);
        Ok(None)
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
    /// `c` left read (no longer held): what `forgettable` and `covered_drops` keep of it may go
    /// (`Engine::unfollow_fate`).
    fn unfollow_fate(&mut self, c: &CommitId) {
        let _ = c;
    }
    /// Each blob of `c` as a body (`Engine::blob_body`) under each sync ID where an entry or a
    /// tombstone of it is held here (`Store::naming`, `Store::tombstoned_under`) and under each
    /// of `at`, whatever sync IDs carry a body of it now.
    fn known_under(&mut self, c: &CommitId, at: &BTreeSet<SyncId>) -> Result<BTreeSet<(SyncId, BodyId)>> {
        let _ = (c, at);
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
    /// registers, so they are stamped under the head a store keeping S unread holds), and
    /// whether it is deposit-only; or an endorsement of its recorded head is owed (`Now`).
    fn step_ready(&mut self, s: &SyncId) -> Result<StepReady> {
        let _ = s;
        Ok(StepReady::No)
    }
    /// Issues the step due of S and the endorsements owed (`step_ready`): whether any was written.
    fn issue_step(&mut self, s: &SyncId) -> Result<bool> {
        let _ = s;
        Ok(false)
    }
}

/// Whether S's step may be issued (`Ground::step_ready`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StepReady {
    /// Not due, or a rotation it registers is not logged here yet.
    #[default]
    No,
    /// Due by a role newer than the head registers: issued now.
    Now,
    /// Due by a new deposit key alone: issued once a complete pass of S begun after it came due
    /// ended (spec/permissions.md §3: every entry it can open under S opened at the sources it
    /// reaches, so a co-admin's newer seed there is applied first).
    AfterPass,
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
    /// Records, or things whose lists of the rotation, S carries, when no certificate blob of
    /// the kind in the own store carries all of them: one blob of all of them is logged.
    pub missing: BTreeSet<osis_base::Tid>,
    /// Certificate blobs of the kind noted under S that neither the own store holds nor any
    /// source's stream shows: their rows go.
    pub gone: BTreeSet<osis_base::BlobId>,
    /// Certificate blobs of the kind the own store holds under S that are not stamped under S's
    /// head write key where this node holds it (`Ground::stands`): stamped in place.
    pub stale: BTreeSet<osis_base::BlobId>,
    /// Certificate blobs of the kind the own store holds under S that carry nothing S carries
    /// now, or lose to another there (all it carries of S's, and more, or the same with fewer
    /// others, or the same under a lower ID): they leave it (`Ground::unlog`).
    pub unneeded: BTreeSet<osis_base::BlobId>,
    /// Deletes owed at sources keeping S unread, once S's sources are heard out: each blob there
    /// losing to another blob there (spec/sync-ids.md §6 Delete).
    pub deletes: BTreeSet<(Source, StepId, osis_base::BlobId)>,
    /// What is missing waits for S's first sync here, or a complete pass begun after this pass
    /// place (`read::cert_blobs_missing`): a source's blob, pulled, may carry it.
    pub wait: Option<u64>,
}
