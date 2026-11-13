//! The shared set of a connection (issues/net-shared-set.md): the rule: a node shares sync ID L with
//! a connected peer exactly while, on what it holds now, the peer may hold L. Each side sends a
//! filter of beacons of what it may share, tests its own beacons against the peer's filter and
//! offers the hits; a hit opens L only with the tag or J proving it.
//!
//! Invariants the design rests on (each a default test in tests/it/shared.rs or reconnect.rs):
//! - A beacon is equal on both sides, so a filter entry only finds a pair; a Hit is keyed by its
//!   sender's side and the connection (`osis_crypto::kdf::beacon_hit`): reflected to its sender or
//!   carried to another connection it shows nothing.
//! - An untagged 0 opens nothing for the tester; the tag is computed only with the credential.
//! - J counts the actors a connection proved (`Proven::all`).
//! - `pending` (changed_at past `acked_pos`) is tested at every arrival and every own change, and
//!   `acked_pos` passes only what is acknowledged and tested with no Offer unanswered: two nodes
//!   gaining one credential at once cannot both miss it.
//! - A filter connection ends with the rule: re-judged at every change of what a node holds.
//! - An open whose credential a rotation made stale, its peer neither holder nor departed, ends
//!   at `until` (where the rotation was logged, records not on a connection included): the
//!   requester is served through the rotation and nothing logged after it, and gets `Lost` once
//!   it reported a position past `until` (tests/it/until.rs).
//!
//! - A record says only what need not be sent again (issues/net-reconnect.md): a connection with
//!   a record restores S, `acked_pos`, its own filter's generations and the peer's stored filter,
//!   and first proves the two records agree: `Digest` is its first message each way, and on a
//!   difference each side lists S (`Members`) and closes, with no lag, what only one side holds,
//!   re-marking it pending on both. No Offer goes before the peer's digest is read and no Pull
//!   before the agreement ends (a member only one side holds is out of both streams by then).
//!
//! - A Deposit item goes only where J of its inbox's actor is holder, and is taken only for an
//!   inbox an actor this side proved holds, else 14 whether or not it is held: neither side
//!   learns of an inbox the connection's proofs did not already show (tests/it/deposits.rs).
//!
//! A filter goes only to a peer that proved a known actor, so where only one side knows the other
//! (a link's redeemer) that side's filter is the only one; a connection without a record uses its
//! own pair key, starts with whole filters and tests everything.

use super::{Action, ConnId, SyncEngine};
use super::credentials::Credential;
use super::proofs::Proven;
use super::records::ConnRecord;
use crate::error::Result;
use osis_base::{BlobId, CommitId, LabelId, Tid};
use osis_crypto::kdf::{Side, beacon, beacon_hit, beacon_reply};
use osis_proto::filter::{BEACON_P, Page, beacon_value, decode_gcs, encode_gcs, filter_width, pages};
use osis_proto::msg::{MAX_MEMBERS, MAX_SHARED_ITEMS, OfferItem};
use osis_proto::{Code, Message};
use osis_store::{At, Filter, RecordId};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Entries a peer's filter may hold, the sum of its pages. Resource bound: 0 no filter is
/// accepted (nothing opens), infinity a known actor's filter is this node's memory.
pub const MAX_FILTER_ENTRIES: usize = 1 << 22;
/// A page's body, Golomb-coded bytes: well inside `MAX_MESSAGE` and the request window. A page
/// past it is split. Performance switch: 0 is not a page; infinity a filter in one message.
pub const PAGE_BYTES: usize = 256 * 1024;

/// Credential classes as a member records them (`Member::proved`).
const READ: u8 = 0;
const STATIC: u8 = 1;
/// An open by J with no credential.
const JUDGED: u8 = 2;
/// A served head's sync key, and its deposit key (never opens: a depositor sends its Deposit
/// item), at a node that cannot read the sync ID.
const SYNC: u8 = 3;
const DEPOSIT: u8 = 4;
/// A dialer's proof of a sync secret (`osis_crypto::kdf::sync_proof` of the sync key): the
/// credential a dialer that cannot read L opens it at a reader by (spec/sync.md §5 Opens).
const PROOF: u8 = 5;

/// An open by a sync key (this side's Hit at a peer that cannot read, or a dialer's proof): its
/// peer cannot read the sync ID.
fn by_key(class: u8) -> bool {
    class == SYNC || class == PROOF
}

/// Which credentials `shared_creds` lists: this node's as a reader (`read`), those of the sync
/// IDs it keeps unread (`unread`), and the sync key of each served head it reads (`sync`: tested
/// against a peer that cannot read, never in a filter, since a reader opens to a reader by read
/// secret).
#[derive(Clone, Copy)]
struct Which {
    read: bool,
    unread: bool,
    sync: bool,
    /// On a connection the peer dialed, the proof credential (`PROOF`) of the newest step
    /// `label.0` records of each sync ID this node reads: what a dialer that cannot read L opens
    /// it here by.
    accepts: bool,
    /// On a connection this node dialed, the proof credential of each sync ID it keeps unread
    /// whose head's sync secret it holds (`shared_proof_keys`).
    proves: bool,
}

const ALL: Which = Which { read: true, unread: true, sync: true, accepts: true, proves: true };
/// What a node tests and offers: never an unread sync ID's head credentials (it cannot prove
/// them), but its proofs of their sync secrets as a dialer.
const TESTED: Which = Which { read: true, unread: false, sync: true, accepts: false, proves: true };

/// One credential of one L as this connection sees it.
#[derive(Clone)]
struct Cred {
    label: LabelId,
    class: u8,
    value: [u8; 32],
    /// The key an open signature verifies under: the sync key a `PROOF` derives from, else
    /// `value`.
    key: [u8; 32],
    beacon: [u8; 32],
}

/// One item of an Offer this side sent.
#[derive(Clone)]
enum AskedItem {
    Hit(Cred),
    ByRole(LabelId),
    /// A queued deposit for an inbox's nodes (`Dest::Nodes`), by its outbox key's label and blob.
    Deposit(LabelId, BlobId),
    /// A Behind item on this step of the label (none: a hint's, naming no step;
    /// `SyncEngine::behind`).
    Behind(LabelId, Option<Box<osis_label::Step>>),
    /// A Behind item by a key actor's signing key, naming no step, on this static entry of the
    /// label (`SyncEngine::behind`).
    Static(LabelId, [u8; 32]),
}

/// What a request of this side waits for.
#[derive(Clone)]
enum Asked {
    Beacons { generation: u64, pos: u64, last: bool },
    /// Items in order.
    Offer(Vec<AskedItem>),
    Lost,
}

/// The peer's filter as received.
#[derive(Clone)]
struct PeerFilter {
    generation: u64,
    f: u8,
    /// Sorted.
    values: Vec<u64>,
    /// Entries of the whole filter, and how many additions came since.
    whole: usize,
    added: usize,
}

/// A generation of the peer's arriving in pages.
#[derive(Clone)]
struct Pages {
    generation: u64,
    base: Option<u64>,
    f: u8,
    next_lo: u64,
    values: Vec<u64>,
}

/// One member of S (issues/net-shared-set.md, Opens).
#[derive(Clone)]
struct Member {
    class: u8,
    /// The credential's beacon, for an open by a credential (none for JUDGED): the open stands
    /// while a credential with that beacon is admissible.
    beacon: Option<[u8; 32]>,
    /// While being ended by a rotation: the node log position its stream ends at, inclusive
    /// (issues/net-reconnect.md, Joining and rejoining).
    until: Option<u64>,
}

/// The shared set state of one connection with a record.
#[derive(Clone)]
pub(crate) struct Shared {
    r: [u8; 32],
    by_listener: bool,
    key: [u8; 32],
    dialer: [u8; 32],
    listener: [u8; 32],
    next_id: u32,
    /// The record whose S, `acked_pos` and filters this connection keeps (none: kept nowhere).
    record: Option<RecordId>,
    /// The digest this side sent (none without a record).
    digest: Option<[u8; 32]>,
    /// The peer's digest was read: Offers may go.
    digest_read: bool,
    /// The two records agree (the peer's digest matched, or its last Members page was read):
    /// the stream may pull.
    agreed: bool,
    /// The peer's Members pages read so far.
    peer_list: BTreeSet<LabelId>,
    /// `ack`, `tested` and Offers unanswered (`ConnRecord`), and `acked_pos`, for this connection.
    pending: ConnRecord,
    acked_pos: u64,
    test_due: bool,
    /// Whole filter's entries and additions since, generations: the last sent, the last the peer
    /// acknowledged (additions extend it), whether one went on this connection.
    sent_gen: u64,
    acked_gen: u64,
    started: bool,
    in_flight: bool,
    /// The last generation was refused: a whole filter goes again (`again`) at this time (wall
    /// ms), `resync_ms` after, as a refused Pull does (`stream_refused`).
    retry_at: Option<u64>,
    again: bool,
    whole_n: usize,
    added: usize,
    f: u8,
    sent_pos: u64,
    peer: Option<PeerFilter>,
    /// A filter of the peer's arrived on this connection.
    arrived: bool,
    /// The peer's filter arrivals on this connection: a label not open at a peer that cannot read
    /// it is walked at most once per arrival (`shared_unopened`).
    pub(crate) arrivals: u64,
    /// A filter arrived since the sync keys were last tested: a peer that cannot read tests
    /// nothing, so its filter gaining a head's sync key is found by this side testing every
    /// served head's at each arrival, not only the pending set's.
    sync_due: bool,
    pages: Option<Pages>,
    members: BTreeMap<LabelId, Member>,
    /// Hits already offered and answered (a refused one is not sent again until re-marked).
    offered: BTreeSet<[u8; 32]>,
    /// Sync IDs a ByRole was sent for (none again until re-marked).
    by_role: BTreeSet<LabelId>,
    asked: BTreeMap<u32, Asked>,
    /// This connection's Hit table (the peer's Hit → credential), built at the first Hit, dropped
    /// when what this node holds changes.
    table: Option<HashMap<[u8; 32], Cred>>,
    /// Sync IDs this side tested a key actor's static entry of against the peer's filter and
    /// found absent: a link's sharer refused it (`static_entry_refused`).
    static_missing: BTreeSet<LabelId>,
    /// The last whole filter held this node's read credentials (the peer proved an actor known
    /// here then): when that differs from now, the next generation is whole.
    read_out: bool,
    /// Tests of the pending set run and generations sent on this connection (tests count them).
    work: (u64, u64),
    /// A Deposit item of this side is unanswered (one at a time per connection).
    deposit_out: bool,
    /// Deposits the peer refused (14) on this connection: not offered here again until what this
    /// node holds changes or the peer's next filter arrives (what it holds changed).
    deposits_refused: BTreeSet<(LabelId, BlobId)>,
}

/// Ids this module draws: never one the session's own requests use (top bit set).
const ID_BASE: u32 = osis_proto::msg::NODE_IDS;
/// The id of a dialer's `NoRecord` (`Records::send_resume`).
pub(super) const NO_RECORD_ID: u32 = ID_BASE;

impl Shared {
    fn bare(by_listener: bool) -> Shared {
        Shared {
            r: [0; 32],
            by_listener,
            key: [0; 32],
            dialer: [0; 32],
            listener: [0; 32],
            next_id: 0,
            record: None,
            digest: None,
            digest_read: true,
            agreed: true,
            peer_list: BTreeSet::new(),
            pending: ConnRecord::new([0; 16], 0),
            acked_pos: 0,
            test_due: false,
            sent_gen: 0,
            acked_gen: 0,
            started: false,
            in_flight: false,
            retry_at: None,
            again: false,
            whole_n: 0,
            added: 0,
            f: BEACON_P as u8,
            sent_pos: 0,
            peer: None,
            arrived: false,
            arrivals: 0,
            sync_due: false,
            pages: None,
            members: BTreeMap::new(),
            offered: BTreeSet::new(),
            by_role: BTreeSet::new(),
            asked: BTreeMap::new(),
            table: None,
            static_missing: BTreeSet::new(),
            read_out: false,
            work: (0, 0),
            deposit_out: false,
            deposits_refused: BTreeSet::new(),
        }
    }

    /// Whether L is a member here.
    pub(crate) fn has(&self, l: &LabelId) -> bool {
        self.members.contains_key(l)
    }

    /// Whether `l` is a member not being ended: one that gets what no position bounds (its
    /// relay-only entries).
    pub(crate) fn live(&self, l: &LabelId) -> bool {
        self.members.get(l).is_some_and(|m| m.until.is_none())
    }

    /// Whether S is empty here.
    pub(crate) fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The members of S here.
    pub(crate) fn member_ids(&self) -> impl Iterator<Item = LabelId> + '_ {
        self.members.keys().copied()
    }

    fn side(&self, by_listener: bool) -> Side<'_> {
        (by_listener, &self.key, &self.dialer, &self.listener)
    }
    fn next(&mut self) -> u32 {
        self.next_id = self.next_id.wrapping_add(1);
        ID_BASE | (self.next_id & (ID_BASE - 1))
    }
}

impl SyncEngine {
    /// Whether L is a member of `conn`'s shared set.
    pub(crate) fn shared_member(&self, conn: ConnId, l: &LabelId) -> bool {
        self.records.shared.get(&conn).is_some_and(|s| s.members.contains_key(l))
    }

    /// Whether a member of `conn`'s set was opened by a sync key, a claim or a dialer's proof of a
    /// sync key: one side of the connection cannot read it.
    pub(crate) fn shared_by_key(&self, conn: ConnId, l: &LabelId) -> bool {
        self.records.shared.get(&conn).and_then(|s| s.members.get(l)).is_some_and(|m| by_key(m.class))
    }

    /// Whether a member of `conn`'s set was opened by read credentials: its peer reads it (no
    /// source of it, spec/sync.md §10).
    pub(crate) fn shared_reads(&self, conn: ConnId, l: &LabelId) -> bool {
        self.records.shared.get(&conn).and_then(|s| s.members.get(l)).is_some_and(|m| m.class == READ)
    }

    /// Whether `l`, a label this node syncs, is open in the set of `conn`, a connection this node
    /// dialed to a node the label lists (`label.0`, the configured hosts): read as such a node is
    /// (`stream_apply`), its entries present there by its key, whatever opened it (this node's
    /// sync-key or claim Hit at a peer that cannot read it, a static entry, or read credentials
    /// at a node that reads it too). A sync ID this node keeps unread is never read so.
    pub(crate) fn read_as_host(&self, conn: ConnId, l: &LabelId) -> bool {
        self.conns.get(&conn).is_some_and(|c| c.listed().is_some() && c.labels.contains_key(l)) && self.records.shared.get(&conn).is_some_and(|s| s.members.contains_key(l))
    }

    /// The open of `l` on `conn`, at a peer that cannot read it, ended by its head moving past the
    /// credential it was made by (spec/sync.md §5): closed with a Lost (`shared_close`), it
    /// tests the new head's credential.
    pub(super) fn shared_end(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<Action>) -> Result<()> {
        if self.shared_member(conn, &l) {
            let stopped = self.shared_stopped(conn, &l)?;
            self.shared_close(conn, &l, super::stream::Stop::Here, out)?;
            self.shared_send_lost(conn, vec![(l, stopped)], out)?;
        }
        self.shared_retest(conn, out)
    }

    /// Every label on `conn` is tested against the peer's filter now (a label started there, a
    /// step the walk found shown).
    pub(super) fn shared_retest(&mut self, conn: ConnId, out: &mut Vec<Action>) -> Result<()> {
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        s.sync_due = true;
        s.test_due = true;
        self.shared_test(conn, out)
    }

    /// Sync IDs of the peer's `Members` pages kept on `conn` while its list is read (tests).
    pub fn shared_listed(&self, conn: ConnId) -> usize {
        self.records.shared.get(&conn).map_or(0, |s| s.peer_list.len())
    }

    /// Tests of the pending set run and filter generations sent on `conn` (tests count them).
    pub fn shared_work(&self, conn: ConnId) -> (u64, u64) {
        self.records.shared.get(&conn).map_or((0, 0), |s| s.work)
    }

    /// Sync IDs open on `conn` by its shared set (tests).
    pub fn shared_members(&self, conn: ConnId) -> BTreeSet<LabelId> {
        self.records.shared.get(&conn).map(|s| s.members.keys().copied().collect()).unwrap_or_default()
    }

    /// The cursor a `Lost` for `l` on `conn` would name now (`shared_stopped`; tests).
    #[doc(hidden)]
    pub fn shared_lost_cursor(&mut self, conn: ConnId, l: &LabelId) -> Result<Option<Vec<u8>>> {
        self.shared_stopped(conn, l)
    }

    /// Puts `l` in connection `conn`'s shared set directly (tests whose subject is what a
    /// member gets, not how one is found).
    #[doc(hidden)]
    pub fn shared_admit(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<Action>) -> Result<()> {
        let s = self.records.shared.entry(conn).or_insert_with(|| Shared::bare(self.conns.get(&conn).is_none_or(|c| c.dial.is_none())));
        s.members.insert(l, Member { class: JUDGED, beacon: None, until: None });
        self.shared_open(conn, l, JUDGED, None, out)
    }

    /// Closes member `l` of `conn` here and tells the peer (tests: a close crossing the peer's).
    #[doc(hidden)]
    pub fn shared_drop(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<Action>) -> Result<()> {
        self.shared_close(conn, &l, super::stream::Stop::Here, out)?;
        self.shared_lost_send(conn, l, out)
    }

    /// Whether what `conn` can open is known: its shared set saw the peer's filter and nothing it
    /// asked is unanswered (a host, a peer with no proofs yet counts as still finding).
    pub(crate) fn shared_settled(&self, conn: ConnId) -> bool {
        self.records.shared.get(&conn).is_some_and(|s| s.agreed && s.arrived && !s.test_due && !s.in_flight && s.pending.offers_unanswered == 0)
    }

    /// Whether `conn`'s stream may pull: the two records agree (no record: at once).
    pub(crate) fn shared_agreed(&self, conn: ConnId) -> bool {
        self.records.shared.get(&conn).is_some_and(|s| s.agreed)
    }

    /// Whether the sharer node of the link `l` is followed through showed a filter without this
    /// node's static entry of `l`: it does not list the link's key (spec/sync.md §5). Only the
    /// sharer's filter says so: any other peer (this account's other node, a peer holding no K)
    /// may lack the entry for holding nothing of `l`.
    pub(crate) fn shared_static_missing(&self, l: &LabelId) -> bool {
        let Some(lp) = self.state.hints.get(l).filter(|h| h.via.is_some()).and_then(|h| self.state.link_peers.get(&h.thing)) else { return false };
        self.records.shared.iter().any(|(conn, s)| {
            s.static_missing.contains(l) && !s.members.contains_key(l) && self.conns.get(conn).is_some_and(|c| lp.peers.iter().any(|a| Some(a.key) == c.key()))
        })
    }

    /// The shared set of `conn` starts, whichever side dialed, under the record's `r` or, with no
    /// record, the connection's own pair key (spec/sync.md §10): a filter goes out, holding this
    /// node's read credentials only if the peer proved a known actor (issues/net-shared-set.md,
    /// Words), and the head credentials of the sync IDs it keeps unread always. With a record (`bound`: its
    /// ID, and whether the session proved other actors than the record names) S, `acked_pos` and
    /// both filters are restored, the digest of S goes first, and S is re-judged: what changed
    /// goes, not what the record proves was sent.
    pub(super) fn shared_begin(&mut self, conn: ConnId, bound: Option<(RecordId, bool)>, out: &mut Vec<Action>) -> Result<()> {
        if self.records.shared.contains_key(&conn) {
            return Ok(());
        }
        let Some((binding, by_listener)) = self.conns.get(&conn).map(|c| (c.binding, c.dial.is_none())) else { return Ok(()) };
        let Some((dialer, listener, key)) = binding else { return Ok(()) };
        let Some((id, actors_changed)) = bound else {
            let r = *osis_crypto::kdf::pair_key(&dialer, &listener).expose();
            let s = Shared { r, key, dialer, listener, ..Shared::bare(by_listener) };
            self.records.shared.insert(conn, s);
            return self.shared_send_generation(conn, out);
        };
        let (rec, members, rows) = self.engine.run(|tx| {
            if actors_changed {
                tx.txn.record_pending_all(&id)?;
            }
            let rec = tx.txn.record(&id)?;
            Ok((rec, tx.txn.record_members(&id)?, tx.txn.record_peer_filter(&id)?))
        })?;
        let Some(rec) = rec else { return Ok(()) };
        let peer = (rec.peer.generation > 0).then(|| {
            let hi = 1u64.checked_shl(u32::from(rec.peer.f)).unwrap_or(u64::MAX);
            let mut values: Vec<u64> = rows.iter().flat_map(|g| decode_gcs(g, 0, hi).unwrap_or_default()).collect();
            values.sort_unstable();
            PeerFilter { generation: rec.peer.generation, f: rec.peer.f, values, whole: rec.peer.whole as usize, added: rec.peer.added as usize }
        });
        let digest = osis_crypto::kdf::members_digest(&rec.r, members.iter().map(|(l, _)| &l.0));
        let mut s = Shared {
            r: rec.r,
            key,
            dialer,
            listener,
            // the record's last whole filter as sent: re-sent whole if the peer's known-ness moved
            read_out: true,
            record: Some(id),
            digest: Some(digest),
            digest_read: false,
            agreed: false,
            pending: ConnRecord::new(id, rec.acked_pos),
            acked_pos: rec.acked_pos,
            sent_gen: rec.own.generation,
            acked_gen: rec.own.acked,
            // nothing the peer acknowledged to build on, the last generation sent not
            // acknowledged (its width and counts are not the ones the peer holds), or other
            // actors: a whole filter
            again: rec.own.acked == 0 || rec.own.acked != rec.own.generation || actors_changed,
            whole_n: rec.own.whole as usize,
            added: rec.own.added as usize,
            f: if rec.own.generation == 0 { BEACON_P as u8 } else { rec.own.f },
            sent_pos: rec.acked_pos,
            peer,
            ..Shared::bare(by_listener)
        };
        s.members = members.iter().map(|(l, m)| (*l, Member { class: m.class, beacon: m.beacon, until: m.until })).collect();
        let restored = !s.members.is_empty();
        self.records.shared.insert(conn, s);
        for (l, _) in &members {
            self.member_unread_there(conn, *l, true, out)?;
        }
        // a sync ID it keeps unread is pulled from the start (`stream_join`), its Deletes taken
        let unread = self.unread_heads()?;
        for (l, _) in members.iter().filter(|(l, _)| unread.contains_key(l)) {
            self.hub_down(conn, osis_host::Down::Open(*l), out);
        }
        let pulled: Vec<(LabelId, osis_store::Member)> = members.iter().map(|(l, m)| if unread.contains_key(l) { (*l, osis_store::Member { at: At::Join(None), ..m.clone() }) } else { (*l, m.clone()) }).collect();
        self.stream_bind(conn, id, rec.cursor, &pulled, &members);
        self.unread_restream()?;
        if restored {
            self.pass_due = true;
            self.suspects_due = true;
        }
        self.shared_send(conn, Message::Digest { digest }, out)?;
        self.shared_rejudge(conn, out)?;
        self.shared_send_generation(conn, out)
    }

    /// Every connection re-judged after a change of what this node holds, and the additions and
    /// tests it makes due (issues/net-shared-set.md, Opens and Testing).
    pub(super) fn shared_changed(&mut self, out: &mut Vec<Action>) -> Result<()> {
        if !std::mem::take(&mut self.shared_dirty) {
            return Ok(());
        }
        self.records_end()?;
        let conns: Vec<ConnId> = self.records.shared.keys().copied().collect();
        for conn in conns {
            let Some(s) = self.records.shared.get_mut(&conn) else { continue };
            s.table = None;
            s.test_due = true;
            s.deposits_refused.clear();
            self.shared_rejudge(conn, out)?;
            self.shared_send_generation(conn, out)?;
            self.shared_test(conn, out)?;
        }
        Ok(())
    }

    /// Whether this side's actors for `conn` are still known here: only key actors counted, read
    /// now, never from the proof exchange's time (spec/sync.md §10).
    fn shared_known(&self, conn: ConnId) -> bool {
        self.connection_proven(conn).is_some_and(|p| !super::records::counted_actors(&self.engine, p).is_empty())
    }

    /// `conn`'s credentials admissible now (issues/net-shared-set.md, Admissible), of the `only`
    /// labels when given, of the kinds `which` asks. A label J judges departed has none: a
    /// departure the peer's actors are covered past is not recognised yet (a rotation covering it
    /// reopens by a later credential). A sync ID this node keeps unread has its head's (J is
    /// unknown there: no roster is held).
    fn shared_creds(&mut self, conn: ConnId, only: Option<&BTreeSet<LabelId>>, which: Which) -> Result<Vec<Cred>> {
        let Some(r) = self.records.shared.get(&conn).map(|s| s.r) else { return Ok(Vec::new()) };
        let Some(actors) = self.connection_proven(conn).map(Proven::all) else { return Ok(Vec::new()) };
        let wanted = |l: &LabelId| only.is_none_or(|o| o.contains(l));
        let things = if which.read || which.sync { self.things() } else { BTreeMap::new() };
        let unread = if which.unread { self.unread_heads()? } else { std::sync::Arc::default() };
        let labels: Vec<LabelId> = things.keys().chain(unread.keys().filter(|l| !things.contains_key(l))).filter(|l| wanted(l)).copied().collect();
        let mut creds = self.credentials(&labels)?;
        if !which.read {
            creds.retain(|l, _| !things.contains_key(l));
        }
        if which.sync {
            for (l, (k, _)) in self.peer_creds(conn, &labels) {
                creds.entry(l).or_default().push(Credential::SyncKey(k));
            }
        }
        // proof credentials by sync key, beside the rest
        let by_listener = self.records.shared.get(&conn).is_some_and(|s| s.by_listener);
        let mut proofs: Vec<(LabelId, [u8; 32])> = Vec::new();
        if which.accepts && by_listener {
            for (g, l) in things.iter().filter(|(l, _)| wanted(l) && self.synced.ids.contains(l)).map(|(l, g)| (*g, *l)).collect::<Vec<_>>() {
                if let Some(step) = self.newest_step(&g, &l) {
                    proofs.push((l, step.keys.sync.to_bytes()));
                }
            }
        }
        if which.proves && !by_listener {
            proofs.extend(self.shared_proof_keys(conn, only)?.into_iter().map(|(l, k)| (l, k.verifying_key().to_bytes())));
        }
        let mut judge = self.engine.core.judge(actors);
        let mut out = Vec::new();
        for (l, cs) in creds {
            if let Some(t) = things.get(&l) {
                if judge.of(t) == super::credentials::Judgment::Departed {
                    continue;
                }
            } else if !unread.contains_key(&l) {
                continue;
            }
            for c in cs {
                // a sync ID read here lists the sync key only when asked (`Which::sync`)
                let class = match c {
                    Credential::ReadSecret(_) => READ,
                    Credential::StaticEntry(_) => STATIC,
                    Credential::SyncKey(_) => SYNC,
                    Credential::DepositKey(_) => DEPOSIT,
                };
                let value = c.match_value();
                out.push(Cred { label: l, class, value, key: value, beacon: beacon(&value, &l.0, &r) });
            }
        }
        for (l, key) in proofs {
            if things.get(&l).is_some_and(|t| judge.of(t) == super::credentials::Judgment::Departed) {
                continue;
            }
            let value = osis_crypto::kdf::sync_proof(&key);
            out.push(Cred { label: l, class: PROOF, value, key, beacon: beacon(&value, &l.0, &r) });
        }
        Ok(out)
    }

    /// The labels changed past `pos` and the highest position among them.
    fn shared_changes_after(&mut self, pos: u64) -> Result<(BTreeSet<LabelId>, u64)> {
        let rows = self.engine.run(|tx| Ok(tx.txn.changed_after(pos, usize::MAX)?))?;
        let top = rows.last().map_or(pos, |(p, _)| *p);
        Ok((rows.into_iter().map(|(_, l)| l).collect(), top))
    }

    fn shared_send_generation(&mut self, conn: ConnId, out: &mut Vec<Action>) -> Result<()> {
        let known = self.shared_known(conn);
        let Some(s) = self.records.shared.get(&conn) else { return Ok(()) };
        if s.in_flight || s.retry_at.is_some() {
            return Ok(());
        }
        // a whole filter, also after a refused generation (`shared_retry`) or when the peer's
        // actors became known here or stopped being (the read credentials join or leave it); a
        // connection's first generation goes even with no additions, so the peer's test of its
        // pending set runs
        let first = s.sent_gen == 0 || s.again || s.read_out != known;
        // what reads here goes only to a known actor; what is kept unread to every connection
        let which = Which { read: known, unread: true, sync: false, accepts: known, proves: false };
        let opening = !s.started;
        let after = if first { 0 } else { s.sent_pos };
        let (labels, top) = self.shared_changes_after(after)?;
        if !first && !opening && labels.is_empty() {
            return Ok(());
        }
        let Some(s) = self.records.shared.get(&conn) else { return Ok(()) };
        let (f, whole_n, added) = (s.f, s.whole_n, s.added);
        let mut creds = if first { self.shared_creds(conn, None, which)? } else { self.shared_creds(conn, Some(&labels), which)? };
        // a whole filter when its additions pass the entries in the last one (issues/net-shared-set.md, Staleness)
        let whole = first || added + creds.len() > whole_n;
        if whole && !first {
            creds = self.shared_creds(conn, None, which)?;
        }
        let n = creds.len();
        let width = if whole { filter_width(n) } else { f };
        let mut values: Vec<u64> = creds.iter().map(|c| beacon_value(&c.beacon, width)).collect();
        values.sort_unstable();
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        let base = (!whole).then_some(s.acked_gen);
        s.sent_gen += 1;
        let generation = s.sent_gen;
        s.again = false;
        s.started = true;
        s.work.1 += 1;
        if whole {
            s.read_out = known;
            s.whole_n = n;
            s.added = 0;
            s.f = width;
        } else {
            s.added += n;
        }
        s.in_flight = true;
        s.sent_pos = top;
        let mut msgs = Vec::new();
        for Page { lo, hi, gcs, more } in pages(&values, width, PAGE_BYTES) {
            let id = s.next();
            s.asked.insert(id, Asked::Beacons { generation, pos: top, last: !more });
            msgs.push(Message::Beacons { id, generation, base, f: width, lo, hi, gcs, more });
        }
        let (record, own) = (s.record, Filter { generation, acked: s.acked_gen, f: s.f, whole: s.whole_n as u64, added: s.added as u64 });
        self.stats.beacons_sent += n as u64;
        self.stats.filters_sent += 1;
        if let Some(id) = record {
            self.engine.run(|tx| Ok(tx.txn.record_set_own(&id, own)?))?;
        }
        for m in msgs {
            self.shared_send(conn, m, out)?;
        }
        Ok(())
    }

    /// Sends again the filters whose last generation was refused, once their time came.
    pub(super) fn shared_retry(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let now = self.now();
        let due: Vec<ConnId> = self.records.shared.iter().filter(|(_, s)| s.retry_at.is_some_and(|t| t <= now)).map(|(c, _)| *c).collect();
        for conn in due {
            if let Some(s) = self.records.shared.get_mut(&conn) {
                s.retry_at = None;
            }
            self.shared_send_generation(conn, out)?;
        }
        Ok(())
    }

    /// When a refused filter goes again (`next_wake`).
    pub(super) fn shared_wake(&self) -> Option<u64> {
        self.records.shared.values().filter_map(|s| s.retry_at).min()
    }

    pub(super) fn shared_send(&mut self, conn: ConnId, m: Message, out: &mut Vec<Action>) -> Result<()> {
        self.hub_down(conn, osis_host::Down::Message(Box::new(m)), out);
        Ok(())
    }

    /// A request of this node to `conn`'s peer outside the shared set's own exchange (Stranded,
    /// Suspect), with an id of the set's: answered Ok, nothing waits on the answer. None goes
    /// on a connection keeping no shared set.
    pub(super) fn shared_request(&mut self, conn: ConnId, make: impl FnOnce(u32) -> Message, out: &mut Vec<Action>) -> Result<()> {
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        let id = s.next();
        self.shared_send(conn, make(id), out)
    }

    /// A shared-set message from `conn`'s peer. A dialer's NoRecord starts the connection's set
    /// whoever it proved (what its filter holds is `shared_send_generation`'s); a connection with
    /// no shared set answers refused (a request) or ignores it (an answer).
    pub(super) fn shared_message(&mut self, conn: ConnId, m: Message, out: &mut Vec<Action>) -> Result<()> {
        if !self.records.shared.contains_key(&conn) {
            if matches!(m, Message::NoRecord { .. }) && self.conns.get(&conn).is_some_and(|c| c.dial.is_none()) {
                self.shared_begin(conn, None, out)?;
                return self.shared_message(conn, m, out);
            }
            if m.is_request() {
                self.shared_send(conn, Message::Error { id: m.id(), code: Code::NOT_ADMITTED }, out)?;
            }
            return Ok(());
        }
        match m {
            Message::NoRecord { id } => self.shared_send(conn, Message::Shared { id, codes: vec![(Code::OK, None, None)] }, out),
            Message::Digest { digest } => self.shared_digest(conn, digest, out),
            Message::Members { labels, more } => self.shared_peer_members(conn, labels, more, out),
            Message::Beacons { id, generation, base, f, lo, hi, gcs, more } => self.shared_beacons(conn, id, (generation, base, f, lo, hi), &gcs, more, out),
            Message::Offer { id, items } => self.shared_offer(conn, id, items, out),
            Message::Lost { id, items } => self.shared_lost(conn, id, items, out),
            Message::Shared { id, .. } | Message::Error { id, .. } if id == NO_RECORD_ID => Ok(()),
            Message::Shared { id, codes } => self.shared_reply(conn, id, codes, out),
            // an Error answers what it names as a refusal would (a request refused whole)
            Message::Error { id, code } => {
                let code = if code == Code::OK { Code::REFUSED } else { code };
                self.shared_reply(conn, id, vec![(code, None, None)], out)
            }
            _ => Ok(()),
        }
    }

    /// Closes a connection whose peer broke a filter rule (spec/wire.md §11.2: Error 2 and close).
    fn shared_kill(&mut self, conn: ConnId, id: u32, what: &str, out: &mut Vec<Action>) -> Result<()> {
        self.diag(format!("closing peer: {what}"));
        self.shared_send(conn, Message::Error { id, code: Code::MALFORMED }, out)?;
        self.close(conn, out);
        Ok(())
    }

    fn shared_beacons(&mut self, conn: ConnId, id: u32, (generation, base, f, lo, hi): (u64, Option<u64>, u8, u64, u64), gcs: &[u8], more: bool, out: &mut Vec<Action>) -> Result<()> {
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        // a whole filter replaces, additions build on the one held: a base not held is answered 13
        if base.is_some() && s.peer.as_ref().map(|p| p.generation) != base {
            s.pages = None;
            return self.shared_send(conn, Message::Shared { id, codes: vec![(Code::UNKNOWN_LABEL, None, None)] }, out);
        }
        let space = if f >= 64 { None } else { Some(1u64 << f) };
        let ordered = lo < hi && space.is_none_or(|e| hi <= e);
        let continues = s.pages.as_ref().is_some_and(|p| p.generation == generation && p.f == f && p.base == base && p.next_lo == lo);
        let starts = lo == 0;
        if !ordered || !(continues || starts) {
            return self.shared_kill(conn, id, "filter page out of order", out);
        }
        let Ok(values) = decode_gcs(gcs, lo, hi) else {
            return self.shared_kill(conn, id, "filter page does not decode", out);
        };
        let held = if continues { s.pages.as_ref().map_or(0, |p| p.values.len()) } else { 0 };
        if held + values.len() > MAX_FILTER_ENTRIES {
            return self.shared_kill(conn, id, "filter too large", out);
        }
        if !continues {
            s.pages = Some(Pages { generation, base, f, next_lo: lo, values: Vec::new() });
        }
        let Some(p) = s.pages.as_mut() else { return Ok(()) };
        p.values.extend(values);
        p.next_lo = hi;
        if more {
            return self.shared_send(conn, Message::Shared { id, codes: vec![(Code::OK, None, None)] }, out);
        }
        let Some(p) = s.pages.take() else { return Ok(()) };
        if space.is_some_and(|e| p.next_lo != e) {
            return self.shared_kill(conn, id, "filter does not reach the end of the space", out);
        }
        let mut values = p.values;
        values.sort_unstable();
        let row = encode_gcs(&values, 0);
        let fin = match (p.base, s.peer.take()) {
            (None, _) if f == filter_width(values.len()) => Some(PeerFilter { generation, f, whole: values.len(), added: 0, values }),
            (Some(_), Some(mut held)) if f == held.f && held.added + values.len() <= held.whole => {
                held.added += values.len();
                held.values.extend(values);
                held.values.sort_unstable();
                held.generation = generation;
                Some(held)
            }
            _ => None,
        };
        let Some(fin) = fin else {
            return self.shared_kill(conn, id, "filter width or density", out);
        };
        let stored = Filter { generation, acked: generation, f: fin.f, whole: fin.whole as u64, added: fin.added as u64 };
        let whole = p.base.is_none();
        s.peer = Some(fin);
        s.arrived = true;
        s.arrivals += 1;
        s.sync_due = true;
        s.test_due = true;
        // what the peer refused it judged by what it held then: its holdings moved
        s.deposits_refused.clear();
        let record = s.record;
        self.stats.filters_received += 1;
        if let Some(c) = self.conns.get_mut(&conn) {
            c.req.refused.clear();
        }
        // the peer's filter is the record's: kept so a reconnect sends additions only
        if let Some(rid) = record {
            self.engine.run(|tx| Ok(tx.txn.record_put_peer_filter(&rid, whole, stored, row)?))?;
        }
        self.shared_send(conn, Message::Shared { id, codes: vec![(Code::OK, None, None)] }, out)?;
        self.shared_test(conn, out)
    }

    /// Tests the pending set against the peer's filter (issues/net-shared-set.md, Testing), when
    /// due, after a filter, and with no Offer of this side unanswered.
    fn shared_test(&mut self, conn: ConnId, out: &mut Vec<Action>) -> Result<()> {
        let Some(s) = self.records.shared.get(&conn) else { return Ok(()) };
        // no Offer before the peer's digest is read (issues/net-reconnect.md, Agreement)
        if !s.test_due || s.peer.is_none() || !s.digest_read || s.pending.offers_unanswered > 0 {
            return Ok(());
        }
        let (acked, sync_due) = (s.acked_pos, s.sync_due);
        let (labels, top) = self.shared_changes_after(acked)?;
        let mut creds = self.shared_creds(conn, Some(&labels), TESTED)?;
        if sync_due {
            // a member is skipped below: no credential is built for it
            let member = |l: &LabelId| self.records.shared.get(&conn).is_some_and(|s| s.members.contains_key(l));
            let rest: BTreeSet<LabelId> = self.conns.get(&conn).map(|c| c.labels.keys().filter(|l| !labels.contains(l) && !member(l)).copied().collect()).unwrap_or_default();
            // and a link's key actor's static entry, which only the peer's filter gaining it
            // shows (a hint's label is pending here once)
            let via: BTreeSet<LabelId> = rest.iter().filter(|l| self.state.hints.get(l).is_some_and(|h| h.via.is_some())).copied().collect();
            creds.extend(self.shared_creds(conn, Some(&rest), Which { read: !via.is_empty(), unread: false, sync: true, accepts: false, proves: false })?.into_iter().filter(|c| c.class == SYNC || (c.class == STATIC && via.contains(&c.label))));
        }
        let signing = self.peer_creds(conn, &creds.iter().filter(|c| c.class == SYNC).map(|c| c.label).collect::<Vec<_>>());
        // a dialer proves the sync secret of each sync ID it keeps unread whose head's sync key
        // it derives, at each arrival too: a reader it dialed serves L to it only so
        // (spec/sync.md §5 Opens)
        let proving = self.shared_proof_keys(conn, None)?;
        if sync_due {
            let rest: BTreeSet<LabelId> = proving.keys().filter(|l| !labels.contains(l)).copied().collect();
            creds.extend(self.shared_creds(conn, Some(&rest), Which { read: false, unread: false, sync: false, accepts: false, proves: true })?);
        }
        // the key actors held: a static entry of one goes as a Static item, signed by it
        let signers: Vec<osis_crypto::SigningSecret> = self.engine.core.key_actors.values().map(|id| id.keys().signing.clone()).collect();
        self.stats.tests += 1;
        self.stats.tested += creds.len() as u64;
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        s.test_due = false;
        s.sync_due = false;
        s.work.0 += 1;
        s.pending.tested = s.pending.tested.max(top);
        let side = (s.by_listener, &s.key, &s.dialer, &s.listener);
        // a sync key's Hit signs the open over the peer's Hello challenge and the listener key
        let peer_challenge = if s.by_listener { s.dialer } else { s.listener };
        let Some(peer) = &s.peer else { return Ok(()) };
        let mut items = Vec::new();
        let mut asked = Vec::new();
        let mut more = false;
        for c in creds {
            if s.members.contains_key(&c.label) {
                continue;
            }
            if peer.values.binary_search(&beacon_value(&c.beacon, peer.f)).is_err() {
                if c.class == STATIC {
                    s.static_missing.insert(c.label);
                }
                continue;
            }
            s.static_missing.remove(&c.label);
            let hit = beacon_hit(&c.value, &c.label.0, &c.beacon, side);
            if s.offered.contains(&hit) {
                continue;
            }
            if items.len() == MAX_SHARED_ITEMS {
                more = true;
                break;
            }
            let proof = match c.class {
                SYNC => match signing.get(&c.label) {
                    Some((_, k)) => Some(osis_crypto::sign_open(k, &c.label, &peer_challenge, &s.key)),
                    None => continue,
                },
                PROOF => match proving.get(&c.label) {
                    Some(k) => Some(osis_crypto::sign_open(k, &c.label, &peer_challenge, &s.key)),
                    None => continue,
                },
                _ => None,
            };
            s.offered.insert(hit);
            let signer = (c.class == STATIC).then(|| signers.iter().find(|k| osis_crypto::static_entry(&c.label, &k.verifying_key()) == c.value)).flatten();
            match signer {
                Some(k) => items.push(OfferItem::Static { hit, key: k.verifying_key().to_bytes(), sig: osis_crypto::sign_open(k, &c.label, &peer_challenge, &s.key) }),
                None => items.push(OfferItem::Hit(hit, proof)),
            }
            asked.push(AskedItem::Hit(c));
        }
        s.test_due = more;
        if items.is_empty() {
            return self.shared_roles(conn, out);
        }
        self.stats.hits_sent += items.len() as u64;
        self.shared_send_offer(conn, items, asked, out)
    }

    /// On a connection this node dialed, the sync IDs it keeps unread (of `only`, when given)
    /// whose head's sync key derives from a sync secret it holds, with that key: the Hit it
    /// proves the secret by (spec/sync.md §10 Offer). None where the peer dialed. O(sync epochs
    /// held + sync IDs kept unread).
    fn shared_proof_keys(&mut self, conn: ConnId, only: Option<&BTreeSet<LabelId>>) -> Result<BTreeMap<LabelId, osis_crypto::SigningSecret>> {
        if self.records.shared.get(&conn).is_none_or(|s| s.by_listener) {
            return Ok(BTreeMap::new());
        }
        let unread = self.unread_heads()?;
        if unread.is_empty() {
            return Ok(BTreeMap::new());
        }
        let mut held: BTreeMap<[u8; 32], osis_crypto::SigningSecret> = BTreeMap::new();
        for e in self.engine.core.ix.secrets.values() {
            for (_, secret) in e.sync.held_newest_first() {
                let k = osis_crypto::label_role_key(osis_crypto::LabelRole::Sync, secret);
                held.insert(k.verifying_key().to_bytes(), k);
            }
        }
        let wanted = |l: &LabelId| only.is_none_or(|o| o.contains(l));
        Ok(unread.iter().filter(|(l, _)| wanted(l)).filter_map(|(l, h)| held.get(&h.step.keys.sync.to_bytes()).map(|k| (*l, k.clone()))).collect())
    }

    fn shared_send_offer(&mut self, conn: ConnId, items: Vec<OfferItem>, asked: Vec<AskedItem>, out: &mut Vec<Action>) -> Result<()> {
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        let id = s.next();
        s.asked.insert(id, Asked::Offer(asked));
        s.pending.offers_unanswered += 1;
        self.shared_send(conn, Message::Offer { id, items }, out)
    }

    /// Sends Behind items on `l`, each a step (none: a hint's, naming none) and its sync key,
    /// signed by that key over the peer's Hello challenge and the listener's key (spec/sync.md §5,
    /// Behind), in one Offer. False where no Offer may go (no shared set, the peer's digest not
    /// read).
    /// `by_static`: the keys are key actors' signing keys, naming no step, each asking by its
    /// static entry.
    pub(super) fn shared_behind(&mut self, conn: ConnId, l: LabelId, asks: Vec<(Option<osis_label::Step>, osis_crypto::SigningSecret)>, by_static: bool, out: &mut Vec<Action>) -> Result<bool> {
        let Some(s) = self.records.shared.get(&conn).filter(|s| s.digest_read) else { return Ok(false) };
        let peer_challenge = if s.by_listener { s.dialer } else { s.listener };
        let mut items = Vec::new();
        let mut asked = Vec::new();
        for (step, key) in asks {
            let sig = osis_crypto::sign_open(&key, &l, &peer_challenge, &s.key);
            let pk = key.verifying_key();
            items.push(OfferItem::Behind { label: l, step: step.as_ref().map(osis_label::Step::id), key: pk.to_bytes(), sig });
            asked.push(if by_static { AskedItem::Static(l, osis_crypto::static_entry(&l, &pk)) } else { AskedItem::Behind(l, step.map(Box::new)) });
        }
        self.stats.behind_sent += items.len() as u64;
        self.shared_send_offer(conn, items, asked, out)?;
        Ok(true)
    }

    /// Whether the peer's latest filter on `conn` shows credential `value` of `l`.
    pub(super) fn shared_shows(&self, conn: ConnId, l: &LabelId, value: &[u8; 32]) -> bool {
        let Some(s) = self.records.shared.get(&conn) else { return false };
        let Some(peer) = &s.peer else { return false };
        peer.values.binary_search(&beacon_value(&beacon(value, &l.0, &s.r), peer.f)).is_ok()
    }

    /// ByRole items once the Hits were answered: for L not open that J judges the peer holds
    /// (issues/net-shared-set.md, Offer). Then the pending position may rise.
    fn shared_roles(&mut self, conn: ConnId, out: &mut Vec<Action>) -> Result<()> {
        let Some(actors) = self.connection_proven(conn).map(Proven::all) else { return Ok(()) };
        let things = self.things();
        let mut judge = self.engine.core.judge(actors);
        let Some(s) = self.records.shared.get(&conn) else { return Ok(()) };
        let wanted: Vec<LabelId> = things.iter().filter(|(l, t)| !s.members.contains_key(l) && !s.by_role.contains(l) && judge.of(t) == super::credentials::Judgment::Holder).map(|(l, _)| *l).take(MAX_SHARED_ITEMS).collect();
        if !wanted.is_empty() {
            let set: BTreeSet<LabelId> = wanted.iter().copied().collect();
            let creds = self.shared_creds(conn, Some(&set), TESTED)?;
            let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
            let side = (s.by_listener, &s.key, &s.dialer, &s.listener);
            let mut items = Vec::new();
            let mut asked = Vec::new();
            for l in wanted {
                let hits: Vec<[u8; 32]> = creds.iter().filter(|c| c.label == l && c.class != SYNC && c.class != PROOF).take(osis_proto::msg::MAX_BYROLE_HITS).map(|c| beacon_hit(&c.value, &c.label.0, &c.beacon, side)).collect();
                if hits.is_empty() {
                    continue;
                }
                s.by_role.insert(l);
                items.push(OfferItem::ByRole(l, hits));
                asked.push(AskedItem::ByRole(l));
            }
            if !items.is_empty() {
                self.stats.by_role_sent += items.len() as u64;
                return self.shared_send_offer(conn, items, asked, out);
            }
        }
        self.shared_rise(conn)?;
        self.shared_unopened(conn, out)
    }

    /// The peer's latest filter was tested and every Offer of it answered: each label on this
    /// connection to a peer that cannot read it, not open there, waiting for no Register, is walked, once per filter
    /// arrival (issues/net-one-peer.md 3h2, Stale head): the credentials of its recorded steps,
    /// deepest first, then its held sync keys (`walk_candidates`), but the one this arrival
    /// tested, against the same filter; the first shown is Hit, none shown strands it holding no
    /// credential of the newest step known (`strands`), else asks by a Behind item or registers
    /// the recorded path (`walked`). Every move of a peer's head changes its
    /// filter, so an arrival follows each; one still waiting `resync_ms` after its walk (a Hit
    /// refused, a registration ended, the filter unchanged) is tested and walked again
    /// (`timers`). O(labels on `conn`), and O(steps + sync epochs held) per label walked.
    fn shared_unopened(&mut self, conn: ConnId, out: &mut Vec<Action>) -> Result<()> {
        let Some(s) = self.records.shared.get(&conn).filter(|s| s.peer.is_some() && !s.test_due && s.pending.offers_unanswered == 0) else { return Ok(()) };
        let arrival = s.arrivals;
        let Some(c) = self.conns.get(&conn).filter(|c| c.listed().is_some()) else { return Ok(()) };
        let unopened: Vec<LabelId> = c.labels.iter().filter(|(l, x)| x.phase.is_testing() && x.registering.is_none() && c.req.walked.get(l) != Some(&arrival)).map(|(l, _)| *l).collect();
        if unopened.is_empty() {
            return Ok(());
        }
        let tested = self.peer_creds(conn, &unopened);
        let now = self.now();
        for l in unopened {
            if let Some(c) = self.conns.get_mut(&conn) {
                c.req.walked.insert(l, arrival);
                // walked again `resync_ms` on if still waiting (`timers`)
                if let Some(x) = c.labels.get_mut(&l) {
                    x.last_sync = now;
                }
            }
            let refused = |s: &Self, k: &[u8; 32]| s.conns.get(&conn).is_some_and(|c| c.req.refused.contains(&(l, *k)));
            let candidates: Vec<_> = self.walk_candidates(conn, l, tested.get(&l).map(|x| x.0))?.into_iter().filter(|(_, k)| !refused(self, &k.verifying_key().to_bytes())).collect();
            let Some(s) = self.records.shared.get(&conn) else { return Ok(()) };
            let Some(peer) = &s.peer else { return Ok(()) };
            let shown = candidates.into_iter().find(|(_, k)| peer.values.binary_search(&beacon_value(&beacon(&k.verifying_key().to_bytes(), &l.0, &s.r), peer.f)).is_ok());
            // none shown and no credential of the newest step known held: stranded
            if shown.is_none() && self.strands(conn, l, out)? {
                continue;
            }
            // the peer holds L at the newest recorded step (its path registered, the filter since
            // then tested) and shows none of this node's credentials of it (claim keys of a step
            // whose claim set is not held, say): it holds none the peer takes, stranded
            // (spec/permissions.md §4)
            let resync = self.cfg.resync_ms;
            if shown.is_none() && self.conns.get(&conn).and_then(|c| c.req.registered.get(&l)).is_some_and(|(a, t)| *a != arrival || now >= t.saturating_add(resync)) {
                if let Some(g) = self.label_at(conn, &l).map(|x| x.group) {
                    self.fail(conn, l);
                    self.stranded(conn, g, l, out)?;
                }
                continue;
            }
            self.walked(conn, l, shown, out)?;
        }
        Ok(())
    }

    /// `acked_pos` rises to `min(ack, tested)` once no Offer is unanswered and no test is due.
    fn shared_rise(&mut self, conn: ConnId) -> Result<()> {
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        if s.test_due {
            return Ok(());
        }
        let Some(pos) = s.pending.rise_to().filter(|p| *p > s.acked_pos) else { return Ok(()) };
        s.acked_pos = pos;
        if let Some(id) = s.record {
            self.engine.run(|tx| Ok(tx.txn.record_rise_acked(&id, pos)?))?;
        }
        Ok(())
    }

    fn shared_table(&mut self, conn: ConnId) -> Result<()> {
        if self.records.shared.get(&conn).is_none_or(|s| s.table.is_some()) {
            return Ok(());
        }
        // what its filter shows: a Hit on a read credential only from a known actor, so a stranger
        // holding a read secret learns nothing of what this node reads (issues/net-shared-set.md,
        // The rule)
        let known = self.shared_known(conn);
        let which = Which { read: known, unread: true, sync: false, accepts: known, proves: false };
        let creds = self.shared_creds(conn, None, which)?;
        self.stats.tables_built += 1;
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        let peer_side = (!s.by_listener, &s.key, &s.dialer, &s.listener);
        let table = creds.into_iter().map(|c| (beacon_hit(&c.value, &c.label.0, &c.beacon, peer_side), c)).collect();
        s.table = Some(table);
        Ok(())
    }

    /// Whether a proven key actor of `conn` is the key actor of static entry `value` on `l` (by
    /// the signing key it proved with, known here or not).
    fn shared_static_proved(&self, conn: ConnId, l: &LabelId, value: &[u8; 32]) -> bool {
        let Some(p) = self.connection_proven(conn) else { return false };
        p.signing.values().any(|k| osis_crypto::VerifyingKey::from_slice(k).is_ok_and(|pk| osis_crypto::static_entry(l, &pk) == *value))
    }

    /// Whether `key` is the key actor of static entry `c` and `sig` its open signature over this
    /// side's Hello challenge and the listener's key (a Static item, spec/sync.md §10).
    fn static_signed(s: &Shared, c: &Cred, key: &[u8; 32], sig: &osis_crypto::Signature) -> bool {
        let challenge = if s.by_listener { &s.listener } else { &s.dialer };
        osis_crypto::VerifyingKey::from_slice(key).is_ok_and(|pk| osis_crypto::static_entry(&c.label, &pk) == c.value && osis_crypto::verify_open(&pk, &c.label, challenge, &s.key, sig).is_ok())
    }

    /// Whether a Hit on credential `c` shows its class's proof (issues/net-shared-set.md, Offer):
    /// a read secret's beacon is its own; a static entry's key actor is a proven actor of this
    /// connection; a sync key's open signature (`proof`) verifies under it over this side's Hello
    /// challenge and the listener's static key; a deposit key is never Hit.
    fn shared_hit_proved(&self, conn: ConnId, s: &Shared, c: &Cred, proof: Option<&osis_crypto::Signature>) -> bool {
        let challenge = if s.by_listener { &s.listener } else { &s.dialer };
        let signed = || proof.is_some_and(|sig| osis_crypto::VerifyingKey::from_slice(&c.key).is_ok_and(|pk| osis_crypto::verify_open(&pk, &c.label, challenge, &s.key, sig).is_ok()));
        match c.class {
            READ => true,
            // a key actor's static entry by its proven actor; a claim of a head kept unread by
            // its open signature (spec/sync.md §5 Opens; a static entry is a hash, which no one
            // signs under)
            STATIC => self.shared_static_proved(conn, &c.label, &c.value) || signed(),
            SYNC | PROOF => signed(),
            _ => false,
        }
    }

    fn shared_offer(&mut self, conn: ConnId, id: u32, items: Vec<OfferItem>, out: &mut Vec<Action>) -> Result<()> {
        self.shared_table(conn)?;
        let things = self.things();
        let Some(actors) = self.connection_proven(conn).map(Proven::all) else { return Ok(()) };
        let served = self.served_labels();
        let mut judge = self.engine.core.judge(actors);
        let mut codes = Vec::with_capacity(items.len());
        let mut opens: Vec<(LabelId, u8, Option<[u8; 32]>)> = Vec::new();
        // Deposit items, judged once the loop's borrows end: (index of the answer, the item)
        let mut deposits = Vec::new();
        // static-entry Hits on sync IDs kept unread: (index of the answer, label, entry), their
        // grant from the hub's store
        let mut unread_grants = Vec::new();
        // Behind items: (index of the answer, label, step, signature), answered from the hub's
        // store
        let mut behinds = Vec::new();
        let Some(s) = self.records.shared.get(&conn) else { return Ok(()) };
        for item in items {
            // a Hit's credential, its proof shown
            let hit = match &item {
                OfferItem::Hit(hit, proof) => s.table.as_ref().and_then(|t| t.get(hit)).filter(|c| self.shared_hit_proved(conn, s, c, proof.as_ref())),
                OfferItem::Static { hit, key, sig } => s.table.as_ref().and_then(|t| t.get(hit)).filter(|c| c.class == STATIC && Self::static_signed(s, c, key, sig)),
                _ => None,
            };
            let answer = match item {
                OfferItem::Hit(..) | OfferItem::Static { .. } => match hit {
                    Some(c) => {
                        let tag = beacon_reply(&c.value, &c.label.0, &c.beacon, s.side(s.by_listener));
                        opens.push((c.label, c.class, Some(c.beacon)));
                        // a key actor's node learns the read secret from the head's box for it
                        let grant = (c.class == STATIC).then(|| served.get(&c.label).and_then(|x| x.grant(&c.value))).flatten().map(Box::new);
                        if c.class == STATIC && !served.contains_key(&c.label) {
                            unread_grants.push((codes.len(), c.label, c.value));
                        }
                        (Code::OK, Some(tag), grant)
                    }
                    _ => (Code::NOT_ADMITTED, None, None),
                },
                // a ByRole names a judged holder: a credential it lists opens only as a reader's
                // or a proved key actor's (a public sync key's beacon proves nothing)
                OfferItem::ByRole(l, hits) => {
                    let listed = hits.iter().filter_map(|h| s.table.as_ref().and_then(|t| t.get(h))).find(|c| c.label == l && (c.class == READ || (c.class == STATIC && self.shared_static_proved(conn, &c.label, &c.value))));
                    let holder = things.get(&l).is_some_and(|t| judge.of(t) == super::credentials::Judgment::Holder);
                    if holder || listed.is_some() {
                        opens.push((l, listed.map_or(JUDGED, |c| c.class), listed.map(|c| c.beacon)));
                        (Code::OK, None, None)
                    } else {
                        (Code::NOT_ADMITTED, None, None)
                    }
                }
                OfferItem::Deposit { label, blob, wrap, sig } => {
                    deposits.push((codes.len(), label, blob, wrap, sig));
                    (Code::NOT_ADMITTED, None, None)
                }
                OfferItem::Behind { label, step, key, sig } => {
                    behinds.push((codes.len(), label, step, key, sig));
                    (Code::NOT_ADMITTED, None, None)
                }
            };
            codes.push(answer);
        }
        drop(judge);
        let (challenge, listener) = (if s.by_listener { s.listener } else { s.dialer }, s.key);
        // the steps one reply holds: Behind answers read no more per Offer (notes/flow-control.md,
        // Hub stall bounds)
        let full = osis_proto::session::REPLY_BUDGET / osis_proto::msg::MAX_STEP_WIRE;
        let mut budget = full;
        for (i, l, step, key, sig) in behinds {
            let answer = match self.unread_behind(&l, step.as_ref(), &key, &sig, &challenge, &listener, &mut budget)? {
                super::unread::BehindAnswer::Unknown => (Code::UNKNOWN_LABEL, None, None),
                super::unread::BehindAnswer::ForNow => (Code::RATE_LIMITED, None, None),
                super::unread::BehindAnswer::Refused => continue,
                super::unread::BehindAnswer::Steps(steps) => {
                    self.stats.behind_answered += 1;
                    (Code::OK, None, Some(Box::new(osis_proto::msg::Grant { entry_box: None, steps })))
                }
                super::unread::BehindAnswer::Grant(g) => (Code::OK, None, Some(g)),
            };
            if let Some(c) = codes.get_mut(i) {
                *c = answer;
            }
        }
        self.stats.behind_steps += (full - budget) as u64;
        for (i, l, entry) in unread_grants {
            let grant = self.unread_grant(&l, &entry)?.map(Box::new);
            if let Some(c) = codes.get_mut(i) {
                c.2 = grant;
            }
        }
        let mut takes = Vec::new();
        for (i, l, blob, wrap, sig) in deposits {
            // at a sync ID this node does not read, a Deposit by the hub's store's rules (held
            // unread, or not held yet)
            let code = if !things.contains_key(&l) {
                self.unread_deposit(l, &blob, wrap, &sig)?
            } else {
                let code = self.shared_deposit_verdict(conn, &served, &things, l, &blob, &wrap, &sig)?;
                if code == Code::OK {
                    takes.push((l, blob, wrap));
                }
                code
            };
            if let Some(c) = codes.get_mut(i) {
                c.0 = code;
            }
        }
        // the hub session takes the tester's Deletes from its reading the answer on: told first
        for (l, _, _) in &opens {
            if self.is_unread(l)? {
                self.hub_down(conn, osis_host::Down::Open(*l), out);
            }
        }
        // the answer first: the tester opens on reading it, so a Pull joining L after it finds L
        // open there (stream.rs)
        self.shared_send(conn, Message::Shared { id, codes }, out)?;
        for (l, class, value) in opens {
            self.shared_open(conn, l, class, value, out)?;
        }
        // a deposit taken goes on as one a host gave would: the inbox's own processing
        for (l, blob, wrap) in takes {
            let blob_id = osis_label::blob_id(&blob);
            if self.state.entries.contains_key(&(l, blob_id)) || self.state.tombs.contains_key(&(l, blob_id)) {
                continue;
            }
            self.log_events_from(super::inbound::Src::Served(conn), l, vec![osis_proto::Event::Added { blob_id, blob: Some(blob), wrap, stamp: None }], out)?;
            self.keep_source(l, blob_id);
            self.stream_crossed(conn, vec![blob_id]);
        }
        Ok(())
    }

    /// The answer to a Deposit item (issues/net-shared-set.md, Deposits): taken (0) when this
    /// side proved to the peer an actor holding L's read role and the signature verifies under
    /// its served head's deposit key; refused for now (5) past the peer budgets; else 14, the
    /// same whether or not L is held here. A blob held or dropped here is answered 0 and changes
    /// nothing.
    #[allow(clippy::too_many_arguments)]
    fn shared_deposit_verdict(&mut self, conn: ConnId, served: &BTreeMap<LabelId, super::serve::ServedLabel>, things: &BTreeMap<LabelId, Tid>, l: LabelId, blob: &[u8], wrap: &[u8; osis_crypto::WRAP_LEN], sig: &osis_crypto::Signature) -> Result<Code> {
        let Some(t) = things.get(&l) else { return Ok(Code::NOT_ADMITTED) };
        // what this side proved on the connection, not what it could prove now
        let mine: Vec<Tid> = self.proved(conn).map(|p| p.iter().copied().collect()).unwrap_or_default();
        if self.engine.core.judge(mine).of(t) != super::credentials::Judgment::Holder {
            return Ok(Code::NOT_ADMITTED);
        }
        let Some(head) = served.get(&l).and_then(|x| x.head()) else { return Ok(Code::NOT_ADMITTED) };
        let blob_id = osis_label::blob_id(blob);
        if osis_label::verify_deposit(&head.keys.deposit, &l, &blob_id, wrap, sig).is_err() {
            return Ok(Code::NOT_ADMITTED);
        }
        // ephemeral and relay-only blobs are never deposited (spec/sync.md §5)
        if !osis_label::Prefix::parse(blob).is_ok_and(|p| p.class() == osis_label::Class::Durable) {
            return Ok(Code::NOT_ADMITTED);
        }
        if self.state.entries.contains_key(&(l, blob_id)) || self.state.tombs.contains_key(&(l, blob_id)) {
            return Ok(Code::OK);
        }
        Ok(if self.charge_deposit(conn, l, blob_id, blob.len() as u64) { Code::OK } else { Code::BUDGET_FULL })
    }

    /// Queued deposits go as Deposit items (spec/sync.md §10, Deposit items), one Offer of them
    /// unanswered per connection, after the peer's digest, never to a peer that refused one:
    /// those for a node keeping the label (`Dest::Host`) on a connection to it, those for an
    /// inbox's nodes (`Dest::Nodes`) where J of the inbox's actor is holder.
    pub(super) fn shared_deposits(&mut self, out: &mut Vec<Action>) -> Result<()> {
        use super::state::{Dest, OutKey};
        let now = self.now();
        // one in flight on a connection gone (dialed or served) goes again
        for o in self.outbox.values_mut() {
            if o.sent.is_some_and(|c| !self.records.shared.contains_key(&c)) {
                o.sent = None;
            }
        }
        let ready: Vec<OutKey> = self.outbox.iter().filter(|(_, o)| o.sent.is_none() && o.after <= now).map(|(k, _)| *k).collect();
        let mut due: Vec<(OutKey, Dest)> = Vec::new();
        for k in ready {
            let Some((to, d)) = self.state.outbox.get(&k).map(|r| (r.to.clone(), r.delivery)) else { continue };
            if d.is_some_and(|d| self.names_label_opening(&d)) {
                continue;
            }
            due.push((k, to));
        }
        if due.is_empty() {
            return Ok(());
        }
        let conns: Vec<ConnId> = self.records.shared.iter().filter(|(_, s)| s.digest_read && !s.deposit_out).map(|(c, _)| *c).collect();
        for conn in conns {
            let Some(actors) = self.connection_proven(conn).map(Proven::all) else { continue };
            let host = self.conns.get(&conn).and_then(super::Conn::key);
            let Some(s) = self.records.shared.get(&conn) else { continue };
            let mut judge = self.engine.core.judge(actors);
            let picked: Vec<OutKey> = due
                .iter()
                .filter(|(k, to)| {
                    self.outbox.get(k).is_some_and(|o| o.sent.is_none())
                        && !s.deposits_refused.contains(&(k.1, k.2))
                        && match to {
                            Dest::Host(a) => host == Some(a.key),
                            Dest::Nodes(a) => judge.of(a) == super::credentials::Judgment::Holder,
                        }
                })
                .map(|(k, _)| *k)
                .take(MAX_SHARED_ITEMS)
                .collect();
            drop(judge);
            if picked.is_empty() {
                continue;
            }
            let (mut items, mut asked) = (Vec::new(), Vec::new());
            for k in picked {
                let Some(r) = self.state.outbox.get(&k) else { continue };
                items.push(OfferItem::Deposit { label: r.label, blob: r.blob.clone(), wrap: r.wrap, sig: r.sig });
                asked.push(AskedItem::Deposit(k.1, k.2));
                if let Some(o) = self.outbox.get_mut(&k) {
                    o.sent = Some(conn);
                }
            }
            if let Some(s) = self.records.shared.get_mut(&conn) {
                s.deposit_out = true;
            }
            self.stats.deposits_sent += items.len() as u64;
            self.shared_send_offer(conn, items, asked, out)?;
        }
        Ok(())
    }

    /// This node's deposits under `l` that source `conn` lacks (spec/sync.md §5, Sending), as
    /// Deposit items of one Offer under the source's head deposit key (`p`): its own role writes
    /// through the outbox (kept until taken, `queue_deposit`), any other body it must hold and
    /// judges valid directly, again `RESEND_MS` after while the source still lacks it.
    pub(super) fn deposit_items(&mut self, conn: ConnId, p: &super::pass::Head, ids: Vec<BlobId>, out: &mut Vec<Action>) -> Result<()> {
        let (Some(d), l) = (p.keys.deposit.clone(), p.l) else { return Ok(()) };
        let Some((host, address)) = self.conns.get(&conn).and_then(|c| c.dial.as_ref()).map(|d| (d.key, d.address.clone())) else { return Ok(()) };
        let now = self.now();
        let (mut items, mut asked, mut queued) = (Vec::new(), Vec::new(), false);
        for id in ids {
            if self.state.outbox.contains_key(&(host, l, id)) {
                continue;
            }
            let Some(e) = self.state.entries.get(&(l, id)).cloned() else { continue };
            let Some(blob) = self.engine.blob(&id)? else { continue };
            // a body only while this node judges it valid, its own too (a demoted writer's
            // write): one it judges invalid no writer promotes and nobody deletes
            // (spec/permissions.md §6), so it would hold the label's deposit budget for good
            if let super::state::Kind::Commit { commit, parts, .. } = &e.kind
                && !e.cert
                && !self.engine.judged_valid(commit, parts)
            {
                continue;
            }
            if !e.cert && matches!(e.kind, super::state::Kind::Commit { .. }) && self.mine(&e) {
                // this node's own write placed for deposit: queued, so neither a crash nor
                // forgetting the label recalls it
                let role = self.role_entry(&e);
                self.queue_deposit(l, std::slice::from_ref(&address), &d, blob, e.wrap, None, role);
                queued = true;
                continue;
            }
            let busy = self.conns.get(&conn).is_some_and(|c| super::in_flight(c, &c.req.sent, (l, id), now));
            if busy || items.len() == MAX_SHARED_ITEMS {
                continue;
            }
            let sig = osis_label::sign_deposit(&d, &l, &id, &e.wrap, self.role_entry(&e));
            items.push(OfferItem::Deposit { label: l, blob, wrap: e.wrap, sig });
            asked.push(AskedItem::Deposit(l, id));
            if let Some(c) = self.conns.get_mut(&conn) {
                c.req.sent.insert((l, id), (now, 0));
            }
        }
        if queued {
            self.send_outbox(out)?;
        }
        if items.is_empty() {
            return Ok(());
        }
        self.stats.deposits_sent += items.len() as u64;
        self.shared_send_offer(conn, items, asked, out)
    }

    /// The peer's answer to Deposit item `(l, b)`: taken, it leaves the outbox (the pending
    /// deliveries) and ends the back-off of the others under `l`; refused for now, it backs off as a host's refusal does (`budget`); refused,
    /// it is signed again with the current deposit key if that differs and offered again, else
    /// not offered on this connection again until what this node holds changes or the peer's next
    /// filter arrives.
    fn shared_deposit_answered(&mut self, conn: ConnId, l: LabelId, b: BlobId, code: Code) -> Result<()> {
        if let Some(s) = self.records.shared.get_mut(&conn) {
            s.deposit_out = false;
        }
        // a queued one sent on this connection, else a pass's (in flight until `RESEND_MS`)
        let Some(k) = self.outbox.iter().find(|(k, o)| k.1 == l && k.2 == b && o.sent == Some(conn)).map(|(k, _)| *k) else { return Ok(()) };
        let Some(o) = self.outbox.get_mut(&k) else { return Ok(()) };
        o.sent = None;
        if code == Code::OK {
            self.outbox.remove(&k);
            self.state.remove_out(&k.0, &l, &b);
            // room appeared there: the others waiting for `l` go again now
            let now = self.now();
            for (_, o) in self.outbox.iter_mut().filter(|(x, _)| x.1 == l) {
                o.after = o.after.min(now);
            }
            return Ok(());
        }
        if self.deposit_moot(&k.0, &l, &b) {
            self.outbox.remove(&k);
            self.state.remove_out(&k.0, &l, &b);
            return Ok(());
        }
        if matches!(code, Code::BUDGET_FULL | Code::RATE_LIMITED | Code::STORAGE_CAP) {
            let now = self.now();
            let Some(o) = self.outbox.get_mut(&k) else { return Ok(()) };
            o.tries = o.tries.saturating_add(1);
            let tries = o.tries;
            let back = self.deposit_back_off(tries);
            if let Some(o) = self.outbox.get_mut(&k) {
                o.after = now.saturating_add(back);
            }
            return Ok(());
        }
        if !self.resign_deposit(&k.0, &l, &b)?
            && let Some(s) = self.records.shared.get_mut(&conn)
        {
            s.deposits_refused.insert((l, b));
        }
        Ok(())
    }

    /// L joins `conn`'s S on this side, and this side's stream of the peer; the record keeps it.
    fn shared_open(&mut self, conn: ConnId, l: LabelId, class: u8, beacon: Option<[u8; 32]>, out: &mut Vec<Action>) -> Result<()> {
        // the first sync ID shared here: what this node holds of labels synced with no host is
        // placed for its readers from now on (`serves_readers`)
        self.pass_due |= !by_key(class) && self.records.shared.values().all(Shared::is_empty);
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        s.members.insert(l, Member { class, beacon, until: None });
        self.member_unread_there(conn, l, false, out)?;
        // kept unread: served to the peer from the hub's store, and pulled from it by the store's
        // rules (`unread_events`); the peer's Deletes of it are taken (spec/sync.md §5, Delete)
        if self.is_unread(&l)? {
            self.hub_down(conn, osis_host::Down::Open(l), out);
            self.unread_restream()?;
            return self.stream_join(conn, l, osis_store::Member { class, beacon, until: None, at: At::Join(None) }, out);
        }
        self.suspects_due = true;
        self.stream_join(conn, l, osis_store::Member { class, beacon, until: None, at: At::Join(None) }, out)?;
        self.stream_source_gained(conn, &l, out)
    }

    /// L leaves S on this side (a Lost, a judgment, a digest difference) and is pending again
    /// for this record (issues/net-shared-set.md, Re-marking), whether or not it was a member:
    /// nothing more is served or pulled for it, and its stream position is kept as `stop` says.
    fn shared_close(&mut self, conn: ConnId, l: &LabelId, stop: super::stream::Stop, out: &mut Vec<Action>) -> Result<()> {
        // a sync ID not held here has nothing pending: nothing is re-marked
        let at = self.engine.run(|tx| Ok(tx.txn.changed_at(l)?))?.unwrap_or(u64::MAX);
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        let was = s.members.remove(l).is_some();
        s.by_role.remove(l);
        s.offered.clear();
        s.pending.remark(at);
        s.acked_pos = s.acked_pos.min(at.saturating_sub(1));
        s.test_due = true;
        self.stream_leave(conn, l, at, stop)?;
        // `Phase::Open` is membership: it waits for the peer's filter again, from the next
        // arrival on (one follows the head's move or judgment that ended it), at the newest step
        // known there
        let arrival = self.records.shared.get(&conn).map_or(0, |s| s.arrivals);
        let now = self.now();
        if let Some(c) = self.conns.get_mut(&conn)
            && let Some(lc) = c.labels.get_mut(l).filter(|x| x.phase.is_open())
        {
            lc.phase = super::Phase::Testing { shown: None };
            lc.last_sync = now;
            c.req.walked.insert(*l, arrival);
        }
        if was && self.is_unread(l)? {
            self.hub_down(conn, osis_host::Down::Shut(*l), out);
        }
        self.unread_restream()
    }

    /// Re-judges every member (issues/net-shared-set.md, Opens): a holder stays, and so does a
    /// member whose credential is still admissible. One opened by a credential no longer
    /// admissible, its peer's actors not departed, ends at a rotation: it is served through the
    /// rotation (`until`, `shared_until_at`) and closes once the requester reported a position
    /// past it (`shared_until_due`). Anything else closes now with a `Lost`. A member of a sync
    /// ID kept unread stays while its credential is its head's, else ends through the head's
    /// event (`unread_until`). A connection whose actors are unknown here now keeps what the rule
    /// keeps, but loses its record (and its next filter holds no read credential).
    fn shared_rejudge(&mut self, conn: ConnId, out: &mut Vec<Action>) -> Result<()> {
        if !self.records.shared.contains_key(&conn) {
            return Ok(());
        }
        let known = self.shared_known(conn);
        if !known {
            // a record is honoured only while its actors are known here (spec/sync.md §10)
            self.records.unbind(conn);
            self.stream_unbind(conn);
            if let Some(s) = self.records.shared.get_mut(&conn) {
                s.record = None;
            }
        }
        let Some(actors) = self.connection_proven(conn).map(Proven::all) else { return Ok(()) };
        let creds = self.shared_creds(conn, None, ALL)?;
        let things = self.things();
        let unread = self.unread_heads()?;
        let mut judge = self.engine.core.judge(actors);
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        let (mut gone, mut ending, mut stays, mut unread_ending) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        // members this node no longer syncs at all (a group it handed off or stopped reading)
        let mut unsynced = Vec::new();
        for (l, m) in &s.members {
            let Some(t) = things.get(l) else {
                // kept unread: an open stands while its credential is the head's
                if unread.contains_key(l) {
                    let cred = m.beacon.is_some_and(|b| creds.iter().any(|c| c.label == *l && c.beacon == b));
                    if cred {
                        if m.until.is_some() {
                            stays.push(*l);
                        }
                    } else if m.until.is_none() {
                        unread_ending.push(*l);
                    }
                    continue;
                }
                gone.push(*l);
                unsynced.push(*l);
                continue;
            };
            let j = judge.of(t);
            let cred = m.beacon.is_some_and(|b| m.class != JUDGED && creds.iter().any(|c| c.label == *l && c.beacon == b));
            if j == super::credentials::Judgment::Holder || cred {
                if m.until.is_some() {
                    stays.push(*l);
                }
            } else if j == super::credentials::Judgment::Departed || m.class == JUDGED || by_key(m.class) {
                // a sync-key open holds for one sync key: this side's at a peer that cannot read
                // L, or a dialer's proof of the newest recorded step's here; another sync key
                // ends it at once (spec/sync.md §5 Opens), and a dialer holding the new secret
                // proves it again
                gone.push(*l);
            } else if m.until.is_none() {
                ending.push((*l, *t, m.beacon));
            }
        }
        drop(judge);
        let r = s.r;
        if !ending.is_empty() {
            self.log_flush()?;
        }
        let mut moved: Vec<(LabelId, Option<u64>)> = stays.into_iter().map(|l| (l, None)).collect();
        for (l, t, b) in ending {
            moved.push((l, Some(self.shared_until_at(l, t, b, &r)?)));
        }
        for l in unread_ending {
            moved.push((l, Some(self.unread_until(&l)?)));
        }
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        for (l, u) in &moved {
            if let Some(m) = s.members.get_mut(l) {
                m.until = *u;
            }
        }
        if let Some(id) = s.record.filter(|_| !moved.is_empty()) {
            self.engine.run(|tx| {
                for (l, u) in &moved {
                    tx.txn.record_member_until(&id, *l, *u)?;
                }
                Ok(())
            })?;
        }
        if !gone.is_empty() {
            // where each stopped for the peer: a position it reported, or its `until` if below
            // (issues/net-reconnect.md, Lost and rejoin)
            let mut items = Vec::with_capacity(gone.len());
            for l in &gone {
                let c = self.shared_stopped(conn, l)?;
                self.shared_close(conn, l, super::stream::Stop::Here, out)?;
                items.push((*l, c));
            }
            self.shared_send_lost(conn, items, out)?;
        }
        // at a host, such a label leaves the connection: no stream reads it there any more, so it
        // would never read to its end (nor be Hit again there)
        if let Some(c) = self.conns.get_mut(&conn).filter(|c| !c.to_peer()) {
            for l in &unsynced {
                c.labels.remove(l);
            }
            c.req.forget(|l| unsynced.contains(l));
        }
        self.shared_until_due(conn, out)
    }

    /// Where member `l` stopped for `conn`'s requester: the position the requester reported
    /// storing it at (`stream_reported`), or its `until` if lower. None where it reported none.
    fn shared_stopped(&mut self, conn: ConnId, l: &LabelId) -> Result<Option<Vec<u8>>> {
        let until = self.records.shared.get(&conn).and_then(|s| s.members.get(l)).and_then(|m| m.until);
        let reported = self.stream_reported(conn, l);
        let at = match (until, reported) {
            (Some(u), Some(p)) => u.min(p),
            (None, Some(p)) => p,
            (_, None) => return Ok(None),
        };
        self.engine.run(|tx| Ok(super::state::hub(tx)?.node_log(|t| t.log_cursor(at))?))
    }

    fn shared_send_lost(&mut self, conn: ConnId, items: Vec<(LabelId, Option<Vec<u8>>)>, out: &mut Vec<Action>) -> Result<()> {
        for batch in items.chunks(MAX_SHARED_ITEMS) {
            let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
            let id = s.next();
            s.asked.insert(id, Asked::Lost);
            self.stats.lost_sent += batch.len() as u64;
            self.shared_send(conn, Message::Lost { id, items: batch.to_vec() }, out)?;
        }
        Ok(())
    }

    /// The members of `conn` being ended (`until`).
    pub(super) fn shared_untils(&self, conn: ConnId) -> BTreeMap<LabelId, u64> {
        self.records.shared.get(&conn).map(|s| s.members.iter().filter_map(|(l, m)| m.until.map(|u| (*l, u))).collect()).unwrap_or_default()
    }

    /// Members being ended whose requester reported a position at or past their `until`
    /// (`stream_reported`) close, with a `Lost` naming `until`.
    pub(super) fn shared_until_due(&mut self, conn: ConnId, out: &mut Vec<Action>) -> Result<()> {
        let untils = self.shared_untils(conn);
        if untils.is_empty() {
            return Ok(());
        }
        let due: Vec<(LabelId, u64)> = untils.into_iter().filter(|(l, u)| self.stream_reported(conn, l).is_some_and(|r| r >= *u)).collect();
        if due.is_empty() {
            return Ok(());
        }
        let mut items = Vec::with_capacity(due.len());
        for (l, _) in due {
            let c = self.shared_stopped(conn, &l)?;
            self.shared_close(conn, &l, super::stream::Stop::Here, out)?;
            items.push((l, c));
        }
        self.shared_send_lost(conn, items, out)?;
        self.shared_test(conn, out)
    }

    /// Where a member of `l` (held under `thing`) opened by the credential with beacon `b` under
    /// pair key `r` ends (`until`; issues/net-reconnect.md, Joining and rejoining): where the last
    /// rotation superseding that credential's epoch was logged (the highest first-logged position
    /// of the entries in L of every such rotation), so each rotation is served (a holder this
    /// node judges unknown needs all of them to reach the current epoch) and nothing logged after
    /// them, however it arrived (in their batch, or written between steps). With no such entry
    /// here (the credential no read secret held, an epoch derived from another actor's, a static
    /// entry), the log's end. Read after `log_flush`.
    fn shared_until_at(&mut self, l: LabelId, thing: Tid, b: Option<[u8; 32]>, r: &[u8; 32]) -> Result<u64> {
        let mut blobs: Vec<BlobId> = Vec::new();
        if let (Some(b), Some(e)) = (b, self.engine.epochs(&thing)) {
            let read = &e.read;
            let old = read.epochs().find(|(_, i)| i.secret.as_ref().is_some_and(|s| beacon(s.expose(), &l.0, r) == b)).map(|(ep, _)| *ep);
            if let Some(old) = old {
                let commits: Vec<CommitId> = read.epochs().filter(|(ep, i)| read.is_established(ep) && i.superseded_epochs().contains(&old)).flat_map(|(_, i)| i.rotations.keys().chain(&i.snapshots).copied().collect::<Vec<_>>()).collect();
                blobs = commits.iter().flat_map(|c| self.state.entries_of(&l, c).map(|(b, _)| b)).collect();
            }
        }
        self.engine.run(|tx| {
            let mut last = None;
            for x in &blobs {
                last = last.max(super::state::hub(tx)?.node_log(|t| t.log_entry_first(&l, x))?);
            }
            Ok(match last {
                Some(p) => p,
                None => super::state::hub(tx)?.node_log(|t| t.log_end())?,
            })
        })
    }

    /// Logs what this node holds (`served_labels`, a flush).
    fn log_flush(&mut self) -> Result<()> {
        let _ = self.served_labels();
        self.state.flush(&mut self.engine)
    }

    /// Records not bound to a connection, for the sync IDs whose `changed_at` moved: a member
    /// opened by a credential no longer admissible, the record's actors neither holders nor
    /// departed, ends at its rotation (`until`, `shared_until_at`), as `shared_rejudge` ends one
    /// on a connection; so a rotation while apart ends the stream at the rotation, not at the
    /// reconnect. A departed one closes at the reconnect's re-judging. O(records holding each).
    fn records_end(&mut self) -> Result<()> {
        let moved: Vec<LabelId> = std::mem::take(&mut self.changed_moved).into_iter().collect();
        if moved.is_empty() {
            return Ok(());
        }
        self.log_flush()?;
        let bound: BTreeSet<RecordId> = self.records.shared.values().filter_map(|s| s.record).collect();
        let things = self.things();
        let unread = self.unread_heads()?;
        let creds = self.credentials(&moved)?;
        let mut ends: Vec<(RecordId, LabelId, u64)> = Vec::new();
        for l in &moved {
            // kept unread: a member whose credential is no longer the head's ends at its event
            if !things.contains_key(l) && unread.contains_key(l) {
                let held = self.engine.run(|tx| Ok(tx.txn.records_holding(l)?))?;
                for (rec, m) in held {
                    let Some(b) = m.beacon.filter(|_| m.until.is_none() && !bound.contains(&rec.id)) else { continue };
                    if !creds.get(l).is_some_and(|cs| cs.iter().any(|c| beacon(&c.match_value(), &l.0, &rec.r) == b)) {
                        ends.push((rec.id, *l, self.unread_until(l)?));
                    }
                }
                continue;
            }
            let Some(t) = things.get(l) else { continue };
            let held = self.engine.run(|tx| Ok(tx.txn.records_holding(l)?))?;
            for (rec, m) in held {
                let Some(b) = m.beacon.filter(|_| m.class != JUDGED && m.until.is_none() && !bound.contains(&rec.id)) else { continue };
                let j = self.engine.core.judge(rec.actors.iter().copied()).of(t);
                if j != super::credentials::Judgment::Unknown {
                    continue;
                }
                let admissible = creds.get(l).is_some_and(|cs| {
                    cs.iter().filter(|c| matches!(c, Credential::ReadSecret(_) | Credential::StaticEntry(_))).any(|c| beacon(&c.match_value(), &l.0, &rec.r) == b)
                });
                if !admissible {
                    ends.push((rec.id, *l, self.shared_until_at(*l, *t, Some(b), &rec.r)?));
                }
            }
        }
        if ends.is_empty() {
            return Ok(());
        }
        self.engine.run(|tx| {
            for (id, l, u) in &ends {
                tx.txn.record_member_until(id, *l, Some(*u))?;
            }
            Ok(())
        })
    }

    fn shared_lost(&mut self, conn: ConnId, id: u32, items: Vec<(LabelId, Option<Vec<u8>>)>, out: &mut Vec<Action>) -> Result<()> {
        // only a member of S is closed: a sync ID the peer does not share with this node changes
        // nothing but where it stopped (a Lost crossing this side's own close) and costs no test
        let n = items.len();
        let mut back = Vec::new();
        for (l, c) in items {
            if self.shared_member(conn, &l) {
                // a member this side was ending for the peer (`until`) stopped there for it, not
                // where the peer's own position says: told, as this side's Lost would have
                if self.records.shared.get(&conn).and_then(|s| s.members.get(&l)).is_some_and(|m| m.until.is_some()) {
                    back.push((l, self.shared_stopped(conn, &l)?));
                }
                self.shared_close(conn, &l, super::stream::Stop::Lost(c), out)?;
            } else {
                self.stream_lost_closed(conn, &l, c)?;
            }
        }
        self.shared_send(conn, Message::Shared { id, codes: vec![(Code::OK, None, None); n] }, out)?;
        if !back.is_empty() {
            self.shared_send_lost(conn, back, out)?;
        }
        self.shared_test(conn, out)
    }

    fn shared_reply(&mut self, conn: ConnId, id: u32, codes: Vec<osis_proto::msg::SharedCode>, out: &mut Vec<Action>) -> Result<()> {
        let retry_at = self.now().saturating_add(self.cfg.resync_ms);
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        let Some(asked) = s.asked.remove(&id) else { return Ok(()) };
        match asked {
            Asked::Lost => Ok(()),
            Asked::Beacons { generation, pos, last } => {
                let code = codes.first().map_or(Code::REFUSED, |c| c.0);
                if !last {
                    return Ok(());
                }
                s.in_flight = false;
                if code == Code::OK {
                    s.pending.ack = s.pending.ack.max(pos);
                    // the peer holds this generation: the next additions extend it
                    s.acked_gen = generation;
                    if let Some(id) = s.record {
                        let own = Filter { generation: s.sent_gen, acked: generation, f: s.f, whole: s.whole_n as u64, added: s.added as u64 };
                        self.engine.run(|tx| Ok(tx.txn.record_set_own(&id, own)?))?;
                    }
                } else {
                    // refused (base unknown, an Error): a whole filter goes again after
                    // `resync_ms`, as a refused Pull does (one rule for refused node requests)
                    s.whole_n = 0;
                    s.added = 0;
                    s.again = true;
                    s.retry_at = Some(retry_at);
                }
                self.shared_send_generation(conn, out)?;
                self.shared_rise(conn)
            }
            Asked::Offer(items) => {
                s.pending.offers_unanswered = s.pending.offers_unanswered.saturating_sub(1);
                // Hits answered 0 whose credential is gone: a Lost each, once the Offer is read
                let mut stale = Vec::new();
                // failed grants' Hits: answered for good, after the close below re-marks L
                let mut declined = Vec::new();
                // Behind items' answers per label, in order: the first child answered settles it
                let mut behinds: Vec<(LabelId, Option<osis_label::Step>, Vec<osis_label::Step>, Code)> = Vec::new();
                // Behind items by a static entry: (label, entry, code, grant)
                let mut statics = Vec::new();
                for (item, (code, tag, grant)) in items.into_iter().zip(codes) {
                    if let AskedItem::Deposit(l, b) = item {
                        self.shared_deposit_answered(conn, l, b, code)?;
                        continue;
                    }
                    if let AskedItem::Behind(l, step) = item {
                        let steps = grant.filter(|_| code == Code::OK).map(|g| g.steps).unwrap_or_default();
                        behinds.push((l, step.map(|x| *x), steps, code));
                        continue;
                    }
                    if let AskedItem::Static(l, entry) = item {
                        statics.push((l, entry, code, grant));
                        continue;
                    }
                    if code != Code::OK {
                        // a sync key refused (a filter's false positive, a head the peer does not
                        // hold yet, or one it moved past) is offered again when the peer's filter
                        // next changes; the label stays unopened there (`shared_unopened`)
                        if let AskedItem::Hit(c) = &item
                            && by_key(c.class)
                            && let Some(s) = self.records.shared.get_mut(&conn)
                        {
                            let hit = beacon_hit(&c.value, &c.label.0, &c.beacon, (s.by_listener, &s.key, &s.dialer, &s.listener));
                            s.offered.remove(&hit);
                            // not shown until the next arrival: the walk passes it, and walks on now
                            // past a step it found shown (a filter keeps a moved head's entries)
                            if let Some(x) = self.conns.get_mut(&conn) {
                                x.req.refused.insert((c.label, c.value));
                                if let Some(lc) = x.labels.get_mut(&c.label).filter(|lc| matches!(&lc.phase, super::Phase::Testing { shown: Some(x) } if x.1.verifying_key().to_bytes() == c.value)) {
                                    lc.phase = super::Phase::Testing { shown: None };
                                    x.req.walked.remove(&c.label);
                                }
                            }
                        }
                        continue;
                    }
                    match item {
                        // a ByRole's sender judged the peer a holder: no proof but J, still so now
                        AskedItem::ByRole(l) => {
                            let things = self.things();
                            let actors = self.connection_proven(conn).map(Proven::all).unwrap_or_default();
                            if things.get(&l).is_some_and(|t| self.engine.core.judge(actors).of(t) == super::credentials::Judgment::Holder) {
                                self.shared_open(conn, l, JUDGED, None, out)?;
                            }
                        }
                        AskedItem::Deposit(..) | AskedItem::Behind(..) | AskedItem::Static(..) => {}
                        AskedItem::Hit(c) => {
                            let Some(s) = self.records.shared.get(&conn) else { return Ok(()) };
                            let expect = beacon_reply(&c.value, &c.label.0, &c.beacon, s.side(!s.by_listener));
                            if tag != Some(expect) {
                                continue;
                            }
                            // a static entry's grant gives the read secret, or opens nothing
                            let granted = match &grant {
                                Some(g) if c.class == STATIC => self.granted(conn, c.label, &c.value, g)?,
                                _ => true,
                            };
                            // still admissible when the answer came?
                            let set: BTreeSet<LabelId> = [c.label].into();
                            let now = self.shared_creds(conn, Some(&set), TESTED)?;
                            if granted && now.iter().any(|x| x.value == c.value) {
                                self.shared_open(conn, c.label, c.class, Some(c.beacon), out)?;
                            } else {
                                // offered again once it is this side's credential again (a
                                // step registered under the same sync key); a failed grant's Hit
                                // stays answered, as a refused one, so a forged grant buys no loop
                                if let Some(s) = self.records.shared.get_mut(&conn) {
                                    let hit = beacon_hit(&c.value, &c.label.0, &c.beacon, (s.by_listener, &s.key, &s.dialer, &s.listener));
                                    s.offered.remove(&hit);
                                    if !granted {
                                        declined.push(hit);
                                    }
                                }
                                stale.push(c.label);
                            }
                        }
                    }
                }
                for (l, entry, code, grant) in statics {
                    self.static_answered(conn, l, &entry, code, grant.as_deref(), out)?;
                }
                let mut done: BTreeSet<LabelId> = BTreeSet::new();
                // steps first, then refused for now (a hint's other keys may still be answered)
                behinds.sort_by_key(|x| (x.2.is_empty(), x.3 != Code::RATE_LIMITED));
                for (l, step, steps, code) in &behinds {
                    if done.insert(*l) {
                        self.behind_answered(conn, *l, step.clone(), steps.clone(), *code, out)?;
                    }
                }
                // this tester's credential is gone (issues/net-shared-set.md, Divergence), unless
                // another Hit on L opened it (the same Offer's, read after) or still may (one
                // unanswered): the peer opened L for that one too, and a Lost would close it.
                // Closed here first, so L is pending again (Re-marking) and tested anew
                stale.dedup();
                for l in stale {
                    if !self.shared_member(conn, &l) && !self.shared_hit_out(conn, &l) {
                        self.shared_close(conn, &l, super::stream::Stop::Here, out)?;
                        self.shared_lost_send(conn, l, out)?;
                    }
                }
                if let Some(s) = self.records.shared.get_mut(&conn) {
                    s.offered.extend(declined);
                }
                match self.records.shared.get(&conn) {
                    Some(s) if s.pending.offers_unanswered > 0 => Ok(()),
                    Some(s) if s.test_due => self.shared_test(conn, out),
                    Some(_) => self.shared_roles(conn, out),
                    None => Ok(()),
                }
            }
        }
    }

    /// Whether an Offer of this side still unanswered on `conn` carries a Hit on `l`.
    fn shared_hit_out(&self, conn: ConnId, l: &LabelId) -> bool {
        self.records.shared.get(&conn).is_some_and(|s| s.asked.values().any(|a| matches!(a, Asked::Offer(items) if items.iter().any(|i| matches!(i, AskedItem::Hit(c) if c.label == *l)))))
    }

    fn shared_lost_send(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<Action>) -> Result<()> {
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        let id = s.next();
        s.asked.insert(id, Asked::Lost);
        self.stats.lost_sent += 1;
        self.shared_send(conn, Message::Lost { id, items: vec![(l, None)] }, out)
    }

    /// The peer's digest, its first message (issues/net-reconnect.md, Agreement), compared with
    /// the one this side sent. A match ends it; on a difference this side lists S in full now,
    /// before it acts on any later message, and waits for the peer's list.
    fn shared_digest(&mut self, conn: ConnId, digest: [u8; 32], out: &mut Vec<Action>) -> Result<()> {
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        if s.digest_read {
            return Ok(());
        }
        s.digest_read = true;
        if s.digest == Some(digest) {
            s.agreed = true;
            self.shared_test(conn, out)?;
            return self.stream_ask(conn, false, out);
        }
        let mine: Vec<LabelId> = s.members.keys().copied().collect();
        self.stats.digests_differ += 1;
        self.stats.members_listed += mine.len() as u64;
        let pages: Vec<&[LabelId]> = if mine.is_empty() { vec![&[]] } else { mine.chunks(MAX_MEMBERS).collect() };
        let last = pages.len() - 1;
        for (i, p) in pages.into_iter().enumerate() {
            self.shared_send(conn, Message::Members { labels: p.to_vec(), more: i < last }, out)?;
        }
        self.shared_test(conn, out)
    }

    /// A page of the peer's S. At its last, every member only one side holds is closed on this
    /// side with no lag (its rejoin is a listing) and re-marked pending, so the shared set's own
    /// rule finds it again; then the stream may pull.
    fn shared_peer_members(&mut self, conn: ConnId, labels: Vec<LabelId>, more: bool, out: &mut Vec<Action>) -> Result<()> {
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        if s.agreed || !s.digest_read {
            return Ok(());
        }
        // a sync ID neither in S nor held here changes nothing (nothing to close or re-mark): the
        // list keeps only the rest, so what it holds is bounded by what this node holds
        let (members, rest): (Vec<LabelId>, Vec<LabelId>) = labels.into_iter().partition(|l| s.members.contains_key(l));
        let held = self.engine.run(|tx| rest.into_iter().filter_map(|l| tx.txn.changed_at(&l).map(|c| c.map(|_| l)).transpose()).collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into))?;
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        s.peer_list.extend(members.into_iter().chain(held));
        if more {
            return Ok(());
        }
        let theirs = std::mem::take(&mut s.peer_list);
        let mine: BTreeSet<LabelId> = s.members.keys().copied().collect();
        s.agreed = true;
        for l in mine.symmetric_difference(&theirs) {
            let stop = if mine.contains(l) { super::stream::Stop::Listing } else { super::stream::Stop::Here };
            self.shared_close(conn, l, stop, out)?;
        }
        self.shared_test(conn, out)?;
        self.stream_ask(conn, false, out)
    }
}
