//! Records, agreement and the shared set (spec/sync-opens.md §2-§6, spec/sync-ids.md §6 Walk).
//!
//! **Principle:** each side opens S toward a peer only on its own proof, judged on what it holds
//! now, that the peer may hold S; who dialed proves nothing (model core/test/tla/net/NetOpen.tla:
//! every rule it flags is one function here, named in that function's comment).
//!
//! State: records (spec/sync-opens.md §3: pair key, proven actors, the shared set with each
//! member's credential and beacon, `acked_pos`, this side's filter generations and the peer's
//! latest filter, where members that left stopped); per connection its binding, phase,
//! agreement, filter generations in flight, the Hits its filter makes possible, the Offer in
//! flight, reported positions and walk state; `changed_at` per S with the credentials it was
//! advanced for. Work follows change: a sync ID whose credentials moved advances `changed_at`,
//! re-judges its members on the connections holding it (`holding`), and makes a filter addition
//! and a test due on each connection; nothing walks every sync ID per connection but a whole
//! filter (first contact) and the Hits index, built at the connection's first Hit.
//!
//! Durable (spec/sync-opens.md §3): records live in the store's record rows (`records`), held in
//! memory while a connection holds them and written at the end of each step (`flush`), which
//! also evicts past `RECORD_BUDGET`; `changed_at` per S is the store's (`changed_note`), with the
//! digest of the credentials it was advanced for, so a restart advances it only for a value
//! that moved.

pub mod cred;
pub mod holds;
mod positions;
mod records;

pub use positions::{Positions, Rejoin, Reported};

use crate::session::{Incoming, Proven, Sessions};
use crate::store::Store;
use crate::types::{ConnId, Credential, Cursor, Cx, Position, RecordId, Result, SourceClass};
use crate::unread::Unread;
use cred::{Bind, Shown, Tested, beacon_of, source_class};
use holds::{Creds, Holds, NodeHolds};
use osis_base::{SyncId, Tid, WallMs};
use osis_crypto::NodeRng;
use osis_crypto::kdf::{members_digest, pair_key, resume_tag, resumed_tag};
use osis_engine::sync::J;
use osis_label::StepId;
use osis_proto::filter::{beacon_value, decode_gcs, filter_width, pages};
use osis_proto::limits::{MAX_FILTER_ENTRIES, MAX_FILTER_WIDTH, MAX_MEMBERS, MAX_OFFER_ITEMS, MAX_RESUME_TAGS, MIN_FILTER_WIDTH, NO_RECORD_ID, REPLY_BUDGET};
use osis_proto::{Code, Id, Msg, OfferItem, SharedItem};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// After a refused filter generation, the wait before a whole one (spec/sync-opens.md §5,
/// `resync_ms`, local policy). At 0 a peer refusing every generation gets a whole filter at each
/// refusal, a loop at the speed of the link; at infinity a refusal stops this side's filter on
/// that connection for good (its opens wait for the next connection).
pub const RESYNC_MS: u64 = 30_000;

/// A member of a connection's shared set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub class: SourceClass,
    pub by: Credential,
    /// Being ended: served up to this position.
    pub until: Option<Position>,
}

/// A change of a connection's shared set: the driver hands each to `Streams::moved`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Moved {
    /// S became a member on `conn` (newly open, or open again), rejoining from where opens says.
    Joined(ConnId, SyncId, Rejoin),
    /// S stopped being a member on `conn` (closed, or the connection ended), with where the peer
    /// stood then.
    Left(ConnId, SyncId, LeftAt),
    /// Member S's `until` was set or cleared.
    Until(ConnId, SyncId),
}

/// Where a member's peer stood as it left: what status still counts it holding (spec/sync-status.md
/// §2: a report taken in the step that closed it).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LeftAt {
    /// Its reported position (spec/sync-opens.md §6 Lost).
    pub reported: Option<Position>,
    /// Its `until`, an ended member's.
    pub until: Option<Position>,
}

impl Moved {
    /// The connection it moved on.
    pub fn conn(&self) -> ConnId {
        match self {
            Moved::Joined(c, ..) | Moved::Left(c, ..) | Moved::Until(c, _) => *c,
        }
    }
}

/// How a module that sends reaches a connection: its binding and its sends. The product's is
/// `Sessions`; a test's a recording pair.
pub trait Wire {
    /// The connection's binding and the peer's proofs, once its proofs are done.
    fn bind(&self, c: ConnId) -> Option<(Bind, Proven)>;
    /// Sends a request; its id (top bit set, spec/wire.md §11.2; NoRecord's own) is chosen here.
    fn request(&mut self, c: ConnId, m: Msg) -> Id;
    /// Answers the peer's request `to`.
    fn answer(&mut self, c: ConnId, to: Id, m: Msg);
    /// Pushes Digest or Members: once a connection, never held back.
    fn push(&mut self, c: ConnId, m: Msg);
    /// Closes the connection: the peer broke the protocol.
    fn close(&mut self, c: ConnId, why: &'static str);
}

/// What one step gives opens besides its state: the node, the connections and the time.
pub struct Ctx<'a> {
    pub holds: &'a mut dyn Holds,
    pub wire: &'a mut dyn Wire,
    /// Where records and `changed_at` live.
    pub store: &'a mut Store,
    pub now: WallMs,
}

/// Work done, counted (tests: scaling by counting work, notes/coordination.md).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Work {
    /// Members re-judged.
    pub rejudged: u64,
    /// Beacons computed (filters and tests).
    pub beacons: u64,
    /// Sync IDs tested against a peer's filter.
    pub tested: u64,
    /// `Holds::creds` read.
    pub creds: u64,
    /// Connections' audiences judged again (the actors known here moved).
    pub audiences: u64,
}

/// A record (spec/sync-opens.md §3), as a connection holding it sees it. One kept nowhere
/// (`kept` false) serves a connection that proved no known actor, and goes with it.
#[derive(Clone, Debug)]
struct Record {
    r: [u8; 32],
    actors: Vec<Tid>,
    kept: bool,
    members: BTreeMap<SyncId, Member>,
    /// The beacon each member was opened by (none: by J).
    basis: BTreeMap<SyncId, Option<[u8; 32]>>,
    /// Where each member that left rejoins: held by this side's stream (the connection ended), a
    /// Lost's cursor, or from the start (a digest difference, or this side closed it).
    stopped: BTreeMap<SyncId, Rejoin>,
    acked_pos: u64,
    own: OwnFilter,
    peer: Option<PeerFilter>,
}

/// This side's filter as sent through the record.
#[derive(Clone, Debug, Default)]
struct OwnFilter {
    /// The last generation sent, and the last the peer acknowledged.
    generation: u64,
    acked: u64,
    f: u8,
    whole: u64,
    added: u64,
    /// The `changed_at` position the last generation sent covers, and the one the last
    /// acknowledged covers (one generation is in flight at a time).
    sent_reach: u64,
    acked_reach: u64,
}

#[derive(Clone, Debug)]
struct PeerFilter {
    generation: u64,
    f: u8,
    /// Sorted: up to `MAX_FILTER_ENTRIES`, held while a connection holds the record.
    values: Arc<Vec<u64>>,
    /// Entries of its whole generation, and of the additions since (at most `whole` in all).
    whole: u64,
    added: u64,
    /// Generations arrived through this record, counted here (the peer's numbering is its word).
    arrived: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    /// Dialer: Resume sent with these records listed (and their pair keys).
    Resuming { nonce: [u8; 32], listed: Vec<(RecordId, [u8; 32])> },
    /// Listener: waiting for Resume or NoRecord.
    Waiting,
    /// A record or NoRecord: the shared set runs.
    Running,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Agree {
    /// Digest sent, the peer's not read.
    Sent([u8; 32]),
    /// Digests differ: the peer's Members pages so far.
    Members(Vec<SyncId>),
    Done,
}

/// A request this side has out on a connection.
#[derive(Clone, Debug)]
enum Req {
    Resume,
    NoRecord,
    Beacons { generation: u64 },
    Offer,
    Lost,
}

/// An Offer item sent, to read its answer by.
#[derive(Clone, Debug)]
enum Sent {
    Hit { s: SyncId, cred: Box<Tested>, beacon: [u8; 32] },
    ByRole(SyncId),
    Behind(SyncId, Option<StepId>),
}

/// A filter generation in flight.
#[derive(Clone, Debug)]
struct GenOut {
    generation: u64,
    pages: BTreeSet<Id>,
    refused: bool,
    base_missing: bool,
}

/// A peer's filter generation arriving in pages.
#[derive(Clone, Debug)]
struct PeerGen {
    generation: u64,
    base: Option<u64>,
    f: u8,
    next_lo: u64,
    held_base: bool,
    values: Vec<u64>,
}

#[derive(Clone, Debug, Default)]
struct WalkState {
    /// Steps the source gave, verified (spec/sync-ids.md §6 Known steps).
    known: Vec<osis_label::Step>,
    /// Steps a Behind was refused on, this walk.
    refused: BTreeSet<Option<StepId>>,
    asked: bool,
    /// A Hit on a walk credential refused (a false positive of the filter): it asks Behind.
    missed: bool,
}

#[derive(Clone, Debug)]
struct Conn {
    bind: Bind,
    proven: Proven,
    /// The peer proved a known actor (its read secrets' beacons may go to it), judged at its proof
    /// and again at each move of the actors known here; a change makes the next generation whole.
    known: bool,
    /// The proven actors known here: what a record of this connection names (none: no record).
    named: Vec<Tid>,
    phase: Phase,
    rec: Option<RecordId>,
    agree: Agree,
    peer_digest: bool,
    reqs: BTreeMap<Id, Req>,
    gen_out: Option<GenOut>,
    resync_at: Option<WallMs>,
    whole_next: bool,
    /// The first generation of this connection is not sent yet.
    first: bool,
    /// The Hits this side's filter makes possible: expected peer Hit -> (S, credential, beacon).
    /// Built at the connection's first Hit (`indexed`), then kept by each change of S.
    shown: BTreeMap<[u8; 32], (SyncId, Shown, [u8; 32])>,
    indexed: bool,
    /// Sync IDs whose shown credentials go in the next generation's additions.
    adds: BTreeSet<SyncId>,
    peer_gen: Option<PeerGen>,
    tested_pos: u64,
    test_due: bool,
    offer: Option<Vec<Sent>>,
    /// Reported positions (spec/sync-opens.md §6 Lost): streams' word, through `reported`.
    reported: Positions,
    /// Members with an `until`: what a reported position may close.
    ending: BTreeSet<SyncId>,
    walks: BTreeMap<SyncId, WalkState>,
    /// It lost its record to this connection (spec/sync-opens.md §1 One connection per pair):
    /// it closes, and acts on nothing meanwhile.
    lost_to: Option<ConnId>,
}

/// `changed_at` (spec/sync-opens.md §3): per S a position of this node's own sequence, with the
/// credentials it was advanced for; the store's (`changed_note`), mirrored here as each S comes
/// due.
#[derive(Clone, Debug, Default)]
struct Changed {
    /// The store's sequence end, read at the first settle.
    loaded: bool,
    end: u64,
    at: BTreeMap<SyncId, (u64, [u8; 32], Arc<Creds>)>,
    order: BTreeMap<u64, SyncId>,
}

impl Changed {
    fn pos(&self, s: &SyncId) -> u64 {
        self.at.get(s).map_or(0, |(p, ..)| *p)
    }

    fn after(&self, from: u64) -> Vec<SyncId> {
        self.order.range(from.saturating_add(1)..).map(|(_, s)| *s).collect()
    }
}

#[derive(Clone, Debug)]
pub struct Opens {
    /// The records connections hold (and those released this step, until `flush`).
    records: BTreeMap<RecordId, Record>,
    /// Sync IDs the store shredded, from the first settle.
    shreds: Option<osis_base::memo::Feed<SyncId>>,
    /// What changed of each kept record since `flush`.
    dirty: BTreeMap<RecordId, records::Dirty>,
    /// A store failure this step met: `settle` and `flush` fail the step with it.
    fault: Option<osis_store::Error>,
    /// `RECORD_BUDGET`, as this node keeps it (tests set it).
    budget: u64,
    conns: BTreeMap<ConnId, Conn>,
    changed: Changed,
    /// The connections each sync ID is a member on: what a change of S re-judges.
    holding: BTreeMap<SyncId, BTreeSet<ConnId>>,
    /// The memo effects the product's `Holds` settles.
    fx: holds::Fx,
    /// Stamped per connection as its reported positions move (`reported_at`: status follows it).
    reports: osis_base::memo::Stamps,
    work: Work,
}

impl Default for Opens {
    fn default() -> Opens {
        Opens {
            records: BTreeMap::new(),
            shreds: None,
            dirty: BTreeMap::new(),
            fault: None,
            budget: osis_store::RECORD_BUDGET,
            conns: BTreeMap::new(),
            changed: Changed::default(),
            holding: BTreeMap::new(),
            fx: holds::Fx::default(),
            reports: osis_base::memo::Stamps::default(),
            work: Work::default(),
        }
    }
}

static NO_MEMBERS: BTreeMap<SyncId, Member> = BTreeMap::new();

impl crate::store::Members for BTreeMap<SyncId, Member> {
    fn until(&self, s: &SyncId) -> Option<Option<Position>> {
        self.get(s).map(|m| m.until)
    }
    fn is_empty(&self) -> bool {
        BTreeMap::is_empty(self)
    }
}

/// What a connection may open S by, judged now (spec/sync-opens.md §4 Admissible).
struct Adm {
    j: J,
    shows: Vec<Shown>,
    tests: Vec<Tested>,
    step: Option<osis_crypto::SigningSecret>,
}

impl Opens {
    // ---- the product's entry points ----

    /// `Proved` (Resume or NoRecord, then Digest); Resume, Resumed, Digest, Members, Beacons,
    /// Offer, Shared, Lost.
    pub fn on_message(&mut self, cx: &mut Cx, sessions: &mut Sessions, unread: &Unread, conn: ConnId, m: Incoming, moved: &mut Vec<Moved>) {
        let now = cx.now;
        let mut fx = std::mem::take(&mut self.fx);
        let mut store = cx.store.clone();
        let mut holds = NodeHolds { cx, unread, fx: &mut fx };
        let mut ctx = Ctx { holds: &mut holds, wire: sessions, store: &mut store, now };
        self.message(&mut ctx, conn, m, moved);
        self.fx = fx;
    }

    /// A connection ended: each of its members left (its record keeps them).
    pub fn on_closed(&mut self, cx: &mut Cx, conn: ConnId, moved: &mut Vec<Moved>) {
        let _ = cx;
        self.closed(conn, moved);
    }

    /// The end of the node's step: what changed of each record is written, records past the
    /// budget go (least recently used first, none a connection holds) with what was charged to
    /// them, in one transaction (`Store::write_records`), and records no connection holds leave
    /// memory. Returns the records that went. A store failure met during the step fails it here.
    pub fn flush(&mut self, store: &mut Store) -> Result<Vec<RecordId>> {
        if let Some(e) = self.fault.take() {
            self.dirty.clear();
            return Err(e.into());
        }
        // in use: held by a connection, or listed in a Resume whose answer may name it
        let listed = self.conns.values().flat_map(|c| match &c.phase {
            Phase::Resuming { listed, .. } => listed.iter().map(|(id, _)| *id).collect(),
            _ => Vec::new(),
        });
        let in_use: BTreeSet<RecordId> = self.conns.values().filter_map(|c| c.rec).filter(|r| self.records.get(r).is_some_and(|r| r.kept)).chain(listed).collect();
        let dirty = std::mem::take(&mut self.dirty);
        let records = &self.records;
        let budget = self.budget;
        let evicted = store.write_records(budget, &in_use, |t| {
            for (id, d) in dirty {
                if let Some(r) = records.get(&id).filter(|r| r.kept) {
                    records::write(t, &id, r, d)?;
                }
            }
            Ok(())
        })?;
        let held: BTreeSet<RecordId> = self.conns.values().filter_map(|c| c.rec).collect();
        self.records.retain(|id, r| !r.kept || held.contains(id));
        Ok(evicted)
    }

    /// Tests only: `RECORD_BUDGET` as this node keeps it.
    #[doc(hidden)]
    pub fn set_record_budget(&mut self, budget: u64) {
        self.budget = budget;
    }

    /// Notes a store failure: the step fails at its end.
    fn failed(&mut self, r: Result<()>) {
        if let Err(e) = r {
            self.fault.get_or_insert(match e {
                crate::types::Error::Store(e) => e,
                _ => osis_store::Error::Corrupt("opens: store"),
            });
        }
    }

    fn dirty(&mut self, rid: RecordId) -> &mut records::Dirty {
        self.dirty.entry(rid).or_default()
    }

    /// Marks member S of `conn`'s record changed.
    fn dirty_member(&mut self, conn: ConnId, s: SyncId) {
        if let Some(rid) = self.conns.get(&conn).and_then(|c| c.rec) {
            self.dirty(rid).members.insert(s);
        }
    }

    /// Marks `conn`'s record's own state changed.
    fn dirty_core(&mut self, conn: ConnId) {
        if let Some(rid) = self.conns.get(&conn).and_then(|c| c.rec) {
            self.dirty(rid).core = true;
        }
    }

    /// Streams' reported positions (`reported`).
    pub fn on_reported(&mut self, cx: &mut Cx, sessions: &mut Sessions, unread: &Unread, reported: &mut Vec<Reported>, moved: &mut Vec<Moved>) {
        if reported.is_empty() {
            return;
        }
        let now = cx.now;
        let mut fx = std::mem::take(&mut self.fx);
        let mut store = cx.store.clone();
        let mut holds = NodeHolds { cx, unread, fx: &mut fx };
        let mut ctx = Ctx { holds: &mut holds, wire: sessions, store: &mut store, now };
        for r in reported.drain(..) {
            self.reported(&mut ctx, r, moved);
        }
        self.fx = fx;
    }

    /// Whether anything acted (a member that moved is in `moved`).
    pub fn settle(&mut self, cx: &mut Cx, sessions: &mut Sessions, unread: &Unread, moved: &mut Vec<Moved>) -> Result<bool> {
        let now = cx.now;
        let mut fx = std::mem::take(&mut self.fx);
        let mut store = cx.store.clone();
        let mut holds = NodeHolds { cx, unread, fx: &mut fx };
        let mut ctx = Ctx { holds: &mut holds, wire: sessions, store: &mut store, now };
        let acted = self.tick(&mut ctx, moved);
        self.fx = fx;
        if let Some(e) = self.fault.take() {
            return Err(e.into());
        }
        Ok(acted)
    }

    pub fn members(&self, conn: ConnId) -> &BTreeMap<SyncId, Member> {
        self.conns.get(&conn).and_then(|c| c.rec).and_then(|r| self.records.get(&r)).map_or(&NO_MEMBERS, |r| &r.members)
    }

    /// The peer's record: where streams, read and store keep their per-peer rows (none for a
    /// connection that keeps no record).
    pub fn record(&self, conn: ConnId) -> Option<RecordId> {
        let id = self.conns.get(&conn)?.rec?;
        self.records.get(&id).filter(|r| r.kept).map(|_| id)
    }

    /// The actors `conn`'s proofs count for that are known here (what its record names), as
    /// judged at its proofs (spec/sync-opens.md §2-§3).
    pub fn proven(&self, conn: ConnId) -> &[Tid] {
        self.conns.get(&conn).map_or(&[], |c| &c.named)
    }

    /// How many of the peer's filter generations have arrived through `conn`'s record: moves at
    /// each arrival (spec/sync-inbox.md §3: a refused Deposit item waits for the next).
    pub fn filter_arrivals(&self, conn: ConnId) -> u64 {
        self.conns.get(&conn).and_then(|c| c.rec).and_then(|r| self.records.get(&r)).and_then(|r| r.peer.as_ref()).map_or(0, |p| p.arrived)
    }

    /// Whether the peer's latest filter shows `key` as S's deposit key (spec/sync-opens.md §4
    /// Audiences: a node keeping S unread shows it to every connection): a deposit of S may land
    /// there (filters have false positives: the answer tells).
    pub fn shows_deposit_key(&self, conn: ConnId, s: &SyncId, key: &[u8; 32]) -> bool {
        let Some(r) = self.conns.get(&conn).and_then(|c| c.rec).and_then(|r| self.records.get(&r)) else { return false };
        let Some(p) = &r.peer else { return false };
        p.values.binary_search(&beacon_value(&beacon_of(key, s, &r.r), p.f)).is_ok()
    }

    /// Whether streams may Pull on `conn`: the digests matched or the peer's last Members page
    /// was read (spec/sync-opens.md §3 Agreement).
    pub fn agreed(&self, conn: ConnId) -> bool {
        self.conns.get(&conn).is_some_and(|c| c.phase == Phase::Running && c.agree == Agree::Done)
    }

    /// The kept records holding S as a member (spec/sync-status.md §1: a complete pass waits for
    /// each): as connections hold them, else as written. O(records holding S): read only as a
    /// pass begins.
    pub fn records_holding(&self, store: &Store, s: &SyncId) -> Result<BTreeSet<RecordId>> {
        let stored = store.with_read(|t| t.records_with_row(s, crate::store::rows::tag::MEMBER, b"", usize::MAX))?;
        let held = |id: &RecordId| self.records.get(id).filter(|r| r.kept).map(|r| r.members.contains_key(s));
        Ok(stored.into_iter().filter(|id| held(id) != Some(false)).chain(self.records.iter().filter(|(_, r)| r.kept && r.members.contains_key(s)).map(|(id, _)| *id)).collect())
    }

    /// Member S's reported position on `conn` (spec/sync-opens.md §6 Lost): none for a sync ID
    /// that is no member there.
    pub fn reported_at(&self, conn: ConnId, s: &SyncId) -> Option<&(Position, Cursor)> {
        self.reports.read(&conn);
        self.member(conn, s)?;
        self.conns.get(&conn)?.reported.get(s)
    }

    /// Streams' word: the peer reported a position on `conn` (spec/sync-opens.md §6 Lost). An
    /// ended member at or past its `until` closes with a Lost; only ended members are looked at.
    pub fn reported(&mut self, ctx: &mut Ctx, r: Reported, moved: &mut Vec<Moved>) {
        let conn = r.conn();
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let moved_one = c.reported.take(r);
        self.reports.wrote(&conn, true);
        let check: Vec<SyncId> = match moved_one {
            Some(s) => c.ending.contains(&s).then_some(s).into_iter().collect(),
            None => c.ending.iter().copied().collect(),
        };
        for s in check {
            self.close_if_reached(ctx, conn, s, moved);
        }
    }

    /// An ended member whose reported position is at or past its `until` closes with a Lost.
    fn close_if_reached(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, moved: &mut Vec<Moved>) {
        let Some(until) = self.member(conn, &s).and_then(|m| m.until) else { return };
        if self.reported_at(conn, &s).is_some_and(|(p, _)| *p >= until) {
            self.close_member(ctx, conn, s, true, moved);
        }
    }

    pub fn next_wake(&self) -> Option<WallMs> {
        self.conns.values().filter_map(|c| c.resync_at).min()
    }

    /// The connection `conn` lost its record to (spec/sync-opens.md §1 One connection per pair),
    /// while `conn` is not closed: a dialer does not dial that peer again while the winner lasts.
    pub fn lost_to(&self, conn: ConnId) -> Option<ConnId> {
        self.conns.get(&conn)?.lost_to
    }

    /// The newest `changed_at` position (spec/sync-opens.md §3): it moves on every change that
    /// could make a peer share something (a sync ID new here, a credential or role moved), which
    /// is what the redial rule follows (§1 Redial).
    pub fn changed_end(&self) -> u64 {
        self.changed.end
    }

    /// Tests only: the work counted so far.
    #[doc(hidden)]
    pub fn work(&self) -> Work {
        self.work
    }

    /// Tests only: `changed_at` of S.
    #[doc(hidden)]
    pub fn changed_at(&self, s: &SyncId) -> u64 {
        self.changed.pos(s)
    }

    // ---- the core, over `Ctx` ----

    /// Takes one message for opens.
    pub fn message(&mut self, ctx: &mut Ctx, conn: ConnId, m: Incoming, moved: &mut Vec<Moved>) {
        if self.conns.get(&conn).is_some_and(|c| c.lost_to.is_some()) {
            return;
        }
        match m {
            Incoming::Proved => self.proved(ctx, conn, moved),
            Incoming::Request(id, m) => self.request(ctx, conn, id, m, moved),
            Incoming::Reply(_, id, m) => self.reply(ctx, conn, id, m, moved),
            Incoming::Push(m) => self.push(ctx, conn, m, moved),
        }
        self.run(ctx, conn, moved);
    }

    /// A connection ended.
    pub fn closed(&mut self, conn: ConnId, moved: &mut Vec<Moved>) {
        self.release(conn, moved);
        self.conns.remove(&conn);
    }

    /// `conn` lets its record go: each member leaves it (the record keeps them); a record kept
    /// nowhere goes.
    fn release(&mut self, conn: ConnId, moved: &mut Vec<Moved>) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let Some(rid) = c.rec.take() else { return };
        let Some(r) = self.records.get(&rid) else { return };
        for (s, m) in &r.members {
            moved.push(Moved::Left(conn, *s, LeftAt { reported: c.reported.get(s).map(|(p, _)| *p), until: m.until }));
            if let Some(set) = self.holding.get_mut(s) {
                set.remove(&conn);
            }
        }
        // a kept one stays in memory until `flush` writes it (or another connection takes it)
        if !r.kept {
            self.records.remove(&rid);
        }
    }

    /// spec/sync-opens.md §1 (one connection per pair): `conn` comes to take record `id` while
    /// another connection is of the same pair: it holds that record, or on both the peer proved
    /// the same node (another node of this account). The one of better route rank stays, then the
    /// smaller order hash (`Bind::pair_order`, each under its own record's pair key: the same at
    /// both ends whatever order the two arrived in); the other lets its record go and closes.
    /// Whether `conn` stays.
    fn one_per_pair(&mut self, ctx: &mut Ctx, conn: ConnId, id: RecordId, moved: &mut Vec<Moved>) -> bool {
        let Some(r) = self.records.get(&id).map(|r| r.r) else { return true };
        let Some(c) = self.conns.get(&conn) else { return false };
        let node = c.proven.node;
        let kept = self.records.get(&id).is_some_and(|r| r.kept);
        let same = |k: &Conn| k.rec.is_some_and(|o| (o == id && kept) || (node.is_some() && k.proven.node == node));
        let Some((other, theirs)) = self.conns.iter().filter(|(o, k)| **o != conn && k.lost_to.is_none() && same(k)).find_map(|(o, k)| Some((*o, k.bind.pair_order(&self.records.get(&k.rec?)?.r)))) else { return true };
        let ours = c.bind.pair_order(&r);
        let (loser, winner) = if ours < theirs { (other, conn) } else { (conn, other) };
        self.release(loser, moved);
        if let Some(k) = self.conns.get_mut(&loser) {
            k.lost_to = Some(winner);
        }
        ctx.wire.close(loser, "one connection per pair");
        loser != conn
    }

    /// Keep or close (spec/sync-opens.md §1), opens' part: the connection runs its shared set,
    /// which has no member, and nothing of opens is under way on it (no request of its own out,
    /// agreement done, no filter generation out or arriving, no test due, no Offer unanswered,
    /// no member ending). What may still come from the peer is the caller's to rule out.
    pub fn idle(&self, conn: ConnId) -> bool {
        let Some(c) = self.conns.get(&conn) else { return false };
        c.phase == Phase::Running && c.lost_to.is_none() && self.members(conn).is_empty() && c.reqs.is_empty() && c.agree == Agree::Done && c.peer_digest && c.gen_out.is_none() && c.peer_gen.is_none() && !c.test_due && c.offer.is_none() && c.ending.is_empty() && !c.first
    }

    /// Settles: each sync ID whose credentials moved advances `changed_at`, re-judges its
    /// members and makes filters and tests due; then each connection's due work runs.
    pub fn tick(&mut self, ctx: &mut Ctx, moved: &mut Vec<Moved>) -> bool {
        let before = moved.len();
        // S left this node (spec/sync-set.md §3): its record rows went with the shred; where a
        // member stopped goes from memory too, before anything rejoins, so a later join is from
        // the start
        let shreds = self.shreds.get_or_insert_with(|| ctx.store.shred_feed()).added();
        for s in shreds {
            for r in self.records.values_mut() {
                r.stopped.remove(&s);
                r.basis.remove(&s);
            }
        }
        if !self.changed.loaded {
            let r = ctx.store.with_read(|t| t.changed_end());
            match r {
                Ok(end) => {
                    self.changed.end = end;
                    self.changed.loaded = true;
                }
                Err(e) => {
                    self.failed(Err(e));
                    return false;
                }
            }
        }
        // spec/sync-opens.md §4 Audiences: judged again only when the actors known here moved
        if ctx.holds.known_moved() {
            let conns: Vec<ConnId> = self.conns.keys().copied().collect();
            for conn in conns {
                let Some(c) = self.conns.get(&conn) else { continue };
                let known = peer_known(ctx.holds, &c.proven);
                self.work.audiences += 1;
                if let Some(c) = self.conns.get_mut(&conn)
                    && c.known != known
                {
                    c.known = known;
                    c.whole_next = true;
                }
            }
        }
        for s in ctx.holds.due() {
            self.work.creds += 1;
            let now = ctx.holds.creds(&s);
            let digest = now.as_ref().map(|c| c.digest());
            if digest == self.changed.at.get(&s).map(|(_, d, _)| *d) {
                continue;
            }
            self.moved_creds(ctx, s, now, moved);
        }
        let conns: Vec<ConnId> = self.conns.keys().copied().collect();
        for c in conns {
            if let Some(k) = self.conns.get_mut(&c)
                && k.resync_at.is_some_and(|t| t <= ctx.now)
            {
                k.resync_at = None;
                k.whole_next = true;
            }
            self.run(ctx, c, moved);
        }
        moved.len() > before
    }

    /// S's credentials moved to `now` (none: S left the sync set).
    fn moved_creds(&mut self, ctx: &mut Ctx, s: SyncId, now: Option<Arc<Creds>>, moved: &mut Vec<Moved>) {
        let known = self.changed.at.remove(&s);
        if let Some((p, ..)) = &known {
            self.changed.order.remove(p);
        }
        match now {
            Some(c) => {
                // the store's `changed_at` moves only for credentials that moved since it was
                // written: a restart finds the rest as they were
                let digest = c.digest();
                let r = ctx.store.with_tx(|t| match t.changed_note(s, &digest)? {
                    Some(p) => Ok((p, true)),
                    None => Ok((t.changed_at(&s)?.unwrap_or(0), false)),
                });
                let (pos, advanced) = match r {
                    Ok(x) => x,
                    Err(e) => {
                        self.failed(Err(e));
                        return;
                    }
                };
                self.changed.end = self.changed.end.max(pos);
                self.changed.at.insert(s, (pos, digest, c));
                self.changed.order.insert(pos, s);
                if !advanced && known.is_none() {
                    return;
                }
            }
            None => {
                // spec/sync-opens.md §3: a node that stops holding S drops S from every record in
                // the step that stops it; members on a connection close with a Lost (§6).
                for c in self.holding.get(&s).cloned().unwrap_or_default() {
                    self.close_member(ctx, c, s, true, moved);
                }
                for r in self.records.values_mut() {
                    r.members.remove(&s);
                    r.basis.remove(&s);
                    r.stopped.remove(&s);
                }
                for d in self.dirty.values_mut() {
                    d.members.remove(&s);
                }
                let r = ctx.store.with_tx(|t| t.changed_forget(&s));
                self.failed(r);
            }
        }
        for c in self.holding.get(&s).cloned().unwrap_or_default() {
            self.rejudge(ctx, c, s, moved);
        }
        for k in self.conns.values_mut() {
            k.adds.insert(s);
            k.test_due = true;
        }
        let conns: Vec<ConnId> = self.conns.iter().filter(|(_, k)| k.indexed).map(|(c, _)| *c).collect();
        for c in conns {
            self.index_shown(ctx, c, &s);
        }
    }

    // ---- records and agreement (§3) ----

    fn proved(&mut self, ctx: &mut Ctx, conn: ConnId, moved: &mut Vec<Moved>) {
        let Some((bind, proven)) = ctx.wire.bind(conn) else { return };
        let named = named_known(ctx.holds, &proven);
        let known = peer_known(ctx.holds, &proven);
        let mut c = Conn {
            bind,
            proven,
            known,
            named,
            phase: Phase::Waiting,
            rec: None,
            agree: Agree::Done,
            peer_digest: false,
            reqs: BTreeMap::new(),
            gen_out: None,
            resync_at: None,
            whole_next: false,
            first: true,
            shown: BTreeMap::new(),
            indexed: false,
            adds: BTreeSet::new(),
            peer_gen: None,
            tested_pos: 0,
            test_due: false,
            offer: None,
            reported: Positions::default(),
            ending: BTreeSet::new(),
            walks: BTreeMap::new(),
            lost_to: None,
        };
        if bind.dialer {
            if !c.named.is_empty() {
                // spec/sync-opens.md §3: Resume lists each record naming a proven actor known here
                // now, most recent first.
                let actors = c.named.clone();
                let mut listed: Vec<(RecordId, [u8; 32])> = match ctx.store.with_read(|t| t.records_of_actors(&actors)) {
                    Ok(rs) => rs.into_iter().map(|r| (r.id, r.r)).collect(),
                    Err(e) => {
                        self.failed(Err(e));
                        Vec::new()
                    }
                };
                listed.truncate(MAX_RESUME_TAGS);
                let (d, l) = (bind.own_challenge, bind.peer_challenge);
                let tags = listed.iter().map(|(_, r)| resume_tag(r, &bind.listener_key, &d, &l)).collect();
                let nonce = random32(ctx.holds.rng());
                c.phase = Phase::Resuming { nonce, listed };
                let id = ctx.wire.request(conn, Msg::Resume { id: 0, nonce, tags });
                c.reqs.insert(id, Req::Resume);
                self.conns.insert(conn, c);
            } else {
                self.conns.insert(conn, c);
                self.no_record(ctx, conn, moved);
            }
        } else {
            self.conns.insert(conn, c);
        }
    }

    /// The dialer keeps no record for this listener: NoRecord, and the set runs under the
    /// connection's own pair key (spec/sync-opens.md §3).
    fn no_record(&mut self, ctx: &mut Ctx, conn: ConnId, moved: &mut Vec<Moved>) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let id = ctx.wire.request(conn, Msg::NoRecord { id: NO_RECORD_ID });
        c.reqs.insert(id, Req::NoRecord);
        self.run_unkept(ctx, conn, moved);
    }

    fn run_unkept(&mut self, ctx: &mut Ctx, conn: ConnId, moved: &mut Vec<Moved>) {
        let Some(c) = self.conns.get(&conn) else { return };
        let (d, l) = if c.bind.dialer { (c.bind.own_challenge, c.bind.peer_challenge) } else { (c.bind.peer_challenge, c.bind.own_challenge) };
        let r = *pair_key(&d, &l).expose();
        let id = self.new_record(ctx, r, Vec::new(), false);
        self.take(ctx, conn, id, false, moved);
    }

    /// A new record: a kept one is written now (before the answer naming it goes, and before
    /// any module writes rows in it); one kept nowhere lives in memory with its connection.
    fn new_record(&mut self, ctx: &mut Ctx, r: [u8; 32], actors: Vec<Tid>, kept: bool) -> RecordId {
        let id = if kept {
            let made = ctx.store.with_tx(|t| t.record_create(r, &actors));
            match made {
                Ok(id) => id,
                Err(e) => {
                    self.failed(Err(e));
                    random16(ctx.holds.rng())
                }
            }
        } else {
            random16(ctx.holds.rng())
        };
        self.records.insert(id, Record { r, actors, kept, members: BTreeMap::new(), basis: BTreeMap::new(), stopped: BTreeMap::new(), acked_pos: 0, own: OwnFilter::default(), peer: None });
        id
    }

    /// Record `id` in memory: as a connection holds it, else as its rows hold it. Whether it is.
    fn load(&mut self, ctx: &mut Ctx, id: RecordId) -> bool {
        if self.records.contains_key(&id) {
            return true;
        }
        match ctx.store.with_read(|t| records::load(t, &id)) {
            Ok(Some(r)) => {
                self.records.insert(id, r);
                true
            }
            Ok(None) => false,
            Err(e) => {
                self.failed(Err(e));
                false
            }
        }
    }

    /// The connection takes record `id`: its members are this connection's (each re-judged),
    /// Digest first (with a record), then the filter.
    fn take(&mut self, ctx: &mut Ctx, conn: ConnId, id: RecordId, digest: bool, moved: &mut Vec<Moved>) {
        if !self.load(ctx, id) || !self.one_per_pair(ctx, conn, id, moved) {
            return;
        }
        let kept = self.records.get(&id).is_some_and(|r| r.kept);
        if kept {
            self.dirty(id).used = true;
        }
        let mut core = false;
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let Some(r) = self.records.get_mut(&id) else { return };
        if r.kept && r.actors != c.named {
            // spec/sync-opens.md §3: a session proving other actors than the record names starts
            // with every credential pending and a whole filter.
            r.actors = c.named.clone();
            r.acked_pos = 0;
            r.own.acked = 0;
            c.whole_next = true;
            core = true;
        }
        c.rec = Some(id);
        c.phase = Phase::Running;
        c.tested_pos = r.acked_pos;
        c.test_due = true;
        if digest {
            // spec/sync-opens.md §3 Agreement: Digest first, from the record before anything else.
            let d = members_digest(&r.r, r.members.keys().map(|s| &s.0));
            c.agree = Agree::Sent(d);
            ctx.wire.push(conn, Msg::Digest { digest: d });
        } else {
            c.agree = Agree::Done;
            c.peer_digest = true;
        }
        let members: Vec<SyncId> = r.members.keys().copied().collect();
        if core {
            self.dirty(id).core = true;
        }
        for s in &members {
            self.holding.entry(*s).or_default().insert(conn);
            moved.push(Moved::Joined(conn, *s, Rejoin::Held));
        }
        // spec/sync-opens.md §6: a member is re-judged when a connection takes a record.
        for s in members {
            self.rejudge(ctx, conn, s, moved);
        }
    }

    fn request(&mut self, ctx: &mut Ctx, conn: ConnId, id: Id, m: Msg, moved: &mut Vec<Moved>) {
        let running = self.conns.get(&conn).is_some_and(|c| c.phase == Phase::Running);
        match m {
            Msg::Resume { nonce, tags, .. } => self.resume(ctx, conn, id, nonce, &tags, moved),
            Msg::NoRecord { .. } => {
                if self.conns.get(&conn).is_some_and(|c| c.phase == Phase::Waiting && !c.bind.dialer) {
                    // a Shared holds at least one item (spec/wire.md §11.2): one of code 0
                    ctx.wire.answer(conn, id, Msg::Shared { id, items: vec![SharedItem::code(Code::OK)] });
                    self.run_unkept(ctx, conn, moved);
                } else {
                    ctx.wire.answer(conn, id, Msg::Error { id, code: Code::MALFORMED });
                }
            }
            // spec/sync-opens.md §4: a side keeping no shared set yet answers 14.
            Msg::Beacons { .. } | Msg::Offer { .. } | Msg::Lost { .. } if !running => ctx.wire.answer(conn, id, Msg::Error { id, code: Code::DECLINED }),
            Msg::Beacons { generation, base, f, lo, hi, gcs, more, .. } => self.beacons(ctx, conn, id, generation, base, f, (lo, hi), &gcs, more),
            Msg::Offer { items, .. } => self.offered(ctx, conn, id, items, moved),
            Msg::Lost { items, .. } => self.lost(ctx, conn, id, items, moved),
            _ => {}
        }
    }

    /// Listener: a Resume (spec/sync-opens.md §3).
    fn resume(&mut self, ctx: &mut Ctx, conn: ConnId, id: Id, dnonce: [u8; 32], tags: &[[u8; 32]], moved: &mut Vec<Moved>) {
        let Some(c) = self.conns.get(&conn) else {
            ctx.wire.answer(conn, id, Msg::Error { id, code: Code::MALFORMED });
            return;
        };
        if c.phase != Phase::Waiting || c.bind.dialer {
            ctx.wire.answer(conn, id, Msg::Error { id, code: Code::MALFORMED });
            return;
        }
        if c.named.is_empty() {
            // A connection whose dialer proved no known actor keeps no record: Error 1, and the
            // dialer sends NoRecord (spec/sync-opens.md §3).
            ctx.wire.answer(conn, id, Msg::Error { id, code: Code::REFUSED });
            return;
        }
        let bind = c.bind;
        let actors = c.named.clone();
        let (d, l) = (bind.peer_challenge, bind.own_challenge);
        // A record is honoured only while a proven actor of this session is named by it.
        let held = match ctx.store.with_read(|t| t.records_of_actors(&actors)) {
            Ok(rs) => rs,
            Err(e) => {
                self.failed(Err(e));
                Vec::new()
            }
        };
        let mine: BTreeMap<[u8; 32], (RecordId, [u8; 32])> = held.into_iter().map(|r| (resume_tag(&r.r, &bind.listener_key, &d, &l), (r.id, r.r))).collect();
        let found = tags.iter().find_map(|t| mine.get(t).copied());
        let lnonce = random32(ctx.holds.rng());
        let (rid, tag) = match found {
            Some((rid, r)) => (rid, Some(resumed_tag(&r, &bind.listener_key, &d, &l))),
            // On no match a new record, written before the answer goes.
            None => (self.new_record(ctx, *pair_key(&dnonce, &lnonce).expose(), actors, true), None),
        };
        ctx.wire.answer(conn, id, Msg::Resumed { id, nonce: lnonce, tag });
        self.take(ctx, conn, rid, true, moved);
    }

    fn reply(&mut self, ctx: &mut Ctx, conn: ConnId, id: Id, m: Msg, moved: &mut Vec<Moved>) {
        let Some(req) = self.conns.get_mut(&conn).and_then(|c| c.reqs.remove(&id)) else { return };
        match (req, m) {
            (Req::Resume, Msg::Resumed { nonce, tag, .. }) => self.resumed(ctx, conn, nonce, tag, moved),
            (Req::Resume, _) => self.no_record(ctx, conn, moved),
            // the source's filter shows its new head's credentials when it moves: nothing to do
            (Req::NoRecord | Req::Lost, _) => {}
            (Req::Beacons { generation }, m) => self.beacons_answered(ctx, conn, id, generation, &m),
            (Req::Offer, Msg::Shared { items, .. }) => self.answered(ctx, conn, items, moved),
            (Req::Offer, _) => self.answered(ctx, conn, Vec::new(), moved),
        }
    }

    /// Dialer: the listener's answer to its Resume.
    fn resumed(&mut self, ctx: &mut Ctx, conn: ConnId, lnonce: [u8; 32], tag: Option<[u8; 32]>, moved: &mut Vec<Moved>) {
        let Some(c) = self.conns.get(&conn) else { return };
        let Phase::Resuming { nonce, listed } = &c.phase else { return };
        let (bind, nonce) = (c.bind, *nonce);
        let (d, l) = (bind.own_challenge, bind.peer_challenge);
        // An absent or unexpected answer finds nothing.
        let found = tag.and_then(|t| listed.iter().find(|(_, r)| resumed_tag(r, &bind.listener_key, &d, &l) == t).map(|(id, _)| *id));
        let rid = match found {
            Some(rid) => rid,
            None => {
                let actors = c.named.clone();
                self.new_record(ctx, *pair_key(&nonce, &lnonce).expose(), actors, true)
            }
        };
        self.take(ctx, conn, rid, true, moved);
    }

    fn push(&mut self, ctx: &mut Ctx, conn: ConnId, m: Msg, moved: &mut Vec<Moved>) {
        match m {
            Msg::Digest { digest } => self.digest(ctx, conn, digest),
            Msg::Members { sync_ids, more } => self.members_page(ctx, conn, sync_ids, more, moved),
            _ => {}
        }
    }

    /// The peer's Digest: compared with the one sent, once a connection.
    fn digest(&mut self, ctx: &mut Ctx, conn: ConnId, digest: [u8; 32]) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let Agree::Sent(mine) = c.agree else {
            ctx.wire.close(conn, "Digest out of order");
            return;
        };
        c.peer_digest = true;
        c.test_due = true;
        if mine == digest {
            c.agree = Agree::Done;
            return;
        }
        // On a difference each side sends its set as Members pages, before acting on any later message.
        c.agree = Agree::Members(Vec::new());
        let set: Vec<SyncId> = c.rec.and_then(|r| self.records.get(&r)).map(|r| r.members.keys().copied().collect()).unwrap_or_default();
        let mut chunks: Vec<Vec<SyncId>> = set.chunks(MAX_MEMBERS).map(<[SyncId]>::to_vec).collect();
        if chunks.is_empty() {
            chunks.push(Vec::new());
        }
        let n = chunks.len();
        for (i, page) in chunks.into_iter().enumerate() {
            ctx.wire.push(conn, Msg::Members { sync_ids: page, more: i + 1 < n });
        }
    }

    /// A Members page; on the last, members only this side holds close (no position kept) and
    /// each sync ID in exactly one list is re-marked (spec/sync-opens.md §3 Agreement).
    fn members_page(&mut self, ctx: &mut Ctx, conn: ConnId, ids: Vec<SyncId>, more: bool, moved: &mut Vec<Moved>) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let Agree::Members(list) = &mut c.agree else {
            ctx.wire.close(conn, "Members out of order");
            return;
        };
        // Only sync IDs held here can be closed or re-marked: the rest is not kept.
        list.extend(ids.into_iter().filter(|s| self.changed.at.contains_key(s)));
        if more {
            return;
        }
        let theirs: BTreeSet<SyncId> = std::mem::take(list).into_iter().collect();
        c.agree = Agree::Done;
        let Some(rid) = c.rec else { return };
        let mine: BTreeSet<SyncId> = self.records.get(&rid).map(|r| r.members.keys().copied().collect()).unwrap_or_default();
        for s in mine.difference(&theirs) {
            self.drop_member(conn, *s, false, moved);
        }
        for s in mine.symmetric_difference(&theirs) {
            self.remark(conn, s);
        }
    }

    // ---- filters (§5) ----

    /// The connection's due work: its next filter generation, then a test.
    fn run(&mut self, ctx: &mut Ctx, conn: ConnId, moved: &mut Vec<Moved>) {
        if self.conns.get(&conn).is_none_or(|c| c.lost_to.is_some()) {
            return;
        }
        self.send_generation(ctx, conn);
        self.test(ctx, conn, moved);
    }

    /// Indexes the Hits every credential this side shows on `conn` makes possible, at the
    /// connection's first Hit: a connection the peer Hits nothing on (a reconnect with nothing
    /// changed) computes no beacon of what it does not share.
    fn index_all(&mut self, ctx: &mut Ctx, conn: ConnId) {
        match self.conns.get_mut(&conn) {
            Some(c) if !c.indexed => c.indexed = true,
            _ => return,
        }
        let all: Vec<SyncId> = self.changed.at.keys().copied().collect();
        for s in all {
            self.index_shown(ctx, conn, &s);
        }
    }

    /// Indexes S's shown credentials on `conn` (spec/sync-opens.md §5 Opening: a Hit names no
    /// sync ID; the receiver finds it among what its filter shows). Nothing is removed: a stored
    /// filter keeps old entries, and a Hit on one is judged by what is admissible now.
    fn index_shown(&mut self, ctx: &mut Ctx, conn: ConnId, s: &SyncId) {
        let Some(adm) = self.admissible(ctx, conn, s) else { return };
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let Some(r) = c.rec.and_then(|r| self.records.get(&r)) else { return };
        for sh in adm.shows {
            let b = beacon_of(sh.matched(), s, &r.r);
            self.work.beacons += 1;
            c.shown.insert(c.bind.peer_hit(sh.matched(), s, &b), (*s, sh, b));
        }
    }

    /// Sends the next generation of this side's filter when none is in flight (spec/sync-opens.md
    /// §5 Filter): the first of a connection with an acknowledged record is additions of the sync
    /// IDs past `acked_pos` (sent even when empty), else whole; later ones additions of the sync
    /// IDs whose credentials or roster changed; a whole one once additions pass its entries.
    fn send_generation(&mut self, ctx: &mut Ctx, conn: ConnId) {
        let Some(c) = self.conns.get(&conn) else { return };
        if c.phase != Phase::Running || c.gen_out.is_some() || c.resync_at.is_some() {
            return;
        }
        let Some(rid) = c.rec else { return };
        let Some(r) = self.records.get(&rid) else { return };
        let first = c.first;
        // spec/sync-opens.md §4 Audiences: as judged at the proof and at each move of the actors
        // known here (a change made the generation whole)
        let known = c.known;
        let whole = c.whole_next || r.own.generation == 0 || (first && r.own.acked != r.own.generation);
        let ids: Vec<SyncId> = if whole {
            Vec::new()
        } else if first {
            self.changed.after(r.acked_pos)
        } else {
            c.adds.iter().copied().collect()
        };
        if !whole && !first && ids.is_empty() {
            return;
        }
        let (rr, room) = (r.r, r.own.whole.saturating_sub(r.own.added));
        let mut beacons = if whole { None } else { Some(self.shown_beacons(ctx, conn, &ids, known, &rr)) };
        // Additions bring at most the whole one's n entries in all (spec/wire.md §11.2): past it, whole.
        if beacons.as_ref().is_some_and(|b| b.len() as u64 > room) {
            beacons = None;
        }
        let whole = beacons.is_none();
        let beacons = match beacons {
            Some(b) => b,
            None => {
                let all: Vec<SyncId> = self.changed.at.keys().copied().collect();
                self.shown_beacons(ctx, conn, &all, known, &rr)
            }
        };
        let Some(r) = self.records.get_mut(&rid) else { return };
        let f = if whole { filter_width(beacons.len()).clamp(MIN_FILTER_WIDTH, MAX_FILTER_WIDTH) } else { r.own.f };
        let mut values: Vec<u64> = beacons.iter().map(|b| beacon_value(b, f)).collect();
        values.sort_unstable();
        let generation = r.own.generation + 1;
        let base = if whole { None } else { Some(r.own.acked) };
        r.own.generation = generation;
        r.own.f = f;
        if whole {
            r.own.whole = values.len() as u64;
            r.own.added = 0;
        } else {
            r.own.added += values.len() as u64;
        }
        r.own.sent_reach = self.changed.end;
        self.dirty_core(conn);
        let Some(c) = self.conns.get_mut(&conn) else { return };
        c.first = false;
        c.whole_next = false;
        c.adds.clear();
        let mut ids = BTreeSet::new();
        for p in pages(&values, f, REPLY_BUDGET / 2) {
            let id = ctx.wire.request(conn, Msg::Beacons { id: 0, generation, base, f, lo: p.lo, hi: p.hi, gcs: p.gcs, more: p.more });
            ids.insert(id);
            c.reqs.insert(id, Req::Beacons { generation });
        }
        c.gen_out = Some(GenOut { generation, pages: ids, refused: false, base_missing: false });
    }

    /// The beacons of the credentials `ids` show to this peer (spec/sync-opens.md §4 Audiences: a
    /// read secret's only to a known actor).
    fn shown_beacons(&mut self, ctx: &mut Ctx, conn: ConnId, ids: &[SyncId], known: bool, r: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut beacons = Vec::new();
        for s in ids {
            if let Some(adm) = self.admissible(ctx, conn, s) {
                for sh in adm.shows.iter().filter(|sh| known || !sh.secret_audience()) {
                    self.work.beacons += 1;
                    beacons.push(beacon_of(sh.matched(), s, r));
                }
            }
        }
        beacons
    }

    /// The peer answered a page of this side's generation `generation`.
    fn beacons_answered(&mut self, ctx: &mut Ctx, conn: ConnId, id: Id, generation: u64, m: &Msg) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let Some(g) = c.gen_out.as_mut().filter(|g| g.generation == generation) else { return };
        g.pages.remove(&id);
        match m {
            Msg::Shared { items, .. } if items.first().is_some_and(|i| i.code == Code::OK) => {}
            Msg::Shared { items, .. } if items.first().is_some_and(|i| i.code == Code::UNKNOWN_SYNC_ID) => g.base_missing = true,
            _ => g.refused = true,
        }
        if !g.pages.is_empty() {
            return;
        }
        let Some(g) = c.gen_out.take() else { return };
        let Some(r) = c.rec.and_then(|r| self.records.get_mut(&r)) else { return };
        if g.refused {
            // A refused generation is followed, after `resync_ms`, by a whole one.
            c.resync_at = Some(WallMs(ctx.now.0.saturating_add(RESYNC_MS)));
        } else if g.base_missing {
            c.whole_next = true;
        } else {
            r.own.acked = g.generation;
            r.own.acked_reach = r.own.sent_reach;
            self.dirty_core(conn);
            self.rise(conn);
        }
    }

    /// A page of the peer's filter (spec/wire.md §11.2 Beacons).
    #[allow(clippy::too_many_arguments)]
    fn beacons(&mut self, ctx: &mut Ctx, conn: ConnId, id: Id, generation: u64, base: Option<u64>, f: u8, (lo, hi): (u64, u64), gcs: &[u8], more: bool) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let Some(r) = c.rec.and_then(|r| self.records.get_mut(&r)) else { return };
        let end = 1u64.checked_shl(u32::from(f)).unwrap_or(u64::MAX);
        let fresh = lo == 0;
        let fits = (MIN_FILTER_WIDTH..=MAX_FILTER_WIDTH).contains(&f) && hi <= end && lo < hi;
        let follows = c.peer_gen.as_ref().is_some_and(|p| p.generation == generation && p.f == f && p.base == base && p.next_lo == lo);
        let values = decode_gcs(gcs, lo, hi);
        if !fits || !(fresh || follows) || values.is_err() || (!more && hi != end) {
            ctx.wire.answer(conn, id, Msg::Error { id, code: Code::MALFORMED });
            ctx.wire.close(conn, "a filter page breaking the format");
            return;
        }
        if fresh {
            let held = base.and_then(|b| r.peer.as_ref().filter(|p| p.generation == b));
            // Additions at another width than their base's break the format.
            if held.is_some_and(|p| p.f != f) {
                ctx.wire.answer(conn, id, Msg::Error { id, code: Code::MALFORMED });
                ctx.wire.close(conn, "filter additions at another width");
                return;
            }
            let held_base = base.is_none() || held.is_some();
            c.peer_gen = Some(PeerGen { generation, base, f, next_lo: lo, held_base, values: Vec::new() });
        }
        let Some(p) = c.peer_gen.as_mut() else { return };
        p.next_lo = hi;
        if p.held_base {
            p.values.extend(values.unwrap_or_default());
        }
        // spec/wire.md §11.2 Beacons: a whole filter of n entries is `filter_width(n)` wide (so
        // at most 2^(f-8) entries); additions bring at most the whole one's n in all.
        let n = p.values.len() as u64;
        let cap = match (p.base, &r.peer) {
            (None, _) => MAX_FILTER_ENTRIES.min(1 << (f - MIN_FILTER_WIDTH)),
            (Some(_), Some(old)) => old.whole.saturating_sub(old.added),
            (Some(_), None) => 0,
        };
        let narrow = !more && p.base.is_none() && filter_width(p.values.len()).max(MIN_FILTER_WIDTH) != f;
        if p.held_base && (n > cap || narrow) {
            ctx.wire.answer(conn, id, Msg::Error { id, code: Code::MALFORMED });
            ctx.wire.close(conn, "a filter breaking its width or entry count");
            return;
        }
        let code = if p.held_base { Code::OK } else { Code::UNKNOWN_SYNC_ID };
        ctx.wire.answer(conn, id, Msg::Shared { id, items: vec![SharedItem::code(code)] });
        if more {
            return;
        }
        let Some(p) = c.peer_gen.take() else { return };
        if !p.held_base {
            return;
        }
        let mut values = p.values;
        values.sort_unstable();
        let row = records::encode_values(&values);
        let whole = match (&mut r.peer, p.base) {
            (Some(old), Some(_)) => {
                old.generation = p.generation;
                old.added += values.len() as u64;
                let all = Arc::make_mut(&mut old.values);
                all.extend(values);
                all.sort_unstable();
                old.arrived += 1;
                false
            }
            _ => {
                let arrived = r.peer.as_ref().map_or(0, |o| o.arrived) + 1;
                r.peer = Some(PeerFilter { generation: p.generation, f: p.f, whole: values.len() as u64, added: 0, values: Arc::new(values), arrived });
                true
            }
        };
        // Testing at each filter arrival: from `acked_pos` (spec/sync-opens.md §5 Testing). Other
        // tests (an answer read, a change) go on from the position tested on this connection, so a
        // refused Hit is not sent again at each answer while the peer has not acknowledged a
        // generation.
        c.tested_pos = c.tested_pos.min(r.acked_pos);
        c.test_due = true;
        if let Some(rid) = c.rec {
            let d = self.dirty(rid);
            d.core = true;
            match &mut d.filter {
                Some((_, gens)) if !whole => gens.push((p.generation, row)),
                f => *f = Some((whole, vec![(p.generation, row)])),
            }
        }
    }

    // ---- testing and Offer (§5) ----

    /// What `conn` may open S by now (spec/sync-opens.md §4 Admissible, Departed): S synced here,
    /// J of the peer, and the credentials at an epoch covering every departure where J is departed.
    fn admissible(&mut self, ctx: &mut Ctx, conn: ConnId, s: &SyncId) -> Option<Adm> {
        let creds = self.changed.at.get(s).map(|(_, _, c)| c.clone())?;
        creds.holding?;
        let c = self.conns.get(&conn)?;
        // spec/sync-opens.md §4 J: judged on the rosters held now, from what this connection proved.
        let actors = ctx.holds.actors(&c.proven);
        let j = ctx.holds.judge(s, &actors);
        let mut ok = |e: &Option<osis_crypto::Epoch>| j != J::Departed || e.as_ref().is_some_and(|e| ctx.holds.covers_departures(s, e));
        let shows = creds.shows.iter().filter(|(_, e)| ok(e)).map(|(x, _)| x.clone()).collect();
        let tests = creds.tests.iter().filter(|(_, e)| ok(e)).map(|(x, _)| x.clone()).collect();
        let step = creds.step.as_ref().filter(|(_, e)| ok(e)).map(|(k, _)| k.clone());
        Some(Adm { j, shows, tests, step })
    }

    /// Tests the pending sync IDs against the peer's latest filter and sends one Offer
    /// (spec/sync-opens.md §5 Testing): Hits first, then ByRole; at most one Offer unanswered.
    fn test(&mut self, ctx: &mut Ctx, conn: ConnId, moved: &mut Vec<Moved>) {
        let _ = &moved;
        let Some(c) = self.conns.get(&conn) else { return };
        if !c.test_due || c.phase != Phase::Running || !c.peer_digest || c.agree != Agree::Done && !matches!(c.agree, Agree::Members(_)) || c.offer.is_some() {
            return;
        }
        let Some(rid) = c.rec else { return };
        let Some(r) = self.records.get(&rid) else { return };
        let Some(pf) = r.peer.clone() else { return };
        let (rr, bind, from) = (r.r, c.bind, c.tested_pos);
        let mut pending = self.changed.after(from);
        // a walk Hit refused: S asks Behind (spec/sync-ids.md §6 Walk)
        let missed: Vec<SyncId> = c.walks.iter().filter(|(_, w)| w.missed).map(|(s, _)| *s).collect();
        if !missed.is_empty() {
            let have: BTreeSet<SyncId> = pending.iter().copied().collect();
            pending.extend(missed.into_iter().filter(|s| !have.contains(s)));
        }
        let end = self.changed.end;
        let mut sent = Vec::new();
        let mut items = Vec::new();
        let mut cut = false;
        for s in pending {
            // a refused walk Hit counts as none shown, once
            let missed = self.conns.get_mut(&conn).and_then(|c| c.walks.get_mut(&s)).is_some_and(|w| std::mem::take(&mut w.missed));
            if self.member(conn, &s).is_some() {
                continue;
            }
            let Some(adm) = self.admissible(ctx, conn, &s) else { continue };
            self.work.tested += 1;
            let mut hit = false;
            for t in &adm.tests {
                if missed && t.step().is_some() {
                    continue;
                }
                let m = t.matched(&s);
                let b = beacon_of(&m, &s, &rr);
                self.work.beacons += 1;
                if pf.values.binary_search(&beacon_value(&b, pf.f)).is_err() {
                    continue;
                }
                let h = bind.hit(&m, &s, &b);
                items.push(match t {
                    Tested::SyncKey { key, .. } | Tested::Claim { key, .. } => OfferItem::Hit { hit: h, sig: Some(bind.sign(key, &s)) },
                    Tested::Static { key, .. } => OfferItem::Static { hit: h, signing_pk: key.verifying_key().to_bytes(), sig: bind.sign(key, &s) },
                    Tested::Read(..) | Tested::Proof(_) => OfferItem::Hit { hit: h, sig: None },
                });
                sent.push(Sent::Hit { s, cred: Box::new(t.clone()), beacon: b });
                hit = true;
                // spec/sync-ids.md §6 Walk: the first shown of the walk's credentials is Hit.
                if t.step().is_some() {
                    break;
                }
            }
            if adm.j == J::Reader {
                // ByRole for S still not open that J judges the peer reads (a Hit may be a false
                // positive of the filter), with this side's Hits of its read secrets and static
                // entries.
                let hits = adm.tests.iter().filter(|t| matches!(t, Tested::Read(..) | Tested::Static { .. })).take(osis_proto::limits::MAX_ITEM_HITS).map(|t| {
                    let m = t.matched(&s);
                    bind.hit(&m, &s, &beacon_of(&m, &s, &rr))
                });
                items.push(OfferItem::ByRole { sync_id: s, hits: hits.collect() });
                sent.push(Sent::ByRole(s));
            } else if !hit && adm.j == J::SyncHolder {
                self.behind_item(ctx, conn, &s, &adm, &mut items, &mut sent);
            }
            if items.len() >= MAX_OFFER_ITEMS {
                cut = true;
                break;
            }
        }
        let Some(c) = self.conns.get_mut(&conn) else { return };
        if !cut {
            c.tested_pos = end;
            c.test_due = false;
        }
        items.truncate(MAX_OFFER_ITEMS);
        sent.truncate(MAX_OFFER_ITEMS);
        if items.is_empty() {
            self.rise(conn);
            return;
        }
        let id = ctx.wire.request(conn, Msg::Offer { id: 0, items });
        c.reqs.insert(id, Req::Offer);
        c.offer = Some(sent);
    }

    /// A Behind item for S toward a peer J judges a sync holder, when no walk credential was
    /// shown (spec/sync-ids.md §6 Behind): by a credential of the newest known step it holds one
    /// of, each step once per walk.
    fn behind_item(&mut self, ctx: &mut Ctx, conn: ConnId, s: &SyncId, adm: &Adm, items: &mut Vec<OfferItem>, sent: &mut Vec<Sent>) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let w = c.walks.entry(*s).or_default();
        let known: Vec<Tested> = w.known.iter().rev().flat_map(|st| ctx.holds.step_creds(s, st)).map(|(t, _)| t).collect();
        let cand = known.iter().chain(adm.tests.iter()).find(|t| matches!(t, Tested::SyncKey { .. } | Tested::Claim { .. } | Tested::Static { .. }) && !w.refused.contains(&t.step()));
        let Some(t) = cand else { return };
        let (key, step) = match t {
            Tested::Claim { key, step, .. } => (key, Some(*step)),
            Tested::SyncKey { key, step } | Tested::Static { key, step } => (key, *step),
            _ => return,
        };
        w.asked = true;
        let bind = c.bind;
        items.push(OfferItem::Behind(osis_proto::BehindItem { sync_id: *s, step, key: key.verifying_key().to_bytes(), sig: bind.sign(key, s) }));
        sent.push(Sent::Behind(*s, step));
    }

    /// The peer's answers to this side's Offer (spec/sync-opens.md §5 Opening): the tester opens S
    /// on the answer's valid tag, its credential still admissible, and its own proof of the
    /// replier (J, or the answer's proof); then Lost each S the peer accepted and it did not open.
    fn answered(&mut self, ctx: &mut Ctx, conn: ConnId, items: Vec<SharedItem>, moved: &mut Vec<Moved>) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let Some(sent) = c.offer.take() else { return };
        let bind = c.bind;
        let mut accepted = BTreeSet::new();
        let mut retest = false;
        for (i, x) in sent.into_iter().enumerate() {
            let a = items.get(i).cloned().unwrap_or(SharedItem::code(Code::DECLINED));
            match x {
                // A refused Hit on a walk credential (a false positive of the filter) counts as
                // none shown: S asks Behind in the next Offer (spec/sync-ids.md §6 Walk).
                Sent::Hit { s, cred, .. } if a.code != Code::OK => {
                    if cred.step().is_some()
                        && self.member(conn, &s).is_none()
                        && let Some(c) = self.conns.get_mut(&conn)
                    {
                        c.walks.entry(s).or_default().missed = true;
                    }
                }
                Sent::Hit { s, cred, beacon } => {
                    let m = cred.matched(&s);
                    // The tag: computable only with the credential and S, by the replier's side.
                    // Without it the peer showed no knowledge of S: no Lost names S to it (a
                    // false positive of the filter answered OK would learn S).
                    if a.tag != Some(bind.peer_tag(&m, &s, &beacon)) {
                        continue;
                    }
                    accepted.insert(s);
                    if self.member(conn, &s).is_some() {
                        continue;
                    }
                    let Some(adm) = self.admissible(ctx, conn, &s) else { continue };
                    // Its credential still admissible.
                    if !adm.tests.iter().any(|t| t.matched(&s) == m) {
                        continue;
                    }
                    if !self.replier_proved(ctx, &bind, &s, &cred, &a, adm.j) {
                        continue;
                    }
                    let by = cred.credential(&s);
                    self.open(conn, s, Member { class: source_class(&by, true), by, until: None }, Some(beacon), moved);
                }
                Sent::ByRole(s) if a.code == Code::OK => {
                    accepted.insert(s);
                    // An accepted ByRole opens S at its sender while J is still reader there.
                    if self.member(conn, &s).is_none() && self.admissible(ctx, conn, &s).is_some_and(|a| a.j == J::Reader) {
                        self.open(conn, s, Member { class: SourceClass::Reader, by: Credential::J, until: None }, None, moved);
                    }
                }
                Sent::Behind(s, named) => {
                    let Some(c) = self.conns.get_mut(&conn) else { continue };
                    let w = c.walks.entry(s).or_default();
                    w.asked = false;
                    match (a.code, a.grant) {
                        (Code::OK, Some(g)) => {
                            let known = ctx.holds.verify_steps(&s, named.as_ref(), &g.steps);
                            if !known.is_empty() {
                                w.known.extend(known);
                                retest = true;
                            }
                        }
                        // The source does not keep S: once it does, its filter shows its step's
                        // sync key (spec/sync-opens.md §4 Admissible) and a test opens it.
                        (Code::UNKNOWN_SYNC_ID, _) => {}
                        // Refused on a step: off the source's path; ask on an earlier one.
                        _ => {
                            w.refused.insert(named);
                        }
                    }
                    if retest {
                        self.remark(conn, &s);
                    }
                }
                _ => {}
            }
        }
        // Once all answers are read: Lost each S the peer accepted and this side did not open.
        let lost: Vec<SyncId> = accepted.into_iter().filter(|s| self.member(conn, s).is_none()).collect();
        if !lost.is_empty() {
            let items = lost.iter().map(|s| (*s, self.reported_cursor(conn, s))).collect();
            self.send_lost(ctx, conn, items);
        }
        self.rise(conn);
        if let Some(c) = self.conns.get_mut(&conn) {
            c.test_due = true;
        }
    }

    /// The tester's own proof of the replier (spec/sync-opens.md §5): J judges it a holder, or
    /// the answer proves it: a tag keyed by a secret is its own proof; for a sync key or claim, an
    /// open signature by the sync key of the step hit; for a static entry, the grant's head sync
    /// key, the grant taken once it verifies.
    fn replier_proved(&mut self, ctx: &mut Ctx, bind: &Bind, s: &SyncId, cred: &Tested, a: &SharedItem, j: J) -> bool {
        if matches!(j, J::Reader | J::SyncHolder) || cred.secret() {
            return true;
        }
        let Some(sig) = &a.sig else { return false };
        let key = match cred {
            // The replier's step is the step hit: a step older than the one hit proves nothing.
            Tested::SyncKey { key, .. } => key.verifying_key().to_bytes(),
            Tested::Claim { sync, .. } => *sync,
            // the grant's secrets are taken only once `sig` verifies under its head's sync key
            Tested::Static { key, .. } => {
                let entry = osis_crypto::static_entry(s, &key.verifying_key());
                let Some(g) = a.grant.as_ref() else { return false };
                return ctx.holds.take_grant(s, &entry, g, &|k| bind.peer_signed(k, s, sig));
            }
            Tested::Read(..) | Tested::Proof(_) => return true,
        };
        bind.peer_signed(&key, s, sig)
    }

    /// The peer's Offer (spec/sync-opens.md §5 Opening): this side opens S on a Hit that is one
    /// of its shown credentials its filter to this peer shows, carrying its proof; the session
    /// learns of the open before the answer goes.
    fn offered(&mut self, ctx: &mut Ctx, conn: ConnId, id: Id, items: Vec<OfferItem>, moved: &mut Vec<Moved>) {
        if items.iter().any(|i| matches!(i, OfferItem::Hit { .. } | OfferItem::Static { .. } | OfferItem::ByRole { .. })) {
            self.index_all(ctx, conn);
        }
        let mut answers = Vec::with_capacity(items.len());
        for item in items {
            let a = match item {
                OfferItem::Hit { hit, sig } => self.accept_hit(ctx, conn, &hit, sig.as_ref(), None, moved),
                OfferItem::Static { hit, signing_pk, sig } => self.accept_hit(ctx, conn, &hit, Some(&sig), Some(signing_pk), moved),
                OfferItem::ByRole { sync_id, hits } => self.accept_by_role(ctx, conn, sync_id, &hits, moved),
                OfferItem::Deposit(d) => {
                    let src = self.record(conn).map_or(crate::store::Source::Conn(conn), crate::store::Source::Record);
                    SharedItem::code(ctx.holds.deposit(src, &d))
                }
                // an open signature by the key it names, bound to this connection (spec/sync-ids.md
                // §6 Behind); a sync ID not kept here is 13 whatever it carries
                OfferItem::Behind(b) => match self.conns.get(&conn) {
                    Some(c) if c.bind.peer_signed(&b.key, &b.sync_id, &b.sig) => ctx.holds.behind(&b),
                    _ => ctx.holds.behind_unsigned(&b.sync_id),
                },
            };
            answers.push(a);
        }
        ctx.wire.answer(conn, id, Msg::Shared { id, items: answers });
    }

    fn accept_hit(&mut self, ctx: &mut Ctx, conn: ConnId, hit: &[u8; 32], sig: Option<&osis_crypto::Signature>, signing: Option<[u8; 32]>, moved: &mut Vec<Moved>) -> SharedItem {
        let refuse = SharedItem::code(Code::DECLINED);
        let Some(c) = self.conns.get(&conn) else { return refuse };
        let Some((s, shown, beacon)) = c.shown.get(hit).cloned() else { return refuse };
        let (bind, proven) = (c.bind, c.proven.clone());
        // Only what this side's filter to this peer shows: a read secret only to a known actor.
        if shown.secret_audience() && !peer_known(ctx.holds, &proven) {
            return refuse;
        }
        // Judged on what this side holds now: a credential no longer shown proves nothing.
        let Some(adm) = self.admissible(ctx, conn, &s) else { return refuse };
        if !adm.shows.contains(&shown) {
            return refuse;
        }
        let proved = match (&shown, signing) {
            (Shown::Read(..) | Shown::Proof(_), None) => true,
            (Shown::SyncKey(k) | Shown::Claim(k), None) => sig.is_some_and(|g| bind.peer_signed(k, &s, g)),
            (Shown::Static(e), None) => proven_statics(&s, &proven).contains(e),
            (Shown::Static(e), Some(pk)) => osis_crypto::VerifyingKey::from_bytes(&pk).is_ok_and(|k| osis_crypto::static_entry(&s, &k) == *e) && sig.is_some_and(|g| bind.peer_signed(&pk, &s, g)),
            // A deposit key's Hit carries none and opens nothing.
            _ => false,
        };
        if !proved {
            return refuse;
        }
        let secret = matches!(shown, Shown::Read(..) | Shown::Proof(_));
        // A side accepts a Hit on a sync key, claim or static entry only while it holds the sync
        // secret of its step: its answer is signed by it.
        // A Hit on a sync key is answered by that key, one of this side's steps' (a node keeping
        // S unread with no head shows each sync secret's).
        let own = match &shown {
            Shown::SyncKey(pk) => adm.tests.iter().find_map(|t| match t {
                Tested::SyncKey { key, .. } if key.verifying_key().to_bytes() == *pk => Some(key),
                _ => None,
            }),
            _ => None,
        };
        let answer_sig = match (own.or(adm.step.as_ref()), secret) {
            (_, true) => None,
            (Some(k), false) => Some(bind.sign(k, &s)),
            (None, false) => return refuse,
        };
        let grant = match &shown {
            Shown::Static(e) => ctx.holds.grant(&s, e),
            _ => None,
        };
        if self.member(conn, &s).is_none() {
            let by = shown.credential();
            self.open(conn, s, Member { class: source_class(&by, false), by, until: None }, Some(beacon), moved);
        }
        SharedItem { code: Code::OK, tag: Some(bind.tag(shown.matched(), &s, &beacon)), grant, sig: answer_sig }
    }

    /// ByRole (spec/sync-opens.md §5): opens S when this side holds S and J judges the peer a
    /// reader, or a listed Hit is its own of a read secret or a static entry, carrying its proof.
    fn accept_by_role(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, hits: &[[u8; 32]], moved: &mut Vec<Moved>) -> SharedItem {
        let Some(adm) = self.admissible(ctx, conn, &s) else { return SharedItem::code(Code::DECLINED) };
        if adm.j == J::Reader {
            if self.member(conn, &s).is_none() {
                self.open(conn, s, Member { class: SourceClass::Reader, by: Credential::J, until: None }, None, moved);
            }
            return SharedItem::code(Code::OK);
        }
        let Some(c) = self.conns.get(&conn) else { return SharedItem::code(Code::DECLINED) };
        let proven = c.proven.clone();
        let statics = proven_statics(&s, &proven);
        let known = c.known;
        let found = hits.iter().filter_map(|h| c.shown.get(h).cloned()).find(|(hs, sh, _)| {
            *hs == s
                && adm.shows.contains(sh)
                && match sh {
                    Shown::Read(..) => known,
                    Shown::Static(e) => statics.contains(e),
                    _ => false,
                }
        });
        match found {
            Some((_, sh, b)) => {
                if self.member(conn, &s).is_none() {
                    let by = sh.credential();
                    self.open(conn, s, Member { class: SourceClass::Reader, by, until: None }, Some(b), moved);
                }
                SharedItem::code(Code::OK)
            }
            None => SharedItem::code(Code::DECLINED),
        }
    }

    // ---- members, ending and Lost (§6) ----

    fn member(&self, conn: ConnId, s: &SyncId) -> Option<&Member> {
        self.members(conn).get(s)
    }

    fn open(&mut self, conn: ConnId, s: SyncId, m: Member, beacon: Option<[u8; 32]>, moved: &mut Vec<Moved>) {
        let Some(rid) = self.conns.get(&conn).and_then(|c| c.rec) else { return };
        let Some(r) = self.records.get_mut(&rid) else { return };
        r.members.insert(s, m);
        r.basis.insert(s, beacon);
        let rejoin = r.stopped.remove(&s).unwrap_or(Rejoin::Held);
        self.dirty(rid).members.insert(s);
        self.holding.entry(s).or_default().insert(conn);
        moved.push(Moved::Joined(conn, s, rejoin));
    }

    /// Re-judges member S of `conn` (spec/sync-opens.md §6): J reader or sync holder stays; an
    /// open by a credential stays while it is admissible; one no longer admissible whose peer J
    /// judges neither holder nor departed is ended (`until`); any other closes at once with a Lost.
    fn rejudge(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, moved: &mut Vec<Moved>) {
        let Some(m) = self.member(conn, &s).cloned() else { return };
        self.work.rejudged += 1;
        let Some(adm) = self.admissible(ctx, conn, &s) else {
            // S left the sync set: closes at once.
            self.close_member(ctx, conn, s, true, moved);
            return;
        };
        let rr = self.conns.get(&conn).and_then(|c| c.rec).and_then(|r| self.records.get(&r)).map(|r| r.r).unwrap_or_default();
        let basis = self.conns.get(&conn).and_then(|c| c.rec).and_then(|r| self.records.get(&r)).and_then(|r| r.basis.get(&s).copied()).flatten();
        let holder = matches!(adm.j, J::Reader | J::SyncHolder);
        let admissible = m.by != Credential::J
            && basis.is_some_and(|b| adm.shows.iter().any(|x| beacon_of(x.matched(), &s, &rr) == b) || adm.tests.iter().any(|t| beacon_of(&t.matched(&s), &s, &rr) == b));
        let stays = holder || admissible;
        if stays {
            // A member ended and then judged holder or admissible again is no longer ended.
            self.set_until(conn, &s, None, moved);
        } else if m.by == Credential::J || adm.j == J::Departed {
            self.close_member(ctx, conn, s, true, moved);
        } else if m.until.is_none() {
            let until = ctx.holds.until(&s, &m.by);
            self.set_until(conn, &s, Some(until), moved);
            self.close_if_reached(ctx, conn, s, moved);
        }
    }

    /// Sets or clears member S's `until`; streams hears of it (`Moved::Until`).
    fn set_until(&mut self, conn: ConnId, s: &SyncId, until: Option<Position>, moved: &mut Vec<Moved>) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let Some(m) = c.rec.and_then(|r| self.records.get_mut(&r)).and_then(|r| r.members.get_mut(s)) else { return };
        if m.until == until {
            return;
        }
        m.until = until;
        if until.is_some() {
            c.ending.insert(*s);
        } else {
            c.ending.remove(s);
        }
        moved.push(Moved::Until(conn, *s));
        self.dirty_member(conn, *s);
    }

    /// The peer's reported position's cursor for S on `conn` (spec/sync-opens.md §6 Lost).
    fn reported_cursor(&self, conn: ConnId, s: &SyncId) -> Option<Cursor> {
        self.reported_at(conn, s).map(|(_, c)| c.clone())
    }

    /// Closes member S of `conn`; with `lost`, back to testing with a Lost naming where it stopped
    /// (the member is closed before its Lost goes).
    fn close_member(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, lost: bool, moved: &mut Vec<Moved>) {
        let Some(m) = self.member(conn, &s).cloned() else { return };
        // Where it stopped for the peer: its reported position, or `until` where lower.
        let mut cursor = self.reported_cursor(conn, &s);
        if let (Some(u), Some((p, _))) = (m.until, self.reported_at(conn, &s))
            && u < *p
        {
            cursor = ctx.holds.cursor_at(u);
        }
        // Closed here with a Lost: it rejoins from the start unless the peer's Lost names where it
        // stopped (spec/sync-opens.md §6: a crossed Lost lost with its connection skips nothing).
        self.drop_member(conn, s, !lost, moved);
        self.remark(conn, &s);
        if lost {
            self.send_lost(ctx, conn, vec![(s, cursor)]);
        }
    }

    /// Removes member S from `conn`'s record; `keep`: its rejoin reads from where this side's
    /// stream holds it, else (a digest difference, or closed here with a Lost) from the start.
    fn drop_member(&mut self, conn: ConnId, s: SyncId, keep: bool, moved: &mut Vec<Moved>) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let Some(r) = c.rec.and_then(|r| self.records.get_mut(&r)) else { return };
        let Some(m) = r.members.remove(&s) else { return };
        let at = LeftAt { reported: c.reported.get(&s).map(|(p, _)| *p), until: m.until };
        c.reported.forget(&s);
        self.reports.wrote(&conn, true);
        c.ending.remove(&s);
        r.basis.remove(&s);
        r.stopped.insert(s, if keep { Rejoin::Held } else { Rejoin::From(None) });
        if let Some(set) = self.holding.get_mut(&s) {
            set.remove(&conn);
        }
        moved.push(Moved::Left(conn, s, at));
        self.dirty_member(conn, s);
    }

    fn send_lost(&mut self, ctx: &mut Ctx, conn: ConnId, items: Vec<(SyncId, Option<Cursor>)>) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        for chunk in items.chunks(MAX_OFFER_ITEMS) {
            let items = chunk.iter().map(|(s, cur)| (*s, cur.clone().and_then(|b| osis_proto::Cursor::new(b).ok()))).collect();
            let id = ctx.wire.request(conn, Msg::Lost { id: 0, items });
            c.reqs.insert(id, Req::Lost);
        }
    }

    /// The peer's Lost (spec/sync-opens.md §6): each member named closes, where it stopped kept
    /// (also when this side closed it first), S re-marked; a member this side was ending is
    /// answered with its own Lost.
    fn lost(&mut self, ctx: &mut Ctx, conn: ConnId, id: Id, items: Vec<osis_proto::Join>, moved: &mut Vec<Moved>) {
        let n = items.len();
        let mut answer = Vec::new();
        for (s, cur) in items {
            let cursor = cur.map(osis_proto::Cursor::into_bytes);
            let ending = self.member(conn, &s).and_then(|m| m.until);
            // where it stopped for the peer, read before the member goes
            let (rc, rp) = (self.reported_cursor(conn, &s), self.reported_at(conn, &s).map(|(p, _)| *p));
            if self.member(conn, &s).is_some() {
                self.drop_member(conn, s, true, moved);
            }
            self.remark(conn, &s);
            // Kept for a member that left (also one this side closed first: the two crossed);
            // a Lost naming anything else keeps nothing.
            if let Some(r) = self.conns.get(&conn).and_then(|c| c.rec).and_then(|r| self.records.get_mut(&r))
                && let Some(at) = r.stopped.get_mut(&s)
            {
                *at = Rejoin::From(cursor);
                self.dirty_member(conn, s);
            }
            if let Some(u) = ending {
                let c = if rp.is_none_or(|p| u < p) { ctx.holds.cursor_at(u).or(rc) } else { rc };
                answer.push((s, c));
            }
        }
        ctx.wire.answer(conn, id, Msg::Shared { id, items: vec![SharedItem::code(Code::OK); n] });
        if !answer.is_empty() {
            self.send_lost(ctx, conn, answer);
        }
    }

    /// Re-marks S for `conn`'s record (spec/sync-opens.md §5 Testing): its `acked_pos` and the
    /// tested position drop below `changed_at(S)`, and a test is due.
    /// A sync ID not in this node's sync set has no `changed_at`: re-marking it changes nothing.
    fn remark(&mut self, conn: ConnId, s: &SyncId) {
        if !self.changed.at.contains_key(s) {
            return;
        }
        let below = self.changed.pos(s).saturating_sub(1);
        let Some(c) = self.conns.get_mut(&conn) else { return };
        c.tested_pos = c.tested_pos.min(below);
        c.test_due = true;
        if let Some(r) = c.rec.and_then(|r| self.records.get_mut(&r))
            && r.acked_pos > below
        {
            r.acked_pos = below;
            self.dirty_core(conn);
        }
    }

    /// `acked_pos` rises, with no Offer unanswered, to the lower of the position the peer's last
    /// acknowledged generation reached and the position tested (spec/sync-opens.md §5 Testing).
    fn rise(&mut self, conn: ConnId) {
        let Some(c) = self.conns.get(&conn) else { return };
        if c.offer.is_some() {
            return;
        }
        let tested = c.tested_pos;
        let Some(r) = c.rec.and_then(|r| self.records.get_mut(&r)) else { return };
        let to = r.acked_pos.max(r.own.acked_reach.min(tested));
        if to != r.acked_pos {
            r.acked_pos = to;
            self.dirty_core(conn);
        }
    }
}

/// The actors `p` proved that are known here now, sorted (spec/sync-opens.md §3: a record is
/// honoured only while a proven actor of the session is named by it and known here now).
fn named_known(holds: &mut dyn Holds, p: &Proven) -> Vec<Tid> {
    holds.actors(p).into_iter().filter(|a| holds.known_actor(a)).collect()
}

/// Whether the peer proved a known actor (spec/sync-opens.md §4 Audiences), judged now.
fn peer_known(holds: &mut dyn Holds, p: &Proven) -> bool {
    !named_known(holds, p).is_empty()
}

/// The static entries of S whose key actor the peer proved on this connection by its signing key
/// (spec/sync-opens.md §5 Proof).
fn proven_statics(s: &SyncId, p: &Proven) -> Vec<[u8; 32]> {
    p.key_actors.values().filter_map(|k| osis_crypto::VerifyingKey::from_bytes(k).ok()).map(|k| osis_crypto::static_entry(s, &k)).collect()
}

fn random32(rng: &mut dyn NodeRng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b
}

fn random16(rng: &mut dyn NodeRng) -> RecordId {
    let mut b = [0u8; 16];
    rng.fill_bytes(&mut b);
    b
}

/// The product's `Wire`: the driver's sessions.
impl Wire for Sessions {
    fn bind(&self, c: ConnId) -> Option<(Bind, Proven)> {
        let s = self.get(c)?;
        let b = s.binding()?;
        let (own, peer) = if s.dialer { (b.dialer_challenge, b.listener_challenge) } else { (b.listener_challenge, b.dialer_challenge) };
        Some((Bind { dialer: s.dialer, own_challenge: own, peer_challenge: peer, listener_key: b.listener_key, rank: s.rank }, s.proven().clone()))
    }

    fn request(&mut self, c: ConnId, m: Msg) -> Id {
        self.get_mut(c).map_or(0, |s| s.request(crate::session::To::Opens, m))
    }

    fn answer(&mut self, c: ConnId, to: Id, m: Msg) {
        if let Some(s) = self.get_mut(c) {
            s.answer(to, m);
        }
    }

    fn push(&mut self, c: ConnId, m: Msg) {
        if let Some(s) = self.get_mut(c) {
            s.push_now(m);
        }
    }

    fn close(&mut self, c: ConnId, why: &'static str) {
        if let Some(s) = self.get_mut(c) {
            s.close(why);
        }
    }
}
