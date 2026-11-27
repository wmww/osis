//! Records, agreement and the shared set (spec/sync-opens.md §2-§6, spec/sync-ids.md §6 Walk).
//!
//! **Principle:** each side opens S toward a peer only on its own proof, judged on what it holds
//! now, that the peer may hold S; who dialed proves nothing (model core/test/tla/net/NetOpen.tla:
//! every rule it flags is one function here, named in that function's comment).
//!
//! State: records (spec/sync-opens.md §3: pair key, proven claims, the shared set with each
//! member's credential and beacon, `acked_pos`, this side's filter generations and the peer's
//! latest filter, where members that left stopped); per connection its binding, phase,
//! agreement, filter generations in flight, the Hits its filter makes possible, the Offer in
//! flight, reported positions and walk state; `changed_at` per S with the credentials it was
//! advanced for. Work follows change: a sync ID whose credentials moved advances `changed_at`,
//! judges its member in every record in memory holding it, connected or not (`held`), and makes
//! a filter addition and a test due on each connection; nothing walks every sync ID per connection but a whole
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
use crate::store::{Source, Store};
use crate::types::{ConnId, Credential, Cursor, Cx, Position, RecordId, Result, SourceClass};
use crate::unread::Unread;
use cred::{Bind, Shown, Tested, beacon_of};
use holds::{Creds, Holds, NodeHolds};
pub use holds::named;
use osis_store::Named;
use osis_base::{Mono, SyncId};
use osis_crypto::NodeRng;
use osis_crypto::kdf::{members_digest, pair_key, resume_tag, resumed_tag};
use osis_engine::sync::J;
use osis_blob::StepId;
use osis_proto::filter::{Beacons, Run, beacon_value, count_gcs, filter_width, pages};
use osis_proto::limits::{MAX_FILTER_ENTRIES, MAX_FILTER_WIDTH, MAX_MEMBERS, MAX_OFFER_ITEMS, MAX_RESUME_TAGS, MIN_FILTER_WIDTH, NO_RECORD_ID, REPLY_BUDGET};
use osis_proto::{Code, Id, Msg, OfferItem, SharedItem};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A member of a connection's shared set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// The peer's class, as it declared opening S (spec/sync-opens.md §4 Source).
    pub class: SourceClass,
    /// This side's class as it declared it then: a move closes the member (§6).
    pub own: SourceClass,
    pub by: Credential,
    /// Being ended: served up to this position.
    pub until: Option<Position>,
    /// Ended for its peer's departure (spec/sync-opens.md §6), with the things the peer proved:
    /// told their removals (`tell`) and served the public's edge alone; at a store source it closes on the peer's
    /// Lost alone, and registering there waits on no role commit.
    pub departed: Option<Arc<BTreeSet<osis_base::Tid>>>,
}

/// A change of a connection's shared set: the driver hands each to `Streams::moved`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Moved {
    /// S became a member on `conn` (newly open, or open again), rejoining from where opens says.
    Joined(ConnId, SyncId, Rejoin),
    /// S stopped being a member on `conn` (closed, or the connection of a record kept nowhere
    /// ended), with where the peer stood then.
    Left(ConnId, SyncId, LeftAt),
    /// Member S's `until` was set or cleared.
    Until(ConnId, SyncId),
    /// Where S, closed on `conn` earlier, stopped is no longer kept: what its source showed goes
    /// (spec/sync-opens.md §6 Where it stopped).
    Forgot(ConnId, SyncId),
    /// Member S of kept record R, which no connection holds, closed (judged in the step of a
    /// change, or S left the sync set): what is kept of S for that source goes.
    Gone(RecordId, SyncId),
    /// Kept record R is connected on `conn` (`Opens::conn_of`): its members are that
    /// connection's, standing where the record holds them. No member moves. `true`: the record
    /// was just read from its rows (a restart's), so nothing of its members was followed: the
    /// modules learn them now (`Opens::members`).
    Taken(ConnId, RecordId, bool),
    /// `conn` let kept record R go: the record keeps its members where they stand.
    Released(ConnId, RecordId),
}

/// Where a member's peer stood as it left: what status still counts it holding (spec/sync-status.md
/// §2: a report taken in the step that closed it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeftAt {
    /// The record it left: where its rows live (a record kept nowhere: the connection).
    pub src: Source,
    /// Its reported position (spec/sync-opens.md §6 Lost), as it tells what the peer holds
    /// (spec/sync-status.md §2): none for one ended for its departure, shown the public's edge alone.
    pub reported: Option<Position>,
    /// Its `until`, an ended member's.
    pub until: Option<Position>,
    /// How it left (spec/sync-opens.md §6 Where it stopped).
    pub how: Leaving,
}

/// How a member left a connection's shared set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leaving {
    /// Closed, where it stopped kept while the connection lasts.
    Kept,
    /// Closed keeping nothing of where it stopped: what its source showed goes, and its rejoin is
    /// from the start.
    Forgot,
}

/// Why a member closes here (spec/sync-opens.md §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Close {
    /// Its `until` reached: where its own stream holds it is kept until the peer's Lost.
    Until,
    /// J departed: nothing kept.
    AtOnce,
    /// S left this node's sync set: nothing kept, and its Lost names no position.
    Left,
    /// This side's class moved: kept as at `Until`, and S opens again by testing.
    Class,
}

impl Moved {
    /// The connection it moved on (none for a record no connection holds).
    pub fn conn(&self) -> Option<ConnId> {
        match self {
            Moved::Joined(c, ..) | Moved::Left(c, ..) | Moved::Until(c, _) | Moved::Forgot(c, _) | Moved::Taken(c, ..) | Moved::Released(c, _) => Some(*c),
            Moved::Gone(..) => None,
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
    /// The monotonic clock its waits (resync, retries) run on.
    pub mono: Mono,
}

/// Work done, counted (tests: scaling by counting work, notes/principles.md).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Work {
    /// Members re-judged.
    pub rejudged: u64,
    /// Members whose standing (`Holds::standing`) came due.
    pub standing: u64,
    /// Beacons computed (filters and tests).
    pub beacons: u64,
    /// Sync IDs tested against a peer's filter.
    pub tested: u64,
    /// `Holds::creds` read.
    pub creds: u64,
}

/// A record (spec/sync-opens.md §3), as a connection holding it sees it. One kept nowhere
/// (`kept` false) serves a connection on which either side proved nothing, and goes with it.
#[derive(Clone, Debug)]
struct Record {
    r: [u8; 32],
    named: Named,
    kept: bool,
    members: BTreeMap<SyncId, Member>,
    /// The beacon each member was opened by (none: by J).
    basis: BTreeMap<SyncId, Option<[u8; 32]>>,
    /// Where each member closed on the connection holding the record stopped (spec/sync-opens.md
    /// §6 Where it stopped): where this side's stream holds it (closed here at its `until`), or the
    /// peer's Lost's cursor. Memory only: it goes when that connection lets the record go.
    stopped: BTreeMap<SyncId, Rejoin>,
    /// Where this side's walk of each S stopped at the peer (`Opens::stops`; a kept record only).
    walk: BTreeMap<SyncId, Stop>,
    acked_pos: u64,
    own: OwnFilter,
    peer: Option<PeerFilter>,
    /// Its members were told to the modules (an open, a take's `Moved::Taken`); a record the
    /// start read to follow its members is told at its first take.
    told: bool,
}

/// This side's filter as sent through the record.
#[derive(Clone, Debug, Default)]
struct OwnFilter {
    /// The last generation sent, and the last the peer acknowledged.
    generation: u64,
    acked: u64,
    /// The filter as of the last generation sent, and as of the last acknowledged: after a
    /// generation never acknowledged the next counts the entries of both (spec/sync-opens.md §5).
    shape: Shape,
    acked_shape: Shape,
    /// The `changed_at` position the last generation sent covers, and the one the last
    /// acknowledged covers (one generation is in flight at a time).
    sent_reach: u64,
    acked_reach: u64,
}

/// A filter's width, the entries of its whole generation, and of the additions since.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Shape {
    f: u8,
    whole: u64,
    added: u64,
}

#[derive(Clone, Debug)]
struct PeerFilter {
    generation: u64,
    f: u8,
    /// Up to `MAX_FILTER_ENTRIES` and as many added, held while a connection holds the record,
    /// as coded (about what the peer sent: notes/decode-bounds.md).
    values: Arc<Beacons>,
    /// Entries of its whole generation, and of the additions since (at most `whole` in all).
    whole: u64,
    added: u64,
    /// Generations arrived through this record, counted here (the peer's numbering is its word).
    arrived: u64,
    /// `values` holds the entries (else they are in the record's rows: no connection holds it).
    held: bool,
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
    /// `own`: the class this side declared in it.
    Hit { s: SyncId, cred: Box<Tested>, beacon: [u8; 32], own: SourceClass },
    ByRole(SyncId, SourceClass),
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
    /// Whole, or additions on the generation held itself (not a later one).
    exact: bool,
    /// The generation's entries so far, as coded.
    values: Run,
}

#[derive(Clone, Debug, Default)]
struct WalkState {
    /// Steps the source gave, verified (spec/sync-ids.md §6 Known steps).
    known: Vec<osis_blob::Step>,
    /// Steps a Behind was refused on, this walk.
    refused: BTreeSet<Option<StepId>>,
    /// A Hit on a walk credential refused: S is tested again.
    missed: bool,
    /// The walk credentials whose Hit was refused (a false positive of the filter, or a beacon
    /// the peer no longer shows: nothing leaves a stored filter), by match value: each counts
    /// as not shown until S opens here (spec/sync-ids.md §6 Walk).
    unshown: BTreeSet<[u8; 32]>,
    /// Behind answers refused for now (4) in a row: the next ask waits `inbox::backoff_ms` of
    /// it (`Conn::retries`).
    backoffs: u32,
    /// Its back-off is over (`Conn::retries`, taken at the tick): the next test tests S again.
    retry: bool,
}

#[derive(Clone, Debug)]
struct Conn {
    bind: Bind,
    proven: Proven,
    /// The claims of the peer's proofs: what a record of this connection
    /// names (none: no record). Who the peer is now: `counted`.
    named: Named,
    phase: Phase,
    rec: Option<RecordId>,
    agree: Agree,
    peer_digest: bool,
    reqs: BTreeMap<Id, Req>,
    gen_out: Option<GenOut>,
    resync_at: Option<Mono>,
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
    /// A filter arrived since the sync IDs tested by the public entry alone were last tested
    /// (`Changed::public_tested`).
    public_due: bool,
    offer: Option<Vec<Sent>>,
    /// Reported positions (spec/sync-opens.md §6 Lost): streams' word, through `reported`.
    reported: Positions,
    /// Members with an `until`: what a reported position may close.
    ending: BTreeSet<SyncId>,
    walks: BTreeMap<SyncId, WalkState>,
    /// Walks whose Behind was refused for now (4), by when they ask again (spec/sync-ids.md §6
    /// Behind: asked again after a back-off); due ones join the next test.
    retries: BTreeSet<(Mono, SyncId)>,
    /// It lost its record to this connection (spec/sync-opens.md §1 One connection per pair):
    /// it closes, and acts on nothing meanwhile.
    lost_to: Option<ConnId>,
    /// Per S, the highest `until` an ended member reached on this connection: a Hit on a lapsed
    /// or superseded read secret opens S again here only for a later one (spec/sync-opens.md §6).
    served: BTreeMap<SyncId, Position>,
    /// The notices sent on this connection, per S by content, and the S whose peer was sent a
    /// notice of its departure here (`tell`).
    told: BTreeSet<(SyncId, [u8; 32])>,
    told_departed: BTreeSet<SyncId>,
    /// The S whose ByRole this side refused, J judging the peer no holder: its standing is
    /// followed, and S re-marked here once J judges it one (spec/sync-opens.md §5 ByRole).
    asked: BTreeSet<SyncId>,
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
    /// The sync IDs whose credentials test the public entry without showing it (a locator
    /// redeemed: spec/sync-opens.md §5 Testing): tested at each
    /// filter arrival, since a peer's filter shows the entry once the public reads S's thing,
    /// whatever this node's own credentials did.
    public_tested: BTreeSet<SyncId>,
}

impl Changed {
    fn pos(&self, s: &SyncId) -> u64 {
        self.at.get(s).map_or(0, |(p, ..)| *p)
    }

    fn after(&self, from: u64) -> Vec<SyncId> {
        self.order.range(from.saturating_add(1)..).map(|(_, s)| *s).collect()
    }
}

/// Kept records by acknowledgement position, grouped by the claims each names (a peer is what it
/// proves: two records naming the same claims are not told apart, spec/sync-opens.md §1 One
/// connection per pair, Limit): what `wait_for` reads for a peer the rosters say may hold S none
/// of whose records has acknowledged S's current credentials, each of its records judged by
/// what it names (its account's key included). Loaded from the store at the first
/// settle (O(records)), then kept by each move of a record's `acked_pos` or claims, a record made
/// and a record evicted. Bound: one entry per kept record (`RECORD_BUDGET`).
#[derive(Clone, Debug, Default)]
struct Acks {
    rec: BTreeMap<RecordId, (u64, Named)>,
    by_claims: BTreeMap<Named, BTreeSet<(u64, RecordId)>>,
    /// Per claims, the highest `acked_pos` of their records.
    by_pos: BTreeSet<(u64, Named)>,
}

impl Acks {
    fn set(&mut self, id: RecordId, now: Option<(u64, &Named)>) {
        if let Some((p, n)) = self.rec.remove(&id) {
            self.regroup(&n, |g| {
                g.remove(&(p, id));
            });
        }
        if let Some((p, n)) = now {
            self.regroup(n, |g| {
                g.insert((p, id));
            });
            self.rec.insert(id, (p, n.clone()));
        }
    }

    /// Changes the records naming `a` by `f`, keeping their highest position in `by_pos`.
    fn regroup(&mut self, a: &Named, f: impl FnOnce(&mut BTreeSet<(u64, RecordId)>)) {
        let g = self.by_claims.entry(a.clone()).or_default();
        let was = g.last().map(|(p, _)| *p);
        f(g);
        let now = g.last().map(|(p, _)| *p);
        if g.is_empty() {
            self.by_claims.remove(a);
        }
        if was != now {
            if let Some(p) = was {
                self.by_pos.remove(&(p, a.clone()));
            }
            if let Some(p) = now {
                self.by_pos.insert((p, a.clone()));
            }
        }
    }
}

/// How a peer counts for `Opens::wait_for`, by the claims it proved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    /// Never waited for (this account's own nodes, for a self-removal; a peer no one now).
    Skipped,
    /// Who it may be says it may hold S (`Engine::may_hold`): waited for also while its
    /// record has not acknowledged S's current credentials.
    MayHold,
    /// Waited for only while it has S open or its record holds S.
    Unlisted,
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
    /// The records in memory holding each sync ID as a member, whether a connection holds them
    /// or not (`on` says which): what a change of S judges.
    held: BTreeMap<SyncId, BTreeSet<RecordId>>,
    /// The memo effects the product's `Holds` settles.
    fx: holds::Fx,
    /// Stamped per connection as its reported positions move (`reported_at`: status follows it).
    reports: osis_base::memo::Stamps,
    /// Stamped per S as a connection or record gains or loses it as a member, as a record's
    /// acknowledgement passes or falls below `changed_at(S)` or S's `changed_at` moves, whole as
    /// records are evicted or `acks` loads (`wait_for`: leave, status and life follow it).
    peers: osis_base::memo::Stamps,
    /// Stamped per (connection, S) as the connection's member S opens, changes (ended,
    /// departed) or goes, the connection taking or letting go its record included (`member`:
    /// inbox and read judge by it).
    member_stamps: osis_base::memo::Stamps,
    /// Stamped per (source, S) as the record's member S opens, changes or goes (`member_at`:
    /// what is judged of a record's member whatever connection holds it); never by a take or a
    /// release.
    record_members: osis_base::memo::Stamps,
    /// Stamped per source as a connection takes or lets go its record or its digests agree
    /// (`conn_of`, `agreed_on`).
    connected: osis_base::memo::Stamps,
    /// Stamped per S as the records in memory holding it move, never by a take or a release
    /// (`sources_of`), and fed with each (S, source) coming to be one (`sources_feed`).
    sources: osis_base::memo::Stamps,
    /// Kept records by `acked_pos` (`wait_for`); none before the first settle loads it.
    acks: Option<Acks>,
    /// Per S, the connections whose walk stopped there (spec/sync-ids.md §6 Stranded there), each
    /// with the sync key of the step it stopped at (none: this node's recorded head). Goes with
    /// the connection, S opening there, and S leaving the sync set (`walk_stop`: status follows it).
    stops: osis_base::memo::Stamped<SyncId, BTreeMap<ConnId, Stop>>,
    /// Other records of a pair one connection took (spec/sync-opens.md §3 One record per pair):
    /// removed at `flush` once no connection holds or lists one.
    dropped: BTreeSet<RecordId>,
    /// The connection holding each record: record R is connected on C.
    on: BTreeMap<RecordId, ConnId>,
    /// Records that left memory since `unloaded` was last read: streams keeps a record's place
    /// in memory as long as opens keeps the record.
    unloaded: Vec<RecordId>,
    /// Per record, the members whose J `Holds` follows (`Holds::standing`): followed across the
    /// record's connections, from S's open or the take that judged it until S leaves the record,
    /// the record goes (evicted, dropped, a record kept nowhere let go), S leaves the sync set,
    /// what the record names moves, or its J moves while no connection holds it.
    followed: BTreeMap<RecordId, BTreeSet<SyncId>>,
    /// Members of `followed` to unfollow at the next `tick` (one opened again meanwhile is
    /// followed still).
    unfollowed: BTreeSet<(RecordId, SyncId)>,
    /// Kept records a connection let go since the last settle: a member whose peer is no one
    /// closes once none holds the record.
    let_go: Vec<RecordId>,
    /// Every kept record with a member is in memory and followed (read at the first settle).
    following: bool,
    work: Work,
}

/// Where a walk stopped at a source: the sync key of the step (none: the recorded head).
pub type Stop = Option<[u8; 32]>;

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
            held: BTreeMap::new(),
            fx: holds::Fx::default(),
            reports: osis_base::memo::Stamps::named("opens: reports"),
            peers: osis_base::memo::Stamps::named("opens: peers"),
            member_stamps: osis_base::memo::Stamps::named("opens: members"),
            record_members: osis_base::memo::Stamps::named("opens: record members"),
            connected: osis_base::memo::Stamps::named("opens: connected"),
            sources: osis_base::memo::Stamps::named("opens: sources"),
            acks: None,
            stops: osis_base::memo::Stamped::default(),
            dropped: BTreeSet::new(),
            on: BTreeMap::new(),
            unloaded: Vec::new(),
            followed: BTreeMap::new(),
            unfollowed: BTreeSet::new(),
            let_go: Vec::new(),
            following: false,
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
    /// This node follows S by a locator's value alone, holding none of its thing's secrets
    /// (`Creds::by_role`): it asks every peer to open S by role and judges none of them.
    by_role: bool,
    /// Kept unread past its keys (`Creds::stopped`): it asks every peer to open S by role, beside
    /// its Hits, and judges none of them.
    stopped: bool,
    /// This node's class for S now (spec/sync-opens.md §4 Source).
    own: SourceClass,
    shows: Vec<Shown>,
    tests: Vec<Tested>,
    /// Where J is departed: the sync proofs of this side's recorded steps (`Creds::walk`, and
    /// the newest the Departed rule keeps out of `shows`), taken from a store only, and its read
    /// secrets at superseded epochs, shown in the filter: an open by one is ended at once, so this
    /// side registers past a store's keys or tells a reader its removals
    /// (spec/sync-opens.md §6), whether or not S was open there at the removal. Toward every peer, the lapsed
    /// read secrets (`Creds::lapsed`), taken from a reader or keys holder: ended at once likewise.
    walk: Vec<Shown>,
    step: Option<osis_crypto::SigningSecret>,
}

impl Opens {
    // ---- the product's entry points ----

    /// `Proved` (Resume or NoRecord, then Digest); Resume, Resumed, Digest, Members, Beacons,
    /// Offer, Shared, Lost.
    pub fn on_message(&mut self, cx: &mut Cx, sessions: &mut Sessions, unread: &Unread, conn: ConnId, m: Incoming, moved: &mut Vec<Moved>) {
        self.live(cx, sessions, unread, |o, ctx| o.message(ctx, conn, m, moved));
    }

    /// `f` over the node's own holds, sessions and store.
    fn live<T>(&mut self, cx: &mut Cx, sessions: &mut Sessions, unread: &Unread, f: impl FnOnce(&mut Self, &mut Ctx) -> T) -> T {
        let mono = cx.mono;
        let mut fx = std::mem::take(&mut self.fx);
        let mut store = cx.store.clone();
        let mut holds = NodeHolds { cx, unread, fx: &mut fx };
        let out = osis_base::costs::scoped("opens", || f(self, &mut Ctx { holds: &mut holds, wire: sessions, store: &mut store, mono }));
        self.fx = fx;
        out
    }

    /// The end of the node's step: what changed of each record is written, records past the
    /// budget go (least recently used first, none a connection holds) with what was charged to
    /// them, in one transaction (`Store::write_records`), memory's with them; a kept record no
    /// connection holds stays in memory while it has a member, without its peer's filter entries
    /// (read again at its next take). Returns the records that went (evicted, and others of
    /// a pair dropped). A store failure met during the step fails it here.
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
        let dropped: BTreeSet<RecordId> = self.dropped.iter().filter(|id| !in_use.contains(*id)).copied().collect();
        let evicted = store.write_records(budget, &in_use, &dropped, |t| {
            for (id, d) in dirty {
                if let Some(r) = records.get(&id).filter(|r| r.kept) {
                    records::write(t, &id, r, d)?;
                }
            }
            Ok(())
        })?;
        for id in evicted.iter().chain(&dropped) {
            self.forget_record(*id, Source::Record(*id));
        }
        if !evicted.is_empty() {
            if let Some(acks) = &mut self.acks {
                for id in &evicted {
                    acks.set(*id, None);
                }
            }
            self.peers.wrote_all();
        }
        self.dropped.retain(|id| !dropped.contains(id));
        let held: BTreeSet<RecordId> = self.conns.values().filter_map(|c| c.rec).collect();
        // a kept record no connection holds stays in memory only for its members (what is judged
        // of them across its connections), without its peer's filter entries: one with none
        // keeps nothing there that its rows do not, so a dialer proving fresh link keys with no
        // right to any S costs memory only while connected
        let unloaded = &mut self.unloaded;
        self.records.retain(|id, r| {
            let stays = !r.kept || held.contains(id) || !r.members.is_empty();
            if !stays {
                unloaded.push(*id);
            }
            stays
        });
        for (_, r) in self.records.iter_mut().filter(|(id, r)| r.kept && !held.contains(*id)) {
            if let Some(p) = r.peer.as_mut().filter(|p| p.held) {
                p.values = Arc::default();
                p.held = false;
            }
        }
        Ok(evicted.into_iter().chain(dropped).collect())
    }

    /// The records that left memory since this was last read (evicted, dropped, let go) and are
    /// not back in it.
    pub fn unloaded(&mut self) -> Vec<RecordId> {
        let records = &self.records;
        std::mem::take(&mut self.unloaded).into_iter().filter(|id| !records.contains_key(id)).collect()
    }

    /// Record `id` leaves memory (evicted, dropped, a record kept nowhere let go): its members
    /// go from `held`, are unfollowed at the next `tick`, and read as gone. `src`: where its rows
    /// live.
    fn forget_record(&mut self, id: RecordId, src: Source) -> Option<Record> {
        self.unfollow_record(id);
        let r = self.records.remove(&id)?;
        self.unloaded.push(id);
        for s in r.members.keys() {
            self.hold(*s, id, None);
            self.record_members.wrote(&(src, *s), false);
        }
        Some(r)
    }

    /// Record `rid` in memory holds S as a member at `src` (`Some`), or not (`held`): S's sources
    /// moved (`sources`).
    fn hold(&mut self, s: SyncId, rid: RecordId, src: Option<Source>) {
        let was = self.held.get(&s).map_or(0, BTreeSet::len);
        match src {
            Some(src) => {
                if self.held.entry(s).or_default().insert(rid) {
                    // a record read from its rows: what read of its members moves too
                    self.record_members.wrote(&(src, s), true);
                    self.sources.wrote_added(&(s, src), true, true);
                }
            }
            None => {
                if let Some(set) = self.held.get_mut(&s) {
                    set.remove(&rid);
                    if set.is_empty() {
                        self.held.remove(&s);
                    }
                }
            }
        }
        let now = self.held.get(&s).map_or(0, BTreeSet::len);
        if now != was {
            self.sources.wrote(&s, true);
        }
        if (now == 0) != (was == 0) {
            self.sources.wrote(&("any", s), true);
        }
    }

    /// The sources of S: each record in memory holding S as a member, whether or not a
    /// connection holds it (a record kept nowhere: its connection). Stamped per S: a take or
    /// release moves nothing of it.
    pub fn sources_of(&self, s: &SyncId) -> Vec<Source> {
        self.sources.read(s);
        let of = |id: &RecordId| match self.records.get(id) {
            Some(r) if r.kept => Some(Source::Record(*id)),
            Some(_) => self.conn_on(*id).map(Source::Conn),
            None => None,
        };
        self.held.get(s).into_iter().flatten().filter_map(of).collect()
    }

    /// Whether S has a source (`sources_of`): moves only when that flips.
    pub fn has_sources(&self, s: &SyncId) -> bool {
        self.sources.read(&("any", *s));
        self.held.contains_key(s)
    }

    /// A cursor over the (S, source) pairs that come to be sources from now on (a member
    /// opening, a record coming into memory with its members).
    pub fn sources_feed(&self) -> osis_base::memo::Feed<(SyncId, Source)> {
        self.sources.feed()
    }

    /// The connection holding the record at `src` once its digests agreed (spec/sync-opens.md §3
    /// Agreement): where what is owed to that source goes. Stamped per source with `conn_of`.
    pub fn agreed_on(&self, src: Source) -> Option<ConnId> {
        self.conn_of(src).filter(|c| self.agreed(*c))
    }

    /// `conn`'s digests agreed: what read follows of its record moves (`agreed_on`).
    fn agreed_moved(&self, conn: ConnId) {
        if let Some(src) = self.source_of(conn) {
            self.connected.wrote(&src, true);
        }
    }

    /// The connection holding record `rid` now, if any.
    fn conn_on(&self, rid: RecordId) -> Option<ConnId> {
        self.on.get(&rid).copied().filter(|c| self.conns.get(c).is_some_and(|k| k.rec == Some(rid)))
    }

    /// Tests only: the records in memory.
    #[doc(hidden)]
    pub fn records_in_memory(&self) -> usize {
        self.records.len()
    }

    /// Tests only: `RECORD_BUDGET` as this node keeps it.
    #[doc(hidden)]
    pub fn set_record_budget(&mut self, budget: u64) {
        self.budget = budget;
    }

    /// `r`'s value; a store failure is noted (the step fails at its end).
    fn ok<T>(&mut self, r: Result<T>) -> Option<T> {
        r.map_err(|e| self.fault.get_or_insert(e.into_store("opens: store"))).ok()
    }

    fn dirty(&mut self, rid: RecordId) -> &mut records::Dirty {
        self.dirty.entry(rid).or_default()
    }

    /// Streams' reported positions (`reported`).
    pub fn on_reported(&mut self, cx: &mut Cx, sessions: &mut Sessions, unread: &Unread, reported: &mut Vec<Reported>, moved: &mut Vec<Moved>) {
        if reported.is_empty() {
            return;
        }
        self.live(cx, sessions, unread, |o, ctx| {
            for r in reported.drain(..) {
                o.reported(ctx, r, moved);
            }
        });
    }

    /// Whether anything acted (a member that moved is in `moved`).
    pub fn settle(&mut self, cx: &mut Cx, sessions: &mut Sessions, unread: &Unread, moved: &mut Vec<Moved>) -> Result<bool> {
        let acted = self.live(cx, sessions, unread, |o, ctx| o.tick(ctx, moved));
        if let Some(e) = self.fault.take() {
            return Err(e.into());
        }
        Ok(acted)
    }

    /// `conn`'s members (stamped whole: a judgement of one reads `member`).
    pub fn members(&self, conn: ConnId) -> &BTreeMap<SyncId, Member> {
        self.member_stamps.read_all();
        self.members_unstamped(conn)
    }

    /// `conn`'s member S (stamped per (connection, S)).
    pub fn member(&self, conn: ConnId, s: &SyncId) -> Option<&Member> {
        self.member_stamps.read(&(conn, *s));
        self.members_unstamped(conn).get(s)
    }

    /// The record `conn` holds, in memory.
    fn record_on(&self, conn: ConnId) -> Option<&Record> {
        self.records.get(&self.conns.get(&conn)?.rec?)
    }

    fn members_unstamped(&self, conn: ConnId) -> &BTreeMap<SyncId, Member> {
        self.record_on(conn).map_or(&NO_MEMBERS, |r| &r.members)
    }

    /// Member S of `conn`'s record opened, changed or went (`member_stamps`, `record_members`).
    fn member_moved(&self, conn: ConnId, s: &SyncId, present: bool) {
        self.member_stamps.wrote(&(conn, *s), present);
        if let Some(src) = self.source_of(conn) {
            self.record_members.wrote(&(src, *s), present);
        }
    }

    /// Where `conn`'s record keeps its rows: the record, or the connection for one kept nowhere.
    fn source_of(&self, conn: ConnId) -> Option<Source> {
        let id = self.conns.get(&conn)?.rec?;
        Some(if self.records.get(&id)?.kept { Source::Record(id) } else { Source::Conn(conn) })
    }

    /// Member S of the record at `src`, whether or not a connection holds it now (stamped per
    /// (source, S); a take or release moves nothing of it). A kept record with a member stays in
    /// memory from its first take until it goes (evicted, dropped); before, none.
    pub fn member_at(&self, src: Source, s: &SyncId) -> Option<&Member> {
        self.record_members.read(&(src, *s));
        let id = match src {
            Source::Record(id) => id,
            Source::Conn(c) => self.conns.get(&c)?.rec?,
        };
        self.records.get(&id)?.members.get(s)
    }

    /// The connection holding the record at `src` now: record R is connected on C (stamped per
    /// source).
    pub fn conn_of(&self, src: Source) -> Option<ConnId> {
        self.connected.read(&src);
        match src {
            Source::Record(id) => self.on.get(&id).copied(),
            Source::Conn(c) => self.conns.get(&c).and_then(|k| k.rec).map(|_| c),
        }
    }

    /// The peer's record: where streams, read and store keep their per-peer rows (none for a
    /// connection that keeps no record).
    pub fn record(&self, conn: ConnId) -> Option<RecordId> {
        let id = self.conns.get(&conn)?.rec?;
        self.records.get(&id).filter(|r| r.kept).map(|_| id)
    }

    /// The claims of `conn`'s proofs (what its record names,
    /// spec/sync-opens.md §2-§3); who the peer is now is `counted` of these.
    pub fn named(&self, conn: ConnId) -> Named {
        self.conns.get(&conn).map(|c| c.named.clone()).unwrap_or_default()
    }

    /// What `conn`'s peer's filter holds here, entries and heap bytes: its latest filter and the
    /// generation arriving (notes/decode-bounds.md: about what the peer sent of them).
    pub fn peer_filter_held(&self, conn: ConnId) -> (u64, usize) {
        let Some(c) = self.conns.get(&conn) else { return (0, 0) };
        let latest = self.record_on(conn).and_then(|r| r.peer.as_ref()).map_or((0, 0), |p| (p.values.len(), p.values.bytes()));
        let arriving = c.peer_gen.as_ref().map_or((0, 0), |g| (g.values.len(), g.values.bytes()));
        (latest.0 + arriving.0, latest.1 + arriving.1)
    }

    /// How many of the peer's filter generations have arrived through `conn`'s record: moves at
    /// each arrival (spec/sync-inbox.md §3: a refused Deposit item waits for the next).
    pub fn filter_arrivals(&self, conn: ConnId) -> u64 {
        self.record_on(conn).and_then(|r| r.peer.as_ref()).map_or(0, |p| p.arrived)
    }

    /// Whether the peer's latest filter shows `key` as S's deposit key (spec/sync-opens.md §5
    /// Filter: a node keeping S unread shows it to every connection): a deposit of S may land
    /// there (filters have false positives: the answer tells).
    pub fn shows_deposit_key(&self, conn: ConnId, s: &SyncId, key: &[u8; 32]) -> bool {
        let Some(r) = self.record_on(conn) else { return false };
        let Some(p) = &r.peer else { return false };
        p.values.contains(beacon_value(&beacon_of(key, s, &r.r), p.f))
    }

    /// Whether streams may Pull on `conn`: the digests matched or the peer's last Members page
    /// was read (spec/sync-opens.md §3 Agreement).
    pub fn agreed(&self, conn: ConnId) -> bool {
        self.conns.get(&conn).is_some_and(|c| c.phase == Phase::Running && c.agree == Agree::Done)
    }

    /// The kept records holding S as a member, naming a peer (spec/sync-status.md §1: a complete
    /// pass waits for each while it does). Stamped per S (`peers`). O(records holding S): read as
    /// a pass begins and as it is judged.
    pub fn records_holding(&self, store: &Store, s: &SyncId) -> Result<BTreeSet<RecordId>> {
        let mut out = BTreeSet::new();
        for id in self.holders_of(store, s)? {
            if !self.named_of(store, &id)?.is_empty() {
                out.insert(id);
            }
        }
        Ok(out)
    }

    /// Record `id`'s named claims: as a connection holds it, else as written.
    fn named_of(&self, store: &Store, id: &RecordId) -> Result<Named> {
        Ok(match self.records.get(id) {
            Some(r) => r.named.clone(),
            None => store.with_read(|t| t.record(id))?.map(|r| r.named).unwrap_or_default(),
        })
    }

    /// The kept records holding S as a member: as connections hold them, else as written.
    /// Stamped per S (`peers`).
    fn holders_of(&self, store: &Store, s: &SyncId) -> Result<BTreeSet<RecordId>> {
        self.peers.read(s);
        let stored = store.with_read(|t| t.records_with_row(s, crate::store::rows::tag::MEMBER, b"", usize::MAX))?;
        let held = |id: &RecordId| self.records.get(id).filter(|r| r.kept).map(|r| r.members.contains_key(s));
        Ok(stored.into_iter().filter(|id| held(id) != Some(false)).chain(self.records.iter().filter(|(_, r)| r.kept && r.members.contains_key(s)).map(|(id, _)| *id)).collect())
    }

    /// Whether some peer is to be waited for on S (spec/sync-set.md §3, spec/permissions.md §3
    /// Lost access: the duties
    /// that act once no peer could still take or tell what S holds): a peer `peer` does not skip
    /// with S open on a connection up now, or whose kept record holds S as a member, or that the
    /// rosters say may hold S (`Peer::MayHold`) no kept record of which (by who it names: a
    /// peer is what it proves) has acknowledged S's current
    /// credentials (`acked_pos` below `changed_at(S)`; every record before S has one), each of
    /// those records judged by `peer` on what it names. A peer whose record acknowledged them
    /// with S not a member does not hold S; one with no record was never met; a record evicted
    /// (`RECORD_BUDGET`) goes with its wait. Before the
    /// records are indexed (the first settle), waited. Stamped per S (`peers`); what `peer`
    /// reads is the caller's to follow. O(connections and records holding S, and records not
    /// acknowledging S).
    pub fn wait_for(&self, store: &Store, s: &SyncId, mut peer: impl FnMut(&Named) -> Peer) -> Result<bool> {
        self.peers.read(s);
        if self.held.get(s).into_iter().flatten().filter_map(|r| self.conn_on(*r)).any(|c| self.conns.get(&c).is_some_and(|k| peer(&k.named) != Peer::Skipped)) {
            return Ok(true);
        }
        for id in self.holders_of(store, s)? {
            if peer(&self.named_of(store, &id)?) != Peer::Skipped {
                return Ok(true);
            }
        }
        let Some(acks) = &self.acks else { return Ok(true) };
        let below = self.changed.at.get(s).map_or(u64::MAX, |(p, ..)| *p);
        // a peer none of whose records reached `below`: every record of it is below
        let records = acks.by_pos.range(..(below, Named::default())).flat_map(|(_, a)| acks.by_claims.get(a).into_iter().flatten());
        Ok(records.filter_map(|(_, id)| acks.rec.get(id).map(|(_, n)| n)).any(|n| peer(n) == Peer::MayHold))
    }

    /// `wait_for` judged by who each peer may be on the rosters held here (`Engine::may_hold` of
    /// what its record names, spec/sync-set.md §3 To be waited for): the one rule every duty
    /// reads (leave, a self-removal's drop, read's repairs, a pass with no source). `own`: a
    /// peer proving this node's own thing counts (a self-removal skips it, spec/sync-status.md
    /// §2). A failed read counts the peer.
    pub fn waited(&self, engine: &mut osis_engine::Engine, store: &Store, s: &SyncId, own: bool) -> Result<bool> {
        let me = engine.tid();
        let none = osis_blob::Certificates::default();
        self.wait_for(store, s, |named| {
            if !own && named.things().contains(&me) {
                return Peer::Skipped;
            }
            let may = engine.proven(&named.claims, &none).and_then(|p| engine.may_hold(s, &p)).unwrap_or(true);
            if may { Peer::MayHold } else { Peer::Unlisted }
        })
    }

    /// Whether this node's walk of S stopped at some source (spec/sync-ids.md §6 Stranded there:
    /// no credential of the newest step known there, or Behind refused it), and where: a stop
    /// naming a step it reached before one naming none, the lowest connection first. Stamped
    /// per S. O(connections stopped on S).
    pub fn walk_stop(&self, s: &SyncId) -> Option<Stop> {
        let at = self.stops.get(s)?;
        at.values().find(|x| x.is_some()).or_else(|| at.values().next()).copied()
    }

    /// Sets (or with `None` clears) where the walk of S stopped on `conn`, kept in its record
    /// (spec/sync-opens.md §3: the record keeps the source's step), so the record's next
    /// connection (a restart's) starts stopped there until a test there says otherwise.
    fn set_stop(&mut self, conn: ConnId, s: SyncId, stop: Option<Stop>) {
        self.index_stop(conn, s, stop);
        let Some(rid) = self.conns.get(&conn).and_then(|c| c.rec) else { return };
        let Some(r) = self.records.get_mut(&rid).filter(|r| r.kept) else { return };
        let was = match stop {
            Some(x) => r.walk.insert(s, x),
            None => r.walk.remove(&s),
        };
        if was != stop {
            self.dirty(rid).walk.insert(s);
        }
    }

    /// The stops `walk_stop` reads: S stopped on `conn` at `stop` (none: not stopped).
    fn index_stop(&mut self, conn: ConnId, s: SyncId, stop: Option<Stop>) {
        let mut at = self.stops.get(&s).cloned().unwrap_or_default();
        match stop {
            Some(x) => at.insert(conn, x),
            None => at.remove(&conn),
        };
        if at.is_empty() {
            self.stops.remove(&s);
        } else {
            self.stops.insert(s, at);
        }
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

    /// An ended member whose reported position is at or past its `until` closes with a Lost; one
    /// at a store source ended for its peer's departure waits for the peer's. One ended for its
    /// peer's departure at a reader source takes its `until` once a notice of it went (`tell`).
    fn close_if_reached(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, moved: &mut Vec<Moved>) {
        let Some(m) = self.member(conn, &s).filter(|m| !(m.departed.is_some() && m.class == SourceClass::Store)).cloned() else { return };
        let until = match m.until {
            Some(u) => u,
            None if m.departed.is_some() => {
                if !self.tell(ctx, conn, s, true) {
                    return;
                }
                let u = ctx.holds.departure_until(&s);
                let Some(rid) = self.conns.get(&conn).and_then(|c| c.rec) else { return };
                self.set_until(rid, &s, u, moved);
                u
            }
            None => return,
        };
        if self.reported_at(conn, &s).is_some_and(|(p, _)| *p >= until) {
            self.close_member(ctx, conn, s, Close::Until, moved);
        }
    }

    pub fn next_wake(&self) -> Option<Mono> {
        self.conns.values().flat_map(|c| c.resync_at.into_iter().chain(c.retries.first().map(|(t, _)| *t))).min()
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
        self.run(ctx, conn);
    }

    /// A connection ended: each of its members left (its record keeps them).
    pub fn closed(&mut self, conn: ConnId, moved: &mut Vec<Moved>) {
        self.release(conn, moved);
        if let Some(c) = self.conns.remove(&conn) {
            for s in c.walks.keys() {
                self.index_stop(conn, *s, None);
            }
        }
    }

    /// At the first settle: the store's `changed_at` end and the kept records' `acked_pos`.
    fn load_first(&mut self, store: &Store) -> Result<()> {
        if !self.changed.loaded {
            self.changed.end = store.with_read(|t| t.changed_end())?;
            self.changed.loaded = true;
        }
        if self.acks.is_none() {
            let mut acks = store.with_read(|t| {
                let mut acks = Acks::default();
                for rec in t.records_all()? {
                    let pos = records::acked_pos(t, &rec.id)?;
                    acks.set(rec.id, Some((pos, &rec.named)));
                }
                Ok(acks)
            })?;
            // records in memory are newer than their rows
            for (id, r) in self.records.iter().filter(|(_, r)| r.kept) {
                acks.set(*id, Some((r.acked_pos, &r.named)));
            }
            self.acks = Some(acks);
            self.peers.wrote_all();
        }
        Ok(())
    }

    /// At the first settle, once S's credentials are known: every kept record with a member not
    /// in memory is read from its rows (its peer filter left for a take) and its members judged
    /// and followed, so a member is re-judged at each change whether or not a connection held
    /// its record since the start (spec/sync-opens.md §6). O(kept records and their members),
    /// once per start.
    fn follow_kept(&mut self, ctx: &mut Ctx, moved: &mut Vec<Moved>) -> Result<()> {
        let records = &self.records;
        let read = ctx.store.with_read(|t| {
            let mut out = Vec::new();
            for rec in t.records_all()? {
                if !records.contains_key(&rec.id)
                    && !t.record_tag_rows(&rec.id, crate::store::rows::tag::MEMBER)?.is_empty()
                    && let Some(r) = records::load(t, &rec.id, false)?
                {
                    out.push((rec.id, r));
                }
            }
            Ok(out)
        })?;
        self.following = true;
        for (id, r) in read {
            let members: Vec<SyncId> = r.members.keys().copied().collect();
            self.records.insert(id, r);
            for s in &members {
                self.hold(*s, id, Some(Source::Record(id)));
            }
            for s in members {
                self.judge(ctx, id, s, moved);
            }
        }
        Ok(())
    }

    /// `conn` lets its record go: a kept one keeps its members where they stand (`Released`);
    /// one kept nowhere goes, each member closing with it.
    fn release(&mut self, conn: ConnId, moved: &mut Vec<Moved>) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let Some(rid) = c.rec.take() else { return };
        if self.on.get(&rid) == Some(&conn) {
            self.on.remove(&rid);
        }
        let src = if self.records.get(&rid).is_some_and(|r| r.kept) { Source::Record(rid) } else { Source::Conn(conn) };
        self.connected.wrote(&src, false);
        let Some(r) = self.records.get(&rid) else { return };
        let walk: Vec<SyncId> = r.walk.keys().copied().collect();
        for (s, m) in &r.members {
            self.member_stamps.wrote(&(conn, *s), false);
            self.peers.wrote(s, true);
            if let Source::Conn(_) = src {
                moved.push(Moved::Left(conn, *s, LeftAt { src, reported: c.reported.get(s).filter(|_| m.departed.is_none()).map(|(p, _)| *p), until: m.until, how: Leaving::Kept }));
            }
        }
        // where members closed on this connection stopped lasts the connection
        moved.extend(r.stopped.keys().map(|s| Moved::Forgot(conn, *s)));
        if let Source::Record(rid) = src {
            moved.push(Moved::Released(conn, rid));
            self.let_go.push(rid);
        }
        let Some(r) = self.records.get_mut(&rid) else { return };
        r.stopped.clear();
        // a kept one stays in memory until `flush` writes it (or another connection takes it),
        // its members' J followed still
        if !r.kept {
            self.forget_record(rid, src);
        }
        // its walk stops stay in the record for the next connection taking it
        for s in walk {
            self.index_stop(conn, s, None);
        }
    }

    /// spec/sync-opens.md §1 (one connection per pair): `conn` comes to take record `id` while
    /// another connection is of the same pair: it holds that record, or on both the peer proved
    /// the same node. The later stays when one side dialed both, else the one of better route
    /// rank, then the smaller order hash (`Bind::pair_order`, each under its own record's pair
    /// key: the same at both ends whatever order the two arrived in); the other lets its record
    /// go and closes. Whether `conn` stays.
    fn one_per_pair(&mut self, ctx: &mut Ctx, conn: ConnId, id: RecordId, moved: &mut Vec<Moved>) -> bool {
        let Some(r) = self.records.get(&id).map(|r| r.r) else { return true };
        let Some(c) = self.conns.get(&conn) else { return false };
        let node = c.proven.node();
        let kept = self.records.get(&id).is_some_and(|r| r.kept);
        let same = |k: &Conn| k.rec.is_some_and(|o| (o == id && kept) || (node.is_some() && k.proven.node() == node));
        let Some(other) = self.conns.iter().find(|(o, k)| **o != conn && k.lost_to.is_none() && same(k)).map(|(o, _)| *o) else { return true };
        let Some(ours) = self.conns.get(&conn).map(|c| c.bind.pair_order(&r)) else { return false };
        let Some(theirs) = self.conns.get(&other).and_then(|k| Some(k.bind.pair_order(&self.records.get(&k.rec?)?.r))) else { return true };
        // the later stays when one side dialed both (numbered in order at each end), else the one
        // of better route rank, then the smaller order hash: a node dials a peer at most once at a
        // time, so of two it dialed, the earlier is one it gave up (its close not arrived, or an
        // earlier run of the node)
        let stays = if conn.accepted() == other.accepted() { conn > other } else { ours < theirs };
        let (loser, winner) = if stays { (other, conn) } else { (conn, other) };
        self.release(loser, moved);
        if let Some(k) = self.conns.get_mut(&loser) {
            k.lost_to = Some(winner);
        }
        ctx.wire.close(loser, "one connection per pair");
        stays
    }

    /// spec/sync-opens.md §3 One record per pair: record `id`, of the pair `conn` holds, goes
    /// (at `flush`, with its charges, as an eviction), each member it held re-marked on `conn`.
    fn drop_record(&mut self, ctx: &mut Ctx, id: RecordId, conn: ConnId) {
        // in memory, with its members, whether or not a start followed it
        if self.load(ctx, id).is_none() {
            return;
        }
        let members: Vec<SyncId> = self.records.get(&id).map(|r| r.members.keys().copied().collect()).unwrap_or_default();
        self.forget_record(id, Source::Record(id));
        self.dirty.remove(&id);
        if let Some(acks) = &mut self.acks {
            acks.set(id, None);
        }
        self.peers.wrote_all();
        self.dropped.insert(id);
        for s in members {
            self.remark(conn, &s);
        }
    }

    /// spec/sync-opens.md §3 One record per pair: `conn` took kept record `id`; every other
    /// record naming the node its peer proved goes, none a connection holds.
    fn drop_others(&mut self, ctx: &mut Ctx, conn: ConnId, id: RecordId) {
        let Some(node) = self.conns.get(&conn).and_then(|c| c.proven.node()) else { return };
        let read = ctx.store.with_read(|t| t.records_of_things(&[node]));
        let others: Vec<RecordId> = self.ok(read).unwrap_or_default().into_iter().filter(|r| r.id != id && r.named.node() == Some(node) && !self.on.contains_key(&r.id)).map(|r| r.id).collect();
        for o in others {
            self.drop_record(ctx, o, conn);
        }
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
        let loaded = self.load_first(ctx.store);
        if self.ok(loaded).is_none() {
            return false;
        }
        // S's rows shredded (spec/sync-set.md §3) left this node even when synced again before
        // this tick saw it leave: it holds S no more, then takes S's credentials as new
        let shreds: BTreeSet<SyncId> = self.shreds.get_or_insert_with(|| ctx.store.shred_feed()).added().into_iter().collect();
        let mut due: BTreeSet<SyncId> = ctx.holds.due().into_iter().collect();
        due.extend(shreds.iter().copied());
        for s in due {
            self.work.creds += 1;
            let now = ctx.holds.creds(&s);
            let digest = now.as_ref().map(|c| c.digest());
            if !shreds.contains(&s) && digest == self.changed.at.get(&s).map(|(_, d, _)| *d) {
                continue;
            }
            self.moved_creds(ctx, s, now, shreds.contains(&s), moved);
        }
        if !self.following {
            let read = self.follow_kept(ctx, moved);
            if self.ok(read).is_none() {
                return false;
            }
        }
        // spec/sync-opens.md §6: a member is re-judged when the judgement of its peer's proof
        // moves (its removal or demotion arriving, its account's revocation, an `until`
        // passing): O(members resting on what moved)
        for (r, s) in std::mem::take(&mut self.unfollowed) {
            ctx.holds.unfollow(r, &s);
        }
        // whether or not a connection holds the record, in this step
        for (r, s) in ctx.holds.standing_due() {
            self.work.standing += 1;
            if self.records.get(&r).is_some_and(|x| x.members.contains_key(&s)) {
                self.judge(ctx, r, s, moved);
            } else if let Some(c) = self.conn_on(r).filter(|c| self.conns.get(c).is_some_and(|k| k.asked.contains(&s))) {
                let named = self.conns.get(&c).map(|k| k.named.clone()).unwrap_or_default();
                if matches!(self.follow(ctx, r, s, &named), Some(J::Reader | J::SyncHolder)) {
                    if let Some(k) = self.conns.get_mut(&c) {
                        k.asked.remove(&s);
                    }
                    self.remark(c, &s);
                }
            } else {
                self.unfollow_member(r, s);
                ctx.holds.unfollow(r, &s);
            }
        }
        // a record no connection holds any more: its members whose peer is no one close
        for rid in std::mem::take(&mut self.let_go) {
            if self.conn_on(rid).is_some() {
                continue;
            }
            let Some(r) = self.records.get(&rid) else { continue };
            let named = r.named.clone();
            let members: Vec<SyncId> = r.members.keys().copied().collect();
            for s in members {
                if self.follow(ctx, rid, s, &named).is_none() {
                    self.judge(ctx, rid, s, moved);
                }
            }
        }
        let conns: Vec<ConnId> = self.conns.keys().copied().collect();
        for c in conns {
            if let Some(k) = self.conns.get_mut(&c) {
                if k.resync_at.is_some_and(|t| t <= ctx.mono) {
                    k.resync_at = None;
                    k.whole_next = true;
                }
                // a back-off over leaves `retries` here, so no wake past stays (whatever the test
                // then finds, or however long it waits on an Offer out): S joins the next test
                while let Some((_, s)) = k.retries.first().copied().filter(|(t, _)| *t <= ctx.mono) {
                    k.retries.pop_first();
                    k.walks.entry(s).or_default().retry = true;
                    k.test_due = true;
                }
            }
            self.run(ctx, c);
        }
        moved.len() > before
    }

    /// This node holds S no more (spec/sync-set.md §3 Stopping, spec/sync-opens.md §3, §6 Where it
    /// stopped): S's credentials went to none, or its rows went with a shred. S drops from every
    /// record in this step: its members on a connection close with a Lost naming none, each
    /// connection whose record keeps a stop of S is told nothing of S is kept here, and what is
    /// kept of S for a record no connection holds goes.
    fn left(&mut self, ctx: &mut Ctx, s: SyncId, moved: &mut Vec<Moved>) {
        let on: Vec<ConnId> = self.held.get(&s).into_iter().flatten().filter_map(|r| self.conn_on(*r)).collect();
        for c in on {
            self.close_member(ctx, c, s, Close::Left, moved);
        }
        let kept: Vec<ConnId> = self.conns.iter().filter(|(_, k)| k.rec.and_then(|r| self.records.get(&r)).is_some_and(|r| r.stopped.contains_key(&s))).map(|(c, _)| *c).collect();
        for c in kept {
            self.send_lost(ctx, c, vec![(s, None)]);
        }
        self.peers.wrote(&s, false);
        for k in self.conns.values_mut() {
            k.walks.remove(&s);
            k.retries.retain(|(_, x)| *x != s);
        }
        self.stops.remove(&s);
        // the record rows of S go with S in the store
        for c in self.conns.keys() {
            self.member_stamps.wrote(&(*c, s), false);
            if let Some(src) = self.source_of(*c) {
                self.record_members.wrote(&(src, s), false);
            }
        }
        // a record no connection holds: what is kept of S for it goes too
        for id in self.held.get(&s).cloned().unwrap_or_default() {
            self.hold(s, id, None);
            if self.records.get(&id).is_some_and(|r| r.kept && r.members.contains_key(&s)) {
                self.record_members.wrote(&(Source::Record(id), s), false);
                moved.push(Moved::Gone(id, s));
            }
        }
        let gone: Vec<RecordId> = self.followed.iter().filter(|(_, m)| m.contains(&s)).map(|(r, _)| *r).collect();
        for r in gone {
            self.unfollow_member(r, s);
            ctx.holds.unfollow(r, &s);
        }
        for r in self.records.values_mut() {
            r.walk.remove(&s);
            r.members.remove(&s);
            r.basis.remove(&s);
            r.stopped.remove(&s);
        }
        for d in self.dirty.values_mut() {
            d.members.remove(&s);
            d.walk.remove(&s);
        }
        let r = ctx.store.with_tx(|t| t.changed_forget(&s));
        self.ok(r);
    }

    /// S's credentials moved to `now` (none: S left the sync set); `shredded`: S's rows went
    /// meanwhile, so S left this node whatever `now` is.
    fn moved_creds(&mut self, ctx: &mut Ctx, s: SyncId, now: Option<Arc<Creds>>, shredded: bool, moved: &mut Vec<Moved>) {
        if shredded || now.is_none() {
            self.left(ctx, s, moved);
        }
        let known = self.changed.at.remove(&s);
        if let Some((p, ..)) = &known {
            self.changed.order.remove(p);
        }
        self.changed.public_tested.remove(&s);
        if let Some(c) = &now
            && c.tests.iter().any(|(t, _)| matches!(t, Tested::Public))
            && !c.shows.iter().any(|(x, _)| matches!(x, Shown::Public(_)))
        {
            self.changed.public_tested.insert(s);
        }
        if let Some(c) = now {
            // the store's `changed_at` moves only for credentials that moved since it was
            // written: a restart finds the rest as they were
            let digest = c.digest();
            let r = ctx.store.with_tx(|t| match t.changed_note(s, &digest)? {
                Some(p) => Ok((p, true)),
                None => Ok((t.changed_at(&s)?.unwrap_or(0), false)),
            });
            let Some((pos, advanced)) = self.ok(r) else { return };
            self.changed.end = self.changed.end.max(pos);
            self.changed.at.insert(s, (pos, digest, c));
            self.changed.order.insert(pos, s);
            if known.as_ref().is_none_or(|(p, ..)| *p != pos) {
                self.peers.wrote(&s, true);
            }
            if !advanced && known.is_none() {
                return;
            }
        }
        // spec/sync-opens.md §6: every record holding S, connected or not, in this step
        for rid in self.held.get(&s).cloned().unwrap_or_default() {
            self.judge(ctx, rid, s, moved);
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
        let named = ctx.holds.named(&proven);
        let mut c = Conn {
            bind,
            proven,
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
            public_due: false,
            offer: None,
            reported: Positions::default(),
            ending: BTreeSet::new(),
            walks: BTreeMap::new(),
            retries: BTreeSet::new(),
            lost_to: None,
            served: BTreeMap::new(),
            asked: BTreeSet::new(),
            told: BTreeSet::new(),
            told_departed: BTreeSet::new(),
        };
        if bind.dialer {
            if !c.named.is_empty() {
                // spec/sync-opens.md §3: Resume lists each record naming a thing proven in this
                // session, most recent first.
                let things = c.named.things();
                let rs = ctx.store.with_read(|t| t.records_of_things(&things));
                let mut listed: Vec<(RecordId, [u8; 32])> = self.ok(rs).unwrap_or_default().into_iter().map(|r| (r.id, r.r)).collect();
                listed.truncate(MAX_RESUME_TAGS);
                let (d, l) = (bind.own_challenge, bind.peer_challenge);
                let tags = listed.iter().map(|(_, r)| resume_tag(r, &bind.listener_key, &d, &l)).collect();
                let nonce = random(ctx.holds.rng());
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
        let id = self.new_record(ctx, r, Named::default(), false);
        self.take(ctx, conn, id, false, moved);
    }

    /// A new record: a kept one is written now (before the answer naming it goes, and before
    /// any module writes rows in it); one kept nowhere lives in memory with its connection.
    fn new_record(&mut self, ctx: &mut Ctx, r: [u8; 32], named: Named, kept: bool) -> RecordId {
        let made = if kept { ctx.store.with_tx(|t| t.record_create(r, &named)).map(Some) } else { Ok(None) };
        let id = self.ok(made).flatten().unwrap_or_else(|| random(ctx.holds.rng()));
        self.records.insert(id, Record { r, named, kept, members: BTreeMap::new(), basis: BTreeMap::new(), stopped: BTreeMap::new(), walk: BTreeMap::new(), acked_pos: 0, own: OwnFilter::default(), peer: None, told: true });
        self.acks_moved(id, None);
        id
    }

    /// Record `id` in memory: as memory holds it (`Some(false)`), else as its rows hold it
    /// (`Some(true)`: nothing of it was followed). None: no such record.
    fn load(&mut self, ctx: &mut Ctx, id: RecordId) -> Option<bool> {
        if let Some(r) = self.records.get(&id) {
            let Some(f) = r.peer.as_ref().filter(|p| !p.held).map(|p| p.f) else { return Some(false) };
            let read = ctx.store.with_read(|t| records::filter_values(t, &id, f));
            let v = self.ok(read)?;
            if let Some(p) = self.records.get_mut(&id).and_then(|r| r.peer.as_mut()) {
                p.values = Arc::new(v);
                p.held = true;
            }
            return Some(false);
        }
        let read = ctx.store.with_read(|t| records::load(t, &id, true));
        let r = self.ok(read)??;
        let members: Vec<SyncId> = r.members.keys().copied().collect();
        self.records.insert(id, r);
        for s in members {
            self.hold(s, id, Some(Source::Record(id)));
        }
        Some(true)
    }

    /// The connection takes record `id`: its members are this connection's, Digest first (with
    /// a record), then the filter. Its members were judged in the step of each change while no
    /// connection held it (spec/sync-opens.md §6), a start's included (`follow_kept`): judged
    /// here only where nothing of them was followed (a record read from its rows for this take)
    /// or what the record names moves.
    fn take(&mut self, ctx: &mut Ctx, conn: ConnId, id: RecordId, digest: bool, moved: &mut Vec<Moved>) {
        let Some(read) = self.load(ctx, id) else { return };
        if !self.one_per_pair(ctx, conn, id, moved) {
            let winner = self.conns.get(&conn).and_then(|c| c.lost_to);
            let theirs = winner.and_then(|w| self.conns.get(&w)).and_then(|k| k.rec);
            match winner {
                // another record of the pair the winner took (spec/sync-opens.md §3 One record per pair)
                Some(w) if theirs != Some(id) && self.records.get(&id).is_some_and(|r| r.kept) => self.drop_record(ctx, id, w),
                // read from its rows for this take, nothing of it judged or followed: it leaves
                // memory as it came, so the next take reads and judges it afresh
                _ if read => {
                    self.forget_record(id, Source::Record(id));
                }
                _ => {}
            }
            return;
        }
        let kept = self.records.get(&id).is_some_and(|r| r.kept);
        if kept {
            self.dirty(id).used = true;
        }
        let mut core = false;
        let was = self.records.get(&id).filter(|r| r.kept).map(|r| (r.acked_pos, r.named.clone()));
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let Some(r) = self.records.get_mut(&id) else { return };
        // the modules learn its members now unless they were told (a record the start read)
        let fresh = read || !r.told;
        r.told = true;
        let renamed = r.kept && r.named != c.named;
        if renamed {
            // spec/sync-opens.md §3: a session proving other things than the record names starts
            // with every credential pending and a whole filter (other paths or keys alone prove
            // the same things, named so from now on: written as the record is used).
            if r.named.things() != c.named.things() {
                r.acked_pos = 0;
                r.own.acked = 0;
                c.whole_next = true;
            }
            r.named = c.named.clone();
            core = true;
        }
        c.rec = Some(id);
        self.on.insert(id, conn);
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
        // ended members close on this connection's reported positions
        c.ending = r.members.iter().filter(|(_, m)| m.until.is_some() || m.departed.is_some()).map(|(s, _)| *s).collect();
        let walk: Vec<(SyncId, Stop)> = r.walk.iter().map(|(s, x)| (*s, *x)).collect();
        if core {
            self.dirty(id).core = true;
            self.acks_moved(id, was);
        }
        // J was judged of what the record named: judged again of what it names now
        if renamed {
            for s in self.followed.remove(&id).unwrap_or_default() {
                ctx.holds.unfollow(id, &s);
            }
        }
        // where its walks stopped at this peer before (spec/sync-opens.md §3), until a test says
        // otherwise
        for (s, x) in walk {
            self.index_stop(conn, s, Some(x));
        }
        if let Some(src) = self.source_of(conn) {
            self.connected.wrote(&src, true);
        }
        // a record kept nowhere is new with its connection: no member yet
        debug_assert!(kept || members.is_empty(), "a record kept nowhere taken with members");
        if kept {
            moved.push(Moved::Taken(conn, id, fresh));
        }
        // each member a holder's: told its notices on this connection (`tell`)
        for s in members.clone() {
            self.tell(ctx, conn, s, false);
        }
        for s in &members {
            self.member_stamps.wrote(&(conn, *s), true);
        }
        if read || renamed {
            for s in members {
                self.rejudge(ctx, conn, s, moved);
            }
        }
        if kept {
            self.drop_others(ctx, conn, id);
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
        let Some(c) = self.conns.get(&conn).filter(|c| c.phase == Phase::Waiting && !c.bind.dialer) else {
            ctx.wire.answer(conn, id, Msg::Error { id, code: Code::MALFORMED });
            return;
        };
        if c.named.is_empty() {
            // A connection whose dialer proved nothing keeps no record: Error 1, and the dialer
            // sends NoRecord (spec/sync-opens.md §3).
            ctx.wire.answer(conn, id, Msg::Error { id, code: Code::REFUSED });
            return;
        }
        let bind = c.bind;
        let named = c.named.clone();
        let (d, l) = (bind.peer_challenge, bind.own_challenge);
        // A record is honoured only while a thing proven in this session is named by it.
        let held = ctx.store.with_read(|t| t.records_of_things(&named.things()));
        let held = self.ok(held).unwrap_or_default();
        let mine: BTreeMap<[u8; 32], (RecordId, [u8; 32])> = held.into_iter().map(|r| (resume_tag(&r.r, &bind.listener_key, &d, &l), (r.id, r.r))).collect();
        let found = tags.iter().find_map(|t| mine.get(t).copied());
        let lnonce = random(ctx.holds.rng());
        let (rid, tag) = match found {
            Some((rid, r)) => (rid, Some(resumed_tag(&r, &bind.listener_key, &d, &l))),
            // On no match a new record, written before the answer goes.
            None => (self.new_record(ctx, *pair_key(&dnonce, &lnonce).expose(), named, true), None),
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
        match found {
            Some(rid) => self.take(ctx, conn, rid, true, moved),
            None => {
                let named = c.named.clone();
                let rid = self.new_record(ctx, *pair_key(&nonce, &lnonce).expose(), named, true);
                self.take(ctx, conn, rid, true, moved);
            }
        }
    }

    fn push(&mut self, ctx: &mut Ctx, conn: ConnId, m: Msg, moved: &mut Vec<Moved>) {
        match m {
            Msg::Digest { digest } => self.digest(ctx, conn, digest),
            Msg::Members { sync_ids, more } => self.members_page(ctx, conn, sync_ids, more, moved),
            // taken whatever is shared: the notice is judged by what it carries alone
            Msg::Notice { sync_id, holder, epoch, notice } => ctx.holds.take_notice(&sync_id, &holder, &epoch, &notice),
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
            self.agreed_moved(conn);
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
        self.agreed_moved(conn);
        let Some(c) = self.conns.get(&conn) else { return };
        let Some(rid) = c.rec else { return };
        let mine: BTreeSet<SyncId> = self.records.get(&rid).map(|r| r.members.keys().copied().collect()).unwrap_or_default();
        for s in mine.difference(&theirs) {
            self.drop_member(conn, *s, None, moved);
        }
        for s in mine.symmetric_difference(&theirs) {
            self.remark(conn, s);
        }
    }

    // ---- filters (§5) ----

    /// The connection's due work: its next filter generation, then a test.
    fn run(&mut self, ctx: &mut Ctx, conn: ConnId) {
        if self.conns.get(&conn).is_none_or(|c| c.lost_to.is_some()) {
            return;
        }
        self.send_generation(ctx, conn);
        self.test(ctx, conn);
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
        for sh in adm.shows.into_iter().chain(adm.walk) {
            let b = beacon_of(sh.matched(), s, &r.r);
            self.work.beacons += 1;
            c.shown.insert(c.bind.peer_hit(sh.matched(), s, &b), (*s, sh, b));
        }
    }

    /// Sends the next generation of this side's filter when none is in flight (spec/sync-opens.md
    /// §5 Filter): the first of a connection with an acknowledged record is additions of the sync
    /// IDs past `acked_pos` (sent even when empty), else whole; later ones additions of the sync
    /// IDs whose credentials changed; a whole one once additions pass its entries.
    fn send_generation(&mut self, ctx: &mut Ctx, conn: ConnId) {
        let Some(c) = self.conns.get(&conn) else { return };
        if c.phase != Phase::Running || c.gen_out.is_some() || c.resync_at.is_some() {
            return;
        }
        let Some(rid) = c.rec else { return };
        let first = c.first;
        let whole_next = c.whole_next;
        let Some(r) = self.records.get_mut(&rid) else { return };
        // after a generation the peer never acknowledged (its answer lost with a connection; the
        // peer may hold it or not), additions go on the last acknowledged one with the entries of
        // either counted as sent, so the peer never counts more than this side; after a whole one
        // of another width or entry count, whole
        let mut lost_whole = false;
        if r.own.acked != r.own.generation {
            let (s, a) = (&mut r.own.shape, r.own.acked_shape);
            lost_whole = (s.f, s.whole) != (a.f, a.whole);
            s.added = s.added.max(a.added);
        }
        let whole = whole_next || r.own.acked == 0 || lost_whole;
        let ids: Vec<SyncId> = if whole {
            Vec::new()
        } else if first {
            self.changed.after(r.acked_pos)
        } else {
            self.conns.get(&conn).map(|c| c.adds.iter().copied().collect()).unwrap_or_default()
        };
        if !whole && !first && ids.is_empty() {
            return;
        }
        let Some(r) = self.records.get(&rid) else { return };
        let (rr, room) = (r.r, r.own.shape.whole.saturating_sub(r.own.shape.added));
        // Additions bring at most the whole one's n entries in all (spec/wire.md §11.2): past it, whole.
        let adds = if whole { None } else { Some(self.shown_beacons(ctx, conn, &ids, &rr)).filter(|b| b.len() as u64 <= room) };
        let whole = adds.is_none();
        let beacons = match adds {
            Some(b) => b,
            None => {
                let all: Vec<SyncId> = self.changed.at.keys().copied().collect();
                self.shown_beacons(ctx, conn, &all, &rr)
            }
        };
        let Some(r) = self.records.get_mut(&rid) else { return };
        let f = if whole { filter_width(beacons.len()).clamp(MIN_FILTER_WIDTH, MAX_FILTER_WIDTH) } else { r.own.shape.f };
        let mut values: Vec<u64> = beacons.iter().map(|b| beacon_value(b, f)).collect();
        values.sort_unstable();
        let generation = r.own.generation + 1;
        let base = if whole { None } else { Some(r.own.acked) };
        r.own.generation = generation;
        r.own.shape.f = f;
        if whole {
            r.own.shape.whole = values.len() as u64;
            r.own.shape.added = 0;
        } else {
            r.own.shape.added += values.len() as u64;
        }
        r.own.sent_reach = self.changed.end;
        self.dirty(rid).core = true;
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

    /// The beacons of the credentials `ids` show (spec/sync-opens.md §5 Beacon), the walk proofs
    /// shown to a departed peer included (§4 Admissible).
    fn shown_beacons(&mut self, ctx: &mut Ctx, conn: ConnId, ids: &[SyncId], r: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut beacons = Vec::new();
        for s in ids {
            if let Some(adm) = self.admissible(ctx, conn, s) {
                for sh in adm.shows.iter().chain(&adm.walk) {
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
        let Some(rid) = c.rec else { return };
        let Some(r) = self.records.get_mut(&rid) else { return };
        if g.refused {
            // A refused generation is followed, after `resync_ms`, by a whole one.
            c.resync_at = Some(ctx.mono.after(crate::types::RESYNC_MS));
        } else if g.base_missing {
            c.whole_next = true;
        } else {
            r.own.acked = g.generation;
            r.own.acked_shape = r.own.shape;
            r.own.acked_reach = r.own.sent_reach;
            self.dirty(rid).core = true;
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
        if !fits || !(fresh || follows) || count_gcs(gcs, lo, hi).is_err() || (!more && hi != end) {
            return break_format(ctx, conn, id, "a filter page breaking the format");
        }
        if fresh {
            // additions go on their base or on a later generation held (one whose answer was lost
            // with a connection: it only adds entries, spec/sync-opens.md §5 Filter)
            let held = base.and_then(|b| r.peer.as_ref().filter(|p| p.generation >= b));
            let exact = base.is_none() || held.is_some_and(|p| Some(p.generation) == base);
            // Additions at another width than their base's break the format; than a later
            // generation's, they are taken as on a base not held.
            if exact && held.is_some_and(|p| p.f != f) {
                return break_format(ctx, conn, id, "filter additions at another width");
            }
            let held_base = base.is_none() || held.is_some_and(|p| p.f == f);
            c.peer_gen = Some(PeerGen { generation, base, f, next_lo: lo, held_base, exact, values: Run::default() });
        }
        let Some(p) = c.peer_gen.as_mut() else { return };
        p.next_lo = hi;
        if p.held_base && p.values.extend_from_gcs(gcs, lo, hi).is_err() {
            // checked above; pages come in ascending ranges (`follows`)
            return break_format(ctx, conn, id, "a filter page breaking the format");
        }
        // spec/wire.md §11.2 Beacons: a whole filter of n entries is `filter_width(n)` wide (so
        // at most 2^(f-8) entries); additions bring at most the whole one's n in all.
        let n = p.values.len();
        let cap = match (p.base, &r.peer) {
            (None, _) => MAX_FILTER_ENTRIES.min(1 << (f - MIN_FILTER_WIDTH)),
            (Some(_), Some(old)) => old.whole.saturating_sub(old.added),
            (Some(_), None) => 0,
        };
        let narrow = !more && p.base.is_none() && filter_width(usize::try_from(n).unwrap_or(usize::MAX)).max(MIN_FILTER_WIDTH) != f;
        if p.held_base && (n > cap || narrow) {
            if p.exact {
                return break_format(ctx, conn, id, "a filter breaking its width or entry count");
            }
            p.held_base = false;
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
        let values = p.values;
        // the generation's row: its run, as the filter's own coding (`encode_gcs`) of its values
        let row = values.gcs().to_vec();
        let whole = match (&mut r.peer, p.base) {
            (Some(old), Some(_)) => {
                old.generation = p.generation;
                old.added += values.len();
                Arc::make_mut(&mut old.values).add(values);
                old.arrived += 1;
                false
            }
            _ => {
                let arrived = r.peer.as_ref().map_or(0, |o| o.arrived) + 1;
                let whole = values.len();
                let mut all = Beacons::default();
                all.add(values);
                r.peer = Some(PeerFilter { generation: p.generation, f: p.f, whole, added: 0, values: Arc::new(all), arrived, held: true });
                true
            }
        };
        // Testing at each filter arrival: from `acked_pos` (spec/sync-opens.md §5 Testing). Other
        // tests (an answer read, a change) go on from the position tested on this connection, so a
        // refused Hit is not sent again at each answer while the peer has not acknowledged a
        // generation.
        c.tested_pos = c.tested_pos.min(r.acked_pos);
        c.test_due = true;
        c.public_due = true;
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
        let c = self.conns.get(&conn)?;
        // spec/sync-opens.md §4 J: judged on the rosters held now, from what this connection's
        // proofs count for now.
        let proven = ctx.holds.counts(&c.named, &c.proven.copies);
        let j = ctx.holds.judge(s, &proven);
        self.admissible_as(ctx, s, j)
    }

    /// `admissible` with J judged already.
    fn admissible_as(&mut self, ctx: &mut Ctx, s: &SyncId, j: J) -> Option<Adm> {
        let creds = self.changed.at.get(s).map(|(_, _, c)| c.clone())?;
        creds.holding?;
        let mut ok = |e: &Option<osis_crypto::Epoch>| j != J::Departed || e.as_ref().is_some_and(|e| ctx.holds.covers_departures(s, e));
        let (shows, rest): (Vec<_>, Vec<_>) = creds.shows.iter().partition(|(_, e)| ok(e));
        let shows = shows.into_iter().map(|(x, _)| x.clone()).collect();
        let mut walk: Vec<Shown> = match j {
            J::Departed => rest.into_iter().map(|(x, _)| x).filter(|x| matches!(x, Shown::Proof(..))).chain(creds.walk.iter()).cloned().collect(),
            _ => Vec::new(),
        };
        walk.extend(creds.lapsed.iter().cloned());
        let tests = creds.tests.iter().filter(|(_, e)| ok(e)).map(|(x, _)| x.clone()).collect();
        let step = creds.step.as_ref().filter(|(_, e)| ok(e)).map(|(k, _)| k.clone());
        let own = crate::types::class_of(creds.holding?);
        Some(Adm { j, by_role: creds.by_role, stopped: creds.stopped, own, shows, tests, walk, step })
    }

    /// Tests the pending sync IDs against the peer's latest filter and sends one Offer
    /// (spec/sync-opens.md §5 Testing): Hits first, then ByRole; at most one Offer unanswered.
    fn test(&mut self, ctx: &mut Ctx, conn: ConnId) {
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
        // and a Behind refused for now, its back-off over, asked again
        let mut missed: Vec<SyncId> = c.walks.iter().filter(|(_, w)| w.missed || w.retry).map(|(s, _)| *s).collect();
        // tested by the public entry alone: again at each filter arrival (`Changed::public_tested`)
        if c.public_due {
            missed.extend(self.changed.public_tested.iter().copied());
            missed.sort();
            missed.dedup();
        }
        if !missed.is_empty() {
            let have: BTreeSet<SyncId> = pending.iter().copied().collect();
            pending.extend(missed.into_iter().filter(|s| !have.contains(s)));
        }
        let end = self.changed.end;
        let mut sent = Vec::new();
        let mut items = Vec::new();
        let mut cut = false;
        for s in pending {
            // a refused walk Hit counts as that credential not shown
            let unshown = self.conns.get_mut(&conn).and_then(|c| c.walks.get_mut(&s)).map(|w| {
                w.retry = false;
                w.missed = false;
                w.unshown.clone()
            }).unwrap_or_default();
            if self.member(conn, &s).is_some() {
                continue;
            }
            let Some(adm) = self.admissible(ctx, conn, &s) else { continue };
            self.work.tested += 1;
            let mut hit = false;
            for t in &adm.tests {
                let m = t.matched(&s);
                if t.step().is_some() && unshown.contains(&m) {
                    continue;
                }
                let b = beacon_of(&m, &s, &rr);
                self.work.beacons += 1;
                if !pf.values.contains(beacon_value(&b, pf.f)) {
                    continue;
                }
                let h = bind.hit(&m, &s, &b);
                let class = adm.own;
                items.push(match t {
                    Tested::SyncKey { key, .. } | Tested::Claim { key, .. } => OfferItem::Hit { hit: h, sig: Some(bind.sign(key, &s)), class },
                    Tested::Static { key, .. } => OfferItem::Static { hit: h, signing_pk: key.verifying_key().to_bytes(), sig: bind.sign(key, &s), class },
                    Tested::Read(..) | Tested::Proof(..) | Tested::Public => OfferItem::Hit { hit: h, sig: None, class },
                });
                sent.push(Sent::Hit { s, cred: Box::new(t.clone()), beacon: b, own: adm.own });
                hit = true;
                // spec/sync-ids.md §6 Walk: the first shown of the walk's credentials is Hit.
                if t.step().is_some() {
                    break;
                }
            }
            if adm.j == J::Reader || adm.by_role || adm.stopped {
                // ByRole for S still not open that J judges the peer reads, or that this side
                // follows by a locator's value alone (beside its public entry's Hit, which
                // may be a false positive of the filter, refused), with this side's Hits of its
                // read secrets and static entries (a Hit may be a false positive of the filter).
                let hits = adm.tests.iter().filter(|t| matches!(t, Tested::Read(..) | Tested::Static { .. })).take(osis_proto::limits::MAX_ITEM_HITS).map(|t| {
                    let m = t.matched(&s);
                    bind.hit(&m, &s, &beacon_of(&m, &s, &rr))
                });
                items.push(OfferItem::ByRole { sync_id: s, hits: hits.collect(), class: adm.own });
                sent.push(Sent::ByRole(s, adm.own));
                self.set_stop(conn, s, None);
            } else if !hit && adm.j == J::SyncHolder {
                let stop = self.walk_on(ctx, conn, &s, &adm, &mut items, &mut sent);
                if stop.is_some() {
                    osis_base::costs::count("opens: walk stopped", 1);
                }
                self.set_stop(conn, s, stop);
            } else {
                self.set_stop(conn, s, None);
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
            c.public_due = false;
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

    /// The walk of S toward a peer J judges a sync holder, when no walk credential was shown
    /// (spec/sync-ids.md §6 Walk): stopped there (spec/sync-ids.md §6 Stranded there) when it
    /// holds no credential of the newest step known there or Behind refused that step; else a
    /// Behind item (`behind_item`), and stopped when none is left to ask by. Where it stopped.
    fn walk_on(&mut self, ctx: &mut Ctx, conn: ConnId, s: &SyncId, adm: &Adm, items: &mut Vec<OfferItem>, sent: &mut Vec<Sent>) -> Option<Stop> {
        let w = self.conns.get(&conn)?.walks.get(s);
        let newest = w.and_then(|w| w.known.last()).cloned();
        if let Some(n) = &newest {
            let refused = w.is_some_and(|w| w.refused.contains(&Some(n.id())));
            if refused || ctx.holds.step_creds(s, n).is_empty() {
                return Some(Some(n.keys.sync.to_bytes()));
            }
        }
        // refused for now and backed off, or asked: the stop (if any) stands until an answer
        // says otherwise
        if self.backed_off(conn, s) || self.behind_item(ctx, conn, s, adm, items, sent) {
            return self.stops.get(s).and_then(|at| at.get(&conn).copied());
        }
        Some(newest.map(|n| n.keys.sync.to_bytes()))
    }

    /// Whether S's Behind toward `conn` was refused for now (4) and waits out its back-off.
    fn backed_off(&self, conn: ConnId, s: &SyncId) -> bool {
        self.conns.get(&conn).is_some_and(|c| c.retries.iter().any(|(_, x)| x == s))
    }

    /// A Behind item for S toward a peer J judges a sync holder, when no walk credential was
    /// shown (spec/sync-ids.md §6 Behind): by a credential of the newest known step it holds one
    /// of, each step once per walk. Whether one was asked.
    fn behind_item(&mut self, ctx: &mut Ctx, conn: ConnId, s: &SyncId, adm: &Adm, items: &mut Vec<OfferItem>, sent: &mut Vec<Sent>) -> bool {
        let Some(c) = self.conns.get_mut(&conn) else { return false };
        let w = c.walks.entry(*s).or_default();
        let known: Vec<Tested> = w.known.iter().rev().flat_map(|st| ctx.holds.step_creds(s, st)).map(|(t, _)| t).collect();
        let cand = known.iter().chain(adm.tests.iter()).find(|t| matches!(t, Tested::SyncKey { .. } | Tested::Claim { .. } | Tested::Static { .. }) && !w.refused.contains(&t.step()));
        let Some(t) = cand else { return false };
        let (key, step) = match t {
            Tested::Claim { key, step, .. } => (key, Some(*step)),
            Tested::SyncKey { key, step } | Tested::Static { key, step } => (key, *step),
            _ => return false,
        };
        items.push(OfferItem::Behind(osis_proto::BehindItem { sync_id: *s, step, key: key.verifying_key().to_bytes(), sig: c.bind.sign(key, s) }));
        sent.push(Sent::Behind(*s, step));
        true
    }

    /// The peer's answers to this side's Offer (spec/sync-opens.md §5 Opening): the tester opens S
    /// on the answer's valid tag, its credential still admissible, and its own proof of the
    /// replier (J, or the answer's proof); then Lost each S the peer accepted and it did not open.
    fn answered(&mut self, ctx: &mut Ctx, conn: ConnId, items: Vec<SharedItem>, moved: &mut Vec<Moved>) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let Some(sent) = c.offer.take() else { return };
        let bind = c.bind;
        let mut accepted = BTreeSet::new();
        let mut crossed = Vec::new();
        for (i, x) in sent.into_iter().enumerate() {
            let a = items.get(i).cloned().unwrap_or(SharedItem::code(Code::DECLINED));
            match x {
                // A refused Hit on a walk credential counts as that credential not shown: S is
                // tested again with the rest, asking Behind once none is shown (spec/sync-ids.md
                // §6 Walk).
                Sent::Hit { s, cred, .. } if a.code != Code::OK => {
                    if cred.step().is_some()
                        && self.member(conn, &s).is_none()
                        && let Some(c) = self.conns.get_mut(&conn)
                    {
                        let w = c.walks.entry(s).or_default();
                        w.missed = true;
                        w.unshown.insert(cred.matched(&s));
                    }
                }
                Sent::Hit { s, cred, beacon, own } => {
                    let m = cred.matched(&s);
                    // The tag: computable only with the credential and S, by the replier's side.
                    // Without it the peer showed no knowledge of S: no Lost names S to it (a
                    // false positive of the filter answered OK would learn S).
                    if a.tag != Some(bind.peer_tag(&m, &s, &beacon)) {
                        continue;
                    }
                    accepted.insert(s);
                    if self.member(conn, &s).is_some() {
                        crossed.extend(self.crossed(conn, s, own, a.class));
                        continue;
                    }
                    let Some(adm) = self.admissible(ctx, conn, &s) else { continue };
                    // Its credential still admissible, its class still the one it declared.
                    if !adm.tests.iter().any(|t| t.matched(&s) == m) || adm.own != own {
                        continue;
                    }
                    if !self.replier_proved(ctx, &bind, &s, &cred, &a, adm.j) {
                        continue;
                    }
                    let by = cred.credential(&s);
                    self.open(ctx, conn, s, Member { class: a.class, own, by, until: None, departed: None }, Some(beacon), moved);
                }
                Sent::ByRole(s, own) if a.code == Code::OK => {
                    accepted.insert(s);
                    crossed.extend(self.crossed(conn, s, own, a.class));
                    // An accepted ByRole opens S at its sender while J is still reader there, or
                    // while it follows S by a value alone (it judges nobody).
                    if self.member(conn, &s).is_none() && self.admissible(ctx, conn, &s).is_some_and(|a| (a.j == J::Reader || a.by_role || a.stopped) && a.own == own) {
                        self.open(ctx, conn, s, Member { class: a.class, own, by: Credential::J, until: None, departed: None }, None, moved);
                    }
                }
                // refused: tried again once something re-marks S or moves `changed_at(S)` (§5)
                Sent::ByRole(..) => {}
                Sent::Behind(s, named) => {
                    let Some(c) = self.conns.get_mut(&conn) else { continue };
                    let w = c.walks.entry(s).or_default();
                    if a.code == Code::RATE_LIMITED {
                        c.retries.insert((ctx.mono.after(crate::inbox::backoff_ms(w.backoffs)), s));
                        w.backoffs = w.backoffs.saturating_add(1);
                    } else {
                        w.backoffs = 0;
                    }
                    // the walk goes on (tested again) with each step it learns there, and after
                    // each refusal on an earlier step; each step is refused once per walk, and
                    // an answer naming only steps it knows changes nothing
                    let retest = match (a.code, a.grant) {
                        (Code::OK, Some(g)) => {
                            let mut known = ctx.holds.verify_steps(&s, &w.known, &g.steps);
                            known.retain(|st| !w.known.iter().any(|k| k.id() == st.id()));
                            let new = !known.is_empty();
                            w.known.extend(known);
                            new
                        }
                        // The source does not keep S: once it does, its filter shows its step's
                        // sync key (spec/sync-opens.md §4 Admissible) and a test opens it.
                        (Code::UNKNOWN_SYNC_ID, _) => false,
                        // Refused for now: asked again after a back-off (`retries`), never
                        // counted as off the path.
                        (Code::RATE_LIMITED, _) => false,
                        // Refused on a step: off the source's path; ask on an earlier one.
                        _ => w.refused.insert(named),
                    };
                    if retest {
                        self.remark(conn, &s);
                    }
                }
            }
        }
        // Once all answers are read: Lost each S the peer accepted and this side did not open.
        let lost: Vec<SyncId> = accepted.into_iter().filter(|s| self.member(conn, s).is_none()).collect();
        if !lost.is_empty() {
            let items = lost.iter().map(|s| (*s, self.reported_at(conn, s).map(|(_, c)| c.clone()))).collect();
            self.send_lost(ctx, conn, items);
        }
        for s in crossed {
            self.close_member(ctx, conn, s, Close::Class, moved);
        }
        self.rise(conn);
        if let Some(c) = self.conns.get_mut(&conn) {
            c.test_due = true;
        }
    }

    /// S, open on `conn` already by a crossing exchange, when the classes this exchange declared
    /// (`own`, the peer's `peer`) are not the member's: the peer may have opened S by this one, so
    /// the two sides disagree on a class, and S closes as for a class move (spec/sync-opens.md §4
    /// Source). One being ended closes at its `until` as it is.
    fn crossed(&self, conn: ConnId, s: SyncId, own: SourceClass, peer: SourceClass) -> Option<SyncId> {
        self.member(conn, &s).filter(|m| m.until.is_none() && (m.own, m.class) != (own, peer)).map(|_| s)
    }

    /// The tester's own proof of the replier (spec/sync-opens.md §5): J judges it a holder, or
    /// the answer proves it: a tag keyed by a secret is its own proof; for a sync key or claim, an
    /// open signature by the sync key of the step hit; for a static or the public entry, the
    /// grant's head sync key, the grant taken once it verifies.
    fn replier_proved(&mut self, ctx: &mut Ctx, bind: &Bind, s: &SyncId, cred: &Tested, a: &SharedItem, j: J) -> bool {
        let by_j = matches!(j, J::Reader | J::SyncHolder);
        let key = match cred {
            // the grant's secrets are taken once `sig` verifies under its head's sync key, whatever
            // J says; J alone may count the replier proved
            Tested::Static { .. } | Tested::Public => {
                let entry = cred.matched(s);
                let (Some(sig), Some(g)) = (&a.sig, a.grant.as_ref()) else { return by_j };
                return ctx.holds.take_grant(s, &entry, g, &|k| bind.peer_signed(k, s, sig)) || by_j;
            }
            _ if by_j => return true,
            Tested::Read(..) | Tested::Proof(..) => return true,
            // The replier's step is the step hit: a step older than the one hit proves nothing.
            Tested::SyncKey { key, .. } => key.verifying_key().to_bytes(),
            Tested::Claim { sync, .. } => *sync,
        };
        a.sig.as_ref().is_some_and(|sig| bind.peer_signed(&key, s, sig))
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
                OfferItem::Hit { hit, sig, class } => self.accept_hit(ctx, conn, &hit, sig.as_ref(), None, class, moved),
                OfferItem::Static { hit, signing_pk, sig, class } => self.accept_hit(ctx, conn, &hit, Some(&sig), Some(signing_pk), class, moved),
                OfferItem::ByRole { sync_id, hits, class } => self.accept_by_role(ctx, conn, sync_id, &hits, class, moved),
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

    /// `class`: the class the peer declared in its item.
    #[allow(clippy::too_many_arguments)]
    fn accept_hit(&mut self, ctx: &mut Ctx, conn: ConnId, hit: &[u8; 32], sig: Option<&osis_crypto::Signature>, signing: Option<[u8; 32]>, class: SourceClass, moved: &mut Vec<Moved>) -> SharedItem {
        let refuse = SharedItem::code(Code::DECLINED);
        let Some(c) = self.conns.get(&conn) else { return refuse };
        let Some((s, shown, beacon)) = c.shown.get(hit).cloned() else { return refuse };
        let (bind, proven) = (c.bind, c.proven.clone());
        // Judged on what this side holds now: a credential no longer shown proves nothing.
        let Some(adm) = self.admissible(ctx, conn, &s) else { return refuse };
        // a departed peer's Hit on its step (a store) or on a superseded epoch it reads at: opened
        // only ended, a store to be moved past its keys, a reader to be served up to its departure
        // (or, by a lapsed read secret, any peer holding it up to that epoch's supersession)
        let walk = adm.walk.contains(&shown)
            && match shown {
                Shown::Proof(..) => class == SourceClass::Store,
                // a store reads nothing: a read secret proves a reader
                Shown::Read(..) => class != SourceClass::Store,
                _ => false,
            };
        if !adm.shows.contains(&shown) && !walk {
            return refuse;
        }
        // A deposit key's Hit carries no proof and opens nothing.
        let Some(by) = shown.credential() else { return refuse };
        let proved = match (&shown, signing) {
            (Shown::Read(..) | Shown::Proof(..), None) => true,
            (Shown::SyncKey(k) | Shown::Claim(k), None) => sig.is_some_and(|g| bind.peer_signed(k, &s, g)),
            (Shown::Static(e), None) => proven_statics(&s, &proven).contains(e),
            (Shown::Static(e), Some(pk)) => osis_crypto::VerifyingKey::from_bytes(&pk).is_ok_and(|k| osis_crypto::static_entry(&s, &k) == *e) && sig.is_some_and(|g| bind.peer_signed(&pk, &s, g)),
            // anyone may hold S: the Hit proves only that it is bound to this connection
            (Shown::Public(_), None) => true,
            // a Static item names a static entry
            (_, Some(_)) | (Shown::Deposit(_), None) => false,
        };
        if !proved {
            return refuse;
        }
        let secret = matches!(shown, Shown::Read(..) | Shown::Proof(..));
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
            Shown::Static(e) | Shown::Public(e) => ctx.holds.grant(&s, e),
            _ => None,
        };
        // served up to its `until` here already: nothing more to serve it (a departed peer: once
        // told its removals, `judge`)
        if walk && matches!(shown, Shown::Read(..)) && let Some(u) = self.conns.get(&conn).and_then(|c| c.served.get(&s)).copied() {
            let until = match adm.j {
                J::Departed => self.conns.get(&conn).is_some_and(|c| c.told_departed.contains(&s)).then(|| ctx.holds.departure_until(&s)),
                _ => Some(ctx.holds.until(&s, &by)),
            };
            if until.is_some_and(|x| u >= x) {
                return refuse;
            }
        }
        let m = Member { class, own: adm.own, by, until: None, departed: None };
        if self.open(ctx, conn, s, m, Some(beacon), moved) && walk {
            self.rejudge(ctx, conn, s, moved);
        }
        SharedItem { code: Code::OK, tag: Some(bind.tag(shown.matched(), &s, &beacon)), grant, sig: answer_sig, class: adm.own }
    }

    /// ByRole (spec/sync-opens.md §5): opens S when this side holds S and J judges the peer a
    /// reader, or a listed Hit is its own of a read secret or a static entry, carrying its proof.
    fn accept_by_role(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, hits: &[[u8; 32]], class: SourceClass, moved: &mut Vec<Moved>) -> SharedItem {
        let Some(adm) = self.admissible(ctx, conn, &s) else { return SharedItem::code(Code::DECLINED) };
        let ok = SharedItem { class: adm.own, ..SharedItem::code(Code::OK) };
        if matches!(adm.j, J::Reader | J::SyncHolder) {
            self.open(ctx, conn, s, Member { class, own: adm.own, by: Credential::J, until: None, departed: None }, None, moved);
            return ok;
        }
        // J judges the peer no holder: followed, so S is tested here again once it is one
        if let Some((rid, named)) = self.conns.get(&conn).and_then(|c| Some((c.rec?, c.named.clone()))) {
            self.follow(ctx, rid, s, &named);
            if let Some(c) = self.conns.get_mut(&conn) {
                c.asked.insert(s);
            }
        }
        let Some(c) = self.conns.get(&conn) else { return SharedItem::code(Code::DECLINED) };
        let proven = c.proven.clone();
        let statics = proven_statics(&s, &proven);
        let found = hits.iter().filter_map(|h| c.shown.get(h).cloned()).find_map(|(hs, sh, b)| {
            let own = hs == s
                && adm.shows.contains(&sh)
                && match &sh {
                    Shown::Read(..) => true,
                    Shown::Static(e) => statics.contains(e),
                    _ => false,
                };
            sh.credential().filter(|_| own).map(|by| (by, b))
        });
        match found {
            Some((by, b)) => {
                self.open(ctx, conn, s, Member { class, own: adm.own, by, until: None, departed: None }, Some(b), moved);
                ok
            }
            None => SharedItem::code(Code::DECLINED),
        }
    }

    // ---- members, ending and Lost (§6) ----

    /// Opens S on `conn` unless it is a member there already. Whether it opened.
    fn open(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, m: Member, beacon: Option<[u8; 32]>, moved: &mut Vec<Moved>) -> bool {
        let Some(c) = self.conns.get(&conn) else { return false };
        let Some(rid) = c.rec else { return false };
        if self.records.get(&rid).is_none_or(|r| r.members.contains_key(&s)) {
            return false;
        }
        // its standing is followed from here (spec/sync-opens.md §6)
        let named = c.named.clone();
        self.follow(ctx, rid, s, &named);
        let Some(r) = self.records.get_mut(&rid) else { return false };
        r.members.insert(s, m);
        r.basis.insert(s, beacon);
        if let Some(c) = self.conns.get_mut(&conn) {
            // the walk ends: a credential refused before may be the source's step later
            if let Some(w) = c.walks.get_mut(&s) {
                w.unshown.clear();
            }
            c.reported.opened(s);
        }
        let rejoin = r.stopped.remove(&s).unwrap_or(Rejoin::From(None));
        self.dirty(rid).members.insert(s);
        self.member_moved(conn, &s, true);
        let src = self.source_of(conn);
        self.hold(s, rid, src);
        self.peers.wrote(&s, true);
        moved.push(Moved::Joined(conn, s, rejoin));
        self.set_stop(conn, s, None);
        self.tell(ctx, conn, s, false);
        true
    }

    /// Sends the peer on `conn` the notices S's things tell it (spec/permissions.md §4 Notices,
    /// `Holds::notices`) not yet sent on this connection: to a member opened by role or at a
    /// store source (`departed` false), the newest box of each holder it reaches that cannot open
    /// it by its wrap; to one ended for its departure, its departure. Whether a notice of its
    /// departure went.
    /// Cost: one `Engine::notices_for` per open and per member judged; a notice sealed once per
    /// connection.
    fn tell(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, departed: bool) -> bool {
        // a member by a read secret holds the epoch it shows: its boxes open by their wraps
        if !departed && self.member(conn, &s).is_some_and(|m| m.by != Credential::J && m.class != SourceClass::Store) {
            return false;
        }
        let proven = self.proven_on(ctx, conn);
        let notices = ctx.holds.notices(&s, &proven);
        let Some(c) = self.conns.get_mut(&conn) else { return false };
        for n in notices.into_iter().filter(|n| n.departs == departed) {
            if c.told.insert((s, n.key)) {
                ctx.wire.push(conn, Msg::Notice { sync_id: s, holder: n.holder, epoch: n.epoch, notice: n.bytes });
            }
            if n.departs {
                c.told_departed.insert(s);
            }
        }
        c.told_departed.contains(&s)
    }

    /// Re-judges member S of `conn` (`judge`).
    fn rejudge(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, moved: &mut Vec<Moved>) {
        if let Some(rid) = self.conns.get(&conn).and_then(|c| c.rec) {
            self.judge(ctx, rid, s, moved);
        }
    }

    /// Judges member S of record `rid` again (spec/sync-opens.md §6), whether or not a connection
    /// holds the record: J reader or sync holder stays; an open by a credential stays while it is
    /// admissible; one no longer admissible whose peer J judges neither holder nor departed is
    /// ended (`until`, judged now), and stays ended until it closes; one whose peer J judges
    /// departed is ended too (`Member::departed`: told its departure, served the public's edge alone; at a store source it
    /// closes on the peer's Lost alone), and closes at once once its peer is not; any other closes at once (with a Lost where a connection
    /// holds the record), as does any whose peer is no one once no connection holds the record.
    /// One that stays, not ended, closes keeping where it stopped once this side's class is not
    /// the one it declared opening S (an ended one opens again past its `until` anyway).
    fn judge(&mut self, ctx: &mut Ctx, rid: RecordId, s: SyncId, moved: &mut Vec<Moved>) {
        let Some(r) = self.records.get(&rid) else { return };
        let Some(m) = r.members.get(&s).cloned() else { return };
        self.work.rejudged += 1;
        osis_base::costs::count("opens: members judged", 1);
        let conn = self.conn_on(rid);
        // who the peer is: what the connection proved (a record kept nowhere names nothing), else
        // what the record names
        let named = match conn.and_then(|c| self.conns.get(&c)) {
            Some(c) => c.named.clone(),
            None => r.named.clone(),
        };
        let (rr, basis) = (r.r, r.basis.get(&s).copied().flatten());
        let j = self.follow(ctx, rid, s, &named);
        let Some(adm) = self.admissible_as(ctx, &s, j.unwrap_or(J::Unknown)) else {
            // S left the sync set: closes at once.
            self.end_member(ctx, rid, conn, s, Close::Left, moved);
            return;
        };
        // a peer that is no one never resumes the record: kept for no connection, nothing waits
        // on its return (while a connection holds it, its session's proofs stand)
        if j.is_none() && conn.is_none() {
            self.end_member(ctx, rid, conn, s, Close::AtOnce, moved);
            return;
        }
        // a member by J at a side following S by a value alone stays while it does
        let holder = matches!(adm.j, J::Reader | J::SyncHolder) || ((adm.by_role || adm.stopped) && m.by == Credential::J);
        let admissible = m.by != Credential::J
            && basis.is_some_and(|b| adm.shows.iter().any(|x| beacon_of(x.matched(), &s, &rr) == b) || adm.tests.iter().any(|t| beacon_of(&t.matched(&s), &s, &rr) == b));
        let stays = holder || admissible;
        // a peer no longer departed: its stream skipped all but the public's edge, so its member closes
        // at once, naming no position (`close_member`)
        if m.departed.is_some() && adm.j != J::Departed {
            self.end_member(ctx, rid, conn, s, Close::AtOnce, moved);
            return;
        }
        // An ended member judged holder or admissible again stays ended: the peer's stream may be
        // past `until` already (S's entries since skipped), so it closes there and opens again.
        if stays {
            if m.own != adm.own && m.until.is_none() {
                self.end_member(ctx, rid, conn, s, Close::Class, moved);
            } else if let Some(c) = conn {
                self.tell(ctx, c, s, false);
            }
        } else if adm.j == J::Departed {
            // ended for its departure: told its departure, served the public's edge alone (a reader learns
            // its removal there); a store learns it only by a Register, so it stays while this
            // side registers past its keys, until its own Lost
            if m.departed.is_none() {
                // at a store the position of its head's event; at a reader the public's edge's,
                // once its notices went on a connection (`tell`)
                let none = osis_blob::Certificates::default();
                let copies = conn.and_then(|c| self.conns.get(&c)).map_or(&none, |k| &k.proven.copies);
                let proven = proven_things(ctx, &named, copies);
                self.set_departed(rid, &s, Arc::new(proven));
                let until = match m.class {
                    SourceClass::Store => Some(m.until.unwrap_or_else(|| ctx.holds.until(&s, &m.by))),
                    _ => m.until.or_else(|| conn.is_some_and(|c| self.tell(ctx, c, s, true)).then(|| ctx.holds.departure_until(&s))),
                };
                if let Some(u) = until {
                    self.set_until(rid, &s, u, moved);
                }
                if let Some(c) = conn {
                    self.close_if_reached(ctx, c, s, moved);
                }
            }
        } else if m.by == Credential::J {
            self.end_member(ctx, rid, conn, s, Close::AtOnce, moved);
        } else if m.until.is_none() {
            let until = ctx.holds.until(&s, &m.by);
                self.set_until(rid, &s, until, moved);
            if let Some(c) = conn {
                self.close_if_reached(ctx, c, s, moved);
            }
        }
    }

    /// The things the peer on `conn` proved (`proven_things`).
    fn proven_on(&self, ctx: &mut Ctx, conn: ConnId) -> BTreeSet<osis_base::Tid> {
        let Some(c) = self.conns.get(&conn) else { return BTreeSet::new() };
        proven_things(ctx, &c.named, &c.proven.copies)
    }

    /// Closes member S of record `rid` for `why`: on the connection holding it (`close_member`),
    /// else in the record alone, keeping nothing of where it stopped (a stop lasts only a
    /// connection): its peer finds it closed by the next take's digest (§3 Agreement).
    fn end_member(&mut self, ctx: &mut Ctx, rid: RecordId, conn: Option<ConnId>, s: SyncId, why: Close, moved: &mut Vec<Moved>) {
        if let Some(c) = conn {
            self.close_member(ctx, c, s, why, moved);
            return;
        }
        let Some(r) = self.records.get_mut(&rid) else { return };
        if r.members.remove(&s).is_none() {
            return;
        }
        r.basis.remove(&s);
        let kept = r.kept;
        self.unfollow_member(rid, s);
        ctx.holds.unfollow(rid, &s);
        self.hold(s, rid, None);
        self.peers.wrote(&s, true);
        if kept {
            self.record_members.wrote(&(Source::Record(rid), s), false);
            self.dirty(rid).members.insert(s);
            moved.push(Moved::Gone(rid, s));
        }
        // re-marked (§5 Testing): the next connection tests S again
        if let Some(pos) = self.changed.at.get(&s).map(|(p, ..)| p.saturating_sub(1))
            && self.records.get(&rid).is_some_and(|r| r.acked_pos > pos)
        {
            self.set_acked(rid, pos);
        }
    }

    /// J of member S of record `rid` (`Holds::standing`; `None`: its peer is no one), followed
    /// from here: judged with the copies of the connection holding it, if one does.
    fn follow(&mut self, ctx: &mut Ctx, rid: RecordId, s: SyncId, named: &Named) -> Option<J> {
        self.unfollowed.remove(&(rid, s));
        self.followed.entry(rid).or_default().insert(s);
        let none = osis_blob::Certificates::default();
        let copies = self.conn_on(rid).and_then(|c| self.conns.get(&c)).map_or(&none, |k| &k.proven.copies);
        ctx.holds.standing(rid, &s, named, copies)
    }

    /// Member S of record `rid` is no longer followed here (`Holds::unfollow` is the caller's).
    fn unfollow_member(&mut self, rid: RecordId, s: SyncId) {
        if let Some(f) = self.followed.get_mut(&rid) {
            f.remove(&s);
            if f.is_empty() {
                self.followed.remove(&rid);
            }
        }
    }

    /// Record `rid` went: its members are unfollowed at the next `tick`.
    fn unfollow_record(&mut self, rid: RecordId) {
        for s in self.followed.remove(&rid).unwrap_or_default() {
            self.unfollowed.insert((rid, s));
        }
    }

    /// Marks ended member S of record `rid` as ended for its peer's departure (`Member::departed`):
    /// it takes its `until` at a report (`close_if_reached`).
    fn set_departed(&mut self, rid: RecordId, s: &SyncId, proven: Arc<BTreeSet<osis_base::Tid>>) {
        let Some(m) = self.records.get_mut(&rid).and_then(|r| r.members.get_mut(s)) else { return };
        if m.departed.is_some() {
            return;
        }
        m.departed = Some(proven);
        if let Some(c) = self.conn_on(rid)
            && let Some(k) = self.conns.get_mut(&c)
        {
            k.ending.insert(*s);
        }
        self.member_changed(rid, s);
    }

    /// Ends member S of record `rid`: sets its `until`; streams on the connection holding it
    /// hears of it (`Moved::Until`), and a connection taking it later finds it ended.
    fn set_until(&mut self, rid: RecordId, s: &SyncId, until: Position, moved: &mut Vec<Moved>) {
        let Some(m) = self.records.get_mut(&rid).and_then(|r| r.members.get_mut(s)) else { return };
        if m.until == Some(until) {
            return;
        }
        m.until = Some(until);
        if let Some(c) = self.conn_on(rid)
            && let Some(k) = self.conns.get_mut(&c)
        {
            k.ending.insert(*s);
            moved.push(Moved::Until(c, *s));
        }
        self.member_changed(rid, s);
    }

    /// Member S of record `rid` changed in place: stamped, and written at `flush`.
    fn member_changed(&mut self, rid: RecordId, s: &SyncId) {
        match self.conn_on(rid) {
            Some(c) => self.member_moved(c, s, true),
            None => self.record_members.wrote(&(Source::Record(rid), *s), true),
        }
        if self.records.get(&rid).is_some_and(|r| r.kept) {
            self.dirty(rid).members.insert(*s);
        }
    }

    /// Closes member S of `conn` (spec/sync-opens.md §6), back to testing with a Lost naming where
    /// it stopped for the peer (the member is closed before its Lost goes); `why` says what of
    /// where it stopped this side keeps.
    fn close_member(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, why: Close, moved: &mut Vec<Moved>) {
        let Some(m) = self.member(conn, &s).cloned() else { return };
        if let (Close::Until, Some(u), Some(c)) = (why, m.until, self.conns.get_mut(&conn)) {
            let at = c.served.entry(s).or_insert(u);
            *at = (*at).max(u);
        }
        // one ended for its departure was shown the public's edge alone: its position past the rest
        // names nothing it holds, so its peer rejoins from the start
        let cursor = match why {
            Close::Left => None,
            _ if m.departed.is_some() => None,
            _ => self.stopped_for_peer(ctx, conn, &s, m.until),
        };
        self.drop_member(conn, s, matches!(why, Close::Until | Close::Class).then_some(Rejoin::Held), moved);
        self.remark(conn, &s);
        self.send_lost(ctx, conn, vec![(s, cursor)]);
    }

    /// Where member S stopped for the peer (spec/sync-opens.md §6 Lost): its reported position, or
    /// `until` where lower.
    fn stopped_for_peer(&self, ctx: &mut Ctx, conn: ConnId, s: &SyncId, until: Option<Position>) -> Option<Cursor> {
        match (until, self.reported_at(conn, s)) {
            (Some(u), Some((p, _))) if u < *p => ctx.holds.cursor_at(u),
            (_, r) => r.map(|(_, c)| c.clone()),
        }
    }

    /// Removes member S from `conn`'s record, keeping `stop` as where it stopped (none: nothing is
    /// kept, so what its source showed goes and its rejoin is from the start).
    fn drop_member(&mut self, conn: ConnId, s: SyncId, stop: Option<Rejoin>, moved: &mut Vec<Moved>) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let Some(rid) = c.rec else { return };
        let Some(r) = self.records.get_mut(&rid) else { return };
        let Some(m) = r.members.remove(&s) else { return };
        self.member_stamps.wrote(&(conn, s), false);
        let src = if r.kept { Source::Record(rid) } else { Source::Conn(conn) };
        self.record_members.wrote(&(src, s), false);
        self.unfollowed.insert((rid, s));
        if self.followed.get_mut(&rid).is_some_and(|f| f.remove(&s) && f.is_empty()) {
            self.followed.remove(&rid);
        }
        let at = LeftAt { src, reported: c.reported.get(&s).filter(|_| m.departed.is_none()).map(|(p, _)| *p), until: m.until, how: if stop.is_some() { Leaving::Kept } else { Leaving::Forgot } };
        c.reported.forget(&s);
        self.reports.wrote(&conn, true);
        c.ending.remove(&s);
        r.basis.remove(&s);
        match stop {
            Some(j) => r.stopped.insert(s, j),
            None => r.stopped.remove(&s),
        };
        self.hold(s, rid, None);
        self.peers.wrote(&s, true);
        moved.push(Moved::Left(conn, s, at));
        self.dirty(rid).members.insert(s);
    }

    fn send_lost(&mut self, ctx: &mut Ctx, conn: ConnId, items: Vec<(SyncId, Option<Cursor>)>) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        for chunk in items.chunks(MAX_OFFER_ITEMS) {
            let items = chunk.iter().map(|(s, cur)| (*s, cur.clone().and_then(|b| osis_proto::Cursor::new(b).ok()))).collect();
            let id = ctx.wire.request(conn, Msg::Lost { id: 0, items });
            c.reqs.insert(id, Req::Lost);
        }
    }

    /// The peer's Lost (spec/sync-opens.md §6): each member open here named closes, where it
    /// stopped set to the Lost's cursor (none: nothing kept), S re-marked, and is answered with
    /// this side's own Lost; a stop this side keeps (closed here first: the two crossed) takes the
    /// cursor alike.
    fn lost(&mut self, ctx: &mut Ctx, conn: ConnId, id: Id, items: Vec<osis_proto::Join>, moved: &mut Vec<Moved>) {
        let n = items.len();
        let mut answer = Vec::new();
        for (s, cur) in items {
            let stop = cur.map(|c| Rejoin::From(Some(c.into_bytes())));
            if let Some(m) = self.member(conn, &s).cloned() {
                // where it stopped for the peer, read before the member goes
                answer.push((s, self.stopped_for_peer(ctx, conn, &s, m.until)));
                self.drop_member(conn, s, stop, moved);
                self.remark(conn, &s);
            } else if let Some(r) = self.conns.get(&conn).and_then(|c| c.rec).and_then(|r| self.records.get_mut(&r))
                && r.stopped.contains_key(&s)
            {
                match stop {
                    Some(j) => drop(r.stopped.insert(s, j)),
                    None => {
                        r.stopped.remove(&s);
                        moved.push(Moved::Forgot(conn, s));
                    }
                }
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
        if let Some(rid) = c.rec
            && self.records.get(&rid).is_some_and(|r| r.acked_pos > below)
        {
            self.set_acked(rid, below);
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
        let Some(rid) = c.rec else { return };
        let Some(r) = self.records.get(&rid) else { return };
        let to = r.acked_pos.max(r.own.acked_reach.min(tested));
        if to != r.acked_pos {
            self.set_acked(rid, to);
        }
    }

    /// Record `rid`'s `acked_pos` moves to `to` (written at `flush`).
    fn set_acked(&mut self, rid: RecordId, to: u64) {
        let Some(r) = self.records.get_mut(&rid) else { return };
        let was = r.kept.then(|| (r.acked_pos, r.named.clone()));
        r.acked_pos = to;
        self.dirty(rid).core = true;
        self.acks_moved(rid, was);
    }

    /// Record `rid`'s `acked_pos` or what it names moved from `was` (none: not indexed, a new
    /// record): `acks` follows, and `peers` is stamped for each S whose `changed_at` lies between
    /// the two positions (every S past the lower one, and each S it holds as a member, when what
    /// it names changed, an account's new key included: who may hold S is judged by it, a
    /// revoked key not awaited). O(sync IDs stamped): what the record's next filter iterates.
    fn acks_moved(&mut self, rid: RecordId, was: Option<(u64, Named)>) {
        let now = self.records.get(&rid).filter(|r| r.kept).map(|r| (r.acked_pos, r.named.clone()));
        if now == was {
            return;
        }
        let (lo, hi) = match (&was, &now) {
            (Some((a, x)), Some((b, y))) if x == y => ((*a).min(*b), (*a).max(*b)),
            _ => (was.iter().chain(&now).map(|(p, _)| *p).min().unwrap_or(0), u64::MAX),
        };
        let mut moved: Vec<SyncId> = if lo < hi { self.changed.order.range(lo + 1..=hi).map(|(_, s)| *s).collect() } else { Vec::new() };
        if hi == u64::MAX {
            moved.extend(self.records.get(&rid).into_iter().flat_map(|r| r.members.keys().copied()));
        }
        for s in moved {
            self.peers.wrote(&s, true);
        }
        if let Some(acks) = &mut self.acks {
            acks.set(rid, now.as_ref().map(|(p, n)| (*p, n)));
        }
    }
}

/// Answers a filter page breaking the format and closes the connection (spec/wire.md §11.2).
fn break_format(ctx: &mut Ctx, conn: ConnId, id: Id, why: &'static str) {
    ctx.wire.answer(conn, id, Msg::Error { id, code: Code::MALFORMED });
    ctx.wire.close(conn, why);
}

/// The static entries of S whose link key the peer proved on this connection by its signing key
/// (spec/sync-opens.md §5 Proof).
fn proven_statics(s: &SyncId, p: &Proven) -> Vec<[u8; 32]> {
    p.keys().filter_map(|k| osis_crypto::VerifyingKey::from_bytes(k).ok()).map(|k| osis_crypto::static_entry(s, &k)).collect()
}

fn random<const N: usize>(rng: &mut dyn NodeRng) -> [u8; N] {
    let mut b = [0u8; N];
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

/// The things a peer naming `named` proves, with `copies` (`Holds::counts`): what a departed
/// peer is told and served by (`Member::departed`).
fn proven_things(ctx: &mut Ctx, named: &Named, copies: &osis_blob::Certificates) -> BTreeSet<osis_base::Tid> {
    ctx.holds.counts(named, copies).into_iter().map(|p| p.thing).collect()
}
