//! Records, agreement and the shared set (spec/sync-opens.md §2-§6).
//!
//! **Principle:** each side opens S toward a peer only on its own proof, judged on what it holds
//! now, that the peer may hold S; who dialed proves nothing (model core/test/tla/net/NetOpen.tla).
//!
//! State: records (spec/sync-opens.md §3: pair key, proven claims, the shared set with each
//! member's credential and beacon, `acked_pos`, this side's filter generations and the peer's
//! latest filter, where members that left stopped); per connection its binding, phase,
//! agreement, filter generations in flight, the Hits its filter makes possible, the Offer in
//! flight, reported positions; `changed_at` per S with the credentials it was
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
    /// (spec/sync-status.md §2).
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
    /// Its credential no longer admissible: nothing kept.
    AtOnce,
    /// S left this node's sync set: nothing kept, and its Lost names no position.
    Left,
    /// This side's class moved: kept as at `Until`, and S opens again by testing. Either, for a
    /// member this side declared a stub that no longer holds S so: as `AtOnce`.
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
    /// The beacon each member was opened by.
    basis: BTreeMap<SyncId, [u8; 32]>,
    /// Where each member closed on the connection holding the record stopped (spec/sync-opens.md
    /// §6 Where it stopped): where this side's stream holds it (closed here at its `until`), or the
    /// peer's Lost's cursor. Memory only: it goes when that connection lets the record go.
    stopped: BTreeMap<SyncId, Rejoin>,
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
    /// A Head of S, with the steps its earlier answers gave (asked again from the last).
    Head { s: SyncId, got: Vec<osis_blob::Step> },
}

/// An Offer item sent, to read its answer by.
#[derive(Clone, Debug)]
enum Sent {
    /// `own`: the class this side declared in it.
    Hit { s: SyncId, cred: Box<Tested>, beacon: [u8; 32], own: SourceClass },
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
    offer: Option<Vec<Sent>>,
    /// Reported positions (spec/sync-opens.md §6 Lost): streams' word, through `reported`.
    reported: Positions,
    /// Members with an `until`: what a reported position may close.
    ending: BTreeSet<SyncId>,
    /// Ended members at a store source the registrar judged owed no Register since they ended
    /// (inbox's `take_owed`): only these close at their `until` (spec/sync-opens.md §6).
    unowed: BTreeSet<SyncId>,
    /// It lost its record to this connection (spec/sync-opens.md §1 One connection per pair):
    /// it closes, and acts on nothing meanwhile.
    lost_to: Option<ConnId>,
    /// Per S and the classes (own, peer's) it was open with, the highest `until` an ended member
    /// reached on this connection: a Hit declaring those classes on an older step's sync proof
    /// opens S again here only for a later one (spec/sync-opens.md §6); a class moved since (a
    /// reader that came to keep S unread) opens it anew.
    served: BTreeMap<(SyncId, SourceClass, SourceClass), Position>,
    /// Per S, the `changed_at` position at which this side last asked the peer Head: asked once
    /// per change of S, never again while S stands (spec/sync-ids.md §6 Head).
    asked_head: BTreeMap<SyncId, u64>,
    /// The beacons of this side's tested credentials of each S, by beacon, as last tested here:
    /// what a filter arrival's new entries are looked up in (spec/sync-opens.md §5 Testing).
    /// Built at the first arrival that needs it, then kept by each test of S.
    tested_ix: Option<TestedBeacons>,
    /// Sync IDs a filter arrival's new entries name: tested at the next test, whatever their
    /// `changed_at`.
    retest: BTreeSet<SyncId>,
}

/// `Conn::tested_ix`: beacon -> S, and per S its beacons.
#[derive(Clone, Debug, Default)]
struct TestedBeacons {
    by_beacon: BTreeMap<[u8; 32], SyncId>,
    of: BTreeMap<SyncId, Vec<[u8; 32]>>,
}

impl TestedBeacons {
    fn set(&mut self, s: SyncId, beacons: Vec<[u8; 32]>) {
        for b in self.of.remove(&s).unwrap_or_default() {
            self.by_beacon.remove(&b);
        }
        for b in &beacons {
            self.by_beacon.insert(*b, s);
        }
        if !beacons.is_empty() {
            self.of.insert(s, beacons);
        }
    }

    /// The sync IDs with a beacon whose first `f` bits are `v`.
    fn named(&self, v: u64, f: u8) -> impl Iterator<Item = SyncId> + '_ {
        let shift = 64 - u32::from(f.clamp(1, 64));
        let key = |x: u64| {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&x.to_be_bytes());
            k
        };
        let lo = v.checked_shl(shift).unwrap_or(0);
        let hi = v.checked_add(1).and_then(|x| x.checked_shl(shift)).filter(|x| *x > lo);
        let range = match hi {
            Some(h) => self.by_beacon.range(key(lo)..key(h)),
            None => self.by_beacon.range(key(lo)..),
        };
        range.map(|(_, s)| *s)
    }
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
    /// Stamped per (connection, S) as the connection's member S opens, changes (ended) or goes, the connection taking or letting go its record included (`member`:
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
    /// Other records of a pair one connection took (spec/sync-opens.md §3 One record per pair):
    /// removed at `flush` once no connection holds or lists one.
    dropped: BTreeSet<RecordId>,
    /// The connection holding each record: record R is connected on C.
    on: BTreeMap<RecordId, ConnId>,
    /// Records that left memory since `unloaded` was last read: streams keeps a record's place
    /// in memory as long as opens keeps the record.
    unloaded: Vec<RecordId>,
    /// Every kept record with a member is in memory and judged (read at the first settle).
    following: bool,
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
            held: BTreeMap::new(),
            fx: holds::Fx::default(),
            reports: osis_base::memo::Stamps::named("opens: reports"),
            peers: osis_base::memo::Stamps::named("opens: peers"),
            member_stamps: osis_base::memo::Stamps::named("opens: members"),
            record_members: osis_base::memo::Stamps::named("opens: record members"),
            connected: osis_base::memo::Stamps::named("opens: connected"),
            sources: osis_base::memo::Stamps::named("opens: sources"),
            acks: None,
            dropped: BTreeSet::new(),
            on: BTreeMap::new(),
            unloaded: Vec::new(),
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
    /// This node's class for S now (spec/sync-opens.md §4 Source).
    own: SourceClass,
    shows: Vec<Shown>,
    tests: Vec<Tested>,
    step: Option<osis_crypto::SigningSecret>,
    /// The sync key of this node's head (none: no head here).
    head: Option<[u8; 32]>,
}

impl Adm {
    /// Whether `by` is a credential of the head (spec/sync-opens.md §4 One open rule): the sync
    /// proof of the head's sync key or of a sync secret held newer than the head's (a step past
    /// this node's path: the head has not moved past it), or a head claim (shown: bound to the
    /// head here; tested: at the source's step); with no head here, any proof.
    fn of_head(&self, by: &Credential) -> bool {
        // tested proofs are newest first
        let at = |k: &[u8; 32]| self.tests.iter().position(|t| matches!(t, Tested::Proof(_, x) if x == k));
        match by {
            Credential::SyncProof(k) => self.head.is_none_or(|h| h == *k || at(k).zip(at(&h)).is_some_and(|(a, b)| a < b)),
            Credential::ClaimKey(k) => self.shows.contains(&Shown::ClaimKey(*k)) || self.tests.iter().any(|t| matches!(t, Tested::ClaimKey { key, .. } if key.verifying_key().to_bytes() == *k)),
        }
    }
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
    /// go from `held` and read as gone. `src`: where its rows live.
    fn forget_record(&mut self, id: RecordId, src: Source) -> Option<Record> {
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

    /// The registrar's word (inbox's `take_owed`): whether a Register is owed at the store source
    /// at `src` for S. An ended member there owed none closes at its `until` once reached.
    pub fn on_owed(&mut self, cx: &mut Cx, sessions: &mut Sessions, unread: &Unread, owed: Vec<(Source, SyncId, bool)>, moved: &mut Vec<Moved>) {
        self.live(cx, sessions, unread, |o, ctx| {
            for (src, s, owed) in owed {
                let Some(conn) = o.conn_of(src) else { continue };
                let Some(c) = o.conns.get_mut(&conn) else { continue };
                if owed || !c.ending.contains(&s) {
                    c.unowed.remove(&s);
                } else if c.unowed.insert(s) {
                    o.close_if_reached(ctx, conn, s, moved);
                }
            }
        });
    }

    /// An ended member whose reported position is at or past its `until` closes with a Lost; at
    /// a store source only once no Register is owed there (spec/sync-opens.md §6).
    fn close_if_reached(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, moved: &mut Vec<Moved>) {
        let Some(m) = self.member(conn, &s) else { return };
        let Some(until) = m.until else { return };
        if m.class == SourceClass::Store && !self.conns.get(&conn).is_some_and(|c| c.unowed.contains(&s)) {
            return;
        }
        if self.reported_at(conn, &s).is_some_and(|(p, _)| *p >= until) {
            self.close_member(ctx, conn, s, Close::Until, moved);
        }
    }

    pub fn next_wake(&self) -> Option<Mono> {
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
        self.run(ctx, conn);
    }

    /// A connection ended: each of its members left (its record keeps them).
    pub fn closed(&mut self, conn: ConnId, moved: &mut Vec<Moved>) {
        self.release(conn, moved);
        self.conns.remove(&conn);
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
    /// in memory is read from its rows (its peer filter left for a take) and its members judged,
    /// so a member is re-judged at each change whether or not a connection held
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
        for (s, m) in &r.members {
            self.member_stamps.wrote(&(conn, *s), false);
            self.peers.wrote(s, true);
            if let Source::Conn(_) = src {
                moved.push(Moved::Left(conn, *s, LeftAt { src, reported: c.reported.get(s).map(|(p, _)| *p), until: m.until, how: Leaving::Kept }));
            }
        }
        // where members closed on this connection stopped lasts the connection
        moved.extend(r.stopped.keys().map(|s| Moved::Forgot(conn, *s)));
        if let Source::Record(rid) = src {
            moved.push(Moved::Released(conn, rid));
        }
        let Some(r) = self.records.get_mut(&rid) else { return };
        r.stopped.clear();
        // a kept one stays in memory until `flush` writes it (or another connection takes it)
        if !r.kept {
            self.forget_record(rid, src);
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
        let conns: Vec<ConnId> = self.conns.keys().copied().collect();
        for c in conns {
            if let Some(k) = self.conns.get_mut(&c)
                && k.resync_at.is_some_and(|t| t <= ctx.mono)
            {
                k.resync_at = None;
                k.whole_next = true;
            }
            self.run(ctx, c);
        }
        moved.len() > before
    }

    /// This node holds S no more (spec/sync-set.md §3 Stopping, spec/sync-opens.md §3, §6 Where it
    /// stopped): S's credentials went to none, or its rows went with a shred. S drops from every
    /// record in this step: its members on a connection close with a Lost naming none, each
    /// connection whose record keeps where S stopped is told nothing of S is kept here, and what
    /// is kept of S for a record no connection holds goes.
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
        for r in self.records.values_mut() {
            r.members.remove(&s);
            r.basis.remove(&s);
            r.stopped.remove(&s);
        }
        for d in self.dirty.values_mut() {
            d.members.remove(&s);
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
            self.index_shown(c, &s);
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
            offer: None,
            reported: Positions::default(),
            ending: BTreeSet::new(),
            unowed: BTreeSet::new(),
            lost_to: None,
            served: BTreeMap::new(),
            asked_head: BTreeMap::new(),
            tested_ix: None,
            retest: BTreeSet::new(),
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
        self.records.insert(id, Record { r, named, kept, members: BTreeMap::new(), basis: BTreeMap::new(), stopped: BTreeMap::new(), acked_pos: 0, own: OwnFilter::default(), peer: None, told: true });
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
        c.ending = r.members.iter().filter(|(_, m)| m.until.is_some()).map(|(s, _)| *s).collect();
        if core {
            self.dirty(id).core = true;
            self.acks_moved(id, was);
        }
        if let Some(src) = self.source_of(conn) {
            self.connected.wrote(&src, true);
        }
        // a record kept nowhere is new with its connection: no member yet
        debug_assert!(kept || members.is_empty(), "a record kept nowhere taken with members");
        if kept {
            moved.push(Moved::Taken(conn, id, fresh));
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
            Msg::Head { sync_id, after, .. } => head_answer(ctx, conn, id, &sync_id, after.as_ref()),
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
            (Req::Head { s, mut got }, Msg::HeadReply { steps, .. }) => {
                let full = steps.len() == osis_proto::limits::MAX_HEAD_STEPS;
                got.extend(steps);
                // a full page: asked again from its last step
                if full && let Some(last) = got.last().map(osis_blob::Step::id) {
                    let id = ctx.wire.request(conn, Msg::Head { id: 0, sync_id: s, after: Some(last) });
                    if let Some(c) = self.conns.get_mut(&conn) {
                        c.reqs.insert(id, Req::Head { s, got });
                    }
                    return;
                }
                // taken only as a verified path from genesis: the answerer's word on its own head
                if osis_blob::verify_path(&s, &got).is_ok() {
                    ctx.holds.hear_path(&s, got);
                }
            }
            (Req::Head { .. }, _) => {}
        }
    }

    /// Asks the peer on `conn` Head of S (spec/sync-ids.md §6 Head), once per change of S there.
    fn ask_head(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId) {
        let at = self.changed.at.get(&s).map_or(0, |(p, _, _)| *p);
        let Some(c) = self.conns.get_mut(&conn) else { return };
        if c.asked_head.get(&s).is_some_and(|x| *x >= at) {
            return;
        }
        c.asked_head.insert(s, at);
        let id = ctx.wire.request(conn, Msg::Head { id: 0, sync_id: s, after: None });
        if let Some(c) = self.conns.get_mut(&conn) {
            c.reqs.insert(id, Req::Head { s, got: Vec::new() });
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
    fn index_all(&mut self, conn: ConnId) {
        match self.conns.get_mut(&conn) {
            Some(c) if !c.indexed => c.indexed = true,
            _ => return,
        }
        let all: Vec<SyncId> = self.changed.at.keys().copied().collect();
        for s in all {
            self.index_shown(conn, &s);
        }
    }

    /// Indexes S's shown credentials on `conn` (spec/sync-opens.md §5 Opening: a Hit names no
    /// sync ID; the receiver finds it among what its filter shows). Nothing is removed: a stored
    /// filter keeps old entries, and a Hit on one is judged by what is admissible now.
    fn index_shown(&mut self, conn: ConnId, s: &SyncId) {
        let Some(adm) = self.admissible(s) else { return };
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
        let adds = if whole { None } else { Some(self.shown_beacons(&ids, &rr)).filter(|b| b.len() as u64 <= room) };
        let whole = adds.is_none();
        let beacons = match adds {
            Some(b) => b,
            None => {
                let all: Vec<SyncId> = self.changed.at.keys().copied().collect();
                self.shown_beacons(&all, &rr)
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

    /// The beacons of the credentials `ids` show (spec/sync-opens.md §5 Beacon).
    fn shown_beacons(&mut self, ids: &[SyncId], r: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut beacons = Vec::new();
        for s in ids {
            if let Some(adm) = self.admissible(s) {
                for sh in &adm.shows {
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
        // its entries new against the filter held: a credential tested and refused before may be
        // shown now (a claim written since), so the sync IDs they name are tested again
        let fresh: Vec<u64> = values.iter().filter(|v| r.peer.as_ref().is_none_or(|o| o.f != p.f || !o.values.contains(*v))).collect();
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
        if let Some(rid) = c.rec {
            let d = self.dirty(rid);
            d.core = true;
            match &mut d.filter {
                Some((_, gens)) if !whole => gens.push((p.generation, row)),
                f => *f = Some((whole, vec![(p.generation, row)])),
            }
        }
        self.retest_named(conn, p.f, &fresh);
    }

    /// The sync IDs a filter arrival's new entries `fresh` (`f` bits wide) may show a tested
    /// credential of are tested again (spec/sync-opens.md §5 Testing), from the tested beacons
    /// (built here first: every S this side syncs, one beacon per tested credential).
    fn retest_named(&mut self, conn: ConnId, f: u8, fresh: &[u64]) {
        if fresh.is_empty() {
            return;
        }
        let Some(rr) = self.record_on(conn).map(|r| r.r) else { return };
        if self.conns.get(&conn).is_some_and(|c| c.tested_ix.is_none()) {
            let mut ix = TestedBeacons::default();
            let all: Vec<SyncId> = self.changed.at.keys().copied().collect();
            for s in all {
                let Some(adm) = self.admissible(&s) else { continue };
                self.work.beacons += adm.tests.len() as u64;
                ix.set(s, adm.tests.iter().map(|t| beacon_of(&t.matched(), &s, &rr)).collect());
            }
            if let Some(c) = self.conns.get_mut(&conn) {
                c.tested_ix = Some(ix);
            }
        }
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let Some(ix) = c.tested_ix.as_ref() else { return };
        let named: BTreeSet<SyncId> = fresh.iter().flat_map(|v| ix.named(*v, f)).collect();
        c.retest.extend(named);
    }

    // ---- testing and Offer (§5) ----

    /// What this node may open S by now (spec/sync-opens.md §4 Admissible): S synced here, and
    /// its credentials.
    fn admissible(&self, s: &SyncId) -> Option<Adm> {
        let creds = self.changed.at.get(s).map(|(_, _, c)| c.clone())?;
        let own = crate::types::class_of(creds.holding?);
        Some(Adm { own, shows: creds.shows.clone(), tests: creds.tests.clone(), step: creds.step.clone(), head: creds.head })
    }

    /// Tests the pending sync IDs against the peer's latest filter and sends one Offer
    /// (spec/sync-opens.md §5 Testing): at most one Offer unanswered.
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
        // those a filter arrival named (`retest_named`) not pending already
        pending.extend(c.retest.iter().filter(|s| self.changed.pos(s) <= from).copied());
        let end = self.changed.end;
        let mut tested: Vec<(SyncId, Vec<[u8; 32]>)> = Vec::new();
        let mut sent = Vec::new();
        let mut items = Vec::new();
        let mut cut = false;
        let mut heads = Vec::new();
        for s in pending {
            if self.member(conn, &s).is_some() {
                continue;
            }
            let Some(adm) = self.admissible(&s) else { continue };
            self.work.tested += 1;
            let before = items.len();
            tested.push((s, Vec::new()));
            for t in &adm.tests {
                let m = t.matched();
                let b = beacon_of(&m, &s, &rr);
                self.work.beacons += 1;
                if let Some((_, bs)) = tested.last_mut() {
                    bs.push(b);
                }
                // one it would not open by is not sent (spec/sync-opens.md §6)
                if self.served_past(ctx, conn, &s, &adm, &t.credential(), None) {
                    continue;
                }
                if !pf.values.contains(beacon_value(&b, pf.f)) {
                    continue;
                }
                let h = bind.hit(&m, &s, &b);
                let class = adm.own;
                items.push(match t {
                    Tested::ClaimKey { key, .. } => OfferItem::Hit { hit: h, sig: Some(bind.sign(key, &s)), class },
                    Tested::Proof(..) => OfferItem::Hit { hit: h, sig: None, class },
                });
                sent.push(Sent::Hit { s, cred: Box::new(t.clone()), beacon: b, own: adm.own });
            }
            // following S with no path, or by claims the peer's filter does not show: its head
            // is asked (spec/sync-ids.md §6 Head)
            if items.len() == before && adm.own != SourceClass::Store && (adm.head.is_none() || adm.tests.iter().any(|t| matches!(t, Tested::ClaimKey { .. }))) {
                heads.push(s);
            }
            if items.len() >= MAX_OFFER_ITEMS {
                cut = true;
                break;
            }
        }
        for s in heads {
            self.ask_head(ctx, conn, s);
        }
        let Some(c) = self.conns.get_mut(&conn) else { return };
        for (s, bs) in tested {
            c.retest.remove(&s);
            if let Some(ix) = c.tested_ix.as_mut() {
                ix.set(s, bs);
            }
        }
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

    /// The peer's answers to this side's Offer (spec/sync-opens.md §5 Opening): the tester opens S
    /// on the answer's valid tag or signature, its credential still admissible; then Lost each S
    /// the peer accepted and it did not open.
    fn answered(&mut self, ctx: &mut Ctx, conn: ConnId, items: Vec<SharedItem>, moved: &mut Vec<Moved>) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let Some(sent) = c.offer.take() else { return };
        let bind = c.bind;
        let mut accepted = BTreeSet::new();
        let mut crossed = Vec::new();
        let mut refused = Vec::new();
        for (i, x) in sent.into_iter().enumerate() {
            let a = items.get(i).cloned().unwrap_or(SharedItem::code(Code::DECLINED));
            let Sent::Hit { s, cred, beacon, own } = x;
            if a.code != Code::OK {
                // a credential the peer's filter showed once and that opens nothing there now (a
                // claim no longer at its head, an older step's proof served to its end): its head is
                // asked (spec/sync-ids.md §6 Head), as for claims its filter does not show
                if own != SourceClass::Store {
                    refused.push(s);
                }
                continue;
            }
            let m = cred.matched();
            // The tag: computable only with the credential and S, by the replier's side.
            // Without it the peer showed no knowledge of S: no Lost names S to it (a false
            // positive of the filter answered OK would learn S).
            if a.tag != Some(bind.peer_tag(&m, &s, &beacon)) {
                continue;
            }
            accepted.insert(s);
            if self.member(conn, &s).is_some() {
                crossed.extend(self.crossed(conn, s, own, a.class));
                continue;
            }
            let Some(adm) = self.admissible(&s) else { continue };
            // Its credential still admissible, its class still the one it declared.
            if !adm.tests.iter().any(|t| t.matched() == m) || adm.own != own {
                continue;
            }
            if !replier_proved(&bind, &s, &cred, &a) {
                continue;
            }
            let by = cred.credential();
            if self.served_past(ctx, conn, &s, &adm, &by, Some(a.class)) {
                continue;
            }
            if self.open(conn, s, Member { class: a.class, own, by, until: None }, beacon, moved) {
                self.rejudge(ctx, conn, s, moved);
            }
        }
        // Once all answers are read: Lost each S the peer accepted and this side did not open.
        let lost: Vec<SyncId> = accepted.iter().copied().filter(|s| self.member(conn, s).is_none()).collect();
        if !lost.is_empty() {
            let items = lost.iter().map(|s| (*s, self.reported_at(conn, s).map(|(_, c)| c.clone()))).collect();
            self.send_lost(ctx, conn, items);
        }
        for s in crossed {
            self.close_member(ctx, conn, s, Close::Class, moved);
        }
        // a refusal beside a Hit of the same Offer the peer accepted (a holder's two claims, read
        // and sync) says nothing of its head
        refused.retain(|s| !accepted.contains(s));
        refused.dedup();
        for s in refused {
            self.ask_head(ctx, conn, s);
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

    /// The peer's Offer (spec/sync-opens.md §5 Opening): this side opens S on a Hit that is one
    /// of its shown credentials its filter to this peer shows, carrying its proof; the session
    /// learns of the open before the answer goes.
    fn offered(&mut self, ctx: &mut Ctx, conn: ConnId, id: Id, items: Vec<OfferItem>, moved: &mut Vec<Moved>) {
        if items.iter().any(|i| matches!(i, OfferItem::Hit { .. })) {
            self.index_all(conn);
        }
        let mut answers = Vec::with_capacity(items.len());
        for item in items {
            let a = match item {
                OfferItem::Hit { hit, sig, class } => self.accept_hit(ctx, conn, &hit, sig.as_ref(), class, moved),
                OfferItem::Deposit(d) => {
                    let src = self.record(conn).map_or(crate::store::Source::Conn(conn), crate::store::Source::Record);
                    SharedItem::code(ctx.holds.deposit(src, &d))
                }
            };
            answers.push(a);
        }
        ctx.wire.answer(conn, id, Msg::Shared { id, items: answers });
    }

    /// Whether `by`, an older step's sync proof, opens nothing on `conn` with this side's class and
    /// the peer's (`peer`; none: any): an ended member open with those classes reached its `until`
    /// there already, and `by`'s is no later (spec/sync-opens.md §6).
    fn served_past(&self, ctx: &mut Ctx, conn: ConnId, s: &SyncId, adm: &Adm, by: &Credential, peer: Option<SourceClass>) -> bool {
        if adm.of_head(by) {
            return false;
        }
        let Some(c) = self.conns.get(&conn) else { return false };
        let reached = c.served.range((*s, adm.own, SourceClass::Reader)..=(*s, adm.own, SourceClass::Stub)).filter(|((_, _, p), _)| peer.is_none_or(|x| x == *p)).map(|(_, u)| *u).max();
        reached.is_some_and(|u| u >= ctx.holds.until(s, by))
    }

    /// A Hit (spec/sync-opens.md §5 Opening); `class`: the class the peer declared in it.
    fn accept_hit(&mut self, ctx: &mut Ctx, conn: ConnId, hit: &[u8; 32], sig: Option<&osis_crypto::Signature>, class: SourceClass, moved: &mut Vec<Moved>) -> SharedItem {
        let refuse = SharedItem::code(Code::DECLINED);
        let Some(c) = self.conns.get(&conn) else { return refuse };
        // a filter's false positive (spec/sync-opens.md §5 Testing): a Hit on nothing shown
        let Some((s, shown, beacon)) = c.shown.get(hit).cloned() else {
            osis_base::costs::count("opens: hits on nothing shown", 1);
            return refuse;
        };
        let bind = c.bind;
        // Judged on what this side holds now: a credential no longer shown proves nothing.
        let Some(adm) = self.admissible(&s) else { return refuse };
        if !adm.shows.contains(&shown) {
            return refuse;
        }
        // A deposit key's Hit carries no proof and opens nothing.
        let Some(by) = shown.credential() else { return refuse };
        // A sync proof's Hit is keyed by the proof; a claim's carries an open signature by it,
        // and its answer one by this side's head's sync key (spec/sync-opens.md §5 Proof).
        let answer_sig = match &shown {
            Shown::Proof(..) => None,
            Shown::ClaimKey(k) => {
                let Some(step) = adm.step.as_ref().filter(|_| sig.is_some_and(|g| bind.peer_signed(k, &s, g))) else { return refuse };
                Some(bind.sign(step, &s))
            }
            Shown::Deposit(_) => return refuse,
        };
        if self.served_past(ctx, conn, &s, &adm, &by, Some(class)) {
            return refuse;
        }
        let m = Member { class, own: adm.own, by, until: None };
        if self.open(conn, s, m, beacon, moved) {
            self.rejudge(ctx, conn, s, moved);
        }
        SharedItem { code: Code::OK, tag: Some(bind.tag(shown.matched(), &s, &beacon)), sig: answer_sig, class: adm.own }
    }

    // ---- members, ending and Lost (§6) ----

    /// Opens S on `conn` unless it is a member there already. Whether it opened.
    fn open(&mut self, conn: ConnId, s: SyncId, m: Member, beacon: [u8; 32], moved: &mut Vec<Moved>) -> bool {
        let Some(c) = self.conns.get(&conn) else { return false };
        let Some(rid) = c.rec else { return false };
        if self.records.get(&rid).is_none_or(|r| r.members.contains_key(&s)) {
            return false;
        }
        let Some(r) = self.records.get_mut(&rid) else { return false };
        r.members.insert(s, m);
        r.basis.insert(s, beacon);
        if let Some(c) = self.conns.get_mut(&conn) {
            c.reported.opened(s);
        }
        let rejoin = r.stopped.remove(&s).unwrap_or(Rejoin::From(None));
        self.dirty(rid).members.insert(s);
        self.member_moved(conn, &s, true);
        let src = self.source_of(conn);
        self.hold(s, rid, src);
        self.peers.wrote(&s, true);
        moved.push(Moved::Joined(conn, s, rejoin));
        true
    }

    /// Re-judges member S of `conn` (`judge`).
    fn rejudge(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, moved: &mut Vec<Moved>) {
        if let Some(rid) = self.conns.get(&conn).and_then(|c| c.rec) {
            self.judge(ctx, rid, s, moved);
        }
    }

    /// Judges member S of record `rid` again (spec/sync-opens.md §6), whether or not a connection
    /// holds the record: one whose credential is admissible and of the head stays; one whose
    /// credential is admissible but not of the head is ended (`until`, judged now), and stays
    /// ended until it closes; any other closes at once (with a Lost where a connection holds the
    /// record). One that stays, not ended, closes keeping where it stopped once this side's class
    /// is not the one it declared opening S.
    fn judge(&mut self, ctx: &mut Ctx, rid: RecordId, s: SyncId, moved: &mut Vec<Moved>) {
        let Some(r) = self.records.get(&rid) else { return };
        let Some(m) = r.members.get(&s).cloned() else { return };
        self.work.rejudged += 1;
        osis_base::costs::count("opens: members judged", 1);
        let conn = self.conn_on(rid);
        let (rr, basis) = (r.r, r.basis.get(&s).copied());
        let Some(adm) = self.admissible(&s) else {
            // S left the sync set: closes at once.
            self.end_member(ctx, rid, conn, s, Close::Left, moved);
            return;
        };
        // a claim opened by its open signature stays admissible here once its block is bound to
        // an older step (the head moved): ended, as an older step's proof is (§6)
        let claimed = matches!(m.by, Credential::ClaimKey(_)) && adm.head.is_some();
        let admissible = claimed || basis.is_some_and(|b| adm.shows.iter().any(|x| beacon_of(x.matched(), &s, &rr) == b) || adm.tests.iter().any(|t| beacon_of(&t.matched(), &s, &rr) == b));
        if !admissible {
            self.end_member(ctx, rid, conn, s, Close::AtOnce, moved);
        } else if !adm.of_head(&m.by) {
            if m.until.is_none() {
                let until = ctx.holds.until(&s, &m.by);
                self.set_until(rid, &s, until, moved);
            }
            if let Some(c) = conn {
                self.close_if_reached(ctx, c, s, moved);
            }
        } else if m.own != adm.own && m.until.is_none() {
            self.end_member(ctx, rid, conn, s, Close::Class, moved);
        }
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
            k.unowed.remove(s);
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
        // a member this side held as a stub was served role entries alone: where its stream stood
        // says nothing of the rest, so once this side holds S otherwise, whatever closes it keeps
        // nothing (spec/sync-opens.md §6)
        let moved_on = m.own == SourceClass::Stub && self.admissible(&s).is_none_or(|a| a.own != SourceClass::Stub);
        let why = if moved_on && matches!(why, Close::Class | Close::Until) { Close::AtOnce } else { why };
        if let (Close::Until, Some(u), Some(c)) = (why, m.until, self.conns.get_mut(&conn)) {
            let at = c.served.entry((s, m.own, m.class)).or_insert(u);
            *at = (*at).max(u);
        }
        let cursor = match why {
            Close::Left => None,
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
        let at = LeftAt { src, reported: c.reported.get(&s).map(|(p, _)| *p), until: m.until, how: if stop.is_some() { Leaving::Kept } else { Leaving::Forgot } };
        c.reported.forget(&s);
        self.reports.wrote(&conn, true);
        c.ending.remove(&s);
        c.unowed.remove(&s);
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

/// The tester's proof of the replier (spec/sync-opens.md §5 Proof an answer carries): a sync
/// proof's tag is its own proof; a claim's answer carries an open signature by the sync key of
/// the step the claim is at.
fn replier_proved(bind: &Bind, s: &SyncId, cred: &Tested, a: &SharedItem) -> bool {
    match cred {
        Tested::Proof(..) => true,
        Tested::ClaimKey { sync, .. } => a.sig.as_ref().is_some_and(|sig| bind.peer_signed(sync, s, sig)),
    }
}

/// Answers a Head (spec/sync-ids.md §6 Head): the steps of this node's path of S after `after`
/// (none: from genesis) through its head, at most `MAX_HEAD_STEPS`, whatever the connection
/// proved; 13 for an S it does not hold or a step not on its path.
fn head_answer(ctx: &mut Ctx, conn: ConnId, id: Id, s: &SyncId, after: Option<&osis_blob::StepId>) {
    let path = ctx.store.synced(s).and_then(|_| ctx.store.path(s).ok().flatten());
    let start = path.as_ref().and_then(|p| match after {
        None => Some(0),
        Some(a) => p.steps.iter().position(|st| st.id() == *a).map(|i| i + 1),
    });
    let reply = match (path, start) {
        (Some(p), Some(i)) if !p.steps.is_empty() => Msg::HeadReply { id, steps: p.steps.iter().skip(i).take(osis_proto::limits::MAX_HEAD_STEPS).cloned().collect() },
        _ => Msg::Error { id, code: Code::UNKNOWN_SYNC_ID },
    };
    ctx.wire.answer(conn, id, reply);
}

/// Answers a filter page breaking the format and closes the connection (spec/wire.md §11.2).
fn break_format(ctx: &mut Ctx, conn: ConnId, id: Id, why: &'static str) {
    ctx.wire.answer(conn, id, Msg::Error { id, code: Code::MALFORMED });
    ctx.wire.close(conn, why);
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
