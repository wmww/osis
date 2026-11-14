//! Streams and flow control (spec/sync-streams.md §3-§6, spec/wire.md §11.2 Pull, PullReply,
//! Stream, Applied, Fetch; spec/sync-judgement.md §3 `known`).
//!
//! **Principle:** every node pulls each member of a connection's shared set from its peer by one
//! stream over that peer's node log; a push only continues a pull, and a gap is repaired by
//! reading again, never by trusting order. A position is stored only once what it covers is
//! applied, so a lost or replayed message costs a re-read, never a wrong view (model:
//! core/test/tla/net/NetStream.tla; each `SN_*` rule names its function here).
//!
//! Both sides of a connection serve (`serve`: answering Pulls and Fetches, pushing under
//! `follow`) and pull (`pull`: Pulls, joins, applying in order, fetching bodies one source at a
//! time). What each source showed is `known` (stamped, so `read`, `unread` and `status` follow it
//! by key). Members come and go by `Moved` from opens; the reported positions a requester gives
//! this side as server go back to opens as `Reported`.
//!
//! The core runs over `Ctx` (the store, the engine's part as `Ground`, the connections as `Wire`,
//! opens' shared set as `Shared`), so its rules run against scripted peers; the product's entry
//! points build it from `Cx`, `Sessions` and `Opens`.
//!
//! State: per connection, as server, the follow cursor and `seq`, the blobs that crossed it, the
//! ephemeral listing, the joins awaiting their merge's report; as requester, the Pull out, the
//! received cursors, `seq` applied, gaps, messages in hand awaiting bodies, the fetch queue and
//! the fetches out; per source (a peer's record, or the connection) the stored cursor, the members
//! at the stream, joins in pages and where members that left stopped; `known` per source; the
//! blobs asked from some source.
//!
//! Not built: durability (positions and `known` live in memory, keyed by record: opens keeps its
//! records in memory, so a restart is a first contact); relay-only entries (the engine's relay
//! path); the engine's linked blobs (`wants`: pages and header lists before apply); bundles
//! (`import`); `Rank::Never` from the engine (a keyset without history: the facade has no call
//! for it yet).

mod known;
mod pull;
mod serve;

pub use known::{Known, Refusal};

use crate::opens::{Member, Moved, Opens, Reported};
use crate::session::{Incoming, Sessions, To};
use crate::store::{Source, Store};
use crate::types::{ConnId, Cx, Entry, Error, Position, RecordId, Result};
use crate::unread::Sources;
use osis_base::memo::Stamped;
use osis_base::{BlobId, SyncId, WallMs};
use osis_engine::Engine;
use osis_engine::sync::Opened;
use osis_proto::{Id, Msg, Wrap};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Bytes a requester lets a server inline per body while a member has no other source
/// (spec/sync-streams.md §4 Bodies; local policy). At 0 every body costs a Fetch round trip; at
/// infinity whole blobs come inline, and each again from every source once a second one joins.
pub const INLINE_LIMIT: u64 = 16 * 1024;

/// Messages a requester keeps in hand per connection while their bodies arrive
/// (spec/sync-streams.md §4 Flow control: its local bound). At 0 every push is dropped and read
/// again; at infinity a slow body holds unbounded announcements in memory.
pub const PENDING_CAP: usize = 64;

/// Fetches a requester keeps out per connection (spec/sync-streams.md §5: how many are asked at
/// a time is local policy). At 0 nothing is fetched; at infinity the window alone bounds them.
pub const FETCHES_OUT: usize = 2;

/// The wait before a refused Pull is sent again, and before a join refused while S stays a
/// member is joined again (`resync_ms`, spec/sync-streams.md §4 Joining; local policy). At 0 a
/// peer refusing loops at the speed of the link; at infinity a refusal stops the stream for good.
pub const RESYNC_MS: u64 = 30_000;

/// How long a blob counts as asked at one source before another that has it is asked too
/// (spec/sync-streams.md §4 Bodies: the Stall rule's wait).
pub const ASKED_MS: u64 = crate::session::STALL_TIMEOUT_MS;

/// What opening a pulled body did at a node reading S.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opening {
    Taken,
    NotOpen,
    /// It opened and is bad, or its bytes are not its ID's: asked again elsewhere.
    Bad,
}

/// A body's place in the fill order (spec/sync-streams.md §4 Fill order, §5 First sync).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rank {
    /// It opens, at this fetch order (order 0 first).
    Order(u64),
    /// It does not open (yet): ranked again as secrets arrive.
    Unopened,
    /// It can never open here (a keyset without history): not fetched.
    Never,
}

/// The engine's part of a pull at a node reading S.
pub trait Ground {
    /// Opens the entry's wrap and takes what the blob holds (`Engine::open_entry`).
    fn open(&mut self, s: &SyncId, e: &Entry, bytes: &[u8]) -> Result<Opening>;
    /// The body's place in the fill order.
    fn rank(&mut self, s: &SyncId, b: &BlobId, wrap: &Wrap) -> Rank;
}

/// How streams reaches a connection. The product's is `Sessions`.
pub trait Wire {
    /// Sends a request (its id chosen there); none when the connection is gone.
    fn request(&mut self, c: ConnId, m: Msg) -> Option<Id>;
    fn answer(&mut self, c: ConnId, id: Id, m: Msg);
    /// A push under spec/sync-streams.md §2: `false` when it does not fit now.
    fn push(&mut self, c: ConnId, m: Msg) -> bool;
}

/// What streams reads of opens: the shared set, agreement, the record, reported positions.
pub trait Shared {
    fn members(&self, c: ConnId) -> &BTreeMap<SyncId, Member>;
    /// Whether this side may Pull (spec/sync-opens.md §3 Agreement).
    fn agreed(&self, c: ConnId) -> bool;
    fn record(&self, c: ConnId) -> Option<RecordId>;
    /// Member S's reported position (spec/sync-opens.md §6), as opens folded streams' reports.
    fn reported(&self, c: ConnId, s: &SyncId) -> Option<Position>;
}

/// What one step gives streams.
pub struct Ctx<'a> {
    pub store: &'a mut Store,
    pub ground: &'a mut dyn Ground,
    pub wire: &'a mut dyn Wire,
    pub shared: &'a dyn Shared,
    pub now: WallMs,
    /// Reported positions for opens (`Opens::reported`).
    pub reported: &'a mut Vec<Reported>,
}

/// Work done, counted (tests: scaling by counting work, notes/coordination.md).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Work {
    /// Log events a server read.
    pub served: u64,
    /// Events a requester applied.
    pub applied: u64,
    /// Members a step looked at.
    pub members: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Streams {
    serve: BTreeMap<ConnId, serve::Serve>,
    pull: BTreeMap<ConnId, pull::Pulling>,
    /// Where this node stands in each source's log.
    places: BTreeMap<Source, pull::Place>,
    known: Known,
    /// Blobs asked from some source, and when (one source at a time).
    asked: HashMap<BlobId, (ConnId, WallMs)>,
    /// The connections each sync ID is a member on (its sources).
    holders: BTreeMap<SyncId, BTreeSet<ConnId>>,
    /// Kept unread: entries refused for room per S, with S's bytes when the last was refused.
    room: BTreeMap<SyncId, (u64, BTreeSet<BlobId>)>,
    /// The connections whose stream is caught up both ways (this side applied the peer's to its
    /// end, the peer applied every message served to it), with when the Pull the last reply
    /// answered was sent: status follows it per connection (`caught_up`).
    caught: Stamped<ConnId, WallMs>,
    work: Work,
}

impl Streams {
    // ---- the product's entry points ----

    /// A member joined (its join is due) or left (its stream stops where it stands) a
    /// connection's shared set; the connection may be gone already.
    pub fn moved(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, m: Moved, reported: &mut Vec<Reported>) {
        product(cx, sessions, opens, reported, |ctx| self.member_moved(ctx, m));
    }

    /// Pull, PullReply, Stream, Applied, Fetch, FetchReply.
    pub fn on_message(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, conn: ConnId, m: Incoming, reported: &mut Vec<Reported>) {
        product(cx, sessions, opens, reported, |ctx| self.message(ctx, conn, m));
    }

    /// Whether anything acted.
    pub fn settle(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, reported: &mut Vec<Reported>) -> Result<bool> {
        let mut out = Ok(false);
        product(cx, sessions, opens, reported, |ctx| out = self.tick(ctx));
        out
    }

    /// A complete pass wants a fresh Pull on `conn` (`again`).
    pub fn pull_again(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, conn: ConnId, reported: &mut Vec<Reported>) {
        product(cx, sessions, opens, reported, |ctx| self.again(ctx, conn));
    }

    /// A source with no cursor: a bundle (spec/sync-streams.md §6).
    pub fn import(&mut self, cx: &mut Cx, bundle: &mut dyn std::io::Read) -> Result<()> {
        let _ = (cx, bundle);
        Err(Error::NotBuilt("streams::import"))
    }

    pub fn next_wake(&self) -> Option<WallMs> {
        let asked = self.asked.values().map(|(_, at)| WallMs(at.0.saturating_add(ASKED_MS))).min();
        self.pull.values().filter_map(pull::Pulling::wake).chain(asked).min()
    }

    // ---- reads (stamped: memo-safe) ----

    /// The source a connection is: its record, else itself.
    pub fn source(&self, shared: &dyn Shared, conn: ConnId) -> Source {
        shared.record(conn).map_or(Source::Conn(conn), Source::Record)
    }

    /// What sources showed of S (spec/sync-judgement.md §3 `known`).
    pub fn known(&self) -> &Known {
        &self.known
    }

    /// Whether `src` showed `b` present under S: its durable entries by the record (or the
    /// connection), its ephemeral ones by the connection up now.
    pub fn knows(&self, src: Source, conn: Option<ConnId>, s: &SyncId, b: &BlobId) -> bool {
        self.known.knows(src, s, b) || conn.is_some_and(|c| Source::Conn(c) != src && self.known.knows(Source::Conn(c), s, b))
    }

    /// Whether the source on `conn` is caught up for S (spec/sync-status.md §1): this side's
    /// stream of S there at the stream, its last reply the end, no gap, nothing in hand and no
    /// Pull out (spec/sync-streams.md §4; `SN_rearm`), and the peer reported every message
    /// served to it applied.
    pub fn caught_up(&self, conn: ConnId, s: &SyncId) -> bool {
        self.caught_since(conn, s).is_some()
    }

    /// When the Pull was sent whose reply S's caught up on `conn` rests on: none while not caught
    /// up. Stamped per connection and per (source, S).
    pub fn caught_since(&self, conn: ConnId, s: &SyncId) -> Option<WallMs> {
        let t = *self.caught.get(&conn)?;
        let p = self.pull.get(&conn)?;
        self.places.get(&p.src).is_some_and(|pl| pl.at_stream.contains(s) && !pl.joining.contains_key(s)).then_some(t)
    }

    /// Tests only: what a connection's pulling holds for its peer (messages in hand, queued and
    /// failed bodies, refusals to tell).
    #[doc(hidden)]
    pub fn holding(&self, conn: ConnId) -> usize {
        self.pull.get(&conn).map_or(0, pull::Pulling::holding)
    }

    /// Tests only: the work counted so far.
    #[doc(hidden)]
    pub fn work(&self) -> Work {
        self.work
    }

    // ---- the core, over `Ctx` ----

    /// Takes one message for streams.
    pub fn message(&mut self, ctx: &mut Ctx, conn: ConnId, m: Incoming) {
        match m {
            Incoming::Request(id, Msg::Pull(p)) => self.on_pull(ctx, conn, id, *p),
            Incoming::Request(id, Msg::Fetch { sync_id, max_reply, ids, .. }) => self.on_fetch(ctx, conn, id, sync_id, max_reply, ids),
            Incoming::Push(Msg::Applied { cursor }) => self.on_applied(ctx, conn, cursor.into_bytes()),
            Incoming::Push(Msg::Stream(st)) => self.on_stream(ctx, conn, *st),
            Incoming::Reply(To::Streams, id, m) => self.on_reply(ctx, conn, id, m),
            _ => {}
        }
        self.run(ctx, conn);
        self.track(ctx, conn);
    }

    /// A member moved.
    pub fn member_moved(&mut self, ctx: &mut Ctx, m: Moved) {
        let (Moved::Joined(conn, ..) | Moved::Left(conn, _) | Moved::Until(conn, _)) = &m;
        let conn = *conn;
        match m {
            Moved::Joined(conn, s, rejoin) => {
                self.holders.entry(s).or_default().insert(conn);
                self.served_joined(ctx, conn, s);
                self.joined(ctx, conn, s, rejoin);
                // a member gaining another source: its other streams ask inline 0 again
                for c in self.holders.get(&s).into_iter().flatten() {
                    if let Some(p) = self.pull.get_mut(c) {
                        p.inline_check = true;
                    }
                }
                self.run(ctx, conn);
            }
            Moved::Left(conn, s) => {
                if let Some(set) = self.holders.get_mut(&s) {
                    set.remove(&conn);
                    if set.is_empty() {
                        self.holders.remove(&s);
                    }
                }
                self.served_left(conn, &s);
                self.left(ctx, conn, s);
            }
            Moved::Until(conn, s) => self.served_ending(ctx, conn, s),
        }
        self.track(ctx, conn);
    }

    /// Wants a Pull from the stream's cursor on `conn` though nothing else is due, sent once any
    /// under way ends (a complete pass, spec/sync-status.md §1; spec/permissions.md §3).
    pub fn again(&mut self, ctx: &mut Ctx, conn: ConnId) {
        let Some(p) = self.pull.get_mut(&conn) else { return };
        p.again = true;
        self.run(ctx, conn);
        self.track(ctx, conn);
    }

    /// Keeps `caught` for `conn` as its pulling and serving now stand.
    fn track(&mut self, ctx: &Ctx, conn: ConnId) {
        let end = ctx.store.log_bounds().map(|(e, _)| e);
        let mark = ctx.store.memory_mark();
        let now = self.pull.get(&conn).filter(|p| p.caught_up() && end.as_ref().is_ok_and(|e| self.served_applied(conn, *e, mark))).map(|p| p.answered_at);
        if self.caught.get(&conn).copied() != now {
            match now {
                Some(t) => self.caught.insert(conn, t),
                None => self.caught.remove(&conn),
            };
        }
    }

    /// A connection ended (before opens reports its members left): what lasted it alone goes,
    /// its members' places stay with the record.
    pub fn closed(&mut self, conn: ConnId) {
        self.serve.remove(&conn);
        if let Some(p) = self.pull.remove(&conn)
            && p.src == Source::Conn(conn)
        {
            self.places.remove(&p.src);
        }
        self.asked.retain(|_, (c, _)| *c != conn);
        self.known.forget_source(Source::Conn(conn));
        for set in self.holders.values_mut() {
            set.remove(&conn);
        }
        self.holders.retain(|_, v| !v.is_empty());
        self.caught.remove(&conn);
    }

    /// Settles every connection: pushes under `follow`, Pulls and Fetches due, room regained.
    pub fn tick(&mut self, ctx: &mut Ctx) -> Result<bool> {
        let mut acted = self.room_grew(ctx)?;
        let conns: BTreeSet<ConnId> = self.serve.keys().chain(self.pull.keys()).copied().collect();
        for c in conns {
            acted |= self.push(ctx, c)?;
            self.run(ctx, c);
            self.track(ctx, c);
        }
        Ok(acted)
    }
}

impl Sources for Streams {
    /// spec/sync-set.md §3: an own entry counts held at a source once a source's stream showed it.
    fn present(&self, s: &SyncId, b: &BlobId) -> bool {
        self.known.present(s, b)
    }
}

/// Runs `f` over the product's `Ctx`.
fn product(cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, reported: &mut Vec<Reported>, f: impl FnOnce(&mut Ctx)) {
    let now = cx.now;
    let mut ground = EngineGround { engine: cx.engine };
    let mut ctx = Ctx { store: cx.store, ground: &mut ground, wire: sessions, shared: opens, now, reported };
    f(&mut ctx);
}

/// The product's `Ground`: the engine's facade.
struct EngineGround<'a> {
    engine: &'a mut Engine,
}

impl Ground for EngineGround<'_> {
    fn open(&mut self, s: &SyncId, e: &Entry, bytes: &[u8]) -> Result<Opening> {
        match self.engine.open_entry(s, &e.blob, &e.wrap, bytes) {
            Ok(Opened::Commit(..) | Opened::Linked | Opened::Inbox(_)) => Ok(Opening::Taken),
            Ok(Opened::NotOpen) | Err(osis_engine::Error::NotBuilt(_)) => Ok(Opening::NotOpen),
            Ok(Opened::Bad) => Ok(Opening::Bad),
            Err(e) => Err(e.into()),
        }
    }

    fn rank(&mut self, s: &SyncId, b: &BlobId, wrap: &Wrap) -> Rank {
        let Ok(Some(c)) = self.engine.read_credentials(s) else { return Rank::Unopened };
        match osis_label::wrap_order(c.read_secrets.iter().map(|(_, k)| k), b, wrap) {
            Some(o) => Rank::Order(o),
            None => Rank::Unopened,
        }
    }
}

impl Wire for Sessions {
    fn request(&mut self, c: ConnId, m: Msg) -> Option<Id> {
        Some(self.get_mut(c)?.request(To::Streams, m))
    }
    fn answer(&mut self, c: ConnId, id: Id, m: Msg) {
        if let Some(s) = self.get_mut(c) {
            s.answer(id, m);
        }
    }
    fn push(&mut self, c: ConnId, m: Msg) -> bool {
        self.get_mut(c).is_some_and(|s| s.push(m))
    }
}

impl Shared for Opens {
    fn members(&self, c: ConnId) -> &BTreeMap<SyncId, Member> {
        Opens::members(self, c)
    }
    fn agreed(&self, c: ConnId) -> bool {
        Opens::agreed(self, c)
    }
    fn record(&self, c: ConnId) -> Option<RecordId> {
        Opens::record(self, c)
    }
    fn reported(&self, c: ConnId, s: &SyncId) -> Option<Position> {
        self.reported_at(c, s).map(|(p, _)| *p)
    }
}
