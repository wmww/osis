//! Streams and flow control (spec/sync-streams.md §3-§5, spec/wire.md §11.2 Pull, PullReply,
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
//! by key). Members come and go by `Moved` from opens, a kept record's all at once as it is taken
//! or released (`Moved::Taken`, `Released`); the reported positions a requester gives
//! this side as server go back to opens as `Reported`.
//!
//! The core runs over `Ctx` (the store, the engine's part as `Ground`, the connections as `Wire`,
//! opens' shared set as `Shared`), so its rules run against scripted peers; the product's entry
//! points build it from `Cx`, `Sessions` and `Opens`.
//!
//! State: per connection, as server, the follow cursor and `seq`, the
//! ephemeral listing, the joins awaiting their merge's report, the messages asking a report not
//! yet reported (by cursor), the members joined and not read for the peer since; as requester, the Pull out, the
//! received cursors, `seq` applied, gaps, messages in hand awaiting bodies, the fetch queue and
//! the fetches out; per source (a peer's record, or the connection) the stored cursor, the members
//! at the stream, joins in pages and where members that left stopped; `known` per source (only
//! of entries held, tombstoned or taken here: what a source lists grows nothing else); the blobs asked
//! from some source.
//!
//! Durable (spec/sync-streams.md §3 Durability): a record source's place (the stream's cursor,
//! members at it, joins, where members that left stopped) and what it showed (`known`) are rows of
//! its record, written by the transaction that applies what they cover; a connection's are in
//! memory and go with it. A record's place is held in memory as long as opens holds the record
//! (`record_left`), so a reconnect reads and writes nothing of it per member.
//!
//! Relay-only entries: `relay` (notes/ephemeral.md, In osis-sync).
//!
//! Not built: the engine's linked blobs (`wants`: pages and header lists before apply);
//! `Rank::Never` from the engine (a keyset without history: the facade has no call for it yet).

mod known;
mod pull;
mod relay;
mod serve;

pub use known::{Known, Row as KnownRow};

use crate::opens::{Member, Moved, Opens, Reported};
use crate::session::{Incoming, Sessions, To};
use crate::store::{Source, Store};
use crate::types::{ConnId, Cx, Entry, Position, RecordId, Result};
use osis_base::memo::{Stamped, StampedSet};
use osis_base::{BlobId, Mono, SyncId, WallMs};
use osis_engine::Engine;
use osis_engine::sync::Opened;
use osis_proto::{Id, Msg, Wrap};
use std::collections::{BTreeMap, BTreeSet};

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

/// How long a blob counts as asked at one source before another that has it is asked too
/// (spec/sync-streams.md §4 Bodies: the Stall rule's wait).
pub const ASKED_MS: u64 = crate::session::STALL_TIMEOUT_MS;

/// What opening a pulled body did at a node reading S.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opening {
    /// It opened to what no entry keeps: a piece, a sealed fire.
    Taken,
    /// It opened to a commit held here, or a certificate blob: the entry is kept as it came, the
    /// reader's own store's copy of the body (spec/sync-judgement.md §3 Own store: a held blob goes on verbatim);
    /// `gave`: it brought something new, else it stays charged to its bringer unless stamped
    /// (spec/sync-ids.md §5 Peer budget: it gives nothing held).
    Held { gave: bool },
    NotOpen,
    /// It opened to a commit that pends here (spec/commits.md §4 Pending storage): the entry is
    /// kept as its carrier (`store::Follow`).
    Pends,
    /// It opened to an ephemeral commit now held here, costing this much held: the entry is
    /// kept, counted at that against S's memory cap (spec/sync-compaction.md §2 Caps), so the
    /// next one opened has the room left.
    Memory(u64),
    /// It opened and is bad, or its bytes are not its ID's: asked again elsewhere.
    Bad,
}

/// A body's place in the fill order (spec/sync-streams.md §4 Fill order, §5 First sync).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rank {
    /// It opens, at this fetch order (order 0 first).
    Order(u64),
    /// It does not open (yet): kept, and opened by the store as a read secret of S arrives
    /// (`store::Follow`, parked).
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
    /// Whether what blob `b` carries under S is known here with no entry needed: a record or
    /// list blob opened before (spec/permissions.md §4: it counts while held here or shown at a
    /// source), which a fetch would only open again. Not fetched; a source's showing of it is
    /// kept (`known`), so it counts while shown.
    fn counted(&mut self, s: &SyncId, b: &BlobId) -> bool {
        let _ = (s, b);
        false
    }
    /// Whether held blob `b` under S is a role entry by this node's own judgement
    /// (`Engine::role_entry`): what a node opening S shows a peer holding S's thing for keys.
    fn role_entry(&mut self, s: &SyncId, b: &BlobId) -> bool {
        let _ = (s, b);
        false
    }
    /// Whether held blob `b` under S is a notice of a removal of a holder a peer proving
    /// `proven` reaches (`Engine::notice_tells`): what a departed peer is shown.
    fn notice_tells(&mut self, s: &SyncId, b: &BlobId, proven: &std::collections::BTreeSet<osis_base::Tid>) -> bool {
        let _ = (s, b, proven);
        false
    }
    /// The write key of the head S's `sync.0` records here (`ReadCredentials::head`), which the
    /// store's served path follows.
    fn head_write(&mut self, s: &SyncId) -> Option<osis_crypto::VerifyingKey> {
        let _ = s;
        None
    }
    /// This node's own relay-only commits not sent yet, sealed per read sync ID
    /// (`Engine::take_relays`).
    fn own_relays(&mut self) -> Result<Vec<osis_engine::sync::Relay>> {
        Ok(Vec::new())
    }
    /// A relay-only blob received under read S, opened and delivered (`Engine::open_relay`).
    fn open_relay(&mut self, s: &SyncId, e: &Entry, bytes: &[u8]) -> Result<osis_engine::sync::RelayOpened> {
        let _ = (s, e, bytes);
        Ok(osis_engine::sync::RelayOpened::NotOpen)
    }
    /// A stamp of entry `b` of S under its wrap, where this node writes S's head.
    fn stamp(&mut self, s: &SyncId, b: &BlobId, wrap: &Wrap) -> Option<osis_proto::Stamp> {
        let _ = (s, b, wrap);
        None
    }
    /// An entry that opened to a pending commit was not kept (`store::release`).
    fn unkept(&mut self, store: &crate::store::Store, b: &BlobId) -> Result<()> {
        let _ = (store, b);
        Ok(())
    }
    /// An entry of commit `c`'s body under S this node holds or makes, whatever its own judgement
    /// of the body (spec/sync-judgement.md §3 Asked by ID): its store's entry holding the body,
    /// else a fresh encryption of the body under S; none where it holds no whole body.
    fn want(&mut self, store: &crate::store::Store, s: &SyncId, c: &osis_base::CommitId) -> Result<Option<Given>> {
        let _ = (store, s, c);
        Ok(None)
    }
}

/// An entry given outside any stream (a Want's answer): the blob, its wrap and stamp.
pub type Given = (Vec<u8>, Wrap, Option<osis_proto::Stamp>);

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
    /// The wall clock: a relay's expiry and `ts` are judged by it.
    pub now: WallMs,
    /// The monotonic clock streams' waits run on.
    pub mono: Mono,
    /// Reported positions for opens (`Opens::reported`).
    pub reported: &'a mut Vec<Reported>,
}

/// Work done, counted (tests: scaling by counting work, notes/principles.md).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Work {
    /// Log events a server read.
    pub served: u64,
    /// Events a requester applied.
    pub applied: u64,
    /// Members a step looked at.
    pub members: u64,
}

#[derive(Clone, Debug)]
pub struct Streams {
    serve: BTreeMap<ConnId, serve::Serve>,
    pull: BTreeMap<ConnId, pull::Pulling>,
    /// Where this node stands in each source's log.
    places: BTreeMap<Source, pull::Place>,
    /// Sync IDs the store shredded: dropped from every place kept in memory.
    shreds: osis_base::memo::Feed<SyncId>,
    /// Sync IDs kept unread whose dropped copy is fetched anew (`Store::set_unheld`).
    anew: osis_base::memo::Feed<SyncId>,
    known: Known,
    /// Blobs asked from some source, and when (one source at a time).
    asked: BTreeMap<BlobId, (ConnId, Mono)>,
    /// The connections each sync ID is a member on (its sources).
    holders: BTreeMap<SyncId, BTreeSet<ConnId>>,
    /// The connections whose streams stand at their ends both ways (this side's last Pull there
    /// answered to the end with nothing of it in hand, the peer's followed): the part of caught
    /// up that is the connection's (`caught_up`).
    caught: StampedSet<ConnId>,
    /// The members busy on a connection (spec/sync-status.md §1): an event of S in hand there,
    /// or served to the peer and not reported applied, or logged and not pushed, or a join of S
    /// left to read on. Kept per (connection, S), so S's traffic moves no other member's caught
    /// up; `busy_of` is the same per connection.
    busy: StampedSet<(ConnId, SyncId)>,
    busy_of: BTreeMap<ConnId, BTreeSet<SyncId>>,
    /// Per caught-up connection, the place (`pulls_sent`) of the Pull the last reply answered:
    /// status's passes alone read it (`caught_since`), so a Pull answered moves no one else.
    caught_at: Stamped<ConnId, u64>,
    /// Pulls sent so far, on every connection: each Pull's place, strictly increasing, so a pass
    /// tells a Pull sent after it began from one before in the same millisecond.
    pulls_sent: u64,
    /// Relay-only blobs taken, per sync ID until their expiry, and each S's relay rate.
    relays: osis_proto::RelayGate,
    /// A store failure this step met: `settle` fails the step with it.
    fault: Option<osis_store::Error>,
    work: Work,
    /// Sources whose connection ended keeping stops of members closed on it, which go at the
    /// next tick (spec/sync-opens.md §6 Where it stopped).
    unkept: Vec<(Source, Vec<SyncId>)>,
}

impl Streams {
    /// Streams over the node's store: where a record source's place and word live.
    /// A store failure reading what it owes fails its first step (`fault`).
    pub fn new(store: Store) -> Streams {
        let (anew, owed) = store.anew_feed();
        let unkept = pull::forget_unkept(store.clone());
        let mut st = Streams { serve: BTreeMap::new(), pull: BTreeMap::new(), places: BTreeMap::new(), shreds: store.shred_feed(), anew, known: Known::new(store), asked: BTreeMap::new(), holders: BTreeMap::new(), caught: StampedSet::default(), busy: StampedSet::default(), busy_of: BTreeMap::new(), caught_at: Stamped::default(), pulls_sent: 0, relays: osis_proto::RelayGate::default(), fault: None, work: Work::default(), unkept: Vec::new() };
        st.failed(owed);
        st.failed(unkept);
        st
    }

    /// Tests only (world copies): reads the copy's store.
    #[doc(hidden)]
    pub fn set_store(&mut self, store: Store) {
        self.known.set_store(store);
    }

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

    /// Entry `b` of S fetched from the source on `conn` though no message in hand owes it: a body
    /// counting missing again that the source's stream showed present (read's word,
    /// spec/sync-judgement.md §3 Dropped bodies).
    #[allow(clippy::too_many_arguments)]
    pub fn fetch_again(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, conn: ConnId, s: SyncId, b: BlobId, reported: &mut Vec<Reported>) {
        product(cx, sessions, opens, reported, |ctx| self.refetch(ctx, conn, s, b));
    }

    /// Commit `c`'s body under S asked for by ID on `conn` (read's word: a body counting missing,
    /// spec/sync-judgement.md §3 Asked by ID), whatever the source's stream shows.
    #[allow(clippy::too_many_arguments)]
    pub fn want(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, conn: ConnId, s: SyncId, c: osis_base::CommitId, reported: &mut Vec<Reported>) {
        product(cx, sessions, opens, reported, |ctx| self.want_in(ctx, conn, s, c));
    }

    /// `want` over `Ctx`.
    pub fn want_in(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, c: osis_base::CommitId) {
        self.want_body(ctx, conn, s, c);
    }

    pub fn next_wake(&self) -> Option<Mono> {
        let asked = self.asked.values().map(|(_, at)| at.after(ASKED_MS)).min();
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

    /// Whether the source on `conn` is caught up on S (spec/sync-status.md §1): this side's
    /// stream of S there at the stream, its last reply the end, no gap, no reply or push of S in
    /// hand and no Pull out (spec/sync-streams.md §4; `SN_rearm`), and the peer followed this
    /// side's stream with every event of S logged here pushed and reported applied.
    pub fn caught_up(&self, conn: ConnId, s: &SyncId) -> bool {
        self.caught.contains(&conn) && !self.busy.contains(&(conn, *s)) && self.pull.get(&conn).is_some_and(|p| self.places.get(&p.src).is_some_and(|pl| pl.at_stream.contains(s) && !pl.joining.contains_key(s)))
    }

    /// The place (`pull_seq`) of the Pull whose reply S's caught up on `conn` rests on: none
    /// while not caught up. Stamped per connection and per (source, S).
    pub fn caught_since(&self, conn: ConnId, s: &SyncId) -> Option<u64> {
        let t = *self.caught_at.get(&conn)?;
        self.caught_up(conn, s).then_some(t)
    }

    /// The Pulls sent so far: a Pull sent after this reads a greater place (`caught_since`).
    pub fn pull_seq(&self) -> u64 {
        self.pulls_sent
    }

    /// Tests only: what a connection's pulling holds for its peer (messages in hand, queued and
    /// failed bodies, refusals to tell, what a listing under way keeps).
    #[doc(hidden)]
    pub fn holding(&self, conn: ConnId) -> usize {
        self.pull.get(&conn).map_or(0, pull::Pulling::holding)
    }

    /// Tests only: the sources whose place is held in memory.
    #[doc(hidden)]
    pub fn places(&self) -> usize {
        self.places.len()
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
            Incoming::Request(id, Msg::Fetch { max_reply, ids, .. }) => self.on_fetch(ctx, conn, id, max_reply, ids),
            Incoming::Request(id, Msg::Want { max_reply, ids, .. }) => self.on_want(ctx, conn, id, max_reply, ids),
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
        let conn = m.conn();
        match m {
            Moved::Taken(conn, rid, _) => {
                self.taken(ctx, conn, rid);
                self.run(ctx, conn);
            }
            Moved::Released(conn, _) => self.closed(conn),
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
            Moved::Left(conn, s, at) => {
                if let Some(set) = self.holders.get_mut(&s) {
                    set.remove(&conn);
                    if set.is_empty() {
                        self.holders.remove(&s);
                    }
                }
                self.served_left(conn, &s);
                self.left(ctx, conn, s, at.how);
            }
            Moved::Until(conn, s) => self.served_ending(ctx, conn, s),
            Moved::Forgot(conn, s) => self.forgot(ctx, conn, s),
            // what the record's source showed of S goes with the member (spec/sync-opens.md §6)
            Moved::Gone(rid, s) => self.forget_stops(ctx, Source::Record(rid), &[s]),
        }
        if let Some(conn) = conn {
            self.track(ctx, conn);
        }
    }

    /// Wants a Pull from the stream's cursor on `conn` though nothing else is due, sent once any
    /// under way ends (a complete pass, spec/sync-status.md §1; spec/permissions.md §3).
    pub fn again(&mut self, ctx: &mut Ctx, conn: ConnId) {
        let Some(p) = self.pull.get_mut(&conn) else { return };
        p.again = true;
        self.run(ctx, conn);
        self.track(ctx, conn);
    }

    /// Keeps `caught` and `busy` for `conn` as its pulling and serving now stand: O(members
    /// busy there, and events logged since the last).
    fn track(&mut self, ctx: &Ctx, conn: ConnId) {
        let scanned = self.scan_unpushed(ctx, conn);
        self.failed(scanned);
        let mut busy = BTreeSet::new();
        if let Some(p) = self.pull.get(&conn) {
            busy.extend(p.in_hand().copied());
        }
        self.served_busy(ctx, conn, &mut busy);
        let was = self.busy_of.remove(&conn).unwrap_or_default();
        for s in was.difference(&busy) {
            self.busy.remove(&(conn, *s));
        }
        for s in busy.difference(&was) {
            self.busy.insert((conn, *s));
        }
        if !busy.is_empty() {
            self.busy_of.insert(conn, busy);
        }
        let now = self.pull.get(&conn).filter(|p| p.caught_up() && self.followed(conn)).map(|p| p.answered_at);
        match now {
            Some(t) => {
                self.caught.insert(conn);
                self.caught_at.insert(conn, t);
            }
            None => {
                self.caught.remove(&conn);
                self.caught_at.remove(&conn);
            }
        }
    }

    /// A connection ended (before opens reports its members left): what lasted it alone goes,
    /// its members' places stay with the record.
    pub fn closed(&mut self, conn: ConnId) {
        self.serve.remove(&conn);
        if let Some(p) = self.pull.remove(&conn) {
            self.dropped_in_hand(&p);
            match p.src {
                // a record's place stays with the record (`record_left`); where members closed on
                // this connection stopped lasts the connection: gone at the next tick (a start
                // finds those a crash left)
                Source::Record(_) => {
                    if let Some(place) = self.places.get(&p.src).filter(|pl| !pl.closed.is_empty()) {
                        self.unkept.push((p.src, place.closed.iter().copied().collect()));
                    }
                }
                Source::Conn(_) => {
                    self.places.remove(&p.src);
                }
            }
        }
        self.asked.retain(|_, (c, _)| *c != conn);
        let r = self.known.forget_source(Source::Conn(conn));
        self.failed(r);
        for set in self.holders.values_mut() {
            set.remove(&conn);
        }
        self.holders.retain(|_, v| !v.is_empty());
        self.caught.remove(&conn);
        self.caught_at.remove(&conn);
        for s in self.busy_of.remove(&conn).unwrap_or_default() {
            self.busy.remove(&(conn, s));
        }
    }

    /// Record `rid` left opens' memory: its place goes from memory (its rows stay).
    pub fn record_left(&mut self, rid: RecordId) {
        let src = Source::Record(rid);
        if !self.pull.values().any(|p| p.src == src) {
            self.places.remove(&src);
        }
    }

    /// Settles every connection: pushes under `follow`, Pulls and Fetches due, room regained.
    pub fn tick(&mut self, ctx: &mut Ctx) -> Result<bool> {
        self.forget_shredded();
        for (src, ss) in std::mem::take(&mut self.unkept) {
            // a member opened again since (on the record's next connection) keeps its place
            let ss: Vec<SyncId> = ss.into_iter().filter(|s| self.places.get(&src).is_none_or(|p| p.closed.contains(s))).collect();
            if !ss.is_empty() {
                self.forget_stops(ctx, src, &ss);
            }
        }
        let r = self.known.settle();
        self.failed(r);
        let mut acted = self.send_relays(ctx)?;
        let roomy = ctx.store.room_grew()?;
        acted |= !roomy.is_empty();
        self.untell_full(&roomy);
        acted |= self.fetch_anew(ctx);
        let conns: BTreeSet<ConnId> = self.serve.keys().chain(self.pull.keys()).copied().collect();
        for c in conns {
            acted |= self.push(ctx, c)?;
            self.run(ctx, c);
            self.track(ctx, c);
        }
        if let Some(e) = self.fault.take() {
            return Err(e.into());
        }
        Ok(acted)
    }

    /// S left this node (spec/sync-set.md §3): what places hold of it in memory goes (every
    /// source's rows of it went with the shred), so a later join reads it from the start.
    /// Run before any place is read (`place`): a member leaving S later in the step of its shred
    /// must find no position to keep, else it writes S's rows back after the shred. S full
    /// (its wait went with the shred) is told full no longer on each connection still sharing it.
    pub(super) fn forget_shredded(&mut self) {
        let shredded = self.shreds.added();
        for s in &shredded {
            for place in self.places.values_mut() {
                place.forget(s);
            }
        }
        self.untell_full(&shredded);
    }

    /// Notes a store failure (or an engine's broken invariant, its text kept): the step fails at
    /// the next settle.
    fn failed(&mut self, r: Result<()>) {
        if let Err(e) = r {
            self.fault.get_or_insert(e.into_store("streams: store"));
        }
    }
}

/// Runs `f` over the product's `Ctx`.
fn product(cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, reported: &mut Vec<Reported>, f: impl FnOnce(&mut Ctx)) {
    let (now, mono) = (cx.now, cx.mono);
    let mut ground = EngineGround { engine: cx.engine, store: cx.store.clone(), rng: &mut *cx.rng };
    let mut ctx = Ctx { store: cx.store, ground: &mut ground, wire: sessions, shared: opens, now, mono, reported };
    osis_base::costs::scoped("streams", || f(&mut ctx));
}

/// What opening entry `e` of read S with `bytes` does at this node (the product's `Ground::open`,
/// over `Engine::open_entry`).
pub fn opening(engine: &mut Engine, store: &crate::store::Store, s: &SyncId, e: &Entry, bytes: &[u8]) -> Result<Opening> {
    match crate::store::open_entry(engine, store, s, &e.blob, &e.wrap, bytes) {
        Ok(o) if crate::store::pends(engine, &e.blob, &o) => Ok(Opening::Pends),
        Ok(Opened::Commit(c, _)) if engine.holds_memory(&c) => Ok(Opening::Memory(engine.memory_charge(&c)?)),
        Ok(Opened::Commit(_, i)) => Ok(Opening::Held { gave: !matches!(i, osis_engine::Ingested::Duplicate(_)) }),
        // a certificate blob is kept as it came, counted as the own store's and charged to no
        // one, as a start's open of it does (spec/permissions.md §4 Logging certificates: one
        // logged by any node counts; read keeps one per set of certificates, `cert_blobs`)
        Ok(Opened::Records(_)) => Ok(Opening::Held { gave: true }),
        // a sync copy is its bringer's word (anyone sealing to the holder or depositing under
        // its sync ID makes one, a forged genesis counting where none of the thing's admins' word
        // is held, `Core::copies_speak`):
        // charged to its bringer unless stamped (spec/sync-ids.md §5 Peer budget)
        Ok(Opened::SyncCopy) => Ok(Opening::Held { gave: false }),
        // a notice: its removal's copy taken, kept as any certificate blob is
        Ok(Opened::Notice(..)) => Ok(Opening::Held { gave: true }),
        Ok(Opened::Linked) => Ok(Opening::Taken),
        Ok(Opened::NotOpen) => Ok(Opening::NotOpen),
        Ok(Opened::Bad) => Ok(Opening::Bad),
        Err(e) => Err(e),
    }
}

/// The product's `Ground`: the engine's facade.
struct EngineGround<'a> {
    engine: &'a mut Engine,
    /// For S's memory room (`store::open_entry`).
    store: crate::store::Store,
    /// For sealing own relay-only commits.
    rng: &'a mut dyn osis_crypto::NodeRng,
}

impl Ground for EngineGround<'_> {
    fn open(&mut self, s: &SyncId, e: &Entry, bytes: &[u8]) -> Result<Opening> {
        opening(self.engine, &self.store, s, e, bytes)
    }

    fn own_relays(&mut self) -> Result<Vec<osis_engine::sync::Relay>> {
        Ok(self.engine.take_relays(&mut *self.rng)?)
    }

    fn open_relay(&mut self, s: &SyncId, e: &Entry, bytes: &[u8]) -> Result<osis_engine::sync::RelayOpened> {
        Ok(self.engine.open_relay(s, &e.blob, &e.wrap, bytes)?)
    }

    fn stamp(&mut self, s: &SyncId, b: &BlobId, wrap: &Wrap) -> Option<osis_proto::Stamp> {
        let w = self.engine.signers(s, None).ok()?.stamp?;
        Some(osis_blob::sign_stamp(&w, s, b, wrap, false))
    }

    fn unkept(&mut self, store: &crate::store::Store, b: &BlobId) -> Result<()> {
        self.engine.forget_carrier(b);
        if !store.named(b)? {
            self.engine.unnamed_copy(b)?;
        }
        if let Some(c) = self.engine.blob_commit(b) {
            crate::store::release(self.engine, store, &c)?;
        }
        Ok(())
    }

    fn head_write(&mut self, s: &SyncId) -> Option<osis_crypto::VerifyingKey> {
        Some(self.engine.read_credentials(s).ok()??.head.as_ref()?.keys.write)
    }

    fn rank(&mut self, s: &SyncId, b: &BlobId, wrap: &Wrap) -> Rank {
        let Ok(Some(c)) = self.engine.read_credentials(s) else { return Rank::Unopened };
        match osis_blob::wrap_order(c.read_secrets.iter().map(|(_, k)| k), b, wrap) {
            Some(o) => Rank::Order(o),
            None => Rank::Unopened,
        }
    }

    fn counted(&mut self, s: &SyncId, b: &BlobId) -> bool {
        self.engine.cert_blob_noted(s, b)
    }

    fn role_entry(&mut self, s: &SyncId, b: &BlobId) -> bool {
        self.engine.role_entry(s, b)
    }

    fn notice_tells(&mut self, s: &SyncId, b: &BlobId, proven: &std::collections::BTreeSet<osis_base::Tid>) -> bool {
        self.engine.notice_tells(s, b, proven)
    }

    fn want(&mut self, store: &crate::store::Store, s: &SyncId, c: &osis_base::CommitId) -> Result<Option<Given>> {
        let id = osis_engine::sync::BodyId::unit(*c);
        let Some(meta) = self.engine.sync_body(s, &id)? else { return Ok(None) };
        let blobs = self.engine.commit_blobs(c)?;
        let mut held = Vec::new();
        for b in blobs.iter() {
            let Some(bytes) = store.bytes(b)? else { continue };
            if let Some(e) = store.entry(s, b)?
                && self.engine.blob_body(s, b)? == Some(id)
                && self.engine.body_held_by(&meta, b)
            {
                return Ok(Some((bytes, e.wrap, e.stamp)));
            }
            // a genuine blob under any sync ID: its sections go into a fresh encryption as they came
            for x in store.naming(b)? {
                if self.engine.blob_body(&x, b)?.is_some() && let Some(e) = store.entry(&x, b)? {
                    held.push(osis_engine::sync::HeldBlob { sync_id: x, wrap: e.wrap, bytes });
                    break;
                }
            }
        }
        Ok(self.engine.seal_body(s, &id, &held, &mut *self.rng)?.map(|(sealed, wrap)| (sealed.blob, wrap, None)))
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
