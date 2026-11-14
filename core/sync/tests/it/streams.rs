//! Streams alone (osis_sync::streams): two sides over real stores, each serving and pulling
//! over one connection whose frames go through the real codec; the shared set, the engine's
//! opening and the fabric scripted. One test per rule of spec/sync-streams.md §3-§5 it implements,
//! each `SN_*` control of core/test/tla/net/NetStream.tla named on its test, and costs at n and
//! 10n.

use osis_base::format::TOMBSTONE_LIFETIME_MS;
use osis_base::{BlobId, SyncId, Tid, WallMs};
use osis_crypto::{Epoch, LabelRole, Secret32, SeededRng, WRAP_LEN, label_role_key};
use osis_engine::sync::{Caps, Holding, SyncSet};
use osis_label::{ClaimSet, Class, Parent, Prefix, Step, StepKeys};
use osis_proto::limits::{REPLY_BUDGET, SMALL_REPLY, TOP_BIT};
use osis_proto::{Code, Event, Id, Msg, Pull};
use osis_store::{MemoryBackend, MemoryRoot, RecordId};
use osis_sync::opens::Member;
use osis_sync::session::{Incoming, To};
use osis_sync::store::Source;
use osis_sync::streams::{Ctx, Ground, Opening, Rank, Rejoin, Reported, Shared, Streams, Wire};
use osis_sync::types::{ConnId, Credential, Entry, Result, SourceClass};
use osis_sync::unread::Sources;
use osis_sync::Store;
use std::collections::{BTreeMap, VecDeque};

/// The one connection, as each side names it.
const C: ConnId = ConnId(1);
const THING: Tid = Tid::from_bytes([0x51; 15]);

// ---- the scripted parts ----

/// The engine's part: what opened, and each blob's fill rank.
#[derive(Default)]
struct Table {
    opened: Vec<BlobId>,
    rank: BTreeMap<BlobId, Rank>,
}

impl Ground for Table {
    fn open(&mut self, _s: &SyncId, e: &Entry, _bytes: &[u8]) -> Result<Opening> {
        self.opened.push(e.blob);
        Ok(Opening::Taken)
    }
    fn rank(&mut self, _s: &SyncId, b: &BlobId, _w: &[u8; WRAP_LEN]) -> Rank {
        self.rank.get(b).copied().unwrap_or(Rank::Unopened)
    }
}

/// A frame on its way.
#[derive(Clone, Debug)]
enum Frame {
    Req(Id, Vec<u8>),
    Ans(Id, Vec<u8>),
    Push(Vec<u8>),
}

impl Frame {
    fn msg(&self) -> Msg {
        match self {
            Frame::Req(_, b) | Frame::Ans(_, b) | Frame::Push(b) => Msg::decode(b).unwrap(),
        }
    }
}

/// One side's sends.
#[derive(Default)]
struct Pipe {
    out: Vec<(ConnId, Frame)>,
    next: Id,
    /// Pushes refused (the push rule: no room).
    full: bool,
}

impl Wire for Pipe {
    fn request(&mut self, c: ConnId, mut m: Msg) -> Option<Id> {
        self.next += 1;
        let id = TOP_BIT | self.next;
        m.set_id(id);
        self.out.push((c, Frame::Req(id, m.encode())));
        Some(id)
    }
    fn answer(&mut self, c: ConnId, id: Id, mut m: Msg) {
        m.set_id(id);
        self.out.push((c, Frame::Ans(id, m.encode())));
    }
    fn push(&mut self, c: ConnId, m: Msg) -> bool {
        if self.full {
            return false;
        }
        self.out.push((c, Frame::Push(m.encode())));
        true
    }
}

/// The shared set as opens would hold it.
#[derive(Default)]
struct Open {
    members: BTreeMap<ConnId, BTreeMap<SyncId, Member>>,
    record: Option<RecordId>,
    rejoin: BTreeMap<SyncId, Rejoin>,
}

static NONE: BTreeMap<SyncId, Member> = BTreeMap::new();

impl Shared for Open {
    fn members(&self, c: ConnId) -> &BTreeMap<SyncId, Member> {
        self.members.get(&c).unwrap_or(&NONE)
    }
    fn agreed(&self, _c: ConnId) -> bool {
        true
    }
    fn record(&self, _c: ConnId) -> Option<RecordId> {
        self.record
    }
    fn rejoin(&self, _c: ConnId, s: &SyncId) -> Rejoin {
        self.rejoin.get(s).cloned().unwrap_or(Rejoin::Held)
    }
}

fn member() -> Member {
    Member { class: SourceClass::Reader, by: Credential::J, until: None, step: None }
}

struct Side {
    backend: MemoryBackend,
    root: MemoryRoot,
    store: Store,
    streams: Streams,
    table: Table,
    pipe: Pipe,
    open: Open,
    reported: Vec<Reported>,
    set: SyncSet,
}

impl Side {
    fn new(seed: u64) -> Side {
        let (backend, root) = (MemoryBackend::new(), MemoryRoot::new());
        let store = Store::open(Box::new(backend.clone()), Box::new(root.clone()), Box::new(SeededRng::from_u64(seed))).unwrap();
        Side { backend, root, store, streams: Streams::default(), table: Table::default(), pipe: Pipe::default(), open: Open { record: Some([seed as u8; 16]), ..Open::default() }, reported: Vec::new(), set: SyncSet::default() }
    }

    fn hold(&mut self, s: SyncId, h: Holding) {
        self.set.ids.insert(s, (THING, h));
        self.store.set_sync_set(&self.set);
    }

    /// The store reopened over its device (a restart).
    fn restart(&mut self, seed: u64) {
        self.store = Store::open(Box::new(self.backend.clone()), Box::new(self.root.clone()), Box::new(SeededRng::from_u64(seed))).unwrap();
        self.store.set_sync_set(&self.set);
    }

    fn with<T>(&mut self, now: u64, f: impl FnOnce(&mut Streams, &mut Ctx) -> T) -> T {
        let Side { store, streams, table, pipe, open, reported, .. } = self;
        let mut ctx = Ctx { store, ground: table, wire: pipe, shared: &*open, now: WallMs(now), reported };
        f(streams, &mut ctx)
    }

    fn join(&mut self, now: u64, s: SyncId) {
        self.open.members.entry(C).or_default().insert(s, member());
        self.with(now, |st, ctx| st.member_moved(ctx, osis_sync::opens::Moved::Joined(C, s)));
    }

    fn leave(&mut self, now: u64, s: SyncId) {
        if let Some(m) = self.open.members.get_mut(&C) {
            m.remove(&s);
        }
        self.with(now, |st, ctx| st.member_moved(ctx, osis_sync::opens::Moved::Left(C, s)));
    }

    /// A durable entry of its own logged under a read S.
    fn log(&mut self, s: SyncId, n: usize) -> BlobId {
        let (b, bytes) = blob(n, Class::Durable);
        let e = Entry { blob: b, wrap: [n as u8; WRAP_LEN], stamp: None, deposited: false, own: true, class: Class::Durable, expires: None };
        assert_eq!(self.store.log(&s, e, Some(bytes), None).unwrap(), Code::OK);
        b
    }

    fn src(&self) -> Source {
        self.open.record.map_or(Source::Conn(C), Source::Record)
    }
}

/// Two sides over one connection; `a` is the dialer only by name: both serve and pull.
struct Pair {
    a: Side,
    b: Side,
    now: u64,
    /// Frames held back instead of delivered (the fabric losing them), by a test's filter.
    held: Vec<(bool, Frame)>,
    /// Frames delivered, each way (`true`: a to b).
    seen: Vec<(bool, Msg)>,
}

impl Pair {
    fn new() -> Pair {
        Pair { a: Side::new(1), b: Side::new(2), now: 1_000, held: Vec::new(), seen: Vec::new() }
    }

    /// S read at both, a member both ways.
    fn shared_read(&mut self, s: SyncId) {
        self.a.hold(s, Holding::Read);
        self.b.hold(s, Holding::Read);
        self.a.join(self.now, s);
        self.b.join(self.now, s);
    }

    /// Delivers until nothing moves, settling both sides between deliveries; `drop` loses a frame
    /// (a to b when its flag is true).
    fn run_with(&mut self, mut drop: impl FnMut(bool, &Msg) -> bool) {
        for _ in 0..10_000 {
            let now = self.now;
            self.a.with(now, |s, c| s.tick(c).unwrap());
            self.b.with(now, |s, c| s.tick(c).unwrap());
            let on_c = |out: &mut Vec<(ConnId, Frame)>| {
                let (here, rest): (Vec<_>, Vec<_>) = std::mem::take(out).into_iter().partition(|(c, _)| *c == C);
                *out = rest;
                here.into_iter().map(|(_, f)| f)
            };
            let mut q: VecDeque<(bool, Frame)> = on_c(&mut self.a.pipe.out).map(|f| (true, f)).chain(on_c(&mut self.b.pipe.out).map(|f| (false, f))).collect();
            if q.is_empty() {
                return;
            }
            while let Some((ab, f)) = q.pop_front() {
                let m = f.msg();
                if drop(ab, &m) {
                    self.held.push((ab, f));
                    continue;
                }
                self.seen.push((ab, m.clone()));
                let to = if ab { &mut self.b } else { &mut self.a };
                let inc = match f {
                    Frame::Req(id, _) => Incoming::Request(id, m),
                    Frame::Ans(id, _) => Incoming::Reply(To::Streams, id, m),
                    Frame::Push(_) => Incoming::Push(m),
                };
                to.with(now, |s, c| s.message(c, C, inc));
            }
        }
        panic!("streams did not settle");
    }

    fn run(&mut self) {
        self.run_with(|_, _| false);
    }

    /// Messages of `kind` delivered from b to a (b's requests and pushes).
    fn sent_by_b(&self, kind: u64) -> Vec<&Msg> {
        self.seen.iter().filter(|(ab, m)| !*ab && m.kind() == kind).map(|(_, m)| m).collect()
    }

    fn sent_by_a(&self, kind: u64) -> Vec<&Msg> {
        self.seen.iter().filter(|(ab, m)| *ab && m.kind() == kind).map(|(_, m)| m).collect()
    }
}

fn sid(b: u8) -> SyncId {
    SyncId([b; 16])
}

/// A blob of `class` with `n` bytes of payload.
fn blob(n: usize, class: Class) -> (BlobId, Vec<u8>) {
    let mut rng = SeededRng::from_u64(n as u64 ^ 0x5eed);
    let p = Prefix::for_keys([n as u8; 16], &[1; 16], None, &[]).unwrap().with_class(class);
    let (_, bytes) = osis_label::frame(&p, &vec![n as u8; n], &mut rng).unwrap();
    (osis_label::blob_id(&bytes), bytes)
}

fn knows(side: &Side, from: Source, s: SyncId, b: BlobId) -> bool {
    side.streams.knows(from, Some(C), &s, &b)
}

/// A server-level exchange: one Pull request into `side`, its answer.
fn pull_at(side: &mut Side, now: u64, p: Pull) -> osis_proto::PullReply {
    let id = TOP_BIT | 77;
    side.with(now, |s, c| s.message(c, C, Incoming::Request(id, Msg::Pull(Box::new(Pull { id, ..p })))));
    let (_, f) = side.pipe.out.pop().unwrap();
    match f.msg() {
        Msg::PullReply(r) => *r,
        m => panic!("not a PullReply: {m:?}"),
    }
}

fn plain_pull(cursor: Option<Vec<u8>>, joins: Vec<(SyncId, Option<Vec<u8>>)>, max_reply: usize) -> Pull {
    let cur = |c: Option<Vec<u8>>| c.map(|c| osis_proto::Cursor::new(c).unwrap());
    Pull { id: 0, cursor: cur(cursor), joins: joins.into_iter().map(|(s, c)| (s, cur(c))).collect(), inline_limit: 0, max_reply: max_reply as u64, follow: false, ephemeral: false }
}

fn added(r: &[(SyncId, Event)]) -> Vec<BlobId> {
    r.iter().filter_map(|(_, e)| if let Event::Added { blob_id, .. } = e { Some(*blob_id) } else { None }).collect()
}

// ---- kept unread: a sync ID's steps and stamps ----

struct Sid {
    id: SyncId,
    sync: Secret32,
    write: Secret32,
    admin: Secret32,
    deposit: Secret32,
    genesis: (Step, ClaimSet),
}

impl Sid {
    fn new(b: u8) -> Sid {
        let (sync, write, admin, deposit) = (Secret32::from_bytes([b; 32]), Secret32::from_bytes([b + 1; 32]), Secret32::from_bytes([b + 2; 32]), Secret32::from_bytes([b + 3; 32]));
        let id = osis_label::genesis_label(&admin);
        let keys = StepKeys::derive(&sync, &write, &admin, &deposit, &id);
        let mut rng = SeededRng::from_u64(99);
        let read = Epoch::derive(&THING, osis_base::Role::Read, 0, &write).unwrap();
        let se = Epoch::derive(&THING, osis_base::Role::Sync, 0, &sync).unwrap();
        let d = label_role_key(LabelRole::Delete, &admin);
        let genesis = osis_label::register(Parent::Genesis(&d), keys, &[], (&THING, read, &write), (se, &sync), &mut rng).unwrap();
        Sid { id, sync, write, admin, deposit, genesis }
    }

    /// A side keeping this sync ID unread, its genesis registered.
    fn keep(&self, side: &mut Side) {
        let _ = (&self.sync, &self.admin, &self.deposit);
        side.hold(self.id, Holding::Unread);
        assert_eq!(side.store.take_register(&self.id, &self.genesis.0, Some(&self.genesis.1)).unwrap(), Code::OK);
    }

    /// A stamped entry of a fresh blob taken into `side`'s store.
    fn stamped(&self, side: &mut Side, n: usize, good: bool) -> BlobId {
        let (b, bytes) = blob(n, Class::Durable);
        let w = [3u8; WRAP_LEN];
        let key = if good { label_role_key(LabelRole::Write, &self.write) } else { label_role_key(LabelRole::Write, &Secret32::from_bytes([0xee; 32])) };
        let stamp = osis_label::sign_stamp(&key, &self.id, &b, &w, false);
        let e = Entry { blob: b, wrap: w, stamp: Some(stamp), deposited: false, own: false, class: Class::Durable, expires: None };
        // a bad stamp is planted as a read S's own entry would be: the server serves what it holds
        if good {
            assert_eq!(side.store.take_stamped(&self.id, &e, bytes).unwrap(), Code::OK);
        } else {
            side.hold(self.id, Holding::Read);
            assert_eq!(side.store.log(&self.id, e, Some(bytes), None).unwrap(), Code::OK);
            side.hold(self.id, Holding::Unread);
        }
        b
    }
}

// ---- the tests ----

// spec/sync-streams.md §4 (Stream): a member is pulled by one stream: listed from the start, its
// bodies taken (inline while it has one source), then each later run pushed as a Stream; the
// requester knows what the source holds and is caught up.
#[test]
fn listed_then_pushed_spec_sync_streams_4() {
    let mut p = Pair::new();
    let s = sid(1);
    let x: Vec<BlobId> = (0..3).map(|i| p.a.log(s, 100 + i)).collect();
    p.shared_read(s);
    p.run();
    let src = p.a.src();
    let _ = src;
    for b in &x {
        assert!(knows(&p.b, p.b.src(), s, *b));
    }
    assert_eq!(p.b.table.opened.len(), 3, "inline bodies opened");
    assert!(p.b.streams.caught_up(C, &s));
    let y = p.a.log(s, 200);
    p.run();
    assert!(knows(&p.b, p.b.src(), s, y));
    let streams = p.sent_by_a(43);
    assert!(streams.iter().any(|m| matches!(m, Msg::Stream(st) if added(&st.events) == [y] && st.seq == 0 && st.cursor.is_some())));
    assert!(p.b.streams.caught_up(C, &s));
    assert!(p.b.streams.known().present(&s, &y));
}

// spec/sync-streams.md §4 (Stream: both sides pull), SN_bothpull: whoever dialed, each side pulls
// the other.
#[test]
fn both_sides_pull_spec_sync_streams_4() {
    let mut p = Pair::new();
    let s = sid(1);
    let x = p.a.log(s, 100);
    let y = p.b.log(s, 101);
    p.shared_read(s);
    p.run();
    assert!(knows(&p.b, p.b.src(), s, x));
    assert!(knows(&p.a, p.a.src(), s, y));
    assert!(!p.sent_by_a(41).is_empty() && !p.sent_by_b(41).is_empty());
}

// spec/sync-streams.md §4 (Reading: a requester stores a cursor only after applying what it
// covers), SN_cursor: a body announced without bytes holds the message (and its Applied) until it
// is fetched; the source's reported position moves only then.
#[test]
fn cursor_stored_once_bodies_held_spec_sync_streams_4() {
    let mut p = Pair::new();
    let s = sid(1);
    let big = p.a.log(s, 40_000);
    p.shared_read(s);
    p.run_with(|ab, m| ab && m.kind() == 20);
    assert!(!p.b.streams.caught_up(C, &s));
    assert!(p.sent_by_b(44).is_empty(), "no Applied before the body");
    assert_eq!(p.a.streams.reported(C, &s), None);
    assert!(!knows(&p.b, p.b.src(), s, big));
    // the fetch answered: applied, stored, reported
    let held = std::mem::take(&mut p.held);
    for (_, f) in held {
        let m = f.msg();
        let Frame::Ans(id, _) = f else { continue };
        p.b.with(p.now, |st, c| st.message(c, C, Incoming::Reply(To::Streams, id, m)));
    }
    p.run();
    assert!(knows(&p.b, p.b.src(), s, big));
    assert_eq!(p.b.table.opened, [big]);
    assert!(!p.sent_by_b(44).is_empty());
    assert!(p.a.streams.reported(C, &s).is_some());
    assert!(p.b.streams.caught_up(C, &s));
}

// spec/sync-streams.md §4 (Pushes: seq), the storm-489005 scenario, SN_rearm: a lost push is
// noticed by the next Stream's seq; the requester applies none after it, is not caught up, and
// reads again from its stored cursor, ephemeral entries listed again.
#[test]
fn lost_push_read_again_by_seq_spec_sync_streams_4() {
    let mut p = Pair::new();
    let s = sid(1);
    p.shared_read(s);
    p.run();
    let x = p.a.log(s, 100);
    let mut lost = false;
    p.run_with(|ab, m| {
        let hit = ab && m.kind() == 43 && !lost;
        lost |= hit;
        hit
    });
    assert!(lost);
    assert!(!knows(&p.b, p.b.src(), s, x));
    // the next push has seq 1: a gap
    let y = p.a.log(s, 101);
    let before = p.sent_by_b(41).len();
    p.run();
    let pulls = p.sent_by_b(41);
    assert_eq!(pulls.len(), before + 1, "read again");
    assert!(matches!(pulls.last().unwrap(), Msg::Pull(q) if q.ephemeral), "ephemeral listed again after a dropped push");
    assert!(knows(&p.b, p.b.src(), s, x) && knows(&p.b, p.b.src(), s, y));
    assert!(p.b.streams.caught_up(C, &s));
}

// spec/sync-streams.md §4 (Reading: filtered by the connection's shared set), SN_gate: a member the
// server no longer shares gets no later event.
#[test]
fn served_by_the_shared_set_now_spec_sync_streams_4() {
    let mut p = Pair::new();
    let (s, t) = (sid(1), sid(2));
    p.shared_read(s);
    p.shared_read(t);
    p.run();
    p.a.open.members.get_mut(&C).unwrap().remove(&s);
    let x = p.a.log(s, 100);
    let y = p.a.log(t, 101);
    p.run();
    assert!(!knows(&p.b, p.b.src(), s, x));
    assert!(knows(&p.b, p.b.src(), t, y));
    assert!(p.sent_by_a(43).iter().all(|m| matches!(m, Msg::Stream(st) if st.events.iter().all(|(x, _)| *x != s))));
}

// spec/sync-streams.md §3 (Cursor: one naming no position of this history), SN_inc, SN_copies:
// a cursor from another store's log is no cursor: every member from the start, whole.
#[test]
fn a_cursor_of_another_history_lists_whole_spec_sync_streams_3() {
    let mut a = Side::new(1);
    let mut other = Side::new(3);
    let s = sid(1);
    a.hold(s, Holding::Read);
    other.hold(s, Holding::Read);
    let x = a.log(s, 100);
    other.log(s, 101);
    let foreign = other.store.read_log(&BTreeMap::from([(s, None)]), None, 10).unwrap().cursor;
    a.open.members.entry(C).or_default().insert(s, member());
    let r = pull_at(&mut a, 1, plain_pull(foreign, vec![], REPLY_BUDGET));
    assert!(r.whole && !r.trimmed);
    assert_eq!(added(&r.events), [x]);
    let own = r.cursor.unwrap().into_bytes();
    let r = pull_at(&mut a, 1, plain_pull(Some(own), vec![], REPLY_BUDGET));
    assert!(!r.whole && r.events.is_empty());
}

// spec/sync-streams.md §3 (Cursor: a restart keeps the incarnations before it), SN_history: after
// a store restart, a cursor from before it resumes; no listing from the start.
#[test]
fn a_restart_honours_earlier_cursors_spec_sync_streams_3() {
    let mut a = Side::new(1);
    let s = sid(1);
    a.hold(s, Holding::Read);
    a.log(s, 100);
    a.open.members.entry(C).or_default().insert(s, member());
    let c = pull_at(&mut a, 1, plain_pull(None, vec![], REPLY_BUDGET)).cursor.unwrap().into_bytes();
    a.restart(9);
    let y = a.log(s, 101);
    let r = pull_at(&mut a, 2, plain_pull(Some(c), vec![], REPLY_BUDGET));
    assert!(!r.whole);
    assert_eq!(added(&r.events), [y]);
}

// spec/wire.md §11.2 (Pull: whole), spec/sync-streams.md §3 (Node log: a listing from the start is
// the live set and recent deletions), SN_listdels: a whole reply carries the deletion events the
// log holds, so a requester that knew the entry learns it left.
#[test]
fn a_whole_listing_carries_deletions_spec_sync_streams_3() {
    let mut a = Side::new(1);
    let s = sid(1);
    a.hold(s, Holding::Read);
    let x = a.log(s, 100);
    a.store.drop_entry(&s, &x, Vec::new()).unwrap();
    a.open.members.entry(C).or_default().insert(s, member());
    let r = pull_at(&mut a, 1, plain_pull(None, vec![], REPLY_BUDGET));
    assert!(r.whole);
    assert!(r.events.contains(&(s, Event::Deleted(x))));
}

// spec/sync-streams.md §4 (Applying: a listing never treats an absent entry as deleted, except
// one from the start marked trimmed), SN_infer_lit, SN_infer_knew: a whole listing leaves `known`
// and the requester's own store alone; only a trimmed one replaces what the source holds.
#[test]
fn absence_is_no_deletion_but_trimmed_spec_sync_streams_4() {
    let mut p = Pair::new();
    let s = sid(1);
    let x = p.a.log(s, 100);
    let own = p.b.log(s, 300);
    p.shared_read(s);
    p.run();
    assert!(knows(&p.b, p.b.src(), s, x));
    // b goes away; a drops x and its deletion event leaves a's log: b's cursor is below the horizon
    p.b.leave(p.now, s);
    p.a.leave(p.now, s);
    p.a.store.drop_entry(&s, &x, Vec::new()).unwrap();
    p.a.log(s, 101);
    p.now += TOMBSTONE_LIFETIME_MS + 1;
    p.a.store.settle_at(WallMs(p.now)).unwrap();
    p.a.join(p.now, s);
    p.b.join(p.now, s);
    p.run();
    let replies: Vec<_> = p.sent_by_a(42).into_iter().filter_map(|m| if let Msg::PullReply(r) = m { Some(r.clone()) } else { None }).collect();
    assert!(replies.last().unwrap().trimmed);
    assert!(!knows(&p.b, p.b.src(), s, x), "a trimmed listing replaced what a holds");
    assert!(p.b.store.entry(&s, &own).unwrap().is_some(), "nothing of b's own store goes");
}

// spec/sync-streams.md §4 (Joining: a join in pages keeps its own position), SN_joindur, and
// spec/sync-opens.md §6 (reported positions: a join's own until the message merging it is
// covered), SN_lostolder.
#[test]
fn a_join_in_pages_keeps_its_position_spec_sync_streams_4() {
    let mut a = Side::new(1);
    let (s, t) = (sid(1), sid(2));
    a.hold(s, Holding::Read);
    a.hold(t, Holding::Read);
    for i in 0..300 {
        a.log(t, 1000 + i);
    }
    a.log(s, 100);
    a.open.members.entry(C).or_default().insert(s, member());
    let c = pull_at(&mut a, 1, plain_pull(None, vec![], REPLY_BUDGET)).cursor.unwrap().into_bytes();
    a.open.members.get_mut(&C).unwrap().insert(t, member());
    let r = pull_at(&mut a, 1, plain_pull(Some(c.clone()), vec![(t, None)], SMALL_REPLY));
    let [(jt, Some(jc))] = r.joins.as_slice() else { panic!("the join is in pages: {:?}", r.joins) };
    assert_eq!(*jt, t);
    let first = added(&r.events).len();
    assert!(first > 0 && first < 300);
    assert_eq!(a.streams.reported(C, &t), None, "joined from the start: no position yet");
    let mut seen = first;
    let mut jc = jc.clone().into_bytes();
    let mut stream = r.cursor.unwrap().into_bytes();
    loop {
        let r = pull_at(&mut a, 1, plain_pull(Some(stream.clone()), vec![(t, Some(jc.clone()))], SMALL_REPLY));
        seen += added(&r.events).len();
        stream = r.cursor.unwrap().into_bytes();
        match r.joins.as_slice() {
            [(_, Some(c))] => jc = c.clone().into_bytes(),
            [] => break,
            j => panic!("{j:?}"),
        }
        let _ = c.len();
    }
    assert_eq!(seen, 300, "every event of the join, each once");
    // merged: the member follows the stream once an Applied covers the merging reply
    a.with(1, |st, cx| st.message(cx, C, Incoming::Push(Msg::Applied { cursor: osis_proto::Cursor::new(stream.clone()).unwrap() })));
    assert!(a.reported.contains(&Reported::Merged(C, t)));
    assert_eq!(a.streams.reported(C, &t), a.streams.reported(C, &s));
}

// spec/sync-streams.md §4 (Joining: a join of a member the server does not share is answered so;
// one refused while S stays a member is joined again `resync_ms` later), SN_joinans.
#[test]
fn a_refused_join_is_joined_again_later_spec_sync_streams_4() {
    let mut p = Pair::new();
    let (s, t) = (sid(1), sid(2));
    p.shared_read(s);
    p.run();
    p.a.hold(t, Holding::Read);
    p.b.hold(t, Holding::Read);
    let x = p.a.log(t, 100);
    p.b.join(p.now, t);
    p.run();
    assert!(!p.b.streams.caught_up(C, &t), "refused: not in the stream");
    p.a.join(p.now, t);
    let pulls = p.sent_by_b(41).len();
    p.run();
    assert_eq!(p.sent_by_b(41).len(), pulls, "not before resync_ms");
    p.now += osis_sync::streams::RESYNC_MS;
    p.run();
    assert!(knows(&p.b, p.b.src(), t, x));
    assert!(p.b.streams.caught_up(C, &t));
}

// spec/sync-opens.md §3 (Agreement: a member only one side holds closes with no position; its
// rejoin is from the start), SN_sreconcile: a rejoin opens says is from the start names no cursor,
// whatever this side held.
#[test]
fn a_rejoin_from_the_start_names_no_cursor_spec_sync_opens_3() {
    let mut p = Pair::new();
    let s = sid(1);
    p.a.log(s, 100);
    p.shared_read(s);
    p.run();
    p.b.leave(p.now, s);
    p.b.open.rejoin.insert(s, Rejoin::From(None));
    p.b.join(p.now, s);
    p.run();
    let last = p.sent_by_b(41).into_iter().last().unwrap();
    assert!(matches!(last, Msg::Pull(q) if q.joins == vec![(s, None)]));
    // held: from where the stream stood
    p.b.leave(p.now, s);
    p.b.open.rejoin.clear();
    p.b.join(p.now, s);
    p.run();
    let last = p.sent_by_b(41).into_iter().last().unwrap();
    assert!(matches!(last, Msg::Pull(q) if matches!(q.joins.as_slice(), [(x, Some(_))] if *x == s)));
}

// spec/sync-streams.md §4 (Applying: a Deleted says only that the source no longer holds the
// entry, never acted on as a delete).
#[test]
fn a_deletion_is_never_a_delete_here_spec_sync_streams_4() {
    let mut p = Pair::new();
    let s = sid(1);
    let x = p.a.log(s, 100);
    p.shared_read(s);
    p.run();
    let e = p.b.store.entry(&s, &x).unwrap();
    assert!(e.is_none());
    let mine = p.b.log(s, 100);
    assert_eq!(mine, x, "b holds the same blob of its own");
    p.a.store.drop_entry(&s, &x, Vec::new()).unwrap();
    p.run();
    assert!(!knows(&p.b, p.b.src(), s, x));
    assert!(p.b.store.entry(&s, &x).unwrap().is_some());
}

// spec/sync-streams.md §4 (Bodies: from one source at a time, `inline_limit` 0 with another
// source, the next source only when one fails; a body crosses a connection once).
#[test]
fn bodies_one_source_at_a_time_spec_sync_streams_4() {
    let mut p = Pair::new();
    let s = sid(1);
    let x = p.a.log(s, 100);
    // a second source of S at b: a connection whose frames never go anywhere
    p.b.hold(s, Holding::Read);
    p.b.open.members.entry(ConnId(9)).or_default().insert(s, member());
    p.b.with(p.now, |st, c| st.member_moved(c, osis_sync::opens::Moved::Joined(ConnId(9), s)));
    p.shared_read(s);
    p.run();
    let pulls = p.sent_by_b(41);
    assert!(matches!(pulls.last().unwrap(), Msg::Pull(q) if q.inline_limit == 0));
    assert_eq!(p.b.table.opened, [x]);
    let fetches = p.b.pipe.out.iter().filter(|(c, f)| *c == ConnId(9) && f.msg().kind() == 19).count();
    assert_eq!(fetches, 0, "nothing asked of the other source");
    assert_eq!(p.sent_by_b(19).len(), 1);
}

// spec/sync-streams.md §4 (Fill order, §5 First sync: order 0 goes before anything else is asked;
// a node holding a keyset without history fetches no body it can never open).
#[test]
fn order_zero_first_never_not_fetched_spec_sync_streams_5() {
    let mut p = Pair::new();
    let s = sid(1);
    let (z, h, n, u) = (p.a.log(s, 40_001), p.a.log(s, 40_002), p.a.log(s, 40_003), p.a.log(s, 40_004));
    p.b.table.rank = BTreeMap::from([(z, Rank::Order(0)), (h, Rank::Order(5)), (n, Rank::Never), (u, Rank::Unopened)]);
    p.shared_read(s);
    p.run();
    let fetches: Vec<Vec<BlobId>> = p.sent_by_b(19).into_iter().map(|m| if let Msg::Fetch { ids, .. } = m { ids.clone() } else { vec![] }).collect();
    assert_eq!(fetches.first().unwrap(), &vec![z], "order 0 alone first");
    assert!(fetches.iter().flatten().all(|b| *b != n), "never opens: never fetched");
    let order: Vec<BlobId> = fetches.into_iter().flatten().collect();
    // an unstamped entry is deposited: one that does not open goes before the highest order
    assert_eq!(order, [z, u, h]);
    assert!(p.b.streams.caught_up(C, &s), "the body never fetched holds nothing up");
}

// spec/sync-streams.md §4 (Full): a node keeping S unread refusing a pulled entry for room tells
// the peer `full` once, fetches no entry it refused while full, and once room grew says `full`
// false and pulls S again from the start.
#[test]
fn full_told_then_room_again_spec_sync_streams_4() {
    let mut p = Pair::new();
    let k = Sid::new(10);
    k.keep(&mut p.a);
    k.keep(&mut p.b);
    let x = k.stamped(&mut p.a, 3000, true);
    let y = k.stamped(&mut p.a, 3001, true);
    p.b.store.set_caps(&Caps { policy: BTreeMap::from([("bytes".to_string(), 4000)]), ..Caps::default() });
    p.a.join(p.now, k.id);
    p.b.join(p.now, k.id);
    p.run();
    let a_src = p.a.src();
    assert!(p.a.streams.known().full(a_src, &k.id), "b told it is full");
    let fulls = p.sent_by_b(43).iter().filter(|m| matches!(m, Msg::Stream(st) if st.events.iter().any(|(_, e)| *e == Event::Full(true)))).count();
    assert_eq!(fulls, 1);
    let taken = [x, y].iter().filter(|b| p.b.store.entry(&k.id, b).unwrap().is_some()).count();
    assert_eq!(taken, 1);
    // room grows: b drops what it took
    let held = if p.b.store.entry(&k.id, &x).unwrap().is_some() { x } else { y };
    p.b.store.drop_entry(&k.id, &held, Vec::new()).unwrap();
    p.run();
    assert!(!p.a.streams.known().full(a_src, &k.id));
    assert!(matches!(p.sent_by_b(41).last().unwrap(), Msg::Pull(q) if q.joins == vec![(k.id, None)]), "pulled again from the start");
}

// spec/sync-streams.md §4 (Refused): an entry refused for anything but room is told with its code;
// the peer keeps the refusal with the entry's stamp and head, and counts code 6 as deleted there.
#[test]
fn refusals_told_and_kept_spec_sync_streams_4() {
    let mut p = Pair::new();
    let k = Sid::new(10);
    k.keep(&mut p.a);
    k.keep(&mut p.b);
    let bad = k.stamped(&mut p.a, 500, false);
    let good = k.stamped(&mut p.a, 501, true);
    p.b.store.drop_entry(&k.id, &good, Vec::new()).unwrap();
    p.a.join(p.now, k.id);
    p.b.join(p.now, k.id);
    p.run();
    let src = p.a.src();
    let r = p.a.streams.known().refusal(src, &k.id, &bad).cloned().unwrap();
    assert_eq!(r.code, Code::REFUSED);
    assert!(r.stamp.is_some());
    assert!(p.sent_by_b(43).iter().any(|m| matches!(m, Msg::Stream(st) if st.cursor.is_none() && st.events.contains(&(k.id, Event::Refused(good, Code::TOMBSTONED))))));
    assert!(!p.a.streams.known().knows(src, &k.id, &good), "6 counts as deleted there");
}

// spec/sync-set.md §3 (a node keeping S unread leaves once each own entry is present at a
// source): `Sources::present` is what a source's stream showed.
#[test]
fn present_at_a_source_spec_sync_set_3() {
    let mut p = Pair::new();
    let s = sid(1);
    let x = p.a.log(s, 100);
    assert!(!Sources::present(&p.b.streams, &s, &x));
    p.shared_read(s);
    p.run();
    assert!(Sources::present(&p.b.streams, &s, &x));
}

// spec/sync-streams.md §4 (ephemeral entries listed at the first Pull and with every join): the
// memory part goes with its bytes; known through the connection alone, gone with it.
#[test]
fn ephemeral_listed_and_gone_with_the_connection_spec_sync_streams_4() {
    let mut p = Pair::new();
    let s = sid(1);
    p.a.hold(s, Holding::Read);
    let (e, bytes) = blob(120, Class::Ephemeral);
    let entry = Entry { blob: e, wrap: [7; WRAP_LEN], stamp: None, deposited: false, own: true, class: Class::Ephemeral, expires: None };
    assert_eq!(p.a.store.log(&s, entry, Some(bytes), None).unwrap(), Code::OK);
    p.b.hold(s, Holding::Read);
    p.a.join(p.now, s);
    p.b.join(p.now, s);
    p.run();
    assert!(p.b.streams.knows(Source::Conn(C), None, &s, &e));
    assert!(!p.b.streams.knows(p.b.src(), None, &s, &e), "not under the record");
    p.b.streams.closed(C);
    assert!(!p.b.streams.knows(Source::Conn(C), None, &s, &e));
}

// spec/sync-streams.md §4 (an ended member is served up to `until`; it reaching `until` goes as a
// Stream with a cursor and no events, asking report).
#[test]
fn an_ended_member_told_at_its_until_spec_sync_streams_4() {
    let mut p = Pair::new();
    let (s, u) = (sid(1), sid(3));
    p.a.log(s, 100);
    p.shared_read(s);
    p.run();
    // until past what b reported, reached through events b is not served (u is not shared)
    p.a.hold(u, Holding::Read);
    p.a.log(u, 102);
    let (end, _) = p.a.store.log_bounds().unwrap();
    p.a.open.members.get_mut(&C).unwrap().get_mut(&s).unwrap().until = Some(end);
    let late = p.a.log(s, 101);
    p.run();
    assert!(!knows(&p.b, p.b.src(), s, late), "nothing past until");
    assert!(p.sent_by_a(43).iter().any(|m| matches!(m, Msg::Stream(st) if st.events.is_empty() && st.report && st.cursor.is_some())));
}

// spec/sync-streams.md §4 (Costs): a push costs the events since the cursor, whatever the log
// holds: one new event read at n and at 10n entries.
#[test]
fn push_work_follows_the_events_not_the_log_spec_sync_streams_4() {
    let served = |n: usize| {
        let mut p = Pair::new();
        let s = sid(1);
        for i in 0..n {
            p.a.log(s, 100 + i);
        }
        p.shared_read(s);
        p.run();
        let before = p.a.streams.work().served;
        p.a.log(s, 100_000);
        p.run();
        p.a.streams.work().served - before
    };
    assert_eq!(served(20), served(200));
    assert_eq!(served(20), 1);
}
