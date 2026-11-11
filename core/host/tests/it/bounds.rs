//! Resource bounds and replication robustness (spec/sync.md §5: hosts cap storage; spec/wire.md
//! §11.2 Register Error 12): Hello deadline, host-wide caps, bounded sweeps,
//! retry after refusals, mutual replication.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use osis_base::BlobId;
use osis_proto::*;
use osis_proto::msg::DeleteItem;
use osis_host::{HostPolicy, HubOutput};
use osis_store::Fault;

fn live(w: &World, h: usize, l: &Label) -> Vec<BlobId> {
    LabelStore::live_ids(w.hubs[h].store(), &l.id).unwrap()
}

// spec: none (host policy): a connection without a Hello within `hello_ms` is closed
#[test]
fn hello_deadline() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy { hello_ms: 5_000, ..HostPolicy::default() });
    w.connect(h);
    let (silent, _) = w.connect_silent(h);
    assert_eq!(w.hubs[h].connections(), 2);
    w.advance(4_999);
    assert!(w.link_open(silent));
    w.advance(1);
    assert!(!w.link_open(silent));
    assert_eq!(w.hubs[h].connections(), 1);
}

// spec/wire.md §11.1 (a Hello lists at most 16 versions), spec/requirements.md (peer input never
// causes unbounded allocation): a first frame above a Hello's size is refused before its body
// arrives; partial frames over all connections stay under `max_buffered_bytes`, the connection
// holding the largest closed first.
#[test]
fn partial_frames_bounded() {
    let mut w = World::new();
    let budget = 20 << 20;
    let h = w.add_hub(HostPolicy { max_buffered_bytes: budget, ..HostPolicy::default() });
    let now = w.now();
    let hub = &mut w.hubs[h];
    // before Hello: a frame header of MAX_MESSAGE closes at once
    hub.accept(now, 1, [9; 32], osis_host::Remote::key([1; 32]));
    let out = hub.input(now, 1, (osis_base::format::MAX_MESSAGE as u32).to_be_bytes().to_vec());
    assert!(out.contains(&HubOutput::Close(1)), "{out:?}");
    assert_eq!(hub.buffered(), 0);
    // after Hello: each connection starts a MAX_MESSAGE frame and sends 8 MiB of it
    let mut closed = 0;
    for id in 10..14u64 {
        hub.accept(now, id, [9; 32], osis_host::Remote::key([id as u8; 32]));
        hub.input(now, id, encode_frame(&Hello::new(now, [2; 32]).encode()));
        let mut bytes = (osis_base::format::MAX_MESSAGE as u32).to_be_bytes().to_vec();
        bytes.extend(vec![0u8; 8 << 20]);
        let out = hub.input(now, id, bytes);
        closed += out.iter().filter(|o| matches!(o, HubOutput::Close(_))).count();
        assert!(hub.buffered() <= budget, "{} buffered", hub.buffered());
    }
    assert_eq!(closed, 2, "two of four over the budget");
}

/// A hub whose output bound is `budget`, with connections 1..=n started, their Hellos taken:
/// `Written` keeps what each was sent (for exact take reports).
fn unread_hub(w: &mut World, budget: usize, n: u64) -> (usize, Written) {
    let h = w.add_hub(HostPolicy { max_buffered_bytes: budget, ..HostPolicy::default() });
    let now = w.now();
    let hub = &mut w.hubs[h];
    let mut wr = Written::default();
    for id in 1..=n {
        wr.add(&hub.accept(now, id, [9; 32], osis_host::Remote::key([id as u8; 32])));
        wr.add(&hub.input(now, id, encode_frame(&Hello::new(now, [2; 32]).encode())));
        hub.sent(now, &[(id, wr.of(id))]);
    }
    (h, wr)
}

/// Bytes sent per connection so far.
#[derive(Default)]
struct Written(std::collections::BTreeMap<u64, u64>);

impl Written {
    fn add(&mut self, out: &[HubOutput]) {
        for o in out {
            if let HubOutput::Send(i, b) = o {
                *self.0.entry(*i).or_default() += b.len() as u64;
            }
        }
    }

    fn of(&self, id: u64) -> u64 {
        self.0.get(&id).copied().unwrap_or(0)
    }
}

/// Node sync's push of about `size` bytes (it holds output against the bound).
fn push(n: u8, size: usize) -> osis_host::Down {
    osis_host::Down::Message(Box::new(Message::Stream(Box::new(osis_proto::msg::Stream {
        events: vec![(osis_base::LabelId([1; 16]), Event::Added { blob_id: BlobId([n; 32]), blob: Some(vec![n; size]), wrap: [0; osis_crypto::WRAP_LEN], stamp: None })],
        cursor: Some(vec![n]),
        report: false,
    }))))
}

fn ping(id: u32) -> Vec<u8> {
    encode_frame(&Message::Ping { id: id as _, wall_ms: 0 }.encode())
}

/// A request whose reply allowance is `allowance` (a Fetch of nothing on an unknown label: its
/// reply is a small Error).
fn asking(id: u32, allowance: usize) -> Vec<u8> {
    encode_frame(&Message::Fetch { id: id as _, label: osis_base::LabelId([0xee; 16]), max_reply: allowance as u64, ids: vec![BlobId([1; 32])] }.encode())
}

fn closed(out: &[HubOutput]) -> Vec<u64> {
    out.iter().filter_map(|o| if let HubOutput::Close(id) = o { Some(*id) } else { None }).collect()
}

/// The ids of replies sent to connection `to`.
fn answers(out: &[HubOutput], to: u64) -> Vec<u64> {
    out.iter().filter_map(|o| if let HubOutput::Send(i, b) = o && *i == to { Message::decode(&b[4..]).ok().map(|m| m.id().into()) } else { None }).collect()
}

// spec/sync.md §10 (Served connections): a connection holding more than its share of
// `max_buffered_bytes` has its requests wait, in order, and takes no input meanwhile; readers
// that read, however slowly, all keep their connections, and each request is answered once its
// reader drained enough
#[test]
fn slow_readers_drain_their_shares() {
    let mut w = World::new();
    let mib = 1 << 20;
    let (h, mut wr) = unread_hub(&mut w, 4 * mib, 6);
    let mut now = w.now();
    let hub = &mut w.hubs[h];
    // six readers holding 2 MiB each (pushes), each asking: all wait
    let mut taken: Vec<u64> = (0..=6).map(|id| wr.of(id)).collect();
    for id in 1..=6u64 {
        wr.add(&hub.down(now, vec![(id, push(id as u8, 2 * mib - 4096))]));
    }
    for id in 1..=6u64 {
        let out = hub.input(now, id, ping(id as u32));
        wr.add(&out);
        assert!(answers(&out, id).is_empty() && hub.waits(id));
    }
    // each reads 512 KiB per report period, 6 only 64 KiB
    let mut answered = std::collections::BTreeSet::new();
    let mut rounds = 0;
    while answered.len() < 6 {
        rounds += 1;
        assert!(rounds < 100, "never answered: {answered:?}");
        let reports: Vec<(u64, u64)> = (1..=6u64).map(|id| {
            taken[id as usize] = (taken[id as usize] + (64 << 10) * if id == 6 { 1 } else { 8 }).min(wr.of(id));
            (id, taken[id as usize])
        }).collect();
        now += osis_proto::serving::PUSH_POLL_MS;
        let mut out = hub.sent(now, &reports);
        out.extend(hub.tick(now));
        wr.add(&out);
        assert!(closed(&out).is_empty(), "a reader closed: {out:?}");
        for id in 1..=6u64 {
            if answers(&out, id).contains(&id) {
                assert!(answered.insert(id));
                assert!(!hub.waits(id));
            }
        }
        assert!(hub.held() <= 4 * mib + 6 * (2 * mib), "held {}", hub.held());
    }
    assert_eq!(hub.connections(), 6);
    let resumed = hub.take_resumed();
    assert!((1..=6).all(|id| resumed.contains(&id)));
}

// spec/sync.md §10 (Served connections): fifteen readers trickling over their shares slow only
// themselves: with the bound full of their bytes, a newcomer's request is answered within one
// report period every time (the bound's room it needs is kept for it), the tricklers wait, and
// none is closed
#[test]
fn tricklers_slow_only_themselves() {
    let mut w = World::new();
    let mib = 1 << 20;
    let (h, mut wr) = unread_hub(&mut w, 15 * mib, 16);
    let mut now = w.now();
    let hub = &mut w.hubs[h];
    let mut taken: Vec<u64> = (0..=16).map(|id| wr.of(id)).collect();
    // fifteen fill the bound, each asks: over its share once the newcomer is active too
    for id in 1..=15u64 {
        wr.add(&hub.down(now, vec![(id, push(id as u8, mib - 4096))]));
    }
    for id in 1..=15u64 {
        wr.add(&hub.input(now, id, ping(id as u32)));
    }
    for round in 1..=10u32 {
        // the newcomer asks
        let out = hub.input(now, 16, ping(100 + round));
        wr.add(&out);
        let mut got = answers(&out, 16);
        // a report period: the tricklers take 16 KiB each, the newcomer all it was sent
        let mut reports: Vec<(u64, u64)> = (1..=15u64).map(|id| {
            taken[id as usize] += 16 << 10;
            (id, taken[id as usize])
        }).collect();
        reports.push((16, wr.of(16)));
        now += osis_proto::serving::PUSH_POLL_MS;
        let mut out = hub.sent(now, &reports);
        out.extend(hub.tick(now));
        wr.add(&out);
        assert!(closed(&out).is_empty(), "round {round}: {out:?}");
        if round == 1 {
            assert!((1..=15).all(|id| hub.waits(id)), "tricklers over their shares wait");
        }
        if got.is_empty() {
            got = answers(&out, 16);
        }
        assert_eq!(got, vec![u64::from(100 + round)], "round {round}: the newcomer answered within the period");
        assert!(hub.held() <= 15 * mib, "held {}", hub.held());
    }
    // drained under their shares, the tricklers are answered too
    let resumed = hub.take_resumed();
    assert!((1..=15).all(|id| resumed.contains(&id)), "{resumed:?}");
}

// spec/sync.md §10 (Served connections): a request bigger than any share waits its turn while
// the bound has no room for it: the bound's room is kept for it (another's request within its
// own share waits too), and once a report period passes, connections whose output did not move
// are closed, the one holding the most first and only until it fits; it then runs
#[test]
fn a_big_reply_waits_its_turn() {
    let mut w = World::new();
    let mib = 1 << 20;
    let (h, mut wr) = unread_hub(&mut w, 4 * mib, 3);
    let now = w.now();
    let hub = &mut w.hubs[h];
    // 1 never reads 3 MiB, 2 reads its 1 MiB slowly: the bound is full
    let t2 = wr.of(2);
    wr.add(&hub.down(now, vec![(1, push(1, 3 * mib - 8192))]));
    wr.add(&hub.down(now, vec![(2, push(2, mib - 8192))]));
    // 3 holds nothing and asks for up to 3 MiB: more than its share (4/3 MiB), more than is left
    let out = hub.input(now, 3, asking(30, 3 * mib));
    assert!(answers(&out, 3).is_empty() && hub.waits(3));
    // 2's small request, within its share, waits behind 3's need
    let out = [hub.sent(now, &[(2, t2 + (64 << 10))]), hub.input(now, 2, ping(20))].concat();
    assert!(answers(&out, 2).is_empty() && hub.waits(2));
    // within the report period nothing closes
    let half = now + osis_proto::serving::PUSH_POLL_MS / 2;
    let out = [hub.sent(half, &[(2, t2 + (128 << 10))]), hub.tick(half)].concat();
    assert!(closed(&out).is_empty());
    let at = now + osis_proto::serving::PUSH_POLL_MS;
    let out = [hub.sent(at, &[(2, t2 + (192 << 10))]), hub.tick(at)].concat();
    assert_eq!(closed(&out), vec![1], "the biggest of those not moving, and only it");
    assert_eq!(answers(&out, 3), vec![30], "3 runs once it fits");
    assert!(!hub.waits(3));
    assert!(hub.held() <= 4 * mib);
    // and 2, with the reservation gone, at its next report
    let out = hub.sent(at, &[(2, t2 + (256 << 10))]);
    assert_eq!(answers(&out, 2), vec![20]);
    assert_eq!(hub.connections(), 2);
}

// spec/sync.md §10 (Served connections): push room granted is reserved until the pushes come:
// room granted to every connection at once, each spent whole, stays within the bound
#[test]
fn granted_room_stays_within_the_bound() {
    let mut w = World::new();
    let mib = 1 << 20;
    let (h, _) = unread_hub(&mut w, 64 * mib, 10);
    let now = w.now();
    let hub = &mut w.hubs[h];
    let out = hub.down(now, (1..=10u64).map(|id| (id, osis_host::Down::WantRoom)).collect());
    let grants: Vec<(u64, usize)> = out.iter().filter_map(|o| if let HubOutput::Up(id, osis_host::Up::Room { budget }) = o { Some((*id, *budget)) } else { None }).collect();
    assert!(!grants.is_empty());
    assert!(hub.held() <= 64 * mib, "granted {}", hub.held());
    for (id, budget) in grants {
        hub.down(now, vec![(id, push(id as u8, budget.saturating_sub(1024)))]);
        assert!(hub.held() <= 64 * mib, "held {}", hub.held());
    }
}

// spec/sync.md §10 (Served connections): requests queued behind holders that never read all
// run within a report period: the stuck holders are closed until the whole queue fits, not one
// request's room a period
#[test]
fn a_queue_behind_stuck_holders_runs_at_once() {
    let mut w = World::new();
    let mib = 1 << 20;
    let (h, _) = unread_hub(&mut w, 8 * mib, 11);
    let mut now = w.now();
    let hub = &mut w.hubs[h];
    // eight never read 1 MiB each: the bound is full
    for id in 1..=8u64 {
        hub.down(now, vec![(id, push(id as u8, mib - 4096))]);
    }
    // three ask node sync for up to 1.5 MiB each (handed up, the allowance reserved until node
    // sync answers): each past its share, all queued
    let ask = |k: u32| encode_frame(&Message::Fetch { id: osis_proto::msg::NODE_IDS | k, label: osis_base::LabelId([0xee; 16]), max_reply: (3 * mib / 2) as u64, ids: vec![BlobId([1; 32])] }.encode());
    let up = |out: &[HubOutput], id: u64| out.iter().any(|o| matches!(o, HubOutput::Up(i, osis_host::Up::Message(_)) if *i == id));
    for id in 9..=11u64 {
        let out = hub.input(now, id, ask(id as u32));
        assert!(!up(&out, id) && hub.waits(id));
    }
    let mut ran = std::collections::BTreeMap::new();
    for p in 1..=3u32 {
        now += osis_proto::serving::PUSH_POLL_MS;
        let out = hub.tick(now);
        eprintln!("p{p} held {} conns {} closes {:?} waits {:?}", hub.held(), hub.connections(), closed(&out), (9..=11).map(|i| hub.waits(i)).collect::<Vec<_>>());
        for id in 9..=11u64 {
            if up(&out, id) {
                ran.insert(id, p);
            }
        }
        assert!(hub.held() <= 8 * mib);
    }
    assert_eq!(ran, (9..=11u64).map(|id| (id, 1)).collect(), "all in the first period");
    assert!(hub.connections() >= 11 - 5, "closed only what the queue needs");
}

// spec/sync.md §6 (Stall), §10 (Served connections): a request waiting for the bound's room
// while every holder drains slowly runs before its peer's stall time: once it has waited half of
// it, the biggest holders are closed, moving or not, until it fits; not before
#[test]
fn a_waiting_request_runs_within_half_the_stall_time() {
    let mut w = World::new();
    let mib = 1 << 20;
    let (h, mut wr) = unread_hub(&mut w, 4 * mib, 5);
    let mut now = w.now();
    let hub = &mut w.hubs[h];
    let mut taken: Vec<u64> = (0..=5).map(|id| wr.of(id)).collect();
    for id in 1..=4u64 {
        wr.add(&hub.down(now, vec![(id, push(id as u8, mib - 4096))]));
    }
    // 5 asks for more than the four drain in half the stall time at 16 KiB a period each
    let out = hub.input(now, 5, asking(50, 3 * mib + 4 * mib / 5));
    assert!(answers(&out, 5).is_empty() && hub.waits(5));
    let periods = osis_proto::client::STALL_TIMEOUT_MS / 2 / osis_proto::serving::PUSH_POLL_MS;
    let mut ran = None;
    for p in 1..=periods + 1 {
        let reports: Vec<(u64, u64)> = (1..=4u64).map(|id| {
            taken[id as usize] += 16 << 10;
            (id, taken[id as usize])
        }).collect();
        now += osis_proto::serving::PUSH_POLL_MS;
        let mut out = hub.sent(now, &reports);
        out.extend(hub.tick(now));
        let gone = closed(&out);
        if answers(&out, 5) == vec![50] {
            ran = Some(p);
            assert!(!gone.is_empty(), "made room by closing");
            break;
        }
        assert!(gone.is_empty(), "period {p}: closed before half the stall time: {gone:?}");
        assert!(hub.held() <= 4 * mib);
    }
    assert_eq!(ran, Some(periods), "runs at half the stall time");
}

// spec/sync.md §10 (Served connections): while a request waits for the bound's room, only
// output that does not move is closed for it: a connection holding only a reservation for a reply
// to come (a request node sync answers later) has no bytes to move and stays
#[test]
fn a_reservation_is_not_output_that_stalls() {
    let mut w = World::new();
    let kib = 1 << 10;
    let (h, _) = unread_hub(&mut w, 1 << 20, 3);
    let mut now = w.now();
    let hub = &mut w.hubs[h];
    let ask = Message::Fetch { id: osis_proto::msg::NODE_IDS | 1, label: osis_base::LabelId([0xee; 16]), max_reply: 600 << 10, ids: vec![BlobId([1; 32])] };
    let out = hub.input(now, 1, encode_frame(&ask.encode()));
    assert!(out.iter().any(|o| matches!(o, HubOutput::Up(1, _))), "handed up");
    hub.down(now, vec![(2, push(2, 300 * kib))]);
    let out = hub.input(now, 3, asking(30, 400 * kib));
    assert!(answers(&out, 3).is_empty() && hub.waits(3));
    now += osis_proto::serving::PUSH_POLL_MS;
    let out = [hub.sent(now, &[]), hub.tick(now)].concat();
    assert_eq!(closed(&out), vec![2]);
    assert_eq!(answers(&out, 3), vec![30]);
}

// spec/sync.md §10 (Served connections): shares follow the active connections: one over a
// smaller share, after another becomes active, just waits (nobody is closed) and is answered
// as it drains
#[test]
fn shares_follow_the_active() {
    let mut w = World::new();
    let mib = 1 << 20;
    let (h, mut wr) = unread_hub(&mut w, 4 * mib, 2);
    let now = w.now();
    let hub = &mut w.hubs[h];
    let t1 = wr.of(1);
    // 1 holds 1.5 MiB alone: its share is the whole bound, its Ping is answered
    wr.add(&hub.down(now, vec![(1, push(1, 3 * mib / 2))]));
    let out = hub.input(now, 1, ping(1));
    wr.add(&out);
    assert_eq!(answers(&out, 1), vec![1]);
    // 2 and 3 hold something: shares of 4/3 MiB, 1's next Ping waits
    wr.add(&hub.down(now, vec![(2, push(2, 4096))]));
    hub.accept(now, 3, [9; 32], osis_host::Remote::key([3; 32]));
    hub.input(now, 3, encode_frame(&Hello::new(now, [2; 32]).encode()));
    let out = [hub.sent(now, &[(3, 0)]), hub.input(now, 1, ping(2))].concat();
    assert!(closed(&out).is_empty());
    assert!(answers(&out, 1).is_empty() && hub.waits(1));
    // 3 leaves: 1's share grows, it is answered at its next report
    assert!(closed(&hub.closed(3)).is_empty());
    let out = hub.sent(now, &[(1, t1 + 4096)]);
    assert_eq!(answers(&out, 1), vec![2]);
    assert!(!hub.waits(1));
}

// spec/requirements.md (peer input never causes unbounded work): a message's entries reach disk
// in one store commit, not one per entry: at most three durable writes (rows, root, cleanup when
// it shreds: a removal, or a table page split) for 1024 uploads or 1024 deletes
#[test]
fn one_commit_per_message() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy::default());
    let c = w.connect(h);
    let l = Label::new(3);
    w.setup(c, &l);
    let before = w.faults[h].writes();
    let ev = w.run(c, Command::Upload { label: l.id, entries: (0..1024).map(|n| l.entry(blob(n))).collect() });
    assert_eq!(statuses(&ev), vec![Code::OK; 1024]);
    assert!(w.faults[h].writes() - before <= 3, "{} durable writes of an upload", w.faults[h].writes() - before);
    assert_eq!(live(&w, h, &l).len(), 1024);
    let before = w.faults[h].writes();
    let key = l.head_keys().delete.clone();
    let items = (0..1024).map(|n| DeleteItem::sign(&key, &l.id, osis_label::blob_id(&blob(n))).unwrap()).collect();
    assert_eq!(statuses(&w.run(c, Command::Delete { label: l.id, items })), vec![Code::OK; 1024]);
    assert!(w.faults[h].writes() - before <= 3, "{} durable writes of a delete", w.faults[h].writes() - before);
    assert!(live(&w, h, &l).is_empty());
}

// spec/requirements.md (durability): nothing is acknowledged or pushed before its input's commit:
// when the commit fails, the uploader gets no status and the subscriber no push, both are
// closed, nothing of it is kept, and the uploader's retry is taken once writes work again. A
// delete's shredding commit failing at any of its writes (rows, root, cleanup) acknowledges
// nothing either, and leaves its entries all deleted or all live
#[test]
fn failed_commit_sends_nothing() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy::default());
    // client index = link index
    let (a, c) = (w.connect(h), w.connect(h));
    let l = Label::new(3);
    w.setup(a, &l);
    w.open(c, &l);
    w.run(c, Command::Subscribe { labels: vec![l.id] });
    w.take(c);
    w.faults[h].at(0, Fault::Fail);
    let ev = w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(blob(1))] });
    assert!(statuses(&ev).is_empty(), "{ev:?}");
    assert!(events_of(&w.take(c)).0.is_empty());
    assert!(!w.link_open(a) && !w.link_open(c));
    assert!(live(&w, h, &l).is_empty(), "the failed commit was rolled back");
    let a2 = w.connect(h);
    w.open(a2, &l);
    assert_eq!(statuses(&w.run(a2, Command::Upload { label: l.id, entries: vec![l.entry(blob(1))] })), vec![Code::OK]);
    assert_eq!(live(&w, h, &l), vec![osis_label::blob_id(&blob(1))]);
    let key = l.head_keys().delete.clone();
    for (n, at) in (10u64..).step_by(2).zip(0..3) {
        let ids = [osis_label::blob_id(&blob(n)), osis_label::blob_id(&blob(n + 1))];
        let a = w.connect(h);
        w.open(a, &l);
        assert_eq!(statuses(&w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(blob(n)), l.entry(blob(n + 1))] })), vec![Code::OK; 2]);
        w.faults[h].at(at, Fault::Fail);
        let items = ids.iter().map(|id| DeleteItem::sign(&key, &l.id, *id).unwrap()).collect();
        let ev = w.run(a, Command::Delete { label: l.id, items });
        assert!(statuses(&ev).is_empty(), "write {at}: {ev:?}");
        assert!(!w.link_open(a));
        let held = live(&w, h, &l).iter().filter(|id| ids.contains(id)).count();
        // the rows and the root are the commit point: the cleanup's failure comes after it
        assert_eq!(held, if at < 2 { 2 } else { 0 }, "write {at}");
    }
    let a3 = w.connect(h);
    w.open(a3, &l);
    assert_eq!(statuses(&w.run(a3, Command::Upload { label: l.id, entries: vec![l.entry(blob(2))] })), vec![Code::OK]);
}

// spec/wire.md §11.2 Register, spec/sync.md §5: host-wide caps refuse new labels (Error 12) and new entries (code 12)
#[test]
fn host_wide_caps() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy { max_labels: 2, max_entries: 3, ..HostPolicy::default() });
    let c = w.connect(h);
    let (l1, l2, l3) = (Label::new(3), Label::new(4), Label::new(5));
    w.setup(c, &l1);
    w.setup(c, &l2);
    let ev = w.run(c, l3.register_cmd(0));
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::STORAGE_CAP, .. }]), "{ev:?}");
    let ev = w.run(c, Command::Upload { label: l1.id, entries: (0..2).map(|n| l1.entry(blob(n))).collect() });
    assert_eq!(statuses(&ev), vec![Code::OK; 2]);
    let ev = w.run(c, Command::Upload { label: l2.id, entries: (2..4).map(|n| l2.entry(blob(n))).collect() });
    assert_eq!(statuses(&ev), vec![Code::OK, Code::STORAGE_CAP]);
    assert_eq!(w.hubs[h].store().totals().unwrap().entries, 3);
}

// spec/sync.md §5 Expiry: sweeps run in bounded steps; the hub asks for another tick at once while work remains
#[test]
fn sweeps_are_bounded() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy::default());
    let c = w.connect(h);
    let l = Label::new(3);
    w.setup(c, &l);
    let t = w.now() + 1_000;
    w.run(c, Command::Upload { label: l.id, entries: (0..2500).map(|n| l.entry(blob_with(n, t, vec![]))).collect() });
    w.clock.advance(1_000);
    let now = w.now();
    w.hubs[h].tick(now);
    assert_eq!(live(&w, h, &l).len(), 2500 - 1024);
    assert_eq!(w.hubs[h].next_due(now), Some(now));
    w.settle();
    assert!(live(&w, h, &l).is_empty());
    assert_eq!(w.hubs[h].store().totals().unwrap().entries, 0);
}

// spec/sync.md §5: a replication batch refused for now (code 12) does not advance the position; the label is retried and converges once the peer has room
#[test]
fn replication_retries_after_refusal() {
    let mut w = World::new();
    let (s1, s2) = (w.add_hub(HostPolicy::default()), w.add_hub(HostPolicy { cap_entries: 3, ..HostPolicy::default() }));
    let a = w.connect(s1);
    let l = Label::new(3);
    w.setup(a, &l);
    w.run(a, Command::Upload { label: l.id, entries: (0..5).map(|n| l.entry(blob(n))).collect() });
    w.peer(s1, s2);
    assert_eq!(live(&w, s2, &l).len(), 3);
    let head = LabelStore::log_head(w.hubs[s1].store(), &l.id).unwrap();
    let pos = w.hubs[s1].store().replica_pos(&hub_key(s2), &l.id).unwrap();
    assert!(pos.is_none_or(|p| p.1 < head.1), "{pos:?}");
    assert!(w.diagnostics.iter().any(|d| d.contains("retrying")), "{:?}", w.diagnostics);
    // a retry while the peer is still full changes nothing
    w.advance(1_000);
    assert_eq!(live(&w, s2, &l).len(), 3);
    w.restart(s2, HostPolicy::default());
    w.peer(s1, s2);
    assert_eq!(live(&w, s2, &l), sorted((0..5).map(bid).collect()));
    assert_eq!(w.hubs[s1].store().replica_pos(&hub_key(s2), &l.id).unwrap(), Some(head));
}

// spec/sync.md §5: two hosts replicating to each other converge without sending entries back; one entry with two wraps settles
#[test]
fn mutual_replication_settles() {
    let mut w = World::new();
    let (s1, s2) = (w.add_hub(HostPolicy::default()), w.add_hub(HostPolicy::default()));
    let (a, b) = (w.connect(s1), w.connect(s2));
    let l = Label::new(3);
    w.setup(a, &l);
    w.setup(b, &l);
    let x = blob(100);
    let e1 = l.entry(x.clone());
    let mut e2 = e1.clone();
    e2.wrap = [0x77; osis_crypto::WRAP_LEN];
    e2.stamp = osis_label::sign_stamp(&l.head_keys().write, &l.id, &osis_label::blob_id(&x), &e2.wrap);
    w.peer(s1, s2);
    w.peer(s2, s1);
    // both wraps arrive at once, each at one side
    w.send(a, Command::Upload { label: l.id, entries: vec![e1] });
    w.send(b, Command::Upload { label: l.id, entries: vec![e2] });
    w.pump();
    w.settle();
    w.run(a, Command::Upload { label: l.id, entries: (0..10).map(|n| l.entry(blob(n))).collect() });
    let heads = |w: &World| [s1, s2].map(|h| LabelStore::log_head(w.hubs[h].store(), &l.id).unwrap().1);
    let settled = heads(&w);
    // genesis and 11 adds: the side holding one wrap keeps it
    assert!(settled.iter().all(|h| *h == 12), "{settled:?}");
    assert_eq!(live(&w, s1, &l), live(&w, s2, &l));
    w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(blob(50))] });
    let after = heads(&w);
    assert_eq!(after, [settled[0] + 1, settled[1] + 1], "one add each, no echo");
    assert!(w.diagnostics.is_empty(), "{:?}", w.diagnostics);
}

/// An Upload of one `size`-byte entry, its id in the node's range when `node`.
fn upload(node: bool, size: usize) -> Vec<u8> {
    let id = if node { osis_proto::msg::NODE_IDS | 7 } else { 7 };
    encode_frame(&Message::Upload { id, label: osis_base::LabelId([1; 16]), entries: vec![osis_proto::msg::Entry { blob: vec![1; size], wrap: [0; osis_crypto::WRAP_LEN], stamp: osis_crypto::Signature([0; 64]), replaces: vec![] }] }.encode())
}

// spec/sync.md §10 (Served connections): received frames count against the input bound until
// they run or are answered: frames waiting for output room, and requests handed up to node sync
// (whose reply allowance alone counts against the output bound); past it the connection holding
// the most is closed
#[test]
fn received_frames_stay_within_the_bound() {
    let mut w = World::new();
    let mib = 1 << 20;
    let (h, _) = unread_hub(&mut w, mib, 9);
    let now = w.now();
    let hub = &mut w.hubs[h];
    // the output bound full: each frame waits for room
    hub.down(now, vec![(1, push(1, mib - 4096))]);
    let mut gone = 0;
    for id in 2..=9u64 {
        gone += closed(&hub.input(now, id, upload(false, 600 << 10))).len();
        assert!(hub.buffered() <= mib, "{} buffered", hub.buffered());
    }
    assert_eq!(gone, 7, "one waiting frame fits");
    // handed up: the frame is input held until node sync answers
    let (h, _) = unread_hub(&mut w, mib, 2);
    let hub = &mut w.hubs[h];
    let out = hub.input(now, 1, upload(true, 600 << 10));
    assert!(closed(&out).is_empty() && out.iter().any(|o| matches!(o, HubOutput::Up(1, _))));
    assert!(hub.buffered() > 600 << 10 && hub.held() <= mib);
    assert_eq!(closed(&hub.input(now, 2, upload(true, 600 << 10))).len(), 1);
    assert!(hub.buffered() <= mib && hub.held() <= mib);
}
