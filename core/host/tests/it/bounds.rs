//! Resource bounds (spec/sync.md §5: hosts cap storage; spec/wire.md §11.2 Register Error 12;
//! §10 Served connections): Hello deadline, output and input bounds, one commit per message,
//! host-wide caps, bounded sweeps.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use osis_base::BlobId;
use osis_proto::*;
use osis_proto::msg::DeleteItem;
use osis_host::{HostPolicy, HubOutput};
use osis_store::Fault;

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
        seq: 0,
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
        now += osis_proto::session::PUSH_POLL_MS;
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
        now += osis_proto::session::PUSH_POLL_MS;
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
    let half = now + osis_proto::session::PUSH_POLL_MS / 2;
    let out = [hub.sent(half, &[(2, t2 + (128 << 10))]), hub.tick(half)].concat();
    assert!(closed(&out).is_empty());
    let at = now + osis_proto::session::PUSH_POLL_MS;
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
        now += osis_proto::session::PUSH_POLL_MS;
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
    let periods = osis_proto::window::STALL_TIMEOUT_MS / 2 / osis_proto::session::PUSH_POLL_MS;
    let mut ran = None;
    for p in 1..=periods + 1 {
        let reports: Vec<(u64, u64)> = (1..=4u64).map(|id| {
            taken[id as usize] += 16 << 10;
            (id, taken[id as usize])
        }).collect();
        now += osis_proto::session::PUSH_POLL_MS;
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
    now += osis_proto::session::PUSH_POLL_MS;
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

// spec/requirements.md (peer input never causes unbounded work): a message's items reach disk in
// one store commit, not one per item: at most three durable writes (rows, root, cleanup when it
// shreds) for 1024 deletes
#[test]
fn one_commit_per_message() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy::default());
    let c = w.connect(h);
    let l = Label::new(3);
    w.setup(c, &l);
    assert_eq!(pull_all(&w, h, &l, 0..1024), vec![Code::OK; 1024]);
    let before = w.faults[h].writes();
    let key = l.head_keys().delete.clone();
    let items = (0..1024).map(|n| DeleteItem::sign(&key, &l.id, osis_label::blob_id(&blob(n)))).collect();
    assert_eq!(statuses(&w.run(c, |id| Message::Delete { id, label: l.id, items })), vec![Code::OK; 1024]);
    assert!(w.faults[h].writes() - before <= 3, "{} durable writes of a delete", w.faults[h].writes() - before);
    assert!(live(&w, h, &l).is_empty());
}

// spec/requirements.md (durability): nothing is acknowledged before its input's commit: a
// delete's shredding commit failing at its rows or root write acknowledges nothing, closes the
// connection and leaves its entries live; failing at the cleanup after its commit point (the
// root) it landed, so it is acknowledged and its entries are gone; a delete is taken after either
#[test]
fn failed_commit_sends_nothing() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy::default());
    let a = w.connect(h);
    let l = Label::new(3);
    w.setup(a, &l);
    let key = l.head_keys().delete.clone();
    for (n, at) in (10u64..).step_by(2).zip(0..3) {
        let ids = [osis_label::blob_id(&blob(n)), osis_label::blob_id(&blob(n + 1))];
        assert_eq!(pull_all(&w, h, &l, [n, n + 1]), vec![Code::OK; 2]);
        // client index = link index
        let a = w.connect(h);
        w.open(a, &l);
        w.faults[h].at(at, Fault::Fail);
        let items = ids.iter().map(|id| DeleteItem::sign(&key, &l.id, *id)).collect();
        let ev = w.run(a, |id| Message::Delete { id, label: l.id, items });
        let landed = at == 2;
        assert_eq!(statuses(&ev), if landed { vec![Code::OK; 2] } else { vec![] }, "write {at}: {ev:?}");
        assert_eq!(w.link_open(a), landed, "write {at}");
        let held = live(&w, h, &l).iter().filter(|id| ids.contains(id)).count();
        assert_eq!(held, if landed { 0 } else { 2 }, "write {at}");
    }
    let a3 = w.connect(h);
    w.open(a3, &l);
    let item = DeleteItem::sign(&key, &l.id, osis_label::blob_id(&blob(10)));
    assert_eq!(statuses(&w.run(a3, |id| Message::Delete { id, label: l.id, items: vec![item] })), vec![Code::OK]);
    assert!(!live(&w, h, &l).contains(&osis_label::blob_id(&blob(10))));
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
    let ev = w.run(c, |id| l3.register(id, 0));
    assert!(matches!(&ev[..], [Message::Error { code: Code::STORAGE_CAP, .. }]), "{ev:?}");
    assert_eq!(pull_all(&w, h, &l1, 0..2), vec![Code::OK; 2]);
    assert_eq!(pull_all(&w, h, &l2, 2..4), vec![Code::OK, Code::STORAGE_CAP]);
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
    for n in 0..2500 {
        assert_eq!(pull(&w, h, &l, &l.entry(blob_with(n, t, vec![]))), Code::OK);
    }
    w.clock.advance(1_000);
    let now = w.now();
    w.hubs[h].tick(now);
    assert_eq!(live(&w, h, &l).len(), 2500 - 1024);
    assert_eq!(w.hubs[h].next_due(now), Some(now));
    w.settle();
    assert!(live(&w, h, &l).is_empty());
    assert_eq!(w.hubs[h].store().totals().unwrap().entries, 0);
}

/// A request of about `size` bytes: an Offer of one Deposit item when `node` (handed up to node
/// sync), else a client-port Call (answered by the session: no Auth yet).
fn big_request(node: bool, size: usize) -> Vec<u8> {
    let msg = if node {
        let item = osis_proto::msg::OfferItem::Deposit { label: osis_base::LabelId([1; 16]), blob: vec![1; size], wrap: [0; osis_crypto::WRAP_LEN], sig: osis_crypto::Signature([0; 64]) };
        Message::Offer { id: osis_proto::msg::NODE_IDS | 7, items: vec![item] }
    } else {
        Message::Call { id: 7, max_reply: osis_proto::window::SMALL_REPLY as u64, method: 0, args: vec![osis_base::Value::bytes(&vec![1; size])] }
    };
    encode_frame(&msg.encode())
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
        gone += closed(&hub.input(now, id, big_request(false, 600 << 10))).len();
        assert!(hub.buffered() <= mib, "{} buffered", hub.buffered());
    }
    assert_eq!(gone, 7, "one waiting frame fits");
    // handed up: the frame is input held until node sync answers
    let (h, _) = unread_hub(&mut w, mib, 2);
    let hub = &mut w.hubs[h];
    let out = hub.input(now, 1, big_request(true, 600 << 10));
    assert!(closed(&out).is_empty() && out.iter().any(|o| matches!(o, HubOutput::Up(1, _))), "{out:?}");
    assert!(hub.buffered() > 600 << 10 && hub.held() <= mib);
    assert_eq!(closed(&hub.input(now, 2, big_request(true, 600 << 10))).len(), 1);
    assert!(hub.buffered() <= mib && hub.held() <= mib);
}

// spec/sync.md §5 Role entries: a stamped role entry is taken past the label's and the host's
// caps with no bound of its own; a deposited one is outside the caps too, within the deposit
// budget; a plain entry still meets the cap
#[test]
fn role_entries_outside_the_caps_spec_sync_5() {
    use osis_base::{ManualClock, WallMs};
    use osis_crypto::{SeededRng, Signature};
    use osis_proto::msg::WRAP_LEN;
    let store = osis_store::Store::open_or_create(Box::new(osis_store::MemoryBackend::new()), Box::new(osis_store::MemoryRoot::new()), osis_store::StoreConfig::default(), &mut SeededRng::from_seed([1; 32])).unwrap();
    let clock = std::sync::Arc::new(ManualClock::new(WallMs(T0)));
    let policy = HostPolicy { cap_entries: 1, max_entries: 2, ..HostPolicy::unlimited() };
    let mut s = osis_host::HostStore::open(store, clock, policy, Box::new(SeededRng::from_seed([2; 32]))).unwrap();
    let f = osis_proto::examples::Fixture::new(0x10);
    s.push_step(&f.label, f.genesis.clone(), Some(f.genesis_claims.clone())).unwrap();
    let mut put = |n: u64, stamped: bool, role: bool| {
        let b = blob(n);
        let p = Put { blob_id: osis_label::blob_id(&b), blob: &b, wrap: [0; WRAP_LEN], stamp: stamped.then_some(Signature([1; 64])), expiry: None, ephemeral: false, now: T0, role };
        s.put(&f.label, p).unwrap()
    };
    let budget = 64 + 4 * f.genesis_claims.claims.len() as u64;
    for n in 0..3 * budget {
        assert_eq!(put(n, true, true), Code::OK, "stamped role entry {n}");
    }
    assert_eq!(put(10_000, true, false), Code::OK, "a plain entry within the cap");
    assert_eq!(put(10_001, true, false), Code::STORAGE_CAP);
    for n in 0..budget {
        assert_eq!(put(20_000 + n, false, true), Code::OK, "deposited role entry {n}");
    }
    assert_eq!(put(30_000, false, true), Code::BUDGET_FULL);
}
