//! A client against a server over a throttled link with the drivers' send queues (spec/sync.md
//! §6: the request window, held pushes and the stall timeout): bulk uploads, fetches and pushes
//! on a slow link finish on one connection, and neither side's queue outgrows `WINDOW_QUEUE`
//! (`SEND_QUEUE` with pushes).

use osis_proto::client::{STALL_TIMEOUT_MS, WINDOW, WINDOW_QUEUE};
use osis_proto::server::SEND_QUEUE;
use osis_proto::examples::{Label, blob_sized};
use osis_proto::*;
use std::collections::VecDeque;

const T0: u64 = 1_700_000_000_000;

/// One direction: the driver's queue (refused past `cap` as `LinkTx::send` does, which closes the
/// connection), drained at the link's rate.
struct Pipe {
    q: VecDeque<Vec<u8>>,
    queued: usize,
    max: usize,
    cap: usize,
    /// Bytes taken so far (`LinkTx::taken`).
    taken: u64,
}

impl Pipe {
    fn new(cap: usize) -> Pipe {
        Pipe { q: VecDeque::new(), queued: 0, max: 0, cap, taken: 0 }
    }

    fn push(&mut self, b: Vec<u8>, side: &str) {
        assert!(self.queued == 0 || self.queued + b.len() <= self.cap, "{side}: {} bytes queued, closed as slow", self.queued + b.len());
        self.queued += b.len();
        self.max = self.max.max(self.queued);
        self.q.push_back(b);
    }

    fn take(&mut self, mut n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        while n > 0 {
            let Some(front) = self.q.front_mut() else { break };
            let k = n.min(front.len());
            out.extend(front.drain(..k));
            if front.is_empty() {
                self.q.pop_front();
            }
            n -= k;
        }
        self.queued -= out.len();
        self.taken += out.len() as u64;
        out
    }
}

struct Run {
    now: u64,
    client: ClientSession,
    server: ServerConnection,
    store: MemoryLabelStore,
    up: Pipe,
    down: Pipe,
    timer: Option<u64>,
    events: Vec<ClientEvent>,
}

impl Run {
    fn new() -> Run {
        let mut r = Run {
            now: T0,
            client: ClientSession::new(ClientConfig { peer_static_key: [0x5e; 32], challenge: [0x80; 32] }),
            server: ServerConnection::new(ServerConfig { static_key: [0x5e; 32], challenge: [0x40; 32] }),
            store: MemoryLabelStore::new([9; 32]),
            // the node's `MAX_QUEUED` and the server's default `max_queued_bytes`
            up: Pipe::new(64 << 20),
            down: Pipe::new(48 << 20),
            timer: None,
            events: Vec::new(),
        };
        let so = r.server.handle(T0, &mut r.store, ServerInput::Start);
        r.server_out(so);
        r.input(ClientInput::Start);
        r
    }

    fn input(&mut self, i: ClientInput) {
        for o in self.client.handle(self.now, i) {
            match o {
                ClientOutput::Send(b) => self.up.push(b, "client"),
                ClientOutput::Event(e) => self.events.push(e),
                ClientOutput::SetTimer(t) => self.timer = Some(t),
                ClientOutput::Close => panic!("client closed the session at {} s: {:?}", (self.now - T0) / 1000, self.events.last()),
            }
        }
    }

    fn server_out(&mut self, out: Vec<ServerOutput>) {
        for o in out {
            match o {
                ServerOutput::Send(b) => self.down.push(b, "server"),
                ServerOutput::Close => panic!("server closed"),
                ServerOutput::StoreError(e) => panic!("{e}"),
                ServerOutput::Changed(_) | ServerOutput::Relay(_) | ServerOutput::PeerError(_) => {}
            }
        }
    }

    /// Steps the link (`rate` bytes per direction per `step_ms`) until nothing is outstanding.
    fn settle(&mut self, rate: usize, step_ms: u64) {
        while self.client.outstanding() > 0 || self.up.queued > 0 || self.down.queued > 0 || self.server.held() {
            self.now += step_ms;
            let b = self.up.take(rate);
            if !b.is_empty() {
                self.input(ClientInput::Sent);
                let so = self.server.handle(self.now, &mut self.store, ServerInput::Bytes(b));
                self.server_out(so);
            }
            let b = self.down.take(rate);
            if !b.is_empty() {
                // the driver reports what the transport took (before input and at ticks)
                let so = self.server.handle(self.now, &mut self.store, ServerInput::Taken(self.down.taken));
                self.server_out(so);
                self.input(ClientInput::Bytes(b));
            }
            if self.timer.is_some_and(|t| t <= self.now) {
                self.timer = None;
                self.input(ClientInput::Timer);
            }
            assert!(self.now - T0 < 1 << 40, "no end");
        }
    }

    fn command(&mut self, c: Command, rate: usize, step_ms: u64) -> Vec<ClientEvent> {
        self.input(ClientInput::Command(c));
        self.settle(rate, step_ms);
        std::mem::take(&mut self.events)
    }
}

/// Uploads `n` blobs of `size` bytes over the link, fetches them back, all on one session.
fn round_trip(n: u64, size: usize, rate: usize, step_ms: u64) -> Run {
    let mut r = Run::new();
    let l = Label::new(1);
    r.settle(rate, step_ms);
    r.command(Command::Register { label: l.id, step: l.steps[0].clone(), claim_set: Some(l.sets[0].clone()) }, rate, step_ms);
    let ev = r.command(Command::Open { label: l.id, key: OpenKey::Sync(l.head_keys().sync.clone()) }, rate, step_ms);
    assert!(ev.iter().any(|e| matches!(e, ClientEvent::Opened { .. })), "{ev:?}");
    let entries: Vec<Entry> = (0..n).map(|i| l.entry(blob_sized(i, 0, vec![], size))).collect();
    let ids: Vec<_> = entries.iter().map(|e| osis_label::blob_id(&e.blob)).collect();
    let started = r.now;
    let ev = r.command(Command::Upload { label: l.id, entries }, rate, step_ms);
    let codes: Vec<Code> = ev.iter().flat_map(|e| if let ClientEvent::EntryStatus { codes, .. } = e { codes.clone() } else { vec![] }).collect();
    assert_eq!(codes, vec![Code::OK; n as usize], "{ev:?}");
    assert!(r.now - started > 2 * STALL_TIMEOUT_MS, "the upload took longer than the stall timeout");
    let ev = r.command(Command::Fetch { label: l.id, ids: ids.clone() }, rate, step_ms);
    let got: Vec<_> = ev.iter().flat_map(|e| if let ClientEvent::Fetched { items, .. } = e { items.iter().filter(|f| f.entry.is_some()).map(|f| f.blob_id).collect() } else { vec![] }).collect();
    assert_eq!(got, ids);
    r
}

// spec/sync.md §6 (flow control): 72 MiB up and back at 64 KB/s (each way about 20 minutes, more than the old
// queue caps and with replies minutes apart) on one session; queues stay within the window
#[test]
fn bulk_over_slow_link_spec_sync_6() {
    let r = round_trip(18, 4 << 20, 6_400, 100);
    assert!(r.up.max <= WINDOW_QUEUE && r.down.max <= WINDOW_QUEUE, "{} {}", r.up.max, r.down.max);
    assert!(r.up.max > WINDOW / 2, "the window was used: {}", r.up.max);
}

// spec/sync.md §6: at 1 KB/s one request takes over a quarter of an hour; progress keeps the
// session up
#[test]
fn crawling_link_spec_sync_6() {
    round_trip(2, 1 << 20, 1_000, 1_000);
}

// spec/sync.md §6: requests beyond the window wait for answers; one always goes
#[test]
fn window_holds_requests_back_spec_sync_6() {
    let mut c = ClientSession::new(ClientConfig { peer_static_key: [1; 32], challenge: [2; 32] });
    c.handle(T0, ClientInput::Start);
    c.handle(T0, ClientInput::Bytes(encode_frame(&Hello::new(T0, [3; 32]).encode())));
    let l = Label::new(1);
    let sent = |out: &[ClientOutput]| out.iter().filter_map(|o| if let ClientOutput::Send(f) = o { Message::decode(&f[4..]).ok() } else { None }).collect::<Vec<_>>();
    // each Fetch may bring back a whole message
    let ids: Vec<_> = (0..1024 * 4u32).map(|i| osis_label::blob_id(&i.to_le_bytes())).collect();
    let out = c.handle(T0, ClientInput::Command(Command::Fetch { label: l.id, ids }));
    let first = sent(&out);
    assert_eq!(first.len(), 2, "two fetches fit the window (after the pings)");
    assert_eq!(c.unsent(), 2);
    assert!(c.in_flight() >= WINDOW);
    let Message::Fetch { id, .. } = first[0] else { panic!() };
    let out = c.handle(T0, ClientInput::Bytes(encode_frame(&Message::FetchReply { id, items: vec![] }.encode())));
    assert_eq!(sent(&out).len(), 1, "an answer makes room for the next");
    assert_eq!(c.unsent(), 1);
}

// spec/sync.md §6 (flow control): writers fill a label far faster than its subscriber's 640 KB/s
// link; the server holds the pushes (continued from the subscription's position as the queue
// drains, relay-only entries dropped meanwhile), so the queue stays within `SEND_QUEUE` and every
// entry arrives by push on one connection (without `Taken` the first push overflows the cap)
#[test]
fn pushes_to_slow_subscriber_spec_sync_6() {
    let (rate, step_ms) = (64_000, 100);
    let mut r = Run::new();
    let l = Label::new(1);
    r.settle(rate, step_ms);
    r.command(Command::Register { label: l.id, step: l.steps[0].clone(), claim_set: Some(l.sets[0].clone()) }, rate, step_ms);
    r.command(Command::Open { label: l.id, key: OpenKey::Sync(l.head_keys().sync.clone()) }, rate, step_ms);
    r.command(Command::Sync { label: l.id, cursor: None, inline_limit: 8 << 20, entries: vec![], gained: vec![] }, rate, step_ms);
    r.command(Command::Subscribe { labels: vec![l.id] }, rate, step_ms);
    // another connection uploads 72 MiB at once
    let mut w = ServerConnection::new(ServerConfig { static_key: [0x5e; 32], challenge: [0x41; 32] });
    w.handle(r.now, &mut r.store, ServerInput::Start);
    w.handle(r.now, &mut r.store, ServerInput::Bytes(encode_frame(&Hello::new(r.now, [7; 32]).encode())));
    let mut ids = Vec::new();
    for b in 0..9u32 {
        let entries: Vec<Entry> = (0..2).map(|i| l.entry(blob_sized(u64::from(b * 2 + i), 0, vec![], 4 << 20))).collect();
        ids.extend(entries.iter().map(|e| osis_label::blob_id(&e.blob)));
        let out = w.handle(r.now, &mut r.store, ServerInput::Bytes(encode_frame(&Message::Upload { id: b + 1, label: l.id, entries }.encode())));
        assert!(out.contains(&ServerOutput::Changed(l.id)));
        let so = r.server.handle(r.now, &mut r.store, ServerInput::Changed(l.id));
        r.server_out(so);
    }
    assert!(r.server.held());
    // 8 MiB of pushes are unwritten: room for a small relay, not for one of 1 MiB
    let relay = |n: usize| {
        let e = l.entry(vec![1; n]);
        ServerInput::Relay(Relayed { label: l.id, blob_id: osis_label::blob_id(&e.blob), blob: e.blob, wrap: e.wrap, stamp: e.stamp })
    };
    assert!(r.server.handle(r.now, &mut r.store, relay(1 << 20)).is_empty(), "no room: the relay is dropped");
    let so = r.server.handle(r.now, &mut r.store, relay(100));
    assert_eq!(so.len(), 1);
    r.server_out(so);
    r.settle(rate, step_ms);
    let got: Vec<_> = r
        .events
        .iter()
        .flat_map(|e| if let ClientEvent::Events { events, .. } = e { events.clone() } else { vec![] })
        .filter_map(|e| if let Event::Added { blob_id, blob: Some(b), .. } = e { (b.len() > 100).then_some(blob_id) } else { None })
        .collect();
    assert_eq!(got, ids);
    assert!(r.down.max <= SEND_QUEUE, "{}", r.down.max);
}

// spec/sync.md §6: a request is unanswered while it waits for room in the window, however long
// (the node's resend timer asks this, not the time it was given)
#[test]
fn held_back_requests_count_unanswered_spec_sync_6() {
    let mut c = ClientSession::new(ClientConfig { peer_static_key: [1; 32], challenge: [2; 32] });
    c.handle(T0, ClientInput::Start);
    let l = Label::new(1);
    // given before the Hellos
    c.handle(T0, ClientInput::Command(Command::Fetch { label: l.id, ids: vec![osis_label::blob_id(b"a")] }));
    let first = c.commands();
    assert!(!c.answered(first));
    let sent = |out: &[ClientOutput]| out.iter().filter_map(|o| if let ClientOutput::Send(f) = o { Message::decode(&f[4..]).ok() } else { None }).collect::<Vec<_>>();
    let mut pending: VecDeque<Message> = VecDeque::new();
    pending.extend(sent(&c.handle(T0, ClientInput::Bytes(encode_frame(&Hello::new(T0, [3; 32]).encode())))));
    let ids: Vec<_> = (0..1024 * 4u32).map(|i| osis_label::blob_id(&i.to_le_bytes())).collect();
    pending.extend(sent(&c.handle(T0, ClientInput::Command(Command::Fetch { label: l.id, ids }))));
    let big = c.commands();
    assert!(c.unsent() > 0);
    // answer every request sent, an hour later each time, until the queue drains
    let mut now = T0;
    let mut answered_first = false;
    while let Some(m) = pending.pop_front() {
        now += 3_600_000;
        assert!(!c.answered(big), "a request of the command is still unanswered");
        let reply = match m {
            Message::Fetch { id, .. } => Message::FetchReply { id, items: vec![] },
            Message::Ping { id, .. } => Message::Pong { id, wall_ms: now },
            _ => continue,
        };
        let out = c.handle(now, ClientInput::Bytes(encode_frame(&reply.encode())));
        pending.extend(sent(&out));
        answered_first |= c.answered(first);
    }
    assert!(answered_first);
    assert!(c.answered(big) && c.unsent() == 0);
}
