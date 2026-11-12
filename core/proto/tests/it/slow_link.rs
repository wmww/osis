//! A client against a listener over a throttled link with the drivers' send queues (spec/sync.md
//! §6: the request window and the stall timeout): bulk deposits and fetches between nodes on a
//! slow link finish on one connection, and neither side's queue outgrows `WINDOW_QUEUE`.

use osis_base::BlobId;
use osis_proto::client::{STALL_TIMEOUT_MS, WINDOW, WINDOW_QUEUE};
use osis_proto::examples::{Label, blob_sized};
use osis_proto::msg::{NODE_IDS, OfferItem};
use osis_proto::serving::REPLY_BUDGET;
use osis_proto::*;
use std::collections::{HashMap, VecDeque};

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
    host: ServingSession,
    store: MemoryLabelStore,
    up: Pipe,
    down: Pipe,
    timer: Option<u64>,
    events: Vec<ClientEvent>,
    /// The listener's node: the blobs deposited with it.
    held: HashMap<BlobId, Vec<u8>>,
}

impl Run {
    fn new() -> Run {
        let mut r = Run {
            now: T0,
            client: ClientSession::new(ClientConfig { peer_static_key: [0x5e; 32], challenge: [0x80; 32] }),
            host: ServingSession::new(ServingConfig { static_key: [0x5e; 32], challenge: [0x40; 32] }),
            store: MemoryLabelStore::new(),
            // the node's `MAX_QUEUED` and the host's default `max_queued_bytes`
            up: Pipe::new(64 << 20),
            down: Pipe::new(64 << 20),
            timer: None,
            events: Vec::new(),
            held: HashMap::new(),
        };
        let so = r.host.handle(T0, &mut r.store, ServingInput::Start);
        r.host_out(so);
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

    fn host_out(&mut self, out: Vec<ServingOutput>) {
        for o in out {
            match o {
                ServingOutput::Send(b) => self.down.push(b, "host"),
                ServingOutput::Close => panic!("host closed"),
                ServingOutput::StoreError(e) => panic!("{e}"),
                // the listener's node answers its peer's requests at once
                ServingOutput::Peer(m) => {
                    let reply = self.answer(*m);
                    let so = self.host.handle(self.now, &mut self.store, ServingInput::Peer(Box::new(reply)));
                    self.host_out(so);
                }
                ServingOutput::PeerError(_) | ServingOutput::Request(_) | ServingOutput::Room { .. } => {}
            }
        }
    }

    /// The listener's node: an Offer of deposits is held, a Fetch answered from what it holds.
    fn answer(&mut self, m: Message) -> Message {
        match m {
            Message::Offer { id, items } => {
                let codes = items
                    .into_iter()
                    .map(|i| {
                        let OfferItem::Deposit { blob, .. } = i else { panic!("a deposit") };
                        self.held.insert(osis_label::blob_id(&blob), blob);
                        (Code::OK, None, None)
                    })
                    .collect();
                Message::Shared { id, codes }
            }
            Message::Fetch { id, ids, .. } => Message::FetchReply { id, items: ids.into_iter().map(|blob_id| Fetched { blob_id, entry: self.held.get(&blob_id).map(|b| (b.clone(), [0; osis_crypto::WRAP_LEN], None)) }).collect() },
            m => panic!("{m:?}"),
        }
    }

    /// Steps the link (`rate` bytes per direction per `step_ms`) until nothing is outstanding.
    fn settle(&mut self, rate: usize, step_ms: u64) {
        while self.client.outstanding() > 0 || self.client.in_flight() > 0 || self.client.unsent() > 0 || self.up.queued > 0 || self.down.queued > 0 {
            self.step(rate, step_ms);
        }
    }

    /// One step of the link.
    fn step(&mut self, rate: usize, step_ms: u64) {
        self.now += step_ms;
        let b = self.up.take(rate);
        if !b.is_empty() {
            self.input(ClientInput::Taken(self.up.taken));
            let so = self.host.handle(self.now, &mut self.store, ServingInput::Bytes(b));
            self.host_out(so);
        }
        let b = self.down.take(rate);
        if !b.is_empty() {
            // the driver reports what the transport took (before input and at ticks)
            let so = self.host.handle(self.now, &mut self.store, ServingInput::Taken(self.down.taken));
            self.host_out(so);
            self.input(ClientInput::Bytes(b));
        }
        if self.timer.is_some_and(|t| t <= self.now) {
            self.timer = None;
            self.input(ClientInput::Timer);
        }
        assert!(self.now - T0 < 1 << 40, "no end");
    }

    /// The node's own messages to the listener, sent as the window allows; the answers.
    fn peer(&mut self, ms: Vec<Message>, rate: usize, step_ms: u64) -> Vec<Message> {
        for m in ms {
            self.input(ClientInput::Command(Command::Peer(Box::new(m))));
        }
        self.settle(rate, step_ms);
        std::mem::take(&mut self.events).into_iter().filter_map(|e| if let ClientEvent::Peer(m) = e { Some(*m) } else { None }).collect()
    }
}

/// Deposits `n` blobs of `size` bytes with the listener over the link, one per Offer, and
/// fetches them back, all on one session.
fn round_trip(n: u64, size: usize, rate: usize, step_ms: u64) -> Run {
    let mut r = Run::new();
    let l = Label::new(1);
    r.settle(rate, step_ms);
    let blobs: Vec<Vec<u8>> = (0..n).map(|i| blob_sized(i, 0, vec![], size)).collect();
    let ids: Vec<BlobId> = blobs.iter().map(|b| osis_label::blob_id(b)).collect();
    let offers = blobs.into_iter().zip(0u32..).map(|(b, k)| Message::Offer { id: NODE_IDS | k, items: vec![l.deposit(b, &l.head_keys().deposit)] }).collect();
    let started = r.now;
    let answers = r.peer(offers, rate, step_ms);
    let codes: Vec<Code> = answers.iter().flat_map(|m| if let Message::Shared { codes, .. } = m { codes.iter().map(|c| c.0).collect() } else { vec![] }).collect();
    assert_eq!(codes, vec![Code::OK; n as usize]);
    assert!(r.now - started > 2 * STALL_TIMEOUT_MS, "the deposits took longer than the stall timeout");
    let fetches = ids.iter().zip(1000u32..).map(|(id, k)| Message::Fetch { id: NODE_IDS | k, label: l.id, max_reply: REPLY_BUDGET as u64, ids: vec![*id] }).collect();
    let answers = r.peer(fetches, rate, step_ms);
    let got: Vec<BlobId> = answers.iter().flat_map(|m| if let Message::FetchReply { items, .. } = m { items.iter().filter(|f| f.entry.is_some()).map(|f| f.blob_id).collect() } else { vec![] }).collect();
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
    let mut first = Vec::new();
    for k in 0..4u32 {
        let fetch = Message::Fetch { id: NODE_IDS | k, label: l.id, max_reply: REPLY_BUDGET as u64, ids: vec![osis_label::blob_id(&k.to_le_bytes())] };
        first.extend(sent(&c.handle(T0, ClientInput::Command(Command::Peer(Box::new(fetch))))));
    }
    assert_eq!(first.len(), 2, "two fetches fit the window (after the pings)");
    assert_eq!(c.unsent(), 2);
    assert!(c.in_flight() >= WINDOW);
    let Message::Fetch { id, .. } = first[0] else { panic!() };
    let out = c.handle(T0, ClientInput::Bytes(encode_frame(&Message::FetchReply { id, items: vec![] }.encode())));
    assert_eq!(sent(&out).len(), 1, "an answer makes room for the next");
    assert_eq!(c.unsent(), 1);
}

// spec/sync.md §6: a request is unanswered while it waits for room in the window, however long
// (the node's resend timer asks this, not the time it was given)
#[test]
fn held_back_requests_count_unanswered_spec_sync_6() {
    let mut c = ClientSession::new(ClientConfig { peer_static_key: [1; 32], challenge: [2; 32] });
    c.handle(T0, ClientInput::Start);
    let l = Label::new(1);
    // given before the Hellos
    c.handle(T0, ClientInput::Command(Command::Path { label: l.id, after: None }));
    let first = c.commands();
    assert!(!c.answered(first));
    let sent = |out: &[ClientOutput]| out.iter().filter_map(|o| if let ClientOutput::Send(f) = o { Message::decode(&f[4..]).ok() } else { None }).collect::<Vec<_>>();
    let mut pending: VecDeque<Message> = VecDeque::new();
    pending.extend(sent(&c.handle(T0, ClientInput::Bytes(encode_frame(&Hello::new(T0, [3; 32]).encode())))));
    // the node's Fetches fill the window; a command made after them waits behind them
    for k in 0..4u32 {
        let fetch = Message::Fetch { id: NODE_IDS | k, label: l.id, max_reply: REPLY_BUDGET as u64, ids: vec![osis_label::blob_id(&k.to_le_bytes())] };
        pending.extend(sent(&c.handle(T0, ClientInput::Command(Command::Peer(Box::new(fetch))))));
    }
    pending.extend(sent(&c.handle(T0, ClientInput::Command(Command::Path { label: l.id, after: None }))));
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
            Message::Path { id, .. } => Message::Error { id, code: Code::REFUSED },
            _ => continue,
        };
        let out = c.handle(now, ClientInput::Bytes(encode_frame(&reply.encode())));
        pending.extend(sent(&out));
        answered_first |= c.answered(first);
    }
    assert!(answered_first);
    assert!(c.answered(big) && c.unsent() == 0);
}
