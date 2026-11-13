//! A dialer against a listener over a throttled link with the drivers' send queues (spec/sync.md
//! §6: the request window and the stall timeout): bulk deposits and fetches between nodes on a
//! slow link finish on one connection, and neither side's queue outgrows `WINDOW_QUEUE`.

use osis_base::BlobId;
use osis_proto::window::{STALL_TIMEOUT_MS, WINDOW, WINDOW_QUEUE};
use osis_proto::examples::{Dialer, Label, blob_sized, frames, up};
use osis_proto::msg::{NODE_IDS, OfferItem};
use osis_proto::session::REPLY_BUDGET;
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
    client: Dialer,
    host: Session,
    store: MemoryLabelStore,
    up: Pipe,
    down: Pipe,
    /// What the dialer's session handed up.
    events: Vec<Message>,
    /// The dialer's requests not answered yet.
    outstanding: usize,
    /// The listener's node: the blobs deposited with it.
    held: HashMap<BlobId, Vec<u8>>,
}

impl Run {
    fn new() -> Run {
        let mut r = Run {
            now: T0,
            client: Dialer::new([0x5e; 32], [0x80; 32]),
            host: Session::new(SessionConfig { listener_key: [0x5e; 32], challenge: [0x40; 32], dialed: false }),
            store: MemoryLabelStore::new(),
            // the node's `MAX_QUEUED` and the host's default `max_queued_bytes`
            up: Pipe::new(64 << 20),
            down: Pipe::new(64 << 20),
            events: Vec::new(),
            outstanding: 0,
            held: HashMap::new(),
        };
        let so = r.host.handle(T0, &mut r.store, SessionInput::Start);
        r.host_out(so);
        r.input(SessionInput::Start);
        r
    }

    fn input(&mut self, i: SessionInput) {
        let out = self.client.handle(self.now, i);
        assert!(!out.iter().any(|o| matches!(o, SessionOutput::Close | SessionOutput::PeerError(_))), "dialer closed at {} s: {out:?}", (self.now - T0) / 1000);
        for f in frames(&out) {
            self.up.push(f, "dialer");
        }
        let answers = up(&out);
        self.outstanding -= answers.len();
        self.events.extend(answers);
    }

    fn host_out(&mut self, out: Vec<SessionOutput>) {
        for o in out {
            match o {
                SessionOutput::Send(b) => self.down.push(b, "host"),
                SessionOutput::Close => panic!("host closed"),
                SessionOutput::StoreError(e) => panic!("{e}"),
                // the listener's node answers its peer's requests at once
                SessionOutput::Peer(m) => {
                    let reply = self.answer(*m);
                    let so = self.host.handle(self.now, &mut self.store, SessionInput::Peer(Box::new(reply)));
                    self.host_out(so);
                }
                SessionOutput::PeerError(_) | SessionOutput::Request(_) | SessionOutput::Room { .. } => {}
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
        while self.outstanding > 0 || self.up.queued > 0 || self.down.queued > 0 {
            self.step(rate, step_ms);
        }
    }

    /// One step of the link.
    fn step(&mut self, rate: usize, step_ms: u64) {
        self.now += step_ms;
        let b = self.up.take(rate);
        if !b.is_empty() {
            self.input(SessionInput::Taken(self.up.taken));
            let so = self.host.handle(self.now, &mut self.store, SessionInput::Bytes(b));
            self.host_out(so);
        }
        let b = self.down.take(rate);
        if !b.is_empty() {
            // the driver reports what the transport took (before input and at ticks)
            let so = self.host.handle(self.now, &mut self.store, SessionInput::Taken(self.down.taken));
            self.host_out(so);
            self.input(SessionInput::Bytes(b));
        }
        // the driver closes a stalled connection
        assert!(self.client.session.stall_at().is_none_or(|t| self.now < t), "stalled at {} s", (self.now - T0) / 1000);
        assert!(self.now - T0 < 1 << 40, "no end");
    }

    /// The node's own messages to the listener, sent as the window allows; the answers.
    fn peer(&mut self, ms: Vec<Message>, rate: usize, step_ms: u64) -> Vec<Message> {
        for m in ms {
            self.outstanding += 1;
            self.input(SessionInput::Peer(Box::new(m)));
        }
        self.settle(rate, step_ms);
        std::mem::take(&mut self.events)
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

/// A dialer past the Hellos.
fn ready() -> Dialer {
    let mut c = Dialer::new([1; 32], [2; 32]);
    c.start(T0);
    c.bytes(T0, encode_frame(&Hello::new(T0, [3; 32]).encode()));
    c
}

fn sent(out: &[SessionOutput]) -> Vec<Message> {
    frames(out).iter().filter_map(|f| Message::decode(&f[4..]).ok()).collect()
}

/// A node's Fetch that may bring back a whole message.
fn whole_fetch(l: &Label, k: u32) -> Message {
    Message::Fetch { id: NODE_IDS | k, label: l.id, max_reply: REPLY_BUDGET as u64, ids: vec![osis_label::blob_id(&k.to_le_bytes())] }
}

// spec/sync.md §6: requests beyond the window wait for answers; one always goes
#[test]
fn window_holds_requests_back_spec_sync_6() {
    let mut c = ready();
    let l = Label::new(1);
    let mut first = Vec::new();
    for k in 0..4u32 {
        first.extend(sent(&c.send(T0, whole_fetch(&l, k))));
    }
    assert_eq!(first, vec![whole_fetch(&l, 0), whole_fetch(&l, 1)], "two fetches fit the window");
    for k in 0..2u32 {
        let out = c.bytes(T0, encode_frame(&Message::FetchReply { id: NODE_IDS | k, items: vec![] }.encode()));
        assert_eq!(sent(&out), vec![whole_fetch(&l, k + 2)], "an answer makes room for the next");
    }
}

// spec/sync.md §6: a request waiting for room in the window, however long, is not out: it goes
// in the order made once answers make room, its stall clock starts when it goes, and its answer
// comes up then
#[test]
fn held_back_requests_count_unanswered_spec_sync_6() {
    let mut c = Dialer::new([1; 32], [2; 32]);
    c.start(T0);
    let l = Label::new(1);
    c.bytes(T0, encode_frame(&Hello::new(T0, [3; 32]).encode()));
    // the node's Fetches fill the window; a Register made after them waits behind them
    let mut pending: VecDeque<Message> = VecDeque::new();
    for k in 0..4u32 {
        pending.extend(sent(&c.send(T0, whole_fetch(&l, k))));
    }
    let (reg, out) = c.request(T0, |id| l.register(id, 0));
    assert!(sent(&out).is_empty(), "held back");
    // answer every request sent, an hour later each time, until the queue drains
    let mut now = T0;
    let mut answers = Vec::new();
    while let Some(m) = pending.pop_front() {
        now += 3_600_000;
        assert!(!answers.contains(&reg), "the Register is still unanswered");
        let reply = match m {
            Message::Fetch { id, .. } => Message::FetchReply { id, items: vec![] },
            Message::Register { id, .. } => Message::Error { id, code: Code::REFUSED },
            m => panic!("{m:?}"),
        };
        let out = c.bytes(now, encode_frame(&reply.encode()));
        answers.extend(up(&out).iter().map(Message::id));
        let next = sent(&out);
        if !next.is_empty() {
            assert_eq!(c.session.stall_at(), Some(now + STALL_TIMEOUT_MS), "its clock starts as it goes");
        }
        pending.extend(next);
    }
    assert_eq!(answers, vec![NODE_IDS, NODE_IDS | 1, NODE_IDS | 2, NODE_IDS | 3, reg]);
    assert_eq!(c.session.stall_at(), None);
}
