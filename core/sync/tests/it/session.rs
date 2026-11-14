//! The session (core/sync/src/session.rs): frames, Hello, proofs, ids, routing, the window, pushes,
//! the stall clock. Most tests drive one `Session` against a scripted peer (raw frames through the
//! real encoder) or two `Session`s against each other, over real engines; a few run a world.

use crate::harness::{World, fixture};
use osis_base::copying::{cached, copying};
use osis_base::{Clock, ManualClock, Tid, WallMs};
use osis_crypto::{SeededRng, Secret32, SigningSecret};
use osis_engine::Engine;
use osis_proto::limits::{MAX_MESSAGE, NO_RECORD_ID, REPLY_BUDGET, SMALL_REPLY, TOP_BIT};
use osis_proto::prove::ActorProof;
use osis_proto::{Code, FrameDecoder, Hello, Msg, Prover, Pull, PullReply, encode_frame};
use osis_store::{MemoryBackend, MemoryRoot};
use osis_sync::session::{Close, Incoming, PINGS, STALL_TIMEOUT_MS, DIAL_TIMEOUT_MS, Session, Sessions, To};
use osis_sync::types::Cx;
use osis_sync::{ConnId, NodeKey, Out, Store};
use std::sync::Arc;

const T0: WallMs = WallMs(1_700_000_000_000);
/// The key the listener listens with (dialed by the dialer).
const LISTEN: NodeKey = NodeKey([7; 32]);
/// The dialer's ephemeral key.
const EPH: NodeKey = NodeKey([8; 32]);

/// One end: an engine and store, the time, the rng, outputs a module would make.
struct End {
    engine: Engine,
    store: Store,
    rng: SeededRng,
    now: WallMs,
    out: Vec<Out>,
}

impl End {
    fn cx(&mut self) -> Cx<'_> {
        Cx { engine: &mut self.engine, store: &mut self.store, now: self.now, rng: &mut self.rng, out: &mut self.out }
    }

    fn account(&self) -> Option<Tid> {
        self.engine.account_tid()
    }
}

fn open(seed: u64, clock: Arc<dyn Clock>) -> (Engine, Store) {
    let store = Store::open(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), Box::new(SeededRng::from_u64(seed ^ 1))).expect("store");
    let engine = Engine::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), store.cipher(), osis_engine::Config::default(), clock, Box::new(SeededRng::from_u64(seed))).expect("engine");
    (engine, store)
}

/// Two ends, each with an account of its own, unknown to each other: built once, copied per test.
fn ends() -> (End, End) {
    let clock = Arc::new(ManualClock::new(T0));
    let dyn_clock: Arc<dyn Clock> = clock.clone();
    let built = cached(
        "session_ends",
        || {
            let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(T0));
            (0..2u64)
                .map(|i| {
                    let (mut e, s) = open(i + 1, clock.clone());
                    e.create_account().expect("account");
                    (e, s)
                })
                .collect::<Vec<_>>()
        },
        |v| copying(|| v.iter().map(|(e, s)| (e.test_copy(dyn_clock.clone()).expect("copy"), s.test_copy(dyn_clock.clone()).expect("copy"))).collect::<Vec<_>>()),
    );
    let mut it = built.into_iter().enumerate().map(|(i, (engine, store))| End { engine, store, rng: SeededRng::from_u64(100 + i as u64), now: T0, out: Vec::new() });
    let a = it.next().expect("end");
    let b = it.next().expect("end");
    (a, b)
}

/// A dialer session at `d` and a listener session at `l` on one connection.
struct Pair {
    d: End,
    l: End,
    ds: Session,
    ls: Session,
    /// What each side received, as reported.
    d_in: Vec<Incoming>,
    l_in: Vec<Incoming>,
}

impl Pair {
    fn new() -> Pair {
        let (mut d, mut l) = ends();
        let ds = Session::new(ConnId(1), LISTEN, true, 1, LISTEN, &mut d.cx());
        let ls = Session::new(ConnId(ConnId::ACCEPTED | 1), EPH, false, 1, LISTEN, &mut l.cx());
        Pair { d, l, ds, ls, d_in: Vec::new(), l_in: Vec::new() }
    }

    /// Carries bytes both ways until none flow; the transport takes everything sent.
    fn flow(&mut self) {
        loop {
            let (db, lb) = (self.ds.take_bytes(), self.ls.take_bytes());
            if db.is_empty() && lb.is_empty() {
                return;
            }
            let ins = self.ls.receive(&db, &mut self.l.cx()).expect("listener keeps the connection");
            self.l_in.extend(ins);
            let ins = self.ds.receive(&lb, &mut self.d.cx()).expect("dialer keeps the connection");
            self.d_in.extend(ins);
            // the transport takes everything sent (the session clamps to what it wrote)
            self.ds.taken(u64::MAX, self.d.now);
            self.ls.taken(u64::MAX, self.l.now);
        }
    }
}

/// The frames in `bytes`, Hello first when `hello`.
fn frames(bytes: &[u8], hello: bool) -> (Option<Hello>, Vec<Msg>) {
    let mut d = FrameDecoder::new();
    d.push(bytes);
    let mut h = None;
    let mut out = Vec::new();
    while let Some(b) = d.next_frame().expect("frame") {
        if hello && h.is_none() {
            h = Some(Hello::decode(&b).expect("hello"));
        } else {
            out.push(Msg::decode(&b).expect("message"));
        }
    }
    (h, out)
}

fn frame(m: &Msg) -> Vec<u8> {
    encode_frame(&m.encode())
}

/// A scripted dialer's Hello and the listener session it talks to; the listener's Hello read.
fn listener_with_scripted_dialer() -> (End, End, Session, Hello) {
    let (d, mut l) = ends();
    let mut ls = Session::new(ConnId(ConnId::ACCEPTED | 1), EPH, false, 1, LISTEN, &mut l.cx());
    let (h, _) = frames(&ls.take_bytes(), true);
    let ins = ls.receive(&encode_frame(&Hello::new(T0.0, [3; 32]).encode()), &mut l.cx()).expect("hello");
    assert!(ins.is_empty());
    (d, l, ls, h.expect("listener hello"))
}

/// A key actor's prover (a link key), not an account.
fn key_actor(seed: u8) -> Prover {
    let key = SigningSecret::from_seed(&Secret32::from_bytes([seed; 32]));
    let record = osis_base::CreationRecord::KeyActor { alg: 1, public_key: key.verifying_key().to_bytes().to_vec(), nonce: [seed; 32], account: false };
    Prover { key, record }
}

fn pull(max_reply: u64) -> Msg {
    Msg::Pull(Box::new(Pull { id: 0, cursor: None, joins: Vec::new(), inline_limit: 0, max_reply, follow: false, ephemeral: false }))
}

fn pull_reply(id: u32) -> Msg {
    Msg::PullReply(Box::new(PullReply { id, events: Vec::new(), cursor: None, whole: true, trimmed: false, more: false, report: false, joins: Vec::new() }))
}

/// A pair past Hello, proofs and pings: nothing out on either side.
fn quiet_pair() -> Pair {
    let mut p = Pair::new();
    p.flow();
    assert!(p.ds.proofs_done() && p.ls.proofs_done());
    assert_eq!(p.ds.deadline(), None, "nothing out");
    p
}

// spec/wire.md §11.1 (as its first frame): each side's first frame is its Hello, sent without waiting for
// the other's; nothing else goes before the peer's Hello; both sides then agree on the challenges
// and the listener's static key.
#[test]
fn hello_first_spec_wire_11_1() {
    let mut p = Pair::new();
    let (h, rest) = frames(&p.ds.take_bytes(), true);
    assert!(h.is_some_and(|h| h.versions == [1] && h.wall_ms == T0.0));
    assert!(rest.is_empty(), "the dialer proves only after the listener's Hello");
    assert!(p.ds.binding().is_none());
    p = Pair::new();
    p.flow();
    let (db, lb) = (p.ds.binding().copied(), p.ls.binding().copied());
    assert!(db.is_some() && db == lb, "one binding at both ends");
    assert_eq!(db.map(|b| b.listener_key), Some(LISTEN.0));
    assert_ne!(db.map(|b| b.dialer_challenge), db.map(|b| b.listener_challenge));
}

// spec/wire.md §11.1 (versions): with no version in common both close; the greatest common one is
// used.
#[test]
fn no_common_version_closes_spec_wire_11_1() {
    let (_, mut l) = ends();
    let mut ls = Session::new(ConnId(ConnId::ACCEPTED | 1), EPH, false, 1, LISTEN, &mut l.cx());
    let h = Hello { versions: vec![2, 5], wall_ms: 0, challenge: [1; 32] };
    assert_eq!(ls.receive(&encode_frame(&h.encode()), &mut l.cx()).err(), Some(Close("no common version")));
    let mut ls = Session::new(ConnId(ConnId::ACCEPTED | 2), EPH, false, 1, LISTEN, &mut l.cx());
    let h = Hello { versions: vec![1, 5], wall_ms: 0, challenge: [1; 32] };
    assert!(ls.receive(&encode_frame(&h.encode()), &mut l.cx()).is_ok());
}

// spec/wire.md §11.1 (answered by Error 2): a frame of length 0 or past the cap (a first frame past the Hello
// cap) is answered Error 2 with id 0 and closes the connection, as does a Hello that does not
// decode.
#[test]
fn broken_frames_close_spec_wire_11_1() {
    let (_, mut l) = ends();
    for bytes in [vec![0, 0, 0, 0], ((MAX_MESSAGE + 1) as u32).to_be_bytes().to_vec(), 300u32.to_be_bytes().to_vec(), encode_frame(&[0x80])] {
        let mut ls = Session::new(ConnId(ConnId::ACCEPTED | 1), EPH, false, 1, LISTEN, &mut l.cx());
        ls.take_bytes();
        assert!(ls.receive(&bytes, &mut l.cx()).is_err());
        let (_, ms) = frames(&ls.take_bytes(), false);
        assert_eq!(ms, [Msg::Error { id: 0, code: Code::MALFORMED }]);
    }
    // after Hello: a frame of length 0
    let (_, mut l, mut ls, _) = listener_with_scripted_dialer();
    assert!(ls.receive(&[0, 0, 0, 0], &mut l.cx()).is_err());
}

// spec/wire.md §11.1 (a malformed request is answered Error 2; a request of unknown kind gets Error 11): a malformed request is answered Error 2
// with its id, a request of unknown kind Error 11, a frame whose id cannot be read Error 2 with id
// 0; a malformed reply or push, and a reply naming no request out, are dropped. None closes.
#[test]
fn malformed_messages_spec_wire_11_1() {
    let (_, mut l, mut ls, _) = listener_with_scripted_dialer();
    ls.take_bytes();
    let cbor = |v: osis_base::Value| encode_frame(&osis_base::cbor::encode(&v));
    let int = osis_base::Value::uint;
    let list = osis_base::Value::List;
    let bytes = [
        cbor(list(vec![int(2), int(5)])),                // Ping without wall_ms
        cbor(list(vec![int(47), int(6), int(0)])),       // unknown kind
        cbor(list(vec![int(2), int(1 << 32), int(0)])),  // id past 2^32
        cbor(list(vec![int(3), int(9)])),                // a malformed Pong: dropped
        cbor(list(vec![int(45), int(0)])),               // a malformed Digest: dropped
        frame(&Msg::Pong { id: 9, wall_ms: 1 }),         // answers nothing out: dropped
    ]
    .concat();
    let ins = ls.receive(&bytes, &mut l.cx()).expect("kept");
    assert!(ins.is_empty());
    let (_, ms) = frames(&ls.take_bytes(), false);
    assert_eq!(ms, [Msg::Error { id: 5, code: Code::MALFORMED }, Msg::Error { id: 6, code: Code::UNSUPPORTED }, Msg::Error { id: 0, code: Code::MALFORMED }]);
}

// spec/sync-opens.md §2 (Order): the dialer proves first, after the listener's Hello; a listener
// that does not know any actor the dialer proved answers with no proofs; both report Proved, the
// listener having judged the dialer's account (open at its first epoch where not held) and the
// dialer nothing.
#[test]
fn unknown_dialer_gets_no_proofs_spec_sync_opens_2() {
    let mut p = Pair::new();
    p.flow();
    assert!(matches!(p.l_in.as_slice(), [Incoming::Proved]), "{:?}", p.l_in);
    assert!(matches!(p.d_in.as_slice(), [Incoming::Proved]), "{:?}", p.d_in);
    assert_eq!(p.ls.proven().account(), p.d.account(), "the dialer's account");
    assert_eq!(p.ds.proven(), &Default::default(), "the listener proved nothing to a stranger");
    assert_eq!(p.ds.proved(), [p.d.account().expect("account")], "the dialer proved its account (not its node key: not its own node)");
    assert!(p.ls.proved().is_empty());
}

// spec/sync-opens.md §2 (order; its own node key only to nodes of its own account): a listener that knows the dialer's proved actor (here
// its own account) answers with its proofs: its node key first (the dialer proved the listener's
// account), then its account, each signed as the listener's over the dialer's challenge.
#[test]
fn known_dialer_gets_proofs_spec_sync_opens_2() {
    let (_, mut l, mut ls, _) = listener_with_scripted_dialer();
    let b = *ls.binding().expect("binding");
    let mine: Vec<ActorProof> = l.engine.provers(false).expect("provers").into_iter().map(|(key, record)| Prover { key, record }.sign(false, &b.listener_challenge, &LISTEN.0)).collect();
    ls.take_bytes();
    let ins = ls.receive(&frame(&Msg::Prove { id: 4, proofs: mine, rotations: Some(Vec::new()) }), &mut l.cx()).expect("kept");
    assert!(matches!(ins.as_slice(), [Incoming::Proved]));
    assert_eq!(ls.proven().account(), l.account());
    let (_, ms) = frames(&ls.take_bytes(), false);
    let [Msg::Proved { id: 4, proofs }] = ms.as_slice() else { panic!("{ms:?}") };
    assert_eq!(proofs.len(), 2);
    assert!(!proofs[0].record.is_account() && proofs[1].actor() == l.account().expect("account"), "node key first, then the account");
    assert!(proofs.iter().all(|p| p.verify(true, &b.dialer_challenge, &LISTEN.0)));
}

// spec/wire.md §11.2 (Prove): a verifier checks proofs in order and stops at the first that does
// not verify: those before it stand; key actors proved count whether known or not.
#[test]
fn proofs_stop_at_the_first_bad_spec_wire_11_2() {
    let (_, mut l, mut ls, _) = listener_with_scripted_dialer();
    let b = *ls.binding().expect("binding");
    let good = key_actor(1).sign(false, &b.listener_challenge, &LISTEN.0);
    let bad = key_actor(2).sign(false, &[0; 32], &LISTEN.0);
    let after = key_actor(3).sign(false, &b.listener_challenge, &LISTEN.0);
    let wrong_side = key_actor(4).sign(true, &b.listener_challenge, &LISTEN.0);
    ls.receive(&frame(&Msg::Prove { id: 4, proofs: vec![good.clone(), bad, after], rotations: None }), &mut l.cx()).expect("kept");
    assert_eq!(ls.proven().key_actors.keys().copied().collect::<Vec<_>>(), [good.actor()]);
    let (_, mut l, mut ls, _) = listener_with_scripted_dialer();
    ls.receive(&frame(&Msg::Prove { id: 4, proofs: vec![wrong_side], rotations: None }), &mut l.cx()).expect("kept");
    assert!(ls.proven().key_actors.is_empty(), "a proof made as the listener proves nothing from the dialer");
}

// spec/wire.md §11.2 (Prove): at most one per connection, dialer to listener: a second Prove, or
// one from the listener, is answered Error 2.
#[test]
fn one_prove_from_the_dialer_spec_wire_11_2() {
    let (_, mut l, mut ls, _) = listener_with_scripted_dialer();
    ls.receive(&frame(&Msg::Prove { id: 4, proofs: Vec::new(), rotations: None }), &mut l.cx()).expect("kept");
    ls.take_bytes();
    let ins = ls.receive(&frame(&Msg::Prove { id: 5, proofs: Vec::new(), rotations: None }), &mut l.cx()).expect("kept");
    assert!(ins.is_empty());
    assert_eq!(frames(&ls.take_bytes(), false).1, [Msg::Error { id: 5, code: Code::MALFORMED }]);
    let mut p = quiet_pair();
    let ins = p.ds.receive(&frame(&Msg::Prove { id: 6, proofs: Vec::new(), rotations: None }), &mut p.d.cx()).expect("kept");
    assert!(ins.is_empty());
    assert_eq!(frames(&p.ds.take_bytes(), false).1, [Msg::Error { id: 6, code: Code::MALFORMED }]);
}

// spec/wire.md §11.1-§11.2 (ids): requests get nonzero ids not in use; the shared set's and the
// stream's requests have the top bit set, NoRecord exactly 2^31, others not.
#[test]
fn request_ids_spec_wire_11_2() {
    let mut p = quiet_pair();
    let a = p.ds.request(To::Streams, pull(SMALL_REPLY as u64));
    let b = p.ds.request(To::Streams, Msg::Fetch { id: 0, sync_id: osis_base::SyncId([1; 16]), max_reply: SMALL_REPLY as u64, ids: vec![osis_base::BlobId([2; 32])] });
    let c = p.ds.request(To::Opens, Msg::NoRecord { id: 0 });
    let d = p.ds.request(To::Inbox, Msg::Ping { id: 0, wall_ms: 0 });
    assert!(a & TOP_BIT != 0 && b & TOP_BIT != 0 && a != b && a != NO_RECORD_ID);
    assert_eq!(c, NO_RECORD_ID);
    assert!(d != 0 && d & TOP_BIT == 0);
    let (_, ms) = frames(&p.ds.take_bytes(), false);
    assert_eq!(ms.iter().map(Msg::id).collect::<Vec<_>>(), [a, b, c, d], "sent in the order made, each with its id");
}

// spec/sync-streams.md §1 (flow control): at most `WINDOW` in flight, a request counting its frame and
// its reply allowance; the next goes once one is answered, in the order made; one always goes.
#[test]
fn window_spec_sync_streams_1() {
    let mut p = quiet_pair();
    let ids: Vec<u32> = (0..3).map(|_| p.ds.request(To::Streams, pull(REPLY_BUDGET as u64))).collect();
    let (_, ms) = frames(&p.ds.take_bytes(), false);
    assert_eq!(ms.iter().map(Msg::id).collect::<Vec<_>>(), ids[..2], "two of about 9 MiB each fill the 16 MiB window");
    let ins = p.ds.receive(&frame(&pull_reply(ids[0])), &mut p.d.cx()).expect("kept");
    assert!(matches!(ins.as_slice(), [Incoming::Reply(To::Streams, id, Msg::PullReply(_))] if *id == ids[0]));
    let (_, ms) = frames(&p.ds.take_bytes(), false);
    assert_eq!(ms.iter().map(Msg::id).collect::<Vec<_>>(), ids[2..], "the third goes once the first is answered");
}

// spec/wire.md §11.2 (Pull): Pulls and top-bit Fetches are answered in the order they arrive; one
// still out when a later one's answer arrives is skipped: a Pull refused, a Fetch answered with none.
#[test]
fn skipped_pulls_and_fetches_spec_wire_11_2() {
    let mut p = quiet_pair();
    let a = p.ds.request(To::Streams, pull(SMALL_REPLY as u64));
    let f = p.ds.request(To::Streams, Msg::Fetch { id: 0, sync_id: osis_base::SyncId([1; 16]), max_reply: SMALL_REPLY as u64, ids: vec![osis_base::BlobId([2; 32])] });
    let b = p.ds.request(To::Streams, pull(SMALL_REPLY as u64));
    p.ds.take_bytes();
    let ins = p.ds.receive(&frame(&pull_reply(b)), &mut p.d.cx()).expect("kept");
    let got: Vec<(u32, u64)> = ins.iter().map(|i| match i {
        Incoming::Reply(To::Streams, id, m) => (*id, m.kind()),
        other => panic!("{other:?}"),
    }).collect();
    assert_eq!(got, [(a, 0), (f, 20), (b, 42)]);
    assert!(matches!(&ins[0], Incoming::Reply(_, _, Msg::Error { code: Code::DECLINED, .. })));
    assert!(matches!(&ins[1], Incoming::Reply(_, _, Msg::FetchReply { items, .. }) if items.is_empty()));
    assert_eq!(p.ds.deadline(), None, "none left out");
}

// spec/wire.md §11.2 (replies): a reply goes to the module that sent the request; one of a kind that
// does not answer it is dropped and leaves the request out.
#[test]
fn replies_go_to_their_sender_spec_wire_11_2() {
    let mut p = quiet_pair();
    let d = p.ds.request(To::Read, Msg::Delete { id: 0, sync_id: osis_base::SyncId([1; 16]), items: Vec::new() });
    p.ds.take_bytes();
    let ins = p.ds.receive(&frame(&Msg::Ok { id: d }), &mut p.d.cx()).expect("kept");
    assert!(ins.is_empty(), "Ok does not answer a Delete");
    let ins = p.ds.receive(&frame(&Msg::Status { id: d, codes: vec![Code::OK] }), &mut p.d.cx()).expect("kept");
    assert!(matches!(ins.as_slice(), [Incoming::Reply(To::Read, id, Msg::Status { .. })] if *id == d));
    assert_eq!(ins[0].to(), Some(To::Read));
}

// spec: none (routing, notes/sync-boundary.md session): a request or push goes to the module of its
// kind; the client port's requests go to the node's owner (`To::Port`), a Notify to none.
#[test]
fn routing_by_kind() {
    let s = osis_base::SyncId([1; 16]);
    let req = |m: Msg| Incoming::Request(1, m).to();
    assert_eq!(req(Msg::Resume { id: 1, nonce: [0; 32], tags: Vec::new() }), Some(To::Opens));
    assert_eq!(req(Msg::NoRecord { id: NO_RECORD_ID }), Some(To::Opens));
    assert_eq!(req(pull(SMALL_REPLY as u64)), Some(To::Streams));
    assert_eq!(req(Msg::Suspect { id: 1, sync_id: s, entries: Vec::new() }), Some(To::Inbox));
    assert_eq!(req(Msg::Unsub { id: 1, sub_id: 2 }), Some(To::Port));
    assert_eq!(req(Msg::Auth { id: 1, secret: None, session_id: [0; 16] }), Some(To::Port));
    assert_eq!(Incoming::Push(Msg::Unsub { id: 1, sub_id: 2 }).to(), None);
    assert_eq!(Incoming::Push(Msg::Digest { digest: [0; 32] }).to(), Some(To::Opens));
    assert_eq!(Incoming::Push(Msg::Applied { cursor: osis_proto::Cursor::new(vec![1]).expect("cursor") }).to(), Some(To::Streams));
    assert_eq!(Incoming::Proved.to(), Some(To::Opens));
}

// spec/sync-streams.md §1 (Unanswered requests): a peer whose requests received and not answered
// pass `WINDOW + 2 × MAX_MESSAGE + 4` (frames plus allowances) is closed, without running the one
// that passes it; answering makes room again.
#[test]
fn flooding_peer_closes_spec_sync_streams_1() {
    let (_, mut l, mut ls, _) = listener_with_scripted_dialer();
    let big = |id: u32| {
        let mut m = pull(REPLY_BUDGET as u64);
        m.set_id(id);
        frame(&m)
    };
    for id in 1..=3 {
        let ins = ls.receive(&big(TOP_BIT | id), &mut l.cx()).expect("within the bound");
        assert!(matches!(ins.as_slice(), [Incoming::Request(..)]));
    }
    ls.answer(TOP_BIT | 1, pull_reply(0));
    assert!(ls.receive(&big(TOP_BIT | 4), &mut l.cx()).is_ok(), "an answer made room");
    assert_eq!(ls.receive(&big(TOP_BIT | 5), &mut l.cx()).err(), Some(Close("too many requests unanswered")));
}

// spec/wire.md §11.1 (not reused while its request is outstanding): a request reusing the id of one not answered yet is answered Error 2
// and closes the connection.
#[test]
fn reused_request_id_closes_spec_wire_11_1() {
    let (_, mut l, mut ls, _) = listener_with_scripted_dialer();
    let m = Msg::Fetch { id: TOP_BIT | 3, sync_id: osis_base::SyncId([1; 16]), max_reply: SMALL_REPLY as u64, ids: vec![osis_base::BlobId([2; 32])] };
    assert!(ls.receive(&frame(&m), &mut l.cx()).is_ok());
    ls.take_bytes();
    assert_eq!(ls.receive(&frame(&m), &mut l.cx()).err(), Some(Close("request id reused")));
    assert_eq!(frames(&ls.take_bytes(), false).1, [Msg::Error { id: TOP_BIT | 3, code: Code::MALFORMED }]);
}

// spec/sync-streams.md §2 (a node sends a push): a push goes while the bytes not taken by the transport, it
// included, stay within `REPLY_BUDGET`, or none are; else it waits until the transport takes them.
#[test]
fn pushes_wait_for_room_spec_sync_streams_2() {
    let mut p = quiet_pair();
    let digest = Msg::Digest { digest: [1; 32] };
    let big = Msg::Members { sync_ids: vec![osis_base::SyncId([2; 16]); 4096], more: true };
    let n = big.encode().len() as u64 + 4;
    let fit = (REPLY_BUDGET as u64 / n) as usize;
    for _ in 0..fit {
        assert!(p.ds.push(big.clone()));
    }
    assert!(!p.ds.push(big.clone()), "past REPLY_BUDGET unwritten");
    p.ds.take_bytes();
    assert!(!p.ds.push(big.clone()), "handed out is not taken");
    p.ds.taken(u64::MAX, p.d.now);
    assert!(p.ds.push(big.clone()) && p.ds.push(digest), "taken: room again");
}

// spec/sync-streams.md §1 (Stall): the oldest request out closes the connection `STALL_TIMEOUT_MS`
// after it last moved; it moves when sent with none other out, when the transport takes its frame
// whole, when bytes of a reply to it arrive (a partial frame too), and when the one before it is
// answered; a reply to another request moves nothing.
#[test]
fn stall_clock_spec_sync_streams_1() {
    let mut p = quiet_pair();
    let stall = |at: u64| Some(WallMs(T0.0 + at + STALL_TIMEOUT_MS));
    let a = p.ds.request(To::Streams, pull(SMALL_REPLY as u64));
    let b = p.ds.request(To::Inbox, Msg::Ping { id: 0, wall_ms: 0 });
    assert_eq!(p.ds.deadline(), stall(0), "sent with none other out");
    p.d.now = WallMs(T0.0 + 10);
    let ins = p.ds.receive(&frame(&Msg::Pong { id: b, wall_ms: 0 }), &mut p.d.cx()).expect("kept");
    assert_eq!(ins.len(), 1);
    assert_eq!(p.ds.deadline(), stall(0), "a reply to another request moves nothing");
    p.ds.taken(u64::MAX, WallMs(T0.0 + 20));
    assert_eq!(p.ds.deadline(), stall(20), "the transport took its frame");
    p.ds.taken(u64::MAX, WallMs(T0.0 + 25));
    assert_eq!(p.ds.deadline(), stall(20), "once");
    p.d.now = WallMs(T0.0 + 30);
    let reply = frame(&pull_reply(a));
    p.ds.receive(&reply[..12], &mut p.d.cx()).expect("kept");
    assert_eq!(p.ds.deadline(), stall(30), "bytes of a reply to it");
    p.ds.receive(&reply[12..], &mut p.d.cx()).expect("kept");
    assert_eq!(p.ds.deadline(), None, "answered");
}

// spec/sync-streams.md §1 (Stall): other bytes received (pushes, the peer's requests) move the
// stall clock too, within their bound.
#[test]
fn other_bytes_move_the_stall_clock_spec_sync_streams_1() {
    let mut p = quiet_pair();
    p.ds.request(To::Streams, pull(SMALL_REPLY as u64));
    p.ds.take_bytes();
    p.d.now = WallMs(T0.0 + 1000);
    p.ds.receive(&frame(&Msg::Digest { digest: [0; 32] }), &mut p.d.cx()).expect("kept");
    assert_eq!(p.ds.deadline(), Some(WallMs(T0.0 + 1000 + STALL_TIMEOUT_MS)), "a push moved it");
}

// spec/sync-transport.md §1, spec/sync-opens.md §1 (Dial timeout): a connection whose peer
// sends no Hello closes `STALL_TIMEOUT_MS` after it came up; a dial not up `DIAL_TIMEOUT_MS` after
// it started closes as failed. A world of two connected nodes ends quiet: no deadline left.
#[test]
fn hello_and_dial_deadlines_spec_sync_opens_1() {
    let mut s = Sessions::default();
    s.set_now(T0);
    s.dialing(ConnId(5));
    assert_eq!(s.next_wake(), Some(WallMs(T0.0 + DIAL_TIMEOUT_MS)));
    assert!(s.tick(WallMs(T0.0 + DIAL_TIMEOUT_MS - 1)).is_empty());
    assert_eq!(s.tick(WallMs(T0.0 + DIAL_TIMEOUT_MS)), [(ConnId(5), Close("dial timed out"))]);
    assert_eq!(s.next_wake(), None);
    let (_, mut l) = ends();
    let ls = Session::new(ConnId(ConnId::ACCEPTED | 1), EPH, false, 1, LISTEN, &mut l.cx());
    assert_eq!(ls.deadline(), Some(WallMs(T0.0 + STALL_TIMEOUT_MS)), "waiting for the peer's Hello");
}

// spec/sync-streams.md §1 (clock): the dialer pings, one at a time, `PINGS` times, and estimates the
// peer's clock offset from the round trips; the listener pings nothing.
#[test]
fn clock_offset_from_pings_spec_sync_streams_1() {
    let mut p = Pair::new();
    p.l.now = WallMs(T0.0 + 7_000);
    let mut pings = 0;
    loop {
        let db = p.ds.take_bytes();
        let lb = p.ls.take_bytes();
        if db.is_empty() && lb.is_empty() {
            break;
        }
        let pinged = frames_after_hello(&db).iter().filter(|m| matches!(m, Msg::Ping { .. })).count();
        assert!(pinged <= 1, "one Ping at a time");
        pings += pinged;
        p.l_in.extend(p.ls.receive(&db, &mut p.l.cx()).expect("kept"));
        p.d_in.extend(p.ds.receive(&lb, &mut p.d.cx()).expect("kept"));
        assert!(!frames_after_hello(&lb).iter().any(|m| matches!(m, Msg::Ping { .. })));
    }
    assert_eq!(pings, PINGS as usize);
    assert_eq!(p.ds.clock_offset(), Some(7_000));
    assert_eq!(p.ls.clock_offset(), None);
}

/// Messages in `bytes`, skipping a leading Hello.
fn frames_after_hello(bytes: &[u8]) -> Vec<Msg> {
    let mut d = FrameDecoder::new();
    d.push(bytes);
    let mut out = Vec::new();
    while let Some(b) = d.next_frame().expect("frame") {
        if let Ok(m) = Msg::decode(&b) {
            out.push(m);
        }
    }
    out
}

// spec/sync-opens.md §2, spec/sync-streams.md §1: two world nodes that connect run Hello, proofs and
// pings and go quiet: no deadline left, a handful of deliveries.
#[test]
fn a_connection_goes_quiet_spec_sync_opens_2() {
    let mut w = fixture("session_two_bare", || {
        let mut w = World::new(0);
        w.add_bare_node();
        w.add_bare_node();
        w.run();
        w
    });
    let to = w.address(1);
    w.apply_as(0, vec![Out::Dial(ConnId(1), to)]);
    let before = w.deliveries;
    w.run();
    assert!(w.deliveries - before < 40, "{} deliveries", w.deliveries - before);
}

/// A Stream push carrying one blob of `n` bytes.
fn big_push(n: usize) -> Msg {
    let event = osis_proto::msg::Event::Added { blob_id: osis_base::BlobId([1; 32]), blob: Some(vec![0; n]), wrap: [0; osis_proto::msg::WRAP_LEN], stamp: None };
    Msg::Stream(Box::new(osis_proto::msg::Stream { events: vec![(osis_base::SyncId([1; 16]), event)], cursor: None, report: false, seq: 0 }))
}

// spec/sync-streams.md §1 (Closing): a peer that takes none of what this side writes is kept while
// the unwritten bytes stay within `WINDOW + 2 × (MAX_MESSAGE + 4)` plus this side's own in flight,
// and closed past it; the transport taking them makes room.
#[test]
fn peer_that_reads_nothing_closes_spec_sync_streams_1() {
    let (_, mut l, mut ls, _) = listener_with_scripted_dialer();
    let blob = vec![0u8; 8 << 20];
    let mut kept = None;
    for i in 1..=5u32 {
        let id = TOP_BIT | i;
        let fetch = Msg::Fetch { id, sync_id: osis_base::SyncId([1; 16]), max_reply: REPLY_BUDGET as u64, ids: vec![osis_base::BlobId([2; 32])] };
        let r = ls.receive(&frame(&fetch), &mut l.cx());
        assert!(r.is_ok(), "{i}: within the bound ({} MiB unwritten)", (i - 1) * 8);
        ls.answer(id, Msg::FetchReply { id, items: vec![osis_proto::msg::Fetched { blob_id: osis_base::BlobId([2; 32]), entry: Some((blob.clone(), [0; osis_proto::msg::WRAP_LEN], None)) }] });
        if i == 4 {
            kept = Some(ls.clone());
        }
    }
    let ping = frame(&Msg::Ping { id: 1, wall_ms: 0 });
    assert_eq!(ls.receive(&ping, &mut l.cx()).err(), Some(Close("the peer reads nothing")), "40 MiB unwritten");
    let mut ls = kept.expect("copy");
    assert!(ls.receive(&ping, &mut l.cx()).is_ok(), "32 MiB unwritten: kept");
}

// spec/sync-streams.md §1 (Stall): a frame trickled byte by byte moves the stall clock only when it
// is a reply to the oldest request out: the partial bytes of a push, or of a reply to another
// request, move nothing (a push counts once its frame is whole); and other bytes stop moving it
// past their bound, until it moves by its own events again.
#[test]
fn trickled_and_other_bytes_spec_sync_streams_1() {
    let mut p = quiet_pair();
    let stall = |at: u64| Some(WallMs(T0.0 + at + STALL_TIMEOUT_MS));
    let a = p.ds.request(To::Streams, pull(SMALL_REPLY as u64));
    let b = p.ds.request(To::Inbox, Msg::Ping { id: 0, wall_ms: 0 });
    p.ds.take_bytes();
    assert_eq!(p.ds.deadline(), stall(0));
    // one byte a millisecond
    let trickle = |p: &mut Pair, bytes: &[u8]| {
        for x in bytes {
            p.d.now = WallMs(p.d.now.0 + 1);
            p.ds.receive(&[*x], &mut p.d.cx()).expect("kept");
        }
        p.d.now.0 - T0.0
    };
    let push = frame(&Msg::Digest { digest: [3; 32] });
    trickle(&mut p, &push[..push.len() - 1]);
    assert_eq!(p.ds.deadline(), stall(0), "a push's partial bytes move nothing");
    let moved = trickle(&mut p, &push[push.len() - 1..]);
    assert_eq!(p.ds.deadline(), stall(moved), "a whole push does");
    trickle(&mut p, &frame(&Msg::Pong { id: b, wall_ms: 0 }));
    assert_eq!(p.ds.deadline(), stall(moved), "nor does a reply to another request, partial or whole");
    // other bytes past `WINDOW + 2 × (MAX_MESSAGE + 4) + WINDOW + 2 × MAX_MESSAGE + 4` (about 68 MiB)
    let big = frame(&big_push(8_000_000));
    let mut moves = 0;
    for i in 0..10u64 {
        p.d.now = WallMs(T0.0 + 1000 + i);
        p.ds.receive(&big, &mut p.d.cx()).expect("kept");
        if p.ds.deadline() == stall(1000 + i) {
            moves += 1;
        }
    }
    assert_eq!(moves, 8, "eight 8 MB pushes move it, the ninth passes the bound");
    p.d.now = WallMs(T0.0 + 2000);
    p.ds.receive(&frame(&pull_reply(a)), &mut p.d.cx()).expect("kept");
    assert_eq!(p.ds.deadline(), None, "answered: nothing out");
}

// spec/sync-streams.md §1 (Stall), spec/sync-transport.md §1: in a world, a dialer whose peer
// sends no Hello (mute), or never answers its Prove (deaf), closes the connection at its tick
// `STALL_TIMEOUT_MS` after it came up, not before; the close reaches the peer.
#[test]
fn silent_peers_close_at_the_tick_spec_sync_streams_1() {
    for deaf in [false, true] {
        let mut w = fixture("session_two_bare", || {
            let mut w = World::new(0);
            w.add_bare_node();
            w.add_bare_node();
            w.run();
            w
        });
        if deaf {
            w.net.deaf.insert(1);
        } else {
            w.net.mute.insert(1);
        }
        w.trace = true;
        let to = w.address(1);
        w.apply_as(0, vec![Out::Dial(ConnId(1), to)]);
        let closed = |w: &World| w.seen.iter().any(|s| matches!(s, crate::harness::Seen::Closed { node: 1, .. }));
        w.advance(STALL_TIMEOUT_MS - 1);
        assert!(!closed(&w), "deaf {deaf}: kept until the bound");
        w.advance(1);
        assert!(closed(&w), "deaf {deaf}: closed at the bound");
    }
}

// spec/sync-opens.md §1 (keep or close): the dialer's peer is quiet once a Ping sent while the
// dialer had nothing under way comes back with no other frame before it: whatever the peer sent
// before reading it (a test's Offer after a filter) has arrived. A frame between makes it ask again.
#[test]
fn a_quiet_peer_answers_the_probe_first_spec_sync_opens_1() {
    let mut p = quiet_pair();
    assert!(!p.ds.quiet(), "not known yet: a probe goes");
    assert!(!p.ds.quiet(), "one probe at a time");
    let probes = frames_after_hello(&p.ds.take_bytes());
    assert!(matches!(probes.as_slice(), [Msg::Ping { .. }]), "{probes:?}");
    // the peer pushed something before it read the probe
    p.ls.push_now(Msg::Digest { digest: [1; 32] });
    let pong = p.ls.receive(&frame(&probes[0]), &mut p.l.cx()).expect("kept");
    assert!(pong.is_empty());
    p.flow();
    assert!(!p.ds.quiet(), "a frame came before the Pong: asked again");
    p.flow();
    assert!(p.ds.quiet(), "nothing before the Pong");
}
