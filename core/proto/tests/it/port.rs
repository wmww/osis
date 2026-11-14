//! Client-port kinds (spec/wire.md §11.1-§11.2, notes/client-port.md §2): round trips, id rules,
//! the serving and client roles over a loopback.

use osis_base::Value;
use osis_proto::session::REPLY_BUDGET;
use osis_proto::examples::{Dialer, frames, up};
use osis_proto::{Code, Hello, MAX_SUBS, MemoryLabelStore, Message, Outcome, Payload, SessionConfig, SessionInput, SessionOutput, Session, encode_frame};
use osis_proto::window::SMALL_REPLY;

const T0: u64 = 1_700_000_000_000;

fn frame(m: &Message) -> Vec<u8> {
    encode_frame(&m.encode())
}

fn sent(out: &[SessionOutput]) -> Vec<Message> {
    out.iter().filter_map(|o| if let SessionOutput::Send(f) = o { Some(Message::decode(&f[4..]).unwrap()) } else { None }).collect()
}

fn requests(out: &[SessionOutput]) -> Vec<Message> {
    out.iter().filter_map(|o| if let SessionOutput::Request(m) = o { Some((**m).clone()) } else { None }).collect()
}

/// A listening session past the Hellos.
fn serving() -> (Session, MemoryLabelStore) {
    let mut s = Session::new(SessionConfig { listener_key: [1; 32], challenge: [2; 32], dialed: false });
    let mut store = MemoryLabelStore::new();
    s.handle(T0, &mut store, SessionInput::Start);
    s.handle(T0, &mut store, SessionInput::Bytes(encode_frame(&Hello::new(T0, [3; 32]).encode())));
    (s, store)
}

fn ok(v: Value) -> Outcome {
    Outcome::Ok { value: v }
}

// spec/wire.md §11.2: each client-port kind round-trips; Notify carries id 0, every request a nonzero id; max_reply within SMALL_REPLY..=REPLY_BUDGET
#[test]
fn kinds_round_trip_and_id_rules() {
    let small = SMALL_REPLY as u64;
    let msgs = [
        Message::Auth { id: 1, secret: None, session: [9; 16] },
        Message::Call { id: 2, max_reply: small, method: 3, args: vec![Value::Str("x".into()), Value::List(vec![])] },
        Message::Reply { id: 2, outcome: ok(Value::Int(5)) },
        Message::Reply { id: 2, outcome: Outcome::Err { code: 1, detail: vec![Value::Bytes(vec![0; 15])] } },
        Message::Sub { id: 4, max_reply: REPLY_BUDGET as u64, filter: Value::List(vec![Value::uint(0)]) },
        Message::Unsub { id: 5, sub: 4 },
        Message::Notify { sub: 4, payload: Payload::Delivery { value: Value::Bool(true) } },
        Message::Notify { sub: 4, payload: Payload::Lapsed },
        Message::Notify { sub: 4, payload: Payload::TooLarge { source: Value::Int(1) } },
    ];
    for m in msgs {
        assert_eq!(Message::decode(&m.encode()).unwrap(), m);
    }
    let raw = |v: Vec<Value>| osis_base::cbor::encode(&Value::List(v));
    let u = Value::uint;
    // a Notify with a request id, a Call with id 0, a max_reply out of range, sub id 0
    for bad in [
        raw(vec![u(29), u(3), u(4), Value::List(vec![u(1)])]),
        raw(vec![u(25), u(0), u(small), u(1), Value::List(vec![])]),
        raw(vec![u(25), u(1), u(small - 1), u(1), Value::List(vec![])]),
        raw(vec![u(25), u(1), u(REPLY_BUDGET as u64 + 1), u(1), Value::List(vec![])]),
        raw(vec![u(28), u(1), u(0)]),
        raw(vec![u(26), u(1), Value::List(vec![u(2)])]),
        raw(vec![u(29), u(0), u(4), Value::List(vec![u(1), u(1)])]),
    ] {
        assert!(Message::decode(&bad).is_err());
    }
}

// spec/wire.md §11.2: a Call before Auth is Error 1; after an answered Auth calls go up; a reply above max_reply is TooLarge
#[test]
fn serving_auth_call_and_reply_bound() {
    let (mut s, mut st) = serving();
    let call = Message::Call { id: 2, max_reply: SMALL_REPLY as u64, method: 0, args: vec![] };
    let out = s.handle(T0, &mut st, SessionInput::Bytes(frame(&call)));
    assert_eq!(sent(&out), vec![Message::Error { id: 2, code: Code::REFUSED }]);
    let auth = Message::Auth { id: 1, secret: None, session: [0; 16] };
    let out = s.handle(T0, &mut st, SessionInput::Bytes(frame(&auth)));
    assert_eq!(requests(&out), vec![auth]);
    assert!(!s.authed());
    let out = s.handle(T0, &mut st, SessionInput::Reply { id: 1, reply: Ok(ok(Value::Bytes(vec![0; 16]))) });
    assert_eq!(sent(&out).len(), 1);
    assert!(s.authed());
    let out = s.handle(T0, &mut st, SessionInput::Bytes(frame(&call)));
    assert_eq!(requests(&out), vec![call]);
    // a reply above max_reply goes as TooLarge with the bound
    let big = Value::Bytes(vec![0; SMALL_REPLY]);
    let out = s.handle(T0, &mut st, SessionInput::Reply { id: 2, reply: Ok(ok(big)) });
    assert_eq!(sent(&out), vec![Message::Reply { id: 2, outcome: Outcome::too_large(SMALL_REPLY) }]);
    // an answer to nothing asked is dropped
    assert!(s.handle(T0, &mut st, SessionInput::Reply { id: 2, reply: Ok(ok(Value::Int(0))) }).is_empty());
}

// spec/wire.md §11.1: a Sub's id stays reserved while live (a Sub reusing it is Error 2); Unsub is answered Ok and later Notifies for it are dropped; a lapsed Notify frees the id; at most MAX_SUBS live (code 4)
#[test]
fn serving_sub_ids_and_caps() {
    let (mut s, mut st) = serving();
    s.handle(T0, &mut st, SessionInput::Bytes(frame(&Message::Auth { id: 1, secret: None, session: [0; 16] })));
    s.handle(T0, &mut st, SessionInput::Reply { id: 1, reply: Ok(ok(Value::Bytes(vec![0; 16]))) });
    let sub = |id| Message::Sub { id, max_reply: SMALL_REPLY as u64, filter: Value::Int(0) };
    let out = s.handle(T0, &mut st, SessionInput::Bytes(frame(&sub(5))));
    assert_eq!(requests(&out).len(), 1);
    s.handle(T0, &mut st, SessionInput::Reply { id: 5, reply: Ok(ok(Value::Int(1))) });
    let out = s.handle(T0, &mut st, SessionInput::Bytes(frame(&sub(5))));
    assert_eq!(sent(&out), vec![Message::Error { id: 5, code: Code::MALFORMED }]);
    let d = || Payload::Delivery { value: Value::Int(2) };
    let out = s.handle(T0, &mut st, SessionInput::Notify(vec![(5, d()), (6, d())]));
    assert_eq!(sent(&out), vec![Message::Notify { sub: 5, payload: d() }]);
    // a Notify above the subscription's max_reply ends it
    let out = s.handle(T0, &mut st, SessionInput::Notify(vec![(5, Payload::Delivery { value: Value::Bytes(vec![0; SMALL_REPLY]) })]));
    assert_eq!(sent(&out), vec![Message::Notify { sub: 5, payload: Payload::Lapsed }]);
    assert_eq!(s.subs(), 0);
    // the id is free again; Unsub answers Ok and drops what follows
    s.handle(T0, &mut st, SessionInput::Bytes(frame(&sub(5))));
    s.handle(T0, &mut st, SessionInput::Reply { id: 5, reply: Ok(ok(Value::Int(1))) });
    let out = s.handle(T0, &mut st, SessionInput::Bytes(frame(&Message::Unsub { id: 7, sub: 5 })));
    assert_eq!(sent(&out), vec![Message::Ok { id: 7 }]);
    assert_eq!(requests(&out).len(), 1);
    assert!(s.handle(T0, &mut st, SessionInput::Notify(vec![(5, d())])).is_empty());
    // a refused Sub frees its id
    s.handle(T0, &mut st, SessionInput::Bytes(frame(&sub(8))));
    s.handle(T0, &mut st, SessionInput::Reply { id: 8, reply: Ok(Outcome::Err { code: 1, detail: vec![] }) });
    assert_eq!(s.subs(), 0);
    // the cap
    for id in 0..MAX_SUBS as u32 {
        let out = s.handle(T0, &mut st, SessionInput::Bytes(frame(&sub(100 + id))));
        assert_eq!(requests(&out).len(), 1);
        s.handle(T0, &mut st, SessionInput::Reply { id: 100 + id, reply: Ok(ok(Value::Int(1))) });
    }
    let out = s.handle(T0, &mut st, SessionInput::Bytes(frame(&sub(9))));
    assert_eq!(sent(&out), vec![Message::Error { id: 9, code: Code::RATE_LIMITED }]);
}

// spec/sync-judgement.md §2: Notifies wait for push room: Room comes at once with nothing unwritten, else when the transport took enough
#[test]
fn serving_room_follows_the_push_rule() {
    let (mut s, mut st) = serving();
    // flow control on, nothing unwritten
    s.handle(T0, &mut st, SessionInput::Taken(10_000));
    let out = s.handle(T0, &mut st, SessionInput::WantRoom);
    assert!(out.contains(&SessionOutput::Room { budget: REPLY_BUDGET }));
    s.handle(T0, &mut st, SessionInput::Bytes(frame(&Message::Auth { id: 1, secret: None, session: [0; 16] })));
    // a reply of nearly REPLY_BUDGET unwritten: no room until taken
    let out = s.handle(T0, &mut st, SessionInput::Reply { id: 1, reply: Ok(ok(Value::Bytes(vec![0; SMALL_REPLY - 64]))) });
    assert_eq!(sent(&out).len(), 1);
    let out = s.handle(T0, &mut st, SessionInput::WantRoom);
    let room = out.iter().find_map(|o| if let SessionOutput::Room { budget } = o { Some(*budget) } else { None }).unwrap();
    assert!(room < REPLY_BUDGET);
    assert!(!s.held());
}

/// Moves frames between a dialer and a listening session until both are quiet; returns what the
/// dialer's session handed up and the listener's requests.
fn pump(c: &mut Dialer, s: &mut Session, st: &mut MemoryLabelStore, mut to_s: Vec<u8>) -> (Vec<Message>, Vec<Message>) {
    let (mut ups, mut reqs) = (Vec::new(), Vec::new());
    loop {
        if to_s.is_empty() {
            return (ups, reqs);
        }
        let so = s.handle(T0, st, SessionInput::Bytes(std::mem::take(&mut to_s)));
        reqs.extend(requests(&so));
        let to_c: Vec<u8> = frames(&so).concat();
        if to_c.is_empty() {
            return (ups, reqs);
        }
        let co = c.bytes(T0, to_c);
        ups.extend(up(&co));
        to_s = frames(&co).concat();
    }
}

/// A request of the dialer's upper layer under the id it picks: the id and the bytes it sent.
fn client_sends(c: &mut Dialer, m: impl FnOnce(u32) -> Message) -> (u32, Vec<u8>) {
    let (id, out) = c.request(T0, m);
    (id, frames(&out).concat())
}

fn serving_sends(out: Vec<SessionOutput>) -> Vec<u8> {
    frames(&out).concat()
}

// spec/wire.md §11.1-§11.2: the client role over a dialer session: Auth, Call and Sub go out
// under the upper layer's ids and their answers come up by id; Notifies come up for the live
// subscription; once its Unsub is answered Ok none follows
#[test]
fn client_role_over_loopback() {
    let mut c = Dialer::new([1; 32], [4; 32]);
    let (mut s, mut st) = serving();
    c.start(T0);
    c.bytes(T0, encode_frame(&Hello::new(T0, [2; 32]).encode()));
    let (auth, b) = client_sends(&mut c, |id| Message::Auth { id, secret: None, session: [7; 16] });
    let (_, reqs) = pump(&mut c, &mut s, &mut st, b);
    assert_eq!(reqs, vec![Message::Auth { id: auth, secret: None, session: [7; 16] }]);
    let f = serving_sends(s.handle(T0, &mut st, SessionInput::Reply { id: auth, reply: Ok(ok(Value::Bytes(vec![1; 16]))) }));
    assert_eq!(up(&c.bytes(T0, f)), vec![Message::Reply { id: auth, outcome: ok(Value::Bytes(vec![1; 16])) }]);
    let (sub, b) = client_sends(&mut c, |id| Message::Sub { id, max_reply: SMALL_REPLY as u64, filter: Value::Int(3) });
    let (_, reqs) = pump(&mut c, &mut s, &mut st, b);
    assert!(matches!(reqs[..], [Message::Sub { id, .. }] if id == sub), "{reqs:?}");
    let f = serving_sends(s.handle(T0, &mut st, SessionInput::Reply { id: sub, reply: Ok(ok(Value::Int(0))) }));
    assert_eq!(up(&c.bytes(T0, f)), vec![Message::Reply { id: sub, outcome: ok(Value::Int(0)) }]);
    for t in 0..30i64 {
        let (call, b) = client_sends(&mut c, |id| Message::Call { id, max_reply: SMALL_REPLY as u64, method: 1, args: vec![] });
        let (_, reqs) = pump(&mut c, &mut s, &mut st, b);
        assert!(matches!(reqs[..], [Message::Call { id, .. }] if id == call), "{reqs:?}");
        let f = serving_sends(s.handle(T0, &mut st, SessionInput::Reply { id: call, reply: Ok(ok(Value::Int(t))) }));
        assert_eq!(up(&c.bytes(T0, f)), vec![Message::Reply { id: call, outcome: ok(Value::Int(t)) }]);
    }
    let d = Payload::Delivery { value: Value::Int(9) };
    let f = serving_sends(s.handle(T0, &mut st, SessionInput::Notify(vec![(sub, d.clone())])));
    assert_eq!(up(&c.bytes(T0, f)), vec![Message::Notify { sub, payload: d.clone() }]);
    // after Unsub nothing more is delivered
    let (unsub, b) = client_sends(&mut c, |id| Message::Unsub { id, sub });
    let (ups, reqs) = pump(&mut c, &mut s, &mut st, b);
    assert!(matches!(reqs[..], [Message::Unsub { .. }]));
    assert_eq!(ups, vec![Message::Ok { id: unsub }]);
    assert_eq!(s.subs(), 0);
    assert!(s.handle(T0, &mut st, SessionInput::Notify(vec![(sub, d)])).is_empty());
    assert!(!c.session.is_closed() && c.session.stall_at().is_none());
}

// spec/sync-judgement.md §2, spec/wire.md §11.2: client-port requests handed out keep their allowance counted across inputs until answered: Auths pipelined one per input and never answered close the session past MAX_UNANSWERED, after at most that many bytes' worth were handed out
#[test]
fn unanswered_auths_close_the_session() {
    let (mut s, mut st) = serving();
    let mut handed = 0usize;
    let mut closed = false;
    for id in 1..=20_000u32 {
        let out = s.handle(T0, &mut st, SessionInput::Bytes(frame(&Message::Auth { id, secret: None, session: [0; 16] })));
        handed += requests(&out).len();
        if out.contains(&SessionOutput::Close) {
            closed = true;
            break;
        }
    }
    assert!(closed, "never closed after {handed} Auths");
    assert!(handed <= osis_proto::window::MAX_UNANSWERED / SMALL_REPLY, "{handed} handed out");
}

// spec/sync-judgement.md §2: Calls pipelined one per input: a client within WINDOW never reaches the bound, one past it is closed; answering frees the allowance
#[test]
fn unanswered_calls_past_the_window_close() {
    let (mut s, mut st) = serving();
    s.handle(T0, &mut st, SessionInput::Bytes(frame(&Message::Auth { id: 1, secret: None, session: [0; 16] })));
    s.handle(T0, &mut st, SessionInput::Reply { id: 1, reply: Ok(ok(Value::Bytes(vec![0; 16]))) });
    let call = |id| Message::Call { id, max_reply: SMALL_REPLY as u64, method: 0, args: vec![] };
    let per = frame(&call(1_000_000)).len() + SMALL_REPLY;
    let within = osis_proto::window::WINDOW / per;
    assert!(within >= 2);
    // answered ones free their allowance: a client within the window goes on without end
    for round in 0..4u32 {
        let base = 10 + round * 100_000;
        for id in base..base + within as u32 {
            let out = s.handle(T0, &mut st, SessionInput::Bytes(frame(&call(id))));
            assert_eq!(requests(&out).len(), 1, "within the window");
        }
        for id in base..base + within as u32 {
            s.handle(T0, &mut st, SessionInput::Reply { id, reply: Ok(ok(Value::Int(0))) });
        }
    }
    let mut closed = false;
    for id in 0..2 * osis_proto::window::MAX_UNANSWERED as u32 / per as u32 {
        let out = s.handle(T0, &mut st, SessionInput::Bytes(frame(&call(1_000_000 + id))));
        if out.contains(&SessionOutput::Close) {
            closed = true;
            break;
        }
    }
    assert!(closed);
    assert!(s.is_closed());
}

// spec/wire.md §11.2: an Unsub before an answered Auth is Error 1 and never handed out
#[test]
fn unsub_before_auth_is_refused() {
    let (mut s, mut st) = serving();
    let out = s.handle(T0, &mut st, SessionInput::Bytes(frame(&Message::Unsub { id: 3, sub: 7 })));
    assert_eq!(sent(&out), vec![Message::Error { id: 3, code: Code::REFUSED }]);
    assert!(requests(&out).is_empty());
}
