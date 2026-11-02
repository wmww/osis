//! Client-port kinds (spec/wire.md §11.1-§11.2, notes/client-port.md §2): round trips, id rules,
//! the serving and client roles over a loopback.

use osis_base::Value;
use osis_proto::serving::REPLY_BUDGET;
use osis_proto::{ClientConfig, ClientEvent, ClientInput, ClientOutput, ClientSession, Code, Command, Hello, MAX_SUBS, MemoryLabelStore, Message, Outcome, Payload, ServingConfig, ServingInput, ServingOutput, ServingSession, encode_frame};
use osis_proto::client::SMALL_REPLY;

const T0: u64 = 1_700_000_000_000;

fn frame(m: &Message) -> Vec<u8> {
    encode_frame(&m.encode())
}

fn sent(out: &[ServingOutput]) -> Vec<Message> {
    out.iter().filter_map(|o| if let ServingOutput::Send(f) = o { Some(Message::decode(&f[4..]).unwrap()) } else { None }).collect()
}

fn requests(out: &[ServingOutput]) -> Vec<Message> {
    out.iter().filter_map(|o| if let ServingOutput::Request(m) = o { Some((**m).clone()) } else { None }).collect()
}

/// A serving session past the Hellos.
fn serving(port: bool) -> (ServingSession, MemoryLabelStore) {
    let mut s = ServingSession::new(ServingConfig { static_key: [1; 32], challenge: [2; 32] });
    if port {
        s = s.with_port();
    }
    let mut store = MemoryLabelStore::new([5; 32]);
    s.handle(T0, &mut store, ServingInput::Start);
    s.handle(T0, &mut store, ServingInput::Bytes(encode_frame(&Hello::new(T0, [3; 32]).encode())));
    (s, store)
}

fn ok(seq: u64, v: Value) -> Outcome {
    Outcome::Ok { seq, value: v }
}

// spec/wire.md §11.2: each client-port kind round-trips; Notify carries id 0, every request a nonzero id; max_reply within SMALL_REPLY..=REPLY_BUDGET
#[test]
fn kinds_round_trip_and_id_rules() {
    let small = SMALL_REPLY as u64;
    let msgs = [
        Message::Auth { id: 1, client_pk: None, session: [9; 16], sig: None },
        Message::Call { id: 2, max_reply: small, method: 3, args: vec![Value::Str("x".into()), Value::List(vec![])] },
        Message::Reply { id: 2, outcome: ok(7, Value::Int(5)) },
        Message::Reply { id: 2, outcome: Outcome::Err { code: 1, detail: vec![Value::Bytes(vec![0; 15])] } },
        Message::Sub { id: 4, max_reply: REPLY_BUDGET as u64, filter: Value::List(vec![Value::uint(0)]) },
        Message::Unsub { id: 5, sub: 4 },
        Message::Notify { sub: 4, payload: Payload::Delivery { seq: 8, value: Value::Bool(true) } },
        Message::Notify { sub: 4, payload: Payload::Lapsed },
        Message::Notify { sub: 4, payload: Payload::TooLarge { seq: 9, source: Value::Int(1) } },
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

// spec/wire.md §11.2: a Call before Auth is Error 1; after an answered Auth calls go up; a reply above max_reply is TooLarge; a node without the port (a host) answers Error 11
#[test]
fn serving_auth_call_and_reply_bound() {
    let (mut h, mut st) = serving(false);
    let out = h.handle(T0, &mut st, ServingInput::Bytes(frame(&Message::Auth { id: 1, client_pk: None, session: [0; 16], sig: None })));
    assert_eq!(sent(&out), vec![Message::Error { id: 1, code: Code::UNSUPPORTED }]);

    let (mut s, mut st) = serving(true);
    let call = Message::Call { id: 2, max_reply: SMALL_REPLY as u64, method: 0, args: vec![] };
    let out = s.handle(T0, &mut st, ServingInput::Bytes(frame(&call)));
    assert_eq!(sent(&out), vec![Message::Error { id: 2, code: Code::REFUSED }]);
    let auth = Message::Auth { id: 1, client_pk: None, session: [0; 16], sig: None };
    let out = s.handle(T0, &mut st, ServingInput::Bytes(frame(&auth)));
    assert_eq!(requests(&out), vec![auth]);
    assert!(s.none_opened());
    let out = s.handle(T0, &mut st, ServingInput::Reply { id: 1, reply: Ok(ok(0, Value::Bytes(vec![0; 16]))) });
    assert_eq!(sent(&out).len(), 1);
    assert!(s.authed() && !s.none_opened());
    let out = s.handle(T0, &mut st, ServingInput::Bytes(frame(&call)));
    assert_eq!(requests(&out), vec![call]);
    // a reply above max_reply goes as TooLarge with the bound
    let big = Value::Bytes(vec![0; SMALL_REPLY]);
    let out = s.handle(T0, &mut st, ServingInput::Reply { id: 2, reply: Ok(ok(1, big)) });
    assert_eq!(sent(&out), vec![Message::Reply { id: 2, outcome: Outcome::too_large(SMALL_REPLY) }]);
    // an answer to nothing asked is dropped
    assert!(s.handle(T0, &mut st, ServingInput::Reply { id: 2, reply: Ok(ok(1, Value::Int(0))) }).is_empty());
}

// spec/wire.md §11.1: a Sub's id stays reserved while live (a Sub reusing it is Error 2); Unsub is answered Ok and later Notifies for it are dropped; a lapsed Notify frees the id; at most MAX_SUBS live (code 4)
#[test]
fn serving_sub_ids_and_caps() {
    let (mut s, mut st) = serving(true);
    s.handle(T0, &mut st, ServingInput::Bytes(frame(&Message::Auth { id: 1, client_pk: None, session: [0; 16], sig: None })));
    s.handle(T0, &mut st, ServingInput::Reply { id: 1, reply: Ok(ok(0, Value::Bytes(vec![0; 16]))) });
    let sub = |id| Message::Sub { id, max_reply: SMALL_REPLY as u64, filter: Value::Int(0) };
    let out = s.handle(T0, &mut st, ServingInput::Bytes(frame(&sub(5))));
    assert_eq!(requests(&out).len(), 1);
    s.handle(T0, &mut st, ServingInput::Reply { id: 5, reply: Ok(ok(0, Value::Int(1))) });
    let out = s.handle(T0, &mut st, ServingInput::Bytes(frame(&sub(5))));
    assert_eq!(sent(&out), vec![Message::Error { id: 5, code: Code::MALFORMED }]);
    let d = |seq| Payload::Delivery { seq, value: Value::Int(2) };
    let out = s.handle(T0, &mut st, ServingInput::Notify(vec![(5, d(1)), (6, d(1))]));
    assert_eq!(sent(&out), vec![Message::Notify { sub: 5, payload: d(1) }]);
    // a Notify above the subscription's max_reply ends it
    let out = s.handle(T0, &mut st, ServingInput::Notify(vec![(5, Payload::Delivery { seq: 2, value: Value::Bytes(vec![0; SMALL_REPLY]) })]));
    assert_eq!(sent(&out), vec![Message::Notify { sub: 5, payload: Payload::Lapsed }]);
    assert_eq!(s.subs(), 0);
    // the id is free again; Unsub answers Ok and drops what follows
    s.handle(T0, &mut st, ServingInput::Bytes(frame(&sub(5))));
    s.handle(T0, &mut st, ServingInput::Reply { id: 5, reply: Ok(ok(0, Value::Int(1))) });
    let out = s.handle(T0, &mut st, ServingInput::Bytes(frame(&Message::Unsub { id: 7, sub: 5 })));
    assert_eq!(sent(&out), vec![Message::Ok { id: 7 }]);
    assert_eq!(requests(&out).len(), 1);
    assert!(s.handle(T0, &mut st, ServingInput::Notify(vec![(5, d(3))])).is_empty());
    // a refused Sub frees its id
    s.handle(T0, &mut st, ServingInput::Bytes(frame(&sub(8))));
    s.handle(T0, &mut st, ServingInput::Reply { id: 8, reply: Ok(Outcome::Err { code: 1, detail: vec![] }) });
    assert_eq!(s.subs(), 0);
    // the cap
    for id in 0..MAX_SUBS as u32 {
        let out = s.handle(T0, &mut st, ServingInput::Bytes(frame(&sub(100 + id))));
        assert_eq!(requests(&out).len(), 1);
        s.handle(T0, &mut st, ServingInput::Reply { id: 100 + id, reply: Ok(ok(0, Value::Int(1))) });
    }
    let out = s.handle(T0, &mut st, ServingInput::Bytes(frame(&sub(9))));
    assert_eq!(sent(&out), vec![Message::Error { id: 9, code: Code::RATE_LIMITED }]);
}

// spec/sync.md §6: Notifies wait for push room: Room comes at once with nothing unwritten, else when the transport took enough
#[test]
fn serving_room_follows_the_push_rule() {
    let (mut s, mut st) = serving(true);
    // flow control on, nothing unwritten
    s.handle(T0, &mut st, ServingInput::Taken(10_000));
    let out = s.handle(T0, &mut st, ServingInput::WantRoom);
    assert!(out.contains(&ServingOutput::Room { budget: REPLY_BUDGET }));
    s.handle(T0, &mut st, ServingInput::Bytes(frame(&Message::Auth { id: 1, client_pk: None, session: [0; 16], sig: None })));
    // a reply of nearly REPLY_BUDGET unwritten: no room until taken
    let out = s.handle(T0, &mut st, ServingInput::Reply { id: 1, reply: Ok(ok(0, Value::Bytes(vec![0; SMALL_REPLY - 64]))) });
    assert_eq!(sent(&out).len(), 1);
    let out = s.handle(T0, &mut st, ServingInput::WantRoom);
    let room = out.iter().find_map(|o| if let ServingOutput::Room { budget } = o { Some(*budget) } else { None }).unwrap();
    assert!(room < REPLY_BUDGET);
    assert!(!s.held());
}

/// Moves frames between a client and a serving session until both are quiet; returns the
/// client's events and the serving side's requests.
fn pump(c: &mut ClientSession, s: &mut ServingSession, st: &mut MemoryLabelStore, mut to_s: Vec<u8>) -> (Vec<ClientEvent>, Vec<Message>) {
    let (mut evs, mut reqs) = (Vec::new(), Vec::new());
    loop {
        if to_s.is_empty() {
            return (evs, reqs);
        }
        let so = s.handle(T0, st, ServingInput::Bytes(std::mem::take(&mut to_s)));
        reqs.extend(requests(&so));
        let mut to_c = Vec::new();
        for o in so {
            if let ServingOutput::Send(f) = o {
                to_c.extend(f);
            }
        }
        if to_c.is_empty() {
            return (evs, reqs);
        }
        for o in c.handle(T0, ClientInput::Bytes(to_c)) {
            match o {
                ClientOutput::Send(f) => to_s.extend(f),
                ClientOutput::Event(e) => evs.push(e),
                _ => {}
            }
        }
    }
}

fn client_sends(c: &mut ClientSession, cmd: Command) -> Vec<u8> {
    let mut b = Vec::new();
    for o in c.handle(T0, ClientInput::Command(cmd)) {
        if let ClientOutput::Send(f) = o {
            b.extend(f);
        }
    }
    b
}

fn serving_sends(out: Vec<ServingOutput>) -> Vec<u8> {
    out.into_iter().filter_map(|o| if let ServingOutput::Send(f) = o { Some(f) } else { None }).flatten().collect()
}

// spec/wire.md §11.1-§11.2: the client role: Auth, Call and Sub answered by token, Notifies delivered to the live subscription only, a live Sub's id never reused for another request, Unsub frees it once answered
#[test]
fn client_role_over_loopback() {
    let mut c = ClientSession::new(ClientConfig { peer_static_key: [1; 32], challenge: [4; 32] });
    let (mut s, mut st) = serving(true);
    let mut hello = Vec::new();
    for o in c.handle(T0, ClientInput::Start) {
        if let ClientOutput::Send(f) = o {
            hello.extend(f);
        }
    }
    let server_hello = encode_frame(&Hello::new(T0, [2; 32]).encode());
    let mut first = Vec::new();
    for o in c.handle(T0, ClientInput::Bytes(server_hello)) {
        if let ClientOutput::Send(f) = o {
            first.extend(f);
        }
    }
    // the pings
    pump(&mut c, &mut s, &mut st, first);
    let b = client_sends(&mut c, Command::Auth { token: 10, session: [7; 16] });
    let (_, reqs) = pump(&mut c, &mut s, &mut st, b);
    let [Message::Auth { id, session, client_pk: None, .. }] = reqs[..] else { panic!("{reqs:?}") };
    assert_eq!(session, [7; 16]);
    let f = serving_sends(s.handle(T0, &mut st, ServingInput::Reply { id, reply: Ok(ok(0, Value::Bytes(vec![1; 16]))) }));
    let evs: Vec<ClientOutput> = c.handle(T0, ClientInput::Bytes(f));
    assert!(evs.contains(&ClientOutput::Event(ClientEvent::Reply { token: 10, reply: Ok(ok(0, Value::Bytes(vec![1; 16]))) })));
    let b = client_sends(&mut c, Command::Sub { token: 11, max_reply: SMALL_REPLY as u64, filter: Value::Int(3) });
    let (_, reqs) = pump(&mut c, &mut s, &mut st, b);
    let [Message::Sub { id: sub, .. }] = reqs[..] else { panic!() };
    let f = serving_sends(s.handle(T0, &mut st, ServingInput::Reply { id: sub, reply: Ok(ok(1, Value::Int(0))) }));
    c.handle(T0, ClientInput::Bytes(f));
    // many calls: none takes the live Sub's id
    for t in 0..300u64 {
        let b = client_sends(&mut c, Command::Call { token: 1000 + t, max_reply: SMALL_REPLY as u64, method: 1, args: vec![] });
        let (_, reqs) = pump(&mut c, &mut s, &mut st, b);
        let [Message::Call { id, .. }] = reqs[..] else { panic!() };
        assert_ne!(id, sub);
        let f = serving_sends(s.handle(T0, &mut st, ServingInput::Reply { id, reply: Ok(ok(2, Value::Int(t as i64))) }));
        let out = c.handle(T0, ClientInput::Bytes(f));
        assert!(out.contains(&ClientOutput::Event(ClientEvent::Reply { token: 1000 + t, reply: Ok(ok(2, Value::Int(t as i64))) })));
    }
    let d = Payload::Delivery { seq: 3, value: Value::Int(9) };
    let f = serving_sends(s.handle(T0, &mut st, ServingInput::Notify(vec![(sub, d.clone())])));
    let out = c.handle(T0, ClientInput::Bytes(f));
    assert!(out.contains(&ClientOutput::Event(ClientEvent::Notify { token: 11, payload: d.clone() })));
    // after Unsub nothing more is delivered
    let b = client_sends(&mut c, Command::Unsub { token: 11 });
    let f = serving_sends(s.handle(T0, &mut st, ServingInput::Notify(vec![(sub, d.clone())])));
    let out = c.handle(T0, ClientInput::Bytes(f));
    assert!(!out.iter().any(|o| matches!(o, ClientOutput::Event(ClientEvent::Notify { .. }))));
    let (evs, reqs) = pump(&mut c, &mut s, &mut st, b);
    assert!(matches!(reqs[..], [Message::Unsub { .. }]));
    assert!(evs.is_empty());
    assert_eq!(s.subs(), 0);
}

// spec/sync.md §6, spec/wire.md §11.2: client-port requests handed out keep their allowance counted across inputs until answered: Auths pipelined one per input and never answered close the session past MAX_UNANSWERED, after at most that many bytes' worth were handed out
#[test]
fn unanswered_auths_close_the_session() {
    let (mut s, mut st) = serving(true);
    let mut handed = 0usize;
    let mut closed = false;
    for id in 1..=20_000u32 {
        let out = s.handle(T0, &mut st, ServingInput::Bytes(frame(&Message::Auth { id, client_pk: None, session: [0; 16], sig: None })));
        handed += requests(&out).len();
        if out.contains(&ServingOutput::Close) {
            closed = true;
            break;
        }
    }
    assert!(closed, "never closed after {handed} Auths");
    assert!(handed <= osis_proto::client::MAX_UNANSWERED / SMALL_REPLY, "{handed} handed out");
}

// spec/sync.md §6: Calls pipelined one per input: a client within WINDOW never reaches the bound, one past it is closed; answering frees the allowance
#[test]
fn unanswered_calls_past_the_window_close() {
    let (mut s, mut st) = serving(true);
    s.handle(T0, &mut st, ServingInput::Bytes(frame(&Message::Auth { id: 1, client_pk: None, session: [0; 16], sig: None })));
    s.handle(T0, &mut st, ServingInput::Reply { id: 1, reply: Ok(ok(0, Value::Bytes(vec![0; 16]))) });
    let call = |id| Message::Call { id, max_reply: SMALL_REPLY as u64, method: 0, args: vec![] };
    let per = frame(&call(1_000_000)).len() + SMALL_REPLY;
    let within = osis_proto::client::WINDOW / per;
    assert!(within >= 2);
    // answered ones free their allowance: a client within the window goes on without end
    for round in 0..4u32 {
        let base = 10 + round * 100_000;
        for id in base..base + within as u32 {
            let out = s.handle(T0, &mut st, ServingInput::Bytes(frame(&call(id))));
            assert_eq!(requests(&out).len(), 1, "within the window");
        }
        for id in base..base + within as u32 {
            s.handle(T0, &mut st, ServingInput::Reply { id, reply: Ok(ok(0, Value::Int(0))) });
        }
    }
    let mut closed = false;
    for id in 0..1000u32 {
        let out = s.handle(T0, &mut st, ServingInput::Bytes(frame(&call(1_000_000 + id))));
        if out.contains(&ServingOutput::Close) {
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
    let (mut s, mut st) = serving(true);
    let out = s.handle(T0, &mut st, ServingInput::Bytes(frame(&Message::Unsub { id: 3, sub: 7 })));
    assert_eq!(sent(&out), vec![Message::Error { id: 3, code: Code::REFUSED }]);
    assert!(requests(&out).is_empty());
}
