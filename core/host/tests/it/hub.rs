//! Scripted clients against hosts (`Hub` over `HostStore`): sessions through the protocol
//! engines, entries as node sync puts them (spec/sync.md §4-§9, spec/wire.md §11).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use osis_base::{BlobId, WallMs};
use osis_crypto::SigningSecret;
use osis_proto::msg::DeleteItem;
use osis_proto::*;
use osis_host::HostPolicy;

/// A header blind (spec/crypto.md §7).
const HB: [u8; 16] = [0x4b; 16];

// spec/sync.md §5: a registered label opens by its sync key on every connection; a genesis whose
// delete key does not hash to the label ID is refused
#[test]
fn register_and_open() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy::default());
    let (a, b) = (w.connect(h), w.connect(h));
    let l = Label::new(3);
    w.setup(a, &l);
    w.open(a, &l);
    w.open(b, &l);
    let other = Label::new(4);
    let ev = w.run(a, Command::Register { label: l.id, step: other.steps[0].clone(), claim_set: None });
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::MALFORMED, .. }]), "{ev:?}");
}

// spec/sync.md §5 (Register): a claim set must hash to the step's
// spec/sync.md §5 (claim set hash)
#[test]
fn claim_set_must_hash_to_the_steps_spec_sync_5() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy::default());
    let a = w.connect(h);
    let l = Label::new(3);
    let ev = w.run(a, Command::Register { label: l.id, step: l.steps[0].clone(), claim_set: Some(Label::new(4).sets[0].clone()) });
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::MALFORMED, .. }]), "{ev:?}");
    w.setup(a, &l);
}

// spec/sync.md §5: deposits by the deposit key within the budget; refused under another key
// (the depositor learning the code alone) or when full; a promoted one leaves the budget;
// deposited entries are flagged
#[test]
fn deposits_and_budget() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy::default());
    let a = w.connect(h);
    let l = Label::new(3);
    w.setup(a, &l);
    let max = 64 + 4 * l.sets[0].claims.len() as u64;
    let dk = l.head_keys().deposit.clone();
    assert_eq!(deposit_verified(&w, h, l.deposit(blob(0), &dk)), (Code::OK, true));
    assert_eq!(deposit_verified(&w, h, l.deposit(blob(1), &l.head_keys().write.clone())), (Code::REFUSED, false));
    for n in 1..max {
        assert_eq!(deposit(&w, h, l.deposit(blob(n), &dk)), Code::OK);
    }
    assert_eq!(deposit_verified(&w, h, l.deposit(blob(500), &dk)), (Code::BUDGET_FULL, true));
    // a writer promotes one: out of the budget
    assert_eq!(pull_all(&w, h, &l, [0]), vec![Code::OK]);
    assert_eq!(deposit(&w, h, l.deposit(blob(500), &dk)), Code::OK);
    let ids = live(&w, h, &l);
    let s = w.hubs[h].store();
    let deposited = ids.iter().filter(|b| s.entry(&l.id, b).unwrap().unwrap().stamp.is_none()).count() as u64;
    assert_eq!(deposited, max);
}

// spec/sync.md §5, spec/crypto.md §7: deletes by the delete key and by a level's delete key (level 3: write key, levels 1-2: sync key); tombstones refuse the identical blob for TOMBSTONE_LIFETIME
// spec/sync.md §5 (delete keys)
#[test]
fn deletes_and_tombstones() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy::default());
    let a = w.connect(h);
    let l = Label::new(3);
    w.setup(a, &l);
    w.open(a, &l);
    let dk = |t: &osis_crypto::Secret32| osis_crypto::DeleteSecret::derive(t);
    let commit = |level: u8, t: &osis_crypto::Secret32, n: u64| osis_crypto::commitment(level, &dk(t).verifying_key(), &salt(n), &HB).unwrap();
    let (t1, t3) = (s32(1), s32(3));
    let b3 = blob_with(10, 0, vec![commit(3, &t3, 10)]);
    let b1 = blob_with(11, 0, vec![commit(1, &t1, 11)]);
    let plain = blob(12);
    for b in [&b3, &b1, &plain] {
        assert_eq!(pull(&w, h, &l, &l.entry(b.clone())), Code::OK);
    }
    let k = l.head_keys().clone();
    let by = |b: &[u8], n: u64, level: u8, t: &osis_crypto::Secret32, signer: &SigningSecret| DeleteItem::sign_by(signer, &[(level, &dk(t))], &salt(n), &HB, &l.id, osis_label::blob_id(b)).unwrap();
    let plain_by = |signer: &SigningSecret| DeleteItem::sign(signer, &l.id, osis_label::blob_id(&plain)).unwrap();
    let ev = w.run(a, Command::Delete { label: l.id, items: vec![by(&b3, 10, 3, &t3, &k.sync), by(&b3, 10, 3, &t1, &k.write), by(&b1, 11, 1, &t1, &k.sync), plain_by(&k.write)] });
    assert_eq!(statuses(&ev), vec![Code::REFUSED, Code::REFUSED, Code::OK, Code::REFUSED]);
    let ev = w.run(a, Command::Delete { label: l.id, items: vec![by(&b3, 10, 3, &t3, &k.write), plain_by(&k.delete)] });
    assert_eq!(statuses(&ev), vec![Code::OK, Code::OK]);
    // deleting again is fine; the identical blob is refused while tombstoned, accepted after
    assert_eq!(statuses(&w.run(a, Command::Delete { label: l.id, items: vec![plain_by(&k.delete)] })), vec![Code::OK]);
    assert_eq!(pull(&w, h, &l, &l.entry(plain.clone())), Code::TOMBSTONED);
    w.advance(osis_base::format::TOMBSTONE_LIFETIME_MS);
    assert_eq!(pull(&w, h, &l, &l.entry(plain)), Code::OK);
    assert_eq!(live(&w, h, &l), vec![osis_label::blob_id(&blob(12))]);
}

// spec/sync.md §5: a delete runs at once and leaves a tombstone; expiry deletes at T with no
// tombstone; an expired prefix is refused
#[test]
fn deletes_and_expiry() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy::default());
    let a = w.connect(h);
    let l = Label::new(3);
    w.setup(a, &l);
    w.open(a, &l);
    let now = w.now();
    let expiring = blob_with(20, now + 3_000, vec![]);
    let plain = blob(21);
    for b in [&expiring, &plain] {
        assert_eq!(pull(&w, h, &l, &l.entry(b.clone())), Code::OK);
    }
    let dk = l.head_keys().delete.clone();
    let tid = osis_label::blob_id(&plain);
    assert_eq!(w.hubs[h].next_due(w.now()), Some(now + 3_000));
    w.advance(3_000);
    let eid = osis_label::blob_id(&expiring);
    assert_eq!(live(&w, h, &l), vec![tid]);
    assert!(!w.hubs[h].store().tombstoned(&l.id, &eid).unwrap());
    assert_eq!(statuses(&w.run(a, Command::Delete { label: l.id, items: vec![DeleteItem::sign(&dk, &l.id, tid).unwrap()] })), vec![Code::OK]);
    assert!(live(&w, h, &l).is_empty());
    assert!(w.hubs[h].store().tombstoned(&l.id, &tid).unwrap());
    assert_eq!(pull(&w, h, &l, &l.entry(expiring)), Code::EXPIRED);
}

/// A blob of class `c` (spec/wire.md §5).
fn classed(n: u8, c: osis_label::Class) -> Vec<u8> {
    classed_at(n, c, None, 20)
}

/// A blob of class `c` with prefix expiry `t` and `len` plaintext bytes.
fn classed_at(n: u8, c: osis_label::Class, t: Option<u64>, len: usize) -> Vec<u8> {
    let p = osis_label::Prefix::new([n; 16], t.map(WallMs), vec![]).unwrap().with_class(c);
    osis_label::frame(&p, &vec![n; len], &mut osis_crypto::SeededRng::from_seed([n; 32])).unwrap().1
}

/// A relay-only blob as a writer makes it: expiring `MAX_DRIFT` after now (spec/wire.md §5).
fn relay_blob(w: &World, n: u8) -> Vec<u8> {
    classed_at(n, osis_label::Class::Relay, Some(w.now() + osis_base::format::MAX_DRIFT_MS), 20)
}

// spec/sync.md §5: a stamped relay-only entry is passed on and held by nobody (no entry, no store
// row); an unstamped one is refused
#[test]
fn relays_are_held_by_nobody() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy::default());
    let a = w.connect(h);
    let l = Label::new(3);
    w.setup(a, &l);
    let stored_rows = w.hubs[h].store().rows().unwrap();
    let relay = relay_blob(&w, 5);
    let rid = osis_label::blob_id(&relay);
    assert!(matches!(pull_taken(&w, h, &l, &l.entry(relay.clone())), serving::Taken::Relay(r) if r.blob_id == rid));
    assert_eq!(w.hubs[h].store().rows().unwrap(), stored_rows, "relays store nothing");
    assert!(w.hubs[h].store().entry(&l.id, &rid).unwrap().is_none());
    assert_eq!(deposit(&w, h, l.deposit(relay, &l.head_keys().deposit.clone())), Code::REFUSED);
}

// spec/sync.md §5 (relay-only entries; security review H1): a reader or removed holder holding
// one stamped relay blob re-sends it in a loop: it is passed on once; a blob without an expiry,
// expired, expiring far ahead or over `MAX_RELAY_BLOB` is refused; past the label's relay rate
// fresh relays get code 4
#[test]
fn relay_replay_flood_bounded_spec_sync_5() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy { relays: 5, ..HostPolicy::default() });
    let a = w.connect(h);
    let l = Label::new(3);
    w.setup(a, &l);
    let relay = relay_blob(&w, 5);
    let passed = (0..200).filter(|_| matches!(pull_taken(&w, h, &l, &l.entry(relay.clone())), serving::Taken::Relay(_))).count();
    assert_eq!(pull(&w, h, &l, &l.entry(relay)), Code::OK, "seen: OK, not passed on");
    assert_eq!(passed, 1);
    let drift = osis_base::format::MAX_DRIFT_MS;
    let now = w.now();
    let bad = [
        (classed(6, osis_label::Class::Relay), Code::REFUSED),
        (classed_at(7, osis_label::Class::Relay, Some(now), 20), Code::EXPIRED),
        (classed_at(8, osis_label::Class::Relay, Some(now + 2 * drift + 1), 20), Code::REFUSED),
        (classed_at(9, osis_label::Class::Relay, Some(now + drift), osis_base::format::MAX_RELAY_BLOB), Code::TOO_LARGE),
    ];
    for (blob, code) in bad {
        assert_eq!(pull(&w, h, &l, &l.entry(blob)), code);
    }
    let taken: Vec<Option<Code>> = (10..16)
        .map(|n| match pull_taken(&w, h, &l, &l.entry(relay_blob(&w, n))) {
            serving::Taken::Relay(_) => None,
            serving::Taken::Code(c) => Some(c),
        })
        .collect();
    assert_eq!(taken, [None, None, None, None, Some(Code::RATE_LIMITED), Some(Code::RATE_LIMITED)], "the label's rate");
    assert!(w.hubs[h].store().rows().unwrap() < 100, "nothing stored");
}

// spec/sync.md §4, §5: ephemeral entries are held in memory: live like any, no store row,
// refused past the label's ephemeral cap (deposits too), gone after a restart
#[test]
fn ephemeral_entries_in_memory() {
    let mut w = World::new();
    // two entries fit with their per-entry overhead (about 1000 bytes each), three do not
    let policy = HostPolicy { ephemeral_bytes: 2_400, ..HostPolicy::default() };
    let h = w.add_hub(policy.clone());
    let a = w.connect(h);
    let l = Label::new(3);
    w.setup(a, &l);
    let rows = w.hubs[h].store().rows().unwrap();
    let eph: Vec<Vec<u8>> = (1..=3).map(|n| classed(n, osis_label::Class::Ephemeral)).collect();
    let codes: Vec<Code> = eph.iter().map(|e| pull(&w, h, &l, &l.entry(e.clone()))).collect();
    assert_eq!(codes, vec![Code::OK, Code::OK, Code::STORAGE_CAP], "the third is over the cap");
    assert_eq!(w.hubs[h].store().rows().unwrap(), rows, "no row");
    let charged = w.hubs[h].store().ephemeral_bytes(&l.id);
    assert!(charged > (eph[0].len() + eph[1].len()) as u64 && charged <= 2_400, "blobs and their overhead: {charged}");
    let ids: Vec<BlobId> = eph[..2].iter().map(|e| osis_label::blob_id(e)).collect();
    assert_eq!(live(&w, h, &l), sorted(ids.clone()));
    assert_eq!(deposit(&w, h, l.deposit(eph[2].clone(), &l.head_keys().deposit.clone())), Code::STORAGE_CAP);
    // a restart loses them; a durable entry stays
    assert_eq!(pull_all(&w, h, &l, [9]), vec![Code::OK]);
    w.restart(h, policy);
    assert_eq!(live(&w, h, &l), vec![bid(9)]);
    assert_eq!(w.hubs[h].store().ephemeral_bytes(&l.id), 0);
}

// spec/sync.md §4: the node's state is durable: after a restart the live set and the tombstones
// stand
#[test]
fn restart_keeps_state() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy::default());
    let a = w.connect(h);
    let l = Label::new(3);
    w.setup(a, &l);
    w.open(a, &l);
    assert_eq!(pull_all(&w, h, &l, 0..5), vec![Code::OK; 5]);
    let item = DeleteItem::sign(&l.head_keys().delete, &l.id, bid(0)).unwrap();
    assert_eq!(statuses(&w.run(a, Command::Delete { label: l.id, items: vec![item] })), vec![Code::OK]);
    w.restart(h, HostPolicy::default());
    w.advance(1_000);
    assert_eq!(live(&w, h, &l), sorted((1..5).map(bid).collect()));
    assert!(w.hubs[h].store().tombstoned(&l.id, &bid(0)).unwrap());
    assert_eq!(pull_all(&w, h, &l, [0]), vec![Code::TOMBSTONED]);
}

/// The connection hub `h` handed up last started (its `Up::Start`).
fn started(w: &World, h: usize) -> osis_host::ConnId {
    w.ups.iter().rev().find_map(|(x, c, u)| (*x == h && matches!(u, osis_host::Up::Start(_))).then_some(*c)).expect("a start")
}

// issues/net-one-peer.md step 3 (The hub calls up for nothing; spec/wire.md §11.2): a session's
// start with its binding (the listener's key, the dialer as the transport tells it) goes up at
// its Hello, an open of the hub's own sends nothing up, then node-kind messages unjudged in
// arrival order; node sync's answers come down and go out; the end goes up once the connection
// is gone
#[test]
fn node_kinds_go_up_answers_come_down() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy::default());
    let a = w.connect(h);
    let conn = started(&w, h);
    let Some((_, _, osis_host::Up::Start(b))) = w.ups.first() else { panic!("{:?}", w.ups) };
    assert_eq!((b.dialer, b.key, b.remote), ([0xc0 + a as u8; 32], hub_key(h), osis_host::Remote::key([0xe0 + a as u8; 32])));
    w.ups.clear();
    let l = Label::new(3);
    w.setup(a, &l);
    w.open(a, &l);
    assert!(w.ups.is_empty(), "{:?}", w.ups);
    w.send(a, Command::Prove(vec![]));
    w.pump();
    let pull = osis_proto::msg::Pull { id: osis_proto::msg::NODE_IDS | 7, cursor: None, joins: vec![], inline_limit: 0, max_reply: osis_proto::serving::REPLY_BUDGET as u64, follow: true, ephemeral: false };
    w.send(a, Command::Peer(Box::new(Message::Pull(Box::new(pull.clone())))));
    w.pump();
    let ups: Vec<Message> = w.ups.drain(..).map(|(_, c, u)| match u {
        osis_host::Up::Message(m) if c == conn => *m,
        u => panic!("{u:?}"),
    }).collect();
    assert!(matches!(&ups[..], [Message::Prove { .. }, Message::Pull(p)] if **p == pull), "{ups:?}");
    assert!(w.events[a].is_empty(), "nothing answered before node sync does");
    let prove_id = ups[0].id();
    w.down(h, vec![(conn, osis_host::Down::Message(Box::new(Message::Proved { id: prove_id, proofs: vec![] }))), (conn, osis_host::Down::Message(Box::new(Message::Error { id: pull.id, code: Code::NOT_ADMITTED })))]);
    let ev = std::mem::take(&mut w.events[a]);
    assert!(matches!(&ev[..], [ClientEvent::Proved { proofs }, ClientEvent::Peer(e)] if proofs.is_empty() && matches!(**e, Message::Error { id, code: Code::NOT_ADMITTED } if id == pull.id)), "{ev:?}");
    w.down(h, vec![(conn, osis_host::Down::Close)]);
    assert_eq!(w.ups, vec![(h, conn, osis_host::Up::End)]);
}

// spec/sync.md §6 (Stall): node sync's requests on a hub session go within the session's
// window and stall there as any requester's: unanswered past `STALL_TIMEOUT_MS`, the hub closes
// the connection and hands up its end
#[test]
fn a_stalled_node_request_closes_spec_sync_6() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy::default());
    let a = w.connect(h);
    let conn = started(&w, h);
    w.run(a, Command::Prove(vec![]));
    let Some((_, _, osis_host::Up::Message(prove))) = w.ups.last() else { panic!("{:?}", w.ups) };
    let id = prove.id();
    w.down(h, vec![(conn, osis_host::Down::Message(Box::new(Message::Proved { id, proofs: vec![] })))]);
    w.events[a].clear();
    w.ups.clear();
    let pull = osis_proto::msg::Pull { id: osis_proto::msg::NODE_IDS | 7, cursor: None, joins: vec![], inline_limit: 0, max_reply: osis_proto::serving::REPLY_BUDGET as u64, follow: true, ephemeral: false };
    w.down(h, vec![(conn, osis_host::Down::Message(Box::new(Message::Pull(Box::new(pull)))))]);
    assert!(matches!(&w.events[a][..], [ClientEvent::Peer(m)] if matches!(**m, Message::Pull(_))), "{:?}", w.events[a]);
    w.advance(osis_proto::client::STALL_TIMEOUT_MS - 1);
    assert!(w.ups.is_empty() && w.hubs[h].connections() == 1);
    w.advance(1);
    assert_eq!(w.ups, vec![(h, conn, osis_host::Up::End)]);
    assert_eq!(w.hubs[h].connections(), 0);
}
