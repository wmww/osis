//! Scripted clients against blind nodes (`Hub` over `BackendStore`): every operation through the
//! protocol engines (spec/sync.md §4-§9, spec/wire.md §11).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::*;
use osis_core::{BlobId, WallMs};
use osis_crypto::SigningSecret;
use osis_proto::msg::{DeleteItem, PublishAuth, PublishKey, Wrap};
use osis_proto::*;
use osis_server::Policy;
use osis_store::Backend;

// spec/sync.md §5, §6: register, open, upload inline with Sync, download by replay, cursor sync with gained and want
#[test]
fn register_open_sync_download() {
    let mut w = World::new();
    let h = w.add_hub(Policy::default());
    let (a, b) = (w.connect(h), w.connect(h));
    let l = Label::new(3);
    w.setup(a, &l);
    w.open(a, &l);
    w.open(b, &l);
    let ev = w.run(a, sync(l.id, None, (0..30).map(|n| l.entry(blob(n))).collect(), vec![]));
    assert_eq!(statuses(&ev), vec![Code::OK; 30]);
    let ev = w.run(b, sync(l.id, None, vec![], vec![]));
    let (evs, cursor) = events_of(&ev);
    assert_eq!(added(&evs), sorted((0..30).map(bid).collect()));
    let Event::Added { blob: Some(bytes), wrap, stamp: Some(s), .. } = &evs[0] else { panic!() };
    let e = l.entry(bytes.clone());
    assert_eq!((*wrap, *s), (e.wrap, e.stamp));
    w.run(a, Command::Upload { label: l.id, entries: (30..35).map(|n| l.entry(blob(n))).collect() });
    let ev = w.run(b, sync(l.id, cursor, vec![], vec![bid(32), bid(100)]));
    assert_eq!(added(&events_of(&ev).0), [30, 31, 33, 34].map(bid));
    assert!(ev.contains(&ClientEvent::Want { label: l.id, ids: vec![bid(100)] }));
    // a genesis whose delete key does not hash to the label ID is refused; a known label's genesis gets the head
    let other = Label::new(4);
    let ev = w.run(a, Command::Register { label: l.id, step: other.steps[0].clone(), claim_set: None });
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::MALFORMED, .. }]), "{ev:?}");
}

// spec/sync.md §5: a claim set must hash to the step's; claims and static entries open at the head
// spec/sync.md §5 (claim set hash)
#[test]
fn claims_and_static_entries() {
    let mut w = World::new();
    let h = w.add_hub(Policy::default());
    let a = w.connect(h);
    let l = Label::new(3);
    let ev = w.run(a, Command::Register { label: l.id, step: l.steps[0].clone(), claim_set: Some(Label::new(4).sets[0].clone()) });
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::MALFORMED, .. }]), "{ev:?}");
    w.setup(a, &l);
    let claim = l.steps[0].claim_key(&l.reader).unwrap();
    let ev = w.run(a, Command::Open { label: l.id, key: OpenKey::Claim { step: l.steps[0].id(), key: claim } });
    assert!(matches!(&ev[..], [ClientEvent::Opened { entry_box: None, .. }]), "{ev:?}");
    let ka = SigningSecret::from_seed(&s32(0x32));
    let ev = w.run(a, Command::Open { label: l.id, key: OpenKey::Static(ka) });
    assert!(matches!(&ev[..], [ClientEvent::Opened { entry_box: Some(_), .. }]), "{ev:?}");
}

// spec/sync.md §5: deposits by the deposit key within the budget, reported in the reply; refused under another key or when full; deposited entries are flagged
// spec/sync.md §5 (deposit refusals)
#[test]
fn deposits_and_budget() {
    let mut w = World::new();
    let h = w.add_hub(Policy::default());
    let a = w.connect(h);
    let l = Label::new(3);
    w.setup(a, &l);
    let max = 64 + 4 * l.sets[0].claims.len() as u64;
    let dk = l.head_keys().deposit.clone();
    let ev = w.run(a, l.deposit(blob(0), &dk));
    assert!(matches!(&ev[..], [ClientEvent::Budget { code: Code::OK, entries_left, .. }] if *entries_left == max - 1), "{ev:?}");
    let ev = w.run(a, l.deposit(blob(1), &l.head_keys().write.clone()));
    assert_eq!(statuses(&ev), vec![Code::REFUSED]);
    for n in 1..max {
        w.run(a, l.deposit(blob(n), &dk));
    }
    let ev = w.run(a, l.deposit(blob(500), &dk));
    assert!(matches!(&ev[..], [ClientEvent::Budget { code: Code::BUDGET_FULL, entries_left: 0, .. }]), "{ev:?}");
    // a writer promotes one: out of the budget
    assert_eq!(statuses(&w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(blob(0))] })), vec![Code::OK]);
    assert_eq!(statuses(&w.run(a, l.deposit(blob(500), &dk))), vec![Code::OK]);
    w.open(a, &l);
    let (evs, _) = events_of(&w.run(a, sync(l.id, None, vec![], vec![])));
    let deposited = evs.iter().filter(|e| matches!(e, Event::Added { stamp: None, .. })).count() as u64;
    assert_eq!(deposited, max);
}

// spec/sync.md §5, spec/crypto.md §7: deletes by the delete key and by a level's delete key (level 3: write key, levels 1-2: sync key); tombstones refuse the identical blob for TOMBSTONE_LIFETIME
// spec/sync.md §5 (delete keys)
#[test]
fn deletes_and_tombstones() {
    let mut w = World::new();
    let h = w.add_hub(Policy::default());
    let a = w.connect(h);
    let l = Label::new(3);
    w.setup(a, &l);
    w.open(a, &l);
    let dk = |t: &osis_crypto::Secret32| osis_crypto::DeleteSecret::derive(t);
    let commit = |level: u8, t: &osis_crypto::Secret32, n: u64| osis_crypto::commitment(level, &dk(t).verifying_key(), &salt(n)).unwrap();
    let (t1, t3) = (s32(1), s32(3));
    let b3 = blob_with(10, 0, vec![commit(3, &t3, 10)]);
    let b1 = blob_with(11, 0, vec![commit(1, &t1, 11)]);
    let plain = blob(12);
    w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(b3.clone()), l.entry(b1.clone()), l.entry(plain.clone())] });
    let k = l.head_keys().clone();
    let by = |b: &[u8], n: u64, level: u8, t: &osis_crypto::Secret32, signer: &SigningSecret| DeleteItem::sign_by(signer, &dk(t), level, &salt(n), &l.id, osis_label::blob_id(b), None).unwrap();
    let plain_by = |signer: &SigningSecret| DeleteItem::sign(signer, &l.id, osis_label::blob_id(&plain), None).unwrap();
    let ev = w.run(a, Command::Delete { label: l.id, items: vec![by(&b3, 10, 3, &t3, &k.sync), by(&b3, 10, 3, &t1, &k.write), by(&b1, 11, 1, &t1, &k.sync), plain_by(&k.write)] });
    assert_eq!(statuses(&ev), vec![Code::REFUSED, Code::REFUSED, Code::OK, Code::REFUSED]);
    let ev = w.run(a, Command::Delete { label: l.id, items: vec![by(&b3, 10, 3, &t3, &k.write), plain_by(&k.delete)] });
    assert_eq!(statuses(&ev), vec![Code::OK, Code::OK]);
    // deleting again is fine; the identical blob is refused while tombstoned, accepted after
    assert_eq!(statuses(&w.run(a, Command::Delete { label: l.id, items: vec![plain_by(&k.delete)] })), vec![Code::OK]);
    assert_eq!(statuses(&w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(plain.clone())] })), vec![Code::TOMBSTONED]);
    w.advance(osis_core::format::TOMBSTONE_LIFETIME_MS);
    assert_eq!(statuses(&w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(plain)] })), vec![Code::OK]);
    let ids = osis_proto::LabelStore::live_ids(w.hubs[h].store(), &l.id).unwrap();
    assert_eq!(ids, vec![osis_label::blob_id(&blob(12))]);
}

// spec/sync.md §5, §8: a timed delete (earliest wins) runs at its time with Pending then Deleted events, pushed to subscribers; expiry deletes at T with no event and no tombstone
#[test]
fn timed_deletes_and_expiry() {
    let mut w = World::new();
    let h = w.add_hub(Policy::default());
    let (a, b) = (w.connect(h), w.connect(h));
    let l = Label::new(3);
    w.setup(a, &l);
    w.open(a, &l);
    w.open(b, &l);
    let now = w.now();
    let expiring = blob_with(20, now + 3_000, vec![]);
    let timed = blob(21);
    w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(expiring.clone()), l.entry(timed.clone())] });
    let (_, cursor) = events_of(&w.run(b, sync(l.id, None, vec![], vec![])));
    w.run(b, Command::Subscribe { labels: vec![l.id] });
    let dk = l.head_keys().delete.clone();
    let tid = osis_label::blob_id(&timed);
    let item = |at: u64| DeleteItem::sign(&dk, &l.id, tid, Some(WallMs(at))).unwrap();
    assert_eq!(statuses(&w.run(a, Command::Delete { label: l.id, items: vec![item(now + 10_000), item(now + 5_000)] })), vec![Code::OK, Code::OK]);
    assert_eq!(statuses(&w.run(a, Command::Delete { label: l.id, items: vec![item(now + 8_000)] })), vec![Code::OK]);
    let (pushed, _) = events_of(&w.take(b));
    assert_eq!(pushed, vec![Event::Pending { blob_id: tid, at: now + 10_000 }, Event::Pending { blob_id: tid, at: now + 5_000 }]);
    assert_eq!(w.hubs[h].next_due(w.now()), Some(now + 3_000));
    w.advance(3_000);
    assert!(w.take(b).is_empty(), "expiry pushes nothing");
    let eid = osis_label::blob_id(&expiring);
    assert_eq!(osis_proto::LabelStore::live_ids(w.hubs[h].store(), &l.id).unwrap(), vec![tid]);
    assert!(!osis_proto::LabelStore::tombstoned(w.hubs[h].store(), &l.id, &eid).unwrap());
    w.advance(2_000);
    let (pushed, _) = events_of(&w.take(b));
    assert_eq!(pushed, vec![Event::Deleted(tid)]);
    let (evs, _) = events_of(&w.run(b, sync(l.id, cursor, vec![], vec![])));
    assert_eq!(evs, vec![Event::Pending { blob_id: tid, at: now + 10_000 }, Event::Pending { blob_id: tid, at: now + 5_000 }, Event::Deleted(tid)]);
    // an expired prefix is refused on upload
    assert_eq!(statuses(&w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(expiring)] })), vec![Code::EXPIRED]);
}

// spec/sync.md §6, spec/wire.md §11.2: a cursor below the log horizon gets Error 10; range reconciliation finds both differences
#[test]
fn horizon_falls_back_to_reconciliation() {
    let mut w = World::new();
    let h = w.add_hub(Policy { log_keep: 64, ..Policy::default() });
    let (a, b) = (w.connect(h), w.connect(h));
    let l = Label::new(3);
    w.setup(a, &l);
    w.open(a, &l);
    w.open(b, &l);
    w.run(a, Command::Upload { label: l.id, entries: (0..100).map(|n| l.entry(blob(n))).collect() });
    let (_, cursor) = events_of(&w.run(b, sync(l.id, None, vec![], vec![])));
    w.run(a, Command::Upload { label: l.id, entries: (100..200).map(|n| l.entry(blob(n))).collect() });
    let ev = w.run(b, sync(l.id, cursor, vec![l.entry(blob(900))], vec![]));
    assert!(ev.contains(&ClientEvent::NeedReconcile { label: l.id }), "{ev:?}");
    assert_eq!(statuses(&ev), vec![Code::OK]);
    let ids: Vec<BlobId> = (0..100).chain(500..505).chain([900]).map(bid).collect();
    let ev = w.run(b, Command::Reconcile { label: l.id, ids });
    assert_eq!(ev, vec![ClientEvent::Reconciled { label: l.id, need: sorted((100..200).map(bid).collect()), have: sorted((500..505).map(bid).collect()) }]);
    // a fresh replay still ends with a cursor that works
    let (_, c) = events_of(&w.run(b, Command::Sync { label: l.id, cursor: None, inline_limit: 0, entries: vec![], gained: vec![] }));
    w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(blob(901))] });
    assert_eq!(added(&events_of(&w.run(b, sync(l.id, c, vec![], vec![]))).0), vec![bid(901)]);
}

// spec/sync.md §8, §9: subscriptions push new events in the cursor-reply format; signals under the write or deposit key reach the other subscribers, never the sender; nothing is stored
#[test]
fn subscriptions_and_signals() {
    let mut w = World::new();
    let h = w.add_hub(Policy { signals: 2, ..Policy::default() });
    let (a, b, c) = (w.connect(h), w.connect(h), w.connect(h));
    let l = Label::new(3);
    w.setup(a, &l);
    for x in [a, b, c] {
        w.open(x, &l);
    }
    let ev = w.run(b, Command::Subscribe { labels: vec![l.id, osis_core::LabelId([0xee; 16])] });
    assert_eq!(ev, vec![ClientEvent::Subscribed { labels: vec![l.id, osis_core::LabelId([0xee; 16])], codes: vec![Code::OK, Code::NOT_OPENED] }]);
    w.run(a, Command::Subscribe { labels: vec![l.id] });
    w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(blob(1))] });
    let (evs, cursor) = events_of(&w.take(b));
    assert_eq!(added(&evs), vec![bid(1)]);
    assert!(cursor.is_some());
    // a new head is pushed too
    let mut l2 = l;
    let (child, set) = l2.rotate(20);
    w.run(a, Command::Register { label: l2.id, step: child.clone(), claim_set: Some(set) });
    assert_eq!(events_of(&w.take(b)).0, vec![Event::Head(child)]);
    w.take(a);
    let backend_rows = w.backends[h].scan(&[], None, usize::MAX).unwrap().len();
    let env = vec![0x5a; 100];
    let wrap: Wrap = [3; 49];
    let auth = PublishAuth::sign(PublishKey::Write, &l2.head_keys().write, &l2.id, &osis_label::blob_id(&env), &wrap);
    w.run(a, Command::Signal { label: l2.id, blob: env.clone(), wrap, auth: auth.clone() });
    assert_eq!(w.take(b), vec![ClientEvent::Signal { label: l2.id, blob: env.clone(), wrap, auth: auth.clone() }]);
    assert!(w.take(a).is_empty() && w.take(c).is_empty(), "not the sender, not unsubscribed");
    let dauth = PublishAuth::sign(PublishKey::Deposit, &l2.head_keys().deposit, &l2.id, &osis_label::blob_id(&env), &wrap);
    w.run(c, Command::Signal { label: l2.id, blob: env.clone(), wrap, auth: dauth });
    assert_eq!(w.take(b).len(), 1);
    assert_eq!(w.take(a).len(), 1);
    assert_eq!(w.backends[h].scan(&[], None, usize::MAX).unwrap().len(), backend_rows, "signals store nothing");
    // over the rate limit: dropped
    w.run(a, Command::Signal { label: l2.id, blob: env, wrap, auth });
    assert!(w.take(b).is_empty());
}

// spec/sync.md §5: blind-to-blind replication is push only: steps with claim sets and stamped entries reach the peer; deposits and deletions do not travel
#[test]
fn two_servers_replicate() {
    let mut w = World::new();
    let (s1, s2) = (w.add_hub(Policy::default()), w.add_hub(Policy::default()));
    let a = w.connect(s1);
    let l = Label::new(3);
    w.setup(a, &l);
    w.run(a, Command::Upload { label: l.id, entries: (0..10).map(|n| l.entry(blob(n))).collect() });
    w.run(a, l.deposit(blob(50), &l.head_keys().deposit.clone()));
    let link = w.peer(s1, s2);
    let b = w.connect(s2);
    // the claim set came along: a claim opens at the peer
    let claim = l.steps[0].claim_key(&l.reader).unwrap();
    let ev = w.run(b, Command::Open { label: l.id, key: OpenKey::Claim { step: l.steps[0].id(), key: claim } });
    assert!(matches!(&ev[..], [ClientEvent::Opened { .. }]), "{ev:?}");
    let (evs, cursor) = events_of(&w.run(b, sync(l.id, None, vec![], vec![])));
    assert_eq!(added(&evs), sorted((0..10).map(bid).collect()));
    // live changes follow; a new head before them
    w.run(b, Command::Subscribe { labels: vec![l.id] });
    let mut l = l;
    let (child, set) = l.rotate(20);
    w.run(a, Command::Register { label: l.id, step: child.clone(), claim_set: Some(set) });
    w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(blob(10))] });
    let (pushed, _) = events_of(&w.take(b));
    assert_eq!(pushed.len(), 2, "{pushed:?}");
    assert_eq!(pushed[0], Event::Head(child));
    assert_eq!(added(&pushed[1..]), vec![bid(10)]);
    // deletes are not relayed
    w.open(a, &l);
    let item = DeleteItem::sign(&l.head_keys().delete, &l.id, bid(0), None).unwrap();
    w.run(a, Command::Delete { label: l.id, items: vec![item] });
    assert!(w.take(b).is_empty());
    // the acknowledged position is kept: a new connection sends nothing new
    let (log_id, head) = osis_proto::LabelStore::log_head(w.hubs[s1].store(), &l.id).unwrap();
    assert_eq!(w.hubs[s1].store().replica_pos(&hub_key(s2), &l.id).unwrap(), Some((log_id, head)));
    w.cut(link);
    let peer_head = osis_proto::LabelStore::log_head(w.hubs[s2].store(), &l.id).unwrap();
    w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(blob(11))] });
    w.peer(s1, s2);
    assert_eq!(osis_proto::LabelStore::log_head(w.hubs[s2].store(), &l.id).unwrap().1, peer_head.1 + 1);
    assert_eq!(added(&events_of(&w.take(b)).0), vec![bid(11)]);
    let (evs, _) = events_of(&w.run(b, sync(l.id, cursor, vec![], vec![])));
    assert_eq!(added(&evs), vec![bid(10), bid(11)]);
    assert!(w.diagnostics.is_empty(), "{:?}", w.diagnostics);
}

// spec/sync.md §5: replication of a label whose log no longer reaches the peer's position replays the path and the live stamped entries, each run of steps before the entries stamped under its key
#[test]
fn replication_replays_past_the_horizon() {
    let mut w = World::new();
    let (s1, s2) = (w.add_hub(Policy { log_keep: 16, ..Policy::default() }), w.add_hub(Policy::default()));
    let a = w.connect(s1);
    let mut l = Label::new(3);
    w.setup(a, &l);
    // entries stamped under the genesis key, then under the child's: each run goes before the next step
    w.run(a, Command::Upload { label: l.id, entries: (0..100).map(|n| l.entry(blob(n))).collect() });
    let (child, set) = l.rotate(20);
    w.run(a, Command::Register { label: l.id, step: child, claim_set: Some(set) });
    w.run(a, Command::Upload { label: l.id, entries: (100..300).map(|n| l.entry(blob(n))).collect() });
    assert!(osis_proto::LabelStore::log_after(w.hubs[s1].store(), &l.id, 0, 1).unwrap().is_none());
    w.peer(s1, s2);
    let b = w.connect(s2);
    w.open(b, &l);
    assert_eq!(osis_proto::LabelStore::path(w.hubs[s2].store(), &l.id).unwrap(), l.steps);
    let (evs, _) = events_of(&w.run(b, Command::Sync { label: l.id, cursor: None, inline_limit: 0, entries: vec![], gained: vec![] }));
    assert_eq!(added(&evs), sorted((0..300).map(bid).collect()));
    assert!(w.diagnostics.is_empty(), "{:?}", w.diagnostics);
}

// spec/sync.md §4: the node's state is durable: after a restart cursors stay valid and pending deletions still run
#[test]
fn restart_keeps_state() {
    let mut w = World::new();
    let h = w.add_hub(Policy::default());
    let a = w.connect(h);
    let l = Label::new(3);
    w.setup(a, &l);
    w.open(a, &l);
    w.run(a, Command::Upload { label: l.id, entries: (0..5).map(|n| l.entry(blob(n))).collect() });
    let now = w.now();
    let item = DeleteItem::sign(&l.head_keys().delete, &l.id, bid(0), Some(WallMs(now + 1_000))).unwrap();
    w.run(a, Command::Delete { label: l.id, items: vec![item] });
    let (_, cursor) = events_of(&w.run(a, sync(l.id, None, vec![], vec![])));
    w.restart(h, Policy::default());
    let a = w.connect(h);
    w.open(a, &l);
    w.advance(1_000);
    let (evs, _) = events_of(&w.run(a, sync(l.id, cursor, vec![], vec![])));
    assert_eq!(evs, vec![Event::Deleted(bid(0))]);
}
