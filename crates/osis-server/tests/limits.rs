//! Negative cases (spec/sync.md §5; notes/sync.md "Limits"): what a stale, reading or hostile
//! client cannot do at a blind node.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::*;
use osis_core::LabelId;
use osis_proto::msg::DeleteItem;
use osis_proto::*;
use osis_server::Policy;

fn world() -> (World, usize) {
    let mut w = World::new();
    let h = w.add_hub(Policy::default());
    let c = w.connect(h);
    (w, c)
}

// spec/sync.md §5 Open: an ex-member's superseded sync key gets the child step and nothing else
// spec/sync.md §5 (stale sync key), §5 (download needs open)
/// A header blind (spec/crypto.md §7).
const HB: [u8; 16] = [0x4b; 16];

#[test]
fn stale_sync_key_gets_exactly_one_step() {
    let (mut w, c) = world();
    let mut l = Label::new(3);
    w.setup(c, &l);
    w.run(c, Command::Upload { label: l.id, entries: vec![l.entry(blob(1))] });
    let old = l.head_keys().clone();
    let (s1, cs1) = l.rotate(20);
    w.run(c, Command::Register { label: l.id, step: s1.clone(), claim_set: Some(cs1) });
    let (s2, cs2) = l.rotate(40);
    w.run(c, Command::Register { label: l.id, step: s2, claim_set: Some(cs2) });
    let ev = w.run(c, Command::Open { label: l.id, key: OpenKey::Sync(old.sync.clone()) });
    assert!(matches!(&ev[..], [ClientEvent::Step { step, .. }] if *step == s1), "{ev:?}");
    for cmd in [sync(l.id, None, vec![], vec![]), Command::Fetch { label: l.id, ids: vec![bid(1)] }, Command::Path { label: l.id, after: None }, Command::Reconcile { label: l.id, ids: vec![] }] {
        let ev = w.run(c, cmd);
        assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::NOT_OPENED, .. }]), "{ev:?}");
    }
    let ev = w.run(c, Command::Subscribe { labels: vec![l.id] });
    assert_eq!(ev, vec![ClientEvent::Subscribed { labels: vec![l.id], codes: vec![Code::NOT_OPENED] }]);
    // the old write key gets 9 with the head
    let ev = w.run(c, Command::Upload { label: l.id, entries: vec![l.entry_by(blob(2), &old.write)] });
    assert!(matches!(&ev[..], [ClientEvent::EntryStatus { codes, head: Some(h), .. }] if *codes == vec![Code::NOT_HEAD] && h.id() == l.steps[2].id()), "{ev:?}");
}

// spec/sync.md §5 Stamp, Deposit: a reader (sync key only) cannot upload or deposit, nor sign deletes without a delete key
// spec/sync.md §5 (upload refusals), §5 (delete keys), §5 (register)
#[test]
fn reader_cannot_write() {
    let (mut w, c) = world();
    let l = Label::new(3);
    w.setup(c, &l);
    let sk = l.head_keys().sync.clone();
    assert_eq!(statuses(&w.run(c, Command::Upload { label: l.id, entries: vec![l.entry_by(blob(1), &sk)] })), vec![Code::REFUSED]);
    assert_eq!(statuses(&w.run(c, l.deposit(blob(2), &sk))), vec![Code::REFUSED]);
    w.run(c, Command::Upload { label: l.id, entries: vec![l.entry(blob(3))] });
    let item = DeleteItem::sign(&sk, &l.id, bid(3), None).unwrap();
    assert_eq!(statuses(&w.run(c, Command::Delete { label: l.id, items: vec![item] })), vec![Code::REFUSED]);
    // a register under a reader's key: answered with the head
    let mut fork = Label::new(3);
    let (child, _) = fork.rotate(60);
    let mut forged = child.clone();
    forged.sig.0[0] ^= 1;
    let ev = w.run(c, Command::Register { label: l.id, step: forged, claim_set: None });
    assert!(matches!(&ev[..], [ClientEvent::Head { head, .. }] if head.id() == l.steps[0].id()), "{ev:?}");
}

// spec/sync.md §5 Delete, spec/crypto.md §7: a delete-key signature deletes only the body whose prefix commits to it (under that body's salt), at its level
// spec/sync.md §5 (delete keys)
#[test]
fn delete_key_deletes_only_its_own_body() {
    let (mut w, c) = world();
    let l = Label::new(3);
    w.setup(c, &l);
    let dk = osis_crypto::DeleteSecret::derive(&s32(1));
    let commit = |level: u8, n: u64| osis_crypto::commitment(level, &dk.verifying_key(), &salt(n), &HB).unwrap();
    let mine = blob_with(10, 0, vec![commit(1, 10)]);
    let other = blob_with(11, 0, vec![commit(1, 99)]);
    let plain = blob(12);
    w.run(c, Command::Upload { label: l.id, entries: vec![l.entry(mine.clone()), l.entry(other.clone()), l.entry(plain.clone())] });
    let k = l.head_keys().clone();
    let item = |b: &[u8], n: u64, level: u8| DeleteItem::sign_by(&k.sync, &dk, level, &salt(n), &HB, &l.id, osis_label::blob_id(b), None).unwrap();
    // hostile deletes: a forged delete key; the right key under the write label key (level 1
    // needs the sync key); the right key at another level; another blob's salt
    let forged = DeleteItem::sign_by(&k.sync, &osis_crypto::DeleteSecret::derive(&s32(2)), 1, &salt(10), &HB, &l.id, osis_label::blob_id(&mine), None).unwrap();
    let wrong_label_key = DeleteItem::sign_by(&k.write, &dk, 1, &salt(10), &HB, &l.id, osis_label::blob_id(&mine), None).unwrap();
    let ev = w.run(c, Command::Delete { label: l.id, items: vec![forged, wrong_label_key, item(&other, 11, 1), item(&plain, 12, 1), item(&mine, 10, 2), item(&mine, 11, 1), item(&mine, 10, 1)] });
    assert_eq!(statuses(&ev), vec![Code::REFUSED, Code::REFUSED, Code::REFUSED, Code::REFUSED, Code::REFUSED, Code::REFUSED, Code::OK]);
    // a delete for a body no longer held is refused (it cannot be checked, nor a tombstone revealed)
    assert_eq!(statuses(&w.run(c, Command::Delete { label: l.id, items: vec![item(&mine, 10, 1)] })), vec![Code::REFUSED]);
    // the same body under another label is untouched
    let l2 = Label::new(4);
    w.setup(c, &l2);
    w.run(c, Command::Upload { label: l2.id, entries: vec![l2.entry(mine.clone())] });
    w.open(c, &l2);
    let ev = w.run(c, Command::Fetch { label: l2.id, ids: vec![osis_label::blob_id(&mine)] });
    assert!(matches!(&ev[..], [ClientEvent::Fetched { items, .. }] if items[0].entry.is_some()), "{ev:?}");
}

// spec/sync.md §5: deposits over the budget and tombstoned IDs are refused; a blob is fetched only as an entry of an opened label
// spec/sync.md §5 (deposit refusals), §5 (download needs open)
#[test]
fn budget_tombstone_and_fetch_scope() {
    let (mut w, c) = world();
    let l = Label::new(3);
    let l2 = Label::new(4);
    w.setup(c, &l);
    w.setup(c, &l2);
    let dk = l.head_keys().deposit.clone();
    let max = 64 + 4 * l.sets[0].claims.len() as u64;
    for n in 0..max {
        assert_eq!(statuses(&w.run(c, l.deposit(blob(n), &dk))), vec![Code::OK]);
    }
    assert_eq!(statuses(&w.run(c, l.deposit(blob(max), &dk))), vec![Code::BUDGET_FULL]);
    let item = DeleteItem::sign(&l.head_keys().delete, &l.id, bid(0), None).unwrap();
    assert_eq!(statuses(&w.run(c, Command::Delete { label: l.id, items: vec![item] })), vec![Code::OK]);
    assert_eq!(statuses(&w.run(c, l.deposit(blob(0), &dk))), vec![Code::TOMBSTONED]);
    assert_eq!(statuses(&w.run(c, Command::Upload { label: l.id, entries: vec![l.entry(blob(0))] })), vec![Code::TOMBSTONED]);
    // blob 1 is held under l only: opening l2 does not reach it
    w.open(c, &l2);
    let ev = w.run(c, Command::Fetch { label: l2.id, ids: vec![bid(1)] });
    assert!(matches!(&ev[..], [ClientEvent::Fetched { items, .. }] if items[0].entry.is_none()), "{ev:?}");
    // an unknown label
    let ev = w.run(c, Command::Open { label: LabelId([0xee; 16]), key: OpenKey::Sync(l.head_keys().sync.clone()) });
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::UNKNOWN_LABEL, .. }]), "{ev:?}");
}

// spec/sync.md §5: a genesis step for an existing label (another admin's) is answered with the head; only a child of the head is accepted
// spec/sync.md §5 (register)
#[test]
fn registration_squatting() {
    let (mut w, c) = world();
    let mut l = Label::new(3);
    w.setup(c, &l);
    let (s1, cs1) = l.rotate(20);
    let (s2, cs2) = l.rotate(40);
    // a grandchild is not a child of the head
    let ev = w.run(c, Command::Register { label: l.id, step: s2.clone(), claim_set: Some(cs2.clone()) });
    assert!(matches!(&ev[..], [ClientEvent::Head { head, .. }] if *head == l.steps[0]), "{ev:?}");
    assert_eq!(w.run(c, Command::Register { label: l.id, step: s1, claim_set: Some(cs1) }), vec![ClientEvent::Registered { label: l.id }]);
    assert_eq!(w.run(c, Command::Register { label: l.id, step: s2, claim_set: Some(cs2) }), vec![ClientEvent::Registered { label: l.id }]);
    let ev = w.run(c, l.register_cmd(0));
    assert!(matches!(&ev[..], [ClientEvent::Head { head, .. }] if *head == l.steps[2]), "{ev:?}");
}
