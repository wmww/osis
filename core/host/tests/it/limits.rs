//! Negative cases (spec/sync.md §5; notes/label-access.md and notes/inbox.md "Limits"): what a stale, reading or hostile
//! peer cannot do at a host.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use osis_base::LabelId;
use osis_proto::msg::DeleteItem;
use osis_proto::*;
use osis_host::HostPolicy;

/// The hub every test here uses.
const H: usize = 0;

fn world() -> (World, usize) {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy::default());
    assert_eq!(h, H);
    let c = w.connect(h);
    (w, c)
}

/// A header blind (spec/crypto.md §7).
const HB: [u8; 16] = [0x4b; 16];

// spec/sync.md §5 Open: an ex-holder's superseded sync key gets the child step and nothing else;
// an entry stamped under a superseded write key gets code 9 alone

#[test]
fn stale_sync_key_gets_exactly_one_step() {
    let (mut w, c) = world();
    let mut l = Label::new(3);
    w.setup(c, &l);
    assert_eq!(pull_all(&w, H, &l, [1]), vec![Code::OK]);
    let old = l.head_keys().clone();
    let (s1, cs1) = l.rotate(20);
    w.run(c, Command::Register { label: l.id, step: s1.clone(), claim_set: Some(cs1) });
    let (s2, cs2) = l.rotate(40);
    w.run(c, Command::Register { label: l.id, step: s2, claim_set: Some(cs2) });
    let ev = w.run(c, Command::Open { label: l.id, key: OpenKey::Sync { step: None, key: old.sync.clone() } });
    assert!(matches!(&ev[..], [ClientEvent::Step { step, .. }] if *step == s1), "{ev:?}");
    let ev = w.run(c, Command::Path { label: l.id, after: None });
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::NOT_OPENED, .. }]), "{ev:?}");
    assert_eq!(pull(&w, H, &l, &l.entry_by(blob(2), &old.write)), Code::NOT_HEAD);
}

// spec/sync.md §5 Stamp, Deposit: a reader (sync key only) cannot stamp or deposit, nor sign deletes without a delete key
// spec/sync.md §5 (stamp refusals), §5 (delete keys), §5 (register), §5 (deposit budget)
#[test]
fn reader_cannot_write() {
    let (mut w, c) = world();
    let l = Label::new(3);
    w.setup(c, &l);
    let sk = l.head_keys().sync.clone();
    assert_eq!(pull(&w, H, &l, &l.entry_by(blob(1), &sk)), Code::REFUSED);
    // a badly signed deposit learns its code only (spec/sync.md §5)
    assert_eq!(deposit_verified(&w, H, l.deposit(blob(2), &sk)), (Code::REFUSED, false));
    assert_eq!(pull_all(&w, H, &l, [3]), vec![Code::OK]);
    let item = DeleteItem::sign(&sk, &l.id, bid(3)).unwrap();
    assert_eq!(statuses(&w.run(c, Command::Delete { label: l.id, items: vec![item] })), vec![Code::REFUSED]);
    // a register under a stranger's key: code 9 alone, never the head (spec/sync.md §5)
    let mut fork = Label::new(3);
    let (child, _) = fork.rotate(60);
    let mut forged = child.clone();
    forged.sig.0[0] ^= 1;
    let ev = w.run(c, Command::Register { label: l.id, step: forged, claim_set: None });
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::NOT_HEAD, .. }]), "{ev:?}");
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
    for b in [&mine, &other, &plain] {
        assert_eq!(pull(&w, H, &l, &l.entry(b.clone())), Code::OK);
    }
    let k = l.head_keys().clone();
    let item = |b: &[u8], n: u64, level: u8| DeleteItem::sign_by(&k.sync, &[(level, &dk)], &salt(n), &HB, &l.id, osis_label::blob_id(b)).unwrap();
    // hostile deletes: a forged delete key; the right key under the write label key (level 1
    // needs the sync key); the right key at another level; another blob's salt
    let forged = DeleteItem::sign_by(&k.sync, &[(1, &osis_crypto::DeleteSecret::derive(&s32(2)))], &salt(10), &HB, &l.id, osis_label::blob_id(&mine)).unwrap();
    let wrong_label_key = DeleteItem::sign_by(&k.write, &[(1, &dk)], &salt(10), &HB, &l.id, osis_label::blob_id(&mine)).unwrap();
    let ev = w.run(c, Command::Delete { label: l.id, items: vec![forged, wrong_label_key, item(&other, 11, 1), item(&plain, 12, 1), item(&mine, 10, 2), item(&mine, 11, 1), item(&mine, 10, 1)] });
    assert_eq!(statuses(&ev), vec![Code::REFUSED, Code::REFUSED, Code::REFUSED, Code::REFUSED, Code::REFUSED, Code::REFUSED, Code::OK]);
    // a delete for a body no longer held is refused (it cannot be checked, nor a tombstone revealed)
    assert_eq!(statuses(&w.run(c, Command::Delete { label: l.id, items: vec![item(&mine, 10, 1)] })), vec![Code::REFUSED]);
    // the same body under another label is untouched
    let l2 = Label::new(4);
    w.setup(c, &l2);
    assert_eq!(pull(&w, H, &l2, &l2.entry(mine.clone())), Code::OK);
    assert_eq!(live(&w, H, &l2), vec![osis_label::blob_id(&mine)]);
}

// spec/sync.md §5: deposits over the budget and tombstoned IDs are refused; an unknown label does
// not open
// spec/sync.md §5 (deposit refusals)
#[test]
fn budget_and_tombstone() {
    let (mut w, c) = world();
    let l = Label::new(3);
    w.setup(c, &l);
    let dk = l.head_keys().deposit.clone();
    let max = 64 + 4 * l.sets[0].claims.len() as u64;
    for n in 0..max {
        assert_eq!(deposit(&w, H, l.deposit(blob(n), &dk)), Code::OK);
    }
    assert_eq!(deposit(&w, H, l.deposit(blob(max), &dk)), Code::BUDGET_FULL);
    let item = DeleteItem::sign(&l.head_keys().delete, &l.id, bid(0)).unwrap();
    assert_eq!(statuses(&w.run(c, Command::Delete { label: l.id, items: vec![item] })), vec![Code::OK]);
    assert_eq!(deposit(&w, H, l.deposit(blob(0), &dk)), Code::TOMBSTONED);
    assert_eq!(pull_all(&w, H, &l, [0]), vec![Code::TOMBSTONED]);
    let ev = w.run(c, Command::Open { label: LabelId([0xee; 16]), key: OpenKey::Sync { step: None, key: l.head_keys().sync.clone() } });
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::UNKNOWN_LABEL, .. }]), "{ev:?}");
}

// spec/sync.md §5: a genesis step for an existing label (another admin's) is refused (code 9, without the head); only a child of the head is accepted
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
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::NOT_HEAD, .. }]), "{ev:?}");
    assert_eq!(w.run(c, Command::Register { label: l.id, step: s1, claim_set: Some(cs1) }), vec![ClientEvent::Registered { label: l.id }]);
    assert_eq!(w.run(c, Command::Register { label: l.id, step: s2, claim_set: Some(cs2) }), vec![ClientEvent::Registered { label: l.id }]);
    let ev = w.run(c, l.register_cmd(0));
    assert!(matches!(&ev[..], [ClientEvent::Refused { code: Code::NOT_HEAD, .. }]), "{ev:?}");
}
