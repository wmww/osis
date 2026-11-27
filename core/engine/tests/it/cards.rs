//! Cards (spec/sync-inbox.md §1 Card, spec/permissions.md §5.2): a card counts only written along
//! a path through its thing; a thing's inbox is its own `keys.0` field, an admin's: a writer
//! cannot move it, an admin's move spreads to every card its thing's nodes may write, a writer's
//! keys refresh keeps it; a party holding nothing of an account but a card of it grants to it and
//! fires at the inbox the account's admins chose.

use crate::common::T0;
use osis_base::{Role, Tid, Value};
use osis_crdt::{Op, PathOp};
use osis_engine::flows::cards;
use osis_engine::local_peer::{Account, LocalPeer};
use osis_engine::{Engine, Mutation};
use osis_schema::core_types as ct;
use osis_schema::Codec;

/// A thing minted with admin `admin`, made independent where `independent`, held.
fn thing(lp: &mut LocalPeer, i: usize, admin: Tid, independent: bool) -> Tid {
    let mut m = Mutation::new();
    let t = lp.peers[i].engine.new_thing(&mut m, admin);
    lp.peers[i].commit(m).unwrap();
    if independent {
        lp.peers[i].engine.make_independent(&t).unwrap();
    }
    lp.hold_at(i, t);
    t
}

/// Whether every card of `a` held at `e` carries the current `keys.0` commits of `a` and of its
/// inbox there.
fn cards_current(e: &mut Engine, a: &Tid) -> bool {
    let inbox = e.inbox_of(a).unwrap().unwrap();
    let mut keys = e.current_keys(a).unwrap();
    keys.extend(e.current_keys(&inbox).unwrap());
    let cards = e.cards_of(a).unwrap();
    !cards.is_empty()
        && cards.iter().all(|(_, card)| {
            let carried: std::collections::BTreeSet<_> = card.keys.iter().filter_map(|b| osis_commit::CommitBlob::decode(b).ok()).map(|b| b.id()).collect();
            keys.is_subset(&carried)
        })
}

/// Write on `accs[0]` for `accs[1]`, `accs[0]` held at node 1.
fn writer(lp: &mut LocalPeer, accs: &[Tid]) {
    lp.peers[0].engine.grant(&accs[0], &accs[1], &ct::Edge { role: Role::Write, until: None, may_grant: false, retain: false, floor: None }).unwrap();
    lp.sync_all().unwrap();
    lp.hold_at(1, accs[0]);
    lp.sync_all().unwrap();
}

/// One node's account, its card on the profile filled in.
fn one() -> (LocalPeer, Account) {
    let (mut lp, acc) = LocalPeer::one_account(1, 0, T0).unwrap();
    lp.peers[0].engine.refresh_cards().unwrap();
    (lp, acc)
}

// spec/permissions.md §5.2: a card of B written on the profile along a path through A alone (B
// no member of it) is refused by its writer and, written anyway, invalid: it reads nowhere; A's own card there, along a path through A,
// reads and carries A's keys.
#[test]
fn a_card_written_off_its_path_is_invalid_spec_permissions_5_2() {
    let (mut lp, acc) = one();
    let b = thing(&mut lp, 0, acc.thing, true);
    let mut m = Mutation::new();
    m.act_as(acc.thing);
    m.op(acc.profile, &ct::card_ak(&b), PathOp { path: vec![], op: Op::Set(ct::Card::default().to_value()) }).unwrap();
    assert!(lp.peers[0].commit(m.clone()).is_err(), "refused writer-side");
    lp.peers[0].engine.core.skip_writer_rules = true;
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.peers[0].engine.core.skip_writer_rules = false;
    let e = &mut lp.peers[0].engine;
    assert!(e.cards_of(&b).unwrap().is_empty(), "off its path: no card of B");
    let a = e.cards_of(&acc.thing).unwrap();
    assert_eq!(a.len(), 1, "A's card on the profile");
    assert!(!a[0].1.keys.is_empty(), "carrying A's keys");
    let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
    let values = |l: &[Vec<u8>]| Value::List(l.iter().map(|b| osis_base::decode(b, &limits).unwrap()).collect());
    assert!(osis_blob::Certificates::from_values(&values(&a[0].1.keys), &values(&a[0].1.records), usize::MAX).is_ok(), "in the holder keys form");
    assert_eq!(e.inbox_of(&acc.thing).unwrap(), Some(acc.inbox));
}

// spec/sync-inbox.md §1: an inbox is a thing of its own. A thing naming none has none; naming itself is refused, and a `keys.0` naming it anyway names none.
#[test]
fn an_inbox_is_a_thing_of_its_own_spec_sync_inbox_1() {
    let (mut lp, acc) = one();
    let b = thing(&mut lp, 0, acc.thing, true);
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.inbox_of(&b).unwrap(), None, "naming none: no inbox");
    assert!(matches!(e.set_inbox(b, b), Err(osis_engine::Error::Misuse(_))), "itself refused");
    let mut m = Mutation::new();
    cards::put_inbox(&mut m, b, b).unwrap();
    lp.peers[0].commit(m).unwrap();
    assert_eq!(lp.peers[0].engine.inbox_of(&b).unwrap(), None, "naming itself: no inbox");
}

// spec/sync-inbox.md §1: an admin moves A's inbox; A's cards on the profile and on C are
// rewritten carrying it (A's newest `keys.0` and the new inbox's keys).
#[test]
fn an_inbox_move_spreads_to_every_card_spec_sync_inbox_1() {
    let (mut lp, acc) = one();
    let c = thing(&mut lp, 0, acc.thing, false);
    let i2 = thing(&mut lp, 0, acc.thing, true);
    let e = &mut lp.peers[0].engine;
    assert!(e.write_card(c, acc.thing).unwrap());
    e.set_inbox(acc.thing, i2).unwrap();
    assert_eq!(e.inbox_of(&acc.thing).unwrap(), Some(i2));
    assert_eq!(e.cards_of(&acc.thing).unwrap().len(), 2);
    assert!(cards_current(e, &acc.thing), "every card carries the move");
    assert!(!e.refresh_cards().unwrap(), "nothing left to rewrite");
}

// spec/permissions.md §3 (Who rotates: a `keys.0` delta touching the inbox field needs admin), spec/sync-inbox.md
// §1: node 1, acting for an account holding write on A0, may not move A0's inbox: refused at its
// writer, and a commit writing it anyway (forged) is invalid at both nodes, A0's inbox unmoved.
// Control: node 0, an admin of A0, moves it.
#[test]
fn a_writer_cannot_move_the_inbox_spec_permissions_3() {
    let (mut lp, accs) = LocalPeer::accounts(2, 0, T0).unwrap();
    writer(&mut lp, &accs);
    let i2 = thing(&mut lp, 1, accs[1], true);
    let inbox = lp.peers[0].engine.inbox_of(&accs[0]).unwrap().unwrap();
    assert_eq!(lp.peers[1].engine.inbox_of(&accs[0]).unwrap(), Some(inbox));
    assert!(matches!(lp.peers[1].engine.set_inbox(accs[0], i2), Err(osis_engine::Error::Permission { needs: Role::Admin, .. })), "refused writer-side");
    let mut m = Mutation::new();
    cards::put_inbox(&mut m, accs[0], i2).unwrap();
    // the plain write path too: a `keys.0` op outside a writer's keysets needs admin
    assert!(matches!(lp.peers[1].engine.write(m.clone()), Err(osis_engine::Error::Permission { needs: Role::Admin, .. })), "refused writer-side, written plainly");
    lp.peers[1].engine.core.skip_writer_rules = true;
    let forged = lp.peers[1].commit(m).unwrap().unwrap();
    lp.peers[1].engine.core.skip_writer_rules = false;
    lp.sync_all().unwrap();
    for i in 0..2 {
        assert_eq!(lp.peers[i].engine.part_valid(&forged, 0), Some(false), "node {i}: the forged move is invalid");
        assert_eq!(lp.peers[i].engine.inbox_of(&accs[0]).unwrap(), Some(inbox), "node {i}: the inbox stays");
    }
    let i3 = thing(&mut lp, 0, accs[0], true);
    lp.peers[0].engine.set_inbox(accs[0], i3).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[1].engine.inbox_of(&accs[0]).unwrap(), Some(i3), "control: an admin's move counts");
}

// spec/sync-inbox.md §1: node 1, a writer of A0 (through its account), refreshes A0's card on C
// after rotating A0, before it sees node 0's move of A0's inbox; once both sync, A0's inbox is the
// moved one everywhere and every card carries A0's newest keys: a writer's refresh carries the admin's inbox, never
// one of its own.
#[test]
fn a_writers_refresh_keeps_the_admins_inbox_spec_sync_inbox_1() {
    let (mut lp, accs) = LocalPeer::accounts(2, 0, T0).unwrap();
    let c = thing(&mut lp, 0, accs[0], false);
    lp.peers[0].engine.write_card(c, accs[0]).unwrap();
    writer(&mut lp, &accs);
    lp.hold_at(1, c);
    lp.sync_all().unwrap();
    let i2 = thing(&mut lp, 0, accs[0], true);
    lp.peers[0].engine.set_inbox(accs[0], i2).unwrap();
    lp.advance(1000);
    lp.peers[1].engine.rotate_leaving_out(&accs[0], &[Role::Read], &[]).unwrap();
    lp.peers[1].engine.refresh_cards().unwrap();
    for _ in 0..3 {
        lp.sync_all().unwrap();
        for p in lp.peers.iter_mut() {
            p.engine.refresh_cards().unwrap();
        }
    }
    for i in 0..2 {
        let e = &mut lp.peers[i].engine;
        assert_eq!(e.inbox_of(&accs[0]).unwrap(), Some(i2), "node {i}: the admin's inbox");
        assert!(cards_current(e, &accs[0]), "node {i}: every card carries A0's newest keys and the inbox's");
    }
}

// spec/permissions.md §5.2 (Compaction snapshot; card aspect): node 1, a writer of
// C through its own account alone, holds A0's card on C. Its snapshot of the card aspect carries
// the card off a path through A0: refused writer-side and, written anyway, invalid at node 0.
// Node 0's own snapshot, acting as A0, is valid at node 1; once node 1 removes the card (any
// writer's power), node 1's snapshot of the removed aspect is valid.
#[test]
fn a_card_snapshot_off_its_path_is_invalid_spec_permissions_5_2() {
    let (mut lp, accs) = LocalPeer::accounts(2, 0, T0).unwrap();
    let c = thing(&mut lp, 0, accs[0], true);
    let ak = ct::card_ak(&accs[0]);
    lp.peers[0].engine.write_card(c, accs[0]).unwrap();
    lp.peers[0].engine.grant(&c, &accs[1], &ct::Edge { role: Role::Write, until: None, may_grant: false, retain: false, floor: None }).unwrap();
    lp.sync_all().unwrap();
    lp.hold_at(1, c);
    lp.sync_all().unwrap();
    assert!(lp.peers[1].engine.cards_of(&accs[0]).unwrap().iter().any(|(h, _)| *h == c), "node 1 reads A0's card on C");
    assert!(lp.peers[1].engine.snapshot(&c, &ak).is_err(), "refused writer-side");
    lp.peers[1].engine.core.skip_writer_rules = true;
    let off = lp.peers[1].engine.snapshot(&c, &ak).unwrap().unwrap();
    lp.peers[1].engine.core.skip_writer_rules = false;
    let on = lp.peers[0].engine.snapshot(&c, &ak).unwrap().unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[0].engine.part_valid(&off, 0), Some(false), "off its path: invalid");
    assert_eq!(lp.peers[1].engine.part_valid(&on, 0), Some(true), "through A0: valid");
    lp.peers[1].engine.remove_card(c, accs[0]).unwrap();
    let removed = lp.peers[1].engine.snapshot(&c, &ak).unwrap().unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[0].engine.part_valid(&removed, 0), Some(true), "a removal's snapshot: any writer's");
    assert!(!lp.peers[0].engine.cards_of(&accs[0]).unwrap().iter().any(|(h, _)| *h == c), "the card is gone at node 0");
}

// spec/sync-inbox.md §1 (Card), spec/permissions.md §4 (current `keys.0` commits): a fresh node
// paired into A, A's card on the profile reaching it before the pairing grant (which writes
// nothing in A's `keys.0`), rewrites the card once and settles, not due again each round; the
// grant arriving moves nothing.
#[test]
fn a_card_rewrite_settles_for_a_paired_node_spec_sync_inbox_1() {
    let (mut lp, acc) = LocalPeer::one_account(1, 0, T0).unwrap();
    let mut p = osis_engine::local_peer::Peer::new(7, lp.peers[0].engine.now()).unwrap();
    let (node, keys) = (p.engine.tid(), p.engine.node_keys().unwrap());
    let done = lp.peers[0].engine.pair(&acc.thing, &node, &keys, Role::Admin).unwrap();
    p.engine.take_pairing(&acc.thing).unwrap();
    p.know(&[acc.thing, acc.profile]).unwrap();
    for id in lp.peers[0].engine.commit_ids() {
        if !done.commits.contains(&id) {
            let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
            p.engine.ingest(&pk.bytes, pk.blobs).unwrap();
        }
    }
    p.engine.refresh_cards().unwrap();
    assert!(!p.engine.refresh_cards().unwrap(), "settled: nothing left to rewrite");
    for id in &done.commits {
        let pk = lp.peers[0].engine.package(id).unwrap().unwrap();
        p.engine.ingest(&pk.bytes, pk.blobs).unwrap();
    }
    assert!(!p.engine.refresh_cards().unwrap(), "the grant writes no keys.0: nothing to rewrite");
    assert_eq!(p.engine.inbox_of(&acc.thing).unwrap(), Some(acc.inbox));
}

// spec/permissions.md §4 (current `keys.0` commits: every commit with a write live in the
// `keys.0` state), spec/sync-inbox.md §1 (Card), spec/wire.md §9 (Holder keys): every role of
// A0's inbox is rotated after the commit that wrote its sync ID, deposit seed and step. A fresh node
// taking only the inbox's holder keys (what a card of A0 carries of it) rebuilds its `keys.0`
// whole, the step's read key among it, so a read key is in force to seal a fire to. Failed when
// the current commits were the newest rotation commits and the newest `keys.0` commit alone (the
// sync differential's `New(1), Pair(1), Unpair(0, 2), Run, Strong(0, None, 0), Give(3, 0,
// Node(0), Reads)`: a stranger never sealed its grant fire).
#[test]
fn holder_keys_rebuild_the_whole_keys_state_after_a_rotation_spec_permissions_4() {
    let mut lp = LocalPeer::new_apart(1, 0, T0).unwrap();
    let (acc, _) = osis_engine::local_peer::make_account(&mut lp.peers[0].engine).unwrap();
    let e0 = &mut lp.peers[0].engine;
    let made = e0.get_typed(&acc.inbox, &ct::KEYS).unwrap().unwrap();
    e0.rotate_leaving_out(&acc.inbox, &[Role::Sync, Role::Read, Role::Write, Role::Admin], &[]).unwrap().unwrap();
    let want = e0.get_typed(&acc.inbox, &ct::KEYS).unwrap().unwrap();
    assert!(want.read != made.read && want.sync_id.is_some() && want.step.is_some(), "every keyset rotated, the rest kept");
    let keys = e0.holder_keys(&acc.inbox).unwrap();
    let mut q = osis_engine::local_peer::Peer::new(8, T0).unwrap();
    q.engine.take_holder_keys(&acc.inbox, &keys, None).unwrap();
    assert_eq!(q.engine.get_typed(&acc.inbox, &ct::KEYS).unwrap(), Some(want), "the inbox's keys.0 rebuilt whole from its holder keys");
}
