//! Cards (spec/sync-inbox.md §1 Card, spec/permissions.md §5.2): a card counts only written along
//! a path through its thing; the inbox it names is the one with the greatest `since`, a move
//! spreads to every card its thing's nodes may write, a keys refresh keeps the inbox; a party
//! holding nothing of an account but a card of it grants to it and fires at the inbox the card
//! names.

use crate::common::T0;
use osis_base::{Role, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
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

/// The inbox each card of `a` held at `e` names, by host.
fn named(e: &mut Engine, a: &Tid) -> Vec<(Tid, Tid, u64)> {
    e.cards_of(a).unwrap().into_iter().map(|(h, c)| (h, c.inbox.map_or(*a, Tid::from), c.since.0)).collect()
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
    m.op(acc.profile, &ct::CARD, PathOp { path: vec![PathSeg::Key(Value::Weak(b))], op: Op::Set(cards::naming(None, T0).to_value()) }).unwrap();
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

// spec/sync-inbox.md §1 (`since`): A's cards on the profile and on C name its inbox; a move on the
// profile writes a greater `since`, and A's node rewrites C to the new inbox with it.
#[test]
fn an_inbox_move_spreads_to_every_card_spec_sync_inbox_1() {
    let (mut lp, acc) = one();
    let c = thing(&mut lp, 0, acc.thing, false);
    let i2 = thing(&mut lp, 0, acc.thing, true);
    let e = &mut lp.peers[0].engine;
    assert!(e.write_card(c, acc.thing, Some(acc.inbox), None).unwrap());
    let before = named(e, &acc.thing);
    assert!(before.iter().all(|x| x.1 == acc.inbox) && before.len() == 2);
    assert!(e.write_card(acc.profile, acc.thing, Some(i2), None).unwrap());
    e.refresh_cards().unwrap();
    let after = named(e, &acc.thing);
    assert_eq!(after.len(), 2);
    assert!(after.iter().all(|x| x.1 == i2 && x.2 > before[0].2), "every card names the new inbox, at a greater since: {after:?}");
    assert_eq!(e.inbox_of(&acc.thing).unwrap(), Some(i2));
}

// spec/sync-inbox.md §1 (`since`): a writer of A naming A's inbox at a `since` past its own
// write's stamp (one no later move reaches) writes an invalid card: it names no inbox, so a later
// move by A's other writers wins. Control: the same card at its write's time counts.
#[test]
fn a_card_since_past_its_write_is_invalid_spec_sync_inbox_1() {
    let run = |ahead: u64| {
        let (mut lp, acc) = one();
        let c = thing(&mut lp, 0, acc.thing, false);
        let i2 = thing(&mut lp, 0, acc.thing, true);
        let now = lp.peers[0].engine.now();
        let card = ct::Card { since: osis_base::WallMs(now.0 + ahead), ..cards::naming(Some(i2), now) };
        let m = cards::put(c, acc.thing, &card).unwrap();
        lp.peers[0].engine.core.skip_writer_rules = true;
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.peers[0].engine.core.skip_writer_rules = false;
        let e = &mut lp.peers[0].engine;
        (e.inbox_of(&acc.thing).unwrap(), acc.inbox, i2)
    };
    let (inbox, old, _) = run(10 * 365 * 24 * 3600 * 1000);
    assert_eq!(inbox, Some(old), "a since past its write names nothing");
    let (inbox, _, i2) = run(0);
    assert_eq!(inbox, Some(i2), "control: a since at its write names the inbox");
}

// spec/sync-inbox.md §1, held-model `closure::cards` control `Restamp`: node 0 moves A's inbox on
// the profile; node 1, not yet seeing it, rotates A and refreshes A's cards with the old inbox,
// written after the move. Ordered by `since`, not by the writes' stamps, both nodes end with
// every card naming the new inbox and carrying A's new keys.
#[test]
fn a_keys_refresh_does_not_undo_a_move_spec_sync_inbox_1() {
    let (mut lp, acc) = LocalPeer::one_account(2, 0, T0).unwrap();
    let c = thing(&mut lp, 0, acc.thing, false);
    let i2 = thing(&mut lp, 0, acc.thing, true);
    lp.peers[0].engine.write_card(c, acc.thing, Some(acc.inbox), None).unwrap();
    lp.sync_all().unwrap();
    for p in lp.peers.iter_mut() {
        p.engine.refresh_cards().unwrap();
    }
    lp.peers[0].engine.write_card(acc.profile, acc.thing, Some(i2), None).unwrap();
    lp.advance(1000);
    lp.peers[1].engine.rotate_leaving_out(&acc.thing, &[Role::Read], &[]).unwrap();
    lp.peers[1].engine.refresh_cards().unwrap();
    assert!(named(&mut lp.peers[1].engine, &acc.thing).iter().all(|x| x.1 == acc.inbox), "node 1 refreshed with the inbox it knows");
    for _ in 0..3 {
        lp.sync_all().unwrap();
        for p in lp.peers.iter_mut() {
            p.engine.refresh_cards().unwrap();
        }
    }
    for i in 0..2 {
        let e = &mut lp.peers[i].engine;
        let keys = e.current_keys(&acc.thing);
        let cards = e.cards_of(&acc.thing).unwrap();
        assert_eq!(cards.len(), 2, "node {i}");
        assert!(named(e, &acc.thing).iter().all(|x| x.1 == i2), "node {i}: every card names the moved inbox");
        for (_, card) in cards {
            let carried: std::collections::BTreeSet<_> = card.keys.iter().filter_map(|b| osis_commit::CommitBlob::decode(b).ok()).map(|b| b.id()).collect();
            assert!(keys.is_subset(&carried), "node {i}: the card carries A's new keys");
        }
    }
}

// spec/permissions.md §2 (Granting to a thing): node 1 holds nothing of account A0 but A0's
// profile, read (as a contact card gives it). Before, its grant to A0 is refused; once it holds
// the profile, A0's card there gives it A0's keys, and its grant is fired at the inbox the card
// names.
#[test]
fn a_card_alone_lets_a_stranger_grant_spec_permissions_2() {
    let mut lp = LocalPeer::new_apart(2, 0, T0).unwrap();
    let (acc, _) = osis_engine::local_peer::make_account(&mut lp.peers[0].engine).unwrap();
    lp.peers[0].engine.refresh_cards().unwrap();
    let me1 = lp.peers[1].engine.me();
    let t = thing(&mut lp, 1, me1, true);
    assert!(lp.peers[1].engine.grant(&t, &acc.thing, &ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None }).is_err(), "no card, no keys: refused");
    // node 0 grants node 1 read on the profile (node 1's keys shown by hand)
    let keys = lp.peers[1].engine.holder_keys(&me1).unwrap();
    lp.peers[0].engine.take_holder_keys(&me1, &keys, None).unwrap();
    lp.peers[0].engine.grant(&acc.profile, &me1, &ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None }).unwrap();
    lp.peers[1].know(&[acc.profile]).unwrap();
    let ids = lp.peers[0].engine.commit_ids();
    crate::flows::send_carried(&mut lp, 0, 1, &ids);
    crate::flows::send_carried(&mut lp, 0, 1, &ids);
    let e1 = &mut lp.peers[1].engine;
    e1.take_carried().unwrap();
    assert_eq!(e1.inbox_of(&acc.thing).unwrap(), Some(acc.inbox), "A0's card read");
    e1.grant(&t, &acc.thing, &ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None }).unwrap();
    let owed: Vec<Tid> = e1.fires_owed().iter().filter_map(|id| e1.sealed_fire(id).ok().flatten()).map(|f| f.thing).collect();
    assert!(owed.contains(&acc.inbox), "the grant is fired at A0's inbox: {owed:?}");
}
