//! Making an account (spec/permissions.md §8): A minted with the node thing as mint admin and
//! independent at once, its inbox and profile minted with admin A, the node entering all three.

use crate::common::T0;
use osis_base::Role;
use osis_engine::local_peer::Peer;
use osis_schema::core_types as ct;

// spec/permissions.md §8 Making, spec/sync-inbox.md §1: A is minted with the node thing as mint
// admin, independent; its inbox and profile are minted with admin A, independent, held by strongs
// from A; A's `keys.0` names the inbox, whose setting takes both inbox signals; the node holds A
// (a strong from its root) and reads all three, the inbox and profile in A's sync unit, with
// admin on each by A's record edge.
#[test]
fn making_an_account_spec_permissions_8() {
    let mut p = Peer::new(1, T0).unwrap();
    let (acc, _) = p.engine.make_account().unwrap();
    let e = &mut p.engine;
    let me = e.me();
    assert_eq!(e.mint_admin(&acc.thing), Some(me));
    for t in [acc.inbox, acc.profile] {
        assert_eq!(e.mint_admin(&t), Some(acc.thing));
        assert!(e.closure_holds(&t) && e.sync_unit(&acc.thing).contains(&t), "in A's sync unit");
        assert_eq!(e.role_on(&t), Some(Role::Admin));
    }
    for t in [acc.thing, acc.inbox, acc.profile] {
        assert!(e.sync_id_of(&t).unwrap().is_some(), "independent: a sync ID of its own");
    }
    assert!(e.closure_holds(&acc.thing));
    assert_eq!(e.role_on(&acc.thing), Some(Role::Admin));
    assert_eq!(e.inbox_thing(&acc.thing), Some(acc.inbox));
    let x = e.get_typed(&acc.inbox, &ct::RETENTION).unwrap().unwrap();
    for s in ct::INBOX_SIGNALS {
        assert!(x.rules.contains_key(&osis_base::Ak::new(s).unwrap()), "{s} enabled");
    }
    e.check_closure();
}

/// A thing peer 0 mints with its node thing, held from its own root alone, made independent.
fn independent_of_0(lp: &mut osis_engine::local_peer::LocalPeer) -> osis_base::Tid {
    let e = &mut lp.peers[0].engine;
    let me = e.me();
    let (t, _) = e.create_with_admin(&me).unwrap();
    e.make_independent(&t).unwrap();
    t
}

// spec/sync-set.md §2 First entry: peer 1 reads X only through G (peer 1 read on G, G read on
// X). Its root's strong to X alone enters nothing: no unit it syncs carries X, and no key part of
// an own or read thing holds a piece on X (G is held for no reading of peer 1's). Once its root
// strongs G too, G is entered (its node thing's piece) and read, and G's piece on X carries it.
#[test]
fn a_strong_enters_only_what_a_unit_piece_or_offer_carries_spec_sync_set_2() {
    let mut lp = crate::common::net(2, 0);
    let (g, x) = (independent_of_0(&mut lp), independent_of_0(&mut lp));
    let n1 = lp.peers[1].engine.me();
    lp.peers[0].engine.grant(&g, &n1, &crate::common::edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&x, &g, &crate::common::edge(Role::Read)).unwrap();
    lp.hold_at(1, x);
    lp.sync_all().unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(!e.closure_holds(&x), "a role through G and a strong: nothing carries X");
    e.check_closure();
    lp.hold_at(1, g);
    lp.sync_all().unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(e.closure_holds(&g), "G: the node thing's piece");
    assert!(e.closure_holds(&x), "X: G's piece, G read");
    e.check_closure();
}
