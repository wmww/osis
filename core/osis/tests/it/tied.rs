//! Tied grants (spec/permissions.md §2, notes/tags.md Sharing a tag): `share_into` writes the
//! placement and a tied edge together; an unplace removes the tied edge at once where that is a
//! self-removal, else a node that may removes it later; one way only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::scenario::{introduce, new_tag, person};
use osis::core::{BODY, GROUP};
use osis::{EdgeOpts, Error, GroupReach, Osis, Role, Share, ShareOpts, Tid};
use osis_sim::world::World;

fn card(db: &Osis, text: &str) -> Tid {
    db.write_with(|w| {
        let c = w.create(db.me())?;
        w.at(c, BODY).set(&text.to_string())?;
        Ok(c)
    })
    .unwrap()
}

fn text(db: &Osis, t: Tid) -> Option<String> {
    db.get(t, BODY).unwrap()
}

fn edit(db: &Osis, t: Tid, new: &str) {
    db.write_with(|w| w.at(t, BODY).set(&new.to_string())).unwrap();
}

fn listed(db: &Osis, g: Tid, t: Tid) -> bool {
    db.get(g, GROUP).unwrap().unwrap_or_default().items.contains(&t)
}

fn reach_of(db: &Osis, t: Tid, g: Tid) -> Option<GroupReach> {
    db.reach(t).into_iter().find(|r| r.group == g)
}

/// Alice's shared tag `g` (Bob writer, Carol writer); Bob's card shared into it, tied.
struct Setup {
    w: World,
    alice: Osis,
    bob: Osis,
    carol: Osis,
    g: Tid,
}

fn setup() -> Setup {
    let mut w = World::new();
    let sv = w.add_server().unwrap();
    let [alice, bob, carol] = [1, 2, 3].map(|s| person(&mut w, s, sv));
    let b = introduce(&mut w, &alice, &bob);
    let c = introduce(&mut w, &alice, &carol);
    let g = new_tag(&alice, "Shared").unwrap();
    alice.grant(g, b, Role::Write, EdgeOpts::default()).unwrap();
    alice.grant(g, c, Role::Write, EdgeOpts::default()).unwrap();
    w.run();
    Setup { w, alice, bob, carol, g }
}

// spec/permissions.md §2 (the tie; self-removal by G's admin; one direction only): share_into
// writes the placement and the tied edge at once; Alice, admin of the tag only, unplaces Bob's
// card and its tied edge goes in the same call; a stale placement never re-grants (Bob revokes
// the tag's edge, the placement stays, the card stays excluded); `remove_edge_of` is the tag
// admin's self-removal.
#[test]
fn share_into_unplace_and_stale_placement() {
    let Setup { mut w, alice, bob, g, .. } = setup();
    let t = card(&bob, "plan");
    assert_eq!(bob.share_into(t, g, Role::Write, ShareOpts::default()).unwrap(), Share::Tied(Role::Write));
    assert!(listed(&bob, g, t) && bob.roster(t)[&g].tied, "placement and edge at once");
    w.run();
    assert_eq!(text(&alice, t).as_deref(), Some("plan"));
    assert_eq!(reach_of(&alice, t, g), Some(GroupReach { group: g, placed: true, share: Share::Tied(Role::Write) }));

    // no admin on Bob's card: the edge goes as a self-removal through admin on the tag, at once
    alice.write_with(|w| w.unplace(t, g)).unwrap();
    assert!(!alice.roster(t).contains_key(&g), "removed with the unplace, before any sync");
    w.run();
    assert!(!bob.roster(t).contains_key(&g));
    assert_eq!(text(&alice, t), None, "Alice lost the card");
    assert_eq!(reach_of(&bob, t, g), None);

    // shared again, then Bob revokes the edge: the placement stays and re-grants nothing
    assert_eq!(bob.share_into(t, g, Role::Read, ShareOpts::default()).unwrap(), Share::Tied(Role::Read));
    w.run();
    w.until(bob.demote(t, g, osis::Lower::Remove, osis::Demotion::default()), 1000, 20).expect("pre-sync").unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    assert!(listed(&bob, g, t), "the placement stays");
    assert!(!bob.roster(t).contains_key(&g), "and grants nothing");
    assert_eq!(reach_of(&bob, t, g).map(|r| r.share), Some(Share::Excluded));
    // (the tag's members are not told of the removal: issues/group-edge-removal-unseen.md)
    edit(&bob, t, "plan v2");
    w.run();
    assert_eq!(text(&alice, t).as_deref(), Some("plan"), "nothing new reaches the tag");

    // the tag's admin removes a hand grant of the tag on Bob's card (pain point 3)
    bob.grant(t, g, Role::Read, EdgeOpts::default()).unwrap();
    w.run();
    assert!(matches!(bob.remove_edge_of(g, t), Err(Error::Invalid(_))), "Bob is the card's admin: demote");
    alice.remove_edge_of(g, t).unwrap();
    w.run();
    assert!(!bob.roster(t).contains_key(&g));
    assert!(matches!(alice.share_into(t, g, Role::Read, ShareOpts::default()), Err(Error::Permission { .. })), "only what you may share");
}

// spec/permissions.md §2 (tied edge removed), §2 (provenance): Carol, a writer of the tag, may not remove
// the tag's edge; after her unplace a node that may (Bob, the card's admin, or Alice, the tag's)
// removes the tied edge once synced. A hand grant to the tag on a placed card survives an unplace.
#[test]
fn obligation_after_unplace_and_hand_grant_survives() {
    let Setup { mut w, alice, bob, carol, g } = setup();
    let tied = card(&bob, "tied");
    let hand = card(&bob, "hand");
    bob.share_into(tied, g, Role::Read, ShareOpts::default()).unwrap();
    bob.write_with(|w| w.place(hand, g)).unwrap();
    bob.grant(hand, g, Role::Read, EdgeOpts::default()).unwrap();
    w.run();
    assert_eq!(reach_of(&carol, hand, g).map(|r| r.share), Some(Share::Untied(Role::Read)));
    carol.write_with(|w| {
        w.unplace(tied, g)?;
        w.unplace(hand, g)
    })
    .unwrap();
    assert!(carol.roster(tied).contains_key(&g), "Carol may not remove it");
    assert_eq!(reach_of(&carol, tied, g), Some(GroupReach { group: g, placed: false, share: Share::Tied(Role::Read) }));
    w.run();
    for db in [&alice, &bob, &carol] {
        assert_eq!(db.roster(hand).get(&g).map(|e| (e.role, e.tied)), Some((Role::Read, false)), "the hand grant stays");
    }
    for db in [&alice, &bob, &carol] {
        assert!(!db.roster(tied).contains_key(&g), "the tied edge went");
    }
    assert_eq!(text(&carol, tied), None, "Carol lost it");
}

// spec/permissions.md §2 (tied edge removed), concurrent add and remove, the safe direction: offline, Carol unplaces
// the card while Bob raises the tag's tied edge (the placement exists, so only the edge is
// written). The join has no placement and a tied edge: the obligation removes it.
#[test]
fn concurrent_raise_and_unplace_converge_unshared() {
    let Setup { mut w, alice, bob, carol, g } = setup();
    let t = card(&bob, "plan");
    bob.share_into(t, g, Role::Read, ShareOpts::default()).unwrap();
    w.run();
    w.set_online(&bob, false);
    w.set_online(&carol, false);
    carol.write_with(|w| w.unplace(t, g)).unwrap();
    assert_eq!(bob.share_into(t, g, Role::Write, ShareOpts::default()).unwrap(), Share::Tied(Role::Write));
    w.set_online(&bob, true);
    w.set_online(&carol, true);
    w.advance(60_000);
    w.run();
    for db in [&alice, &bob, &carol] {
        assert!(!listed(db, g, t));
    }
    for db in [&alice, &bob, &carol] {
        assert!(!db.roster(t).contains_key(&g), "unplaced and unshared");
    }
}

// spec/permissions.md §2 (nesting): a sub-tag shared into the tag with a tied edge, a card shared
// into the sub-tag; the tag's members reach the card through both; removing the sub-tag from the
// tag removes that tied edge and the reach.
#[test]
fn nested_tied_shares() {
    let Setup { mut w, alice, bob, carol, g } = setup();
    let sub = bob.write_with(|w| {
        let s = w.create(bob.me())?;
        w.make_group(s)?;
        Ok(s)
    })
    .unwrap();
    bob.sync(sub, &[]).unwrap();
    let t = card(&bob, "deep");
    assert_eq!(bob.share_into(sub, g, Role::Read, ShareOpts { subgroup: true, ..ShareOpts::default() }).unwrap(), Share::Tied(Role::Read));
    bob.share_into(t, sub, Role::Write, ShareOpts::default()).unwrap();
    // the sub-tag's own aspects (its roster among them) sync as an item of the tag
    bob.write_with(|w| w.place(sub, g)).unwrap();
    w.run();
    assert_eq!(text(&carol, t).as_deref(), Some("deep"), "tag -> sub-tag -> card");
    assert_eq!(carol.role_on(t), Some(Role::Read), "the minimum along the path");
    alice.write_with(|w| {
        w.remove_subgroup(g, sub)?;
        w.unplace(sub, g)
    })
    .unwrap();
    assert!(!alice.roster(sub).contains_key(&g), "Alice, admin of the tag only: at once");
    w.run();
    assert!(!bob.roster(sub).contains_key(&g));
    assert_eq!(bob.roster(t).get(&sub).map(|e| e.tied), Some(true), "the inner share stays");
    assert_eq!(carol.role_on(t), None);
}


// spec/permissions.md §2 (tied edge removed only once the placement is gone): Bob's laptop
// shares his card into Alice's tag while it reaches Bob's server but not the tag's; Bob's phone
// gets the tied edge from Bob's server and, after an unrelated write by Alice, passes the tag's
// label, which lacks the placement. The placement is on its way, not gone: the edge must stay
// (the tie names a placement the phone does not hold yet).
#[test]
fn edge_before_placement_is_not_removed() {
    let mut w = World::new();
    let s1 = w.add_server().unwrap();
    let s2 = w.add_server().unwrap();
    let alice = person(&mut w, 1, s1);
    let bob = person(&mut w, 2, s2);
    let join = Osis::pair(w.cfg(3, &[]), &bob.pair_offer().unwrap()).unwrap();
    let (_, reply) = bob.pair_accept(join.request()).unwrap();
    let phone = join.finish(&reply).unwrap();
    w.run();
    let b = introduce(&mut w, &alice, &bob);
    let g = new_tag(&alice, "Shared").unwrap();
    alice.grant(g, b, Role::Write, EdgeOpts::default()).unwrap();
    w.run();
    let t = card(&bob, "plan");
    bob.write_with(|w| w.place(t, bob.home())).unwrap();
    for _ in 0..3 {
        w.advance(70_000);
    }
    assert!(text(&phone, t).is_some() && phone.get(g, GROUP).unwrap().is_some(), "the phone holds the card and the tag");
    w.set_reachable(&bob, s1, false);
    assert_eq!(bob.share_into(t, g, Role::Read, ShareOpts::default()).unwrap(), Share::Tied(Role::Read));
    w.advance(70_000);
    assert!(phone.roster(t).get(&g).is_some_and(|e| e.tied) && !listed(&phone, g, t), "the phone has the edge, not the placement");
    // other activity under the tag's label: the phone passes it again
    alice.write_with(|w| w.at(g, osis::core::NAME).set(&"Shared!".to_string())).unwrap();
    for _ in 0..3 {
        w.advance(70_000);
    }
    w.set_reachable(&bob, s1, true);
    w.advance(70_000);
    assert!(listed(&alice, g, t));
    assert_eq!(bob.roster(t).get(&g).map(|e| e.tied), Some(true), "the share stays");
}

// spec/permissions.md §2 (the tie names the placement): Bob's phone gets the tied edge before the
// placement and keeps it; the placement arrives, then the phone (a writer of the tag, admin of the
// card) unplaces it: no self-removal, so its obligation removes the edge as an explicit demotion.
#[test]
fn edge_first_then_placement_then_unplace_removes_it() {
    let mut w = World::new();
    let s1 = w.add_server().unwrap();
    let s2 = w.add_server().unwrap();
    let alice = person(&mut w, 1, s1);
    let bob = person(&mut w, 2, s2);
    let join = Osis::pair(w.cfg(3, &[]), &bob.pair_offer().unwrap()).unwrap();
    let (_, reply) = bob.pair_accept(join.request()).unwrap();
    let phone = join.finish(&reply).unwrap();
    w.run();
    let b = introduce(&mut w, &alice, &bob);
    let g = new_tag(&alice, "Shared").unwrap();
    alice.grant(g, b, Role::Write, EdgeOpts::default()).unwrap();
    w.run();
    let t = card(&bob, "plan");
    bob.write_with(|w| w.place(t, bob.home())).unwrap();
    for _ in 0..3 {
        w.advance(70_000);
    }
    w.set_reachable(&bob, s1, false);
    bob.share_into(t, g, Role::Read, ShareOpts::default()).unwrap();
    w.advance(70_000);
    assert!(phone.roster(t).get(&g).is_some_and(|e| e.tied) && !listed(&phone, g, t), "the edge first");
    w.set_reachable(&bob, s1, true);
    for _ in 0..3 {
        w.advance(70_000);
    }
    assert!(listed(&phone, g, t) && listed(&alice, g, t), "then the placement");
    assert!(phone.roster(t).get(&g).is_some_and(|e| e.tied));
    assert_eq!(text(&alice, t).as_deref(), Some("plan"));
    // Alice, admin of the tag, would remove it too: offline, the phone's obligation alone
    w.set_online(&alice, false);
    phone.write_with(|w| w.unplace(t, g)).unwrap();
    assert!(phone.roster(t).contains_key(&g), "not a self-removal: left to the obligation");
    w.advance(70_000);
    assert!(!phone.roster(t).contains_key(&g) && !bob.roster(t).contains_key(&g), "the phone removed it");
    w.set_online(&alice, true);
    for _ in 0..3 {
        w.advance(70_000);
    }
    for db in [&alice, &bob, &phone] {
        assert!(!listed(db, g, t));
        assert!(!db.roster(t).contains_key(&g), "the tied edge went");
    }
}

// spec/permissions.md §2 (held dead), spec/crdt.md §4.2, §5.5: while Alice and Bob are offline,
// Carol unplaces the card and then replaces the tag's whole `/group`: the reset prunes the placement's tombstone, so the
// others never see the element; absent under a later reset counts as dead, and the edge goes.
#[test]
fn placement_pruned_by_a_reset_counts_as_gone() {
    let Setup { mut w, alice, bob, carol, g } = setup();
    let t = card(&bob, "plan");
    let other = card(&carol, "other");
    bob.share_into(t, g, Role::Read, ShareOpts::default()).unwrap();
    w.run();
    w.set_online(&alice, false);
    w.set_online(&bob, false);
    carol.write_with(|w| w.unplace(t, g)).unwrap();
    w.run();
    let group = osis::core::Group { items: [other].into(), subgroups: Default::default() };
    carol.write_with(|w| w.at(g, GROUP).replace(&group)).unwrap();
    w.run();
    w.set_online(&alice, true);
    w.set_online(&bob, true);
    w.advance(60_000);
    w.run();
    for db in [&alice, &bob, &carol] {
        assert!(!listed(db, g, t) && listed(db, g, other));
        assert!(!db.roster(t).contains_key(&g), "the tied edge went");
    }
}
