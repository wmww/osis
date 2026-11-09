//! Tied grants (spec/permissions.md §2, notes/tags.md Sharing a tag): `add_with_grant` writes the
//! membership and a tied grant together; a removal removes the tied grant at once where that is a
//! self-removal, else a node that may removes it later; one way only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common::TestWrites as _;
use crate::scenario::{account, introduce, new_tag};
use osis::internals::Internals as _;
use osis::internals::node::sync::EntryKind;
use osis::core::{BODY};
use osis::internals::core_types::{GROUP};
use osis::{SetRoleOpts, Member, GrantOpts, Error, Osis, Role, Tid};
use osis_sim::world::World;

fn card(db: &Osis, text: &str) -> Tid {
    db.commit_with(|w| {
        let c = w.create()?;
        w.at(c, BODY).set(&text.to_string())?;
        Ok(c)
    })
    .unwrap()
}

fn text(db: &Osis, t: Tid) -> Option<String> {
    db.at(t, BODY).get().unwrap()
}

fn edit(db: &Osis, t: Tid, new: &str) {
    db.commit_set(t, BODY, &new.to_string()).unwrap();
}

fn listed(db: &Osis, g: Tid, t: Tid) -> bool {
    db.at(g, GROUP).get().unwrap().unwrap_or_default().items.contains(&t)
}

/// How a group's holders reach a thing through that group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tie {
    /// A grant that goes with the membership.
    Tied(Role),
    /// A grant by hand: it stays when the membership goes.
    Untied(Role),
    /// A member with no grant: the group's holders do not reach it through this.
    Excluded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GroupView {
    group: Tid,
    member: bool,
    tie: Tie,
}

/// A group's view of a thing, from what the API tells: a member with or without a grant, or a grant
/// going with a membership that is gone.
fn reach_of(db: &Osis, t: Tid, g: Tid) -> Option<GroupView> {
    let gs = db.groups_of(t).unwrap();
    let member = gs.item_of.contains(&g) || gs.subgroup_of.contains(&g);
    let tie = match db.grants(t).unwrap().get(&g) {
        Some(e) if e.with_membership => Tie::Tied(e.role),
        Some(e) if member => Tie::Untied(e.role),
        None if member => Tie::Excluded,
        _ => return None,
    };
    Some(GroupView { group: g, member, tie })
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
    let host = w.add_host();
    let [alice, bob, carol] = [1, 2, 3].map(|s| account(&mut w, s, host));
    let b = introduce(&mut w, &alice, &bob);
    let c = introduce(&mut w, &alice, &carol);
    let g = new_tag(&alice, "Shared").unwrap();
    alice.grant(g, b, Role::Write, GrantOpts::default()).unwrap();
    alice.grant(g, c, Role::Write, GrantOpts::default()).unwrap();
    w.run();
    Setup { w, alice, bob, carol, g }
}

// spec/permissions.md §2 (the tie; self-removal by G's admin; one direction only): add_with_grant
// writes the membership and the tied grant at once; Alice, admin of the tag only, removes Bob's
// card and its tied grant goes in the same call; a stale membership never re-grants (Bob revokes
// the tag's grant, the membership stays, the card stays excluded); `leave` with the tag as holder is the tag
// admin's self-removal.
#[test]
fn add_with_grant_remove_and_stale_membership() {
    let Setup { mut w, alice, bob, carol, g } = setup();
    let t = card(&bob, "plan");
    bob.add_with_grant(Member::Item(t), g, Role::Write).unwrap();
    assert_eq!(reach_of(&bob, t, g).map(|r| r.tie), Some(Tie::Tied(Role::Write)));
    assert!(listed(&bob, g, t) && bob.grants(t).unwrap()[&g].with_membership, "membership and grant at once");
    w.run();
    assert_eq!(text(&alice, t).as_deref(), Some("plan"));
    assert_eq!(reach_of(&alice, t, g), Some(GroupView { group: g, member: true, tie: Tie::Tied(Role::Write) }));

    // no admin on Bob's card: the grant goes as a self-removal through admin on the tag, at once
    alice.commit_with(|w| w.group(g).remove(osis::Member::Item(t))).unwrap();
    assert!(!alice.grants(t).unwrap().contains_key(&g), "removed with the removal, before any sync");
    w.run();
    assert!(!bob.grants(t).unwrap().contains_key(&g));
    assert_eq!(text(&alice, t), None, "Alice lost the card");
    assert_eq!(reach_of(&bob, t, g), None);

    // shared again, then Bob revokes the grant: the membership stays and re-grants nothing
    bob.add_with_grant(Member::Item(t), g, Role::Read).unwrap();
    assert_eq!(reach_of(&bob, t, g).map(|r| r.tie), Some(Tie::Tied(Role::Read)));
    w.run();
    bob.set_role(t, g, None, SetRoleOpts::default()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    assert!(listed(&bob, g, t), "the membership stays");
    assert!(!bob.grants(t).unwrap().contains_key(&g), "and grants nothing");
    assert_eq!(reach_of(&bob, t, g).map(|r| r.tie), Some(Tie::Excluded));
    for db in [&alice, &carol] {
        assert!(!db.grants(t).unwrap().contains_key(&g), "the tag's holders learn the removal");
    }
    edit(&bob, t, "plan v2");
    w.run();
    assert_eq!(text(&alice, t), None, "the tag lost the card, nothing new reaches it");

    // the tag's admin removes a hand grant of the tag on Bob's card (pain point 3)
    bob.grant(t, g, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    assert!(matches!(bob.leave(g, t), Err(Error::Invalid(_))), "Bob is the card's admin: set_role");
    alice.leave(g, t).unwrap();
    w.run();
    assert!(!bob.grants(t).unwrap().contains_key(&g));
    assert!(matches!(alice.add_with_grant(Member::Item(t), g, Role::Read), Err(Error::Permission { .. })), "only what you may share");
}

// spec/permissions.md §2 (tied edge removed), §2 (provenance): Carol, a writer of the tag, may not remove
// the tag's grant; after her remove a node that may (Bob, the card's admin, or Alice, the tag's)
// removes the tied grant once synced. A hand grant to the tag on an added card survives a removal.
#[test]
fn obligation_after_remove_and_hand_grant_survives() {
    let Setup { mut w, alice, bob, carol, g } = setup();
    let tied = card(&bob, "tied");
    let hand = card(&bob, "hand");
    bob.add_with_grant(Member::Item(tied), g, Role::Read).unwrap();
    bob.commit_with(|w| w.group(g).add(osis::Member::Item(hand))).unwrap();
    bob.grant(hand, g, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    assert_eq!(reach_of(&carol, hand, g).map(|r| r.tie), Some(Tie::Untied(Role::Read)));
    carol.commit_with(|w| {
        w.group(g).remove(osis::Member::Item(tied))?;
        w.group(g).remove(osis::Member::Item(hand))
    })
    .unwrap();
    assert!(carol.grants(tied).unwrap().contains_key(&g), "Carol may not remove it");
    assert_eq!(reach_of(&carol, tied, g), Some(GroupView { group: g, member: false, tie: Tie::Tied(Role::Read) }));
    w.run();
    for db in [&alice, &bob, &carol] {
        assert_eq!(db.grants(hand).unwrap().get(&g).map(|e| (e.role, e.with_membership)), Some((Role::Read, false)), "the hand grant stays");
    }
    for db in [&alice, &bob, &carol] {
        assert!(!db.grants(tied).unwrap().contains_key(&g), "the tied grant went");
    }
    assert_eq!(text(&carol, tied), None, "Carol lost it");
}

// spec/permissions.md §2 (tied edge removed), concurrent add and remove, the safe direction: offline, Carol removes
// the card while Bob raises the tag's tied grant (the membership exists, so only the grant is
// written). The join has no membership and a tied grant: the obligation removes it.
#[test]
fn concurrent_raise_and_remove_converge_ungranted() {
    let Setup { mut w, alice, bob, carol, g } = setup();
    let t = card(&bob, "plan");
    bob.add_with_grant(Member::Item(t), g, Role::Read).unwrap();
    w.run();
    w.set_online(&bob, false);
    w.set_online(&carol, false);
    carol.commit_with(|w| w.group(g).remove(osis::Member::Item(t))).unwrap();
    bob.add_with_grant(Member::Item(t), g, Role::Write).unwrap();
    assert_eq!(reach_of(&bob, t, g).map(|r| r.tie), Some(Tie::Tied(Role::Write)));
    w.set_online(&bob, true);
    w.set_online(&carol, true);
    w.advance(60_000);
    w.run();
    for db in [&alice, &bob, &carol] {
        assert!(!listed(db, g, t));
    }
    for db in [&alice, &bob, &carol] {
        assert!(!db.grants(t).unwrap().contains_key(&g), "removed and unshared");
    }
}

// spec/permissions.md §2 (nesting): a sub-tag shared into the tag with a tied grant, a card shared
// into the sub-tag; the tag's holders reach the card through both; removing the sub-tag from the
// tag removes that tied grant and the reach.
#[test]
fn nested_tied_grants() {
    let Setup { mut w, alice, bob, carol, g } = setup();
    let sub = bob.commit_with(|w| {
        let s = w.create()?;
        Ok(s)
    })
    .unwrap();
    bob.sync(sub, &[]).unwrap();
    let t = card(&bob, "deep");
    bob.add_with_grant(Member::Subgroup(sub), g, Role::Read).unwrap();
    assert_eq!(reach_of(&bob, sub, g).map(|r| r.tie), Some(Tie::Tied(Role::Read)));
    bob.add_with_grant(Member::Item(t), sub, Role::Write).unwrap();
    // the sub-tag's own aspects (its roster among them) sync as an item of the tag
    bob.commit_with(|w| w.group(g).add(osis::Member::Item(sub))).unwrap();
    w.run();
    assert_eq!(text(&carol, t).as_deref(), Some("deep"), "tag -> sub-tag -> card");
    assert_eq!(carol.role_on(t).unwrap(), Some(Role::Read), "the minimum along the path");
    alice.commit_with(|w| {
        w.group(g).remove(osis::Member::Subgroup(sub))?;
        w.group(g).remove(osis::Member::Item(sub))
    })
    .unwrap();
    assert!(!alice.grants(sub).unwrap().contains_key(&g), "Alice, admin of the tag only: at once");
    w.run();
    assert!(!bob.grants(sub).unwrap().contains_key(&g));
    assert_eq!(bob.grants(t).unwrap().get(&sub).map(|e| e.with_membership), Some(true), "the inner share stays");
    assert_eq!(carol.role_on(t).unwrap(), None);
}


// spec/permissions.md §2 (tied edge removed): Bob's phone holds his sub-tag but does not sync
// it. Carol removes it from the tag while Alice and Bob's
// laptop are away: the phone, admin of the sub-tag by Bob, sees the tie die but leaves the
// grant to the sub-tag's holders; Bob's laptop removes it once back.
#[test]
fn stopped_scope_left_to_holders() {
    let Setup { mut w, alice, bob, carol, g } = setup();
    let join = osis::internals::pair(w.cfg(4, &[]), &bob.pair_offer().unwrap()).unwrap();
    let (_, reply) = bob.pair_accept(join.request()).unwrap();
    let phone = join.finish(&reply).unwrap();
    let sub = bob.commit_with(|w| {
        let s = w.create()?;
        Ok(s)
    })
    .unwrap();
    bob.sync(sub, &[]).unwrap();
    bob.add_with_grant(Member::Item(sub), g, Role::Read).unwrap();
    assert_eq!(reach_of(&bob, sub, g).map(|r| r.tie), Some(Tie::Tied(Role::Read)));
    w.run();
    phone.set_sync_options(sub, osis::SyncOptions { mode: osis::SyncMode::Stopped }).unwrap();
    w.run();
    assert_eq!(phone.grants(sub).unwrap().get(&g).map(|e| e.with_membership), Some(true));
    w.set_online(&alice, false);
    w.set_online(&bob, false);
    carol.commit_with(|w| w.group(g).remove(osis::Member::Item(sub))).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    assert!(!listed(&phone, g, sub), "the phone saw the removal");
    assert!(phone.grants(sub).unwrap().contains_key(&g), "but left the tied grant alone");
    w.set_online(&alice, true);
    w.set_online(&bob, true);
    w.advance(60_000);
    w.run();
    assert!(!bob.grants(sub).unwrap().contains_key(&g), "a holder removed it");
}

// spec/permissions.md §2 (tied edge removed only once the membership is gone): Bob's laptop
// shares his card into Alice's tag while it reaches Bob's peer but not the tag's; Bob's phone
// gets the tied grant from Bob's peer and, after an unrelated write by Alice, passes the tag's
// label, which lacks the membership. The membership is on its way, not gone: the grant must stay
// (the tie names a membership the phone does not hold yet).
#[test]
fn grant_before_membership_is_not_removed() {
    let mut w = World::new();
    let s1 = w.add_host();
    let s2 = w.add_host();
    let alice = account(&mut w, 1, s1);
    let bob = account(&mut w, 2, s2);
    let join = osis::internals::pair(w.cfg(3, &[]), &bob.pair_offer().unwrap()).unwrap();
    let (_, reply) = bob.pair_accept(join.request()).unwrap();
    let phone = join.finish(&reply).unwrap();
    w.run();
    let b = introduce(&mut w, &alice, &bob);
    let g = new_tag(&alice, "Shared").unwrap();
    alice.grant(g, b, Role::Write, GrantOpts::default()).unwrap();
    w.run();
    let t = card(&bob, "plan");
    bob.commit_with(|w| w.group(bob.home()).add(osis::Member::Item(t))).unwrap();
    for _ in 0..3 {
        w.advance(70_000);
    }
    assert!(text(&phone, t).is_some() && phone.has_content(g).unwrap(), "the phone holds the card and the tag");
    w.set_reachable(&bob, s1, false);
    bob.add_with_grant(Member::Item(t), g, Role::Read).unwrap();
    assert_eq!(reach_of(&bob, t, g).map(|r| r.tie), Some(Tie::Tied(Role::Read)));
    w.advance(70_000);
    assert!(phone.grants(t).unwrap().get(&g).is_some_and(|e| e.with_membership) && !listed(&phone, g, t), "the phone has the grant, not the membership");
    // other activity under the tag's label: the phone passes it again
    alice.commit_set(g, osis::core::NAME, &"Shared!".to_string()).unwrap();
    for _ in 0..3 {
        w.advance(70_000);
    }
    w.set_reachable(&bob, s1, true);
    w.advance(70_000);
    assert!(listed(&alice, g, t));
    assert_eq!(bob.grants(t).unwrap().get(&g).map(|e| e.with_membership), Some(true), "the share stays");
}

// spec/permissions.md §2 (the tie names the membership): Bob's phone gets the tied grant before the
// membership and keeps it; the membership arrives, then the phone (a writer of the tag, admin of the
// card) removes it: no self-removal, so its obligation removes the grant as an explicit role removal.
#[test]
fn grant_first_then_add_then_remove_removes_it() {
    let mut w = World::new();
    let s1 = w.add_host();
    let s2 = w.add_host();
    let alice = account(&mut w, 1, s1);
    let bob = account(&mut w, 2, s2);
    let join = osis::internals::pair(w.cfg(3, &[]), &bob.pair_offer().unwrap()).unwrap();
    let (_, reply) = bob.pair_accept(join.request()).unwrap();
    let phone = join.finish(&reply).unwrap();
    w.run();
    let b = introduce(&mut w, &alice, &bob);
    let g = new_tag(&alice, "Shared").unwrap();
    alice.grant(g, b, Role::Write, GrantOpts::default()).unwrap();
    w.run();
    let t = card(&bob, "plan");
    bob.commit_with(|w| w.group(bob.home()).add(osis::Member::Item(t))).unwrap();
    for _ in 0..3 {
        w.advance(70_000);
    }
    w.set_reachable(&bob, s1, false);
    bob.add_with_grant(Member::Item(t), g, Role::Read).unwrap();
    w.advance(70_000);
    assert!(phone.grants(t).unwrap().get(&g).is_some_and(|e| e.with_membership) && !listed(&phone, g, t), "the grant first");
    w.set_reachable(&bob, s1, true);
    for _ in 0..3 {
        w.advance(70_000);
    }
    assert!(listed(&phone, g, t) && listed(&alice, g, t), "then the membership");
    assert!(phone.grants(t).unwrap().get(&g).is_some_and(|e| e.with_membership));
    assert_eq!(text(&alice, t).as_deref(), Some("plan"));
    // Alice, admin of the tag, would remove it too: offline, the phone's obligation alone
    w.set_online(&alice, false);
    phone.commit_with(|w| w.group(g).remove(osis::Member::Item(t))).unwrap();
    assert!(phone.grants(t).unwrap().contains_key(&g), "not a self-removal: left to the obligation");
    w.advance(70_000);
    assert!(!phone.grants(t).unwrap().contains_key(&g) && !bob.grants(t).unwrap().contains_key(&g), "the phone removed it");
    w.set_online(&alice, true);
    for _ in 0..3 {
        w.advance(70_000);
    }
    for db in [&alice, &bob, &phone] {
        assert!(!listed(db, g, t));
        assert!(!db.grants(t).unwrap().contains_key(&g), "the tied grant went");
    }
}

// spec/permissions.md §2 (held dead), spec/crdt.md §4.2, §5.5: while Alice and Bob are offline,
// Carol removes the card and then replaces the tag's whole `group.0`: the reset prunes the membership's tombstone, so the
// others never see the element; absent under a later reset counts as dead, and the grant goes.
#[test]
fn membership_pruned_by_a_reset_counts_as_gone() {
    let Setup { mut w, alice, bob, carol, g } = setup();
    let t = card(&bob, "plan");
    let other = card(&carol, "other");
    bob.add_with_grant(Member::Item(t), g, Role::Read).unwrap();
    w.run();
    w.set_online(&alice, false);
    w.set_online(&bob, false);
    carol.commit_with(|w| w.group(g).remove(osis::Member::Item(t))).unwrap();
    w.run();
    let group = osis::internals::core_types::Group { items: [other].into(), subgroups: Default::default() };
    // no API call does this; another implementation's commit may
    carol.engine(|e| {
        let mut m = osis::internals::node::Mutation::new();
        m.op(g, &GROUP, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Replace(osis::Codec::to_value(&group)) })?;
        e.write(m)
    }).unwrap();
    w.run();
    w.set_online(&alice, true);
    w.set_online(&bob, true);
    w.advance(60_000);
    w.run();
    for db in [&alice, &bob, &carol] {
        assert!(!listed(db, g, t) && listed(db, g, other));
        assert!(!db.grants(t).unwrap().contains_key(&g), "the tied grant went");
    }
}

// spec/permissions.md §2 (held dead), §5 (a demotion invalidates the demoted writer's later
// writes): offline, Bob adds his card to the tag with a grant while Alice lowers him to reader of the tag.
// His membership is invalid everywhere and never arrives; his tied grant on his own card is valid.
// The tie names an element no node will hold: the grant must go, not wait forever.
#[test]
fn invalidated_membership_removes_the_tied_grant() {
    let Setup { mut w, alice, bob, carol, g } = setup();
    let t = card(&bob, "plan");
    bob.commit_with(|w| w.group(bob.home()).add(osis::Member::Item(t))).unwrap();
    w.run();
    w.set_online(&bob, false);
    bob.add_with_grant(Member::Item(t), g, Role::Read).unwrap();
    assert_eq!(reach_of(&bob, t, g).map(|r| r.tie), Some(Tie::Tied(Role::Read)));
    alice.set_role(g, bob.me(), Some(Role::Read), SetRoleOpts::default()).unwrap();
    w.run();
    w.set_online(&bob, true);
    for _ in 0..4 {
        w.advance(70_000);
    }
    for db in [&alice, &bob, &carol] {
        assert!(!listed(db, g, t), "the membership is invalid");
        assert!(!db.grants(t).unwrap().contains_key(&g), "the tied grant went");
    }
}

// spec/permissions.md §2 (a removal of another actor's grant is placed under the labels holding
// it): Bob, the card's admin, removes the tag's hand-granted grant on his card added to the tag;
// the tag's admin and its other writer drop it from their roster and reach and lose the card
// (the removal leaves the tag's closure bodies, so only that membership tells Carol). Whether Carol
// reads the card's fresh deposit seed through its own sync ID: issues/removed-holder-reads-fresh-deposit-seed.md.
#[test]
fn group_holders_learn_grant_removal() {
    let Setup { mut w, alice, bob, carol, g } = setup();
    let t = card(&bob, "plan");
    bob.commit_with(|w| w.group(g).add(osis::Member::Item(t))).unwrap();
    bob.grant(t, g, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    for db in [&alice, &carol] {
        assert!(db.grants(t).unwrap().contains_key(&g), "granted");
    }
    let seed = |db: &Osis| db.at(t, osis::internals::core_types::KEYS).get().unwrap().and_then(|k| k.deposit_seed);
    let old = seed(&bob);
    bob.set_role(t, g, None, SetRoleOpts::default()).unwrap();
    w.run();
    for db in [&alice, &bob, &carol] {
        assert!(!db.grants(t).unwrap().contains_key(&g), "the removal reached {}", db.me());
        assert_eq!(reach_of(db, t, g).map(|r| r.tie), Some(Tie::Excluded));
    }
    assert_eq!(text(&carol, t), None, "Carol lost the card");
    assert_ne!(seed(&bob), old, "the removal refreshed the card's deposit seed");
    // the seed itself, Carol may learn: issues/removed-holder-reads-fresh-deposit-seed.md
}

// spec/sync.md §2 (an actor naming no inbox uses its first admin's), §3: Bob grants the tag (which names
// no inbox) read on his own tag; the blob sealed to the tag under Alice's home label opens there,
// so Alice, the tag's admin, learns the grant and its removal.
#[test]
fn inherited_inbox_opens() {
    let Setup { mut w, alice, bob, carol, g } = setup();
    let t = new_tag(&bob, "Bob's").unwrap();
    bob.grant(t, g, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    for db in [&alice, &carol] {
        assert!(db.grants(t).unwrap().contains_key(&g), "the grant reached {}", db.me());
        assert_eq!(db.at(t, osis::core::NAME).get().unwrap(), Some("Bob's".to_string()));
    }
    bob.set_role(t, g, None, SetRoleOpts::default()).unwrap();
    w.run();
    for db in [&alice, &carol] {
        assert!(!db.grants(t).unwrap().contains_key(&g), "and its removal {}", db.me());
    }
}

// spec/permissions.md §2 (a node that applied a removal of G's grant on a thing in G's closure
// places it under G's labels): Dave, admin of Bob's card through his tag H only (he syncs no
// label holding the tag G and holds no `keys.0` of G, so no inbox blob goes), removes G's grant on
// the card added to G and H; Alice, G's admin, learns it through H and places it under G's
// label, so Carol learns it too (before, she uploaded the card's bodies Alice deleted there
// again on every pass). The card's new deposit seed: not from that copy; Carol still reaches the
// card's own sync ID (issues/removed-holder-reads-fresh-deposit-seed.md).
#[test]
fn group_admin_learns_removal_elsewhere() {
    let Setup { mut w, alice, bob, carol, g } = setup();
    let dave = account(&mut w, 4, 0);
    let b = introduce(&mut w, &dave, &bob);
    let a = introduce(&mut w, &dave, &alice);
    let h = new_tag(&dave, "H").unwrap();
    dave.grant(h, b, Role::Write, GrantOpts::default()).unwrap();
    dave.grant(h, a, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    let t = card(&bob, "plan");
    bob.commit_with(|w| {
        w.group(g).add(osis::Member::Item(t))?;
        w.group(h).add(osis::Member::Item(t))
    })
    .unwrap();
    bob.grant(t, g, Role::Read, GrantOpts::default()).unwrap();
    bob.grant(t, h, Role::Admin, GrantOpts::default()).unwrap();
    w.run();
    assert_eq!(text(&carol, t).as_deref(), Some("plan"));
    let seed = |db: &Osis| db.at(t, osis::internals::core_types::KEYS).get().unwrap().and_then(|k| k.deposit_seed);
    let old = seed(&carol);
    dave.set_role(t, g, None, SetRoleOpts::default()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    let stale: Vec<&str> = [("alice", &alice), ("bob", &bob), ("carol", &carol), ("dave", &dave)].into_iter().filter(|(_, db)| db.grants(t).unwrap().contains_key(&g)).map(|(n, _)| n).collect();
    assert!(stale.is_empty(), "the removal reached everyone; not {stale:?}");
    assert_ne!(seed(&bob), old, "the removal refreshed the card's deposit seed");
    // and the deletes are not undone again: nothing of the card is back under the tag's label
    let l = carol.engine(|e| e.group_labels(&g).unwrap().into_iter().find(|x| !x.replaced).unwrap().id);
    let of_card = |db: &Osis| {
        let entries = db.sync_engine(|s| s.entries(&l));
        entries.into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if db.engine(|e| e.header(commit).is_some_and(|h| h.aspects.iter().any(|a| a.tid == t))))).count()
    };
    let before = of_card(&carol);
    w.advance(3_600_000);
    w.run();
    assert_eq!(of_card(&carol), before, "Carol re-uploads nothing of the card");
}

// spec/sync.md §3: a removal by someone who knows the group's keys comes by its inbox: the admin's copy, with the remover's chain, leaves out the thing's newest `keys.0` (a later reader of the group never learns the fresh seed: `zoe` below; Carol, a reader until the removal, can: issues/removed-holder-reads-fresh-deposit-seed.md)
#[test]
fn group_admin_copies_removal_without_new_keys() {
    let Setup { mut w, alice, bob, carol, g } = setup();
    let dave = account(&mut w, 4, 0);
    let b = introduce(&mut w, &dave, &bob);
    let a = introduce(&mut w, &dave, &alice);
    let d = dave.me();
    let h = new_tag(&dave, "H").unwrap();
    dave.grant(h, b, Role::Write, GrantOpts::default()).unwrap();
    dave.grant(h, a, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    // dave learns g's keys
    let met = card(&alice, "met");
    alice.sync(met, &[]).unwrap();
    alice.grant(met, g, Role::Read, GrantOpts::default()).unwrap();
    alice.grant(met, d, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    assert_eq!(text(&dave, met).as_deref(), Some("met"));
    let t = card(&bob, "plan");
    bob.commit_with(|w| {
        w.group(g).add(osis::Member::Item(t))?;
        w.group(h).add(osis::Member::Item(t))
    })
    .unwrap();
    bob.grant(t, g, Role::Read, GrantOpts::default()).unwrap();
    bob.grant(t, h, Role::Admin, GrantOpts::default()).unwrap();
    w.run();
    assert_eq!(text(&carol, t).as_deref(), Some("plan"));
    let seed = |db: &Osis| db.at(t, osis::internals::core_types::KEYS).get().unwrap().and_then(|k| k.deposit_seed);
    let old = seed(&carol);
    dave.set_role(t, g, None, SetRoleOpts::default()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    assert!(!carol.grants(t).unwrap().contains_key(&g), "the removal reached carol");
    assert_ne!(seed(&dave), old, "the removal refreshed the deposit seed");
}

/// A removal that does not wait for sync.
fn skip() -> SetRoleOpts {
    SetRoleOpts::default()
}

fn seed_of(db: &Osis, t: Tid) -> Option<[u8; 32]> {
    db.at(t, osis::internals::core_types::KEYS).get().ok().flatten().and_then(|k| k.deposit_seed)
}

// spec/sync.md §5, §6: Dave reads G and removes G's grant on his card outside G's closure: his deposit under G's label is promoted by its admin, who reads the card no more and holds none of its fresh `keys.0`, its author's chain complete without it; a reader joining later learns the removal and not the fresh deposit seed
#[test]
fn group_removal_deposit_promoted_without_new_keys() {
    let Setup { mut w, alice, bob: _, carol: _, g } = setup();
    let dave = account(&mut w, 4, 0);
    let zoe = account(&mut w, 6, 0);
    let d = introduce(&mut w, &alice, &dave);
    let z = introduce(&mut w, &alice, &zoe);
    alice.grant(g, d, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    let t = card(&dave, "plan");
    dave.sync(t, &[]).unwrap();
    dave.grant(t, g, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    assert_eq!(text(&alice, t).as_deref(), Some("plan"));
    dave.set_role(t, g, None, skip()).unwrap();
    w.run();
    w.advance(120_000);
    w.run();
    let (r, l) = dave.engine(|e| (e.aspect_commit(&t, "roles.0").unwrap().0, e.group_labels(&g).unwrap()[0].id));
    let ids: Vec<_> = alice.sync_engine(|s| s.entries(&l)).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == r)).map(|(id, _)| id).collect();
    assert!(!ids.is_empty(), "the removal is under G's label");
    for id in &ids {
        let e = osis_proto::store::LabelStore::entry(w.hosts[0].hub.store(), &l, id).unwrap().unwrap();
        assert!(e.stamp.is_some(), "promoted");
    }
    alice.grant(g, z, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    assert!(!zoe.grants(t).unwrap().contains_key(&g), "the removal reached zoe");
    assert_ne!(seed_of(&zoe, t), seed_of(&dave, t), "zoe does not learn the fresh seed");
}

// spec/sync.md §3: M's first admin is group O; Dave removes M's grant on his card; the copy under O's home label leaves out the fresh deposit seed, which a reader joining O later would otherwise read there
#[test]
fn first_admin_home_copy_of_removal_without_new_keys() {
    let mut w = World::new();
    let host = w.add_host();
    let [alice, eve, dave, zoe] = [1, 2, 4, 6].map(|s| account(&mut w, s, host));
    let e = introduce(&mut w, &alice, &eve);
    let d = introduce(&mut w, &alice, &dave);
    let z = introduce(&mut w, &alice, &zoe);
    let o = new_tag(&alice, "O").unwrap();
    alice.grant(o, e, Role::Read, GrantOpts::default()).unwrap();
    let m = alice
        .commit_with(|w| {
            let m = w.create_with_admin(o)?;
            Ok(m)
        })
        .unwrap();
    alice.sync(m, &[]).unwrap();
    w.run();
    alice.grant(m, d, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    let t = card(&dave, "plan");
    dave.sync(t, &[]).unwrap();
    dave.grant(t, m, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    assert_eq!(text(&alice, t).as_deref(), Some("plan"));
    dave.set_role(t, m, None, skip()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    alice.grant(o, z, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    assert_ne!(seed_of(&zoe, t), seed_of(&dave, t), "O's later reader learns the fresh seed");
}

/// Dave's card `t`, with H (Alice's tag, Eve co-admin, Carol reader) whose keys Dave knows.
fn outsider() -> (World, Osis, Osis, Osis, Osis, Osis, Tid, Tid, Tid) {
    let mut w = World::new();
    let host = w.add_host();
    let [alice, eve, dave, carol, bob] = [1, 2, 4, 5, 6].map(|s| account(&mut w, s, host));
    let e = introduce(&mut w, &alice, &eve);
    let d = introduce(&mut w, &alice, &dave);
    let c = introduce(&mut w, &alice, &carol);
    let b = introduce(&mut w, &alice, &bob);
    let h = new_tag(&alice, "H").unwrap();
    alice.grant(h, e, Role::Admin, GrantOpts::default()).unwrap();
    alice.grant(h, c, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    let m = card(&alice, "meeting");
    alice.sync(m, &[]).unwrap();
    alice.grant(m, h, Role::Read, GrantOpts::default()).unwrap();
    alice.grant(m, d, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    alice.set_role(m, h, None, skip()).unwrap();
    w.run();
    let t = card(&dave, "dave's");
    w.run();
    (w, alice, eve, dave, carol, bob, h, b, t)
}

// spec/sync.md §3: a `label.0` write after a rotation is a delta on the record an earlier one set: a grant to a group of a thing rotated before it copies them all, or the group's readers never find the thing's label
#[test]
fn grant_to_group_of_a_thing_rotated_before() {
    let (mut w, alice, _eve, dave, carol, _bob, h, _b, t) = outsider();
    let frank = account(&mut w, 7, 0);
    let f = introduce(&mut w, &dave, &frank);
    dave.sync(t, &[]).unwrap();
    dave.grant(t, f, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    dave.set_role(t, f, None, skip()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    dave.grant(t, h, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    assert_eq!(text(&alice, t).as_deref(), Some("dave's"));
    assert_eq!(text(&carol, t).as_deref(), Some("dave's"), "the group's reader");
}

// spec/sync.md §3, §6: H lost the grant while its one copying admin was away and got it back: she holds the removal from the inbox without its `keys.0`, and a co-admin must not delete her copies for lack of it; a reader joining later reads the thing
#[test]
fn grant_lost_and_regained_with_the_admin_away() {
    let (mut w, alice, eve, dave, carol, bob, h, b, t) = outsider();
    dave.sync(t, &[]).unwrap();
    dave.grant(t, h, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    assert_eq!(text(&carol, t).as_deref(), Some("dave's"));
    w.set_online(&alice, false);
    dave.set_role(t, h, None, skip()).unwrap();
    w.run();
    w.advance(30_000);
    w.run();
    w.set_online(&eve, false);
    w.set_online(&alice, true);
    dave.grant(t, h, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    w.advance(30_000);
    w.run();
    w.set_online(&eve, true);
    w.run();
    w.advance(120_000);
    w.run();
    alice.grant(h, b, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    w.advance(120_000);
    w.run();
    for (n, db) in [("alice", &alice), ("eve", &eve), ("carol", &carol), ("bob", &bob)] {
        assert_eq!(text(db, t).as_deref(), Some("dave's"), "{n}");
    }
}

// spec/sync.md §3, §6: a thing's grant to a group granted and removed in turn with its admins and a reader going away and back: all end alike, a later reader reads it or not by the last write and never learns a seed it should not, and the label goes quiet
#[test]
#[ignore = "tier 2: 40 seeds, about 3 minutes"]
fn grant_and_removal_orders_large() {
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_TIED_START", "OSIS_TIED_SEEDS", osis_base::testenv::large(0..40));
    seeds.announce("grant_and_removal_orders_large");
    for seed in seeds.range {
        let mut r = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut next = move |m: u64| {
            r ^= r << 13;
            r ^= r >> 7;
            r ^= r << 17;
            r % m
        };
        let (mut w, alice, eve, dave, carol, bob, h, b, t) = outsider();
        let ops = 1 + next(5);
        let mut granted = false;
        for _ in 0..ops {
            for db in [&alice, &eve, &carol] {
                let on = next(3) != 0;
                w.set_online(db, on);
            }
            w.run();
            if granted {
                dave.set_role(t, h, None, skip()).unwrap();
            } else {
                dave.sync(t, &[]).unwrap();
                dave.grant(t, h, Role::Read, GrantOpts::default()).unwrap();
            }
            granted = !granted;
            w.run();
            if next(2) == 0 {
                w.advance(1 + next(60_000));
                w.run();
            }
        }
        for db in [&alice, &eve, &carol] {
            w.set_online(db, true);
        }
        w.run();
        w.advance(120_000);
        w.run();
        // an admin copies a removal `SETTLE_MS` after it arrives, and it arrived in that advance
        w.advance(120_000);
        w.run();
        for (n, db) in [("alice", &alice), ("eve", &eve), ("carol", &carol), ("dave", &dave)] {
            assert_eq!(db.grants(t).unwrap().contains_key(&h), granted, "seed {seed}: {n}'s roster");
        }
        alice.grant(h, b, Role::Read, GrantOpts::default()).unwrap();
        w.run();
        w.advance(120_000);
        w.run();
        if granted {
            for (n, db) in [("alice", &alice), ("eve", &eve), ("carol", &carol), ("bob", &bob)] {
                assert_eq!(text(db, t).as_deref(), Some("dave's"), "seed {seed}: {n} reads");
            }
        } else {
            assert_eq!(text(&bob, t), None, "seed {seed}: bob reads");
            assert_ne!(seed_of(&bob, t), seed_of(&dave, t), "seed {seed}: bob's seed");
        }
        w.start_tally();
        w.advance(3_600_000);
        w.run();
        for (n, db) in [("alice", &alice), ("eve", &eve), ("carol", &carol), ("bob", &bob), ("dave", &dave)] {
            let tally = w.tally(db);
            // a heartbeat an hour is all that goes up
            assert!(!tally.contains_key("Delete") && tally.get("Upload").is_none_or(|u| u.0 < 4), "seed {seed}: {n}: {tally:?}");
        }
    }
}


/// Bob joins H once all is quiet, and must read `t` from what its label holds.
fn later_reader_reads(w: &mut World, alice: &Osis, bob: &Osis, h: Tid, b: Tid, t: Tid, what: &str) {
    w.advance(120_000);
    w.run();
    alice.grant(h, b, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    w.advance(120_000);
    w.run();
    assert_eq!(text(bob, t).as_deref(), Some("dave's"), "{what}");
}

// spec/sync.md §6, spec/permissions.md §4: a copy's chain leaves out every `keys.0`: the outside granter rotating his account after the grant must not lose the copy
#[ignore = "needs step (e): an account's keys move only by a rotation of its epoch (issues/account-signing.md)"]
#[test]
fn a_copy_survives_its_granter_rotating() {
    let (mut w, alice, _eve, dave, carol, bob, h, b, t) = outsider();
    dave.sync(t, &[]).unwrap();
    dave.grant(t, h, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    assert_eq!(text(&carol, t).as_deref(), Some("dave's"));
    let frank = account(&mut w, 7, 0);
    let f = introduce(&mut w, &dave, &frank);
    let keys = alice.at(dave.home(), osis::internals::core_types::KEYS).get().unwrap();
    dave.grant(dave.me(), f, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    dave.set_role(dave.home(), f, None, skip()).unwrap();
    w.run();
    assert_ne!(alice.at(dave.home(), osis::internals::core_types::KEYS).get().unwrap(), keys, "alice holds his new keys");
    later_reader_reads(&mut w, &alice, &bob, h, b, t, "the granter's keys moved");
}

/// Frank's `t` with Dave its admin by a grant, granted by Dave to H.
fn franks_thing(w: &mut World, dave: &Osis, h: Tid) -> (Osis, Tid, Tid) {
    let frank = account(w, 7, 0);
    let fd = introduce(w, &frank, dave);
    let t = card(&frank, "dave's");
    frank.sync(t, &[]).unwrap();
    frank.grant(t, fd, Role::Admin, GrantOpts::default()).unwrap();
    w.run();
    dave.grant(t, h, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    (frank, t, fd)
}

// spec/sync.md §6: the granter's chain moves after the copy (his grant lowered) with the copying admin away: the co-admin completes it rather than delete the copy
#[test]
fn a_copy_survives_its_granters_grant_changing() {
    let (mut w, alice, eve, dave, carol, bob, h, b, _t) = outsider();
    let (frank, t, fd) = franks_thing(&mut w, &dave, h);
    assert_eq!(text(&carol, t).as_deref(), Some("dave's"));
    w.set_online(&alice, false);
    frank.set_role(t, fd, Some(Role::Write), skip()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    assert_eq!(text(&eve, t).as_deref(), Some("dave's"));
    w.set_online(&alice, true);
    w.run();
    later_reader_reads(&mut w, &alice, &bob, h, b, t, "the granter's grant moved");
    assert_eq!(text(&alice, t).as_deref(), Some("dave's"));
}

// spec/sync.md §6: the same with the granter removed from the thing
#[test]
fn a_copy_survives_its_granter_leaving() {
    let (mut w, alice, _e, dave, _c, bob, h, b, _t) = outsider();
    let (frank, t, fd) = franks_thing(&mut w, &dave, h);
    frank.set_role(t, fd, None, skip()).unwrap();
    w.run();
    later_reader_reads(&mut w, &alice, &bob, h, b, t, "the granter removed");
}

// spec/sync.md §3: a copy carries no `keys.0` of the thing: a group's reader with write finds them under its label, stamps and is read by all
#[test]
fn a_write_grant_by_an_outsider_writes() {
    let (mut w, alice, eve, dave, carol, bob, h, b, t) = outsider();
    dave.sync(t, &[]).unwrap();
    dave.grant(t, h, Role::Write, GrantOpts::default()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    alice.grant(h, b, Role::Write, GrantOpts::default()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    assert_eq!(text(&bob, t).as_deref(), Some("dave's"));
    edit(&bob, t, "by bob");
    w.run();
    w.advance(60_000);
    w.run();
    for (n, db) in [("alice", &alice), ("eve", &eve), ("dave", &dave), ("carol", &carol)] {
        assert_eq!(text(db, t).as_deref(), Some("by bob"), "{n}");
    }
}

// spec/sync.md §3, §6: a thing under a group the granter administers, and leaves after the grant
#[test]
fn a_grant_on_a_thing_a_group_owns_by_an_outsider() {
    let (mut w, alice, _e, dave, carol, bob, h, b, _t) = outsider();
    let frank = account(&mut w, 7, 0);
    let fd = introduce(&mut w, &frank, &dave);
    let p = new_tag(&frank, "P").unwrap();
    frank.grant(p, fd, Role::Admin, GrantOpts::default()).unwrap();
    w.run();
    let mut x = dave.write();
    let c = x.create_with_admin(p).unwrap();
    x.at(c, BODY).set(&"dave's".to_string()).unwrap();
    let t = c;
    x.commit().unwrap();
    w.run();
    dave.sync(t, &[]).unwrap();
    dave.grant(t, h, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    assert_eq!(text(&carol, t).as_deref(), Some("dave's"), "carol");
    // p rotates: dave leaves p
    frank.set_role(p, fd, None, skip()).unwrap();
    w.run();
    later_reader_reads(&mut w, &alice, &bob, h, b, t, "under a group");
}

// spec/sync.md §3, spec/permissions.md §4: the granter's chain runs through a thing made by its record
#[test]
fn a_grant_by_a_chain_through_a_record_made_thing() {
    let (mut w, alice, _e, dave, carol, bob, h, b, _t) = outsider();
    let frank = account(&mut w, 7, 0);
    let fd = introduce(&mut w, &frank, &dave);
    let df = introduce(&mut w, &dave, &frank);
    let f = dave.commit_with(|w| w.create()).unwrap();
    dave.sync(f, &[]).unwrap();
    dave.grant(f, df, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    let _ = fd;
    let t = card(&frank, "dave's");
    frank.sync(t, &[]).unwrap();
    frank.grant(t, f, Role::Admin, GrantOpts::default()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    assert_eq!(text(&dave, t).as_deref(), Some("dave's"), "dave reads through f");
    dave.grant(t, h, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    assert_eq!(text(&carol, t).as_deref(), Some("dave's"), "carol");
    later_reader_reads(&mut w, &alice, &bob, h, b, t, "through a record-made thing");
}

// spec/sync.md §3: after a removal a later reader of the group neither reads the thing nor learns its keys, however often it rotated since
#[test]
fn a_later_reader_learns_no_keys_of_a_thing_the_group_lost() {
    let (mut w, alice, _e, dave, _c, bob, h, b, t) = outsider();
    let frank = account(&mut w, 7, 0);
    let f = introduce(&mut w, &dave, &frank);
    dave.sync(t, &[]).unwrap();
    dave.grant(t, h, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    dave.set_role(t, h, None, skip()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    // t rotates on: its label moves while h is out
    dave.grant(t, f, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    dave.set_role(t, f, None, skip()).unwrap();
    w.run();
    w.advance(120_000);
    w.run();
    alice.grant(h, b, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    w.advance(120_000);
    w.run();
    assert_eq!(text(&bob, t), None);
    assert_eq!(seed_of(&bob, t), None, "no keys of t for a later reader");
    assert!(dave.at(t, osis::internals::core_types::KEYS).get().unwrap().is_some());
}
