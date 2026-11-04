//! More of the sharing and sync surface through hosts in process (notes/api.md Sharing
//! and roles, Sync configuration and status, Diagnostics), no tokio: see osis_sim::world.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis::internals::Internals as _;
use crate::common;
use osis_sim::world::World;
use common::*;
use crate::common::CreateIn;
use osis::{Demotion, DiagnosticKind, Error, Lower, Osis, Role, SyncScope, SyncState, Tid, Value, WaitForSync};
use std::time::Duration;

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

fn item(db: &Osis, owner: Tid, g: Tid, v: &str) -> Tid {
    let mut w = db.write();
    let t = w.create_in(owner, &[g]).unwrap();
    w.at(t, ak("t:x.0")).set(&s(v)).unwrap();
    w.commit().unwrap();
    t
}

fn x(db: &Osis, t: Tid) -> Option<Value> {
    db.get(t, ak("t:x.0")).unwrap()
}

fn group(db: &Osis) -> Tid {
    let mut w = db.write();
    let g = w.create_in(db.me(), &[db.home()]).unwrap();
    w.make_group(g).unwrap();
    w.commit().unwrap();
    db.sync(g, &[]).unwrap();
    g
}

/// Alice and Bob on one host, Bob granted `role` on Alice's synced group.
fn alice_bob(w: &mut World, role: Role) -> (Osis, Osis, Tid) {
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
    w.run();
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let g = group(&alice);
    alice.grant(g, b, role, Default::default()).unwrap();
    w.run();
    (alice, bob, g)
}

/// Diagnostics of `kind` a database reports from now on.
fn diags(db: &Osis, kind: DiagnosticKind) -> std::sync::mpsc::Receiver<Vec<Tid>> {
    let (tx, rx) = std::sync::mpsc::channel();
    db.on_diagnostic(move |_, d| {
        if d.kind == kind {
            let _ = tx.send(d.tids);
        }
    })
    .detach();
    rx
}

// notes/api.md Sharing (change_edge, leave), spec/permissions.md §2: a raise is a change, a
// lower role is refused there (`demote`); a holder's self-removal reaches the admin.
#[test]
fn change_edge_and_leave_spec_permissions_2() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Read);
    assert_eq!(bob.role_on(g), Some(Role::Read));
    alice.change_edge(g, bob.me(), Role::Write, Default::default()).unwrap();
    assert!(matches!(alice.change_edge(g, bob.me(), Role::Read, Default::default()), Err(Error::Invalid(_))));
    w.run();
    assert_eq!(bob.role_on(g), Some(Role::Write));
    let u = item(&bob, g, g, "as a writer");
    w.run();
    assert_eq!(x(&alice, u), Some(s("as a writer")));
    bob.leave(g).unwrap();
    w.run();
    assert!(!alice.roster(g).contains_key(&bob.me()));
    assert_eq!(bob.role_on(g), None);
}

// notes/api.md Sharing (revoke_link), spec/permissions.md §9: revoking a multi-use link removes
// its key; `links` no longer lists it.
#[test]
fn revoke_link_spec_permissions_9() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let g = group(&alice);
    alice.make_link(g, Role::Read, Default::default()).unwrap();
    let ls = alice.links(g);
    assert_eq!(ls.len(), 1);
    assert!(!ls[0].single_use);
    w.run();
    w.until(alice.revoke_link(ls[0].id, Demotion { sync: WaitForSync::Skip, backdate: None, repudiate: false, keep: None }), 1000, 5).unwrap();
    assert!(alice.links(g).is_empty());
}

// spec/permissions.md §4 (owners' keysets), spec/crypto.md §4 (keyset names): a person who got its host after creation has an inbox write as its newest `keys.0`; a link's actor names the person's keyset, so that keyset must come along or a redeemer holds no established epoch to box
#[test]
fn redeem_link_of_a_person_with_a_late_host_spec_permissions_4() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = Osis::create(w.cfg(1, &[])).unwrap();
    let (bob, _) = w.person(2, &[host]);
    alice.add_host(&bob.hosts()[0]).unwrap();
    w.run();
    let g = group(&alice);
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
}

fn device(w: &mut World, db: &Osis, seed: u64) -> Tid {
    let join = Osis::pair(w.cfg(seed, &[]), &db.pair_offer().unwrap()).unwrap();
    let (node, reply) = db.pair_accept(join.request()).unwrap();
    join.finish(&reply).unwrap();
    w.run();
    node
}

fn skip_sync() -> Demotion {
    Demotion { sync: WaitForSync::Skip, backdate: None, repudiate: false, keep: None }
}

// spec/permissions.md §4 (current `keys.0`), spec/crypto.md §4 (keyset names): a rotation of a group names a holder's keyset; a holder with a late host has an inbox write as its newest `keys.0`; an admin who joins after the rotation still gets the keyset, or holds no established epoch to box a grant with
#[test]
fn newcomer_admin_after_a_rotation_naming_a_late_host_holder_spec_crypto_4() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (dave, _) = w.person(4, &[host]);
    let (erin, _) = w.person(5, &[host]);
    let (frank, _) = w.person(6, &[host]);
    let (bob, _) = Osis::create(w.cfg(2, &[])).unwrap();
    bob.add_host(&alice.hosts()[0]).unwrap();
    w.run();
    let mut ids = Vec::new();
    for d in [&bob, &dave, &erin] {
        let card = d.contact_card().unwrap();
        w.run();
        ids.push(w.until(alice.import_contact(&card), 1000, 10).unwrap());
    }
    let g = group(&alice);
    alice.grant(g, ids[0], Role::Write, Default::default()).unwrap();
    alice.grant(g, ids[1], Role::Read, Default::default()).unwrap();
    w.run();
    w.until(alice.demote(g, ids[1], Lower::Remove, skip_sync()), 1000, 10).unwrap();
    w.run();
    alice.grant(g, ids[2], Role::Admin, Default::default()).unwrap();
    w.run();
    let card = frank.contact_card().unwrap();
    w.run();
    let f = w.until(erin.import_contact(&card), 1000, 10).unwrap();
    erin.grant(g, f, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(frank.role_on(g), Some(Role::Read));
    let t = item(&erin, g, g, "from erin");
    w.run();
    assert_eq!((x(&bob, t), x(&frank, t)), (Some(s("from erin")), Some(s("from erin"))));
}

// spec/permissions.md §4 (current `keys.0`), §3: the person rotates (a device removed), then gets another host, then makes a link: its keyset is not its newest `keys.0`
#[test]
fn redeem_link_after_a_rotation_and_a_late_host_spec_permissions_4() {
    let mut w = World::new();
    let h0 = w.add_host();
    let h1 = w.add_host();
    let (alice, _) = w.person(1, &[h0]);
    let (bob, _) = w.person(2, &[h0]);
    let node = device(&mut w, &alice, 7);
    let g = group(&alice);
    w.until(alice.remove_device(node, skip_sync()), 1000, 10).unwrap();
    w.run();
    alice.add_host(&w.addr(h1).unwrap()).unwrap();
    w.run();
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
}

// spec/permissions.md §9, §4: a link made before its person's recovery still works, and one made after
#[test]
fn links_around_a_recovery_spec_permissions_9() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, card) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
    let (carol, _) = w.person(3, &[host]);
    let g = group(&alice);
    let before = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    let back = w.until(Osis::restore(w.cfg(9, &[]), &card), 1000, 30).unwrap();
    w.run();
    assert_eq!(w.until(bob.redeem(&before), 1000, 30).unwrap(), g);
    let g2 = group(&back);
    let after = back.make_link(g2, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(w.until(carol.redeem(&after), 1000, 30).unwrap(), g2);
}

// spec/permissions.md §4, spec/sync.md §5: an owner's new device holds K's keyset under the target's label before any secret of K (K's box is under K's label alone): it still opens K's label, by the epochs its owner's derive, and gets K's secrets
#[test]
fn new_device_gets_k_keyset_before_its_box_spec_permissions_4() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
    let g = group(&alice);
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    let k = alice.links(g)[0].id;
    // K rotates when the joiner leaves
    w.until(bob.demote(k, bob.me(), Lower::Remove, skip_sync()), 1000, 10).unwrap();
    w.run();
    w.advance(70_000);
    w.run();
    let join = Osis::pair(w.cfg(7, &[]), &alice.pair_offer().unwrap()).unwrap();
    let (_, reply) = alice.pair_accept(join.request()).unwrap();
    let dev = join.finish(&reply).unwrap();
    w.run();
    w.advance(70_000);
    w.run();
    assert!(dev.engine(|e| e.epochs(&k).is_some_and(|x| x.read.held().next().is_some() && x.admin.held().next().is_some())), "the device holds K's secrets");
}

// spec/permissions.md §9, spec/sync.md §2 (entry boxes): a link works after a joiner left and K rotated; its new joiner reads what was there, is a holder and writes
#[test]
fn redeem_after_a_joiner_left_spec_permissions_9() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
    let (carol, _) = w.person(3, &[host]);
    let (dave, _) = w.person(4, &[host]);
    let g = group(&alice);
    let t = item(&alice, g, g, "from alice");
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    let k = alice.links(g)[0].id;
    w.until(bob.demote(k, bob.me(), Lower::Remove, skip_sync()), 1000, 10).unwrap();
    w.run();
    w.advance(70_000);
    w.run();
    assert_eq!(w.until(carol.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    assert!(carol.engine(|e| e.knows(&k) && e.roster(&k).contains_key(&carol.me())));
    assert_eq!(x(&carol, t), Some(s("from alice")));
    let u = item(&carol, g, g, "from carol");
    w.run();
    assert_eq!(x(&alice, u), Some(s("from carol")));
    assert_eq!(alice.links(g).len(), 1, "the link still works and says so");
    // twice over: the entry box names only the last rotation's wrap
    w.until(carol.demote(k, carol.me(), Lower::Remove, skip_sync()), 1000, 10).unwrap();
    w.run();
    w.advance(70_000);
    w.run();
    assert_eq!(w.until(dave.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    assert_eq!(x(&dave, t), Some(s("from alice")));
    // a leaver holding the link text comes back by it
    assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    let v = item(&dave, g, g, "from dave");
    w.run();
    assert_eq!(x(&bob, v), Some(s("from dave")));
}

// spec/permissions.md §9: a revoked link tells its redeemer so, at once (`Invalid`, not a wait's `Network`), before and after K's new step reached the host, and shows nowhere; so does a kicked joiner's and one past `until`
#[test]
fn ended_link_fails_clearly_spec_permissions_9() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
    let (carol, _) = w.person(3, &[host]);
    let g = group(&alice);
    let revoked = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    w.until(alice.revoke_link(alice.links(g)[0].id, skip_sync()), 1000, 10).unwrap();
    w.run();
    assert!(alice.links(g).is_empty());
    assert!(matches!(w.until(carol.redeem(&revoked), 1000, 30), Err(Error::Invalid(_))));
    assert_eq!(carol.engine(|e| e.held_key_actors()), 0, "the link key is forgotten");
    let kicked = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    w.until(bob.redeem(&kicked), 1000, 30).unwrap();
    w.run();
    w.until(alice.revoke_joiner(alice.links(g)[0].id, bob.me(), skip_sync()), 1000, 10).unwrap();
    w.run();
    assert!(alice.links(g).is_empty());
    assert!(matches!(w.until(carol.redeem(&kicked), 1000, 30), Err(Error::Invalid(_))));
    let until = osis::WallMs(alice.now().0 + 1000);
    let expired = alice.make_link(g, Role::Write, osis::LinkOpts { until: Some(until), single_use: false, direct: false }).unwrap();
    w.run();
    assert_eq!(alice.links(g).len(), 1);
    w.advance(2000);
    assert!(alice.links(g).is_empty(), "past `until`, finalized or not");
    assert!(matches!(w.until(carol.redeem(&expired), 1000, 30), Err(Error::Invalid(_))));
    assert_eq!(carol.role_on(g), None);
    let fresh = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(w.until(carol.redeem(&fresh), 1000, 30).unwrap(), g);
}

// spec/permissions.md §9, §3: a read link too: its joiner rotates nothing on leaving, the sharer does; the link goes on
#[test]
fn redeem_after_a_read_joiner_left_spec_permissions_9() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
    let (carol, _) = w.person(3, &[host]);
    let g = group(&alice);
    let t = item(&alice, g, g, "from alice");
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    let k = alice.links(g)[0].id;
    let before = alice.engine(|e| e.epochs(&k).unwrap().read.newest().unwrap());
    w.until(bob.demote(k, bob.me(), Lower::Remove, skip_sync()), 1000, 10).unwrap();
    w.run();
    w.advance(70_000);
    w.run();
    let v = item(&alice, g, g, "after the leave");
    w.run();
    assert_ne!(alice.engine(|e| e.epochs(&k).unwrap().read.newest().unwrap()), before, "K rotated");
    assert_eq!(x(&bob, v), None, "what the rotation protects");
    assert_eq!(w.until(carol.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    assert_eq!((x(&carol, t), x(&carol, v)), (Some(s("from alice")), Some(s("after the leave"))));
}

// spec/permissions.md §9, §3: a device removal rotates K (a departure inside its owner): a link no one used yet still works, a read link as well
#[test]
fn redeem_after_a_device_removal_spec_permissions_9() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (carol, _) = w.person(3, &[host]);
    let node = device(&mut w, &alice, 7);
    let g = group(&alice);
    let t = item(&alice, g, g, "from alice");
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    w.run();
    w.until(alice.remove_device(node, skip_sync()), 1000, 10).unwrap();
    w.run();
    w.advance(70_000);
    w.run();
    assert_eq!(w.until(carol.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    assert_eq!(x(&carol, t), Some(s("from alice")));
}

// spec/permissions.md §9: the common race: a link passed on before its label reached the host is no ended link: the redeemer waits for it
#[test]
fn redeem_waits_for_a_link_still_uploading_spec_permissions_9() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (carol, _) = w.person(3, &[host]);
    let g = group(&alice);
    let t = item(&alice, g, g, "from alice");
    w.run();
    w.set_reachable(&alice, host, false);
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    let mut redeem = std::pin::pin!(carol.redeem(&link));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    for _ in 0..10 {
        assert!(redeem.as_mut().poll(&mut cx).is_pending(), "still uploading, not ended");
        w.advance(1000);
        w.run();
    }
    w.set_reachable(&alice, host, true);
    assert_eq!(w.until(redeem, 1000, 30).unwrap(), g);
    w.run();
    assert_eq!(x(&carol, t), Some(s("from alice")));
}

/// `link` with its target replaced: nothing signs the pair.
fn naming(link: &osis::ShareLink, target: Tid) -> osis::ShareLink {
    let mut l = osis_label::ShareLink::from_text(&link.to_string()).unwrap();
    l.target = target;
    l.to_text().unwrap().parse().unwrap()
}

// spec/permissions.md §9 (Redeem): a link naming a thing its K holds no edge on joins nothing and fails plainly, whether the redeemer holds the named thing or has never heard of it
#[test]
fn redeem_of_a_mismatched_target_joins_nothing_spec_permissions_9() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (carol, _) = w.person(3, &[host]);
    let (dave, _) = w.person(4, &[host]);
    let held = group(&alice);
    let other = group(&alice);
    let card = carol.contact_card().unwrap();
    w.run();
    let c = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    alice.grant(held, c, Role::Read, Default::default()).unwrap();
    let t = item(&alice, other, other, "in the other group");
    let link = alice.make_link(other, Role::Write, Default::default()).unwrap();
    let k = alice.links(other)[0].id;
    w.run();
    assert_eq!(carol.role_on(held), Some(Role::Read));
    let bad = naming(&link, held);
    for (who, db) in [("holds the target", &carol), ("does not know it", &dave)] {
        assert!(matches!(w.until(db.redeem(&bad), 1000, 200), Err(Error::Invalid(_))), "{who}");
        w.run();
        assert_eq!(db.role_on(other), None, "{who}");
        assert_eq!(x(db, t), None, "{who}: what the key read went with it");
        let groups = db.status().unwrap().groups;
        assert!(!groups.contains_key(&other) && !groups.contains_key(&k), "{who}: no longer synced");
        assert!(!alice.roster(k).contains_key(&db.me()), "{who}");
    }
    assert_eq!(carol.role_on(held), Some(Role::Read));
    // the key was not spent: the honest link still works
    assert_eq!(w.until(dave.redeem(&link), 1000, 30).unwrap(), other);
    w.run();
    assert_eq!(x(&dave, t), Some(s("in the other group")));
}

// spec/permissions.md §9 (Redeem): an honest link works for a target this node already knows, K's edge reaching it by K's label; a redeemer who still holds the role it had gets the link's on top
#[test]
fn redeem_of_a_target_already_known_spec_permissions_9() {
    let mut w = World::new();
    let (alice, carol, g) = alice_bob(&mut w, Role::Read);
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(carol.role_on(g), Some(Role::Read));
    assert_eq!(w.until(carol.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    assert_eq!(carol.role_on(g), Some(Role::Write));
}

// spec/permissions.md §9 (Redeem), spec/sync.md §3 (certificate copy): K's edge on the target outlives the delivery that first carried it, so a link redeemed after its inbox blob expired works, target unknown
#[test]
fn redeem_after_the_delivery_expired_spec_permissions_9() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (carol, _) = w.person(3, &[host]);
    let g = group(&alice);
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    w.run();
    w.advance(osis_base::format::INBOX_LIFETIME_MS + 3 * osis_base::format::MAX_DRIFT_MS);
    w.run();
    w.set_online(&alice, false);
    assert_eq!(w.until(carol.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    assert_eq!(carol.role_on(g), Some(Role::Read));
}

// spec/permissions.md §9 (Redeem): K taken off the target ends the link: a redeemer is told at once and does not join K
#[test]
fn redeem_after_k_left_the_target_spec_permissions_9() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (carol, _) = w.person(3, &[host]);
    let g = group(&alice);
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    let k = alice.links(g)[0].id;
    w.run();
    w.until(alice.demote(g, k, Lower::Remove, skip_sync()), 1000, 10).unwrap();
    w.run();
    assert!(matches!(w.until(carol.redeem(&link), 1000, 30), Err(Error::Invalid(_))));
    w.run();
    assert!(!alice.roster(k).contains_key(&carol.me()));
}

// spec/permissions.md §9 (Bearer use), spec/sync.md §3 (invite requests): a contact card naming a thing its K holds no edge on makes nobody a contact: its owner would count as connected on the word of the card's text
#[test]
fn contact_card_with_a_mismatched_target_spec_permissions_9() {
    let mut w = World::new();
    let (alice, carol, g) = alice_bob(&mut w, Role::Read);
    let eve = w.person(5, &[0]).0;
    let card = eve.contact_card().unwrap();
    w.run();
    let mut bad = osis_label::ShareLink::from_text(&card.to_string()).unwrap();
    bad.target = g;
    let bad: osis::ContactCard = bad.to_text().unwrap().parse().unwrap();
    assert!(matches!(w.until(carol.import_contact(&bad), 1000, 200), Err(Error::Network(_))));
    assert!(carol.profile_of(alice.me()).unwrap().is_none());
    assert_eq!(w.until(carol.import_contact(&card), 1000, 30).unwrap(), eve.me());
}

/// Steps `redeem` until L shows on K here, K's label not read to its end.
fn step_until_l_is_here(w: &mut World, db: &Osis, redeem: &mut std::pin::Pin<&mut impl Future>, k: Tid, l: Tid) {
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    for _ in 0..1000 {
        assert!(redeem.as_mut().poll(&mut cx).is_pending());
        if db.engine(|e| e.roster(&k).contains_key(&l)) {
            return;
        }
        w.step(None);
    }
    panic!("L never here");
}

// spec/permissions.md §9 (Redeem): no edge seen by a node cut off before the end of K's label says nothing of the link: `Network`, not `Invalid`, which an app takes for a dead link
#[test]
fn redeem_cut_off_mid_read_is_no_verdict_spec_permissions_9() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (carol, _) = w.person(3, &[host]);
    let g = group(&alice);
    let other = group(&alice);
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    let k = alice.links(g)[0].id;
    let l = alice.engine(|e| e.held_links().unwrap().iter().find(|h| h.k == k).unwrap().l);
    w.run();
    let bad = naming(&link, other);
    let mut redeem = std::pin::pin!(carol.redeem(&bad));
    step_until_l_is_here(&mut w, &carol, &mut redeem, k, l);
    assert!(!carol.sync_engine(|e| e.complete_pass(&k)));
    w.set_reachable(&carol, host, false);
    assert!(matches!(w.until(redeem, 1000, 200), Err(Error::Network(_))));
    assert!(!alice.roster(k).contains_key(&carol.me()));
}

// spec/permissions.md §9 (Redeem), §3: a link read while its maker's upload stalled, K's head there and K's commits not: the failed redemption drops what the head gave, and a retry opens K's label anew and joins (the steps stop the upload at points inside that stretch)
#[test]
fn retry_after_a_stalled_upload_spec_permissions_9() {
    for cut in [14, 20, 26] {
        let mut w = World::new();
        let host = w.add_host();
        let (alice, _) = w.person(1, &[host]);
        let (carol, _) = w.person(3, &[host]);
        let g = group(&alice);
        w.run();
        let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
        for _ in 0..cut {
            w.step(None);
        }
        w.set_reachable(&alice, host, false);
        assert!(matches!(w.until(carol.redeem(&link), 1000, 200), Err(Error::Network(_))), "cut {cut}");
        w.set_reachable(&alice, host, true);
        w.run();
        assert_eq!(w.until(carol.redeem(&link), 1000, 200).unwrap(), g, "cut {cut}");
        w.run();
        assert_eq!(carol.role_on(g), Some(Role::Read), "cut {cut}");
    }
}

// spec/permissions.md §9 (Redeem), §6: a maker who is not the target's owner, a roster snapshot of the target since, its authors off: K's edge still reaches a new redeemer
#[test]
fn redeem_of_a_target_someone_else_owns_after_a_snapshot_spec_permissions_9() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Admin);
    let (carol, _) = w.person(3, &[0]);
    let t = item(&alice, g, g, "x");
    w.run();
    let link = bob.make_link(g, Role::Read, Default::default()).unwrap();
    w.run();
    alice.engine(|e| e.roster_snapshot(&g, None)).unwrap();
    w.run();
    w.advance(1000);
    item(&bob, g, g, "by bob");
    let link2 = bob.make_link(g, Role::Read, Default::default()).unwrap();
    w.run();
    w.set_online(&alice, false);
    w.set_online(&bob, false);
    assert_eq!(w.until(carol.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    assert_eq!(x(&carol, t), Some(s("x")));
    let (dave, _) = w.person(4, &[0]);
    assert_eq!(w.until(dave.redeem(&link2), 1000, 30).unwrap(), g);
}

// spec/permissions.md §3, §9: a failed redemption drops only what only the key read: not what a sibling device's redemption gave, a joiner's role, a kept copy or a contact's profile
#[test]
fn failed_redemption_drops_only_what_only_the_key_read_spec_permissions_3() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Read);
    let (carol, _) = w.person(3, &[0]);
    let t = item(&alice, g, g, "x");
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    let k = alice.links(g)[0].id;
    let one = alice.make_link(g, Role::Read, osis::LinkOpts { single_use: true, ..Default::default() }).unwrap();
    let k1 = alice.links(g).into_iter().map(|l| l.id).find(|x| *x != k).unwrap();
    let card = alice.contact_card().unwrap();
    w.run();
    // a sibling's: the used-up link fails on the other device, the role through the person stays
    let c2 = pair_device(&mut w, &carol, 13);
    assert_eq!(w.until(carol.redeem(&one), 1000, 30).unwrap(), g);
    w.run();
    assert!(matches!(w.until(c2.redeem(&one), 1000, 200), Err(Error::Invalid(_))));
    w.run();
    assert_eq!(c2.role_on(k1), Some(Role::Read));
    w.advance(120_000); // the new device's re-seal
    w.run();
    assert_eq!(x(&c2, t), Some(s("x")));
    // a contact: the card's key kept as a bearer, the same key again with a wrong target
    assert_eq!(w.until(carol.import_contact(&card), 1000, 30).unwrap(), alice.me());
    w.run();
    let mut bad = osis_label::ShareLink::from_text(&card.to_string()).unwrap();
    bad.target = carol.home();
    let bad: osis::ContactCard = bad.to_text().unwrap().parse().unwrap();
    assert!(w.until(carol.import_contact(&bad), 1000, 200).is_err());
    w.run();
    assert!(carol.profile_of(alice.me()).unwrap().is_some());
    let mine = group(&carol);
    carol.grant(mine, alice.me(), Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(alice.role_on(mine), Some(Role::Read), "still a contact, its keys here");
    // a kept copy: after a wrong target, then the link's own key revoked; a joiner's role likewise
    let d = Demotion { sync: WaitForSync::Skip, backdate: None, repudiate: false, keep: Some(true) };
    w.until(alice.demote(g, bob.me(), Lower::Remove, d), 1000, 10).unwrap();
    w.run();
    assert_eq!(bob.kept_copies().unwrap(), vec![g]);
    assert!(w.until(bob.redeem(&naming(&link, alice.me())), 1000, 200).is_err());
    w.run();
    assert_eq!((bob.kept_copies().unwrap(), x(&bob, t)), (vec![g], Some(s("x"))), "a wrong target");
    assert_eq!(w.until(carol.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    w.until(alice.revoke_link(k, skip_sync()), 1000, 10).unwrap();
    w.run();
    assert!(matches!(w.until(bob.redeem(&link), 1000, 200), Err(Error::Invalid(_))));
    w.run();
    assert_eq!((bob.kept_copies().unwrap(), x(&bob, t)), (vec![g], Some(s("x"))), "a revoked link");
    assert!(matches!(w.until(carol.redeem(&link), 1000, 200), Err(Error::Invalid(_))));
    w.run();
    let after = item(&alice, g, g, "after");
    w.run();
    assert_eq!(x(&carol, after), Some(s("after")));
    assert_eq!(x(&bob, after), None);
}

// spec/permissions.md §9: one host refusing L's entry (here a child step taken without its claim set, past its cap) is no end of the link while another of its hosts has not answered; every host refusing is
#[test]
fn one_host_refusing_is_no_end_spec_permissions_9() {
    let mut w = World::new();
    let (capped, other, own) = (w.add_host(), w.add_host(), w.add_host());
    let (alice, _) = w.person(1, &[capped, other]);
    let (bob, _) = w.person(2, &[other]);
    let (carol, _) = w.person(3, &[own]);
    let g = group(&alice);
    let t = item(&alice, g, g, "from alice");
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    w.until(bob.redeem(&link), 1000, 30).unwrap();
    w.run();
    let policy = osis_host::HostPolicy { cap_bytes: 1, ..osis_host::HostPolicy::default() };
    w.hosts[capped].hub.store_mut().set_policy(policy);
    let k = alice.links(g)[0].id;
    w.until(bob.demote(k, bob.me(), Lower::Remove, skip_sync()), 1000, 10).unwrap();
    w.run();
    w.advance(70_000);
    w.run();
    w.set_reachable(&carol, other, false);
    let mut redeem = std::pin::pin!(carol.redeem(&link));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    for _ in 0..10 {
        assert!(redeem.as_mut().poll(&mut cx).is_pending(), "the other host may still serve it");
        w.advance(1000);
        w.run();
    }
    w.set_reachable(&carol, other, true);
    assert_eq!(w.until(redeem, 1000, 30).unwrap(), g);
    w.run();
    assert_eq!(x(&carol, t), Some(s("from alice")));
    // revoked: a redeemer with one host down waits it out, with every host refusing is told at once
    w.until(alice.revoke_link(alice.links(g)[0].id, skip_sync()), 1000, 10).unwrap();
    w.run();
    w.hosts[capped].hub.store_mut().set_policy(osis_host::HostPolicy::default());
    w.advance(70_000);
    w.run();
    let (dave, _) = w.person(4, &[own]);
    w.set_reachable(&dave, other, false);
    let mut redeem = std::pin::pin!(dave.redeem(&link));
    w.advance(1000);
    w.run();
    assert!(redeem.as_mut().poll(&mut cx).is_pending());
    w.set_reachable(&dave, other, true);
    assert!(matches!(w.until(redeem, 1000, 10), Err(Error::Invalid(_))));
}

// spec/permissions.md §5.3, notes/api.md Demotion: offline, `Required` fails `Unsynced` after
// `PRESYNC_WAIT`; `Try` proceeds after its timeout with an `Unsynced` diagnostic.
#[test]
fn demotion_presync_policies_spec_permissions_5_3() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Write);
    item(&bob, g, g, "bob wrote");
    w.run();
    w.set_online(&alice, false);
    let r = w.until(alice.demote(g, bob.me(), Lower::Remove, Demotion::default()), 10_000, 10);
    assert!(matches!(r, Err(Error::Unsynced { ref groups }) if groups.contains(&g)), "{r:?}");
    assert!(alice.roster(g).contains_key(&bob.me()), "nothing stamped");
    let unsynced = diags(&alice, DiagnosticKind::Unsynced);
    let t = Demotion { sync: WaitForSync::Try(Duration::from_secs(5)), backdate: None, repudiate: false, keep: None };
    w.until(alice.demote(g, bob.me(), Lower::To(Role::Read), t), 1000, 10).unwrap();
    assert_eq!(alice.roster(g).get(&bob.me()).map(|e| e.role), Some(Role::Read));
    assert!(recv(&unsynced).contains(&g));
}

// notes/api.md Sync status (watch_status, Stranded), Diagnostics: a watcher sees the home group
// synced; a device removed while away is stranded on the home label and says so.
// spec/permissions.md §3
#[test]
fn watch_status_and_stranded_spec_permissions_3() {
    let mut w = World::new();
    let host = w.add_host();
    let (da, _) = w.person(1, &[host]);
    let (tx, rx) = std::sync::mpsc::channel();
    let _sub = da.watch_status(move |_, st| {
        let _ = tx.send(st);
    });
    w.run();
    let home = da.home();
    let mut seen = recv(&rx);
    while seen.groups.get(&home).map(|g| g.state) != Some(SyncState::Synced) {
        seen = recv(&rx);
    }
    let join = Osis::pair(w.cfg(2, &[]), &da.pair_offer().unwrap()).unwrap();
    let (node, reply) = da.pair_accept(join.request()).unwrap();
    let db = join.finish(&reply).unwrap();
    w.run();
    let stranded = diags(&db, DiagnosticKind::Stranded);
    w.set_online(&db, false);
    w.until(da.remove_device(node, Demotion { sync: WaitForSync::Skip, backdate: None, repudiate: false, keep: None }), 1000, 5).unwrap();
    item(&da, da.me(), home, "after the removal");
    w.run();
    w.set_online(&db, true);
    for _ in 0..3 {
        w.advance(70_000);
    }
    assert_eq!(db.status().unwrap().groups.get(&home).map(|g| g.state), Some(SyncState::Stranded));
    assert!(recv(&stranded).contains(&home));
}

// spec/permissions.md §4 (stranded heartbeat), §9: the sharer's other device opens a link's
// K label as soon as it is registered, before K's own secrets reach the host (it sees K as
// deriving from the person then); it deposits no heartbeat under a key the head does not
// register, and reads K once they arrive (they are boxed to the person).
#[test]
fn sharers_other_device_deposits_no_foreign_heartbeat_spec_permissions_4() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let join = Osis::pair(w.cfg(2, &[]), &alice.pair_offer().unwrap()).unwrap();
    let (_, reply) = alice.pair_accept(join.request()).unwrap();
    let dev = join.finish(&reply).unwrap();
    w.run();
    let (tx, rx) = std::sync::mpsc::channel();
    dev.on_diagnostic(move |_, d| {
        let _ = tx.send(d.detail.clone());
    })
    .detach();
    let g = group(&alice);
    alice.make_link(g, Role::Read, Default::default()).unwrap();
    let k = alice.links(g)[0].id;
    w.run();
    w.advance(70_000);
    w.run();
    let refused: Vec<String> = rx.try_iter().filter(|d| d.contains("deposit refused")).collect();
    assert!(refused.is_empty(), "{refused:?}");
    assert_eq!(dev.status().unwrap().groups.get(&k).map(|s| s.state), Some(SyncState::Synced));
    assert!(dev.engine(|e| e.epochs(&k).is_some_and(|x| x.read.held().next().is_some()) && e.group_actor(&k) == k), "the device reads K");
}

// spec/sync.md §11, notes/api.md Sync (bundles): a device that cannot reach the host takes
// what it misses from a bundle another device exported.
#[test]
fn bundle_round_trip_spec_sync_11() {
    let mut w = World::new();
    let host = w.add_host();
    let (da, _) = w.person(1, &[host]);
    w.run();
    let join = Osis::pair(w.cfg(2, &[]), &da.pair_offer().unwrap()).unwrap();
    let (_, reply) = da.pair_accept(join.request()).unwrap();
    let db = join.finish(&reply).unwrap();
    w.run();
    w.set_online(&db, false);
    let t = item(&da, da.me(), da.home(), "by bundle");
    w.until(da.wait_synced(SyncScope::All, Duration::from_secs(30)), 1000, 5).unwrap();
    let mut b = Vec::new();
    da.export_bundle(&[da.home()], &mut b).unwrap();
    assert_eq!(x(&db, t), None);
    db.import_bundle(&b[..]).unwrap();
    db.settle();
    assert_eq!(x(&db, t), Some(s("by bundle")));
}

// notes/api.md Handle (restore), Sharing (redeem): waits time out with `Network`; a failed
// restore leaves no person record; a dropped redemption leaves no waiter and no held key.
// spec: none (API surface, notes/api.md)
#[test]
fn waits_time_out_and_roll_back_spec_api_handle() {
    let mut a = World::new();
    let host = a.add_host();
    let (alice, card) = a.person(1, &[host]);
    let g = group(&alice);
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    a.run();
    // a world without that host: nothing answers
    let mut w = World::new();
    let store = osis::MemStore::new();
    let mut c = w.cfg(4, &[]);
    c.store = osis::StoreAt::Memory(store);
    c.wait_timeout = Duration::from_secs(5);
    let r = w.until(Osis::restore(c.clone(), &card), 1000, 10);
    assert!(matches!(r, Err(Error::Network(_))), "{r:?}");
    assert!(Osis::open(c).is_err(), "no person record after a failed restore");
    let (bob, _) = a.person(2, &[host]);
    {
        let f = bob.redeem(&link);
        let mut f = std::pin::pin!(f);
        assert!(std::future::Future::poll(f.as_mut(), &mut std::task::Context::from_waker(std::task::Waker::noop())).is_pending());
        assert_eq!(bob.waiting(), 1);
        assert_eq!(bob.engine(|e| e.held_key_actors()), 1);
    }
    a.run();
    assert_eq!(bob.waiting(), 0, "a dropped future leaves no waiter");
    assert_eq!(bob.engine(|e| e.held_key_actors()), 0, "nor the link key");
}

// spec/permissions.md §5.1 Frontier (chain-write forgery): Bob removes Carol without having
// received anything of hers; Carol, offline with a lagging clock, then writes Bob's admin edge
// with an `until`, stamped before the removal, and hands it over directly. Bob's frontier does not cover it: it drops,
// Bob keeps admin without `until` and Carol stays removed.
#[test]
fn removed_admin_cannot_backdate_removers_edge_spec_permissions_5_1() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
    // Carol's own clock: kept with the world's, then left behind while she is offline
    let cl = clock();
    let mut c = w.cfg(3, &[host]);
    c.clock = Some(cl.clone());
    let carol = Osis::create(c).unwrap().0;
    w.run();
    let (bc, cc) = (bob.contact_card().unwrap(), carol.contact_card().unwrap());
    w.run();
    let b = w.until(alice.import_contact(&bc), 1000, 10).unwrap();
    cl.set(osis::WallMs(w.now()));
    let c = w.until(alice.import_contact(&cc), 1000, 10).unwrap();
    cl.set(osis::WallMs(w.now()));
    let g = group(&alice);
    alice.grant(g, b, Role::Admin, Default::default()).unwrap();
    alice.grant(g, c, Role::Admin, Default::default()).unwrap();
    w.run();
    cl.set(osis::WallMs(w.now()));
    w.run();
    assert_eq!((bob.role_on(g), carol.role_on(g)), (Some(Role::Admin), Some(Role::Admin)));
    w.set_online(&carol, false);
    w.advance(60_000);
    w.until(bob.demote(g, c, Lower::Remove, Demotion { sync: WaitForSync::Skip, backdate: None, repudiate: false, keep: None }), 1000, 10).unwrap();
    w.run();
    let until = osis::WallMs(w.now() + 3_600_000);
    carol.change_edge(g, b, Role::Admin, osis::EdgeOpts { until: Some(until), invite: None }).unwrap();
    assert_eq!(carol.roster(g).get(&b).and_then(|e| e.until), Some(until), "carol wrote it");
    // straight to Alice and Bob (G's hosts refuse her stale write key)
    deliver(&carol, &alice);
    deliver(&carol, &bob);
    w.run();
    w.advance(3_700_000);
    for db in [&alice, &bob] {
        let r = db.roster(g);
        assert_eq!(r.get(&b).map(|e| (e.role, e.until)), Some((Role::Admin, None)));
        assert!(!r.contains_key(&c));
    }
    assert_eq!(bob.role_on(g), Some(Role::Admin));
}

// spec/sync.md §3 (invite requests), notes/api.md Sharing: an invite from a stranger waits as a
// request; `decline_invite` forgets it, `accept_invite` joins; a request
// answered once is gone.
#[test]
fn invite_requests_accept_and_decline_spec_sync_3() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
    let bi = w.index(&bob).unwrap();
    w.holds_invites.insert(bi);
    w.run();
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let (g1, g2) = (group(&alice), group(&alice));
    let t2 = item(&alice, g2, g2, "two");
    alice.grant(g1, b, Role::Read, Default::default()).unwrap();
    w.run();
    let r1 = bob.invite_requests().unwrap();
    assert_eq!(r1.len(), 1);
    bob.decline_invite(r1[0]).unwrap();
    assert!(matches!(bob.accept_invite(r1[0]), Err(Error::Invalid(_))), "declined: gone");
    alice.grant(g2, b, Role::Read, Default::default()).unwrap();
    w.run();
    w.advance(60_000);
    let r2 = bob.invite_requests().unwrap();
    assert!(r2.len() == 1 && r2[0] != r1[0], "the declined one stays gone");
    assert_eq!(x(&bob, t2), None);
    bob.accept_invite(r2[0]).unwrap();
    w.run();
    w.advance(60_000);
    assert_eq!(x(&bob, t2), Some(s("two")));
    assert_eq!(bob.role_on(g1), None);
    assert!(bob.invite_requests().unwrap().is_empty());
}

// spec/sync.md §3: a sender whose card was imported (a contact) is connected: its invite goes
// through with no request.
#[test]
fn contact_invite_goes_through_spec_sync_3() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
    let bi = w.index(&bob).unwrap();
    w.holds_invites.insert(bi);
    w.run();
    let (bc, ac) = (bob.contact_card().unwrap(), alice.contact_card().unwrap());
    w.run();
    let b = w.until(alice.import_contact(&bc), 1000, 10).unwrap();
    w.until(bob.import_contact(&ac), 1000, 10).unwrap();
    let g = group(&alice);
    let t = item(&alice, g, g, "hi");
    alice.grant(g, b, Role::Read, Default::default()).unwrap();
    w.run();
    w.advance(60_000);
    assert!(bob.invite_requests().unwrap().is_empty());
    assert_eq!(x(&bob, t), Some(s("hi")));
}

// spec/permissions.md §9 (removed device's links): a removed device keeps the seeds of the person's links, so
// `remove_device` lists them, a link made on that device too; the device left can revoke it.
#[test]
fn removing_a_device_lists_its_links_spec_permissions_9() {
    let mut w = World::new();
    let host = w.add_host();
    let (da, _) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
    let (carol, _) = w.person(3, &[host]);
    let g = group(&da);
    let offer = da.pair_offer().unwrap();
    let join = Osis::pair(w.cfg(4, &[]), &offer).unwrap();
    let (_, reply) = da.pair_accept(join.request()).unwrap();
    let db = join.finish(&reply).unwrap();
    w.run();
    let made_there = db.make_link(g, Role::Read, Default::default()).unwrap();
    w.run();
    let there = da.links(g)[0].id;
    let made_here = da.make_link(g, Role::Read, Default::default()).unwrap();
    w.run();
    let links = da.links(g);
    assert_eq!(links.len(), 2, "every device lists the person's links");
    let here = links.iter().map(|l| l.id).find(|k| *k != there).unwrap();
    let stranger = carol.node();
    assert!(w.until(da.remove_device(stranger, skip_sync()), 1000, 10).unwrap().is_empty(), "no device of this person");
    let open = w.until(da.remove_device(db.node(), skip_sync()), 1000, 10).unwrap();
    let mut ids: Vec<Tid> = open.iter().map(|l| l.id).collect();
    ids.sort();
    let mut want = vec![there, here];
    want.sort();
    assert_eq!(ids, want);
    assert!(open.iter().all(|l| l.target == g && !l.single_use && l.role == Role::Read));
    assert_eq!(da.all_links().len(), 2);
    w.run();
    // the removal ended neither: the seed still reads
    assert_eq!(w.until(bob.redeem(&made_there), 1000, 30).unwrap(), g);
    w.run();
    w.until(da.revoke_link(there, skip_sync()), 1000, 10).unwrap();
    w.run();
    assert!(w.until(carol.redeem(&made_there), 1000, 30).is_err(), "revoked from the device left");
    assert_eq!(w.until(carol.redeem(&made_here), 1000, 30).unwrap(), g, "the other still works");
    assert_eq!(da.all_links().iter().map(|l| l.id).collect::<Vec<_>>(), vec![here]);
}

fn pair_device(w: &mut World, da: &Osis, seed: u64) -> Osis {
    let offer = da.pair_offer().unwrap();
    let join = Osis::pair(w.cfg(seed, &[]), &offer).unwrap();
    let (_, reply) = da.pair_accept(join.request()).unwrap();
    let db = join.finish(&reply).unwrap();
    w.run();
    db
}

// spec/permissions.md §9, spec/sync.md §2: a link's text names its hosts, so a working link's K
// label stays on them whichever device of the person moves hosts: redeemed there, it reaches
// the sharer and reads the target on its new hosts.
#[test]
fn moving_hosts_keeps_a_link_made_on_another_device_spec_permissions_9() {
    for by_maker in [true, false] {
        let mut w = World::new();
        let (h0, h1) = (w.add_host(), w.add_host());
        let (da, _) = w.person(1, &[h0]);
        let (bob, _) = w.person(2, &[h1]);
        let g = group(&da);
        let t = item(&da, g, g, "shared");
        let db = pair_device(&mut w, &da, 4);
        let link = da.make_link(g, Role::Read, Default::default()).unwrap();
        w.run();
        let k = db.links(g)[0].id;
        let mover = if by_maker { &da } else { &db };
        mover.add_host(&w.addr(h1).unwrap()).unwrap();
        w.run();
        mover.remove_host(&w.addr(h0).unwrap()).unwrap();
        w.run();
        let hosts = mover.engine(|e| e.group_labels(&k).unwrap().iter().flat_map(|l| l.hosts.iter().map(|a| a.url.clone()).collect::<Vec<_>>()).collect::<Vec<_>>());
        assert_eq!(hosts, ["quic://host0:1"], "by maker {by_maker}");
        assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
        for _ in 0..3 {
            w.advance(60_000);
            w.run();
        }
        assert_eq!(x(&bob, t), Some(s("shared")), "by maker {by_maker}");
        assert!(da.roster(k).contains_key(&bob.me()), "the redemption reached the sharer");
    }
}

// spec/permissions.md §9, spec/sync.md §2: a revoked link has no holder but the person's on K, yet
// K's label stays too, on either device: cut off from the link's host, the device revokes and
// moves hosts, and the revocation still reaches a redeemer there.
#[test]
fn moving_hosts_after_a_revoke_keeps_the_links_label_spec_permissions_9() {
    for by_maker in [true, false] {
        let mut w = World::new();
        let (h0, h1) = (w.add_host(), w.add_host());
        let (da, _) = w.person(1, &[h0]);
        let (carol, _) = w.person(3, &[h1]);
        let g = group(&da);
        let db = pair_device(&mut w, &da, 4);
        let link = da.make_link(g, Role::Read, Default::default()).unwrap();
        w.run();
        let k = db.links(g)[0].id;
        let mover = if by_maker { &da } else { &db };
        w.set_reachable(mover, h0, false);
        w.until(mover.revoke_link(k, skip_sync()), 1000, 10).unwrap();
        mover.add_host(&w.addr(h1).unwrap()).unwrap();
        mover.remove_host(&w.addr(h0).unwrap()).unwrap();
        w.run();
        let hosts = mover.engine(|e| e.group_labels(&k).unwrap().iter().flat_map(|l| l.hosts.iter().map(|a| a.url.clone()).collect::<Vec<_>>()).collect::<Vec<_>>());
        assert_eq!(hosts, ["quic://host0:1"], "by maker {by_maker}");
        w.set_reachable(mover, h0, true);
        for _ in 0..3 {
            w.advance(60_000);
            w.run();
        }
        assert!(w.until(carol.redeem(&link), 1000, 30).is_err(), "by maker {by_maker}: the revocation reached the link's host");
    }
}

// spec/permissions.md §9, §3: a removed device's revocation of a link does not stand, written
// before it hears of the removal (its commit is past the removal's frontier) or after (it lists
// nothing and is refused); the link goes on working
#[test]
fn removed_device_revokes_no_link_spec_permissions_9() {
    for aware in [false, true] {
        let mut w = World::new();
        let host = w.add_host();
        let (da, _) = w.person(1, &[host]);
        let (bob, _) = w.person(2, &[host]);
        let g = group(&da);
        let db = pair_device(&mut w, &da, 4);
        let link = da.make_link(g, Role::Read, Default::default()).unwrap();
        w.run();
        let k = db.links(g)[0].id;
        w.set_online(&db, aware);
        w.until(da.remove_device(db.node(), skip_sync()), 1000, 10).unwrap();
        w.run();
        if aware {
            assert!(db.all_links().is_empty());
            assert!(matches!(w.until(db.revoke_link(k, skip_sync()), 1000, 10), Err(Error::Invalid(_))));
        } else {
            w.until(db.revoke_link(k, skip_sync()), 1000, 10).unwrap();
            w.set_online(&db, true);
        }
        for _ in 0..3 {
            w.advance(60_000);
            w.run();
        }
        assert_eq!(da.links(g).len(), 1, "aware {aware}");
        assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
    }
}

// spec/permissions.md §9: both devices act on K, each not having heard the other: they agree on
// K's roster and the links, whatever the order. A revocation that has not seen a redemption
// judges it as any other device's would (spec/permissions.md §3: `Skip`).
#[test]
fn two_devices_act_on_a_link_spec_permissions_9() {
    for order in 0..4 {
        let mut w = World::new();
        let host = w.add_host();
        let (da, _) = w.person(1, &[host]);
        let (bob, _) = w.person(2, &[host]);
        let (carol, _) = w.person(3, &[host]);
        let g = group(&da);
        let db = pair_device(&mut w, &da, 4);
        let link = da.make_link(g, Role::Read, Default::default()).unwrap();
        w.run();
        let k = db.links(g)[0].id;
        match order {
            0 => {
                w.set_online(&db, false);
                assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
                w.run();
                w.until(db.revoke_link(k, skip_sync()), 1000, 10).unwrap();
                w.set_online(&db, true);
            }
            1 => {
                w.set_online(&db, false);
                w.until(da.revoke_link(k, skip_sync()), 1000, 10).unwrap();
                w.until(db.revoke_link(k, skip_sync()), 1000, 10).unwrap();
                w.set_online(&db, true);
            }
            2 => {
                assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
                assert_eq!(w.until(carol.redeem(&link), 1000, 30).unwrap(), g);
                w.run();
                w.set_online(&da, false);
                w.until(db.demote(g, bob.me(), Lower::Remove, skip_sync()), 1000, 20).unwrap();
                w.set_online(&da, true);
            }
            _ => {
                assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
                w.run();
                w.set_online(&db, false);
                w.until(da.demote(g, bob.me(), Lower::Remove, skip_sync()), 1000, 20).unwrap();
                w.until(db.revoke_link(k, skip_sync()), 1000, 10).unwrap();
                w.set_online(&db, true);
            }
        }
        for _ in 0..4 {
            w.advance(60_000);
            w.run();
        }
        let r = da.roster(k);
        assert_eq!(r, db.roster(k), "order {order}");
        assert!(da.links(g).is_empty() && db.links(g).is_empty(), "order {order}");
        assert!(!r.contains_key(&bob.me()), "order {order}");
        if order == 2 {
            assert!(r.contains_key(&carol.me()));
            let after = item(&da, g, g, "after");
            w.run();
            assert_eq!(x(&carol, after), Some(s("after")));
            assert_eq!(x(&bob, after), None);
        }
    }
}

// spec/permissions.md §9: every device of the person lists its links, a restored one too, to a
// thing without a label of its own before the link as well, and revokes them
#[test]
fn links_listed_on_every_device_and_after_restore_spec_permissions_9() {
    let mut w = World::new();
    let host = w.add_host();
    let (da, card) = w.person(1, &[host]);
    let g = group(&da);
    let t = item(&da, da.me(), da.home(), "plain");
    let db = pair_device(&mut w, &da, 4);
    da.make_link(g, Role::Read, Default::default()).unwrap();
    da.make_link(t, Role::Read, Default::default()).unwrap();
    da.make_link(t, Role::Write, osis::LinkOpts { until: None, single_use: true, direct: false }).unwrap();
    w.run();
    assert_eq!(db.all_links().len(), 3);
    let cfg = w.cfg(5, &[host]);
    let re = w.until(Osis::restore(cfg, &card), 1000, 30).unwrap();
    for _ in 0..3 {
        w.advance(60_000);
        w.run();
    }
    assert_eq!(re.all_links().len(), 3);
    let id = re.links(t).iter().find(|l| !l.single_use).unwrap().id;
    w.until(re.revoke_link(id, skip_sync()), 1000, 10).unwrap();
    w.run();
    assert_eq!(da.all_links().len(), 2);
    assert_eq!(db.all_links().len(), 2);
}
