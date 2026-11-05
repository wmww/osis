//! More of the sharing and sync surface through hosts in process (notes/api.md Sharing
//! and roles, Sync configuration and status, Diagnostics), no tokio: see osis_sim::world.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common::TestWrites as _;
use osis::internals::Internals as _;
use crate::common;
use osis_sim::world::World;
use common::*;
use crate::common::CreateIn;
use osis::{SetRoleOpts, SyncFirst, Error, Osis, Role, SyncScope, SyncState, Tid, Value};
use std::time::Duration;

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

fn item(db: &Osis, owner: Tid, g: Tid, v: &str) -> Tid {
    let mut w = db.write();
    let t = w.create_in(owner, &[g]).unwrap();
    w.at(t, osis::Key::untyped(ak("t:x.0"))).set(&s(v)).unwrap();
    w.commit().unwrap();
    t
}

fn x(db: &Osis, t: Tid) -> Option<Value> {
    db.at(t, osis::Key::untyped(ak("t:x.0"))).get().unwrap()
}

fn group(db: &Osis) -> Tid {
    let mut w = db.write();
    let g = w.create_in(db.me(), &[db.me()]).unwrap();
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
fn diags(db: &Osis, kind: fn(osis::Diagnostic) -> Option<Vec<Tid>>) -> std::sync::mpsc::Receiver<Vec<Tid>> {
    let (tx, rx) = std::sync::mpsc::channel();
    db.on_diagnostic(move |_, d| {
        if let Some(t) = kind(d) {
            let _ = tx.send(t);
        }
    }).unwrap()
    .detach();
    rx
}

// notes/api.md Sharing (grant, leave), spec/permissions.md §2: a raise is a change, a lower role
// is refused there (`set_role`); a holder's self-removal reaches the admin.
#[test]
fn grant_and_leave_spec_permissions_2() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Read);
    assert_eq!(bob.role_on(g).unwrap(), Some(Role::Read));
    alice.grant(g, bob.me(), Role::Write, Default::default()).unwrap();
    assert!(matches!(alice.grant(g, bob.me(), Role::Read, Default::default()), Err(Error::Invalid(_))));
    w.run();
    assert_eq!(bob.role_on(g).unwrap(), Some(Role::Write));
    let u = item(&bob, g, g, "as a writer");
    w.run();
    assert_eq!(x(&alice, u), Some(s("as a writer")));
    bob.leave(bob.me(), g).unwrap();
    w.run();
    assert!(!alice.grants(g).unwrap().contains_key(&bob.me()));
    assert_eq!(bob.role_on(g).unwrap(), None);
}

// notes/api.md Sharing: `grant` never lowers a role: lowering needs a pre-sync and a rotation, which
// only `set_role` runs. A grant at the same role still changes `until` and `invite`, a raise goes
// through, and the refused grant writes nothing and says what to call.
// spec: none (API surface, notes/api.md)
#[test]
fn grant_refuses_a_lower_role() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Write);
    let b = bob.me();
    let plain = {
        let mut x = alice.write();
        let t = x.create().unwrap();
        x.at(t, osis::Key::untyped(ak("t:x.0"))).set(&s("v")).unwrap();
        x.commit().unwrap();
        t
    };
    alice.grant(plain, b, Role::Admin, Default::default()).unwrap();
    for (t, to, had) in [(g, Role::Read, Role::Write), (plain, Role::Write, Role::Admin), (plain, Role::Read, Role::Admin)] {
        let before = alice.engine(|e| e.commit_ids().len());
        let r = alice.grant(t, b, to, Default::default());
        assert!(matches!(&r, Err(Error::Invalid(m)) if m.contains("set_role")), "{r:?}");
        assert_eq!(alice.engine(|e| e.commit_ids().len()), before, "nothing written");
        assert_eq!(alice.grants(t).unwrap()[&b].role, had);
    }
    w.run();
    assert_eq!(bob.role_on(g).unwrap(), Some(Role::Write));
    // the same role changes the rest of the grant
    let until = osis::Time(alice.now().unwrap().0 + 1_000_000);
    alice.grant(g, b, Role::Write, osis::GrantOpts { until: Some(until), invite: None }).unwrap();
    assert_eq!(alice.grants(g).unwrap()[&b].until, Some(until));
    alice.grant(g, b, Role::Admin, Default::default()).unwrap();
    assert_eq!(alice.grants(g).unwrap()[&b].role, Role::Admin);
}

// notes/api.md Sharing (revoke_link), spec/permissions.md §8: revoking a multi-use link removes
// its key; `links` no longer lists it.
#[test]
fn revoke_link_spec_permissions_8() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let g = group(&alice);
    alice.make_link(g, Role::Read, Default::default()).unwrap();
    let ls = alice.links_of(g).unwrap();
    assert_eq!(ls.len(), 1);
    assert!(!ls[0].single_use);
    w.run();
    w.until(alice.revoke_link(ls[0].id, SyncFirst::Skip), 1000, 5).unwrap();
    assert!(alice.links_of(g).unwrap().is_empty());
}

// spec/permissions.md §4 (owners' keysets), spec/crypto.md §4 (keyset names): a person who got its host after creation has an inbox write as its newest `keys.0`; a link's actor names the person's keyset, so that keyset must come along or a redeemer holds no established epoch to box
#[test]
fn redeem_link_of_a_person_with_a_late_host_spec_permissions_4() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = osis::internals::create(w.cfg(1, &[])).unwrap();
    let (bob, _) = w.person(2, &[host]);
    alice.add_host(&bob.hosts().unwrap()[0]).unwrap();
    w.run();
    let g = group(&alice);
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
}

fn device(w: &mut World, db: &Osis, seed: u64) -> Tid {
    let join = osis::internals::pair(w.cfg(seed, &[]), &db.pair_offer().unwrap()).unwrap();
    let (node, reply) = db.pair_accept(join.request()).unwrap();
    join.finish(&reply).unwrap();
    w.run();
    node
}

fn skip_sync() -> SetRoleOpts {
    SetRoleOpts { sync: SyncFirst::Skip, keep: None }
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
    let (bob, _) = osis::internals::create(w.cfg(2, &[])).unwrap();
    bob.add_host(&alice.hosts().unwrap()[0]).unwrap();
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
    w.until(alice.set_role(g, ids[1], None, skip_sync()), 1000, 10).unwrap();
    w.run();
    alice.grant(g, ids[2], Role::Admin, Default::default()).unwrap();
    w.run();
    let card = frank.contact_card().unwrap();
    w.run();
    let f = w.until(erin.import_contact(&card), 1000, 10).unwrap();
    erin.grant(g, f, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(frank.role_on(g).unwrap(), Some(Role::Read));
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

// spec/permissions.md §8, §4: a link made before its person's recovery still works, and one made after
#[test]
fn links_around_a_recovery_spec_permissions_8() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, card) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
    let (carol, _) = w.person(3, &[host]);
    let g = group(&alice);
    let before = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    let back = w.until(osis::internals::restore(w.cfg(9, &[]), &card), 1000, 30).unwrap();
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
    let k = alice.links_of(g).unwrap()[0].id.actor();
    // K rotates when the joiner leaves
    w.until(bob.set_role(k, bob.me(), None, skip_sync()), 1000, 10).unwrap();
    w.run();
    w.advance(70_000);
    w.run();
    let join = osis::internals::pair(w.cfg(7, &[]), &alice.pair_offer().unwrap()).unwrap();
    let (_, reply) = alice.pair_accept(join.request()).unwrap();
    let dev = join.finish(&reply).unwrap();
    w.run();
    w.advance(70_000);
    w.run();
    assert!(dev.engine(|e| e.epochs(&k).is_some_and(|x| x.read.held().next().is_some() && x.admin.held().next().is_some())), "the device holds K's secrets");
}

// spec/permissions.md §8, spec/sync.md §2 (entry boxes): a link works after a joiner left and K rotated; its new joiner reads what was there, is a holder and writes
#[test]
fn redeem_after_a_joiner_left_spec_permissions_8() {
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
    let k = alice.links_of(g).unwrap()[0].id.actor();
    w.until(bob.set_role(k, bob.me(), None, skip_sync()), 1000, 10).unwrap();
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
    assert_eq!(alice.links_of(g).unwrap().len(), 1, "the link still works and says so");
    // twice over: the entry box names only the last rotation's wrap
    w.until(carol.set_role(k, carol.me(), None, skip_sync()), 1000, 10).unwrap();
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

// spec/permissions.md §8: a revoked link tells its redeemer so, at once (`Invalid`, not a wait's `Network`), before and after K's new step reached the host, and shows nowhere; so does a kicked joiner's and one past `until`
#[test]
fn ended_link_fails_clearly_spec_permissions_8() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
    let (carol, _) = w.person(3, &[host]);
    let g = group(&alice);
    let revoked = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    w.until(alice.revoke_link(alice.links_of(g).unwrap()[0].id, SyncFirst::Skip), 1000, 10).unwrap();
    w.run();
    assert!(alice.links_of(g).unwrap().is_empty());
    assert!(matches!(w.until(carol.redeem(&revoked), 1000, 30), Err(Error::Invalid(_))));
    assert_eq!(carol.engine(|e| e.held_key_actors()), 0, "the link key is forgotten");
    let kicked = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    w.until(bob.redeem(&kicked), 1000, 30).unwrap();
    w.run();
    w.until(alice.set_role(g, bob.me(), None, skip_sync()), 1000, 10).unwrap();
    w.run();
    assert!(alice.links_of(g).unwrap().is_empty());
    assert!(matches!(w.until(carol.redeem(&kicked), 1000, 30), Err(Error::Invalid(_))));
    let until = osis::Time(alice.now().unwrap().0 + 1000);
    let expired = alice.make_link(g, Role::Write, osis::LinkOpts { until: Some(until), single_use: false, direct: false }).unwrap();
    w.run();
    assert_eq!(alice.links_of(g).unwrap().len(), 1);
    w.advance(2000);
    assert!(alice.links_of(g).unwrap().is_empty(), "past `until`, finalized or not");
    assert!(matches!(w.until(carol.redeem(&expired), 1000, 30), Err(Error::Invalid(_))));
    assert_eq!(carol.role_on(g).unwrap(), None);
    let fresh = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(w.until(carol.redeem(&fresh), 1000, 30).unwrap(), g);
}

// spec/permissions.md §8, §3: a read link too: its joiner rotates nothing on leaving, the sharer does; the link goes on
#[test]
fn redeem_after_a_read_joiner_left_spec_permissions_8() {
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
    let k = alice.links_of(g).unwrap()[0].id.actor();
    let before = alice.engine(|e| e.epochs(&k).unwrap().read.newest().unwrap());
    w.until(bob.set_role(k, bob.me(), None, skip_sync()), 1000, 10).unwrap();
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

// spec/permissions.md §8, §3: a device removal rotates K (a departure inside its owner): a link no one used yet still works, a read link as well
#[test]
fn redeem_after_a_device_removal_spec_permissions_8() {
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

// spec/permissions.md §8: the common race: a link passed on before its label reached the host is no ended link: the redeemer waits for it
#[test]
fn redeem_waits_for_a_link_still_uploading_spec_permissions_8() {
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

// spec/permissions.md §8 (Redeem): a link naming a thing its K holds no edge on joins nothing and fails plainly, whether the redeemer holds the named thing or has never heard of it
#[test]
fn redeem_of_a_mismatched_target_joins_nothing_spec_permissions_8() {
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
    let k = alice.links_of(other).unwrap()[0].id.actor();
    w.run();
    assert_eq!(carol.role_on(held).unwrap(), Some(Role::Read));
    let bad = naming(&link, held);
    for (who, db) in [("holds the target", &carol), ("does not know it", &dave)] {
        assert!(w.try_until(db.redeem(&bad), 1000, 200).is_none(), "{who}: nothing says the grant will not come");
        w.run();
        assert_eq!(db.role_on(other).unwrap(), None, "{who}");
        assert_eq!(x(db, t), None, "{who}: what the key read went with it");
        let groups = db.status().unwrap().groups;
        assert!(!groups.contains_key(&other) && !groups.contains_key(&k), "{who}: no longer synced");
        assert!(!alice.grants(k).unwrap().contains_key(&db.me()), "{who}");
    }
    assert_eq!(carol.role_on(held).unwrap(), Some(Role::Read));
    // the key was not spent: the honest link still works
    assert_eq!(w.until(dave.redeem(&link), 1000, 30).unwrap(), other);
    w.run();
    assert_eq!(x(&dave, t), Some(s("in the other group")));
}

// spec/permissions.md §8 (Redeem): an honest link works for a target this node already knows, K's edge reaching it by K's label; a redeemer who still holds the role it had gets the link's on top
#[test]
fn redeem_of_a_target_already_known_spec_permissions_8() {
    let mut w = World::new();
    let (alice, carol, g) = alice_bob(&mut w, Role::Read);
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(carol.role_on(g).unwrap(), Some(Role::Read));
    assert_eq!(w.until(carol.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    assert_eq!(carol.role_on(g).unwrap(), Some(Role::Write));
}

// spec/permissions.md §8 (Redeem), spec/sync.md §3 (certificate copy): K's edge on the target outlives the delivery that first carried it, so a link redeemed after its inbox blob expired works, target unknown
#[test]
fn redeem_after_the_delivery_expired_spec_permissions_8() {
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
    assert_eq!(carol.role_on(g).unwrap(), Some(Role::Read));
}

// spec/permissions.md §8 (Redeem): K taken off the target ends the link: a redeemer is told at once and does not join K
#[test]
fn redeem_after_k_left_the_target_spec_permissions_8() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (carol, _) = w.person(3, &[host]);
    let g = group(&alice);
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    let k = alice.links_of(g).unwrap()[0].id.actor();
    w.run();
    w.until(alice.set_role(g, k, None, skip_sync()), 1000, 10).unwrap();
    w.run();
    assert!(matches!(w.until(carol.redeem(&link), 1000, 30), Err(Error::Invalid(_))));
    w.run();
    assert!(!alice.grants(k).unwrap().contains_key(&carol.me()));
}

// spec/permissions.md §8 (Bearer use), spec/sync.md §3 (invite requests): a contact card naming a thing its K holds no edge on makes nobody a contact: its owner would count as connected on the word of the card's text
#[test]
fn contact_card_with_a_mismatched_target_spec_permissions_8() {
    let mut w = World::new();
    let (alice, carol, g) = alice_bob(&mut w, Role::Read);
    let eve = w.person(5, &[0]).0;
    let card = eve.contact_card().unwrap();
    w.run();
    let mut bad = osis_label::ShareLink::from_text(&card.to_string()).unwrap();
    bad.target = g;
    let bad: osis::ContactCard = bad.to_text().unwrap().parse().unwrap();
    assert!(w.try_until(carol.import_contact(&bad), 1000, 200).is_none(), "nothing says the grant will not come");
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

// spec/permissions.md §8 (Redeem): no edge seen by a node cut off before the end of K's label says nothing of the link: it waits, not `Invalid`, which an app takes for a dead link
#[test]
fn redeem_cut_off_mid_read_is_no_verdict_spec_permissions_8() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (carol, _) = w.person(3, &[host]);
    let g = group(&alice);
    let other = group(&alice);
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    let k = alice.links_of(g).unwrap()[0].id.actor();
    let l = alice.engine(|e| e.held_links().unwrap().iter().find(|h| h.k == k).unwrap().l);
    w.run();
    let bad = naming(&link, other);
    let mut redeem = std::pin::pin!(carol.redeem(&bad));
    step_until_l_is_here(&mut w, &carol, &mut redeem, k, l);
    assert!(!carol.sync_engine(|e| e.complete_pass(&k)));
    w.set_reachable(&carol, host, false);
    assert!(w.try_until(redeem, 1000, 200).is_none());
    assert!(!alice.grants(k).unwrap().contains_key(&carol.me()));
}

// spec/permissions.md §8 (Redeem), §3: a link read while its maker's upload stalled, K's head there and K's commits not: the failed redemption drops what the head gave, and a retry opens K's label anew and joins (the steps stop the upload at points inside that stretch)
#[test]
fn retry_after_a_stalled_upload_spec_permissions_8() {
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
        assert!(w.try_until(carol.redeem(&link), 1000, 200).is_none(), "cut {cut}");
        w.set_reachable(&alice, host, true);
        w.run();
        assert_eq!(w.until(carol.redeem(&link), 1000, 200).unwrap(), g, "cut {cut}");
        w.run();
        assert_eq!(carol.role_on(g).unwrap(), Some(Role::Read), "cut {cut}");
    }
}

// spec/permissions.md §8 (Redeem), §6: a maker who is not the target's owner, a roster snapshot of the target since, its authors off: K's edge still reaches a new redeemer
#[test]
fn redeem_of_a_target_someone_else_owns_after_a_snapshot_spec_permissions_8() {
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

// spec/permissions.md §3, §8: a failed redemption drops only what only the key read: not what a sibling device's redemption gave, a joiner's role, a kept copy or a contact's profile
#[test]
fn failed_redemption_drops_only_what_only_the_key_read_spec_permissions_3() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Read);
    let (carol, _) = w.person(3, &[0]);
    let t = item(&alice, g, g, "x");
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    let k = alice.links_of(g).unwrap()[0].id.actor();
    let one = alice.make_link(g, Role::Read, osis::LinkOpts { single_use: true, ..Default::default() }).unwrap();
    let k1 = alice.links_of(g).unwrap().into_iter().map(|l| l.id.actor()).find(|x| *x != k).unwrap();
    let card = alice.contact_card().unwrap();
    w.run();
    // a sibling's: the used-up link fails on the other device, the role through the person stays
    let c2 = pair_device(&mut w, &carol, 13);
    assert_eq!(w.until(carol.redeem(&one), 1000, 30).unwrap(), g);
    w.run();
    assert!(matches!(w.until(c2.redeem(&one), 1000, 200), Err(Error::Invalid(_))));
    w.run();
    assert_eq!(c2.role_on(k1).unwrap(), Some(Role::Read));
    w.advance(120_000); // the new device's re-seal
    w.run();
    assert_eq!(x(&c2, t), Some(s("x")));
    // a contact: the card's key kept as a bearer, the same key again with a wrong target
    assert_eq!(w.until(carol.import_contact(&card), 1000, 30).unwrap(), alice.me());
    w.run();
    let mut bad = osis_label::ShareLink::from_text(&card.to_string()).unwrap();
    bad.target = carol.me();
    let bad: osis::ContactCard = bad.to_text().unwrap().parse().unwrap();
    assert!(w.try_until(carol.import_contact(&bad), 1000, 200).is_none());
    w.run();
    assert!(carol.profile_of(alice.me()).unwrap().is_some());
    let mine = group(&carol);
    carol.grant(mine, alice.me(), Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(alice.role_on(mine).unwrap(), Some(Role::Read), "still a contact, its keys here");
    // a kept copy: after a wrong target, then the link's own key revoked; a joiner's role likewise
    let d = SetRoleOpts { sync: SyncFirst::Skip, keep: Some(true) };
    w.until(alice.set_role(g, bob.me(), None, d), 1000, 10).unwrap();
    w.run();
    assert_eq!(bob.kept_copies().unwrap(), vec![g]);
    assert!(w.try_until(bob.redeem(&naming(&link, alice.me())), 1000, 200).is_none());
    w.run();
    assert_eq!((bob.kept_copies().unwrap(), x(&bob, t)), (vec![g], Some(s("x"))), "a wrong target");
    assert_eq!(w.until(carol.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    w.until(alice.revoke_link(crate::common::link_id(k), SyncFirst::Skip), 1000, 10).unwrap();
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

// spec/permissions.md §8: one host refusing L's entry (here a child step taken without its claim set, past its cap) is no end of the link while another of its hosts has not answered; every host refusing is
#[test]
fn one_host_refusing_is_no_end_spec_permissions_8() {
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
    let k = alice.links_of(g).unwrap()[0].id.actor();
    w.until(bob.set_role(k, bob.me(), None, skip_sync()), 1000, 10).unwrap();
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
    w.until(alice.revoke_link(alice.links_of(g).unwrap()[0].id, SyncFirst::Skip), 1000, 10).unwrap();
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

// spec/permissions.md §5.3, notes/api.md Demotion and the pre-sync: offline, `Required` waits with nothing
// stamped; `Try` proceeds after its time with an `Unsynced` diagnostic.
#[test]
fn demotion_presync_policies_spec_permissions_5_3() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Write);
    item(&bob, g, g, "bob wrote");
    w.run();
    w.set_online(&alice, false);
    assert!(w.try_until(alice.set_role(g, bob.me(), None, SetRoleOpts::default()), 10_000, 10).is_none(), "out of reach: it may yet catch up");
    assert!(alice.grants(g).unwrap().contains_key(&bob.me()), "nothing stamped");
    let unsynced = diags(&alice, |d| if let osis::Diagnostic::RoleLoweredUnsynced { groups, .. } = d { Some(groups) } else { None });
    let t = SetRoleOpts { sync: SyncFirst::Try(Duration::from_secs(5)), keep: None };
    w.until(alice.set_role(g, bob.me(), Some(Role::Read), t), 1000, 10).unwrap();
    assert_eq!(alice.grants(g).unwrap().get(&bob.me()).map(|e| e.role), Some(Role::Read));
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
    let _sub = da.on_status_change(move |_, st| {
        let _ = tx.send(st.unwrap());
    }).unwrap();
    w.run();
    let home = da.me();
    let mut seen = recv(&rx);
    while seen.groups.get(&home).map(|g| g.state) != Some(SyncState::Synced) {
        seen = recv(&rx);
    }
    let join = osis::internals::pair(w.cfg(2, &[]), &da.pair_offer().unwrap()).unwrap();
    let (node, reply) = da.pair_accept(join.request()).unwrap();
    let db = join.finish(&reply).unwrap();
    w.run();
    let stranded = diags(&db, |d| if let osis::Diagnostic::Stranded { group, .. } = d { Some(vec![group]) } else { None });
    w.set_online(&db, false);
    w.until(da.remove_device(node, SetRoleOpts { sync: SyncFirst::Skip, keep: None }), 1000, 5).unwrap();
    item(&da, da.me(), home, "after the removal");
    w.run();
    w.set_online(&db, true);
    for _ in 0..3 {
        w.advance(70_000);
    }
    assert_eq!(db.status().unwrap().groups.get(&home).map(|g| g.state), Some(SyncState::Stranded));
    assert!(recv(&stranded).contains(&home));
}

// spec/permissions.md §4 (stranded heartbeat), §8: the sharer's other device opens a link's
// K label as soon as it is registered, before K's own secrets reach the host (it sees K as
// deriving from the person then); it deposits no heartbeat under a key the head does not
// register, and reads K once they arrive (they are boxed to the person).
#[test]
fn sharers_other_device_deposits_no_foreign_heartbeat_spec_permissions_4() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let join = osis::internals::pair(w.cfg(2, &[]), &alice.pair_offer().unwrap()).unwrap();
    let (_, reply) = alice.pair_accept(join.request()).unwrap();
    let dev = join.finish(&reply).unwrap();
    w.run();
    let (tx, rx) = std::sync::mpsc::channel();
    dev.on_diagnostic(move |_, d| {
        let _ = tx.send(d.to_string());
    }).unwrap()
    .detach();
    let g = group(&alice);
    alice.make_link(g, Role::Read, Default::default()).unwrap();
    let k = alice.links_of(g).unwrap()[0].id.actor();
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
    let join = osis::internals::pair(w.cfg(2, &[]), &da.pair_offer().unwrap()).unwrap();
    let (_, reply) = da.pair_accept(join.request()).unwrap();
    let db = join.finish(&reply).unwrap();
    w.run();
    w.set_online(&db, false);
    let t = item(&da, da.me(), da.me(), "by bundle");
    w.until(da.wait_synced(SyncScope::All), 1000, 5).unwrap();
    let mut b = Vec::new();
    da.export_bundle(&[da.me()], &mut b).unwrap();
    assert_eq!(x(&db, t), None);
    db.import_bundle(&b[..]).unwrap();
    db.settle();
    assert_eq!(x(&db, t), Some(s("by bundle")));
}

// notes/api.md Handle (restore), Sharing (redeem): waits last until dropped; a dropped
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
    c.store = osis::Store::Memory(store);
    assert!(w.try_until(osis::internals::restore(c.clone(), &card), 1000, 10).is_none());
    assert!(osis::internals::open(c).is_err(), "no person record after a dropped restore");
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
    c.handle.internals.clock = Some(cl.clone());
    let carol = osis::internals::create(c).unwrap().0;
    w.run();
    let (bc, cc) = (bob.contact_card().unwrap(), carol.contact_card().unwrap());
    w.run();
    let b = w.until(alice.import_contact(&bc), 1000, 10).unwrap();
    cl.set(osis::Time(w.now()));
    let c = w.until(alice.import_contact(&cc), 1000, 10).unwrap();
    cl.set(osis::Time(w.now()));
    let g = group(&alice);
    alice.grant(g, b, Role::Admin, Default::default()).unwrap();
    alice.grant(g, c, Role::Admin, Default::default()).unwrap();
    w.run();
    cl.set(osis::Time(w.now()));
    w.run();
    assert_eq!((bob.role_on(g).unwrap(), carol.role_on(g).unwrap()), (Some(Role::Admin), Some(Role::Admin)));
    w.set_online(&carol, false);
    w.advance(60_000);
    w.until(bob.set_role(g, c, None, SetRoleOpts { sync: SyncFirst::Skip, keep: None }), 1000, 10).unwrap();
    w.run();
    let until = osis::Time(w.now() + 3_600_000);
    carol.grant(g, b, Role::Admin, osis::GrantOpts { until: Some(until), invite: None }).unwrap();
    assert_eq!(carol.grants(g).unwrap().get(&b).and_then(|e| e.until), Some(until), "carol wrote it");
    // straight to Alice and Bob (G's hosts refuse her stale write key)
    deliver(&carol, &alice);
    deliver(&carol, &bob);
    w.run();
    w.advance(3_700_000);
    for db in [&alice, &bob] {
        let r = db.grants(g).unwrap();
        assert_eq!(r.get(&b).map(|e| (e.role, e.until)), Some((Role::Admin, None)));
        assert!(!r.contains_key(&c));
    }
    assert_eq!(bob.role_on(g).unwrap(), Some(Role::Admin));
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
    assert_eq!(bob.role_on(g1).unwrap(), None);
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

// spec/permissions.md §8 (removed device's links): a removed device keeps the seeds of the person's links, so
// `remove_device` lists them, a link made on that device too; the device left can revoke it.
#[test]
fn removing_a_device_lists_its_links_spec_permissions_8() {
    let mut w = World::new();
    let host = w.add_host();
    let (da, _) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
    let (carol, _) = w.person(3, &[host]);
    let g = group(&da);
    let offer = da.pair_offer().unwrap();
    let join = osis::internals::pair(w.cfg(4, &[]), &offer).unwrap();
    let (_, reply) = da.pair_accept(join.request()).unwrap();
    let db = join.finish(&reply).unwrap();
    w.run();
    let made_there = db.make_link(g, Role::Read, Default::default()).unwrap();
    w.run();
    let there = da.links_of(g).unwrap()[0].id.actor();
    let made_here = da.make_link(g, Role::Read, Default::default()).unwrap();
    w.run();
    let links = da.links_of(g).unwrap();
    assert_eq!(links.len(), 2, "every device lists the person's links");
    let here = links.iter().map(|l| l.id.actor()).find(|k| *k != there).unwrap();
    let stranger = carol.node();
    assert!(w.until(da.remove_device(stranger, skip_sync()), 1000, 10).unwrap().is_empty(), "no device of this person");
    let open = w.until(da.remove_device(db.node(), skip_sync()), 1000, 10).unwrap();
    let mut ids: Vec<Tid> = open.iter().map(|l| l.id.actor()).collect();
    ids.sort();
    let mut want = vec![there, here];
    want.sort();
    assert_eq!(ids, want);
    assert!(open.iter().all(|l| l.target == g && !l.single_use && l.role == Role::Read));
    assert_eq!(da.links().unwrap().len(), 2);
    w.run();
    // the removal ended neither: the seed still reads
    assert_eq!(w.until(bob.redeem(&made_there), 1000, 30).unwrap(), g);
    w.run();
    w.until(da.revoke_link(crate::common::link_id(there), SyncFirst::Skip), 1000, 10).unwrap();
    w.run();
    assert!(w.until(carol.redeem(&made_there), 1000, 30).is_err(), "revoked from the device left");
    assert_eq!(w.until(carol.redeem(&made_here), 1000, 30).unwrap(), g, "the other still works");
    assert_eq!(da.links().unwrap().iter().map(|l| l.id.actor()).collect::<Vec<_>>(), vec![here]);
}

fn pair_device(w: &mut World, da: &Osis, seed: u64) -> Osis {
    let offer = da.pair_offer().unwrap();
    let join = osis::internals::pair(w.cfg(seed, &[]), &offer).unwrap();
    let (_, reply) = da.pair_accept(join.request()).unwrap();
    let db = join.finish(&reply).unwrap();
    w.run();
    db
}

// spec/permissions.md §8, spec/sync.md §2: a link's text names its hosts, so a working link's K
// label stays on them whichever device of the person moves hosts: redeemed there, it reaches
// the sharer and reads the target on its new hosts.
#[test]
fn moving_hosts_keeps_a_link_made_on_another_device_spec_permissions_8() {
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
        let k = db.links_of(g).unwrap()[0].id.actor();
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
        assert!(da.grants(k).unwrap().contains_key(&bob.me()), "the redemption reached the sharer");
    }
}

// spec/permissions.md §8, spec/sync.md §2: a revoked link has no holder but the person's on K, yet
// K's label stays too, on either device: cut off from the link's host, the device revokes and
// moves hosts, and the revocation still reaches a redeemer there.
#[test]
fn moving_hosts_after_a_revoke_keeps_the_links_label_spec_permissions_8() {
    for by_maker in [true, false] {
        let mut w = World::new();
        let (h0, h1) = (w.add_host(), w.add_host());
        let (da, _) = w.person(1, &[h0]);
        let (carol, _) = w.person(3, &[h1]);
        let g = group(&da);
        let db = pair_device(&mut w, &da, 4);
        let link = da.make_link(g, Role::Read, Default::default()).unwrap();
        w.run();
        let k = db.links_of(g).unwrap()[0].id.actor();
        let mover = if by_maker { &da } else { &db };
        w.set_reachable(mover, h0, false);
        w.until(mover.revoke_link(crate::common::link_id(k), SyncFirst::Skip), 1000, 10).unwrap();
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

// spec/permissions.md §8, §3: a removed device's revocation of a link does not stand, written
// before it hears of the removal (its commit is past the removal's frontier) or after (it lists
// nothing and is refused); the link goes on working
#[test]
fn removed_device_revokes_no_link_spec_permissions_8() {
    for aware in [false, true] {
        let mut w = World::new();
        let host = w.add_host();
        let (da, _) = w.person(1, &[host]);
        let (bob, _) = w.person(2, &[host]);
        let g = group(&da);
        let db = pair_device(&mut w, &da, 4);
        let link = da.make_link(g, Role::Read, Default::default()).unwrap();
        w.run();
        let k = db.links_of(g).unwrap()[0].id.actor();
        w.set_online(&db, aware);
        w.until(da.remove_device(db.node(), skip_sync()), 1000, 10).unwrap();
        w.run();
        if aware {
            assert!(db.links().unwrap().is_empty());
            assert!(matches!(w.until(db.revoke_link(crate::common::link_id(k), SyncFirst::Skip), 1000, 10), Err(Error::Invalid(_))));
        } else {
            w.until(db.revoke_link(crate::common::link_id(k), SyncFirst::Skip), 1000, 10).unwrap();
            w.set_online(&db, true);
        }
        for _ in 0..3 {
            w.advance(60_000);
            w.run();
        }
        assert_eq!(da.links_of(g).unwrap().len(), 1, "aware {aware}");
        assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
    }
}

// spec/permissions.md §8: both devices act on K, each not having heard the other: they agree on
// K's roster and the links, whatever the order. A revocation that has not seen a redemption
// judges it as any other device's would (spec/permissions.md §3: `Skip`).
#[test]
fn two_devices_act_on_a_link_spec_permissions_8() {
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
        let k = db.links_of(g).unwrap()[0].id.actor();
        match order {
            0 => {
                w.set_online(&db, false);
                assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
                w.run();
                w.until(db.revoke_link(crate::common::link_id(k), SyncFirst::Skip), 1000, 10).unwrap();
                w.set_online(&db, true);
            }
            1 => {
                w.set_online(&db, false);
                w.until(da.revoke_link(crate::common::link_id(k), SyncFirst::Skip), 1000, 10).unwrap();
                w.until(db.revoke_link(crate::common::link_id(k), SyncFirst::Skip), 1000, 10).unwrap();
                w.set_online(&db, true);
            }
            2 => {
                assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
                assert_eq!(w.until(carol.redeem(&link), 1000, 30).unwrap(), g);
                w.run();
                w.set_online(&da, false);
                w.until(db.set_role(g, bob.me(), None, skip_sync()), 1000, 20).unwrap();
                w.set_online(&da, true);
            }
            _ => {
                assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
                w.run();
                w.set_online(&db, false);
                w.until(da.set_role(g, bob.me(), None, skip_sync()), 1000, 20).unwrap();
                w.until(db.revoke_link(crate::common::link_id(k), SyncFirst::Skip), 1000, 10).unwrap();
                w.set_online(&db, true);
            }
        }
        for _ in 0..4 {
            w.advance(60_000);
            w.run();
        }
        let r = da.grants(k).unwrap();
        assert_eq!(r, db.grants(k).unwrap(), "order {order}");
        assert!(da.links_of(g).unwrap().is_empty() && db.links_of(g).unwrap().is_empty(), "order {order}");
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

// spec/permissions.md §8: every device of the person lists its links, a restored one too, to a
// thing without a label of its own before the link as well, and revokes them
#[test]
fn links_listed_on_every_device_and_after_restore_spec_permissions_8() {
    let mut w = World::new();
    let host = w.add_host();
    let (da, card) = w.person(1, &[host]);
    let g = group(&da);
    let t = item(&da, da.me(), da.me(), "plain");
    let db = pair_device(&mut w, &da, 4);
    da.make_link(g, Role::Read, Default::default()).unwrap();
    da.make_link(t, Role::Read, Default::default()).unwrap();
    da.make_link(t, Role::Write, osis::LinkOpts { until: None, single_use: true, direct: false }).unwrap();
    w.run();
    assert_eq!(db.links().unwrap().len(), 3);
    let cfg = w.cfg(5, &[host]);
    let re = w.until(osis::internals::restore(cfg, &card), 1000, 30).unwrap();
    for _ in 0..3 {
        w.advance(60_000);
        w.run();
    }
    assert_eq!(re.links().unwrap().len(), 3);
    let id = re.links_of(t).unwrap().iter().find(|l| !l.single_use).unwrap().id;
    w.until(re.revoke_link(id, SyncFirst::Skip), 1000, 10).unwrap();
    w.run();
    assert_eq!(da.links().unwrap().len(), 2);
    assert_eq!(db.links().unwrap().len(), 2);
}

// notes/api.md Sharing (`set_role`), spec/permissions.md §2: a raise waits for nothing and keeps
// `until` and `invite`; a lowering caps `invite` and keeps `until`; a role that stays writes nothing;
// no current role: `Some` grants, `None` writes nothing; `keep` beside a role is `Invalid`, at once.
#[test]
fn set_role_raises_lowers_and_writes_nothing_when_nothing_changes() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Write);
    let b = bob.me();
    let commits = |db: &Osis| db.engine(|e| e.commit_ids().len());
    let until = osis::Time(alice.now().unwrap().0 + 1_000_000);
    alice.grant(g, b, Role::Write, osis::GrantOpts { until: Some(until), invite: Some(Role::Write) }).unwrap();

    let before = commits(&alice);
    w.until(alice.set_role(g, b, Some(Role::Write), Default::default()), 1000, 5).unwrap();
    assert_eq!(commits(&alice), before, "the same role");
    let keep = SetRoleOpts { keep: Some(true), ..Default::default() };
    assert!(matches!(w.until(alice.set_role(g, b, Some(Role::Read), keep), 1000, 5), Err(Error::Invalid(_))));
    assert_eq!(alice.grants(g).unwrap()[&b].role, Role::Write, "nothing written");

    // a raise: no pre-sync, whatever `sync` says, so a cut-off node raises too
    w.set_online(&alice, false);
    w.until(alice.set_role(g, b, Some(Role::Admin), Default::default()), 1000, 5).unwrap();
    let e = alice.grants(g).unwrap()[&b];
    assert_eq!((e.role, e.until, e.invite), (Role::Admin, Some(until), Some(Role::Write)));
    w.set_online(&alice, true);
    w.run();

    w.until(alice.set_role(g, b, Some(Role::Read), skip_sync()), 1000, 5).unwrap();
    let e = alice.grants(g).unwrap()[&b];
    assert_eq!((e.role, e.until, e.invite), (Role::Read, Some(until), Some(Role::Read)), "invite capped");

    // removed, then nothing to remove; `Some` grants anew with default options
    w.until(alice.set_role(g, b, None, skip_sync()), 1000, 5).unwrap();
    let before = commits(&alice);
    w.until(alice.set_role(g, b, None, skip_sync()), 1000, 5).unwrap();
    assert_eq!(commits(&alice), before, "no role, none to remove");
    w.until(alice.set_role(g, b, Some(Role::Read), Default::default()), 1000, 5).unwrap();
    let e = alice.grants(g).unwrap()[&b];
    assert_eq!((e.role, e.until, e.invite), (Role::Read, None, None));
}

// spec/permissions.md §3, §5.1: a new edge below one past its `until` is a demotion to receivers,
// with a frontier and a rotation: `grant` refuses it as it does a live one, and `set_role` makes it.
// At its old role or above, `grant` renews it. Whatever ended, the holder has the role afterwards.
#[test]
fn a_role_below_an_ended_grant_takes_set_role() {
    for role in [Role::Write, Role::Admin] {
        let mut w = World::new();
        let (alice, bob, g) = alice_bob(&mut w, role);
        let b = bob.me();
        let until = osis::Time(alice.now().unwrap().0 + 1000);
        alice.grant(g, b, role, osis::GrantOpts { until: Some(until), invite: None }).unwrap();
        w.run();
        w.advance(2000);
        assert!(!alice.grants(g).unwrap().contains_key(&b), "ended");
        let before = alice.engine(|e| e.commit_ids().len());
        let r = alice.grant(g, b, Role::Read, Default::default());
        assert!(matches!(&r, Err(Error::Invalid(m)) if m.contains("set_role")), "{r:?}");
        assert_eq!(alice.engine(|e| e.commit_ids().len()), before, "nothing written");
        w.until(alice.set_role(g, b, Some(Role::Read), skip_sync()), 1000, 10).unwrap();
        w.run();
        assert_eq!(alice.grants(g).unwrap()[&b].role, Role::Read);
        assert_eq!(bob.role_on(g).unwrap(), Some(Role::Read));
        // ended once more: renewed at its role
        alice.grant(g, b, Role::Read, osis::GrantOpts { until: Some(osis::Time(alice.now().unwrap().0 + 1000)), invite: None }).unwrap();
        w.run();
        w.advance(2000);
        alice.grant(g, b, Role::Read, Default::default()).unwrap();
        w.run();
        assert_eq!(bob.role_on(g).unwrap(), Some(Role::Read));
    }
}

// notes/api.md Sharing (`leave`), spec/permissions.md §2: no such grant writes nothing; another
// actor needs this node its admin (`Permission`), and an admin of the target is sent to `set_role`.
#[test]
fn leave_of_no_grant_and_of_others() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Read);
    let before = bob.engine(|e| e.commit_ids().len());
    bob.leave(alice.me(), bob.me()).unwrap();
    assert_eq!(bob.engine(|e| e.commit_ids().len()), before, "no such grant");
    let host = w.add_host();
    let (carol, _) = w.person(3, &[host]);
    w.run();
    let card = carol.contact_card().unwrap();
    w.run();
    let c = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    alice.grant(g, c, Role::Read, Default::default()).unwrap();
    w.run();
    assert!(bob.grants(g).unwrap().contains_key(&c));
    assert!(matches!(bob.leave(c, g), Err(Error::Permission { .. })));
    assert!(matches!(alice.leave(bob.me(), g), Err(Error::Invalid(_))), "Alice is g's admin: set_role");
    assert!(alice.grants(g).unwrap().contains_key(&bob.me()));
}

// notes/api.md Sharing (`leave`): one holding only through a link's actor is told so, for nothing
// would change: never a quiet success with the role still there. Leaving that actor ends it.
// spec: none (API surface, notes/api.md)
#[test]
fn leave_tells_of_another_way_in() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
    w.run();
    let g = group(&alice);
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    w.run();
    w.until(bob.redeem(&link), 1000, 30).unwrap();
    w.run();
    let k = alice.links_of(g).unwrap()[0].id.actor();
    assert!(bob.role_on(g).unwrap().is_some());
    let r = bob.leave(bob.me(), g);
    assert!(matches!(&r, Err(Error::Invalid(m)) if m.contains(&k.to_string())), "{r:?}");
    bob.leave(bob.me(), k).unwrap();
    assert!(bob.holders(g).unwrap().iter().all(|h| h.actor != bob.me()));
    bob.leave(bob.me(), g).unwrap();
}

// spec/permissions.md §1 (effective role: the best path), notes/api.md Sharing (`holders`): a
// member of an actor reached two ways gets the better one too, whichever was found first; the same
// way again adds nothing.
#[test]
fn holders_finds_the_best_way_through_a_nested_actor() {
    let mut w = World::new();
    let (alice, bob, t) = alice_bob(&mut w, Role::Read);
    let b = bob.me();
    // walked in tid order: the worse ways come first
    let mut gs = [group(&alice), group(&alice), group(&alice), group(&alice)];
    gs.sort();
    let team = group(&alice);
    let soon = osis::Time(alice.now().unwrap().0 + 1_000_000);
    alice.grant(t, gs[0], Role::Read, Default::default()).unwrap();
    alice.grant(t, gs[1], Role::Write, osis::GrantOpts { until: Some(soon), invite: None }).unwrap();
    alice.grant(t, gs[2], Role::Write, Default::default()).unwrap();
    alice.grant(t, gs[3], Role::Read, Default::default()).unwrap();
    for g in gs {
        alice.grant(g, team, Role::Admin, Default::default()).unwrap();
    }
    alice.grant(team, b, Role::Admin, Default::default()).unwrap();
    let ways: Vec<(Role, Option<osis::Time>, Tid)> = alice.holders(t).unwrap().into_iter().filter(|h| h.actor == b && h.through.len() == 2).map(|h| (h.role, h.until, h.through[0])).collect();
    assert_eq!(ways, [(Role::Read, None, gs[0]), (Role::Write, Some(soon), gs[1]), (Role::Write, None, gs[2])], "the last way beats none before it");
    assert_eq!(alice.holders(t).unwrap().iter().filter(|h| h.actor == team).count(), 4, "each grant the team holds by");
}

// notes/api.md Sharing (`holders`), spec/permissions.md §2, §8: one entry per grant that makes an
// actor a holder: direct and through a link both, the role the least along the way; `holders` of
// the link's actor answers who holds through it.
#[test]
fn holders_lists_every_grant_and_who_holds_through_a_link() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Write);
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    let k = alice.links_of(g).unwrap()[0].id.actor();
    let hs = alice.holders(g).unwrap();
    let ways: Vec<&osis::Holder> = hs.iter().filter(|h| h.actor == bob.me()).collect();
    assert_eq!(ways.iter().map(|h| (h.role, h.through.clone())).collect::<Vec<_>>(), vec![(Role::Write, vec![]), (Role::Read, vec![k])]);
    assert!(alice.holders(k).unwrap().iter().any(|h| h.actor == bob.me() && h.through.is_empty()));
    // nearest first
    let depth: Vec<usize> = hs.iter().map(|h| h.through.len()).collect();
    assert!(depth.windows(2).all(|d| d[0] <= d[1]), "{depth:?}");
    // a removal goes down both
    w.until(alice.set_role(g, bob.me(), None, skip_sync()), 1000, 10).unwrap();
    assert!(!alice.holders(g).unwrap().iter().any(|h| h.actor == bob.me()));
}

// spec/permissions.md §5.1 step 4, notes/api.md Sharing (`grant`): a holder that left, or whose
// grant ended and was finalized, keeps what it wrote; an explicit write below the role it lost
// audits it, and with no frontier would undo all of it everywhere. So `grant` refuses (writing
// nothing, as for a present role), `set_role` writes the frontier first, and at the old role or
// above nothing is in question.
#[test]
fn a_role_below_one_lost_keeps_what_the_holder_wrote_spec_permissions_5_1() {
    for ended in [false, true] {
        let mut w = World::new();
        let (alice, bob, g) = alice_bob(&mut w, Role::Write);
        let b = bob.me();
        if ended {
            alice.grant(g, b, Role::Write, osis::GrantOpts { until: Some(osis::Time(alice.now().unwrap().0 + 5000)), invite: None }).unwrap();
            w.run();
        }
        let mine = item(&bob, g, g, "by bob");
        w.run();
        assert_eq!(x(&alice, mine), Some(s("by bob")));
        if ended {
            w.advance(10_000);
            w.run();
            w.advance(70_000);
            w.run();
            assert!(alice.engine(|e| e.core.timelines.get(&g).is_some_and(|t| t.edges_at(None).get(&b, &g).is_none())), "finalized");
        } else {
            bob.leave(b, g).unwrap();
            w.run();
        }
        assert!(!alice.grants(g).unwrap().contains_key(&b));
        let before = alice.engine(|e| e.commit_ids().len());
        let r = alice.grant(g, b, Role::Read, Default::default());
        assert!(matches!(&r, Err(Error::Invalid(m)) if m.contains("set_role")), "{r:?}");
        assert_eq!(alice.engine(|e| e.commit_ids().len()), before, "nothing written");
        assert_eq!(x(&alice, mine), Some(s("by bob")));
        w.until(alice.set_role(g, b, Some(Role::Read), skip_sync()), 1000, 10).unwrap();
        assert_eq!(alice.grants(g).unwrap()[&b].role, Role::Read);
        assert_eq!(x(&alice, mine), Some(s("by bob")), "kept at the admin");
        w.run();
        w.advance(70_000);
        w.run();
        assert_eq!(bob.role_on(g).unwrap(), Some(Role::Read));
        assert_eq!(x(&bob, mine), Some(s("by bob")), "kept and readable at the holder");
    }
    // at the old role: no question, `grant` does it
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Write);
    let mine = item(&bob, g, g, "by bob");
    w.run();
    bob.leave(bob.me(), g).unwrap();
    w.run();
    alice.grant(g, bob.me(), Role::Write, Default::default()).unwrap();
    assert_eq!(x(&alice, mine), Some(s("by bob")));
}

// spec/permissions.md §2: an invite grant over a grant that ended: one still in the state is a
// removal to receivers, so `Permission` (it needs an admin), never a commit they would refuse; once
// an admin's write took it away the grant counts as none, audits nothing, and goes through.
#[test]
fn invite_grant_over_an_ended_grant_spec_permissions_2() {
    let mut w = World::new();
    let (alice, carol, g) = alice_bob(&mut w, Role::Read);
    alice.grant(g, carol.me(), Role::Read, osis::GrantOpts { invite: Some(Role::Read), ..Default::default() }).unwrap();
    w.run();
    let (dan, _) = w.person(3, &[0]);
    w.run();
    let card = dan.contact_card().unwrap();
    w.run();
    let d = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    w.until(carol.import_contact(&card), 1000, 10).unwrap();
    alice.grant(g, d, Role::Write, osis::GrantOpts { until: Some(osis::Time(alice.now().unwrap().0 + 1000)), invite: None }).unwrap();
    w.run();
    let by_dan = item(&dan, g, g, "by dan");
    w.run();
    w.advance(5000);
    let r = carol.grant(g, d, Role::Read, Default::default());
    assert!(matches!(r, Err(Error::Permission { .. })), "{r:?}");
    // Alice's next write finalizes it
    item(&alice, g, g, "by alice");
    w.run();
    w.advance(70_000);
    w.run();
    carol.grant(g, d, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(alice.grants(g).unwrap()[&d].role, Role::Read);
    assert_eq!(x(&alice, by_dan), Some(s("by dan")));
}

// spec/permissions.md §5.3, notes/arbitrary-values.md: a wait has no deadline however far the clock runs; `Required` too, while its group may yet sync, and it fails `Unsynced` once it never can; `SyncFirst::Try` goes ahead at 0 at once, and at `Duration::MAX` is `Required` that does not fail
#[test]
fn waits_have_no_deadline_and_try_goes_ahead() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Write);
    item(&bob, g, g, "bob wrote");
    w.run();
    w.set_online(&alice, false);
    item(&alice, g, g, "alice wrote, offline");
    {
        let f = alice.wait_synced(SyncScope::Thing(g));
        let mut f = std::pin::pin!(f);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(f.as_mut().poll(&mut cx).is_pending());
        w.advance(10 * 365 * 86_400_000);
        w.run();
        assert!(f.as_mut().poll(&mut cx).is_pending(), "no deadline");
    }
    let required = SetRoleOpts::default();
    assert!(w.try_until(alice.set_role(g, bob.me(), Some(Role::Read), required), 1000, 100).is_none());
    let forever = SetRoleOpts { sync: SyncFirst::Try(Duration::MAX), keep: None };
    assert!(w.try_until(alice.set_role(g, bob.me(), Some(Role::Read), forever), 1000, 100).is_none());
    let t = SetRoleOpts { sync: SyncFirst::Try(Duration::ZERO), keep: None };
    w.until(alice.set_role(g, bob.me(), Some(Role::Read), t), 10, 2).unwrap();
    assert_eq!(alice.grants(g).unwrap()[&bob.me()].role, Role::Read);

}

// spec/permissions.md §5.3, notes/api.md set_role: `SyncFirst::Try` gives the whole call its time: a holder with two ways in, offline, does not cost it twice
#[test]
fn try_is_for_the_call_not_each_way_in() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Write);
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    w.run();
    w.until(bob.redeem(&link), 1000, 30).unwrap();
    w.run();
    w.set_online(&alice, false);
    let t = SetRoleOpts { sync: SyncFirst::Try(Duration::from_secs(5)), keep: None };
    w.until(alice.set_role(g, bob.me(), None, t), 1000, 8).unwrap();
    assert!(!alice.holders(g).unwrap().iter().any(|h| h.actor == bob.me()));
}
