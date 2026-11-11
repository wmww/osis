//! More of the sharing and sync surface through peers in process (notes/api.md Sharing
//! and roles, Sync configuration and status, Diagnostics), no tokio: see osis_sim::world.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common::TestWrites as _;
use osis::internals::Internals as _;
use crate::common;
use osis_sim::world::World;
use common::*;
use crate::common::CreateIn;
use osis::{SetRoleOpts, Error, HolderKind, Osis, Role, SyncScope, SyncState, Tid, Value};

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

fn item(db: &Osis, admin: Tid, g: Tid, v: &str) -> Tid {
    let mut w = db.write();
    let t = w.create_in(admin, &[g]).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&s(v)).unwrap();
    w.commit().unwrap();
    t
}

fn x(db: &Osis, t: Tid) -> Option<Value> {
    db.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap()
}

fn group(db: &Osis) -> Tid {
    let mut w = db.write();
    let g = w.create_in(db.me(), &[db.home()]).unwrap();
    w.commit().unwrap();
    db.sync(g, &[]).unwrap();
    g
}

/// Alice and Bob on one peer, Bob granted `role` on Alice's synced group.
fn alice_bob(w: &mut World, role: Role) -> (Osis, Osis, Tid) {
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    w.run();
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let g = group(&alice);
    alice.grant(g, b, role, Default::default()).unwrap();
    w.run();
    (alice, bob, g)
}

/// Diagnostics of `kind` a node reports from now on.
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
// only `set_role` runs. A grant at the same role still changes `until` and `may_grant`, a raise goes
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
        x.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&s("v")).unwrap();
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
    alice.grant(g, b, Role::Write, osis::GrantOpts { until: Some(until), may_grant: None }).unwrap();
    assert_eq!(alice.grants(g).unwrap()[&b].until, Some(until));
    alice.grant(g, b, Role::Admin, Default::default()).unwrap();
    assert_eq!(alice.grants(g).unwrap()[&b].role, Role::Admin);
}

// spec/permissions.md §4 (first admins' keysets), spec/crypto.md §4 (held keyset): an account who got its peer after creation has an inbox write as its newest `keys.0`; a link's actor boxes the account at its keyset, so that keyset must come along or a redeemer holds no established epoch to box
#[test]
fn redeem_link_of_an_account_with_a_late_peer_spec_permissions_4() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = osis::internals::create(w.cfg(1, &[])).unwrap();
    let bob = w.account(2, &[host]);
    alice.add_peer(&bob.saved_peers().unwrap()[0]).unwrap();
    w.run();
    let g = group(&alice);
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
}

fn new_node(w: &mut World, db: &Osis, seed: u64) -> Tid {
    let join = osis::internals::pair(w.cfg(seed, &[]), &db.pair_offer().unwrap()).unwrap();
    let (node, reply) = db.pair_accept(join.request()).unwrap();
    join.finish(&reply).unwrap();
    w.run();
    node
}

fn skip_sync() -> SetRoleOpts {
    SetRoleOpts { retain_copy: None }
}

// spec/permissions.md §4 (current `keys.0`), spec/crypto.md §4 (held keyset): a rotation of a group boxes a holder at its keyset; a holder with a late peer has an inbox write as its newest `keys.0`; an admin who joins after the rotation still gets the keyset, or holds no established epoch to box a grant with
#[test]
fn newcomer_admin_after_a_rotation_naming_a_late_peer_holder_spec_crypto_4() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let dave = w.account(4, &[host]);
    let erin = w.account(5, &[host]);
    let frank = w.account(6, &[host]);
    let bob = osis::internals::create(w.cfg(2, &[])).unwrap();
    bob.add_peer(&alice.saved_peers().unwrap()[0]).unwrap();
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
    alice.set_role(g, ids[1], None, skip_sync()).unwrap();
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

// spec/permissions.md §4 (current `keys.0`), §3: the account rotates (a node removed), then gets another peer, then makes a link: its keyset is not its newest `keys.0`
#[test]
fn redeem_link_after_a_rotation_and_a_late_peer_spec_permissions_4() {
    let mut w = World::new();
    let h0 = w.add_host();
    let h1 = w.add_host();
    let alice = w.account(1, &[h0]);
    let bob = w.account(2, &[h0]);
    let node = new_node(&mut w, &alice, 7);
    let g = group(&alice);
    alice.set_role(alice.home(), node, None, skip_sync()).unwrap();
    w.run();
    alice.add_peer(&w.addr(h1).unwrap()).unwrap();
    w.run();
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
}

// spec/permissions.md §4, spec/sync.md §5: a first admin's new node holds K's keyset under the target's label before any secret of K (K's box is under K's label alone): it still opens K's label, by the epochs its first admin's derive, and gets K's secrets
#[test]
fn new_node_gets_k_keyset_before_its_box_spec_permissions_4() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    let g = group(&alice);
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    let k = alice.links_of(g).unwrap()[0].id.actor();
    // K rotates when the joiner leaves
    bob.set_role(k, bob.me(), None, skip_sync()).unwrap();
    w.run();
    w.advance(70_000);
    w.run();
    let join = osis::internals::pair(w.cfg(7, &[]), &alice.pair_offer().unwrap()).unwrap();
    let (_, reply) = alice.pair_accept(join.request()).unwrap();
    let dev = join.finish(&reply).unwrap();
    w.run();
    w.advance(70_000);
    w.run();
    assert!(dev.engine(|e| e.epochs(&k).is_some_and(|x| x.read.held().next().is_some() && x.admin.held().next().is_some())), "the node holds K's secrets");
}

// spec/permissions.md §7, spec/sync.md §2 (entry boxes): a link works after a joiner left and K rotated; its new joiner reads what was there, is a holder and writes
#[test]
fn redeem_after_a_joiner_left_spec_permissions_7() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    let carol = w.account(3, &[host]);
    let dave = w.account(4, &[host]);
    let g = group(&alice);
    let t = item(&alice, g, g, "from alice");
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    let k = alice.links_of(g).unwrap()[0].id.actor();
    bob.set_role(k, bob.me(), None, skip_sync()).unwrap();
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
    carol.set_role(k, carol.me(), None, skip_sync()).unwrap();
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

// notes/api.md Sharing (revoke_link), spec/permissions.md §7: revoking a multi-use link removes its key; `links` no longer lists it. A revoked link tells its redeemer so, at once (`Invalid`, not a wait's `Network`), before and after K's new step reached the peer, and shows nowhere; so does a kicked joiner's and one past `until`
#[test]
fn ended_link_fails_clearly_spec_permissions_7() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    let carol = w.account(3, &[host]);
    let g = group(&alice);
    let revoked = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    let ls = alice.links_of(g).unwrap();
    assert_eq!(ls.len(), 1);
    assert!(!ls[0].single_use);
    alice.revoke_link(ls[0].id).unwrap();
    w.run();
    assert!(alice.links_of(g).unwrap().is_empty());
    assert!(matches!(w.until(carol.redeem(&revoked), 1000, 30), Err(Error::Invalid(_))));
    assert_eq!(carol.engine(|e| e.held_key_actors()), 0, "the link key is forgotten");
    let kicked = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    w.until(bob.redeem(&kicked), 1000, 30).unwrap();
    w.run();
    alice.set_role(g, bob.me(), None, skip_sync()).unwrap();
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

// spec/permissions.md §7, §3: a read link too: its joiner rotates nothing on leaving, the sharer does; the link goes on
#[test]
fn redeem_after_a_read_joiner_left_spec_permissions_7() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    let carol = w.account(3, &[host]);
    let g = group(&alice);
    let t = item(&alice, g, g, "from alice");
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    let k = alice.links_of(g).unwrap()[0].id.actor();
    let before = alice.engine(|e| e.epochs(&k).unwrap().read.newest().unwrap());
    bob.set_role(k, bob.me(), None, skip_sync()).unwrap();
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

// spec/permissions.md §7, §3: a node removal rotates the account, then K (its box to the account stale): a link no one used yet still works, a read link as well
#[test]
fn redeem_after_a_node_removal_spec_permissions_7() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let carol = w.account(3, &[host]);
    let node = new_node(&mut w, &alice, 7);
    let g = group(&alice);
    let t = item(&alice, g, g, "from alice");
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    w.run();
    alice.set_role(alice.home(), node, None, skip_sync()).unwrap();
    w.run();
    w.advance(70_000);
    w.run();
    assert_eq!(w.until(carol.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    assert_eq!(x(&carol, t), Some(s("from alice")));
}

// spec/permissions.md §7: the common race: a link passed on before its label reached the peer is no ended link: the redeemer waits for it
#[test]
fn redeem_waits_for_a_link_still_uploading_spec_permissions_7() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let carol = w.account(3, &[host]);
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

// spec/permissions.md §7 (Redeem): a link naming a thing its K holds no grant on joins nothing and fails plainly, whether the redeemer holds the named thing or has never heard of it
#[test]
fn redeem_of_a_mismatched_target_joins_nothing_spec_permissions_7() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let carol = w.account(3, &[host]);
    let dave = w.account(4, &[host]);
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

// spec/permissions.md §7 (Redeem), spec/sync.md §3 (certificate copy): K's grant on the target outlives the delivery that first carried it, so a link redeemed after its inbox blob expired works, target unknown
#[test]
fn redeem_after_the_delivery_expired_spec_permissions_7() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let carol = w.account(3, &[host]);
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

// spec/permissions.md §7 (Redeem): K taken off the target ends the link: a redeemer is told at once and does not join K
#[test]
fn redeem_after_k_left_the_target_spec_permissions_7() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let carol = w.account(3, &[host]);
    let g = group(&alice);
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    let k = alice.links_of(g).unwrap()[0].id.actor();
    w.run();
    alice.set_role(g, k, None, skip_sync()).unwrap();
    w.run();
    assert!(matches!(w.until(carol.redeem(&link), 1000, 30), Err(Error::Invalid(_))));
    w.run();
    assert!(!alice.grants(k).unwrap().contains_key(&carol.me()));
}

// spec/permissions.md §7 (Bearer use), spec/sync.md §3 (invite requests): a contact card naming a thing its K holds no grant on makes nobody a contact: its first admin would count as connected on the word of the card's text
#[test]
fn contact_card_with_a_mismatched_target_spec_permissions_7() {
    let mut w = World::new();
    let (alice, carol, g) = alice_bob(&mut w, Role::Read);
    let eve = w.account(5, &[0]);
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

// spec/permissions.md §7 (Redeem): no grant seen by a node cut off before the end of K's label says nothing of the link: it waits, not `Invalid`, which an app takes for a dead link
#[test]
fn redeem_cut_off_mid_read_is_no_verdict_spec_permissions_7() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let carol = w.account(3, &[host]);
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

// spec/permissions.md §7 (Redeem), §3: a link read while its maker's upload stalled, K's head there and K's commits not: the failed redemption drops what the head gave, and a retry opens K's label anew and joins (the steps stop the upload at points inside that stretch)
#[test]
fn retry_after_a_stalled_upload_spec_permissions_7() {
    for cut in [14, 20, 26] {
        let mut w = World::new();
        let host = w.add_host();
        let alice = w.account(1, &[host]);
        let carol = w.account(3, &[host]);
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

// spec/permissions.md §7 (Redeem): a maker who is not the target's first admin, its authors off: K's grant still reaches a new redeemer
#[test]
fn redeem_of_a_target_someone_else_owns_spec_permissions_7() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Admin);
    let carol = w.account(3, &[0]);
    let t = item(&alice, g, g, "x");
    w.run();
    let link = bob.make_link(g, Role::Read, Default::default()).unwrap();
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
    let dave = w.account(4, &[0]);
    assert_eq!(w.until(dave.redeem(&link2), 1000, 30).unwrap(), g);
}

// spec/permissions.md §3, §7: a failed redemption drops only what only the key read: not what a sibling node's redemption gave, a joiner's role, a kept copy or a contact's profile
#[test]
fn failed_redemption_drops_only_what_only_the_key_read_spec_permissions_3() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Read);
    let carol = w.account(3, &[0]);
    let t = item(&alice, g, g, "x");
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    let k = alice.links_of(g).unwrap()[0].id.actor();
    let one = alice.make_link(g, Role::Read, osis::LinkOpts { single_use: true, ..Default::default() }).unwrap();
    let k1 = alice.links_of(g).unwrap().into_iter().map(|l| l.id.actor()).find(|x| *x != k).unwrap();
    let card = alice.contact_card().unwrap();
    w.run();
    // a sibling's: the used-up link naming a wrong target fails on the other node, the role
    // through the account stays; naming its own target it returns it, the account having joined
    let c2 = pair_node(&mut w, &carol, 13);
    // joined: the maker's rotation for the spent link boxes the account's epoch key, so nothing strands
    w.advance(120_000);
    w.run();
    assert_eq!(w.until(carol.redeem(&one), 1000, 200).unwrap(), g);
    w.run();
    assert!(matches!(w.until(c2.redeem(&naming(&one, alice.me())), 1000, 200), Err(Error::Invalid(_))));
    w.run();
    assert_eq!(c2.role_on(k1).unwrap(), Some(Role::Read));
    assert_eq!(w.until(c2.redeem(&one), 1000, 200).unwrap(), g);
    w.run();
    assert_eq!(c2.role_on(k1).unwrap(), Some(Role::Read));
    w.advance(120_000); // the new node's re-seal
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
    let d = SetRoleOpts { retain_copy: Some(true) };
    alice.set_role(g, bob.me(), None, d).unwrap();
    w.run();
    assert_eq!(bob.retained_copies().unwrap(), vec![g]);
    assert!(w.try_until(bob.redeem(&naming(&link, alice.me())), 1000, 200).is_none());
    w.run();
    assert_eq!((bob.retained_copies().unwrap(), x(&bob, t)), (vec![g], Some(s("x"))), "a wrong target");
    assert_eq!(w.until(carol.redeem(&link), 1000, 30).unwrap(), g);
    let dave = w.account(4, &[0]);
    assert_eq!(w.until(dave.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    alice.revoke_link(crate::common::link_id(k)).unwrap();
    w.run();
    assert!(matches!(w.until(bob.redeem(&link), 1000, 200), Err(Error::Invalid(_))));
    w.run();
    assert_eq!((bob.retained_copies().unwrap(), x(&bob, t)), (vec![g], Some(s("x"))), "a revoked link");
    // Carol reaches G through the single-use link still: nothing to join, the revoked link unjudged
    assert_eq!(w.until(carol.redeem(&link), 1000, 1).unwrap(), g);
    // Dave, its joiner: the revoked link naming a wrong target fails and leaves his role on K
    assert!(matches!(w.until(dave.redeem(&naming(&link, alice.me())), 1000, 200), Err(Error::Invalid(_))));
    w.run();
    let after = item(&alice, g, g, "after");
    w.run();
    assert_eq!(x(&carol, after), Some(s("after")));
    assert_eq!(x(&dave, after), Some(s("after")), "a joiner's role");
    assert_eq!(x(&bob, after), None);
}

// spec/permissions.md §7: one peer refusing L's entry (here a child step taken without its claim set, past its cap) is no end of the link while another of its peers has not answered; every peer refusing is
#[test]
fn one_peer_refusing_is_no_end_spec_permissions_7() {
    let mut w = World::new();
    let (capped, other, own) = (w.add_host(), w.add_host(), w.add_host());
    let alice = w.account(1, &[capped, other]);
    let bob = w.account(2, &[other]);
    let carol = w.account(3, &[own]);
    let g = group(&alice);
    let t = item(&alice, g, g, "from alice");
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    w.until(bob.redeem(&link), 1000, 30).unwrap();
    w.run();
    let policy = osis_host::HostPolicy { cap_bytes: 1, ..osis_host::HostPolicy::default() };
    w.hosts[capped].hub.store_mut().set_policy(policy);
    let k = alice.links_of(g).unwrap()[0].id.actor();
    bob.set_role(k, bob.me(), None, skip_sync()).unwrap();
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
    // revoked: a redeemer with one peer down waits it out, with every peer refusing is told at once
    alice.revoke_link(alice.links_of(g).unwrap()[0].id).unwrap();
    w.run();
    w.hosts[capped].hub.store_mut().set_policy(osis_host::HostPolicy::default());
    w.advance(70_000);
    w.run();
    let dave = w.account(4, &[own]);
    w.set_reachable(&dave, other, false);
    let mut redeem = std::pin::pin!(dave.redeem(&link));
    w.advance(1000);
    w.run();
    assert!(redeem.as_mut().poll(&mut cx).is_pending());
    w.set_reachable(&dave, other, true);
    assert!(matches!(w.until(redeem, 1000, 10), Err(Error::Invalid(_))));
}

// notes/api.md Sync status (Stranded), Sync waits; spec/permissions.md §3: stranded means no host
// can serve the label. A node removed from its account while away, its home on two peers, with one
// of them out of reach: the peer it reaches refuses it, but the other may yet serve it, so it is
// not stranded and `wait_synced` waits; once both refused it is, and `wait_synced` fails `Unsynced`.
#[test]
fn stranded_only_when_every_host_refuses_spec_permissions_3() {
    let mut w = World::new();
    let (h1, h2) = (w.add_host(), w.add_host());
    let da = w.account(1, &[h1, h2]);
    let join = osis::internals::pair(w.cfg(2, &[h1, h2]), &da.pair_offer().unwrap()).unwrap();
    let (node, reply) = da.pair_accept(join.request()).unwrap();
    let db = join.finish(&reply).unwrap();
    w.run();
    let home = da.home();
    w.set_online(&db, false);
    da.set_role(home, node, None, SetRoleOpts { retain_copy: None }).unwrap();
    item(&da, da.me(), home, "after the removal");
    w.run();
    w.set_reachable(&db, h2, false);
    w.set_online(&db, true);
    for _ in 0..3 {
        w.advance(70_000);
    }
    let state = |db: &osis::Osis| db.status().unwrap().groups.get(&home).map(|g| g.state);
    assert_ne!(state(&db), Some(SyncState::Stranded), "one peer refusing, the other not heard");
    assert!(w.try_until(db.wait_synced(osis::SyncScope::Thing(home)), 1000, 10).is_none(), "the other peer may serve it");
    w.set_reachable(&db, h2, true);
    for _ in 0..3 {
        w.advance(70_000);
    }
    assert_eq!(state(&db), Some(SyncState::Stranded), "every peer refused");
    assert!(matches!(w.until(db.wait_synced(osis::SyncScope::Thing(home)), 1000, 10), Err(Error::Unsynced { .. })));
}

// notes/api.md Sync status (watch_status, Stranded), Diagnostics: a watcher sees the home group
// synced; a node removed while away is stranded on the home label and says so.
// spec/permissions.md §3
#[test]
fn watch_status_and_stranded_spec_permissions_3() {
    let mut w = World::new();
    let host = w.add_host();
    let da = w.account(1, &[host]);
    let (tx, rx) = std::sync::mpsc::channel();
    let _sub = da.on_status_change(move |_, st| {
        let _ = tx.send(st.unwrap());
    }).unwrap();
    w.run();
    let home = da.home();
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
    da.set_role(da.home(), node, None, SetRoleOpts { retain_copy: None }).unwrap();
    item(&da, da.me(), home, "after the removal");
    w.run();
    w.set_online(&db, true);
    for _ in 0..3 {
        w.advance(70_000);
    }
    assert_eq!(db.status().unwrap().groups.get(&home).map(|g| g.state), Some(SyncState::Stranded));
    assert!(recv(&stranded).contains(&home));
    // a removal writes at once, stranded or not (spec/permissions.md §5.3)
    db.set_role(home, da.node(), None, SetRoleOpts::default()).unwrap();
    assert!(!db.grants(home).unwrap().contains_key(&da.node()));
}

// spec/permissions.md §4 (stranded), §7: the sharer's other node opens a link's K label as soon
// as it is registered, before K's own secrets reach the peer (it sees K as deriving from the
// account then); it deposits nothing under a key the head does not register, and reads K once
// they arrive (they are boxed to the account).
#[test]
fn sharers_other_node_deposits_nothing_foreign_spec_permissions_4() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
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
    assert!(dev.engine(|e| e.epochs(&k).is_some_and(|x| x.read.held().next().is_some()) && e.group_actor(&k) == k), "the node reads K");
}

// spec/sync.md §11, notes/api.md Sync (bundles): a node that cannot reach the peer takes
// what it misses from a bundle another node exported.
#[test]
fn bundle_round_trip_spec_sync_11() {
    let mut w = World::new();
    let host = w.add_host();
    let da = w.account(1, &[host]);
    w.run();
    let join = osis::internals::pair(w.cfg(2, &[]), &da.pair_offer().unwrap()).unwrap();
    let (_, reply) = da.pair_accept(join.request()).unwrap();
    let db = join.finish(&reply).unwrap();
    w.run();
    w.set_online(&db, false);
    let t = item(&da, da.me(), da.home(), "by bundle");
    w.until(da.wait_synced(SyncScope::All), 1000, 5).unwrap();
    let mut b = Vec::new();
    da.export_bundle(&[da.home()], &mut b).unwrap();
    assert_eq!(x(&db, t), None);
    db.import_bundle(&b[..]).unwrap();
    db.settle();
    assert_eq!(x(&db, t), Some(s("by bundle")));
}

// notes/api.md Sharing (redeem): waits last until dropped; a dropped redemption leaves no waiter
// and no held key.
// spec: none (API surface, notes/api.md)
#[test]
fn waits_time_out_and_roll_back_spec_api_handle() {
    let mut a = World::new();
    let host = a.add_host();
    let alice = a.account(1, &[host]);
    let g = group(&alice);
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    a.run();
    let bob = a.account(2, &[host]);
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
// received anything of hers; Carol, offline with a lagging clock, then writes Bob's admin grant
// with an `until`, stamped before the removal, and hands it over directly. Bob's frontier does not cover it: it drops,
// Bob keeps admin without `until` and Carol stays removed.
#[test]
fn removed_admin_cannot_backdate_removers_edge_spec_permissions_5_1() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    // Carol's own clock: kept with the world's, then left behind while she is offline
    let cl = clock();
    let mut c = w.cfg(3, &[host]);
    c.app.internals.clock = Some(cl.clone());
    let carol = osis::internals::create(c).unwrap();
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
    bob.set_role(g, c, None, SetRoleOpts { retain_copy: None }).unwrap();
    w.run();
    let until = osis::Time(w.now() + 3_600_000);
    carol.grant(g, b, Role::Admin, osis::GrantOpts { until: Some(until), may_grant: None }).unwrap();
    assert_eq!(carol.grants(g).unwrap().get(&b).and_then(|e| e.until), Some(until), "carol wrote it");
    // straight to Alice and Bob (G's peers refuse her stale write key)
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
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
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
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
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

// spec/permissions.md §7 (removed node's links): a removed node keeps the seeds of the account's links, so
// `remove_device` lists them, a link made on that node too; the node left can revoke it.
#[test]
fn removing_a_node_lists_its_links_spec_permissions_7() {
    let mut w = World::new();
    let host = w.add_host();
    let da = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    let carol = w.account(3, &[host]);
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
    assert_eq!(links.len(), 2, "every node lists the account's links");
    let here = links.iter().map(|l| l.id.actor()).find(|k| *k != there).unwrap();
    let stranger = carol.node();
    assert!(da.remove_node(stranger, skip_sync()).unwrap().is_empty(), "no node of this account");
    let open = da.remove_node(db.node(), skip_sync()).unwrap();
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
    da.revoke_link(crate::common::link_id(there)).unwrap();
    w.run();
    assert!(w.until(carol.redeem(&made_there), 1000, 30).is_err(), "revoked from the node left");
    assert_eq!(w.until(carol.redeem(&made_here), 1000, 30).unwrap(), g, "the other still works");
    assert_eq!(da.links().unwrap().iter().map(|l| l.id.actor()).collect::<Vec<_>>(), vec![here]);
}

// spec: none (issues/net-reconnect.md, Built): the blobs a pairing brings (`Joining::finish` ingests
// a package with them) are logged at the node that took them: whatever a new node holds under a
// label, its bytes and row together, the node log lists, a chunk among them
#[test]
fn a_paired_node_logs_every_entry_it_holds() {
    let mut w = World::new();
    let h = w.add_host();
    let da = w.account(1, &[h]);
    let g = group(&da);
    let t = item(&da, g, g, "x");
    let big: String = "abcdefg".repeat(100_000);
    let mut m = da.write();
    m.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Str(big)).unwrap();
    m.commit().unwrap();
    w.run();
    let db = pair_node(&mut w, &da, 4);
    w.run();
    db.sync_engine(|e| {
        let labels: Vec<_> = e.label_status().into_iter().map(|x| x.label).collect();
        let logged: Vec<_> = e.engine_mut().run(|tx| Ok(tx.txn.log_read(None, 1 << 20)?)).unwrap().events.into_iter().map(|x| x.event).collect();
        let mut held = 0;
        for l in labels {
            let entries: Vec<_> = e.entries(&l).into_iter().map(|(b, _)| b).collect();
            for b in entries {
                if e.engine_mut().has_blob(&b) {
                    held += 1;
                    assert!(logged.contains(&osis_store::NodeEvent::Added(l, b)), "held and unlogged: {b:?}");
                }
            }
        }
        assert!(held > 1, "the node holds entries: {held}");
    });
}

fn pair_node(w: &mut World, da: &Osis, seed: u64) -> Osis {
    let offer = da.pair_offer().unwrap();
    let join = osis::internals::pair(w.cfg(seed, &[]), &offer).unwrap();
    let (_, reply) = da.pair_accept(join.request()).unwrap();
    let db = join.finish(&reply).unwrap();
    w.run();
    db
}

// spec/permissions.md §7, spec/sync.md §2: a link's text names its peers, so a working link's K
// label stays on them whichever node of the account moves peers: redeemed there, it reaches
// the sharer and reads the target on its new hosts.
#[test]
fn moving_peers_keeps_a_link_made_on_another_node_spec_permissions_7() {
    for by_maker in [true, false] {
        let mut w = World::new();
        let (h0, h1) = (w.add_host(), w.add_host());
        let da = w.account(1, &[h0]);
        let bob = w.account(2, &[h1]);
        let g = group(&da);
        let t = item(&da, g, g, "shared");
        let db = pair_node(&mut w, &da, 4);
        let link = da.make_link(g, Role::Read, Default::default()).unwrap();
        w.run();
        let k = db.links_of(g).unwrap()[0].id.actor();
        let mover = if by_maker { &da } else { &db };
        mover.add_peer(&w.addr(h1).unwrap()).unwrap();
        w.run();
        mover.remove_peer(&w.addr(h0).unwrap()).unwrap();
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

// spec/permissions.md §7, spec/sync.md §2: a revoked link has no holder but the account's on K, yet
// K's label stays too, on either node: cut off from the link's peer, the node revokes and
// moves peers, and the revocation still reaches a redeemer there.
#[test]
fn moving_peers_after_a_revoke_keeps_the_links_sync_spec_permissions_7() {
    for by_maker in [true, false] {
        let mut w = World::new();
        let (h0, h1) = (w.add_host(), w.add_host());
        let da = w.account(1, &[h0]);
        let carol = w.account(3, &[h1]);
        let g = group(&da);
        let db = pair_node(&mut w, &da, 4);
        let link = da.make_link(g, Role::Read, Default::default()).unwrap();
        w.run();
        let k = db.links_of(g).unwrap()[0].id.actor();
        let mover = if by_maker { &da } else { &db };
        w.set_reachable(mover, h0, false);
        mover.revoke_link(crate::common::link_id(k)).unwrap();
        mover.add_peer(&w.addr(h1).unwrap()).unwrap();
        mover.remove_peer(&w.addr(h0).unwrap()).unwrap();
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

// spec/permissions.md §7, §3: a removed node's revocation of a link does not stand, written
// before it hears of the removal (its commit is past the removal's frontier) or after (it lists
// nothing and is refused); the link goes on working
#[test]
fn removed_node_revokes_no_link_spec_permissions_7() {
    for aware in [false, true] {
        let mut w = World::new();
        let host = w.add_host();
        let da = w.account(1, &[host]);
        let bob = w.account(2, &[host]);
        let g = group(&da);
        let db = pair_node(&mut w, &da, 4);
        let link = da.make_link(g, Role::Read, Default::default()).unwrap();
        w.run();
        let k = db.links_of(g).unwrap()[0].id.actor();
        w.set_online(&db, aware);
        da.set_role(da.home(), db.node(), None, skip_sync()).unwrap();
        w.run();
        if aware {
            assert!(db.links().unwrap().is_empty());
            assert!(matches!(db.revoke_link(crate::common::link_id(k)), Err(Error::Invalid(_))));
        } else {
            db.revoke_link(crate::common::link_id(k)).unwrap();
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

// spec/permissions.md §7: both nodes act on K, each not having heard the other: they agree on
// K's roster and the links, whatever the order. A revocation that has not seen a redemption
// judges it as any other node's would (spec/permissions.md §3: `Skip`).
#[test]
fn two_nodes_act_on_a_link_spec_permissions_7() {
    for order in 0..4 {
        let mut w = World::new();
        let host = w.add_host();
        let da = w.account(1, &[host]);
        let bob = w.account(2, &[host]);
        let carol = w.account(3, &[host]);
        let g = group(&da);
        let db = pair_node(&mut w, &da, 4);
        let link = da.make_link(g, Role::Read, Default::default()).unwrap();
        w.run();
        let k = db.links_of(g).unwrap()[0].id.actor();
        match order {
            0 => {
                w.set_online(&db, false);
                assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
                w.run();
                db.revoke_link(crate::common::link_id(k)).unwrap();
                w.set_online(&db, true);
            }
            1 => {
                w.set_online(&db, false);
                da.revoke_link(crate::common::link_id(k)).unwrap();
                db.revoke_link(crate::common::link_id(k)).unwrap();
                w.set_online(&db, true);
            }
            2 => {
                assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
                assert_eq!(w.until(carol.redeem(&link), 1000, 30).unwrap(), g);
                w.run();
                w.set_online(&da, false);
                db.set_role(g, bob.me(), None, skip_sync()).unwrap();
                w.set_online(&da, true);
            }
            _ => {
                assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
                w.run();
                w.set_online(&db, false);
                da.set_role(g, bob.me(), None, skip_sync()).unwrap();
                db.revoke_link(crate::common::link_id(k)).unwrap();
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

// spec/permissions.md §7: every node of the account lists its links, one paired after them too, to a
// thing without a label of its own before the link as well, and revokes them
#[test]
fn links_listed_on_every_node_and_one_paired_later_spec_permissions_7() {
    let mut w = World::new();
    let host = w.add_host();
    let da = w.account(1, &[host]);
    let g = group(&da);
    let t = item(&da, da.me(), da.home(), "plain");
    let db = pair_node(&mut w, &da, 4);
    da.make_link(g, Role::Read, Default::default()).unwrap();
    da.make_link(t, Role::Read, Default::default()).unwrap();
    da.make_link(t, Role::Write, osis::LinkOpts { until: None, single_use: true, direct: false }).unwrap();
    w.run();
    assert_eq!(db.links().unwrap().len(), 3);
    let re = pair_node(&mut w, &da, 5);
    for _ in 0..3 {
        w.advance(60_000);
        w.run();
    }
    assert_eq!(re.links().unwrap().len(), 3);
    let id = re.links_of(t).unwrap().iter().find(|l| !l.single_use).unwrap().id;
    re.revoke_link(id).unwrap();
    w.run();
    assert_eq!(da.links().unwrap().len(), 2);
    assert_eq!(db.links().unwrap().len(), 2);
}

// notes/api.md Sharing (`set_role`), spec/permissions.md §2: a raise waits for nothing and keeps
// `until` and `may_grant`; a lowering caps `may_grant` and keeps `until`; a role that stays writes nothing;
// no current role: `Some` grants, `None` writes nothing; `retain_copy` beside a role is `Invalid`, at once.
#[test]
fn set_role_raises_lowers_and_writes_nothing_when_nothing_changes() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Write);
    let b = bob.me();
    let commits = |db: &Osis| db.engine(|e| e.commit_ids().len());
    let until = osis::Time(alice.now().unwrap().0 + 1_000_000);
    alice.grant(g, b, Role::Write, osis::GrantOpts { until: Some(until), may_grant: Some(Role::Write) }).unwrap();

    let before = commits(&alice);
    alice.set_role(g, b, Some(Role::Write), Default::default()).unwrap();
    assert_eq!(commits(&alice), before, "the same role");
    let keep = SetRoleOpts { retain_copy: Some(true) };
    assert!(matches!(alice.set_role(g, b, Some(Role::Read), keep), Err(Error::Invalid(_))));
    assert_eq!(alice.grants(g).unwrap()[&b].role, Role::Write, "nothing written");

    // a raise: no pre-sync, whatever `sync` says, so a cut-off node raises too
    w.set_online(&alice, false);
    alice.set_role(g, b, Some(Role::Admin), Default::default()).unwrap();
    let e = alice.grants(g).unwrap()[&b];
    assert_eq!((e.role, e.until, e.may_grant), (Role::Admin, Some(until), Some(Role::Write)));
    w.set_online(&alice, true);
    w.run();

    alice.set_role(g, b, Some(Role::Read), skip_sync()).unwrap();
    let e = alice.grants(g).unwrap()[&b];
    assert_eq!((e.role, e.until, e.may_grant), (Role::Read, Some(until), Some(Role::Read)), "may_grant capped");

    // removed, then nothing to remove; `Some` grants anew with default options
    alice.set_role(g, b, None, skip_sync()).unwrap();
    let before = commits(&alice);
    alice.set_role(g, b, None, skip_sync()).unwrap();
    assert_eq!(commits(&alice), before, "no role, none to remove");
    alice.set_role(g, b, Some(Role::Read), Default::default()).unwrap();
    let e = alice.grants(g).unwrap()[&b];
    assert_eq!((e.role, e.until, e.may_grant), (Role::Read, None, None));
}

// spec/permissions.md §3, §5.1: a new grant below one past its `until` is a demotion to receivers,
// with a frontier and a rotation: `grant` refuses it as it does a live one, and `set_role` makes it.
// At its old role or above, `grant` renews it. Whatever ended, the holder has the role afterwards.
#[test]
fn a_role_below_an_ended_grant_takes_set_role() {
    for role in [Role::Write, Role::Admin] {
        let mut w = World::new();
        let (alice, bob, g) = alice_bob(&mut w, role);
        let b = bob.me();
        let until = osis::Time(alice.now().unwrap().0 + 1000);
        alice.grant(g, b, role, osis::GrantOpts { until: Some(until), may_grant: None }).unwrap();
        w.run();
        w.advance(2000);
        assert!(!alice.grants(g).unwrap().contains_key(&b), "ended");
        let before = alice.engine(|e| e.commit_ids().len());
        let r = alice.grant(g, b, Role::Read, Default::default());
        assert!(matches!(&r, Err(Error::Invalid(m)) if m.contains("set_role")), "{r:?}");
        assert_eq!(alice.engine(|e| e.commit_ids().len()), before, "nothing written");
        alice.set_role(g, b, Some(Role::Read), skip_sync()).unwrap();
        w.run();
        assert_eq!(alice.grants(g).unwrap()[&b].role, Role::Read);
        assert_eq!(bob.role_on(g).unwrap(), Some(Role::Read));
        // ended once more: renewed at its role
        alice.grant(g, b, Role::Read, osis::GrantOpts { until: Some(osis::Time(alice.now().unwrap().0 + 1000)), may_grant: None }).unwrap();
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
    let carol = w.account(3, &[host]);
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

// notes/api.md Sharing (`leave`): a link joiner's leave ends its join of the link, in one call.
// spec: none (API surface, notes/api.md)
#[test]
fn leave_ends_a_link_join() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    w.run();
    let g = group(&alice);
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    w.run();
    w.until(bob.redeem(&link), 1000, 30).unwrap();
    w.run();
    assert!(bob.role_on(g).unwrap().is_some());
    bob.leave(bob.me(), g).unwrap();
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
    alice.grant(t, gs[1], Role::Write, osis::GrantOpts { until: Some(soon), may_grant: None }).unwrap();
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

// notes/api.md Sharing (`holders`), spec/permissions.md §2, §7: one entry per grant that makes an
// actor a holder: direct and through a link both, the role the least along the way; `holders` of
// the link's actor answers who holds through it. spec/permissions.md §7 (Redeem): an honest link
// works for a target this node already knows, K's grant reaching it by K's label; a redeemer who
// still holds the role it had gets the link's on top.
#[test]
fn holders_lists_every_grant_and_who_holds_through_a_link() {
    let mut w = World::new();
    // a reader raised by a write link: a way of its own (a link to what he reaches at its role joins nothing)
    let (alice, bob, g) = alice_bob(&mut w, Role::Read);
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(bob.role_on(g).unwrap(), Some(Role::Read));
    assert_eq!(w.until(bob.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    assert_eq!(bob.role_on(g).unwrap(), Some(Role::Write));
    let k = alice.links_of(g).unwrap()[0].id.actor();
    let hs = alice.holders(g).unwrap();
    let ways: Vec<&osis::Holder> = hs.iter().filter(|h| h.actor == bob.me()).collect();
    assert_eq!(ways.iter().map(|h| (h.role, h.through.clone())).collect::<Vec<_>>(), vec![(Role::Read, vec![]), (Role::Write, vec![k])]);
    assert!(alice.holders(k).unwrap().iter().any(|h| h.actor == bob.me() && h.through.is_empty()));
    // nearest first
    let depth: Vec<usize> = hs.iter().map(|h| h.through.len()).collect();
    assert!(depth.windows(2).all(|d| d[0] <= d[1]), "{depth:?}");
    // a removal goes down both
    alice.set_role(g, bob.me(), None, skip_sync()).unwrap();
    assert!(!alice.holders(g).unwrap().iter().any(|h| h.actor == bob.me()));
}

// spec/permissions.md §5.1 step 4, notes/api.md Sharing (`grant`): a holder that left, or whose
// grant ended and was finalized, keeps what it wrote; an explicit write below the role it lost
// audits it, so `grant` carries the frontier of what the granter received, as `set_role` does,
// and at the old role or above nothing is in question.
#[test]
fn a_role_below_one_lost_keeps_what_the_holder_wrote_spec_permissions_5_1() {
    for ended in [false, true] {
        let mut w = World::new();
        let (alice, bob, g) = alice_bob(&mut w, Role::Write);
        let b = bob.me();
        if ended {
            alice.grant(g, b, Role::Write, osis::GrantOpts { until: Some(osis::Time(alice.now().unwrap().0 + 5000)), may_grant: None }).unwrap();
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
        alice.grant(g, b, Role::Read, Default::default()).unwrap();
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
    alice.grant(g, carol.me(), Role::Read, osis::GrantOpts { may_grant: Some(Role::Read), ..Default::default() }).unwrap();
    w.run();
    let dan = w.account(3, &[0]);
    w.run();
    let card = dan.contact_card().unwrap();
    w.run();
    let d = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    w.until(carol.import_contact(&card), 1000, 10).unwrap();
    alice.grant(g, d, Role::Write, osis::GrantOpts { until: Some(osis::Time(alice.now().unwrap().0 + 1000)), may_grant: None }).unwrap();
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

// notes/arbitrary-values.md: a wait has no deadline however far the clock runs; `set_role` waits for nothing (spec/permissions.md §5.3)
#[test]
fn waits_have_no_deadline_and_set_role_does_not_wait() {
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
    alice.set_role(g, bob.me(), Some(Role::Read), SetRoleOpts::default()).unwrap();
    assert_eq!(alice.grants(g).unwrap()[&bob.me()].role, Role::Read);
}

// spec/permissions.md §5.3, notes/api.md set_role: `set_role` removes every way in at once: a holder granted and joined by a link, offline
#[test]
fn set_role_removes_every_way_in() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Write);
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    w.run();
    w.until(bob.redeem(&link), 1000, 30).unwrap();
    w.run();
    w.set_online(&alice, false);
    alice.set_role(g, bob.me(), None, SetRoleOpts::default()).unwrap();
    assert!(!alice.holders(g).unwrap().iter().any(|h| h.actor == bob.me()));
}

// spec/permissions.md §3 (a self-removal carries no rotation), spec/crypto.md §4 (Seal: a holder
// actor at a blocked keyset is left out): Alice's team K reads her doc G; Dave reads K and writes
// G. With Alice offline, Bob leaves K and Dave writes to G, leaving K out (K's epochs miss Bob's
// departure and Dave may not rotate K): Carol, of K, does not read it. Alice comes back and
// writes nothing, yet her node rotates K in its next pass (every pass rotates what is due first)
// and re-seals K to G: Carol reads Dave's write; Bob never does.
#[test]
fn team_reads_again_after_a_member_left_spec_permissions_3() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    let carol = w.account(3, &[host]);
    let dave = w.account(4, &[host]);
    w.run();
    let mut ids = Vec::new();
    for p in [&bob, &carol, &dave] {
        let card = p.contact_card().unwrap();
        w.run();
        ids.push(w.until(alice.import_contact(&card), 1000, 10).unwrap());
    }
    let k = group(&alice);
    let g = group(&alice);
    for id in &ids {
        alice.grant(k, *id, Role::Read, Default::default()).unwrap();
    }
    alice.grant(g, ids[2], Role::Write, Default::default()).unwrap();
    alice.grant(g, k, Role::Read, Default::default()).unwrap();
    w.run();
    let before = item(&alice, g, g, "before");
    w.run();
    assert_eq!(x(&carol, before), Some(s("before")));
    let k_was = alice.engine(|e| e.epochs(&k).unwrap().read.newest().unwrap());
    let g_was = dave.engine(|e| e.epochs(&g).unwrap().read.newest().unwrap());
    w.set_online(&alice, false);
    bob.leave(bob.me(), k).unwrap();
    w.run();
    let v = item(&dave, g, g, "after bob left");
    w.advance(70_000);
    w.run();
    assert_ne!(dave.engine(|e| e.epochs(&g).unwrap().read.newest().unwrap()), g_was, "Dave rotated G");
    assert_eq!(x(&carol, v), None, "K left out of G meanwhile");
    assert_eq!(x(&bob, v), None);
    w.set_online(&alice, true);
    for _ in 0..3 {
        w.advance(70_000);
        w.run();
    }
    assert_ne!(alice.engine(|e| e.epochs(&k).unwrap().read.newest().unwrap()), k_was, "K rotated with nothing written under it");
    assert_eq!(x(&carol, v), Some(s("after bob left")), "Carol reads G again through K");
    assert_eq!(x(&bob, v), None, "Bob does not");
}

// spec/permissions.md §5.3, §5.1: Bob writes while Alice is away; back, she removes him at once:
// his write, received by no writer, is undone everywhere. Synced first (`wait_synced`, the
// documented way to keep more), his write is in her frontier and stays. Likewise with a second way
// in, a write link he joined by: neither way alone puts his writes on G in question, both together do.
#[test]
fn set_role_keeps_what_was_synced_first_spec_permissions_5_3() {
    for (now, joined) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut w = World::new();
        // joined: Bob, a reader, joins by a write link, then is granted write as well (a link
        // to what he already reaches at its role joins nothing)
        let (alice, bob, g) = alice_bob(&mut w, if joined { Role::Read } else { Role::Write });
        if joined {
            let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
            w.run();
            w.until(bob.redeem(&link), 1000, 30).unwrap();
            w.run();
            alice.grant(g, bob.me(), Role::Write, Default::default()).unwrap();
            w.run();
            assert_eq!(alice.holders(g).unwrap().iter().filter(|h| h.actor == bob.me()).count(), 2);
        }
        w.set_online(&alice, false);
        let t = item(&bob, g, g, "while alice was away");
        w.run();
        w.set_online(&alice, true);
        assert_eq!(x(&alice, t), None, "not received yet");
        if !now {
            w.until(alice.wait_synced(SyncScope::Thing(g)), 1000, 30).unwrap();
        }
        alice.set_role(g, bob.me(), None, SetRoleOpts::default()).unwrap();
        w.run();
        w.advance(70_000);
        w.run();
        assert!(!alice.holders(g).unwrap().iter().any(|h| h.actor == bob.me()));
        assert_eq!(x(&alice, t), (!now).then(|| s("while alice was away")), "now {now} joined {joined}");
    }
}

// spec/crypto.md §7 (a writer lists the thing's delete keys), notes/api.md Rights: a role whose
// delete keys are not here yet (no inbox hint, the thing's `keys.0` in a later batch: another node
// of the grantee's account, a group's grant learned from its certificate copy) reads as `Read`
// and a content write on it is `Permission`, until the keys come; then both say the role. An
// admin's grant fails meanwhile too (issues/admin-before-keys-error.md: not yet `Permission`).
#[test]
fn role_before_delete_keys_reads_as_read_spec_crypto_7() {
    for role in [Role::Write, Role::Admin] {
        let (alice, bob, carol, dave) = (db(1), db(2), db(3), db(4));
        deliver(&bob, &alice);
        deliver(&carol, &alice);
        deliver(&dave, &bob);
        let mut w = alice.write();
        let t = w.create().unwrap();
        w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&s("one")).unwrap();
        w.commit().unwrap();
        // the first holder gives `t` secrets of its own: its `keys.0` goes in that commit
        alice.grant(t, carol.me(), Role::Read, Default::default()).unwrap();
        alice.grant(t, bob.me(), role, Default::default()).unwrap();
        let keys = ak("keys.0");
        let (later, now): (Vec<_>, Vec<_>) = alice.engine(|e| {
            e.commit_ids().into_iter().map(|id| (e.header(&id).unwrap().aspects.iter().any(|a| a.tid == t && a.ak == keys), e.package(&id).unwrap().unwrap())).partition(|(k, _)| *k)
        });
        assert_eq!(later.len(), 1, "one commit carries t's keys.0");
        for (_, pk) in &now {
            bob.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
        }
        let write = |v: &str| {
            let mut w = bob.write();
            w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&s(v))?;
            w.commit().map(drop)
        };
        assert_eq!(bob.engine(|e| e.role_on(&t)), Some(role), "the grant is here");
        assert_eq!(bob.role_on(t).unwrap(), Some(Role::Read));
        assert!(matches!(write("two"), Err(Error::Permission { tid, needs: Role::Write }) if tid == t));
        let grant = || bob.grant(t, dave.me(), Role::Read, Default::default());
        if role == Role::Admin {
            assert!(grant().is_err());
        }
        for (_, pk) in &later {
            bob.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
        }
        assert_eq!(bob.role_on(t).unwrap(), Some(role));
        write("two").unwrap();
        if role == Role::Admin {
            grant().unwrap();
        }
    }
}

// spec/permissions.md §5.1 (Frontier): a grant lowering `may_grant` is a demotion of the holder's
// invite class and carries what the granter had received: the grants the holder made by it that
// the granter had received stay, at every node; one it had not received goes.
#[test]
fn lower_may_grant_keeps_received_grants_spec_permissions_5_1() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Read);
    let b = bob.me();
    alice.grant(g, b, Role::Read, osis::GrantOpts { may_grant: Some(Role::Read), ..Default::default() }).unwrap();
    w.run();
    let carol = w.account(3, &[0]);
    let dan = w.account(4, &[0]);
    w.run();
    let mut ids = Vec::new();
    for db in [&carol, &dan] {
        let card = db.contact_card().unwrap();
        w.run();
        ids.push(w.until(bob.import_contact(&card), 1000, 10).unwrap());
    }
    let (c, d) = (ids[0], ids[1]);
    w.run();
    bob.grant(g, c, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(alice.grants(g).unwrap()[&c].role, Role::Read);
    w.set_online(&alice, false);
    bob.grant(g, d, Role::Read, Default::default()).unwrap();
    w.run();
    assert!(!alice.grants(g).unwrap().contains_key(&d), "unseen");
    alice.grant(g, b, Role::Read, Default::default()).unwrap();
    w.set_online(&alice, true);
    w.run();
    w.advance(70_000);
    w.run();
    assert_eq!(alice.grants(g).unwrap()[&b].may_grant, None);
    for db in [&alice, &bob, &carol] {
        let gs = db.grants(g).unwrap();
        assert_eq!(gs.get(&c).map(|e| e.role), Some(Role::Read), "carol's grant stays");
        assert!(!gs.contains_key(&d), "dan's grant, unseen, goes");
    }
    assert_eq!(carol.role_on(g).unwrap(), Some(Role::Read));
}

/// Who holds `g` as `db` sees it: (actor, kind, role) of the ways with this `through`.
fn ways(db: &Osis, g: Tid, through: &[Tid]) -> Vec<(Tid, HolderKind, Role)> {
    db.holders(g).unwrap().into_iter().filter(|h| h.through == through).map(|h| (h.actor, h.kind, h.role)).collect()
}

// spec/permissions.md §7, spec/wire.md §3: a link's actor reads as a link on another holder's node, before and after its single use; its joiner reads as an actor at the lesser role; an account reads as an actor, its nodes as keys
#[test]
fn holders_say_what_each_actor_is_spec_permissions_7() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Write);
    let carol = w.account(3, &[0]);
    let once = alice.make_link(g, Role::Write, osis::LinkOpts { single_use: true, ..Default::default() }).unwrap();
    let k = alice.links_of(g).unwrap()[0].id.actor();
    w.run();
    assert!(ways(&bob, g, &[]).contains(&(k, HolderKind::Link, Role::Write)), "a link, on a node that did not make it");
    assert!(ways(&bob, g, &[]).contains(&(alice.me(), HolderKind::Actor, Role::Admin)), "an account");
    assert!(ways(&bob, g, &[alice.me()]).is_empty(), "an account's nodes are its own");
    assert!(ways(&alice, g, &[k]).iter().any(|(_, kind, _)| *kind == HolderKind::Key), "the link's key, while it works");
    w.until(carol.redeem(&once), 1000, 30).unwrap();
    w.run();
    let t = item(&carol, g, g, "from a joiner");
    w.run();
    assert!(x(&bob, t).is_some());
    assert!(ways(&bob, g, &[]).contains(&(k, HolderKind::Link, Role::Write)), "still a link once spent: its key is gone");
    assert!(!ways(&bob, g, &[k]).iter().any(|(_, kind, _)| *kind == HolderKind::Key), "the key is gone");
    assert!(ways(&bob, g, &[k]).contains(&(carol.me(), HolderKind::Actor, Role::Write)), "the joiner");
    alice.set_role(g, k, Some(Role::Read), SetRoleOpts::default()).unwrap();
    w.run();
    assert!(ways(&bob, g, &[k]).contains(&(carol.me(), HolderKind::Actor, Role::Read)), "the lesser role along the way");
    // one who reaches g only through a team made after the link was spent still reads K's record
    let dave = w.account(4, &[0]);
    let card = dave.contact_card().unwrap();
    w.run();
    let d = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let team = group(&alice);
    alice.grant(team, d, Role::Write, Default::default()).unwrap();
    alice.grant(g, team, Role::Read, Default::default()).unwrap();
    w.run();
    assert!(ways(&dave, g, &[]).contains(&(k, HolderKind::Link, Role::Read)), "a link, through a team, after its single use");
}

// notes/api.md Sharing (`leave`): ends one's own grant and a link join, one call; a team the account holds through stays; through a team alone it is Invalid and nothing changes
// spec: none (API surface, notes/api.md)
#[test]
fn leave_ends_grant_and_link_join_not_a_team() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Read);
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    let k = alice.links_of(g).unwrap()[0].id.actor();
    w.run();
    w.until(bob.redeem(&link), 1000, 30).unwrap();
    // a team Bob is a member of, holding g
    let team = group(&alice);
    alice.grant(team, bob.me(), Role::Write, Default::default()).unwrap();
    alice.grant(g, team, Role::Write, Default::default()).unwrap();
    w.run();
    assert!(ways(&bob, g, &[k]).iter().any(|(a, ..)| *a == bob.me()), "joined the link");
    bob.leave(bob.me(), g).unwrap();
    w.run();
    assert!(!ways(&bob, g, &[]).iter().any(|(a, ..)| *a == bob.me()), "its own grant ended");
    assert!(!ways(&bob, g, &[k]).iter().any(|(a, ..)| *a == bob.me()), "its link join ended");
    assert!(ways(&bob, team, &[]).iter().any(|(a, ..)| *a == bob.me()), "the team is kept");
    assert_eq!(bob.role_on(g).unwrap(), Some(Role::Write), "and still reaches g through it");
    assert!(matches!(bob.leave(bob.me(), g), Err(Error::Invalid(_))), "the team alone: leaving it is what ends the role");
    assert!(ways(&bob, team, &[]).iter().any(|(a, ..)| *a == bob.me()));
    assert!(alice.grants(g).unwrap().contains_key(&team));
}

// notes/api.md Sharing (`leave`): a link's maker gives up its admin of K with the rest, so no way in is left; the link keeps working, and an admin of the target ending K ends it
// spec: none (API surface, notes/api.md)
#[test]
fn leave_of_a_links_maker_gives_up_the_link() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Admin);
    let carol = w.account(3, &[0]);
    let link = alice.make_link(g, Role::Write, Default::default()).unwrap();
    let id = alice.links_of(g).unwrap()[0].id;
    let k = id.actor();
    w.run();
    alice.leave(alice.me(), g).unwrap();
    w.run();
    assert_eq!(alice.role_on(g).unwrap(), None, "no way in is left, K's included");
    w.until(carol.redeem(&link), 1000, 30).unwrap();
    w.run();
    assert_eq!(carol.role_on(g).unwrap(), Some(Role::Write), "a leave ends no link");
    assert!(matches!(alice.revoke_link(id), Err(Error::Permission { .. })), "not the leaver's to end: told so");
    bob.set_role(g, k, None, SetRoleOpts::default()).unwrap();
    w.run();
    assert!(!bob.grants(g).unwrap().contains_key(&k), "an admin of the target can end it");
}

// notes/api.md Sharing (`leave`): every refusal comes before anything is written: a group's leave that the target forbids leaves its link join too
// spec: none (API surface, notes/api.md)
#[test]
fn leave_refused_on_one_way_writes_nothing() {
    let mut w = World::new();
    let (alice, bob, g) = alice_bob(&mut w, Role::Admin);
    let team = group(&alice);
    alice.grant(team, bob.me(), Role::Admin, Default::default()).unwrap();
    alice.grant(g, team, Role::Write, Default::default()).unwrap();
    // a K that sorts before g, whose removal an unchecked loop would write first
    let k = (0..64).find_map(|_| {
        alice.make_link(g, Role::Write, Default::default()).unwrap();
        alice.links_of(g).unwrap().iter().map(|l| l.id.actor()).find(|k| *k < g)
    }).unwrap();
    alice.grant(k, team, Role::Read, Default::default()).unwrap();
    w.run();
    // bob is an admin of g by another way: removing the team's grant on g is set_role's
    assert!(matches!(bob.leave(team, g), Err(Error::Invalid(_))));
    w.run();
    assert!(alice.grants(k).unwrap().contains_key(&team), "the join of K stays");
    assert!(alice.grants(g).unwrap().contains_key(&team));
}

// spec/permissions.md §7 (Redeem: the redeemer keeps the link key until its join is at a
// source): Bob redeems Alice's direct link with no host between them; their connection drops
// right after Bob writes his join and before Alice has it. The link key is what admits him at
// her node until she holds the join, so the next connection is admitted and the join gets there.
#[test]
fn redeem_survives_a_drop_before_the_join_arrives_spec_permissions_7() {
    let mut w = World::new();
    let relay = w.add_relay(None);
    let alice = w.account(1, &[]);
    let bob = w.account(2, &[]);
    w.place(&alice, &[], osis_sim::reach::Uplink::Public, &[relay]);
    w.place(&bob, &[], osis_sim::reach::Uplink::Public, &[relay]);
    w.run();
    let g = group(&alice);
    let link = alice.make_link(g, Role::Write, osis::LinkOpts { direct: true, ..Default::default() }).unwrap();
    let k = osis_label::ShareLink::from_text(&link.to_string()).unwrap().k;
    w.run();
    let f = bob.redeem(&link);
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let b = bob.me();
    let joined = |db: &Osis| db.engine(|e| e.roster(&k).contains_key(&b));
    // step until Bob's redeem writes the join, then cut the connection before it is sent
    for _ in 0..10_000 {
        assert!(std::future::Future::poll(f.as_mut(), &mut cx).is_pending());
        if joined(&bob) {
            break;
        }
        if !w.step(None) {
            w.advance(1000);
        }
    }
    assert!(joined(&bob) && !joined(&alice), "the join written, not at Alice");
    w.set_peer_reachable(&alice, &bob, false);
    w.run();
    w.set_peer_reachable(&alice, &bob, true);
    assert_eq!(w.try_until(f, 1000, 120).map(Result::unwrap), Some(g), "redeemed once a connection is back");
    assert!(joined(&alice), "the join reached Alice");
    let t = item(&bob, g, g, "from bob");
    w.run();
    assert_eq!(x(&alice, t), Some(s("from bob")));
}

/// The keyset (n, nonce) `db`'s newest read epoch of `a` boxes holder actor `h` at, if any.
fn sealed_keyset(db: &Osis, a: Tid, h: Tid) -> Option<(u64, [u8; 32])> {
    use osis::internals::core_types as ct;
    db.engine(|e| {
        let newest = e.epochs(&a)?.read.newest()?;
        let s = e.get_typed(&a, &ct::SECRETS).unwrap()?;
        s.boxes.iter().find(|(k, _)| k.holder == h && k.role == Role::Read && (k.epoch.n, k.epoch.nonce) == (newest.n(), *newest.nonce())).map(|(_, b)| match b {
            ct::SecretBox::Sealed(x) => x.keyset.as_ref().map(|k| (k.n, k.nonce)),
            ct::SecretBox::Symmetric(x) => Some((x.epoch.n, x.epoch.nonce)),
        })?
    })
}

/// The read epochs (n, nonce) of `a` that `db` holds the secret of.
fn held_read(db: &Osis, a: Tid) -> Vec<(u64, [u8; 32])> {
    db.engine(|e| e.epochs(&a).map(|x| x.read.held().map(|(ep, _)| (ep.n(), *ep.nonce())).collect()).unwrap_or_default())
}

// spec/crypto.md §4 (Encrypting under: an epoch whose secret the node lacks is judged by order;
// Reported), spec/permissions.md §4 (a stranded report carries the holder's keys): team T (Alice
// its admin, Bob, Carol, Dave) reads Carol's doc X. Carol leaves T and drops its secrets. With
// Alice away, Dave leaves T (no rotation) and Carol hears of it: T's keyset was made before Dave
// left, so it cannot cover him, and Carol's next write to X leaves T out. Gone from T, Carol does
// not follow it; once Alice rotates T, Bob is stranded on X and his report carries T's new keys:
// Carol re-seals T there. Bob reads everything Carol wrote; X is never sealed to T at a keyset
// Dave held. Without the order rule Dave's keyset is sealed to; without the keys T stays out.
#[test]
fn team_left_out_reads_again_by_its_stranded_report_spec_crypto_4() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    let carol = w.account(3, &[host]);
    let dave = w.account(4, &[host]);
    w.run();
    let mut ids = Vec::new();
    for p in [&bob, &carol, &dave] {
        let card = p.contact_card().unwrap();
        w.run();
        ids.push(w.until(alice.import_contact(&card), 1000, 10).unwrap());
    }
    let t = group(&alice);
    for id in &ids {
        alice.grant(t, *id, Role::Read, Default::default()).unwrap();
    }
    w.run();
    let x_ = group(&carol);
    carol.grant(x_, t, Role::Read, Default::default()).unwrap();
    w.run();
    carol.leave(carol.me(), t).unwrap();
    for _ in 0..3 {
        w.advance(70_000);
        w.run();
    }
    assert!(held_read(&carol, t).is_empty(), "Carol dropped T's secrets");
    let before = item(&carol, x_, x_, "before");
    w.run();
    assert_eq!(x(&bob, before), Some(s("before")));
    let dave_held = held_read(&dave, t);
    let not_daves = |db: &Osis| sealed_keyset(db, x_, t).is_none_or(|k| !dave_held.contains(&k));
    w.set_online(&alice, false);
    dave.leave(dave.me(), t).unwrap();
    w.run();
    let out = item(&carol, x_, x_, "after dave left");
    w.run();
    assert!(not_daves(&carol), "X sealed to T at a keyset Dave held");
    assert!(carol.engine(|e| !e.departures(&t).unwrap().is_empty()), "Carol knows Dave left");
    assert_eq!(x(&bob, out), None, "T left out of X");
    w.set_online(&alice, true);
    for _ in 0..4 {
        w.advance(70_000);
        w.run();
    }
    let after = item(&carol, x_, x_, "after T rotated");
    for _ in 0..2 {
        w.advance(70_000);
        w.run();
    }
    assert!(sealed_keyset(&carol, x_, t).is_some() && not_daves(&carol), "T sealed again, at a keyset Dave never held");
    assert_eq!(x(&bob, out), Some(s("after dave left")));
    assert_eq!(x(&bob, after), Some(s("after T rotated")));
    assert_eq!(x(&dave, after), None);
}

// spec/crypto.md §4 (Seal: a keyset with a stale box is skipped; Reported), spec/permissions.md
// §4 (a stranded report carries the holder's keys): Alice, G's one admin, holds none of team A's
// secrets (she left A); A (Bob its admin) holds team M (Carol, Dave). Carol removes Dave from M
// while Bob is away, and M's new keyset reaches Alice under G's labels, so A's box to M is stale
// there: removing Erin from G, Alice leaves A out. Bob comes back and rotates A; A's members,
// left out, hold no current epoch of G to place A's new keyset under, so only their stranded
// report brings it to Alice, who re-seals A. Carol reads what Alice wrote meanwhile and after.
#[test]
fn team_left_out_by_a_sealer_reading_none_of_it_reads_again_spec_crypto_4() {
    let mut w = World::new();
    let host = w.add_host();
    let [alice, bob, carol, dave, erin] = [1, 2, 3, 4, 5].map(|i| w.account(i, &[host]));
    w.run();
    let card = |w: &mut World, from: &Osis, to: &Osis| {
        let c = from.contact_card().unwrap();
        w.run();
        w.until(to.import_contact(&c), 1000, 10).unwrap()
    };
    let alice_at_bob = card(&mut w, &alice, &bob);
    let bob_at_carol = card(&mut w, &bob, &carol);
    let dave_at_carol = card(&mut w, &dave, &carol);
    let erin_at_alice = card(&mut w, &erin, &alice);
    let m = group(&carol);
    carol.grant(m, bob_at_carol, Role::Read, Default::default()).unwrap();
    carol.grant(m, dave_at_carol, Role::Read, Default::default()).unwrap();
    w.run();
    let a = group(&bob);
    bob.grant(a, alice_at_bob, Role::Read, Default::default()).unwrap();
    bob.grant(a, m, Role::Read, Default::default()).unwrap();
    w.run();
    let g = group(&alice);
    alice.grant(g, a, Role::Read, Default::default()).unwrap();
    alice.grant(g, erin_at_alice, Role::Read, Default::default()).unwrap();
    w.run();
    alice.leave(alice.me(), a).unwrap();
    let settle = |w: &mut World, rounds: usize| {
        for _ in 0..rounds {
            w.advance(70_000);
            w.run();
        }
    };
    settle(&mut w, 3);
    assert!(held_read(&alice, a).is_empty(), "Alice dropped A's secrets");
    let before = item(&alice, g, g, "before");
    w.run();
    assert_eq!(x(&carol, before), Some(s("before")));
    w.set_online(&bob, false);
    carol.set_role(m, dave_at_carol, None, Default::default()).unwrap();
    settle(&mut w, 3);
    alice.set_role(g, erin_at_alice, None, Default::default()).unwrap();
    settle(&mut w, 3);
    let mid = item(&alice, g, g, "mid");
    w.run();
    assert_eq!(sealed_keyset(&alice, g, a), None, "A left out of G");
    assert_eq!(x(&carol, mid), None);
    w.set_online(&bob, true);
    settle(&mut w, 6);
    let after = item(&alice, g, g, "after");
    settle(&mut w, 2);
    assert!(sealed_keyset(&alice, g, a).is_some(), "A sealed again");
    assert_eq!(x(&carol, mid), Some(s("mid")));
    assert_eq!(x(&carol, after), Some(s("after")));
    assert_eq!(x(&dave, after), None);
}

/// Bob's two nodes joined Alice's group `g` by her link: (laptop, phone, g, K).
fn joined_twice(w: &mut World) -> (Osis, Osis, Osis, Tid, Tid) {
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let laptop = w.account(2, &[host]);
    let join = osis::internals::pair(w.cfg(3, &[]), &laptop.pair_offer().unwrap()).unwrap();
    let (_, reply) = laptop.pair_accept(join.request()).unwrap();
    let phone = join.finish(&reply).unwrap();
    let g = group(&alice);
    let link = alice.make_link(g, Role::Read, Default::default()).unwrap();
    let k = alice.links_of(g).unwrap()[0].id.actor();
    w.run();
    assert_eq!(w.until(laptop.redeem(&link), 1000, 30).unwrap(), g);
    w.run();
    assert_eq!(phone.role_on(g).unwrap(), Some(Role::Read));
    (alice, laptop, phone, g, k)
}

/// Bob's account no longer holds K, wherever it is read, and his nodes reported no failed leave.
fn left_k(w: &mut World, alice: &Osis, bob: &[&Osis], g: Tid, k: Tid) {
    let me = bob[0].me();
    assert!(!alice.grants(k).unwrap().contains_key(&me), "the joiner left K");
    for b in bob {
        assert_eq!(b.role_on(g).unwrap(), None);
        assert!(!b.grants(k).map(|x| x.contains_key(&me)).unwrap_or(false), "left K on every node");
        let d = w.diagnostics(b);
        assert!(d.iter().all(|d| !d.contains("leaving ended link")), "{d:?}");
    }
}

// spec/permissions.md §7 (the link has ended: a joiner leaves K): K taken off the target, a
// joiner leaves K, with two nodes seeing it at once and one of them offline when it happened
#[test]
fn a_joiner_leaves_k_once_k_left_the_target_spec_permissions_7() {
    let mut w = World::new();
    let (alice, laptop, phone, g, k) = joined_twice(&mut w);
    w.set_online(&phone, false);
    alice.set_role(g, k, None, SetRoleOpts::default()).unwrap();
    w.run();
    w.set_online(&phone, true);
    w.advance(60_000);
    left_k(&mut w, &alice, &[&laptop, &phone], g, k);
}

// spec/permissions.md §7 (the link has ended: K's grant on the target past `until`): K's grant
// ending while every node of the joiner is offline: back online, the joiner leaves K
#[test]
fn a_joiner_leaves_k_once_ks_grant_expired_spec_permissions_7() {
    let mut w = World::new();
    let (alice, laptop, phone, g, k) = joined_twice(&mut w);
    let hour = 3_600_000;
    alice.grant(g, k, Role::Read, osis::GrantOpts { until: Some(osis::Time(w.now() + hour)), ..Default::default() }).unwrap();
    w.run();
    assert_eq!(laptop.role_on(g).unwrap(), Some(Role::Read));
    w.set_online(&laptop, false);
    w.set_online(&phone, false);
    w.advance(2 * hour);
    w.set_online(&laptop, true);
    w.set_online(&phone, true);
    w.advance(60_000);
    left_k(&mut w, &alice, &[&laptop, &phone], g, k);
}
