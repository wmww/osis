//! Sharing and sync through blind servers in process (notes/api.md Sharing and membership,
//! Sync configuration and status), no tokio: see common/world.rs.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis::internals::Internals as _;
use crate::common;
use common::world::World;
use common::*;
use crate::common::CreateIn;
use osis::{Demotion, Lower, Osis, Role, SyncScope, SyncState, Tid, Value};
use std::time::Duration;

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

/// A thing in `g` (owned by `owner`) with `/t/x` = `v`.
fn item(db: &Osis, owner: Tid, g: Tid, v: &str) -> Tid {
    let mut w = db.write();
    let t = w.create_in(owner, &[g]).unwrap();
    w.at(t, ak("/t/x")).set(&s(v)).unwrap();
    w.commit().unwrap();
    t
}

fn x(db: &Osis, t: Tid) -> Option<Value> {
    db.get(t, ak("/t/x")).unwrap()
}

// notes/api.md Handle (create), Sync status; spec/sync.md §2 (home label): a new person's home
// label registers at its server; status turns Synced and wait_synced resolves after a write.
#[test]
fn create_syncs_home_spec_sync_2() {
    let mut w = World::new();
    let sv = w.add_server();
    let (db, _card) = w.person(1, &[sv]);
    w.run();
    let st = db.status().unwrap();
    assert_eq!(st.groups.get(&db.home()).map(|g| g.state), Some(SyncState::Synced), "{st:?}");
    assert_eq!(st.connected, 1);
    item(&db, db.me(), db.home(), "hello");
    assert_ne!(db.status().unwrap().groups.get(&db.home()).map(|g| g.state), Some(SyncState::Synced), "a local commit is not at the server yet");
    w.until(db.wait_synced(SyncScope::All, Duration::from_secs(60)), 1000, 10).unwrap();
}

// notes/api.md Sharing (devices), spec/sync.md §2 (pairing: the only way a node receives a
// grant): the app carries the request and the reply; the new device becomes an admin of the
// person, reads the home group and its writes reach the first device.
#[test]
fn pairing_spec_permissions_1() {
    let mut w = World::new();
    let sv = w.add_server();
    let (da, _) = w.person(1, &[sv]);
    w.run();
    let t = item(&da, da.me(), da.home(), "before pairing");
    for i in 0..10 {
        item(&da, da.me(), da.home(), &format!("{i}{}", "x".repeat(4000)));
    }
    let offer = da.pair_offer().unwrap();
    let join = Osis::pair(w.cfg(2, &[]), &offer).unwrap();
    let req: osis::PairRequest = join.request().to_string().parse().unwrap();
    let (node, reply) = da.pair_accept(&req).unwrap();
    assert_eq!(node, join.node());
    assert!(reply.to_string().len() < 40_000, "certificates and /label only, no content: {}", reply.to_string().len());
    assert!(da.pair_accept(&req).is_err(), "an offer is used once");
    let db = join.finish(&reply).unwrap();
    assert_eq!(db.me(), da.me());
    w.run();
    assert_eq!(x(&db, t), Some(s("before pairing")));
    let u = item(&db, db.me(), db.home(), "from the new device");
    w.run();
    assert_eq!(x(&da, u), Some(s("from the new device")));
    let devs: Vec<Tid> = da.devices().unwrap().into_iter().map(|d| d.node).collect();
    assert!(devs.contains(&da.node()) && devs.contains(&db.node()), "{devs:?}");
    // a lost device, removed without waiting (spec/permissions.md §5.3 `Skip`)
    let skip = osis::Demotion { sync: osis::WaitForSync::Skip, backdate: None };
    w.until(da.remove_device(db.node(), skip), 1000, 5).unwrap();
    assert!(!da.devices().unwrap().iter().any(|d| d.node == db.node()));
    let after = item(&da, da.me(), da.home(), "after the removal");
    w.run();
    assert_eq!(x(&db, after), None, "the removed device reads nothing new");
}

// spec/permissions.md §9 (recovery card), notes/api.md Handle (restore): a fresh device with
// the card claims the home label by the recovery key, downloads it and becomes an admin.
#[test]
fn restore_from_card_spec_permissions_9() {
    let mut w = World::new();
    let sv = w.add_server();
    let (da, card) = w.person(1, &[sv]);
    let t = item(&da, da.me(), da.home(), "kept by the server");
    w.run();
    let card: osis::RecoveryCard = card.to_string().parse().unwrap();
    w.advance(1000);
    let dc = w.until(Osis::restore(w.cfg(4, &[]), &card), 1000, 10).unwrap();
    w.run();
    assert_eq!(dc.me(), da.me());
    assert_eq!(x(&dc, t), Some(s("kept by the server")));
    assert_eq!(dc.role_on(dc.me()), Some(Role::Admin));
    let u = item(&dc, dc.me(), dc.home(), "after restore");
    w.run();
    assert_eq!(x(&da, u), Some(s("after restore")));
}

// notes/api.md Reads (knows), Writes (delete): Bob, with write on one of Alice's groups and read
// on another listing the same thing, deletes it: its placement in the writable group goes, the
// read-only group keeps listing it (the delete does not fail), and Alice reads it as deleted.
// spec: none (API surface, notes/api.md)
#[test]
fn delete_reaches_other_node_spec_api_writes() {
    let mut w = World::new();
    let sv = w.add_server();
    let (alice, _) = w.person(1, &[sv]);
    let (bob, _) = w.person(2, &[sv]);
    w.run();
    let g = group(&alice);
    let ro = group(&alice);
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    alice.grant(g, b, Role::Write, Default::default()).unwrap();
    alice.grant(ro, b, Role::Read, Default::default()).unwrap();
    let t = item(&alice, g, g, "doomed");
    alice.write_with(|wr| wr.place(t, ro)).unwrap();
    w.run();
    assert!(bob.knows(t));
    assert_eq!(bob.groups_of(t).item_of.len(), 2);
    bob.write_with(|wr| wr.delete(t)).unwrap();
    assert!(!bob.knows(t));
    w.run();
    assert!(!alice.knows(t) && alice.created(t).is_some());
    assert_eq!(x(&alice, t), None);
    assert_eq!(alice.groups_of(t).item_of, vec![ro]);
}

/// A group owned by `db`'s person, synced on its servers.
fn group(db: &Osis) -> Tid {
    let mut w = db.write();
    let g = w.create_in(db.me(), &[db.home()]).unwrap();
    w.make_group(g).unwrap();
    w.commit().unwrap();
    db.sync(g, &[]).unwrap();
    g
}

// spec/sync.md §3 (contact card, inbox), spec/permissions.md §2 (grant): Alice imports Bob's
// contact card and grants him write on a synced group; the grant reaches Bob's device through
// his inbox; both read and write things the group owns (entitlement: things owned elsewhere
// stay unshared, notes/sync.md).
#[test]
fn grant_by_inbox_spec_sync_3() {
    let mut w = World::new();
    let sv = w.add_server();
    let (alice, _) = w.person(1, &[sv]);
    let (bob, _) = w.person(2, &[sv]);
    w.run();
    let g = group(&alice);
    let card: osis::ContactCard = bob.contact_card().unwrap().to_string().parse().unwrap();
    assert_eq!(bob.contact_card().unwrap(), card, "made once");
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    assert_eq!(b, bob.me());
    alice.grant(g, b, Role::Write, Default::default()).unwrap();
    let t = item(&alice, g, g, "for bob");
    w.run();
    assert_eq!(x(&bob, t), Some(s("for bob")));
    assert_eq!(bob.role_on(g), Some(Role::Write));
    let u = item(&bob, g, g, "from bob");
    w.run();
    assert_eq!(x(&alice, u), Some(s("from bob")));
}

/// Alice and `n` other people on one server; each other person's card imported by Alice.
fn people(w: &mut World, n: usize) -> (Osis, Vec<Osis>, Vec<Tid>) {
    let sv = w.add_server();
    let (alice, _) = w.person(1, &[sv]);
    let others: Vec<Osis> = (0..n).map(|i| w.person(2 + i as u64, &[sv]).0).collect();
    w.run();
    let mut ids = Vec::new();
    for o in &others {
        let card = o.contact_card().unwrap();
        w.run();
        ids.push(w.until(alice.import_contact(&card), 1000, 10).unwrap());
    }
    (alice, others, ids)
}

// spec/permissions.md §9 (links): Bob redeems a single-use write link to Alice's group and
// reads what was there before; his redemption removes the link key (the link's `flags`, spec/
// wire.md §10); Alice's device finalizes it when it sees that (K rotates), Bob stays a member and
// a second redeemer is refused (`Network` after `wait_timeout`).
#[test]
fn link_redeem_spec_permissions_9() {
    let mut w = World::new();
    let (alice, others, _) = people(&mut w, 1);
    let bob = &others[0];
    let g = group(&alice);
    let before = item(&alice, g, g, "before the link");
    let link = alice.make_link(g, Role::Write, osis::LinkOpts { until: None, single_use: true, direct: false }).unwrap();
    assert_eq!(alice.links(g).len(), 1);
    w.run();
    let link: osis::ShareLink = link.to_string().parse().unwrap();
    // a hinted label the joiner fails to open first is retried after `resync_ms`
    assert_eq!(w.until(bob.redeem(&link), 1000, 10).unwrap(), g);
    w.run();
    assert_eq!(x(bob, before), Some(s("before the link")));
    let u = item(bob, g, g, "from the joiner");
    w.run();
    assert_eq!(x(&alice, u), Some(s("from the joiner")));
    assert!(alice.links(g).is_empty(), "single use: L left K");
    assert!(alice.engine(|e| !e.held_links().unwrap().is_empty() && e.links_due().unwrap().is_empty()), "finalized on the redemption");
    let v = item(&alice, g, g, "after the link ended");
    w.run();
    assert_eq!(x(bob, v), Some(s("after the link ended")), "the joiner stays");
    let mut c = w.cfg(9, &[0]);
    c.wait_timeout = Duration::from_secs(5);
    let carol = Osis::create(c).unwrap().0;
    w.run();
    assert!(matches!(w.until(carol.redeem(&link), 1000, 10), Err(osis::Error::Network(_))), "used once");
    assert_eq!(carol.role_on(g), None);
    assert_eq!(carol.engine(|e| e.held_key_actors()), 0, "the link key is forgotten");
}

// spec/permissions.md §9, spec/sync.md §5: a used single-use link refuses a second redeemer
// at once and later (0, 10, 20 s after the first redemption settled): the sharer registers a
// step without L as soon as L's departure is covered, whoever rotated K.
#[test]
fn used_link_refused_at_once_spec_permissions_9() {
    let mut w = World::new();
    let (alice, others, _) = people(&mut w, 1);
    let bob = &others[0];
    let g = group(&alice);
    item(&alice, g, g, "before the link");
    let link = alice.make_link(g, Role::Write, osis::LinkOpts { until: None, single_use: true, direct: false }).unwrap();
    w.run();
    let link: osis::ShareLink = link.to_string().parse().unwrap();
    assert_eq!(w.until(bob.redeem(&link), 1000, 10).unwrap(), g);
    w.run();
    for (i, wait) in [0, 10_000, 10_000].into_iter().enumerate() {
        w.advance(wait);
        let mut c = w.cfg(20 + i as u64, &[0]);
        c.wait_timeout = Duration::from_secs(5);
        let carol = Osis::create(c).unwrap().0;
        w.run();
        assert!(matches!(w.until(carol.redeem(&link), 1000, 10), Err(osis::Error::Network(_))), "refused, attempt {i}");
        assert_eq!(carol.role_on(g), None);
    }
}

// spec/permissions.md §9, §5.1: with the sharer offline, a second redeemer of a used
// single-use link whose view still lists L (the first redemption not applied there: the
// joiner's rotation of K pends its chain) is not told it joined: refused, or admitted only
// once the first redemption is applied in its view (then its grant is void).
#[test]
fn used_link_with_sharer_offline_spec_permissions_9() {
    let mut w = World::new();
    let (alice, others, _) = people(&mut w, 1);
    let bob = &others[0];
    let g = group(&alice);
    item(&alice, g, g, "before the link");
    let link = alice.make_link(g, Role::Write, osis::LinkOpts { until: None, single_use: true, direct: false }).unwrap();
    w.run();
    let link: osis::ShareLink = link.to_string().parse().unwrap();
    w.set_online(&alice, false);
    assert_eq!(w.until(bob.redeem(&link), 1000, 10).unwrap(), g);
    item(bob, g, g, "from the joiner");
    w.run();
    let mut c = w.cfg(30, &[0]);
    c.wait_timeout = Duration::from_secs(5);
    let carol = Osis::create(c).unwrap().0;
    w.run();
    let r = w.until(carol.redeem(&link), 1000, 10);
    assert!(r.is_err(), "refused while the first redemption is not applied: {r:?}");
    assert_eq!(carol.role_on(g), None);
    w.set_online(&alice, true);
    w.advance(600_000);
    w.run();
    assert_eq!(carol.role_on(g), None, "still no role once the sharer is back");
}

/// Alice's synced group with a read link expiring in an hour, redeemed by Bob: (world, alice,
/// bob, group, K, L).
fn until_link(w: &mut World) -> (Osis, Osis, Tid, Tid, Tid) {
    let sv = w.add_server();
    let [alice, bob] = [1, 2].map(|i| w.person(i, &[sv]).0);
    w.run();
    let g = group(&alice);
    let until = osis::WallMs(w.now() + 3_600_000);
    let link = alice.make_link(g, Role::Read, osis::LinkOpts { until: Some(until), single_use: false, direct: false }).unwrap();
    w.run();
    assert_eq!(w.until(bob.redeem(&link), 1000, 10).unwrap(), g);
    w.run();
    let k = alice.links(g)[0].id;
    let l = alice.roster(k).into_keys().find(|m| alice.owner_of(*m).is_none()).unwrap();
    (alice, bob, g, k, l)
}

/// Whether `db` holds link (k, l) and has nothing of it left to finalize (L's edge on K is
/// gone by an explicit removal: it expired, so it is not alive).
fn finalized(db: &Osis, k: Tid, l: Tid) -> bool {
    db.engine(|e| e.held_links().unwrap().iter().any(|x| (x.k, x.l) == (k, l)) && e.links_due().unwrap().is_empty())
}

// spec/permissions.md §9 (link finalized): `until` finalized by a sharer device's removal of L; with Alice's
// device offline when the link expires, her other device (which holds the seed thing, not the
// link record) removes L at expiry; back online, Alice's device writes nothing more; Bob stays.
#[test]
fn until_link_finalized_by_other_device_spec_permissions_9() {
    let mut w = World::new();
    let (alice, bob, g, k, l) = until_link(&mut w);
    let join = Osis::pair(w.cfg(9, &[0]), &alice.pair_offer().unwrap()).unwrap();
    let (_, reply) = alice.pair_accept(join.request()).unwrap();
    let alice2 = join.finish(&reply).unwrap();
    w.run();
    assert!(alice2.engine(|e| e.held_links().unwrap().iter().any(|x| (x.k, x.l) == (k, l))), "the other device holds the seed thing");
    w.set_online(&alice, false);
    w.advance(3_600_000);
    w.run();
    assert!(finalized(&alice2, k, l), "finalized at expiry");
    assert!(!finalized(&alice, k, l), "offline: not yet here");
    // removals of L on K written by a database
    let removals = |db: &Osis| db.engine(|e| e.commit_ids().into_iter().filter(|c| e.header(c).is_some_and(|h| h.author == db.node() && h.frontier.is_some() && h.aspects.iter().any(|a| a.tid == k && a.ak.as_str() == "/members"))).count());
    assert_eq!(removals(&alice2), 1);
    w.set_online(&alice, true);
    w.advance(60_000);
    w.run();
    assert!(finalized(&alice, k, l), "the other device's removal arrived");
    assert_eq!(removals(&alice), 0, "and wrote no removal of its own");
    assert!(alice.roster(k).contains_key(&bob.me()) && bob.role_on(g).is_some(), "the joiner stays");
}

// spec/permissions.md §9 (link finalized): Alice's only device is offline when the link expires; it removes L
// once it is back and synced K's label; Bob stays.
#[test]
fn until_link_finalized_when_sharer_returns_spec_permissions_9() {
    let mut w = World::new();
    let (alice, bob, g, k, l) = until_link(&mut w);
    w.set_online(&alice, false);
    w.advance(2 * 3_600_000);
    assert!(!finalized(&alice, k, l), "waits for a complete pass of K's labels");
    w.set_online(&alice, true);
    w.advance(60_000);
    w.run();
    assert!(finalized(&alice, k, l));
    assert!(alice.roster(k).contains_key(&bob.me()) && bob.role_on(g).is_some(), "the joiner stays");
}

/// Alice's synced group with a multi-use read link redeemed by Bob and Carol: (world, alice,
/// bob, carol, group, link actor K, link key L).
fn joined_by_link() -> (World, Osis, Osis, Osis, Tid, Tid, Tid) {
    let mut w = World::new();
    let sv = w.add_server();
    let [alice, bob, carol] = [1, 2, 3].map(|i| w.person(i, &[sv]).0);
    w.run();
    let g = group(&alice);
    let link = alice.make_link(g, Role::Read, osis::LinkOpts::default()).unwrap();
    w.run();
    for o in [&bob, &carol] {
        assert_eq!(w.until(o.redeem(&link), 1000, 10).unwrap(), g);
        w.run();
    }
    let k = alice.links(g)[0].id;
    let l = alice.roster(k).into_keys().find(|m| alice.owner_of(*m).is_none()).unwrap();
    (w, alice, bob, carol, g, k, l)
}

// spec/permissions.md §9 (a joiner is revoked together with the link key), notes/api.md
// Sharing (`member_path`, `demote`): a link joiner reaches the target through K; removing it on
// the target removes it and L from K in one commit, so a failed pre-sync leaves both in place
// and a retry completes; a second removal writes nothing; a joiner's role cannot be lowered.
#[test]
fn demote_link_joiner_spec_permissions_9() {
    let (mut w, alice, bob, carol, g, k, l) = joined_by_link();
    assert_eq!(alice.member_path(g, bob.me()), vec![(g, k), (k, bob.me())]);
    // offline, the required pre-sync fails: nothing changed
    w.set_online(&alice, false);
    let r = w.until(alice.demote(g, bob.me(), Lower::Remove, Demotion::default()), 1000, 60);
    assert!(matches!(r, Err(osis::Error::Unsynced { .. })), "{r:?}");
    assert!(alice.roster(k).contains_key(&bob.me()) && alice.roster(k).contains_key(&l), "no half-removal");
    w.set_online(&alice, true);
    let skip = Demotion { sync: osis::WaitForSync::Skip, backdate: None };
    w.until(alice.demote(g, bob.me(), Lower::Remove, skip), 1000, 10).unwrap();
    let r = alice.roster(k);
    assert!(!r.contains_key(&bob.me()) && !r.contains_key(&l) && r.contains_key(&carol.me()));
    assert!(alice.member_path(g, bob.me()).is_empty());
    assert!(alice.links(g).is_empty(), "the link ends with its joiner");
    let commits = alice.engine(|e| e.commit_ids().len());
    w.until(alice.demote(g, bob.me(), Lower::Remove, skip), 1000, 10).unwrap();
    assert_eq!(alice.engine(|e| e.commit_ids().len()), commits, "nothing left to remove");
    assert!(matches!(w.until(alice.demote(g, carol.me(), Lower::To(Role::Read), skip), 1000, 10), Err(osis::Error::Invalid(_))));
}

// spec/permissions.md §9, notes/api.md Sharing (`demote`): after a joiner's removal the other
// joiner reads new content and the removed one does not; another device of the sharer, which
// holds no record of the link, refuses to demote a joiner instead of reporting success, and
// syncs the removal to rest (spec/permissions.md §3: it once rotated the target without end,
// since a late part of a joiner's redemption was judged without its `/members` part and the
// rotation of K that removal made never established there).
#[test]
fn demote_link_joiner_content_spec_permissions_9() {
    let (mut w, alice, bob, carol, g, _, _) = joined_by_link();
    let join = Osis::pair(w.cfg(9, &[0]), &alice.pair_offer().unwrap()).unwrap();
    let (_, reply) = alice.pair_accept(join.request()).unwrap();
    let alice2 = join.finish(&reply).unwrap();
    w.run();
    let skip = Demotion { sync: osis::WaitForSync::Skip, backdate: None };
    assert!(matches!(w.until(alice2.demote(g, carol.me(), Lower::Remove, skip), 1000, 10), Err(osis::Error::Invalid(_))));
    w.until(alice.demote(g, bob.me(), Lower::Remove, Demotion::default()), 1000, 20).unwrap();
    let after = item(&alice, g, g, "after bob left");
    w.run();
    assert_eq!(x(&carol, after), Some(s("after bob left")));
    assert_eq!(x(&bob, after), None);
    assert_eq!(x(&alice2, after), Some(s("after bob left")));
}

// spec/permissions.md §3 (removal with rotation), §5.3 (pre-sync), notes/api.md Sharing
// (demote): Alice removes Bob after the pre-sync; Carol keeps reading new content, Bob does
// not; Bob's write made before the removal stays.
// spec/crypto.md §4 (removed member)
#[test]
fn removal_rotates_spec_permissions_3() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 2);
    let (bob, carol) = (&others[0], &others[1]);
    let g = group(&alice);
    for id in &ids {
        alice.grant(g, *id, Role::Write, Default::default()).unwrap();
    }
    w.run();
    let by_bob = item(bob, g, g, "bob was here");
    w.run();
    w.until(alice.demote(g, ids[0], osis::Lower::Remove, osis::Demotion::default()), 1000, 10).unwrap();
    assert!(!alice.roster(g).contains_key(&ids[0]));
    let after = item(&alice, g, g, "after bob left");
    w.run();
    assert_eq!(x(carol, after), Some(s("after bob left")));
    assert_eq!(x(bob, after), None);
    assert_eq!(x(&alice, by_bob), Some(s("bob was here")));
    assert_eq!(x(carol, by_bob), Some(s("bob was here")));
}

// spec/permissions.md §5.1 (frontier received), §5.3 (receipts only), notes/sync.md
// Receipts-only reads: Alice's phone holds group G but none of its subgroup H (receipts-only).
// Bob writes in both; the phone removes him with the required pre-sync, which reads H's commit
// headers only. His edit in H, which the phone never held, is kept at Carol; nothing went under
// H's label from the phone.
#[test]
fn removal_from_partial_device_keeps_unheld_edits_spec_permissions_5_3() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 2);
    let (bob, carol) = (&others[0], &others[1]);
    let g = group(&alice);
    let h = {
        let mut wr = alice.write();
        let h = wr.create_in(g, &[]).unwrap();
        wr.make_group(h).unwrap();
        wr.commit().unwrap();
        h
    };
    alice.sync(h, &[]).unwrap();
    for id in &ids {
        alice.grant(g, *id, Role::Write, Default::default()).unwrap();
    }
    w.run();
    let join = Osis::pair(w.cfg(9, &[]), &alice.pair_offer().unwrap()).unwrap();
    let (_, reply) = alice.pair_accept(join.request()).unwrap();
    let phone = join.finish(&reply).unwrap();
    phone.sync_policy(h, osis::GroupPolicy { receipts_only: true, ..Default::default() });
    w.run();
    let in_g = item(bob, g, g, "bob in g");
    let in_h = item(bob, h, h, "bob in h");
    w.run();
    assert_eq!(x(&phone, in_g), Some(s("bob in g")));
    assert_eq!(x(&phone, in_h), None, "the phone holds nothing of H");
    assert_eq!(x(carol, in_h), Some(s("bob in h")));
    let label = alice.engine(|e| e.group_labels(&h).unwrap())[0].id;
    let log = |w: &World| osis_proto::store::LabelStore::log_head(w.servers[0].hub.store(), &label).unwrap();
    for db in [&alice, bob, carol] {
        w.set_online(db, false);
    }
    let before = log(&w);
    w.until(phone.demote(g, ids[0], Lower::Remove, Demotion::default()), 1000, 30).unwrap();
    w.run();
    assert_eq!(log(&w), before, "the phone placed nothing under H's label");
    // received by header only: by commit ID, never by counters (spec/permissions.md §5.1)
    let r = phone.engine(|e| e.receipt(&in_h, &ak("/t/x")).unwrap());
    assert!(r.nodes.is_empty() && r.commits.len() == 1, "{r:?}");
    for db in [&alice, bob, carol] {
        w.set_online(db, true);
    }
    // the dials wait for their retry time
    w.advance(10_000);
    w.run();
    assert!(!carol.roster(g).contains_key(&ids[0]));
    assert_eq!(x(carol, in_g), Some(s("bob in g")));
    assert_eq!(x(carol, in_h), Some(s("bob in h")), "his edit under H stays: the phone's frontier covers it");
}

// spec/permissions.md §5.3, notes/api.md Sync configuration and status: a group held for receipts only shows as such in
// the status, and `wait_synced` leaves it out.
#[test]
fn receipts_only_status_spec_permissions_5_3() {
    let mut w = World::new();
    let (alice, _, _) = people(&mut w, 1);
    let g = group(&alice);
    let h = {
        let mut wr = alice.write();
        let h = wr.create_in(g, &[]).unwrap();
        wr.make_group(h).unwrap();
        wr.commit().unwrap();
        h
    };
    alice.sync(h, &[]).unwrap();
    w.run();
    let join = Osis::pair(w.cfg(9, &[]), &alice.pair_offer().unwrap()).unwrap();
    let (_, reply) = alice.pair_accept(join.request()).unwrap();
    let phone = join.finish(&reply).unwrap();
    phone.sync_policy(h, osis::GroupPolicy { receipts_only: true, ..Default::default() });
    // one field changed from the policy as set keeps the others
    phone.sync_policy(h, osis::GroupPolicy { publish_reach: Some(false), ..phone.group_policy(h) });
    assert_eq!(phone.group_policy(h), osis::GroupPolicy { publish_reach: Some(false), receipts_only: true });
    w.run();
    let st = phone.status().unwrap();
    assert_eq!(st.groups.get(&h).map(|s| s.state), Some(SyncState::ReceiptsOnly), "{st:?}");
    assert_eq!(st.groups.get(&g).map(|s| s.state), Some(SyncState::Synced), "{st:?}");
    // nothing of H goes into a wait for it
    w.until(phone.wait_synced(SyncScope::All, Duration::from_secs(10)), 1000, 10).unwrap();
    assert!(w.until(phone.wait_synced(SyncScope::Group(h), Duration::from_secs(10)), 1000, 10).is_err(), "H is not synced here");
}

// spec/sync.md §5 (relay-only entries), notes/api.md Signals: a signal aspect set on a shared
// thing reaches another person's connected device through the server once; local callbacks fire
// too; nothing is held.
#[test]
fn remote_signal_spec_sync_5() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let bob = &others[0];
    let g = group(&alice);
    alice.grant(g, ids[0], Role::Write, Default::default()).unwrap();
    w.run();
    let ring = osis::Lifetimes::signal(ak("/t/typing"));
    let (tx, rx) = std::sync::mpsc::channel();
    let tx2 = tx.clone();
    let _a = alice.at(g, ring.clone()).on_change(move |_, c| tx.send(("alice", c)).unwrap()).unwrap();
    let _b = bob.at(g, ring.clone()).on_change(move |_, c| tx2.send(("bob", c)).unwrap()).unwrap();
    let _ = (recv(&rx), recv(&rx));
    bob.write_with(|wr| wr.at(g, ring.clone()).set(&Value::Int(1))).unwrap();
    w.run();
    let mut got = [recv(&rx), recv(&rx)];
    got.sort_by_key(|g| g.0);
    assert_eq!(got.iter().map(|(n, c)| (*n, c.value.clone())).collect::<Vec<_>>(), vec![("alice", Ok(Some(Value::Int(1)))), ("bob", Ok(Some(Value::Int(1))))]);
    assert!(matches!(got[0].1.source, osis::Source::Remote(i) if i.actor == bob.me() && i.node == bob.node()));
    assert!(matches!(got[1].1.source, osis::Source::Local(_)));
    alice.settle();
    assert!(rx.try_recv().is_err(), "once");
    assert_eq!(alice.get(g, ring).unwrap(), None);
}

// spec/commits.md §6 (expiry), notes/chat.md (disappearing messages): a message written with an
// expiry reaches the other member and is gone everywhere once it expires.
#[test]
fn disappearing_message_spec_commits_6() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let bob = &others[0];
    let g = group(&alice);
    alice.grant(g, ids[0], Role::Write, Default::default()).unwrap();
    w.run();
    let mut wr = alice.write();
    let m = wr.create_in(g, &[g]).unwrap();
    wr.at(m, ak("/t/x")).expires_in(Duration::from_secs(10)).set(&s("gone soon")).unwrap();
    wr.commit().unwrap();
    w.run();
    assert_eq!(x(bob, m), Some(s("gone soon")));
    w.advance(11_000);
    assert_eq!(x(&alice, m), None);
    assert_eq!(x(bob, m), None);
}

const TEXT_SCHEMA: &str = "schema 0x0123456789abcdef0123456789abcd01;\nrevision 1;\naspect /n/body: text;\n";

// notes/api.md Text editing sessions, spec/requirements.md (Generality: one commit per editing
// pause): two devices edit one text concurrently in sessions; each commit is one edit, the
// remote edit merges into the other buffer and both converge with both edits.
// spec/crdt.md §5.7
#[test]
fn text_sessions_merge_spec_crdt_5_7() {
    let mut w = World::new();
    let sv = w.add_server();
    let (da, _) = w.person(1, &[sv]);
    w.run();
    let join = Osis::pair(w.cfg(2, &[]), &da.pair_offer().unwrap()).unwrap();
    let (_, reply) = da.pair_accept(join.request()).unwrap();
    let db = join.finish(&reply).unwrap();
    for d in [&da, &db] {
        d.register_schema_source("t.osis", TEXT_SCHEMA).unwrap();
    }
    let body = da.key("/n/body").unwrap();
    let mut wr = da.write();
    let t = wr.create_in(da.me(), &[da.home()]).unwrap();
    wr.commit().unwrap();
    let sa = da.edit_text(t, body.clone(), osis::Path::root()).unwrap();
    sa.insert(0, "hello").unwrap();
    assert!(sa.commit().unwrap().is_some());
    assert_eq!(sa.commit().unwrap(), None, "nothing new");
    w.run();
    let sb = db.edit_text(t, db.key("/n/body").unwrap(), osis::Path::root()).unwrap();
    assert_eq!(sb.text(), "hello");
    let (tx, rx) = std::sync::mpsc::channel();
    sa.on_remote(move |s, _| {
        let _ = tx.send(s.to_string());
    });
    sb.insert(5, " world").unwrap();
    sa.insert(0, ">").unwrap();
    sb.commit().unwrap();
    w.run();
    let merged = recv(&rx);
    assert_eq!(merged, ">hello world", "local edit committed first, then merged");
    assert_eq!(sa.text(), merged);
    w.run();
    db.settle();
    assert_eq!(sb.text(), merged);
}

/// Two paired devices with a text thing `t` reading "hello world", and a session on it from
/// the first.
fn text_pair() -> (World, Osis, Osis, Tid, osis::TextSession) {
    let mut w = World::new();
    let sv = w.add_server();
    let (da, _) = w.person(1, &[sv]);
    w.run();
    let join = Osis::pair(w.cfg(2, &[]), &da.pair_offer().unwrap()).unwrap();
    let (_, reply) = da.pair_accept(join.request()).unwrap();
    let db = join.finish(&reply).unwrap();
    for d in [&da, &db] {
        d.register_schema_source("t.osis", TEXT_SCHEMA).unwrap();
    }
    let t = da.write_with(|w| w.create_in(da.me(), &[da.home()])).unwrap();
    let sa = da.edit_text(t, da.key("/n/body").unwrap(), osis::Path::root()).unwrap();
    sa.insert(0, "hello world").unwrap();
    sa.commit().unwrap();
    w.run();
    db.settle();
    (w, da, db, t, sa)
}

/// The `Uncommitted` diagnostics of `db`, as they arrive.
fn uncommitted(db: &Osis) -> (osis::Subscription, std::sync::mpsc::Receiver<Vec<Tid>>) {
    let (tx, rx) = std::sync::mpsc::channel();
    let sub = db.on_diagnostic(move |_, d| {
        if d.kind == osis::DiagnosticKind::Uncommitted {
            let _ = tx.send(d.tids);
        }
    });
    (sub, rx)
}

// notes/api.md Text sessions (`on_remote` edits): a remote edit in the middle of the text
// reaches the session as splices, each at the text before it; applied in order they give the
// merged text, and a caret mapped through them stays on its char.
// spec: none (API surface, notes/api.md)
#[test]
fn text_session_remote_splices_map_caret() {
    let (mut w, _da, db, t, sa) = text_pair();
    let (tx, rx) = std::sync::mpsc::channel();
    sa.on_remote(move |s, e| {
        let _ = tx.send((s.to_string(), e.to_vec()));
    });
    let sb = db.edit_text(t, db.key("/n/body").unwrap(), osis::Path::root()).unwrap();
    assert_eq!(sb.text(), "hello world");
    sb.replace(0..1, "H").unwrap();
    sb.insert(6, "big ").unwrap();
    sb.commit().unwrap();
    w.run();
    let (merged, edits) = recv(&rx);
    assert_eq!(merged, "Hello big world");
    assert!(edits.len() >= 2, "two separate edits: {edits:?}");
    let mut text: Vec<char> = "hello world".chars().collect();
    for e in &edits {
        text.splice(e.at..e.at + e.del, e.text.chars());
    }
    assert_eq!(text.iter().collect::<String>(), merged);
    let old: Vec<char> = "hello world".chars().collect();
    let map = |c: usize| edits.iter().fold(c, |c, e| e.map(c));
    for caret in [2, 3, 8, 9] {
        assert_eq!(text.get(map(caret)), old.get(caret), "caret {caret} -> {}", map(caret));
    }
    assert_eq!(map(11), text.len(), "the end stays the end");
}

// notes/api.md Text sessions: a session whose thing another device deleted drops its pending
// text when it is dropped and reports it (`Uncommitted`): it never recreates the thing.
// spec: none (API surface, notes/api.md)
#[test]
fn text_session_after_remote_delete_drops() {
    let (mut w, da, db, t, sa) = text_pair();
    let (_d, rx) = uncommitted(&da);
    db.write_with(|w| w.delete(t)).unwrap();
    sa.insert(11, "!").unwrap();
    w.run();
    assert!(!da.knows(t), "deleted here");
    sa.insert(0, "> ").unwrap();
    drop(sa);
    assert_eq!(recv(&rx), vec![t]);
    w.run();
    for d in [&da, &db] {
        assert!(!d.knows(t), "not recreated");
        assert_eq!(d.get(t, d.key("/n/body").unwrap()).unwrap(), None);
    }
}

// notes/api.md Text sessions: the same for a delete on the session's own device.
// spec: none (API surface, notes/api.md)
#[test]
fn text_session_after_local_delete_drops() {
    let (mut w, da, db, t, sa) = text_pair();
    let (_d, rx) = uncommitted(&da);
    sa.insert(11, "!").unwrap();
    da.write_with(|w| w.delete(t)).unwrap();
    drop(sa);
    assert_eq!(recv(&rx), vec![t]);
    w.run();
    for d in [&da, &db] {
        assert!(!d.knows(t), "not recreated");
        assert_eq!(d.get(t, d.key("/n/body").unwrap()).unwrap(), None);
    }
}

// notes/api.md Text sessions: a commit after the delete fails `UnknownThing` and keeps the
// edits; once the delete is undone they commit.
// spec: none (API surface, notes/api.md)
#[test]
fn text_session_keeps_edits_across_delete_undo() {
    let (_w, da, _db, t, sa) = text_pair();
    sa.insert(11, "!").unwrap();
    da.write_with(|w| w.delete(t)).unwrap();
    assert!(matches!(sa.commit(), Err(osis::Error::UnknownThing { .. })));
    assert!(!da.knows(t), "not recreated");
    assert_eq!(sa.text(), "hello world!", "kept");
    da.undo(&osis::Scope::Thing(t)).unwrap().unwrap();
    assert!(da.knows(t));
    sa.commit().unwrap().unwrap();
    assert_eq!(da.get(t, da.key("/n/body").unwrap()).unwrap(), Some(osis::Value::Str("hello world!".into())));
}

// notes/api.md Sync configuration (`add_server`), spec/sync.md §2 (`/label` servers, inbox): a
// database created without servers has its home label on none; adding a server moves the home
// label and the person's inbox there, and the home group syncs.
#[test]
fn add_server_moves_labels_spec_sync_2() {
    let mut w = World::new();
    let sv = w.add_server();
    let (a, card) = Osis::create(w.cfg(1, &[])).unwrap();
    assert!(card.is_none());
    w.run();
    assert_eq!(a.status().unwrap().groups[&a.home()].state, SyncState::NoServers);
    a.add_server(&w.addr(sv)).unwrap();
    w.run();
    assert_eq!(a.status().unwrap().groups[&a.home()].state, SyncState::Synced);
    let inbox = a.get(a.me(), osis::core::KEYS).unwrap().unwrap().inbox.unwrap();
    assert_eq!(inbox.servers.len(), 1);
    w.until(a.wait_synced(SyncScope::All, Duration::from_secs(10)), 1000, 10).unwrap();
    a.remove_server(&w.addr(sv)).unwrap();
    w.run();
    assert_eq!(a.status().unwrap().groups[&a.home()].state, SyncState::NoServers);
}

// notes/api.md Sync configuration (`add_server` scope), spec/sync.md §2: Alice's server changes
// move her home label and her own shared group, not a group Bob owns that she co-administers,
// not her link's actor (the link text names its servers); her shared group keeps its last
// server.
#[test]
fn add_server_scope_spec_sync_2() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let (s0, s1) = (0, w.add_server());
    let bob = &others[0];
    let card = alice.contact_card().unwrap();
    w.run();
    let a = w.until(bob.import_contact(&card), 1000, 10).unwrap();
    let mine = group(&alice);
    alice.grant(mine, ids[0], Role::Write, Default::default()).unwrap();
    let his = group(bob);
    bob.grant(his, a, Role::Admin, Default::default()).unwrap();
    w.run();
    assert_eq!(alice.role_on(his), Some(Role::Admin));
    alice.make_link(mine, Role::Read, osis::LinkOpts::default()).unwrap();
    let k = alice.links(mine)[0].id;
    w.run();
    let servers = |g: Tid| alice.engine(|e| e.group_labels(&g).unwrap().into_iter().find(|l| !l.replaced).unwrap().servers.len());
    alice.add_server(&w.addr(s1)).unwrap();
    w.run();
    assert_eq!((servers(alice.home()), servers(mine), servers(his), servers(k)), (2, 2, 1, 1));
    alice.remove_server(&w.addr(s0)).unwrap();
    alice.remove_server(&w.addr(s1)).unwrap();
    w.run();
    assert_eq!((servers(alice.home()), servers(mine), servers(his), servers(k)), (0, 1, 1, 1), "a shared group keeps its last server");
}
