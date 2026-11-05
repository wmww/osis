//! Sharing and sync through hosts in process (notes/api.md Sharing and roles,
//! Sync configuration and status), no tokio: see osis_sim::world.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common::TestWrites as _;
use osis::internals::Internals as _;
use crate::common;
use osis_sim::world::World;
use common::*;
use crate::common::CreateIn;
use osis::{Demotion, Lower, Osis, Role, SyncScope, SyncState, Tid, Value};
use std::time::Duration;

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

/// A thing in `g` (owned by `owner`) with `t:x.0` = `v`.
fn item(db: &Osis, owner: Tid, g: Tid, v: &str) -> Tid {
    let mut w = db.write();
    let t = w.create_in(owner, &[g]).unwrap();
    w.at(t, ak("t:x.0")).set(&s(v)).unwrap();
    w.commit().unwrap();
    t
}

fn write_refused(db: &Osis, t: Tid) -> bool {
    let mut w = db.write();
    w.at(t, ak("t:x.0")).set(&s("no")).is_err() || w.commit().is_err()
}

fn x(db: &Osis, t: Tid) -> Option<Value> {
    db.at(t, ak("t:x.0")).get().unwrap()
}

// notes/api.md Handle (create), Sync status; spec/sync.md §2 (home label): a new person's home
// label registers at its host; status turns Synced and wait_synced resolves after a write.
#[test]
fn create_syncs_home_spec_sync_2() {
    let mut w = World::new();
    let host = w.add_host();
    let (db, _card) = w.person(1, &[host]);
    w.run();
    let st = db.status().unwrap();
    assert_eq!(st.groups.get(&db.me()).map(|g| g.state), Some(SyncState::Synced), "{st:?}");
    assert_eq!(st.connected, 1);
    item(&db, db.me(), db.me(), "hello");
    assert_ne!(db.status().unwrap().groups.get(&db.me()).map(|g| g.state), Some(SyncState::Synced), "a local commit is not at the host yet");
    w.until(db.wait_synced(SyncScope::All, Duration::from_secs(60)), 1000, 10).unwrap();
}

// notes/api.md Sharing (devices), spec/sync.md §2 (pairing: the only way a node receives a
// grant): the app carries the request and the reply; the new device becomes an admin of the
// person, reads the home group and its writes reach the first device.
#[test]
fn pairing_spec_permissions_1() {
    let mut w = World::new();
    let host = w.add_host();
    let (da, _) = w.person(1, &[host]);
    w.run();
    let t = item(&da, da.me(), da.me(), "before pairing");
    for i in 0..10 {
        item(&da, da.me(), da.me(), &format!("{i}{}", "x".repeat(4000)));
    }
    let offer = da.pair_offer().unwrap();
    let join = Osis::pair(w.cfg(2, &[]), &offer).unwrap();
    let req: osis::PairRequest = join.request().to_string().parse().unwrap();
    let (node, reply) = da.pair_accept(&req).unwrap();
    assert_eq!(node, join.node());
    assert!(reply.to_string().len() < 40_000, "certificates and label.0 only, no content: {}", reply.to_string().len());
    assert!(da.pair_accept(&req).is_err(), "an offer is used once");
    let db = join.finish(&reply).unwrap();
    assert_eq!(db.me(), da.me());
    w.run();
    assert_eq!(x(&db, t), Some(s("before pairing")));
    let u = item(&db, db.me(), db.me(), "from the new device");
    w.run();
    assert_eq!(x(&da, u), Some(s("from the new device")));
    let devs: Vec<Tid> = da.devices().unwrap().into_iter().map(|d| d.node).collect();
    assert!(devs.contains(&da.node()) && devs.contains(&db.node()), "{devs:?}");
    // a lost device, removed without waiting (spec/permissions.md §5.3 `Skip`)
    let skip = osis::Demotion { sync: osis::WaitForSync::Skip, backdate: None, repudiate: false, keep: None };
    w.until(da.remove_device(db.node(), skip), 1000, 5).unwrap();
    assert!(!da.devices().unwrap().iter().any(|d| d.node == db.node()));
    let after = item(&da, da.me(), da.me(), "after the removal");
    w.run();
    assert_eq!(x(&db, after), None, "the removed device reads nothing new");
}

// spec/permissions.md §8 (recovery card), notes/api.md Handle (restore): a fresh device with
// the card claims the home label by the recovery key, downloads it and becomes an admin.
#[test]
fn restore_from_card_spec_permissions_8() {
    let mut w = World::new();
    let host = w.add_host();
    let (da, card) = w.person(1, &[host]);
    let t = item(&da, da.me(), da.me(), "kept by the host");
    w.run();
    let card: osis::RecoveryCard = card.to_string().parse().unwrap();
    w.advance(1000);
    let dc = w.until(Osis::restore(w.cfg(4, &[]), &card), 1000, 10).unwrap();
    w.run();
    assert_eq!(dc.me(), da.me());
    assert_eq!(x(&dc, t), Some(s("kept by the host")));
    assert_eq!(dc.role_on(dc.me()).unwrap(), Some(Role::Admin));
    let u = item(&dc, dc.me(), dc.me(), "after restore");
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
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
    w.run();
    let g = group(&alice);
    let ro = group(&alice);
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    alice.grant(g, b, Role::Write, Default::default()).unwrap();
    alice.grant(ro, b, Role::Read, Default::default()).unwrap();
    let t = item(&alice, g, g, "doomed");
    let mut wr = alice.write();
    wr.place(t, ro).unwrap();
    wr.commit().unwrap();
    w.run();
    assert!(bob.knows(t).unwrap());
    assert_eq!(bob.groups_of(t).unwrap().item_of.len(), 2);
    let mut wr = bob.write();
    wr.delete(t).unwrap();
    wr.commit().unwrap();
    assert!(!bob.knows(t).unwrap());
    w.run();
    assert!(!alice.knows(t).unwrap() && alice.created(t).unwrap().is_some());
    assert_eq!(x(&alice, t), None);
    assert_eq!(alice.groups_of(t).unwrap().item_of, vec![ro]);
}

/// A group owned by `db`'s person, synced on its hosts.
fn group(db: &Osis) -> Tid {
    let mut w = db.write();
    let g = w.create_in(db.me(), &[db.me()]).unwrap();
    w.make_group(g).unwrap();
    w.commit().unwrap();
    db.sync(g, &[]).unwrap();
    g
}

// spec/permissions.md §4, spec/sync.md §10, notes/client-port.md §3 (attribution): a thin client's commit, written by its node as the client's actor, reaches another account holding the group through sync, applied there with that actor and that node in its header (the actor's creation record travels with its edge); its grants to the actor reach the account's other device through the home group
#[test]
fn client_commit_reaches_a_third_device() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
    w.run();
    let g = group(&alice);
    let card: osis::ContactCard = bob.contact_card().unwrap().to_string().parse().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    alice.grant(g, b, Role::Write, Default::default()).unwrap();
    let t = item(&alice, g, g, "first");
    let (actor, _) = alice.add_client(None).unwrap();
    alice.grant(g, actor, Role::Write, Default::default()).unwrap();
    let c = alice.acting_as(actor);
    let mut wr = c.write();
    wr.at(t, ak("t:x.0")).set(&s("by the client")).unwrap();
    wr.commit().unwrap();
    w.run();
    assert_eq!(x(&bob, t), Some(s("by the client")));
    let last = &bob.commits(&osis::CommitQuery::new().scope(osis::Scope::Thing(t))).unwrap()[0];
    assert_eq!((last.commit.actor, last.commit.node), (actor, alice.node()));
    assert_eq!(bob.roster(g).unwrap().get(&actor).map(|e| e.role), Some(Role::Write));
    // and Bob's writes still reach Alice's client view
    let mut wr = bob.write();
    wr.at(t, ak("t:x.0")).set(&s("by bob")).unwrap();
    wr.commit().unwrap();
    w.run();
    assert_eq!(c.at(t, ak("t:x.0")).get().unwrap(), Some(s("by bob")));
}

// spec/sync.md §3 (contact card, inbox), spec/permissions.md §2 (grant): Alice imports Bob's
// contact card and grants him write on a synced group; the grant reaches Bob's device through
// his inbox; both read and write things the group owns (entitlement: things owned elsewhere
// stay unshared, notes/sync.md).
#[test]
fn grant_by_inbox_spec_sync_3() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
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
    assert_eq!(bob.role_on(g).unwrap(), Some(Role::Write));
    let u = item(&bob, g, g, "from bob");
    w.run();
    assert_eq!(x(&alice, u), Some(s("from bob")));
}

/// Alice and `n` other people on one host; each other person's card imported by Alice.
fn people(w: &mut World, n: usize) -> (Osis, Vec<Osis>, Vec<Tid>) {
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let others: Vec<Osis> = (0..n).map(|i| w.person(2 + i as u64, &[host]).0).collect();
    w.run();
    let mut ids = Vec::new();
    for o in &others {
        let card = o.contact_card().unwrap();
        w.run();
        ids.push(w.until(alice.import_contact(&card), 1000, 10).unwrap());
    }
    (alice, others, ids)
}

// spec/permissions.md §8 (links): Bob redeems a single-use write link to Alice's group and
// reads what was there before; his redemption removes the link key (the link's `flags`,
// spec/wire.md §10); Alice's device finalizes it when it sees that (K rotates), Bob stays a holder and
// a second redeemer is told the link ended.
#[test]
fn link_redeem_spec_permissions_8() {
    let mut w = World::new();
    let (alice, others, _) = people(&mut w, 1);
    let bob = &others[0];
    let g = group(&alice);
    let before = item(&alice, g, g, "before the link");
    let link = alice.make_link(g, Role::Write, osis::LinkOpts { until: None, single_use: true, direct: false }).unwrap();
    assert_eq!(alice.links_of(g).unwrap().len(), 1);
    w.run();
    let link: osis::ShareLink = link.to_string().parse().unwrap();
    // a hinted label the joiner fails to open first is retried after `resync_ms`
    assert_eq!(w.until(bob.redeem(&link), 1000, 10).unwrap(), g);
    w.run();
    assert_eq!(x(bob, before), Some(s("before the link")));
    let u = item(bob, g, g, "from the joiner");
    w.run();
    assert_eq!(x(&alice, u), Some(s("from the joiner")));
    assert!(alice.links_of(g).unwrap().is_empty(), "single use: L left K");
    assert!(alice.engine(|e| !e.held_links().unwrap().is_empty() && e.links_due().unwrap().is_empty()), "finalized on the redemption");
    let v = item(&alice, g, g, "after the link ended");
    w.run();
    assert_eq!(x(bob, v), Some(s("after the link ended")), "the joiner stays");
    let mut c = w.cfg(9, &[0]);
    c.wait_timeout = Duration::from_secs(5);
    let carol = Osis::create(c).unwrap().0;
    w.run();
    assert!(matches!(w.until(carol.redeem(&link), 1000, 10), Err(osis::Error::Invalid(_))), "used once");
    assert_eq!(carol.role_on(g).unwrap(), None);
    assert_eq!(carol.engine(|e| e.held_key_actors()), 0, "the link key is forgotten");
}

// spec/permissions.md §8, spec/sync.md §5: a used single-use link refuses a second redeemer
// at once and later (0, 10, 20 s after the first redemption settled): the sharer registers a
// step without L as soon as L's departure is covered, whoever rotated K.
#[test]
fn used_link_refused_at_once_spec_permissions_8() {
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
        assert!(matches!(w.until(carol.redeem(&link), 1000, 10), Err(osis::Error::Invalid(_))), "refused, attempt {i}");
        assert_eq!(carol.role_on(g).unwrap(), None);
    }
}

// spec/permissions.md §8, §5.1: with the sharer offline, a second redeemer of a used
// single-use link whose view still lists L (the first redemption not applied there: the
// joiner's rotation of K pends its chain) is not told it joined: refused, or admitted only
// once the first redemption is applied in its view (then its grant is void).
#[test]
fn used_link_with_sharer_offline_spec_permissions_8() {
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
    assert_eq!(carol.role_on(g).unwrap(), None);
    w.set_online(&alice, true);
    w.advance(600_000);
    w.run();
    assert_eq!(carol.role_on(g).unwrap(), None, "still no role once the sharer is back");
}

/// Alice's synced group with a read link expiring in an hour, redeemed by Bob: (world, alice,
/// bob, group, K, L).
fn until_link(w: &mut World) -> (Osis, Osis, Tid, Tid, Tid) {
    let host = w.add_host();
    let [alice, bob] = [1, 2].map(|i| w.person(i, &[host]).0);
    w.run();
    let g = group(&alice);
    let until = osis::WallMs(w.now() + 3_600_000);
    let link = alice.make_link(g, Role::Read, osis::LinkOpts { until: Some(until), single_use: false, direct: false }).unwrap();
    w.run();
    assert_eq!(w.until(bob.redeem(&link), 1000, 10).unwrap(), g);
    w.run();
    let k = alice.links_of(g).unwrap()[0].id;
    let l = alice.roster(k).unwrap().into_keys().find(|m| alice.owner_of(*m).unwrap().is_none()).unwrap();
    (alice, bob, g, k, l)
}

/// Whether `db` holds link (k, l) and has nothing of it left to finalize (L's edge on K is
/// gone by an explicit removal: it expired, so it is not alive).
fn finalized(db: &Osis, k: Tid, l: Tid) -> bool {
    db.engine(|e| e.held_links().unwrap().iter().any(|x| (x.k, x.l) == (k, l)) && e.links_due().unwrap().is_empty())
}

// spec/permissions.md §8 (link finalized): `until` finalized by a sharer device's removal of L; with Alice's
// device offline when the link expires, her other device (which holds the seed thing, not the
// link record) removes L at expiry; back online, Alice's device writes nothing more; Bob stays.
#[test]
fn until_link_finalized_by_other_device_spec_permissions_8() {
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
    let removals = |db: &Osis| db.engine(|e| e.commit_ids().into_iter().filter(|c| e.header(c).is_some_and(|h| h.author == db.node() && h.frontier.is_some() && h.aspects.iter().any(|a| a.tid == k && a.ak.as_str() == "roles.0"))).count());
    assert_eq!(removals(&alice2), 1);
    w.set_online(&alice, true);
    w.advance(60_000);
    w.run();
    assert!(finalized(&alice, k, l), "the other device's removal arrived");
    assert_eq!(removals(&alice), 0, "and wrote no removal of its own");
    assert!(alice.roster(k).unwrap().contains_key(&bob.me()) && bob.role_on(g).unwrap().is_some(), "the joiner stays");
}

// spec/permissions.md §8 (link finalized): Alice's only device is offline when the link expires; it removes L
// once it is back and synced K's label; Bob stays.
#[test]
fn until_link_finalized_when_sharer_returns_spec_permissions_8() {
    let mut w = World::new();
    let (alice, bob, g, k, l) = until_link(&mut w);
    w.set_online(&alice, false);
    w.advance(2 * 3_600_000);
    assert!(!finalized(&alice, k, l), "waits for a complete pass of K's labels");
    w.set_online(&alice, true);
    w.advance(60_000);
    w.run();
    assert!(finalized(&alice, k, l));
    assert!(alice.roster(k).unwrap().contains_key(&bob.me()) && bob.role_on(g).unwrap().is_some(), "the joiner stays");
}

/// Alice's synced group with a multi-use read link redeemed by Bob and Carol: (world, alice,
/// bob, carol, group, link actor K, link key L).
fn joined_by_link() -> (World, Osis, Osis, Osis, Tid, Tid, Tid) {
    let mut w = World::new();
    let host = w.add_host();
    let [alice, bob, carol] = [1, 2, 3].map(|i| w.person(i, &[host]).0);
    w.run();
    let g = group(&alice);
    let link = alice.make_link(g, Role::Read, osis::LinkOpts::default()).unwrap();
    w.run();
    for o in [&bob, &carol] {
        assert_eq!(w.until(o.redeem(&link), 1000, 10).unwrap(), g);
        w.run();
    }
    let k = alice.links_of(g).unwrap()[0].id;
    let l = alice.roster(k).unwrap().into_keys().find(|m| alice.owner_of(*m).unwrap().is_none()).unwrap();
    (w, alice, bob, carol, g, k, l)
}

// spec/permissions.md §8 (a joiner is revoked together with the link key), notes/api.md
// Sharing (`holder_path`, `demote`): a link joiner reaches the target through K; removing it on
// the target removes it and L from K in one commit, so a failed pre-sync leaves both in place
// and a retry completes; a second removal writes nothing; a joiner's role cannot be lowered.
#[test]
fn demote_link_joiner_spec_permissions_8() {
    let (mut w, alice, bob, carol, g, k, l) = joined_by_link();
    assert_eq!(alice.holder_path(g, bob.me()).unwrap(), vec![(g, k), (k, bob.me())]);
    // offline, the required pre-sync fails: nothing changed
    w.set_online(&alice, false);
    let r = w.until(alice.demote(g, bob.me(), Lower::Remove, Demotion::default()), 1000, 60);
    assert!(matches!(r, Err(osis::Error::Unsynced { .. })), "{r:?}");
    assert!(alice.roster(k).unwrap().contains_key(&bob.me()) && alice.roster(k).unwrap().contains_key(&l), "no half-removal");
    w.set_online(&alice, true);
    let skip = Demotion { sync: osis::WaitForSync::Skip, backdate: None, repudiate: false, keep: None };
    w.until(alice.demote(g, bob.me(), Lower::Remove, skip), 1000, 10).unwrap();
    let r = alice.roster(k).unwrap();
    assert!(!r.contains_key(&bob.me()) && !r.contains_key(&l) && r.contains_key(&carol.me()));
    assert!(alice.holder_path(g, bob.me()).unwrap().is_empty());
    assert!(alice.links_of(g).unwrap().is_empty(), "the link ends with its joiner");
    let commits = alice.engine(|e| e.commit_ids().len());
    w.until(alice.demote(g, bob.me(), Lower::Remove, skip), 1000, 10).unwrap();
    assert_eq!(alice.engine(|e| e.commit_ids().len()), commits, "nothing left to remove");
    assert!(matches!(w.until(alice.demote(g, carol.me(), Lower::To(Role::Read), skip), 1000, 10), Err(osis::Error::Invalid(_))));
}

// spec/permissions.md §8, notes/api.md Sharing (`demote`): after a joiner's removal the other
// joiner reads new content and the removed one does not; another device of the sharer can do the
// removal, holding the link's seed thing, and syncs it to rest (spec/permissions.md §3: it once rotated the target without end,
// since a late part of a joiner's redemption was judged without its `roles.0` part and the
// rotation of K that removal made never established there).
#[test]
fn demote_link_joiner_content_spec_permissions_8() {
    let (mut w, alice, bob, carol, g, _, _) = joined_by_link();
    let join = Osis::pair(w.cfg(9, &[0]), &alice.pair_offer().unwrap()).unwrap();
    let (_, reply) = alice.pair_accept(join.request()).unwrap();
    let alice2 = join.finish(&reply).unwrap();
    w.run();
    let skip = Demotion { sync: osis::WaitForSync::Skip, backdate: None, repudiate: false, keep: None };
    w.until(alice2.demote(g, bob.me(), Lower::Remove, skip), 1000, 20).unwrap();
    let after = item(&alice, g, g, "after bob left");
    w.run();
    assert_eq!(x(&carol, after), Some(s("after bob left")));
    assert_eq!(x(&bob, after), None);
    assert_eq!(x(&alice2, after), Some(s("after bob left")));
}

// spec/permissions.md §3 (removal with rotation), §5.3 (pre-sync), notes/api.md Sharing
// (demote): Alice removes Bob after the pre-sync; Carol keeps reading new content, Bob does
// not; Bob's write made before the removal stays.
// spec/crypto.md §4 (removed holder)
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
    assert!(!alice.roster(g).unwrap().contains_key(&ids[0]));
    let after = item(&alice, g, g, "after bob left");
    w.run();
    assert_eq!(x(carol, after), Some(s("after bob left")));
    assert_eq!(x(bob, after), None);
    assert_eq!(x(&alice, by_bob), Some(s("bob was here")));
    assert_eq!(x(carol, by_bob), Some(s("bob was here")));
}

// spec: none (API surface); notes/sync.md Receipts-only reads, notes/client-port.md §2 (rows that wait): a pre-sync's read of a receipts-only group ends with its future, also one dropped before it finished: a daemon outlives a client gone mid-demote
#[test]
fn dropped_demote_ends_its_receipts_read() {
    use std::future::Future;
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let g = group(&alice);
    let h = {
        let mut wr = alice.write();
        let h = wr.create_in(g, &[]).unwrap();
        wr.make_group(h).unwrap();
        wr.commit().unwrap();
        h
    };
    alice.sync(h, &[]).unwrap();
    alice.grant(g, ids[0], Role::Write, Default::default()).unwrap();
    w.run();
    drop(others);
    alice.sync_policy(h, osis::GroupPolicy { receipts_only: true, ..Default::default() }).unwrap();
    w.run();
    w.set_online(&alice, false);
    let mut d = Box::pin(alice.demote(g, ids[0], Lower::Remove, Demotion::default()));
    assert!(d.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop())).is_pending());
    assert_eq!(alice.sync_engine(|s| s.receipts_read(&[h])), None, "reading");
    drop(d);
    assert_eq!(alice.sync_engine(|s| s.receipts_read(&[h])), Some(Ok(())), "nobody reads any more");
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
    phone.sync_policy(h, osis::GroupPolicy { receipts_only: true, ..Default::default() }).unwrap();
    w.run();
    let in_g = item(bob, g, g, "bob in g");
    let in_h = item(bob, h, h, "bob in h");
    w.run();
    assert_eq!(x(&phone, in_g), Some(s("bob in g")));
    assert_eq!(x(&phone, in_h), None, "the phone holds nothing of H");
    assert_eq!(x(carol, in_h), Some(s("bob in h")));
    let label = alice.engine(|e| e.group_labels(&h).unwrap())[0].id;
    let log = |w: &World| osis_proto::store::LabelStore::log_head(w.hosts[0].hub.store(), &label).unwrap();
    for db in [&alice, bob, carol] {
        w.set_online(db, false);
    }
    let before = log(&w);
    w.until(phone.demote(g, ids[0], Lower::Remove, Demotion::default()), 1000, 30).unwrap();
    w.run();
    assert_eq!(log(&w), before, "the phone placed nothing under H's label");
    // received by header only (spec/permissions.md §5.1)
    let r = phone.engine(|e| e.receipt(&in_h, &ak("t:x.0")).unwrap());
    assert!(r.commits.len() == 1, "{r:?}");
    for db in [&alice, bob, carol] {
        w.set_online(db, true);
    }
    // the dials wait for their retry time
    w.advance(10_000);
    w.run();
    assert!(!carol.roster(g).unwrap().contains_key(&ids[0]));
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
    phone.sync_policy(h, osis::GroupPolicy { receipts_only: true, ..Default::default() }).unwrap();
    // one field changed from the policy as set keeps the others
    phone.sync_policy(h, osis::GroupPolicy { publish_reach: Some(false), ..phone.group_policy(h).unwrap() }).unwrap();
    assert_eq!(phone.group_policy(h).unwrap(), osis::GroupPolicy { publish_reach: Some(false), receipts_only: true });
    w.run();
    let st = phone.status().unwrap();
    assert_eq!(st.groups.get(&h).map(|s| s.state), Some(SyncState::ReceiptsOnly), "{st:?}");
    assert_eq!(st.groups.get(&g).map(|s| s.state), Some(SyncState::Synced), "{st:?}");
    // nothing of H goes into a wait for it
    w.until(phone.wait_synced(SyncScope::All, Duration::from_secs(10)), 1000, 10).unwrap();
    assert!(w.until(phone.wait_synced(SyncScope::Group(h), Duration::from_secs(10)), 1000, 10).is_err(), "H is not synced here");
}

// spec/sync.md §5 (relay-only entries), notes/api.md Signals: a signal aspect set on a shared
// thing reaches another person's connected device through the host once; local callbacks fire
// too; nothing is held.
#[test]
fn remote_signal_spec_sync_5() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let bob = &others[0];
    let g = group(&alice);
    alice.grant(g, ids[0], Role::Write, Default::default()).unwrap();
    w.run();
    let ring = ak("t:typing.0*");
    let (tx, rx) = std::sync::mpsc::channel();
    let tx2 = tx.clone();
    let _a = alice.at(g, ring.clone()).on_change(move |_, c| tx.send(("alice", c)).unwrap()).unwrap();
    let _b = bob.at(g, ring.clone()).on_change(move |_, c| tx2.send(("bob", c)).unwrap()).unwrap();
    let _ = (recv(&rx), recv(&rx));
    bob.commit_set(g, ring.clone(), &Value::Int(1)).unwrap();
    w.run();
    let mut got = [recv(&rx), recv(&rx)];
    got.sort_by_key(|g| g.0);
    assert_eq!(got.iter().map(|(n, c)| (*n, c.value.clone())).collect::<Vec<_>>(), vec![("alice", Ok(Some(Value::Int(1)))), ("bob", Ok(Some(Value::Int(1))))]);
    assert!(matches!(got[0].1.source, osis::Source::Remote(i) if i.actor == bob.me() && i.node == bob.node()));
    assert!(matches!(got[1].1.source, osis::Source::Local(_)));
    alice.settle();
    assert!(rx.try_recv().is_err(), "once");
    assert_eq!(alice.at(g, ring).get().unwrap(), None);
}

// spec/commits.md §6 (expiry), notes/chat.md (disappearing messages): a message written with an
// expiry reaches the other holder and is gone everywhere once it expires.
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
    wr.at(m, ak("t:x.0")).expires_in(Duration::from_secs(10)).set(&s("gone soon")).unwrap();
    wr.commit().unwrap();
    w.run();
    assert_eq!(x(bob, m), Some(s("gone soon")));
    w.advance(11_000);
    assert_eq!(x(&alice, m), None);
    assert_eq!(x(bob, m), None);
}

const TEXT_SCHEMA: &str = "version 1;\naspect n:body.0: text;\n";

// notes/api.md Text editing sessions, spec/requirements.md (Generality: one commit per editing
// pause): two devices edit one text concurrently in sessions; each commit is one edit, the
// remote edit merges into the other buffer and both converge with both edits.
// spec/crdt.md §5.7
#[test]
fn text_sessions_merge_spec_crdt_5_7() {
    let mut w = World::new();
    let host = w.add_host();
    let (da, _) = w.person(1, &[host]);
    w.run();
    let join = Osis::pair(w.cfg(2, &[]), &da.pair_offer().unwrap()).unwrap();
    let (_, reply) = da.pair_accept(join.request()).unwrap();
    let db = join.finish(&reply).unwrap();
    for d in [&da, &db] {
        d.register_schema("t.osis", TEXT_SCHEMA).unwrap();
    }
    let body = da.key("n:body.0").unwrap();
    let mut wr = da.write();
    let t = wr.create_in(da.me(), &[da.me()]).unwrap();
    wr.commit().unwrap();
    let sa = da.edit_text(t, body.clone(), osis::Path::root()).unwrap();
    sa.replace(0..0, "hello").unwrap();
    assert!(sa.commit().unwrap().is_some());
    assert_eq!(sa.commit().unwrap(), None, "nothing new");
    w.run();
    let sb = db.edit_text(t, db.key("n:body.0").unwrap(), osis::Path::root()).unwrap();
    assert_eq!(sb.text(), "hello");
    let (tx, rx) = std::sync::mpsc::channel();
    sa.on_remote(move |s, _| {
        let _ = tx.send(s.to_string());
    });
    sb.replace(5..5, " world").unwrap();
    sa.replace(0..0, ">").unwrap();
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
    let host = w.add_host();
    let (da, _) = w.person(1, &[host]);
    w.run();
    let join = Osis::pair(w.cfg(2, &[]), &da.pair_offer().unwrap()).unwrap();
    let (_, reply) = da.pair_accept(join.request()).unwrap();
    let db = join.finish(&reply).unwrap();
    for d in [&da, &db] {
        d.register_schema("t.osis", TEXT_SCHEMA).unwrap();
    }
    let t = da.batch(|w| w.create_in(da.me(), &[da.me()])).unwrap();
    let sa = da.edit_text(t, da.key("n:body.0").unwrap(), osis::Path::root()).unwrap();
    sa.replace(0..0, "hello world").unwrap();
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
    }).unwrap();
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
    let sb = db.edit_text(t, db.key("n:body.0").unwrap(), osis::Path::root()).unwrap();
    assert_eq!(sb.text(), "hello world");
    sb.replace(0..1, "H").unwrap();
    sb.replace(6..6, "big ").unwrap();
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
    db.batch(|w| w.delete(t)).unwrap();
    sa.replace(11..11, "!").unwrap();
    w.run();
    assert!(!da.knows(t).unwrap(), "deleted here");
    sa.replace(0..0, "> ").unwrap();
    drop(sa);
    assert_eq!(recv(&rx), vec![t]);
    w.run();
    for d in [&da, &db] {
        assert!(!d.knows(t).unwrap(), "not recreated");
        assert_eq!(d.at(t, d.key("n:body.0").unwrap()).get().unwrap(), None);
    }
}

// notes/api.md Text sessions: the same for a delete on the session's own device.
// spec: none (API surface, notes/api.md)
#[test]
fn text_session_after_local_delete_drops() {
    let (mut w, da, db, t, sa) = text_pair();
    let (_d, rx) = uncommitted(&da);
    sa.replace(11..11, "!").unwrap();
    da.batch(|w| w.delete(t)).unwrap();
    drop(sa);
    assert_eq!(recv(&rx), vec![t]);
    w.run();
    for d in [&da, &db] {
        assert!(!d.knows(t).unwrap(), "not recreated");
        assert_eq!(d.at(t, d.key("n:body.0").unwrap()).get().unwrap(), None);
    }
}

// notes/api.md Text sessions: a commit after the delete fails `UnknownThing` and keeps the
// edits; once the delete is undone they commit.
// spec: none (API surface, notes/api.md)
#[test]
fn text_session_keeps_edits_across_delete_undo() {
    let (_w, da, _db, t, sa) = text_pair();
    sa.replace(11..11, "!").unwrap();
    let mut w = da.write();
    w.delete(t).unwrap();
    w.commit().unwrap();
    assert!(matches!(sa.commit(), Err(osis::Error::UnknownThing { .. })));
    assert!(!da.knows(t).unwrap(), "not recreated");
    assert_eq!(sa.text(), "hello world!", "kept");
    da.undo(&osis::Scope::Thing(t)).unwrap().unwrap();
    assert!(da.knows(t).unwrap());
    sa.commit().unwrap().unwrap();
    assert_eq!(da.at(t, da.key("n:body.0").unwrap()).get().unwrap(), Some(osis::Value::Str("hello world!".into())));
}

// notes/api.md Sync configuration (`add_host`), spec/sync.md §2 (`label.0` hosts, inbox): a
// database created without hosts has its home label on none; adding a host moves the home
// label and the person's inbox there, and the home group syncs.
#[test]
fn add_host_moves_labels_spec_sync_2() {
    let mut w = World::new();
    let host = w.add_host();
    let (a, card) = Osis::create(w.cfg(1, &[])).unwrap();
    assert!(card.is_none());
    w.run();
    assert_eq!(a.status().unwrap().groups[&a.me()].state, SyncState::NoHosts);
    a.add_host(&w.addr(host).unwrap()).unwrap();
    w.run();
    assert_eq!(a.status().unwrap().groups[&a.me()].state, SyncState::Synced);
    let inbox = a.at(a.me(), osis::core::KEYS).get().unwrap().unwrap().inbox.unwrap();
    assert_eq!(inbox.hosts.len(), 1);
    w.until(a.wait_synced(SyncScope::All, Duration::from_secs(10)), 1000, 10).unwrap();
    a.remove_host(&w.addr(host).unwrap()).unwrap();
    w.run();
    assert_eq!(a.status().unwrap().groups[&a.me()].state, SyncState::NoHosts);
}

// notes/api.md Sync status (`wait_synced(All)` leaves `NoHosts` groups out): Carol has no
// hosts (her home is `NoHosts`) and joined Alice's hosted group by a link; Alice's later
// write reaches her through `wait_synced(All)`, while `Group(home)` still fails `Unsynced`.
// spec: none (API surface, notes/api.md)
#[test]
fn wait_synced_all_skips_hostless_groups() {
    let mut w = World::new();
    let (alice, _, _) = people(&mut w, 0);
    let g = group(&alice);
    let link = alice.make_link(g, Role::Write, osis::LinkOpts::default()).unwrap();
    w.run();
    let carol = Osis::create(w.cfg(9, &[])).unwrap().0;
    w.run();
    assert_eq!(w.until(carol.redeem(&link), 1000, 10).unwrap(), g);
    w.run();
    assert_eq!(carol.status().unwrap().groups[&carol.me()].state, SyncState::NoHosts);
    let t = item(&alice, g, g, "after the redeem");
    w.until(alice.wait_synced(SyncScope::All, Duration::from_secs(10)), 1000, 10).unwrap();
    w.until(carol.wait_synced(SyncScope::All, Duration::from_secs(10)), 1000, 10).unwrap();
    assert_eq!(x(&carol, t), Some(s("after the redeem")));
    assert!(matches!(w.until(carol.wait_synced(SyncScope::Group(carol.me()), Duration::from_secs(10)), 1000, 10), Err(osis::Error::Unsynced { .. })));
}

// notes/api.md Sync status (`wait_synced` scopes the deliveries): Bob's inbox is on a host
// Alice cannot reach, so her grant to him stays queued; `Group(other)` resolves meanwhile,
// `Group(g)` and `All` wait for it until the host is back.
// spec: none (API surface, notes/api.md)
#[test]
fn wait_synced_scopes_deliveries() {
    let mut w = World::new();
    let (h1, h2) = (w.add_host(), w.add_host());
    let (alice, _) = w.person(1, &[h1]);
    let (bob, _) = w.person(2, &[h2]);
    w.run();
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let (g, other) = (group(&alice), group(&alice));
    w.run();
    w.set_reachable(&alice, h2, false);
    alice.grant(g, b, Role::Read, Default::default()).unwrap();
    item(&alice, other, other, "unrelated");
    let short = Duration::from_secs(5);
    w.until(alice.wait_synced(SyncScope::Group(other), short), 1000, 10).unwrap();
    assert!(matches!(w.until(alice.wait_synced(SyncScope::Group(g), short), 1000, 10), Err(osis::Error::Network(_))));
    assert!(matches!(w.until(alice.wait_synced(SyncScope::All, short), 1000, 10), Err(osis::Error::Network(_))));
    w.set_reachable(&alice, h2, true);
    w.until(alice.wait_synced(SyncScope::All, Duration::from_secs(120)), 1000, 130).unwrap();
}

// notes/api.md Sync status (`wait_synced(All)` waits on every label with hosts): Carol's group
// has a hostless label and, after `unsync` and `sync` with a host, a hosted one; the group
// shows `NoHosts`, yet `All` waits for her write under the hosted label.
// spec: none (API surface, notes/api.md)
#[test]
fn wait_synced_all_waits_on_hosted_label_of_mixed_group() {
    let mut w = World::new();
    let h = w.add_host();
    let carol = Osis::create(w.cfg(9, &[])).unwrap().0;
    w.run();
    let g = group(&carol);
    carol.unsync(g).unwrap();
    carol.sync(g, &[w.addr(h).unwrap()]).unwrap();
    w.run();
    let st = carol.status().unwrap().groups[&g].clone();
    assert_eq!((st.state, st.labels.len()), (SyncState::NoHosts, 2), "a hostless and a hosted label");
    w.until(carol.wait_synced(SyncScope::All, Duration::from_secs(10)), 1000, 10).unwrap();
    // the hostless one is replaced (it takes nothing until it retires): `Group(g)` fails only
    // on her hostless home, which holds `g`
    let r = w.until(carol.wait_synced(SyncScope::Group(g), Duration::from_secs(10)), 1000, 10);
    assert!(matches!(&r, Err(osis::Error::Unsynced { groups }) if *groups == [carol.me()]), "{r:?}");
    w.set_reachable(&carol, h, false);
    item(&carol, g, g, "while cut off");
    assert!(matches!(w.until(carol.wait_synced(SyncScope::All, Duration::from_secs(5)), 1000, 10), Err(osis::Error::Network(_))));
    w.set_reachable(&carol, h, true);
    w.until(carol.wait_synced(SyncScope::All, Duration::from_secs(120)), 1000, 130).unwrap();
}

// notes/api.md Sync status (`All` waits for every delivery): Carol syncs no label with hosts;
// her grant on her hostless group to Bob is queued for his inbox host, which she cannot
// reach: `All` does not resolve before it lands, `Group(g)` fails `Unsynced` (Bob can never
// fetch `g`).
// spec: none (API surface, notes/api.md)
#[test]
fn wait_synced_all_waits_for_deliveries_without_hosted_groups() {
    let mut w = World::new();
    let h = w.add_host();
    let (bob, _) = w.person(2, &[h]);
    let carol = Osis::create(w.cfg(9, &[])).unwrap().0;
    w.run();
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(carol.import_contact(&card), 1000, 10).unwrap();
    let g = group(&carol);
    w.run();
    w.set_reachable(&carol, h, false);
    // the groups learned from Bob's card held for receipts only: no label of hers with hosts
    // is synced
    for (h, _) in carol.status().unwrap().groups.into_iter().filter(|(_, s)| s.state != SyncState::NoHosts) {
        carol.sync_policy(h, osis::GroupPolicy { receipts_only: true, ..Default::default() }).unwrap();
    }
    carol.grant(g, b, Role::Read, Default::default()).unwrap();
    assert!(matches!(w.until(carol.wait_synced(SyncScope::All, Duration::from_secs(5)), 1000, 10), Err(osis::Error::Network(_))));
    assert!(matches!(w.until(carol.wait_synced(SyncScope::Group(g), Duration::from_secs(5)), 1000, 10), Err(osis::Error::Unsynced { .. })));
    w.set_reachable(&carol, h, true);
    w.until(carol.wait_synced(SyncScope::All, Duration::from_secs(120)), 1000, 130).unwrap();
}

// notes/api.md Sync configuration (`add_host` scope), spec/sync.md §2: Alice's host changes
// move her home label and her own shared group, not a group Bob owns that she co-administers,
// not her link's actor (the link text names its hosts); her shared group keeps its last
// host.
#[test]
fn add_host_scope_spec_sync_2() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let (s0, s1) = (0, w.add_host());
    let bob = &others[0];
    let card = alice.contact_card().unwrap();
    w.run();
    let a = w.until(bob.import_contact(&card), 1000, 10).unwrap();
    let mine = group(&alice);
    alice.grant(mine, ids[0], Role::Write, Default::default()).unwrap();
    let his = group(bob);
    bob.grant(his, a, Role::Admin, Default::default()).unwrap();
    w.run();
    assert_eq!(alice.role_on(his).unwrap(), Some(Role::Admin));
    alice.make_link(mine, Role::Read, osis::LinkOpts::default()).unwrap();
    let k = alice.links_of(mine).unwrap()[0].id;
    w.run();
    let hosts = |g: Tid| alice.engine(|e| e.group_labels(&g).unwrap().into_iter().find(|l| !l.replaced).unwrap().hosts.len());
    alice.add_host(&w.addr(s1).unwrap()).unwrap();
    w.run();
    assert_eq!((hosts(alice.me()), hosts(mine), hosts(his), hosts(k)), (2, 2, 1, 1));
    alice.remove_host(&w.addr(s0).unwrap()).unwrap();
    alice.remove_host(&w.addr(s1).unwrap()).unwrap();
    w.run();
    assert_eq!((hosts(alice.me()), hosts(mine), hosts(his), hosts(k)), (0, 1, 1, 1), "a shared group keeps its last host");
}

// spec/crdt.md §2.1 (a session per open): a device restored from a backup of its store keeps
// its signing key; it writes at once under a new session, so the commits written after the
// backup (which the pass brings back) and its new ones never share a source: nothing is void
// (spec/commits.md §4) and every write stands, at the device, its peers and a fresh device.
// (see also `reopen_under_one_seed_draws_a_new_session_spec_crdt_2_1`)
#[test]
fn restored_store_writes_at_once_spec_crdt_2_1() {
    let mut w = World::new();
    let host = w.add_host();
    let cfg = w.cfg(1, &[host]);
    let osis::StoreAt::Memory(store) = &cfg.store else { unreachable!() };
    let store = store.clone();
    let (a, card) = Osis::create(cfg).unwrap();
    w.run();
    let t = item(&a, a.me(), a.me(), "before the backup");
    let u = item(&a, a.me(), a.me(), "other before the backup");
    w.run();
    let backup = store.backup();
    for v in ["after the backup 1", "after the backup 2"] {
        a.commit_set(t, ak("t:x.0"), &s(v)).unwrap();
        a.commit_set(u, ak("t:x.0"), &s(v)).unwrap();
    }
    w.run();
    w.until(a.wait_synced(SyncScope::All, Duration::from_secs(60)), 1000, 10).unwrap();
    let node = a.node();
    let lost = commit_with(&a, |wr| wr.at(u, ak("t:x.0")).set(&s("after the backup 3"))).id.commit().unwrap();
    w.run();
    assert_eq!(a.close().unwrap(), osis::Close::Closed);
    w.advance(1000);

    let mut rc = w.cfg(2, &[host]);
    rc.store = osis::StoreAt::Memory(backup);
    let b = Osis::open(rc).unwrap();
    assert_eq!(b.node(), node, "the same device identity");
    assert_eq!(x(&b, t), Some(s("before the backup")), "the backup's state");
    // written before any pass: session form, a new session
    let first = commit_with(&b, |wr| wr.at(t, ak("t:x.0")).set(&s("restored"))).id.commit().unwrap();
    let form = |db: &Osis, c| db.engine(|e| e.header(&c).unwrap().form);
    assert!(matches!(form(&b, first), osis_commit::Form::Session(_)));
    // an undo before the pass too: of a creation, which also edits the home group's `group.0`
    let v = item(&b, b.me(), b.me(), "made after the restore");
    let undo = b.undo(&osis::Scope::Thing(v)).unwrap().unwrap().id.commit().unwrap();
    assert!(matches!(form(&b, undo), osis_commit::Form::Session(_)));
    assert_eq!(x(&b, v), None);
    w.run();
    assert_eq!(x(&b, t), Some(s("restored")), "the restored write stands");
    assert_eq!(x(&b, u), Some(s("after the backup 3")), "the lost writes came back");
    assert_ne!(form(&b, lost), form(&b, first), "the lost commits are another session's");
    let next = commit_with(&b, |wr| wr.at(u, ak("t:x.0")).set(&s("restored, caught up"))).id.commit().unwrap();
    assert_eq!(form(&b, next), form(&b, first), "one session per open");
    w.run();
    assert_eq!(x(&b, u), Some(s("restored, caught up")));
    let diags = w.diagnostics(&b);
    assert!(!diags.iter().any(|d| d.starts_with("OverlappingCounters")), "{diags:?}");
    // a fresh device of the person reads every write
    let card = card.unwrap();
    let c = w.until(Osis::restore(w.cfg(3, &[]), &card), 1000, 10).unwrap();
    w.run();
    assert_eq!((x(&c, t), x(&c, u), x(&c, v)), (Some(s("restored")), Some(s("restored, caught up")), None));
    assert!(!c.groups_of(v).unwrap().item_of.contains(&c.me()), "the undone creation left the home group");
}

/// A thing of `db`'s person with `t:x.0` = `v`, placed nowhere.
fn plain(db: &Osis, v: &str) -> Tid {
    db.batch(|w| {
        let t = w.create(db.me())?;
        w.at(t, ak("t:x.0")).set(&s(v))?;
        Ok(t)
    })
    .unwrap()
}

/// The holders `status` at `db` lists as without a route to `t` (`SyncState::NoRoute`); empty
/// when every holder has one.
fn unrouted(db: &Osis, t: Tid) -> Vec<Tid> {
    db.status().unwrap().groups.get(&t).filter(|g| g.state == SyncState::NoRoute).map(|g| g.unrouted.clone()).unwrap_or_default()
}

fn no_routes(db: &Osis) -> bool {
    db.status().unwrap().groups.values().all(|g| g.state != SyncState::NoRoute)
}

// spec/sync.md §2 (Route), §3: a grant on a thing placed nowhere records the role and no more: the holder holds it, reads nothing, and both sides show him without a route; `sync` then gives the thing a label, delivered to him, and he reads and writes; a later holder of the labeled thing needs no second label
#[test]
fn a_grant_then_a_sync_gives_the_route() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 2);
    let (bob, carol) = (&others[0], &others[1]);
    let t = plain(&alice, "for bob");
    alice.grant(t, ids[0], Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(x(bob, t), None);
    assert_eq!(bob.roster(t).unwrap().get(&ids[0]).map(|e| e.role), Some(Role::Write), "the role is held: the blob carried the granter's chain");
    assert_eq!(unrouted(&alice, t), vec![ids[0]]);
    assert_eq!(unrouted(bob, t), vec![ids[0]]);
    assert!(alice.status().unwrap().groups[&t].labels.is_empty(), "no label on a grant");
    alice.sync(t, &[]).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("for bob")));
    assert!(unrouted(&alice, t).is_empty() && unrouted(bob, t).is_empty());
    assert_eq!(bob.status().unwrap().groups[&t].state, SyncState::Synced);
    bob.commit_set(t, ak("t:x.0"), &s("from bob")).unwrap();
    w.run();
    assert_eq!(x(&alice, t), Some(s("from bob")));
    let label = alice.status().unwrap().groups[&t].labels.clone();
    assert_eq!(label.len(), 1);
    alice.grant(t, ids[1], Role::Read, Default::default()).unwrap();
    assert!(unrouted(&alice, t).is_empty(), "a labeled thing is a route for every holder");
    w.run();
    assert_eq!(x(carol, t), Some(s("from bob")));
    assert_eq!(alice.status().unwrap().groups[&t].labels, label);
}

// spec/sync.md §2: synced first, then granted: a route from the start
#[test]
fn a_sync_then_a_grant() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let t = plain(&alice, "for bob");
    alice.sync(t, &[]).unwrap();
    alice.grant(t, ids[0], Role::Read, Default::default()).unwrap();
    assert!(unrouted(&alice, t).is_empty());
    w.run();
    assert_eq!(x(&others[0], t), Some(s("for bob")));
    assert!(unrouted(&others[0], t).is_empty());
}

// spec/sync.md §2 (Route), notes/api.md Sharing: `share` syncs the thing only when the holder reads no label carrying it; a holder who reads a label that carries it, this node's own client on this person's thing, need none
#[test]
fn share_syncs_only_when_the_holder_has_no_route() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 2);
    let g = group(&alice);
    alice.grant(g, ids[0], Role::Read, Default::default()).unwrap();
    let t = item(&alice, g, g, "in g");
    w.run();
    assert_eq!(x(&others[0], t), Some(s("in g")));
    alice.share(t, ids[0], Role::Write, Default::default()).unwrap();
    assert!(!alice.status().unwrap().groups.contains_key(&t), "bob reads g, which carries it");
    alice.share(t, ids[1], Role::Read, Default::default()).unwrap();
    assert!(alice.status().unwrap().groups.contains_key(&t), "carol reads no label of it: synced");
    w.run();
    assert_eq!(x(&others[1], t), Some(s("in g")));
    let u = plain(&alice, "local");
    let (a, _) = alice.add_client(None).unwrap();
    alice.share(u, a, Role::Read, Default::default()).unwrap();
    assert!(!alice.status().unwrap().groups.contains_key(&u), "a client reads what this node holds");
    assert!(matches!(alice.share(u, Tid::from_bytes([9; 15]), Role::Read, Default::default()), Err(osis::Error::UnknownActor { .. })));
    assert!(!alice.status().unwrap().groups.contains_key(&u), "nothing synced for a refused share");
}

// spec/sync.md §2: `unsync` after a share cuts the route, shown at both sides; synced again, the new label reaches the holder
#[test]
fn an_unsync_after_a_share_cuts_the_route() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let bob = &others[0];
    let t = plain(&alice, "one");
    alice.share(t, ids[0], Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("one")));
    alice.unsync(t).unwrap();
    w.run();
    assert_eq!(unrouted(&alice, t), vec![ids[0]]);
    assert_eq!(unrouted(bob, t), vec![ids[0]]);
    alice.commit_set(t, ak("t:x.0"), &s("two")).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("one")), "nothing carries the write");
    alice.sync(t, &[]).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("two")));
    assert!(unrouted(&alice, t).is_empty() && unrouted(bob, t).is_empty());
}

// spec/sync.md §2: a thing leaving the group that carried it leaves its holder with the role and no route; placed back, the route is back
#[test]
fn a_thing_leaving_its_group_loses_the_route() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let bob = &others[0];
    let g = group(&alice);
    alice.grant(g, ids[0], Role::Read, Default::default()).unwrap();
    let t = item(&alice, g, g, "in g");
    alice.grant(t, ids[0], Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("in g")));
    assert!(unrouted(&alice, t).is_empty() && unrouted(bob, t).is_empty());
    alice.batch(|w| w.unplace(t, g)).unwrap();
    w.run();
    assert_eq!(unrouted(&alice, t), vec![ids[0]]);
    assert_eq!(unrouted(bob, t), vec![ids[0]]);
    alice.batch(|w| w.place(t, g)).unwrap();
    w.run();
    assert!(unrouted(&alice, t).is_empty() && unrouted(bob, t).is_empty());
    alice.commit_set(t, ak("t:x.0"), &s("back")).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("back")));
}

// spec/sync.md §2: kicked from the group but keeping an edge on its item: the role stays, the route goes, `sync` of the item brings one
#[test]
fn losing_the_group_but_keeping_the_edge_loses_the_route() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let bob = &others[0];
    let g = group(&alice);
    alice.grant(g, ids[0], Role::Read, Default::default()).unwrap();
    let t = item(&alice, g, g, "in g");
    alice.grant(t, ids[0], Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("in g")));
    w.until(alice.demote(g, ids[0], Lower::Remove, skip()), 1000, 10).unwrap();
    w.run();
    assert!(bob.roster(t).unwrap().contains_key(&ids[0]) && !bob.roster(g).unwrap().contains_key(&ids[0]));
    assert_eq!(unrouted(&alice, t), vec![ids[0]]);
    assert_eq!(unrouted(bob, t), vec![ids[0]]);
    alice.commit_set(t, ak("t:x.0"), &s("after")).unwrap();
    alice.sync(t, &[]).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("after")));
    assert!(unrouted(&alice, t).is_empty() && unrouted(bob, t).is_empty());
}

// spec/sync.md §2 (owner's example): T in synced G shared with Bob alone, who reads no part of G: a plain grant leaves him without a route (a reader of T alone cannot open G's label); `share` gives T its own label
#[test]
fn a_thing_in_a_synced_group_shared_with_an_outsider() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let bob = &others[0];
    let g = group(&alice);
    let t = item(&alice, g, g, "in g");
    alice.grant(t, ids[0], Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(bob, t), None);
    assert_eq!(unrouted(&alice, t), vec![ids[0]]);
    assert_eq!(unrouted(bob, t), vec![ids[0]]);
    assert!(!bob.knows(g).unwrap());
    alice.share(t, ids[0], Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("in g")));
    assert!(unrouted(&alice, t).is_empty() && unrouted(bob, t).is_empty());
    assert!(!bob.knows(g).unwrap(), "G's label stays closed to him");
}

// spec/sync.md §2, spec/permissions.md §8: a link to a thing placed nowhere resolves: the link syncs the thing (K reads its label alone), redeem returns and the thing reads
#[test]
fn a_link_to_a_plain_item_resolves() {
    let mut w = World::new();
    let (alice, others, _) = people(&mut w, 1);
    let t = plain(&alice, "linked");
    let link = alice.make_link(t, Role::Read, Default::default()).unwrap();
    assert!(alice.status().unwrap().groups.contains_key(&t));
    w.run();
    assert_eq!(w.until(others[0].redeem(&link), 2000, 10).unwrap(), t);
    w.run();
    assert_eq!(x(&others[0], t), Some(s("linked")));
}

// spec/sync.md §2: a thing owned by someone else: an admin by an edge shares it (the label on his hosts); an invite edge alone grants the role, cannot sync (`share` says so and writes nothing) and leaves the holder without a route
#[test]
fn a_grant_on_someone_elses_item() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 3);
    let (bob, carol, dan) = (&others[0], &others[1], &others[2]);
    let g = group(&alice);
    alice.grant(g, ids[0], Role::Read, Default::default()).unwrap();
    alice.grant(g, ids[1], Role::Read, Default::default()).unwrap();
    let shared = |v: &str| {
        let t = plain(&alice, v);
        alice.share_into(t, g, Role::Read, Default::default()).unwrap();
        t
    };
    let t = shared("alice's");
    alice.grant(t, ids[0], Role::Admin, Default::default()).unwrap();
    let u = shared("invite");
    alice.grant(u, ids[1], Role::Read, osis::EdgeOpts { invite: Some(Role::Read), ..Default::default() }).unwrap();
    assert!(!alice.status().unwrap().groups.contains_key(&t), "both read g");
    let card = dan.contact_card().unwrap();
    w.run();
    let d = w.until(carol.import_contact(&card), 1000, 10).unwrap();
    w.until(bob.import_contact(&card), 1000, 10).unwrap();
    w.run();
    let r = carol.share(u, d, Role::Read, Default::default());
    assert!(matches!(r, Err(osis::Error::Permission { tid, .. }) if tid == u), "{r:?}");
    assert!(!carol.roster(u).unwrap().contains_key(&d), "nothing written");
    carol.grant(u, d, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(unrouted(carol, u), vec![d]);
    assert_eq!(x(dan, u), None);
    bob.share(t, d, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(dan, t), Some(s("alice's")));
    assert!(unrouted(bob, t).is_empty());
}

// spec/sync.md §3: a grant to a group, the item placed nowhere: the admin's copy under the group's label tells its readers of the role and the missing route; `sync` of the item is delivered to the group and copied too, so they read it, a later reader as well; no placement, nothing split; and the edge's end reaches them
#[test]
fn a_grant_to_a_group_reaches_its_readers() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 2);
    let (bob, carol) = (&others[0], &others[1]);
    let h = group(&alice);
    alice.grant(h, ids[0], Role::Read, Default::default()).unwrap();
    w.run();
    let t = plain(&alice, "for h");
    alice.grant(t, h, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(bob, t), None);
    assert!(bob.roster(t).unwrap().contains_key(&h), "the group's reader learns the role under its label");
    assert_eq!(unrouted(&alice, t), vec![h]);
    assert_eq!(unrouted(bob, t), vec![h]);
    alice.sync(t, &[]).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("for h")));
    assert!(unrouted(&alice, t).is_empty() && unrouted(bob, t).is_empty());
    assert!(bob.groups_of(t).unwrap().item_of.is_empty() && alice.groups_of(t).unwrap().item_of.is_empty(), "no placement");
    assert!(bob.status().unwrap().split.is_empty() && alice.status().unwrap().split.is_empty());
    assert!(write_refused(bob, t), "read only");
    alice.commit_set(t, ak("t:x.0"), &s("later")).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("later")));
    // a later reader finds it under the group's label
    alice.grant(h, ids[1], Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(carol, t), Some(s("later")));
    // and the edge's end reaches them
    w.until(alice.demote(t, h, Lower::Remove, Demotion { sync: osis::WaitForSync::Skip, ..Default::default() }), 1000, 10).unwrap();
    w.run();
    alice.commit_set(t, ak("t:x.0"), &s("after")).unwrap();
    w.run();
    assert_ne!(x(bob, t), Some(s("after")));
    assert_ne!(x(carol, t), Some(s("after")));
}

// spec/sync.md §3: the grant's blob long gone from the group's inbox, the thing's first `label.0` write comes as a blob of its own and the admin copies the label from it: a sync long after the grant still reaches the group's readers
#[test]
fn a_sync_long_after_the_grant_reaches_the_groups_readers() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let bob = &others[0];
    let h = group(&alice);
    alice.grant(h, ids[0], Role::Read, Default::default()).unwrap();
    w.run();
    let t = plain(&alice, "for h");
    alice.grant(t, h, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(unrouted(bob, t), vec![h]);
    for _ in 0..4 {
        w.advance(osis::schema::osis_base::format::INBOX_LIFETIME_MS / 2 + 3_600_000);
        w.run();
    }
    assert_eq!(x(bob, t), None);
    alice.sync(t, &[]).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("for h")));
    assert!(unrouted(bob, t).is_empty());
}

// spec/sync.md §3: a co-admin who never met the group syncs the thing: no blob reaches the group (he cannot seal to it), but the owner's device learns the label under a group that carries the thing and copies it from the grant's blob: the group's readers read
#[test]
fn a_sync_by_a_co_admin_who_never_met_the_group_reaches_its_readers() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 2);
    let (bob, carol) = (&others[0], &others[1]);
    let h = group(&alice);
    alice.grant(h, ids[0], Role::Read, Default::default()).unwrap();
    let g2 = group(&alice);
    alice.grant(g2, ids[1], Role::Read, Default::default()).unwrap();
    let t = item(&alice, g2, g2, "in g2");
    alice.grant(t, ids[1], Role::Admin, Default::default()).unwrap();
    w.run();
    assert_eq!(x(carol, t), Some(s("in g2")));
    alice.grant(t, h, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(unrouted(bob, t), vec![h], "bob reads h, not g2");
    assert!(!carol.knows(h).unwrap());
    carol.sync(t, &[]).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("in g2")));
    assert!(unrouted(bob, t).is_empty() && unrouted(&alice, t).is_empty());
}

// spec/sync.md §2 (Home label): a grant to one's own group with no label records the role; the group's readers (there are none yet) have no route until `sync`; synced, the group's label carries the copy and its items
#[test]
fn a_grant_to_a_group_with_no_label() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let bob = &others[0];
    let h = alice.batch(|w| {
        let g = w.create(alice.me())?;
        w.make_group(g)?;
        Ok(g)
    })
    .unwrap();
    let private = alice.batch(|w| {
        let t = w.create_in(h, &[h])?;
        w.at(t, ak("t:x.0")).set(&s("private"))?;
        Ok(t)
    })
    .unwrap();
    let t = plain(&alice, "before");
    alice.grant(t, h, Role::Read, Default::default()).unwrap();
    assert!(!alice.status().unwrap().groups.contains_key(&h), "not lifted");
    assert!(unrouted(&alice, t).is_empty(), "nobody but Alice reads her group: nothing is missed");
    alice.grant(h, ids[0], Role::Read, Default::default()).unwrap();
    assert_eq!(unrouted(&alice, t), vec![h], "Bob reads it, and nothing carries it");
    assert_eq!(unrouted(&alice, h), vec![ids[0]]);
    alice.sync(h, &[]).unwrap();
    alice.sync(t, &[]).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("before")));
    assert_eq!(x(bob, private), Some(s("private")));
}

// spec/sync.md §2 (Route): a thing placed in a synced group its actor may not read is not carried there (it is excluded): a holder who reads the group has no route to it, the status says so, and `share` makes the route
#[test]
fn an_excluded_thing_is_no_route_through_its_group() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let bob = &others[0];
    let g = alice.batch(|w| {
        let g = w.create(alice.me())?;
        w.make_group(g)?;
        Ok(g)
    })
    .unwrap();
    alice.sync(g, &[]).unwrap();
    alice.grant(g, ids[0], Role::Read, Default::default()).unwrap();
    w.run();
    let t = plain(&alice, "excluded");
    alice.batch(|w| w.place(t, g)).unwrap();
    alice.grant(t, ids[0], Role::Read, Default::default()).unwrap();
    w.run();
    w.advance(120_000);
    w.run();
    assert_eq!(x(bob, t), None);
    assert_eq!(unrouted(&alice, t), vec![ids[0]], "the granter");
    assert_eq!(unrouted(bob, t), vec![ids[0]], "the holder");
    alice.share(t, ids[0], Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("excluded")));
}

// spec/sync.md §2 (Route): a subgroup holding an item, the subgroup synced only through its parent: the parent's readers read the item through it, so nobody lacks a route (the subgroup's edge is what looks unrouted: it reads no label, the label reads it)
#[test]
fn a_holder_read_through_a_synced_group_has_a_route() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let bob = &others[0];
    let group = |text: &str| {
        alice
            .batch(|w| {
                let g = w.create(alice.me())?;
                w.make_group(g)?;
                w.at(g, ak("t:x.0")).set(&s(text))?;
                Ok(g)
            })
            .unwrap()
    };
    let g = group("parent");
    alice.sync(g, &[]).unwrap();
    alice.grant(g, ids[0], Role::Read, Default::default()).unwrap();
    let sub = group("sub");
    let t = plain(&alice, "deep");
    alice.share_into(sub, g, Role::Read, osis::ShareOpts { subgroup: true, ..Default::default() }).unwrap();
    alice.share_into(t, sub, Role::Read, Default::default()).unwrap();
    alice.batch(|w| w.place(sub, g)).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("deep")));
    assert!(unrouted(&alice, t).is_empty() && unrouted(bob, t).is_empty());
    assert!(unrouted(&alice, sub).is_empty() && unrouted(bob, sub).is_empty());
}

// spec/sync.md §2 (Route): what nobody misses shows no missing route: an ownerless thing and a local group's items here, at their only reader; a thing a removed reader's node still holds the roster of; a thing whose roster reached a reader as a writer's chain, its label unknown there
#[test]
fn no_missing_route_where_nobody_misses_one() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 2);
    let (bob, frank) = (&others[0], &others[1]);
    let o = alice.create_ownerless(alice.me()).unwrap();
    w.run();
    assert!(unrouted(&alice, o).is_empty(), "local, as any thing placed nowhere");
    let p = crate::scenario::private_tag(&alice, "private").unwrap();
    let t = plain(&alice, "tagged");
    alice.share_into(t, p, Role::Read, Default::default()).unwrap();
    w.run();
    assert!(unrouted(&alice, t).is_empty(), "a private tag in home");
    // a group Bob leaves behind: he read its item; he has no business with its route now
    let g = alice.batch(|w| {
        let g = w.create(alice.me())?;
        w.make_group(g)?;
        Ok(g)
    })
    .unwrap();
    alice.sync(g, &[]).unwrap();
    alice.grant(g, ids[0], Role::Read, Default::default()).unwrap();
    let item = plain(&alice, "item");
    alice.share_into(item, g, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(bob, item), Some(s("item")));
    w.until(alice.demote(g, ids[0], osis::Lower::Remove, osis::Demotion { sync: osis::WaitForSync::Skip, ..Default::default() }), 1000, 20).unwrap();
    w.run();
    w.advance(120_000);
    w.run();
    assert_eq!(x(bob, item), None);
    assert!(unrouted(bob, item).is_empty(), "no business of Bob's now");
    assert!(no_routes(bob));
    // a writer's chain through a thing whose label Bob does not read
    let owner = alice.batch(|w| {
        let g = w.create(alice.me())?;
        w.make_group(g)?;
        Ok(g)
    })
    .unwrap();
    alice.sync(owner, &[]).unwrap();
    alice.grant(owner, ids[1], Role::Admin, Default::default()).unwrap();
    w.run();
    let shared = alice
        .batch(|w| {
            let c = w.create(owner)?;
            w.at(c, ak("t:x.0")).set(&s("shared"))?;
            Ok(c)
        })
        .unwrap();
    alice.sync(shared, &[]).unwrap();
    alice.grant(shared, ids[0], Role::Read, Default::default()).unwrap();
    w.run();
    frank.commit_set(shared, ak("t:x.0"), &s("by frank")).unwrap();
    w.run();
    w.advance(120_000);
    w.run();
    assert_eq!(x(bob, shared), Some(s("by frank")));
    assert!(no_routes(bob), "Frank's edge on the owner reached Bob as his chain");
}

// spec/sync.md §2, notes/api.md (`wait_synced`): a thing with no route has no label to wait for: `Unsynced` at once, not a wait for its row in the status
#[test]
fn waiting_on_a_thing_with_no_route_fails_at_once() {
    let mut w = World::new();
    let (alice, _, ids) = people(&mut w, 1);
    let t = plain(&alice, "t");
    alice.grant(t, ids[0], Role::Read, Default::default()).unwrap();
    let f = alice.wait_synced(SyncScope::Group(t), std::time::Duration::from_secs(3600));
    assert!(matches!(w.until(f, 1, 1), Err(osis::Error::Unsynced { .. })));
}

// spec/sync.md §2: a grant to a node that reads nothing of the thing is recorded and shown without a route (no inbox can tell it; a node is reached through its person); one that reads it sees the edge
#[test]
fn a_grant_to_a_bare_node() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let bob = &others[0];
    let t = plain(&alice, "t");
    alice.grant(t, bob.node(), Role::Read, Default::default()).unwrap();
    assert!(alice.roster(t).unwrap().contains_key(&bob.node()));
    assert_eq!(unrouted(&alice, t), vec![bob.node()]);
    alice.share(t, ids[0], Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("t")));
    assert!(unrouted(&alice, t).is_empty(), "its person reads it");
    alice.grant(t, bob.node(), Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(bob.roster(t).unwrap().get(&bob.node()).map(|e| e.role), Some(Role::Write));
}

// spec/permissions.md §1, spec/sync.md §2: an ownerless group's inbox is its own label: its readers read the grant from there, and the admin's copy serves later ones
#[test]
fn a_grant_to_an_ownerless_group() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 2);
    let (bob, carol) = (&others[0], &others[1]);
    let f = alice.create_ownerless(alice.me()).unwrap();
    alice.sync(f, &[]).unwrap();
    alice.grant(f, ids[0], Role::Read, Default::default()).unwrap();
    w.run();
    let t = plain(&alice, "for f");
    alice.share(t, f, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("for f")));
    alice.grant(f, ids[1], Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(carol, t), Some(s("for f")));
}

// spec/sync.md §3: a reader's share to an ownerless group reaches the other readers from its inbox with the admin offline; only an admin copies it, so what the label takes is the same with more readers
#[test]
fn a_grant_to_a_group_is_copied_only_by_its_admin() {
    let took = |readers: usize| {
        let mut w = World::new();
        let (alice, others, ids) = people(&mut w, readers);
        let f = alice.create_ownerless(alice.me()).unwrap();
        alice.sync(f, &[]).unwrap();
        for id in &ids {
            alice.grant(f, *id, Role::Read, Default::default()).unwrap();
        }
        w.run();
        w.set_online(&alice, false);
        let label = alice.status().unwrap().groups[&f].labels[0];
        let log = |w: &World| osis_proto::store::LabelStore::log_head(w.hosts[0].hub.store(), &label).unwrap().1;
        let before = log(&w);
        let t = plain(&others[0], "for f");
        others[0].share(t, f, Role::Read, Default::default()).unwrap();
        w.run();
        for o in &others {
            assert_eq!(x(o, t), Some(s("for f")));
        }
        log(&w) - before
    };
    assert_eq!(took(2), took(4));
}

// spec/sync.md §3, notes/chat-designs/e-realms.md: realms nest by grants to groups: a reader of the top reads the child and what the child holds, whichever grant came first
#[test]
fn grants_to_groups_nest() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let bob = &others[0];
    let (p, k) = (group(&alice), group(&alice));
    let t = plain(&alice, "in k");
    alice.share(t, k, Role::Read, Default::default()).unwrap();
    alice.grant(k, p, Role::Read, Default::default()).unwrap();
    w.run();
    alice.grant(p, ids[0], Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("in k")));
    let u = plain(&alice, "later in k");
    alice.share(u, k, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(bob, u), Some(s("later in k")));
}

// spec/sync.md §2: an ownerless group's label is its inbox, with every chunk of its content: a reader tries none of them as an inbox blob
#[test]
fn chunks_under_an_inbox_label_cost_no_kem() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let bob = &others[0];
    let f = alice.create_ownerless(alice.me()).unwrap();
    alice.sync(f, &[]).unwrap();
    alice.grant(f, ids[0], Role::Read, Default::default()).unwrap();
    w.run();
    let before = bob.sync_engine(|e| e.pass_stats().inbox_tries);
    let big: String = (0..3_000_000u32).map(|i| char::from(b'a' + ((i.wrapping_mul(2654435761) >> 13) % 26) as u8)).collect();
    let t = alice
        .batch(|w| {
            let t = w.create_in(f, &[f])?;
            w.at(t, ak("t:x.0")).set(&Value::Str(big.clone()))?;
            Ok(t)
        })
        .unwrap();
    w.run();
    assert!(x(bob, t).is_some());
    assert_eq!(bob.sync_engine(|e| e.pass_stats().inbox_tries), before);
}

// spec/sync.md §3, spec/wire.md §9: a grant to a group by someone who reads no part of it: the inbox blob carries his chain, so the group's admin applies it with the thing still unsynced and copies it, and a reader who never met him verifies it; synced later, they read it
#[test]
fn a_grant_to_a_group_by_an_outsider() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 2);
    let (bob, dave) = (&others[0], &others[1]);
    let h = group(&alice);
    // dave learns the group's keys and meets alice through a thing the group held, and is gone before bob comes
    let m = plain(&alice, "meeting");
    alice.share(m, h, Role::Read, Default::default()).unwrap();
    alice.share(m, ids[1], Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(dave, m), Some(s("meeting")));
    w.until(alice.demote(m, h, Lower::Remove, Demotion { sync: osis::WaitForSync::Skip, ..Default::default() }), 1000, 10).unwrap();
    w.run();
    let t = plain(dave, "dave's");
    dave.grant(t, h, Role::Read, Default::default()).unwrap();
    w.run();
    assert!(alice.invite_requests().unwrap().is_empty(), "connected");
    assert!(alice.roster(t).unwrap().contains_key(&h), "applied without a label of the thing");
    assert_eq!(unrouted(&alice, t), vec![h]);
    alice.grant(h, ids[0], Role::Read, Default::default()).unwrap();
    w.run();
    assert!(bob.roster(t).unwrap().contains_key(&h), "copied under the group's label with his chain");
    dave.sync(t, &[]).unwrap();
    w.run();
    assert_eq!(x(&alice, t), Some(s("dave's")));
    assert_eq!(x(bob, t), Some(s("dave's")));
    assert!(unrouted(&alice, t).is_empty() && unrouted(bob, t).is_empty());
}

// spec/sync.md §2: a grant to a holder whose inbox is not known here (an outsider knows the ownerless group's keys, not its label) is recorded all the same: nothing can tell the holder, and `status` shows it without a route
#[test]
fn a_grant_to_a_holder_nothing_reaches() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let dave = &others[0];
    let f = alice.create_ownerless(alice.me()).unwrap();
    alice.sync(f, &[]).unwrap();
    let m = plain(&alice, "meeting");
    alice.share(m, f, Role::Read, Default::default()).unwrap();
    alice.share(m, ids[0], Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(dave, m), Some(s("meeting")));
    let t = plain(dave, "dave's");
    dave.grant(t, f, Role::Read, Default::default()).unwrap();
    w.run();
    assert!(dave.roster(t).unwrap().contains_key(&f));
    assert_eq!(unrouted(dave, t), vec![f]);
    assert!(!alice.knows(t).unwrap());
}

// spec/sync.md §6, spec/permissions.md §4: an admin by an edge on a group's item reaches a holder outside the group: he keeps the creation records of its owner chain under the item's label, though their commit wrote more
#[test]
fn a_grant_on_a_group_owned_item_by_an_admin_edge() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 3);
    let (bob, carol, dan) = (&others[0], &others[1], &others[2]);
    let g = group(&alice);
    alice.grant(g, ids[0], Role::Read, Default::default()).unwrap();
    alice.grant(g, ids[1], Role::Read, Default::default()).unwrap();
    let t = item(&alice, g, g, "group's");
    alice.sync(t, &[]).unwrap();
    alice.grant(t, ids[0], Role::Admin, Default::default()).unwrap();
    let card = dan.contact_card().unwrap();
    w.run();
    let d = w.until(bob.import_contact(&card), 1000, 10).unwrap();
    w.run();
    bob.grant(t, d, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(dan, t), Some(s("group's")));
    assert_eq!(x(carol, t), Some(s("group's")));
    // the same with the label made by bob's share
    let u = item(&alice, g, g, "u");
    alice.grant(u, ids[0], Role::Admin, Default::default()).unwrap();
    w.run();
    bob.share(u, d, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(dan, u), Some(s("u")));
}

// spec/sync.md §2: a grant to a client of this node, or a refused grant, makes no label and shows no missing route: the thing stays as local as it was
#[test]
fn a_grant_to_a_client_or_a_refused_one_makes_no_label() {
    let mut w = World::new();
    let (alice, _, ids) = people(&mut w, 1);
    let t = plain(&alice, "local");
    let (a, _) = alice.add_client(None).unwrap();
    alice.grant(t, a, Role::Read, Default::default()).unwrap();
    assert!(!alice.status().unwrap().groups.contains_key(&t));
    assert!(matches!(alice.grant(t, Tid::from_bytes([9; 15]), Role::Read, Default::default()), Err(osis::Error::UnknownActor { .. })));
    let r = alice.grant(t, ids[0], Role::Read, osis::EdgeOpts { invite: Some(Role::Write), ..Default::default() });
    assert!(matches!(r, Err(osis::Error::Invalid(_))), "{r:?}");
    assert!(!alice.status().unwrap().groups.contains_key(&t));
}

// spec/permissions.md §3, Keep: a removal keeping leaves the holder's database a read-only copy it
// reads and may drop; a removal saying erase over the same grant does not; a grant without `keep`
// erases.
#[test]
fn removal_keeps_a_copy_spec_permissions_3() {
    for (keep, say, kept) in [(Some(true), None, true), (Some(true), Some(false), false), (None, Some(true), true), (None, None, false)] {
        let mut w = World::new();
        let (alice, others, _) = people(&mut w, 1);
        let bob = &others[0];
        let g = group(&alice);
        let t = item(&alice, g, g, "before");
        if let Some(k) = keep {
            alice.set_keep_default(g, k).unwrap();
        }
        alice.grant(g, bob.me(), Role::Read, osis::EdgeOpts::default()).unwrap();
        w.run();
        assert_eq!(x(bob, t), Some(s("before")));
        let d = Demotion { sync: osis::WaitForSync::Skip, backdate: None, repudiate: false, keep: say };
        w.until(alice.demote(g, bob.me(), Lower::Remove, d), 1000, 10).unwrap();
        w.run();
        assert_eq!(bob.kept_copies().unwrap().contains(&g), kept);
        assert_eq!(x(bob, t), kept.then(|| s("before")));
        if kept {
            assert!(write_refused(bob, t), "read-only");
            bob.drop_kept(g).unwrap();
            assert!(bob.kept_copies().unwrap().is_empty());
            assert_eq!(x(bob, t), None);
        }
    }
}

// spec/permissions.md §3, Keep: a re-grant ends the copy: the node syncs and reads again what it
// missed, as one that erased does.
#[test]
fn a_regrant_ends_a_copy_spec_permissions_3() {
    for keep in [Some(true), None] {
        let mut w = World::new();
        let (alice, others, _) = people(&mut w, 1);
        let bob = &others[0];
        let g = group(&alice);
        let t = item(&alice, g, g, "before");
        if let Some(k) = keep {
            alice.set_keep_default(g, k).unwrap();
        }
        alice.grant(g, bob.me(), Role::Read, osis::EdgeOpts::default()).unwrap();
        w.run();
        let d = Demotion { sync: osis::WaitForSync::Skip, backdate: None, repudiate: false, keep: None };
        w.until(alice.demote(g, bob.me(), Lower::Remove, d), 1000, 10).unwrap();
        w.run();
        assert_eq!(x(bob, t), keep.map(|_| s("before")));
        let mut wr = alice.write();
        wr.at(t, ak("t:x.0")).set(&s("during")).unwrap();
        wr.commit().unwrap();
        w.run();
        assert_eq!(x(bob, t), keep.map(|_| s("before")), "frozen");
        alice.grant(g, bob.me(), Role::Read, Default::default()).unwrap();
        w.run();
        assert_eq!(x(bob, t), Some(s("during")));
        assert!(bob.kept_copies().unwrap().is_empty());
        assert!(bob.status().unwrap().groups.contains_key(&g));
    }
}

// spec/permissions.md §3, Keep; §8: a kick of a link's joiner fills from the target's default as the
// link was made, and says for itself too; the two ways round.
#[test]
fn a_joiners_removal_overrides_the_default_spec_permissions_3() {
    for (link, say, kept) in [(true, Some(false), false), (false, Some(true), true), (true, None, true), (false, None, false)] {
        let mut w = World::new();
        let (alice, others, _) = people(&mut w, 1);
        let bob = &others[0];
        let g = group(&alice);
        let t = item(&alice, g, g, "before");
        if link {
            alice.set_keep_default(g, true).unwrap();
        }
        let l = alice.make_link(g, Role::Read, osis::LinkOpts { until: None, single_use: false, direct: false }).unwrap();
        w.run();
        w.until(bob.redeem(&l), 1000, 10).unwrap();
        w.run();
        assert_eq!(x(bob, t), Some(s("before")));
        let d = Demotion { sync: osis::WaitForSync::Skip, backdate: None, repudiate: false, keep: say };
        w.until(alice.demote(g, bob.me(), Lower::Remove, d), 1000, 10).unwrap();
        w.run();
        assert_eq!(x(bob, t), kept.then(|| s("before")), "link {link} say {say:?}");
    }
}


// spec/permissions.md §2: a person's keep default does not reach a device's removal: the device erases.
#[test]
fn a_persons_default_does_not_reach_a_device_spec_permissions_2() {
    let mut w = World::new();
    let host = w.add_host();
    let (da, _) = w.person(1, &[host]);
    let t = item(&da, da.me(), da.me(), "before");
    let join = Osis::pair(w.cfg(2, &[]), &da.pair_offer().unwrap()).unwrap();
    let (_, reply) = da.pair_accept(join.request()).unwrap();
    let db = join.finish(&reply).unwrap();
    w.run();
    assert_eq!(x(&db, t), Some(s("before")));
    da.set_keep_default(da.me(), true).unwrap();
    w.run();
    let skip = osis::Demotion { sync: osis::WaitForSync::Skip, backdate: None, repudiate: false, keep: None };
    w.until(da.remove_device(db.node(), skip), 1000, 5).unwrap();
    w.run();
    assert_eq!(x(&db, t), None, "the device erases");
    assert!(db.kept_copies().unwrap().is_empty());
}

fn skip() -> Demotion {
    Demotion { sync: osis::WaitForSync::Skip, ..Default::default() }
}

// spec/permissions.md §2, §3: a reader removed from a group a thing was granted to reads nothing written after; another reader and a later one do
#[test]
fn kicked_from_a_group_ends_what_it_holds() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 4);
    let (bob, carol, dan, erin) = (&others[0], &others[1], &others[2], &others[3]);
    let h = group(&alice);
    alice.grant(h, ids[0], Role::Write, Default::default()).unwrap();
    alice.grant(h, ids[1], Role::Read, Default::default()).unwrap();
    w.run();
    let t = plain(&alice, "one");
    alice.share(t, h, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("one")));
    bob.commit_set(t, ak("t:x.0"), &s("bob's")).unwrap();
    w.run();
    assert_eq!(x(&alice, t), Some(s("bob's")));
    w.until(alice.demote(h, ids[0], Lower::Remove, skip()), 1000, 10).unwrap();
    w.run();
    alice.commit_set(t, ak("t:x.0"), &s("after")).unwrap();
    w.run();
    assert_ne!(x(bob, t), Some(s("after")));
    assert_eq!(x(carol, t), Some(s("after")));
    assert!(write_refused(bob, t), "write role went with the group");
    // the group's later reader reads the newest, and through history
    alice.grant(h, ids[2], Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(dan, t), Some(s("after")));
    // the edge's end is under the group's label too: a reader after it reads nothing later
    w.until(alice.demote(t, h, Lower::Remove, skip()), 1000, 10).unwrap();
    w.run();
    alice.commit_set(t, ak("t:x.0"), &s("edge gone")).unwrap();
    w.run();
    alice.grant(h, ids[3], Role::Read, Default::default()).unwrap();
    w.run();
    w.advance(120_000);
    w.run();
    assert_eq!(erin.role_on(t).unwrap(), None);
    assert_ne!(x(erin, t), Some(s("edge gone")));
    assert_ne!(x(dan, t), Some(s("edge gone")));
}

// spec/permissions.md §2, §3: the same two levels down, and a link joiner of the group
#[test]
fn kicked_from_a_nested_group_or_by_link_ends_what_it_holds() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 3);
    let (bob, carol, dan) = (&others[0], &others[1], &others[2]);
    let (p, k) = (group(&alice), group(&alice));
    let t = plain(&alice, "one");
    alice.share(t, k, Role::Read, Default::default()).unwrap();
    alice.grant(k, p, Role::Read, Default::default()).unwrap();
    alice.grant(p, ids[0], Role::Read, Default::default()).unwrap();
    alice.grant(p, ids[1], Role::Read, Default::default()).unwrap();
    w.run();
    let link = alice.make_link(p, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(w.until(dan.redeem(&link), 1000, 10).unwrap(), p);
    w.run();
    assert_eq!(x(bob, t), Some(s("one")));
    assert_eq!(x(dan, t), Some(s("one")), "joiner");
    w.until(alice.demote(p, ids[0], Lower::Remove, skip()), 1000, 10).unwrap();
    w.run();
    alice.commit_set(t, ak("t:x.0"), &s("after")).unwrap();
    w.run();
    assert_ne!(x(bob, t), Some(s("after")));
    assert_eq!(x(carol, t), Some(s("after")));
    assert_eq!(x(dan, t), Some(s("after")));
    w.until(alice.demote(p, dan.me(), Lower::Remove, skip()), 1000, 10).unwrap();
    w.run();
    alice.commit_set(t, ak("t:x.0"), &s("last")).unwrap();
    w.run();
    assert_ne!(x(dan, t), Some(s("last")));
    assert_eq!(x(carol, t), Some(s("last")));
}

// spec/sync.md §3: with both admins away a reader's grant to the group waits under its label: back, they apply it and copy it, and a later reader reads it
#[test]
fn a_grant_to_a_group_with_the_admin_away_and_two_admins() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 3);
    let (bob, eve, dave) = (&others[0], &others[1], &others[2]);
    let f = alice.create_ownerless(alice.me()).unwrap();
    alice.sync(f, &[]).unwrap();
    alice.grant(f, ids[0], Role::Read, Default::default()).unwrap();
    alice.grant(f, ids[1], Role::Admin, Default::default()).unwrap();
    w.run();
    // bob, a reader, grants with both admins away: readers read it; later readers need an admin
    w.set_online(&alice, false);
    w.set_online(eve, false);
    let t = plain(bob, "for f");
    bob.share(t, f, Role::Read, Default::default()).unwrap();
    w.run();
    w.set_online(&alice, true);
    w.set_online(eve, true);
    w.run();
    w.advance(120_000);
    w.run();
    assert_eq!(x(&alice, t), Some(s("for f")));
    assert_eq!(x(eve, t), Some(s("for f")));
    alice.grant(f, ids[2], Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(dave, t), Some(s("for f")));
}

// spec/sync.md §3: two admins copy an outsider's grant from the inbox with his chain just received: a later reader finds it whatever order they went in
#[test]
fn a_grant_to_a_group_by_an_outsider_with_two_admins() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 3);
    let (bob, dave, eve) = (&others[0], &others[1], &others[2]);
    let h = group(&alice);
    alice.grant(h, ids[2], Role::Admin, Default::default()).unwrap();
    w.run();
    let m = plain(&alice, "meeting");
    alice.share(m, h, Role::Read, Default::default()).unwrap();
    alice.share(m, ids[1], Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(dave, m), Some(s("meeting")));
    w.until(alice.demote(m, h, Lower::Remove, skip()), 1000, 10).unwrap();
    w.run();
    let t = plain(dave, "dave's");
    dave.share(t, h, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(x(&alice, t), Some(s("dave's")));
    assert_eq!(x(eve, t), Some(s("dave's")));
    w.advance(60_000);
    w.run();
    alice.grant(h, ids[0], Role::Read, Default::default()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    assert_eq!(x(bob, t), Some(s("dave's")));
}

/// `f`'s outcome if it has one now.
fn poll_now<F: std::future::Future + Unpin>(f: &mut F) -> Option<F::Output> {
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match std::pin::Pin::new(f).poll(&mut cx) {
        std::task::Poll::Ready(v) => Some(v),
        std::task::Poll::Pending => None,
    }
}

// spec/sync.md §3, notes/api.md (`wait_synced`): a holder whose grant names a label it has not read yet (its host out of reach for now) waits for it; its grant is pending there, so no missing route shows
#[test]
fn a_holder_waits_for_the_label_its_grant_names() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let bob = &others[0];
    let h1 = w.add_host();
    w.set_reachable(bob, h1, false);
    let t = plain(&alice, "there");
    alice.sync(t, &[w.addr(h1).unwrap()]).unwrap();
    alice.grant(t, ids[0], Role::Read, Default::default()).unwrap();
    w.run();
    assert!(unrouted(bob, t).is_empty(), "{:?}", bob.status().unwrap().groups.get(&t));
    let mut f = Box::pin(bob.wait_synced(SyncScope::Group(t), Duration::from_secs(3600)));
    assert!(poll_now(&mut f).is_none(), "the route is on its way");
    w.run();
    w.advance(1000);
    w.run();
    assert!(poll_now(&mut f).is_none(), "still waiting");
    w.set_reachable(bob, h1, true);
    w.until(f, 1000, 30).unwrap();
    assert_eq!(x(bob, t), Some(s("there")));
}

// spec/sync.md §3, notes/api.md (`wait_synced`): right after accepting a grant the holder waits for the label it names; before accepting nothing is on its way
#[test]
fn a_wait_right_after_accepting_a_grant() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let bob = &others[0];
    w.holds_invites.insert(1);
    let t = plain(&alice, "there");
    alice.share(t, ids[0], Role::Read, Default::default()).unwrap();
    w.until(alice.wait_synced(SyncScope::Group(t), Duration::from_secs(3600)), 1000, 30).unwrap();
    w.run();
    let r = w.until(bob.wait_synced(SyncScope::Group(t), Duration::from_secs(3600)), 1000, 30);
    assert!(matches!(r, Err(osis::Error::Unsynced { .. })), "{r:?}");
    let reqs = bob.invite_requests().unwrap();
    assert_eq!(reqs.len(), 1);
    bob.accept_invite(reqs[0]).unwrap();
    let mut f = Box::pin(bob.wait_synced(SyncScope::Group(t), Duration::from_secs(3600)));
    assert!(poll_now(&mut f).is_none(), "accepted: the route is on its way");
    w.until(f, 1000, 30).unwrap();
    assert_eq!(x(bob, t), Some(s("there")));
}

// spec/sync.md §3, notes/api.md (`wait_synced`): a brand new device of a holder, on a thing granted to its person before it existed and on one its person owns: its first sync brings both, and it waits
#[test]
fn a_new_devices_first_wait_on_a_shared_thing() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let bob = &others[0];
    let t = plain(&alice, "alice's");
    alice.share(t, ids[0], Role::Read, Default::default()).unwrap();
    let mine = plain(bob, "bob's");
    bob.sync(mine, &[]).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("alice's")));
    let join = Osis::pair(w.cfg(9, &[0]), &bob.pair_offer().unwrap()).unwrap();
    let (_, reply) = bob.pair_accept(join.request()).unwrap();
    let bob2 = join.finish(&reply).unwrap();
    let mut a = Box::pin(bob2.wait_synced(SyncScope::Group(t), Duration::from_secs(3600)));
    let mut b = Box::pin(bob2.wait_synced(SyncScope::Group(mine), Duration::from_secs(3600)));
    if let Some(r) = poll_now(&mut a) {
        panic!("new device, granted thing: {r:?}");
    }
    if let Some(r) = poll_now(&mut b) {
        panic!("new device, own thing: {r:?}");
    }
    w.until(a, 1000, 30).unwrap();
    w.until(b, 1000, 30).unwrap();
    assert_eq!(x(&bob2, t), Some(s("alice's")));
    assert_eq!(x(&bob2, mine), Some(s("bob's")));
    assert!(no_routes(&bob2));
}

// spec/sync.md §2 (Route): `share` of a whole group: it gets the label, its items go along; the holder has a route to both
#[test]
fn share_of_a_group_carries_its_items() {
    let mut w = World::new();
    let (alice, others, ids) = people(&mut w, 1);
    let bob = &others[0];
    let g = alice.batch(|w| {
        let g = w.create(alice.me())?;
        w.make_group(g)?;
        Ok(g)
    })
    .unwrap();
    let t = item(&alice, g, g, "in g");
    alice.share(g, ids[0], Role::Read, Default::default()).unwrap();
    assert!(no_routes(&alice));
    w.until(alice.wait_synced(SyncScope::Group(t), Duration::from_secs(3600)), 1000, 30).unwrap();
    w.run();
    assert_eq!(x(bob, t), Some(s("in g")));
    assert!(no_routes(bob));
}

// spec/crdt.md §2.1: a session per open, also under one test seed (`Config::seed`): one nonce drawn
// twice would make the second open's writes reuse the first's dots and void both commits.
#[test]
fn reopen_under_one_seed_draws_a_new_session_spec_crdt_2_1() {
    let mut w = World::new();
    let host = w.add_host();
    let cfg = w.cfg(1, &[host]);
    let (a, _) = Osis::create(cfg.clone()).unwrap();
    w.run();
    let t = item(&a, a.me(), a.me(), "first");
    let mut forms = vec![];
    let mut db = a;
    for v in ["second", "third"] {
        assert_eq!(db.close().unwrap(), osis::Close::Closed);
        w.advance(1000);
        db = Osis::open(cfg.clone()).unwrap();
        let c = commit_with(&db, |wr| wr.at(t, ak("t:x.0")).set(&s(v))).id.commit().unwrap();
        forms.push(db.engine(|e| e.header(&c).unwrap().form));
        w.run();
        assert_eq!(x(&db, t), Some(s(v)));
    }
    assert_ne!(forms[0], forms[1], "two opens, two sessions");
    let diags = w.diagnostics(&db);
    assert!(!diags.iter().any(|d| d.starts_with("OverlappingCounters")), "{diags:?}");
}
