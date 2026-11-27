//! A link's first contact over real connections (spec/sync-inbox.md §6, spec/permissions.md §7):
//! the redeemer dials the sharer node by the link's hints, opens K by the link key's static entry,
//! takes the head's entry box, pulls K and joins.

use crate::harness::{World, edge, fixture, two_nodes};
use osis_base::Role;
use osis_blob::ShareLink;
use osis_sync::types::Waiting;

/// Node 0 makes a read link to its profile; node 1 redeems it (cut off from node 0 when `apart`).
fn redeeming(apart: bool) -> (World, ShareLink) {
    let mut w = two_nodes();
    let p0 = w.node(0).profile.unwrap();
    let link = w.make_link(0, p0, Role::Read);
    if apart {
        w.partition(0, 1);
    }
    assert_eq!(w.redeem(1, &link), Waiting::Pending);
    (w, link)
}

/// `redeeming(false)`, run to quiet.
fn redeemed() -> (World, ShareLink) {
    let (mut w, link) = redeeming(false);
    w.run();
    (w, link)
}

/// Three nodes, each with an account of its own, quiet. Built once per process (`fixture`).
fn three_nodes() -> World {
    fixture("links three nodes", || {
        let mut w = World::new(0);
        for _ in 0..3 {
            w.add_node();
        }
        w.run();
        w
    })
}

// spec/sync-inbox.md §6 (First contact), spec/sync-set.md §2 (Sync set: a link's sync ID while
// its redeemer redeems it), spec/sync-opens.md §5 (Opening: a static entry's answer carries the
// head's entry box and the path): K, listed in the sharer's D, opens at node 1 by L's static entry, and node 1
// takes K's read secret from the head's entry box.
#[test]
fn a_link_opens_k_by_its_static_entry_spec_sync_inbox_6() {
    let (mut w, link) = redeemed();
    let s = link.k_sync_id;
    assert!(matches!(w.engine(0).sync_holder(&s).unwrap(), Some((_, osis_engine::sync::Holding::Read))), "the sharer syncs K");
    assert!(matches!(w.engine(1).sync_holder(&s).unwrap(), Some((t, osis_engine::sync::Holding::Read)) if t == [link.k].into()), "the redeemer follows K's sync ID");
    assert!(w.status(1).get(&s).is_some_and(|st| !st.sources.is_empty()), "K open at the sharer");
    assert!(!w.engine(1).read_credentials(&s).unwrap().unwrap().read_secrets.is_empty(), "K's read secret from the entry box");
}

/// Node 0's read link to its profile, followed at node 1 (not run): node 1 knows K only from the
/// link text.
fn followed() -> (World, ShareLink) {
    let mut w = two_nodes();
    let p0 = w.node(0).profile.unwrap();
    let link = w.make_link(0, p0, Role::Read);
    w.write(1, |e| e.follow_link(&link)).unwrap();
    (w, link)
}

fn learned_nothing(w: &mut World, s: &osis_base::SyncId) -> bool {
    w.engine(1).read_credentials(s).unwrap().unwrap().read_secrets.is_empty()
}

// spec/sync-opens.md §5 (Opening: for a static entry the tester takes the box's secrets only when
// the path verifies from its genesis step, the box's sync secret derives the head's sync key and
// `sig` verifies under it): a box sealed to L with secrets of the forger's choosing, on K's real
// path, opens nothing; nor does the real box on a path of another sync ID; the real one opens the
// head's sync key and learns nothing until `learn_grant`.
#[test]
fn a_static_grant_is_verified_before_it_is_learned_spec_sync_opens_5() {
    use osis_crypto::{BoxSlot, EntryItem, EntryRead, Epoch, Secret32, SeededRng};
    let (mut w, link) = followed();
    let s = link.k_sync_id;
    let path = w.engine(0).sync_ids(&link.k).unwrap().iter().find(|o| o.id == s).unwrap().path.steps.clone();
    let steps: Vec<osis_blob::Step> = path.iter().map(|(st, _)| st.clone()).collect();
    let head = steps.last().unwrap().clone();
    let lkey = osis_engine::Identity::link_key(link.seed.clone(), link.k);
    let entry = osis_crypto::static_entry(&s, &lkey.signing().verifying_key());
    let real = path.last().unwrap().1.as_ref().unwrap().entries.get(&entry).unwrap().clone();
    let (x, y) = (Secret32::from_bytes([9; 32]), Secret32::from_bytes([8; 32]));
    let item = EntryItem { read: Some(EntryRead { epoch: Epoch::derive(&link.k, Role::Read, 1, &x).unwrap(), secret: x, earlier: None }), sync: (Epoch::derive(&link.k, Role::Sync, 1, &y).unwrap(), y) };
    let slot = BoxSlot::Entry { sync_id: s, step_key: head.step_key, actor: link.k };
    let sealed = osis_crypto::seal_entry(lkey.link_read_kem().unwrap().public(), &slot, &item, &mut SeededRng::from_u64(1)).unwrap();
    let osis_schema::core_types::SecretBox::Sealed(mut sb) = real.clone() else { panic!("a sealed entry box") };
    sb.sealed = osis_schema::core_types::Sealed::X25519MlKem768(sealed);
    let forged = osis_schema::core_types::SecretBox::Sealed(sb);
    assert!(w.engine(1).open_grant(&s, &entry, &steps, &forged).unwrap().is_none(), "a forged box opens nothing");
    let p0 = w.node(0).profile.unwrap();
    let other: Vec<osis_blob::Step> = w.engine(0).sync_ids(&p0).unwrap()[0].path.steps.iter().map(|(st, _)| st.clone()).collect();
    assert!(w.engine(1).open_grant(&s, &entry, &other, &real).unwrap().is_none(), "a path of another sync ID opens nothing");
    assert!(learned_nothing(&mut w, &s));
    let g = w.engine(1).open_grant(&s, &entry, &steps, &real).unwrap().expect("the real grant opens");
    assert_eq!(g.key, head.keys.sync.to_bytes());
    assert!(learned_nothing(&mut w, &s), "opened, not learned before the signature verifies");
    w.write(1, |e| e.learn_grant(&g)).unwrap();
    assert!(!learned_nothing(&mut w, &s), "learned once the caller takes it");
}

// spec/sync-set.md §2 (Sync set: a link's sync ID while its redeemer redeems it): the link text is untrusted. A link
// naming a thing node 1 syncs as K, or naming that thing's sync ID as K's, changes nothing of how
// node 1 syncs it.
#[test]
fn a_link_text_never_moves_another_things_sync_id_spec_sync_set_2() {
    let mut w = two_nodes();
    let real = w.make_link(0, w.node(0).profile.unwrap(), Role::Read);
    let set = w.engine(1).sync_set().unwrap();
    let (&own, (ts, _)) = set.ids.iter().next().expect("node 1 syncs something");
    let t = *ts.first().unwrap();
    let thing_before = w.engine(1).thing_sync(&t).unwrap();
    // K = that thing, under the real link's sync ID
    let as_k = ShareLink { k: t, ..real.clone() };
    w.write(1, |e| e.follow_link(&as_k)).unwrap();
    assert_eq!(w.engine(1).thing_sync(&t).unwrap(), thing_before, "a held thing named as K syncs as before");
    assert_eq!(w.engine(1).sync_holder(&real.k_sync_id).unwrap(), None, "the link's sync ID is nobody's here");
    w.write(1, |e| e.unfollow_link(&t));
    // K's sync ID = that thing's
    let stolen = ShareLink { k_sync_id: own, ..real };
    w.write(1, |e| e.follow_link(&stolen)).unwrap();
    assert_eq!(*w.engine(1).sync_set().unwrap(), *set, "the sync set is as before");
    assert_eq!(w.engine(1).thing_sync(&stolen.k).unwrap(), osis_engine::sync::ThingSync::Dependent, "K has no sync ID of its own here");
}

// spec/permissions.md §7 (Redeem: the link has ended, and the redeemer stops there, when a held
// role history shows L's grant removed): a link finalized before it is redeemed answers `Never`
// and keeps nothing.
#[test]
fn an_ended_link_is_not_redeemed_spec_permissions_7() {
    let mut w = two_nodes();
    let p0 = w.node(0).profile.unwrap();
    let link = w.make_link(0, p0, Role::Read);
    let l = osis_engine::identity::link_key_tid(&link.seed, link.k);
    w.write(0, |e| e.finalize_link(&link.k, &l)).unwrap();
    assert!(w.engine(0).link_ended(&link));
    assert!(matches!(w.redeem(0, &link), Waiting::Never(_)));
    assert!(w.engine(0).read_credentials(&link.k_sync_id).unwrap().is_none_or(|c| c.acting.is_empty()), "L not acted for");
}



// spec/permissions.md §7 (Redeem: the join waits for K's history, then seals K's secrets to the
// redeemer): accounts 1 and 2 join K0 by node 0's link, account 0 joins K1 by node 1's link; node
// 2 then redeems node 1's link. Node 2 already shares a stream with node 1, so K1 joins it
// mid-stream and L's grant (roster) arrives before K1's keyset (fetched last: wrapped under the
// epoch it supersedes); the join waits for the keyset, never fails for want of it.
#[test]
fn a_third_redeemer_sharing_another_link_joins_spec_permissions_7() {
    let mut w = three_nodes();
    let links: Vec<ShareLink> = (0..3).map(|i| {
        let p = w.node(i).profile.unwrap();
        w.make_link(i, p, Role::Read)
    }).collect();
    for (j, i) in [(1, 0), (2, 0), (0, 1), (2, 1)] {
        w.redeem(j, &links[i]);
        w.run();
        assert_eq!(w.redeem(j, &links[i]), Waiting::Done, "{j} redeems {i}'s link");
        let a = w.node(j).account.unwrap();
        assert!(w.engine(i).roster(&links[i].k).contains_key(&a), "{j}'s join held at {i}");
    }
}

// spec/permissions.md §7 (joiner's leave): a node of the joining account writes its leave of K
// once it holds K's edge on the link's target removed: node 0 takes K off its profile; node 1's
// account leaves K, at node 1 and at node 0.
#[test]
#[ignore = "sync rewrite: a joiner's leave and deposit counts"]
fn a_joiner_leaves_k_once_k_left_the_target_spec_permissions_7() {
    let (mut w, link) = redeemed();
    let a1 = w.node(1).account.unwrap();
    assert!(w.engine(1).roster(&link.k).contains_key(&a1), "joined");
    w.write(0, |e| e.demote(&link.target, &osis_engine::flows::Demotion { holder: link.k, new: None, retain: None })).unwrap();
    w.run();
    assert!(!w.engine(1).roster(&link.target).contains_key(&link.k), "K off the target at node 1");
    for i in 0..2 {
        assert!(!w.engine(i).roster(&link.k).contains_key(&a1), "node {i}: node 1's account still holds K");
    }
}

// spec/permissions.md §7 (joiner's leave: K's edge on the target past `until`): node 0 gives K's
// edge on its profile an `until` a minute ahead; once it passes, by time alone, node 1's account
// leaves K.
#[test]
#[ignore = "sync rewrite: a joiner's leave and deposit counts"]
fn a_joiner_leaves_k_once_its_edge_on_the_target_expired_spec_permissions_7() {
    let (mut w, link) = redeemed();
    let a1 = w.node(1).account.unwrap();
    let until = osis_base::WallMs(w.now().0 + 60_000);
    let edge = osis_schema::core_types::Edge { role: Role::Read, until: Some(until), may_grant: false, retain: false, floor: None };
    w.write(0, |e| e.grant(&link.target, &link.k, &edge)).unwrap();
    w.run();
    assert!(w.now() >= until, "the run reached the expiry");
    for i in 0..2 {
        assert!(!w.engine(i).roster(&link.k).contains_key(&a1), "node {i}: node 1's account still holds K");
    }
}

// spec/permissions.md §7 (Joiner's leave): the held role history read as it shows K's edge on the
// target now: node 0, cut off from node 1, takes K off its profile and grants it again; once
// healed node 1 holds K's edge alive and its account stays in K (a hostile ordering of the
// removal and the re-grant removes no live join).
#[test]
fn a_joiner_stays_when_k_was_granted_again_before_it_heard_spec_permissions_7() {
    let (mut w, link) = redeemed();
    let a1 = w.node(1).account.unwrap();
    w.partition(0, 1);
    w.write(0, |e| e.demote(&link.target, &osis_engine::flows::Demotion { holder: link.k, new: None, retain: None })).unwrap();
    w.write(0, |e| e.grant(&link.target, &link.k, &edge(Role::Read))).unwrap();
    w.heal();
    w.run();
    assert!(w.engine(1).roster(&link.target).contains_key(&link.k), "K on the target at node 1");
    for i in 0..2 {
        assert!(w.engine(i).roster(&link.k).contains_key(&a1), "node {i}: node 1's account left K");
    }
}

// spec/permissions.md §7 (joiner's leave: K's edge on the target past `until`, judged by the
// node's own clock): as above, but node 1 is cut off from node 0 once it holds the edge, so
// nothing arrives: the `until` passing alone makes node 1's account leave K there.
#[test]
fn a_joiner_leaves_k_by_its_clock_alone_spec_permissions_7() {
    let (mut w, link) = redeemed();
    let a1 = w.node(1).account.unwrap();
    let until = osis_base::WallMs(w.now().0 + 60_000);
    let edge = osis_schema::core_types::Edge { role: Role::Read, until: Some(until), may_grant: false, retain: false, floor: None };
    w.write(0, |e| e.grant(&link.target, &link.k, &edge)).unwrap();
    w.advance(1000);
    assert!(w.engine(1).roster(&link.target).contains_key(&link.k) && w.engine(1).roster(&link.k).contains_key(&a1), "node 1 holds the edge, joined");
    w.partition(0, 1);
    w.advance(120_000);
    assert!(!w.engine(1).roster(&link.k).contains_key(&a1), "node 1's account still holds K");
}

// spec/sync-judgement.md §2 (required set: certificates the same at every node),
// spec/permissions.md §7 (Redeem): a reader through a link key alone logs nothing of its own under K. Node 2
// joins K by node 0's read link, then node 1 redeems it: L's grant to node 1's account is
// deposited and promoted. It verifies at node 2, which does not hold node 1's node thing.
#[test]
fn a_link_keys_promoted_grant_verifies_where_the_redeemers_node_is_not_held_spec_sync_judgement_2() {
    let mut w = three_nodes();
    let p0 = w.node(0).profile.unwrap();
    let link = w.make_link(0, p0, Role::Read);
    w.redeem(2, &link);
    w.run();
    assert_eq!(w.redeem(2, &link), Waiting::Done, "node 2 joined K");
    w.redeem(1, &link);
    w.run();
    assert_eq!(w.redeem(1, &link), Waiting::Done, "node 1 joined K");
    let a1 = w.node(1).account.unwrap();
    let n1 = w.engine(1).tid();
    for i in [0, 2] {
        assert!(w.engine(i).roster(&link.k).contains_key(&a1), "node 1's join verified at node {i}");
    }
    assert!(!w.engine(2).closure_holds(&n1), "node 1's node thing is not held at node 2");
}

// spec/sync-inbox.md §6 (First contact: a node may stop following a link after a time of its
// choosing): node 1 redeems node 0's link while node 0 is unreachable; a restart halfway keeps
// the redeem and its start; at the follow time the redeem is given up: not redeemed, K's sync ID
// no longer followed, nothing kept across a restart, and node 0 no longer dialed.
#[test]
fn a_link_whose_sharer_never_answers_is_given_up_spec_sync_inbox_6() {
    use osis_sync::types::FOLLOW_LINK_MS;
    let (mut w, link) = redeeming(true);
    // the restart off the redial pace's grid (`REDIAL_MS` from each dial), so only the follow
    // time's own wake ticks node 1 at it
    let off = FOLLOW_LINK_MS / 2 + 7_001;
    w.advance(off);
    w.power_off(1);
    w.power_on(1);
    w.advance(1);
    assert!(w.node(1).node.redeeming(&link.k), "kept across the restart");
    assert!(w.engine(1).sync_holder(&link.k_sync_id).unwrap().is_some(), "K's sync ID followed");
    let before = w.dials(1).work().dials;
    w.advance(FOLLOW_LINK_MS - off - 2);
    assert!(w.node(1).node.redeeming(&link.k), "still redeemed before the follow time from its start");
    assert!(w.dials(1).work().dials > before, "node 0 dialed meanwhile");
    w.advance(2);
    assert!(!w.node(1).node.redeeming(&link.k), "given up at the follow time from its start, woken for it");
    assert_eq!(w.engine(1).sync_holder(&link.k_sync_id).unwrap(), None, "K's sync ID unfollowed");
    let after = w.dials(1).work().dials;
    w.advance(FOLLOW_LINK_MS);
    assert_eq!(w.dials(1).work().dials, after, "node 0 no longer dialed");
    w.power_off(1);
    w.power_on(1);
    w.advance(1);
    assert!(!w.node(1).node.redeeming(&link.k), "nothing kept");
    // redeeming it again starts again, and with node 0 back it joins
    w.heal();
    assert_eq!(w.redeem(1, &link), Waiting::Pending);
    w.run();
    assert_eq!(w.redeem(1, &link), Waiting::Done, "joined once redeemed again");
}

// spec/sync-inbox.md §6 (First contact): a sharer that answers within the follow time is joined
// as ever: node 0 back just before it, node 1 joins.
#[test]
fn a_sharer_answering_before_the_follow_time_is_joined_spec_sync_inbox_6() {
    use osis_sync::types::FOLLOW_LINK_MS;
    let (mut w, link) = redeeming(true);
    w.advance(FOLLOW_LINK_MS - 60_000);
    w.heal();
    w.run();
    assert_eq!(w.redeem(1, &link), Waiting::Done, "joined");
    let a1 = w.node(1).account.unwrap();
    assert!(w.engine(0).roster(&link.k).contains_key(&a1), "the join held at the sharer");
}

// spec/permissions.md §7 (Redeem: a redeemer keeps the seed until its grant is at a source),
// spec/sync-inbox.md §6 (A redeemer not joined: only it stops at its node's follow time): a join
// written just before the follow time, its sharer gone before taking it, keeps the link followed
// past it (given up, the join could never reach a source, and redeeming again joins nothing);
// with node 0 back, the join is held there and the link forgotten.
#[test]
fn a_joined_redeem_is_followed_past_the_follow_time_until_its_join_is_held_spec_permissions_7() {
    use osis_sync::types::FOLLOW_LINK_MS;
    let (mut w, link) = redeeming(true);
    w.advance(FOLLOW_LINK_MS - 60_000);
    w.heal();
    // one input at a time, so node 0 is cut off right after node 1 writes the join
    let a1 = w.node(1).account.unwrap();
    while !w.engine(1).roster(&link.k).contains_key(&a1) && w.step_or_wake() {}
    w.partition(0, 1);
    assert!(w.engine(1).role_on(&link.k).is_some(), "joined within the follow time");
    assert!(!w.engine(0).roster(&link.k).contains_key(&a1), "the join not at the sharer");
    w.advance(2 * FOLLOW_LINK_MS);
    assert!(w.node(1).node.redeeming(&link.k), "joined, the join not held: followed on");
    assert!(w.engine(1).sync_holder(&link.k_sync_id).unwrap().is_some(), "K's sync ID followed");
    w.heal();
    w.run();
    assert!(w.engine(0).roster(&link.k).contains_key(&a1), "the join held at the sharer");
    assert!(!w.node(1).node.redeeming(&link.k), "forgotten once held");
}

// spec/permissions.md §7 (Redeem: a redeemer keeps the seed until its grant is at a source and
// SHOULD discard it then), spec/sync-set.md §4, spec/sync-ids.md §2
// (One sync ID per independent thing: every holder of a role on it syncs it through that sync ID):
// node 1 redeems node 0's single-use link; once node 0 holds the join, node 1 forgets the link (L
// acted for no more) and syncs K read through D's strong to it: what node 0 writes
// on K after reaches it. Redeeming the link again, L long gone, is done and writes no second join.
#[test]
#[ignore = "sync rewrite: a joiner's leave and deposit counts"]
fn a_held_join_forgets_the_link_and_k_stays_synced_spec_permissions_7() {
    let mut w = two_nodes();
    let (p0, a0, a1) = (w.node(0).profile.unwrap(), w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let peers = osis_blob::link_peers(w.node(0).key.0, &w.net.reach.items(0), &[]);
    let spec = osis_engine::flows::LinkSpec { target: p0, role: Role::Read, until: None, peers, single_use: true };
    let link = w.write(0, |e| e.create_link(&a0, &spec)).unwrap().0;
    assert_eq!(w.redeem(1, &link), Waiting::Pending);
    w.run();
    assert!(w.engine(0).roster(&link.k).contains_key(&a1), "the join held at the sharer");
    assert!(!w.node(1).node.redeeming(&link.k), "forgotten once held");
    let s = link.k_sync_id;
    assert!(w.engine(1).read_credentials(&s).unwrap().is_some_and(|c| c.acting.is_empty()), "K read, L acted for no more");
    assert!(matches!(w.engine(1).sync_holder(&s).unwrap(), Some((t, osis_engine::sync::Holding::Read)) if t == [link.k].into()), "K synced read");
    let on_k = w.engine(1).core.on_thing(&link.k).count();
    assert_eq!(w.redeem(1, &link), Waiting::Done, "joined: done");
    w.run();
    assert_eq!(w.engine(1).core.on_thing(&link.k).count(), on_k, "no second join");
    let ak = osis_base::Ak::new("t:reg.0").unwrap();
    w.write(0, |e| {
        let mut m = osis_engine::Mutation::new();
        m.set(link.k, &ak, &osis_base::Value::Int(7)).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert_eq!(w.engine(1).get(&link.k, &ak).unwrap(), Some(osis_base::Value::Int(7)), "K synced after the link");
}

// spec/permissions.md §7 (First contact: once its join is held a redeemer keeps the link's peers,
// not the seed, as addresses to dial while its account holds a role on the target): node 1's
// link forgotten, node 0 stays a dial hint there, across a restart, until node 1's account
// leaves K (K taken off the target), when it goes.
#[test]
fn a_joined_links_peers_stay_dial_hints_while_it_holds_k_spec_permissions_7() {
    use osis_sync::driver::dials::Why;
    let (mut w, link) = redeemed();
    let sharer = w.node(0).key.0;
    assert!(!w.node(1).node.redeeming(&link.k), "joined, the link forgotten");
    let hinted = |w: &World| w.dials(1).why(&sharer).contains(&Why::Hint);
    assert!(hinted(&w), "the link's peer kept as a dial hint");
    w.power_off(1);
    w.power_on(1);
    w.run();
    assert!(hinted(&w), "kept across a restart");
    w.write(0, |e| e.demote(&link.target, &osis_engine::flows::Demotion { holder: link.k, new: None, retain: None })).unwrap();
    w.run();
    assert!(!w.engine(1).roster(&link.k).contains_key(&w.node(1).account.unwrap()), "node 1's account left K");
    assert!(!hinted(&w), "the peer dropped with the join");
}

// spec/permissions.md §8 (Pairing), spec/sync-set.md §4 (Redeeming: a locator is kept until
// its target is held): node 1, paired to node 0's account and configured to dial nothing,
// restarts before it has met node 0: it still dials node 0 by the peers pairing handed over and
// syncs the account; across a later restart it dials node 0 as a dial peer of the account.
#[test]
fn a_paired_node_restarted_before_first_contact_still_dials_the_pairer_spec_sync_inbox_5() {
    use osis_sync::driver::dials::Why;
    let mut w = World::new(0);
    w.add_node();
    w.run();
    let pairer = w.node(0).key.0;
    w.partition(0, 1);
    let j = w.pair(0);
    assert_eq!(j, 1);
    w.power_off(1);
    w.power_on(1);
    w.advance(1);
    let hinted = |w: &World| w.dials(1).why(&pairer).contains(&Why::Hint);
    assert!(hinted(&w), "the pairer kept as a dial hint across the restart");
    w.heal();
    w.run();
    let a = w.node(0).account.unwrap();
    let dial = osis_base::Ak::new("dial.0").unwrap();
    assert_eq!(w.engine(1).get(&a, &dial).unwrap(), w.engine(0).get(&a, &dial).unwrap(), "the account synced with the pairer");
    w.power_off(1);
    w.power_on(1);
    w.run();
    let s = w.engine(1).sync_id_of(&a).unwrap().unwrap();
    assert!(w.dials(1).why(&pairer).contains(&Why::Sync(s)), "the pairer dialed as the account's");
}

// spec/sync-inbox.md §6 (A redeemer not joined within a time of its node's choosing: a locator to
// the thing its node root's settings name is followed until held),
// spec/permissions.md §8 (Pairing): node 1, paired to node 0's account, is off for longer than a
// redeem's follow time before it meets node 0; back on, it still enters its account. Failed with
// the follow time ending the pairing's locator: the node gave it up at its start and never entered.
#[test]
fn a_paired_node_off_past_the_follow_time_still_enters_its_account_spec_sync_inbox_6() {
    let mut w = World::new(0);
    w.add_node();
    w.run();
    let j = w.pair(0);
    w.power_off(j);
    w.advance(2 * osis_sync::types::FOLLOW_LINK_MS);
    w.power_on(j);
    w.run();
    let a = w.node(0).account.unwrap();
    let e = w.engine(j);
    assert!(e.closure_holds(&a) && e.role_on(&a) == Some(Role::Admin), "the paired node entered its account");
}

// spec/sync-opens.md §5 (ByRole: a side following S by a locator alone sends ByRole beside
// its public entry's Hit), spec/permissions.md §8 (Pairing): node 0's account is public at sync,
// so the node it pairs Hits the account's public entry, which it sends as noise (`Lie::Miss`: a
// filter's false positive, refused); it enters by role all the same. Failed with ByRole sent only
// where no Hit on S went: the node never entered and gave the locator up.
#[test]
fn a_paired_node_whose_public_hit_is_refused_enters_by_role_spec_sync_opens_5() {
    let mut w = World::new(0);
    w.add_node();
    let a = w.node(0).account.unwrap();
    w.write(0, |e| e.grant(&a, &osis_base::Tid::PUBLIC, &edge(Role::Sync))).unwrap();
    w.run();
    let j = w.pair(0);
    w.lie(j, Some(crate::harness::lies::Lie::Miss));
    w.run();
    assert!(w.missed_hits(j) > 0, "the paired node Hit the public entry");
    let e = w.engine(j);
    assert!(e.closure_holds(&a) && e.role_on(&a) == Some(Role::Admin), "the paired node entered its account");
}

// spec/sync-streams.md §4 (Fill order: an entry opening with a section it cannot open, holding a
// part that counts missing, opens again as that part's thing's read secrets gain an epoch),
// spec/permissions.md §7 (Redeem: wait for K's grant on the target): accounts 1 and 2 join node
// 0's link, so node 0 holds account 1's creation commit from a certificate copy (its keys only)
// and shares K0 with two sources (its pulls fetch every body, none inline). Node 0 then redeems
// node 1's link: the creation commit's blob under K1 opens before the target's secrets are held,
// its section with the target's `created.0` sealed; once the secrets arrive it opens, the record
// lets K1's grant on the target apply, and the join is written.
#[test]
fn a_held_commits_sealed_part_opens_once_its_things_secrets_arrive_spec_sync_streams_4() {
    let mut w = three_nodes();
    let links: Vec<ShareLink> = (0..2).map(|i| {
        let p = w.node(i).profile.unwrap();
        w.make_link(i, p, Role::Read)
    }).collect();
    for j in [1, 2] {
        w.redeem(j, &links[0]);
        w.run();
    }
    assert_eq!(w.redeem(0, &links[1]), Waiting::Pending);
    w.run();
    let a0 = w.node(0).account.unwrap();
    assert!(w.engine(0).roster(&links[1].target).contains_key(&links[1].k), "K1's grant on the target held at node 0");
    assert!(w.engine(1).roster(&links[1].k).contains_key(&a0), "node 0's join held at node 1");
}

// spec/sync-inbox.md §5 (Contact card: the profile's sync ID carries the account's public record,
// the `keys.0` commits as certificate copies): node 1 imports node 0's card and holds node 0's
// account keys, though the commit making the account also makes its profile, whose body under
// the profile's sync ID the certificates join as one per-sync-ID copy.
#[test]
fn a_card_importer_holds_the_accounts_keys_spec_sync_inbox_5() {
    let mut w = two_nodes();
    let (p0, a0) = (w.node(0).profile.unwrap(), w.node(0).account.unwrap());
    let card = w.make_link(0, p0, Role::Read);
    w.redeem(1, &card);
    w.run();
    assert_eq!(w.redeem(1, &card), Waiting::Done);
    let _ = a0;
}
