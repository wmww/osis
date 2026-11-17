#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The engine's facade for sync (`osis_engine::sync`, notes/sync-facade.md): each call against
//! the spec rule it serves, over `LocalPeer` (commits and sealed fires carried by hand).

use crate::common::{REG, s};
use crate::flows::{edge_of, people, spread, thing_of};
use osis_base::{Ak, Role, Tid};
use osis_crypto::SeededRng;
use osis_engine::flows::Demotion;
use osis_engine::local_peer::LocalPeer;
use osis_engine::Mutation;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

// spec/sync-ids.md §3 (claim key: a listed reader derives it from its own key and the step key),
// §4 (owner), spec/sync-opens.md §4 (admissible: read secrets at a current epoch, the head's sync
// proof).
#[test]
fn read_credentials_and_claim_key_spec_sync_ids_3() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (_, d) = e.account().unwrap().unwrap();
    let ds = e.sync_id_of(&d).unwrap().unwrap();
    let ids = e.sync_ids(&d).unwrap();
    assert_eq!(ids.len(), 1);
    assert!(!ids[0].hint);
    let head = ids[0].path.steps.last().unwrap().0.clone();
    head.verify_genesis().unwrap();
    let rc = e.read_credentials(&ds).unwrap().expect("a reader of D");
    assert_eq!(rc.head.as_ref().map(|s| s.id()), Some(head.id()));
    assert!(!rc.read_secrets.is_empty(), "a current read secret");
    assert_eq!(rc.proofs.first().map(|p| p.0), Some(head.id()), "the head's sync proof first");
    let ck = e.claim_key(&ds, &head.id()).unwrap().expect("this node is listed at genesis");
    let (_, Some(claims)) = &ids[0].path.steps[0] else { panic!("claim set held") };
    assert!(claims.claims.contains(&ck.verifying_key().to_bytes()));
}

// spec/data-model.md §9 (`caps^.0`: on the node root), spec/sync-ids.md §5 (caps).
#[test]
fn caps_read_from_the_node_spec_sync_ids_5() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    assert!(e.caps().unwrap().things.is_empty(), "absent: the defaults");
    let me = e.node_root().unwrap();
    let t = Tid::from_bytes([9; 15]);
    let mut m = Mutation::new();
    m.set(me, &ct::CAPS, &ct::Caps { policy: [("entries".to_string(), 7)].into(), things: [(t.into(), ct::ThingCaps { entries: 3, bytes: 4 })].into() }).unwrap();
    e.commit(m).unwrap().unwrap();
    let c = e.caps().unwrap();
    assert_eq!(c.policy.get("entries"), Some(&7));
    assert_eq!(c.things.get(&t).map(|x| (x.entries, x.bytes)), Some((3, 4)));
}

// spec/sync-ids.md §6 (Steps: an admin issues a step when it holds an epoch newer than its
// recorded head registers, a child of that head, after logging the rotation commits it registers):
// nothing is due until a removal rotates; then the step is due, naming the removal's rotation
// among what it registers, and its issue records a child of the recorded head at the new sync
// epoch, after which nothing is due; a fresh step is a further child. A refreshed deposit seed
// makes a step due, and `issue_due_step` issues it (both read the head and seed one way).
#[test]
fn a_step_is_due_after_a_rotation_spec_sync_ids_6() {
    let (mut lp, ps) = people(3);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
    let s = lp.peers[0].engine.sync_id_of(&t).unwrap().unwrap();
    let head = |lp: &mut LocalPeer| lp.peers[0].engine.sync_ids(&t).unwrap().iter().find(|o| o.id == s).unwrap().path.steps.last().unwrap().0.clone();
    assert!(lp.peers[0].engine.due_step(&s).unwrap().is_none(), "nothing newer");
    let before = head(&mut lp);
    let done = lp.peers[0].engine.demote(&t, &Demotion { holder: ps[1], new: None, retain: None }).unwrap();
    let needs = lp.peers[0].engine.due_step(&s).unwrap().expect("the rotation's step is due");
    assert!(needs.needs.contains(done.commits.last().unwrap()) && !needs.deposit_only, "it registers the removal's rotation");
    let step = lp.peers[0].engine.issue_due_step(&s).unwrap().expect("issued");
    assert_eq!((step.prev, head(&mut lp).id()), (Some(before.id()), step.id()), "a child of the recorded head, recorded");
    let sync = lp.peers[0].engine.epochs(&t).unwrap().sync.newest_held().map(|(_, x)| x.clone()).unwrap();
    assert_eq!(step.keys.sync, osis_crypto::role_key(osis_crypto::RoleKey::Sync, &sync).verifying_key(), "at the new sync epoch");
    assert!(lp.peers[0].engine.due_step(&s).unwrap().is_none(), "nothing due after it");
    let (fresh, _) = lp.peers[0].engine.issue_step(&t, &s, true).unwrap().expect("a fresh step");
    assert_eq!((fresh.prev, head(&mut lp).id()), (Some(step.id()), fresh.id()));
    // a refreshed deposit seed: due by the seed `issue_due_step` reads, and issued from it
    lp.peers[0].engine.refresh_deposit_seed(&t).unwrap();
    assert!(lp.peers[0].engine.due_step(&s).unwrap().is_some_and(|d| d.deposit_only), "a new deposit key is due");
    let seeded = lp.peers[0].engine.issue_due_step(&s).unwrap().expect("issued by the same reading");
    assert_eq!(seeded.prev, Some(fresh.id()));
    assert!(lp.peers[0].engine.due_step(&s).unwrap().is_none(), "nothing due after it");
}

/// Peers 0 and 1 nodes of one account (paired), peer 2 of another, which makes a thing and
/// grants the first account write on it; everyone holds everything. The account and the thing.
fn siblings_granted() -> (LocalPeer, Tid, Tid) {
    let (lp, (a, t)) = LocalPeer::cached("facade::siblings_granted", || {
        let mut lp = crate::common::net_bare(3, 0);
        let a = lp.peers[0].engine.create_account().unwrap().0.account;
        let n = lp.peers[1].engine.tid();
        let card = lp.peers[1].engine.commit_ids();
        crate::flows::send(&mut lp, 1, 0, &card);
        let (_, sent) = lp.peers[0].engine.pair(&n).unwrap();
        crate::flows::send(&mut lp, 0, 1, &sent);
        lp.peers[1].engine.paired(&a).unwrap();
        let b = lp.peers[2].engine.create_account().unwrap().0.account;
        spread(&mut lp);
        let t = thing_of(&mut lp, 2, b);
        lp.peers[2].engine.grant(&t, &a, &edge_of(Role::Write)).unwrap();
        spread(&mut lp);
        for i in [0, 1] {
            assert!(lp.peers[i].engine.epochs(&t).is_some_and(|x| x.read.holds_any()), "node {i} reads it");
        }
        (lp, (a, t))
    });
    (lp, a, t)
}

// spec/permissions.md §3 (Lost access: whichever node of the account made it), spec/sync-status.md
// §2: node 0 removes its account from a thing; node 1, its sibling, applies the removal and waits
// for sync as the writer does (through a restart and the lost-access trigger), then drops; the
// other account's node waits on nothing.
#[test]
fn a_siblings_self_removal_waits_and_drops_alike_spec_perm_3() {
    let (mut lp, a, t) = siblings_granted();
    let c = lp.peers[0].engine.demote(&t, &Demotion { holder: a, new: None, retain: None }).unwrap().commits[0];
    spread(&mut lp);
    assert!(lp.peers[0].engine.waiting_removals().contains(&c), "the writer waits");
    assert!(lp.peers[2].engine.waiting_removals().is_empty(), "another account's node waits on nothing");
    lp.peers[1].restart(1).unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(e.waiting_removals().contains(&c), "the sibling waits too, through a restart");
    e.role_duties().unwrap();
    assert!(e.epochs(&t).is_some_and(|x| x.read.holds_any()), "kept while it waits");
    e.removal_done(&c).unwrap();
    assert!(e.waiting_removals().is_empty());
    assert!(e.epochs(&t).is_none_or(|x| x.read.held().next().is_none()), "dropped");
}

// spec/permissions.md §3 (Lost access): each lost actor drops once the own self-removals behind
// it are done; one still waiting holds back nothing else.
#[test]
fn a_self_removal_done_drops_its_own_loss_alone_spec_perm_3() {
    let (mut lp, ps) = people(2);
    let (t1, t2) = (thing_of(&mut lp, 0, ps[0]), thing_of(&mut lp, 0, ps[0]));
    for t in [t1, t2] {
        lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Write)).unwrap();
    }
    spread(&mut lp);
    let e = &mut lp.peers[1].engine;
    let c1 = e.demote(&t1, &Demotion { holder: ps[1], new: None, retain: None }).unwrap().commits[0];
    let c2 = e.demote(&t2, &Demotion { holder: ps[1], new: None, retain: None }).unwrap().commits[0];
    assert_eq!(*e.waiting_removals(), BTreeSet::from([c1, c2]));
    e.removal_done(&c1).unwrap();
    assert!(e.epochs(&t1).is_none_or(|x| x.read.held().next().is_none()), "t1 dropped");
    assert!(e.epochs(&t2).is_some_and(|x| x.read.holds_any()), "t2 waits on its own removal");
    e.removal_done(&c2).unwrap();
    assert!(e.epochs(&t2).is_none_or(|x| x.read.held().next().is_none()), "t2 dropped");
}

// spec/permissions.md §3 (Lost access): a self-removal sync is done with leaves no wait behind:
// peer 1 leaves a thing it still reads through a holder, then is removed from the holder; the
// lost-access trigger drops the thing.
#[test]
fn a_loss_behind_a_done_self_removal_drops_at_the_trigger_spec_perm_3() {
    let (mut lp, ps) = people(2);
    let (g, t) = (thing_of(&mut lp, 0, ps[0]), thing_of(&mut lp, 0, ps[0]));
    let e = &mut lp.peers[0].engine;
    e.grant(&g, &ps[1], &edge_of(Role::Read)).unwrap();
    e.grant(&t, &g, &edge_of(Role::Read)).unwrap();
    e.grant(&t, &ps[1], &edge_of(Role::Write)).unwrap();
    spread(&mut lp);
    let e = &mut lp.peers[1].engine;
    let c = e.demote(&t, &Demotion { holder: ps[1], new: None, retain: None }).unwrap().commits[0];
    e.removal_done(&c).unwrap();
    assert!(e.waiting_removals().is_empty());
    assert!(e.epochs(&t).is_some_and(|x| x.read.holds_any()), "read through the holder");
    spread(&mut lp);
    lp.peers[0].engine.demote(&g, &Demotion { holder: ps[1], new: None, retain: None }).unwrap();
    spread(&mut lp);
    let e = &mut lp.peers[1].engine;
    e.role_duties().unwrap();
    assert!(e.epochs(&t).is_none_or(|x| x.read.held().next().is_none()), "dropped");
}

/// Whether node `i` holds a read secret of `t`.
fn reads(lp: &LocalPeer, i: usize, t: &Tid) -> bool {
    lp.peers[i].engine.epochs(t).is_some_and(|x| x.read.holds_any())
}

/// Tells node `i` sync is done with every removal it waits on.
fn all_done(lp: &mut LocalPeer, i: usize) {
    let e = &mut lp.peers[i].engine;
    for c in e.waiting_removals().iter() {
        e.removal_done(c).unwrap();
    }
    assert!(e.waiting_removals().is_empty(), "node {i}");
}

// spec/permissions.md §3 (Lost access: a self-removal by itself, its account or a key actor it
// holds): another account's removal of this account is no wait of its; an own removal that
// leaves a path drops nothing when done; a done told for a commit not waited on drops nothing.
#[test]
fn only_an_own_self_removal_waits_and_done_drops_only_the_lost_spec_perm_3() {
    let (mut lp, a, t) = siblings_granted();
    let b = lp.peers[2].engine.account().unwrap().unwrap().0;
    let g = thing_of(&mut lp, 2, b);
    lp.peers[2].engine.grant(&g, &a, &edge_of(Role::Read)).unwrap();
    lp.peers[2].engine.grant(&t, &g, &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    let other = lp.peers[2].engine.demote(&t, &Demotion { holder: a, new: None, retain: None }).unwrap().commits[0];
    spread(&mut lp);
    for i in [0, 1] {
        assert!(lp.peers[i].engine.waiting_removals().is_empty(), "node {i}: another account's removal is no wait");
        lp.peers[i].engine.removal_done(&other).unwrap();
        assert!(reads(&lp, i, &t), "node {i}: a done not waited on drops nothing");
    }
    lp.peers[2].engine.grant(&t, &a, &edge_of(Role::Write)).unwrap();
    spread(&mut lp);
    let own = lp.peers[0].engine.demote(&t, &Demotion { holder: a, new: None, retain: None }).unwrap().commits[0];
    spread(&mut lp);
    for i in [0, 1] {
        assert!(lp.peers[i].engine.waiting_removals().contains(&own), "node {i} waits on the own removal");
        all_done(&mut lp, i);
        assert!(reads(&lp, i, &t), "node {i} still reads through the holder: nothing dropped");
    }
}

// spec/permissions.md §3 (Lost access): both siblings remove their account from a thing while
// apart; once each holds both removals and sync is done with what it waits on, each drops.
#[test]
fn siblings_removing_at_once_both_drop_spec_perm_3() {
    let (mut lp, a, t) = siblings_granted();
    for i in [0, 1] {
        lp.peers[i].engine.demote(&t, &Demotion { holder: a, new: None, retain: None }).unwrap();
        lp.advance(10);
    }
    spread(&mut lp);
    for i in [0, 1] {
        assert!(!lp.peers[i].engine.waiting_removals().is_empty(), "node {i} waits");
        assert!(reads(&lp, i, &t), "node {i} keeps it while it waits");
        all_done(&mut lp, i);
        assert!(!reads(&lp, i, &t), "node {i} dropped");
    }
}

// spec/permissions.md §3 (Lost access): a re-grant applied while a sibling's removal waits
// keeps the secrets when the removal is done.
#[test]
fn a_regrant_during_the_wait_keeps_the_secrets_spec_perm_3() {
    let (mut lp, a, t) = siblings_granted();
    let c = lp.peers[0].engine.demote(&t, &Demotion { holder: a, new: None, retain: None }).unwrap().commits[0];
    spread(&mut lp);
    assert!(lp.peers[1].engine.waiting_removals().contains(&c));
    lp.advance(10);
    lp.peers[2].engine.grant(&t, &a, &edge_of(Role::Write)).unwrap();
    spread(&mut lp);
    for i in [0, 1] {
        all_done(&mut lp, i);
        lp.peers[i].engine.role_duties().unwrap();
        assert!(reads(&lp, i, &t), "node {i} re-granted: kept");
    }
}

// spec/permissions.md §3 (Lost access): a crash after the drop and before the removal leaves
// the wait (`removal_done`'s order) finds it waiting after a restart; done again clears it.
#[test]
fn a_crash_between_drop_and_clear_is_done_again_spec_perm_3() {
    let (mut lp, a, t) = siblings_granted();
    let c = lp.peers[0].engine.demote(&t, &Demotion { holder: a, new: None, retain: None }).unwrap().commits[0];
    spread(&mut lp);
    let e = &mut lp.peers[1].engine;
    let lost: Vec<Tid> = e.lost_leaving().unwrap().actors.into_keys().collect();
    assert!(lost.contains(&t), "t lost behind the removal");
    e.forget_lost(osis_engine::rotation::LostScope::Only(&lost)).unwrap();
    lp.peers[1].restart(1).unwrap();
    let e = &mut lp.peers[1].engine;
    assert_eq!(*e.waiting_removals(), BTreeSet::from([c]), "still waiting after the restart");
    assert!(!reads(&lp, 1, &t));
    all_done(&mut lp, 1);
}


// spec/sync-ids.md §6 (steps: registered only once the source holds the role commits its epochs
// depend on): the genesis step's needs are the rotations of its epochs, held here.
#[test]
fn a_step_needs_its_epochs_rotations_spec_sync_ids_6() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (_, d) = e.account().unwrap().unwrap();
    let ids = e.sync_ids(&d).unwrap();
    let step = ids[0].path.steps[0].0.id();
    let needs = e.step_needs(&ids[0].id, &step).unwrap();
    assert!(!needs.is_empty());
    assert!(needs.iter().all(|c| e.core.ix.commits.contains_key(c)));
}

/// Peer `i`'s node writes its own `reach.0` a second later; the commit (a card commit, spec/
/// permissions.md §4).
fn reach(lp: &mut LocalPeer, i: usize, k: u8) -> osis_base::CommitId {
    lp.advance(1000);
    let n = lp.peers[i].engine.tid();
    let mut m = Mutation::new();
    m.set(n, &ct::REACH, &ct::Reach { dialable: [k; 32], items: Vec::new(), account: None }).unwrap();
    lp.peers[i].engine.commit(m).unwrap().unwrap()
}

// spec/sync-judgement.md §2 must-not-hold (another node's card commit once a later valid card
// commit of that node writing the same aspect is under the sync ID, an entry of it this node
// opened). Hostile: a later card held as a commit with no entry of it opened here (a forged
// supersession) supersedes nothing, and this node's own card never goes by this rule. The rule
// firing: core/engine/src/sync/tests_facts.rs.
#[test]
fn a_card_known_only_as_a_commit_supersedes_nothing_spec_sync_judgement_2() {
    let (mut lp, d) = crate::flows::account_two_nodes();
    let ds = lp.peers[0].engine.sync_id_of(&d).unwrap().unwrap();
    let old = reach(&mut lp, 1, 1);
    reach(&mut lp, 1, 2);
    let (o1, _) = (reach(&mut lp, 0, 3), reach(&mut lp, 0, 4));
    spread(&mut lp);
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.read_facts(&ds, &old).unwrap().must_not, None, "a later card held but never opened here: kept");
    assert_eq!(e.read_facts(&ds, &o1).unwrap().must_not, None, "its own card: never by this rule");
}

// spec/sync-judgement.md §2 must-not-hold (another node's card commit, for `node.0` and `reach.0`,
// once that node is a node of the account no more after an applied edge write on D ended its
// grant). Hostile: a removed node paired again is a node again, its card kept; its `keys.0` card
// never goes by this rule.
#[test]
fn a_card_goes_with_its_nodes_grant_spec_sync_judgement_2() {
    let (mut lp, d) = crate::flows::account_two_nodes();
    let ds = lp.peers[0].engine.sync_id_of(&d).unwrap().unwrap();
    let n1 = lp.peers[1].engine.tid();
    let r = reach(&mut lp, 1, 1);
    spread(&mut lp);
    let keys = *lp.peers[0].engine.core.ix.by_aspect.get(&(n1, Ak::new("keys.0").unwrap())).unwrap().iter().next().unwrap();
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.read_facts(&ds, &r).unwrap().must_not, None, "a node of the account: kept");
    e.demote(&d, &Demotion { holder: n1, new: None, retain: None }).unwrap();
    assert_eq!(e.read_facts(&ds, &r).unwrap().must_not, Some(osis_engine::sync::MustNot::CardEnded));
    assert_eq!(e.read_facts(&ds, &keys.1).unwrap().must_not, None, "its keys.0 card stays");
    e.pair(&n1).unwrap();
    assert_eq!(e.read_facts(&ds, &r).unwrap().must_not, None, "paired again: kept");
}

// spec/sync-judgement.md §2 required set (the certificate blobs of spec/permissions.md §4): the
// other node's `reach.0` card is in D's sync ID's required set, so read never judges it
// outside it (must-not-hold, deleted at a node keeping the sync ID unread by a delete-key
// holder); sealed as a copy, it opens at the card's own node.
#[test]
fn another_nodes_card_is_in_the_required_set_spec_sync_judgement_2() {
    let (mut lp, d) = crate::flows::account_two_nodes();
    let ds = lp.peers[0].engine.sync_id_of(&d).unwrap().unwrap();
    let r = reach(&mut lp, 1, 1);
    spread(&mut lp);
    let e = &mut lp.peers[0].engine;
    let b = e.sync_bodies(&r).unwrap();
    assert!(b.get(&ds).is_some_and(|m| m.certificate && m.copy && !m.parts.is_empty()), "the card's certificate body under D's sync ID: {b:?}");
    let f = e.body_facts(&ds, &r).unwrap();
    assert!(f.required && !f.closure, "{f:?}");
    let (sealed, wrap) = e.seal_body(&ds, &r, &[], &mut SeededRng::from_u64(1)).unwrap().expect("sealed as a certificate copy");
    assert_eq!(e.blob_of(&sealed.id).map(|r| r.copy), Some(true));
    match lp.peers[1].engine.open_entry(&ds, &sealed.id, &wrap, &sealed.blob, u64::MAX).unwrap() {
        osis_engine::sync::Opened::Commit(c, _) => assert_eq!(c, r),
        o => panic!("{o:?}"),
    }
}

/// The key actors `e` proves as besides its account (`provers`: what it acts for on the wire).
fn link_keys_held(e: &mut osis_engine::Engine) -> BTreeSet<Tid> {
    let me = e.account().unwrap().map(|(a, _)| a);
    e.provers(false).unwrap().iter().map(|(_, r)| r.tid()).filter(|t| Some(*t) != me).collect()
}

// spec/permissions.md §7 (First contact: the redeemer proves L until its join is held, then keeps
// the link's peers, not the seed): a link key is held exactly while a followed link names
// it. Two link texts sharing one seed: letting one go keeps the key the other still uses, across
// a reload; it goes with the last. A key held by `hold_key_actor` stays when a link naming it goes.
#[test]
fn a_link_key_goes_with_the_last_followed_link_naming_it_spec_permissions_7() {
    let (mut lp, ps) = people(2);
    let target = thing_of(&mut lp, 0, ps[0]);
    let spec = osis_engine::flows::LinkSpec { target, role: Role::Read, until: None, peers: Vec::new(), single_use: false };
    let a = lp.peers[0].engine.create_link(&ps[0], &spec).unwrap().0;
    let b = lp.peers[0].engine.create_link(&ps[0], &spec).unwrap().0;
    // b's text with a's seed
    let shared = osis_blob::ShareLink { seed: a.seed.clone(), ..b.clone() };
    let l = osis_engine::identity::key_actor_tid(&a.seed);
    let e = &mut lp.peers[1].engine;
    assert!(link_keys_held(e).is_empty());
    e.follow_link(&a).unwrap();
    e.follow_link(&shared).unwrap();
    e.unfollow_link(&a.k);
    assert_eq!(link_keys_held(e), BTreeSet::from([l]), "b's text still names L");
    e.reload().unwrap();
    assert_eq!(link_keys_held(e), BTreeSet::from([l]), "and after a reload");
    e.unfollow_link(&shared.k);
    assert!(link_keys_held(e).is_empty(), "L goes with the last link naming it");
    e.check_index();
    e.hold_key_actor(a.seed.clone()).unwrap();
    e.reload().unwrap();
    e.follow_link(&a).unwrap();
    e.unfollow_link(&a.k);
    assert_eq!(link_keys_held(e), BTreeSet::from([l]), "held by hold_key_actor, across a reload: kept");
    e.check_index();
    e.drop_key_actor(&l);
    assert!(link_keys_held(e).is_empty());
    e.check_index();
}

// spec/permissions.md §7 (First contact): following a link again under another seed holds the new
// key and lets the old go (no other link names it), across a reload; letting the link go holds none.
#[test]
fn following_a_link_again_under_another_seed_lets_its_old_key_go_spec_permissions_7() {
    let (mut lp, ps) = people(2);
    let target = thing_of(&mut lp, 0, ps[0]);
    let spec = osis_engine::flows::LinkSpec { target, role: Role::Read, until: None, peers: Vec::new(), single_use: false };
    let a = lp.peers[0].engine.create_link(&ps[0], &spec).unwrap().0;
    let b = lp.peers[0].engine.create_link(&ps[0], &spec).unwrap().0;
    let reseeded = osis_blob::ShareLink { seed: b.seed.clone(), ..a.clone() };
    let lb = osis_engine::identity::key_actor_tid(&b.seed);
    let e = &mut lp.peers[1].engine;
    e.follow_link(&a).unwrap();
    e.follow_link(&reseeded).unwrap();
    assert_eq!(link_keys_held(e), BTreeSet::from([lb]), "a's old key let go");
    e.reload().unwrap();
    assert_eq!(link_keys_held(e), BTreeSet::from([lb]), "and after a reload");
    e.check_index();
    e.unfollow_link(&a.k);
    assert!(link_keys_held(e).is_empty());
    e.check_index();
}

// spec/sync-status.md §3 History complete (a complete pass of every sync ID carrying the thing):
// a fresh node wants one pass of D's sync ID, whenever begun; history is complete once it is noted.
#[test]
fn history_completes_with_a_pass_spec_sync_status_3() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (_, d) = e.account().unwrap().unwrap();
    let ds = e.sync_id_of(&d).unwrap().unwrap();
    assert_eq!(e.passes_wanted().unwrap().get(&ds), Some(&0), "one pass, whenever");
    assert!(!e.history_complete(&d).unwrap());
    let now = e.begin_pass();
    e.note_complete_pass(&ds, now).unwrap();
    assert!(e.history_complete(&d).unwrap() && !e.passes_wanted().unwrap().contains_key(&ds));
}

// spec/crypto.md §4 (names): a rotation names the edge writes its rotator held that pin a holder
// below a role, and what it names travels with it: a removal's rotation logs with it the earlier
// removal it names.
#[test]
fn a_rotation_logs_with_it_the_commits_it_names_spec_crypto_4() {
    let (mut lp, ps) = people(3);
    let t = thing_of(&mut lp, 0, ps[0]);
    let e = &mut lp.peers[0].engine;
    e.give_own_secrets(&t).unwrap();
    e.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
    e.grant(&t, &ps[2], &edge_of(Role::Read)).unwrap();
    let first = *e.demote(&t, &Demotion { holder: ps[1], new: None, retain: None }).unwrap().commits.last().unwrap();
    let second = *e.demote(&t, &Demotion { holder: ps[2], new: None, retain: None }).unwrap().commits.last().unwrap();
    let with = e.logged_with(&second).unwrap();
    assert!(with.contains(&first), "the earlier removal it names: {with:?}");
}

/// A record blob of `records` under `t`'s current read epoch at peer `i` (spec/wire.md §3), as
/// any reader of the sync ID could frame one: its ID, bytes and wrap.
fn record_blob_by_hand(lp: &mut LocalPeer, i: usize, t: &Tid, records: &[osis_base::CreationRecord]) -> (osis_base::BlobId, Vec<u8>, osis_engine::sync::Wrap) {
    let mut rng = SeededRng::from_u64(17);
    let plain = osis_commit::record_blob::encode_record_blob(records);
    let prefix = osis_blob::Prefix::for_groups(osis_blob::Prefix::random_salt(&mut rng), &[7; 16], None, &[]).unwrap().with_class(osis_blob::Class::Durable);
    let (key, blob) = osis_blob::frame(&prefix, &plain, &mut rng).unwrap();
    let id = osis_blob::blob_id(&blob);
    let w = lp.peers[i].engine.wrap_secret(t, None).unwrap().expect("a read epoch");
    let wrap = osis_crypto::wrap(&w, &id, &key, 0).unwrap();
    (id, blob, wrap)
}

// spec/wire.md §3 (creation record; Record blob), spec/permissions.md §4 (Chain certificates),
// spec/commits.md §4 (Pending storage): a record's tid is the hash of its encoding, records go raw
// in a record blob. A reader of S framing a record blob cannot plant a false record for a thing it
// names: a record altered to name another first admin is a record of another tid, and the
// receiver learns nothing of the thing; the genuine record, sealed by its holder, is kept loose
// until a commit here awaits it, then learned as it is.
#[test]
fn a_forged_record_in_a_record_blob_names_no_other_thing_spec_wire_3() {
    let (mut lp, d) = crate::flows::account_two_nodes();
    let ds = lp.peers[0].engine.sync_id_of(&d).unwrap().unwrap();
    let a = lp.peers[0].engine.account().unwrap().unwrap().0;
    let u = thing_of(&mut lp, 0, a);
    let real = lp.peers[0].engine.core.created(&u).cloned().unwrap();
    assert!(lp.peers[1].engine.core.created(&u).is_none(), "u not spread");
    let osis_base::CreationRecord::Thing { nonce, .. } = real.clone() else { panic!() };
    let forged = osis_base::CreationRecord::Thing { admin: lp.peers[1].engine.tid(), nonce, link: None };
    assert_ne!(forged.tid(), u);
    let (id, blob, wrap) = record_blob_by_hand(&mut lp, 0, &d, std::slice::from_ref(&forged));
    match lp.peers[1].engine.open_entry(&ds, &id, &wrap, &blob, u64::MAX).unwrap() {
        osis_engine::sync::Opened::Records(tids) => assert_eq!(tids, [forged.tid()].into()),
        o => panic!("{o:?}"),
    }
    assert!(lp.peers[1].engine.core.created(&u).is_none(), "nothing learned of u");
    let (id, bytes, wrap) = lp.peers[0].engine.seal_records(&ds, &[u].into(), &mut SeededRng::from_u64(3)).unwrap().expect("sealed");
    assert!(matches!(lp.peers[1].engine.open_entry(&ds, &id, &wrap, &bytes, u64::MAX).unwrap(), osis_engine::sync::Opened::Records(_)));
    assert!(lp.peers[1].engine.core.created(&u).is_none() && lp.peers[1].engine.carries_loose(&id), "nothing awaits u yet: loose");
    later_write_on(&mut lp, u);
    assert_eq!(lp.peers[1].engine.core.created(&u), Some(&real));
    assert!(!lp.peers[1].engine.carries_loose(&id), "its carrier gives something held");
}

/// Peer 0 writes on `u` and peer 1 ingests that commit alone (`u`'s record not with it): it
/// awaits `u`'s record there.
fn later_write_on(lp: &mut LocalPeer, u: Tid) {
    let mut m = Mutation::new();
    m.set(u, &REG, &s("later")).unwrap();
    let c = lp.peers[0].engine.commit(m).unwrap().unwrap();
    let bytes = lp.peers[0].engine.commit_bytes(&c).unwrap().unwrap();
    lp.peers[1].engine.ingest(&bytes, Vec::new()).unwrap();
}

/// `n` junk records (things no commit names) and one genuine one in record blobs a reader of
/// S frames, opened at peer 1, then the junk blob's entry gone: (loose records while carried,
/// records learned, loose left, whether the genuine one was learned once awaited).
fn junk_records(n: usize) -> (usize, usize, usize, bool) {
    let (mut lp, d) = crate::flows::account_two_nodes();
    let ds = lp.peers[0].engine.sync_id_of(&d).unwrap().unwrap();
    let a = lp.peers[0].engine.account().unwrap().unwrap().0;
    let u = thing_of(&mut lp, 0, a);
    let real = lp.peers[0].engine.core.created(&u).cloned().unwrap();
    let junk: Vec<osis_base::CreationRecord> = (0..n).map(|i| osis_base::CreationRecord::Thing { admin: a, nonce: { let mut x = [9u8; 32]; x[..8].copy_from_slice(&(i as u64).to_be_bytes()); x }, link: None }).collect();
    let known = |lp: &LocalPeer| junk.iter().filter(|r| lp.peers[1].engine.core.created(&r.tid()).is_some()).count();
    let (jb, jbytes, jwrap) = record_blob_by_hand(&mut lp, 0, &d, &junk);
    let (gb, gbytes, gwrap) = record_blob_by_hand(&mut lp, 0, &d, std::slice::from_ref(&real));
    assert_ne!(jb, gb);
    for (b, bytes, wrap) in [(&jb, &jbytes, &jwrap), (&gb, &gbytes, &gwrap)] {
        assert!(matches!(lp.peers[1].engine.open_entry(&ds, b, wrap, bytes, u64::MAX).unwrap(), osis_engine::sync::Opened::Records(_)));
    }
    let carried = lp.peers[1].engine.loose_records();
    let learned = known(&lp);
    lp.peers[1].engine.forget_carrier(&jb);
    let left = lp.peers[1].engine.loose_records();
    later_write_on(&mut lp, u);
    (carried, learned + known(&lp), left, lp.peers[1].engine.core.created(&u) == Some(&real))
}

// spec/commits.md §4 (Pending storage), spec/requirements.md (malicious readers only waste
// storage; peer input never causes unbounded storage): records nothing here awaits are kept only
// while their carrier is (its entry charged to the peer that brought it): n and 10n junk records
// are never learned and go with their blob's entry, and they evict nothing another blob carries.
#[test]
fn junk_records_go_with_their_carrier_spec_commits_4() {
    for n in [20, 200] {
        let (carried, learned, left, genuine) = junk_records(n);
        assert_eq!(carried, n + 1, "kept loose while carried");
        assert_eq!(learned, 0, "never learned: nothing names them");
        assert_eq!(left, 1, "gone with their carrier; the other blob's stays");
        assert!(genuine, "the other blob's record, learned once awaited");
    }
}

// spec/commits.md §4 (Records: learned once something awaits it): a loose record is learned when
// a commit by its actor arrives, the author's record being what that commit awaits.
#[test]
fn a_loose_author_record_is_learned_when_its_commit_comes_spec_commits_4() {
    let mut lp = crate::common::net_bare(2, 5);
    let a = lp.peers[0].engine.create_account().unwrap().0.account;
    let b = lp.peers[1].engine.create_account().unwrap().0.account;
    let t = thing_of(&mut lp, 0, a);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    let s0 = lp.peers[0].engine.sync_id_of(&t).unwrap().unwrap();
    let rec = lp.peers[1].engine.core.created(&b).cloned().unwrap();
    let (id, bytes, wrap) = record_blob_by_hand(&mut lp, 0, &t, std::slice::from_ref(&rec));
    assert!(matches!(lp.peers[0].engine.open_entry(&s0, &id, &wrap, &bytes, u64::MAX).unwrap(), osis_engine::sync::Opened::Records(_)));
    assert!(lp.peers[0].engine.core.created(&b).is_none() && lp.peers[0].engine.carries_loose(&id));
    let u = thing_of(&mut lp, 1, b);
    let mut m = Mutation::new();
    m.set(u, &REG, &s("later")).unwrap();
    let c = lp.peers[1].engine.commit(m).unwrap().unwrap();
    let cb = lp.peers[1].engine.commit_bytes(&c).unwrap().unwrap();
    lp.peers[0].engine.ingest(&cb, Vec::new()).unwrap();
    assert_eq!(lp.peers[0].engine.core.created(&b), Some(&rec), "the author's record, awaited");
}

// spec/commits.md §4 (Records: learned once something awaits it; Examined again): a pending
// commit that, examined again for one record arriving, comes to await a second record kept
// loose learns that one too, in the same `reexamine`, whichever record it awaits first.
#[test]
fn a_loose_record_awaited_after_another_arrives_is_learned_spec_commits_4() {
    for loose_author in [false, true] {
        let mut lp = crate::common::net_bare(2, 5);
        let a = lp.peers[0].engine.create_account().unwrap().0.account;
        let b = lp.peers[1].engine.create_account().unwrap().0.account;
        let t = thing_of(&mut lp, 0, a);
        lp.peers[0].engine.give_own_secrets(&t).unwrap();
        let s0 = lp.peers[0].engine.sync_id_of(&t).unwrap().unwrap();
        let u = thing_of(&mut lp, 1, b);
        let rb = lp.peers[1].engine.core.created(&b).cloned().unwrap();
        let ru = lp.peers[1].engine.core.created(&u).cloned().unwrap();
        let (loose, later) = if loose_author { (rb.clone(), ru.clone()) } else { (ru.clone(), rb.clone()) };
        let mut m = Mutation::new();
        m.set(u, &REG, &s("later")).unwrap();
        let c = lp.peers[1].engine.commit(m).unwrap().unwrap();
        let cb = lp.peers[1].engine.commit_bytes(&c).unwrap().unwrap();
        // 0's t names u holder, so u is needed here (spec/commits.md §5 What a held thing needs)
        crate::common::edge_write(&mut lp.peers[0].engine, t, u, Some(edge_of(Role::Read)), None);
        // the commit first, awaiting `later`'s record (the loose one is not yet known here)
        lp.peers[0].engine.ingest(&cb, Vec::new()).unwrap();
        let first = lp.peers[0].engine.pending().into_iter().find(|(x, _)| *x == c).map(|x| x.1);
        let (id, bytes, wrap) = record_blob_by_hand(&mut lp, 0, &t, std::slice::from_ref(&loose));
        lp.peers[0].engine.open_entry(&s0, &id, &wrap, &bytes, u64::MAX).unwrap();
        if lp.peers[0].engine.core.created(&loose.tid()).is_some() {
            continue; // the commit awaited the loose one first: learned at once (the other test)
        }
        assert!(lp.peers[0].engine.carries_loose(&id), "loose: {first:?}");
        lp.peers[0].engine.learn_records(vec![later.clone()]).unwrap();
        assert_eq!(lp.peers[0].engine.core.created(&loose.tid()), Some(&loose), "loose_author {loose_author}: awaited once {:?} arrived, now {:?}", later.tid(), lp.peers[0].engine.pending().into_iter().find(|(x, _)| *x == c));
    }
}

// spec/sync-ids.md §2 (One sync ID per actor): a commit that gives a thing role secrets of its own also
// creates its sync ID and records it in `sync.0`, in that one commit. A thing given secrets of its
// own, by `give_own_secrets` or by its first grant, has its sync ID, and the first commit
// with a `secrets.0` part on it carries a `sync.0` write too.
#[test]
fn own_secrets_and_the_sync_id_come_in_one_commit_spec_sync_ids_2() {
    for by_grant in [false, true] {
        let (mut lp, ps) = people(2);
        let admin = lp.peers[0].engine.plain_admin();
        let t = thing_of(&mut lp, 0, admin);
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.sync_id_of(&t).unwrap(), None, "a plain thing has none");
        let done = if by_grant { e.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap() } else { e.give_own_secrets(&t).unwrap() };
        assert!(e.sync_id_of(&t).unwrap().is_some(), "a sync ID (by grant: {by_grant})");
        let secrets = Ak::new("secrets.0").unwrap();
        let sync = ct::SYNC.name();
        // the first commit with a secrets.0 part on t gives them (later ones box holders)
        let first = done.commits.iter().map(|c| e.header(c).unwrap()).find(|h| h.aspects.iter().any(|a| a.tid == t && a.ak == secrets)).expect("a commit gives t its secrets");
        assert!(first.aspects.iter().any(|a| a.ak == sync), "the commit giving t secrets writes sync.0 (by grant: {by_grant})");
    }
}

// spec/commits.md §5 Destruction: nobody writes a destroyed thing, so no role commit is owed
// there. Peer 0 grants a reader with an `until`, destroys t and the `until` passes: the derived
// duty owes nothing on t, its secrets still held, past the purge's floor too.
#[test]
fn a_destroyed_thing_owes_no_role_commit_spec_commits_5() {
    let (mut lp, ps) = people(2);
    let t = thing_of(&mut lp, 0, ps[0]);
    let until = osis_base::WallMs(lp.peers[0].engine.now().0 + 100);
    lp.peers[0].engine.grant(&t, &ps[1], &ct::Edge { until: Some(until), ..edge_of(Role::Read) }).unwrap();
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let now = e.now();
    m.set(t, &ct::PURGE, &now).unwrap();
    m.purge(osis_commit::PurgeItem::Aspect { tid: t, ak: ct::CREATED.name() });
    e.commit(m).unwrap().unwrap();
    assert!(!e.knows(&t), "t destroyed");
    lp.advance(1_000);
    let e = &mut lp.peers[0].engine;
    assert!(e.held_actors().contains(&t), "its secrets held");
    assert!(!e.role_duty_due(&t).unwrap(), "nothing owed on t");
    lp.advance(osis_base::format::ROLE_KEEP_MS + 1_000);
    lp.peers[0].tick().unwrap();
    assert!(!lp.peers[0].engine.role_duty_due(&t).unwrap(), "past the floor: nothing owed on t");
}

// spec/permissions.md §3 (next-step triggers: a deposit-only step waits while an unapplied
// `keys.0` write of the actor signed by a current admin is held): admin A refreshes T's seed
// twice, the second time after a party departed and with its clock ahead, so co-admin B holds the
// first refresh applied and the second pending. B's seed then derives a deposit key other than
// the head's, but one the departed party knows: stepping to it would let that party deposit.
// Nothing is due at B until the second refresh applies; then its step is at the newest key.
#[test]
fn a_deposit_only_step_waits_for_a_seed_held_pending_spec_permissions_3() {
    let (mut lp, ps) = people(2);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Admin)).unwrap();
    spread(&mut lp);
    let s = lp.peers[0].engine.sync_id_of(&t).unwrap().unwrap();
    let first = *lp.peers[0].engine.refresh_deposit_seed(&t).unwrap().commits.last().unwrap();
    crate::flows::send(&mut lp, 0, 1, &[first]);
    lp.peers[0].clock.advance(3 * osis_base::format::MAX_DRIFT_MS / 2);
    let second = *lp.peers[0].engine.refresh_deposit_seed(&t).unwrap().commits.last().unwrap();
    let pk = lp.peers[0].engine.package(&second).unwrap().unwrap();
    assert!(matches!(lp.deliver(1, &pk).unwrap(), osis_engine::Ingested::Pending(_, osis_engine::Reason::Drift)), "the second refresh waits at B");
    assert!(lp.peers[1].engine.due_step(&s).unwrap().is_none(), "nothing due while it waits");
    assert!(lp.peers[1].engine.issue_due_step(&s).unwrap().is_none(), "no step to the first refresh's key");
    lp.peers[1].clock.advance(3 * osis_base::format::MAX_DRIFT_MS / 2);
    lp.peers[1].reexamine().unwrap();
    let step = lp.peers[1].engine.issue_due_step(&s).unwrap().expect("due once it applied");
    let again = lp.peers[0].engine.issue_due_step(&s).unwrap().expect("A's own step");
    assert_eq!(step.keys.deposit, again.keys.deposit, "B's step is at the newest deposit key");
}
