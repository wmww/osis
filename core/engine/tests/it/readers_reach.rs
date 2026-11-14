//! What a reader, or a party gone from a thing, can make a writer keep or learn through the
//! facade's judgement (`osis_engine::sync`): promotion, grant copies, certificates and wraps,
//! each against the spec rule bounding it, over `LocalPeer` (commits carried by hand).

use crate::flows::{edge_of, people, spread, thing_of};
use osis_base::{Role, SyncId, Tid};
use osis_crypto::{KeyActorKeys, Secret32, SeededRng};
use osis_engine::flows::Demotion;
use osis_engine::local_peer::LocalPeer;
use osis_engine::sync::Promote;
use osis_engine::Mutation;
use osis_schema::core_types as ct;

/// Files `t` in peer `i`'s synced group as an item.
fn add_item(lp: &mut LocalPeer, i: usize, t: Tid) {
    let (_, d) = lp.peers[i].engine.account().unwrap().unwrap();
    let mut m = Mutation::new();
    m.op(d, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(0)], op: osis_crdt::Op::Add(osis_base::Value::Tid(t)) }).unwrap();
    lp.peers[i].engine.commit(m).unwrap().unwrap();
}

/// Peer 0 makes group `g` and grants peer 1's account `role` on it; both file it and hold
/// everything: `g`, its home sync ID, peer 1's account.
fn member_of_a_group(role: Role) -> (LocalPeer, Tid, SyncId, Tid) {
    let (mut lp, ps) = people(2);
    let g = thing_of(&mut lp, 0, ps[0]);
    let done = lp.peers[0].engine.grant(&g, &ps[1], &edge_of(role)).unwrap();
    for (h, b) in lp.inbox_blobs(0, &done).unwrap() {
        if h == ps[1] {
            lp.peers[1].engine.take_inbox_blob(&b, true).unwrap();
        }
    }
    for i in 0..2 {
        add_item(&mut lp, i, g);
    }
    spread(&mut lp);
    let s = lp.peers[0].engine.home_sync_id(&g).unwrap().unwrap();
    (lp, g, s, ps[1])
}

// spec/sync-inbox.md §4 (Promotion: only for parts whose author held write on S's actor at the
// commit's `ts`), spec/permissions.md §4 (no group sync ID holds a node's certificate, card or
// tid): reader peer 1 of group g mints key actors and writes each a `reach.0` card of 4 KB of its
// choosing. At writer peer 0, holding them, none is promotable under g's sync ID nor among what
// that sync ID must hold: a reader cannot make g's writers keep cards it mints.
#[test]
fn a_readers_minted_key_actors_cards_are_not_kept_spec_sync_inbox_4() {
    let (mut lp, _, s, _) = member_of_a_group(Role::Read);
    let mut cards = Vec::new();
    for i in 0..3u8 {
        let e = &mut lp.peers[1].engine;
        let seed = Secret32::from_bytes([i + 1; 32]);
        let k = e.hold_key_actor(seed.clone()).unwrap();
        let mut m = Mutation::new();
        assert_eq!(m.create(osis_engine::identity::key_actor_record(&KeyActorKeys::from_seed(&seed).signing.verifying_key(), &seed)), k);
        m.sign_as(k);
        let reach = ct::Reach { dialable: [0; 32], items: vec![format!("{i}{}", "x".repeat(4000))], account: None };
        m.set(k, &ct::REACH, &reach).unwrap();
        cards.push(e.commit(m).unwrap().unwrap());
    }
    spread(&mut lp);
    let e = &mut lp.peers[0].engine;
    for c in &cards {
        assert!(e.header(c).is_some(), "the writer holds the card");
        assert_eq!(e.promotable(&s, c).unwrap(), Promote::Never, "a minted key actor's card is never promoted");
        assert!(!e.sync_bodies(c).unwrap().contains_key(&s), "nor held under g's sync ID");
    }
}

// spec/sync-inbox.md §4 (Promotion: only for parts whose author held write on S's actor at the
// commit's `ts`): reader peer 1 of group g grants g read on things it makes. At writer peer 0,
// holding the grants, none is promotable under g's sync ID: a reader's deposit of its own grant
// to the group is never stamped by promotion.
#[test]
fn a_readers_grant_to_the_group_is_not_promoted_spec_sync_inbox_4() {
    let (mut lp, g, s, me) = member_of_a_group(Role::Read);
    let grants: Vec<_> = (0..2).map(|_| share_with(&mut lp, 1, g, me)).collect();
    spread(&mut lp);
    for c in &grants {
        assert_eq!(lp.peers[0].engine.promotable(&s, c).unwrap(), Promote::Never);
    }
}

/// Peer `i` makes a thing of its own and grants `g` read on it: the grant commit.
fn share_with(lp: &mut LocalPeer, i: usize, g: Tid, me: Tid) -> osis_base::CommitId {
    let t = thing_of(lp, i, me);
    *lp.peers[i].engine.grant(&t, &g, &edge_of(Role::Read)).unwrap().commits.last().unwrap()
}

// spec/sync-inbox.md §5 (Grant copy: only an edge write whose author held write on the actor at its
// `ts`), spec/requirements.md (posting into a shared space needs write on its actor): reader peer
// 1 of group g mints `DEPOSITS_WAITING + 8` things and grants g read on each; writer peer 0 shares
// one of its own. At peer 0, none of the reader's grants is held under g's sync ID (a reader cannot
// make g's writers keep what it mints), the writer's is.
#[test]
fn a_readers_grants_to_the_group_are_no_grant_copies_spec_sync_inbox_5() {
    let (mut lp, g, s, me) = member_of_a_group(Role::Read);
    let n = osis_base::format::DEPOSITS_WAITING + 8;
    let grants: Vec<_> = (0..n).map(|_| share_with(&mut lp, 1, g, me)).collect();
    let writer = lp.peers[0].engine.account().unwrap().unwrap().0;
    let ours = share_with(&mut lp, 0, g, writer);
    spread(&mut lp);
    let e = &mut lp.peers[0].engine;
    let held = grants.iter().filter(|c| e.sync_bodies(c).unwrap().contains_key(&s)).count();
    assert_eq!(held, 0, "{held} of {n} reader grants held under g's sync ID");
    assert!(e.sync_bodies(&ours).unwrap().contains_key(&s), "the writer's grant is g's grant copy");
}

// spec/crypto.md §3 (deposit seed: a fresh one in each rotation), §5 (who wraps under what: a
// removal's rotation commit is wrapped under the epoch it supersedes): peer 0 removes reader
// peer 1 from thing t, which rotates t and writes a fresh deposit seed in t's `keys.0`. Peer 1,
// opening that commit's entry under t's sync ID with the secrets it keeps, should not learn the
// seed. Fails: the one blob carries `keys.0` beside the boxes that need the old wrap
// (issues/fresh-deposit-seed-readable-by-departed.md, accepted residual).
#[test]
#[ignore = "issues/fresh-deposit-seed-readable-by-departed.md"]
fn a_removed_reader_never_learns_the_fresh_deposit_seed_spec_crypto_3() {
    let (mut lp, t, s, p1) = member_of_a_group(Role::Read);
    let old = lp.peers[0].engine.deposit_seed(&t).unwrap().unwrap();
    let done = lp.peers[0].engine.demote(&t, &Demotion { holder: p1, new: None, retain: None }).unwrap();
    let new = lp.peers[0].engine.deposit_seed(&t).unwrap().unwrap();
    assert_ne!(old.expose(), new.expose(), "refreshed");
    let mut rng = SeededRng::from_u64(9);
    for c in &done.commits {
        let Some((sealed, wrap)) = lp.peers[0].engine.seal_body(&s, c, &[], &mut rng).unwrap() else { continue };
        lp.peers[1].engine.open_entry(&s, &sealed.id, &wrap, &sealed.blob).unwrap();
    }
    let learned = lp.peers[1].engine.deposit_seed(&t).unwrap();
    assert!(learned.is_none_or(|x| x.expose() != new.expose()), "the removed reader holds the fresh seed");
}

/// The index in `c`'s header of `t`'s `keys.0` part, at peer `i`.
fn keys_part(lp: &mut LocalPeer, i: usize, c: &osis_base::CommitId, t: Tid) -> Option<usize> {
    lp.peers[i].engine.header(c).unwrap().aspects.iter().position(|a| a.tid == t && a.ak.as_str() == "keys.0")
}

// spec/crypto.md §4 (Stale: a box to a holder actor is recorded in the commit that writes it;
// Carried), spec/permissions.md §4 (current `keys.0` commits: with the commits holding box records
// at the newest keysets' epochs): Bob's team A holds a role on Alice's group G; Bob grants Carol's
// team M, then team N, read on A. Under G's sync ID Carol's node logs (`sync_bodies`), as A's current
// `keys.0` commits, M's grant with its record of A's box to M, though N's grant is A's newest `keys.0`
// commit: so a sealer of G holding none of A's boxes finds A's epoch stale once M moves on.
#[test]
fn a_grants_box_record_goes_with_the_keysets_under_the_holders_sync_ids_spec_crypto_4() {
    let (mut lp, ps) = people(3);
    let (alice, bob, carol) = (ps[0], ps[1], ps[2]);
    let g = thing_of(&mut lp, 0, alice);
    let a = thing_of(&mut lp, 1, bob);
    let m = thing_of(&mut lp, 2, carol);
    let n = thing_of(&mut lp, 2, carol);
    spread(&mut lp);
    for x in [m, n] {
        lp.peers[2].engine.give_own_secrets(&x).unwrap();
    }
    lp.peers[1].engine.give_own_secrets(&a).unwrap();
    spread(&mut lp);
    lp.peers[0].engine.grant(&g, &a, &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    let to_m = *lp.peers[1].engine.grant(&a, &m, &edge_of(Role::Read)).unwrap().commits.last().unwrap();
    spread(&mut lp);
    let to_n = *lp.peers[1].engine.grant(&a, &n, &edge_of(Role::Read)).unwrap().commits.last().unwrap();
    spread(&mut lp);
    add_item(&mut lp, 2, g);
    spread(&mut lp);
    let s = lp.peers[0].engine.home_sync_id(&g).unwrap().unwrap();
    let rec = keys_part(&mut lp, 2, &to_m, a).expect("M's grant records A's box to M");
    assert!(keys_part(&mut lp, 2, &to_n, a).is_some(), "N's grant is A's newer keys.0 commit");
    let under = lp.peers[2].engine.sync_bodies(&to_m).unwrap().get(&s).cloned();
    assert!(under.as_ref().is_some_and(|b| b.certificate && b.parts.contains(&rec)), "M's grant's record under G's sync ID: {under:?}");
}
