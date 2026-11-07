//! Addenda (spec/permissions.md §5.2, Addenda; issues/revocation-without-arbiter.md's expected
//! outcomes): writers vouch for a removed holder's edits the remover never received.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::flows::Demotion;
use crate::local_peer::LocalPeer;
use crate::Mutation;
use osis_base::{Ak, CommitId, Role, Tid, Value};
use osis_schema::core_types as ct;

const T0: osis_base::WallMs = osis_base::WallMs(1_700_000_000_000);

fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, tied: None }
}

/// `n` peers; peer 0 makes thing `t` and grants peers 1.. `roles`; everyone synced.
fn world(n: usize, seed: u64, roles: &[Role]) -> (LocalPeer, Tid) {
    let mut lp = LocalPeer::new(n, seed, T0).unwrap();
    lp.sync_all().unwrap();
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    m.set(t, &ak("x:a.0"), &Value::Int(0)).unwrap();
    lp.peers[0].commit(m).unwrap();
    for (i, r) in roles.iter().enumerate() {
        let who = lp.peers[i + 1].engine.tid();
        lp.peers[0].engine.grant(&t, &who, &edge(*r)).unwrap();
    }
    lp.sync_all().unwrap();
    lp.advance(1000);
    (lp, t)
}

fn write(lp: &mut LocalPeer, by: usize, t: Tid, a: &str, v: i64) -> CommitId {
    let mut m = Mutation::new();
    m.set(t, &ak(a), &Value::Int(v)).unwrap();
    let id = lp.peers[by].commit(m).unwrap().unwrap();
    lp.advance(1000);
    id
}

/// A removal stamped a second after everything so far: what the peers received so far was
/// received before its `ts`.
fn remove(lp: &mut LocalPeer, by: usize, t: Tid, holder: usize) -> CommitId {
    lp.advance(1000);
    let h = lp.peers[holder].engine.tid();
    let d = Demotion { holder: h, new: None, retain: None };
    let id = *lp.peers[by].engine.demote(&t, &d).unwrap().commits.last().unwrap();
    lp.advance(1000);
    id
}

fn reads(lp: &mut LocalPeer, peer: usize, t: Tid, a: &str) -> Option<Value> {
    lp.peers[peer].engine.get(&t, &ak(a)).unwrap()
}

fn valid(lp: &LocalPeer, peer: usize, c: &CommitId, t: Tid, a: &str) -> bool {
    let m = lp.peers[peer].engine.core.ix.commits.get(c).unwrap();
    m.valid_at(m.aspect(&t, &ak(a)).unwrap())
}

/// The addenda commits held at `peer` on `t`, by author.
fn addenda(lp: &LocalPeer, peer: usize, t: Tid) -> Vec<(Tid, CommitId)> {
    let core = &lp.peers[peer].engine.core;
    core.ix.addenda.keys().filter(|(th, _)| *th == t).map(|(_, c)| (core.ix.commits.get(c).unwrap().view.author, *c)).collect()
}

// spec/permissions.md §5.2 (Addenda), §5.3: Alice removes Bob without having received his edit.
// Received before the removal by a writer (Carol), the edit stays everywhere: her addendum lists
// it. Received by a reader (Eve) alone it is undone everywhere: readers vouch for nothing.
#[test]
fn unsynced_removal_witnessed_by_a_writer_spec_perm_5_2() {
    for carol_saw in [true, false] {
        let (mut lp, t) = world(4, 11, &[Role::Write, Role::Write, Role::Read]);
        let e = write(&mut lp, 1, t, "x:e.0", 7);
        lp.sync(1, if carol_saw { 2 } else { 3 }).unwrap();
        let r = remove(&mut lp, 0, t, 1);
        assert!(!lp.peers[0].engine.core.ix.commits.get(&r).unwrap().view.frontier.as_ref().unwrap().covers(&e), "not listed: never received");
        lp.sync_all().unwrap();
        for p in [0, 2, 3] {
            assert_eq!(valid(&lp, p, &e, t, "x:e.0"), carol_saw, "peer {p}, carol saw {carol_saw}");
            assert_eq!(reads(&mut lp, p, t, "x:e.0"), carol_saw.then_some(Value::Int(7)), "peer {p}");
        }
        let carol = lp.peers[2].engine.tid();
        let by_carol = addenda(&lp, 0, t).into_iter().filter(|(a, _)| *a == carol).count();
        assert_eq!(by_carol, usize::from(carol_saw), "Carol vouches iff she received it in time");
        assert!(addenda(&lp, 0, t).iter().all(|(a, _)| *a == carol), "nobody else saw it: no other addendum");
    }
}

// spec/permissions.md §5.2 (Addenda, rule 2): an edit a writer received only after the removal's
// `ts` is not vouched for.
#[test]
fn received_after_the_removal_is_not_vouched_for_spec_perm_5_2() {
    let (mut lp, t) = world(3, 12, &[Role::Write, Role::Write]);
    let e = write(&mut lp, 1, t, "x:e.0", 7);
    let r = remove(&mut lp, 0, t, 1);
    // Carol gets the edit after the removal's stamp, then the removal
    lp.sync(1, 2).unwrap();
    lp.sync(0, 2).unwrap();
    lp.sync_all().unwrap();
    assert!(lp.peers[2].engine.core.ix.commits.contains_key(&r));
    assert!(addenda(&lp, 2, t).is_empty(), "nothing to vouch for");
    assert!(!valid(&lp, 2, &e, t, "x:e.0"));
    assert!(!valid(&lp, 0, &e, t, "x:e.0"));
}

// spec/permissions.md §5.2 (Addenda, rule 5), issues/revocation-without-arbiter.md "skip then
// coverage falls": Carol vouched for Bob's edit; Alice then removes Carol without having received
// Carol's addendum, so it falls and the edit with it; Dave, a writer who received Carol's addendum
// before her removal, vouches for the addendum in turn, and the edit is back everywhere.
#[test]
fn a_fallen_addendum_is_vouched_for_in_turn_spec_perm_5_2() {
    let (mut lp, t) = world(4, 13, &[Role::Write, Role::Write, Role::Write]);
    let e = write(&mut lp, 1, t, "x:e.0", 7);
    lp.sync(1, 2).unwrap();
    remove(&mut lp, 0, t, 1);
    lp.sync(0, 2).unwrap();
    let carol = lp.peers[2].engine.tid();
    let (_, a) = addenda(&lp, 2, t).into_iter().find(|(x, _)| *x == carol).unwrap();
    // Dave receives Carol's addendum (and the edit), Alice does not
    lp.sync(2, 3).unwrap();
    lp.advance(1000);
    remove(&mut lp, 0, t, 2);
    lp.sync_all().unwrap();
    let dave = lp.peers[3].engine.tid();
    assert!(addenda(&lp, 0, t).iter().any(|(x, _)| *x == dave), "Dave vouches for Carol's addendum");
    for p in [0, 2, 3] {
        assert!(valid(&lp, p, &a, t, ct::ADDENDA_AK), "peer {p}: Carol's addendum counts again");
        assert!(valid(&lp, p, &e, t, "x:e.0"), "peer {p}: the edit is back");
        assert_eq!(reads(&mut lp, p, t, "x:e.0"), Some(Value::Int(7)), "peer {p}");
    }
}

// spec/permissions.md §5.2 (Addenda, rule 1): a reader's addendum vouches for nothing, however it
// got written.
#[test]
fn a_readers_addendum_counts_for_nothing_spec_perm_5_2() {
    let (mut lp, t) = world(3, 14, &[Role::Write, Role::Read]);
    let e = write(&mut lp, 1, t, "x:e.0", 7);
    lp.sync(1, 2).unwrap();
    let r = remove(&mut lp, 0, t, 1);
    lp.sync(0, 2).unwrap();
    assert!(addenda(&lp, 2, t).is_empty(), "a reader writes none");
    let mut m = Mutation::new();
    let op = osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::bytes(&r.0))], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&ct::Frontier { commits: [e].into_iter().collect() })) };
    m.op(t, &ct::ADDENDA, op).unwrap();
    m.unchecked = true;
    lp.peers[2].engine.core.skip_writer_rules = true;
    let forged = lp.peers[2].commit(m).unwrap().unwrap();
    lp.peers[2].engine.core.skip_writer_rules = false;
    lp.sync_all().unwrap();
    for p in [0, 2] {
        assert!(!valid(&lp, p, &forged, t, ct::ADDENDA_AK), "peer {p}");
        assert!(!valid(&lp, p, &e, t, "x:e.0"), "peer {p}");
    }
}

// spec/permissions.md §5.1 (a frontier of any size), §5.2 (Addenda): the remover's frontier
// lists what fits its list bound; the rest it lists in its own addenda, so a kick keeps every
// edit it received whatever their number.
#[test]
fn a_long_frontier_overflows_into_the_removers_addenda_spec_perm_5_1() {
    let (mut lp, t) = world(3, 16, &[Role::Write, Role::Write]);
    let es: Vec<(String, CommitId)> = (0..6).map(|i| { let a = format!("x:e{i}.0"); let id = write(&mut lp, 1, t, &a, i); (a, id) }).collect();
    lp.sync(1, 0).unwrap();
    // room for the chain certificates and a few of Bob's commits, not all
    lp.peers[0].engine.list_bound(150);
    let r = remove(&mut lp, 0, t, 1);
    let f = lp.peers[0].engine.core.ix.commits.get(&r).unwrap().view.frontier.clone().unwrap();
    let listed = es.iter().filter(|(_, id)| f.covers(id)).count();
    assert!(listed < es.len(), "the frontier left some out: {listed}");
    let alice = lp.peers[0].engine.tid();
    assert!(addenda(&lp, 0, t).iter().any(|(x, _)| *x == alice), "the remover's addendum carries the rest");
    lp.sync_all().unwrap();
    for p in [0, 2] {
        for (a, id) in &es {
            assert!(valid(&lp, p, id, t, a), "peer {p}: {a}");
        }
    }
}

// spec/permissions.md §5.2 (re-grant): an edit no writer saw is undone at every node that
// applied the removal; a re-grant makes it valid again everywhere, from the bodies kept.
#[test]
fn regrant_restores_what_no_writer_saw_spec_perm_5_2() {
    let (mut lp, t) = world(3, 17, &[Role::Write, Role::Write]);
    let e = write(&mut lp, 1, t, "x:e.0", 7);
    remove(&mut lp, 0, t, 1);
    // Carol receives the edit after the removal's stamp: she vouches for nothing
    lp.advance(1000);
    lp.sync(1, 2).unwrap();
    lp.sync(0, 2).unwrap();
    assert!(!valid(&lp, 2, &e, t, "x:e.0"));
    assert_eq!(reads(&mut lp, 2, t, "x:e.0"), None);
    let bob = lp.peers[1].engine.tid();
    lp.peers[0].engine.grant(&t, &bob, &edge(Role::Write)).unwrap();
    lp.advance(1000);
    lp.sync_all().unwrap();
    for p in [0, 1, 2] {
        assert!(valid(&lp, p, &e, t, "x:e.0"), "peer {p}");
        assert_eq!(reads(&mut lp, p, t, "x:e.0"), Some(Value::Int(7)), "peer {p}");
    }
}

/// Peer `by` writes `ak` = `v` on `t` acting for `actor`, past the writer-side rules.
fn write_as(lp: &mut LocalPeer, by: usize, actor: Tid, t: Tid, a: &str, v: i64) -> CommitId {
    let mut m = Mutation::new();
    m.set(t, &ak(a), &Value::Int(v)).unwrap();
    m.retention(t, &ak(a), osis_schema::Retention { by: osis_schema::PurgeBy::Nobody, ..Default::default() }).unwrap();
    m.act_as(actor);
    let id = lp.peers[by].commit(m).unwrap().unwrap();
    lp.advance(1000);
    id
}

/// Peer `by` writes an addendum on `t` naming removal `r` and listing `lists`, whatever it
/// received (a lying witness).
fn forge_addendum(lp: &mut LocalPeer, by: usize, t: Tid, r: CommitId, lists: &[CommitId]) -> CommitId {
    let mut m = Mutation::new();
    let op = osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::bytes(&r.0))], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&ct::Frontier { commits: lists.iter().copied().collect() })) };
    m.op(t, &ct::ADDENDA, op).unwrap();
    m.unchecked = true;
    lp.peers[by].engine.core.skip_writer_rules = true;
    let id = lp.peers[by].commit(m).unwrap().unwrap();
    lp.peers[by].engine.core.skip_writer_rules = false;
    lp.advance(1000);
    id
}

/// A team T (peer 3's actor) holds write on N; Bob (1) is a member of T; Mallory (2) writes N
/// but not T. Alice (0) removes T from N; Bob's write on N acting for T reached nobody before
/// the removal. Returns (lp, N, T, removal, Bob's write).
fn team_world(seed: u64) -> (LocalPeer, Tid, Tid, CommitId, CommitId) {
    let (mut lp, n) = world(4, seed, &[Role::Read, Role::Write]);
    let (bob, team) = (lp.peers[1].engine.tid(), lp.peers[3].engine.tid());
    lp.peers[0].engine.grant(&n, &team, &edge(Role::Write)).unwrap();
    // T is peer 3's own actor: a plain edge write, as for an account's nodes
    let mut m = Mutation::new();
    m.op(team, &ct::ROLES, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(bob))], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&edge(Role::Write))) }).unwrap();
    lp.peers[3].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.advance(1000);
    let e = write_as(&mut lp, 1, team, n, "x:e.0", 7);
    let r = remove(&mut lp, 0, n, 3);
    (lp, n, team, r, e)
}

// spec/permissions.md §5.2 (Addenda, Acting per part): a lying writer of N (Mallory, received
// Bob's write after the removal) vouches for the part on N; Bob still writes T, so the Acting
// part needs no vouching and the write counts. The same as a lying witness for a removed
// holder acting for itself: a writer can always vouch for the removed side's earlier writes on
// a thing it writes (stated limit, notes/permissions.md Revocation).
#[test]
fn lying_writer_vouches_for_a_removed_teams_write_spec_perm_5_2() {
    let (mut lp, n, _, r, e) = team_world(21);
    lp.sync(1, 2).unwrap();
    lp.sync(0, 2).unwrap();
    assert!(!valid(&lp, 2, &e, n, "x:e.0"), "Mallory received it after the removal");
    let a = forge_addendum(&mut lp, 2, n, r, &[e]);
    lp.sync_all().unwrap();
    for p in [0, 2, 3] {
        assert!(valid(&lp, p, &a, n, ct::ADDENDA_AK), "peer {p}");
        assert!(valid(&lp, p, &e, n, "x:e.0"), "peer {p}: vouched on N, acting for T unchanged");
    }
}

// spec/permissions.md §5.2 (Acting): with Bob also removed from T, a writer of N vouching for
// the part on N makes nothing count: the Acting check fails, and with it every part of the
// commit, until a writer of T vouches on T.
#[test]
fn acting_unvouched_invalidates_every_part_spec_perm_5_2() {
    let (mut lp, n, team, r, e) = team_world(22);
    let rt = remove(&mut lp, 3, team, 1);
    lp.sync(1, 2).unwrap();
    lp.sync(0, 2).unwrap();
    lp.sync(3, 2).unwrap();
    forge_addendum(&mut lp, 2, n, r, &[e]);
    lp.sync_all().unwrap();
    for p in [0, 2, 3] {
        assert!(!valid(&lp, p, &e, n, "x:e.0"), "peer {p}: Acting unvouched");
    }
    // the team's own node vouches on T (a writer of T)
    forge_addendum(&mut lp, 3, team, rt, &[e]);
    lp.sync_all().unwrap();
    for p in [0, 2, 3] {
        assert!(valid(&lp, p, &e, n, "x:e.0"), "peer {p}: both parts vouched");
    }
}


// spec/permissions.md §5.2 (Addenda): a removed writer's compaction snapshot is no plain content
// commit: no addendum lists it, and it falls with the removal while its delta, vouched for,
// stays (what it covered is fetched again, spec/permissions.md §5.2 Compaction snapshot).
#[test]
fn a_removed_writers_snapshot_is_not_vouched_for_spec_perm_5_2() {
    let (mut lp, t) = world(3, 18, &[Role::Write, Role::Write]);
    let e = write(&mut lp, 1, t, "x:e.0", 7);
    let snap = lp.peers[1].engine.snapshot(&t, &ak("x:e.0")).unwrap().unwrap();
    lp.advance(1000);
    lp.sync(1, 2).unwrap();
    let r = remove(&mut lp, 0, t, 1);
    assert!(!lp.peers[0].engine.core.ix.commits.get(&r).unwrap().view.frontier.as_ref().unwrap().covers(&snap));
    lp.sync_all().unwrap();
    for p in [0, 2] {
        assert!(valid(&lp, p, &e, t, "x:e.0"), "peer {p}: the delta");
        assert!(!valid(&lp, p, &snap, t, "x:e.0"), "peer {p}: the snapshot");
        assert_eq!(reads(&mut lp, p, t, "x:e.0"), Some(Value::Int(7)), "peer {p}");
    }
}
