//! Addenda (spec/permissions.md §5.2, Addenda): writers vouch for a removed holder's edits the remover never received.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::flows::Demotion;
use crate::local_peer::LocalPeer;
use crate::Mutation;
use osis_base::{Ak, Clock, CommitId, Role, Tid, Value};
use osis_schema::core_types as ct;

const T0: osis_base::WallMs = osis_base::WallMs(1_700_000_000_000);

fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, tied: None, floor: None }
}

/// `n` peers; peer 0 makes thing `t` and grants peers 1.. `roles`; everyone synced.
fn world(n: usize, roles: &[Role]) -> (LocalPeer, Tid) {
    LocalPeer::cached(&format!("apply::tests_addenda::world/{n}/{roles:?}"), || build(n, roles))
}

fn build(n: usize, roles: &[Role]) -> (LocalPeer, Tid) {
    let mut lp = LocalPeer::fresh(n, T0);
    lp.sync_all().unwrap();
    let me = lp.peers[0].engine.me();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    m.set(t, &ak("x:a.0"), &Value::Int(0)).unwrap();
    lp.peers[0].commit(m).unwrap();
    for (i, r) in roles.iter().enumerate() {
        let who = lp.peers[i + 1].engine.me();
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
    let h = lp.peers[holder].engine.me();
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
        let (mut lp, t) = world(4, &[Role::Write, Role::Write, Role::Read]);
        let e = write(&mut lp, 1, t, "x:e.0", 7);
        lp.sync(1, if carol_saw { 2 } else { 3 }).unwrap();
        let r = remove(&mut lp, 0, t, 1);
        assert!(!lp.peers[0].engine.core.ix.commits.get(&r).unwrap().view.frontier.as_ref().unwrap().covers(&e), "not listed: never received");
        lp.sync_all().unwrap();
        for p in [0, 2, 3] {
            assert_eq!(valid(&lp, p, &e, t, "x:e.0"), carol_saw, "peer {p}, carol saw {carol_saw}");
            assert_eq!(reads(&mut lp, p, t, "x:e.0"), carol_saw.then_some(Value::Int(7)), "peer {p}");
        }
        let carol = lp.peers[2].engine.me();
        let by_carol = addenda(&lp, 0, t).into_iter().filter(|(a, _)| *a == carol).count();
        assert_eq!(by_carol, usize::from(carol_saw), "Carol vouches iff she received it in time");
        assert!(addenda(&lp, 0, t).iter().all(|(a, _)| *a == carol), "nobody else saw it: no other addendum");
    }
}

// spec/permissions.md §5.2 (Addenda, rule 2): an edit a writer received only after the removal's
// `ts` is not vouched for.
#[test]
fn received_after_the_removal_is_not_vouched_for_spec_perm_5_2() {
    let (mut lp, t) = world(3, &[Role::Write, Role::Write]);
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

// spec/permissions.md §5.2 (Addenda, rule 5): Carol vouched for Bob's edit; Alice then removes Carol without having received
// Carol's addendum, so it falls and the edit with it; Dave, a writer who received Carol's addendum
// before her removal, vouches for the addendum in turn, and the edit is back everywhere.
#[test]
fn a_fallen_addendum_is_vouched_for_in_turn_spec_perm_5_2() {
    let (mut lp, t) = world(4, &[Role::Write, Role::Write, Role::Write]);
    let e = write(&mut lp, 1, t, "x:e.0", 7);
    lp.sync(1, 2).unwrap();
    remove(&mut lp, 0, t, 1);
    lp.sync(0, 2).unwrap();
    let carol = lp.peers[2].engine.me();
    let (_, a) = addenda(&lp, 2, t).into_iter().find(|(x, _)| *x == carol).unwrap();
    // Dave receives Carol's addendum (and the edit), Alice does not
    lp.sync(2, 3).unwrap();
    lp.advance(1000);
    remove(&mut lp, 0, t, 2);
    lp.sync_all().unwrap();
    let dave = lp.peers[3].engine.me();
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
    let (mut lp, t) = world(3, &[Role::Write, Role::Read]);
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
    let (mut lp, t) = world(3, &[Role::Write, Role::Write]);
    let es: Vec<(String, CommitId)> = (0..6).map(|i| { let a = format!("x:e{i}.0"); let id = write(&mut lp, 1, t, &a, i); (a, id) }).collect();
    lp.sync(1, 0).unwrap();
    // room for the chain certificates and a few of Bob's commits, not all
    lp.peers[0].engine.list_bound(150);
    let r = remove(&mut lp, 0, t, 1);
    let f = lp.peers[0].engine.core.ix.commits.get(&r).unwrap().view.frontier.clone().unwrap();
    let listed = es.iter().filter(|(_, id)| f.covers(id)).count();
    assert!(listed < es.len(), "the frontier left some out: {listed}");
    let alice = lp.peers[0].engine.me();
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
    let (mut lp, t) = world(3, &[Role::Write, Role::Write]);
    let e = write(&mut lp, 1, t, "x:e.0", 7);
    remove(&mut lp, 0, t, 1);
    // Carol receives the edit after the removal's stamp: she vouches for nothing
    lp.advance(1000);
    lp.sync(1, 2).unwrap();
    lp.sync(0, 2).unwrap();
    assert!(!valid(&lp, 2, &e, t, "x:e.0"));
    assert_eq!(reads(&mut lp, 2, t, "x:e.0"), None);
    let bob = lp.peers[1].engine.me();
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
    // the actor's author-chain key is not this node's: purgeable by admins
    m.retention(t, &ak(a), osis_schema::Retention { by: osis_schema::PurgeBy::Admin }).unwrap();
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
fn team_world() -> (LocalPeer, Tid, Tid, CommitId, CommitId) {
    let (lp, (n, team, r, e)) = LocalPeer::cached("apply::tests_addenda::team_world", || {
        let (lp, n, team, r, e) = build_team();
        (lp, (n, team, r, e))
    });
    (lp, n, team, r, e)
}

fn build_team() -> (LocalPeer, Tid, Tid, CommitId, CommitId) {
    let (mut lp, n) = build(4, &[Role::Read, Role::Write]);
    let (bob, team) = (lp.peers[1].engine.me(), lp.peers[3].engine.me());
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
    let (mut lp, n, _, r, e) = team_world();
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
    let (mut lp, n, team, r, e) = team_world();
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
    let (mut lp, t) = world(3, &[Role::Write, Role::Write]);
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

// spec/permissions.md §5.2 (Addenda): an addendum is the entry its own delta creates. Dave holds
// Carol's answer to the removal (an entry at the same key) when he answers: his addendum is a new
// entry beside hers, counts, and is written once, however many transactions follow.
#[test]
fn a_second_writer_answers_beside_the_first_once_spec_perm_5_2() {
    let (mut lp, t) = world(4, &[Role::Write, Role::Write, Role::Write]);
    let e = write(&mut lp, 1, t, "x:e.0", 7);
    lp.sync(1, 2).unwrap();
    lp.sync(1, 3).unwrap();
    let r = remove(&mut lp, 0, t, 1);
    lp.sync(0, 2).unwrap();
    let (carol, dave) = (lp.peers[2].engine.me(), lp.peers[3].engine.me());
    let (_, a) = addenda(&lp, 2, t).into_iter().find(|(x, _)| *x == carol).unwrap();
    // Dave gets Carol's addendum before the removal it answers
    let pk = lp.peers[2].engine.package(&a).unwrap().unwrap();
    lp.deliver(3, &pk).unwrap();
    lp.sync(0, 3).unwrap();
    for i in 0..3 {
        lp.sync_all().unwrap();
        write(&mut lp, 3, t, "x:d.0", i);
    }
    let by_dave: Vec<CommitId> = addenda(&lp, 3, t).into_iter().filter(|(x, _)| *x == dave).map(|(_, c)| c).collect();
    assert_eq!(by_dave.len(), 1, "Dave answers once");
    let lists = lp.peers[3].engine.core.ix.addenda.get(&(t, by_dave[0])).unwrap().clone();
    assert!(lists.entries.iter().any(|(rm, l)| *rm == r && l.contains(&e)), "Dave's entry lists the edit: {lists:?}");
    for p in [0, 2, 3] {
        assert!(valid(&lp, p, &by_dave[0], t, ct::ADDENDA_AK), "peer {p}: Dave's addendum counts");
        assert!(valid(&lp, p, &e, t, "x:e.0"), "peer {p}");
    }
}

// spec/permissions.md §5.2 (Addenda): an addendum without its body is still its writer's write,
// listing nothing. Carol answers Alice's removal of Bob with an addendum; Alice, not holding it,
// removes Carol; Dave receives the addendum then, invalid, and drops its body. Alice re-grants
// Carol, receives the addendum and removes her again, listing it: at Dave it turns valid with
// its body gone, and reopened and rebuilt indexes judge it alike. Its body, fetched again, then
// lists Bob's edit, which turns valid.
#[test]
fn a_bodiless_addendum_is_judged_by_its_header_spec_perm_5_2() {
    let (mut lp, t) = world(4, &[Role::Write, Role::Admin, Role::Read]);
    let e = write(&mut lp, 1, t, "x:e.0", 7);
    lp.sync(1, 2).unwrap();
    remove(&mut lp, 0, t, 1);
    lp.sync(0, 2).unwrap();
    let carol = lp.peers[2].engine.me();
    let (_, a) = addenda(&lp, 2, t).into_iter().find(|(x, _)| *x == carol).unwrap();
    remove(&mut lp, 0, t, 2);
    lp.sync(0, 3).unwrap();
    lp.sync(2, 3).unwrap();
    assert!(!valid(&lp, 3, &a, t, ct::ADDENDA_AK), "after Carol's removal, unlisted");
    lp.sync(2, 0).unwrap();
    lp.peers[0].engine.grant(&t, &carol, &edge(Role::Admin)).unwrap();
    lp.advance(1000);
    let r2 = remove(&mut lp, 0, t, 2);
    assert!(lp.peers[0].engine.core.ix.commits.get(&r2).unwrap().view.frontier.as_ref().unwrap().covers(&a));
    lp.sync(0, 3).unwrap();
    let m = lp.peers[3].engine.core.ix.commits.get(&a).unwrap();
    assert!(!m.holds(m.aspect(&t, &ak(ct::ADDENDA_AK)).unwrap()), "body not held");
    assert!(valid(&lp, 3, &a, t, ct::ADDENDA_AK), "listed by the second removal");
    let d0 = lp.peers[3].engine.index_digest();
    lp.peers[3].engine.reload().unwrap();
    assert_eq!(d0.first_diff(&lp.peers[3].engine.index_digest()), None, "reopened");
    lp.peers[3].engine.rebuild_index().unwrap();
    assert_eq!(d0.first_diff(&lp.peers[3].engine.index_digest()), None, "rebuilt");
    // the body fetched again once valid: its entry counts, and Bob's edit with it
    assert!(!valid(&lp, 3, &e, t, "x:e.0"), "listed by the bodiless addendum alone");
    lp.sync(2, 3).unwrap();
    let m = lp.peers[3].engine.core.ix.commits.get(&a).unwrap();
    assert!(m.holds(m.aspect(&t, &ak(ct::ADDENDA_AK)).unwrap()), "body fetched again");
    assert!(valid(&lp, 3, &e, t, "x:e.0"), "the arrived body's entry counts");
    let d1 = lp.peers[3].engine.index_digest();
    lp.peers[3].engine.reload().unwrap();
    assert_eq!(d1.first_diff(&lp.peers[3].engine.index_digest()), None, "reopened with the body");
    lp.peers[3].engine.rebuild_index().unwrap();
    assert_eq!(d1.first_diff(&lp.peers[3].engine.index_digest()), None, "rebuilt with the body");
}

// spec/commits.md §5 (Forgetting), spec/permissions.md §5.2 (Addenda): an addendum dropped while
// invalid lists nothing, so forgetting it leaves every judgment as it was (its thing is not
// stale after the transaction).
#[test]
fn forgetting_an_invalid_addendum_judges_nothing_spec_perm_5_2() {
    let (mut lp, t) = world(3, &[Role::Write, Role::Read]);
    let e = write(&mut lp, 1, t, "x:e.0", 7);
    lp.sync(1, 2).unwrap();
    let r = remove(&mut lp, 0, t, 1);
    lp.sync(0, 2).unwrap();
    let forged = forge_addendum(&mut lp, 2, t, r, &[e]);
    lp.sync_all().unwrap();
    let eng = &mut lp.peers[0].engine;
    assert!(eng.kept_invalid(&forged) && eng.forgettable(&forged), "dropped while invalid");
    eng.forget_commits(&[forged]).unwrap();
    assert!(!eng.core.ix.commits.contains_key(&forged));
    assert!(!eng.core.stale());
    assert!(addenda(&lp, 0, t).is_empty());
    assert!(!valid(&lp, 0, &e, t, "x:e.0"));
    assert_eq!(reads(&mut lp, 0, t, "x:e.0"), None);
}

/// One of the removed writer's writes in
/// `a_removed_writers_writes_read_alike_in_any_arrival_order_and_tie_spec_perm_5_2`: its `ts`,
/// whether the remover and the witness had it before the removal.
struct BobWrite {
    ts: osis_base::Ts,
    to_alice: bool,
    to_carol: bool,
}

// spec/requirements.md Convergence, spec/permissions.md §5.2 (Position, Addenda, re-grant): Alice
// removes Bob while his writes reach her, Carol (a writer) or neither, his last one stamped before
// the removal, in its very `ts` (the HLC tie) or after it, the three roles on random peers so
// either tid order; maybe a re-grant after. Every peer, a restarted remover, and fresh nodes handed
// every commit in random orders (twice, so a body dropped while invalid comes back) read what the
// history gives: Bob's write counts iff re-granted, or stamped no later than the removal and
// received before it by Alice (her frontier) or Carol (her addendum), whatever the tids.
#[test]
fn a_removed_writers_writes_read_alike_in_any_arrival_order_and_tie_spec_perm_5_2() {
    let ties = osis_base::testenv::run_seeds("apply::tests_addenda::a_removed_writers_writes_read_alike_in_any_arrival_order_and_tie_spec_perm_5_2", &REMOVED_WRITER_SEEDS, false, removed_writer_replay, removed_writers_writes);
    assert!((0..3).all(|t| ties.contains(&t)), "every tie case ran: {ties:?}");
}

/// The default test's seeds, a covering set: every tie case; with a witness's addendum leaving
/// out a write at the removal's `ts`, 11 of seeds 0-47 fail (the last four of these among them),
/// with addenda ignored 18.
const REMOVED_WRITER_SEEDS: [u64; 6] = [0, 3, 9, 13, 16, 21];

/// Small size (a tenth of large) or large under `OSIS_FULL=1`; seeds: OSIS_ADDENDA_START,
/// OSIS_ADDENDA_SEEDS.
#[test]
#[ignore = "property"]
fn a_removed_writers_writes_read_alike_large_spec_perm_5_2() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_ADDENDA_START", "OSIS_ADDENDA_SEEDS", osis_base::testenv::large(0..400));
    s.run("apply::tests_addenda::a_removed_writers_writes_read_alike_large_spec_perm_5_2", removed_writer_replay, removed_writers_writes);
}

fn removed_writer_replay(s: u64) -> String {
    format!("OSIS_ADDENDA_START={s} OSIS_ADDENDA_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact apply::tests_addenda::a_removed_writers_writes_read_alike_large_spec_perm_5_2")
}

/// One seed of `a_removed_writers_writes_read_alike_in_any_arrival_order_and_tie_spec_perm_5_2`:
/// its tie case.
fn removed_writers_writes(seed: u64) -> usize {
    let mut rng = (seed + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut below = |n: u64| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng % n
    };
    let p: [usize; 3] = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]][below(6) as usize];
    let [a, b, c] = p;
    let mut lp = LocalPeer::fresh(3, T0);
    lp.sync_all().unwrap();
    let alice = lp.peers[a].engine.me();
    let mut m = Mutation::new();
    let t = lp.peers[a].engine.new_thing(&mut m, alice);
    m.set(t, &ak("x:v.0"), &Value::Int(0)).unwrap();
    lp.peers[a].commit(m).unwrap();
    for i in [b, c] {
        let who = lp.peers[i].engine.me();
        lp.peers[a].engine.grant(&t, &who, &edge(Role::Write)).unwrap();
    }
    lp.sync_all().unwrap();
    // 0: Bob's last write a millisecond before the removal; 1: at its `ts`; 2: after it
    let tie = below(3) as usize;
    let n = 1 + below(2);
    let mut bobs: Vec<BobWrite> = Vec::new();
    let bob_writes = |lp: &mut LocalPeer, k: u64, before: bool, below: &mut dyn FnMut(u64) -> u64| {
        let mut m = Mutation::new();
        m.set(t, &ak("x:v.0"), &Value::Int(k as i64 + 1)).unwrap();
        let id = lp.peers[b].commit(m).unwrap().unwrap();
        let ts = lp.peers[b].engine.header(&id).unwrap().ts;
        let (mut to_alice, mut to_carol) = (false, false);
        if before {
            let pk = lp.peers[b].engine.package(&id).unwrap().unwrap();
            // to Alice only if no tie is wanted: her clock passes the write's `ts`
            if below(3) == 0 && tie != 1 {
                lp.deliver(a, &pk).unwrap();
                to_alice = true;
            }
            if below(2) == 0 {
                lp.deliver(c, &pk).unwrap();
                to_carol = true;
            }
        }
        BobWrite { ts, to_alice, to_carol }
    };
    for k in 0..n {
        lp.advance(1000);
        if k + 1 < n || tie != 2 {
            let w = bob_writes(&mut lp, k, true, &mut below);
            bobs.push(w);
        }
    }
    if tie == 0 {
        lp.advance(1);
    }
    let bob = lp.peers[b].engine.me();
    let r = *lp.peers[a].engine.demote(&t, &Demotion { holder: bob, new: None, retain: None }).unwrap().commits.last().unwrap();
    let r_ts = lp.peers[a].engine.header(&r).unwrap().ts;
    if tie == 2 {
        lp.advance(1);
        let w = bob_writes(&mut lp, n - 1, false, &mut below);
        bobs.push(w);
    }
    if tie == 1 {
        assert_eq!(bobs.last().unwrap().ts, r_ts, "seed {seed}: the tie");
    }
    // what arrives from here on arrives after the removal's `ts`
    lp.advance(1);
    let regrant = below(4) == 0;
    if regrant {
        lp.advance(1000);
        lp.peers[a].engine.grant(&t, &bob, &edge(Role::Write)).unwrap();
    }
    for _ in 0..3 {
        lp.sync_all().unwrap();
    }
    // the history's word: the newest counting write of Bob's, else Alice's
    let counts = |w: &BobWrite| regrant || w.ts <= r_ts && (w.to_alice || w.to_carol);
    let want = Some(Value::Int(bobs.iter().filter(|w| counts(w)).map(|w| w.ts).max().and_then(|ts| bobs.iter().position(|w| w.ts == ts)).map_or(0, |i| i as i64 + 1)));
    let at = format!("seed {seed}: Alice {a}, Bob {b}, Carol {c}, tie {tie}, regrant {regrant}, writes {:?}", bobs.iter().map(|w| (w.to_alice, w.to_carol)).collect::<Vec<_>>());
    let held: Vec<Vec<CommitId>> = (0..3).map(|i| lp.peers[i].engine.commit_ids()).collect();
    assert!(held.iter().all(|h| *h == held[0]), "{at}: every peer holds the same commits");
    for i in 0..3 {
        assert_eq!(reads(&mut lp, i, t, "x:v.0"), want, "{at}: peer {i}");
    }
    lp.peers[a].restart(seed).unwrap();
    assert_eq!(reads(&mut lp, a, t, "x:v.0"), want, "{at}: the remover restarted");
    let mut pks = lp.packages(a).unwrap();
    let mut fresh = crate::local_peer::Peer::new(3 + seed, lp.peers[a].clock.now_wall_ms()).unwrap();
    for _ in 0..3 {
        for i in (1..pks.len()).rev() {
            pks.swap(i, below(i as u64 + 1) as usize);
        }
        let mut f = fresh.copy().unwrap();
        for _ in 0..2 {
            for pk in &pks {
                f.receive_with(&pk.bytes, pk.blobs.clone(), &pk.lists).unwrap();
            }
        }
        assert_eq!(f.engine.get(&t, &ak("x:v.0")).unwrap(), want, "{at}: a fresh node, order {:?}", pks.iter().map(|p| p.id).collect::<Vec<_>>());
    }
    tie
}

// spec/requirements.md Convergence, spec/permissions.md §5.2 (Position, Addenda, Compaction
// snapshot): Bob writes in the very `ts` of his removal, Alice not having it. Carol received it
// first and compacts the register over it, or Bob compacts in that `ts` himself (a snapshot, no
// plain content: no addendum lists it). Every peer, a restarted one and fresh nodes handed every
// commit in either order read alike: Bob's write stands by Carol's addendum when she had it, and
// Bob's own snapshot never stands, whatever the tids.
#[test]
fn a_compaction_around_a_write_at_its_removals_ts_reads_alike_spec_perm_5_2() {
    for [a, b, c] in [[0, 1, 2], [1, 0, 2], [2, 1, 0]] {
        for bob_compacts in [false, true] {
            let mut lp = LocalPeer::fresh(3, T0);
            lp.sync_all().unwrap();
            let alice = lp.peers[a].engine.me();
            let mut m = Mutation::new();
            let t = lp.peers[a].engine.new_thing(&mut m, alice);
            m.set(t, &ak("x:v.0"), &Value::Int(0)).unwrap();
            lp.peers[a].commit(m).unwrap();
            let (bob, carol) = (lp.peers[b].engine.me(), lp.peers[c].engine.me());
            for who in [bob, carol] {
                lp.peers[a].engine.grant(&t, &who, &edge(Role::Write)).unwrap();
            }
            lp.sync_all().unwrap();
            lp.advance(1000);
            let mut m = Mutation::new();
            m.set(t, &ak("x:v.0"), &Value::Int(5)).unwrap();
            let w = lp.peers[b].commit(m).unwrap().unwrap();
            let snap = bob_compacts.then(|| lp.peers[b].engine.snapshot(&t, &ak("x:v.0")).unwrap().unwrap());
            let pk = lp.peers[b].engine.package(&w).unwrap().unwrap();
            lp.deliver(c, &pk).unwrap();
            if let Some(s) = snap {
                let pk = lp.peers[b].engine.package(&s).unwrap().unwrap();
                lp.deliver(c, &pk).unwrap();
            }
            let r = *lp.peers[a].engine.demote(&t, &Demotion { holder: bob, new: None, retain: None }).unwrap().commits.last().unwrap();
            let r_ts = lp.peers[a].engine.header(&r).unwrap().ts;
            let at = format!("Alice {a}, Bob {b}, Carol {c}, Bob compacts {bob_compacts}");
            assert_eq!(lp.peers[b].engine.header(&w).unwrap().ts, r_ts, "{at}: the tie");
            if !bob_compacts {
                lp.advance(1);
                lp.peers[c].engine.snapshot(&t, &ak("x:v.0")).unwrap().unwrap();
            }
            lp.advance(1);
            for _ in 0..3 {
                lp.sync_all().unwrap();
            }
            let want = Some(Value::Int(5));
            for i in 0..3 {
                assert_eq!(reads(&mut lp, i, t, "x:v.0"), want, "{at}: peer {i}");
                if let Some(s) = snap {
                    assert!(!valid(&lp, i, &s, t, "x:v.0"), "{at}: peer {i}: Bob's snapshot");
                }
            }
            lp.peers[c].restart(1).unwrap();
            assert_eq!(reads(&mut lp, c, t, "x:v.0"), want, "{at}: Carol restarted");
            let mut fresh = crate::local_peer::Peer::new(3, lp.peers[a].clock.now_wall_ms()).unwrap();
            for from in [a, c] {
                let mut pks = lp.packages(from).unwrap();
                for rev in [false, true] {
                    if rev {
                        pks.reverse();
                    }
                    let mut f = fresh.copy().unwrap();
                    for _ in 0..2 {
                        for pk in &pks {
                            f.receive_with(&pk.bytes, pk.blobs.clone(), &pk.lists).unwrap();
                        }
                    }
                    assert_eq!(f.engine.get(&t, &ak("x:v.0")).unwrap(), want, "{at}: a fresh node from {from}, reversed {rev}");
                }
            }
        }
    }
}

// spec/permissions.md §5.2 (Position, re-grant; security): Alice grants Bob write, and a write of
// Bob's (forged: he did not hold write yet) carries the grant's very `ts`. Ordered before the
// grant whatever the tids, it is invalid at every peer though Bob holds write for good; his next
// write, after the grant, stands.
#[test]
fn a_write_at_its_authors_grants_ts_is_before_the_grant_spec_perm_5_2() {
    for [a, b] in [[0, 1], [1, 0]] {
        let mut lp = LocalPeer::fresh(3, T0);
        lp.sync_all().unwrap();
        let alice = lp.peers[a].engine.me();
        let mut m = Mutation::new();
        let t = lp.peers[a].engine.new_thing(&mut m, alice);
        m.set(t, &ak("x:v.0"), &Value::Int(0)).unwrap();
        lp.peers[a].commit(m).unwrap();
        let bob = lp.peers[b].engine.me();
        lp.peers[a].engine.grant(&t, &bob, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        lp.advance(1000);
        let mut m = Mutation::new();
        m.set(t, &ak("x:v.0"), &Value::Int(5)).unwrap();
        m.unchecked = true;
        lp.peers[b].engine.core.skip_writer_rules = true;
        let w = lp.peers[b].commit(m).unwrap().unwrap();
        lp.peers[b].engine.core.skip_writer_rules = false;
        let g = *lp.peers[a].engine.grant(&t, &bob, &edge(Role::Write)).unwrap().commits.last().unwrap();
        let at = format!("Alice {a}, Bob {b}");
        assert_eq!(lp.peers[b].engine.header(&w).unwrap().ts, lp.peers[a].engine.header(&g).unwrap().ts, "{at}: the tie");
        lp.advance(1);
        lp.sync_all().unwrap();
        for p in 0..3 {
            assert!(!valid(&lp, p, &w, t, "x:v.0"), "{at}: peer {p}: the write at the grant's ts");
            assert_eq!(reads(&mut lp, p, t, "x:v.0"), Some(Value::Int(0)), "{at}: peer {p}");
        }
        let later = write(&mut lp, b, t, "x:v.0", 6);
        lp.sync_all().unwrap();
        for p in 0..3 {
            assert!(valid(&lp, p, &later, t, "x:v.0"), "{at}: peer {p}: the write after the grant");
        }
    }
}

// spec/permissions.md §5.2 (Position, Addenda rules 1 and 5): Carol answers Bob's removal, and in
// that very `ts` Alice, not having her addendum, removes Carol too. Carol held write at the start
// of her addendum's `ts`, and Dave, who received it in time, vouches for it: it counts, and Bob's
// edit with it, at every peer whatever the tids.
#[test]
fn an_addendum_at_its_authors_removals_ts_counts_when_vouched_for_spec_perm_5_2() {
    for [a, b, c, d] in [[0, 1, 2, 3], [2, 1, 0, 3]] {
        let mut lp = LocalPeer::fresh(4, T0);
        lp.sync_all().unwrap();
        let alice = lp.peers[a].engine.me();
        let mut m = Mutation::new();
        let t = lp.peers[a].engine.new_thing(&mut m, alice);
        m.set(t, &ak("x:a.0"), &Value::Int(0)).unwrap();
        lp.peers[a].commit(m).unwrap();
        let (bob, carol) = (lp.peers[b].engine.me(), lp.peers[c].engine.me());
        for i in [b, c, d] {
            let who = lp.peers[i].engine.me();
            lp.peers[a].engine.grant(&t, &who, &edge(Role::Write)).unwrap();
        }
        lp.sync_all().unwrap();
        lp.advance(1000);
        let e = write(&mut lp, b, t, "x:e.0", 7);
        lp.sync(b, c).unwrap();
        lp.advance(1000);
        lp.peers[a].engine.demote(&t, &Demotion { holder: bob, new: None, retain: None }).unwrap();
        lp.advance(1000);
        lp.sync(a, c).unwrap();
        let (_, ad) = addenda(&lp, c, t).into_iter().find(|(x, _)| *x == carol).unwrap();
        lp.sync(c, d).unwrap();
        let rc = *lp.peers[a].engine.demote(&t, &Demotion { holder: carol, new: None, retain: None }).unwrap().commits.last().unwrap();
        let at = format!("Alice {a}, Carol {c}");
        assert_eq!(lp.peers[c].engine.header(&ad).unwrap().ts, lp.peers[a].engine.header(&rc).unwrap().ts, "{at}: the tie");
        lp.advance(1000);
        for _ in 0..3 {
            lp.sync_all().unwrap();
        }
        for p in 0..4 {
            assert!(valid(&lp, p, &ad, t, ct::ADDENDA_AK), "{at}: peer {p}: Carol's addendum");
            assert!(valid(&lp, p, &e, t, "x:e.0"), "{at}: peer {p}: Bob's edit");
            assert_eq!(reads(&mut lp, p, t, "x:e.0"), Some(Value::Int(7)), "{at}: peer {p}");
        }
    }
}
