//! Addenda (spec/permissions.md §5.2, Addenda): writers vouch for a removed holder's edits the remover never received.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::flows::Demotion;
use crate::local_peer::LocalPeer;
use crate::Mutation;
use osis_base::{Ak, CommitId, Role, Tid, Value};
use osis_schema::core_types as ct;
use crate::rotation::tests::edge;

const T0: osis_base::WallMs = osis_base::WallMs(1_700_000_000_000);

fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
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
    lp.hold(t);
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

/// Peer 0 keeps a day of history on every aspect of `t` (spec/commits.md §5 The setting): its
/// writes stay inside the kept window while live and a day after replaced.
fn keep_history(lp: &mut LocalPeer, t: Tid) {
    keep_history_from(lp, 0, t);
    lp.sync_all().unwrap();
}

/// `keep_history` written by peer `from`, sent from it to the others only.
fn keep_history_from(lp: &mut LocalPeer, from: usize, t: Tid) {
    let day = osis_schema::History::Keep { until: None, after: Some(86_400_000) };
    let setting = ct::RetentionSetting { default: Some(ct::RetentionEntry { history: Some(day), ..Default::default() }), ..Default::default() };
    let mut m = Mutation::new();
    m.set(t, &ct::RETENTION, &setting).unwrap();
    lp.peers[from].commit(m).unwrap();
    for p in 0..lp.peers.len() {
        if p != from {
            lp.sync(from, p).unwrap();
        }
    }
    lp.advance(1000);
}

/// The frontier of removal `r` at `peer`: the commits it lists and those of them that are
/// compaction snapshots by the remover (its own cover).
fn frontier_of(lp: &LocalPeer, peer: usize, r: &CommitId) -> (std::collections::BTreeSet<CommitId>, Vec<CommitId>) {
    let core = &lp.peers[peer].engine.core;
    let rm = core.ix.commits.get(r).unwrap();
    let f = rm.view.frontier.as_ref().unwrap();
    let own = f.commits().iter().filter(|c| core.ix.commits.get(*c).is_some_and(|m| m.view.kind.is_compaction() && m.view.signer == rm.view.signer)).copied().collect();
    (f.commits().iter().copied().collect(), own)
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
    core.ix.addenda.keys().filter(|(th, _)| *th == t).map(|(_, c)| (core.ix.commits.get(c).unwrap().view.signer, *c)).collect()
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

// spec/permissions.md §5.2 (addenda; writing; that it received in r's window): an edit a writer
// received only after the removal's `ts` is not vouched for; nor one received after the removal
// itself, though before its `ts` (Alice's clock runs ahead, so the removal reaches Carol early).
#[test]
fn received_after_the_removal_is_not_vouched_for_spec_perm_5_2() {
    for early in [false, true] {
        let (mut lp, t) = world(3, &[Role::Write, Role::Write]);
        let e = write(&mut lp, 1, t, "x:e.0", 7);
        if early {
            lp.peers[0].clock.advance(10_000);
        }
        let r = remove(&mut lp, 0, t, 1);
        // Carol gets the removal first when it is early, else the edit after the removal's stamp
        let order = if early { [(0, 2), (1, 2)] } else { [(1, 2), (0, 2)] };
        for (a, b) in order {
            lp.sync(a, b).unwrap();
        }
        if early {
            let got = lp.peers[2].engine.core.ix.commits.get(&e).unwrap().received;
            assert!(got.0 <= lp.peers[0].engine.header(&r).unwrap().ts.wall_ms().0, "the edit reached Carol by the removal's ts");
        }
        lp.advance(20_000);
        lp.sync_all().unwrap();
        // an open judges every removal again
        lp.peers[2].restart(7).unwrap();
        lp.sync_all().unwrap();
        assert!(lp.peers[2].engine.core.ix.commits.contains_key(&r));
        assert!(addenda(&lp, 2, t).is_empty(), "nothing to vouch for, early {early}");
        assert!(!valid(&lp, 2, &e, t, "x:e.0"));
        assert!(!valid(&lp, 0, &e, t, "x:e.0"));
    }
}

// spec/permissions.md §5.2 (addenda; itself vouched for by other addenda or not): Carol vouched for Bob's edit; Alice then removes Carol without having received
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

// spec/permissions.md §5.2 (addenda; gives write just before a's key): a reader's addendum vouches for nothing, however it
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

// spec/permissions.md §5.1 (frontier; which its own addenda list instead), §5.2 (Addenda): the remover's frontier
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
    // the purge author's level-2 key is not this node's: purgeable by admins
    m.purge_by(t, &ak(a), osis_schema::PurgeBy::Admin).unwrap();
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

/// A team T (a thing peer 3 makes and administers) holds write on N; Bob (1) is a member of T;
/// Mallory (2) writes N and only reads T, as Alice (0) does. Alice (0) removes T from N; Bob's write on N acting for T
/// reached nobody before the removal. Returns (lp, N, T, removal, Bob's write).
fn team_world() -> (LocalPeer, Tid, Tid, CommitId, CommitId) {
    let (lp, (n, team, r, e)) = LocalPeer::cached("apply::tests_addenda::team_world", || {
        let (lp, n, team, r, e) = build_team();
        (lp, (n, team, r, e))
    });
    (lp, n, team, r, e)
}

fn build_team() -> (LocalPeer, Tid, Tid, CommitId, CommitId) {
    let (mut lp, n) = build(4, &[Role::Read, Role::Write]);
    let (bob, me3) = (lp.peers[1].engine.me(), lp.peers[3].engine.me());
    let mut m = Mutation::new();
    let team = lp.peers[3].engine.new_thing(&mut m, me3);
    lp.peers[3].commit(m).unwrap();
    lp.hold(team);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&n, &team, &edge(Role::Write)).unwrap();
    let mut m = Mutation::new();
    m.op(team, &ct::ROLES, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Weak(bob))], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&edge(Role::Write))) }).unwrap();
    lp.peers[3].commit(m).unwrap().unwrap();
    // Alice and Mallory read T: they hold what is written on it
    lp.share(3, team);
    lp.sync_all().unwrap();
    lp.advance(1000);
    let e = write_as(&mut lp, 1, team, n, "x:e.0", 7);
    lp.advance(1000);
    let r = *lp.peers[0].engine.demote(&n, &Demotion { holder: team, new: None, retain: None }).unwrap().commits.last().unwrap();
    lp.advance(1000);
    (lp, n, team, r, e)
}

// spec/permissions.md §5.2 (addenda: with the old walk's Acting check, notes/redesign-plan.md, Interim in code): a lying writer of N (Mallory, received
// Bob's write after the removal) vouches for the part on N; Bob still writes T, so the Acting
// part needs no vouching and the write counts. The same as a lying witness for a removed
// holder acting for itself: a writer can always vouch for the removed side's earlier writes on
// a thing it writes (stated limit, notes/revocation.md).
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

// spec/permissions.md §5.2 (content: the old walk's Acting check, notes/redesign-plan.md, Interim in code): with Bob also removed from T, a writer of N vouching for
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

// spec/commits.md §5 (Forgetting: every part covered or dropped as invalid),
// spec/permissions.md §5.2 (Addenda): an addendum dropped while invalid lists nothing and judges
// nothing, kept or forgotten.
#[test]
fn an_invalid_addendum_is_forgettable_spec_commits_5() {
    let (mut lp, t) = world(3, &[Role::Write, Role::Read]);
    let e = write(&mut lp, 1, t, "x:e.0", 7);
    lp.sync(1, 2).unwrap();
    let r = remove(&mut lp, 0, t, 1);
    lp.sync(0, 2).unwrap();
    let forged = forge_addendum(&mut lp, 2, t, r, &[e]);
    lp.sync_all().unwrap();
    let eng = &mut lp.peers[0].engine;
    assert!(eng.kept_invalid(&forged) && eng.forgettable(&forged).unwrap(), "dropped while invalid, forgettable");
    assert!(!valid(&lp, 0, &e, t, "x:e.0"));
    assert_eq!(reads(&mut lp, 0, t, "x:e.0"), None);
    lp.peers[0].engine.forget_commits(&[forged]).unwrap();
    assert!(!lp.peers[0].engine.core.ix.commits.contains_key(&forged));
    assert!(!valid(&lp, 0, &e, t, "x:e.0"));
    assert_eq!(reads(&mut lp, 0, t, "x:e.0"), None);
}

/// Rows by kind: count and bytes (`Engine::local_census`).
type Census = std::collections::BTreeMap<String, (usize, usize)>;

/// Bob, removed by Alice without knowing it, writes `n` edits; Alice receives them, judges them
/// invalid and forgets every commit she may: Alice's rows by kind and the edits.
fn removed_writer_writes(n: usize) -> (LocalPeer, Tid, Vec<CommitId>, Census) {
    let (mut lp, t) = world(2, &[Role::Write]);
    remove(&mut lp, 0, t, 1);
    let edits: Vec<CommitId> = (0..n).map(|i| write(&mut lp, 1, t, "x:e.0", i64::try_from(i).unwrap())).collect();
    lp.sync(1, 0).unwrap();
    let e = &mut lp.peers[0].engine;
    assert!(edits.iter().all(|c| e.kept_invalid(c)), "every edit dropped as invalid");
    let due: Vec<CommitId> = e.commit_ids().into_iter().filter(|c| e.forgettable(c).unwrap()).collect();
    e.forget_commits(&due).unwrap();
    assert!(edits.iter().all(|c| !e.core.ix.commits.contains_key(c)), "every edit forgotten");
    let census = e.local_census().unwrap();
    (lp, t, edits, census)
}

// spec/commits.md §5 (Forgetting: every part covered or dropped as invalid), spec/permissions.md
// §6 (Invalid deltas: a delta dropped so that turns valid again is fetched from any holder),
// spec/requirements.md Scale: a removed writer's invalid commits leave Alice nothing, the same
// rows at 3 and 30 of them; a re-grant brings them back from Bob, judged valid.
#[test]
fn a_removed_writers_invalid_commits_are_forgotten_spec_commits_5() {
    let (_, _, _, a) = removed_writer_writes(3);
    let (mut lp, t, edits, b) = removed_writer_writes(30);
    let bytes = |c: &Census| c.values().map(|v| v.1).sum::<usize>();
    assert!(b.iter().all(|(k, v)| v.0 <= a.get(k).map_or(0, |x| x.0)) && bytes(&b) <= bytes(&a) + 64, "rows by kind {a:?} at n, {b:?} at 10n");
    let bob = lp.peers[1].engine.me();
    lp.peers[0].engine.grant(&t, &bob, &edge(Role::Write)).unwrap();
    lp.advance(1000);
    lp.sync_all().unwrap();
    let last = *edits.last().unwrap();
    assert!(valid(&lp, 0, &last, t, "x:e.0"), "received again and judged valid");
    assert_eq!(reads(&mut lp, 0, t, "x:e.0"), Some(Value::Int(29)));
}

// spec/permissions.md §6 (Invalid deltas: fetched again from any holder), spec/commits.md §5
// (Forgetting): hostile order. Bob learns his removal, so every node judges his edits invalid;
// Alice forgets them; a re-grant still brings them back from Bob, who keeps his own invalid
// commits (his user is told the write was refused), judged valid at Alice.
#[test]
fn a_regrant_after_everyone_judged_them_invalid_brings_them_back_spec_perm_6() {
    let (mut lp, t, edits, _) = removed_writer_writes(3);
    lp.sync(0, 1).unwrap();
    let last = *edits.last().unwrap();
    assert!(!valid(&lp, 1, &last, t, "x:e.0"), "Bob judges his edit invalid too");
    assert!(lp.peers[1].engine.commit_bytes(&last).unwrap().is_some(), "Bob keeps his own body");
    let bob = lp.peers[1].engine.me();
    lp.peers[0].engine.grant(&t, &bob, &edge(Role::Write)).unwrap();
    lp.advance(1000);
    lp.sync_all().unwrap();
    assert!(valid(&lp, 0, &last, t, "x:e.0"), "received again and judged valid");
    assert_eq!(reads(&mut lp, 0, t, "x:e.0"), Some(Value::Int(2)));
}

/// One of the removed writer's writes in
/// `a_removed_writers_writes_read_alike_plain_spec_perm_5_2`: its `ts`,
/// whether the remover and the witness had it before the removal.
struct BobWrite {
    ts: osis_base::Ts,
    to_alice: bool,
    to_carol: bool,
}

// spec/requirements.md Convergence, spec/permissions.md §5.2 (Position; Addenda; re-grant): Alice
// removes Bob while his writes reach her, Carol (a writer) or neither, his last one stamped before
// the removal, in its very `ts` (the HLC tie) or after it, the three roles on random peers so
// either tid order; maybe a re-grant after. Every peer, a restarted remover, and fresh nodes handed
// every commit in random orders (twice, so a body dropped while invalid comes back) read what the
// history gives: Bob's write counts iff re-granted, or stamped no later than the removal and
// received before it by Alice (her frontier) or Carol (her addendum), whatever the tids.
#[test]
#[ignore = "property"]
fn a_removed_writers_writes_read_alike_plain_spec_perm_5_2() {
    let cases = osis_base::testenv::run_seeds("apply::tests_addenda::a_removed_writers_writes_read_alike_plain_spec_perm_5_2", &REMOVED_WRITER_SEEDS, false, removed_writer_replay, removed_writers_writes);
    assert!((0..3).all(|t| cases.iter().any(|c| c.0 == t)), "every tie case ran: {cases:?}");
    assert!([false, true].iter().all(|r| cases.iter().any(|c| c.1 == *r)), "with and without a re-grant: {cases:?}");
}

/// The `_plain` property's seeds, a covering set: every tie case, with and without a re-grant; with a
/// witness's addendum leaving out a write at the removal's `ts`, 11 of seeds 0-47 fail (9, 13, 16
/// and 21 among them), with addenda ignored 18, with frontiers ignored 7 (0), with re-grants
/// ignored 8 (4).
const REMOVED_WRITER_SEEDS: [u64; 7] = [0, 3, 4, 9, 13, 16, 21];

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

/// One seed of `a_removed_writers_writes_read_alike_plain_spec_perm_5_2`:
/// its tie case, and whether Bob was granted again.
fn removed_writers_writes(seed: u64) -> (usize, bool) {
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
    lp.hold(t);
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
    // on t (each keeps its own roots' and the chains it needs)
    let held: Vec<Vec<CommitId>> = (0..3).map(|i| lp.peers[i].engine.commit_ids().into_iter().filter(|c| lp.peers[i].engine.header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == t))).collect()).collect();
    assert!(held.iter().all(|h| *h == held[0]), "{at}: every peer holds the same commits on t");
    for i in 0..3 {
        assert_eq!(reads(&mut lp, i, t, "x:v.0"), want, "{at}: peer {i}");
    }
    lp.peers[a].restart(seed).unwrap();
    assert_eq!(reads(&mut lp, a, t, "x:v.0"), want, "{at}: the remover restarted");
    // a fresh node holding t, granted read by Alice, handed everything Alice holds
    let mut fresh = lp.fresh_reader(a, t, 3 + seed);
    let mut pks = lp.packages_to_peer(a, &mut fresh).unwrap();
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
    (tie, regrant)
}

// spec/requirements.md Convergence, spec/permissions.md §5.2 (Position; Addenda: compaction
// snapshot): Bob writes in the very `ts` of his removal, Alice not having it. Carol received it
// first and compacts the register over it, or Bob compacts in that `ts` himself (a snapshot, no
// plain content: no addendum lists it). Every peer, a restarted one and fresh nodes handed every
// commit in either order read alike: Bob's write stands by Carol's addendum when she had it, and
// Bob's own snapshot never stands, whatever the tids (both orders of the tied pair's).
#[test]
fn a_compaction_around_a_write_at_its_removals_ts_reads_alike_spec_perm_5_2() {
    for [a, b, c] in [[0, 1, 2], [1, 0, 2]] {
        for bob_compacts in [false, true] {
            let mut lp = LocalPeer::fresh(3, T0);
            lp.sync_all().unwrap();
            let alice = lp.peers[a].engine.me();
            let mut m = Mutation::new();
            let t = lp.peers[a].engine.new_thing(&mut m, alice);
            m.set(t, &ak("x:v.0"), &Value::Int(0)).unwrap();
            lp.peers[a].commit(m).unwrap();
            lp.hold(t);
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
            // a fresh node holding t, granted read by Alice (Carol has the grant), handed
            // everything Alice or Carol holds
            let mut fresh = lp.fresh_reader(a, t, 3);
            lp.sync(a, c).unwrap();
            for from in [a, c] {
                let mut pks = lp.packages_to_peer(from, &mut fresh).unwrap();
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

// spec/permissions.md §5.2 (Position; re-grant: security): Alice grants Bob write, and a write of
// Bob's (forged: he did not hold write yet) carries the grant's very `ts`. Ordered before the
// grant whatever the tids, it is invalid at both though Bob holds write for good; his next
// write, after the grant, stands.
#[test]
fn a_write_at_its_authors_grants_ts_is_before_the_grant_spec_perm_5_2() {
    for [a, b] in [[0, 1], [1, 0]] {
        let mut lp = LocalPeer::fresh(2, T0);
        lp.sync_all().unwrap();
        let alice = lp.peers[a].engine.me();
        let mut m = Mutation::new();
        let t = lp.peers[a].engine.new_thing(&mut m, alice);
        m.set(t, &ak("x:v.0"), &Value::Int(0)).unwrap();
        lp.peers[a].commit(m).unwrap();
        lp.hold(t);
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
        for p in 0..2 {
            assert!(!valid(&lp, p, &w, t, "x:v.0"), "{at}: peer {p}: the write at the grant's ts");
            assert_eq!(reads(&mut lp, p, t, "x:v.0"), Some(Value::Int(0)), "{at}: peer {p}");
        }
        let later = write(&mut lp, b, t, "x:v.0", 6);
        lp.sync_all().unwrap();
        for p in 0..2 {
            assert!(valid(&lp, p, &later, t, "x:v.0"), "{at}: peer {p}: the write after the grant");
        }
    }
}

// spec/permissions.md §5.2 (Position: addenda rules 1 and 5): Carol answers Bob's removal, and in
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
        lp.hold(t);
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

// spec/commits.md §5 (Covered: by a valid snapshot the node holds; Forgetting), spec/permissions.md
// §5.2: a snapshot its writer made after a removal it had not received is invalid where the
// removal is held, so it drops nothing there and nothing becomes forgettable; a remaining
// writer's snapshot of the same state does drop the body.
#[test]
fn a_removed_writers_later_snapshot_drops_nothing_spec_commits_5() {
    let (mut lp, t) = world(3, &[Role::Write, Role::Write]);
    let e = write(&mut lp, 1, t, "x:e.0", 7);
    lp.sync_all().unwrap();
    write(&mut lp, 1, t, "x:e.0", 8);
    remove(&mut lp, 0, t, 1);
    lp.sync(0, 2).unwrap();
    // peer 1, not holding its removal, compacts what it holds
    let snap = lp.peers[1].engine.snapshot(&t, &ak("x:e.0")).unwrap().unwrap();
    lp.advance(1000);
    let pk = lp.peers[1].engine.package(&snap).unwrap().unwrap();
    lp.deliver(2, &pk).unwrap();
    assert!(lp.peers[2].engine.core.ix.commits.get(&snap).is_some_and(|m| m.aspect(&t, &ak("x:e.0")).is_some_and(|ai| !m.valid_at(ai))), "the snapshot is invalid at peer 2");
    assert!(valid(&lp, 2, &e, t, "x:e.0"));
    assert!(lp.peers[2].engine.covered_drops(&e).unwrap().is_empty(), "an invalid snapshot drops nothing");
    assert!(!lp.peers[2].engine.forgettable(&e).unwrap());
    // control: peer 0's snapshot of the same state covers it
    let ours = lp.peers[0].engine.snapshot(&t, &ak("x:e.0")).unwrap().unwrap();
    lp.advance(1000);
    let pk = lp.peers[0].engine.package(&ours).unwrap().unwrap();
    lp.deliver(2, &pk).unwrap();
    assert_eq!(lp.peers[2].engine.covered_drops(&e).unwrap(), vec![(t, ak("x:e.0"))]);
}

/// Peer `p` covers `(t, a)` with a snapshot of its own and forgets every held commit of
/// `author` there that it covers (spec/commits.md §5 Forgetting): what a list can no longer name.
fn forget_under_own_snapshot(lp: &mut LocalPeer, p: usize, author: usize, t: Tid, a: &str) -> CommitId {
    let a = ak(a);
    let x = lp.peers[author].engine.me();
    let s = lp.peers[p].engine.snapshot(&t, &a).unwrap().unwrap();
    let e = &mut lp.peers[p].engine;
    let mine: Vec<CommitId> = e.core.held_on(&(t, a.clone())).filter(|c| e.core.ix.commits.get(c).is_some_and(|m| m.view.signer == x)).collect();
    for c in &mine {
        assert_eq!(e.covered(&s, c, &t, &a).unwrap(), Some(true));
        e.drop_body(c, &t, &a).unwrap();
    }
    assert!(mine.iter().all(|c| e.forgettable(c).unwrap()));
    e.forget_commits(&mine).unwrap();
    lp.advance(1000);
    s
}

// spec/permissions.md §5.1 (Own cover): a remover lists by ID every commit of the removed writer
// it still holds, kept history or not, and writes no own cover for them: the common case costs
// IDs only.
#[test]
fn removal_lists_what_it_holds_spec_perm_5_1() {
    for keep in [false, true] {
        let (mut lp, t) = world(3, &[Role::Write, Role::Write]);
        if keep {
            keep_history(&mut lp, t);
        }
        let es = [write(&mut lp, 1, t, "x:e.0", 7), write(&mut lp, 1, t, "x:e.0", 8), write(&mut lp, 1, t, "x:f.0", 9)];
        lp.sync_all().unwrap();
        let r = remove(&mut lp, 0, t, 1);
        let (f, own) = frontier_of(&lp, 0, &r);
        assert!(es.iter().all(|c| f.contains(c)), "keep {keep}: every held commit listed");
        assert!(own.is_empty(), "keep {keep}: nothing forgotten, no own cover");
        lp.sync_all().unwrap();
        for p in [0, 2] {
            assert_eq!(reads(&mut lp, p, t, "x:e.0"), Some(Value::Int(8)), "peer {p}");
            assert_eq!(reads(&mut lp, p, t, "x:f.0"), Some(Value::Int(9)), "peer {p}");
        }
    }
}

// spec/permissions.md §5.1 (Own cover), §5.2 (Copies): the issue's minimal case. Alice holds
// Bob's edit only under Dave's snapshot (every holder dropped its body as covered, Alice forgot
// it); Carol removed Dave earlier without that snapshot, so it falls once her removal arrives.
// Alice's removal of Bob cannot list the forgotten edit; it names her own fresh snapshot, which
// carries it from her state: it stays everywhere.
#[test]
fn own_cover_outlives_another_writers_falling_cover_spec_perm_5_1() {
    let (mut lp, t) = world(4, &[Role::Write, Role::Admin, Role::Write]);
    let e = write(&mut lp, 1, t, "x:e.0", 7);
    lp.sync(1, 3).unwrap();
    let a = ak("x:e.0");
    let s = lp.peers[3].engine.snapshot(&t, &a).unwrap().unwrap();
    lp.advance(1000);
    for p in [0, 1] {
        lp.sync(3, p).unwrap();
    }
    // every holder drops the edit's body under Dave's cover; Alice forgets it whole
    for p in [0, 1, 3] {
        let en = &mut lp.peers[p].engine;
        assert_eq!(en.covered(&s, &e, &t, &a).unwrap(), Some(true), "peer {p}");
        en.drop_body(&e, &t, &a).unwrap();
    }
    assert!(lp.peers[0].engine.forgettable(&e).unwrap());
    lp.peers[0].engine.forget_commits(&[e]).unwrap();
    // Carol removes Dave, never having received his snapshot
    remove(&mut lp, 2, t, 3);
    let r = remove(&mut lp, 0, t, 1);
    let (_, own) = frontier_of(&lp, 0, &r);
    assert_eq!(own.len(), 1, "Alice's own cover of the aspect");
    lp.sync_all().unwrap();
    lp.sync_all().unwrap();
    for p in [0, 2] {
        assert!(!lp.peers[p].engine.core.ix.commits.get(&s).is_some_and(|m| m.valid_at(0)), "peer {p}: Dave's cover fell");
        assert_eq!(reads(&mut lp, p, t, "x:e.0"), Some(Value::Int(7)), "peer {p}: Alice's own cover carries the edit");
    }
}

// spec/permissions.md §5.1 (Own cover): the remover's own cover stands while its removal applies.
// Alice forgot Bob's edit under her own earlier snapshot, which nobody else received. Carol
// receives Alice's removal of Bob but not the own cover it names, and removes Alice: her frontier
// lists the removal (it applies) and neither snapshot. The own cover counts all the same as the
// removal's word, so Bob's edit it alone carries stays; the earlier snapshot falls.
#[test]
fn own_cover_stands_with_its_removal_spec_perm_5_1() {
    let (mut lp, t) = world(3, &[Role::Write, Role::Admin]);
    let a = ak("x:e.0");
    write(&mut lp, 1, t, "x:e.0", 7);
    lp.sync(1, 0).unwrap();
    forget_under_own_snapshot(&mut lp, 0, 1, t, "x:e.0");
    let r = remove(&mut lp, 0, t, 1);
    let (_, own) = frontier_of(&lp, 0, &r);
    assert_eq!(own.len(), 1);
    let pk = lp.peers[0].engine.package(&r).unwrap().unwrap();
    lp.deliver(2, &pk).unwrap();
    assert!(lp.peers[2].engine.core.ix.commits.contains_key(&r) && !lp.peers[2].engine.core.ix.commits.contains_key(&own[0]), "the removal alone");
    remove(&mut lp, 2, t, 0);
    lp.sync_all().unwrap();
    lp.sync_all().unwrap();
    for p in [0, 2] {
        assert!(lp.peers[p].engine.core.ix.commits.get(&own[0]).is_some_and(|m| m.valid_at(0)), "peer {p}: the own cover stands with the removal");
        assert_eq!(lp.peers[p].engine.get(&t, &a).unwrap(), Some(Value::Int(7)), "peer {p}");
    }
}

// spec/permissions.md §5.1 (Own cover), spec/commits.md §5 (Covered): a removal voided later
// leaves every other holder as it was. Alice forgot Bob's edit under her own snapshot, so her
// removal of Bob names her own cover of it; Dave holds the edit and receives both. He keeps its
// body under that cover (only its writer drops under it) and his addendum lists it all the same.
// Carol, never holding the removal, removes Alice: the removal falls, its own cover with it, and
// Dave and Carol read the edit from Dave's copy, Bob gone.
#[test]
fn a_voided_removal_leaves_holders_as_they_were_spec_perm_5_1() {
    let (mut lp, t) = world(4, &[Role::Write, Role::Admin, Role::Write]);
    let a = ak("x:e.0");
    let e = write(&mut lp, 1, t, "x:e.0", 7);
    lp.sync(1, 0).unwrap();
    lp.sync(1, 3).unwrap();
    forget_under_own_snapshot(&mut lp, 0, 1, t, "x:e.0");
    let r = remove(&mut lp, 0, t, 1);
    let (_, own) = frontier_of(&lp, 0, &r);
    assert_eq!(own.len(), 1, "Alice's own cover");
    for c in [own[0], r] {
        let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
        lp.deliver(3, &pk).unwrap();
    }
    let d = &mut lp.peers[3].engine;
    assert_eq!(d.covered(&own[0], &e, &t, &a).unwrap(), Some(true), "the own cover covers Dave's copy");
    assert!(d.own_kept_under(&own[0], &e, &t, &a).unwrap(), "Dave keeps it: only Alice drops under her own cover");
    let dave = lp.peers[3].engine.me();
    let by_dave: Vec<CommitId> = addenda(&lp, 3, t).into_iter().filter(|(x, _)| *x == dave).map(|(_, c)| c).collect();
    assert_eq!(by_dave.len(), 1, "Dave answers the removal");
    let lists = lp.peers[3].engine.core.ix.addenda.get(&(t, by_dave[0])).unwrap().clone();
    assert!(lists.entries.iter().any(|(rm, l)| *rm == r && l.contains(&e)), "listed though the own cover carries it: {lists:?}");
    remove(&mut lp, 2, t, 0);
    for _ in 0..2 {
        for (x, y) in [(0, 2), (2, 3), (0, 3)] {
            lp.sync(x, y).unwrap();
            lp.sync(y, x).unwrap();
        }
    }
    for p in [2, 3] {
        assert!(!lp.peers[p].engine.core.ix.commits.get(&own[0]).is_some_and(|m| m.valid_at(0)), "peer {p}: the own cover fell with its removal");
        assert_eq!(reads(&mut lp, p, t, "x:e.0"), Some(Value::Int(7)), "peer {p}: Dave's copy");
    }
}

// spec/commits.md §5 (Keep bounds), §7, spec/permissions.md §5.1 (Own cover): undo across a
// removal on kept history. Held: Alice's removal of Bob lists his kept edit by ID and writes no own
// cover; her later undo of her own write over it brings it back everywhere. Forgotten before the
// thing kept history: her removal names her own cover of the aspect, which drops no kept body
// (their keep bound is still ahead), and Carol's undo of her write made after it brings Bob's edit
// back from that cover everywhere.
#[test]
fn undo_across_a_removal_on_kept_history_spec_commits_7() {
    for forgot in [false, true] {
        let (mut lp, t) = world(3, &[Role::Write, Role::Admin]);
        let a = ak("x:e.0");
        let b = write(&mut lp, 1, t, "x:e.0", 7);
        lp.sync_all().unwrap();
        if forgot {
            forget_under_own_snapshot(&mut lp, 0, 1, t, "x:e.0");
        }
        // the setting from Alice, nothing sent to her: what she forgot stays forgotten
        keep_history_from(&mut lp, 0, t);
        let (undoer, mine) = if forgot {
            let r = remove(&mut lp, 0, t, 1);
            let (f, own) = frontier_of(&lp, 0, &r);
            assert!(!f.contains(&b) && own.len() == 1, "forgotten: the own cover");
            lp.sync_all().unwrap();
            (2, write(&mut lp, 2, t, "x:e.0", 9))
        } else {
            let mine = write(&mut lp, 0, t, "x:e.0", 8);
            lp.sync_all().unwrap();
            let r = remove(&mut lp, 0, t, 1);
            let (f, own) = frontier_of(&lp, 0, &r);
            assert!(f.contains(&b) && own.is_empty(), "held: listed by ID, no own cover");
            (0, mine)
        };
        lp.sync_all().unwrap();
        for p in [0, 2] {
            assert!(lp.peers[p].engine.drop_from(&mine, &t, &a).unwrap() > lp.peers[p].engine.now().0, "forgot {forgot}: peer {p}: the kept write stays to its bound");
        }
        lp.peers[undoer].engine.revert(&mine).unwrap().unwrap();
        lp.sync_all().unwrap();
        for p in [0, 2] {
            assert_eq!(reads(&mut lp, p, t, "x:e.0"), Some(Value::Int(7)), "forgot {forgot}: peer {p}: Bob's edit back");
        }
    }
}

/// Bytes of commit `c` at `peer` and of the blobs it links that `known` lacks, and those blobs'
/// count.
fn new_bytes(lp: &mut LocalPeer, peer: usize, c: &CommitId, known: &std::collections::BTreeSet<osis_base::BlobId>) -> (usize, usize, usize) {
    let pk = lp.peers[peer].engine.package(c).unwrap().unwrap();
    let fresh: Vec<_> = pk.blobs.iter().filter(|(b, _)| !known.contains(b)).collect();
    (pk.bytes.len(), fresh.len(), fresh.iter().map(|(_, b)| b.len()).sum())
}

// spec/permissions.md §5.1 (Own cover): what a removal costs, counted. Bodies held: one 32 B ID per
// commit and no snapshot. Forgotten (the remover compacted and forgot them): one own cover per
// aspect. A chunked large value's own cover links the value's pieces, which every holder already
// has, so it adds its commit and no piece, however large the value.
#[test]
fn own_cover_cost_counts_spec_perm_5_1() {
    // a 1 MiB value, then a one-byte edit of it: the edit reuses all but the changed chunk
    for forget in [false, true] {
        let (mut lp, t) = world(2, &[Role::Write]);
        let big = |lp: &mut LocalPeer, k: u8| {
            let mut m = Mutation::new();
            let mut v: Vec<u8> = (0..16 * 65536).map(|i| (i * 7 % 251) as u8).collect();
            v[0] = k;
            m.set(t, &ak("x:big.0"), &Value::Bytes(v)).unwrap();
            let c = lp.peers[1].commit(m).unwrap().unwrap();
            lp.advance(1000);
            c
        };
        let b1 = big(&mut lp, 0);
        let b2 = big(&mut lp, 1);
        lp.sync_all().unwrap();
        let mut known = std::collections::BTreeSet::new();
        for c in [b1, b2] {
            known.extend(lp.peers[0].engine.package(&c).unwrap().unwrap().blobs.into_iter().map(|x| x.0));
        }
        if forget {
            let s = forget_under_own_snapshot(&mut lp, 0, 1, t, "x:big.0");
            known.extend(lp.peers[0].engine.package(&s).unwrap().unwrap().blobs.into_iter().map(|x| x.0));
        }
        let r = remove(&mut lp, 0, t, 1);
        let (f, own) = frontier_of(&lp, 0, &r);
        if !forget {
            assert!(f.contains(&b1) && f.contains(&b2) && own.is_empty(), "held: IDs only");
            eprintln!("1 MiB chunked value, bodies held: 2 IDs listed, no own cover");
            continue;
        }
        assert!(!f.contains(&b1) && !f.contains(&b2) && own.len() == 1);
        let (commit, blobs, bytes) = new_bytes(&mut lp, 0, &own[0], &known);
        eprintln!("1 MiB chunked value, forgotten: own cover commit {commit} B, {blobs} new blobs ({bytes} B)");
        assert_eq!(blobs, 0, "the snapshot reuses every piece");
        assert!(commit < 2048, "a commit linking the value: {commit} B");
    }

    // 40 aspects written once each
    for forget in [false, true] {
        let (mut lp, t) = world(2, &[Role::Write]);
        let n = 40;
        for i in 0..n {
            write(&mut lp, 1, t, &format!("x:a{i}.0"), i);
        }
        lp.sync_all().unwrap();
        if forget {
            for i in 0..n {
                forget_under_own_snapshot(&mut lp, 0, 1, t, &format!("x:a{i}.0"));
            }
        }
        let r = remove(&mut lp, 0, t, 1);
        let (f, own) = frontier_of(&lp, 0, &r);
        let total: usize = own.iter().map(|c| lp.peers[0].engine.package(c).unwrap().unwrap().bytes.len()).sum();
        eprintln!("{n} one-write aspects, forgotten {forget}: {} own covers ({total} B), frontier {} IDs", own.len(), f.len());
        assert_eq!(own.len(), if forget { n as usize } else { 0 });
    }
}

// spec/permissions.md §5.1 (Own cover), spec/commits.md §5 (Covered; Purge on replace): only its
// writer drops under an own cover, on a purge-on-replace aspect too. Dave covers Bob's edit with
// his own snapshot and drops its body; Alice forgets the edit under Dave's snapshot, so her
// removal of Bob names her own cover. Dave keeps his snapshot under it, whether it arrives before
// the removal or with it (`ahead`); Carol, never
// holding the removal, removes Alice: the own cover falls, and Dave's snapshot still carries the
// edit at Dave and Carol.
#[test]
fn purge_on_replace_keeps_what_an_own_cover_covers_spec_perm_5_1() {
    for ahead in [true, false] {
        let (mut lp, t) = world(4, &[Role::Write, Role::Admin, Role::Write]);
        let a = ak("x:e.0");
        let mut m = Mutation::new();
        m.set(t, &ct::RETENTION, &ct::RetentionSetting::of(a.clone(), osis_schema::History::PurgeOnReplace)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.sync_all().unwrap();
        lp.advance(1000);
        let e = write(&mut lp, 1, t, "x:e.0", 7);
        lp.sync(1, 3).unwrap();
        let s = lp.peers[3].engine.snapshot(&t, &a).unwrap().unwrap();
        lp.advance(1000);
        let d = &mut lp.peers[3].engine;
        assert_eq!(d.covered(&s, &e, &t, &a).unwrap(), Some(true));
        d.drop_body(&e, &t, &a).unwrap();
        for c in [e, s] {
            let pk = lp.peers[3].engine.package(&c).unwrap().unwrap();
            lp.deliver(0, &pk).unwrap();
        }
        let al = &mut lp.peers[0].engine;
        assert_eq!(al.covered(&s, &e, &t, &a).unwrap(), Some(true));
        al.drop_body(&e, &t, &a).unwrap();
        assert!(al.forgettable(&e).unwrap());
        al.forget_commits(&[e]).unwrap();
        lp.advance(1000);
        let r = remove(&mut lp, 0, t, 1);
        let (_, own) = frontier_of(&lp, 0, &r);
        assert_eq!(own.len(), 1, "Alice's own cover");
        let order = if ahead { [own[0], r] } else { [r, own[0]] };
        for c in order {
            let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
            lp.deliver(3, &pk).unwrap();
            let held = lp.peers[3].engine.core.ix.commits.get(&s).is_some_and(|m| m.holds(0) && !m.is_dropped(0));
            assert!(held && lp.peers[3].engine.covered_drops(&s).unwrap().is_empty(), "ahead {ahead}: Dave keeps his snapshot under Alice's own cover");
        }
        remove(&mut lp, 2, t, 0);
        for _ in 0..2 {
            lp.sync(2, 3).unwrap();
            lp.sync(3, 2).unwrap();
        }
        for p in [2, 3] {
            assert!(!lp.peers[p].engine.core.ix.commits.get(&own[0]).is_some_and(|m| m.valid_at(0)), "ahead {ahead}: peer {p}: the own cover fell with its removal");
            assert_eq!(reads(&mut lp, p, t, "x:e.0"), Some(Value::Int(7)), "ahead {ahead}: peer {p}: Dave's snapshot carries the edit");
        }
    }
}

// spec/permissions.md §5.2 (addenda; writing; when it first holds the role after): Carol, a
// reader, received Bob's edit before Alice removed Bob without it; Alice then grants Carol write.
// Carol writes her addendum then, by the state rule (answering once, as Carol applied the removal
// without the role, loses the edit), and the edit stands at every node.
#[test]
fn a_witness_granted_write_after_the_removal_writes_its_addendum_then_spec_perm_5_2() {
    let (mut lp, t) = world(3, &[Role::Write, Role::Read]);
    let e = write(&mut lp, 1, t, "x:e.0", 7);
    lp.sync(1, 2).unwrap();
    lp.advance(1);
    remove(&mut lp, 0, t, 1);
    lp.sync(0, 2).unwrap();
    assert!(addenda(&lp, 2, t).is_empty(), "a reader writes none");
    let carol = lp.peers[2].engine.me();
    lp.peers[0].engine.grant(&t, &carol, &edge(Role::Write)).unwrap();
    lp.advance(1000);
    lp.sync(0, 2).unwrap();
    assert_eq!(addenda(&lp, 2, t).iter().filter(|(a, _)| *a == carol).count(), 1, "Carol writes once she holds write");
    lp.sync_all().unwrap();
    for p in 0..3 {
        assert!(valid(&lp, p, &e, t, "x:e.0"), "peer {p}: the edit stands");
    }
}

/// Peer 0 (Alice) demotes Bob (peer 1, an admin) on `t` to `to` (`None`: removes him), a second
/// after everything so far.
fn demote_to(lp: &mut LocalPeer, t: Tid, to: Option<Role>) -> CommitId {
    lp.advance(1000);
    let bob = lp.peers[1].engine.me();
    let d = Demotion { holder: bob, new: to.map(edge), retain: None };
    let id = *lp.peers[0].engine.demote(&t, &d).unwrap().commits.last().unwrap();
    lp.advance(1000);
    id
}

// spec/permissions.md §5.2 (addenda; gives write just before a's key, and admin where the
// delta needs admin): Bob, an admin, writes admin-only content; Alice removes him, or lowers him
// to write, without it. Carol, an admin who received it, writes her addendum by the state rule
// and it keeps Bob's write at every node; Dave, a writer who received it too, owes none.
#[test]
fn admin_only_content_is_kept_by_an_admin_witness_spec_perm_5_2() {
    for to in [None, Some(Role::Write)] {
        let (mut lp, t) = world(4, &[Role::Admin, Role::Admin, Role::Write]);
        let e = write(&mut lp, 1, t, "x:p^.0", 7);
        for p in [2, 3] {
            lp.sync(1, p).unwrap();
        }
        lp.advance(1);
        demote_to(&mut lp, t, to);
        lp.sync_all().unwrap();
        let (carol, dave) = (lp.peers[2].engine.me(), lp.peers[3].engine.me());
        let by: Vec<Tid> = addenda(&lp, 0, t).into_iter().map(|(a, _)| a).collect();
        assert!(by.contains(&carol), "Carol, an admin, writes one ({to:?})");
        assert!(!by.contains(&dave), "Dave, a writer, owes none ({to:?})");
        for p in 0..4 {
            assert!(valid(&lp, p, &e, t, "x:p^.0"), "peer {p} ({to:?}): Bob's admin-only write stands");
        }
    }
}

// spec/permissions.md §5.2 (addenda; gives write just before a's key, and admin where the
// delta needs admin): as above, but only Dave, a writer, received Bob's admin-only write; his
// addendum listing it (written by hand: the state rule writes none) keeps nothing.
#[test]
fn admin_only_content_is_not_kept_by_a_writers_addendum_spec_perm_5_2() {
    let (mut lp, t) = world(4, &[Role::Admin, Role::Admin, Role::Write]);
    for p in &mut lp.peers {
        p.engine.write_addenda(false);
    }
    let e = write(&mut lp, 1, t, "x:p^.0", 7);
    lp.sync(1, 3).unwrap();
    lp.advance(1);
    let r = demote_to(&mut lp, t, None);
    lp.sync(0, 3).unwrap();
    let mut m = Mutation::new();
    let list = ct::Frontier { commits: [e].into_iter().collect() };
    m.op(t, &ct::ADDENDA, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::bytes(&r.0))], op: osis_crdt::Op::Put(osis_schema::Codec::to_value(&list)) }).unwrap();
    let a = lp.peers[3].commit(m).unwrap().unwrap();
    lp.advance(1000);
    lp.sync_all().unwrap();
    for p in 0..4 {
        assert!(valid(&lp, p, &a, t, ct::ADDENDA_AK), "peer {p}: Dave's addendum is a valid write of his");
        assert!(!valid(&lp, p, &e, t, "x:p^.0"), "peer {p}: a writer's addendum keeps no admin-only write");
    }
}

// spec/permissions.md §5.2 (addenda; writing), issues/s3-addenda-build.md (the trigger): Bob
// mints t2 under t and writes on it; Carol receives the edit before t2's creation, so it waits
// there for the record, and Alice removes Bob from t (and so t2) without it. Carol judged the
// removal with no candidate; once the creation arrives the edit applies, received before the
// removal, and she writes her addendum on t2 then.
#[test]
fn an_edit_received_in_time_that_applies_late_is_vouched_for_spec_perm_5_2() {
    let (mut lp, t) = world(3, &[Role::Write, Role::Write]);
    let mut m = Mutation::new();
    let t2 = lp.peers[1].engine.new_thing(&mut m, t);
    let made = lp.peers[1].commit(m).unwrap().unwrap();
    lp.advance(1000);
    let e = write(&mut lp, 1, t2, "x:e.0", 7);
    let send = |lp: &mut LocalPeer, c: CommitId| {
        let pk = lp.peers[1].engine.package(&c).unwrap().unwrap();
        lp.deliver(2, &pk).unwrap();
    };
    send(&mut lp, e);
    assert!(lp.peers[2].engine.core.ix.pending.contains_key(&e), "the edit waits at Carol for t2's record");
    lp.advance(1);
    remove(&mut lp, 0, t, 1);
    lp.sync(0, 2).unwrap();
    assert!(addenda(&lp, 2, t2).is_empty(), "nothing applied to vouch for yet");
    // the creation, and t2 into Carol's closure
    send(&mut lp, made);
    lp.hold_at(2, t2);
    lp.peers[2].reexamine().unwrap();
    assert!(lp.peers[2].engine.core.ix.commits.contains_key(&e), "the edit applies at Carol");
    let carol = lp.peers[2].engine.me();
    assert_eq!(addenda(&lp, 2, t2).iter().filter(|(a, _)| *a == carol).count(), 1, "Carol vouches once it applies");
}

// spec/permissions.md §5.2 (addenda; writing), spec/sync-set.md §2 Writing: Bob mints t2 under t,
// held by a strong on t in a commit of his own, and writes on t2; Carol receives both, Alice
// removes Bob from t (and so t2) without them. Applying the removal, Carol drops the strong, so t2
// is outside her node closure and the addendum owed there waits; her addendum on t makes the
// strong count again and brings t2 back in, and she writes the one on t2 in the same transaction.
#[test]
fn a_thing_an_addendum_brings_into_the_closure_gets_its_addendum_then_spec_perm_5_2() {
    let (mut lp, t) = world(3, &[Role::Write, Role::Write]);
    let (t2, _) = lp.peers[1].engine.create_with_admin(&t).unwrap();
    lp.advance(1000);
    let e = write(&mut lp, 1, t2, "x:e.0", 7);
    lp.sync(1, 2).unwrap();
    lp.advance(1);
    remove(&mut lp, 0, t, 1);
    lp.sync(0, 2).unwrap();
    let carol = lp.peers[2].engine.me();
    let by_carol = |lp: &LocalPeer, x: Tid| addenda(lp, 2, x).iter().filter(|(a, _)| *a == carol).count();
    assert_eq!(by_carol(&lp, t), 1, "Carol vouches for the strong on t");
    assert!(lp.peers[2].engine.closure_holds(&t2), "the strong counts: t2 is in Carol's node closure");
    assert_eq!(by_carol(&lp, t2), 1, "and the edit on t2 in the same transaction");
    lp.sync_all().unwrap();
    for p in 0..3 {
        assert!(valid(&lp, p, &e, t2, "x:e.0"), "peer {p}: the edit stands");
    }
}

// spec/permissions.md §5.2 (addenda; writing): what is owed is re-derived. Carol holds the
// removal and Bob's edit but writes nothing (writing off); after a restart, her next transaction
// writes the addendum she owes, and the edit stands at every node.
#[test]
fn an_addendum_owed_across_a_restart_is_written_spec_perm_5_2() {
    let (mut lp, t) = world(3, &[Role::Write, Role::Write]);
    let e = write(&mut lp, 1, t, "x:e.0", 7);
    lp.sync(1, 2).unwrap();
    lp.advance(1);
    lp.peers[2].engine.write_addenda(false);
    remove(&mut lp, 0, t, 1);
    lp.sync(0, 2).unwrap();
    assert!(addenda(&lp, 2, t).is_empty(), "nothing written while off");
    lp.peers[2].restart(7).unwrap();
    let mut m = Mutation::new();
    let me = lp.peers[2].engine.me();
    lp.peers[2].engine.new_thing(&mut m, me);
    lp.peers[2].commit(m).unwrap();
    assert_eq!(addenda(&lp, 2, t).iter().filter(|(a, _)| *a == me).count(), 1, "written after the restart");
    lp.sync_all().unwrap();
    for p in 0..3 {
        assert!(valid(&lp, p, &e, t, "x:e.0"), "peer {p}: the edit stands");
    }
}

/// Bob (1) writes `n` edits on `t` that Carol (2) receives and Alice (0) removes him without;
/// Carol writes her addendum. Then Alice raises Dave (3) from read to write, a role change in
/// the removal's component that moves nothing Carol's judgement reads: (removals judged, commits
/// scanned for candidates) at Carol as it arrives.
fn elsewhere_cost(n: usize) -> (u64, u64) {
    let (mut lp, t) = world(4, &[Role::Write, Role::Write, Role::Read]);
    for i in 0..n {
        write(&mut lp, 1, t, "x:e.0", i64::try_from(i).unwrap());
    }
    lp.sync(1, 2).unwrap();
    lp.advance(1);
    remove(&mut lp, 0, t, 1);
    lp.sync(0, 2).unwrap();
    let carol = lp.peers[2].engine.me();
    assert_eq!(addenda(&lp, 2, t).iter().filter(|(a, _)| *a == carol).count(), 1, "Carol answers");
    let dave = lp.peers[3].engine.me();
    lp.peers[0].engine.grant(&t, &dave, &edge(Role::Write)).unwrap();
    lp.advance(1000);
    osis_base::costs::take();
    lp.sync(0, 2).unwrap();
    let c = osis_base::costs::take();
    let get = |k: &str| c.iter().find(|x| x.0 == k).map_or(0, |x| x.2);
    assert_eq!(lp.peers[2].engine.core.timelines.role(&dave, &t, osis_perm::At::END), Some(Role::Write));
    assert_eq!(get("addenda: wake climbs"), 0, "live traffic climbs to no filed party");
    (get("addenda: removals judged"), get("addenda: commits scanned"))
}

// spec/permissions.md §5.2 (Addenda; Writing), notes/principles.md (Fast by construction): a
// removal with candidates is judged again only when something its judgement reads moves (its
// standing in the walk, a commit before it, this node's roles), so another party's role change
// in its component judges it not and scans none of the removed node's commits.
#[test]
fn a_role_change_elsewhere_rescans_no_candidates_spec_perm_5_2() {
    let (small, big) = (elsewhere_cost(5), elsewhere_cost(50));
    println!("addenda: (judged, commits scanned) by a role change elsewhere: {small:?} at n = 5, {big:?} at n = 50");
    assert_eq!((small, big), ((0, 0), (0, 0)));
}

// spec/permissions.md §5.2 (Addenda; Writing: whenever its own current view shows a content
// commit of X ordered before R...): Bob (1) holds write on `t` directly and through team Q
// (Dave's thing, Bob its admin). Bob writes e, received by Carol (2) alone. Dave (3), an admin
// of `t`, removes Q's grant (R1); then Alice (0) removes Bob's own grant (R), holding neither
// e nor R1. Carol receives R first: Bob keeps write through Q, so R demotes nobody below write
// and nothing is owed. R1 then reaches her, ordered before R: Bob falls below write at R, and
// Carol owes an addendum for e, though R1 names neither Bob nor Alice. e stands at every node.
#[test]
fn a_late_removal_of_anothers_path_makes_an_addendum_owed_spec_perm_5_2() {
    let (mut lp, t) = world(4, &[Role::Write, Role::Write, Role::Admin]);
    let (bob, dave) = (lp.peers[1].engine.me(), lp.peers[3].engine.me());
    let mut m = Mutation::new();
    let q = lp.peers[3].engine.new_thing(&mut m, dave);
    lp.peers[3].commit(m).unwrap();
    lp.hold(q);
    lp.sync_all().unwrap();
    lp.peers[3].engine.grant(&q, &bob, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&t, &q, &edge(Role::Write)).unwrap();
    lp.advance(1000);
    lp.sync_all().unwrap();
    let e = write(&mut lp, 1, t, "x:e.0", 7);
    lp.sync(1, 2).unwrap();
    let d = Demotion { holder: q, new: None, retain: None };
    let r1 = *lp.peers[3].engine.demote(&t, &d).unwrap().commits.last().unwrap();
    lp.advance(1000);
    let r = remove(&mut lp, 0, t, 1);
    let pk = lp.peers[0].engine.package(&r).unwrap().unwrap();
    lp.deliver(2, &pk).unwrap();
    lp.advance(1000);
    lp.peers[2].tick().unwrap();
    let carol = lp.peers[2].engine.me();
    assert_eq!(lp.peers[2].engine.core.timelines.role(&bob, &t, osis_perm::At::END), Some(Role::Write), "Bob keeps write through Q");
    assert!(addenda(&lp, 2, t).iter().all(|(a, _)| *a != carol), "nothing owed while Bob keeps write");
    let pk = lp.peers[3].engine.package(&r1).unwrap().unwrap();
    lp.deliver(2, &pk).unwrap();
    lp.advance(1000);
    lp.peers[2].tick().unwrap();
    assert!(lp.peers[2].engine.core.timelines.role(&bob, &t, osis_perm::At::END) < Some(Role::Write), "R1 ordered before R: Bob falls at R");
    assert_eq!(addenda(&lp, 2, t).iter().filter(|(a, _)| *a == carol).count(), 1, "Carol answers once R1 arrives");
    lp.sync_all().unwrap();
    for p in 0..4 {
        assert!(valid(&lp, p, &e, t, "x:e.0"), "peer {p}: e stands");
    }
}

// spec/permissions.md §5.2 (Addenda; Writing): Yan (1), a reader of `t`, holds write on it through two teams
// it minted, X and P. Yan writes e, received by Carol (2) alone. Dave removes
// P's grant (R1); then Alice (0) removes X's (R), holding neither e nor R1. Carol receives R
// first: Yan keeps write through P, so nothing is owed. R1 then reaches her, ordered before R:
// Yan falls below write at R, and Carol owes an addendum for e, though R1 names neither X nor
// Alice and Yan is filed nowhere. e stands at every node.
#[test]
fn a_late_removal_of_a_members_other_team_makes_an_addendum_owed_spec_perm_5_2() {
    let (mut lp, t) = world(4, &[Role::Read, Role::Write, Role::Admin]);
    let yan = lp.peers[1].engine.me();
    let mut teams = Vec::new();
    for _ in 0..2 {
        let mut m = Mutation::new();
        let q = lp.peers[1].engine.new_thing(&mut m, yan);
        lp.peers[1].commit(m).unwrap();
        lp.hold(q);
        teams.push(q);
    }
    lp.sync_all().unwrap();
    for q in &teams {
        lp.peers[0].engine.grant(&t, q, &edge(Role::Write)).unwrap();
    }
    lp.advance(1000);
    lp.sync_all().unwrap();
    let (x, p) = (teams[0], teams[1]);
    assert_eq!(lp.peers[2].engine.core.timelines.role(&yan, &t, osis_perm::At::END), Some(Role::Write), "Yan writes through the teams");
    let e = write(&mut lp, 1, t, "x:e.0", 7);
    lp.sync(1, 2).unwrap();
    let r1 = *lp.peers[3].engine.demote(&t, &Demotion { holder: p, new: None, retain: None }).unwrap().commits.last().unwrap();
    lp.advance(1000);
    lp.advance(1000);
    let r = *lp.peers[0].engine.demote(&t, &Demotion { holder: x, new: None, retain: None }).unwrap().commits.last().unwrap();
    lp.advance(1000);
    let pk = lp.peers[0].engine.package(&r).unwrap().unwrap();
    lp.deliver(2, &pk).unwrap();
    lp.advance(1000);
    lp.peers[2].tick().unwrap();
    let carol = lp.peers[2].engine.me();
    assert_eq!(lp.peers[2].engine.core.timelines.role(&yan, &t, osis_perm::At::END), Some(Role::Write), "Yan keeps write through P");
    assert!(addenda(&lp, 2, t).iter().all(|(a, _)| *a != carol), "nothing owed while Yan keeps write");
    let pk = lp.peers[3].engine.package(&r1).unwrap().unwrap();
    lp.deliver(2, &pk).unwrap();
    lp.advance(1000);
    lp.peers[2].tick().unwrap();
    assert!(lp.peers[2].engine.core.timelines.role(&yan, &t, osis_perm::At::END) < Some(Role::Write), "R1 ordered before R: Yan falls at R");
    assert_eq!(addenda(&lp, 2, t).iter().filter(|(a, _)| *a == carol).count(), 1, "Carol answers once R1 arrives");
    lp.sync_all().unwrap();
    for p in 0..4 {
        assert!(valid(&lp, p, &e, t, "x:e.0"), "peer {p}: e stands");
    }
}
