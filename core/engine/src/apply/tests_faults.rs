//! Work that fails for a fault of this node (`Error::is_fault`) is set aside by its unit
//! (`Engine::take_units`): a received commit whose taking faults pends (`apply::set_aside`), a
//! tick's timer is left unrun, a record unlearned; the node goes on with everything else, the app
//! is told, and an open takes the unit again. Planted in a commit's own step (`Core::apply_fault`)
//! or in a unit's work (`Core::end_fault`).
//! spec: spec/commits.md §4 (No local error from peer bytes).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::engine::EndFault;
use crate::events::{DiagnosticKind, Event};
use crate::local_peer::LocalPeer;
use crate::{Ingested, Mutation, Reason};
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{Ak, CommitId, Tid, Value};

const T0: osis_base::Time = osis_base::Time(1_700_000_000_000);

fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

/// Peer 0 makes thing `t` (`c1`, `x:a.0` 1), which peer 1 holds; then, ahead of peer 1's clock,
/// writes `x:a.0` 2 (`c2`) and `x:b.0` "b" (`c3`), neither delivered.
fn world() -> (LocalPeer, (Tid, CommitId, CommitId)) {
    LocalPeer::cached("apply::tests_faults::world", || {
        let mut lp = LocalPeer::fresh(2, T0);
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &ak("x:a.0"), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.share(0, t);
        lp.sync_all().unwrap();
        lp.peers[0].clock.advance(3 * MAX_DRIFT_MS);
        let mut m = Mutation::new();
        m.set(t, &ak("x:a.0"), &Value::Int(2)).unwrap();
        let c2 = lp.peers[0].commit(m).unwrap().unwrap();
        let mut m = Mutation::new();
        m.set(t, &ak("x:b.0"), &Value::Str("b".into())).unwrap();
        let c3 = lp.peers[0].commit(m).unwrap().unwrap();
        (lp, (t, c2, c3))
    })
}

fn faults_told(rx: &std::sync::mpsc::Receiver<Event>) -> Vec<Option<CommitId>> {
    rx.try_iter().filter_map(|e| if let Event::Diagnostic(d) = e { Some(d) } else { None }).filter(|d| d.kind == DiagnosticKind::Fault).map(|d| d.commit).collect()
}

// A commit faulting on arrival every time pends set aside, counted as not received (its write
// does not read); the commits after it apply; the app is told once; a copy arriving again brings
// no error; an open of a build where it applies applies it.
#[test]
fn a_commit_faulting_on_arrival_is_set_aside_and_the_node_goes_on_spec_commits_4() {
    let (mut lp, (t, c2, c3)) = world();
    lp.peers[1].clock.advance(3 * MAX_DRIFT_MS);
    let pk2 = lp.peers[0].engine.package(&c2).unwrap().unwrap();
    let pk3 = lp.peers[0].engine.package(&c3).unwrap().unwrap();
    let rx = lp.peers[1].engine.subscribe();
    lp.peers[1].engine.core.apply_fault = Some(c2);
    assert_eq!(lp.peers[1].receive(&pk2.bytes, pk2.blobs.clone()).unwrap(), Ingested::Pending(c2, Reason::Fault));
    assert_eq!(lp.peers[1].receive(&pk3.bytes, pk3.blobs.clone()).unwrap(), Ingested::Applied(c3));
    assert_eq!(lp.peers[1].receive(&pk2.bytes, pk2.blobs.clone()).unwrap(), Ingested::Pending(c2, Reason::Fault), "again");
    let e = &mut lp.peers[1].engine;
    assert_eq!(e.get(&t, &ak("x:a.0")).unwrap(), Some(Value::Int(1)), "the set-aside write does not read");
    assert_eq!(e.get(&t, &ak("x:b.0")).unwrap(), Some(Value::Str("b".into())));
    assert_eq!(e.core.ix.pending.get(&c2), Some(&Reason::Fault));
    assert_eq!(faults_told(&rx), vec![Some(c2)]);
    // a new engine, the fault gone (a fixed build)
    lp.peers[1].restart(1).unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(!e.core.ix.pending.contains_key(&c2));
    assert_eq!(e.get(&t, &ak("x:a.0")).unwrap(), Some(Value::Int(2)), "applied at the open");
}

// A commit faulting in a round of examinations is set aside alone, whether its own examination
// faults or the transaction's work its taking brings (the round's end work, outside any step):
// the round's other commit applies, the app is told, nothing owes a reload (each tick reloading,
// the round failing again: a loop), and an open applies it.
#[test]
fn a_commit_faulting_in_a_round_is_set_aside_alone_spec_commits_4() {
    for end in [false, true] {
        let (mut lp, (t, c2, c3)) = world();
        for c in [c2, c3] {
            let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
            assert!(matches!(lp.peers[1].receive(&pk.bytes, pk.blobs).unwrap(), Ingested::Pending(_, Reason::Drift)));
        }
        let rx = lp.peers[1].engine.subscribe();
        match end {
            false => lp.peers[1].engine.core.apply_fault = Some(c2),
            true => lp.peers[1].engine.core.end_fault = Some(EndFault::Commit(c2)),
        }
        lp.peers[1].clock.advance(3 * MAX_DRIFT_MS);
        lp.peers[1].reexamine().unwrap();
        let loads = lp.peers[1].engine.loads();
        lp.peers[1].tick().unwrap();
        let e = &mut lp.peers[1].engine;
        assert_eq!(e.get(&t, &ak("x:b.0")).unwrap(), Some(Value::Str("b".into())), "end {end}: the round's other commit applied");
        assert_eq!(e.core.ix.pending.get(&c2), Some(&Reason::Fault), "end {end}");
        assert_eq!(faults_told(&rx), vec![Some(c2)], "end {end}");
        assert!(!e.reload_owed() && e.loads() == loads, "end {end}: no reload");
        lp.peers[1].restart(1).unwrap();
        assert_eq!(lp.peers[1].engine.get(&t, &ak("x:a.0")).unwrap(), Some(Value::Int(2)), "end {end}: applied at the open");
    }
}

// A tick's timer whose run faults is left unrun until the next open: the tick's other timer runs,
// the app is told, the next timer is not left at now (a driver ticking at once, failing again),
// and an open runs it.
#[test]
fn a_timer_faulting_at_a_tick_is_set_aside_alone_spec_commits_4() {
    let mut lp = LocalPeer::fresh(1, T0);
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap().unwrap();
    let at = osis_base::Time(lp.peers[0].engine.now().0 + 60_000);
    let mut expiring = |k: &str| {
        let mut m = Mutation::new();
        m.set(t, &ak(k), &Value::Int(1)).unwrap();
        m.expires(t, &ak(k), at).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    let ca = expiring("x:a.0");
    expiring("x:b.0");
    let rx = lp.peers[0].engine.subscribe();
    lp.peers[0].engine.core.end_fault = Some(EndFault::Commit(ca));
    lp.peers[0].clock.advance(120_000);
    lp.peers[0].tick().unwrap();
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.get(&t, &ak("x:b.0")).unwrap(), None, "the other timer ran");
    assert_eq!(e.get(&t, &ak("x:a.0")).unwrap(), Some(Value::Int(1)), "its timer set aside");
    assert_eq!(faults_told(&rx), vec![Some(ca)]);
    let now = e.now().0;
    assert!(e.next_timer().unwrap().is_none_or(|x| x > now) && !e.timers_due(), "nothing due now");
    lp.peers[0].restart(1).unwrap();
    lp.peers[0].tick().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("x:a.0")).unwrap(), None, "run after the open");
}

// A tick whose finding of what is due faults (its work shared by every timer) sets that finding
// aside until the next open: the tick returns, nothing is left due (a driver ticking at once,
// faulting again: a spin), the app is told once, and an open finds and runs the timer.
#[test]
fn a_tick_whose_finding_faults_sets_it_aside_spec_commits_4() {
    let mut lp = LocalPeer::fresh(1, T0);
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.set(t, &ak("x:a.0"), &Value::Int(1)).unwrap();
    m.expires(t, &ak("x:a.0"), osis_base::Time(lp.peers[0].engine.now().0 + 60_000)).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let rx = lp.peers[0].engine.subscribe();
    lp.peers[0].engine.core.end_fault = Some(EndFault::Find);
    lp.peers[0].clock.advance(120_000);
    lp.peers[0].tick().unwrap();
    let e = &mut lp.peers[0].engine;
    let now = e.now().0;
    assert!(e.next_timer().unwrap().is_none_or(|x| x > now) && !e.timers_due(), "nothing due now");
    assert_eq!(e.get(&t, &ak("x:a.0")).unwrap(), Some(Value::Int(1)), "its timer not found");
    lp.peers[0].tick().unwrap();
    assert_eq!(faults_told(&rx), vec![None], "told once");
    lp.peers[0].restart(1).unwrap();
    lp.peers[0].tick().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("x:a.0")).unwrap(), None, "run after the open");
}

// An arrival whose taking faults, carrying a record whose learning faults too (work outside the
// commit, in the transaction setting it aside): the commit is set aside, the record left
// unlearned, both told; the node goes on, and an open applies the commit.
#[test]
fn an_arrival_whose_setting_aside_faults_on_a_record_is_set_aside_alone_spec_commits_4() {
    let (mut lp, (t, c2, c3)) = world();
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let u = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap().unwrap();
    let ru = lp.peers[0].engine.core.created(&u).cloned().unwrap();
    lp.peers[1].clock.advance(3 * MAX_DRIFT_MS);
    let pk2 = lp.peers[0].engine.package(&c2).unwrap().unwrap();
    let pk3 = lp.peers[0].engine.package(&c3).unwrap().unwrap();
    let rx = lp.peers[1].engine.subscribe();
    let e = &mut lp.peers[1].engine;
    e.core.apply_fault = Some(c2);
    e.core.end_fault = Some(EndFault::Record(u));
    assert_eq!(e.ingest_carrying(&pk2.bytes, pk2.blobs.clone(), vec![ru]).unwrap(), Ingested::Pending(c2, Reason::Fault));
    assert!(e.core.created(&u).is_none(), "the record left unlearned");
    assert_eq!(e.ingest(&pk3.bytes, pk3.blobs.clone()).unwrap(), Ingested::Applied(c3));
    assert_eq!(e.get(&t, &ak("x:b.0")).unwrap(), Some(Value::Str("b".into())));
    assert_eq!(faults_told(&rx), vec![Some(c2), Some(c2)], "the commit and the record");
    lp.peers[1].restart(1).unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &ak("x:a.0")).unwrap(), Some(Value::Int(2)), "applied at the open");
}

// A commit set aside on arrival keeps the blobs it came with: an open of a build where it applies
// applies it, nothing delivered again (sync's path would fetch them for no commit).
#[test]
fn a_commit_set_aside_on_arrival_keeps_its_blobs_spec_commits_4() {
    let (mut lp, (t, _, _)) = world();
    let mut m = Mutation::new();
    m.set(t, &ak("x:c.0"), &Value::Bytes(vec![7; 200_000])).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    assert!(!pk.blobs.is_empty(), "a commit with blobs");
    let want = lp.peers[0].engine.get(&t, &ak("x:c.0")).unwrap();
    lp.peers[1].clock.advance(3 * MAX_DRIFT_MS);
    let e = &mut lp.peers[1].engine;
    e.core.apply_fault = Some(c);
    assert_eq!(e.ingest(&pk.bytes, pk.blobs.clone()).unwrap(), Ingested::Pending(c, Reason::Fault));
    lp.peers[1].restart(1).unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(!e.core.ix.pending.contains_key(&c), "applied at the open: {:?}", e.core.ix.pending.get(&c));
    assert_eq!(e.get(&t, &ak("x:c.0")).unwrap(), want);
    assert!(pk.blobs.iter().all(|(b, _)| e.blob(b).unwrap().is_some()), "its blobs held");
}

// A commit whose arrival brings a thing into the node closure, waking a commit waiting for it
// whose taking faults (its transaction's end work): the arrival applies, and the woken commit is
// set aside alone, its own unit, never failing the application of the other (spec/commits.md §4
// No local error from peer bytes).
#[test]
fn a_commit_woken_by_an_arrival_faults_alone_spec_commits_4() {
    let (mut lp, (t, _, _)) = world();
    lp.peers[1].clock.advance(3 * MAX_DRIFT_MS);
    let d0 = lp.peers[0].engine.node_root().unwrap();
    let holds = |m: &mut Mutation, from: Tid, to: Tid| {
        m.op(from, &osis_schema::core_types::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(Value::Strong(to)) }).unwrap();
    };
    // w, minted under t, held from peer 0's node root alone: outside peer 1's node closure
    let rec = lp.peers[0].engine.thing_record(t, None);
    let mut m = Mutation::new();
    let w = m.create(rec);
    holds(&mut m, d0, w);
    let cw = lp.peers[0].commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.set(w, &ak("x:a.0"), &Value::Int(7)).unwrap();
    let cy = lp.peers[0].commit(m).unwrap().unwrap();
    // a strong from t, which peer 1 holds: w enters there
    let mut m = Mutation::new();
    holds(&mut m, t, w);
    let x = lp.peers[0].commit(m).unwrap().unwrap();
    for c in [cw, cy] {
        let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
        lp.peers[1].receive(&pk.bytes, pk.blobs).unwrap();
    }
    assert!(lp.peers[1].engine.core.ix.pending.contains_key(&cy), "cy waits for w to enter");
    let rx = lp.peers[1].engine.subscribe();
    lp.peers[1].engine.core.end_fault = Some(EndFault::Commit(cy));
    let pk = lp.peers[0].engine.package(&x).unwrap().unwrap();
    assert_eq!(lp.peers[1].receive(&pk.bytes, pk.blobs).unwrap(), Ingested::Applied(x), "the arrival applies");
    let e = &mut lp.peers[1].engine;
    assert!(e.closure_holds(&w), "w entered");
    assert_eq!(e.core.ix.pending.get(&cy), Some(&Reason::Fault), "the woken commit set aside");
    assert_eq!(faults_told(&rx), vec![Some(cy)]);
    lp.peers[1].restart(1).unwrap();
    assert_eq!(lp.peers[1].engine.get(&w, &ak("x:a.0")).unwrap(), Some(Value::Int(7)), "applied at the open");
}
