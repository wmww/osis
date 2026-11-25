//! A received commit whose apply fails for a fault of this node (`Error::is_fault`, planted with
//! `Core::apply_fault`) is set aside (`apply::set_aside`): it pends, the node goes on with every
//! other commit, the app is told, and an open examines it again.
//! spec: spec/commits.md §4 (No local error from peer bytes).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::events::{DiagnosticKind, Event};
use crate::local_peer::LocalPeer;
use crate::{Ingested, Mutation, Reason};
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{Ak, CommitId, Tid, Value};

const T0: osis_base::WallMs = osis_base::WallMs(1_700_000_000_000);

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

// A commit faulting in a round of examinations is set aside alone: the round's other commit
// applies, and nothing owes a reload (each tick reloading, the round failing again: a loop).
#[test]
fn a_commit_faulting_in_a_round_is_set_aside_alone_spec_commits_4() {
    let (mut lp, (t, c2, c3)) = world();
    for c in [c2, c3] {
        let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
        assert!(matches!(lp.peers[1].receive(&pk.bytes, pk.blobs).unwrap(), Ingested::Pending(_, Reason::Drift)));
    }
    lp.peers[1].engine.core.apply_fault = Some(c2);
    lp.peers[1].clock.advance(3 * MAX_DRIFT_MS);
    lp.peers[1].reexamine().unwrap();
    let loads = lp.peers[1].engine.loads();
    lp.peers[1].tick().unwrap();
    let e = &mut lp.peers[1].engine;
    assert_eq!(e.get(&t, &ak("x:b.0")).unwrap(), Some(Value::Str("b".into())), "the round's other commit applied");
    assert_eq!(e.core.ix.pending.get(&c2), Some(&Reason::Fault));
    assert!(!e.reload_owed() && e.loads() == loads, "no reload");
}
