//! Atomic steps (`Tx::step`): a step inside a transaction (one pending commit's apply, one part's
//! judging, one removal's answer) is applied fully or not at all. A step that ran in full and then
//! failed leaves the store and the in-memory state exactly as a run where it never ran.
//! spec: none (internal: notes/engine.md, Atomic steps), unless a test cites more.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::engine::journal::Journaled;
use crate::engine::{Step, StepFault};
use crate::events::{DiagnosticKind, Event};
use crate::flows::Demotion;
use crate::local_peer::LocalPeer;
use crate::{Engine, Mutation};
use osis_base::{Ak, CommitId, Role, Tid, Value};
use osis_schema::core_types as ct;

const T0: osis_base::WallMs = osis_base::WallMs(1_700_000_000_000);

fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

/// The node's indexes, its perm view and its store, decrypted.
fn state(e: &mut Engine) -> (String, Vec<(String, Vec<u8>)>) {
    // headers decoded alike (decoding is a cache, not undone)
    e.core.ix.commits.values().for_each(|m| drop(m.header.decoded()));
    (format!("{}\n{}", e.core.ix.contents(), e.perm_digest(false)), e.store_dump().unwrap())
}

fn fault(site: Step, after: bool, skip: u32) -> Option<StepFault> {
    Some(StepFault { site, after, skip })
}

/// Runs `scenario` with every step of `site` past the first `skip` failing before it runs, then
/// failing after it ran in full: the node under test (the scenario's result) ends alike.
fn ran_equals_never_ran(site: Step, skip: u32, scenario: impl Fn(Option<StepFault>) -> (LocalPeer, usize)) {
    let mut states = Vec::new();
    for after in [false, true] {
        let (mut lp, p) = scenario(fault(site, after, skip));
        states.push(state(&mut lp.peers[p].engine));
    }
    let (never, ran) = (&states[0], &states[1]);
    assert_eq!(never.0, ran.0, "{site:?}: indexes");
    let first = never.1.iter().zip(&ran.1).find(|(a, b)| a != b).map(|(a, _)| a.0.clone());
    assert!(never.1 == ran.1, "{site:?}: store differs from {first:?}");
}

/// Peer 0 makes thing `t` (`c1`) and writes on it (`c2`); peer 1 receives `c2` first (it waits
/// for `t`'s record), then `c1`: `c2` applies when re-examined.
fn pending_then_applied(seed: u64, f: Option<StepFault>) -> (LocalPeer, CommitId) {
    let mut lp = LocalPeer::new(2, seed, T0).unwrap();
    lp.sync_all().unwrap();
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    m.set(t, &ak("x:a.0"), &Value::Int(1)).unwrap();
    let c1 = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(1000);
    let mut m = Mutation::new();
    m.set(t, &ak("x:a.0"), &Value::Int(2)).unwrap();
    m.set(t, &ak("x:b.0"), &Value::Str("b".into())).unwrap();
    let c2 = lp.peers[0].commit(m).unwrap().unwrap();
    let pks = lp.packages(0).unwrap();
    let pk = |c: CommitId| pks.iter().find(|p| p.id == c).unwrap();
    let e = &mut lp.peers[1].engine;
    e.core.step_fault = f;
    e.ingest(&pk(c2).bytes, pk(c2).blobs.clone()).unwrap();
    assert!(e.core.ix.pending.contains_key(&c2), "waits for the record");
    e.ingest(&pk(c1).bytes, pk(c1).blobs.clone()).unwrap();
    (lp, c2)
}

// A pending commit whose re-examination fails (`Engine::reexamine`) is dropped as bad input with
// nothing of its examination or apply kept.
#[test]
fn reexamined_commit_failing_keeps_nothing() {
    let (lp, c2) = pending_then_applied(961, None);
    assert!(lp.peers[1].engine.core.ix.commits.contains_key(&c2), "without a fault it applies");
    ran_equals_never_ran(Step::Commit, 0, |f| {
        let (lp, c2) = pending_then_applied(961, f);
        let core = &lp.peers[1].engine.core;
        assert!(!core.ix.commits.contains_key(&c2) && !core.ix.pending.contains_key(&c2), "dropped as bad");
        (lp, 1)
    });
}

/// Peer 1 holds thing `t` from peer 0, then receives peer 0's commit with parts on two aspects.
fn two_parts(seed: u64, f: Option<StepFault>) -> (LocalPeer, CommitId) {
    let mut lp = LocalPeer::new(2, seed, T0).unwrap();
    lp.sync_all().unwrap();
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    m.set(t, &ak("x:a.0"), &Value::Int(1)).unwrap();
    lp.peers[0].commit(m).unwrap();
    lp.sync_all().unwrap();
    lp.advance(1000);
    let mut m = Mutation::new();
    m.set(t, &ak("x:a.0"), &Value::Int(2)).unwrap();
    m.set(t, &ak("x:b.0"), &Value::Str("b".into())).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.peers[1].engine.core.step_fault = f;
    lp.sync(0, 1).unwrap();
    (lp, c)
}

// A part whose judging fails (`examine`) is dropped alone, with nothing of its judging kept; the
// commit's other part applies.
#[test]
fn judged_part_failing_keeps_nothing() {
    ran_equals_never_ran(Step::Part, 1, |f| {
        let (lp, c) = two_parts(962, f);
        let m = lp.peers[1].engine.core.ix.commits.get(&c).unwrap();
        assert_eq!((0..m.view.aspects.len()).filter(|ai| m.holds(*ai)).count(), 1, "one part held");
        (lp, 1)
    });
}

/// Peer 1 (a writer) edits `t` and peer 2 (a writer) receives the edit; peer 0 removes peer 1
/// without having received it. Peer 2 owes an addendum once it receives the removal.
fn removal_to_answer(seed: u64) -> (LocalPeer, Tid, CommitId) {
    let mut lp = LocalPeer::new(3, seed, T0).unwrap();
    lp.sync_all().unwrap();
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    m.set(t, &ak("x:a.0"), &Value::Int(0)).unwrap();
    lp.peers[0].commit(m).unwrap();
    for p in [1, 2] {
        let who = lp.peers[p].engine.tid();
        lp.peers[0].engine.grant(&t, &who, &ct::Edge { role: Role::Write, until: None, invite: None, tied: None }).unwrap();
    }
    lp.sync_all().unwrap();
    lp.advance(1000);
    let mut m = Mutation::new();
    m.set(t, &ak("x:e.0"), &Value::Int(7)).unwrap();
    lp.peers[1].commit(m).unwrap();
    lp.sync(1, 2).unwrap();
    lp.advance(2000);
    let bob = lp.peers[1].engine.tid();
    let r = *lp.peers[0].engine.demote(&t, &Demotion { holder: bob, new: None, retain: None }).unwrap().commits.last().unwrap();
    lp.advance(1000);
    (lp, t, r)
}

/// `removal_to_answer`, peer 2 receiving the removal with `f`.
fn removal_answered(seed: u64, f: Option<StepFault>) -> (LocalPeer, Tid, CommitId) {
    let (mut lp, t, r) = removal_to_answer(seed);
    lp.peers[2].engine.core.step_fault = f;
    lp.sync(0, 2).unwrap();
    (lp, t, r)
}

fn addenda_by(lp: &LocalPeer, peer: usize, t: Tid) -> usize {
    let core = &lp.peers[peer].engine.core;
    let me = core.id.tid();
    core.ix.addenda.keys().filter(|(th, c)| *th == t && core.ix.commits.get(c).is_some_and(|m| m.view.author == me)).count()
}

// spec/permissions.md §5.2 (Addenda): an answer to a removal that fails
// (`flows::addenda::answer_removals`) keeps nothing of its
// attempt, and the removal stays due.
#[test]
fn answer_failing_keeps_nothing() {
    let (lp, t, r) = removal_answered(963, None);
    assert_eq!(addenda_by(&lp, 2, t), 1, "without a fault it answers");
    assert!(!lp.peers[2].engine.core.ix.addenda_due.contains(&r));
    ran_equals_never_ran(Step::Answer, 0, |f| {
        let (lp, t, r) = removal_answered(963, f);
        assert_eq!(addenda_by(&lp, 2, t), 0);
        assert!(lp.peers[2].engine.core.ix.addenda_due.contains(&r), "still due");
        (lp, 2)
    });
}

// spec/permissions.md §5.2 (Addenda): an answer that fails every time is reported and stays due without blocking what the node
// receives; once it can be written, the next transaction writes it.
#[test]
fn failing_answer_never_blocks_ingest() {
    let (mut lp, t, r) = removal_to_answer(964);
    let rx = lp.peers[2].engine.subscribe();
    lp.peers[2].engine.core.step_fault = fault(Step::Answer, true, 0);
    lp.sync(0, 2).unwrap();
    assert!(lp.peers[2].engine.core.ix.commits.contains_key(&r), "the removal applies");
    // more from the remover: applied though the answer keeps failing
    let mut m = Mutation::new();
    m.set(t, &ak("x:a.0"), &Value::Int(9)).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync(0, 2).unwrap();
    let e = &mut lp.peers[2].engine;
    assert!(e.core.ix.commits.contains_key(&c), "ingest goes on");
    assert_eq!(e.get(&t, &ak("x:a.0")).unwrap(), Some(Value::Int(9)));
    assert!(e.core.ix.addenda_due.contains(&r), "still due");
    let reported: Vec<_> = rx.try_iter().filter_map(|e| if let Event::Diagnostic(d) = e { Some(d) } else { None }).filter(|d| d.kind == DiagnosticKind::AddendaFailed).collect();
    assert_eq!(reported.len(), 1, "reported once: {reported:?}");
    assert_eq!(reported[0].commit, Some(r));
    e.core.step_fault = None;
    e.run(|_| Ok(())).unwrap();
    assert!(!lp.peers[2].engine.core.ix.addenda_due.contains(&r), "answered");
    assert_eq!(addenda_by(&lp, 2, t), 1);
}
