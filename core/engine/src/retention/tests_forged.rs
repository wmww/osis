//! Hostile input never produces a local error: a writer's forged copies of others' writes (a
//! snapshot carrying them under their stamps with other payloads, spec/permissions.md §5.2 Copies)
//! are joined by copy order (spec/crdt.md §4.1) at every node, and each death they cause is dated
//! (spec/crdt.md §4.8, `bounds::Killed`), on the forger's own apply, at arrival, in a tick and
//! after a restart: no node fails, and all read alike.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::error::Error;
use crate::local_peer::LocalPeer;
use crate::Mutation;
use crdt_model::r#gen::{Rng, kitchen_sink};
use crdt_model::ops::Ty;
use crdt_model::stamp::Source as MSource;
use crdt_model::state::Frag as MFrag;
use osis_base::{Ak, Classified, CommitId, ErrorClass, Role, Tid, Ts, Value};
use osis_crdt::{CounterRange, DeltaCtx, DeltaKind, Fragment, Interner};
use osis_schema::core_types as ct;

const T0: osis_base::WallMs = osis_base::WallMs(1_700_000_000_000);

fn ak() -> Ak {
    Ak::new("x:f.0").unwrap()
}

/// Admin 0, writer 1 (the forger) and reader 2 on a thing of 0 whose setting keeps the
/// aspect's history (so deaths date bodies, `bounds::dated_replaced_at`).
fn world() -> (LocalPeer, Tid) {
    LocalPeer::cached("retention::tests_forged::world", || {
        let mut lp = LocalPeer::fresh(3, T0);
        lp.sync_all().unwrap();
        let (a, w, x) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        let day = osis_schema::History::Keep { until: None, after: Some(86_400_000) };
        m.set(t, &ct::RETENTION, &ct::RetentionSetting::of(ak(), day)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.hold(t);
        let edge = |role| ct::Edge { role, until: None, invite: None, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &w, &edge(Role::Write)).unwrap();
        lp.peers[0].engine.grant(&t, &x, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        lp.advance(60_000);
        (lp, t)
    })
}

/// Writer 1 signs a snapshot of `ak()` carrying `st` (its own apply joins it): `None` where the
/// forger cannot make it (not this property's concern), never an engine invariant broken.
fn forge(lp: &mut LocalPeer, t: Tid, st: Fragment) -> Option<CommitId> {
    let r = lp.peers[1].engine.run(|tx| {
        let (ts, node) = (tx.core.hlc.next(), tx.core.writer_for(&t)?);
        crate::retention::snapshot::build_snapshot(tx, t, ak(), st, ts, node, Default::default(), Default::default(), None, false)
    });
    match r {
        Ok(c) => Some(c),
        Err(Error::Corrupt(m)) => panic!("the forger's own apply broke an engine invariant: {m}"),
        Err(_) => None,
    }
}

/// Peer `to` receives commit `c` of peer 1: a bad input is fine, a local error never.
fn deliver(lp: &mut LocalPeer, to: usize, c: &CommitId) {
    let pk = lp.peers[1].engine.package(c).unwrap().unwrap();
    if let Err(e) = lp.peers[to].receive(&pk.bytes, pk.blobs.clone()) {
        assert_ne!(e.class(), ErrorClass::Local, "peer {to} receiving a forged snapshot: {e}");
    }
}

/// Every peer ticks a day on and restarts: no local error; then all read `ak()` alike.
fn settle_alike(lp: &mut LocalPeer, t: Tid) {
    lp.advance(86_400_000);
    for (i, p) in lp.peers.iter_mut().enumerate() {
        p.tick().unwrap_or_else(|e| panic!("peer {i} ticking: {e}"));
        p.restart(i as u64).unwrap_or_else(|e| panic!("peer {i} reopening: {e}"));
    }
    let reads: Vec<Option<Value>> = lp.peers.iter_mut().map(|p| p.engine.get(&t, &ak()).unwrap()).collect();
    assert!(reads.iter().all(|r| *r == reads[0]), "all read alike: {reads:?}");
}

// spec/crdt.md §4.1 Copy order, §4.8, spec/permissions.md §5.2 Copies: admin 0 adds 5 to a set;
// writer 1 forges a snapshot carrying that element's write under its stamp holding a weak
// reference (a reference sorts above an int, so the copy wins). Every node joins it, the
// forger's own apply included, the write dying nowhere (one write, whichever copy wins), and
// all read the forged value. Fails with a set element's write keyed by what its copy holds.
#[test]
fn a_forged_copy_of_a_set_element_fails_no_node_spec_crdt_4_1() {
    let (mut lp, t) = world();
    let mut m = Mutation::new();
    m.op(t, &ak(), osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Add(Value::Int(5)) }).unwrap();
    lp.peers[0].commit(m).unwrap();
    lp.sync_all().unwrap();
    let st = lp.peers[1].engine.run(|tx| Ok(tx.state(&t, &ak())?.cloned().unwrap())).unwrap();
    let writes = st.writes();
    let (dot, ts) = writes.iter().find_map(|(d, ts)| Some((d.clone(), (*ts)?))).unwrap();
    let weak = Value::Weak(Tid::from_bytes([7; 15]));
    let empty = Fragment::default();
    let mut b = osis_crdt::DeltaBuilder::new(&empty, osis_crdt::Writer::new(ts, dot.src.clone(), dot.ctr));
    b.apply(&osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Add(weak.clone()) }, &osis_crdt::AnyView).unwrap();
    let forged = b.finish().unwrap().0;
    assert_eq!(forged.writes(), writes, "the copy is the write under its own stamp");
    let c = forge(&mut lp, t, forged).expect("the forger makes it");
    deliver(&mut lp, 0, &c);
    deliver(&mut lp, 2, &c);
    settle_alike(&mut lp, t);
    assert_eq!(lp.peers[2].engine.get(&t, &ak()).unwrap(), Some(Value::Set([weak].into_iter().collect())));
}

/// A model fragment as a snapshot's bytes carry it (`None`: no wire form, bad input).
fn carried(d: &MFrag) -> Option<Fragment> {
    let own = MSource::session(250, 0);
    let bytes = crdt_model::wire::encode_snapshot(d, &[], [3; 16], &mut crdt_model::wire::Ctx::new(1 << 40, own.clone(), 1));
    let MSource::Session(b) = own else { unreachable!() };
    let cx = DeltaCtx { ts: Ts::from_u64(1 << 40).unwrap(), own: osis_crdt::Source::session(osis_crdt::Session::from_bytes(&b)), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
    osis_crdt::decode_snapshot(&bytes, &cx, &mut Interner::new(), None).ok().map(|s| s.fragment)
}

/// Seed `k`'s forged history (crdt-model's generators, notes/crdt.md Tests): writers 0 and 1
/// sharing a source and clock (copies of one write differing in payload, one dot under two
/// stamps) on a random type, or hostile single-record text and list writes.
fn forged_history(k: u64) -> Vec<MFrag> {
    let mut r = Rng(2 * k + 1);
    match k % 3 {
        0 => {
            let types = [vec![kitchen_sink()], vec![Ty::Set(Box::new(Ty::Register))], vec![Ty::Text], vec![Ty::List(Box::new(Ty::Register))], vec![Ty::Register, Ty::Text, Ty::Counter, Ty::Set(Box::new(Ty::Register))]];
            let ty = types[r.below(types.len())].clone();
            let srcs = vec![MSource::session(1, 0), MSource::session(1, 0), MSource::session(2, 0)];
            let rounds = 3 + r.below(3);
            crdt_model::r#gen::history(&mut r, &ty, srcs, rounds, false, false, true).into_iter().map(|c| c.delta).collect()
        }
        n => {
            let slots = n == 1 && r.chance(1, 2);
            crdt_model::r#gen::hostile(&mut r, n == 2, slots)
        }
    }
}

/// Seed `k`: writer 1 forges each delta of `forged_history(k)` as a snapshot; peer 0 receives them
/// as made, peer 2 in reverse. No peer fails at any step, and all end reading alike. How many
/// it forged.
fn forged_copies_case(k: u64) -> usize {
    let (mut lp, t) = world();
    let mut made = Vec::new();
    for d in forged_history(k).iter().filter_map(carried) {
        made.extend(forge(&mut lp, t, d));
        lp.advance(10);
    }
    for c in &made {
        deliver(&mut lp, 0, c);
    }
    for c in made.iter().rev() {
        deliver(&mut lp, 2, c);
    }
    settle_alike(&mut lp, t);
    made.len()
}

fn replay(k: u64) -> String {
    format!("OSIS_FORGED_START={k} OSIS_FORGED_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact retention::tests_forged::forged_copies_fail_no_node_large")
}

/// Hostile input never produces a local error, the default sample: one seed of each kind.
#[test]
fn forged_copies_fail_no_node() {
    let made = osis_base::testenv::run_seeds("retention::tests_forged::forged_copies_fail_no_node", &[0, 1, 2], false, replay, forged_copies_case);
    assert!(made.iter().all(|n| *n > 0), "every kind forges: {made:?}");
}

/// `forged_copies_fail_no_node` at size: 300 seeds (`OSIS_FULL=1`), a tenth by default;
/// `OSIS_FORGED_START`/`OSIS_FORGED_SEEDS` pick them.
#[test]
#[ignore]
fn forged_copies_fail_no_node_large() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_FORGED_START", "OSIS_FORGED_SEEDS", osis_base::testenv::large(0..300));
    let made: usize = s.run("retention::tests_forged::forged_copies_fail_no_node_large", replay, forged_copies_case).into_iter().sum();
    assert!(made > 0, "forged nothing");
}
