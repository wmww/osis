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

/// Writer 1 forges two snapshots carrying copies `a` and `b` of one write (one stamp, other
/// payloads); peer 0 receives them in that order, peer 2 reversed: no node fails, all read alike
/// (the forger's own applies included). What every node reads.
fn forged_pair(a: &MFrag, b: &MFrag) -> Option<Value> {
    let (mut lp, t) = world();
    let (fa, fb) = (carried(a).expect("a has a wire form"), carried(b).expect("b has a wire form"));
    let ca = forge(&mut lp, t, fa).expect("the forger makes a");
    lp.advance(10);
    let cb = forge(&mut lp, t, fb).expect("the forger makes b");
    for c in [&ca, &cb] {
        deliver(&mut lp, 0, c);
    }
    for c in [&cb, &ca] {
        deliver(&mut lp, 2, c);
    }
    settle_alike(&mut lp, t);
    lp.peers[2].engine.get(&t, &ak()).unwrap()
}

/// Model stamp `(t, (session 1, ctr))`, and its dot.
fn mstamp(t: u64, ctr: u64) -> crdt_model::stamp::Stamp {
    crdt_model::stamp::Stamp { ts: t << 16, dot: mdot(ctr) }
}

fn mdot(ctr: u64) -> crdt_model::stamp::Dot {
    crdt_model::stamp::Dot { source: MSource::session(1, 0), ctr }
}

// spec/crdt.md §4.1, §4.8, §5.5: copies of one value removal naming other references (and parts):
// one write, whichever wins; the element the losing copy hid shows again, the one the winning
// copy hides dies at the removal. Fails with a removal keyed by its reference and parts.
#[test]
fn forged_copies_of_a_value_removal_fail_no_node_spec_crdt_5_5() {
    use crdt_model::state::{Composite, Elem as MElem, Removal};
    use crdt_model::value::Value as MValue;
    let (wa, wb) = (MValue::Weak([1; 15]), MValue::Weak([2; 15]));
    let elem = |ctr: u64, v: &MValue| (mdot(ctr), MElem { reset: None, frag: Some(Box::new(MFrag::Register { reset: None, write: Some((mstamp(5, ctr), Some(v.clone()))) })), gone: None });
    let removal = |v: &MValue| (mdot(9), MElem { reset: None, frag: None, gone: Some(Removal { stamp: mstamp(8, 9), value: v.clone(), seen: vec![(mdot(1), 3)] }) });
    let set = |elems: Vec<(crdt_model::stamp::Dot, MElem)>| MFrag::Set { c: Composite::default(), elems: elems.into_iter().collect() };
    let a = set(vec![elem(1, &wa), elem(2, &wb), removal(&wa)]);
    let b = set(vec![removal(&wb)]);
    // the copy naming B wins (the greater reference): B hidden, A shows again
    assert_eq!(forged_pair(&a, &b), Some(Value::Set([Value::Weak(Tid::from_bytes([1; 15]))].into_iter().collect())));
}

// spec/crdt.md §4.1, §5.1, §7: copies of one stamp, a register write and a text's reset at the
// aspect root (another encoding): the write implies the reset, so nothing dies. Fails without
// a register write standing for the reset of its stamp.
#[test]
fn a_forged_reset_copy_of_a_register_write_fails_no_node_spec_crdt_5_1() {
    use crdt_model::state::Composite;
    let write = MFrag::Register { reset: None, write: Some((mstamp(5, 3), Some(crdt_model::value::Value::Int(2)))) };
    let reset = MFrag::Seq { text: true, c: Composite { reset: Some(mstamp(5, 3)), w: None, w_valueless: false }, elems: Default::default() };
    assert_eq!(forged_pair(&write, &reset), Some(Value::Int(2)));
}

// spec/crdt.md §4.1, §4.8 When, §5.7: an undelete and a forged delete copy of its flag write (one
// stamp): the delete wins the tie, so the element's creation dies at that stamp. Fails with a
// creation dying only by a delete stamped after the latest undelete.
#[test]
fn a_forged_delete_copy_of_an_undelete_fails_no_node_spec_crdt_4_8() {
    use crdt_model::state::{Anchor as MAnchor, Composite, Content, SeqElem as MSeqElem};
    let text = |e: MSeqElem| MFrag::Seq { text: true, c: Composite::default(), elems: [(mdot(1), e)].into_iter().collect() };
    let mut undeleted = MSeqElem::new(mstamp(4, 1), MAnchor::Head, Content::Char('d'));
    undeleted.deleted = Some((mstamp(25, 7), false));
    undeleted.undel = Some('d');
    let deleted = MSeqElem::flag(mstamp(25, 7), true, None);
    assert_eq!(forged_pair(&text(undeleted), &text(deleted)), Some(Value::Str(String::new())));
}

// spec/crdt.md §4.8 Which write, §7: a register write "ab" (t5) and a position write and a delete
// forged at its own stamp on its second embedded char, each a snapshot of writer 1: the char's
// creation `(t5, Derived, 2)` beats each, though no body holds the char (the register's is a plain
// register), so each forged body is replaced at t5, at every peer in either arrival order, and
// no tick fails. Fails with a register write's embedding read only from bodies holding a text slot.
#[test]
fn a_write_forged_on_an_embedded_char_dies_by_the_register_write_spec_crdt_7() {
    use crdt_model::state::{Anchor as MAnchor, Composite, Content, SeqElem as MSeqElem};
    let s = mstamp(5, 3);
    let reg = MFrag::Register { reset: None, write: Some((s.clone(), Some(crdt_model::value::Value::Str("ab".into())))) };
    let second = crdt_model::stamp::Dot { source: MSource::Derived(Box::new(mdot(3))), ctr: 2 };
    let text = |e: MSeqElem| MFrag::Seq { text: true, c: Composite::default(), elems: [(second.clone(), e)].into_iter().collect() };
    for forged in [text(MSeqElem::write(Content::None, vec![(s.clone(), MAnchor::Head, None)], None)), text(MSeqElem::flag(s.clone(), true, None))] {
        let (mut lp, t) = world();
        let cf = forge(&mut lp, t, carried(&forged).expect("a wire form")).expect("the forger makes it");
        lp.advance(10);
        let cr = forge(&mut lp, t, carried(&reg).expect("a wire form")).expect("the forger makes it");
        for (p, order) in [(0, [&cf, &cr]), (2, [&cr, &cf])] {
            order.into_iter().for_each(|c| deliver(&mut lp, p, c));
        }
        for p in 0..3 {
            assert_eq!(lp.peers[p].engine.replaced_at(&cf, &t, &ak()).unwrap(), Some(Ts::from_u64(s.ts).unwrap()), "peer {p}: {forged:?}");
        }
        settle_alike(&mut lp, t);
    }
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

/// Hostile input never produces a local error, the quick sample (a property): one seed of each kind.
#[test]
#[ignore = "property"]
fn forged_copies_fail_no_node_plain() {
    let made = osis_base::testenv::run_seeds("retention::tests_forged::forged_copies_fail_no_node_plain", &[0, 1, 2], false, replay, forged_copies_case);
    assert!(made.iter().all(|n| *n > 0), "every kind forges: {made:?}");
}

/// `forged_copies_fail_no_node_plain` at size: 300 seeds (`OSIS_FULL=1`), a tenth by default;
/// `OSIS_FORGED_START`/`OSIS_FORGED_SEEDS` pick them.
#[test]
#[ignore]
fn forged_copies_fail_no_node_large() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_FORGED_START", "OSIS_FORGED_SEEDS", osis_base::testenv::large(0..300));
    let made: usize = s.run("retention::tests_forged::forged_copies_fail_no_node_large", replay, forged_copies_case).into_iter().sum();
    assert!(made > 0, "forged nothing");
}

// spec/crdt.md §4.8 When, §5.5, spec/commits.md §5 (nodes holding the same bodies judge alike;
// one holding more judges no later): a value removal hiding a set element's write (t3, removal t15) dates its
// death, though a later reset of the element (t29) prunes the write from the state: in each of the
// six arrival orders, at each step holding the write, peers 0 and 2 date it by the held set alone:
// t15 holding the removal, t29 holding the reset alone, not replaced holding neither. Fails with
// the removals hiding a write read from the state as joined (a pruned write hidden by none).
#[test]
fn a_removal_dates_a_write_a_later_reset_prunes_spec_crdt_4_8() {
    use crdt_model::state::{Composite, Elem as MElem, Removal};
    let strong = crdt_model::value::Value::Strong([2; 15]);
    let set = |e: MElem| MFrag::Set { c: Composite::default(), elems: [(if e.gone.is_some() { mdot(7) } else { mdot(1) }, e)].into_iter().collect() };
    let w = set(MElem { reset: None, frag: Some(Box::new(MFrag::Register { reset: None, write: Some((mstamp(3, 1), Some(strong.clone()))) })), gone: None });
    let r = set(MElem { reset: None, frag: None, gone: Some(Removal { stamp: mstamp(15, 7), value: strong, seen: vec![(mdot(1), 3)] }) });
    let x = set(MElem { reset: Some(mstamp(29, 9)), frag: None, gone: None });
    let (mut lp, t) = world();
    let made: Vec<CommitId> = [w, r, x].iter().map(|f| {
        let c = forge(&mut lp, t, carried(f).expect("a wire form")).expect("the forger makes it");
        lp.advance(10);
        c
    }).collect();
    let at = |s: u64| Some(Ts::from_u64(mstamp(s, 0).ts).unwrap());
    for order in [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        let mut lp = lp.copy().unwrap();
        let mut held = [false; 3];
        for i in order {
            held[i] = true;
            for p in [0, 2] {
                deliver(&mut lp, p, &made[i]);
                if held[0] {
                    let want = if held[1] { at(15) } else if held[2] { at(29) } else { None };
                    assert_eq!(lp.peers[p].engine.replaced_at(&made[0], &t, &ak()).unwrap(), want, "peer {p}, order {order:?}, holding {held:?}");
                }
            }
        }
    }
}

// spec/commits.md §5, spec/crdt.md §4.8 When: a node holding a set element's write (W) gets one
// body holding a value removal hiding it (an hour after W) and a reset of the element (three
// hours after W) that prunes it in the join: the kill's row (when leaving is told) is due a day
// (the kept period) after the removal, never after the reset. Fails with the payloads of the
// apply not noted from the state before the join (the pruned write's value not read).
#[test]
fn a_kill_by_a_removal_and_a_reset_in_one_body_is_told_at_the_removal_spec_commits_5() {
    use crdt_model::state::{Composite, Elem as MElem, Removal};
    const HOUR: u64 = 3_600_000;
    let strong = crdt_model::value::Value::Strong([2; 15]);
    let (mut lp, t) = world();
    let base = osis_base::Clock::now_wall_ms(&*lp.peers[0].clock).0 - 10 * HOUR;
    let set = |es: Vec<(u64, MElem)>| MFrag::Set { c: Composite::default(), elems: es.into_iter().map(|(c, e)| (mdot(c), e)).collect() };
    let w = set(vec![(1, MElem { reset: None, frag: Some(Box::new(MFrag::Register { reset: None, write: Some((mstamp(base, 1), Some(strong.clone()))) })), gone: None })]);
    let rx = set(vec![
        (1, MElem { reset: Some(mstamp(base + 3 * HOUR, 9)), frag: None, gone: None }),
        (7, MElem { reset: None, frag: None, gone: Some(Removal { stamp: mstamp(base + HOUR, 7), value: strong, seen: vec![(mdot(1), 3)] }) }),
    ]);
    let cw = forge(&mut lp, t, carried(&w).expect("a wire form")).expect("the forger makes it");
    let crx = forge(&mut lp, t, carried(&rx).expect("a wire form")).expect("the forger makes it");
    deliver(&mut lp, 2, &cw);
    lp.peers[2].engine.listen_commits(std::sync::Arc::new(move |x: &Tid| *x == t));
    deliver(&mut lp, 2, &crx);
    lp.peers[2].drain_events();
    assert_eq!(lp.peers[2].engine.replaced_at(&cw, &t, &ak()).unwrap(), Some(Ts::from_u64(mstamp(base + HOUR, 0).ts).unwrap()));
    // a minute past a day after the removal
    lp.advance(base + HOUR + 86_400_000 + 60_000 - osis_base::Clock::now_wall_ms(&*lp.peers[0].clock).0);
    lp.peers[2].tick().unwrap();
    let told = lp.peers[2].drain_events().into_iter().any(|e| matches!(e, crate::Event::Commits(ch) if ch.iter().any(|x| x.id == cw)));
    assert!(told, "W's body is told leaving a day after the removal");
}
