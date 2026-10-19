//! Differential tests of join, prune, presence and read against models/crdt (spec/crdt.md §4,
//! §5.1–§5.6, §7).

use crate::fragment::Fragment;
use crate::testutil::{frag, history, mapply, ostate, sink_no_seq, value};
use crdt_model::r#gen::Rng;
use crdt_model::ops::Ty;
use proptest::prelude::*;

/// Delivers the history in a random order with duplicates to the model and to the
/// implementation in lockstep; states and reads must agree after every join.
fn lockstep(seed: u64, types: &[Ty], n: usize, rounds: usize) {
    let mut r = Rng(seed | 1);
    let commits = history(&mut r, types, n, rounds);
    let mut reference = None;
    for c in &commits {
        mapply(&mut reference, c.delta.clone());
    }
    for _ in 0..2 {
        let mut order: Vec<usize> = (0..commits.len()).collect();
        for k in (1..order.len()).rev() {
            order.swap(k, r.below(k + 1));
        }
        let mut model = None;
        let mut ours = Fragment::default();
        for k in order {
            let reps = if r.chance(1, 4) { 2 } else { 1 };
            for _ in 0..reps {
                let Some(c) = commits.get(k) else { continue };
                mapply(&mut model, c.delta.clone());
                ours.join(frag(&c.delta));
                assert_eq!(ours, ostate(&model), "state after joining commit {k}");
                assert_eq!(ours.read(), model.as_ref().and_then(|m| m.read()).map(|v| value(&v)), "read after commit {k}");
            }
        }
        assert_eq!(ours, ostate(&reference), "converged to the reference");
    }
}

proptest! {
    /// §4.1–§4.4, §5.1–§5.6: every non-sequence encoding, nested.
    #[test]
    fn join_matches_model_spec_4(seed in any::<u64>()) {
        lockstep(seed, &[sink_no_seq()], 3, 6);
    }

    /// §7: writers of different encodings at one position meet as slots with embeddings.
    #[test]
    fn slots_match_model_spec_7(seed in any::<u64>()) {
        let set = Ty::Set(Box::new(Ty::Register));
        let map = Ty::Map(Box::new(Ty::Register), Box::new(Ty::Register));
        lockstep(seed, &[Ty::Register, Ty::Counter, set, Ty::Max, map, Ty::Min], 6, 4);
    }

    /// §7 nested: slots below a struct field.
    #[test]
    fn nested_slots_match_model_spec_7(seed in any::<u64>()) {
        let a = Ty::Struct([(1, Ty::Register), (2, Ty::Counter)].into_iter().collect());
        let b = Ty::Struct([(1, Ty::Max), (2, Ty::Set(Box::new(Ty::Register)))].into_iter().collect());
        lockstep(seed, &[a, b], 3, 5);
    }
}

/// §4.1, §7: the reference model itself joins nested multi-encoding positions independently
/// of order (members are pruned like any fragment and dropped once below the register's
/// embedding; a register's reset below its write goes).
fn model_order_independent(seeds: u64) {
    let a = Ty::Struct([(1, Ty::Register), (2, Ty::Counter)].into_iter().collect());
    let b = Ty::Struct([(1, Ty::Max), (2, Ty::Set(Box::new(Ty::Register)))].into_iter().collect());
    let set = Ty::Set(Box::new(Ty::Register));
    let map = Ty::Map(Box::new(Ty::Register), Box::new(Ty::Register));
    let mixes = [vec![a, b], vec![Ty::Register, Ty::Counter, set, Ty::Max, map, Ty::Min], vec![sink_no_seq(), Ty::Register, Ty::Counter]];
    for (mi, types) in mixes.iter().enumerate() {
        for seed in 0..seeds {
            let mut r = Rng(seed | 1);
            let commits = history(&mut r, types, types.len().max(3), 5);
            let (mut s1, mut s2) = (None, None);
            for c in &commits {
                mapply(&mut s1, c.delta.clone());
            }
            for c in commits.iter().rev() {
                mapply(&mut s2, c.delta.clone());
            }
            assert!(s1 == s2, "mix {mi} seed {seed}: model order-dependent");
        }
    }
}

#[test]
fn model_order_independent_spec_7() {
    model_order_independent(60);
}

#[test]
#[ignore]
fn model_order_independent_spec_7_large() {
    model_order_independent(5000);
}

/// §4.8: the change summary names writes that died and when.
#[test]
fn deaths_reported_spec_4_8() {
    use crate::fragment::{RegWrite, Register, Struct};
    use crate::stamp::{Source, Stamp};
    use osis_core::{Tid, Ts, Value};
    let n = Source::node(Tid::from_bytes([1; 15]));
    let st = |t: u64, c: u64| Stamp::new(Ts::from_u64(t << 16).unwrap(), n.clone(), c);
    let reg = |s: Stamp, v: i64| Fragment::Register(Register { reset: None, write: Some(RegWrite { stamp: s, value: Some(Value::Int(v)) }) });
    let field = |s: Stamp, v: i64| Fragment::Struct(Struct { fields: [(1, reg(s, v))].into_iter().collect(), ..Default::default() });
    let mut state = field(st(1, 1), 1);
    let ch = state.join(field(st(2, 2), 2));
    assert!(ch.is_changed());
    assert_eq!(ch.deaths().len(), 1);
    assert_eq!(ch.deaths()[0].stamp, st(1, 1));
    assert_eq!(ch.deaths()[0].at, st(2, 2).ts);
    // a late older write dies on arrival and changes nothing visible
    let ch = state.join(field(st(1, 3), 3));
    assert_eq!(ch.deaths()[0].stamp, st(1, 3));
    // a reset prunes the field's write
    let mut reset = Struct::default();
    reset.meta.reset = Some(st(3, 4));
    let ch = state.join(Fragment::Struct(reset));
    assert!(ch.deaths().iter().any(|d| d.stamp == st(2, 2) && d.at == st(3, 4).ts));
    assert_eq!(state.read(), None);
}
