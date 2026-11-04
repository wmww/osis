//! Differential tests of join, prune, presence and read against core/test/crdt-model (spec/crdt.md §4,
//! §5.1–§5.6, §7).

use crate::fragment::Fragment;
use crate::testutil::{frag, history, mapply, ostate, sess, sink_no_seq, value};
use crdt_model::ops::Ty;
use proptest::prelude::*;

/// Delivers the history in a random order with duplicates to the model and to the
/// implementation in lockstep; states and reads must agree after every join.
pub(crate) fn lockstep(seed: u64, types: &[Ty], n: usize, rounds: usize) {
    let mut r = crate::testutil::rng(seed | 1);
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
                crate::testutil::check_lin(&ours);
                assert_eq!(ours, ostate(&model), "state after joining commit {k}");
                assert_eq!(ours.read(), model.as_ref().and_then(|m| m.read()).map(|v| value(&v)), "read after commit {k}");
            }
        }
        assert_eq!(ours, ostate(&reference), "converged to the reference");
    }
}

/// A register holding a write or reset past a delta's `ts` keeps it (§5.1, §7): what lets a
/// rebuild stop at the winner, in any encoding the position has seen (`Fragment::settled_above`).
fn settled(seed: u64, types: &[Ty]) {
    use crate::fragment::{RegWrite, Register};
    use crate::stamp::Stamp;
    let mut r = crate::testutil::rng(seed | 1);
    let commits = history(&mut r, types, 3, 6);
    // the same joins do change a register below them, and nothing else is settled
    let low = Fragment::Register(Register { reset: Some(Stamp::new(crate::testutil::ts(0), sess(osis_base::Tid::from_bytes([7; 15])), 1)), write: None });
    assert!(commits.iter().any(|c| {
        let mut j = low.clone();
        j.join(frag(&c.delta));
        j != low
    }));
    assert!(commits.iter().all(|c| matches!(frag(&c.delta), Fragment::Register(_)) || !frag(&c.delta).settled_above(crate::testutil::ts(1 << 45))));
    assert!(!Fragment::default().settled_above(crate::testutil::ts(0)));
    let top = osis_base::Tid::from_bytes([7; 15]);
    let stamp = Stamp::new(crate::testutil::ts(1 << 45), sess(top), 1);
    for st in [Register { reset: None, write: Some(RegWrite { stamp: stamp.clone(), value: Some(osis_base::Value::Int(1)) }) }, Register { reset: Some(stamp.clone()), write: None }] {
        let st = Fragment::Register(st);
        assert!(st.settled_above(crate::testutil::ts((1 << 45) - 1)));
        assert!(!st.settled_above(crate::testutil::ts(1 << 45)));
        for c in &commits {
            let mut j = st.clone();
            j.join(frag(&c.delta));
            assert_eq!(j, st, "{:?}", c.delta);
        }
    }
}

proptest! {
    #[test]
    fn settled_register_keeps_above_any_encoding_spec_7(seed in any::<u64>()) {
        let set = Ty::Set(Box::new(Ty::Register));
        let map = Ty::Map(Box::new(Ty::Register), Box::new(Ty::Register));
        let list = Ty::List(Box::new(Ty::Register));
        settled(seed, &[Ty::Register, Ty::Counter, Ty::Max, Ty::Min, Ty::Text, list, set, map, sink_no_seq()]);
    }

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
/// of order (slots are pruned like any fragment and dropped once below the register's
/// embedding; a register's reset below its write goes).
fn model_order_independent(seeds: u64) {
    let a = Ty::Struct([(1, Ty::Register), (2, Ty::Counter)].into_iter().collect());
    let b = Ty::Struct([(1, Ty::Max), (2, Ty::Set(Box::new(Ty::Register)))].into_iter().collect());
    let set = Ty::Set(Box::new(Ty::Register));
    let map = Ty::Map(Box::new(Ty::Register), Box::new(Ty::Register));
    let mixes = [vec![a, b], vec![Ty::Register, Ty::Counter, set, Ty::Max, map, Ty::Min], vec![sink_no_seq(), Ty::Register, Ty::Counter]];
    for (mi, types) in mixes.iter().enumerate() {
        for seed in (1..seeds).step_by(2) {
            let mut r = crate::testutil::rng(seed);
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
    use crate::stamp::Stamp;
    use osis_base::{Tid, Ts, Value};
    let n = sess(Tid::from_bytes([1; 15]));
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

// ---- reads per encoding, built directly (§4.3, §5.2-§5.4)

mod direct {
    use crate::fragment::{Bag, BagKind, CaseWrite, Elem, Enum, Fragment, Meta, RegWrite, Register, Set, Struct};
    use crate::stamp::{Dot, Source, Stamp};
    use crate::testutil::{sess, ts};
    use osis_base::{Tid, Value};
    use std::collections::BTreeMap;

    fn src(n: u8) -> Source {
        let mut b = [0u8; 15];
        b[14] = n;
        sess(Tid::from_bytes(b))
    }
    /// Session 1's write at ts `t`·2^16, counter `c`.
    fn st(t: u64, c: u64) -> Stamp {
        Stamp::new(ts(t << 16), src(1), c)
    }
    fn reg(s: Stamp, v: Value) -> Fragment {
        Fragment::Register(Register { reset: None, write: Some(RegWrite { stamp: s, value: Some(v) }) })
    }
    /// A bag of `kind` with contributions `vs`, element `i` node 1's dot `i + 1`.
    fn bag(kind: BagKind, vs: &[Value]) -> Fragment {
        let elems = vs.iter().enumerate().map(|(k, v)| (Dot::new(src(1), k as u64 + 1), Elem { reset: None, frag: Some(Box::new(reg(st(1, k as u64 + 1), v.clone()))) })).collect();
        Fragment::Bag(Bag { kind, meta: Meta::default(), elems })
    }
    fn f(x: f64) -> Value {
        Value::float(x)
    }
    fn bits(v: Option<Value>) -> Option<Vec<u8>> {
        v.map(|v| osis_base::encode(&v))
    }

    /// §5.2: a float counter sums in dot order, so 1e16 + 1 - 1e16 reads 0 (the 1 is lost),
    /// whatever order the contributions arrived in; ints sum exactly, clamped to i64; a bag holding
    /// both reads as the float sum plus the int sum.
    #[test]
    fn counter_sums_in_dot_order_spec_5_2() {
        let vs = [f(1e16), f(1.0), f(-1e16)];
        let whole = bag(BagKind::Counter, &vs);
        assert_eq!(bits(whole.read()), bits(Some(f(0.0))));
        let Fragment::Bag(b) = &whole else { panic!("bag") };
        for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0]] {
            let mut s = Fragment::default();
            for k in order {
                let (d, e) = b.elems.iter().nth(k).unwrap();
                s.join(Fragment::Bag(Bag { kind: BagKind::Counter, meta: Meta::default(), elems: BTreeMap::from([(d.clone(), e.clone())]) }));
            }
            assert_eq!(bits(s.read()), bits(Some(f(0.0))), "joined in order {order:?}");
        }
        assert_eq!(bag(BagKind::Counter, &[Value::Int(i64::MAX), Value::Int(1)]).read(), Some(Value::Int(i64::MAX)));
        assert_eq!(bag(BagKind::Counter, &[Value::Int(i64::MIN), Value::Int(-1), Value::Int(5)]).read(), Some(Value::Int(i64::MIN + 4)));
        assert_eq!(bits(bag(BagKind::Counter, &[f(0.5), Value::Int(2), Value::Int(3)]).read()), bits(Some(f(5.5))));
        // non-numbers (only from §7 embeddings) are ignored
        assert_eq!(bag(BagKind::Counter, &[Value::Int(2), Value::Str("x".into())]).read(), Some(Value::Int(2)));
    }

    /// §5.2: max and min compare ints by value and anything involving a float by IEEE totalOrder
    /// (-0.0 < 0.0, NaN greatest); equal extremes give the lowest dot's contribution.
    #[test]
    fn max_min_total_order_spec_5_2() {
        let max = |vs: &[Value]| bits(bag(BagKind::Max, vs).read());
        let min = |vs: &[Value]| bits(bag(BagKind::Min, vs).read());
        assert_eq!(max(&[f(-0.0), f(0.0)]), bits(Some(f(0.0))));
        assert_eq!(min(&[f(0.0), f(-0.0)]), bits(Some(f(-0.0))));
        assert_eq!(max(&[f(1.0), f(f64::NAN), f(f64::INFINITY)]), bits(Some(f(f64::NAN))));
        assert_eq!(min(&[f(f64::NAN), f(1.0)]), bits(Some(f(1.0))));
        assert_eq!(max(&[Value::Int(3), f(2.5)]), bits(Some(Value::Int(3))));
        assert_eq!(min(&[Value::Int(3), f(2.5)]), bits(Some(f(2.5))));
        // 2 and 2.0 are equal extremes: the lowest dot's
        assert_eq!(max(&[Value::Int(2), f(2.0)]), bits(Some(Value::Int(2))));
        assert_eq!(max(&[f(2.0), Value::Int(2)]), bits(Some(f(2.0))));
        // ints beyond f64 precision compare exactly
        assert_eq!(max(&[Value::Int(i64::MAX), Value::Int(i64::MAX - 1)]), bits(Some(Value::Int(i64::MAX))));
        assert_eq!(bag(BagKind::Max, &[]).read(), None);
    }

    /// §4.3: an explicit `W` makes an empty set present; a set emptied by a removal stays present
    /// (the element reset is a write inside it); a reset with nothing after makes it absent; a
    /// value-less write does not count.
    #[test]
    fn presence_spec_4_3() {
        let set = |meta: Meta, elems: Vec<(Dot, Elem)>| Fragment::Set(Set { meta, elems: elems.into_iter().collect() });
        let empty = Value::Set(Default::default());
        assert_eq!(set(Meta { reset: None, w: Some(st(1, 1)) }, vec![]).read(), Some(empty.clone()));
        let mut s = set(Meta::default(), vec![(Dot::new(src(1), 1), Elem { reset: None, frag: Some(Box::new(reg(st(1, 1), Value::Int(4)))) })]);
        s.join(set(Meta::default(), vec![(Dot::new(src(1), 1), Elem::tomb(&st(2, 1)))]));
        assert_eq!(s.read(), Some(empty));
        s.join(set(Meta { reset: Some(st(3, 1)), w: None }, vec![]));
        assert_eq!(s.read(), None, "remove_aspect: absent");
        let valueless = Fragment::Register(Register { reset: None, write: Some(RegWrite { stamp: st(1, 1), value: None }) });
        assert_eq!(valueless.read(), None);
        let s = set(Meta::default(), vec![(Dot::new(src(1), 1), Elem { reset: None, frag: Some(Box::new(valueless)) })]);
        assert!(!s.present(), "a value-less creation is no presence");
    }

    /// §5.3: a struct reads every present field, unknown field IDs included; a replace (reset and
    /// content at one stamp) drops every older field; a replace by an empty struct is present.
    #[test]
    fn struct_fields_and_replace_spec_5_3() {
        let fields = |m: Meta, f: Vec<(u64, Fragment)>| Fragment::Struct(Struct { meta: m, fields: f.into_iter().collect() });
        let mut s = fields(Meta::default(), vec![(1, reg(st(1, 1), Value::Int(1))), (900, reg(st(1, 1), Value::Int(9)))]);
        assert_eq!(s.read(), Some(Value::Map([(Value::Int(1), Value::Int(1)), (Value::Int(900), Value::Int(9))].into_iter().collect())));
        s.join(fields(Meta { reset: Some(st(2, 1)), w: None }, vec![(2, reg(st(2, 1), Value::Int(2)))]));
        assert_eq!(s.read(), Some(Value::Map([(Value::Int(2), Value::Int(2))].into_iter().collect())));
        s.join(fields(Meta { reset: Some(st(3, 1)), w: Some(st(3, 1)) }, vec![]));
        assert_eq!(s.read(), Some(Value::Map(osis_base::ValueMap::new())));
    }

    /// §5.4: the case register picks the payload; a payload written for another case stays hidden
    /// (a newer edit of the old case's payload does not flip the value back); a case change drops
    /// every older payload write; no case write reads absent whatever payloads exist.
    #[test]
    fn enum_payloads_per_case_spec_5_4() {
        let en = |m: Meta, case: Option<(Stamp, u64)>, p: Vec<(u64, Fragment)>| Fragment::Enum(Enum { meta: m, case: case.map(|(stamp, c)| CaseWrite { stamp, case: Some(c) }), payloads: p.into_iter().collect() });
        let mut e = en(Meta::default(), Some((st(1, 1), 1)), vec![(1, reg(st(1, 1), Value::Int(10)))]);
        assert_eq!(e.read(), Some(Value::Enum(1, Some(Box::new(Value::Int(10))))));
        // case 2 at t3 (reset, case, payload); an edit of case 1's payload at t4
        e.join(en(Meta { reset: Some(st(3, 1)), w: None }, Some((st(3, 1), 2)), vec![(2, reg(st(3, 1), Value::Int(20)))]));
        e.join(en(Meta::default(), None, vec![(1, reg(st(4, 1), Value::Int(11)))]));
        assert_eq!(e.read(), Some(Value::Enum(2, Some(Box::new(Value::Int(20))))));
        // an older payload write of case 1 is pruned by the case change
        e.join(en(Meta::default(), None, vec![(1, reg(st(2, 1), Value::Int(12)))]));
        let Fragment::Enum(x) = &e else { panic!("enum") };
        assert_eq!(x.payloads.get(&1).and_then(Fragment::read), Some(Value::Int(11)));
        assert_eq!(en(Meta::default(), None, vec![(1, reg(st(1, 1), Value::Int(1)))]).read(), None);
        // a case without a payload fragment reads as the bare case
        assert_eq!(en(Meta::default(), Some((st(1, 1), 0)), vec![]).read(), Some(Value::Enum(0, None)));
    }
}
