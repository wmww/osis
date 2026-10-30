//! Join laws across encodings (spec/crdt.md §4.1, §7) and size/time budgets (tier 2).

use crate::fragment::Fragment;
use crate::testutil::{mapply, ostate, sink_no_seq};
use crdt_model::r#gen::random_op;
use crdt_model::ops::{Ty, Writer as MWriter};
use crdt_model::stamp::Source as MSource;
use proptest::prelude::*;

fn join(a: &Fragment, b: &Fragment) -> Fragment {
    let mut x = a.clone();
    x.join(b.clone());
    x
}

/// Three states, writer `i` using `types[i % len]` at the root.
fn states(seed: u64, types: &[Ty]) -> Vec<Fragment> {
    let mut r = crate::testutil::rng(seed | 1);
    (0..3u8)
        .map(|i| {
            let ty = &types[usize::from(i) % types.len()];
            let mut w = MWriter::new(MSource::node(i + 1), ((r.below(5) as u64 + 1) << 16) + u64::from(i), 1);
            let mut st = None;
            for k in 0..4 {
                w.next_commit(w.ts + ((r.below(3) as u64) << 16) + 1 + k);
                if let Some(d) = random_op(&mut r, &mut w, ty, st.as_ref()) {
                    mapply(&mut st, d);
                }
            }
            ostate(&st)
        })
        .collect()
}

fn laws(s: &[Fragment]) {
    let (a, b, c) = (&s[0], &s[1], &s[2]);
    assert_eq!(join(a, b), join(b, a), "commutative");
    assert_eq!(join(&join(a, b), c), join(a, &join(b, c)), "associative");
    assert_eq!(join(&join(a, c), b), join(&join(c, b), a), "any order");
    assert_eq!(join(a, a), a.clone(), "idempotent");
    assert_eq!(join(&join(a, b), b), join(a, b), "absorbing");
    assert!(!join(a, a).is_empty() || a.is_empty());
    // §4.3: the short-circuit presence equals the presence stamp's
    for x in [a, b, c, &join(a, b)] {
        assert_eq!(x.present(), x.written().is_some(), "present");
    }
}

/// Three states whose writers 0 and 1 share one source and one clock but choose their ops
/// apart, so their writes are copies of one write (equal stamps) with differing payloads, as a
/// forged snapshot carries (spec/permissions.md §5.2). Model states too.
fn forged_states(seed: u64, types: &[Ty]) -> (Vec<Fragment>, Vec<Option<crdt_model::state::Frag>>) {
    let mut r = crate::testutil::rng(seed | 1);
    let base = (r.below(5) as u64 + 1) << 16;
    let steps: Vec<u64> = (0..4).map(|k| ((r.below(3) as u64) << 16) + 1 + k).collect();
    let ms: Vec<_> = (0..3u8)
        .map(|i| {
            let ty = &types[usize::from(i) % types.len()];
            let mut ro = crate::testutil::rng(seed.wrapping_add(u64::from(i) + 7));
            let (src, t0) = if i < 2 { (1, base) } else { (2, base + 2) };
            let mut w = MWriter::new(MSource::node(src), t0, 1);
            let mut st = None;
            for k in &steps {
                w.next_commit(w.ts + k);
                if let Some(d) = random_op(&mut ro, &mut w, ty, st.as_ref()) {
                    mapply(&mut st, d);
                }
            }
            st
        })
        .collect();
    (ms.iter().map(ostate).collect(), ms)
}

/// §4.1 copy order: copies of one write with differing payloads join alike in every order, and
/// as the model joins them.
fn forged_laws(seed: u64, types: &[Ty]) {
    let (s, ms) = forged_states(seed, types);
    laws(&s);
    for (i, j) in [(0, 1), (1, 0), (0, 2)] {
        let mut m = ms[i].clone();
        if let Some(x) = ms[j].clone() {
            mapply(&mut m, x);
        }
        assert_eq!(join(&s[i], &s[j]), ostate(&m), "model join {i} {j}");
        assert_eq!(join(&s[i], &s[j]).read(), m.as_ref().and_then(|x| x.read()).map(|v| crate::testutil::value(&v)), "model read {i} {j}");
        // a placement cached before the join follows it as a fresh one reads (`drop_caches` is
        // debug-only)
        #[cfg(debug_assertions)]
        {
            let mut x = s[i].clone();
            let _ = x.read();
            x.join(s[j].clone());
            let mut y = x.clone();
            y.drop_caches();
            assert_eq!(x.read(), y.read(), "cached read {i} {j}");
        }
    }
}

proptest! {
    /// §4.1 copy order, every encoding, sequences included.
    #[test]
    fn forged_copies_join_alike_spec_4_1(seed in any::<u64>()) {
        let list = Ty::List(Box::new(Ty::Register));
        let mut r = crate::testutil::rng(seed);
        let all = [Ty::Text, list, sink_no_seq()];
        let ty = all[r.below(all.len())].clone();
        forged_laws(seed, &[ty]);
    }

    /// §4.1 copy order across encodings at one position (§7: a text slot holds the register's
    /// embedding, and only the winning copy's).
    #[test]
    fn forged_copies_across_encodings_spec_7(seed in any::<u64>()) {
        let set = Ty::Set(Box::new(Ty::Register));
        let mut r = crate::testutil::rng(seed);
        let all = [Ty::Register, Ty::Text, Ty::Counter, set, sink_no_seq()];
        let pick: Vec<Ty> = (0..3).map(|_| all[r.below(all.len())].clone()).collect();
        forged_laws(seed, &pick);
    }

    /// §4.1: within the non-sequence encodings, nested.
    #[test]
    fn join_laws_spec_4_1(seed in any::<u64>()) {
        laws(&states(seed, &[sink_no_seq()]));
    }

    /// §7: across encodings at one position (slots and embeddings).
    #[test]
    fn join_laws_across_encodings_spec_7(seed in any::<u64>()) {
        let set = Ty::Set(Box::new(Ty::Register));
        let map = Ty::Map(Box::new(Ty::Register), Box::new(Ty::Register));
        let mut r = crate::testutil::rng(seed);
        let all = [Ty::Register, Ty::Counter, Ty::Max, Ty::Min, set, map, sink_no_seq()];
        let pick: Vec<Ty> = (0..3).map(|_| all[r.below(all.len())].clone()).collect();
        laws(&states(seed, &pick));
    }
}

/// Tier 2: a 10^5-entry map delta joins, reads and encodes; a small
/// delta into the big state costs only what it touches.
#[test]
#[ignore]
fn budget_big_map_spec_4_1() {
    use crate::codec::{decode_delta, encode_delta};
    use crate::page::MemoryPages;
    use crate::stamp::{Interner, Source};
    use crate::wire::{Delta, DeltaCtx, DeltaKind};
    use osis_base::{Tid, Ts, Value};
    use std::time::Instant;
    let node = Source::node(Tid::from_bytes([1; 15]));
    let ts = |t: u64| Ts::from_u64(t << 16).unwrap_or_default();
    let kv: std::collections::BTreeMap<Value, Value> = (0..100_000i64).map(|i| (Value::Int(i), Value::Int(i * 2))).collect();
    let mut w = crate::Writer::new(ts(1), node.clone(), 1);
    let t = Instant::now();
    let d = crate::create(&mut w, &crate::AnyView, &Value::Map(kv)).unwrap();
    let create = t.elapsed();
    let t = Instant::now();
    let mut st = Fragment::default();
    st.join(d.clone());
    let join_big = t.elapsed();
    let t = Instant::now();
    let r = st.read();
    let read = t.elapsed();
    assert!(r.is_some());
    let cx = DeltaCtx { ts: ts(1), own: node.clone(), range: w.range(), kind: DeltaKind::Writer };
    let mut pages = MemoryPages::new();
    let t = Instant::now();
    let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: d }, &cx, Some(&mut pages)).unwrap();
    let encode = t.elapsed();
    let t = Instant::now();
    decode_delta(&bytes, &cx, &mut Interner::new(), Some(&mut pages)).unwrap();
    let decode = t.elapsed();
    // a one-entry delta into the big state
    let mut w2 = crate::Writer::new(ts(2), Source::node(Tid::from_bytes([2; 15])), 1);
    let small = crate::create(&mut w2, &crate::AnyView, &Value::Map([(Value::Int(-1), Value::Int(0))].into_iter().collect())).unwrap();
    let t = Instant::now();
    for _ in 0..1000 {
        st.join(small.clone());
    }
    let join_small = t.elapsed() / 1000;
    eprintln!("10^5 map: create {create:?}, join {join_big:?}, read {read:?}, encode {encode:?} ({} pages), decode {decode:?}, small join {join_small:?}", pages.len());
    assert!(join_small.as_micros() < 200, "small join is not O(state): {join_small:?}");
}

/// A cached placement follows a join whose forged copy of an element's chosen position write
/// names another anchor (the old write is gone, so the element's row, until re-placed, sits by a
/// key its record no longer holds; a gate-found seed).
#[test]
fn forged_edge_copy_cached_placement() {
    let (s, _) = forged_states(17419099531132830180, &[Ty::Text]);
    let mut x = s[0].clone();
    let _ = x.read();
    x.join(s[1].clone());
    crate::testutil::check_lin(&x);
    forged_laws(17419099531132830180, &[Ty::Text]);
}

