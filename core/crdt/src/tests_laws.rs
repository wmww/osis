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
            let mut w = MWriter::new(MSource::session(i + 1, 0), ((r.below(5) as u64 + 1) << 16) + u64::from(i), 1);
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

/// `honest`: no copies of one write differ.
fn laws(s: &[Fragment], honest: bool) {
    let (a, b, c) = (&s[0], &s[1], &s[2]);
    assert_eq!(join(a, b), join(b, a), "commutative");
    assert_eq!(join(&join(a, b), c), join(a, &join(b, c)), "associative");
    assert_eq!(join(&join(a, c), b), join(&join(c, b), a), "any order");
    assert_eq!(join(a, a), a.clone(), "idempotent");
    assert_eq!(join(&join(a, b), b), join(a, b), "absorbing");
    assert!(!join(a, a).is_empty() || a.is_empty());
    // `contains` (judged on a piece at the other's positions): sound, and true for what a join
    // took in
    let ab = join(a, b);
    for x in [a, b, c, &ab] {
        for y in [a, b, c, &ab] {
            // its soundness rests on this: the piece is below the whole
            assert_eq!(&join(x, &x.part_at(y)), x, "a piece joins in unchanged");
            if x.contains(y) {
                assert_eq!(&join(x, y), x, "contains only what joins in unchanged");
            }
            // covering copies (spec/commits.md §5): an honest holder of `y`'s writes holds them
            // with `y`'s payloads, so stripping them from its piece and joining `y` back gives
            // the piece again
            if honest && &join(x, y) == x {
                let mut vl = std::collections::BTreeSet::new();
                y.valueless_dots(&mut vl);
                let ix = y.copy_index();
                let mut p = x.part_at(y);
                p.remove_writes(&|d| ix.holds(d) && !vl.contains(d));
                p.join(y.clone());
                assert_eq!(p, x.part_at(y), "an honest holder's copies are the body's");
            }
            // a sequence joins record by record, so its piece decides exactly
            if matches!(x, Fragment::Seq(_)) {
                assert_eq!(x.contains(y), &join(x, y) == x, "a sequence's piece judges as the whole");
            }
        }
        assert!(ab.contains(x) || x == c, "a join contains its parts");
    }
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
            let mut w = MWriter::new(MSource::session(src, 0), t0, 1);
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
    laws(&s, false);
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
        laws(&states(seed, &[sink_no_seq()]), true);
    }

    /// §5.6: maps of texts and lists, and their forged copies.
    #[test]
    fn join_laws_map_of_text_spec_5_6(seed in any::<u64>()) {
        let types = crate::tests_seq::map_of_text();
        laws(&states(seed, &types), true);
        forged_laws(seed, &types);
    }

    /// §7: across encodings at one position (slots and embeddings).
    #[test]
    fn join_laws_across_encodings_spec_7(seed in any::<u64>()) {
        let set = Ty::Set(Box::new(Ty::Register));
        let map = Ty::Map(Box::new(Ty::Register), Box::new(Ty::Register));
        let mut r = crate::testutil::rng(seed);
        let all = [Ty::Register, Ty::Counter, Ty::Max, Ty::Min, set, map, sink_no_seq()];
        let pick: Vec<Ty> = (0..3).map(|_| all[r.below(all.len())].clone()).collect();
        laws(&states(seed, &pick), true);
    }
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
