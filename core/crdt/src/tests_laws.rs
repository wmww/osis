//! Join laws on forged copies (spec/crdt.md §4.1, §7), where the model has no answer for `contains`
//! and `part_at`; on honest states they follow from `tests_model` (equality with a lawful model).

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

/// The join laws on states holding copies of one write with differing payloads, and what the
/// crdt answers there that the model has no counterpart for (`contains`, `part_at`).
fn laws(s: &[Fragment]) {
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
/// forged snapshot carries (spec/permissions.md §5.2).
fn forged_states(seed: u64, types: &[Ty]) -> Vec<Fragment> {
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
    ms.iter().map(ostate).collect()
}

/// §4.1 copy order: copies of one write with differing payloads join alike in every order (as the
/// model joins them: `tests_model`'s twins).
fn forged_laws(seed: u64, types: &[Ty]) {
    let s = forged_states(seed, types);
    laws(&s);
    for (i, j) in [(0, 1), (1, 0), (0, 2)] {
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

    /// §5.6: forged copies in maps of texts and lists.
    #[test]
    fn forged_copies_map_of_text_spec_5_6(seed in any::<u64>()) {
        forged_laws(seed, &crate::tests_seq::map_of_text());
    }
}

/// A cached placement follows a join whose forged copy of an element's chosen position write
/// names another anchor (the old write is gone, so the element's row, until re-placed, sits by a
/// key its record no longer holds; a gate-found seed).
#[test]
fn forged_edge_copy_cached_placement() {
    let s = forged_states(17419099531132830180, &[Ty::Text]);
    let mut x = s[0].clone();
    let _ = x.read();
    x.join(s[1].clone());
    crate::testutil::check_lin(&x);
    forged_laws(17419099531132830180, &[Ty::Text]);
}

/// Copies of one map entry (§5.6) under several keys, as forged snapshots carry them: random
/// records of one dot (`a`, `b`, `c` or key-erased), each holding a register, text element or
/// enum write of one stamp with differing payloads, `depth` maps deep (inner records of one dot
/// under their own keys). One encoding per level unless `slots` (§7: a position written as two
/// encodings).
mod entry_copies {
    use crate::fragment::Fragment;
    use crate::testutil::{frag, ostate, source};
    use crdt_model::r#gen::Rng;
    use crdt_model::stamp::{Dot, Source, Stamp};
    use crdt_model::state::{Anchor, Content, Entry, Frag, SeqElem};
    use crdt_model::value::Value;
    use std::collections::BTreeMap;

    fn st(src: u8, c: u64) -> Stamp {
        Stamp::new(1 << 16, Source::session(src, 0), c)
    }

    fn str(s: &str) -> Value {
        Value::Str(s.into())
    }

    /// A write at a leaf: `kind` 0 a register, 1 a text element, 2 an enum case; by writer 1 or 2.
    fn leaf(r: &mut Rng, kind: usize) -> Frag {
        let src = 1 + r.below(2) as u8;
        match kind {
            0 => Frag::Register { reset: None, write: Some((st(src, 5), [None, Some(str("x")), Some(str("y"))][r.below(3)].clone())) },
            1 => {
                let anchor = if r.chance(1, 2) { Anchor::Head } else { Anchor::Dot(Dot { source: Source::session(2, 0), ctr: 9 }) };
                let mut el = SeqElem::new(st(src, 15), anchor, [Content::None, Content::Char('x'), Content::Char('y')][r.below(3)].clone());
                if r.chance(1, 3) {
                    let del = r.chance(1, 2);
                    el.deleted = Some((st(2, 17), del));
                    el.undel = [None, Some('p'), Some('q')][r.below(3)].filter(|_| !del);
                }
                Frag::Seq { text: true, c: Default::default(), elems: BTreeMap::from([(Dot { source: Source::session(src, 0), ctr: 15 }, el)]) }
            }
            _ => {
                let payload = Frag::Register { reset: None, write: Some((st(2, 26), Some(Value::Int(r.below(2) as i64)))) };
                Frag::Enum { c: Default::default(), case: Some((st(src, 25), [None, Some(1), Some(2)][r.below(3)])), payloads: BTreeMap::from([(1, payload)]) }
            }
        }
    }

    /// One state: records of dot `ctr` of writer 1 under keys from `keys`.
    fn copy(r: &mut Rng, ctr: u64, keys: &[&str], depth: u32, kind: usize, slots: bool) -> Frag {
        let mut entries = BTreeMap::new();
        for _ in 0..1 + r.below(2) {
            let k = r.below(keys.len() + 1);
            let key = (k > 0).then(|| str(keys[k - 1]));
            let created = r.chance(2, 3).then(|| st(1, ctr));
            let inner = if depth > 0 && (!slots || r.chance(2, 3)) {
                copy(r, ctr + 1, &["q", "z"], depth - 1, kind, slots)
            } else {
                let k = if slots { r.below(3) } else { kind };
                leaf(r, k)
            };
            entries.insert((Dot { source: Source::session(1, 0), ctr }, key), Entry { reset: None, frag: Some(Box::new(inner)), created });
        }
        let mut x = Frag::empty(7);
        x.join(Frag::Map { c: Default::default(), entries });
        x
    }

    fn join(a: &Fragment, b: &Fragment) -> Fragment {
        let mut x = a.clone();
        x.join(b.clone());
        x
    }

    /// Which dots expire, for the crdt and for the model.
    type Expiry<'a> = (&'a dyn Fn(&crate::stamp::Dot) -> bool, &'a dyn Fn(&Dot) -> bool);

    /// The join laws, the model's join, and expiry (§4.7) of each part of the copies (outer
    /// creation, inner creation, the leaf write, each writer) before, after and between joins.
    pub(super) fn check(seed: u64, depth: u32, slots: bool) {
        let mut r = crate::testutil::rng(seed);
        let n = 2 + r.below(2);
        let kind = r.below(3);
        let ms: Vec<Frag> = (0..n).map(|_| copy(&mut r, 1, &["a", "b", "c"], depth, kind, slots)).collect();
        let ps: Vec<Fragment> = ms.iter().map(frag).collect();
        let all = ps[1..].iter().fold(ps[0].clone(), |a, b| join(&a, b));
        assert_eq!(all, ps[..n - 1].iter().rev().fold(ps[n - 1].clone(), |a, b| join(&a, b)), "commutative");
        assert_eq!(join(&all, &ps[0]), all, "absorbing");
        if n == 3 {
            assert_eq!(join(&ps[0], &join(&ps[1], &ps[2])), all, "associative");
            assert_eq!(join(&join(&ps[0], &ps[2]), &ps[1]), all, "any order");
        }
        let model = ms[1..].iter().fold(ms[0].clone(), |mut a, b| {
            a.join(b.clone());
            a
        });
        assert_eq!(all, ostate(&Some(model.clone())), "the model's join");
        let w2 = source(&Source::session(2, 0));
        let exps: [Expiry; 5] = [
            (&|_| true, &|_| true),
            (&|d| d.ctr == 1, &|d| d.ctr == 1),
            (&|d| d.ctr == 2, &|d| d.ctr == 2),
            (&|d| d.ctr >= 5, &|d| d.ctr >= 5),
            (&|d| d.src == w2, &|d| d.source == Source::session(2, 0)),
        ];
        for (i, (e, me)) in exps.iter().enumerate() {
            let strip = |x: &Fragment| {
                let mut y = x.clone();
                y.strip(*e);
                y
            };
            let late = strip(&all);
            let early = ps[1..].iter().fold(strip(&ps[0]), |a, b| strip(&join(&a, &strip(b))));
            assert_eq!(early, late, "expiry {i} before the joins");
            let mixed = strip(&ps[1..].iter().fold(ps[0].clone(), |a, b| join(&a, &strip(b))));
            assert_eq!(mixed, late, "expiry {i} of all but the first");
            let mut ml = model.clone();
            ml.strip(*me);
            assert_eq!(late, ostate(&Some(ml)), "expiry {i}, the model's");
        }
    }

    /// A nested entry is its dot whatever its record's key (§4.8 Which write): two copies of
    /// an outer entry under keys `b` and `a`, holding copies of one inner entry under `q` and `z`.
    /// Everything sits under the greatest outer key, as the join of the copies (inner key `z`).
    #[test]
    fn nested_entry_copies_sit_under_the_greatest_key_spec_5_6() {
        let w = Frag::Register { reset: None, write: Some((st(2, 5), Some(str("x")))) };
        let one = |k: &str, i: Frag, d: u64| {
            let e = Entry { reset: None, frag: Some(Box::new(i)), created: Some(st(1, d)) };
            Frag::Map { c: Default::default(), entries: BTreeMap::from([((Dot { source: Source::session(1, 0), ctr: d }, Some(str(k))), e)]) }
        };
        let a = frag(&one("b", one("q", w.clone(), 2), 1));
        let b = frag(&one("a", one("z", w, 2), 1));
        let want = osis_base::Value::Map(osis_base::ValueMap::from([(osis_base::Value::Str("b".into()), osis_base::Value::Map(osis_base::ValueMap::from([(osis_base::Value::Str("z".into()), osis_base::Value::Str("x".into()))])))]));
        assert_eq!(join(&a, &b).read(), Some(want));
        assert_eq!(join(&a, &b), join(&b, &a));
    }

    /// §5.6 with §4.1 and §4.7: forged copies of one entry under several keys, one encoding per
    /// position, flat and nested.
    #[test]
    fn forged_entry_copies_join_and_expire_alike_spec_5_6() {
        for seed in 0..1000 {
            check(seed, (seed % 2) as u32, false);
        }
    }

    /// issues/forged-entry-copies-slots.md: with two encodings at one position (§7) the join
    /// laws and expiry break.
    #[test]
    #[ignore = "issues/forged-entry-copies-slots.md"]
    fn repro_forged_entry_copies_across_encodings() {
        for seed in 0..300 {
            check(seed, 0, true);
        }
    }
}
