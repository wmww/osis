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

/// Copies of one map entry (§5.6) under several keys, as forged snapshots carry them: random
/// records of one dot (`a`, `b`, `c` or key-erased), each holding a write of one stamp with
/// differing payloads (`leaf`) and maybe a reset, `depth` maps deep (inner records of one dot
/// under their own keys). One encoding per level unless `slots` (§7: a register beside other
/// encodings at one position).
mod entry_copies {
    use crate::fragment::Fragment;
    use crate::testutil::{frag, ostate, source};
    use crdt_model::r#gen::Rng;
    use crdt_model::stamp::{Dot, Source, Stamp};
    use crdt_model::state::{Anchor, BagKind, Content, Elem, Entry, Frag, SeqElem};
    use crdt_model::value::Value;
    use std::collections::BTreeMap;

    fn st(src: u8, c: u64) -> Stamp {
        st_at(0, src, c)
    }

    /// `st` at a later time `dt`.
    fn st_at(dt: u64, src: u8, c: u64) -> Stamp {
        Stamp::new((1 << 16) + dt, Source::session(src, 0), c)
    }

    fn str(s: &str) -> Value {
        Value::Str(s.into())
    }

    /// A write at a leaf, by writer 1 or 2: `kind` 0 a register (written at stamp 5), 1 a text
    /// element, 2 an enum case, 3 a counter contribution, 4 a list element, 5 an inner map entry;
    /// beside a register only (§7: copies of what its embedding writes, or its own reset): 6 a
    /// text delete or undelete of an embedded char, 7 a counter contribution copying the
    /// register write with another value (or under a later stamp of its dot), 8 an enum reset at
    /// the register write's stamp, 9 a register reset, 10 an embedded char's creation copying
    /// the register write with another char (or under a later stamp).
    fn leaf(r: &mut Rng, kind: usize) -> Frag {
        let src = 1 + r.below(2) as u8;
        let int = |r: &mut Rng| Some(Value::Int(r.below(2) as i64));
        let dot = |src: u8, ctr: u64| Dot { source: Source::session(src, 0), ctr };
        let bag = |d: Dot, w: (Stamp, Option<Value>)| Frag::Bag { kind: BagKind::Counter, c: Default::default(), elems: BTreeMap::from([(d, Elem { reset: None, frag: Some(Box::new(Frag::Register { reset: None, write: Some(w) })) })]) };
        match kind {
            0 => Frag::Register { reset: None, write: Some((st(src, 5), [None, Some(str("x")), Some(str("y")), Some(Value::Int(1))][r.below(4)].clone())) },
            1 => {
                let anchor = if r.chance(1, 2) { Anchor::Head } else { Anchor::Dot(dot(2, 9)) };
                let mut el = SeqElem::new(st(src, 15), anchor, [Content::None, Content::Char('x'), Content::Char('y')][r.below(3)].clone());
                if r.chance(1, 3) {
                    let del = r.chance(1, 2);
                    el.deleted = Some((st(2, 17), del));
                    el.undel = [None, Some('p'), Some('q')][r.below(3)].filter(|_| !del);
                }
                Frag::Seq { text: true, c: Default::default(), elems: BTreeMap::from([(dot(src, 15), el)]) }
            }
            2 => {
                let payload = Frag::Register { reset: None, write: Some((st(2, 26), int(r))) };
                Frag::Enum { c: Default::default(), case: Some((st(src, 25), [None, Some(1), Some(2)][r.below(3)])), payloads: BTreeMap::from([(1, payload)]) }
            }
            3 => bag(dot(src, 35), (st(src, 35), int(r))),
            4 => {
                let el = SeqElem::new(st(src, 45), Anchor::Head, Content::Frag(Box::new(Frag::Register { reset: None, write: Some((st(src, 46), int(r))) })));
                Frag::Seq { text: false, c: Default::default(), elems: BTreeMap::from([(dot(src, 45), el)]) }
            }
            5 => {
                let e = Entry { reset: None, frag: Some(Box::new(Frag::Register { reset: None, write: Some((st(2, 31), int(r))) })), created: Some(st(2, 30)) };
                Frag::Map { c: Default::default(), entries: BTreeMap::from([((dot(2, 30), Some(str("m"))), e)]) }
            }
            6 => {
                let d = Dot { source: Source::Derived(Box::new(dot(src, 5))), ctr: 1 };
                let el = SeqElem::write(Content::None, vec![], Some((st(2, 17), r.chance(1, 2))));
                Frag::Seq { text: true, c: Default::default(), elems: BTreeMap::from([(d, el)]) }
            }
            7 => bag(dot(src, 5), (st_at([0, 0, 4][r.below(3)], src, 5), [None, Some(Value::Int(0)), Some(Value::Int(7))][r.below(3)].clone())),
            8 => Frag::Enum { c: crdt_model::state::Composite { reset: Some(st(src, 5)), ..Default::default() }, case: None, payloads: BTreeMap::new() },
            9 => Frag::Register { reset: Some(st(2, [3, 7][r.below(2)])), write: r.chance(1, 2).then(|| (st(src, 5), Some(str("x")))) },
            _ => {
                let d = Dot { source: Source::Derived(Box::new(dot(src, 5))), ctr: 1 };
                let el = SeqElem::new(Stamp { ts: (1 << 16) + [0, 0, 4][r.below(3)], dot: d.clone() }, Anchor::Head, [Content::Char('x'), Content::Char('z')][r.below(2)].clone());
                Frag::Seq { text: true, c: Default::default(), elems: BTreeMap::from([(d, el)]) }
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
            let reset = r.chance(1, 6).then(|| st(2, 4));
            let inner = if depth > 0 && (!slots || r.chance(2, 3)) {
                copy(r, ctr + 1, &["q", "z"], depth - 1, kind, slots)
            } else {
                // a register (twice as likely) beside every other kind
                let k = if slots { [0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10][r.below(12)] } else { kind };
                leaf(r, k)
            };
            entries.insert((Dot { source: Source::session(1, 0), ctr }, key), Entry { reset, frag: Some(Box::new(inner)), created });
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
        let kind = r.below(6);
        let ms: Vec<Frag> = (0..n).map(|_| copy(&mut r, 1, &["a", "b", "c"], depth, kind, slots)).collect();
        laws(&ms);
    }

    /// `check` of copies `ms` (two or three).
    fn laws(ms: &[Frag]) {
        let n = ms.len();
        let ps: Vec<Fragment> = ms.iter().map(frag).collect();
        let all = ps[1..].iter().fold(ps[0].clone(), |a, b| join(&a, b));
        assert_eq!(all, ps[..n - 1].iter().rev().fold(ps[n - 1].clone(), |a, b| join(&a, b)), "commutative");
        assert_eq!(join(&all, &ps[0]), all, "absorbing");
        if n == 3 {
            for [a, b, c] in [[0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
                assert_eq!(join(&join(&ps[a], &ps[b]), &ps[c]), all, "order {a} {b} {c}");
            }
            for [a, b, c] in [[0, 1, 2], [1, 0, 2], [2, 0, 1]] {
                assert_eq!(join(&ps[a], &join(&ps[b], &ps[c])), all, "associative {a} ({b} {c})");
            }
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
            // un-merge of each copy (§4.6), joined in either order
            let un = |x: &Fragment| {
                let mut y = x.clone();
                y.remove_dots(*e);
                y
            };
            let fwd = ps[1..].iter().fold(un(&ps[0]), |a, b| join(&a, &un(b)));
            assert_eq!(fwd, ps[..n - 1].iter().rev().fold(un(&ps[n - 1]), |a, b| join(&a, &un(b))), "un-merge {i}, commutative");
            let mu = ms.iter().map(|m| {
                let mut m = m.clone();
                m.unmerge(*me, &|_| false);
                m
            });
            let mu = mu.reduce(|mut a, b| {
                a.join(b);
                a
            });
            assert_eq!(fwd, ostate(&mu), "un-merge {i}, the model's");
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

    /// §5.6 with §4.1, §4.7 and §7: forged copies of one entry under several keys, flat and
    /// nested, one encoding per position or several (a register beside an enum or a text).
    #[test]
    fn forged_entry_copies_join_and_expire_alike_spec_5_6() {
        for seed in 0..400 {
            check(seed, (seed % 4 / 2) as u32, seed % 2 == 1);
        }
    }

    /// A slot's copy of the register's write is the embedding of the register's winning copy
    /// (§7): a forged counter contribution copying `w` with a greater value (§4.1 copy order)
    /// goes, joined with `w` at one position or in two records of one entry.
    #[test]
    fn slot_copy_of_the_register_write_is_its_embedding_spec_7() {
        let d = Dot { source: Source::session(1, 0), ctr: 1 };
        let w = Frag::Register { reset: None, write: Some((st(1, 5), Some(Value::Int(1)))) };
        let reg = Frag::Register { reset: None, write: Some((st(1, 5), Some(Value::Int(7)))) };
        let forged = Frag::Bag { kind: BagKind::Counter, c: Default::default(), elems: BTreeMap::from([(Dot { source: Source::session(1, 0), ctr: 5 }, Elem { reset: None, frag: Some(Box::new(reg)) })]) };
        assert_eq!(join(&frag(&forged), &frag(&w)), frag(&w));
        assert_eq!(join(&frag(&w), &frag(&forged)), frag(&w));
        let rec = |k: &str, f: &Frag| Frag::Map { c: Default::default(), entries: BTreeMap::from([((d.clone(), Some(str(k))), Entry { reset: None, frag: Some(Box::new(f.clone())), created: Some(st(1, 1)) })]) };
        laws(&[rec("a", &forged), rec("b", &w)]);
    }

    /// Copies of the register write `s` in a slot are told by stamp (§7): a bag contribution or
    /// an embedded char's creation under a later stamp of `s.dot` is a write of its own, so it
    /// outlives a greater register write `g` that beats `s` in every arrival order (fitting it
    /// to `s` would drop it only where `s` came before `g`).
    #[test]
    fn slot_copies_of_the_register_write_are_told_by_stamp_spec_7() {
        let s = Frag::Register { reset: None, write: Some((st(1, 5), Some(str("a")))) };
        let g = Frag::Register { reset: None, write: Some((st_at(2, 2, 6), Some(Value::Int(2)))) };
        let bag = Frag::Bag { kind: BagKind::Counter, c: Default::default(), elems: BTreeMap::from([(Dot { source: Source::session(1, 0), ctr: 5 }, Elem { reset: None, frag: Some(Box::new(Frag::Register { reset: None, write: Some((st_at(4, 1, 5), Some(Value::Int(7)))) })) })]) };
        let d = Dot { source: Source::Derived(Box::new(Dot { source: Source::session(1, 0), ctr: 5 })), ctr: 1 };
        let el = SeqElem::new(Stamp { ts: (1 << 16) + 4, dot: d.clone() }, Anchor::Head, Content::Char('z'));
        let text = Frag::Seq { text: true, c: Default::default(), elems: BTreeMap::from([(d, el)]) };
        for forged in [bag, text] {
            laws(&[s.clone(), forged.clone(), g.clone()]);
            assert_ne!(join(&frag(&forged), &frag(&g)), frag(&g), "the forged write stays");
        }
    }

    /// A slot's embedding of the register is the register write's (§7), so it sits in the
    /// record holding that write (§5.6): record `a` holds writer 2's enum case and `b` writer
    /// 1's register write `w`, joined with a copy holding `w` under `a`. `w` sits under `b`, and
    /// its embedded reset does not stay in `a`'s enum slot (as a reset of its own it outlived the
    /// expiry of writer 2's case, which moves the case and leaves `w` alone).
    #[test]
    fn slot_embedding_sits_with_its_register_write_spec_7() {
        let d = Dot { source: Source::session(1, 0), ctr: 1 };
        let w = Frag::Register { reset: None, write: Some((st(1, 5), Some(str("x")))) };
        let case = Frag::Enum { c: Default::default(), case: Some((st(2, 25), Some(1))), payloads: BTreeMap::new() };
        let rec = |f: Frag, created: bool| Entry { reset: None, frag: Some(Box::new(f)), created: created.then(|| st(1, 1)) };
        let one = Frag::Map { c: Default::default(), entries: BTreeMap::from([((d.clone(), Some(str("a"))), rec(case, true)), ((d.clone(), Some(str("b"))), rec(w.clone(), false))]) };
        let two = Frag::Map { c: Default::default(), entries: BTreeMap::from([((d, Some(str("a"))), rec(w, false))]) };
        laws(&[one, two]);
    }
}

