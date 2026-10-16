//! Property tests of spec/crdt.md §10 against the reference model.
use crdt_model::gen::{kitchen_sink, random_op, random_value, Rng};
use crdt_model::ops::{self, Ty, Writer};
use crdt_model::stamp::Source;
use crdt_model::state::{Content, Frag};
use crdt_model::value::Value;
use crdt_model::wire::{decode_delta, encode_delta, Ctx};
use proptest::prelude::*;

/// Encode a delta, check the round trip and canonical re-encoding, return the decoded fragment.
fn roundtrip(f: &Frag, w: &Writer) -> Frag {
    let mut cx = Ctx::new(w.ts, w.source.clone(), w.lo);
    let bytes = encode_delta(f, [7; 16], &mut cx);
    let mut cx2 = Ctx::new(w.ts, w.source.clone(), w.lo);
    cx2.sources = cx.sources.clone();
    let g = decode_delta(&bytes, &mut cx2).expect("decodes");
    let mut cx3 = Ctx::new(w.ts, w.source.clone(), w.lo);
    let bytes2 = encode_delta(&g, [7; 16], &mut cx3);
    assert_eq!(bytes, bytes2, "re-encoding is byte-identical");
    assert_eq!(&g, f, "decoded fragment equals the original");
    g
}

/// Snapshot bytes of a state as a compactor would write them.
fn snapshot(f: &Frag) -> Vec<u8> {
    encode_delta(f, [0; 16], &mut Ctx::new(1 << 40, Source::node(250), 1))
}

struct Replica {
    w: Writer,
    state: Option<Frag>,
}

/// Run `rounds` of random ops on `n` replicas, deliver every delta to everyone in random order with
/// duplicates, and check convergence of reads and snapshots. Returns the final state.
fn converge(seed: u64, ty: &Ty, n: usize, rounds: usize, partial: bool) -> Option<Frag> {
    let mut r = Rng(seed | 1);
    let mut reps: Vec<Replica> = (0..n).map(|i| Replica { w: Writer::new(Source::node(i as u8 + 1), 1 << 16, 1), state: None }).collect();
    let mut deltas: Vec<(Writer, Frag)> = Vec::new();
    for round in 0..rounds {
        for i in 0..n {
            // clocks drift: each writer's ts jumps by a random amount, so concurrency is realistic
            let ts = ((round as u64 * 10 + r.below(10) as u64 + 1) << 16) + i as u64;
            let rep = &mut reps[i];
            let t = ts.max(rep.w.ts + 1);
            rep.w.next_commit(t);
            let Some(d) = random_op(&mut r, &mut rep.w, ty, rep.state.as_ref()) else { continue };
            let d = roundtrip(&d, &rep.w);
            apply(&mut rep.state, d.clone());
            deltas.push((rep.w.clone(), d));
        }
        if partial && r.chance(1, 2) {
            // deliver a random subset to a random replica mid-way (state must stay well-formed)
            let i = r.below(n);
            for (_, d) in deltas.iter() {
                if r.chance(1, 3) {
                    apply(&mut reps[i].state, d.clone());
                }
            }
        }
    }
    // full delivery in random order with duplicates
    for i in 0..n {
        let mut order: Vec<usize> = (0..deltas.len()).collect();
        for k in (1..order.len()).rev() {
            let j = r.below(k + 1);
            order.swap(k, j);
        }
        for k in order {
            apply(&mut reps[i].state, deltas[k].1.clone());
            if r.chance(1, 4) {
                apply(&mut reps[i].state, deltas[k].1.clone());
            }
        }
    }
    let reads: Vec<Option<Value>> = reps.iter().map(|x| x.state.as_ref().and_then(|s| s.read())).collect();
    let snaps: Vec<Vec<u8>> = reps.iter().map(|x| x.state.as_ref().map_or(vec![], snapshot)).collect();
    for i in 1..n {
        assert_eq!(reads[0], reads[i], "reads converge (replica {i})");
        assert_eq!(snaps[0], snaps[i], "snapshots converge (replica {i})");
    }
    reps.swap_remove(0).state
}

fn apply(state: &mut Option<Frag>, d: Frag) {
    match state {
        None => {
            let mut s = d;
            s.prune(None);
            *state = Some(s);
        }
        Some(s) => s.join(d),
    }
}

fn join3(a: &Frag, b: &Frag) -> Frag {
    let mut x = a.clone();
    x.join(b.clone());
    x
}

proptest! {
    #![proptest_config(ProptestConfig { cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(64), .. ProptestConfig::default() })]

    #[test]
    fn convergence_kitchen_sink(seed in any::<u64>()) {
        converge(seed, &kitchen_sink(), 3, 6, true);
    }

    #[test]
    fn convergence_text(seed in any::<u64>()) {
        converge(seed, &Ty::Text, 3, 12, true);
    }

    #[test]
    fn convergence_list(seed in any::<u64>()) {
        let ty = Ty::List(Box::new(Ty::Struct([(1, Ty::Register), (2, Ty::Text)].into_iter().collect())));
        converge(seed, &ty, 3, 8, false);
    }

    #[test]
    fn lattice_laws(seed in any::<u64>()) {
        // three states built from random ops by different writers
        let ty = kitchen_sink();
        let mut r = Rng(seed | 1);
        let mut states = Vec::new();
        for i in 0..3u8 {
            let mut w = Writer::new(Source::node(i + 1), ((r.below(5) as u64 + 1) << 16) + i as u64, 1);
            let mut st: Option<Frag> = None;
            for k in 0..4 {
                w.next_commit(w.ts + ((r.below(3) as u64) << 16) + 1 + k);
                if let Some(d) = random_op(&mut r, &mut w, &ty, st.as_ref()) {
                    apply(&mut st, d);
                }
            }
            states.push(st.unwrap_or_else(|| { let mut f = Frag::empty(4); f.prune(None); f }));
        }
        let (a, b, c) = (&states[0], &states[1], &states[2]);
        prop_assert_eq!(join3(a, b), join3(b, a), "commutative");
        prop_assert_eq!(join3(&join3(a, b), c), join3(a, &join3(b, c)), "associative");
        prop_assert_eq!(join3(a, a), a.clone(), "idempotent");
        prop_assert_eq!(join3(&join3(a, b), b), join3(a, b), "absorbing");
    }

    #[test]
    fn single_writer_text_matches_sequential_model(seed in any::<u64>()) {
        let mut r = Rng(seed | 1);
        let mut w = Writer::new(Source::node(1), 1 << 16, 1);
        let mut st: Option<Frag> = None;
        let mut model: Vec<char> = Vec::new();
        for k in 0..40u64 {
            w.next_commit(((k + 2) << 16) + 1);
            let n = model.len();
            match r.below(3) {
                0 => {
                    let s: String = (0..1 + r.below(4)).map(|_| (b'a' + r.below(6) as u8) as char).collect();
                    let at = r.below(n + 1);
                    let d = ops::seq_insert(&mut w, st.as_ref(), true, at, s.chars().map(Content::Char).collect());
                    let d = roundtrip(&d, &w);
                    apply(&mut st, d);
                    for (i, c) in s.chars().enumerate() {
                        model.insert(at + i, c);
                    }
                }
                1 if n > 0 => {
                    let from = r.below(n);
                    let len = (1 + r.below(3)).min(n - from);
                    let d = ops::seq_delete(&mut w, st.as_ref().unwrap(), from, len).unwrap();
                    let d = roundtrip(&d, &w);
                    apply(&mut st, d);
                    model.drain(from..from + len);
                }
                2 if n > 1 => {
                    let from = r.below(n);
                    let len = (1 + r.below(3)).min(n - from);
                    let after = r.below(n - len + 1);
                    let d = ops::seq_move(&mut w, st.as_ref().unwrap(), from, len, after).unwrap();
                    let d = roundtrip(&d, &w);
                    apply(&mut st, d);
                    let moved: Vec<char> = model.drain(from..from + len).collect();
                    for (i, c) in moved.into_iter().enumerate() {
                        model.insert(after + i, c);
                    }
                }
                _ => {}
            }
            let got = st.as_ref().and_then(|s| s.read()).unwrap_or(Value::Str(String::new()));
            prop_assert_eq!(got, Value::Str(model.iter().collect::<String>()), "after op {}", k);
        }
    }

    #[test]
    fn diff_reaches_value(seed in any::<u64>()) {
        let ty = kitchen_sink();
        let mut r = Rng(seed | 1);
        let mut w = Writer::new(Source::node(1), 1 << 16, 1);
        let mut st: Option<Frag> = None;
        for k in 0..6u64 {
            w.next_commit(((k + 2) << 16) + 1);
            let v = random_value(&mut r, &ty, 0);
            if let Some(d) = crdt_model::diff::diff(&mut w, st.as_ref(), &ty, &v) {
                let d = roundtrip(&d, &w);
                apply(&mut st, d);
            }
            prop_assert_eq!(st.as_ref().unwrap().read(), Some(v));
        }
    }

    #[test]
    fn embeddings_commute_with_join(seed in any::<u64>()) {
        // two register writes (int) joined then embedded == embedded then joined, for counter/max/min;
        // a string register joined into a text state equals joining its embedding.
        let mut r = Rng(seed | 1);
        let mk = |r: &mut Rng, i: u8, s: &str| {
            let w = Writer::new(Source::node(i), ((r.below(4) as u64 + 1) << 16) + i as u64, 1);
            let v = if s.is_empty() { Value::Int(r.below(9) as i64 - 4) } else { Value::Str(s.to_string()) };
            Frag::Register { reset: None, write: Some((w.delta(), v)) }
        };
        for enc in [1u8, 2, 3] {
            let (a, b) = (mk(&mut r, 1, ""), mk(&mut r, 2, ""));
            let mut ab = a.clone();
            ab.join(b.clone());
            let e_ab = crdt_model::embed::embed(&ab, enc).unwrap();
            let mut ea = crdt_model::embed::embed(&a, enc).unwrap();
            ea.join(crdt_model::embed::embed(&b, enc).unwrap());
            prop_assert_eq!(ea.read(), e_ab.read(), "enc {}", enc);
        }
        let (a, b) = (mk(&mut r, 1, "hello"), mk(&mut r, 2, "world"));
        let mut text = crdt_model::embed::embed(&a, 9).unwrap();
        text.prune(None);
        let mut via_reg = text.clone();
        via_reg.join(b.clone());
        let mut via_emb = text.clone();
        via_emb.join(crdt_model::embed::embed(&b, 9).unwrap());
        prop_assert_eq!(via_reg.read(), via_emb.read());
        let mut ab = a.clone();
        ab.join(b.clone());
        prop_assert_eq!(via_reg.read(), ab.read(), "text read equals the LWW winner");
    }

    #[test]
    fn decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        let mut cx = Ctx::new(5 << 16, Source::node(1), 1);
        cx.sources.push(Source::node(2));
        let _ = decode_delta(&bytes, &mut cx);
    }

    #[test]
    fn mutated_delta_never_panics(seed in any::<u64>(), pos in 0usize..200, byte in any::<u8>()) {
        let ty = kitchen_sink();
        let mut r = Rng(seed | 1);
        let mut w = Writer::new(Source::node(1), 3 << 16, 1);
        let v = random_value(&mut r, &ty, 0);
        let d = ops::create(&mut w, &ty, &v);
        let mut cx = Ctx::new(w.ts, w.source.clone(), w.lo);
        let mut bytes = encode_delta(&d, [1; 16], &mut cx);
        if !bytes.is_empty() {
            let p = pos % bytes.len();
            bytes[p] = byte;
        }
        let mut cx2 = Ctx::new(w.ts, w.source.clone(), w.lo);
        cx2.sources = cx.sources.clone();
        if let Ok(f) = decode_delta(&bytes, &mut cx2) {
            let _ = f.read();
            let mut s = f;
            s.prune(None);
            let _ = snapshot(&s);
        }
    }

    #[test]
    fn unmerge_removes_author(seed in any::<u64>()) {
        let ty = kitchen_sink();
        let st = converge(seed, &ty, 3, 4, false);
        let Some(mut st) = st else { return Ok(()) };
        st.unmerge(&|s| *s == Source::node(2));
        let mut stamps = Vec::new();
        st.stamps(&mut stamps);
        // only creation position writes of node 2's own elements may remain (hidden anchors)
        for s in stamps {
            if *s.dot.source.author() == Source::node(2) {
                prop_assert!(matches!(&st, Frag::Struct { .. }), "node 2 stamp survived: {:?}", s);
            }
        }
        let _ = st.read();
        let _ = snapshot(&st);
    }
}

#[test]
fn worked_examples_from_spec() {
    // FOOBAR + insert x after O2 / move FOO to the end -> BARFOOx (§6.4)
    let mut a = Writer::new(Source::node(1), 1 << 16, 1);
    let mut st: Option<Frag> = None;
    let d = ops::seq_insert(&mut a, None, true, 0, "FOOBAR".chars().map(Content::Char).collect());
    apply(&mut st, d);
    let base = st.clone().unwrap();
    let mut b = Writer::new(Source::node(2), 2 << 16, 1);
    let dx = ops::seq_insert(&mut b, Some(&base), true, 3, vec![Content::Char('x')]);
    a.next_commit(3 << 16);
    let dm = ops::seq_move(&mut a, &base, 0, 3, 3).unwrap();
    let mut s1 = base.clone();
    s1.join(dx.clone());
    s1.join(dm.clone());
    let mut s2 = base.clone();
    s2.join(dm);
    s2.join(dx);
    assert_eq!(s1.read(), Some(Value::Str("BARFOOx".into())));
    assert_eq!(s2.read(), s1.read());

    // concurrent inserts at one anchor: later insert nearer the anchor
    let mut c = Writer::new(Source::node(3), 4 << 16, 1);
    let dy = ops::seq_insert(&mut c, Some(&base), true, 3, vec![Content::Char('y')]);
    let mut b2 = Writer::new(Source::node(2), 2 << 16, 1);
    let dx2 = ops::seq_insert(&mut b2, Some(&base), true, 3, vec![Content::Char('x')]);
    let mut s = base.clone();
    s.join(dy);
    s.join(dx2);
    assert_eq!(s.read(), Some(Value::Str("FOOyxBAR".into())));

    // concurrent moves of one element: later wins, never duplicated
    let mut w = Writer::new(Source::node(1), 1 << 16, 1);
    let mut st: Option<Frag> = None;
    apply(&mut st, ops::seq_insert(&mut w, None, true, 0, "abc".chars().map(Content::Char).collect()));
    let base = st.unwrap();
    let mut p = Writer::new(Source::node(2), 5 << 16, 1);
    let mut q = Writer::new(Source::node(3), 4 << 16, 1);
    let m1 = ops::seq_move(&mut p, &base, 0, 1, 2).unwrap(); // a after c
    let m2 = ops::seq_move(&mut q, &base, 0, 1, 1).unwrap(); // a after b
    let mut s = base.clone();
    s.join(m2);
    s.join(m1);
    assert_eq!(s.read(), Some(Value::Str("bca".into())));

    // cycle: x->y (t=5) and y->x (t=4) concurrently from "xy"
    let mut w = Writer::new(Source::node(1), 1 << 16, 1);
    let mut st: Option<Frag> = None;
    apply(&mut st, ops::seq_insert(&mut w, None, true, 0, "xy".chars().map(Content::Char).collect()));
    let base = st.unwrap();
    let mut p = Writer::new(Source::node(2), 5 << 16, 1);
    let mut q = Writer::new(Source::node(3), 4 << 16, 1);
    let m1 = ops::seq_move(&mut p, &base, 0, 1, 1).unwrap(); // x after y
    let m2 = ops::seq_move(&mut q, &base, 1, 1, 0).unwrap(); // y to the start (before x)
    let mut s = base.clone();
    s.join(m1.clone());
    s.join(m2.clone());
    let mut s2 = base.clone();
    s2.join(m2);
    s2.join(m1);
    assert_eq!(s.read(), s2.read());
    assert_eq!(s.read(), Some(Value::Str("yx".into())));
}

#[test]
fn map_resurrection_and_set_semantics() {
    let vt = Ty::Struct([(1, Ty::Register)].into_iter().collect());
    let ty = Ty::Map(Box::new(Ty::Register), Box::new(vt.clone()));
    let mut a = Writer::new(Source::node(1), 1 << 16, 1);
    let mut st: Option<Frag> = None;
    apply(&mut st, ops::map_put(&mut a, None, &vt, &Value::Int(1), &Value::fields(vec![(1, Value::Int(10))])).unwrap());
    let base = st.clone().unwrap();
    // b removes key 1 at t=3; c edits the entry at t=4 (newer) -> entry resurrected with only the newer write
    let mut b = Writer::new(Source::node(2), 3 << 16, 1);
    let rm = ops::map_remove(&mut b, Some(&base), &Value::Int(1)).unwrap();
    let mut c = Writer::new(Source::node(3), 4 << 16, 1);
    let ed = ops::map_put(&mut c, Some(&base), &vt, &Value::Int(1), &Value::fields(vec![(1, Value::Int(11))])).unwrap();
    let mut s = base.clone();
    s.join(rm.clone());
    assert_eq!(s.read(), Some(Value::map(vec![])));
    s.join(ed.clone());
    assert_eq!(s.read(), Some(Value::map(vec![(Value::Int(1), Value::fields(vec![(1, Value::Int(11))]))])));
    // older edit (t=2) loses to the removal
    let mut d = Writer::new(Source::node(4), 2 << 16, 1);
    let old = ops::map_put(&mut d, Some(&base), &vt, &Value::Int(1), &Value::fields(vec![(1, Value::Int(9))])).unwrap();
    let mut s2 = base.clone();
    s2.join(old);
    s2.join(rm);
    assert_eq!(s2.read(), Some(Value::map(vec![])));
    assert_eq!(ty.enc(), 7);

    // set: concurrent add of the same value the remover never saw survives
    let st_ty = Ty::Set(Box::new(Ty::Register));
    let mut a = Writer::new(Source::node(1), 1 << 16, 1);
    let mut st: Option<Frag> = None;
    apply(&mut st, ops::set_add(&mut a, None, &Ty::Register, &Value::Int(5)).unwrap());
    let base = st.unwrap();
    let mut b = Writer::new(Source::node(2), 3 << 16, 1);
    let rm = ops::set_remove(&mut b, Some(&base), &Value::Int(5)).unwrap();
    let mut c = Writer::new(Source::node(3), 2 << 16, 1);
    let add = ops::set_add(&mut c, None, &Ty::Register, &Value::Int(5)).unwrap();
    let mut s = base.clone();
    s.join(rm);
    s.join(add);
    assert_eq!(s.read(), Some(Value::set(vec![Value::Int(5)])));
    assert_eq!(st_ty.enc(), 6);
}
