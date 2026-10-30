//! Property tests of spec/crdt.md (list: notes/crdt.md, Reference model) against the reference model.
use crdt_model::gen::{kitchen_sink, random_op, random_value, Rng};
use crdt_model::ops::{self, Ty, Writer};
use crdt_model::received::Received;
use crdt_model::stamp::{Dot, Source};
use crdt_model::state::{Content, Frag};
use crdt_model::value::Value;
use crdt_model::wire::{decode_delta, decode_snapshot, encode_delta, encode_snapshot, Ctx};
use proptest::prelude::*;

/// Encode a delta, check the round trip and canonical re-encoding, return the decoded fragment.
fn roundtrip(f: &Frag, w: &Writer) -> Frag {
    let mut cx = Ctx::new(w.ts, w.source.clone(), w.lo);
    let bytes = encode_delta(f, [7; 16], &mut cx);
    // decoded as a writer's delta: range and writer-only rules checked (§2.3, §3.3 rule 7)
    let mut cx2 = Ctx::writer(w.ts, w.source.clone(), w.lo, w.hi());
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

/// One commit's counter range: `(source, lo, hi)`.
type Range = (Source, u64, u64);

fn range(w: &Writer) -> Range {
    (w.source.clone(), w.lo, w.hi())
}

/// Predicate over owner dots: the dot lies in one of `ranges`.
fn in_ranges(ranges: &[Range]) -> impl Fn(&Dot) -> bool + '_ {
    move |d: &Dot| ranges.iter().any(|(s, lo, hi)| d.source == *s && (*lo..*hi).contains(&d.ctr))
}

struct Replica {
    w: Writer,
    state: Option<Frag>,
    /// Commits whose T this replica's clock has reached (§4.7).
    expired: Vec<Range>,
    received: Received,
}

impl Replica {
    /// Join, then hold expired commits value-less (the expiry rule strips every later arrival).
    fn apply(&mut self, d: Frag) {
        apply(&mut self.state, d);
        if let Some(s) = &mut self.state {
            s.strip(&in_ranges(&self.expired));
        }
    }
    fn expire(&mut self, r: &Range) {
        if !self.expired.contains(r) {
            self.expired.push(r.clone());
        }
        if let Some(s) = &mut self.state {
            s.strip(&in_ranges(&self.expired));
        }
    }
}

struct Commit {
    w: Writer,
    delta: Frag,
    expiring: bool,
}

/// A compactor's snapshot (§8): expiring commits' values stripped whether expired or not, frontiers from receipts.
/// Round-trips it and returns what a receiver decodes.
fn snapshot_transfer(st: &Frag, received: &Received, expiring: &[Range]) -> (Frag, Vec<(Source, u64)>) {
    let mut f = st.clone();
    f.strip(&in_ranges(expiring));
    let fr = received.frontiers();
    let mut cx = Ctx::new(1 << 40, Source::node(250), 1);
    let bytes = encode_snapshot(&f, &fr, [3; 16], &mut cx);
    let mut cx2 = Ctx::new(1 << 40, Source::node(250), 1);
    let (g, fr2) = decode_snapshot(&bytes, &mut cx2).expect("snapshot decodes");
    let mut cx3 = Ctx::new(1 << 40, Source::node(250), 1);
    assert_eq!(encode_snapshot(&g, &fr2, [3; 16], &mut cx3), bytes, "snapshot re-encodes byte-identically");
    let mut sorted = fr2.clone();
    sorted.sort();
    assert_eq!(sorted, fr, "frontiers round-trip");
    assert_eq!(snapshot(&g), snapshot(&f), "snapshot fragment round-trips");
    (g, fr2)
}

/// Run `rounds` of random ops on `n` replicas, deliver every delta to everyone in random order with
/// duplicates, and check convergence of reads and snapshots. With `expiry`, some commits expire: each replica
/// reaches their T at random points, mid-way snapshots carry them value-less, and at the end all have expired.
/// Returns the final state.
fn converge(seed: u64, ty: &Ty, n: usize, rounds: usize, partial: bool, expiry: bool) -> Option<Frag> {
    let mut r = Rng(seed | 1);
    let mut reps: Vec<Replica> =
        (0..n).map(|i| Replica { w: Writer { keyed: i % 2 == 1, ..Writer::new(Source::node(i as u8 + 1), 1 << 16, 0) }, state: None, expired: vec![], received: Received::default() }).collect();
    let mut commits: Vec<Commit> = Vec::new();
    for round in 0..rounds {
        for i in 0..n {
            // clocks drift: each writer's ts jumps by a random amount, so concurrency is realistic
            let ts = ((round as u64 * 10 + r.below(10) as u64 + 1) << 16) + i as u64;
            let rep = &mut reps[i];
            let t = ts.max(rep.w.ts + 1);
            let before = rep.w.clone();
            rep.w.next_commit(t);
            let Some(d) = random_op(&mut r, &mut rep.w, ty, rep.state.as_ref()) else {
                rep.w = before; // no commit, no counters consumed
                continue;
            };
            let d = roundtrip(&d, &rep.w);
            let expiring = expiry && r.chance(1, 4);
            if expiring {
                // the value-less form of every delta round-trips too
                let mut s = d.clone();
                s.strip(&|_| true);
                roundtrip(&s, &rep.w);
            }
            rep.apply(d.clone());
            let (src, lo, hi) = range(&rep.w);
            rep.received.add(&src, lo, hi);
            commits.push(Commit { w: rep.w.clone(), delta: d, expiring });
        }
        if partial && r.chance(1, 2) {
            // deliver a random subset to a random replica mid-way (state must stay well-formed)
            let i = r.below(n);
            for c in commits.iter() {
                if r.chance(1, 3) {
                    reps[i].apply(c.delta.clone());
                    let (src, lo, hi) = range(&c.w);
                    reps[i].received.add(&src, lo, hi);
                }
            }
        }
        let expiring: Vec<Range> = commits.iter().filter(|c| c.expiring).map(|c| range(&c.w)).collect();
        if expiry && r.chance(1, 2) {
            // a replica's clock passes the T of some expiring commits, received or not
            let i = r.below(n);
            for x in &expiring {
                if r.chance(1, 2) {
                    reps[i].expire(x);
                }
            }
        }
        if expiry && r.chance(1, 3) {
            let (i, j) = (r.below(n), r.below(n));
            if let Some(st) = reps[i].state.clone() {
                let (g, fr) = snapshot_transfer(&st, &reps[i].received, &expiring);
                reps[j].apply(g);
                reps[j].received.add_frontiers(&fr);
            }
        }
    }
    let expiring: Vec<Range> = commits.iter().filter(|c| c.expiring).map(|c| range(&c.w)).collect();
    // full delivery in random order with duplicates; every replica's clock passes every T somewhere in between
    for i in 0..n {
        let mut order: Vec<usize> = (0..commits.len()).collect();
        for k in (1..order.len()).rev() {
            let j = r.below(k + 1);
            order.swap(k, j);
        }
        let expire_at = r.below(order.len() + 1);
        for (pos, k) in order.into_iter().enumerate() {
            if pos == expire_at {
                expiring.iter().for_each(|x| reps[i].expire(x));
            }
            reps[i].apply(commits[k].delta.clone());
            if r.chance(1, 4) {
                reps[i].apply(commits[k].delta.clone());
            }
            let (src, lo, hi) = range(&commits[k].w);
            reps[i].received.add(&src, lo, hi);
        }
        expiring.iter().for_each(|x| reps[i].expire(x));
    }
    let reads: Vec<Option<Value>> = reps.iter().map(|x| x.state.as_ref().and_then(|s| s.read())).collect();
    let snaps: Vec<Vec<u8>> = reps.iter().map(|x| x.state.as_ref().map_or(vec![], snapshot)).collect();
    for i in 1..n {
        assert_eq!(reads[0], reads[i], "reads converge (replica {i})");
        assert_eq!(snaps[0], snaps[i], "snapshots converge (replica {i})");
    }
    // reference: join everything once, then expire
    let mut reference: Option<Frag> = None;
    for c in &commits {
        apply(&mut reference, c.delta.clone());
    }
    if let Some(s) = &mut reference {
        s.strip(&in_ranges(&expiring));
    }
    assert_eq!(reference.as_ref().map_or(vec![], snapshot), snaps[0], "matches join-then-expire");
    // frontiers cover every commit, and a fresh node bootstrapped from a snapshot reads the same
    for rep in &reps {
        for x in &reps {
            assert_eq!(rep.received.frontier(&x.w.source), commits.iter().filter(|c| c.w.source == x.w.source).map(|c| c.w.hi() - 1).max().unwrap_or(0));
        }
    }
    if let Some(st) = &reps[0].state {
        let (g, _) = snapshot_transfer(st, &reps[0].received, &expiring);
        let mut fresh = Replica { w: Writer::new(Source::node(200), 1, 1), state: None, expired: expiring.clone(), received: Received::default() };
        fresh.apply(g);
        assert_eq!(fresh.state.as_ref().and_then(|s| s.read()), reads[0], "snapshot bootstrap reads the same");
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
        converge(seed, &kitchen_sink(), 3, 6, true, false);
    }

    #[test]
    fn convergence_with_expiry(seed in any::<u64>()) {
        converge(seed, &kitchen_sink(), 3, 6, true, true);
    }

    #[test]
    fn convergence_text_with_expiry(seed in any::<u64>()) {
        converge(seed, &Ty::Text, 3, 10, true, true);
    }

    #[test]
    fn convergence_text(seed in any::<u64>()) {
        converge(seed, &Ty::Text, 3, 12, true, false);
    }

    #[test]
    fn convergence_list(seed in any::<u64>()) {
        let ty = Ty::List(Box::new(Ty::Struct([(1, Ty::Register), (2, Ty::Text)].into_iter().collect())));
        converge(seed, &ty, 3, 8, false, true);
    }

    #[test]
    fn lattice_laws(seed in any::<u64>()) {
        // three states built from random ops by different writers
        let ty = kitchen_sink();
        let mut r = Rng(seed | 1);
        let mut states = Vec::new();
        let mut ranges: Vec<Range> = Vec::new();
        for i in 0..3u8 {
            let mut w = Writer::new(Source::node(i + 1), ((r.below(5) as u64 + 1) << 16) + i as u64, 1);
            let mut st: Option<Frag> = None;
            for k in 0..4 {
                w.next_commit(w.ts + ((r.below(3) as u64) << 16) + 1 + k);
                if let Some(d) = random_op(&mut r, &mut w, &ty, st.as_ref()) {
                    apply(&mut st, d);
                    ranges.push(range(&w));
                }
            }
            states.push(st.unwrap_or_else(|| { let mut f = Frag::empty(4); f.prune(None); f }));
        }
        let (a, b, c) = (&states[0], &states[1], &states[2]);
        prop_assert_eq!(join3(a, b), join3(b, a), "commutative");
        prop_assert_eq!(join3(&join3(a, b), c), join3(a, &join3(b, c)), "associative");
        prop_assert_eq!(join3(a, a), a.clone(), "idempotent");
        prop_assert_eq!(join3(&join3(a, b), b), join3(a, b), "absorbing");

        // expiry (§4.7): stripping a random set of commits commutes with join, is idempotent, and a valued copy
        // wins over its value-less one
        let expired: Vec<Range> = ranges.into_iter().filter(|_| r.chance(1, 2)).collect();
        let strip = |f: &Frag| { let mut g = f.clone(); g.strip(&in_ranges(&expired)); g };
        prop_assert_eq!(strip(&join3(a, b)), join3(&strip(a), &strip(b)), "strip commutes with join");
        prop_assert_eq!(strip(&join3(a, &strip(b))), strip(&join3(a, b)), "strip commutes with partial strip");
        prop_assert_eq!(strip(&strip(a)), strip(a), "strip idempotent");
        // a stripped map record moves to its dot's key-erased record (§4.7), which the valued records' read joins
        prop_assert_eq!(join3(a, &strip(a)).read(), a.read(), "valued copy wins");
        let (sa, sb, sc) = (strip(a), strip(b), strip(c));
        prop_assert_eq!(join3(&join3(&sa, &sb), &sc), join3(&sa, &join3(&sb, &sc)), "associative after strip");
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
            Frag::Register { reset: None, write: Some((w.delta(), Some(v))) }
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

        // a value-less register embeds like its valued copy after stripping (§4.7, §7)
        for (reg, enc) in [(mk(&mut r, 1, ""), 1u8), (mk(&mut r, 2, ""), 3), (mk(&mut r, 1, "abc"), 9), (mk(&mut r, 2, ""), 9)] {
            let mut lessr = reg.clone();
            lessr.strip(&|_| true);
            let mut e1 = crdt_model::embed::embed(&reg, enc).unwrap();
            e1.strip(&|_| true);
            let mut e2 = crdt_model::embed::embed(&lessr, enc).unwrap();
            e2.prune(None);
            prop_assert_eq!(e1, e2, "enc {}", enc);
        }
    }

    #[test]
    fn decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        let mut cx = Ctx::new(5 << 16, Source::node(1), 1);
        let _ = decode_delta(&bytes, &mut cx);
        let mut cx = Ctx::writer(5 << 16, Source::node(1), 1, 4);
        let _ = decode_delta(&bytes, &mut cx);
        let mut cx = Ctx::new(5 << 16, Source::node(1), 1);
        let _ = decode_snapshot(&bytes, &mut cx);
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
        let mut cx2 = Ctx::writer(w.ts, w.source.clone(), w.lo, w.hi());
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
        let st = converge(seed, &ty, 3, 4, false, false);
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
    // FOOBAR + insert x after O2 / move FOO to the end -> BARFOOx (notes/crdt.md, Worked examples)
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
    apply(&mut st, ops::set_add(&mut a, None, &Value::Int(5)).unwrap());
    let base = st.unwrap();
    let mut b = Writer::new(Source::node(2), 3 << 16, 1);
    let rm = ops::set_remove(&mut b, Some(&base), &Value::Int(5)).unwrap();
    let mut c = Writer::new(Source::node(3), 2 << 16, 1);
    let add = ops::set_add(&mut c, None, &Value::Int(5)).unwrap();
    let mut s = base.clone();
    s.join(rm);
    s.join(add);
    assert_eq!(s.read(), Some(Value::set(vec![Value::Int(5)])));
    assert_eq!(st_ty.enc(), 6);
}

#[test]
fn expiry_semantics() {
    // §4.7: expiry keeps stamps, so the expired write still beats older writes and loses to newer ones
    let exp = |w: &Writer| { let r = range(w); move |d: &Dot| in_ranges(std::slice::from_ref(&r))(d) };
    let mut a = Writer::new(Source::node(1), 2 << 16, 1);
    let da = ops::create(&mut a, &Ty::Register, &Value::Int(1));
    let mut old = Writer::new(Source::node(2), 1 << 16, 1);
    let dold = ops::create(&mut old, &Ty::Register, &Value::Int(0));
    let mut s = da.clone();
    s.strip(&exp(&a));
    s.join(dold.clone());
    s.strip(&exp(&a));
    assert_eq!(s.read(), None, "older write still loses to the expired one");
    let mut new = Writer::new(Source::node(3), 3 << 16, 1);
    s.join(ops::create(&mut new, &Ty::Register, &Value::Int(2)));
    assert_eq!(s.read(), Some(Value::Int(2)), "newer write wins");

    // map: a key repeated by another commit's record does not revive an entry whose creation expired
    let vt = Ty::Struct([(1, Ty::Register), (2, Ty::Register)].into_iter().collect());
    let mut a = Writer::new(Source::node(1), 1 << 16, 1);
    let put = ops::map_put(&mut a, None, &vt, &Value::Int(7), &Value::fields(vec![(1, Value::Int(1))])).unwrap();
    let mut b = Writer::new(Source::node(2), 2 << 16, 1);
    let edit = ops::map_put(&mut b, Some(&put), &vt, &Value::Int(7), &Value::fields(vec![(1, Value::Int(1)), (2, Value::Int(5))])).unwrap();
    let mut s = put.clone();
    s.join(edit.clone());
    assert_eq!(s.read(), Some(Value::map(vec![(Value::Int(7), Value::fields(vec![(1, Value::Int(1)), (2, Value::Int(5))]))])));
    s.strip(&exp(&a));
    assert_eq!(s.read(), Some(Value::map(vec![])), "entry with value-less creation is not live");
    s.join(edit);
    s.strip(&exp(&a));
    assert_eq!(s.read(), Some(Value::map(vec![])), "late copy of the key is ignored");

    // text: an expired insert stays as hidden anchors, inserts anchored to it keep their place
    let mut a = Writer::new(Source::node(1), 1 << 16, 1);
    let mut st: Option<Frag> = None;
    apply(&mut st, ops::seq_insert(&mut a, None, true, 0, "ab".chars().map(Content::Char).collect()));
    let base = st.unwrap();
    let mut x = Writer::new(Source::node(2), 2 << 16, 1);
    let dx = ops::seq_insert(&mut x, Some(&base), true, 1, "xy".chars().map(Content::Char).collect());
    let mut s = base.clone();
    s.join(dx.clone());
    let mut c = Writer::new(Source::node(3), 3 << 16, 1);
    let dz = ops::seq_insert(&mut c, Some(&s), true, 3, vec![Content::Char('z')]);
    s.join(dz);
    assert_eq!(s.read(), Some(Value::Str("axyzb".into())));
    s.strip(&exp(&x));
    assert_eq!(s.read(), Some(Value::Str("azb".into())));
    s.join(ops::seq_undelete(&mut c, &{ let mut t = base.clone(); t.join(dx.clone()); t }, &[Dot { source: Source::node(2), ctr: 1 }]));
    s.strip(&exp(&x));
    assert_eq!(s.read(), Some(Value::Str("azb".into())), "content repeated by an undelete is stripped");

    // enum: an expired case write leaves the enum absent
    let ty = kitchen_sink();
    let Ty::Struct(fts) = &ty else { unreachable!() };
    let mut a = Writer::new(Source::node(1), 1 << 16, 1);
    let mut s = ops::create(&mut a, &fts[&5], &Value::Enum(1, Some(Box::new(Value::Int(3)))));
    s.strip(&exp(&a));
    assert_eq!(s.read(), None);
}

#[test]
fn reset_keeps_newer_writes_as_anchors() {
    // §5.7/§6.2: a replace at t=5 prunes the old content but keeps every record as a bare anchor, so a concurrent
    // insert at t=6 anchored into the old content stays visible, placed after the new content (END order by dot).
    let s = |v: &str| v.chars().map(Content::Char).collect::<Vec<_>>();
    let mut a = Writer::new(Source::node(1), 1 << 16, 1);
    let mut st: Option<Frag> = None;
    apply(&mut st, ops::seq_insert(&mut a, None, true, 0, s("abc")));
    let base = st.clone().unwrap();
    a.next_commit(5 << 16);
    let rep = ops::replace(&mut a, &Ty::Text, &Value::Str("xyz".into()));
    let mut b = Writer::new(Source::node(2), 6 << 16, 1);
    let q = ops::seq_insert(&mut b, Some(&base), true, 2, s("q"));
    let mut s1 = base.clone();
    s1.join(rep.clone());
    s1.join(q.clone());
    let mut s2 = base.clone();
    s2.join(q);
    s2.join(rep.clone());
    assert_eq!(s1.read(), Some(Value::Str("xyzq".into())));
    assert_eq!(snapshot(&s1), snapshot(&s2));
    // an older concurrent insert (t=3) loses to the reset, as any older write does
    let mut c = Writer::new(Source::node(3), 3 << 16, 1);
    let old = ops::seq_insert(&mut c, Some(&base), true, 2, s("o"));
    let mut s3 = base.clone();
    s3.join(old);
    s3.join(rep.clone());
    assert_eq!(s3.read(), Some(Value::Str("xyz".into())));
    // a newer undelete of an element whose creation was reset revives the flag but not the content (§5.7)
    let mut d = Writer::new(Source::node(4), 2 << 16, 1);
    let del = ops::seq_delete(&mut d, &base, 1, 1).unwrap();
    let mut with_del = base.clone();
    with_del.join(del);
    assert_eq!(with_del.read(), Some(Value::Str("ac".into())));
    d.next_commit(6 << 16);
    let undel = ops::seq_undelete(&mut d, &base, &[Dot { source: Source::node(1), ctr: 2 }]);
    let mut s4 = with_del.clone();
    s4.join(rep.clone());
    s4.join(undel.clone());
    assert_eq!(s4.read(), Some(Value::Str("xyz".into())));
    let mut s5 = with_del.clone();
    s5.join(undel);
    s5.join(rep);
    assert_eq!(snapshot(&s4), snapshot(&s5));
    // remove_aspect: absent, anchors kept, re-creation works
    a.next_commit(7 << 16);
    let rm = ops::remove(&mut a, 9);
    s4.join(rm);
    assert_eq!(s4.read(), None);
    let bytes = snapshot(&s4);
    assert!(bytes.len() > 8, "bare anchors are carried");

    // cycle example (notes/crdt.md, Worked examples): acb, A moves a after b (t=5), B moves b after a (t=4): the later move wins -> cba
    let mut w = Writer::new(Source::node(1), 1 << 16, 1);
    let mut st: Option<Frag> = None;
    apply(&mut st, ops::seq_insert(&mut w, None, true, 0, s("acb")));
    let base = st.unwrap();
    let mut p = Writer::new(Source::node(2), 5 << 16, 1);
    let mut q = Writer::new(Source::node(3), 4 << 16, 1);
    let m1 = ops::seq_move(&mut p, &base, 0, 1, 2).unwrap();
    let m2 = ops::seq_move(&mut q, &base, 2, 1, 1).unwrap();
    let mut s1 = base.clone();
    s1.join(m1.clone());
    s1.join(m2.clone());
    let mut s2 = base.clone();
    s2.join(m2);
    s2.join(m1);
    assert_eq!(s1.read(), Some(Value::Str("cba".into())));
    assert_eq!(s1.read(), s2.read());

    // known anomaly (notes/crdt.md, Worked examples): abcd, move b to the end (t=5) and a concurrent insert x after a (t=4) -> acdbx
    let mut w = Writer::new(Source::node(1), 1 << 16, 1);
    let mut st: Option<Frag> = None;
    apply(&mut st, ops::seq_insert(&mut w, None, true, 0, s("abcd")));
    let base = st.unwrap();
    let mut p = Writer::new(Source::node(2), 5 << 16, 1);
    let mut q = Writer::new(Source::node(3), 4 << 16, 1);
    let mv = ops::seq_move(&mut p, &base, 1, 1, 3).unwrap();
    let ins = ops::seq_insert(&mut q, Some(&base), true, 1, s("x"));
    let mut s1 = base.clone();
    s1.join(mv);
    s1.join(ins);
    assert_eq!(s1.read(), Some(Value::Str("acdbx".into())));
}

#[test]
fn derived_anchor_outlives_its_register() {
    // §6.1/§4.7: P saw the valued register and embedded it; Q only ever saw it value-less. Both place an insert
    // anchored at an embedded character the same way after the register's commit expires.
    let mut a = Writer::new(Source::node(1), 1 << 16, 1);
    let reg = ops::create(&mut a, &Ty::Register, &Value::Str("ab".into()));
    let ra = range(&a);
    let mut text = crdt_model::embed::embed(&reg, 9).unwrap();
    text.prune(None);
    assert_eq!(text.read(), Some(Value::Str("ab".into())));
    let mut b = Writer::new(Source::node(2), 2 << 16, 1);
    let q = ops::seq_insert(&mut b, Some(&text), true, 1, vec![Content::Char('q')]);
    let mut p = text.clone();
    p.join(q.clone());
    assert_eq!(p.read(), Some(Value::Str("aqb".into())));
    p.strip(&in_ranges(std::slice::from_ref(&ra)));
    assert_eq!(p.read(), Some(Value::Str("q".into())));
    let mut lessr = reg.clone();
    lessr.strip(&|_| true);
    let mut qn = crdt_model::embed::embed(&lessr, 9).unwrap();
    qn.join(q);
    qn.strip(&in_ranges(std::slice::from_ref(&ra)));
    assert_eq!(qn.read(), p.read());
    assert_eq!(snapshot(&qn), snapshot(&p));
    // and a later register write by a new app still resets everything older, q included
    let mut c = Writer::new(Source::node(3), 3 << 16, 1);
    p.join(ops::create(&mut c, &Ty::Register, &Value::Str("zz".into())));
    assert_eq!(p.read(), Some(Value::Str("zz".into())));
}

proptest! {
    #![proptest_config(ProptestConfig { cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(64), .. ProptestConfig::default() })]

    #[test]
    fn join_laws_across_encodings(seed in any::<u64>()) {
        // §7: fragments of unrelated encodings meeting at one position still join
        // commutatively and associatively.
        let mut r = Rng(seed | 1);
        let Ty::Struct(fts) = kitchen_sink() else { unreachable!() };
        let tys: Vec<&Ty> = fts.values().collect();
        let mut frags = Vec::new();
        for i in 0..3u8 {
            let ty = tys[r.below(tys.len())];
            let mut w = Writer::new(Source::node(i + 1), ((r.below(4) as u64 + 1) << 16) + i as u64, 1);
            let mut st: Option<Frag> = None;
            for k in 0..3 {
                w.next_commit(w.ts + ((r.below(3) as u64) << 16) + 1 + k);
                if let Some(d) = random_op(&mut r, &mut w, ty, st.as_ref()) {
                    apply(&mut st, d);
                }
            }
            frags.push(st.unwrap_or_else(|| { let mut f = Frag::empty(ty.enc()); f.prune(None); f }));
        }
        let (a, b, c) = (&frags[0], &frags[1], &frags[2]);
        prop_assert_eq!(join3(a, b), join3(b, a), "commutative");
        prop_assert_eq!(join3(&join3(a, b), c), join3(a, &join3(b, c)), "associative");
        prop_assert_eq!(join3(a, a), a.clone(), "idempotent");
    }
}

/// Bootstrap convergence (§8, spec/commits.md §5 "covered"): a fresh node joins from a snapshot mid-way, everyone
/// keeps editing, and the fresh node ends up reading and snapshotting exactly what a full-history node does.
fn converge_bootstrap(seed: u64, ty: &Ty, rounds: usize) {
    let mut r = Rng(seed | 1);
    let n = 3;
    let mut reps: Vec<Replica> =
        (0..n).map(|i| Replica { w: Writer { keyed: i % 2 == 1, ..Writer::new(Source::node(i as u8 + 1), 1 << 16, 0) }, state: None, expired: vec![], received: Received::default() }).collect();
    let mut commits: Vec<Commit> = Vec::new();
    let mut joined_at = 0usize;
    for round in 0..rounds {
        if round == rounds / 2 {
            // deliver everything so far to replica 0, snapshot it, bootstrap a fresh replica from it
            for c in &commits {
                reps[0].apply(c.delta.clone());
                let (src, lo, hi) = range(&c.w);
                reps[0].received.add(&src, lo, hi);
            }
            let mut fresh = Replica { w: Writer::new(Source::node(9), 1 << 16, 0), state: None, expired: vec![], received: Received::default() };
            if let Some(st) = &reps[0].state {
                let (g, fr) = snapshot_transfer(st, &reps[0].received, &[]);
                fresh.apply(g);
                fresh.received.add_frontiers(&fr);
            }
            reps.push(fresh);
            joined_at = commits.len();
        }
        for i in 0..reps.len() {
            let ts = ((round as u64 * 10 + r.below(10) as u64 + 1) << 16) + i as u64;
            let rep = &mut reps[i];
            let t = ts.max(rep.w.ts + 1);
            let before = rep.w.clone();
            rep.w.next_commit(t);
            let Some(d) = random_op(&mut r, &mut rep.w, ty, rep.state.as_ref()) else {
                rep.w = before;
                continue;
            };
            let d = roundtrip(&d, &rep.w);
            rep.apply(d.clone());
            commits.push(Commit { w: rep.w.clone(), delta: d, expiring: false });
        }
        // random partial delivery of post-join commits to everyone, pre-join ones to the old replicas
        for i in 0..reps.len() {
            for (k, c) in commits.iter().enumerate() {
                if (k >= joined_at || i < n) && r.chance(1, 3) {
                    reps[i].apply(c.delta.clone());
                }
            }
        }
    }
    for i in 0..reps.len() {
        for (k, c) in commits.iter().enumerate() {
            if k >= joined_at || i < n {
                reps[i].apply(c.delta.clone());
            }
        }
    }
    let reads: Vec<Option<Value>> = reps.iter().map(|x| x.state.as_ref().and_then(|s| s.read())).collect();
    let snaps: Vec<Vec<u8>> = reps.iter().map(|x| x.state.as_ref().map_or(vec![], snapshot)).collect();
    for i in 1..reps.len() {
        assert_eq!(reads[0], reads[i], "reads converge (replica {i})");
        assert_eq!(snaps[0], snaps[i], "snapshots converge (replica {i})");
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(64), .. ProptestConfig::default() })]

    #[test]
    fn bootstrap_convergence_list(seed in any::<u64>()) {
        let ty = Ty::List(Box::new(Ty::Struct([(1, Ty::Register), (2, Ty::Text), (3, Ty::Set(Box::new(Ty::Register)))].into_iter().collect())));
        converge_bootstrap(seed, &ty, 8);
    }

    #[test]
    fn bootstrap_convergence_kitchen_sink(seed in any::<u64>()) {
        converge_bootstrap(seed, &kitchen_sink(), 6);
    }

    #[test]
    fn bootstrap_convergence_text(seed in any::<u64>()) {
        converge_bootstrap(seed, &Ty::Text, 10);
    }

    #[test]
    fn convergence_list_partial(seed in any::<u64>()) {
        let ty = Ty::List(Box::new(Ty::Struct([(1, Ty::Register), (2, Ty::Text)].into_iter().collect())));
        converge(seed, &ty, 3, 8, true, false);
    }
}

#[test]
fn list_delete_is_an_element_reset() {
    // §5.7, container resurrection: B deletes element 0 at t=5 while C writes a field into it at t=6; the element comes back
    // holding only C's field, on every node and after a snapshot bootstrap; an older nested write (t=4) is dropped.
    let et = Ty::Struct([(1, Ty::Register), (2, Ty::Register)].into_iter().collect());
    let ty = Ty::List(Box::new(et.clone()));
    let mut a = Writer::new(Source::node(1), 1 << 16, 1);
    let mut st: Option<Frag> = None;
    apply(&mut st, ops::create(&mut a, &ty, &Value::List(vec![Value::fields(vec![(1, Value::Int(1)), (2, Value::Int(2))])])));
    let base = st.clone().unwrap();
    let mut b = Writer::new(Source::node(2), 5 << 16, 1);
    let del = roundtrip(&ops::seq_delete(&mut b, &base, 0, 1).unwrap(), &b);
    let mut c = Writer::new(Source::node(3), 6 << 16, 1);
    let newer = roundtrip(&ops::seq_set_elem(&mut c, &base, &et, 0, &Value::fields(vec![(1, Value::Int(1)), (2, Value::Int(9))])).unwrap(), &c);
    let mut d = Writer::new(Source::node(4), 4 << 16, 1);
    let older = roundtrip(&ops::seq_set_elem(&mut d, &base, &et, 0, &Value::fields(vec![(1, Value::Int(7)), (2, Value::Int(2))])).unwrap(), &d);
    let mut s1 = base.clone();
    s1.join(del.clone());
    assert_eq!(s1.read(), Some(Value::List(vec![])));
    s1.join(older.clone());
    assert_eq!(s1.read(), Some(Value::List(vec![])), "older nested write loses to the reset");
    s1.join(newer.clone());
    assert_eq!(s1.read(), Some(Value::List(vec![Value::fields(vec![(2, Value::Int(9))])])), "newer nested write revives the element alone");
    let mut s2 = base.clone();
    s2.join(newer.clone());
    s2.join(older.clone());
    s2.join(del.clone());
    assert_eq!(snapshot(&s1), snapshot(&s2));
    // the scenario that used to diverge: A's snapshot must carry C's write, so a bootstrapped node reads the same
    let (g, _) = snapshot_transfer(&s1, &Received::default(), &[]);
    let mut fresh: Option<Frag> = None;
    apply(&mut fresh, g);
    assert_eq!(fresh.as_ref().unwrap().read(), s1.read());
    assert_eq!(snapshot(fresh.as_ref().unwrap()), snapshot(&s1));
    // the deleted element's body is covered by the snapshot only if joining it changes nothing
    let mut again = fresh.clone().unwrap();
    again.join(newer);
    assert_eq!(snapshot(&again), snapshot(&s1), "covered: the newer write is already in the snapshot");
    // a value-less (expired) list creation keeps others' nested writes (§4.7)
    let mut s3 = base.clone();
    let mut e = Writer::new(Source::node(5), 7 << 16, 1);
    let later = ops::seq_set_elem(&mut e, &base, &et, 0, &Value::fields(vec![(1, Value::Int(1)), (2, Value::Int(3))])).unwrap();
    s3.join(later);
    s3.strip(&in_ranges(&[range(&a)]));
    assert_eq!(s3.read(), Some(Value::List(vec![Value::fields(vec![(2, Value::Int(3))])])));
}

#[test]
fn decoder_rejects_writer_rule_violations() {
    use crdt_model::stamp::Stamp;
    let own = Source::node(1);
    let ts = 3 << 16;
    let enc = |f: &Frag| encode_delta(f, [1; 16], &mut Ctx::new(ts, own.clone(), 5));
    // own stamp outside [lo, hi)
    let f = Frag::Register { reset: None, write: Some((Stamp::new(ts, own.clone(), 7), Some(Value::Int(1)))) };
    assert!(decode_delta(&enc(&f), &mut Ctx::writer(ts, own.clone(), 5, 6)).is_err());
    assert!(decode_delta(&enc(&f), &mut Ctx::writer(ts, own.clone(), 5, 8)).is_ok());
    assert!(decode_delta(&enc(&f), &mut Ctx::new(ts, own.clone(), 5)).is_ok(), "an import or snapshot context checks no range");
    // a foreign stamp in a writer's delta
    let f = Frag::Register { reset: None, write: Some((Stamp::new(2 << 16, Source::node(2), 1), Some(Value::Int(1)))) };
    assert!(decode_delta(&enc(&f), &mut Ctx::writer(ts, own.clone(), 5, 6)).is_err());
    assert!(decode_delta(&enc(&f), &mut Ctx::new(ts, own.clone(), 5)).is_ok());
    // a run of own elements reaching hi, though its first dot is below lo (§2.3)
    let flags = |n: u64| {
        let el = || crdt_model::state::SeqElem { created: None, content: Content::None, pos: vec![], deleted: Some((Stamp::new(ts, own.clone(), 5), true)) };
        let elems = (0..n).map(|i| (Dot { source: own.clone(), ctr: 3 + i }, el())).collect();
        enc(&Frag::Seq { text: true, c: Default::default(), elems })
    };
    assert!(decode_delta(&flags(2), &mut Ctx::writer(ts, own.clone(), 5, 6)).is_ok());
    assert!(decode_delta(&flags(4), &mut Ctx::writer(ts, own.clone(), 5, 6)).is_err());
    // repeated own counter: two set elements created with one counter
    let mut elems = std::collections::BTreeMap::new();
    let reg = |v: i64| Some(Box::new(Frag::Register { reset: None, write: Some((Stamp::new(ts, own.clone(), 5), Some(Value::Int(v)))) }));
    elems.insert(Dot { source: own.clone(), ctr: 5 }, crdt_model::state::Elem { reset: None, frag: reg(1) });
    elems.insert(Dot { source: own.clone(), ctr: 6 }, crdt_model::state::Elem { reset: None, frag: reg(2) });
    let f = Frag::Set { c: Default::default(), elems };
    assert!(decode_delta(&enc(&f), &mut Ctx::writer(ts, own.clone(), 5, 7)).is_ok());
    let mut w = Writer::new(own.clone(), ts, 5);
    let d = ops::create(&mut w, &Ty::Set(Box::new(Ty::Register)), &Value::set(vec![Value::Int(1), Value::Int(2)]));
    assert!(decode_delta(&enc(&d), &mut Ctx::writer(ts, own.clone(), 5, w.hi())).is_ok());
    // an undelete flag in a list run, and a posw order violation, are rejected
    let mut w = Writer::new(own.clone(), ts, 1);
    let et = Ty::Register;
    let mut st: Option<Frag> = None;
    apply(&mut st, ops::create(&mut w, &Ty::List(Box::new(et)), &Value::List(vec![Value::Int(1), Value::Int(2)])));
    let base = st.unwrap();
    let mut b = Writer::new(Source::node(2), 4 << 16, 1);
    let del = ops::seq_delete(&mut b, &base, 0, 1).unwrap();
    let mut bytes = encode_delta(&del, [1; 16], &mut Ctx::new(b.ts, b.source.clone(), b.lo));
    assert!(decode_delta(&bytes, &mut Ctx::writer(b.ts, b.source.clone(), b.lo, b.hi())).is_ok());
    // flip the flag byte (CBOR true 0xf5 -> false 0xf4)
    let p = bytes.iter().rposition(|x| *x == 0xf5).unwrap();
    bytes[p] = 0xf4;
    assert!(decode_delta(&bytes, &mut Ctx::writer(b.ts, b.source.clone(), b.lo, b.hi())).is_err());
}

/// spec §2.2, §7: an embedded character sorts right after the register write it embeds, so a reset
/// above the write removes its characters too, in any delivery order.
#[test]
fn embedded_chars_order_right_after_their_write() {
    use crdt_model::stamp::{Dot, Stamp};
    use crdt_model::state::{Anchor, Composite, SeqElem};
    use std::collections::BTreeMap;
    let t0 = 1000u64 << 16;
    let st = |n: u8, c: u64| Stamp::new(t0, Source::node(n), c);
    let s = st(1, 5);
    let reg = Frag::Register { reset: None, write: Some((s.clone(), Some(Value::Str("ab".into())))) };
    let reset = Frag::Register { reset: Some(st(9, 1)), write: None };
    let d2 = Dot { source: Source::Derived(Box::new(s.dot.clone())), ctr: 2 };
    let ti = st(4, 1);
    let mut el = BTreeMap::new();
    el.insert(ti.dot.clone(), SeqElem::new(ti.clone(), Anchor::Dot(d2), Content::Char('x')));
    let text = Frag::Seq { text: true, c: Composite::default(), elems: el };
    let run = |order: &[&Frag]| {
        let mut a = Frag::empty(0);
        for f in order {
            a.join((*f).clone());
        }
        a
    };
    let a = run(&[&reg, &text, &reset]);
    let b = run(&[&reset, &reg, &text]);
    let c = run(&[&text, &reset, &reg]);
    assert_eq!(a, b);
    assert_eq!(a, c);
}

/// spec §3.3 rule 3, rule 7, §7 Canonical form: the decoder rejects a register reset below the
/// root, runs that are not maximal, and `Slots` members that are empty or add nothing to the
/// register's embedding; the canonical forms decode.
#[test]
fn decoder_rejects_rule_7_strict() {
    use crdt_model::cbor::{encode, Item};
    use crdt_model::stamp::Stamp;
    use crdt_model::state::Composite;
    use std::collections::BTreeMap;
    let own = Source::node(1);
    let ts = 3 << 16;
    let wcx = |hi: u64| Ctx::writer(ts, own.clone(), 1, hi);
    let enc = |f: &Frag| encode_delta(f, [1; 16], &mut Ctx::new(ts, own.clone(), 1));
    // a register reset at the root, and below it
    let reg = Frag::Register { reset: Some(Stamp::new(ts, own.clone(), 1)), write: None };
    assert!(decode_delta(&enc(&reg), &mut wcx(2)).is_ok());
    let nested = Frag::Struct { c: Composite::default(), fields: BTreeMap::from([(1, reg.clone())]) };
    assert!(decode_delta(&enc(&nested), &mut wcx(2)).is_err());
    // two chars created by one commit, the second anchored at the first: one run, never two
    let i = |n: i64| Item::Int(n);
    let a = |v: Vec<Item>| Item::Array(v);
    let delta = |runs: Vec<Item>| encode(&a(vec![Item::Bytes(vec![1; 16]), a(vec![]), a(vec![]), a(vec![i(9), a(vec![]), a(vec![]), a(runs)])]));
    let run = |dot: i64, n: i64, anchor: i64, text: &str| a(vec![i(dot), i(n), a(vec![i(anchor), a(vec![a(vec![i(0), i(n)])])]), Item::Text(text.into()), a(vec![]), a(vec![])]);
    assert!(decode_delta(&delta(vec![run(1, 2, 0, "ab")]), &mut wcx(3)).is_ok());
    assert!(decode_delta(&delta(vec![run(1, 1, 0, "a"), run(2, 1, 1, "b")]), &mut wcx(3)).is_err());
    // the second anchored elsewhere (HEAD): two runs are canonical
    assert!(decode_delta(&delta(vec![run(1, 1, 0, "a"), run(2, 1, 0, "b")]), &mut wcx(3)).is_ok());
    // a snapshot's `Slots`: a set member equal to the register's embedding adds nothing
    let s = Stamp::new(ts, Source::node(2), 1);
    let r = Frag::Register { reset: None, write: Some((s.clone(), Some(Value::Str("x".into())))) };
    let slots = |set: Frag| Frag::Slots { reg: Some(Box::new(r.clone())), slots: BTreeMap::from([(6u8, set)]) };
    let snap = |f: &Frag| encode_snapshot(f, &[], [0; 16], &mut Ctx::new(1 << 40, Source::node(250), 1));
    let dec = |b: &[u8]| decode_snapshot(b, &mut Ctx::new(1 << 40, Source::node(250), 1));
    let bare = Frag::Set { c: Composite { reset: Some(s.clone()), w: None }, elems: BTreeMap::new() };
    assert!(dec(&snap(&slots(bare))).is_err());
    let mut w = Writer::new(Source::node(3), 4 << 16, 1);
    let set = ops::create(&mut w, &Ty::Set(Box::new(Ty::Register)), &Value::set(vec![Value::Int(1)]));
    let mut joined = Frag::empty(0);
    joined.join(r.clone());
    joined.join(set);
    assert!(matches!(joined, Frag::Slots { .. }), "{joined:?}");
    assert!(dec(&snap(&joined)).is_ok());
}

/// spec §3.2 (set elements), §5.5: a set element of a struct type is one register holding the
/// whole value; the decoder rejects a set or bag element whose fragment is not a register.
#[test]
fn set_element_is_a_register_spec_3_2() {
    use crdt_model::state::{Composite, Elem};
    use std::collections::BTreeMap;
    let own = Source::node(1);
    let ts = 3 << 16;
    let pair = Ty::Struct([(1, Ty::Register), (2, Ty::Register)].into_iter().collect());
    let v = Value::fields(vec![(1, Value::Int(1)), (2, Value::Int(2))]);
    let mut w = Writer::new(own.clone(), ts, 1);
    let f = ops::create(&mut w, &Ty::Set(Box::new(pair.clone())), &Value::set(vec![v.clone()]));
    let Frag::Set { elems, .. } = &f else { panic!("set") };
    let e = elems.values().next().unwrap();
    assert!(matches!(e.frag.as_deref(), Some(Frag::Register { reset: None, write: Some((_, Some(x))) }) if *x == v));
    let enc = |f: &Frag| encode_delta(f, [1; 16], &mut Ctx::new(ts, own.clone(), 1));
    let wcx = || Ctx::writer(ts, own.clone(), 1, 3);
    assert!(decode_delta(&enc(&f), &mut wcx()).is_ok());
    // the same element as a nested struct fragment
    let mut w = Writer::new(own.clone(), ts, 1);
    let d = w.stamp().dot;
    let nested = ops::create(&mut w, &pair, &v);
    let bad = Frag::Set { c: Composite::default(), elems: BTreeMap::from([(d, Elem { reset: None, frag: Some(Box::new(nested)) })]) };
    assert!(decode_delta(&enc(&bad), &mut wcx()).is_err());
}

/// spec/crdt.md §3.2 (entry creation `Ci`), §8 (`Authors`): a snapshot of a commit-form writer's
/// map carries each entry's creation commit and the commit's author; both round-trip, an empty
/// `Authors` is omitted, and a writer's own creations carry no `Ci`.
#[test]
fn snapshot_authors_and_creations_round_trip() {
    use crdt_model::wire::{decode_snapshot_authors, encode_snapshot_authors, Authors};
    let c = [9u8; 32];
    let mut w = Writer { source: Source::Commit(c), ts: 7 << 16, lo: 1, next: 1, keyed: false };
    let ty = Ty::Map(Box::new(Ty::Register), Box::new(Ty::Register));
    let v = Value::map(vec![(Value::Int(1), Value::Int(10)), (Value::Int(2), Value::Int(20))]);
    let f = ops::create(&mut w, &ty, &v);
    let Frag::Map { entries, .. } = &f else { panic!("a map") };
    assert!(entries.values().all(|e| e.created.is_some()), "creations recorded");
    // the writer's own delta: creations implied
    let own = roundtrip(&f, &w);
    assert_eq!(own, f);
    let authors: Authors = [(c, ([1; 15], 7 << 16))].into_iter().collect();
    let mut cx = Ctx::new(1 << 40, Source::node(250), 1);
    let bytes = encode_snapshot_authors(&f, &[], &authors, [3; 16], &mut cx);
    let (g, _, au) = decode_snapshot_authors(&bytes, &mut Ctx::new(1 << 40, Source::node(250), 1)).expect("decodes");
    assert_eq!(g, f, "creations carried");
    assert_eq!(au, authors);
    assert_eq!(encode_snapshot_authors(&g, &[], &au, [3; 16], &mut Ctx::new(1 << 40, Source::node(250), 1)), bytes);
    let plain = encode_snapshot(&f, &[], [3; 16], &mut Ctx::new(1 << 40, Source::node(250), 1));
    let (_, _, none) = decode_snapshot_authors(&plain, &mut Ctx::new(1 << 40, Source::node(250), 1)).expect("decodes");
    assert!(none.is_empty() && plain.len() < bytes.len());
}
