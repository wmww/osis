//! Evidence completeness (held_model::evidence; notes/evidence-model-findings.md): hand worlds
//! for each finding and named risk, a slice of the family as a default test, and the sampled
//! searches (`_plain`, `_large`). `explore` prints every rule variant's failures (by hand).
use held_model::evidence::names::*;
use held_model::evidence::*;
use roles_model::paths::{Id, Set};
use roles_model::Role;
use std::collections::BTreeMap;

/// Every check at every step, and the arrival-order check at the end: the failures.
fn fails(w: &World, rule: &Rule) -> Vec<Fail> {
    let mut out = vec![];
    let st = w.run(rule, |st| out.extend(w.p1(rule, st)));
    assert!(!st.unsettled, "logging settles");
    out.extend(w.p3(rule, &st));
    out.extend(w.p4(rule, &st, true));
    out.extend(w.p5_order(rule, &st, 5).0);
    out
}

fn props(f: &[Fail]) -> Vec<&'static str> {
    let mut p: Vec<&str> = f.iter().map(|f| f.prop).collect();
    p.sort();
    p.dedup();
    p
}

/// K writes D through [A, O]; O is W's, and W syncs O alone; X (syncing A) removes K, listing
/// nothing. No honest node syncs both O and D.
fn org_apart() -> World {
    family(Shape { via_org: true, units: 0, listed: false, thief: false, regrant: false, addendum: false, raised: false, q_d: false, q_r: false, y_a: false, org_apart: true, vouch: false })
}

/// Finding 1: the remover's errand by direct taken grants (A's grant on O) never reaches D, two
/// grants below the removed edge: D's reader judges K's write valid, the node holding everything
/// invalid. Followed to the end of the taken grants (O's grant on D, under O's sync ID) it does.
#[test]
fn f1_a_direct_errand_misses_a_unit_two_grants_below_the_removed_edge() {
    let w = org_apart();
    let f = fails(&w, &Rule::design());
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == D && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{f:?}");
    assert!(f.iter().any(|f| f.prop == "P3" && f.sid == D));
    assert_eq!(fails(&w, &Rule::fixed()), vec![]);
}

/// Finding 2, Risk 2: copies placed when their commit is logged and never placed again. O (on
/// K's path) leaves R's unit after K's write: A's grant on O was R's body, so no copy was placed,
/// and it leaves R with O: R's reader pends on K's write for good.
#[test]
fn f2_copies_placed_at_logging_leave_a_sync_id_short_when_a_unit_changes() {
    let mut sh = Shape::nth(0);
    (sh.via_org, sh.units, sh.listed) = (true, 4, true);
    let w = family(sh);
    let atlog = Rule { placement: Placement::AtLog, ..Rule::design() };
    let f = fails(&w, &atlog);
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == R && f.reader == Some(Verdict::Pending) && f.full == Some(Verdict::Valid)), "{f:?}");
    assert_eq!(fails(&w, &Rule::design()), vec![]);
    // D in R's unit from the start: a removal is no body of either, so placed with nothing it
    // reaches R only by the errand, which goes to D's own sync ID
    let mut sh = Shape::nth(0);
    sh.units = 1;
    let f = fails(&family(sh), &atlog);
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == R && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{f:?}");
    assert_eq!(fails(&family(sh), &Rule::design()), vec![]);
}

/// Finding 3, Risk 4: A only reads D when K is removed, so the errand finds no unit where K could
/// write; Y raises A to write later and the stolen K writes D. An errand run once, at the
/// removal, never logs it under D; the standing duty logs it once the raise shows D.
#[test]
fn f3_an_errand_run_once_misses_a_holder_raised_after_the_removal() {
    let mut sh = Shape::nth(0);
    (sh.raised, sh.thief) = (true, true);
    let w = family(sh);
    let f = fails(&w, &Rule { standing: false, ..Rule::design() });
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == D && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{f:?}");
    assert_eq!(fails(&w, &Rule::design()), vec![]);
}

/// Finding 4: K (admin of A) grants Z on A; Z writes D; X removes K, its frontier listing the
/// grant in A's leaf. D's reader seeing only its unit's leaves reads the grant unlisted and drops
/// it (roles-model finding 5, reached here through units): the copy of a lowering carries its leaf
/// for the thing it is on.
#[test]
fn f4_a_reader_needs_the_leaf_of_each_evidence_copy() {
    let pw = roles_model::paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, k, z) = (w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[A]), w.node(true, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Admin, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    let gz = w.write(k, |p| p.edge(K, 2, &[], A, Z, Role::Write, &[]));
    let zc = w.write(z, |p| p.content(Z, 3, &[A], D));
    w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[gz]));
    let f = fails(&w, &Rule { leaves: Leaves::Unit, ..Rule::fixed() });
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == D && f.id == zc && f.reader == Some(Verdict::Invalid)), "{f:?}");
    assert_eq!(fails(&w, &Rule::fixed()), vec![]);
}

/// Finding 5: a reader holding part of a path's evidence judges where it should wait. D's reader
/// holds K's write and K's grant on A but not X's earlier removal (stamped before the write): no
/// edge lacks a setter, so the write is not pending, and it reads valid until the removal comes.
/// No rule over the held set alone tells it apart: only a complete pass of D's sync ID does.
#[test]
fn f5_partial_evidence_judges_before_a_complete_pass() {
    let mut sh = Shape::nth(0);
    sh.thief = true;
    let w = family(sh);
    let st = w.run(&Rule::fixed(), |_| {});
    // the thief's write (stamped after the removal) without the removal
    let thief = *st.entries[&D].iter().max().unwrap();
    let r = st.written.iter().copied().find(|&i| w.removes(i).is_some()).unwrap();
    let v = w.reader(&Rule::fixed(), &st, D, &Set::from([r]));
    assert_eq!(w.verdicts(&v, &Set::from([thief]))[&thief], Verdict::Valid);
    assert_eq!(w.verdicts(&w.reader(&Rule::fixed(), &st, D, &Set::new()), &Set::from([thief]))[&thief], Verdict::Invalid);
    // with no edge write on K's edge at all, it pends
    let g = 0;
    let v = w.reader(&Rule::fixed(), &st, D, &Set::from([g, r]));
    assert_eq!(w.verdicts(&v, &Set::from([thief]))[&thief], Verdict::Pending);
    // and judged from the same partial evidence the node holding everything else agrees (locality)
    assert_eq!(w.p5_order(&Rule::fixed(), &st, 5).0, vec![]);
}

/// Risk 3: a stolen node's first write on E, a dependent of R reached only through R (A holds
/// write on R; K writes E along [A, R], its last hop R's record edge). X syncs A alone, Y syncs R
/// alone. The errand logs X's removal under R (A's taken grant); without it R's reader judges the
/// write valid.
#[test]
fn risk3_a_first_write_through_an_enclosing_root() {
    let pw = roles_model::paths::World::new(&[(X, A), (Y, R), (R, E)]);
    let mut w = World::new(pw, &[A, R]);
    w.member(E, R);
    let (x, y, k) = (w.node(true, &[A]), w.node(true, &[R]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], R, A, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    let late = w.write(k, |p| p.content(K, 8, &[A, R], E));
    assert_eq!(fails(&w, &Rule::design()), vec![]);
    let f = fails(&w, &Rule { errand: Errand::Off, ..Rule::design() });
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == R && f.id == late && f.reader == Some(Verdict::Valid)), "{f:?}");
}

/// P2: D under its own sync ID and R's, joining R between K's write and the removal: both
/// readers judge every write alike, by their own evidence (the removal reaches R through Y, who
/// syncs D and R).
#[test]
fn p2_a_write_under_two_sync_ids_is_judged_alike_by_each() {
    for units in [1, 2, 3] {
        let mut sh = Shape::nth(0);
        (sh.units, sh.thief) = (units, true);
        let w = family(sh);
        let st = w.run(&Rule::fixed(), |_| {});
        assert_eq!(fails(&w, &Rule::fixed()), vec![]);
        if units != 3 {
            let both: Vec<Id> = w.owed_bodies(&st, D).intersection(&w.owed_bodies(&st, R)).copied().collect();
            assert!(both.len() >= 2, "{both:?}");
        }
    }
}

/// P4: forgetting K's writes takes the copy of K's grant out of D's sync ID; nothing else moves.
#[test]
fn p4_evidence_leaves_with_the_last_commit_that_needed_it() {
    let mut sh = Shape::nth(0);
    sh.listed = true;
    let w = family(sh);
    let rule = Rule::fixed();
    let mut st = w.run(&rule, |_| {});
    let gk = 0;
    assert!(w.copies(&st, D).contains(&gk));
    let kw: Vec<Id> = st.entries[&D].iter().copied().filter(|&i| w.w.commits[i].signer == K).collect();
    for i in kw {
        w.forget(&rule, &mut st, i);
    }
    assert!(!w.copies(&st, D).contains(&gk), "{:?}", st.entries[&D]);
    assert_eq!(w.p4(&rule, &st, true), vec![]);
}

/// P6: copies under D after n writes along a path of k holder things, m of them outside D's
/// unit: one per edge write on an outside thing, shared by every write (none per commit).
#[test]
fn p6_copies_are_shared_by_the_writes_along_a_path() {
    for (k, m) in [(1, 1), (2, 1), (2, 2), (3, 2), (3, 3)] {
        let (c1, b1) = cost(3, k, m);
        let (c10, b10) = cost(30, k, m);
        assert_eq!((c1, c10), (m, m), "k {k} m {m}");
        assert_eq!(b10 - b1, 27);
    }
}

/// P1 to P5 over a slice of the family under the fixed rule; the design fails only where
/// finding 1 says.
#[test]
fn p1_to_p5_hold_on_a_slice_of_the_family() {
    for i in (0..FAMILY).step_by(97) {
        let sh = Shape::nth(i);
        let w = family(sh);
        assert_eq!(fails(&w, &Rule::fixed()), vec![], "{sh:?}");
        let d = fails(&w, &Rule::design());
        assert!(d.is_empty() || (sh.via_org && sh.org_apart), "{sh:?} {d:?}");
    }
}

/// The random worlds' seeds: `n` from `OSIS_HELD_START` (default 0).
fn seeds(n: u64) -> std::ops::Range<u64> {
    let start = std::env::var("OSIS_HELD_START").ok().filter(|v| !v.is_empty()).map_or(0, |v| v.parse::<u64>().expect("OSIS_HELD_START is a decimal u64"));
    eprintln!("evidence: random seeds {start}..{}", start + n);
    start..start + n
}

/// P1 to P5 under the fixed rule over every `family_step`th family world and `random` random
/// worlds of 14 moves, a thread per core.
fn search(family_step: usize, random_worlds: u64) {
    let rule = Rule::fixed();
    let mut jobs: Vec<Box<dyn Fn() -> (String, Vec<Fail>) + Sync>> = vec![];
    for i in (0..FAMILY).step_by(family_step) {
        jobs.push(Box::new(move || (format!("{:?}", Shape::nth(i)), fails(&family(Shape::nth(i)), &rule))));
    }
    for seed in seeds(random_worlds) {
        jobs.push(Box::new(move || (format!("random seed {seed}"), fails(&random(seed, 14), &rule))));
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let bad = std::sync::Mutex::new(vec![]);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let Some(j) = jobs.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) else { return };
                let (name, f) = j();
                if !f.is_empty() {
                    bad.lock().unwrap().push(format!("{name}: {:?} {:?}", props(&f), f[0]));
                }
            });
        }
    });
    let bad = bad.into_inner().unwrap();
    assert!(bad.is_empty(), "{} worlds fail, first: {}", bad.len(), bad[0]);
}

#[test]
#[ignore = "property"]
fn one_sync_id_reader_judges_as_everything_plain() {
    search(17, 40);
}

#[test]
#[ignore = "property"]
fn one_sync_id_reader_judges_as_everything_large() {
    search(5, 400);
}

fn variants() -> Vec<(&'static str, Rule)> {
    let d = Rule::design();
    vec![
        ("design", d),
        ("atlog", Rule { placement: Placement::AtLog, ..d }),
        ("no-errand", Rule { errand: Errand::Off, ..d }),
        ("transitive", Rule { errand: Errand::Transitive, ..d }),
        ("edge", Rule { scope: Scope::Edge, ..d }),
        ("transitive+edge", Rule { errand: Errand::Transitive, scope: Scope::Edge, ..d }),
        ("unit-leaves", Rule { leaves: Leaves::Unit, ..d }),
        ("once", Rule { standing: false, ..d }),
    ]
}

/// Every check at every step of `w` under `rule`: failures by property.
fn tally(w: &World, rule: &Rule, out: &mut BTreeMap<&'static str, usize>, first: &mut BTreeMap<&'static str, String>) {
    let mut note = |f: &Fail, out: &mut BTreeMap<&'static str, usize>| {
        *out.entry(f.prop).or_default() += 1;
        first.entry(f.prop).or_insert_with(|| format!("{f:?}"));
    };
    let st = w.run(rule, |st| {
        for f in w.p1(rule, st) {
            note(&f, out);
        }
    });
    if st.unsettled {
        *out.entry("unsettled").or_default() += 1;
    }
    for f in w.p3(rule, &st).iter().chain(&w.p4(rule, &st, true)) {
        note(f, out);
    }
}

#[test]
#[ignore = "by hand"]
fn explore() {
    let lines: Vec<String> = std::thread::scope(|sc| {
        let hs: Vec<_> = variants()
            .into_iter()
            .map(|(name, rule)| {
                sc.spawn(move || {
                    let mut out = BTreeMap::<&str, usize>::new();
                    let mut first = BTreeMap::new();
                    let mut worlds = BTreeMap::<&str, usize>::new();
                    for i in 0..FAMILY {
                        let w = family(Shape::nth(i));
                        let mut o = BTreeMap::<&str, usize>::new();
                        let mut f1 = BTreeMap::new();
                        tally(&w, &rule, &mut o, &mut f1);
                        for (k, v) in o {
                            *out.entry(k).or_default() += v;
                            *worlds.entry(k).or_default() += 1;
                        }
                        for (k, v) in f1 {
                            first.entry(k).or_insert(format!("{:?} {v}", Shape::nth(i)));
                        }
                    }
                    let mut s = format!("{name}: {out:?} worlds {worlds:?}\n");
                    for (k, v) in first {
                        s += &format!("  {k}: {v}\n");
                    }
                    s
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for l in lines {
        eprint!("{l}");
    }
}

#[test]
#[ignore = "by hand"]
fn explore_random() {
    let lines: Vec<String> = std::thread::scope(|sc| {
        let hs: Vec<_> = variants()
            .into_iter()
            .map(|(name, rule)| {
                sc.spawn(move || {
                    let mut out = BTreeMap::<&str, usize>::new();
                    let mut first = BTreeMap::new();
                    let mut prov = 0;
                    for seed in 0..300u64 {
                        let w = random(seed, 12);
                        let mut f1 = BTreeMap::new();
                        tally(&w, &rule, &mut out, &mut f1);
                        let st = w.run(&rule, |_| {});
                        let (o, p) = w.p5_order(&rule, &st, 5);
                        prov += p;
                        for f in o {
                            *out.entry(f.prop).or_default() += 1;
                            f1.entry(f.prop).or_insert(format!("{f:?}"));
                        }
                        for (k, v) in f1 {
                            first.entry(k).or_insert(format!("seed {seed} {v}"));
                        }
                    }
                    let mut s = format!("{name}: {out:?} provisional {prov}\n");
                    for (k, v) in first {
                        s += &format!("  {k}: {v}\n");
                    }
                    s
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for l in lines {
        eprint!("{l}");
    }
}

#[test]
#[ignore = "by hand"]
fn random_shape() {
    let (mut v, mut n) = (BTreeMap::<Verdict, usize>::new(), 0);
    for seed in 0..100 {
        let w = random(seed, 14);
        let st = w.run(&Rule::design(), |_| {});
        for (_, x) in w.verdicts(&w.full(&st, &Default::default()), &st.written) {
            *v.entry(x).or_default() += 1;
        }
        n += st.entries.values().map(|e| e.len()).sum::<usize>();
    }
    eprintln!("{v:?} entries {n}");
}

/// Prints random world `OSIS_HELD_START`'s events and the first failures (by hand).
#[test]
#[ignore = "by hand"]
fn show_random() {
    let seed: u64 = std::env::var("OSIS_HELD_START").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let w = random(seed, 12);
    show(&w, &Rule::design());
}

pub fn show(w: &World, rule: &Rule) {
    eprintln!("units {:?}", w.units);
    for (n, node) in w.nodes.iter().enumerate() {
        eprintln!("node {n} {node:?}");
    }
    for e in &w.events {
        match e {
            Ev::Write(i) => eprintln!("  {i}: by {} {:?}", w.by[*i], w.w.commits[*i]),
            e => eprintln!("  {e:?}"),
        }
    }
    let st = w.run(rule, |st| {
        for f in w.p1(rule, st) {
            eprintln!("{f:?}");
        }
    });
    eprintln!("entries {:?}", st.entries);
    eprintln!("final units {:?}", st.units);
    for f in w.p3(rule, &st).iter().chain(&w.p4(rule, &st, true)) {
        eprintln!("{f:?}");
    }
    let fv = w.verdicts(&w.full(&st, &Default::default()), &st.written);
    eprintln!("full {fv:?}");
    for (n, h) in st.held.iter().enumerate() {
        for &s in &w.syncs(n, &st.units) {
            eprintln!("node {n} sid {s} req {:?}", w.req(rule, s, &st.units, h));
        }
    }
    for &s in &w.sids {
        eprintln!("reader {s} req {:?}", w.req(rule, s, &st.units, &st.entries[&s]));
    }
}
