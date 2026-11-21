//! OPEN 10 (notes/a2-spec/README.md; notes/evidence-model-findings.md 11, 13 on): which edge writes
//! and which stated paths the evidence closure takes. Each variant (`Open10`) on hand worlds, one
//! per property it can fail: P1 (a one-sync-ID reader judges as the node holding everything), P9
//! (no copy of a roster that gives no role on the unit), P10 (no copy of a write no walk applies),
//! the cost a non-admin and an admin can force.
use held_model::evidence::names::*;
use held_model::evidence::*;
use roles_model::paths::{self, Set, Thing};
use roles_model::Role;

/// P0 to P10 at every step and at the end, as `spec_evidence::fails` with the OPEN 10 checks.
pub fn fails(w: &World, rule: &Rule) -> Vec<Fail> {
    fails_at(w, rule, &(1..=w.events.len()).collect())
}

/// `fails`, the per-step checks at the steps `at` (the state after that many events).
pub fn fails_at(w: &World, rule: &Rule, at: &std::collections::BTreeSet<usize>) -> Vec<Fail> {
    let mut out = vec![];
    let st = w.run(rule, |st| {
        if at.contains(&st.step) {
            out.extend(w.p1(rule, st));
            out.extend(w.p9_leak(rule, st));
            out.extend(w.p10_junk(rule, st));
        }
    });
    assert!(!st.unsettled, "logging settles");
    out.extend(w.p0_applied_chained(&st));
    out.extend(w.p4(rule, &st, true));
    out.extend(w.p5_order(rule, &st, 5).0);
    out.extend(w.p8_promotions(rule, &st, PromoteWhen::AfterPass, 0));
    out
}

/// The properties `w` fails under each of `vs` (of `Rule::fixed`).
fn by_variant(w: &World, vs: &[Open10]) -> Vec<(&'static str, Vec<&'static str>)> {
    vs.iter()
        .map(|v| {
            let mut w = w.clone();
            let rule = v.set(&mut w, Rule::fixed());
            let mut p: Vec<&str> = fails(&w, &rule).iter().map(|f| f.prop).collect();
            p.sort();
            p.dedup();
            (v.name(), p)
        })
        .collect()
}

/// X mints A (K, Q writers), Y mints D (A writes it); X syncs A, Y syncs D, Q syncs A, K (no
/// admin) is hostile.
fn base() -> (World, [usize; 4]) {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let n = [w.node(true, &[A]), w.node(true, &[D]), w.node(false, &[A]), w.node(true, &[A])];
    w.write(n[0], |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(n[1], |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    (w, n)
}

/// D's copies with `n` junk grants by K (a writer of A, no admin) on Q's edge, Q writing D
/// through [A] after X's grant: finding 11's cost.
fn junk_copies(v: Open10, n: u32) -> usize {
    let (mut w, [x, _, k, q]) = base();
    w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Write, &[]));
    for i in 0..n {
        w.write(k, |p| p.edge(K, 2 + i, &[], A, Q, Role::Admin, &[]));
    }
    w.write(q, |p| p.content(Q, 2 + n, &[A], D));
    let rule = v.set(&mut w, Rule::fixed());
    let st = w.run(&rule, |_| {});
    w.copies(&st, D).len()
}

/// Cost: junk grants by a non-admin of a path thing add 27 copies under D for 27 more junk
/// grants under the draft, none under every chained variant.
#[test]
fn open10_junk_by_a_non_admin_adds_no_copy_but_under_the_draft() {
    for v in Open10::ALL {
        let more = junk_copies(v, 30) - junk_copies(v, 3);
        assert_eq!(more, if v == Open10::Drafted { 27 } else { 0 }, "{}", v.name());
    }
}

/// Cost: an admin's grants on a used edge are real (chained, applied): each is a copy under D
/// in every variant, so what an admin can force is its own writes on edges D's bodies use.
#[test]
fn open10_an_admins_writes_on_a_used_edge_are_copies_in_every_variant() {
    let copies = |v: Open10, n: u32| {
        let (mut w, [x, _, _, q]) = base();
        for i in 0..n {
            w.write(x, |p| p.edge(X, 1 + i, &[], A, Q, Role::Write, &[]));
        }
        w.write(q, |p| p.content(Q, 2 + n, &[A], D));
        let rule = v.set(&mut w, Rule::fixed());
        let st = w.run(&rule, |_| {});
        w.copies(&st, D).len()
    };
    for v in Open10::ALL {
        assert_eq!(copies(v, 30) - copies(v, 3), 27, "{}", v.name());
    }
}

/// Finding 13: Q writes D through [A] where Q's edge on A holds only K's junk grant (K writes A,
/// no admin). The node holding everything holds an edge write on (Q, A) before the write, so under
/// the draft's pending rule it judges the write invalid (refused); a reader whose closure takes
/// chained writes only holds nothing on (Q, A) and pends: P1 (ii, iii). Pending on chained grants
/// (iv, v) both pend: a write no chained grant reaches waits wherever it is, as one no write
/// reaches does. Refused or waiting, nobody shows it.
#[test]
fn f13_a_path_set_only_by_junk_waits_at_the_reader_where_the_draft_refuses() {
    let (mut w, [_, _, k, q]) = base();
    let junk = w.write(k, |p| p.edge(K, 2, &[], A, Q, Role::Admin, &[]));
    let c = w.write(q, |p| p.content(Q, 3, &[A], D));
    let got = by_variant(&w, &Open10::ALL);
    for (name, p) in &got {
        let p1 = p.contains(&"P1");
        assert_eq!(p1, matches!(*name, "ii-chained" | "iii-joined"), "{name}: {p:?}");
    }
    // the junk itself is a copy under the draft alone (P10)
    let p10: Vec<_> = got.iter().filter(|(_, p)| p.contains(&"P10-junk")).map(|(n, _)| *n).collect();
    assert_eq!(p10, vec!["i-drafted"]);
    // the verdicts at the node holding everything
    let mut wg = w.clone();
    Open10::Granted.set(&mut wg, Rule::fixed());
    let st = w.run(&Rule::fixed(), |_| {});
    let full = |w: &World| w.verdicts(&w.full(&st, &Set::new()), &Set::from([c, junk]));
    assert_eq!(full(&w)[&c], Verdict::Invalid);
    assert_eq!(full(&wg)[&c], Verdict::Pending);
    // the junk itself (K, a writer of A, granting on A): refused where any grant joins (K, A), and
    // waiting where only a grant giving what it needs (admin) does (finding 23, J2)
    assert_eq!(full(&wg)[&junk], if wg.join == Join::Needed { Verdict::Pending } else { Verdict::Invalid });
}

const M1: Thing = 30;
const M2: Thing = 31;
const V: Thing = 32;

/// Finding 11 (b): V mints M1 and M2 and grants M1 write on M2 and K write on M1; M2 holds nothing
/// on A. K states [M1, M2, A] for its write on D. U (honest) syncs M2 and D. Under the draft U
/// copies V's grant of M1 on M2 under D: a roster of a thing that gives no role on D (P9). A
/// closure along joined paths only takes nothing of an unjoined path; the write pends everywhere.
#[test]
fn f11_a_stated_path_no_grant_joins_leaks_a_roster_unless_paths_must_be_joined() {
    let pw = paths::World::new(&[(X, A), (Y, D), (V, M1), (V, M2)]);
    let mut w = World::new(pw, &[A, D, M1, M2]);
    let (y, v, u, k) = (w.node(true, &[D]), w.node(true, &[M1, M2]), w.node(true, &[M2, D]), w.node(false, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    let gm = w.write(v, |p| p.edge(V, 1, &[], M2, M1, Role::Write, &[]));
    w.write(v, |p| p.edge(V, 1, &[], M1, K, Role::Write, &[]));
    let c = w.write(k, |p| p.content(K, 2, &[M1, M2, A], D));
    let _ = u;
    let got = by_variant(&w, &Open10::ALL);
    for (name, p) in &got {
        assert_eq!(p.contains(&"P9-leak"), matches!(*name, "i-drafted" | "ii-chained" | "v-chained-granted"), "{name}: {p:?}");
        assert!(!p.contains(&"P1"), "{name}: {p:?}");
    }
    let st = w.run(&Rule::fixed(), |_| {});
    assert!(st.entries[&D].contains(&gm));
    assert_eq!(w.verdicts(&w.full(&st, &Set::new()), &Set::from([c]))[&c], Verdict::Pending);
}

/// Finding 14: the closure cannot take applied writes only (vi): the re-grant rule reads the
/// first chained grant of each edge, dropped or not (spec/permissions.md §5.2). X makes Q
/// an admin of A; Q grants K write (g1, 1); K writes D at 2; X removes Q at 3 listing nothing
/// (g1 dropped); X grants K again at 5. The node holding everything counts K's path as re-granted
/// from g1 and shows the write; a closure without the dropped g1 holds no write on (K, A) before
/// the write, which pends.
#[test]
fn f14_a_dropped_grant_is_read_by_the_regrant_so_applied_only_strands_a_write() {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, q, k) = (w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[A]), w.node(true, &[A]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Admin, &[]));
    let g1 = w.write(q, |p| p.edge(Q, 1, &[], A, K, Role::Write, &[]));
    let c = w.write(k, |p| p.content(K, 2, &[A], D));
    w.write(x, |p| p.edge(X, 3, &[], A, Q, Role::None, &[]));
    w.write(x, |p| p.edge(X, 5, &[], A, K, Role::Write, &[]));
    let st = w.run(&Rule::fixed(), |_| {});
    let rd = paths::judge(&w.w, &w.rules, &w.full(&st, &Set::new()).v);
    assert!(rd.dropped.contains(&g1) && rd.valid.contains(&c));
    for (name, p) in by_variant(&w, &Open10::ALL) {
        assert_eq!(p.contains(&"P1"), name == "vi-applied", "{name}: {p:?}");
    }
}

/// Finding 15: a writer's finalizes are chained (spec/permissions.md §4 Chained writes: write on
/// its target, for a removal), so a writer of A without admin still grows a dependent's copies
/// under (iv) once A's edge it finalizes is a used one: K finalizes Q's edge `n` times; none ends
/// anything (Q's grant has no `until`), every one is a copy under D. Likewise an inviter's invite
/// grants onto a holder that has a grant (chained by its invite, applied nowhere).
#[test]
fn f15_a_writers_finalizes_and_an_inviters_grants_are_chained_and_copied() {
    let copies = |n: u32| {
        let (mut w, [x, _, k, q]) = base();
        w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Write, &[]));
        for i in 0..n {
            w.write(k, |p| p.push(K, 2 + i, &[], A, paths::Kind::finalize(Q)));
        }
        w.write(q, |p| p.content(Q, 2 + n, &[A], D));
        let rule = Open10::Granted.set(&mut w, Rule::fixed());
        let st = w.run(&rule, |_| {});
        assert_eq!(fails(&w, &rule), vec![]);
        w.copies(&st, D).len()
    };
    assert_eq!(copies(30) - copies(3), 27);
    // an inviter's invite grants onto a holder with a current grant apply nowhere and are chained
    let invites = |n: u32| {
        let (mut w, [x, _, k, q]) = base();
        w.write(x, |p| p.push(X, 1, &[], A, paths::Kind::set(K, Role::Write).may_grant()));
        w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Write, &[]));
        for i in 0..n {
            w.write(k, |p| p.push(K, 2 + i, &[], A, paths::Kind::set(Q, Role::Read)));
        }
        w.write(q, |p| p.content(Q, 2 + n, &[A], D));
        let rule = Open10::Granted.set(&mut w, Rule::fixed());
        let st = w.run(&rule, |_| {});
        assert_eq!(fails(&w, &rule), vec![]);
        w.copies(&st, D).len()
    };
    assert_eq!(invites(30) - invites(3), 27);
}

/// Finding 9, made expressible (`World::creations`: a part resetting an entry waits for its
/// creation; a commit's edge writes on a thing apply together): X removes K and Q (a reader of
/// A) from A in one commit C; K writes D through [A] after it. D's evidence holds C (on K's edge)
/// and C's part on Q's edge, not X's grant to Q, the creation of the entry that part resets (Q's
/// removal takes no write away, so reach brings no witness of it): D's reader never applies C
/// and shows K's write pending where the node holding everything judges it invalid. The draft's
/// clause (every write on the commit's other edges on the thing) or the creations alone close it.
#[test]
fn f9_a_removal_of_two_holders_waits_for_each_creation() {
    let (mut w, [x, _, _, _]) = base();
    let kn = w.node(true, &[A]);
    w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Read, &[]));
    w.write_parts(x, |p| p.commit(X, 5, &[], A, vec![paths::Kind::set(K, Role::None), paths::Kind::set(Q, Role::None)]));
    let c = w.write(kn, |p| p.content(K, 6, &[A], D));
    for v in [Open10::Drafted, Open10::Granted] {
        for ce in [CommitEdges::Off, CommitEdges::Creations, CommitEdges::AllWrites] {
            let mut w = w.clone();
            let mut rule = v.set(&mut w, Rule::fixed());
            rule.closure.commit_edges = ce;
            let f = fails(&w, &rule);
            if ce == CommitEdges::Off {
                assert!(f.iter().any(|f| f.prop == "P1" && f.id == c && f.reader == Some(Verdict::Pending) && f.full == Some(Verdict::Invalid)), "{} {ce:?}: {f:?}", v.name());
            } else {
                assert_eq!(f, vec![], "{} {ce:?}", v.name());
            }
        }
    }
}

/// Cost under (iv), counted: copies under D are the chained writes on the outside edges its
/// bodies' paths use, shared by every write (flat at 3 and 30 writes), one more per re-grant on a
/// used edge (role churn), and repeated under every sync ID whose unit carries D (each counts the
/// path things outside its own unit).
#[test]
fn cost_copies_follow_path_edges_and_churn_never_writes() {
    for (k, m) in [(1, 1), (2, 1), (2, 2), (3, 2), (3, 3), (4, 4)] {
        let a = cost_with(3, k, m, 0, 1, Open10::Granted);
        let b = cost_with(30, k, m, 0, 1, Open10::Granted);
        assert_eq!((a.copies, b.copies), (m, m), "k {k} m {m}");
        assert_eq!(b.bodies - a.bodies, 27);
    }
    for churn in [1, 10] {
        assert_eq!(cost_with(3, 2, 2, churn, 1, Open10::Granted).copies, 2 + churn);
        // churn on an edge inside the unit is bodies, no copy
        assert_eq!(cost_with(3, 2, 0, churn, 1, Open10::Granted).copies, 0);
    }
    for carried in [1, 2, 4] {
        assert_eq!(cost_with(3, 3, 1, 0, carried, Open10::Granted).copies_everywhere, 1 + 3 * (carried - 1));
    }
}

/// The variants on a slice of the family: with every grant chained and every path joined, (i) to
/// (v) hold alike (the family has no junk). (vi) fails here too (finding 14): not run.
#[test]
fn open10_variants_agree_where_every_write_is_chained() {
    for i in (0..FAMILY).step_by(1999) {
        let w = family(Shape::nth(i));
        for (name, p) in by_variant(&w, &Open10::ALL[..5]) {
            assert!(p.is_empty(), "{name} {:?}: {p:?}", Shape::nth(i));
        }
    }
}

/// Per variant, the worlds failing each property over every `step`th family world and `n` random
/// worlds of 14 moves (by hand: `OSIS_OPEN10_STEP`, `OSIS_OPEN10_RANDOM`).
#[test]
#[ignore = "by hand"]
fn open10_explore() {
    let env = |k: &str, d: usize| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    let (step, n) = (env("OSIS_OPEN10_STEP", 97), env("OSIS_OPEN10_RANDOM", 100));
    let mut jobs: Vec<(Open10, String, World)> = vec![];
    for v in Open10::ALL {
        for i in (0..FAMILY).step_by(step) {
            jobs.push((v, format!("{:?}", Shape::nth(i)), family(Shape::nth(i))));
        }
        for seed in 0..n as u64 {
            jobs.push((v, format!("random {seed}"), random(seed, 14)));
        }
    }
    let out = std::sync::Mutex::new(std::collections::BTreeMap::<&str, (usize, std::collections::BTreeMap<&str, (usize, String)>)>::new());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let Some((v, name, w)) = jobs.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) else { return };
                let mut w = w.clone();
                let rule = v.set(&mut w, Rule::fixed());
                let f = fails(&w, &rule);
                let mut o = out.lock().unwrap();
                let e = o.entry(v.name()).or_default();
                e.0 += 1;
                let mut seen = std::collections::BTreeSet::new();
                for x in f {
                    if seen.insert(x.prop) {
                        let p = e.1.entry(x.prop).or_insert((0, format!("{name}: {x:?}")));
                        p.0 += 1;
                    }
                }
            });
        }
    });
    for (v, (worlds, props)) in out.into_inner().unwrap() {
        eprintln!("{v}: {worlds} worlds");
        for (p, (k, first)) in props {
            eprintln!("  {p}: {k} worlds, first {first}");
        }
    }
}

/// Prints random world `OSIS_HELD_START` under (iv) and its failures (by hand).
#[test]
#[ignore = "by hand"]
fn open10_show_random() {
    let seed: u64 = std::env::var("OSIS_HELD_START").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut w = random(seed, 14);
    let rule = Open10::Granted.set(&mut w, Rule::fixed());
    crate::spec_evidence::show(&w, &rule);
    for f in fails(&w, &rule) {
        eprintln!("{f:?}");
    }
}
