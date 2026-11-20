//! The evidence generators' gaps (notes/evidence-model-findings.md, Generators): per-node trust
//! sets (P1 for readers trusting otherwise than the world), paths of up to four holder things with
//! churn and junk on every edge and second routes (`wide`), content in the split form across units
//! (`Wide::split`), path entries opening late (`Wide::late`, `World::opens`). Each under A3's rule
//! and brief 3's (`Stage::A2`), vouches counting and not. `gaps_explore` (by hand) tallies them;
//! the sampled searches run A3's and the recommended A2 rule.
use crate::spec_reach::{stage_fails, Job};
use held_model::evidence::names::*;
use held_model::evidence::*;
use roles_model::paths::{self, Set};
use roles_model::Role;
use std::collections::{BTreeMap, BTreeSet};

/// Two random trust sets over `w`'s edge writes (each lowering or other edge write with one
/// chance in two), from `seed`.
pub fn trust_sets(w: &World, seed: u64) -> Vec<Set> {
    let mut rng = roles_model::Rng::thread(seed, 2);
    let edges: Vec<usize> = (0..w.w.commits.len()).filter(|&i| w.w.sets(i).is_some()).collect();
    (0..2).map(|_| edges.iter().copied().filter(|_| rng.below(2) == 0).collect()).collect()
}

/// `w` under `stage` (P0 to P10 as `stage_fails`) and P1 for readers trusting each of `trusts`
/// at every step.
pub fn gap_fails(w: &World, stage: Stage, vouches: bool, trusts: &[Set]) -> Vec<Fail> {
    let mut out = stage_fails(w, stage, vouches);
    if trusts.is_empty() {
        return out;
    }
    let mut w = w.clone();
    w.rules = crate::spec_story::rules(vouches);
    let mut rule = stage.set(&mut w, Rule::fixed());
    rule.closure.vouches = vouches;
    w.run(&rule, |st| {
        for t in trusts {
            out.extend(w.p1_trusting(&rule, st, t, "P1-trust"));
        }
    });
    out
}

/// Per-node trust: X removes K from A listing nothing; K had written D through [A]. A reader
/// trusting the removal and one not trusting it each judge K's write as the node holding
/// everything with the same trust: the removal and K's grant are evidence either way.
#[test]
fn gaps_a_reader_trusting_otherwise_holds_what_its_walk_reads() {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, k) = (w.node(true, &[A, D]), w.node(true, &[D]), w.node(true, &[A]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[A], D));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    for s in Stage::ALL {
        assert_eq!(gap_fails(&w, s, true, &[Set::new(), Set::from([r])]), vec![], "{}", s.name());
    }
}

/// A content commit in the split form across units: K writes D along [A] and R along [O] in one
/// commit; X removes K from A. D's reader judges its part invalid, R's its part valid, each as the
/// node holding everything, under every stage that carries the removal to D (X syncs A and D).
#[test]
fn gaps_a_split_commit_is_judged_per_part_by_each_unit() {
    let pw = paths::World::new(&[(X, A), (W, O), (Y, D), (Y, R)]);
    let mut w = World::new(pw, &[A, O, D, R]);
    let (x, wn, y, k) = (w.node(true, &[A, D]), w.node(true, &[O]), w.node(true, &[D, R]), w.node(true, &[A, O]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(wn, |p| p.edge(W, 1, &[], O, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], R, O, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 2, &[], A, K, Role::None, &[]));
    let ids = w.write_parts(k, |p| p.split(K, 3, K, &[(&[A], D), (&[O], R)]));
    for s in Stage::ALL {
        assert_eq!(gap_fails(&w, s, true, &[]), vec![], "{}", s.name());
    }
    let mut wg = w.clone();
    let rule = Stage::A2.set(&mut wg, Rule::fixed());
    let st = wg.run(&rule, |_| {});
    let rd = |s| wg.verdicts(&wg.reader(&rule, &st, s, &Set::new()), &Set::from([ids[0], ids[1]]));
    assert_eq!(rd(D)[&ids[0]], Verdict::Invalid);
    assert_eq!(rd(R)[&ids[1]], Verdict::Valid);
}

/// A path entry opening late: K writes D along [A]; its entry opens only when Y's key commit on D
/// arrives. Until then D's reader and the node holding everything pend on it and D's evidence
/// takes nothing of its path (no copy of K's grant); once it opens the grant is a copy and the
/// write valid.
#[test]
fn gaps_a_path_entry_opening_late_brings_its_evidence_then() {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, k) = (w.node(true, &[A, D]), w.node(true, &[D]), w.node(true, &[A]));
    let g = w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    let c = w.write(k, |p| p.content(K, 2, &[A], D));
    let o = w.write(y, |p| p.content(Y, 3, &[], D));
    w.opens.insert(c, o);
    for s in Stage::ALL {
        assert_eq!(gap_fails(&w, s, true, &[]), vec![], "{}", s.name());
    }
    let mut wg = w.clone();
    let rule = Stage::A2.set(&mut wg, Rule::fixed());
    let mut seen = vec![];
    wg.run(&rule, |st| {
        let v = wg.verdicts(&wg.reader(&rule, st, D, &Set::new()), &Set::from([c]));
        seen.push((st.step, v.get(&c).copied(), wg.copies(st, D).contains(&g)));
    });
    assert_eq!(seen[2], (3, Some(Verdict::Pending), false), "{seen:?}");
    assert_eq!(seen[3], (4, Some(Verdict::Valid), true), "{seen:?}");
}

/// The option sets `wide` worlds run under: each of split and late with grants only (`mint`
/// off), and minted things alone and with both.
const WIDE_OPTS: [Wide; 6] = [
    Wide { split: false, late: false, mint: false },
    Wide { split: true, late: false, mint: false },
    Wide { split: false, late: true, mint: false },
    Wide { split: true, late: true, mint: false },
    Wide { split: false, late: false, mint: true },
    Wide { split: true, late: true, mint: true },
];

/// The wide worlds' jobs: `n` seeds from `start` of `wide(seed, 16, opt)`.
fn wide_jobs(start: u64, n: u64, opt: Wide) -> Vec<Job> {
    (start..start + n).map(|seed| Box::new(move || (format!("wide {opt:?} {seed}"), wide(seed, 16, opt), None)) as Job).collect()
}

/// Per stage, vouches counting and not, the worlds failing each property (P1-trust: two random
/// trust sets) over `OSIS_GAPS_N` (60) wide worlds per option set and the family slice, and the
/// worlds a stage fails (P1 or P3) where today holds, by hand. `OSIS_EV_RULE` names one stage.
#[test]
#[ignore = "by hand"]
fn gaps_explore() {
    let n: u64 = std::env::var("OSIS_GAPS_N").ok().and_then(|v| v.parse().ok()).unwrap_or(60);
    let stages: Vec<Stage> = match std::env::var("OSIS_EV_RULE") {
        Ok(name) => Stage::ALL.into_iter().filter(|s| s.name() == name).collect(),
        Err(_) => Stage::ALL.to_vec(),
    };
    let opts = WIDE_OPTS;
    let out = std::sync::Mutex::new(BTreeMap::<(String, &str, bool), BTreeMap<&str, (usize, String)>>::new());
    let mut jobs: Vec<(String, Job)> = vec![];
    for opt in opts {
        for j in wide_jobs(0, n, opt) {
            jobs.push((format!("{opt:?}"), j));
        }
    }
    for i in (0..FAMILY).step_by(97) {
        jobs.push(("family".into(), Box::new(move || (format!("{:?}", Shape::nth(i)), family(Shape::nth(i)), None))));
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let Some((g, j)) = jobs.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) else { return };
                let (name, w, _) = j();
                let trusts = trust_sets(&w, name.bytes().fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(b as u64)));
                for vouches in [true, false] {
                    let today: BTreeSet<&str> = if stages.contains(&Stage::Today) { gap_fails(&w, Stage::Today, vouches, &[]).iter().map(|f| f.prop).collect() } else { BTreeSet::new() };
                    for &s in &stages {
                        let f = gap_fails(&w, s, vouches, &trusts);
                        let mut o = out.lock().unwrap();
                        let e = o.entry((g.clone(), s.name(), vouches)).or_default();
                        let mut seen = BTreeSet::new();
                        for x in &f {
                            if seen.insert(x.prop) {
                                e.entry(x.prop).or_insert((0, format!("{name}: {x:?}"))).0 += 1;
                            }
                        }
                        if stages.contains(&Stage::Today) && f.iter().any(|x| matches!(x.prop, "P1" | "P3") && !today.contains(x.prop)) {
                            e.entry("WORSE-THAN-TODAY").or_insert((0, format!("{name}"))).0 += 1;
                        }
                    }
                }
            });
        }
    });
    for ((g, s, v), props) in out.into_inner().unwrap() {
        eprintln!("{g} {s} vouches {v}");
        for (p, (k, first)) in props {
            eprintln!("  {p}: {k} worlds, first {first}");
        }
    }
}

/// The sampled property: A3's rule (`Stage::A3`) holds P0 to P10 and P1 for two random trust sets
/// over `wide` worlds under every option set (`per` seeds each from `OSIS_HELD_START`), and brief 3
/// with reach (`Stage::ReachNoErrand`, OPEN 14's proposal) fails P1 or P3 in no world where
/// today's rule holds both, over those and `random` random worlds, every `family_step`th family
/// world and `story` story seeds under every unit crossing; vouches counting and not.
fn search(per: u64, family_step: usize, random_worlds: u64, story: u64) {
    let start = std::env::var("OSIS_HELD_START").ok().filter(|v| !v.is_empty()).map_or(0, |v| v.parse::<u64>().expect("OSIS_HELD_START is a decimal u64"));
    eprintln!("reach and gaps: wide and random seeds from {start}");
    let mut jobs: Vec<(bool, Job)> = vec![];
    for opt in WIDE_OPTS {
        jobs.extend(wide_jobs(start, per, opt).into_iter().map(|j| (true, j)));
    }
    for i in (0..FAMILY).step_by(family_step) {
        jobs.push((false, Box::new(move || (format!("{:?}", Shape::nth(i)), family(Shape::nth(i)), None))));
    }
    for seed in start..start + random_worlds {
        jobs.push((false, Box::new(move || (format!("random {seed}"), random(seed, 14), None))));
    }
    for seed in start..start + story {
        for u in 0..STORY_UNITS {
            jobs.push((
                false,
                Box::new(move || {
                    let sim = paths::random_world(seed, &crate::spec_story::rules(true));
                    let w = story_world(&sim, u);
                    let at = crate::spec_story::story_steps(&w, &sim);
                    (format!("story {seed} units {u}"), w, Some(at))
                }),
            ));
        }
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let bad = std::sync::Mutex::new(vec![]);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let Some((a3, j)) = jobs.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) else { return };
                let (name, w, at) = j();
                for vouches in [true, false] {
                    if *a3 {
                        let trusts = trust_sets(&w, name.bytes().fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(b as u64)));
                        if let Some(f) = gap_fails(&w, Stage::A3, vouches, &trusts).first() {
                            bad.lock().unwrap().push(format!("a3 vouches {vouches} {name}: {f:?}"));
                        }
                    }
                    let p13 = |s: Stage| -> BTreeSet<&'static str> { crate::spec_reach::stage_fails_at(&w, s, vouches, at.as_ref()).into_iter().map(|f| f.prop).filter(|p| matches!(*p, "P1" | "P3")).collect() };
                    let reach = p13(Stage::ReachNoErrand);
                    if !reach.is_empty() && !reach.is_subset(&p13(Stage::Today)) {
                        bad.lock().unwrap().push(format!("reach-no-errand worse than today, vouches {vouches} {name}: {reach:?}"));
                    }
                }
            });
        }
    });
    let bad = bad.into_inner().unwrap();
    assert!(bad.is_empty(), "{} fail, first: {}", bad.len(), bad[0]);
}

#[test]
#[ignore = "property"]
fn evidence_reach_and_generator_gaps_plain() {
    search(2, 97 * 4, 8, 1);
}

#[test]
#[ignore = "property"]
fn evidence_reach_and_generator_gaps_large() {
    search(40, 17, 150, 10);
}

/// One `wide` world by hand: `OSIS_GAPS_SEED`, `OSIS_GAPS_OPT` (letters s, l, m: split, late,
/// mint), its commits, events and every stage's failures (vouches counting).
#[test]
#[ignore = "by hand"]
fn gaps_show() {
    let seed: u64 = std::env::var("OSIS_GAPS_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let o = std::env::var("OSIS_GAPS_OPT").unwrap_or_default();
    let w = wide(seed, 16, Wide { split: o.contains('s'), late: o.contains('l'), mint: o.contains('m') });
    eprintln!("records {:?}\nunits {:?}\nopens {:?}", w.w.records, w.units, w.opens);
    for (n, nd) in w.nodes.iter().enumerate() {
        eprintln!("node {n}: honest {} syncs {:?}", nd.honest, nd.syncs);
    }
    for (i, c) in w.w.commits.iter().enumerate() {
        eprintln!("{i}: by {} cid {} {} ts {} path {:?} on {} {:?} hops {:?}", w.by[i], w.w.cid(i), c.signer, c.ts, c.path, c.on, c.kind, w.w.hops(i));
    }
    eprintln!("events {:?}", w.events);
    for s in Stage::ALL {
        for f in stage_fails(&w, s, true) {
            eprintln!("{}: {f:?}", s.name());
        }
    }
}

/// Finding 20 (`wide` seed 14204407699, split and late, shrunk): K writes O through [A], where A holds
/// only read on O, after X removed K from A; nobody honest syncs A and O. The write is invalid
/// everywhere (no write reaches O through A), with or without the removal; the path is joined (a
/// grant joins (A, O)), so O's evidence closure over everything holds the removal, which no rule
/// delivers to O (no write path leads from A into O, so neither reach nor the errand goes there).
/// P3 owed it all the same; it is owed where it can move a verdict: where its reach is held. Once
/// W raises A to write on O (backdated, after the removal), reach holds and A3's standing errand
/// carries it, while every stage without the errand misses it (finding 17's class, today too).
#[test]
fn gaps_a_removal_on_a_path_through_a_read_hop_is_owed_once_it_has_reach() {
    let base = |raise: bool| {
        let pw = paths::World::new(&[(X, A), (W, O)]);
        let mut w = World::new(pw, &[A, O]);
        let (x, wn, k) = (w.node(true, &[A]), w.node(true, &[O]), w.node(false, &[]));
        w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
        w.write(wn, |p| p.edge(W, 1, &[], O, A, Role::Read, &[]));
        let r = w.write(x, |p| p.edge(X, 4, &[], A, K, Role::None, &[]));
        let c = w.write(k, |p| p.content(K, 8, &[A], O));
        if raise {
            w.write(wn, |p| p.edge(W, 2, &[], O, A, Role::Write, &[]));
        }
        (w, r, c)
    };
    let (w, r, c) = base(false);
    let mut wr = w.clone();
    let rule = Stage::A3.set(&mut wr, Rule::fixed());
    let st = wr.run(&rule, |_| {});
    let all = wr.full(&st, &Set::new()).v.held;
    // the old P3: the full closure of O's bodies holds the removal, O's reader does not require it
    assert!(wr.closure(&rule, &wr.owed_bodies(&st, O), &all).contains(&r));
    assert!(!wr.req(&rule, O, &st.units, &st.entries[&O]).contains(&r));
    assert_eq!(wr.verdicts(&wr.full(&st, &Set::new()), &Set::from([c]))[&c], Verdict::Invalid);
    for s in Stage::ALL {
        assert_eq!(gap_fails(&w, s, true, &[]), vec![], "{}", s.name());
    }
    let (w, r, _) = base(true);
    for s in Stage::ALL {
        let f = gap_fails(&w, s, true, &[]);
        assert_eq!(f.iter().any(|f| f.prop == "P3" && f.id == r), s != Stage::A3, "{}: {f:?}", s.name());
    }
}
