//! OPEN 14 (notes/a2-spec/README.md): how removals reach a sync ID between A2 and A3. Each
//! delivery rule (`Stage`) over OPEN 10's (iv) closure and judge: A3's (reach and the errand), reach
//! with no errand, brief 3's (no reach, Role changes travel), the derivation's actor seed alone,
//! main's today (chain certificates on any path), and brief 3 keeping today's any-path chains for
//! removals alone. Hand worlds per finding; `reach_explore` (by hand) tallies every stage over the
//! family, random and story worlds and lists worlds where a stage fails and today holds.
use crate::spec_open10::fails_at;
use held_model::evidence::names::*;
use held_model::evidence::*;
use roles_model::paths::{self, Thing};
use roles_model::Role;
use std::collections::{BTreeMap, BTreeSet};

/// `w` under `stage`, vouches counting or not: the failures (P0 to P10), the per-step checks at
/// steps `at` (every step: None).
pub fn stage_fails_at(w: &World, stage: Stage, vouches: bool, at: Option<&Steps>) -> Vec<Fail> {
    let mut w = w.clone();
    w.rules = crate::spec_story::rules(vouches);
    let mut rule = stage.set(&mut w, Rule::fixed());
    rule.closure.vouches = vouches;
    let all: Steps = (1..=w.events.len()).collect();
    fails_at(&w, &rule, at.unwrap_or(&all))
}

pub type Steps = BTreeSet<usize>;

pub fn stage_fails(w: &World, stage: Stage, vouches: bool) -> Vec<Fail> {
    stage_fails_at(w, stage, vouches, None)
}

/// The properties `w` fails under each stage.
fn by_stage(w: &World) -> BTreeMap<&'static str, Vec<&'static str>> {
    Stage::ALL
        .iter()
        .map(|&s| {
            let mut p: Vec<&str> = stage_fails(w, s, true).iter().map(|f| f.prop).collect();
            p.sort();
            p.dedup();
            (s.name(), p)
        })
        .collect()
}

/// Finding 1's world (K writes D through [A, O]; O's admin W syncs O alone, D's admin Y syncs D
/// and R; X, syncing A, removes K listing nothing): no honest node syncs A together with O or D.
/// Only the errand carries the removal to D: every stage without it fails P1 (D's reader shows
/// K's write valid, the node holding everything invalid) and P3, today's included.
#[test]
fn open14_with_no_honest_node_between_only_the_errand_reaches_d() {
    let w = family(Shape { via_org: true, units: 0, listed: false, thief: true, regrant: false, addendum: false, raised: false, q_d: false, q_r: false, y_a: false, org_apart: true, vouch: false });
    for (name, p) in by_stage(&w) {
        assert_eq!(p.contains(&"P1") && p.contains(&"P3"), name != "a3", "{name}: {p:?}");
    }
    let f = stage_fails(&w, Stage::A2, true);
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == D && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{f:?}");
}

/// The removed party's own other route (OPEN 14's finding): Y grants K write on D directly and A
/// write on D and R; K writes D directly (its stated path [], no hop through A); X removes K from
/// A; the stolen K writes R through [A]. X syncs A and D, Y syncs D and R; nobody honest syncs A
/// and R. Today K's write on D carries K's chain to D, which runs through A (any path), so X logs
/// the removal under D, Y takes it there and logs it under R as evidence of the thief's write.
/// By stated paths D's evidence holds nothing of (K, A): brief 3 (no reach) leaves R's reader
/// showing the thief's write; reach (A joins D) and today's chains kept for removals carry it.
#[test]
fn open14_a_removed_writers_other_route_carried_the_removal_today() {
    let pw = paths::World::new(&[(X, A), (Y, D), (Y, R)]);
    let mut w = World::new(pw, &[A, D, R]);
    let (x, y, k) = (w.node(true, &[A, D]), w.node(true, &[D, R]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], R, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, K, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[], D));
    w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    let late = w.write(k, |p| p.content(K, 8, &[A], R));
    let got = by_stage(&w);
    for (name, p) in &got {
        let fails = matches!(*name, "a2" | "a2-actor");
        assert_eq!(p.contains(&"P1"), fails, "{name}: {p:?}");
    }
    let f = stage_fails(&w, Stage::A2, true);
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == R && f.id == late && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{f:?}");
}

/// R's mint admin (`open14_keys_open_*`).
const V: Thing = 7;

/// Role changes travel's keys-open half carries a removal of a thing's grant to the things that
/// read through it: K (of A) writes R through [A, O, D] (A writes O, O writes D, D writes R); Y
/// removes O from D; the stolen K writes R again. Y syncs D and A, N syncs A and R; R's admin V
/// syncs R alone. A reads through O, so the removal goes under A (Y logs it there), N takes it to
/// R as evidence of K's write. Reach alone puts it under R only (D joins R), where nobody holding
/// it syncs: with keys-open travel left out (the derivation alone, or reach in its place) R's
/// reader shows K's late write.
#[test]
fn open14_keys_open_travel_carries_a_removal_to_the_things_reading_through_it() {
    let pw = paths::World::new(&[(X, A), (W, O), (Y, D), (V, R)]);
    let mut w = World::new(pw, &[A, O, D, R]);
    let (x, wn, y, v, k) = (w.node(true, &[A]), w.node(true, &[O]), w.node(true, &[D, A]), w.node(true, &[R]), w.node(false, &[]));
    let _n = w.node(true, &[A, R]);
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(wn, |p| p.edge(W, 1, &[], O, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, O, Role::Write, &[]));
    w.write(v, |p| p.edge(V, 1, &[], R, D, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[A, O, D], R));
    w.write(y, |p| p.edge(Y, 6, &[], D, O, Role::None, &[]));
    let late = w.write(k, |p| p.content(K, 8, &[A, O, D], R));
    let mut wr = w.clone();
    let mut no_keys = Stage::ReachNoErrand.set(&mut wr, Rule::fixed());
    no_keys.keys_open = false;
    let f = crate::spec_open10::fails(&wr, &no_keys);
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == R && f.id == late && f.reader == Some(Verdict::Valid)), "{f:?}");
    for (name, p) in by_stage(&w) {
        assert_eq!(p.contains(&"P1"), name == "a2-actor", "{name}: {p:?}");
    }
}

/// The stage failures of every world in a job list, a thread per core: per (stage, vouches) the
/// failing worlds per property, and per stage the worlds it fails (P1 or P3) where today holds.
pub type Job = Box<dyn Fn() -> (String, World, Option<Steps>) + Sync>;

pub fn tally(jobs: &[Job], stages: &[Stage]) -> String {
    let out = std::sync::Mutex::new(BTreeMap::<(&str, bool), BTreeMap<&str, (usize, String)>>::new());
    let worse = std::sync::Mutex::new(BTreeMap::<&str, (usize, String)>::new());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let Some(j) = jobs.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) else { return };
                let (name, w, at) = j();
                for vouches in [true, false] {
                    let today: BTreeSet<&str> = stage_fails_at(&w, Stage::Today, vouches, at.as_ref()).iter().map(|f| f.prop).filter(|p| matches!(*p, "P1" | "P3")).collect();
                    for &s in stages {
                        let f = stage_fails_at(&w, s, vouches, at.as_ref());
                        let mut o = out.lock().unwrap();
                        let e = o.entry((s.name(), vouches)).or_default();
                        let mut seen = BTreeSet::new();
                        for x in &f {
                            if seen.insert(x.prop) {
                                e.entry(x.prop).or_insert((0, format!("{name}: {x:?}"))).0 += 1;
                            }
                        }
                        if let Some(x) = f.iter().find(|x| matches!(x.prop, "P1" | "P3") && !today.contains(x.prop)) {
                            worse.lock().unwrap().entry(s.name()).or_insert((0, format!("vouches {vouches} {name}: {x:?}"))).0 += 1;
                        }
                    }
                }
            });
        }
    });
    let mut s = String::new();
    for ((st, v), props) in out.into_inner().unwrap() {
        s += &format!("{st} vouches {v}\n");
        for (p, (k, first)) in props {
            s += &format!("  {p}: {k} worlds, first {first}\n");
        }
    }
    for (st, (k, first)) in worse.into_inner().unwrap() {
        s += &format!("WORSE THAN TODAY {st}: {k}, first {first}\n");
    }
    s
}

/// Every stage over every `OSIS_REACH_STEP`th family world (97), `OSIS_REACH_RANDOM` random
/// worlds (100) and `OSIS_STORY_N` story seeds under every unit crossing (12), by hand.
#[test]
#[ignore = "by hand"]
fn reach_explore() {
    let env = |k: &str, d: usize| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    let (step, n, story) = (env("OSIS_REACH_STEP", 97), env("OSIS_REACH_RANDOM", 100), env("OSIS_STORY_N", 12));
    let mut jobs: Vec<Job> = vec![];
    for i in (0..FAMILY).step_by(step) {
        jobs.push(Box::new(move || (format!("{:?}", Shape::nth(i)), family(Shape::nth(i)), None)));
    }
    for seed in 0..n as u64 {
        jobs.push(Box::new(move || (format!("random {seed}"), random(seed, 14), None)));
    }
    for seed in 0..story as u64 {
        for u in 0..STORY_UNITS {
            jobs.push(Box::new(move || {
                let sim = paths::random_world(seed, &crate::spec_story::rules(true));
                let w = story_world(&sim, u);
                let at = crate::spec_story::story_steps(&w, &sim);
                (format!("story {seed} units {u}"), w, Some(at))
            }));
        }
    }
    eprintln!("{}", tally(&jobs, &Stage::ALL));
}

