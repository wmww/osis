//! OPEN 14 (notes/a2-spec/README.md): how removals reach a sync ID between A2 and A3. Each delivery
//! rule (`Stage`) over OPEN 10's (iv) closure and judge: the drafted A3's (reach and the errand,
//! parked until stage D), brief 3's (no reach, Role changes travel), the derivation's actor seed
//! alone, main's today (chain certificates on any path), and brief 3 keeping today's any-path
//! chains for removals alone. Hand worlds per finding; `reach_explore` (by hand) tallies every
//! stage over the family, random and story worlds and lists worlds where a stage fails and today
//! holds.
use crate::spec_open10::fails_at;
use held_model::evidence::names::*;
use held_model::evidence::*;
use roles_model::paths::{self, Thing};
use roles_model::Role;
use std::collections::{BTreeMap, BTreeSet};

/// `w` under `stage`: the failures (P0 to P10), the per-step checks at
/// steps `at` (every step: None).
pub fn stage_fails_at(w: &World, stage: Stage, at: Option<&Steps>) -> Vec<Fail> {
    stage_fails_at_with(w, stage, at, |r| r)
}

/// `stage_fails_at` with `f` applied to the stage's rule.
pub fn stage_fails_at_with(w: &World, stage: Stage, at: Option<&Steps>, f: impl Fn(Rule) -> Rule) -> Vec<Fail> {
    let mut w = w.clone();
    w.rules = crate::spec_story::rules();
    let rule = f(stage.set(&mut w, Rule::fixed()));
    let all: Steps = (1..=w.events.len()).collect();
    fails_at(&w, &rule, at.unwrap_or(&all))
}

pub type Steps = BTreeSet<usize>;

pub fn stage_fails(w: &World, stage: Stage) -> Vec<Fail> {
    stage_fails_at(w, stage, None)
}

/// The properties `w` fails under each stage.
fn by_stage(w: &World) -> BTreeMap<&'static str, Vec<&'static str>> {
    by_stage_with(w, |r| r)
}

/// `stage_fails` with `f` applied to the stage's rule.
pub fn stage_fails_with(w: &World, stage: Stage, f: impl Fn(Rule) -> Rule) -> Vec<Fail> {
    let mut w = w.clone();
    w.rules = crate::spec_story::rules();
    let rule = f(stage.set(&mut w, Rule::fixed()));
    crate::spec_open10::fails(&w, &rule)
}

/// `by_stage` with `f` applied to each stage's rule (a control).
fn by_stage_with(w: &World, f: impl Fn(Rule) -> Rule) -> BTreeMap<&'static str, Vec<&'static str>> {
    Stage::ALL
        .iter()
        .map(|&s| {
            let mut p: Vec<&str> = stage_fails_with(w, s, &f).iter().map(|f| f.prop).collect();
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
    let w = family(Shape { via_org: true, units: 0, listed: false, thief: true, regrant: false, addendum: false, raised: false, q_d: false, q_r: false, y_a: false, org_apart: true, grant: false, mint: 0 });
    for (name, p) in by_stage(&w) {
        assert_eq!(p.contains(&"P1") && p.contains(&"P3"), name != "a3", "{name}: {p:?}");
    }
    let f = stage_fails(&w, Stage::A2);
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
    let f = stage_fails(&w, Stage::A2);
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == R && f.id == late && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{f:?}");
}

/// R's mint admin (`open14_keys_open_*`).
const V: Thing = 7;

/// Role changes travel's keys-open half carries a removal of a thing's grant to the things that
/// read through it: K (of A) writes R through [A, O, D] (A writes O, O writes D, D writes R); Y
/// removes O from D; the stolen K writes R again. Y syncs D and A, N syncs A and R; R's admin V
/// syncs R alone. A reads through O, so the removal goes under A (Y logs it there), N takes it to
/// R as evidence of K's write. With keys-open travel left out (`a2-actor`) R's reader shows K's
/// late write.
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
    w.write(k, |p| p.content(K, 8, &[A, O, D], R));
    for (name, p) in by_stage(&w) {
        assert_eq!(p.contains(&"P1"), name == "a2-actor", "{name}: {p:?}");
    }
}

/// The rule with record edges left out of reach, keys-open travel and the errand (the control).
fn grants_only(r: Rule) -> Rule {
    Rule { records: false, ..r }
}

/// OPEN 17: finding 19's world with O minted by A (record (A, O)) in place of W granting A write
/// on O. K writes R through [A, O, D]; Y removes O from D; the stolen K writes R again. A's keys
/// open O through its record edge (spec/sync-set.md §2: effective role climbs record edges), so
/// Role changes travel puts the removal under A and N carries it to R. Every stage but the actor
/// seed alone holds; read through grants only, every stage but A3 fails P1 at R (today's too: the
/// control under-reads today).
#[test]
fn open17_keys_open_through_a_mint_admins_record_edge() {
    let pw = paths::World::new(&[(X, A), (A, O), (Y, D), (V, R)]);
    let mut w = World::new(pw, &[A, O, D, R]);
    let (x, y, v, k) = (w.node(true, &[A]), w.node(true, &[D, A]), w.node(true, &[R]), w.node(false, &[]));
    let _n = w.node(true, &[A, R]);
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, O, Role::Write, &[]));
    w.write(v, |p| p.edge(V, 1, &[], R, D, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[A, O, D], R));
    w.write(y, |p| p.edge(Y, 6, &[], D, O, Role::None, &[]));
    let late = w.write(k, |p| p.content(K, 8, &[A, O, D], R));
    for (name, p) in by_stage(&w) {
        assert_eq!(p.contains(&"P1"), name == "a2-actor", "{name}: {p:?}");
    }
    for (name, p) in by_stage_with(&w, grants_only) {
        assert_eq!(p.contains(&"P1"), name != "a3", "control {name}: {p:?}");
    }
    let f = stage_fails_with(&w, Stage::Today, grants_only);
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == R && f.id == late && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{f:?}");
}

/// OPEN 17, reach through a record edge: finding 18's world with D minted by A in place of Y
/// granting A write on D. X grants K write on D (by descent through A) and Y grants A write on R;
/// K writes D directly; X removes K from A; the stolen K writes R through [A]. X syncs A and D, Y
/// syncs D and R. Today K's chain to D climbs A's record edge, so the removal goes under D; reach
/// joins A to D by the record edge.
#[test]
fn open17_a_removed_writers_other_route_through_a_record_edge() {
    let pw = paths::World::new(&[(X, A), (A, D), (Y, R)]);
    let mut w = World::new(pw, &[A, D, R]);
    let (x, y, k) = (w.node(true, &[A, D]), w.node(true, &[D, R]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], R, A, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 1, &[], D, K, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[], D));
    w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    w.write(k, |p| p.content(K, 8, &[A], R));
    for (name, p) in by_stage(&w) {
        assert_eq!(p.contains(&"P1"), matches!(name, "a2" | "a2-actor"), "{name}: {p:?}");
    }
    let today = stage_fails(&w, Stage::Today);
    assert!(!today.iter().any(|f| f.prop == "P1"), "{today:?}");
}

/// The stage failures of every world in a job list, a thread per core: per stage the
/// failing worlds per property, and per stage the worlds it fails (P1 or P3) where today holds.
pub type Job = Box<dyn Fn() -> (String, World, Option<Steps>) + Sync>;

/// `f` is applied to every stage's rule but today's (a control against today as built).
pub fn tally(jobs: &[Job], stages: &[Stage], f: impl Fn(Rule) -> Rule + Sync) -> String {
    let out = std::sync::Mutex::new(BTreeMap::<&str, BTreeMap<&str, (usize, String)>>::new());
    let worse = std::sync::Mutex::new(BTreeMap::<&str, (usize, String)>::new());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let Some(j) = jobs.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) else { return };
                let (name, w, at) = j();
                let today: BTreeSet<&str> = stage_fails_at(&w, Stage::Today, at.as_ref()).iter().map(|f| f.prop).filter(|p| matches!(*p, "P1" | "P3")).collect();
                for &s in stages {
                    let f = if s == Stage::Today { stage_fails_at(&w, s, at.as_ref()) } else { stage_fails_at_with(&w, s, at.as_ref(), &f) };
                    let mut o = out.lock().unwrap();
                    let e = o.entry(s.name()).or_default();
                    let mut seen = BTreeSet::new();
                    for x in &f {
                        if seen.insert(x.prop) {
                            e.entry(x.prop).or_insert((0, format!("{name}: {x:?}"))).0 += 1;
                        }
                    }
                    if let Some(x) = f.iter().find(|x| matches!(x.prop, "P1" | "P3") && !today.contains(x.prop)) {
                        worse.lock().unwrap().entry(s.name()).or_insert((0, format!("{name}: {x:?}"))).0 += 1;
                    }
                }
            });
        }
    });
    let mut s = String::new();
    for (st, props) in out.into_inner().unwrap() {
        s += &format!("{st}\n");
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
/// `OSIS_REACH_CONTROL`: `grants` reads every stage but today's over grants only (`Rule::records`
/// off), `any` takes every removal as a reach seed (`Removals::Any`).
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
                let sim = paths::random_world(seed, &crate::spec_story::rules());
                let w = story_world(&sim, u);
                let at = crate::spec_story::story_steps(&w, &sim);
                (format!("story {seed} units {u}"), w, Some(at))
            }));
        }
    }
    let control = std::env::var("OSIS_REACH_CONTROL").unwrap_or_default();
    eprintln!("{}", tally(&jobs, &Stage::ALL, |r| match control.as_str() {
        "grants" => grants_only(r),
        "any" => any_removal(r),
        _ => r,
    }));
}

// ---- OPEN 16: which removals reach ----

fn any_removal(r: Rule) -> Rule {
    Rule { removals: Removals::Any, ..r }
}

fn takes_write(r: Rule) -> Rule {
    Rule { removals: Removals::TakesWrite, ..r }
}

/// The properties `w` fails under each stage, by each removal rule: equal under both (the
/// narrowing loses nothing a stage held).
fn same_under_both(w: &World) -> BTreeMap<&'static str, Vec<&'static str>> {
    let (a, t) = (by_stage_with(w, any_removal), by_stage_with(w, takes_write));
    assert_eq!(a, t, "the narrowing moves a property");
    t
}

/// What S holds at the end of `w` under `stage` with `f` on its rule, and at each step.
fn entries_with(w: &World, stage: Stage, s: Thing, f: impl Fn(Rule) -> Rule) -> Vec<paths::Set> {
    let mut w = w.clone();
    let rule = f(stage.set(&mut w, Rule::fixed()));
    let mut out = vec![];
    w.run(&rule, |st| out.push(st.entries[&s].clone()));
    out
}

/// A plain reader added to and removed from a hub: P (a key actor) is granted read on O and
/// removed; O writes D; M writes D through [O]. Under `Any` the removal and the grant it resets
/// are required under D for good (reach: O joins D); under `TakesWrite` neither (P never held
/// write on O, so no write rests on its edge). Every property holds under both.
#[test]
fn open16_a_plain_readers_grant_and_removal_on_a_hub_stay_off_its_documents() {
    let pw = paths::World::new(&[(Y, O), (Y, D)]);
    let mut w = World::new(pw, &[O, D]);
    let (y, m) = (w.node(true, &[O, D]), w.node(true, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, O, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], O, K, Role::Write, &[]));
    let g = w.write(y, |p| p.edge(Y, 2, &[], O, Q, Role::Read, &[]));
    w.write(m, |p| p.content(K, 3, &[O], D));
    let r = w.write(y, |p| p.edge(Y, 4, &[], O, Q, Role::None, &[]));
    for (stage, p) in same_under_both(&w) {
        assert!(p.is_empty() || stage == "a2-actor" && p.iter().all(|p| *p != "P1"), "{stage}: {p:?}");
    }
    for stage in [Stage::A3] {
        let any = entries_with(&w, stage, D, any_removal);
        assert!(any.last().unwrap().is_superset(&paths::Set::from([g, r])), "{any:?}");
        let tw = entries_with(&w, stage, D, takes_write);
        assert!(tw.last().unwrap().is_disjoint(&paths::Set::from([g, r])), "{tw:?}");
    }
}

/// Finding 18's world with K's write grant on A written by a second admin Q, backdated before
/// X's removal and arriving after it (finding 3's shape): X grants K read on A (1), Q (admin)
/// grants K write (2, written last but one), X removes K (6). Until the grant arrives the removal
/// takes no write away at any node, so it is no reach seed; once held it is, at D with its witness
/// (the grant), and Y carries it to R as evidence of the stolen K's write through [A]. Every stage
/// holds as under `Any`.
#[test]
fn open16_a_backdated_write_grant_arriving_late_makes_the_removal_reach_then() {
    let pw = paths::World::new(&[(X, A), (Y, D), (Y, R)]);
    let mut w = World::new(pw, &[A, D, R]);
    let (x, y, q, k) = (w.node(true, &[A, D]), w.node(true, &[D, R]), w.node(true, &[A]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Admin, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Read, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], R, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, K, Role::Write, &[]));
    w.write(k, |p| p.content(K, 3, &[], D));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    let g = w.write(q, |p| p.edge(Q, 2, &[], A, K, Role::Write, &[]));
    w.write(k, |p| p.content(K, 8, &[A], R));
    for (stage, p) in same_under_both(&w) {
        assert_eq!(p.contains(&"P1"), matches!(stage, "a2" | "a2-actor"), "{stage}: {p:?}");
    }
    let tw = entries_with(&w, Stage::A3, D, takes_write);
    // after the removal, before the grant: not under D; after the grant: both
    assert!(!tw[g - 1].contains(&r), "{tw:?}");
    assert!(tw[g].is_superset(&paths::Set::from([r, g])), "{tw:?}");
}

/// A writer removed (5: a reach seed), granted read again (7: after a write grant on the edge, so a
/// reach seed too: it takes nothing more away, and costs one copy), and the stolen K backdating
/// a write through [A] at 6, between them (written last). The first removal is under D by reach
/// and Y carries it to R, where the backdated write is judged invalid as everywhere.
#[test]
fn open16_a_write_backdated_between_a_removal_and_a_read_regrant() {
    let pw = paths::World::new(&[(X, A), (Y, D), (Y, R)]);
    let mut w = World::new(pw, &[A, D, R]);
    let (x, y, k) = (w.node(true, &[A, D]), w.node(true, &[D, R]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], R, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, K, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[], D));
    let r = w.write(x, |p| p.edge(X, 5, &[], A, K, Role::None, &[]));
    let rr = w.write(x, |p| p.edge(X, 7, &[], A, K, Role::Read, &[]));
    w.write(k, |p| p.content(K, 6, &[A], R));
    for (stage, p) in same_under_both(&w) {
        assert_eq!(p.contains(&"P1"), matches!(stage, "a2" | "a2-actor"), "{stage}: {p:?}");
    }
    let tw = entries_with(&w, Stage::A3, R, takes_write);
    assert!(tw.last().unwrap().contains(&r), "{tw:?}");
    let td = entries_with(&w, Stage::A3, D, takes_write);
    assert!(td.last().unwrap().contains(&rr), "{td:?}");
}

/// The narrowing is per edge: K writes on A (write) and reads on O (read); W removes K from O
/// (no reach seed: K never held write on O), X removes K from A (a reach seed); K wrote D
/// directly, the stolen K writes R through [A]. Under `TakesWrite` D holds the removal from A and
/// not the one from O; every stage holds as under `Any`.
#[test]
fn open16_a_readers_removal_on_one_edge_and_a_writers_on_another() {
    let pw = paths::World::new(&[(X, A), (W, O), (Y, D), (Y, R)]);
    let mut w = World::new(pw, &[A, O, D, R]);
    let (x, wn, y, k) = (w.node(true, &[A, D]), w.node(true, &[O, D]), w.node(true, &[D, R]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(wn, |p| p.edge(W, 1, &[], O, K, Role::Read, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, O, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], R, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, K, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[], D));
    let ro = w.write(wn, |p| p.edge(W, 5, &[], O, K, Role::None, &[]));
    let ra = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    w.write(k, |p| p.content(K, 8, &[A], R));
    for (stage, p) in same_under_both(&w) {
        assert_eq!(p.contains(&"P1"), matches!(stage, "a2" | "a2-actor"), "{stage}: {p:?}");
    }
    let td = entries_with(&w, Stage::A3, D, takes_write);
    assert!(td.last().unwrap().contains(&ra) && !td.last().unwrap().contains(&ro), "{td:?}");
}

/// Demotions: K admin on A, lowered to write (5: gives write, no removal), then to read (6: below
/// write after a write-or-above grant: a reach seed with the admin grant as its witness). Both
/// rules agree; D holds the second and its witness, not the first.
#[test]
fn open16_a_demotion_to_read_reaches_and_one_to_write_does_not() {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, k) = (w.node(true, &[A, D]), w.node(true, &[D]), w.node(true, &[]));
    let g = w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Admin, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, K, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[], D));
    let to_write = w.write(x, |p| p.edge(X, 5, &[], A, K, Role::Write, &[]));
    let to_read = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::Read, &[]));
    for (stage, p) in same_under_both(&w) {
        assert!(!p.contains(&"P1"), "{stage}: {p:?}");
    }
    let td = entries_with(&w, Stage::A3, D, takes_write);
    let end = td.last().unwrap();
    assert!(end.contains(&to_read) && end.contains(&g) && !end.contains(&to_write), "{td:?}");
}

/// What a document of an organisation holds (README OPEN 16, For Tess 6): hub O writes D; M writes
/// D through [O]; `wr` writers granted write on O and removed, `rd` readers granted read on O and
/// removed. Copies under D: under `TakesWrite` 2 per writer removal (it and its grant) and M's
/// grant, whatever the readers; under `Any` 2 more per reader.
fn org_copies(wr: usize, rd: usize, f: impl Fn(Rule) -> Rule) -> usize {
    let pw = paths::World::new(&[(Y, O), (Y, D)]);
    let mut w = World::new(pw, &[O, D]);
    let (y, m) = (w.node(true, &[O, D]), w.node(true, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, O, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], O, M, Role::Write, &[]));
    w.write(m, |p| p.content(M, 2, &[O], D));
    for (n, role) in std::iter::repeat_n(Role::Write, wr).chain(std::iter::repeat_n(Role::Read, rd)).enumerate() {
        let h = 100 + n as Thing;
        w.write(y, |p| p.edge(Y, 3, &[], O, h, role, &[]));
        w.write(y, |p| p.edge(Y, 4, &[], O, h, Role::None, &[]));
    }
    let mut w2 = w.clone();
    let rule = f(Stage::A3.set(&mut w2, Rule::fixed()));
    let st = w2.run(&rule, |_| {});
    w2.copies(&st, D).len()
}

/// M: a member signer of the organisation (`org_copies`).
const M: Thing = 8;

#[test]
fn open16_a_document_holds_two_copies_per_writer_removal_whatever_its_readers() {
    for (wr, rd) in [(1, 0), (1, 3), (1, 30), (3, 3), (3, 30)] {
        assert_eq!(org_copies(wr, rd, takes_write), 2 * wr + 1, "wr {wr} rd {rd}");
        assert_eq!(org_copies(wr, rd, any_removal), 2 * wr + 2 * rd + 1, "wr {wr} rd {rd}");
    }
}
