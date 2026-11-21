//! How removals reach a sync ID (notes/write-path-design.md §2, D1 to D3: lazy delivery; OPEN 14
//! of notes/a2-spec/README.md). Each rule (`Stage`) over OPEN 10's (iv) closure and judge: the
//! design (`a2`: Role changes travel whole), the actor seed alone, main's today (chain
//! certificates on any path), and the design keeping today's any-path chains for removals alone.
//! Each is judged against its reference (`World::reference`) and its gap counted (`World::gap`).
//! Hand worlds per finding; `reach_explore` (by hand) tallies every stage over the family, random
//! and story worlds, with the worlds where a stage has the gap and today has none.
use crate::spec_open10::fails_at;
use held_model::evidence::names::*;
use held_model::evidence::*;
use roles_model::paths::{self, Thing};
use roles_model::Role;
use std::collections::{BTreeMap, BTreeSet};

pub type Steps = BTreeSet<usize>;

/// `w` under the story's rules and `stage`'s rule, `f` applied to it.
pub fn staged(w: &World, stage: Stage, f: impl Fn(Rule) -> Rule) -> (World, Rule) {
    let mut w = w.clone();
    w.rules = crate::spec_story::rules();
    let rule = f(stage.set(&mut w, Rule::fixed()));
    (w, rule)
}

/// `w` under `stage` (`f` on its rule): the failures (P0 to P10), the per-step checks at steps
/// `at` (every step: None).
pub fn stage_fails_with(w: &World, stage: Stage, at: Option<&Steps>, f: impl Fn(Rule) -> Rule) -> Vec<Fail> {
    let (w, rule) = staged(w, stage, f);
    let all: Steps = (1..=w.events.len()).collect();
    fails_at(&w, &rule, at.unwrap_or(&all))
}

pub fn stage_fails(w: &World, stage: Stage) -> Vec<Fail> {
    stage_fails_with(w, stage, None, |r| r)
}

/// The gap of `w` under `stage` (`f` on its rule) at every step: what lazy delivery leaves
/// showing (`World::gap`).
pub fn stage_gaps_with(w: &World, stage: Stage, f: impl Fn(Rule) -> Rule) -> Vec<Fail> {
    let (w, rule) = staged(w, stage, f);
    let mut out = vec![];
    w.run(&rule, |st| out.extend(w.gap(&rule, st)));
    out
}

pub fn stage_gaps(w: &World, stage: Stage) -> Vec<Fail> {
    stage_gaps_with(w, stage, |r| r)
}

/// The properties `w` fails under each stage, `f` on each stage's rule (a control; none: `|r| r`).
fn by_stage(w: &World, f: impl Fn(Rule) -> Rule) -> BTreeMap<&'static str, Vec<&'static str>> {
    Stage::ALL
        .iter()
        .map(|&s| {
            let mut p: Vec<&str> = stage_fails_with(w, s, None, &f).iter().map(|f| f.prop).collect();
            p.sort();
            p.dedup();
            (s.name(), p)
        })
        .collect()
}

/// Finding 17's world (finding 1's: K writes D through [A, O]; O's admin W syncs O alone, D's
/// admin Y syncs D and R; X, syncing A, removes K listing nothing; the stolen K writes D): no
/// honest node syncs A together with O or D, so no node holding the removal holds D. Every stage
/// holds against its reference; every stage, today's included, has the gap at D (its reader shows
/// K's writes valid, the node holding everything invalid).
#[test]
fn open14_with_no_honest_node_between_the_removal_is_the_gap_at_d() {
    let w = family(Shape { via_org: true, units: 0, listed: false, thief: true, regrant: false, addendum: false, raised: false, q_d: false, q_r: false, y_a: false, org_apart: true, grant: false, mint: 0 });
    for (name, p) in by_stage(&w, |r| r) {
        assert_eq!(p, Vec::<&str>::new(), "{name}");
    }
    for s in Stage::ALL {
        let g = stage_gaps(&w, s);
        assert!(g.iter().any(|f| f.sid == D && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{}: {g:?}", s.name());
    }
}

/// The removed party's own other route (OPEN 14's finding): Y grants K write on D directly and A
/// write on D and R; K writes D directly (its stated path [], no hop through A); X removes K from
/// A; the stolen K writes R through [A]. X syncs A and D, Y syncs D and R; nobody honest syncs A
/// and R. Today K's write on D carries K's chain to D, which runs through A (any path), so X logs
/// the removal under D, Y takes it there and logs it under R as evidence of the thief's write.
/// By stated paths D's evidence holds nothing of (K, A), so no node holding the removal holds R:
/// the design has the gap at R (its reader shows the thief's write), where today's chains, kept
/// for removals or not, carry it. Every stage holds against its reference.
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
    for (name, p) in by_stage(&w, |r| r) {
        assert_eq!(p, Vec::<&str>::new(), "{name}");
    }
    for s in Stage::ALL {
        let g = stage_gaps(&w, s);
        assert_eq!(g.iter().any(|f| f.sid == R && f.id == late && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), matches!(s, Stage::A2 | Stage::A2Actor), "{}: {g:?}", s.name());
    }
}

/// R's mint admin (`open14_keys_open_*`).
const V: Thing = 7;

/// Role changes travel's keys-open half carries a removal of a thing's grant to the things that
/// read through it: K (of A) writes R through [A, O, D] (A writes O, O writes D, D writes R); Y
/// removes O from D; the stolen K writes R again. Y syncs D and A, N syncs A and R; R's admin V
/// syncs R alone. A reads through O, so the removal goes under A (Y logs it there), N takes it to
/// R as evidence of K's write. With keys-open travel left out (`a2-actor`) no node holding the
/// removal holds R: R's reader shows K's late write, counted as the gap (the reference follows the
/// rule's own delivery, so a delivery rule is compared by its gap).
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
    for (name, p) in by_stage(&w, |r| r) {
        assert_eq!(p, Vec::<&str>::new(), "{name}");
    }
    for s in Stage::ALL {
        assert_eq!(stage_gaps(&w, s).iter().any(|f| f.sid == R && f.id == late), s == Stage::A2Actor, "{}", s.name());
    }
}

/// The rule with record edges left out of keys-open travel (the control).
fn grants_only(r: Rule) -> Rule {
    Rule { records: false, ..r }
}

/// OPEN 17: finding 19's world with O minted by A (record (A, O)) in place of W granting A write
/// on O. K writes R through [A, O, D]; Y removes O from D; the stolen K writes R again. A's keys
/// open O through its record edge (spec/sync-set.md §2: effective role climbs record edges), so
/// Role changes travel puts the removal under A and N carries it to R. Every stage but the actor
/// seed alone brings it; read through grants only, none does (today's too: the control under-reads
/// today), and R's reader shows K's late write: the gap.
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
    for f in [(|r| r) as fn(Rule) -> Rule, grants_only] {
        for (name, p) in by_stage(&w, f) {
            assert_eq!(p, Vec::<&str>::new(), "{name}");
        }
    }
    let at_r = |g: Vec<Fail>| g.iter().any(|f| f.sid == R && f.id == late && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid));
    for s in Stage::ALL {
        assert_eq!(at_r(stage_gaps(&w, s)), s == Stage::A2Actor, "{}", s.name());
        assert!(at_r(stage_gaps_with(&w, s, grants_only)), "control {}", s.name());
    }
}

/// OPEN 17, finding 18's world with D minted by A in place of Y granting A write on D. X grants K
/// write on D (by descent through A) and Y grants A write on R; K writes D directly; X removes K
/// from A; the stolen K writes R through [A]. X syncs A and D, Y syncs D and R. Today K's chain to
/// D climbs A's record edge, so the removal goes under D and Y takes it to R; the design has the
/// gap at R.
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
    for (name, p) in by_stage(&w, |r| r) {
        assert_eq!(p, Vec::<&str>::new(), "{name}");
    }
    for s in Stage::ALL {
        assert_eq!(stage_gaps(&w, s).iter().any(|f| f.sid == R), matches!(s, Stage::A2 | Stage::A2Actor), "{}", s.name());
    }
}

/// The stage failures of every world in a job list, a thread per core: per stage the failing
/// worlds per property (the gap counted as `gap`), and per stage the worlds with the gap where
/// today has none.
pub type Job = Box<dyn Fn() -> (String, World, Option<Steps>) + Sync>;

/// `f` is applied to every stage's rule but today's (a control against today as built).
pub fn tally(jobs: &[Job], stages: &[Stage], f: impl Fn(Rule) -> Rule + Sync) -> String {
    let runs = crate::util::par_map(jobs, |j| {
        let (name, w, at) = j();
        let today = stage_gaps(&w, Stage::Today).is_empty();
        let per: Vec<(Stage, Vec<Fail>, bool)> = stages
            .iter()
            .map(|&s| {
                let fs = |r| if s == Stage::Today { r } else { f(r) };
                let (mut f, g) = (stage_fails_with(&w, s, at.as_ref(), fs), stage_gaps_with(&w, s, fs));
                let worse_here = today && !g.is_empty();
                f.extend(g);
                (s, f, worse_here)
            })
            .collect();
        (name, per)
    });
    let mut out = BTreeMap::<&str, BTreeMap<&str, (usize, String)>>::new();
    let mut worse = BTreeMap::<&str, (usize, String)>::new();
    for (name, per) in runs {
        for (s, f, worse_here) in per {
            crate::util::count_props(out.entry(s.name()).or_default(), &name, &f);
            if let Some(x) = f.iter().find(|x| worse_here && x.prop == "gap") {
                worse.entry(s.name()).or_insert((0, format!("{name}: {x:?}"))).0 += 1;
            }
        }
    }
    let mut s = String::new();
    for (st, props) in out {
        s += &format!("{st}\n");
        for (p, (k, first)) in props {
            s += &format!("  {p}: {k} worlds, first {first}\n");
        }
    }
    for (st, (k, first)) in worse {
        s += &format!("GAP WHERE TODAY HAS NONE {st}: {k}, first {first}\n");
    }
    s
}

/// Every stage over every `OSIS_REACH_STEP`th family world (97), `OSIS_REACH_RANDOM` random
/// worlds (100) and `OSIS_STORY_N` story seeds under every unit crossing (12), by hand.
/// `OSIS_REACH_CONTROL`: `grants` reads every stage but today's over grants only (`Rule::records`
/// off).
#[test]
#[ignore = "by hand"]
fn reach_explore() {
    use crate::util::env;
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
    eprintln!("{}", tally(&jobs, &Stage::ALL, |r| if control == "grants" { grants_only(r) } else { r }));
}
