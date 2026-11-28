//! Evidence over roles-model's stolen-node story (`evidence::story_world`): the story's role
//! history (may-grant grants, finalizes, `until`, covers, purges, trust, addenda written by the state-based
//! rule, commits of several grant writes and of several things, self-removals, paths of
//! two hops, a dependent by descent) under held-model's units and
//! delivery, each world under every unit crossing (`STORY_UNITS`). Checked at the end of each tick
//! of the story, and the order checks at the end.
use crate::spec_evidence::fails_at;
use held_model::evidence::*;
use roles_model::paths::{self, Rules};

/// The rules a story is built and judged by.
pub fn rules() -> Rules {
    Rules::fixed()
}

/// Story world `sim` under unit crossing `units`: the failures under the spec's rule.
pub fn story_fails(sim: &paths::Sim, units: usize) -> Vec<Fail> {
    let mut w = story_world(sim, units);
    w.rules = rules();
    fails_at(&w, &Rule::fixed(), &story_steps(&w, sim))
}

/// The steps ending a tick of the story (the state after the last event made at each tick).
pub fn story_steps(w: &World, sim: &paths::Sim) -> std::collections::BTreeSet<usize> {
    let tick = |k: usize| match w.events[k] {
        Ev::Write(i) => Some(sim.made[i]),
        _ => None,
    };
    (0..w.events.len()).filter(|&k| k + 1 == w.events.len() || (tick(k).is_some() && tick(k + 1).is_some_and(|t| Some(t) != tick(k)))).map(|k| k + 1).collect()
}

/// One story world with a retag (ORG joining T2's unit after the removal): the adapter's default
/// check. Family world with X's role write granting across two things in one commit, the kiosk
/// (may-grant grants kept under a demotion) and the thief removing H and B in one commit.
#[test]
fn a_story_world_under_a_retag_holds() {
    let setup = paths::Setup { x_role: 5, x_a2: 5, h_t1: true, h_t2: true, regrant: true, ..Default::default() };
    let sim = paths::Sim::build(&setup, &rules(), &[paths::Move { kind: 43, ts: 8, made: 7 }], &mut roles_model::Rng(0));
    assert!((0..sim.w.commits.len()).any(|i| sim.w.parts(sim.w.cid(i)) > 1));
    assert_eq!(story_fails(&sim, 3), vec![]);
}

/// Failing worlds per property over story random worlds `OSIS_HELD_START..+OSIS_STORY_N`
/// (default 0..12), each under every unit crossing (by hand).
#[test]
#[ignore = "by hand"]
fn story_explore() {
    use crate::util::env;
    let (start, n) = (env("OSIS_HELD_START", 0), env("OSIS_STORY_N", 12));
    let jobs: Vec<(u64, usize)> = (start..start + n).flat_map(|seed| (0..STORY_UNITS).map(move |u| (seed, u))).collect();
    let runs = crate::util::par_map(&jobs, |&(seed, u)| (seed, u, story_fails(&paths::random_world(seed, &rules()), u)));
    let mut out = std::collections::BTreeMap::<&str, (usize, String)>::new();
    for (seed, u, f) in runs {
        crate::util::count_props(&mut out, &format!("seed {seed} units {u}"), &f);
    }
    for (p, (k, first)) in out {
        eprintln!("{p}: {k} worlds, first {first}");
    }
}

/// Every property over `story` story random worlds from `OSIS_HELD_START`, each under every unit
/// crossing, a thread per core.
fn search(story: u64) {
    let start = crate::util::env("OSIS_HELD_START", 0u64);
    eprintln!("story seeds {start}..{}", start + story);
    let jobs: Vec<(u64, usize)> = (start..start + story).flat_map(|seed| (0..STORY_UNITS).map(move |u| (seed, u))).collect();
    let bad: Vec<String> = crate::util::par_map(&jobs, |&(seed, u)| story_fails(&paths::random_world(seed, &rules()), u).first().map(|x| format!("story seed {seed} units {u}: {x:?}"))).into_iter().flatten().collect();
    assert!(bad.is_empty(), "{} worlds fail, first: {}", bad.len(), bad[0]);
}

#[test]
#[ignore = "property"]
fn evidence_over_story_worlds_plain() {
    search(3);
}

#[test]
#[ignore = "property"]
fn evidence_over_story_worlds_large() {
    search(40);
}
