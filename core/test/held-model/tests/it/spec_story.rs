//! Evidence over roles-model's stolen-node story (`evidence::story_world`): the story's role
//! history (may-grant grants, finalizes, `until`, covers, purges, trust, addenda written by the state-based
//! rule, commits of several edge writes and of several things, self-removals, paths of
//! two hops, a dependent by descent) under held-model's units and
//! delivery, each world under every unit crossing (`STORY_UNITS`). Checked at the end of each tick
//! of the story, and the order checks at the end.
use crate::spec_variants::fails_at;
use held_model::evidence::*;
use roles_model::paths::{self, Rules};

/// The rules a story is built and judged by.
pub fn rules() -> Rules {
    Rules::fixed()
}

/// Story world `sim` under unit crossing `units` and variant `v`: the failures.
pub fn story_fails(sim: &paths::Sim, units: usize, v: Variant) -> Vec<Fail> {
    let mut w = story_world(sim, units);
    w.rules = rules();
    let rule = v.set(&mut w, Rule::fixed());
    fails_at(&w, &rule, &story_steps(&w, sim))
}

/// The steps ending a tick of the story (the state after the last event made at each tick).
pub fn story_steps(w: &World, sim: &paths::Sim) -> std::collections::BTreeSet<usize> {
    let tick = |k: usize| match w.events[k] {
        Ev::Write(i) => Some(sim.made[i]),
        _ => None,
    };
    (0..w.events.len()).filter(|&k| k + 1 == w.events.len() || (tick(k).is_some() && tick(k + 1).is_some_and(|t| Some(t) != tick(k)))).map(|k| k + 1).collect()
}

/// One story world under (iv) with a retag (ORG joining T2's unit after the removal): the
/// adapter's default check. Family world with X's role write granting across two things in one
/// commit, the kiosk (may-grant grants kept under a demotion) and the thief removing H and B in one commit.
#[test]
fn a_story_world_under_a_retag_holds_under_iv() {
    let setup = paths::Setup { x_role: 5, x_a2: 5, h_t1: true, h_t2: true, regrant: true, ..Default::default() };
    let sim = paths::Sim::build(&setup, &rules(), &[paths::Move { kind: 43, ts: 8, made: 7 }], &mut roles_model::Rng(0));
    assert!((0..sim.w.commits.len()).any(|i| sim.w.parts(sim.w.cid(i)) > 1));
    assert_eq!(story_fails(&sim, 3, Variant::Granted), vec![]);
}

/// Per variant, failing worlds per property over story random worlds
/// `OSIS_HELD_START..+OSIS_STORY_N` (default 0..12), each under every unit crossing (by hand).
#[test]
#[ignore = "by hand"]
fn story_explore() {
    use crate::util::env;
    let (start, n) = (env("OSIS_HELD_START", 0), env("OSIS_STORY_N", 12));
    let vs: Vec<Variant> = match std::env::var("OSIS_EV_RULE") {
        Ok(name) => Variant::ALL.into_iter().filter(|v| v.name() == name).collect(),
        Err(_) => vec![Variant::Drafted, Variant::Granted],
    };
    let mut jobs = vec![];
    for &v in &vs {
        for seed in start..start + n {
            for u in 0..STORY_UNITS {
                jobs.push((v, seed, u));
            }
        }
    }
    let t0 = std::time::Instant::now();
    let runs = crate::util::par_map(&jobs, |&(v, seed, u)| (v, seed, u, story_fails(&paths::random_world(seed, &rules()), u, v)));
    eprintln!("{} jobs in {:?}", jobs.len(), t0.elapsed());
    let mut out = std::collections::BTreeMap::<&str, std::collections::BTreeMap<&str, (usize, String)>>::new();
    for (v, seed, u, f) in runs {
        crate::util::count_props(out.entry(v.name()).or_default(), &format!("seed {seed} units {u}"), &f);
    }
    for (v, props) in out {
        eprintln!("{v}");
        for (p, (k, first)) in props {
            eprintln!("  {p}: {k} worlds, first {first}");
        }
    }
}

/// P0 to P10 under closure variant (iv) (chained writes along joined paths, pending on chained grants,
/// entry creations): every `family_step`th family world, `random`
/// random worlds of 14 moves and `story` story random worlds under every unit crossing, from
/// `OSIS_HELD_START`, a thread per core.
fn search(family_step: usize, random_worlds: u64, story: u64) {
    let start = crate::util::env("OSIS_HELD_START", 0u64);
    eprintln!("closure variant (iv): random seeds {start}..{}, story seeds {start}..{}", start + random_worlds, start + story);
    type Job = Box<dyn Fn() -> (String, Vec<Fail>) + Sync>;
    let mut jobs: Vec<Job> = vec![];
    let set = move |mut w: World| {
        let rule = Variant::Granted.set(&mut w, Rule::fixed());
        w.rules = rules();
        crate::spec_variants::fails(&w, &rule)
    };
    for i in (0..FAMILY).step_by(family_step) {
        jobs.push(Box::new(move || (format!("{:?}", Shape::nth(i)), set(family(Shape::nth(i))))));
    }
    for seed in start..start + random_worlds {
        jobs.push(Box::new(move || (format!("random seed {seed}"), set(random(seed, 14)))));
    }
    for seed in start..start + story {
        for u in 0..STORY_UNITS {
            jobs.push(Box::new(move || {
                let sim = paths::random_world(seed, &rules());
                (format!("story seed {seed} units {u}"), story_fails(&sim, u, Variant::Granted))
            }));
        }
    }
    let bad: Vec<String> = crate::util::par_map(&jobs, |j| j()).into_iter().filter_map(|(name, f)| f.first().map(|x| format!("{name}: {x:?}"))).collect();
    assert!(bad.is_empty(), "{} worlds fail, first: {}", bad.len(), bad[0]);
}

#[test]
#[ignore = "property"]
fn evidence_along_joined_chained_paths_plain() {
    search(97, 40, 3);
}

#[test]
#[ignore = "property"]
fn evidence_along_joined_chained_paths_large() {
    search(17, 400, 40);
}
