//! Evidence over roles-model's stolen-node story (`evidence::story_world`): the story's role
//! history (invites, finalizes, `until`, covers, purges, trust, addenda written by the state-based
//! rule, commits of several edge writes and of several things, self-removals, paths of
//! two hops, a dependent by descent) under held-model's units and
//! delivery, each world under every unit crossing (`STORY_UNITS`). Checked at the end of each tick
//! of the story, and the order checks at the end.
use crate::spec_open10::fails_at;
use held_model::evidence::*;
use roles_model::paths::{self, Rules};

/// The rules a story is built and judged by.
pub fn rules() -> Rules {
    Rules::fixed()
}

/// Story world `sim` under unit crossing `units` and variant `v`: the failures.
pub fn story_fails(sim: &paths::Sim, units: usize, v: Open10) -> Vec<Fail> {
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
/// commit, the kiosk (invites kept under a demotion) and the thief removing H and B in one commit.
#[test]
fn a_story_world_under_a_retag_holds_under_iv() {
    let setup = paths::Setup { x_role: 5, x_a2: 5, h_t1: true, h_t2: true, regrant: true, ..Default::default() };
    let sim = paths::Sim::build(&setup, &rules(), &[paths::Move { kind: 43, ts: 8, made: 7 }], &mut roles_model::Rng(0));
    assert!((0..sim.w.commits.len()).any(|i| sim.w.parts(sim.w.cid(i)) > 1));
    assert_eq!(story_fails(&sim, 3, Open10::Granted), vec![]);
}

/// Per variant, failing worlds per property over story random worlds
/// `OSIS_HELD_START..+OSIS_STORY_N` (default 0..12), each under every unit crossing (by hand).
#[test]
#[ignore = "by hand"]
fn story_explore() {
    let env = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    let (start, n) = (env("OSIS_HELD_START", 0), env("OSIS_STORY_N", 12));
    let vs: Vec<Open10> = match std::env::var("OSIS_EV_RULE") {
        Ok(name) => Open10::ALL.into_iter().filter(|v| v.name() == name).collect(),
        Err(_) => vec![Open10::Drafted, Open10::Granted],
    };
    let mut jobs = vec![];
    for &v in &vs {
        for seed in start..start + n {
            for u in 0..STORY_UNITS {
                jobs.push((v, seed, u));
            }
        }
    }
    let out = std::sync::Mutex::new(std::collections::BTreeMap::<&str, std::collections::BTreeMap<&str, (usize, String)>>::new());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let t0 = std::time::Instant::now();
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let Some(&(v, seed, u)) = jobs.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) else { return };
                let sim = paths::random_world(seed, &rules());
                let f = story_fails(&sim, u, v);
                let mut o = out.lock().unwrap();
                let e = o.entry(v.name()).or_default();
                let mut seen = std::collections::BTreeSet::new();
                for x in f {
                    if seen.insert(x.prop) {
                        e.entry(x.prop).or_insert((0, format!("seed {seed} units {u}: {x:?}"))).0 += 1;
                    }
                }
            });
        }
    });
    eprintln!("{} jobs in {:?}", jobs.len(), t0.elapsed());
    for (v, props) in out.into_inner().unwrap() {
        eprintln!("{v}");
        for (p, (k, first)) in props {
            eprintln!("  {p}: {k} worlds, first {first}");
        }
    }
}

/// P0 to P10 under OPEN 10's (iv) (chained writes along joined paths, pending on chained grants,
/// entry creations): every `family_step`th family world, `random`
/// random worlds of 14 moves and `story` story random worlds under every unit crossing, from
/// `OSIS_HELD_START`, a thread per core.
fn search(family_step: usize, random_worlds: u64, story: u64) {
    let start = std::env::var("OSIS_HELD_START").ok().filter(|v| !v.is_empty()).map_or(0, |v| v.parse::<u64>().expect("OSIS_HELD_START is a decimal u64"));
    eprintln!("open10 (iv): random seeds {start}..{}, story seeds {start}..{}", start + random_worlds, start + story);
    type Job = Box<dyn Fn() -> (String, Vec<Fail>) + Sync>;
    let mut jobs: Vec<Job> = vec![];
    let set = move |mut w: World| {
        let rule = Open10::Granted.set(&mut w, Rule::fixed());
        w.rules = rules();
        crate::spec_open10::fails(&w, &rule)
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
                (format!("story seed {seed} units {u}"), story_fails(&sim, u, Open10::Granted))
            }));
        }
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
                    bad.lock().unwrap().push(format!("{name}: {:?}", f[0]));
                }
            });
        }
    });
    let bad = bad.into_inner().unwrap();
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
