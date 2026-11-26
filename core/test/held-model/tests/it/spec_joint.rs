//! The joint property (notes/holder-access-study.md, With A2; held_model::evidence `joint`): a
//! node acting as a signer and holding one sync ID plus its paths' key parts judges and acts as
//! the node holding everything. Over the evidence family, random and wide worlds under the spec's
//! rule (`Rule::fixed`), with a control per check. spec: none (modelled before any spec).
use crate::util::{env, par_any, par_map};
use held_model::evidence::*;
use std::collections::BTreeMap;

/// The failures over `w` at every step.
fn joint(w: World, j: Joint) -> Vec<Fail> {
    let rule = Rule::fixed();
    let mut out = vec![];
    roles_model::paths::judging_once(&w.w, || w.run(&rule, |st| out.extend(w.joint(&rule, st, j))));
    out
}

/// Per property the worlds failing it and the first failure.
type Tally = BTreeMap<&'static str, (usize, String)>;

/// Every `family_step`th family world and `n` random and `n` wide worlds (seeds from
/// `OSIS_HELD_START`), each built by its job with its name.
type Job = Box<dyn Fn() -> (String, World) + Sync>;
fn worlds(family_step: usize, n: u64) -> Vec<Job> {
    let start = env("OSIS_HELD_START", 0u64);
    let mut jobs: Vec<Job> = vec![];
    for i in (0..FAMILY).step_by(family_step) {
        jobs.push(Box::new(move || (format!("{:?}", Shape::nth(i)), family(Shape::nth(i)))));
    }
    for seed in start..start + n {
        jobs.push(Box::new(move || (format!("random {seed}"), random(seed, 14))));
        jobs.push(Box::new(move || (format!("wide {seed}"), wide(seed, 16, Wide { mint: seed % 2 == 1, ..Wide::default() }))));
    }
    jobs
}

/// The worlds of `jobs` under `j`: per property the worlds failing it and the first failure.
fn tally(jobs: &[Job], j: Joint) -> Tally {
    let mut out = Tally::new();
    for (name, f) in par_map(jobs, |job| {
        let (name, w) = job();
        (name, joint(w, j))
    }) {
        let mut first = BTreeMap::new();
        for x in &f {
            first.entry(x.prop).or_insert(x);
        }
        for (p, x) in first {
            out.entry(p).or_insert((0, format!("{name}: {x:?}"))).0 += 1;
        }
    }
    out
}

/// Each control and the check it fails. `J-judge` has none: no generated world holds a key part
/// that moves a verdict on S's bodies off both S's reference and the node holding everything.
const CONTROLS: [(Joint, &str); 3] = [(Joint::Unit, "J-act"), (Joint::UnitLog, "J-logged"), (Joint::Grants, "J-act")];

/// The design holds every check over every world of `jobs`; each control fails its own in some
/// world (searched until one does).
fn holds_with_controls(jobs: &[Job], controls: &[(Joint, &str)]) {
    let t = tally(jobs, Joint::Paths);
    eprintln!("joint, design: {} worlds", jobs.len());
    assert!(t.is_empty(), "the design fails: {t:?}");
    for (j, prop) in controls {
        let fails = par_any(jobs, |job| joint(job().1, *j).iter().any(|f| f.prop == *prop));
        assert!(fails, "control {j:?} never fails {prop} in {} worlds", jobs.len());
    }
}

fn search(family_step: usize, n: u64) {
    holds_with_controls(&worlds(family_step, n), &CONTROLS);
}

#[test]
fn joint_holds_on_a_slice() {
    holds_with_controls(&worlds(1999, 4), &CONTROLS[..2]);
}

/// K (a member of A) reaches D through [A] and [A, O]; W removes A on O. D's entries lack the
/// removal (no body of D rests on it), A's key part has it: K, syncing D alone with its paths' key
/// parts, does not act along the removed hop. Holding key parts without their removals, it does.
#[test]
fn joint_a_removed_hop_reaches_the_actor_through_the_key_part() {
    use held_model::evidence::names::*;
    use roles_model::Role;
    let pw = roles_model::paths::World::new(&[(X, A), (W, O), (Y, D)]);
    let mut w = World::new(pw, &[A, O, D]);
    let (x, wn, y) = (w.node(true, &[A]), w.node(true, &[O]), w.node(true, &[D]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(wn, |p| p.edge(W, 1, &[], O, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, O, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(wn, |p| p.edge(W, 2, &[], O, A, Role::None, &[]));
    let acts = |j: Joint| joint(w.clone(), j).into_iter().filter(|f| f.prop == "J-act").count();
    assert_eq!(acts(Joint::Paths), 0);
    assert!(acts(Joint::Grants) > 0);
}

#[test]
#[ignore = "property"]
fn joint_one_sync_id_and_key_parts_act_as_everything_plain() {
    search(env("OSIS_JOINT_STEP", 97), env("OSIS_JOINT_RANDOM", 40));
}
