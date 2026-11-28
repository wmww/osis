//! The joint property (held_model::evidence `joint`; spec/sync-set.md §2 Stubs): a node
//! acting as a signer and holding one sync ID plus the stubs of the holders on its paths judges
//! and acts as the node holding everything. Over the evidence family, random and wide worlds under the spec's
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

/// Each control and the check it fails. `J-judge` has none: no generated world holds a stub that
/// moves a verdict on S's bodies off both S's reference and the node holding everything.
const CONTROLS: [(Joint, &str); 4] = [(Joint::Unit, "J-act"), (Joint::UnitLog, "J-logged"), (Joint::Grants, "J-act"), (Joint::WorldPaths, "J-act")];

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

/// K (a member of A) reaches D through [A], [A, O] and [A, H, O]; W removes A on O. D's entries
/// lack the removal (no body of D rests on it); O stays on a path, so O's stub, cut to the grants
/// into it from the path's holders, has the removal with the grant: K, syncing D alone with its
/// paths' stubs, does not act along the removed hop. Holding stubs without their removals, it
/// does.
#[test]
fn joint_a_removed_hop_reaches_the_actor_through_the_stub() {
    use held_model::evidence::names::*;
    use roles_model::Role;
    let pw = roles_model::paths::World::new(&[(X, A), (W, O), (Y, D), (W, H)]);
    let mut w = World::new(pw, &[A, O, D, H]);
    let (x, wn, y) = (w.node(true, &[A]), w.node(true, &[O, H]), w.node(true, &[D]));
    w.write(x, |p| p.grant(X, 1, &[], A, K, Role::Write, &[]));
    w.write(wn, |p| p.grant(W, 1, &[], O, A, Role::Write, &[]));
    w.write(wn, |p| p.grant(W, 1, &[], H, A, Role::Write, &[]));
    w.write(wn, |p| p.grant(W, 1, &[], O, H, Role::Write, &[]));
    w.write(y, |p| p.grant(Y, 1, &[], D, O, Role::Write, &[]));
    w.write(y, |p| p.grant(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(wn, |p| p.grant(W, 2, &[], O, A, Role::None, &[]));
    let acts = |j: Joint| joint(w.clone(), j).into_iter().filter(|f| f.prop == "J-act").count();
    assert_eq!(acts(Joint::Paths), 0);
    assert!(acts(Joint::Grants) > 0);
}

/// O is minted by A and holds write on H. Z (admin on H) would reach O through [H, A], H on A by
/// Q's grant; X then lowers Q to write on A with no frontier, so H's hop on A falls with it. A
/// holder's stub carries the lowering with the hop it undoes (the evidence of H's grant on A is
/// every write on Q's hop), so Z's own reading shows no path the world's lacks: Z does not act
/// along [H, A], with or without the paths its own reading shows.
#[test]
fn joint_a_stub_carries_a_lowering_with_the_hop_it_undoes() {
    use held_model::evidence::names::*;
    use roles_model::Role;
    let pw = roles_model::paths::World::new(&[(X, A), (A, O), (W, H)]);
    let mut w = World::new(pw, &[A, O, H]);
    let (x, h) = (w.node(true, &[A, O]), w.node(true, &[H]));
    w.node(true, &[O]);
    w.write(h, |p| p.grant(W, 1, &[], H, Z, Role::Admin, &[]));
    w.write(h, |p| p.grant(W, 1, &[], H, O, Role::Write, &[]));
    w.write(h, |p| p.content(Z, 1, &[], H));
    w.write(x, |p| p.grant(X, 1, &[], A, Q, Role::Admin, &[]));
    w.write(x, |p| p.grant(Q, 1, &[], A, H, Role::Write, &[]));
    w.write(x, |p| p.grant(X, 2, &[], A, Q, Role::Write, &[]));
    let acts = |j: Joint| joint(w.clone(), j).into_iter().filter(|f| f.prop == "J-act").count();
    assert_eq!(acts(Joint::Paths), 0);
    assert_eq!(acts(Joint::WorldPaths), 0);
}

#[test]
#[ignore = "property"]
fn joint_one_sync_id_and_chain_stubs_act_as_everything_plain() {
    search(env("OSIS_JOINT_STEP", 97), env("OSIS_JOINT_RANDOM", 40));
}
