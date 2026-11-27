//! How removals reach a sync ID (notes/write-path-design.md §2, D1 to D3: lazy delivery). Each
//! delivery rule (`deliveries`): the spec's (`Rule::fixed`: chain stubs) and bodies' evidence
//! alone (`Rule::bodies_only`). Each is judged against its reference
//! (`World::reference`) and its gap counted (`World::gap`). Hand worlds per finding;
//! `reach_explore` (by hand) tallies every delivery rule over the family, random and story worlds.
use crate::spec_evidence::fails_at;
use held_model::evidence::names::*;
use held_model::evidence::*;
use roles_model::paths::{self, Thing};
use roles_model::Role;
use std::collections::{BTreeMap, BTreeSet};

pub type Steps = BTreeSet<usize>;

/// The delivery rules compared, by name.
pub fn deliveries() -> [(&'static str, Rule); 2] {
    [("stubs", Rule::fixed()), ("bodies", Rule::bodies_only())]
}

/// `w` under `rule`: the failures, the per-step checks at steps `at` (every step: None).
pub fn fails_under(w: &World, rule: &Rule, at: Option<&Steps>) -> Vec<Fail> {
    let all: Steps = (1..=w.events.len()).collect();
    fails_at(w, rule, at.unwrap_or(&all))
}

/// The gap of `w` under `rule` at every step: what lazy delivery leaves showing (`World::gap`).
pub fn gaps_under(w: &World, rule: &Rule) -> Vec<Fail> {
    let mut out = vec![];
    w.run(rule, |st| out.extend(w.gap(rule, st)));
    out
}

/// The properties `w` fails under each delivery rule, `f` on each (a control; none: `|r| r`).
fn by_delivery(w: &World, f: impl Fn(Rule) -> Rule) -> BTreeMap<&'static str, Vec<&'static str>> {
    deliveries()
        .into_iter()
        .map(|(name, r)| {
            let mut p: Vec<&str> = fails_under(w, &f(r), None).iter().map(|f| f.prop).collect();
            p.sort();
            p.dedup();
            (name, p)
        })
        .collect()
}

/// Finding 17's world (finding 1's: K writes D through [A, O]; O's admin W syncs O alone, D's
/// admin Y syncs D and R; X, syncing A, removes K listing nothing; the stolen K writes D): no
/// honest node syncs A together with O or D, so no node holding the removal holds D. Every rule
/// holds against its reference; every rule has the gap at D (its reader shows
/// K's writes valid, the node holding everything invalid).
#[test]
fn reach_with_no_honest_node_between_the_removal_is_the_gap_at_d() {
    let w = family(Shape { via_org: true, units: 0, listed: false, thief: true, regrant: false, addendum: false, raised: false, q_d: false, q_r: false, y_a: false, org_apart: true, grant: false, mint: 0 });
    for (name, p) in by_delivery(&w, |r| r) {
        assert_eq!(p, Vec::<&str>::new(), "{name}");
    }
    for (name, rule) in deliveries() {
        let g = gaps_under(&w, &rule);
        assert!(g.iter().any(|f| f.sid == D && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{name}: {g:?}");
    }
}

/// The removed party's own other route (finding 18): Y grants K write on D directly and A
/// write on D and R; K writes D directly (its stated path [], no hop through A); X removes K from
/// A; the stolen K writes R through [A]. X syncs A and D, Y syncs D and R; nobody honest syncs A
/// and R. By stated paths D's evidence holds nothing of (K, A), so no node holding the removal
/// holds R: every rule has the gap at R (its reader shows the thief's write) and holds against
/// its reference.
#[test]
fn reach_a_removed_writers_other_route_is_the_gap_at_r() {
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
    for (name, p) in by_delivery(&w, |r| r) {
        assert_eq!(p, Vec::<&str>::new(), "{name}");
    }
    for (name, rule) in deliveries() {
        let g = gaps_under(&w, &rule);
        assert!(g.iter().any(|f| f.sid == R && f.id == late && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{name}: {g:?}");
    }
}

/// R's mint admin.
const V: Thing = 7;

/// Finding 19's world: K (of A) writes R through [A, O, D] (A writes O, O writes D, D writes R);
/// Y removes O from D; the stolen K writes R again. Y syncs D and A, N syncs A and R; R's admin V
/// syncs R alone. `wider` adds H (Y's), on which D holds read, to A's unit: a chain A, O, D, H by
/// which A's keys open a thing of A's unit, so O and D are chain stubs in A.
fn finding_19(record: bool, wider: bool) -> (World, paths::Id) {
    let o_admin = if record { A } else { W };
    let pw = paths::World::new(&[(X, A), (o_admin, O), (Y, D), (V, R), (Y, H)]);
    let mut w = World::new(pw, &[A, O, D, R, H]);
    let (x, wn, y, v, k) = (w.node(true, &[A]), w.node(true, &[O]), w.node(true, &[D, A]), w.node(true, &[R]), w.node(false, &[]));
    let _n = w.node(true, &[A, R]);
    if wider {
        w.member(H, A);
    }
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    if !record {
        w.write(wn, |p| p.edge(W, 1, &[], O, A, Role::Write, &[]));
    }
    w.write(y, |p| p.edge(Y, 1, &[], D, O, Role::Write, &[]));
    w.write(v, |p| p.edge(V, 1, &[], R, D, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], H, D, Role::Read, &[]));
    w.write(k, |p| p.content(K, 2, &[A, O, D], R));
    w.write(y, |p| p.edge(Y, 6, &[], D, O, Role::None, &[]));
    let late = w.write(k, |p| p.content(K, 8, &[A, O, D], R));
    (w, late)
}

/// Finding 19's gap under stubs (notes/stub-rewrite.md, Open for Tess 4): no unit carries anything through O
/// and D, so no node holding the removal holds R, and R's reader shows K's late write under every
/// rule. With a unit reading through them (`wider`), the chain stubs carry the removal under A
/// and N takes it to R; carrying bodies' evidence alone leaves the gap.
#[test]
fn reach_a_chain_stub_carries_a_removal_to_the_units_reading_through_it() {
    for record in [false, true] {
        for wider in [false, true] {
            let (w, late) = finding_19(record, wider);
            for (name, p) in by_delivery(&w, |r| r) {
                assert_eq!(p, Vec::<&str>::new(), "{name}");
            }
            for (name, rule) in deliveries() {
                let gap = gaps_under(&w, &rule).iter().any(|f| f.sid == R && f.id == late && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid));
                assert_eq!(gap, !(wider && rule.chain_stubs), "{name} record {record} wider {wider}");
            }
        }
    }
}

/// The rule with record edges left out of the chains (the control): A's keys open O through its
/// record edge alone, so no chain is found and the gap stays.
#[test]
fn records_chains_climb_a_mint_admins_record_edge() {
    let (w, late) = finding_19(true, true);
    let rule = Rule { records: false, ..Rule::fixed() };
    assert!(gaps_under(&w, &rule).iter().any(|f| f.sid == R && f.id == late));
}

/// A record edge on the other route: finding 18's world with D minted by A in place of Y granting A write on D. X grants K
/// write on D (by descent through A) and Y grants A write on R; K writes D directly; X removes K
/// from A; the stolen K writes R through [A]. X syncs A and D, Y syncs D and R. No node holding
/// the removal holds R: every rule has the gap at R.
#[test]
fn records_a_removed_writers_other_route_through_a_record_edge() {
    let pw = paths::World::new(&[(X, A), (A, D), (Y, R)]);
    let mut w = World::new(pw, &[A, D, R]);
    let (x, y, k) = (w.node(true, &[A, D]), w.node(true, &[D, R]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], R, A, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 1, &[], D, K, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[], D));
    w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    w.write(k, |p| p.content(K, 8, &[A], R));
    for (name, p) in by_delivery(&w, |r| r) {
        assert_eq!(p, Vec::<&str>::new(), "{name}");
    }
    for (name, rule) in deliveries() {
        assert!(gaps_under(&w, &rule).iter().any(|f| f.sid == R), "{name}");
    }
}

/// A world to check: its name, the world, the steps to check it at (every step: None).
pub type Job = Box<dyn Fn() -> (String, World, Option<Steps>) + Sync>;

/// The failures of every world in a job list under each delivery rule (`f` applied to each, a
/// control), a thread per core: per rule the failing worlds per property (the gap counted as `gap`).
pub fn tally(jobs: &[Job], f: impl Fn(Rule) -> Rule + Sync) -> String {
    let runs = crate::util::par_map(jobs, |j| {
        let (name, w, at) = j();
        let per: Vec<(&'static str, Vec<Fail>)> = deliveries()
            .into_iter()
            .map(|(d, r)| {
                let r = f(r);
                let mut fails = fails_under(&w, &r, at.as_ref());
                fails.extend(gaps_under(&w, &r));
                (d, fails)
            })
            .collect();
        (name, per)
    });
    let mut out = BTreeMap::<&str, BTreeMap<&str, (usize, String)>>::new();
    for (name, per) in runs {
        for (d, f) in per {
            crate::util::count_props(out.entry(d).or_default(), &name, &f);
        }
    }
    let mut s = String::new();
    for (st, props) in out {
        s += &format!("{st}\n");
        for (p, (k, first)) in props {
            s += &format!("  {p}: {k} worlds, first {first}\n");
        }
    }
    s
}

/// Every delivery rule over every `OSIS_REACH_STEP`th family world (97), `OSIS_REACH_RANDOM` random
/// worlds (100) and `OSIS_STORY_N` story seeds under every unit crossing (12), by hand.
/// `OSIS_REACH_CONTROL`: `grants` reads every rule over grants only (`Rule::records` off).
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
    eprintln!("{}", tally(&jobs, |r| if control == "grants" { Rule { records: false, ..r } } else { r }));
}
