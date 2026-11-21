//! The evidence generators' gaps (notes/evidence-model-findings.md, Generators): per-node trust
//! sets (P1 for readers trusting otherwise than the world), paths of up to four holder things with
//! churn and junk on every edge and second routes (`wide`), content in the split form across units
//! (`Wide::split`), path entries opening late (`Wide::late`, `World::opens`). Each under every
//! stage, the design's (`Stage::A2`) first, judged against its reference with the gap counted.
//! `gaps_explore` (by hand) tallies them; the sampled searches run the design.
use crate::spec_reach::{stage_fails, stage_gaps, Job};
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
pub fn gap_fails(w: &World, stage: Stage, trusts: &[Set]) -> Vec<Fail> {
    let mut out = stage_fails(w, stage);
    if trusts.is_empty() {
        return out;
    }
    let mut w = w.clone();
    w.rules = crate::spec_story::rules();
    let rule = stage.set(&mut w, Rule::fixed());
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
        assert_eq!(gap_fails(&w, s, &[Set::new(), Set::from([r])]), vec![], "{}", s.name());
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
        assert_eq!(gap_fails(&w, s, &[]), vec![], "{}", s.name());
    }
    let mut wg = w.clone();
    let rule = Stage::A2.set(&mut wg, Rule::fixed());
    let st = wg.run(&rule, |_| {});
    let rd = |s| wg.verdicts(&wg.reader(&rule, &st, s, &Set::new()), &Set::from([ids[0], ids[1]]));
    assert_eq!(rd(D)[&ids[0]], Verdict::Invalid);
    assert_eq!(rd(R)[&ids[1]], Verdict::Valid);
}

/// A list entry names its part on its leaf's thing alone (finding 24; `wide` seed 14204407701,
/// split, late and mint, shrunk): Z writes one commit in the split form, a part on D through
/// [A, O] and a part on A directly; X removes Z from A listing the commit's part on D only (it
/// lists what it chooses: nothing checks a list). The judge (roles-model `paths`,
/// `World::in_leaves`) reads an entry per thing, so A's reader, holding the whole list, and the
/// node holding everything both judge Z's part on A unlisted (invalid), at every stage.
#[test]
fn gaps_a_list_entry_names_its_part_on_its_leafs_thing_alone() {
    let pw = paths::World::new(&[(X, A), (W, O), (Y, D)]);
    let mut w = World::new(pw, &[A, O, D]);
    let (x, wn, y, z) = (w.node(true, &[A]), w.node(true, &[O]), w.node(true, &[D]), w.node(true, &[A, D]));
    w.write(x, |p| p.edge(X, 1, &[], A, Z, Role::Write, &[]));
    w.write(wn, |p| p.edge(W, 1, &[], O, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, O, Role::Write, &[]));
    let ids = w.write_parts(z, |p| p.split(Z, 2, Z, &[(&[A, O], D), (&[], A)]));
    w.write(x, |p| p.edge(X, 3, &[], A, Z, Role::None, &[ids[0]]));
    for s in Stage::ALL {
        let f = gap_fails(&w, s, &[]);
        assert!(f.iter().all(|f| f.prop.starts_with("P1") || f.prop == "P8-promote") && !f.iter().any(|f| f.prop == "P1" && f.id == ids[1]), "{}: {f:?}", s.name());
    }
    let mut wl = w.clone();
    let rule = Stage::A2.set(&mut wl, Rule::fixed());
    let st = wl.run(&rule, |_| {});
    let full = wl.verdicts(&wl.full(&st, &Set::new()), &Set::from([ids[0], ids[1]]));
    assert_eq!((full[&ids[0]], full[&ids[1]]), (Verdict::Valid, Verdict::Invalid));
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
        assert_eq!(gap_fails(&w, s, &[]), vec![], "{}", s.name());
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

/// Per stage, the worlds failing each property (P1-trust: two random trust sets) or with the gap
/// over `OSIS_GAPS_N` (60) wide worlds per option set and the family slice, and the worlds with
/// the gap where today has none, by hand. `OSIS_EV_RULE` names one stage.
#[test]
#[ignore = "by hand"]
fn gaps_explore() {
    let n: u64 = std::env::var("OSIS_GAPS_N").ok().and_then(|v| v.parse().ok()).unwrap_or(60);
    let stages: Vec<Stage> = match std::env::var("OSIS_EV_RULE") {
        Ok(name) => Stage::ALL.into_iter().filter(|s| s.name() == name).collect(),
        Err(_) => Stage::ALL.to_vec(),
    };
    let opts = WIDE_OPTS;
    let out = std::sync::Mutex::new(BTreeMap::<(String, &str), BTreeMap<&str, (usize, String)>>::new());
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
                let today = stages.contains(&Stage::Today) && stage_gaps(&w, Stage::Today).is_empty();
                for &s in &stages {
                    let mut f = gap_fails(&w, s, &trusts);
                    let gp = stage_gaps(&w, s);
                    let worse = today && !gp.is_empty();
                    f.extend(gp);
                    let mut o = out.lock().unwrap();
                    let e = o.entry((g.clone(), s.name())).or_default();
                    let mut seen = BTreeSet::new();
                    for x in &f {
                        if seen.insert(x.prop) {
                            e.entry(x.prop).or_insert((0, format!("{name}: {x:?}"))).0 += 1;
                        }
                    }
                    if worse {
                        e.entry("GAP-WHERE-TODAY-HAS-NONE").or_insert((0, name.to_string())).0 += 1;
                    }
                }
            });
        }
    });
    for ((g, s), props) in out.into_inner().unwrap() {
        eprintln!("{g} {s}");
        for (p, (k, first)) in props {
            eprintln!("  {p}: {k} worlds, first {first}");
        }
    }
}

/// The sampled property: the design (`Stage::A2`) holds P0 to P10 and P1 for two random trust
/// sets against its reference over `wide` worlds under every option set (`per` seeds each from
/// `OSIS_HELD_START`), the worlds with the gap counted.
fn search(per: u64) {
    let start = std::env::var("OSIS_HELD_START").ok().filter(|v| !v.is_empty()).map_or(0, |v| v.parse::<u64>().expect("OSIS_HELD_START is a decimal u64"));
    eprintln!("gaps: wide seeds from {start}");
    let mut jobs: Vec<Job> = vec![];
    for opt in WIDE_OPTS {
        jobs.extend(wide_jobs(start, per, opt));
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let bad = std::sync::Mutex::new(vec![]);
    let gap = std::sync::atomic::AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let Some(j) = jobs.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) else { return };
                let (name, w, _) = j();
                let trusts = trust_sets(&w, name.bytes().fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(b as u64)));
                if let Some(f) = gap_fails(&w, Stage::A2, &trusts).first() {
                    bad.lock().unwrap().push(format!("a2 {name}: {f:?}"));
                }
                gap.fetch_add(usize::from(!stage_gaps(&w, Stage::A2).is_empty()), std::sync::atomic::Ordering::Relaxed);
            });
        }
    });
    // the gap, counted (issues/removed-key-writes-show-far.md)
    eprintln!("{} worlds; {} with the gap", jobs.len(), gap.into_inner());
    let bad = bad.into_inner().unwrap();
    assert!(bad.is_empty(), "{} fail, first: {}", bad.len(), bad[0]);
}

#[test]
#[ignore = "property"]
fn evidence_reach_and_generator_gaps_plain() {
    search(2);
}

#[test]
#[ignore = "property"]
fn evidence_reach_and_generator_gaps_large() {
    search(40);
}

/// One `wide` world by hand: `OSIS_GAPS_SEED`, `OSIS_GAPS_OPT` (letters s, l, m: split, late,
/// mint), its commits, events and every stage's failures.
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
        eprintln!("{i}: by {} cid {} {} ts {} path {:?} on {} {:?} rests {:?}", w.by[i], w.w.cid(i), c.signer, c.ts, c.path, c.on, c.kind, w.w.rests(i));
    }
    eprintln!("events {:?}", w.events);
    for s in Stage::ALL {
        for f in stage_fails(&w, s) {
            eprintln!("{}: {f:?}", s.name());
        }
    }
}

/// Finding 20 (`wide` seed 14204407699, split and late, shrunk): K writes O through [A], where A holds
/// only read on O, after X removed K from A; nobody honest syncs A and O. The write is invalid
/// everywhere (no write reaches O through A), with or without the removal. Where any grant joins a
/// hop (J1) the path is joined, so O's evidence closure over everything holds the removal, which
/// nothing delivers to O and which moves no verdict there. Where only a grant giving what the write
/// needs joins (J2, finding 23) the closure stops at the read hop and the write waits everywhere.
/// Once W raises A to write on O (backdated, after the removal), the removal decides K's write and
/// no node holding it holds O: the gap at every stage (finding 17's class, today too).
#[test]
fn gaps_a_removal_on_a_path_through_a_read_hop_is_the_gap_once_it_decides() {
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
    let (mut w, r, c) = base(false);
    for join in [Join::Any, Join::Needed] {
        w.join = join;
        let mut wr = w.clone();
        let rule = Stage::A2.set(&mut wr, Rule::fixed());
        let st = wr.run(&rule, |_| {});
        let all = wr.full(&st, &Set::new()).v.held;
        // J1: the full closure of O's bodies holds the removal (a read grant joins (A, O)), O's
        // reader does not require it, the write is invalid; J2: the read hop joins nothing for a
        // write, so the closure stops there and the write waits everywhere
        let any = join == Join::Any;
        assert_eq!(wr.closure(&rule, &wr.owed_bodies(&st, O), &all).contains(&r), any);
        assert!(!wr.req(&rule, O, &st.units, &st.entries[&O]).contains(&r));
        assert_eq!(wr.verdicts(&wr.full(&st, &Set::new()), &Set::from([c]))[&c], if any { Verdict::Invalid } else { Verdict::Pending });
        for s in Stage::ALL {
            assert_eq!(gap_fails(&w, s, &[]), vec![], "{} {}", join.name(), s.name());
        }
    }
    let (w, _, c) = base(true);
    for s in Stage::ALL {
        assert_eq!(gap_fails(&w, s, &[]), vec![], "{}", s.name());
        assert!(stage_gaps(&w, s).iter().any(|f| f.sid == O && f.id == c && f.reader == Some(Verdict::Valid)), "{}", s.name());
    }
}

/// Finding 23 (`wide` seed 14204407685, shrunk): the stolen K writes R through [A, O], A holding
/// only read on O (W's grant), O write on R; X, W and Y each sync their own thing alone and the
/// thief logs no grant giving below write. The node holding everything judges the write invalid
/// (no write reaches R through a read hop); R's reader, lacking W's read grant, holds no chained
/// grant on (A, O). Under J1 (a hop joined by any chained grant) it pends: P1 fails at every
/// stage, today's included. Under J2 (joined and pending by a grant giving the role the part
/// needs) the node holding everything pends too; under J3 (a hop no grant joins judged invalid)
/// the reader judges it invalid. Either holds P1 at every stage; J3 leaves X's grant to K, which
/// the thief logs, held under R and required by no reader (P4).
#[test]
fn gaps_a_write_through_a_read_hop_pends_at_a_reader_lacking_the_read_grant() {
    let pw = paths::World::new(&[(X, A), (W, O), (Y, R)]);
    let mut w = World::new(pw, &[A, O, R]);
    let (x, wn, y, k) = (w.node(true, &[A]), w.node(true, &[O]), w.node(true, &[R]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(wn, |p| p.edge(W, 1, &[], O, A, Role::Read, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], R, O, Role::Write, &[]));
    let c = w.write(k, |p| p.content(K, 5, &[A, O], R));
    for join in Join::ALL {
        w.join = join;
        for s in Stage::ALL {
            let f = crate::spec_reach::stage_fails(&w, s);
            let pends = f.iter().any(|f| f.prop == "P1" && f.sid == R && f.id == c && f.reader == Some(Verdict::Pending) && f.full == Some(Verdict::Invalid));
            assert_eq!(pends, join == Join::Any, "{} {}: {f:?}", join.name(), s.name());
            assert!(f.iter().all(|f| matches!(f.prop, "P1" | "P4-held")), "{} {}: {f:?}", join.name(), s.name());
            // the thief logs X's grant to K under R, which R's reader requires only where it
            // joins the path: never under J1 or J3 (no grant on (A, O) held), and under J2 the
            // thief's closure takes it only through today's any-path chains
            let held = f.iter().any(|f| f.prop == "P4-held");
            assert_eq!(held, join != Join::Needed || s == Stage::Today, "{} {}: {f:?}", join.name(), s.name());
        }
    }
}

/// The generator reaches finding 23's shape at default size (`wide`'s read-hop move): among the
/// first `wide` worlds (no options) some hold the thief's write through a read hop that a reader
/// without the read grant pends on while the node holding everything judges it invalid, under the
/// design with J1 (a hop joined by any grant); with J2 it holds each of them. (The sampled searches
/// run every world under J2.)
#[test]
fn gaps_wide_worlds_reach_the_read_hop() {
    let mut hit = vec![];
    for seed in 0..16 {
        let mut w = wide(seed, 16, Wide::default());
        w.join = Join::Any;
        if crate::spec_reach::stage_fails(&w, Stage::A2).iter().any(|f| f.prop == "P1" && f.reader == Some(Verdict::Pending) && f.full == Some(Verdict::Invalid)) {
            hit.push(seed);
            w.join = Join::Needed;
            assert_eq!(crate::spec_reach::stage_fails(&w, Stage::A2), vec![], "seed {seed}");
        }
    }
    assert!(!hit.is_empty(), "the generator no longer reaches finding 23's read hop in 16 worlds: raise its rate");
}

/// Finding 28 (`wide` seed 14204407714, split, shrunk): X removes K and Q from A in one commit; Q
/// (its node honest, syncing A and D) then writes D through [A], A holding only read on D; the
/// stolen K writes R through [A]. Y syncs D and R; nobody honest syncs A and R. The removal reaches
/// R only by riding Q's write: where a read hop joins a path (J1, J4's closure, today's any-path
/// chains), D's evidence takes the removal's copy (Q's removal is in it), Y holds it and R's reader
/// requires it; under J2 Q's write through the read hop brings nothing, no node holding the removal
/// holds R, and R's reader shows K's write valid: the gap (the design's, where today has none).
#[test]
fn gaps_a_removal_rides_a_write_through_a_read_hop_only_where_read_joins() {
    let pw = paths::World::new(&[(X, A), (Y, D), (Y, R)]);
    let mut w = World::new(pw, &[A, D, R]);
    let (x, y, q, k) = (w.node(true, &[A]), w.node(true, &[D, R]), w.node(true, &[A, D]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Admin, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Read, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], R, A, Role::Write, &[]));
    w.write_parts(x, |p| p.commit(X, 3, &[], A, vec![paths::Kind::set(K, Role::None), paths::Kind::set(Q, Role::None)]));
    w.write(q, |p| p.content(Q, 4, &[A], D));
    let c = w.write(k, |p| p.content(K, 5, &[A], R));
    for join in Join::ALL {
        w.join = join;
        for s in Stage::ALL {
            assert_eq!(gap_fails(&w, s, &[]), vec![], "{} {}", join.name(), s.name());
            let g = stage_gaps(&w, s);
            let shows = g.iter().any(|f| f.sid == R && f.id == c && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid));
            assert_eq!(shows, join == Join::Needed && matches!(s, Stage::A2 | Stage::A2Actor), "{} {}: {g:?}", join.name(), s.name());
        }
    }
}
