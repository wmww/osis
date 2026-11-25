//! The evidence generators' gaps (notes/evidence-model-findings.md, Generators): per-node trust
//! sets (P1 for readers trusting otherwise than the world), paths of up to four holder things with
//! churn and junk on every edge and second routes (`wide`), content in the split form across units
//! (`Wide::split`), path entries opening late (`Wide::late`, `World::opens`). Each under every
//! delivery rule (`spec_reach::deliveries`), judged against its reference with the gap counted.
//! `gaps_explore` (by hand) tallies them; the sampled searches run the spec's rule.
use crate::spec_reach::{deliveries, fails_under, gaps_under, Job};
use held_model::evidence::names::*;
use held_model::evidence::*;
use roles_model::paths::{self, Set};
use roles_model::Role;
use std::collections::BTreeMap;

/// Two random trust sets over `w`'s edge writes (each lowering or other edge write with one
/// chance in two), from `seed`.
pub fn trust_sets(w: &World, seed: u64) -> Vec<Set> {
    let mut rng = roles_model::Rng::thread(seed, 2);
    let edges: Vec<usize> = (0..w.w.commits.len()).filter(|&i| w.w.sets(i).is_some()).collect();
    (0..2).map(|_| edges.iter().copied().filter(|_| rng.below(2) == 0).collect()).collect()
}

/// A world name's trust-set seed.
fn name_seed(name: &str) -> u64 {
    name.bytes().fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(b as u64))
}

/// `w` under `rule` (every property, `fails_under`) and P1 for readers trusting each of `trusts`
/// at every step.
pub fn gap_fails(w: &World, rule: &Rule, trusts: &[Set]) -> Vec<Fail> {
    let mut out = fails_under(w, rule, None);
    if trusts.is_empty() {
        return out;
    }
    w.run(rule, |st| {
        for t in trusts {
            out.extend(w.p1_trusting(rule, st, t, "P1-trust"));
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
    for (name, rule) in deliveries() {
        assert_eq!(gap_fails(&w, &rule, &[Set::new(), Set::from([r])]), vec![], "{name}");
    }
}

/// A content commit in the split form across units: K writes D along [A] and R along [O] in one
/// commit; X removes K from A. D's reader judges its part invalid, R's its part valid, each as the
/// node holding everything, under every rule that carries the removal to D (X syncs A and D).
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
    for (name, rule) in deliveries() {
        assert_eq!(gap_fails(&w, &rule, &[]), vec![], "{name}");
    }
    let wg = w;
    let rule = Rule::fixed();
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
/// node holding everything both judge Z's part on A unlisted (invalid), under every rule.
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
    for (name, rule) in deliveries() {
        let f = gap_fails(&w, &rule, &[]);
        assert!(f.iter().all(|f| f.prop.starts_with("P1") || f.prop == "P8-promote") && !f.iter().any(|f| f.prop == "P1" && f.id == ids[1]), "{name}: {f:?}");
    }
    let wl = w;
    let rule = Rule::fixed();
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
    for (name, rule) in deliveries() {
        assert_eq!(gap_fails(&w, &rule, &[]), vec![], "{name}");
    }
    let wg = w;
    let rule = Rule::fixed();
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

/// Per delivery rule, the worlds failing each property (P1-trust: two random trust sets) or with
/// the gap over `OSIS_GAPS_N` (60) wide worlds per option set and the family slice, by hand.
#[test]
#[ignore = "by hand"]
fn gaps_explore() {
    let n = crate::util::env("OSIS_GAPS_N", 60u64);
    let opts = WIDE_OPTS;
    let mut jobs: Vec<(String, Job)> = vec![];
    for opt in opts {
        for j in wide_jobs(0, n, opt) {
            jobs.push((format!("{opt:?}"), j));
        }
    }
    for i in (0..FAMILY).step_by(97) {
        jobs.push(("family".into(), Box::new(move || (format!("{:?}", Shape::nth(i)), family(Shape::nth(i)), None))));
    }
    let runs = crate::util::par_map(&jobs, |(g, j)| {
        let (name, w, _) = j();
        let trusts = trust_sets(&w, name_seed(&name));
        let per: Vec<(&'static str, Vec<Fail>)> = deliveries()
            .into_iter()
            .map(|(d, r)| {
                let (mut f, gp) = (gap_fails(&w, &r, &trusts), gaps_under(&w, &r));
                f.extend(gp);
                (d, f)
            })
            .collect();
        (g, name, per)
    });
    let mut out = BTreeMap::<(String, &str), BTreeMap<&str, (usize, String)>>::new();
    for (g, name, per) in runs {
        for (d, f) in per {
            crate::util::count_props(out.entry((g.clone(), d)).or_default(), &name, &f);
        }
    }
    for ((g, s), props) in out {
        eprintln!("{g} {s}");
        for (p, (k, first)) in props {
            eprintln!("  {p}: {k} worlds, first {first}");
        }
    }
}

/// The sampled property: the spec's rule holds every property and P1 for two random trust sets
/// against its reference over `wide` worlds under every option set (`per` seeds each from
/// `OSIS_HELD_START`), the worlds with the gap counted.
fn search(per: u64) {
    let start = crate::util::env("OSIS_HELD_START", 0u64);
    eprintln!("gaps: wide seeds from {start}");
    let mut jobs: Vec<Job> = vec![];
    for opt in WIDE_OPTS {
        jobs.extend(wide_jobs(start, per, opt));
    }
    let runs = crate::util::par_map(&jobs, |j| {
        let (name, w, _) = j();
        let first = gap_fails(&w, &Rule::fixed(), &trust_sets(&w, name_seed(&name))).first().map(|f| format!("{name}: {f:?}"));
        (first, !gaps_under(&w, &Rule::fixed()).is_empty())
    });
    // the gap, counted (issues/removed-key-writes-show-far.md)
    eprintln!("{} worlds; {} with the gap", jobs.len(), runs.iter().filter(|r| r.1).count());
    let bad: Vec<String> = runs.into_iter().filter_map(|r| r.0).collect();
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
/// mint), its commits, events and every delivery rule's failures.
#[test]
#[ignore = "by hand"]
fn gaps_show() {
    let seed = crate::util::env("OSIS_GAPS_SEED", 0u64);
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
    for (name, rule) in deliveries() {
        for f in fails_under(&w, &rule, None) {
            eprintln!("{name}: {f:?}");
        }
    }
}

/// Finding 20 (`wide` seed 14204407699, split and late, shrunk): K writes O through [A], where A
/// holds only read on O, after X removed K from A; nobody honest syncs A and O. The write is
/// invalid everywhere (no write reaches O through A), with or without the removal: O's evidence
/// closure over everything holds the removal (an edge write on (K, A)), which nothing delivers to
/// O and which moves no verdict there. Once W raises A to write on O (backdated, after the
/// removal), the removal decides K's write and no node holding it holds O: the gap under every
/// rule (finding 17's class).
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
    let (w, r, c) = base(false);
    let rule = Rule::fixed();
    let st = w.run(&rule, |_| {});
    let all = w.full(&st, &Set::new()).v.held;
    assert!(w.closure(&rule, &w.owed_bodies(&st, O), &all).contains(&r));
    assert!(!w.req(&rule, O, &st.units, &st.entries[&O]).contains(&r));
    assert_eq!(w.verdicts(&w.full(&st, &Set::new()), &Set::from([c]))[&c], Verdict::Invalid);
    for (name, rule) in deliveries() {
        assert_eq!(gap_fails(&w, &rule, &[]), vec![], "{name}");
        assert_eq!(gaps_under(&w, &rule), vec![], "{name}");
    }
    let (w, _, c) = base(true);
    for (name, rule) in deliveries() {
        assert_eq!(gap_fails(&w, &rule, &[]), vec![], "{name}");
        assert!(gaps_under(&w, &rule).iter().any(|f| f.sid == O && f.id == c && f.reader == Some(Verdict::Valid)), "{name}");
    }
}

/// The thief reads as never written what it withholds: the stolen K writes D through [A]; Q, an
/// admin of A by X's grant, gives Z read there (a fresh grant below write, which the thief never
/// logs); X makes K and Z admins in one commit, whose part on (Z, A) names the entry Q's grant
/// created. The thief logs its write, X's grants to K and their commit, and not X's grant to Q:
/// only Q's withheld grant brings it, so D's reader would hold it requiring nothing of it (P4).
#[test]
fn gaps_the_thief_logs_nothing_only_a_grant_it_withholds_brings() {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, q, k) = (w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[A]), w.node(false, &[A, D]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Admin, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[A], D));
    w.write(q, |p| p.edge(Q, 3, &[], A, Z, Role::Read, &[]));
    w.write_parts(x, |p| p.commit(X, 4, &[], A, vec![paths::Kind::set(K, Role::Admin), paths::Kind::set(Z, Role::Admin)]));
    for (name, rule) in deliveries() {
        assert_eq!(gap_fails(&w, &rule, &[]), vec![], "{name}");
    }
}

/// A removal riding another write (`wide` seed 14204407714, split, shrunk): X removes K and Q from A in one commit; Q
/// (its node honest, syncing A and D) then writes D through [A], A holding only read on D; the
/// stolen K writes R through [A]. Y syncs D and R; nobody honest syncs A and R. The removal reaches
/// R by riding Q's write: D's evidence takes every edge write on (Q, A), the removal's commit
/// among them, and with it every write on the edges that commit sets, so Y holds it and R's reader
/// requires it: no gap.
#[test]
fn gaps_a_removal_rides_a_write_through_a_read_hop() {
    let pw = paths::World::new(&[(X, A), (Y, D), (Y, R)]);
    let mut w = World::new(pw, &[A, D, R]);
    let (x, y, q, k) = (w.node(true, &[A]), w.node(true, &[D, R]), w.node(true, &[A, D]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Admin, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Read, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], R, A, Role::Write, &[]));
    w.write_parts(x, |p| p.commit(X, 3, &[], A, vec![paths::Kind::set(K, Role::None), paths::Kind::set(Q, Role::None)]));
    w.write(q, |p| p.content(Q, 4, &[A], D));
    w.write(k, |p| p.content(K, 5, &[A], R));
    for (name, rule) in deliveries() {
        assert_eq!(gap_fails(&w, &rule, &[]), vec![], "{name}");
        assert_eq!(gaps_under(&w, &rule), vec![], "{name}");
    }
}

/// Finding 23 (`wide` seed 14204407685, shrunk): the stolen K writes R through [A, O], A holding
/// only read on O (W's grant), O write on R; X, W and Y each sync their own thing alone and the
/// thief logs no grant giving below write. The node holding everything judges the write invalid
/// (no write reaches R through a read hop); R's reader holds no edge write on (A, O) and pends:
/// W's read grant is evidence of the write, but no node holding it syncs R. Lazy delivery leaves it
/// behind as it does a removal: every rule holds against its reference and the gap is at R,
/// pending where the node holding everything refuses (neither shows the write).
#[test]
fn gaps_a_write_through_a_read_hop_pends_at_a_reader_no_source_brings_the_read_grant() {
    let pw = paths::World::new(&[(X, A), (W, O), (Y, R)]);
    let mut w = World::new(pw, &[A, O, R]);
    let (x, wn, y, k) = (w.node(true, &[A]), w.node(true, &[O]), w.node(true, &[R]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(wn, |p| p.edge(W, 1, &[], O, A, Role::Read, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], R, O, Role::Write, &[]));
    let c = w.write(k, |p| p.content(K, 5, &[A, O], R));
    for (name, rule) in deliveries() {
        assert_eq!(fails_under(&w, &rule, None), vec![], "{name}");
        let g = gaps_under(&w, &rule);
        assert!(g.iter().any(|f| f.sid == R && f.id == c && f.reader == Some(Verdict::Pending) && f.full == Some(Verdict::Invalid)), "{name}: {g:?}");
    }
}

/// The generator reaches finding 23's shape at default size (`wide`'s read-hop move): among the
/// first `wide` worlds (no options) some have the gap pending where the node holding everything
/// judges invalid.
#[test]
fn gaps_wide_worlds_reach_the_read_hop() {
    let hit = (0..16).filter(|&seed| gaps_under(&wide(seed, 16, Wide::default()), &Rule::fixed()).iter().any(|f| f.reader == Some(Verdict::Pending) && f.full == Some(Verdict::Invalid))).count();
    assert!(hit > 0, "the generator no longer reaches finding 23's read hop in 16 worlds: raise its rate");
}
