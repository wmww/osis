//! Evidence completeness (held_model::evidence; notes/evidence-model-findings.md): hand worlds
//! for each finding and named risk, a slice of the family as a default test, and the sampled
//! searches (`_plain`, `_large`). `explore` prints every rule variant's failures (by hand).
use held_model::evidence::names::*;
use held_model::evidence::*;
use roles_model::paths::{Id, Set};
use roles_model::Role;
use std::collections::BTreeMap;

/// Every check at every step, and the arrival-order check at the end: the failures.
fn fails(w: &World, rule: &Rule) -> Vec<Fail> {
    let mut out = vec![];
    let st = w.run(rule, |st| {
        out.extend(w.p1(rule, st));
        out.extend(w.p11_keysets(rule, st));
    });
    assert!(!st.unsettled, "logging settles");
    out.extend(w.p4(rule, &st, true));
    out.extend(w.p5_order(rule, &st, 5).0);
    out.extend(w.p8_promotions(rule, &st, PromoteWhen::AfterPass, 0));
    out
}

/// P8 and finding 5: D's reader holding the thief's write and K's grant but not X's earlier
/// removal finds nothing pending; promoting then (a deposit, a cover dropping what it covers)
/// contradicts the verdict of the node holding everything. Promoting only on D's whole entries
/// (after a complete pass) never does.
#[test]
fn p8_promoting_before_a_complete_pass_is_reversed_by_what_it_lacked() {
    let mut sh = Shape::nth(0);
    (sh.thief, sh.q_d) = (true, true);
    let w = family(sh);
    let st = w.run(&Rule::fixed(), |_| {});
    assert_eq!(w.p8_promotions(&Rule::fixed(), &st, PromoteWhen::AfterPass, 5), vec![]);
    let f = w.p8_promotions(&Rule::fixed(), &st, PromoteWhen::WhenNothingPends, 5);
    assert!(f.iter().any(|f| f.sid == D && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{f:?}");
}

/// P8: a promotion taken after a complete pass is reversed by a write made later (the node
/// holding everything reverses with it; one made earlier and delivered late does too, finding
/// 33): D's reader promotes K's first write, which X's removal, written after, cuts; the
/// promotion is undone by the rules (the body leaves the store), never final.
#[test]
fn p8_a_promotion_after_a_complete_pass_is_reversed_by_a_later_write() {
    let mut sh = Shape::nth(0);
    sh.q_d = true;
    let w = family(sh);
    let rule = Rule::fixed();
    let mut taken: Vec<(usize, Id)> = vec![];
    let st = w.run(&rule, |st| {
        let seen = w.reader(&rule, st, D, &Set::new());
        for i in w.promotions(&seen, &w.bodies(D, &st.units, &seen.v.held)) {
            taken.push((st.step, i));
        }
        assert_eq!(w.p8_promotions(&rule, st, PromoteWhen::AfterPass, 0), vec![]);
    });
    let fin = w.verdicts(&w.full(&st, &Set::new()), &st.written);
    let reversed: Vec<(usize, Id)> = taken.iter().copied().filter(|&(_, i)| fin[&i] == Verdict::Invalid).collect();
    assert!(!reversed.is_empty(), "{taken:?}");
    for (step, _) in reversed {
        // every later step that reversed it is a write
        assert!(w.events[step..].iter().any(|e| matches!(e, Ev::Write(_))));
    }
}

/// The split path form (notes/path-form.md): K writes T1 along [A] and T2 along [B] in one
/// commit; Y removes K from B. T1's sync ID requires nothing of T2's path (its readers cannot
/// open T2's entry, and need not): T1's part is valid there and T2's invalid at T2's reader,
/// each judged as the node holding everything.
#[test]
fn split_a_part_on_another_thing_adds_no_evidence_requirement() {
    const T1: roles_model::paths::Thing = 30;
    const T2: roles_model::paths::Thing = 31;
    const B: roles_model::paths::Thing = 32;
    let pw = roles_model::paths::World::new(&[(X, A), (X, T1), (Y, B), (Y, T2)]);
    let mut w = World::new(pw, &[A, B, T1, T2]);
    let (x, y, k) = (w.node(true, &[A, T1]), w.node(true, &[B, T2]), w.node(true, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 1, &[], T1, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], B, K, Role::Write, &[]));
    let gt2 = w.write(y, |p| p.edge(Y, 1, &[], T2, B, Role::Write, &[]));
    // the split commit: two parts, one commit (`World::split`)
    let parts = w.write_parts(k, |p| p.split(K, 2, K, &[(&[A], T1), (&[B], T2)]));
    w.write(y, |p| p.edge(Y, 6, &[], B, K, Role::None, &[]));
    let st = w.run(&Rule::fixed(), |_| {});
    let full = w.verdicts(&w.full(&st, &Set::new()), &st.written);
    assert_eq!((full[&parts[0]], full[&parts[1]]), (Verdict::Valid, Verdict::Invalid));
    let rule = Rule::fixed();
    assert_eq!(fails(&w, &rule), vec![]);
    let st = w.run(&rule, |_| {});
    let on_b: Vec<Id> = st.entries[&T1].iter().copied().filter(|&i| w.on(i) == B || w.on(i) == T2 || i == gt2).collect();
    assert!(on_b.is_empty(), "{on_b:?}");
}

/// Finding 11, pinned as the draft has it: a writer of A without admin writes `n` grants of
/// admin on Q's edge, none of which applies; Q writes D through [A], so every one is in D's
/// evidence (an edge write on an edge of the stated path, whatever its validity) and Q's node
/// copies each under D. D's copies grow with what a non-admin of A writes, unbounded.
#[test]
fn f11_a_non_admin_of_a_path_thing_grows_the_evidence_with_writes_that_never_apply() {
    let copies = |n: u32| {
        let pw = roles_model::paths::World::new(&[(X, A), (Y, D)]);
        let mut w = World::new(pw, &[A, D]);
        let (x, y, k, q) = (w.node(true, &[A]), w.node(true, &[D]), w.node(false, &[A]), w.node(true, &[A]));
        w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
        w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Write, &[]));
        w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
        let junk: Vec<Id> = (0..n).map(|i| w.write(k, |p| p.edge(K, 2 + i, &[], A, Q, Role::Admin, &[]))).collect();
        w.write(q, |p| p.content(Q, 2 + n, &[A], D));
        let st = w.run(&Rule::fixed(), |_| {});
        let full = w.verdicts(&w.full(&st, &Set::new()), &st.written);
        assert!(junk.iter().all(|j| full[j] == Verdict::Invalid));
        assert!(junk.iter().all(|j| st.entries[&D].contains(j)));
        w.copies(&st, D).len()
    };
    assert_eq!(copies(30) - copies(3), 27);
}

fn props(f: &[Fail]) -> Vec<&'static str> {
    let mut p: Vec<&str> = f.iter().map(|f| f.prop).collect();
    p.sort();
    p.dedup();
    p
}

/// K writes D through [A, O]; O is W's, and W syncs O alone; X (syncing A) removes K, listing
/// nothing. No honest node syncs both O and D.
fn org_apart() -> World {
    family(Shape { via_org: true, units: 0, listed: false, thief: false, regrant: false, addendum: false, raised: false, q_d: false, q_r: false, y_a: false, org_apart: true, grant: false, mint: 0 })
}

/// The gap of `w` under `rule`: every body a reference judges otherwise than the node holding
/// everything, at every step.
fn gaps(w: &World, rule: &Rule) -> Vec<Fail> {
    let mut out = vec![];
    w.run(rule, |st| out.extend(w.gap(st)));
    out
}

/// The gap (notes/write-path-design.md §2, The gap; issues/removed-key-writes-show-far.md):
/// worlds where no node holding X's removal of K syncs the sync ID K's write is under, so lazy
/// delivery never brings it there and its reader shows the write the node holding everything
/// drops; each holds every property against its reference and is counted as the gap. Finding 1's
/// and 17's (K writes D through [A, O], nobody honest syncs O with D or A), finding 3's (A raised
/// on D after the removal, the stolen K writing D), risk 3's (K writes E, a dependent of R, through
/// [A, R], X syncing A alone, Y R alone). A node holding the removal that syncs D (Q) closes it.
#[test]
fn gap_a_removal_no_node_holding_it_brings_leaves_the_write_showing() {
    let mut raised = Shape::nth(0);
    (raised.raised, raised.thief) = (true, true);
    let pw = roles_model::paths::World::new(&[(X, A), (Y, R), (R, E)]);
    let mut risk3 = World::new(pw, &[A, R]);
    risk3.member(E, R);
    let (x, y, k) = (risk3.node(true, &[A]), risk3.node(true, &[R]), risk3.node(false, &[]));
    risk3.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    risk3.write(y, |p| p.edge(Y, 1, &[], R, A, Role::Write, &[]));
    risk3.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    risk3.write(k, |p| p.content(K, 8, &[A, R], E));
    for (name, w, s) in [("f1", org_apart(), D), ("f3", family(raised), D), ("risk3", risk3, R)] {
        assert_eq!(fails(&w, &Rule::fixed()), vec![], "{name}");
        let g = gaps(&w, &Rule::fixed());
        assert!(g.iter().any(|f| f.sid == s && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{name}: {g:?}");
    }
    let mut closed = raised;
    closed.q_d = true;
    assert_eq!((fails(&family(closed), &Rule::fixed()), gaps(&family(closed), &Rule::fixed())), (vec![], vec![]));
}

/// The control of the reference: judged against the node holding everything (no removal
/// excused), D's reader in finding 1's world fails P1; against its reference it holds.
#[test]
fn gap_judged_against_everything_the_reader_fails() {
    let w = org_apart();
    let st = w.run(&Rule::fixed(), |_| {});
    let full = w.verdicts(&w.full(&st, &Set::new()), &st.written);
    let rd = w.verdicts(&w.reader(&Rule::fixed(), &st, D, &Set::new()), &w.owed_bodies(&st, D));
    assert!(rd.iter().any(|(i, v)| *v != full[i]), "{rd:?} {full:?}");
    assert_eq!(w.p1(&Rule::fixed(), &st), vec![]);
}

/// Finding 2, Risk 2: copies placed when their commit is logged and never placed again. O (on
/// K's path) leaves R's unit after K's write: A's grant on O was R's body, so no copy was placed,
/// and it leaves R with O: R's reader pends on K's write for good.
#[test]
fn f2_copies_placed_at_logging_leave_a_sync_id_short_when_a_unit_changes() {
    let mut sh = Shape::nth(0);
    (sh.via_org, sh.units, sh.listed) = (true, 4, true);
    let w = family(sh);
    let atlog = Rule { placement: Placement::AtLog, ..Rule::fixed() };
    let f = fails(&w, &atlog);
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == R && f.reader == Some(Verdict::Pending) && f.full == Some(Verdict::Valid)), "{f:?}");
    assert_eq!(fails(&w, &Rule::fixed()), vec![]);
}

/// Keysets carry whole demotions (notes/write-path-design.md §2, D2; notes/a3-spec/README.md Open
/// 8): X removes K from A; Y, D's admin, syncing A and D, rotates D, its keyset carrying the
/// removal (A writes D); the stolen K then writes D through [A]. From the rotation on, D holds the
/// removal as evidence of the keyset, before any body needs it, and D's reader judges the keyset
/// held and K's write invalid. The control (`Rule::keysets` off) fails P11 and P1 at the rotation:
/// D's reader holds a keyset without the demotion it carries, pending where the node holding it
/// all judges it valid.
#[test]
fn keysets_a_rotation_carries_the_demotions_its_writer_holds() {
    let pw = roles_model::paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, k) = (w.node(true, &[A]), w.node(true, &[A, D]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    let ks = w.rotate(y, &[r], |p| p.content(Y, 7, &[], D));
    let late = w.write(k, |p| p.content(K, 8, &[A], D));
    let rule = Rule::fixed();
    assert_eq!(fails(&w, &rule), vec![]);
    let mut at = vec![];
    w.run(&rule, |st| at.push(st.entries[&D].contains(&r)));
    assert_eq!(at, [false, false, false, true, true]);
    let st = w.run(&rule, |_| {});
    let v = w.verdicts(&w.reader(&rule, &st, D, &Set::new()), &Set::from([ks, late]));
    assert_eq!((v[&ks], v[&late]), (Verdict::Valid, Verdict::Invalid));
    let f = fails(&w, &Rule { keysets: false, ..rule });
    assert!(f.iter().any(|f| f.prop == "P11" && f.sid == D && f.id == r), "{f:?}");
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == D && f.id == ks && f.reader == Some(Verdict::Pending) && f.full == Some(Verdict::Valid)), "{f:?}");
}

/// Finding 4, the list whole (notes/write-path-design.md §2, E4): K (admin of A) grants Z on A; Z
/// writes D; X removes K, its list naming the grant. A copy of the removal under D carries its
/// whole list, so D's reader reads the grant listed; reading only its unit's entries (the control
/// `Lists::Unit`) it reads the grant unlisted and drops it (roles-model finding 5, through units).
#[test]
fn f4_a_reader_needs_the_leaf_of_each_evidence_copy() {
    let pw = roles_model::paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, k, z) = (w.node(true, &[A, D]), w.node(true, &[D]), w.node(true, &[A]), w.node(true, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Admin, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    let gz = w.write(k, |p| p.edge(K, 2, &[], A, Z, Role::Write, &[]));
    let zc = w.write(z, |p| p.content(Z, 3, &[A], D));
    w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[gz]));
    let f = fails(&w, &Rule { lists: Lists::Unit, ..Rule::fixed() });
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == D && f.id == zc && f.reader == Some(Verdict::Invalid)), "{f:?}");
    assert_eq!(fails(&w, &Rule::fixed()), vec![]);
}

/// Finding 5: a reader holding part of a path's evidence judges where it should wait. D's reader
/// holds K's write and K's grant on A but not X's earlier removal (stamped before the write): no
/// edge lacks a setter, so the write is not pending, and it reads valid until the removal comes.
/// No rule over the held set alone tells it apart: only a complete pass of D's sync ID does.
#[test]
fn f5_partial_evidence_judges_before_a_complete_pass() {
    let mut sh = Shape::nth(0);
    (sh.thief, sh.q_d) = (true, true);
    let w = family(sh);
    let st = w.run(&Rule::fixed(), |_| {});
    // the thief's write (stamped after the removal) without the removal
    let thief = *st.entries[&D].iter().max().unwrap();
    let r = st.written.iter().copied().find(|&i| w.removes(i).is_some()).unwrap();
    let v = w.reader(&Rule::fixed(), &st, D, &Set::from([r]));
    assert_eq!(w.verdicts(&v, &Set::from([thief]))[&thief], Verdict::Valid);
    assert_eq!(w.verdicts(&w.reader(&Rule::fixed(), &st, D, &Set::new()), &Set::from([thief]))[&thief], Verdict::Invalid);
    // with no edge write on K's edge at all, it pends
    let g = 0;
    let v = w.reader(&Rule::fixed(), &st, D, &Set::from([g, r]));
    assert_eq!(w.verdicts(&v, &Set::from([thief]))[&thief], Verdict::Pending);
    // and judged from the same partial evidence the node holding everything else agrees (locality)
    assert_eq!(w.p5_order(&Rule::fixed(), &st, 5).0, vec![]);
}

/// P2: D under its own sync ID and R's, joining R between K's write and the removal: both
/// readers judge every write alike, by their own evidence (the removal reaches neither: the gap,
/// alike under both).
#[test]
fn p2_a_write_under_two_sync_ids_is_judged_alike_by_each() {
    for units in [1, 2, 3] {
        let mut sh = Shape::nth(0);
        (sh.units, sh.thief) = (units, true);
        let w = family(sh);
        let st = w.run(&Rule::fixed(), |_| {});
        assert_eq!(fails(&w, &Rule::fixed()), vec![]);
        if units != 3 {
            let both: Vec<Id> = w.owed_bodies(&st, D).intersection(&w.owed_bodies(&st, R)).copied().collect();
            assert!(both.len() >= 2, "{both:?}");
        }
    }
}

/// P4: forgetting K's writes takes out of D's sync ID everything only they needed, X's removal
/// of K and K's grant included: a removal's copy leaves with the last body it judges
/// (notes/write-path-design.md §2, D1). Q, syncing A and D, logged the removal there.
#[test]
fn p4_evidence_leaves_with_the_last_commit_that_needed_it() {
    let mut sh = Shape::nth(0);
    (sh.listed, sh.q_d) = (true, true);
    let w = family(sh);
    let (gk, r) = (0, 4);
    assert_eq!(w.removes(r), Some((K, A)));
    let rule = Rule::fixed();
    let mut st = w.run(&rule, |_| {});
    assert!(w.copies(&st, D).is_superset(&Set::from([gk, r])));
    let kw: Vec<Id> = st.entries[&D].iter().copied().filter(|&i| w.w.commits[i].signer == K).collect();
    for i in kw {
        w.forget(&rule, &mut st, i);
    }
    assert_eq!(w.copies(&st, D), Set::new());
    assert_eq!(w.p4(&rule, &st, true), vec![]);
}

/// P6: copies under D after n writes along a path of k holder things, m of them outside D's
/// unit: one per edge write on an outside thing, shared by every write (none per commit).
#[test]
fn p6_copies_are_shared_by_the_writes_along_a_path() {
    for (k, m) in [(1, 1), (2, 1), (2, 2), (3, 2), (3, 3)] {
        let (c1, b1) = cost(3, k, m);
        let (c10, b10) = cost(30, k, m);
        assert_eq!((c1, c10), (m, m), "k {k} m {m}");
        assert_eq!(b10 - b1, 27);
    }
}

/// P1 to P8 over a slice of the family under the fixed rule, the gap counted: it is never
/// empty there (the family's removal reaches D only where Q or Y holds A and D).
#[test]
fn p1_to_p8_hold_on_a_slice_of_the_family() {
    let mut gap = 0;
    for i in (0..FAMILY).step_by(97 * 3) {
        let sh = Shape::nth(i);
        let w = family(sh);
        assert_eq!(fails(&w, &Rule::fixed()), vec![], "{sh:?}");
        gap += usize::from(!gaps(&w, &Rule::fixed()).is_empty());
    }
    assert!(gap > 0);
}

/// The random worlds' seeds: `n` from `OSIS_HELD_START` (default 0).
fn seeds(n: u64) -> std::ops::Range<u64> {
    let start = std::env::var("OSIS_HELD_START").ok().filter(|v| !v.is_empty()).map_or(0, |v| v.parse::<u64>().expect("OSIS_HELD_START is a decimal u64"));
    eprintln!("evidence: random seeds {start}..{}", start + n);
    start..start + n
}

/// P1 to P8 under the fixed rule over every `family_step`th family world and `random` random
/// worlds of 14 moves, a thread per core.
fn search(family_step: usize, random_worlds: u64) {
    let mut jobs: Vec<Box<dyn Fn() -> (String, Vec<Fail>, usize, usize) + Sync>> = vec![];
    let rule = Rule::fixed();
    // the failures, whether the world has the gap, its keysets carrying a demotion
    let run = move |w: World| (fails(&w, &rule), usize::from(!gaps(&w, &rule).is_empty()), w.keysets.values().filter(|c| !c.is_empty()).count());
    for i in (0..FAMILY).step_by(family_step) {
        jobs.push(Box::new(move || {
            let (f, g, k) = run(family(Shape::nth(i)));
            (format!("{:?}", Shape::nth(i)), f, g, k)
        }));
    }
    for seed in seeds(random_worlds) {
        jobs.push(Box::new(move || {
            let (f, g, k) = run(random(seed, 14));
            (format!("random seed {seed}"), f, g, k)
        }));
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let bad = std::sync::Mutex::new(vec![]);
    let gap = std::sync::atomic::AtomicUsize::new(0);
    let carrying = std::sync::atomic::AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let Some(j) = jobs.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) else { return };
                let (name, f, g, k) = j();
                gap.fetch_add(g, std::sync::atomic::Ordering::Relaxed);
                carrying.fetch_add(k, std::sync::atomic::Ordering::Relaxed);
                if !f.is_empty() {
                    bad.lock().unwrap().push(format!("{name}: {:?} {:?}", props(&f), f[0]));
                }
            });
        }
    });
    let bad = bad.into_inner().unwrap();
    // the gap, counted (issues/removed-key-writes-show-far.md)
    let carrying = carrying.into_inner();
    eprintln!("{} worlds; {} with the gap; {carrying} keysets carrying a demotion", jobs.len(), gap.into_inner());
    assert!(bad.is_empty(), "{} worlds fail, first: {}", bad.len(), bad[0]);
    assert!(carrying > 0, "no keyset carries a demotion: raise the rotation rate in `random`");
}

#[test]
#[ignore = "property"]
fn one_sync_id_reader_judges_as_everything_plain() {
    search(17, 40);
}

#[test]
#[ignore = "property"]
fn one_sync_id_reader_judges_as_everything_large() {
    search(5, 400);
}

fn variants() -> Vec<(&'static str, Rule)> {
    let d = Rule::fixed();
    vec![("fixed", d), ("atlog", Rule { placement: Placement::AtLog, ..d }), ("unit-lists", Rule { lists: Lists::Unit, ..d })]
}

/// Every check at every step of `w` under `rule`: failures by property.
fn tally(w: &World, rule: &Rule, out: &mut BTreeMap<&'static str, usize>, first: &mut BTreeMap<&'static str, String>) {
    let mut note = |f: &Fail, out: &mut BTreeMap<&'static str, usize>| {
        *out.entry(f.prop).or_default() += 1;
        first.entry(f.prop).or_insert_with(|| format!("{f:?}"));
    };
    let st = w.run(rule, |st| {
        for f in w.p1(rule, st).iter().chain(&w.gap(st)) {
            note(f, out);
        }
    });
    if st.unsettled {
        *out.entry("unsettled").or_default() += 1;
    }
    for f in w.p4(rule, &st, true) {
        note(&f, out);
    }
}

#[test]
#[ignore = "by hand"]
fn explore() {
    let lines: Vec<String> = std::thread::scope(|sc| {
        let hs: Vec<_> = variants()
            .into_iter()
            .map(|(name, rule)| {
                sc.spawn(move || {
                    let mut out = BTreeMap::<&str, usize>::new();
                    let mut first = BTreeMap::new();
                    let mut worlds = BTreeMap::<&str, usize>::new();
                    for i in 0..FAMILY {
                        let w = family(Shape::nth(i));
                        let mut o = BTreeMap::<&str, usize>::new();
                        let mut f1 = BTreeMap::new();
                        tally(&w, &rule, &mut o, &mut f1);
                        for (k, v) in o {
                            *out.entry(k).or_default() += v;
                            *worlds.entry(k).or_default() += 1;
                        }
                        for (k, v) in f1 {
                            first.entry(k).or_insert(format!("{:?} {v}", Shape::nth(i)));
                        }
                    }
                    let mut s = format!("{name}: {out:?} worlds {worlds:?}\n");
                    for (k, v) in first {
                        s += &format!("  {k}: {v}\n");
                    }
                    s
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for l in lines {
        eprint!("{l}");
    }
}

#[test]
#[ignore = "by hand"]
fn explore_random() {
    let lines: Vec<String> = std::thread::scope(|sc| {
        let hs: Vec<_> = variants()
            .into_iter()
            .map(|(name, rule)| {
                sc.spawn(move || {
                    let mut out = BTreeMap::<&str, usize>::new();
                    let mut first = BTreeMap::new();
                    let mut prov = 0;
                    for seed in 0..300u64 {
                        let w = random(seed, 12);
                        let mut f1 = BTreeMap::new();
                        tally(&w, &rule, &mut out, &mut f1);
                        let st = w.run(&rule, |_| {});
                        let (o, p) = w.p5_order(&rule, &st, 5);
                        prov += p;
                        for f in o {
                            *out.entry(f.prop).or_default() += 1;
                            f1.entry(f.prop).or_insert(format!("{f:?}"));
                        }
                        for (k, v) in f1 {
                            first.entry(k).or_insert(format!("seed {seed} {v}"));
                        }
                    }
                    let mut s = format!("{name}: {out:?} provisional {prov}\n");
                    for (k, v) in first {
                        s += &format!("  {k}: {v}\n");
                    }
                    s
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for l in lines {
        eprint!("{l}");
    }
}

#[test]
#[ignore = "by hand"]
fn random_shape() {
    let (mut v, mut n) = (BTreeMap::<Verdict, usize>::new(), 0);
    for seed in 0..100 {
        let w = random(seed, 14);
        let st = w.run(&Rule::fixed(), |_| {});
        for (_, x) in w.verdicts(&w.full(&st, &Default::default()), &st.written) {
            *v.entry(x).or_default() += 1;
        }
        n += st.entries.values().map(|e| e.len()).sum::<usize>();
    }
    eprintln!("{v:?} entries {n}");
}

/// Prints random world `OSIS_HELD_START`'s events and the first failures (by hand).
#[test]
#[ignore = "by hand"]
fn show_random() {
    let seed: u64 = std::env::var("OSIS_HELD_START").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let w = random(seed, 12);
    let name = std::env::var("OSIS_EV_RULE").unwrap_or_else(|_| "fixed".into());
    let rule = variants().into_iter().find(|v| v.0 == name).expect("OSIS_EV_RULE names a variant").1;
    show(&w, &rule);
}

pub fn show(w: &World, rule: &Rule) {
    eprintln!("units {:?}", w.units);
    for (n, node) in w.nodes.iter().enumerate() {
        eprintln!("node {n} {node:?}");
    }
    for e in &w.events {
        match e {
            Ev::Write(i) => eprintln!("  {i}: by {} {:?}", w.by[*i], w.w.commits[*i]),
            e => eprintln!("  {e:?}"),
        }
    }
    let st = w.run(rule, |st| {
        for f in w.p1(rule, st) {
            eprintln!("{f:?}");
        }
    });
    eprintln!("entries {:?}", st.entries);
    eprintln!("final units {:?}", st.units);
    for f in w.p4(rule, &st, true).iter().chain(&w.gap(&st)) {
        eprintln!("{f:?}");
    }
    let fv = w.verdicts(&w.full(&st, &Default::default()), &st.written);
    eprintln!("full {fv:?}");
    for (n, h) in st.held.iter().enumerate() {
        for &s in &w.syncs(n, &st.units) {
            eprintln!("node {n} sid {s} req {:?}", w.req(rule, s, &st.units, h));
        }
    }
    for &s in &w.sids {
        eprintln!("reader {s} req {:?}", w.req(rule, s, &st.units, &st.entries[&s]));
    }
}

