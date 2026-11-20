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
    let st = w.run(rule, |st| out.extend(w.p1(rule, st)));
    assert!(!st.unsettled, "logging settles");
    out.extend(w.p3(rule, &st));
    out.extend(w.p4(rule, &st, true));
    out.extend(w.p5_order(rule, &st, 5).0);
    out.extend(w.p7_leaf_waits(rule, &st));
    out.extend(w.p8_acts(rule, &st, ActWhen::AfterPass, 0));
    out
}

/// K writes c0 and c1 on D along [A]; X, having received c0 alone, removes K listing it. X syncs
/// A, Y syncs D, K's node is honest. Returns the world and (c0, c1).
fn listed_one_of_two() -> (World, Id, Id) {
    let pw = roles_model::paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, k) = (w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[A]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    let c0 = w.write(k, |p| p.content(K, 2, &[A], D));
    let c1 = w.write(k, |p| p.content(K, 3, &[A], D));
    w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[c0]));
    (w, c0, c1)
}

/// Finding 6: a leaf kept only with the commits it names (the growth study's literal rule)
/// leaves with c0 once c0 is forgotten (covered), and c1, which it does not name but whose
/// verdict reads it (on its thing, resting on the lowered edge),
/// then waits for good at D's reader where it was invalid. Kept with every commit it reads, it
/// stays.
#[test]
fn f6_a_leaf_kept_with_the_commits_it_names_strands_one_it_does_not_name() {
    let (w, _, c1) = listed_one_of_two();
    let named = Rule { lists: Lists::Travels(LeafKeep::Named), ..Rule::fixed() };
    let f = fails(&w, &named);
    assert!(f.iter().any(|f| f.prop == "P4-forget" && f.sid == D && f.id == c1 && f.reader == Some(Verdict::Pending) && f.full == Some(Verdict::Invalid)), "{f:?}");
    assert_eq!(fails(&w, &Rule::listed()), vec![]);
    assert_eq!(fails(&w, &Rule::fixed()), vec![]);
}

/// P7: a commit held without the leaf that reads it waits: D's reader holding c0, c1 and the
/// removal but not its leaf for D judges both pending, never invalid; with the leaf, c0 valid
/// and c1 invalid. Forgetting c0 and c1 takes the leaf out of D's sync ID; the removal's role
/// entries stay with it.
#[test]
fn p7_a_commit_held_without_its_leaf_waits_and_the_leaf_leaves_with_what_it_reads() {
    let (w, c0, c1) = listed_one_of_two();
    let rule = Rule::listed();
    let mut st = w.run(&rule, |_| {});
    let seen = w.reader(&rule, &st, D, &Set::new());
    let both = Set::from([c0, c1]);
    let v = w.verdicts(&seen, &both);
    assert_eq!((v[&c0], v[&c1]), (Verdict::Valid, Verdict::Invalid));
    assert_eq!(st.leaves[&D].len(), 1);
    let mut short = seen.clone();
    short.lists = Some(Default::default());
    let v = w.verdicts(&short, &both);
    assert_eq!((v[&c0], v[&c1]), (Verdict::Pending, Verdict::Pending));
    assert_eq!(w.p7_leaf_waits(&rule, &st), vec![]);
    w.forget(&rule, &mut st, c0);
    assert_eq!(st.leaves[&D].len(), 1, "c1 still reads it");
    w.forget(&rule, &mut st, c1);
    assert!(st.leaves[&D].is_empty(), "{:?}", st.leaves);
    assert_eq!(w.p4(&rule, &st, false), vec![]);
}

/// Finding 27: X removes Z from A at 3 though Z never held write there (the removal takes no
/// write away), listing Z's earlier write c0 in D's leaf; X then grants Z write and Z writes c1 on
/// D through [A]. D's reader holds the removal (an edge write on c1's path) and, under `Judged`,
/// waits for its D leaf, which only X holds: X syncs A alone and no errand carries a removal that
/// takes no write away. Under `Cuts` a leaf is read only where its lowering takes away what the
/// commit needs, so nothing waits on a lowering that cuts nothing.
#[test]
fn f27_a_leaf_of_a_lowering_that_cuts_nothing_is_waited_on_by_nobody() {
    let pw = roles_model::paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, z) = (w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    let c0 = w.write(z, |p| p.content(Z, 2, &[A], D));
    w.write(x, |p| p.edge(X, 3, &[], A, Z, Role::None, &[c0]));
    w.write(x, |p| p.edge(X, 4, &[], A, Z, Role::Write, &[]));
    let c1 = w.write(z, |p| p.content(Z, 5, &[A], D));
    let judged = Rule { lists: Lists::Travels(LeafKeep::Judged), ..Rule::fixed() };
    let f = fails(&w, &judged);
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == D && f.id == c1 && f.reader == Some(Verdict::Pending) && f.full == Some(Verdict::Valid)), "{f:?}");
    assert_eq!(fails(&w, &Rule::listed()), vec![]);
    // the leaf exists and is read by nothing: D's reader holds the removal, not the leaf
    let st = w.run(&Rule::listed(), |_| {});
    assert!(st.leaves[&D].is_empty() && w.reader(&Rule::listed(), &st, D, &Set::new()).v.held.contains(&2));
}

/// P8 and finding 5: D's reader holding the thief's write and K's grant but not X's earlier
/// removal finds nothing pending; acting then (a promotion of a deposit, a cover dropping what it
/// covers) contradicts the verdict of the node holding everything. Acting only on D's whole
/// entries (after a complete pass) never does.
#[test]
fn p8_acting_before_a_complete_pass_is_reversed_by_what_it_lacked() {
    let mut sh = Shape::nth(0);
    sh.thief = true;
    let w = family(sh);
    let st = w.run(&Rule::fixed(), |_| {});
    assert_eq!(w.p8_acts(&Rule::fixed(), &st, ActWhen::AfterPass, 5), vec![]);
    let f = w.p8_acts(&Rule::fixed(), &st, ActWhen::WhenNothingPends, 5);
    assert!(f.iter().any(|f| f.sid == D && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{f:?}");
}

/// P8: an act taken after a complete pass is reversed by a write made later (the node holding
/// everything reverses with it; one made earlier and delivered late does too, finding 33): X
/// re-grants K after removing it, so D's reader drops K's first write as invalid, then judges it
/// valid again; the drop must be undoable (the body fetched again, spec/sync-judgement.md §3
/// Dropped bodies), never final.
#[test]
fn p8_an_act_after_a_complete_pass_is_reversed_by_a_later_write() {
    let mut sh = Shape::nth(0);
    sh.regrant = true;
    let w = family(sh);
    let rule = Rule::fixed();
    let mut taken: Vec<(usize, Act)> = vec![];
    let st = w.run(&rule, |st| {
        let seen = w.reader(&rule, st, D, &Set::new());
        for a in w.acts(&seen, &w.bodies(D, &st.units, &seen.v.held)) {
            taken.push((st.step, a));
        }
        assert_eq!(w.p8_acts(&rule, st, ActWhen::AfterPass, 0), vec![]);
    });
    let fin = w.verdicts(&w.full(&st, &Set::new()), &st.written);
    let reversed: Vec<(usize, Act)> = taken.iter().copied().filter(|&(_, a)| matches!(a, Act::Drop(i) if fin[&i] == Verdict::Valid)).collect();
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
    for rule in [Rule::fixed(), Rule::listed()] {
        assert_eq!(fails(&w, &rule), vec![]);
        let st = w.run(&rule, |_| {});
        let on_b: Vec<Id> = st.entries[&T1].iter().copied().filter(|&i| w.on(i) == B || w.on(i) == T2 || i == gt2).collect();
        assert!(on_b.is_empty(), "{on_b:?}");
    }
}

/// Finding 6, in any order: X removes K at 6 listing c, which K stamped at 7 (its clock ahead)
/// and X received first. The leaf is evidence of c though c is stamped after the lowering, so
/// D's sync ID carries it and D's reader judges c valid (listed), as the node holding everything.
/// A leaf kept only for the commits stamped before its lowering never reaches D: c invalid there.
#[test]
fn f6_a_leaf_is_evidence_of_a_commit_stamped_after_its_lowering() {
    let pw = roles_model::paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, k) = (w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[A]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    let c = w.write(k, |p| p.content(K, 7, &[A], D));
    w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[c]));
    let rule = Rule::listed();
    let st = w.run(&rule, |_| {});
    assert_eq!(w.verdicts(&w.full(&st, &Set::new()), &st.written)[&c], Verdict::Valid);
    assert_eq!(st.leaves[&D].len(), 1);
    assert_eq!(w.verdicts(&w.reader(&rule, &st, D, &Set::new()), &Set::from([c]))[&c], Verdict::Valid);
    assert_eq!(fails(&w, &rule), vec![]);
}

/// An addendum is evidence of the commits it lists that rest on its removal's edge and leaves
/// with the last of them (`addendum_live`): Q's addendum on D lists c1; forgetting c1 takes it
/// out of D's sync ID while c0, which it does not list, stays. Kept for good, it would outlive
/// everything it can keep.
#[test]
fn an_addendum_leaves_with_the_last_commit_it_lists() {
    let pw = roles_model::paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, k, q) = (w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[A]), w.node(true, &[A]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    let c0 = w.write(k, |p| p.content(K, 2, &[A], D));
    let c1 = w.write(k, |p| p.content(K, 3, &[A], D));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    let ad = w.write(q, |p| p.addendum(Q, 7, &[A], D, r, &[c1]));
    let rule = Rule::listed();
    let mut st = w.run(&rule, |_| {});
    assert!(st.entries[&D].contains(&ad));
    w.forget(&rule, &mut st, c1);
    assert!(st.entries[&D].contains(&c0));
    assert!(!st.entries[&D].contains(&ad), "{:?}", st.entries[&D]);
    assert_eq!(fails(&w, &rule), vec![]);
}

/// Finding 10: a vouch on N keyed by R counts parts on N alone, so D's evidence holds a vouch
/// against a removal it holds only where it holds something on N. Y's vouch on F keyed by X's
/// removal of K from A is in F's sync ID, not D's, though Y syncs both and D's evidence holds the
/// removal; D's reader judges as the node holding everything.
#[test]
fn f10_a_vouch_on_a_thing_the_evidence_holds_nothing_on_stays_out() {
    const F: roles_model::paths::Thing = 15;
    let pw = roles_model::paths::World::new(&[(X, A), (Y, D), (Y, F)]);
    let mut w = World::new(pw, &[A, D, F]);
    let (x, y, k, z) = (w.node(true, &[A]), w.node(true, &[D, F]), w.node(true, &[A]), w.node(true, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Admin, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(k, |p| p.edge(K, 2, &[], A, Z, Role::Write, &[]));
    w.write(z, |p| p.content(Z, 3, &[A], D));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    let vf = w.write(y, |p| p.vouch(Y, 7, &[], F, r, &[]));
    let rule = Rule::fixed();
    let st = w.run(&rule, |_| {});
    assert!(st.entries[&D].contains(&r));
    assert!(st.entries[&F].contains(&vf));
    assert!(!st.entries[&D].contains(&vf), "{:?}", st.entries[&D]);
    assert_eq!(fails(&w, &rule), vec![]);
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

/// Finding 12: X removes K (5) and grants it again (6); K writes c on D at 7. D's reader holding
/// the removal but not yet the re-grant judges c invalid, the node holding everything valid: a
/// drop then (the control, acting on any arrival) discards a body the node holding everything
/// shows; acting after a complete pass never does.
#[test]
fn f12_a_drop_on_partial_evidence_discards_a_valid_body() {
    let pw = roles_model::paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, k) = (w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[A]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 5, &[], A, K, Role::None, &[]));
    w.write(x, |p| p.edge(X, 6, &[], A, K, Role::Write, &[]));
    let c = w.write(k, |p| p.content(K, 7, &[A], D));
    let rule = Rule::fixed();
    let st = w.run(&rule, |_| {});
    assert_eq!(w.p8_acts(&rule, &st, ActWhen::AfterPass, 5), vec![]);
    let f = w.p8_acts(&rule, &st, ActWhen::WhenNothingPends, 5);
    assert!(f.iter().any(|f| f.id == c && f.reader == Some(Verdict::Invalid) && f.full == Some(Verdict::Valid)), "{f:?}");
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
    family(Shape { via_org: true, units: 0, listed: false, thief: false, regrant: false, addendum: false, raised: false, q_d: false, q_r: false, y_a: false, org_apart: true, vouch: false, mint: 0 })
}

/// Finding 1: the remover's errand by direct taken grants (A's grant on O) never reaches D, two
/// grants below the removed edge: D's reader judges K's write valid, the node holding everything
/// invalid. Followed to the end of the taken grants (O's grant on D, under O's sync ID) it does.
#[test]
fn f1_a_direct_errand_misses_a_unit_two_grants_below_the_removed_edge() {
    let w = org_apart();
    let f = fails(&w, &Rule::design());
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == D && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{f:?}");
    assert!(f.iter().any(|f| f.prop == "P3" && f.sid == D));
    assert_eq!(fails(&w, &Rule::fixed()), vec![]);
}

/// Finding 2, Risk 2: copies placed when their commit is logged and never placed again. O (on
/// K's path) leaves R's unit after K's write: A's grant on O was R's body, so no copy was placed,
/// and it leaves R with O: R's reader pends on K's write for good.
#[test]
fn f2_copies_placed_at_logging_leave_a_sync_id_short_when_a_unit_changes() {
    let mut sh = Shape::nth(0);
    (sh.via_org, sh.units, sh.listed) = (true, 4, true);
    let w = family(sh);
    let atlog = Rule { placement: Placement::AtLog, ..Rule::design() };
    let f = fails(&w, &atlog);
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == R && f.reader == Some(Verdict::Pending) && f.full == Some(Verdict::Valid)), "{f:?}");
    assert_eq!(fails(&w, &Rule::design()), vec![]);
    // D in R's unit from the start: a removal is no body of either, so placed with nothing it
    // reaches R only by the errand, which goes to D's own sync ID
    let mut sh = Shape::nth(0);
    sh.units = 1;
    let f = fails(&family(sh), &atlog);
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == R && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{f:?}");
    assert_eq!(fails(&family(sh), &Rule::design()), vec![]);
}

/// Finding 3, Risk 4: A only reads D when K is removed, so the errand finds no unit where K could
/// write; Y raises A to write later and the stolen K writes D. An errand run once, at the
/// removal, never logs it under D; the standing duty logs it once the raise shows D.
#[test]
fn f3_an_errand_run_once_misses_a_holder_raised_after_the_removal() {
    let mut sh = Shape::nth(0);
    (sh.raised, sh.thief) = (true, true);
    let w = family(sh);
    let f = fails(&w, &Rule { standing: false, ..Rule::design() });
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == D && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{f:?}");
    assert_eq!(fails(&w, &Rule::design()), vec![]);
}

/// Finding 4: K (admin of A) grants Z on A; Z writes D; X removes K, its frontier listing the
/// grant in A's leaf. D's reader seeing only its unit's leaves reads the grant unlisted and drops
/// it (roles-model finding 5, reached here through units): the copy of a lowering carries its leaf
/// for the thing it is on.
#[test]
fn f4_a_reader_needs_the_leaf_of_each_evidence_copy() {
    let pw = roles_model::paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, k, z) = (w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[A]), w.node(true, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Admin, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    let gz = w.write(k, |p| p.edge(K, 2, &[], A, Z, Role::Write, &[]));
    let zc = w.write(z, |p| p.content(Z, 3, &[A], D));
    w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[gz]));
    let f = fails(&w, &Rule { leaves: Leaves::Unit, ..Rule::fixed() });
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
    sh.thief = true;
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

/// Risk 3: a stolen node's first write on E, a dependent of R reached only through R (A holds
/// write on R; K writes E along [A, R], its last hop R's record edge). X syncs A alone, Y syncs R
/// alone. The errand logs X's removal under R (A's taken grant); without it R's reader judges the
/// write valid.
#[test]
fn risk3_a_first_write_through_an_enclosing_root() {
    let pw = roles_model::paths::World::new(&[(X, A), (Y, R), (R, E)]);
    let mut w = World::new(pw, &[A, R]);
    w.member(E, R);
    let (x, y, k) = (w.node(true, &[A]), w.node(true, &[R]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], R, A, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    let late = w.write(k, |p| p.content(K, 8, &[A, R], E));
    assert_eq!(fails(&w, &Rule::design()), vec![]);
    let f = fails(&w, &Rule { errand: Errand::Off, ..Rule::design() });
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == R && f.id == late && f.reader == Some(Verdict::Valid)), "{f:?}");
}

/// P2: D under its own sync ID and R's, joining R between K's write and the removal: both
/// readers judge every write alike, by their own evidence (the removal reaches R through Y, who
/// syncs D and R).
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

/// P4: forgetting K's writes takes out of D's sync ID everything only they needed: what stays is
/// X's removal of K, whose reach (A writes D) keeps it for good, and under `Removals::TakesWrite`
/// its witness, K's grant (with every removal: `Removals::Any`, the grant leaves).
#[test]
fn p4_evidence_leaves_with_the_last_commit_that_needed_it() {
    let mut sh = Shape::nth(0);
    sh.listed = true;
    let w = family(sh);
    let (gk, r) = (0, 4);
    assert_eq!(w.removes(r), Some((K, A)));
    for (removals, left) in [(Removals::TakesWrite, Set::from([gk, r])), (Removals::Any, Set::from([r]))] {
        let rule = Rule { removals, ..Rule::fixed() };
        let mut st = w.run(&rule, |_| {});
        assert!(w.copies(&st, D).contains(&gk));
        let kw: Vec<Id> = st.entries[&D].iter().copied().filter(|&i| w.w.commits[i].signer == K).collect();
        for i in kw {
            w.forget(&rule, &mut st, i);
        }
        assert_eq!(w.copies(&st, D), left, "{removals:?}");
        assert_eq!(w.p4(&rule, &st, true), vec![]);
    }
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

/// P1 to P5 over a slice of the family under the fixed rule; the design fails only where
/// finding 1 says: D two errand steps from A (through O, granted or minted, or down a mint chain
/// two deep) with no honest node syncing O (W apart, or O minted by A: nobody writes O).
#[test]
fn p1_to_p5_hold_on_a_slice_of_the_family() {
    for i in (0..FAMILY).step_by(97 * 3) {
        let sh = Shape::nth(i);
        let w = family(sh);
        assert_eq!(fails(&w, &Rule::fixed()), vec![], "{sh:?}");
        assert_eq!(fails(&w, &Rule::listed()), vec![], "{sh:?}");
        let d = fails(&w, &Rule::design());
        assert!(d.is_empty() || ((sh.via_org || sh.mint == 2) && (sh.org_apart || sh.mint > 0)), "{sh:?} {d:?}");
    }
}

/// The random worlds' seeds: `n` from `OSIS_HELD_START` (default 0).
fn seeds(n: u64) -> std::ops::Range<u64> {
    let start = std::env::var("OSIS_HELD_START").ok().filter(|v| !v.is_empty()).map_or(0, |v| v.parse::<u64>().expect("OSIS_HELD_START is a decimal u64"));
    eprintln!("evidence: random seeds {start}..{}", start + n);
    start..start + n
}

/// P1 to P8 under the fixed rule and under `listed` (leaves travelling as evidence) over every
/// `family_step`th family world and `random` random worlds of 14 moves, a thread per core.
fn search(family_step: usize, random_worlds: u64) {
    let mut jobs: Vec<Box<dyn Fn() -> (String, Vec<Fail>) + Sync>> = vec![];
    // `listed` (A3's) on half the worlds `fixed` (A2's) runs on
    for (name, rule, part) in [("fixed", Rule::fixed(), 1), ("listed", Rule::listed(), 2)] {
        for i in (0..FAMILY).step_by(family_step * part) {
            jobs.push(Box::new(move || (format!("{name} {:?}", Shape::nth(i)), fails(&family(Shape::nth(i)), &rule))));
        }
        for seed in seeds(random_worlds / part as u64) {
            jobs.push(Box::new(move || (format!("{name} random seed {seed}"), fails(&random(seed, 14), &rule))));
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
                    bad.lock().unwrap().push(format!("{name}: {:?} {:?}", props(&f), f[0]));
                }
            });
        }
    });
    let bad = bad.into_inner().unwrap();
    assert!(bad.is_empty(), "{} worlds fail, first: {}", bad.len(), bad[0]);
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
    let d = Rule::design();
    vec![
        ("design", d),
        ("atlog", Rule { placement: Placement::AtLog, ..d }),
        ("no-errand", Rule { errand: Errand::Off, ..d }),
        ("transitive", Rule { errand: Errand::Transitive, ..d }),
        ("edge", Rule { scope: Scope::Edge, ..d }),
        ("transitive+edge", Rule { errand: Errand::Transitive, scope: Scope::Edge, ..d }),
        ("unit-leaves", Rule { leaves: Leaves::Unit, ..d }),
        ("once", Rule { standing: false, ..d }),
        ("listed", Rule::listed()),
        ("listed-judged", Rule { lists: Lists::Travels(LeafKeep::Judged), ..Rule::fixed() }),
        ("listed-named", Rule { lists: Lists::Travels(LeafKeep::Named), ..Rule::fixed() }),
    ]
}

/// Every check at every step of `w` under `rule`: failures by property.
fn tally(w: &World, rule: &Rule, out: &mut BTreeMap<&'static str, usize>, first: &mut BTreeMap<&'static str, String>) {
    let mut note = |f: &Fail, out: &mut BTreeMap<&'static str, usize>| {
        *out.entry(f.prop).or_default() += 1;
        first.entry(f.prop).or_insert_with(|| format!("{f:?}"));
    };
    let st = w.run(rule, |st| {
        for f in w.p1(rule, st) {
            note(&f, out);
        }
    });
    if st.unsettled {
        *out.entry("unsettled").or_default() += 1;
    }
    for f in w.p3(rule, &st).iter().chain(&w.p4(rule, &st, true)).chain(&w.p7_leaf_waits(rule, &st)) {
        note(f, out);
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
        let st = w.run(&Rule::design(), |_| {});
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
    let name = std::env::var("OSIS_EV_RULE").unwrap_or_else(|_| "design".into());
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
    for f in w.p3(rule, &st).iter().chain(&w.p4(rule, &st, true)) {
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
