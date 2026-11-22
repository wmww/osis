//! Hand worlds: one counterpart per rule-naming hand test of roles-model `paths` (src/paths/tests.rs,
//! same names), each read by the walk and the model at the views the model's test reads, so every
//! rule has a small named world besides the random runs. Each world is built as the model's test
//! builds it; `agree` compares the whole reading (statuses, histories, final roles and invites,
//! void trusted writes, disputes). Content commits are left out: the walk judges edge-class parts.
//! spec/permissions.md §1, §2, §5.1.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::{agree, agree_all};
use roles_model::paths::*;
use roles_model::Role::{self, Admin, None as Gone, Read, Write};
use std::collections::BTreeMap;

/// A with H (mint), X and B paired by H at 1.
fn paired() -> (World, Id, Id) {
    let mut w = account();
    let gx = w.edge(H, 1, &[], A, X, Admin, &[]);
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    (w, gx, gb)
}

// ---- Descent, self-removal by path end, `until` ----

// spec/permissions.md §1: a write by descent rests on the record edges; a lowering of a record
// edge audits what goes through it.
#[test]
fn a_write_by_descent_is_judged_along_the_record_edges() {
    let (mut w, ..) = paired();
    w.edge(H, 3, &[A, T1], D1, A2, Write, &[]);
    let low = w.edge(H, 5, &[A], D1, T1, Gone, &[]);
    agree_all(&w, &[]);
    agree_all(&w, &[low]);
}

// notes/a1-spec/README.md Open 21: H takes admin on T1 (its direct edge, by [A]) and removes A's
// record edge on T1 by the descent []: later content and grants by H stated along the descent or
// through [A] rest on the removed record edge and apply nowhere; marking the hop H to T1 direct
// (H's own grant), they apply, as in the model.
#[test]
fn a_detached_things_owner_writes_it_only_by_a_marked_direct_hop() {
    let mut w = account();
    let g = w.edge(H, 1, &[A], T1, H, Admin, &[]);
    let cut = w.edge(H, 2, &[], T1, A, Gone, &[g]);
    w.edge(H, 4, &[], T1, B, Write, &[]);
    w.edge(H, 4, &[A], T1, N5, Write, &[]);
    w.content(H, 3, &[], T1);
    w.content(H, 3, &[A], T1);
    w.push_marked(H, 3, &[], T1, Kind::Content, &[0]);
    w.push_marked(H, 5, &[], T1, Kind::set(Z, Write), &[0]);
    agree_all(&w, &[]);
    agree_all(&w, &[cut]);
}

// The one-encoding rule (draft §1 Path, Direct mark): a mark on a hop not otherwise read as a
// descent of two steps or more applies nowhere (B's direct grant; A's record edge; a hop past the
// members); H's marked hop applies where it holds a direct edge, nowhere before.
#[test]
#[ignore = "D2: walk rebuilt after D (notes/redesign-plan.md)"]
fn a_mark_off_a_descent_of_two_steps_applies_nowhere() {
    let mut w = account();
    w.push(H, 1, &[A], T1, Kind::set(B, Admin));
    w.content(B, 2, &[], T1);
    w.push_marked(B, 2, &[], T1, Kind::Content, &[0]);
    w.push_marked(B, 2, &[], T1, Kind::set(N5, Write), &[0]);
    w.content(A, 2, &[], T1);
    w.push_marked(A, 2, &[], T1, Kind::Content, &[0]);
    w.push_marked(B, 2, &[], T1, Kind::Content, &[1]);
    w.push_marked(H, 2, &[], T1, Kind::Content, &[0]);
    w.push_marked(H, 2, &[], T1, Kind::set(Z, Write), &[0]);
    w.content(H, 2, &[], T1);
    w.push(H, 3, &[A], T1, Kind::set(H, Write));
    w.push_marked(H, 4, &[], T1, Kind::Content, &[0]);
    agree_all(&w, &[]);
}

// A final hop marked direct is the path's last edge (draft §1 Path's last edge): the path's
// invite reads the direct edge, as the model.
#[test]
fn a_marked_final_hop_is_the_last_edge() {
    let mut w = account();
    let gh = w.push(H, 1, &[A], T1, Kind::set(H, Admin));
    let gb = w.push(H, 1, &[A], T1, Kind::set(B, Admin));
    w.push(H, 2, &[], T1, Kind::set(A, Gone).listing(w.cut(&[gh, gb])));
    w.push_marked(H, 3, &[], T1, Kind::set(B, Gone), &[0]);
    agree_all(&w, &[]);
    let mut w = account();
    let gh = w.push(H, 1, &[A], T1, Kind::set(H, Read).may_grant());
    let gb = w.push(H, 1, &[A], T1, Kind::set(B, Admin));
    w.push(B, 2, &[], T1, Kind::set(A, Gone).listing(w.cut(&[gh, gb])));
    w.push_marked(H, 3, &[], T1, Kind::set(Z, Read), &[0]);
    w.push_marked(H, 3, &[], T1, Kind::set(N5, Write), &[0]);
    agree_all(&w, &[]);
}

// Two routes, two claims (draft §1 Path, Direct mark): a remover takes both, as the model.
#[test]
fn a_party_with_both_routes_is_cut_off_by_removing_both() {
    for listed in [true, false] {
        let mut w = account();
        let gh = w.push(H, 1, &[A], T1, Kind::set(H, Admin));
        let gb = w.push(H, 1, &[A], T1, Kind::set(B, Admin));
        let detach = w.push(B, 3, &[], T1, Kind::set(A, Gone).listing(w.cut(&[gh, gb])));
        w.content(H, 4, &[], T1);
        let marked = w.push_marked(H, 4, &[], T1, Kind::Content, &[0]);
        let list = if listed { vec![marked] } else { vec![] };
        let r = w.push(B, 5, &[], T1, Kind::set(H, Gone).listing(w.cut(&list)));
        w.push_marked(H, 6, &[], T1, Kind::Content, &[0]);
        agree_all(&w, &[]);
        agree_all(&w, &[r]);
        agree_all(&w, &[detach]);
    }
}

// The thief with the far ancestor's key (draft §1 Path, Direct mark): backdated marked writes
// fall with the removal of H's direct grant, trusted or not.
#[test]
fn a_removed_far_ancestors_backdated_marked_writes_fall() {
    let mut w = account();
    let gh = w.push(H, 1, &[A], T1, Kind::set(H, Admin));
    let gb = w.push(H, 1, &[A], T1, Kind::set(B, Admin));
    w.push(H, 2, &[], T1, Kind::set(A, Gone).listing(w.cut(&[gh, gb])));
    let r = w.push(B, 5, &[], T1, Kind::set(H, Gone));
    w.push_marked(H, 4, &[], T1, Kind::Content, &[0]);
    w.push_marked(H, 4, &[], T1, Kind::set(Z, Admin), &[0]);
    w.push(H, 4, &[], T1, Kind::set(N5, Admin));
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
}

// notes/path-model-findings.md 43: a self-removal rewriting its holder's own admin unchanged keeps
// no admin past a lowering's drops: B's removal of H, dropping H's grant of B, is void.
#[test]
fn a_self_rewrite_keeps_no_admin_its_grant_lost() {
    for rewrite in [false, true] {
        let mut w = account();
        w.push(H, 1, &[], A, Kind::set(B, Admin));
        if rewrite {
            w.push(B, 2, &[], A, Kind::set(B, Admin));
        }
        let r = w.push(B, 3, &[], A, Kind::set(H, Gone));
        agree_all(&w, &[]);
        agree_all(&w, &[r]);
        let (_, p) = super::walk(&w, &View::all(&w));
        assert_eq!(p.status(&super::input(&w, &View::all(&w)).ids[&r]), Some(osis_perm::paths::Status::Void), "{rewrite}");
    }
}

// roles-model `a_marked_hop_under_a_removal_with_a_list`: a grant along a marked direct hop of a
// detached thing, under a removal listing other writes, and the grant or not.
#[test]
fn a_marked_hop_under_a_removal_with_a_list() {
    for (marked, listed) in [(true, true), (true, false), (false, true)] {
        let mut w = account();
        let gs: Vec<Id> = [H, B, N5].iter().map(|&h| w.push(H, 1, &[A], T1, Kind::set(h, Admin))).collect();
        w.push(H, 2, &[], T1, Kind::set(A, Gone).listing(w.cut(&gs)));
        let gx = w.push_marked(H, 3, &[], T1, Kind::set(X, Write), if marked { &[0] } else { &[] });
        let hc = w.push_marked(H, 4, &[], T1, Kind::Content, &[0]);
        w.content(X, 5, &[], T1);
        let list = if listed { vec![hc, gx] } else { vec![hc] };
        let r = w.push(B, 6, &[], T1, Kind::set(H, Gone).listing(w.cut(&list)));
        agree_all(&w, &[]);
        agree_all(&w, &[r]);
    }
}

// spec/permissions.md §2: a self-removal (a path ending at the holder) audits nothing and raises
// nothing.
#[test]
fn a_self_removal_by_path_end_audits_nothing() {
    let (mut w, ..) = paired();
    w.edge(B, 2, &[], A, N5, Admin, &[]);
    w.edge(B, 3, &[], A, B, Gone, &[]);
    agree_all(&w, &[]);
    let (mut w, ..) = paired();
    w.edge(B, 2, &[], A, N5, Admin, &[]);
    let r = w.edge(H, 3, &[], A, B, Gone, &[]);
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
    let mut w = account();
    w.edge(H, 1, &[A], T1, A2, Write, &[]);
    w.edge(K, 3, &[A2], T1, A2, Gone, &[]);
    agree_all(&w, &[]);
    let mut w = account();
    w.edge(H, 1, &[A], T1, A2, Write, &[]);
    w.edge(K, 2, &[A2], T1, A2, Admin, &[]);
    agree_all(&w, &[]);
}

// spec/permissions.md §5.1: a lowering of h puts a self-removal of h in question like a write
// through h (control `-leave`).
#[test]
fn a_backdated_leave_undoes_nothing_the_removed_node_made() {
    let (mut w, _, gb) = paired();
    let down = w.edge(X, 3, &[], A, B, Write, &[gb]);
    let g5 = w.edge(X, 3, &[], A, N5, Admin, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[down, g5]);
    w.edge(X, 2, &[], A, X, Gone, &[]);
    agree_all(&w, &[r]);
    agree_all(&w, &[]);
}

#[test]
fn a_backdated_leave_shields_nothing_from_the_removal() {
    let (mut w, ..) = paired();
    w.edge(X, 4, &[], A, Z, Admin, &[]);
    w.edge(X, 5, &[], A, X, Gone, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    agree_all(&w, &[r]);
    agree_all(&w, &[]);
}

#[test]
fn a_timed_self_removal_is_put_in_question_like_a_leave() {
    for (role, until) in [(Admin, 2), (Write, 20)] {
        let (mut w, _, gb) = paired();
        let down = w.edge(X, 3, &[], A, B, Write, &[gb]);
        let g5 = w.edge(X, 3, &[], A, N5, Admin, &[]);
        let r = w.edge(H, 6, &[], A, X, Gone, &[down, g5]);
        let timed = w.edge(X, 1, &[], A, X, role, &[]);
        w.set_until(timed, until);
        agree_all(&w, &[r]);
        agree_all(&w, &[]);
    }
}

#[test]
fn a_holder_things_leave_is_put_in_question_by_a_removal_of_its_edge() {
    let mut w = account();
    w.edge(H, 1, &[], A, X, Admin, &[]);
    w.edge(H, 1, &[], A, B, Admin, &[]);
    let g2 = w.edge(H, 1, &[A], T1, A2, Admin, &[]);
    w.edge(X, 2, &[A], T1, A, Gone, &[]);
    let gn = w.edge(B, 3, &[A], T1, N6, Write, &[]);
    let rk = w.edge(K, 6, &[A2], T1, A, Gone, &[g2, gn]);
    agree_all(&w, &[]);
    agree_all(&w, &[rk]);
}

// spec/permissions.md §5.1: an `until` passing audits nothing; the next explicit write does.
#[test]
fn an_until_passing_audits_nothing_the_next_explicit_write_does() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    w.set_until(gb, 5);
    w.edge(B, 3, &[], A, N5, Admin, &[]);
    agree_all(&w, &[]);
    let r = w.edge(H, 7, &[], A, B, Gone, &[]);
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
}

// spec/permissions.md §5.1: the edge as restored reads each value's role with its `until`
// disregarded, a value already ended at its own `ts` included: H gives B admin ending at 2 at 3
// (a lowering), B grants N5 at 4 (holding nothing), H removes B at 5 listing nothing: restored at
// admin, the removal falls and drops B's grant. (No model hand test: the walk's own world.)
#[test]
fn an_ended_value_restores_its_role() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    let ended = w.edge(H, 3, &[], A, B, Admin, &[gb]);
    w.set_until(ended, 2);
    w.edge(B, 4, &[], A, N5, Admin, &[]);
    let r = w.edge(H, 5, &[], A, B, Gone, &[]);
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
}

// spec/permissions.md §5.1 step 4: `keeps` passes over a finalize whose own `keeps` fails, as over
// a grant. H grants N5 and B admin; N5 grants N6; N6 gives B admin until 4, finalizes it at 5
// and grants B admin again at 6; B grants Z; Z removes N5 listing nothing. Its drop of N5's grant
// takes N6's writes' authority without dropping them: reading B's edge back for Z's path, N6's
// re-grant, finalize and timed grant are all passed over and H's grant decides: the removal
// applies. Stopping at the finalize would make it void. (No model hand test: the walk's own.)
#[test]
fn keeps_passes_over_a_fallen_finalize() {
    let mut w = account();
    w.edge(H, 1, &[], A, N5, Admin, &[]);
    w.edge(H, 1, &[], A, B, Admin, &[]);
    w.edge(N5, 2, &[], A, N6, Admin, &[]);
    let g = w.edge(N6, 3, &[], A, B, Admin, &[]);
    w.set_until(g, 4);
    w.push(N6, 5, &[], A, Kind::finalize(B));
    w.edge(N6, 6, &[], A, B, Admin, &[]);
    w.edge(B, 7, &[], A, Z, Admin, &[]);
    let l = w.edge(Z, 8, &[], A, N5, Gone, &[]);
    agree_all(&w, &[]);
    agree_all(&w, &[l]);
    let rd = judge(&w, &super::rules(), &View::all(&w));
    assert!(rd.applied.contains(&l), "{rd:?}");
}

// ---- Mutual removal ----

// Two admins removing each other, at every held subset and trust.
#[test]
fn two_nodes_removing_each_other_never_leave_no_admin() {
    let mut w = account();
    let gx = w.edge(H, 1, &[], A, X, Admin, &[]);
    let rh = w.edge(H, 6, &[], A, X, Gone, &[]);
    let rx = w.edge(X, 6, &[], A, H, Gone, &[gx]);
    let pick = |bits: u32, ids: &[Id]| -> Set { ids.iter().enumerate().filter(|(k, _)| bits >> k & 1 == 1).map(|(_, i)| *i).collect() };
    for h in 0..8u32 {
        for t in 0..4u32 {
            agree(&w, &View { held: pick(h, &[gx, rh, rx]), leaves: None, trust: pick(t, &[rh, rx]) });
        }
    }
}

// ---- Each lowering judged once: void, applied, drops that only grow ----

// spec/permissions.md §5.1 step 3: a removal whose drops take its own standing is void (control
// `-no-void`).
#[test]
fn a_removal_whose_drops_take_its_own_standing_is_void() {
    let (mut w, ..) = paired();
    let rx = w.edge(X, 5, &[], A, H, Gone, &[]);
    agree_all(&w, &[]);
    agree_all(&w, &[rx]);
}

#[test]
fn two_lowerings_unapplying_each_other_settle_on_the_earlier() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    w.edge(B, 3, &[], A, H, Gone, &[gb]);
    w.edge(N5, 4, &[], A, H, Gone, &[g5]);
    agree_all(&w, &[]);
}

#[test]
fn a_lowering_dropped_later_keeps_its_drops() {
    let mut w = account();
    w.edge(H, 1, &[], A, B, Admin, &[]);
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    w.edge(H, 2, &[], A, N5, Gone, &[]);
    let lb = w.edge(B, 3, &[], A, H, Gone, &[0, g5]);
    w.edge(N5, 4, &[], A, B, Gone, &[]);
    agree_all(&w, &[]);
    agree_all(&w, &[lb]);
}

#[test]
fn a_void_write_has_no_effect() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    w.edge(H, 1, &[], A, N5, Admin, &[]);
    w.edge(B, 2, &[], A, Z, Admin, &[]);
    w.edge(Z, 3, &[], A, H, Gone, &[gb]);
    w.edge(Z, 4, &[], A, B, Gone, &[]);
    agree_all(&w, &[]);
}

#[test]
fn a_lowering_dropping_the_grant_it_rests_on_is_void() {
    let mut w = account();
    w.edge(H, 3, &[], A, B, Admin, &[]);
    let g6 = w.edge(H, 3, &[], A, N6, Admin, &[]);
    let again = w.edge(N6, 5, &[], A, B, Admin, &[g6]);
    w.edge(N6, 5, &[], A, H, Gone, &[g6, again]);
    w.edge(B, 6, &[], A, N6, Gone, &[]);
    agree_all(&w, &[]);
}

#[test]
fn an_earlier_void_write_has_no_effect() {
    let mut w = account();
    let g1 = w.edge(H, 2, &[], A, B, Admin, &[]);
    w.edge(H, 10, &[], A, B, Admin, &[]);
    w.edge(B, 9, &[], A, H, Gone, &[]);
    w.edge(B, 10, &[], A, H, Gone, &[g1]);
    agree_all(&w, &[]);
}

#[test]
fn small_world_830267_judged_once() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    let g5 = w.edge(H, 3, &[], A, N5, Admin, &[]);
    let g6 = w.edge(H, 3, &[], A, N6, Admin, &[]);
    let n6 = w.edge(N5, 3, &[], A, N6, Admin, &[gb, g5]);
    w.edge(B, 4, &[], A, N5, Gone, &[g6, gb]);
    w.edge(N6, 4, &[], A, H, Gone, &[g5, n6]);
    w.edge(N6, 8, &[], A, B, Gone, &[]);
    agree_all(&w, &[]);
}

#[test]
fn small_world_360379_judged_once() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    w.edge(H, 1, &[], A, N6, Admin, &[gb]);
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let r5 = w.edge(N5, 1, &[], A, H, Gone, &[gb, g5]);
    w.edge(B, 2, &[], A, N5, Gone, &[g5]);
    w.edge(H, 9, &[], A, B, Gone, &[gb, r5]);
    agree_all(&w, &[]);
}

#[test]
fn small_world_234147_judged_once() {
    let mut w = account();
    let g5 = w.edge(H, 3, &[], A, N5, Admin, &[]);
    let gz = w.edge(N5, 3, &[], A, Z, Admin, &[g5]);
    w.edge(Z, 3, &[], A, H, Gone, &[g5, gz]);
    w.edge(N5, 8, &[], A, N6, Admin, &[g5]);
    let r6 = w.edge(N6, 8, &[], A, Z, Gone, &[]);
    w.edge(H, 9, &[], A, N6, Gone, &[g5]);
    w.edge(N5, 10, &[], A, H, Gone, &[r6]);
    agree_all(&w, &[]);
    agree_all(&w, &[r6]);
}

#[test]
fn a_lowerings_check_does_not_read_what_its_drops_free() {
    let mut w = account();
    let g6 = w.edge(H, 1, &[], A, N6, Admin, &[]);
    let g5 = w.edge(N6, 2, &[], A, N5, Admin, &[]);
    let r1 = w.edge(H, 4, &[], A, N6, Gone, &[g5]);
    let r2 = w.edge(H, 4, &[], A, N6, Gone, &[r1]);
    let l = w.edge(N5, 4, &[], A, H, Gone, &[r2, g6]);
    for t in [&[][..], &[r1], &[l], &[r2]] {
        agree_all(&w, t);
    }
}

// spec/permissions.md §5.1 step 4: the void check reads its grant chain back.
#[test]
fn a_lowering_dropping_its_granters_grant_is_void() {
    let mut w = account();
    w.edge(H, 4, &[], A, Z, Admin, &[]);
    let g5 = w.edge(Z, 8, &[], A, N5, Admin, &[]);
    w.edge(N5, 10, &[], A, H, Gone, &[g5]);
    agree_all(&w, &[]);
}

#[test]
fn a_lowering_taking_nothing_is_judged_when_a_restart_gives_it_the_edge() {
    let (mut w, ..) = paired();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let out = w.edge(X, 3, &[], A, N5, Gone, &[g5]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[out]);
    w.edge(X, 2, &[], A, N5, Gone, &[g5]);
    w.edge(N5, 2, &[], A, Z, Admin, &[]);
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
}

#[test]
fn a_stray_drop_in_a_fight_of_admins_is_shown() {
    let mut w = account();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let g6 = w.edge(N5, 1, &[], A, N6, Admin, &[g5]);
    let gb = w.edge(N5, 7, &[], A, B, Admin, &[]);
    let gz = w.edge(B, 8, &[], A, Z, Admin, &[gb]);
    w.edge(N6, 8, &[], A, B, Gone, &[gb, gz, g6]);
    w.edge(Z, 9, &[], A, N6, Gone, &[g5, gz]);
    let rz = w.edge(H, 10, &[], A, Z, Gone, &[]);
    agree_all(&w, &[]);
    agree_all(&w, &[rz]);
}

#[test]
fn a_thiefs_lowering_after_the_removal_holds_nothing() {
    for by_z in [false, true] {
        let mut w = minted_by(M);
        let gh = w.edge(M, 1, &[], A, H, Admin, &[]);
        let gx = w.edge(M, 1, &[], A, X, Admin, &[]);
        let by = if by_z {
            w.edge(X, 4, &[], A, Z, Admin, &[gx]);
            Z
        } else {
            X
        };
        let r = w.edge(H, 6, &[], A, X, Gone, &[]);
        w.edge(by, 7, &[], A, M, Gone, &[gx]);
        w.edge(by, 7, &[], A, H, Gone, &[gx, gh]);
        agree_all(&w, &[]);
        agree_all(&w, &[r]);
    }
    let mut w = minted_by(M);
    w.edge(M, 1, &[], A, H, Admin, &[]);
    let gx = w.edge(M, 1, &[], A, X, Admin, &[]);
    w.edge(X, 4, &[], A, M, Gone, &[gx]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
}

#[test]
fn a_removal_whose_author_falls_later_keeps_its_verdict() {
    let (mut w, ..) = paired();
    w.edge(X, 2, &[], A, N5, Admin, &[]);
    w.edge(B, 3, &[A], T1, A2, Write, &[]);
    w.edge(N5, 4, &[], A, B, Gone, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
}

// ---- Nothing is exempt; the audit over the held writes ----

// spec/permissions.md §5.1: nothing is exempt from a lowering's drops (control `-exempt`).
#[test]
fn nothing_through_the_removed_edge_is_exempt() {
    let (mut w, ..) = paired();
    w.edge(X, 2, &[], A, Z, Admin, &[]);
    w.edge(Z, 3, &[], A, H, Admin, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    agree_all(&w, &[r]);
    agree_all(&w, &[]);
    let (mut w, ..) = paired();
    let tg = w.edge(X, 2, &[], A, H, Admin, &[]);
    w.set_until(tg, 7);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    agree_all(&w, &[r]);
    agree_all(&w, &[]);
}

// spec/permissions.md §5.1 step 3: the audit puts the held writes in question (control
// `-audit-applied`).
#[test]
fn the_audit_puts_the_held_writes_in_question() {
    let (mut w, gx, gb) = paired();
    w.edge(X, 5, &[], A, H, Gone, &[gx, gb]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.edge(X, 1, &[], A, X, Gone, &[]);
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
}

// ---- Lists, trust, seeds, disputes ----

#[test]
fn a_list_keeping_what_unmakes_its_removal_voids_it() {
    let (mut w, gx, gb) = paired();
    let rx = w.edge(X, 5, &[], A, H, Gone, &[gx, gb]);
    let listed = w.edge(H, 6, &[], A, X, Gone, &[rx]);
    agree_all(&w, &[listed]);
    agree_all(&w, &[]);
    let (mut w, gx, gb) = paired();
    w.edge(X, 5, &[], A, H, Gone, &[gx, gb]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    agree_all(&w, &[r]);
    agree_all(&w, &[]);
    for honest in [false, true] {
        let mut w = minted_by(M);
        let gh = w.edge(M, 0, &[], A, H, Admin, &[]);
        let gx = w.edge(M, 0, &[], A, X, Admin, &[]);
        let list = if honest { vec![gx, gh] } else { vec![gx] };
        let rm = w.edge(X, 3, &[], A, M, Gone, &list);
        let mut w2 = w.clone();
        let listed = w.edge(H, 6, &[], A, X, Gone, &[rm]);
        agree_all(&w, &[listed]);
        agree_all(&w, &[]);
        let left = w2.edge(H, 6, &[], A, X, Gone, &[]);
        agree_all(&w2, &[left]);
    }
}

#[test]
fn a_remover_keeps_what_it_received_first() {
    let (mut w, gx, gb) = paired();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let down = w.edge(X, 2, &[], A, H, Write, &[gx, gb, g5]);
    w.edge(N5, 3, &[], A, H, Admin, &[]);
    let out = w.edge(X, 4, &[], A, N5, Gone, &[g5]);
    for list in [vec![down, out], vec![down], vec![out]] {
        let mut w = w.clone();
        let r = w.edge(H, 6, &[], A, X, Gone, &list);
        agree_all(&w, &[r]);
        agree_all(&w, &[]);
    }
}

#[test]
fn a_removed_node_writing_a_grant_to_the_remover_stays_removed() {
    let (mut w, ..) = paired();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let out = w.edge(X, 2, &[], A, N5, Gone, &[g5]);
    w.edge(N5, 3, &[], A, H, Admin, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[out]);
    agree_all(&w, &[r]);
    agree_all(&w, &[]);
}

#[test]
fn a_made_up_key_regranting_the_remover_holds_nothing() {
    let (mut w, ..) = paired();
    let tg = w.edge(X, 2, &[], A, H, Admin, &[]);
    w.set_until(tg, 7);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    agree_all(&w, &[r]);
}

#[test]
fn a_party_removed_before_the_theft_stays_removed() {
    let (mut w, ..) = paired();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let out = w.edge(X, 3, &[], A, N5, Gone, &[g5]);
    let x5 = w.edge(X, 5, &[], A, H, Gone, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[out, x5]);
    w.edge(N5, 2, &[], A, H, Admin, &[]);
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
}

// spec/permissions.md §5.1 Trust set: a node trusting nothing is shown the removal as a dispute.
#[test]
fn a_node_trusting_nothing_is_shown_the_removal_as_a_dispute() {
    let (mut w, gx, gb) = paired();
    let tg = w.edge(X, 4, &[], A, H, Admin, &[]);
    w.set_until(tg, 7);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.edge(X, 7, &[], A, H, Gone, &[gx, gb]);
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
}

#[test]
fn a_removal_of_two_hops_holds_against_a_lowering_above_its_signer() {
    let (mut w, ..) = paired();
    w.edge(K, 1, &[], A2, X, Admin, &[]);
    let gs = w.edge(B, 2, &[A], T1, A2, Admin, &[]);
    w.edge(X, 5, &[A2], T1, A, Gone, &[gs]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let r3 = w.edge(B, 6, &[A], T1, A2, Gone, &[]);
    agree_all(&w, &[]);
    agree_all(&w, &[r, r3]);
    w.edge(X, 5, &[A], T1, A, Gone, &[]);
    agree_all(&w, &[r, r3]);
}

#[test]
fn a_dispute_whose_write_is_a_no_op_where_trusted_is_shown() {
    let (mut w, ..) = paired();
    w.edge(K, 1, &[], A2, X, Admin, &[]);
    let gs = w.edge(B, 2, &[A], T1, A2, Admin, &[]);
    w.edge(X, 3, &[A], T1, A2, Gone, &[]);
    w.edge(X, 3, &[A2], T1, A, Gone, &[gs]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let r3 = w.edge(B, 6, &[A], T1, A2, Gone, &[]);
    agree_all(&w, &[]);
    agree_all(&w, &[r3]);
    agree_all(&w, &[r]);
}

// spec/permissions.md §5.1 Trust set: dispute candidates are explicit lowerings (control
// `-all-candidates`).
#[test]
fn an_honest_holder_leave_is_no_dispute() {
    let mut w = account();
    w.edge(H, 1, &[A], T1, A2, Admin, &[]);
    w.edge(K, 2, &[A2], T1, Z, Write, &[]);
    w.edge(K, 3, &[A2], T1, A2, Gone, &[]);
    agree_all(&w, &[]);
}

// spec/permissions.md §5.1 Seeds: a trusted demotion to write keeps the grants made by flag
// (control `-seeds-all`).
#[test]
fn a_trusted_demotion_to_write_keeps_the_grants_made_by_flag() {
    let mut w = account();
    w.edge(H, 1, &[], A, B, Admin, &[]);
    w.push(H, 1, &[A], T1, Kind::set(A2, Admin));
    w.edge(K, 1, &[], A2, X, Write, &[]);
    w.push(X, 4, &[A2], T1, Kind::set(G, Read));
    let kiosk = w.push(B, 6, &[A], T1, Kind::set(A2, Write).may_grant());
    agree_all(&w, &[]);
    agree_all(&w, &[kiosk]);
}

// ---- May-grant and finalizes ----

/// The model's: A2 shares T1 at write, GU (A2's guests) holds read with the flag on T1.
fn invited() -> World {
    let mut w = account();
    w.push(H, 1, &[A], T1, Kind::set(A2, Write));
    w.push(H, 1, &[A], T1, Kind::set(GU, Read).may_grant());
    w.edge(K, 1, &[], A2, X, Write, &[]);
    w
}

// notes/write-path-design.md §1 G1, G2: a may-grant grant applies by its path's flag (controls
// `-no-flag`, `-last-hop`).
#[test]
fn a_may_grant_grant_applies_by_its_paths_flag() {
    let mut w = invited();
    w.push(X, 2, &[A2, GU], T1, Kind::set(Z, Read));
    w.push(X, 2, &[A2, GU], T1, Kind::set(N6, Write));
    w.push(X, 2, &[A2], T1, Kind::set(N5, Read));
    w.push(X, 3, &[A2, GU], T1, Kind::set(Z, Read).until(9));
    w.push(X, 4, &[A2, GU], T1, Kind::set(Z, Gone));
    agree_all(&w, &[]);
}

#[test]
fn a_may_grant_grant_needs_its_role_on_every_hop() {
    let mut w = account();
    w.push(H, 1, &[A], T1, Kind::set(GU, Write).may_grant());
    w.edge(K, 1, &[], A2, X, Read, &[]);
    w.push(X, 2, &[A2, GU], T1, Kind::set(Z, Read));
    w.push(X, 2, &[A2, GU], T1, Kind::set(N6, Write));
    agree_all(&w, &[]);
}

// spec/permissions.md §5.1 step 3: a lowering falls in role or flag (control `-admin-falls`).
#[test]
fn a_may_grant_grant_by_a_removed_writer_falls_unless_listed() {
    let mut w = invited();
    let z = w.push(X, 3, &[A2, GU], T1, Kind::set(Z, Read));
    w.push(X, 4, &[A2, GU], T1, Kind::set(N6, Read));
    let r = w.edge(K, 6, &[], A2, X, Gone, &[z]);
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
}

// spec/permissions.md §2 (Finalize).
#[test]
fn a_finalize_ends_an_ended_grant_and_a_may_grant_grant_follows_it() {
    let mut w = invited();
    w.push(X, 2, &[A2, GU], T1, Kind::set(Z, Read).until(4));
    w.push(K, 3, &[A2], T1, Kind::finalize(Z));
    w.push(X, 2, &[A2, GU], T1, Kind::set(N6, Read));
    w.push(N6, 3, &[], T1, Kind::finalize(Z));
    let fin = w.push(K, 4, &[A2], T1, Kind::finalize(Z));
    w.push(X, 5, &[A2, GU], T1, Kind::set(Z, Read));
    agree_all(&w, &[]);
    agree(&w, &View::all(&w).without(&[fin]));
    let mut w = invited();
    w.edge(H, 1, &[], A, B, Admin, &[]);
    w.push(H, 2, &[A], T1, Kind::set(N6, Admin).until(4));
    w.push(K, 5, &[A2], T1, Kind::finalize(N6));
    w.push(B, 6, &[A], T1, Kind::finalize(N6));
    agree_all(&w, &[]);
}

// spec/permissions.md §2 (Finalize): a finalize is a shape: a frontier-less removal of one's own
// grant by path end is a self-removal, along a path ending elsewhere an explicit removal.
#[test]
fn a_frontier_less_removal_of_ones_own_grant_is_no_finalize() {
    let mut w = invited();
    w.push(X, 2, &[A2, GU], T1, Kind::set(Z, Read).until(4));
    w.push(Z, 3, &[], T1, Kind::finalize(Z));
    w.push(K, 4, &[A2], T1, Kind::finalize(Z));
    agree_all(&w, &[]);
    let mut w = account();
    w.edge(H, 1, &[], A, Z, Admin, &[]);
    w.push(H, 1, &[A], T1, Kind::set(Z, Admin).until(3));
    w.edge(Z, 2, &[], T1, N5, Write, &[]);
    w.push(Z, 5, &[A], T1, Kind::finalize(Z));
    agree_all(&w, &[]);
}

// spec/permissions.md §2 (Self-removal): it lowers in every component; a removal always lowers.
#[test]
fn a_self_removal_lowers_in_every_component() {
    for k in [Kind::set(Z, Gone), Kind::set(Z, Read).until(5), Kind::set(Z, Read).until(9).may_grant(), Kind::set(Z, Read)] {
        let mut w = invited();
        w.push(X, 2, &[A2, GU], T1, Kind::set(Z, Read).until(9));
        w.push(Z, 3, &[], T1, k);
        agree_all(&w, &[]);
    }
}

// spec/permissions.md §5.1 step 2: a lowering applied by its verdict that would set its edge's
// flag (its role not above the edge as restored) applies only by admin along its path. N6,
// admin by H's grant, gives Z write and then read with the flag (a fall, judged and applied); B
// gave Z read at 2; B removes H not listing H's grant of N6, and the restart finds N6 with no
// authority: Z stays at B's read, with no flag. (No model hand test: the walk's own.)
#[test]
fn a_lowering_applied_by_its_verdict_sets_no_flag() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    w.edge(H, 1, &[], A, N6, Admin, &[]);
    w.edge(B, 2, &[], A, Z, Read, &[]);
    w.edge(N6, 3, &[], A, Z, Write, &[]);
    w.push(N6, 3, &[], A, Kind::set(Z, Read).may_grant());
    let r = w.edge(B, 7, &[], A, H, Gone, &[gb]);
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
}

#[test]
fn the_explicit_removal_after_a_finalize_audits_the_grants_made_by_flag() {
    let mut w = account();
    let l = N6;
    w.push(H, 1, &[A], T1, Kind::set(l, Write).may_grant().until(5));
    let z = w.push(l, 2, &[], T1, Kind::set(Z, Write));
    w.push(l, 3, &[], T1, Kind::set(N5, Write));
    w.push(B, 6, &[A], T1, Kind::finalize(l));
    w.edge(H, 1, &[], A, B, Admin, &[]);
    agree_all(&w, &[]);
    let r = w.edge(H, 7, &[A], T1, l, Gone, &[z]);
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
}

#[test]
fn a_write_clearing_the_flag_audits_the_grants_made_by_it() {
    let mut w = invited();
    let z = w.push(X, 2, &[A2, GU], T1, Kind::set(Z, Read));
    let plain = w.push(B, 5, &[A], T1, Kind::set(GU, Read));
    w.edge(H, 1, &[], A, B, Admin, &[]);
    agree_all(&w, &[]);
    agree_all(&w, &[plain]);
    w.edit(plain, |k| k.listing(BTreeMap::from([(T1, Set::from([z]))])));
    agree_all(&w, &[]);
}

// G5 with the flag below the role it was granted at (the walk's invite level, the role, falls with
// it): N5 holds write with the flag on A and grants Z read and N6 write by it; H demotes N5 to
// read with the flag (N6's grant falls, Z's stands), then sets it to write without the flag (Z's
// falls, or stands where listed).
#[test]
fn a_flag_kept_below_the_granted_role_keeps_the_grants_it_still_covers() {
    let mut w = account();
    w.push(H, 1, &[], A, Kind::set(N5, Write).may_grant());
    let z = w.push(N5, 2, &[], A, Kind::set(Z, Read));
    w.push(N5, 2, &[], A, Kind::set(N6, Write).may_grant());
    let down = w.push(H, 3, &[], A, Kind::set(N5, Read).may_grant());
    let plain = w.push(H, 4, &[], A, Kind::set(N5, Write));
    let roles = |w: &World| {
        let rd = judge(w, &Rules::fixed(), &View::all(w));
        (rd.role(Z, A), rd.role(N6, A))
    };
    assert_eq!(roles(&w), (Gone, Gone));
    agree_all(&w, &[]);
    agree_all(&w, &[down, plain]);
    let v = View::all(&w).without(&[plain]);
    let rd = judge(&w, &Rules::fixed(), &v);
    assert_eq!((rd.role(Z, A), rd.role(N6, A)), (Read, Gone));
    agree(&w, &v);
    w.edit(plain, |k| k.listing(BTreeMap::from([(A, Set::from([z]))])));
    assert_eq!(roles(&w), (Read, Gone));
    agree_all(&w, &[]);
}

// spec/permissions.md §5.1 step 2: a lowering applied by its verdict only lowers (finding 27).
#[test]
fn a_lowering_applied_by_its_verdict_raises_nothing() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    w.edge(H, 1, &[], A, N6, Admin, &[]);
    w.edge(N6, 3, &[], A, Z, Write, &[]);
    w.edge(N6, 3, &[], A, Z, Role::Read, &[]);
    let r = w.edge(B, 7, &[], A, H, Gone, &[gb]);
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
}

// ---- Several edge writes in one commit ----

// spec/commits.md §2: a commit's lowerings judged part by part, `keeps` passing over the
// commit's earlier drops (control `-own-drops`).
#[test]
fn a_commit_whose_drops_together_take_its_path_applies_only_what_keeps_it() {
    let mut w = account();
    w.edge(H, 1, &[], A, B, Admin, &[]);
    w.edge(H, 1, &[], A, N5, Admin, &[]);
    w.edge(B, 2, &[], A, X, Admin, &[]);
    w.edge(N5, 3, &[], A, X, Admin, &[]);
    let ids = w.commit(X, 5, &[], A, vec![Kind::set(N5, Gone), Kind::set(B, Gone)]);
    agree_all(&w, &[]);
    agree_all(&w, &[ids[0]]);
}

// spec/permissions.md §5.1 step 4: in `keeps`, a lowering left after the passing over decides by
// its value, never read through its own check. N5 (X's admin grant) lowers B to write, X raises B
// back to admin; B's removal of X drops X's grants (N5's and B's raise), so B's own edge is read
// back to N5's lowering, which decides: B's removal is void and X stays admin (passing over the
// lowering because N5's own grant is dropped would reach H's grant of B and apply it).
#[test]
fn a_lowering_whose_own_path_falls_still_decides_its_edge_in_keeps() {
    let (mut w, ..) = paired();
    w.edge(X, 2, &[], A, N5, Admin, &[]);
    w.edge(N5, 3, &[], A, B, Write, &[]);
    w.edge(X, 4, &[], A, B, Admin, &[]);
    let r = w.edge(B, 10, &[], A, X, Gone, &[]);
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
}

// spec/permissions.md §5.1 step 2: a commit's later part is taken in the same pass as an earlier
// part's drops, before the restart: X's commit removes B on A (dropping B's grant of X on ORG) and
// N5 on ORG through that grant, which still stands there, so the second applies, falls and is
// judged with the first's drops passed over: void (taken only after the restart it would apply
// nowhere and get no verdict).
#[test]
fn a_commits_later_part_is_taken_before_the_restart_its_earlier_drops_start() {
    let mut w = account();
    w.edge(H, 1, &[], A, X, Admin, &[]);
    w.edge(H, 1, &[], A, B, Admin, &[]);
    w.edge(H, 1, &[A], ORG, N5, Admin, &[]);
    w.edge(B, 2, &[A], ORG, X, Admin, &[]);
    let p1 = w.push(X, 5, &[], A, Kind::set(B, Gone));
    let p2 = w.push(X, 5, &[], ORG, Kind::set(N5, Gone));
    w.group(&[p1, p2]);
    agree_all(&w, &[]);
    let rd = judge(&w, &super::rules(), &View::all(&w));
    assert!(rd.applied.contains(&p1) && !rd.applied.contains(&p2), "the model: p1 applied, p2 not");
}

// spec/commits.md §2: the part on an edge of the commit's own path last; two parts on one edge
// are bad input (control `-refuse-shapes`).
#[test]
fn a_commit_of_several_writes_is_judged_part_by_part_its_own_path_last() {
    let (mut w, ..) = paired();
    let ga = w.edge(H, 1, &[A, T1], D1, A, Admin, &[]);
    w.commit(X, 5, &[], A, vec![Kind::set(X, Gone), Kind::set(B, Gone)]);
    w.commit(X, 5, &[], A, vec![Kind::set(N5, Admin), Kind::set(N5, Write)]);
    let rec = w.commit(H, 5, &[A], D1, vec![Kind::set(T1, Gone).listing(w.cut(&[ga])), Kind::set(N5, Admin)]);
    agree_all(&w, &[]);
    agree_all(&w, &[rec[1]]);
}

const LK: Thing = 30;
const L: Thing = 31;
const R1: Thing = 32;
const R2: Thing = 33;

fn link() -> World {
    let mut w = World::new(&[(H, A), (A, LK)]);
    w.push(H, 1, &[A], LK, Kind::set(L, Read).may_grant());
    w
}

fn redeem(w: &mut World, ts: u32, r: Thing) -> Vec<Id> {
    w.commit(L, ts, &[], LK, vec![Kind::set(r, Read), Kind::set(L, Gone)])
}

// spec/permissions.md §7: the single-use link redemption, once, twice concurrently, and a thief
// with the link key after it.
#[test]
fn a_link_redemption_grants_once_and_ends_the_link() {
    let mut w = link();
    redeem(&mut w, 3, R1);
    agree_all(&w, &[]);
    for later in [3, 4] {
        let mut w = link();
        redeem(&mut w, 3, R1);
        redeem(&mut w, later, R2);
        agree_all(&w, &[]);
    }
    let (z1, z2) = (34, 35);
    let mut w = link();
    let red = redeem(&mut w, 3, R1);
    w.push(L, 5, &[], LK, Kind::set(z1, Read));
    let back = w.push(L, 2, &[], LK, Kind::set(z2, Read));
    agree_all(&w, &[]);
    let mut w2 = w.clone();
    let end = w.push(H, 6, &[A], LK, Kind::set(L, Gone).listing(w.cut(&red)));
    agree_all(&w, &[]);
    agree_all(&w, &[end]);
    let end = w2.push(H, 6, &[A], LK, Kind::set(L, Gone).listing(w2.cut(&[red[0], red[1], back])));
    agree_all(&w2, &[end]);
}

// notes/a1-spec/README.md Open 23 (draft §5.1 step 3: a drop takes a commit's edge-class parts on
// its thing together): a single-use link redeemed twice, the sharer listing what it saw, at nodes
// trusting nothing and trusting the removal; roles-model
// `a_single_use_link_redeemed_twice_stays_with_the_redemption_the_sharer_listed`, its worlds.
#[test]
fn a_single_use_link_redeemed_twice_stays_with_the_redemption_the_sharer_listed() {
    // (the thief's ts, the seen redeemer's ts, the sharer lists the thief's too, single use)
    for (t2, t1, both, single) in [(3, 4, false, true), (2, 3, false, true), (4, 3, false, true), (3, 4, true, true), (3, 4, false, false)] {
        for neither in [false, true] {
            let mut w = link();
            let one = |w: &mut World, ts: u32, r: Thing| if single { redeem(w, ts, r) } else { vec![w.push(L, ts, &[], LK, Kind::set(r, Read))] };
            let (seen, thief) = if t2 < t1 {
                let b = one(&mut w, t2, R2);
                (one(&mut w, t1, R1), b)
            } else {
                let a = one(&mut w, t1, R1);
                (a, one(&mut w, t2, R2))
            };
            let list: Vec<Id> = if neither { vec![] } else if both { seen.iter().chain(&thief).copied().collect() } else { seen.clone() };
            let end = w.push(H, 6, &[A], LK, Kind::set(L, Gone).listing(w.cut(&list)));
            agree_all(&w, &[]);
            agree_all(&w, &[end]);
        }
    }
}

// ---- Writes that apply nowhere and still decide a fight (findings 33 to 36: accepted) ----

#[test]
fn an_unapplied_grant_changes_nothing_observed() {
    let mut w = account();
    let again = w.edge(H, 11, &[], A, N5, Admin, &[]);
    w.edge(N5, 11, &[], A, H, Write, &[again]);
    w.edit(1, |k| k.may_grant());
    w.edge(N5, 9, &[], A, N6, Gone, &[]);
    let g6 = w.push(N5, 8, &[], A, Kind::set(N6, Write).may_grant().until(10));
    w.edge(H, 3, &[], A, N5, Admin, &[]);
    agree_all(&w, &[]);
    agree(&w, &View::all(&w).without(&[g6]));
}

fn h_demotes_n5(listing: &[Id]) -> World {
    let mut w = account();
    let h = w.push(H, 7, &[], A, Kind::set(N5, Write).may_grant());
    w.push(N5, 4, &[], A, Kind::set(Z, Write).may_grant().listing(w.cut(&[h])));
    w.push(H, 4, &[], A, Kind::set(N5, Admin));
    w.push(H, 4, &[], A, Kind::set(Z, Admin));
    w.push(Z, 5, &[], A, Kind::set(H, Read).listing(w.cut(&[0, 1, 2, 3])));
    w.push(Z, 5, &[], A, Kind::set(N5, Read).listing(w.cut(&[0, 2, 3])));
    let f = w.cut(listing);
    w.edit(h, |k| k.listing(f));
    w
}

#[test]
fn a_lowering_whose_drops_let_an_earlier_write_take_its_authority_changes_roles_unshown() {
    for listing in [&[][..], &[1]] {
        let w = h_demotes_n5(listing);
        agree_all(&w, &[]);
        agree(&w, &View::all(&w).without(&[0]));
    }
}

#[test]
fn a_grant_applying_nowhere_gives_a_lowering_its_verdict() {
    let mut w = account();
    w.push(H, 6, &[], A, Kind::set(N5, Gone));
    w.commit(N5, 2, &[], A, vec![Kind::set(H, Admin).until(4), Kind::set(B, Admin)]);
    let b = w.push(B, 4, &[], A, Kind::set(H, Admin).listing(w.cut(&[1, 2])));
    w.push(H, 2, &[], A, Kind::set(N5, Admin).listing(w.cut(&[b])));
    agree_all(&w, &[]);
    agree(&w, &View::all(&w).without(&[b]));
}

#[test]
fn with_honest_writers_a_grant_applying_nowhere_decides_a_fight() {
    for end in [Kind::set(H, Admin).until(8), Kind::set(H, Gone)] {
        let mut w = account();
        w.push(H, 5, &[], A, Kind::set(B, Admin));
        w.push(B, 6, &[], A, end.listing(w.cut(&[0])));
        w.push(B, 7, &[], A, Kind::set(Z, Admin));
        let g = w.push(Z, 8, &[], A, Kind::set(H, Admin));
        let r = w.push(H, 12, &[], A, Kind::set(B, Gone));
        agree_all(&w, &[]);
        agree_all(&w, &[r]);
        agree(&w, &View::all(&w).without(&[g]));
    }
}

#[test]
fn an_end_judged_at_its_key_applies_for_good_and_can_strand_the_thing() {
    let mut w = account();
    let gb = w.push(H, 2, &[], A, Kind::set(B, Admin));
    let gn = w.push(H, 2, &[], A, Kind::set(N6, Admin));
    w.push(N6, 3, &[], A, Kind::set(H, Gone).listing(w.cut(&[gn])));
    w.commit(B, 3, &[], A, vec![Kind::set(H, Admin).until(5).listing(w.cut(&[gb, gn])), Kind::set(N6, Admin).until(5).listing(w.cut(&[gb]))]);
    agree_all(&w, &[]);
}
