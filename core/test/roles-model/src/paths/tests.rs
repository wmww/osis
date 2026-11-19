//! Hand worlds: the minimal one of each property, then the searches at small size. A `repro_*`
//! asserts the wanted behaviour under the notes' rules and fails: a finding of
//! notes/path-model-findings.md, which its `#[ignore]` names; the test after it checks the fix.

use super::*;
use Role::{Admin, None as Gone, Write};

/// A with H (mint), X and B paired by H at 1.
fn paired() -> (World, Id, Id) {
    let mut w = account();
    let gx = w.edge(H, 1, &[], A, X, Admin, &[]);
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    (w, gx, gb)
}

fn design(w: &World, trust: &[Id]) -> Reading {
    judge(w, &Rules::design(), &View::all(w).trusting(trust))
}

fn with(w: &World, trust: &[Id], f: impl Fn(&mut Rules)) -> Reading {
    let mut r = Rules::design();
    f(&mut r);
    judge(w, &r, &View::all(w).trusting(trust))
}

// ---- Safety and liveness: what holds ----

/// Stolen device, steps 1-3 and 8 (notes/account-membership-design.md §2).
#[test]
fn a_write_the_remover_or_a_writer_received_shows_a_later_one_does_not() {
    let (mut w, ..) = paired();
    let listed = w.content(X, 3, &[A], T1);
    let witnessed = w.content(X, 4, &[A], T1);
    let unseen = w.content(X, 4, &[A, ORG], T2);
    let backdated = w.content(X, 5, &[A], T1);
    let r = w.edge(H, 6, &[], A, X, Gone, &[listed]);
    let ad = w.addendum(B, 7, &[A], T1, r, &[witnessed]);
    let after = w.content(X, 8, &[A], T1);
    let honest = w.content(B, 8, &[A, ORG], T2);
    let rd = design(&w, &[r]);
    assert_eq!(rd.valid, Set::from([listed, witnessed, ad, honest]));
    assert!(![unseen, backdated, after].iter().any(|i| rd.shows(*i)));
    assert_eq!(rd.role(X, A), Gone);
    // without B's addendum the write only B received falls
    let rd = judge(&w, &Rules::design(), &View::all(&w).trusting(&[r]).without(&[ad]));
    assert!(!rd.valid.contains(&witnessed) && rd.valid.contains(&listed));
}

/// notes/write-path-design.md §1: a write is judged along its stated path alone.
#[test]
fn a_write_on_a_cut_path_never_shows_by_another_path_its_signer_holds() {
    let (mut w, ..) = paired();
    w.edge(K, 1, &[], A2, X, Write, &[]);
    w.edge(B, 2, &[A], T1, A2, Write, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let cut = w.content(X, 8, &[A], T1);
    let other = w.content(X, 8, &[A2], T1);
    let never = w.content(X, 8, &[ORG], T1);
    let twice = w.content(X, 8, &[A2, A, A2], T1);
    let rd = design(&w, &[r]);
    assert_eq!(rd.valid, Set::from([other]));
    assert!(![cut, never, twice].iter().any(|i| rd.shows(*i)));
    // K removes X from A2: that path's own removal judges the writes through it
    let r2 = w.edge(K, 9, &[], A2, X, Gone, &[other]);
    let back = w.content(X, 7, &[A2], T1);
    let late = w.content(X, 10, &[A2], T1);
    let rd = design(&w, &[r, r2]);
    assert!(rd.valid.contains(&other) && !rd.shows(back) && !rd.shows(late));
}

/// Stolen device, steps 4-5: X backdates a grant to a made-up key, which removes H.
#[test]
fn a_made_up_key_holds_nothing_where_the_removal_is_trusted() {
    let (mut w, gx, _) = paired();
    let gz = w.edge(X, 2, &[], A, Z, Admin, &[]);
    let rz = w.edge(Z, 3, &[], A, H, Gone, &[gx]);
    let zc = w.content(Z, 4, &[A], T1);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let hc = w.content(H, 8, &[A], T1);
    // the walk alone sides with the earlier stamp: the thief's
    let plain = design(&w, &[]);
    assert_eq!((plain.role(H, A), plain.role(X, A), plain.role(Z, A)), (Gone, Admin, Admin));
    assert_eq!(disputes(&w, &Rules::design(), &View::all(&w)), vec![r]);
    for rules in [Rules::design(), Rules::fixed()] {
        let rd = judge(&w, &rules, &View::all(&w).trusting(&[r]));
        assert_eq!((rd.role(H, A), rd.role(X, A), rd.role(Z, A)), (Admin, Gone, Gone));
        assert!(rd.valid.contains(&hc) && ![gz, rz, zc].iter().any(|i| rd.shows(*i)));
        assert!(rd.void.is_empty() && rd.stray.is_empty());
    }
}

/// A removal reaches a unit only through a node holding both (notes/write-path-design.md §2);
/// logged under every unit X could read it leaves no window where X never wrote.
#[test]
fn a_removal_logged_only_where_the_node_wrote_leaves_a_window() {
    let (mut w, gx, _) = paired();
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let first = w.content(X, 8, &[A, ORG], T2);
    // T2's unit at a source that never held A: X's write and the grant riding with it
    let source = Set::from([first, gx]);
    let v = View { held: evidence(&w, &Set::from([first]), &source), leaves: Some(Things::from([T2])), trust: Set::new() };
    assert!(judge(&w, &Rules::design(), &v).valid.contains(&first));
    let v = View { held: evidence(&w, &Set::from([first, r]), &source), ..v };
    assert!(!judge(&w, &Rules::design(), &v).shows(first));
}

// ---- The role-write gap ----

/// X shares T1 with A2; K writes; H, who does not sync T1, removes X.
fn shared_by_x() -> (World, Id, Id, Id, Id) {
    let (mut w, ..) = paired();
    let gs = w.edge(X, 2, &[A], T1, A2, Write, &[]);
    let kc = w.content(K, 3, &[A2], T1);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let later = w.content(K, 8, &[A2], T1);
    (w, gs, kc, r, later)
}

#[test]
#[ignore = "notes/path-model-findings.md: a grant the remover did not hold falls, and every write made under it"]
fn repro_a_grant_the_remover_did_not_hold_stands() {
    let (w, gs, kc, r, later) = shared_by_x();
    let rd = design(&w, &[r]);
    assert!(rd.applied.contains(&gs) && rd.valid.contains(&kc) && rd.valid.contains(&later), "{rd:?}");
}

#[test]
fn a_grant_the_remover_did_not_hold_stands_by_a_co_admins_vouch() {
    let (mut w, gs, kc, r, later) = shared_by_x();
    let v = w.vouch(B, 7, &[A], T1, r, &[gs]);
    for vouch in [Vouch::BaseWalk, Vouch::SameWalk] {
        let rd = with(&w, &[r], |x| x.vouch = vouch);
        assert!(rd.applied.is_superset(&Set::from([gs, v])) && rd.valid.is_superset(&Set::from([kc, later])) && !rd.circle);
    }
    assert!(!design(&w, &[r]).shows(kc));
}

/// A vouch counts only ordered after its removal and for a commit on its own thing: B's vouch
/// stamped before H's removal, and its vouch on A naming X's grant on T1, keep nothing.
#[test]
fn a_vouch_counts_only_after_its_removal_and_on_its_own_thing() {
    let (mut w, gs, kc, r, _) = shared_by_x();
    w.vouch(B, 5, &[A], T1, r, &[gs]);
    w.vouch(B, 7, &[], A, r, &[gs]);
    let rd = fixed(&w, &[r]);
    assert!(!rd.applied.contains(&gs) && !rd.valid.contains(&kc));
}

/// B shares T1 with A2, X removes A2 again, K writes on; H, who does not sync T1, removes X.
fn unshared_by_x() -> (World, Id, Id, Id) {
    let (mut w, ..) = paired();
    w.edge(B, 2, &[A], T1, A2, Write, &[]);
    let out = w.edge(X, 3, &[A], T1, A2, Gone, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let kc = w.content(K, 8, &[A2], T1);
    (w, out, r, kc)
}

#[test]
#[ignore = "notes/path-model-findings.md: removing a node undoes the removals it made where the remover did not hold them"]
fn repro_a_removal_the_removed_node_made_stays() {
    let (w, out, r, kc) = unshared_by_x();
    let rd = design(&w, &[r]);
    assert!(rd.applied.contains(&out) && rd.role(A2, T1) == Gone && !rd.shows(kc), "{rd:?}");
}

#[test]
fn a_removal_the_removed_node_made_stays_by_a_co_admins_vouch() {
    let (mut w, out, r, kc) = unshared_by_x();
    w.vouch(B, 7, &[A], T1, r, &[out]);
    let rd = with(&w, &[r], |x| x.vouch = Vouch::BaseWalk);
    assert!(rd.applied.contains(&out) && rd.role(A2, T1) == Gone && !rd.shows(kc));
}

/// X demotes B to write on A; H removes X without having received that; B, an admin again
/// once the demotion falls, vouches for it.
fn demoted_voucher() -> (World, Id, Id, Id) {
    let (mut w, ..) = paired();
    let down = w.edge(X, 3, &[], A, B, Write, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let v = w.vouch(B, 7, &[], A, r, &[down]);
    (w, down, r, v)
}

#[test]
#[ignore = "notes/path-model-findings.md: a vouch judged in the walk it changes circles (no fixpoint)"]
fn repro_a_vouch_judged_in_the_walk_it_changes_settles() {
    let (w, _, r, _) = demoted_voucher();
    let rd = with(&w, &[r], |x| x.vouch = Vouch::SameWalk);
    assert!(!rd.circle, "the vouch counts only while what it vouches for does not stand");
}

#[test]
fn a_vouch_judged_in_the_walk_without_vouches_settles() {
    let (w, down, r, v) = demoted_voucher();
    let rd = with(&w, &[r], |x| x.vouch = Vouch::BaseWalk);
    assert!(!rd.circle && rd.applied.contains(&down) && rd.role(B, A) == Write);
    // the vouch itself does not apply in the walk it made: it is read from the walk before it
    assert!(!rd.applied.contains(&v));
}

/// No escalation: a key X made up, or X by another path, vouches for nothing.
#[test]
fn a_vouch_gives_nothing_to_whoever_could_not_have_made_the_write() {
    let (mut w, ..) = paired();
    w.edge(K, 1, &[], A2, X, Write, &[]);
    w.edge(B, 2, &[A], T1, A2, Admin, &[]);
    let gz = w.edge(X, 2, &[], A, Z, Admin, &[]);
    let gt = w.edge(X, 2, &[A], T1, Z, Admin, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.vouch(Z, 7, &[], A, r, &[gz]);
    w.vouch(X, 7, &[], A, r, &[gz]);
    // X holds write on A2, A2 admin on T1: its path gives write, not admin
    w.vouch(X, 7, &[A2], T1, r, &[gt]);
    w.vouch(Z, 7, &[], T1, r, &[gt]);
    for vouch in [Vouch::BaseWalk, Vouch::SameWalk] {
        let rd = with(&w, &[r], |x| x.vouch = vouch);
        assert!(!rd.circle && !rd.shows(gz) && !rd.shows(gt) && rd.role(Z, A) == Gone && rd.role(Z, T1) == Gone);
    }
}

/// X pairs N5 and shares T1 with A2; B received the pairing, only N5 the share.
fn second_hand() -> (World, Id, Id, Id) {
    let (mut w, ..) = paired();
    let g5 = w.edge(X, 2, &[], A, N5, Admin, &[]);
    let gs = w.edge(X, 3, &[A], T1, A2, Write, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.vouch(B, 7, &[], A, r, &[g5]);
    w.vouch(N5, 7, &[A], T1, r, &[gs]);
    (w, g5, gs, r)
}

#[test]
#[ignore = "notes/path-model-findings.md: under the walk-without-vouches reading a holder kept by a vouch vouches for nothing"]
fn repro_a_holder_kept_by_a_vouch_vouches_in_turn() {
    let (w, g5, gs, r) = second_hand();
    let rd = with(&w, &[r], |x| x.vouch = Vouch::BaseWalk);
    assert!(rd.applied.contains(&g5));
    assert!(rd.applied.contains(&gs), "N5 received the share by the removal and could have made it");
}

#[test]
fn a_holder_kept_by_a_vouch_vouches_in_turn_in_the_same_walk() {
    let (w, g5, gs, r) = second_hand();
    let rd = with(&w, &[r], |x| x.vouch = Vouch::SameWalk);
    assert!(!rd.circle && rd.applied.contains(&g5) && rd.applied.contains(&gs));
}

// ---- The collateral grantee ----

/// X pairs N5 offline; N5 writes; H removes X, never having received the pairing, then pairs
/// N5 again.
fn collateral() -> (World, Id, Id, Id) {
    let (mut w, ..) = paired();
    w.edge(X, 2, &[], A, N5, Admin, &[]);
    let week = w.content(N5, 3, &[A], T1);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.edge(H, 8, &[], A, N5, Admin, &[]);
    let after = w.content(N5, 9, &[A], T1);
    (w, week, r, after)
}

#[test]
#[ignore = "notes/path-model-findings.md: the collateral grantee's writes before its re-grant stay invalid"]
fn repro_a_collateral_grantees_writes_count_after_its_re_grant() {
    let (w, week, r, after) = collateral();
    let rd = design(&w, &[r]);
    assert!(rd.valid.contains(&after));
    assert!(rd.valid.contains(&week), "counted from the re-grant, the first point the settled walk gave N5 the role");
}

#[test]
fn a_collateral_grantees_writes_count_from_its_first_chained_grant() {
    let (w, week, r, after) = collateral();
    let rd = with(&w, &[r], |x| x.regrant = Regrant::FirstChained);
    assert!(rd.valid.contains(&week) && rd.valid.contains(&after));
}

/// The fix's cost: a grant the thief backdates is chained, so a holder granted later may
/// stamp content back to it.
#[test]
fn a_backdated_grant_moves_a_current_holders_first_point_back() {
    let (mut w, ..) = paired();
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.edge(X, 2, &[A], T1, A2, Write, &[]);
    w.edge(B, 7, &[A], T1, A2, Write, &[]);
    let early = w.content(K, 4, &[A2], T1);
    assert!(!design(&w, &[r]).shows(early));
    assert!(with(&w, &[r], |x| x.regrant = Regrant::FirstChained).valid.contains(&early));
}

/// X's write only N5 received: N5's addendum is valid once N5 is re-granted, but N5 held
/// nothing at its key.
#[test]
#[ignore = "notes/path-model-findings.md: a re-granted writer's addendum vouches for nothing"]
fn repro_a_re_granted_writers_addendum_vouches() {
    let (mut w, ..) = paired();
    w.edge(X, 2, &[], A, N5, Admin, &[]);
    let xc = w.content(X, 3, &[A], T1);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let ad = w.addendum(N5, 7, &[A], T1, r, &[xc]);
    w.edge(H, 8, &[], A, N5, Admin, &[]);
    let rd = with(&w, &[r], |x| x.regrant = Regrant::FirstChained);
    assert!(rd.valid.contains(&ad));
    assert!(rd.valid.contains(&xc), "N5 received X's write before the removal");
}

// ---- Alike: a reader outside A ----

/// X pairs N5 (H received it and lists it); N5 writes T1. The reader holds T1's unit, the
/// removal logged there and the evidence.
fn reader_of_t1() -> (World, View, Id) {
    let (mut w, ..) = paired();
    let g5 = w.edge(X, 2, &[], A, N5, Admin, &[]);
    let c = w.content(N5, 3, &[A], T1);
    let r = w.edge(H, 6, &[], A, X, Gone, &[g5]);
    w.content(N5, 8, &[A], T1);
    let all = View::all(&w).held;
    let unit: Set = all.iter().copied().filter(|&i| w.commits[i].on == T1 || i == r).collect();
    let v = View { held: evidence(&w, &unit, &all), leaves: Some(Things::from([T1])), trust: Set::from([r]) };
    assert!(v.held.contains(&g5));
    (w, v, c)
}

#[test]
#[ignore = "notes/path-model-findings.md: a reader holding only T's leaf cannot tell a listed grant on A from a dropped one"]
fn repro_a_reader_with_its_things_leaf_reads_as_a_member() {
    let (w, v, c) = reader_of_t1();
    let member = design(&w, &v.trust.iter().copied().collect::<Vec<_>>());
    assert!(member.valid.contains(&c));
    assert_eq!(judge(&w, &Rules::design(), &v).valid, member.valid);
}

#[test]
fn a_reader_with_the_leaves_of_its_evidence_reads_as_a_member() {
    let (w, mut v, _) = reader_of_t1();
    v.leaves = Some(Things::from([T1, A]));
    let member = design(&w, &v.trust.iter().copied().collect::<Vec<_>>());
    assert_eq!(judge(&w, &Rules::design(), &v).valid, member.valid);
}

// ---- Disputes: sides, a switch, pairing, the window ----

/// X backdates its removal of H (keeping itself and B); H removes X.
fn fight() -> (World, Id, Id) {
    let (mut w, gx, gb) = paired();
    let rx = w.edge(X, 5, &[], A, H, Gone, &[gx, gb]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    (w, rx, r)
}

#[test]
fn a_switch_takes() {
    let (mut w, rx, r) = fight();
    let xc = w.content(X, 3, &[A], T1);
    let hc = w.content(H, 8, &[A], T1);
    let bc = w.content(B, 8, &[A], T1);
    let thief = w.content(X, 9, &[A], T1);
    // B on X's side
    let rd = design(&w, &[rx]);
    assert_eq!((rd.role(H, A), rd.role(X, A)), (Gone, Admin));
    assert!(!rd.shows(hc) && rd.valid.is_superset(&Set::from([xc, bc, thief])));
    assert_eq!(disputes(&w, &Rules::design(), &View::all(&w).trusting(&[rx])), vec![r]);
    // its user switches: R applies at it, so it answers R as any writer does, by what it had
    // received by R's ts
    let ad = w.addendum(B, 12, &[A], T1, r, &[xc]);
    let rd = design(&w, &[r]);
    assert_eq!((rd.role(H, A), rd.role(X, A)), (Admin, Gone));
    assert_eq!(rd.valid, Set::from([xc, hc, bc, ad]));
    // and back: a function of the held writes and the trust set
    assert_eq!(design(&w, &[rx]).role(H, A), Gone);
}

#[test]
#[ignore = "notes/path-model-findings.md: a node paired after a backdated fight takes the walk's side and is no member at itself"]
fn repro_a_node_paired_after_a_fight_is_a_member_at_itself() {
    let (mut w, _, _) = fight();
    w.edge(H, 8, &[], A, N6, Admin, &[]);
    assert_eq!(design(&w, &[]).role(N6, A), Admin);
}

#[test]
fn a_node_paired_with_its_pairers_trust_entries_is_a_member_at_itself() {
    let (mut w, _, r) = fight();
    w.edge(H, 8, &[], A, N6, Admin, &[]);
    let c = w.content(N6, 9, &[A], T1);
    let rd = design(&w, &[r]);
    assert!(rd.role(N6, A) == Admin && rd.valid.contains(&c));
}

/// The thief acts first, honestly stamped, and H receives it before removing X.
#[test]
#[ignore = "notes/path-model-findings.md: a frontier listing everything received blesses the thief's removal of the remover"]
fn repro_a_removal_listing_all_it_received_applies() {
    let (mut w, gx, gb) = paired();
    let rx = w.edge(X, 5, &[], A, H, Gone, &[gx, gb]);
    let f = w.through((X, A), |_| true);
    assert_eq!(f, vec![rx]);
    let r = w.edge(H, 6, &[], A, X, Gone, &f);
    let rd = design(&w, &[r]);
    assert!(rd.void.is_empty() && rd.role(X, A) == Gone, "{rd:?}");
}

#[test]
fn a_removal_leaving_out_the_removals_it_contests_applies() {
    let (w, _, r) = fight();
    let rd = design(&w, &[r]);
    assert!(rd.void.is_empty() && rd.role(X, A) == Gone && rd.role(H, A) == Admin);
}

/// X's removal of H lists nothing, its own grant included (X holds admin by H's grant).
fn self_voiding() -> (World, Id, Id) {
    let (mut w, _, gb) = paired();
    let rx = w.edge(X, 5, &[], A, H, Gone, &[]);
    (w, gb, rx)
}

#[test]
#[ignore = "notes/path-model-findings.md: a removal not listing its own grant drops what it does not list and then does not apply"]
fn repro_nothing_falls_by_a_removal_that_does_not_apply() {
    let (w, gb, rx) = self_voiding();
    let rd = design(&w, &[]);
    assert!(!rd.applied.contains(&rx) && rd.role(H, A) == Admin);
    assert!(rd.stray.is_empty() && rd.applied.contains(&gb), "B fell: {rd:?}");
}

#[test]
fn nothing_raises_a_dispute_over_a_removal_that_voids_itself() {
    let (w, ..) = self_voiding();
    assert!(disputes(&w, &Rules::design(), &View::all(&w)).is_empty());
}

// ---- The last admin ----

#[test]
fn two_nodes_removing_each_other_never_leave_no_admin() {
    let mut w = account();
    let gx = w.edge(H, 1, &[], A, X, Admin, &[]);
    let rh = w.edge(H, 6, &[], A, X, Gone, &[]);
    let rx = w.edge(X, 6, &[], A, H, Gone, &[gx]);
    let admins = |rd: &Reading| rd.roles.iter().filter(|(e, r)| e.1 == A && **r == Admin).count();
    for held in 0..8u32 {
        for trust in 0..4u32 {
            let pick = |bits: u32, ids: &[Id]| -> Set { ids.iter().enumerate().filter(|(k, _)| bits >> k & 1 == 1).map(|(_, i)| *i).collect() };
            let v = View { held: pick(held, &[gx, rh, rx]), leaves: None, trust: pick(trust, &[rh, rx]) };
            for rules in [Rules::design(), Rules::fixed()] {
                let n = admins(&judge(&w, &rules, &v));
                assert!(n >= 1 && (n == 1 || !v.held.contains(&rh)), "{v:?}");
            }
        }
    }
    // each side reads itself the one admin; the walk alone takes the lower key (H's)
    assert_eq!(design(&w, &[rh]).role(H, A), Admin);
    assert_eq!(design(&w, &[rx]).role(X, A), Admin);
    assert_eq!(design(&w, &[]).role(H, A), Admin);
}

#[test]
fn a_lowering_that_leaves_no_admin_applies_only_when_marked() {
    let mut w = account();
    let leave = w.edge(H, 3, &[], A, H, Gone, &[]);
    let hc = w.content(H, 5, &[A], T1);
    let rd = design(&w, &[]);
    assert!(!rd.applied.contains(&leave) && rd.role(H, A) == Admin && rd.valid.contains(&hc));
    w.mark_adminless(leave);
    let rd = design(&w, &[]);
    assert!(rd.applied.contains(&leave) && rd.role(H, A) == Gone && !rd.shows(hc));
}

/// H pairs B, then leaves A. Whether its leaving applies turns on B's grant being held.
fn leaver() -> (World, Id, Id, Id) {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    let leave = w.edge(H, 3, &[], A, H, Gone, &[gb]);
    let hc = w.content(H, 5, &[A], T1);
    (w, gb, leave, hc)
}

#[test]
fn the_last_admin_rule_is_a_function_of_the_held_writes() {
    let (w, gb, leave, hc) = leaver();
    let rd = design(&w, &[]);
    assert!(rd.applied.contains(&leave) && !rd.shows(hc));
    let rd = judge(&w, &Rules::design(), &View::all(&w).without(&[gb]));
    assert!(!rd.applied.contains(&leave) && rd.valid.contains(&hc));
}

#[test]
#[ignore = "notes/path-model-findings.md: the last-admin rule reads the thing's every admin edge, which a reader's evidence does not hold"]
fn repro_a_reader_judges_the_last_admin_rule_as_a_member() {
    let (w, _, leave, hc) = leaver();
    // T1's unit: H's write and the evidence of its path (B never wrote T1)
    let v = View { held: evidence(&w, &Set::from([hc]), &View::all(&w).held), leaves: None, trust: Set::new() };
    assert!(v.held.contains(&leave));
    assert_eq!(judge(&w, &Rules::design(), &v).shows(hc), design(&w, &[]).shows(hc));
}

#[test]
fn a_reader_holding_the_remaining_admins_grant_judges_the_last_admin_rule_as_a_member() {
    let (w, gb, _, hc) = leaver();
    let mut v = View { held: evidence(&w, &Set::from([hc]), &View::all(&w).held), leaves: None, trust: Set::new() };
    v.held.insert(gb);
    assert_eq!(judge(&w, &Rules::design(), &v).shows(hc), design(&w, &[]).shows(hc));
}

// ---- Another path's addendum ----

/// X, removed from A, still writes T1 through A2: it backdates a write through A and vouches
/// for it itself.
fn own_addendum() -> (World, Id, Id) {
    let (mut w, ..) = paired();
    w.edge(K, 1, &[], A2, X, Write, &[]);
    w.edge(B, 2, &[A], T1, A2, Write, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let back = w.content(X, 4, &[A], T1);
    w.addendum(X, 7, &[A2], T1, r, &[back]);
    (w, r, back)
}

#[test]
#[ignore = "notes/path-model-findings.md: a removed node holding write by another path vouches for its own backdated writes through the cut one"]
fn repro_a_write_made_after_the_removal_does_not_show_by_its_signers_addendum() {
    let (w, r, back) = own_addendum();
    assert!(!design(&w, &[r]).shows(back));
}

#[test]
fn an_addendum_vouches_for_no_commit_of_its_own_signer() {
    let (w, r, back) = own_addendum();
    assert!(!with(&w, &[r], |x| x.no_own_addendum = true).shows(back));
}

// ---- Keys: a standing dispute ----

/// H on its own removal's side, B on X's: the sides the keys layer reads.
fn sides(switch_at: Option<usize>) -> impl Fn(usize) -> Vec<Side> {
    let (w, rx, r) = fight();
    move |pass| {
        let hs = Side::of(&w, &design(&w, &[r]), H, A);
        let b_trust = if switch_at.is_some_and(|p| pass >= p) { r } else { rx };
        vec![hs, Side::of(&w, &design(&w, &[b_trust]), B, A)]
    }
}

#[test]
#[ignore = "notes/path-model-findings.md: both sides of a standing dispute rotate at every pass (the withdraw rule and the knowing re-key answer each other)"]
fn repro_a_standing_dispute_stops_rotating() {
    let (_, per) = rotations(8, Withdraw::AsWritten, sides(None));
    assert_eq!(per[4..], [0, 0, 0, 0], "rotations per pass {per:?}");
}

#[test]
fn a_standing_dispute_rotates_once_a_side_when_the_other_sides_epochs_are_not_answered() {
    let s = sides(None);
    let (eps, per) = rotations(8, Withdraw::SideOnly, &s);
    assert_eq!(per, [2, 0, 0, 0, 0, 0, 0, 0]);
    // secrecy: what H encrypts under boxes no X; B, on X's side, boxes it (accepted, counted)
    let at = s(7);
    let cur = current(&eps, &at[0], Withdraw::SideOnly);
    assert!(cur.len() == 1 && !eps[cur[0]].boxes.contains(&X) && eps[cur[0]].boxes.contains(&B));
    let cur = current(&eps, &at[1], Withdraw::SideOnly);
    assert!(cur.len() == 1 && eps[cur[0]].boxes.contains(&X));
}

/// B's user switches at pass 3: one more rotation (B withdraws its own), then none; both
/// encrypt under one epoch boxing no X, and H's epoch was boxed to B all along.
#[test]
fn a_switch_ends_the_rotations() {
    for rule in [Withdraw::AsWritten, Withdraw::SideOnly] {
        let s = sides(Some(3));
        let (eps, per) = rotations(8, rule, &s);
        assert_eq!(per[5..], [0, 0, 0], "{rule:?}: {per:?}");
        if rule == Withdraw::SideOnly {
            assert_eq!(per.iter().sum::<usize>(), 3);
            assert!(eps[1].maker == H && eps[1].boxes.contains(&B));
        }
        let at = s(7);
        let cur = current(&eps, &at[0], rule);
        assert_eq!(cur, current(&eps, &at[1], rule));
        assert!(cur.len() == 1 && !eps[cur[0]].boxes.contains(&X));
    }
}

// ---- The list (notes/account-membership-design.md §4) ----

fn fixed(w: &World, trust: &[Id]) -> Reading {
    judge(w, &Rules::fixed(), &View::all(w).trusting(trust))
}

fn fixed_but(w: &World, trust: &[Id], f: impl Fn(&mut Rules)) -> Reading {
    let mut r = Rules::fixed();
    f(&mut r);
    judge(w, &r, &View::all(w).trusting(trust))
}

/// X removed N5 long before the theft; H received it and lists it. N5, holding nothing, writes a
/// grant of admin to H: it applies nowhere, and X's removal of N5 stays made.
#[test]
fn a_removed_node_writing_a_grant_to_the_remover_stays_removed() {
    let (mut w, ..) = paired();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let out = w.edge(X, 2, &[], A, N5, Gone, &[g5]);
    let junk = w.edge(N5, 3, &[], A, H, Admin, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[out]);
    let rd = fixed(&w, &[r]);
    assert!(rd.applied.contains(&out) && !rd.shows(junk) && rd.role(N5, A) == Gone && rd.void.is_empty());
}

/// Every other lowering the removed node made stays made: listed by the remover (X's removal of
/// N5), or vouched for by a witness the remover did not hear (X's demotion of B, only B
/// received it). Control: no vouch counting, the demotion only B received is undone.
#[test]
fn a_lowering_the_removed_node_made_before_stays_made() {
    let (mut w, _, gb) = paired();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let out = w.edge(X, 2, &[], A, N5, Gone, &[g5]);
    let down = w.edge(X, 3, &[], A, B, Write, &[gb]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[out]);
    w.vouch(B, 7, &[], A, r, &[down]);
    let rd = fixed(&w, &[r]);
    assert!(rd.applied.is_superset(&Set::from([out, down])) && rd.role(N5, A) == Gone && rd.role(B, A) == Write);
    let rd = fixed_but(&w, &[r], |x| x.vouch = Vouch::Off);
    assert!(rd.role(N5, A) == Gone && rd.role(B, A) == Admin);
}

// ---- The last admin relying on a named admin (notes/write-path-design.md §5) ----

/// H pairs B, then leaves A naming B as the admin that remains; H writes T1 after. A reader of
/// T1 holds H's write, its path's evidence and, as the leave's evidence, B's grant: it judges the
/// leave as A's members do (finding 8). Control: the rule reading every admin edge of A, the
/// reader (lacking B's grant) refuses the leave and shows H's later write.
#[test]
fn a_reader_judges_the_named_last_admin_rule_as_a_member() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    let leave = w.edge(H, 3, &[], A, H, Gone, &[gb]);
    w.rely(leave, B);
    let hc = w.content(H, 5, &[A], T1);
    let all = View::all(&w).held;
    let unit = Set::from([hc]);
    let reader = |rules: Rules| {
        let v = View { held: evidence(&w, &unit, &all), leaves: None, trust: Set::new() };
        (judge(&w, &rules, &v).shows(hc), judge(&w, &rules, &View::all(&w)).shows(hc))
    };
    assert!(evidence(&w, &unit, &all).contains(&gb));
    assert_eq!(reader(Rules::fixed()), (false, false));
    // without the named edge's writes as evidence, the any-edge rule splits reader and member
    let v = View { held: Set::from([hc, leave]), leaves: None, trust: Set::new() };
    let any = Rules { last_admin: LastAdmin::AnyEdge, ..Rules::fixed() };
    assert!(judge(&w, &any, &v).shows(hc) && !judge(&w, &any, &View::all(&w)).shows(hc));
    // the named rule reads the same two edges at both
    assert!(!judge(&w, &Rules::fixed(), &View { held: Set::from([hc, leave, gb]), ..v }).shows(hc));
}

/// The named admin was removed by an earlier-stamped write of a third (C = N5): the leave is
/// not applied though C stands (the cost the note states); a reader holding the leave's evidence
/// (B's grant and its removal) judges it so too.
#[test]
fn a_leave_relying_on_an_admin_removed_earlier_is_not_applied() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    w.edge(H, 1, &[], A, N5, Admin, &[]);
    w.edge(N5, 3, &[], A, B, Gone, &[gb]);
    let leave = w.edge(H, 4, &[], A, H, Gone, &[gb]);
    w.rely(leave, B);
    let hc = w.content(H, 5, &[A], T1);
    let rd = fixed(&w, &[]);
    assert!(!rd.applied.contains(&leave) && rd.valid.contains(&hc));
    let all = View::all(&w).held;
    let v = View { held: evidence(&w, &Set::from([hc]), &all), leaves: None, trust: Set::new() };
    assert_eq!(judge(&w, &Rules::fixed(), &v).shows(hc), rd.shows(hc));
}

/// A timed admin is no remaining admin (Tess): H grants B admin until 8 and leaves naming B; the
/// leave is not applied. Control: a timed edge counting as standing, the leave applies and A has
/// no admin from 8 on, though no write was marked.
#[test]
fn a_timed_admin_is_no_remaining_admin() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    w.set_until(gb, 8);
    let leave = w.edge(H, 3, &[], A, H, Gone, &[gb]);
    w.rely(leave, B);
    let rd = fixed(&w, &[]);
    assert!(!rd.applied.contains(&leave) && rd.role(H, A) == Admin);
    let rd = fixed_but(&w, &[], |x| x.last_admin = LastAdmin::NamedTimed);
    assert!(rd.applied.contains(&leave) && !rd.roles.iter().any(|(e, r)| e.1 == A && *r == Admin));
    // marked, it applies under the rule
    w.mark_adminless(leave);
    assert!(fixed(&w, &[]).applied.contains(&leave));
}

/// Giving the last standing admin an `until` is a lowering of it: H grants B admin, gives B an
/// `until` (relying on itself), then leaves naming B: not applied. Two admins leaving each
/// other: the earlier-stamped applies, the later is not.
#[test]
fn no_unmarked_schedule_leaves_a_thing_without_a_standing_admin() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    let timed = w.edge(H, 2, &[], A, B, Admin, &[gb]);
    w.set_until(timed, 20);
    let leave = w.edge(H, 3, &[], A, H, Gone, &[]);
    w.rely(leave, B);
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&timed) && !rd.applied.contains(&leave) && rd.role(H, A) == Admin);
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    let lb = w.edge(B, 3, &[], A, B, Gone, &[]);
    w.rely(lb, H);
    let lh = w.edge(H, 4, &[], A, H, Gone, &[gb]);
    w.rely(lh, B);
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&lb) && !rd.applied.contains(&lh) && rd.role(H, A) == Admin);
}

/// Giving the last standing admin an `until` is a lowering of it: H, A's only admin, gives itself
/// an `until` naming no other admin: not applied. Control: a timed admin counting as standing.
#[test]
fn the_last_standing_admin_takes_an_until_only_when_marked() {
    let mut w = account();
    let timed = w.edge(H, 2, &[], A, H, Admin, &[]);
    w.set_until(timed, 8);
    let rd = fixed(&w, &[]);
    assert!(!rd.applied.contains(&timed) && rd.role(H, A) == Admin);
    assert!(fixed_but(&w, &[], |x| x.last_admin = LastAdmin::NamedTimed).applied.contains(&timed));
    w.mark_adminless(timed);
    assert!(fixed(&w, &[]).applied.contains(&timed));
}

// ---- Nobody vouches for its own signer's commit (finding 10) ----

/// X, cut from A but still admin on T1 through A2, vouches through A2 for its own grant through
/// A, stamped before the removal and received by nobody: it counts for nothing. Control: a vouch
/// counting for its own signer's commit, the grant applies.
#[test]
fn a_removed_signer_vouches_for_nothing_of_its_own() {
    let (mut w, ..) = paired();
    w.edge(K, 1, &[], A2, X, Admin, &[]);
    w.edge(H, 1, &[A], T1, A2, Admin, &[]);
    let gz = w.edge(X, 2, &[A], T1, Z, Admin, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.vouch(X, 7, &[A2], T1, r, &[gz]);
    let rd = fixed(&w, &[r]);
    assert!(!rd.applied.contains(&gz) && rd.role(Z, T1) == Gone, "{rd:?}");
    let rd = fixed_but(&w, &[r], |x| x.no_own_vouch = false);
    assert!(rd.applied.contains(&gz) && rd.role(Z, T1) == Admin);
}

// ---- A re-granted writer writes again ----

/// X's write only N5 received: N5's addendum written as it applies the removal (N5 holding
/// nothing then) vouches for nothing; the one it writes after its new grant does.
#[test]
fn a_re_granted_writers_later_addendum_vouches() {
    let (mut w, ..) = paired();
    w.edge(X, 2, &[], A, N5, Admin, &[]);
    let xc = w.content(X, 3, &[A], T1);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.addendum(N5, 7, &[A], T1, r, &[xc]);
    w.edge(H, 8, &[], A, N5, Admin, &[]);
    assert!(!fixed(&w, &[r]).valid.contains(&xc));
    w.addendum(N5, 9, &[A], T1, r, &[xc]);
    assert!(fixed(&w, &[r]).valid.contains(&xc));
}

/// The collateral grantee re-granted, writing by the state-based rule: holding admin again in
/// the first walk and having received its own fallen grant by the removal, it vouches for that
/// grant (X's commit, not its own), which then applies at its own key: its writes from the gap
/// stand, role writes included, under either re-grant reading (notes/path-model-findings.md 13).
#[test]
fn a_re_granted_grantee_vouches_for_its_own_fallen_grant() {
    let (mut w, ..) = paired();
    let g5 = w.edge(X, 2, &[], A, N5, Admin, &[]);
    let week = w.content(N5, 3, &[A], T1);
    let gap = w.edge(N5, 4, &[A], T1, A2, Write, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.edge(H, 8, &[], A, N5, Admin, &[]);
    let rd = fixed_but(&w, &[r], |x| x.regrant = Regrant::FirstApplied);
    assert!(!rd.applied.contains(&g5) && !rd.valid.contains(&week) && !rd.applied.contains(&gap));
    w.vouch(N5, 9, &[], A, r, &[g5]);
    let rd = fixed_but(&w, &[r], |x| x.regrant = Regrant::FirstApplied);
    assert!(rd.applied.contains(&g5) && rd.valid.contains(&week) && rd.applied.contains(&gap));
}

// ---- Nothing is exempt (finding 15) ----

/// X backdates a grant of admin to a key it made up, Z, and Z a grant of admin to H (H is admin
/// already): Z's grant sets an edge of H's removal's path, so X's grant of Z is what "such a write's
/// own path rests on", put in question by nothing, and Z stays admin wherever H's removal is
/// trusted under the control exempting a removal's chain (`exempt_chain`, finding 15). Nothing is
/// exempt: X's grant of Z is an unlisted write through the removed edge.
#[test]
fn a_made_up_key_regranting_the_remover_holds_nothing() {
    let (mut w, ..) = paired();
    w.edge(X, 2, &[], A, Z, Admin, &[]);
    w.edge(Z, 3, &[], A, H, Admin, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let zc = w.content(Z, 8, &[A], T1);
    let rd = fixed(&w, &[r]);
    assert!(rd.role(Z, A) == Gone && !rd.valid.contains(&zc), "{rd:?}");
}

/// X backdates a grant of admin until 7 to H, the remover: it sets an edge of H's removal's path,
/// so the removal never puts it in question. H's edge is then timed, so the removal (naming no
/// other admin) is refused and, trusted, void: X keeps A and H loses it at 7 (finding 15, under
/// `exempt_chain`). Nothing is exempt: the timed grant falls like any unlisted write.
#[test]
fn a_backdated_timed_grant_to_the_remover_changes_nothing() {
    let (mut w, ..) = paired();
    let tg = w.edge(X, 2, &[], A, H, Admin, &[]);
    w.set_until(tg, 7);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let rd = fixed(&w, &[r]);
    assert!(rd.void.is_empty() && rd.role(X, A) == Gone && rd.role(H, A) == Admin, "{rd:?}");
}

// ---- A removal is judged in the world its list makes (notes/write-path-design.md §1) ----

/// Finding 15's two worlds: nothing is exempt, so the thief's grant of a made-up key and its
/// timed grant to the remover are unlisted writes through the removed edge, dropped like any.
/// Control: the grants the removal's path rests on, read from the held writes, exempt.
#[test]
fn nothing_through_the_removed_edge_is_exempt() {
    let (mut w, ..) = paired();
    let gz = w.edge(X, 2, &[], A, Z, Admin, &[]);
    let zh = w.edge(Z, 3, &[], A, H, Admin, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let zc = w.content(Z, 8, &[A], T1);
    let rd = fixed(&w, &[r]);
    assert!(rd.role(Z, A) == Gone && !rd.valid.contains(&zc) && !rd.shows(gz) && !rd.shows(zh) && rd.void.is_empty());
    // the plain walk reads the same: the removal applies, audits, and still applies
    let rd = fixed(&w, &[]);
    assert!(rd.role(Z, A) == Gone && rd.lowered.contains(&r) && rd.role(H, A) == Admin);
    assert!(fixed_but(&w, &[r], |x| x.exempt_chain = true).role(Z, A) == Admin);

    let (mut w, ..) = paired();
    let tg = w.edge(X, 2, &[], A, H, Admin, &[]);
    w.set_until(tg, 7);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let rd = fixed(&w, &[r]);
    assert!(rd.void.is_empty() && !rd.shows(tg) && rd.role(X, A) == Gone && rd.role(H, A) == Admin);
    assert!(fixed_but(&w, &[r], |x| x.exempt_chain = true).void.contains(&r));
    // untrusted, it is the ordinary dispute of a backdated write against the remover
    assert!(!fixed(&w, &[]).applied.contains(&r));
    assert_eq!(disputes(&w, &Rules::fixed(), &View::all(&w)), vec![r]);
}

/// Finding 4's world: X's removal of H lists nothing, its own grant included. Its drops made,
/// it does not apply, so it is void: nothing falls by it and no dispute is raised. Control: the
/// drops of a write that does not apply stay.
#[test]
fn a_removal_that_does_not_apply_once_its_drops_are_made_is_void() {
    let (w, gb, rx) = self_voiding();
    let rd = fixed(&w, &[]);
    assert!(!rd.applied.contains(&rx) && rd.stray.is_empty() && rd.dropped.is_empty());
    assert!(rd.applied.contains(&gb) && rd.role(H, A) == Admin && rd.role(B, A) == Admin);
    assert!(disputes(&w, &Rules::fixed(), &View::all(&w)).is_empty());
    assert!(fixed(&w, &[rx]).void.contains(&rx));
    let rd = fixed_but(&w, &[], |x| x.void_unapplied = false);
    assert!(!rd.stray.is_empty() && !rd.applied.contains(&gb));
}

/// A removal made under a grant a later removal drops is void with it: N5 (paired by X, the
/// pairing never received by H) removes B listing nothing; H removes X. N5's grant falls, its
/// removal of B no longer applies, and B's role writes stand. Control: B's role write stays
/// dropped by a removal that does not apply.
#[test]
fn a_removal_whose_author_falls_later_drops_nothing() {
    let (mut w, _, gb) = paired();
    w.edge(X, 2, &[], A, N5, Admin, &[]);
    let bg = w.edge(B, 3, &[A], T1, A2, Write, &[]);
    let out = w.edge(N5, 4, &[], A, B, Gone, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    for trust in [&[][..], &[r][..]] {
        let rd = fixed(&w, trust);
        assert!(!rd.applied.contains(&out) && rd.stray.is_empty() && rd.applied.is_superset(&Set::from([gb, bg])), "{rd:?}");
    }
    let rd = fixed_but(&w, &[], |x| x.void_unapplied = false);
    assert!(!rd.applied.contains(&out) && !rd.applied.contains(&bg) && rd.stray.contains(&bg));
}

/// Findings 7 and 12: a list keeping what unmakes its removal voids it, and nothing reads an
/// entry as absent: the remover leaves such a write out (it contests it). The thief's removal
/// of the remover; of the remover's granter M, listing nothing; and an honest removal of M
/// (listing M's grant of H), which stays made when listed and is undone when left out: so the
/// remover leaves out by effect, never by the edge lowered.
#[test]
fn a_list_keeping_what_unmakes_its_removal_voids_it() {
    let (mut w, gx, gb) = paired();
    let rx = w.edge(X, 5, &[], A, H, Gone, &[gx, gb]);
    let listed = w.edge(H, 6, &[], A, X, Gone, &[rx]);
    assert!(fixed(&w, &[listed]).void.contains(&listed));
    let (mut w, gx, gb) = paired();
    let rx = w.edge(X, 5, &[], A, H, Gone, &[gx, gb]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let rd = fixed(&w, &[r]);
    assert!(rd.void.is_empty() && !rd.shows(rx) && (rd.role(H, A), rd.role(X, A), rd.role(B, A)) == (Admin, Gone, Admin));
    // an admin's vouch naming it voids the removal: the accomplice that is a current admin
    w.vouch(B, 7, &[], A, r, &[rx]);
    assert!(fixed(&w, &[r]).void.contains(&r));

    for honest in [false, true] {
        let mut w = minted_by(M);
        let gh = w.edge(M, 0, &[], A, H, Admin, &[]);
        let gx = w.edge(M, 0, &[], A, X, Admin, &[]);
        let list = if honest { vec![gx, gh] } else { vec![gx] };
        let rm = w.edge(X, 3, &[], A, M, Gone, &list);
        let mut w2 = w.clone();
        let listed = w.edge(H, 6, &[], A, X, Gone, &[rm]);
        let rd = fixed(&w, &[listed]);
        assert_eq!(rd.void.contains(&listed), !honest);
        assert!(!honest || (rd.role(M, A) == Gone && rd.role(X, A) == Gone && rd.role(H, A) == Admin));
        let left = w2.edge(H, 6, &[], A, X, Gone, &[]);
        let rd = fixed(&w2, &[left]);
        assert!(rd.void.is_empty() && rd.role(H, A) == Admin && rd.role(X, A) == Gone && rd.role(M, A) == Admin);
    }
}

/// Why the remover keeps in the order received, not in key order. X removed N5 long ago (`out`,
/// received then). The thief, holding both keys, backdates a demotion of H by X before `out`
/// and a grant of admin to H by N5 between them. Kept in key order, the demotion comes first
/// and the removal applies with it (N5's grant repairs it), and then not with `out` (which
/// drops N5's grant): `out` is left out and N5 is back. Kept in the order received, `out` is
/// kept, the demotion left out, and N5 stays removed.
#[test]
fn a_remover_keeps_what_it_received_first() {
    let (mut w, gx, gb) = paired();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let down = w.edge(X, 2, &[], A, H, Write, &[gx, gb, g5]);
    let junk = w.edge(N5, 3, &[], A, H, Admin, &[]);
    let out = w.edge(X, 4, &[], A, N5, Gone, &[g5]);
    let world = |list: &[Id]| {
        let mut w = w.clone();
        let r = w.edge(H, 6, &[], A, X, Gone, list);
        (fixed(&w, &[r]), r)
    };
    let (rd, r) = world(&[down, out]);
    assert!(rd.void.contains(&r));
    let (rd, _) = world(&[down]);
    assert!(rd.void.is_empty() && rd.role(N5, A) == Admin && rd.shows(junk));
    let (rd, _) = world(&[out]);
    assert!(rd.void.is_empty() && rd.role(N5, A) == Gone && !rd.shows(junk) && !rd.shows(down) && rd.role(H, A) == Admin);
}

/// The hand worlds of the other findings read the same with nothing exempt: a removed node's
/// junk grant to the remover (README Vouches), a lowering the removed node made vouched for by
/// the node it lowered (2), a re-granted grantee vouching for its fallen grant (13), a
/// backdated leave (14).
#[test]
fn the_other_findings_read_the_same_with_nothing_exempt() {
    let (mut w, _, gb) = paired();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let out = w.edge(X, 2, &[], A, N5, Gone, &[g5]);
    let junk = w.edge(N5, 3, &[], A, H, Admin, &[]);
    let down = w.edge(X, 3, &[], A, B, Write, &[gb]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[out]);
    w.vouch(B, 7, &[], A, r, &[down]);
    let rd = fixed(&w, &[r]);
    assert!(rd.applied.is_superset(&Set::from([out, down])) && !rd.shows(junk) && rd.role(N5, A) == Gone && rd.role(B, A) == Write);

    let (mut w, ..) = paired();
    let g5 = w.edge(X, 2, &[], A, N5, Admin, &[]);
    let gap = w.edge(N5, 4, &[A], T1, A2, Write, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.edge(H, 8, &[], A, N5, Admin, &[]);
    assert!(!fixed(&w, &[r]).applied.contains(&gap));
    w.vouch(N5, 9, &[], A, r, &[g5]);
    assert!(fixed(&w, &[r]).applied.is_superset(&Set::from([g5, gap])));

    let (mut w, _, gb) = paired();
    let down = w.edge(X, 3, &[], A, B, Write, &[gb]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[down]);
    let leave = w.edge(X, 2, &[], A, X, Gone, &[]);
    w.rely(leave, H);
    let rd = fixed(&w, &[r]);
    assert!(!rd.applied.contains(&leave) && rd.applied.contains(&down) && rd.role(B, A) == Write);
}

// ---- Descent, self-removal by path end, `until` (brief 3) ----

/// X writes D1 (a dependent of T1) stating [A]: by descent its hops are (X, A), (A, T1),
/// (T1, D1). H's removal of X cuts it unless listed; a lowering of the descent edge (T1, D1)
/// audits the writes through it like any edge.
#[test]
fn a_write_by_descent_is_judged_along_the_record_edges() {
    let (mut w, ..) = paired();
    let listed = w.content(X, 3, &[A], D1);
    let unlisted = w.content(X, 4, &[A], D1);
    assert_eq!(w.hops(listed), &[(X, A), (A, T1), (T1, D1)]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[listed]);
    let rd = fixed(&w, &[r]);
    assert!(rd.valid.contains(&listed) && !rd.valid.contains(&unlisted));
    // the record edge T1 -> D1 lowered by an admin of T1 (explicitly, listing nothing): B's
    // write through it before falls, H's grant on D1 by another path stands
    let (mut w, ..) = paired();
    let bc = w.content(B, 3, &[A], D1);
    let g = w.edge(H, 3, &[A, T1], D1, A2, Write, &[]);
    let kc = w.content(K, 4, &[A2], D1);
    let low = w.edge(H, 5, &[A], D1, T1, Gone, &[]);
    w.mark_adminless(low);
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&low) && !rd.valid.contains(&bc));
    // H's grant states [A, T1] and so rests on (T1, D1) too: it falls with it, and K's write
    assert!(!rd.applied.contains(&g) && !rd.valid.contains(&kc));
}

/// A self-removal (a path ending at the holder) audits nothing: B leaves A, and the grant it
/// made stands though its leave lists nothing; H's explicit removal of B listing nothing drops
/// it. A2 leaving T1 by K's path [A2] keeps K's earlier write and ends its later one.
#[test]
fn a_self_removal_by_path_end_audits_nothing() {
    let (mut w, ..) = paired();
    let g5 = w.edge(B, 2, &[], A, N5, Admin, &[]);
    let leave = w.edge(B, 3, &[], A, B, Gone, &[]);
    w.rely(leave, H);
    assert!(w.leave(leave) && w.hops(leave).is_empty());
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&leave) && rd.applied.contains(&g5) && rd.role(B, A) == Gone);
    let (mut w, ..) = paired();
    let g5 = w.edge(B, 2, &[], A, N5, Admin, &[]);
    w.edge(H, 3, &[], A, B, Gone, &[]);
    assert!(!fixed(&w, &[]).applied.contains(&g5));
    let mut w = account();
    w.edge(H, 1, &[A], T1, A2, Write, &[]);
    let before = w.content(K, 2, &[A2], T1);
    let out = w.edge(K, 3, &[A2], T1, A2, Gone, &[]);
    let after = w.content(K, 4, &[A2], T1);
    assert!(w.leave(out) && w.hops(out) == [(K, A2)]);
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&out) && rd.valid.contains(&before) && !rd.valid.contains(&after));
}

/// A self-removal raises nothing: a path ending at the holder setting a higher value applies
/// nowhere.
#[test]
fn a_self_removal_raises_nothing() {
    let mut w = account();
    w.edge(H, 1, &[A], T1, A2, Write, &[]);
    let up = w.edge(K, 2, &[A2], T1, A2, Admin, &[]);
    assert!(w.leave(up) && !fixed(&w, &[]).applied.contains(&up));
}

/// The thief backdates its own leave before the removal: the removal still audits against the
/// edge as restored (admin), so X's backdated writes before the leave fall unless listed
/// (spec/permissions.md §5.1, Edge as restored).
#[test]
fn a_backdated_leave_shields_nothing_from_the_removal() {
    let (mut w, ..) = paired();
    let listed = w.content(X, 3, &[A], T1);
    let gz = w.edge(X, 4, &[], A, Z, Admin, &[]);
    let back = w.content(X, 4, &[A], T1);
    let leave = w.edge(X, 5, &[], A, X, Gone, &[]);
    w.rely(leave, H);
    let r = w.edge(H, 6, &[], A, X, Gone, &[listed]);
    // with the leave put in question (finding 14) it is dropped; without, it stands and R still
    // audits against the edge as restored
    for in_q in [true, false] {
        let rd = fixed_but(&w, &[r], |x| x.leave_in_question = in_q);
        assert!(rd.applied.contains(&leave) != in_q && rd.lowered.contains(&r));
        assert!(rd.valid.contains(&listed) && !rd.valid.contains(&back) && !rd.applied.contains(&gz) && rd.role(Z, A) == Gone);
    }
}

/// An `until` passing audits nothing; the next explicit write on that edge audits against the
/// edge as restored: B, admin until 5, grants N5 at 3; N5 stands past 5; H's removal of B at 7
/// listing nothing drops it.
#[test]
fn an_until_passing_audits_nothing_the_next_explicit_write_does() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    w.set_until(gb, 5);
    let g5 = w.edge(B, 3, &[], A, N5, Admin, &[]);
    let bc = w.content(B, 6, &[A], T1);
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&g5) && rd.role(N5, A) == Admin && !rd.valid.contains(&bc));
    w.edge(H, 7, &[], A, B, Gone, &[]);
    assert!(!fixed(&w, &[]).applied.contains(&g5));
}

/// The thief backdates its own leave before the role writes it made honestly (a demotion of B
/// and a grant to N5, both received by H and listed): a self-removal audits nothing and states
/// no hop, so no audit reaches it, and X held no admin at its later writes: they fall, and N5
/// with them (finding 14). Fix modelled: a lowering of h puts a self-removal of h in question
/// like a write through h; unlisted, the backdated leave is dropped.
#[test]
fn a_backdated_leave_undoes_nothing_the_removed_node_made() {
    let (mut w, _, gb) = paired();
    let down = w.edge(X, 3, &[], A, B, Write, &[gb]);
    let g5 = w.edge(X, 3, &[], A, N5, Admin, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[down, g5]);
    let leave = w.edge(X, 2, &[], A, X, Gone, &[]);
    w.rely(leave, H);
    let rd = fixed(&w, &[r]);
    assert!(!rd.applied.contains(&leave) && rd.applied.is_superset(&Set::from([down, g5])));
    assert_eq!((rd.role(B, A), rd.role(N5, A)), (Write, Admin));
    let rd = fixed_but(&w, &[r], |x| x.leave_in_question = false);
    assert!(rd.applied.contains(&leave) && !rd.applied.contains(&down) && rd.role(N5, A) == Gone);
}

// ---- The searches at small size ----

fn assert_holds(st: &Stats, what: &str) {
    for k in ["safety", "liveness", "alike", "removal kept", "removal", "own path", "admin", "stray"] {
        assert!(st.checked.get(k).is_some_and(|n| *n > 0), "{what}: no {k} check ran");
    }
    assert!(st.failures() == 0, "{what}: {:?}\n{:?}", st.fails, st.first);
}

#[test]
fn random_worlds_hold() {
    assert_holds(&random(400, &Rules::fixed()), "random");
}

/// Under the first round's reading the wanted behaviour fails where the findings say, and
/// safety holds.
#[test]
fn the_notes_rules_fail_liveness_and_alike_never_safety() {
    let st = random(400, &Rules::design());
    for k in ["liveness", "alike", "removal kept"] {
        assert!(st.fails.contains_key(k), "{k}: {:?}", st.fails);
    }
    for k in ["settles"] {
        assert!(!st.fails.contains_key(k), "{k}: {:?}", st.first.get(k));
    }
}

/// Each fix alone is needed: without it the search fails.
#[test]
fn each_fix_is_needed() {
    let f = Rules::fixed();
    let cases = [
        ("vouch", Rules { vouch: Vouch::Off, ..f }),
        ("leaves", Rules { evidence_leaves: false, ..f }),
        ("sticky", Rules { void_unapplied: false, ..f }),
        ("listed", Rules { stands: false, ..f }),
        ("exempt", Rules { exempt_chain: true, ..f }),
        ("timed", Rules { last_admin: LastAdmin::NamedTimed, ..f }),
        ("own vouch", Rules { no_own_vouch: false, ..f }),
        ("once", Rules { rewrite: false, ..f }),
        ("leave", Rules { leave_in_question: false, ..f }),
    ];
    for (name, rules) in cases {
        assert!(random(400, &rules).failures() > 0, "{name}");
    }
}

#[test]
fn small_family_sample_holds() {
    assert_holds(&family_run(&Rules::fixed(), 211), "family");
}

fn var(k: &str) -> Option<u64> {
    std::env::var(k).ok().filter(|v| !v.is_empty()).map(|v| v.parse::<u64>().unwrap_or_else(|_| panic!("{k}={v:?} is not a decimal u64")))
}

/// Random worlds `OSIS_ROLES_START` (default 0) on, `OSIS_ROLES_SEEDS` many (20,000), a thread
/// per core, each from its own index.
#[test]
#[ignore = "property"]
fn random_worlds_hold_large() {
    let start = var("OSIS_ROLES_START").unwrap_or(0);
    let n = var("OSIS_ROLES_SEEDS").unwrap_or(20_000);
    let st = crate::on_every_core(|th, threads, st: &mut Stats| {
        for i in (start + th as u64..start + n).step_by(threads) {
            check(&random_world(i, &Rules::fixed()), &Rules::fixed(), st);
        }
    });
    st.print("paths", &Rules::fixed());
    assert_holds(&st, &format!("OSIS_ROLES_START={start}"));
}

/// Every 53rd world of the small family (`-- 0 paths-exh` runs all of them by hand): a stride
/// coprime with every dimension's size (2, 3, 4, 28), so no dimension is fixed or tied to
/// another (an even stride keeps `h_t1` false in every world).
#[test]
#[ignore = "property"]
fn small_family_holds_large() {
    let st = family_run(&Rules::fixed(), 53);
    st.print("paths family", &Rules::fixed());
    assert_holds(&st, "family");
}


// ---- The void step (notes/write-path-design.md §1, A write that does not apply has no effect) ----

/// A small world of admins removing and granting each other on A (H its mint): `n` edge writes,
/// each by a random party, setting a random party's edge to admin or none at a random `ts`,
/// listing each earlier write with probability one half.
fn tiny(i: u64, n: usize) -> World {
    let mut rng = Rng::thread(0x701d, i as usize);
    let parties = [H, B, N5, Z, N6];
    let mut w = account();
    for _ in 0..n {
        let (s, h) = (parties[rng.below(5)], parties[rng.below(5)]);
        let ts = 1 + rng.below(n) as u32;
        let list: Vec<Id> = (0..w.commits.len()).filter(|_| rng.below(2) == 0).collect();
        let role = if rng.below(2) == 0 { Admin } else { Gone };
        if s != h {
            w.edge(s, ts, &[], A, h, role, &list);
        }
    }
    w
}

/// `w` with its commits pushed in the order `perm` (ids relabelled; every key in these worlds
/// differs in `ts` or signer, so the walk's order is unchanged), and the map old id -> new.
fn relabel(w: &World, perm: &[Id]) -> (World, BTreeMap<Id, Id>) {
    let mut out = World::new(&w.records);
    let mut map = BTreeMap::new();
    for (k, &i) in perm.iter().enumerate() {
        map.insert(i, k);
    }
    for &i in perm {
        let c = &w.commits[i];
        let kind = match &c.kind {
            Kind::Edge { holder, role, until, frontier, relies, adminless } => {
                let f = frontier.iter().map(|(t, l)| (*t, l.iter().map(|j| map[j]).collect())).collect();
                Kind::Edge { holder: *holder, role: *role, until: *until, frontier: f, relies: *relies, adminless: *adminless }
            }
            k => k.clone(),
        };
        out.push(c.signer, c.ts, &c.path, c.on, kind);
    }
    (out, map)
}

/// The reading of `w` is the reading of every relabelling of it, and every order of voiding
/// reaches it.
fn one_reading(w: &World) -> Reading {
    let rd = fixed(w, &[]);
    assert_eq!(void_orders(w, &Rules::fixed(), &View::all(w)).len(), 1);
    let n = w.commits.len();
    for rot in 1..n {
        let perm: Vec<Id> = (0..n).map(|k| (k + rot) % n).rev().collect();
        let (w2, map) = relabel(w, &perm);
        let r2 = fixed(&w2, &[]);
        assert_eq!(r2.applied, rd.applied.iter().map(|i| map[i]).collect::<Set>());
        assert_eq!(r2.dropped, rd.dropped.iter().map(|i| map[i]).collect::<Set>());
    }
    rd
}

/// Two lowerings, each un-applying the other through its drops: B and N5, both paired by H,
/// each remove H listing only their own grant, so each drops the other's. Two consistent worlds
/// exist (either removal applied, the other's author dropped); the walk applies the earlier by
/// key, in any input order, by any order of voiding, and voids nothing.
#[test]
fn two_lowerings_unapplying_each_other_settle_on_the_earlier() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let lb = w.edge(B, 3, &[], A, H, Gone, &[gb]);
    let l5 = w.edge(N5, 4, &[], A, H, Gone, &[g5]);
    let rd = one_reading(&w);
    assert!(rd.applied.contains(&lb) && !rd.applied.contains(&l5) && rd.dropped == Set::from([g5]) && rd.voided.is_empty());
    // the other consistent world: N5's removal applied once B's is not held
    let other = judge(&w, &Rules::fixed(), &View::all(&w).without(&[lb]));
    assert!(other.applied.contains(&l5) && other.dropped == Set::from([gb]));
}

/// No consistent world: B and N5 paired by H; H removes N5 (D); B removes H listing its own and
/// N5's grants, so it drops D; N5, an admin again, removes B, which drops B's removal. B's removal
/// applied makes N5's apply, which drops it; not applied, it would apply. The walk voids B's
/// removal (it made drops and does not apply), in any input order and by any order of voiding.
#[test]
fn lowerings_with_no_consistent_world_void_the_earliest() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let d = w.edge(H, 2, &[], A, N5, Gone, &[]);
    let lb = w.edge(B, 3, &[], A, H, Gone, &[gb, g5]);
    let l5 = w.edge(N5, 4, &[], A, B, Gone, &[]);
    let rd = one_reading(&w);
    assert_eq!(rd.voided, Set::from([lb]));
    assert!(rd.applied.contains(&d) && !rd.applied.contains(&l5) && rd.dropped.is_empty() && rd.stray.is_empty());
    assert_eq!((rd.role(H, A), rd.role(B, A), rd.role(N5, A)), (Admin, Admin, Gone));
}

/// Control: voiding every unapplied lowering that made drops at once, in place of the earliest.
/// H pairs B and N6; N6 grants B admin and removes H listing that grant (so it drops H's grant of
/// B); B removes N6, dropping both. Earliest first: N6's removal of H is void, B (by H's grant)
/// still removes N6. All at once, B's removal is void too and N6 stays; voiding B's removal
/// first reaches that reading too, so which unapplied lowering is voided first matters.
#[test]
fn voiding_all_at_once_differs_from_the_earliest_first() {
    let mut w = account();
    let gb = w.edge(H, 3, &[], A, B, Admin, &[]);
    let g6 = w.edge(H, 3, &[], A, N6, Admin, &[]);
    let again = w.edge(N6, 5, &[], A, B, Admin, &[g6]);
    let l6 = w.edge(N6, 5, &[], A, H, Gone, &[g6, again]);
    let lb = w.edge(B, 6, &[], A, N6, Gone, &[]);
    let rd = fixed(&w, &[]);
    assert_eq!(void_orders(&w, &Rules::fixed(), &View::all(&w)).len(), 2);
    assert!(rd.voided == Set::from([l6]) && rd.applied.is_superset(&Set::from([gb, g6, lb])) && rd.role(N6, A) == Gone);
    let once = fixed_but(&w, &[], |x| x.void_order = VoidOrder::AllAtOnce);
    assert!(once.voided == Set::from([l6, lb]) && once.role(N6, A) == Admin);
}

/// A void write has an effect (notes/path-model-findings.md, 16): H pairs B and N5; B pairs Z;
/// Z removes H listing B's grant (so it drops H's pairing of N5), then removes B listing nothing,
/// which drops B's pairing of Z, so neither of Z's removals applies. Earliest by key first, Z's
/// removal of H is voided before the removal of B that took its author's grant: both are void.
/// Without the removal of B held, the removal of H applies: the void write changed the reading.
#[test]
#[ignore = "notes/path-model-findings.md 16: voiding the earliest first lets a void write undo an earlier lowering"]
fn repro_a_void_write_has_no_effect() {
    let (w, s) = void_with_effect();
    let rd = fixed(&w, &[]);
    assert!(rd.voided.contains(&s));
    assert_eq!(rd.applied, judge(&w, &Rules::fixed(), &View::all(&w).without(&[s])).applied);
}

fn void_with_effect() -> (World, Id) {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    w.edge(H, 1, &[], A, N5, Admin, &[]);
    w.edge(B, 2, &[], A, Z, Admin, &[]);
    w.edge(Z, 3, &[], A, H, Gone, &[gb]);
    let s = w.edge(Z, 4, &[], A, B, Gone, &[]);
    (w, s)
}

/// The latest by key first answers this world (Z's removal of B is void, its removal of H
/// applies); it is no answer either: small worlds (`tiny`) where a void write still has an effect
/// under it exist (notes/path-model-findings.md 16).
#[test]
fn voiding_the_latest_first_answers_the_void_with_effect() {
    let (w, s) = void_with_effect();
    let rd = fixed_but(&w, &[], |x| x.void_order = VoidOrder::Latest);
    assert!(rd.voided == Set::from([s]) && rd.role(H, A) == Gone && rd.role(N5, A) == Gone);
    assert_eq!(rd.applied, judge(&w, &Rules::fixed(), &View::all(&w).without(&[s])).applied);
}

/// Small worlds of admins removing and granting each other (`tiny`) settle with no stray drop,
/// within one round per held lowering (the void set only grows); the drops of a void lowering kept
/// (control) are stray.
#[test]
fn small_worlds_settle_with_no_stray_drop() {
    let f = Rules::fixed();
    let (mut voided, mut sticky) = (0, 0);
    for n in [4usize, 8, 12] {
        for i in 0..400u64 {
            let w = tiny(i * 100 + n as u64, n);
            let rd = fixed(&w, &[]);
            let lowerings = (0..w.commits.len()).filter(|&k| w.lowers(k).is_some()).count();
            assert!(rd.stray.is_empty() && rd.rounds as usize <= 2 * lowerings, "n {n} i {i}: {rd:?}");
            voided += rd.voided.len();
            sticky += judge(&w, &Rules { void_unapplied: false, ..f }, &View::all(&w)).stray.len();
        }
    }
    assert!(voided > 0 && sticky > 0, "{voided} {sticky}");
}

/// What a party with admin can make every reader not trusting a removal of it walk: X grants k
/// keys of its own admin and each removes X listing nothing, so each drops its own grant and is
/// void. The walk is redone once per such removal (any order of voiding: only one has applied
/// when the restart finds it void), each redo walking the whole component again: rounds grow
/// with k and passes with k too, each over the component, so the work is O(k^2) for 2k writes
/// (notes/path-model-findings.md 17). A node trusting H's removal of X drops X's grants as seeds:
/// no round.
#[test]
fn void_rounds_grow_with_a_partys_writes() {
    let count = |k: usize| {
        let (mut w, ..) = paired();
        for z in 0..k {
            w.edge(X, 1, &[], A, 30 + z as Thing, Admin, &[]);
        }
        for z in 0..k {
            w.edge(30 + z as Thing, 2, &[], A, X, Gone, &[]);
        }
        let r = w.edge(H, 6, &[], A, X, Gone, &[]);
        let plain = fixed(&w, &[]);
        assert!(plain.stray.is_empty() && plain.voided.len() == k && plain.lowered.contains(&r));
        assert_eq!(fixed(&w, &[r]).rounds, 0);
        // each pass walks every held edge write
        (plain.rounds, plain.passes * w.commits.len() as u64)
    };
    let (small, large) = (count(10), count(100));
    // two walks per reading (the first, with no vouch counting, and the settled one); the work
    // grows with the square of the party's writes
    assert_eq!((small.0, large.0), (20, 200), "{small:?} {large:?}");
    assert!(large.1 >= 80 * small.1, "{small:?} {large:?}");
}
