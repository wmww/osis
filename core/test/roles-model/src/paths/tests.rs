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
    for k in ["safety", "liveness", "alike", "removal kept", "removal", "own path", "admin", "stray", "untrusted", "dispute"] {
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
        ("once", Rules { rewrite: false, ..f }),
        ("leave", Rules { leave_in_question: false, ..f }),
    ];
    for (name, rules) in cases {
        assert!(random(100, &rules).failures() > 0, "{name}");
    }
}

#[test]
fn small_family_sample_holds() {
    assert_holds(&family_run(&Rules::fixed(), 1009), "family");
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

/// Every 157th world of the small family (`-- 0 paths-exh` runs all of them by hand): a stride
/// coprime with every dimension's size (2, 4, 5, 40), so no dimension is fixed or tied to
/// another (an even stride keeps `h_t1` false in every world).
#[test]
#[ignore = "property"]
fn small_family_holds_large() {
    let st = family_run(&Rules::fixed(), 157);
    st.print("paths family", &Rules::fixed());
    assert_holds(&st, "family");
}


// ---- The void step (notes/write-path-design.md §1, A write that does not apply has no effect) ----

/// The reading of `w` is the reading of every relabelling of it keeping the walk's order.
fn one_reading(w: &World) -> Reading {
    let rd = fixed(w, &[]);
    let v = View::all(w);
    assert!(one_reading_relabelled(w, &Rules::fixed(), &v, &rd));
    let n = w.commits.len();
    for rot in 1..n {
        let perm: Vec<Id> = (0..n).map(|k| (k + rot) % n).rev().collect();
        let (w2, map) = rebuild(w, &perm);
        let r2 = fixed(&w2, &[]);
        assert_eq!(r2.applied, rd.applied.iter().map(|i| map[i]).collect::<Set>());
        assert_eq!(r2.dropped, rd.dropped.iter().map(|i| map[i]).collect::<Set>());
    }
    rd
}

/// Two lowerings, each un-applying the other through its drops: B and N5, both paired by H,
/// each remove H listing only their own grant, so each drops the other's. Two consistent worlds
/// exist (either removal applied, the other's author dropped); the walk applies the earlier by
/// key, in any input order, and voids nothing: the later one is judged once the earlier is
/// settled, and its author holds nothing there.
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

/// A lowering that drops the earlier lowering its author's standing rests on is void: B and N5
/// paired by H; H removes N5 (D); B removes H listing its own and N5's grants, so it drops D and
/// N5 is an admin again; N5 removes B, which drops B's removal, so D stands and N5 holds nothing.
/// No reading applies N5's removal; with it void, B's removal applies (as where N5's is not
/// held). Control: the latest first voids B's removal, and N5's, which does not apply, undid it.
#[test]
fn a_lowering_dropping_what_its_author_rests_on_is_void() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let d = w.edge(H, 2, &[], A, N5, Gone, &[]);
    let lb = w.edge(B, 3, &[], A, H, Gone, &[gb, g5]);
    let l5 = w.edge(N5, 4, &[], A, B, Gone, &[]);
    let rd = one_reading(&w);
    assert_eq!(rd.voided, Set::from([l5]));
    assert!(rd.applied.contains(&lb) && rd.dropped == Set::from([d]) && rd.stray.is_empty());
    assert_eq!((rd.role(H, A), rd.role(B, A), rd.role(N5, A)), (Gone, Admin, Admin));
    assert!(no_effect(&w, &Rules::fixed(), &View::all(&w), &rd, l5));
    let latest = fixed_but(&w, &[], |x| x.void_order = VoidOrder::Latest);
    assert!(latest.voided == Set::from([lb]) && latest.role(H, A) == Admin);
    assert!(judge(&w, &Rules::fixed(), &View::all(&w).without(&[l5])).applied.contains(&lb));
    assert_eq!(fixed_but(&w, &[], |x| x.void_order = VoidOrder::Consistent).voided, Set::from([l5]));
}

/// A void write has no effect (notes/path-model-findings.md 16): the reading is the reading with
/// it not held. H pairs B and N5; B pairs Z; Z removes H listing B's grant (so it drops H's
/// pairing of N5), then removes B listing nothing, which drops B's pairing of Z, so neither of
/// Z's removals applies. In key order the removal of H applies, and the removal of B, judged
/// with it settled, is void: as where the removal of B is not held. Controls: the earliest first
/// voids the removal of H before the removal of B that took its author's grant, so both are
/// void and the void removal of B undid the removal of H; all at once the same.
#[test]
fn a_void_write_has_no_effect() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    w.edge(H, 1, &[], A, N5, Admin, &[]);
    w.edge(B, 2, &[], A, Z, Admin, &[]);
    let zh = w.edge(Z, 3, &[], A, H, Gone, &[gb]);
    let zb = w.edge(Z, 4, &[], A, B, Gone, &[]);
    let without = judge(&w, &Rules::fixed(), &View::all(&w).without(&[zb]));
    let rd = one_reading(&w);
    assert!(rd.voided == Set::from([zb]) && rd.applied == without.applied && rd.role(H, A) == Gone && rd.role(N5, A) == Gone);
    for o in [VoidOrder::Earliest, VoidOrder::AllAtOnce] {
        let c = fixed_but(&w, &[], |x| x.void_order = o);
        assert!(c.voided == Set::from([zh, zb]) && c.role(H, A) == Admin, "{o:?}");
        assert!(!no_effect(&w, &Rules { void_order: o, ..Rules::fixed() }, &View::all(&w), &c, zb), "{o:?}");
    }
}

/// A later lowering overrules an earlier one it drops: H pairs B and N6; N6 grants B admin and
/// removes H listing that grant (so it drops H's grant of B); B removes N6 listing nothing,
/// which drops N6's grant of B and N6's removal of H, so H's grant of B stands again. In key order
/// N6's removal applies; B's, judged once it is settled, applies in the world its drops make (N6's
/// removal of H overruled, H's grant of B back): H and B stay, N6 is removed, as where N6's
/// removal is not held. No void set is consistent: each removal, judged with the other held,
/// applies by voiding it. Controls: the latest first voids B's removal and N6 keeps A; the
/// earliest first voids N6's removal and B (by H's grant) removes N6; all at once, both are void.
#[test]
fn a_later_lowering_overrules_an_earlier_one_it_drops() {
    let mut w = account();
    let gb = w.edge(H, 3, &[], A, B, Admin, &[]);
    let g6 = w.edge(H, 3, &[], A, N6, Admin, &[]);
    let again = w.edge(N6, 5, &[], A, B, Admin, &[g6]);
    let l6 = w.edge(N6, 5, &[], A, H, Gone, &[g6, again]);
    let lb = w.edge(B, 6, &[], A, N6, Gone, &[]);
    assert_eq!(void_orders(&w, &Rules::fixed(), &View::all(&w)).len(), 2);
    let rd = one_reading(&w);
    assert!(rd.voided == Set::from([l6]) && rd.applied.contains(&lb) && rd.role(H, A) == Admin && rd.role(N6, A) == Gone && rd.role(B, A) == Admin);
    assert_eq!(rd.applied, judge(&w, &Rules::fixed(), &View::all(&w).without(&[l6])).applied);
    assert!(fixed_but(&w, &[], |x| x.void_order = VoidOrder::Consistent).inconsistent);
    let latest = fixed_but(&w, &[], |x| x.void_order = VoidOrder::Latest);
    assert!(latest.voided == Set::from([lb]) && latest.applied.contains(&l6) && latest.role(N6, A) == Admin && latest.role(H, A) == Gone);
    let earliest = fixed_but(&w, &[], |x| x.void_order = VoidOrder::Earliest);
    assert!(earliest.voided == Set::from([l6]) && earliest.applied.is_superset(&Set::from([gb, g6, lb])) && earliest.role(N6, A) == Gone);
    let once = fixed_but(&w, &[], |x| x.void_order = VoidOrder::AllAtOnce);
    assert!(once.voided == Set::from([l6, lb]) && once.role(N6, A) == Admin && once.role(H, A) == Admin);
}

/// Finding 16's mirror: H grants B admin at 2 and again at 10; B removes H at 9 listing neither
/// (it drops the first grant, its own standing: void), and at 10 listing the first (it drops only
/// the second). Without the removal at 9 held, the removal at 10 applies. In key order the
/// removal at 9 is void before the one at 10 is judged, and that one applies. Control: the latest
/// first, the walk where the removal at 9 dropped the first grant leaves both unapplied, the one
/// at 10 is voided first, then the one at 9: the void write took the later removal with it.
#[test]
fn an_earlier_void_write_has_no_effect() {
    let mut w = account();
    let g1 = w.edge(H, 2, &[], A, B, Admin, &[]);
    w.edge(H, 10, &[], A, B, Admin, &[]);
    let early = w.edge(B, 9, &[], A, H, Gone, &[]);
    let late = w.edge(B, 10, &[], A, H, Gone, &[g1]);
    let without = judge(&w, &Rules::fixed(), &View::all(&w).without(&[early]));
    assert!(without.applied.contains(&late) && without.role(H, A) == Gone);
    let rd = one_reading(&w);
    assert_eq!(rd.voided, Set::from([early]), "{rd:?}");
    assert_eq!(rd.applied, without.applied);
    let latest = fixed_but(&w, &[], |x| x.void_order = VoidOrder::Latest);
    assert!(latest.voided == Set::from([early, late]) && latest.role(H, A) == Admin);
    assert!(!no_effect(&w, &Rules { void_order: VoidOrder::Latest, ..Rules::fixed() }, &View::all(&w), &latest, early));
}

/// The first-walk reading (`VoidOrder::Stratified`: no lowering drops in a first walk, those not
/// applied there void, the rest drop) misses a removal whose own drops take its author's
/// standing: N6, paired by H, removes H listing nothing. It applies in the first walk; in the
/// second it drops H's grant of N6 and then does not apply, so the drop is stray.
#[test]
fn the_first_walk_misses_a_removal_dropping_its_own_standing() {
    let mut w = account();
    let g6 = w.edge(H, 1, &[], A, N6, Admin, &[]);
    let r = w.edge(N6, 3, &[], A, H, Gone, &[]);
    let st = fixed_but(&w, &[], |x| x.void_order = VoidOrder::Stratified);
    assert!(st.stray == Set::from([g6]) && !st.applied.contains(&r));
    let rd = fixed(&w, &[]);
    assert!(rd.voided == Set::from([r]) && rd.applied.contains(&g6) && rd.stray.is_empty());
}

/// Key order re-resolves the earlier overrules at every later lowering (tiny world 830267,
/// one of 3 in 1,000,000 failing `void`): H pairs B at 1, N5 and N6 at 3; N5 grants N6 admin
/// at 3; at 4 B removes N5 (dropping that grant) and N6 removes H (dropping H's grants of B and
/// N6). N6's removal is judged applying, B's overruled. N6's removal of B at 8 drops nothing,
/// yet its judgement voids the latest of the two (N6's removal of H) and B's too: H keeps A.
/// Without B's removal held, N6's removal of H applies.
#[test]
#[ignore = "notes/path-model-findings.md: key order re-resolves earlier overrules, so a void write has an effect"]
fn repro_a_void_write_has_no_effect_in_key_order() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    let g5 = w.edge(H, 3, &[], A, N5, Admin, &[]);
    let g6 = w.edge(H, 3, &[], A, N6, Admin, &[]);
    let n6 = w.edge(N5, 3, &[], A, N6, Admin, &[gb, g5]);
    w.edge(B, 4, &[], A, N5, Gone, &[g6, gb]);
    w.edge(N6, 4, &[], A, H, Gone, &[g5, n6]);
    w.edge(N6, 8, &[], A, B, Gone, &[]);
    let rd = fixed(&w, &[]);
    for &x in &rd.voided {
        assert!(no_effect(&w, &Rules::fixed(), &View::all(&w), &rd, x), "void {x} has an effect: {rd:?}");
    }
}

/// The thief's lowering stamped just after the honest removal, aimed at what the removal rests
/// on (M's grant of H), by X or by a made-up key X granted backdated, overrules nothing: its
/// author holds nothing at its key in the walk where the removal applies. Backdated before the
/// removal it applies only where the removal is not trusted, shown as a dispute.
#[test]
fn a_thiefs_lowering_after_the_removal_overrules_nothing() {
    for by_z in [false, true] {
        let mut w = minted_by(M);
        let gh = w.edge(M, 1, &[], A, H, Admin, &[]);
        let gx = w.edge(M, 1, &[], A, X, Admin, &[]);
        let by = if by_z { w.edge(X, 4, &[], A, Z, Admin, &[gx]); Z } else { X };
        let r = w.edge(H, 6, &[], A, X, Gone, &[]);
        w.edge(by, 7, &[], A, M, Gone, &[gx]);
        w.edge(by, 7, &[], A, H, Gone, &[gx, gh]);
        for t in [&[][..], &[r]] {
            let rd = fixed(&w, t);
            assert!(rd.applied.contains(&r) && rd.voided.is_empty() && (rd.role(H, A), rd.role(X, A), rd.role(Z, A)) == (Admin, Gone, Gone), "{by_z} {t:?}");
        }
    }
    let mut w = minted_by(M);
    w.edge(M, 1, &[], A, H, Admin, &[]);
    let gx = w.edge(M, 1, &[], A, X, Admin, &[]);
    w.edge(X, 4, &[], A, M, Gone, &[gx]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    assert_eq!(fixed(&w, &[]).role(H, A), Gone);
    assert_eq!(disputes(&w, &Rules::fixed(), &View::all(&w)), vec![r]);
    let rd = fixed(&w, &[r]);
    assert!((rd.role(H, A), rd.role(X, A), rd.role(M, A)) == (Admin, Gone, Admin) && rd.void.is_empty());
}

/// Small worlds of admins granting and removing each other (`tiny`; README.md, Paths, for the
/// search): no stray drop, every void write without effect, one reading under a relabelling.
/// The drops of a void lowering kept (control) are stray.
#[test]
fn small_worlds_hold() {
    let st = tiny_run(3000, &Rules::fixed());
    assert!(st.failures() == 0 && st.checked["void"] > 0, "{:?} {:?}", st.fails, st.first);
    let sticky = tiny_run(300, &Rules { void_unapplied: false, ..Rules::fixed() });
    assert!(sticky.fails.contains_key("stray"));
}

/// What a party with admin can make a reader walk (notes/path-model-findings.md 17): X grants k
/// keys of its own admin and each removes X listing nothing, so each drops its own grant and is
/// void; H removes X. Per void order, at a node trusting nothing and at one trusting H's removal:
/// walks redone, passes and edge-class commits visited. Trusting the removal, X's grants are
/// seeds and no removal of a key audits. Trusting nothing, every order walks once per void
/// removal over the component: work O(k^2) for 2k writes.
fn void_cost(order: VoidOrder, k: usize) -> ((u32, u64, u64), (u32, u64, u64)) {
    let (mut w, ..) = paired();
    for z in 0..k {
        w.edge(X, 1, &[], A, 30 + z as Thing, Admin, &[]);
    }
    for z in 0..k {
        w.edge(30 + z as Thing, 2, &[], A, X, Gone, &[]);
    }
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let rules = Rules { void_order: order, ..Rules::fixed() };
    let plain = judge(&w, &rules, &View::all(&w));
    if order != VoidOrder::Stratified {
        assert!(plain.stray.is_empty() && plain.voided.len() == k && plain.lowered.contains(&r), "{order:?}");
    }
    let t = judge(&w, &rules, &View::all(&w).trusting(&[r]));
    assert!(t.applied.contains(&r) && (t.voided.is_empty() || order == VoidOrder::Stratified));
    ((plain.rounds, plain.passes, plain.walked), (t.rounds, t.passes, t.walked))
}

#[test]
fn void_rounds_grow_with_a_partys_writes() {
    for o in [VoidOrder::KeyOrder, VoidOrder::Latest, VoidOrder::Stratified, VoidOrder::Consistent] {
        let (small, large) = (void_cost(o, 10), void_cost(o, 100));
        println!("{o:?}: k 10 plain {:?} trusting {:?}; k 100 plain {:?} trusting {:?}", small.0, small.1, large.0, large.1);
        // trusting the removal: work linear in k (key order and the latest first: no round)
        assert!(large.1 .2 <= 12 * small.1 .2, "{o:?}");
        if matches!(o, VoidOrder::KeyOrder | VoidOrder::Latest) {
            assert!(small.1 .0 == 0 && large.1 .0 == 0, "{o:?}");
            // trusting nothing: a walk per void removal (two vouch walks), commits visited k^2
            assert!(small.0 .0 == 20 && large.0 .0 == 200 && large.0 .2 >= 50 * small.0 .2, "{o:?} {small:?} {large:?}");
        }
    }
}

/// A node trusting nothing: X backdates a grant
/// of admin until 7 to H, then removes H at 7, listing its own and B's grants. In the plain walk H's edge is timed at its removal
/// of X, so the removal (naming no standing admin) is refused, and X's removal of H applies: the
/// node is shown H's removal as a dispute, never a silent loss, and trusting it gives the
/// members' reading.
#[test]
fn a_node_trusting_nothing_is_shown_the_removal_as_a_dispute() {
    let (mut w, gx, gb) = paired();
    let tg = w.edge(X, 4, &[], A, H, Admin, &[]);
    w.set_until(tg, 7);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let rx = w.edge(X, 7, &[], A, H, Gone, &[gx, gb]);
    let plain = fixed(&w, &[]);
    assert!(!plain.applied.contains(&r) && plain.applied.contains(&rx) && plain.stray.is_empty());
    assert_eq!(disputes(&w, &Rules::fixed(), &View::all(&w)), vec![r]);
    let rd = fixed(&w, &[r]);
    assert!(rd.void.is_empty() && !rd.shows(tg) && !rd.shows(rx) && rd.role(H, A) == Admin && rd.role(X, A) == Gone);
}

/// Two readings of a lowering's drops (notes/path-model-findings.md 18): the audit puts in
/// question the applied writes before it, a trusted write's seeds the held ones. X, stolen,
/// backdates its own leave to 1 and removes H at 5 (honestly stamped, listing every grant); H
/// removes X at 6. Over the applied writes, H's removal drops the leave, X's removal of H then
/// applies, so H's removal is void and the leave stands; over the held writes it drops the leave
/// and X's removal of H too, and applies. Same roles here (X left either way); where X had made
/// an honest grant after 1, the first reading loses it. Trusting H's removal, both read alike.
#[test]
fn the_audit_over_the_held_writes_differs_only_where_nothing_is_trusted() {
    let (mut w, gx, gb) = paired();
    let rx = w.edge(X, 5, &[], A, H, Gone, &[gx, gb]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let leave = w.edge(X, 1, &[], A, X, Gone, &[]);
    w.rely(leave, H);
    let applied = fixed(&w, &[]);
    assert!(applied.voided.contains(&r) && applied.applied.contains(&leave) && !applied.applied.contains(&rx));
    let held = fixed_but(&w, &[], |x| x.audit_held = true);
    assert!(held.applied.contains(&r) && held.dropped.is_superset(&Set::from([leave, rx])));
    assert_eq!((applied.role(H, A), applied.role(X, A)), (held.role(H, A), held.role(X, A)));
    assert_eq!(fixed(&w, &[r]).applied, fixed_but(&w, &[r], |x| x.audit_held = true).applied);
}

/// Finding 16 against safety: X removed N5 before the theft (`out`, listing H's pairing of it).
/// The thief, heard before H's removal, removes H listing nothing: that drops H's grant of X, so
/// it is void, and H's walk applies the removal with it named (the writers' rule keeps it). Later
/// it backdates, with N5's key, a grant of admin to H before `out`. `out` drops that grant; the
/// removal of H drops X's grant, so `out` is unapplied: both are unapplied droppers.
fn n5_back() -> (World, Id, Id) {
    let (mut w, gx, _) = paired();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let out = w.edge(X, 3, &[], A, N5, Gone, &[g5]);
    let x5 = w.edge(X, 5, &[], A, H, Gone, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[out, x5]);
    // H's list names both: its own walk applies the removal with them
    assert!(fixed(&w, &[r]).applied.contains(&r) && fixed(&w, &[r]).role(N5, A) == Gone);
    let _ = gx;
    w.edge(N5, 2, &[], A, H, Admin, &[]);
    (w, out, r)
}

/// In key order `out` applies and N5 stays removed. Control: the earliest first voids `out`
/// and N5 is back wherever the removal is trusted.
#[test]
fn a_party_removed_before_the_theft_stays_removed() {
    let (w, out, r) = n5_back();
    let rd = fixed(&w, &[r]);
    assert!(rd.applied.contains(&out) && rd.role(N5, A) == Gone && rd.void.is_empty());
    let rd = fixed_but(&w, &[r], |x| x.void_order = VoidOrder::Earliest);
    assert!(rd.voided.contains(&out) && rd.role(N5, A) == Admin);
}


/// The writers' leaving out in the story: N5,
/// removed by X before the theft, its key the thief's; the thief, heard before the removal, grants
/// H admin until just after it (X) and, as N5, admin before X's removal of N5. In the order
/// received, H keeps X's removal of N5 and leaves the timed grant out: N5 stays removed. Control:
/// in key order the timed grant comes first, N5's grant repairs it, X's removal of N5 is then the
/// write H's removal does not apply with, and N5 is back.
#[test]
fn the_remover_keeps_what_it_received_first_in_the_story() {
    let s = Setup { n5: 3, ..Setup::default() };
    let moves = [Move { kind: 24, ts: 2, made: 5 }, Move { kind: 30, ts: 2, made: 5 }];
    let n5 = |rules: Rules| {
        let m = Sim::build(&s, &rules, &moves, &mut Rng(0));
        let mut st = Stats::default();
        check(&m, &rules, &mut st);
        (judge(&m.w, &rules, &m.view(H, &rules)).role(N5, A), st.failures())
    };
    assert_eq!(n5(Rules::fixed()), (Gone, 0));
    let (role, fails) = n5(Rules { key_order: true, ..Rules::fixed() });
    assert!(role == Admin && fails > 0);
}

/// Equivocation: X signs a twin of its removal of
/// N5 at its `ts`, ordered first, listing H's pairing of N5 and not N5's grant to B. Received by H
/// before the removal it is a write H's removal applies with, so H keeps it: the twin applies, the
/// first is a no-op and N5's grant to B falls (as any lowering X made that H heard). Received
/// after, the removal drops it at every node, trusting or not, and the first stays made, its list
/// with it.
#[test]
fn an_equivocating_twin_of_an_earlier_removal() {
    let s = Setup { n5: 3, ..Setup::default() };
    for (made, kept) in [(5, true), (9, false)] {
        let m = Sim::build(&s, &Rules::fixed(), &[Move { kind: 35, ts: 3, made }], &mut Rng(0));
        let twin = *m.thief.keys().next().unwrap();
        for n in [H, B, N6] {
            let rd = judge(&m.w, &Rules::fixed(), &m.view(n, &Rules::fixed()));
            assert_eq!(rd.applied.contains(&twin), kept, "node {n}");
            assert_eq!(rd.applied.contains(&m.gb5.unwrap()), !kept, "node {n}");
            assert!(rd.applied.contains(&m.out5.unwrap()) && rd.role(N5, A) == Gone);
        }
        let mut st = Stats::default();
        check(&m, &Rules::fixed(), &mut st);
        assert_eq!(st.failures(), 0);
    }
}

/// Vouches that void (notes/path-model-findings.md 20): N5, paired by X and listed by H's removal,
/// is the thief's: it vouches for X's removal of H, which H's removal left out. Trusted, the
/// removal is void by that vouch (the accomplice: a party holding admin after it), and without
/// the vouch it stands. Z or X vouching the same counts for nothing. Once the removal is void the
/// walk applies X's removal of H, so the vouch's removal does not apply in the first walk and the
/// vouch counts no more: the final reading holds no counting vouch, and what voided the removal
/// is not in the reading that shows it void.
#[test]
fn a_current_admins_vouch_voids_the_removal_and_leaves_no_trace() {
    let (mut w, gx, gb) = paired();
    let g5 = w.edge(X, 2, &[], A, N5, Admin, &[]);
    let rx = w.edge(X, 5, &[], A, H, Gone, &[gx, gb]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[g5]);
    assert!(fixed(&w, &[r]).void.is_empty());
    for by in [Z, X] {
        let mut w = w.clone();
        w.vouch(by, 7, &[], A, r, &[rx]);
        assert!(fixed(&w, &[r]).void.is_empty());
    }
    let v5 = w.vouch(N5, 7, &[], A, r, &[rx]);
    let rd = fixed(&w, &[r]);
    assert!(rd.void.contains(&r) && rd.counting.is_empty() && rd.role(X, A) == Admin && rd.role(H, A) == Gone);
    assert!(judge(&w, &Rules::fixed(), &View::all(&w).trusting(&[r]).without(&[v5])).void.is_empty());
}

/// A removal stating more than one hop: B removes
/// A2 from T1 stating [A], so it rests on (B, A) and (A, T1). X, admin on A2 (A2 admin on T1),
/// backdates through A2 a removal of A from T1, an edge above B's own: in the plain walk B's
/// removal finds no path and is a dispute shown; trusted, its seeds drop X's write (it rests on
/// the edge B lowers) and it applies. X making A leave T1 through A (a self-removal, marked) is
/// dropped by H's removal of X the same way. X's write through A2 after B's removal shows nowhere.
#[test]
fn a_removal_of_two_hops_holds_against_a_lowering_above_its_signer() {
    let (mut w, ..) = paired();
    w.edge(K, 1, &[], A2, X, Admin, &[]);
    let gs = w.edge(B, 2, &[A], T1, A2, Admin, &[]);
    // listing B's grant to A2, its own authority (else it drops it and is void)
    let xa = w.edge(X, 5, &[A2], T1, A, Gone, &[gs]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let r3 = w.edge(B, 6, &[A], T1, A2, Gone, &[]);
    let late = w.content(X, 7, &[A2], T1);
    let plain = fixed(&w, &[]);
    assert!(!plain.applied.contains(&r3) && plain.applied.contains(&xa), "{plain:?}");
    assert!(disputes(&w, &Rules::fixed(), &View::all(&w)).contains(&r3));
    let rd = fixed(&w, &[r, r3]);
    assert!(rd.void.is_empty() && rd.applied.contains(&r3) && !rd.shows(xa) && !rd.shows(late));
    assert_eq!((rd.role(A, T1), rd.role(A2, T1)), (Admin, Gone));
    let mut w2 = w.clone();
    let leave = w2.edge(X, 5, &[A], T1, A, Gone, &[]);
    w2.mark_adminless(leave);
    let rd = fixed(&w2, &[r, r3]);
    assert!(rd.void.is_empty() && !rd.shows(leave) && rd.applied.contains(&r3) && rd.role(A, T1) == Admin);
}

/// Finding 21: a dispute whose own write is a no-op where trusted. X, admin on A2 (A2 admin on
/// T1), removed A2 from T1 through A before the theft (`xr`, B vouches for it); the thief
/// backdates through A2 a removal of A from T1 (`xa`). A node trusting nothing: H's removal of X
/// drops `xr` (B's vouch does not count there, A being off T1), so `xa` applies and B's removal
/// of A2 finds no path. Trusted, B's removal drops `xa` by its seeds, the vouch counts, `xr`
/// stands, and B's removal is a no-op (A2 is off T1 already): read as spec/permissions.md §5.1
/// words it (the trusted write must lower its edge) it raises no dispute, and the node reads A
/// off T1 silently. As a write that applies once trusted, it is shown.
#[test]
fn a_dispute_whose_write_is_a_no_op_where_trusted_is_shown() {
    let (mut w, ..) = paired();
    w.edge(K, 1, &[], A2, X, Admin, &[]);
    let gs = w.edge(B, 2, &[A], T1, A2, Admin, &[]);
    let xr = w.edge(X, 3, &[A], T1, A2, Gone, &[]);
    let xa = w.edge(X, 3, &[A2], T1, A, Gone, &[gs]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let r3 = w.edge(B, 6, &[A], T1, A2, Gone, &[]);
    w.vouch(B, 7, &[A], T1, r, &[xr]);
    let plain = fixed(&w, &[]);
    assert!(plain.applied.contains(&xa) && !plain.applied.contains(&r3) && plain.role(A, T1) == Gone);
    let t = fixed(&w, &[r3]);
    assert!(t.applied.contains(&r3) && !t.lowered.contains(&r3) && t.applied.contains(&xr) && t.role(A, T1) == Admin);
    assert_eq!(disputes(&w, &Rules::fixed(), &View::all(&w)), vec![r3]);
}

/// Self-removal and time. X's backdated leave
/// carrying an `until` (admin until 2), and X setting its own edge to write until after the
/// story, each stamped before role writes X made honestly that H lists: a lowering of (X, A) puts
/// each in question like a write through it, so H's removal drops them and X's writes stand.
/// Control: a self-removal never put in question, X's writes fall.
#[test]
fn a_timed_self_removal_is_put_in_question_like_a_leave() {
    for (role, until) in [(Admin, 2), (Write, 20)] {
        let (mut w, _, gb) = paired();
        let down = w.edge(X, 3, &[], A, B, Write, &[gb]);
        let g5 = w.edge(X, 3, &[], A, N5, Admin, &[]);
        let r = w.edge(H, 6, &[], A, X, Gone, &[down, g5]);
        let timed = w.edge(X, 1, &[], A, X, role, &[]);
        w.set_until(timed, until);
        w.rely(timed, H);
        assert!(w.leave(timed));
        let rd = fixed(&w, &[r]);
        assert!(!rd.applied.contains(&timed) && rd.applied.is_superset(&Set::from([down, g5])), "{role:?}");
        let rd = fixed_but(&w, &[r], |x| x.leave_in_question = false);
        assert!(rd.applied.contains(&timed) && !rd.applied.contains(&g5), "{role:?}");
    }
}

/// A leave of a holder thing: X makes A leave T1 (marked adminless), stamped before a grant B made
/// on T1 through (A, T1); K, a co-admin of T1 through A2, then removes A from T1 listing B's
/// grant. The leave is put in question like a write through (A, T1): unlisted, it is dropped, and
/// B's grant stands. Control: never put in question, the leave takes B's authority and its grant.
#[test]
fn a_holder_things_leave_is_put_in_question_by_a_removal_of_its_edge() {
    let mut w = account();
    w.edge(H, 1, &[], A, X, Admin, &[]);
    w.edge(H, 1, &[], A, B, Admin, &[]);
    let g2 = w.edge(H, 1, &[A], T1, A2, Admin, &[]);
    let leave = w.edge(X, 2, &[A], T1, A, Gone, &[]);
    w.mark_adminless(leave);
    let gn = w.edge(B, 3, &[A], T1, N6, Write, &[]);
    // K lists its own holder's grant too (else it drops its own authority and is void)
    let rk = w.edge(K, 6, &[A2], T1, A, Gone, &[g2, gn]);
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&rk) && !rd.applied.contains(&leave) && rd.applied.contains(&gn) && rd.role(N6, T1) == Write);
    let rd = fixed_but(&w, &[], |x| x.leave_in_question = false);
    assert!(rd.applied.contains(&leave) && !rd.applied.contains(&gn));
}

/// A vouch counts only where its removal applies in the first walk (notes/account-membership-
/// design.md §4, It counts; finding 22: the model had read only its key). X removed N5 before the
/// theft; the thief backdates X's own edge to write until after the story, removes H (honestly
/// stamped, before H's removal), and with N5's key vouches against H's removal for all three. A
/// node trusting nothing: in the first walk H's removal drops the timed self-demotion, X's
/// removal of H then applies and H's is void; there N5 is an admin again, but H's removal does
/// not apply, so N5's vouch counts for nothing and H's removal is the dispute shown. Counted by
/// its key alone, N5's vouch would keep all three: H's removal would apply there with N5 back
/// and the self-demotion standing, a reading unlike the trusted side's with no dispute shown.
#[test]
fn a_vouch_counts_only_where_its_removal_applies_in_the_first_walk() {
    let (mut w, gx, gb) = paired();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let out = w.edge(X, 3, &[], A, N5, Gone, &[g5]);
    let rx = w.edge(X, 5, &[], A, H, Gone, &[gx, gb, g5]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[out]);
    let timed = w.edge(X, 2, &[], A, X, Write, &[]);
    w.set_until(timed, 20);
    w.rely(timed, H);
    let v5 = w.vouch(N5, 7, &[], A, r, &[out, rx, timed]);
    let plain = fixed(&w, &[]);
    assert!(!plain.counting.contains(&v5) && !plain.applied.contains(&r));
    assert_eq!(disputes(&w, &Rules::fixed(), &View::all(&w)), vec![r]);
    let rd = fixed(&w, &[r]);
    assert!(rd.void.is_empty() && rd.role(N5, A) == Gone && rd.role(H, A) == Admin && !rd.shows(timed));
}

