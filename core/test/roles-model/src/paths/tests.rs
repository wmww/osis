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

/// Finding 4's world: X's removal of H lists nothing, its own grant included. Its drops would
/// take its own standing, so it is void: nothing falls by it and no dispute is raised. Control:
/// it applies.
#[test]
fn a_removal_whose_drops_take_its_own_standing_is_void() {
    let (w, gb, rx) = self_voiding();
    let rd = fixed(&w, &[]);
    assert!(!rd.applied.contains(&rx) && rd.stray.is_empty() && rd.dropped.is_empty());
    assert!(rd.applied.contains(&gb) && rd.role(H, A) == Admin && rd.role(B, A) == Admin);
    assert!(disputes(&w, &Rules::fixed(), &View::all(&w)).is_empty());
    assert!(fixed(&w, &[rx]).void.contains(&rx));
    // control: it applies, dropping every grant of H, its author's included: A has no admin
    let rd = fixed_but(&w, &[], |x| x.self_void = false);
    assert!(rd.applied.contains(&rx) && !rd.applied.contains(&gb) && !rd.roles.iter().any(|(e, r)| e.1 == A && *r == Admin));
}

/// A removal made under a grant a later removal drops keeps its verdict: N5 (paired by X, the
/// pairing never received by H) removes B listing nothing; H removes X. Trusting nothing, N5's
/// removal applied at its key and stands, B's grant dropped by it (each lowering is judged once);
/// the node is shown H's removal, whose trust changes the reading. Trusted, its seeds take X's
/// pairing of N5 before the walk, so N5's removal never holds the right and B's writes stand.
#[test]
fn a_removal_whose_author_falls_later_keeps_its_verdict() {
    let (mut w, _, gb) = paired();
    w.edge(X, 2, &[], A, N5, Admin, &[]);
    let bg = w.edge(B, 3, &[A], T1, A2, Write, &[]);
    let out = w.edge(N5, 4, &[], A, B, Gone, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&out) && !rd.applied.contains(&bg) && rd.role(B, A) == Gone && rd.role(N5, A) == Gone && rd.stray.is_empty(), "{rd:?}");
    assert_eq!(disputes(&w, &Rules::fixed(), &View::all(&w)), vec![r]);
    let rd = fixed(&w, &[r]);
    assert!(!rd.applied.contains(&out) && rd.applied.is_superset(&Set::from([gb, bg])) && rd.role(B, A) == Admin);
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
    for k in ["safety", "liveness", "alike", "removal kept", "removal", "own path", "admin", "untrusted", "dispute", "safety N", "admin N", "own path N"] {
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
        ("no-void", Rules { self_void: false, ..f }),
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
    assert_holds(&family_run(&Rules::fixed(), 2017), "family");
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
/// coprime with every dimension's size (2, 4, 5, 48), so no dimension is fixed or tied to
/// another (an even stride keeps `h_t1` false in every world).
#[test]
#[ignore = "property"]
fn small_family_holds_large() {
    let st = family_run(&Rules::fixed(), 157);
    st.print("paths family", &Rules::fixed());
    assert_holds(&st, "family");
}


// ---- Each lowering judged once (notes/write-path-design.md §1; findings 16, 17) ----

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

/// Two lowerings, each taking the other's author: B and N5, both paired by H, each remove H
/// listing only their own grant. The earlier by key applies and drops H's grant of N5; the later
/// then finds its author holding nothing and does not apply. In any input order.
#[test]
fn two_lowerings_unapplying_each_other_settle_on_the_earlier() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let lb = w.edge(B, 3, &[], A, H, Gone, &[gb]);
    let l5 = w.edge(N5, 4, &[], A, H, Gone, &[g5]);
    let rd = one_reading(&w);
    assert!(rd.applied.contains(&lb) && !rd.applied.contains(&l5) && rd.dropped == Set::from([g5]) && rd.voided.is_empty());
}

/// A lowering holding its right at its key applies, and what it dropped stays dropped when a later
/// lowering drops it: H pairs B and N5 and removes N5 (D); B removes H listing its own and N5's
/// grants, so it drops D; N5, an admin again, removes B listing nothing, so it drops B's removal.
/// N5's removal rests on H's grant, which nothing it drops touches: it applies. D stays dropped
/// though its dropper is dropped (a stray drop): H and N5 stay, B goes.
#[test]
fn a_lowering_dropped_later_keeps_its_drops() {
    let mut w = account();
    w.edge(H, 1, &[], A, B, Admin, &[]);
    let gb = 0;
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let d = w.edge(H, 2, &[], A, N5, Gone, &[]);
    let lb = w.edge(B, 3, &[], A, H, Gone, &[gb, g5]);
    let l5 = w.edge(N5, 4, &[], A, B, Gone, &[]);
    let rd = one_reading(&w);
    assert!(rd.applied.contains(&l5) && rd.dropped == Set::from([d, lb]) && rd.stray == Set::from([d]) && rd.voided.is_empty(), "{rd:?}");
    assert_eq!((rd.role(H, A), rd.role(B, A), rd.role(N5, A)), (Admin, Gone, Admin));
    // trusted, B's removal drops D by its seeds, and N5's removal, holding H's grant, still drops
    // it: void, it loses them, and the reading is the same
    let t = fixed(&w, &[lb]);
    assert!(t.void == Set::from([lb]) && t.roles == rd.roles);
}

/// A void write has no effect: H pairs B and N5; B pairs Z; Z removes H listing B's grant (so it
/// drops H's pairing of N5), then removes B listing nothing, which would drop B's pairing of Z,
/// Z's own standing: void, and the reading is the reading without it held.
#[test]
fn a_void_write_has_no_effect() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    w.edge(H, 1, &[], A, N5, Admin, &[]);
    w.edge(B, 2, &[], A, Z, Admin, &[]);
    let zh = w.edge(Z, 3, &[], A, H, Gone, &[gb]);
    let zb = w.edge(Z, 4, &[], A, B, Gone, &[]);
    let rd = one_reading(&w);
    assert!(rd.voided == Set::from([zb]) && rd.applied.contains(&zh) && rd.role(H, A) == Gone && rd.role(N5, A) == Gone);
    assert!(no_effect(&w, &Rules::fixed(), &View::all(&w), &rd, zb));
}

/// A lowering whose drops take the grant its own path rests on is void, though another lowering
/// it drops took what that grant replaced: H pairs B and N6; N6 grants B admin again and removes H
/// listing that grant (so it drops H's grant of B); B removes N6 listing nothing, which would drop
/// N6's grant of B, the only one B holds there: void. N6 keeps A and H is removed.
#[test]
fn a_lowering_dropping_the_grant_it_rests_on_is_void() {
    let mut w = account();
    let gb = w.edge(H, 3, &[], A, B, Admin, &[]);
    let g6 = w.edge(H, 3, &[], A, N6, Admin, &[]);
    let again = w.edge(N6, 5, &[], A, B, Admin, &[g6]);
    let l6 = w.edge(N6, 5, &[], A, H, Gone, &[g6, again]);
    let lb = w.edge(B, 6, &[], A, N6, Gone, &[]);
    let rd = one_reading(&w);
    assert!(rd.voided == Set::from([lb]) && rd.applied.contains(&l6) && rd.dropped == Set::from([gb]), "{rd:?}");
    assert_eq!((rd.role(H, A), rd.role(N6, A), rd.role(B, A)), (Gone, Admin, Admin));
    assert!(no_effect(&w, &Rules::fixed(), &View::all(&w), &rd, lb));
}

/// H grants B admin at 2 and again at 10; B removes H at 9 listing neither (it drops the grant at
/// 2, its own standing: void) and at 10 listing the first (it drops only the second and keeps its
/// standing by the first): the one at 10 applies, as where the one at 9 is not held.
#[test]
fn an_earlier_void_write_has_no_effect() {
    let mut w = account();
    let g1 = w.edge(H, 2, &[], A, B, Admin, &[]);
    w.edge(H, 10, &[], A, B, Admin, &[]);
    let early = w.edge(B, 9, &[], A, H, Gone, &[]);
    let late = w.edge(B, 10, &[], A, H, Gone, &[g1]);
    let rd = one_reading(&w);
    assert!(rd.voided == Set::from([early]) && rd.applied.contains(&late) && rd.role(H, A) == Gone);
    assert!(no_effect(&w, &Rules::fixed(), &View::all(&w), &rd, early));
}

/// Small worlds 830267, 360379 and 234147: fights of three or four admins where a lowering
/// applied at its key keeps its drops once a later lowering drops it.
/// 830267: H pairs B at 1, N5 and N6 at 3; N5 grants N6 admin at 3; at 4 B removes N5 (dropping
/// that grant) and N6 removes H, which would drop H's grant of N6, its only one left: void. N6's
/// removal of B at 8 rests on H's grant and applies, dropping B's removal; N5's grant of N6
/// stays dropped (stray). H, N5 and N6 keep A.
#[test]
fn small_world_830267_judged_once() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    let g5 = w.edge(H, 3, &[], A, N5, Admin, &[]);
    let g6 = w.edge(H, 3, &[], A, N6, Admin, &[]);
    let n6 = w.edge(N5, 3, &[], A, N6, Admin, &[gb, g5]);
    let b5 = w.edge(B, 4, &[], A, N5, Gone, &[g6, gb]);
    let h = w.edge(N6, 4, &[], A, H, Gone, &[g5, n6]);
    let b = w.edge(N6, 8, &[], A, B, Gone, &[]);
    let rd = one_reading(&w);
    assert!(rd.voided == Set::from([h]) && rd.applied.contains(&b) && rd.dropped == Set::from([n6, b5]) && rd.stray == Set::from([n6]), "{rd:?}");
    assert_eq!((rd.role(H, A), rd.role(B, A), rd.role(N5, A), rd.role(N6, A)), (Admin, Gone, Admin, Admin));
    assert!(no_effect(&w, &Rules::fixed(), &View::all(&w), &rd, h));
}

/// 360379: H pairs B, N6 and N5 at 1; N5 removes H at 1 listing B's and its own grants (dropping
/// H's grant of N6); B removes N5 at 2 (dropping that removal); H removes B at 9 (dropping B's
/// removal). Each holds its right at its key and applies; each drop stands, so N6's grant and N5's
/// removal of H stay dropped though their droppers are dropped (two stray drops): H and N5 keep A.
#[test]
fn small_world_360379_judged_once() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    let g6 = w.edge(H, 1, &[], A, N6, Admin, &[gb]);
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let r5 = w.edge(N5, 1, &[], A, H, Gone, &[gb, g5]);
    let b5 = w.edge(B, 2, &[], A, N5, Gone, &[g5]);
    let hb = w.edge(H, 9, &[], A, B, Gone, &[gb, r5]);
    let rd = one_reading(&w);
    assert!(rd.applied.contains(&hb) && rd.dropped == Set::from([g6, r5, b5]) && rd.stray == Set::from([g6, r5]) && rd.voided.is_empty(), "{rd:?}");
    assert_eq!((rd.role(H, A), rd.role(B, A), rd.role(N5, A), rd.role(N6, A)), (Admin, Gone, Admin, Gone));
}

/// 234147, trusting N6's removal of Z or nothing: H pairs N5; N5 pairs Z; Z removes H (listing
/// both grants) at 3; N5 pairs N6 at 8; N6 removes Z at 8, dropping Z's removal; H removes N6 at
/// 9, dropping N6's removal (trusted, it is void and loses its seeds); N5's removal of H at 10
/// would drop H's grant of N5: void. Z's removal of H stays dropped (stray): H, N5 and Z keep A.
#[test]
fn small_world_234147_judged_once() {
    let mut w = account();
    let g5 = w.edge(H, 3, &[], A, N5, Admin, &[]);
    let gz = w.edge(N5, 3, &[], A, Z, Admin, &[g5]);
    let zh = w.edge(Z, 3, &[], A, H, Gone, &[g5, gz]);
    let g6 = w.edge(N5, 8, &[], A, N6, Admin, &[g5]);
    let r6 = w.edge(N6, 8, &[], A, Z, Gone, &[]);
    let h6 = w.edge(H, 9, &[], A, N6, Gone, &[g5]);
    let last = w.edge(N5, 10, &[], A, H, Gone, &[r6]);
    for t in [&[][..], &[r6]] {
        let rd = fixed(&w, t);
        assert!(rd.voided == Set::from([last]) && rd.applied.is_superset(&Set::from([g5, gz, g6, h6])) && rd.stray == Set::from([zh]), "{t:?} {rd:?}");
        assert_eq!((rd.role(H, A), rd.role(N5, A), rd.role(Z, A), rd.role(N6, A)), (Admin, Admin, Admin, Gone));
        assert_eq!(rd.void.contains(&r6), !t.is_empty());
    }
}

/// What the void check does not read: what a lowering's own drops free (small world 349938, the
/// one of 1,000,000 `tiny` worlds leaving A with no admin). H pairs N6, N6 pairs N5; H removes N6
/// listing that pairing, and removes N6 again listing the first removal (a no-op); N5 removes H
/// listing H's second removal and its grant of N6. N5's path rests on N6's grant, which nothing N5
/// drops touches, so N5's removal applies and drops H's first removal; the restart that drop makes
/// lets H's second removal take N6's edge, which drops N6's grant of N5; N5's removal keeps its
/// verdict. A ends with no admin, trusting nothing, H's first removal (void: the current admin it
/// left in place removed its author) or N5's (void too). Shown: H's second removal, whose seeds
/// take N6's grant of N5 before the walk.
#[test]
fn a_lowerings_check_does_not_read_what_its_drops_free() {
    let mut w = account();
    let g6 = w.edge(H, 1, &[], A, N6, Admin, &[]);
    let g5 = w.edge(N6, 2, &[], A, N5, Admin, &[]);
    let r1 = w.edge(H, 4, &[], A, N6, Gone, &[g5]);
    let r2 = w.edge(H, 4, &[], A, N6, Gone, &[r1]);
    let l = w.edge(N5, 4, &[], A, H, Gone, &[r2, g6]);
    for t in [&[][..], &[r1], &[l]] {
        let rd = fixed(&w, t);
        assert!(rd.applied == Set::from([g6, r2, l]) && rd.dropped == Set::from([g5, r1]) && rd.void == t.iter().copied().collect(), "{t:?} {rd:?}");
        assert!(!rd.roles.iter().any(|(e, r)| e.1 == A && *r == Admin));
        assert_eq!(disputes(&w, &Rules::fixed(), &View::all(&w).trusting(t)), vec![r2]);
    }
    let rd = fixed(&w, &[r2]);
    assert!(!rd.applied.contains(&l) && rd.role(H, A) == Admin);
}

/// The void check reads the grant chain back: H pairs Z, Z pairs N5, and N5 removes H listing
/// only Z's grant of it. Its drop of H's grant of Z takes the grant N5's own came through: void,
/// and H keeps A. Control: taking each setter as it stands (Z's grant of N5 as admin), it applies
/// and A is left with no admin.
#[test]
fn a_lowering_dropping_its_granters_grant_is_void() {
    let mut w = account();
    let gz = w.edge(H, 4, &[], A, Z, Admin, &[]);
    let g5 = w.edge(Z, 8, &[], A, N5, Admin, &[]);
    let l = w.edge(N5, 10, &[], A, H, Gone, &[g5]);
    let rd = one_reading(&w);
    assert!(rd.voided == Set::from([l]) && rd.applied == Set::from([gz, g5]) && rd.role(H, A) == Admin, "{rd:?}");
    assert!(no_effect(&w, &Rules::fixed(), &View::all(&w), &rd, l));
}

/// A lowering that takes nothing where it is first reached is judged by the restart that gives it
/// the edge: X removes N5 honestly at 3 (`out`, heard by H and listed); the thief backdates a
/// removal of N5 to 2 and, with N5's key, a grant of admin to Z after it. Trusting nothing, `out`
/// first takes nothing (N5 is off A already) and the grant does not apply; H's removal drops the
/// backdated removal, the grant applies, and `out`, now taking N5's edge, audits and drops it: Z
/// holds nothing, trusted or not.
#[test]
fn a_lowering_taking_nothing_is_judged_when_a_restart_gives_it_the_edge() {
    let (mut w, ..) = paired();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let out = w.edge(X, 3, &[], A, N5, Gone, &[g5]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[out]);
    w.edge(X, 2, &[], A, N5, Gone, &[g5]);
    let gz = w.edge(N5, 2, &[], A, Z, Admin, &[]);
    for t in [&[][..], &[r]] {
        let rd = fixed(&w, t);
        assert!(rd.applied.contains(&r) && rd.applied.contains(&out) && rd.dropped.contains(&gz) && rd.role(Z, A) == Gone, "{t:?} {rd:?}");
    }
}

/// A stray drop costing a role in a fight of admins (the smallest such `tiny` world trusting a
/// lowering that applies): H pairs N5, N5 pairs N6 and B, B pairs Z; N6 removes B; Z removes N6
/// not listing that removal, so it drops it; H removes Z listing nothing, so it drops Z's removal.
/// N6 stays an admin and so does B: N6's removal stays dropped. Trusting H's removal of Z, its
/// seeds take Z's removal before the walk and B is removed: shown as a dispute.
#[test]
fn a_stray_drop_in_a_fight_of_admins_is_shown() {
    let mut w = account();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let g6 = w.edge(N5, 1, &[], A, N6, Admin, &[g5]);
    let gb = w.edge(N5, 7, &[], A, B, Admin, &[]);
    let gz = w.edge(B, 8, &[], A, Z, Admin, &[gb]);
    let rb = w.edge(N6, 8, &[], A, B, Gone, &[gb, gz, g6]);
    let rn6 = w.edge(Z, 9, &[], A, N6, Gone, &[g5, gz]);
    let rz = w.edge(H, 10, &[], A, Z, Gone, &[]);
    let rd = one_reading(&w);
    assert!(rd.dropped == Set::from([rb, rn6]) && rd.stray == Set::from([rb]) && rd.applied.contains(&rz), "{rd:?}");
    assert_eq!((rd.role(B, A), rd.role(N6, A), rd.role(Z, A)), (Admin, Admin, Gone));
    assert_eq!(disputes(&w, &Rules::fixed(), &View::all(&w)), vec![rz]);
    let t = fixed(&w, &[rz]);
    assert!(t.void.is_empty() && t.applied.contains(&rb) && t.role(B, A) == Gone);
}

/// The thief's lowering stamped just after the honest removal, aimed at what the removal rests
/// on (M's grant of H), by X or by a made-up key X granted backdated, holds nothing at its key in
/// the walk where the removal applies. Backdated before the removal it applies only where the
/// removal is not trusted, shown as a dispute.
#[test]
fn a_thiefs_lowering_after_the_removal_holds_nothing() {
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
/// search): one reading under a relabelling. Control: a lowering whose drops take its author's
/// standing applying, A is left with no admin (counted).
#[test]
fn small_worlds_hold() {
    let st = tiny_run(3000, &Rules::fixed());
    assert!(st.failures() == 0 && st.checked["void"] > 0 && st.checked["admin T"] > 0, "{:?} {:?}", st.fails, st.first);
    let no_void = tiny_run(300, &Rules { self_void: false, ..Rules::fixed() });
    assert!(no_void.noted.contains_key("admin N"));
}

/// What a party with admin can make a reader walk (finding 17): X grants k keys of its own admin
/// and each removes X listing nothing, so each would drop its own grant and is void; H removes X.
/// At a node trusting nothing each void removal costs its check (the setters of its path read
/// back: one each) and H's removal one restart; trusting H's removal, X's grants are seeds and no
/// removal of a key holds the right. Returns (restarts, commits visited, setters read) for each.
fn void_cost(k: usize) -> ((u32, u64, u64), (u32, u64, u64)) {
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
    let t = fixed(&w, &[r]);
    assert!(t.applied.contains(&r) && t.voided.is_empty());
    ((plain.rounds, plain.walked, plain.checked), (t.rounds, t.walked, t.checked))
}

#[test]
fn a_partys_self_voiding_writes_cost_linear_work() {
    let (small, large) = (void_cost(10), void_cost(100));
    println!("k 10: plain {:?} trusting {:?}; k 100: plain {:?} trusting {:?}", small.0, small.1, large.0, large.1);
    // two walks each (the first with no vouch counting): one restart each, for H's removal
    assert!(small.0 .0 == 2 && large.0 .0 == 2 && small.1 .0 == 0 && large.1 .0 == 0);
    for (s, l) in [(small.0, large.0), (small.1, large.1)] {
        assert!(l.1 + l.2 <= 12 * (s.1 + s.2), "{s:?} {l:?}");
    }
}

/// The bound a void check has (finding 17): it reads the setters along its author's own grant
/// chain. X grants Z1 admin, each Zi grants Zi+1, and Zk removes X k times listing nothing: each
/// removal reads the chain back to X's grant, its own drop, and is void, so k checks read k
/// setters each: work k² for 2k writes, at a node trusting nothing.
#[test]
fn a_void_check_reads_its_own_grant_chain() {
    let cost = |k: usize| {
        let (mut w, ..) = paired();
        let z = |i: usize| 30 + i as Thing;
        w.edge(X, 1, &[], A, z(0), Admin, &[]);
        for i in 1..k {
            w.edge(z(i - 1), 1, &[], A, z(i), Admin, &[]);
        }
        for t in 0..k {
            w.edge(z(k - 1), 2 + t as u32, &[], A, X, Gone, &[]);
        }
        let rd = fixed(&w, &[]);
        assert!(rd.voided.len() == k && rd.rounds == 0);
        rd.checked
    };
    let (small, large) = (cost(10), cost(100));
    assert!(large >= 50 * small, "{small} {large}");
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
/// question the held writes before it, as a trusted write's seeds do. X, stolen, backdates its own
/// leave to 1 and removes H at 5 (honestly stamped, listing every grant); H removes X at 6. Over
/// the held writes H's removal drops the leave and X's removal of H, and applies. Control, over
/// the applied writes: it drops the leave alone (X's removal of H, unapplied while X had left, is
/// no applied write), and the restart its drop makes applies X's removal of H, which takes H: H
/// and X both end removed, unlike the trusting side. Trusting H's removal, both read alike.
#[test]
fn the_audit_puts_the_held_writes_in_question() {
    let (mut w, gx, gb) = paired();
    let rx = w.edge(X, 5, &[], A, H, Gone, &[gx, gb]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let leave = w.edge(X, 1, &[], A, X, Gone, &[]);
    w.rely(leave, H);
    let held = fixed(&w, &[]);
    assert!(held.applied.contains(&r) && held.dropped == Set::from([leave, rx]) && (held.role(H, A), held.role(X, A)) == (Admin, Gone));
    let applied = fixed_but(&w, &[], |x| x.audit_held = false);
    assert!(applied.applied.is_superset(&Set::from([r, rx])) && applied.dropped == Set::from([leave]) && (applied.role(H, A), applied.role(X, A)) == (Gone, Gone));
    assert_eq!(fixed(&w, &[r]).applied, fixed_but(&w, &[r], |x| x.audit_held = false).applied);
    assert_eq!(fixed(&w, &[r]).applied, held.applied);
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

/// `out` applies at its key (X still holds A there) and drops N5's backdated grant to H; X's
/// removal of H is void (it drops H's grant of X); N5 stays removed, trusted or not.
#[test]
fn a_party_removed_before_the_theft_stays_removed() {
    let (w, out, r) = n5_back();
    for t in [&[][..], &[r]] {
        let rd = fixed(&w, t);
        assert!(rd.applied.contains(&out) && rd.applied.contains(&r) && rd.role(N5, A) == Gone && rd.void.is_empty(), "{t:?}");
    }
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

/// Equivocation: X signs a twin of its removal of N5 at its `ts`, ordered first, listing H's
/// pairing of N5 and not N5's grant to B. Received by H before the removal it is a write H's
/// removal applies with, so H keeps it: the twin applies, the first is a no-op and N5's grant to
/// B falls (as any lowering X made that H heard). Received after, a trusting node's seeds take the
/// twin before the walk and the first stays made, its list with it; a node trusting nothing judges
/// the twin applying at its key, so its drop of N5's grant to B stands when H's removal drops it
/// (a stray drop), and H's removal is shown to it as a dispute.
#[test]
fn an_equivocating_twin_of_an_earlier_removal() {
    let s = Setup { n5: 3, ..Setup::default() };
    for (made, kept) in [(5, true), (9, false)] {
        let m = Sim::build(&s, &Rules::fixed(), &[Move { kind: 35, ts: 3, made }], &mut Rng(0));
        let twin = *m.thief.keys().next().unwrap();
        for n in [H, B, N6] {
            let rd = judge(&m.w, &Rules::fixed(), &m.view(n, &Rules::fixed()));
            assert_eq!(rd.applied.contains(&twin), kept, "node {n}");
            assert_eq!(rd.applied.contains(&m.gb5.unwrap()), !kept && n != N6, "node {n}");
            assert!(rd.applied.contains(&m.out5.unwrap()) && rd.role(N5, A) == Gone);
        }
        let v = m.view(N6, &Rules::fixed());
        assert_eq!(judge(&m.w, &Rules::fixed(), &v).stray.contains(&m.gb5.unwrap()), !kept);
        assert_eq!(disputes(&m.w, &Rules::fixed(), &v).contains(&m.r), !kept);
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
/// design.md §4, It counts; finding 22). X removed N5 before the theft; the thief backdates X's
/// own edge to write until after the story, removes H (honestly stamped, before H's removal), and
/// with N5's key vouches against H's removal for all three. A node trusting nothing: H's removal
/// puts the held writes through X's edge in question, so it drops the self-demotion and X's
/// removal of H and applies; the restart its drops make applies X's removal of N5, so N5 holds
/// nothing at its vouch, which counts for nothing. Both sides read alike and nothing is shown.
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
    assert!(!plain.counting.contains(&v5) && plain.applied.is_superset(&Set::from([r, out])) && plain.dropped == Set::from([timed, rx]), "{plain:?}");
    assert!(disputes(&w, &Rules::fixed(), &View::all(&w)).is_empty());
    let rd = fixed(&w, &[r]);
    assert!(rd.void.is_empty() && rd.role(N5, A) == Gone && rd.role(H, A) == Admin && !rd.shows(timed) && rd.roles == plain.roles);
}

// ---- Invites and finalizes (spec/permissions.md §2 along one path; notes/write-path-design.md §1, Edge writes) ----

/// A with H; A2 (K's) shares T1 at write inviting read (by H, through A); K gives X write on A2.
fn invited() -> World {
    let mut w = account();
    w.push(H, 1, &[A], T1, Kind::set(A2, Write).inviting(Role::Read));
    w.edge(K, 1, &[], A2, X, Write, &[]);
    w
}

/// An invite grant applies by its path's invite (the roles before the last edge, the last edge's
/// invite), to a holder with no current grant, and gives no right to change another edge.
#[test]
fn an_invite_grant_applies_by_its_paths_invite() {
    let mut w = invited();
    let z = w.push(X, 2, &[A2], T1, Kind::set(Z, Role::Read));
    let beyond = w.push(X, 2, &[A2], T1, Kind::set(N6, Write));
    let again = w.push(X, 3, &[A2], T1, Kind::set(Z, Role::Read).until(9));
    let lower = w.push(X, 4, &[A2], T1, Kind::set(Z, Gone));
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&z) && ![beyond, again, lower].iter().any(|i| rd.applied.contains(i)));
    assert_eq!((rd.role(Z, T1), rd.role(N6, T1)), (Role::Read, Gone));
    // control: a role on the last edge suffices, so a writer grants write
    let rd = fixed_but(&w, &[], |r| r.invite_check = false);
    assert_eq!(rd.role(N6, T1), Write);
}

/// A writer removed from the holder it invited through: its invites rest on that edge, fall
/// unless the removal lists them, whether the edge fell from admin or from write.
#[test]
fn an_invite_by_a_removed_writer_falls_unless_listed() {
    let mut w = invited();
    let z = w.push(X, 3, &[A2], T1, Kind::set(Z, Role::Read));
    let n6 = w.push(X, 4, &[A2], T1, Kind::set(N6, Role::Read));
    let r = w.edge(K, 6, &[], A2, X, Gone, &[z]);
    for trust in [vec![], vec![r]] {
        let rd = fixed(&w, &trust);
        assert!(rd.applied.contains(&z) && !rd.shows(n6), "{trust:?}");
        assert_eq!((rd.role(Z, T1), rd.role(N6, T1)), (Role::Read, Gone));
    }
    // control: only a fall from admin audits; trusting nothing the unlisted invite stands
    let rd = fixed_but(&w, &[], |r| r.any_fall = false);
    assert_eq!(rd.role(N6, T1), Role::Read);
}

/// An expired grant counts as none: an invite over it applies, before or after a finalize; a
/// finalize applies only to an ended grant, by a writer holding at least its role (an admin for a
/// timed admin grant), audits nothing and makes nothing standing.
#[test]
fn a_finalize_ends_an_ended_grant_and_an_invite_follows_it() {
    let mut w = invited();
    let timed = w.push(X, 2, &[A2], T1, Kind::set(Z, Role::Read).until(4));
    let early = w.push(K, 3, &[A2], T1, Kind::finalize(Z));
    let by_reader = w.push(Z, 3, &[], T1, Kind::finalize(Z));
    let fin = w.push(K, 4, &[A2], T1, Kind::finalize(Z));
    let again = w.push(X, 5, &[A2], T1, Kind::set(Z, Role::Read));
    let rd = fixed(&w, &[]);
    assert!([timed, fin, again].iter().all(|i| rd.applied.contains(i)));
    assert!(![early, by_reader].iter().any(|i| rd.applied.contains(i)));
    assert_eq!(rd.role(Z, T1), Role::Read);
    // without the finalize the invite over the ended grant applies all the same
    let rd = judge(&w, &Rules::fixed(), &View::all(&w).without(&[fin]));
    assert!(rd.applied.contains(&again) && rd.role(Z, T1) == Role::Read);
    // a timed admin grant is finalized by an admin only (its role at least the grant's), not by a
    // writer: the finalize is the grant's departure for keys
    let mut w = invited();
    w.edge(H, 1, &[], A, B, Admin, &[]);
    w.push(H, 2, &[A], T1, Kind::set(N6, Admin).until(4));
    let by_writer = w.push(K, 5, &[A2], T1, Kind::finalize(N6));
    let by_admin = w.push(B, 6, &[A], T1, Kind::finalize(N6));
    let rd = fixed(&w, &[]);
    assert!(!rd.applied.contains(&by_writer) && rd.applied.contains(&by_admin));
}

/// spec/permissions.md §7, a link: L, timed with an invite, invites; its `until` passing and the
/// finalize audit nothing (the invitee's writes stand by their own keys); the next explicit
/// removal of L audits against the edge as restored and drops the invites it does not list.
#[test]
fn the_explicit_removal_after_a_finalize_audits_the_invites() {
    let mut w = account();
    let l = N6;
    w.push(H, 1, &[A], T1, Kind::set(l, Write).inviting(Write).until(5));
    let z = w.push(l, 2, &[], T1, Kind::set(Z, Write));
    let n5 = w.push(l, 3, &[], T1, Kind::set(N5, Write));
    let wz = w.content(Z, 4, &[], T1);
    let fin = w.push(B, 6, &[A], T1, Kind::finalize(l));
    w.edge(H, 1, &[], A, B, Admin, &[]);
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&fin) && rd.valid.contains(&wz));
    assert_eq!((rd.role(Z, T1), rd.role(N5, T1)), (Write, Write));
    let r = w.edge(H, 7, &[A], T1, l, Gone, &[z]);
    for trust in [vec![], vec![r]] {
        let rd = fixed(&w, &trust);
        assert!(rd.applied.contains(&r) && rd.valid.contains(&wz) && !rd.applied.contains(&n5), "{trust:?}");
        assert_eq!((rd.role(Z, T1), rd.role(N5, T1)), (Write, Gone));
    }
}

/// A re-grant dropping the invite the share carried lowers it: it audits the invites made under
/// it, and an honest one lists them (story: B's re-grant of A2 keeps the invite and lists).
#[test]
fn a_write_dropping_an_invite_audits_the_invites_under_it() {
    let mut w = invited();
    let z = w.push(X, 2, &[A2], T1, Kind::set(Z, Role::Read));
    let plain = w.push(B, 5, &[A], T1, Kind::set(A2, Write));
    w.edge(H, 1, &[], A, B, Admin, &[]);
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&plain) && rd.dropped.contains(&z));
    w.edit(plain, |k| k.listing(BTreeMap::from([(T1, Set::from([z]))])));
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&z) && rd.role(Z, T1) == Role::Read);
}

// ---- Purge authors (notes/write-path-design.md §1, The purge author) ----

/// A request by author P matches the deltas naming exactly P as their purge author, never every
/// delta whose chain holds P.
#[test]
fn a_purge_by_author_takes_exactly_that_authors_deltas() {
    let (mut w, ..) = paired();
    let b_as_a = w.content_as(B, 2, &[A], T1, 1);
    let h_as_a = w.content_as(H, 2, &[A], T1, 1);
    let b_as_b = w.content(B, 2, &[A], T1);
    let later = w.content_as(H, 4, &[A], T1, 1);
    let q = w.purge(B, 3, &[A], T1, A);
    let rd = fixed(&w, &[]);
    assert!(rd.valid.contains(&q));
    assert_eq!(rd.purged, Set::from([b_as_a, h_as_a]));
    assert!(!rd.purged.contains(&b_as_b) && !rd.purged.contains(&later));
    // control: matched by chain, B's own edit goes too
    assert!(fixed_but(&w, &[], |r| r.purge_exact = false).purged.contains(&b_as_b));
}

/// The author right is held only through the request's own chain: a member writing through A2
/// purges what A2 authored; an admin of the thing by another path names A2 and holds nothing
/// (the model's right is the `author` class alone).
#[test]
fn a_purge_holds_the_right_only_through_its_own_chain() {
    let mut w = invited();
    let k = w.content_as(K, 2, &[A2], T1, 1);
    w.edge(H, 1, &[], A, X, Admin, &[]);
    let by_admin = w.purge(X, 3, &[A], T1, A2);
    let rd = fixed(&w, &[]);
    assert!(rd.valid.contains(&by_admin) && rd.purged.is_empty());
    assert!(fixed_but(&w, &[], |r| r.purge_chain = false).purged.contains(&k));
    w.purge(X, 4, &[A2], T1, A2);
    assert_eq!(fixed(&w, &[]).purged, Set::from([k]));
}

/// A removed signer's backdated purge through the cut edge takes nothing, trusted or not; listed
/// by the removal it stands; a purge through a path the signer keeps still holds.
#[test]
fn a_removed_signers_backdated_purge_takes_nothing() {
    let mut w = invited();
    w.edge(H, 1, &[], A, X, Admin, &[]);
    let h = w.content_as(H, 2, &[A], T1, 1);
    let k = w.content_as(K, 2, &[A2], T1, 1);
    let q = w.purge(X, 5, &[A], T1, A);
    let qk = w.purge(X, 5, &[A2], T1, A2);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    for trust in [vec![], vec![r]] {
        let rd = fixed(&w, &trust);
        assert!(!rd.valid.contains(&q) && rd.valid.contains(&qk), "{trust:?}");
        assert_eq!(rd.purged, Set::from([k]), "{trust:?}");
    }
    w.edit(r, |kind| kind.listing(BTreeMap::from([(T1, Set::from([q]))])));
    assert!(fixed(&w, &[r]).purged.contains(&h));
}

// ---- Covers (spec/commits.md §5 Covered; notes/account-membership-design.md §1, Cutoff and Carrying) ----

/// The accepted window (spec/permissions.md §5.2 Copies, §5.3; notes/account-membership-design.md
/// §1 Cutoff and Carrying, §2 step 2): the thief X, removed by H, withholds H's removal from K
/// (serving K alone; the story's move 46, set by hand: the model's evidence closure is complete)
/// and writes T1 after it; K, an honest writer of T1 that does not yet hold the removal, compacts
/// T1 carrying that write. The write is invalid everywhere, and K's valid cover shows it for good
/// at every node holding the cover (and in every later snapshot, as state). What bounds the
/// window: K's receipt of the removal; from then K's walk shows nothing new of the thief's. The story counts it (`window`), never as a
/// safety failure; under the variant `-facts` the carried write falls with the removal.
#[test]
fn a_cover_by_a_writer_not_yet_holding_the_removal_carries_the_late_write() {
    let s = Setup { x_a2: 0, ..Setup::default() };
    for (rules, carried) in [(Rules::fixed(), true), (Rules { cover_facts: true, ..Rules::fixed() }, false)] {
        let m = Sim::build(&s, &rules, &[Move { kind: 46, ts: 7, made: 7 }], &mut Rng(1));
        let late = *m.thief.keys().next().unwrap();
        let (window, after): (Vec<Id>, Vec<Id>) = (0..m.w.commits.len()).filter(|&i| m.w.commits[i].signer == K && matches!(m.w.commits[i].kind, Kind::Cover { .. })).partition(|c| m.unaware.contains(c));
        assert_eq!(window.len(), 1);
        assert!(m.w.names(window[0], late));
        // K's cover made once it holds the removal carries the late write only as the window
        // cover's copy, which is state: without its covers K's walk then shows nothing of it
        assert!(!after.is_empty() && after.iter().all(|&c| m.w.names(c, late) == carried));
        let t = m.w.commits[after[0]].ts;
        let covers: Vec<Id> = window.iter().chain(&after).copied().collect();
        assert!(!judge(&m.w, &rules, &m.view_at(K, Some(t), &rules).without(&covers)).shows(late));
        for n in [B, K, RD, RD3] {
            let rd = judge(&m.w, &rules, &m.view(n, &rules));
            assert!(rd.valid.contains(&window[0]) && !rd.valid.contains(&late), "node {n}");
            assert_eq!(rd.shows(late), carried, "node {n}");
        }
        let mut st = Stats::default();
        check(&m, &rules, &mut st);
        assert!(!st.fails.contains_key("safety") && !st.fails.contains_key("safety N"), "{:?}", st.fails);
        assert_eq!(st.noted.contains_key("window"), carried, "{:?}", st.noted);
    }
}

/// An own cover: H forgot X's write (it holds only B's cover carrying it), covers it in a
/// snapshot of its own, and names that in its removal. Under copies (the rule) the valid covers
/// show it, named or not. Under `-facts` a list naming a cover names what it carries, so the
/// write stands judged by its facts; listing nothing, it falls.
#[test]
fn a_removal_naming_its_own_cover_keeps_what_the_cover_carries() {
    let (mut w, ..) = paired();
    let x = w.content(X, 3, &[A], T1);
    let bc = w.push(B, 4, &[A], T1, Kind::Cover { carries: Set::from([x]) });
    let own = w.push(H, 5, &[A], T1, Kind::Cover { carries: Set::from([x]) });
    let r = w.edge(H, 6, &[], A, X, Gone, &[own]);
    let v = View::all(&w).trusting(&[r]).without(&[x]);
    let facts = Rules { cover_facts: true, ..Rules::fixed() };
    let rd = judge(&w, &facts, &v);
    assert!(rd.valid.contains(&x) && rd.valid.contains(&bc));
    // under copies (the rule) both covers stay valid, so their copies show it, named or not
    assert!(judge(&w, &Rules::fixed(), &v).shows(x));
    w.edit(r, |k| k.listing(BTreeMap::new()));
    assert!(judge(&w, &Rules::fixed(), &v).shows(x));
    let rd = judge(&w, &facts, &v);
    assert!(!rd.valid.contains(&x) && rd.valid.contains(&own));
}

/// A cover written by a party removed later, unlisted, falls with its writer's other writes:
/// the honest write it carries stays valid where its commit is held (its author's node keeps
/// it); a node that forgot it under the fallen cover holds no valid statement of it, so it counts
/// there as never received and is fetched again from a holder. The removed party's own carried
/// write falls everywhere. Listed by the removal, the cover stands and carries both.
#[test]
fn a_fallen_cover_takes_nothing_honest() {
    let (mut w, ..) = paired();
    let b = w.content(B, 2, &[A], T1);
    let x = w.content(X, 3, &[A], T1);
    let xc = w.push(X, 4, &[A], T1, Kind::Cover { carries: Set::from([b, x]) });
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let at_author = judge(&w, &Rules::fixed(), &View::all(&w).trusting(&[r]));
    assert!(!at_author.valid.contains(&xc) && at_author.valid.contains(&b) && !at_author.shows(x));
    let forgot = View::all(&w).trusting(&[r]).without(&[b, x]);
    let rd = judge(&w, &Rules::fixed(), &forgot);
    assert!(!rd.valid.contains(&b) && !rd.shows(x));
    w.edit(r, |k| k.listing(BTreeMap::from([(T1, Set::from([xc]))])));
    let rd = judge(&w, &Rules::fixed(), &forgot);
    assert!(rd.valid.contains(&xc) && rd.shows(b) && rd.shows(x));
}
