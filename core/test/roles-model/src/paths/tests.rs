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

#[test]
fn a_removal_never_puts_its_own_grant_in_question() {
    let (mut w, gb, rx) = self_voiding();
    let rd = with(&w, &[], |x| x.own_chain_exempt = true);
    // an ordinary removal: it applies, B (unlisted) falls with H, and H's answer is a dispute
    assert!(rd.applied.contains(&rx) && rd.stray.is_empty() && !rd.applied.contains(&gb));
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let rd = with(&w, &[r], |x| x.own_chain_exempt = true);
    assert!(rd.role(H, A) == Admin && rd.role(X, A) == Gone && rd.applied.contains(&gb));
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

// ---- The searches at small size ----

fn random(n: u64, rules: &Rules, own_leaf: bool) -> Stats {
    let mut st = Stats::default();
    let mut rng = Rng(0);
    for _ in 0..n {
        check(&random_world(&mut rng, rules), rules, own_leaf, &mut st);
    }
    st
}

fn assert_holds(st: &Stats, what: &str) {
    for k in ["safety", "liveness", "alike", "removal kept"] {
        assert!(st.checked.get(k).is_some_and(|n| *n > 0), "{what}: no {k} check ran");
    }
    assert!(st.failures() == 0, "{what}: {:?}\n{:?}", st.fails, st.first);
}

#[test]
fn random_worlds_hold() {
    assert_holds(&random(400, &Rules::fixed(), false), "random");
}

/// Under the notes' rules the wanted behaviour fails where the findings say, and safety holds.
#[test]
fn the_notes_rules_fail_liveness_and_alike_never_safety() {
    let st = random(400, &Rules::design(), true);
    for k in ["liveness", "alike", "removal kept"] {
        assert!(st.fails.contains_key(k), "{k}: {:?}", st.fails);
    }
    for k in ["safety", "stray", "settles", "removal"] {
        assert!(!st.fails.contains_key(k), "{k}: {:?}", st.first.get(k));
    }
}

/// Each fix alone is needed: without it the search fails.
#[test]
fn each_fix_is_needed() {
    let cases: [(&str, fn(&mut Rules), bool); 3] = [("vouch", |r| r.vouch = Vouch::Off, false), ("regrant", |r| r.regrant = Regrant::FirstApplied, false), ("leaves", |_| {}, true)];
    for (name, undo, own_leaf) in cases {
        let mut rules = Rules::fixed();
        undo(&mut rules);
        assert!(random(400, &rules, own_leaf).failures() > 0, "{name}");
    }
}

#[test]
fn small_family_sample_holds() {
    let mut st = Stats::default();
    for i in (0..FAMILY).step_by(211) {
        check(&family(i, &Rules::fixed()), &Rules::fixed(), false, &mut st);
    }
    assert_holds(&st, "family");
}

fn var(k: &str) -> Option<u64> {
    std::env::var(k).ok().filter(|v| !v.is_empty()).map(|v| v.parse::<u64>().unwrap_or_else(|_| panic!("{k}={v:?} is not a decimal u64")))
}

/// Worlds from `OSIS_ROLES_START` (default 0), `OSIS_ROLES_SEEDS` many (40,000), a thread per
/// core.
#[test]
#[ignore = "property"]
fn random_worlds_hold_large() {
    let start = var("OSIS_ROLES_START").unwrap_or(0);
    let n = var("OSIS_ROLES_SEEDS").unwrap_or(40_000);
    let st = crate::on_every_core(|th, threads, st: &mut Stats| {
        let mut rng = Rng(Rng::thread(start, th).0 | 1);
        for _ in 0..n.div_ceil(threads as u64) {
            check(&random_world(&mut rng, &Rules::fixed()), &Rules::fixed(), false, st);
        }
    });
    st.print("paths");
    assert_holds(&st, &format!("OSIS_ROLES_START={start}"));
}

#[test]
#[ignore = "property"]
fn small_family_holds_exhaustive() {
    let st = crate::on_every_core(|th, threads, st: &mut Stats| {
        for i in (th..FAMILY).step_by(threads) {
            check(&family(i, &Rules::fixed()), &Rules::fixed(), false, st);
        }
    });
    st.print("paths family");
    assert_holds(&st, "family");
}

/// X, cut from A but still admin on T1 through A2, vouches through A2 for its own grant through
/// A, stamped before the removal and received by nobody: it applies (finding 10, nobody vouches
/// for its own signer's commit, argued for vouches; lands with A1).
#[test]
#[ignore = "notes/path-model-findings.md 10: a vouch counts for a commit of its own signer"]
fn repro_a_removed_signer_vouches_for_nothing_of_its_own() {
    let (mut w, ..) = paired();
    w.edge(K, 1, &[], A2, X, Admin, &[]);
    w.edge(H, 1, &[A], T1, A2, Admin, &[]);
    let gz = w.edge(X, 2, &[A], T1, Z, Admin, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.vouch(X, 7, &[A2], T1, r, &[gz]);
    let rd = judge(&w, &Rules::fixed(), &View::all(&w).trusting(&[r]));
    assert!(!rd.applied.contains(&gz) && rd.role(Z, T1) == Gone, "{rd:?}");
}
