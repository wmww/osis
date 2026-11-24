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

// ---- Role writes a removal does not list (issues/role-vouch-contested.md) ----

/// X shares T1 with A2; K writes; H, who does not sync T1, removes X.
fn shared_by_x() -> (World, Id, Id, Id, Id) {
    let (mut w, ..) = paired();
    let gs = w.edge(X, 2, &[A], T1, A2, Write, &[]);
    let kc = w.content(K, 3, &[A2], T1);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let later = w.content(K, 8, &[A2], T1);
    (w, gs, kc, r, later)
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

/// A role write of X that H's removal does not list falls, with what rests on it, whoever else
/// received it; listed, it stands.
#[test]
fn a_grant_the_removal_does_not_list_falls_and_a_listed_one_stands() {
    let (mut w, gs, kc, r, later) = shared_by_x();
    let rd = fixed(&w, &[r]);
    assert!(!rd.applied.contains(&gs) && rd.role(A2, T1) == Gone && !rd.shows(kc) && !rd.shows(later), "{rd:?}");
    let f = w.cut(&[gs]);
    w.edit(r, |k| k.listing(f));
    let rd = fixed(&w, &[r]);
    assert!(rd.applied.contains(&gs) && rd.role(A2, T1) == Write && rd.valid.contains(&kc) && rd.valid.contains(&later), "{rd:?}");
}

/// The same for a removal X made: unlisted, it is undone and A2 holds T1 again; listed, it stands.
#[test]
fn a_removal_the_removed_party_made_stands_only_where_listed() {
    let (mut w, out, r, kc) = unshared_by_x();
    let rd = fixed(&w, &[r]);
    assert!(!rd.applied.contains(&out) && rd.role(A2, T1) == Write && rd.valid.contains(&kc), "{rd:?}");
    let f = w.cut(&[out]);
    w.edit(r, |k| k.listing(f));
    let rd = fixed(&w, &[r]);
    assert!(rd.applied.contains(&out) && rd.role(A2, T1) == Gone && !rd.shows(kc), "{rd:?}");
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
fn a_collateral_grantees_writes_count_from_its_first_grant_by_right() {
    let (w, week, r, after) = collateral();
    let rd = with(&w, &[r], |x| x.regrant = Regrant::FirstByRight);
    assert!(rd.valid.contains(&week) && rd.valid.contains(&after));
}

/// The fix's cost: a grant the thief backdates is made by right (C2), so a holder granted later may
/// stamp content back to it.
#[test]
fn a_backdated_grant_moves_a_current_holders_first_point_back() {
    let (mut w, ..) = paired();
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.edge(X, 2, &[A], T1, A2, Write, &[]);
    w.edge(B, 7, &[A], T1, A2, Write, &[]);
    let early = w.content(K, 4, &[A2], T1);
    assert!(!design(&w, &[r]).shows(early));
    assert!(with(&w, &[r], |x| x.regrant = Regrant::FirstByRight).valid.contains(&early));
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
    let rd = with(&w, &[r], |x| x.regrant = Regrant::FirstByRight);
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

// ---- Mutual removal ----

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

/// The pair no rule over the held set tells apart (issues/role-vouch-contested.md, Why no vouch
/// can work), read by the rule: X removed N5 at 3 and only B received it; H removes X listing
/// nothing. X's removal of N5 is undone, so N5's key is an admin's: its grant of admin to a key Z
/// after the theft applies, at every node and trusted or not (the cost the issue accepts until
/// someone removes N5 again). N5's backdated removal of B: at a node trusting nothing X's removal
/// of N5 drops it before H's removal drops that, and a drop stands for good; where H's removal is
/// trusted its seeds drop X's removal of N5 first, and B is removed.
#[test]
fn a_removal_the_remover_did_not_hold_is_undone() {
    let (mut w, gx, gb) = paired();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let out5 = w.edge(X, 3, &[], A, N5, Gone, &[g5]);
    let down = w.edge(N5, 2, &[], A, B, Gone, &[gb]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[gx]);
    let gz = w.edge(N5, 7, &[], A, Z, Admin, &[]);
    for (t, b) in [(&[][..], Admin), (&[r], Gone)] {
        let rd = fixed(&w, t);
        assert!(!rd.applied.contains(&out5) && rd.applied.contains(&gz) && rd.applied.contains(&down) == (b == Gone), "{t:?}: {rd:?}");
        assert_eq!((rd.role(N5, A), rd.role(Z, A), rd.role(B, A)), (Admin, Admin, b), "{t:?}");
    }
}

/// A lowering the removed node made stays made where the remover lists it (X's removal of N5)
/// and is undone where it does not (X's demotion of B, which only B received).
#[test]
fn a_lowering_the_removed_node_made_before_stays_made_only_where_listed() {
    let (mut w, _, gb) = paired();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let out = w.edge(X, 2, &[], A, N5, Gone, &[g5]);
    let down = w.edge(X, 3, &[], A, B, Write, &[gb]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[out]);
    let rd = fixed(&w, &[r]);
    assert!(rd.applied.contains(&out) && !rd.applied.contains(&down) && rd.role(N5, A) == Gone && rd.role(B, A) == Admin);
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
    // exempt, the timed grant stays and H's admin ends at 7
    assert!(fixed_but(&w, &[r], |x| x.exempt_chain = true).role(H, A) == Gone);
    // untrusted, the removal applies with H's record edge and drops the timed grant alike
    assert_eq!(fixed(&w, &[]).roles, rd.roles);
    assert!(disputes(&w, &Rules::fixed(), &View::all(&w)).is_empty());
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
/// junk grant to the remover, a lowering the removed node made that the remover did not list
/// (2), a backdated leave (14).
#[test]
fn the_other_findings_read_the_same_with_nothing_exempt() {
    let (mut w, _, gb) = paired();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let out = w.edge(X, 2, &[], A, N5, Gone, &[g5]);
    let junk = w.edge(N5, 3, &[], A, H, Admin, &[]);
    let down = w.edge(X, 3, &[], A, B, Write, &[gb]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[out]);
    let rd = fixed(&w, &[r]);
    assert!(rd.applied.contains(&out) && !rd.applied.contains(&down) && !rd.shows(junk) && rd.role(N5, A) == Gone && rd.role(B, A) == Admin);

    let (mut w, _, gb) = paired();
    let down = w.edge(X, 3, &[], A, B, Write, &[gb]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[down]);
    let leave = w.edge(X, 2, &[], A, X, Gone, &[]);
    let rd = fixed(&w, &[r]);
    assert!(!rd.applied.contains(&leave) && rd.applied.contains(&down) && rd.role(B, A) == Write);
}

// ---- Descent, self-removal by path end, `until` ----

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
    let rd = fixed(&w, &[r]);
    assert!(!rd.applied.contains(&leave) && rd.applied.is_superset(&Set::from([down, g5])));
    assert_eq!((rd.role(B, A), rd.role(N5, A)), (Write, Admin));
    let rd = fixed_but(&w, &[r], |x| x.leave_in_question = false);
    assert!(rd.applied.contains(&leave) && !rd.applied.contains(&down) && rd.role(N5, A) == Gone);
}

// ---- The searches (properties: every roles-model gate selects them, and nothing else can move them) ----

fn assert_holds(st: &Stats, what: &str) {
    for k in ["safety", "liveness", "alike", "removal kept", "removal", "own path", "untrusted", "dispute", "safety N", "own path N", "held first", "no order"] {
        assert!(st.checked.get(k).is_some_and(|n| *n > 0), "{what}: no {k} check ran");
    }
    for k in ["void", "idle", "one reading"] {
        assert!(st.checked.get(k).is_some_and(|n| *n > 0), "{what}: no {k} check ran");
    }
    assert!(st.failures() == 0, "{what}: {:?}\n{:?}", st.fails, st.first);
}

/// Under the first round's reading the wanted behaviour fails where the findings say.
#[test]
#[ignore = "property"]
fn the_notes_rules_fail_liveness_and_alike_plain() {
    let st = random_from(0, 400, &Rules::design());
    for k in ["liveness", "alike"] {
        assert!(st.fails.contains_key(k), "{k}: {:?}", st.fails);
    }
}

/// Each fix alone is needed: without it the search fails.
#[test]
#[ignore = "property"]
fn each_fix_is_needed_plain() {
    let f = Rules::fixed();
    let cases = [
        ("leaves", Rules { evidence_leaves: false, ..f }),
        ("no-void", Rules { self_void: false, ..f }),
        ("listed", Rules { stands: false, ..f }),
        ("exempt", Rules { exempt_chain: true, ..f }),
        ("once", Rules { rewrite: false, ..f }),
        ("no-own", Rules { sides: Sides::NoOwn, ..f }),
        ("no-receipt", Rules { sides: Sides::NoReceipt, ..f }),
    ];
    for (name, rules) in cases {
        assert!(random_from(0, 100, &rules).failures() > 0, "{name}");
    }
    // a backdated leave reaches the search through three of the thief's moves: 400 worlds
    assert!(random_from(0, 400, &Rules { leave_in_question: false, ..f }).failures() > 0, "leave");
    // the variant recording a lowering only where it took its hop down fails rarely (finding 52)
    assert!(random_from(0, 1000, &Rules { sides: Sides::Lowered, ..f }).failures() > 0, "lowered");
}

/// Random worlds `OSIS_ROLES_START` (default 0) on, `OSIS_ROLES_SEEDS` many (13,000: about 215
/// CPU-s), a thread per core, each from its own index (a larger sample is split across holds by
/// the start, as `-- N paths --from K` splits a search).
#[test]
#[ignore = "property"]
fn random_worlds_hold_large() {
    let start = crate::env_u64("OSIS_ROLES_START").unwrap_or(0);
    let n = crate::env_u64("OSIS_ROLES_SEEDS").unwrap_or(13_000);
    let st = random_from(start, n, &Rules::fixed());
    st.print("paths", &Rules::fixed());
    assert_holds(&st, &format!("OSIS_ROLES_START={start}"));
}

/// Every 367th world of the small family (22,501 worlds; `-- 0 paths-exh` runs all
/// of them by hand): a stride coprime with every dimension's size (2, 4, 6, 56;
/// `family_on_every_core` refuses one that is not), so every value of every dimension is reached
/// and none is tied to another (an even stride keeps `h_t1` false in every world): each thief
/// move about 400 times, stamped before and after the removal alike, each setup field's values
/// in equal shares.
#[test]
#[ignore = "property"]
fn small_family_holds_large() {
    let st = family_run(&Rules::fixed(), 367);
    st.print("paths family", &Rules::fixed());
    assert_holds(&st, "family");
}

/// A dead grant moves no first point back (notes/write-path-design.md §1, Judging content, C2): A2
/// administers T1 and X writes A2, a path H's removal of X from A does not touch. After the
/// removal X grants Z write through [A2] at 7 by may-grant, by right, and Z writes T1 at 7, before its
/// grant in key order. X's grant of write to Z through [A], stamped at the removal's `ts` and
/// ordered after it, applies nowhere and is made with no right in this reading, so Z's write
/// counts from its grant through [A2] with or without the dead grant: it shows in neither.
#[test]
fn a_dead_grant_moves_no_may_grant_grantees_first_point_back() {
    let (mut w, ..) = paired();
    w.edge(K, 1, &[], A2, X, Write, &[]);
    w.edge(H, 1, &[A], T1, A2, Admin, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let dead = w.edge(X, 6, &[A], T1, Z, Write, &[]);
    let inv = w.edge(X, 7, &[A2], T1, Z, Write, &[]);
    let c = w.content(Z, 7, &[], T1);
    assert!(w.key(r) < w.key(dead) && w.pos(c) < w.key(inv));
    let x = Rules::fixed();
    let v = View::all(&w).trusting(&[r]);
    let rd = judge(&w, &x, &v);
    assert!(!rd.applied.contains(&dead) && rd.by_flag.contains(&inv) && rd.role(Z, T1) == Write && !rd.valid.contains(&c), "{rd:?}");
    let rd = judge(&w, &x, &v.clone().without(&[dead]));
    assert!(rd.by_flag.contains(&inv) && rd.role(Z, T1) == Write && !rd.valid.contains(&c), "{rd:?}");
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
    assert_eq!(no_effect(&w, &Rules::fixed(), &View::all(&w), &rd, zb), (true, true));
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
    assert_eq!(no_effect(&w, &Rules::fixed(), &View::all(&w), &rd, lb), (true, true));
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
    assert_eq!(no_effect(&w, &Rules::fixed(), &View::all(&w), &rd, early), (true, true));
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
    assert_eq!(no_effect(&w, &Rules::fixed(), &View::all(&w), &rd, h), (true, true));
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
    assert_eq!(no_effect(&w, &Rules::fixed(), &View::all(&w), &rd, l), (true, true));
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

/// Small worlds of admins granting and removing each other (`tiny`), of may-grant (`tiny_flags`;
/// README.md, Paths, for the search), and of a thing detached from its folder written by marked
/// direct hops (`tiny_detached`): one reading under a relabelling. Controls: a lowering whose drops take its author's
/// standing applying, a commit of several parts loses its path's authority (`self-taken`); in
/// `tiny_flags`, `-no-flag` grants with no right (`may-grant right`) and `-role-falls` leaves a
/// grant standing past the flag's clearing (`may-grant audited`).
#[test]
#[ignore = "property"]
fn small_worlds_hold_plain() {
    for (flags, detached, keyed) in [(false, false, false), (true, false, false), (false, true, false), (false, false, true)] {
        for honest in [Honesty::None, Honesty::Lists, Honesty::Writers] {
            let st = tiny_run_from(0, 3000, &Rules::fixed(), TinyMode { flags, detached, keys: keyed, honest });
            // honest writers make few writes that do not apply: their worlds check `honest` alone here
            let ran = |k: &str| st.checked.get(k).is_some_and(|n| *n > 0);
            let keys: &[&str] = if honest == Honesty::Writers { &["honest"] } else { &["void", "honest", "idle N", "unapplied N"] };
            assert!(st.failures() == 0 && keys.iter().all(|k| ran(k)), "{flags} {detached} {keyed} {honest:?} {:?} {:?} {:?}", st.checked, st.fails, st.first);
        }
    }
    let no_void = tiny_run_from(0, 1000, &Rules { self_void: false, ..Rules::fixed() }, TinyMode { flags: false, detached: false, keys: false, honest: Honesty::None });
    assert!(no_void.fails.get("self-taken").is_some_and(|n| *n > 0), "{:?}", no_void.fails);
    let flags = TinyMode { flags: true, detached: false, keys: false, honest: Honesty::None };
    for (rules, k) in [(Rules { flag_check: false, ..Rules::fixed() }, "may-grant right"), (Rules { flag_falls: false, ..Rules::fixed() }, "may-grant audited")] {
        let st = tiny_run_from(0, 3000, &rules, flags);
        assert!(st.fails.get(k).is_some_and(|n| *n > 0), "{k} {:?}", st.fails);
    }
    let keys = TinyMode { flags: false, detached: false, keys: true, honest: Honesty::None };
    for (rules, k) in [(Rules { key_hop: false, ..Rules::fixed() }, "key audited"), (Rules { key_hop: false, ..Rules::fixed() }, "key right")] {
        let st = tiny_run_from(0, 3000, &rules, keys);
        assert!(st.fails.get(k).is_some_and(|n| *n > 0), "{k} {:?}", st.fails);
    }
}

/// What a party with admin can make a reader walk (finding 17): X grants k keys of its own admin
/// and each removes X listing nothing, so each would drop its own grant and is void; H removes X.
/// At a node trusting nothing each void removal costs its check (the setters of its path read
/// back: one each) and H's removal one restart; trusting H's removal, X's grants are seeds and no
/// removal of a key holds the right. Returns (restarts, commits visited, setters read) for each.
fn void_cost(k: usize) -> ((u32, u64, u64), (u32, u64, u64)) {
    let (mut w, ..) = paired();
    for z in 0..k {
        w.edge(X, 1, &[], A, 23 + z as Thing, Admin, &[]);
    }
    for z in 0..k {
        w.edge(23 + z as Thing, 2, &[], A, X, Gone, &[]);
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
    // one restart, for H's removal
    assert!(small.0 .0 == 1 && large.0 .0 == 1 && small.1 .0 == 0 && large.1 .0 == 0);
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
        let z = |i: usize| 23 + i as Thing;
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

/// A node trusting nothing: X backdates a removal of H to 5, listing its own and B's grants; H
/// removes X at 6. In the plain walk X's removal applies at its key and H's then holds no right:
/// the node is shown H's removal as a dispute, never a silent loss, and trusting it gives the
/// members' reading.
#[test]
fn a_node_trusting_nothing_is_shown_the_removal_as_a_dispute() {
    let (mut w, gx, gb) = paired();
    let rx = w.edge(X, 5, &[], A, H, Gone, &[gx, gb]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let plain = fixed(&w, &[]);
    assert!(!plain.applied.contains(&r) && plain.applied.contains(&rx) && plain.stray.is_empty());
    assert_eq!(disputes(&w, &Rules::fixed(), &View::all(&w)), vec![r]);
    let rd = fixed(&w, &[r]);
    assert!(rd.void.is_empty() && !rd.shows(rx) && rd.role(H, A) == Admin && rd.role(X, A) == Gone);
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
    let moves = [Move { kind: 21, ts: 2, made: 5 }, Move { kind: 27, ts: 2, made: 5 }];
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

/// Findings 45, 46 (L3): the thief, heard before the removal, grants H admin until 7 (move 21,
/// stamped 3, made 5); H removes X at 6. The removal applies with that grant held, but H's own
/// path then ends at 7 where without it H stands: H's list leaves it out, the removal drops it, and
/// H stays a standing admin. Control (`-no-end`: kept wherever the removal applies) H's list keeps
/// it and H's admin ends at 7 (`own path` fails).
#[test]
fn the_removers_list_leaves_out_an_end_on_its_own_path() {
    let s = Setup { b_side_x: true, ..Setup::default() };
    let moves = [Move { kind: 21, ts: 3, made: 5 }];
    let own_path = |rules: Rules| {
        let m = Sim::build(&s, &rules, &moves, &mut Rng(0));
        let mut st = Stats::default();
        check(&m, &rules, &mut st);
        (judge(&m.w, &rules, &m.view(H, &rules)).role(H, A), st.fails.get("own path").copied().unwrap_or(0))
    };
    assert_eq!(own_path(Rules::fixed()), (Admin, 0));
    let (role, fails) = own_path(Rules { own_end: false, ..Rules::fixed() });
    assert!(role == Gone && fails > 0, "{role:?} {fails}");
}

/// L3's hand worlds (notes/write-path-design.md §6, 2): M mints A, grants H admin until 20 (H's
/// only grant) and X admin; H removes X at 6, listing by the writers' rule what it received, in that
/// order. X's grant of B is kept (the removal applies with it, H's path ends at 20 either way); X
/// shortening H's grant to 7 is left out (with it H's path ends at 7); X's end on B's admin is kept
/// (on no hop of H's path); X's grant of a made-up key Z, which sets H's admin to end at 7, is left
/// out (with it Z's end applies). Trusted, H stays admin until 20. Control `-no-end`: every one is
/// kept (the removal applies with each) and H's admin ends at 7.
#[test]
fn the_writers_rule_leaves_out_what_ends_the_removers_path_sooner() {
    let mut w = minted_by(M);
    let gh = w.push(M, 1, &[], A, Kind::set(H, Admin).until(20));
    let gx = w.push(M, 1, &[], A, Kind::set(X, Admin));
    let gb = w.push(X, 2, &[], A, Kind::set(B, Admin));
    let gz = w.push(X, 2, &[], A, Kind::set(Z, Admin));
    let zs = w.push(Z, 3, &[], A, Kind::set(H, Admin).until(7));
    let eb = w.push(X, 4, &[], A, Kind::set(B, Admin).until(8));
    let short = w.push(X, 4, &[], A, Kind::set(H, Admin).until(7));
    let r = w.push(H, 6, &[], A, Kind::set(X, Gone));
    let recv = [gh, gx, gb, gz, zs, eb, short];
    let h_at = |rules: &Rules| {
        let mut w = w.clone();
        let l = writers_list(&w, rules, r, &recv);
        let f = w.cut(&l);
        w.edit(r, |k| k.listing(f));
        let rd = judge(&w, rules, &View::all(&w).trusting(&[r]));
        assert!(rd.applied.contains(&r) && rd.void.is_empty(), "{rd:?}");
        (l, rd.state.get(&(H, A)).copied())
    };
    assert_eq!(h_at(&Rules::fixed()), (vec![gb, eb], Some((Admin, Some(20)))));
    assert_eq!(h_at(&Rules { own_end: false, ..Rules::fixed() }), (vec![gb, gz, eb, short], Some((Admin, Some(7)))));
}

/// L3 clause by clause, where H's only admin is X's grant (M mints A and grants X admin; H
/// removes X at 6, listing by the writers' rule what it received, in that order). A write with
/// which the removal still does not apply is left out (X's grant of B, received before X's timed
/// grant of H); where the removal applies with everything named and its path has no end (X's grant
/// of H standing), everything is named, X's grant of B with it; each write is compared with the
/// end the list kept so far gives (X shortening its timed grant of H to 7 is left out against the
/// end 20 that grant gave, though the removal with no list at all would not apply).
#[test]
fn the_writers_rule_reads_each_clause() {
    let list = |until: Option<u32>, short: bool| {
        let mut w = minted_by(M);
        let gx = w.push(M, 1, &[], A, Kind::set(X, Admin));
        let k = Kind::set(H, Admin);
        let gh = w.push(X, 2, &[], A, match until { Some(u) => k.until(u), None => k });
        let gb = w.push(X, 3, &[], A, Kind::set(B, Admin));
        let mut recv = vec![gx, gb, gh];
        if short {
            recv = vec![gx, gh, w.push(X, 4, &[], A, Kind::set(H, Admin).until(7))];
        }
        let r = w.push(H, 6, &[], A, Kind::set(X, Gone));
        (writers_list(&w, &Rules::fixed(), r, &recv), gh, gb)
    };
    let (l, gh, _) = list(Some(20), false);
    assert_eq!(l, vec![gh]);
    let (l, gh, gb) = list(None, false);
    assert_eq!(l, vec![gb, gh]);
    let (l, gh, _) = list(Some(20), true);
    assert_eq!(l, vec![gh]);
}

/// Finding 49 (`tiny` with honest lists, world 387049 shrunk; every write held, nothing trusted):
/// H grants Z admin and N6 admin until 4 at 2; Z grants N6 admin at 5; N6 sets H's admin to end at
/// 9 at 7 and makes it standing again at 8; H removes Z at 10, listing nothing; Z removes N6 at 12.
/// Held, N6's second write gives H admin at 10 in the first pass: H's removal is judged there and
/// drops Z's grant of N6, so neither of N6's writes applies in the end (N6 never held its right),
/// and Z's removal of N6, reached with no right, never applies. Without it, the first pass reaches
/// Z's removal of N6 with Z still admin (H's admin ended at 9) and judges it applied, a verdict it
/// keeps once H's removal applies in a later pass: N6's edge is cut at 12. An idle write of a party
/// that held its right in no reading decides whether a removal applies, unshown (the class of 35,
/// gated as `illegit gains`).
#[test]
#[ignore = "notes/path-model-findings.md 49: an idle write of a party with no right decides a removal"]
fn repro_an_idle_write_with_no_right_decides_nothing() {
    let mut w = account();
    w.push(Z, 12, &[], A, Kind::set(N6, Gone));
    let again = w.push(N6, 8, &[], A, Kind::set(H, Admin).listing(w.cut(&[0])));
    w.push(N6, 7, &[], A, Kind::set(H, Admin).until(9).listing(w.cut(&[0, 1])));
    w.push(Z, 5, &[], A, Kind::set(N6, Admin).listing(w.cut(&[1, 2])));
    let r = w.push(H, 10, &[], A, Kind::set(Z, Gone));
    w.commit(H, 2, &[], A, vec![Kind::set(Z, Admin).listing(w.cut(&[0, 2])), Kind::set(N6, Admin).until(4).listing(w.cut(&[1, 3, 4]))]);
    let all = fixed(&w, &[]);
    let less = judge(&w, &Rules::fixed(), &View::all(&w).without(&[again]));
    assert!(!all.applied.contains(&again) && all.applied.contains(&r), "{all:?}");
    assert_eq!(less.observed(&w), all.observed(&w));
}

/// F1, a node sides with its own lowering: X, stolen, removes H at 5, honestly stamped and
/// received by every node at once (`Setup::x_first`); H removes X at 6, its list leaving X's
/// removal out (L3: with it the removal would not apply). H wrote its removal, so it trusts it:
/// its seeds take X's removal and H stands. B held X's removal first and records nothing for H's
/// (F3): its walk applies X's removal, H's holds no right there and is shown as a dispute;
/// choosing it reads as H does. Control `-no-own`: H's own walk applies X's removal and H's
/// removal holds no right at H (finding 48).
#[test]
fn a_remover_sides_with_its_own_removal() {
    let s = Setup { x_first: true, ..Setup::default() };
    let rules = Rules::fixed();
    let m = Sim::build(&s, &rules, &[], &mut Rng(0));
    let vh = m.view(H, &rules);
    let rd = judge(&m.w, &rules, &vh);
    assert!(vh.trust.contains(&m.r) && rd.applied.contains(&m.r) && rd.role(H, A) == Admin && rd.role(X, A) == Gone, "{rd:?}");
    let vb = m.view_unchosen(B, &rules);
    let rd = judge(&m.w, &rules, &vb);
    assert!(!vb.trust.contains(&m.r) && !rd.applied.contains(&m.r) && rd.role(H, A) == Gone && rd.role(X, A) == Admin, "{:?} {rd:?}", vb.trust);
    assert!(disputes(&m.w, &rules, &vb).contains(&m.r));
    let rd = judge(&m.w, &rules, &choose(&m.w, &rules, &vb, m.r));
    assert!(rd.applied.contains(&m.r) && rd.role(H, A) == Admin && rd.role(X, A) == Gone, "{rd:?}");
    let off = Rules { sides: Sides::NoOwn, ..rules };
    let m = Sim::build(&s, &off, &[], &mut Rng(0));
    let rd = judge(&m.w, &off, &m.view(H, &off));
    assert!(!rd.applied.contains(&m.r) && rd.role(H, A) == Gone, "{rd:?}");
}

/// A thief heard first keeps the nodes that heard it until their users choose (accepted:
/// notes/disputes.md). X, stolen, demotes H to write stamped 7, heard by H and B at 5 (move 25);
/// H removes X at 6. B held the demotion, applying, before H's removal arrived, a write ordered
/// before it that its list leaves out: B records the demotion (F2), its seeds take H's removal,
/// and B is told of the counter-removal (F5, `countered`). Choosing H's removal drops the record
/// of the demotion (F4) and reads as H does. Control `-choice-adds`: the demotion stays recorded,
/// its seeds take the removal chosen, and the choice is void.
#[test]
fn a_thief_heard_first_keeps_a_node_until_its_user_chooses() {
    let s = Setup::default();
    let rules = Rules::fixed();
    let mv = [Move { kind: 25, ts: 7, made: 5 }];
    let m = Sim::build(&s, &rules, &mv, &mut Rng(0));
    let down = *m.thief.keys().next().unwrap();
    let vh = m.view(H, &rules);
    let rd = judge(&m.w, &rules, &vh);
    assert!(vh.trust.contains(&m.r) && !vh.trust.contains(&down) && rd.applied.contains(&m.r) && rd.role(H, A) == Admin, "{:?} {rd:?}", vh.trust);
    let vb = m.view_unchosen(B, &rules);
    let rd = judge(&m.w, &rules, &vb);
    assert!(vb.trust.contains(&down) && !rd.applied.contains(&m.r) && rd.role(H, A) == Write && rd.role(X, A) == Admin, "{:?} {rd:?}", vb.trust);
    assert_eq!(countered(&m.w, &rules, &vb), vec![m.r]);
    let chosen = choose(&m.w, &rules, &vb, m.r);
    let rd = judge(&m.w, &rules, &chosen);
    assert!(!chosen.trust.contains(&down) && rd.applied.contains(&m.r) && rd.void.is_empty() && rd.role(H, A) == Admin && rd.role(X, A) == Gone, "{rd:?}");
    // its user chooses at `AFTER` in the story (`Sim::chose`): B's final view is that choice
    assert_eq!(m.chose.get(&B), Some(&vec![m.r]));
    assert_eq!(m.view(B, &rules).trust, chosen.trust);
    let off = Rules { sides: Sides::ChoiceAdds, ..rules };
    let rd = judge(&m.w, &off, &choose(&m.w, &off, &vb, m.r));
    assert!(rd.void.contains(&m.r) && rd.role(H, A) == Write, "{rd:?}");
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
        let m = Sim::build(&s, &Rules::fixed(), &[Move { kind: 31, ts: 3, made }], &mut Rng(0));
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
    let rd = fixed(&w2, &[r, r3]);
    assert!(rd.void.is_empty() && !rd.shows(leave) && rd.applied.contains(&r3) && rd.role(A, T1) == Admin);
}

/// Finding 21: a dispute whose own write is a no-op where trusted. X, admin on A2 (A2 admin on
/// T1), backdates through A2 a removal of A from T1 (`xa`) before its own removal of A2 from T1
/// through A (`xr`, which H's removal of X lists). A node trusting nothing: `xa` applies, so `xr`
/// and B's removal of A2 find no path. Trusted, B's removal drops `xa` by its seeds, `xr`
/// applies, and B's removal is a no-op (A2 is off T1 already): read as spec/permissions.md §5.1
/// words it (the trusted write must lower its edge) it raises no dispute, and the node reads A
/// off T1 silently. As a write that applies once trusted, it is shown.
#[test]
fn a_dispute_whose_write_is_a_no_op_where_trusted_is_shown() {
    let (mut w, ..) = paired();
    w.edge(K, 1, &[], A2, X, Admin, &[]);
    let gs = w.edge(B, 2, &[A], T1, A2, Admin, &[]);
    let xa = w.edge(X, 3, &[A2], T1, A, Gone, &[gs]);
    let xr = w.edge(X, 4, &[A], T1, A2, Gone, &[]);
    w.edge(H, 6, &[], A, X, Gone, &[xr]);
    let r3 = w.edge(B, 6, &[A], T1, A2, Gone, &[]);
    let plain = fixed(&w, &[]);
    assert!(plain.applied.contains(&xa) && !plain.applied.contains(&r3) && plain.role(A, T1) == Gone);
    let t = fixed(&w, &[r3]);
    assert!(t.applied.contains(&r3) && !t.lowered.contains(&r3) && t.applied.contains(&xr) && t.role(A, T1) == Admin);
    // shown too: `xr`, which trusted drops `xa` by its seeds
    assert_eq!(disputes(&w, &Rules::fixed(), &View::all(&w)), vec![xr, r3]);
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
        assert!(w.leave(timed));
        let rd = fixed(&w, &[r]);
        assert!(!rd.applied.contains(&timed) && rd.applied.is_superset(&Set::from([down, g5])), "{role:?}");
        let rd = fixed_but(&w, &[r], |x| x.leave_in_question = false);
        assert!(rd.applied.contains(&timed) && !rd.applied.contains(&g5), "{role:?}");
    }
}

/// A leave of a holder thing: X makes A leave T1, stamped before a grant B made
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
    let gn = w.edge(B, 3, &[A], T1, N6, Write, &[]);
    // K lists its own holder's grant too (else it drops its own authority and is void)
    let rk = w.edge(K, 6, &[A2], T1, A, Gone, &[g2, gn]);
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&rk) && !rd.applied.contains(&leave) && rd.applied.contains(&gn) && rd.role(N6, T1) == Write);
    let rd = fixed_but(&w, &[], |x| x.leave_in_question = false);
    assert!(rd.applied.contains(&leave) && !rd.applied.contains(&gn));
}

/// N5's removal of H from A (listing B's grant and H's share of T1, not N5's own grant) and of
/// A2's share of T1 (through A), in one commit or two. Returns the world and the two removals.
fn removals_on_two_things(one: bool) -> (World, Id, Id) {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    w.edge(H, 1, &[], A, N5, Admin, &[]);
    let share = w.edge(H, 1, &[A], T1, A2, Write, &[]);
    let on_a = w.edge(N5, 5, &[], A, H, Gone, &[gb, share]);
    let on_t = w.edge(N5, 5, &[A], T1, A2, Gone, &[]);
    if one {
        w.group(&[on_a, on_t]);
    }
    (w, on_a, on_t)
}

/// A commit's parts on different things are judged each on its own (finding 6): N5's removal on
/// A is void (it would drop N5's own grant) and its removal on T1 applies, whether or not the two
/// share a commit.
#[test]
fn a_commits_parts_on_two_things_are_judged_each_on_its_own() {
    for one in [true, false] {
        let (w, on_a, on_t) = removals_on_two_things(one);
        let rd = fixed(&w, &[]);
        assert!(rd.voided.contains(&on_a) && rd.applied.contains(&on_t) && rd.dropped.is_empty(), "{one}: {rd:?}");
        assert_eq!((rd.role(H, A), rd.role(N5, A), rd.role(A2, T1)), (Admin, Admin, Gone), "{one}");
    }
}

// ---- May-grant and finalizes (spec/permissions.md §2 along one path; notes/write-path-design.md §1 G1 to G5, Edge writes) ----

/// A with H; A2 (K's) shares T1 at write, and GU (A2's guests, minted with A2) holds read with the
/// may-grant flag on T1 (by H, through A): the arrangement letting a writer of A2 add readers of T1
/// and no more (G3); K gives X write on A2, so X's path [A2, GU] gives may-grant at read.
fn guests() -> World {
    let mut w = account();
    w.push(H, 1, &[A], T1, Kind::set(A2, Write));
    w.push(H, 1, &[A], T1, Kind::set(GU, Role::Read).may_grant());
    w.edge(K, 1, &[], A2, X, Write, &[]);
    w
}

/// A may-grant grant applies where every hop of its path gives its role and the last carries the
/// flag (G1, G2: X's [A2, GU]), to a holder with no current grant, and gives no right to change
/// another edge. Beyond the arrangement: write through [A2, GU] (GU holds read), and read through
/// [A2], whose share carries no flag. Controls: the flag not read (`-no-flag`) grants through
/// [A2]; the last hop's role not read grants write through [A2, GU].
#[test]
fn a_may_grant_grant_applies_by_its_paths_flag() {
    let mut w = guests();
    let z = w.push(X, 2, &[A2, GU], T1, Kind::set(Z, Role::Read));
    let beyond = w.push(X, 2, &[A2, GU], T1, Kind::set(N6, Write));
    let flagless = w.push(X, 2, &[A2], T1, Kind::set(N5, Role::Read));
    let again = w.push(X, 3, &[A2, GU], T1, Kind::set(Z, Role::Read).until(9));
    let lower = w.push(X, 4, &[A2, GU], T1, Kind::set(Z, Gone));
    let rd = fixed(&w, &[]);
    assert!(rd.by_flag.contains(&z) && ![beyond, flagless, again, lower].iter().any(|i| rd.applied.contains(i)), "{rd:?}");
    assert_eq!((rd.role(Z, T1), rd.role(N6, T1), rd.role(N5, T1)), (Role::Read, Gone, Gone));
    // control: a role on the last hop suffices, so a writer of A2 grants through A2's share
    let rd = fixed_but(&w, &[], |r| r.flag_check = false);
    assert_eq!((rd.role(N5, T1), rd.role(N6, T1)), (Role::Read, Gone));
}

/// G1's minimum (control `-last-hop`): a reader of A2 reaches GU's flag but holds read on its
/// first hop, so it grants readers and no writers, though GU's share would carry write.
#[test]
fn a_may_grant_grant_needs_its_role_on_every_hop() {
    let mut w = account();
    w.push(H, 1, &[A], T1, Kind::set(GU, Write).may_grant());
    w.edge(K, 1, &[], A2, X, Role::Read, &[]);
    let read = w.push(X, 2, &[A2, GU], T1, Kind::set(Z, Role::Read));
    let write = w.push(X, 2, &[A2, GU], T1, Kind::set(N6, Write));
    let rd = fixed(&w, &[]);
    assert!(rd.by_flag.contains(&read) && !rd.applied.contains(&write), "{rd:?}");
    let rd = fixed_but(&w, &[], |r| r.min_check = false);
    assert_eq!(rd.role(N6, T1), Write);
}

/// A grant through a hop carrying no flag is made with no right (G1): X grants N5 write through
/// [A2], whose share carries no flag, at 2; N5 writes T1 at 3; H grants N5 write at 5. N5's path
/// is re-granted from H's grant, its first by right, so the write at 3 stays invalid; were X's
/// grant by right it would count from 2.
#[test]
fn a_grant_by_a_flagless_hop_moves_no_first_point_back() {
    let mut w = guests();
    let x = w.push(X, 2, &[A2], T1, Kind::set(N5, Write));
    let c = w.content(N5, 3, &[], T1);
    let h = w.push(H, 5, &[A], T1, Kind::set(N5, Write));
    let rd = fixed(&w, &[]);
    assert!(!rd.applied.contains(&x) && rd.applied.contains(&h) && !rd.valid.contains(&c), "{rd:?}");
}

/// A writer removed from the holder it granted through: its may-grant grants rest on that edge,
/// fall unless the removal lists them, whether the edge fell from admin or from write.
#[test]
fn a_may_grant_grant_by_a_removed_writer_falls_unless_listed() {
    let mut w = guests();
    let z = w.push(X, 3, &[A2, GU], T1, Kind::set(Z, Role::Read));
    let n6 = w.push(X, 4, &[A2, GU], T1, Kind::set(N6, Role::Read));
    let r = w.edge(K, 6, &[], A2, X, Gone, &[z]);
    for trust in [vec![], vec![r]] {
        let rd = fixed(&w, &trust);
        assert!(rd.applied.contains(&z) && !rd.shows(n6), "{trust:?}");
        assert_eq!((rd.role(Z, T1), rd.role(N6, T1)), (Role::Read, Gone));
    }
    // control: only a fall from admin audits; trusting nothing the unlisted grant stands
    let rd = fixed_but(&w, &[], |r| r.any_fall = false);
    assert_eq!(rd.role(N6, T1), Role::Read);
}

/// An expired grant counts as none: a may-grant grant over it applies, before or after a finalize; a
/// finalize applies only to an ended grant, by a writer holding at least its role (an admin for a
/// timed admin grant), audits nothing and makes nothing standing.
#[test]
fn a_finalize_ends_an_ended_grant_and_a_may_grant_grant_follows_it() {
    let mut w = guests();
    let timed = w.push(X, 2, &[A2, GU], T1, Kind::set(Z, Role::Read).until(4));
    let early = w.push(K, 3, &[A2], T1, Kind::finalize(Z));
    w.push(X, 2, &[A2, GU], T1, Kind::set(N6, Role::Read));
    let by_reader = w.push(N6, 3, &[], T1, Kind::finalize(Z));
    let fin = w.push(K, 4, &[A2], T1, Kind::finalize(Z));
    let again = w.push(X, 5, &[A2, GU], T1, Kind::set(Z, Role::Read));
    let rd = fixed(&w, &[]);
    assert!([timed, fin, again].iter().all(|i| rd.applied.contains(i)));
    assert!(![early, by_reader].iter().any(|i| rd.applied.contains(i)));
    assert_eq!(rd.role(Z, T1), Role::Read);
    // without the finalize the grant over the ended one applies all the same
    let rd = judge(&w, &Rules::fixed(), &View::all(&w).without(&[fin]));
    assert!(rd.applied.contains(&again) && rd.role(Z, T1) == Role::Read);
    // a timed admin grant is finalized by an admin only (its role at least the grant's), not by a
    // writer: the finalize is the grant's departure for keys
    let mut w = guests();
    w.edge(H, 1, &[], A, B, Admin, &[]);
    w.push(H, 2, &[A], T1, Kind::set(N6, Admin).until(4));
    let by_writer = w.push(K, 5, &[A2], T1, Kind::finalize(N6));
    let by_admin = w.push(B, 6, &[A], T1, Kind::finalize(N6));
    let rd = fixed(&w, &[]);
    assert!(!rd.applied.contains(&by_writer) && rd.applied.contains(&by_admin));
}

/// A finalize is a shape (spec/permissions.md §2 Finalize: a frontier-less removal of another
/// holder's grant that is no self-removal), whatever a writer means: Z removing its own grant by
/// the empty path with no frontier is a self-removal and applies, so the finalize after it ends
/// nothing; Z removing its own grant along a path ending elsewhere is an explicit removal listing
/// nothing, which drops the grant Z made through it.
#[test]
fn a_frontier_less_removal_of_ones_own_grant_is_no_finalize() {
    let mut w = guests();
    w.push(X, 2, &[A2, GU], T1, Kind::set(Z, Role::Read).until(4));
    let leave = w.push(Z, 3, &[], T1, Kind::finalize(Z));
    let fin = w.push(K, 4, &[A2], T1, Kind::finalize(Z));
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&leave) && !rd.applied.contains(&fin));
    let mut w = account();
    w.edge(H, 1, &[], A, Z, Admin, &[]);
    w.push(H, 1, &[A], T1, Kind::set(Z, Admin).until(3));
    let n5 = w.edge(Z, 2, &[], T1, N5, Write, &[]);
    let own = w.push(Z, 5, &[A], T1, Kind::finalize(Z));
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&own) && rd.dropped.contains(&n5));
}

/// A self-removal lowers in every component (spec/permissions.md §2 Self-removal): a removal
/// always lowers, a timed grant's included; a rewrite setting the flag applies nothing; one
/// bringing the `until` earlier applies.
#[test]
fn a_self_removal_lowers_in_every_component() {
    let timed = |k: Kind| {
        let mut w = guests();
        w.push(X, 2, &[A2, GU], T1, Kind::set(Z, Role::Read).until(9));
        let leave = w.push(Z, 3, &[], T1, k);
        fixed(&w, &[]).applied.contains(&leave)
    };
    assert!(timed(Kind::set(Z, Gone)));
    assert!(timed(Kind::set(Z, Role::Read).until(5)));
    assert!(!timed(Kind::set(Z, Role::Read).until(9).may_grant()));
    assert!(!timed(Kind::set(Z, Role::Read)));
}

/// spec/permissions.md §7, a link: L, timed with the flag, grants; its `until` passing and the
/// finalize audit nothing (the grantee's writes stand by their own keys); the next explicit
/// removal of L audits against the edge as restored and drops the grants made by it it does not
/// list.
#[test]
fn the_explicit_removal_after_a_finalize_audits_the_grants_made_by_flag() {
    let mut w = account();
    let l = N6;
    w.push(H, 1, &[A], T1, Kind::set(l, Write).may_grant().until(5));
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

/// A re-grant clearing the flag the share carried lowers it (G5): it audits the may-grant grants
/// made by it, and an honest one lists them (story: B's re-grant of A2 keeps the flag and lists).
/// Control `-role-falls` (only a fall in role is judged): the unlisted grant stands.
#[test]
fn a_write_clearing_the_flag_audits_the_grants_made_by_it() {
    let mut w = guests();
    let z = w.push(X, 2, &[A2, GU], T1, Kind::set(Z, Role::Read));
    let plain = w.push(B, 5, &[A], T1, Kind::set(GU, Role::Read));
    w.edge(H, 1, &[], A, B, Admin, &[]);
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&plain) && rd.dropped.contains(&z));
    assert_eq!(fixed_but(&w, &[], |r| r.flag_falls = false).role(Z, T1), Role::Read);
    w.edit(plain, |k| k.listing(BTreeMap::from([(T1, Set::from([z]))])));
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&z) && rd.role(Z, T1) == Role::Read);
}

/// The edge as restored reads a value's role and flag alike, its `until` disregarded (notes/
/// write-path-design.md §1 W3): H gives N5 write with the flag; N5 grants Z read by it and writes
/// content; H sets N5 write with the flag until 3 at 4 (ended at its own `ts`), listing both; H
/// removes N5 at 5 listing nothing. Restored, N5's edge gave write with the flag before the
/// removal, so it takes both: Z's grant falls as the content does.
#[test]
fn an_ended_value_restores_its_flag_as_its_role() {
    let mut w = account();
    w.push(H, 1, &[], A, Kind::set(N5, Write).may_grant());
    let z = w.push(N5, 2, &[], A, Kind::set(Z, Role::Read));
    let c = w.content(N5, 2, &[], A);
    let ended = w.push(H, 4, &[], A, Kind::set(N5, Write).may_grant().until(3));
    w.edit(ended, |k| k.listing(BTreeMap::from([(A, Set::from([z, c]))])));
    w.edge(H, 5, &[], A, N5, Gone, &[]);
    let rd = fixed(&w, &[]);
    assert!(!rd.valid.contains(&c), "{rd:?}");
    assert!(rd.dropped.contains(&z) && rd.role(Z, A) == Gone, "{rd:?}");
}

/// A lowering applied by its verdict only lowers (finding 27): N6, admin by H's grant, grants Z
/// write and demotes it to read, which is judged (a fall from write) and applied; B removes H not
/// listing H's grant of N6, which drops it, and the restart finds N6 with no authority. Its
/// demotion, applied for good, does not raise Z from none to read there: Z ends with nothing, as
/// without the grant, at a node trusting nothing and one trusting the removal alike.
#[test]
fn a_lowering_applied_by_its_verdict_raises_nothing() {
    let mut w = account();
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    w.edge(H, 1, &[], A, N6, Admin, &[]);
    let z = w.edge(N6, 3, &[], A, Z, Write, &[]);
    w.edge(N6, 3, &[], A, Z, Role::Read, &[]);
    let r = w.edge(B, 7, &[], A, H, Gone, &[gb]);
    for trust in [vec![], vec![r]] {
        let rd = fixed(&w, &trust);
        assert_eq!(rd.role(Z, A), Gone, "{trust:?}");
        assert_eq!(no_effect(&w, &Rules::fixed(), &View::all(&w).trusting(&trust), &rd, z), (true, true), "{trust:?}");
    }
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

/// An edge write whose holder is its target is not applied (spec/permissions.md §1), whoever
/// writes it: A's admin H granting A admin on A, and A acting as itself on its own edge, set
/// nothing; H's grant to X beside them applies.
#[test]
fn an_edge_write_whose_holder_is_its_target_is_not_applied() {
    let (mut w, gx, _) = paired();
    let by_admin = w.edge(H, 2, &[], A, A, Admin, &[]);
    let by_itself = w.edge(A, 3, &[], A, A, Gone, &[]);
    assert!(!w.well(by_admin) && !w.well(by_itself));
    let rd = design(&w, &[]);
    assert!(rd.applied.contains(&gx) && !rd.applied.contains(&by_admin) && !rd.applied.contains(&by_itself));
    assert_eq!((rd.role(A, A), rd.role(X, A)), (Gone, Admin));
}

/// One commit states one path (notes/path-form.md, One path): X, granted admin on A, writes A,
/// T1 (minted by A) and D1 (minted by T1) stating [A]: A is the path's end, the others hang from
/// it by record edges, and every part rests on (X, A) alone above the descent. H's removal of X
/// cuts them alike. A thing the path's end does not reach (A2), and a thing listed before the
/// end (A stated [A, T1]: named twice), are written by no part of it.
#[test]
fn a_commit_writes_its_paths_end_and_what_hangs_from_it() {
    let (mut w, ..) = paired();
    let ids = w.stated(X, 3, &[A], 0, &[A, T1, D1]);
    assert_eq!(w.hops(ids[0]), &[(X, A)]);
    assert_eq!(w.hops(ids[1]), &[(X, A), (A, T1)]);
    assert_eq!(w.hops(ids[2]), &[(X, A), (A, T1), (T1, D1)]);
    let off = w.stated(X, 3, &[A], 0, &[A2])[0];
    let above = w.stated(X, 3, &[A, T1], 0, &[A, T1]);
    assert!(!w.well(above[0]) && w.well(above[1]));
    let rd = fixed(&w, &[]);
    assert!(ids.iter().all(|i| rd.valid.contains(i)) && !rd.valid.contains(&off) && !rd.valid.contains(&above[0]) && rd.valid.contains(&above[1]));
    let r = w.edge(H, 6, &[], A, X, Gone, &[ids[1]]);
    let rd = fixed(&w, &[r]);
    assert!(rd.valid.contains(&ids[1]) && !rd.valid.contains(&ids[0]) && !rd.valid.contains(&ids[2]));
}

/// Proposed (`Rules::author_thing`): a write may be by the thing it writes. X writes T1 stating
/// [A, T1] and naming T1; B, another writer of T1, purges by author T1 and takes exactly that
/// delta, not X's edit by A nor its own. Without the variant no request's chain holds T1. A
/// request by a signer with no path to T1 is invalid and takes nothing either way.
#[test]
fn a_write_by_the_thing_it_writes_is_purged_by_any_writer_of_it() {
    let (mut w, ..) = paired();
    let by_thing = w.stated(X, 2, &[A, T1], 2, &[T1])[0];
    assert_eq!(w.purge_author(by_thing), T1);
    let by_a = w.content_as(X, 2, &[A], T1, 1);
    let own = w.content(B, 2, &[A], T1);
    let q = w.purge(B, 3, &[A], T1, T1);
    let stray = w.purge(Z, 3, &[], T1, T1);
    let rd = fixed_but(&w, &[], |r| r.author_thing = true);
    assert!(rd.valid.contains(&q) && !rd.valid.contains(&stray));
    assert_eq!(rd.purged, Set::from([by_thing]));
    assert!(!rd.purged.contains(&by_a) && !rd.purged.contains(&own));
    assert!(fixed(&w, &[]).purged.is_empty());
}

/// A commit whose things need different paths (notes/path-form.md, The split form) is judged per
/// thing exactly as one commit per thing at the same key: X writes T1 along [A] (H's grant) and
/// A2 along its own grant from K ([]), in one commit and as two. Every reading agrees: both valid;
/// H's removal of X from A takes T1's part and leaves A2's (the commit half valid, as any commit
/// whose deltas are judged on their own, spec/commits.md §4); K's removal the other way round; a
/// removal listing the commit keeps T1's part; X's purge by author on T1 takes T1's part alone. A
/// unit holding T1's part needs no edge of A2's path as evidence, and the reverse.
#[test]
fn a_commit_spanning_two_paths_is_judged_per_thing_as_one_commit_per_thing() {
    // `then` adds the later writes to both worlds alike; the parts keep their ids in both
    let build = |one: bool, then: &dyn Fn(&mut World, [Id; 2])| {
        let (mut w, ..) = paired();
        let gk = w.edge(K, 1, &[], A2, X, Write, &[]);
        let s = if one {
            let v = w.split(X, 3, X, &[(&[A], T1), (&[], A2)]);
            [v[0], v[1]]
        } else {
            [w.content(X, 3, &[A], T1), w.content(X, 3, &[], A2)]
        };
        then(&mut w, s);
        (w, s, gk)
    };
    type Then = Box<dyn Fn(&mut World, [Id; 2]) -> Vec<Id>>;
    // (later writes, trusted among them, which parts stand, which are purged)
    let cases: Vec<(Then, [bool; 2], [bool; 2])> = vec![
        (Box::new(|_, _| vec![]), [true, true], [false, false]),
        (Box::new(|w, _| vec![w.edge(H, 6, &[], A, X, Gone, &[])]), [false, true], [false, false]),
        (Box::new(|w, _| vec![w.edge(K, 6, &[], A2, X, Gone, &[])]), [true, false], [false, false]),
        (Box::new(|w, s| vec![w.edge(H, 6, &[], A, X, Gone, &[s[0]])]), [true, true], [false, false]),
        (Box::new(|w, _| { w.purge(X, 4, &[A], T1, X); vec![] }), [true, true], [true, false]),
    ];
    for (k, (then, stand, purged)) in cases.iter().enumerate() {
        let trust = std::cell::RefCell::new(vec![]);
        let run = |one| {
            let (w, s, _) = build(one, &|w, s| *trust.borrow_mut() = then(w, s));
            (fixed(&w, &trust.borrow()), w, s)
        };
        let (rd1, w1, s) = run(true);
        let (rd2, ..) = run(false);
        assert_eq!(w1.cid(s[0]), w1.cid(s[1]), "one commit");
        assert_eq!((&rd1.valid, &rd1.purged, &rd1.applied, &rd1.roles), (&rd2.valid, &rd2.purged, &rd2.applied, &rd2.roles), "case {k}");
        assert_eq!(s.map(|i| rd1.valid.contains(&i)), *stand, "case {k}");
        assert_eq!(s.map(|i| rd1.purged.contains(&i)), *purged, "case {k}");
    }
    let (w, s, k_grant) = build(true, &|_, _| {});
    let all = View::all(&w).held;
    let of_t1 = evidence(&w, &Set::from([s[0]]), &all);
    assert!(!of_t1.contains(&s[1]) && !of_t1.contains(&k_grant));
    assert!(evidence(&w, &Set::from([s[1]]), &all).contains(&k_grant));
}

/// The author right is held only through the request's own chain: a member writing through A2
/// purges what A2 authored; an admin of the thing by another path names A2 and holds nothing
/// (the model's right is the `author` class alone).
#[test]
fn a_purge_holds_the_right_only_through_its_own_chain() {
    let mut w = guests();
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
    let mut w = guests();
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
/// (serving K alone; the story's move 41, set by hand: the model's evidence closure is complete)
/// and writes T1 after it; K, an honest writer of T1 that does not yet hold the removal, compacts
/// T1 carrying that write. The write is invalid everywhere, and K's valid cover shows it for good
/// at every node holding the cover (and in every later snapshot, as state). What bounds the
/// window: K's receipt of the removal; from then K's walk shows nothing new of the thief's. The story counts it (`window`), never as a
/// safety failure; under the variant `-facts` the carried write falls with the removal.
#[test]
fn a_cover_by_a_writer_not_yet_holding_the_removal_carries_the_late_write() {
    let s = Setup { x_a2: 0, ..Setup::default() };
    for (rules, carried) in [(Rules::fixed(), true), (Rules { cover_facts: true, ..Rules::fixed() }, false)] {
        let m = Sim::build(&s, &rules, &[Move { kind: 41, ts: 7, made: 7 }], &mut Rng(1));
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

// ---- A commit of several edge writes (spec/commits.md §2; notes/a1-spec/README.md, OPEN 10) ----

/// X's edge granted by B and by N5; X removes B and N5 in one commit, listing nothing. Its parts
/// are judged in holder order: the removal of B drops B's grant of X, N5's grant still keeping X's
/// edge, and applies. The removal of N5 would drop N5's grant: past its own drop and the commit's
/// earlier one X's edge has no grant left, so it is void, and X keeps admin by N5's grant, trusted
/// or not. Control (`keeps` over each lowering's own drops alone): both apply and the commit's
/// path ends with no authority.
#[test]
fn a_commit_whose_drops_together_take_its_path_applies_only_what_keeps_it() {
    let mut w = account();
    w.edge(H, 1, &[], A, B, Admin, &[]);
    w.edge(H, 1, &[], A, N5, Admin, &[]);
    let bx = w.edge(B, 2, &[], A, X, Admin, &[]);
    let nx = w.edge(N5, 3, &[], A, X, Admin, &[]);
    let ids = w.commit(X, 5, &[], A, vec![Kind::set(N5, Gone), Kind::set(B, Gone)]);
    let (rb, r5) = (ids[0], ids[1]);
    assert_eq!(w.sets(rb), Some((B, A)));
    for t in [&[][..], &[rb]] {
        let rd = fixed(&w, t);
        assert!(rd.applied.contains(&rb) && rd.voided == Set::from([r5]) && rd.dropped == Set::from([bx]) && rd.self_taken.is_empty(), "{t:?} {rd:?}");
        assert_eq!((rd.role(X, A), rd.role(B, A), rd.role(N5, A)), (Admin, Gone, Admin));
        assert_eq!(no_effect(&w, &Rules::fixed(), &View::all(&w).trusting(t), &rd, r5), (true, true));
    }
    let rd = fixed_but(&w, &[], |r| r.commit_drops = false);
    assert!(rd.applied.is_superset(&Set::from([rb, r5])) && rd.dropped == Set::from([bx, nx]) && rd.role(X, A) == Gone, "{rd:?}");
    assert_eq!(rd.self_taken, Set::from([rb]));
}

/// A commit of several edge writes is judged part by part like any, the part on an edge of its
/// own stated path last (spec/commits.md §2; notes/a1-spec/README.md, OPEN 14). X removes B and
/// leaves A in one commit: both apply. H, along [A],
/// takes T1's record edge off D1 (the edge its descent ends with) and grants N5 admin on D1: the
/// grant applies by the path as it stood, then the removal, judged as any lowering, applies and
/// drops nothing of its own commit (no list can name it). Naming one holder twice is bad input.
/// Control (`-refuse-shapes`: a self-removal or a part on the commit's own path refuses the
/// commit): none of these apply.
#[test]
fn a_commit_of_several_writes_is_judged_part_by_part_its_own_path_last() {
    let build = || {
        let (mut w, ..) = paired();
        let ga = w.edge(H, 1, &[A, T1], D1, A, Admin, &[]);
        let own = w.commit(X, 5, &[], A, vec![Kind::set(X, Gone), Kind::set(B, Gone)]);
        let twice = w.commit(X, 5, &[], A, vec![Kind::set(N5, Admin), Kind::set(N5, Write)]);
        let rec = w.commit(H, 5, &[A], D1, vec![Kind::set(T1, Gone).listing(w.cut(&[ga])), Kind::set(N5, Admin)]);
        (w, own, twice, rec)
    };
    let (w, own, twice, rec) = build();
    assert!(w.leave(own[1]) && w.sets(own[0]) == Some((B, A)) && w.sets(rec[1]) == Some((T1, D1)));
    let rd = keyed(&w);
    assert!(own.iter().chain(&rec).all(|i| rd.applied.contains(i)) && twice.iter().all(|i| !w.well(*i) && !rd.applied.contains(i)), "{rd:?}");
    assert_eq!((rd.role(X, A), rd.role(B, A), rd.role(N5, A)), (Gone, Gone, Gone));
    assert_eq!((rd.role(T1, D1), rd.role(N5, D1), rd.role(A, D1)), (Gone, Admin, Admin));
    assert!(rd.dropped.is_empty());
    // trusted, the removal's seeds reach no part of its own commit either
    let rd = fixed(&w, &[rec[1]]);
    assert!(rd.dropped.is_empty() && rd.void.is_empty() && rd.role(N5, D1) == Admin, "{rd:?}");
    let rd = fixed_but(&w, &[], |r| r.refuse_shapes = true);
    assert!(own.iter().chain(&rec).all(|i| !rd.applied.contains(i)) && (rd.role(X, A), rd.role(B, A), rd.role(T1, D1)) == (Admin, Admin, Admin));
}

// ---- The single-use link redemption (spec/permissions.md §7; notes/a1-spec/README.md, OPEN 14) ----

/// The link thing (minted with A, the sharer's account), its link key, two redeemers and a key
/// the thief makes up.
const LK: Thing = 30;
const L: Thing = 31;
const R1: Thing = 32;
const R2: Thing = 33;

/// A sharing LK by a link: H grants L read with the flag on LK by [A].
fn link() -> World {
    let mut w = World::new(&[(H, A), (A, LK)]);
    w.push(H, 1, &[A], LK, Kind::set(L, Role::Read).may_grant());
    w
}

/// A redemption: signing as L, one commit granting `r` read on LK by may-grant and removing L's own grant.
fn redeem(w: &mut World, ts: u32, r: Thing) -> Vec<Id> {
    w.commit(L, ts, &[], LK, vec![Kind::set(r, Role::Read), Kind::set(L, Gone)])
}

/// The reading trusting nothing, checked to be the reading of a relabelling keeping the key
/// order (commits sharing `ts` and signer, a commit's parts among them, keep theirs).
fn keyed(w: &World) -> Reading {
    let rd = fixed(w, &[]);
    assert!(one_reading_relabelled(w, &Rules::fixed(), &View::all(w), &rd));
    rd
}

/// Every gate of the `tiny` search holds of `w` read with `trust`.
fn tiny_gates(w: &World, trust: &[Id]) {
    let mut st = TinyStats::default();
    let recv = (0..w.commits.len()).map(|k| (0..w.cid(k)).collect()).collect();
    tiny_check(0, &Tiny { w: w.clone(), v: View::all(w).trusting(trust), recv }, &Rules::fixed(), &mut st);
    assert!(st.failures() == 0, "{:?} {:?}", st.fails, st.first);
}

/// Redeemed once: the grant applies by L's flag as it stood, then L's leave, last: R1 reads LK
/// and L holds nothing. Control (`-refuse-shapes`): the redemption applies nowhere, L keeps its
/// grant and R1 gets none.
#[test]
fn a_link_redemption_grants_once_and_ends_the_link() {
    let mut w = link();
    let red = redeem(&mut w, 3, R1);
    assert!(w.leave(red[1]) && w.sets(red[0]) == Some((R1, LK)));
    let rd = keyed(&w);
    assert!(red.iter().all(|i| rd.applied.contains(i)) && rd.by_flag.contains(&red[0]), "{rd:?}");
    assert_eq!((rd.role(R1, LK), rd.role(L, LK)), (Role::Read, Gone));
    assert!(disputes(&w, &Rules::fixed(), &View::all(&w)).is_empty());
    tiny_gates(&w, &[]);
    let rd = fixed_but(&w, &[], |r| r.refuse_shapes = true);
    assert!(red.iter().all(|i| !rd.applied.contains(i)) && (rd.role(R1, LK), rd.role(L, LK)) == (Gone, Role::Read));
}

/// Redeemed twice concurrently (two holders of the seed, both at 3, or at 3 and 4): the redemption
/// first in key order grants and ends L's grant; the other's grant finds no flag on L's edge and
/// applies nowhere, its leave a no-op. One redeemer holds LK at every node, whatever arrives first.
#[test]
fn a_link_redeemed_twice_concurrently_grants_once() {
    for later in [3, 4] {
        let mut w = link();
        let a = redeem(&mut w, 3, R1);
        let b = redeem(&mut w, later, R2);
        let rd = keyed(&w);
        assert!(a.iter().all(|i| rd.applied.contains(i)) && !rd.applied.contains(&b[0]), "{later} {rd:?}");
        assert_eq!((rd.role(R1, LK), rd.role(R2, LK), rd.role(L, LK)), (Role::Read, Gone, Gone));
        tiny_gates(&w, &[]);
    }
}

/// A thief holding the link key after the redemption: its grant stamped after it finds L's edge
/// gone and applies nowhere; one backdated before it applies by L's flag then, until the
/// sharer's explicit removal of L, listing the redemption it received, drops it (spec/permissions.md
/// §7, Finalized). Trusted or not, R1 keeps LK and the thief's keys hold nothing.
#[test]
fn a_thief_with_the_link_key_after_redemption_keeps_nothing_past_the_sharers_removal() {
    let (z1, z2) = (34, 35);
    let mut w = link();
    let red = redeem(&mut w, 3, R1);
    let late = w.push(L, 5, &[], LK, Kind::set(z1, Role::Read));
    let back = w.push(L, 2, &[], LK, Kind::set(z2, Role::Read));
    let before = fixed(&w, &[]);
    assert!(!before.applied.contains(&late) && before.applied.contains(&back) && before.role(z2, LK) == Role::Read);
    let end = w.push(H, 6, &[A], LK, Kind::set(L, Gone).listing(w.cut(&red)));
    for t in [&[][..], &[end]] {
        let rd = fixed(&w, t);
        assert!(rd.applied.contains(&end) && rd.dropped == Set::from([late, back]), "{t:?} {rd:?}");
        assert_eq!((rd.role(R1, LK), rd.role(z1, LK), rd.role(z2, LK), rd.role(L, LK)), (Role::Read, Gone, Gone, Gone));
        tiny_gates(&w, t);
    }
    // the backdated grant received by the sharer before its removal of L is listed and stands, as
    // today (spec/permissions.md §7 Finalized: one received before it stands): the link's seed is
    // a bearer credential until that removal
    let mut w = link();
    let red = redeem(&mut w, 3, R1);
    let back = w.push(L, 2, &[], LK, Kind::set(z2, Role::Read));
    let end = w.push(H, 6, &[A], LK, Kind::set(L, Gone).listing(w.cut(&[red[0], red[1], back])));
    let rd = fixed(&w, &[end]);
    assert!(rd.applied.contains(&end) && rd.applied.contains(&back) && rd.role(z2, LK) == Role::Read, "{rd:?}");
}

/// Every gate of the `tiny` search holds of `w` read with `trust` under `rules`.
fn tiny_gates_under(w: &World, trust: &[Id], rules: &Rules) -> TinyStats {
    let mut st = TinyStats::default();
    let recv = (0..w.commits.len()).map(|k| (0..w.cid(k)).collect()).collect();
    tiny_check(0, &Tiny { w: w.clone(), v: View::all(w).trusting(trust), recv }, rules, &mut st);
    st
}

/// A single-use link redeemed twice, the sharer H removing L at 6 listing what it received
/// (notes/a1-spec/README.md Open 23), under the rule and each other reading of what a drop takes
/// (`Drops`), trusting nothing and trusting the removal alike: who holds LK in the end,
/// (R1, R2). R2 is the thief, R1 the redeemer the sharer saw.
/// - `unseen`: R2 redeems at 3, unseen by H; R1 at 4; H lists R1's redemption.
/// - `backdated`: as `unseen`, R2's redemption stamped 2 (made after R1's).
/// - `later`: R1 at 3, R2 at 4 unseen; H lists R1's.
/// - `both`: R2 at 3, R1 at 4, H lists both: the first in key order holds it.
/// - `neither`: as `unseen`, H lists nothing.
/// - `multi`: a link for many (no leave part): R2 at 3 unseen, R1 at 4 listed.
/// The rule (`Drops::Commit`): R2's grant falls and its leave with it (one commit's parts on LK),
/// so R1's grant applies: R1 holds LK, as today's walk has it. Control `-part-drops`: in `unseen`
/// and `backdated`, at a node not trusting the removal, R2's leave stands (its need at L's edge,
/// admin, was never met there), so R1's grant finds L's edge gone and nobody holds LK; a node
/// trusting it seeds the leave too (a seed asks only that the removal's value not meet the need)
/// and gives R1 LK: the nodes read differently by trust. The other worlds read alike under every
/// reading and trust.
#[test]
fn a_single_use_link_redeemed_twice_stays_with_the_redemption_the_sharer_listed() {
    type Want = (Role, Role);
    let read = Role::Read;
    let worlds: Vec<(&str, World, Id, Want, Want)> = {
        let mut out = vec![];
        let mut add = |name: &'static str, t2: Option<u32>, t1: u32, list: &dyn Fn(&[Id], &[Id]) -> Vec<Id>, single: bool, fixed: Want, fair: Want| {
            let mut w = link();
            let one = |w: &mut World, ts: u32, r: Thing| if single { redeem(w, ts, r) } else { vec![w.push(L, ts, &[], LK, Kind::set(r, Role::Read))] };
            let (a, b) = match t2 {
                Some(t2) if t2 < t1 => {
                    let b = one(&mut w, t2, R2);
                    (one(&mut w, t1, R1), b)
                }
                _ => {
                    let a = one(&mut w, t1, R1);
                    (a, one(&mut w, t2.unwrap_or(4), R2))
                }
            };
            let end = w.push(H, 6, &[A], LK, Kind::set(L, Gone).listing(w.cut(&list(&a, &b))));
            out.push((name, w, end, fixed, fair));
        };
        add("unseen", Some(3), 4, &|a, _| a.to_vec(), true, (Gone, Gone), (read, Gone));
        add("backdated", Some(2), 3, &|a, _| a.to_vec(), true, (Gone, Gone), (read, Gone));
        add("later", Some(4), 3, &|a, _| a.to_vec(), true, (read, Gone), (read, Gone));
        add("both", Some(3), 4, &|a, b| a.iter().chain(b).copied().collect(), true, (Gone, read), (Gone, read));
        add("neither", Some(3), 4, &|_, _| vec![], true, (Gone, Gone), (Gone, Gone));
        add("multi", Some(3), 4, &|a, _| a.to_vec(), false, (read, Gone), (read, Gone));
        out
    };
    let readings = [Drops::Commit, Drops::Part, Drops::LeaveLowers, Drops::LeaveOnGrant, Drops::Redemption];
    for (name, w, end, fixed_want, fair) in &worlds {
        for ln in readings {
            let rules = Rules { drops: ln, ..Rules::fixed() };
            for t in [&[][..], &[*end]] {
                let rd = judge(w, &rules, &View::all(w).trusting(t));
                let want = if ln == Drops::Part && t.is_empty() { *fixed_want } else { *fair };
                assert_eq!((rd.role(R1, LK), rd.role(R2, LK), rd.role(L, LK)), (want.0, want.1, Gone), "{name} {ln:?} trust {t:?}: {rd:?}");
                assert!(rd.applied.contains(end), "{name} {ln:?}");
                let st = tiny_gates_under(w, t, &rules);
                assert!(st.failures() == 0, "{name} {ln:?} trust {t:?}: {:?} {:?}", st.fails, st.first);
            }
        }
    }
}

/// What `Drops::Commit` changes outside links: parts of one commit on a thing differ in need only
/// where its path gives less than admin (may-grant grants, a finalize, a leave). B holds write
/// with the flag on A and, in one commit, grants Z read and N5 write by it; H, not having
/// received it, then demotes B to read with the flag. N5's grant needs write with the flag and
/// falls; Z's needs read with it, which B keeps: by its own need it stands (control
/// `-part-drops`), under the rule it falls with N5's (the commit's `roles.0` delta on A is one
/// part), as osis-perm's walk has it. No generator makes parts of one commit whose needs differ (`tiny_flags` writes no
/// such commit, `tiny` commits no leave beside another part), so `-part-drops` reads every
/// generated world alike. And B hands A over to N5
/// (a may-grant grant and a leave in one commit), unseen by H, who then removes B or lowers it to read: N5
/// falls and B ends as H set it under either reading.
#[test]
fn a_writers_commit_on_a_thing_falls_together_where_its_parts_need_differ() {
    for part in [false, true] {
        let rules = Rules { drops: if part { Drops::Part } else { Drops::Commit }, ..Rules::fixed() };
        let mut w = account();
        w.push(H, 1, &[], A, Kind::set(B, Write).may_grant());
        w.commit(B, 2, &[], A, vec![Kind::set(Z, Role::Read), Kind::set(N5, Write)]);
        w.push(H, 3, &[], A, Kind::set(B, Role::Read).may_grant());
        let rd = judge(&w, &rules, &View::all(&w));
        assert_eq!((rd.role(Z, A), rd.role(N5, A), rd.role(B, A)), (if part { Role::Read } else { Gone }, Gone, Role::Read), "part {part}: {rd:?}");
        for to in [Gone, Role::Read] {
            let mut w = account();
            w.push(H, 1, &[], A, Kind::set(B, Write).may_grant());
            w.commit(B, 2, &[], A, vec![Kind::set(N5, Write), Kind::set(B, Gone)]);
            w.push(H, 3, &[], A, Kind::set(B, to));
            let rd = judge(&w, &rules, &View::all(&w));
            assert_eq!((rd.role(N5, A), rd.role(B, A)), (Gone, to), "part {part} {to:?}: {rd:?}");
        }
    }
}

/// The nodes' views of story world `m` whose reading under `rules` differs from `Rules::fixed`'s:
/// what users observe or which edge-class parts apply.
fn views_differing(m: &Sim, rules: &Rules) -> u64 {
    let f = Rules::fixed();
    m.honest()
        .iter()
        .filter(|&&n| {
            let v = m.view(n, &f);
            let (a, b) = (judge(&m.w, &f, &v), judge(&m.w, rules, &v));
            a.observed(&m.w) != b.observed(&m.w) || a.applied != b.applied
        })
        .count() as u64
}

/// By hand (notes/a1-spec/README.md Open 23): the story's worlds (no link in them) read alike under
/// `fixed` (`Drops::Commit`) and each other reading of what a drop takes but `-leave-lowers`, at
/// every honest node: the random worlds from `OSIS_ROLES_START` (`OSIS_ROLES_SEEDS`, 13,000) and
/// every 367th family world, the gate's sizes. The rule meant for redemptions changes no other
/// reading there (its reach elsewhere: `tiny`'s commits of several parts, the differentials).
#[test]
#[ignore = "by hand: Open 23's readings against fixed"]
fn leave_readings_change_no_story_reading() {
    let start = crate::env_u64("OSIS_ROLES_START").unwrap_or(0);
    let n = crate::env_u64("OSIS_ROLES_SEEDS").unwrap_or(13_000);
    let mut out = vec![];
    for ln in [Drops::Part, Drops::LeaveLowers, Drops::LeaveOnGrant, Drops::Redemption] {
        let rules = Rules { drops: ln, ..Rules::fixed() };
        let random: u64 = crate::on_every_core(|th, threads, c: &mut u64| {
            for i in (start + th as u64..start + n).step_by(threads) {
                *c += views_differing(&random_world(i, &Rules::fixed()), &rules);
            }
        });
        let fam: u64 = crate::family_on_every_core(FAMILY, 367, |i, c: &mut u64| *c += views_differing(&family(i, &Rules::fixed()), &rules));
        println!("{ln:?}: views reading otherwise: random {random}, family {fam}");
        out.push((ln, random, fam));
    }
    assert!(out.iter().filter(|x| x.0 != Drops::LeaveLowers).all(|x| x.1 == 0 && x.2 == 0), "{out:?}");
}

/// Two admins leaving at once (notes/permissions.md, The last admin: a writer's check only): H
/// (A's mint admin) and B (granted admin) each leave A at 3, as each saw the other standing. Both
/// apply and A has no admin, as a deliberate leave would leave it.
#[test]
fn two_admins_leaving_at_once_leave_the_thing_adminless() {
    let mut w = account();
    w.edge(H, 1, &[], A, B, Admin, &[]);
    let lh = w.push(H, 3, &[], A, Kind::set(H, Gone));
    let lb = w.push(B, 3, &[], A, Kind::set(B, Gone));
    assert!(w.leave(lh) && w.leave(lb) && w.key(lh) < w.key(lb));
    let rd = keyed(&w);
    assert!(rd.applied.contains(&lh) && rd.applied.contains(&lb), "{rd:?}");
    assert_eq!((rd.role(H, A), rd.role(B, A)), (Gone, Gone));
    tiny_gates(&w, &[]);
}

/// A path's last hop giving admin gives may-grant (G1, G4): holder M holds admin on T, B holds
/// write on M. B's grants on T through [M] apply as may-grant grants up to B's role on M (every hop
/// giving it, the last admin): read and write apply, the write carrying the flag (G2: the new
/// grant may), admin does not (it needs admin along the path). X, a reader of M, so grants
/// readers and not writers (control `-last-hop`).
#[test]
fn a_writer_of_an_admin_holder_grants_up_to_its_own_role() {
    const M: Thing = 41;
    const T: Thing = 42;
    let mut w = World::new(&[(H, M), (H, T)]);
    w.edge(H, 1, &[], T, M, Admin, &[]);
    w.edge(H, 1, &[], M, B, Write, &[]);
    let read = w.push(B, 2, &[M], T, Kind::set(Z, Role::Read));
    let write = w.push(B, 2, &[M], T, Kind::set(N5, Write).may_grant());
    let admin = w.push(B, 2, &[M], T, Kind::set(N6, Admin));
    // a reader of M grants readers on T
    w.edge(H, 1, &[], M, X, Role::Read, &[]);
    let x_read = w.push(X, 3, &[M], T, Kind::set(K, Role::Read));
    let x_write = w.push(X, 3, &[M], T, Kind::set(A2, Write));
    let rd = keyed(&w);
    assert!(rd.by_flag.contains(&read) && rd.by_flag.contains(&write) && !rd.applied.contains(&admin), "{rd:?}");
    assert!(rd.by_flag.contains(&x_read) && !rd.applied.contains(&x_write), "{rd:?}");
    assert_eq!((rd.role(Z, T), rd.role(N5, T), rd.role(N6, T), rd.role(K, T), rd.role(A2, T)), (Role::Read, Write, Gone, Role::Read, Gone));
    tiny_gates(&w, &[]);
}

/// A thing detached from its folder (notes/a1-spec/README.md Open 21): H mints A (the folder),
/// A mints T. H grants itself admin on T by [A] (its direct edge (H, T)), then removes A's record
/// edge on T by its descent []: both apply. A record edge
/// is an edge like any (the walk starts it at admin and edge writes move it), and a descent rests
/// on each of its record edges as they stand at the part's key: so H's later content and grant on
/// T, stated along the descent [] or through [A], apply nowhere, though H holds admin on T by its
/// own direct edge, which no unmarked path can state (a hop from a mint ancestor is a descent).
/// Marking the hop H to T as the direct edge, both apply, as today's walk has it.
#[test]
fn a_detached_things_owner_writes_it_only_by_a_marked_direct_hop() {
    const T: Thing = 40;
    let mut w = World::new(&[(H, A), (A, T)]);
    let g = w.push(H, 1, &[A], T, Kind::set(H, Admin));
    let cut = w.push(H, 2, &[], T, Kind::set(A, Gone).listing(w.cut(&[g])));
    assert_eq!(w.hops(cut), [(H, A), (A, T)], "the removal of A's record edge rests on its descent");
    let by_descent = w.content(H, 3, &[], T);
    let through_a = w.content(H, 3, &[A], T);
    let marked = w.push_marked(H, 3, &[], T, Kind::Content, &[0]);
    assert_eq!(w.hops(marked), [(H, T)]);
    let grant_descent = w.push(H, 4, &[], T, Kind::set(B, Write));
    let grant_marked = w.push_marked(H, 5, &[], T, Kind::set(N5, Write), &[0]);
    for t in [&[][..], &[cut]] {
        let rd = fixed(&w, t);
        assert!(rd.applied.contains(&g) && rd.applied.contains(&cut), "{t:?} {rd:?}");
        assert_eq!((rd.role(H, T), rd.role(A, T)), (Admin, Gone));
        assert!(!rd.valid.contains(&by_descent) && !rd.valid.contains(&through_a) && rd.valid.contains(&marked), "{t:?} {rd:?}");
        assert!(!rd.applied.contains(&grant_descent) && rd.applied.contains(&grant_marked), "{t:?} {rd:?}");
        assert_eq!((rd.role(B, T), rd.role(N5, T)), (Gone, Write));
        let st = tiny_gates_under(&w, t, &Rules::fixed());
        assert!(st.failures() == 0, "{t:?}: {:?} {:?}", st.fails, st.first);
    }
}

/// Why the hop is stated, not read off what is held (notes/a1-spec/README.md Open 21): H, two
/// record edges above T, makes M admin on T and writes T by the descent []. M then grants H read
/// on T, stamped before H's write. Were a hop from a mint ancestor read as direct wherever a
/// direct edge is held (`push_marked` standing for that reading), M's grant would turn H's write
/// into one through a read edge: invalid. M, by granting, decides how H's earlier writes are
/// read. Stated, H's write stays a descent and valid whatever edge M writes.
#[test]
fn a_hop_read_by_the_direct_edges_held_lets_another_admin_void_a_mint_ancestors_writes() {
    const T: Thing = 40;
    const M: Thing = 41;
    let mut w = World::new(&[(H, A), (A, T)]);
    w.push(H, 1, &[], T, Kind::set(M, Admin));
    let stated = w.content(H, 3, &[], T);
    let as_direct = w.push_marked(H, 3, &[], T, Kind::Content, &[0]);
    let rd = fixed(&w, &[]);
    assert!(rd.valid.contains(&stated) && !rd.valid.contains(&as_direct), "no direct edge: {rd:?}");
    w.push(M, 2, &[], T, Kind::set(H, Role::Read));
    let rd = fixed(&w, &[]);
    assert!(rd.valid.contains(&stated) && !rd.valid.contains(&as_direct), "M's read grant: {rd:?}");
    assert_eq!(rd.role(H, T), Role::Read);
}

/// A self-removal rewriting its holder's own admin unchanged (it lowers, so it applies) does not
/// keep that admin past a lowering's drops (notes/path-model-findings.md 43): H grants B admin on
/// A; B rewrites its own grant unchanged; B removes H listing nothing, which drops H's grant of B,
/// the only authority B's removal had. `keeps` reads B's edge back past the rewrite (it gives at
/// most what the edge gave before it, here nothing): the removal is void, H stays an admin, as
/// without the rewrite.
#[test]
fn a_self_rewrite_keeps_no_admin_its_grant_lost() {
    for rewrite in [false, true] {
        let mut w = account();
        let gb = w.push(H, 1, &[], A, Kind::set(B, Admin));
        if rewrite {
            w.push(B, 2, &[], A, Kind::set(B, Admin));
        }
        let r = w.push(B, 3, &[], A, Kind::set(H, Gone));
        let rd = fixed(&w, &[]);
        assert!(rd.applied.contains(&gb) && !rd.applied.contains(&r) && rd.voided.contains(&r), "{rewrite}: {rd:?}");
        assert_eq!((rd.role(H, A), rd.role(B, A)), (Admin, Admin), "{rewrite}");
    }
}

/// The one-encoding rule (spec/permissions.md §1 Path, Direct mark): a mark only on a
/// hop otherwise read as a descent of two steps or more. B holds a direct grant on T1 (B is on no
/// record chain of T1): [] marked applies nowhere, unmarked applies. A, T1's mint admin, holds the
/// record edge, which is its direct edge: its write by [] marked applies nowhere, unmarked applies.
/// A mark past the members (hop 1 of a path of one hop) applies nowhere. H's marked hop, where H
/// holds a direct edge on T1, applies; where it holds none, nowhere (no edge, not the descent).
/// (A, minted by H, signs by a key H grants.)
#[test]
fn a_mark_off_a_descent_of_two_steps_applies_nowhere() {
    let mut w = account();
    w.push(H, 1, &[], A, Kind::set(own_key(A), Admin));
    w.push(H, 1, &[A], T1, Kind::set(B, Admin));
    let b_plain = w.content(B, 2, &[], T1);
    let b_marked = w.push_marked(B, 2, &[], T1, Kind::Content, &[0]);
    let a_plain = w.content(A, 2, &[], T1);
    let a_marked = w.push_marked(A, 2, &[], T1, Kind::Content, &[0]);
    let past = w.push_marked(B, 2, &[], T1, Kind::Content, &[1]);
    let h_none = w.push_marked(H, 2, &[], T1, Kind::Content, &[0]);
    let h_descent = w.content(H, 2, &[], T1);
    w.push(H, 3, &[A], T1, Kind::set(H, Write));
    let h_marked = w.push_marked(H, 4, &[], T1, Kind::Content, &[0]);
    assert!(!w.well(b_marked) && !w.well(a_marked) && !w.well(past) && w.well(h_none));
    let rd = fixed(&w, &[]);
    assert!(rd.valid.contains(&b_plain) && rd.valid.contains(&a_plain) && rd.valid.contains(&h_descent) && rd.valid.contains(&h_marked), "{rd:?}");
    assert!([b_marked, a_marked, past, h_none].iter().all(|i| !rd.valid.contains(i)), "{rd:?}");
}

/// A final hop marked direct is the path's last edge (spec/permissions.md §1 Path: its last
/// edge): T1 detached, H holds admin on it by its direct grant, B by its own. H removes B along
/// the marked hop: its last edge (H's grant) gives admin, so it applies (the descent would give
/// nothing). H, given read with the flag on T1 in place of admin, grants Z read along the marked
/// hop and not N5 write: the last edge's flag at its role.
#[test]
fn a_marked_final_hop_is_the_last_edge() {
    let mut w = account();
    let gh = w.push(H, 1, &[A], T1, Kind::set(H, Admin));
    let gb = w.push(H, 1, &[A], T1, Kind::set(B, Admin));
    w.push(H, 2, &[], T1, Kind::set(A, Gone).listing(w.cut(&[gh, gb])));
    let r = w.push_marked(H, 3, &[], T1, Kind::set(B, Gone), &[0]);
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&r) && rd.role(B, T1) == Gone, "{rd:?}");
    let mut w = account();
    let gh = w.push(H, 1, &[A], T1, Kind::set(H, Role::Read).may_grant());
    let gb = w.push(H, 1, &[A], T1, Kind::set(B, Admin));
    w.push(B, 2, &[], T1, Kind::set(A, Gone).listing(w.cut(&[gh, gb])));
    let inv = w.push_marked(H, 3, &[], T1, Kind::set(Z, Role::Read), &[0]);
    let too_much = w.push_marked(H, 3, &[], T1, Kind::set(N5, Write), &[0]);
    let rd = fixed(&w, &[]);
    assert!(rd.by_flag.contains(&inv) && !rd.applied.contains(&too_much) && rd.role(Z, T1) == Role::Read, "{rd:?}");
}

/// Two routes, two claims (spec/permissions.md §1 Path, Direct mark): H holds T1 by the
/// descent and by its own direct grant; B holds a direct admin grant on T1. B removes A's record
/// edge on T1, detaching it: H's write along the descent stamped after applies nowhere, the one
/// along its marked direct hop stands. B then removes H's direct grant listing that write: H's
/// later marked write falls, the listed one stays; unlisted, it falls too. A remover takes both
/// routes, as any party's two grants.
#[test]
fn a_party_with_both_routes_is_cut_off_by_removing_both() {
    let mut w = account();
    let gh = w.push(H, 1, &[A], T1, Kind::set(H, Admin));
    let gb = w.push(H, 1, &[A], T1, Kind::set(B, Admin));
    let detach = w.push(B, 3, &[], T1, Kind::set(A, Gone).listing(w.cut(&[gh, gb])));
    let by_descent = w.content(H, 4, &[], T1);
    let marked = w.push_marked(H, 4, &[], T1, Kind::Content, &[0]);
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&gb) && rd.applied.contains(&detach), "{rd:?}");
    assert!(!rd.valid.contains(&by_descent) && rd.valid.contains(&marked), "{rd:?}");
    let r = w.push(B, 5, &[], T1, Kind::set(H, Gone).listing(w.cut(&[marked])));
    let later = w.push_marked(H, 6, &[], T1, Kind::Content, &[0]);
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&r) && rd.valid.contains(&marked) && !rd.valid.contains(&later), "{rd:?}");
    assert_eq!(rd.role(H, T1), Gone);
    w.edit(r, |k| k.listing(BTreeMap::new()));
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&r) && !rd.valid.contains(&marked), "unlisted, the marked write falls with the grant: {rd:?}");
}

/// The thief with the far ancestor's key (spec/permissions.md §1 Path, Direct mark): H
/// holds T1 by its direct grant only (A's record edge removed), B by its own. After B removes H's
/// grant, the thief holding H's key backdates a marked write and a marked grant of Z: both fall,
/// trusting the removal or not; a grant along the cut descent applies nowhere at all.
#[test]
fn a_removed_far_ancestors_backdated_marked_writes_fall() {
    let mut w = account();
    let gh = w.push(H, 1, &[A], T1, Kind::set(H, Admin));
    let gb = w.push(H, 1, &[A], T1, Kind::set(B, Admin));
    w.push(H, 2, &[], T1, Kind::set(A, Gone).listing(w.cut(&[gh, gb])));
    let r = w.push(B, 5, &[], T1, Kind::set(H, Gone));
    let back = w.push_marked(H, 4, &[], T1, Kind::Content, &[0]);
    let grant = w.push_marked(H, 4, &[], T1, Kind::set(Z, Admin), &[0]);
    let descent = w.push(H, 4, &[], T1, Kind::set(N5, Admin));
    for t in [&[][..], &[r]] {
        let rd = fixed(&w, t);
        assert!(rd.applied.contains(&r) && !rd.valid.contains(&back) && !rd.applied.contains(&grant) && !rd.applied.contains(&descent), "{t:?} {rd:?}");
        assert_eq!((rd.role(Z, T1), rd.role(N5, T1), rd.role(H, T1)), (Gone, Gone, Gone));
        let st = tiny_gates_under(&w, t, &Rules::fixed());
        assert!(st.failures() == 0, "{t:?}: {:?} {:?}", st.fails, st.first);
    }
}

/// The mark meets the other rules (spec/permissions.md §1 Path, Direct mark; §5.1):
/// T1 minted with admin A, A with admin H. H grants itself, B and N5 admin on T1 (direct grants through [A]), then
/// detaches T1 (A's record edge removed, listing those grants). Along its marked direct hop H
/// grants X write and writes content; X writes. B removes H listing H's content: H's grant of X
/// rests on the removed edge, so it falls with X's write unless B's list names it too; the listed
/// content stays. The grant stated by the cut descent instead applies nowhere.
#[test]
fn a_marked_hop_under_a_removal_with_a_list() {
    for (marked, listed) in [(true, true), (true, false), (false, true)] {
        let mut w = account();
        let gs: Vec<Id> = [H, B, N5].iter().map(|&h| w.push(H, 1, &[A], T1, Kind::set(h, Admin))).collect();
        let detach = w.push(H, 2, &[], T1, Kind::set(A, Gone).listing(w.cut(&gs)));
        let mark: &[usize] = if marked { &[0] } else { &[] };
        let gx = w.push_marked(H, 3, &[], T1, Kind::set(X, Write), mark);
        let hc = w.push_marked(H, 4, &[], T1, Kind::Content, &[0]);
        let xc = w.content(X, 5, &[], T1);
        let list = if listed { vec![hc, gx] } else { vec![hc] };
        let r = w.push(B, 6, &[], T1, Kind::set(H, Gone).listing(w.cut(&list)));
        for t in [&[][..], &[r]] {
            let rd = fixed(&w, t);
            let ctx = format!("{marked} {listed} {t:?}: {rd:?}");
            assert!(rd.applied.contains(&detach) && rd.applied.contains(&r) && rd.valid.contains(&hc), "{ctx}");
            assert_eq!(rd.role(H, T1), Gone, "{ctx}");
            let stays = marked && listed;
            assert_eq!((rd.applied.contains(&gx), rd.valid.contains(&xc), rd.role(X, T1)), (stays, stays, if stays { Write } else { Gone }), "{ctx}");
            let st = tiny_gates_under(&w, t, &Rules::fixed());
            assert!(st.failures() == 0, "{ctx}: {:?} {:?}", st.fails, st.first);
        }
    }
}

/// `tiny_detached` reaches every case its doc names (counted over its first 300 worlds, every
/// count above zero): a marked hop applying, one applying nowhere (no direct edge), a mark off a
/// descent of two steps or more (on no descent, on a one-step descent, past the hops), A's record
/// edge removed (T1 detached), and an unmarked descent applying nowhere.
#[test]
fn tiny_detached_worlds_reach_the_marked_cases() {
    let mut n = BTreeMap::<&str, u64>::new();
    for i in 0..300 {
        let t = tiny_world(i, TinyMode { flags: false, detached: true, keys: false, honest: Honesty::None }, &Rules::fixed());
        let rd = judge(&t.w, &Rules::fixed(), &t.v);
        for (k, c) in t.w.commits.iter().enumerate() {
            let does = rd.applied.contains(&k) || rd.valid.contains(&k);
            let key = match (c.direct.is_empty(), t.w.well(k), does) {
                (false, true, true) => "marked applies",
                (false, true, false) => "marked applies nowhere",
                (false, false, _) => {
                    let all: Vec<Thing> = std::iter::once(c.signer).chain(c.path.iter().copied()).chain([T1]).collect();
                    let off = |j: usize| match all.get(j + 1) {
                        None => Some("mark past the hops"),
                        Some(&q) if t.w.mint_of(q) == Some(all[j]) => Some("mark on a one-step descent"),
                        Some(&q) if t.w.joins(all[j], q).len() < 2 => Some("mark on no descent"),
                        Some(_) => None,
                    };
                    c.direct.iter().find_map(|&j| off(j)).unwrap_or("other")
                }
                (true, _, false) if c.on == T1 && c.signer == H && c.path.is_empty() => "descent applies nowhere",
                _ => "other",
            };
            *n.entry(key).or_default() += 1;
            if rd.applied.contains(&k) && matches!(&c.kind, Kind::Edge { holder, role: Role::None, .. } if *holder == A) {
                *n.entry("detached").or_default() += 1;
            }
        }
    }
    for k in ["marked applies", "marked applies nowhere", "mark on no descent", "mark on a one-step descent", "mark past the hops", "descent applies nowhere", "detached"] {
        assert!(n.get(k).is_some_and(|c| *c > 0), "{k}: {n:?}");
    }
}

// ---- Dispute candidates (notes/a1-spec/README.md, OPEN 12) ----

/// An honest holder thing's leave: H grants A2 admin on T1 by [A], K grants Z write by [A2], and K
/// makes A2 leave T1 (a self-removal by [A2], naming A). Trusted, its seeds would drop K's grant
/// (unlisted: a self-removal carries no frontier), so as a candidate it is shown in an honest
/// history. Candidates are explicit writes: a self-removal, never trusted, is none. Control: every
/// lowering of another holder's edge a candidate, the leave is shown.
#[test]
fn an_honest_holder_leave_is_no_dispute() {
    let mut w = account();
    w.edge(H, 1, &[A], T1, A2, Admin, &[]);
    let gz = w.edge(K, 2, &[A2], T1, Z, Write, &[]);
    let leave = w.edge(K, 3, &[A2], T1, A2, Gone, &[]);
    assert!(w.leave(leave));
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&leave) && rd.role(Z, T1) == Write && rd.role(A2, T1) == Gone);
    assert!(disputes(&w, &Rules::fixed(), &View::all(&w)).is_empty());
    let all = Rules { candidates: Candidates::All, ..Rules::fixed() };
    assert_eq!(disputes(&w, &all, &View::all(&w)), vec![leave]);
    assert!(!judge(&w, &all, &View::all(&w).trusting(&[leave])).shows(gz));
}

// ---- Seeds by need: a demotion to write (a kiosk) ----

/// A2 holds admin on T1; X, a writer of A2, grants G read on T1 through A2 by may-grant; B, not
/// having received it, demotes A2 on T1 to write with the flag (a kiosk: a holder kept at write).
/// The grant's need on (A2, T1) is read with the flag, which the demotion still gives: its audit
/// keeps it at a node trusting nothing, and a trusted demotion's seeds (its value's unmet needs)
/// keep it too, so both read alike and nothing is shown. Control (seeds every unlisted write
/// resting on the edge): the trusting node drops the grant and the demotion is shown as a dispute.
#[test]
fn a_trusted_demotion_to_write_keeps_the_grants_made_by_flag() {
    let mut w = account();
    w.edge(H, 1, &[], A, B, Admin, &[]);
    w.push(H, 1, &[A], T1, Kind::set(A2, Admin));
    w.edge(K, 1, &[], A2, X, Write, &[]);
    let gi = w.push(X, 4, &[A2], T1, Kind::set(G, Role::Read));
    let kiosk = w.push(B, 6, &[A], T1, Kind::set(A2, Write).may_grant());
    for t in [&[][..], &[kiosk]] {
        let rd = fixed(&w, t);
        assert!(rd.applied.contains(&kiosk) && rd.applied.contains(&gi) && rd.role(G, T1) == Role::Read, "{t:?} {rd:?}");
    }
    assert!(disputes(&w, &Rules::fixed(), &View::all(&w)).is_empty());
    let all = Rules { seeds_by_need: false, ..Rules::fixed() };
    assert_eq!(judge(&w, &all, &View::all(&w).trusting(&[kiosk])).role(G, T1), Gone);
    assert_eq!(disputes(&w, &all, &View::all(&w)), vec![kiosk]);
}


// ---- What a write that does not apply may change (notes/path-model-findings.md 33) ----

/// H grants N5 admin at 3 and again at 11; N5 gives N6 write with the flag until 10 at 8,
/// removes N6 at 9, and demotes H to write with the flag at 11 listing only H's second grant.
/// The removal of N6 falls from write, is judged and applied; the demotion of H drops H's first
/// grant of N5, and the restart leaves N5 no right at 8 and 9: the grant of N6 does not apply,
/// and the removal of N6 still applies by its verdict. Without the grant held the removal never
/// falls and does not apply. What users observe is the same either way (N6 never holds a role,
/// every role over time, what each may grant and content alike): only whether the removal of N6 shows as
/// applied differs, which nobody sees.
#[test]
fn an_unapplied_grant_changes_nothing_observed() {
    let mut w = account();
    let again = w.edge(H, 11, &[], A, N5, Admin, &[]);
    w.edge(N5, 11, &[], A, H, Write, &[again]);
    w.edit(1, |k| k.may_grant());
    let r6 = w.edge(N5, 9, &[], A, N6, Gone, &[]);
    let g6 = w.push(N5, 8, &[], A, Kind::set(N6, Write).may_grant().until(10));
    w.edge(H, 3, &[], A, N5, Admin, &[]);
    let (n6, h) = (w.content(N6, 9, &[], A), w.content(H, 12, &[], A));
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&r6) && !rd.applied.contains(&g6), "{rd:?}");
    assert!(!rd.valid.contains(&n6) && rd.valid.contains(&h));
    let without = judge(&w, &Rules::fixed(), &View::all(&w).without(&[g6]));
    assert!(!without.applied.contains(&r6) && [H, N5, N6].iter().all(|&n| without.role(n, A) == rd.role(n, A)));
    assert_eq!(no_effect(&w, &Rules::fixed(), &View::all(&w), &rd, g6), (true, false));
}

/// Finding 34's world: H grants N5 and Z admin at 4; N5 demotes Z to write at 4 (after H's grants
/// in key order); Z demotes H and N5 to read at 5; H demotes N5 to write at 7, listing nothing.
fn h_demotes_n5(listing: &[Id]) -> (World, Id) {
    let mut w = account();
    let h = w.push(H, 7, &[], A, Kind::set(N5, Write).may_grant());
    w.push(N5, 4, &[], A, Kind::set(Z, Write).may_grant().listing(w.cut(&[h])));
    w.push(H, 4, &[], A, Kind::set(N5, Admin));
    w.push(H, 4, &[], A, Kind::set(Z, Admin));
    w.push(Z, 5, &[], A, Kind::set(H, Role::Read).listing(w.cut(&[0, 1, 2, 3])));
    w.push(Z, 5, &[], A, Kind::set(N5, Role::Read).listing(w.cut(&[0, 2, 3])));
    let f = w.cut(listing);
    w.edit(h, |k| k.listing(f));
    (w, h)
}

/// Finding 34 (accepted, counted): the first pass applies N5's demotion of Z, so Z's writes at 5
/// do not apply, and H's demotion of N5 is judged with H holding admin: `keeps` holds (no setter of
/// H's edge is dropped) and it applies, dropping N5's demotion of Z. The restart lets Z's writes at
/// 5 apply, so H's demotion, now raising N5 from read, applies nowhere (finding 27), yet its drop
/// stays: H ends at read and Z admin, where without H's demotion held H stays admin and Z at write.
/// No dispute is shown: trusted, H's demotion's seeds take N5's demotion of Z first, Z's writes
/// apply and H's demotion is void, its seeds lost: the same reading; trusting any other lowering
/// changes nothing. Accepted: a fight among three admins, each holding admin at its write; every
/// node reads it alike and the verdict, once given, stands (finding 16). Listing N5's demotion of Z
/// (which an honest H that received it names), H's demotion applies and nothing idle has an effect.
#[test]
fn a_lowering_whose_drops_let_an_earlier_write_take_its_authority_changes_roles_unshown() {
    let (w, h) = h_demotes_n5(&[]);
    let v = View::all(&w);
    let rd = fixed(&w, &[]);
    assert!(!rd.applied.contains(&h) && rd.dropped == Set::from([1]) && (rd.role(H, A), rd.role(Z, A)) == (Role::Read, Admin), "{rd:?}");
    let without = judge(&w, &Rules::fixed(), &v.clone().without(&[h]));
    assert_eq!((without.role(H, A), without.role(N5, A), without.role(Z, A)), (Admin, Admin, Write));
    assert_eq!(idle_gate(&w, &[]), vec![h]);
    assert!(disputes(&w, &Rules::fixed(), &v).is_empty());
    let (w, h) = h_demotes_n5(&[1]);
    let rd = keyed(&w);
    assert!(rd.applied.contains(&h) && (rd.role(H, A), rd.role(N5, A), rd.role(Z, A)) == (Admin, Write, Write), "{rd:?}");
    assert!(effects(&w, &Rules::fixed(), &View::all(&w), &rd).iter().all(|e| !e.observed));
}

/// The idle writes with an effect users observe and no dispute shown (counted in the searches:
/// findings 34 to 36).
fn idle_gate(w: &World, trust: &[Id]) -> Vec<Id> {
    let v = View::all(w).trusting(trust);
    let rd = judge(w, &Rules::fixed(), &v);
    effects(w, &Rules::fixed(), &v, &rd).into_iter().filter(|e| e.observed && !e.shown).map(|e| e.id).collect()
}

/// Finding 35 (accepted, counted; the smallest `tiny` world counted in `idle N`): H grants N5 admin
/// at 2; N5, in one commit at 2, sets H's admin to end at 4 and grants B admin; B grants H admin
/// again at 4; H removes N5 at 6, listing nothing. Held, B's grant gives H admin at 6: H's removal is
/// judged, its drops take N5's commit (H's edge is its record edge again), so B's grant applies
/// nowhere in the end: H admin, N5 and B none. Without B's grant H's admin ended at 4 and its removal
/// has no right: N5 and B admins, H none. No dispute either way: H's removal applies; N5's end on H
/// is a grant (`Until::Plain`). As a lowering judged at its key (`Until::AtKey`) the same: its drops
/// are none (nothing before it is stamped past its end), so trusting it changes nothing.
#[test]
fn a_grant_applying_nowhere_gives_a_lowering_its_verdict() {
    let mut w = account();
    let r = w.push(H, 6, &[], A, Kind::set(N5, Gone));
    w.commit(N5, 2, &[], A, vec![Kind::set(H, Admin).until(4), Kind::set(B, Admin)]);
    let b = w.push(B, 4, &[], A, Kind::set(H, Admin).listing(w.cut(&[1, 2])));
    w.push(H, 2, &[], A, Kind::set(N5, Admin).listing(w.cut(&[b])));
    for rules in [Rules::fixed(), Rules { until: Until::AtKey, ..Rules::fixed() }] {
        let v = View::all(&w);
        let rd = judge(&w, &rules, &v);
        assert!(rd.applied.contains(&r) && !rd.applied.contains(&b) && (rd.role(H, A), rd.role(N5, A), rd.role(B, A)) == (Admin, Gone, Gone), "{rd:?}");
        let without = judge(&w, &rules, &v.clone().without(&[b]));
        assert!(!without.applied.contains(&r) && (without.role(H, A), without.role(N5, A), without.role(B, A)) == (Gone, Admin, Admin), "{without:?}");
        let fx: Vec<Id> = effects(&w, &rules, &v, &rd).into_iter().filter(|e| e.observed && !e.shown).map(|e| e.id).collect();
        assert_eq!(fx, vec![b]);
    }
}

/// Finding 36's world (honest writers: each list the writers' rule's over what its writer received,
/// each clock past what it saw): H grants B admin at 5; B sets H's admin to end at 8 at 6, listing
/// H's grant of B, and grants Z admin at 7; Z, having received all three, grants H admin again at
/// 8; H, having received only Z's grant, removes B at 12 listing nothing.
fn b_ends_h(end: Kind) -> (World, Id, Id, Vec<Vec<Id>>) {
    let mut w = account();
    w.push(H, 5, &[], A, Kind::set(B, Admin));
    w.push(B, 6, &[], A, end.listing(w.cut(&[0])));
    w.push(B, 7, &[], A, Kind::set(Z, Admin));
    let g = w.push(Z, 8, &[], A, Kind::set(H, Admin));
    let r = w.push(H, 12, &[], A, Kind::set(B, Gone));
    (w, g, r, vec![vec![], vec![0], vec![0, 1], vec![0, 1, 2], vec![0, 3]])
}

/// Finding 36 (accepted, counted): in `b_ends_h`, held, Z's grant gives H admin at 12: H's removal
/// drops B's writes, Z's grant among them, and H's edge is its record edge again: B and Z none, H
/// admin. Without it H's admin ended at 8: B and Z admins, H none. Nobody is hostile and no dispute
/// is shown. As a lowering judged at its key (`Until::AtKey`) B's end drops nothing: the same. With
/// B removing H at 6 in place of the end date the world reads the same, unshown: the class is a
/// re-grant by the lowerer's own grantee that lets the lowered admin's counter-lowering apply and
/// then falls with its drops, end date or not.
#[test]
fn with_honest_writers_a_grant_applying_nowhere_decides_a_fight() {
    for rules in [Rules::fixed(), Rules { until: Until::AtKey, ..Rules::fixed() }] {
        for end in [Kind::set(H, Admin).until(8), Kind::set(H, Gone)] {
            let (w, g, r, recv) = b_ends_h(end);
            let v = View::all(&w);
            assert!(lists_honest(&w, &rules, &recv));
            let rd = judge(&w, &rules, &v);
            assert!(rd.applied.contains(&r) && !rd.applied.contains(&g) && (rd.role(H, A), rd.role(B, A), rd.role(Z, A)) == (Admin, Gone, Gone), "{rd:?}");
            let without = judge(&w, &rules, &v.clone().without(&[g]));
            assert!(!without.applied.contains(&r) && (without.role(H, A), without.role(B, A), without.role(Z, A)) == (Gone, Admin, Admin), "{without:?}");
            let fx: Vec<Id> = effects(&w, &rules, &v, &rd).into_iter().filter(|e| e.observed && !e.shown).map(|e| e.id).collect();
            assert_eq!(fx, vec![g]);
            assert!(disputes(&w, &rules, &v).is_empty());
            // a fight among parties each holding admin at its write in some reading
            assert!(fight_among(&w, &rules, &v, &rd, &[g]).illegit.is_empty());
        }
    }
}

/// The variant `Until::PastEnd` (an end's drops also the writes after it resting on its edge stamped
/// past the end, whatever sets the edge between) shows finding 36's world: B's end drops H's removal
/// (stamped 12, past 8, through H's edge), so Z's grant applies and B, Z and H stay admins, and
/// H's removal is shown as a dispute. With B removing H in place of the end date it changes nothing:
/// an end date takes more than a removal, a write made under a later re-grant included.
#[test]
fn an_end_dropping_writes_past_it_shows_the_honest_fight() {
    let rules = Rules { until: Until::PastEnd, ..Rules::fixed() };
    let (w, g, r, _) = b_ends_h(Kind::set(H, Admin).until(8));
    let v = View::all(&w);
    let rd = judge(&w, &rules, &v);
    assert!(rd.dropped.contains(&r) && rd.applied.contains(&g) && (rd.role(H, A), rd.role(B, A), rd.role(Z, A)) == (Admin, Admin, Admin), "{rd:?}");
    assert_eq!(disputes(&w, &rules, &v), vec![r]);
    let (w, g, _, _) = b_ends_h(Kind::set(H, Gone));
    let rd = judge(&w, &rules, &View::all(&w));
    assert!(!rd.applied.contains(&g) && (rd.role(H, A), rd.role(B, A)) == (Admin, Gone));
}

/// Why `Until::PastEnd` is no rule (it fails liveness in the story, an honest admin's writes lost
/// at the trusting nodes, and `quiet` in this honest world): H grants N5 and B admin at 1; N5 sets
/// H's admin to end at 4 at 2; B, not having received it, removes N5 at 3 listing nothing; H, not
/// having received N5's end either, grants Z admin at 5. Judged at its key N5's end drops H's grant
/// (stamped past 4, through H's edge); B's removal then drops N5's end, H's edge is standing again,
/// but the grant stays dropped (drops only grow): Z none at nodes trusting nothing, B's removal shown
/// as a dispute in an honest history. Trusting B's removal, its seeds take N5's end first: Z admin.
/// Under the rule, and as a lowering judged at its key (`Until::AtKey`), N5's end drops nothing and
/// Z is admin everywhere.
#[test]
fn an_end_dropping_writes_past_it_keeps_its_drops_after_it_falls() {
    let mut w = account();
    w.push(H, 1, &[], A, Kind::set(N5, Admin));
    w.push(H, 1, &[], A, Kind::set(B, Admin));
    w.push(N5, 2, &[], A, Kind::set(H, Admin).until(4));
    let rb = w.push(B, 3, &[], A, Kind::set(N5, Gone));
    let g = w.push(H, 5, &[], A, Kind::set(Z, Admin));
    let past = Rules { until: Until::PastEnd, ..Rules::fixed() };
    let v = View::all(&w);
    let rd = judge(&w, &past, &v);
    assert!(rd.stray == Set::from([g]) && (rd.role(H, A), rd.role(Z, A)) == (Admin, Gone), "{rd:?}");
    assert_eq!(disputes(&w, &past, &v), vec![rb]);
    assert_eq!(judge(&w, &past, &v.clone().trusting(&[rb])).role(Z, A), Admin);
    for rules in [Rules::fixed(), Rules { until: Until::AtKey, ..Rules::fixed() }] {
        for t in [vec![], vec![rb]] {
            let rd = judge(&w, &rules, &v.clone().trusting(&t));
            assert!(rd.applied.contains(&g) && rd.role(Z, A) == Admin, "{rd:?}");
        }
        assert!(disputes(&w, &rules, &v).is_empty());
    }
}

/// Why `Until::AtKey` is not the rule (`tiny`: A left with no standing admin at nodes trusting
/// nothing in 13 of 1,000,000 worlds against 3, with no dispute shown more): H grants B and N6
/// admin at 2; N6 removes H at 3 listing H's grant of N6; B, in one commit at 3 (before N6's in key
/// order), sets H's and N6's admin to end at 5. Judged at its key B's commit applies; N6's removal,
/// H's edge timed, applies and drops
/// H's grant of B. Restarted, B holds nothing, yet its ends keep their verdict and apply: H and B
/// none, N6 timed, A with no standing admin. As grants (the rule) B's ends apply nowhere once B
/// holds nothing: N6 stays a standing admin. The idle-write counts it lowers (47 to 35) are such
/// ends applying for good, not disputes shown.
#[test]
fn an_end_judged_at_its_key_applies_for_good_and_can_strand_the_thing() {
    let mut w = account();
    let gb = w.push(H, 2, &[], A, Kind::set(B, Admin));
    let gn = w.push(H, 2, &[], A, Kind::set(N6, Admin));
    let r = w.push(N6, 3, &[], A, Kind::set(H, Gone).listing(w.cut(&[gn])));
    let ends = w.commit(B, 3, &[], A, vec![Kind::set(H, Admin).until(5).listing(w.cut(&[gb, gn])), Kind::set(N6, Admin).until(5).listing(w.cut(&[gb]))]);
    let v = View::all(&w);
    let at_key = judge(&w, &Rules { until: Until::AtKey, ..Rules::fixed() }, &v);
    assert!(at_key.applied.is_superset(&Set::from([r, ends[0], ends[1]])) && at_key.dropped.contains(&gb), "{at_key:?}");
    assert!(!at_key.roles.iter().any(|(e, r)| e.1 == A && *r == Admin), "{at_key:?}");
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&r) && !rd.applied.contains(&ends[0]) && (rd.role(H, A), rd.role(B, A), rd.role(N6, A)) == (Gone, Gone, Admin), "{rd:?}");
}


/// Why `Until::AtKey` is not the rule: the required gate it fails (`illegit gains V`, `tiny` with
/// honest lists, 1 in 1,000,000; world 888396 shrunk, trusting N5's removal of N6, which ends void).
/// N6, admin by H's grant at 2, in one commit at 3 gives B admin until 5 and N5 admin; N5 grants Z
/// admin at 5; Z, at 5, grants B admin and then sets B's admin to end at 7; N6 removes N5 at 5.
/// Judged at its key Z's end (B standing by Z's grant) applies; N6's removal drops N5's grant of Z;
/// restarted, Z holds nothing and its grant applies nowhere, but its end keeps its verdict and,
/// lowering nothing as restored (B admin), applies: B admin until 7, not 5. Without Z's grant held
/// the end lengthens B's end, takes nothing and has no right: B until 5. So an idle write of a party
/// that held its right in no reading changes roles, unshown. (The verdict's raise check, finding 27,
/// reads roles only.) Under the rule both of Z's writes apply nowhere and nothing idle has an effect.
#[test]
fn an_end_judged_at_its_key_lets_an_idle_write_lengthen_a_grant() {
    let mut w = account();
    w.push(N5, 5, &[], A, Kind::set(Z, Admin));
    let g = w.push(Z, 5, &[], A, Kind::set(B, Admin).listing(w.cut(&[0])));
    w.push(H, 2, &[], A, Kind::set(N6, Admin).listing(w.cut(&[0, 1])));
    let end = w.push(Z, 5, &[], A, Kind::set(B, Admin).until(7));
    w.push(N6, 5, &[], A, Kind::set(N5, Gone));
    let r = w.push(N5, 7, &[], A, Kind::set(N6, Gone));
    w.commit(N6, 3, &[], A, vec![Kind::set(B, Admin).until(5), Kind::set(N5, Admin).listing(w.cut(&[0, 1, 2, 3, 5]))]);
    let v = View::all(&w).trusting(&[r]);
    let at_key = Rules { until: Until::AtKey, ..Rules::fixed() };
    let rd = judge(&w, &at_key, &v);
    assert!(rd.void == Set::from([r]) && rd.applied.contains(&end) && !rd.applied.contains(&g) && rd.state[&(B, A)] == (Admin, Some(7)), "{rd:?}");
    let without = judge(&w, &at_key, &v.clone().without(&[g]));
    assert!(!without.applied.contains(&end) && without.state[&(B, A)] == (Admin, Some(5)), "{without:?}");
    let fx: Vec<Id> = effects(&w, &at_key, &v, &rd).into_iter().filter(|e| e.observed && !e.shown).map(|e| e.id).collect();
    assert_eq!(fx, vec![g]);
    assert_eq!(fight_among(&w, &at_key, &v, &rd, &[g]).gains, Set::from([g]));
    let rd = judge(&w, &Rules::fixed(), &v);
    assert!(!rd.applied.contains(&end) && !rd.applied.contains(&g) && rd.state[&(B, A)] == (Admin, Some(5)), "{rd:?}");
    assert!(effects(&w, &Rules::fixed(), &v, &rd).iter().all(|e| !e.observed));
}


/// Why `Until::AtKey` is not the rule: the story's `own path N` fails (62 of 200,000 worlds, thief
/// move 23, shrunk): X, stolen, backdates a grant of admin to a made-up key Z at 1, and Z sets H's
/// admin to end at 7 at 2; H removes X at 6 listing nothing. At a node trusting
/// nothing, judged at its key Z's end applies (Z admin by X's grant then); H's removal applies and
/// drops X's grant of Z; restarted, Z holds nothing, yet its end keeps its verdict: H's admin ends
/// at 7, a made-up key's write taking the remover's standing for good. Under the rule Z's end
/// applies nowhere once Z holds nothing: H admin. Trusting H's removal, its seeds take X's grant of
/// Z first and Z's end never applies, either way.
#[test]
fn an_end_judged_at_its_key_lets_a_made_up_key_end_the_removers_admin() {
    let (mut w, gx, _) = paired();
    let gz = w.push(X, 1, &[], A, Kind::set(Z, Admin));
    let end = w.push(Z, 2, &[], A, Kind::set(H, Admin).until(7));
    let r = w.push(H, 6, &[], A, Kind::set(X, Gone).listing(w.cut(&[gx])));
    let at_key = Rules { until: Until::AtKey, ..Rules::fixed() };
    let rd = judge(&w, &at_key, &View::all(&w));
    assert!(rd.applied.is_superset(&Set::from([r, end])) && rd.dropped.contains(&gz) && rd.role(H, A) == Gone, "{rd:?}");
    for (rules, t) in [(Rules::fixed(), vec![]), (Rules::fixed(), vec![r]), (at_key, vec![r])] {
        let rd = judge(&w, &rules, &View::all(&w).trusting(&t));
        assert!(rd.applied.contains(&r) && !rd.applied.contains(&end) && rd.role(H, A) == Admin, "{rd:?}");
    }
}

// ---- A removed key's backdated lowering ----

/// An earlier write of an honest admin dropped for good by a removed key's backdated lowering:
/// H paired N5; B shared T1 with A2 at 2;
/// X removed N5 at 3, listing H's grant, and everyone received it; H removes X at 6 listing it.
/// With N5's key the thief backdates a removal of B to 2, ordered after B's share. It applies at
/// its key (N5 an admin then) and drops B's share (unlisted, resting on B's edge); X's removal of
/// N5 then drops the thief's write, but a drop stands for good (finding 16): the share stays
/// dropped where X's removal of N5 is not trusted: B is an admin throughout and its share is lost,
/// and X's removal of N5 is shown as a dispute. A node that held X's removal of N5 before the
/// backdated write arrived trusts it (F1): its seeds take the write before it acts and the share
/// stands (`first_received_trusts_a_removal_held_before_a_backdated_write`).
#[test]
fn a_removed_keys_backdated_lowering_drops_a_witness_write_for_good() {
    let (mut w, ..) = paired();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let gs = w.edge(B, 2, &[A], T1, A2, Write, &[]);
    let out5 = w.edge(X, 3, &[], A, N5, Gone, &[g5]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[out5]);
    let rd = fixed(&w, &[r]);
    assert!(rd.applied.contains(&gs) && rd.role(A2, T1) == Write, "{rd:?}");
    let down = w.edge(N5, 2, &[], A, B, Gone, &[]);
    assert!(w.key(gs) < w.key(down) && w.key(down) < w.key(out5));
    for t in [&[][..], &[r]] {
        let rd = fixed(&w, t);
        assert!(rd.role(B, A) == Admin && !rd.applied.contains(&down) && !rd.applied.contains(&gs) && rd.role(A2, T1) == Gone && rd.stray.contains(&gs), "{rd:?}");
    }
    assert_eq!(disputes(&w, &Rules::fixed(), &View::all(&w).trusting(&[r])), vec![out5]);
    let rd = fixed(&w, &[r, out5]);
    assert!(rd.applied.contains(&gs) && rd.dropped.contains(&down) && rd.role(A2, T1) == Write && rd.void.is_empty(), "{rd:?}");
}

/// F2 and F3 in the story: H paired N5 and X removed it at 3 (`Setup::n5` 3), every node
/// receiving it then; the thief, after the removal, backdates N5's removal of B to 2 (move 47,
/// made 9). Each node holding X's removal of N5, applying, when the backdated write arrives
/// records it trusted, so B's writes stand there: H, B, the reader RD, and N5's own node (the
/// write is signed with its key and is not its own). A node joining at 10 receives both in one
/// update and records nothing (F3): its walk applies the backdated removal at its key, B's share
/// is lost, and X's removal of N5 is shown as a dispute, which chosen reads as the others.
/// Controls: `-no-receipt` (nothing recorded: the share is lost at RD), `-tie` (the joining node
/// records the removal as if it had held it first).
#[test]
fn first_received_trusts_a_removal_held_before_a_backdated_write() {
    let s = Setup { n5: 3, ..Setup::default() };
    let rules = Rules::fixed();
    let mv = [Move { kind: 47, ts: 2, made: 9 }];
    let m = Sim::build(&s, &rules, &mv, &mut Rng(0));
    let out5 = m.out5.unwrap();
    for n in [H, B, N5, RD] {
        let v = m.view(n, &rules);
        assert!(v.trust.contains(&out5), "node {n}: {:?}", v.trust);
        let rd = judge(&m.w, &rules, &v);
        assert!(rd.role(B, A) == Admin && (n == H || rd.applied.contains(&m.gs)), "node {n}: {rd:?}");
    }
    let mut st = Stats::default();
    check(&m, &rules, &mut st);
    assert_eq!(st.failures(), 0, "{:?}", st.fails);
    let mut late = m.clone();
    late.joins(RD, 10, &rules);
    assert!(late.chose.get(&RD).is_some_and(|c| c.contains(&out5)));
    let v = late.view_unchosen(RD, &rules);
    let rd = judge(&late.w, &rules, &v);
    assert!(!v.trust.contains(&out5) && !rd.applied.contains(&m.gs) && rd.role(A2, T1) == Gone, "{:?} {rd:?}", v.trust);
    assert_eq!(disputes(&late.w, &rules, &v), vec![out5]);
    let rd = judge(&late.w, &rules, &choose(&late.w, &rules, &v, out5));
    assert!(rd.applied.contains(&m.gs) && rd.role(A2, T1) == Write, "{rd:?}");
    for (sides, at, trusts) in [(Sides::NoReceipt, None, false), (Sides::Tie, Some(10), true)] {
        let off = Rules { sides, ..rules };
        let mut m = Sim::build(&s, &off, &mv, &mut Rng(0));
        if let Some(at) = at {
            m.joins(RD, at, &off);
        }
        let v = m.view(RD, &off);
        assert_eq!(v.trust.contains(&out5), trusts, "{sides:?}");
        assert_eq!(judge(&m.w, &off, &v).applied.contains(&m.gs), trusts, "{sides:?}");
    }
}

/// F2, one side per fight: X, stolen, demotes H to write stamped 7, heard by B at 5; H removes X
/// at 6, and B, holding the demotion first, records it (its seeds take the removal). The thief
/// then ends X's own admin at 2 (move 33), so the demotion holds no right and B's walk applies
/// H's removal, and backdates an end of H's admin at 6 (move 44), a write H's removal leaves out.
/// B has a side in that fight already: it records nothing for H's removal, reads by the walk
/// (the removal without right once H's admin ends) and is told of the removal, which chosen
/// applies. Control `-both`: B records the removal beside the demotion, the demotion's seeds
/// take it, both are void, and B is shown nothing.
#[test]
fn a_recorded_side_keeps_the_other_side_of_its_fight_unrecorded() {
    let mv = [Move { kind: 25, ts: 7, made: 5 }, Move { kind: 33, ts: 1, made: 7 }, Move { kind: 44, ts: 1, made: 9 }];
    for (sides, both) in [(Sides::Received, false), (Sides::Both, true)] {
        let rules = Rules { sides, ..Rules::fixed() };
        let m = Sim::build(&Setup::default(), &rules, &mv, &mut Rng(0));
        let down = *m.thief.iter().find(|(_, k)| **k == 25).unwrap().0;
        let v = m.view_unchosen(B, &rules);
        let rd = judge(&m.w, &rules, &v);
        assert!(v.trust.contains(&down) && !rd.applied.contains(&m.r), "{sides:?}: {:?} {rd:?}", v.trust);
        assert_eq!(v.trust.contains(&m.r), both, "{sides:?}");
        assert_eq!(countered(&m.w, &rules, &v), if both { vec![] } else { vec![m.r] }, "{sides:?}");
        assert!(disputes(&m.w, &rules, &v).is_empty(), "{sides:?}");
        let rd = judge(&m.w, &rules, &choose(&m.w, &rules, &v, m.r));
        assert!(rd.applied.contains(&m.r) && rd.role(H, A) == Admin && rd.role(X, A) == Gone, "{sides:?}: {rd:?}");
    }
}

/// F2, a lowering that applied is a side whether or not it took anything: X, stolen, removes H
/// at 5 (`Setup::x_first`) and again stamped 8 (move 11), both heard by B at 5; the second applies
/// in B's walk taking nothing (H is gone at 5). H removes X at 6, a write the second leaves out:
/// B held the second first and records it. The thief then ends X's own admin at 2 (move 33), so
/// B's walk applies H's removal, and backdates an end of H's admin at 6 (move 44): B has a side
/// in that fight, records nothing for H's removal and is told of it. Variant `-lowered` (a
/// lowering recorded only where it took its hop down): B records H's removal here, but the
/// variant fails the story: a reader holding H's removal before any write of X's (X's grant
/// arrives as evidence with X's backdated removal of H) applied it taking nothing, records
/// nothing, and the backdated removal acts (`each_fix_is_needed_plain`).
#[test]
fn a_lowering_that_applied_taking_nothing_is_a_side() {
    let s = Setup { x_first: true, ..Setup::default() };
    let mv = [Move { kind: 11, ts: 8, made: 5 }, Move { kind: 33, ts: 1, made: 7 }, Move { kind: 44, ts: 1, made: 9 }];
    for (sides, lowered) in [(Sides::Received, false), (Sides::Lowered, true)] {
        let rules = Rules { sides, ..Rules::fixed() };
        let m = Sim::build(&s, &rules, &mv, &mut Rng(0));
        let again = *m.thief.iter().find(|(_, k)| **k == 11).unwrap().0;
        let v = m.view_unchosen(B, &rules);
        let rd = judge(&m.w, &rules, &v);
        assert_eq!((v.trust.contains(&again), v.trust.contains(&m.r)), (!lowered, lowered), "{sides:?}: {:?}", v.trust);
        assert_eq!(rd.applied.contains(&m.r) && rd.role(H, A) == Admin, lowered, "{sides:?}: {rd:?}");
        assert_eq!(countered(&m.w, &rules, &v).contains(&m.r), !lowered, "{sides:?}");
    }
}

/// F4, a choice drops an earlier lowering of its own path. M minted A and paired H; H paired X
/// and N5, and X removed N5 at 3. X, stolen, demotes H to write stamped 1, listing its own
/// grant, and removes it stamped 5 listing nothing; H removes X at 6, naming X's removal of N5
/// and X's removal of H (void in H's walk: its drops take X's own grant) and leaving the
/// demotion out. A node that heard X first recorded both of X's lowerings. Choosing the honest
/// lowerings drops both records: the demotion as a seed of H's removal, X's removal of H as an
/// earlier lowering of the hop H's removal rests on. Control `-choice-seeds` (only the seeds,
/// either way): X's removal of H stays recorded beside H's removal of X, its seeds take X's own
/// grant, and X's removal of N5, unapplied in that round, loses its seeds with it.
#[test]
fn a_choice_drops_an_earlier_lowering_of_its_own_path() {
    let mut w = minted_by(M);
    w.edge(M, 0, &[], A, H, Admin, &[]);
    let gx = w.edge(H, 1, &[], A, X, Admin, &[]);
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let out5 = w.edge(X, 3, &[], A, N5, Gone, &[g5]);
    let down = w.edge(X, 1, &[], A, H, Write, &[gx]);
    let off = w.edge(X, 5, &[], A, H, Gone, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[out5, off]);
    let v = View::all(&w).trusting(&[down, off]);
    let rd = judge(&w, &Rules::fixed(), &v);
    assert!(rd.role(H, A) == Gone && rd.role(X, A) == Admin && !rd.applied.contains(&r), "{rd:?}");
    for (sides, void) in [(Sides::Received, false), (Sides::ChoiceSeeds, true)] {
        let rules = Rules { sides, ..Rules::fixed() };
        let chosen = [r, out5].into_iter().fold(v.clone(), |v, c| choose(&w, &rules, &v, c));
        assert_eq!(chosen.trust.contains(&off), void, "{sides:?}");
        let rd = judge(&w, &rules, &chosen);
        assert_eq!(rd.void.contains(&out5), void, "{sides:?}: {rd:?}");
        assert!(rd.applied.contains(&r) && rd.role(H, A) == Admin && rd.role(X, A) == Gone && rd.role(N5, A) == Gone, "{sides:?}: {rd:?}");
    }
}

/// W10, reach-back candidates tried together: two removed keys' backdated lowerings of one admin.
/// X removed N5 at 3; after H removes X, the thief backdates a demotion of B to 2 with X's key
/// (move 50) and another with N5's (move 48). A node holding both removals first records both and
/// keeps B's share.
#[test]
fn two_backdated_lowerings_are_taken_where_their_removals_were_held_first() {
    let (m, rules) = masked();
    let v = m.view(B, &rules);
    let rd = judge(&m.w, &rules, &v);
    assert!(v.trust.contains(&m.r) && v.trust.contains(&m.out5.unwrap()) && rd.applied.contains(&m.gs) && rd.role(B, A) == Admin, "{:?} {rd:?}", v.trust);
}

fn masked() -> (Sim, Rules) {
    let s = Setup { n5: 3, ..Setup::default() };
    let rules = Rules::fixed();
    (Sim::build(&s, &rules, &[Move { kind: 50, ts: 2, made: 7 }, Move { kind: 48, ts: 2, made: 8 }], &mut Rng(0)), rules)
}

/// W10, the same world at a node trusting nothing (N6): both demotions apply at their keys and B's
/// share is dropped. Trusting either removal alone leaves the other demotion dropping it, so each
/// removal, whose drops include a lowering of another holder's edge, is tried beside the other:
/// both are shown, and choosing them brings the share back. Control `-alone` (each candidate tried
/// alone): nothing is shown and the share is lost.
#[test]
fn masking_lowerings_removals_are_shown_together() {
    let (m, rules) = masked();
    let out5 = m.out5.unwrap();
    for joint in [true, false] {
        let rules = Rules { joint, ..rules };
        let v = m.view(N6, &rules);
        assert!(v.trust.is_empty() && !judge(&m.w, &rules, &v).applied.contains(&m.gs), "{joint}");
        let shown = disputes(&m.w, &rules, &v);
        assert_eq!(shown, if joint { vec![out5, m.r] } else { vec![] }, "{joint}");
        let chosen = shown.iter().fold(v, |v, &r| choose(&m.w, &rules, &v, r));
        let rd = judge(&m.w, &rules, &chosen);
        assert_eq!(rd.applied.contains(&m.gs) && rd.role(B, A) == Admin, joint, "{joint}: {rd:?}");
    }
}

// ---- A cut's list answers that cut alone (notes/evidence-model-findings.md 26) ----

const CT: Thing = 43;

/// Z holds write on A (H's grant at 1); A holds write on CT (M's grant at 2, M CT's mint).
fn cut_twice() -> World {
    let mut w = World::new(&[(H, A), (M, CT)]);
    w.edge(H, 1, &[], A, Z, Write, &[]);
    w.edge(M, 2, &[], CT, A, Write, &[]);
    w
}

fn any_cut(w: &World) -> Reading {
    fixed_but(w, &[], |r| r.answers = Answers::AnyCut)
}

/// M removes A from CT at 4, listing nothing; Z then writes CT through [A] at 5; H removes Z from
/// A at 7 listing everything it received, Z's write included. H's list answers H's cut of (Z, A)
/// alone: M's cut of (A, CT) already refused the write, and H holds no authority over that edge.
/// Control `-list-any-cut`: H's list revives it.
#[test]
fn a_cuts_list_keeps_a_write_from_that_cut_alone() {
    let mut w = cut_twice();
    w.edge(M, 4, &[], CT, A, Gone, &[]);
    let c = w.content(Z, 5, &[A], CT);
    let r = w.edge(H, 7, &[], A, Z, Gone, &[c]);
    for t in [&[][..], &[r]] {
        let rd = judge(&w, &Rules::fixed(), &View::all(&w).trusting(t));
        assert!(!rd.shows(c), "{rd:?}");
    }
    assert!(any_cut(&w).valid.contains(&c));
    // an addendum against H's removal answers H's cut alone too
    w.edge(H, 1, &[], A, B, Write, &[]);
    w.addendum(B, 8, &[A], CT, r, &[c]);
    assert!(!fixed(&w, &[]).shows(c));
}

/// Both removals, stamped 4, list Z's write stamped 5: backdated (an honest remover's clock passes
/// what it received, spec/crdt.md HLC rules). Each cut lists it, so it stands against each: valid. Where only M lists it, H's cut of (Z, A), the
/// edge's last write before it, refuses it.
#[test]
fn a_write_after_two_cuts_stands_where_each_lists_it() {
    for both in [true, false] {
        let mut w = cut_twice();
        let c = w.content(Z, 5, &[A], CT);
        w.edge(M, 4, &[], CT, A, Gone, &[c]);
        let list = if both { vec![c] } else { vec![] };
        w.edge(H, 4, &[], A, Z, Gone, &list);
        assert_eq!(fixed(&w, &[]).valid.contains(&c), both, "both {both}");
        assert!(any_cut(&w).valid.contains(&c));
    }
}

/// One edge cut twice after the write: H's first removal lists it or not, the second (after a
/// re-grant) does not. It stands only where each cut is answered: an addendum answers the cut it
/// is against, not the other.
#[test]
fn a_write_stands_only_where_every_later_cut_of_its_edge_answers_it() {
    for listed in [true, false] {
        let mut w = World::new(&[(H, A)]);
        w.edge(H, 1, &[], A, Z, Write, &[]);
        w.edge(H, 1, &[], A, B, Write, &[]);
        let c = w.content(Z, 2, &[], A);
        let list = if listed { vec![c] } else { vec![] };
        let r1 = w.edge(H, 4, &[], A, Z, Gone, &list);
        w.edge(H, 5, &[], A, Z, Write, &[]);
        let r2 = w.edge(H, 6, &[], A, Z, Gone, &[]);
        assert!(!fixed(&w, &[]).shows(c));
        assert_eq!(any_cut(&w).valid.contains(&c), listed);
        // an addendum against the first cut alone
        let mut w1 = w.clone();
        w1.addendum(B, 7, &[], A, r1, &[c]);
        assert!(!fixed(&w1, &[]).shows(c), "listed {listed}");
        // against the second: valid where the first is answered too
        w.addendum(B, 7, &[], A, r2, &[c]);
        assert_eq!(fixed(&w, &[]).valid.contains(&c), listed, "listed {listed}");
        w.addendum(B, 7, &[], A, r1, &[c]);
        assert!(fixed(&w, &[]).valid.contains(&c), "listed {listed}");
    }
}

/// A write stamped before its path gave the role, listed by a later cut: the list answers the
/// cut, not the missing grant (valid as if the cut had not cut it: the edge gave nothing then).
#[test]
fn a_list_gives_no_role_the_path_never_gave() {
    let mut w = World::new(&[(H, A)]);
    let c = w.content(Z, 1, &[], A);
    w.edge(H, 2, &[], A, Z, Write, &[]);
    w.edge(H, 4, &[], A, Z, Gone, &[c]);
    assert!(!fixed(&w, &[]).shows(c));
    assert!(any_cut(&w).valid.contains(&c));
}

/// The edge before an answering cut is read at the write's `ts`: H's removal at 2 lists Z's write
/// stamped 5 (backdated, as above), but Z's grant ended at 3: the cut not taken, the edge gave
/// nothing at 5. With a standing grant it stands.
#[test]
fn an_answered_cut_gives_back_only_what_the_edge_gave_at_the_write() {
    for until in [true, false] {
        let mut w = World::new(&[(H, A)]);
        w.push(H, 1, &[], A, if until { Kind::set(Z, Write).until(3) } else { Kind::set(Z, Write) });
        let c = w.content(Z, 5, &[], A);
        w.edge(H, 2, &[], A, Z, Gone, &[c]);
        assert_eq!(fixed(&w, &[]).valid.contains(&c), !until, "until {until}");
        assert!(any_cut(&w).valid.contains(&c));
    }
}

/// H cuts (Z, A) listing nothing, grants it again and cuts it again listing both of Z's writes:
/// the one made after the re-grant needs only the second cut's answer; the one the first cut
/// refused stays refused (the final state gives nothing, so no re-grant).
#[test]
fn a_second_cut_of_an_edge_answers_only_what_the_first_left_standing() {
    let mut w = World::new(&[(H, A)]);
    w.edge(H, 1, &[], A, Z, Write, &[]);
    let c0 = w.content(Z, 2, &[], A);
    w.edge(H, 3, &[], A, Z, Gone, &[]);
    w.edge(H, 4, &[], A, Z, Write, &[]);
    let c1 = w.content(Z, 5, &[], A);
    w.edge(H, 6, &[], A, Z, Gone, &[c0, c1]);
    let rd = fixed(&w, &[]);
    assert!(rd.valid.contains(&c1) && !rd.shows(c0), "{rd:?}");
    assert!(any_cut(&w).valid.contains(&c0));
}

/// B's addendum against H's removal of Z keeps Z's write; H then removes B: the addendum, B's
/// write, stands against that cut of its own path only where H's list names it, and Z's write
/// with it.
#[test]
fn an_addendum_keeps_a_write_while_it_stands_against_its_witness_removal() {
    for listed in [true, false] {
        let mut w = World::new(&[(H, A)]);
        w.edge(H, 1, &[], A, Z, Write, &[]);
        w.edge(H, 1, &[], A, B, Write, &[]);
        let c = w.content(Z, 2, &[], A);
        let r1 = w.edge(H, 4, &[], A, Z, Gone, &[]);
        let a = w.addendum(B, 5, &[], A, r1, &[c]);
        w.edge(H, 7, &[], A, B, Gone, &if listed { vec![a] } else { vec![] });
        let rd = fixed(&w, &[]);
        assert_eq!((rd.valid.contains(&a), rd.valid.contains(&c)), (listed, listed), "listed {listed}");
    }
}

/// M cuts (A, CT) and H removes Z from A after Z's write through [A], neither listing it; W,
/// writing CT directly, writes an addendum against H's removal: it answers H's cut alone, so the
/// write stands only once W answers M's cut too.
#[test]
fn an_addendum_answers_the_cut_it_is_against_alone() {
    let mut w = cut_twice();
    w.edge(M, 1, &[], CT, W, Write, &[]);
    let c = w.content(Z, 3, &[A], CT);
    let rm = w.edge(M, 4, &[], CT, A, Gone, &[]);
    let rh = w.edge(H, 5, &[], A, Z, Gone, &[]);
    w.addendum(W, 6, &[], CT, rh, &[c]);
    assert!(!fixed(&w, &[]).shows(c));
    assert!(any_cut(&w).valid.contains(&c));
    w.addendum(W, 7, &[], CT, rm, &[c]);
    assert!(fixed(&w, &[]).valid.contains(&c));
}

/// Z's one commit writes CT through [A] and A directly; M cuts (A, CT), then H removes Z listing
/// the commit in both leaves: the part on A stands by H's list; the part on CT falls to M's cut,
/// which H's list does not answer.
#[test]
fn a_commits_parts_answer_the_cuts_of_their_own_paths() {
    let mut w = cut_twice();
    let parts = w.split(Z, 3, Z, &[(&[A], CT), (&[], A)]);
    w.edge(M, 4, &[], CT, A, Gone, &[]);
    let honest = w.through((Z, A), |_| true);
    w.edge(H, 5, &[], A, Z, Gone, &honest);
    let rd = fixed(&w, &[]);
    assert!(rd.valid.contains(&parts[1]) && !rd.shows(parts[0]), "{rd:?}");
    assert!(any_cut(&w).valid.contains(&parts[0]));
}

// ---- A list entry names its part on its leaf's thing alone (notes/evidence-model-findings.md 24) ----

/// Z writes one commit with a part on T1 through [A] and a part on A; H removes Z from A listing
/// the commit in T1's leaf alone. The entry names the part on T1, not the part on A: a reader of A
/// holds no leaf of T1, so only this reading is one every node can make. Listed in both leaves
/// (the honest remover: each part resting on the lowered edge, in its own thing's leaf), both stand.
#[test]
fn a_list_entry_names_its_part_on_its_leafs_thing_alone() {
    let (mut w, ..) = paired();
    w.edge(H, 1, &[], A, Z, Write, &[]);
    let parts = w.split(Z, 2, Z, &[(&[A], T1), (&[], A)]);
    let (on_t1, on_a) = (parts[0], parts[1]);
    let mut w2 = w.clone();
    w.edge(H, 4, &[], A, Z, Gone, &[on_t1]);
    let rd = fixed(&w, &[]);
    assert!(rd.valid.contains(&on_t1) && !rd.shows(on_a), "{rd:?}");
    let honest = w2.through((Z, A), |_| true);
    assert!(honest.contains(&on_t1) && honest.contains(&on_a));
    w2.edge(H, 4, &[], A, Z, Gone, &honest);
    let rd = fixed(&w2, &[]);
    assert!(rd.valid.contains(&on_t1) && rd.valid.contains(&on_a), "{rd:?}");
}

/// The same for an edge-class part, which a lowering's audit drops: X's one commit grants K write
/// on T1 through [A] and B write on A; H removes X from A listing the commit in T1's leaf alone:
/// the grant on T1 stays, the grant on A drops; listed in both leaves, both stay.
#[test]
fn a_list_entry_keeps_an_edge_class_part_on_its_leafs_thing_alone() {
    for both in [false, true] {
        let mut w = World::new(&[(H, A), (A, T1)]);
        w.edge(H, 1, &[], A, X, Admin, &[]);
        let on_t1 = w.push(X, 2, &[A], T1, Kind::set(K, Write));
        let on_a = w.push(X, 2, &[], A, Kind::set(B, Write));
        w.group(&[on_t1, on_a]);
        let list = if both { w.cut(&[on_t1, on_a]) } else { w.cut(&[on_t1]) };
        w.push(H, 4, &[], A, Kind::set(X, Gone).listing(list));
        let rd = fixed(&w, &[]);
        assert!(rd.applied.contains(&on_t1) && rd.applied.contains(&on_a) == both, "both {both}: {rd:?}");
    }
}

// ---- Keys (notes/write-path-design.md, Keys K1 to K6) ----

/// A key its holder wrote down, and one the thief made up.
const RK: Thing = KEYS | 0x40;
const TK: Thing = KEYS | 0x41;
/// A thing minted with a key (its own: no mint admin), and its dependent.
const T: Thing = 40;
const TD: Thing = 41;

/// K1: a thing minted with a key signs as itself from the start; one minted with a mint admin has
/// no key and signs as nothing until an admin grants one.
#[test]
fn a_thing_signs_by_the_key_its_record_holds_or_one_an_admin_grants() {
    let mut w = account();
    let t_own = w.content(T, 1, &[], T);
    let a_none = w.content(A, 1, &[], A);
    let add = w.push(H, 2, &[], A, Kind::set(RK, Admin));
    let a_rk = w.push_signed(RK, A, 3, &[], A, Kind::Content);
    let a_own = w.content(A, 3, &[], A);
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&add) && rd.valid.contains(&t_own) && rd.valid.contains(&a_rk), "{rd:?}");
    assert!(!rd.valid.contains(&a_none) && !rd.valid.contains(&a_own), "{rd:?}");
    // without the key hop A's own key signs as A
    assert!(fixed_but(&w, &[], |r| r.key_hop = false).valid.contains(&a_own));
}

/// K3: a key's grant is an edge like any. A's admins write it at any role, beside other keys; a
/// key acts as its thing by the role its grant gives (at write: content, no edge write); an admin
/// removes a key by the ordinary removal, and what the key signed falls unless listed (K4).
#[test]
fn a_keys_grant_is_written_and_removed_like_any_grant() {
    let mut w = account();
    let rk = w.push(H, 1, &[], A, Kind::set(RK, Admin));
    let tk = w.push(H, 2, &[], A, Kind::set(TK, Write));
    let c = w.push_signed(TK, A, 3, &[], A, Kind::Content);
    let g = w.push_signed(TK, A, 3, &[], A, Kind::set(Z, Admin));
    let up = w.push_signed(RK, A, 4, &[], A, Kind::set(N6, Write));
    let rd = fixed(&w, &[]);
    assert!([rk, tk, up].iter().all(|i| rd.applied.contains(i)) && rd.valid.contains(&c) && !rd.applied.contains(&g), "{rd:?}");
    assert!(rd.key_role(RK, A) == Admin && rd.key_role(TK, A) == Write && rd.role(Z, A) == Gone);
    let out = w.edge(H, 5, &[], A, RK, Gone, &[]);
    let late = w.push_signed(RK, A, 6, &[], A, Kind::set(H, Gone));
    for trust in [vec![], vec![out]] {
        let v = View::all(&w).trusting(&trust);
        let rd = judge(&w, &Rules::fixed(), &v);
        assert!(rd.applied.contains(&out) && rd.dropped.contains(&up) && !rd.applied.contains(&late), "{trust:?}: {rd:?}");
        assert!(rd.key_role(RK, A) == Gone && rd.role(H, A) == Admin && rd.role(N6, A) == Gone && rd.valid.contains(&c), "{trust:?}: {rd:?}");
        assert!(disputes(&w, &Rules::fixed(), &v).is_empty(), "{trust:?}");
    }
}

/// K3: a key's grant carries `until` and the may-grant flag as any grant. RK holds write with the
/// flag on A until 5: it adds TK at write by may-grant (its key hop the path's last hop, G1), adds
/// nobody at admin, writes until its grant ends; TK's grant outlives it.
#[test]
fn a_keys_grant_takes_until_and_the_flag() {
    let mut w = account();
    w.push(H, 1, &[], A, Kind::set(RK, Write).may_grant().until(5));
    let by_flag = w.push_signed(RK, A, 2, &[], A, Kind::set(TK, Write));
    let over = w.push_signed(RK, A, 2, &[], A, Kind::set(Z, Admin));
    let c1 = w.push_signed(RK, A, 3, &[], A, Kind::Content);
    let c2 = w.push_signed(RK, A, 6, &[], A, Kind::Content);
    let t = w.push_signed(TK, A, 6, &[], A, Kind::Content);
    let rd = fixed(&w, &[]);
    assert!(rd.by_flag.contains(&by_flag) && !rd.applied.contains(&over) && rd.valid.contains(&c1) && !rd.valid.contains(&c2) && rd.valid.contains(&t), "{rd:?}");
    assert!(rd.key_role(TK, A) == Write && rd.key_role(RK, A) == Gone && rd.role(Z, A) == Gone);
    // without the flag the key adds nobody
    let mut w = account();
    w.push(H, 1, &[], A, Kind::set(RK, Write));
    let g = w.push_signed(RK, A, 2, &[], A, Kind::set(TK, Write));
    assert!(!fixed(&w, &[]).applied.contains(&g));
}

/// K5: a key outranks nothing. T, minted with its own key, makes H admin; H removes the key by
/// an ordinary removal (listing what the key signed) and the key's later writes apply nowhere.
/// Where the key and an admin remove each other it is an admin dispute like
/// any: the walk takes the earlier in key order, a node trusting the other reads the other.
#[test]
fn a_key_outranks_no_admin() {
    let mut w = account();
    w.records.push((T, TD));
    let gh = w.push(T, 1, &[], T, Kind::set(H, Admin));
    let down = w.content(T, 2, &[], TD);
    let out = w.edge(H, 3, &[], T, own_key(T), Gone, &[gh, down]);
    let back = w.edge(T, 4, &[], T, H, Gone, &[]);
    let late = w.content(T, 4, &[], TD);
    for trust in [vec![], vec![out]] {
        let v = View::all(&w).trusting(&trust);
        let rd = judge(&w, &Rules::fixed(), &v);
        assert!(rd.applied.contains(&out) && !rd.applied.contains(&back) && rd.valid.contains(&down) && !rd.valid.contains(&late), "{trust:?}: {rd:?}");
        assert!(rd.role(H, T) == Admin && rd.key_role(own_key(T), T) == Gone, "{trust:?}: {rd:?}");
        // the removed key's later removal of H is shown, as any removed admin's counter-removal is
        assert_eq!(disputes(&w, &Rules::fixed(), &v), vec![back], "{trust:?}");
    }
    let mut w = account();
    let gh = w.push(T, 1, &[], T, Kind::set(H, Admin));
    let by_key = w.edge(T, 3, &[], T, H, Gone, &[]);
    let by_h = w.edge(H, 4, &[], T, own_key(T), Gone, &[gh]);
    let v = View::all(&w);
    let rd = judge(&w, &Rules::fixed(), &v);
    assert!(rd.applied.contains(&by_key) && !rd.applied.contains(&by_h) && rd.role(H, T) == Gone && rd.key_role(own_key(T), T) == Admin, "{rd:?}");
    assert_eq!(disputes(&w, &Rules::fixed(), &v), vec![by_h]);
    let rd = fixed(&w, &[by_h]);
    assert!(rd.applied.contains(&by_h) && rd.role(H, T) == Admin && rd.key_role(own_key(T), T) == Gone, "{rd:?}");
}

/// K4: a key lowers or drops its own grant whatever its role (a self-removal: it audits nothing),
/// and raises it by no write of its own.
#[test]
fn a_key_lowers_its_own_grant_whatever_its_role() {
    let mut w = account();
    w.push(H, 1, &[], A, Kind::set(RK, Write));
    let c = w.push_signed(RK, A, 2, &[], A, Kind::Content);
    let raise = w.push_signed(RK, A, 2, &[], A, Kind::set(RK, Admin));
    let own = w.push_signed(RK, A, 3, &[], A, Kind::set(RK, Gone));
    let after = w.push_signed(RK, A, 4, &[], A, Kind::Content);
    assert!(w.leave(own) && w.leave(raise));
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&own) && !rd.applied.contains(&raise) && rd.valid.contains(&c) && !rd.valid.contains(&after) && rd.key_role(RK, A) == Gone, "{rd:?}");
    assert!(disputes(&w, &Rules::fixed(), &View::all(&w)).is_empty());
}

/// K3: a key's grant rests on its writer's path like any grant (nothing vouches for a role
/// write): H grants RK admin on A, makes M admin, and M removes H listing its own grant and
/// leaving RK's out. RK's grant falls, M grants its own key, and RK removes nobody.
#[test]
fn a_keys_grant_falls_with_its_grantor_where_the_removal_leaves_it_out() {
    let mut w = account();
    let attach = w.push(H, 1, &[], A, Kind::set(RK, Admin));
    let gm = w.edge(H, 2, &[], A, M, Admin, &[]);
    let mh = w.edge(M, 3, &[], A, H, Gone, &[gm]);
    let tk = w.push(M, 4, &[], A, Kind::set(TK, Admin));
    let out = w.push_signed(RK, A, 5, &[], A, Kind::set(M, Gone));
    for trust in [vec![], vec![mh]] {
        let rd = fixed(&w, &trust);
        assert!(rd.dropped.contains(&attach) && rd.applied.contains(&tk) && !rd.applied.contains(&out), "{trust:?}: {rd:?}");
        assert!(rd.role(M, A) == Admin && rd.key_role(RK, A) == Gone && rd.key_role(TK, A) == Admin && rd.role(H, A) == Gone);
    }
}

/// A stolen admin node backdates a grant to a key it made up, to before its removal, and acts as
/// A by it to remove the remover (listing H's grant of X, which its key rests
/// on). Where the removal is trusted its seeds take the
/// add and nothing of the key acts; where nothing is trusted the walk applies the made-up key's
/// removal of H and shows H's removal of X as a dispute, whose choice reads as the trusting node.
#[test]
fn a_stolen_nodes_backdated_key_grant_falls_where_its_removal_is_trusted() {
    let mut w = account();
    let gx = w.edge(H, 1, &[], A, X, Admin, &[]);
    let attach = w.push(X, 4, &[], A, Kind::set(TK, Admin));
    let th = w.push_signed(TK, A, 5, &[], A, Kind::set(H, Gone).listing(w.cut(&[gx])));
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let t = fixed(&w, &[r]);
    assert!(t.dropped.contains(&attach) && !t.applied.contains(&th) && t.applied.contains(&r), "{t:?}");
    assert!(t.role(X, A) == Gone && t.key_role(TK, A) == Gone && t.role(H, A) == Admin);
    let v = View::all(&w);
    let plain = judge(&w, &Rules::fixed(), &v);
    assert!(plain.applied.contains(&th) && !plain.applied.contains(&r), "{plain:?}");
    assert_eq!(disputes(&w, &Rules::fixed(), &v), vec![r]);
    // without the key hop the made-up key acts as A wherever its add falls
    assert!(fixed_but(&w, &[r], |r| r.key_hop = false).applied.contains(&th));
}

/// K4: removing a key is the ordinary removal: what the key signed falls unless the removal lists
/// it; a key removing itself audits nothing; two keys removing each other are an admin dispute.
#[test]
fn removing_a_key_drops_what_it_signed_unless_listed() {
    let base = || {
        let mut w = account();
        w.push(H, 1, &[], A, Kind::set(RK, Admin));
        let add = w.push_signed(RK, A, 2, &[], A, Kind::set(TK, Admin));
        let c1 = w.push_signed(TK, A, 3, &[], A, Kind::Content);
        let g1 = w.push_signed(TK, A, 3, &[], A, Kind::set(Z, Write));
        let c2 = w.push_signed(TK, A, 4, &[], A, Kind::Content);
        let g2 = w.push_signed(TK, A, 4, &[], A, Kind::set(N6, Write));
        (w, add, c1, g1, c2, g2)
    };
    let (mut w, _, c1, g1, c2, g2) = base();
    let f = w.cut(&[c1, g1]);
    let r = w.push_signed(RK, A, 5, &[], A, Kind::set(TK, Gone).listing(f));
    for trust in [vec![], vec![r]] {
        let rd = fixed(&w, &trust);
        assert!(rd.valid.contains(&c1) && rd.applied.contains(&g1) && !rd.valid.contains(&c2) && rd.dropped.contains(&g2), "{trust:?}: {rd:?}");
        assert!(rd.key_role(TK, A) == Gone && rd.role(Z, A) == Write && rd.role(N6, A) == Gone);
    }
    assert!(fixed_but(&w, &[], |r| r.key_hop = false).valid.contains(&c2));
    // a key removing itself audits nothing
    let (mut w, _, c1, g1, c2, g2) = base();
    let own = w.push_signed(TK, A, 5, &[], A, Kind::set(TK, Gone));
    let after = w.push_signed(TK, A, 6, &[], A, Kind::Content);
    assert!(w.leave(own));
    let rd = fixed(&w, &[]);
    assert!([c1, c2].iter().all(|i| rd.valid.contains(i)) && [g1, g2, own].iter().all(|i| rd.applied.contains(i)) && !rd.valid.contains(&after), "{rd:?}");
    assert!(disputes(&w, &Rules::fixed(), &View::all(&w)).is_empty());
    // two keys removing each other: the earlier in key order applies, the other is a dispute (TK's
    // lists RK's add of TK, which its own key rests on)
    let (mut w, add, ..) = base();
    let by_rk = w.push_signed(RK, A, 5, &[], A, Kind::set(TK, Gone));
    let by_tk = w.push_signed(TK, A, 5, &[], A, Kind::set(RK, Gone).listing(w.cut(&[add])));
    let v = View::all(&w);
    let rd = judge(&w, &Rules::fixed(), &v);
    assert!(rd.applied.contains(&by_rk) && !rd.applied.contains(&by_tk) && rd.key_role(RK, A) == Admin, "{rd:?}");
    assert_eq!(disputes(&w, &Rules::fixed(), &v), vec![by_tk]);
    let rd = fixed(&w, &[by_tk]);
    assert!(rd.applied.contains(&by_tk) && rd.key_role(RK, A) == Gone && rd.key_role(TK, A) == Admin, "{rd:?}");
}

/// W7 with the key hop: a key replaces itself in one commit (acting as its thing, adding the
/// new key and removing itself), and the commit applies whichever key sorts first: its removal of
/// its own key hop takes effect after the add. Control: the parts in holder order (the old rule),
/// the replacement applies only where the new key sorts first.
#[test]
fn a_key_replaces_itself_in_one_commit_in_either_key_order() {
    let world = |old: Thing, new: Thing, w7: bool| {
        let mut w = account();
        w.push(H, 1, &[], A, Kind::set(old, Admin));
        let parts = vec![Kind::set(new, Admin), Kind::set(old, Gone)];
        let ids = if w7 {
            w.commit_signed(old, A, 2, &[], A, parts, &[])
        } else {
            let mut parts = parts;
            parts.sort_by_key(|k| match k {
                Kind::Edge { holder, .. } => *holder,
                _ => unreachable!(),
            });
            let ids: Vec<Id> = parts.into_iter().map(|k| w.push_signed(old, A, 2, &[], A, k)).collect();
            w.group(&ids);
            ids
        };
        let by_new = w.push_signed(new, A, 3, &[], A, Kind::Content);
        let by_old = w.push_signed(old, A, 3, &[], A, Kind::Content);
        let rd = fixed(&w, &[]);
        let ok = ids.iter().all(|i| rd.applied.contains(i)) && rd.key_role(new, A) == Admin && rd.key_role(old, A) == Gone && rd.valid.contains(&by_new) && !rd.valid.contains(&by_old);
        (ok, rd)
    };
    for (old, new) in [(RK, TK), (TK, RK)] {
        let (ok, rd) = world(old, new, true);
        assert!(ok, "{old:#x} by {new:#x}: {rd:?}");
    }
    // the old order: only the replacement by a key sorting before the signing one applies
    assert!(world(TK, RK, false).0 && !world(RK, TK, false).0);
}

/// W4 reads the key hop: a key's removal of the key that added it, listing nothing, drops that add
/// and so its own key hop: void. Listing the add, it applies (control `-no-key-hop`: nothing rests on
/// the key hop, so it applies dropping nothing).
#[test]
fn a_key_removal_dropping_its_own_keys_add_is_void() {
    let mut w = account();
    w.push(H, 1, &[], A, Kind::set(RK, Admin));
    let add = w.push_signed(RK, A, 2, &[], A, Kind::set(TK, Admin));
    let r = w.push_signed(TK, A, 3, &[], A, Kind::set(RK, Gone));
    let rd = fixed(&w, &[]);
    assert!(rd.voided.contains(&r) && rd.key_role(RK, A) == Admin && rd.key_role(TK, A) == Admin, "{rd:?}");
    assert!(fixed_but(&w, &[], |r| r.key_hop = false).applied.contains(&r));
    w.edit(r, |k| k.listing(BTreeMap::from([(A, Set::from([add]))])));
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&r) && rd.key_role(RK, A) == Gone && rd.key_role(TK, A) == Admin, "{rd:?}");
}

/// Finding 56: a write counts toward a first point only where its grantor held the right at its key
/// in the reading (notes/write-path-design.md §1, Judging content, C2), so a grant by a party whose own grant had ended moves no re-granted
/// holder's first point back: H gives B admin until 3; B gives N6 admin until 8 at 6 (no right,
/// applying nowhere); H gives B admin at 7; B gives N6 admin at 10; N6 writes at 9 (also with B's
/// grant ending at 6, the idle grant's own `ts`). N6's content
/// shows neither with B's idle grant held nor without it.
#[test]
fn an_idle_grant_with_no_right_moves_no_first_point_back() {
    // B's grant ending at 3, and ending at 6, the idle grant's own `ts` (ended there, as in the walk)
    for end in [3, 6] {
        let mut w = account();
        w.push(H, 1, &[], A, Kind::set(B, Admin).until(end));
        let idle = w.push(B, 6, &[], A, Kind::set(N6, Admin).until(8));
        w.push(H, 7, &[], A, Kind::set(B, Admin));
        w.push(B, 10, &[], A, Kind::set(N6, Admin));
        let c = w.content(N6, 9, &[], A);
        let rd = fixed(&w, &[]);
        assert!(!rd.applied.contains(&idle), "{end}");
        let without = judge(&w, &Rules::fixed(), &View::all(&w).without(&[idle]));
        assert!(!rd.valid.contains(&c) && !without.valid.contains(&c), "{end}: {rd:?}");
    }
}

/// As above where the grantor's right was taken by a lowering applying in the reading (C2 reads the
/// walk): H gives B admin at 1 and removes it at 2;
/// B gives N6 admin at 3; H gives N6 admin at 6; N6 writes at 4. And a key that removed itself:
/// H adds RK to A at 1, RK (as A) removes itself at 1; RK, as A, gives N5 admin at 2; H gives N5
/// admin at 5; N5 writes at 3. Neither content shows.
#[test]
fn an_idle_grant_after_its_grantors_removal_moves_no_first_point_back() {
    let mut w = account();
    w.push(H, 1, &[], A, Kind::set(B, Admin));
    w.push(H, 2, &[], A, Kind::set(B, Gone));
    w.push(B, 3, &[], A, Kind::set(N6, Admin));
    w.push(H, 6, &[], A, Kind::set(N6, Admin));
    let c = w.content(N6, 4, &[], A);
    let mut k = account();
    k.push(H, 1, &[], A, Kind::set(RK, Admin));
    k.push_signed(RK, A, 1, &[], A, Kind::set(RK, Gone));
    k.push_signed(RK, A, 2, &[], A, Kind::set(N5, Admin));
    k.push(H, 5, &[], A, Kind::set(N5, Admin));
    let ck = k.content(N5, 3, &[], A);
    for (w, c) in [(&w, c), (&k, ck)] {
        assert!(!fixed(w, &[]).valid.contains(&c), "{:?}", fixed(w, &[]));
    }
}

/// As above for a may-grant grant (C2 by G1): a grant whose path gave may-grant only by a value
/// ended at its key counts for nothing, the flag on its last hop (B holding write with the flag on A
/// until 3, granting on A) or the role on a hop before it (B holding write on A until 3, granting
/// on T1 through [A], whose record edge gives admin).
#[test]
fn an_idle_may_grant_grant_with_no_right_moves_no_first_point_back() {
    for two in [false, true] {
        let mut w = account();
        let (path, on): (&[Thing], Thing) = if two { (&[A], T1) } else { (&[], A) };
        let g = if two { Kind::set(B, Write) } else { Kind::set(B, Write).may_grant() };
        w.push(H, 1, &[], A, g.clone().until(3));
        let idle = w.push(B, 6, path, on, Kind::set(N6, Write).until(8));
        w.push(H, 7, &[], A, g);
        let grant = w.push(B, 10, path, on, Kind::set(N6, Write));
        let c = w.content(N6, 9, &[], on);
        let rd = fixed(&w, &[]);
        assert!(!rd.applied.contains(&idle) && rd.by_flag.contains(&grant) && !rd.valid.contains(&c), "{two}: {rd:?}");
    }
}


/// A key that removed itself makes no may-grant grant (G1: every hop gives the role, the key hop
/// first): B, holding write with the
/// flag on A, removes its own key, then grants N6 write on A by may-grant. It applies nowhere and,
/// made with no right (C2), moves no first point back: N6's content before its later grant shows not.
#[test]
fn a_removed_key_makes_no_may_grant_grant() {
    let mut w = account();
    w.push(H, 1, &[], A, Kind::set(B, Write).may_grant());
    w.push_signed(own_key(B), B, 2, &[], B, Kind::set(own_key(B), Gone));
    let g = w.push(B, 3, &[], A, Kind::set(N6, Write));
    w.push(H, 6, &[], A, Kind::set(N6, Write));
    let c = w.content(N6, 4, &[], A);
    let rd = fixed(&w, &[]);
    assert!(rd.key_role(own_key(B), B) == Gone && !rd.applied.contains(&g) && rd.role(N6, A) == Write && !rd.valid.contains(&c), "{rd:?}");
}

/// A lowered key's commit can stand at a node trusting nothing, which is then shown the lowering
/// (each lowering judged once, as among members): RK grants TK admin; TK demotes RK to write;
/// H, having received neither, removes both in one commit. RK's removal is judged with RK at
/// write, so it puts RK's grant of TK (applied by admin) in no question; TK's removal then drops
/// the demotion, and the grant stands in the next pass. Nothing of TK's shows either way (TK's
/// own removal takes it), both removals are shown as disputes, and a node trusting them drops
/// the grant. The same world with things for the keys reads alike.
#[test]
fn a_lowered_keys_grant_standing_where_nothing_is_trusted_is_shown() {
    for keys in [true, false] {
        let mut w = account();
        let (x, z) = if keys { (RK, TK) } else { (X, Z) };
        let by = |w: &mut World, k: Thing, ts: u32, kind: Kind| if keys { w.push_signed(k, A, ts, &[], A, kind) } else { w.push(k, ts, &[], A, kind) };
        w.push(H, 1, &[], A, Kind::set(x, Admin));
        let g = by(&mut w, x, 4, Kind::set(z, Admin));
        let c = by(&mut w, z, 5, Kind::Content);
        let cut = w.cut(&[g]);
        by(&mut w, z, 5, Kind::set(x, Write).listing(cut));
        let late = by(&mut w, z, 6, Kind::set(B, Admin));
        let out = w.commit(H, 7, &[], A, vec![Kind::set(x, Gone), Kind::set(z, Gone)]);
        let v = View::all(&w);
        let rd = judge(&w, &Rules::fixed(), &v);
        assert!(rd.applied.contains(&g) && !rd.valid.contains(&c) && !rd.applied.contains(&late) && rd.role(B, A) == Gone, "{keys}: {rd:?}");
        assert_eq!(disputes(&w, &Rules::fixed(), &v), out, "{keys}");
        let t = fixed(&w, &out);
        assert!(t.dropped.contains(&g) && !t.valid.contains(&c) && t.role(B, A) == Gone, "{keys}: {t:?}");
    }
}
