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

/// notes/a1-spec/permissions.md §5.1 Vouches, the first counting condition: an entry counts only
/// against a removal applying as a lowering (an explicit write), never against a self-removal. X
/// grants Z write on A and leaves A; N5 vouches on A against the leave, naming the grant. Trusted
/// (no draft trust set holds a self-removal, but the generators trust one), the leave seeds the
/// grant, and the vouch keeps nothing.
#[test]
fn a_vouch_against_a_self_removal_never_counts() {
    let mut w = account();
    w.edge(H, 1, &[], A, X, Admin, &[]);
    w.edge(H, 1, &[], A, N5, Admin, &[]);
    let g = w.edge(X, 2, &[], A, Z, Write, &[]);
    let leave = w.push(X, 3, &[], A, Kind::set(X, Gone).relying(H));
    w.vouch(N5, 4, &[], A, leave, &[g]);
    let rd = fixed(&w, &[leave]);
    assert_eq!((rd.applied.contains(&leave), rd.counting.is_empty(), rd.dropped.contains(&g), rd.role(Z, A)), (true, true, true, Gone));
}

/// X's one commit grants G write on T1 and on T2, both through A; H removes X listing nothing; B,
/// admin on T1 alone (H's grant through A), vouches on T1 for it.
fn two_things() -> (World, Id, Id, Id) {
    let mut w = account();
    w.edge(H, 1, &[], A, X, Admin, &[]);
    w.edge(H, 1, &[A], T1, B, Admin, &[]);
    let on1 = w.push(X, 2, &[A], T1, Kind::set(G, Write));
    let on2 = w.push(X, 2, &[A, ORG], T2, Kind::set(G, Write));
    w.group(&[on1, on2]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.vouch(B, 7, &[], T1, r, &[on1]);
    (w, on1, on2, r)
}

/// notes/a1-spec/permissions.md §5.1 Vouches (`Entry::OnThing`): a counting entry keeps its
/// commit's parts on the vouch's own thing alone. B's vouch keeps X's grant on T1, where B is an
/// admin, and not the one on T2, where B holds nothing: with a thief who backdated the commit and
/// an accomplice holding T1, authority on T1 would keep a write on T2 no holder of T2 vouched for.
/// Control (`Entry::Whole`, the commit named whole): the grant on T2 stands.
#[test]
fn a_vouch_keeps_a_commits_parts_on_its_own_thing_alone() {
    let (w, on1, on2, r) = two_things();
    let rd = fixed(&w, &[r]);
    assert!(rd.applied.contains(&on1) && !rd.applied.contains(&on2), "{rd:?}");
    assert_eq!((rd.role(G, T1), rd.role(G, T2)), (Write, Gone));
    let whole = fixed_but(&w, &[r], |x| x.entry = Entry::Whole);
    assert!(whole.applied.contains(&on1) && whole.applied.contains(&on2));
}

/// The honest cost: X's two-thing commit reached B (admin on T1) and H's co-admin N5 (admin on A,
/// so on T2) in time. Each vouches on the things it administers, as the writers' rule asks, and both
/// parts stay; without N5's vouch the part on T2 falls unless the remover lists it.
#[test]
fn a_commit_writing_two_things_stays_by_a_vouch_on_each() {
    let (mut w, on1, on2, r) = two_things();
    w.edge(H, 1, &[], A, N5, Admin, &[]);
    let v5 = w.vouch(N5, 7, &[A, ORG], T2, r, &[on2]);
    let rd = fixed(&w, &[r]);
    assert!(rd.applied.contains(&on1) && rd.applied.contains(&on2), "{rd:?}");
    let rd = judge(&w, &Rules::fixed(), &View::all(&w).trusting(&[r]).without(&[v5]));
    assert!(rd.applied.contains(&on1) && !rd.applied.contains(&on2));
}

/// notes/path-model-findings.md 39: a voucher's admin is read in the walk with no vouch counting,
/// where a lowering only a vouch keeps is dropped. X, keeping admin on A2, removed A2's share of T1
/// before the theft (B received it and vouches for it); after H's removal X makes Z an admin of A2,
/// backdates a grant of write on T1 to Z through [A], and Z vouches for it along [A2]. Z held admin
/// on T1 only in the walk where A2's removal is dropped, yet its vouch keeps the grant.
#[test]
#[ignore = "issues/voucher-admin-in-first-walk.md"]
fn repro_a_voucher_holds_admin_by_a_share_only_a_vouch_removes() {
    let (mut w, ..) = paired();
    w.edge(K, 1, &[], A2, X, Admin, &[]);
    w.edge(H, 1, &[A], T1, A2, Admin, &[]);
    let out = w.edge(X, 3, &[A], T1, A2, Gone, &[]);
    let gz = w.edge(X, 5, &[A], T1, Z, Write, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.vouch(B, 7, &[A], T1, r, &[out]);
    w.edge(X, 7, &[], A2, Z, Admin, &[]);
    w.vouch(Z, 7, &[A2], T1, r, &[gz]);
    let rd = fixed(&w, &[r]);
    assert!(rd.applied.contains(&out) && rd.role(A2, T1) == Gone);
    assert!(!rd.applied.contains(&gz) && rd.role(Z, T1) == Gone, "{rd:?}");
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

// ---- The searches (properties: every roles-model gate selects them, and nothing else can move them) ----

fn assert_holds(st: &Stats, what: &str) {
    for k in ["safety", "liveness", "alike", "removal kept", "removal", "own path", "admin", "untrusted", "dispute", "safety N", "admin N", "own path N"] {
        assert!(st.checked.get(k).is_some_and(|n| *n > 0), "{what}: no {k} check ran");
    }
    for k in ["void", "idle", "one reading"] {
        assert!(st.checked.get(k).is_some_and(|n| *n > 0), "{what}: no {k} check ran");
    }
    assert!(st.failures() == 0, "{what}: {:?}\n{:?}", st.fails, st.first);
}

/// Under the first round's reading the wanted behaviour fails where the findings say, and
/// safety holds.
#[test]
#[ignore = "property"]
fn the_notes_rules_fail_liveness_and_alike_never_safety_plain() {
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
#[ignore = "property"]
fn each_fix_is_needed_plain() {
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

fn var(k: &str) -> Option<u64> {
    std::env::var(k).ok().filter(|v| !v.is_empty()).map(|v| v.parse::<u64>().unwrap_or_else(|_| panic!("{k}={v:?} is not a decimal u64")))
}

/// Random worlds `OSIS_ROLES_START` (default 0) on, `OSIS_ROLES_SEEDS` many (13,000: about 215
/// CPU-s), a thread per core, each from its own index (a larger sample is split across holds by
/// the start, as `-- N paths --from K` splits a search).
#[test]
#[ignore = "property"]
fn random_worlds_hold_large() {
    let start = var("OSIS_ROLES_START").unwrap_or(0);
    let n = var("OSIS_ROLES_SEEDS").unwrap_or(13_000);
    let st = random_from(start, n, &Rules::fixed());
    st.print("paths", &Rules::fixed());
    assert_holds(&st, &format!("OSIS_ROLES_START={start}"));
}

/// Every 367th world of the small family (30,636 worlds; `-- 0 paths-exh` runs all
/// of them by hand): a stride coprime with every dimension's size (2, 4, 5, 6, 61;
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

/// What the story's `idle gains` gate must not count as a gain (`void_checks`, `by_right`): A2
/// administers T1 and X writes A2, a path H's removal of X from A does not touch. After the
/// removal X invites Z at write through [A2] at 7, by right, and Z writes T1 at 7, before its
/// invite in key order. X's grant of write to Z through [A], stamped at the removal's `ts` and
/// ordered after it, applies nowhere; held, it is the edge's first chained grant, so Z's write
/// counts from 6 (finding 9: no new right, an earlier `ts`). Z holds write with or without the
/// dead grant: its write showing is no gain by a key that never held the right.
#[test]
fn a_dead_grant_moves_an_invited_keys_first_point_back() {
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
    assert!(!rd.applied.contains(&dead) && rd.invited.contains(&inv) && rd.role(Z, T1) == Write && rd.valid.contains(&c), "{rd:?}");
    let rd = judge(&w, &x, &v.without(&[dead]));
    assert!(rd.invited.contains(&inv) && rd.role(Z, T1) == Write && !rd.valid.contains(&c), "{rd:?}");
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

/// Small worlds of admins granting and removing each other (`tiny`), and of invites (`tiny_invites`;
/// README.md, Paths, for the search): one reading under a relabelling. Control: a lowering whose drops take its author's
/// standing applying, A is left with no admin (counted).
#[test]
#[ignore = "property"]
fn small_worlds_hold_plain() {
    for invites in [false, true] {
        for honest in [Honesty::None, Honesty::Lists, Honesty::Writers] {
            let st = tiny_run(3000, &Rules::fixed(), TinyMode { invites, honest });
            // honest writers make few writes that do not apply: their worlds check `honest` alone here
            let ran = |k: &str| st.checked.get(k).is_some_and(|n| *n > 0);
            let keys: &[&str] = if honest == Honesty::Writers { &["honest", "admin T"] } else { &["void", "admin T", "honest", "idle N", "unapplied N"] };
            assert!(st.failures() == 0 && keys.iter().all(|k| ran(k)), "{invites} {honest:?} {:?} {:?} {:?}", st.checked, st.fails, st.first);
        }
    }
    let no_void = tiny_run(300, &Rules { self_void: false, ..Rules::fixed() }, TinyMode { invites: false, honest: Honesty::None });
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
    w.push(X, 2, &[A2], T1, Kind::set(N6, Role::Read));
    let by_reader = w.push(N6, 3, &[], T1, Kind::finalize(Z));
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

/// A finalize is a shape (spec/permissions.md §2 Finalize: a frontier-less removal of another
/// holder's grant that is no self-removal), whatever a writer means: Z removing its own grant by
/// the empty path with no frontier is a self-removal and applies, so the finalize after it ends
/// nothing; Z removing its own grant along a path ending elsewhere is an explicit removal listing
/// nothing, which drops the grant Z made through it.
#[test]
fn a_frontier_less_removal_of_ones_own_grant_is_no_finalize() {
    let mut w = invited();
    w.push(X, 2, &[A2], T1, Kind::set(Z, Role::Read).until(4));
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
/// always lowers, a timed grant's included; a rewrite raising the invite applies nothing; one
/// bringing the `until` earlier applies.
#[test]
fn a_self_removal_lowers_in_every_component() {
    let timed = |k: Kind| {
        let mut w = invited();
        w.push(X, 2, &[A2], T1, Kind::set(Z, Role::Read).until(9));
        let leave = w.push(Z, 3, &[], T1, k);
        fixed(&w, &[]).applied.contains(&leave)
    };
    assert!(timed(Kind::set(Z, Gone)));
    assert!(timed(Kind::set(Z, Role::Read).until(5)));
    assert!(!timed(Kind::set(Z, Role::Read).until(9).inviting(Role::Read)));
    assert!(!timed(Kind::set(Z, Role::Read)));
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
/// leaves A in one commit, its leave relying on H: both apply. Relying on B instead, the leave is
/// judged with B's removal in effect: B is no remaining admin, so it is refused. H, along [A],
/// takes T1's record edge off D1 (the edge its descent ends with) and grants N5 admin on D1: the
/// grant applies by the path as it stood, then the removal, judged as any lowering, applies and
/// drops nothing of its own commit (no list can name it). Naming one holder twice is bad input.
/// Control (`-refuse-shapes`: a self-removal or a part on the commit's own path refuses the
/// commit): none of these apply.
#[test]
fn a_commit_of_several_writes_is_judged_part_by_part_its_own_path_last() {
    let build = |relies: Thing| {
        let (mut w, ..) = paired();
        let ga = w.edge(H, 1, &[A, T1], D1, A, Admin, &[]);
        let own = w.commit(X, 5, &[], A, vec![Kind::set(X, Gone).relying(relies), Kind::set(B, Gone)]);
        let twice = w.commit(X, 5, &[], A, vec![Kind::set(N5, Admin), Kind::set(N5, Write)]);
        let rec = w.commit(H, 5, &[A], D1, vec![Kind::set(T1, Gone).relying(A).listing(w.cut(&[ga])), Kind::set(N5, Admin)]);
        (w, own, twice, rec)
    };
    let (w, own, twice, rec) = build(H);
    assert!(w.leave(own[1]) && w.sets(own[0]) == Some((B, A)) && w.sets(rec[1]) == Some((T1, D1)));
    let rd = keyed(&w);
    assert!(own.iter().chain(&rec).all(|i| rd.applied.contains(i)) && twice.iter().all(|i| !w.well(*i) && !rd.applied.contains(i)), "{rd:?}");
    assert_eq!((rd.role(X, A), rd.role(B, A), rd.role(N5, A)), (Gone, Gone, Gone));
    assert_eq!((rd.role(T1, D1), rd.role(N5, D1), rd.role(A, D1)), (Gone, Admin, Admin));
    assert!(rd.dropped.is_empty());
    // trusted, the removal's seeds reach no part of its own commit either
    let rd = fixed(&w, &[rec[1]]);
    assert!(rd.dropped.is_empty() && rd.void.is_empty() && rd.role(N5, D1) == Admin, "{rd:?}");
    let (w2, own2, ..) = build(B);
    let rd = fixed(&w2, &[]);
    assert!(rd.applied.contains(&own2[0]) && !rd.applied.contains(&own2[1]) && (rd.role(X, A), rd.role(B, A)) == (Admin, Gone), "{rd:?}");
    let rd = fixed_but(&w, &[], |r| r.refuse_shapes = true);
    assert!(own.iter().chain(&rec).all(|i| !rd.applied.contains(i)) && (rd.role(X, A), rd.role(B, A), rd.role(T1, D1)) == (Admin, Admin, Admin));
}

// ---- The single-use link redemption (spec/permissions.md §7; notes/a1-spec/README.md, OPEN 14) ----

/// The link thing (minted with A, the sharer's account), its key actor, two redeemers and a key
/// the thief makes up.
const LK: Thing = 30;
const L: Thing = 31;
const R1: Thing = 32;
const R2: Thing = 33;

/// A sharing LK by a link: H grants L read inviting read on LK by [A].
fn link() -> World {
    let mut w = World::new(&[(H, A), (A, LK)]);
    w.push(H, 1, &[A], LK, Kind::set(L, Role::Read).inviting(Role::Read));
    w
}

/// A redemption: signing as L, one commit invite-granting `r` read on LK and removing L's own grant.
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

/// Redeemed once: the grant applies by L's invite as it stood, then L's leave, last: R1 reads LK
/// and L holds nothing. Control (`-refuse-shapes`): the redemption applies nowhere, L keeps its
/// grant and R1 gets none.
#[test]
fn a_link_redemption_grants_once_and_ends_the_link() {
    let mut w = link();
    let red = redeem(&mut w, 3, R1);
    assert!(w.leave(red[1]) && w.sets(red[0]) == Some((R1, LK)));
    let rd = keyed(&w);
    assert!(red.iter().all(|i| rd.applied.contains(i)) && rd.invited.contains(&red[0]), "{rd:?}");
    assert_eq!((rd.role(R1, LK), rd.role(L, LK)), (Role::Read, Gone));
    assert!(disputes(&w, &Rules::fixed(), &View::all(&w)).is_empty());
    tiny_gates(&w, &[]);
    let rd = fixed_but(&w, &[], |r| r.refuse_shapes = true);
    assert!(red.iter().all(|i| !rd.applied.contains(i)) && (rd.role(R1, LK), rd.role(L, LK)) == (Gone, Role::Read));
}

/// Redeemed twice concurrently (two holders of the seed, both at 3, or at 3 and 4): the redemption
/// first in key order grants and ends L's grant; the other's grant finds no invite on L's edge and
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
/// gone and applies nowhere; one backdated before it applies by L's invite then, until the
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
/// where its path gives less than admin (invite grants, a finalize, a leave). B holds write
/// inviting write on A and, in one commit, invites Z as reader and N5 as writer; H, not having
/// received it, then lowers B's invite to read. N5's grant needs invite write and falls; Z's needs
/// invite read, which B keeps: by its own need it stands (control `-part-drops`), under the rule
/// it falls with N5's (the commit's `roles.0` delta on A is one part), as today's walk has it
/// (engine `role_paths` class world "a writer's two invites in one commit"). No generator makes
/// parts of one commit whose needs differ (`tiny_invites` never lowers an invite alone, `tiny`
/// commits no leave beside another part), so `-part-drops` reads every generated world alike.
/// And B hands A over to N5
/// (invite and leave in one commit), unseen by H, who then removes B or lowers it to read: N5
/// falls and B ends as H set it under either reading.
#[test]
fn a_writers_commit_on_a_thing_falls_together_where_its_parts_need_differ() {
    for part in [false, true] {
        let rules = Rules { drops: if part { Drops::Part } else { Drops::Commit }, ..Rules::fixed() };
        let mut w = account();
        w.push(H, 1, &[], A, Kind::set(B, Write).inviting(Write));
        w.commit(B, 2, &[], A, vec![Kind::set(Z, Role::Read), Kind::set(N5, Write)]);
        w.push(H, 3, &[], A, Kind::set(B, Write).inviting(Role::Read));
        let rd = judge(&w, &rules, &View::all(&w));
        assert_eq!((rd.role(Z, A), rd.role(N5, A), rd.role(B, A)), (if part { Role::Read } else { Gone }, Gone, Write), "part {part}: {rd:?}");
        for to in [Gone, Role::Read] {
            let mut w = account();
            w.push(H, 1, &[], A, Kind::set(B, Write).inviting(Write));
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
    let start = var("OSIS_ROLES_START").unwrap_or(0);
    let n = var("OSIS_ROLES_SEEDS").unwrap_or(13_000);
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

/// Two admins leaving at once (notes/a1-spec/README.md step 3, For Tess before the switch): H (A's
/// mint admin) and B (granted admin) each leave A at 3, each naming the other as the admin that
/// remains, as each saw it standing. The leave first in key order applies; the later one's named
/// remaining admin has left in the pass, so it applies nothing and its signer stays A's admin:
/// A keeps one admin, the one whose leave came later. Today's walk applies both (the last-admin
/// rule is the writer's check there) and A has none.
#[test]
fn two_admins_leaving_at_once_keep_the_later_one() {
    let mut w = account();
    w.edge(H, 1, &[], A, B, Admin, &[]);
    let lh = w.push(H, 3, &[], A, Kind::set(H, Gone).relying(B));
    let lb = w.push(B, 3, &[], A, Kind::set(B, Gone).relying(H));
    assert!(w.leave(lh) && w.leave(lb) && w.key(lh) < w.key(lb));
    let rd = keyed(&w);
    assert!(rd.applied.contains(&lh) && !rd.applied.contains(&lb), "{rd:?}");
    assert_eq!((rd.role(H, A), rd.role(B, A)), (Gone, Admin));
    tiny_gates(&w, &[]);
}

/// An admin edge gives every invite (notes/a1-spec/permissions.md §2 Path's invite): team M holds
/// admin on T, B holds write on M. B's grants on T through [M] apply as invite grants up to B's
/// role on M (the path's invite: the least of its edges' roles but the last, and the last's
/// invite, every invite at admin): read and write apply, admin does not (it needs admin along the
/// path). X, a reader of M, so invites readers and not writers. Today a grant names its invite
/// and M's names none, so none of B's or X's applies.
#[test]
fn a_writer_of_an_admin_team_invites_up_to_its_own_role() {
    const M: Thing = 41;
    const T: Thing = 42;
    let mut w = World::new(&[(H, M), (H, T)]);
    w.edge(H, 1, &[], T, M, Admin, &[]);
    w.edge(H, 1, &[], M, B, Write, &[]);
    let read = w.push(B, 2, &[M], T, Kind::set(Z, Role::Read));
    let write = w.push(B, 2, &[M], T, Kind::set(N5, Write).inviting(Role::Read));
    let admin = w.push(B, 2, &[M], T, Kind::set(N6, Admin));
    // a reader of M invites readers to T
    w.edge(H, 1, &[], M, X, Role::Read, &[]);
    let x_read = w.push(X, 3, &[M], T, Kind::set(K, Role::Read));
    let x_write = w.push(X, 3, &[M], T, Kind::set(A2, Write));
    let rd = keyed(&w);
    assert!(rd.invited.contains(&read) && rd.invited.contains(&write) && !rd.applied.contains(&admin), "{rd:?}");
    assert!(rd.invited.contains(&x_read) && !rd.applied.contains(&x_write), "{rd:?}");
    assert_eq!((rd.role(Z, T), rd.role(N5, T), rd.role(N6, T), rd.role(K, T), rd.role(A2, T)), (Role::Read, Write, Gone, Role::Read, Gone));
    tiny_gates(&w, &[]);
}

/// A thing detached from its folder (notes/a1-spec/README.md Open 21): H mints A (the folder),
/// A mints T. H grants itself admin on T by [A] (its direct edge (H, T)), then removes A's record
/// edge on T by its descent [], naming itself as the admin that remains: both apply. A record edge
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
    let cut = w.push(H, 2, &[], T, Kind::set(A, Gone).listing(w.cut(&[g])).relying(H));
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

// ---- The remaining admin past the lowering's drops (notes/a1-spec/README.md, OPEN 5) ----

/// M mints A, grants H admin until 20 and X admin, and leaves naming X; X grants B admin. H
/// removes X naming B, listing nothing: H's own edge is timed, so B's is the remaining admin it
/// relies on, and its drops take X's grant of B: void, X stays an admin and A keeps a standing
/// one, trusted or not. Control (the rule read before the drops alone): the removal applies and A
/// is left with no standing admin, though no write was marked. Listing X's grant of B, it applies.
#[test]
fn a_lowering_whose_drops_take_its_remaining_admin_is_void() {
    let mut w = minted_by(M);
    w.push(M, 1, &[], A, Kind::set(H, Admin).until(20));
    let gx = w.edge(M, 1, &[], A, X, Admin, &[]);
    let leave = w.edge(M, 2, &[], A, M, Gone, &[]);
    w.rely(leave, X);
    let xb = w.edge(X, 3, &[], A, B, Admin, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.rely(r, B);
    let standing = |rd: &Reading| rd.roles.iter().any(|(e, x)| e.1 == A && *x == Admin);
    for t in [&[][..], &[r]] {
        let rd = fixed(&w, t);
        assert!(rd.applied.contains(&leave) && !rd.applied.contains(&r) && rd.role(X, A) == Admin && standing(&rd), "{t:?} {rd:?}");
    }
    let rd = fixed_but(&w, &[], |x| x.remains_kept = false);
    assert!(rd.applied.contains(&r) && rd.dropped.contains(&xb) && !standing(&rd), "{rd:?}");
    w.edit(r, |k| k.listing(BTreeMap::from([(A, Set::from([xb, gx]))])));
    let rd = fixed(&w, &[r]);
    assert!(rd.applied.contains(&r) && rd.role(B, A) == Admin && rd.role(X, A) == Gone);
}

// ---- The last edge is a hop of the stated path (notes/a1-spec/README.md, OPEN 9) ----

/// A reaches D1 by descent (A, T1, D1: two steps) and also holds a direct grant on D1. J, admin on
/// D1, writes T2 through D1 (which holds write there) after H removes J from D1 by [A], naming no
/// remaining admin. The path's last hop is T1's record edge, not one edge from A: it has no last
/// edge, so the removal applies nowhere, at a member and at a reader of T2 holding J's write and
/// its evidence alike (A's direct grant on D1 is on no path it holds). Control (A's direct grant
/// read as the last edge though no hop): a member applies the removal and J's write falls, the
/// reader refuses it and shows the write. Naming T1 (its record edge) it applies at both.
#[test]
fn a_remaining_admin_by_a_descent_of_two_steps_is_named() {
    let mut w = account();
    let ga = w.edge(H, 1, &[A, T1], D1, A, Admin, &[]);
    w.edge(H, 1, &[A], D1, J, Admin, &[]);
    w.push(H, 1, &[A, ORG], T2, Kind::set(D1, Write));
    let r = w.edge(H, 4, &[A], D1, J, Gone, &[]);
    let late = w.content(J, 5, &[D1], T2);
    let all = View::all(&w).held;
    let reader = View { held: evidence(&w, &Set::from([late]), &all), leaves: None, trust: Set::new() };
    assert!(reader.held.contains(&r) && !reader.held.contains(&ga));
    let shows = |w: &World, rules: &Rules| (judge(w, rules, &View::all(w)).shows(late), judge(w, rules, &reader).shows(late));
    assert_eq!(shows(&w, &Rules::fixed()), (true, true));
    assert_eq!(shows(&w, &Rules { last_hop: false, ..Rules::fixed() }), (false, true));
    w.rely(r, T1);
    assert_eq!(shows(&w, &Rules::fixed()), (false, false));
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
    w.rely(leave, A);
    assert!(w.leave(leave));
    let rd = fixed(&w, &[]);
    assert!(rd.applied.contains(&leave) && rd.role(Z, T1) == Write && rd.role(A2, T1) == Gone);
    assert!(disputes(&w, &Rules::fixed(), &View::all(&w)).is_empty());
    let all = Rules { candidates: Candidates::All, ..Rules::fixed() };
    assert_eq!(disputes(&w, &all, &View::all(&w)), vec![leave]);
    assert!(!judge(&w, &all, &View::all(&w).trusting(&[leave])).shows(gz));
}

// ---- Seeds by need: a demotion to write (a kiosk) ----

/// A2 holds admin on T1 inviting read; X, a writer of A2, invites G to read T1 through A2; B, not
/// having received the invite, demotes A2 on T1 to write inviting read (a kiosk: a holder kept at
/// write). The invite's need on (A2, T1) is read as an invite, which the demotion still gives:
/// its audit keeps it at a node trusting nothing, and a trusted demotion's seeds (its value's
/// unmet needs) keep it too, so both read alike and nothing is shown. Control (seeds every
/// unlisted write resting on the edge): the trusting node drops the invite and the demotion is
/// shown as a dispute.
#[test]
fn a_trusted_demotion_to_write_keeps_the_invites_under_it() {
    let mut w = account();
    w.edge(H, 1, &[], A, B, Admin, &[]);
    w.push(H, 1, &[A], T1, Kind::set(A2, Admin).inviting(Role::Read));
    w.edge(K, 1, &[], A2, X, Write, &[]);
    let gi = w.push(X, 4, &[A2], T1, Kind::set(G, Role::Read));
    let kiosk = w.push(B, 6, &[A], T1, Kind::set(A2, Write).inviting(Role::Read));
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

/// H grants N5 admin at 3 and again at 11; N5 gives N6 write inviting write until 10 at 8,
/// removes N6 at 9, and demotes H to write inviting write at 11 listing only H's second grant.
/// The removal of N6 falls from write, is judged and applied; the demotion of H drops H's first
/// grant of N5, and the restart leaves N5 no right at 8 and 9: the grant of N6 does not apply,
/// and the removal of N6 still applies by its verdict. Without the grant held the removal never
/// falls and does not apply. What users observe is the same either way (N6 never holds a role,
/// every role over time, invite and content alike): only whether the removal of N6 shows as
/// applied differs, which nobody sees.
#[test]
fn an_unapplied_grant_changes_nothing_observed() {
    let mut w = account();
    let again = w.edge(H, 11, &[], A, N5, Admin, &[]);
    w.edge(N5, 11, &[], A, H, Write, &[again]);
    w.edit(1, |k| k.inviting(Write));
    let r6 = w.edge(N5, 9, &[], A, N6, Gone, &[]);
    let g6 = w.push(N5, 8, &[], A, Kind::set(N6, Write).inviting(Write).until(10));
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
    let h = w.push(H, 7, &[], A, Kind::set(N5, Write).inviting(Write));
    w.push(N5, 4, &[], A, Kind::set(Z, Write).inviting(Write).listing(w.cut(&[h])));
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
    w.commit(N5, 2, &[], A, vec![Kind::set(H, Admin).until(4), Kind::set(B, Admin).relying(Z)]);
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
/// order), sets H's and N6's admin to end at 5. Judged at its key B's commit applies (both ends
/// pass the last-admin rule on B's standing edge); N6's removal, H's edge timed, applies and drops
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
    let g = w.push(Z, 5, &[], A, Kind::set(B, Admin).relying(H).listing(w.cut(&[0])));
    w.push(H, 2, &[], A, Kind::set(N6, Admin).relying(N6).listing(w.cut(&[0, 1])));
    let end = w.push(Z, 5, &[], A, Kind::set(B, Admin).until(7));
    w.push(N6, 5, &[], A, Kind::set(N5, Gone).relying(Z));
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
/// move 26, shrunk): X, stolen, backdates a grant of admin to a made-up key Z at 1, and Z sets H's
/// admin to end at 7 at 2; H removes X at 6 listing nothing, relying on B. At a node trusting
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
    let r = w.push(H, 6, &[], A, Kind::set(X, Gone).relying(B).listing(w.cut(&[gx])));
    let at_key = Rules { until: Until::AtKey, ..Rules::fixed() };
    let rd = judge(&w, &at_key, &View::all(&w));
    assert!(rd.applied.is_superset(&Set::from([r, end])) && rd.dropped.contains(&gz) && rd.role(H, A) == Gone, "{rd:?}");
    for (rules, t) in [(Rules::fixed(), vec![]), (Rules::fixed(), vec![r]), (at_key, vec![r])] {
        let rd = judge(&w, &rules, &View::all(&w).trusting(&t));
        assert!(rd.applied.contains(&r) && !rd.applied.contains(&end) && rd.role(H, A) == Admin, "{rd:?}");
    }
}

// ---- Making again (`Rules::remake`; notes/role-remake-model.md) ----

fn remake(w: &World, trust: &[Id]) -> Reading {
    judge(w, &Rules::remake(), &View::all(w).trusting(trust))
}

/// The pair no counting rule tells apart (notes/path-model-findings.md 42). X removed N5 at 3;
/// only B received it; H removes X at 6 listing nothing. With N5's key the thief backdates a
/// removal of B to 2. The same held set is the honest history where N5 removed a stolen B at 2
/// and the thief, with X's and B's keys, backdates X's removal of N5 and B's answer to it.
/// Under the vouch (`fixed`), B's vouch: where H's removal is trusted N5 is an admin and B removed,
/// no dispute shown; trusting nothing, B's vouch counts, N5 removed, H's removal shown.
#[test]
fn the_pair_under_the_vouch_reads_the_thiefs_side_unshown() {
    let (mut w, ..) = paired();
    w.edge(H, 1, &[], A, N5, Admin, &[]);
    w.edge(N5, 2, &[], A, B, Gone, &[]);
    let out5 = w.edge(X, 3, &[], A, N5, Gone, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let vb = w.vouch(B, 7, &[], A, r, &[out5]);
    let x = Rules::fixed();
    let v = View::all(&w).trusting(&[r]);
    let rd = judge(&w, &x, &v);
    assert!(rd.counting.is_empty() && rd.role(N5, A) == Admin && rd.role(B, A) == Gone && disputes(&w, &x, &v).is_empty(), "{rd:?}");
    let v = View::all(&w);
    let rd = judge(&w, &x, &v);
    assert!(rd.counting == Set::from([vb]) && rd.role(N5, A) == Gone && rd.role(B, A) == Admin && disputes(&w, &x, &v) == vec![r], "{rd:?}");
}

/// The pair under `remake`: B makes X's removal of N5 again as its own at 7, listing what it had
/// received resting on N5's edge when X's removal reached it (H's grant). An ordinary fight of two
/// admins: where only H's removal is trusted, N5's backdated removal of B applies, B's removal does
/// not, and B's removal is shown as a dispute; trusting B's too (world 1's user), its seeds take
/// N5's write: N5 removed, B an admin, nothing shown; a node trusting nothing shows both removals.
/// World 2's user, shown the same dispute, does not trust B's write and reads B removed. A vouch in
/// either world is inert.
#[test]
fn the_pair_under_remake_is_an_ordinary_fight_shown_to_both_worlds() {
    let (mut w, ..) = paired();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    w.edge(N5, 2, &[], A, B, Gone, &[]);
    w.edge(X, 3, &[], A, N5, Gone, &[g5]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let rb = w.edge(B, 7, &[], A, N5, Gone, &[g5]);
    w.rely(rb, H);
    let x = Rules::remake();
    let v = View::all(&w).trusting(&[r]);
    let rd = judge(&w, &x, &v);
    assert!(rd.role(N5, A) == Admin && rd.role(B, A) == Gone && !rd.applied.contains(&rb) && disputes(&w, &x, &v) == vec![rb], "{rd:?}");
    let v = View::all(&w).trusting(&[r, rb]);
    let rd = judge(&w, &x, &v);
    assert!(rd.role(N5, A) == Gone && rd.role(B, A) == Admin && rd.void.is_empty() && disputes(&w, &x, &v).is_empty(), "{rd:?}");
    let v = View::all(&w);
    assert!(!disputes(&w, &x, &v).is_empty());
    // a vouch is inert under `remake`
    let mut w2 = w.clone();
    w2.vouch(B, 7, &[], A, r, &[]);
    let rd2 = judge(&w2, &x, &View::all(&w2).trusting(&[r]));
    assert!(rd2.counting.is_empty() && rd2.role(N5, A) == Admin && rd2.role(B, A) == Gone, "{rd2:?}");
}

/// Finding 39's world under `remake` (notes/path-model-findings.md 45): B makes X's removal of
/// A2's share of T1 again at 7. X's backdated grant to Z through [A] falls with H's removal, and
/// what Z wrote through A2 while the share stood again (a grant of admin to itself at 6) rests on
/// the edge B lowers, is unlisted, and falls: Z holds nothing on T1, trusted or not. Z's vouch is
/// inert.
#[test]
fn finding_39s_thief_holds_nothing_where_a_witness_makes_the_removal_again() {
    let (mut w, ..) = paired();
    w.edge(K, 1, &[], A2, X, Admin, &[]);
    w.edge(H, 1, &[A], T1, A2, Admin, &[]);
    w.edge(X, 3, &[A], T1, A2, Gone, &[]);
    let gz = w.edge(X, 5, &[A], T1, Z, Write, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.edge(X, 6, &[], A2, Z, Admin, &[]);
    let gz2 = w.edge(Z, 6, &[A2], T1, Z, Admin, &[]);
    w.vouch(Z, 7, &[A2], T1, r, &[gz]);
    w.edge(B, 7, &[A], T1, A2, Gone, &[]);
    for t in [&[][..], &[r]] {
        let rd = remake(&w, t);
        assert!(rd.role(A2, T1) == Gone && rd.role(Z, T1) == Gone && rd.role(A, T1) == Admin && !rd.applied.contains(&gz) && !rd.applied.contains(&gz2), "{rd:?}");
    }
}

/// What a witness making a share again gives back (notes/role-remake-model.md, What users lose):
/// X shared T1 with A2 at 2 (H never received it); K wrote T1 through A2 at 3 and invited G to
/// read at 4; B, which received the share, makes it again at 7. Under `remake` K's content counts
/// back to the first grant (the re-grant rule), and G's invite, a role write made under the fallen
/// share before it was made again, stays dropped. Under the vouch both stand.
#[test]
fn a_share_made_again_counts_content_back_and_drops_role_writes_made_under_it() {
    let (mut w, ..) = paired();
    let gs = w.edge(X, 2, &[A], T1, A2, Write, &[]);
    w.edit(gs, |k| k.inviting(Role::Read));
    let c = w.content(K, 3, &[A2], T1);
    let gi = w.edge(K, 4, &[A2], T1, G, Role::Read, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let mut wf = w.clone();
    let rs = w.edge(B, 7, &[A], T1, A2, Write, &[c, gi]);
    w.edit(rs, |k| k.inviting(Role::Read));
    let rd = remake(&w, &[r]);
    assert!(rd.valid.contains(&c) && rd.role(A2, T1) == Write && !rd.applied.contains(&gi) && rd.role(G, T1) == Gone, "{rd:?}");
    wf.vouch(B, 7, &[A], T1, r, &[gs]);
    let rd = fixed(&wf, &[r]);
    assert!(rd.valid.contains(&c) && rd.applied.contains(&gi) && rd.role(G, T1) == Role::Read, "{rd:?}");
}

/// The window a later honest write closes: X shared T1 with A2 at 2 (H never received it), K wrote
/// T1 through A2 at 3, and B, which received both, removed A2 from T1 at 5 listing K's write. B
/// never makes the share again (its own later removal replaced it), so the share stood from 2 to 5
/// in no reading and K's write, listed by B's removal, is lost. Under the vouch it stands.
#[test]
fn a_share_a_later_honest_removal_replaced_is_never_made_again_and_its_window_is_lost() {
    let (mut w, ..) = paired();
    let gs = w.edge(X, 2, &[A], T1, A2, Write, &[]);
    let c = w.content(K, 3, &[A2], T1);
    let rb = w.edge(B, 5, &[A], T1, A2, Gone, &[c]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let rd = remake(&w, &[r, rb]);
    assert!(!rd.valid.contains(&c), "{rd:?}");
    let mut wf = w.clone();
    wf.vouch(B, 7, &[A], T1, r, &[gs]);
    let rd = fixed(&wf, &[r, rb]);
    assert!(rd.valid.contains(&c), "{rd:?}");
}

/// Two witnesses race (notes/role-remake-model.md, What users lose): X removed N5 and demoted B to write
/// at 3, before the theft; B and N5 received both, H neither; H removes X at 6 listing nothing.
/// Each witness's walk drops what X did, so each holds admin. N5 makes X's demotion of B again
/// at 7: B, now a writer, cannot make X's removal of N5 again. Had B written first, N5 could not
/// have made the demotion again. Which of X's writes stand depends on which witness wrote first,
/// and neither order gives both. Under the vouch B's vouch (its right read with X's writes
/// dropped) keeps both.
#[test]
fn two_witnesses_race_and_neither_order_makes_both_writes_again() {
    let (mut w, ..) = paired();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    let out5 = w.edge(X, 3, &[], A, N5, Gone, &[g5]);
    let down = w.edge(X, 3, &[], A, B, Write, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    // N5 first
    let mut w1 = w.clone();
    let d = w1.edge(N5, 7, &[], A, B, Write, &[]);
    w1.rely(d, H);
    let rb = w1.edge(B, 8, &[], A, N5, Gone, &[g5]);
    w1.rely(rb, H);
    let rd = remake(&w1, &[r, d]);
    assert!(rd.role(B, A) == Write && rd.role(N5, A) == Admin && !rd.applied.contains(&rb), "{rd:?}");
    // B first
    let mut w2 = w.clone();
    let rb = w2.edge(B, 7, &[], A, N5, Gone, &[g5]);
    w2.rely(rb, H);
    let d = w2.edge(N5, 8, &[], A, B, Write, &[]);
    w2.rely(d, H);
    let rd = remake(&w2, &[r, rb]);
    assert!(rd.role(B, A) == Admin && rd.role(N5, A) == Gone && !rd.applied.contains(&d), "{rd:?}");
    // the vouch: B's right read with X's writes dropped
    let mut wf = w.clone();
    wf.vouch(B, 7, &[], A, r, &[out5, down]);
    let rd = fixed(&wf, &[r]);
    assert!(rd.role(B, A) == Write && rd.role(N5, A) == Gone, "{rd:?}");
}

/// A lowering only its victim received (notes/role-remake-model.md, What users lose): X demoted B
/// to write at 3; only B received it. Under `remake` nobody makes it again: B's own leave would
/// audit nothing (a self-removal never does, finding 14), so it is no making again, and B stays an
/// admin. Under the vouch B vouches for it and it stays made.
#[test]
fn a_demotion_only_its_victim_received_is_lost_under_remake() {
    let (mut w, ..) = paired();
    let down = w.edge(X, 3, &[], A, B, Write, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let rd = remake(&w, &[r]);
    assert!(rd.role(B, A) == Admin, "{rd:?}");
    w.vouch(B, 7, &[], A, r, &[down]);
    let rd = fixed(&w, &[r]);
    assert!(rd.role(B, A) == Write, "{rd:?}");
}

/// Content addenda have the shape only through the role layer (notes/role-remake-model.md,
/// Content addenda): X wrote T1 at 3, and removed N5 at 3; only B received either; with N5's key the thief
/// backdates a removal of B to 2; H removes X at 6 listing nothing. B's addendum lists X's write.
/// Under the vouch, trusting H's removal, B's vouch for X's removal of N5 counts for nothing (B
/// holds nothing in the first walk), N5's removal of B applies, and B's addendum, by a writer
/// holding nothing at its key, keeps nothing: X's honest write is lost, no dispute shown. Under
/// `remake` B also makes the removal of N5 again: trusting it, B is an admin and its addendum
/// keeps X's write; trusting only H's removal the write is lost and B's removal is shown. A content
/// write lowers nobody, so a thief holding only content keys cannot contest a witness at all.
#[test]
fn an_addendum_is_contested_only_through_its_witness_standing() {
    let (mut w, ..) = paired();
    let g5 = w.edge(H, 1, &[], A, N5, Admin, &[]);
    w.edge(N5, 2, &[], A, B, Gone, &[]);
    let c = w.content(X, 3, &[A], T1);
    let out5 = w.edge(X, 3, &[], A, N5, Gone, &[g5]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.addendum(B, 7, &[A], T1, r, &[c]);
    let mut wf = w.clone();
    wf.vouch(B, 7, &[], A, r, &[out5]);
    let x = Rules::fixed();
    let v = View::all(&wf).trusting(&[r]);
    let rd = judge(&wf, &x, &v);
    assert!(!rd.valid.contains(&c) && rd.role(B, A) == Gone && disputes(&wf, &x, &v).is_empty(), "{rd:?}");
    let rb = w.edge(B, 7, &[], A, N5, Gone, &[g5]);
    w.rely(rb, H);
    let rd = remake(&w, &[r, rb]);
    assert!(rd.valid.contains(&c) && rd.role(B, A) == Admin && rd.role(N5, A) == Gone, "{rd:?}");
    let x = Rules::remake();
    let v = View::all(&w).trusting(&[r]);
    let rd = judge(&w, &x, &v);
    assert!(!rd.valid.contains(&c) && disputes(&w, &x, &v) == vec![rb], "{rd:?}");
    // without the thief's role write the witness stands and the write counts, whatever content
    // the thief adds
    let (mut w3, ..) = paired();
    let g5 = w3.edge(H, 1, &[], A, N5, Admin, &[]);
    let c = w3.content(X, 3, &[A], T1);
    w3.edge(X, 3, &[], A, N5, Gone, &[g5]);
    let r = w3.edge(H, 6, &[], A, X, Gone, &[]);
    w3.content(X, 2, &[A], T1);
    w3.addendum(B, 7, &[A], T1, r, &[c]);
    let rd = remake(&w3, &[r]);
    assert!(rd.valid.contains(&c), "{rd:?}");
}

/// The required gates under `Rules::remake`, as `random_worlds_hold_large` (from
/// `OSIS_ROLES_START`, `OSIS_ROLES_SEEDS` many, 13,000 by default).
#[test]
#[ignore = "property"]
fn remake_random_worlds_hold_large() {
    let start = var("OSIS_ROLES_START").unwrap_or(0);
    let n = var("OSIS_ROLES_SEEDS").unwrap_or(13_000);
    let st = random_from(start, n, &Rules::remake());
    st.print("paths-remake", &Rules::remake());
    assert_holds(&st, &format!("remake OSIS_ROLES_START={start}"));
}

/// The required gates under `Rules::remake` on every 367th family world.
#[test]
#[ignore = "property"]
fn remake_small_family_holds_large() {
    let st = family_run(&Rules::remake(), 367);
    st.print("paths-exh-remake", &Rules::remake());
    assert_holds(&st, "remake family");
}

/// `remake` changes only the vouch and the story's honest writing: small worlds (no vouch, no
/// story) read alike under both rule sets, so the `tiny` searches are not run under it.
#[test]
fn tiny_worlds_read_alike_under_remake() {
    for invites in [false, true] {
        for i in 0..200 {
            let t = tiny_world(i, TinyMode { invites, honest: Honesty::None }, &Rules::fixed());
            let (f, r) = (judge(&t.w, &Rules::fixed(), &t.v), judge(&t.w, &Rules::remake(), &t.v));
            assert!(f.observed(&t.w) == r.observed(&t.w) && f.applied == r.applied && f.dropped == r.dropped && f.void == r.void, "{invites} {i}");
        }
    }
}

/// A witness's earlier write dropped for good by a removed key's backdated lowering
/// (notes/role-remake-model.md, Found on the way): H paired N5; B shared T1 with A2 at 2;
/// X removed N5 at 3, listing H's grant, and everyone received it; H removes X at 6 listing it.
/// With N5's key the thief backdates a removal of B to 2, ordered after B's share. It applies at
/// its key (N5 an admin then) and drops B's share (unlisted, resting on B's edge); X's removal of
/// N5 then drops the thief's write, but a drop stands for good (finding 16): the share stays
/// dropped, under the vouch and under `remake` alike, trusted or not. No vouch or witness is
/// involved: B is an admin throughout and its share is lost.
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
    for x in [Rules::fixed(), Rules::remake()] {
        for t in [&[][..], &[r]] {
            let rd = judge(&w, &x, &View::all(&w).trusting(t));
            assert!(rd.role(B, A) == Admin && !rd.applied.contains(&down) && !rd.applied.contains(&gs) && rd.role(A2, T1) == Gone && rd.stray.contains(&gs), "{rd:?}");
        }
    }
}
