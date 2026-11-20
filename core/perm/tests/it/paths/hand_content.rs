//! Hand worlds of step 3b: one counterpart per rule-naming hand test of roles-model `paths` on
//! content, vouches, addenda, covers and purges (src/paths/tests.rs, same names), read by the walk
//! and the model at the views the model's test reads (`agree`: statuses, histories, roles, void
//! trusted writes, every delta's validity, copies, purges, disputes), with the walk's own reason
//! where the rule is named; then the walk's own worlds for draft sentences no model test reaches.
//! spec/permissions.md §5.1, §5.2 (draft: notes/a1-spec/permissions.md §5.1 Vouches, §5.2, §6).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::{agree, agree_all, cid, tid, verdict, walk};
use osis_base::{Ak, CommitId, PurgeBy, Role as R, Tid, Ts, WallMs};
use osis_perm::paths::{By, Commit, Content, Delta, DeltaClass, EdgeWrite, Part, PartKind, Paths, Status};
use osis_perm::{Edge, Frontier, WriteId};
use roles_model::paths::*;
use roles_model::Role::{Admin, None as Gone, Write};
use roles_model::Rng;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A with H (mint), X and B paired by H at 1.
fn paired() -> (World, Id, Id) {
    let mut w = account();
    let gx = w.edge(H, 1, &[], A, X, Admin, &[]);
    let gb = w.edge(H, 1, &[], A, B, Admin, &[]);
    (w, gx, gb)
}

/// The invite world of the model's tests: A2 (K's) shares T1 at write inviting read, by H
/// through A; K gives X write on A2.
fn invited() -> World {
    let mut w = account();
    w.push(H, 1, &[A], T1, Kind::set(A2, Write).inviting(roles_model::Role::Read));
    w.edge(K, 1, &[], A2, X, Write, &[]);
    w
}

fn all(w: &World, trust: &[Id]) -> View {
    View::all(w).trusting(trust)
}

// ---- Safety and liveness ----

// spec/permissions.md §5.2: a cut write the removal or a writer's addendum names stands, a later
// one does not.
#[test]
fn a_write_the_remover_or_a_writer_received_shows_a_later_one_does_not() {
    let (mut w, ..) = paired();
    let listed = w.content(X, 3, &[A], T1);
    let witnessed = w.content(X, 4, &[A], T1);
    w.content(X, 4, &[A, ORG], T2);
    w.content(X, 5, &[A], T1);
    let r = w.edge(H, 6, &[], A, X, Gone, &[listed]);
    let ad = w.addendum(B, 7, &[A], T1, r, &[witnessed]);
    w.content(X, 8, &[A], T1);
    w.content(B, 8, &[A, ORG], T2);
    agree_all(&w, &[r]);
    agree(&w, &all(&w, &[r]).without(&[ad]));
    assert_eq!(verdict(&w, &all(&w, &[r]), listed), Some(Content::Valid(By::Listed)));
    assert_eq!(verdict(&w, &all(&w, &[r]), witnessed), Some(Content::Valid(By::Vouched)));
}

// spec/permissions.md §5.2: a write is judged along its stated path alone.
#[test]
fn a_write_on_a_cut_path_never_shows_by_another_path_its_signer_holds() {
    let (mut w, ..) = paired();
    w.edge(K, 1, &[], A2, X, Write, &[]);
    w.edge(B, 2, &[A], T1, A2, Write, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.content(X, 8, &[A], T1);
    let other = w.content(X, 8, &[A2], T1);
    w.content(X, 8, &[ORG], T1);
    w.content(X, 8, &[A2, A, A2], T1);
    agree_all(&w, &[r]);
    let r2 = w.edge(K, 9, &[], A2, X, Gone, &[other]);
    w.content(X, 7, &[A2], T1);
    w.content(X, 10, &[A2], T1);
    agree_all(&w, &[r, r2]);
}

// spec/permissions.md §5.1: the thief's grant to a made-up key holds nothing where the removal is
// trusted, its content included.
#[test]
fn a_made_up_key_holds_nothing_where_the_removal_is_trusted() {
    let (mut w, gx, _) = paired();
    w.edge(X, 2, &[], A, Z, Admin, &[]);
    w.edge(Z, 3, &[], A, H, Gone, &[gx]);
    w.content(Z, 4, &[A], T1);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.content(H, 8, &[A], T1);
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
}

// spec/permissions.md §5.2: a removal reaches a unit only through a node holding both.
#[test]
fn a_removal_logged_only_where_the_node_wrote_leaves_a_window() {
    let (mut w, gx, _) = paired();
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let first = w.content(X, 8, &[A, ORG], T2);
    let source = Set::from([first, gx]);
    let v = View { held: evidence(&w, &Set::from([first]), &source), leaves: Some(Things::from([T2])), trust: Set::new() };
    agree(&w, &v);
    agree(&w, &View { held: evidence(&w, &Set::from([first, r]), &source), ..v });
}

// ---- The role-write gap: vouches ----

fn shared_by_x() -> (World, Id, Id) {
    let (mut w, ..) = paired();
    let gs = w.edge(X, 2, &[A], T1, A2, Write, &[]);
    w.content(K, 3, &[A2], T1);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.content(K, 8, &[A2], T1);
    (w, gs, r)
}

// spec/permissions.md §5.1: a co-admin's vouch keeps a grant the remover did not hold, and the
// writes made under it.
#[test]
fn a_grant_the_remover_did_not_hold_stands_by_a_co_admins_vouch() {
    let (mut w, gs, r) = shared_by_x();
    w.vouch(B, 7, &[A], T1, r, &[gs]);
    agree_all(&w, &[r]);
    let (inp, p) = walk(&w, &all(&w, &[r]));
    assert_eq!(p.status(&inp.ids[&gs]), Some(Status::Applied));
    assert!(p.counting().contains(&(cid(w.cid(r)), cid(w.cid(gs)), tid(T1))));
}

// spec/permissions.md §5.1: a vouch counts only ordered after its removal and for a commit on its
// own thing.
#[test]
fn a_vouch_counts_only_after_its_removal_and_on_its_own_thing() {
    let (mut w, gs, r) = shared_by_x();
    w.vouch(B, 5, &[A], T1, r, &[gs]);
    w.vouch(B, 7, &[], A, r, &[gs]);
    agree_all(&w, &[r]);
    assert!(walk(&w, &all(&w, &[r])).1.counting().is_empty());
}

// spec/permissions.md §5.1 Vouches (draft: an entry counts only against an edge write applying
// as a lowering, an explicit write; Trust set, Seeds: a part that never applied is seeded and
// dropped all the same): X grants Z write on A and leaves A; N5 vouches against the leave,
// naming the grant. The leave trusted (no draft trust set holds a self-removal; the generators
// trust one), it seeds the grant and the vouch keeps nothing. X's vouch on A after H's removal of
// X applies nowhere; the trusted leave seeds it (Dropped, not Unapplied), N5's vouch naming it.
#[test]
fn a_vouch_against_a_self_removal_never_counts() {
    let mut w = account();
    w.edge(H, 1, &[], A, X, Admin, &[]);
    w.edge(H, 1, &[], A, N5, Admin, &[]);
    let g = w.edge(X, 2, &[], A, Z, Write, &[]);
    let leave = w.push(X, 3, &[], A, Kind::set(X, Gone).relying(H));
    w.vouch(N5, 4, &[], A, leave, &[g]);
    agree_all(&w, &[leave]);
    let (inp, p) = walk(&w, &all(&w, &[leave]));
    assert!(p.counting().is_empty());
    assert_eq!((p.status(&inp.ids[&leave]), p.status(&inp.ids[&g])), (Some(Status::Applied), Some(Status::Dropped)));

    // the content world's shape: X's vouch stamped with H's removal of X, ordered after it
    let mut w = account();
    w.edge(H, 1, &[], A, X, Admin, &[]);
    w.edge(H, 1, &[], A, N5, Admin, &[]);
    let r = w.edge(H, 3, &[], A, X, Gone, &[]);
    let xv = w.vouch(X, 3, &[], A, r, &[]);
    let leave = w.edge(X, 4, &[], A, X, Gone, &[]);
    w.vouch(N5, 5, &[], A, leave, &[xv]);
    agree_all(&w, &[leave]);
    let (inp, p) = walk(&w, &all(&w, &[leave]));
    assert!(p.counting().is_empty());
    assert_eq!((p.status(&inp.ids[&leave]), p.status(&inp.ids[&xv])), (Some(Status::Applied), Some(Status::Dropped)));
    let (inp, p) = walk(&w, &all(&w, &[]));
    assert_eq!(p.status(&inp.ids[&xv]), Some(Status::Unapplied));
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

// notes/a1-spec/permissions.md §5.1 Vouches: a counting entry keeps its commit's parts on the
// vouch's own thing alone: B's vouch keeps X's grant on T1 and not the one on T2.
#[test]
fn a_vouch_keeps_a_commits_parts_on_its_own_thing_alone() {
    let (w, on1, on2, r) = two_things();
    agree_all(&w, &[r]);
    let (inp, p) = walk(&w, &all(&w, &[r]));
    assert_eq!((p.status(&inp.ids[&on1]), p.status(&inp.ids[&on2])), (Some(Status::Applied), Some(Status::Dropped)));
    assert_eq!(p.counting(), &BTreeSet::from([(cid(w.cid(r)), cid(w.cid(on1)), tid(T1))]));
}

// notes/a1-spec/permissions.md §5.1 Vouches (Writing: a vouch per thing): with N5, an admin of A,
// vouching on T2 too, both parts stay; without it the part on T2 falls.
#[test]
fn a_commit_writing_two_things_stays_by_a_vouch_on_each() {
    let (mut w, on1, on2, r) = two_things();
    w.edge(H, 1, &[], A, N5, Admin, &[]);
    let v5 = w.vouch(N5, 7, &[A, ORG], T2, r, &[on2]);
    agree_all(&w, &[r]);
    let (inp, p) = walk(&w, &all(&w, &[r]));
    assert_eq!((p.status(&inp.ids[&on1]), p.status(&inp.ids[&on2])), (Some(Status::Applied), Some(Status::Applied)));
    agree(&w, &all(&w, &[r]).without(&[v5]));
}

// spec/permissions.md §5.1: a co-admin's vouch keeps a removal the removed node made.
#[test]
fn a_removal_the_removed_node_made_stays_by_a_co_admins_vouch() {
    let (mut w, ..) = paired();
    w.edge(B, 2, &[A], T1, A2, Write, &[]);
    let out = w.edge(X, 3, &[A], T1, A2, Gone, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.content(K, 8, &[A2], T1);
    w.vouch(B, 7, &[A], T1, r, &[out]);
    agree_all(&w, &[r]);
}

// spec/permissions.md §5.1: the vouch is read from the walk without vouches, so it settles.
#[test]
fn a_vouch_judged_in_the_walk_without_vouches_settles() {
    let (mut w, ..) = paired();
    let down = w.edge(X, 3, &[], A, B, Write, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.vouch(B, 7, &[], A, r, &[down]);
    agree_all(&w, &[r]);
}

// spec/permissions.md §5.1: a key X made up, or X by another path, vouches for nothing.
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
    w.vouch(X, 7, &[A2], T1, r, &[gt]);
    w.vouch(Z, 7, &[], T1, r, &[gt]);
    agree_all(&w, &[r]);
}

// ---- The collateral grantee: re-grant from the first chained write ----

// spec/permissions.md §5.2: a re-granted path's writes count from each edge's first chained write.
#[test]
fn a_collateral_grantees_writes_count_from_its_first_chained_grant() {
    let (mut w, ..) = paired();
    w.edge(X, 2, &[], A, N5, Admin, &[]);
    let week = w.content(N5, 3, &[A], T1);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.edge(H, 8, &[], A, N5, Admin, &[]);
    w.content(N5, 9, &[A], T1);
    agree_all(&w, &[r]);
    assert_eq!(verdict(&w, &all(&w, &[r]), week), Some(Content::Valid(By::Regranted)));
}

// spec/permissions.md §5.2: a grant the thief backdates is chained, so a holder granted later may
// stamp content back to it.
#[test]
fn a_backdated_grant_moves_a_current_holders_first_point_back() {
    let (mut w, ..) = paired();
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.edge(X, 2, &[A], T1, A2, Write, &[]);
    w.edge(B, 7, &[A], T1, A2, Write, &[]);
    let early = w.content(K, 4, &[A2], T1);
    agree_all(&w, &[r]);
    assert_eq!(verdict(&w, &all(&w, &[r]), early), Some(Content::Valid(By::Regranted)));
}

// spec/permissions.md §5.2: a re-granted path counts from the latest of its edges' first chained
// writes: X's write through A2 before A2's share of T1 stays invalid though X's own grant on A2 is
// older (the walk's own world, read by the model too).
#[test]
fn a_re_grant_counts_from_the_latest_edges_first_chained_write() {
    let mut w = account();
    w.edge(K, 1, &[], A2, X, Write, &[]);
    let early = w.content(X, 3, &[A2], T1);
    w.edge(H, 5, &[A], T1, A2, Write, &[]);
    let late = w.content(X, 6, &[A2], T1);
    agree_all(&w, &[]);
    assert_eq!(verdict(&w, &all(&w, &[]), early), Some(Content::Invalid));
    assert_eq!(verdict(&w, &all(&w, &[]), late), Some(Content::Valid(By::Held)));
}

// spec/permissions.md §4: a write no record or earlier chained write gives (a stranger's) is no
// chained write, so it moves no first point back (the walk's own world, read by the model too).
#[test]
fn a_strangers_grant_moves_no_first_point_back() {
    let mut w = account();
    w.edge(Z, 2, &[], T1, A2, Write, &[]);
    let early = w.content(K, 4, &[A2], T1);
    w.edge(H, 7, &[A], T1, A2, Write, &[]);
    agree_all(&w, &[]);
    assert_eq!(verdict(&w, &all(&w, &[]), early), Some(Content::Invalid));
}

// ---- Addenda ----

// spec/permissions.md §5.2: an addendum vouches only against a removal ordered before it: B's
// addendum stamped before H's removal keeps nothing; the one after keeps X's write.
#[test]
fn an_addendum_vouches_only_after_its_removal() {
    let (mut w, ..) = paired();
    let xc = w.content(X, 3, &[A], T1);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.addendum(B, 5, &[A], T1, r, &[xc]);
    agree_all(&w, &[r]);
    assert_eq!(verdict(&w, &all(&w, &[r]), xc), Some(Content::Invalid));
    w.addendum(B, 7, &[A], T1, r, &[xc]);
    agree_all(&w, &[r]);
    assert_eq!(verdict(&w, &all(&w, &[r]), xc), Some(Content::Valid(By::Vouched)));
}

// spec/permissions.md §5.2: an addendum vouches for no commit of its own signer.
#[test]
fn an_addendum_vouches_for_no_commit_of_its_own_signer() {
    let (mut w, ..) = paired();
    w.edge(K, 1, &[], A2, X, Write, &[]);
    w.edge(B, 2, &[A], T1, A2, Write, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    let back = w.content(X, 4, &[A], T1);
    w.addendum(X, 7, &[A2], T1, r, &[back]);
    agree_all(&w, &[r]);
    assert_eq!(verdict(&w, &all(&w, &[r]), back), Some(Content::Invalid));
}

// spec/permissions.md §5.1: a removed signer vouches for nothing of its own.
#[test]
fn a_removed_signer_vouches_for_nothing_of_its_own() {
    let (mut w, ..) = paired();
    w.edge(K, 1, &[], A2, X, Admin, &[]);
    w.edge(H, 1, &[A], T1, A2, Admin, &[]);
    let gz = w.edge(X, 2, &[A], T1, Z, Admin, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.vouch(X, 7, &[A2], T1, r, &[gz]);
    agree_all(&w, &[r]);
    let (inp, p) = walk(&w, &all(&w, &[r]));
    assert!(p.counting().is_empty() && p.status(&inp.ids[&gz]) == Some(Status::Dropped));
}

// spec/permissions.md §5.2: a re-granted writer's addendum written after its new grant vouches.
#[test]
fn a_re_granted_writers_later_addendum_vouches() {
    let (mut w, ..) = paired();
    w.edge(X, 2, &[], A, N5, Admin, &[]);
    let xc = w.content(X, 3, &[A], T1);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.addendum(N5, 7, &[A], T1, r, &[xc]);
    w.edge(H, 8, &[], A, N5, Admin, &[]);
    agree_all(&w, &[r]);
    assert_eq!(verdict(&w, &all(&w, &[r]), xc), Some(Content::Invalid));
    w.addendum(N5, 9, &[A], T1, r, &[xc]);
    agree_all(&w, &[r]);
    assert_eq!(verdict(&w, &all(&w, &[r]), xc), Some(Content::Valid(By::Vouched)));
}

// spec/permissions.md §5.1: the collateral grantee granted again vouches for its own fallen grant.
#[test]
fn a_re_granted_grantee_vouches_for_its_own_fallen_grant() {
    let (mut w, ..) = paired();
    let g5 = w.edge(X, 2, &[], A, N5, Admin, &[]);
    w.content(N5, 3, &[A], T1);
    w.edge(N5, 4, &[A], T1, A2, Write, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.edge(H, 8, &[], A, N5, Admin, &[]);
    agree_all(&w, &[r]);
    w.vouch(N5, 9, &[], A, r, &[g5]);
    agree_all(&w, &[r]);
}

// spec/permissions.md §5.1: an accomplice's vouch voids the trusted removal and leaves no trace.
#[test]
fn a_current_admins_vouch_voids_the_removal_and_leaves_no_trace() {
    let (mut w, gx, gb) = paired();
    let g5 = w.edge(X, 2, &[], A, N5, Admin, &[]);
    let rx = w.edge(X, 5, &[], A, H, Gone, &[gx, gb]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[g5]);
    agree_all(&w, &[r]);
    for by in [Z, X] {
        let mut w = w.clone();
        w.vouch(by, 7, &[], A, r, &[rx]);
        agree_all(&w, &[r]);
    }
    let v5 = w.vouch(N5, 7, &[], A, r, &[rx]);
    agree_all(&w, &[r]);
    agree(&w, &all(&w, &[r]).without(&[v5]));
    let (inp, p) = walk(&w, &all(&w, &[r]));
    assert!(p.void_trusted().contains(&inp.ids[&r]) && p.counting().is_empty());
}

// spec/permissions.md §5.1: a vouch counts only where its removal applies in the first walk.
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
    w.vouch(N5, 7, &[], A, r, &[out, rx, timed]);
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
}

// ---- Purge authors ----

// spec/permissions.md §6: a request by author takes exactly the deltas naming that purge author.
#[test]
fn a_purge_by_author_takes_exactly_that_authors_deltas() {
    let (mut w, ..) = paired();
    let b_as_a = w.content_as(B, 2, &[A], T1, 1);
    w.content_as(H, 2, &[A], T1, 1);
    w.content(B, 2, &[A], T1);
    w.content_as(H, 4, &[A], T1, 1);
    w.purge(B, 3, &[A], T1, A);
    agree_all(&w, &[]);
    let (inp, p) = walk(&w, &all(&w, &[]));
    assert!(p.purged().contains(&inp.ids[&b_as_a]));
}

// spec/permissions.md §6: the author right is held only through the request's own chain.
#[test]
fn a_purge_holds_the_right_only_through_its_own_chain() {
    let mut w = invited();
    w.content_as(K, 2, &[A2], T1, 1);
    w.edge(H, 1, &[], A, X, Admin, &[]);
    w.purge(X, 3, &[A], T1, A2);
    agree_all(&w, &[]);
    w.purge(X, 4, &[A2], T1, A2);
    agree_all(&w, &[]);
}

// spec/permissions.md §6: a removed signer's backdated purge through the cut edge takes nothing;
// listed by the removal it stands.
#[test]
fn a_removed_signers_backdated_purge_takes_nothing() {
    let mut w = invited();
    w.edge(H, 1, &[], A, X, Admin, &[]);
    w.content_as(H, 2, &[A], T1, 1);
    w.content_as(K, 2, &[A2], T1, 1);
    let q = w.purge(X, 5, &[A], T1, A);
    w.purge(X, 5, &[A2], T1, A2);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
    w.edit(r, |kind| kind.listing(BTreeMap::from([(T1, Set::from([q]))])));
    agree_all(&w, &[r]);
}

// ---- Covers ----

// spec/permissions.md §5.2: a cover by a writer not yet holding the removal carries the late write
// for good (the accepted window).
#[test]
fn a_cover_by_a_writer_not_yet_holding_the_removal_carries_the_late_write() {
    let s = Setup { x_a2: 0, ..Setup::default() };
    let m = Sim::build(&s, &Rules::fixed(), &[Move { kind: 46, ts: 7, made: 7 }], &mut Rng(1));
    let late = *m.thief.keys().next().unwrap();
    for n in [B, K, RD, RD3] {
        let v = m.view(n, &Rules::fixed());
        agree(&m.w, &v);
        let (_, p) = walk(&m.w, &v);
        assert!(p.copies().contains(&cid(m.w.cid(late))), "node {n}");
    }
}

// spec/permissions.md §5.2: an own cover named by the removal: the valid covers' copies show the
// forgotten write, named or not.
#[test]
fn a_removal_naming_its_own_cover_keeps_what_the_cover_carries() {
    let (mut w, ..) = paired();
    let x = w.content(X, 3, &[A], T1);
    w.push(B, 4, &[A], T1, Kind::Cover { carries: Set::from([x]) });
    let own = w.push(H, 5, &[A], T1, Kind::Cover { carries: Set::from([x]) });
    let r = w.edge(H, 6, &[], A, X, Gone, &[own]);
    agree(&w, &all(&w, &[r]).without(&[x]));
    w.edit(r, |k| k.listing(BTreeMap::new()));
    agree(&w, &all(&w, &[r]).without(&[x]));
}

// spec/permissions.md §5.2: a fallen cover takes nothing honest; listed, it carries both.
#[test]
fn a_fallen_cover_takes_nothing_honest() {
    let (mut w, ..) = paired();
    let b = w.content(B, 2, &[A], T1);
    let x = w.content(X, 3, &[A], T1);
    let xc = w.push(X, 4, &[A], T1, Kind::Cover { carries: Set::from([b, x]) });
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    agree_all(&w, &[r]);
    agree(&w, &all(&w, &[r]).without(&[b, x]));
    w.edit(r, |k| k.listing(BTreeMap::from([(T1, Set::from([xc]))])));
    agree(&w, &all(&w, &[r]).without(&[b, x]));
    assert_eq!(verdict(&w, &all(&w, &[r]), b), Some(Content::Valid(By::Held)));
    assert_eq!(verdict(&w, &all(&w, &[r]), x), Some(Content::Valid(By::Listed)));
}

// ---- Alike: a reader outside A ----

// spec/permissions.md §5.2: a reader holding the leaves of its evidence reads as a member.
#[test]
fn a_reader_with_the_leaves_of_its_evidence_reads_as_a_member() {
    let (mut w, ..) = paired();
    let g5 = w.edge(X, 2, &[], A, N5, Admin, &[]);
    w.content(N5, 3, &[A], T1);
    let r = w.edge(H, 6, &[], A, X, Gone, &[g5]);
    w.content(N5, 8, &[A], T1);
    let held = View::all(&w).held;
    let unit: Set = held.iter().copied().filter(|&i| w.commits[i].on == T1 || i == r).collect();
    let v = View { held: evidence(&w, &unit, &held), leaves: Some(Things::from([T1, A])), trust: Set::from([r]) };
    agree(&w, &v);
    agree(&w, &View { leaves: Some(Things::from([T1])), ..v });
}

// ---- The walk's own: draft sentences no model test reaches ----

fn t(n: u32) -> Tid {
    let mut b = [0u8; 15];
    b[..4].copy_from_slice(&n.to_be_bytes());
    Tid::from_bytes(b)
}

fn ms(n: u64) -> Ts {
    Ts::make(WallMs(n), 0).unwrap()
}

fn role_class(on: u32, path: &[u32]) -> Part {
    let d = Delta { aspect: Ak::new("keys.0").unwrap(), needs: R::Admin, purge_author: 0, retention: PurgeBy::Admin, class: DeltaClass::RoleClass };
    Part { on: t(on), path: path.iter().map(|&x| t(x)).collect(), kind: PartKind::Delta(d) }
}

fn edge(on: u32, path: &[u32], holder: u32, value: Option<Edge>, listing: Option<&[u64]>) -> Part {
    let frontier = listing.map(|l| Arc::new(Frontier::new(l.iter().map(|&i| c(i)))));
    Part { on: t(on), path: path.iter().map(|&x| t(x)).collect(), kind: PartKind::Edge(EdgeWrite { holder: t(holder), value, frontier, remains: None, adminless: false }) }
}

fn c(i: u64) -> CommitId {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&i.to_be_bytes());
    CommitId(b)
}

fn commit(id: u64, ts: u64, signer: u32, parts: Vec<Part>) -> Commit {
    Commit { id: c(id), ts: ms(ts), signer: t(signer), parts }
}

const KH: u32 = 1;
const KX: u32 = 3;
const KB: u32 = 2;
const KA: u32 = 10;
const KT: u32 = 13;
const KS: u32 = 14;

fn recs() -> BTreeMap<Tid, Tid> {
    BTreeMap::from([(t(KA), t(KH)), (t(KT), t(KA)), (t(KS), t(KA))])
}

fn admin() -> Option<Edge> {
    Some(Edge::new(R::Admin))
}

// spec/permissions.md §1: a commit by a key actor on itself has the members [S]: its delta on
// itself along the empty path is valid with no edge read; along any other path it names S twice.
#[test]
fn a_key_actor_writes_on_itself_as_its_only_member() {
    let commits = [commit(1, 2, KX, vec![role_class(KX, &[])]), commit(2, 2, KX, vec![role_class(KX, &[KA])])];
    let p = Paths::evaluate(&recs(), BTreeSet::new(), &commits);
    assert_eq!(p.content(&WriteId(c(1), 0)), Some(Content::Valid(By::Held)));
    assert_eq!(p.content(&WriteId(c(2), 0)), Some(Content::Invalid));
}

// spec/permissions.md §1: no edge write targets a key actor: one on its own signer, a
// self-removal of its grant on itself included, applies nowhere.
#[test]
fn an_edge_write_on_its_signer_is_bad_input() {
    let commits = [commit(1, 2, KX, vec![edge(KX, &[], KX, None, Some(&[]))]), commit(2, 2, KX, vec![edge(KX, &[], KB, admin(), Some(&[]))])];
    let p = Paths::evaluate(&recs(), BTreeSet::new(), &commits);
    assert_eq!(p.status(&WriteId(c(1), 0)), Some(Status::Unapplied));
    assert_eq!(p.status(&WriteId(c(2), 0)), Some(Status::Unapplied));
}

// spec/permissions.md §5.1: a removal saying retain (`until` 0, role read) restores read in the
// edge as restored, as the draft's words read it (notes/a1-spec/README.md Open 15, not decided):
// a second explicit removal of the same holder then falls from read to none and is judged.
#[test]
fn a_retain_removal_restores_read_as_the_draft_reads_it() {
    let commits = [
        commit(1, 1, KH, vec![edge(KA, &[], KX, admin(), Some(&[]))]),
        commit(2, 5, KH, vec![edge(KA, &[], KX, Some(Edge::kept_end()), Some(&[]))]),
        commit(3, 6, KH, vec![edge(KA, &[], KX, None, Some(&[]))]),
    ];
    let p = Paths::evaluate(&recs(), BTreeSet::new(), &commits);
    let w = p.writes(&t(KX), &t(KA));
    assert_eq!(w.len(), 3);
    assert_eq!((w[2].restored, w[2].explicit), (Some(R::Read), true), "{w:?}");
    assert!(!w[2].cuts(R::Write) && w[1].cuts(R::Write));
}

// spec/permissions.md §5.1: the first counting condition: an edge write of the removal applies as
// a lowering in the first walk, whether or not it takes anything from the edge's value (a vouch is
// part of its removal's list, read wherever the removal drops). X left A by itself before H's
// removal, which lists the leave, so the removal takes nothing from X's value yet falls from X's
// edge as restored and drops X's unlisted grant: B's vouch for that grant keeps it, as roles-model
// `counting` reads it (notes/path-model-findings.md 22: R applies in the first walk).
#[test]
fn a_vouch_counts_against_a_removal_of_a_holder_already_gone() {
    let commits = vec![
        commit(1, 1, KH, vec![edge(KA, &[], KX, admin(), Some(&[]))]),
        commit(2, 1, KH, vec![edge(KA, &[], KB, admin(), Some(&[]))]),
        commit(3, 2, KX, vec![edge(KT, &[KA], 7, Some(Edge::new(R::Write)), Some(&[]))]),
        commit(4, 3, KX, vec![Part { on: t(KA), path: vec![], kind: PartKind::Edge(EdgeWrite { holder: t(KX), value: None, frontier: None, remains: Some(t(KH)), adminless: false }) }]),
        commit(5, 6, KH, vec![edge(KA, &[], KX, None, Some(&[4]))]),
    ];
    let p = Paths::evaluate(&recs(), BTreeSet::new(), &commits);
    assert_eq!((p.status(&WriteId(c(4), 0)), p.status(&WriteId(c(5), 0))), (Some(Status::Applied), Some(Status::Applied)));
    assert_eq!(p.status(&WriteId(c(3), 0)), Some(Status::Dropped));
    let vouch = commit(6, 7, KB, vec![Part { on: t(KT), path: vec![t(KA)], kind: PartKind::Vouch { removal: c(5), list: Frontier::new([c(3)]) } }]);
    let p = Paths::evaluate(&recs(), BTreeSet::new(), &[commits, vec![vouch]].concat());
    assert_eq!(p.counting(), &BTreeSet::from([(c(5), c(3), t(KT))]));
    assert_eq!(p.status(&WriteId(c(3), 0)), Some(Status::Applied));
}

// notes/a1-spec/permissions.md §5.1 Vouches: a counting entry keeps its commit's parts on its
// vouch's thing alone. X's commit c grants holder 7 write on T and on S, both along [A]; H removes
// X listing nothing; B, admin on T alone, vouches on T. The entry keeps c's part on T and not the
// one on S, where B holds nothing: else, X having backdated c and B its accomplice, authority on T
// would keep a write on S no holder of S vouched for. With S's admin H vouching on S too, both stay.
#[test]
fn a_counting_entry_keeps_its_commits_parts_on_its_vouchs_thing_alone() {
    // B holds admin on T only (H's grant through A), not on S
    let commits = vec![
        commit(1, 1, KH, vec![edge(KA, &[], KX, admin(), Some(&[]))]),
        commit(2, 1, KH, vec![edge(KT, &[KA], KB, admin(), Some(&[]))]),
        commit(3, 2, KX, vec![edge(KT, &[KA], 7, Some(Edge::new(R::Write)), Some(&[])), edge(KS, &[KA], 7, Some(Edge::new(R::Write)), Some(&[]))]),
        commit(5, 6, KH, vec![edge(KA, &[], KX, None, Some(&[]))]),
        commit(6, 7, KB, vec![Part { on: t(KT), path: vec![], kind: PartKind::Vouch { removal: c(5), list: Frontier::new([c(3)]) } }]),
    ];
    let p = Paths::evaluate(&recs(), BTreeSet::from([WriteId(c(5), 0)]), &commits);
    assert_eq!(p.counting(), &BTreeSet::from([(c(5), c(3), t(KT))]));
    assert_eq!((p.status(&WriteId(c(3), 0)), p.status(&WriteId(c(3), 1))), (Some(Status::Applied), Some(Status::Dropped)));
    let on_s = commit(7, 7, KH, vec![Part { on: t(KS), path: vec![t(KA)], kind: PartKind::Vouch { removal: c(5), list: Frontier::new([c(3)]) } }]);
    let p = Paths::evaluate(&recs(), BTreeSet::from([WriteId(c(5), 0)]), &[commits, vec![on_s]].concat());
    assert_eq!(p.counting(), &BTreeSet::from([(c(5), c(3), t(KT)), (c(5), c(3), t(KS))]));
    assert_eq!((p.status(&WriteId(c(3), 0)), p.status(&WriteId(c(3), 1))), (Some(Status::Applied), Some(Status::Applied)));
}

fn admin_only(on: u32, path: &[u32], class: DeltaClass) -> Part {
    let aspect = Ak::new(if matches!(class, DeltaClass::Addendum { .. }) { "addenda.0" } else { "doc^.0" }).unwrap();
    let d = Delta { aspect, needs: R::Admin, purge_author: 0, retention: PurgeBy::AuthorOrAdmin, class };
    Part { on: t(on), path: path.iter().map(|&x| t(x)).collect(), kind: PartKind::Delta(d) }
}

// spec/permissions.md §5.2: an admin-only delta is judged with admin in place of write: cut by a
// fall from admin, vouched for only by an addendum whose path gives admin. X, admin on A, writes
// admin-only content on T; H demotes X to write listing nothing; N's addendum (write on A) vouches
// for nothing, B's (admin) does. X's plain write stays valid: the demotion is no cut below write.
#[test]
fn an_addendum_vouches_for_admin_only_content_only_by_admin() {
    const KN: u32 = 4;
    let base = vec![
        commit(1, 1, KH, vec![edge(KA, &[], KX, admin(), Some(&[]))]),
        commit(2, 1, KH, vec![edge(KA, &[], KB, admin(), Some(&[]))]),
        commit(3, 1, KH, vec![edge(KA, &[], KN, Some(Edge::new(R::Write)), Some(&[]))]),
        commit(4, 2, KX, vec![admin_only(KT, &[KA], DeltaClass::Plain)]),
        commit(5, 2, KX, vec![role_class(KT, &[KA])]),
        commit(6, 2, KX, vec![Part { kind: PartKind::Delta(Delta { aspect: Ak::new("doc.0").unwrap(), needs: R::Write, purge_author: 0, retention: PurgeBy::AuthorOrAdmin, class: DeltaClass::Plain }), ..role_class(KT, &[KA]) }]),
        commit(7, 5, KH, vec![edge(KA, &[], KX, Some(Edge::new(R::Write)), Some(&[]))]),
    ];
    let by = |signer, id| commit(id, 6, signer, vec![admin_only(KT, &[KA], DeltaClass::Addendum { removal: c(7), list: Frontier::new([c(4), c(5)]) })]);
    let p = Paths::evaluate(&recs(), BTreeSet::new(), &[base.clone(), vec![by(KN, 8)]].concat());
    assert_eq!(p.content(&WriteId(c(4), 0)), Some(Content::Invalid));
    assert_eq!(p.content(&WriteId(c(6), 0)), Some(Content::Valid(By::Held)));
    let p = Paths::evaluate(&recs(), BTreeSet::new(), &[base, vec![by(KB, 8)]].concat());
    assert_eq!(p.content(&WriteId(c(4), 0)), Some(Content::Valid(By::Vouched)));
    // a role-class delta is no content an addendum vouches for
    assert_eq!(p.content(&WriteId(c(5), 0)), Some(Content::Invalid));
}

// spec/permissions.md §5.2: a commit carrying a purge request is no content an addendum vouches
// for: X's commit of a write and a purge request, cut, stays invalid whatever B's addendum lists.
#[test]
fn an_addendum_vouches_for_no_commit_carrying_a_purge_request() {
    let base = vec![
        commit(1, 1, KH, vec![edge(KA, &[], KX, admin(), Some(&[]))]),
        commit(2, 1, KH, vec![edge(KA, &[], KB, admin(), Some(&[]))]),
        commit(4, 2, KX, vec![admin_only(KT, &[KA], DeltaClass::Plain), Part { kind: PartKind::Delta(Delta { aspect: Ak::new("doc^.0").unwrap(), needs: R::Write, purge_author: 1, retention: PurgeBy::AuthorOrAdmin, class: DeltaClass::PurgeByAuthor { author: t(KA) } }), ..role_class(KT, &[KA]) }]),
        commit(5, 2, KX, vec![admin_only(KT, &[KA], DeltaClass::Plain)]),
        commit(7, 5, KH, vec![edge(KA, &[], KX, None, Some(&[]))]),
        commit(8, 6, KB, vec![admin_only(KT, &[KA], DeltaClass::Addendum { removal: c(7), list: Frontier::new([c(4), c(5)]) })]),
    ];
    let p = Paths::evaluate(&recs(), BTreeSet::new(), &base);
    assert_eq!(p.content(&WriteId(c(4), 0)), Some(Content::Invalid));
    assert_eq!(p.content(&WriteId(c(5), 0)), Some(Content::Valid(By::Vouched)));
}

// spec/permissions.md §5.1: an entry counts only for a commit ordered before its removal: B's vouch
// naming X's key rotation made after H's removal keeps nothing of it (as a cut's list it would keep
// it whatever the order, §5.2).
#[test]
fn a_vouch_names_no_commit_ordered_after_its_removal() {
    let commits = [
        commit(1, 1, KH, vec![edge(KA, &[], KX, admin(), Some(&[]))]),
        commit(2, 1, KH, vec![edge(KT, &[KA], KB, admin(), Some(&[]))]),
        commit(5, 6, KH, vec![edge(KA, &[], KX, None, Some(&[]))]),
        commit(3, 7, KX, vec![role_class(KT, &[KA])]),
        commit(6, 8, KB, vec![Part { on: t(KT), path: vec![], kind: PartKind::Vouch { removal: c(5), list: Frontier::new([c(3)]) } }]),
    ];
    let p = Paths::evaluate(&recs(), BTreeSet::new(), &commits);
    assert!(p.counting().is_empty());
    assert_eq!(p.content(&WriteId(c(3), 0)), Some(Content::Invalid));
}

// ---- Rules no model control names: one world each, failing where the rule is dropped ----

const KZ: u32 = 4;
const KY: u32 = 6;
const KG: u32 = 5;

fn doc(on: u32, path: &[u32], aspect: &str, class: DeltaClass) -> Part {
    let d = Delta { aspect: Ak::new(aspect).unwrap(), needs: R::Write, purge_author: 0, retention: PurgeBy::AuthorOrAdmin, class };
    Part { on: t(on), path: path.iter().map(|&x| t(x)).collect(), kind: PartKind::Delta(d) }
}

fn plain(on: u32) -> Part {
    doc(on, &[KA], "doc.0", DeltaClass::Plain)
}

fn addendum(on: u32, removal: u64, list: &[u64]) -> Part {
    doc(on, &[KA], "addenda.0", DeltaClass::Addendum { removal: c(removal), list: Frontier::new(list.iter().map(|&i| c(i))) })
}

fn snapshot(on: u32, aspect: &str, carries: &[u64]) -> Part {
    doc(on, &[KA], aspect, DeltaClass::Snapshot { carries: Frontier::new(carries.iter().map(|&i| c(i))) })
}

fn vouch(on: u32, path: &[u32], removal: u64, list: &[u64]) -> Part {
    Part { on: t(on), path: path.iter().map(|&x| t(x)).collect(), kind: PartKind::Vouch { removal: c(removal), list: Frontier::new(list.iter().map(|&i| c(i))) } }
}

/// H grants each of `who` admin on A at 1 (commit IDs 100 on).
fn admins(who: &[u32]) -> Vec<Commit> {
    (0u64..).zip(who).map(|(i, &k)| commit(100 + i, 1, KH, vec![edge(KA, &[], k, admin(), Some(&[]))])).collect()
}

fn verdicts(commits: &[Commit]) -> Paths {
    Paths::evaluate(&recs(), BTreeSet::new(), commits)
}

// spec/permissions.md §5.2 Addenda: an addendum vouches only for a delta ordered before its
// removal: X's write stamped after H's removal stays invalid whatever B's addendum lists (else a
// colluding writer keeps the removed party's later writes).
#[test]
fn an_addendum_vouches_for_nothing_stamped_after_its_removal() {
    let mut w = admins(&[KX, KB]);
    w.push(commit(7, 6, KH, vec![edge(KA, &[], KX, None, Some(&[]))]));
    w.push(commit(8, 8, KX, vec![plain(KT)]));
    w.push(commit(9, 9, KB, vec![addendum(KT, 7, &[8])]));
    assert_eq!(verdicts(&w).content(&WriteId(c(8), 0)), Some(Content::Invalid));
}

// spec/permissions.md §5.2 Addenda: an addendum vouches only for deltas on its own thing: B's
// addendum on S names X's write on T in vain; the same on T vouches.
#[test]
fn an_addendum_vouches_only_on_its_own_thing() {
    let base = [admins(&[KX, KB]), vec![commit(4, 2, KX, vec![plain(KT)]), commit(7, 6, KH, vec![edge(KA, &[], KX, None, Some(&[]))])]].concat();
    let on = |thing| verdicts(&[base.clone(), vec![commit(9, 7, KB, vec![addendum(thing, 7, &[4])])]].concat()).content(&WriteId(c(4), 0));
    assert_eq!(on(KS), Some(Content::Invalid));
    assert_eq!(on(KT), Some(Content::Valid(By::Vouched)));
}

// spec/permissions.md §5.2 Copies: a list naming a snapshot names what it carries for that
// snapshot's thing and aspect, and only a valid snapshot of the delta's thing and aspect shows its
// copy: H's removal names B's snapshots of T's `other.0` and of S's `doc.0`, both carrying X's
// write on T's `doc.0`, which stays cut and is no copy; a snapshot of T's `doc.0` names it.
#[test]
fn a_snapshot_names_and_copies_only_its_own_thing_and_aspect() {
    let with = |s: Part| {
        let w = [admins(&[KX, KB]), vec![commit(4, 2, KX, vec![plain(KT)]), commit(5, 3, KB, vec![s]), commit(7, 6, KH, vec![edge(KA, &[], KX, None, Some(&[5]))])]].concat();
        verdicts(&w).content(&WriteId(c(4), 0))
    };
    assert_eq!(with(snapshot(KT, "other.0", &[4])), Some(Content::Invalid));
    assert_eq!(with(snapshot(KS, "doc.0", &[4])), Some(Content::Invalid));
    assert_eq!(with(snapshot(KT, "doc.0", &[4])), Some(Content::Valid(By::Listed)));
}

// spec/permissions.md §5.2 Addenda: addenda vouch for no snapshot: X's snapshot, cut, stays
// invalid whatever B's addendum lists.
#[test]
fn an_addendum_vouches_for_no_snapshot() {
    let w = [admins(&[KX, KB]), vec![commit(4, 2, KX, vec![snapshot(KT, "doc.0", &[])]), commit(7, 6, KH, vec![edge(KA, &[], KX, None, Some(&[]))]), commit(9, 7, KB, vec![addendum(KT, 7, &[4])])]].concat();
    assert_eq!(verdicts(&w).content(&WriteId(c(4), 0)), Some(Content::Invalid));
}

// spec/permissions.md §5.1 Second walk, §5.2: §5.2 reads a removal's list with its counting
// entries: X's key rotation on T, cut by H's removal, is valid as listed by B's vouch on T.
#[test]
fn a_counting_entry_lists_a_role_class_delta_for_content() {
    let w = [admins(&[KX, KB]), vec![commit(4, 2, KX, vec![role_class(KT, &[KA])]), commit(7, 6, KH, vec![edge(KA, &[], KX, None, Some(&[]))])]].concat();
    assert_eq!(verdicts(&w).content(&WriteId(c(4), 0)), Some(Content::Invalid));
    let w = [w, vec![commit(9, 7, KB, vec![vouch(KT, &[KA], 7, &[4])])]].concat();
    let p = verdicts(&w);
    assert_eq!(p.counting(), &BTreeSet::from([(c(7), c(4), t(KT))]));
    assert_eq!(p.content(&WriteId(c(4), 0)), Some(Content::Valid(By::Listed)));
}

// spec/permissions.md §5.1 step 3, Vouches: no list names its own commit: H's commit removing G
// from A also rotates T's keys along [G, A]; B's vouch naming that commit keeps nothing of it.
#[test]
fn a_vouch_names_nothing_of_its_removals_own_commit() {
    let recs = BTreeMap::from([(t(KA), t(KH)), (t(KT), t(KA)), (t(KG), t(KH))]);
    let w = [
        admins(&[KB, KG]),
        vec![commit(7, 6, KH, vec![edge(KA, &[], KG, None, Some(&[])), role_class(KT, &[KG, KA])]), commit(9, 7, KB, vec![vouch(KT, &[KA], 7, &[7])])],
    ]
    .concat();
    let p = Paths::evaluate(&recs, BTreeSet::new(), &w);
    assert_eq!(p.status(&WriteId(c(7), 0)), Some(Status::Applied));
    assert!(p.counting().is_empty());
    assert_eq!(p.content(&WriteId(c(7), 1)), Some(Content::Invalid));
}

// spec/permissions.md §5.2 Addenda (A is valid: the least fixpoint): validity passes along a chain
// of addenda. X's write is cut by H's removal at 5; Y's addendum at 6 vouches for it, Y is removed
// at 7; Z's addendum at 8 vouches for Y's, Z is removed at 9; B's at 10 vouches for Z's. Each
// holds by the next; without B's none does.
#[test]
fn validity_passes_along_a_chain_of_addenda() {
    let base = [
        admins(&[KX, KB, KY, KZ]),
        vec![
            commit(10, 2, KX, vec![plain(KT)]),
            commit(11, 5, KH, vec![edge(KA, &[], KX, None, Some(&[]))]),
            commit(12, 6, KY, vec![addendum(KT, 11, &[10])]),
            commit(13, 7, KH, vec![edge(KA, &[], KY, None, Some(&[]))]),
            commit(14, 8, KZ, vec![addendum(KT, 13, &[12])]),
            commit(15, 9, KH, vec![edge(KA, &[], KZ, None, Some(&[]))]),
        ],
    ]
    .concat();
    let ids = [10, 12, 14].map(|i| WriteId(c(i), 0));
    let p = verdicts(&base);
    assert!(ids.iter().all(|id| p.content(id) == Some(Content::Invalid)));
    let p = verdicts(&[base, vec![commit(16, 10, KB, vec![addendum(KT, 15, &[14])])]].concat());
    assert!(ids.iter().all(|id| p.content(id) == Some(Content::Valid(By::Vouched))), "{:?}", ids.map(|id| p.content(&id)));
}

// spec/permissions.md §5.2 Addenda: an addendum vouches only for a delta ordered before its
// removal, which is ordered before the addendum, so support only runs back in position and no set
// of addenda supports itself: Y's and Z's addenda, each cut, each naming the other against the
// other's removal, stay invalid.
#[test]
fn addenda_naming_each_other_support_nothing() {
    let w = [
        admins(&[KB, KY, KZ]),
        vec![
            commit(12, 5, KY, vec![addendum(KT, 15, &[14])]),
            commit(14, 5, KZ, vec![addendum(KT, 13, &[12])]),
            commit(13, 6, KH, vec![edge(KA, &[], KY, None, Some(&[]))]),
            commit(15, 6, KH, vec![edge(KA, &[], KZ, None, Some(&[]))]),
        ],
    ]
    .concat();
    let p = verdicts(&w);
    assert_eq!((p.content(&WriteId(c(12), 0)), p.content(&WriteId(c(14), 0))), (Some(Content::Invalid), Some(Content::Invalid)));
}

// `Changed` names the commits whose counting entries changed: B's vouch arriving changes no edge's
// history, yet lists X's key rotation; every arrival order reports it.
#[test]
fn a_counting_change_is_named() {
    let w = [admins(&[KX, KB]), vec![commit(4, 2, KX, vec![role_class(KT, &[KA])]), commit(7, 6, KH, vec![edge(KA, &[], KX, None, Some(&[]))]), commit(9, 7, KB, vec![vouch(KT, &[KA], 7, &[4])])]].concat();
    let mut orders: Vec<Vec<usize>> = vec![vec![]];
    for k in 0..w.len() {
        orders = orders.into_iter().flat_map(|o| (0..=o.len()).map(move |at| [&o[..at], &[k], &o[at..]].concat())).collect();
    }
    for order in orders {
        let mut p = Paths::new(&recs(), BTreeSet::new());
        for &k in &order {
            let before = p.clone();
            let ch = p.add(std::slice::from_ref(&w[k]));
            assert_eq!(super::incremental::check(&before, &p, &ch), None, "order {order:?}, adding {k}");
        }
    }
}

// spec/permissions.md §5.2 Copies: no snapshot carries a role commit, so no list names one through
// a snapshot and no snapshot shows one as a copy: H's removal names B's `keys.0` snapshot claiming
// X's key rotation, which stays cut.
#[test]
fn no_snapshot_carries_a_role_commit() {
    let snap = doc(KT, &[KA], "keys.0", DeltaClass::Snapshot { carries: Frontier::new([c(4)]) });
    let snap = Part { kind: PartKind::Delta(Delta { needs: R::Admin, ..match snap.kind { PartKind::Delta(d) => d, _ => unreachable!() } }), ..snap };
    let w = [admins(&[KX, KB]), vec![commit(4, 2, KX, vec![role_class(KT, &[KA])]), commit(5, 3, KB, vec![snap]), commit(7, 6, KH, vec![edge(KA, &[], KX, None, Some(&[5]))])]].concat();
    let p = verdicts(&w);
    assert_eq!(p.content(&WriteId(c(5), 0)), Some(Content::Valid(By::Held)));
    assert_eq!(p.content(&WriteId(c(4), 0)), Some(Content::Invalid));
    assert!(p.copies().is_empty());
}

// notes/a1-spec/permissions.md §5.1 Vouches, §5.2: a counting entry lists c's role-class parts
// on its vouch's thing alone for content too: X's key rotations on T and on S in one commit, both
// along [A], cut by H's removal; B, admin on T alone, vouches on T: the part on T is listed, the
// one on S stays invalid.
#[test]
fn a_counting_entry_lists_a_role_class_delta_on_its_vouchs_thing_alone() {
    let w = vec![
        commit(1, 1, KH, vec![edge(KA, &[], KX, admin(), Some(&[]))]),
        commit(2, 1, KH, vec![edge(KT, &[KA], KB, admin(), Some(&[]))]),
        commit(4, 2, KX, vec![role_class(KT, &[KA]), role_class(KS, &[KA])]),
        commit(7, 6, KH, vec![edge(KA, &[], KX, None, Some(&[]))]),
        commit(9, 7, KB, vec![vouch(KT, &[], 7, &[4])]),
    ];
    let p = verdicts(&w);
    assert_eq!(p.counting(), &BTreeSet::from([(c(7), c(4), t(KT))]));
    assert_eq!((p.content(&WriteId(c(4), 0)), p.content(&WriteId(c(4), 1))), (Some(Content::Valid(By::Listed)), Some(Content::Invalid)));
}

// notes/a1-spec/permissions.md §5.1 Vouches (c rests on R's edge by a part on N): X's commit
// grants on T along X's own grant there and on S along [A]; H removes X from A; B's vouch on T
// counts for nothing (c's part on T does not rest on X's edge on A), and c's part on S falls.
#[test]
fn an_entry_counts_only_where_cs_part_on_its_thing_rests_on_rs_edge() {
    let w = vec![
        commit(1, 1, KH, vec![edge(KA, &[], KX, admin(), Some(&[]))]),
        commit(2, 1, KH, vec![edge(KT, &[KA], KB, admin(), Some(&[]))]),
        commit(3, 1, KH, vec![edge(KT, &[KA], KX, admin(), Some(&[]))]),
        commit(4, 2, KX, vec![edge(KT, &[], 7, Some(Edge::new(R::Write)), Some(&[])), edge(KS, &[KA], 7, Some(Edge::new(R::Write)), Some(&[]))]),
        commit(7, 6, KH, vec![edge(KA, &[], KX, None, Some(&[]))]),
        commit(9, 7, KB, vec![vouch(KT, &[], 7, &[4])]),
    ];
    let p = verdicts(&w);
    assert!(p.counting().is_empty(), "{:?}", p.counting());
    assert_eq!((p.status(&WriteId(c(4), 0)), p.status(&WriteId(c(4), 1))), (Some(Status::Applied), Some(Status::Dropped)));
}

// spec/permissions.md §5.1 Vouches, §5.2 Position: a commit with no edge-class part is ordered at
// the start of its `ts`, so X's key rotation stamped in the millisecond of H's removal is ordered
// before it (cut by it) and B's vouch keeps it, whatever the signers' tids.
#[test]
fn a_role_class_delta_in_its_removals_millisecond_is_ordered_before_it() {
    let w = [admins(&[KX, KB]), vec![commit(4, 6, KX, vec![role_class(KT, &[KA])]), commit(7, 6, KH, vec![edge(KA, &[], KX, None, Some(&[]))])]].concat();
    assert_eq!(verdicts(&w).content(&WriteId(c(4), 0)), Some(Content::Invalid));
    let p = verdicts(&[w, vec![commit(9, 7, KB, vec![vouch(KT, &[KA], 7, &[4])])]].concat());
    assert_eq!(p.counting(), &BTreeSet::from([(c(7), c(4), t(KT))]));
    assert_eq!(p.content(&WriteId(c(4), 0)), Some(Content::Valid(By::Listed)));
}
