//! Hand worlds of step 3b: one counterpart per rule-naming hand test of roles-model `paths` on
//! content, addenda, covers and purges (src/paths/tests.rs, same names), read by the walk
//! and the model at the views the model's test reads (`agree`: statuses, histories, roles, void
//! trusted writes, every delta's validity, copies, purges, disputes), with the walk's own reason
//! where the rule is named; then the walk's own worlds for draft sentences no model test reaches.
//! spec/permissions.md §5.1, §5.2, §6.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::{agree, agree_all, all, cid, commit, invited, model_cid, ms, paired, t, verdict, walk};
use osis_base::{Ak, PurgeBy, Role as R, Tid};
use osis_perm::paths::{By, Commit, Content, Delta, DeltaClass, EdgeWrite, Part, PartKind, Paths, Status};
use osis_perm::{Edge, Frontier, WriteId};
use roles_model::paths::*;
use roles_model::Role::{Admin, None as Gone, Write};
use roles_model::Rng;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

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

// spec/permissions.md §5.1 (Frontier: nothing but the frontier decides what X's writes before T
// survive): X's grant H's removal does not list falls, with K's writes resting on it, whoever else
// received it; listed, it stands.
#[test]
fn a_grant_the_removal_does_not_list_falls_and_a_listed_one_stands() {
    let (mut w, gs, kc, r, later) = shared_by_x();
    agree_all(&w, &[r]);
    let (inp, p) = walk(&w, &all(&w, &[r]));
    assert_eq!(p.status(&inp.ids[&gs]), Some(Status::Dropped));
    assert_eq!((verdict(&w, &all(&w, &[r]), kc), verdict(&w, &all(&w, &[r]), later)), (Some(Content::Invalid), Some(Content::Invalid)));
    let f = w.cut(&[gs]);
    w.edit(r, |k| k.listing(f));
    agree_all(&w, &[r]);
    let (inp, p) = walk(&w, &all(&w, &[r]));
    assert_eq!(p.status(&inp.ids[&gs]), Some(Status::Applied));
}

// spec/permissions.md §5.1: the same for a removal X made: unlisted, it is undone and A2 holds T1
// again; listed, it stands.
#[test]
fn a_removal_the_removed_party_made_stands_only_where_listed() {
    let (mut w, ..) = paired();
    w.edge(B, 2, &[A], T1, A2, Write, &[]);
    let out = w.edge(X, 3, &[A], T1, A2, Gone, &[]);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.content(K, 8, &[A2], T1);
    agree_all(&w, &[r]);
    let (inp, p) = walk(&w, &all(&w, &[r]));
    assert_eq!(p.status(&inp.ids[&out]), Some(Status::Dropped));
    let f = w.cut(&[out]);
    w.edit(r, |k| k.listing(f));
    agree_all(&w, &[r]);
    let (inp, p) = walk(&w, &all(&w, &[r]));
    assert_eq!(p.status(&inp.ids[&out]), Some(Status::Applied));
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

// spec/permissions.md §5.2 Re-grant: a may-grant grant is made by right, so it is its edge's first
// point: GU holds write on T1 with the flag, X (K's writer on A2, GU's mint) grants N5 write
// through it; N5's write, cut by H's removal of N5, counts again once H grants N5 write back.
#[test]
fn a_may_grant_grant_is_made_by_right_for_the_re_grant() {
    let mut w = account();
    w.push(H, 1, &[A], T1, Kind::set(GU, Write).may_grant());
    w.edge(K, 1, &[], A2, X, Write, &[]);
    w.push(X, 2, &[A2, GU], T1, Kind::set(N5, Write));
    let early = w.content(N5, 3, &[], T1);
    w.edge(H, 5, &[A], T1, N5, Gone, &[]);
    w.edge(H, 7, &[A], T1, N5, Write, &[]);
    agree_all(&w, &[]);
    assert_eq!(verdict(&w, &all(&w, &[]), early), Some(Content::Valid(By::Regranted)));
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
    let m = Sim::build(&s, &Rules::fixed(), &[Move { kind: 41, ts: 7, made: 7 }], &mut Rng(1));
    let late = *m.thief.keys().next().unwrap();
    for n in [B, K, RD, RD3] {
        let v = m.view(n, &Rules::fixed());
        agree(&m.w, &v);
        let (_, p) = walk(&m.w, &v);
        assert!(p.copies().contains(&model_cid(&m.w, late)), "node {n}");
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

fn role_class(on: u32, path: &[u32]) -> Part {
    let d = Delta { aspect: Ak::new("keys.0").unwrap(), needs: R::Admin, purge_author: 0, purge_by: PurgeBy::Admin, class: DeltaClass::RoleClass };
    Part { on: t(on), path: path.iter().map(|&x| t(x)).collect(), direct: 0, kind: PartKind::Delta(d) }
}

fn edge(on: u32, path: &[u32], holder: u32, value: Option<Edge>, listing: Option<&[u64]>) -> Part {
    let frontier = listing.map(|l| Arc::new(super::whole(&[KH, KX, KB, KA, KT, KS, KZ, KY, KG].map(t), l.iter().map(|&i| cid(i)))));
    Part { on: t(on), path: path.iter().map(|&x| t(x)).collect(), direct: 0, kind: PartKind::Edge(EdgeWrite { holder: t(holder), value, frontier }) }
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
    let commits = [commit(1, ms(2), KX, vec![role_class(KX, &[])]), commit(2, ms(2), KX, vec![role_class(KX, &[KA])])];
    let p = Paths::evaluate(&recs(), BTreeSet::new(), &commits);
    assert_eq!(p.content(&WriteId(cid(1), 0)), Some(Content::Valid(By::Held)));
    assert_eq!(p.content(&WriteId(cid(2), 0)), Some(Content::Invalid));
}

// spec/permissions.md §1: no edge write targets a key actor: one on its own signer, a
// self-removal of its grant on itself included, applies nowhere.
#[test]
fn an_edge_write_on_its_signer_is_bad_input() {
    let commits = [commit(1, ms(2), KX, vec![edge(KX, &[], KX, None, Some(&[]))]), commit(2, ms(2), KX, vec![edge(KX, &[], KB, admin(), Some(&[]))])];
    let p = Paths::evaluate(&recs(), BTreeSet::new(), &commits);
    assert_eq!(p.status(&WriteId(cid(1), 0)), Some(Status::Unapplied));
    assert_eq!(p.status(&WriteId(cid(2), 0)), Some(Status::Unapplied));
}

// spec/permissions.md §5.1: a removal saying retain (`until` 0, role read) restores read in the
// edge as restored, as the draft's words read it (notes/a1-spec/README.md Open 15, not decided):
// a second explicit removal of the same holder then falls from read to none and is judged.
#[test]
fn a_retain_removal_restores_read_as_the_draft_reads_it() {
    let commits = [
        commit(1, ms(1), KH, vec![edge(KA, &[], KX, admin(), Some(&[]))]),
        commit(2, ms(5), KH, vec![edge(KA, &[], KX, Some(Edge::kept_end()), Some(&[]))]),
        commit(3, ms(6), KH, vec![edge(KA, &[], KX, None, Some(&[]))]),
    ];
    let p = Paths::evaluate(&recs(), BTreeSet::new(), &commits);
    let w = p.writes(&t(KX), &t(KA));
    assert_eq!(w.len(), 3);
    assert_eq!((w[2].restored, w[2].explicit), (Some(R::Read), true), "{w:?}");
    assert!(!w[2].cuts(R::Write) && w[1].cuts(R::Write));
}

fn admin_only(on: u32, path: &[u32], class: DeltaClass) -> Part {
    let aspect = Ak::new(if matches!(class, DeltaClass::Addendum { .. }) { "addenda.0" } else { "doc^.0" }).unwrap();
    let d = Delta { aspect, needs: R::Admin, purge_author: 0, purge_by: PurgeBy::AuthorOrAdmin, class };
    Part { on: t(on), path: path.iter().map(|&x| t(x)).collect(), direct: 0, kind: PartKind::Delta(d) }
}

// spec/permissions.md §5.2: an admin-only delta is judged with admin in place of write: cut by a
// fall from admin, vouched for only by an addendum whose path gives admin. X, admin on A, writes
// admin-only content on T; H demotes X to write listing nothing; N's addendum (write on A) vouches
// for nothing, B's (admin) does. X's plain write stays valid: the demotion is no cut below write.
#[test]
fn an_addendum_vouches_for_admin_only_content_only_by_admin() {
    const KN: u32 = 4;
    let base = vec![
        commit(1, ms(1), KH, vec![edge(KA, &[], KX, admin(), Some(&[]))]),
        commit(2, ms(1), KH, vec![edge(KA, &[], KB, admin(), Some(&[]))]),
        commit(3, ms(1), KH, vec![edge(KA, &[], KN, Some(Edge::new(R::Write)), Some(&[]))]),
        commit(4, ms(2), KX, vec![admin_only(KT, &[KA], DeltaClass::Plain)]),
        commit(5, ms(2), KX, vec![role_class(KT, &[KA])]),
        commit(6, ms(2), KX, vec![Part { direct: 0, kind: PartKind::Delta(Delta { aspect: Ak::new("doc.0").unwrap(), needs: R::Write, purge_author: 0, purge_by: PurgeBy::AuthorOrAdmin, class: DeltaClass::Plain }), ..role_class(KT, &[KA]) }]),
        commit(7, ms(5), KH, vec![edge(KA, &[], KX, Some(Edge::new(R::Write)), Some(&[]))]),
    ];
    let by = |signer, id| commit(id, ms(6), signer, vec![admin_only(KT, &[KA], DeltaClass::Addendum { removal: cid(7), list: Frontier::new([cid(4), cid(5)]) })]);
    let p = Paths::evaluate(&recs(), BTreeSet::new(), &[base.clone(), vec![by(KN, 8)]].concat());
    assert_eq!(p.content(&WriteId(cid(4), 0)), Some(Content::Invalid));
    assert_eq!(p.content(&WriteId(cid(6), 0)), Some(Content::Valid(By::Held)));
    let p = Paths::evaluate(&recs(), BTreeSet::new(), &[base, vec![by(KB, 8)]].concat());
    assert_eq!(p.content(&WriteId(cid(4), 0)), Some(Content::Valid(By::Vouched)));
    // a role-class delta is no content an addendum vouches for
    assert_eq!(p.content(&WriteId(cid(5), 0)), Some(Content::Invalid));
}

// spec/permissions.md §5.2: a commit carrying a purge request is no content an addendum vouches
// for: X's commit of a write and a purge request, cut, stays invalid whatever B's addendum lists.
#[test]
fn an_addendum_vouches_for_no_commit_carrying_a_purge_request() {
    let base = vec![
        commit(1, ms(1), KH, vec![edge(KA, &[], KX, admin(), Some(&[]))]),
        commit(2, ms(1), KH, vec![edge(KA, &[], KB, admin(), Some(&[]))]),
        commit(4, ms(2), KX, vec![admin_only(KT, &[KA], DeltaClass::Plain), Part { direct: 0, kind: PartKind::Delta(Delta { aspect: Ak::new("doc^.0").unwrap(), needs: R::Write, purge_author: 1, purge_by: PurgeBy::AuthorOrAdmin, class: DeltaClass::Purge { names: osis_perm::paths::Names::Author(t(KA)) } }), ..role_class(KT, &[KA]) }]),
        commit(5, ms(2), KX, vec![admin_only(KT, &[KA], DeltaClass::Plain)]),
        commit(7, ms(5), KH, vec![edge(KA, &[], KX, None, Some(&[]))]),
        commit(8, ms(6), KB, vec![admin_only(KT, &[KA], DeltaClass::Addendum { removal: cid(7), list: Frontier::new([cid(4), cid(5)]) })]),
    ];
    let p = Paths::evaluate(&recs(), BTreeSet::new(), &base);
    assert_eq!(p.content(&WriteId(cid(4), 0)), Some(Content::Invalid));
    assert_eq!(p.content(&WriteId(cid(5), 0)), Some(Content::Valid(By::Vouched)));
}

// ---- Rules no model control names: one world each, failing where the rule is dropped ----

const KZ: u32 = 4;
const KY: u32 = 6;
const KG: u32 = 5;

fn doc(on: u32, path: &[u32], aspect: &str, class: DeltaClass) -> Part {
    let d = Delta { aspect: Ak::new(aspect).unwrap(), needs: R::Write, purge_author: 0, purge_by: PurgeBy::AuthorOrAdmin, class };
    Part { on: t(on), path: path.iter().map(|&x| t(x)).collect(), direct: 0, kind: PartKind::Delta(d) }
}

fn plain(on: u32) -> Part {
    doc(on, &[KA], "doc.0", DeltaClass::Plain)
}

fn addendum(on: u32, removal: u64, list: &[u64]) -> Part {
    doc(on, &[KA], "addenda.0", DeltaClass::Addendum { removal: cid(removal), list: Frontier::new(list.iter().map(|&i| cid(i))) })
}

fn snapshot(on: u32, aspect: &str, carries: &[u64]) -> Part {
    doc(on, &[KA], aspect, DeltaClass::Snapshot { carries: Frontier::new(carries.iter().map(|&i| cid(i))), stated: BTreeMap::new(), own: false })
}

/// H grants each of `who` admin on A at 1 (commit IDs 100 on).
fn admins(who: &[u32]) -> Vec<Commit> {
    (0u64..).zip(who).map(|(i, &k)| commit(100 + i, ms(1), KH, vec![edge(KA, &[], k, admin(), Some(&[]))])).collect()
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
    w.push(commit(7, ms(6), KH, vec![edge(KA, &[], KX, None, Some(&[]))]));
    w.push(commit(8, ms(8), KX, vec![plain(KT)]));
    w.push(commit(9, ms(9), KB, vec![addendum(KT, 7, &[8])]));
    assert_eq!(verdicts(&w).content(&WriteId(cid(8), 0)), Some(Content::Invalid));
}

// spec/permissions.md §5.2 Addenda: an addendum vouches only for deltas on its own thing: B's
// addendum on S names X's write on T in vain; the same on T vouches.
#[test]
fn an_addendum_vouches_only_on_its_own_thing() {
    let base = [admins(&[KX, KB]), vec![commit(4, ms(2), KX, vec![plain(KT)]), commit(7, ms(6), KH, vec![edge(KA, &[], KX, None, Some(&[]))])]].concat();
    let on = |thing| verdicts(&[base.clone(), vec![commit(9, ms(7), KB, vec![addendum(thing, 7, &[4])])]].concat()).content(&WriteId(cid(4), 0));
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
        let w = [admins(&[KX, KB]), vec![commit(4, ms(2), KX, vec![plain(KT)]), commit(5, ms(3), KB, vec![s]), commit(7, ms(6), KH, vec![edge(KA, &[], KX, None, Some(&[5]))])]].concat();
        verdicts(&w).content(&WriteId(cid(4), 0))
    };
    assert_eq!(with(snapshot(KT, "other.0", &[4])), Some(Content::Invalid));
    assert_eq!(with(snapshot(KS, "doc.0", &[4])), Some(Content::Invalid));
    assert_eq!(with(snapshot(KT, "doc.0", &[4])), Some(Content::Valid(By::Listed)));
}

// spec/permissions.md §5.2 Addenda: addenda vouch for no snapshot: X's snapshot, cut, stays
// invalid whatever B's addendum lists.
#[test]
fn an_addendum_vouches_for_no_snapshot() {
    let w = [admins(&[KX, KB]), vec![commit(4, ms(2), KX, vec![snapshot(KT, "doc.0", &[])]), commit(7, ms(6), KH, vec![edge(KA, &[], KX, None, Some(&[]))]), commit(9, ms(7), KB, vec![addendum(KT, 7, &[4])])]].concat();
    assert_eq!(verdicts(&w).content(&WriteId(cid(4), 0)), Some(Content::Invalid));
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
            commit(10, ms(2), KX, vec![plain(KT)]),
            commit(11, ms(5), KH, vec![edge(KA, &[], KX, None, Some(&[]))]),
            commit(12, ms(6), KY, vec![addendum(KT, 11, &[10])]),
            commit(13, ms(7), KH, vec![edge(KA, &[], KY, None, Some(&[]))]),
            commit(14, ms(8), KZ, vec![addendum(KT, 13, &[12])]),
            commit(15, ms(9), KH, vec![edge(KA, &[], KZ, None, Some(&[]))]),
        ],
    ]
    .concat();
    let ids = [10, 12, 14].map(|i| WriteId(cid(i), 0));
    let p = verdicts(&base);
    assert!(ids.iter().all(|id| p.content(id) == Some(Content::Invalid)));
    let p = verdicts(&[base, vec![commit(16, ms(10), KB, vec![addendum(KT, 15, &[14])])]].concat());
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
            commit(12, ms(5), KY, vec![addendum(KT, 15, &[14])]),
            commit(14, ms(5), KZ, vec![addendum(KT, 13, &[12])]),
            commit(13, ms(6), KH, vec![edge(KA, &[], KY, None, Some(&[]))]),
            commit(15, ms(6), KH, vec![edge(KA, &[], KZ, None, Some(&[]))]),
        ],
    ]
    .concat();
    let p = verdicts(&w);
    assert_eq!((p.content(&WriteId(cid(12), 0)), p.content(&WriteId(cid(14), 0))), (Some(Content::Invalid), Some(Content::Invalid)));
}

// spec/permissions.md §5.2 Copies: no snapshot carries a role commit, so no list names one through
// a snapshot and no snapshot shows one as a copy: H's removal names B's `keys.0` snapshot claiming
// X's key rotation, which stays cut.
#[test]
fn no_snapshot_carries_a_role_commit() {
    let snap = doc(KT, &[KA], "keys.0", DeltaClass::Snapshot { carries: Frontier::new([cid(4)]), stated: BTreeMap::new(), own: false });
    let snap = Part { kind: PartKind::Delta(Delta { needs: R::Admin, ..match snap.kind { PartKind::Delta(d) => d, _ => unreachable!() } }), ..snap };
    let w = [admins(&[KX, KB]), vec![commit(4, ms(2), KX, vec![role_class(KT, &[KA])]), commit(5, ms(3), KB, vec![snap]), commit(7, ms(6), KH, vec![edge(KA, &[], KX, None, Some(&[5]))])]].concat();
    let p = verdicts(&w);
    assert_eq!(p.content(&WriteId(cid(5), 0)), Some(Content::Valid(By::Held)));
    assert_eq!(p.content(&WriteId(cid(4), 0)), Some(Content::Invalid));
    assert!(p.copies().is_empty());
}

// spec/permissions.md §5.2 Position: a commit with no edge-class part is ordered at the start of
// its `ts`, so X's key rotation stamped in the millisecond of H's removal is ordered before it and
// cut by it, whatever the signers' tids; listed, it stands.
#[test]
fn a_role_class_delta_in_its_removals_millisecond_is_ordered_before_it() {
    let w = [admins(&[KX, KB]), vec![commit(4, ms(6), KX, vec![role_class(KT, &[KA])]), commit(7, ms(6), KH, vec![edge(KA, &[], KX, None, Some(&[]))])]].concat();
    assert_eq!(verdicts(&w).content(&WriteId(cid(4), 0)), Some(Content::Invalid));
    let w = [admins(&[KX, KB]), vec![commit(4, ms(6), KX, vec![role_class(KT, &[KA])]), commit(7, ms(6), KH, vec![edge(KA, &[], KX, None, Some(&[4]))])]].concat();
    assert_eq!(verdicts(&w).content(&WriteId(cid(4), 0)), Some(Content::Valid(By::Listed)));
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

// spec/permissions.md §5.2 (content): M's cut of (A, CT) refuses Z's later write through [A];
// H's later removal of Z listing it answers H's cut alone. Mutation: one answered cut answering
// every cut fails it.
#[test]
fn a_cuts_list_keeps_a_write_from_that_cut_alone() {
    let mut w = cut_twice();
    w.edge(M, 4, &[], CT, A, Gone, &[]);
    let c = w.content(Z, 5, &[A], CT);
    let r = w.edge(H, 7, &[], A, Z, Gone, &[c]);
    agree_all(&w, &[]);
    agree_all(&w, &[r]);
    assert_eq!(verdict(&w, &all(&w, &[]), c), Some(Content::Invalid));
    w.edge(H, 1, &[], A, B, Write, &[]);
    w.addendum(B, 8, &[A], CT, r, &[c]);
    agree_all(&w, &[]);
    assert_eq!(verdict(&w, &all(&w, &[]), c), Some(Content::Invalid));
}

// spec/permissions.md §5.2 (content): Z's write, stamped after both removals and listed by both
// (backdated removals: an honest remover's clock passes what it received, spec/crdt.md HLC
// rules), stands where each cut lists it; where only M lists it H's cut, the edge's last
// write before it, refuses it.
#[test]
fn a_write_after_two_cuts_stands_where_each_lists_it() {
    for both in [true, false] {
        let mut w = cut_twice();
        let c = w.content(Z, 5, &[A], CT);
        w.edge(M, 4, &[], CT, A, Gone, &[c]);
        let list = if both { vec![c] } else { vec![] };
        w.edge(H, 4, &[], A, Z, Gone, &list);
        agree_all(&w, &[]);
        assert_eq!(verdict(&w, &all(&w, &[]), c), Some(if both { Content::Valid(By::Listed) } else { Content::Invalid }), "both {both}");
    }
}

// spec/permissions.md §5.2 (content): two cuts of one edge after the write, the first listing it
// or not: it stands only where each cut is answered, an addendum answering the cut it is against
// alone. Mutations: an addendum answering any cut, a list answering every cut, fail it.
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
        agree_all(&w, &[]);
        assert_eq!(verdict(&w, &all(&w, &[]), c), Some(Content::Invalid));
        let mut w1 = w.clone();
        w1.addendum(B, 7, &[], A, r1, &[c]);
        agree_all(&w1, &[]);
        assert_eq!(verdict(&w1, &all(&w1, &[]), c), Some(Content::Invalid), "listed {listed}");
        w.addendum(B, 7, &[], A, r2, &[c]);
        agree_all(&w, &[]);
        assert_eq!(verdict(&w, &all(&w, &[]), c), Some(if listed { Content::Valid(By::Vouched) } else { Content::Invalid }), "listed {listed}");
        w.addendum(B, 7, &[], A, r1, &[c]);
        agree_all(&w, &[]);
        assert_eq!(verdict(&w, &all(&w, &[]), c), Some(Content::Valid(By::Vouched)), "listed {listed}");
    }
}

// spec/permissions.md §5.2 (content): a write stamped before its path gave the role, listed by a
// later cut: the list answers the cut, not the missing grant.
#[test]
fn a_list_gives_no_role_the_path_never_gave() {
    let mut w = World::new(&[(H, A)]);
    let c = w.content(Z, 1, &[], A);
    w.edge(H, 2, &[], A, Z, Write, &[]);
    w.edge(H, 4, &[], A, Z, Gone, &[c]);
    agree_all(&w, &[]);
    assert_eq!(verdict(&w, &all(&w, &[]), c), Some(Content::Invalid));
}

// spec/permissions.md §5.2 (content): the edge before an answering cut is read at the write's
// `ts`: a grant ended by then gives nothing back. Mutation: read at the cut's `ts` fails it.
#[test]
fn an_answered_cut_gives_back_only_what_the_edge_gave_at_the_write() {
    for until in [true, false] {
        let mut w = World::new(&[(H, A)]);
        w.push(H, 1, &[], A, if until { Kind::set(Z, Write).until(3) } else { Kind::set(Z, Write) });
        let c = w.content(Z, 5, &[], A);
        w.edge(H, 2, &[], A, Z, Gone, &[c]);
        agree_all(&w, &[]);
        assert_eq!(verdict(&w, &all(&w, &[]), c), Some(if until { Content::Invalid } else { Content::Valid(By::Listed) }), "until {until}");
    }
}

// spec/permissions.md §5.2 (content): an edge cut, re-granted and cut again, the second cut listing
// both of Z's writes: the one after the re-grant stands by it, the one the first cut refused stays
// refused.
#[test]
fn a_second_cut_of_an_edge_answers_only_what_the_first_left_standing() {
    let mut w = World::new(&[(H, A)]);
    w.edge(H, 1, &[], A, Z, Write, &[]);
    let c0 = w.content(Z, 2, &[], A);
    w.edge(H, 3, &[], A, Z, Gone, &[]);
    w.edge(H, 4, &[], A, Z, Write, &[]);
    let c1 = w.content(Z, 5, &[], A);
    w.edge(H, 6, &[], A, Z, Gone, &[c0, c1]);
    agree_all(&w, &[]);
    assert_eq!(verdict(&w, &all(&w, &[]), c0), Some(Content::Invalid));
    assert_eq!(verdict(&w, &all(&w, &[]), c1), Some(Content::Valid(By::Listed)));
}

// spec/permissions.md §5.2 (addenda): B's addendum against H's removal of Z keeps Z's write while
// the addendum stands against H's later removal of B: where H's list names it.
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
        agree_all(&w, &[]);
        assert_eq!(verdict(&w, &all(&w, &[]), c), Some(if listed { Content::Valid(By::Vouched) } else { Content::Invalid }), "listed {listed}");
    }
}

// spec/permissions.md §5.2 (addenda): M cuts (A, CT) and H removes Z after Z's write through [A],
// neither listing it; W's addendum against H's removal answers H's cut alone: the write stands once
// W answers M's cut too. Mutation: an addendum answering every cut of the path fails it.
#[test]
fn an_addendum_answers_the_cut_it_is_against_alone() {
    let mut w = cut_twice();
    w.edge(M, 1, &[], CT, W, Write, &[]);
    let c = w.content(Z, 3, &[A], CT);
    let rm = w.edge(M, 4, &[], CT, A, Gone, &[]);
    let rh = w.edge(H, 5, &[], A, Z, Gone, &[]);
    w.addendum(W, 6, &[], CT, rh, &[c]);
    agree_all(&w, &[]);
    assert_eq!(verdict(&w, &all(&w, &[]), c), Some(Content::Invalid));
    w.addendum(W, 7, &[], CT, rm, &[c]);
    agree_all(&w, &[]);
    assert_eq!(verdict(&w, &all(&w, &[]), c), Some(Content::Valid(By::Vouched)));
}

// spec/permissions.md §5.2 (content): Z's one commit on CT through [A] and on A; M cuts (A, CT),
// then H removes Z listing the commit in both leaves: the part on A stands, the part on CT falls.
#[test]
fn a_commits_parts_answer_the_cuts_of_their_own_paths() {
    let mut w = cut_twice();
    let parts = w.split(Z, 3, Z, &[(&[A], CT), (&[], A)]);
    w.edge(M, 4, &[], CT, A, Gone, &[]);
    let honest = w.through((Z, A), |_| true);
    w.edge(H, 5, &[], A, Z, Gone, &honest);
    agree_all(&w, &[]);
    assert_eq!(verdict(&w, &all(&w, &[]), parts[0]), Some(Content::Invalid));
    assert_eq!(verdict(&w, &all(&w, &[]), parts[1]), Some(Content::Valid(By::Listed)));
}

// spec/permissions.md §5.1 (the list): an entry in thing t's leaf names its commit's part on t
// alone: Z's commit on T1 through [A] and on A, listed in T1's leaf only, keeps its part on T1 and
// loses its part on A; listed in both leaves (the honest remover), both stand. Mutation: an entry
// naming its commit's parts on every thing fails it.
#[test]
fn a_list_entry_names_its_part_on_its_leafs_thing_alone() {
    let (mut w, ..) = paired();
    w.edge(H, 1, &[], A, Z, Write, &[]);
    let parts = w.split(Z, 2, Z, &[(&[A], T1), (&[], A)]);
    let (on_t1, on_a) = (parts[0], parts[1]);
    let mut w2 = w.clone();
    w.edge(H, 4, &[], A, Z, Gone, &[on_t1]);
    agree_all(&w, &[]);
    assert_eq!(verdict(&w, &all(&w, &[]), on_t1), Some(Content::Valid(By::Listed)));
    assert_eq!(verdict(&w, &all(&w, &[]), on_a), Some(Content::Invalid));
    let honest = w2.through((Z, A), |_| true);
    w2.edge(H, 4, &[], A, Z, Gone, &honest);
    agree_all(&w2, &[]);
    assert_eq!(verdict(&w2, &all(&w2, &[]), on_a), Some(Content::Valid(By::Listed)));
}

// spec/permissions.md §5.1 (the list): the same for edge-class parts a lowering's audit drops: X's
// commit granting on T1 through [A] and on A, listed in T1's leaf alone, keeps the grant on T1 and
// drops the one on A. Mutation: `List::names` reading every leaf fails it.
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
        agree_all(&w, &[]);
    }
}
