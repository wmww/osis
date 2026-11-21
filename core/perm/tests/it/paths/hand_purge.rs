//! Hand worlds of step 4 (purges): one counterpart per rule-naming hand test of roles-model
//! `paths::purge` (src/paths/purge/tests.rs, same names; not the two of Open 20's `purge_addenda`,
//! brief 4d), read by the walk and the model at the model test's views (`agree`, under
//! `Rules::purging`), with the walk's reading asserted as the model test asserts it; then the
//! walk's own worlds for draft sentences no model world reaches (selectors and stamps, a
//! destruction by a writer and of every aspect, the author class through a listed thing, a copy
//! judged by every snapshot's statement, an own cover by another signer's lowering, could hold).
//! spec/permissions.md §6, §5.2 (draft: notes/a1-spec/permissions.md §6, §5.2 Own cover);
//! spec/commits.md §4, §5 (draft: notes/a1-spec/commits.md §4 Could hold the right, §5 Purge).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::{agree, as_known, cid, tid, walk};
use osis_base::{Ak, Role as R};
use osis_perm::paths::{Content, DeltaClass, PartKind, Paths, Stated};
use osis_perm::WriteId;
use roles_model::paths::*;
use roles_model::Role::{Admin, None as Gone, Write};
use std::collections::{BTreeMap, BTreeSet};

/// A minted by H, T1 minted with A, A2 by K; H pairs X and B (admin on A) and grants W write on T1.
fn base() -> World {
    let mut w = World::new(&[(H, A), (K, A2), (A, T1)]);
    w.edge(H, 1, &[], A, X, Admin, &[]);
    w.edge(H, 1, &[], A, B, Admin, &[]);
    w.edge(H, 1, &[A], T1, W, Write, &[]);
    w
}

fn content(w: &mut World, n: Thing, t: u32, path: &[Thing], by: PurgeBy) -> Id {
    let i = w.content(n, t, path, T1);
    w.set_purge_by(i, by);
    i
}

fn all(w: &World, trust: &[Id]) -> View {
    View::all(w).trusting(trust)
}

/// The walk's purged deltas and purged copies at view `v` (model ids), once it agrees with the
/// model there.
#[track_caller]
fn purged(w: &World, v: &View) -> Set {
    agree(w, v);
    let w = as_known(w, v);
    let (inp, p) = walk(&w, v);
    let back: BTreeMap<WriteId, Id> = inp.ids.iter().map(|(&i, &id)| (id, i)).collect();
    let mut out: Set = p.purged().iter().map(|id| back[id]).collect();
    let copies = p.purged_copies();
    out.extend((0..w.commits.len()).filter(|&j| matches!(w.commits[j].kind, Kind::Content) && copies.contains(&cid(w.cid(j)))));
    out
}

/// Whether model content `i` shows in the walk at view `v` (valid, or a copy), once it agrees.
#[track_caller]
fn shows(w: &World, v: &View, i: Id) -> bool {
    agree(w, v);
    let w = as_known(w, v);
    let (inp, p) = walk(&w, v);
    inp.ids.get(&i).is_some_and(|id| matches!(p.content(id), Some(Content::Valid(_)))) || p.copies().contains(&cid(w.cid(i)))
}

// ---- the model's hand worlds ----

// spec/permissions.md §6: draft The right: each named delta is judged alone by the members of its
// purge-by set the request holds: a writer's request by whole aspect takes the `writer` deltas and
// its own `author_or_admin` one, never an `admin` delta or another author's; an admin's takes them
// all.
#[test]
fn a_request_holds_each_class_of_its_named_deltas_alone() {
    let mut w = base();
    let adm = content(&mut w, B, 2, &[A], PurgeBy::Admin);
    let other = content(&mut w, B, 2, &[A], PurgeBy::AuthorOrAdmin);
    let own = content(&mut w, W, 2, &[], PurgeBy::AuthorOrAdmin);
    let any = content(&mut w, B, 2, &[A], PurgeBy::Writer);
    w.request(W, 3, &[], T1, Names::Aspect);
    assert_eq!(purged(&w, &all(&w, &[])), Set::from([own, any]));
    w.request(B, 4, &[A], T1, Names::Aspect);
    assert_eq!(purged(&w, &all(&w, &[])), Set::from([adm, other, own, any]));
}

// spec/permissions.md §6: draft Holding a role: a removed signer's backdated request by whole
// aspect, and its backdated destruction, take nothing, trusted or not; listed by the removal they
// stand.
#[test]
fn a_removed_signers_backdated_request_or_destruction_takes_nothing() {
    for names in [Names::Aspect, Names::Destroy] {
        let mut w = base();
        let h = content(&mut w, H, 2, &[A], PurgeBy::Admin);
        let q = w.request(X, 5, &[A], T1, names);
        let r = w.edge(H, 6, &[], A, X, Gone, &[]);
        for trust in [vec![], vec![r]] {
            assert!(purged(&w, &all(&w, &trust)).is_empty(), "{names:?} {trust:?}");
        }
        w.edit(r, |k| k.listing(BTreeMap::from([(T1, Set::from([q]))])));
        assert!(purged(&w, &all(&w, &[r])).contains(&h), "{names:?}");
    }
}

// spec/commits.md §5 Destruction (draft permissions.md §6 Destruction): a destruction is judged
// without the cuts on edges into its own thing stamped after it: Z, admin of T1 by H's direct
// grant, destroys T1; H's later removal of Z from T1, listing nothing, does not undo it. Z admin
// of A instead, the same removal on (Z, A) does.
#[test]
fn a_destruction_stands_against_a_later_cut_on_its_own_thing_alone() {
    for on_thing in [true, false] {
        let mut w = base();
        let h = content(&mut w, H, 2, &[A], PurgeBy::Admin);
        let (path, edge): (&[Thing], Thing) = if on_thing { (&[], T1) } else { (&[A], A) };
        let at: &[Thing] = if on_thing { &[A] } else { &[] };
        w.edge(H, 1, at, edge, Z, Admin, &[]);
        w.request(Z, 4, path, T1, Names::Destroy);
        let r = w.edge(H, 6, at, edge, Z, Gone, &[]);
        assert_eq!(purged(&w, &all(&w, &[r])).contains(&h), on_thing);
    }
}

// spec/commits.md §5 Purge, Without the header (draft permissions.md §6 Copies): a request reaches
// a write a node holds only as a valid cover's copy: K compacts T1 carrying B's write; a node
// holding the cover and B's later request, not the write, reads the copy purged.
#[test]
fn a_request_reaches_the_copy_of_a_write_the_node_does_not_hold() {
    let mut w = base();
    w.edge(B, 1, &[A], T1, A2, Write, &[]);
    let d = w.content(B, 2, &[A], T1);
    w.push(K, 3, &[A2], T1, Kind::Cover { carries: Set::from([d]) });
    w.purge(B, 4, &[A], T1, B);
    assert!(purged(&w, &all(&w, &[])).contains(&d));
    let late = View::all(&w).without(&[d]);
    assert!(shows(&w, &late, d) && purged(&w, &late).contains(&d));
}

// spec/permissions.md §5.2: draft Own cover: an own cover stands while the removal naming it
// applies: H forgot X's write under its own cover S and its removal of X names S; B later removes
// H listing the removal but not S. X's write shows at H by S's copy; B listing nothing, H's removal
// falls and S with it.
#[test]
fn an_own_cover_stands_while_its_removal_applies() {
    for listed in [true, false] {
        let mut w = base();
        let x = w.content(X, 2, &[A], T1);
        let s = w.push(H, 5, &[A], T1, Kind::Cover { carries: Set::from([x]) });
        w.own_cover(s);
        let r = w.edge(H, 6, &[], A, X, Gone, &[s]);
        let got: Vec<Id> = w.through((H, A), |i| i != s && (listed || i != r));
        let rh = w.edge(B, 9, &[], A, H, Gone, &got);
        let at_h = View::all(&w).without(&[x]).trusting(&[r, rh]);
        assert_eq!(shows(&w, &at_h, x), listed);
    }
}

// spec/permissions.md §5.2: draft Own cover, "an explicit lowering R the timeline applies": an
// own cover stands while its removal applies, whatever that removal takes from its edge here: a
// node holding H's removal of X but not H's grant of X reads H's own cover as H does.
#[test]
fn an_own_cover_stands_while_its_removal_applies_whatever_it_takes_here() {
    let mut w = base();
    let x = w.content(X, 2, &[A], T1);
    let s = w.push(H, 5, &[A], T1, Kind::Cover { carries: Set::from([x]) });
    w.own_cover(s);
    let r = w.edge(H, 6, &[], A, X, Gone, &[s]);
    let got: Vec<Id> = w.through((H, A), |i| i != s);
    let rh = w.edge(B, 9, &[], A, H, Gone, &got);
    let v = View::all(&w).without(&[0, x]).trusting(&[r, rh]);
    assert!(shows(&w, &v, s) && shows(&w, &v, x));
    let (inp, p) = walk(&w, &v);
    assert_eq!(p.content(&inp.ids[&s]), Some(Content::Valid(osis_perm::paths::By::OwnCover)));
}

// spec/permissions.md §5.2: draft Own cover, "its path gave the role S needs on the thing just
// before S's key": an own cover whose path gave its writer no role just before it stands by
// nothing: Z, granted admin on A only after writing it, lists it in its removal of B.
#[test]
fn an_own_cover_whose_path_gave_no_role_stands_by_nothing() {
    let mut w = base();
    let d = w.content(B, 2, &[A], T1);
    let s = w.push(Z, 5, &[A], T1, Kind::Cover { carries: Set::from([d]) });
    w.own_cover(s);
    w.edge(H, 6, &[], A, Z, Admin, &[]);
    let r = w.edge(Z, 7, &[], A, B, Gone, &[s, d]);
    assert!(!shows(&w, &all(&w, &[r]), s));
}

// spec/permissions.md §6: a request X makes after its removal is kept by nothing; one made before,
// not listed, falls (no addendum vouches for a request: Open 20).
#[test]
fn a_request_made_after_the_removal_is_kept_by_no_witness() {
    let mut w = base();
    let h = content(&mut w, H, 2, &[A], PurgeBy::Admin);
    w.request(X, 4, &[A], T1, Names::Aspect);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.addendum(B, 7, &[A], T1, r, &[]);
    assert!(!purged(&w, &all(&w, &[r])).contains(&h));
}

// ---- the walk's own ----

// spec/permissions.md §6: draft What it names: a request names only deltas stamped before it:
// by aspect and by author every earlier one of its selector, by commit that one alone.
#[test]
fn a_request_names_only_deltas_stamped_before_it() {
    let mut w = base();
    let early = content(&mut w, B, 2, &[A], PurgeBy::AuthorOrAdmin);
    let by_h = content(&mut w, H, 2, &[A], PurgeBy::AuthorOrAdmin);
    let late = content(&mut w, B, 5, &[A], PurgeBy::AuthorOrAdmin);
    for (names, want) in [(Names::Aspect, vec![early, by_h]), (Names::Author(B), vec![early]), (Names::Commit(early), vec![early]), (Names::Commit(late), vec![])] {
        let mut v = w.clone();
        v.request(B, 3, &[A], T1, names);
        assert_eq!(purged(&v, &all(&v, &[])), want.into_iter().collect(), "{names:?}");
    }
}

// spec/commits.md §5 Destruction (draft permissions.md §6): a destruction holds the `admin` right
// alone: a writer's takes nothing, even a `writer` delta; an admin's takes every delta of the
// thing, one stamped after it included.
#[test]
fn a_destruction_by_a_writer_takes_nothing() {
    let mut w = base();
    let any = content(&mut w, W, 2, &[], PurgeBy::Writer);
    let later = content(&mut w, B, 5, &[A], PurgeBy::Admin);
    let mut by_w = w.clone();
    by_w.request(W, 3, &[], T1, Names::Destroy);
    assert!(purged(&by_w, &all(&by_w, &[])).is_empty());
    w.request(B, 3, &[A], T1, Names::Destroy);
    assert_eq!(purged(&w, &all(&w, &[])), Set::from([any, later]));
}

// spec/permissions.md §6: draft The right, `author`: a writer's request holds the author right
// over a delta whose purge author its path lists: K, writer of T1 through A2 (B's share), takes
// what A2 authored there, not what H authored.
#[test]
fn a_writers_request_takes_the_author_deltas_its_path_holds() {
    let mut w = base();
    w.edge(B, 1, &[A], T1, A2, Write, &[]);
    let as_a2 = w.content_as(K, 2, &[A2], T1, 1);
    w.set_purge_by(as_a2, PurgeBy::AuthorOrAdmin);
    content(&mut w, H, 2, &[A], PurgeBy::AuthorOrAdmin);
    w.request(K, 3, &[A2], T1, Names::Aspect);
    assert_eq!(purged(&w, &all(&w, &[])), Set::from([as_a2]));
}

// spec/commits.md §5 Purge, Without the header: a copy is purged only where the request holds the
// right by what every valid held snapshot carrying it states: W's request (write) takes B's
// `writer` copy that two covers state alike; where one of them states `admin`, it does not.
#[test]
fn a_copy_is_purged_only_by_what_every_snapshot_states() {
    let mut w = base();
    w.edge(B, 1, &[A], T1, A2, Write, &[]);
    let d = content(&mut w, B, 2, &[A], PurgeBy::Writer);
    let c1 = w.push(K, 3, &[A2], T1, Kind::Cover { carries: Set::from([d]) });
    w.push(K, 4, &[A2], T1, Kind::Cover { carries: Set::from([d]) });
    w.request(W, 5, &[], T1, Names::Aspect);
    let late = View::all(&w).without(&[d]);
    assert!(purged(&w, &late).contains(&d));
    let mut inp = super::input(&w, &late);
    let c = cid(w.cid(c1));
    let snap = inp.commits.iter_mut().find(|x| x.id == c).unwrap();
    let PartKind::Delta(delta) = &mut snap.parts[0].kind else { panic!() };
    let DeltaClass::Snapshot { stated, .. } = &mut delta.class else { panic!() };
    stated.insert(cid(w.cid(d)), Stated { ts: osis_base::Ts::make(osis_base::WallMs(2), 0).unwrap(), purge_author: tid(B), purge_by: osis_base::PurgeBy::Admin });
    let p = Paths::evaluate(&inp.records, BTreeSet::new(), &inp.commits);
    assert!(p.copies().contains(&cid(w.cid(d))) && p.purged_copies().is_empty());
}

// spec/commits.md §5 Destruction: a destruction names every delta of its thing, of every aspect;
// a request by aspect names its own aspect alone.
#[test]
fn a_destruction_names_every_aspect() {
    let mut w = base();
    let doc = content(&mut w, H, 2, &[A], PurgeBy::Admin);
    let note = content(&mut w, H, 2, &[A], PurgeBy::Admin);
    let by_aspect = w.request(B, 3, &[A], T1, Names::Aspect);
    let mut inp = super::input(&w, &all(&w, &[]));
    let note_id = inp.ids[&note];
    for c in inp.commits.iter_mut().filter(|c| c.id == note_id.0) {
        let PartKind::Delta(d) = &mut c.parts[0].kind else { panic!() };
        d.aspect = Ak::new("note.0").unwrap();
    }
    let p = Paths::evaluate(&inp.records, BTreeSet::new(), &inp.commits);
    assert_eq!(p.purged(), BTreeSet::from([inp.ids[&doc]]));
    let q = inp.ids[&by_aspect];
    for c in inp.commits.iter_mut().filter(|c| c.id == q.0) {
        let PartKind::Delta(d) = &mut c.parts[0].kind else { panic!() };
        d.aspect = Ak::new("created.0").unwrap();
        d.class = DeltaClass::Purge { names: osis_perm::paths::Names::Destroy };
    }
    let p = Paths::evaluate(&inp.records, BTreeSet::new(), &inp.commits);
    assert_eq!(p.purged(), BTreeSet::from([inp.ids[&doc], note_id]));
}

// spec/permissions.md §5.2: draft Own cover, "signed by S's signer": an own cover stands only by
// its own writer's lowering: B's removal of X lists H's own cover, H lists nothing of it, and B's
// later removal of H (listing H's grants, not the cover) cuts it: it falls, and X's write it
// carried with it.
#[test]
fn an_own_cover_stands_only_by_its_writers_lowering() {
    let mut w = base();
    let x = w.content(X, 2, &[A], T1);
    let s = w.push(H, 5, &[A], T1, Kind::Cover { carries: Set::from([x]) });
    w.own_cover(s);
    let r = w.edge(B, 6, &[], A, X, Gone, &[s]);
    let got: Vec<Id> = w.through((H, A), |i| i != s);
    let rh = w.edge(B, 9, &[], A, H, Gone, &got);
    let v = View::all(&w).without(&[x]).trusting(&[r, rh]);
    assert!(!shows(&w, &v, s) && !shows(&w, &v, x));
}

// spec/commits.md §4: draft Could hold the right: a node that cannot judge acts on a request
// whose path could give the right by any held edge write, whatever its validity: X's request made
// after its removal holds no right but could hold admin; a stranger's could hold nothing; W's
// (write) could hold the `writer` right and its own `author_or_admin` one, never `admin`.
#[test]
fn a_removed_partys_request_could_still_hold_a_strangers_could_not() {
    let mut w = base();
    w.edge(H, 6, &[], A, X, Gone, &[]);
    let qx = w.request(X, 7, &[A], T1, Names::Aspect);
    let qz = w.request(Z, 7, &[A], T1, Names::Aspect);
    let qw = w.request(W, 7, &[], T1, Names::Aspect);
    let v = all(&w, &[]);
    agree(&w, &v);
    let (inp, p) = walk(&w, &v);
    let (qx, qz, qw) = (inp.ids[&qx], inp.ids[&qz], inp.ids[&qw]);
    assert_eq!(p.right(&qx), Some(Default::default()));
    assert_eq!((p.could_give(&qx, R::Admin), p.could_give(&qz, R::Write), p.could_give(&qw, R::Admin), p.could_give(&qw, R::Write)), (Some(true), Some(false), Some(false), Some(true)));
    let (wt, ht) = (tid(W), tid(H));
    assert_eq!(
        [p.could_hold(&qw, osis_base::PurgeBy::Admin, Some(&wt)), p.could_hold(&qw, osis_base::PurgeBy::Writer, Some(&ht)), p.could_hold(&qw, osis_base::PurgeBy::AuthorOrAdmin, Some(&wt)), p.could_hold(&qw, osis_base::PurgeBy::AuthorOrAdmin, Some(&ht))],
        [Some(false), Some(true), Some(true), Some(false)]
    );
}

// spec/permissions.md §6: draft Holding a role, "a cut's list names it, whatever their order":
// X's request by aspect, cut by H's removal of X at 9 listing nothing, holds no right; H's
// backdated removal at 5 listing it gives the right back (the removal at 9 then takes nothing:
// no cut). In every arrival order, `Changed` reports the request's scope where its right moves
// (here only a cut changes: no final role nor first chained point moves).
#[test]
fn a_backdated_cut_listing_a_request_gives_its_right_back() {
    let mut w = World::new(&[(H, A), (A, T1)]);
    w.edge(H, 1, &[], A, X, Admin, &[]);
    let h = content(&mut w, H, 2, &[A], PurgeBy::Admin);
    let q = w.request(X, 3, &[A], T1, Names::Aspect);
    w.edge(H, 9, &[], A, X, Gone, &[]);
    assert!(purged(&w, &all(&w, &[])).is_empty());
    w.edge(H, 5, &[], A, X, Gone, &[q]);
    assert_eq!(purged(&w, &all(&w, &[])), Set::from([h]));
    super::incremental::every_order(&w);
}

// spec/commits.md §5 Purge, Without the header: a snapshot's stated facts are its signer's word
// (issues/forged-copy-undetected.md): W's cover of T1 states itself purge author and `writer` of
// H's `admin` write, and W purges by author itself. A node holding the cover and the request but
// not the write reads the copy purged (the hole, by construction); holding the write too, its own
// facts decide and nothing is purged, as the engine reads the header (`retention::tests_carried`).
#[test]
fn a_misstated_fact_steers_a_purge_only_where_the_original_is_not_held() {
    let mut w = base();
    let h = content(&mut w, H, 2, &[A], PurgeBy::Admin);
    let s = w.push(W, 3, &[], T1, Kind::Cover { carries: Set::from([h]) });
    w.purge(W, 4, &[], T1, W);
    let forge = |v: &View| {
        let mut inp = super::input(&w, v);
        let c = cid(w.cid(s));
        let snap = inp.commits.iter_mut().find(|x| x.id == c).unwrap();
        let PartKind::Delta(delta) = &mut snap.parts[0].kind else { panic!() };
        let DeltaClass::Snapshot { stated, .. } = &mut delta.class else { panic!() };
        stated.insert(cid(w.cid(h)), Stated { ts: osis_base::Ts::make(osis_base::WallMs(2), 0).unwrap(), purge_author: tid(W), purge_by: osis_base::PurgeBy::Writer });
        let p = Paths::evaluate(&inp.records, BTreeSet::new(), &inp.commits);
        (inp, p)
    };
    // honest statements: nothing purged, held or not
    assert!(purged(&w, &all(&w, &[])).is_empty() && purged(&w, &View::all(&w).without(&[h])).is_empty());
    let (_, p) = forge(&View::all(&w).without(&[h]));
    assert!(p.copies().contains(&cid(w.cid(h))) && p.purged_copies() == BTreeSet::from([cid(w.cid(h))]));
    let (inp, p) = forge(&all(&w, &[]));
    assert!(p.purged().is_empty() && p.purged_copies().is_empty() && matches!(p.content(&inp.ids[&h]), Some(Content::Valid(_))));
}
