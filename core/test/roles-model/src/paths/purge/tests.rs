//! Hand worlds of the purge rules (notes/purge-model.md): the smallest world of each property,
//! each beside the rule set that fails it. Then the purge worlds at small size.

use super::*;
use Role::{Admin, None as Gone, Write};

/// A minted by H, T1 minted with A, A2 by K; H pairs X and B (admin on A) and grants W write on T1.
fn base() -> World {
    let mut w = World::new(&[(H, A), (K, A2), (A, T1)]);
    w.edge(H, 1, &[], A, X, Admin, &[]);
    w.edge(H, 1, &[], A, B, Admin, &[]);
    w.edge(H, 1, &[A], T1, W, Write, &[]);
    w
}

fn read(w: &World, rules: &Rules, trust: &[Id]) -> Reading {
    judge(w, rules, &View::all(w).trusting(trust))
}

fn content(w: &mut World, n: Thing, t: u32, path: &[Thing], ret: Retention) -> Id {
    let i = w.content(n, t, path, T1);
    w.retain(i, ret);
    i
}

/// Each named delta is judged alone by the members of its retention set the request holds
/// (draft §6): a writer's request by whole aspect takes the `writer` deltas and its own
/// `author_or_admin` one, never an `admin` delta or another author's; an admin's takes them all.
/// `fixed` reads requests by author alone.
#[test]
fn a_request_holds_each_class_of_its_named_deltas_alone() {
    let mut w = base();
    let adm = content(&mut w, B, 2, &[A], Retention::Admin);
    let other = content(&mut w, B, 2, &[A], Retention::AuthorOrAdmin);
    let own = content(&mut w, W, 2, &[], Retention::AuthorOrAdmin);
    let any = content(&mut w, B, 2, &[A], Retention::Writer);
    let by_w = w.request(W, 3, &[], T1, Names::Aspect);
    assert_eq!(read(&w, &Rules::purging(), &[]).purged, Set::from([own, any]));
    w.request(B, 4, &[A], T1, Names::Aspect);
    assert_eq!(read(&w, &Rules::purging(), &[]).purged, Set::from([adm, other, own, any]));
    assert!(read(&w, &Rules::fixed(), &[]).purged.is_empty(), "{by_w}");
}

/// A removed signer's backdated request by whole aspect, and its backdated destruction, take
/// nothing, trusted or not; listed by the removal they stand. Read at their key alone (`-purge-at-key`,
/// "gone means gone"), they erase what the removal holds out.
#[test]
fn a_removed_signers_backdated_request_or_destruction_takes_nothing() {
    for names in [Names::Aspect, Names::Destroy] {
        let mut w = base();
        let h = content(&mut w, H, 2, &[A], Retention::Admin);
        let q = w.request(X, 5, &[A], T1, names);
        let r = w.edge(H, 6, &[], A, X, Gone, &[]);
        for trust in [vec![], vec![r]] {
            assert!(read(&w, &Rules::purging(), &trust).purged.is_empty(), "{names:?} {trust:?}");
        }
        assert!(read(&w, &Rules { purge_at_key: true, ..Rules::purging() }, &[r]).purged.contains(&h), "{names:?}");
        w.edit(r, |k| k.listing(BTreeMap::from([(T1, Set::from([q]))])));
        assert!(read(&w, &Rules::purging(), &[r]).purged.contains(&h), "{names:?}");
    }
}

/// A destruction is judged without the cuts on edges into its own thing stamped after it (spec/
/// commits.md §5 Destruction): Z, admin of T1 by H's direct grant, destroys T1; H's later removal of
/// Z from T1, listing nothing, does not undo it. Z admin of A instead, the same removal on (Z, A) does.
#[test]
fn a_destruction_stands_against_a_later_cut_on_its_own_thing_alone() {
    for on_thing in [true, false] {
        let mut w = base();
        let h = content(&mut w, H, 2, &[A], Retention::Admin);
        let (path, edge): (&[Thing], Thing) = if on_thing { (&[], T1) } else { (&[A], A) };
        let at: &[Thing] = if on_thing { &[A] } else { &[] };
        w.edge(H, 1, at, edge, Z, Admin, &[]);
        w.request(Z, 4, path, T1, Names::Destroy);
        let r = w.edge(H, 6, at, edge, Z, Gone, &[]);
        assert_eq!(read(&w, &Rules::purging(), &[r]).purged.contains(&h), on_thing);
    }
}

/// Finding 41 (notes/path-model-findings.md): X purges by whole aspect at 4 as itself; B, an admin,
/// receives it; H, which did not, removes X at 6 listing nothing; B's addendum at 7 names the request.
/// spec/requirements.md Permissions keeps an edit a remaining writer vouches for having received by
/// then; the draft (no addendum vouches for a purge request) drops it, so H's message comes back.
#[test]
#[ignore = "notes/path-model-findings.md 41: a purge request only a witness received in time falls"]
fn repro_a_request_only_a_witness_received_stands() {
    let (w, h) = witnessed();
    assert!(read(&w, &Rules::purging(), &[]).purged.contains(&h));
}

fn witnessed() -> (World, Id) {
    let mut w = base();
    let h = content(&mut w, H, 2, &[A], Retention::Admin);
    let q = w.request(X, 4, &[A], T1, Names::Aspect);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.addendum(B, 7, &[A], T1, r, &[q]);
    (w, h)
}

/// The fix proposed for finding 41 (`Rules::purge_addenda`): an addendum by a holder of the role the
/// class needs vouches for the request: B's (admin) keeps the admin right; W's (write) only the
/// write right, so H's admin delta stays.
#[test]
fn an_addendum_by_a_holder_of_the_class_keeps_a_request() {
    let rules = Rules { purge_addenda: true, ..Rules::purging() };
    let (w, h) = witnessed();
    for trust in [vec![], vec![w.commits.len() - 2]] {
        assert!(read(&w, &rules, &trust).purged.contains(&h), "{trust:?}");
    }
    let mut w = base();
    let h = content(&mut w, H, 2, &[A], Retention::Admin);
    let any = content(&mut w, H, 2, &[A], Retention::Writer);
    let q = w.request(X, 4, &[A], T1, Names::Aspect);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    w.addendum(W, 7, &[], T1, r, &[q]);
    assert_eq!(read(&w, &rules, &[r]).purged, Set::from([any]));
    assert!(!read(&w, &rules, &[r]).purged.contains(&h));
}

/// A request reaches a write a node holds only as a valid cover's copy (spec/commits.md §5 Purge,
/// Without the header): K compacts T1 carrying B's write; LJ holds the cover and B's later request,
/// not the write. Under `purging` it reads the copy purged, as a node holding the write does;
/// `fixed` (held deltas alone) leaves the copy showing at LJ.
#[test]
fn a_request_reaches_the_copy_of_a_write_the_node_does_not_hold() {
    let mut w = base();
    w.edge(B, 1, &[A], T1, A2, Write, &[]);
    let d = w.content(B, 2, &[A], T1);
    w.push(K, 3, &[A2], T1, Kind::Cover { carries: Set::from([d]) });
    w.purge(B, 4, &[A], T1, B);
    let late = View::all(&w).without(&[d]);
    for (rules, copy) in [(Rules::purging(), true), (Rules::fixed(), false)] {
        assert!(read(&w, &rules, &[]).purged.contains(&d));
        let rd = judge(&w, &rules, &late);
        assert!(rd.copied.contains(&d));
        assert_eq!(rd.purged.contains(&d), copy);
    }
}

/// An own cover stands while the removal naming it applies (draft §5.2 Own cover): H forgot X's
/// write under its own cover S and its removal of X names S; B later removes H listing the removal
/// but not S (it had not received it). Under `purging` X's write shows at H by S's copy; judged as
/// any cover, S falls with B's cut and the write H's removal kept is gone at H. B listing nothing,
/// H's removal falls and S with it under both.
#[test]
fn an_own_cover_stands_while_its_removal_applies() {
    for listed in [true, false] {
        let mut w = base();
        let x = w.content(X, 2, &[A], T1);
        let s = w.push(H, 5, &[A], T1, Kind::Cover { carries: Set::from([x]) });
        w.own_cover(s);
        let r = w.edge(H, 6, &[], A, X, Gone, &[s]);
        // B lists what it received through (H, A): H's grants, and H's removal or not; never S
        let got: Vec<Id> = w.through((H, A), |i| i != s && (listed || i != r));
        let rh = w.edge(B, 9, &[], A, H, Gone, &got);
        let at_h = View::all(&w).without(&[x]).trusting(&[r, rh]);
        let shows = |rules: &Rules| judge(&w, rules, &at_h).shows(x);
        assert_eq!(shows(&Rules::purging()), listed);
        assert!(!shows(&Rules { own_cover: false, ..Rules::purging() }));
    }
}

/// An own cover stands while its removal applies, whatever that removal takes from its edge at
/// the node reading it (draft §5.2 Own cover: "an explicit lowering R the timeline applies"): a
/// node holding H's removal of X but not H's grant of X (nothing to take there) reads H's own cover
/// as H does. Read only where the removal falls, the cover would stand at H and fall at that node
/// for want of an unrelated grant.
#[test]
fn an_own_cover_stands_while_its_removal_applies_whatever_it_takes_here() {
    let mut w = base();
    let x = w.content(X, 2, &[A], T1);
    let s = w.push(H, 5, &[A], T1, Kind::Cover { carries: Set::from([x]) });
    w.own_cover(s);
    let r = w.edge(H, 6, &[], A, X, Gone, &[s]);
    let got: Vec<Id> = w.through((H, A), |i| i != s);
    let rh = w.edge(B, 9, &[], A, H, Gone, &got);
    // the grant of X (commit 0) not held: the removal applies and takes nothing
    let v = View::all(&w).without(&[0, x]).trusting(&[r, rh]);
    let rd = judge(&w, &Rules::purging(), &v);
    assert!(rd.applied.contains(&r) && rd.valid.contains(&s) && rd.shows(x));
}

/// An own cover whose path gave its writer no role just before it stands by nothing (draft §5.2
/// Own cover: "valid when its path gave the role S needs on the thing just before S's key"): Z,
/// granted admin on A only after writing it, lists it in its removal of B.
#[test]
fn an_own_cover_whose_path_gave_no_role_stands_by_nothing() {
    let mut w = base();
    let d = w.content(B, 2, &[A], T1);
    let s = w.push(Z, 5, &[A], T1, Kind::Cover { carries: Set::from([d]) });
    w.own_cover(s);
    w.edge(H, 6, &[], A, Z, Admin, &[]);
    let r = w.edge(Z, 7, &[], A, B, Gone, &[s, d]);
    let rd = read(&w, &Rules::purging(), &[r]);
    assert!(rd.applied.contains(&r) && !rd.valid.contains(&s));
}

/// The pair (notes/purge-model.md, Indistinguishable pairs): an honest X purging at 4, witnessed by
/// B, before H removes it, and a thief with X's key making the same request in the window before the
/// removal, witnessed by B. The held sets are one, so every rule reads them alike: keeping a witnessed
/// request keeps the thief's window request too, as with content (accepted: the window), and a thief
/// request made after the removal is witnessed by no one.
#[test]
fn a_request_made_after_the_removal_is_kept_by_no_witness() {
    let rules = Rules { purge_addenda: true, ..Rules::purging() };
    let mut w = base();
    let h = content(&mut w, H, 2, &[A], Retention::Admin);
    let q = w.request(X, 4, &[A], T1, Names::Aspect);
    let r = w.edge(H, 6, &[], A, X, Gone, &[]);
    // an honest addendum lists what its writer received by the removal's `ts`: the thief's request
    // made after it is in no honest addendum; a colluding writer's is a writer's word (as content)
    w.addendum(B, 7, &[A], T1, r, &[]);
    assert!(!read(&w, &rules, &[r]).purged.contains(&h), "{q}");
}

/// Purge worlds at small size: the draft's purge rules hold every
/// required gate but `purge witnessed` (finding 41), which its fix closes; `fixed` (the `author`
/// class alone) fails `purge kept` (classes, selectors, copies owed); `-purge-at-key` and
/// `-list-any-cut` fail safety.
#[test]
#[ignore = "property"]
fn purge_worlds_hold_plain() {
    let n = 400;
    let st = purge_run_from(0, n, &Rules::purging());
    st.print("paths-purge");
    let others: u64 = st.fails.iter().filter(|(k, _)| **k != "purge witnessed").map(|(_, n)| n).sum();
    assert!(others == 0 && st.fails.contains_key("purge witnessed"), "{:?} {:?}", st.fails, st.first);
    for k in ["purge kept", "purge safety", "alike", "could hold", "own cover", "bodies"] {
        assert!(st.checked.get(k).is_some_and(|n| *n > 0), "no {k} check ran");
    }
    let st = purge_run_from(0, n, &Rules { purge_addenda: true, ..Rules::purging() });
    assert!(st.failures() == 0, "{:?} {:?}", st.fails, st.first);
    assert!(purge_run_from(0, n, &Rules::fixed()).fails.contains_key("purge kept"));
    assert!(purge_run_from(0, n, &Rules { purge_at_key: true, ..Rules::purging() }).fails.contains_key("purge safety"));
    assert!(purge_run_from(0, n, &Rules { own_cover: false, ..Rules::purging() }).fails.contains_key("own cover"));
    // a cut's list answering every cut of the path: the thief's requests along [ORG] past B's cut
    assert!(purge_run_from(0, n, &Rules { answers: Answers::AnyCut, ..Rules::purging() }).fails.contains_key("purge safety"));
}

/// As `purge_worlds_hold_plain` at the gate's size (4,000 worlds a rule set, about 16 CPU-s each):
/// the draft's purge rules hold every required gate but `purge witnessed` (finding 41), which its
/// fix (`purge_addenda`) closes.
#[test]
#[ignore = "property"]
fn purge_worlds_hold_large() {
    let st = purge_run_from(0, 4000, &Rules::purging());
    // the noted counts (an excused destruction among them) are the run's to read
    st.print("paths-purge");
    let others: u64 = st.fails.iter().filter(|(k, _)| **k != "purge witnessed").map(|(_, n)| n).sum();
    assert!(others == 0 && st.fails.contains_key("purge witnessed"), "{:?} {:?}", st.fails, st.first);
    let st = purge_run_from(0, 4000, &Rules { purge_addenda: true, ..Rules::purging() });
    assert!(st.failures() == 0, "{:?} {:?}", st.fails, st.first);
}
