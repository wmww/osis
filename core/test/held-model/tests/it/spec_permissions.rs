//! spec/permissions.md §5.1 (role timeline), §5.2 (content validity).
use crate::util::*;
use held_model::gen::{ADM, REG};
use held_model::*;

const OTHER: Aspect = Aspect::reg(5);

fn writer_history() -> Vec<Commit> {
    vec![edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None), reg(10, 1, 1, REG, Retention::PLAIN, 1), reg(11, 1, 2, OTHER, Retention::PLAIN, 2)]
}

// spec/permissions.md §5.2: a demotion's frontier keeps exactly the writes it lists
#[test]
fn demotion_frontier_keeps_listed_writes_spec_permissions_5_2() {
    let mut cs = writer_history();
    cs.push(edge(20, FIRST_ADMIN, 3, 1, None, Some(vec![10])));
    let o = evaluate(&held(4, cs));
    assert_eq!(o.valid[&(10, 0)], true);
    assert_eq!(o.valid[&(11, 0)], false);
}

// spec/permissions.md §5.2: re-grant revives the writes since the first point it held the role
#[test]
fn regrant_revives_writes_spec_permissions_5_2() {
    let mut cs = writer_history();
    cs.push(edge(20, FIRST_ADMIN, 3, 1, None, Some(vec![])));
    cs.push(edge(30, FIRST_ADMIN, 4, 1, Some(Role::Write), None));
    let o = evaluate(&held(5, cs));
    assert_eq!(o.valid[&(10, 0)], true);
    assert_eq!(o.valid[&(11, 0)], true);
}

// spec/permissions.md §5.1 (step 4): an edge admin's fall audits its edge writes the frontier leaves out
#[test]
fn demotion_audits_edge_admin_grants_spec_permissions_5_1() {
    let cs = |f: Vec<CommitId>| {
        vec![
            edge(5, FIRST_ADMIN, 0, 2, Some(Role::Admin), None),
            edge(6, 2, 1, 1, Some(Role::Write), None),
            reg(10, 1, 2, REG, Retention::PLAIN, 1),
            edge(20, FIRST_ADMIN, 3, 2, None, Some(f)),
        ]
    };
    let o = evaluate(&held(4, cs(vec![])));
    assert_eq!(o.valid[&(6, 0)], false);
    assert_eq!(o.valid[&(10, 0)], false);
    assert_eq!(read(&held(4, cs(vec![])), REG), Read::Absent);
    let o = evaluate(&held(4, cs(vec![6])));
    assert_eq!(o.valid[&(6, 0)], true);
    assert_eq!(o.valid[&(10, 0)], true);
}

// spec/permissions.md §5.2: an admin-only aspect needs admin
#[test]
fn admin_only_aspect_needs_admin_spec_permissions_5_2() {
    let w = vec![edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None), reg(10, 1, 1, ADM, Retention::PLAIN, 1)];
    assert_eq!(evaluate(&held(2, w)).valid[&(10, 0)], false);
    let a = vec![edge(5, FIRST_ADMIN, 0, 1, Some(Role::Admin), None), reg(10, 1, 1, ADM, Retention::PLAIN, 1)];
    assert_eq!(evaluate(&held(2, a)).valid[&(10, 0)], true);
}

// spec/permissions.md §6: a demotion not listing the request takes the purge right, however early
#[test]
fn demotion_takes_the_purge_right_spec_permissions_6() {
    let cs = |f: Vec<CommitId>| {
        vec![
            edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None),
            reg(10, 1, 1, REG, Retention::PLAIN, 7),
            purge(15, 1, 2, PurgeItem::Commit { commit: 10, thing: T, aspect: REG }),
            edge(20, FIRST_ADMIN, 3, 1, None, Some(f)),
        ]
    };
    assert_eq!(read(&held(4, cs(vec![10, 15])), REG), Read::Absent);
    // the purge falls; the write it named is not listed either, so nothing shows
    let o = evaluate(&held(4, cs(vec![10])));
    assert!(o.purged.is_empty());
    assert_eq!(read(&held(4, cs(vec![10])), REG), Read::Reg(7));
}

// spec/permissions.md §6: the right is judged at the request's time, not the delta's
#[test]
fn purge_right_judged_at_the_request_spec_permissions_6() {
    let cs = |grant_h: u64| {
        vec![
            reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 7),
            edge(5, FIRST_ADMIN, grant_h, 1, Some(Role::Admin), None),
            purge(20, 1, 3, PurgeItem::Commit { commit: 10, thing: T, aspect: REG }),
        ]
    };
    let o = evaluate(&held(5, cs(2)));
    assert_eq!(o.purged.get(&(10, 0)), Some(&20), "granted between the delta and the request");
    assert_eq!(read(&held(5, cs(2)), REG), Read::Absent);
    assert!(evaluate(&held(5, cs(4))).purged.is_empty(), "granted after the request");
}

// spec/permissions.md §5.2, spec/commits.md §5: a body dropped as covered reads through its cover;
// the cover turning invalid (a demotion of its author) leaves the body never received, to be
// fetched again, and until then the node reads less than one that kept it
#[test]
fn cover_turning_invalid_uncovers_the_dropped_body_spec_permissions_5_2() {
    let w = set(1, 10, 7);
    let mk = |demoted: bool| {
        let mut own = reg(10, FIRST_ADMIN, 1, REG, Retention::WRITER, 7);
        own.parts[0].body = Body::Dropped(20);
        let s = snap(20, 1, 2, REG, Retention::WRITER, vec![w.clone()]);
        let mut cs = vec![edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None), own, s];
        if demoted {
            cs.push(edge(30, FIRST_ADMIN, 3, 1, None, Some(vec![])));
        }
        held(5, cs)
    };
    let o = evaluate(&mk(false));
    assert!(o.uncovered.is_empty());
    assert_eq!(read(&mk(false), REG), Read::Reg(7), "dropped: read through the cover");
    let h = mk(true);
    let o = evaluate(&h);
    assert_eq!(o.valid[&(20, 0)], false);
    assert_eq!(o.uncovered, [(10, 0)].into_iter().collect());
    assert_eq!(read(&h, REG), Read::Absent, "the cover is un-merged, the body is gone: fetch it again");
    assert_eq!(act(&h, &o, None).commits[1].parts[0].body, Body::Missing);
}

// spec/permissions.md §5.2: an earlier removal's frontier keeps counting after a re-grant and
// a second removal that lists nothing
#[test]
fn earlier_removal_frontier_counts_after_re_removal_spec_permissions_5_2() {
    let mut cs = writer_history();
    cs.push(edge(20, FIRST_ADMIN, 3, 1, None, Some(vec![10])));
    cs.push(edge(30, FIRST_ADMIN, 4, 1, Some(Role::Write), None));
    cs.push(edge(40, FIRST_ADMIN, 5, 1, Some(Role::Read), Some(vec![])));
    let o = evaluate(&held(6, cs));
    assert_eq!(o.valid[&(10, 0)], true);
    assert_eq!(o.valid[&(11, 0)], false);
}

/// An addendum on T by `author` at hour `h` naming `removal` and listing `lists`.
fn addendum(id: CommitId, author: NodeId, h: u64, removal: CommitId, lists: Vec<CommitId>) -> Commit {
    let body = Body::Held(Delta::Addenda(vec![(removal, lists)]));
    content(id, author, h, vec![Part { thing: T, aspect: Aspect::ADDENDA, retention: Retention::ROLE, body, stripped: Default::default() }])
}

// spec/permissions.md §5.2 (Addenda): a writer's addendum after the removal vouches for the
// plain content it lists; a reader's, one before the removal, or one listing an admin-only
// delta does not
#[test]
fn addendum_vouches_for_listed_plain_content_spec_permissions_5_2() {
    let base = |witness: Role| {
        vec![
            edge(5, FIRST_ADMIN, 0, 1, Some(Role::Admin), None),
            edge(6, FIRST_ADMIN, 0, 2, Some(witness), None),
            reg(10, 1, 1, REG, Retention::PLAIN, 1),
            reg(11, 1, 2, ADM, Retention::PLAIN, 2),
            edge(20, FIRST_ADMIN, 3, 1, None, Some(vec![])),
        ]
    };
    let valid = |cs: Vec<Commit>| {
        let o = evaluate(&held(6, cs));
        (o.valid[&(10, 0)], o.valid[&(11, 0)])
    };
    assert_eq!(valid(base(Role::Write)), (false, false));
    let with = |witness: Role, h: u64| {
        let mut cs = base(witness);
        cs.push(addendum(30, 2, h, 20, vec![10, 11]));
        cs
    };
    assert_eq!(valid(with(Role::Write, 4)), (true, false));
    assert_eq!(valid(with(Role::Read, 4)), (false, false));
    // ordered before the removal
    assert_eq!(valid(with(Role::Write, 2)), (false, false));
}

// spec/permissions.md §5.2 (Addenda): an addendum valid only through another one counts (the
// least fixpoint); a stripped body lists nothing
#[test]
fn addendum_vouched_by_another_counts_spec_permissions_5_2() {
    let cs = |listed: bool| {
        let mut v = vec![
            edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None),
            edge(6, FIRST_ADMIN, 0, 2, Some(Role::Write), None),
            edge(7, FIRST_ADMIN, 0, 3, Some(Role::Write), None),
            reg(10, 1, 1, REG, Retention::PLAIN, 1),
            // 2 vouches for 1, then is removed; 3 vouches for 2's addendum
            edge(20, FIRST_ADMIN, 2, 1, None, Some(vec![])),
            addendum(30, 2, 3, 20, vec![10]),
            edge(40, FIRST_ADMIN, 4, 2, None, Some(vec![])),
            addendum(50, 3, 5, 40, vec![30]),
        ];
        if !listed {
            v[7].parts[0].body = Body::Held(Delta::Addenda(vec![]));
        }
        v
    };
    let o = evaluate(&held(6, cs(true)));
    assert_eq!((o.valid[&(30, 0)], o.valid[&(10, 0)]), (true, true));
    let o = evaluate(&held(6, cs(false)));
    assert_eq!((o.valid[&(30, 0)], o.valid[&(10, 0)]), (false, false));
}
