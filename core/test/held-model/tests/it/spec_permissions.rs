//! spec/permissions.md §5.1 (role timeline), §5.2 (content validity).
use crate::util::*;
use held_model::gen::{ADM, REG};
use held_model::*;

const OTHER: Aspect = Aspect::reg(5);

fn writer_history() -> Vec<Commit> {
    vec![edge(5, OWNER, 0, 1, Some(Role::Write), None), reg(10, 1, 1, REG, Retention::PLAIN, 1), reg(11, 1, 2, OTHER, Retention::PLAIN, 2)]
}

// spec/permissions.md §5.2: a demotion's frontier keeps exactly the writes it lists
#[test]
fn demotion_frontier_keeps_listed_writes_spec_permissions_5_2() {
    let mut cs = writer_history();
    cs.push(edge(20, OWNER, 3, 1, None, Some(vec![10])));
    let o = evaluate(&held(4, cs));
    assert_eq!(o.valid[&(10, 0)], true);
    assert_eq!(o.valid[&(11, 0)], false);
}

// spec/permissions.md §5.2: re-grant revives the writes since the first point it held the role
#[test]
fn regrant_revives_writes_spec_permissions_5_2() {
    let mut cs = writer_history();
    cs.push(edge(20, OWNER, 3, 1, None, Some(vec![])));
    cs.push(edge(30, OWNER, 4, 1, Some(Role::Write), None));
    let o = evaluate(&held(5, cs));
    assert_eq!(o.valid[&(10, 0)], true);
    assert_eq!(o.valid[&(11, 0)], true);
}

// spec/permissions.md §5.1 (step 4): an edge admin's fall audits its edge writes the frontier leaves out
#[test]
fn demotion_audits_edge_admin_grants_spec_permissions_5_1() {
    let cs = |f: Vec<CommitId>| {
        vec![
            edge(5, OWNER, 0, 2, Some(Role::Admin), None),
            edge(6, 2, 1, 1, Some(Role::Write), None),
            reg(10, 1, 2, REG, Retention::PLAIN, 1),
            edge(20, OWNER, 3, 2, None, Some(f)),
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
    let w = vec![edge(5, OWNER, 0, 1, Some(Role::Write), None), reg(10, 1, 1, ADM, Retention::PLAIN, 1)];
    assert_eq!(evaluate(&held(2, w)).valid[&(10, 0)], false);
    let a = vec![edge(5, OWNER, 0, 1, Some(Role::Admin), None), reg(10, 1, 1, ADM, Retention::PLAIN, 1)];
    assert_eq!(evaluate(&held(2, a)).valid[&(10, 0)], true);
}

// spec/permissions.md §7: a demotion not listing the request takes the purge right, however early
#[test]
fn demotion_takes_the_purge_right_spec_permissions_7() {
    let cs = |f: Vec<CommitId>| {
        vec![
            edge(5, OWNER, 0, 1, Some(Role::Write), None),
            reg(10, 1, 1, REG, Retention::PLAIN, 7),
            purge(15, 1, 2, PurgeItem::Commit { commit: 10, thing: T, aspect: REG }),
            edge(20, OWNER, 3, 1, None, Some(f)),
        ]
    };
    assert_eq!(read(&held(4, cs(vec![10, 15])), REG), Read::Absent);
    // the purge falls; the write it named is not listed either, so nothing shows
    let o = evaluate(&held(4, cs(vec![10])));
    assert!(o.purged.is_empty());
    assert_eq!(read(&held(4, cs(vec![10])), REG), Read::Reg(7));
}
