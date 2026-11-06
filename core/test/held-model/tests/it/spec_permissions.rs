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

// spec/permissions.md §5.2: a snapshot dropped while valid leaves what it gave; a copy of it held
// again and judged invalid takes that back, but not writes of a delta dropped here otherwise
#[test]
fn dropped_valid_snapshot_held_again_invalid_takes_back_spec_permissions_5_2() {
    let w = set(1, 10, 7);
    let mk = |snap_body: Body, own_body: Body, dropped_valid: bool| {
        let mut own = reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 7);
        own.parts[0].body = own_body;
        let mut s = snap(20, 1, 2, REG, Retention::WRITER, vec![w.clone()]);
        s.parts[0].body = snap_body;
        let mut h = held(5, vec![edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None), own, s, edge(30, FIRST_ADMIN, 3, 1, None, Some(vec![]))]);
        h.own_state = vec![StateWrite { thing: T, aspect: REG, write: w.clone() }];
        if dropped_valid {
            h.dropped_valid.insert((20, 0));
        }
        h
    };
    let s_body = Body::Held(Delta::Writes(vec![w.clone()]));
    assert_eq!(evaluate(&mk(s_body.clone(), Body::Missing, false)).valid[&(20, 0)], false);
    assert_eq!(read(&mk(Body::Dropped, Body::Missing, true), REG), Read::Reg(7), "dropped: what it gave stays");
    assert_eq!(read(&mk(s_body.clone(), Body::Missing, true), REG), Read::Absent, "held again invalid: taken back");
    assert_eq!(read(&mk(s_body.clone(), Body::Missing, false), REG), Read::Reg(7), "never dropped: gave nothing to take");
    assert_eq!(read(&mk(s_body, Body::Dropped, true), REG), Read::Reg(7), "its own delta dropped here: stays");
}
