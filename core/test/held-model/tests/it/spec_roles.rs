//! spec/permissions.md §1 (ownership), §2 (self-removal, `until`, finalize, invites), §5.2 (acting),
//! §7 (links).
use crate::util::*;
use held_model::gen::{LINK_K, LINK_L, PERSON, REG};
use held_model::*;

fn timed(holder: NodeId, role: Role, until_h: u64) -> EdgeWrite {
    EdgeWrite { holder, role: Some(role), invite: None, until: Some(at(until_h)) }
}

// spec/permissions.md §2 (Self-removal): a holder removes its own edge with no authority on the
// target; it audits nothing
#[test]
fn self_removal_needs_no_authority_and_audits_nothing_spec_permissions_2() {
    let hd = held(5, vec![
        edge(5, OWNER, 0, 1, Some(Role::Write), None),
        reg(10, 1, 1, REG, Retention::PLAIN, 1),
        edge(6, 1, 2, 1, None, None),
        reg(11, 1, 3, Aspect::reg(5), Retention::PLAIN, 2),
    ]);
    let o = evaluate(&hd);
    assert!(o.valid[&(6, 0)]);
    assert!(o.valid[&(10, 0)]);
    assert!(!o.valid[&(11, 0)]);
}

// spec/permissions.md §2 (`until`, Finalize): a timed edge ends at its `until`; a frontier-less
// removal applies only past it
#[test]
fn until_ends_an_edge_and_finalize_applies_only_past_it_spec_permissions_2() {
    let cs = |fin_h: u64| {
        vec![
            edge_on(5, OWNER, 0, T, timed(1, Role::Write, 3), None),
            reg(10, 1, 1, REG, Retention::PLAIN, 1),
            reg(11, 1, 4, Aspect::reg(5), Retention::PLAIN, 2),
            edge(6, OWNER, fin_h, 1, None, None),
        ]
    };
    let o = evaluate(&held(5, cs(2)));
    assert!(o.valid[&(10, 0)]);
    assert!(!o.valid[&(11, 0)]);
    assert!(!o.valid[&(6, 0)], "before the until a finalize applies nothing");
    assert!(evaluate(&held(5, cs(4))).valid[&(6, 0)]);
}

// spec/permissions.md §2 (Invite grant): an invite holder adds an edge up to its effective invite
#[test]
fn invite_grant_up_to_the_invite_spec_permissions_2() {
    let inv = EdgeWrite { holder: 1, role: Some(Role::Write), invite: Some(Role::Write), until: None };
    let cs = |role: Role| {
        vec![
            edge_on(5, OWNER, 0, T, inv, None),
            edge(6, 1, 1, 2, Some(role), None),
            reg(10, 2, 2, REG, Retention::PLAIN, 1),
        ]
    };
    let o = evaluate(&held(5, cs(Role::Write)));
    assert!(o.valid[&(6, 0)] && o.valid[&(10, 0)]);
    let o = evaluate(&held(5, cs(Role::Admin)));
    assert!(!o.valid[&(6, 0)]);
}

// spec/permissions.md §7 (Redeem, Single use, Finalized): L invite-grants a node on K and removes its
// own edge; the sharer's explicit removal of L audits L's grants its frontier leaves out
#[test]
fn link_redeem_and_finalize_spec_permissions_7() {
    let l = EdgeWrite { holder: LINK_L, role: Some(Role::Write), invite: Some(Role::Write), until: None };
    let redeem = {
        let mut c = edge_on(7, LINK_L, 1, LINK_K, EdgeWrite::role(3, Some(Role::Write)), None);
        c.parts.push(edge_on(0, 0, 0, LINK_K, EdgeWrite::role(LINK_L, None), None).parts.remove(0));
        c
    };
    let cs = |fin: Option<Vec<CommitId>>| {
        let mut v = vec![
            edge_on(5, OWNER, 0, T, EdgeWrite::role(LINK_K, Some(Role::Write)), None),
            edge_on(6, OWNER, 0, LINK_K, l, None),
            redeem.clone(),
            reg(10, 3, 2, REG, Retention::PLAIN, 1),
        ];
        if let Some(f) = fin {
            v.push(edge_on(8, OWNER, 3, LINK_K, EdgeWrite::role(LINK_L, None), Some(f)));
        }
        held(5, v)
    };
    let o = evaluate(&cs(None));
    assert!(o.valid[&(7, 0)] && o.valid[&(7, 1)], "grant and self-removal both apply");
    assert!(o.valid[&(10, 0)], "the joiner writes through K");
    let o = evaluate(&cs(Some(vec![])));
    assert!(!o.valid[&(7, 0)] && !o.valid[&(10, 0)]);
    let o = evaluate(&cs(Some(vec![7])));
    assert!(o.valid[&(7, 0)] && o.valid[&(10, 0)]);
}

// spec/permissions.md §1 (Ownership), §5.2: owner-chain authority through a person actor; an admin
// of the person loses it with an explicit demotion
#[test]
fn owner_chain_through_a_person_spec_permissions_1() {
    let on12 = |id, author, h| Commit { parts: vec![Part { thing: 12, ..part(REG, Retention::PLAIN, vec![set(h, id, 1)]) }], ..content(id, author, h, vec![]) };
    let cs = |demote: bool| {
        let mut v = vec![on12(10, 2, 1), edge_on(5, 2, 1, PERSON, EdgeWrite::role(3, Some(Role::Admin)), None), on12(11, 3, 2)];
        if demote {
            v.push(edge_on(6, 2, 3, PERSON, EdgeWrite::role(3, None), Some(vec![])));
        }
        held(5, v)
    };
    let o = evaluate(&cs(false));
    assert!(o.valid[&(10, 0)] && o.valid[&(11, 0)]);
    assert!(!evaluate(&cs(true)).valid[&(11, 0)]);
}

// spec/permissions.md §1 (Ownerless thing): the first admin's record edge is an edge like any
#[test]
fn ownerless_first_admin_is_an_edge_spec_permissions_1() {
    let on13 = |id, author, h| Commit { parts: vec![Part { thing: 13, ..part(REG, Retention::PLAIN, vec![set(h, id, 1)]) }], ..content(id, author, h, vec![]) };
    let cs = |remove: bool| {
        let mut v = vec![edge_on(5, 3, 0, 13, EdgeWrite::role(1, Some(Role::Admin)), None), on13(10, 3, 2)];
        if remove {
            // the frontier lists the grant that made node 1 admin, else the audit drops it
            v.push(edge_on(6, 1, 1, 13, EdgeWrite::role(3, None), Some(vec![5])));
        }
        held(5, v)
    };
    assert!(evaluate(&cs(false)).valid[&(10, 0)]);
    assert!(!evaluate(&cs(true)).valid[&(10, 0)]);
}

// spec/permissions.md §5.2 (Acting): a delta acting for an actor is valid only while its author could
// write on that actor
#[test]
fn acting_for_a_person_spec_permissions_5_2() {
    let as_person = |id, author, h| Commit { actor: PERSON, parts: vec![Part { thing: 12, ..part(REG, Retention::PLAIN, vec![set(h, id, 1)]) }], ..content(id, author, h, vec![]) };
    let o = evaluate(&held(5, vec![as_person(10, 2, 1), as_person(11, 1, 1)]));
    assert!(o.valid[&(10, 0)]);
    assert!(!o.valid.contains_key(&(11, 0)), "nothing leads from node 1 to thing 12: it waits");
    let o = evaluate(&held(5, vec![edge_on(5, 2, 0, PERSON, EdgeWrite::role(1, Some(Role::Write)), None), as_person(11, 1, 1)]));
    assert!(o.valid[&(11, 0)]);
}
