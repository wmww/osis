//! spec/permissions.md §1 (mint admin), §2 (self-removal, `until`, finalize, may-grant), §5.2 (content),
//! §7 (links).
use crate::util::*;
use held_model::gen::{ACCOUNT, LINK_K, LINK_L, REG};
use held_model::*;

fn timed(holder: NodeId, role: Role, until_h: u64) -> EdgeWrite {
    EdgeWrite { holder, role: Some(role), may_grant: false, until: Some(at(until_h)) }
}

// spec/permissions.md §2 (Self-removal): a holder removes its own edge with no authority on the
// target; it audits nothing
#[test]
fn self_removal_needs_no_authority_and_audits_nothing_spec_permissions_2() {
    let hd = held(5, vec![
        edge(5, MINT_ADMIN, 0, 1, Some(Role::Write), None),
        reg(10, 1, 1, REG, PurgeBy::AuthorOrAdmin, 1),
        edge(6, 1, 2, 1, None, None),
        reg(11, 1, 3, Aspect::plain(5), PurgeBy::AuthorOrAdmin, 2),
    ]);
    let o = evaluate(&hd);
    assert!(o.valid[&(6, 0)]);
    assert!(o.valid[&(10, 0)]);
    assert!(!o.valid[&(11, 0)]);
}

// spec/permissions.md §2 (`until`; finalize): a timed edge ends at its `until`; a frontier-less
// removal applies only past it
#[test]
fn until_ends_an_edge_and_finalize_applies_only_past_it_spec_permissions_2() {
    let cs = |fin_h: u64| {
        vec![
            edge_on(5, MINT_ADMIN, 0, T, timed(1, Role::Write, 3), None),
            reg(10, 1, 1, REG, PurgeBy::AuthorOrAdmin, 1),
            reg(11, 1, 4, Aspect::plain(5), PurgeBy::AuthorOrAdmin, 2),
            edge(6, MINT_ADMIN, fin_h, 1, None, None),
        ]
    };
    let o = evaluate(&held(5, cs(2)));
    assert!(o.valid[&(10, 0)]);
    assert!(!o.valid[&(11, 0)]);
    assert!(!o.valid[&(6, 0)], "before the until a finalize applies nothing");
    assert!(evaluate(&held(5, cs(4))).valid[&(6, 0)]);
}

// spec/permissions.md §2 (May-grant grant): a holder whose grant carries the flag adds a holder
// up to its grant's role
#[test]
fn may_grant_grant_up_to_the_grants_role_spec_permissions_2() {
    let inv = EdgeWrite { holder: 1, role: Some(Role::Write), may_grant: true, until: None };
    let cs = |role: Role| {
        vec![
            edge_on(5, MINT_ADMIN, 0, T, inv, None),
            edge(6, 1, 1, 2, Some(role), None),
            reg(10, 2, 2, REG, PurgeBy::AuthorOrAdmin, 1),
        ]
    };
    let o = evaluate(&held(5, cs(Role::Write)));
    assert!(o.valid[&(6, 0)] && o.valid[&(10, 0)]);
    let o = evaluate(&held(5, cs(Role::Admin)));
    assert!(!o.valid[&(6, 0)]);
}

// spec/permissions.md §7 (redeem; single use; finalized): L adds a node on K by may-grant and
// removes its own edge; the joiner writes along [K]; the sharer's explicit removal of L drops the
// redemption its frontier leaves out
#[test]
fn link_redeem_and_finalize_spec_permissions_7() {
    let l = EdgeWrite { holder: LINK_L, role: Some(Role::Write), may_grant: true, until: None };
    let redeem = {
        let mut c = edge_on(7, LINK_L, 1, LINK_K, EdgeWrite::role(3, Some(Role::Write)), None);
        c.parts.push(edge_on(0, 0, 0, LINK_K, EdgeWrite::role(LINK_L, None), None).parts.remove(0));
        c
    };
    let cs = |fin: Option<Vec<CommitId>>| {
        let mut v = vec![
            edge_on(5, MINT_ADMIN, 0, T, EdgeWrite::role(LINK_K, Some(Role::Write)), None),
            edge_on(6, MINT_ADMIN, 0, LINK_K, l, None),
            redeem.clone(),
            reg(10, 3, 2, REG, PurgeBy::AuthorOrAdmin, 1).along(&[LINK_K]),
        ];
        if let Some(f) = fin {
            v.push(edge_on(8, MINT_ADMIN, 3, LINK_K, EdgeWrite::role(LINK_L, None), Some(f)));
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

// spec/permissions.md §1 (mint admin, Path), §5.2: a path through an account's record edge; an
// admin of the account writes along [account], and loses that with an explicit demotion
#[test]
fn record_edge_through_an_account_spec_permissions_1() {
    let on12 = |id, author, h| Commit { parts: vec![Part { thing: 12, ..part(REG, PurgeBy::AuthorOrAdmin, vec![set(h, id, 1)]) }], ..content(id, author, h, vec![]) };
    let cs = |demote: bool| {
        let mut v = vec![on12(10, 2, 1), edge_on(5, 2, 1, ACCOUNT, EdgeWrite::role(3, Some(Role::Admin)), None), on12(11, 3, 2).along(&[ACCOUNT])];
        if demote {
            v.push(edge_on(6, 2, 3, ACCOUNT, EdgeWrite::role(3, None), Some(vec![])));
        }
        held(5, v)
    };
    let o = evaluate(&cs(false));
    assert!(o.valid[&(10, 0)] && o.valid[&(11, 0)]);
    assert!(!evaluate(&cs(true)).valid[&(11, 0)]);
}

// spec/permissions.md §2 (Self-removal): node 2, admin of the account by its record edge,
// removes the account's record edge on 12 along the path [account], which ends at the holder: a
// self-removal, not a finalize
#[test]
fn record_edge_removed_by_an_admin_of_the_mint_admin_spec_permissions_2() {
    let on12 = |id, author, h| Commit { parts: vec![Part { thing: 12, ..part(REG, PurgeBy::AuthorOrAdmin, vec![set(h, id, 1)]) }], ..content(id, author, h, vec![]) };
    let o = evaluate(&held(5, vec![on12(10, 2, 1), edge_on(6, 2, 2, 12, EdgeWrite::role(ACCOUNT, None), None).along(&[ACCOUNT]), on12(11, 2, 3)]));
    assert!(o.valid[&(6, 0)], "the removal applies");
    assert!(o.valid[&(10, 0)] && !o.valid[&(11, 0)]);
}

// spec/permissions.md §1: the mint admin's record edge is an edge like any
#[test]
fn mint_admin_is_an_edge_spec_permissions_1() {
    let on13 = |id, author, h| Commit { parts: vec![Part { thing: 13, ..part(REG, PurgeBy::AuthorOrAdmin, vec![set(h, id, 1)]) }], ..content(id, author, h, vec![]) };
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

// spec/permissions.md §5.2 (Content), spec/commits.md §4 (Unjudgeable): a delta stated along the
// account, the account its purge author, is valid only where every edge of that path gives write;
// it waits while an edge of the path is neither a record edge nor set by a held grant
#[test]
fn a_delta_along_an_account_rests_on_its_signers_edge_there_spec_permissions_5_2() {
    let as_account = |id, author, h| Commit { author: ACCOUNT, parts: vec![Part { thing: 12, ..part(REG, PurgeBy::AuthorOrAdmin, vec![set(h, id, 1)]) }], ..content(id, author, h, vec![]) }.along(&[ACCOUNT]);
    let o = evaluate(&held(5, vec![as_account(10, 2, 1), as_account(11, 1, 1)]));
    assert!(o.valid[&(10, 0)]);
    assert!(!o.valid.contains_key(&(11, 0)), "nothing leads from node 1 to thing 12: it waits");
    let o = evaluate(&held(5, vec![edge_on(5, 2, 0, ACCOUNT, EdgeWrite::role(1, Some(Role::Write)), None), as_account(11, 1, 1)]));
    assert!(o.valid[&(11, 0)]);
}

// spec/permissions.md §1 (Path: nothing but the stated path judges a part), §5.2: node 1 holds
// write on T by its own grant and through K; a write stated along [K] falls with K's grant though
// 1's own grant stands, and one stating no thing falls with 1's own grant though K's stands
#[test]
fn only_the_stated_path_judges_a_delta_spec_permissions_1() {
    let cs = |removed: NodeId| {
        held(5, vec![
            edge_on(5, MINT_ADMIN, 0, T, EdgeWrite::role(LINK_K, Some(Role::Write)), None),
            edge_on(6, MINT_ADMIN, 0, LINK_K, EdgeWrite::role(1, Some(Role::Write)), None),
            edge_on(7, MINT_ADMIN, 0, T, EdgeWrite::role(1, Some(Role::Write)), None),
            reg(10, 1, 1, REG, PurgeBy::AuthorOrAdmin, 1),
            reg(11, 1, 2, REG, PurgeBy::AuthorOrAdmin, 2).along(&[LINK_K]),
            edge_on(8, MINT_ADMIN, 3, T, EdgeWrite::role(removed, None), Some(vec![])),
        ])
    };
    let o = evaluate(&cs(LINK_K));
    assert!(o.valid[&(10, 0)] && !o.valid[&(11, 0)], "K's grant is the hop of the path along K alone");
    let o = evaluate(&cs(1));
    assert!(!o.valid[&(10, 0)] && o.valid[&(11, 0)], "1's own grant is the hop of the direct path alone");
}

// spec/permissions.md §6 (The right: author): a request holding write holds the author right over
// a delta only where its own path holds the delta's purge author. Node 1 writes T along [K] as K;
// node 2, a writer of K, purges it along [K]; node 3, a writer of T by its own grant, does not,
// but takes a delta purgeable by `writer`
#[test]
fn the_author_right_needs_the_purge_author_on_the_requests_path_spec_permissions_6() {
    let cs = |by: PurgeBy, requester: NodeId, path: &[ThingId]| {
        let mut v = vec![
            edge_on(5, MINT_ADMIN, 0, T, EdgeWrite::role(LINK_K, Some(Role::Write)), None),
            edge_on(6, MINT_ADMIN, 0, LINK_K, EdgeWrite::role(1, Some(Role::Write)), None),
            edge_on(7, MINT_ADMIN, 0, LINK_K, EdgeWrite::role(2, Some(Role::Write)), None),
            edge_on(8, MINT_ADMIN, 0, T, EdgeWrite::role(3, Some(Role::Write)), None),
            Commit { author: LINK_K, ..reg(10, 1, 1, REG, by, 1).along(&[LINK_K]) },
        ];
        v.push(purge(20, requester, 2, PurgeItem::Commit { commit: 10, thing: T, aspect: REG }).along(path));
        evaluate(&held(5, v))
    };
    let o = cs(PurgeBy::AuthorOrAdmin, 2, &[LINK_K]);
    assert!(o.valid[&(10, 0)] && o.purged.contains_key(&(10, 0)), "K is on the request's path");
    assert!(!cs(PurgeBy::AuthorOrAdmin, 3, &[]).purged.contains_key(&(10, 0)), "a writer whose path does not hold K");
    assert!(cs(PurgeBy::Writer, 3, &[]).purged.contains_key(&(10, 0)), "any writer's request takes a `writer` delta");
    assert!(!cs(PurgeBy::Admin, 2, &[LINK_K]).purged.contains_key(&(10, 0)), "an `admin` delta is no writer's");
}
