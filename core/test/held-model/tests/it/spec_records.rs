//! Records as writes (notes/expiry-creation-design.md §3): a thing exists while a creation of it
//! (`created.0`) is held live; parts on a thing that does not exist are not held, and fetched
//! again once its creation comes; expiry or purge of the creation destroys the thing, and the node
//! forgets it; what relies on a destroyed thing lives on. spec/commits.md §4, §5, §6;
//! spec/permissions.md §1.
use crate::util::*;
use held_model::gen::{creation, ACCOUNT, CREATION_ID, LINK_K, REG};
use held_model::*;

/// T's creation by its mint admin at hour 0, `admin` with no history promised, expiring at
/// hour `expires`.
fn made(expires: Option<u64>) -> Commit {
    creation(T, RecordLink::Admin(MINT_ADMIN), MINT_ADMIN, ts(0), PurgeBy::Admin, expires.map(at))
}

fn without(mut h: Held, id: CommitId) -> Held {
    h.commits.retain(|c| c.id != id);
    h
}

// spec/commits.md §4 (A held part waits): the thing exists while its creation is held; without
// it the write is not held and its commit is thrown out, to be fetched again; once the creation
// comes the commit reads as if both came together
#[test]
fn creation_after_writes_reads_like_creation_first_spec_commits_4() {
    let both = held(5, vec![made(None), reg(10, MINT_ADMIN, 1, REG, PurgeBy::AuthorOrAdmin, 1)]);
    assert_eq!(read(&both, REG), int(1));
    let early = without(both.clone(), CREATION_ID + T);
    let o = evaluate(&early);
    assert_eq!(o.fates[&(10, 0)], Fate::MustDrop(DropWhy::Unknown));
    assert_eq!(o.revisit, [10].into());
    assert_eq!(read(&early, REG), None);
    let mut late = act(&early, &o, None);
    assert!(late.commits.iter().all(|c| c.id != 10), "thrown out whole");
    // the creation comes; the commit thrown out is fetched again
    late.commits.push(made(None));
    late.commits.push(reg(10, MINT_ADMIN, 1, REG, PurgeBy::AuthorOrAdmin, 1));
    assert_eq!(evaluate(&late).reads, evaluate(&both).reads);
}

// spec/commits.md §6: a thing's creation expiring destroys it: every part on it goes, the read is
// absent from T on, and what the node holds next says the same
#[test]
fn expired_creation_destroys_the_thing_spec_commits_6() {
    let h = |now| held(now, vec![made(Some(3)), reg(10, MINT_ADMIN, 1, REG, PurgeBy::Admin, 1)]);
    let o = evaluate(&h(2));
    assert!(o.destroyed.is_empty());
    assert!(o.deadlines.contains(&at(3)));
    assert_eq!(read(&h(2), REG), int(1));
    let o = evaluate(&h(3));
    assert_eq!(o.destroyed, [T].into());
    assert_eq!(o.fates[&(10, 0)], Fate::MustDrop(DropWhy::Destroyed), "kept for good, it goes with its thing");
    assert_eq!(o.fates[&(CREATION_ID + T, 0)], Fate::Leftover(LeftoverWhy::Expired), "its gone creation stays, a header");
    assert_eq!(read(&h(3), REG), None);
    let next = act(&h(3), &o, None);
    assert!(next.commits.iter().flat_map(|c| c.parts.iter()).filter(|p| p.thing == T && p.aspect != Aspect::CREATED).all(|p| p.body == Body::Missing));
    assert_eq!(evaluate(&next).reads, o.reads);
    assert_eq!(evaluate(&next).destroyed, [T].into(), "still destroyed, not unknown");
}

// spec/commits.md §5 (Destruction): authority that passed through a destroyed thing stands as its
// held edge writes say, its gone creations and role-class parts staying however it was destroyed: a
// write on T along [K], made before K expired, reads on once the node has dropped what K's
// destruction drops
#[test]
fn authority_through_an_expired_thing_stands_spec_commits_5() {
    let k = creation(LINK_K, RecordLink::Admin(MINT_ADMIN), MINT_ADMIN, ts(0), PurgeBy::Admin, Some(at(3)));
    let h = held(5, vec![
        k,
        edge_on(5, MINT_ADMIN, 0, T, EdgeWrite::role(LINK_K, Some(Role::Write)), None),
        edge_on(6, MINT_ADMIN, 0, LINK_K, EdgeWrite::role(3, Some(Role::Write)), None),
        reg(10, 3, 1, REG, PurgeBy::AuthorOrAdmin, 7).along(&[LINK_K]),
    ]);
    let o = evaluate(&h);
    assert_eq!(o.destroyed, [LINK_K].into());
    assert!(o.valid[&(10, 0)]);
    assert_eq!(read(&h, REG), int(7));
    let next = act(&h, &o, None);
    let on = evaluate(&next);
    assert_eq!(on.destroyed, [LINK_K].into());
    assert!(on.valid[&(10, 0)], "the path through K still judges");
    assert_eq!(on.reads, o.reads);
}

// spec/commits.md §5 (Purge): a purge of the creation by a right holder destroys the thing; one by a
// node without the right does not
#[test]
fn purged_creation_destroys_the_thing_spec_commits_5() {
    let item = PurgeItem::Aspect { thing: T, aspect: Aspect::CREATED };
    let w = reg(10, MINT_ADMIN, 1, REG, PurgeBy::AuthorOrAdmin, 1);
    let hd = held(5, vec![made(None), w.clone(), purge(20, MINT_ADMIN, 2, item)]);
    let o = evaluate(&hd);
    assert_eq!(o.destroyed, [T].into());
    assert!(o.applied.contains(&20), "the request stands, its own part on the thing forgotten");
    assert_eq!(read(&hd, REG), None);
    let other = held(5, vec![made(None), w, edge(5, MINT_ADMIN, 0, 2, Some(Role::Write), None), purge(20, 2, 2, item)]);
    assert!(evaluate(&other).destroyed.is_empty());
    assert_eq!(read(&other, REG), int(1));
}

// spec/permissions.md §6 (Destruction), spec/commits.md §5: any admin at the request may destroy a thing,
// and the verdict reads the edges the destruction keeps: a removal arriving after the destruction makes it
// fall, and a stale creation copy is destroyed again
#[test]
fn destruction_is_judged_from_the_edges_it_keeps_spec_permissions_6() {
    let item = PurgeItem::Aspect { thing: T, aspect: Aspect::CREATED };
    let w = reg(10, MINT_ADMIN, 1, REG, PurgeBy::AuthorOrAdmin, 1);
    let grant = edge(5, MINT_ADMIN, 0, 2, Some(Role::Admin), None);
    let by_grant = held(5, vec![made(None), grant.clone(), w.clone(), purge(20, 2, 2, item)]);
    let o = evaluate(&by_grant);
    assert_eq!(o.destroyed, [T].into(), "a grant on the thing gives the right to destroy it");
    assert_eq!(read(&by_grant, REG), None);
    // a stale creation copy the purge still names destroys it again: the edges stayed
    let mut next = act(&by_grant, &o, None);
    assert_eq!(read(&next, REG), None);
    next.commits.retain(|c| c.id != CREATION_ID + T);
    next.commits.push(made(None));
    assert_eq!(evaluate(&next).destroyed, [T].into(), "a stale copy brings nothing back while the purge is held");
    assert_eq!(read(&next, REG), None);
    // the grantee removes the mint admin before its request: the destruction falls in either order
    // its frontier lists the grant the removal rests on, else the audit drops it
    let removal = edge(6, 2, 1, MINT_ADMIN, None, Some(vec![5]));
    let by_first = purge(20, MINT_ADMIN, 2, item);
    let raced = held(5, vec![made(None), grant.clone(), removal.clone(), w.clone(), by_first.clone()]);
    assert!(evaluate(&raced).destroyed.is_empty(), "removal held first");
    let first = held(5, vec![made(None), grant, w, by_first]);
    let o = evaluate(&first);
    assert_eq!(o.destroyed, [T].into());
    let mut then = act(&first, &o, None);
    then.commits.push(removal);
    then.commits.retain(|c| c.id != CREATION_ID + T);
    then.commits.push(made(None));
    assert!(evaluate(&then).destroyed.is_empty(), "destruction first: the removal arriving later makes it fall");
}

// notes/expiry-creation-design.md §3 (Destruction): a write after the destruction is a write to an unknown
// thing: never read, whether the expired creation is held or not
#[test]
fn write_after_the_destruction_is_ignored_spec_commits_6() {
    let late = reg(10, MINT_ADMIN, 4, REG, PurgeBy::AuthorOrAdmin, 2);
    let hd = held(5, vec![made(Some(3)), late]);
    let o = evaluate(&hd);
    assert_eq!(o.fates[&(10, 0)], Fate::MustDrop(DropWhy::Destroyed));
    assert_eq!(read(&hd, REG), None);
    let mut next = act(&hd, &o, None);
    assert_eq!(read(&next, REG), None);
    // a write arriving after the node dropped what the destruction drops is never read either
    next.commits.push(reg(11, MINT_ADMIN, 4, REG, PurgeBy::AuthorOrAdmin, 3));
    let o = evaluate(&next);
    assert_eq!(o.fates[&(11, 0)], Fate::MustDrop(DropWhy::Destroyed));
    assert_eq!(read(&next, REG), None);
}

// spec/permissions.md §1 (mint admin), notes/expiry-creation-design.md §3 (Things relying on a destroyed thing, B):
// what relies on a destroyed thing lives on: thing 12, whose mint admin is the account, reads on
// after the account's creation expires, its chain proved by the account's raw record
#[test]
fn things_a_destroyed_thing_created_live_on_spec_permissions_1() {
    let acc = creation(ACCOUNT, RecordLink::Admin(2), 2, ts(0), PurgeBy::Admin, Some(at(3)));
    let w = Commit { parts: vec![Part { thing: 12, ..part(REG, PurgeBy::AuthorOrAdmin, vec![set(1, 10, 7)]) }], ..reg(10, 2, 1, REG, PurgeBy::AuthorOrAdmin, 7) };
    let hd = held(5, vec![acc, w]);
    let o = evaluate(&hd);
    assert_eq!(o.destroyed, [ACCOUNT].into());
    assert!(o.valid[&(10, 0)]);
    assert_eq!(o.reads.get(&(12, REG)).cloned().flatten(), int(7));
}

// notes/expiry-creation-design.md §3 (Destruction: purge is per part): purging one creation of a
// commit making two things destroys that thing alone
#[test]
fn purging_one_creation_leaves_the_others_of_its_commit_spec_commits_5() {
    const OTHER: ThingId = 14;
    let w = |id, thing, v: i64| Commit { parts: vec![Part { thing, ..part(REG, PurgeBy::AuthorOrAdmin, vec![set(1, id, v)]) }], ..reg(id, MINT_ADMIN, 1, REG, PurgeBy::AuthorOrAdmin, v) };
    let mut c = made(None);
    let other = Part { thing: OTHER, ..c.parts[0].clone() };
    c.parts.push(other);
    let item = PurgeItem::Aspect { thing: T, aspect: Aspect::CREATED };
    let hd = held(5, vec![c, w(10, T, 1), w(11, OTHER, 2), purge(20, MINT_ADMIN, 2, item)]);
    let o = evaluate(&hd);
    assert_eq!(o.destroyed, [T].into());
    assert_eq!(o.reads.get(&(T, REG)).cloned().flatten(), None);
    assert_eq!(o.reads.get(&(OTHER, REG)).cloned().flatten(), int(2));
    assert_eq!(o.fates[&(CREATION_ID + T, 0)], Fate::Leftover(LeftoverWhy::Purged), "the purged creation stays as its leftover");
    assert_ne!(o.fates[&(CREATION_ID + T, 1)], Fate::MustDrop(DropWhy::Destroyed));
}

// notes/expiry-creation-design.md §3 (Things relying on a destroyed thing): a thing kept only as a chain proof is not
// back: a write on the destroyed account goes while its raw record is held
#[test]
fn a_kept_record_does_not_bring_a_destroyed_thing_back_spec_permissions_1() {
    let acc = creation(ACCOUNT, RecordLink::Admin(2), 2, ts(0), PurgeBy::Admin, Some(at(3)));
    let w = |id, h: u64| Commit { parts: vec![Part { thing: ACCOUNT, ..part(REG, PurgeBy::AuthorOrAdmin, vec![set(h, id, 7)]) }], ..reg(id, 2, h, REG, PurgeBy::AuthorOrAdmin, 7) };
    let hd = held(5, vec![acc, w(10, 1)]);
    let o = evaluate(&hd);
    assert_eq!(o.destroyed, [ACCOUNT].into());
    assert_eq!(o.fates[&(10, 0)], Fate::MustDrop(DropWhy::Destroyed));
    let mut next = act(&hd, &o, None);
    assert!(next.records.iter().any(|r| r.id == ACCOUNT), "held as a chain proof");
    next.commits.push(w(11, 4));
    let o = evaluate(&next);
    assert_eq!(o.destroyed, [ACCOUNT].into(), "its gone creation stays beside the record");
    assert_eq!(o.fates[&(11, 0)], Fate::MustDrop(DropWhy::Destroyed));
    assert_eq!(o.reads.get(&(ACCOUNT, REG)).cloned().flatten(), None);
}
