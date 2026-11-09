//! Records as writes (notes/expiry-creation-design.md §3): a thing exists while a creation of it
//! (`created.0`) is held live; parts on a thing that does not exist are not held, and fetched
//! again once its creation comes; expiry or purge of the creation ends the thing, and the node
//! forgets it; things an ended thing created live on. spec/commits.md §4, §5, §6;
//! spec/permissions.md §1.
use crate::util::*;
use held_model::gen::{creation, ACCOUNT, CREATION_ID, REG};
use held_model::*;

/// T's creation by its first admin at hour 0, `admin` with no history promised, expiring at
/// hour `expires`.
fn made(expires: Option<u64>) -> Commit {
    creation(T, RecordLink::Admin(FIRST_ADMIN), FIRST_ADMIN, ts(0), Retention::ROLE, expires.map(at))
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
    let both = held(5, vec![made(None), reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 1)]);
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
    late.commits.push(reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 1));
    assert_eq!(evaluate(&late).reads, evaluate(&both).reads);
}

// spec/commits.md §6: a thing's creation expiring ends it: every part on it goes, the read is
// absent from T on, and what the node holds next says the same
#[test]
fn expired_creation_ends_the_thing_spec_commits_6() {
    let h = |now| held(now, vec![made(Some(3)), reg(10, FIRST_ADMIN, 1, REG, Retention::FIXED, 1)]);
    let o = evaluate(&h(2));
    assert!(o.ended.is_empty());
    assert!(o.deadlines.contains(&at(3)));
    assert_eq!(read(&h(2), REG), int(1));
    let o = evaluate(&h(3));
    assert_eq!(o.ended, [T].into());
    assert_eq!(o.fates[&(10, 0)], Fate::MustDrop(DropWhy::Ended), "kept for good, it goes with its thing");
    assert_eq!(o.fates[&(CREATION_ID + T, 0)], Fate::MustDrop(DropWhy::Ended));
    assert_eq!(read(&h(3), REG), None);
    let next = act(&h(3), &o, None);
    assert!(next.commits.iter().flat_map(|c| c.parts.iter()).filter(|p| p.thing == T).all(|p| p.body == Body::Missing));
    assert_eq!(evaluate(&next).reads, o.reads);
    assert!(evaluate(&next).ended.is_empty(), "nothing of it held: it is unknown, not ended");
}

// spec/commits.md §5 (Purge): a purge of the creation by a right holder ends the thing; one by a
// node without the right does not
#[test]
fn purged_creation_ends_the_thing_spec_commits_5() {
    let item = PurgeItem::Commit { commit: CREATION_ID + T, thing: T, aspect: Aspect::CREATED };
    let w = reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 1);
    let hd = held(5, vec![made(None), w.clone(), purge(20, FIRST_ADMIN, 2, item)]);
    let o = evaluate(&hd);
    assert_eq!(o.ended, [T].into());
    assert!(o.applied.contains(&20), "the request stands, its own part on the thing forgotten");
    assert_eq!(read(&hd, REG), None);
    let other = held(5, vec![made(None), w, edge(5, FIRST_ADMIN, 0, 2, Some(Role::Write), None), purge(20, 2, 2, item)]);
    assert!(evaluate(&other).ended.is_empty());
    assert_eq!(read(&other, REG), int(1));
}

// spec/commits.md §5 (Purge), spec/permissions.md §6: the right to end a thing is judged with the
// thing's data held: an admin by a grant on the thing itself ends it
#[test]
fn ending_is_judged_with_the_things_roles_spec_commits_5() {
    let item = PurgeItem::Aspect { thing: T, aspect: Aspect::CREATED };
    let hd = held(5, vec![made(None), edge(5, FIRST_ADMIN, 0, 2, Some(Role::Admin), None), reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 1), purge(20, 2, 2, item)]);
    let o = evaluate(&hd);
    assert_eq!(o.ended, [T].into());
    assert_eq!(o.fates[&(5, 0)], Fate::MustDrop(DropWhy::Ended), "its roles go with it");
    let next = act(&hd, &o, None);
    assert_eq!(evaluate(&next).reads, o.reads);
}

// notes/expiry-creation-design.md §3 (Ending): a write after the end is a write to an unknown
// thing: never read, whether the expired creation is held or not
#[test]
fn write_after_the_end_is_ignored_spec_commits_6() {
    let late = reg(10, FIRST_ADMIN, 4, REG, Retention::PLAIN, 2);
    let hd = held(5, vec![made(Some(3)), late]);
    let o = evaluate(&hd);
    assert_eq!(o.fates[&(10, 0)], Fate::MustDrop(DropWhy::Ended));
    assert_eq!(read(&hd, REG), None);
    let mut next = act(&hd, &o, None);
    assert_eq!(read(&next, REG), None);
    // the creation forgotten, a write arriving later is to an unknown thing
    next.commits.push(reg(11, FIRST_ADMIN, 4, REG, Retention::PLAIN, 3));
    let o = evaluate(&next);
    assert_eq!(o.revisit, [11].into());
    assert_eq!(read(&next, REG), None);
}

// spec/permissions.md §1 (first admins), notes/expiry-creation-design.md §3 (Dependents, B):
// things an ended thing created live on: thing 12, whose first admin is the account, reads on
// after the account's creation expires, its chain proved by the account's raw record
#[test]
fn things_an_ended_thing_created_live_on_spec_permissions_1() {
    let acc = creation(ACCOUNT, RecordLink::Admin(2), 2, ts(0), Retention::ROLE, Some(at(3)));
    let w = Commit { parts: vec![Part { thing: 12, ..part(REG, Retention::PLAIN, vec![set(1, 10, 7)]) }], ..reg(10, 2, 1, REG, Retention::PLAIN, 7) };
    let hd = held(5, vec![acc, w]);
    let o = evaluate(&hd);
    assert_eq!(o.ended, [ACCOUNT].into());
    assert!(o.valid[&(10, 0)]);
    assert_eq!(o.reads.get(&(12, REG)).cloned().flatten(), int(7));
}
