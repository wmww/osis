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

// spec/permissions.md §6 (Ending), spec/commits.md §5: any admin at the request may end a thing,
// and the verdict reads the edges the ending keeps: a removal arriving after the ending makes it
// fall, and a stale creation copy is ended again
#[test]
fn ending_is_judged_from_the_edges_it_keeps_spec_permissions_6() {
    let item = PurgeItem::Aspect { thing: T, aspect: Aspect::CREATED };
    let w = reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 1);
    let grant = edge(5, FIRST_ADMIN, 0, 2, Some(Role::Admin), None);
    let by_grant = held(5, vec![made(None), grant.clone(), w.clone(), purge(20, 2, 2, item)]);
    let o = evaluate(&by_grant);
    assert_eq!(o.ended, [T].into(), "a grant on the thing gives the right to end it");
    assert_eq!(read(&by_grant, REG), None);
    // a stale creation copy the purge still names ends it again: the edges stayed
    let mut next = act(&by_grant, &o, None);
    assert_eq!(read(&next, REG), None);
    next.commits.retain(|c| c.id != CREATION_ID + T);
    next.commits.push(made(None));
    assert_eq!(evaluate(&next).ended, [T].into(), "a stale copy brings nothing back while the purge is held");
    assert_eq!(read(&next, REG), None);
    // the grantee removes the first admin before its request: the ending falls in either order
    // its frontier lists the grant the removal rests on, else the audit drops it
    let removal = edge(6, 2, 1, FIRST_ADMIN, None, Some(vec![5]));
    let by_first = purge(20, FIRST_ADMIN, 2, item);
    let raced = held(5, vec![made(None), grant.clone(), removal.clone(), w.clone(), by_first.clone()]);
    assert!(evaluate(&raced).ended.is_empty(), "removal held first");
    let first = held(5, vec![made(None), grant, w, by_first]);
    let o = evaluate(&first);
    assert_eq!(o.ended, [T].into());
    let mut then = act(&first, &o, None);
    then.commits.push(removal);
    then.commits.retain(|c| c.id != CREATION_ID + T);
    then.commits.push(made(None));
    assert!(evaluate(&then).ended.is_empty(), "ending first: the removal arriving later makes it fall");
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

// notes/expiry-creation-design.md §3 (Ending: purge is per part): purging one creation of a
// commit making two things ends that thing alone
#[test]
fn ending_one_creation_leaves_the_others_of_its_commit_spec_commits_5() {
    const OTHER: ThingId = 14;
    let w = |id, thing, v: i64| Commit { parts: vec![Part { thing, ..part(REG, Retention::PLAIN, vec![set(1, id, v)]) }], ..reg(id, FIRST_ADMIN, 1, REG, Retention::PLAIN, v) };
    let mut c = made(None);
    let other = Part { thing: OTHER, ..c.parts[0].clone() };
    c.parts.push(other);
    let item = PurgeItem::Commit { commit: CREATION_ID + T, thing: T, aspect: Aspect::CREATED };
    let hd = held(5, vec![c, w(10, T, 1), w(11, OTHER, 2), purge(20, FIRST_ADMIN, 2, item)]);
    let o = evaluate(&hd);
    assert_eq!(o.ended, [T].into());
    assert_eq!(o.reads.get(&(T, REG)).cloned().flatten(), None);
    assert_eq!(o.reads.get(&(OTHER, REG)).cloned().flatten(), int(2));
    assert_eq!(o.fates[&(CREATION_ID + T, 0)], Fate::Leftover(LeftoverWhy::Purged), "the value-less creation stays");
    assert_ne!(o.fates[&(CREATION_ID + T, 1)], Fate::MustDrop(DropWhy::Ended));
}

// notes/expiry-creation-design.md §3 (Dependents): a thing kept only as a chain proof is not
// back: a write on the ended account goes while its raw record is held
#[test]
fn a_kept_record_does_not_bring_an_ended_thing_back_spec_permissions_1() {
    let acc = creation(ACCOUNT, RecordLink::Admin(2), 2, ts(0), Retention::ROLE, Some(at(3)));
    let w = |id, h: u64| Commit { parts: vec![Part { thing: ACCOUNT, ..part(REG, Retention::PLAIN, vec![set(h, id, 7)]) }], ..reg(id, 2, h, REG, Retention::PLAIN, 7) };
    let hd = held(5, vec![acc, w(10, 1)]);
    let o = evaluate(&hd);
    assert_eq!(o.ended, [ACCOUNT].into());
    assert_eq!(o.fates[&(10, 0)], Fate::MustDrop(DropWhy::Ended));
    let mut next = act(&hd, &o, None);
    assert!(next.records.iter().any(|r| r.id == ACCOUNT), "held as a chain proof");
    next.commits.push(w(11, 4));
    let o = evaluate(&next);
    assert_eq!(o.fates[&(11, 0)], Fate::MustDrop(DropWhy::Unknown));
    assert_eq!(o.revisit, [11].into());
    assert_eq!(o.reads.get(&(ACCOUNT, REG)).cloned().flatten(), None);
}
