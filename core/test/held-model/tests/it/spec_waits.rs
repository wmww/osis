//! spec/commits.md §4 (pending, waits), §5 (a waiting part past its expiry, required retention);
//! record waits as notes/expiry-creation-design.md §3 has them (thrown out, fetched again).
use crate::util::*;
use held_model::gen::{ACCOUNT, CREATION_ID, REG};
use held_model::*;

const UNKNOWN: ThingId = 99;

fn on(thing: ThingId, mut c: Commit) -> Commit {
    for p in &mut c.parts {
        p.thing = thing;
    }
    c
}

// spec/commits.md §4 (Pending), notes/expiry-creation-design.md §3: the author's record unknown,
// the commit is thrown out whole, to be fetched again
#[test]
fn unknown_author_record_throws_the_commit_out_spec_commits_4() {
    let mut hd = held(5, vec![edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None), reg(10, 1, 1, REG, Retention::PLAIN, 1)]);
    assert!(evaluate(&hd).applied.contains(&10));
    hd.records.retain(|t| t.id != 1);
    let o = evaluate(&hd);
    assert!(!o.applied.contains(&10));
    assert!(o.revisit.contains(&10));
    assert!(!act(&hd, &o, None).commits.iter().any(|c| c.id == 10));
}

// spec/commits.md §4 (A held part waits, Apply), notes/expiry-creation-design.md §3: a part on a
// thing with no creation held is not held, alone; a commit holding only such parts is thrown out
#[test]
fn part_on_unknown_thing_is_not_held_spec_commits_4() {
    let mut c = reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 1);
    c.parts.push(on(UNKNOWN, reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 2)).parts.remove(0));
    let hd = held(5, vec![c.clone()]);
    let o = evaluate(&hd);
    assert!(o.applied.contains(&10));
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Plain));
    assert_eq!(o.fates[&(10, 1)], Fate::MustDrop(DropWhy::Unknown));
    assert!(o.revisit.is_empty());
    assert_eq!(read(&hd, REG), int(1));
    assert_eq!(act(&hd, &o, None).commits.iter().find(|x| x.id == 10).unwrap().parts[1].body, Body::Missing);
    // nothing else held: the commit is thrown out
    c.parts.remove(0);
    let o = evaluate(&held(5, vec![c]));
    assert!(!o.applied.contains(&10));
    assert_eq!(o.revisit, [10].into());
    // a part on an unknown thing is not held whatever its expiry: no header applies
    let mut late = held(5, vec![]);
    let mut c = on(UNKNOWN, reg(11, FIRST_ADMIN, 1, REG, Retention::PLAIN, 2));
    c.expires = Some(at(3));
    late.commits.push(c);
    let o = evaluate(&late);
    assert_eq!(o.fates[&(11, 0)], Fate::MustDrop(DropWhy::Unknown));
    assert!(!o.applied.contains(&11) && o.revisit.contains(&11));
}

// spec/commits.md §4 (A held part waits), notes/expiry-creation-design.md §3: a record up the
// thing's chain unknown: the part is not held
#[test]
fn unknown_record_up_the_chain_throws_the_part_out_spec_commits_4() {
    let w = Commit { parts: vec![Part { thing: 12, ..part(REG, Retention::PLAIN, vec![set(1, 10, 7)]) }], ..reg(10, 2, 1, REG, Retention::PLAIN, 7) };
    let mut hd = held(5, vec![w]);
    assert!(evaluate(&hd).applied.contains(&10));
    hd.records.retain(|r| r.id != ACCOUNT);
    hd.commits.retain(|c| c.id != CREATION_ID + ACCOUNT);
    let o = evaluate(&hd);
    assert_eq!(o.fates[&(10, 0)], Fate::MustDrop(DropWhy::Unknown));
    assert!(o.revisit.contains(&10));
}

// spec/commits.md §4 (A held part waits): nothing leads from the author to the thing until an edge does
#[test]
fn author_with_no_way_to_the_thing_waits_spec_commits_4() {
    let w = reg(10, 2, 1, REG, Retention::PLAIN, 1);
    let o = evaluate(&held(5, vec![w.clone()]));
    assert!(!o.applied.contains(&10));
    let o = evaluate(&held(5, vec![w, edge(5, FIRST_ADMIN, 2, 2, Some(Role::Write), None)]));
    assert!(o.applied.contains(&10));
    assert!(!o.valid[&(10, 0)], "applied, invalid: the grant came after it");
}

// spec/commits.md §4 (A held part waits), spec/versioning.md §2: a parked part waits alone
#[test]
fn parked_part_waits_alone_spec_commits_4() {
    let mut c = reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 1);
    c.parts.push(part(Aspect::plain(5), Retention::PLAIN, vec![]));
    c.parts[1].body = Body::Parked;
    let hd = held(5, vec![c]);
    let o = evaluate(&hd);
    assert!(o.applied.contains(&10));
    assert_eq!(o.fates[&(10, 1)], Fate::Keep(KeepWhy::Pending));
    assert_eq!(read(&hd, REG), int(1));
}

// spec/commits.md §4 (What a wait holds): a role commit's part on an unknown thing goes alone
#[test]
fn role_commit_part_on_unknown_thing_goes_alone_spec_commits_4() {
    let mut c = edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None);
    c.parts.push(on(UNKNOWN, edge(5, FIRST_ADMIN, 0, 2, Some(Role::Write), None)).parts.remove(0));
    let o = evaluate(&held(5, vec![c, reg(10, 1, 1, REG, Retention::PLAIN, 1)]));
    assert!(o.applied.contains(&5) && o.valid[&(5, 0)]);
    assert!(!o.valid[&(5, 1)]);
    assert_eq!(o.fates[&(5, 1)], Fate::MustDrop(DropWhy::Unknown));
    assert!(o.valid[&(10, 0)]);
}

/// A thing nothing leads to from node 0 (first admin node 1): a part of node 0's on it waits.
const AWAY: ThingId = 11;

// spec/commits.md §5 (A waiting part past its expiry), §4: it goes and decides nothing; the commit
// applies without it
#[test]
fn waiting_part_past_expiry_goes_spec_commits_5() {
    let mut c = reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 1);
    c.parts.push(on(AWAY, reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 2)).parts.remove(0));
    c.expires = Some(at(3));
    let hd = held(4, vec![c]);
    let o = evaluate(&hd);
    assert!(o.applied.contains(&10));
    assert_eq!(o.fates[&(10, 0)], Fate::Leftover(LeftoverWhy::Expired));
    assert_eq!(o.fates[&(10, 1)], Fate::MustDrop(DropWhy::Gone));
    assert_eq!(act(&hd, &o, None).commits.iter().find(|x| x.id == 10).unwrap().parts[1].body, Body::Missing);
}

fn required(id: CommitId, h: u64, rules: Vec<Rule>) -> Commit {
    let p = Part { thing: T, aspect: Aspect::REQUIRED, retention: Retention::FIXED, body: Body::Held(Delta::Required(rules)), stripped: Default::default() };
    content(id, FIRST_ADMIN, h, vec![p])
}

// spec/commits.md §5 (Required retention): a delta breaking the setting in force at its key is
// invalid; one before the setting is not judged by it
#[test]
fn breaking_required_retention_is_invalid_spec_commits_5() {
    let rule = Rule { aspect: Some(REG.name), retention: Retention::WRITER, expiry: Some(HOUR) };
    let mut ok = reg(12, FIRST_ADMIN, 2, REG, Retention::WRITER, 3);
    ok.expires = Some(at(2) + HOUR);
    let o = evaluate(&held(2, vec![
        reg(10, FIRST_ADMIN, 0, REG, Retention::PLAIN, 1),
        required(5, 1, vec![rule]),
        reg(11, FIRST_ADMIN, 2, REG, Retention::PLAIN, 2),
        ok,
        reg(13, FIRST_ADMIN, 2, Aspect::plain(5), Retention::PLAIN, 4),
    ]));
    assert!(o.valid[&(10, 0)]);
    assert!(!o.valid[&(11, 0)]);
    assert!(o.valid[&(12, 0)]);
    assert!(o.valid[&(13, 0)], "no entry governs another AK");
}

// spec/commits.md §4 (Pending), §5 (A waiting part past its expiry): a commit whose only held part
// waits pends; once the part has gone at its expiry no part is held and it applies as its header
#[test]
fn only_waiting_part_gone_at_expiry_applies_the_header_spec_commits_5() {
    let mut c = on(AWAY, reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 2));
    c.expires = Some(at(3));
    let o = evaluate(&held(2, vec![c.clone()]));
    assert!(!o.applied.contains(&10));
    assert!(o.deadlines.contains(&at(3)));
    let o = evaluate(&held(3, vec![c]));
    assert!(o.applied.contains(&10));
    assert_eq!(o.fates[&(10, 0)], Fate::MustDrop(DropWhy::Gone));
}
