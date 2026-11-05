//! spec/commits.md §4 (pending, waits), §5 (a waiting part past its expiry, required retention).
use crate::util::*;
use held_model::gen::REG;
use held_model::*;

const UNKNOWN: ThingId = 99;

fn on(thing: ThingId, mut c: Commit) -> Commit {
    for p in &mut c.parts {
        p.thing = thing;
    }
    c
}

// spec/commits.md §4 (Pending): the author's record unknown
#[test]
fn unknown_author_record_pends_spec_commits_4() {
    let mut hd = held(5, vec![edge(5, OWNER, 0, 1, Some(Role::Write), None), reg(10, 1, 1, REG, Retention::PLAIN, 1)]);
    assert!(evaluate(&hd).applied.contains(&10));
    hd.things.retain(|t| t.id != 1);
    assert!(!evaluate(&hd).applied.contains(&10));
}

// spec/commits.md §4 (A held part waits, Apply): a part on an unknown thing waits alone
#[test]
fn part_on_unknown_thing_waits_alone_spec_commits_4() {
    let mut c = reg(10, OWNER, 1, REG, Retention::PLAIN, 1);
    c.parts.push(on(UNKNOWN, reg(10, OWNER, 1, REG, Retention::PLAIN, 2)).parts.remove(0));
    let hd = held(5, vec![c.clone()]);
    let o = evaluate(&hd);
    assert!(o.applied.contains(&10));
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Plain));
    assert_eq!(o.fates[&(10, 1)], Fate::Keep(KeepWhy::Pending));
    assert_eq!(read(&hd, REG), Read::Reg(1));
    // every held part waiting: the commit pends
    c.parts.remove(0);
    assert!(!evaluate(&held(5, vec![c])).applied.contains(&10));
}

// spec/commits.md §4 (A held part waits): nothing leads from the author to the thing until an edge does
#[test]
fn author_with_no_way_to_the_thing_waits_spec_commits_4() {
    let w = reg(10, 2, 1, REG, Retention::PLAIN, 1);
    let o = evaluate(&held(5, vec![w.clone()]));
    assert!(!o.applied.contains(&10));
    let o = evaluate(&held(5, vec![w, edge(5, OWNER, 2, 2, Some(Role::Write), None)]));
    assert!(o.applied.contains(&10));
    assert!(!o.valid[&(10, 0)], "applied, invalid: the grant came after it");
}

// spec/commits.md §4 (A held part waits), spec/versioning.md §2: a parked part waits alone
#[test]
fn parked_part_waits_alone_spec_commits_4() {
    let mut c = reg(10, OWNER, 1, REG, Retention::PLAIN, 1);
    c.parts.push(part(Aspect::reg(5), Retention::PLAIN, vec![]));
    c.parts[1].body = Body::Parked;
    let hd = held(5, vec![c]);
    let o = evaluate(&hd);
    assert!(o.applied.contains(&10));
    assert_eq!(o.fates[&(10, 1)], Fate::Keep(KeepWhy::Pending));
    assert_eq!(read(&hd, REG), Read::Reg(1));
}

// spec/commits.md §4 (What a wait holds): a role commit's parts wait alone
#[test]
fn role_commit_parts_wait_alone_spec_commits_4() {
    let mut c = edge(5, OWNER, 0, 1, Some(Role::Write), None);
    c.parts.push(on(UNKNOWN, edge(5, OWNER, 0, 2, Some(Role::Write), None)).parts.remove(0));
    let o = evaluate(&held(5, vec![c, reg(10, 1, 1, REG, Retention::PLAIN, 1)]));
    assert!(o.applied.contains(&5) && o.valid[&(5, 0)]);
    assert!(!o.valid[&(5, 1)]);
    assert!(o.valid[&(10, 0)]);
}

// spec/commits.md §5 (A waiting part past its expiry), §4: it goes and decides nothing; the commit
// applies without it
#[test]
fn waiting_part_past_expiry_goes_spec_commits_5() {
    let mut c = reg(10, OWNER, 1, REG, Retention::PLAIN, 1);
    c.parts.push(on(UNKNOWN, reg(10, OWNER, 1, REG, Retention::PLAIN, 2)).parts.remove(0));
    c.expires = Some(at(3));
    let hd = held(4, vec![c]);
    let o = evaluate(&hd);
    assert!(o.applied.contains(&10));
    assert_eq!(o.fates[&(10, 0)], Fate::Leftover(LeftoverWhy::Expired));
    assert_eq!(o.fates[&(10, 1)], Fate::MustDrop(DropWhy::Gone));
    assert_eq!(act(&hd, &o, None).commits[0].parts[1].body, Body::Missing);
}

fn required(id: CommitId, h: u64, rules: Vec<Rule>) -> Commit {
    let p = Part { thing: T, aspect: Aspect::REQUIRED, retention: Retention::FIXED, body: Body::Held(Delta::Required(rules)), stripped: Default::default() };
    content(id, OWNER, h, vec![p])
}

// spec/commits.md §5 (Required retention): a delta breaking the setting in force at its key is
// invalid; one before the setting is not judged by it
#[test]
fn breaking_required_retention_is_invalid_spec_commits_5() {
    let rule = Rule { prefix: Some(REG.name), retention: Retention::WRITER, expiry: Some(HOUR) };
    let mut ok = reg(12, OWNER, 2, REG, Retention::WRITER, 3);
    ok.expires = Some(at(2) + HOUR);
    let o = evaluate(&held(2, vec![
        reg(10, OWNER, 0, REG, Retention::PLAIN, 1),
        required(5, 1, vec![rule]),
        reg(11, OWNER, 2, REG, Retention::PLAIN, 2),
        ok,
        reg(13, OWNER, 2, Aspect::reg(5), Retention::PLAIN, 4),
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
    let mut c = on(UNKNOWN, reg(10, OWNER, 1, REG, Retention::PLAIN, 2));
    c.expires = Some(at(3));
    let o = evaluate(&held(2, vec![c.clone()]));
    assert!(!o.applied.contains(&10));
    assert!(o.deadlines.contains(&at(3)));
    let o = evaluate(&held(3, vec![c]));
    assert!(o.applied.contains(&10));
    assert_eq!(o.fates[&(10, 0)], Fate::MustDrop(DropWhy::Gone));
}
