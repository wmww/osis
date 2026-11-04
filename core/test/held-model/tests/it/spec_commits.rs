//! spec/commits.md §4 (atomic apply), §5 (retention, purge), §6 (expiry).
use crate::util::*;
use held_model::gen::{MAP, REG};
use held_model::*;

const OTHER: Aspect = Aspect::reg(5);

fn two_parts(expires: Option<u64>) -> Commit {
    let mut c = content(10, OWNER, 1, vec![part(REG, Retention::PLAIN, vec![set(1, 10, 7)]), part(OTHER, Retention::PLAIN, vec![set(1, 10, 8)])]);
    c.expires = expires;
    c
}

// spec/commits.md §4 (Atomic apply)
#[test]
fn atomic_apply_waits_for_a_missing_part_spec_commits_4() {
    let h = held(2, vec![missing(two_parts(None), 1)]);
    assert!(!evaluate(&h).applied.contains(&10));
    assert_eq!(read(&h, REG), Read::Absent);
    assert_eq!(fate(&h, 10), Fate::Keep(KeepWhy::Pending));
    let h = held(2, vec![two_parts(None)]);
    assert_eq!(read(&h, REG), Read::Reg(7));
}

// spec/commits.md §4 (Dropped or expired)
#[test]
fn missing_expired_part_counts_held_spec_commits_4() {
    let h = held(3, vec![missing(two_parts(Some(at(2))), 1)]);
    let o = evaluate(&h);
    assert!(o.applied.contains(&10));
    assert_eq!(o.fates[&(10, 0)], Fate::Leftover(LeftoverWhy::Expired));
}

// spec/commits.md §4 (Under a later snapshot)
#[test]
fn missing_part_under_later_snapshot_counts_held_spec_commits_4() {
    let s = snap(20, OWNER, 2, REG, Retention::WRITER, vec![set(1, 10, 7)]);
    let h = held(3, vec![missing(reg(10, OWNER, 1, REG, Retention::PLAIN, 7), 0), s]);
    assert!(evaluate(&h).applied.contains(&10));
    assert_eq!(read(&h, REG), Read::Reg(7));
}

// spec/commits.md §4 (Past keep at most)
#[test]
fn missing_part_past_keep_at_most_counts_held_spec_commits_4() {
    let zero = Retention { most_zero: true, ..Retention::WRITER };
    let cs = vec![missing(reg(10, OWNER, 1, REG, zero, 1), 0), reg(11, OWNER, 2, REG, Retention::PLAIN, 2)];
    assert!(!evaluate(&held(1, cs.clone())).applied.contains(&10));
    assert!(evaluate(&held(3, cs)).applied.contains(&10));
}

// spec/commits.md §4 (Purged)
#[test]
fn missing_part_purged_counts_held_spec_commits_4() {
    let cs = vec![
        edge(5, OWNER, 0, 1, Some(Role::Write), None),
        missing(reg(10, 1, 1, REG, Retention::PLAIN, 7), 0),
        purge(20, OWNER, 2, PurgeItem::Commit(10)),
    ];
    assert!(evaluate(&held(3, cs)).applied.contains(&10));
}

// spec/commits.md §4 (Author lowered)
#[test]
fn missing_part_of_lowered_author_counts_held_spec_commits_4() {
    let cs = vec![
        edge(5, OWNER, 0, 1, Some(Role::Write), None),
        missing(reg(10, 1, 1, REG, Retention::PLAIN, 7), 0),
        edge(20, OWNER, 2, 1, None, Some(vec![])),
    ];
    let o = evaluate(&held(3, cs));
    assert!(o.applied.contains(&10));
    assert_eq!(o.valid[&(10, 0)], false);
}

// spec/commits.md §5 (Purge)
#[test]
fn author_purge_leaves_a_leftover_and_no_value_spec_commits_5() {
    let cs = vec![
        edge(5, OWNER, 0, 1, Some(Role::Write), None),
        reg(10, 1, 1, REG, Retention::PLAIN, 7),
        purge(20, 1, 2, PurgeItem::Commit(10)),
    ];
    let h = held(3, cs);
    let o = evaluate(&h);
    assert_eq!(o.fates[&(10, 0)], Fate::Leftover(LeftoverWhy::Purged));
    assert_eq!(read(&h, REG), Read::Absent);
    assert_eq!(o.forbidden.len(), 1);
    let h2 = act(&h, &o, None);
    assert!(evaluate(&h2).forbidden.is_empty());
    assert_eq!(read(&h2, REG), Read::Absent);
}

// spec/commits.md §5 (Purge), spec/permissions.md §7: an author may not purge an `admin` delta
#[test]
fn purge_without_the_right_drops_nothing_spec_commits_5() {
    let cs = vec![
        edge(5, OWNER, 0, 1, Some(Role::Write), None),
        reg(10, 1, 1, REG, Retention::PLAIN.with_by(PurgeBy::Admin), 7),
        purge(20, 1, 2, PurgeItem::Commit(10)),
    ];
    let h = held(3, cs);
    assert_eq!(read(&h, REG), Read::Reg(7));
    assert!(evaluate(&h).purged.is_empty());
}

// spec/commits.md §5 (Who and how long): `nobody` has no holder
#[test]
fn nobody_delta_stays_spec_commits_5() {
    let r = Retention { by: PurgeBy::Nobody, least_abs: Some(FOREVER), ..Retention::PLAIN };
    let h = held(3, vec![reg(10, OWNER, 1, REG, r, 7), purge(20, OWNER, 2, PurgeItem::Aspect { thing: T, aspect: REG })]);
    assert_eq!(fate(&h, 10), Fate::Keep(KeepWhy::AtLeast));
    assert_eq!(read(&h, REG), Read::Reg(7));
}

// spec/commits.md §5 (Purge), spec/crdt.md §4.7 (Copies)
#[test]
fn snapshot_copy_of_a_purged_value_is_a_leftover_spec_commits_5() {
    let cs = vec![
        reg(10, OWNER, 1, REG, Retention::PLAIN, 7),
        snap(15, OWNER, 2, REG, Retention::WRITER, vec![set(1, 10, 7)]),
        purge(20, OWNER, 3, PurgeItem::Commit(10)),
    ];
    let h = held(4, cs);
    let o = evaluate(&h);
    assert_eq!(o.fates[&(10, 0)], Fate::Leftover(LeftoverWhy::Purged));
    assert_eq!(o.fates[&(15, 0)], Fate::Leftover(LeftoverWhy::Copy));
    assert_eq!(o.forbidden.len(), 2);
    assert!(evaluate(&act(&h, &o, None)).forbidden.is_empty());
}

// spec/commits.md §5 (Keep at most): 0 after replaced, no live write: bound at the first death
#[test]
fn keep_at_most_zero_drops_after_first_death_spec_commits_5() {
    let zero = Retention { most_zero: true, ..Retention::WRITER };
    let cs = vec![reg(10, OWNER, 1, REG, zero, 1), reg(11, OWNER, 2, REG, Retention::PLAIN, 2)];
    assert_eq!(fate(&held(1, cs.clone()), 10), Fate::Keep(KeepWhy::Plain));
    let none = DropWhy::AtMost { carrier: false };
    assert_eq!(fate(&held(2, cs), 10), Fate::MustDrop(none));
}

// spec/commits.md §5 (Keep at most, Carrier): live writes stay in the state
#[test]
fn keep_at_most_with_live_write_keeps_it_in_state_spec_commits_5() {
    let r = Retention { most_abs: Some(at(2)), ..Retention::PLAIN };
    let h = held(4, vec![reg(10, OWNER, 1, REG, r, 1)]);
    let o = evaluate(&h);
    assert_eq!(o.fates[&(10, 0)], Fate::MustDrop(DropWhy::AtMost { carrier: true }));
    let h2 = act(&h, &o, None);
    assert_eq!(h2.commits[0].parts[0].body, Body::Dropped);
    assert_eq!(h2.own_state.len(), 1);
    assert_eq!(read(&h2, REG), Read::Reg(1));
}

// spec/commits.md §5 (Keep at least, Between the bounds)
#[test]
fn keep_at_least_blocks_compaction_spec_commits_5() {
    let r = Retention { least_rel: Some(5 * HOUR), ..Retention::PLAIN };
    let cs = vec![
        reg(10, OWNER, 1, REG, r, 1),
        reg(11, OWNER, 2, REG, Retention::PLAIN, 2),
        snap(12, OWNER, 3, REG, Retention::WRITER, vec![set(2, 11, 2)]),
    ];
    assert_eq!(fate(&held(4, cs.clone()), 10), Fate::Keep(KeepWhy::AtLeast));
    assert_eq!(fate(&held(9, cs), 10), Fate::MayDrop(DropWhy::Covered { by: 12 }));
}

// spec/commits.md §5 (Between the bounds): the covering snapshot's commit must hold the right
#[test]
fn covering_snapshot_needs_the_right_spec_commits_5() {
    let admin = Retention::PLAIN.with_by(PurgeBy::Admin);
    let base = vec![edge(5, OWNER, 0, 1, Some(Role::Write), None), reg(10, OWNER, 1, REG, admin, 1), reg(11, OWNER, 2, REG, Retention::PLAIN, 2)];
    let mut by_writer = base.clone();
    by_writer.push(snap(12, 1, 3, REG, Retention::WRITER, vec![set(2, 11, 2)]));
    assert_eq!(fate(&held(4, by_writer), 10), Fate::Keep(KeepWhy::Plain));
    let mut by_admin = base;
    by_admin.push(snap(12, OWNER, 3, REG, Retention::WRITER, vec![set(2, 11, 2)]));
    assert_eq!(fate(&held(4, by_admin), 10), Fate::MayDrop(DropWhy::Covered { by: 12 }));
}

// spec/commits.md §5 (Carrier only)
#[test]
fn carrier_only_snapshot_covers_nothing_spec_commits_5() {
    let carrier = Retention { least_rel: Some(HOUR), most_zero: true, ..Retention::WRITER };
    let cs = vec![reg(10, OWNER, 1, REG, Retention::PLAIN, 1), snap(12, OWNER, 3, REG, carrier, vec![set(1, 10, 1)])];
    assert_eq!(fate(&held(4, cs), 10), Fate::Keep(KeepWhy::Plain));
}

// spec/commits.md §6: at T every value-carrying write dies; the body is held as its leftover
#[test]
fn expired_delta_is_a_leftover_and_reads_absent_spec_commits_6() {
    let mut c = reg(10, OWNER, 1, REG, Retention::PLAIN, 7);
    c.expires = Some(at(2));
    let h = held(1, vec![c.clone()]);
    assert_eq!(read(&h, REG), Read::Reg(7));
    let h = held(3, vec![c]);
    let o = evaluate(&h);
    assert_eq!(o.fates[&(10, 0)], Fate::Leftover(LeftoverWhy::Expired));
    assert_eq!(read(&h, REG), Read::Absent);
    assert!(evaluate(&act(&h, &o, None)).forbidden.is_empty());
}

// spec/commits.md §6: a map entry's key copied by another delta's record goes with the entry's expiry
#[test]
fn expired_key_copy_in_another_body_is_stripped_spec_commits_6() {
    let e = Dot { commit: 10, ctr: 1 };
    let mut c = content(10, OWNER, 1, vec![part(MAP, Retention::PLAIN, vec![
        Write { stamp: st(1, 10, 1), op: Op::Create { key: Some(3) } },
        Write { stamp: st(1, 10, 1), op: Op::SetIn { entry: e, key: Some(3), value: Some(4) } },
    ])]);
    c.expires = Some(at(3));
    let w = content(11, OWNER, 2, vec![part(MAP, Retention::PLAIN, vec![Write { stamp: st(2, 11, 1), op: Op::SetIn { entry: e, key: Some(3), value: Some(5) } }])]);
    let h = held(4, vec![c, w]);
    let o = evaluate(&h);
    assert_eq!(o.fates[&(11, 0)], Fate::Leftover(LeftoverWhy::Copy));
    // the entry is not live; the other write inside it keeps the map present (spec/crdt.md §4.3)
    assert_eq!(read(&h, MAP), Read::Map(Default::default()));
    assert!(evaluate(&act(&h, &o, None)).forbidden.is_empty());
}

// spec/permissions.md §7 (Judgment): a leftover with no request dropping it counts as never received
#[test]
fn valueless_body_without_reason_is_never_received_spec_commits_5() {
    let mut c = reg(10, OWNER, 1, REG, Retention::PLAIN, 7);
    c.parts[0].body = Body::Held(Delta::Writes(vec![Write { stamp: st(1, 10, 1), op: Op::Set { value: None } }]));
    let h = held(2, vec![c]);
    assert_eq!(fate(&h, 10), Fate::NeverReceived);
    assert_eq!(read(&h, REG), Read::Absent);
}

// spec/commits.md §5 (Bodies and deaths): an invalid write under 0 after replaced dies at its fall
#[test]
fn invalid_write_dies_at_its_fall_spec_commits_5() {
    let zero = Retention { most_zero: true, ..Retention::WRITER };
    let cs = vec![edge(5, OWNER, 0, 1, Some(Role::Write), None), reg(10, 1, 1, REG, zero, 1), edge(20, OWNER, 3, 1, None, Some(vec![]))];
    let o = evaluate(&held(3, cs));
    assert_eq!(o.deaths[&(10, 0)], (Some(at(3)), Some(at(3))));
    assert_eq!(o.fates[&(10, 0)], Fate::MustDrop(DropWhy::AtMost { carrier: false }));
}

// spec/crdt.md §2.2 (Parking)
#[test]
fn far_future_commit_is_parked_spec_commits_4() {
    let h = held(3, vec![reg(10, OWNER, 5, REG, Retention::PLAIN, 7)]);
    let o = evaluate(&h);
    assert!(o.parked.contains(&10));
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Pending));
    assert_eq!(read(&h, REG), Read::Absent);
}

// spec/commits.md §5 (Keep at most, live write), spec/crdt.md §4.6 (Seq elements): an invalid
// creation's hidden anchor is a live write, so dropping its body at its fall keeps it in the state
#[test]
fn invalid_text_body_dropped_at_its_fall_keeps_its_anchors_spec_commits_5() {
    use held_model::gen::TEXT;
    let zero = Retention { most_zero: true, ..Retention::WRITER };
    let a = Dot { commit: 10, ctr: 1 };
    let cs = vec![
        edge(5, OWNER, 0, 1, Some(Role::Write), None),
        content(10, 1, 1, vec![part(TEXT, zero, vec![Write { stamp: st(1, 10, 1), op: Op::Insert { anchor: None, ch: Some(1) } }])]),
        content(11, OWNER, 2, vec![part(TEXT, Retention::PLAIN, vec![Write { stamp: st(2, 11, 1), op: Op::Insert { anchor: Some(a), ch: Some(2) } }])]),
        edge(20, OWNER, 3, 1, None, Some(vec![])),
    ];
    let h = held(5, cs);
    let o = evaluate(&h);
    assert_eq!(o.fates[&(10, 0)], Fate::MustDrop(DropWhy::AtMost { carrier: true }));
    let h2 = act(&h, &o, None);
    assert_eq!(read(&h2, TEXT), Read::Text(vec![2]));
}

// spec/commits.md §5 (Dropping a body): a body held as its leftover only for a copy it carries
// keeps its keep bounds; it drops at keep at most like a whole one
#[test]
fn copy_leftover_drops_at_its_bound_spec_commits_5() {
    let r = Retention { most_abs: Some(at(3)), ..Retention::WRITER };
    let cs = vec![
        reg(10, OWNER, 1, REG, Retention::PLAIN, 7),
        snap(15, OWNER, 2, REG, r, vec![set(1, 10, 7)]),
        purge(20, OWNER, 2, PurgeItem::Commit(10)),
    ];
    assert_eq!(fate(&held(2, cs.clone()), 15), Fate::Leftover(LeftoverWhy::Copy));
    assert!(matches!(fate(&held(3, cs), 15), Fate::MustDrop(DropWhy::AtMost { .. })));
}

// spec/permissions.md §7: a body stripped for a purge that no longer stands counts as never
// received; its stripped copy no longer joins
#[test]
fn stripped_copy_of_a_fallen_purge_is_never_received_spec_permissions_7() {
    let mut s = snap(15, OWNER, 2, REG, Retention::WRITER, vec![Write { stamp: st(1, 10, 1), op: Op::Set { value: None } }]);
    s.parts[0].stripped.insert(10);
    let h = held(3, vec![missing(reg(10, OWNER, 1, REG, Retention::PLAIN, 7), 0), s]);
    assert_eq!(fate(&h, 15), Fate::NeverReceived);
    assert_eq!(read(&h, REG), Read::Absent);
    assert_eq!(act(&h, &evaluate(&h), None).commits[1].parts[0].body, Body::Missing);
}
