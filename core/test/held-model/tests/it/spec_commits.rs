//! spec/commits.md §4 (apply), §5 (retention, purge), §6 (expiry).
use crate::util::*;
use held_model::gen::{MAP, REG};
use held_model::*;

const OTHER: Aspect = Aspect::reg(5);

fn two_parts(expires: Option<u64>) -> Commit {
    let mut c = content(10, FIRST_ADMIN, 1, vec![part(REG, Retention::PLAIN, vec![set(1, 10, 7)]), part(OTHER, Retention::PLAIN, vec![set(1, 10, 8)])]);
    c.expires = expires;
    c
}

// spec/commits.md §4 (Apply): nothing waits for a part; a missing delta is absent
#[test]
fn missing_part_is_absent_and_the_commit_applies_spec_commits_4() {
    let h = held(2, vec![missing(two_parts(None), 1)]);
    let o = evaluate(&h);
    assert!(o.applied.contains(&10));
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Plain));
    assert_eq!(read(&h, REG), Read::Reg(7));
    assert_eq!(read(&h, OTHER), Read::Absent);
}

// spec/commits.md §4 (Pending): a commit with no part held applies as its header alone
#[test]
fn commit_with_no_part_held_applies_as_its_header_spec_commits_4() {
    let h = held(2, vec![missing(missing(two_parts(None), 0), 1)]);
    assert!(evaluate(&h).applied.contains(&10));
    assert_eq!(read(&h, REG), Read::Absent);
}

// spec/commits.md §4, spec/permissions.md §5.2: a missing delta of an applied commit is judged all
// the same (its validity decides its fall and what a late copy gives)
#[test]
fn missing_part_of_lowered_author_is_judged_spec_commits_4() {
    let cs = vec![
        edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None),
        missing(reg(10, 1, 1, REG, Retention::PLAIN, 7), 0),
        edge(20, FIRST_ADMIN, 2, 1, None, Some(vec![])),
    ];
    let o = evaluate(&held(3, cs));
    assert!(o.applied.contains(&10));
    assert_eq!(o.valid[&(10, 0)], false);
}

// spec/commits.md §5 (Purge)
#[test]
fn author_purge_leaves_a_leftover_and_no_value_spec_commits_5() {
    let cs = vec![
        edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None),
        reg(10, 1, 1, REG, Retention::PLAIN, 7),
        purge(20, 1, 2, PurgeItem::Commit { commit: 10, thing: T, aspect: REG }),
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

// spec/commits.md §5 (Purge), spec/wire.md §4: a request by commit names that commit's delta on
// one aspect, not its other deltas
#[test]
fn purge_by_commit_names_one_aspect_spec_commits_5() {
    let h = held(3, vec![two_parts(None), purge(20, FIRST_ADMIN, 2, PurgeItem::Commit { commit: 10, thing: T, aspect: REG })]);
    assert_eq!(read(&h, REG), Read::Absent);
    assert_eq!(read(&h, OTHER), Read::Reg(8));
}

// spec/commits.md §5 (Purge), spec/permissions.md §6: an author may not purge an `admin` delta
#[test]
fn purge_without_the_right_drops_nothing_spec_commits_5() {
    let cs = vec![
        edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None),
        reg(10, 1, 1, REG, Retention::PLAIN.with_by(PurgeBy::Admin), 7),
        purge(20, 1, 2, PurgeItem::Commit { commit: 10, thing: T, aspect: REG }),
    ];
    let h = held(3, cs);
    assert_eq!(read(&h, REG), Read::Reg(7));
    assert!(evaluate(&h).purged.is_empty());
}

// spec/commits.md §5 (Who and how long): `nobody` has no holder
#[test]
fn nobody_delta_stays_spec_commits_5() {
    let h = held(3, vec![reg(10, FIRST_ADMIN, 1, REG, Retention::FIXED, 7), purge(20, FIRST_ADMIN, 2, PurgeItem::Aspect { thing: T, aspect: REG })]);
    assert_eq!(fate(&h, 10), Fate::Keep(KeepWhy::Until));
    assert_eq!(read(&h, REG), Read::Reg(7));
}

// spec/commits.md §5 (Purge), spec/crdt.md §4.7 (Copies)
#[test]
fn snapshot_copy_of_a_purged_value_is_a_leftover_spec_commits_5() {
    let cs = vec![
        reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 7),
        snap(15, FIRST_ADMIN, 2, REG, Retention::WRITER, vec![set(1, 10, 7)]),
        purge(20, FIRST_ADMIN, 3, PurgeItem::Commit { commit: 10, thing: T, aspect: REG }),
    ];
    let h = held(4, cs);
    let o = evaluate(&h);
    assert_eq!(o.fates[&(10, 0)], Fate::Leftover(LeftoverWhy::Purged));
    assert_eq!(o.fates[&(15, 0)], Fate::Leftover(LeftoverWhy::Copy));
    assert_eq!(o.forbidden.len(), 2);
    assert!(evaluate(&act(&h, &o, None)).forbidden.is_empty());
}

// spec/commits.md §5 (history purge-on-replace): gone once replaced. A writer holding the body that applies
// the kill owes a covering snapshot in that transaction; once a valid cover with the right is
// held the body must go, at every node; a node without the right owes nothing and keeps it
#[test]
fn none_body_is_owed_a_cover_at_the_kill_and_drops_covered_spec_commits_5() {
    let cs = vec![reg(10, FIRST_ADMIN, 1, REG, Retention::PURGE_ON_REPLACE, 1), reg(11, FIRST_ADMIN, 2, REG, Retention::PLAIN, 2)];
    let o = evaluate(&held(1, cs[..1].to_vec()));
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Plain));
    assert!(o.owed.is_empty() && o.replaced.is_empty());
    let h = held(2, cs.clone());
    let o = evaluate(&h);
    assert!(o.replaced.contains(&(10, 0)));
    assert_eq!(o.owed, [(10, 0)].into_iter().collect(), "the writer owes the cover");
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Plain), "until it is covered");
    let s = cover(&h, &o, T, REG, 12, ts(2) + 1);
    assert_eq!(s.parts[0].retention, Retention::WRITER, "it carries no purge-on-replace write live: convenient");
    let mut cs2 = cs.clone();
    cs2.push(s);
    let h2 = held(2, cs2.clone());
    let o2 = evaluate(&h2);
    assert_eq!(o2.fates[&(10, 0)], Fate::MustDrop(DropWhy::Covered { by: 12 }));
    assert!(o2.owed.is_empty());
    let h3 = act(&h2, &o2, None);
    assert_eq!(h3.commits[0].parts[0].body, Body::Dropped(12));
    assert_eq!(read(&h3, REG), Read::Reg(2));
    // a reader (node 3 has no role on T) owes nothing and drops only once the cover arrives
    let mut reader = held(2, cs);
    reader.me = 3;
    let o = evaluate(&reader);
    assert!(o.owed.is_empty());
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Plain));
    reader.commits = cs2;
    assert_eq!(fate(&reader, 10), Fate::MustDrop(DropWhy::Covered { by: 12 }));
}

// spec/commits.md §5 (Purge): a commit carrying a purge request keeps its blobs until wall(ts) +
// ROLE_KEEP, whatever its history mode (seed 9450000)
#[test]
fn purge_request_floor_beats_none_spec_commits_5() {
    let mut a = reg(10, FIRST_ADMIN, 1, REG, Retention::PURGE_ON_REPLACE, 1);
    a.purge = vec![PurgeItem::Commit { commit: 3, thing: T, aspect: OTHER }];
    let cs = vec![a, reg(11, FIRST_ADMIN, 2, REG, Retention::PLAIN, 2), snap(12, FIRST_ADMIN, 3, REG, Retention::PURGE_ON_REPLACE, vec![set(2, 11, 2)])];
    let o = evaluate(&held(3, cs.clone()));
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Until));
    assert!(o.owed.is_empty());
    assert!(o.deadlines.contains(&(at(1) + ROLE_KEEP)));
    assert_eq!(fate(&held(1 + ROLE_KEEP / HOUR, cs), 10), Fate::MustDrop(DropWhy::Covered { by: 12 }));
}

// spec/commits.md §5 (history purge-on-replace): a body partly replaced (its entry creation live, its value
// dead) is covered by the snapshot of the whole state, which carries the live creation
#[test]
fn none_body_partly_replaced_is_covered_by_the_state_snapshot_spec_commits_5() {
    let e = st(1, 10, 1);
    let mk = Write { stamp: e, op: Op::Create { key: Some(1) } };
    let put = |h: u64, c: CommitId, v: Val| Write { stamp: st(h, c, 1), op: Op::SetIn { entry: e.dot, key: Some(1), value: Some(v) } };
    let a = content(10, FIRST_ADMIN, 1, vec![part(MAP, Retention::PURGE_ON_REPLACE, vec![mk, put(1, 10, 5)])]);
    let b = content(11, FIRST_ADMIN, 2, vec![part(MAP, Retention::PLAIN, vec![put(2, 11, 6)])]);
    let h = held(2, vec![a, b]);
    let o = evaluate(&h);
    assert_eq!(o.owed, [(10, 0)].into_iter().collect());
    let mut h2 = h.clone();
    h2.commits.push(cover(&h, &o, T, MAP, 12, ts(2) + 1));
    let o2 = evaluate(&h2);
    assert_eq!(o2.fates[&(10, 0)], Fate::MustDrop(DropWhy::Covered { by: 12 }));
    let h3 = act(&h2, &o2, None);
    assert_eq!(read(&h3, MAP), Read::Map([(1, 6)].into_iter().collect()));
    assert_eq!(read(&h3, MAP), read(&h, MAP));
}

// spec/commits.md §5 (Covered): on an aspect mixing modes the state snapshot purges on replace;
// it covers the purge-on-replace body but not a live body kept D after replaced, whose history it
// could not keep. Once that body's write is dead, it is covered like any.
#[test]
fn purge_on_replace_snapshot_leaves_a_live_kept_body_spec_commits_5() {
    let kept = Retention::WRITER.after(5 * HOUR);
    let mk = |c: CommitId, h: u64, k: Val, v: Val| content(c, FIRST_ADMIN, h, vec![part(MAP, if c == 10 { kept } else { Retention::PURGE_ON_REPLACE }, vec![
        Write { stamp: st(h, c, 1), op: Op::Create { key: Some(k) } },
        Write { stamp: st(h, c, 1), op: Op::SetIn { entry: st(h, c, 1).dot, key: Some(k), value: Some(v) } },
    ])]);
    let h = held(3, vec![mk(10, 1, 1, 5), mk(11, 2, 2, 6)]);
    let o = evaluate(&h);
    let mut h2 = h.clone();
    h2.commits.push(cover(&h, &o, T, MAP, 12, ts(2) + 1));
    assert_eq!(h2.commits[2].parts[0].retention, Retention::PURGE_ON_REPLACE);
    let o2 = evaluate(&h2);
    assert_eq!(o2.fates[&(10, 0)], Fate::Keep(KeepWhy::Plain), "kept body, live: not covered");
    assert_eq!(o2.fates[&(11, 0)], Fate::MustDrop(DropWhy::Covered { by: 12 }));
    // a reset of the map kills the kept body's writes: past its bound any snapshot covers it
    let mut h3 = act(&h2, &o2, None);
    h3.commits.push(content(13, FIRST_ADMIN, 3, vec![part(MAP, kept, vec![reset(3, 13)])]));
    h3.now = at(4);
    let o3 = evaluate(&h3);
    let mut h4 = h3.clone();
    h4.commits.push(cover(&h3, &o3, T, MAP, 14, ts(4)));
    h4.now = at(9);
    assert!(matches!(evaluate(&h4).fates[&(10, 0)], Fate::MayDrop(DropWhy::Covered { .. })), "dead past its bound: covered");
}

// spec/commits.md §5 (history purge-on-replace): a snapshot carrying a purge-on-replace write live is purge-on-replace itself,
// so its copy goes when that write is replaced
#[test]
fn snapshot_of_a_none_write_is_none_spec_commits_5() {
    let cs = vec![reg(10, FIRST_ADMIN, 1, REG, Retention::PURGE_ON_REPLACE, 1), reg(11, FIRST_ADMIN, 1, OTHER, Retention::PLAIN, 1)];
    assert_eq!(snapshot_retention(&cs, T, REG, &[set(1, 10, 1)]), Retention::PURGE_ON_REPLACE);
    assert_eq!(snapshot_retention(&cs, T, OTHER, &[set(1, 11, 1)]), Retention::WRITER);
    // the mode is the carried write's own delta's, not another delta of its commit
    let two = vec![content(10, FIRST_ADMIN, 1, vec![part(REG, Retention::PURGE_ON_REPLACE, vec![set(1, 10, 1)]), part(OTHER, Retention::PLAIN, vec![set(1, 10, 2)])])];
    assert_eq!(snapshot_retention(&two, T, OTHER, &[set(1, 10, 2)]), Retention::WRITER);
}

// spec/sync.md §7 (covered-equal): of two snapshots at one `ts` covering each other, only the lower
// commit ID covers: the higher goes, the lower stays
#[test]
fn covered_equal_snapshots_lower_id_covers_spec_sync_7() {
    let cs = vec![
        reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 1),
        snap(12, FIRST_ADMIN, 2, REG, Retention::WRITER, vec![set(1, 10, 1)]),
        snap(13, FIRST_ADMIN, 2, REG, Retention::WRITER, vec![set(1, 10, 1)]),
    ];
    let o = evaluate(&held(3, cs));
    assert_eq!(o.fates[&(13, 0)], Fate::MayDrop(DropWhy::Covered { by: 12 }));
    assert_eq!(o.fates[&(12, 0)], Fate::Keep(KeepWhy::Plain));
}

// spec/commits.md §5 (keep-at-least, absolute T): never compacted before T, convenient after; the
// replaced write shows in history() until T
#[test]
fn keep_until_blocks_compaction_spec_commits_5() {
    let cs = vec![
        reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN.until(at(5)), 1),
        reg(11, FIRST_ADMIN, 2, REG, Retention::PLAIN, 2),
        snap(12, FIRST_ADMIN, 3, REG, Retention::WRITER, vec![set(2, 11, 2)]),
    ];
    let o = evaluate(&held(4, cs.clone()));
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Until));
    assert!(o.deadlines.contains(&at(5)));
    assert_eq!(o.history[&(T, REG)], [(st(1, 10, 1), 10)].into_iter().collect());
    let o = evaluate(&held(5, cs));
    assert_eq!(o.fates[&(10, 0)], Fate::MayDrop(DropWhy::Covered { by: 12 }));
    assert!(o.history.is_empty());
}

// spec/commits.md §5 (keep-at-least, D after replaced): no node drops the body earlier than D
// after the earliest valid replacing write it holds, by its signed ts, and history() shows the
// replaced write until then; readers and writers holding the same data judge alike; a body
// nothing held supersedes is past the bound
#[test]
fn keep_after_replaced_limits_the_compactor_spec_commits_5() {
    let r = Retention::PLAIN.after(5 * HOUR);
    let cs = vec![
        reg(10, FIRST_ADMIN, 1, REG, r, 1),
        reg(11, FIRST_ADMIN, 4, REG, Retention::PLAIN, 2),
        reg(13, FIRST_ADMIN, 2, REG, Retention::PLAIN, 3),
        snap(12, FIRST_ADMIN, 5, REG, Retention::WRITER, vec![set(4, 11, 2)]),
    ];
    let o = evaluate(&held(6, cs.clone()));
    assert_eq!(o.replaced_at[&(10, 0)], Some(at(2)), "the earliest replacing write held");
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Until));
    assert_eq!(o.fates[&(13, 0)], Fate::MayDrop(DropWhy::Covered { by: 12 }), "convenient");
    assert_eq!(o.history[&(T, REG)], [(st(1, 10, 1), 10)].into_iter().collect());
    assert!(o.deadlines.contains(&at(7)));
    let o = evaluate(&held(7, cs.clone()));
    assert_eq!(o.fates[&(10, 0)], Fate::MayDrop(DropWhy::Covered { by: 12 }));
    assert!(o.history.is_empty());
    // without the earlier replacer held, the bound counts from the later one
    let mut fewer = cs.clone();
    fewer.remove(2);
    assert_eq!(evaluate(&held(7, fewer)).fates[&(10, 0)], Fate::Keep(KeepWhy::Until));
    // a reader (node 3 holds no right) keeps it as a writer does, showing the same history
    let mut reader = held(6, cs);
    reader.me = 3;
    let o = evaluate(&reader);
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Until));
    assert_eq!(o.history[&(T, REG)], [(st(1, 10, 1), 10)].into_iter().collect());
}

// spec/commits.md §5 (Between the bounds): the covering snapshot's commit must hold the right
#[test]
fn covering_snapshot_needs_the_right_spec_commits_5() {
    let admin = Retention::PLAIN.with_by(PurgeBy::Admin);
    let base = vec![edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None), reg(10, FIRST_ADMIN, 1, REG, admin, 1), reg(11, FIRST_ADMIN, 2, REG, Retention::PLAIN, 2)];
    let mut by_writer = base.clone();
    by_writer.push(snap(12, 1, 3, REG, Retention::WRITER, vec![set(2, 11, 2)]));
    assert_eq!(fate(&held(4, by_writer), 10), Fate::Keep(KeepWhy::Plain));
    let mut by_admin = base;
    by_admin.push(snap(12, FIRST_ADMIN, 3, REG, Retention::WRITER, vec![set(2, 11, 2)]));
    assert_eq!(fate(&held(4, by_admin), 10), Fate::MayDrop(DropWhy::Covered { by: 12 }));
}

// spec/commits.md §6: at T every value-carrying write dies; the body is held as its leftover
#[test]
fn expired_delta_is_a_leftover_and_reads_absent_spec_commits_6() {
    let mut c = reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 7);
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
    let mut c = content(10, FIRST_ADMIN, 1, vec![part(MAP, Retention::PLAIN, vec![
        Write { stamp: st(1, 10, 1), op: Op::Create { key: Some(3) } },
        Write { stamp: st(1, 10, 1), op: Op::SetIn { entry: e, key: Some(3), value: Some(4) } },
    ])]);
    c.expires = Some(at(3));
    let w = content(11, FIRST_ADMIN, 2, vec![part(MAP, Retention::PLAIN, vec![Write { stamp: st(2, 11, 1), op: Op::SetIn { entry: e, key: Some(3), value: Some(5) } }])]);
    let h = held(4, vec![c, w]);
    let o = evaluate(&h);
    assert_eq!(o.fates[&(11, 0)], Fate::Leftover(LeftoverWhy::Copy));
    // the entry is not live; the other write inside it keeps the map present (spec/crdt.md §4.3)
    assert_eq!(read(&h, MAP), Read::Map(Default::default()));
    assert!(evaluate(&act(&h, &o, None)).forbidden.is_empty());
}

// spec/permissions.md §6 (Judgment): a leftover with no request dropping it counts as never received
#[test]
fn valueless_body_without_reason_is_never_received_spec_commits_5() {
    let mut c = reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 7);
    c.parts[0].body = Body::Held(Delta::Writes(vec![Write { stamp: st(1, 10, 1), op: Op::Set { value: None } }]));
    let h = held(2, vec![c]);
    assert_eq!(fate(&h, 10), Fate::NeverReceived);
    assert_eq!(read(&h, REG), Read::Absent);
}

// spec/crdt.md §4.8 (Revival), spec/commits.md §5: an invalid purge-on-replace body has no dead write and
// nothing owes it a cover; it stays until a snapshot covers it (one carrying a later reset)
#[test]
fn invalid_none_body_stays_until_covered_spec_commits_5() {
    let cs = vec![edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None), reg(10, 1, 1, REG, Retention::PURGE_ON_REPLACE, 1), edge(20, FIRST_ADMIN, 3, 1, None, Some(vec![]))];
    let h = held(3, cs.clone());
    let o = evaluate(&h);
    assert_eq!(o.valid[&(10, 0)], false);
    assert!(o.replaced.is_empty() && o.owed.is_empty());
    let mut h2 = h.clone();
    h2.commits.push(cover(&h, &o, T, REG, 12, ts(3)));
    assert_eq!(fate(&h2, 10), Fate::Keep(KeepWhy::Plain), "the state's snapshot carries nothing over it");
    let mut cs3 = cs;
    cs3.push(content(11, FIRST_ADMIN, 2, vec![part(REG, Retention::PLAIN, vec![reset(2, 11)])]));
    let h3 = held(3, cs3);
    let o3 = evaluate(&h3);
    let mut h4 = h3.clone();
    h4.commits.push(cover(&h3, &o3, T, REG, 12, ts(3)));
    assert_eq!(fate(&h4, 10), Fate::MustDrop(DropWhy::Covered { by: 12 }));
}

// spec/crdt.md §2.2 (Parking)
#[test]
fn far_future_commit_is_parked_spec_commits_4() {
    let h = held(3, vec![reg(10, FIRST_ADMIN, 5, REG, Retention::PLAIN, 7)]);
    let o = evaluate(&h);
    assert!(o.parked.contains(&10));
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Pending));
    assert_eq!(read(&h, REG), Read::Absent);
}

// spec/crdt.md §4.6 (Seq elements), spec/commits.md §5: an invalid purge-on-replace text body whose
// element others anchor on stays held (the state's snapshot carries only its hidden anchor, so
// it covers nothing of it); its anchors stay in the state
#[test]
fn invalid_none_text_body_stays_with_its_anchors_spec_commits_5() {
    use held_model::gen::TEXT;
    let a = Dot { commit: 10, ctr: 1 };
    let cs = vec![
        edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None),
        content(10, 1, 1, vec![part(TEXT, Retention::PURGE_ON_REPLACE, vec![Write { stamp: st(1, 10, 1), op: Op::Insert { anchor: None, ch: Some(1) } }])]),
        content(11, FIRST_ADMIN, 2, vec![part(TEXT, Retention::PLAIN, vec![Write { stamp: st(2, 11, 1), op: Op::Insert { anchor: Some(a), ch: Some(2) } }])]),
        edge(20, FIRST_ADMIN, 3, 1, None, Some(vec![])),
    ];
    let h = held(5, cs);
    let o = evaluate(&h);
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Plain));
    assert!(o.owed.is_empty());
    let mut h2 = h.clone();
    h2.commits.push(cover(&h, &o, T, TEXT, 12, ts(5)));
    assert_eq!(fate(&h2, 10), Fate::Keep(KeepWhy::Plain));
    assert_eq!(read(&h2, TEXT), Read::Text(vec![2]));
}

// spec/commits.md §5 (Dropping a body): a body held as its leftover only for a copy it carries is
// a body like a whole one: judged stripped, a later snapshot covers it
#[test]
fn copy_leftover_drops_as_covered_spec_commits_5() {
    let cs = vec![
        reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 7),
        snap(15, FIRST_ADMIN, 2, REG, Retention::WRITER, vec![set(1, 10, 7)]),
        purge(20, FIRST_ADMIN, 2, PurgeItem::Commit { commit: 10, thing: T, aspect: REG }),
    ];
    assert_eq!(fate(&held(2, cs.clone()), 15), Fate::Leftover(LeftoverWhy::Copy));
    let h = held(3, cs);
    let mut h2 = h.clone();
    h2.commits.push(cover(&h, &evaluate(&h), T, REG, 16, ts(3)));
    assert_eq!(fate(&h2, 15), Fate::MayDrop(DropWhy::Covered { by: 16 }));
}

// spec/permissions.md §6: a body stripped for a purge that no longer stands counts as never
// received; its stripped copy no longer joins
#[test]
fn stripped_copy_of_a_fallen_purge_is_never_received_spec_permissions_6() {
    let mut s = snap(15, FIRST_ADMIN, 2, REG, Retention::WRITER, vec![Write { stamp: st(1, 10, 1), op: Op::Set { value: None } }]);
    s.parts[0].stripped.insert(10);
    let h = held(3, vec![missing(reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 7), 0), s]);
    assert_eq!(fate(&h, 15), Fate::NeverReceived);
    assert_eq!(read(&h, REG), Read::Absent);
    assert_eq!(act(&h, &evaluate(&h), None).commits[1].parts[0].body, Body::Missing);
}

// spec/commits.md §5 (Bodies and deaths): a snapshot is replaced at the latest death among the
// writes no later snapshot carries. 12 carries entries 1 (10) and 2 (11); 13 overwrites 1 at 3;
// 14 carries 2 live; 15 overwrites 2 at 5. 14 keeps 2's history, so 12 is replaced at 3, 14 at 5.
#[test]
fn snapshot_replaced_at_last_death_no_later_snapshot_carries_spec_commits_5() {
    let r = Retention::WRITER.after(5 * HOUR);
    let mk = |h: u64, c: CommitId, k: Val, v: Val| vec![Write { stamp: st(h, c, 1), op: Op::Create { key: Some(k) } }, Write { stamp: st(h, c, 1), op: Op::SetIn { entry: st(h, c, 1).dot, key: Some(k), value: Some(v) } }];
    let put = |h: u64, c: CommitId, e: CommitId, k: Val, v: Val| Write { stamp: st(h, c, 1), op: Op::SetIn { entry: st(1, e, 1).dot, key: Some(k), value: Some(v) } };
    let (one, two) = (mk(1, 10, 1, 5), mk(1, 11, 2, 6));
    let cs = vec![
        content(10, FIRST_ADMIN, 1, vec![part(MAP, r, one.clone())]),
        content(11, FIRST_ADMIN, 1, vec![part(MAP, r, two.clone())]),
        snap(12, FIRST_ADMIN, 2, MAP, r, [one.clone(), two.clone()].concat()),
        content(13, FIRST_ADMIN, 3, vec![part(MAP, r, vec![put(3, 13, 10, 1, 7)])]),
        snap(14, FIRST_ADMIN, 4, MAP, r, [vec![one[0].clone(), put(3, 13, 10, 1, 7)], two].concat()),
        content(15, FIRST_ADMIN, 5, vec![part(MAP, r, vec![put(5, 15, 11, 2, 8)])]),
    ];
    let o = evaluate(&held(6, cs));
    assert_eq!((o.replaced_at[&(12, 0)], o.replaced_at[&(14, 0)]), (Some(at(3)), Some(at(5))));
}

// spec/commits.md §5 Fixed retention: a snapshot carrying a keep-for-D write live keeps that D,
// counted from the latest of its carried writes' replacements, so a write compacted while live
// keeps its history for D after it is replaced
#[test]
fn snapshot_keeps_the_longest_d_of_what_it_carries_spec_commits_5() {
    let r = Retention::PLAIN.after(5 * HOUR);
    let cs = vec![reg(10, FIRST_ADMIN, 1, REG, r, 1), reg(11, FIRST_ADMIN, 1, OTHER, Retention::PLAIN, 1)];
    assert_eq!(snapshot_retention(&cs, T, REG, &[set(1, 10, 1)]), Retention::WRITER.after(5 * HOUR));
    assert_eq!(snapshot_retention(&cs, T, OTHER, &[set(1, 11, 1)]), Retention::WRITER);
    // 12 carries 10's write live; 13 replaces it at 3; 14 covers 12 and 10
    let cs = vec![
        reg(10, FIRST_ADMIN, 1, REG, r, 1),
        snap(12, FIRST_ADMIN, 2, REG, Retention::WRITER.after(5 * HOUR), vec![set(1, 10, 1)]),
        reg(13, FIRST_ADMIN, 3, REG, Retention::PLAIN, 2),
        snap(14, FIRST_ADMIN, 4, REG, Retention::WRITER, vec![set(3, 13, 2)]),
    ];
    let o = evaluate(&held(5, cs.clone()));
    assert_eq!(o.replaced_at[&(12, 0)], Some(at(3)));
    assert_eq!(o.fates[&(12, 0)], Fate::Keep(KeepWhy::Until), "the snapshot keeps the carried write's D");
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Until));
    assert_eq!(evaluate(&held(8, cs)).fates[&(12, 0)], Fate::MayDrop(DropWhy::Covered { by: 14 }));
}

// spec/commits.md §5 (Bodies and deaths): a later snapshot counts as carrying a write only if it
// keeps history at least as long. 12 (kept 5 h) carries entry 1 (10); 11 writes entry 2 purge on
// replace; 13 carries both, purging on replace itself; 14 overwrites 1 at 4. 13 keeps no history,
// so 12 is replaced at 4 and shows 1's history until 9.
#[test]
fn purge_on_replace_later_snapshot_carries_no_kept_history_spec_commits_5() {
    let r = Retention::WRITER.after(5 * HOUR);
    let mk = |h: u64, c: CommitId, k: Val, v: Val| vec![Write { stamp: st(h, c, 1), op: Op::Create { key: Some(k) } }, Write { stamp: st(h, c, 1), op: Op::SetIn { entry: st(h, c, 1).dot, key: Some(k), value: Some(v) } }];
    let put = |h: u64, c: CommitId, e: CommitId, k: Val, v: Val| Write { stamp: st(h, c, 1), op: Op::SetIn { entry: st(1, e, 1).dot, key: Some(k), value: Some(v) } };
    let (one, two) = (mk(1, 10, 1, 5), mk(2, 11, 2, 6));
    for later in [Retention::PURGE_ON_REPLACE, Retention::WRITER, Retention::WRITER.after(HOUR)] {
        let cs = vec![
            content(10, FIRST_ADMIN, 1, vec![part(MAP, r, one.clone())]),
            snap(12, FIRST_ADMIN, 1, MAP, r, one.clone()),
            content(11, FIRST_ADMIN, 2, vec![part(MAP, Retention::PURGE_ON_REPLACE, two.clone())]),
            snap(13, FIRST_ADMIN, 3, MAP, later, [one.clone(), two.clone()].concat()),
            content(14, FIRST_ADMIN, 4, vec![part(MAP, r, vec![put(4, 14, 10, 1, 7)])]),
        ];
        let o = evaluate(&held(6, cs));
        assert_eq!(o.replaced_at[&(12, 0)], Some(at(4)), "{later:?}");
        assert!(o.history.get(&(T, MAP)).is_some_and(|x| x.iter().any(|(s, c)| *c == 12 && s.dot.commit == 10)), "{later:?}");
    }
}
