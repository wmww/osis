//! spec/commits.md §4 (apply), §5 (retention, purge), §6 (expiry).
use crate::util::*;
use held_model::gen::{MAP, REG};
use held_model::*;

const OTHER: Aspect = Aspect::plain(5);

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
    assert_eq!(read(&h, REG), int(7));
    assert_eq!(read(&h, OTHER), None);
}

// spec/commits.md §4 (Pending): a commit with no part held applies as its header alone
#[test]
fn commit_with_no_part_held_applies_as_its_header_spec_commits_4() {
    let h = held(2, vec![missing(missing(two_parts(None), 0), 1)]);
    assert!(evaluate(&h).applied.contains(&10));
    assert_eq!(read(&h, REG), None);
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
    assert_eq!(read(&h, REG), None);
    assert_eq!(o.forbidden.len(), 1);
    let h2 = act(&h, &o, None);
    assert!(evaluate(&h2).forbidden.is_empty());
    assert_eq!(read(&h2, REG), None);
}

// spec/commits.md §5 (Purge), spec/wire.md §4: a request by commit names that commit's delta on
// one aspect, not its other deltas
#[test]
fn purge_by_commit_names_one_aspect_spec_commits_5() {
    let h = held(3, vec![two_parts(None), purge(20, FIRST_ADMIN, 2, PurgeItem::Commit { commit: 10, thing: T, aspect: REG })]);
    assert_eq!(read(&h, REG), None);
    assert_eq!(read(&h, OTHER), int(8));
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
    assert_eq!(read(&h, REG), int(7));
    assert!(evaluate(&h).purged.is_empty());
}

// spec/commits.md §5 (Who and how long): fixed retention (`nobody`) has no holder: a purge of the
// setting takes nothing, and it stays in force
#[test]
fn nobody_delta_stays_spec_commits_5() {
    let cs = vec![setting(5, 0, REG, KEPT), reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 7), reg(11, FIRST_ADMIN, 2, REG, Retention::PLAIN, 8), purge(20, FIRST_ADMIN, 3, PurgeItem::Aspect { thing: T, aspect: Aspect::RETENTION })];
    let o = evaluate(&held(4, cs));
    assert!(o.purged.is_empty());
    assert_eq!(o.fates[&(5, 0)], Fate::Keep(KeepWhy::Plain));
    assert_eq!(o.history[&(T, REG)], [(st(1, 10, 1), 10)].into_iter().collect());
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

// issues/thing-history.md (Purge on replace): gone once replaced under a setting saying so. A
// writer holding the body that applies the kill owes a covering snapshot in that transaction; once
// a valid cover with the right is held the body must go, at every node; a node without the right
// owes nothing and keeps it until such a cover comes
#[test]
fn none_body_is_owed_a_cover_at_the_kill_and_drops_covered_spec_commits_5() {
    let por = setting(5, 0, REG, Opt::Purge);
    let cs = vec![por.clone(), reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 1), reg(11, FIRST_ADMIN, 2, REG, Retention::PLAIN, 2)];
    let o = evaluate(&held(1, cs[..2].to_vec()));
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Plain));
    assert!(o.owed.is_empty() && o.replaced.is_empty());
    let h = held(2, cs.clone());
    let o = evaluate(&h);
    assert!(o.under_purge.contains(&(10, 0)));
    assert_eq!(o.owed, [(10, 0)].into_iter().collect(), "the writer owes the cover");
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Plain), "until it is covered");
    let s = cover(&h, &o, T, REG, 12, ts(2) + 1);
    assert_eq!(s.parts[0].retention, Retention::WRITER);
    let mut cs2 = cs.clone();
    cs2.push(s);
    let h2 = held(2, cs2.clone());
    let o2 = evaluate(&h2);
    assert_eq!(o2.fates[&(10, 0)], Fate::MustDrop(DropWhy::Covered { by: 12 }));
    assert!(o2.owed.is_empty());
    let h3 = act(&h2, &o2, None);
    assert_eq!(h3.commits[1].parts[0].body, Body::Dropped(12));
    assert_eq!(read(&h3, REG), int(2));
    // a reader (node 3 has no role on T) owes nothing and drops only once the cover arrives
    let mut reader = held(2, cs.clone());
    reader.me = 3;
    let o = evaluate(&reader);
    assert!(o.owed.is_empty());
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Plain));
    reader.commits = held(2, cs2).commits;
    assert_eq!(fate(&reader, 10), Fate::MustDrop(DropWhy::Covered { by: 12 }));
    // no setting held: nothing is promised, nothing owed
    let o = evaluate(&held(2, cs[1..].to_vec()));
    assert!(o.under_purge.is_empty() && o.owed.is_empty());
}

// spec/commits.md §5 (Purge): a commit carrying a purge request keeps its blobs until wall(ts) +
// ROLE_KEEP, whatever the setting says (seed 9450000)
#[test]
fn purge_request_floor_beats_none_spec_commits_5() {
    let mut a = reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 1);
    a.purge = vec![PurgeItem::Commit { commit: 3, thing: T, aspect: OTHER }];
    let cs = vec![setting(5, 0, REG, Opt::Purge), a, reg(11, FIRST_ADMIN, 2, REG, Retention::PLAIN, 2), snap(12, FIRST_ADMIN, 3, REG, Retention::WRITER, vec![set(2, 11, 2)])];
    let o = evaluate(&held(3, cs.clone()));
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Until));
    assert!(o.owed.is_empty());
    assert!(o.deadlines.contains(&(at(1) + ROLE_KEEP)));
    assert_eq!(fate(&held(1 + ROLE_KEEP / HOUR, cs), 10), Fate::MustDrop(DropWhy::Covered { by: 12 }));
}

// issues/thing-history.md (Purge on replace): a body partly replaced (its entry creation live, its
// value dead) is covered by the snapshot of the whole state, which carries the live creation
#[test]
fn none_body_partly_replaced_is_covered_by_the_state_snapshot_spec_commits_5() {
    let a = content(10, FIRST_ADMIN, 1, vec![part(MAP, Retention::PLAIN, new_entry(1, 10, 1, 5))]);
    let b = content(11, FIRST_ADMIN, 2, vec![part(MAP, Retention::PLAIN, vec![put(2, 11, 10, 1, 6)])]);
    let h = held(2, vec![setting(5, 0, MAP, Opt::Purge), a, b]);
    let o = evaluate(&h);
    assert_eq!(o.owed, [(10, 0)].into_iter().collect());
    let mut h2 = h.clone();
    h2.commits.push(cover(&h, &o, T, MAP, 12, ts(2) + 1));
    let o2 = evaluate(&h2);
    assert_eq!(o2.fates[&(10, 0)], Fate::MustDrop(DropWhy::Covered { by: 12 }));
    let h3 = act(&h2, &o2, None);
    assert_eq!(read(&h3, MAP), map(&[(1, 6)]));
    assert_eq!(read(&h3, MAP), read(&h, MAP));
}

// issues/thing-history.md (History): a snapshot is judged by the setting like any body: carrying
// a write live, then replaced under purge on replace, a right holder's cover drops it everywhere
#[test]
fn snapshot_under_purge_on_replace_drops_covered_spec_commits_5() {
    let cs = vec![
        setting(5, 0, REG, Opt::Purge),
        reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 1),
        snap(12, FIRST_ADMIN, 2, REG, Retention::WRITER, vec![set(1, 10, 1)]),
        reg(13, FIRST_ADMIN, 3, REG, Retention::PLAIN, 2),
    ];
    let h = held(3, cs);
    let o = evaluate(&h);
    assert!(o.under_purge.contains(&(12, 0)) && o.owed.contains(&(12, 0)));
    let mut h2 = h.clone();
    h2.commits.push(cover(&h, &o, T, REG, 14, ts(3) + 1));
    assert_eq!(fate(&h2, 12), Fate::MustDrop(DropWhy::Covered { by: 14 }));
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

// issues/thing-history.md (History, keep until T): never compacted before T, droppable after; the
// replaced write shows in history() until T
#[test]
fn keep_until_blocks_compaction_spec_commits_5() {
    let cs = vec![
        setting(5, 0, REG, keep_until(5)),
        reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 1),
        reg(11, FIRST_ADMIN, 2, REG, Retention::PLAIN, 2),
        snap(12, FIRST_ADMIN, 3, REG, Retention::WRITER, vec![set(2, 11, 2)]),
    ];
    let o = evaluate(&held(4, cs.clone()));
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Until));
    assert!(o.deadlines.contains(&at(5)));
    assert_eq!(o.history[&(T, REG)], [(st(1, 10, 1), 10)].into_iter().collect());
    assert_eq!(o.fates[&(11, 0)], Fate::Keep(KeepWhy::Plain), "live: read on its own, no cover drops it");
    let o = evaluate(&held(5, cs));
    assert_eq!(o.fates[&(10, 0)], Fate::MayDrop(DropWhy::Covered { by: 12 }));
    assert!(o.history.is_empty());
}

// issues/thing-history.md (History, keep D after replaced): no node drops a body earlier than D
// after the earliest valid replacing write it holds, by its signed ts, and history() shows the
// replaced write until then; readers and writers holding the same data judge alike
#[test]
fn keep_after_replaced_limits_the_compactor_spec_commits_5() {
    let r = Retention::PLAIN;
    let cs = vec![
        setting(5, 0, REG, keep_after(5)),
        reg(10, FIRST_ADMIN, 1, REG, r, 1),
        reg(11, FIRST_ADMIN, 4, REG, r, 2),
        reg(13, FIRST_ADMIN, 2, REG, r, 3),
        snap(12, FIRST_ADMIN, 5, REG, Retention::WRITER, vec![set(4, 11, 2)]),
    ];
    let o = evaluate(&held(6, cs.clone()));
    assert_eq!(o.replaced_at[&(10, 0)], Some(at(2)), "the earliest replacing write held");
    assert_eq!((o.fates[&(10, 0)], o.fates[&(13, 0)]), (Fate::Keep(KeepWhy::Until), Fate::Keep(KeepWhy::Until)));
    assert_eq!(o.history[&(T, REG)], [(st(1, 10, 1), 10), (st(2, 13, 1), 13)].into_iter().collect());
    assert!(o.deadlines.contains(&at(7)) && o.deadlines.contains(&at(9)));
    let o = evaluate(&held(7, cs.clone()));
    assert_eq!(o.fates[&(10, 0)], Fate::MayDrop(DropWhy::Covered { by: 12 }));
    assert_eq!(o.history[&(T, REG)], [(st(2, 13, 1), 13)].into_iter().collect(), "leaves in replaced order");
    // without the earlier replacer held, the window counts from the later one
    let mut fewer = cs.clone();
    fewer.remove(3);
    assert_eq!(evaluate(&held(7, fewer)).fates[&(10, 0)], Fate::Keep(KeepWhy::Until));
    // a reader (node 3 holds no right) keeps it as a writer does, showing the same history
    let mut reader = held(6, cs);
    reader.me = 3;
    let o = evaluate(&reader);
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Until));
    assert_eq!(o.history[&(T, REG)].len(), 2);
}

// issues/thing-history.md (Purge on replace, last rule; Decisions 4): a body out of history drops
// under any valid writer's cover, the right or not; under purge on replace only a right holder's
// cover forces the drop, and a right holder owes one until it is held
#[test]
fn out_of_history_drops_under_any_writers_cover_spec_commits_5() {
    let admin = Retention::ADMIN;
    let base = vec![edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None), reg(10, FIRST_ADMIN, 1, REG, admin, 1), reg(11, FIRST_ADMIN, 2, REG, Retention::PLAIN, 2)];
    let by_writer = snap(12, 1, 3, REG, Retention::WRITER, vec![set(2, 11, 2)]);
    let by_admin = snap(13, FIRST_ADMIN, 3, REG, Retention::WRITER, vec![set(2, 11, 2)]);
    let with = |more: &[Commit]| held(4, [base.clone(), more.to_vec()].concat());
    assert_eq!(fate(&with(&[by_writer.clone()]), 10), Fate::MayDrop(DropWhy::Covered { by: 12 }));
    let por = setting(6, 0, REG, Opt::Purge);
    let o = evaluate(&with(&[por.clone(), by_writer.clone()]));
    assert_eq!(o.fates[&(10, 0)], Fate::MayDrop(DropWhy::Covered { by: 12 }));
    assert!(o.owed.contains(&(10, 0)), "the admin still owes its cover");
    assert_eq!(fate(&with(&[por, by_writer, by_admin]), 10), Fate::MustDrop(DropWhy::Covered { by: 13 }));
    // in history, no cover drops it
    assert_eq!(fate(&with(&[setting(6, 0, REG, KEPT), snap(12, 1, 3, REG, Retention::WRITER, vec![set(2, 11, 2)])]), 10), Fate::Keep(KeepWhy::Until));
}

// spec/commits.md §6: at T every value-carrying write dies; the body is held as its leftover
#[test]
fn expired_delta_is_a_leftover_and_reads_absent_spec_commits_6() {
    let mut c = reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 7);
    c.expires = Some(at(2));
    let h = held(1, vec![c.clone()]);
    assert_eq!(read(&h, REG), int(7));
    let h = held(3, vec![c]);
    let o = evaluate(&h);
    assert_eq!(o.fates[&(10, 0)], Fate::Leftover(LeftoverWhy::Expired));
    assert_eq!(read(&h, REG), None);
    assert!(evaluate(&act(&h, &o, None)).forbidden.is_empty());
}

// spec/crdt.md §4.7, §5.6: another delta's value inside an entry outlives the entry creation's expiry,
// under that write's own copy of the key, and its body keeps its value
#[test]
fn other_write_outlives_an_expired_entry_spec_crdt_4_7() {
    let mut c = content(10, FIRST_ADMIN, 1, vec![part(MAP, Retention::PLAIN, vec![
        created(1, 10, 3), put(1, 10, 10, 3, 4)
    ])]);
    c.expires = Some(at(3));
    let w = content(11, FIRST_ADMIN, 2, vec![part(MAP, Retention::PLAIN, vec![put(2, 11, 10, 3, 5)])]);
    let h = held(4, vec![c, w]);
    let o = evaluate(&h);
    assert!(!matches!(o.fates[&(11, 0)], Fate::Leftover(_)), "{:?}", o.fates[&(11, 0)]);
    assert_eq!(read(&h, MAP), map(&[(3, 5)]));
    assert!(evaluate(&act(&h, &o, None)).forbidden.is_empty());
}

// spec/permissions.md §6 (Judgment): a leftover with no request dropping it counts as never received
#[test]
fn valueless_body_without_reason_is_never_received_spec_commits_5() {
    let mut c = reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 7);
    c.parts[0].body = Body::Held(Delta::Writes(set_valueless(1, 10)));
    let h = held(2, vec![c]);
    assert_eq!(fate(&h, 10), Fate::NeverReceived);
    assert_eq!(read(&h, REG), None);
}

// spec/permissions.md §6: a body judged invalid goes, owing no cover, and dropping it changes no
// read; the node's own invalid write stays (its user may write it again)
#[test]
fn invalid_body_drops_unless_own_spec_permissions_6() {
    let cs = vec![setting(6, 0, REG, Opt::Purge), edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None), reg(10, 1, 1, REG, Retention::PLAIN, 1), edge(20, FIRST_ADMIN, 3, 1, None, Some(vec![]))];
    let h = held(3, cs);
    let o = evaluate(&h);
    assert_eq!(o.valid[&(10, 0)], false);
    assert!(o.replaced.is_empty() && o.owed.is_empty());
    assert_eq!(o.fates[&(10, 0)], Fate::MustDrop(DropWhy::Invalid));
    let h2 = act(&h, &o, None);
    assert_eq!(h2.commits.iter().find(|c| c.id == 10).unwrap().parts[0].body, Body::Missing);
    assert_eq!(read(&h2, REG), read(&h, REG));
    let own = Held { me: 1, ..h };
    assert_eq!(evaluate(&own).fates[&(10, 0)], Fate::Keep(KeepWhy::Plain));
}

// spec/crdt.md §2.2 (Parking)
#[test]
fn far_future_commit_is_parked_spec_commits_4() {
    let h = held(3, vec![reg(10, FIRST_ADMIN, 5, REG, Retention::PLAIN, 7)]);
    let o = evaluate(&h);
    assert!(o.parked.contains(&10));
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Pending));
    assert_eq!(read(&h, REG), None);
}

// spec/crdt.md §4.6 (Seq elements), §6.1, spec/permissions.md §6: an invalid text body whose
// element another insert anchors on goes; the anchored insert reads alike before and after
#[test]
fn invalid_text_body_drops_anchored_insert_reads_spec_permissions_6() {
    use held_model::gen::TEXT;
    let a = (10, 1);
    let cs = vec![
        edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None),
        setting(6, 0, TEXT, Opt::Purge),
        content(10, 1, 1, vec![part(TEXT, Retention::PLAIN, vec![ins(1, 10, 1, None, Some(1))])]),
        content(11, FIRST_ADMIN, 2, vec![part(TEXT, Retention::PLAIN, vec![ins(2, 11, 1, Some(a), Some(2))])]),
        edge(20, FIRST_ADMIN, 3, 1, None, Some(vec![])),
    ];
    let h = held(5, cs);
    let o = evaluate(&h);
    assert_eq!(o.fates[&(10, 0)], Fate::MustDrop(DropWhy::Invalid));
    assert!(o.owed.is_empty());
    assert_eq!(read(&h, TEXT), text(&[2]));
    assert_eq!(read(&act(&h, &o, None), TEXT), text(&[2]));
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

// spec/permissions.md §6, spec/crdt.md §4.7 Join: a body stripped for a purge that no longer stands
// stays held as its leftover: its value-less copy hides the write until the valued one joins
#[test]
fn stripped_copy_of_a_fallen_purge_stays_held_spec_permissions_6() {
    let mut s = snap(15, FIRST_ADMIN, 2, REG, Retention::WRITER, vec![set_valueless(1, 10)]);
    s.parts[0].stripped.insert(10);
    let h = held(3, vec![missing(reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 7), 0), s.clone()]);
    assert_ne!(fate(&h, 15), Fate::NeverReceived);
    assert_eq!(read(&h, REG), None);
    assert!(matches!(act(&h, &evaluate(&h), None).commits[1].parts[0].body, Body::Held(_)));
    let h = held(3, vec![reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 7), s]);
    assert_eq!(read(&h, REG), int(7));
}

// spec/commits.md §5 (Bodies and deaths): a snapshot is replaced at the latest death among the
// writes no later snapshot carries. 12 carries entries 1 (10) and 2 (11); 13 overwrites 1 at 3;
// 14 carries 2 live; 15 overwrites 2 at 5. 14 keeps 2's history, so 12 is replaced at 3, 14 at 5.
#[test]
fn snapshot_replaced_at_last_death_no_later_snapshot_carries_spec_commits_5() {
    let r = Retention::WRITER;
    let mk = new_entry;
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

// issues/thing-history.md (History): a snapshot is judged by the setting like any body, from its
// replacement: carrying a write live, it keeps that write's history for D after it is replaced
#[test]
fn snapshot_kept_like_any_body_spec_commits_5() {
    let cs = vec![
        setting(5, 0, REG, keep_after(5)),
        reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 1),
        snap(12, FIRST_ADMIN, 2, REG, Retention::WRITER, vec![set(1, 10, 1)]),
        reg(13, FIRST_ADMIN, 3, REG, Retention::PLAIN, 2),
        snap(14, FIRST_ADMIN, 4, REG, Retention::WRITER, vec![set(3, 13, 2)]),
    ];
    let o = evaluate(&held(5, cs.clone()));
    assert_eq!(o.replaced_at[&(12, 0)], Some(at(3)));
    assert_eq!(o.fates[&(12, 0)], Fate::Keep(KeepWhy::Until));
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Until));
    assert_eq!(evaluate(&held(8, cs)).fates[&(12, 0)], Fate::MayDrop(DropWhy::Covered { by: 14 }));
}

// spec/commits.md §5 (Bodies and deaths): a later snapshot carrying a dead write holds its
// history. 12 carries entry 1 (10); 11 writes entry 2; 13 carries both; 14 overwrites 1 at 4. 13
// carries 12's dead write, so 12 is not dated by it (nothing else of it died): 13 is replaced at 4
// and shows 1's history until 9, and 12 may go under 13's cover
#[test]
fn a_later_snapshot_carrying_a_dead_write_holds_its_history_spec_commits_5() {
    let r = Retention::WRITER;
    let mk = new_entry;
    let (one, two) = (mk(1, 10, 1, 5), mk(2, 11, 2, 6));
    let cs = vec![
        setting(5, 0, MAP, keep_after(5)),
        content(10, FIRST_ADMIN, 1, vec![part(MAP, r, one.clone())]),
        snap(12, FIRST_ADMIN, 1, MAP, r, one.clone()),
        content(11, FIRST_ADMIN, 2, vec![part(MAP, r, two.clone())]),
        snap(13, FIRST_ADMIN, 3, MAP, r, [one.clone(), two.clone()].concat()),
        content(14, FIRST_ADMIN, 4, vec![part(MAP, r, vec![put(4, 14, 10, 1, 7)])]),
    ];
    let o = evaluate(&held(6, cs));
    assert_eq!((o.replaced_at[&(12, 0)], o.replaced_at[&(13, 0)]), (None, Some(at(4))));
    assert!(o.history[&(T, MAP)].iter().any(|(s, c)| *c == 13 && s.dot == dot(10, 1)));
    assert_eq!(o.fates[&(12, 0)], Fate::MayDrop(DropWhy::Covered { by: 13 }));
}
