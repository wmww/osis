//! Thing-level history (issues/thing-history.md, held_model::thing_history): the judgment's
//! properties, each over every small world, so a failure names a minimal counterexample: first on
//! the greenfield functions, then (`ev_`) through `evaluate`, on held sets of settings and register
//! writes or fires of one thing, in hours.
use held_model::thing_history::*;

const END: Ms = 7;
const OPTS: [Opt; 6] = [Opt::None, Opt::Keep { after: 1, until: 0 }, Opt::Keep { after: 3, until: 0 }, Opt::Keep { after: 0, until: 4 }, Opt::Keep { after: 0, until: NEVER }, Opt::Purge];

/// Every timeline of up to `n` settings stamped in `0..END`.
fn timelines(n: usize) -> Vec<Vec<Setting>> {
    let mut all = vec![vec![]];
    let mut last: Vec<Vec<Setting>> = vec![vec![]];
    for id in 0..n as u32 {
        let mut next = Vec::new();
        for t in &last {
            for ts in 0..END {
                for opt in OPTS {
                    let mut t = t.clone();
                    t.push(Setting { ts, id, opt });
                    next.push(t);
                }
            }
        }
        all.extend(next.iter().cloned());
        last = next;
    }
    all
}

fn perms<T: Clone>(v: &[T]) -> Vec<Vec<T>> {
    if v.len() <= 1 {
        return vec![v.to_vec()];
    }
    let mut out = Vec::new();
    for i in 0..v.len() {
        let mut rest = v.to_vec();
        let x = rest.remove(i);
        for mut p in perms(&rest) {
            p.insert(0, x.clone());
            out.push(p);
        }
    }
    out
}

/// Bodies leave in the order they were replaced: one threshold per aspect says what is in
/// history, so a node needs one timer per aspect and holding more bodies (an earlier
/// replacement) never keeps a body longer.
#[test]
fn leaves_in_replaced_order() {
    for one_way in [false, true] {
        for t in timelines(3) {
            for r in 0..END {
                assert!(out(&t, one_way, r) <= out(&t, one_way, r + 1), "{t:?} r {r}");
            }
        }
    }
}

/// Out is for good: a setting stamped after the moment a body left never brings it back, and
/// one stamped at or before the moment a body was replaced changes nothing before that moment.
#[test]
fn a_later_setting_never_brings_back() {
    for one_way in [false, true] {
        for t in timelines(2) {
            for r in 0..END {
                let o = out(&t, one_way, r);
                if o == NEVER {
                    continue;
                }
                for ts in o + 1..END + 2 {
                    for opt in OPTS {
                        let mut t2 = t.clone();
                        t2.push(Setting { ts, id: 9, opt });
                        assert_eq!(out(&t2, one_way, r), o, "{t:?} + {opt:?}@{ts}, r {r}");
                    }
                }
            }
        }
    }
}

/// A later setting reaches what is still in history: it may shorten or extend it, never to
/// before its own stamp.
#[test]
fn a_later_setting_acts_from_its_stamp() {
    for t in timelines(2) {
        for r in 0..END {
            let o = out(&t, true, r);
            for ts in 0..END {
                for opt in OPTS {
                    let mut t2 = t.clone();
                    t2.push(Setting { ts, id: 9, opt });
                    if t.iter().all(|s| s.ts <= ts) && o > ts {
                        assert!(out(&t2, true, r) >= ts.max(r), "{t:?} + {opt:?}@{ts}, r {r}");
                    }
                }
            }
        }
    }
}

/// A setting arriving late (stamped before ones already held) can put a body back in history:
/// the judgment follows the settings held, not the order they came in.
#[test]
fn a_late_setting_can_reshow_a_held_body() {
    let short = Setting { ts: 3, id: 1, opt: Opt::None };
    let long = Setting { ts: 1, id: 0, opt: Opt::Keep { after: 0, until: NEVER } };
    // replaced at 2, judged at 2 holding only `short`: out; `long` (stamped 1) arrives: in until 3
    assert_eq!(out(&[short], true, 2), 2);
    assert_eq!(out(&[short, long], true, 2), 3);
}

/// Purge on replace keeps its property under late dating: a node holding fewer bodies dates a
/// replacement later, and content replaced under purge on replace is never history there.
#[test]
fn purge_on_replace_content_is_never_history_however_dated() {
    for t in timelines(3) {
        for r in 0..END {
            if !purge_owed(&t, true, r) {
                continue;
            }
            for later in r..END + 2 {
                assert_eq!(out(&t, true, later), later, "{t:?} replaced {r} dated {later}");
            }
        }
    }
}

/// Why keep after purge on replace reads as none: without it, a node that dates the
/// replacement later (the replacing body itself purged) shows purged content as history.
#[test]
fn without_one_way_late_dating_shows_purged_content() {
    let t = [Setting { ts: 1, id: 0, opt: Opt::Purge }, Setting { ts: 3, id: 1, opt: Opt::Keep { after: 0, until: NEVER } }];
    assert!(purge_owed(&t, false, 2));
    assert_eq!(out(&t, false, 4), NEVER);
    assert_eq!(out(&t, true, 4), 4);
}

fn bodies(fire: bool) -> Vec<Body> {
    [1, 3, 5].iter().enumerate().map(|(i, ts)| Body { ts: *ts, id: i as u32, fire }).collect()
}

#[derive(Clone, Copy, Debug)]
enum Item {
    S(Setting),
    B(Body),
}
fn stamp(i: &Item) -> Ms {
    match i {
        Item::S(s) => s.ts,
        Item::B(b) => b.ts,
    }
}

/// With nothing late (everything stamped up to now is held when judged) a node that drops at
/// the first allowed moment shows, at every moment, what a node that keeps everything shows,
/// and a body that left never shows again.
#[test]
fn nothing_late_dropping_loses_no_history() {
    for fire in [false, true] {
        for t in timelines(2) {
            let (mut n, mut gone) = (Eager::default(), Vec::<u32>::new());
            let all = bodies(fire);
            for now in 0..END + 4 {
                for s in t.iter().filter(|s| s.ts == now) {
                    n.setting(*s, true, now);
                }
                for b in all.iter().filter(|b| b.ts == now) {
                    n.body(*b, true, now);
                }
                n.act(true, now);
                let (ts, bs): (Vec<Setting>, Vec<Body>) = (t.iter().filter(|s| s.ts <= now).copied().collect(), all.iter().filter(|b| b.ts <= now).copied().collect());
                let h = n.history(true, now);
                assert_eq!(h, history(&ts, true, &bs, now), "{t:?} fire {fire} now {now}");
                assert!(gone.iter().all(|g| !h.contains(g)), "{t:?} now {now}: came back");
                gone.extend(bs.iter().filter(|b| replaced_at(&bs, b).is_some() && !h.contains(&b.id)).map(|b| b.id));
            }
        }
    }
}

/// In any arrival order, at any pace, a node that drops at the first allowed moment never
/// shows what a node holding everything does not, and what it lacks it dropped itself; nodes
/// that drop nothing show alike whatever the order (the judgment reads only what is held).
#[test]
fn any_order_dropping_shows_a_subset() {
    for fire in [false, true] {
        for t in timelines(2).into_iter().filter(|t| t.len() == 2) {
            let all = bodies(fire);
            let items: Vec<Item> = t.iter().map(|s| Item::S(*s)).chain(all.iter().map(|b| Item::B(*b))).collect();
            for order in perms(&items) {
                // each item arrives no earlier than its stamp; `lag` delays the whole run
                for lag in [0, 2] {
                    let (mut n, mut now) = (Eager::default(), 0);
                    for i in &order {
                        now = now.max(stamp(i)) + lag;
                        match i {
                            Item::S(s) => n.setting(*s, true, now),
                            Item::B(b) => n.body(*b, true, now),
                        }
                    }
                    for now in now..now + 5 {
                        n.act(true, now);
                        let (h, full) = (n.history(true, now), history(&t, true, &all, now));
                        assert!(h.iter().all(|x| full.contains(x)), "{order:?} now {now}: shows more");
                        assert!(full.iter().all(|x| h.contains(x) || n.dropped.contains(x)), "{order:?} now {now}: lost without a drop");
                    }
                }
            }
        }
    }
}


/// The same properties through `evaluate`.
mod ev {
use super::perms;
use crate::util::*;
use held_model::gen::{REG, SIG};
use held_model::*;
use std::collections::BTreeSet;

/// The greenfield options in hours.
const EV_OPTS: [fn() -> Opt; 6] = [|| Opt::None, || keep_after(1), || keep_after(3), || keep_until(4), || KEPT, || Opt::Purge];

/// Every timeline of up to `n` settings (hour, option), stamped at `stamps`.
fn ev_timelines(n: usize, stamps: &[u64], opts: &[Opt]) -> Vec<Vec<(u64, Opt)>> {
    let mut all = vec![vec![]];
    let mut last: Vec<Vec<(u64, Opt)>> = vec![vec![]];
    for _ in 0..n {
        let next: Vec<Vec<(u64, Opt)>> = last.iter().flat_map(|t| stamps.iter().flat_map(move |&h| opts.iter().map(move |&o| [t.clone(), vec![(h, o)]].concat()))).collect();
        all.extend(next.iter().cloned());
        last = next;
    }
    all
}
fn all_opts() -> Vec<Opt> {
    EV_OPTS.iter().map(|f| f()).collect()
}
/// The first admin's settings of a timeline on aspect `a`, keyed in list order.
fn settings_of(a: Aspect, tl: &[(u64, Opt)]) -> Vec<Commit> {
    tl.iter().enumerate().map(|(i, &(h, o))| setting(100 + i as CommitId, h, a, o)).collect()
}
/// Body `id` at hour `h`: a register write on `REG`, or a fire on `SIG`.
fn body(id: CommitId, h: u64, fire: bool) -> Commit {
    reg(id, FIRST_ADMIN, h, if fire { SIG } else { REG }, Retention::PLAIN, id as i64)
}
/// Bodies 10, 11, 12 at hours 1, 3, 5 (values: 10 replaced at 3, 11 at 5).
fn bodies3(fire: bool) -> Vec<Commit> {
    vec![body(10, 1, fire), body(11, 3, fire), body(12, 5, fire)]
}
fn aspect(fire: bool) -> Aspect {
    if fire { SIG } else { REG }
}
/// The commits history() lists on the aspect.
fn listed(h: &Held, a: Aspect) -> BTreeSet<CommitId> {
    evaluate(h).history.get(&(T, a)).map(|s| s.iter().map(|x| x.1).collect()).unwrap_or_default()
}
fn world(now: u64, tl: &[(u64, Opt)], fire: bool, bodies: Vec<Commit>) -> Held {
    held(now, [settings_of(aspect(fire), tl), bodies].concat())
}

// issues/thing-history.md (History): bodies leave in the order they were replaced, and holding
// more bodies (an earlier replacement) never keeps one longer
#[test]
fn ev_leaves_in_replaced_order() {
    for fire in [false, true] {
        for tl in ev_timelines(2, &[0, 2, 4, 6], &all_opts()) {
            for now in 5..11 {
                let l = listed(&world(now, &tl, fire, bodies3(fire)), aspect(fire));
                assert!(!l.contains(&10) || l.contains(&11), "{tl:?} fire {fire} now {now}: {l:?}");
                if !fire {
                    // 11 not held: 10 is replaced at 5
                    let fewer = listed(&world(now, &tl, fire, vec![body(10, 1, fire), body(12, 5, fire)]), REG);
                    assert!(!l.contains(&10) || fewer.contains(&10), "{tl:?} now {now}");
                }
            }
        }
    }
}

/// The first hour from `from` at which body 10 is not listed, if before 15.
fn left(tl: &[(u64, Opt)], fire: bool, from: u64) -> Option<u64> {
    (from..15).find(|&now| !listed(&world(now, tl, fire, bodies3(fire)), aspect(fire)).contains(&10))
}

// issues/thing-history.md (History): out is for good: a setting stamped after a body left never
// brings it back
#[test]
fn ev_a_later_setting_never_brings_back() {
    for fire in [false, true] {
        let r = if fire { 1 } else { 3 };
        for tl in ev_timelines(1, &[0, 2, 4, 6], &all_opts()) {
            let Some(o) = left(&tl, fire, r) else { continue };
            for ts in [o + 1, o + 2] {
                for opt in all_opts() {
                    let t2 = [tl.clone(), vec![(ts, opt)]].concat();
                    for now in o..o + 4 {
                        assert!(!listed(&world(now, &t2, fire, bodies3(fire)), aspect(fire)).contains(&10), "{tl:?} + {opt:?}@{ts}: back at {now}");
                    }
                }
            }
        }
    }
}

// issues/thing-history.md (In force): a setting acts from its own stamp: before it, held or not,
// it changes nothing
#[test]
fn ev_a_later_setting_acts_from_its_stamp() {
    for fire in [false, true] {
        for tl in ev_timelines(1, &[0, 2, 4], &all_opts()) {
            for ts in [3, 5, 6] {
                for opt in all_opts() {
                    let t2 = [tl.clone(), vec![(ts, opt)]].concat();
                    for now in ts.saturating_sub(1).max(1)..ts {
                        let a = listed(&world(now, &tl, fire, bodies3(fire)), aspect(fire));
                        assert_eq!(listed(&world(now, &t2, fire, bodies3(fire)), aspect(fire)), a, "{tl:?} + {opt:?}@{ts} now {now}");
                    }
                }
            }
        }
    }
}

// issues/thing-history.md (In force): a setting is in force from its own commit on: one in the
// replacing commit governs the body it replaces
#[test]
fn ev_in_force_from_its_own_commit() {
    let mut both = setting(20, 3, REG, Opt::Purge);
    both.parts.push(part(REG, Retention::PLAIN, vec![set(3, 20, 7)]));
    let h = held(4, vec![setting(19, 0, REG, KEPT), body(10, 1, false), both]);
    let o = evaluate(&h);
    assert!(o.under_purge.contains(&(10, 0)));
    assert!(listed(&h, REG).is_empty());
}

// issues/thing-history.md (In force, Decisions 3): settings are in force by key from their own
// stamps, whatever order they are held in. From a newer setting's stamp on, a node also holding
// an older-stamped one shows what a node holding only the newer shows, unless the older set purge
// on replace and the newer keeps (one way: then neither keeps anything). Of two admins' settings at
// one stamp the later key governs from it, as alone.
#[test]
fn ev_in_force_by_key_from_its_own_stamp() {
    // replaced at 4 and 6, judged from hour 6 on (no replacement stamped ahead of the clock)
    let bodies = || vec![body(10, 3, false), body(11, 4, false), body(12, 6, false)];
    let one_way = |a: Opt, b: Opt| a == Opt::Purge && matches!(b, Opt::Keep { .. });
    let view = |h: &Held| {
        let o = evaluate(h);
        (o.history.get(&(T, REG)).map(|s| s.iter().map(|x| x.1).collect::<BTreeSet<_>>()).unwrap_or_default(), o.under_purge)
    };
    for older in all_opts() {
        for newer in all_opts() {
            for now in 6..12 {
                let only = view(&world(now, &[(3, newer)], false, bodies()));
                let both = view(&world(now, &[(1, older), (3, newer)], false, bodies()));
                if one_way(older, newer) {
                    assert!(both.0.is_empty(), "{older:?}, {newer:?} now {now}: one way");
                } else {
                    assert_eq!(both, only, "{older:?}, {newer:?} now {now}");
                }
            }
            // two admins at hour 2: node 1's key is the later
            let grant = edge(5, FIRST_ADMIN, 0, 1, Some(Role::Admin), None);
            let s = |id, by, opt| setting_by(id, by, 2, Setting { rules: vec![(REG.name, SettingEntry { history: opt, expires: None })], default: None });
            let (lo, hi) = (s(100, FIRST_ADMIN, older), s(101, 1, newer));
            for now in 6..12 {
                let at_once = |cs: Vec<Commit>| view(&held(now, [vec![grant.clone()], cs, bodies()].concat()));
                let a = at_once(vec![lo.clone(), hi.clone()]);
                assert_eq!(at_once(vec![hi.clone(), lo.clone()]), a, "{older:?}, {newer:?} now {now}: held order");
                if one_way(older, newer) {
                    assert!(a.0.is_empty(), "{older:?}, {newer:?} now {now}: one way");
                } else {
                    assert_eq!(a, at_once(vec![hi.clone()]), "{older:?}, {newer:?} now {now}: the later key governs");
                }
            }
        }
    }
}

// issues/thing-history.md (Decisions 1): a setting arriving late (stamped before ones already
// held) can put a body still held back in history
#[test]
fn ev_a_late_setting_can_reshow_a_held_body() {
    let bodies = || vec![body(10, 1, false), body(11, 2, false)];
    let short = (3, Opt::None);
    let long = (1, KEPT);
    assert!(listed(&world(2, &[short], false, bodies()), REG).is_empty());
    let both = world(2, &[long, short], false, bodies());
    assert_eq!(listed(&both, REG), [10].into());
    assert!(listed(&world(3, &[long, short], false, bodies()), REG).is_empty());
}

// issues/thing-history.md (Purge on replace, Decisions 3): content replaced under purge on replace
// is never history, however late a node dates the replacement (holding fewer bodies)
#[test]
fn ev_purge_on_replace_content_is_never_history_however_dated() {
    let mut reached = 0;
    for tl in ev_timelines(2, &[0, 2, 4, 6], &all_opts()) {
        let h = world(5, &tl, false, bodies3(false));
        if !evaluate(&h).under_purge.contains(&(10, 0)) {
            continue;
        }
        reached += 1;
        for now in 5..12 {
            assert!(!listed(&world(now, &tl, false, bodies3(false)), REG).contains(&10), "{tl:?} now {now}");
            let fewer = world(now, &tl, false, vec![body(10, 1, false), missing(body(11, 3, false), 0), body(12, 5, false)]);
            assert!(!listed(&fewer, REG).contains(&10), "{tl:?} now {now}: dated at 5");
        }
    }
    assert!(reached > 0);
}

// issues/thing-history.md (One way): the greenfield counterexample, judged by `evaluate`: a keep
// after purge on replace keeps nothing, so a node dating the replacement after the keep shows none
#[test]
fn ev_keep_after_purge_on_replace_keeps_nothing() {
    let tl = [(1, Opt::Purge), (3, KEPT)];
    let full = vec![body(10, 0, false), body(11, 2, false), body(12, 4, false)];
    assert!(evaluate(&world(5, &tl, false, full.clone())).under_purge.contains(&(10, 0)));
    let fewer = vec![full[0].clone(), missing(full[1].clone(), 0), full[2].clone()];
    assert!(listed(&world(5, &tl, false, fewer), REG).is_empty(), "dated at 4, after the keep");
    // a body replaced after the keep: still none (one way)
    assert!(listed(&world(5, &tl, false, vec![body(10, 3, false), body(11, 4, false)]), REG).is_empty());
}

// issues/thing-history.md (Decisions 2): who may purge a body changes nothing of its history
#[test]
fn ev_who_may_purge_changes_no_history() {
    for tl in ev_timelines(1, &[0, 2, 4, 6], &all_opts()) {
        for now in 5..10 {
            let with = |by: PurgeBy| {
                let bs: Vec<Commit> = bodies3(false).into_iter().map(|mut c| { c.parts[0].retention = Retention { by }; c }).collect();
                listed(&world(now, &tl, false, bs), REG)
            };
            let a = with(PurgeBy::AuthorOrAdmin);
            assert_eq!(with(PurgeBy::Admin), a, "{tl:?} now {now}");
            assert_eq!(with(PurgeBy::Writer), a, "{tl:?} now {now}");
        }
    }
}

// issues/thing-history.md (The setting): a setting is an admin-only delta: one by a writer is no
// setting until the writer is admin; one in an expiring commit is none; no validity depends on one
#[test]
fn ev_only_valid_settings_are_in_force_and_none_judges_validity() {
    let bodies = || vec![body(10, 1, false), body(11, 3, false)];
    let by_writer = setting_by(19, 1, 0, Setting { rules: vec![(REG.name, SettingEntry { history: KEPT, expires: Some(HOUR) })], default: None });
    let grant = |role| edge(5, FIRST_ADMIN, 0, 1, Some(role), None);
    let h = held(4, [vec![grant(Role::Write), by_writer.clone()], bodies()].concat());
    assert!(listed(&h, REG).is_empty(), "a writer's setting is none");
    assert!(evaluate(&h).settings.is_empty());
    let h = held(4, [vec![grant(Role::Admin), by_writer.clone()], bodies()].concat());
    assert_eq!(listed(&h, REG), [10].into(), "an admin's is in force");
    let mut exp = setting(19, 0, REG, KEPT);
    exp.expires = Some(at(9));
    assert!(listed(&held(4, [vec![exp], bodies()].concat()), REG).is_empty(), "one in an expiring commit is none");
    // writes breaking every default a setting gives (expiry, purge option) are valid
    let mut b = body(12, 2, false);
    b.parts[0].retention = Retention::WRITER;
    b.expires = Some(at(9));
    let o = evaluate(&held(4, vec![setting(19, 0, REG, Opt::Purge), b]));
    assert_eq!(o.valid[&(12, 0)], true);
}

/// A node receiving each commit at its stamp, acting at once and dropping everything it may.
fn eager(mut h: Held, now: u64) -> Held {
    h.now = at(now);
    for _ in 0..20 {
        let o = evaluate(&h);
        let n = act(&h, &o, None);
        let may = o.fates.iter().find(|(_, f)| matches!(f, Fate::MayDrop(_))).map(|x| *x.0);
        let n = match may {
            Some(pr) => act(&n, &evaluate(&n), Some(pr)),
            None => n,
        };
        if n == h {
            return h;
        }
        h = n;
    }
    panic!("eager did not settle")
}

/// Bodies 10 and 11 at hours 1 and 3, each with the writer's snapshot covering it (values), and
/// 12 at 5: what an eager node may drop.
fn covered3(fire: bool) -> Vec<Commit> {
    let mut v = bodies3(fire);
    if !fire {
        for (id, h) in [(10, 1), (11, 3), (12, 5)] {
            v.push(snap(id + 20, FIRST_ADMIN, h, REG, Retention::WRITER, vec![set(h, id, id as i64)]));
        }
    }
    v
}

/// The writes history() lists on the aspect, by stamp (a snapshot carrying a write lists it too).
fn shown_writes(h: &Held, a: Aspect) -> BTreeSet<Stamp> {
    evaluate(h).history.get(&(T, a)).map(|s| s.iter().map(|x| x.0.clone()).collect()).unwrap_or_default()
}

// issues/thing-history.md (Convergence): with nothing late a node that drops at the first allowed
// moment shows, at every moment, the writes a node keeping everything shows, and a write that left
// never shows again
#[test]
fn ev_nothing_late_dropping_loses_no_history() {
    let mut dropped = 0;
    for fire in [false, true] {
        for tl in ev_timelines(2, &[0, 3], &all_opts()) {
            let all = [settings_of(aspect(fire), &tl), covered3(fire)].concat();
            let mut n = held(0, vec![]);
            let mut gone: BTreeSet<Stamp> = BTreeSet::new();
            let mut ever: BTreeSet<Stamp> = BTreeSet::new();
            for now in 0..9 {
                let arrive: Vec<Commit> = all.iter().filter(|c| c.ts / MS <= at(now) && !n.commits.iter().any(|x| x.id == c.id)).cloned().collect();
                n.commits.extend(arrive);
                n = eager(n, now);
                let keep_all = held(now, all.iter().filter(|c| c.ts / MS <= at(now)).cloned().collect());
                let (e, k) = (shown_writes(&n, aspect(fire)), shown_writes(&keep_all, aspect(fire)));
                assert_eq!(e, k, "{tl:?} fire {fire} now {now}");
                assert!(gone.is_disjoint(&e), "{tl:?} fire {fire} now {now}: came back");
                gone.extend(ever.difference(&e).cloned());
                ever.extend(e);
            }
            dropped += n.commits.iter().filter(|c| c.parts.iter().any(|p| matches!(p.body, Body::Dropped(_) | Body::Missing))).count();
        }
    }
    assert!(dropped > 0);
}

// issues/thing-history.md (Convergence, Dropped stays dropped): in any arrival order, late, a node
// dropping at the first allowed moment never shows what a node holding everything does not, and
// what it lacks it dropped itself
#[test]
fn ev_any_order_dropping_shows_a_subset() {
    let opts = [Opt::None, keep_after(1), KEPT, Opt::Purge];
    for tl in ev_timelines(2, &[0, 2], &opts).into_iter().filter(|t| t.len() == 2) {
        let items = [settings_of(SIG, &tl), vec![body(10, 1, true), body(11, 3, true)]].concat();
        for order in perms(&items) {
            let (mut n, mut now) = (held(0, vec![]), 0);
            for c in &order {
                now = now.max((wall(c.ts) - W0) / HOUR) + 2;
                n.commits.push(c.clone());
                n = eager(n, now);
            }
            for now in now..now + 3 {
                n = eager(n, now);
                let full = held(now, items.clone());
                let (h, f) = (listed(&n, SIG), listed(&full, SIG));
                assert!(h.is_subset(&f), "{order:?} now {now}: shows more");
                let lost: Vec<CommitId> = f.difference(&h).copied().collect();
                for c in lost {
                    let p = &n.commits.iter().find(|x| x.id == c).unwrap().parts[0];
                    assert!(!matches!(p.body, Body::Held(_)), "{tl:?} {:?} now {now}: lost {c} without a drop", order.iter().map(|c| c.id).collect::<Vec<_>>());
                }
            }
        }
    }
}
}
