//! Thing-level history (issues/thing-history.md, held_model::thing_history): the judgment's
//! properties, each over every small world, so a failure names a minimal counterexample.
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
                assert!(out(&t, one_way, r, false) <= out(&t, one_way, r + 1, false), "{t:?} r {r}");
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
                let o = out(&t, one_way, r, false);
                if o == NEVER {
                    continue;
                }
                for ts in o + 1..END + 2 {
                    for opt in OPTS {
                        let mut t2 = t.clone();
                        t2.push(Setting { ts, id: 9, opt });
                        assert_eq!(out(&t2, one_way, r, false), o, "{t:?} + {opt:?}@{ts}, r {r}");
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
            let o = out(&t, true, r, false);
            for ts in 0..END {
                for opt in OPTS {
                    let mut t2 = t.clone();
                    t2.push(Setting { ts, id: 9, opt });
                    if t.iter().all(|s| s.ts <= ts) && o > ts {
                        assert!(out(&t2, true, r, false) >= ts.max(r), "{t:?} + {opt:?}@{ts}, r {r}");
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
    assert_eq!(out(&[short], true, 2, false), 2);
    assert_eq!(out(&[short, long], true, 2, false), 3);
}

/// Purge on replace keeps its property under late dating: a node holding fewer bodies dates a
/// replacement later, and content replaced under purge on replace is never history there.
#[test]
fn purge_on_replace_content_is_never_history_however_dated() {
    for t in timelines(3) {
        for r in 0..END {
            if !purge_owed(&t, true, r, false) {
                continue;
            }
            for later in r..END + 2 {
                assert_eq!(out(&t, true, later, false), later, "{t:?} replaced {r} dated {later}");
            }
        }
    }
}

/// Why keep after purge on replace reads as none: without it, a node that dates the
/// replacement later (the replacing body itself purged) shows purged content as history.
#[test]
fn without_one_way_late_dating_shows_purged_content() {
    let t = [Setting { ts: 1, id: 0, opt: Opt::Purge }, Setting { ts: 3, id: 1, opt: Opt::Keep { after: 0, until: NEVER } }];
    assert!(purge_owed(&t, false, 2, false));
    assert_eq!(out(&t, false, 4, false), NEVER);
    assert_eq!(out(&t, true, 4, false), 4);
}

/// A body nobody may purge is never out, whatever the settings.
#[test]
fn nobody_is_always_history() {
    for t in timelines(2) {
        for r in 0..END {
            assert_eq!(out(&t, true, r, true), NEVER);
            assert!(!purge_owed(&t, true, r, true));
        }
    }
}

fn bodies(fire: bool) -> Vec<Body> {
    [1, 3, 5].iter().enumerate().map(|(i, ts)| Body { ts: *ts, id: i as u32, fire, nobody: false }).collect()
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
