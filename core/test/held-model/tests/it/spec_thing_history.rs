//! Thing-level history (spec/commits.md §5 The setting, notes/engine-retention-history.md; held_model::thing_history): the judgment's
//! properties, first on the greenfield functions (small worlds exhaustively, larger ones at
//! random, with the negative controls failing), then (`ev_`) through `evaluate`, on held sets of
//! settings and register writes or fires of one thing, in hours.
use held_model::gen::Rng;
use held_model::thing_history::*;

const END: Ms = 7;
const OPTS: [Opt; 6] = [Opt::None, Opt::Keep { after: 1, until: 0 }, Opt::Keep { after: 3, until: 0 }, Opt::Keep { after: 0, until: 4 }, Opt::Keep { after: 0, until: NEVER }, Opt::Purge];

/// Every chain of up to `n` settings stamped in `0..END`, each written by a writer holding the one
/// before it by key (`written_after`: the floor carried).
fn chains(n: usize) -> Vec<Vec<Setting>> {
    let mut all = vec![vec![]];
    let mut last: Vec<Vec<Setting>> = vec![vec![]];
    for id in 0..n as u32 {
        let mut next = Vec::new();
        for t in &last {
            let from = t.last().map_or(0, |s: &Setting| s.ts);
            for ts in from..END {
                for &opt in &OPTS {
                    let mut t = t.clone();
                    t.push(written_after(t.last(), ts, id, opt));
                    next.push(t);
                }
            }
        }
        all.extend(next.iter().cloned());
        last = next;
    }
    all
}

/// Every subset of `v`.
fn subsets<T: Clone>(v: &[T]) -> Vec<Vec<T>> {
    (0..1u32 << v.len()).map(|m| v.iter().enumerate().filter(|(i, _)| m & (1 << i) != 0).map(|x| x.1.clone()).collect()).collect()
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

fn bodies(fire: bool) -> Vec<Body> {
    [1, 3, 5].iter().enumerate().map(|(i, ts)| Body { ts: *ts, id: i as u32, fire }).collect()
}

/// The violations of purge on replace's promise in one world under `rule`: a body the oracle says
/// was replaced under purge on replace (`purged`) shown by a node holding `held` of the bodies and
/// `known` of the settings, one of them at or after the setting it was replaced under (a node
/// holding none such has not learnt of the purge: what it shows is a late setting's), at any
/// moment from its replacement.
fn shown_purged(settings: &[Setting], all: &[Body], known: &[Setting], held: &[Body], rule: Rule) -> usize {
    let mut n = 0;
    for b in held.iter().filter(|b| purged(settings, all, b)) {
        let r = replaced_at(all, b).unwrap();
        let under = settings.iter().filter(|s| s.ts <= r).max().unwrap();
        if !known.iter().any(|s| s >= under) {
            continue;
        }
        n += (r..END + 6).filter(|&now| history(known, rule, held, now).contains(&b.id)).count();
    }
    n
}

/// Purge on replace is one way (Tess's decision 3): content replaced under it never shows, at
/// any node holding the setting it was replaced under or a later one, whatever else it holds
/// (any subset of the bodies, so a replacement dated late) and in whatever order it came. Over
/// every small world. Negative controls: with no floor, or the floor read against the dated
/// replacement, purged content shows.
#[test]
fn purged_content_never_shows() {
    let all = bodies(false);
    let (mut reached, mut no_floor, mut by_replaced) = (0, 0, 0);
    for t in chains(2) {
        for known in subsets(&t).into_iter().filter(|k| !k.is_empty()) {
            for held in subsets(&all) {
                reached += held.iter().filter(|b| purged(&t, &all, b)).count();
                assert_eq!(shown_purged(&t, &all, &known, &held, Rule::Floor), 0, "{t:?} known {known:?} held {held:?}");
                no_floor += shown_purged(&t, &all, &known, &held, Rule::NoFloor);
                by_replaced += shown_purged(&t, &all, &known, &held, Rule::FloorByReplaced);
            }
        }
    }
    assert!(reached > 0 && no_floor > 0 && by_replaced > 0, "reached {reached}, no floor {no_floor}, by replaced {by_replaced}");
}

/// A random world: a chain of up to 5 settings and up to 7 register writes at distinct stamps
/// in `0..20` (values or fires).
fn random_world(r: &mut Rng) -> (Vec<Setting>, Vec<Body>) {
    let mut ts: Vec<Ms> = (0..20).collect();
    r.shuffle(&mut ts);
    let fire = r.chance(20);
    let mut all: Vec<Body> = ts[..2 + r.below(6) as usize].iter().enumerate().map(|(i, t)| Body { ts: *t, id: i as u32, fire }).collect();
    all.sort();
    let mut stamps: Vec<Ms> = (0..1 + r.below(5)).map(|_| r.below(20)).collect();
    stamps.sort();
    let opts = [Opt::None, Opt::Keep { after: 2, until: 0 }, Opt::Keep { after: 7, until: 0 }, Opt::Keep { after: 0, until: 12 }, Opt::Keep { after: 0, until: NEVER }, Opt::Purge, Opt::Purge];
    let mut settings: Vec<Setting> = Vec::new();
    for (id, t) in stamps.into_iter().enumerate() {
        let s = written_after(settings.last(), t, id as u32, r.pick(&opts));
        settings.push(s);
    }
    (settings, all)
}

/// `purged_content_never_shows` over random larger worlds, each node holding a random subset of
/// the settings and bodies; then an eager node fed every item in a random order, late, that never
/// shows purged content once it holds a setting at or after the one it was replaced under.
#[test]
fn purged_content_never_shows_random() {
    let (mut reached, mut no_floor, mut by_replaced) = (0, 0, 0);
    let mut r = Rng::new(0);
    for _ in 0..4000 {
        let (t, all) = random_world(&mut r);
        let pick = |r: &mut Rng, v: &[Body]| -> Vec<Body> { v.iter().filter(|_| r.chance(60)).copied().collect() };
        let held = pick(&mut r, &all);
        let known: Vec<Setting> = t.iter().filter(|_| r.chance(60)).copied().collect();
        reached += held.iter().filter(|b| purged(&t, &all, b)).count();
        assert_eq!(shown_purged(&t, &all, &known, &held, Rule::Floor), 0, "{t:?} known {known:?} held {held:?}");
        no_floor += shown_purged(&t, &all, &known, &held, Rule::NoFloor);
        by_replaced += shown_purged(&t, &all, &known, &held, Rule::FloorByReplaced);
        // an eager node in a random arrival order
        #[derive(Clone, Copy)]
        enum Item {
            S(Setting),
            B(Body),
        }
        let mut items: Vec<Item> = t.iter().map(|s| Item::S(*s)).chain(all.iter().map(|b| Item::B(*b))).collect();
        r.shuffle(&mut items);
        let (mut n, mut now) = (Eager::default(), 0);
        for i in items {
            match i {
                Item::S(s) => {
                    now = now.max(s.ts) + r.below(3);
                    n.setting(s, Rule::Floor, now)
                }
                Item::B(b) => {
                    now = now.max(b.ts) + r.below(3);
                    n.body(b, Rule::Floor, now)
                }
            }
            for b in n.held.iter().filter(|b| purged(&t, &all, b)) {
                let rt = replaced_at(&all, b).unwrap();
                let under = t.iter().filter(|s| s.ts <= rt).max().unwrap();
                if n.settings.iter().any(|s| s >= under) {
                    assert!(!n.history(Rule::Floor, now).contains(&b.id), "{t:?} {all:?}: eager shows {b:?} at {now}");
                }
            }
        }
    }
    assert!(reached > 0 && no_floor > 0 && by_replaced > 0, "reached {reached}, no floor {no_floor}, by replaced {by_replaced}");
}

/// Under one setting bodies leave in the order they were replaced, but for those under the floor
/// (out when replaced): one cursor per aspect times what leaves, and a body under the floor is told
/// late at worst, never early.
#[test]
fn leaves_in_replaced_order() {
    for t in chains(2) {
        let cur = current(&t);
        for ts in 0..END {
            let b = Body { ts, id: 0, fire: false };
            if cur.is_some_and(|s| ts < s.floor) {
                assert!((ts..END + 2).all(|r| out(cur, Rule::Floor, &b, r) == r));
                continue;
            }
            for r in ts..END + 2 {
                assert!(out(cur, Rule::Floor, &b, r) <= out(cur, Rule::Floor, &b, r + 1), "{t:?} {b:?} r {r}");
            }
        }
    }
}

/// Kept while live (spec/commits.md §5): a live body is kept at m exactly while a replacement of
/// it at m would be kept by the current setting. Entries with a D and a T too.
#[test]
fn kept_while_live_while_a_replacement_would_be_kept() {
    let mut opts = OPTS.to_vec();
    opts.push(Opt::Keep { after: 1, until: 5 });
    for prev in [None, Some(Opt::Purge)] {
        for &opt in &opts {
            let p = prev.map(|o| written_after(None, 2, 0, o));
            let cur = Some(written_after(p.as_ref(), 3, 1, opt));
            for ts in 0..END {
                let b = Body { ts, id: 0, fire: false };
                let l = live_until(cur, &b);
                for m in ts..END + 6 {
                    assert_eq!(m < l, out(cur, Rule::Floor, &b, m) > m, "{cur:?} {b:?} m {m}: live until {l}");
                }
                assert_eq!(l == NEVER, out(cur, Rule::Floor, &b, NEVER - 1) > NEVER - 1, "{cur:?} {b:?}");
            }
        }
    }
}

/// The current setting alone decides: a newer one lengthening history re-shows a body still held
/// (dropped stays dropped, Tess's decision 1), one shortening it ends it at once, and an older
/// setting arriving late changes nothing.
#[test]
fn the_current_setting_alone_decides() {
    let held = [Body { ts: 1, id: 0, fire: false }, Body { ts: 2, id: 1, fire: false }];
    let short = written_after(None, 0, 0, Opt::Keep { after: 1, until: 0 });
    let long = written_after(Some(&short), 4, 1, Opt::Keep { after: 10, until: 0 });
    assert!(history(&[short], Rule::Floor, &held, 4).is_empty());
    assert_eq!(history(&[short, long], Rule::Floor, &held, 4), [0]);
    let none = written_after(Some(&long), 5, 2, Opt::None);
    assert!(history(&[short, long, none], Rule::Floor, &held, 5).is_empty());
    // an older setting held late is not current
    assert_eq!(history(&[long, short], Rule::Floor, &held, 4), [0]);
    // an eager node that dropped the body under `short` does not get it back
    let mut e = Eager::default();
    e.setting(short, Rule::Floor, 0);
    e.body(held[0], Rule::Floor, 1);
    e.body(held[1], Rule::Floor, 3);
    e.setting(long, Rule::Floor, 4);
    e.body(held[0], Rule::Floor, 4);
    assert!(e.history(Rule::Floor, 4).is_empty() && e.dropped == [0]);
}

/// Turning purge on replace off keeps what is written from then on (options keep their
/// property): a body written at or after the floor is kept by the keep entry as if no purge came
/// before; one written before it is under purge on replace when replaced, also with fewer bodies
/// held. The floor is carried by every later setting.
#[test]
fn keep_after_purge_keeps_what_is_written_after() {
    let p = written_after(None, 1, 0, Opt::Purge);
    let k = written_after(Some(&p), 3, 1, Opt::Keep { after: 0, until: NEVER });
    assert_eq!(k.floor, 3);
    let k2 = written_after(Some(&k), 5, 2, Opt::Keep { after: 4, until: 0 });
    assert_eq!(k2.floor, 3);
    let (old, new) = (Body { ts: 2, id: 0, fire: false }, Body { ts: 4, id: 1, fire: false });
    let last = Body { ts: 6, id: 2, fire: false };
    assert!(under_purge(Some(k), Rule::Floor, &old, 4) && !under_purge(Some(k), Rule::Floor, &new, 6));
    assert_eq!(history(&[p, k], Rule::Floor, &[old, new, last], 6), [1]);
    assert_eq!(history(&[p, k], Rule::Floor, &[old, last], 6), Vec::<u32>::new());
    assert_eq!(history(&[k2], Rule::Floor, &[old, new, last], 7), [1]);
}

/// In any arrival order, at any pace, a node that drops at the first allowed moment shows, once
/// every item arrived, no more than a node holding everything, but a body that arrived after a
/// superseder of its was dropped (dated by what is held, so later: an arrival); what it lacks it
/// dropped itself (a setting current later may keep what an earlier one let go).
#[test]
fn any_order_dropping_shows_a_subset() {
    #[derive(Clone, Copy, Debug)]
    enum Item {
        S(Setting),
        B(Body),
    }
    for fire in [false, true] {
        for t in chains(2).into_iter().filter(|t| t.len() == 2) {
            let all = bodies(fire);
            let items: Vec<Item> = t.iter().map(|s| Item::S(*s)).chain(all.iter().map(|b| Item::B(*b))).collect();
            for order in perms(&items) {
                for lag in [0, 2] {
                    let (mut n, mut now) = (Eager::default(), 0);
                    let mut late: Vec<u32> = Vec::new();
                    for i in &order {
                        match i {
                            Item::S(s) => {
                                now = now.max(s.ts) + lag;
                                n.setting(*s, Rule::Floor, now)
                            }
                            Item::B(b) => {
                                now = now.max(b.ts) + lag;
                                if !b.fire && all.iter().any(|o| !o.fire && (o.ts, o.id) > (b.ts, b.id) && n.dropped.contains(&o.id)) {
                                    late.push(b.id);
                                }
                                n.body(*b, Rule::Floor, now)
                            }
                        }
                    }
                    for now in now..now + 5 {
                        n.act(Rule::Floor, now);
                        let (h, full) = (n.history(Rule::Floor, now), history(&t, Rule::Floor, &all, now));
                        assert!(h.iter().all(|x| full.contains(x) || late.contains(x)), "{order:?} now {now}: shows more");
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
/// The first admin's settings of a timeline on aspect `a`, keyed in list order, each written
/// holding the newest before it (`Setting::written_after`: the floor carried).
fn settings_of(a: Aspect, tl: &[(u64, Opt)]) -> Vec<Commit> {
    let mut out: Vec<Commit> = Vec::new();
    for (i, &(h, o)) in tl.iter().enumerate() {
        let newest = out.iter().filter(|c| c.ts <= ts(h)).max_by_key(|c| c.key()).and_then(|c| match &c.parts[0].body {
            Body::Held(Delta::Retention(x)) => Some(x.clone()),
            _ => None,
        });
        let x = Setting { rules: vec![(a.name, SettingEntry { history: o, expires: None, purge_before: 0 })], default: None, written: None }.written_after(newest.as_ref(), at(h));
        out.push(setting_by(100 + i as CommitId, FIRST_ADMIN, h, x));
    }
    out
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

// spec/commits.md §5 (The setting): bodies leave in the order they were replaced, and holding
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

// spec/commits.md §5 (the setting; in force): a setting is in force from its own commit on: one in the
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

// spec/commits.md §5 (In force), notes/engine-retention-history.md Tess's decisions, 1 and 3: the
// newest held valid setting alone decides, whatever older ones are held and in whatever order: a
// node also holding an older one shows what a node holding only the newer shows, but where the
// older purged on replace (one way: the newer carries a floor at its own stamp, so a body written
// before it is under purge on replace). Of two admins' settings at one stamp the later key
// decides, as alone. A newer setting re-shows a body still held; an older one arriving late
// changes nothing.
#[test]
fn ev_the_newest_setting_alone_decides() {
    // 10 written at 2, before the newer's stamp; replaced at 4 and 6
    let bodies = || vec![body(10, 2, false), body(11, 4, false), body(12, 6, false)];
    let view = |h: &Held| {
        let o = evaluate(h);
        (o.history.get(&(T, REG)).map(|s| s.iter().map(|x| x.1).collect::<BTreeSet<_>>()).unwrap_or_default(), o.under_purge)
    };
    for older in all_opts() {
        for newer in all_opts() {
            for now in 6..12 {
                let only = view(&world(now, &[(3, newer)], false, bodies()));
                let both = view(&world(now, &[(1, older), (3, newer)], false, bodies()));
                if older == Opt::Purge {
                    assert!(!both.0.contains(&10) && both.1.contains(&(10, 0)), "{older:?}, {newer:?} now {now}: one way");
                    let less = |s: &BTreeSet<CommitId>| s.iter().copied().filter(|c| *c != 10).collect::<BTreeSet<_>>();
                    assert_eq!(less(&both.0), less(&only.0), "{older:?}, {newer:?} now {now}");
                } else {
                    assert_eq!(both, only, "{older:?}, {newer:?} now {now}");
                }
            }
            // two admins at hour 2: node 1's key is the later
            let grant = edge(5, FIRST_ADMIN, 0, 1, Some(Role::Admin), None);
            let s = |id, by, opt| setting_by(id, by, 2, Setting { rules: vec![(REG.name, SettingEntry { history: opt, expires: None, purge_before: 0 })], default: None, written: None });
            let (lo, hi) = (s(100, FIRST_ADMIN, older), s(101, 1, newer));
            for now in 6..12 {
                let at_once = |cs: Vec<Commit>| view(&held(now, [vec![grant.clone()], cs, bodies()].concat()));
                let a = at_once(vec![lo.clone(), hi.clone()]);
                assert_eq!(at_once(vec![hi.clone(), lo.clone()]), a, "{older:?}, {newer:?} now {now}: held order");
                assert_eq!(a, at_once(vec![hi.clone()]), "{older:?}, {newer:?} now {now}: the later key decides");
            }
        }
    }
    // 10 replaced at 4, kept an hour: out at 5; a newer keep of 5 hours re-shows it, an older none
    // arriving late changes nothing
    assert!(!listed(&world(6, &[(0, keep_after(1))], false, bodies()), REG).contains(&10));
    assert!(listed(&world(6, &[(0, keep_after(1)), (5, keep_after(5))], false, bodies()), REG).contains(&10));
    assert!(listed(&world(6, &[(5, keep_after(5)), (0, Opt::None)], false, bodies()), REG).contains(&10));
}

// spec/commits.md §5 (Purge on replace; One way), notes/engine-retention-history.md Tess's
// decisions, 3: content replaced under purge on replace (the setting in force by stamp at its
// replacement purged: the oracle, from the past no node keeps) is never history at a node holding
// that setting or a later one, however late it dates the replacement (holding fewer bodies). Each
// setting is written by an admin holding those stamped before it (one written without the purging
// setting carries no floor: the writer's word, as for any default)
#[test]
fn ev_purge_on_replace_content_is_never_history_however_dated() {
    let mut reached = 0;
    for tl in ev_timelines(2, &[0, 2, 4, 6], &all_opts()).into_iter().filter(|t| t.is_sorted_by_key(|x| x.0)) {
        // 10 is replaced at 3 by 11
        let mut by_stamp = tl.clone();
        by_stamp.sort_by_key(|x| x.0);
        if by_stamp.iter().rev().find(|x| x.0 <= 3).is_none_or(|x| x.1 != Opt::Purge) {
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

// spec/commits.md §5 (One way): the greenfield counterexample, judged by `evaluate`: a keep after
// purge on replace keeps no body written before it, so a node dating the replacement after the
// keep shows none; a body written after it is kept as the keep says
#[test]
fn ev_keep_after_purge_on_replace_keeps_what_is_written_after() {
    let tl = [(1, Opt::Purge), (3, KEPT)];
    let full = vec![body(10, 0, false), body(11, 2, false), body(12, 4, false)];
    let o = evaluate(&world(5, &tl, false, full.clone()));
    assert!(o.under_purge.contains(&(10, 0)) && o.under_purge.contains(&(11, 0)));
    let fewer = vec![full[0].clone(), missing(full[1].clone(), 0), full[2].clone()];
    assert!(listed(&world(5, &tl, false, fewer), REG).is_empty(), "dated at 4, after the keep");
    // a body written after the keep is kept
    assert_eq!(listed(&world(6, &tl, false, vec![body(10, 4, false), body(11, 5, false)]), REG), [10].into());
    // a body replaced ahead of the clock is kept from a covered drop until the clock reaches it
    // where the current setting keeps history (Keep bounds, Dated only where history is kept)
    for tl in [&[(1, Opt::Purge), (3, KEPT)][..], &[(3, KEPT)][..]] {
        let h = world(5, tl, false, vec![body(10, 0, false)]);
        assert!(evaluate(&h).kept(T, REG, h.now + 1_000, at(0), h.now), "{tl:?}");
    }
    let h = world(5, &[(1, Opt::Purge)], false, vec![body(10, 0, false)]);
    assert!(!evaluate(&h).kept(T, REG, h.now + 1_000, at(0), h.now));
}

// notes/engine-retention-history.md (Tess's decisions, 2): who may purge a body changes nothing of its history
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

// spec/commits.md §5 (The setting): a setting is an admin-only delta: one by a writer is no
// setting until the writer is admin; one in an expiring commit is one until it expires; no
// validity depends on one
#[test]
fn ev_only_valid_settings_are_in_force_and_none_judges_validity() {
    let bodies = || vec![body(10, 1, false), body(11, 3, false)];
    // just after the grant: a write at its `ts` is concurrent with it (spec/permissions.md §5.2, Position)
    let by_writer = Commit { ts: ts(0) + 1, ..setting_by(19, 1, 0, Setting { rules: vec![(REG.name, SettingEntry { history: KEPT, expires: Some(HOUR), purge_before: 0 })], default: None, written: None }) };
    let grant = |role| edge(5, FIRST_ADMIN, 0, 1, Some(role), None);
    let h = held(4, [vec![grant(Role::Write), by_writer.clone()], bodies()].concat());
    assert!(listed(&h, REG).is_empty(), "a writer's setting is none");
    assert!(evaluate(&h).settings.is_empty());
    let h = held(4, [vec![grant(Role::Admin), by_writer.clone()], bodies()].concat());
    assert_eq!(listed(&h, REG), [10].into(), "an admin's is in force");
    let mut exp = setting(19, 0, REG, KEPT);
    exp.expires = Some(at(9));
    assert_eq!(listed(&held(4, [vec![exp.clone()], bodies()].concat()), REG), [10].into(), "one in an expiring commit is one");
    assert!(listed(&held(9, [vec![exp], bodies()].concat()), REG).is_empty(), "until it expires");
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

// spec/commits.md §5 (The setting: a function of the settings and bodies held): with nothing late
// a node that drops at the first allowed moment shows, at every moment, what a node keeping
// everything shows under one setting, and no more under several (a newer setting may keep what an
// earlier one let go: dropped stays dropped)
#[test]
fn ev_nothing_late_dropping_loses_no_history() {
    let mut dropped = 0;
    for fire in [false, true] {
        for tl in ev_timelines(2, &[0, 3], &all_opts()) {
            let all = [settings_of(aspect(fire), &tl), covered3(fire)].concat();
            let mut n = held(0, vec![]);
            for now in 0..9 {
                let arrive: Vec<Commit> = all.iter().filter(|c| c.ts / MS <= at(now) && !n.commits.iter().any(|x| x.id == c.id)).cloned().collect();
                n.commits.extend(arrive);
                n = eager(n, now);
                let keep_all = held(now, all.iter().filter(|c| c.ts / MS <= at(now)).cloned().collect());
                let (e, k) = (shown_writes(&n, aspect(fire)), shown_writes(&keep_all, aspect(fire)));
                assert!(e.is_subset(&k), "{tl:?} fire {fire} now {now}: shows more");
                // one setting, held before every body
                if tl.iter().all(|x| x.0 == 0) && tl.len() <= 1 {
                    assert_eq!(e, k, "{tl:?} fire {fire} now {now}");
                }
            }
            dropped += n.commits.iter().filter(|c| c.parts.iter().any(|p| matches!(p.body, Body::Dropped(_) | Body::Missing))).count();
        }
    }
    assert!(dropped > 0);
}

// spec/commits.md §5 (the setting; dropped stays dropped): in any arrival order, late, a node
// dropping at the first allowed moment never shows what a node holding everything does not, and
// what it lacks it dropped itself
#[test]
fn ev_any_order_dropping_shows_a_subset() {
    let opts = [Opt::None, keep_after(1), KEPT, Opt::Purge];
    for tl in ev_timelines(2, &[0, 2], &opts).into_iter().filter(|t| t.len() == 2) {
        let items = [settings_of(SIG, &tl), vec![body(10, 1, true), body(11, 3, true)]].concat();
        // the reference holds everything: one judgment per moment, whatever the order
        let mut full_at = std::collections::BTreeMap::new();
        for order in perms(&items) {
            let (mut n, mut now) = (held(0, vec![]), 0);
            for c in &order {
                now = now.max((wall(c.ts) - W0) / HOUR) + 2;
                n.commits.push(c.clone());
                n = eager(n, now);
            }
            for now in now..now + 3 {
                n = eager(n, now);
                let f = full_at.entry(now).or_insert_with(|| listed(&held(now, items.clone()), SIG));
                let h = listed(&n, SIG);
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

// spec/commits.md §5 (Purge on replace), AMBIGUITIES 68: content replaced under purge on
// replace is never history, even while its replacement is stamped ahead of the node's clock; a
// keep entry lists it from the moment it is held
#[test]
fn ev_purge_on_replace_never_history_ahead_of_the_clock() {
    let now = 2;
    assert!(listed(&world(now, &[(0, Opt::Purge)], false, bodies3(false)), REG).is_empty());
    assert!(listed(&world(now, &[(0, Opt::None)], false, bodies3(false)), REG).is_empty());
    assert!(listed(&world(now, &[(0, Opt::Keep { after: 1, until: 0 })], false, bodies3(false)), REG).contains(&10));
}
}
