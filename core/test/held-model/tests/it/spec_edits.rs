//! Signal edits (notes/signal-edits-design.md, held_model::edits). Properties checked over every subset
//! of small worlds, smallest first, so a failure names a minimal counterexample.
use crate::util::*;
use held_model::edits::{listed, listing, Entry, Shows};
use held_model::*;

const SIG: Aspect = Aspect::signal(5);
const SIG2: Aspect = Aspect::signal(6);
const FOREVER_KEPT: Retention = Retention { by: PurgeBy::AuthorOrAdmin, history: History::Keep { until: FOREVER, after: 0 } };
const A: NodeId = 1;
const B: NodeId = 2;
const X: NodeId = 3;

fn fire(id: CommitId, author: NodeId, h: u64, r: Retention) -> Commit {
    reg(id, author, h, SIG, r, id as i64)
}
fn edit(id: CommitId, author: NodeId, h: u64, r: Retention, of: CommitId) -> Commit {
    let mut c = fire(id, author, h, r);
    c.parts[0].replaces = Some(of);
    c
}
fn expiring(mut c: Commit, h: u64) -> Commit {
    c.expires = Some(at(h));
    c
}
fn purge_of(id: CommitId, author: NodeId, h: u64, target: CommitId) -> Commit {
    purge(id, author, h, PurgeItem::Commit { commit: target, thing: T, aspect: SIG })
}
fn grants() -> Vec<Commit> {
    vec![edge(1, FIRST_ADMIN, 0, A, Some(Role::Write), None), edge(2, FIRST_ADMIN, 0, B, Some(Role::Write), None), edge(3, FIRST_ADMIN, 0, X, Some(Role::Admin), None)]
}
fn world(now: u64, set: &[Commit]) -> Held {
    let mut c = grants();
    c.extend_from_slice(set);
    held(now, c)
}
fn at_sig(h: &Held) -> Vec<Entry> {
    listing(h).remove(&(T, SIG)).unwrap_or_default()
}
fn shown(h: &Held) -> Vec<(CommitId, CommitId, Shows)> {
    at_sig(h).into_iter().map(|e| (e.place.1, e.version, e.shows)).collect()
}
fn val(id: CommitId) -> Shows {
    Shows::Value(Value::Int(id as i64))
}
/// Each subset of `u` smallest first, with the commits of `u` it holds.
fn each_subset(u: &[Commit], mut f: impl FnMut(&[Commit])) {
    let mut masks: Vec<u32> = (0..1u32 << u.len()).collect();
    masks.sort_by_key(|m| m.count_ones());
    for m in masks {
        let s: Vec<Commit> = u.iter().enumerate().filter(|(i, _)| m >> i & 1 == 1).map(|(_, c)| c.clone()).collect();
        f(&s);
    }
}
fn ids(s: &[Commit]) -> Vec<CommitId> {
    s.iter().map(|c| c.id).collect()
}
fn without(s: &[Commit], gone: &[CommitId]) -> Vec<Commit> {
    s.iter().filter(|c| !gone.contains(&c.id)).cloned().collect()
}
/// The shape every property reasons about: same-actor versions on one original.
fn u_edits(r: Retention) -> Vec<Commit> {
    vec![fire(10, A, 1, r), edit(11, A, 2, r, 10), edit(12, A, 3, r, 10)]
}

// the rule, one honored example: reads as the newest, keeps its place and order
#[test]
fn an_edit_reads_in_the_originals_place() {
    let r = FOREVER_KEPT;
    let s = [fire(10, A, 1, r), fire(20, B, 2, r), edit(11, A, 3, r, 10), edit(12, A, 4, r, 10)];
    assert_eq!(shown(&world(9, &s)), vec![(10, 12, val(12)), (20, 20, val(20))]);
}

/// Nodes holding the same commits read alike: any node, any order of the commits.
fn alike(u: &[Commit], nows: &[u64]) {
    each_subset(u, |s| {
        for &n in nows {
            let w = world(n, s);
            let want = listing(&w);
            let mut rev = w.clone();
            rev.commits.reverse();
            assert_eq!(listing(&rev), want, "order: {:?} now {n}", ids(s));
            for me in [A, B, X] {
                assert_eq!(listing(&Held { me, ..w.clone() }), want, "me {me}: {:?} now {n}", ids(s));
            }
        }
    });
}

// every claim shape that is not honored, forged or dangling
fn u_forged() -> Vec<Commit> {
    let r = FOREVER_KEPT;
    let mut u = u_edits(r);
    u.push(edit(30, B, 4, r, 10)); // another actor's claim
    u.push(Commit { actor: A, ..edit(31, B, 4, r, 10) }); // actor claimed, not verified: invalid
    u.push(edit(32, A, 4, r, 11)); // names a version (chain)
    u.push(edit(33, A, 0, r, 10)); // sorts before it
    let mut other = edit(34, A, 4, r, 10); // on another aspect
    other.parts[0] = part(SIG2, r, vec![set(4, 34, 34)]);
    other.parts[0].replaces = Some(10);
    u.push(other);
    u.push(edit(35, A, 4, r, 999)); // names nothing
    u
}

/// Where the forged commit's own message sits: at its own place, or nowhere when it is invalid.
fn forged_entry(id: CommitId, h: &Held) -> Vec<(u64, CommitId)> {
    if id == 31 {
        return vec![];
    }
    let c = h.commits.iter().find(|c| c.id == id).unwrap();
    vec![(c.ts, c.id)]
}

// A forged claim changes no reading except adding the forger's own message
#[test]
fn forged_claims_change_only_the_forgers_own_place() {
    let forged = [30u32, 31, 32, 33, 34, 35];
    each_subset(&u_forged(), |s| {
        for &f in forged.iter().filter(|f| ids(s).contains(f)) {
            let w = world(9, s);
            let full = listing(&w);
            let less = listing(&world(9, &without(s, &[f])));
            let places = forged_entry(f, &w);
            let mut got = full.clone();
            for es in got.values_mut() {
                es.retain(|e| !places.contains(&e.place));
            }
            got.retain(|_, es| !es.is_empty());
            let mut want = less;
            want.retain(|_, es| !es.is_empty());
            assert_eq!(got, want, "forged {f} of {:?}", ids(s));
            for e in full.values().flatten() {
                assert!(e.version != f || places.contains(&e.place), "{f} took the place of another: {:?}", ids(s));
            }
            for place in &places {
                let own = full.values().flatten().find(|e| e.place == *place).unwrap_or_else(|| panic!("{f}'s own message is missing: {:?}", ids(s)));
                assert_eq!((own.version, &own.shows), (f, &val(f)), "{f} of {:?}", ids(s));
            }
        }
    });
}

#[test]
fn nodes_holding_the_same_commits_read_alike() {
    alike(&u_forged(), &[9]);
    alike(&u_validity(), &[9]);
    alike(&u_purge(Retention::PLAIN.after(2 * HOUR)), &[6, 7]);
    alike(&u_expiry(), &[5, 7]);
}

/// A reading depends only on what is listed: a held commit not listed reads as one never held
/// (an edit turned invalid or expired shows the previous version). `ends`: (original, purge) pairs;
/// a purged-out original's header still ends the message.
fn unlisted_counts_for_nothing(u: &[Commit], nows: &[u64], signals: &[CommitId], ends: &[(CommitId, CommitId)]) {
    each_subset(u, |s| {
        for &n in nows {
            let w = world(n, s);
            let all = at_sig(&w);
            let on = listed(&w);
            for &c in signals.iter().filter(|c| ids(s).contains(c) && !on.contains(c) && !ends.iter().any(|(o, p)| o == *c && ids(s).contains(p))) {
                assert_eq!(all, at_sig(&world(n, &without(s, &[c]))), "{c} unlisted in {:?} now {n}", ids(s));
            }
        }
    });
}

fn u_validity() -> Vec<Commit> {
    let r = FOREVER_KEPT;
    let mut u = u_edits(r);
    u.push(edge(40, X, 4, A, None, Some(vec![]))); // kick, all A's writes fall
    u.push(edge(41, X, 4, A, None, Some(vec![10, 11, 12]))); // kick, all stay
    u.push(edge(42, X, 4, A, None, Some(vec![10]))); // the original stays, the edits fall
    u.push(edge(43, X, 4, A, None, Some(vec![11]))); // the edit stays, the original falls
    u.push(edge(44, FIRST_ADMIN, 5, X, None, Some(vec![]))); // the kicker's kicks fall: A's writes return
    u
}

// an edit turned invalid (or expired) shows the previous version: unlisted, it counts for nothing
#[test]
fn an_unlisted_commit_counts_for_nothing() {
    unlisted_counts_for_nothing(&u_validity(), &[9], &[10, 11, 12], &[]);
    unlisted_counts_for_nothing(&u_expiry(), &[1, 3, 4, 5, 6, 7, 9], &[10, 11, 12, 13], &[]);
    unlisted_counts_for_nothing(&u_purge(Retention::PLAIN.after(2 * HOUR)), &[4, 6, 7, 9, 12], &[10, 11, 12], &[(10, 52)]);
}

// An invalid original takes its versions with it (no entry at its place), and they return when it
// re-validates, in any order the commits arrive: a function of the held set
#[test]
fn an_invalid_original_loses_its_place_and_returns_with_it() {
    each_subset(&u_validity(), |s| {
        let w = world(9, s);
        let o = evaluate(&w);
        let held = ids(s);
        let valid = |c: CommitId| o.valid.get(&(c, 0)) == Some(&true);
        if held.contains(&10) && !valid(10) {
            assert!(at_sig(&w).iter().all(|e| e.place.1 != 10), "{held:?}");
        }
        // the kicker's fall re-validates: as if the kicks were never held
        if held.contains(&44) {
            let was = at_sig(&world(9, &without(s, &[40, 41, 42, 43, 44])));
            assert_eq!(at_sig(&w), was, "{held:?}");
        }
    });
}

// A valid edit of an invalid original is a fire of its own, at its own place; it folds when the
// original is valid
#[test]
fn a_valid_edit_of_an_invalid_original_stands_alone_until_it_validates() {
    let r = FOREVER_KEPT;
    let s = [fire(10, A, 1, r), edit(11, A, 3, r, 10)];
    let granted_at = |h| held(9, vec![edge(1, FIRST_ADMIN, h, A, Some(Role::Write), None), s[0].clone(), s[1].clone()]);
    assert_eq!(shown(&granted_at(2)), vec![(11, 11, val(11))]);
    assert_eq!(shown(&granted_at(0)), vec![(10, 11, val(11))]);
}

fn u_purge(r: Retention) -> Vec<Commit> {
    let mut u = u_edits(r);
    u.push(purge_of(50, A, 5, 12));
    u.push(purge_of(51, A, 5, 11));
    u.push(purge_of(52, A, 5, 10));
    u.push(purge_of(53, X, 5, 12));
    u
}

// A purged newest version keeps older ones from returning, at every time, when versions share
// retention (a required rule makes them)
#[test]
fn a_purged_newest_version_keeps_older_ones_gone() {
    for r in [FOREVER_KEPT, Retention::PLAIN.until(at(8)), Retention::PLAIN.after(2 * HOUR)] {
        each_subset(&u_purge(r), |s| {
            for n in [6u64, 7, 8, 9, 12, 20] {
                let w = world(n, s);
                let o = evaluate(&w);
                let purged = |c| o.purged.keys().any(|&(x, _)| x == c);
                for e in at_sig(&w).iter().filter(|e| e.place.1 == 10) {
                    if let Shows::Value(_) = e.shows {
                        assert!(!ids(s).iter().any(|&c| c > e.version && matches!(c, 11 | 12) && purged(c)), "{:?} now {n}: {e:?}", ids(s));
                    }
                }
            }
        });
    }
}

// Limit: a purged edit with a shorter keep than older versions lets them return when its tombstone
// ends. Purging old text names the earlier versions in the same commit, so nothing returns.
#[test]
fn a_purged_edit_with_a_shorter_keep_is_a_stated_limit() {
    let short = Retention::PLAIN.after(2 * HOUR);
    let s = [fire(10, A, 1, FOREVER_KEPT), edit(11, A, 2, short, 10), purge_of(50, A, 3, 11)];
    assert_eq!(shown(&world(4, &s)), vec![(10, 11, Shows::Purged)]);
    assert_eq!(shown(&world(6, &s)), vec![(10, 10, val(10))]);
    let mut v = edit(11, A, 2, short, 10);
    v.purge.push(PurgeItem::Commit { commit: 10, thing: T, aspect: SIG });
    let s = [fire(10, A, 1, FOREVER_KEPT), v, purge_of(50, A, 3, 11)];
    assert_eq!(shown(&world(3000, &s)), vec![(10, 10, Shows::Purged)]);
}

// A purge of the original by any commit but one of its own versions ends the message: racing and
// later versions no longer show, also once its tombstone is gone
#[test]
fn a_purge_of_the_original_ends_the_message() {
    let r = FOREVER_KEPT;
    let race = [fire(10, A, 1, r), edit(11, A, 3, r, 10), purge_of(50, X, 2, 10)];
    assert_eq!(shown(&world(9, &race)), vec![(10, 10, Shows::Purged)]);
    let later = [fire(10, A, 1, r), purge_of(50, A, 2, 10), edit(11, A, 3, r, 10), edit(12, A, 4, r, 10)];
    assert_eq!(shown(&world(9, &later)), vec![(10, 10, Shows::Purged)]);
    let long = Retention::PLAIN.after(9 * HOUR);
    let gone = [fire(10, A, 1, Retention::PLAIN.after(2 * HOUR)), edit(11, A, 3, long, 10), purge_of(50, X, 2, 10)];
    assert_eq!(shown(&world(8, &gone)), vec![]);
    // a version purging it too does not undo the moderator's end
    let mut own = edit(11, A, 3, r, 10);
    own.purge.push(PurgeItem::Commit { commit: 10, thing: T, aspect: SIG });
    assert_eq!(shown(&world(9, &[fire(10, A, 1, r), own, purge_of(5, X, 2, 10)])), vec![(10, 10, Shows::Purged)]);
    // another actor's claim on it stays that actor's own message
    let forged = [fire(10, A, 1, r), purge_of(50, X, 2, 10), edit(30, B, 3, r, 10)];
    assert_eq!(shown(&world(9, &forged)), vec![(10, 10, Shows::Purged), (30, 30, val(30))]);
}

// An edit that purges every earlier version in its own commit stays honored: old text gone, the new
// text in the original's place
#[test]
fn an_edit_purging_earlier_versions_stays_honored() {
    let r = FOREVER_KEPT;
    let mut v = edit(11, A, 3, r, 10);
    v.purge.push(PurgeItem::Commit { commit: 10, thing: T, aspect: SIG });
    let w = world(9, &[fire(10, A, 1, r), v]);
    assert_eq!(shown(&w), vec![(10, 11, val(11))]);
    assert!(evaluate(&w).purged.contains_key(&(10, 0)));
}

fn u_expiry() -> Vec<Commit> {
    let r = FOREVER_KEPT;
    vec![
        expiring(fire(10, A, 1, r), 6),
        expiring(edit(11, A, 2, r, 10), 6),
        expiring(edit(12, A, 3, r, 10), 4),  // shorter: the previous version shows after it
        expiring(edit(13, A, 3, r, 10), 8),  // longer: stands alone once the original is gone
    ]
}

// An edit expired shows the previous; an over-long one stands alone at its own place once the
// original has expired. At every time.
#[test]
fn expiry_shows_the_previous_or_stands_alone() {
    each_subset(&u_expiry(), |s| {
        if !ids(s).contains(&10) {
            return;
        }
        for n in 1u64..10 {
            let w = world(n, s);
            let exp = |c: &Commit| c.expires.is_some_and(|t| at(n) >= t);
            for e in at_sig(&w) {
                assert!(!exp(s.iter().find(|c| c.id == e.version).unwrap()), "{:?} now {n}: {e:?}", ids(s));
            }
            if n >= 6 {
                assert!(at_sig(&w).iter().all(|e| e.place.1 != 10), "{:?} now {n}", ids(s));
            }
        }
    });
}

// Limit: an original past its keep reads like one never held (the version alone), and the jump to its
// own place happens at every node, also with one shared `after`.
#[test]
fn a_gone_original_reads_like_one_never_held() {
    let keep = Retention::PLAIN.after(2 * HOUR);
    let (o, v) = (fire(10, A, 1, keep), edit(11, A, 2, keep, 10));
    let both = [o, v.clone()];
    assert_eq!(shown(&world(2, &both)), vec![(10, 11, val(11))]);
    assert_eq!(shown(&world(3, &both)), vec![(11, 11, val(11))]);
    assert_eq!(shown(&world(5, &both)), shown(&world(5, &[v.clone()])));
    assert_eq!(shown(&world(5, &[v.clone()])), vec![]); // past D of the version too
    let v2 = edit(12, A, 2, Retention::PLAIN.after(5 * HOUR), 10);
    assert_eq!(shown(&world(5, &[fire(10, A, 1, keep), v2.clone()])), shown(&world(5, &[v2.clone()])));
    assert_eq!(shown(&world(5, &[v2])), vec![(12, 12, val(12))]);
}
