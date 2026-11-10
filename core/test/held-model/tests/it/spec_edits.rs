//! Signal edits (notes/signal-edits-design.md, held_model::edits). Properties checked over every subset
//! of small worlds, smallest first, so a failure names a minimal counterexample.
use crate::util::*;
use held_model::edits::{listed, listing, Entry, Shows};
use held_model::*;

const SIG: Aspect = Aspect::signal(5);
const SIG2: Aspect = Aspect::signal(6);
const A: NodeId = 1;
const B: NodeId = 2;
const X: NodeId = 3;

fn fire(id: CommitId, author: NodeId, h: u64) -> Commit {
    reg(id, author, h, SIG, Retention::PLAIN, id as i64)
}
fn edit(id: CommitId, author: NodeId, h: u64, of: CommitId) -> Commit {
    let mut c = fire(id, author, h);
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
/// The grants, `set`, and unless `set` holds a `retention^.0` setting, one keeping every AK for good.
fn world(now: u64, set: &[Commit]) -> Held {
    let mut c = grants();
    if !set.iter().any(|c| c.parts.iter().any(|p| p.aspect == Aspect::RETENTION)) {
        c.push(setting_by(4, FIRST_ADMIN, 0, Setting { rules: vec![], default: Some(SettingEntry { history: KEPT, expires: None }) }));
    }
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
fn u_edits() -> Vec<Commit> {
    vec![fire(10, A, 1), edit(11, A, 2, 10), edit(12, A, 3, 10)]
}

// the rule, one honored example: reads as the newest, keeps its place and order
#[test]
fn an_edit_reads_in_the_originals_place() {
    let s = [fire(10, A, 1), fire(20, B, 2), edit(11, A, 3, 10), edit(12, A, 4, 10)];
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
    let mut u = u_edits();
    u.push(edit(30, B, 4, 10)); // another actor's claim
    u.push(Commit { actor: A, ..edit(31, B, 4, 10) }); // actor claimed, not verified: invalid
    u.push(edit(32, A, 4, 11)); // names a version (chain)
    u.push(edit(33, A, 0, 10)); // sorts before it
    let mut other = edit(34, A, 4, 10); // on another aspect
    other.parts[0] = part(SIG2, Retention::PLAIN, vec![set(4, 34, 34)]);
    other.parts[0].replaces = Some(10);
    u.push(other);
    u.push(edit(35, A, 4, 999)); // names nothing
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
    alike(&u_purge(keep_after(2)), &[6, 7]);
    alike(&u_expiry(), &[5, 7]);
    alike(&[missing(fire(10, A, 1), 0), edit(11, A, 2, 10), missing(edit(12, A, 3, 10), 0), edit(30, B, 4, 10)], &[9]);
}

/// A reading depends only on what is listed: a held commit not listed reads as one never held
/// (an edit turned invalid or expired shows the previous version).
fn unlisted_counts_for_nothing(u: &[Commit], nows: &[u64], signals: &[CommitId]) {
    each_subset(u, |s| {
        for &n in nows {
            let w = world(n, s);
            let all = at_sig(&w);
            let on = listed(&w);
            for &c in signals.iter().filter(|c| ids(s).contains(c) && !on.contains(c)) {
                assert_eq!(all, at_sig(&world(n, &without(s, &[c]))), "{c} unlisted in {:?} now {n}", ids(s));
            }
        }
    });
}

fn u_validity() -> Vec<Commit> {
    let mut u = u_edits();
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
    unlisted_counts_for_nothing(&u_validity(), &[9], &[10, 11, 12]);
    unlisted_counts_for_nothing(&u_expiry(), &[1, 3, 4, 5, 6, 7, 9], &[10, 11, 12, 13]);
    unlisted_counts_for_nothing(&u_purge(keep_after(2)), &[4, 6, 7, 9, 12], &[10, 11, 12]);
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
    let s = [fire(10, A, 1), edit(11, A, 3, 10)];
    let granted_at = |h| held(9, vec![edge(1, FIRST_ADMIN, h, A, Some(Role::Write), None), setting(4, 0, SIG, KEPT), s[0].clone(), s[1].clone()]);
    assert_eq!(shown(&granted_at(2)), vec![(11, 11, val(11))]);
    assert_eq!(shown(&granted_at(0)), vec![(10, 11, val(11))]);
}

/// Versions, purges of each, and the signal's window `opt` (its setting in every subset).
fn u_purge(opt: Opt) -> Vec<Commit> {
    let mut u = u_edits();
    u.push(setting(5, 0, SIG, opt));
    u.push(purge_of(50, A, 5, 12));
    u.push(purge_of(51, A, 5, 11));
    u.push(purge_of(52, A, 5, 10));
    u.push(purge_of(53, X, 5, 12));
    u
}

// A purged newest version keeps older ones from returning, at every time: versions share their
// aspect's window, each from its own `ts`
#[test]
fn a_purged_newest_version_keeps_older_ones_gone() {
    for opt in [KEPT, keep_until(8), keep_after(2)] {
        each_subset(&u_purge(opt), |s| {
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

// One window per aspect: a purged edit's tombstone, listed from its request's `ts`, outlasts the
// versions before it, so none returns when it ends. Purging old text names the earlier versions too.
#[test]
fn a_purged_edits_tombstone_outlasts_older_versions() {
    let w = setting(5, 0, SIG, keep_after(2));
    let s = [w.clone(), fire(10, A, 1), edit(11, A, 2, 10), purge_of(50, A, 3, 11)];
    assert_eq!(shown(&world(2, &s)), vec![(10, 11, Shows::Purged)]);
    // the original left at 3: the tombstone stands alone until 5, and 10 never shows again
    assert_eq!(shown(&world(4, &s)), vec![(11, 11, Shows::Purged)]);
    assert_eq!(shown(&world(5, &s)), vec![]);
    let mut v = edit(11, A, 2, 10);
    v.purge.push(PurgeItem::Commit { commit: 10, thing: T, aspect: SIG });
    let s = [fire(10, A, 1), v, purge_of(50, A, 3, 11)];
    assert_eq!(shown(&world(3000, &s)), vec![(10, 11, Shows::Purged)]);
}

// A purge takes only what it names: a racing or later version of a purged original still shows, in
// its place while the tombstone is listed and at its own once it is not; no more than a new message
// could do. A deletion meant to hold names the versions too.
#[test]
fn a_purge_takes_only_what_it_names() {
    let race = [fire(10, A, 1), edit(11, A, 3, 10), purge_of(50, X, 2, 10)];
    assert_eq!(shown(&world(9, &race)), vec![(10, 11, val(11))]);
    let later = [fire(10, A, 1), purge_of(50, A, 2, 10), edit(11, A, 3, 10), edit(12, A, 4, 10)];
    assert_eq!(shown(&world(9, &later)), vec![(10, 12, val(12))]);
    // the tombstone (from 2) ends before the version (from 3): it shows at its own place
    let gone = [setting(5, 0, SIG, keep_after(2)), fire(10, A, 1), edit(11, A, 3, 10), purge_of(50, X, 2, 10)];
    assert_eq!(shown(&world(4, &gone)), vec![(11, 11, val(11))]);
    // naming the version too takes it
    let both = [fire(10, A, 1), edit(11, A, 3, 10), purge_of(50, X, 4, 10), purge_of(51, X, 4, 11)];
    assert_eq!(shown(&world(9, &both)), vec![(10, 11, Shows::Purged)]);
    // another actor's claim on it stays that actor's own message
    let forged = [fire(10, A, 1), purge_of(50, X, 2, 10), edit(30, B, 3, 10)];
    assert_eq!(shown(&world(9, &forged)), vec![(10, 10, Shows::Purged), (30, 30, val(30))]);
}

// An edit that purges every earlier version in its own commit stays honored: old text gone, the new
// text in the original's place
#[test]
fn an_edit_purging_earlier_versions_stays_honored() {
    let mut v = edit(11, A, 3, 10);
    v.purge.push(PurgeItem::Commit { commit: 10, thing: T, aspect: SIG });
    let w = world(9, &[fire(10, A, 1), v]);
    assert_eq!(shown(&w), vec![(10, 11, val(11))]);
    assert!(evaluate(&w).purged.contains_key(&(10, 0)));
}

fn u_expiry() -> Vec<Commit> {
    vec![
        expiring(fire(10, A, 1), 6),
        expiring(edit(11, A, 2, 10), 6),
        expiring(edit(12, A, 3, 10), 4),  // shorter: the previous version shows after it
        expiring(edit(13, A, 3, 10), 8),  // longer: stands alone once the original is gone
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

// Limit: an original out of history reads like one never held (the version alone), and the jump
// to its own place happens at every node.
#[test]
fn a_gone_original_reads_like_one_never_held() {
    let keep = setting(5, 0, SIG, keep_after(2));
    let (o, v) = (fire(10, A, 1), edit(11, A, 2, 10));
    let both = [keep.clone(), o, v.clone()];
    assert_eq!(shown(&world(2, &both)), vec![(10, 11, val(11))]);
    assert_eq!(shown(&world(3, &both)), vec![(11, 11, val(11))]);
    assert_eq!(shown(&world(3, &both)), shown(&world(3, &[keep.clone(), v.clone()])));
    assert_eq!(shown(&world(4, &[keep, v])), vec![]); // out of history too
}

// Listing is judged from headers: an original whose body is not here holds its versions' place, and
// reads as its newest version whose body is here; a version whose body is not here reads as nothing
#[test]
fn an_original_without_its_body_keeps_its_versions() {
    let s = [missing(fire(10, A, 1), 0), edit(11, A, 2, 10), missing(edit(12, A, 3, 10), 0)];
    assert_eq!(shown(&world(9, &s)), vec![(10, 11, val(11))]);
    let s = [missing(fire(10, A, 1), 0), missing(edit(11, A, 2, 10), 0)];
    assert_eq!(shown(&world(9, &s)), vec![(10, 10, Shows::NotFetched)]);
    let s = [fire(10, A, 1), missing(edit(11, A, 2, 10), 0)];
    assert_eq!(shown(&world(9, &s)), vec![(10, 10, val(10))]);
}

// spec/commits.md §5 Purge: a request that expires reaches only deltas expiring no later than it
#[test]
fn an_expiring_request_reaches_only_earlier_expiries() {
    let item = |c| PurgeItem::Commit { commit: c, thing: T, aspect: SIG };
    let mut rq = expiring(purge(50, A, 4, item(10)), 6);
    rq.purge.extend([item(11), item(12)]);
    let s = [fire(10, A, 1), expiring(fire(11, A, 2), 5), expiring(fire(12, A, 3), 8), rq];
    let o = evaluate(&world(4, &s));
    assert!(!o.purged.contains_key(&(10, 0)), "no expiry: out of reach");
    assert!(o.purged.contains_key(&(11, 0)));
    assert!(!o.purged.contains_key(&(12, 0)), "expires later than the request");
}
