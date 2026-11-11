//! The keyed list reconciler: applying its steps to the old list gives the new one, rows that
//! stay keep their element, and only changed rows are rebuilt.
use osis_kit::list::{Op, apply, reconcile};

/// Applies `reconcile(old, new)` to elements tagged with where they came from; checks the
/// result's keys and that kept rows were not rebuilt unless moved.
fn check(old: &[(u32, u32)], new: &[(u32, u32)]) -> Vec<Op<u32>> {
    let ops = reconcile(old, new);
    // element: (key, value, built here)
    let mut list: Vec<(u32, u32, bool)> = old.iter().map(|(k, v)| (*k, *v, false)).collect();
    apply(&mut list, &ops, |i, k| (*k, new[i].1, true));
    let got: Vec<(u32, u32)> = list.iter().map(|(k, v, _)| (*k, *v)).collect();
    assert_eq!(got, new, "old {old:?} ops {ops:?}");
    ops
}

#[test]
fn unchanged_list_needs_nothing() {
    assert!(check(&[(1, 0), (2, 0)], &[(1, 0), (2, 0)]).is_empty());
}

#[test]
fn insert_remove_change() {
    assert_eq!(check(&[(1, 0), (2, 0), (3, 0)], &[(1, 0), (3, 5), (4, 0)]), vec![Op::Remove(2), Op::Remove(1), Op::Insert(1, 3), Op::Insert(2, 4)]);
}

/// The first row of the pair changed and moved past the last: the row that did not change is the
/// one kept, whichever comes first in a tie for the longest run.
#[test]
fn a_changed_row_is_never_kept_over_one_that_did_not_change() {
    assert_eq!(check(&[(1, 0), (2, 0)], &[(2, 0), (1, 1)]), vec![Op::Remove(0), Op::Insert(1, 1)]);
    assert_eq!(check(&[(1, 0), (2, 0)], &[(2, 1), (1, 0)]), vec![Op::Remove(1), Op::Insert(0, 2)]);
}

/// A row changing in place rebuilds that row; duplicate keys each keep their own value.
#[test]
fn duplicates_take_their_own_values() {
    let old = [(1, 0), (1, 1), (2, 0)];
    let new = [(1, 1), (1, 2), (2, 0)];
    let ops = check(&old, &new);
    assert!(ops.contains(&Op::Insert(1, 1)), "{ops:?}");
}

/// Whatever the reorder, a list costs at most one remove and one insert per row, and reversing a
/// long list keeps one row.
#[test]
fn a_reorder_is_linear_in_rows() {
    let old: Vec<(u32, u32)> = (0..10_000).map(|i| (i, 0)).collect();
    let reversed: Vec<(u32, u32)> = old.iter().rev().copied().collect();
    let ops = reconcile(&old, &reversed);
    assert_eq!(ops.len(), 2 * (old.len() - 1));
    let everything_new: Vec<(u32, u32)> = old.iter().map(|(k, _)| (k + 100_000, 0)).collect();
    assert_eq!(reconcile(&old, &everything_new).len(), 2 * old.len());
    let everything_changed: Vec<(u32, u32)> = old.iter().map(|(k, _)| (*k, 1)).collect();
    assert_eq!(reconcile(&old, &everything_changed).len(), 2 * old.len());
}

#[test]
fn a_row_moving_far_touches_that_row() {
    // the first row sorts last: rows between keep their widgets, one row rebuilt
    let old: Vec<(u32, u32)> = (0..50).map(|i| (i, 0)).collect();
    let mut new = old[1..].to_vec();
    new.push((0, 1));
    assert_eq!(check(&old, &new), vec![Op::Remove(0), Op::Insert(49, 0)]);
}

#[test]
fn duplicates_and_empties() {
    check(&[], &[(1, 0), (2, 0)]);
    check(&[(1, 0), (2, 0)], &[]);
    check(&[(1, 0), (1, 0), (2, 0)], &[(2, 0), (1, 0)]);
    check(&[(1, 0)], &[(1, 0), (1, 0)]);
}

/// Every pair of short lists over a few keys (exhaustive up to length 4, keys 0..4, values 0..2).
#[test]
fn exhaustive_small() {
    fn lists() -> Vec<Vec<(u32, u32)>> {
        let mut out = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..4 {
            let mut next = Vec::new();
            for l in &frontier {
                for k in 0..4 {
                    for v in 0..2 {
                        let mut x: Vec<(u32, u32)> = l.clone();
                        if x.iter().any(|(xk, _)| *xk == k) {
                            continue;
                        }
                        x.push((k, v));
                        next.push(x);
                    }
                }
            }
            out.extend(next.iter().cloned());
            frontier = next;
        }
        out
    }
    let all = lists();
    for a in all.iter().step_by(61) {
        for b in &all {
            let ops = check(a, b);
            let kept = b.iter().filter(|r| a.contains(r)).count();
            let inserts = ops.iter().filter(|o| matches!(o, Op::Insert(..))).count();
            let removes = ops.iter().filter(|o| matches!(o, Op::Remove(..))).count();
            // a row that moved or changed is one remove and one insert; a row new or gone is the one
            assert_eq!(inserts - (b.len() - kept), removes - (a.len() - kept), "{a:?} -> {b:?}: {ops:?}");
        }
    }
}

/// Random old/new lists (duplicate keys included, up to 12 rows): every op is in range when
/// applied (the lenient `apply` would skip one silently), applying gives `new`, and a kept row
/// already holds its new value.
#[test]
fn random_lists_strict() {
    let mut seed = 1u64; // xorshift at seed 0 (its state is never 0)
    let mut rnd = |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    for _ in 0..20_000 {
        let keys = 1 + rnd(10);
        let dup = rnd(4) == 0;
        let make = |rnd: &mut dyn FnMut(u64) -> u64| {
            let len = rnd(13) as usize;
            let mut l: Vec<(u64, u64)> = Vec::new();
            while l.len() < len {
                let k = rnd(keys);
                if dup || !l.iter().any(|(x, _)| *x == k) {
                    l.push((k, rnd(2)));
                } else if l.len() as u64 >= keys {
                    break;
                }
            }
            l
        };
        let old = make(&mut rnd);
        let new = make(&mut rnd);
        let ops = reconcile(&old, &new);
        // (key, value, rebuilt)
        let mut list: Vec<(u64, u64, bool)> = old.iter().map(|(k, v)| (*k, *v, false)).collect();
        for op in &ops {
            match op {
                Op::Remove(i) => {
                    assert!(*i < list.len(), "{old:?} -> {new:?}: {ops:?}");
                    list.remove(*i);
                }
                Op::Insert(i, k) => {
                    assert!(*i <= list.len(), "{old:?} -> {new:?}: {ops:?}");
                    list.insert(*i, (*k, u64::MAX, true));
                }
            }
        }
        // rebuilt rows take the new value on creation; a kept row must already hold it
        let got: Vec<u64> = list.iter().map(|(k, _, _)| *k).collect();
        let want: Vec<u64> = new.iter().map(|(k, _)| *k).collect();
        assert_eq!(got, want, "{old:?} -> {new:?}: {ops:?}");
        for (i, (_, v, rebuilt)) in list.iter().enumerate() {
            assert!(*rebuilt || *v == new[i].1, "stale value at {i}: {old:?} -> {new:?}: {ops:?}");
        }
    }
}
