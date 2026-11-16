//! The keyed list reconciler: applying its steps to the old list gives the new one (every step in
//! range), rows that stay keep their element, and only changed rows are rebuilt.
use osis_kit::view::keyed::{Op, reconcile};
use std::fmt::Debug;
use std::hash::Hash;

/// Applies `reconcile(old, new)` to `old` as a list widget takes it, inserted rows taking their
/// new value: the result is `new` only if every step is in range and every kept row already held
/// its value.
fn check<K: Eq + Hash + Clone + Debug, V: Clone + PartialEq + Debug>(old: &[(K, V)], new: &[(K, V)]) -> Vec<Op<K>> {
    let ops = reconcile(old, new);
    let mut got = old.to_vec();
    for op in &ops {
        match op {
            Op::Remove(i) => drop(got.remove(*i)),
            Op::Insert(i, k) => got.insert(*i, (k.clone(), new[*i].1.clone())),
        }
    }
    assert_eq!(got, new, "old {old:?} ops {ops:?}");
    ops
}

#[test]
fn unchanged_list_needs_nothing() {
    assert!(check(&[(1, 0), (2, 0)], &[(1, 0), (2, 0)]).is_empty());
}

/// The first row of the pair changed and moved past the last: the row that did not change is the
/// one kept, whichever comes first in a tie for the longest run.
#[test]
fn a_changed_row_is_never_kept_over_one_that_did_not_change() {
    assert_eq!(check(&[(1, 0), (2, 0)], &[(2, 0), (1, 1)]), vec![Op::Remove(0), Op::Insert(1, 1)]);
    assert_eq!(check(&[(1, 0), (2, 0)], &[(2, 1), (1, 0)]), vec![Op::Remove(1), Op::Insert(0, 2)]);
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

/// Random old/new lists (duplicate keys included, up to 12 rows): every op is in range, applying
/// gives `new`, and a kept row already holds its new value.
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
        check(&old, &new);
    }
}
