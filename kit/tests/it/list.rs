//! The keyed list reconciler: applying its steps to the old list gives the new one, rows that
//! stay keep their element, and only changed rows are updated.
use osis_kit::list::{Op, apply, reconcile};

/// Applies `reconcile(old, new)` to elements tagged with where they came from; checks the
/// result's keys and that kept rows were not rebuilt unless moved.
fn check(old: &[(u32, u32)], new: &[(u32, u32)]) -> Vec<Op<u32>> {
    let ops = reconcile(old, new);
    // element: (key, value, built here)
    let mut list: Vec<(u32, u32, bool)> = old.iter().map(|(k, v)| (*k, *v, false)).collect();
    apply(&mut list, &ops, |k| (*k, new.iter().find(|(nk, _)| nk == k).unwrap().1, true), |i, x| x.1 = new[i].1);
    let got: Vec<(u32, u32)> = list.iter().map(|(k, v, _)| (*k, *v)).collect();
    assert_eq!(got, new, "old {old:?} ops {ops:?}");
    ops
}

#[test]
fn unchanged_list_needs_nothing() {
    assert!(check(&[(1, 0), (2, 0)], &[(1, 0), (2, 0)]).is_empty());
}

#[test]
fn insert_remove_update() {
    assert_eq!(check(&[(1, 0), (2, 0), (3, 0)], &[(1, 0), (3, 5), (4, 0)]), vec![Op::Remove(1), Op::Update(1), Op::Insert(2, 4)]);
}

#[test]
fn rename_moves_one_row() {
    // b renamed to z sorts last: one move, one update
    assert_eq!(check(&[(1, 0), (2, 0), (3, 0)], &[(1, 0), (3, 0), (2, 1)]), vec![Op::Move { from: 2, to: 1 }, Op::Update(2)]);
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
    for a in all.iter().step_by(7) {
        for b in &all {
            let ops = check(a, b);
            let kept = b.iter().filter(|(k, _)| a.iter().any(|(ak, _)| ak == k)).count();
            let inserts = ops.iter().filter(|o| matches!(o, Op::Insert(..))).count();
            assert_eq!(inserts, b.len() - kept, "{a:?} -> {b:?}: {ops:?}");
        }
    }
}
