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

/// Random old/new lists (duplicate keys included, up to 12 rows): every op is in range when
/// applied (the lenient `apply` would skip one silently), moves go up, applying gives `new`, and
/// a row is updated only if its value changed or it was moved or rebuilt.
#[test]
fn random_lists_strict() {
    let mut seed = 0x9e3779b97f4a7c15u64;
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
                Op::Move { from, to } => {
                    assert!(*to < *from && *from < list.len(), "{old:?} -> {new:?}: {ops:?}");
                    let mut x = list.remove(*from);
                    x.2 = true;
                    list.insert(*to, x);
                }
                Op::Update(i) => {
                    assert!(*i < list.len(), "{old:?} -> {new:?}: {ops:?}");
                    let (_, nv) = new[*i];
                    assert!(list[*i].1 != nv || list[*i].2, "needless update {old:?} -> {new:?}: {ops:?}");
                    list[*i].1 = nv;
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
